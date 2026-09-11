//! Assigning the staged `code/`, `content/`, `meta/` files to contents and building the FST.
//!
//! The layout mirrors a working retail/TeconMoon inject byte-for-byte in structure (confirmed
//! necessary: the Wii U installer hangs on other content layouts — see the install-hang saga). The
//! content order and grouping are:
//!
//! 1. content 0 = FST;
//! 2. `code/app.xml`, then `code/cos.xml` — each its own non-hashed content;
//! 3. `meta/` split into hashed contents: `meta.xml` alone, the boot bundle
//!    ([`META_BOOT_BUNDLE`]) together, [`META_SINGLES`] each alone, then any leftover meta files
//!    grouped into one;
//! 4. the remaining `code/` files (`.rpx`/`.rpl` first) — each its own non-hashed content;
//! 5. `content/` (game data: shaders + `hif_*.nfs`) — title-owned hashed content(s) of up to
//!    [`MAX_GAME_CONTENT_BYTES`], placed **LAST** (no content may follow the game data).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::util::align_up;

use super::fst::{self, Fst, FstContent, FstNode, FstNodeKind, OFFSET_FACTOR};

/// TMD/FST content type for non-hashed content.
pub const TYPE_NONHASHED: u16 = 0x2001;
/// TMD/FST content type for hashed content.
pub const TYPE_HASHED: u16 = 0x2003;

// FST directory and file flags.
/// FST flags for code directory/files.
const FST_FLAGS_CODE: u16 = 0x0000;
/// FST flags for content directory/files.
const FST_FLAGS_CONTENT: u16 = 0x0400;
/// FST flags for meta directory/files.
const FST_FLAGS_META: u16 = 0x0040;

// FST content table flags.
/// FST content table flag indicating hashed content.
const CONTENT_FLAG_HASHED: u16 = 0x0200;
/// FST content table flag indicating non-hashed content.
const CONTENT_FLAG_NONHASHED: u16 = 0x0100;
/// Group id stamped on hashed metadata contents (retail uses 0x0400 for the meta group).
const CONTENT_GROUP_META: u32 = 0x0400;
/// Group id stamped on non-hashed (code/FST) contents: none.
const CONTENT_GROUP_NONE: u32 = 0x0000;

// FST entry-type flags.
/// FST entry-type flag for HIF (game data) files.
const ENTRY_TYPE_HIF: u8 = 0x02;

const SECTOR: u64 = 0x8000;

/// A file placed within a content, at a byte offset relative to the content start.
#[derive(Clone, Debug)]
pub struct PlacedFile {
    /// Absolute path on disk.
    pub path: PathBuf,
    /// Byte offset within the content (0x20-aligned).
    pub offset: u64,
    /// File size in bytes.
    pub size: u64,
}

/// A planned content to be encrypted and written.
#[derive(Clone, Debug)]
pub struct PlannedContent {
    /// Content index / id.
    pub index: u16,
    /// Content type (`TYPE_HASHED` / `TYPE_NONHASHED`).
    pub content_type: u16,
    /// Files in this content, in placement order (empty for the FST content).
    pub files: Vec<PlacedFile>,
    /// Total decrypted size of the content's data (before encryption padding).
    pub data_len: u64,
    /// True for the game (`hif_*.nfs`) contents. These must carry a non-zero owner title id and a
    /// game-specific group id in the FST content table, or the Wii U installer hangs when it
    /// finalises the content. Metadata/code contents keep owner 0 (matching retail).
    pub is_game: bool,
}

/// The full package plan: the serialized FST (content 0) and every content's file layout.
pub struct PackagePlan {
    /// Serialized FST bytes (the data for content 0).
    pub fst: Vec<u8>,
    /// All contents, index 0 first (the FST content).
    pub contents: Vec<PlannedContent>,
}

// Intermediate tree node before FST serialization.
enum Tree {
    Dir {
        name: String,
        flags: u16,
        children: Vec<Tree>,
    },
    File {
        name: String,
        path: PathBuf,
        size: u64,
        cluster: u16,
        flags: u16,
        type_flags: u8,
    },
}

fn is_hif(name: &str) -> bool {
    name.starts_with("hif_") && name.ends_with(".nfs")
}

/// Maximum decrypted bytes packed into a single game content before rolling over to a new one.
/// The reference packers (NUSPacker/UWUVCI) group game data into large contents rather than one
/// content per file; the Wii U installer hangs installing a package that splits the game across
/// many small contents (confirmed: the same game data installs as one content but hangs when split
/// per-`hif`).
///
/// The cap must keep each encrypted `.app` (~1.6% larger than the decrypted data here) **under 2
/// GiB** (`INT32_MAX`): a content ≥2 GiB hangs the installer immediately (a size field is handled
/// as signed 32-bit somewhere in the install path — matching NUSPacker's historical 2 GiB limit,
/// and confirmed on hardware where 2.98 GiB game contents hung at install while ≤1.2 GiB ones
/// installed). 1.75 GiB decrypted → ~1.74 GiB `.app`, a comfortable margin. NOT a hash-group
/// boundary — game contents may hold many `hif_*.nfs` files.
const MAX_GAME_CONTENT_BYTES: u64 = 0x7000_0000; // 1.75 GiB (keeps the .app under 2 GiB)

/// Rolling state for packing `hif_*.nfs` game files into a few large contents.
struct GameGrouping {
    /// Index of the content currently being filled, if any.
    current: Option<u16>,
    /// Decrypted bytes already assigned to `current`.
    current_size: u64,
}

impl GameGrouping {
    fn new() -> Self {
        GameGrouping {
            current: None,
            current_size: 0,
        }
    }

    /// Return the content index a game file at `path` of `size` bytes should join, creating a new
    /// content when the current one is full (or none exists yet).
    ///
    /// Errors if the file alone exceeds [`MAX_GAME_CONTENT_BYTES`] — packing it in regardless would
    /// silently recreate the ≥2 GiB content that the cap exists to prevent (see the installer-hang
    /// rationale on the constant).
    fn content_for(
        &mut self,
        path: &Path,
        size: u64,
        contents: &mut Vec<PlannedContent>,
    ) -> Result<u16> {
        let placed = align_up(size, OFFSET_FACTOR as u64);
        if placed > MAX_GAME_CONTENT_BYTES {
            return Err(Error::FormatLimit(format!(
                "{} is {size} bytes, which alone exceeds the {MAX_GAME_CONTENT_BYTES}-byte game \
                 content cap; a content at/above 2 GiB is known to hang the Wii U installer, so \
                 this file cannot be packaged as-is",
                path.display()
            )));
        }
        Ok(match self.current {
            Some(idx) if self.current_size + placed <= MAX_GAME_CONTENT_BYTES => {
                self.current_size += placed;
                idx
            }
            _ => {
                let idx = contents.len() as u16;
                contents.push(PlannedContent {
                    index: idx,
                    content_type: TYPE_HASHED,
                    files: Vec::new(),
                    data_len: 0,
                    is_game: true,
                });
                self.current = Some(idx);
                self.current_size = placed;
                idx
            }
        })
    }
}

fn read_dir_sorted(dir: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| Error::io(dir, e))?
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::io(dir, e))?;
    // Case-insensitive by name, matching retail FST ordering. Names differing only by case compare
    // equal under `to_lowercase()`, so tiebreak on the exact bytes too — otherwise two such entries
    // would fall back to readdir order, which is filesystem-dependent and would break byte-identity
    // of the output across machines/filesystems.
    entries.sort_by_key(|e| {
        let n = e.file_name().to_string_lossy().into_owned();
        (n.to_lowercase(), n)
    });
    Ok(entries)
}

/// Like [`read_dir_sorted`] but places `hif_*.nfs` files first. In the game (`content/`) directory
/// this puts `hif_000000.nfs` at offset 0 of the game content — `fw.img` reads the game content
/// from offset 0 as the NFS (its EGGS header must be there), so the disc data must precede the
/// shader assets, or the emulator hangs at boot. No effect on `code/`/`meta/` (no hif files).
fn read_dir_hif_first(dir: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries = read_dir_sorted(dir)?;
    // Same case-insensitive-with-exact-tiebreak rationale as `read_dir_sorted` above.
    entries.sort_by_key(|e| {
        let n = e.file_name().to_string_lossy().into_owned();
        let lower = n.to_lowercase();
        (!is_hif(&lower), lower, n) // hif files first, then everything else in name order
    });
    Ok(entries)
}

/// Meta files that share one hashed content in retail/TeconMoon layouts (the "boot bundle").
const META_BOOT_BUNDLE: &[&str] = &[
    "iconTex.tga",
    "bootTvTex.tga",
    "bootDrcTex.tga",
    "bootSound.btsnd",
];
/// Meta files that each get their own hashed content, in this order (after meta.xml and the bundle).
const META_SINGLES: &[&str] = &["bootMovie.h264", "bootLogoTex.tga"];

/// Plan the package layout from a staged build directory.
///
/// `title_id` is the Wii U title id; it derives the owner title id and group id stamped on the
/// game (`content/`) contents in the FST content table.
///
/// Content order mirrors a working retail/TeconMoon inject (confirmed necessary — the Wii U
/// installer hangs on other layouts): FST, `app.xml`, `cos.xml`, then the split `meta/` contents
/// (hashed), then the remaining `code/` files (non-hashed), then the `content/` game data (hashed,
/// title-owned) LAST.
pub fn plan(build_dir: &Path, title_id: u64) -> Result<PackagePlan> {
    let code_dir = build_dir.join("code");
    let content_dir = build_dir.join("content");
    let meta_dir = build_dir.join("meta");

    // Content 0 is the FST; the rest are allocated below in install order.
    let mut contents: Vec<PlannedContent> = vec![PlannedContent {
        index: 0,
        content_type: TYPE_NONHASHED,
        files: Vec::new(),
        data_len: 0,
        is_game: false,
    }];
    // Assigned content index per staged file path.
    let mut cluster_of: HashMap<PathBuf, u16> = HashMap::new();

    let alloc = |ct: u16, is_game: bool, contents: &mut Vec<PlannedContent>| -> u16 {
        let idx = contents.len() as u16;
        contents.push(PlannedContent {
            index: idx,
            content_type: ct,
            files: Vec::new(),
            data_len: 0,
            is_game,
        });
        idx
    };

    // 1. app.xml, then cos.xml — each its own non-hashed content.
    for name in ["app.xml", "cos.xml"] {
        let p = code_dir.join(name);
        if p.is_file() {
            let idx = alloc(TYPE_NONHASHED, false, &mut contents);
            cluster_of.insert(p, idx);
        }
    }

    // 2. meta/ — split into hashed contents: meta.xml alone, the boot bundle together, then the
    //    known singles, then any leftover meta files grouped into one content.
    if meta_dir.is_dir() {
        if meta_dir.join("meta.xml").is_file() {
            let idx = alloc(TYPE_HASHED, false, &mut contents);
            cluster_of.insert(meta_dir.join("meta.xml"), idx);
        }
        let bundle: Vec<&&str> = META_BOOT_BUNDLE
            .iter()
            .filter(|f| meta_dir.join(f).is_file())
            .collect();
        if !bundle.is_empty() {
            let idx = alloc(TYPE_HASHED, false, &mut contents);
            for f in bundle {
                cluster_of.insert(meta_dir.join(f), idx);
            }
        }
        for f in META_SINGLES {
            if meta_dir.join(f).is_file() {
                let idx = alloc(TYPE_HASHED, false, &mut contents);
                cluster_of.insert(meta_dir.join(f), idx);
            }
        }
        // Any other meta files (e.g. Manual.bfma, rating images the base retains but TeconMoon
        // strips) share ONE hashed content, matching retail (which groups them) — one-per-file
        // would explode the content count.
        let leftover: Vec<PathBuf> = read_dir_sorted(&meta_dir)?
            .into_iter()
            .map(|e| e.path())
            .filter(|p| p.is_file() && !cluster_of.contains_key(p))
            .collect();
        if !leftover.is_empty() {
            let idx = alloc(TYPE_HASHED, false, &mut contents);
            for p in leftover {
                cluster_of.insert(p, idx);
            }
        }
    }

    // 3. remaining code/ files (everything except app.xml/cos.xml) — each its own non-hashed
    //    content, .rpx/.rpl first (matching the reference layout), then the rest sorted.
    if code_dir.is_dir() {
        let mut rest: Vec<PathBuf> = read_dir_sorted(&code_dir)?
            .into_iter()
            .map(|e| e.path())
            .filter(|p| {
                p.is_file() && !cluster_of.contains_key(p) // app.xml/cos.xml already assigned
            })
            .collect();
        // Same case-insensitive-with-exact-tiebreak rationale as read_dir_sorted above: names
        // differing only by case must not fall back to filesystem-dependent readdir order.
        rest.sort_by_key(|p| {
            let n = p.file_name().unwrap().to_string_lossy().into_owned();
            let lower = n.to_lowercase();
            let exec = lower.ends_with(".rpx") || lower.ends_with(".rpl");
            (!exec, lower, n)
        });
        for p in rest {
            let idx = alloc(TYPE_NONHASHED, false, &mut contents);
            cluster_of.insert(p, idx);
        }
    }

    // 4. content/ (game data: shaders + hif) — title-owned hashed content(s), packed to
    //    MAX_GAME_CONTENT_BYTES, placed LAST.
    if content_dir.is_dir() {
        let mut game = GameGrouping::new();
        for (path, size) in collect_files(&content_dir)? {
            let idx = game.content_for(&path, size, &mut contents)?;
            cluster_of.insert(path, idx);
        }
    }

    // Build the FST directory tree (code, content, meta) referencing the assigned clusters.
    let mut root_children = Vec::new();
    if code_dir.is_dir() {
        let children = build_dir_tree(&code_dir, FST_FLAGS_CODE, FST_FLAGS_CODE, &cluster_of)?;
        if !children.is_empty() {
            root_children.push(Tree::Dir {
                name: "code".into(),
                flags: FST_FLAGS_CODE,
                children,
            });
        }
    }
    if content_dir.is_dir() {
        let children = build_dir_tree(
            &content_dir,
            FST_FLAGS_CONTENT,
            FST_FLAGS_CONTENT,
            &cluster_of,
        )?;
        if !children.is_empty() {
            root_children.push(Tree::Dir {
                name: "content".into(),
                flags: FST_FLAGS_CONTENT,
                children,
            });
        }
    }
    if meta_dir.is_dir() {
        let children = build_dir_tree(&meta_dir, FST_FLAGS_META, FST_FLAGS_META, &cluster_of)?;
        if !children.is_empty() {
            root_children.push(Tree::Dir {
                name: "meta".into(),
                flags: FST_FLAGS_META,
                children,
            });
        }
    }

    // Flatten to FST nodes, assigning per-content offsets in traversal order.
    let mut nodes: Vec<FstNode> = Vec::new();
    // Root node placeholder; end_index filled after flattening.
    nodes.push(FstNode {
        name: String::new(),
        kind: FstNodeKind::Dir {
            parent_index: 0,
            end_index: 0,
        },
        type_flags: 0,
        flags: 0,
        cluster: 0,
    });
    flatten(&root_children, 0, &mut nodes, &mut contents);
    let total = nodes.len() as u32;
    if let FstNodeKind::Dir { end_index, .. } = &mut nodes[0].kind {
        *end_index = total;
    }

    // The game contents are owned by the vWii disc-title equivalent (0x00050000_<gameid>) and
    // carry a game-specific group id (low 16 bits of the title id), matching a working retail/
    // TeconMoon inject. Metadata/code contents keep owner 0. Getting this wrong makes the Wii U
    // installer hang when it finalises the first game content.
    let game_owner_title_id = 0x0005_0000_0000_0000 | (title_id & 0xFFFF_FFFF);
    let game_group_id = (title_id & 0xFFFF) as u32;

    // Content 0 is the FST itself, so its size must be known before the content table (which the
    // FST contains) can be built. `fst::serialized_len` breaks that circularity: the serialized
    // length depends only on the FST's shape — the content count and the node list, both final by
    // now — never on any field's value. Reading `contents[0].data_len` here instead would read the
    // 0 it was initialized with and round it up to a single sector, which happens to be right only
    // while the FST stays under 0x8000 bytes (every real one does today, hence no byte change —
    // but a large enough title would have been mis-sized, overlapping content 1).
    contents[0].data_len = fst::serialized_len(contents.len(), &nodes) as u64;

    // Compute FST secondary headers (cumulative content offsets in sectors).
    let mut fst_contents = Vec::with_capacity(contents.len());
    let mut cursor_sectors: u32 = 0;
    for c in &contents {
        let size_sectors = align_up(c.data_len.max(1), SECTOR) / SECTOR;
        let (owner_title_id, group_id, flags) = if c.is_game {
            (game_owner_title_id, game_group_id, CONTENT_FLAG_HASHED)
        } else {
            match c.content_type {
                TYPE_HASHED => (0, CONTENT_GROUP_META, CONTENT_FLAG_HASHED),
                _ => (0, CONTENT_GROUP_NONE, CONTENT_FLAG_NONHASHED),
            }
        };
        fst_contents.push(FstContent {
            offset_sectors: cursor_sectors,
            size_sectors: size_sectors as u32,
            owner_title_id,
            group_id,
            flags,
        });
        cursor_sectors += size_sectors as u32;
    }

    let fst = Fst {
        offset_factor: OFFSET_FACTOR,
        contents: fst_contents,
        nodes,
    };
    let fst_bytes = fst.serialize();
    // The size stamped into the content table above must be exactly what serializing produced.
    debug_assert_eq!(fst_bytes.len() as u64, contents[0].data_len);

    Ok(PackagePlan {
        fst: fst_bytes,
        contents,
    })
}

/// Recursively collect all files under `dir` (depth-first, sorted) as (path, size), in FST order.
fn collect_files(dir: &Path) -> Result<Vec<(PathBuf, u64)>> {
    let mut out = Vec::new();
    for entry in read_dir_hif_first(dir)? {
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_files(&path)?);
        } else {
            let size = entry.metadata().map_err(|e| Error::io(&path, e))?.len();
            out.push((path, size));
        }
    }
    Ok(out)
}

/// Build the FST subtree for `dir`, taking each file's content index from `cluster_of` (assigned
/// during content allocation). `hif_*.nfs` files carry the [`ENTRY_TYPE_HIF`] entry-type flag.
fn build_dir_tree(
    dir: &Path,
    dir_flags: u16,
    file_flags: u16,
    cluster_of: &HashMap<PathBuf, u16>,
) -> Result<Vec<Tree>> {
    let mut out = Vec::new();
    for entry in read_dir_hif_first(dir)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if path.is_dir() {
            let children = build_dir_tree(&path, dir_flags, file_flags, cluster_of)?;
            out.push(Tree::Dir {
                name,
                flags: dir_flags,
                children,
            });
        } else {
            let size = entry.metadata().map_err(|e| Error::io(&path, e))?.len();
            let cluster = *cluster_of.get(&path).ok_or_else(|| {
                Error::UnsupportedDisc(format!("{} was not assigned to a content", path.display()))
            })?;
            let type_flags = if is_hif(&name) { ENTRY_TYPE_HIF } else { 0x00 };
            out.push(Tree::File {
                name,
                path,
                size,
                cluster,
                flags: file_flags,
                type_flags,
            });
        }
    }
    Ok(out)
}

fn flatten(
    children: &[Tree],
    parent_index: u32,
    nodes: &mut Vec<FstNode>,
    contents: &mut [PlannedContent],
) {
    for child in children {
        match child {
            Tree::Dir {
                name,
                flags,
                children,
            } => {
                let my_index = nodes.len() as u32;
                nodes.push(FstNode {
                    name: name.clone(),
                    kind: FstNodeKind::Dir {
                        parent_index,
                        end_index: 0,
                    },
                    type_flags: 0,
                    flags: *flags,
                    cluster: 0,
                });
                flatten(children, my_index, nodes, contents);
                let end = nodes.len() as u32;
                if let FstNodeKind::Dir { end_index, .. } = &mut nodes[my_index as usize].kind {
                    *end_index = end;
                }
                // A directory's cluster mirrors its first child's (cosmetic).
                let cluster = nodes
                    .get(my_index as usize + 1)
                    .map(|n| n.cluster)
                    .unwrap_or(0);
                nodes[my_index as usize].cluster = cluster;
            }
            Tree::File {
                name,
                path,
                size,
                cluster,
                flags,
                type_flags,
            } => {
                let c = &mut contents[*cluster as usize];
                let offset = align_up(c.data_len, OFFSET_FACTOR as u64);
                c.files.push(PlacedFile {
                    path: path.clone(),
                    offset,
                    size: *size,
                });
                c.data_len = offset + *size;
                nodes.push(FstNode {
                    name: name.clone(),
                    kind: FstNodeKind::File {
                        offset,
                        size: *size,
                    },
                    type_flags: *type_flags,
                    flags: *flags,
                    cluster: *cluster,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_a_small_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("code")).unwrap();
        std::fs::create_dir_all(root.join("content/assets/shaders/cafe")).unwrap();
        std::fs::create_dir_all(root.join("meta")).unwrap();
        std::fs::write(root.join("code/app.xml"), b"<app/>").unwrap();
        std::fs::write(root.join("code/cos.xml"), b"<cos/>").unwrap();
        std::fs::write(root.join("code/frisbiiU.rpx"), vec![0u8; 100]).unwrap();
        std::fs::write(
            root.join("content/assets/shaders/cafe/banner.gsh"),
            vec![1u8; 50],
        )
        .unwrap();
        std::fs::write(root.join("content/hif_000000.nfs"), vec![2u8; 0x8000]).unwrap();
        std::fs::write(root.join("meta/meta.xml"), b"<menu/>").unwrap();
        std::fs::write(root.join("meta/iconTex.tga"), vec![3u8; 200]).unwrap();

        let plan = plan(root, 0x00050002_534b4a45).unwrap();
        // FST content + code content + rpx content + assets content + hif content + meta content
        assert!(plan.contents.len() >= 6);
        assert!(!plan.fst.is_empty());

        // FST must round-trip and contain the expected files.
        let parsed = Fst::parse(&plan.fst).unwrap();
        let names: Vec<_> = parsed.nodes.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"frisbiiU.rpx"));
        assert!(names.contains(&"hif_000000.nfs"));
        // The hif file carries the 0x02 entry type flag.
        let hif = parsed
            .nodes
            .iter()
            .find(|n| n.name == "hif_000000.nfs")
            .unwrap();
        assert_eq!(hif.type_flags, 0x02);
        // The game (hif) content is owned by the vWii disc title and has the game group id; a
        // zero owner makes the Wii U installer hang finalising it.
        let game_ct = &parsed.contents[hif.cluster as usize];
        assert_eq!(game_ct.owner_title_id, 0x00050000_534b4a45);
        assert_eq!(game_ct.group_id, 0x4a45);
        // content/ shaders share the title-owned game content (matching TeconMoon), and it is the
        // LAST content in the package.
        let banner = parsed
            .nodes
            .iter()
            .find(|n| n.name == "banner.gsh")
            .unwrap();
        assert_eq!(
            banner.cluster, hif.cluster,
            "shaders live in the game content"
        );
        assert_eq!(
            hif.cluster as usize,
            parsed.contents.len() - 1,
            "the game content is last"
        );
        // meta.xml is in its own hashed content, before the game content.
        let meta = parsed.nodes.iter().find(|n| n.name == "meta.xml").unwrap();
        assert_ne!(meta.cluster, hif.cluster);
        assert_eq!(parsed.contents[meta.cluster as usize].owner_title_id, 0);
        // Each code file gets its own content (matching retail/TeconMoon layout).
        let app = parsed.nodes.iter().find(|n| n.name == "app.xml").unwrap();
        let cos = parsed.nodes.iter().find(|n| n.name == "cos.xml").unwrap();
        let rpx = parsed
            .nodes
            .iter()
            .find(|n| n.name == "frisbiiU.rpx")
            .unwrap();
        assert_ne!(
            app.cluster, cos.cluster,
            "each code file gets its own content"
        );
        assert_ne!(app.cluster, rpx.cluster);
    }

    /// Every content's `offset_sectors` must be the running sum of the previous contents' sizes —
    /// the property that breaks the moment content 0 is mis-sized, since every later offset is
    /// derived from it.
    fn assert_cumulative_offsets(contents: &[FstContent]) {
        for i in 1..contents.len() {
            assert_eq!(
                contents[i].offset_sectors,
                contents[i - 1].offset_sectors + contents[i - 1].size_sectors,
                "content {i} must start where content {} ends",
                i - 1
            );
        }
    }

    /// A small package's FST fits in one 0x8000 sector, so content 0 occupies exactly one sector
    /// and content 1 starts right after it. (This is the case every real title hits today, which
    /// is why sizing content 0 correctly is byte-identical here.)
    #[test]
    fn small_fst_occupies_one_sector_and_content_one_follows_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("code")).unwrap();
        std::fs::create_dir_all(root.join("content/assets/shaders/cafe")).unwrap();
        std::fs::create_dir_all(root.join("meta")).unwrap();
        std::fs::write(root.join("code/app.xml"), b"<app/>").unwrap();
        std::fs::write(root.join("code/cos.xml"), b"<cos/>").unwrap();
        std::fs::write(root.join("code/frisbiiU.rpx"), vec![0u8; 100]).unwrap();
        std::fs::write(
            root.join("content/assets/shaders/cafe/banner.gsh"),
            vec![1u8; 50],
        )
        .unwrap();
        std::fs::write(root.join("content/hif_000000.nfs"), vec![2u8; 0x8000]).unwrap();
        std::fs::write(root.join("meta/meta.xml"), b"<menu/>").unwrap();
        std::fs::write(root.join("meta/iconTex.tga"), vec![3u8; 200]).unwrap();

        let plan = plan(root, 0x00050002_534b4a45).unwrap();
        assert!(plan.fst.len() < 0x8000, "this FST must be under one sector");
        let parsed = Fst::parse(&plan.fst).unwrap();
        assert_eq!(parsed.contents[0].size_sectors, 1);
        assert_eq!(parsed.contents[1].offset_sectors, 1);
        assert_cumulative_offsets(&parsed.contents);
    }

    /// Once the FST grows past 0x8000 bytes, content 0 spans several sectors — and the old code,
    /// which read `contents[0].data_len` while it was still 0, always recorded 1, overlapping
    /// content 0 with content 1. Build a tree with enough files to push the FST over a sector and
    /// pin the whole cumulative layout.
    #[test]
    fn large_fst_spans_multiple_sectors_and_later_contents_follow_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("code")).unwrap();
        std::fs::create_dir_all(root.join("meta")).unwrap();
        std::fs::write(root.join("code/app.xml"), b"<app/>").unwrap();
        std::fs::write(root.join("code/cos.xml"), b"<cos/>").unwrap();
        std::fs::write(root.join("meta/meta.xml"), b"<menu/>").unwrap();
        // ~2200 leftover meta files: each costs a 0x10 entry plus its name, so the entry+name
        // tables alone push the FST well past 0x8000 bytes. They all share the single
        // leftover-meta content, so the content count stays small.
        for i in 0..2200 {
            std::fs::write(root.join(format!("meta/f{i:05}.bin")), b"x").unwrap();
        }

        let plan = plan(root, 0x00050002_534b4a45).unwrap();
        assert!(
            plan.fst.len() > 0x8000,
            "the FST must exceed one sector for this test to mean anything (got {})",
            plan.fst.len()
        );
        let parsed = Fst::parse(&plan.fst).unwrap();
        assert_eq!(
            parsed.contents[0].size_sectors as usize,
            plan.fst.len().div_ceil(0x8000),
            "content 0 must be sized from the FST's real length"
        );
        assert_eq!(
            parsed.contents[1].offset_sectors, parsed.contents[0].size_sectors,
            "content 1 must start after the whole FST, not overlap it"
        );
        assert_cumulative_offsets(&parsed.contents);
    }

    #[test]
    fn game_grouping_packs_up_to_the_cap_in_one_content() {
        let mut game = GameGrouping::new();
        let mut contents: Vec<PlannedContent> = Vec::new();
        // Both sizes are already OFFSET_FACTOR-aligned, so their sum lands exactly on the cap.
        let a = MAX_GAME_CONTENT_BYTES - OFFSET_FACTOR as u64;
        let b = OFFSET_FACTOR as u64;
        let idx_a = game
            .content_for(Path::new("a.bin"), a, &mut contents)
            .unwrap();
        let idx_b = game
            .content_for(Path::new("b.bin"), b, &mut contents)
            .unwrap();
        assert_eq!(
            idx_a, idx_b,
            "sum equal to the cap must stay in one content"
        );
        assert_eq!(contents.len(), 1);
    }

    #[test]
    fn game_grouping_splits_at_the_file_boundary_once_over_the_cap() {
        let mut game = GameGrouping::new();
        let mut contents: Vec<PlannedContent> = Vec::new();
        let a = MAX_GAME_CONTENT_BYTES - OFFSET_FACTOR as u64;
        // The smallest possible excess given OFFSET_FACTOR alignment granularity.
        let b = 2 * OFFSET_FACTOR as u64;
        let idx_a = game
            .content_for(Path::new("a.bin"), a, &mut contents)
            .unwrap();
        let idx_b = game
            .content_for(Path::new("b.bin"), b, &mut contents)
            .unwrap();
        assert_ne!(
            idx_a, idx_b,
            "a file that would push the running total past the cap rolls over to a new content"
        );
        assert_eq!(contents.len(), 2);
    }

    #[test]
    fn game_grouping_errors_when_a_single_file_exceeds_the_cap() {
        let mut game = GameGrouping::new();
        let mut contents: Vec<PlannedContent> = Vec::new();
        let path = Path::new("huge_hif_000000.nfs");
        let err = game
            .content_for(path, MAX_GAME_CONTENT_BYTES + 1, &mut contents)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("huge_hif_000000.nfs"),
            "error should name the offending file: {msg}"
        );
    }

    #[test]
    fn read_dir_sorted_orders_case_only_duplicates_deterministically() {
        // Names differing only by case must sort deterministically (case-insensitive primary key,
        // exact-bytes tiebreak) regardless of creation/readdir order, which is filesystem-dependent
        // and would otherwise break byte-identity of the output across machines/filesystems.
        let dir_a = tempfile::tempdir().unwrap();
        std::fs::write(dir_a.path().join("Foo.txt"), b"a").unwrap();
        std::fs::write(dir_a.path().join("foo.txt"), b"b").unwrap();

        let dir_b = tempfile::tempdir().unwrap();
        std::fs::write(dir_b.path().join("foo.txt"), b"b").unwrap();
        std::fs::write(dir_b.path().join("Foo.txt"), b"a").unwrap();

        fn names(dir: &Path) -> Vec<String> {
            read_dir_sorted(dir)
                .unwrap()
                .into_iter()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        }

        let expected = vec!["Foo.txt".to_string(), "foo.txt".to_string()];
        assert_eq!(
            names(dir_a.path()),
            expected,
            "insertion order: Foo.txt then foo.txt"
        );
        assert_eq!(
            names(dir_b.path()),
            expected,
            "insertion order: foo.txt then Foo.txt"
        );
    }

    #[test]
    fn code_files_with_case_only_duplicate_names_order_deterministically() {
        // Same bug class as read_dir_sorted, in plan()'s separate rpx/rpl-first sort for the
        // remaining code/ files: case-only duplicates must break ties on exact bytes, not fall
        // back to filesystem-dependent readdir order.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("code")).unwrap();
        std::fs::write(root.join("code/Foo.rpl"), vec![0u8; 10]).unwrap();
        std::fs::write(root.join("code/foo.rpl"), vec![1u8; 10]).unwrap();

        let plan = plan(root, 0x00050002_534b4a45).unwrap();
        let parsed = Fst::parse(&plan.fst).unwrap();
        let foo_upper = parsed.nodes.iter().find(|n| n.name == "Foo.rpl").unwrap();
        let foo_lower = parsed.nodes.iter().find(|n| n.name == "foo.rpl").unwrap();
        assert!(
            foo_upper.cluster < foo_lower.cluster,
            "Foo.rpl sorts before foo.rpl by exact-bytes tiebreak, so it gets the earlier content"
        );
    }
}
