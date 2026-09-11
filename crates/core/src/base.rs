//! The user-supplied Wii U base title.
//!
//! Every Wii VC injection is built on top of a real Wii U Virtual Console title (by
//! convention Rhythm Heaven Fever, `00050000101B0700`). The base supplies the closed
//! Nintendo framework binaries — `fw.img`, `frisbiiU.rpx`, `cos.xml`, `htk.bin`,
//! `nn_hai_user.rpl` — that have no clean-room reimplementation and cannot be redistributed.
//! The user obtains their own dump; this module never bundles one.
//!
//! Two [`BaseSource`] implementations are provided:
//!
//! * [`WuaBase`] — a Cemu `.wua` ZArchive (read natively via the pure-Rust `zarust` crate);
//! * [`DirBase`] — an already-extracted directory tree.
//!
//! Both [`stage`](BaseSource::stage) the base's `code/`, `content/` (minus the base's own
//! `hif_*.nfs`, which the injected game replaces) and `meta/` into a build directory, and
//! return the 16-byte `htk.bin` NFS key. A third implementation, `NusBase` (download-from-NUS),
//! lives in [`crate::nus`] behind this same trait.

use std::fs;
use std::path::{Path, PathBuf};

use zarust::{ArchiveReader, EntryKind, NodeHandle, ROOT_NODE};

use crate::error::{Error, Result};

/// Files that must be present in a base title's `code/` directory.
pub const REQUIRED_CODE_FILES: &[&str] = &[
    "cos.xml",
    "frisbiiU.rpx",
    "fw.img",
    "fw.tmd",
    "htk.bin",
    "nn_hai_user.rpl",
];

/// A base title staged into a build directory.
pub struct StagedBase {
    /// The 16-byte NFS AES key read from `code/htk.bin`.
    pub htk: [u8; 16],
    /// The build directory the three trees below live in — what [`crate::package::build_package`]
    /// packages. Carried here so callers that already hold a `StagedBase` need not also thread the
    /// work directory separately (the three paths are derived from it).
    pub build_dir: PathBuf,
    /// Path to the staged `code/` directory.
    pub code_dir: PathBuf,
    /// Path to the staged `content/` directory.
    pub content_dir: PathBuf,
    /// Path to the staged `meta/` directory.
    pub meta_dir: PathBuf,
}

/// A provider of Wii U base-title content.
pub trait BaseSource {
    /// Stage the base's `code/`, `content/` and `meta/` trees into `build_dir`, skipping the
    /// base's own `hif_*.nfs` game data. `build_dir` must already exist.
    fn stage(&mut self, build_dir: &Path) -> Result<StagedBase>;

    /// Materialize the base's **original** `hif_*.nfs` game disc (which [`stage`] deliberately
    /// skips) somewhere `nod`'s NFS reader can open it, and return the directory holding the
    /// `hif_*.nfs` files. The returned layout must let `nod` find the AES key at
    /// `<dir>/../code/htk.bin` or `<dir>/htk.bin`.
    ///
    /// `dest` is scratch space the implementation may (but need not) populate — a source that
    /// already has the files on disk can return its own directory instead. Returns `Ok(None)`
    /// when the source has no original NFS (e.g. an already-stripped directory base).
    ///
    /// Used by the GameCube path to recover the base game's genuine apploader (see
    /// [`crate::apploader`]).
    ///
    /// [`stage`]: BaseSource::stage
    fn materialize_original_nfs(&mut self, dest: &Path) -> Result<Option<PathBuf>>;
}

pub(crate) fn is_base_game_nfs(name: &str) -> bool {
    name.starts_with("hif_") && name.ends_with(".nfs")
}

/// Join `rel` onto `base`, rejecting anything that could escape `base`: an absolute path, a `..`
/// (or `.`) component, or an empty name. Used wherever a path component comes from untrusted
/// data — a title FST entry (from a downloaded or user-supplied title), a `.wua` archive entry
/// name, or a base directory entry — so a hostile `../../etc/passwd`-style name can't write
/// outside the intended output directory. Ordinary nested names behave exactly as a plain
/// `base.join(rel)` would.
pub(crate) fn safe_join(base: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() {
        return Err(Error::InvalidTitle(
            "refusing to join an empty path entry".into(),
        ));
    }
    let rel_path = Path::new(rel);
    for component in rel_path.components() {
        match component {
            std::path::Component::Normal(_) => {}
            _ => {
                return Err(Error::InvalidTitle(format!(
                    "refusing to join unsafe path entry {rel:?}"
                )));
            }
        }
    }
    Ok(base.join(rel_path))
}

pub(crate) fn finalize_stage(build_dir: &Path) -> Result<StagedBase> {
    let code_dir = build_dir.join("code");
    let content_dir = build_dir.join("content");
    let meta_dir = build_dir.join("meta");

    for f in REQUIRED_CODE_FILES {
        let p = code_dir.join(f);
        if !p.exists() {
            return Err(Error::MissingFile(p));
        }
    }
    let htk_path = code_dir.join("htk.bin");
    let htk_bytes = fs::read(&htk_path).map_err(|e| Error::io(&htk_path, e))?;
    let htk: [u8; 16] = htk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKey {
            name: "htk.bin",
            reason: format!("expected 16 bytes, got {}", htk_bytes.len()),
        })?;

    Ok(StagedBase {
        htk,
        build_dir: build_dir.to_path_buf(),
        code_dir,
        content_dir,
        meta_dir,
    })
}

// ---------------------------------------------------------------------------
// .wua (ZArchive) base
// ---------------------------------------------------------------------------

/// Base title subdirectories [`WuaBase::stage`] and [`DirBase::stage`] copy out; anything else
/// under the title root (a `.wua` can carry other junk alongside the title) is left behind.
const STAGE_SUBDIRS: [&str; 3] = ["code", "content", "meta"];

/// A base title read from a Cemu `.wua` ZArchive.
pub struct WuaBase {
    reader: ArchiveReader<fs::File>,
    /// Handle of the `<titleId>_v<version>` title root inside the archive.
    title_root: NodeHandle,
    /// The archive path, kept only to annotate error messages.
    path: PathBuf,
}

impl WuaBase {
    /// Open a `.wua` archive and locate its title root.
    ///
    /// If the archive holds multiple titles, the first one containing a `code/` directory is
    /// used.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let reader =
            ArchiveReader::open(&path).map_err(|e| wua_err(&path, "opening archive", e))?;

        let mut title_root = None;
        for entry in reader
            .directory_entries(ROOT_NODE)
            .map_err(|e| wua_err(&path, "reading root directory entries", e))?
        {
            if entry.kind == EntryKind::Directory {
                // A title root has a `code/` child. A failure reading this candidate's children
                // is a real archive problem, not evidence it isn't the title root — propagate
                // it instead of silently treating it as "no code/ here, keep looking", which
                // would otherwise surface as a misleading "no title found" for what's actually
                // a corrupt archive.
                let children = reader
                    .directory_entries(entry.handle)
                    .map_err(|e| wua_err(&path, "reading directory entries", e))?;
                if children
                    .iter()
                    .any(|c| c.name == b"code" && c.is_directory())
                {
                    title_root = Some(entry.handle);
                    break;
                }
            }
        }
        let title_root = title_root.ok_or_else(|| {
            Error::InvalidTitle(format!(
                "no Wii U title (a '<id>_v<n>/code/' tree) found in {}",
                path.display()
            ))
        })?;

        Ok(WuaBase {
            reader,
            title_root,
            path,
        })
    }

    fn copy_dir(&mut self, handle: NodeHandle, dest: &Path) -> Result<()> {
        fs::create_dir_all(dest).map_err(|e| Error::io(dest, e))?;
        // Collect owned entries first so the immutable borrow ends before read_file_to_end.
        let entries: Vec<(String, EntryKind, NodeHandle)> = self
            .reader
            .directory_entries(handle)
            .map_err(|e| wua_err(&self.path, "reading directory entries", e))?
            .into_iter()
            .map(|e| {
                (
                    String::from_utf8_lossy(e.name).into_owned(),
                    e.kind,
                    e.handle,
                )
            })
            .collect();

        for (name, kind, h) in entries {
            let path = safe_join(dest, &name)?;
            match kind {
                EntryKind::Directory => self.copy_dir(h, &path)?,
                EntryKind::File => {
                    if is_base_game_nfs(&name) {
                        continue;
                    }
                    let data = self
                        .reader
                        .read_file_to_end(h)
                        .map_err(|e| wua_err(&self.path, &format!("reading file {name:?}"), e))?;
                    fs::write(&path, data).map_err(|e| Error::io(&path, e))?;
                }
            }
        }
        Ok(())
    }
}

impl WuaBase {
    /// Handle of the named directory directly under the title root, if present.
    fn title_subdir(&self, name: &str) -> Result<Option<NodeHandle>> {
        Ok(self
            .reader
            .directory_entries(self.title_root)
            .map_err(|e| wua_err(&self.path, "reading title root directory entries", e))?
            .into_iter()
            .find(|e| e.is_directory() && e.name == name.as_bytes())
            .map(|e| e.handle))
    }
}

impl BaseSource for WuaBase {
    fn stage(&mut self, build_dir: &Path) -> Result<StagedBase> {
        let title_root = self.title_root;
        // Copy only code/, content/ (minus hif_*.nfs) and meta/ — not every directory under the
        // title root, which may carry other files a `.wua` doesn't need staged.
        let subdirs: Vec<(String, NodeHandle)> = self
            .reader
            .directory_entries(title_root)
            .map_err(|e| wua_err(&self.path, "reading title root directory entries", e))?
            .into_iter()
            .filter(|e| e.is_directory())
            .map(|e| (String::from_utf8_lossy(e.name).into_owned(), e.handle))
            .filter(|(name, _)| STAGE_SUBDIRS.contains(&name.as_str()))
            .collect();

        for (name, handle) in subdirs {
            self.copy_dir(handle, &build_dir.join(&name))?;
        }
        finalize_stage(build_dir)
    }

    fn materialize_original_nfs(&mut self, dest: &Path) -> Result<Option<PathBuf>> {
        let Some(content) = self.title_subdir("content")? else {
            return Ok(None);
        };
        let hifs: Vec<(String, NodeHandle)> = self
            .reader
            .directory_entries(content)
            .map_err(|e| wua_err(&self.path, "reading content directory entries", e))?
            .into_iter()
            .filter(|e| {
                e.kind == EntryKind::File && is_base_game_nfs(&String::from_utf8_lossy(e.name))
            })
            .map(|e| (String::from_utf8_lossy(e.name).into_owned(), e.handle))
            .collect();
        if !hifs.iter().any(|(name, _)| name == "hif_000000.nfs") {
            return Ok(None);
        }

        let content_dir = dest.join("content");
        fs::create_dir_all(&content_dir).map_err(|e| Error::io(&content_dir, e))?;
        for (name, handle) in hifs {
            let path = safe_join(&content_dir, &name)?;
            let data = self
                .reader
                .read_file_to_end(handle)
                .map_err(|e| wua_err(&self.path, &format!("reading file {name:?}"), e))?;
            fs::write(&path, data).map_err(|e| Error::io(&path, e))?;
        }

        // The NFS key, where nod looks for it (`<content>/../code/htk.bin`).
        let Some(code) = self.title_subdir("code")? else {
            return Ok(None);
        };
        let Some(htk) = self
            .reader
            .directory_entries(code)
            .map_err(|e| wua_err(&self.path, "reading code directory entries", e))?
            .into_iter()
            .find(|e| e.kind == EntryKind::File && e.name == b"htk.bin")
            .map(|e| e.handle)
        else {
            return Ok(None);
        };
        let code_dir = dest.join("code");
        fs::create_dir_all(&code_dir).map_err(|e| Error::io(&code_dir, e))?;
        let htk_bytes = self
            .reader
            .read_file_to_end(htk)
            .map_err(|e| wua_err(&self.path, "reading htk.bin", e))?;
        let htk_path = code_dir.join("htk.bin");
        fs::write(&htk_path, htk_bytes).map_err(|e| Error::io(&htk_path, e))?;

        Ok(Some(content_dir))
    }
}

/// Wrap a `zarust` error with the archive path and the operation being performed, so a failure
/// deep in a nested `copy_dir` call still names the `.wua` file it came from. Not
/// [`Error::InvalidTitle`]: these are archive I/O failures (open, read), not judgments about
/// the title's content being malformed.
fn wua_err(path: &Path, op: &str, e: zarust::Error) -> Error {
    Error::Other(anyhow::anyhow!("{op} on {}: {}", path.display(), e))
}

// ---------------------------------------------------------------------------
// Extracted-directory base
// ---------------------------------------------------------------------------

/// A base title read from an already-extracted directory tree.
pub struct DirBase {
    root: PathBuf,
}

impl DirBase {
    /// Point at a directory containing `code/`, `content/`, `meta/` — either directly or one
    /// level down inside a single `<titleId>_v<n>` subfolder (as produced by extracting a
    /// `.wua`).
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.join("code").is_dir() {
            return Ok(DirBase {
                root: path.to_path_buf(),
            });
        }
        // Look one level down for a title folder. A real read failure here (permission denied,
        // `path` not even a directory, ...) is propagated rather than swallowed into the same
        // generic "no code/ directory found" the fallback below reports for an honestly-empty
        // base — those are different problems and deserve different messages.
        for entry in fs::read_dir(path).map_err(|e| Error::io(path, e))? {
            let entry = entry.map_err(|e| Error::io(path, e))?;
            let p = entry.path();
            if p.is_dir() && p.join("code").is_dir() {
                return Ok(DirBase { root: p });
            }
        }
        Err(Error::InvalidTitle(format!(
            "no 'code/' directory found in base path {}",
            path.display()
        )))
    }
}

impl BaseSource for DirBase {
    fn stage(&mut self, build_dir: &Path) -> Result<StagedBase> {
        for sub in STAGE_SUBDIRS {
            let src = self.root.join(sub);
            if src.is_dir() {
                copy_tree(&src, &build_dir.join(sub))?;
            }
        }
        finalize_stage(build_dir)
    }

    fn materialize_original_nfs(&mut self, _dest: &Path) -> Result<Option<PathBuf>> {
        // Everything is already on disk in the right layout (`content/hif_*.nfs` beside
        // `code/htk.bin`) — hand out our own directory, no copying. A base dir that was itself
        // produced by staging has no hif files and yields `None`.
        let content = self.root.join("content");
        if content.join("hif_000000.nfs").is_file() && self.root.join("code/htk.bin").is_file() {
            Ok(Some(content))
        } else {
            Ok(None)
        }
    }
}

/// Recursively copy `src` into `dest`, skipping the base's own `hif_*.nfs` files.
fn copy_tree(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest).map_err(|e| Error::io(dest, e))?;
    for entry in fs::read_dir(src).map_err(|e| Error::io(src, e))? {
        let entry = entry.map_err(|e| Error::io(src, e))?;
        let name = entry.file_name();
        let from = entry.path();
        let to = safe_join(dest, &name.to_string_lossy())?;
        if from.is_dir() {
            copy_tree(&from, &to)?;
        } else if !is_base_game_nfs(&name.to_string_lossy()) {
            fs::copy(&from, &to).map_err(|e| Error::io(&from, e))?;
        }
    }
    Ok(())
}

/// Open a base title from a path, dispatching on extension (`.wua` vs directory).
pub fn open_base(path: impl AsRef<Path>) -> Result<Box<dyn BaseSource>> {
    let path = path.as_ref();
    if path.is_dir() {
        Ok(Box::new(DirBase::new(path)?))
    } else if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("wua"))
    {
        Ok(Box::new(WuaBase::open(path)?))
    } else {
        Err(Error::InvalidTitle(format!(
            "base must be a directory or a .wua archive: {}",
            path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_accepts_normal_nested_names() {
        let base = Path::new("/out");
        assert_eq!(
            safe_join(base, "code/app.xml").unwrap(),
            base.join("code/app.xml")
        );
        assert_eq!(safe_join(base, "meta.xml").unwrap(), base.join("meta.xml"));
    }

    #[test]
    fn safe_join_rejects_parent_dir_traversal() {
        let base = Path::new("/out");
        assert!(safe_join(base, "../x").is_err());
        assert!(safe_join(base, "a/../../b").is_err());
        assert!(safe_join(base, "code/../../../etc/passwd").is_err());
    }

    #[test]
    fn safe_join_rejects_absolute_paths() {
        let base = Path::new("/out");
        assert!(safe_join(base, "/abs").is_err());
        assert!(safe_join(base, "/etc/passwd").is_err());
    }

    #[test]
    fn safe_join_rejects_empty_name() {
        let base = Path::new("/out");
        assert!(safe_join(base, "").is_err());
    }

    /// `copy_tree` copies nested files and skips the base's own `hif_*.nfs` files, wherever they
    /// appear in the tree.
    #[test]
    fn copy_tree_copies_nested_files_and_skips_hif() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("a.txt"), b"a").unwrap();
        std::fs::write(src.path().join("sub/b.txt"), b"b").unwrap();
        std::fs::write(src.path().join("hif_000000.nfs"), b"nfsdata").unwrap();
        std::fs::write(src.path().join("sub/hif_000001.nfs"), b"nfsdata2").unwrap();

        let dst = tempfile::tempdir().unwrap();
        let dest_root = dst.path().join("out");
        copy_tree(src.path(), &dest_root).unwrap();

        assert_eq!(std::fs::read(dest_root.join("a.txt")).unwrap(), b"a");
        assert_eq!(std::fs::read(dest_root.join("sub/b.txt")).unwrap(), b"b");
        assert!(!dest_root.join("hif_000000.nfs").exists());
        assert!(!dest_root.join("sub/hif_000001.nfs").exists());
    }

    /// `DirBase::new` accepts a root with `code/` directly under it, and one containing a single
    /// `<title>/code/` subfolder (as produced by extracting a `.wua`).
    #[test]
    fn dirbase_new_finds_code_directly_or_one_level_down() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("code")).unwrap();
        assert!(DirBase::new(dir.path()).is_ok());

        let dir2 = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir2.path().join("SomeTitle_v0/code")).unwrap();
        assert!(DirBase::new(dir2.path()).is_ok());
    }

    /// A directory with no `code/` anywhere (directly or one level down) is an `InvalidTitle`
    /// error, not a read error.
    #[test]
    fn dirbase_new_errors_when_no_code_dir_found() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("random")).unwrap();
        // `DirBase` holds no `Debug` impl, so match on the `Result` directly rather than
        // `unwrap_err()` (which requires the `Ok` type to be `Debug`).
        let Err(err) = DirBase::new(dir.path()) else {
            panic!("expected an error for a directory with no code/ anywhere");
        };
        assert!(matches!(err, Error::InvalidTitle(_)), "got {err}");
    }

    /// A genuine read failure (here: the "directory" is actually a file, so `read_dir` fails) must
    /// propagate as a real `Error::Io`, distinct from the generic "no code/ found" case.
    #[test]
    fn dirbase_new_propagates_a_real_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("not_a_dir");
        std::fs::write(&file_path, b"x").unwrap();
        let Err(err) = DirBase::new(&file_path) else {
            panic!("expected an error when the base path is a file, not a directory");
        };
        assert!(
            matches!(err, Error::Io { .. }),
            "expected an I/O error, got {err}"
        );
    }

    /// `open_base` dispatches on extension (case-insensitively) vs directory, and rejects
    /// anything else outright.
    #[test]
    fn open_base_dispatches_on_extension_and_kind() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("code")).unwrap();
        assert!(open_base(dir.path()).is_ok());

        // A `.wua` extension (any case) must dispatch to `WuaBase::open`, not the "must be a
        // directory or a .wua archive" rejection — even though this particular file isn't a real
        // archive and so fails for a different reason once opened.
        let bogus_wua = dir.path().join("nope.WUA");
        std::fs::write(&bogus_wua, b"not a real archive").unwrap();
        // `Box<dyn BaseSource>` holds no `Debug` impl, so match on the `Result` directly rather
        // than `unwrap_err()`.
        let Err(err) = open_base(&bogus_wua) else {
            panic!("expected a bogus .wua archive to fail opening");
        };
        assert!(
            !err.to_string()
                .contains("must be a directory or a .wua archive"),
            "a .wua extension should dispatch to WuaBase::open: {err}"
        );

        // Anything else (not a directory, no .wua extension) is rejected outright.
        let other = dir.path().join("something.bin");
        std::fs::write(&other, b"x").unwrap();
        let Err(err2) = open_base(&other) else {
            panic!("expected a plain file with no .wua extension to be rejected");
        };
        assert!(matches!(err2, Error::InvalidTitle(_)), "got {err2}");
        assert!(err2
            .to_string()
            .contains("must be a directory or a .wua archive"));
    }
}
