//! Assembly of the installable WUP package (title.tmd/tik/cert + `.app`/`.h3`).
//!
//! Given a build directory containing the staged `code/`, `content/` and `meta/` trees, the
//! packager assigns files to contents, builds the FST, encrypts each content (with H0–H3
//! hash trees for hashed contents), and emits the TMD, ticket and certificate chain.

pub mod cert;
pub mod content;
pub mod content_crypto;
pub mod extract;
pub mod fst;
pub mod ticket;
pub mod tmd;

use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use cert::CertChain;
use content_crypto::{encode_hashed_to_writer, encode_nonhashed};
use tmd::ContentRecord;

/// Parameters for building a WUP package.
pub struct PackageParams<'a> {
    /// Wii U title id (`00050002<disc4hex>`).
    pub title_id: u64,
    /// TMD group id (2 bytes).
    pub group_id: u16,
    /// The Wii U common key, for encrypting the title key into the ticket.
    pub wiiu_common_key: [u8; 16],
    /// The (decrypted) title key used to encrypt content.
    pub title_key: [u8; 16],
    /// The certificate chain to emit as `title.cert`.
    pub cert: &'a CertChain,
}

/// Statistics about a built package.
#[derive(Debug, Clone)]
pub struct PackageStats {
    /// Number of contents written (including the FST).
    pub content_count: usize,
    /// Total bytes of encrypted content written.
    pub total_content_bytes: u64,
}

/// Assemble one content's decrypted bytes by placing its files at their offsets.
///
/// Used for the small non-hashed contents (and the FST); large hashed contents are streamed via
/// [`ContentPlaintextReader`] instead of buffered here.
///
/// Every file's size was measured during planning ([`content::plan`]) and is what fixed both this
/// content's length and the size recorded for the file in the FST. A file that changed on disk
/// between then and now is therefore a hard error: a file that grew would panic on the slice
/// bounds, and a file that shrank would be silently zero-padded to its planned size and shipped
/// that way. Staging writes these files, so this only happens if something outside the build is
/// mutating the work directory — worth reporting, not worth papering over.
fn assemble_content(c: &content::PlannedContent, fst: &[u8]) -> Result<Vec<u8>> {
    if c.index == 0 {
        return Ok(fst.to_vec());
    }
    let mut buf = vec![0u8; c.data_len as usize];
    for f in &c.files {
        let bytes = fs::read(&f.path).map_err(|e| Error::io(&f.path, e))?;
        if bytes.len() as u64 != f.size {
            return Err(Error::FormatLimit(format!(
                "{} changed size after planning: expected {} bytes, found {}",
                f.path.display(),
                f.size,
                bytes.len()
            )));
        }
        let start = f.offset as usize;
        buf[start..start + bytes.len()].copy_from_slice(&bytes);
    }
    Ok(buf)
}

/// A `Read` that streams a content's decrypted plaintext — the exact bytes [`assemble_content`]
/// would produce (files at their `offset`s, alignment gaps zero-filled, total `data_len`) — without
/// buffering the whole content or any whole file. This lets large hashed game contents be encoded
/// straight to disk. Files are read sequentially, one open at a time.
struct ContentPlaintextReader {
    files: Vec<content::PlacedFile>, // ascending, non-overlapping by offset
    data_len: u64,
    pos: u64,
    file_idx: usize,
    open: Option<File>,
}

impl ContentPlaintextReader {
    fn new(c: &content::PlannedContent) -> Self {
        let mut files = c.files.clone();
        files.sort_by_key(|f| f.offset);
        ContentPlaintextReader {
            files,
            data_len: c.data_len,
            pos: 0,
            file_idx: 0,
            open: None,
        }
    }
}

impl Read for ContentPlaintextReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.data_len || buf.is_empty() {
            return Ok(0);
        }
        // Skip any files we've fully passed (defensive; reads are sequential).
        while let Some(f) = self.files.get(self.file_idx) {
            if self.pos >= f.offset + f.size {
                self.file_idx += 1;
                self.open = None;
            } else {
                break;
            }
        }
        let want = buf.len().min((self.data_len - self.pos) as usize);
        match self.files.get(self.file_idx) {
            // A gap before the next file: emit zeros up to its offset.
            Some(f) if self.pos < f.offset => {
                let n = want.min((f.offset - self.pos) as usize);
                buf[..n].fill(0);
                self.pos += n as u64;
                Ok(n)
            }
            // Inside the current file's region: stream from it.
            Some(f) => {
                let (foff, fsize) = (f.offset, f.size);
                if self.open.is_none() {
                    let mut fh = File::open(&self.files[self.file_idx].path)?;
                    fh.seek(SeekFrom::Start(self.pos - foff))?;
                    self.open = Some(fh);
                }
                let n = want.min((foff + fsize - self.pos) as usize);
                self.open.as_mut().unwrap().read_exact(&mut buf[..n])?;
                self.pos += n as u64;
                if self.pos >= foff + fsize {
                    self.open = None;
                    self.file_idx += 1;
                }
                Ok(n)
            }
            // Trailing gap after the last file, up to data_len.
            None => {
                let n = want;
                buf[..n].fill(0);
                self.pos += n as u64;
                Ok(n)
            }
        }
    }
}

/// Returns `true` if `name` is a known WUP output filename this crate writes: an 8-hex-digit
/// content id with a `.app` or `.h3` extension, or one of `title.tmd`/`title.tik`/`title.cert`.
fn is_known_output_name(name: &str) -> bool {
    if name == "title.tmd" || name == "title.tik" || name == "title.cert" {
        return true;
    }
    let Some(stem) = name
        .strip_suffix(".app")
        .or_else(|| name.strip_suffix(".h3"))
    else {
        return false;
    };
    stem.len() == 8 && stem.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Suffix of an output still being written. See [`StagedOutputs`].
const PART_SUFFIX: &str = ".part";

/// Returns `true` if `name` is a file a build of this crate may have left in `out_dir`: a final
/// output ([`is_known_output_name`]) or the `<name>.part` temporary of one.
///
/// A `.part` file only survives a process that died mid-build (a kill, a power cut) — [`Drop`]
/// removes them otherwise — so the next build must be free to sweep them away, exactly like a
/// stale final output.
fn is_sweepable_output_name(name: &str) -> bool {
    is_known_output_name(name)
        || name
            .strip_suffix(PART_SUFFIX)
            .is_some_and(is_known_output_name)
}

/// Outputs written as `<name>.part` and renamed into place by [`StagedOutputs::commit`]; if the
/// value is dropped uncommitted, every `.part` is removed.
///
/// Without this, a build that fails partway (disc full, a staged file vanishing, a kill) leaves
/// `out_dir` holding some of the `.app`s plus — worse — a `title.tmd` that looks complete. WUP
/// installers copy whatever they find next to the TMD, so a partial package is an *installable*
/// broken title rather than an obvious failure. Staging makes the final names appear only once
/// every byte is on disk.
///
/// The `.part` files are siblings in `out_dir`, so they are on the same filesystem as their
/// destinations and [`fs::rename`] is a metadata operation — no second pass over a multi-GB
/// `.app`. No `fsync`: this guards against a failed *build*, not against a power-cut filesystem.
struct StagedOutputs<'a> {
    out_dir: &'a Path,
    /// `(part path, final path)` in registration order — also the order `commit` renames in.
    pending: Vec<(PathBuf, PathBuf)>,
    committed: bool,
}

impl<'a> StagedOutputs<'a> {
    fn new(out_dir: &'a Path) -> Self {
        StagedOutputs {
            out_dir,
            pending: Vec::new(),
            committed: false,
        }
    }

    /// Register `final_name` as an output of this build and return the `.part` path to write it to.
    fn stage(&mut self, final_name: &str) -> PathBuf {
        let part = self.out_dir.join(format!("{final_name}{PART_SUFFIX}"));
        let final_path = self.out_dir.join(final_name);
        self.pending.push((part.clone(), final_path));
        part
    }

    /// Rename every staged output into its final name, in registration order.
    ///
    /// On Windows `rename` fails if the destination exists, but [`clean_stale_outputs`] ran at the
    /// start of the build and removed every known final name, so the destinations are free.
    ///
    /// A rename that fails mid-way leaves a genuinely partial package behind, which is the state
    /// this type exists to avoid — so the already-renamed finals are removed again (best effort,
    /// alongside the remaining `.part`s) before the error propagates.
    fn commit(mut self) -> Result<()> {
        for (i, (part, final_path)) in self.pending.iter().enumerate() {
            if let Err(e) = fs::rename(part, final_path) {
                for (_, done) in &self.pending[..i] {
                    let _ = fs::remove_file(done);
                }
                for (remaining, _) in &self.pending[i..] {
                    let _ = fs::remove_file(remaining);
                }
                // Cleanup is done; stop `Drop` from repeating it.
                self.committed = true;
                return Err(Error::io(part, e));
            }
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for StagedOutputs<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Failing to clean up is not worth masking the error that caused the failure.
        for (part, _) in &self.pending {
            let _ = fs::remove_file(part);
        }
    }
}

/// Remove pre-existing WUP output files from `out_dir` before a build writes new ones.
///
/// A rebuild that produces fewer contents than a previous run into the same `out_dir` would
/// otherwise leave orphan `NNNNNNNN.app`/`.h3` files behind; WUP installers copy everything they
/// find, so a stale orphan would get installed alongside the new title. Only files matching the
/// known output patterns are removed (see [`is_sweepable_output_name`], which also covers `.part`
/// leftovers from a build that was killed); nothing else in `out_dir` (other files,
/// subdirectories) is touched.
fn clean_stale_outputs(out_dir: &Path) -> Result<()> {
    let entries = match fs::read_dir(out_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(out_dir, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(out_dir, e))?;
        let path = entry.path();
        let is_file = entry
            .file_type()
            .map_err(|e| Error::io(&path, e))?
            .is_file();
        if !is_file {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if is_sweepable_output_name(name) {
            fs::remove_file(&path).map_err(|e| Error::io(&path, e))?;
        }
    }
    Ok(())
}

/// Build a complete installable WUP package from a staged build directory into `out_dir`.
///
/// Every output is written to a `<name>.part` sibling and renamed into place only once the whole
/// package is on disk (see [`StagedOutputs`]), so a failure never leaves an installable-looking
/// partial package behind.
pub fn build_package(
    build_dir: &Path,
    out_dir: &Path,
    params: &PackageParams,
) -> Result<PackageStats> {
    fs::create_dir_all(out_dir).map_err(|e| Error::io(out_dir, e))?;
    clean_stale_outputs(out_dir)?;
    let plan = content::plan(build_dir, params.title_id)?;

    let mut staged = StagedOutputs::new(out_dir);
    let mut records = Vec::with_capacity(plan.contents.len());
    let mut total_content_bytes = 0u64;

    for c in &plan.contents {
        let app_path = staged.stage(&format!("{:08x}.app", c.index));
        let (size, tmd_hash) = if c.content_type == content::TYPE_HASHED {
            // Large game contents: stream the plaintext straight to the encrypted .app one hash
            // group at a time, so we never buffer the whole content in memory.
            let file = File::create(&app_path).map_err(|e| Error::io(&app_path, e))?;
            let mut writer = BufWriter::new(file);
            let reader = ContentPlaintextReader::new(c);
            let summary = encode_hashed_to_writer(&params.title_key, c.index, reader, &mut writer)
                .map_err(|e| Error::io(&app_path, e))?;
            writer.flush().map_err(|e| Error::io(&app_path, e))?;
            let h3_path = staged.stage(&format!("{:08x}.h3", c.index));
            fs::write(&h3_path, &summary.h3).map_err(|e| Error::io(&h3_path, e))?;
            (summary.size, summary.tmd_hash)
        } else {
            // Small non-hashed contents (and the FST): assemble in memory (no .h3).
            let plaintext = assemble_content(c, &plan.fst)?;
            let encoded = encode_nonhashed(&params.title_key, c.index, &plaintext);
            fs::write(&app_path, &encoded.data).map_err(|e| Error::io(&app_path, e))?;
            (encoded.size, encoded.tmd_hash)
        };
        total_content_bytes += size;

        records.push(ContentRecord {
            id: c.index as u32,
            index: c.index,
            content_type: c.content_type,
            size,
            hash: tmd_hash,
        });
    }

    // Cert, ticket, TMD — registered (and so renamed into place) in that order, leaving the TMD
    // last: it is the file installers key on to decide a package is there at all.
    let cert_path = staged.stage("title.cert");
    fs::write(&cert_path, params.cert.as_bytes()).map_err(|e| Error::io(&cert_path, e))?;

    let enc_title_key =
        ticket::encrypt_title_key(&params.wiiu_common_key, params.title_id, &params.title_key);
    let tik_bytes = ticket::build_ticket(params.title_id, &enc_title_key);
    let tik_path = staged.stage("title.tik");
    fs::write(&tik_path, &tik_bytes).map_err(|e| Error::io(&tik_path, e))?;

    let tmd_bytes = tmd::build_tmd(params.title_id, params.group_id, &records);
    let tmd_path = staged.stage("title.tmd");
    fs::write(&tmd_path, &tmd_bytes).map_err(|e| Error::io(&tmd_path, e))?;

    // Every byte is on disk (the hashed-content writer was flushed and dropped inside its block
    // above); publish the whole package under its final names.
    staged.commit()?;

    Ok(PackageStats {
        content_count: plan.contents.len(),
        total_content_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cert::EXPECTED_CERT_LEN;
    use content::{PlacedFile, PlannedContent, TYPE_HASHED};

    /// The streaming reader must reproduce `assemble_content`'s buffer byte-for-byte, including the
    /// zero-filled alignment gaps between files and the trailing gap up to `data_len`.
    #[test]
    fn content_plaintext_reader_matches_assemble_content() {
        let dir = tempfile::tempdir().unwrap();
        // Three files at non-adjacent 0x20-aligned offsets → gaps before/between/after.
        let mk = |name: &str, byte: u8, len: usize| {
            let p = dir.path().join(name);
            std::fs::write(&p, vec![byte; len]).unwrap();
            (p, len as u64)
        };
        let (p0, s0) = mk("a.bin", 0xAA, 100);
        let (p1, s1) = mk("b.bin", 0xBB, 0x40);
        let (p2, s2) = mk("c.bin", 0xCC, 7);
        let files = vec![
            PlacedFile {
                path: p0,
                offset: 0x20,
                size: s0,
            }, // gap [0,0x20)
            PlacedFile {
                path: p1,
                offset: 0x100,
                size: s1,
            }, // gap after a.bin
            PlacedFile {
                path: p2,
                offset: 0x200,
                size: s2,
            },
        ];
        let data_len = 0x240; // trailing gap after c.bin
        let c = PlannedContent {
            index: 5,
            content_type: TYPE_HASHED,
            files,
            data_len,
            is_game: true,
        };

        let expected = assemble_content(&c, &[]).unwrap();
        assert_eq!(expected.len(), data_len as usize);

        let mut got = Vec::new();
        ContentPlaintextReader::new(&c)
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(
            got, expected,
            "streamed plaintext must match assemble_content"
        );

        // Also check it works with a tiny read buffer (forces many short reads across boundaries).
        let mut reader = ContentPlaintextReader::new(&c);
        let mut got2 = Vec::new();
        let mut small = [0u8; 3];
        loop {
            let n = reader.read(&mut small).unwrap();
            if n == 0 {
                break;
            }
            got2.extend_from_slice(&small[..n]);
        }
        assert_eq!(got2, expected, "small-buffer reads must also match");
    }

    /// A staged file whose size no longer matches what planning recorded must be an error, in
    /// both directions: growing would have panicked on the slice bounds, shrinking would have been
    /// silently zero-padded into the package.
    #[test]
    fn assemble_content_rejects_a_file_that_changed_size_after_planning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.xml");
        let planned = PlannedContent {
            index: 1,
            content_type: TYPE_HASHED,
            files: vec![PlacedFile {
                path: path.clone(),
                offset: 0,
                size: 100,
            }],
            data_len: 100,
            is_game: false,
        };

        // Exactly the planned size: fine.
        std::fs::write(&path, vec![0xEE; 100]).unwrap();
        assert_eq!(assemble_content(&planned, &[]).unwrap(), vec![0xEE; 100]);

        for (label, actual) in [("grew", 128usize), ("shrank", 64)] {
            std::fs::write(&path, vec![0xEE; actual]).unwrap();
            let err = assemble_content(&planned, &[]).unwrap_err();
            assert!(
                matches!(err, Error::FormatLimit(_)),
                "a file that {label} should be a format-limit error, got {err}"
            );
            let msg = err.to_string();
            assert!(msg.contains("app.xml"), "error should name the file: {msg}");
            assert!(
                msg.contains("100") && msg.contains(&actual.to_string()),
                "error should give both sizes: {msg}"
            );
        }
    }

    #[test]
    fn known_output_name_matches_only_expected_patterns() {
        assert!(is_known_output_name("0000000f.app"));
        assert!(is_known_output_name("0000000f.h3"));
        assert!(is_known_output_name("deadbeef.app"));
        assert!(is_known_output_name("title.tmd"));
        assert!(is_known_output_name("title.tik"));
        assert!(is_known_output_name("title.cert"));

        assert!(!is_known_output_name("readme.txt"));
        assert!(!is_known_output_name("deadbeef.app.bak"));
        assert!(!is_known_output_name("deadbee.app")); // 7 hex digits
        assert!(!is_known_output_name("deadbeefg.app")); // 9 chars
        assert!(!is_known_output_name("nothex01.app")); // non-hex chars
        assert!(!is_known_output_name("content"));

        // `.part` temporaries are sweepable but are not themselves final outputs.
        for name in ["0000000f.app.part", "0000000f.h3.part", "title.tmd.part"] {
            assert!(!is_known_output_name(name), "{name}");
            assert!(is_sweepable_output_name(name), "{name}");
        }
        for name in ["readme.txt.part", "deadbeef.app.bak.part", ".part"] {
            assert!(!is_sweepable_output_name(name), "{name}");
        }
        // Every final output is sweepable too.
        assert!(is_sweepable_output_name("title.tmd"));
        assert!(is_sweepable_output_name("0000000f.app"));
    }

    /// `clean_stale_outputs` must remove only files matching the known output patterns, leaving
    /// decoy files and subdirectories untouched.
    #[test]
    fn clean_stale_outputs_removes_only_known_patterns() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();

        // Including `.part` leftovers from a build that was killed before it could clean up.
        let known = [
            "0000000f.app",
            "0000000f.h3",
            "title.tmd",
            "00000010.app.part",
            "title.tik.part",
        ];
        let decoys = ["readme.txt", "deadbeef.app.bak", "readme.txt.part"];
        for name in known.iter().chain(decoys.iter()) {
            fs::write(p.join(name), b"stale").unwrap();
        }
        fs::create_dir(p.join("subdir")).unwrap();
        fs::write(p.join("subdir/00000001.app"), b"nested").unwrap();

        clean_stale_outputs(p).unwrap();

        for name in known {
            assert!(!p.join(name).exists(), "{name} should have been removed");
        }
        for name in decoys {
            assert!(p.join(name).exists(), "{name} should NOT have been removed");
        }
        assert!(p.join("subdir").is_dir(), "subdirectory must be untouched");
        assert!(
            p.join("subdir/00000001.app").exists(),
            "files inside subdirectories must be untouched"
        );
    }

    #[test]
    fn clean_stale_outputs_on_missing_dir_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist-yet");
        clean_stale_outputs(&missing).unwrap();
    }

    /// Stage the smallest tree `content::plan` accepts: one non-hashed content per `code/` file,
    /// a hashed `meta.xml` content, and one hashed game content holding the NFS.
    fn stage_minimal_build(build_dir: &Path) {
        for (rel, body) in [
            ("code/app.xml", &b"<app/>"[..]),
            ("code/cos.xml", &b"<cos/>"[..]),
            ("meta/meta.xml", &b"<menu/>"[..]),
            ("content/hif_000000.nfs", &b"EGGS"[..]),
        ] {
            let path = build_dir.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }
    }

    fn test_params(cert: &CertChain) -> PackageParams<'_> {
        PackageParams {
            title_id: 0x0005_0002_1010_1000,
            group_id: 0x0000,
            wiiu_common_key: [0x11; 16],
            title_key: [0x22; 16],
            cert,
        }
    }

    /// A build that runs to completion must leave only final names — no `.part` sibling may
    /// survive `commit`, or the next `clean_stale_outputs` would be doing real work every time and
    /// the package directory would ship junk.
    #[test]
    fn successful_build_leaves_only_final_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let build_dir = dir.path().join("build");
        let out_dir = dir.path().join("out");
        stage_minimal_build(&build_dir);

        let cert = CertChain(vec![0u8; EXPECTED_CERT_LEN]);
        let stats = build_package(&build_dir, &out_dir, &test_params(&cert)).unwrap();
        assert!(stats.content_count >= 4);

        let mut names: Vec<String> = fs::read_dir(&out_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert!(!names.is_empty());
        for name in &names {
            assert!(
                is_known_output_name(name),
                "unexpected leftover in the package dir: {name}"
            );
            assert!(!name.ends_with(PART_SUFFIX), "leftover temporary: {name}");
        }
        for required in ["title.tmd", "title.tik", "title.cert"] {
            assert!(names.iter().any(|n| n == required), "missing {required}");
        }
    }

    /// The point of staging: a build that fails partway must leave **nothing** installable behind.
    /// Without it, the small contents (and on some paths the TMD) would already sit in `out_dir`
    /// under their final names, and a WUP installer would happily copy that torso.
    ///
    /// The failure is injected with a dangling symlink in `content/`: `content::plan` accepts it
    /// (`DirEntry::metadata` reports the link itself, not its missing target), and the streaming
    /// [`ContentPlaintextReader`] then fails on `File::open` — after the code/meta contents have
    /// been written.
    #[test]
    #[cfg(unix)]
    fn failed_build_leaves_no_package_files() {
        let dir = tempfile::tempdir().unwrap();
        let build_dir = dir.path().join("build");
        let out_dir = dir.path().join("out");
        stage_minimal_build(&build_dir);
        std::os::unix::fs::symlink("/nonexistent", build_dir.join("content/zz.bin")).unwrap();

        let cert = CertChain(vec![0u8; EXPECTED_CERT_LEN]);
        let err = build_package(&build_dir, &out_dir, &test_params(&cert)).unwrap_err();
        eprintln!("expected failure: {err}");

        for entry in fs::read_dir(&out_dir).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !is_sweepable_output_name(&name),
                "a failed build left {name} behind"
            );
        }
    }
}
