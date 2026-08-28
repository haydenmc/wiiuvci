//! Extracting a Wii apploader from the base title's own game disc.
//!
//! The base VC title's `content/hif_*.nfs` *is* the original VC game's Wii disc, NFS-encoded
//! with the key in `code/htk.bin`; its data partition carries a genuine apploader at logical
//! offset 0x2440 (`boot.bin | bi2.bin | apploader | …`). When the user does not supply
//! `--apploader`, the GameCube path takes this one. That matches the reference tools
//! (TeconMoon/UWUVCI), which rebuild the base's own disc with `wit`/`nfs2iso2nfs` and so inherit
//! its apploader implicitly; because wiivci authors the synthetic disc clean-room instead, the
//! apploader has to be recovered from the base explicitly.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Error, Result};

/// Logical partition-data offset of the apploader image (after `boot.bin` @0 and `bi2.bin`
/// @0x440); matches `crate::wii_author::APPLOADER_OFF`.
const APPLOADER_PART_OFF: u64 = 0x2440;

/// Apploader image header: 0x10-byte revision/date string, entry point u32 @0x10, payload size
/// u32 @0x14, trailer size u32 @0x18, 4 bytes padding.
const HEADER_LEN: usize = 0x20;

/// Sanity ceiling for a real apploader image — retail ones are ~200 KiB.
const MAX_APPLOADER_BYTES: usize = 2 << 20;

/// An apploader image extracted from a disc, with the header fields worth logging.
pub(crate) struct ApploaderImage {
    /// The full image (header + payload + trailer), as embedded at partition offset 0x2440.
    pub bytes: Vec<u8>,
    /// The header's revision/date string (e.g. `2011/01/19`).
    pub date: String,
    /// The header's entry point (a MEM1 address, e.g. `0x8120_0294`).
    pub entry: u32,
}

/// Parse an apploader header and return the total image length it declares.
fn parse_header(header: &[u8; HEADER_LEN]) -> Result<(usize, String, u32)> {
    let be32 =
        |o: usize| u32::from_be_bytes([header[o], header[o + 1], header[o + 2], header[o + 3]]);
    let (entry, size, trailer) = (be32(0x10), be32(0x14) as usize, be32(0x18) as usize);
    let total = HEADER_LEN + size + trailer;
    if entry == 0 || size == 0 || total > MAX_APPLOADER_BYTES {
        return Err(Error::UnsupportedDisc(format!(
            "no plausible apploader at partition offset {APPLOADER_PART_OFF:#x} \
             (entry {entry:#010x}, size {size:#x}, trailer {trailer:#x})"
        )));
    }
    let date = String::from_utf8_lossy(&header[..0x10])
        .trim_end_matches('\0')
        .trim()
        .to_string();
    Ok((total, date, entry))
}

/// Read the apploader image out of an NFS-encoded Wii disc.
///
/// `nfs_dir` must contain `hif_000000.nfs` (plus any further splits); `nod` locates the AES key
/// at `nfs_dir/../code/htk.bin` or `nfs_dir/htk.bin`. Hash validation is off — only ~200 KiB
/// near the front of the disc is read.
pub(crate) fn extract_from_nfs(nfs_dir: &Path) -> Result<ApploaderImage> {
    let hif0 = nfs_dir.join("hif_000000.nfs");
    let disc = nod::Disc::new_with_options(
        &hif0,
        &nod::OpenOptions {
            rebuild_encryption: false,
            validate_hashes: false,
        },
    )
    .map_err(|e| Error::UnsupportedDisc(format!("opening base NFS {}: {e}", hif0.display())))?;
    let mut part = disc
        .open_partition_kind(nod::PartitionKind::Data)
        .map_err(|e| Error::UnsupportedDisc(format!("opening base NFS data partition: {e}")))?;

    let ioerr = |e| Error::io(&hif0, e);
    let mut header = [0u8; HEADER_LEN];
    part.seek(SeekFrom::Start(APPLOADER_PART_OFF))
        .map_err(ioerr)?;
    part.read_exact(&mut header).map_err(ioerr)?;
    let (total, date, entry) = parse_header(&header)?;

    let mut bytes = vec![0u8; total];
    part.seek(SeekFrom::Start(APPLOADER_PART_OFF))
        .map_err(ioerr)?;
    part.read_exact(&mut bytes).map_err(ioerr)?;
    Ok(ApploaderImage { bytes, date, entry })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid apploader image with recognizable bytes.
    fn fake_apploader() -> Vec<u8> {
        let (size, trailer) = (0x400usize, 0x100usize);
        let mut img = vec![0u8; HEADER_LEN + size + trailer];
        img[..10].copy_from_slice(b"2026/08/27");
        img[0x10..0x14].copy_from_slice(&0x8130_0000u32.to_be_bytes());
        img[0x14..0x18].copy_from_slice(&(size as u32).to_be_bytes());
        img[0x18..0x1C].copy_from_slice(&(trailer as u32).to_be_bytes());
        for (i, b) in img[HEADER_LEN..].iter_mut().enumerate() {
            *b = (i.wrapping_mul(31) ^ 0x5C) as u8;
        }
        img
    }

    #[test]
    fn parses_a_valid_header() {
        let img = fake_apploader();
        let (total, date, entry) = parse_header(img[..HEADER_LEN].try_into().unwrap()).unwrap();
        assert_eq!(total, img.len());
        assert_eq!(date, "2026/08/27");
        assert_eq!(entry, 0x8130_0000);
    }

    #[test]
    fn rejects_implausible_headers() {
        // All zeros: no entry point, no size.
        assert!(parse_header(&[0u8; HEADER_LEN]).is_err());
        // Huge declared size.
        let mut h = [0u8; HEADER_LEN];
        h[0x10..0x14].copy_from_slice(&0x8130_0000u32.to_be_bytes());
        h[0x14..0x18].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_header(&h).is_err());
    }

    /// Real-fixture test: pull the apploader out of the Rhythm Heaven Fever `.wua` base the
    /// same way the GameCube pipeline does. Ignored by default — it materializes several
    /// hundred MB of NFS from the archive.
    #[test]
    #[ignore = "reads the multi-hundred-MB base NFS from the .wua; run manually"]
    fn extracts_a_real_apploader_from_the_wua_base() {
        use crate::base::BaseSource;

        let wua = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test_titles/Rhythm Heaven Fever[00050000101B0700][USA][v0].wua");
        if !wua.exists() {
            eprintln!(
                "skipping extracts_a_real_apploader_from_the_wua_base: {} not present",
                wua.display()
            );
            return;
        }
        let mut base = crate::base::WuaBase::open(&wua).unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let dir = base
            .materialize_original_nfs(scratch.path())
            .unwrap()
            .expect("the .wua base carries its original NFS");
        let app = extract_from_nfs(&dir).unwrap();
        assert!(
            (0x1000..=MAX_APPLOADER_BYTES).contains(&app.bytes.len()),
            "implausible apploader size {}",
            app.bytes.len()
        );
        assert_eq!(
            app.entry & 0xFF00_0000,
            0x8100_0000,
            "entry must be a MEM1 address"
        );
        assert!(!app.date.is_empty());
        eprintln!(
            "extracted apploader: {} bytes, {}, entry {:#010x}",
            app.bytes.len(),
            app.date,
            app.entry
        );
    }

    /// End-to-end, fully offline: author a synthetic disc with known apploader bytes, pack it
    /// to NFS, and read the apploader back out through `extract_from_nfs`.
    #[test]
    fn round_trips_through_an_authored_nfs() {
        use crate::nfs::build_nfs;
        use crate::wii_author::{author_gc_disc, GcDiscInputs};
        use std::io::Cursor;

        let apploader = fake_apploader();
        let iso: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let main_dol: Vec<u8> = (0..4096u32).map(|i| (i ^ 0xA5) as u8).collect();

        let out = tempfile::tempdir().unwrap();
        let disc_path = out.path().join("gc_disc.img");
        let mut cur = Cursor::new(iso.clone());
        let mut authored = author_gc_disc(
            &mut cur,
            iso.len() as u64,
            &GcDiscInputs {
                game_id: *b"GM2E8P",
                disc_title: "GC Test",
                main_dol: &main_dol,
                apploader: &apploader,
            },
            &disc_path,
        )
        .unwrap();

        let htk = [0x5Au8; 16];
        let nfs_dir = out.path().join("content");
        std::fs::create_dir_all(&nfs_dir).unwrap();
        let plan = authored.plan.clone();
        build_nfs(&mut authored, &htk, &nfs_dir, &plan).unwrap();
        std::fs::write(nfs_dir.join("htk.bin"), htk).unwrap();

        let got = extract_from_nfs(&nfs_dir).unwrap();
        assert_eq!(got.bytes, apploader, "apploader must round-trip exactly");
        assert_eq!(got.date, "2026/08/27");
        assert_eq!(got.entry, 0x8130_0000);
    }
}
