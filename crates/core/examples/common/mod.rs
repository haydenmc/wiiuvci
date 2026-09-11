//! Shared helpers for the diagnostic examples under `crates/core/examples/`.
//!
//! Each example that needs a helper adds `mod common;` — Cargo compiles this file as a module
//! of every example that references it. Not every example uses every helper, hence the blanket
//! `dead_code` allow below.
#![allow(dead_code)]

use std::path::Path;

use anyhow::Context;
use wiivci_core::keys::WiiUCommonKey;
use wiivci_core::package::ticket::decrypt_title_key;

/// Dummy title key used by examples that repackage/inspect content without a real ticket
/// (e.g. re-running `build_package`/`decode_hashed` on already-staged data).
pub const DUMMY_TITLE_KEY: [u8; 16] = [
    0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
];

/// Load the Wii U common key from `WIIU_COMMON_KEY`, per CLAUDE.md: the key is passed only via
/// this env var, never as a CLI argument. Mirrors the CLI's `load_wiiu_key`: the value may be
/// either an inline hex string or a path to a key file.
pub fn wiiu_common_key() -> anyhow::Result<WiiUCommonKey> {
    let val = std::env::var("WIIU_COMMON_KEY")
        .context("WIIU_COMMON_KEY not set (hex string or path to a key file)")?;
    let path = Path::new(&val);
    let raw = if path.is_file() {
        std::fs::read(path).with_context(|| format!("reading key file {}", path.display()))?
    } else {
        val.into_bytes()
    };
    WiiUCommonKey::parse(&raw).context("invalid WIIU_COMMON_KEY")
}

/// Extract the title id (offset 0x1DC, 8 bytes) from a raw ticket, bounds-checked.
pub fn title_id_from_tik(tik: &[u8]) -> anyhow::Result<u64> {
    anyhow::ensure!(
        tik.len() >= 0x1E4,
        "ticket too short ({} bytes, need at least 0x1E4)",
        tik.len()
    );
    Ok(u64::from_be_bytes(tik[0x1DC..0x1E4].try_into().unwrap()))
}

/// Decrypt the title key embedded in a raw ticket (encrypted title key at 0x1BF, title id at
/// 0x1DC), bounds-checked.
pub fn title_key_from_tik(tik: &[u8], common: &WiiUCommonKey) -> anyhow::Result<[u8; 16]> {
    anyhow::ensure!(
        tik.len() >= 0x1E4,
        "ticket too short ({} bytes, need at least 0x1E4)",
        tik.len()
    );
    let title_id = title_id_from_tik(tik)?;
    let mut enc_tk = [0u8; 16];
    enc_tk.copy_from_slice(&tik[0x1BF..0x1CF]);
    Ok(decrypt_title_key(&common.0, title_id, &enc_tk))
}

/// Read a WUP content file by id, trying the uppercase name (`XXXXXXXX.app`) then the lowercase
/// one — packages produced by different tools disagree on case.
pub fn read_app(dir: &Path, id: u32) -> anyhow::Result<Vec<u8>> {
    let up = dir.join(format!("{id:08X}.app"));
    let lo = dir.join(format!("{id:08x}.app"));
    std::fs::read(&up)
        .or_else(|_| std::fs::read(&lo))
        .with_context(|| format!("reading {} (or lowercase name)", up.display()))
}

/// Open a disc/NFS image with hash rebuilding and validation both disabled — the common case for
/// examples that just want to read logical file data or headers, not verify the hash tree.
pub fn open_decrypted_disc(path: &Path) -> anyhow::Result<nod::Disc> {
    nod::Disc::new_with_options(
        path,
        &nod::OpenOptions {
            rebuild_encryption: false,
            validate_hashes: false,
        },
    )
    .with_context(|| format!("opening disc {}", path.display()))
}

/// Lowercase hex-encode a byte slice.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read a big-endian u32 from the first 4 bytes of `b`.
pub fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}

/// Print `usage` to stderr and exit with status 2 if `args` has fewer than `min` elements.
/// Examples call this with their positional args (after skipping argv[0]) so a missing argument
/// prints usage instead of panicking with an `unwrap`/`expect` backtrace.
pub fn usage_or_exit(args: &[String], min: usize, usage: &str) {
    if args.len() < min {
        eprintln!("{usage}");
        std::process::exit(2);
    }
}
