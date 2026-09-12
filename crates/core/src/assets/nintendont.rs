//! Fetching the Nintendont **autoboot forwarder**, used as the synthetic Wii disc's `main.dol`
//! when injecting a GameCube game.
//!
//! The disc's `main.dol` must be FIX94's [nintendont-autoboot-forwarder], NOT the stock Nintendont
//! `loader.dol`: stock `loader.dol` is a Homebrew-Channel-style app that does not run as a Wii-VC
//! disc's `main.dol`, so a disc built with it installs but reboots to the menu on launch. The
//! forwarder is a tiny (~194 KiB) shim that reads `sd:/nincfg.bin`, loads Nintendont from
//! `sd:/apps/nintendont/boot.dol`, and autoboots the emulated disc's game — so a GameCube inject
//! requires Nintendont to be installed on the SD card (see the pipeline's boot warning).
//!
//! It is free homebrew (GPL). The user can override with a locally-built forwarder (e.g. FIX94's
//! `force_4_by_3` variant) via `--nintendont`, and must supply one when `--offline`.
//!
//! [nintendont-autoboot-forwarder]: https://github.com/FIX94/nintendont-autoboot-forwarder

use std::time::Duration;

use anyhow::{Context, anyhow};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

use super::http_client;

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The pinned Nintendont autoboot forwarder (`v1.2`, default-config variant).
pub const NINTENDONT_LOADER_URL: &str = "https://github.com/FIX94/nintendont-autoboot-forwarder/releases/download/v1.2/nintendont_default_autobooter.dol";

/// A loose sanity floor: the forwarder is ~194 KiB; anything smaller than this is an HTML error
/// page or a truncated download, not a real `.dol`.
const MIN_LOADER_BYTES: usize = 16 * 1024;

/// SHA-256 of the pinned `v1.2` release asset at [`NINTENDONT_LOADER_URL`] (198,336 bytes),
/// confirmed by downloading it (`curl -sL <url> | sha256sum`) and cross-checked against
/// `.dev/nintendont_default_autobooter.dol`, a copy of that same asset — both hashed identical.
/// GitHub release assets are immutable once published, so this is a real integrity check, not
/// just a size floor: an HTML error page, a truncated download, or a tampered mirror will all
/// fail it even if they happen to clear [`MIN_LOADER_BYTES`].
const NINTENDONT_LOADER_SHA256: [u8; 32] = [
    0x6e, 0xff, 0x4c, 0x9b, 0x1b, 0xf4, 0xaf, 0xe8, 0x38, 0x3a, 0x06, 0x61, 0x3c, 0x43, 0x1b, 0xb9,
    0xa1, 0x05, 0x86, 0x3a, 0x3b, 0xe1, 0xd1, 0x33, 0x20, 0x62, 0x1b, 0x8a, 0x11, 0x74, 0x2c, 0x5e,
];

/// Verify `bytes` against `expected`, naming both hashes on mismatch. Parameterized over the
/// expected hash (rather than hard-coding [`NINTENDONT_LOADER_SHA256`]) so this is directly
/// testable on arbitrary in-memory data, with no network round trip and no dependency on the
/// real ~194 KiB forwarder being present on disk.
fn verify_sha256(bytes: &[u8], expected: &[u8; 32]) -> Result<()> {
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if &actual != expected {
        return Err(Error::Other(anyhow!(
            "Nintendont forwarder download from {NINTENDONT_LOADER_URL} does not match the \
             pinned SHA-256 (expected {}, got {}); the release asset may have changed or the \
             download may be corrupted/tampered — supply a known-good file with --nintendont",
            hex(expected),
            hex(&actual)
        )));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Download the pinned Nintendont autoboot forwarder for use as the disc's `main.dol`. Errors on
/// any network/HTTP failure, an implausibly small response, or a SHA-256 mismatch against the
/// pinned release asset, so callers can fall back to a user-supplied file.
pub fn download_boot_dol() -> Result<Vec<u8>> {
    let url = NINTENDONT_LOADER_URL;
    log::info!("downloading the Nintendont autoboot forwarder from {url}");
    let client = http_client(FETCH_TIMEOUT)?;
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("fetching Nintendont loader from {url}"))
        .map_err(Error::Other)?;
    if !response.status().is_success() {
        return Err(Error::Other(anyhow!(
            "Nintendont download failed: {url} returned {}",
            response.status()
        )));
    }
    let bytes = response
        .bytes()
        .with_context(|| format!("reading Nintendont loader body from {url}"))
        .map_err(Error::Other)?
        .to_vec();
    if bytes.len() < MIN_LOADER_BYTES {
        return Err(Error::Other(anyhow!(
            "Nintendont forwarder download from {url} was only {} bytes (expected the ~194 KiB \
             autoboot forwarder .dol); supply one with --nintendont",
            bytes.len()
        )));
    }
    verify_sha256(&bytes, &NINTENDONT_LOADER_SHA256)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fully in-memory: hash arbitrary bytes ourselves and confirm `verify_sha256` accepts them
    /// against their own hash, with no network round trip and no dependency on the real ~194 KiB
    /// forwarder being present on disk.
    #[test]
    fn verify_sha256_accepts_matching_bytes() {
        let data = b"pretend this is the Nintendont forwarder";
        let expected: [u8; 32] = Sha256::digest(data).into();
        verify_sha256(data, &expected).expect("bytes must match their own hash");
    }

    #[test]
    fn verify_sha256_rejects_mismatched_bytes() {
        let expected = [0xAAu8; 32]; // some hash `data` certainly doesn't have
        let err = verify_sha256(b"not the real forwarder", &expected).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("does not match the pinned SHA-256"),
            "{message}"
        );
    }

    /// Confirms [`NINTENDONT_LOADER_SHA256`] itself still matches the pinned release asset, when
    /// a copy of it is available locally (it isn't checked into the repo — see `.dev/`).
    #[test]
    fn pinned_hash_matches_the_dev_fixture() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.dev/nintendont_default_autobooter.dol");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!(
                "skipping pinned_hash_matches_the_dev_fixture: {} not present",
                path.display()
            );
            return;
        };
        verify_sha256(&bytes, &NINTENDONT_LOADER_SHA256)
            .expect("pinned fixture must match NINTENDONT_LOADER_SHA256");
    }
}
