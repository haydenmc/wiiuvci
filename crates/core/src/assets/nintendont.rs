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

use anyhow::{anyhow, Context};

use crate::error::{Error, Result};

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The pinned Nintendont autoboot forwarder (`v1.2`, default-config variant).
pub const NINTENDONT_LOADER_URL: &str = "https://github.com/FIX94/nintendont-autoboot-forwarder/releases/download/v1.2/nintendont_default_autobooter.dol";

/// A loose sanity floor: the forwarder is ~194 KiB; anything smaller than this is an HTML error
/// page or a truncated download, not a real `.dol`.
const MIN_LOADER_BYTES: usize = 16 * 1024;

/// Download the pinned Nintendont autoboot forwarder for use as the disc's `main.dol`. Errors on
/// any network/HTTP failure or an implausibly small response, so callers can fall back to a
/// user-supplied file.
pub fn download_boot_dol() -> Result<Vec<u8>> {
    let url = NINTENDONT_LOADER_URL;
    log::info!("downloading the Nintendont autoboot forwarder from {url}");
    let client = reqwest::blocking::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .context("building HTTP client")
        .map_err(Error::Other)?;
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
    Ok(bytes)
}
