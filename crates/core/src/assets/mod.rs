//! Boot-texture conversion and best-effort artwork/title fetching for injected titles.

use std::time::Duration;

use crate::error::{Error, Result};

pub mod artrepo;
pub mod gametdb;
pub mod images;
pub mod nintendont;

pub use artrepo::{art_png_name, download_texture, download_texture_opt};
pub use gametdb::{lookup_title, lookup_title_opt};
pub use images::{png_to_tga, BootTexture};

/// The shared connect timeout for every HTTP fetch this crate makes: distinguishes "server
/// unreachable" from "server slow to respond", independent of how long a given caller is willing
/// to wait for the body ([`http_client`]'s `read_timeout`).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a `reqwest` blocking client with this crate's standard connect timeout, a caller-chosen
/// `read_timeout` (per-read stall bound — see [`crate::nus::NusClient::with_base_url`] for why
/// that's not a whole-request deadline), and a stable user agent. Shared by every HTTP fetch in
/// [`crate::assets`] and by [`crate::nus`], which needs a much longer `read_timeout` for
/// multi-hundred-MB content downloads.
pub(crate) fn http_client(read_timeout: Duration) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent("wiivci")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(read_timeout)
        .build()
        .map_err(|e| Error::Other(anyhow::anyhow!("building HTTP client: {e}")))
}
