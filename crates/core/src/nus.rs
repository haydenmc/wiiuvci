//! Downloading a base title from the Nintendo Update Server (NUS / CCS CDN).
//!
//! NUS serves each title's `tmd`, `cetk`, and content files over **plain HTTP** at
//! `http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/<titleID>/<file>`. Content files are
//! encrypted with the title key; the title key itself is not freely served for paid titles,
//! so the caller supplies it (the encrypted form from a title-key database, decrypted here
//! with the Wii U common key). Nothing is bundled.
//!
//! [`NusBase`] downloads the base, decrypts and extracts it (via [`crate::package::extract`]),
//! and presents it through the [`BaseSource`](crate::base::BaseSource) trait like any other
//! base — skipping the base's own `hif_*.nfs`, which the injected game replaces (so those
//! large contents are never even downloaded).

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use crate::assets::http_client;
use crate::base::{finalize_stage, is_base_game_nfs, BaseSource, StagedBase};
use crate::error::{Error, Result};
use crate::package::extract::extract_title;
use crate::package::ticket::decrypt_title_key;
use crate::package::tmd::parse_content_records;

/// Default CCS CDN base URL (plain HTTP; content is already encrypted).
pub const DEFAULT_NUS_URL: &str = "http://ccs.cdn.c.shop.nintendowifi.net/ccs/download";

/// A content or TMD response bigger than this is refused before its body is read: no NUS content
/// (even a base title's largest `.app`) legitimately approaches this size, so a `Content-Length`
/// past it means either a misbehaving server/mirror or a mistaken URL — better to fail fast on
/// the header than stream gigabytes into memory first.
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// A minimal NUS/CCS content client.
pub struct NusClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

impl NusClient {
    /// Create a client using [`DEFAULT_NUS_URL`].
    pub fn new() -> Result<Self> {
        Self::with_base_url(DEFAULT_NUS_URL)
    }

    /// Create a client with a custom base URL (e.g. a mirror).
    pub fn with_base_url(base_url: impl Into<String>) -> Result<Self> {
        // Timeout semantics matter here: a base title's largest `.app` runs to hundreds of MB,
        // which can legitimately take far longer than any fixed deadline on a slow link. See
        // [`NusClient::get`] — the body is streamed through `Read`, where reqwest applies
        // `timeout` *per read* (a stall timeout) rather than as a whole-request deadline, so a
        // slow-but-progressing download is never cut off while a dead connection still fails.
        let http = http_client(Duration::from_secs(120))?;
        Ok(NusClient {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    fn get(&self, title_id: u64, file: &str) -> Result<Vec<u8>> {
        let url = format!("{}/{:016x}/{}", self.base_url, title_id, file);
        let mut resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| Error::Other(anyhow::anyhow!("GET {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Other(anyhow::anyhow!(
                "GET {url}: HTTP {}",
                resp.status()
            )));
        }
        if let Some(len) = resp.content_length() {
            if len > MAX_RESPONSE_BYTES {
                return Err(Error::Other(anyhow::anyhow!(
                    "GET {url}: Content-Length {len} exceeds the {MAX_RESPONSE_BYTES}-byte sanity \
                     limit; refusing to download it"
                )));
            }
        }
        // Stream the body via `Read` rather than `Response::bytes()`: `bytes()` runs the whole
        // body download under the client's single `timeout`, so any content that takes longer
        // than that in total fails even while data is flowing. `Read::read` applies the same
        // timeout to each individual read instead, which is the stall semantics we want (see
        // [`NusClient::with_base_url`]).
        let mut bytes = Vec::new();
        resp.read_to_end(&mut bytes)
            .map_err(|e| Error::Other(anyhow::anyhow!("reading {url}: {e}")))?;
        Ok(bytes)
    }

    /// Download the latest TMD (or a specific `version`).
    pub fn tmd(&self, title_id: u64, version: Option<u32>) -> Result<Vec<u8>> {
        let file = match version {
            Some(v) => format!("tmd.{v}"),
            None => "tmd".to_string(),
        };
        self.get(title_id, &file)
    }

    /// Download one content by its id (NUS names contents by uppercase 8-hex id, no extension).
    pub fn content(&self, title_id: u64, content_id: u32) -> Result<Vec<u8>> {
        self.get(title_id, &format!("{content_id:08X}"))
    }
}

/// A base title obtained by downloading from NUS.
pub struct NusBase {
    title_id: u64,
    enc_title_key: [u8; 16],
    wiiu_common_key: [u8; 16],
    version: Option<u32>,
    client: NusClient,
}

impl NusBase {
    /// Create an NUS-backed base source.
    ///
    /// * `title_id` — the base title id (e.g. `0x00050000101B0700`).
    /// * `enc_title_key` — the 16-byte *encrypted* title key (as found in title-key
    ///   databases); decrypted internally with `wiiu_common_key`.
    /// * `version` — a specific TMD version, or `None` for the latest.
    pub fn new(
        title_id: u64,
        enc_title_key: [u8; 16],
        wiiu_common_key: [u8; 16],
        version: Option<u32>,
        client: NusClient,
    ) -> Self {
        NusBase {
            title_id,
            enc_title_key,
            wiiu_common_key,
            version,
            client,
        }
    }
}

impl BaseSource for NusBase {
    fn stage(&mut self, build_dir: &Path) -> Result<StagedBase> {
        log::info!("downloading base TMD for {:016x} from NUS", self.title_id);
        let tmd = self.client.tmd(self.title_id, self.version)?;
        let records = parse_content_records(&tmd)?;

        let title_key =
            decrypt_title_key(&self.wiiu_common_key, self.title_id, &self.enc_title_key);

        // Download each referenced content on demand, once, caching in memory. Contents that
        // hold only the base's hif_*.nfs are never requested (extract skips those files).
        let cache: RefCell<HashMap<u32, Vec<u8>>> = RefCell::new(HashMap::new());
        let reader = |id: u32| -> Result<Vec<u8>> {
            if let Some(bytes) = cache.borrow().get(&id) {
                return Ok(bytes.clone());
            }
            log::info!("downloading content {id:08X} from NUS");
            let bytes = self.client.content(self.title_id, id)?;
            cache.borrow_mut().insert(id, bytes.clone());
            Ok(bytes)
        };

        extract_title(&records, &title_key, &reader, build_dir, is_base_game_nfs)?;

        finalize_stage(build_dir)
    }

    fn materialize_original_nfs(
        &mut self,
        dest: &std::path::Path,
    ) -> Result<Option<std::path::PathBuf>> {
        log::info!(
            "downloading the base's original game data from NUS to recover its apploader \
             (this is the large content stage() normally skips)"
        );
        let tmd = self.client.tmd(self.title_id, self.version)?;
        let records = parse_content_records(&tmd)?;
        let title_key =
            decrypt_title_key(&self.wiiu_common_key, self.title_id, &self.enc_title_key);

        let reader = |id: u32| -> Result<Vec<u8>> {
            log::info!("downloading content {id:08X} from NUS");
            self.client.content(self.title_id, id)
        };
        // Keep only the NFS files and the key beside them; every other content is skipped and
        // therefore never downloaded.
        extract_title(&records, &title_key, &reader, dest, |name| {
            !(is_base_game_nfs(name) || name == "htk.bin")
        })?;

        let content_dir = dest.join("content");
        if content_dir.join("hif_000000.nfs").is_file() && dest.join("code/htk.bin").is_file() {
            Ok(Some(content_dir))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live end-to-end NUS test: download + decrypt + extract Rhythm Heaven Fever and confirm
    /// the staged framework files match the `.wua`-staged base in `.dev/base`. Requires network
    /// access to the CCS CDN and `WIIU_COMMON_KEY`; the encrypted title key is read from the
    /// reference ticket. Ignored by default.
    #[test]
    #[ignore = "hits the live NUS CDN; needs .dev/wup_ref, .dev/base and WIIU_COMMON_KEY"]
    fn nus_download_matches_wua_base() {
        let refdir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/wup_ref");
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/base");
        let tik = match std::fs::read(refdir.join("title.tik")) {
            Ok(t) => t,
            Err(_) => {
                eprintln!(
                    "skipping nus_download_matches_wua_base: {} not present",
                    refdir.join("title.tik").display()
                );
                return;
            }
        };
        if !base.join("code/app.xml").exists() {
            eprintln!(
                "skipping nus_download_matches_wua_base: {} not present",
                base.join("code/app.xml").display()
            );
            return;
        }
        let Ok(hex) = std::env::var("WIIU_COMMON_KEY") else {
            eprintln!("skipping nus_download_matches_wua_base: WIIU_COMMON_KEY not present");
            return;
        };
        let mut common = [0u8; 16];
        for i in 0..16 {
            common[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let title_id = u64::from_be_bytes(tik[0x1DC..0x1E4].try_into().unwrap());
        let mut enc_key = [0u8; 16];
        enc_key.copy_from_slice(&tik[0x1BF..0x1CF]);

        let mut nus = NusBase::new(title_id, enc_key, common, None, NusClient::new().unwrap());
        let out = tempfile::tempdir().unwrap();
        let staged = match nus.stage(out.path()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping (NUS unreachable?): {e}");
                return;
            }
        };
        // The htk key and the framework files must match the .wua-staged base.
        let base_htk = std::fs::read(base.join("code/htk.bin")).unwrap();
        assert_eq!(staged.htk.as_slice(), base_htk.as_slice());
        for rel in ["code/frisbiiU.rpx", "code/cos.xml", "meta/meta.xml"] {
            let got = std::fs::read(out.path().join(rel)).unwrap();
            let want = std::fs::read(base.join(rel)).unwrap();
            assert_eq!(got, want, "NUS-extracted {rel} differs from the .wua base");
        }
    }
}
