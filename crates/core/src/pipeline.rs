//! End-to-end injection pipeline: Wii disc + base title → installable WUP package.
//!
//! Steps:
//! 1. open the source disc ([`crate::input`]); `nod` decrypts Wii partitions internally;
//! 2. stage the base title into a build directory ([`crate::base`]);
//! 3. convert the disc to NFS under `content/` ([`crate::nfs`]);
//! 4. drop in the game's `rvlt.tik`/`rvlt.tmd` and fakesign-patch `fw.img`;
//! 5. regenerate `code/app.xml`, `meta/meta.xml` and the boot textures ([`crate::meta`],
//!    [`crate::assets`]);
//! 6. package it all into `title.tmd`/`tik`/`cert` + `.app`/`.h3` ([`crate::package`]).

use std::path::{Path, PathBuf};

use crate::assets::images::{png_to_tga, BootTexture};
use crate::assets::{artrepo, gametdb};
use crate::base::{BaseSource, StagedBase};
use crate::consts::{TMD_CONTENT0_HASH, WII_SIG};
use crate::disc_patch;
use crate::error::{Error, Result};
use crate::fwimg;
use crate::input::{GcImage, SourceDisc};
use crate::keys::WiiUCommonKey;
use crate::meta::appxml;
use crate::meta::metaxml::{patch as patch_meta, MetaOptions};
use crate::meta::titleid;
use crate::nfs::build_nfs;
use crate::nincfg::{self, NincfgOptions};
use crate::package::cert::CertChain;
use crate::package::{build_package, PackageParams, PackageStats};
use crate::video::VideoPatches;
use crate::wii_author::{self, GcDiscInputs};

/// Fixed plaintext title key used to encrypt content (stored, encrypted, in the ticket — its
/// value is arbitrary, matching the convention of the reference tools).
const TITLE_KEY: [u8; 16] = [
    0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
];

/// Region code written to `meta.xml` (bitmask: 1=JP, 2=US, 4=EU).
#[derive(Clone, Copy, Debug)]
pub enum Region {
    /// Japan.
    Japan,
    /// USA.
    Usa,
    /// Europe.
    Europe,
}

impl Region {
    fn code(self) -> u32 {
        match self {
            Region::Japan => 1,
            Region::Usa => 2,
            Region::Europe => 4,
        }
    }
}

/// Which console the source game is for. Selects the community art-repository key and the
/// `meta.xml` `drc_use` value; everything else in the packaging tail is platform-agnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    /// A Wii disc, injected as itself.
    Wii,
    /// A GameCube image, injected inside a synthetic Wii disc that boots Nintendont.
    GameCube,
}

impl Platform {
    /// The key the community art repository (UWUVCI-IMAGES) files a game's boot art under.
    pub fn art_key(self) -> &'static str {
        match self {
            Platform::Wii => "wii",
            Platform::GameCube => "gcn",
        }
    }

    /// The `meta.xml` `drc_use` value for this platform. A Wii inject exposes the GamePad only as
    /// a pointer (`1`), or not at all (`0`). A GameCube/Nintendont inject drives the emulated game
    /// with the GamePad, so it must also set bit 16 (`0x10000`) — "GamePad usable as a controller
    /// in vWii" — giving `0x10001` (and `1` when the GamePad is disabled). This mirrors the
    /// reference injector, which writes `65537` for GameCube and `1` for Wii; without bit 16, vWii
    /// never hands Nintendont the GamePad.
    pub fn drc_use(self, gamepad: bool) -> u32 {
        match (self, gamepad) {
            (Platform::GameCube, true) => 0x0001_0001,
            (Platform::GameCube, false) => 1,
            (Platform::Wii, true) => 1,
            (Platform::Wii, false) => 0,
        }
    }
}

/// Configuration for a single injection.
pub struct Config {
    /// Source Wii disc image (ISO/RVZ/…).
    pub input: PathBuf,
    /// Base title source (local `.wua`/directory, or an NUS download).
    pub base: Box<dyn BaseSource>,
    /// Output directory for the WUP package.
    pub out: PathBuf,
    /// Wii U common key (validated).
    pub wiiu_common_key: WiiUCommonKey,
    /// Certificate chain (`title.cert`).
    pub cert: CertChain,
    /// Override title string; if `None`, looked up on GameTDB.
    pub title: Option<String>,
    /// Optional PNG artwork overrides.
    pub icon_png: Option<PathBuf>,
    /// Optional TV boot image PNG.
    pub boot_tv_png: Option<PathBuf>,
    /// Optional GamePad boot image PNG.
    pub boot_drc_png: Option<PathBuf>,
    /// meta.xml region.
    pub region: Region,
    /// Whether the GamePad is usable (`drc_use`).
    pub gamepad: bool,
    /// Fetch missing art/title from online services.
    pub online: bool,
    /// Optional `main.dol` video patches (flicker filter / dithering). Wii path only.
    pub video: VideoPatches,
    /// Store the data partition sparsely by skipping inter-file gaps (normally `true`). When `false`
    /// the whole partition is stored. Wii path only.
    pub skip_gaps: bool,
    /// Also skip storing FST files whose entire content is zero (dummy/padding files); normally
    /// `false`. Wii path only. See [`crate::input::SourceDisc::used_data_group_runs`].
    pub trim_zeros: bool,
    /// When `Some`, the input is a GameCube image and is injected via Nintendont with these
    /// options (see [`run_gamecube`]). When `None`, the input is treated as a Wii disc.
    pub gamecube: Option<GameCubeOptions>,
}

/// Options for a GameCube (Nintendont) injection.
pub struct GameCubeOptions {
    /// Nintendont's `boot.dol`, used as the synthetic disc's `main.dol`.
    pub nintendont_dol: Vec<u8>,
    /// The Wii apploader placed in the synthetic disc. May be empty (the output then validates but
    /// will not boot on hardware — a real apploader is required for that).
    pub apploader: Vec<u8>,
    /// Force 16:9 in the generated `nincfg.bin`.
    pub widescreen: bool,
    /// GameCube language for `nincfg.bin`.
    pub language: nincfg::Language,
    /// Forced video mode for `nincfg.bin`.
    pub video_mode: nincfg::VideoMode,
    /// Emulate a memory card.
    pub memcard_emu: bool,
    /// Memory-card size exponent (`nincfg.bin` `MemCardBlocks`, `0..=4`; `2` ⇒ 251 blocks, the
    /// standard 512 KiB card). See [`nincfg::NincfgOptions::memcard_blocks`].
    pub memcard_blocks: u8,
    /// Maximum number of controllers (`0..=4`).
    pub max_pads: u32,
    /// Controller slot the Wii U GamePad occupies (`0..=3`).
    pub wiiu_gamepad_slot: u32,
    /// Optional Gecko cheat file path (on SD) recorded in `nincfg.bin`.
    pub cheat_path: Option<String>,
    /// Override the synthetic carrier disc's 6-character disc id (and the Wii disc title id
    /// derived from its first four characters). Defaults to the GameCube game's own id. The
    /// reference TeconMoon carrier disc is `CEMU69`.
    pub disc_id: Option<[u8; 6]>,
    /// Override the carrier disc's header title string. Defaults to `--title` / the game id. The
    /// reference carrier disc is `PunEmu 1.1`.
    pub disc_title: Option<String>,
}

/// Result of an injection.
#[derive(Debug, Clone)]
pub struct Summary {
    /// The derived Wii U title id.
    pub title_id: u64,
    /// The 6-character source game id.
    pub game_id: String,
    /// The resolved title string.
    pub title: String,
    /// Package statistics.
    pub package: PackageStats,
    /// Output directory.
    pub out: PathBuf,
}

/// Run the injection described by `config`, using `work_dir` as scratch space for the staged
/// build tree. `work_dir` should be empty; callers typically pass a fresh temp directory.
pub fn run(mut config: Config, work_dir: &Path) -> Result<Summary> {
    if config.gamecube.is_some() {
        return run_gamecube(config, work_dir);
    }

    log::info!("opening source disc {}", config.input.display());
    let mut source = SourceDisc::open(&config.input)?;
    let game_id = source.game_id_str();
    let disc4 = source.disc_id4();
    let ids = titleid::derive(disc4);

    // 1. Stage the base into work_dir/{code,content,meta}.
    log::info!("staging base title");
    let staged = config.base.stage(work_dir)?;

    // 2. Plan the whole-disc hash rebuild (RVZ/WIA zero the per-cluster hashes) plus any
    //    main.dol video patches (see crate::disc_patch).
    let plan = disc_patch::plan_disc(
        &mut source,
        &config.video,
        config.skip_gaps,
        config.trim_zeros,
    )?;

    // 3. Convert the disc to NFS under content/, rebuilding the Wii hash tree.
    log::info!("building NFS (this reads the whole disc)…");
    let nfs_stats = build_nfs(&mut source, &staged.htk, &staged.content_dir, &plan)?;
    log::info!(
        "NFS: {} file(s), {} bytes",
        nfs_stats.file_count,
        nfs_stats.total_bytes
    );

    // 4. Game ticket/TMD become rvlt.tik / rvlt.tmd. Both are fakesigned (RSA signature zeroed):
    //    fw.img's signature check is patched to accept a zeroed signature, and rejects the disc's
    //    real signature — so an unmodified ticket/TMD boots the framework but hangs the emulator.
    let mut rvlt_tik = source.raw_ticket().to_vec();
    fakesign(&mut rvlt_tik)?;
    std::fs::write(staged.code_dir.join("rvlt.tik"), &rvlt_tik)
        .map_err(|e| Error::io(staged.code_dir.join("rvlt.tik"), e))?;
    let mut rvlt_tmd = source.raw_tmd().to_vec();
    // Also updates the content hash to the rebuilt H3 table, and zeroes the signature.
    update_rvlt_tmd(&mut rvlt_tmd, &plan.rvlt_content_hash)?;
    std::fs::write(staged.code_dir.join("rvlt.tmd"), &rvlt_tmd)
        .map_err(|e| Error::io(staged.code_dir.join("rvlt.tmd"), e))?;

    // 5. Fakesign-patch fw.img so the (fakesigned) title is accepted.
    fwimg::patch_file(&staged.code_dir.join("fw.img"), fwimg::FAKESIGN_PATCHES)?;

    // 6-8. Metadata, boot textures, packaging (shared with the GameCube path).
    finish_package(&config, &staged, &ids, game_id, Platform::Wii, |_package| {
        Ok(())
    })
}

/// Run a GameCube injection: author a synthetic Wii disc that boots Nintendont (with the game as
/// `files/game.iso`), then reuse the Wii pipeline's NFS/packaging back half. Also emits an
/// `nincfg.bin` next to the output for the user's SD card.
fn run_gamecube(mut config: Config, work_dir: &Path) -> Result<Summary> {
    let mut gc_opts = config
        .gamecube
        .take()
        .expect("run() dispatches here only when gamecube options are present");

    log::info!("opening GameCube image {}", config.input.display());
    let mut gc = GcImage::open(&config.input)?;
    let game_id = gc.game_id_str();
    let game_id4 = gc.disc_id4();
    let ids = titleid::derive(game_id4);
    let iso_size = gc.iso_size();

    // 1. Stage the base title.
    log::info!("staging base title");
    let staged = config.base.stage(work_dir)?;

    // 2. Borrow the Wii cert chain (and, unless --apploader was given, a real apploader) from the
    // base title's own game disc; then author the synthetic Wii disc around them.
    let extras = base_disc_extras(&mut *config.base, work_dir, gc_opts.apploader.is_empty());
    if let Some(apploader) = extras.apploader {
        gc_opts.apploader = apploader;
    }
    let cert_chain = extras.cert_chain;

    let disc_title = gc_opts
        .disc_title
        .clone()
        .or_else(|| config.title.clone())
        .unwrap_or_else(|| game_id.clone());
    let disc_id = gc_opts.disc_id.unwrap_or_else(|| gc.game_id());
    let disc_path = work_dir.join("gc_disc.img");
    log::info!(
        "authoring synthetic Wii disc (embedding {} MiB game.iso)…",
        iso_size / (1024 * 1024)
    );
    let inputs = GcDiscInputs {
        game_id: disc_id,
        disc_title: &disc_title,
        main_dol: &gc_opts.nintendont_dol,
        apploader: &gc_opts.apploader,
        cert_chain: &cert_chain,
    };
    let mut authored = wii_author::author_gc_disc(gc.iso_stream(), iso_size, &inputs, &disc_path)?;

    // 3. Convert to NFS under content/, rebuilding the Wii hash tree.
    log::info!("building NFS (this reads the whole disc)…");
    let plan = authored.plan.clone();
    let nfs_stats = build_nfs(&mut authored, &staged.htk, &staged.content_dir, &plan)?;
    log::info!(
        "NFS: {} file(s), {} bytes",
        nfs_stats.file_count,
        nfs_stats.total_bytes
    );

    // Take the ticket/TMD out of the authored disc, which closes its open handle on the scratch
    // image. This must happen *before* the removal below: on Windows deleting a file that is
    // still open fails with a sharing violation, and on every platform the blocks stay allocated
    // until the last handle goes away. (`AuthoredDisc` owns the `File`, so a partial destructure
    // would not release it — see `AuthoredDisc::into_rvlt`.)
    let (rvlt_ticket, rvlt_tmd) = authored.into_rvlt();

    // The synthetic disc image (a full-disc-size scratch file) is only needed to build the NFS;
    // remove it now instead of leaving it in work_dir alongside the NFS content, which would
    // otherwise roughly double peak scratch usage for the rest of the build.
    remove_scratch_file(&disc_path)?;

    // 4. Write the synthetic disc's Wii ticket/TMD as rvlt.tik / rvlt.tmd.
    let tik_path = staged.code_dir.join("rvlt.tik");
    std::fs::write(&tik_path, &rvlt_ticket).map_err(|e| Error::io(&tik_path, e))?;
    let tmd_path = staged.code_dir.join("rvlt.tmd");
    std::fs::write(&tmd_path, &rvlt_tmd).map_err(|e| Error::io(&tmd_path, e))?;

    // 5. Patch fw.img: fakesign + homebrew (AHBPROT/MEMPROT) so Nintendont gets hardware access.
    fwimg::patch_file(&staged.code_dir.join("fw.img"), fwimg::HOMEBREW_PATCHES)?;

    // 6-8. Metadata, boot textures, packaging (shared with the Wii path). Step 9 (nincfg.bin) runs
    // as the packaging hook below, after build_package but before the Summary is built.
    finish_package(
        &config,
        &staged,
        &ids,
        game_id,
        Platform::GameCube,
        |_package| {
            // 9. Emit nincfg.bin next to the output package (it belongs at the SD-card root, not
            // in the WUP).
            let nincfg = nincfg::generate(&NincfgOptions {
                game_id: game_id4,
                widescreen: gc_opts.widescreen,
                language: gc_opts.language,
                video_mode: gc_opts.video_mode,
                memcard_emu: gc_opts.memcard_emu,
                memcard_blocks: gc_opts.memcard_blocks,
                max_pads: gc_opts.max_pads,
                wiiu_gamepad_slot: gc_opts.wiiu_gamepad_slot,
                cheat_path: gc_opts.cheat_path.clone(),
            })?;
            // Resolve --out to an absolute path first: a bare relative `--out` (e.g. `MyGame`,
            // with no parent component) would otherwise leave `parent()` ambiguous, landing
            // nincfg.bin wherever the process happens to be running from rather than reliably
            // next to the output.
            let out_abs =
                std::path::absolute(&config.out).map_err(|e| Error::io(&config.out, e))?;
            let nincfg_path = out_abs
                .parent()
                .unwrap_or(out_abs.as_path())
                .join("nincfg.bin");
            if nincfg_path.exists() {
                log::warn!(
                    "overwriting existing {} (each build's nincfg.bin is game-specific)",
                    nincfg_path.display()
                );
            }
            std::fs::write(&nincfg_path, nincfg).map_err(|e| Error::io(&nincfg_path, e))?;
            log::info!(
                "wrote {} — copy it to your SD card root for Nintendont. Note: Nintendont reads \
                 this ONE file for every GC inject, so its settings (widescreen, language, video \
                 mode, memory card, cheats, pads) apply to ALL installed GameCube titles",
                nincfg_path.display()
            );
            Ok(())
        },
    )
}

/// What the GameCube path borrows from the base title's own Wii game disc (see
/// [`base_disc_extras`]). Both fields are best-effort: an empty `cert_chain` or a `None`
/// `apploader` means the package will validate but not boot on hardware.
struct BaseDiscExtras {
    /// The Wii certificate chain, or empty if it could not be read.
    cert_chain: Vec<u8>,
    /// A genuine Wii apploader, if one was wanted and could be extracted.
    apploader: Option<Vec<u8>>,
}

/// Take from the base title's **original** game disc the two things a GameCube source disc can't
/// provide: the Wii certificate chain (always — the vWii framework needs it to validate the
/// fakesigned ticket/TMD) and, when `want_apploader`, a real Wii apploader. Both come from the
/// base's `content/hif_*.nfs`, materialized once under `work_dir`. The reference tools inherit both
/// the same way, by rebuilding the base's own disc.
///
/// Every failure is a warning rather than an error: the resulting package still builds and still
/// validates, it just won't boot on hardware — and saying so once, loudly, is more useful than
/// aborting a multi-GB build the user may well be running to inspect the rest of the output.
fn base_disc_extras(
    base: &mut dyn BaseSource,
    work_dir: &Path,
    want_apploader: bool,
) -> BaseDiscExtras {
    let mut extras = BaseDiscExtras {
        cert_chain: Vec::new(),
        apploader: None,
    };
    let nfs_scratch = work_dir.join("base_nfs");
    match base.materialize_original_nfs(&nfs_scratch) {
        Ok(Some(dir)) => {
            match crate::apploader::extract_cert_chain_from_nfs(&dir) {
                Ok(c) => {
                    log::info!(
                        "using the Wii cert chain from the base disc ({} bytes)",
                        c.len()
                    );
                    extras.cert_chain = c;
                }
                Err(e) => log::warn!(
                    "no cert chain: reading it from the base disc failed ({e}) — the package \
                     will validate but will NOT boot on hardware"
                ),
            }
            if want_apploader {
                match crate::apploader::extract_from_nfs(&dir) {
                    Ok(app) => {
                        log::info!(
                            "using the apploader from the base title's own game disc \
                             ({} bytes, {}, entry {:#010x})",
                            app.bytes.len(),
                            app.date,
                            app.entry
                        );
                        extras.apploader = Some(app.bytes);
                    }
                    Err(e) => log::warn!(
                        "no apploader: extracting one from the base failed ({e}) — the \
                         package will validate but will NOT boot on hardware (supply one \
                         with --apploader)"
                    ),
                }
            }
        }
        Ok(None) => log::warn!(
            "the base has no original game disc to take the cert chain / apploader from — \
             the package will validate but will NOT boot on hardware"
        ),
        Err(e) => log::warn!("could not read the base's original game disc ({e})"),
    }
    // The materialized copy (up to a few hundred MB) is only needed for the small reads above.
    // A failure here is not fatal — the whole work_dir is temporary — but it is worth saying,
    // since it leaves those hundreds of MB occupied for the rest of the build.
    if let Err(e) = std::fs::remove_dir_all(&nfs_scratch)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        log::warn!(
            "could not remove the scratch copy of the base disc at {} ({e})",
            nfs_scratch.display()
        );
    }
    extras
}

/// Delete a scratch file, reporting how much space it freed.
///
/// A file that is already gone is success (nothing to free); any other failure propagates, because
/// the files this is used on are disc-sized and silently leaving one behind can fill the user's
/// scratch volume mid-build.
fn remove_scratch_file(path: &Path) -> Result<()> {
    match std::fs::metadata(path).and_then(|m| {
        let len = m.len();
        std::fs::remove_file(path).map(|()| len)
    }) {
        Ok(freed) => log::info!(
            "removed scratch {} ({:.1} MiB freed)",
            path.display(),
            freed as f64 / (1024.0 * 1024.0)
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(path, e)),
    }
    Ok(())
}

/// Shared tail of both injection paths: regenerate `app.xml`/`meta.xml`, resolve the boot
/// textures, package the WUP, and build the `Summary`. `platform` selects the `drc_use` value and
/// the boot-art repository key (see [`Platform`]); `after_package` runs after `build_package` but
/// before the `Summary` is built (the GameCube path uses it to emit `nincfg.bin`; the Wii path
/// passes a no-op).
fn finish_package(
    config: &Config,
    staged: &StagedBase,
    ids: &titleid::TitleIds,
    game_id: String,
    platform: Platform,
    after_package: impl FnOnce(&PackageStats) -> Result<()>,
) -> Result<Summary> {
    let (code_dir, meta_dir) = (staged.code_dir.as_path(), staged.meta_dir.as_path());

    // 6. Metadata: app.xml + meta.xml.
    std::fs::write(code_dir.join("app.xml"), appxml::generate(ids))
        .map_err(|e| Error::io(code_dir.join("app.xml"), e))?;

    let title = resolve_title(config, &game_id);
    let meta_path = meta_dir.join("meta.xml");
    let base_meta = std::fs::read_to_string(&meta_path).map_err(|e| Error::io(&meta_path, e))?;
    let patched = patch_meta(
        &base_meta,
        &MetaOptions {
            ids,
            long_name: &title,
            short_name: &title,
            publisher: "",
            region: config.region.code(),
            drc_use: platform.drc_use(config.gamepad),
        },
    )?;
    std::fs::write(&meta_path, patched).map_err(|e| Error::io(&meta_path, e))?;

    // 7. Boot textures (icon / TV / DRC; UWUVCI-IMAGES keys GameCube art under "gcn").
    resolve_textures(config, platform, &game_id, meta_dir)?;

    // 8. Package.
    log::info!("packaging WUP into {}", config.out.display());
    let params = PackageParams {
        title_id: ids.title_id,
        group_id: (ids.group_id & 0xFFFF) as u16,
        wiiu_common_key: config.wiiu_common_key.0,
        title_key: TITLE_KEY,
        cert: &config.cert,
    };
    let package = build_package(&staged.build_dir, &config.out, &params)?;

    after_package(&package)?;

    Ok(Summary {
        title_id: ids.title_id,
        game_id,
        title,
        package,
        out: config.out.clone(),
    })
}

/// The title string written into `meta.xml`: `--title` if given, else GameTDB's name for the
/// game, else the raw game id.
fn resolve_title(config: &Config, game_id: &str) -> String {
    if let Some(t) = &config.title {
        return t.clone();
    }
    if config.online {
        match gametdb::lookup_title(game_id) {
            Some(name) => return name,
            // `lookup_title` already warns about *why* it came up empty (network, cache); what it
            // can't say is that this was the run's only chance at a real title, so the package is
            // about to be named "RSPE01" on the Wii U menu. Someone who passed `--online` for the
            // title needs to see that, not go looking for it in the finished meta.xml.
            None => log::warn!("no GameTDB title for {game_id}; using the game id as the title"),
        }
    }
    game_id.to_string()
}

/// Choose the GamePad (DRC) boot PNG: its own art if present, otherwise fall back to the TV
/// image so both screens show a matching splash (`png_to_tga` resizes it to the DRC dimensions;
/// both are 16:9, so there is no distortion). `None` when neither is available (keep the base's).
fn drc_source(drc: Option<Vec<u8>>, tv: &Option<Vec<u8>>) -> Option<Vec<u8>> {
    drc.or_else(|| tv.clone())
}

/// Write a boot texture from a user-supplied PNG, an online download, or leave the base's.
///
/// When no GamePad-specific art is found, the TV image is reused for `bootDrcTex` so both screens
/// match (the community art repos usually only carry the TV image).
fn resolve_textures(
    config: &Config,
    platform: Platform,
    game_id: &str,
    meta_dir: &Path,
) -> Result<()> {
    // Resolve a texture's source PNG: an override path, else an online download, else None.
    let resolve_src =
        |tex: BootTexture, override_png: &Option<PathBuf>| -> Result<Option<Vec<u8>>> {
            if let Some(path) = override_png {
                Ok(Some(std::fs::read(path).map_err(|e| Error::io(path, e))?))
            } else if config.online {
                Ok(artrepo::download_texture(platform.art_key(), game_id, tex))
            } else {
                Ok(None)
            }
        };
    let write_tex = |tex: BootTexture, bytes: &[u8]| -> Result<()> {
        let tga = png_to_tga(bytes, tex)?;
        let path = meta_dir.join(tex.filename());
        std::fs::write(&path, tga).map_err(|e| Error::io(&path, e))?;
        log::info!("wrote {}", tex.filename());
        Ok(())
    };
    // `download_texture` warns about *why* a fetch came up empty (404, network); what it can't say
    // is which texture therefore keeps whatever art the base title shipped with — the visible
    // outcome, and the one thing that isn't obvious from a successful build's output.
    let kept_base_art = |tex: BootTexture| {
        if config.online {
            log::info!(
                "no {} art for {game_id}; keeping the base title's",
                tex.filename()
            );
        }
    };

    if let Some(bytes) = resolve_src(BootTexture::Icon, &config.icon_png)? {
        write_tex(BootTexture::Icon, &bytes)?;
    } else {
        kept_base_art(BootTexture::Icon);
    }

    let tv = resolve_src(BootTexture::BootTv, &config.boot_tv_png)?;
    if let Some(bytes) = &tv {
        write_tex(BootTexture::BootTv, bytes)?;
    } else {
        kept_base_art(BootTexture::BootTv);
    }

    let drc_own = resolve_src(BootTexture::BootDrc, &config.boot_drc_png)?;
    if drc_own.is_none() && tv.is_some() {
        log::info!("no GamePad boot art found; reusing the TV image for bootDrcTex");
    }
    if let Some(bytes) = drc_source(drc_own, &tv) {
        write_tex(BootTexture::BootDrc, &bytes)?;
    } else {
        kept_base_art(BootTexture::BootDrc);
    }
    Ok(())
}

/// Fakesign a Wii ticket or TMD by zeroing its RSA signature. `fw.img`'s signature check is patched
/// to accept a zeroed signature, so `rvlt.tik`/`rvlt.tmd` must be fakesigned this way (their
/// original Nintendo signatures are rejected by the patched check and hang the emulator at boot).
///
/// A blob too short to hold the signature field is an error, not a no-op: silently skipping the
/// fakesign ships a `rvlt.tik`/`rvlt.tmd` that still carries a real signature, which the patched
/// `fw.img` rejects — the build "succeeds" and then hangs at boot on hardware, the hardest kind of
/// failure to diagnose.
fn fakesign(data: &mut [u8]) -> Result<()> {
    if data.len() < WII_SIG.end {
        return Err(Error::UnsupportedDisc(format!(
            "ticket/TMD is only {} bytes, too short to hold the RSA signature at 0x{:X}..0x{:X} \
             that must be zeroed to fakesign it (expected at least {} bytes)",
            data.len(),
            WII_SIG.start,
            WII_SIG.end,
            WII_SIG.end
        )));
    }
    data[WII_SIG].fill(0);
    Ok(())
}

/// After a `main.dol` patch or trim, point the Wii partition TMD's single content record at the
/// rebuilt H3 table and fakesign it. The Wii TMD stores the content hash at `0x1F4` and its
/// RSA-2048 signature at `0x004..0x104`.
///
/// Errors on a TMD too short to hold either field, for the same reason as [`fakesign`]: a skipped
/// content hash means the disc's rebuilt H3 table no longer matches the TMD, which fails at boot
/// rather than at build time.
fn update_rvlt_tmd(tmd: &mut [u8], content_hash: &[u8; 20]) -> Result<()> {
    if tmd.len() < TMD_CONTENT0_HASH + 20 {
        return Err(Error::UnsupportedDisc(format!(
            "TMD is only {} bytes, too short to hold the content hash at 0x{:X}..0x{:X} \
             (expected at least {} bytes)",
            tmd.len(),
            TMD_CONTENT0_HASH,
            TMD_CONTENT0_HASH + 20,
            TMD_CONTENT0_HASH + 20
        )));
    }
    fakesign(tmd)?;
    tmd[TMD_CONTENT0_HASH..TMD_CONTENT0_HASH + 20].copy_from_slice(content_hash);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drc_use_is_gamepad_controller_on_gamecube_only() {
        // GameCube drives the game with the GamePad, so it sets bit 16 (0x10001); Wii uses it only
        // as a pointer (1). Disabling the GamePad drops to 1 (GC) / 0 (Wii).
        assert_eq!(Platform::GameCube.drc_use(true), 0x0001_0001);
        assert_eq!(Platform::GameCube.drc_use(false), 1);
        assert_eq!(Platform::Wii.drc_use(true), 1);
        assert_eq!(Platform::Wii.drc_use(false), 0);
    }

    /// The art-repository keys are wire values: UWUVCI-IMAGES files GameCube art under "gcn", not
    /// "gc" or "gamecube", and a typo here silently means "no art found" for every GC inject.
    #[test]
    fn art_key_matches_the_repository_layout() {
        assert_eq!(Platform::Wii.art_key(), "wii");
        assert_eq!(Platform::GameCube.art_key(), "gcn");
    }

    /// A scratch file that is already gone is not an error — the build has nothing left to free
    /// and no reason to fail — but one that exists must actually be deleted.
    #[test]
    fn remove_scratch_file_deletes_and_tolerates_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gc_disc.img");
        std::fs::write(&path, b"scratch").unwrap();

        remove_scratch_file(&path).unwrap();
        assert!(!path.exists(), "the scratch file should be gone");

        // Second call: nothing to remove, still Ok.
        remove_scratch_file(&path).unwrap();
    }

    /// The signature field ends at 0x104. A blob one byte short must be an error, not a silent
    /// skip — a `rvlt.tik`/`rvlt.tmd` that keeps its real signature is rejected by the patched
    /// `fw.img` and hangs at boot, long after the build reported success.
    #[test]
    fn fakesign_errors_on_a_short_blob_and_zeroes_the_signature_otherwise() {
        let mut short = vec![0xAAu8; WII_SIG.end - 1];
        let err = fakesign(&mut short).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedDisc(_)),
            "expected an unsupported-disc error, got {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains(&(WII_SIG.end - 1).to_string()) && msg.contains(&WII_SIG.end.to_string()),
            "error should give the actual and the required length: {msg}"
        );

        // Exactly long enough: the signature is zeroed and nothing else is touched.
        let mut exact = vec![0xAAu8; WII_SIG.end];
        fakesign(&mut exact).unwrap();
        assert_eq!(&exact[..WII_SIG.start], &[0xAA; 4]);
        assert!(exact[WII_SIG].iter().all(|&b| b == 0));
    }

    /// Same boundary for the TMD, which additionally writes the content hash at 0x1F4.
    #[test]
    fn update_rvlt_tmd_errors_on_a_short_tmd_and_writes_both_fields_otherwise() {
        let hash = [0x5Au8; 20];
        let min = TMD_CONTENT0_HASH + 20;

        let mut short = vec![0xAAu8; min - 1];
        let err = update_rvlt_tmd(&mut short, &hash).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedDisc(_)),
            "expected an unsupported-disc error, got {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains(&(min - 1).to_string()) && msg.contains(&min.to_string()),
            "error should give the actual and the required length: {msg}"
        );
        assert_eq!(short, vec![0xAAu8; min - 1], "a rejected TMD is untouched");

        let mut exact = vec![0xAAu8; min];
        update_rvlt_tmd(&mut exact, &hash).unwrap();
        assert!(exact[WII_SIG].iter().all(|&b| b == 0), "signature zeroed");
        assert_eq!(
            &exact[TMD_CONTENT0_HASH..min],
            &hash,
            "content hash written"
        );
    }

    #[test]
    fn drc_uses_own_art_when_present() {
        let drc = Some(vec![1, 2, 3]);
        let tv = Some(vec![9, 9]);
        assert_eq!(drc_source(drc, &tv), Some(vec![1, 2, 3]));
    }

    #[test]
    fn drc_falls_back_to_tv_when_absent() {
        let tv = Some(vec![9, 9]);
        assert_eq!(drc_source(None, &tv), Some(vec![9, 9]));
    }

    #[test]
    fn drc_is_none_when_neither_present() {
        assert_eq!(drc_source(None, &None), None);
    }
}
