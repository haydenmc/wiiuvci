//! `wiivci` — inject a Wii game into a Wii U Virtual Console (WUP) package.
//!
//! Copyright (C) 2026 Hayden. Licensed under the GNU General Public License, version 3 or
//! later. This program comes with ABSOLUTELY NO WARRANTY. See the LICENSE file for details.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{ArgGroup, Parser, ValueEnum};

use wiivci_core::assets::nintendont;
use wiivci_core::base::{open_base, BaseSource};
use wiivci_core::input::{probe, DiscKind};
use wiivci_core::keys::WiiUCommonKey;
use wiivci_core::nincfg::{Language, VideoMode};
use wiivci_core::nus::{NusBase, NusClient};
use wiivci_core::package::cert::CertChain;
use wiivci_core::pipeline::{self, Config, GameCubeOptions, Region};
use wiivci_core::video::VideoPatches;

/// Inject a Wii game (ISO/RVZ) into an installable Wii U Virtual Console package.
#[derive(Parser, Debug)]
#[command(name = "wiivci", version, about)]
#[command(group(ArgGroup::new("base_src").required(true).args(["base", "base_title_id"])))]
struct Cli {
    /// Source Wii disc image (ISO, RVZ, WBFS, …).
    #[arg(short, long)]
    input: PathBuf,

    /// Base Wii U VC title: a Cemu `.wua` archive or an extracted title directory.
    #[arg(short, long)]
    base: Option<PathBuf>,

    /// Instead of --base, download the base from NUS: its 16-hex title id
    /// (e.g. 00050000101B0700). Requires --base-title-key.
    #[arg(long, value_name = "HEX16")]
    base_title_id: Option<String>,

    /// Encrypted title key (32 hex) for the NUS base title, as found in title-key databases.
    #[arg(long, value_name = "HEX32", requires = "base_title_id")]
    base_title_key: Option<String>,

    /// Specific base TMD version to download (default: latest).
    #[arg(long, value_name = "N", requires = "base_title_id")]
    base_version: Option<u32>,

    /// Override the NUS/CCS base URL (default: the Nintendo CCS CDN).
    #[arg(long, value_name = "URL", requires = "base_title_id")]
    nus_url: Option<String>,

    /// Output directory for the WUP package (created if absent).
    #[arg(short, long)]
    out: PathBuf,

    /// Wii U common key: 32 hex chars, or a path to a 16-byte / hex key file.
    #[arg(long, value_name = "KEY|FILE", env = "WIIU_COMMON_KEY")]
    wiiu_common_key: String,

    /// Certificate chain (`title.cert`) from any dumped Wii U title.
    #[arg(long, value_name = "FILE")]
    cert: PathBuf,

    /// Title name shown on the Wii U menu (default: looked up on GameTDB when online).
    #[arg(long)]
    title: Option<String>,

    /// Override the 128x128 icon (PNG).
    #[arg(long, value_name = "PNG")]
    icon: Option<PathBuf>,

    /// Override the 1280x720 TV boot image (PNG).
    #[arg(long, value_name = "PNG")]
    boot_tv: Option<PathBuf>,

    /// Override the 854x480 GamePad boot image (PNG).
    #[arg(long, value_name = "PNG")]
    boot_drc: Option<PathBuf>,

    /// Target region written to meta.xml.
    #[arg(long, value_enum, default_value_t = RegionArg::Us)]
    region: RegionArg,

    /// Mark the GamePad as unusable (sets drc_use = 0).
    #[arg(long)]
    no_gamepad: bool,

    /// Disable all network lookups (GameTDB title + cover art).
    #[arg(long)]
    offline: bool,

    /// Remove the video flicker filter (patches the game's main.dol for a sharper image).
    #[arg(long)]
    deflicker: bool,

    /// Halve the vertical filter instead of removing it (softer than --deflicker).
    #[arg(long)]
    half_vfilter: bool,

    /// Remove framebuffer dithering (better colour accuracy).
    #[arg(long)]
    remove_dithering: bool,

    /// Store the whole partition instead of skipping unused inter-file gaps (much larger NFS).
    #[arg(long)]
    keep_gaps: bool,

    /// Skip storing dummy/padding files whose entire content is zero (smaller NFS; off by default).
    #[arg(long)]
    trim_zeros: bool,

    /// Force GameCube (Nintendont) mode. Normally auto-detected from the input image.
    #[arg(long)]
    gamecube: bool,

    /// GameCube: Nintendont autoboot-forwarder `.dol` to use as the disc's main.dol
    /// (default: downloaded, pinned FIX94 forwarder). Nintendont itself must be on the SD card.
    #[arg(long, value_name = "DOL")]
    nintendont: Option<PathBuf>,

    /// GameCube: Wii `apploader.img` for the synthetic disc (default: extracted from the base
    /// title's own game disc).
    #[arg(long, value_name = "IMG")]
    apploader: Option<PathBuf>,

    /// Force 16:9 widescreen.
    #[arg(long, help_heading = GC_NINCFG_HEADING)]
    widescreen: bool,

    /// Game language.
    #[arg(long, value_enum, default_value_t = GcLangArg::Auto, help_heading = GC_NINCFG_HEADING)]
    gc_language: GcLangArg,

    /// Forced video mode (`progressive` = 480p).
    #[arg(long, value_enum, default_value_t = GcVideoArg::Auto, help_heading = GC_NINCFG_HEADING)]
    gc_video: GcVideoArg,

    /// Disable emulated memory card.
    #[arg(long, help_heading = GC_NINCFG_HEADING)]
    no_memcard: bool,

    /// Emulated memory-card size in blocks: 59, 123, 251, 507 or 1019.
    #[arg(long, value_name = "BLOCKS", default_value = "251",
          value_parser = parse_memcard_size, help_heading = GC_NINCFG_HEADING)]
    gc_memcard_blocks: u8,

    /// Maximum number of controllers.
    #[arg(long, value_name = "N", default_value_t = 4,
          value_parser = clap::value_parser!(u32).range(0..=4), help_heading = GC_NINCFG_HEADING)]
    gc_max_pads: u32,

    /// Controller slot the Wii U GamePad occupies.
    #[arg(long, value_name = "SLOT", default_value_t = 0,
          value_parser = clap::value_parser!(u32).range(0..=3), help_heading = GC_NINCFG_HEADING)]
    gc_gamepad_slot: u32,

    /// SD path to a Gecko cheat file (`.gct`); enables cheats.
    #[arg(long, value_name = "SDPATH", help_heading = GC_NINCFG_HEADING)]
    cheats: Option<String>,

    /// Keep the intermediate build directory instead of deleting it.
    #[arg(long, value_name = "DIR")]
    work_dir: Option<PathBuf>,
}

/// Help section for the settings written into `nincfg.bin`. Nintendont reads that ONE file from
/// the SD-card root for every GameCube inject, so these are effectively global — the most
/// recently copied `nincfg.bin` applies to ALL installed GC titles.
const GC_NINCFG_HEADING: &str =
    "GameCube settings (nincfg.bin — shared by EVERY GC inject on the SD card)";

/// Map a Nintendont memory-card size in blocks to the `MemCardBlocks` exponent
/// (`blocks = (1 << (x + 6)) - 5`).
fn parse_memcard_size(s: &str) -> std::result::Result<u8, String> {
    match s {
        "59" => Ok(0),
        "123" => Ok(1),
        "251" => Ok(2),
        "507" => Ok(3),
        "1019" => Ok(4),
        _ => Err("memory-card size must be one of 59, 123, 251, 507 or 1019 blocks".into()),
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum GcVideoArg {
    Auto,
    Ntsc,
    Pal50,
    Pal60,
    Mpal,
    Progressive,
    None,
}

impl From<GcVideoArg> for VideoMode {
    fn from(v: GcVideoArg) -> Self {
        match v {
            GcVideoArg::Auto => VideoMode::Auto,
            GcVideoArg::Ntsc => VideoMode::ForceNtsc,
            GcVideoArg::Pal50 => VideoMode::ForcePal50,
            GcVideoArg::Pal60 => VideoMode::ForcePal60,
            GcVideoArg::Mpal => VideoMode::ForceMpal,
            GcVideoArg::Progressive => VideoMode::ForceProgressive,
            GcVideoArg::None => VideoMode::None,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum GcLangArg {
    Auto,
    English,
    German,
    French,
    Spanish,
    Italian,
    Dutch,
}

impl From<GcLangArg> for Language {
    fn from(l: GcLangArg) -> Self {
        match l {
            GcLangArg::Auto => Language::Auto,
            GcLangArg::English => Language::English,
            GcLangArg::German => Language::German,
            GcLangArg::French => Language::French,
            GcLangArg::Spanish => Language::Spanish,
            GcLangArg::Italian => Language::Italian,
            GcLangArg::Dutch => Language::Dutch,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum RegionArg {
    Jp,
    Us,
    Eu,
}

impl From<RegionArg> for Region {
    fn from(r: RegionArg) -> Self {
        match r {
            RegionArg::Jp => Region::Japan,
            RegionArg::Us => Region::Usa,
            RegionArg::Eu => Region::Europe,
        }
    }
}

/// Parse exactly `N` hex bytes from a string (ignoring surrounding whitespace).
fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    let s = s.trim();
    if s.len() != N * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("expected {} hex characters, got {:?}", N * 2, s));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    Ok(out)
}

/// Build the base source from the CLI: a local path, or an NUS download.
fn build_base(cli: &Cli, wiiu_common_key: &WiiUCommonKey) -> Result<Box<dyn BaseSource>> {
    if let Some(path) = &cli.base {
        return open_base(path).with_context(|| format!("opening base {}", path.display()));
    }
    // NUS path (validated present by the arg group).
    let title_id_hex = cli
        .base_title_id
        .as_ref()
        .expect("arg group guarantees this");
    let title_id = u64::from_str_radix(title_id_hex.trim(), 16)
        .with_context(|| format!("invalid --base-title-id {title_id_hex:?}"))?;
    let key_hex = cli
        .base_title_key
        .as_ref()
        .ok_or_else(|| anyhow!("--base-title-key is required with --base-title-id"))?;
    let enc_title_key = parse_hex::<16>(key_hex).context("invalid --base-title-key")?;
    let client = match &cli.nus_url {
        Some(url) => NusClient::with_base_url(url),
        None => NusClient::new(),
    }?;
    Ok(Box::new(NusBase::new(
        title_id,
        enc_title_key,
        wiiu_common_key.0,
        cli.base_version,
        client,
    )))
}

/// Resolve GameCube (Nintendont) options: obtain Nintendont's `boot.dol` (a local file or a
/// pinned download) and the optional apploader, plus nincfg settings.
fn build_gc_options(cli: &Cli) -> Result<GameCubeOptions> {
    let nintendont_dol = match &cli.nintendont {
        Some(path) => std::fs::read(path)
            .with_context(|| format!("reading Nintendont dol {}", path.display()))?,
        None => {
            if cli.offline {
                return Err(anyhow!(
                    "--nintendont <boot.dol> is required with --offline (cannot download Nintendont)"
                ));
            }
            nintendont::download_boot_dol().context(
                "downloading Nintendont (supply one with --nintendont to avoid the network)",
            )?
        }
    };
    let apploader = match &cli.apploader {
        Some(path) => {
            std::fs::read(path).with_context(|| format!("reading apploader {}", path.display()))?
        }
        None => Vec::new(),
    };
    Ok(GameCubeOptions {
        nintendont_dol,
        apploader,
        widescreen: cli.widescreen,
        language: cli.gc_language.into(),
        video_mode: cli.gc_video.into(),
        memcard_emu: !cli.no_memcard,
        memcard_blocks: cli.gc_memcard_blocks,
        max_pads: cli.gc_max_pads,
        wiiu_gamepad_slot: cli.gc_gamepad_slot,
        cheat_path: cli.cheats.clone(),
    })
}

/// Prepare a user-supplied `--work-dir`: create it if absent, but refuse to reuse an existing
/// non-empty directory. `pipeline::run` stages the base title and NFS content by writing new
/// files into `work_dir/content/` without clearing what's already there, so leftover files from a
/// previous (e.g. larger) build — notably stale `hif_*.nfs` — would silently get packaged into
/// the new title. Erroring out is safer than deleting a directory the user pointed us at.
fn prepare_work_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating work dir {}", dir.display()))?;
    let mut entries =
        std::fs::read_dir(dir).with_context(|| format!("reading work dir {}", dir.display()))?;
    if entries.next().is_some() {
        return Err(anyhow!(
            "--work-dir {} already exists and is not empty; empty it or pick another path \
             (reusing a dirty work dir can package stale leftover files, e.g. from a previous build)",
            dir.display()
        ));
    }
    Ok(())
}

/// Load a key from either an inline hex string or a file path.
fn load_wiiu_key(arg: &str) -> Result<WiiUCommonKey> {
    let path = std::path::Path::new(arg);
    let raw = if path.is_file() {
        std::fs::read(path).with_context(|| format!("reading key file {}", path.display()))?
    } else {
        arg.as_bytes().to_vec()
    };
    WiiUCommonKey::parse(&raw).context("invalid Wii U common key")
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    let wiiu_common_key = load_wiiu_key(&cli.wiiu_common_key)?;
    let cert = CertChain::load(&cli.cert)
        .with_context(|| format!("loading certificate chain {}", cli.cert.display()))?;
    let base = build_base(&cli, &wiiu_common_key)?;

    // GameCube mode: explicit flag or auto-detected from the input image.
    let is_gamecube = cli.gamecube || matches!(probe(&cli.input), Ok(DiscKind::GameCube));
    if is_gamecube && (cli.deflicker || cli.half_vfilter || cli.remove_dithering) {
        eprintln!("note: --deflicker/--half-vfilter/--remove-dithering are Wii-only and ignored for GameCube");
    }
    let gamecube = if is_gamecube {
        Some(build_gc_options(&cli)?)
    } else {
        None
    };

    let config = Config {
        input: cli.input,
        base,
        out: cli.out,
        wiiu_common_key,
        cert,
        title: cli.title,
        icon_png: cli.icon,
        boot_tv_png: cli.boot_tv,
        boot_drc_png: cli.boot_drc,
        region: cli.region.into(),
        gamepad: !cli.no_gamepad,
        online: !cli.offline,
        video: VideoPatches {
            deflicker: cli.deflicker,
            half_vfilter: cli.half_vfilter,
            dithering: cli.remove_dithering,
        },
        skip_gaps: !cli.keep_gaps,
        trim_zeros: cli.trim_zeros,
        gamecube,
    };

    // Use a caller-provided work dir, or a temp dir cleaned up on completion.
    let (work_path, _guard) = match &cli.work_dir {
        Some(dir) => {
            prepare_work_dir(dir)?;
            (dir.clone(), None)
        }
        None => {
            let tmp = tempfile::tempdir().context("creating temp work dir")?;
            (tmp.path().to_path_buf(), Some(tmp))
        }
    };

    let summary = pipeline::run(config, &work_path)?;

    println!("\nDone.");
    println!("  Game:      {} ({})", summary.title, summary.game_id);
    println!("  Title ID:  {:016X}", summary.title_id);
    println!(
        "  Package:   {} content file(s), {:.1} MiB",
        summary.package.content_count,
        summary.package.total_content_bytes as f64 / (1024.0 * 1024.0)
    );
    println!("  Output:    {}", summary.out.display());
    println!("\nInstall the output folder with WUP Installer GX2 (sd:/install/<name>/).");
    println!("The target console needs signature patches (Aroma/Tiramisu) to install and boot.");
    if is_gamecube {
        println!(
            "GameCube: also copy the generated nincfg.bin (next to the output) to your SD card root."
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod gc_flag_tests {
    use super::*;
    use clap::Parser;

    /// Minimal valid argv; append GC flags per test.
    fn parse(extra: &[&str]) -> Cli {
        let mut argv = vec![
            "wiivci",
            "-i",
            "game.rvz",
            "-b",
            "base.wua",
            "-o",
            "out",
            "--wiiu-common-key",
            "00000000000000000000000000000000",
            "--cert",
            "title.cert",
        ];
        argv.extend_from_slice(extra);
        Cli::try_parse_from(argv).expect("argv must parse")
    }

    #[test]
    fn nincfg_flag_defaults_match_the_previous_hardcoded_values() {
        let cli = parse(&[]);
        assert!(matches!(cli.gc_video, GcVideoArg::Auto));
        assert_eq!(cli.gc_memcard_blocks, 2, "251 blocks ⇒ exponent 2");
        assert_eq!(cli.gc_max_pads, 4);
        assert_eq!(cli.gc_gamepad_slot, 0);
        assert!(!cli.no_memcard);
        assert!(!cli.widescreen);
    }

    #[test]
    fn nincfg_flags_parse_and_map() {
        let cli = parse(&[
            "--gc-video",
            "progressive",
            "--gc-memcard-blocks",
            "1019",
            "--gc-max-pads",
            "2",
            "--gc-gamepad-slot",
            "1",
        ]);
        assert!(matches!(
            VideoMode::from(cli.gc_video),
            VideoMode::ForceProgressive
        ));
        assert_eq!(cli.gc_memcard_blocks, 4, "1019 blocks ⇒ exponent 4");
        assert_eq!(cli.gc_max_pads, 2);
        assert_eq!(cli.gc_gamepad_slot, 1);
    }

    #[test]
    fn memcard_size_accepts_only_nintendont_sizes() {
        for (blocks, exp) in [("59", 0u8), ("123", 1), ("251", 2), ("507", 3), ("1019", 4)] {
            assert_eq!(parse_memcard_size(blocks).unwrap(), exp);
        }
        assert!(parse_memcard_size("512").is_err());
        assert!(parse_memcard_size("0").is_err());
        assert!(Cli::try_parse_from([
            "wiivci",
            "-i",
            "g",
            "-b",
            "b",
            "-o",
            "o",
            "--wiiu-common-key",
            "00000000000000000000000000000000",
            "--cert",
            "c",
            "--gc-memcard-blocks",
            "512"
        ])
        .is_err());
    }

    #[test]
    fn out_of_range_pads_and_slot_are_rejected() {
        for bad in [["--gc-max-pads", "5"], ["--gc-gamepad-slot", "4"]] {
            let mut argv = vec![
                "wiivci",
                "-i",
                "g",
                "-b",
                "b",
                "-o",
                "o",
                "--wiiu-common-key",
                "00000000000000000000000000000000",
                "--cert",
                "c",
            ];
            argv.extend_from_slice(&bad);
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }
}

#[cfg(test)]
mod work_dir_tests {
    use super::prepare_work_dir;

    #[test]
    fn accepts_missing_dir_by_creating_it() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("fresh");
        assert!(!dir.exists());
        prepare_work_dir(&dir).unwrap();
        assert!(dir.is_dir());
    }

    #[test]
    fn accepts_existing_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        prepare_work_dir(dir.path()).unwrap();
    }

    #[test]
    fn rejects_existing_nonempty_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("leftover.txt"), b"stale").unwrap();
        let err = prepare_work_dir(dir.path()).unwrap_err();
        assert!(err.to_string().contains("not empty"));
        // The stale file must be left untouched, not deleted.
        assert!(dir.path().join("leftover.txt").exists());
    }

    #[test]
    fn rejects_existing_dir_with_stale_subdir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("content")).unwrap();
        let err = prepare_work_dir(dir.path()).unwrap_err();
        assert!(err.to_string().contains("not empty"));
    }
}
