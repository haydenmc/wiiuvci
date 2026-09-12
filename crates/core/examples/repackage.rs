//! Repackage an already-staged build tree (code/content/meta) through the CURRENT build_package,
//! for isolating packaging structure from disc/game data. Uses the dummy title key (0x1337..).
//! Run: WIIU_COMMON_KEY=<32hex or key file> cargo run -p wiivci-core --release --example repackage -- <staged_dir> <out> <cert_path> <title_id_hex>
mod common;

use std::path::Path;
use wiivci_core::package::cert::CertChain;
use wiivci_core::package::{PackageParams, build_package};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    common::usage_or_exit(
        &args,
        4,
        "usage: repackage <staged_dir> <out> <cert_path> <title_id_hex>",
    );
    let staged = &args[0];
    let out = &args[1];
    let cert_path = &args[2];
    let title_id = u64::from_str_radix(&args[3], 16)?;

    let ckey = common::wiiu_common_key()?;
    let cert = CertChain::load(Path::new(cert_path))?;
    let params = PackageParams {
        title_id,
        group_id: (title_id & 0xFFFF) as u16,
        wiiu_common_key: ckey.0,
        title_key: common::DUMMY_TITLE_KEY,
        cert: &cert,
    };
    let stats = build_package(Path::new(staged), Path::new(out), &params)?;
    println!(
        "packaged {} contents, {} bytes into {out}",
        stats.content_count, stats.total_content_bytes
    );
    Ok(())
}
