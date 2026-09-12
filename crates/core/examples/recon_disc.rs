//! Dev utility: reconstruct the mountable NFS/disc from a WUP package directory, so it can be
//! reopened with `nod` and compared structurally against another disc.
//! Writes <out>/content/hif_%06d.nfs and <out>/code/htk.bin (the layout nod's NFS reader wants).
//! Run: WIIU_COMMON_KEY=<32hex or key file> cargo run -p wiivci-core --release --example recon_disc -- <wup_dir> <out_dir>
mod common;

use std::path::Path;
use wiivci_core::package::extract::extract_title;
use wiivci_core::package::tmd::parse_content_records;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    common::usage_or_exit(&args, 2, "usage: recon_disc <wup_dir> <out_dir>");
    let wup = Path::new(&args[0]);
    let out = &args[1];

    let common_key = common::wiiu_common_key()?;
    let tmd = std::fs::read(wup.join("title.tmd"))?;
    let tik = std::fs::read(wup.join("title.tik"))?;
    let title_id = common::title_id_from_tik(&tik)?;
    let title_key = common::title_key_from_tik(&tik, &common_key)?;
    println!(
        "title_id={title_id:016x} title_key={}",
        common::hex(&title_key)
    );

    let records = parse_content_records(&tmd)?;
    let reader = |id: u32| -> wiivci_core::error::Result<Vec<u8>> {
        common::read_app(wup, id)
            .map_err(|e| wiivci_core::error::Error::InvalidTitle(e.to_string()))
    };
    std::fs::create_dir_all(out)?;
    // Extract everything, including hif_*.nfs (skip nothing).
    extract_title(&records, &title_key, &reader, Path::new(&out), |_| false)?;
    println!("reconstructed into {out}");
    Ok(())
}
