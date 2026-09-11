//! Decode content 0 (the FST) of a WUP package and dump its content table (secondary headers).
//! Run: cargo run -p wiivci-core --release --example fst_ctable -- <wup_dir>
mod common;

use std::path::Path;
use wiivci_core::package::content_crypto::{decode_hashed, decode_nonhashed};
use wiivci_core::package::fst::Fst;
use wiivci_core::package::tmd::parse_content_records;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    common::usage_or_exit(&args, 1, "usage: fst_ctable <wup_dir>");
    let wup = Path::new(&args[0]);
    let tmd = std::fs::read(wup.join("title.tmd"))?;
    let records = parse_content_records(&tmd)?;
    let fst_rec = records
        .iter()
        .find(|r| r.index == 0)
        .ok_or_else(|| anyhow::anyhow!("no content index 0 (FST) in title.tmd"))?;
    let cipher = common::read_app(wup, fst_rec.id)?;
    let fst_data = if fst_rec.content_type == 0x2003 {
        decode_hashed(&common::DUMMY_TITLE_KEY, 0, &cipher)
    } else {
        decode_nonhashed(&common::DUMMY_TITLE_KEY, 0, &cipher)
    }?;
    let fst = Fst::parse(&fst_data).ok_or_else(|| anyhow::anyhow!("failed to parse FST"))?;
    println!(
        "offset_factor={:#x} contents={} nodes={}",
        fst.offset_factor,
        fst.contents.len(),
        fst.nodes.len()
    );
    println!(
        "{:>3} | {:>12} {:>12} | {:>16} {:>10} {:>6}",
        "i", "off_sec", "size_sec", "owner_title_id", "group_id", "flags"
    );
    for (i, c) in fst.contents.iter().enumerate() {
        println!(
            "{i:>3} | {:>12} {:>12} | {:016x} {:>#10x} {:>#6x}",
            c.offset_sectors, c.size_sectors, c.owner_title_id, c.group_id, c.flags
        );
    }
    Ok(())
}
