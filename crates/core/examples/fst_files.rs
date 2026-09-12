//! Dump the package FST (content 0): each file's path -> content index, offset, size.
//! Run: cargo run -p wiiuvci-core --release --example fst_files -- <wup_dir>
mod common;

use std::path::Path;
use wiiuvci_core::package::content_crypto::{decode_hashed, decode_nonhashed};
use wiiuvci_core::package::extract::node_paths;
use wiiuvci_core::package::fst::{Fst, FstNodeKind};
use wiiuvci_core::package::tmd::parse_content_records;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    common::usage_or_exit(&args, 1, "usage: fst_files <wup_dir>");
    let wup = Path::new(&args[0]);
    let tmd = std::fs::read(wup.join("title.tmd"))?;
    let records = parse_content_records(&tmd)?;
    let fst_rec = records
        .iter()
        .find(|r| r.index == 0)
        .ok_or_else(|| anyhow::anyhow!("no content index 0 (FST) in title.tmd"))?;
    let cipher = common::read_app(wup, fst_rec.id)?;
    let data = if fst_rec.content_type == 0x2003 {
        decode_hashed(&common::DUMMY_TITLE_KEY, 0, &cipher)
    } else {
        decode_nonhashed(&common::DUMMY_TITLE_KEY, 0, &cipher)
    }?;
    let fst = Fst::parse(&data).ok_or_else(|| anyhow::anyhow!("failed to parse FST"))?;
    let paths = node_paths(&fst);

    println!("content-type per content index:");
    for (i, c) in fst.contents.iter().enumerate() {
        let rec = records.iter().find(|r| r.index as usize == i);
        println!(
            "  content {i}: type={:#06x} group={:#x} owner={:016x}",
            rec.map(|r| r.content_type).unwrap_or(0),
            c.group_id,
            c.owner_title_id
        );
    }
    println!("\nfile -> content @offset:");
    let mut rows: Vec<(u16, u64, String, u64)> = Vec::new();
    for (i, node) in fst.nodes.iter().enumerate() {
        if let FstNodeKind::File { size, offset } = node.kind {
            rows.push((node.cluster, offset, paths[i].clone(), size));
        }
    }
    rows.sort();
    for (cluster, offset, path, size) in rows {
        println!("  [c{cluster:>2}] @{offset:>10} {path} ({size})");
    }
    Ok(())
}
