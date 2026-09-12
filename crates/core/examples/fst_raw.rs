//! Parse an already-decrypted package FST (e.g. .dev/wup_ref/fst_decrypted.bin) and dump the
//! file -> content mapping. Run: cargo run -p wiiuvci-core --release --example fst_raw -- <fst.bin>
mod common;

use wiiuvci_core::package::extract::node_paths;
use wiiuvci_core::package::fst::{Fst, FstNodeKind};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    common::usage_or_exit(&args, 1, "usage: fst_raw <fst.bin>");
    let data = std::fs::read(&args[0])?;
    let fst = Fst::parse(&data).ok_or_else(|| anyhow::anyhow!("failed to parse FST"))?;
    let paths = node_paths(&fst);

    for (i, c) in fst.contents.iter().enumerate() {
        println!(
            "content {i}: group={:#x} owner={:016x} flags={:#x}",
            c.group_id, c.owner_title_id, c.flags
        );
    }
    println!("\nfile -> content (offset within content):");
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
