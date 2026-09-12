//! Dev utility: report the data-partition file layout of a Wii disc.
//! Prints partition data size vs. the highest file end offset (to distinguish
//! "trailing padding only" from "gap with files near the end").
//! Run: cargo run -p wiivci-core --release --example fst_layout -- <disc>
mod common;

use std::path::Path;

use nod::{PartitionKind, SECTOR_SIZE};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    common::usage_or_exit(&args, 1, "usage: fst_layout <disc>");
    let disc = common::open_decrypted_disc(Path::new(&args[0]))?;
    let is_wii = disc.header().is_wii();
    println!("is_wii={is_wii} disc_size={}", disc.disc_size());
    for p in disc.partitions() {
        println!(
            "partition idx={} kind={:?} start_sector={} data_start={} data_end={} data_bytes={}",
            p.index,
            p.kind,
            p.start_sector,
            p.data_start_sector,
            p.data_end_sector,
            (p.data_end_sector as u64 - p.data_start_sector as u64) * SECTOR_SIZE as u64
        );
    }
    let mut part = disc.open_partition_kind(PartitionKind::Data)?;
    let meta = part.meta()?;
    let fst = meta.fst().map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut max_end: u64 = 0;
    let mut max_name = String::new();
    let mut count = 0u64;
    for (_, node, name) in fst.iter() {
        if node.is_dir() {
            continue;
        }
        count += 1;
        let off = node.offset(is_wii);
        let len = node.length();
        let end = off + len;
        if end > max_end {
            max_end = end;
            max_name = name.unwrap_or_default().into_owned();
        }
    }
    println!("files={count}");
    println!(
        "highest file end (logical partition offset) = {max_end} bytes = {:.1} MiB  ({max_name})",
        max_end as f64 / (1024.0 * 1024.0)
    );
    Ok(())
}
