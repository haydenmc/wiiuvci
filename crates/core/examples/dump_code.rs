//! Decrypt a WUP title dir and extract its files (code/, content/, meta/) to an output dir.
//! Run: WIIU_COMMON_KEY=<32hex or key file> cargo run -p wiivci-core --release --example dump_code -- <wup_dir> <out_dir>
mod common;

use std::path::Path;
use wiivci_core::package::extract::{extract_title, ContentReader};
use wiivci_core::package::tmd::parse_content_records;

struct DirReader<'a>(&'a Path);
impl ContentReader for DirReader<'_> {
    fn read(&self, id: u32) -> wiivci_core::error::Result<Vec<u8>> {
        common::read_app(self.0, id)
            .map_err(|e| wiivci_core::error::Error::InvalidTitle(e.to_string()))
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    common::usage_or_exit(&args, 2, "usage: dump_code <wup_dir> <out_dir>");
    let wup = Path::new(&args[0]);
    let out = Path::new(&args[1]);

    let common_key = common::wiiu_common_key()?;
    let tik = std::fs::read(wup.join("title.tik"))?;
    let tmd = std::fs::read(wup.join("title.tmd"))?;
    let title_id = common::title_id_from_tik(&tik)?;
    let title_key = common::title_key_from_tik(&tik, &common_key)?;

    let records = parse_content_records(&tmd)?;
    std::fs::create_dir_all(out)?;
    extract_title(&records, &title_key, &DirReader(wup), out, |_| false)?;
    println!("extracted title {title_id:016x} to {}", out.display());
    Ok(())
}
