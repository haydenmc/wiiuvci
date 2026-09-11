//! Dev utility: stage a base title and print key reference files.
//! Run: cargo run -p wiivci-core --release --example stage_base -- <base.wua|dir> <out_dir>
mod common;

use wiivci_core::base::{open_base, REQUIRED_CODE_FILES};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    common::usage_or_exit(&args, 2, "usage: stage_base <base> <out_dir>");
    let base = &args[0];
    let out = &args[1];
    std::fs::create_dir_all(out)?;

    let mut source = open_base(base)?;
    let staged = source.stage(std::path::Path::new(out))?;

    println!("htk.bin = {}", common::hex(&staged.htk));
    println!("code_dir = {}", staged.code_dir.display());
    for f in REQUIRED_CODE_FILES {
        let p = staged.code_dir.join(f);
        println!(
            "  {f}: {} bytes",
            std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0)
        );
    }
    for name in ["code/app.xml", "code/cos.xml", "meta/meta.xml"] {
        let p = std::path::Path::new(&out).join(name);
        if let Ok(s) = std::fs::read_to_string(&p) {
            println!("\n===== {name} ({} bytes) =====\n{}", s.len(), s);
        }
    }
    Ok(())
}
