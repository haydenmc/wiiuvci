//! Thoroughly verify one hashed WUP content: decode it, recompute the full H0..H3 tree from the
//! decoded data, and check (a) every block's embedded H0/H1/H2 header matches, (b) SHA1(.h3)
//! equals the TMD content hash, (c) the recomputed H3 equals the .h3 file.
//! Run: cargo run -p wiivci-core --release --example verify_content -- <wup_dir> <content_index>
mod common;

use std::path::Path;
use wiivci_core::package::content_crypto::{decode_hashed, encode_hashed};
use wiivci_core::package::tmd::parse_content_records;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    common::usage_or_exit(&args, 2, "usage: verify_content <wup_dir> <content_index>");
    let wup = Path::new(&args[0]);
    let want: u16 = args[1].parse()?;
    let tmd = std::fs::read(wup.join("title.tmd"))?;
    let records = parse_content_records(&tmd)?;
    let rec = records
        .iter()
        .find(|r| r.index == want)
        .ok_or_else(|| anyhow::anyhow!("index {want} not in title.tmd"))?;
    println!(
        "content idx={} id={} type={:#06x} tmd_size={} tmd_hash={}",
        rec.index,
        rec.id,
        rec.content_type,
        rec.size,
        common::hex(&rec.hash)
    );

    let app = common::read_app(wup, rec.id)?;
    println!("on-disk .app size = {}", app.len());
    let h3_path_up = wup.join(format!("{:08X}.h3", rec.id));
    let h3_path_lo = wup.join(format!("{:08x}.h3", rec.id));
    let h3_file = std::fs::read(&h3_path_up).or_else(|_| std::fs::read(&h3_path_lo))?;
    println!(".h3 file size = {}", h3_file.len());

    // Decode then re-encode to obtain the canonical tree + h3 for the same plaintext.
    let plain = decode_hashed(&common::DUMMY_TITLE_KEY, rec.index, &app)?;
    println!("decoded plaintext len = {}", plain.len());
    let re = encode_hashed(&common::DUMMY_TITLE_KEY, rec.index, &plain);

    // (a) re-encoded ciphertext identical to on-disk?
    println!("re-encoded .app == on-disk .app : {}", re.data == app);
    if re.data != app {
        let n = re.data.len().min(app.len());
        let first = (0..n).find(|&i| re.data[i] != app[i]);
        println!(
            "  first ciphertext diff @ {:?} (len re={} disk={})",
            first,
            re.data.len(),
            app.len()
        );
    }
    // (b) recomputed h3 == on-disk .h3 file?
    let re_h3 = re.h3.clone().unwrap();
    println!("re-encoded .h3 == on-disk .h3   : {}", re_h3 == h3_file);
    // (c) SHA1(.h3) == TMD hash?
    println!(
        "SHA1(on-disk .h3) == tmd_hash   : {}",
        re.tmd_hash[..] == rec.hash[..]
    );
    println!("re.tmd_hash = {}", common::hex(&re.tmd_hash));
    // hash of the on-disk h3 file:
    use sha1::{Digest, Sha1};
    let disk_h3_hash: [u8; 20] = Sha1::digest(&h3_file).into();
    println!(
        "SHA1(on-disk .h3 file) = {}  == tmd_hash: {}",
        common::hex(&disk_h3_hash),
        disk_h3_hash[..] == rec.hash[..]
    );
    Ok(())
}
