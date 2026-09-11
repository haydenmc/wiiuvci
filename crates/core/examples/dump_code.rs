//! Decrypt a WUP title dir and extract its files (code/, content/, meta/) to an output dir.
//! Run: WIIU_COMMON_KEY=<32hex> cargo run -p wiivci-core --release --example dump_code -- <wup_dir> <out_dir>
use std::path::Path;
use wiivci_core::package::extract::{extract_title, ContentReader};
use wiivci_core::package::ticket::decrypt_title_key;
use wiivci_core::package::tmd::parse_content_records;

struct DirReader<'a>(&'a Path);
impl ContentReader for DirReader<'_> {
    fn read(&self, id: u32) -> wiivci_core::error::Result<Vec<u8>> {
        let up = self.0.join(format!("{id:08X}.app"));
        let lo = self.0.join(format!("{id:08x}.app"));
        std::fs::read(&up)
            .or_else(|_| std::fs::read(&lo))
            .map_err(|e| wiivci_core::error::Error::io(&up, e))
    }
}

fn main() {
    let wup = std::env::args()
        .nth(1)
        .expect("usage: dump_code <wup_dir> <out_dir>");
    let out = std::env::args().nth(2).expect("out_dir");
    let wup = Path::new(&wup);
    let out = Path::new(&out);

    let key_hex = std::env::var("WIIU_COMMON_KEY").expect("WIIU_COMMON_KEY");
    let mut common = [0u8; 16];
    for (i, b) in common.iter_mut().enumerate() {
        *b = u8::from_str_radix(&key_hex.trim()[i * 2..i * 2 + 2], 16).unwrap();
    }

    let tik = std::fs::read(wup.join("title.tik")).unwrap();
    let tmd = std::fs::read(wup.join("title.tmd")).unwrap();
    let title_id = u64::from_be_bytes(tik[0x1DC..0x1E4].try_into().unwrap());
    let mut enc_tk = [0u8; 16];
    enc_tk.copy_from_slice(&tik[0x1BF..0x1CF]);
    let title_key = decrypt_title_key(&common, title_id, &enc_tk);

    let records = parse_content_records(&tmd).unwrap();
    std::fs::create_dir_all(out).unwrap();
    extract_title(&records, &title_key, &DirReader(wup), out, |_| false).unwrap();
    println!("extracted title {title_id:016x} to {}", out.display());
}
