//! Pull the carrier-disc template pieces out of a known-good GameCube inject (e.g. a TeconMoon
//! package): its `apploader.img` and forwarder `main.dol`, plus the disc id/title, so the same
//! pieces can be fed to `wiivci --apploader … --nintendont … --gc-disc-id … --gc-disc-title …`.
//! Run: WIIU_COMMON_KEY=<32hex> cargo run -p wiivci-core --release --example gc_template_extract -- <wup_dir> <out_dir>
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use nod::{Disc, OpenOptions, PartitionKind};
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

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn main() {
    let wup = std::env::args()
        .nth(1)
        .expect("usage: gc_template_extract <wup_dir> <out_dir>");
    let out = std::env::args().nth(2).expect("out_dir");
    let (wup, out) = (Path::new(&wup), Path::new(&out));

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

    // Decrypt the package into a scratch dir (only the NFS + htk.bin are needed).
    let scratch = out.join("_decrypted");
    std::fs::create_dir_all(&scratch).unwrap();
    extract_title(&records, &title_key, &DirReader(wup), &scratch, |_| false).unwrap();

    let disc_path = scratch.join("content").join("hif_000000.nfs");
    let mut disc = Disc::new_with_options(
        &disc_path,
        &OpenOptions {
            rebuild_encryption: false,
            validate_hashes: false,
        },
    )
    .expect("open NFS disc");
    let mut hdr = [0u8; 0x60];
    disc.read_exact(&mut hdr).unwrap();
    let disc_id = String::from_utf8_lossy(&hdr[0..6]).to_string();
    let disc_title = String::from_utf8_lossy(&hdr[0x20..0x60])
        .trim_end_matches('\0')
        .to_string();

    let mut part = disc.open_partition_kind(PartitionKind::Data).unwrap();
    let mut boot = [0u8; 0x440];
    part.read_exact(&mut boot).unwrap();
    let dol_off = (be32(&boot, 0x420) as u64) << 2;
    let fst_off = (be32(&boot, 0x424) as u64) << 2;

    // Apploader: header-declared size (0x20 header + payload + trailer).
    let mut app_hdr = [0u8; 0x20];
    part.seek(SeekFrom::Start(0x2440)).unwrap();
    part.read_exact(&mut app_hdr).unwrap();
    let app_len = 0x20 + be32(&app_hdr, 0x14) as usize + be32(&app_hdr, 0x18) as usize;
    let mut apploader = vec![0u8; app_len];
    part.seek(SeekFrom::Start(0x2440)).unwrap();
    part.read_exact(&mut apploader).unwrap();

    // main.dol: everything between the DOL offset and the FST (the header-declared DOL size is
    // the max section end).
    let mut dol = vec![0u8; (fst_off - dol_off) as usize];
    part.seek(SeekFrom::Start(dol_off)).unwrap();
    part.read_exact(&mut dol).unwrap();
    let dol_len = (0..18)
        .map(|i| (be32(&dol, i * 4) + be32(&dol, 0x90 + i * 4)) as usize)
        .max()
        .unwrap();
    dol.truncate(dol_len);

    std::fs::write(out.join("apploader.img"), &apploader).unwrap();
    std::fs::write(out.join("main.dol"), &dol).unwrap();
    let _ = std::fs::remove_dir_all(&scratch);
    println!(
        "disc id {disc_id:?}, title {disc_title:?}\napploader: {} bytes ({}, entry {:#x}) -> {}\nmain.dol: {} bytes -> {}\n\nreplay with:\n  --apploader {} --nintendont {} --gc-disc-id {disc_id} --gc-disc-title {disc_title:?}",
        apploader.len(),
        String::from_utf8_lossy(&app_hdr[..0x10]).trim_end_matches('\0'),
        be32(&app_hdr, 0x10),
        out.join("apploader.img").display(),
        dol.len(),
        out.join("main.dol").display(),
        out.join("apploader.img").display(),
        out.join("main.dol").display(),
    );
}
