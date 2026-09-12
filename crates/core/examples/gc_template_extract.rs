//! Pull the carrier-disc template pieces out of a known-good GameCube inject (e.g. a TeconMoon
//! package): its `apploader.img` and forwarder `main.dol`, plus the disc id/title, so the same
//! pieces can be fed to `wiivci --apploader … --nintendont … --gc-disc-id … --gc-disc-title …`.
//! Run: WIIU_COMMON_KEY=<32hex or key file> cargo run -p wiivci-core --release --example gc_template_extract -- <wup_dir> <out_dir>
mod common;

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use nod::PartitionKind;
use wiivci_core::package::extract::{ContentReader, extract_title};
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
    common::usage_or_exit(&args, 2, "usage: gc_template_extract <wup_dir> <out_dir>");
    let (wup, out) = (Path::new(&args[0]), Path::new(&args[1]));

    let common_key = common::wiiu_common_key()?;
    let tik = std::fs::read(wup.join("title.tik"))?;
    let tmd = std::fs::read(wup.join("title.tmd"))?;
    let title_key = common::title_key_from_tik(&tik, &common_key)?;
    let records = parse_content_records(&tmd)?;

    // Decrypt the package into a scratch dir (only the NFS + htk.bin are needed).
    let scratch = out.join("_decrypted");
    std::fs::create_dir_all(&scratch)?;
    extract_title(&records, &title_key, &DirReader(wup), &scratch, |_| false)?;

    let disc_path = scratch.join("content").join("hif_000000.nfs");
    let mut disc = common::open_decrypted_disc(&disc_path)?;
    let mut hdr = [0u8; 0x60];
    disc.read_exact(&mut hdr)?;
    let disc_id = String::from_utf8_lossy(&hdr[0..6]).to_string();
    let disc_title = String::from_utf8_lossy(&hdr[0x20..0x60])
        .trim_end_matches('\0')
        .to_string();

    let mut part = disc.open_partition_kind(PartitionKind::Data)?;
    let mut boot = [0u8; 0x440];
    part.read_exact(&mut boot)?;
    let dol_off = (common::be32(&boot[0x420..]) as u64) << 2;
    let fst_off = (common::be32(&boot[0x424..]) as u64) << 2;

    // Apploader: header-declared size (0x20 header + payload + trailer).
    let mut app_hdr = [0u8; 0x20];
    part.seek(SeekFrom::Start(0x2440))?;
    part.read_exact(&mut app_hdr)?;
    let app_len =
        0x20 + common::be32(&app_hdr[0x14..]) as usize + common::be32(&app_hdr[0x18..]) as usize;
    let mut apploader = vec![0u8; app_len];
    part.seek(SeekFrom::Start(0x2440))?;
    part.read_exact(&mut apploader)?;

    // main.dol: everything between the DOL offset and the FST (the header-declared DOL size is
    // the max section end).
    let mut dol = vec![0u8; (fst_off - dol_off) as usize];
    part.seek(SeekFrom::Start(dol_off))?;
    part.read_exact(&mut dol)?;
    let dol_len = (0..18)
        .map(|i| (common::be32(&dol[i * 4..]) + common::be32(&dol[0x90 + i * 4..])) as usize)
        .max()
        .unwrap();
    dol.truncate(dol_len);

    std::fs::write(out.join("apploader.img"), &apploader)?;
    std::fs::write(out.join("main.dol"), &dol)?;
    let _ = std::fs::remove_dir_all(&scratch);
    println!(
        "disc id {disc_id:?}, title {disc_title:?}\napploader: {} bytes ({}, entry {:#x}) -> {}\nmain.dol: {} bytes -> {}\n\nreplay with:\n  --apploader {} --nintendont {} --gc-disc-id {disc_id} --gc-disc-title {disc_title:?}",
        apploader.len(),
        String::from_utf8_lossy(&app_hdr[..0x10]).trim_end_matches('\0'),
        common::be32(&app_hdr[0x10..]),
        out.join("apploader.img").display(),
        dol.len(),
        out.join("main.dol").display(),
        out.join("apploader.img").display(),
        out.join("main.dol").display(),
    );
    Ok(())
}
