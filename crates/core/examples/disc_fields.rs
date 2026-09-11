//! Print the boot-relevant fields of any Wii disc `nod` can open (RVZ/ISO or an NFS `hif_000000.nfs`):
//! disc header, partition table, region, 0x4FFFC magic, partition header offsets, ticket/TMD key
//! fields, boot.bin offsets, bi2, apploader header. `--base <wua>` materializes a base title's own
//! NFS first. Run: cargo run -p wiivci-core --release --example disc_fields -- <disc|hif> | --base <wua> <scratch>
mod common;

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    common::usage_or_exit(
        &args,
        1,
        "usage: disc_fields <disc|hif> | --base <wua> <scratch>",
    );
    let path: PathBuf = if args[0] == "--base" {
        common::usage_or_exit(&args, 3, "usage: disc_fields --base <wua> <scratch>");
        let mut base = wiivci_core::base::open_base(&args[1])?;
        let dir = base
            .materialize_original_nfs(std::path::Path::new(&args[2]))?
            .ok_or_else(|| anyhow::anyhow!("base has no NFS"))?;
        dir.join("hif_000000.nfs")
    } else {
        PathBuf::from(&args[0])
    };
    let mut disc = common::open_decrypted_disc(&path)?;
    let mut hdr = vec![0u8; 0x50000];
    disc.seek(SeekFrom::Start(0))?;
    disc.read_exact(&mut hdr)?;
    println!(
        "id={:?} title={:?}",
        String::from_utf8_lossy(&hdr[0..6]),
        String::from_utf8_lossy(&hdr[0x20..0x60]).trim_end_matches('\0')
    );
    println!(
        "hdr 0x18 magic={:#x} 0x60/61={:#x}/{:#x}",
        common::be32(&hdr[0x18..]),
        hdr[0x60],
        hdr[0x61]
    );
    println!("parttable 0x40000: {}", common::hex(&hdr[0x40000..0x40040]));
    println!("0x48000: {}", common::hex(&hdr[0x48000..0x48010]));
    println!("region 0x4E000: {}", common::hex(&hdr[0x4E000..0x4E020]));
    println!("0x4FFF0: {}", common::hex(&hdr[0x4FFF0..0x50000]));
    let info_off = (common::be32(&hdr[0x40004..]) as u64) << 2;
    let part_off = (common::be32(&hdr[info_off as usize..]) as u64) << 2;
    println!("part_off={part_off:#x}");
    let mut ph = vec![0u8; 0x2C0];
    disc.seek(SeekFrom::Start(part_off))?;
    disc.read_exact(&mut ph)?;
    println!("tik: titlekey@1BF={} tikid@1D0={:#x} console@1D8={:#x} titleid@1DC={:#x} 1E4={} ver@1E6={} 1E8..1F2={} ckidx={} 1F2..222={} mask@222={}",
        common::hex(&ph[0x1BF..0x1CF]), be64(&ph, 0x1D0), common::be32(&ph[0x1D8..]), be64(&ph, 0x1DC), common::hex(&ph[0x1E4..0x1E6]), common::hex(&ph[0x1E6..0x1E8]), common::hex(&ph[0x1E8..0x1F2]), ph[0x1F1], common::hex(&ph[0x1F2..0x222]), common::hex(&ph[0x222..0x262]));
    println!("tik limits@264={}", common::hex(&ph[0x264..0x2A4]));
    println!("parthdr 2A4..2C0: {}", common::hex(&ph[0x2A4..0x2C0]));
    let tmd_off = (common::be32(&ph[0x2A8..]) as u64) << 2;
    let tmd_size = common::be32(&ph[0x2A4..]) as usize;
    let mut tmd = vec![0u8; tmd_size];
    disc.seek(SeekFrom::Start(part_off + tmd_off))?;
    disc.read_exact(&mut tmd)?;
    println!("tmd: ver/crl/vwii@180={} sysver={:#x} titleid={:#x} type={:#x} group={} 19A..1DC={} access={:#x} titlever={} ncont={} boot={}",
        common::hex(&tmd[0x180..0x184]), be64(&tmd, 0x184), be64(&tmd, 0x18C), common::be32(&tmd[0x194..]), common::hex(&tmd[0x198..0x19A]), common::hex(&tmd[0x19A..0x1D8]), common::be32(&tmd[0x1D8..]), common::be32(&tmd[0x1DC..])>>16, common::be32(&tmd[0x1DC..])&0xffff, common::be32(&tmd[0x1E0..])>>16);
    for i in 0..((tmd_size - 0x1E4) / 0x24).min(4) {
        let c = &tmd[0x1E4 + i * 0x24..];
        println!(
            "  content{i}: id={:#x} idx={} type={:#x} size={:#x} hash={}",
            common::be32(c),
            common::be32(&c[4..]) >> 16,
            common::be32(&c[4..]) & 0xffff,
            be64(c, 8),
            common::hex(&c[16..36])
        );
    }
    let mut part = disc.open_partition_kind(nod::PartitionKind::Data)?;
    let mut b = vec![0u8; 0x2480];
    part.seek(SeekFrom::Start(0))?;
    let mut filled = 0;
    while filled < b.len() {
        let n = part.read(&mut b[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    println!(
        "boot.bin id={:?} 0x18={:#x} 0x60/61={:#x}/{:#x}",
        String::from_utf8_lossy(&b[0..6]),
        common::be32(&b[0x18..]),
        b[0x60],
        b[0x61]
    );
    println!("boot.bin 0x400..0x440: {}", common::hex(&b[0x400..0x440]));
    println!("  dol_off={:#x} fst_off={:#x} fst_size={:#x} fst_max={:#x} user_pos={:#x} user_len={:#x} 438={:#x}",
        (common::be32(&b[0x420..]) as u64)<<2, (common::be32(&b[0x424..]) as u64)<<2, (common::be32(&b[0x428..]) as u64)<<2, (common::be32(&b[0x42C..]) as u64)<<2, common::be32(&b[0x430..]), common::be32(&b[0x434..]), common::be32(&b[0x438..]));
    println!("bi2 0x00..0x40: {}", common::hex(&b[0x440..0x480]));
    println!(
        "apploader hdr: date={:?} entry={:#x} size={:#x} trailer={:#x}",
        String::from_utf8_lossy(&b[0x2440..0x2450]).trim_end_matches('\0'),
        common::be32(&b[0x2450..]),
        common::be32(&b[0x2454..]),
        common::be32(&b[0x2458..])
    );
    Ok(())
}
