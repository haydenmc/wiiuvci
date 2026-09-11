//! Open a recon'd disc with Wii-hash validation ENABLED and read the whole data partition,
//! reporting the first offset where a hash check fails (mirrors Nintendont's hash-verified DI read).
//! Run: cargo run -p wiivci-core --release --example validate_part -- <recon_dir> [read_len_hex]
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use nod::{Disc, OpenOptions, PartitionKind};

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: validate_part <recon_dir> [len]");
    let cap = std::env::args()
        .nth(2)
        .map(|s| usize::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
        .unwrap_or(0x0060_0000);
    let hif = Path::new(&dir).join("content").join("hif_000000.nfs");

    let disc = Disc::new_with_options(
        &hif,
        &OpenOptions {
            rebuild_encryption: true,
            validate_hashes: true,
        },
    )
    .expect("open disc");

    let mut part = match disc.open_partition_kind(PartitionKind::Data) {
        Ok(p) => p,
        Err(e) => {
            println!("open_partition_kind(Data) FAILED: {e}");
            return;
        }
    };

    // Read in 0x8000 logical chunks; report first read error (a hash failure surfaces as an Err).
    part.seek(SeekFrom::Start(0)).unwrap();
    let mut buf = vec![0u8; 0x8000];
    let mut off: u64 = 0;
    let mut ok_bytes: u64 = 0;
    while off < cap as u64 {
        match part.read(&mut buf) {
            Ok(0) => {
                println!("EOF at logical {off:#x}");
                break;
            }
            Ok(n) => {
                ok_bytes += n as u64;
                off += n as u64;
            }
            Err(e) => {
                println!(
                    "READ/HASH ERROR at logical {off:#x} (after {ok_bytes:#x} valid bytes): {e}"
                );
                return;
            }
        }
    }
    println!(
        "validated OK: read {ok_bytes:#x} logical bytes with hashes valid (up to cap {cap:#x})"
    );
}
