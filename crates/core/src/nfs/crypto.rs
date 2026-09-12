//! Per-sector AES-128-CBC encryption for NFS data.
//!
//! Each 0x8000-byte logical sector is encrypted independently with:
//!
//! * key = the 16-byte `htk.bin` from the base title;
//! * IV  = `[0u8; 12] ++ big_endian_u32(logical_sector)`.
//!
//! This mirrors `nod`'s NFS *reader* (which decrypts with the identical key/IV scheme), so
//! output produced here round-trips back through `nod` to the original decrypted disc.

use crate::aes_cbc;

/// Compute the CBC IV for a given logical sector.
#[inline]
fn sector_iv(logical_sector: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[12..16].copy_from_slice(&logical_sector.to_be_bytes());
    iv
}

/// Encrypt one logical sector in place.
///
/// `buf.len()` must be a multiple of the 16-byte AES block — every caller passes a whole
/// [`crate::input::DISC_SECTOR_SIZE`] sector, so the invariant is entirely caller-controlled and
/// cannot be violated by disc/asset data. It is therefore an `expect`, not a soft failure: the
/// only way CBC/`NoPadding` can error here is a ragged length, and the previous "transform the
/// aligned prefix and swallow the error" fallback would have written the tail out as **plaintext**
/// in a release build — silently shipping unencrypted bytes into the NFS is far worse than a
/// panic that names the broken invariant.
#[inline]
pub fn encrypt_sector(key: &[u8; 16], logical_sector: u32, buf: &mut [u8]) {
    debug_assert_eq!(
        buf.len() % BLOCK,
        0,
        "NFS sector buffers must be a whole number of AES blocks"
    );
    let iv = sector_iv(logical_sector);
    aes_cbc::encrypt(key, iv, buf).expect("NoPadding on a block-aligned buffer cannot fail");
}

/// Decrypt one logical sector in place (inverse of [`encrypt_sector`]); used by tests. Same
/// caller-controlled length invariant — and the same `expect` — as [`encrypt_sector`].
#[inline]
pub fn decrypt_sector(key: &[u8; 16], logical_sector: u32, buf: &mut [u8]) {
    debug_assert_eq!(
        buf.len() % BLOCK,
        0,
        "NFS sector buffers must be a whole number of AES blocks"
    );
    let iv = sector_iv(logical_sector);
    aes_cbc::decrypt(key, iv, buf).expect("NoPadding on a block-aligned buffer cannot fail");
}

/// AES block size; sector buffers must be a multiple of this.
const BLOCK: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iv_places_sector_in_low_bytes_big_endian() {
        assert_eq!(sector_iv(0), [0u8; 16]);
        let iv = sector_iv(0x1F00);
        assert_eq!(&iv[0..12], &[0u8; 12]);
        assert_eq!(&iv[12..16], &[0x00, 0x00, 0x1F, 0x00]);
        assert_eq!(&sector_iv(1)[12..16], &[0, 0, 0, 1]);
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let key = [0x11u8; 16];
        let original: Vec<u8> = (0..0x8000).map(|i| (i * 7) as u8).collect();
        let mut buf = original.clone();
        encrypt_sector(&key, 42, &mut buf);
        assert_ne!(buf, original);
        decrypt_sector(&key, 42, &mut buf);
        assert_eq!(buf, original);
    }

    /// A buffer that is not a whole number of AES blocks is a broken caller invariant and must
    /// panic rather than leave the ragged tail as plaintext. Only meaningful with
    /// `debug_assertions` off (in a debug build the `debug_assert_eq!` fires first — also a
    /// panic, just a different message), which is how the gates run these tests
    /// (`cargo test --release`).
    #[test]
    #[cfg(not(debug_assertions))]
    #[should_panic(expected = "NoPadding on a block-aligned buffer cannot fail")]
    fn ragged_buffer_panics_instead_of_leaving_plaintext() {
        let key = [0x33u8; 16];
        let mut buf = [0xAAu8; 20]; // one whole block + 4 bytes
        encrypt_sector(&key, 7, &mut buf);
    }

    #[test]
    fn different_sectors_produce_different_ciphertext() {
        let key = [0x22u8; 16];
        let plain = [0u8; 32];
        let mut a = plain;
        let mut b = plain;
        encrypt_sector(&key, 1, &mut a);
        encrypt_sector(&key, 2, &mut b);
        assert_ne!(a, b, "IV differs by sector so ciphertext must differ");
    }
}
