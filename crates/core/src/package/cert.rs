//! The certificate chain (`title.cert`).
//!
//! The chain contains Nintendo's real public CA/CP/XS certificates and signatures. It is
//! identical across all retail titles and required for installation, but it is genuinely
//! Nintendo's data, so — like the keys and the base title — it is **user-supplied** rather
//! than bundled. Any dumped Wii U title provides a `title.cert`; the user passes it in.
//!
//! This module validates a supplied chain and passes it through unchanged.

use std::ops::RangeInclusive;
use std::path::Path;

use crate::error::{Error, Result};

/// Size of a standard retail Wii U certificate chain.
pub const EXPECTED_CERT_LEN: usize = 0xA00; // 2560

const ROOT_CA_ISSUER: &[u8] = b"Root-CA00000003";

/// The WUP signature type used throughout the fakesigned package (TMD, ticket): RSA-2048
/// SHA-256. Defined once here (rather than separately in `tmd.rs` and `ticket.rs`, which both
/// used to hard-code the same `0x0001_0004` constant) since all three formats share Nintendo's
/// one signature-type namespace.
pub(crate) const SIG_TYPE_RSA2048_SHA256: u32 = 0x0001_0004;

/// The range of signature types a retail certificate chain's first certificate may use. Also
/// defined here, next to [`SIG_TYPE_RSA2048_SHA256`], since it's the same namespace.
pub(crate) const SIG_TYPE_RANGE: RangeInclusive<u32> = 0x0001_0000..=0x0001_0005;

/// A validated certificate chain, ready to write as `title.cert`.
pub struct CertChain(pub Vec<u8>);

impl CertChain {
    /// Load and validate a certificate chain from a file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|e| Error::io(path, e))?;
        Self::from_bytes(bytes)
    }

    /// Validate raw certificate-chain bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != EXPECTED_CERT_LEN {
            return Err(Error::InvalidTitle(format!(
                "certificate chain has unexpected size {} (expected {EXPECTED_CERT_LEN})",
                bytes.len()
            )));
        }
        // The first cert's signature type must be a known RSA type, and the chain must
        // contain the Root-CA00000003 issuer somewhere.
        let sig_type = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        if !SIG_TYPE_RANGE.contains(&sig_type) {
            return Err(Error::InvalidTitle(format!(
                "certificate chain has unexpected signature type {sig_type:#x}"
            )));
        }
        if !bytes
            .windows(ROOT_CA_ISSUER.len())
            .any(|w| w == ROOT_CA_ISSUER)
        {
            return Err(Error::InvalidTitle(
                "certificate chain does not contain the Root-CA00000003 issuer".into(),
            ));
        }
        Ok(CertChain(bytes))
    }

    /// The raw certificate-chain bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_size() {
        assert!(CertChain::from_bytes(vec![0u8; 100]).is_err());
    }

    /// The right size but an out-of-range signature type is rejected.
    #[test]
    fn from_bytes_rejects_bad_signature_type() {
        let mut bytes = vec![0u8; EXPECTED_CERT_LEN];
        bytes[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        bytes[100..115].copy_from_slice(ROOT_CA_ISSUER);
        // `CertChain` holds no `Debug` impl, so match on the `Result` directly rather than
        // `unwrap_err()` (which requires the `Ok` type to be `Debug`).
        let Err(err) = CertChain::from_bytes(bytes) else {
            panic!("expected an out-of-range signature type to be rejected");
        };
        assert!(matches!(err, Error::InvalidTitle(_)), "got {err}");
    }

    /// A valid signature type but no `Root-CA00000003` issuer string anywhere in the chain is
    /// rejected.
    #[test]
    fn from_bytes_rejects_missing_root_ca_issuer() {
        let mut bytes = vec![0u8; EXPECTED_CERT_LEN];
        bytes[0..4].copy_from_slice(&0x0001_0001u32.to_be_bytes());
        let Err(err) = CertChain::from_bytes(bytes) else {
            panic!("expected a chain with no Root-CA00000003 issuer to be rejected");
        };
        assert!(matches!(err, Error::InvalidTitle(_)), "got {err}");
    }

    /// The right size, a valid signature type, and the issuer string present: accepted.
    #[test]
    fn from_bytes_accepts_a_valid_chain() {
        let mut bytes = vec![0u8; EXPECTED_CERT_LEN];
        bytes[0..4].copy_from_slice(&0x0001_0001u32.to_be_bytes());
        bytes[200..200 + ROOT_CA_ISSUER.len()].copy_from_slice(ROOT_CA_ISSUER);
        let chain = CertChain::from_bytes(bytes.clone()).unwrap();
        assert_eq!(chain.as_bytes(), bytes.as_slice());
    }

    #[test]
    #[ignore = "needs the .dev reference fixtures; run with --ignored"]
    fn accepts_reference_cert() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/wup_ref/title.cert");
        if !path.exists() {
            eprintln!(
                "skipping accepts_reference_cert: {} not present",
                path.display()
            );
            return;
        }
        let chain = CertChain::load(&path).expect("load reference cert");
        assert_eq!(chain.as_bytes().len(), EXPECTED_CERT_LEN);
    }
}
