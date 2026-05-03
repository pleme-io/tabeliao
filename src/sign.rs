//! State-leaf signing.
//!
//! v0.1: BLAKE3 keyed-HMAC over the state-leaf root, with the key
//! sourced from a 64-hex-char `signing_key` argument. Cartorio only
//! validates signature SHAPE (64 hex chars, non-empty `signer_id`) — not
//! cryptographic validity — so this satisfies the contract today and
//! gives a real signature shape.
//!
//! v0.2 will swap this for either a local Ed25519 key or an Akeyless
//! DFC handle; the trait below is the seam.

use cartorio::core::types::{SignedRoot, SigningAlgorithm};
use chrono::{DateTime, Utc};
use tameshi::hash::Blake3Hash;

use crate::error::{Result, TabeliaoError};

pub trait Signer {
    /// Sign the given state-leaf root. Returns a `SignedRoot` ready to
    /// embed in `AdmitArtifactInput`.
    ///
    /// # Errors
    /// Fails if signing material is invalid (e.g. wrong key length).
    fn sign(
        &self,
        root: &Blake3Hash,
        signer_id: &str,
        signed_at: DateTime<Utc>,
    ) -> Result<SignedRoot>;
}

/// BLAKE3 keyed-HMAC signer. The key is exactly 32 bytes.
pub struct Blake3Signer {
    key: [u8; 32],
}

impl Blake3Signer {
    /// Build from a 64-hex-char string.
    ///
    /// # Errors
    /// Fails if the string is not 64 hex chars.
    pub fn from_hex(hex_key: &str) -> Result<Self> {
        if hex_key.len() != 64 {
            return Err(TabeliaoError::InvalidInput(format!(
                "signing key must be 64 hex chars, got {}",
                hex_key.len()
            )));
        }
        let bytes = hex::decode(hex_key)
            .map_err(|e| TabeliaoError::InvalidInput(format!("signing key not hex: {e}")))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| TabeliaoError::InvalidInput("signing key not 32 bytes".into()))?;
        Ok(Self { key })
    }
}

impl Signer for Blake3Signer {
    fn sign(
        &self,
        root: &Blake3Hash,
        signer_id: &str,
        signed_at: DateTime<Utc>,
    ) -> Result<SignedRoot> {
        let mac = blake3::keyed_hash(&self.key, &root.0);
        Ok(SignedRoot {
            root: root.clone(),
            signature: hex::encode(mac.as_bytes()),
            algorithm: SigningAlgorithm::Blake3KeyedHmac,
            signer_id: signer_id.to_string(),
            signed_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        "0".repeat(64)
    }

    #[test]
    fn from_hex_rejects_short_key() {
        assert!(Blake3Signer::from_hex("abc").is_err());
    }

    #[test]
    fn from_hex_rejects_non_hex() {
        assert!(Blake3Signer::from_hex(&"z".repeat(64)).is_err());
    }

    #[test]
    fn signature_is_64_hex_chars() {
        let s = Blake3Signer::from_hex(&key()).unwrap();
        let now = Utc::now();
        let sig = s.sign(&Blake3Hash::digest(b"x"), "publisher:alice", now).unwrap();
        assert_eq!(sig.signature.len(), 64);
        assert!(sig.signature.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(sig.signer_id, "publisher:alice");
        assert_eq!(sig.signed_at, now);
    }

    #[test]
    fn signature_is_deterministic_per_root_and_key() {
        let s1 = Blake3Signer::from_hex(&key()).unwrap();
        let s2 = Blake3Signer::from_hex(&key()).unwrap();
        let now = Utc::now();
        let r = Blake3Hash::digest(b"same-root");
        let a = s1.sign(&r, "alice", now).unwrap();
        let b = s2.sign(&r, "alice", now).unwrap();
        assert_eq!(a.signature, b.signature, "same key+root → same signature");
    }

    #[test]
    fn different_root_yields_different_signature() {
        let s = Blake3Signer::from_hex(&key()).unwrap();
        let now = Utc::now();
        let a = s.sign(&Blake3Hash::digest(b"a"), "alice", now).unwrap();
        let b = s.sign(&Blake3Hash::digest(b"b"), "alice", now).unwrap();
        assert_ne!(a.signature, b.signature);
    }

    #[test]
    fn different_key_yields_different_signature() {
        let s1 = Blake3Signer::from_hex(&"0".repeat(64)).unwrap();
        let s2 = Blake3Signer::from_hex(&"f".repeat(64)).unwrap();
        let now = Utc::now();
        let r = Blake3Hash::digest(b"root");
        let a = s1.sign(&r, "alice", now).unwrap();
        let b = s2.sign(&r, "alice", now).unwrap();
        assert_ne!(a.signature, b.signature);
    }
}
