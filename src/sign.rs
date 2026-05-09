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

/// Real Ed25519 signer — the same primitive Sigstore/cosign use under
/// the hood. Asymmetric: the signer holds a private key, verifiers
/// hold the matching public key. Cartorio (v0.4+) does cryptographic
/// verification when its `verifier.ed25519_publisher_keys` policy is
/// set for the org.
///
/// This is the *cryptographic* foundation for cosign. The remaining
/// piece for full Sigstore is the **OIDC + Fulcio + Rekor** flow that
/// transforms an OIDC identity token into a short-lived signing cert
/// and records the signature in the public transparency log. That
/// flow requires production infra (Fulcio service URL, Rekor URL,
/// OIDC issuer); see `docs/COSIGN-PLAN.md` for the upgrade procedure.
///
/// The signature payload is the `Blake3Hash` of the state-leaf root
/// (32 bytes) — the same message Sigstore would sign. Once
/// sigstore-rs is integrated, the signature wire format stays
/// identical, so cartorio v0.4's Ed25519 verification path keeps
/// working.
pub struct Ed25519Signer {
    signing_key: ed25519_dalek::SigningKey,
}

impl Ed25519Signer {
    /// Generate a new keypair using OS randomness. Caller must persist
    /// `verifying_key()` for verifiers and the private key
    /// (`to_bytes()`) for the signer's keystore.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self {
            signing_key: ed25519_dalek::SigningKey::generate(&mut rng),
        }
    }

    /// Load from 32 raw private-key bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::from_bytes(bytes),
        }
    }

    /// Load from a 64-hex-char string.
    ///
    /// # Errors
    /// Fails if the string is not 64 hex chars.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        if hex_str.len() != 64 {
            return Err(TabeliaoError::InvalidInput(format!(
                "Ed25519 private key must be 64 hex chars, got {}",
                hex_str.len()
            )));
        }
        let bytes = hex::decode(hex_str)
            .map_err(|e| TabeliaoError::InvalidInput(format!("hex decode: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| TabeliaoError::InvalidInput("private key not 32 bytes".into()))?;
        Ok(Self::from_bytes(&arr))
    }

    /// Get the verifying (public) key as 32 bytes. Distribute this to
    /// verifiers; cartorio's `verify_ed25519_signed_root` consumes it.
    #[must_use]
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the verifying key as a 64-hex-char string.
    #[must_use]
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.verifying_key_bytes())
    }

    /// Sign arbitrary bytes (DSSE-style envelope, in-toto Statement
    /// PAE bytes, etc.). Returns the 64-byte Ed25519 signature.
    /// Used by Phase C3b's SLSA Provenance signer + Phase C4's
    /// Sigstore Bundle v0.3 emitter.
    #[must_use]
    pub fn sign_bytes(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.signing_key.sign(message).to_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn sign(
        &self,
        root: &Blake3Hash,
        signer_id: &str,
        signed_at: DateTime<Utc>,
    ) -> Result<SignedRoot> {
        use ed25519_dalek::Signer as _;
        let sig = self.signing_key.sign(&root.0);
        Ok(SignedRoot {
            root: root.clone(),
            signature: hex::encode(sig.to_bytes()),
            algorithm: SigningAlgorithm::Ed25519,
            signer_id: signer_id.to_string(),
            signed_at,
            cert_chain: None,
            rekor_bundle: None,
        })
    }
}

/// Alias preserved for caller compatibility — `CosignSigner` IS
/// `Ed25519Signer` in v0.4. When the full Sigstore (Fulcio + Rekor)
/// flow lands, this alias can become a wrapper that calls Sigstore
/// while keeping the same trait surface.
pub type CosignSigner = Ed25519Signer;

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
            cert_chain: None,
            rekor_bundle: None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod ed25519_tests {
    use super::*;
    use cartorio::core::types::SigningAlgorithm;
    use cartorio::merkle::{verify_ed25519_signed_root, verify_signed_root_shape};

    #[test]
    fn ed25519_round_trip_sign_then_verify() {
        let signer = Ed25519Signer::generate();
        let pk = signer.verifying_key_bytes();
        let now = Utc::now();
        let root = Blake3Hash::digest(b"some-state-leaf-root");
        let signed = signer.sign(&root, "publisher:alice@pleme.io", now).unwrap();

        // Wire-shape check (cartorio's first-line validation).
        verify_signed_root_shape(&signed).unwrap();
        // Cryptographic verify.
        verify_ed25519_signed_root(&signed, &pk).unwrap();
    }

    #[test]
    fn ed25519_signature_is_128_hex_chars() {
        let signer = Ed25519Signer::generate();
        let signed = signer.sign(&Blake3Hash::digest(b"x"), "p", Utc::now()).unwrap();
        assert_eq!(signed.signature.len(), 128);
        assert!(signed.signature.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(signed.algorithm, SigningAlgorithm::Ed25519);
    }

    #[test]
    fn ed25519_verify_fails_under_wrong_public_key() {
        let signer = Ed25519Signer::generate();
        let other = Ed25519Signer::generate();
        let signed = signer
            .sign(&Blake3Hash::digest(b"x"), "p", Utc::now())
            .unwrap();
        assert!(verify_ed25519_signed_root(&signed, &other.verifying_key_bytes()).is_err());
    }

    #[test]
    fn ed25519_verify_fails_when_root_is_tampered() {
        let signer = Ed25519Signer::generate();
        let pk = signer.verifying_key_bytes();
        let mut signed = signer
            .sign(&Blake3Hash::digest(b"original"), "p", Utc::now())
            .unwrap();
        // Swap the root field — signature was over the original.
        signed.root = Blake3Hash::digest(b"tampered");
        assert!(verify_ed25519_signed_root(&signed, &pk).is_err());
    }

    #[test]
    fn ed25519_verify_fails_when_signature_is_tampered() {
        let signer = Ed25519Signer::generate();
        let pk = signer.verifying_key_bytes();
        let mut signed = signer
            .sign(&Blake3Hash::digest(b"x"), "p", Utc::now())
            .unwrap();
        // Flip a bit in the signature.
        let mut sig_bytes = hex::decode(&signed.signature).unwrap();
        sig_bytes[0] ^= 1;
        signed.signature = hex::encode(sig_bytes);
        assert!(verify_ed25519_signed_root(&signed, &pk).is_err());
    }

    #[test]
    fn ed25519_signer_from_hex_round_trip_yields_same_public_key() {
        let s1 = Ed25519Signer::generate();
        let priv_hex = hex::encode(s1.signing_key.to_bytes());
        let s2 = Ed25519Signer::from_hex(&priv_hex).unwrap();
        assert_eq!(s1.verifying_key_bytes(), s2.verifying_key_bytes());
    }

    #[test]
    fn ed25519_signer_from_hex_rejects_short_key() {
        assert!(Ed25519Signer::from_hex("abc").is_err());
    }

    #[test]
    fn cosign_signer_alias_is_ed25519() {
        // Validate the public alias works.
        let _signer: CosignSigner = Ed25519Signer::generate();
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
