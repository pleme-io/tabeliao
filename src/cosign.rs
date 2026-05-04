//! Cosign signature bundle — wire-format compatible with
//! `cosign sign-blob --bundle=...`.
//!
//! The bundle is what `cosign verify-blob --bundle=...` reads. It
//! carries the signature, the signing certificate (or public key in
//! PEM), and an optional Rekor inclusion proof. By emitting this
//! exact JSON shape, tabeliao-produced signatures are
//! verifiable by stock cosign tooling — no pleme-io-specific
//! verifier required.
//!
//! Today (v0.5):
//!   - `base64Signature`: real Ed25519 signature, base64-encoded.
//!   - `cert`: publisher's Ed25519 public key in PEM
//!     (SubjectPublicKeyInfo). When Fulcio is wired up, this becomes
//!     the short-lived Fulcio cert chain for the OIDC identity.
//!   - `rekorBundle`: null. When Rekor is wired up, this becomes
//!     the inclusion proof from the public transparency log.
//!
//! The bundle is embedded as a sibling artifact — cartorio doesn't
//! need to know its internal shape; verifiers fetch it alongside the
//! artifact and pass it to `cosign verify-blob`.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Result, TabeliaoError};

/// Wire-format `cosign sign-blob --bundle` JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignBundle {
    /// Base64-encoded signature bytes.
    #[serde(rename = "base64Signature")]
    pub base64_signature: String,
    /// PEM-encoded x509 certificate (Fulcio short-lived cert OR a
    /// publisher's stable public key wrapped in a self-signed cert).
    /// In v0.5: PEM-encoded SubjectPublicKeyInfo (a "raw" public
    /// key, not a full cert). cosign's `--key` flag accepts this
    /// shape via `cosign sign-blob --key cosign.pub` workflows.
    pub cert: Option<String>,
    /// Rekor transparency-log inclusion proof. `null` until Rekor is
    /// integrated.
    #[serde(rename = "rekorBundle", skip_serializing_if = "Option::is_none")]
    pub rekor_bundle: Option<RekorBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorBundle {
    #[serde(rename = "SignedEntryTimestamp")]
    pub signed_entry_timestamp: String,
    #[serde(rename = "Payload")]
    pub payload: RekorPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorPayload {
    pub body: String,
    #[serde(rename = "integratedTime")]
    pub integrated_time: i64,
    #[serde(rename = "logIndex")]
    pub log_index: i64,
    #[serde(rename = "logID")]
    pub log_id: String,
}

/// Sign `bytes` with an Ed25519 private key and return a cosign
/// bundle. The bundle carries the public key as PEM-encoded SPKI so
/// any verifier with the public key can call
/// `cosign verify-blob --key <pubkey>.pem --bundle <bundle>.json blob`.
///
/// # Errors
/// Returns errors for invalid key bytes (shouldn't happen if you
/// constructed the SigningKey legitimately).
pub fn sign_blob_to_bundle(signing_key: &SigningKey, bytes: &[u8]) -> Result<CosignBundle> {
    let sig = signing_key.sign(bytes);
    let vk = signing_key.verifying_key();
    let pem = ed25519_public_key_to_pem(&vk);
    Ok(CosignBundle {
        base64_signature: BASE64.encode(sig.to_bytes()),
        cert: Some(pem),
        rekor_bundle: None,
    })
}

/// Verify a cosign bundle against the bytes it claims to sign + a
/// publicly-known Ed25519 verifying key. Used by tabeliao tests; in
/// production an external auditor uses `cosign verify-blob`.
///
/// # Errors
/// Returns errors for: malformed base64 signature, signature length
/// mismatch, signature does not verify under the public key.
pub fn verify_blob_bundle(
    bundle: &CosignBundle,
    bytes: &[u8],
    expected_pubkey: &VerifyingKey,
) -> Result<()> {
    let sig_bytes = BASE64
        .decode(&bundle.base64_signature)
        .map_err(|e| TabeliaoError::InvalidInput(format!("base64 signature: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| TabeliaoError::InvalidInput("Ed25519 signature must be 64 bytes".into()))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    expected_pubkey
        .verify(bytes, &sig)
        .map_err(|e| TabeliaoError::InvalidInput(format!("cosign signature verify failed: {e}")))?;
    Ok(())
}

/// Encode an Ed25519 public key as PEM-formatted SubjectPublicKeyInfo
/// (the format `cosign --key` reads). The body is a fixed 44-byte
/// DER blob: the SPKI prefix (`30 2A 30 05 06 03 2B 65 70 03 21 00`)
/// followed by the 32-byte raw public key.
#[must_use]
pub fn ed25519_public_key_to_pem(vk: &VerifyingKey) -> String {
    // RFC 8410 — Ed25519 SubjectPublicKeyInfo prefix (12 bytes):
    //   SEQUENCE (2A) {
    //     SEQUENCE (05) { OID 1.3.101.112 ed25519 }
    //     BIT STRING (21 00) ...32 bytes...
    //   }
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut spki = Vec::with_capacity(SPKI_PREFIX.len() + 32);
    spki.extend_from_slice(&SPKI_PREFIX);
    spki.extend_from_slice(&vk.to_bytes());
    let b64 = BASE64.encode(&spki);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer() -> SigningKey {
        let mut rng = rand::rngs::OsRng;
        SigningKey::generate(&mut rng)
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let sk = test_signer();
        let vk = sk.verifying_key();
        let bytes = b"some-blob-content";
        let bundle = sign_blob_to_bundle(&sk, bytes).unwrap();
        verify_blob_bundle(&bundle, bytes, &vk).unwrap();
    }

    #[test]
    fn verify_fails_under_wrong_pubkey() {
        let sk1 = test_signer();
        let sk2 = test_signer();
        let bundle = sign_blob_to_bundle(&sk1, b"x").unwrap();
        assert!(verify_blob_bundle(&bundle, b"x", &sk2.verifying_key()).is_err());
    }

    #[test]
    fn verify_fails_for_tampered_blob() {
        let sk = test_signer();
        let bundle = sign_blob_to_bundle(&sk, b"original").unwrap();
        assert!(verify_blob_bundle(&bundle, b"tampered", &sk.verifying_key()).is_err());
    }

    #[test]
    fn bundle_serializes_to_cosign_compatible_json() {
        let sk = test_signer();
        let bundle = sign_blob_to_bundle(&sk, b"x").unwrap();
        let json = serde_json::to_value(&bundle).unwrap();
        assert!(json.get("base64Signature").is_some());
        assert!(json.get("cert").is_some());
        // rekorBundle absent (skipped via skip_serializing_if).
        // Verify the round-trip.
        let de: CosignBundle = serde_json::from_value(json).unwrap();
        assert_eq!(de.base64_signature, bundle.base64_signature);
    }

    #[test]
    fn pem_envelope_has_correct_markers() {
        let sk = test_signer();
        let pem = ed25519_public_key_to_pem(&sk.verifying_key());
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn bundle_wire_format_matches_cosign_canonical_shape() {
        // SNAPSHOT — the JSON keys cosign sign-blob --bundle emits.
        // Renaming any of these breaks interop with stock cosign tools.
        let sk = test_signer();
        let bundle = sign_blob_to_bundle(&sk, b"x").unwrap();
        let json = serde_json::to_value(&bundle).unwrap();
        // base64Signature: required, present.
        assert!(
            json.get("base64Signature").is_some(),
            "missing base64Signature key (cosign wire format)"
        );
        // cert: present (PEM SPKI today; Fulcio cert chain in vNext).
        assert!(json.get("cert").is_some(), "missing cert key");
        // rekorBundle: skipped when None (skip_serializing_if).
        assert!(
            json.get("rekorBundle").is_none(),
            "rekorBundle must be absent when None; cosign treats absent == null"
        );
    }

    #[test]
    fn bundle_with_rekor_serializes_rekor_bundle_in_canonical_shape() {
        // When the Rekor field is populated (full keyless), the wire
        // shape must match cosign's: SignedEntryTimestamp + Payload.
        use super::{RekorBundle, RekorPayload};
        let bundle = CosignBundle {
            base64_signature: "abc".into(),
            cert: Some("PEM".into()),
            rekor_bundle: Some(RekorBundle {
                signed_entry_timestamp: "sig".into(),
                payload: RekorPayload {
                    body: "body".into(),
                    integrated_time: 1_700_000_000,
                    log_index: 42,
                    log_id: "logid".into(),
                },
            }),
        };
        let json = serde_json::to_value(&bundle).unwrap();
        assert!(json["rekorBundle"]["SignedEntryTimestamp"].is_string());
        assert!(json["rekorBundle"]["Payload"]["body"].is_string());
        assert_eq!(
            json["rekorBundle"]["Payload"]["integratedTime"],
            serde_json::json!(1_700_000_000)
        );
        assert_eq!(json["rekorBundle"]["Payload"]["logIndex"], serde_json::json!(42));
        assert_eq!(json["rekorBundle"]["Payload"]["logID"], "logid");
    }

    #[test]
    fn bundle_round_trips_via_json() {
        let sk = test_signer();
        let bundle = sign_blob_to_bundle(&sk, b"some-blob").unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        let back: CosignBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.base64_signature, bundle.base64_signature);
        assert_eq!(back.cert, bundle.cert);
        verify_blob_bundle(&back, b"some-blob", &sk.verifying_key()).unwrap();
    }

    #[test]
    fn pem_round_trips_through_x509_parser() {
        // Best-effort: the PEM body must be valid base64 of a 44-byte
        // DER SPKI blob. We don't pull in a full ASN.1 parser here
        // (sigstore-rs would handle that in production); we sanity-
        // check the length.
        let sk = test_signer();
        let pem = ed25519_public_key_to_pem(&sk.verifying_key());
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let decoded = BASE64.decode(body).unwrap();
        assert_eq!(decoded.len(), 44, "Ed25519 SPKI is 44 bytes");
        // Last 32 bytes MUST equal the raw public key.
        assert_eq!(&decoded[12..], &sk.verifying_key().to_bytes());
    }
}
