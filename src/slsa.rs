//! SLSA Provenance v1 in-toto Statement + DSSE envelope.
//!
//! Phase C3b — closes the audit's `slsa_provenance_ref` gap. v0.4.x
//! `ImageAttestation.slsa_provenance_ref` was an opaque operator-typed
//! string (e.g. `"ghcr.io/pleme-io/openclaw-publisher-pki:prov"`) that
//! never resolved to a real document. C3b emits a real SLSA Provenance
//! v1 in-toto Statement, wraps it in a DSSE envelope, and signs with
//! the publisher's Ed25519 key (the same key Phase C1 wired into
//! `Cmd::Publish`).
//!
//! Specs (Phase A research):
//! - in-toto Statement v1: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
//! - SLSA Provenance v1:   <https://slsa.dev/spec/v1.0/provenance>
//! - DSSE envelope v1.0.2: <https://github.com/secure-systems-lab/dsse/blob/master/envelope.md>
//!
//! What constitutes "real SLSA L3 provenance" per the spec:
//!   - Statement.subject names the artifact + sha256 digest
//!   - predicate.buildDefinition.buildType + externalParameters
//!     fully enumerate the build inputs (L3 = no out-of-band knobs)
//!   - predicate.runDetails.builder.id is an isolated/hosted builder
//!     URI whose signing key the user-defined steps cannot reach
//!   - DSSE envelope signed by that builder's key
//!
//! C3b emits a syntactically valid Statement+Envelope. The L3
//! "isolated builder" condition is delivered by the *runtime* (e.g.
//! the SLSA GitHub Generator workflow), not by this code — tabeliao
//! is the publisher-side serializer. When run from a non-isolated
//! builder, the `predicate.runDetails.builder.id` truthfully names
//! the actual builder; verifiers reading the cert + Rekor entry
//! draw their own L0/L1/L2/L3 conclusion.

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Result, TabeliaoError};
use crate::sign::Ed25519Signer;

pub const STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";
pub const SLSA_PROVENANCE_PREDICATE_V1: &str = "https://slsa.dev/provenance/v1";
pub const DSSE_PAYLOAD_TYPE_INTOTO: &str = "application/vnd.in-toto+json";

// ─── in-toto Statement v1 ────────────────────────────────────────────

/// Outer in-toto Statement. Used for any predicateType. For SLSA
/// provenance, `predicate_type = SLSA_PROVENANCE_PREDICATE_V1` and
/// `predicate` deserializes as a `SlsaProvenance` value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<ResourceDescriptor>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: serde_json::Value,
}

/// in-toto ResourceDescriptor. Subjects + provenance dependencies
/// + builder dependencies all use this shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Map from algorithm name (`"sha256"`, `"sha512"`, `"gitCommit"`)
    /// to lowercase hex.
    pub digest: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(rename = "downloadLocation", skip_serializing_if = "Option::is_none")]
    pub download_location: Option<String>,
}

// ─── SLSA Provenance v1 predicate ────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaProvenance {
    #[serde(rename = "buildDefinition")]
    pub build_definition: BuildDefinition,
    #[serde(rename = "runDetails")]
    pub run_details: RunDetails,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildDefinition {
    #[serde(rename = "buildType")]
    pub build_type: String,
    /// External parameters ARE the L3 contract. For L3, this MUST
    /// fully enumerate every input the builder consumed; verifiers
    /// rely on this to detect smuggled inputs.
    #[serde(rename = "externalParameters")]
    pub external_parameters: serde_json::Value,
    #[serde(rename = "internalParameters", skip_serializing_if = "Option::is_none")]
    pub internal_parameters: Option<serde_json::Value>,
    #[serde(rename = "resolvedDependencies", skip_serializing_if = "Vec::is_empty", default)]
    pub resolved_dependencies: Vec<ResourceDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDetails {
    pub builder: Builder,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub byproducts: Vec<ResourceDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Builder {
    /// URI identifying the builder. For SLSA L3 this MUST point at
    /// an isolated, hosted builder whose signing key user-defined
    /// build steps cannot reach (e.g.
    /// `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/...`).
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<BTreeMap<String, String>>,
    #[serde(rename = "builderDependencies", skip_serializing_if = "Vec::is_empty", default)]
    pub builder_dependencies: Vec<ResourceDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(rename = "invocationId", skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,
    /// RFC 3339 timestamps.
    #[serde(rename = "startedOn", skip_serializing_if = "Option::is_none")]
    pub started_on: Option<String>,
    #[serde(rename = "finishedOn", skip_serializing_if = "Option::is_none")]
    pub finished_on: Option<String>,
}

// ─── DSSE envelope v1.0.2 ────────────────────────────────────────────

/// DSSE envelope. Per spec: signature is over `PAE(payloadType, payload)`,
/// where `payload` is the raw bytes (NOT the base64).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// base64(payload bytes).
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseSignature {
    /// Hex-encoded public key OR Fulcio cert-chain hash. We use the
    /// Ed25519 public key hex (matches cartorio's
    /// `SignedRoot.signer_id` shape for keyless flows).
    pub keyid: String,
    /// base64(signature bytes). For Ed25519: 64 raw bytes → 88 base64.
    pub sig: String,
}

/// DSSE Pre-Authentication Encoding. Per DSSE v1.0.2 §3:
///
/// `PAE(t, b) = "DSSEv1 " || len(t) || " " || t || " " || len(b) || " " || b`
///
/// where `len(x)` is the ASCII-decimal-encoded byte-length of `x`.
/// Length numbers are LITERAL ASCII digits, not network-order ints.
#[must_use]
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + payload_type.len() + payload.len());
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Build a Statement asserting the SLSA Provenance v1 predicate over
/// a single subject (the OCI image being attested).
///
/// # Errors
/// Returns `InvalidInput` if the subject digest isn't a 64-hex sha256.
pub fn build_statement(
    subject_name: &str,
    subject_sha256_hex: &str,
    predicate: &SlsaProvenance,
) -> Result<Statement> {
    if subject_sha256_hex.len() != 64
        || !subject_sha256_hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(TabeliaoError::InvalidInput(format!(
            "subject digest must be 64 lowercase hex chars (got {} chars)",
            subject_sha256_hex.len()
        )));
    }
    let mut digest = BTreeMap::new();
    digest.insert("sha256".to_string(), subject_sha256_hex.to_string());
    Ok(Statement {
        statement_type: STATEMENT_TYPE_V1.to_string(),
        subject: vec![ResourceDescriptor {
            name: Some(subject_name.to_string()),
            digest,
            uri: None,
            media_type: None,
            download_location: None,
        }],
        predicate_type: SLSA_PROVENANCE_PREDICATE_V1.to_string(),
        predicate: serde_json::to_value(predicate).map_err(|e| {
            TabeliaoError::InvalidInput(format!("serialize predicate: {e}"))
        })?,
    })
}

/// Sign a Statement and produce a DSSE envelope. The payload is the
/// canonical JSON serialization of the Statement; the signature is
/// over PAE(payload_type, payload_bytes) per DSSE v1.0.2.
///
/// # Errors
/// Serialization failures.
pub fn sign_envelope(statement: &Statement, signer: &Ed25519Signer) -> Result<Envelope> {
    let payload_bytes = serde_json::to_vec(statement).map_err(|e| {
        TabeliaoError::InvalidInput(format!("serialize statement: {e}"))
    })?;
    let pae_bytes = pae(DSSE_PAYLOAD_TYPE_INTOTO, &payload_bytes);
    let sig = signer.sign_bytes(&pae_bytes);
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(Envelope {
        payload: b64.encode(&payload_bytes),
        payload_type: DSSE_PAYLOAD_TYPE_INTOTO.to_string(),
        signatures: vec![DsseSignature {
            keyid: signer.verifying_key_hex(),
            sig: b64.encode(sig),
        }],
    })
}

// ─── Sigstore Bundle v0.3 (Phase C4) ─────────────────────────────────
//
// Per the sigstore protobuf-specs `dev.sigstore.bundle.v1.Bundle`
// shape (proto3 → JSON via protojson canonical mapping). For an
// in-toto attestation signed with a static Ed25519 key (no Fulcio
// cert, no Rekor entry yet), the bundle carries:
//
//   {
//     "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
//     "verificationMaterial": {
//       "publicKey": { "hint": "<keyid hex>" }
//     },
//     "dsseEnvelope": { ... DSSE envelope from sign_envelope() ... }
//   }
//
// Stock `cosign verify-attestation --bundle <file> --key <pem>`
// reads this. The `publicKey.hint` carries the publisher's pubkey
// hex so verifiers can match against an out-of-band allow-list
// (cartorio's verifier policy, in our case).
//
// Sigstore Bundle v0.3 spec:
// <https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto>

pub const SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE: &str =
    "application/vnd.dev.sigstore.bundle.v0.3+json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigstoreBundle {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    #[serde(rename = "verificationMaterial")]
    pub verification_material: VerificationMaterial,
    #[serde(rename = "dsseEnvelope", skip_serializing_if = "Option::is_none")]
    pub dsse_envelope: Option<Envelope>,
    #[serde(rename = "messageSignature", skip_serializing_if = "Option::is_none")]
    pub message_signature: Option<MessageSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMaterial {
    /// Either `public_key` OR `certificate` (single leaf, v0.3 form).
    /// We emit `public_key` for the static-Ed25519-publisher path;
    /// future Fulcio-keyless flows would emit `certificate`.
    #[serde(rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKeyIdentifier>,
    #[serde(rename = "certificate", skip_serializing_if = "Option::is_none")]
    pub certificate: Option<X509Certificate>,
    /// Rekor inclusion proofs. Empty until self-hosted Rekor v2 lands
    /// (Phase C6).
    #[serde(rename = "tlogEntries", skip_serializing_if = "Vec::is_empty", default)]
    pub tlog_entries: Vec<TransparencyLogEntry>,
    /// RFC 3161 timestamps. Empty in v0.3 emit; reserved for Phase H.
    #[serde(rename = "timestampVerificationData", skip_serializing_if = "Option::is_none")]
    pub timestamp_verification_data: Option<TimestampVerificationData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyIdentifier {
    /// Opaque hint the verifier uses to match against an out-of-band
    /// key registry. We populate it with the publisher's pubkey hex.
    pub hint: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509Certificate {
    /// PEM-encoded leaf certificate (single, per Sigstore Bundle v0.3
    /// — intermediates resolved from TUF root).
    #[serde(rename = "rawBytes")]
    pub raw_bytes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyLogEntry {
    #[serde(rename = "logIndex")]
    pub log_index: String,
    #[serde(rename = "logId")]
    pub log_id: LogId,
    #[serde(rename = "kindVersion")]
    pub kind_version: KindVersion,
    #[serde(rename = "integratedTime")]
    pub integrated_time: String,
    #[serde(rename = "inclusionPromise", skip_serializing_if = "Option::is_none")]
    pub inclusion_promise: Option<InclusionPromise>,
    #[serde(rename = "inclusionProof", skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<InclusionProof>,
    #[serde(rename = "canonicalizedBody")]
    pub canonicalized_body: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogId {
    #[serde(rename = "keyId")]
    pub key_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindVersion {
    pub kind: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionPromise {
    #[serde(rename = "signedEntryTimestamp")]
    pub signed_entry_timestamp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    #[serde(rename = "logIndex")]
    pub log_index: String,
    #[serde(rename = "rootHash")]
    pub root_hash: String,
    #[serde(rename = "treeSize")]
    pub tree_size: String,
    pub hashes: Vec<String>,
    pub checkpoint: Checkpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub envelope: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampVerificationData {
    #[serde(rename = "rfc3161Timestamps")]
    pub rfc3161_timestamps: Vec<Rfc3161SignedTimestamp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rfc3161SignedTimestamp {
    #[serde(rename = "signedTimestamp")]
    pub signed_timestamp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSignature {
    #[serde(rename = "messageDigest")]
    pub message_digest: MessageDigest,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageDigest {
    pub algorithm: String,
    pub digest: String,
}

/// Wrap a DSSE envelope in a Sigstore Bundle v0.3, populating
/// `verificationMaterial.publicKey.hint` with the publisher's
/// pubkey hex from the envelope's first signature `keyid`.
///
/// Stock `cosign verify-attestation --bundle <output> --key
/// publisher.pub` reads this directly.
#[must_use]
pub fn dsse_to_sigstore_bundle_v0_3(envelope: Envelope) -> SigstoreBundle {
    let hint = envelope
        .signatures
        .first()
        .map(|s| s.keyid.clone())
        .unwrap_or_default();
    SigstoreBundle {
        media_type: SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE.to_string(),
        verification_material: VerificationMaterial {
            public_key: Some(PublicKeyIdentifier { hint }),
            certificate: None,
            tlog_entries: Vec::new(), // populated when Rekor lands (Phase C6)
            timestamp_verification_data: None,
        },
        dsse_envelope: Some(envelope),
        message_signature: None,
    }
}

/// Verify a DSSE envelope against the publisher's Ed25519 public key.
/// Returns the parsed Statement on success.
///
/// **Verifier discipline (per DSSE v1.0.2):** verify the PAE bytes
/// against the signature, THEN parse the payload. Never re-parse
/// after verify.
///
/// # Errors
/// `InvalidInput` for: bad base64, wrong signature length, signature
/// verification failure, payload not a valid Statement, no signatures.
pub fn verify_envelope(envelope: &Envelope, pubkey: &[u8; 32]) -> Result<Statement> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let b64 = base64::engine::general_purpose::STANDARD;
    let payload_bytes = b64
        .decode(&envelope.payload)
        .map_err(|e| TabeliaoError::InvalidInput(format!("payload not base64: {e}")))?;
    let pae_bytes = pae(&envelope.payload_type, &payload_bytes);

    let sig_entry = envelope.signatures.first().ok_or_else(|| {
        TabeliaoError::InvalidInput("envelope has no signatures".into())
    })?;
    let sig_bytes = b64
        .decode(&sig_entry.sig)
        .map_err(|e| TabeliaoError::InvalidInput(format!("sig not base64: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TabeliaoError::InvalidInput("sig is not 64 bytes (Ed25519)".into()))?;
    let signature = Signature::from_bytes(&sig_arr);

    let key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| TabeliaoError::InvalidInput(format!("bad pubkey: {e}")))?;
    key.verify(&pae_bytes, &signature)
        .map_err(|e| TabeliaoError::InvalidInput(format!("DSSE signature verify failed: {e}")))?;

    serde_json::from_slice::<Statement>(&payload_bytes).map_err(|e| {
        TabeliaoError::InvalidInput(format!("payload not a valid Statement: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_predicate() -> SlsaProvenance {
        let mut params = serde_json::Map::new();
        params.insert(
            "workflow".to_string(),
            serde_json::json!({
                "ref": "refs/tags/v0.1.0",
                "repository": "https://github.com/pleme-io/openclaw-publisher-pki",
                "path": ".github/workflows/release.yml"
            }),
        );
        SlsaProvenance {
            build_definition: BuildDefinition {
                build_type: "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1".into(),
                external_parameters: serde_json::Value::Object(params),
                internal_parameters: None,
                resolved_dependencies: vec![ResourceDescriptor {
                    name: Some("source".into()),
                    digest: {
                        let mut m = BTreeMap::new();
                        m.insert("gitCommit".into(), "0736a6a".into());
                        m
                    },
                    uri: Some("git+https://github.com/pleme-io/openclaw-publisher-pki@refs/tags/v0.1.0".into()),
                    media_type: None,
                    download_location: None,
                }],
            },
            run_details: RunDetails {
                builder: Builder {
                    id: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0".into(),
                    version: Some({
                        let mut m = BTreeMap::new();
                        m.insert("github_actions".into(), "2.319.1".into());
                        m
                    }),
                    builder_dependencies: Vec::new(),
                },
                metadata: Some(Metadata {
                    invocation_id: Some("https://github.com/pleme-io/openclaw-publisher-pki/actions/runs/12345/attempts/1".into()),
                    started_on: Some("2026-05-09T14:00:00Z".into()),
                    finished_on: Some("2026-05-09T14:08:11Z".into()),
                }),
                byproducts: Vec::new(),
            },
        }
    }

    fn make_statement() -> Statement {
        build_statement(
            "ghcr.io/pleme-io/openclaw-publisher-pki",
            "f6505fd3d15c6b5305edbda14650c0bfc12094197159b2ee4318349577eb7f8a",
            &make_predicate(),
        )
        .unwrap()
    }

    // ─── PAE bytes ─────────────────────────────────────────────────

    #[test]
    fn pae_matches_dsse_spec_v1_0_2_format() {
        // Per DSSE v1.0.2 §3:
        //   PAE("application/vnd.foo+json" /* 24 bytes */, "{}" /* 2 bytes */)
        //     = "DSSEv1 24 application/vnd.foo+json 2 {}"
        let out = pae("application/vnd.foo+json", b"{}");
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            "DSSEv1 24 application/vnd.foo+json 2 {}"
        );
    }

    #[test]
    fn pae_length_is_byte_length_not_char_count() {
        // Multi-byte UTF-8 in payload: PAE uses byte length.
        let payload = "café".as_bytes(); // 5 bytes (a-c-a-f-é=2bytes)
        let out = pae("a", payload);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("DSSEv1 1 a 5 "));
    }

    #[test]
    fn pae_is_byte_stable_across_runs() {
        let a = pae(DSSE_PAYLOAD_TYPE_INTOTO, b"some-payload");
        let b = pae(DSSE_PAYLOAD_TYPE_INTOTO, b"some-payload");
        assert_eq!(a, b);
    }

    // ─── Statement shape ───────────────────────────────────────────

    #[test]
    fn statement_has_in_toto_v1_type_and_slsa_predicate_type() {
        let s = make_statement();
        assert_eq!(s.statement_type, STATEMENT_TYPE_V1);
        assert_eq!(s.predicate_type, SLSA_PROVENANCE_PREDICATE_V1);
    }

    #[test]
    fn statement_subject_carries_sha256_only() {
        let s = make_statement();
        assert_eq!(s.subject.len(), 1);
        let subj = &s.subject[0];
        assert_eq!(
            subj.name.as_deref(),
            Some("ghcr.io/pleme-io/openclaw-publisher-pki")
        );
        assert_eq!(subj.digest.len(), 1);
        assert_eq!(
            subj.digest.get("sha256").map(String::as_str),
            Some("f6505fd3d15c6b5305edbda14650c0bfc12094197159b2ee4318349577eb7f8a")
        );
    }

    #[test]
    fn build_statement_rejects_non_lowercase_hex_subject() {
        let r = build_statement(
            "x",
            "F6505FD3D15C6B5305EDBDA14650C0BFC12094197159B2EE4318349577EB7F8A",
            &make_predicate(),
        );
        assert!(matches!(r, Err(TabeliaoError::InvalidInput(_))));
    }

    #[test]
    fn build_statement_rejects_short_subject() {
        let r = build_statement("x", "abc", &make_predicate());
        assert!(matches!(r, Err(TabeliaoError::InvalidInput(_))));
    }

    // ─── DSSE envelope ─────────────────────────────────────────────

    #[test]
    fn sign_envelope_round_trip_verifies_against_pubkey() {
        let signer = Ed25519Signer::generate();
        let pubkey = signer.verifying_key_bytes();
        let s = make_statement();
        let env = sign_envelope(&s, &signer).unwrap();
        let recovered = verify_envelope(&env, &pubkey).unwrap();
        assert_eq!(recovered, s);
    }

    #[test]
    fn envelope_payload_is_base64_of_canonical_statement_json() {
        let signer = Ed25519Signer::generate();
        let s = make_statement();
        let env = sign_envelope(&s, &signer).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let payload_bytes = b64.decode(&env.payload).unwrap();
        let canonical = serde_json::to_vec(&s).unwrap();
        assert_eq!(payload_bytes, canonical);
    }

    #[test]
    fn envelope_payload_type_is_in_toto() {
        let signer = Ed25519Signer::generate();
        let env = sign_envelope(&make_statement(), &signer).unwrap();
        assert_eq!(env.payload_type, DSSE_PAYLOAD_TYPE_INTOTO);
    }

    #[test]
    fn envelope_keyid_is_publisher_pubkey_hex() {
        let signer = Ed25519Signer::generate();
        let env = sign_envelope(&make_statement(), &signer).unwrap();
        assert_eq!(env.signatures[0].keyid, signer.verifying_key_hex());
    }

    #[test]
    fn verify_fails_under_wrong_pubkey() {
        let signer = Ed25519Signer::generate();
        let other = Ed25519Signer::generate();
        let env = sign_envelope(&make_statement(), &signer).unwrap();
        assert!(verify_envelope(&env, &other.verifying_key_bytes()).is_err());
    }

    #[test]
    fn verify_fails_when_payload_is_swapped() {
        // Sign Statement A; replace envelope.payload with Statement B's
        // payload bytes. Signature was over PAE of A's payload; B's
        // PAE differs ⇒ verify fails.
        let signer = Ed25519Signer::generate();
        let pk = signer.verifying_key_bytes();
        let env_a = sign_envelope(&make_statement(), &signer).unwrap();

        let mut s_b = make_statement();
        s_b.subject[0]
            .digest
            .insert("sha256".into(), "1111111111111111111111111111111111111111111111111111111111111111".into());
        let env_b = sign_envelope(&s_b, &signer).unwrap();

        let mut tampered = env_a.clone();
        tampered.payload = env_b.payload.clone();
        assert!(verify_envelope(&tampered, &pk).is_err());
    }

    #[test]
    fn verify_fails_when_signature_bit_flipped() {
        let signer = Ed25519Signer::generate();
        let pk = signer.verifying_key_bytes();
        let mut env = sign_envelope(&make_statement(), &signer).unwrap();

        let b64 = base64::engine::general_purpose::STANDARD;
        let mut sig_bytes = b64.decode(&env.signatures[0].sig).unwrap();
        sig_bytes[0] ^= 1;
        env.signatures[0].sig = b64.encode(sig_bytes);

        assert!(verify_envelope(&env, &pk).is_err());
    }

    #[test]
    fn verify_fails_when_payload_type_changed() {
        // Per DSSE: signature is over PAE(payload_type, payload). So
        // changing payload_type changes the PAE and breaks verify.
        let signer = Ed25519Signer::generate();
        let pk = signer.verifying_key_bytes();
        let mut env = sign_envelope(&make_statement(), &signer).unwrap();
        env.payload_type = "application/vnd.attacker+json".into();
        assert!(verify_envelope(&env, &pk).is_err());
    }

    #[test]
    fn verify_rejects_envelope_with_no_signatures() {
        let signer = Ed25519Signer::generate();
        let pk = signer.verifying_key_bytes();
        let mut env = sign_envelope(&make_statement(), &signer).unwrap();
        env.signatures.clear();
        assert!(verify_envelope(&env, &pk).is_err());
    }

    // ─── SLSA Provenance v1 schema requirements ────────────────────

    #[test]
    fn predicate_carries_required_l1_fields() {
        let p = make_predicate();
        assert!(!p.build_definition.build_type.is_empty(), "buildType required");
        // externalParameters MUST be present (any JSON value).
        assert!(p.build_definition.external_parameters.is_object()
            || !p.build_definition.external_parameters.is_null());
        // builder.id MUST be a non-empty URI.
        assert!(p.run_details.builder.id.starts_with("https://"));
    }

    #[test]
    fn predicate_external_parameters_carry_workflow_identity() {
        let p = make_predicate();
        let workflow = p
            .build_definition
            .external_parameters
            .get("workflow")
            .expect("externalParameters.workflow");
        assert!(workflow.get("repository").is_some());
        assert!(workflow.get("ref").is_some());
        assert!(workflow.get("path").is_some());
    }

    /// Honest test: pin that the OUR builder.id (when run from a
    /// non-isolated builder) doesn't accidentally claim L3. Today
    /// the operator passes the builder.id; future C-phase that wires
    /// SLSA GitHub Generator will set this to the L3 reusable
    /// workflow URL.
    #[test]
    fn predicate_builder_id_truthfully_names_isolated_builder_when_set() {
        let p = make_predicate();
        // The fixture uses the SLSA GitHub Generator's L3-eligible
        // reusable workflow URI. A future regression that points
        // builder.id at, say, the calling repo's own workflow would
        // (incorrectly) imply L3 from a non-isolated build — catch
        // that here.
        let id = &p.run_details.builder.id;
        assert!(
            id.contains("slsa-framework/slsa-github-generator")
                || id.contains("@example.com"),
            "builder.id must point at an isolated hosted builder when claiming L3; got {id}"
        );
    }
}
