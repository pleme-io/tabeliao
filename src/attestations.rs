//! YAML-authored attestations config.
//!
//! Operator's view: this is the file you edit per artifact. It carries
//! the four pillars (source / build / image / compliance) plus the
//! identifying fields. Lazily-typed: missing pillars are `None`, which
//! cartorio rejects per `kind.required_pillars()`.

use std::path::Path;

use cartorio::core::types::{
    ArtifactKind, AttestationChain, BuildAttestation, ComplianceAttestation, ComplianceStatus,
    ImageAttestation, SbomAttestation, SlsaProvenanceAttestation, SourceAttestation,
};
use serde::{Deserialize, Serialize};
use tameshi::hash::Blake3Hash;

use crate::error::{Result, TabeliaoError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationsConfig {
    pub kind: ArtifactKind,
    pub name: String,
    pub version: String,
    pub publisher_id: String,
    pub org: String,
    #[serde(default)]
    pub attestation: AttestationsBlock,
    /// For `kind: bundle` artifacts only: the typed list of member
    /// (digest, kind, pack_hash) triples. Each entry MUST already be
    /// admitted to cartorio with that exact `pack_hash`. Bundle pack
    /// tests verify the member set is non-empty, includes both an
    /// image and a chart, and that all member pack_hashes are
    /// non-zero — and the bundle's own `pack_hash` inherits the
    /// member proofs deterministically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_members: Option<Vec<BundleMemberSpec>>,
    /// **v0.8.0 (Phase C6) — real SBOM document attached inline.**
    /// Base64-encoded canonical CycloneDX 1.6 (or SPDX 2.3) JSON.
    /// When set, cartorio's `BuildAttestation.sbom_hash` validation
    /// is supplemented by the new `SbomAttestation` pillar carrying
    /// the actual bytes + their SHA-256.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom_document_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom_referrer_url: Option<String>,
    /// **v0.8.0 (Phase C6) — real SLSA Provenance v1 DSSE envelope.**
    /// Base64-encoded canonical envelope JSON. When set, populates
    /// the new `SlsaProvenanceAttestation` pillar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slsa_envelope_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slsa_referrer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slsa_build_level: Option<u8>,
}

/// YAML-authored bundle member entry. Mirrors `provas::BundleMember`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMemberSpec {
    pub digest: String,
    /// One of `oci-image`, `helm-chart`, `skill` — uses the same
    /// kebab-case as cartorio's `ArtifactKind` serde rename.
    pub kind: String,
    pub pack_hash: Blake3Hash,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttestationsBlock {
    pub source: Option<SourceBlock>,
    pub build: Option<BuildBlock>,
    pub image: Option<ImageBlock>,
    pub compliance: Option<ComplianceBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceBlock {
    pub git_commit: String,
    pub tree_hash: Blake3Hash,
    pub flake_lock_hash: Blake3Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildBlock {
    pub closure_hash: Blake3Hash,
    pub sbom_hash: Blake3Hash,
    pub slsa_level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageBlock {
    /// `cosign_signature_ref` and `slsa_provenance_ref` are operator-
    /// supplied. The `oci_digest` is filled in by tabeliao at publish
    /// time from the manifest body's hash — it is NOT authored.
    pub cosign_signature_ref: String,
    pub slsa_provenance_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceBlock {
    pub framework: String,
    pub baseline: String,
    pub profile: String,
    pub result_hash: Blake3Hash,
    pub status: ComplianceStatus,
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    const SAMPLE_YAML: &str = r"
kind: oci-image
name: my-app
version: 1.0.0
publisher_id: alice@pleme.io
org: pleme-io
attestation:
  source:
    git_commit: abc123
    tree_hash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    flake_lock_hash: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  build:
    closure_hash: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    sbom_hash: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
    slsa_level: 3
  image:
    cosign_signature_ref: ghcr.io/x:sig
    slsa_provenance_ref: ghcr.io/x:prov
  compliance:
    framework: NIST_800_53
    baseline: high
    profile: nist-800-53-high
    result_hash: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    status: compliant
";

    #[test]
    fn parse_full_yaml_roundtrips() {
        let cfg: AttestationsConfig = serde_yaml_ng::from_str(SAMPLE_YAML).unwrap();
        assert_eq!(cfg.name, "my-app");
        assert_eq!(cfg.publisher_id, "alice@pleme.io");
        assert!(cfg.attestation.source.is_some());
        assert!(cfg.attestation.build.is_some());
        assert!(cfg.attestation.image.is_some());
        assert!(cfg.attestation.compliance.is_some());
    }

    #[test]
    fn into_attestation_chain_uses_supplied_digest_for_image_pillar() {
        let cfg: AttestationsConfig = serde_yaml_ng::from_str(SAMPLE_YAML).unwrap();
        let chain = cfg.into_attestation_chain("sha256:beefbeef");
        let image = chain.image.unwrap();
        assert_eq!(image.oci_digest, "sha256:beefbeef");
        assert_eq!(image.cosign_signature_ref, "ghcr.io/x:sig");
    }

    #[test]
    fn empty_attestation_block_yields_all_none_pillars() {
        let yaml = r"
kind: oci-image
name: bare
version: 0.0.0
publisher_id: bob
org: pleme-io
";
        let cfg: AttestationsConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let chain = cfg.into_attestation_chain("sha256:1");
        assert!(chain.source.is_none());
        assert!(chain.build.is_none());
        assert!(chain.image.is_none());
        assert!(chain.compliance.is_none());
    }
}

impl AttestationsConfig {
    /// # Errors
    /// Fails on filesystem read errors or YAML parse errors.
    pub fn from_yaml_path(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| TabeliaoError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let cfg: Self = serde_yaml_ng::from_str(&text).map_err(|e| TabeliaoError::Yaml {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(cfg)
    }

    /// Build the cartorio `AttestationChain` from this config, splicing
    /// in the manifest digest for the image pillar's `oci_digest`.
    #[must_use]
    pub fn into_attestation_chain(self, manifest_digest: &str) -> AttestationChain {
        AttestationChain {
            source: self.attestation.source.map(|s| SourceAttestation {
                git_commit: s.git_commit,
                tree_hash: s.tree_hash,
                flake_lock_hash: s.flake_lock_hash,
            }),
            build: self.attestation.build.map(|b| BuildAttestation {
                closure_hash: b.closure_hash,
                sbom_hash: b.sbom_hash,
                slsa_level: b.slsa_level,
            }),
            image: self.attestation.image.map(|i| ImageAttestation {
                oci_digest: manifest_digest.to_string(),
                cosign_signature_ref: i.cosign_signature_ref,
                slsa_provenance_ref: i.slsa_provenance_ref,
            }),
            compliance: self.attestation.compliance.map(|c| ComplianceAttestation {
                framework: c.framework,
                baseline: c.baseline,
                profile: c.profile,
                result_hash: c.result_hash,
                status: c.status,
            }),
            sbom: self.sbom_document_b64.as_ref().map(|doc_b64| {
                let sha = sha256_of_b64(doc_b64);
                SbomAttestation {
                    format: self.sbom_format.clone().unwrap_or_else(|| "cyclonedx-1.6".into()),
                    document_sha256: sha,
                    document_b64: Some(doc_b64.clone()),
                    referrer_url: self.sbom_referrer_url.clone(),
                }
            }),
            slsa_provenance: self.slsa_envelope_b64.as_ref().map(|env_b64| {
                let sha = sha256_of_b64(env_b64);
                SlsaProvenanceAttestation {
                    predicate_type: "https://slsa.dev/provenance/v1".into(),
                    envelope_sha256: sha,
                    envelope_b64: Some(env_b64.clone()),
                    referrer_url: self.slsa_referrer_url.clone(),
                    build_level: self.slsa_build_level.unwrap_or(0),
                }
            }),
            // SSDF pillar wired in a future sub-phase (Common Form PDF
            // attestation flow).
            ssdf: None,
        }
    }
}

/// Compute sha256 hex of base64-decoded document bytes. Used to bind
/// the canonical document hash that lives in cartorio's
/// `*_attestation.*_sha256` fields.
fn sha256_of_b64(b64: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .unwrap_or_default();
    let mut h = Sha256::new();
    h.update(&bytes);
    format!("{:x}", h.finalize())
}
