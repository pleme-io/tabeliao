//! Demo helpers — shared scaffolding for the openclaw hackathon
//! seeding binaries (`seed_demo` + `seed_failure_tamper`). Synthesises
//! a stable AttestationsConfig for a given (kind, name, version,
//! pack-profile) tuple so both binaries author the same shape.
//!
//! Not part of the public publishing surface — these helpers exist to
//! drive demo flows against a live cartorio. Real publishers
//! construct `AttestationsConfig` from their own SBOM, build, image,
//! and pack outputs; the values here are deterministic placeholders
//! computed from the artifact name.
//!
//! Behind a `demo` feature flag would be cleaner long-term; for now
//! it's gated only by being public-API in a section nothing else
//! consumes.

use cartorio::core::types::{ArtifactKind, ComplianceStatus};
use tameshi::hash::Blake3Hash;

use crate::AttestationsConfig;
use crate::attestations::{
    AttestationsBlock, BuildBlock, ComplianceBlock, ImageBlock, SourceBlock,
};

/// Stable demo-publisher identity used by every seeded artifact.
pub const DEMO_PUBLISHER: &str = "demo@pleme.io";

/// Stable demo org — must match the running cartorio's
/// `RegistryConfig.org`.
pub const DEMO_ORG: &str = "pleme-io";

/// Build a deterministic `AttestationsConfig` for a given artifact.
/// All hash fields are derived from the artifact name so two runs
/// against an empty cartorio produce identical state-leaf roots.
#[must_use]
pub fn artifact_config(
    kind: ArtifactKind,
    name: &str,
    version: &str,
    profile: &str,
) -> AttestationsConfig {
    AttestationsConfig {
        kind: kind.clone(),
        name: name.into(),
        version: version.into(),
        publisher_id: DEMO_PUBLISHER.into(),
        org: DEMO_ORG.into(),
        attestation: AttestationsBlock {
            source: Some(SourceBlock {
                git_commit: "demo-commit-0000000".into(),
                tree_hash: Blake3Hash::digest(format!("{name}-tree").as_bytes()),
                flake_lock_hash: Blake3Hash::digest(format!("{name}-lock").as_bytes()),
            }),
            build: Some(BuildBlock {
                closure_hash: Blake3Hash::digest(format!("{name}-closure").as_bytes()),
                sbom_hash: Blake3Hash::digest(format!("{name}-sbom").as_bytes()),
                slsa_level: 3,
            }),
            image: if matches!(kind, ArtifactKind::OciImage) {
                Some(ImageBlock {
                    cosign_signature_ref: format!("ghcr.io/pleme-io/{name}:sig"),
                    slsa_provenance_ref: format!("ghcr.io/pleme-io/{name}:prov"),
                })
            } else {
                None
            },
            compliance: Some(ComplianceBlock {
                framework: "FedRAMP".into(),
                baseline: "high".into(),
                profile: profile.into(),
                result_hash: Blake3Hash::digest(format!("{name}-pack-hash").as_bytes()),
                status: ComplianceStatus::Compliant,
            }),
        },
        bundle_members: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_inputs() {
        let a = artifact_config(
            ArtifactKind::OciImage,
            "demo-x",
            "1.0.0",
            "fedramp-high-openclaw-image@2",
        );
        let b = artifact_config(
            ArtifactKind::OciImage,
            "demo-x",
            "1.0.0",
            "fedramp-high-openclaw-image@2",
        );
        assert_eq!(
            a.attestation.source.as_ref().unwrap().tree_hash,
            b.attestation.source.as_ref().unwrap().tree_hash,
        );
        assert_eq!(
            a.attestation.compliance.as_ref().unwrap().result_hash,
            b.attestation.compliance.as_ref().unwrap().result_hash,
        );
    }

    #[test]
    fn image_kind_emits_image_block() {
        let cfg = artifact_config(
            ArtifactKind::OciImage,
            "img",
            "0.1.0",
            "fedramp-high-openclaw-image@2",
        );
        assert!(cfg.attestation.image.is_some());
    }

    #[test]
    fn non_image_kind_omits_image_block() {
        let cfg = artifact_config(
            ArtifactKind::HelmChart,
            "chart",
            "0.1.0",
            "fedramp-high-openclaw-helm-content@1",
        );
        assert!(cfg.attestation.image.is_none());
    }

    #[test]
    fn publisher_and_org_are_stable() {
        let cfg = artifact_config(
            ArtifactKind::Bundle,
            "anything",
            "anywhere",
            "anyprofile",
        );
        assert_eq!(cfg.publisher_id, DEMO_PUBLISHER);
        assert_eq!(cfg.org, DEMO_ORG);
    }
}
