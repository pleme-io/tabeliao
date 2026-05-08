//! Compose an `AdmitArtifactInput` from a parsed config + manifest
//! digest + signer.

use cartorio::core::types::{
    AdmitArtifactInput, ArtifactStatus, ComplianceRun, ModifierIdentity,
};
use cartorio::merkle::compose_state_leaf_root;
use chrono::{DateTime, Utc};

use crate::attestations::AttestationsConfig;
use crate::error::Result;
use crate::sign::Signer;

/// Build a fully-signed `AdmitArtifactInput` with optional per-test
/// compliance run.
///
/// # Errors
/// Propagates signer errors (bad key, etc.).
pub fn build_admit_input_with_run<S: Signer>(
    cfg: AttestationsConfig,
    manifest_digest: &str,
    signed_at: DateTime<Utc>,
    signer: &S,
    compliance_run: Option<ComplianceRun>,
) -> Result<AdmitArtifactInput> {
    build_admit_input_inner(cfg, manifest_digest, signed_at, signer, compliance_run)
}

/// Build a fully-signed `AdmitArtifactInput` (no compliance run).
///
/// # Errors
/// Propagates signer errors (bad key, etc.).
pub fn build_admit_input<S: Signer>(
    cfg: AttestationsConfig,
    manifest_digest: &str,
    signed_at: DateTime<Utc>,
    signer: &S,
) -> Result<AdmitArtifactInput> {
    build_admit_input_inner(cfg, manifest_digest, signed_at, signer, None)
}

fn build_admit_input_inner<S: Signer>(
    cfg: AttestationsConfig,
    manifest_digest: &str,
    signed_at: DateTime<Utc>,
    signer: &S,
    compliance_run: Option<ComplianceRun>,
) -> Result<AdmitArtifactInput> {
    let kind = cfg.kind;
    let name = cfg.name.clone();
    let version = cfg.version.clone();
    let publisher_id = cfg.publisher_id.clone();
    let org = cfg.org.clone();
    let chain = cfg.into_attestation_chain(manifest_digest);

    let modifier = ModifierIdentity::Publisher {
        publisher_id: publisher_id.clone(),
    };
    let state_root = compose_state_leaf_root(
        kind.name(),
        &name,
        &version,
        &publisher_id,
        &org,
        manifest_digest,
        &chain,
        ArtifactStatus::Active,
        &modifier,
        signed_at.timestamp(),
    );
    let signed_root = signer.sign(&state_root, &modifier.signer_label(), signed_at)?;

    Ok(AdmitArtifactInput {
        kind,
        name,
        version,
        publisher_id,
        org,
        digest: manifest_digest.into(),
        attestation: chain,
        admitted_at: signed_at,
        signed_root,
        compliance_run,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestations::{
        AttestationsBlock, AttestationsConfig, BuildBlock, ComplianceBlock, ImageBlock, SourceBlock,
    };
    use crate::sign::Blake3Signer;
    use cartorio::core::types::{ArtifactKind, ComplianceStatus};
    use chrono::Utc;
    use tameshi::hash::Blake3Hash;

    fn full_cfg() -> AttestationsConfig {
        AttestationsConfig {
            kind: ArtifactKind::OciImage,
            name: "my-img".into(),
            version: "1.0.0".into(),
            publisher_id: "alice@pleme.io".into(),
            org: "pleme-io".into(),
            attestation: AttestationsBlock {
                source: Some(SourceBlock {
                    git_commit: "abc".into(),
                    tree_hash: Blake3Hash::digest(b"tree"),
                    flake_lock_hash: Blake3Hash::digest(b"lock"),
                }),
                build: Some(BuildBlock {
                    closure_hash: Blake3Hash::digest(b"closure"),
                    sbom_hash: Blake3Hash::digest(b"sbom"),
                    slsa_level: 3,
                }),
                image: Some(ImageBlock {
                    cosign_signature_ref: "ref:sig".into(),
                    slsa_provenance_ref: "ref:prov".into(),
                }),
                compliance: Some(ComplianceBlock {
                    framework: "NIST".into(),
                    baseline: "high".into(),
                    profile: "p".into(),
                    result_hash: Blake3Hash::digest(b"r"),
                    status: ComplianceStatus::Compliant,
                }),
            },
            bundle_members: None,
        }
    }

    #[test]
    fn signed_root_root_equals_recomputed_state_leaf_root() {
        let signer = Blake3Signer::from_hex(&"0".repeat(64)).unwrap();
        let now = Utc::now();
        let input = build_admit_input(full_cfg(), "sha256:beefbeef", now, &signer).unwrap();

        // Recompute with the exact same args; cartorio's admit handler
        // does the same and rejects on mismatch.
        let chain = full_cfg().into_attestation_chain("sha256:beefbeef");
        let modifier = ModifierIdentity::Publisher {
            publisher_id: "alice@pleme.io".into(),
        };
        let recomputed = compose_state_leaf_root(
            ArtifactKind::OciImage.name(),
            "my-img",
            "1.0.0",
            "alice@pleme.io",
            "pleme-io",
            "sha256:beefbeef",
            &chain,
            ArtifactStatus::Active,
            &modifier,
            now.timestamp(),
        );
        assert_eq!(input.signed_root.root, recomputed);
    }

    #[test]
    fn admitted_at_matches_signed_at() {
        let signer = Blake3Signer::from_hex(&"0".repeat(64)).unwrap();
        let now = Utc::now();
        let input = build_admit_input(full_cfg(), "sha256:beef", now, &signer).unwrap();
        assert_eq!(input.admitted_at, now);
        assert_eq!(input.signed_root.signed_at, now);
    }

    #[test]
    fn image_pillar_oci_digest_is_set_to_supplied_digest() {
        let signer = Blake3Signer::from_hex(&"0".repeat(64)).unwrap();
        let now = Utc::now();
        let input = build_admit_input(full_cfg(), "sha256:cafebabe", now, &signer).unwrap();
        assert_eq!(input.attestation.image.unwrap().oci_digest, "sha256:cafebabe");
    }
}
