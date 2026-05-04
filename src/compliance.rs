//! Compliance pack execution. Lookup by pack id; run against the
//! manifest about to be published; bake the resulting `pack_hash`
//! into the `ComplianceAttestation.result_hash` so cartorio's merkle
//! tree carries an attested claim that's transferably re-derivable.

use cartorio::core::types::{ComplianceAttestation, ComplianceStatus};
use provas::{
    BundleMember, Pack, Runner, Target, fedramp_high_openclaw_bundle_v1,
    fedramp_high_openclaw_helm_content_v1, fedramp_high_openclaw_helm_v1,
    fedramp_high_openclaw_image_v1, fedramp_high_openclaw_image_v2,
};
use tameshi::hash::Blake3Hash;

use crate::error::{Result, TabeliaoError};

/// Look up a pack by its identifier of the form `pack_id@pack_version`.
///
/// # Errors
/// Returns `Err` for unknown pack ids.
pub fn pack_by_name(name: &str) -> Result<Pack> {
    match name {
        "fedramp-high-openclaw-image@1" => Ok(fedramp_high_openclaw_image_v1()),
        "fedramp-high-openclaw-image@2" => Ok(fedramp_high_openclaw_image_v2()),
        "fedramp-high-openclaw-helm@1" => Ok(fedramp_high_openclaw_helm_v1()),
        "fedramp-high-openclaw-helm-content@1" => Ok(fedramp_high_openclaw_helm_content_v1()),
        "fedramp-high-openclaw-bundle@1" => Ok(fedramp_high_openclaw_bundle_v1()),
        other => Err(TabeliaoError::InvalidInput(format!(
            "unknown compliance pack: {other:?}; known: \
             fedramp-high-openclaw-image@1, fedramp-high-openclaw-image@2, \
             fedramp-high-openclaw-helm@1, fedramp-high-openclaw-helm-content@1, \
             fedramp-high-openclaw-bundle@1"
        ))),
    }
}

/// Run a helm-content pack against parsed Chart.yaml + values.yaml +
/// templates. The substantive helm compliance surface — verifies the
/// chart's actual configuration, not just its OCI manifest envelope.
///
/// # Errors
/// Returns `Err` if any test fails.
pub fn enforce_helm_content_pack(
    pack: &Pack,
    chart_yaml: &str,
    values_yaml: &str,
    templates: std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<Blake3Hash> {
    let target = Target::from_helm_chart_sources(chart_yaml, values_yaml, templates)
        .map_err(|e| TabeliaoError::InvalidInput(format!("helm chart yaml parse: {e}")))?;
    enforce_inner(pack, &target)
}

/// Run a helm pack against a helm-OCI manifest body.
///
/// # Errors
/// Returns `Err` if any test fails, with operator-readable reasons.
pub fn enforce_helm_pack(pack: &Pack, manifest_bytes: &[u8]) -> Result<Blake3Hash> {
    let target = Target::from_helm_manifest_bytes(manifest_bytes.to_vec());
    enforce_inner(pack, &target)
}

/// Run a bundle pack against a list of bundle members. Each member's
/// `pack_hash` must be the result of running its own pack against its
/// own target — so the bundle proof transitively depends on each
/// member's proof.
///
/// # Errors
/// Returns `Err` if any bundle test fails.
pub fn enforce_bundle_pack(pack: &Pack, members: Vec<BundleMember>) -> Result<Blake3Hash> {
    let target = Target::from_bundle_members(members);
    enforce_inner(pack, &target)
}

fn enforce_inner(pack: &Pack, target: &Target) -> Result<Blake3Hash> {
    let result = Runner::run_pack(pack, target);
    if !result.all_passed {
        let failures: Vec<String> = result
            .runs
            .iter()
            .filter_map(|r| match &r.outcome {
                provas::TestOutcome::Fail { reason } => {
                    Some(format!("  - {} (v{}): {reason}", r.test_id, r.test_version))
                }
                provas::TestOutcome::Pass { .. } => None,
            })
            .collect();
        return Err(TabeliaoError::InvalidInput(format!(
            "compliance pack {}@{} FAILED:\n{}",
            pack.id,
            pack.version,
            failures.join("\n")
        )));
    }
    Ok(result.pack_hash)
}

/// Run the pack against an OCI image manifest; fail-closed on any
/// test failure. Returns the `pack_hash` to embed in
/// `ComplianceAttestation.result_hash`.
///
/// # Errors
/// Returns `Err` if any test fails. The error message lists every
/// failing test with its reason — the operator sees exactly what's
/// non-compliant before anything is published.
pub fn enforce_pack(pack: &Pack, manifest_bytes: &[u8]) -> Result<Blake3Hash> {
    let target = Target::from_oci_manifest_bytes(manifest_bytes.to_vec());
    enforce_inner(pack, &target)
}

/// Build a `ComplianceAttestation` whose fields exactly describe the
/// pack run: framework + baseline come from the pack name convention,
/// profile is `pack_id@pack_version`, `result_hash` is the deterministic
/// `pack_hash`. Anyone with the same pack and target re-derives the
/// same hash — that's the proof.
#[must_use]
pub fn attestation_from_pack(pack: &Pack, pack_hash: Blake3Hash) -> ComplianceAttestation {
    let (framework, baseline) = framework_baseline_from_pack_id(&pack.id);
    ComplianceAttestation {
        framework,
        baseline,
        profile: format!("{}@{}", pack.id, pack.version),
        result_hash: pack_hash,
        status: ComplianceStatus::Compliant,
    }
}

fn framework_baseline_from_pack_id(pack_id: &str) -> (String, String) {
    if pack_id.starts_with("fedramp-high-") {
        ("FedRAMP".into(), "high".into())
    } else if pack_id.starts_with("fedramp-moderate-") {
        ("FedRAMP".into(), "moderate".into())
    } else if pack_id.starts_with("nist-800-53-") {
        ("NIST_800_53".into(), "default".into())
    } else {
        ("CUSTOM".into(), "default".into())
    }
}

/// Build a `BundleMember` from a published cartorio artifact's
/// public fields (digest, kind name, compliance `result_hash`).
#[must_use]
pub fn bundle_member_from_artifact_fields(
    digest: &str,
    kind_name: &str,
    member_pack_hash: Blake3Hash,
) -> BundleMember {
    BundleMember {
        digest: digest.to_string(),
        kind: kind_name.to_string(),
        pack_hash: member_pack_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_MANIFEST: &[u8] = br#"{
      "schemaVersion": 2,
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "size": 100
      },
      "layers": [
        {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "size": 1000}
      ],
      "annotations": {
        "io.pleme.slsa-provenance-ref": "ghcr.io/pleme-io/openclaw@sha256:beef"
      }
    }"#;

    const NON_COMPLIANT_MANIFEST: &[u8] = br#"{
      "schemaVersion": 1,
      "mediaType": "application/vnd.acme.bogus+json"
    }"#;

    #[test]
    fn known_pack_name_resolves() {
        assert!(pack_by_name("fedramp-high-openclaw-image@1").is_ok());
    }

    #[test]
    fn unknown_pack_name_errors() {
        assert!(pack_by_name("does-not-exist@1").is_err());
    }

    #[test]
    fn enforce_pack_passes_for_compliant_manifest() {
        let pack = pack_by_name("fedramp-high-openclaw-image@1").unwrap();
        let hash = enforce_pack(&pack, GOOD_MANIFEST).expect("compliant manifest must pass");
        // Determinism: re-run yields identical hash.
        let hash2 = enforce_pack(&pack, GOOD_MANIFEST).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn enforce_pack_fails_for_non_compliant_manifest() {
        let pack = pack_by_name("fedramp-high-openclaw-image@1").unwrap();
        let err = enforce_pack(&pack, NON_COMPLIANT_MANIFEST)
            .expect_err("non-compliant manifest must fail");
        let s = err.to_string();
        assert!(s.contains("FAILED"));
        // Each failing test should be named.
        assert!(s.contains("oci.schema_version_is_two"));
        assert!(s.contains("oci.has_official_media_type"));
    }

    #[test]
    fn attestation_carries_pack_identity_in_profile_field() {
        let pack = pack_by_name("fedramp-high-openclaw-image@1").unwrap();
        let hash = enforce_pack(&pack, GOOD_MANIFEST).unwrap();
        let att = attestation_from_pack(&pack, hash);
        assert_eq!(att.framework, "FedRAMP");
        assert_eq!(att.baseline, "high");
        assert_eq!(att.profile, "fedramp-high-openclaw-image@1");
        assert_eq!(att.status, ComplianceStatus::Compliant);
    }
}
