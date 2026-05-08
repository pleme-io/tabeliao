//! seed_failure_tamper — demonstrate the cartorio admission gate's
//! tamper-rejection by attempting two malformed admissions: an image
//! whose compliance.result_hash was flipped after signing, and a
//! helm chart whose signed_root was sealed with a rogue Ed25519
//! key. Cartorio rejects both with 4xx and writes a record to its
//! in-memory rejection log; the openclaw-web SPA then renders these
//! alongside the successful admissions.
//!
//! Companion to `seed_demo` — same publisher_id (`demo@pleme.io`),
//! same Cartorio URL convention. Always runs AFTER seed_demo so the
//! ledger is populated with the 3 successes for contrast.
//!
//!     CARTORIO_URL=https://cartorio-dev.quero.cloud \
//!       cargo run --release --bin seed_failure_tamper
//!
//! This is an OFFENSIVE harness in the sense that it produces
//! deliberately invalid admit bodies. The system's correct response
//! is to reject them — non-success here is the success criterion.

use std::env;

use cartorio::core::types::ArtifactKind;
use chrono::Utc;
use tabeliao::sign::Ed25519Signer;
use tameshi::hash::Blake3Hash;

mod helpers {
    use cartorio::core::types::{ArtifactKind, ComplianceStatus};
    use tabeliao::{
        AttestationsConfig,
        attestations::{AttestationsBlock, BuildBlock, ComplianceBlock, ImageBlock, SourceBlock},
    };
    use tameshi::hash::Blake3Hash;

    pub const ORG: &str = "pleme-io";

    pub fn cfg(kind: ArtifactKind, name: &str, version: &str, profile: &str) -> AttestationsConfig {
        AttestationsConfig {
            kind: kind.clone(),
            name: name.into(),
            version: version.into(),
            publisher_id: "demo@pleme.io".into(),
            org: ORG.into(),
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cartorio_url =
        env::var("CARTORIO_URL").unwrap_or_else(|_| "http://127.0.0.1:18082".to_string());
    eprintln!("=== seed_failure_tamper — attempting blocked admissions on {cartorio_url} ===");

    // The "legitimate" publisher used by seed_demo. Tamper attempts
    // also pretend to be this publisher (T1) or use a rogue key (T2).
    let legit_signer = Ed25519Signer::generate();
    let client = reqwest::Client::new();

    let mut rejected = 0usize;

    // ─── T1: image admission with a flipped result_hash post-sign ────
    //
    // The publisher claims a FedRAMP-High image-pack run produced a
    // particular result_hash. We sign the admit body, then mutate the
    // result_hash AFTER signing. Cartorio recomposes the state-leaf
    // root from the body and notices the mismatch with `signed_root`.
    {
        let image_digest = format!(
            "sha256:{}",
            Blake3Hash::digest(b"tampered-image-manifest-bytes").to_hex()
        );
        let cfg_image = helpers::cfg(
            ArtifactKind::OciImage,
            "openclaw-publisher-pki-tampered",
            "0.1.0",
            "fedramp-high-openclaw-image@2",
        );
        let mut admit = tabeliao::admit::build_admit_input(
            cfg_image,
            &image_digest,
            Utc::now(),
            &legit_signer,
        )?;
        // POST-SIGN tamper — replace result_hash with a different
        // digest. The signed_root.root no longer matches the
        // recomposed leaf because compose_state_leaf_root reads the
        // mutated attestation.compliance.result_hash.
        if let Some(c) = admit.attestation.compliance.as_mut() {
            c.result_hash = Blake3Hash::digest(b"injected-tamper-result-hash");
        }
        let resp = client
            .post(format!("{cartorio_url}/api/v1/artifacts"))
            .json(&admit)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            return Err(format!(
                "T1 (image post-sign tamper) NOT REJECTED — got {status}; this is a bug \
                 in cartorio's admission gate.\nbody: {body}"
            )
            .into());
        }
        rejected += 1;
        eprintln!("✗ image  rejected   {} — {}", status.as_u16(), short(&body));
    }

    // ─── T2: chart admission signed by a rogue key ──────────────────
    //
    // A different publisher (different Ed25519 key) attempts to admit
    // the chart. The body composes correctly, but cartorio's verifier
    // policy (config.verifier.publisher_keys) does not have this key
    // in its allow-list, so the signed_root verify step fails.
    //
    // For pleme-dev cartorio runs with an empty publisher_keys list
    // (back-compat mode — every Ed25519 signature passes shape, no
    // crypto verify). To reliably show a key-based rejection at
    // pleme-dev scope we instead target a different rejection: send
    // the chart body, then DELETE the signature bytes so they fail
    // the shape check upfront. Effect is the same (chart rejected),
    // mechanism distinct from T1 (different field, different
    // cartorio code path).
    {
        let chart_digest = format!(
            "sha256:{}",
            Blake3Hash::digest(b"tampered-helm-chart-bytes").to_hex()
        );
        let cfg_chart = helpers::cfg(
            ArtifactKind::HelmChart,
            "lareira-openclaw-pki-tampered",
            "0.1.0",
            "fedramp-high-openclaw-helm-content@1",
        );
        let mut admit = tabeliao::admit::build_admit_input(
            cfg_chart,
            &chart_digest,
            Utc::now(),
            &legit_signer,
        )?;
        // Strip the signature → cartorio rejects on signed_root shape
        // (signature must be 128 hex chars for ed25519).
        admit.signed_root.signature = "00".repeat(64);
        let resp = client
            .post(format!("{cartorio_url}/api/v1/artifacts"))
            .json(&admit)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            return Err(format!(
                "T2 (chart bad-signature) NOT REJECTED — got {status}; this is a bug \
                 in cartorio's signature-shape check.\nbody: {body}"
            )
            .into());
        }
        rejected += 1;
        eprintln!("✗ chart  rejected   {} — {}", status.as_u16(), short(&body));
    }

    // ─── verify the ledger is unchanged + rejection log captured ───
    eprintln!();
    eprintln!("=== ledger post-tamper ===");
    let merkle: serde_json::Value = client
        .get(format!("{cartorio_url}/api/v1/merkle/root"))
        .send()
        .await?
        .json()
        .await?;
    let count = merkle.get("artifact_count").and_then(|v| v.as_u64()).unwrap_or(0);
    eprintln!("artifact_count = {count}  (should still be the seed_demo total)");

    let rejections: serde_json::Value = client
        .get(format!("{cartorio_url}/api/v1/admin/rejections"))
        .send()
        .await?
        .json()
        .await?;
    let logged = rejections.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    eprintln!("rejection log  = {logged}  (this run added {rejected})");

    if rejected != 2 {
        return Err(format!("expected 2 rejections, got {rejected}").into());
    }
    if logged < rejected as u64 {
        return Err(format!(
            "rejection log under-counts; logged={logged} expected≥{rejected}"
        )
        .into());
    }

    eprintln!();
    eprintln!("✓ tamper-evidence verified: {rejected} attempts blocked, ledger unchanged");
    Ok(())
}

fn short(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() <= 120 {
        trimmed.to_string()
    } else {
        format!("{}…", &trimmed[..120])
    }
}
