//! seed_demo — populate a live cartorio with three demo admissions
//! (image + helm chart + bundle) so the openclaw-web SPA renders real
//! proofs end-to-end.
//!
//! Built for the public pleme-dev demo: cartorio runs `--backend
//! memory` (substrate `rust-service-flake.nix` doesn't yet thread
//! `cargoFeatures`) so content is ephemeral. After every cartorio pod
//! restart, re-run this binary against a port-forwarded cartorio:
//!
//!     kubectl --context pleme-dev -n openclaw port-forward \
//!       svc/openclaw-stack-cartorio 18082:8082 &
//!     CARTORIO_URL=http://127.0.0.1:18082 \
//!       cargo run --release --bin seed_demo
//!
//! NOT a replacement for `tabeliao::publish` — this skips the lacre
//! gate + zot push + real OCI manifest. Synthesizes a stable bundle
//! of three admissions sufficient to render the SPA's overview /
//! artifacts / detail / verify views.

use std::env;

use cartorio::core::types::ArtifactKind;
use chrono::Utc;
use tabeliao::{demo::artifact_config, sign::Ed25519Signer};
use tameshi::hash::Blake3Hash;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cartorio_url =
        env::var("CARTORIO_URL").unwrap_or_else(|_| "http://127.0.0.1:18082".to_string());
    eprintln!("=== seed_demo — populating {cartorio_url} ===");

    let signer = Ed25519Signer::generate();
    let client = reqwest::Client::new();

    // ── 1. OCI image admission ───────────────────────────────────────
    let image_digest = format!(
        "sha256:{}",
        Blake3Hash::digest(b"openclaw-publisher-pki-manifest-bytes").to_hex()
    );
    let image_input = tabeliao::admit::build_admit_input(
        artifact_config(
            ArtifactKind::OciImage,
            "openclaw-publisher-pki",
            "0.1.0",
            "fedramp-high-openclaw-image@2",
        ),
        &image_digest,
        Utc::now(),
        &signer,
    )?;
    let resp = client
        .post(format!("{cartorio_url}/api/v1/artifacts"))
        .json(&image_input)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("image admit {status}: {body}").into());
    }
    eprintln!("✓ image admitted    digest={image_digest}");

    // ── 2. Helm chart admission ──────────────────────────────────────
    let chart_digest = format!(
        "sha256:{}",
        Blake3Hash::digest(b"lareira-openclaw-pki-chart-bytes").to_hex()
    );
    let chart_input = tabeliao::admit::build_admit_input(
        artifact_config(
            ArtifactKind::HelmChart,
            "lareira-openclaw-pki",
            "0.1.0",
            "fedramp-high-openclaw-helm-content@1",
        ),
        &chart_digest,
        Utc::now(),
        &signer,
    )?;
    let resp = client
        .post(format!("{cartorio_url}/api/v1/artifacts"))
        .json(&chart_input)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("chart admit {status}: {body}").into());
    }
    eprintln!("✓ chart admitted    digest={chart_digest}");

    // ── 3. Bundle admission (binds image + chart) ────────────────────
    let bundle_digest = format!(
        "sha256:{}",
        Blake3Hash::digest(b"openclaw-bundle-v0.1.0").to_hex()
    );
    let mut bundle_cfg = artifact_config(
        ArtifactKind::Bundle,
        "openclaw",
        "0.1.0",
        "fedramp-high-openclaw-bundle@1",
    );
    bundle_cfg.bundle_members = Some(vec![
        tabeliao::attestations::BundleMemberSpec {
            digest: image_digest.clone(),
            kind: "oci-image".into(),
            pack_hash: Blake3Hash::digest(b"openclaw-publisher-pki-pack-hash"),
        },
        tabeliao::attestations::BundleMemberSpec {
            digest: chart_digest.clone(),
            kind: "helm-chart".into(),
            pack_hash: Blake3Hash::digest(b"lareira-openclaw-pki-pack-hash"),
        },
    ]);
    let bundle_input =
        tabeliao::admit::build_admit_input(bundle_cfg, &bundle_digest, Utc::now(), &signer)?;
    let resp = client
        .post(format!("{cartorio_url}/api/v1/artifacts"))
        .json(&bundle_input)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("bundle admit {status}: {body}").into());
    }
    eprintln!("✓ bundle admitted   digest={bundle_digest}");

    // ── verify ──────────────────────────────────────────────────────
    let resp = client
        .get(format!("{cartorio_url}/api/v1/artifacts?limit=10"))
        .send()
        .await?
        .text()
        .await?;
    eprintln!("\n=== final state ===");
    eprintln!("{resp}");
    Ok(())
}
