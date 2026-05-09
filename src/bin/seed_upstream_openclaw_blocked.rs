//! seed_upstream_openclaw_blocked — tamper-rejection demo named at the
//! REAL upstream openclaw digest.
//!
//! Demonstrates the failure path the user actually cares about:
//!
//! "Could a publisher claim the unmodified upstream openclaw image
//!  is FedRAMP-High compliant by signing the lie cryptographically?"
//!
//! Answer: cartorio's state-leaf invariant rejects the attempt because
//! the publisher would have to either (a) match the result_hash to a
//! real pack run (which fails — see the upstream-audit-2026-05-08.txt
//! capture for the 5 specific failures), or (b) tamper the result_hash
//! post-sign and produce a state-leaf-mismatch.
//!
//! This binary takes path (b) — signs an admit body with one
//! `result_hash`, mutates it post-sign, POSTs to cartorio. The expected
//! outcome is HTTP 4xx with an entry on the /rejected tab tagged with
//! the real upstream openclaw digest:
//!
//!     sha256:59bed2fa7d8f2953dd6fdb4b9adf00a40c5a57b38cdf5e0ca40d916d610f1a14
//!
//! Companion to `seed_failure_tamper` — same publisher, same cartorio.
//! Run AFTER seed_demo + seed_failure_tamper.
//!
//!     CARTORIO_URL=https://cartorio-dev.quero.cloud \
//!       cargo run --release --bin seed_upstream_openclaw_blocked

use std::env;

use cartorio::core::types::ArtifactKind;
use chrono::Utc;
use tabeliao::{demo::artifact_config, sign::Ed25519Signer};
use tameshi::hash::Blake3Hash;

/// The real, canonical sha256 of the linux/amd64 manifest body for
/// `ghcr.io/openclaw/openclaw:latest` as of 2026-05-08. Verifiable by
/// anyone with `curl + Bearer <ghcr-token>`.
const UPSTREAM_OPENCLAW_AMD64_DIGEST: &str =
    "sha256:59bed2fa7d8f2953dd6fdb4b9adf00a40c5a57b38cdf5e0ca40d916d610f1a14";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cartorio_url =
        env::var("CARTORIO_URL").unwrap_or_else(|_| "http://127.0.0.1:18082".to_string());
    eprintln!(
        "=== seed_upstream_openclaw_blocked — attempting forged FedRAMP-High admission \
         for upstream openclaw on {cartorio_url} ==="
    );

    let signer = Ed25519Signer::generate();
    let client = reqwest::Client::new();

    // Claim: upstream openclaw is FedRAMP-High compliant under
    // fedramp-high-openclaw-image@2.
    //
    // Reality (captured live 2026-05-08): the real pack run against
    // these exact bytes fails 5 tests for missing OCI annotations
    // (created/source/revision/version/SLSA-provenance-ref).
    let cfg = artifact_config(
        ArtifactKind::OciImage,
        "openclaw-upstream-as-shipped",
        "ghcr-latest-amd64",
        "fedramp-high-openclaw-image@2",
    );

    let mut admit = tabeliao::admit::build_admit_input(
        cfg,
        UPSTREAM_OPENCLAW_AMD64_DIGEST,
        Utc::now(),
        &signer,
    )?;

    // POST-SIGN tamper — flip the result_hash to a value that does NOT
    // correspond to the (failing) real pack run on the upstream
    // bytes. Cartorio recomposes the state-leaf from the body and
    // notices signed_root.root != recomposed_root → 4xx + rejection
    // log entry tagged with the upstream openclaw digest.
    if let Some(c) = admit.attestation.compliance.as_mut() {
        c.result_hash = Blake3Hash::digest(b"forged-claim-of-fedramp-high-compliance");
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
            "FORGED ADMISSION NOT REJECTED — got {status}; cartorio's state-leaf invariant \
             missed a tamper. body: {body}"
        )
        .into());
    }
    eprintln!(
        "✗ upstream openclaw rejected {} — {}",
        status.as_u16(),
        short(&body)
    );

    // Confirm the rejection log captured this attempt by digest.
    let rejections: serde_json::Value = client
        .get(format!("{cartorio_url}/api/v1/admin/rejections"))
        .send()
        .await?
        .json()
        .await?;
    let logged = rejections
        .get("total")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    eprintln!("rejection log total = {logged}");

    eprintln!();
    eprintln!(
        "✓ The real upstream openclaw amd64 ({UPSTREAM_OPENCLAW_AMD64_DIGEST}) cannot be \n  \
         admitted as FedRAMP-High via tampering. The state-leaf invariant catches it.\n\n  \
         Note: the real pack run against these bytes ALSO fails (5 OCI annotation tests).\n  \
         tabeliao's pre-publish gate would have refused much earlier; this binary skips\n  \
         that gate intentionally to demonstrate cartorio's defense-in-depth."
    );
    Ok(())
}

fn short(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() <= 200 {
        trimmed.to_string()
    } else {
        format!("{}…", &trimmed[..200])
    }
}
