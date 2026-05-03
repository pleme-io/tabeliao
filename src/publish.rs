//! End-to-end publish: hash → admit → push.

use std::time::Duration;

use cartorio::core::types::AdmitArtifactInput;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::admit::build_admit_input;
use crate::attestations::AttestationsConfig;
use crate::error::{Result, TabeliaoError};
use crate::sign::Signer;

#[derive(Debug, Clone)]
pub struct PublishPlan {
    pub cartorio_url: String,
    pub lacre_url: String,
    /// Image name as it appears in OCI registry paths
    /// (e.g. `myorg/myapp`).
    pub image_path: String,
    /// Reference (tag or digest) to push under, e.g. `v1.0.0` or
    /// `sha256:beef...`.
    pub reference: String,
    pub manifest_bytes: Vec<u8>,
    pub manifest_content_type: String,
    /// Optional compliance pack to enforce before publishing. When set,
    /// tabeliao runs the pack, fails closed on any failure, and bakes
    /// the resulting `pack_hash` into the `ComplianceAttestation`. The
    /// `AttestationsConfig`'s compliance block is overridden when this
    /// is `Some`.
    pub compliance_pack_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishOutcome {
    pub digest: String,
    pub artifact_id: String,
    pub event_id: String,
    pub composed_root: String,
}

/// # Errors
/// Returns errors for any step: pack enforcement failure, cartorio
/// admit rejection, network errors, lacre push rejection.
pub async fn publish<S: Signer>(
    mut cfg: AttestationsConfig,
    plan: PublishPlan,
    signer: &S,
) -> Result<PublishOutcome> {
    let digest = manifest_digest(&plan.manifest_bytes);
    let admitted_at = Utc::now();

    if let Some(pack_name) = plan.compliance_pack_name.as_deref() {
        let pack = crate::compliance::pack_by_name(pack_name)?;
        let pack_hash = crate::compliance::enforce_pack(&pack, &plan.manifest_bytes)?;
        let att = crate::compliance::attestation_from_pack(&pack, pack_hash);
        // Splice the pack-derived attestation into the operator-supplied
        // config. Source/build/image pillars are author-supplied;
        // compliance is now load-bearing on the pack run.
        cfg.attestation.compliance = Some(crate::attestations::ComplianceBlock {
            framework: att.framework,
            baseline: att.baseline,
            profile: att.profile,
            result_hash: att.result_hash,
            status: att.status,
        });
    }

    let input = build_admit_input(cfg, &digest, admitted_at, signer)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| TabeliaoError::Network {
            target: plan.cartorio_url.clone(),
            source: e,
        })?;

    let admit_outcome = submit_admit(&client, &plan.cartorio_url, &input).await?;
    push_manifest(&client, &plan).await?;

    Ok(PublishOutcome {
        digest,
        artifact_id: admit_outcome.id,
        event_id: admit_outcome.event_id,
        composed_root: admit_outcome.composed_root,
    })
}

#[must_use]
pub fn manifest_digest(body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(body);
    format!("sha256:{}", hex::encode(h.finalize()))
}

#[derive(Deserialize)]
struct AdmitResponseBody {
    id: String,
    event_id: String,
    composed_root: String,
}

async fn submit_admit(
    client: &reqwest::Client,
    cartorio_url: &str,
    input: &AdmitArtifactInput,
) -> Result<AdmitResponseBody> {
    let url = format!(
        "{}/api/v1/artifacts",
        cartorio_url.trim_end_matches('/')
    );
    let resp = client
        .post(&url)
        .json(input)
        .send()
        .await
        .map_err(|e| TabeliaoError::Network {
            target: url.clone(),
            source: e,
        })?;
    let status = resp.status().as_u16();
    if status == 200 {
        return resp.json::<AdmitResponseBody>().await.map_err(|e| {
            TabeliaoError::Network {
                target: url,
                source: e,
            }
        });
    }
    let body = resp.text().await.unwrap_or_default();
    Err(TabeliaoError::AdmitRejected {
        status,
        message: body,
    })
}

async fn push_manifest(client: &reqwest::Client, plan: &PublishPlan) -> Result<()> {
    let url = format!(
        "{}/v2/{}/manifests/{}",
        plan.lacre_url.trim_end_matches('/'),
        plan.image_path.trim_matches('/'),
        plan.reference
    );
    let resp = client
        .put(&url)
        .header("content-type", &plan.manifest_content_type)
        .body(plan.manifest_bytes.clone())
        .send()
        .await
        .map_err(|e| TabeliaoError::Network {
            target: url.clone(),
            source: e,
        })?;
    let status = resp.status().as_u16();
    // OCI Distribution Spec: 201 Created on success, 202 Accepted is
    // also acceptable for async-finalize backends.
    if (200..300).contains(&status) {
        return Ok(());
    }
    let body = resp.text().await.unwrap_or_default();
    Err(TabeliaoError::PushRejected {
        status,
        message: body,
    })
}
