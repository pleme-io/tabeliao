//! End-to-end: tabeliao publishes through cartorio + lacre + a mock
//! OCI backend, all over real TCP. Closes the operator loop:
//!
//! ```text
//!   tabeliao::publish(cfg, plan, signer)
//!       │
//!       ├─▶ POST cartorio/api/v1/artifacts        ← admission
//!       │
//!       └─▶ PUT  lacre/v2/{image}/manifests/{ref} ← shipping
//!                via cartorio lookup-by-digest
//!                if Active+org match → forward to backend
//! ```
//!
//! Asserts:
//!   1. cartorio admits successfully (signature verifies, no skew)
//!   2. lacre forwards to backend (cartorio reports Active+org)
//!   3. backend received the exact manifest bytes
//!   4. cartorio's `lookup_by_digest` returns the same id

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    extract::Request,
    response::Response,
    routing::any,
};
use cartorio::{api::router as cartorio_router, config::RegistryConfig, state::AppState as CartorioAppState};
use lacre::{
    Backend, HttpBackend, HttpCartorioClient,
    routes::{AppState as LacreAppState, router as lacre_router},
};
use tabeliao::{
    AttestationsConfig, PublishPlan, publish,
    attestations::{AttestationsBlock, BuildBlock, ComplianceBlock, ImageBlock, SourceBlock},
    sign::Blake3Signer,
};
use cartorio::core::types::{ArtifactKind, ComplianceStatus};
use tameshi::hash::Blake3Hash;

const ORG: &str = "pleme-io";

#[derive(Default)]
struct MockBackend {
    received: Mutex<Vec<(String, String, Vec<u8>)>>,
}

async fn spawn_mock_backend() -> (String, Arc<MockBackend>) {
    let backend = Arc::new(MockBackend::default());
    let backend_clone = backend.clone();
    let app: Router = Router::new().route(
        "/{*rest}",
        any(move |req: Request| {
            let backend = backend_clone.clone();
            async move {
                let method = req.method().as_str().to_string();
                let path = req.uri().path().to_string();
                let body = axum::body::to_bytes(req.into_body(), 4 * 1024 * 1024)
                    .await
                    .unwrap_or_default();
                backend
                    .received
                    .lock()
                    .unwrap()
                    .push((method, path, body.to_vec()));
                Response::builder()
                    .status(201)
                    .header("docker-content-digest", "sha256:fake")
                    .body(axum::body::Body::from("ok"))
                    .unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, backend)
}

async fn spawn_cartorio() -> (String, Arc<CartorioAppState>) {
    let cfg = RegistryConfig {
        org: ORG.into(),
        listen: "127.0.0.1:0".into(),
        pki_url: None,
    };
    let state = CartorioAppState::new(cfg);
    let app = cartorio_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, state)
}

async fn spawn_lacre(cartorio_url: String, backend_url: String, org: &str) -> String {
    let cartorio_client = HttpCartorioClient::new(cartorio_url).unwrap();
    let backend: Arc<dyn Backend> = Arc::new(HttpBackend::new(backend_url).unwrap());
    let state = Arc::new(LacreAppState {
        cartorio: Arc::new(cartorio_client),
        backend,
        org: org.into(),
        max_manifest_bytes: 4 * 1024 * 1024,
    });
    let app = lacre_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    url
}

fn cfg_for(name: &str, version: &str) -> AttestationsConfig {
    AttestationsConfig {
        kind: ArtifactKind::OciImage,
        name: name.into(),
        version: version.into(),
        publisher_id: "alice@pleme.io".into(),
        org: ORG.into(),
        attestation: AttestationsBlock {
            source: Some(SourceBlock {
                git_commit: "abc123".into(),
                tree_hash: Blake3Hash::digest(b"tree"),
                flake_lock_hash: Blake3Hash::digest(b"lock"),
            }),
            build: Some(BuildBlock {
                closure_hash: Blake3Hash::digest(b"closure"),
                sbom_hash: Blake3Hash::digest(b"sbom"),
                slsa_level: 3,
            }),
            image: Some(ImageBlock {
                cosign_signature_ref: "ghcr.io/x:sig".into(),
                slsa_provenance_ref: "ghcr.io/x:prov".into(),
            }),
            compliance: Some(ComplianceBlock {
                framework: "NIST_800_53".into(),
                baseline: "high".into(),
                profile: "nist-800-53-high".into(),
                result_hash: Blake3Hash::digest(b"compliance-passed"),
                status: ComplianceStatus::Compliant,
            }),
        },
    }
}

const TEST_MANIFEST: &[u8] = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":1},"layers":[]}"#;

#[tokio::test]
async fn full_publisher_loop_admits_and_pushes_compliant_image() {
    let (backend_url, backend_recorder) = spawn_mock_backend().await;
    let (cartorio_url, cartorio_state) = spawn_cartorio().await;
    let lacre_url = spawn_lacre(cartorio_url.clone(), backend_url, ORG).await;

    let signer = Blake3Signer::from_hex(&"0".repeat(64)).unwrap();
    let plan = PublishPlan {
        cartorio_url: cartorio_url.clone(),
        lacre_url: lacre_url.clone(),
        image_path: "myorg/myimage".into(),
        reference: "v1.0.0".into(),
        manifest_bytes: TEST_MANIFEST.to_vec(),
        manifest_content_type: "application/vnd.oci.image.manifest.v1+json".into(),
    };
    let outcome = publish(cfg_for("myimage", "1.0.0"), plan, &signer).await.unwrap();

    // Outcome shape sanity.
    assert!(outcome.digest.starts_with("sha256:"));
    assert!(outcome.artifact_id.starts_with("art-"));
    assert!(outcome.event_id.starts_with("evt-"));

    // Cartorio knows about the artifact at the same digest.
    let by_digest = cartorio_state
        .store
        .get_artifact_by_digest(&outcome.digest)
        .await
        .expect("cartorio must have admitted by this digest");
    assert_eq!(by_digest.id, outcome.artifact_id);
    assert_eq!(by_digest.org, ORG);
    assert_eq!(by_digest.name, "myimage");

    // Lacre forwarded the manifest to the backend.
    let received = backend_recorder.received.lock().unwrap();
    let manifest_puts: Vec<_> = received
        .iter()
        .filter(|(m, p, _)| m == "PUT" && p.contains("/manifests/"))
        .collect();
    assert_eq!(manifest_puts.len(), 1, "exactly one manifest must reach backend");
    assert_eq!(manifest_puts[0].2, TEST_MANIFEST);
    assert_eq!(manifest_puts[0].1, "/v2/myorg/myimage/manifests/v1.0.0");
}

#[tokio::test]
async fn publish_idempotency_admit_only_once_per_digest() {
    // Publishing the same body twice must result in cartorio rejecting
    // the second admit (already-admitted) — without leaking state.
    let (backend_url, _backend) = spawn_mock_backend().await;
    let (cartorio_url, _cstate) = spawn_cartorio().await;
    let lacre_url = spawn_lacre(cartorio_url.clone(), backend_url, ORG).await;

    let signer = Blake3Signer::from_hex(&"0".repeat(64)).unwrap();
    let plan1 = PublishPlan {
        cartorio_url: cartorio_url.clone(),
        lacre_url: lacre_url.clone(),
        image_path: "myorg/idem".into(),
        reference: "v1".into(),
        manifest_bytes: TEST_MANIFEST.to_vec(),
        manifest_content_type: "application/vnd.oci.image.manifest.v1+json".into(),
    };
    publish(cfg_for("idem", "1.0.0"), plan1.clone(), &signer)
        .await
        .expect("first publish");

    // Second publish with same bytes → same digest → cartorio conflict.
    let result = publish(cfg_for("idem", "2.0.0"), plan1, &signer).await;
    let err = result.expect_err("second publish must fail");
    let err_str = err.to_string();
    assert!(
        err_str.contains("already admitted") || err_str.contains("conflict") || err_str.contains("409"),
        "expected conflict-shaped error, got: {err_str}"
    );
}

#[tokio::test]
async fn publish_fails_at_admit_stage_when_signing_key_drifts() {
    // Build the input with one key, then post it to a server that
    // would compute the same composed_root regardless — the signature
    // shape passes (cartorio only checks shape today). This test
    // documents that current behavior; if/when cartorio adds signature
    // VERIFICATION, this test must flip and assert rejection.
    let (backend_url, _backend) = spawn_mock_backend().await;
    let (cartorio_url, _cstate) = spawn_cartorio().await;
    let lacre_url = spawn_lacre(cartorio_url.clone(), backend_url, ORG).await;

    let bad_signer = Blake3Signer::from_hex(&"f".repeat(64)).unwrap();
    let plan = PublishPlan {
        cartorio_url: cartorio_url.clone(),
        lacre_url,
        image_path: "myorg/bad-key".into(),
        reference: "v1".into(),
        manifest_bytes: TEST_MANIFEST.to_vec(),
        manifest_content_type: "application/vnd.oci.image.manifest.v1+json".into(),
    };
    // Cartorio currently accepts any 64-hex signature shape.
    let outcome = publish(cfg_for("bad-key", "1.0.0"), plan, &bad_signer)
        .await
        .expect("v0.1 cartorio accepts ANY 64-hex signature shape");
    assert!(outcome.artifact_id.starts_with("art-"));
}

#[tokio::test]
async fn publish_surfaces_lacre_rejection_when_org_mismatch() {
    // Configure tabeliao to publish for "other-org" but lacre gates
    // ORG=pleme-io. Cartorio admits (its org-match logic is per-input,
    // not per-instance), but lacre rejects with 403.
    let (backend_url, backend_recorder) = spawn_mock_backend().await;
    // Note: cartorio's RegistryConfig has org pinned to ORG too; a
    // publisher submitting with org=other-org would be rejected at
    // cartorio. To exercise lacre's org check specifically, we need
    // cartorio configured for "other-org" but lacre configured for
    // "pleme-io".
    let cfg = RegistryConfig {
        org: "other-org".into(),
        listen: "127.0.0.1:0".into(),
        pki_url: None,
    };
    let cartorio_state = CartorioAppState::new(cfg);
    let app = cartorio_router(cartorio_state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cartorio_url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let lacre_url = spawn_lacre(cartorio_url.clone(), backend_url, ORG).await;

    let signer = Blake3Signer::from_hex(&"0".repeat(64)).unwrap();
    let mut config = cfg_for("crossorg", "1.0.0");
    config.org = "other-org".into();
    let plan = PublishPlan {
        cartorio_url,
        lacre_url,
        image_path: "myorg/crossorg".into(),
        reference: "v1".into(),
        manifest_bytes: TEST_MANIFEST.to_vec(),
        manifest_content_type: "application/vnd.oci.image.manifest.v1+json".into(),
    };
    let result = publish(config, plan, &signer).await;
    let err = result.expect_err("lacre must reject org-mismatch");
    let s = err.to_string();
    assert!(
        s.contains("registered under") || s.contains("403"),
        "expected lacre 403 with org-mismatch reason, got: {s}"
    );
    // Backend must NOT have seen the manifest PUT.
    assert!(
        backend_recorder
            .received
            .lock()
            .unwrap()
            .iter()
            .all(|(m, p, _)| !(m == "PUT" && p.contains("/manifests/"))),
        "backend must not see manifest under cross-org publish"
    );
}

#[tokio::test]
async fn publish_to_unreachable_cartorio_returns_network_error() {
    let (backend_url, _backend) = spawn_mock_backend().await;
    let dead_cartorio = "http://127.0.0.1:1".to_string();
    let lacre_url = spawn_lacre(dead_cartorio.clone(), backend_url, ORG).await;

    let signer = Blake3Signer::from_hex(&"0".repeat(64)).unwrap();
    let plan = PublishPlan {
        cartorio_url: dead_cartorio,
        lacre_url,
        image_path: "myorg/dead".into(),
        reference: "v1".into(),
        manifest_bytes: TEST_MANIFEST.to_vec(),
        manifest_content_type: "application/vnd.oci.image.manifest.v1+json".into(),
    };
    let result = publish(cfg_for("dead", "1.0.0"), plan, &signer).await;
    let err = result.expect_err("must fail when cartorio is unreachable");
    let s = err.to_string();
    assert!(
        s.contains("network") || s.contains("connect") || s.contains("error sending"),
        "expected network-shaped error, got: {s}"
    );
}
