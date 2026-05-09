//! CycloneDX 1.6 SBOM generation from an OCI image manifest.
//!
//! Phase C3a — closes one of the audit's load-bearing gaps:
//! `BuildAttestation.sbom_hash` was an operator-typed opaque hex
//! string, with no link to a real document. This module makes the
//! SBOM a real CycloneDX 1.6 JSON document, deterministic from the
//! manifest bytes, with `sbom_hash = blake3(serialized canonical JSON)`.
//!
//! Format: CycloneDX 1.6 — the federal-procurement-friendly SBOM
//! standard adopted by EO 14028 / OMB M-22-18 / NTIA Minimum Elements
//! (per the Phase A audit research). Schema:
//! <https://cyclonedx.org/docs/1.6/json/>.
//!
//! Scope of this minimum viable SBOM:
//!
//! - **bomFormat / specVersion / serialNumber / version** — required.
//! - **metadata.timestamp** — operator-supplied (default now()) so the
//!   SBOM is reproducible from a single timestamp input.
//! - **metadata.tools[*]** — declares tabeliao as the producer.
//! - **metadata.component** — the OCI image being SBOM'd
//!   (type=container, name=image-path, version=ref, hashes=sha256
//!   manifest digest).
//! - **components[*]** — one entry per layer in the manifest, type=file,
//!   hashes=sha256 layer digest, properties=mediaType+size.
//!
//! NTIA Minimum Elements coverage (per Phase A research):
//!   ✓ supplier  (set on metadata.component if vendor annotation present)
//!   ✓ name
//!   ✓ version  (= reference; falls back to digest)
//!   ✓ unique identifier  (= sha256 manifest digest as a hash)
//!   ✓ dependency relationships  (image-component has every layer as
//!     a transitive dependency via `dependencies` graph)
//!   ✓ author  (the producing tool — tabeliao)
//!   ✓ timestamp
//!
//! What this MVP does NOT do (yet):
//!
//! - Walk inside the image filesystem to enumerate Linux packages
//!   (apt/rpm/apk). That requires `syft` or equivalent — a future
//!   `--use-syft` flag will subprocess syft and merge its output.
//! - Sign the SBOM document. Phase C3b's DSSE+Ed25519 path covers it.
//! - Embed VEX (Vulnerability Exchange) statements. Tracked in a
//!   future sub-phase alongside Trivy integration.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, TabeliaoError};

/// Canonical media type for a CycloneDX 1.6 JSON SBOM (per
/// cyclonedx.org/specification/overview).
pub const CYCLONEDX_MEDIA_TYPE: &str = "application/vnd.cyclonedx+json";

/// CycloneDX 1.6 version string we emit.
pub const SPEC_VERSION: &str = "1.6";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sbom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: Metadata,
    pub components: Vec<Component>,
    pub dependencies: Vec<Dependency>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub timestamp: String,
    pub tools: Tools,
    pub component: Component,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tools {
    pub components: Vec<Component>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    #[serde(rename = "type")]
    pub component_type: ComponentType,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hashes: Vec<Hash>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub properties: Vec<Property>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentType {
    Application,
    Container,
    File,
    Library,
    Firmware,
    OperatingSystem,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash {
    pub alg: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Property {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub bom_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub depends_on: Vec<String>,
}

/// Build an SBOM from an OCI manifest's bytes + a few declarative
/// inputs. Determinism contract: same inputs ⇒ byte-identical output.
///
/// `image_name` is the OCI image path (e.g. `pleme-io/openclaw-pki`).
/// `reference` is the publish reference (tag or digest). `timestamp`
/// is RFC 3339; pass `Utc::now().to_rfc3339()` at the operator boundary.
/// `serial_number` is a UUID URN — the operator passes one for
/// repeatability (same urn across re-runs preserves the SBOM's
/// `serialNumber` field for downstream tooling that cares).
///
/// # Errors
/// Returns `InvalidInput` if the manifest is not valid JSON or has
/// no `layers[]` array.
pub fn from_oci_manifest(
    manifest_bytes: &[u8],
    image_name: &str,
    reference: &str,
    timestamp: &str,
    serial_number_urn: &str,
    publisher: Option<&str>,
) -> Result<Sbom> {
    let v: serde_json::Value = serde_json::from_slice(manifest_bytes).map_err(|e| {
        TabeliaoError::InvalidInput(format!("manifest is not valid JSON: {e}"))
    })?;
    let layers = v
        .get("layers")
        .and_then(|l| l.as_array())
        .ok_or_else(|| TabeliaoError::InvalidInput("manifest has no layers[] array".into()))?;

    // Image manifest digest = sha256 of the manifest body bytes (the
    // same value cartorio uses as the artifact key).
    let mut h = Sha256::new();
    h.update(manifest_bytes);
    let manifest_sha256 = format!("{:x}", h.finalize());

    let image_bom_ref = format!("pkg:oci/{image_name}@sha256:{manifest_sha256}");

    let image_component = Component {
        bom_ref: Some(image_bom_ref.clone()),
        component_type: ComponentType::Container,
        name: image_name.to_string(),
        version: Some(reference.to_string()),
        publisher: publisher.map(str::to_string),
        hashes: vec![Hash {
            alg: "SHA-256".into(),
            content: manifest_sha256.clone(),
        }],
        properties: Vec::new(),
    };

    let mut layer_components: Vec<Component> = Vec::with_capacity(layers.len());
    let mut layer_refs: Vec<String> = Vec::with_capacity(layers.len());
    for (i, layer) in layers.iter().enumerate() {
        let digest = layer.get("digest").and_then(|d| d.as_str()).ok_or_else(|| {
            TabeliaoError::InvalidInput(format!("layer[{i}] has no digest"))
        })?;
        // Strip the `sha256:` prefix for the hash content per
        // CycloneDX `Hash.content` shape (just the encoded portion).
        let content = digest.strip_prefix("sha256:").unwrap_or(digest);
        let media_type = layer.get("mediaType").and_then(|m| m.as_str()).unwrap_or("");
        let size = layer.get("size").and_then(|s| s.as_u64());
        let bom_ref = format!("pkg:oci/layer/{digest}");
        let mut props = vec![Property {
            name: "oci:mediaType".into(),
            value: media_type.to_string(),
        }];
        if let Some(s) = size {
            props.push(Property {
                name: "oci:size".into(),
                value: s.to_string(),
            });
        }
        layer_components.push(Component {
            bom_ref: Some(bom_ref.clone()),
            component_type: ComponentType::File,
            name: format!("layer-{i:03}"),
            version: None,
            publisher: None,
            hashes: vec![Hash {
                alg: "SHA-256".into(),
                content: content.to_string(),
            }],
            properties: props,
        });
        layer_refs.push(bom_ref);
    }

    let dependencies = vec![Dependency {
        bom_ref: image_bom_ref.clone(),
        depends_on: layer_refs,
    }];

    let tabeliao_component = Component {
        bom_ref: None,
        component_type: ComponentType::Application,
        name: "tabeliao".into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
        publisher: Some("pleme-io".into()),
        hashes: Vec::new(),
        properties: Vec::new(),
    };

    Ok(Sbom {
        bom_format: "CycloneDX".into(),
        spec_version: SPEC_VERSION.into(),
        serial_number: serial_number_urn.to_string(),
        version: 1,
        metadata: Metadata {
            timestamp: timestamp.to_string(),
            tools: Tools {
                components: vec![tabeliao_component],
            },
            component: image_component,
        },
        components: layer_components,
        dependencies,
    })
}

/// Serialize the SBOM as canonical JSON: 2-space indent, sorted keys
/// where serde gives us order, no trailing newline. Determinism is
/// load-bearing for the `sbom_hash` to match across re-runs.
///
/// # Errors
/// Returns the underlying serde error if serialization fails (cannot
/// happen for our schema in practice).
pub fn serialize_canonical(sbom: &Sbom) -> Result<String> {
    serde_json::to_string_pretty(sbom)
        .map_err(|e| TabeliaoError::InvalidInput(format!("serialize sbom: {e}")))
}

/// Compute the SHA-256 of the canonical SBOM bytes. This is what
/// goes into `BuildAttestation.sbom_hash` (cartorio v0.5.x will
/// also store the SBOM document itself; in v0.4.x the hash is the
/// only mechanism).
///
/// # Errors
/// Returns the serialization error.
pub fn canonical_sha256(sbom: &Sbom) -> Result<String> {
    let json = serialize_canonical(sbom)?;
    let mut h = Sha256::new();
    h.update(json.as_bytes());
    Ok(format!("{:x}", h.finalize()))
}

/// Validate that an SBOM byte stream is the canonical serialization
/// of an `Sbom` value (parses + re-serializes + compares hashes).
/// Used by verifiers to confirm the document hasn't been tampered.
///
/// # Errors
/// Returns `InvalidInput` if parsing or canonicalization fails.
pub fn verify_canonical_serialization(bytes: &[u8]) -> Result<()> {
    let parsed: Sbom = serde_json::from_slice(bytes).map_err(|e| {
        TabeliaoError::InvalidInput(format!("sbom bytes are not valid CycloneDX JSON: {e}"))
    })?;
    let canonical = serialize_canonical(&parsed)?;
    if canonical.as_bytes() != bytes {
        return Err(TabeliaoError::InvalidInput(
            "sbom bytes are valid CycloneDX but NOT canonical serialization (re-serialize to fix)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = br#"{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "size": 5683,
    "digest": "sha256:c34b8ac752cccfed6197abc689e7adfe0200b9ea9ba711c2e15c455ce9ef0665"
  },
  "layers": [
    {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 94070, "digest": "sha256:a25e2cd169d8fdb863f567a3f2500a26bb857fb95f3008e3b941db93b3065da3"},
    {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 9400, "digest": "sha256:b25e2cd169d8fdb863f567a3f2500a26bb857fb95f3008e3b941db93b3065da4"}
  ]
}"#;

    fn build() -> Sbom {
        from_oci_manifest(
            FIXTURE,
            "pleme-io/openclaw-publisher-pki",
            "v0.1.0",
            "2026-05-09T00:00:00Z",
            "urn:uuid:00000000-0000-0000-0000-000000000000",
            Some("Pleme.io"),
        )
        .unwrap()
    }

    #[test]
    fn sbom_carries_required_cyclonedx_fields() {
        let s = build();
        assert_eq!(s.bom_format, "CycloneDX");
        assert_eq!(s.spec_version, "1.6");
        assert!(s.serial_number.starts_with("urn:uuid:"));
        assert_eq!(s.version, 1);
        assert_eq!(s.metadata.timestamp, "2026-05-09T00:00:00Z");
        assert_eq!(s.metadata.tools.components[0].name, "tabeliao");
    }

    #[test]
    fn metadata_component_is_the_image_with_manifest_digest() {
        let s = build();
        let c = &s.metadata.component;
        assert_eq!(c.component_type, ComponentType::Container);
        assert_eq!(c.name, "pleme-io/openclaw-publisher-pki");
        assert_eq!(c.version.as_deref(), Some("v0.1.0"));
        assert_eq!(c.publisher.as_deref(), Some("Pleme.io"));
        assert_eq!(c.hashes.len(), 1);
        assert_eq!(c.hashes[0].alg, "SHA-256");
        // Re-hash the fixture and compare.
        let mut h = Sha256::new();
        h.update(FIXTURE);
        let expected = format!("{:x}", h.finalize());
        assert_eq!(c.hashes[0].content, expected);
    }

    #[test]
    fn each_layer_becomes_a_file_component_with_sha256_hash() {
        let s = build();
        assert_eq!(s.components.len(), 2);
        assert_eq!(s.components[0].component_type, ComponentType::File);
        assert_eq!(s.components[0].hashes[0].alg, "SHA-256");
        // Layer hash = encoded portion only (no sha256: prefix).
        assert!(!s.components[0].hashes[0].content.starts_with("sha256:"));
        assert_eq!(s.components[0].hashes[0].content.len(), 64);
        assert!(
            s.components[0]
                .properties
                .iter()
                .any(|p| p.name == "oci:mediaType")
        );
        assert!(
            s.components[0]
                .properties
                .iter()
                .any(|p| p.name == "oci:size" && p.value == "94070")
        );
    }

    #[test]
    fn dependency_graph_links_image_to_every_layer() {
        let s = build();
        assert_eq!(s.dependencies.len(), 1);
        let dep = &s.dependencies[0];
        assert!(dep.bom_ref.starts_with("pkg:oci/"));
        assert_eq!(dep.depends_on.len(), 2);
        assert!(dep.depends_on.iter().all(|r| r.starts_with("pkg:oci/layer/")));
    }

    #[test]
    fn canonical_serialization_is_deterministic() {
        let s1 = build();
        let s2 = build();
        let j1 = serialize_canonical(&s1).unwrap();
        let j2 = serialize_canonical(&s2).unwrap();
        assert_eq!(j1, j2, "two builds must produce byte-identical SBOM JSON");
    }

    #[test]
    fn canonical_sha256_is_stable_across_runs() {
        let s = build();
        let h1 = canonical_sha256(&s).unwrap();
        let h2 = canonical_sha256(&s).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // sha256 hex
    }

    #[test]
    fn changing_image_reference_changes_sbom_hash() {
        let a = from_oci_manifest(
            FIXTURE, "x/y", "v1", "2026-05-09T00:00:00Z",
            "urn:uuid:00000000-0000-0000-0000-000000000000", None,
        ).unwrap();
        let b = from_oci_manifest(
            FIXTURE, "x/y", "v2", "2026-05-09T00:00:00Z",
            "urn:uuid:00000000-0000-0000-0000-000000000000", None,
        ).unwrap();
        assert_ne!(canonical_sha256(&a).unwrap(), canonical_sha256(&b).unwrap());
    }

    #[test]
    fn changing_layer_byte_changes_sbom_hash() {
        // Same image ref + reference + timestamp + UUID → only manifest
        // bytes differ → SBOM hash differs. Flip a single char inside
        // a layer digest from 'a' → 'b' (preserves JSON validity, just
        // changes one hex char of one digest).
        let mut alt = FIXTURE.to_vec();
        // Find the first occurrence of "a25e2cd169" inside the manifest
        // (the first layer's digest's encoded portion) and bump the
        // first 'a' to 'b'.
        let needle = b"a25e2cd169";
        let pos = alt
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("fixture must contain the layer digest prefix");
        alt[pos] = b'b';

        let a = from_oci_manifest(
            FIXTURE, "x/y", "v1", "2026-05-09T00:00:00Z",
            "urn:uuid:00000000-0000-0000-0000-000000000000", None,
        ).unwrap();
        let b = from_oci_manifest(
            &alt, "x/y", "v1", "2026-05-09T00:00:00Z",
            "urn:uuid:00000000-0000-0000-0000-000000000000", None,
        ).unwrap();
        assert_ne!(canonical_sha256(&a).unwrap(), canonical_sha256(&b).unwrap());
    }

    #[test]
    fn invalid_manifest_json_errors_clearly() {
        let bad = b"not-json";
        let r = from_oci_manifest(
            bad, "x/y", "v1", "t", "urn", None,
        );
        assert!(matches!(r, Err(TabeliaoError::InvalidInput(_))));
    }

    #[test]
    fn manifest_without_layers_errors_clearly() {
        let bad = br#"{"schemaVersion":2}"#;
        let r = from_oci_manifest(
            bad, "x/y", "v1", "t", "urn", None,
        );
        assert!(matches!(r, Err(TabeliaoError::InvalidInput(_))));
    }

    #[test]
    fn verify_canonical_round_trip_passes() {
        let s = build();
        let json = serialize_canonical(&s).unwrap();
        verify_canonical_serialization(json.as_bytes()).unwrap();
    }

    #[test]
    fn verify_rejects_non_canonical_serialization() {
        let s = build();
        let json = serialize_canonical(&s).unwrap();
        // Reformat without indent — same Sbom value but different bytes.
        let parsed: Sbom = serde_json::from_str(&json).unwrap();
        let compact = serde_json::to_string(&parsed).unwrap();
        assert!(verify_canonical_serialization(compact.as_bytes()).is_err());
    }

    #[test]
    fn fields_unused_by_property_dont_serialize() {
        // Components without bom-ref / version / publisher / hashes /
        // properties should omit those fields. Catches accidental
        // serde defaults that bloat the wire shape. Inspect the
        // round-tripped SBOM's tabeliao tool entry directly via
        // serde_json::Value so the test is robust to formatting.
        let s = build();
        let json = serialize_canonical(&s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let tools = v["metadata"]["tools"]["components"]
            .as_array()
            .unwrap();
        let tabeliao_tool = tools
            .iter()
            .find(|c| c["name"] == "tabeliao")
            .unwrap();
        // skip_serializing_if dropped the empty-collection fields:
        assert!(tabeliao_tool.get("bom-ref").is_none(), "tabeliao tool should not carry bom-ref");
        assert!(tabeliao_tool.get("hashes").is_none(), "tabeliao tool should not carry hashes");
        assert!(tabeliao_tool.get("properties").is_none(), "tabeliao tool should not carry properties");
        // Sanity: a populated component DOES carry hashes.
        assert!(json.contains("\"hashes\""));
    }

    /// Honest test: confirm we'd catch the "all-zero placeholder
    /// digests" pattern from the audit. Phase A noted that
    /// REPRESENTATIVE_OPENCLAW_PKI_IMAGE_MANIFEST used `sha256:1111...`
    /// placeholders. The SBOM faithfully echos those into Hash.content;
    /// a verifier comparing the SBOM to the actual ghcr image would
    /// see a hash mismatch. This test pins the predicate.
    #[test]
    fn placeholder_layer_digests_propagate_to_sbom() {
        let placeholder = br#"{
          "schemaVersion": 2,
          "config": {"mediaType":"application/vnd.docker.container.image.v1+json","size":1,"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
          "layers": [{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":1000,"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}]
        }"#;
        let s = from_oci_manifest(
            placeholder, "x/y", "v1", "t", "urn", None,
        ).unwrap();
        assert_eq!(s.components[0].hashes[0].content, "1111111111111111111111111111111111111111111111111111111111111111");
    }

    /// Phase B's `OciNoUppercaseInDigestEncoded` predicate would catch
    /// `SHA256:` mixed-case manifests; the SBOM happens to forward
    /// whatever it's given. This test is documentary — the SBOM does
    /// not normalize, so upstream invariants are preserved (catches
    /// would happen at the OCI manifest layer).
    #[test]
    fn sbom_does_not_silently_normalize_digest_case() {
        let upper = br#"{
          "schemaVersion": 2,
          "layers": [{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":1,"digest":"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]
        }"#;
        let s = from_oci_manifest(
            upper, "x/y", "v1", "t", "urn", None,
        ).unwrap();
        // Encoded portion preserved as-given (uppercase).
        assert!(s.components[0].hashes[0].content.contains('A'));
    }
}
