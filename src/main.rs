use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use tabeliao::{
    AttestationsConfig, PublishPlan, publish,
    sign::{Blake3Signer, Ed25519Signer, Signer},
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(version, about = "tabeliao — publisher-side companion to cartorio + lacre")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, Default)]
#[clap(rename_all = "kebab-case")]
enum SigningAlgorithm {
    /// Real cryptographic Ed25519 (Sigstore/cosign-compatible).
    /// **Production default since v0.7.0.** Cartorio's
    /// `verify_ed25519_signed_root` consumes the signature against the
    /// publisher's public key in the verifier policy.
    #[default]
    Ed25519,
    /// BLAKE3 keyed-HMAC. Cartorio shape-checks only — NOT cryptographic.
    /// Retained for tests, demos, and clusters that haven't deployed an
    /// Ed25519 verifier policy yet. Deprecated for production.
    Blake3,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Compute sha256 digest of a manifest file (offline, no network).
    Digest {
        manifest: PathBuf,
    },
    /// Emit a SLSA Provenance v1 in-toto Statement wrapped in a DSSE
    /// envelope, signed with Ed25519. Output is JSON suitable for
    /// attaching to an OCI image as a referrer (Phase C4) and
    /// reading by stock `cosign verify-attestation --type
    /// slsaprovenance1`.
    SlsaProvenance {
        /// OCI image name + sha256 digest of the artifact being attested.
        #[arg(long)]
        subject_name: String,
        /// 64-hex-char sha256 digest (no `sha256:` prefix).
        #[arg(long)]
        subject_sha256: String,
        /// SLSA buildType URI (e.g.
        /// `https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1`).
        #[arg(long)]
        build_type: String,
        /// Source repository URL (sets resolvedDependencies[0].uri).
        #[arg(long)]
        source_repo: String,
        /// Source git commit (sets resolvedDependencies[0].digest.gitCommit).
        #[arg(long)]
        source_commit: String,
        /// Source ref (e.g. `refs/tags/v0.1.0`).
        #[arg(long)]
        source_ref: String,
        /// Builder identity URI. For SLSA L3 this MUST point at an
        /// isolated hosted builder whose signing key is unreachable
        /// from user-defined steps.
        #[arg(long)]
        builder_id: String,
        /// RFC 3339 build start timestamp.
        #[arg(long)]
        build_started: Option<String>,
        /// RFC 3339 build finish timestamp.
        #[arg(long)]
        build_finished: Option<String>,
        /// Workflow path inside the source repo (sets
        /// externalParameters.workflow.path).
        #[arg(long)]
        workflow_path: Option<String>,
        /// Signing-key sources — same trio as `publish`. Mutually
        /// exclusive; exactly one MUST be set. Always Ed25519.
        #[arg(long, conflicts_with_all = ["signing_key_file", "signing_key"])]
        signing_key_stdin: bool,
        #[arg(long, env = "TABELIAO_SIGNING_KEY_FILE", conflicts_with = "signing_key")]
        signing_key_file: Option<PathBuf>,
        #[arg(long, env = "TABELIAO_SIGNING_KEY")]
        signing_key: Option<String>,
        /// Output path. If unset, write to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Generate a CycloneDX 1.6 SBOM for an OCI image manifest.
    /// Output is canonical JSON (deterministic — same inputs ⇒
    /// byte-identical output) suitable for hashing into
    /// `BuildAttestation.sbom_hash` and attaching as an OCI
    /// referrer per OCI v1.1 (Phase C5).
    Sbom {
        /// Path to the manifest body (raw bytes).
        #[arg(long)]
        manifest: PathBuf,
        /// OCI image path (e.g. `pleme-io/openclaw-publisher-pki`).
        #[arg(long)]
        image: String,
        /// Reference (tag or digest) for the published artifact.
        #[arg(long)]
        reference: String,
        /// RFC 3339 timestamp for `metadata.timestamp`. Defaults to
        /// the current UTC time if unset; pass an explicit value to
        /// reproduce a previous SBOM bit-for-bit.
        #[arg(long)]
        timestamp: Option<String>,
        /// UUID URN for `serialNumber`. Defaults to a value derived
        /// from the manifest digest so re-runs over the same image
        /// produce the same urn (deterministic).
        #[arg(long)]
        serial_number: Option<String>,
        /// Optional publisher name (sets `metadata.component.publisher`).
        #[arg(long)]
        publisher: Option<String>,
        /// Output path. If unset, write to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Submit a `CompliantListing` to cartorio + push manifest to lacre.
    Publish {
        /// Path to the manifest body (raw bytes, hashed as-is).
        #[arg(long)]
        manifest: PathBuf,
        /// Path to the YAML attestations config.
        #[arg(long)]
        config: PathBuf,
        /// Cartorio base URL (e.g. `<http://cartorio:8082>`).
        #[arg(long, env = "TABELIAO_CARTORIO_URL")]
        cartorio: String,
        /// Lacre base URL (e.g. `<http://lacre:8083>`).
        #[arg(long, env = "TABELIAO_LACRE_URL")]
        lacre: String,
        /// OCI image path (e.g. `myorg/myimage`).
        #[arg(long)]
        image: String,
        /// Reference to push under (tag or digest, e.g. `v1.0.0`).
        #[arg(long)]
        reference: String,
        /// Manifest content-type.
        #[arg(
            long,
            default_value = "application/vnd.oci.image.manifest.v1+json"
        )]
        content_type: String,
        /// Signing algorithm. Default: `ed25519` (production).
        /// `blake3` is HMAC, shape-checked only — for tests/demos.
        #[arg(long, env = "TABELIAO_SIGNING_ALGORITHM", value_enum, default_value_t = SigningAlgorithm::Ed25519)]
        algorithm: SigningAlgorithm,
        /// **Most secure (preferred for production)**: read the
        /// 64-hex-char private key from stdin. The key never touches
        /// disk and never enters argv. Pipe-friendly with any secret
        /// materializer:
        ///
        ///   `cofre apply --manifest cofre.yaml && \
        ///    sops --decrypt --extract '["openclaw_publisher_key"]' \
        ///         secrets.sops.json | tabeliao publish --signing-key-stdin ...`
        ///
        ///   `akeyless get-secret-value --name /openclaw/publisher-key \
        ///    | jq -r .value | tabeliao publish --signing-key-stdin ...`
        ///
        /// Mutually exclusive with `--signing-key-file` and
        /// `--signing-key`. Exactly one MUST be set.
        #[arg(long, conflicts_with_all = ["signing_key_file", "signing_key"])]
        signing_key_stdin: bool,
        /// Path to a file containing the 64-hex-char private key.
        /// Better than `--signing-key` (no argv leak); worse than
        /// `--signing-key-stdin` (key briefly hits disk). Acceptable
        /// when the file lives on a tmpfs mount.
        ///
        /// Mutually exclusive with `--signing-key-stdin` and
        /// `--signing-key`.
        #[arg(long, env = "TABELIAO_SIGNING_KEY_FILE", conflicts_with = "signing_key")]
        signing_key_file: Option<PathBuf>,
        /// 64-hex-char signing key as a literal string. **Discouraged
        /// for production** — the key ends up in `argv` and shell
        /// history. Kept for back-compat and CI shims that pass it
        /// via env. Use `--signing-key-stdin` (preferred) or
        /// `--signing-key-file` instead.
        #[arg(long, env = "TABELIAO_SIGNING_KEY")]
        signing_key: Option<String>,
        /// Optional compliance pack to enforce. Format
        /// `pack_id@version` (e.g. `fedramp-high-openclaw-image@3`).
        /// When set, the pack runs against the manifest pre-publish,
        /// any failing test aborts the publish, and the resulting
        /// `pack_hash` is baked into the `ComplianceAttestation`.
        #[arg(long, env = "TABELIAO_COMPLIANCE_PACK")]
        pack: Option<String>,
        /// **Phase C7** — attach a CycloneDX (or SPDX) SBOM document
        /// to the cartorio admission. The file is read, base64-encoded,
        /// and lands in the new `AttestationChain.sbom` pillar (Phase
        /// C5) so verifiers can re-derive `sbom_hash` from public bytes.
        #[arg(long)]
        attach_sbom: Option<PathBuf>,
        /// SBOM format string for the `SbomAttestation.format` field.
        /// Defaults to `cyclonedx-1.6` (matches `tabeliao sbom` output).
        #[arg(long)]
        sbom_format: Option<String>,
        /// **Phase C7** — attach a DSSE-wrapped SLSA Provenance v1
        /// envelope (e.g. produced by `tabeliao slsa-provenance`).
        /// Lands in `AttestationChain.slsa_provenance`.
        #[arg(long)]
        attach_slsa: Option<PathBuf>,
        /// SLSA build level claimed (0-3). Default 0 (unverified).
        /// Operator passes 3 only when builder.id points at an
        /// isolated hosted builder (e.g. SLSA GitHub Generator).
        #[arg(long, default_value_t = 0)]
        slsa_build_level: u8,
    },
}

/// Resolve the signing key from one of three mutually-exclusive
/// sources, in preference order:
///
///   1. `--signing-key-stdin` — read from stdin (cofre/akeyless/sops
///      pipe-friendly; key never touches disk or argv). PREFERRED.
///   2. `--signing-key-file` — read from file. Acceptable on tmpfs.
///   3. `--signing-key` — inline string from CLI/env. Discouraged
///      for production.
///
/// Returns a `Zeroizing<String>` so the buffer is overwritten on
/// drop. The trim handles trailing newlines from `cofre`-style
/// piped output.
fn resolve_signing_key(
    stdin: bool,
    file: Option<&PathBuf>,
    inline: Option<&str>,
) -> std::result::Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    if stdin {
        // 256-byte cap is generous (64 hex + whitespace ≪ 256). Also
        // bounds memory exposure if a caller mistakenly pipes a large
        // file in.
        let mut buf = Zeroizing::new(String::with_capacity(256));
        let mut limited = std::io::stdin().lock().take(256);
        limited
            .read_to_string(&mut buf)
            .map_err(|e| format!("read --signing-key-stdin: {e}"))?;
        let trimmed = Zeroizing::new(buf.trim().to_string());
        // `buf` is dropped + zeroized; `trimmed` carries forward.
        return Ok(trimmed);
    }
    match (file, inline) {
        (Some(path), None) => {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("read signing-key file {}: {e}", path.display()))?;
            // Wrap immediately. The intermediate `String` from
            // `read_to_string` is unzeroizable (std::fs returns a
            // plain String), but it's bounded in lifetime to this
            // function and dropped before signing. Future hardening
            // can swap to `read_to_zeroizing` if it becomes available.
            Ok(Zeroizing::new(content.trim().to_string()))
        }
        (None, Some(key)) => Ok(Zeroizing::new(key.to_string())),
        (None, None) => Err(
            "no signing key supplied — set --signing-key-stdin (preferred), \
             --signing-key-file, or --signing-key (env: TABELIAO_SIGNING_KEY{,_FILE})"
                .into(),
        ),
        (Some(_), Some(_)) => Err(
            "both --signing-key-file and --signing-key set; choose one (clap should have caught this)"
                .into(),
        ),
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        // Logs go to stderr — canonical CLI behavior. Stdout is
        // reserved for the structured PublishOutcome JSON so callers
        // can pipe + parse it without log noise.
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    match args.cmd {
        Cmd::Digest { manifest } => {
            let bytes = std::fs::read(&manifest)?;
            println!("{}", tabeliao::publish::manifest_digest(&bytes));
            Ok(())
        }
        Cmd::SlsaProvenance {
            subject_name,
            subject_sha256,
            build_type,
            source_repo,
            source_commit,
            source_ref,
            builder_id,
            build_started,
            build_finished,
            workflow_path,
            signing_key_stdin,
            signing_key_file,
            signing_key,
            output,
        } => {
            let key_hex = resolve_signing_key(
                signing_key_stdin,
                signing_key_file.as_ref(),
                signing_key.as_deref(),
            )?;
            let signer = Ed25519Signer::from_hex(&key_hex)?;
            let mut workflow = serde_json::Map::new();
            workflow.insert("repository".into(), serde_json::Value::String(source_repo.clone()));
            workflow.insert("ref".into(), serde_json::Value::String(source_ref.clone()));
            if let Some(p) = workflow_path {
                workflow.insert("path".into(), serde_json::Value::String(p));
            }
            let mut params = serde_json::Map::new();
            params.insert("workflow".into(), serde_json::Value::Object(workflow));

            let mut commit_digest = std::collections::BTreeMap::new();
            commit_digest.insert("gitCommit".into(), source_commit.clone());

            let predicate = tabeliao::slsa::SlsaProvenance {
                build_definition: tabeliao::slsa::BuildDefinition {
                    build_type,
                    external_parameters: serde_json::Value::Object(params),
                    internal_parameters: None,
                    resolved_dependencies: vec![tabeliao::slsa::ResourceDescriptor {
                        name: Some("source".into()),
                        digest: commit_digest,
                        uri: Some(format!("git+{source_repo}@{source_ref}")),
                        media_type: None,
                        download_location: None,
                    }],
                },
                run_details: tabeliao::slsa::RunDetails {
                    builder: tabeliao::slsa::Builder {
                        id: builder_id,
                        version: None,
                        builder_dependencies: Vec::new(),
                    },
                    metadata: if build_started.is_some() || build_finished.is_some() {
                        Some(tabeliao::slsa::Metadata {
                            invocation_id: None,
                            started_on: build_started,
                            finished_on: build_finished,
                        })
                    } else {
                        None
                    },
                    byproducts: Vec::new(),
                },
            };
            let statement = tabeliao::slsa::build_statement(&subject_name, &subject_sha256, &predicate)?;
            let envelope = tabeliao::slsa::sign_envelope(&statement, &signer)?;
            let json = serde_json::to_string_pretty(&envelope)?;
            info!(publisher_pubkey = %signer.verifying_key_hex(), "SLSA Provenance signed");
            match output {
                Some(path) => std::fs::write(&path, json.as_bytes())?,
                None => println!("{json}"),
            }
            Ok(())
        }
        Cmd::Sbom {
            manifest,
            image,
            reference,
            timestamp,
            serial_number,
            publisher,
            output,
        } => {
            let manifest_bytes = std::fs::read(&manifest)?;
            // Default timestamp = now (RFC 3339). Operator must pass
            // an explicit timestamp to reproduce a prior SBOM
            // bit-for-bit. Default serial = derived from manifest
            // digest (deterministic across re-runs over same image).
            let ts = timestamp.unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
            let serial = serial_number.unwrap_or_else(|| {
                let digest = tabeliao::publish::manifest_digest(&manifest_bytes);
                let hex_part = digest.strip_prefix("sha256:").unwrap_or(&digest);
                // RFC 4122 UUID URN: synth a v4-shape from the first
                // 32 hex chars of the manifest digest. Not a true v4
                // (no random bits), but stable across re-runs and
                // syntactically valid as a urn:uuid:.
                let h = hex_part;
                format!(
                    "urn:uuid:{}-{}-{}-{}-{}",
                    &h[0..8],
                    &h[8..12],
                    &h[12..16],
                    &h[16..20],
                    &h[20..32]
                )
            });
            let sbom = tabeliao::sbom::from_oci_manifest(
                &manifest_bytes,
                &image,
                &reference,
                &ts,
                &serial,
                publisher.as_deref(),
            )?;
            let json = tabeliao::sbom::serialize_canonical(&sbom)?;
            match output {
                Some(path) => std::fs::write(&path, json.as_bytes())?,
                None => println!("{json}"),
            }
            Ok(())
        }
        Cmd::Publish {
            manifest,
            config,
            cartorio,
            lacre,
            image,
            reference,
            content_type,
            algorithm,
            signing_key_stdin,
            signing_key_file,
            signing_key,
            pack,
            attach_sbom,
            sbom_format,
            attach_slsa,
            slsa_build_level,
        } => {
            let mut cfg = AttestationsConfig::from_yaml_path(&config)?;
            // Phase C7 — attach SBOM + SLSA documents from disk, base64-
            // encoding so they ride inside the cartorio admit JSON.
            // sha256 of the raw bytes lands in
            // SbomAttestation.document_sha256 / SlsaProvenanceAttestation
            // .envelope_sha256 (computed in into_attestation_chain).
            if let Some(sbom_path) = &attach_sbom {
                use base64::Engine as _;
                let bytes = std::fs::read(sbom_path)?;
                cfg.sbom_document_b64 =
                    Some(base64::engine::general_purpose::STANDARD.encode(&bytes));
                cfg.sbom_format = sbom_format.or_else(|| Some("cyclonedx-1.6".into()));
                info!(path = %sbom_path.display(), bytes = bytes.len(), "attached SBOM");
            }
            if let Some(slsa_path) = &attach_slsa {
                use base64::Engine as _;
                let bytes = std::fs::read(slsa_path)?;
                cfg.slsa_envelope_b64 =
                    Some(base64::engine::general_purpose::STANDARD.encode(&bytes));
                cfg.slsa_build_level = Some(slsa_build_level);
                info!(path = %slsa_path.display(), bytes = bytes.len(), level = slsa_build_level, "attached SLSA");
            }
            let manifest_bytes = std::fs::read(&manifest)?;
            let key_hex = resolve_signing_key(
                signing_key_stdin,
                signing_key_file.as_ref(),
                signing_key.as_deref(),
            )?;
            // Construct the signer per the chosen algorithm. The Signer
            // trait is the seam — both impls produce a SignedRoot the
            // cartorio admit endpoint accepts.
            let plan = PublishPlan {
                cartorio_url: cartorio,
                lacre_url: lacre,
                image_path: image,
                reference,
                manifest_bytes,
                manifest_content_type: content_type,
                compliance_pack_name: pack,
            };
            let outcome = match algorithm {
                SigningAlgorithm::Ed25519 => {
                    info!("signing with Ed25519 (cartorio cryptographic verify path)");
                    let signer = Ed25519Signer::from_hex(&key_hex)?;
                    let pub_hex = signer.verifying_key_hex();
                    info!(public_key_hex = %pub_hex, "publisher Ed25519 public key (deploy to cartorio verifier policy)");
                    publish_with(cfg, plan, &signer).await?
                }
                SigningAlgorithm::Blake3 => {
                    warn!("signing with Blake3 keyed-HMAC — cartorio shape-checks only, NOT cryptographic. Use --algorithm ed25519 for production.");
                    let signer = Blake3Signer::from_hex(&key_hex)?;
                    publish_with(cfg, plan, &signer).await?
                }
            };
            println!("{}", serde_json::to_string_pretty(&outcome)?);
            Ok(())
        }
    }
}

async fn publish_with<S: Signer>(
    cfg: AttestationsConfig,
    plan: PublishPlan,
    signer: &S,
) -> tabeliao::Result<tabeliao::PublishOutcome> {
    publish(cfg, plan, signer).await
}
