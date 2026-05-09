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
        } => {
            let cfg = AttestationsConfig::from_yaml_path(&config)?;
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
