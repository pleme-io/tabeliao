use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use tabeliao::{
    AttestationsConfig, PublishPlan, publish,
    sign::{Blake3Signer, Ed25519Signer, Signer},
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

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
        /// **Preferred:** path to a file containing the 64-hex-char
        /// private key (no trailing newline required). Avoids leaking
        /// the key into process listings / shell history.
        ///
        /// Mutually exclusive with `--signing-key`. Exactly one of the
        /// two MUST be set.
        #[arg(long, env = "TABELIAO_SIGNING_KEY_FILE", conflicts_with = "signing_key")]
        signing_key_file: Option<PathBuf>,
        /// 64-hex-char signing key as a literal string. **Discouraged
        /// for production** — the key ends up in `argv` and shell
        /// history. Use `--signing-key-file` instead. Kept for
        /// back-compat and CI shims that pass it via env.
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

/// Resolve the signing key from either `--signing-key-file` or
/// `--signing-key`. Exactly one must be set; returns the trimmed
/// 64-hex string. The file path is preferred — production deployments
/// should use cofre or akeyless to materialize the file to a tmpfs
/// mount that's removed after the publish completes.
fn resolve_signing_key(
    file: Option<&PathBuf>,
    inline: Option<&str>,
) -> std::result::Result<String, Box<dyn std::error::Error>> {
    match (file, inline) {
        (Some(path), None) => {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("read signing-key file {}: {e}", path.display()))?;
            Ok(content.trim().to_string())
        }
        (None, Some(key)) => Ok(key.to_string()),
        (None, None) => Err(
            "no signing key supplied — set --signing-key-file (preferred) \
             or --signing-key (env: TABELIAO_SIGNING_KEY{,_FILE})"
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
        Cmd::Publish {
            manifest,
            config,
            cartorio,
            lacre,
            image,
            reference,
            content_type,
            algorithm,
            signing_key_file,
            signing_key,
            pack,
        } => {
            let cfg = AttestationsConfig::from_yaml_path(&config)?;
            let manifest_bytes = std::fs::read(&manifest)?;
            let key_hex = resolve_signing_key(signing_key_file.as_ref(), signing_key.as_deref())?;
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
