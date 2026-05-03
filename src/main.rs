use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tabeliao::{
    AttestationsConfig, PublishPlan, publish,
    sign::Blake3Signer,
};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "tabeliao — publisher-side companion to cartorio + lacre")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
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
        /// 64-hex-char signing key. Required for v0.1; later replaced
        /// by Akeyless DFC handle.
        #[arg(long, env = "TABELIAO_SIGNING_KEY")]
        signing_key: String,
        /// Optional compliance pack to enforce. Format
        /// `pack_id@version` (e.g. `fedramp-high-openclaw-image@1`).
        /// When set, the pack runs against the manifest pre-publish,
        /// any failing test aborts the publish, and the resulting
        /// `pack_hash` is baked into the `ComplianceAttestation`.
        #[arg(long, env = "TABELIAO_COMPLIANCE_PACK")]
        pack: Option<String>,
    },
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
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
            signing_key,
            pack,
        } => {
            let cfg = AttestationsConfig::from_yaml_path(&config)?;
            let manifest_bytes = std::fs::read(&manifest)?;
            let signer = Blake3Signer::from_hex(&signing_key)?;
            let plan = PublishPlan {
                cartorio_url: cartorio,
                lacre_url: lacre,
                image_path: image,
                reference,
                manifest_bytes,
                manifest_content_type: content_type,
                compliance_pack_name: pack,
            };
            let outcome = publish(cfg, plan, &signer).await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
            Ok(())
        }
    }
}
