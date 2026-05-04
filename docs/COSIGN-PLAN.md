# Cosign / Sigstore — current state + remaining keyless upgrade

## Current state (v0.6.0)

✅ **Real Ed25519 signing** — the same cryptographic primitive Sigstore
uses. `Ed25519Signer` produces 64-byte signatures over the state-leaf
root. Cartorio v0.4.1 verifies them via `verify_ed25519_signed_root`.

✅ **cosign-bundle wire format** — `tabeliao::cosign::sign_blob_to_bundle`
produces JSON in the exact shape `cosign sign-blob --bundle=...`
emits. `tabeliao::cosign::verify_blob_bundle` verifies. Stock
`cosign verify-blob --bundle=...` interoperates because:
- `base64Signature`: real Ed25519 signature, base64-encoded.
- `cert`: PEM-encoded SubjectPublicKeyInfo (RFC 8410 — the format
  `cosign verify-blob --key cosign.pub` reads).
- `rekorBundle`: `null` (currently no transparency log entry).

✅ **`CosignSigner = Ed25519Signer`** — the trait and type alias are
public. Production deployments construct it from a key persisted in
their secret manager (Akeyless DFC, Hashicorp Vault, Kubernetes
Secret).

✅ **Verifier-side cryptographic check** — cartorio v0.4.1 dispatches by
`SigningAlgorithm`: Blake3KeyedHmac → 64 hex (shape-only),
Ed25519 → 128 hex + verify against configured public-key allowlist.

## What's needed for full keyless (Fulcio + Rekor)

Three production-infrastructure pieces, none of which is tabeliao or
cartorio code:

### 1. OIDC token issuance

The publisher proves their identity to Fulcio via an OIDC token. The
issuer depends on where the publisher runs:

| Environment | Issuer |
|---|---|
| GitHub Actions CI | GitHub Actions OIDC (built-in) |
| Local human signer | Browser-based interactive flow against an internal Authentik or Google |
| Kubernetes pod signer | K8s ServiceAccount projection → Spire / cert-manager |

This is **deployment configuration**, not code. tabeliao gains a
`--oidc-issuer` flag; the OIDC token gets passed to step (2).

### 2. Fulcio short-lived cert

Exchange the OIDC token at Fulcio for a short-lived (10-minute) X.509
cert bound to the OIDC subject. The tabeliao change:

```rust
// In src/sign.rs — replace Ed25519Signer's static keypair with
// an ephemeral Fulcio-cert-bound keypair.
pub struct SigstoreSigner {
    fulcio_client: sigstore::fulcio::FulcioClient,
    rekor_client: sigstore::rekor::RekorClient,
    oidc_token: String,
}

impl Signer for SigstoreSigner {
    fn sign(&self, root: &Blake3Hash, _: &str, _: DateTime<Utc>) -> Result<SignedRoot> {
        // 1. Generate ephemeral Ed25519 keypair
        // 2. Submit pubkey + OIDC token to Fulcio → cert chain
        // 3. Sign root with ephemeral private key
        // 4. Submit (sig, cert, root) to Rekor → inclusion proof
        // 5. Return SignedRoot { signature, algorithm: Ed25519, signer_id: <fulcio cert subject> }
        //    + populate cosign bundle's `cert` (Fulcio chain) and
        //    `rekorBundle` (inclusion proof) — verifier reads them
        //    via the existing `verify_blob_bundle` shape.
    }
}
```

The cosign bundle wire format **does not change** — the `cert` field
becomes the Fulcio cert chain (PEM-encoded x509) instead of the
publisher's static SPKI. Verifiers (including stock cosign) keep
working unchanged.

### 3. Rekor inclusion proof

Submit the (signature, cert, message) to a Rekor instance for the
public transparency log entry. Returns the entry's body + integrated
timestamp + log index + log ID — all four populate the bundle's
`rekorBundle` field. Verifiers can confirm inclusion by re-fetching
the entry and matching the proof.

### 4. Cartorio admission policy

Cartorio currently dispatches by `SigningAlgorithm` to choose the
verify path. For full keyless, it gains an admission-policy config:

```rust
// In src/state.rs or a new src/policy.rs:
pub struct VerifierPolicy {
    /// Which Fulcio identities (OIDC subjects) may sign for this
    /// org+framework+baseline. e.g. for FedRAMP-High openclaw:
    ///   "repo:pleme-io/openclaw-publisher-pki@refs/heads/main"
    pub allowed_subjects: BTreeSet<String>,
    /// Trusted Fulcio root certs (TUF-distributed; pinned).
    pub fulcio_roots: Vec<X509Cert>,
    /// Required Rekor instance(s).
    pub rekor_urls: Vec<String>,
}
```

The admission handler gets:

```rust
if matches!(input.signed_root.algorithm, SigningAlgorithm::Ed25519) {
    // (a) Parse cert chain from cosign bundle
    // (b) Verify chain against fulcio_roots
    // (c) Verify cert subject is in allowed_subjects
    // (d) Verify Rekor inclusion proof against rekor_urls
    // (e) Verify signature with cert's public key
}
```

This is the layer that says "only signed by GitHub Actions in the
openclaw-publisher-pki repo's main branch counts as a valid
FedRAMP-High admission."

## Why this is layered the way it is

The `pack_hash` is a **constructive proof** — anyone with the pack
source code + the artifact bytes can re-derive it. No signer
required for the proof's mathematical validity.

Cosign answers the orthogonal question of *"who attested this
proof"* — useful for audit trails and policy. Today (v0.6.0) we use
a publisher-managed Ed25519 keypair; vNext we use Fulcio-issued
ephemeral certs bound to OIDC identity. The wire format is identical.

## v0.6.0 deployment usage

For a deployment that's **NOT** ready for full keyless yet:

1. Generate an Ed25519 keypair per publisher (one-time):
   ```rust
   let signer = Ed25519Signer::generate();
   let private_hex = hex::encode(signer.signing_key.to_bytes());
   let public_hex = signer.verifying_key_hex();
   // Store private_hex in Akeyless / Vault.
   // Distribute public_hex to cartorio's verifier_policy.
   ```

2. Configure cartorio's verifier policy with the publisher's public
   key in `verifier.ed25519_publisher_keys[publisher_id]`.

3. Tabeliao publishes with `--signing-key $PRIVATE_HEX`; cartorio
   verifies with the configured public key; auditors can fetch the
   cosign bundle and verify with stock cosign tooling.

4. Migration to keyless is additive: same wire format, swap the
   signer's source of identity (OIDC + Fulcio) at deployment time.
