# Cosign / Sigstore integration — upgrade plan

## Status

- v0.3.x: `Blake3Signer` produces deterministic keyed-HMAC signatures.
  Cartorio validates *signature shape* (64 hex chars, non-empty
  `signer_id`) but not cryptographic validity. `CosignSigner` is a
  scaffold (`Signer` trait implemented; `sign()` returns an error).

- vNext (planned): Real Sigstore — Fulcio identity, Rekor transparency
  log, per-publisher signing keys.

## Why this is deferred

Full Sigstore integration in Rust requires:

- `sigstore-rs` crate integration — async client, OIDC token flow for
  Fulcio cert issuance, Rekor inclusion proof.
- A working OIDC issuer for the publisher (GitHub Actions, Google,
  internal Authentik) — the publisher's identity becomes a Fulcio cert.
- Verifier-side policy: which Fulcio roots are trusted, which Rekor
  instance, what identity claims are allowed (e.g. only
  `repo:pleme-io/openclaw-publisher-pki@ref:refs/heads/main` may sign
  openclaw-publisher-pki listings).
- Cartorio-side validation: replace the shape-only signature check
  with actual cosign verification.

That's a multi-day chunk of work that touches every layer of the
stack. Phase A scope ships without it; the proof model already works
because `pack_hash` is an independent constructive proof — cosign
adds *who* signed, not *whether the proof is valid*.

## Upgrade procedure (when ready)

1. **Add sigstore-rs deps in tabeliao:**
   ```toml
   sigstore = { version = "0.10", features = ["full-native-tls"] }
   ```

2. **Replace `CosignSigner` body** in `src/sign.rs`:
   - Use `sigstore::fulcio::FulcioClient::request_certificate` with
     OIDC token from env (`SIGSTORE_ID_TOKEN` / GitHub Actions OIDC).
   - Sign the state-leaf root with the ephemeral key bound to the
     Fulcio cert.
   - Submit to Rekor via `sigstore::rekor::RekorClient::create_entry`.
   - Set `SignedRoot.signature` = hex of cosign signature bytes.
   - Set `SignedRoot.signer_id` = Fulcio cert subject (e.g.
     `oidc:repo:pleme-io/openclaw-publisher-pki@refs/heads/main`).
   - Set `SignedRoot.algorithm` = new variant `SigningAlgorithm::CosignFulcio`
     (requires bumping cartorio's enum, breaking wire format → cartorio v0.4).

3. **Cartorio: replace `verify_signed_root_shape` with full verify** in
   `src/merkle.rs`:
   - When `algorithm = CosignFulcio`, call
     `sigstore::cosign::Client::verify` with:
     - The state-leaf root as the message
     - The signature from `SignedRoot.signature`
     - The cert chain (cached in cartorio? or fetched from a known URL?)
     - Verifier policy (Fulcio root + Rekor URL)
   - If verification fails → reject admission with the cosign error.

4. **Cartorio admission policy**: the admission handler gains an
   optional `verifier_policy: VerifierPolicy` config field that
   specifies the Fulcio identity allowlist per `(framework, baseline)`.
   E.g. for FedRAMP-High: only `repo:pleme-io/*@refs/heads/main` may
   sign FedRAMP-High admissions.

5. **provas-verify**: add a `--verify-signature` flag that re-runs the
   cosign verify step. Without the flag, only `pack_hash` is verified
   (current behavior); with it, the full chain (pack + cosign + Rekor
   inclusion) is checked.

## Test plan

- New tabeliao integration test: `cosign_sign_round_trip` that signs +
  verifies + posts to a local sigstore-rs test fixture.
- Cartorio extended_tamper.rs gains: `cosign_signature_for_wrong_root_rejected`,
  `cosign_signature_from_unauthorized_identity_rejected`.
- provas-verify gains: `--verify-signature` integration test.

## Why this matters less than it seems

The `pack_hash` is a constructive proof: anyone with the pack source
+ the artifact bytes can re-derive it without trusting any signer.
Cosign answers the orthogonal question of "*who* attested this
proof" — useful for audit trails and policy (e.g. "only signed by
GitHub Actions in the repo's main branch counts"), but not required
for the proof's mathematical validity.

The current `Blake3Signer` is sufficient for non-production
demonstrations; production-FedRAMP-High deployments will require this
upgrade before going live.
