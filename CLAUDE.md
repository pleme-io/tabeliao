# tabeliao — agent-facing canonical context

> **Read [`README.md`](./README.md) and the org-level
> [`COMPLIANCE-PROOF.md`](https://github.com/pleme-io/cartorio/blob/main/docs/COMPLIANCE-PROOF.md)
> first.** This file covers tabeliao-specific operational rules.

## What tabeliao is

The publisher CLI. Closes the operator loop:

```
manifest bytes + attestations.yaml + --pack <pack_id>
   ↓
sha256(bytes) → digest
   ↓
RUN PACK against bytes (FAIL CLOSED on any test failure)
   ↓
construct AdmitArtifactInput with pack_hash → ComplianceAttestation.result_hash
   ↓
construct ComplianceRun (per-test outcomes) → input.compliance_run
   ↓
sign state-leaf root with Ed25519Signer (production default since
   v0.7.0 / Phase C1). Cartorio cryptographically verifies the
   signature against the publisher's public key in the verifier
   policy. `--algorithm blake3` retained for tests/demos only — emits
   a deprecation warning on stderr.
   ↓
POST cartorio admit
   ↓
PUT lacre push (lacre asks cartorio → forwards if Active+org match)
```

## Architectural invariants — DO NOT BREAK

1. **`--pack` is mandatory for compliant publishes.** Without it,
   the `compliance.result_hash` is whatever the YAML says, which is
   not a proof. CI policies require this flag; the GitHub Action
   refuses without it.

2. **Fail closed.** Pack failure → no admit, no push, exit non-zero.
   Operator sees per-test reasons in stderr; CI logs them. Do NOT
   add a `--continue-on-failure` flag.

3. **`pack_hash` is the operator's deliverable.** When the test pack
   passes, the resulting `pack_hash` is what cartorio will store.
   The publish flow recomputes the same hash that any verifier will
   recompute. If they ever differ, the proof is broken — tested by
   `provable_statement_openclaw_*` e2e tests.

4. **`ComplianceRun.pack_hash` MUST equal
   `ComplianceAttestation.result_hash`.** Cartorio v0.4.0+ admission
   validates this binding. Tabeliao's `build_admit_input_with_run`
   constructs both from the same Runner output, so they match by
   construction.

5. **The cosign-bundle wire format is THE wire format.** When full
   keyless lands, the bundle structure stays — only `cert` changes
   from static SPKI to Fulcio cert chain, and `rekorBundle` becomes
   non-null. Do NOT introduce a tabeliao-specific signature format.

## Signing rules

| Signer | When to use | Wire-up status |
|---|---|---|
| `Ed25519Signer` | **Production default since v0.7.0 / Phase C1.** Real cryptographic signatures verifiable by `cartorio::merkle::verify_ed25519_signed_root` against the publisher's allow-listed pubkey. Sigstore/cosign-compatible. | **Default in `Cmd::Publish`.** Construct via `--algorithm ed25519` (default) + `--signing-key-file <path>` (preferred) or `--signing-key <hex>` (back-compat). Mutually exclusive. |
| `Blake3Signer` | Tests, demos, clusters that haven't deployed an Ed25519 verifier policy. Cartorio shape-checks (64 hex). | Opt-in via `--algorithm blake3`. Emits a deprecation warning on stderr. |
| `CosignSigner` (full Sigstore — Fulcio + Rekor) | When Fulcio + Rekor self-host land (Phase C2/C5). Sigstore Bundle v0.3 protobuf + Fulcio cert chain + Rekor inclusion proof. | Not yet wired. The current `cosign.rs` emits the **legacy** `cosign sign-blob --bundle` JSON shape; Phase C4/C5 migrate it to Sigstore Bundle v0.3 protobuf and add Rekor `tlog_entries`. |

## When adding a new pack to `pack_by_name`

```rust
pub fn pack_by_name(name: &str) -> Result<Pack> {
    match name {
        // existing packs ...
        "fedramp-moderate-foo@1" => Ok(provas::fedramp_moderate_foo_v1()),
        other => Err(...),
    }
}
```

Then add to:
- `src/main.rs` known-pack list (in the `Cmd::Publish` doc-string).
- `action.yml`'s description.
- `tests/e2e.rs` — a known-good positive test for the new pack.
- `tests/real_openclaw_e2e.rs` if the pack applies to openclaw.

## Wire-format change discipline

Tabeliao's public surface:
- `AttestationsConfig` (YAML) — back-compat additive only. Adding
  optional fields is fine. Removing or renaming requires a major bump.
- `PublishOutcome` (CLI stdout JSON) — the action.yml reads
  `artifact_id`, `digest`, `composed_root`. Don't rename these.
- The cosign bundle format (`tabeliao::cosign::CosignBundle`) is
  literally cosign's wire format; do NOT diverge from cosign's spec.

## Testing rules

- **Every new pack** gets:
  - Lib test (positive: known-good target passes every test).
  - E2E test (admits + verifies the proof end-to-end).
- **Every new signer** gets:
  - Round-trip sign+verify test.
  - Wrong-key rejection test.
  - Tampered-root rejection test.
  - Tampered-signature rejection test.
- **Every new admit-input field** gets:
  - Happy-path test (cartorio accepts).
  - Validation test (cartorio rejects on shape violation).

## Companion repos

See README. The dep chain: tabeliao → provas (packs) + cartorio
(admit endpoint). Lacre is downstream — receives the manifest from
tabeliao after admission. The four-repo system is tested end-to-end
in `tests/real_openclaw_e2e.rs`; this is the load-bearing
integration test that must stay green across changes.
