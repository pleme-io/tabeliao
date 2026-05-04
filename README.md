# tabeliao

Publisher CLI — the operator-facing companion to cartorio + lacre +
provas. Closes the loop: collects attestations, runs the compliance
pack, signs the state-leaf root, submits the `CompliantListing` to
cartorio, then pushes the manifest through lacre to the backing OCI
registry.

> *Tabelião* (PT-BR): the official at a *cartório* who certifies
> documents. The publisher takes their image to the tabelião, who
> stamps it with attestations and lodges the record at cartorio.

## What `tabeliao publish` does

```
1. read manifest bytes        ──── digest = sha256(bytes)
2. read attestations.yaml     ──── source/build/image/compliance pillars
3. resolve compliance pack    ──── e.g. fedramp-high-openclaw-image@1
4. RUN PACK against bytes     ──── fail-closed if any test Fails
                              ──── pack_hash = result
5. splice into compliance     ──── attestation.compliance.result_hash = pack_hash
6. compose state-leaf root    ──── deterministic, server will recompute and check
7. sign root                  ──── BLAKE3 keyed-HMAC (v0.1; Akeyless DFC later)
8. POST cartorio admit        ──── cartorio verifies signature shape, clock skew,
                                   stores ArtifactState in merkle tree
9. PUT  lacre manifest        ──── lacre asks cartorio by digest, forwards
                                   if Active+org match
```

Result: an artifact in cartorio with a transferable compliance proof,
a manifest in the OCI registry, and a `(digest, profile, result_hash)`
triple anyone can verify.

## CLI surface

```bash
# Compute sha256 digest offline (no network, no admission, no push).
tabeliao digest manifest.json

# Full publish: admit + push, with mandatory pack enforcement.
tabeliao publish \
  --manifest      manifest.json \
  --config        attestations.yaml \
  --cartorio      http://cartorio:8082 \
  --lacre         http://lacre:8083 \
  --image         myorg/openclaw \
  --reference     v1.2.3 \
  --pack          fedramp-high-openclaw-image@1 \
  --signing-key   $TABELIAO_SIGNING_KEY      # 64-hex-char
```

Env vars: `TABELIAO_CARTORIO_URL`, `TABELIAO_LACRE_URL`,
`TABELIAO_SIGNING_KEY`, `TABELIAO_COMPLIANCE_PACK`.

## Pack flag is the load-bearing switch

When `--pack` is provided, tabeliao:
- Resolves the pack by name (today: 3 known packs).
- Runs every test in the pack against the manifest bytes.
- **Fails closed if any test fails** — operator sees the per-test
  reason; nothing is admitted to cartorio, nothing is pushed.
- Bakes the resulting `pack_hash` into the
  `ComplianceAttestation.result_hash`. This is what cartorio stores;
  this is what verifiers re-derive.

Three packs are known today (extend by editing `src/compliance.rs`):

| Pack | Target | Use |
|---|---|---|
| `fedramp-high-openclaw-image@1` | OCI image manifest | Most common: docker images. |
| `fedramp-high-openclaw-helm@1` | Helm-as-OCI manifest | Helm charts pushed via OCI Distribution. |
| `fedramp-high-openclaw-bundle@1` | Composed deployable | The image+chart-together proof; admitted as `kind=Bundle`. |

## attestations.yaml shape

```yaml
kind: oci-image                 # or helm-chart, skill, bundle
name: openclaw
version: 1.2.3
publisher_id: alice@pleme.io
org: pleme-io
attestation:
  source:
    git_commit: abc123
    tree_hash: <hex>
    flake_lock_hash: <hex>
  build:
    closure_hash: <hex>
    sbom_hash: <hex>
    slsa_level: 3
  image:
    cosign_signature_ref: ghcr.io/x:sig
    slsa_provenance_ref: ghcr.io/x:prov
  compliance:                    # overridden by --pack at publish time
    framework: FedRAMP
    baseline: high
    profile: fedramp-high-openclaw-image@1
    result_hash: <will-be-recomputed-by---pack>
    status: compliant
```

When `--pack` is set, the `attestation.compliance` block is replaced
with the pack-derived attestation — the operator declares the pack,
tabeliao computes the proof.

## Compliance proof — see canonical doc

For the broader concept (transferable, mechanically-verifiable
compliance receipts, the bundle proof for openclaw image+chart, the
verifier procedure), read
[`cartorio/docs/COMPLIANCE-PROOF.md`](https://github.com/pleme-io/cartorio/blob/main/docs/COMPLIANCE-PROOF.md).

## Test corpus (30 tests, 0 clippy warnings)

- 12 lib tests: signer determinism, attestation parsing, admit-input
  shape.
- 4 compliance-module tests: pack lookup, enforce_pack pass/fail,
  attestation field derivation.
- 14 e2e tests over real TCP (cartorio + lacre + mock backend):
  - Full publisher loop (admit + push compliant image)
  - Pack enforcement (compliant → push; non-compliant → 0
    admissions, 0 pushes; unknown pack → input error)
  - **`provable_statement_openclaw_is_fedramp_high`** — image proof
  - **`provable_statement_openclaw_bundle_is_fedramp_high`** — bundle
    proof for image+chart together
  - Adversarial: tampering scenarios that must break the proof
  - Failure modes: cartorio down → 503, backend down → 502, org
    mismatch → 403

## Status

Reference impl. v0.3.0. The Blake3 keyed-HMAC signer is a
placeholder; the `Signer` trait is the seam where Akeyless DFC or
local Ed25519 plug in.
