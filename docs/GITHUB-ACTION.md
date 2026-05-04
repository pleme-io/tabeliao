# tabeliao-publish — GitHub Action

`tabeliao` ships its own `action.yml` at the repo root, so any
GitHub workflow can call it as:

```yaml
- uses: pleme-io/tabeliao@v0.3.0
  with:
    manifest:      ./out/manifest.json
    config:        ./.tabeliao/openclaw-publisher-pki.yaml
    cartorio-url:  ${{ vars.CARTORIO_URL }}
    lacre-url:     ${{ vars.LACRE_URL }}
    image-path:    pleme-io/openclaw-publisher-pki
    reference:     v0.1.0
    pack:          fedramp-high-openclaw-image@2
    signing-key:   ${{ secrets.TABELIAO_SIGNING_KEY }}
```

## What it does

1. Installs `tabeliao` (downloads release binary, falls back to
   `cargo install` if the platform binary isn't available).
2. Calls `tabeliao publish` with the supplied inputs, which:
   - Computes `sha256(manifest)` → digest.
   - Resolves the named pack from provas.
   - Runs every test in the pack against the manifest bytes.
   - **Fails the build if any test fails** — operator sees per-test
     reasons in CI logs; nothing is admitted to cartorio, nothing is
     pushed.
   - On success: bakes the deterministic `pack_hash` into the
     cartorio admission, POSTs the admission, then PUTs the manifest
     through lacre.
3. Emits `artifact-id`, `digest`, `composed-root` as outputs for
   downstream steps.

## CI policy: the `--pack` flag is mandatory

Without `pack:`, this action fails fast with a clear error. The
default repo branch protection should require any release workflow
to invoke this action — that's how compliance gating is enforced at
the CI layer (mirroring lacre's runtime gating).

## Example workflow

```yaml
# .github/workflows/release.yml
name: release
on:
  push:
    tags: ['v*']

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: build OCI manifest with nix
        run: |
          nix build .#dockerImage
          # nix produces a manifest at ./result/manifest.json
          cp ./result/manifest.json ./out/manifest.json

      - uses: pleme-io/tabeliao@v0.3.0
        id: publish
        with:
          manifest:      ./out/manifest.json
          config:        ./.tabeliao/${{ github.event.repository.name }}.yaml
          cartorio-url:  ${{ vars.CARTORIO_URL }}
          lacre-url:     ${{ vars.LACRE_URL }}
          image-path:    ${{ github.repository }}
          reference:     ${{ github.ref_name }}
          pack:          fedramp-high-openclaw-image@2
          signing-key:   ${{ secrets.TABELIAO_SIGNING_KEY }}

      - name: report
        run: |
          echo "Published ${{ github.repository }}@${{ github.ref_name }}"
          echo "  digest:        ${{ steps.publish.outputs.digest }}"
          echo "  artifact_id:   ${{ steps.publish.outputs.artifact-id }}"
          echo "  composed_root: ${{ steps.publish.outputs.composed-root }}"
```

## What's NOT in this action (yet)

- **Helm chart publishing.** Symmetrical action `tabeliao-publish-chart`
  would take Chart.yaml + values.yaml + templates dir, run the
  helm-content pack, admit via cartorio. Separate action because the
  inputs differ.
- **Bundle composition.** `tabeliao-publish-bundle` takes member
  artifact IDs (or digests) + bundle YAML, runs bundle pack, admits
  bundle artifact. To compose the openclaw image+chart proof in CI,
  you'd run all three actions in sequence.
- **Cosign signing.** Today this action uses `Blake3Signer`. When
  cosign integration lands (see `tabeliao/docs/COSIGN-PLAN.md`),
  this action gains a `cosign-identity-token` input.

These extensions are mechanical; the proof model already supports
them via the `--pack` flag pointing at different packs.
