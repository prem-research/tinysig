# Trustbase v1.0.0 integration fixture

Captured on 2026-10-21 from:

- `https://trustbase.prem.io/measurements.json`
- `https://trustbase.prem.io/provenance.sigstore.json`

The bundle binds `measurements.json` SHA-256
`c41fa8acd7139e34c31b821deb79dde544b84152f7696f0ea5e53b0ae5107018`
to `prem-research/trustbase` release workflow tag `v1.0.0`, source revision
`d8525fb042f3ad96f3f7bfb481138b3661f282bf`, and GitHub TSA timestamp
`2026-10-20T23:13:22Z` (`1792538002`). It also signs an archive subject whose
bytes are not included in this fixture.

`github-trusted-root.json` is the GitHub instance object extracted from
`gh attestation trusted-root` (TUF verified) on the capture date. It is historical
test data, not a production default trust store. Certificates and public keys
are public verification material; no private keys or credentials are included.
Unit tests use an explicitly fixed test-only private scalar to re-sign cloned
certificate/token structures; no such keys are used outside test builds.

Independent offline verification succeeded with:

```sh
gh attestation verify sigstore/tests/fixtures/measurements.json \
  --bundle sigstore/tests/fixtures/provenance.sigstore.json \
  --repo prem-research/trustbase \
  --cert-identity https://github.com/prem-research/trustbase/.github/workflows/release.yml@refs/tags/v1.0.0 \
  --source-ref refs/tags/v1.0.0 \
  --source-digest d8525fb042f3ad96f3f7bfb481138b3661f282bf \
  --custom-trusted-root trusted-root.jsonl
```

`trusted-root.jsonl` in that command is the original CLI export; it is not
included. To use the single-object fixture with CLI versions that require JSONL,
compact it to one line first with `jq -c . github-trusted-root.json`.
