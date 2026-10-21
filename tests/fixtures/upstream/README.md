# Upstream Sigstore conformance fixtures

These files are unmodified copies from Sigstore's conformance suite and
`sigstore-go` test data. They are fixed, public test inputs, not production
trust configuration. The bundle tests use the exact bytes in `a.txt` (SHA-256
`a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf`).

## Provenance

The conformance files were copied from
[`sigstore/sigstore-conformance` at `43321d80f52958efa584c6c975716150db62180b`](https://github.com/sigstore/sigstore-conformance/tree/43321d80f52958efa584c6c975716150db62180b/test/assets/bundle-verify):

| Local file | Upstream path under `test/assets/bundle-verify/` | Expected |
| --- | --- | --- |
| `a.txt` | `a.txt` | Signed artifact |
| `production-dsse-v03.json` | `happy-path-intoto-in-dsse-v3/bundle.sigstore.json` | Valid DSSE / Rekor v1 |
| `production-message-v03.json` | `happy-path-v0.3-new-mediaType/bundle.sigstore.json` | Valid message signature / Rekor v1 |
| `bad-inclusion-proof-v03.json` | `inclusion-proof-corrupted-hash_fail/bundle.sigstore.json` | Reject corrupted Merkle inclusion proof |
| `bad-hashedrekord-entry-v03.json` | `wrong-hashedrekord-entry_fail/bundle.sigstore.json` | Reject entry for a different signature |
| `bad-dsse-envelope-v03.json` | `dsse-mismatch-envelope_fail/bundle.sigstore.json` | Reject log entry for a different envelope |
| `bad-dsse-signature-v03.json` | `dsse-mismatch-sig_fail/bundle.sigstore.json` | Reject log entry for a different DSSE signature |
| `staging-rekor2-dsse-v03.json` | `rekor2-dsse-happy-path/bundle.sigstore.json` | Valid DSSE / Rekor v2 |
| `staging-rekor2-dsse-root.json` | `rekor2-dsse-happy-path/trusted_root.json` | Matching staging root |
| `staging-rekor2-message-v03.json` | `rekor2-happy-path/bundle.sigstore.json` | Valid message signature / Rekor v2 |
| `staging-rekor2-message-root.json` | `rekor2-happy-path/trusted_root.json` | Matching staging root |

`public-good-root.json` is copied from
[`sigstore/sigstore-go` at `0161b209ec10567b1f8cd9d8f23bdcdc2064fe3d`](https://github.com/sigstore/sigstore-go/blob/0161b209ec10567b1f8cd9d8f23bdcdc2064fe3d/pkg/testing/data/trusted-roots/public-good.json),
path `pkg/testing/data/trusted-roots/public-good.json`. Its Rekor log ID matches
both production bundles. It is a historical fixture, not an automatically
updated public-good root. Production callers must obtain and authenticate
their own current trust root.

All four valid bundles have signing certificate identity
`https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main`
and OIDC issuer `https://token.actions.githubusercontent.com`. The production
DSSE attestation names `a.txt` as its in-toto subject. Its provenance describes
`loosebazooka/aa-test` at source revision
`ebff8dfbd609b7b22237c7719ce07f2dc7934f5f`; this differs intentionally
from the signing certificate identity. The Rekor integrated time is
`1734374576`. The staging Rekor v2 fixtures use the custom roots supplied
beside them and include an RFC 3161 timestamp because Rekor v2 entries do not
carry integrated time.

Both upstream repositories are Apache-2.0 licensed: see the
[`sigstore-conformance` license statement](https://github.com/sigstore/sigstore-conformance/blob/43321d80f52958efa584c6c975716150db62180b/README.md#licensing)
and the [`sigstore-go` license](https://github.com/sigstore/sigstore-go/blob/0161b209ec10567b1f8cd9d8f23bdcdc2064fe3d/LICENSE).
