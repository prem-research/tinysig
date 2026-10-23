# tinysig

A small, offline Sigstore bundle verifier for Rust. It authenticates that an
artifact was signed by an expected identity, using only byte slices and trust
metadata you provide. There is no network access, platform clock, randomness,
TLS, or filesystem use.

- `no_std` + `alloc`; builds for `wasm32-unknown-unknown` with zero host imports.
- Nine direct dependencies, all pure-Rust RustCrypto/serde crates.
- Fail-closed: unsupported formats and algorithms are rejected, never skipped,
  and errors return no partially verified data.

```toml
[dependencies]
tinysig = { path = "../tinysig" }
```

## Two verifiers

| | GitHub artifact attestations | Public-good Sigstore |
| --- | --- | --- |
| API | `verify`, `verify_digest` | `public::PublicVerifier` |
| Instance | GitHub's private Sigstore (`fulcio.githubapp.com`) | `fulcio.sigstore.dev`, Rekor, CT |
| Evidence | Fulcio certificate + RFC 3161 timestamp | Fulcio certificate + SCT + Rekor v1/v2 entries (+ RFC 3161) |
| Content | DSSE in-toto statement with SLSA v1 provenance | Message signature or DSSE in-toto statement |
| Policy | Repository, workflow, refs, trigger, runner, commit, subject name | Exact certificate identity and OIDC issuer |
| Trust root | Embedded GitHub snapshot, or your own | Yours (no embedded snapshot) |
| Returns | Signing time, source commit, matched ref | Signing times, SHA-256, signed DSSE payload |

Use the GitHub verifier for `gh attestation`/`actions/attest-build-provenance`
output from private and internal repositories. Use the public verifier for
bundles logged in the public-good instance, such as attestations from public
repositories and `cosign`/`sigstore-*` client output.

Both verifiers take an inclusive upper time bound (`not_after`) from the
caller. Supply it from a trusted clock or release policy, never from the bundle.

## GitHub artifact attestations

```rust,no_run
use tinysig::{Policy, TrustedRoot, verify};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let roots = TrustedRoot::embedded()?;
let policy = Policy::builder()
    .repository("example/project") // Or https://github.com/example/project.
    .workflow_path(".github/workflows/release.yml")
    .release_tag("v1.2.0")
    .artifact_name("package.tar.gz")
    .now_unix_seconds(1_792_627_200) // Example only: supply your trusted current time.
    .build()?;
let result = verify(
    &std::fs::read("package.tar.gz")?,
    &std::fs::read("package.sigstore.json")?,
    &roots,
    &policy,
)?;
println!("Built from {} at {}", result.source_revision, result.source_ref);
# Ok(())
# }
```

`verify` hashes the exact artifact bytes; do not parse or reformat them first.
`verify_digest` takes a caller-computed SHA-256 instead (see
[Streaming large artifacts](#streaming-large-artifacts)).

### Building a policy

`Policy::builder()` requires an artifact subject name, at least one allowed ref,
and an upper time bound. Repository, workflow path, OIDC issuer
(`https://token.actions.githubusercontent.com`), and trigger (`push`) have
defaults. The repository and workflow defaults are Trustbase's (see
[Used in Trustbase](#used-in-trustbase)), so set them for any other project.
`build()` returns `Error::Policy` for missing fields, malformed identities, or
inverted time bounds. The finished policy owns its strings and can be reused
across calls; `policy.to_builder()` changes one constraint and keeps the rest.

Pin an immutable source commit, repository/owner IDs, runner classification,
trigger, and an inclusive signing-time interval when you know them:

```rust,no_run
use tinysig::{Policy, RunnerEnvironment};
# fn example() -> Result<(), tinysig::Error> {
let policy = Policy::builder()
    .repository("example/project")
    .workflow_path(".github/workflows/build.yaml")
    .branch("release/1.x")
    .event_name("workflow_dispatch")
    .artifact_name("package.tar.gz")
    .source_revision("d8525fb042f3ad96f3f7bfb481138b3661f282bf")
    .repository_id("123")
    .repository_owner_id("456")
    .runner_environment(RunnerEnvironment::GitHubHosted)
    .not_before(1_792_500_000)
    .not_after(1_792_627_200)
    .build()?;
# let _ = policy;
# Ok(())
# }
```

Permit an explicit set of refs, for example during a release transition:

```rust,no_run
# use tinysig::Policy;
# fn example() -> Result<(), tinysig::Error> {
let policy = Policy::builder()
    .repository("example/project")
    .git_ref("refs/tags/v1.2.0")
    .allow_git_ref("refs/tags/v1.2.1")
    .artifact_name("package.tar.gz")
    .not_after(1_792_627_200)
    .build()?;
# let _ = policy;
# Ok(())
# }
```

`git_ref`, `release_tag`, and `branch` replace the allowed-ref set;
`allow_git_ref` appends to it. Ref matching is exact, duplicates are removed,
and at most 32 refs may be supplied. Tags need no `v` prefix and may contain
slashes. Refs use a conservative ASCII Git-ref subset: no wildcard, whitespace,
empty/dot-prefixed components, `..`, trailing `.`, or `.lock` suffix. Repository
URLs are normalized only by adding `https://github.com/` to `owner/repo`;
identity matching is case-sensitive.

`oidc_issuer` sets an exact issuer expectation without changing the trusted CAs.
`source_revision` pins a 40-character lowercase commit. Runner, repository ID,
and owner ID constraints are checked in both the certificate and the signed
provenance. `VerifiedArtifact::source_ref` reports which allowed ref matched.
There are no switches that skip signature, digest, identity, or timestamp checks.

The same repository, ref, and workflow must appear in the certificate SAN, build
signer, source configuration, and signed provenance. Reusable workflows from a
different repository or ref are outside the supported profile.

The caller chooses the release and maintains any rollback policy. Verification
authenticates the selected release; it does not discover the latest one, enforce
a monotonic version counter, or establish that the CI workflow was free of
compromise. Provenance is signed by the workflow; its claims are not an
independent audit of that workflow.

### GitHub trust root

`TrustedRoot::embedded()` loads a pinned snapshot of GitHub's Fulcio CA and
timestamp-authority paths, embedded with `include_bytes!`. It was obtained
through GitHub CLI's TUF verification on 2026-10-21, includes historical and
then-current authority paths with their validity windows, and does not
auto-refresh. `EMBEDDED_GITHUB_TRUST_ROOT` exposes the exact bytes;
[`trust/README.md`](trust/README.md) records their source, fingerprint, and
refresh procedure.

After an authority rotation, update the crate or supply authenticated metadata:

```rust,no_run
use tinysig::TrustedRoot;
# fn example() -> Result<(), Box<dyn std::error::Error>> {
let roots = TrustedRoot::from_json(&std::fs::read("github-trusted-root.json")?)?;
# let _ = roots;
# Ok(())
# }
```

On a trusted, connected provisioning machine, GitHub CLI authenticates both
instances' metadata with TUF and prints JSONL. Select the GitHub object; the
parser accepts exactly one JSON object.

```sh
gh attestation trusted-root > trusted-root.jsonl
jq -sc '.[] | select(any(.certificateAuthorities[]; .uri == "fulcio.githubapp.com"))' \
  trusted-root.jsonl > github-trusted-root.json
```

The library does **not** authenticate this JSON: attacker-selected roots grant
the attacker signing authority. Pin it in trusted configuration or a verified
application release, and refresh it through the same channel. Each authority's
`validFor` window and every certificate's validity window are enforced at the
signed time; both endpoints are inclusive. Metadata expiry and rollback checks
belong to the external TUF client. GitHub documents the two-instance model in
[Verifying attestations offline](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline).

### What is checked

1. The RFC 3161 timestamp is signed by a pinned GitHub TSA leaf whose full pinned
   path is valid at `genTime`. CMS content type, message digest, signature digest
   algorithm, signer issuer/serial, ESS `SigningCertificateV2` hash, and any
   signed `tsa` name must agree with that leaf.
2. The timestamp's message imprint is the hash of the **DSSE signature**, and its
   time satisfies the policy's inclusive bounds.
3. The signing leaf chains through a pinned GitHub Fulcio path and is valid at the
   timestamp. Path signatures, names, basic constraints, path lengths, key usage,
   extended key usage, and critical extensions are checked. Intermediates come
   only from the trust root.
4. Certificate SAN, OIDC issuer, build signer/configuration, source repository,
   ref, trigger, and source/build revisions match the policy.
5. The P-256 DSSE signature covers the exact payload via DSSE PAE. The payload is
   an in-toto v1 statement with SLSA v1 provenance whose workflow, ref, trigger,
   builder, and resolved source commit agree with the certificate.
6. Exactly one subject with the policy's name carries the artifact's SHA-256.
   Duplicate subject names are rejected.

| Input | Supported |
| --- | --- |
| Bundle | `application/vnd.dev.sigstore.bundle.v0.3+json` |
| Content | One P-256/SHA-256 DSSE signature, `application/vnd.in-toto+json` |
| Timestamp | One DER RFC 3161 response with status `granted` or `grantedWithMods`, one CMS signer, signed attributes, pinned TSA leaf |
| CMS signature | ECDSA P-256/SHA-256, P-384/SHA-384, or P-384/SHA-256 |
| Timestamp/ESS hash | SHA-256, SHA-384, SHA-512 |
| Certificates | X.509 v3, ECDSA P-256/SHA-256 or P-384/SHA-384; caller-pinned ordered paths |
| Time encoding | Whole-second UTC `genTime`; metadata RFC 3339 `YYYY-MM-DDTHH:MM:SSZ` |
| Timestamp accuracy | Up to one second, optional millisecond/microsecond fields; nominal `genTime` is used |
| Bundle Base64 | Standard or URL-safe alphabet, padded or unpadded |
| Authority metadata | GitHub-instance TrustedRoot v0.1; 2–4 certificates per path, 1–16 paths per purpose |

Unknown critical certificate extensions, duplicate extensions, unsupported name
or policy constraints, embedded CMS certificates/CRLs, other signature
algorithms, multiple signatures/timestamps, message-signature bundles, and
transparency-log entries are rejected. GitHub's private instance has no CT or
Rekor evidence, so this path makes no public transparency claim.

## Public-good Sigstore

```rust,no_run
# fn example() -> Result<(), Box<dyn std::error::Error>> {
use tinysig::public::PublicVerifier;
let verifier = PublicVerifier::from_json(&std::fs::read("public-trusted-root.json")?)?;
let result = verifier.verify(
    &std::fs::read("artifact.txt")?,
    &std::fs::read("artifact.sigstore.json")?,
    "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
    "https://token.actions.githubusercontent.com",
    1_792_627_200, // Example: supply a trusted current-time upper bound.
)?;
println!("Verified SHA-256: {:02x?}", result.sha256);
# Ok(())
# }
```

`PublicVerifier` is built once from a TrustedRoot and reused. `verify_digest`
accepts a caller-computed SHA-256. A successful result means:

1. **Content.** A message signature is a P-256 ECDSA signature over the
   artifact's SHA-256 (a claimed `messageDigest` must match). A DSSE envelope
   has one P-256 signature over the PAE of an in-toto v1/v0.1 statement whose
   subjects include the artifact's SHA-256; `dsse_payload` returns the signed
   statement bytes.
2. **Identity.** The Fulcio leaf has exactly one SAN, a URI or email equal to
   `identity`, and its issuer extension (`1.3.6.1.4.1.57264.1.8`, or legacy
   `.1.1`; both must agree when present) equals `issuer`.
3. **Transparency.** Every Rekor entry (1–16) is checked against the log named
   by its `logId` only. Its canonicalized body must name this exact signature,
   certificate, and artifact/payload digest, and it must have an RFC 9162
   inclusion proof to a checkpoint signed by that log. Witness cosignatures are
   ignored.
4. **Time.** Signing times come only from Rekor v1 signed entry timestamps
   (SETs) and RFC 3161 tokens signed by a pinned TSA path; an unsigned
   `integratedTime` is never used. At least one is required, and all must be at
   or before `not_after`. Rekor v2 entries carry no SET, so they need a timestamp.
5. **Certificates.** At every authenticated time, the leaf chains through one
   pinned Fulcio authority path, and the Fulcio, CT, and Rekor keys used are
   within their validity windows. The leaf carries an embedded SCT signed by a
   pinned CT log (RFC 6962 precertificate reconstruction).

| Input | Supported |
| --- | --- |
| Bundle | v0.3 (`certificate`), v0.2 (`x509CertificateChain`; only its leaf is used) |
| Content | Message signature, or one DSSE signature over `application/vnd.in-toto+json` |
| Leaf key | ECDSA P-256 / SHA-256 |
| Rekor v1 | `hashedrekord` and `dsse` 0.0.1, ECDSA P-256 log keys, SET and checkpoint |
| Rekor v2 | `hashedrekord` 0.0.2 (message or DSSE PAE digest), Ed25519 or ECDSA P-256 log keys |
| CT | v1 SCTs, ECDSA P-256 / SHA-256 log keys |
| Timestamp | Up to four RFC 3161 tokens; embedded CMS certificates are ignored, never trusted |
| Trust root | Sigstore TrustedRoot v0.1; RFC 3339 times with optional fractional seconds |

Rekor v2 `dsse` 0.0.2 entries, public-key (non-Fulcio) bundles, v0.1 bundles,
RSA or Ed25519 leaf keys, and log or CT keys of other algorithms are rejected.
Log keys of unsupported algorithms in the trust root are skipped. Protobuf JSON
64-bit integers must be canonical decimal strings.

The caller must authenticate the TrustedRoot, for example by selecting the
public-good object from `gh attestation trusted-root` or using a Sigstore TUF
client, and must handle its refresh and rollback. The public verifier
authenticates a signer and artifact bytes, not the meaning of a DSSE payload:
a statement may make claims about a different repository or workflow, so parse
and authorize `dsse_payload` before acting on it.

## Streaming large artifacts

Both `verify_digest` functions avoid buffering a large file. Hash **all** of
its bytes; a digest copied from an unverified checksum file verifies only the
claim about that digest.

```rust,no_run
use sha2::{Digest, Sha256};
use std::io::Read;
use tinysig::{Policy, TrustedRoot, verify_digest};
# fn example(mut archive: impl Read, bundle: &[u8], roots: &TrustedRoot, policy: &Policy) -> Result<(), Box<dyn std::error::Error>> {
let mut hash = Sha256::new();
let mut buffer = [0u8; 64 * 1024];
loop {
    let n = archive.read(&mut buffer)?;
    if n == 0 { break; }
    hash.update(&buffer[..n]);
}
let result = verify_digest(hash.finalize().into(), bundle, roots, policy)?;
# let _ = result;
# Ok(())
# }
```

This snippet also needs `sha2` as a direct dependency.

## WebAssembly

The library needs no `wasm-bindgen`, WASI, JavaScript cryptography, filesystem,
networking, or host imports. Link it into your Rust WebAssembly application and
call it with byte slices. `alloc` requires the consumer to provide an allocator;
Rust's normal `std` Wasm application does so. The crate ships no JavaScript ABI.

Build and **execute** the standalone smoke adapter, which verifies a real
attestation fixture, rejects tampered artifact bytes, and asserts the module has
zero host imports:

```sh
rustup target add wasm32-unknown-unknown
cargo check --target wasm32-unknown-unknown
cargo build --example wasm_smoke --target wasm32-unknown-unknown --release
node tests/wasm.mjs
```

## Limits and scope

Inputs are bounded: bundle JSON ≤ 1 MiB, GitHub trust metadata ≤ 256 KiB,
public trust metadata ≤ 1 MiB, certificate DER ≤ 16 KiB, timestamp DER ≤ 32 KiB,
and ≤ 64 statement subjects. Artifact size is not limited when streamed through
`verify_digest`. JSON/DER parsing allocates within these bounds; the consumer
sets its own memory/CPU budget. Duplicate consumed JSON fields are rejected by
typed deserialization. Unknown top-level bundle and verification-material
fields are rejected; unknown DSSE envelope fields and unrelated provenance and
trust-metadata fields are ignored.

Signing, trust-root downloads, TUF updates, certificate discovery,
regex/wildcard identity rules, and transport are outside the library's scope.

The implementation follows the
[Sigstore bundle format](https://docs.sigstore.dev/about/bundle/),
[Fulcio extension definitions](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md),
[DSSE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md),
[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161),
[RFC 5652](https://www.rfc-editor.org/rfc/rfc5652),
[RFC 5035](https://www.rfc-editor.org/rfc/rfc5035),
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962),
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162), and
[C2SP signed notes](https://github.com/C2SP/C2SP/blob/main/signed-note.md),
within the profiles above. A security and conformance review is in
[`docs/security-review.md`](docs/security-review.md).

## Dependencies and validation

Nine direct dependencies, all with default features disabled:

| Dependency | Purpose |
| --- | --- |
| `base64` | Decode bundle certificates, signatures, payloads, timestamps |
| `der` | Strict ASN.1 decoding/encoding of CMS and RFC 3161 |
| `x509-cert` | X.509 structures and extensions; shares `der` |
| `p256`, `p384` | Pure Rust ECDSA signature verification |
| `ed25519-dalek` | Rekor v2 checkpoint signatures |
| `sha2` | Artifact, CMS, Merkle, and timestamp hashing |
| `serde`, `serde_json` | Typed bundle, provenance, and trust metadata parsing |

There are no development-only dependencies. The RustCrypto curve crates share
their arithmetic dependencies. Their upstream `ecdsa` feature also enables
signing internals such as `rfc6979`/`hmac`; this crate exposes no signing API.
`rand_core` appears transitively as traits, with no `getrandom` entropy backend.
There is no `rustls`, OpenSSL, `ring`, HTTP client, async runtime, protobuf
runtime, or general-purpose Sigstore SDK in the dependency graph.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo tree --target wasm32-unknown-unknown -e normal
```

Tests cover a real GitHub attestation fixture, byte-for-byte upstream Sigstore
conformance bundles (production Rekor v1 and staging Rekor v2, with DSSE and
message signatures, plus malformed log/envelope cases), and tampered artifacts,
payloads, signatures, timestamps, checkpoints, log IDs, and trust-root windows.
Synthetically re-signed certificates and timestamps test failure paths, and
`tests/forged_public_pki.rs` mints public-path bundles under a test-only Fulcio
chain, CT log, and Rekor log to break one invariant at a time. Fixtures
use expired short-lived certificates intentionally: authenticated signing-time
validation keeps historical artifacts verifiable. Fixture provenance is recorded
in [`tests/fixtures/README.md`](tests/fixtures/README.md) and
[`tests/fixtures/upstream/README.md`](tests/fixtures/upstream/README.md).

## Used in Trustbase

tinysig verifies the release artifacts of
[`prem-research/trustbase`](https://github.com/prem-research/trustbase). Each
release publishes `measurements.json` and a `provenance.sigstore.json` bundle
produced by GitHub artifact attestations on the private instance. The `Policy`
defaults (repository `prem-research/trustbase`, workflow
`.github/workflows/release.yml`, trigger `push`) match that workflow, so a
Trustbase consumer only names the release and artifact:

```rust,no_run
use tinysig::{Policy, TrustedRoot, verify};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let policy = Policy::builder()
    .release_tag("v1.0.0")
    .artifact_name("measurements.json")
    .now_unix_seconds(1_792_627_200) // Example only: supply your trusted current time.
    .build()?;
let result = verify(
    &std::fs::read("measurements.json")?,
    &std::fs::read("provenance.sigstore.json")?,
    &TrustedRoot::embedded()?,
    &policy,
)?;
println!("Verified source commit: {}", result.source_revision);
# Ok(())
# }
```

Fetch the files with any transport, then run the native adapter. `-` selects the
embedded GitHub authorities; pass a JSON path to use your own:

```sh
curl --fail --location --output measurements.json https://trustbase.prem.io/measurements.json
curl --fail --location --output provenance.sigstore.json https://trustbase.prem.io/provenance.sigstore.json
cargo run --example verify_release -- \
  - provenance.sigstore.json measurements.json measurements.json v1.0.0
```

The Pages URLs track the latest release, so an expected-tag mismatch fails; for
a historical version, use the files from that version's GitHub release. Release
archives such as `trustbase-inputs-v1.0.0.tar.gz` can be verified without
buffering:

```sh
cargo run --example stream_archive -- \
  - provenance.sigstore.json \
  trustbase-inputs-v1.0.0.tar.gz trustbase-inputs-v1.0.0.tar.gz v1.0.0
```

The native examples take the upper time bound from `SystemTime`; a WebAssembly
consumer supplies its own trusted clock. The Trustbase `v1.0.0` release is the
library's main real-world regression fixture, and the `wasm_smoke` example
verifies it inside WebAssembly.
