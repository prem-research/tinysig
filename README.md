# trustbase-sigstore

Offline verification of `prem-research/trustbase` release artifacts and their
`provenance.sigstore.json` bundles. A `no_std` + `alloc` Rust library that builds
for `wasm32-unknown-unknown`, with no TLS, networking, OS clock, or randomness.

Add it to a consumer:

```toml
[dependencies]
trustbase-sigstore = { path = "../tinysig/sigstore" }
```

The API has two verification functions: `verify` for artifact bytes, and
`verify_digest` for a SHA-256 digest computed by the caller. Both require an
explicit allowed source ref, artifact subject name, latest acceptable signed time,
and GitHub authority metadata. Use the embedded CA/TSA snapshot or provision your
own authenticated metadata. Every check must succeed before
either function returns `VerifiedArtifact`.

```rust,no_run
use trustbase_sigstore::{Policy, TrustedRoot, verify};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let roots = TrustedRoot::embedded()?;
let policy = Policy::builder()
    .release_tag("v1.0.0")
    .artifact_name("measurements.json")
    .now_unix_seconds(1_792_627_200) // Example only: supply your trusted current time.
    .build()?;
let result = verify(
    &std::fs::read("measurements.json")?,
    &std::fs::read("provenance.sigstore.json")?,
    &roots,
    &policy,
)?;
println!("Verified source commit: {}", result.source_revision);
# Ok(())
# }
```

Only GitHub's private-instance v0.3 DSSE bundles with an RFC 3161 timestamp
are supported. This is the format of Trustbase's published `v1.0.0` release.
Public Sigstore/Rekor bundles, SCT verification, signing, trust-root downloads,
TUF updates, certificate discovery, regex/wildcard rules, and reusable workflows
in a different repository/ref are outside
this crate's scope. Unsupported inputs fail closed.

## Embedded CAs and trust provisioning

`TrustedRoot::embedded()` loads a pinned GitHub CA and timestamp-authority snapshot
using `include_bytes!`. No provisioning file or network call is needed. The
snapshot was obtained through GitHub CLI's TUF verification on 2026-10-21 and
includes historical and current-at-capture authority paths with their validity
windows. It is part of the trusted crate distribution and does not auto-refresh.

`EMBEDDED_GITHUB_TRUST_ROOT` exposes the exact embedded JSON bytes.
`trust/README.md` records its source, fingerprint, and refresh procedure. Authority
rotation may require a crate update or authenticated caller-supplied metadata:

```rust,no_run
use trustbase_sigstore::TrustedRoot;
# fn example() -> Result<(), Box<dyn std::error::Error>> {
let roots = TrustedRoot::from_json(&std::fs::read("github-trusted-root.json")?)?;
# let _ = roots;
# Ok(())
# }
```

On a connected, trusted provisioning machine, GitHub CLI can authenticate both
instances' metadata using TUF. Its output is JSONL: select the GitHub object
before supplying it to this crate. The parser accepts one JSON object, not a
JSONL stream or the public-good-instance object.

```sh
gh attestation trusted-root > trusted-root.jsonl
jq -sc '.[] | select(any(.certificateAuthorities[]; .uri == "fulcio.githubapp.com"))' \
  trusted-root.jsonl > github-trusted-root.json
```

Pin that resulting file in trusted application configuration, a verified
application release, or your provisioning system. The library does **not**
authenticate the JSON itself; giving it attacker-selected roots gives the
attacker authority to sign artifacts. Refresh the file through the same trusted
channel when GitHub rotates authorities. Each authority's metadata `validFor`
window is enforced at the signed time, in addition to every certificate's own
validity window. An authority window's end is exclusive; X.509 `notAfter` is
inclusive. Metadata expiry and rollback checks belong to the external TUF client.

The separate root in `tests/fixtures/` remains a historical test fixture; refreshing
the embedded snapshot does not require changing historical fixtures.

GitHub documents the two-instance model and offline root export in
[Verifying attestations offline](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline).

## Download and verify a release

Transport is the caller's responsibility. For example, obtain the original
artifact and detached bundle, then run the native file adapter from the workspace
root:

```sh
curl --fail --location --output measurements.json https://trustbase.prem.io/measurements.json
curl --fail --location --output provenance.sigstore.json https://trustbase.prem.io/provenance.sigstore.json
cargo run -p trustbase-sigstore --example verify_release -- \
  - provenance.sigstore.json measurements.json measurements.json v1.0.0
```

The `-` argument selects embedded authorities; pass a JSON file path instead to
use your own authenticated metadata. The Pages URLs track the published release; an expected tag mismatch fails.
For a historical version, obtain both files from that version's GitHub release.
Do not reformat JSON before hashing it. For an archive, use its exact in-toto
subject name, such as `trustbase-inputs-v1.0.0.tar.gz`.

The native example supplies Unix seconds using `SystemTime`; a WebAssembly
consumer should supply its own trusted clock or explicit upper time bound. The
library never reads the platform clock. Do not use the bundle's timestamp itself
as the upper time bound.

## Build a policy

`Policy::builder()` defaults to repository `prem-research/trustbase`, workflow
`.github/workflows/release.yml`, OIDC issuer
`https://token.actions.githubusercontent.com`, and event `push`. It requires an
artifact name, at least one allowed ref, and an upper time bound. `build()` returns
`Error::Policy` for missing fields, malformed identities, or inverted time bounds.
The finished policy owns its strings and can be reused by reference across calls.
Use `policy.to_builder()` to change a release or advance its upper time bound
while preserving the other configured constraints.

Pin an immutable source commit, repository/owner IDs, runner classification, and
an inclusive signing-time interval when your application knows those constraints:

```rust,no_run
use trustbase_sigstore::{Policy, RunnerEnvironment};
# fn example() -> Result<(), trustbase_sigstore::Error> {
let policy = Policy::builder()
    .release_tag("v1.0.0")
    .artifact_name("measurements.json")
    .source_revision("d8525fb042f3ad96f3f7bfb481138b3661f282bf")
    .repository_id("1421861904")
    .repository_owner_id("192444375")
    .runner_environment(RunnerEnvironment::SelfHosted)
    .not_before(1_792_500_000)
    .not_after(1_792_627_200)
    .build()?;
# let _ = policy;
# Ok(())
# }
```

Use another GitHub repository/workflow, a branch, or another trigger while keeping
the same signature and certificate verification profile:

```rust,no_run
use trustbase_sigstore::{Policy, RunnerEnvironment};
# fn example() -> Result<(), trustbase_sigstore::Error> {
let policy = Policy::builder()
    .repository("example/project") // Or https://github.com/example/project.
    .workflow_path(".github/workflows/build.yaml")
    .branch("release/1.x")
    .event_name("workflow_dispatch")
    .runner_environment(RunnerEnvironment::GitHubHosted)
    .artifact_name("package.tar.gz")
    .now_unix_seconds(1_792_627_200)
    .build()?;
# let _ = policy;
# Ok(())
# }
```

Permit an explicit set of refs, for example during a release transition:

```rust,no_run
# use trustbase_sigstore::Policy;
# fn example() -> Result<(), trustbase_sigstore::Error> {
let policy = Policy::builder()
    .git_ref("refs/tags/v1.0.0")
    .allow_git_ref("refs/tags/v1.0.1")
    .artifact_name("measurements.json")
    .not_after(1_792_627_200)
    .build()?;
# let _ = policy;
# Ok(())
# }
```

`git_ref`, `release_tag`, and `branch` replace the allowed-ref set;
`allow_git_ref` appends to it. Ref matching is exact, duplicate refs are removed,
and at most 32 refs may be supplied. Tags need no `v` prefix and may contain
slashes. Refs use a conservative ASCII Git-ref subset: no wildcard, whitespace,
empty/dot-prefixed components, `..`, trailing `.`, or `.lock` suffix. Repository
URLs are normalized only by adding `https://github.com/` to `owner/repo`; identity
matching remains case-sensitive.

`oidc_issuer` sets an exact issuer expectation without changing the trusted CAs.
`source_revision` pins a 40-character lowercase commit. Runner, repository ID,
and owner ID constraints are checked in both certificate and signed provenance.
`VerifiedArtifact::source_ref` reports which allowed ref authenticated the artifact.
There are no switches that skip signature, digest, identity, or timestamp checks.

The same repository/ref/workflow must appear in the certificate SAN, build signer,
source configuration, and signed provenance. Cross-repository reusable workflow
identities remain outside the supported profile. Configuring a different identity
does not add public Sigstore/Rekor bundle support.

The caller chooses the release version and maintains any rollback policy.
Verification authenticates the selected release; it does not discover the latest
release, enforce a monotonic version counter, validate the catalog's contents, or
establish that the CI workflow was free of compromise. The provenance is signed
by the workflow; its claims are not an independent audit of that workflow.

## Stream an archive

`verify_digest` avoids buffering a large archive. This example uses the existing
SHA-256 dependency with a fixed-size read buffer:

```rust,no_run
use sha2::{Digest, Sha256};
use std::io::Read;
use trustbase_sigstore::{Policy, TrustedRoot, verify_digest};
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

Consumers using this snippet must also declare `sha2` as a direct dependency.
A runnable adapter is included:

```sh
cargo run -p trustbase-sigstore --example stream_archive -- \
  - provenance.sigstore.json \
  trustbase-inputs-v1.0.0.tar.gz trustbase-inputs-v1.0.0.tar.gz v1.0.0
```

Hash the complete downloaded artifact. Passing a digest copied from an unverified
checksum file verifies only the claim about that digest.

## WebAssembly

The library is ordinary Rust and needs no `wasm-bindgen`, WASI, JavaScript
cryptography, filesystem, networking, or host imports. Link it into your Rust
WebAssembly application and call `verify` with byte slices. `alloc` requires the
consumer to provide an allocator; Rust's normal `std` Wasm application does so.
The crate provides no JavaScript ABI or bindings dependency.

Build and **execute** the supplied standalone smoke adapter, which verifies the
real CI fixture and rejects tampered artifact bytes:

```sh
rustup target add wasm32-unknown-unknown
cargo check -p trustbase-sigstore --target wasm32-unknown-unknown
cargo build -p trustbase-sigstore --example wasm_smoke --target wasm32-unknown-unknown --release
node sigstore/tests/wasm.mjs
```

The Node script also asserts that the resulting module has zero host imports.
The `wasm_smoke` example uses the embedded authorities and builder, embeds test
artifact/bundle fixtures, and exports a test function; adapt
the normal byte-slice API to your own application's data and binding layer.

## Checks and supported profile

Verification checks all of these bindings:

1. The RFC 3161 timestamp is signed by a pinned GitHub TSA leaf, whose full pinned
   path is valid at `genTime`. CMS content type, message digest, signature digest
   algorithm, signer issuer/serial, and ESS `SigningCertificateV2` hash must agree.
2. The timestamp's message imprint is the SHA-2 hash of the **DSSE signature**.
   Its authenticated time must satisfy the caller's inclusive upper/lower bounds.
3. The signing leaf chains through a pinned GitHub Fulcio path and is valid at
   the authenticated timestamp. Path signatures, issuer names, basic constraints,
   CA path lengths, key usage, extended key usage, and critical extensions are
   checked. Intermediates are taken exclusively from the embedded snapshot or
   authenticated caller configuration.
4. Certificate SAN, OIDC issuer, build signer/configuration, source repository,
   source ref, configured trigger, and source/build revisions bind the artifact
   to the configured repository/workflow/ref (Trustbase defaults are shown above).
5. The P-256 DSSE signature covers the exact payload bytes using DSSE PAE. The
   payload is an in-toto v1 statement with SLSA v1 provenance; its workflow,
   source ref, trigger, builder, and resolved source commit must agree with the
   certificate. Optional additional provenance fields are not interpreted.
6. Exactly one matching subject name carries the SHA-256 of the provided artifact
   bytes (or caller-computed digest). Duplicate subject names are rejected.

This is a deliberately narrow profile, not a general-purpose PKIX or Sigstore
implementation:

| Input | Supported |
| --- | --- |
| Bundle | `application/vnd.dev.sigstore.bundle.v0.3+json` |
| Content | One P-256/SHA-256 DSSE signature, `application/vnd.in-toto+json` |
| Timestamp | One successful DER RFC 3161 response, one CMS signer, signed attributes, pinned TSA leaf |
| CMS signature | P-256/SHA-256 or P-384/SHA-384 ECDSA |
| Timestamp/ESS hash | SHA-256, SHA-384, SHA-512 |
| Certificates | X.509 v3, ECDSA P-256/SHA-256 or P-384/SHA-384; embedded or caller-pinned ordered paths |
| Time encoding | Whole-second UTC `genTime`; metadata RFC 3339 `YYYY-MM-DDTHH:MM:SSZ` |
| Timestamp accuracy | Up to one second, optional millisecond/microsecond fields; nominal `genTime` is used |
| Artifact digest | SHA-256 |
| Authority metadata | GitHub-instance TrustedRoot v0.1; 2–4 certificates per path, 1–16 paths per purpose |

Unknown critical certificate extensions, duplicate extensions, unsupported name
or policy constraints, embedded CMS certificates/CRLs, other signature algorithms,
multiple signatures/timestamps, message-signature bundles, and transparency log
entries are rejected. GitHub's private instance has no CT/Rekor evidence, so this
crate makes no public transparency claim. A future Trustbase switch to public
Sigstore requires implementing that instance's verification before accepting it.

Inputs are bounded: bundle JSON ≤ 1 MiB, trust metadata ≤ 256 KiB, certificate
DER ≤ 16 KiB, timestamp DER ≤ 32 KiB, and ≤ 64 statement subjects. Artifact size
is not limited; stream large artifacts through `verify_digest`. JSON/DER parsing
allocates within these input bounds; the consumer sets its own memory/CPU budget.
Duplicate consumed JSON fields are rejected by typed deserialization. Unknown
bundle fields are rejected; unrelated provenance and trust-metadata fields are
ignored. Errors return no partially authenticated result.

The implementation follows the
[Sigstore bundle format](https://docs.sigstore.dev/about/bundle/),
[Fulcio extension definitions](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md),
[DSSE PAE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md),
[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161),
[RFC 5652](https://www.rfc-editor.org/rfc/rfc5652), and
[RFC 5035](https://www.rfc-editor.org/rfc/rfc5035), within the profile above.

## Dependencies and validation

Eight direct dependencies, all with default features disabled:

| Dependency | Purpose |
| --- | --- |
| `base64` | Decode bundle certificate, signature, payload, timestamp |
| `der` | Strict ASN.1 decoding/encoding of CMS and RFC 3161 |
| `x509-cert` | X.509 structures and extensions; shares `der` |
| `p256`, `p384` | Pure Rust ECDSA signature verification |
| `sha2` | Artifact, CMS, and timestamp hashing |
| `serde`, `serde_json` | Typed bundle, provenance, and trust metadata parsing |

There are no development-only dependencies. The RustCrypto curve crates share
their arithmetic dependencies. Their upstream `ecdsa` feature also enables
signing internals such as `rfc6979`/`hmac`; this crate exposes no signing API.
`rand_core` appears transitively as traits, with no `getrandom` entropy backend.
There is no `rustls`, OpenSSL, `ring`, HTTP client, async runtime, protobuf runtime,
or general-purpose Sigstore SDK in the dependency graph.

From the workspace root:

```sh
cargo test -p trustbase-sigstore
cargo clippy -p trustbase-sigstore --all-targets -- -D warnings
cargo fmt --all -- --check
cargo tree -p trustbase-sigstore --target wasm32-unknown-unknown -e normal
```

Tests include a real Trustbase `v1.0.0` fixture, tampered artifact/payload/signature/
timestamp cases, policy builder validation, configurable identity and time checks,
exact ref/commit/subject checks, embedded/external roots, trust-window checks, and
synthetically re-signed certificate/timestamp failure cases. Fixture provenance
is recorded in `tests/fixtures/README.md`. The fixture uses expired short-lived
certificates intentionally: authenticated signing-time validation allows
historical releases to remain verifiable.
