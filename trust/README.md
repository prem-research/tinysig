# Embedded GitHub authority snapshot

`github-trusted-root.json` contains the GitHub instance's Fulcio CA paths and
timestamp authority paths, captured on 2026-10-21 using the TUF-verified output
of `gh attestation trusted-root`. It is the same authenticated snapshot originally
captured for the Trustbase v1.0.0 integration fixture, now embedded in the library
using `include_bytes!`.

SHA-256 of the exact file bytes:

```text
484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7
```

Use `TrustedRoot::embedded()` to parse it, or `EMBEDDED_GITHUB_TRUST_ROOT` to
inspect its bytes. The snapshot includes authority `validFor` windows, pinned
ordered intermediate/root certificates, and pinned TSA signing certificates.
These restrictions are enforced for both embedded and caller-supplied roots.

To refresh on a trusted, connected provisioning machine:

```sh
gh attestation trusted-root > trusted-root.jsonl
jq -sc '.[] | select(any(.certificateAuthorities[]; .uri == "fulcio.githubapp.com"))' \
  trusted-root.jsonl > sigstore/trust/github-trusted-root.json
sha256sum sigstore/trust/github-trusted-root.json
```

Review the authenticated authority changes, update this capture date and
fingerprint, then run the native and WebAssembly verification checks documented
in the crate README. Do not replace this file with metadata supplied by an
untrusted artifact publisher. The library performs no automatic refresh or TUF
verification; a crate update or caller-supplied authenticated metadata is required
after GitHub introduces new authority paths. Keep historical test fixtures intact.
