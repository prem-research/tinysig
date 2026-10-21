//! A standalone WebAssembly test harness using the real CI fixture.
//! This adapter exports one test function; it is not part of the library API.
use trustbase_sigstore::{Error, Policy, TrustedRoot, verify};

/// Return 1 only when the real signature passes and modified artifact bytes fail.
#[unsafe(no_mangle)]
pub extern "C" fn check() -> u32 {
    let roots = match TrustedRoot::embedded() {
        Ok(roots) => roots,
        Err(_) => return 0,
    };
    let policy = match Policy::builder()
        .release_tag("v1.0.0")
        .artifact_name("measurements.json")
        .now_unix_seconds(1_792_627_200)
        .source_revision("d8525fb042f3ad96f3f7bfb481138b3661f282bf")
        .build()
    {
        Ok(policy) => policy,
        Err(_) => return 0,
    };
    let artifact = include_bytes!("../tests/fixtures/measurements.json");
    let bundle = include_bytes!("../tests/fixtures/provenance.sigstore.json");
    u32::from(
        verify(artifact, bundle, &roots, &policy).is_ok()
            && verify(b"tampered", bundle, &roots, &policy) == Err(Error::Artifact),
    )
}
