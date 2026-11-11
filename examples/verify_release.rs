//! Native file-loading adapter; the library itself has no filesystem dependency.
use std::{
    env,
    error::Error,
    fs,
    time::{SystemTime, UNIX_EPOCH},
};
use tinysig::{Policy, TrustedRoot, verify};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 5 {
        return Err(
            "usage: verify_release GITHUB_ROOT.json|- BUNDLE.json ARTIFACT SUBJECT_NAME RELEASE_TAG"
                .into(),
        );
    }
    let roots = if args[0] == "-" {
        TrustedRoot::embedded()?
    } else {
        TrustedRoot::from_json(&fs::read(&args[0])?)?
    };
    let policy = Policy::builder()
        .artifact_name(&args[3])
        .release_tag(&args[4])
        .now_unix_seconds(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
        .build()?;
    let result = verify(&fs::read(&args[2])?, &fs::read(&args[1])?, &roots, &policy)?;
    println!(
        "Verified {} from {} at {}",
        args[3], result.source_revision, result.signed_at_unix_seconds
    );
    Ok(())
}
