//! Hash an archive incrementally, then authenticate its name and digest.
use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    fs::{self, File},
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};
use trustbase_sigstore::{Policy, TrustedRoot, verify_digest};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 5 {
        return Err(
            "usage: stream_archive GITHUB_ROOT.json|- BUNDLE.json ARCHIVE SUBJECT_NAME RELEASE_TAG"
                .into(),
        );
    }
    let mut file = File::open(&args[2])?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
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
    let result = verify_digest(
        hash.finalize().into(),
        &fs::read(&args[1])?,
        &roots,
        &policy,
    )?;
    println!("Verified {} from {}", args[3], result.source_revision);
    Ok(())
}
