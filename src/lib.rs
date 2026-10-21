#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod certificate;
mod crypto;
mod error;
mod policy;
pub mod public;
mod timestamp;

use alloc::{format, string::String, vec::Vec};
pub use certificate::{EMBEDDED_GITHUB_TRUST_ROOT, TrustedRoot};
pub use error::Error;
use error::Result;
pub use policy::{Policy, PolicyBuilder, RunnerEnvironment};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Authenticated release information, returned only after all checks succeed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArtifact {
    /// SHA-256 of the verified artifact bytes.
    pub sha256: [u8; 32],
    /// GitHub's authenticated signature timestamp, in Unix seconds.
    pub signed_at_unix_seconds: u64,
    /// Source commit bound by the certificate and signed provenance.
    pub source_revision: String,
    /// Exact source ref selected from the policy allowlist.
    pub source_ref: String,
}

/// Verify exact artifact bytes against a detached CI bundle and workflow policy.
///
/// Hashes the original bytes; do not parse or reserialize `measurements.json`
/// before verification. No file access, HTTP, platform clock, randomness, or TLS
/// is used. See the crate documentation for trust provisioning and examples.
pub fn verify(
    artifact: &[u8],
    bundle_json: &[u8],
    roots: &TrustedRoot,
    policy: &Policy,
) -> Result<VerifiedArtifact> {
    verify_digest(Sha256::digest(artifact).into(), bundle_json, roots, policy)
}

/// Verify a caller-computed SHA-256 digest, for streaming large release archives.
///
/// The caller must hash **all exact artifact bytes** with SHA-256. A digest
/// copied from an unverified manifest does not authenticate downloaded content.
pub fn verify_digest(
    digest: [u8; 32],
    bundle_json: &[u8],
    roots: &TrustedRoot,
    policy: &Policy,
) -> Result<VerifiedArtifact> {
    if bundle_json.len() > 1024 * 1024 {
        return Err(Error::Limit);
    }
    let bundle: Bundle = serde_json::from_slice(bundle_json)?;
    if bundle.media_type != "application/vnd.dev.sigstore.bundle.v0.3+json"
        || bundle.dsse_envelope.payload_type != "application/vnd.in-toto+json"
        || bundle.dsse_envelope.signatures.len() != 1
        || !bundle.verification_material.tlog_entries.is_empty()
        || bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps
            .len()
            != 1
    {
        return Err(Error::Unsupported);
    }
    let envelope = bundle.dsse_envelope;
    let signature = crypto::b64(&envelope.signatures[0].sig)?;
    if !envelope.signatures[0].keyid.is_empty() {
        return Err(Error::Unsupported);
    }
    let cert = certificate::parse(&crypto::b64(
        &bundle.verification_material.certificate.raw_bytes,
    )?)?;
    let time = timestamp::verify(
        &crypto::b64(
            &bundle
                .verification_material
                .timestamp_verification_data
                .rfc3161_timestamps[0]
                .signed_timestamp,
        )?,
        &signature,
        &roots.tsa,
        policy.not_after,
        false,
    )?;
    if !roots
        .fulcio
        .iter()
        .any(|a| a.verify(&cert, time, certificate::CODE_SIGNING).is_ok())
    {
        return Err(Error::Trust);
    }
    if policy.not_before.is_some_and(|start| time < start) {
        return Err(Error::Timestamp);
    }
    let identity = certificate::identity(&cert, policy)?;
    let payload = crypto::b64(&envelope.payload)?;
    let pae = pae(&envelope.payload_type, &payload);
    crypto::verify(
        &cert.tbs_certificate.subject_public_key_info,
        &crypto::ecdsa_sha256(),
        &pae,
        &signature,
    )?;
    let statement: Statement = serde_json::from_slice(&payload)?;
    if statement.statement_type != "https://in-toto.io/Statement/v1"
        || statement.predicate_type != "https://slsa.dev/provenance/v1"
    {
        return Err(Error::Unsupported);
    }
    verify_provenance(&statement.predicate, &identity, policy)?;
    if statement.subject.is_empty() || statement.subject.len() > 64 {
        return Err(Error::Limit);
    }
    let subjects = &statement.subject;
    if subjects
        .iter()
        .enumerate()
        .any(|(i, s)| subjects[..i].iter().any(|other| other.name == s.name))
    {
        return Err(Error::Encoding);
    }
    let expected = crypto::hex(&digest);
    if !subjects
        .iter()
        .any(|s| s.name == policy.artifact_name && s.digest.sha256 == expected)
    {
        return Err(Error::Artifact);
    }
    Ok(VerifiedArtifact {
        sha256: digest,
        signed_at_unix_seconds: time,
        source_revision: identity.source_revision,
        source_ref: identity.git_ref,
    })
}

/// DSSE PAE lengths are byte lengths, and the signature covers the original
/// payload bytes, never a JSON reconstruction.
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    pae.extend_from_slice(payload);
    pae
}

fn verify_provenance(
    predicate: &Provenance,
    identity: &certificate::Identity,
    policy: &Policy,
) -> Result<()> {
    let definition = &predicate.build_definition;
    let source = &definition.external_parameters.workflow;
    let github = &definition.internal_parameters.github;
    if definition.build_type != "https://actions.github.io/buildtypes/workflow/v1"
        || source.repository != policy.repository
        || source.path != policy.workflow_path
        || source.git_ref != identity.git_ref
        || github.event_name != policy.event_name
        || predicate.run_details.builder.id != identity.workflow
        || policy
            .runner_environment
            .is_some_and(|e| github.runner_environment.as_deref() != Some(e.as_str()))
        || policy
            .repository_id
            .as_deref()
            .is_some_and(|id| github.repository_id.as_deref() != Some(id))
        || policy
            .repository_owner_id
            .as_deref()
            .is_some_and(|id| github.repository_owner_id.as_deref() != Some(id))
    {
        return Err(Error::Identity);
    }
    let dependencies = &definition.resolved_dependencies;
    let uri = format!("git+{}@{}", policy.repository, identity.git_ref);
    if dependencies.iter().filter(|v| v.uri == uri).count() != 1
        || !dependencies
            .iter()
            .any(|v| v.uri == uri && v.digest.git_commit == identity.source_revision)
    {
        return Err(Error::Identity);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bundle {
    media_type: String,
    verification_material: Material,
    dsse_envelope: Envelope,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Material {
    certificate: certificate::RawCertificate,
    timestamp_verification_data: Timestamps,
    #[serde(default)]
    tlog_entries: Vec<serde::de::IgnoredAny>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Timestamps {
    rfc3161_timestamps: Vec<Timestamp>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Timestamp {
    signed_timestamp: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    payload: String,
    payload_type: String,
    signatures: Vec<Signature>,
}
#[derive(Deserialize)]
struct Signature {
    sig: String,
    #[serde(default)]
    keyid: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Statement {
    #[serde(rename = "_type")]
    statement_type: String,
    subject: Vec<Subject>,
    predicate_type: String,
    predicate: Provenance,
}
#[derive(Deserialize)]
struct Subject {
    name: String,
    digest: ArtifactDigest,
}
#[derive(Deserialize)]
struct ArtifactDigest {
    sha256: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Provenance {
    build_definition: BuildDefinition,
    run_details: RunDetails,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BuildDefinition {
    build_type: String,
    external_parameters: ExternalParameters,
    internal_parameters: InternalParameters,
    resolved_dependencies: Vec<Dependency>,
}
#[derive(Deserialize)]
struct ExternalParameters {
    workflow: Workflow,
}
#[derive(Deserialize)]
struct Workflow {
    repository: String,
    path: String,
    #[serde(rename = "ref")]
    git_ref: String,
}
#[derive(Deserialize)]
struct InternalParameters {
    github: GitHub,
}
#[derive(Deserialize)]
struct GitHub {
    event_name: String,
    runner_environment: Option<String>,
    repository_id: Option<String>,
    repository_owner_id: Option<String>,
}
#[derive(Deserialize)]
struct Dependency {
    uri: String,
    digest: GitDigest,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitDigest {
    git_commit: String,
}
#[derive(Deserialize)]
struct RunDetails {
    builder: Builder,
}
#[derive(Deserialize)]
struct Builder {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configurable_identity_constraints_also_apply_to_provenance() {
        let bundle: Bundle =
            serde_json::from_slice(include_bytes!("../tests/fixtures/provenance.sigstore.json"))
                .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&crypto::b64(&bundle.dsse_envelope.payload).unwrap()).unwrap();
        let policy = Policy::builder()
            .repository("example/project")
            .workflow_path(".github/workflows/build.yaml")
            .branch("release/1.x")
            .event_name("workflow_dispatch")
            .artifact_name("package.tar.gz")
            .runner_environment(RunnerEnvironment::GitHubHosted)
            .repository_id("123")
            .repository_owner_id("456")
            .not_after(1_792_627_200)
            .build()
            .unwrap();
        let identity = certificate::Identity {
            source_revision: "d8525fb042f3ad96f3f7bfb481138b3661f282bf".into(),
            git_ref: "refs/heads/release/1.x".into(),
            workflow: policy.workflow_identity("refs/heads/release/1.x"),
        };
        let predicate = &mut value["predicate"];
        predicate["buildDefinition"]["externalParameters"]["workflow"] = serde_json::json!({
            "repository": policy.repository(), "path": policy.workflow_path(), "ref": identity.git_ref,
        });
        predicate["buildDefinition"]["internalParameters"]["github"] = serde_json::json!({
            "event_name": "workflow_dispatch", "runner_environment": "github-hosted",
            "repository_id": "123", "repository_owner_id": "456",
        });
        predicate["buildDefinition"]["resolvedDependencies"][0]["uri"] =
            format!("git+{}@{}", policy.repository(), identity.git_ref).into();
        predicate["runDetails"]["builder"]["id"] = identity.workflow.clone().into();
        let parsed: Provenance = serde_json::from_value(predicate.clone()).unwrap();
        verify_provenance(&parsed, &identity, &policy).unwrap();
        for (pointer, wrong) in [
            (
                "/buildDefinition/externalParameters/workflow/repository",
                "https://github.com/wrong/project",
            ),
            (
                "/buildDefinition/externalParameters/workflow/path",
                ".github/workflows/wrong.yml",
            ),
            (
                "/buildDefinition/externalParameters/workflow/ref",
                "refs/heads/wrong",
            ),
            (
                "/buildDefinition/internalParameters/github/event_name",
                "push",
            ),
            (
                "/buildDefinition/internalParameters/github/runner_environment",
                "self-hosted",
            ),
            (
                "/buildDefinition/internalParameters/github/repository_id",
                "1",
            ),
            (
                "/buildDefinition/internalParameters/github/repository_owner_id",
                "1",
            ),
            (
                "/runDetails/builder/id",
                "https://github.com/wrong/workflow",
            ),
            (
                "/buildDefinition/resolvedDependencies/0/digest/gitCommit",
                "0000000000000000000000000000000000000000",
            ),
        ] {
            let mut changed = predicate.clone();
            *changed.pointer_mut(pointer).unwrap() = wrong.into();
            let parsed: Provenance = serde_json::from_value(changed).unwrap();
            assert_eq!(
                verify_provenance(&parsed, &identity, &policy),
                Err(Error::Identity),
                "{pointer}"
            );
        }
    }
}
