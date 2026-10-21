use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trustbase_sigstore::{Error, Policy, PolicyBuilder, TrustedRoot, verify, verify_digest};

const ARTIFACT: &[u8] = include_bytes!("fixtures/measurements.json");
const BUNDLE: &[u8] = include_bytes!("fixtures/provenance.sigstore.json");
const ROOT: &[u8] = include_bytes!("fixtures/github-trusted-root.json");
const REVISION: &str = "d8525fb042f3ad96f3f7bfb481138b3661f282bf";

fn policy_builder() -> PolicyBuilder {
    Policy::builder()
        .release_tag("v1.0.0")
        .artifact_name("measurements.json")
        .now_unix_seconds(1_792_627_200)
        .source_revision(REVISION)
}

fn policy() -> Policy {
    policy_builder().build().unwrap()
}

fn changed(change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value = serde_json::from_slice(BUNDLE).unwrap();
    change(&mut value);
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn real_trustbase_ci_bundle() {
    let roots = TrustedRoot::from_json(ROOT).unwrap();
    let result = verify(ARTIFACT, BUNDLE, &roots, &policy()).unwrap();
    assert_eq!(result.source_revision, REVISION);
    assert_eq!(result.signed_at_unix_seconds, 1_792_538_002);
    assert_eq!(result.sha256, <[u8; 32]>::from(Sha256::digest(ARTIFACT)));
    assert_eq!(
        result,
        verify_digest(result.sha256, BUNDLE, &roots, &policy()).unwrap()
    );
}

#[test]
fn altered_artifact_and_wrong_subject_are_rejected() {
    let roots = TrustedRoot::from_json(ROOT).unwrap();
    assert_eq!(
        verify(b"{}", BUNDLE, &roots, &policy()),
        Err(Error::Artifact)
    );
    let p = policy_builder()
        .artifact_name("different.json")
        .build()
        .unwrap();
    assert_eq!(verify(ARTIFACT, BUNDLE, &roots, &p), Err(Error::Artifact));
}

#[test]
fn wrong_tag_commit_and_future_timestamp_are_rejected() {
    let roots = TrustedRoot::from_json(ROOT).unwrap();
    let p = policy_builder().release_tag("v1.0.1").build().unwrap();
    assert_eq!(verify(ARTIFACT, BUNDLE, &roots, &p), Err(Error::Identity));
    let p = policy_builder()
        .source_revision("0000000000000000000000000000000000000000")
        .build()
        .unwrap();
    assert_eq!(verify(ARTIFACT, BUNDLE, &roots, &p), Err(Error::Identity));
    let p = policy_builder().now_unix_seconds(1).build().unwrap();
    assert_eq!(verify(ARTIFACT, BUNDLE, &roots, &p), Err(Error::Timestamp));
}

#[test]
fn dsse_payload_tampering_is_rejected() {
    let roots = TrustedRoot::from_json(ROOT).unwrap();
    let bundle = changed(|v| {
        let mut payload = STANDARD
            .decode(v["dsseEnvelope"]["payload"].as_str().unwrap())
            .unwrap();
        // Whitespace changes preserve JSON semantics, but must break DSSE.
        payload.push(b' ');
        v["dsseEnvelope"]["payload"] = json!(STANDARD.encode(payload));
    });
    assert_eq!(
        verify(ARTIFACT, &bundle, &roots, &policy()),
        Err(Error::Signature)
    );
}

#[test]
fn signature_and_timestamp_tampering_are_rejected() {
    let roots = TrustedRoot::from_json(ROOT).unwrap();
    for pointer in [
        "/dsseEnvelope/signatures/0/sig",
        "/verificationMaterial/timestampVerificationData/rfc3161Timestamps/0/signedTimestamp",
    ] {
        let bundle = changed(|v| {
            let mut bytes = STANDARD
                .decode(v.pointer(pointer).unwrap().as_str().unwrap())
                .unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            *v.pointer_mut(pointer).unwrap() = json!(STANDARD.encode(bytes));
        });
        assert!(verify(ARTIFACT, &bundle, &roots, &policy()).is_err());
    }
}

#[test]
fn unsupported_profiles_and_ambiguous_bundles_are_rejected() {
    let roots = TrustedRoot::from_json(ROOT).unwrap();
    let changes: [fn(&mut Value); 6] = [
        |v| v["mediaType"] = json!("application/vnd.dev.sigstore.bundle.v0.2+json"),
        |v| v["dsseEnvelope"]["payloadType"] = json!("text/plain"),
        |v| v["dsseEnvelope"]["signatures"] = json!([]),
        |v| v["verificationMaterial"]["tlogEntries"] = json!([{}]),
        |v| v["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"] = json!([]),
        |v| {
            let sig = v["dsseEnvelope"]["signatures"][0].clone();
            v["dsseEnvelope"]["signatures"]
                .as_array_mut()
                .unwrap()
                .push(sig);
        },
    ];
    for change in changes {
        assert_eq!(
            verify(ARTIFACT, &changed(change), &roots, &policy()),
            Err(Error::Unsupported)
        );
    }
    let bundle = changed(|v| v["messageSignature"] = json!({}));
    assert_eq!(
        verify(ARTIFACT, &bundle, &roots, &policy()),
        Err(Error::Encoding)
    );
    let text = String::from_utf8(BUNDLE.to_vec()).unwrap().replacen(
        "\"mediaType\":",
        "\"mediaType\":\"duplicate\",\"mediaType\":",
        1,
    );
    assert_eq!(
        verify(ARTIFACT, text.as_bytes(), &roots, &policy()),
        Err(Error::Encoding)
    );
}

#[test]
fn trust_metadata_authority_windows_are_enforced() {
    for key in ["certificateAuthorities", "timestampAuthorities"] {
        let mut root: Value = serde_json::from_slice(ROOT).unwrap();
        for authority in root[key].as_array_mut().unwrap() {
            authority["validFor"]["end"] = json!("2026-10-01T00:00:00Z");
        }
        let root = TrustedRoot::from_json(&serde_json::to_vec(&root).unwrap()).unwrap();
        assert_eq!(
            verify(ARTIFACT, BUNDLE, &root, &policy()),
            Err(Error::Trust)
        );
    }
}

#[test]
fn authority_end_is_inclusive() {
    let mut root: Value = serde_json::from_slice(ROOT).unwrap();
    for key in ["certificateAuthorities", "timestampAuthorities"] {
        let authority = root[key].as_array_mut().unwrap().last_mut().unwrap();
        authority["validFor"]["start"] = json!("2026-10-20T23:13:22Z");
        authority["validFor"]["end"] = json!("2026-10-20T23:13:22Z");
    }
    let roots = TrustedRoot::from_json(&serde_json::to_vec(&root).unwrap()).unwrap();
    verify(ARTIFACT, BUNDLE, &roots, &policy()).unwrap();
    root["timestampAuthorities"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["validFor"] = json!({
        "start": "2026-10-01T00:00:00Z",
        "end": "2026-10-20T23:13:21Z"
    });
    let roots = TrustedRoot::from_json(&serde_json::to_vec(&root).unwrap()).unwrap();
    assert_eq!(
        verify(ARTIFACT, BUNDLE, &roots, &policy()),
        Err(Error::Trust)
    );
}

#[test]
fn dsse_url_safe_base64_and_unknown_fields_verify() {
    let roots = TrustedRoot::from_json(ROOT).unwrap();
    let bundle = changed(|v| {
        let sig = v["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str()
            .unwrap()
            .replace('+', "-")
            .replace('/', "_");
        assert_ne!(sig, v["dsseEnvelope"]["signatures"][0]["sig"]);
        v["dsseEnvelope"]["signatures"][0]["sig"] = json!(sig.trim_end_matches('='));
        v["dsseEnvelope"]["signatures"][0]["futureField"] = json!("ignored");
        v["dsseEnvelope"]["futureField"] = json!("ignored");
    });
    verify(ARTIFACT, &bundle, &roots, &policy()).unwrap();

    // Ignoring unknown fields must not make consumed fields ambiguous.
    let text = String::from_utf8(bundle).unwrap().replacen(
        "\"payloadType\":",
        "\"payloadType\":\"other\",\"payloadType\":",
        1,
    );
    assert_eq!(
        verify(ARTIFACT, text.as_bytes(), &roots, &policy()),
        Err(Error::Encoding)
    );
}

#[test]
fn malformed_and_oversized_inputs_do_not_verify() {
    let roots = TrustedRoot::from_json(ROOT).unwrap();
    for bytes in [b"".as_slice(), b"null", b"{}", b"[]", b"\xff"] {
        assert!(verify(ARTIFACT, bytes, &roots, &policy()).is_err());
        assert!(TrustedRoot::from_json(bytes).is_err());
    }
    assert_eq!(
        verify(ARTIFACT, &vec![b' '; 1024 * 1024 + 1], &roots, &policy()),
        Err(Error::Limit)
    );
    assert!(matches!(
        TrustedRoot::from_json(&vec![b' '; 256 * 1024 + 1]),
        Err(Error::Limit)
    ));
    let mut root: Value = serde_json::from_slice(ROOT).unwrap();
    root["tlogs"] = json!([{}]);
    assert!(matches!(
        TrustedRoot::from_json(&serde_json::to_vec(&root).unwrap()),
        Err(Error::Unsupported)
    ));
}
