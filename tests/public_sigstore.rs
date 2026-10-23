use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tinysig::{Error, public::PublicVerifier};

const ARTIFACT: &[u8] = include_bytes!("fixtures/upstream/a.txt");
const IDENTITY: &str = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main";
const ISSUER: &str = "https://token.actions.githubusercontent.com";
const NOT_AFTER: u64 = 2_000_000_000;
const PUBLIC_ROOT: &[u8] = include_bytes!("fixtures/upstream/public-good-root.json");
const V1_DSSE: &[u8] = include_bytes!("fixtures/upstream/production-dsse-v03.json");
const V1_MESSAGE: &[u8] = include_bytes!("fixtures/upstream/production-message-v03.json");
const V2_DSSE_ROOT: &[u8] = include_bytes!("fixtures/upstream/staging-rekor2-dsse-root.json");
const V2_DSSE: &[u8] = include_bytes!("fixtures/upstream/staging-rekor2-dsse-v03.json");
const V2_MESSAGE_ROOT: &[u8] = include_bytes!("fixtures/upstream/staging-rekor2-message-root.json");
const V2_MESSAGE: &[u8] = include_bytes!("fixtures/upstream/staging-rekor2-message-v03.json");

const CASES: [(&[u8], &[u8], u64); 4] = [
    (PUBLIC_ROOT, V1_DSSE, 1_734_374_576),
    (PUBLIC_ROOT, V1_MESSAGE, 1_710_869_186),
    (V2_DSSE_ROOT, V2_DSSE, 1_778_700_213),
    (V2_MESSAGE_ROOT, V2_MESSAGE, 1_749_729_740),
];

fn verify(root: &[u8], bundle: &[u8]) -> Result<Vec<u64>, Error> {
    PublicVerifier::from_json(root)?
        .verify(ARTIFACT, bundle, IDENTITY, ISSUER, NOT_AFTER)
        .map(|result| result.signed_at_unix_seconds)
}

fn edit(bytes: &[u8], change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(bytes).unwrap();
    change(&mut value);
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn upstream_current_bundles_verify() {
    for (root, bundle, time) in CASES {
        let verifier = PublicVerifier::from_json(root).unwrap();
        let result = verifier
            .verify(ARTIFACT, bundle, IDENTITY, ISSUER, NOT_AFTER)
            .unwrap();
        assert_eq!(result.signed_at_unix_seconds, [time]);
        assert_eq!(result.sha256, <[u8; 32]>::from(Sha256::digest(ARTIFACT)));
        let dsse = serde_json::from_slice::<Value>(bundle).unwrap()["dsseEnvelope"]["payload"]
            .as_str()
            .map(|payload| STANDARD.decode(payload).unwrap());
        assert_eq!(result.dsse_payload, dsse);
        assert_eq!(
            verifier.verify_digest(result.sha256, bundle, IDENTITY, ISSUER, NOT_AFTER),
            Ok(result)
        );
        // The time bound is inclusive.
        verifier
            .verify(ARTIFACT, bundle, IDENTITY, ISSUER, time)
            .unwrap();
        for (artifact, identity, issuer, not_after, error) in [
            (&b"tampered"[..], IDENTITY, ISSUER, NOT_AFTER, None),
            (
                ARTIFACT,
                "wrong identity",
                ISSUER,
                NOT_AFTER,
                Some(Error::Identity),
            ),
            (
                ARTIFACT,
                IDENTITY,
                "wrong issuer",
                NOT_AFTER,
                Some(Error::Identity),
            ),
            (ARTIFACT, IDENTITY, ISSUER, time - 1, Some(Error::Timestamp)),
            (ARTIFACT, "", ISSUER, NOT_AFTER, Some(Error::Policy)),
            (ARTIFACT, IDENTITY, "", NOT_AFTER, Some(Error::Policy)),
        ] {
            let result = verifier.verify(artifact, bundle, identity, issuer, not_after);
            assert!(result.is_err());
            if let Some(error) = error {
                assert_eq!(result, Err(error));
            }
        }
    }
}

#[test]
fn upstream_adversarial_bundles_fail() {
    for bundle in [
        include_bytes!("fixtures/upstream/bad-inclusion-proof-v03.json").as_slice(),
        include_bytes!("fixtures/upstream/bad-hashedrekord-entry-v03.json").as_slice(),
        include_bytes!("fixtures/upstream/bad-dsse-envelope-v03.json").as_slice(),
        include_bytes!("fixtures/upstream/bad-dsse-signature-v03.json").as_slice(),
    ] {
        assert!(verify(PUBLIC_ROOT, bundle).is_err());
    }
}

#[test]
fn wrong_root_and_oversize_input_fail() {
    assert!(verify(V2_MESSAGE_ROOT, V1_MESSAGE).is_err());
    assert!(verify(PUBLIC_ROOT, V2_MESSAGE).is_err());
    assert_eq!(
        PublicVerifier::from_json(&vec![b' '; 1024 * 1024 + 1]).err(),
        Some(Error::Limit)
    );
    assert_eq!(
        verify(PUBLIC_ROOT, &vec![b' '; 1024 * 1024 + 1]),
        Err(Error::Limit)
    );
    // The GitHub private-instance root has no Rekor or CT logs.
    assert!(PublicVerifier::from_json(tinysig::EMBEDDED_GITHUB_TRUST_ROOT).is_err());
}

#[test]
fn rekor_v2_checkpoint_must_match_declared_log_id() {
    let forged = edit(V2_MESSAGE, |b| {
        b["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"] =
            STANDARD.encode([0u8; 32]).into();
    });
    assert_eq!(verify(V2_MESSAGE_ROOT, &forged), Err(Error::Trust));
    // The staging DSSE root also trusts the Rekor v1 staging key; a v2 entry
    // that names it must still fail.
    let root: Value = serde_json::from_slice(V2_DSSE_ROOT).unwrap();
    let other = root["tlogs"][0]["logId"]["keyId"].clone();
    let forged = edit(V2_DSSE, |b| {
        b["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"] = other;
    });
    assert!(verify(V2_DSSE_ROOT, &forged).is_err());
}

#[test]
fn a_signing_time_must_be_authenticated() {
    // Rekor v1: without the SET, integratedTime is unsigned and is not used.
    let unsigned = edit(V1_MESSAGE, |b| {
        b["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("inclusionPromise");
    });
    assert_eq!(verify(PUBLIC_ROOT, &unsigned), Err(Error::Timestamp));
    let moved = edit(V1_MESSAGE, |b| {
        b["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = "1710869187".into();
    });
    assert!(verify(PUBLIC_ROOT, &moved).is_err());
    // Rekor v2: the RFC 3161 timestamp is the only time source.
    let unsigned = edit(V2_MESSAGE, |b| {
        b["verificationMaterial"]
            .as_object_mut()
            .unwrap()
            .remove("timestampVerificationData");
    });
    assert_eq!(verify(V2_MESSAGE_ROOT, &unsigned), Err(Error::Timestamp));
    // A v2 entry cannot claim a v1 promise.
    let promised = edit(V2_MESSAGE, |b| {
        b["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"] =
            json!({"signedEntryTimestamp": "MEUCIQ=="});
    });
    assert_eq!(verify(V2_MESSAGE_ROOT, &promised), Err(Error::Unsupported));
    // Without a pinned TSA, the token is not trusted.
    let root = edit(V2_MESSAGE_ROOT, |r| r["timestampAuthorities"] = json!([]));
    assert_eq!(verify(&root, V2_MESSAGE), Err(Error::Trust));
}

#[test]
fn checkpoints_require_the_log_signature() {
    for (root, bundle) in [(PUBLIC_ROOT, V1_MESSAGE), (V2_DSSE_ROOT, V2_DSSE)] {
        let value: Value = serde_json::from_slice(bundle).unwrap();
        let note = value["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"]
            ["envelope"]
            .as_str()
            .unwrap()
            .to_owned();
        let (text, signatures) = note.split_once("\n\n").unwrap();
        let mut lines: Vec<&str> = signatures.lines().collect();
        // Witness cosignatures alone do not authenticate the checkpoint.
        let log_line = lines.remove(0);
        let mut variants = vec![format!(
            "{text}\n\n{}",
            lines.iter().map(|l| format!("{l}\n")).collect::<String>()
        )];
        // A different tree size under the same signature fails.
        let mut text_lines: Vec<String> = text.lines().map(String::from).collect();
        text_lines[1] = format!("{}", text_lines[1].parse::<u64>().unwrap() + 1);
        variants.push(format!("{}\n\n{log_line}\n", text_lines.join("\n")));
        for envelope in variants {
            let forged = edit(bundle, |b| {
                b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"]["envelope"] =
                    envelope.into();
            });
            assert!(verify(root, &forged).is_err());
        }
    }
}

#[test]
fn certificates_need_a_valid_sct_and_pinned_chain() {
    // Ending the CT log's validity before the SCT was issued rejects the SCT.
    let root = edit(PUBLIC_ROOT, |r| {
        for log in r["ctlogs"].as_array_mut().unwrap() {
            log["publicKey"]["validFor"]["end"] = "2022-10-31T23:59:59.999Z".into();
        }
    });
    assert_eq!(verify(&root, V1_MESSAGE), Err(Error::Trust));
    // Ending the Fulcio authority window before the signing time.
    let root = edit(PUBLIC_ROOT, |r| {
        for authority in r["certificateAuthorities"].as_array_mut().unwrap() {
            authority["validFor"]["end"] = "2024-03-19T17:26:25Z".into();
        }
    });
    assert_eq!(verify(&root, V1_MESSAGE), Err(Error::Trust));
    // A root without CT logs cannot verify Fulcio certificates at all.
    let root = edit(PUBLIC_ROOT, |r| r["ctlogs"] = json!([]));
    assert_eq!(
        PublicVerifier::from_json(&root).err(),
        Some(Error::Unsupported)
    );
}

#[test]
fn bundle_shapes_and_bindings() {
    // v0.2 bundles carry the leaf as the first element of a chain.
    let v02 = edit(V1_MESSAGE, |b| {
        b["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2".into();
        let material = b["verificationMaterial"].as_object_mut().unwrap();
        let leaf = material.remove("certificate").unwrap();
        material.insert(
            "x509CertificateChain".into(),
            json!({"certificates": [leaf]}),
        );
    });
    assert_eq!(verify(PUBLIC_ROOT, &v02), Ok(vec![1_710_869_186]));
    let mixed = edit(&v02, |b| {
        b["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.3+json".into();
    });
    assert_eq!(verify(PUBLIC_ROOT, &mixed), Err(Error::Unsupported));
    for media_type in [
        "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "application/vnd.dev.sigstore.bundle.v0.4+json",
    ] {
        let other = edit(V1_MESSAGE, |b| b["mediaType"] = media_type.into());
        assert_eq!(verify(PUBLIC_ROOT, &other), Err(Error::Unsupported));
    }
    let unknown = edit(V1_MESSAGE, |b| b["extra"] = true.into());
    assert_eq!(verify(PUBLIC_ROOT, &unknown), Err(Error::Encoding));
    // A claimed message digest must match the artifact.
    let digest = edit(V1_MESSAGE, |b| {
        b["messageSignature"]["messageDigest"]["digest"] = STANDARD.encode([0u8; 32]).into();
    });
    assert_eq!(verify(PUBLIC_ROOT, &digest), Err(Error::Artifact));
    // A DSSE statement must name the artifact digest as a subject.
    let verifier = PublicVerifier::from_json(PUBLIC_ROOT).unwrap();
    assert_eq!(
        verifier.verify_digest([0; 32], V1_DSSE, IDENTITY, ISSUER, NOT_AFTER),
        Err(Error::Artifact)
    );
    // Swapping the transparency entries of two valid bundles fails the binding.
    let message: Value = serde_json::from_slice(V1_MESSAGE).unwrap();
    let swapped = edit(V1_DSSE, |b| {
        b["verificationMaterial"]["tlogEntries"] =
            message["verificationMaterial"]["tlogEntries"].clone();
    });
    assert!(verify(PUBLIC_ROOT, &swapped).is_err());
    let none = edit(V1_MESSAGE, |b| {
        b["verificationMaterial"]["tlogEntries"] = json!([])
    });
    assert_eq!(verify(PUBLIC_ROOT, &none), Err(Error::Unsupported));
    let many = edit(V1_MESSAGE, |b| {
        let entry = b["verificationMaterial"]["tlogEntries"][0].clone();
        b["verificationMaterial"]["tlogEntries"] = Value::Array(vec![entry; 17]);
    });
    assert_eq!(verify(PUBLIC_ROOT, &many), Err(Error::Limit));
}

#[test]
fn a_validly_signed_checkpoint_must_commit_to_the_proof() {
    // Both production bundles are checkpointed by the same Rekor key, so the
    // other bundle's checkpoint is authentic but for a different tree.
    let other: Value = serde_json::from_slice(V1_DSSE).unwrap();
    let checkpoint =
        other["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"].clone();
    let forged = edit(V1_MESSAGE, |b| {
        b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"] = checkpoint;
    });
    assert_eq!(verify(PUBLIC_ROOT, &forged), Err(Error::Trust));
}

#[test]
fn the_declared_rekor_key_must_be_valid_at_the_signing_time() {
    for (root, bundle, end) in [
        (PUBLIC_ROOT, V1_MESSAGE, "2024-03-19T17:26:25Z"),
        (V2_MESSAGE_ROOT, V2_MESSAGE, "2025-06-12T12:02:19Z"),
    ] {
        let root = edit(root, |r| {
            for log in r["tlogs"].as_array_mut().unwrap() {
                log["publicKey"]["validFor"]["end"] = end.into();
            }
        });
        assert_eq!(verify(&root, bundle), Err(Error::Trust));
    }
}

#[test]
fn signatures_are_checked_before_log_bindings() {
    fn flip(signature: &Value) -> Value {
        let mut bytes = STANDARD.decode(signature.as_str().unwrap()).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        STANDARD.encode(bytes).into()
    }
    let message = edit(V1_MESSAGE, |b| {
        b["messageSignature"]["signature"] = flip(&b["messageSignature"]["signature"]);
    });
    assert_eq!(verify(PUBLIC_ROOT, &message), Err(Error::Signature));
    let dsse = edit(V2_DSSE, |b| {
        b["dsseEnvelope"]["signatures"][0]["sig"] =
            flip(&b["dsseEnvelope"]["signatures"][0]["sig"]);
    });
    assert_eq!(verify(V2_DSSE_ROOT, &dsse), Err(Error::Signature));
}

#[test]
fn dsse_envelope_shape_is_enforced_on_the_public_path() {
    let two = edit(V1_DSSE, |b| {
        let sig = b["dsseEnvelope"]["signatures"][0].clone();
        b["dsseEnvelope"]["signatures"]
            .as_array_mut()
            .unwrap()
            .push(sig);
    });
    assert_eq!(verify(PUBLIC_ROOT, &two), Err(Error::Unsupported));
    let none = edit(V1_DSSE, |b| b["dsseEnvelope"]["signatures"] = json!([]));
    assert_eq!(verify(PUBLIC_ROOT, &none), Err(Error::Unsupported));
    let other = edit(V1_DSSE, |b| {
        b["dsseEnvelope"]["payloadType"] = "text/plain".into()
    });
    assert_eq!(verify(PUBLIC_ROOT, &other), Err(Error::Unsupported));
    let both = edit(V1_DSSE, |b| {
        b["messageSignature"] = json!({"signature": b["dsseEnvelope"]["signatures"][0]["sig"]});
    });
    assert_eq!(verify(PUBLIC_ROOT, &both), Err(Error::Unsupported));
}

#[test]
fn evidence_count_limits_are_inclusive() {
    let entries = |n: usize| {
        edit(V1_MESSAGE, |b| {
            let entry = b["verificationMaterial"]["tlogEntries"][0].clone();
            b["verificationMaterial"]["tlogEntries"] = Value::Array(vec![entry; n]);
        })
    };
    assert_eq!(verify(PUBLIC_ROOT, &entries(16)), Ok(vec![1_710_869_186]));
    assert_eq!(verify(PUBLIC_ROOT, &entries(17)), Err(Error::Limit));
    let stamps = |n: usize| {
        edit(V2_MESSAGE, |b| {
            let data = &mut b["verificationMaterial"]["timestampVerificationData"];
            let stamp = data["rfc3161Timestamps"][0].clone();
            data["rfc3161Timestamps"] = Value::Array(vec![stamp; n]);
        })
    };
    assert_eq!(verify(V2_MESSAGE_ROOT, &stamps(4)), Ok(vec![1_749_729_740]));
    assert_eq!(verify(V2_MESSAGE_ROOT, &stamps(5)), Err(Error::Limit));
}

#[test]
fn trust_roots_need_every_log_kind_and_consistent_ct_ids() {
    for key in ["tlogs", "ctlogs", "certificateAuthorities"] {
        let root = edit(PUBLIC_ROOT, |r| r[key] = json!([]));
        assert_eq!(
            PublicVerifier::from_json(&root).err(),
            Some(Error::Unsupported),
            "{key}"
        );
    }
    let logs = |n: usize| {
        edit(PUBLIC_ROOT, |r| {
            let log = r["tlogs"][0].clone();
            r["tlogs"] = Value::Array(vec![log; n]);
        })
    };
    assert_eq!(verify(&logs(16), V1_MESSAGE), Ok(vec![1_710_869_186]));
    assert_eq!(
        PublicVerifier::from_json(&logs(17)).err(),
        Some(Error::Limit)
    );
    // Authority chains carry at most four certificates.
    let chain = |n: usize| {
        edit(PUBLIC_ROOT, |r| {
            let certificates = r["certificateAuthorities"][0]["certChain"]["certificates"]
                .as_array()
                .unwrap()
                .clone();
            r["certificateAuthorities"][0]["certChain"]["certificates"] =
                Value::Array(certificates.iter().cycle().take(n).cloned().collect());
        })
    };
    assert!(PublicVerifier::from_json(&chain(4)).is_ok());
    assert_eq!(
        PublicVerifier::from_json(&chain(5)).err(),
        Some(Error::Limit)
    );
    // A CT log ID is the SHA-256 of its key; anything else is a malformed root.
    let wrong_id = edit(PUBLIC_ROOT, |r| {
        r["ctlogs"][0]["logId"]["keyId"] = STANDARD.encode([7u8; 32]).into();
    });
    assert_eq!(
        PublicVerifier::from_json(&wrong_id).err(),
        Some(Error::Encoding)
    );
    let short_id = edit(PUBLIC_ROOT, |r| {
        r["tlogs"][0]["logId"]["keyId"] = STANDARD.encode([7u8; 31]).into();
    });
    assert_eq!(
        PublicVerifier::from_json(&short_id).err(),
        Some(Error::Encoding)
    );
}

#[test]
fn v02_certificate_chains_carry_one_to_four_certificates() {
    let v02 = |n: usize| {
        edit(V1_MESSAGE, |b| {
            b["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2".into();
            let material = b["verificationMaterial"].as_object_mut().unwrap();
            let leaf = material.remove("certificate").unwrap();
            material.insert(
                "x509CertificateChain".into(),
                json!({"certificates": vec![leaf; n]}),
            );
        })
    };
    assert_eq!(verify(PUBLIC_ROOT, &v02(1)), Ok(vec![1_710_869_186]));
    assert_eq!(verify(PUBLIC_ROOT, &v02(4)), Ok(vec![1_710_869_186]));
    assert_eq!(verify(PUBLIC_ROOT, &v02(0)), Err(Error::Unsupported));
    assert_eq!(verify(PUBLIC_ROOT, &v02(5)), Err(Error::Unsupported));
}

#[test]
fn log_windows_round_fractional_seconds_inward() {
    // The production message entry was integrated at 2024-03-19T17:26:26Z.
    for (start, expected) in [
        ("2024-03-19T17:26:26Z", Ok(vec![1_710_869_186])),
        ("2024-03-19T17:26:26.000Z", Ok(vec![1_710_869_186])),
        ("2024-03-19T17:26:26.001Z", Err(Error::Trust)),
        ("2024-03-19T17:26:25.999Z", Ok(vec![1_710_869_186])),
    ] {
        let root = edit(PUBLIC_ROOT, |r| {
            for log in r["tlogs"].as_array_mut().unwrap() {
                log["publicKey"]["validFor"]["start"] = start.into();
            }
        });
        assert_eq!(verify(&root, V1_MESSAGE), expected, "{start}");
    }
    for (end, expected) in [
        ("2024-03-19T17:26:26Z", Ok(vec![1_710_869_186])),
        ("2024-03-19T17:26:26.999Z", Ok(vec![1_710_869_186])),
        ("2024-03-19T17:26:25.999Z", Err(Error::Trust)),
    ] {
        let root = edit(PUBLIC_ROOT, |r| {
            for log in r["tlogs"].as_array_mut().unwrap() {
                log["publicKey"]["validFor"]["end"] = end.into();
            }
        });
        assert_eq!(verify(&root, V1_MESSAGE), expected, "{end}");
    }
}

#[test]
fn fulcio_authority_windows_round_fractional_starts_up() {
    // Signing time 2024-03-19T17:26:26Z: a window starting in that second is
    // inclusive, a window starting one millisecond later is not.
    for (start, expected) in [
        ("2024-03-19T17:26:26Z", Ok(vec![1_710_869_186])),
        ("2024-03-19T17:26:26.000Z", Ok(vec![1_710_869_186])),
        ("2024-03-19T17:26:26.001Z", Err(Error::Trust)),
    ] {
        // Only the current authority: retired ones end before 2024.
        let root = edit(PUBLIC_ROOT, |r| {
            let authorities = r["certificateAuthorities"].as_array_mut().unwrap();
            authorities.last_mut().unwrap()["validFor"]["start"] = start.into();
        });
        assert_eq!(verify(&root, V1_MESSAGE), expected, "{start}");
    }
}
