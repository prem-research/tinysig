//! Public-path bundles forged under a test-only Fulcio chain, CT log, and
//! Rekor v1 log: mint a valid bundle, then break one invariant at a time.
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use core::str::FromStr;
use der::{
    Decode, Encode,
    asn1::{
        Any, BitString, GeneralizedTime, Ia5String, ObjectIdentifier, OctetString, Utf8StringRef,
    },
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tinysig::{Error, public::PublicVerifier};
use x509_cert::{
    Certificate, TbsCertificate, Version,
    ext::{
        AsExtension, Extension,
        pkix::{
            BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
            name::GeneralName,
        },
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::{Time, Validity},
};

const T0: u64 = 1_700_000_000;
const LEAF_LIFE: u64 = 600;
const NOT_AFTER: u64 = T0 + 10_000;
const ARTIFACT: &[u8] = b"forged pki artifact";
const IDENTITY: &str =
    "https://github.com/victim/project/.github/workflows/release.yml@refs/tags/v1.0.0";
const ISSUER: &str = "https://token.actions.githubusercontent.com";
const EARLY: &str = "2000-01-01T00:00:00Z";
const ROOT_NAME: &str = "CN=Test Root,O=forged";
const INTER_NAME: &str = "CN=Test Intermediate,O=forged";

fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn spki(k: &SigningKey) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: oid("1.2.840.10045.2.1"),
            parameters: Some(Any::from_der(&oid("1.2.840.10045.3.1.7").to_der().unwrap()).unwrap()),
        },
        subject_public_key: BitString::from_bytes(
            k.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
    }
}
fn ecdsa_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: oid("1.2.840.10045.4.3.2"),
        parameters: None,
    }
}
fn at(secs: u64) -> Time {
    Time::GeneralTime(GeneralizedTime::from_unix_duration(Duration::from_secs(secs)).unwrap())
}
fn utf8_extension(id: &str, value: &str) -> Extension {
    Extension {
        extn_id: oid(id),
        critical: false,
        extn_value: OctetString::new(Utf8StringRef::new(value).unwrap().to_der().unwrap()).unwrap(),
    }
}
fn sign(tbs: TbsCertificate, signer: &SigningKey) -> Certificate {
    let signature: Signature = signer.sign(&tbs.to_der().unwrap());
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ecdsa_sha256(),
        signature: BitString::from_bytes(signature.to_der().as_bytes()).unwrap(),
    }
}
fn tbs(
    serial: u8,
    issuer: &str,
    subject: Option<&str>,
    not_before: u64,
    not_after: u64,
    k: &SigningKey,
    extensions: Vec<Extension>,
) -> TbsCertificate {
    TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).unwrap(),
        signature: ecdsa_sha256(),
        issuer: Name::from_str(issuer).unwrap(),
        validity: Validity {
            not_before: at(not_before),
            not_after: at(not_after),
        },
        subject: subject.map_or_else(Name::default, |s| Name::from_str(s).unwrap()),
        subject_public_key_info: spki(k),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    }
}
fn ca_extensions(subject: &Name, path_len: u8, eku: bool) -> Vec<Extension> {
    let mut extensions = vec![
        BasicConstraints {
            ca: true,
            path_len_constraint: Some(path_len),
        }
        .to_extension(subject, &[])
        .unwrap(),
        KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
            .to_extension(subject, &[])
            .unwrap(),
    ];
    if eku {
        extensions.push(
            ExtendedKeyUsage(vec![oid("1.3.6.1.5.5.7.3.3")])
                .to_extension(subject, &[])
                .unwrap(),
        );
    }
    extensions
}
fn uri(s: &str) -> GeneralName {
    GeneralName::UniformResourceIdentifier(Ia5String::new(s).unwrap())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Pki {
    root: Certificate,
    intermediate: Certificate,
    intermediate_key: SigningKey,
    ct_key: SigningKey,
    rekor_key: SigningKey,
}

/// Leaf parameters, one per invariant under test.
struct Leaf<'a> {
    key: &'a SigningKey,
    not_before: u64,
    not_after: u64,
    sans: Vec<GeneralName>,
    extra: Vec<Extension>,
    sct_ms: u64,
    sct_signer: &'a SigningKey,
    sct_tbs: Option<Vec<u8>>,
}

impl Pki {
    fn new() -> Self {
        let root_key = key(1);
        let intermediate_key = key(2);
        let root_name = Name::from_str(ROOT_NAME).unwrap();
        let intermediate_name = Name::from_str(INTER_NAME).unwrap();
        let root = sign(
            tbs(
                1,
                ROOT_NAME,
                Some(ROOT_NAME),
                T0 - 10_000_000,
                T0 + 100_000_000,
                &root_key,
                ca_extensions(&root_name, 1, false),
            ),
            &root_key,
        );
        let intermediate = sign(
            tbs(
                2,
                ROOT_NAME,
                Some(INTER_NAME),
                T0 - 5_000_000,
                T0 + 50_000_000,
                &intermediate_key,
                ca_extensions(&intermediate_name, 0, true),
            ),
            &root_key,
        );
        Self {
            root,
            intermediate,
            intermediate_key,
            ct_key: key(3),
            rekor_key: key(4),
        }
    }

    fn log_id(k: &SigningKey) -> Vec<u8> {
        Sha256::digest(spki(k).to_der().unwrap()).to_vec()
    }

    fn standard_leaf<'a>(&'a self, k: &'a SigningKey) -> Leaf<'a> {
        Leaf {
            key: k,
            not_before: T0,
            not_after: T0 + LEAF_LIFE,
            sans: vec![uri(IDENTITY)],
            extra: vec![utf8_extension("1.3.6.1.4.1.57264.1.8", ISSUER)],
            sct_ms: (T0 - 1) * 1000,
            sct_signer: &self.ct_key,
            sct_tbs: None,
        }
    }

    /// Leaf with an embedded SCT, signed by the intermediate.
    fn leaf(&self, leaf: Leaf<'_>) -> Certificate {
        let subject = Name::default();
        let mut extensions = vec![
            KeyUsage(KeyUsages::DigitalSignature.into())
                .to_extension(&subject, &[])
                .unwrap(),
            ExtendedKeyUsage(vec![oid("1.3.6.1.5.5.7.3.3")])
                .to_extension(&subject, &[])
                .unwrap(),
            SubjectAltName(leaf.sans)
                .to_extension(&subject, &[])
                .unwrap(),
        ];
        extensions.extend(leaf.extra);
        let mut tbs = tbs(
            9,
            INTER_NAME,
            None,
            leaf.not_before,
            leaf.not_after,
            leaf.key,
            extensions,
        );
        // RFC 6962 3.2: SCT over the precertificate TBS.
        let precert = leaf.sct_tbs.unwrap_or_else(|| tbs.to_der().unwrap());
        let issuer_key_hash = Sha256::digest(
            self.intermediate
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
        );
        let mut signed = vec![0u8, 0];
        signed.extend_from_slice(&leaf.sct_ms.to_be_bytes());
        signed.extend_from_slice(&[0, 1]);
        signed.extend_from_slice(&issuer_key_hash);
        signed.extend_from_slice(&(precert.len() as u32).to_be_bytes()[1..]);
        signed.extend_from_slice(&precert);
        signed.extend_from_slice(&[0, 0]);
        let signature: Signature = leaf.sct_signer.sign(&signed);
        let signature = signature.to_der();
        let mut sct = vec![0u8];
        sct.extend_from_slice(&Self::log_id(&self.ct_key));
        sct.extend_from_slice(&leaf.sct_ms.to_be_bytes());
        sct.extend_from_slice(&[0, 0, 4, 3]);
        sct.extend_from_slice(&(signature.as_bytes().len() as u16).to_be_bytes());
        sct.extend_from_slice(signature.as_bytes());
        let mut list = (sct.len() as u16 + 2).to_be_bytes().to_vec();
        list.extend_from_slice(&(sct.len() as u16).to_be_bytes());
        list.extend_from_slice(&sct);
        tbs.extensions.as_mut().unwrap().push(Extension {
            extn_id: oid("1.3.6.1.4.1.11129.2.4.2"),
            critical: false,
            extn_value: OctetString::new(OctetString::new(list).unwrap().to_der().unwrap())
                .unwrap(),
        });
        sign(tbs, &self.intermediate_key)
    }

    fn root_json(&self, rekor_start: &str, ct_start: &str, fulcio_start: &str) -> Value {
        let log = |k: &SigningKey, start: &str| {
            json!({
                "baseUrl": "https://log.test", "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": B64.encode(spki(k).to_der().unwrap()),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": {"start": start}
                },
                "logId": {"keyId": B64.encode(Self::log_id(k))}
            })
        };
        json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [log(&self.rekor_key, rekor_start)],
            "certificateAuthorities": [{
                "subject": {"organization": "forged", "commonName": "test"},
                "uri": "https://fulcio.test",
                "certChain": {"certificates": [
                    {"rawBytes": B64.encode(self.intermediate.to_der().unwrap())},
                    {"rawBytes": B64.encode(self.root.to_der().unwrap())}
                ]},
                "validFor": {"start": fulcio_start}
            }],
            "ctlogs": [log(&self.ct_key, ct_start)],
            "timestampAuthorities": []
        })
    }

    /// `hashedrekord` 0.0.1 entry in a one-leaf tree, with SET and checkpoint.
    fn entry(
        &self,
        leaf_der: &[u8],
        signature: &[u8],
        digest: &[u8; 32],
        integrated: u64,
        set_signer: &SigningKey,
        checkpoint_signer: &SigningKey,
    ) -> Value {
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            B64.encode(leaf_der)
        );
        let body = serde_json::to_vec(&json!({
            "apiVersion": "0.0.1", "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": hex(digest)}},
                "signature": {"content": B64.encode(signature), "publicKey": {"content": B64.encode(pem)}}
            }
        }))
        .unwrap();
        let body_b64 = B64.encode(&body);
        let leaf_hash: [u8; 32] = Sha256::new()
            .chain_update([0])
            .chain_update(&body)
            .finalize()
            .into();
        let id = Self::log_id(&self.rekor_key);
        let text = format!("log.test\n1\n{}\n", B64.encode(leaf_hash));
        let checkpoint: Signature = checkpoint_signer.sign(text.as_bytes());
        let mut line = id[..4].to_vec();
        line.extend_from_slice(checkpoint.to_der().as_bytes());
        let envelope = format!("{text}\n\u{2014} log.test {}\n", B64.encode(line));
        let message = format!(
            r#"{{"body":"{body_b64}","integratedTime":{integrated},"logID":"{}","logIndex":0}}"#,
            hex(&id)
        );
        let set: Signature = set_signer.sign(message.as_bytes());
        json!({
            "logIndex": "0",
            "logId": {"keyId": B64.encode(&id)},
            "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
            "integratedTime": integrated.to_string(),
            "inclusionPromise": {"signedEntryTimestamp": B64.encode(set.to_der().as_bytes())},
            "inclusionProof": {
                "logIndex": "0", "rootHash": B64.encode(leaf_hash), "treeSize": "1", "hashes": [],
                "checkpoint": {"envelope": envelope}
            },
            "canonicalizedBody": body_b64
        })
    }
}

fn bundle(leaf: &Certificate, signature: &[u8], entries: Vec<Value>) -> Value {
    json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": B64.encode(leaf.to_der().unwrap())},
            "tlogEntries": entries
        },
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_256", "digest": B64.encode(Sha256::digest(ARTIFACT))},
            "signature": B64.encode(signature)
        }
    })
}

fn verify(root: &Value, bundle: &Value) -> Result<Vec<u64>, Error> {
    PublicVerifier::from_json(&serde_json::to_vec(root).unwrap())?
        .verify(
            ARTIFACT,
            &serde_json::to_vec(bundle).unwrap(),
            IDENTITY,
            ISSUER,
            NOT_AFTER,
        )
        .map(|result| result.signed_at_unix_seconds)
}

struct Forge {
    pki: Pki,
    leaf_key: SigningKey,
    signature: Vec<u8>,
    digest: [u8; 32],
}

impl Forge {
    fn new() -> Self {
        let leaf_key = key(7);
        let signature: Signature = leaf_key.sign(ARTIFACT);
        Self {
            pki: Pki::new(),
            leaf_key,
            signature: signature.to_der().as_bytes().to_vec(),
            digest: Sha256::digest(ARTIFACT).into(),
        }
    }
    fn root(&self) -> Value {
        self.pki.root_json(EARLY, EARLY, EARLY)
    }
    fn leaf(&self) -> Certificate {
        self.pki.leaf(self.pki.standard_leaf(&self.leaf_key))
    }
    fn entry(&self, leaf: &Certificate, integrated: u64) -> Value {
        self.entry_with(
            leaf,
            &self.signature,
            integrated,
            &self.pki.rekor_key,
            &self.pki.rekor_key,
        )
    }
    fn entry_with(
        &self,
        leaf: &Certificate,
        signature: &[u8],
        integrated: u64,
        set: &SigningKey,
        checkpoint: &SigningKey,
    ) -> Value {
        self.pki.entry(
            &leaf.to_der().unwrap(),
            signature,
            &self.digest,
            integrated,
            set,
            checkpoint,
        )
    }
    /// Consistent bundle for `leaf` logged at `integrated`.
    fn bundle(&self, leaf: &Certificate, integrated: u64) -> Value {
        bundle(leaf, &self.signature, vec![self.entry(leaf, integrated)])
    }
}

#[test]
fn forged_pki_baseline_verifies_with_inclusive_leaf_validity() {
    let f = Forge::new();
    let leaf = f.leaf();
    assert_eq!(
        verify(&f.root(), &f.bundle(&leaf, T0 + 5)),
        Ok(vec![T0 + 5])
    );
    assert_eq!(verify(&f.root(), &f.bundle(&leaf, T0)), Ok(vec![T0]));
    assert_eq!(
        verify(&f.root(), &f.bundle(&leaf, T0 + LEAF_LIFE)),
        Ok(vec![T0 + LEAF_LIFE])
    );
    assert_eq!(
        verify(&f.root(), &f.bundle(&leaf, T0 - 1)),
        Err(Error::Trust)
    );
    assert_eq!(
        verify(&f.root(), &f.bundle(&leaf, T0 + LEAF_LIFE + 1)),
        Err(Error::Trust)
    );
    // Every time must fall inside the leaf validity.
    let two = bundle(
        &leaf,
        &f.signature,
        vec![f.entry(&leaf, T0 + 5), f.entry(&leaf, T0 + LEAF_LIFE + 1)],
    );
    assert_eq!(verify(&f.root(), &two), Err(Error::Trust));
    assert_eq!(
        PublicVerifier::from_json(&serde_json::to_vec(&f.root()).unwrap())
            .unwrap()
            .verify(
                ARTIFACT,
                &serde_json::to_vec(&f.bundle(&leaf, T0 + 5)).unwrap(),
                IDENTITY,
                ISSUER,
                T0 + 4
            ),
        Err(Error::Timestamp)
    );
}

#[test]
fn each_log_key_only_authenticates_its_own_evidence() {
    let f = Forge::new();
    let leaf = f.leaf();
    let ct = &f.pki.ct_key;
    let rekor = &f.pki.rekor_key;
    // The CT key may sign SCTs only.
    let set_by_ct = bundle(
        &leaf,
        &f.signature,
        vec![f.entry_with(&leaf, &f.signature, T0 + 5, ct, rekor)],
    );
    assert_eq!(verify(&f.root(), &set_by_ct), Err(Error::Signature));
    let checkpoint_by_ct = bundle(
        &leaf,
        &f.signature,
        vec![f.entry_with(&leaf, &f.signature, T0 + 5, rekor, ct)],
    );
    assert_eq!(verify(&f.root(), &checkpoint_by_ct), Err(Error::Signature));
    // The Rekor key is not a CT log.
    let mut by_rekor = f.pki.standard_leaf(&f.leaf_key);
    by_rekor.sct_signer = rekor;
    let by_rekor = f.pki.leaf(by_rekor);
    assert_eq!(
        verify(&f.root(), &f.bundle(&by_rekor, T0 + 5)),
        Err(Error::Trust)
    );
    // Aliasing the Rekor key under another log ID does not help.
    let mut root = f.root();
    let mut alias = root["tlogs"][0].clone();
    alias["logId"]["keyId"] = B64.encode([5u8; 32]).into();
    root["tlogs"].as_array_mut().unwrap().push(alias);
    let mut entry = f.entry(&leaf, T0 + 5);
    entry["logId"]["keyId"] = B64.encode([5u8; 32]).into();
    assert!(verify(&root, &bundle(&leaf, &f.signature, vec![entry])).is_err());
}

#[test]
fn sct_must_cover_this_precertificate_inside_the_ct_window() {
    let f = Forge::new();
    // SCT over a different precertificate.
    let mut other = f.pki.standard_leaf(&f.leaf_key);
    other.sct_tbs = Some(b"another precertificate".to_vec());
    let other = f.pki.leaf(other);
    assert_eq!(
        verify(&f.root(), &f.bundle(&other, T0 + 5)),
        Err(Error::Trust)
    );
    // SCT timestamp before the CT window.
    let mut early = f.pki.standard_leaf(&f.leaf_key);
    early.sct_ms = 1_100_000_000_000; // 2004-11-09
    let early = f.pki.leaf(early);
    let root = f.pki.root_json(EARLY, "2010-01-01T00:00:00Z", EARLY);
    assert_eq!(verify(&root, &f.bundle(&early, T0 + 5)), Err(Error::Trust));
    assert_eq!(
        verify(&f.root(), &f.bundle(&early, T0 + 5)),
        Ok(vec![T0 + 5])
    );
}

#[test]
fn leaf_profile_is_enforced() {
    let f = Forge::new();
    let subject = Name::default();
    // Two SANs, one of them correct.
    let mut two = f.pki.standard_leaf(&f.leaf_key);
    two.sans.push(uri("https://github.com/attacker/x"));
    let two = f.pki.leaf(two);
    assert_eq!(
        verify(&f.root(), &f.bundle(&two, T0 + 5)),
        Err(Error::Identity)
    );
    // Leaf with cA=TRUE.
    let mut ca = f.pki.standard_leaf(&f.leaf_key);
    ca.extra.push(
        BasicConstraints {
            ca: true,
            path_len_constraint: None,
        }
        .to_extension(&subject, &[])
        .unwrap(),
    );
    let ca = f.pki.leaf(ca);
    assert_eq!(verify(&f.root(), &f.bundle(&ca, T0 + 5)), Err(Error::Trust));
    // Leaf issued by the root, skipping the pinned intermediate.
    let mut tbs = f.leaf().tbs_certificate;
    tbs.issuer = Name::from_str(ROOT_NAME).unwrap();
    let by_root = sign(tbs, &key(1));
    assert_eq!(
        verify(&f.root(), &f.bundle(&by_root, T0 + 5)),
        Err(Error::Trust)
    );
    // Timestamping-only EKU.
    let mut tbs = f.leaf().tbs_certificate;
    for extension in tbs.extensions.as_mut().unwrap() {
        if extension.extn_id == oid("2.5.29.37") {
            *extension = ExtendedKeyUsage(vec![oid("1.3.6.1.5.5.7.3.8")])
                .to_extension(&subject, &[])
                .unwrap();
        }
    }
    let tsa = sign(tbs, &f.pki.intermediate_key);
    assert_eq!(
        verify(&f.root(), &f.bundle(&tsa, T0 + 5)),
        Err(Error::Trust)
    );
    // Legacy raw-string issuer extension alone is accepted.
    let mut legacy = f.pki.standard_leaf(&f.leaf_key);
    legacy.extra = vec![Extension {
        extn_id: oid("1.3.6.1.4.1.57264.1.1"),
        critical: false,
        extn_value: OctetString::new(ISSUER.as_bytes()).unwrap(),
    }];
    let legacy = f.pki.leaf(legacy);
    assert_eq!(
        verify(&f.root(), &f.bundle(&legacy, T0 + 5)),
        Ok(vec![T0 + 5])
    );
}

#[test]
fn trust_root_windows_apply_to_the_authenticated_time() {
    let f = Forge::new();
    let leaf = f.leaf();
    let late = "2030-01-01T00:00:00Z";
    assert_eq!(
        verify(
            &f.pki.root_json(late, EARLY, EARLY),
            &f.bundle(&leaf, T0 + 5)
        ),
        Err(Error::Trust)
    );
    assert_eq!(
        verify(
            &f.pki.root_json(EARLY, EARLY, late),
            &f.bundle(&leaf, T0 + 5)
        ),
        Err(Error::Trust)
    );
}

#[test]
fn log_entries_bind_the_exact_signature_bytes() {
    let f = Forge::new();
    let leaf = f.leaf();
    // Another key's signature, logged consistently.
    let other: Signature = key(8).sign(ARTIFACT);
    let other = other.to_der().as_bytes().to_vec();
    let forged = bundle(
        &leaf,
        &other,
        vec![f.entry_with(&leaf, &other, T0 + 5, &f.pki.rekor_key, &f.pki.rekor_key)],
    );
    assert_eq!(verify(&f.root(), &forged), Err(Error::Signature));
    // Malleated (r, -s) verifies only if the log names those bytes.
    let (r, s) = Signature::from_der(&f.signature).unwrap().split_scalars();
    let malleated = Signature::from_scalars(r, -*s)
        .unwrap()
        .to_der()
        .as_bytes()
        .to_vec();
    let unlogged = bundle(&leaf, &malleated, vec![f.entry(&leaf, T0 + 5)]);
    assert_eq!(verify(&f.root(), &unlogged), Err(Error::Trust));
    let logged = bundle(
        &leaf,
        &malleated,
        vec![f.entry_with(
            &leaf,
            &malleated,
            T0 + 5,
            &f.pki.rekor_key,
            &f.pki.rekor_key,
        )],
    );
    assert_eq!(verify(&f.root(), &logged), Ok(vec![T0 + 5]));
    // Entry for a different digest.
    let wrong = f.pki.entry(
        &leaf.to_der().unwrap(),
        &f.signature,
        &[9; 32],
        T0 + 5,
        &f.pki.rekor_key,
        &f.pki.rekor_key,
    );
    assert_eq!(
        verify(&f.root(), &bundle(&leaf, &f.signature, vec![wrong])),
        Err(Error::Trust)
    );
}

#[test]
fn sct_list_encoding_is_validated() {
    let f = Forge::new();
    let leaf = f.leaf();
    let sct_oid = oid("1.3.6.1.4.1.11129.2.4.2");
    let original = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .unwrap()
        .iter()
        .find(|e| e.extn_id == sct_oid)
        .unwrap()
        .extn_value
        .clone();
    let list = OctetString::from_der(original.as_bytes()).unwrap();
    let list = list.as_bytes();
    let one_sct = list[4..].to_vec(); // drop both length prefixes
    let with_list = |bytes: Vec<u8>| {
        let mut tbs = leaf.tbs_certificate.clone();
        for extension in tbs.extensions.as_mut().unwrap() {
            if extension.extn_id == sct_oid {
                extension.extn_value =
                    OctetString::new(OctetString::new(bytes.clone()).unwrap().to_der().unwrap())
                        .unwrap();
            }
        }
        let cert = sign(tbs, &f.pki.intermediate_key);
        verify(&f.root(), &f.bundle(&cert, T0 + 5))
    };
    let framed = |scts: &[&[u8]]| {
        let mut body = Vec::new();
        for sct in scts {
            body.extend_from_slice(&(sct.len() as u16).to_be_bytes());
            body.extend_from_slice(sct);
        }
        let mut out = (body.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    };
    assert_eq!(with_list(list.to_vec()), Ok(vec![T0 + 5]));
    assert_eq!(with_list(framed(&[&one_sct])), Ok(vec![T0 + 5]));
    // Empty list, wrong declared length, trailing bytes.
    assert_eq!(with_list(framed(&[])), Err(Error::Trust));
    let mut short = framed(&[&one_sct]);
    short[1] = short[1].wrapping_sub(1);
    assert_eq!(with_list(short), Err(Error::Trust));
    let mut trailing = one_sct.clone();
    trailing.push(0);
    assert_eq!(with_list(framed(&[&trailing])), Err(Error::Trust));
    // Bad SCTs are skipped; more than 16 is rejected.
    let bogus = vec![0u8; one_sct.len()];
    assert_eq!(with_list(framed(&[&bogus, &one_sct])), Ok(vec![T0 + 5]));
    let sixteen: Vec<&[u8]> = (0..15).map(|_| &bogus[..]).chain([&one_sct[..]]).collect();
    assert_eq!(with_list(framed(&sixteen)), Ok(vec![T0 + 5]));
    let seventeen: Vec<&[u8]> = (0..16).map(|_| &bogus[..]).chain([&one_sct[..]]).collect();
    // `Limit` inside `sct::verify` surfaces as `Trust`.
    assert_eq!(with_list(framed(&seventeen)), Err(Error::Trust));
    // Wrong version, unknown log, non-ECDSA algorithm.
    let mut version = one_sct.clone();
    version[0] = 1;
    assert_eq!(with_list(framed(&[&version])), Err(Error::Trust));
    let mut unknown_log = one_sct.clone();
    unknown_log[1] ^= 1;
    assert_eq!(with_list(framed(&[&unknown_log])), Err(Error::Trust));
    let mut rsa = one_sct.clone();
    rsa[1 + 32 + 8 + 2 + 1] = 1; // signature algorithm
    assert_eq!(with_list(framed(&[&rsa])), Err(Error::Trust));
}
