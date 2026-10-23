//! Offline verification of public Sigstore (Fulcio, Rekor, CT) bundles.
//!
//! Like the GitHub path, this module is `no_std` + `alloc` and builds for
//! WebAssembly. The caller supplies an
//! authenticated Sigstore TrustedRoot, the exact artifact bytes (or their
//! SHA-256), an exact certificate identity and issuer, and a trusted upper time
//! bound. This path authenticates a signer and artifact; application-specific
//! attestation statements still need their own authorization checks.

mod rekor;
mod sct;

use crate::{
    Envelope, Error, Timestamp,
    certificate::{self, Authority, CODE_SIGNING, RawCertificate},
    crypto,
    error::Result,
    timestamp,
};
use alloc::{string::String, vec::Vec};
use der::{
    Decode,
    asn1::{ObjectIdentifier, Utf8StringRef},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x509_cert::{
    Certificate,
    ext::pkix::{SubjectAltName, name::GeneralName},
    spki::SubjectPublicKeyInfoOwned,
};

const MAX_JSON_BYTES: usize = 1024 * 1024;
const IN_TOTO: &str = "application/vnd.in-toto+json";

/// Authenticated public Sigstore result, returned only after all checks succeed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicVerifiedArtifact {
    /// SHA-256 of the verified artifact bytes.
    pub sha256: [u8; 32],
    /// Every authenticated signing time, in ascending Unix seconds.
    pub signed_at_unix_seconds: Vec<u64>,
    /// Signed in-toto statement bytes for DSSE bundles; `None` for message
    /// signatures. Its claims are authenticated but not authorized: parse and
    /// check them before acting on them.
    pub dsse_payload: Option<Vec<u8>>,
}

/// Reusable verifier initialized from an authenticated Sigstore TrustedRoot.
pub struct PublicVerifier {
    fulcio: Vec<Authority>,
    tsa: Vec<Authority>,
    tlogs: Vec<Log>,
    ctlogs: Vec<Log>,
}

impl PublicVerifier {
    /// Parse one Sigstore `TrustedRoot` JSON object (maximum 1 MiB).
    ///
    /// This does not authenticate or refresh the JSON. Obtain it through a
    /// trusted provisioning channel, such as a TUF client, and handle metadata
    /// rollback externally. Log keys of unsupported algorithms are skipped.
    pub fn from_json(root_json: &[u8]) -> Result<Self> {
        if root_json.len() > MAX_JSON_BYTES {
            return Err(Error::Limit);
        }
        let root: RootJson = serde_json::from_slice(root_json)?;
        if root.media_type != "application/vnd.dev.sigstore.trustedroot+json;version=0.1" {
            return Err(Error::Unsupported);
        }
        if [
            root.certificate_authorities.len(),
            root.timestamp_authorities.len(),
            root.tlogs.len(),
            root.ctlogs.len(),
        ]
        .iter()
        .any(|&n| n > 16)
        {
            return Err(Error::Limit);
        }
        fn authorities(input: Vec<AuthorityJson>) -> Result<Vec<Authority>> {
            input
                .into_iter()
                .map(|a| {
                    if a.cert_chain.certificates.len() > 4 {
                        return Err(Error::Limit);
                    }
                    let chain = a
                        .cert_chain
                        .certificates
                        .iter()
                        .map(|c| certificate::parse(&crypto::b64(&c.raw_bytes)?))
                        .collect::<Result<Vec<_>>>()?;
                    let (start, end) = window_seconds(&a.valid_for)?;
                    Authority::new(chain, start, end)
                })
                .collect()
        }
        let tlogs = root
            .tlogs
            .into_iter()
            .filter_map(|log| Log::parse(log, false).transpose())
            .collect::<Result<Vec<_>>>()?;
        let ctlogs = root
            .ctlogs
            .into_iter()
            .filter_map(|log| Log::parse(log, true).transpose())
            .collect::<Result<Vec<_>>>()?;
        let fulcio = authorities(root.certificate_authorities)?;
        if fulcio.is_empty() || tlogs.is_empty() || ctlogs.is_empty() {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            fulcio,
            tsa: authorities(root.timestamp_authorities)?,
            tlogs,
            ctlogs,
        })
    }

    /// Verify exact artifact bytes against a public Sigstore bundle.
    ///
    /// `identity` is the exact certificate SAN (URI or email), `issuer` the exact
    /// OIDC issuer, and `not_after` an inclusive Unix-seconds bound from a trusted
    /// clock or release policy. No platform clock is read.
    pub fn verify(
        &self,
        artifact: &[u8],
        bundle_json: &[u8],
        identity: &str,
        issuer: &str,
        not_after: u64,
    ) -> Result<PublicVerifiedArtifact> {
        self.verify_digest(
            Sha256::digest(artifact).into(),
            bundle_json,
            identity,
            issuer,
            not_after,
        )
    }

    /// Verify a caller-computed SHA-256 of **all exact artifact bytes**.
    ///
    /// A digest copied from an unverified manifest does not authenticate content.
    pub fn verify_digest(
        &self,
        digest: [u8; 32],
        bundle_json: &[u8],
        identity: &str,
        issuer: &str,
        not_after: u64,
    ) -> Result<PublicVerifiedArtifact> {
        if identity.is_empty() || issuer.is_empty() {
            return Err(Error::Policy);
        }
        if bundle_json.len() > MAX_JSON_BYTES {
            return Err(Error::Limit);
        }
        let bundle: Bundle = serde_json::from_slice(bundle_json)?;
        let material = bundle.verification_material;
        let leaf_der = crypto::b64(
            &match (
                bundle.media_type.as_str(),
                material.certificate,
                material.x509_certificate_chain,
            ) {
                (
                    "application/vnd.dev.sigstore.bundle.v0.3+json"
                    | "application/vnd.dev.sigstore.bundle+json;version=0.3",
                    Some(leaf),
                    None,
                ) => leaf,
                // v0.2 chains may carry intermediates; only pinned ones are used.
                ("application/vnd.dev.sigstore.bundle+json;version=0.2", None, Some(chain))
                    if (1..=4).contains(&chain.certificates.len()) =>
                {
                    chain
                        .certificates
                        .into_iter()
                        .next()
                        .ok_or(Error::Encoding)?
                }
                _ => return Err(Error::Unsupported),
            }
            .raw_bytes,
        )?;
        let leaf = certificate::parse(&leaf_der)?;
        check_identity(&leaf, identity, issuer)?;
        let key = &leaf.tbs_certificate.subject_public_key_info;

        let (signature, content, dsse_payload) =
            match (bundle.message_signature, bundle.dsse_envelope) {
                (Some(message), None) => {
                    if let Some(claimed) = message.message_digest {
                        if claimed.algorithm != "SHA2_256"
                            || crypto::b64(&claimed.digest)? != digest
                        {
                            return Err(Error::Artifact);
                        }
                    }
                    let signature = crypto::b64(&message.signature)?;
                    crypto::verify_p256_prehash(key, &digest, &signature)?;
                    (signature, rekor::Content::Message(digest), None)
                }
                (None, Some(envelope)) => {
                    if envelope.payload_type != IN_TOTO || envelope.signatures.len() != 1 {
                        return Err(Error::Unsupported);
                    }
                    let signature = crypto::b64(&envelope.signatures[0].sig)?;
                    let payload = crypto::b64(&envelope.payload)?;
                    let pae = crate::pae(&envelope.payload_type, &payload);
                    crypto::verify(key, &crypto::ecdsa_sha256(), &pae, &signature)?;
                    check_subject(&payload, &digest)?;
                    let content = rekor::Content::Dsse {
                        payload: Sha256::digest(&payload).into(),
                        pae: Sha256::digest(&pae).into(),
                    };
                    (signature, content, Some(payload))
                }
                _ => return Err(Error::Unsupported),
            };

        let entries = &material.tlog_entries;
        if entries.is_empty() {
            return Err(Error::Unsupported);
        }
        let stamps = material
            .timestamp_verification_data
            .map(|data| data.rfc3161_timestamps)
            .unwrap_or_default();
        if entries.len() > 16 || stamps.len() > 4 {
            return Err(Error::Limit);
        }
        let mut times = Vec::new();
        let mut logs = Vec::new();
        for entry in entries {
            let (log, time) = rekor::verify(entry, &self.tlogs, &leaf_der, &signature, &content)?;
            logs.push(log);
            times.extend(time);
        }
        for stamp in &stamps {
            times.push(timestamp::verify(
                &crypto::b64(&stamp.signed_timestamp)?,
                &signature,
                &self.tsa,
                not_after,
                true,
            )?);
        }
        times.sort_unstable();
        times.dedup();
        // An unsigned Rekor `integratedTime` never counts as a signing time.
        if times.is_empty() || times.iter().any(|&t| t > not_after) {
            return Err(Error::Timestamp);
        }
        if logs
            .iter()
            .any(|log| times.iter().any(|&t| !log.contains(t.saturating_mul(1000))))
        {
            return Err(Error::Trust);
        }
        if !self.fulcio.iter().any(|authority| {
            times
                .iter()
                .all(|&t| authority.verify(&leaf, t, CODE_SIGNING).is_ok())
                && sct::verify(&leaf, &authority.chain[0], &self.ctlogs).is_ok()
        }) {
            return Err(Error::Trust);
        }
        Ok(PublicVerifiedArtifact {
            sha256: digest,
            signed_at_unix_seconds: times,
            dsse_payload,
        })
    }
}

/// The single SAN must equal `identity`; the Fulcio issuer extension `issuer`.
fn check_identity(leaf: &Certificate, identity: &str, issuer: &str) -> Result<()> {
    let sans = leaf
        .tbs_certificate
        .get::<SubjectAltName>()?
        .ok_or(Error::Identity)?
        .1;
    match sans.0.as_slice() {
        [GeneralName::UniformResourceIdentifier(name)] if name.as_str() == identity => (),
        [GeneralName::Rfc822Name(name)] if name.as_str() == identity => (),
        _ => return Err(Error::Identity),
    }
    let extension = |number: &str| {
        let id = ObjectIdentifier::new(number).ok()?;
        leaf.tbs_certificate
            .extensions
            .as_deref()?
            .iter()
            .find(|e| e.extn_id == id)
            .map(|e| e.extn_value.as_bytes())
    };
    // 1.1 is the deprecated raw-string issuer, 1.8 its DER UTF8String successor.
    let legacy = extension("1.3.6.1.4.1.57264.1.1")
        .map(|v| core::str::from_utf8(v).map_err(|_| Error::Encoding))
        .transpose()?;
    let current = extension("1.3.6.1.4.1.57264.1.8")
        .map(|v| Ok::<_, Error>(Utf8StringRef::from_der(v)?.as_str()))
        .transpose()?;
    let found = match (legacy, current) {
        (Some(a), Some(b)) if a != b => return Err(Error::Identity),
        (_, Some(name)) | (Some(name), None) => name,
        (None, None) => return Err(Error::Identity),
    };
    if found != issuer {
        return Err(Error::Identity);
    }
    Ok(())
}

/// The artifact digest must be a SHA-256 subject of the signed in-toto statement.
fn check_subject(payload: &[u8], digest: &[u8; 32]) -> Result<()> {
    let statement: Statement = serde_json::from_slice(payload)?;
    if !matches!(
        statement.statement_type.as_str(),
        "https://in-toto.io/Statement/v1" | "https://in-toto.io/Statement/v0.1"
    ) {
        return Err(Error::Unsupported);
    }
    if statement.subject.is_empty() || statement.subject.len() > 64 {
        return Err(Error::Limit);
    }
    let expected = crypto::hex(digest);
    if !statement
        .subject
        .iter()
        .any(|s| s.digest.sha256.as_deref() == Some(expected.as_str()))
    {
        return Err(Error::Artifact);
    }
    Ok(())
}

/// A pinned Rekor or CT log key with an inclusive validity window in milliseconds.
struct Log {
    id: Vec<u8>,
    key: LogKey,
    start_ms: u64,
    end_ms: Option<u64>,
}

enum LogKey {
    EcdsaP256(SubjectPublicKeyInfoOwned),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl Log {
    fn parse(json: LogJson, ct: bool) -> Result<Option<Self>> {
        // Historical roots list other algorithms; such logs are skipped, so
        // entries naming them fail closed.
        let ed25519 = match json.public_key.key_details.as_str() {
            "PKIX_ECDSA_P256_SHA_256" => false,
            "PKIX_ED25519" if !ct => true,
            _ => return Ok(None),
        };
        let der = crypto::b64(&json.public_key.raw_bytes)?;
        let id = crypto::b64(&json.log_id.key_id)?;
        // RFC 6962 defines CT log IDs as SHA-256 of the key; SCTs name logs by it.
        if id.len() != 32 || (ct && id[..] != Sha256::digest(&der)[..]) {
            return Err(Error::Encoding);
        }
        let spki = SubjectPublicKeyInfoOwned::from_der(&der)?;
        let key = match ed25519 {
            false => LogKey::EcdsaP256(spki),
            true => {
                if spki.algorithm.oid != crypto::oid("1.3.101.112")
                    || spki.algorithm.parameters.is_some()
                {
                    return Err(Error::Encoding);
                }
                let bytes: [u8; 32] = spki
                    .subject_public_key
                    .as_bytes()
                    .and_then(|b| b.try_into().ok())
                    .ok_or(Error::Encoding)?;
                LogKey::Ed25519(
                    ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Encoding)?,
                )
            }
        };
        let start = parse_time(&json.public_key.valid_for.start)?;
        let end = json
            .public_key
            .valid_for
            .end
            .as_deref()
            .map(parse_time)
            .transpose()?;
        // Round the window inward to whole milliseconds.
        let start_ms = start.0 * 1000 + u64::from(start.1).div_ceil(1_000_000);
        let end_ms = end.map(|(s, n)| s * 1000 + u64::from(n) / 1_000_000);
        if end_ms.is_some_and(|end| end < start_ms) {
            return Err(Error::Encoding);
        }
        Ok(Some(Self {
            id,
            key,
            start_ms,
            end_ms,
        }))
    }

    fn contains(&self, ms: u64) -> bool {
        ms >= self.start_ms && self.end_ms.is_none_or(|end| ms <= end)
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match &self.key {
            LogKey::EcdsaP256(key) => {
                crypto::verify(key, &crypto::ecdsa_sha256(), message, signature)
            }
            LogKey::Ed25519(key) => {
                let signature =
                    ed25519_dalek::Signature::from_slice(signature).map_err(|_| Error::Encoding)?;
                key.verify_strict(message, &signature)
                    .map_err(|_| Error::Signature)
            }
        }
    }
}

fn parse_time(s: &str) -> Result<(u64, u32)> {
    if s.len() > 30 {
        return Err(Error::Encoding);
    }
    certificate::parse_rfc3339(s)
}

/// Authority windows in whole seconds, rounded inward.
fn window_seconds(period: &PeriodJson) -> Result<(u64, Option<u64>)> {
    let (start, nanos) = parse_time(&period.start)?;
    let end = period.end.as_deref().map(parse_time).transpose()?;
    Ok((start + u64::from(nanos > 0), end.map(|(s, _)| s)))
}

/// Canonical unsigned decimal, as protobuf JSON encodes 64-bit integers.
fn number(s: &str) -> Result<u64> {
    if s.is_empty() || s.len() > 20 || (s.len() > 1 && s.starts_with('0')) {
        return Err(Error::Encoding);
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Encoding);
    }
    s.parse().map_err(|_| Error::Encoding)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RootJson {
    media_type: String,
    #[serde(default)]
    tlogs: Vec<LogJson>,
    certificate_authorities: Vec<AuthorityJson>,
    #[serde(default)]
    ctlogs: Vec<LogJson>,
    #[serde(default)]
    timestamp_authorities: Vec<AuthorityJson>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorityJson {
    cert_chain: ChainJson,
    valid_for: PeriodJson,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainJson {
    certificates: Vec<RawCertificate>,
}
#[derive(Deserialize)]
struct PeriodJson {
    start: String,
    end: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogJson {
    public_key: PublicKeyJson,
    log_id: LogIdJson,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyJson {
    raw_bytes: String,
    key_details: String,
    valid_for: PeriodJson,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogIdJson {
    key_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bundle {
    media_type: String,
    verification_material: Material,
    message_signature: Option<MessageSignature>,
    dsse_envelope: Option<Envelope>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Material {
    certificate: Option<RawCertificate>,
    x509_certificate_chain: Option<ChainJson>,
    #[serde(default)]
    tlog_entries: Vec<rekor::Entry>,
    timestamp_verification_data: Option<Timestamps>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Timestamps {
    #[serde(default)]
    rfc3161_timestamps: Vec<Timestamp>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MessageSignature {
    message_digest: Option<HashOutput>,
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HashOutput {
    algorithm: String,
    digest: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Statement {
    #[serde(rename = "_type")]
    statement_type: String,
    subject: Vec<Subject>,
}
#[derive(Deserialize)]
struct Subject {
    digest: SubjectDigest,
}
#[derive(Deserialize)]
struct SubjectDigest {
    sha256: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_numbers_and_fractional_windows() {
        assert_eq!(number("0"), Ok(0));
        assert_eq!(number("1734374576"), Ok(1_734_374_576));
        assert_eq!(number("18446744073709551615"), Ok(u64::MAX));
        for bad in [
            "",
            "01",
            "+1",
            "-1",
            "1.0",
            "18446744073709551616",
            "000000000000000000001",
            "100000000000000000000",
        ] {
            assert_eq!(number(bad), Err(Error::Encoding), "{bad}");
        }
        let period = PeriodJson {
            start: "2022-10-20T00:00:00.001Z".into(),
            end: Some("2022-10-31T23:59:59.999Z".into()),
        };
        assert_eq!(
            window_seconds(&period),
            Ok((1_666_224_001, Some(1_667_260_799)))
        );
        assert!(parse_time("2022-10-20T00:00:00.Z").is_err());
        // Each separator position is checked on its own.
        let good = "2022-10-20T00:00:00Z";
        for position in [4, 7, 10, 13, 16, 19] {
            let mut bad = good.as_bytes().to_vec();
            bad[position] = b'0';
            assert!(
                parse_time(core::str::from_utf8(&bad).unwrap()).is_err(),
                "position {position}"
            );
        }
        assert!(parse_time("2022-10-20 00:00:00Z").is_err());
        assert!(parse_time("2022-10-20T00:00:00+00:00").is_err());
        assert!(parse_time("2022-10-20T00:00:0Z").is_err());
        assert_eq!(parse_time(good), Ok((1_666_224_000, 0)));
        assert!(parse_time("2022-10-20T00:00:00.123456789Z").is_ok());
        assert_eq!(
            parse_time("2022-10-20T00:00:00.1234567890Z"),
            Err(Error::Encoding)
        );
        assert_eq!(
            parse_time(&"2022-10-20T00:00:00Z".repeat(2)),
            Err(Error::Encoding)
        );
        // A log whose window ends before it starts is malformed metadata.
        let root = edit_root(|r| {
            r["tlogs"][0]["publicKey"]["validFor"]["start"] = "2024-01-01T00:00:00.5Z".into();
            r["tlogs"][0]["publicKey"]["validFor"]["end"] = "2024-01-01T00:00:00.4Z".into();
        });
        assert_eq!(
            PublicVerifier::from_json(&root).err(),
            Some(Error::Encoding)
        );
        let root = edit_root(|r| {
            r["tlogs"][0]["publicKey"]["validFor"]["start"] = "2024-01-01T00:00:00.5Z".into();
            r["tlogs"][0]["publicKey"]["validFor"]["end"] = "2024-01-01T00:00:00.5Z".into();
        });
        assert!(PublicVerifier::from_json(&root).is_ok());
        assert!(parse_time("2022-10-20T00:00:00.0000000001Z").is_err());
    }

    #[test]
    fn subject_statements_are_bounded_and_typed() {
        let digest = [0xabu8; 32];
        let hex = crypto::hex(&digest);
        let statement = |kind: &str, subjects: alloc::vec::Vec<serde_json::Value>| {
            serde_json::to_vec(&serde_json::json!({
                "_type": kind, "subject": subjects, "predicateType": "x", "predicate": {}
            }))
            .unwrap()
        };
        let subject = |sha256: &str| serde_json::json!({"name": "a", "digest": {"sha256": sha256}});
        let v1 = "https://in-toto.io/Statement/v1";
        check_subject(&statement(v1, alloc::vec![subject(&hex)]), &digest).unwrap();
        check_subject(
            &statement(
                "https://in-toto.io/Statement/v0.1",
                alloc::vec![subject(&hex)],
            ),
            &digest,
        )
        .unwrap();
        assert_eq!(
            check_subject(
                &statement(
                    "https://in-toto.io/Statement/v2",
                    alloc::vec![subject(&hex)]
                ),
                &digest
            ),
            Err(Error::Unsupported)
        );
        assert_eq!(
            check_subject(&statement(v1, alloc::vec![]), &digest),
            Err(Error::Limit)
        );
        let mut many: alloc::vec::Vec<_> = (0..63).map(|_| subject("00")).collect();
        many.push(subject(&hex));
        check_subject(&statement(v1, many.clone()), &digest).unwrap();
        many.insert(0, subject("00"));
        assert_eq!(
            check_subject(&statement(v1, many), &digest),
            Err(Error::Limit)
        );
        assert_eq!(
            check_subject(&statement(v1, alloc::vec![subject("00")]), &digest),
            Err(Error::Artifact)
        );
        assert_eq!(
            check_subject(
                &statement(v1, alloc::vec![subject(&hex.to_uppercase())]),
                &digest
            ),
            Err(Error::Artifact)
        );
        let no_sha256 = serde_json::json!({"name": "a", "digest": {"sha512": "00"}});
        assert_eq!(
            check_subject(&statement(v1, alloc::vec![no_sha256]), &digest),
            Err(Error::Artifact)
        );
    }

    #[test]
    fn log_keys_are_typed_by_key_details() {
        use der::Encode;
        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key();
        let spki = |oid: &str, parameters: bool, key: &[u8]| {
            let algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
                oid: crypto::oid(oid),
                parameters: parameters.then(der::asn1::Any::null),
            };
            SubjectPublicKeyInfoOwned {
                algorithm,
                subject_public_key: der::asn1::BitString::from_bytes(key).unwrap(),
            }
            .to_der()
            .unwrap()
        };
        let log = |details: &str, der: &[u8], ct: bool| {
            use base64::{Engine, engine::general_purpose::STANDARD};
            let id = Sha256::digest(der);
            Log::parse(
                LogJson {
                    public_key: PublicKeyJson {
                        raw_bytes: STANDARD.encode(der),
                        key_details: details.into(),
                        valid_for: PeriodJson {
                            start: "2020-01-01T00:00:00Z".into(),
                            end: None,
                        },
                    },
                    log_id: LogIdJson {
                        key_id: STANDARD.encode(id),
                    },
                },
                ct,
            )
        };
        let good = spki("1.3.101.112", false, ed25519.as_bytes());
        assert!(log("PKIX_ED25519", &good, false).unwrap().is_some());
        // Ed25519 is never accepted for CT logs; unknown details are skipped.
        assert!(log("PKIX_ED25519", &good, true).unwrap().is_none());
        assert!(
            log("PKIX_RSA_PKCS1V15_2048_SHA256", &good, false)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            log(
                "PKIX_ED25519",
                &spki("1.3.101.113", false, ed25519.as_bytes()),
                false
            )
            .err(),
            Some(Error::Encoding)
        );
        assert_eq!(
            log(
                "PKIX_ED25519",
                &spki("1.3.101.112", true, ed25519.as_bytes()),
                false
            )
            .err(),
            Some(Error::Encoding)
        );
        assert_eq!(
            log(
                "PKIX_ED25519",
                &spki("1.3.101.112", false, &ed25519.as_bytes()[..31]),
                false
            )
            .err(),
            Some(Error::Encoding)
        );
    }

    fn edit_root(change: impl FnOnce(&mut serde_json::Value)) -> alloc::vec::Vec<u8> {
        let mut root: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/upstream/public-good-root.json"
        ))
        .unwrap();
        change(&mut root);
        serde_json::to_vec(&root).unwrap()
    }

    fn leaf() -> Certificate {
        let bundle: Bundle = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/upstream/production-message-v03.json"
        ))
        .unwrap();
        let der = crypto::b64(&bundle.verification_material.certificate.unwrap().raw_bytes);
        certificate::parse(&der.unwrap()).unwrap()
    }

    const IDENTITY: &str = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main";
    const ISSUER: &str = "https://token.actions.githubusercontent.com";

    fn set_extension(cert: &mut Certificate, id: &str, value: Option<&[u8]>) {
        let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
        let id = crypto::oid(id);
        match value {
            Some(value) => {
                extensions
                    .iter_mut()
                    .find(|e| e.extn_id == id)
                    .unwrap()
                    .extn_value = der::asn1::OctetString::new(value).unwrap()
            }
            None => extensions.retain(|e| e.extn_id != id),
        }
    }

    #[test]
    fn identity_requires_one_exact_san_and_consistent_issuers() {
        use der::Encode;
        use x509_cert::ext::AsExtension;
        let cert = leaf();
        check_identity(&cert, IDENTITY, ISSUER).unwrap();
        assert_eq!(
            check_identity(&cert, &IDENTITY[..IDENTITY.len() - 1], ISSUER),
            Err(Error::Identity)
        );

        let mut legacy_only = cert.clone();
        set_extension(&mut legacy_only, "1.3.6.1.4.1.57264.1.8", None);
        check_identity(&legacy_only, IDENTITY, ISSUER).unwrap();
        set_extension(&mut legacy_only, "1.3.6.1.4.1.57264.1.1", None);
        assert_eq!(
            check_identity(&legacy_only, IDENTITY, ISSUER),
            Err(Error::Identity)
        );

        let mut conflicting = cert.clone();
        set_extension(
            &mut conflicting,
            "1.3.6.1.4.1.57264.1.1",
            Some(b"https://evil.example"),
        );
        assert_eq!(
            check_identity(&conflicting, IDENTITY, ISSUER),
            Err(Error::Identity)
        );
        let mut current = cert.clone();
        let evil = Utf8StringRef::new("https://evil.example")
            .unwrap()
            .to_der()
            .unwrap();
        set_extension(&mut current, "1.3.6.1.4.1.57264.1.1", None);
        set_extension(&mut current, "1.3.6.1.4.1.57264.1.8", Some(&evil));
        check_identity(&current, IDENTITY, "https://evil.example").unwrap();

        let email = "signer@example.com";
        let sans = |names: alloc::vec::Vec<GeneralName>| {
            let mut cert = cert.clone();
            let extension = SubjectAltName(names)
                .to_extension(&cert.tbs_certificate.subject, &[])
                .unwrap();
            *cert
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .iter_mut()
                .find(|e| e.extn_id == crypto::oid("2.5.29.17"))
                .unwrap() = extension;
            cert
        };
        let mailbox = GeneralName::Rfc822Name(der::asn1::Ia5String::new(email).unwrap());
        let uri =
            GeneralName::UniformResourceIdentifier(der::asn1::Ia5String::new(IDENTITY).unwrap());
        check_identity(&sans(alloc::vec![mailbox.clone()]), email, ISSUER).unwrap();
        // An email SAN matches only its exact address, never a URI identity.
        for wrong in ["other@example.com", "Signer@example.com", IDENTITY] {
            assert_eq!(
                check_identity(&sans(alloc::vec![mailbox.clone()]), wrong, ISSUER),
                Err(Error::Identity),
                "{wrong}"
            );
        }
        assert_eq!(
            check_identity(&sans(alloc::vec![uri.clone()]), email, ISSUER),
            Err(Error::Identity)
        );
        assert_eq!(
            check_identity(&sans(alloc::vec![uri, mailbox]), IDENTITY, ISSUER),
            Err(Error::Identity)
        );
    }
}
