//! Validation of the narrowly supported, pinned GitHub authority paths.
//!
//! Intermediates come exclusively from the embedded snapshot or authenticated
//! caller configuration. No path discovery or general PKIX is implemented.
use crate::{
    Error,
    crypto::{self, oid},
    error::Result,
};
use alloc::{string::String, vec::Vec};
use der::{
    Decode, Encode,
    asn1::{ObjectIdentifier, Utf8StringRef},
};
use serde::Deserialize;
use x509_cert::{
    Certificate, Version,
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName, name::GeneralName},
};

pub(crate) const CODE_SIGNING: ObjectIdentifier = oid("1.3.6.1.5.5.7.3.3");
pub(crate) const TIMESTAMPING: ObjectIdentifier = oid("1.3.6.1.5.5.7.3.8");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RootJson {
    media_type: String,
    certificate_authorities: Vec<AuthorityJson>,
    timestamp_authorities: Vec<AuthorityJson>,
    #[serde(default)]
    tlogs: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    ctlogs: Vec<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorityJson {
    uri: String,
    cert_chain: ChainJson,
    valid_for: PeriodJson,
}

#[derive(Deserialize)]
struct ChainJson {
    certificates: Vec<RawCertificate>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawCertificate {
    pub raw_bytes: String,
}

#[derive(Deserialize)]
struct PeriodJson {
    start: String,
    end: Option<String>,
}

pub(crate) struct Authority {
    pub chain: Vec<Certificate>,
    start: u64,
    end: Option<u64>,
}

/// GitHub Sigstore authority metadata, embedded or supplied by the caller.
///
/// Use [`Self::embedded`] for the built-in snapshot or parse the **GitHub instance**
/// JSON object exported by `gh attestation trusted-root`. Authenticate and pin
/// externally supplied metadata before use.
/// Parsing does not authenticate metadata or implement TUF updates.
/// Public-good-instance roots and JSONL containing multiple objects are rejected.
pub struct TrustedRoot {
    pub(crate) fulcio: Vec<Authority>,
    pub(crate) tsa: Vec<Authority>,
}

/// Pinned GitHub CA and timestamp authority metadata, captured through TUF on
/// 2026-10-21. Embedded with `include_bytes!`; no network access is performed.
/// See `trust/README.md` for provenance, fingerprint, and update instructions.
pub const EMBEDDED_GITHUB_TRUST_ROOT: &[u8] = include_bytes!("../trust/github-trusted-root.json");

impl TrustedRoot {
    /// Load the embedded, pinned GitHub CA and timestamp authority snapshot.
    ///
    /// Authority/certificate validity windows are checked at verification time.
    /// Refresh this crate or use [`Self::from_json`] after authority rotations.
    pub fn embedded() -> Result<Self> {
        Self::from_json(EMBEDDED_GITHUB_TRUST_ROOT)
    }

    /// Parse one GitHub `TrustedRoot` JSON object (maximum 256 KiB).
    pub fn from_json(json: &[u8]) -> Result<Self> {
        if json.len() > 256 * 1024 {
            return Err(Error::Limit);
        }
        let root: RootJson = serde_json::from_slice(json)?;
        if root.media_type != "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
            || !root.tlogs.is_empty()
            || !root.ctlogs.is_empty()
        {
            return Err(Error::Unsupported);
        }
        fn authorities(input: Vec<AuthorityJson>, uri: &str) -> Result<Vec<Authority>> {
            if input.is_empty() || input.len() > 16 {
                return Err(Error::Limit);
            }
            input
                .into_iter()
                .map(|a| {
                    if a.uri != uri {
                        return Err(Error::Unsupported);
                    }
                    if a.cert_chain.certificates.len() < 2 || a.cert_chain.certificates.len() > 4 {
                        return Err(Error::Unsupported);
                    }
                    let chain = a
                        .cert_chain
                        .certificates
                        .into_iter()
                        .map(|c| parse(&crypto::b64(&c.raw_bytes)?))
                        .collect::<Result<Vec<_>>>()?;
                    let start = parse_time(&a.valid_for.start)?;
                    let end = a.valid_for.end.as_deref().map(parse_time).transpose()?;
                    if end.is_some_and(|end| end <= start) {
                        return Err(Error::Encoding);
                    }
                    Ok(Authority { chain, start, end })
                })
                .collect()
        }
        Ok(Self {
            fulcio: authorities(root.certificate_authorities, "fulcio.githubapp.com")?,
            tsa: authorities(root.timestamp_authorities, "timestamp.githubapp.com")?,
        })
    }
}

fn parse_time(s: &str) -> Result<u64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err(Error::Encoding);
    }
    fn number(b: &[u8]) -> Result<u16> {
        b.iter().try_fold(0u16, |n, b| {
            if b.is_ascii_digit() {
                Ok(n * 10 + u16::from(b - b'0'))
            } else {
                Err(Error::Encoding)
            }
        })
    }
    Ok(der::DateTime::new(
        number(&b[..4])?,
        number(&b[5..7])? as u8,
        number(&b[8..10])? as u8,
        number(&b[11..13])? as u8,
        number(&b[14..16])? as u8,
        number(&b[17..19])? as u8,
    )?
    .unix_duration()
    .as_secs())
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Certificate> {
    if bytes.len() > 16 * 1024 {
        return Err(Error::Limit);
    }
    let cert = Certificate::from_der(bytes)?;
    let tbs = &cert.tbs_certificate;
    if tbs.version != Version::V3
        || tbs.issuer_unique_id.is_some()
        || tbs.subject_unique_id.is_some()
    {
        return Err(Error::Unsupported);
    }
    let extensions = tbs.extensions.as_deref().unwrap_or_default();
    for (i, ext) in extensions.iter().enumerate() {
        if extensions[..i]
            .iter()
            .any(|other| other.extn_id == ext.extn_id)
        {
            return Err(Error::Encoding);
        }
        // Constraints we do not implement are rejected even when noncritical.
        if ["2.5.29.30", "2.5.29.33", "2.5.29.36", "2.5.29.54"]
            .iter()
            .any(|s| ext.extn_id == oid(s))
        {
            return Err(Error::Unsupported);
        }
        if ext.critical
            && !["2.5.29.15", "2.5.29.19", "2.5.29.37", "2.5.29.17"]
                .iter()
                .any(|s| ext.extn_id == oid(s))
        {
            return Err(Error::Unsupported);
        }
    }
    Ok(cert)
}

fn valid_at(cert: &Certificate, time: u64) -> Result<()> {
    let v = &cert.tbs_certificate.validity;
    if time < v.not_before.to_unix_duration().as_secs()
        || time > v.not_after.to_unix_duration().as_secs()
    {
        return Err(Error::Trust);
    }
    Ok(())
}

fn usage(cert: &Certificate, purpose: ObjectIdentifier, ca: bool, ca_below: usize) -> Result<()> {
    let tbs = &cert.tbs_certificate;
    let bc = tbs.get::<BasicConstraints>()?;
    let ku = tbs.get::<KeyUsage>()?.ok_or(Error::Trust)?.1;
    if ca {
        let (critical, bc) = bc.ok_or(Error::Trust)?;
        if !critical
            || !bc.ca
            || !ku.key_cert_sign()
            || bc
                .path_len_constraint
                .is_some_and(|limit| ca_below > usize::from(limit))
        {
            return Err(Error::Trust);
        }
    } else if bc.is_some_and(|(_, bc)| bc.ca) || !ku.digital_signature() || ku.key_cert_sign() {
        return Err(Error::Trust);
    }
    match tbs.get::<ExtendedKeyUsage>()? {
        Some((critical, eku)) => {
            if !eku.0.contains(&purpose) {
                return Err(Error::Trust);
            }
            if !ca && purpose == TIMESTAMPING && (!critical || eku.0.as_slice() != [TIMESTAMPING]) {
                return Err(Error::Trust);
            }
        }
        None if !ca => return Err(Error::Trust),
        None => (),
    }
    // Only URI SANs are supported. In this profile SAN constraints are checked
    // against an exact expected workflow, never DNS/wildcard matching.
    if let Some((_, sans)) = tbs.get::<SubjectAltName>()? {
        if sans
            .0
            .iter()
            .any(|n| !matches!(n, GeneralName::UniformResourceIdentifier(_)))
        {
            return Err(Error::Unsupported);
        }
    }
    Ok(())
}

fn issued_by(child: &Certificate, issuer: &Certificate) -> Result<()> {
    if child.tbs_certificate.issuer != issuer.tbs_certificate.subject
        || child.signature_algorithm != child.tbs_certificate.signature
    {
        return Err(Error::Trust);
    }
    crypto::verify(
        &issuer.tbs_certificate.subject_public_key_info,
        &child.signature_algorithm,
        &child.tbs_certificate.to_der()?,
        child.signature.as_bytes().ok_or(Error::Encoding)?,
    )
}

impl Authority {
    /// Fulcio paths start at an issuing CA; timestamp paths start at the pinned TSA leaf.
    pub(crate) fn verify(
        &self,
        leaf: &Certificate,
        time: u64,
        purpose: ObjectIdentifier,
    ) -> Result<()> {
        if time < self.start || self.end.is_some_and(|end| time >= end) {
            return Err(Error::Trust);
        }
        let tsa = purpose == TIMESTAMPING;
        if tsa && self.chain.first() != Some(leaf) {
            return Err(Error::Trust);
        }
        valid_at(leaf, time)?;
        usage(leaf, purpose, false, 0)?;
        let mut previous = leaf;
        for (i, cert) in self.chain.iter().enumerate().skip(usize::from(tsa)) {
            valid_at(cert, time)?;
            usage(cert, purpose, true, i - usize::from(tsa))?;
            issued_by(previous, cert)?;
            previous = cert;
        }
        if previous.tbs_certificate.subject != previous.tbs_certificate.issuer {
            return Err(Error::Trust);
        }
        // The root is already pinned, but checking its signature also checks the
        // algorithm profile and detects accidental corruption in configuration.
        issued_by(previous, previous)
    }
}

pub(crate) fn extension_string(cert: &Certificate, number: u8) -> Result<String> {
    let extension_oid = oid(&alloc::format!("1.3.6.1.4.1.57264.1.{number}"));
    let extension = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|e| e.extn_id == extension_oid)
        .ok_or(Error::Identity)?;
    Ok(Utf8StringRef::from_der(extension.extn_value.as_bytes())?
        .as_str()
        .into())
}

pub(crate) struct Identity {
    pub source_revision: String,
    pub git_ref: String,
    pub workflow: String,
}

pub(crate) fn identity(cert: &Certificate, policy: &crate::Policy) -> Result<Identity> {
    let git_ref = extension_string(cert, 14)?;
    if !policy.git_refs.contains(&git_ref) {
        return Err(Error::Identity);
    }
    let workflow = policy.workflow_identity(&git_ref);
    let sans = cert
        .tbs_certificate
        .get::<SubjectAltName>()?
        .ok_or(Error::Identity)?
        .1;
    if sans.0.len() != 1
        || !sans.0.iter().any(|n| {
            matches!(n,
        GeneralName::UniformResourceIdentifier(uri) if uri.as_str() == workflow)
        })
    {
        return Err(Error::Identity);
    }
    for (number, expected) in [
        (8, policy.oidc_issuer.as_str()),
        (9, workflow.as_str()),
        (12, policy.repository.as_str()),
        (18, workflow.as_str()),
        (20, policy.event_name.as_str()),
    ] {
        if extension_string(cert, number)? != expected {
            return Err(Error::Identity);
        }
    }
    for (number, expected) in [
        (11, policy.runner_environment.map(|e| e.as_str())),
        (15, policy.repository_id.as_deref()),
        (17, policy.repository_owner_id.as_deref()),
    ] {
        if let Some(expected) = expected {
            if extension_string(cert, number)? != expected {
                return Err(Error::Identity);
            }
        }
    }
    let revision = extension_string(cert, 13)?;
    if !crate::policy::valid_revision(&revision)
        || extension_string(cert, 10)? != revision
        || extension_string(cert, 19)? != revision
        || policy
            .source_revision
            .as_ref()
            .is_some_and(|expected| expected != &revision)
    {
        return Err(Error::Identity);
    }
    Ok(Identity {
        source_revision: revision,
        git_ref,
        workflow,
    })
}

#[cfg(test)]
pub(crate) fn test_roots() -> (TrustedRoot, p384::ecdsa::SigningKey) {
    use der::asn1::BitString;
    let mut roots =
        TrustedRoot::from_json(include_bytes!("../tests/fixtures/github-trusted-root.json"))
            .unwrap();
    let key = p384::ecdsa::SigningKey::from_slice(&[7; 48]).unwrap();
    for authority in roots.fulcio.iter_mut().chain(roots.tsa.iter_mut()) {
        for cert in &mut authority.chain {
            cert.tbs_certificate
                .subject_public_key_info
                .subject_public_key =
                BitString::from_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
                    .unwrap();
            test_sign(cert, &key);
        }
    }
    (roots, key)
}

#[cfg(test)]
pub(crate) fn test_sign(cert: &mut Certificate, key: &p384::ecdsa::SigningKey) {
    use p384::ecdsa::{Signature, signature::Signer};
    cert.tbs_certificate.signature = x509_cert::spki::AlgorithmIdentifierOwned {
        oid: oid("1.2.840.10045.4.3.3"),
        parameters: None,
    };
    cert.signature_algorithm = cert.tbs_certificate.signature.clone();
    let signature: Signature = key.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::OctetString;
    use x509_cert::ext::{AsExtension, Extension};

    fn leaf(key: &p384::ecdsa::SigningKey) -> Certificate {
        let bundle: crate::Bundle =
            serde_json::from_slice(include_bytes!("../tests/fixtures/provenance.sigstore.json"))
                .unwrap();
        let mut leaf =
            parse(&crypto::b64(&bundle.verification_material.certificate.raw_bytes).unwrap())
                .unwrap();
        test_sign(&mut leaf, key);
        leaf
    }

    #[test]
    fn configured_workflow_identity_accepts_a_different_authenticated_source() {
        use crate::{Policy, RunnerEnvironment};
        let (roots, key) = test_roots();
        let mut cert = leaf(&key);
        let policy = Policy::builder()
            .repository("example/project")
            .workflow_path(".github/workflows/build.yaml")
            .branch("release/1.x")
            .artifact_name("package.tar.gz")
            .not_after(1_792_627_200)
            .event_name("workflow_dispatch")
            .oidc_issuer("https://example.com/oidc")
            .runner_environment(RunnerEnvironment::GitHubHosted)
            .repository_id("123")
            .repository_owner_id("456")
            .build()
            .unwrap();
        let workflow = policy.workflow_identity("refs/heads/release/1.x");
        let sans = SubjectAltName(alloc::vec![GeneralName::UniformResourceIdentifier(
            der::asn1::Ia5String::new(&workflow).unwrap(),
        )]);
        let san = sans
            .to_extension(&cert.tbs_certificate.subject, &[])
            .unwrap();
        *cert
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id == oid("2.5.29.17"))
            .unwrap() = san;
        for (number, value) in [
            (8, policy.oidc_issuer()),
            (9, workflow.as_str()),
            (11, "github-hosted"),
            (12, policy.repository()),
            (14, "refs/heads/release/1.x"),
            (15, "123"),
            (17, "456"),
            (18, workflow.as_str()),
            (20, "workflow_dispatch"),
        ] {
            let id = oid(&alloc::format!("1.3.6.1.4.1.57264.1.{number}"));
            let extension = cert
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .iter_mut()
                .find(|e| e.extn_id == id)
                .unwrap();
            extension.extn_value =
                OctetString::new(Utf8StringRef::new(value).unwrap().to_der().unwrap()).unwrap();
        }
        test_sign(&mut cert, &key);
        roots
            .fulcio
            .last()
            .unwrap()
            .verify(&cert, 1_792_538_002, CODE_SIGNING)
            .unwrap();
        let checked = identity(&cert, &policy).unwrap();
        assert_eq!(checked.git_ref, "refs/heads/release/1.x");
        assert_eq!(checked.workflow, workflow);
        let wrong = policy.to_builder().branch("other").build().unwrap();
        assert!(matches!(identity(&cert, &wrong), Err(Error::Identity)));
    }

    #[test]
    fn signed_paths_enforce_time_usage_issuer_and_path_length() {
        let (roots, key) = test_roots();
        let leaf = leaf(&key);
        let authority = roots.fulcio.last().unwrap();
        let time = 1_792_538_002;
        authority.verify(&leaf, time, CODE_SIGNING).unwrap();
        assert!(authority.verify(&leaf, 1, CODE_SIGNING).is_err());
        assert!(authority.verify(&leaf, time + 3600, CODE_SIGNING).is_err());
        assert!(authority.verify(&leaf, time, TIMESTAMPING).is_err());

        let mut bad = leaf.clone();
        bad.tbs_certificate.issuer = Default::default();
        test_sign(&mut bad, &key);
        assert!(authority.verify(&bad, time, CODE_SIGNING).is_err());

        let mut bad = leaf.clone();
        let mut usage = bad.tbs_certificate.get::<KeyUsage>().unwrap().unwrap().1;
        usage.0 = x509_cert::ext::pkix::KeyUsages::KeyCertSign.into();
        let extension = usage
            .to_extension(&bad.tbs_certificate.subject, &[])
            .unwrap();
        *bad.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id == oid("2.5.29.15"))
            .unwrap() = extension;
        test_sign(&mut bad, &key);
        assert!(authority.verify(&bad, time, CODE_SIGNING).is_err());

        let (mut roots, key) = test_roots();
        let authority = roots.fulcio.last_mut().unwrap();
        let root = authority.chain.last_mut().unwrap();
        let constraint = BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        };
        let extension = constraint
            .to_extension(&root.tbs_certificate.subject, &[])
            .unwrap();
        *root
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id == oid("2.5.29.19"))
            .unwrap() = extension;
        test_sign(root, &key);
        assert!(authority.verify(&leaf, time, CODE_SIGNING).is_err());
    }

    #[test]
    fn certificate_extensions_fail_closed() {
        let (_, key) = test_roots();
        let mut cert = leaf(&key);
        let extension = cert.tbs_certificate.extensions.as_ref().unwrap()[0].clone();
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(extension);
        assert!(matches!(
            parse(&cert.to_der().unwrap()),
            Err(Error::Encoding)
        ));
        for (oid_string, critical) in [("1.2.3.4.5", true), ("2.5.29.30", false)] {
            let mut cert = leaf(&key);
            cert.tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .push(Extension {
                    extn_id: oid(oid_string),
                    critical,
                    extn_value: OctetString::new([]).unwrap(),
                });
            assert!(matches!(
                parse(&cert.to_der().unwrap()),
                Err(Error::Unsupported)
            ));
        }
    }
}
