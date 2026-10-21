//! The RFC 3161 / CMS subset emitted by GitHub's timestamp service.
//! ASN.1 parsing and DER canonicalization are provided by RustCrypto `der`.
use crate::{
    Error,
    certificate::{Authority, TIMESTAMPING},
    crypto::{self, oid},
    error::Result,
};
use alloc::vec::Vec;
use der::{
    Decode, Encode, Sequence, ValueOrd,
    asn1::{Any, BitString, GeneralizedTime, ObjectIdentifier, OctetString, SetOfVec, Uint},
};
use x509_cert::{
    attr::Attributes,
    ext::pkix::{
        SubjectAltName,
        name::{GeneralName, GeneralNames},
    },
    name::Name,
    serial_number::SerialNumber,
    spki::AlgorithmIdentifierOwned,
};

const SIGNED_DATA: ObjectIdentifier = oid("1.2.840.113549.1.7.2");
const TST_INFO: ObjectIdentifier = oid("1.2.840.113549.1.9.16.1.4");

#[derive(Clone, Debug, Sequence)]
struct Response {
    status: Status,
    token: ContentInfo,
}
#[derive(Clone, Debug, Sequence)]
struct Status {
    status: u8,
    status_string: Option<Vec<alloc::string::String>>,
    fail_info: Option<BitString>,
}
#[derive(Clone, Debug, Sequence)]
struct ContentInfo {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    content: SignedData,
}
#[derive(Clone, Debug, Sequence)]
struct SignedData {
    version: u8,
    digest_algorithms: SetOfVec<AlgorithmIdentifierOwned>,
    content: EncapsulatedContent,
    // Embedded certificates are never used: only a pinned TSA leaf can sign.
    // The GitHub profile rejects them; the public instance always embeds them.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    certificates: Option<SetOfVec<Any>>,
    signer_infos: SetOfVec<SignerInfo>,
}
#[derive(Clone, Debug, Sequence)]
struct EncapsulatedContent {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    content: OctetString,
}
#[derive(Clone, Debug, Sequence, ValueOrd)]
struct SignerInfo {
    version: u8,
    sid: IssuerSerial,
    digest_algorithm: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    signed_attributes: Attributes,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: OctetString,
}
#[derive(Clone, Debug, PartialEq, Eq, Sequence, ValueOrd)]
struct IssuerSerial {
    issuer: Name,
    serial: SerialNumber,
}
#[derive(Clone, Debug, Sequence)]
struct TstInfo {
    version: u8,
    policy: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial: Uint,
    gen_time: GeneralizedTime,
    accuracy: Option<Accuracy>,
    #[asn1(default = "Default::default")]
    ordering: bool,
    nonce: Option<Uint>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    tsa: Option<GeneralName>,
}
#[derive(Clone, Debug, Sequence)]
struct Accuracy {
    seconds: Option<u64>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    millis: Option<u16>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    micros: Option<u16>,
}
#[derive(Clone, Debug, Sequence)]
struct MessageImprint {
    algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}
#[derive(Clone, Debug, Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertId>,
}
#[derive(Clone, Debug, Sequence)]
struct EssCertId {
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    issuer_serial: Option<EssIssuerSerial>,
}
#[derive(Clone, Debug, Sequence)]
struct EssIssuerSerial {
    issuer: GeneralNames,
    serial: SerialNumber,
}

/// Authenticates timestamp contents before returning any time from the token.
pub(crate) fn verify(
    bytes: &[u8],
    signature: &[u8],
    authorities: &[Authority],
    now: u64,
    embedded_certificates: bool,
) -> Result<u64> {
    if bytes.len() > 32 * 1024 {
        return Err(Error::Limit);
    }
    let response = Response::from_der(bytes)?;
    let data = &response.token.content;
    if !matches!(response.status.status, 0 | 1)
        || response
            .status
            .status_string
            .as_ref()
            .is_some_and(|text| text.is_empty())
        || response.status.fail_info.is_some()
        || response.token.content_type != SIGNED_DATA
        || data.version != 3
        || data.content.content_type != TST_INFO
        || data.signer_infos.len() != 1
        || data.digest_algorithms.len() != 1
        || (!embedded_certificates && data.certificates.as_ref().is_some_and(|c| !c.is_empty()))
    {
        return Err(Error::Unsupported);
    }
    let signer = data.signer_infos.get(0).ok_or(Error::Encoding)?;
    if signer.version != 1 || data.digest_algorithms.get(0) != Some(&signer.digest_algorithm) {
        return Err(Error::Unsupported);
    }
    let sha256 = oid("2.16.840.1.101.3.4.2.1");
    let sha384 = oid("2.16.840.1.101.3.4.2.2");
    if !((signer.signature_algorithm.oid == oid("1.2.840.10045.4.3.2")
        && signer.digest_algorithm.oid == sha256)
        || (signer.signature_algorithm.oid == oid("1.2.840.10045.4.3.3")
            && signer.digest_algorithm.oid == sha384))
    {
        return Err(Error::Unsupported);
    }
    let attributes = &signer.signed_attributes;
    // Enforce uniqueness for every attribute, including ones we do not consume.
    for (i, attribute) in attributes.iter().enumerate() {
        if attributes.iter().take(i).any(|a| a.oid == attribute.oid) || attribute.values.len() != 1
        {
            return Err(Error::Encoding);
        }
        if ![
            "1.2.840.113549.1.9.3",
            "1.2.840.113549.1.9.4",
            "1.2.840.113549.1.9.5",
            "1.2.840.113549.1.9.16.2.47",
        ]
        .iter()
        .any(|s| attribute.oid == oid(s))
        {
            return Err(Error::Unsupported);
        }
    }
    let attribute = |name: &str| -> Result<&Any> {
        attributes
            .iter()
            .find(|a| a.oid == oid(name))
            .and_then(|a| a.values.get(0))
            .ok_or(Error::Timestamp)
    };
    if attribute("1.2.840.113549.1.9.3")?.decode_as::<ObjectIdentifier>()? != TST_INFO
        || attribute("1.2.840.113549.1.9.4")?
            .decode_as::<OctetString>()?
            .as_bytes()
            != crypto::hash(&signer.digest_algorithm, data.content.content.as_bytes())?
    {
        return Err(Error::Timestamp);
    }
    let binding = attribute("1.2.840.113549.1.9.16.2.47")?.decode_as::<SigningCertificateV2>()?;
    if binding.certs.len() != 1 {
        return Err(Error::Unsupported);
    }
    let binding = &binding.certs[0];
    let binding_hash = binding
        .hash_algorithm
        .clone()
        .unwrap_or(AlgorithmIdentifierOwned {
            oid: sha256,
            parameters: None,
        });
    let signed_bytes = attributes.to_der()?; // RFC 5652: SET tag, not the IMPLICIT [0] tag.
    let info = TstInfo::from_der(data.content.content.as_bytes())?;
    let time = info.gen_time.to_unix_duration().as_secs();
    if info.version != 1
        || time > now
        || crypto::hash(&info.message_imprint.algorithm, signature)?
            != info.message_imprint.hashed_message.as_bytes()
    {
        return Err(Error::Timestamp);
    }
    if let Some(accuracy) = info.accuracy {
        // GitHub currently declares one-second accuracy. Bound the supported
        // profile; certificate validity uses RFC 3161's nominal genTime.
        if accuracy.seconds.is_some_and(|s| s > 1)
            || accuracy.millis.is_some_and(|n| !(1..=999).contains(&n))
            || accuracy.micros.is_some_and(|n| !(1..=999).contains(&n))
        {
            return Err(Error::Unsupported);
        }
    }
    for authority in authorities {
        let leaf = &authority.chain[0];
        if signer.sid.issuer != leaf.tbs_certificate.issuer
            || signer.sid.serial != leaf.tbs_certificate.serial_number
        {
            continue;
        }
        if binding.cert_hash.as_bytes() != crypto::hash(&binding_hash, &leaf.to_der()?)? {
            continue;
        }
        if let Some(id) = &binding.issuer_serial {
            if id.serial != leaf.tbs_certificate.serial_number
                || id.issuer.as_slice()
                    != [GeneralName::DirectoryName(
                        leaf.tbs_certificate.issuer.clone(),
                    )]
            {
                continue;
            }
        }
        if let Some(tsa) = &info.tsa {
            let subject = GeneralName::DirectoryName(leaf.tbs_certificate.subject.clone());
            let san_matches = leaf
                .tbs_certificate
                .get::<SubjectAltName>()?
                .is_some_and(|(_, sans)| sans.0.contains(tsa));
            if tsa != &subject && !san_matches {
                continue;
            }
        }
        if authority.verify(leaf, time, TIMESTAMPING).is_ok()
            && crypto::verify(
                &leaf.tbs_certificate.subject_public_key_info,
                &signer.signature_algorithm,
                &signed_bytes,
                signer.signature.as_bytes(),
            )
            .is_ok()
        {
            return Ok(time);
        }
    }
    Err(Error::Trust)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustedRoot;

    fn fixture() -> (Response, Vec<u8>) {
        let bundle: crate::Bundle =
            serde_json::from_slice(include_bytes!("../tests/fixtures/provenance.sigstore.json"))
                .unwrap();
        let encoded = &bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps[0]
            .signed_timestamp;
        (
            Response::from_der(&crypto::b64(encoded).unwrap()).unwrap(),
            crypto::b64(&bundle.dsse_envelope.signatures[0].sig).unwrap(),
        )
    }

    fn resign(
        response: &mut Response,
        roots: &TrustedRoot,
        key: &p384::ecdsa::SigningKey,
        bind: bool,
    ) {
        use p384::ecdsa::{Signature, signature::Signer};
        let data = &mut response.token.content;
        let mut signer = data.signer_infos.get(0).unwrap().clone();
        let mut attributes: Vec<_> = signer.signed_attributes.iter().cloned().collect();
        for attribute in &mut attributes {
            if attribute.oid == oid("1.2.840.113549.1.9.4") {
                let digest =
                    crypto::hash(&signer.digest_algorithm, data.content.content.as_bytes())
                        .unwrap();
                let value =
                    Any::from_der(&OctetString::new(digest).unwrap().to_der().unwrap()).unwrap();
                attribute.values = SetOfVec::try_from(alloc::vec![value]).unwrap();
            }
            if bind && attribute.oid == oid("1.2.840.113549.1.9.16.2.47") {
                let mut binding = attribute
                    .values
                    .get(0)
                    .unwrap()
                    .decode_as::<SigningCertificateV2>()
                    .unwrap();
                let leaf = &roots.tsa.last().unwrap().chain[0];
                let algorithm = AlgorithmIdentifierOwned {
                    oid: oid("2.16.840.1.101.3.4.2.1"),
                    parameters: None,
                };
                binding.certs[0].cert_hash =
                    OctetString::new(crypto::hash(&algorithm, &leaf.to_der().unwrap()).unwrap())
                        .unwrap();
                attribute.values = SetOfVec::try_from(alloc::vec![
                    Any::from_der(&binding.to_der().unwrap()).unwrap()
                ])
                .unwrap();
            }
        }
        signer.signed_attributes = SetOfVec::try_from(attributes).unwrap();
        let signature: Signature = key.sign(&signer.signed_attributes.to_der().unwrap());
        signer.signature = OctetString::new(signature.to_der().as_bytes()).unwrap();
        data.signer_infos = SetOfVec::try_from(alloc::vec![signer]).unwrap();
    }

    #[test]
    fn authenticated_timestamp_imprint_and_certificate_binding_are_required() {
        let (roots, key) = crate::certificate::test_roots();
        let (mut response, signature) = fixture();
        resign(&mut response, &roots, &key, true);
        verify(
            &response.to_der().unwrap(),
            &signature,
            &roots.tsa,
            1_792_627_200,
            false,
        )
        .unwrap();

        let (mut wrong_binding, _) = fixture();
        resign(&mut wrong_binding, &roots, &key, false);
        assert_eq!(
            verify(
                &wrong_binding.to_der().unwrap(),
                &signature,
                &roots.tsa,
                1_792_627_200,
                false
            ),
            Err(Error::Trust)
        );

        // The token is correctly signed by a trusted TSA but timestamps a different signature.
        let mut info =
            TstInfo::from_der(response.token.content.content.content.as_bytes()).unwrap();
        info.message_imprint.hashed_message = OctetString::new([0u8; 32]).unwrap();
        response.token.content.content.content = OctetString::new(info.to_der().unwrap()).unwrap();
        resign(&mut response, &roots, &key, true);
        assert_eq!(
            verify(
                &response.to_der().unwrap(),
                &signature,
                &roots.tsa,
                1_792_627_200,
                false
            ),
            Err(Error::Timestamp)
        );
    }

    #[test]
    fn changing_authenticated_time_or_content_digest_breaks_verification() {
        let (roots, key) = crate::certificate::test_roots();
        let (mut response, signature) = fixture();
        resign(&mut response, &roots, &key, true);
        let mut info =
            TstInfo::from_der(response.token.content.content.content.as_bytes()).unwrap();
        info.gen_time =
            GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(1_792_538_003))
                .unwrap();
        response.token.content.content.content = OctetString::new(info.to_der().unwrap()).unwrap();
        assert_eq!(
            verify(
                &response.to_der().unwrap(),
                &signature,
                &roots.tsa,
                1_792_627_200,
                false
            ),
            Err(Error::Timestamp)
        );

        // Updating messageDigest without the corresponding CMS signature must also fail.
        let mut signer = response.token.content.signer_infos.get(0).unwrap().clone();
        let old_signature = signer.signature.clone();
        resign(&mut response, &roots, &key, true);
        signer = response.token.content.signer_infos.get(0).unwrap().clone();
        signer.signature = old_signature;
        response.token.content.signer_infos = SetOfVec::try_from(alloc::vec![signer]).unwrap();
        assert_eq!(
            verify(
                &response.to_der().unwrap(),
                &signature,
                &roots.tsa,
                1_792_627_200,
                false
            ),
            Err(Error::Trust)
        );
    }

    #[test]
    fn github_timestamp_der_profile() {
        let (response, _) = fixture();
        let info = TstInfo::from_der(response.token.content.content.content.as_bytes()).unwrap();
        assert_eq!(info.version, 1);
        let attributes = &response
            .token
            .content
            .signer_infos
            .get(0)
            .unwrap()
            .signed_attributes;
        let binding = attributes
            .iter()
            .find(|a| a.oid == oid("1.2.840.113549.1.9.16.2.47"))
            .unwrap();
        binding
            .values
            .get(0)
            .unwrap()
            .decode_as::<SigningCertificateV2>()
            .unwrap();
    }

    #[test]
    fn granted_with_mods_and_status_text_keep_the_signed_token_valid() {
        let roots =
            TrustedRoot::from_json(include_bytes!("../tests/fixtures/github-trusted-root.json"))
                .unwrap();
        let (mut response, signature) = fixture();
        response.status.status = 1;
        response.status.status_string = Some(alloc::vec!["request modified".into()]);
        verify(
            &response.to_der().unwrap(),
            &signature,
            &roots.tsa,
            1_792_627_200,
            false,
        )
        .unwrap();
    }

    #[test]
    fn embedded_certificates_are_profile_dependent_and_never_trusted() {
        let roots =
            TrustedRoot::from_json(include_bytes!("../tests/fixtures/github-trusted-root.json"))
                .unwrap();
        let (mut response, signature) = fixture();
        let leaf = Any::from_der(&roots.tsa[0].chain[0].to_der().unwrap()).unwrap();
        response.token.content.certificates = Some(SetOfVec::try_from(alloc::vec![leaf]).unwrap());
        let der = response.to_der().unwrap();
        assert_eq!(
            verify(&der, &signature, &roots.tsa, 1_792_627_200, false),
            Err(Error::Unsupported)
        );
        verify(&der, &signature, &roots.tsa, 1_792_627_200, true).unwrap();
        // An embedded certificate does not stand in for a pinned authority.
        assert_eq!(
            verify(&der, &signature, &[], 1_792_627_200, true),
            Err(Error::Trust)
        );
    }

    #[test]
    fn signed_tsa_name_must_match_the_pinned_certificate() {
        let (roots, key) = crate::certificate::test_roots();
        let (mut response, signature) = fixture();
        let tsa_subject = roots.tsa.last().unwrap().chain[0]
            .tbs_certificate
            .subject
            .clone();
        let mut info =
            TstInfo::from_der(response.token.content.content.content.as_bytes()).unwrap();
        info.tsa = Some(GeneralName::DirectoryName(tsa_subject));
        response.token.content.content.content = OctetString::new(info.to_der().unwrap()).unwrap();
        resign(&mut response, &roots, &key, true);
        verify(
            &response.to_der().unwrap(),
            &signature,
            &roots.tsa,
            1_792_627_200,
            false,
        )
        .unwrap();

        info.tsa = Some(GeneralName::UniformResourceIdentifier(
            der::asn1::Ia5String::new("https://attacker.example/tsa").unwrap(),
        ));
        response.token.content.content.content = OctetString::new(info.to_der().unwrap()).unwrap();
        resign(&mut response, &roots, &key, true);
        assert_eq!(
            verify(
                &response.to_der().unwrap(),
                &signature,
                &roots.tsa,
                1_792_627_200,
                false,
            ),
            Err(Error::Trust)
        );
    }
}
