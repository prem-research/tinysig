use crate::{Error, error::Result};
use alloc::{string::String, vec::Vec};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use der::asn1::ObjectIdentifier;
use p256::ecdsa::signature::Verifier;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

pub(crate) const fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}

pub(crate) fn b64(s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .map_err(|_| Error::Encoding)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                DIGITS[(b >> 4) as usize] as char,
                DIGITS[(b & 15) as usize] as char,
            ]
        })
        .collect()
}

pub(crate) fn hash(algorithm: &AlgorithmIdentifierOwned, data: &[u8]) -> Result<Vec<u8>> {
    // RFC 5754 permits absent parameters and NULL for SHA-2 digest identifiers.
    if algorithm
        .parameters
        .as_ref()
        .is_some_and(|p| p != &der::asn1::Any::null())
    {
        return Err(Error::Unsupported);
    }
    match algorithm.oid {
        x if x == oid("2.16.840.1.101.3.4.2.1") => Ok(Sha256::digest(data).to_vec()),
        x if x == oid("2.16.840.1.101.3.4.2.2") => Ok(Sha384::digest(data).to_vec()),
        x if x == oid("2.16.840.1.101.3.4.2.3") => Ok(Sha512::digest(data).to_vec()),
        _ => Err(Error::Unsupported),
    }
}

pub(crate) fn verify(
    key: &SubjectPublicKeyInfoOwned,
    algorithm: &AlgorithmIdentifierOwned,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    if key.algorithm.oid != oid("1.2.840.10045.2.1") || algorithm.parameters.is_some() {
        return Err(Error::Unsupported);
    }
    let curve = key
        .algorithm
        .parameters
        .as_ref()
        .ok_or(Error::Unsupported)?
        .decode_as::<ObjectIdentifier>()?;
    let bytes = key.subject_public_key.as_bytes().ok_or(Error::Encoding)?;
    if curve == oid("1.2.840.10045.3.1.7") && algorithm.oid == oid("1.2.840.10045.4.3.2") {
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::Encoding)?;
        let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| Error::Encoding)?;
        key.verify(message, &sig).map_err(|_| Error::Signature)
    } else if curve == oid("1.3.132.0.34") && algorithm.oid == oid("1.2.840.10045.4.3.3") {
        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::Encoding)?;
        let sig = p384::ecdsa::Signature::from_der(signature).map_err(|_| Error::Encoding)?;
        key.verify(message, &sig).map_err(|_| Error::Signature)
    } else if curve == oid("1.3.132.0.34") && algorithm.oid == oid("1.2.840.10045.4.3.2") {
        // The public Sigstore TSA signs with P-384 over a SHA-256 digest.
        use p384::ecdsa::signature::hazmat::PrehashVerifier;
        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::Encoding)?;
        let sig = p384::ecdsa::Signature::from_der(signature).map_err(|_| Error::Encoding)?;
        key.verify_prehash(&Sha256::digest(message), &sig)
            .map_err(|_| Error::Signature)
    } else {
        Err(Error::Unsupported)
    }
}

pub(crate) fn ecdsa_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: oid("1.2.840.10045.4.3.2"),
        parameters: None,
    }
}

/// Verify a P-256 signature over an already-computed SHA-256 digest.
pub(crate) fn verify_p256_prehash(
    key: &SubjectPublicKeyInfoOwned,
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    if key.algorithm.oid != oid("1.2.840.10045.2.1")
        || key
            .algorithm
            .parameters
            .as_ref()
            .ok_or(Error::Unsupported)?
            .decode_as::<ObjectIdentifier>()?
            != oid("1.2.840.10045.3.1.7")
    {
        return Err(Error::Unsupported);
    }
    let bytes = key.subject_public_key.as_bytes().ok_or(Error::Encoding)?;
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::Encoding)?;
    let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| Error::Encoding)?;
    key.verify_prehash(digest, &sig)
        .map_err(|_| Error::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};

    fn algorithm(id: &str, parameters: Option<der::asn1::Any>) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: oid(id),
            parameters,
        }
    }

    #[test]
    fn digest_dispatch_matches_each_oid_exactly() {
        let data = b"digest me";
        assert_eq!(
            hash(&algorithm("2.16.840.1.101.3.4.2.1", None), data).unwrap(),
            Sha256::digest(data).to_vec()
        );
        assert_eq!(
            hash(&algorithm("2.16.840.1.101.3.4.2.2", None), data).unwrap(),
            Sha384::digest(data).to_vec()
        );
        assert_eq!(
            hash(&algorithm("2.16.840.1.101.3.4.2.3", None), data).unwrap(),
            Sha512::digest(data).to_vec()
        );
        assert_eq!(
            hash(
                &algorithm("2.16.840.1.101.3.4.2.2", Some(der::asn1::Any::null())),
                data
            )
            .unwrap(),
            Sha384::digest(data).to_vec()
        );
        for id in [
            "2.16.840.1.101.3.4.2.4",
            "1.3.14.3.2.26",
            "2.16.840.1.101.3.4.2.20",
        ] {
            assert_eq!(
                hash(&algorithm(id, None), data),
                Err(Error::Unsupported),
                "{id}"
            );
        }
        let not_null =
            der::asn1::Any::from_der(&der::asn1::OctetString::new([1]).unwrap().to_der().unwrap())
                .unwrap();
        assert_eq!(
            hash(&algorithm("2.16.840.1.101.3.4.2.1", Some(not_null)), data),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn signature_verification_rejects_foreign_keys_and_parameters() {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};
        let signer = SigningKey::from_slice(&[3; 32]).unwrap();
        let signature: Signature = signer.sign(b"m");
        let signature = signature.to_der();
        let curve =
            der::asn1::Any::from_der(&oid("1.2.840.10045.3.1.7").to_der().unwrap()).unwrap();
        let key = |algorithm: AlgorithmIdentifierOwned| SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key: der::asn1::BitString::from_bytes(
                signer.verifying_key().to_encoded_point(false).as_bytes(),
            )
            .unwrap(),
        };
        let ec = key(algorithm("1.2.840.10045.2.1", Some(curve.clone())));
        verify(&ec, &ecdsa_sha256(), b"m", signature.as_bytes()).unwrap();
        verify_p256_prehash(&ec, &Sha256::digest(b"m").into(), signature.as_bytes()).unwrap();
        // An RSA key OID with an EC point, and an EC key without a named curve.
        let rsa = key(algorithm("1.2.840.113549.1.1.1", Some(curve.clone())));
        assert_eq!(
            verify(&rsa, &ecdsa_sha256(), b"m", signature.as_bytes()),
            Err(Error::Unsupported)
        );
        assert_eq!(
            verify_p256_prehash(&rsa, &Sha256::digest(b"m").into(), signature.as_bytes()),
            Err(Error::Unsupported)
        );
        let no_curve = key(algorithm("1.2.840.10045.2.1", None));
        assert_eq!(
            verify(&no_curve, &ecdsa_sha256(), b"m", signature.as_bytes()),
            Err(Error::Unsupported)
        );
        assert_eq!(
            verify_p256_prehash(
                &no_curve,
                &Sha256::digest(b"m").into(),
                signature.as_bytes()
            ),
            Err(Error::Unsupported)
        );
        // Signature algorithm parameters are never allowed for ECDSA.
        let with_parameters = algorithm("1.2.840.10045.4.3.2", Some(der::asn1::Any::null()));
        assert_eq!(
            verify(&ec, &with_parameters, b"m", signature.as_bytes()),
            Err(Error::Unsupported)
        );
        // Curve and algorithm must pair: P-256 with SHA-384, or a P-384 point as P-256.
        assert_eq!(
            verify(
                &ec,
                &algorithm("1.2.840.10045.4.3.3", None),
                b"m",
                signature.as_bytes()
            ),
            Err(Error::Unsupported)
        );
        let p384 = der::asn1::Any::from_der(&oid("1.3.132.0.34").to_der().unwrap()).unwrap();
        let mislabelled = key(algorithm("1.2.840.10045.2.1", Some(p384)));
        assert_eq!(
            verify(&mislabelled, &ecdsa_sha256(), b"m", signature.as_bytes()),
            Err(Error::Encoding)
        );
        assert_eq!(
            verify_p256_prehash(
                &mislabelled,
                &Sha256::digest(b"m").into(),
                signature.as_bytes()
            ),
            Err(Error::Unsupported)
        );
        assert_eq!(
            verify(&ec, &ecdsa_sha256(), b"other", signature.as_bytes()),
            Err(Error::Signature)
        );

        // P-384 keys pair with SHA-384, or with SHA-256 for the public TSA; nothing else.
        use p384::ecdsa::signature::hazmat::PrehashSigner;
        let signer384 = p384::ecdsa::SigningKey::from_slice(&[4; 48]).unwrap();
        let p384_curve = der::asn1::Any::from_der(&oid("1.3.132.0.34").to_der().unwrap()).unwrap();
        let key384 = SubjectPublicKeyInfoOwned {
            algorithm: algorithm("1.2.840.10045.2.1", Some(p384_curve)),
            subject_public_key: der::asn1::BitString::from_bytes(
                signer384.verifying_key().to_encoded_point(false).as_bytes(),
            )
            .unwrap(),
        };
        let sha384: p384::ecdsa::Signature = signer384.sign(b"m");
        let sha384 = sha384.to_der();
        let sha256: p384::ecdsa::Signature = signer384.sign_prehash(&Sha256::digest(b"m")).unwrap();
        let sha256 = sha256.to_der();
        verify(
            &key384,
            &algorithm("1.2.840.10045.4.3.3", None),
            b"m",
            sha384.as_bytes(),
        )
        .unwrap();
        verify(&key384, &ecdsa_sha256(), b"m", sha256.as_bytes()).unwrap();
        assert_eq!(
            verify(&key384, &ecdsa_sha256(), b"m", sha384.as_bytes()),
            Err(Error::Signature)
        );
        for id in [
            "1.2.840.10045.4.3.4",
            "1.2.840.10045.4.3.1",
            "1.2.840.10045.4.1",
        ] {
            assert_eq!(
                verify(&key384, &algorithm(id, None), b"m", sha256.as_bytes()),
                Err(Error::Unsupported),
                "{id}"
            );
        }
        let secp256k1 = der::asn1::Any::from_der(&oid("1.3.132.0.10").to_der().unwrap()).unwrap();
        let foreign = key(algorithm("1.2.840.10045.2.1", Some(secp256k1)));
        assert_eq!(
            verify(&foreign, &ecdsa_sha256(), b"m", signature.as_bytes()),
            Err(Error::Unsupported)
        );
        assert_eq!(
            verify(
                &foreign,
                &algorithm("1.2.840.10045.4.3.3", None),
                b"m",
                signature.as_bytes()
            ),
            Err(Error::Unsupported)
        );
    }
}
