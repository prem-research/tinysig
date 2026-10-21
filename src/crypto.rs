use crate::{Error, error::Result};
use alloc::{string::String, vec::Vec};
use base64::{Engine, engine::general_purpose::STANDARD};
use der::asn1::ObjectIdentifier;
use p256::ecdsa::signature::Verifier;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

pub(crate) const fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}

pub(crate) fn b64(s: &str) -> Result<Vec<u8>> {
    STANDARD.decode(s).map_err(|_| Error::Encoding)
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
    } else {
        Err(Error::Unsupported)
    }
}
