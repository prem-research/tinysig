//! Rekor v1 and v2 entries: body binding, RFC 9162 Merkle inclusion, signed
//! checkpoints, and Rekor v1 signed entry timestamps (SETs).

use super::{Log, number};
use crate::{Error, crypto, error::Result};
use alloc::{format, string::String, vec::Vec};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// What the log entry must commit to, beyond the signature and certificate.
pub(super) enum Content {
    /// SHA-256 of the artifact for a message signature.
    Message([u8; 32]),
    /// SHA-256 of the DSSE payload and of its PAE encoding.
    Dsse { payload: [u8; 32], pae: [u8; 32] },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Entry {
    log_index: String,
    log_id: LogId,
    kind_version: KindVersion,
    integrated_time: Option<String>,
    inclusion_promise: Option<Promise>,
    inclusion_proof: Option<Proof>,
    canonicalized_body: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogId {
    key_id: String,
}
#[derive(Deserialize)]
struct KindVersion {
    kind: String,
    version: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Promise {
    signed_entry_timestamp: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Proof {
    log_index: String,
    root_hash: String,
    tree_size: String,
    hashes: Vec<String>,
    checkpoint: Checkpoint,
}
#[derive(Deserialize)]
struct Checkpoint {
    envelope: String,
}

/// Authenticate one entry against the log named by its `logId`. Returns that
/// log and, for a Rekor v1 entry with a valid SET, its integrated time.
pub(super) fn verify<'a>(
    entry: &Entry,
    logs: &'a [Log],
    leaf_der: &[u8],
    signature: &[u8],
    content: &Content,
) -> Result<(&'a Log, Option<u64>)> {
    // Only the declared log's key may authenticate the proof and promise.
    let id = crypto::b64(&entry.log_id.key_id)?;
    let log = logs.iter().find(|log| log.id == id).ok_or(Error::Trust)?;
    let body = crypto::b64(&entry.canonicalized_body)?;
    bind(&body, &entry.kind_version, leaf_der, signature, content)?;
    inclusion(
        entry.inclusion_proof.as_ref().ok_or(Error::Unsupported)?,
        &body,
        log,
    )?;
    let time = match &entry.inclusion_promise {
        // Rekor v2 entries carry neither integrated time nor promise.
        Some(_) if entry.kind_version.version != "0.0.1" => return Err(Error::Unsupported),
        Some(promise) => {
            let time = number(entry.integrated_time.as_deref().ok_or(Error::Encoding)?)?;
            let message = format!(
                r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
                entry.canonicalized_body,
                time,
                crypto::hex(&id),
                number(&entry.log_index)?,
            );
            log.verify(
                message.as_bytes(),
                &crypto::b64(&promise.signed_entry_timestamp)?,
            )?;
            Some(time)
        }
        None => None,
    };
    Ok((log, time))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Body {
    api_version: String,
    kind: String,
    spec: serde_json::Value,
}

/// The logged body must name this exact signature, certificate, and content.
fn bind(
    body: &[u8],
    declared: &KindVersion,
    leaf_der: &[u8],
    signature: &[u8],
    content: &Content,
) -> Result<()> {
    let body: Body = serde_json::from_slice(body)?;
    if body.api_version != declared.version || body.kind != declared.kind {
        return Err(Error::Trust);
    }
    let bound = match (body.kind.as_str(), body.api_version.as_str(), content) {
        ("hashedrekord", "0.0.1", Content::Message(digest)) => {
            let spec: HashedRekordV001 = serde_json::from_value(body.spec)?;
            spec.data.hash.algorithm == "sha256"
                && spec.data.hash.value == crypto::hex(digest)
                && crypto::b64(&spec.signature.content)? == signature
                && pem(&spec.signature.public_key.content)? == leaf_der
        }
        ("dsse", "0.0.1", Content::Dsse { payload, .. }) => {
            let spec: DsseV001 = serde_json::from_value(body.spec)?;
            let [logged] = spec.signatures.as_slice() else {
                return Err(Error::Unsupported);
            };
            spec.payload_hash.algorithm == "sha256"
                && spec.payload_hash.value == crypto::hex(payload)
                && crypto::b64(&logged.signature)? == signature
                && pem(&logged.verifier)? == leaf_der
        }
        ("hashedrekord", "0.0.2", content) => {
            let spec: HashedRekordV002 = serde_json::from_value(body.spec)?;
            let spec = spec.hashed_rekord_v002;
            let digest = match content {
                Content::Message(digest) => digest,
                Content::Dsse { pae, .. } => pae,
            };
            let verifier = &spec.signature.verifier;
            spec.data.algorithm == "SHA2_256"
                && crypto::b64(&spec.data.digest)? == digest
                && crypto::b64(&spec.signature.content)? == signature
                && verifier.key_details == "PKIX_ECDSA_P256_SHA_256"
                && crypto::b64(&verifier.x509_certificate.raw_bytes)? == leaf_der
        }
        _ => return Err(Error::Unsupported),
    };
    if !bound {
        return Err(Error::Trust);
    }
    Ok(())
}

/// Decode one Base64-wrapped PEM certificate, as Rekor v1 bodies store it.
fn pem(encoded: &str) -> Result<Vec<u8>> {
    let pem = crypto::b64(encoded)?;
    let text = core::str::from_utf8(&pem).map_err(|_| Error::Encoding)?;
    let inner = text
        .trim_end()
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|rest| rest.strip_suffix("-----END CERTIFICATE-----"))
        .ok_or(Error::Encoding)?;
    let compact: String = inner.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    crypto::b64(&compact)
}

fn node(left: &[u8], right: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update([1])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// RFC 9162 section 2.1.3.2 inclusion verification, then the signed checkpoint.
fn inclusion(proof: &Proof, body: &[u8], log: &Log) -> Result<()> {
    let index = number(&proof.log_index)?;
    let size = number(&proof.tree_size)?;
    let root: [u8; 32] = crypto::b64(&proof.root_hash)?
        .try_into()
        .map_err(|_| Error::Encoding)?;
    if proof.hashes.len() > 64 {
        return Err(Error::Limit);
    }
    if index >= size {
        return Err(Error::Trust);
    }
    let mut hash: [u8; 32] = Sha256::new()
        .chain_update([0])
        .chain_update(body)
        .finalize()
        .into();
    let (mut f, mut s) = (index, size - 1);
    for sibling in &proof.hashes {
        let sibling: [u8; 32] = crypto::b64(sibling)?
            .try_into()
            .map_err(|_| Error::Encoding)?;
        if s == 0 {
            return Err(Error::Trust);
        }
        if f & 1 == 1 || f == s {
            hash = node(&sibling, &hash);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            hash = node(&hash, &sibling);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 || hash != root {
        return Err(Error::Trust);
    }
    checkpoint(&proof.checkpoint.envelope, size, &root, log)
}

/// A C2SP signed note whose body commits to the proof's tree size and root.
/// Witness cosignatures are ignored; the declared log's signature is required.
fn checkpoint(note: &str, size: u64, root: &[u8; 32], log: &Log) -> Result<()> {
    if note.len() > 64 * 1024 {
        return Err(Error::Limit);
    }
    let split = note.find("\n\n").ok_or(Error::Encoding)?;
    let (text, signatures) = (&note[..=split], &note[split + 2..]);
    let mut lines = text.split_terminator('\n');
    let (Some(origin), Some(tree_size), Some(tree_root)) =
        (lines.next(), lines.next(), lines.next())
    else {
        return Err(Error::Encoding);
    };
    if origin.is_empty() || number(tree_size)? != size || crypto::b64(tree_root)? != root {
        return Err(Error::Trust);
    }
    let lines: Vec<&str> = signatures.split_terminator('\n').collect();
    if lines.is_empty() || lines.len() > 16 {
        return Err(Error::Limit);
    }
    let mut verified = false;
    for line in lines {
        let (_name, encoded) = line
            .strip_prefix("\u{2014} ")
            .and_then(|rest| rest.rsplit_once(' '))
            .ok_or(Error::Encoding)?;
        let signature = crypto::b64(encoded)?;
        // The four-byte key hint is the start of the log ID for Rekor logs.
        if signature.len() > 4
            && signature[..4] == log.id[..4]
            && log.verify(text.as_bytes(), &signature[4..]).is_ok()
        {
            verified = true;
        }
    }
    if !verified {
        return Err(Error::Signature);
    }
    Ok(())
}

#[derive(Deserialize)]
struct HashedRekordV001 {
    data: HashedData,
    signature: HashedSignature,
}
#[derive(Deserialize)]
struct HashedData {
    hash: HexHash,
}
#[derive(Deserialize)]
struct HexHash {
    algorithm: String,
    value: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HashedSignature {
    content: String,
    public_key: PemKey,
}
#[derive(Deserialize)]
struct PemKey {
    content: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DsseV001 {
    payload_hash: HexHash,
    signatures: Vec<DsseSignature>,
}
#[derive(Deserialize)]
struct DsseSignature {
    signature: String,
    verifier: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HashedRekordV002 {
    hashed_rekord_v002: HashedRekordSpec,
}
#[derive(Deserialize)]
struct HashedRekordSpec {
    data: B64Hash,
    signature: V002Signature,
}
#[derive(Deserialize)]
struct B64Hash {
    algorithm: String,
    digest: String,
}
#[derive(Deserialize)]
struct V002Signature {
    content: String,
    verifier: V002Verifier,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct V002Verifier {
    key_details: String,
    x509_certificate: crate::certificate::RawCertificate,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Root of a tree of `size` leaves, by RFC 9162 section 2.1.1.
    fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves.len() {
            1 => leaves[0],
            n => {
                let k = n.next_power_of_two() / 2;
                node(&root(&leaves[..k]), &root(&leaves[k..]))
            }
        }
    }

    fn path(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
        if leaves.len() == 1 {
            return Vec::new();
        }
        let k = leaves.len().next_power_of_two() / 2;
        let (mut proof, sibling) = if index < k {
            (path(index, &leaves[..k]), root(&leaves[k..]))
        } else {
            (path(index - k, &leaves[k..]), root(&leaves[..k]))
        };
        proof.push(sibling);
        proof
    }

    #[test]
    fn inclusion_proofs_for_every_leaf_of_small_trees() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let log = Log {
            id: alloc::vec![0; 32],
            key: super::super::LogKey::Ed25519(
                ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key(),
            ),
            start_ms: 0,
            end_ms: None,
        };
        let signer = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        for size in 1..=13usize {
            let bodies: Vec<Vec<u8>> = (0..size).map(|i| alloc::vec![i as u8; 3]).collect();
            let leaves: Vec<[u8; 32]> = bodies
                .iter()
                .map(|b| {
                    Sha256::new()
                        .chain_update([0])
                        .chain_update(b)
                        .finalize()
                        .into()
                })
                .collect();
            let tree_root = root(&leaves);
            let text = format!("test\n{size}\n{}\n", STANDARD.encode(tree_root));
            use ed25519_dalek::Signer;
            let mut signature = alloc::vec![0; 4];
            signature.extend_from_slice(&signer.sign(text.as_bytes()).to_bytes());
            let envelope = format!("{text}\n\u{2014} test {}\n", STANDARD.encode(signature));
            for (index, body) in bodies.iter().enumerate() {
                let proof = Proof {
                    log_index: format!("{index}"),
                    root_hash: STANDARD.encode(tree_root),
                    tree_size: format!("{size}"),
                    hashes: path(index, &leaves)
                        .iter()
                        .map(|h| STANDARD.encode(h))
                        .collect(),
                    checkpoint: Checkpoint {
                        envelope: envelope.clone(),
                    },
                };
                inclusion(&proof, body, &log).unwrap();
                assert!(inclusion(&proof, b"other", &log).is_err());
                let wrong_index = Proof {
                    log_index: format!("{}", (index + 1) % size),
                    ..proof
                };
                if size > 1 {
                    assert!(inclusion(&wrong_index, body, &log).is_err());
                }
            }
        }
    }
}
