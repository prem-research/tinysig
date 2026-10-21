//! RFC 6962 signed certificate timestamps embedded in Fulcio certificates.

use super::Log;
use crate::{Error, crypto::oid, error::Result};
use alloc::vec::Vec;
use der::{Decode, Encode, asn1::OctetString};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

const SCT_LIST: &str = "1.3.6.1.4.1.11129.2.4.2";

/// At least one embedded SCT must be signed by a pinned CT log valid at its time.
pub(super) fn verify(leaf: &Certificate, issuer: &Certificate, logs: &[Log]) -> Result<()> {
    let id = oid(SCT_LIST);
    let extensions = leaf
        .tbs_certificate
        .extensions
        .as_deref()
        .ok_or(Error::Trust)?;
    let extension = extensions
        .iter()
        .find(|e| e.extn_id == id && !e.critical)
        .ok_or(Error::Trust)?;
    // RFC 6962 section 3.2: the log signed the precertificate TBS, which is the
    // final TBS without the SCT list extension (and without the poison).
    let mut precert = leaf.tbs_certificate.clone();
    precert
        .extensions
        .as_mut()
        .ok_or(Error::Trust)?
        .retain(|e| e.extn_id != id);
    let tbs = precert.to_der()?;
    if tbs.len() > 0x00ff_ffff {
        return Err(Error::Limit);
    }
    let issuer_key_hash = Sha256::digest(issuer.tbs_certificate.subject_public_key_info.to_der()?);

    let list = OctetString::from_der(extension.extn_value.as_bytes())?;
    let mut list = Cursor(list.as_bytes());
    let total = usize::from(list.u16()?);
    if total == 0 || total != list.0.len() {
        return Err(Error::Encoding);
    }
    let mut count = 0;
    while !list.0.is_empty() {
        count += 1;
        if count > 16 {
            return Err(Error::Limit);
        }
        let len = usize::from(list.u16()?);
        let sct = list.take(len)?;
        if verify_one(sct, &issuer_key_hash, &tbs, logs).is_ok() {
            return Ok(());
        }
    }
    Err(Error::Trust)
}

fn verify_one(bytes: &[u8], issuer_key_hash: &[u8], tbs: &[u8], logs: &[Log]) -> Result<()> {
    let mut sct = Cursor(bytes);
    if sct.u8()? != 0 {
        return Err(Error::Unsupported);
    }
    let log_id = sct.take(32)?;
    let timestamp = sct.take(8)?;
    let ms = u64::from_be_bytes(timestamp.try_into().map_err(|_| Error::Encoding)?);
    let ext_len = sct.u16()?;
    let extensions = sct.take(usize::from(ext_len))?;
    if sct.u8()? != 4 || sct.u8()? != 3 {
        return Err(Error::Unsupported); // Only SHA-256 with ECDSA.
    }
    let sig_len = usize::from(sct.u16()?);
    let signature = sct.take(sig_len)?;
    if !sct.0.is_empty() {
        return Err(Error::Encoding);
    }
    let log = logs
        .iter()
        .find(|log| log.id == log_id && log.contains(ms))
        .ok_or(Error::Trust)?;
    let mut signed = Vec::with_capacity(47 + tbs.len() + extensions.len());
    signed.extend_from_slice(&[0, 0]); // v1, certificate_timestamp
    signed.extend_from_slice(timestamp);
    signed.extend_from_slice(&[0, 1]); // precert_entry
    signed.extend_from_slice(issuer_key_hash);
    signed.extend_from_slice(&(tbs.len() as u32).to_be_bytes()[1..]);
    signed.extend_from_slice(tbs);
    signed.extend_from_slice(&ext_len.to_be_bytes());
    signed.extend_from_slice(extensions);
    log.verify(&signed, signature)
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.0.len() {
            return Err(Error::Encoding);
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}
