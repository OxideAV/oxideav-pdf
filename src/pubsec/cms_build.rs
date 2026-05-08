//! Test-fixture-only CMS `EnvelopedData` builder.
//!
//! The PDF round-10 work is **decoder-side**: a real-world enterprise
//! PDF whose `/Encrypt /Filter` is one of `Adobe.PPKLite` /
//! `Entrust.PPKEF` carries a `Recipients` array of CMS objects we
//! need to parse. We don't have a public encoder yet — but we still
//! need fixtures whose CMS envelopes the round-10 reader can decrypt
//! end-to-end. This module is the symmetric writer side that
//! `tests/pubsec.rs` uses to construct those fixtures.
//!
//! It is *not* part of the public API. Module is `pub(crate)` and
//! only the test fixtures + the intra-crate parser unit tests reach
//! into it.
//!
//! Provenance: RFC 5652 §6 only.

use crate::error::PdfError;

use super::cms::{
    OID_AES128_CBC, OID_AES256_CBC, OID_DATA, OID_ENVELOPED_DATA, OID_RSA_ENCRYPTION,
};
use super::der::{
    write_context_constructed, write_context_primitive, write_integer_bytes, write_integer_u64,
    write_octet_string, write_oid, write_sequence, write_set,
};

/// One recipient slot to emit. The encrypted CEK is supplied
/// pre-wrapped — the caller is expected to have done the RSA
/// encryption against the recipient's public key.
#[derive(Debug, Clone)]
pub(crate) struct RecipientPlain {
    /// DER-encoded `issuer` Name, exactly as it appears in the
    /// recipient's certificate.
    pub(crate) issuer_der: Vec<u8>,
    /// Raw INTEGER body of the recipient's certificate serial number.
    pub(crate) serial: Vec<u8>,
    /// The RSA-PKCS1-v1.5-encrypted content-encryption key.
    pub(crate) encrypted_key: Vec<u8>,
}

/// Build an `EnvelopedData` ContentInfo for AES-128-CBC.
///
/// `cek` is the 16-byte AES-128 key the recipients can recover by
/// RSA-decrypting their `encrypted_key`. `iv` is the 16-byte CBC IV.
/// `plaintext` is the bytes to encapsulate (typically the 20-byte
/// seed + 4-byte permissions for ISO 32000-1 §7.6.4.3).
#[allow(dead_code)] // exercised via tests/pubsec.rs only
pub(crate) fn build_envelope_aes128(
    recipients: &[RecipientPlain],
    plaintext: &[u8],
    cek: &[u8; 16],
    iv: &[u8; 16],
) -> Vec<u8> {
    let encrypted = aes128_cbc_encrypt_padded(cek, iv, plaintext);
    build_envelope_inner(recipients, &OID_AES128_CBC, iv, &encrypted)
}

/// Build an `EnvelopedData` ContentInfo for AES-256-CBC.
pub(crate) fn build_envelope_aes256(
    recipients: &[RecipientPlain],
    plaintext: &[u8],
    cek: &[u8; 32],
    iv: &[u8; 16],
) -> Vec<u8> {
    let encrypted = aes256_cbc_encrypt_padded(cek, iv, plaintext);
    build_envelope_inner(recipients, &OID_AES256_CBC, iv, &encrypted)
}

fn build_envelope_inner(
    recipients: &[RecipientPlain],
    content_alg_oid: &[u64],
    iv: &[u8; 16],
    encrypted_content: &[u8],
) -> Vec<u8> {
    // 1) RecipientInfos: SET OF KeyTransRecipientInfo.
    let mut ri_set_body = Vec::new();
    for r in recipients {
        ri_set_body.extend_from_slice(&build_ktri(r));
    }
    let ri_set = write_set(&ri_set_body);

    // 2) EncryptedContentInfo.
    let alg_id = {
        let mut body = write_oid(content_alg_oid);
        body.extend_from_slice(&write_octet_string(iv));
        write_sequence(&body)
    };
    let eci = {
        let mut body = write_oid(&OID_DATA);
        body.extend_from_slice(&alg_id);
        // [0] IMPLICIT OCTET STRING: context-specific primitive.
        body.extend_from_slice(&write_context_primitive(0, encrypted_content));
        write_sequence(&body)
    };

    // 3) EnvelopedData = SEQUENCE { version=0, recipients, eci }.
    let enveloped_body = {
        let mut b = write_integer_u64(0);
        b.extend_from_slice(&ri_set);
        b.extend_from_slice(&eci);
        b
    };
    let enveloped = write_sequence(&enveloped_body);

    // 4) ContentInfo = SEQUENCE { contentType=envelopedData,
    //                              content [0] EXPLICIT EnvelopedData }.
    let outer_body = {
        let mut b = write_oid(&OID_ENVELOPED_DATA);
        b.extend_from_slice(&write_context_constructed(0, &enveloped));
        b
    };
    write_sequence(&outer_body)
}

fn build_ktri(r: &RecipientPlain) -> Vec<u8> {
    // KeyTransRecipientInfo = SEQUENCE {
    //   version 0,
    //   rid IssuerAndSerialNumber,
    //   keyEncryptionAlgorithm AlgorithmIdentifier,
    //   encryptedKey OCTET STRING
    // }
    let serial_int = write_integer_bytes(&r.serial);
    let ias_body = {
        let mut b = Vec::with_capacity(r.issuer_der.len() + serial_int.len());
        b.extend_from_slice(&r.issuer_der);
        b.extend_from_slice(&serial_int);
        b
    };
    let ias = write_sequence(&ias_body);
    let kea = {
        // RSAES-PKCS1-v1_5: AlgorithmIdentifier with NULL parameters.
        let mut b = write_oid(&OID_RSA_ENCRYPTION);
        b.extend_from_slice(&super::der::write_null());
        write_sequence(&b)
    };
    let mut body = write_integer_u64(0);
    body.extend_from_slice(&ias);
    body.extend_from_slice(&kea);
    body.extend_from_slice(&write_octet_string(&r.encrypted_key));
    write_sequence(&body)
}

// AES-CBC PKCS#7 helpers — narrow wrappers around `aes` + `cbc`.
fn aes128_cbc_encrypt_padded(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    type Enc = cbc::Encryptor<aes::Aes128>;
    let enc = Enc::new(key.into(), iv.into());
    let pad_block = (data.len() / 16) + 1;
    let mut buf = vec![0u8; pad_block * 16];
    let n = enc
        .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(data, &mut buf)
        .expect("PKCS7 padding")
        .len();
    buf.truncate(n);
    buf
}

fn aes256_cbc_encrypt_padded(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    type Enc = cbc::Encryptor<aes::Aes256>;
    let enc = Enc::new(key.into(), iv.into());
    let pad_block = (data.len() / 16) + 1;
    let mut buf = vec![0u8; pad_block * 16];
    let n = enc
        .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(data, &mut buf)
        .expect("PKCS7 padding")
        .len();
    buf.truncate(n);
    buf
}

/// Convenience: RSA-PKCS1-v1.5 encrypt a CEK with a public key. The
/// caller supplies an `rsa::RsaPublicKey`. Used by tests/fixtures only.
pub(crate) fn rsa_pkcs1_encrypt(
    pubkey: &rsa::RsaPublicKey,
    cek: &[u8],
) -> Result<Vec<u8>, PdfError> {
    let mut rng = rsa::rand_core::OsRng;
    pubkey
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, cek)
        .map_err(|e| PdfError::other(format!("CMS: RSA encrypt failed: {e}")))
}
