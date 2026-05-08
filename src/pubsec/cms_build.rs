//! CMS `EnvelopedData` builder used by both the writer-side public-key
//! security handler (round 11) and the round-10 fixture builders that
//! exercise the decoder unit tests.
//!
//! The round-10 work was decoder-only: a real-world enterprise PDF
//! whose `/Encrypt /Filter` is one of `Adobe.PPKLite` /
//! `Entrust.PPKEF` carries a `Recipients` array of CMS objects we
//! parse. Round 11 promotes this module to public API so the writer
//! can emit the same envelope shape — symmetric encoder side.
//!
//! Provenance: RFC 5652 §6 only.

use crate::error::PdfError;

use super::cms::{
    OID_AES128_CBC, OID_AES256_CBC, OID_DATA, OID_ENVELOPED_DATA, OID_RC4, OID_RSA_ENCRYPTION,
};
use super::der::{
    write_context_constructed, write_context_primitive, write_integer_bytes, write_integer_u64,
    write_null, write_octet_string, write_oid, write_sequence, write_set,
};

/// Recipient identifier carried by a `KeyTransRecipientInfo` slot of
/// the emitted CMS envelope. Mirrors the two CHOICE arms of RFC 5652
/// §6.2.1: `IssuerAndSerialNumber` (CMS v0) or `SubjectKeyIdentifier`
/// (CMS v2).
#[derive(Debug, Clone)]
pub enum RecipientIdRef {
    /// `IssuerAndSerialNumber` (CMS v0). `issuer_der` is the recipient
    /// certificate's `issuer` SEQUENCE — including its tag/length
    /// header — so the reader's byte-comparison is exact. `serial` is
    /// the raw INTEGER body of the cert's serial number.
    IssuerAndSerial {
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
    },
    /// `SubjectKeyIdentifier` (CMS v2). The 20-byte SHA-1 hash of the
    /// recipient certificate's `SubjectPublicKeyInfo` BIT STRING
    /// contents (RFC 5280 §4.2.1.2 method 1). Encoded as an `[0]`
    /// IMPLICIT OCTET STRING in the CMS envelope.
    SubjectKeyIdentifier { ski: Vec<u8> },
}

/// One recipient slot to emit. The encrypted CEK is supplied
/// pre-wrapped — the caller is expected to have done the RSA
/// encryption against the recipient's public key.
#[derive(Debug, Clone)]
pub struct RecipientPlain {
    /// Recipient identifier — either issuer+serial (CMS v0) or SKI
    /// (CMS v2).
    pub rid: RecipientIdRef,
    /// The RSA-PKCS1-v1.5-encrypted content-encryption key.
    pub encrypted_key: Vec<u8>,
}

impl RecipientPlain {
    /// Convenience constructor that builds an `IssuerAndSerialNumber`
    /// (CMS v0) recipient slot.
    pub fn ias(issuer_der: Vec<u8>, serial: Vec<u8>, encrypted_key: Vec<u8>) -> Self {
        Self {
            rid: RecipientIdRef::IssuerAndSerial { issuer_der, serial },
            encrypted_key,
        }
    }

    /// Convenience constructor that builds a `SubjectKeyIdentifier`
    /// (CMS v2) recipient slot. `ski` is the 20-byte SHA-1 of the
    /// recipient cert's SubjectPublicKeyInfo BIT STRING contents
    /// (RFC 5280 §4.2.1.2 method 1).
    pub fn ski(ski: Vec<u8>, encrypted_key: Vec<u8>) -> Self {
        Self {
            rid: RecipientIdRef::SubjectKeyIdentifier { ski },
            encrypted_key,
        }
    }
}

/// Build an `EnvelopedData` ContentInfo for AES-128-CBC.
///
/// `cek` is the 16-byte AES-128 key the recipients can recover by
/// RSA-decrypting their `encrypted_key`. `iv` is the 16-byte CBC IV.
/// `plaintext` is the bytes to encapsulate (typically the 20-byte
/// seed + 4-byte permissions for ISO 32000-1 §7.6.4.3).
pub fn build_envelope_aes128(
    recipients: &[RecipientPlain],
    plaintext: &[u8],
    cek: &[u8; 16],
    iv: &[u8; 16],
) -> Vec<u8> {
    let encrypted = aes128_cbc_encrypt_padded(cek, iv, plaintext);
    build_envelope_inner(recipients, &OID_AES128_CBC, Some(iv), &encrypted)
}

/// Build an `EnvelopedData` ContentInfo for AES-256-CBC.
pub fn build_envelope_aes256(
    recipients: &[RecipientPlain],
    plaintext: &[u8],
    cek: &[u8; 32],
    iv: &[u8; 16],
) -> Vec<u8> {
    let encrypted = aes256_cbc_encrypt_padded(cek, iv, plaintext);
    build_envelope_inner(recipients, &OID_AES256_CBC, Some(iv), &encrypted)
}

/// Build an `EnvelopedData` ContentInfo whose content-encryption
/// algorithm is RC4 (PDF `adbe.pkcs7.s3` / `s4`). `cek` doubles as the
/// RC4 key — RFC 5652 §6.3 with the RC4 OID 1.2.840.113549.3.4.
pub fn build_envelope_rc4(recipients: &[RecipientPlain], plaintext: &[u8], cek: &[u8]) -> Vec<u8> {
    let encrypted = crate::decrypt::rc4(cek, plaintext);
    build_envelope_inner(recipients, &OID_RC4, None, &encrypted)
}

fn build_envelope_inner(
    recipients: &[RecipientPlain],
    content_alg_oid: &[u64],
    iv: Option<&[u8; 16]>,
    encrypted_content: &[u8],
) -> Vec<u8> {
    // RFC 5652 §10.2.1: EnvelopedData version is 2 if any recipient
    // uses the SubjectKeyIdentifier (CHOICE) form, else 0.
    let envelope_version: u64 = if recipients
        .iter()
        .any(|r| matches!(r.rid, RecipientIdRef::SubjectKeyIdentifier { .. }))
    {
        2
    } else {
        0
    };

    // 1) RecipientInfos: SET OF KeyTransRecipientInfo.
    let mut ri_set_body = Vec::new();
    for r in recipients {
        ri_set_body.extend_from_slice(&build_ktri(r));
    }
    let ri_set = write_set(&ri_set_body);

    // 2) EncryptedContentInfo.
    let alg_id = {
        let mut body = write_oid(content_alg_oid);
        match iv {
            Some(iv) => body.extend_from_slice(&write_octet_string(iv)),
            // RC4 carries a NULL parameters payload (no IV).
            None => body.extend_from_slice(&write_null()),
        }
        write_sequence(&body)
    };
    let eci = {
        let mut body = write_oid(&OID_DATA);
        body.extend_from_slice(&alg_id);
        // [0] IMPLICIT OCTET STRING: context-specific primitive.
        body.extend_from_slice(&write_context_primitive(0, encrypted_content));
        write_sequence(&body)
    };

    // 3) EnvelopedData = SEQUENCE { version, recipients, eci }.
    let enveloped_body = {
        let mut b = write_integer_u64(envelope_version);
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
    //   version CMSVersion,                  -- 0 for IAS, 2 for SKI
    //   rid RecipientIdentifier,             -- CHOICE
    //   keyEncryptionAlgorithm AlgorithmIdentifier,
    //   encryptedKey OCTET STRING
    // }
    let (version, rid_bytes) = match &r.rid {
        RecipientIdRef::IssuerAndSerial { issuer_der, serial } => {
            let serial_int = write_integer_bytes(serial);
            let ias_body = {
                let mut b = Vec::with_capacity(issuer_der.len() + serial_int.len());
                b.extend_from_slice(issuer_der);
                b.extend_from_slice(&serial_int);
                b
            };
            (0u64, write_sequence(&ias_body))
        }
        RecipientIdRef::SubjectKeyIdentifier { ski } => {
            // [0] IMPLICIT OCTET STRING — context-specific primitive
            // wrapping the raw 20-byte SHA-1 of the SPKI.
            (2u64, write_context_primitive(0, ski))
        }
    };
    let kea = {
        // RSAES-PKCS1-v1_5: AlgorithmIdentifier with NULL parameters.
        let mut b = write_oid(&OID_RSA_ENCRYPTION);
        b.extend_from_slice(&super::der::write_null());
        write_sequence(&b)
    };
    let mut body = write_integer_u64(version);
    body.extend_from_slice(&rid_bytes);
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
/// caller supplies an `rsa::RsaPublicKey`.
pub fn rsa_pkcs1_encrypt(pubkey: &rsa::RsaPublicKey, cek: &[u8]) -> Result<Vec<u8>, PdfError> {
    let mut rng = rsa::rand_core::OsRng;
    pubkey
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, cek)
        .map_err(|e| PdfError::other(format!("CMS: RSA encrypt failed: {e}")))
}
