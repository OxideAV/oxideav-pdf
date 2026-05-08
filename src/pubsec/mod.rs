//! PDF public-key security handler — ISO 32000-1 §7.6.4 +
//! ISO 32000-2 §7.6.5.
//!
//! Round-10 work is **decoder-side**: a recipient with an
//! X.509 certificate + RSA private key can open a PDF whose
//! `/Encrypt /Filter` selects one of the public-key SubFilters:
//!
//! | SubFilter             | Symmetric algorithm            | Hash  |
//! |-----------------------|--------------------------------|-------|
//! | `adbe.pkcs7.s3`       | RC4-40 (per-object Algorithm 1) | SHA-1 |
//! | `adbe.pkcs7.s4`       | RC4-128 (per-object Algorithm 1) | SHA-1 |
//! | `adbe.pkcs7.s5` V≤4   | RC4-128 / AES-128 via crypt-filter `CFM`        | SHA-1 |
//! | `adbe.pkcs7.s5` V=5   | AES-256 (no per-object derivation)              | SHA-256 |
//!
//! ## Algorithm summary
//!
//! 1. The trailer's `/Encrypt /Recipients` array (or, for `s5`, the
//!    `/Encrypt /CF /<name> /Recipients` array) is one CMS
//!    `EnvelopedData` per access-permission set. Each envelope's
//!    `RecipientInfos` SET lists every certificate that may open
//!    that permission set; the corresponding `encryptedKey` is the
//!    content-encryption key (CEK) wrapped to that recipient's
//!    public RSA key with `RSAES-PKCS1-v1_5`.
//! 2. The reader matches one of its certificates against the
//!    `IssuerAndSerialNumber` recipient identifier, RSA-decrypts the
//!    CEK with the matching private key, and uses the CEK to decrypt
//!    the envelope's `encryptedContent` (AES-CBC or RC4 per the
//!    envelope's `contentEncryptionAlgorithm`).
//! 3. The decrypted envelope is a 20-byte random seed followed by
//!    optional 4 bytes of permission flags (least-significant byte
//!    first, per ISO 32000-1 §7.6.4.3 — corrected to most-significant
//!    byte first in ISO 32000-2:2020 §7.6.5.3).
//! 4. The file encryption key is the first `n/8` bytes of the digest
//!    over `seed || every_recipient_blob_in_array_order
//!    [|| 0xFFFFFFFF if EncryptMetadata=false]`. The digest is
//!    SHA-1 for the AES-128 / RC4 paths and SHA-256 for the AES-256
//!    path (per ISO 32000-2:2020 §7.6.5.3).
//! 5. The reader hands the resulting [`StandardHandler`] back to the
//!    common decrypt path — string + stream payloads are decrypted
//!    with `Algorithm 1` (V≤4) or with the file key directly (V=5),
//!    exactly as the standard-handler reader already does.
//!
//! ## Provenance
//!
//! Implemented from spec PDFs only:
//! `docs/document/pdf/PDF32000_2008.pdf` §7.6.4 + ISO 32000-2:2020
//! §7.6.5; CMS DER from RFC 5652 §6; X.509 issuer/serial matching
//! from RFC 5280 §4.1.2; RSA-PKCS1-v1.5 from RFC 8017 (PKCS#1).
//!
//! ## Round-10 deferrals
//!
//! * Encoder side (writer-emitted public-key PDFs).
//! * `SubjectKeyIdentifier`-form recipient identifiers (only
//!   `IssuerAndSerialNumber` is used in matching).
//! * `RC2 / 3DES / DES` envelope content algorithms (deprecated in
//!   PDF 2.0; we accept RC4 / AES-128 / AES-256 only).
//! * Recipient lists per *crypt filter* (the `Recipients` entry in
//!   `/CF/<name>` for `s5`); only the document-level `Recipients`
//!   array is wired through. Per-CF recipient lists land alongside
//!   the encoder side in round 11.

pub mod cms;
pub mod der;
pub mod x509;

#[cfg(test)]
pub(crate) mod cms_build;

use crate::decrypt::{CryptMethod, StandardHandler};
use crate::error::PdfError;
use crate::objects::{Dict, Object};

/// Identifies the public-key SubFilter the encryption dictionary
/// declares. Maps to the symmetric algorithm + key length the
/// resulting `StandardHandler` will use for per-object encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubSecSubFilter {
    /// `adbe.pkcs7.s3` — RC4-40, V=1.
    Pkcs7S3,
    /// `adbe.pkcs7.s4` — RC4-128, V=2.
    Pkcs7S4,
    /// `adbe.pkcs7.s5` with V=4 — RC4-128 or AES-128 via crypt-filter `CFM`.
    Pkcs7S5V4 { aes: bool },
    /// `adbe.pkcs7.s5` with V=5 — AES-256, `CFM=AESV3`.
    Pkcs7S5V5,
}

impl PubSecSubFilter {
    fn from_dict(d: &Dict) -> Result<Self, PdfError> {
        let lookup = |k: &str| {
            d.entries()
                .iter()
                .find(|(kk, _)| kk == k)
                .map(|(_, v)| v.clone())
        };
        let sub =
            match lookup("SubFilter") {
                Some(Object::Name(n)) => n,
                _ => return Err(PdfError::other(
                    "PDF pubsec: /Encrypt missing /SubFilter (required for public-key handlers)",
                )),
            };
        let v = match lookup("V") {
            Some(Object::Integer(n)) => n,
            _ => {
                return Err(PdfError::other(
                    "PDF pubsec: /Encrypt missing /V (required)",
                ))
            }
        };
        match (sub.as_str(), v) {
            ("adbe.pkcs7.s3", _) => Ok(Self::Pkcs7S3),
            ("adbe.pkcs7.s4", _) => Ok(Self::Pkcs7S4),
            ("adbe.pkcs7.s5", 4) => {
                let aes = matches!(stmf_cfm(d).as_deref(), Some("AESV2"));
                Ok(Self::Pkcs7S5V4 { aes })
            }
            ("adbe.pkcs7.s5", 5) => Ok(Self::Pkcs7S5V5),
            ("adbe.pkcs7.s5", other) => Err(PdfError::other(format!(
                "PDF pubsec: adbe.pkcs7.s5 with /V={other} not supported (V∈{{4,5}})"
            ))),
            (other, _) => Err(PdfError::other(format!(
                "PDF pubsec: SubFilter={other} not recognised"
            ))),
        }
    }
}

/// Resolve `/CF /<StmF> /CFM` from an `/Encrypt` dict. Returns `None`
/// when any link in the chain is missing.
fn stmf_cfm(d: &Dict) -> Option<String> {
    let entries = d.entries();
    let stmf = entries
        .iter()
        .find(|(k, _)| k == "StmF")
        .and_then(|(_, v)| {
            if let Object::Name(s) = v {
                Some(s.clone())
            } else {
                None
            }
        })?;
    let cf = entries.iter().find(|(k, _)| k == "CF").and_then(|(_, v)| {
        if let Object::Dict(d) = v {
            Some(d.clone())
        } else {
            None
        }
    })?;
    let filter = cf
        .entries()
        .iter()
        .find(|(k, _)| k == &stmf)
        .and_then(|(_, v)| {
            if let Object::Dict(d) = v {
                Some(d.clone())
            } else {
                None
            }
        })?;
    filter
        .entries()
        .iter()
        .find(|(k, _)| k == "CFM")
        .and_then(|(_, v)| {
            if let Object::Name(s) = v {
                Some(s.clone())
            } else {
                None
            }
        })
}

/// User-supplied credential — an X.509 certificate (DER-encoded) and
/// the matching RSA private key. The certificate identifier
/// (`IssuerAndSerialNumber` from RFC 5280) is extracted from the
/// certificate's DER body; the RSA private key is the one used to
/// unwrap the recipient's encrypted content-encryption key.
pub struct PubSecCredential {
    pub(crate) cert: x509::Certificate,
    pub(crate) private_key: rsa::RsaPrivateKey,
}

impl PubSecCredential {
    /// Build a credential from a DER-encoded X.509 certificate and a
    /// PKCS#8-encoded RSA private key (DER, the `PrivateKeyInfo` form
    /// of RFC 5958).
    pub fn from_der(cert_der: &[u8], pkcs8_der: &[u8]) -> Result<Self, PdfError> {
        use rsa::pkcs8::DecodePrivateKey;
        let cert = x509::Certificate::parse(cert_der)?;
        let private_key = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8_der)
            .map_err(|e| PdfError::other(format!("PDF pubsec: RSA private key parse: {e}")))?;
        Ok(Self { cert, private_key })
    }

    /// Build directly from a parsed certificate + RSA key — used by
    /// fixture builders inside the crate (and by integration tests
    /// in `tests/pubsec.rs`).
    #[doc(hidden)]
    pub fn from_parsed(cert: x509::Certificate, private_key: rsa::RsaPrivateKey) -> Self {
        Self { cert, private_key }
    }
}

/// Open a public-key-encrypted PDF given the trailer's `/Encrypt`
/// dict, the trailer's `/ID[0]` bytes (used by `Algorithm 1` for
/// per-object key derivation in V≤4 — public-key handlers don't use
/// it for the document key derivation itself, but the already-built
/// per-object key path consumes it), and the user's credential.
///
/// Returns `Ok(None)` when no recipient slot in any envelope matches
/// the supplied certificate (analogous to a wrong password).
pub fn open_with_certificate(
    encrypt: &Dict,
    credential: &PubSecCredential,
) -> Result<Option<StandardHandler>, PdfError> {
    let sub_filter = PubSecSubFilter::from_dict(encrypt)?;
    let recipients_blobs = recipients_array(encrypt)?;
    if recipients_blobs.is_empty() {
        return Err(PdfError::other(
            "PDF pubsec: /Recipients array is empty (or missing)",
        ));
    }

    // Walk recipient blobs, attempt to find one whose RecipientInfos
    // SET carries our cert. The first match wins per ISO 32000-1
    // §7.6.4.2 ("There shall be only one PKCS#7 object per unique set
    // of access permissions; if a recipient appears in more than one
    // list, the permissions used shall be those in the first matching
    // list").
    for blob in &recipients_blobs {
        let envelope = cms::parse_envelope(blob)?;
        let Some(plaintext) = try_unwrap(&envelope, credential)? else {
            continue;
        };
        // The plaintext is `seed (20 bytes) [|| 4 bytes permissions]`.
        if plaintext.len() < 20 {
            return Err(PdfError::other(format!(
                "PDF pubsec: enveloped content too short ({} < 20 bytes)",
                plaintext.len()
            )));
        }
        let seed = &plaintext[..20];

        // Derive the file encryption key from seed || all_recipients [|| 0xFFFF_FFFF].
        let encrypt_metadata = match encrypt
            .entries()
            .iter()
            .find(|(k, _)| k == "EncryptMetadata")
        {
            Some((_, Object::Bool(b))) => *b,
            _ => true,
        };
        let key = derive_file_key(
            sub_filter,
            seed,
            &recipients_blobs,
            encrypt_metadata,
            key_length_bits(sub_filter, encrypt)?,
        );

        let (method, revision) = match sub_filter {
            PubSecSubFilter::Pkcs7S3 => (CryptMethod::Rc4, 2u8),
            PubSecSubFilter::Pkcs7S4 => (CryptMethod::Rc4, 3),
            PubSecSubFilter::Pkcs7S5V4 { aes } => (
                if aes {
                    CryptMethod::Aes128
                } else {
                    CryptMethod::Rc4
                },
                4,
            ),
            PubSecSubFilter::Pkcs7S5V5 => (CryptMethod::Aes256, 6),
        };
        return Ok(Some(StandardHandler {
            key,
            method,
            revision,
        }));
    }
    Ok(None)
}

/// Resolve the `/Recipients` array of byte-string PKCS#7 envelopes.
/// For `s3` / `s4` it lives at `/Encrypt /Recipients`; for `s5` it
/// lives at `/Encrypt /CF /<StmF> /Recipients` per Table 27 (the
/// document-level `/Recipients` slot is reserved for `s3`/`s4`).
fn recipients_array(encrypt: &Dict) -> Result<Vec<Vec<u8>>, PdfError> {
    let lookup = |dict: &Dict, k: &str| {
        dict.entries()
            .iter()
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.clone())
    };
    let sub = match lookup(encrypt, "SubFilter") {
        Some(Object::Name(n)) => n,
        _ => return Err(PdfError::other("PDF pubsec: /SubFilter required")),
    };
    let array = if sub == "adbe.pkcs7.s5" {
        // /CF /<StmF> /Recipients
        let stmf = match lookup(encrypt, "StmF") {
            Some(Object::Name(n)) => n,
            _ => return Err(PdfError::other("PDF pubsec: s5 requires /StmF")),
        };
        let cf = match lookup(encrypt, "CF") {
            Some(Object::Dict(d)) => d,
            _ => return Err(PdfError::other("PDF pubsec: s5 requires /CF dictionary")),
        };
        let cf_filter = match lookup(&cf, &stmf) {
            Some(Object::Dict(d)) => d,
            _ => {
                return Err(PdfError::other(format!(
                    "PDF pubsec: /CF/{stmf} not found or not a dict"
                )))
            }
        };
        match lookup(&cf_filter, "Recipients") {
            Some(o) => o,
            _ => {
                return Err(PdfError::other(format!(
                    "PDF pubsec: /CF/{stmf}/Recipients missing"
                )))
            }
        }
    } else {
        match lookup(encrypt, "Recipients") {
            Some(o) => o,
            _ => return Err(PdfError::other("PDF pubsec: /Recipients missing")),
        }
    };

    let blobs: Vec<Vec<u8>> = match array {
        Object::Array(items) => items
            .into_iter()
            .map(|item| match item {
                Object::LiteralString(s) | Object::HexString(s) => Ok(s),
                other => Err(PdfError::other(format!(
                    "PDF pubsec: /Recipients element must be a string (got {other:?})"
                ))),
            })
            .collect::<Result<_, _>>()?,
        // PDF 2.0 (s5 from-CF) accepts a single string for per-stream
        // recipients; we treat it as a one-element array here.
        Object::LiteralString(s) | Object::HexString(s) => vec![s],
        other => {
            return Err(PdfError::other(format!(
                "PDF pubsec: /Recipients must be an array of strings (got {other:?})"
            )))
        }
    };
    Ok(blobs)
}

fn key_length_bits(sub: PubSecSubFilter, encrypt: &Dict) -> Result<usize, PdfError> {
    let dict_len = encrypt
        .entries()
        .iter()
        .find(|(k, _)| k == "Length")
        .and_then(|(_, v)| {
            if let Object::Integer(n) = v {
                Some(*n)
            } else {
                None
            }
        });
    let bits = match sub {
        PubSecSubFilter::Pkcs7S3 => 40,
        PubSecSubFilter::Pkcs7S4 => 128,
        PubSecSubFilter::Pkcs7S5V4 { aes } => {
            if aes {
                128
            } else {
                dict_len.unwrap_or(128) as usize
            }
        }
        PubSecSubFilter::Pkcs7S5V5 => 256,
    };
    Ok(bits)
}

/// Find a recipient slot in `envelope` whose IssuerAndSerial matches
/// `credential.cert`, then RSA-decrypt the wrapped CEK and use it to
/// decrypt the envelope's encrypted content. Returns the plaintext
/// (the seed + permissions blob), or `None` if no recipient matched.
fn try_unwrap(
    envelope: &cms::EnvelopedData,
    credential: &PubSecCredential,
) -> Result<Option<Vec<u8>>, PdfError> {
    let our_issuer = &credential.cert.issuer_der;
    let our_serial = &credential.cert.serial;
    for recipient in &envelope.recipients {
        if &recipient.rid.issuer_der == our_issuer && &recipient.rid.serial == our_serial {
            let cek = credential
                .private_key
                .decrypt(rsa::Pkcs1v15Encrypt, &recipient.encrypted_key)
                .map_err(|e| PdfError::other(format!("PDF pubsec: RSA decrypt failed: {e}")))?;
            let plaintext = decrypt_envelope_content(
                &envelope.content_encryption,
                &cek,
                &envelope.encrypted_content,
            )?;
            return Ok(Some(plaintext));
        }
    }
    Ok(None)
}

fn decrypt_envelope_content(
    alg: &cms::ContentEncryption,
    cek: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PdfError> {
    match alg {
        cms::ContentEncryption::Rc4 => Ok(crate::decrypt::rc4(cek, ciphertext)),
        cms::ContentEncryption::Aes128Cbc { iv } => {
            if cek.len() != 16 {
                return Err(PdfError::other(format!(
                    "PDF pubsec: AES-128 CEK must be 16 bytes (got {})",
                    cek.len()
                )));
            }
            aes_cbc_decrypt::<aes::Aes128>(cek, iv, ciphertext)
        }
        cms::ContentEncryption::Aes256Cbc { iv } => {
            if cek.len() != 32 {
                return Err(PdfError::other(format!(
                    "PDF pubsec: AES-256 CEK must be 32 bytes (got {})",
                    cek.len()
                )));
            }
            aes_cbc_decrypt::<aes::Aes256>(cek, iv, ciphertext)
        }
    }
}

fn aes_cbc_decrypt<C>(key: &[u8], iv: &[u8; 16], ct: &[u8]) -> Result<Vec<u8>, PdfError>
where
    C: aes::cipher::BlockCipher
        + aes::cipher::BlockEncrypt
        + aes::cipher::BlockDecrypt
        + aes::cipher::KeyInit
        + aes::cipher::BlockSizeUser<BlockSize = aes::cipher::consts::U16>,
{
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    type Dec<C> = cbc::Decryptor<C>;
    if ct.len() % 16 != 0 {
        return Err(PdfError::other(format!(
            "PDF pubsec: AES-CBC ciphertext {} not block-aligned",
            ct.len()
        )));
    }
    let dec = <Dec<C> as KeyIvInit>::new_from_slices(key, iv)
        .map_err(|e| PdfError::other(format!("PDF pubsec: AES init failed: {e}")))?;
    let mut buf = ct.to_vec();
    let pt = dec
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| PdfError::other(format!("PDF pubsec: AES-CBC unpad: {e:?}")))?;
    Ok(pt.to_vec())
}

/// Derive the file encryption key per ISO 32000-1 §7.6.4.3 / ISO
/// 32000-2 §7.6.5.3. Hash is SHA-1 for V≤4 paths and SHA-256 for the
/// V=5 (AES-256) path.
fn derive_file_key(
    sub: PubSecSubFilter,
    seed: &[u8],
    recipients_blobs: &[Vec<u8>],
    encrypt_metadata: bool,
    key_length_bits: usize,
) -> Vec<u8> {
    let n = key_length_bits / 8;
    let mut input =
        Vec::with_capacity(20 + recipients_blobs.iter().map(|v| v.len()).sum::<usize>() + 4);
    input.extend_from_slice(seed);
    for blob in recipients_blobs {
        input.extend_from_slice(blob);
    }
    if !encrypt_metadata {
        input.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    }
    let digest: Vec<u8> = match sub {
        PubSecSubFilter::Pkcs7S5V5 => {
            use sha2::Digest;
            sha2::Sha256::digest(&input).to_vec()
        }
        _ => {
            use sha1::Digest;
            sha1::Sha1::digest(&input).to_vec()
        }
    };
    digest[..n.min(digest.len())].to_vec()
}

#[cfg(test)]
mod tests {
    use super::cms_build::{
        build_envelope_aes128, build_envelope_aes256, rsa_pkcs1_encrypt, RecipientPlain,
    };
    use super::*;
    use crate::objects::Dict;

    fn rsa_keypair() -> (rsa::RsaPrivateKey, rsa::RsaPublicKey) {
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA keypair");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        (priv_key, pub_key)
    }

    fn fake_cert(issuer: &[u8], serial: &[u8]) -> super::x509::Certificate {
        super::x509::Certificate {
            issuer_der: issuer.to_vec(),
            serial: serial.to_vec(),
        }
    }

    fn make_encrypt_dict(sub_filter: &str, v: i64, recipients: &[Vec<u8>]) -> Dict {
        let mut d = Dict::default();
        d.set("Filter", Object::Name("Adobe.PPKLite".into()));
        d.set("SubFilter", Object::Name(sub_filter.into()));
        d.set("V", Object::Integer(v));
        d.set("P", Object::Integer(-4));
        let arr = recipients
            .iter()
            .map(|r| Object::LiteralString(r.clone()))
            .collect();
        d.set("Recipients", Object::Array(arr));
        d
    }

    #[test]
    fn s4_open_round_trip() {
        // adbe.pkcs7.s4 → RC4-128, SHA-1 hash, V=2.
        let (priv_key, pub_key) = rsa_keypair();
        let issuer_der = super::der::write_sequence(b"O=Test");
        let serial = vec![0x01, 0x42];
        // CEK is the AES-128 key — for the s4 RC4 envelope we use a
        // 128-bit RC4 key; ISO accepts up to 256 bits.
        let cek = [0x66u8; 16];
        // Plaintext = 20-byte seed + 4-byte permissions LE.
        let mut plaintext = vec![0u8; 24];
        plaintext[..20].copy_from_slice(&[0xAB; 20]);
        plaintext[20..24].copy_from_slice(&((-4i32) as u32).to_le_bytes());
        // Encrypt the plaintext under RC4(cek).
        let encrypted_content = crate::decrypt::rc4(&cek, &plaintext);
        let encrypted_key = rsa_pkcs1_encrypt(&pub_key, &cek).unwrap();
        // Build the envelope manually because cms_build's RC4 helper
        // isn't exposed — use the inner builder which assumes the
        // caller pre-encrypted the content.
        let envelope_der = {
            let recipient = RecipientPlain {
                issuer_der: issuer_der.clone(),
                serial: serial.clone(),
                encrypted_key,
            };
            build_envelope_rc4(&[recipient], &encrypted_content)
        };
        let credential = PubSecCredential::from_parsed(fake_cert(&issuer_der, &serial), priv_key);
        let encrypt = make_encrypt_dict("adbe.pkcs7.s4", 2, &[envelope_der]);
        let handler = open_with_certificate(&encrypt, &credential)
            .expect("open ok")
            .expect("matched recipient");
        assert_eq!(handler.method, CryptMethod::Rc4);
        assert_eq!(handler.revision, 3);
        assert_eq!(handler.key.len(), 16);
    }

    /// Build an envelope with a pre-encrypted RC4 content. Used only
    /// by the test above.
    fn build_envelope_rc4(recipients: &[RecipientPlain], encrypted_content: &[u8]) -> Vec<u8> {
        use super::cms::OID_RC4;
        use super::der::{
            write_context_constructed, write_context_primitive, write_integer_u64, write_oid,
            write_sequence, write_set,
        };
        // RecipientInfos.
        let ri_set = {
            let mut body = Vec::new();
            for r in recipients {
                body.extend_from_slice(&build_ktri(r));
            }
            write_set(&body)
        };
        // EncryptedContentInfo with RC4 alg (no parameters or NULL).
        let alg_id = {
            let mut body = write_oid(&OID_RC4);
            body.extend_from_slice(&super::der::write_null());
            write_sequence(&body)
        };
        let eci = {
            let mut body = write_oid(&super::cms::OID_DATA);
            body.extend_from_slice(&alg_id);
            body.extend_from_slice(&write_context_primitive(0, encrypted_content));
            write_sequence(&body)
        };
        let enveloped = {
            let mut body = write_integer_u64(0);
            body.extend_from_slice(&ri_set);
            body.extend_from_slice(&eci);
            write_sequence(&body)
        };
        let outer_body = {
            let mut b = write_oid(&super::cms::OID_ENVELOPED_DATA);
            b.extend_from_slice(&write_context_constructed(0, &enveloped));
            b
        };
        write_sequence(&outer_body)
    }

    fn build_ktri(r: &RecipientPlain) -> Vec<u8> {
        use super::cms::OID_RSA_ENCRYPTION;
        use super::der::{
            write_integer_bytes, write_integer_u64, write_octet_string, write_oid, write_sequence,
        };
        let serial_int = write_integer_bytes(&r.serial);
        let ias_body = {
            let mut b = Vec::with_capacity(r.issuer_der.len() + serial_int.len());
            b.extend_from_slice(&r.issuer_der);
            b.extend_from_slice(&serial_int);
            b
        };
        let ias = write_sequence(&ias_body);
        let kea = {
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

    #[test]
    fn s5_v5_aes256_round_trip() {
        // adbe.pkcs7.s5 V=5 → AES-256, SHA-256 hash.
        let (priv_key, pub_key) = rsa_keypair();
        let issuer_der = super::der::write_sequence(b"O=Test");
        let serial = vec![0x42, 0x01, 0x00];
        let cek = [0xC1u8; 32];
        let iv = [0xCAu8; 16];
        // Plaintext = 20-byte seed + 4-byte permissions MSB.
        let mut plaintext = vec![0u8; 24];
        plaintext[..20].copy_from_slice(&[0xCD; 20]);
        plaintext[20..24].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFC]);
        let encrypted_key = rsa_pkcs1_encrypt(&pub_key, &cek).unwrap();
        let envelope_der = build_envelope_aes256(
            &[RecipientPlain {
                issuer_der: issuer_der.clone(),
                serial: serial.clone(),
                encrypted_key,
            }],
            &plaintext,
            &cek,
            &iv,
        );
        // s5 uses /CF /<StmF> /Recipients (Table 27). Build that
        // dictionary structure.
        let mut filter = Dict::default();
        filter.set("CFM", Object::Name("AESV3".into()));
        filter.set(
            "Recipients",
            Object::Array(vec![Object::LiteralString(envelope_der)]),
        );
        filter.set("Length", Object::Integer(32));
        let mut cf = Dict::default();
        cf.set("DefaultCryptFilter", Object::Dict(filter));
        let mut encrypt = Dict::default();
        encrypt.set("Filter", Object::Name("Adobe.PPKLite".into()));
        encrypt.set("SubFilter", Object::Name("adbe.pkcs7.s5".into()));
        encrypt.set("V", Object::Integer(5));
        encrypt.set("P", Object::Integer(-4));
        encrypt.set("StmF", Object::Name("DefaultCryptFilter".into()));
        encrypt.set("StrF", Object::Name("DefaultCryptFilter".into()));
        encrypt.set("CF", Object::Dict(cf));

        let credential = PubSecCredential::from_parsed(fake_cert(&issuer_der, &serial), priv_key);
        let handler = open_with_certificate(&encrypt, &credential)
            .expect("open ok")
            .expect("matched recipient");
        assert_eq!(handler.method, CryptMethod::Aes256);
        assert_eq!(handler.revision, 6);
        assert_eq!(handler.key.len(), 32);
    }

    #[test]
    fn open_returns_none_when_cert_does_not_match() {
        let (priv_key, pub_key) = rsa_keypair();
        let issuer_der = super::der::write_sequence(b"O=Other");
        let cek = [0u8; 32];
        let iv = [0u8; 16];
        let plaintext = vec![0xAA; 24];
        let encrypted_key = rsa_pkcs1_encrypt(&pub_key, &cek).unwrap();
        let envelope_der = build_envelope_aes256(
            &[RecipientPlain {
                issuer_der: issuer_der.clone(),
                serial: vec![0x01],
                encrypted_key,
            }],
            &plaintext,
            &cek,
            &iv,
        );
        // Caller's cert has a different serial — no match.
        let mut filter = Dict::default();
        filter.set("CFM", Object::Name("AESV3".into()));
        filter.set(
            "Recipients",
            Object::Array(vec![Object::LiteralString(envelope_der)]),
        );
        let mut cf = Dict::default();
        cf.set("F", Object::Dict(filter));
        let mut encrypt = Dict::default();
        encrypt.set("Filter", Object::Name("Adobe.PPKLite".into()));
        encrypt.set("SubFilter", Object::Name("adbe.pkcs7.s5".into()));
        encrypt.set("V", Object::Integer(5));
        encrypt.set("P", Object::Integer(-4));
        encrypt.set("StmF", Object::Name("F".into()));
        encrypt.set("StrF", Object::Name("F".into()));
        encrypt.set("CF", Object::Dict(cf));
        let credential = PubSecCredential::from_parsed(
            fake_cert(&issuer_der, &[0x99]), // different serial
            priv_key,
        );
        let handler = open_with_certificate(&encrypt, &credential).unwrap();
        assert!(handler.is_none(), "unexpected match: {handler:?}");
    }

    #[test]
    fn s5_v4_aes128_round_trip() {
        // adbe.pkcs7.s5 V=4 + AESV2 → AES-128, SHA-1 hash.
        let (priv_key, pub_key) = rsa_keypair();
        let issuer_der = super::der::write_sequence(b"O=v4test");
        let serial = vec![0x05];
        let cek = [0x77u8; 16];
        let iv = [0x88u8; 16];
        let plaintext = vec![0u8; 24];
        let encrypted_key = rsa_pkcs1_encrypt(&pub_key, &cek).unwrap();
        let envelope_der = build_envelope_aes128(
            &[RecipientPlain {
                issuer_der: issuer_der.clone(),
                serial: serial.clone(),
                encrypted_key,
            }],
            &plaintext,
            &cek,
            &iv,
        );
        let mut filter = Dict::default();
        filter.set("CFM", Object::Name("AESV2".into()));
        filter.set(
            "Recipients",
            Object::Array(vec![Object::LiteralString(envelope_der)]),
        );
        let mut cf = Dict::default();
        cf.set("DefaultCryptFilter", Object::Dict(filter));
        let mut encrypt = Dict::default();
        encrypt.set("Filter", Object::Name("Adobe.PPKLite".into()));
        encrypt.set("SubFilter", Object::Name("adbe.pkcs7.s5".into()));
        encrypt.set("V", Object::Integer(4));
        encrypt.set("P", Object::Integer(-4));
        encrypt.set("StmF", Object::Name("DefaultCryptFilter".into()));
        encrypt.set("StrF", Object::Name("DefaultCryptFilter".into()));
        encrypt.set("CF", Object::Dict(cf));
        let credential = PubSecCredential::from_parsed(fake_cert(&issuer_der, &serial), priv_key);
        let handler = open_with_certificate(&encrypt, &credential)
            .expect("open ok")
            .expect("matched recipient");
        assert_eq!(handler.method, CryptMethod::Aes128);
        assert_eq!(handler.revision, 4);
        assert_eq!(handler.key.len(), 16);
    }
}
