//! Minimal CMS (Cryptographic Message Syntax, RFC 5652) parser for
//! the `EnvelopedData` content type used by the PDF public-key
//! security handler (ISO 32000-1 §7.6.4 — see `docs/document/pdf/PDF32000_2008.pdf`).
//!
//! Only the subset PDF readers actually need is implemented:
//!
//! * `ContentInfo` whose `contentType` is the OID
//!   `1.2.840.113549.1.7.3` (`id-envelopedData`).
//! * `EnvelopedData` versions 0 and 2.
//! * `RecipientInfo` of variant `KeyTransRecipientInfo` (no
//!   key-agreement, no KEK, no password, no other) — the only one
//!   the spec lets `adbe.pkcs7.s3`/`s4`/`s5` use in practice.
//! * `RecipientIdentifier` of variant `IssuerAndSerialNumber` (the
//!   `[0] SubjectKeyIdentifier` form is recognised but not yet used
//!   for matching in round 10).
//! * `EncryptedContentInfo` whose `contentType` is `id-data` and
//!   whose `contentEncryptionAlgorithm` is one of the algorithm
//!   identifiers the PDF spec allows (RC4 / AES-128-CBC /
//!   AES-256-CBC).
//!
//! Provenance: RFC 5652 §6 only. Encoding test fixtures consume
//! the symmetric writer side which lives in `cms_build.rs`.

use crate::error::PdfError;

use super::der::{
    maybe_read_context, read_context, read_expected, read_integer_bytes, read_integer_u64,
    read_octet_string, read_oid, read_sequence, read_set, Class,
};

/// OID 1.2.840.113549.1.7.3 — id-envelopedData.
pub const OID_ENVELOPED_DATA: [u64; 7] = [1, 2, 840, 113549, 1, 7, 3];

/// OID 1.2.840.113549.1.7.1 — id-data (the contentType inside
/// `EncryptedContentInfo`).
pub const OID_DATA: [u64; 7] = [1, 2, 840, 113549, 1, 7, 1];

/// OID 1.2.840.113549.1.1.1 — rsaEncryption (RSAES-PKCS1-v1_5 in CMS).
pub const OID_RSA_ENCRYPTION: [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];

/// OID 1.2.840.113549.3.4 — RC4. (PDF s3/s4 with `CFM=V2`).
pub const OID_RC4: [u64; 6] = [1, 2, 840, 113549, 3, 4];

/// OID 2.16.840.1.101.3.4.1.2 — id-aes128-CBC.
pub const OID_AES128_CBC: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 1, 2];

/// OID 2.16.840.1.101.3.4.1.42 — id-aes256-CBC.
pub const OID_AES256_CBC: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 1, 42];

/// Symmetric content-encryption algorithm extracted from the
/// `EnvelopedData::encryptedContentInfo::contentEncryptionAlgorithm`
/// field. Only the algorithms actually referenced by ISO 32000-1
/// §7.6.4.3 are listed.
#[derive(Debug, Clone)]
pub enum ContentEncryption {
    /// RC4 stream cipher; the algorithm identifier carries no
    /// parameters beyond the OID itself.
    Rc4,
    /// AES-128-CBC. The IV is the 16-byte OCTET STRING parameters
    /// payload.
    Aes128Cbc { iv: [u8; 16] },
    /// AES-256-CBC. Same parameter shape as AES-128.
    Aes256Cbc { iv: [u8; 16] },
}

/// Identifier-and-serial-number pair (RFC 5280 §A.1) that points at
/// one of the recipient's certificates. Bytes are the raw DER of the
/// `Name` for `issuer` (so the matcher can byte-compare against the
/// recipient's own certificate's `issuer` directly), and the raw
/// big-endian two's-complement INTEGER body for `serial_number`.
#[derive(Debug, Clone)]
pub struct IssuerAndSerial {
    /// DER-encoded `issuer` Name (a SEQUENCE OF RelativeDistinguishedName).
    pub issuer_der: Vec<u8>,
    /// Raw INTEGER body bytes of `serialNumber`. RFC 5280 §4.1.2.2
    /// allows up to 20 octets; we keep the full big-endian body so a
    /// byte-for-byte match against the user's cert serial is exact.
    pub serial: Vec<u8>,
}

/// `KeyTransRecipientInfo` (RFC 5652 §6.2.1) — the only RecipientInfo
/// flavour the public-key handler ever uses in practice. RSAES-PKCS1
/// v1.5 is the one key-encryption algorithm we accept (per the
/// pre-AES algorithm list in ISO 32000-1 §7.6.4.3 + the RFC 5652
/// recommendation).
#[derive(Debug, Clone)]
pub struct KeyTransRecipientInfo {
    /// Issuer-and-serial-number identifier of the recipient cert.
    pub rid: IssuerAndSerial,
    /// Algorithm identifier of the key-encryption algorithm. We only
    /// accept `OID_RSA_ENCRYPTION` here.
    pub key_encryption_oid: Vec<u64>,
    /// The encrypted content-encryption key, RSA-PKCS1-v1.5 wrapped
    /// to the recipient's public RSA key.
    pub encrypted_key: Vec<u8>,
}

/// Parsed CMS `EnvelopedData` reduced to the fields the PDF public-key
/// handler consumes. Recipients other than `KeyTransRecipientInfo`
/// are ignored (skipped over with a debug-only warning) so a
/// pre-existing PDF written with mixed recipient types can still be
/// opened by a `KeyTrans` user.
#[derive(Debug, Clone)]
pub struct EnvelopedData {
    /// The unique-set-of recipient infos. Each is one wrapped CEK.
    pub recipients: Vec<KeyTransRecipientInfo>,
    /// Symmetric algorithm used to protect the envelope's content.
    pub content_encryption: ContentEncryption,
    /// The encrypted enveloped data (the bytes that decrypt to the
    /// 20-byte seed + 4-byte permissions blob).
    pub encrypted_content: Vec<u8>,
}

/// Parse the `ContentInfo` envelope wrapping an `EnvelopedData` blob,
/// returning the inner parsed structure.
pub fn parse_envelope(data: &[u8]) -> Result<EnvelopedData, PdfError> {
    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    let (body, rest) = read_sequence(data)?;
    if !rest.is_empty() {
        return Err(PdfError::other(
            "CMS: trailing bytes after ContentInfo SEQUENCE",
        ));
    }
    let (oid, rest) = read_oid(body)?;
    if oid != OID_ENVELOPED_DATA {
        return Err(PdfError::other(format!(
            "CMS: ContentInfo contentType must be id-envelopedData (got {oid:?})"
        )));
    }
    let (content, rest) = read_context(rest, 0)?;
    if !rest.is_empty() {
        return Err(PdfError::other(
            "CMS: trailing bytes after [0] EXPLICIT content",
        ));
    }
    parse_enveloped_data(content)
}

/// Parse a bare `EnvelopedData` SEQUENCE (no surrounding ContentInfo).
pub fn parse_enveloped_data(data: &[u8]) -> Result<EnvelopedData, PdfError> {
    // EnvelopedData ::= SEQUENCE {
    //   version              CMSVersion,
    //   originatorInfo       [0] IMPLICIT OriginatorInfo OPTIONAL,
    //   recipientInfos       SET OF RecipientInfo,
    //   encryptedContentInfo EncryptedContentInfo,
    //   unprotectedAttrs     [1] IMPLICIT UnprotectedAttributes OPTIONAL
    // }
    let (body, rest) = read_sequence(data)?;
    if !rest.is_empty() {
        return Err(PdfError::other(
            "CMS: trailing bytes after EnvelopedData SEQUENCE",
        ));
    }
    let (version, body) = read_integer_u64(body)?;
    if version > 4 {
        return Err(PdfError::other(format!(
            "CMS: unsupported EnvelopedData version {version}"
        )));
    }
    // `[0] IMPLICIT OriginatorInfo OPTIONAL` — skip if present (we
    // don't need any of its fields).
    let (_orig, body) = maybe_read_context(body, 0)?;

    // RecipientInfos
    let (ri_set, body) = read_set(body)?;
    let mut recipients = Vec::new();
    let mut cursor = ri_set;
    while !cursor.is_empty() {
        let (parsed, tail) = parse_recipient_info(cursor)?;
        if let Some(p) = parsed {
            recipients.push(p);
        }
        cursor = tail;
    }
    if recipients.is_empty() {
        return Err(PdfError::other(
            "CMS: EnvelopedData has no KeyTransRecipientInfo entries",
        ));
    }

    // EncryptedContentInfo ::= SEQUENCE {
    //   contentType            OBJECT IDENTIFIER,
    //   contentEncryptionAlgorithm AlgorithmIdentifier,
    //   encryptedContent       [0] IMPLICIT OCTET STRING OPTIONAL
    // }
    let (eci, body) = read_sequence(body)?;
    let (_ct_oid, eci_rest) = read_oid(eci)?;
    let (alg_seq, eci_rest) = read_sequence(eci_rest)?;
    let (alg_oid, alg_params) = read_oid(alg_seq)?;
    let content_encryption = decode_content_alg(&alg_oid, alg_params)?;
    // `[0] IMPLICIT OCTET STRING` — context-specific, primitive form.
    let (enc_body, eci_rest) = read_expected(eci_rest, Class::ContextSpecific, 0)?;
    if enc_body.constructed {
        return Err(PdfError::other(
            "CMS: encryptedContent constructed-form not supported",
        ));
    }
    if !eci_rest.is_empty() {
        return Err(PdfError::other(
            "CMS: trailing bytes after EncryptedContentInfo",
        ));
    }
    let encrypted_content = enc_body.body.to_vec();

    // The trailing unprotectedAttrs is OPTIONAL — discard if present.
    let _ = maybe_read_context(body, 1)?;

    Ok(EnvelopedData {
        recipients,
        content_encryption,
        encrypted_content,
    })
}

/// Parse a single `RecipientInfo` element from the SET body. Returns
/// `Ok(None)` for non-`ktri` variants (which are skipped silently).
fn parse_recipient_info(data: &[u8]) -> Result<(Option<KeyTransRecipientInfo>, &[u8]), PdfError> {
    // Peek at the tag to decide which CHOICE branch we're in.
    let (peek, peek_tail) = super::der::read_tlv(data)?;
    if peek.class == Class::ContextSpecific {
        // [1] kari, [2] kekri, [3] pwri, [4] ori — skip whole element.
        return Ok((None, peek_tail));
    }
    // Otherwise it's a KeyTransRecipientInfo SEQUENCE.
    let (ktri_body, tail) = read_sequence(data)?;
    let (version, after_ver) = read_integer_u64(ktri_body)?;
    // version 0 (uses IssuerAndSerialNumber) and 2 (uses
    // SubjectKeyIdentifier) per RFC 5652 §6.2.1. Only v0 has the
    // matching info our public-key handler can use.
    if version > 2 {
        return Err(PdfError::other(format!(
            "CMS: unsupported KeyTransRecipientInfo version {version}"
        )));
    }
    // RecipientIdentifier ::= CHOICE {
    //   issuerAndSerialNumber  IssuerAndSerialNumber,  -- SEQUENCE
    //   subjectKeyIdentifier  [0] SubjectKeyIdentifier  -- OCTET STRING
    // }
    let (rid, after_rid) = if version == 0 {
        let (ias_body, rest) = read_sequence(after_ver)?;
        // IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serial INTEGER }
        // We need the raw DER of `issuer` to byte-compare against the
        // user's certificate's `issuer`, so reconstruct the slice
        // including its tag+length header by computing the offset
        // from `ias_body` to the start of the `serialNumber` TLV.
        let (issuer_tlv, ias_after_issuer) = super::der::read_tlv(ias_body)?;
        if issuer_tlv.class != Class::Universal
            || issuer_tlv.tag_number != super::der::tag::SEQUENCE
        {
            return Err(PdfError::other(
                "CMS: IssuerAndSerialNumber.issuer must be a SEQUENCE",
            ));
        }
        let issuer_total = ias_body.len() - ias_after_issuer.len();
        let issuer_der = ias_body[..issuer_total].to_vec();
        let (serial_body, _) = read_integer_bytes(ias_after_issuer)?;
        (
            IssuerAndSerial {
                issuer_der,
                serial: serial_body.to_vec(),
            },
            rest,
        )
    } else {
        // [0] SubjectKeyIdentifier — not yet matched in round 10.
        return Err(PdfError::other(
            "CMS: KeyTransRecipientInfo[v=2] SubjectKeyIdentifier matching not yet supported",
        ));
    };
    // KeyEncryptionAlgorithm ::= AlgorithmIdentifier
    let (alg_seq, after_alg) = read_sequence(after_rid)?;
    let (kea_oid, _alg_params) = read_oid(alg_seq)?;
    if kea_oid != OID_RSA_ENCRYPTION {
        return Err(PdfError::other(format!(
            "CMS: unsupported KeyEncryptionAlgorithm {kea_oid:?} (only rsaEncryption)"
        )));
    }
    let (enc_key, after_key) = read_octet_string(after_alg)?;
    if !after_key.is_empty() {
        return Err(PdfError::other(
            "CMS: trailing bytes after KeyTransRecipientInfo.encryptedKey",
        ));
    }
    Ok((
        Some(KeyTransRecipientInfo {
            rid,
            key_encryption_oid: kea_oid,
            encrypted_key: enc_key.to_vec(),
        }),
        tail,
    ))
}

fn decode_content_alg(oid: &[u64], params: &[u8]) -> Result<ContentEncryption, PdfError> {
    if oid == OID_RC4 {
        // No parameters, or a NULL.
        Ok(ContentEncryption::Rc4)
    } else if oid == OID_AES128_CBC || oid == OID_AES256_CBC {
        // Parameters are an OCTET STRING wrapping the IV.
        let (iv, _) = read_octet_string(params)?;
        if iv.len() != 16 {
            return Err(PdfError::other(format!(
                "CMS: AES-CBC IV must be 16 bytes (got {})",
                iv.len()
            )));
        }
        let mut iv_arr = [0u8; 16];
        iv_arr.copy_from_slice(iv);
        if oid == OID_AES128_CBC {
            Ok(ContentEncryption::Aes128Cbc { iv: iv_arr })
        } else {
            Ok(ContentEncryption::Aes256Cbc { iv: iv_arr })
        }
    } else {
        Err(PdfError::other(format!(
            "CMS: unsupported contentEncryptionAlgorithm {oid:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubsec::cms_build::{build_envelope_aes256, RecipientPlain};

    #[test]
    fn parse_handcrafted_aes256_envelope() {
        // Build a minimal envelope with one synthetic recipient.
        let issuer_der = super::super::der::write_sequence(b"");
        let recipient = RecipientPlain {
            issuer_der: issuer_der.clone(),
            serial: vec![0x01, 0x02, 0x03],
            encrypted_key: vec![0xAA; 256],
        };
        let plaintext =
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13";
        let envelope = build_envelope_aes256(&[recipient], plaintext, &[0xBBu8; 32], &[0xCCu8; 16]);
        let parsed = parse_envelope(&envelope).expect("parse envelope");
        assert_eq!(parsed.recipients.len(), 1);
        assert_eq!(parsed.recipients[0].rid.serial, vec![0x01, 0x02, 0x03]);
        assert_eq!(parsed.recipients[0].rid.issuer_der, issuer_der);
        match parsed.content_encryption {
            ContentEncryption::Aes256Cbc { iv } => assert_eq!(iv, [0xCC; 16]),
            _ => panic!("expected AES256CBC"),
        }
    }
}
