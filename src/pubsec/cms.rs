//! Minimal CMS (Cryptographic Message Syntax, RFC 5652) parser for
//! the `EnvelopedData` content type used by the PDF public-key
//! security handler (ISO 32000-1 §7.6.4 — see `docs/document/pdf/PDF32000_2008.pdf`).
//!
//! Only the subset PDF readers actually need is implemented:
//!
//! * `ContentInfo` whose `contentType` is the OID
//!   `1.2.840.113549.1.7.3` (`id-envelopedData`).
//! * `EnvelopedData` versions 0, 2, and 3.
//! * `RecipientInfo` of variant `KeyTransRecipientInfo` (RFC 5652
//!   §6.2.1) and `KeyAgreeRecipientInfo` (§6.2.2 — round 12 decoder
//!   side: ECDH / DH / static-static recipients; the originator
//!   public key + UKM are surfaced; the wrapped CEK lands as a
//!   `RecipientEncryptedKey` slot inside the KARI).
//! * `RecipientIdentifier` of variant `IssuerAndSerialNumber` (CMS
//!   v0) or `[0] SubjectKeyIdentifier` (CMS v2). Round 11 wires the
//!   SKI variant through to the matcher (the pubsec module computes
//!   the SHA-1 of the user cert's `SubjectPublicKeyInfo` BIT STRING
//!   contents per RFC 5280 §4.2.1.2 and compares it to the recipient
//!   slot's SKI octet string).
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

/// OID 1.2.840.113549.3.2 — `rc2-cbc` (RFC 2268 + RFC 3217 §3). Used
/// by legacy CMS envelopes whose `EncryptedContentInfo.contentEncryptionAlgorithm`
/// names RC2-CBC. Round-17 adds read-only support so legacy
/// PDF archives still open; PDF 2.0 deprecates RC2 entirely.
///
/// Parameters per RFC 3370 §5.1: SEQUENCE { rc2ParameterVersion INTEGER
/// OPTIONAL DEFAULT 32, iv OCTET STRING (size 8) }. The
/// `rc2ParameterVersion` ↔ effective-key-bits mapping (RFC 2268 §6) is:
/// version 160 → 40 bits, 120 → 64 bits, 58 → 128 bits. We only
/// support the 128-bit effective-key variant on decode (the 40 / 64-bit
/// variants are export-grade legacy and would also be acceptable in
/// principle, but the surface we surface today follows the most-common
/// modern usage).
pub const OID_RC2_CBC: [u64; 6] = [1, 2, 840, 113549, 3, 2];

/// OID 1.2.840.113549.3.7 — `des-EDE3-CBC` (RFC 3370 §5.2 + RFC 5652
/// §12.4). Used by legacy CMS envelopes whose
/// `EncryptedContentInfo.contentEncryptionAlgorithm` names triple-DES
/// in CBC mode. Round-17 adds read-only support; PDF 2.0 deprecates 3DES.
///
/// Parameters: OCTET STRING (size 8) — the 8-byte CBC IV.
pub const OID_DES_EDE3_CBC: [u64; 6] = [1, 2, 840, 113549, 3, 7];

/// Symmetric content-encryption algorithm extracted from the
/// `EnvelopedData::encryptedContentInfo::contentEncryptionAlgorithm`
/// field. Only the algorithms actually referenced by ISO 32000-1
/// §7.6.4.3 + the read-only legacy round-17 set are listed.
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
    /// **Round-17 read-only** — RC2-CBC (RFC 2268 + RFC 3217 §3). The
    /// 8-byte CBC IV is carried in the parameters SEQUENCE alongside
    /// the optional `rc2ParameterVersion` (which we surface as the
    /// effective-key bit length per RFC 2268 §6 — 40 / 64 / 128).
    /// PDF 2.0 deprecates RC2; we accept it on decode only.
    Rc2Cbc {
        /// RC2 effective-key bit length (RFC 2268 §6) — `40`, `64`, or
        /// `128`. Defaults to `32` per RFC 3370 §5.1's
        /// `rc2ParameterVersion` DEFAULT (which translates to 32 effective
        /// bits — but RFC 3370 also explicitly lists 32 → 32 and writers
        /// commonly omit the field entirely, in which case we fall back
        /// to 32).
        effective_key_bits: u32,
        /// 8-byte CBC IV.
        iv: [u8; 8],
    },
    /// **Round-17 read-only** — DES-EDE3-CBC (3DES, RFC 3370 §5.2). The
    /// 8-byte CBC IV is the parameters payload. PDF 2.0 deprecates 3DES;
    /// we accept it on decode only.
    DesEde3Cbc {
        /// 8-byte CBC IV.
        iv: [u8; 8],
    },
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

/// CMS `RecipientIdentifier` (RFC 5652 §6.2.1) — the CHOICE that picks
/// between `IssuerAndSerialNumber` (CMS v0) and `SubjectKeyIdentifier`
/// (CMS v2). The SKI form carries the bare 20-byte SHA-1 of the
/// recipient cert's `SubjectPublicKeyInfo` BIT STRING contents — see
/// RFC 5280 §4.2.1.2 method 1.
#[derive(Debug, Clone)]
pub enum RecipientId {
    /// `IssuerAndSerialNumber` (CMS v0). The matcher compares this to
    /// the user cert's `(issuer_der, serial)` pair byte-for-byte.
    IssuerAndSerial(IssuerAndSerial),
    /// `[0] SubjectKeyIdentifier` (CMS v2). The matcher compares the
    /// raw octet-string body to the SHA-1 of the user cert's
    /// `SubjectPublicKeyInfo` BIT STRING contents.
    SubjectKeyIdentifier(Vec<u8>),
}

/// `KeyTransRecipientInfo` (RFC 5652 §6.2.1) — the only RecipientInfo
/// flavour the public-key handler ever uses in practice. RSAES-PKCS1
/// v1.5 is the one key-encryption algorithm we accept (per the
/// pre-AES algorithm list in ISO 32000-1 §7.6.4.3 + the RFC 5652
/// recommendation).
#[derive(Debug, Clone)]
pub struct KeyTransRecipientInfo {
    /// Recipient identifier — IssuerAndSerial (v0) or SKI (v2).
    pub rid: RecipientId,
    /// Algorithm identifier of the key-encryption algorithm. We only
    /// accept `OID_RSA_ENCRYPTION` here.
    pub key_encryption_oid: Vec<u64>,
    /// The encrypted content-encryption key, RSA-PKCS1-v1.5 wrapped
    /// to the recipient's public RSA key.
    pub encrypted_key: Vec<u8>,
}

/// `OriginatorPublicKey` (RFC 5652 §6.2.2) — the originator's
/// ephemeral or static public key carried as a BIT STRING with an
/// `AlgorithmIdentifier` describing the curve / group. Used by the
/// recipient (along with their own private key) to derive the shared
/// secret that wraps the content-encryption key in a KARI envelope.
#[derive(Debug, Clone)]
pub struct OriginatorPublicKey {
    /// AlgorithmIdentifier OID (e.g. ecPublicKey, dhpublicnumber).
    pub algorithm_oid: Vec<u64>,
    /// Raw AlgorithmIdentifier `parameters` field bytes (e.g. an OID
    /// for the named curve). Empty when the encoded form was a NULL
    /// or absent.
    pub algorithm_params: Vec<u8>,
    /// `subjectPublicKey` BIT STRING contents (no leading unused-bits
    /// byte). For ECDH this is the encoded EC point.
    pub public_key: Vec<u8>,
}

/// `OriginatorIdentifierOrKey` (RFC 5652 §6.2.2) — the CHOICE that
/// identifies the originator side of a key-agreement recipient. We
/// surface every arm so callers can route on the originator type
/// (an importing client may, for example, prefer one originator to
/// another when multiple KARIs are present).
#[derive(Debug, Clone)]
pub enum OriginatorId {
    /// Originator is identified by their `IssuerAndSerialNumber`.
    IssuerAndSerial(IssuerAndSerial),
    /// Originator is identified by their SubjectKeyIdentifier (the
    /// 20-byte SHA-1 of their cert's SPKI BIT STRING contents).
    SubjectKeyIdentifier(Vec<u8>),
    /// Originator's public key is carried in-band (no certificate
    /// reference required).
    OriginatorKey(OriginatorPublicKey),
}

/// `KeyAgreeRecipientIdentifier` (RFC 5652 §6.2.2) — identifies one
/// recipient inside a KARI's `recipientEncryptedKeys` SEQUENCE. Either
/// the legacy `IssuerAndSerial` form or a `RecipientKeyIdentifier` —
/// which carries an SKI plus optional `date` + `other` attributes.
#[derive(Debug, Clone)]
pub enum KeyAgreeRecipientId {
    /// Legacy `IssuerAndSerialNumber` — same shape as KTRI v0.
    IssuerAndSerial(IssuerAndSerial),
    /// `[0] IMPLICIT RecipientKeyIdentifier`. We surface the SKI body
    /// only; the OPTIONAL `date` and `other` fields are skipped (the
    /// PDF public-key handler doesn't consume them).
    RecipientKeyIdentifier { ski: Vec<u8> },
}

/// `RecipientEncryptedKey` (RFC 5652 §6.2.2) — one wrapped CEK inside
/// a KARI envelope. The KARI itself holds a SEQUENCE OF these.
#[derive(Debug, Clone)]
pub struct RecipientEncryptedKey {
    /// Recipient identifier (CHOICE issuerAndSerial / RKID-via-SKI).
    pub rid: KeyAgreeRecipientId,
    /// Wrapped content-encryption key. The unwrap algorithm is named
    /// by the parent KARI's `keyEncryptionAlgorithm` (typically a
    /// key-wrap algorithm such as `id-aes128-wrap` paired with a
    /// key-derivation function like `dhSinglePass-stdDH-sha256kdf-scheme`).
    pub encrypted_key: Vec<u8>,
}

/// `KeyAgreeRecipientInfo` (RFC 5652 §6.2.2) — the second
/// `RecipientInfo` CHOICE arm. Used with ECDH / DH-based recipients
/// (vs RSA-based KTRI). `version` is always 3.
#[derive(Debug, Clone)]
pub struct KeyAgreeRecipientInfo {
    /// Originator side identifier / key.
    pub originator: OriginatorId,
    /// Optional UserKeyingMaterial — extra randomness mixed into the
    /// KDF on both sides. Empty `Vec` means "absent".
    pub ukm: Vec<u8>,
    /// `keyEncryptionAlgorithm` OID — names the KDF + key-wrap
    /// combination (e.g. `dhSinglePass-stdDH-sha256kdf-scheme`).
    pub key_encryption_oid: Vec<u64>,
    /// Raw `keyEncryptionAlgorithm` parameters bytes. For
    /// `dhSinglePass-stdDH-sha*-kdf` this is itself a SEQUENCE
    /// containing the key-wrap algorithm's OID + parameters.
    pub key_encryption_params: Vec<u8>,
    /// One or more recipient slots; each slot's `encryptedKey` is the
    /// CEK wrapped using the shared secret derived from the originator
    /// + recipient pair (and the `keyEncryptionAlgorithm`'s KDF).
    pub recipient_encrypted_keys: Vec<RecipientEncryptedKey>,
}

/// `RecipientInfo` CHOICE — round 12 surfaces both KTRI (RSA) and
/// KARI (DH/ECDH) variants. KEKRI (`[2] kekri`), PWRI (`[3] pwri`),
/// and ORI (`[4] ori`) are still skipped — the PDF spec does not
/// reference them and adding them would expand the threat surface
/// without serving a use case.
#[derive(Debug, Clone)]
pub enum RecipientInfoVariant {
    /// `KeyTransRecipientInfo` — RSA-based, the round-10/11 path.
    KeyTrans(KeyTransRecipientInfo),
    /// `KeyAgreeRecipientInfo` — DH/ECDH-based, round 12 decoder.
    KeyAgree(KeyAgreeRecipientInfo),
}

/// Parsed CMS `EnvelopedData` reduced to the fields the PDF public-key
/// handler consumes. Recipients of unsupported variants (`kekri`,
/// `pwri`, `ori`) are skipped over silently so a pre-existing PDF
/// written with mixed recipient types can still be opened by a
/// supported variant's user.
#[derive(Debug, Clone)]
pub struct EnvelopedData {
    /// Backwards-compatible KTRI-only view of the recipients SET. Code
    /// written against round 10/11 keeps working — only KTRI slots are
    /// surfaced through this list. Round 12 introduces [`Self::all`]
    /// for callers that want the KARI slots too.
    pub recipients: Vec<KeyTransRecipientInfo>,
    /// Round-12 view: every recognised RecipientInfo (KTRI + KARI) in
    /// declaration order. KEKRI / PWRI / ORI are still skipped.
    pub all_recipients: Vec<RecipientInfoVariant>,
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
    let mut all_recipients = Vec::new();
    let mut cursor = ri_set;
    while !cursor.is_empty() {
        let (parsed, tail) = parse_recipient_info(cursor)?;
        if let Some(p) = parsed {
            if let RecipientInfoVariant::KeyTrans(ktri) = &p {
                recipients.push(ktri.clone());
            }
            all_recipients.push(p);
        }
        cursor = tail;
    }
    if all_recipients.is_empty() {
        return Err(PdfError::other(
            "CMS: EnvelopedData has no recognised RecipientInfo entries",
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
        all_recipients,
        content_encryption,
        encrypted_content,
    })
}

/// Parse a single `RecipientInfo` element from the SET body. Returns
/// `Ok(None)` for variants this implementation doesn't recognise
/// (`[2] kekri`, `[3] pwri`, `[4] ori`); KTRI (untagged SEQUENCE) and
/// KARI (`[1]` IMPLICIT) are surfaced as separate enum arms.
fn parse_recipient_info(data: &[u8]) -> Result<(Option<RecipientInfoVariant>, &[u8]), PdfError> {
    // Peek at the tag to decide which CHOICE branch we're in.
    let (peek, peek_tail) = super::der::read_tlv(data)?;
    if peek.class == Class::ContextSpecific {
        match peek.tag_number {
            1 => {
                // [1] IMPLICIT KeyAgreeRecipientInfo — body is the
                // KARI SEQUENCE contents (the implicit tag replaces
                // the SEQUENCE's universal tag).
                let kari = parse_kari(peek.body)?;
                return Ok((Some(RecipientInfoVariant::KeyAgree(kari)), peek_tail));
            }
            // [2] kekri, [3] pwri, [4] ori — skipped silently.
            _ => return Ok((None, peek_tail)),
        }
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
            RecipientId::IssuerAndSerial(IssuerAndSerial {
                issuer_der,
                serial: serial_body.to_vec(),
            }),
            rest,
        )
    } else {
        // [0] IMPLICIT OCTET STRING — context-specific primitive
        // wrapping the recipient's SubjectKeyIdentifier (RFC 5652
        // §6.2.1). The body bytes are the raw 20-byte SHA-1 of the
        // recipient cert's `SubjectPublicKeyInfo` BIT STRING contents
        // (RFC 5280 §4.2.1.2 method 1).
        let (tlv, rest) = super::der::read_tlv(after_ver)?;
        if tlv.class != Class::ContextSpecific || tlv.tag_number != 0 {
            return Err(PdfError::other(format!(
                "CMS: KeyTransRecipientInfo[v=2] expects [0] SubjectKeyIdentifier, got class={:?} tag={}",
                tlv.class, tlv.tag_number
            )));
        }
        if tlv.constructed {
            return Err(PdfError::other(
                "CMS: SubjectKeyIdentifier must be primitive [0] IMPLICIT OCTET STRING",
            ));
        }
        (RecipientId::SubjectKeyIdentifier(tlv.body.to_vec()), rest)
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
        Some(RecipientInfoVariant::KeyTrans(KeyTransRecipientInfo {
            rid,
            key_encryption_oid: kea_oid,
            encrypted_key: enc_key.to_vec(),
        })),
        tail,
    ))
}

/// Parse the body of a `[1] IMPLICIT KeyAgreeRecipientInfo` per RFC
/// 5652 §6.2.2. The implicit tag replaces the SEQUENCE's universal
/// tag, so `data` here is the KARI's body bytes — the same shape we
/// would otherwise see *inside* a `read_sequence(...)` call.
///
/// ```asn.1
/// KeyAgreeRecipientInfo ::= SEQUENCE {
///   version                CMSVersion,                 -- always 3
///   originator         [0] EXPLICIT OriginatorIdentifierOrKey,
///   ukm                [1] EXPLICIT UserKeyingMaterial OPTIONAL,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   recipientEncryptedKeys RecipientEncryptedKeys
/// }
/// ```
fn parse_kari(data: &[u8]) -> Result<KeyAgreeRecipientInfo, PdfError> {
    let (version, body) = read_integer_u64(data)?;
    if version != 3 {
        return Err(PdfError::other(format!(
            "CMS: KeyAgreeRecipientInfo version must be 3 (got {version})"
        )));
    }
    // [0] EXPLICIT OriginatorIdentifierOrKey
    let (orig_body, body) = read_context(body, 0)?;
    let originator = parse_originator(orig_body)?;
    // [1] EXPLICIT UserKeyingMaterial OPTIONAL
    let (ukm_opt, body) = maybe_read_context(body, 1)?;
    let ukm = match ukm_opt {
        Some(b) => {
            // The UKM body is itself an OCTET STRING.
            let (ukm_bytes, rest) = read_octet_string(b)?;
            if !rest.is_empty() {
                return Err(PdfError::other(
                    "CMS: KARI ukm context wrapper has trailing bytes",
                ));
            }
            ukm_bytes.to_vec()
        }
        None => Vec::new(),
    };
    // KeyEncryptionAlgorithmIdentifier
    let (alg_body, body) = read_sequence(body)?;
    let (kea_oid, alg_params) = read_oid(alg_body)?;
    // recipientEncryptedKeys SEQUENCE OF RecipientEncryptedKey
    let (rek_body, body) = read_sequence(body)?;
    if !body.is_empty() {
        return Err(PdfError::other(
            "CMS: KARI has trailing bytes after recipientEncryptedKeys",
        ));
    }
    let mut recipient_encrypted_keys = Vec::new();
    let mut cursor = rek_body;
    while !cursor.is_empty() {
        let (rek, tail) = parse_recipient_encrypted_key(cursor)?;
        recipient_encrypted_keys.push(rek);
        cursor = tail;
    }
    if recipient_encrypted_keys.is_empty() {
        return Err(PdfError::other("CMS: KARI recipientEncryptedKeys is empty"));
    }
    Ok(KeyAgreeRecipientInfo {
        originator,
        ukm,
        key_encryption_oid: kea_oid,
        key_encryption_params: alg_params.to_vec(),
        recipient_encrypted_keys,
    })
}

/// Parse `OriginatorIdentifierOrKey` (RFC 5652 §6.2.2).
///
/// ```asn.1
/// OriginatorIdentifierOrKey ::= CHOICE {
///   issuerAndSerialNumber  IssuerAndSerialNumber,
///   subjectKeyIdentifier  [0] SubjectKeyIdentifier,
///   originatorKey         [1] OriginatorPublicKey
/// }
/// ```
fn parse_originator(data: &[u8]) -> Result<OriginatorId, PdfError> {
    let (peek, _) = super::der::read_tlv(data)?;
    if peek.class == Class::ContextSpecific {
        match peek.tag_number {
            0 => {
                // [0] IMPLICIT SubjectKeyIdentifier (OCTET STRING).
                if peek.constructed {
                    return Err(PdfError::other(
                        "CMS: KARI originator [0] SKI must be primitive",
                    ));
                }
                Ok(OriginatorId::SubjectKeyIdentifier(peek.body.to_vec()))
            }
            1 => {
                // [1] IMPLICIT OriginatorPublicKey — body is the SPKI
                // SEQUENCE contents.
                let opk = parse_originator_public_key(peek.body)?;
                Ok(OriginatorId::OriginatorKey(opk))
            }
            other => Err(PdfError::other(format!(
                "CMS: KARI originator unknown context-tag {other}"
            ))),
        }
    } else {
        // Untagged SEQUENCE — IssuerAndSerialNumber.
        let (ias_body, rest) = read_sequence(data)?;
        if !rest.is_empty() {
            return Err(PdfError::other(
                "CMS: KARI originator IAS has trailing bytes",
            ));
        }
        let (issuer_tlv, ias_after_issuer) = super::der::read_tlv(ias_body)?;
        if issuer_tlv.class != Class::Universal
            || issuer_tlv.tag_number != super::der::tag::SEQUENCE
        {
            return Err(PdfError::other(
                "CMS: KARI originator IAS issuer must be a SEQUENCE",
            ));
        }
        let issuer_total = ias_body.len() - ias_after_issuer.len();
        let issuer_der = ias_body[..issuer_total].to_vec();
        let (serial_body, _) = read_integer_bytes(ias_after_issuer)?;
        Ok(OriginatorId::IssuerAndSerial(IssuerAndSerial {
            issuer_der,
            serial: serial_body.to_vec(),
        }))
    }
}

/// Parse `OriginatorPublicKey` (RFC 5652 §6.2.2). Body shape is
/// `SEQUENCE { algorithm AlgorithmIdentifier, publicKey BIT STRING }`.
fn parse_originator_public_key(data: &[u8]) -> Result<OriginatorPublicKey, PdfError> {
    let (alg_body, after_alg) = read_sequence(data)?;
    let (alg_oid, alg_params) = read_oid(alg_body)?;
    // BIT STRING — body has a leading unused-bits byte we drop.
    let (bs, rest) = super::der::read_tlv(after_alg)?;
    if bs.class != Class::Universal || bs.tag_number != super::der::tag::BIT_STRING {
        return Err(PdfError::other(
            "CMS: KARI OriginatorPublicKey expects BIT STRING for publicKey",
        ));
    }
    if !rest.is_empty() {
        return Err(PdfError::other(
            "CMS: KARI OriginatorPublicKey has trailing bytes",
        ));
    }
    if bs.body.is_empty() {
        return Err(PdfError::other(
            "CMS: KARI OriginatorPublicKey BIT STRING empty",
        ));
    }
    Ok(OriginatorPublicKey {
        algorithm_oid: alg_oid,
        algorithm_params: alg_params.to_vec(),
        public_key: bs.body[1..].to_vec(),
    })
}

/// Parse one `RecipientEncryptedKey` (RFC 5652 §6.2.2).
///
/// ```asn.1
/// RecipientEncryptedKey ::= SEQUENCE {
///   rid          KeyAgreeRecipientIdentifier,
///   encryptedKey EncryptedKey
/// }
/// KeyAgreeRecipientIdentifier ::= CHOICE {
///   issuerAndSerialNumber  IssuerAndSerialNumber,
///   rKeyId             [0] IMPLICIT RecipientKeyIdentifier
/// }
/// RecipientKeyIdentifier ::= SEQUENCE {
///   subjectKeyIdentifier SubjectKeyIdentifier,
///   date GeneralizedTime OPTIONAL,
///   other OtherKeyAttribute OPTIONAL
/// }
/// ```
fn parse_recipient_encrypted_key(data: &[u8]) -> Result<(RecipientEncryptedKey, &[u8]), PdfError> {
    let (rek_body, tail) = read_sequence(data)?;
    let (peek, _) = super::der::read_tlv(rek_body)?;
    let (rid, after_rid) = if peek.class == Class::ContextSpecific && peek.tag_number == 0 {
        // [0] IMPLICIT RecipientKeyIdentifier — body is the RKID's
        // SEQUENCE contents. Consume the [0] TLV from the parent
        // body to compute `after`, then peel its body for the SKI.
        let (rkid_tlv, after) = super::der::read_tlv(rek_body)?;
        let (ski, _ignored) = read_octet_string(rkid_tlv.body)?;
        // The rest of the RKID body (date / other) is skipped — the
        // PDF public-key handler doesn't consume it.
        (
            KeyAgreeRecipientId::RecipientKeyIdentifier { ski: ski.to_vec() },
            after,
        )
    } else {
        // Untagged SEQUENCE → IssuerAndSerialNumber.
        let (ias_body, after) = read_sequence(rek_body)?;
        let (issuer_tlv, ias_after_issuer) = super::der::read_tlv(ias_body)?;
        if issuer_tlv.class != Class::Universal
            || issuer_tlv.tag_number != super::der::tag::SEQUENCE
        {
            return Err(PdfError::other(
                "CMS: KARI REK IAS issuer must be a SEQUENCE",
            ));
        }
        let issuer_total = ias_body.len() - ias_after_issuer.len();
        let issuer_der = ias_body[..issuer_total].to_vec();
        let (serial_body, _) = read_integer_bytes(ias_after_issuer)?;
        (
            KeyAgreeRecipientId::IssuerAndSerial(IssuerAndSerial {
                issuer_der,
                serial: serial_body.to_vec(),
            }),
            after,
        )
    };
    let (enc_key, after_key) = read_octet_string(after_rid)?;
    if !after_key.is_empty() {
        return Err(PdfError::other(
            "CMS: KARI RecipientEncryptedKey has trailing bytes",
        ));
    }
    Ok((
        RecipientEncryptedKey {
            rid,
            encrypted_key: enc_key.to_vec(),
        },
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
    } else if oid == OID_RC2_CBC {
        // Round-17: RC2-CBC. Parameters per RFC 3370 §5.1:
        //   RC2CBCParameter ::= SEQUENCE {
        //     rc2ParameterVersion INTEGER (0..255) DEFAULT 32,  -- effective-key version
        //     iv OCTET STRING (size 8)
        //   }
        // Some legacy writers omit the parameter version; treat that as
        // the DEFAULT 32 (mapped per RFC 2268 §6 to 32 effective bits).
        // Other writers wrap params as a bare OCTET STRING (RFC 2268
        // §6 wire form) — accept both.
        let (param_seq, after_seq) = match read_sequence(params) {
            Ok(parts) => parts,
            Err(_) => {
                // Bare OCTET STRING fallback (RFC 2268 §6).
                let (iv_bytes, _) = read_octet_string(params)?;
                if iv_bytes.len() != 8 {
                    return Err(PdfError::other(format!(
                        "CMS: RC2-CBC bare-OCTET-STRING IV must be 8 bytes (got {})",
                        iv_bytes.len()
                    )));
                }
                let mut iv_arr = [0u8; 8];
                iv_arr.copy_from_slice(iv_bytes);
                return Ok(ContentEncryption::Rc2Cbc {
                    effective_key_bits: 32,
                    iv: iv_arr,
                });
            }
        };
        let _ = after_seq;
        // SEQUENCE-wrapped params: optional INTEGER (rc2ParameterVersion),
        // mandatory OCTET STRING (iv).
        let mut cursor = param_seq;
        let mut effective_key_bits = 32u32;
        let (peek, _) = super::der::read_tlv(cursor)?;
        if peek.class == super::der::Class::Universal && peek.tag_number == super::der::tag::INTEGER
        {
            let (vers_u64, after) = read_integer_u64(cursor)?;
            // RFC 2268 §6 mapping: 160 → 40 bits, 120 → 64 bits, 58 →
            // 128 bits. Other values pass through as the literal
            // effective-key bit count (RFC 3370 §5.1's 32 default).
            effective_key_bits = match vers_u64 {
                160 => 40,
                120 => 64,
                58 => 128,
                v if v <= 255 => v as u32,
                _ => {
                    return Err(PdfError::other(format!(
                        "CMS: RC2 rc2ParameterVersion {vers_u64} out of range (RFC 2268 §6)"
                    )))
                }
            };
            cursor = after;
        }
        let (iv_bytes, rest) = read_octet_string(cursor)?;
        if !rest.is_empty() {
            return Err(PdfError::other(
                "CMS: RC2-CBC parameters trailing bytes after IV",
            ));
        }
        if iv_bytes.len() != 8 {
            return Err(PdfError::other(format!(
                "CMS: RC2-CBC IV must be 8 bytes (got {})",
                iv_bytes.len()
            )));
        }
        let mut iv_arr = [0u8; 8];
        iv_arr.copy_from_slice(iv_bytes);
        Ok(ContentEncryption::Rc2Cbc {
            effective_key_bits,
            iv: iv_arr,
        })
    } else if oid == OID_DES_EDE3_CBC {
        // Round-17: 3DES-CBC. Parameters per RFC 3370 §5.2 / RFC 5652
        // §12.4: OCTET STRING (size 8) — the 8-byte CBC IV.
        let (iv_bytes, _) = read_octet_string(params)?;
        if iv_bytes.len() != 8 {
            return Err(PdfError::other(format!(
                "CMS: DES-EDE3-CBC IV must be 8 bytes (got {})",
                iv_bytes.len()
            )));
        }
        let mut iv_arr = [0u8; 8];
        iv_arr.copy_from_slice(iv_bytes);
        Ok(ContentEncryption::DesEde3Cbc { iv: iv_arr })
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
        let recipient =
            RecipientPlain::ias(issuer_der.clone(), vec![0x01, 0x02, 0x03], vec![0xAA; 256]);
        let plaintext =
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13";
        let envelope = build_envelope_aes256(&[recipient], plaintext, &[0xBBu8; 32], &[0xCCu8; 16]);
        let parsed = parse_envelope(&envelope).expect("parse envelope");
        assert_eq!(parsed.recipients.len(), 1);
        match &parsed.recipients[0].rid {
            super::RecipientId::IssuerAndSerial(ias) => {
                assert_eq!(ias.serial, vec![0x01, 0x02, 0x03]);
                assert_eq!(ias.issuer_der, issuer_der);
            }
            other => panic!("unexpected rid: {other:?}"),
        }
        match parsed.content_encryption {
            ContentEncryption::Aes256Cbc { iv } => assert_eq!(iv, [0xCC; 16]),
            _ => panic!("expected AES256CBC"),
        }
    }
}
