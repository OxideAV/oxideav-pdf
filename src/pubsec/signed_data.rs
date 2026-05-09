//! CMS `SignedData` (RFC 5652 §5) parser scaffolding for PDF
//! digital-signature payloads (ISO 32000-1 §12.8 + ETSI EN 319 142
//! PAdES profiles).
//!
//! Round-19 ships the parser + typed accessors only — signature
//! verification (hash-then-RSA / ECDSA dispatch per
//! `digestAlgorithm` + `signatureAlgorithm`) is deferred to a follow-up
//! round. Today's surface lets callers:
//!
//! * Pull a PDF signature blob (typically the bytes between the
//!   `Contents <` and `>` of a `/Sig` annotation, hex-decoded) into a
//!   structurally-parsed [`SignedData`] value.
//! * Inspect the embedded certificate set (`certs[]`), the per-signer
//!   identifier (IAS / SKI), and the signed/unsigned attribute lists.
//! * Recover the encapsulated content body when present (detached
//!   signatures — by far the most common shape in PAdES — leave
//!   `encap_content_octets` empty; the bytes to verify are then the
//!   PDF byte ranges named in the `/ByteRange` array).
//!
//! ```asn.1
//! SignedData ::= SEQUENCE {
//!   version              CMSVersion,
//!   digestAlgorithms     SET OF DigestAlgorithmIdentifier,
//!   encapContentInfo     EncapsulatedContentInfo,
//!   certificates     [0] IMPLICIT CertificateSet OPTIONAL,
//!   crls             [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//!   signerInfos          SET OF SignerInfo
//! }
//!
//! EncapsulatedContentInfo ::= SEQUENCE {
//!   eContentType   OBJECT IDENTIFIER,
//!   eContent   [0] EXPLICIT OCTET STRING OPTIONAL
//! }
//!
//! SignerInfo ::= SEQUENCE {
//!   version              CMSVersion,
//!   sid                  SignerIdentifier,
//!   digestAlgorithm      DigestAlgorithmIdentifier,
//!   signedAttrs      [0] IMPLICIT SignedAttributes OPTIONAL,
//!   signatureAlgorithm   SignatureAlgorithmIdentifier,
//!   signature            SignatureValue,
//!   unsignedAttrs    [1] IMPLICIT UnsignedAttributes OPTIONAL
//! }
//! ```
//!
//! Provenance: RFC 5652 §5 (CMS SignedData) + RFC 5126 §5 (CAdES
//! signed-attributes layout) + RFC 5280 §4 (CertificateChoices) +
//! ISO 32000-1 §12.8.3.3 (PDF signature handler interaction).

use crate::error::PdfError;

use super::cms::{IssuerAndSerial, OID_SIGNED_DATA};
use super::der::{
    maybe_read_context, read_context, read_expected, read_integer_bytes, read_integer_u64,
    read_octet_string, read_oid, read_sequence, read_set, read_tlv, tag, Class,
};

/// `SignerIdentifier` (RFC 5652 §5.3) — the CHOICE that picks between
/// `IssuerAndSerialNumber` (CMS v1) and `[0] SubjectKeyIdentifier`
/// (CMS v3). Same shape as the EnvelopedData KTRI's
/// [`super::cms::RecipientId`] but distinguished by name to keep the
/// type contracts on each side independent.
#[derive(Debug, Clone)]
pub enum SignerIdentifier {
    /// `IssuerAndSerialNumber` — CMS SignerInfo v1.
    IssuerAndSerial(IssuerAndSerial),
    /// `[0] SubjectKeyIdentifier` — CMS SignerInfo v3. The 20-byte
    /// SHA-1 of the signer cert's `SubjectPublicKeyInfo` BIT STRING
    /// contents (RFC 5280 §4.2.1.2 method 1).
    SubjectKeyIdentifier(Vec<u8>),
}

/// One `Attribute` (RFC 5652 §5.3) — `(attr_type, attr_values)`. The
/// values are surfaced as raw DER bytes so a caller can re-parse per
/// the OID's contract without the scaffolding having to know every
/// signed-attribute schema in CAdES / PAdES / RFC 9216.
#[derive(Debug, Clone)]
pub struct Attribute {
    /// `attrType` OID arcs.
    pub oid: Vec<u64>,
    /// Raw DER bytes of each `attrValues` SET element. Each entry is
    /// the bytes of one full TLV (tag + length + body), so the caller
    /// can re-parse with [`super::der::read_tlv`].
    pub values: Vec<Vec<u8>>,
}

/// One `SignerInfo` slot inside the `SignedData.signerInfos` SET.
///
/// Round-19 keeps the surface inspection-only — the bytes that would
/// feed signature verification are all surfaced (digest_algorithm OID,
/// signature_algorithm OID, raw signature octet string), but no verify
/// helper is implemented this round.
#[derive(Debug, Clone)]
pub struct SignerInfo {
    /// CMS SignerInfo version — 1 (IAS) or 3 (SKI).
    pub version: u64,
    /// Signer identifier — IAS (v1) or SKI (v3).
    pub sid: SignerIdentifier,
    /// `digestAlgorithm` OID arcs (e.g. SHA-256 = 2.16.840.1.101.3.4.2.1).
    pub digest_algorithm_oid: Vec<u64>,
    /// `digestAlgorithm` raw parameter bytes (typically a NULL or
    /// absent — we surface what was on the wire so a caller can
    /// distinguish encodings).
    pub digest_algorithm_params: Vec<u8>,
    /// OPTIONAL signed attributes (`[0] IMPLICIT SET OF Attribute`).
    /// Per RFC 5652 §5.3, when present the signature is computed over
    /// the DER encoding of the SignedAttributes SET (with universal
    /// SET tag, NOT the implicit `[0]` tag — RFC 5652 §5.4).
    /// Empty vec means "absent".
    pub signed_attrs: Vec<Attribute>,
    /// **Round-19 verification helper** — when `signed_attrs` was
    /// present on the wire, this carries the raw DER body of the
    /// `[0] IMPLICIT` SET. The verifier needs to re-encode this with
    /// the universal SET tag (0x31) before hashing per RFC 5652 §5.4
    /// — to make that mechanical, we store the body bytes here and
    /// the re-tagging happens in the verify dispatch (deferred).
    /// `None` when `signed_attrs` was absent.
    pub signed_attrs_der: Option<Vec<u8>>,
    /// `signatureAlgorithm` OID arcs (e.g. RSAES-PKCS1-v1.5 =
    /// 1.2.840.113549.1.1.1, ECDSA-with-SHA256 = 1.2.840.10045.4.3.2).
    pub signature_algorithm_oid: Vec<u64>,
    /// `signatureAlgorithm` raw parameter bytes.
    pub signature_algorithm_params: Vec<u8>,
    /// `signature` OCTET STRING — the actual signature octets the
    /// verifier checks against the digest of the signed bytes.
    pub signature: Vec<u8>,
    /// OPTIONAL unsigned attributes (`[1] IMPLICIT SET OF Attribute`).
    pub unsigned_attrs: Vec<Attribute>,
}

/// Parsed CMS `SignedData` reduced to the fields a PDF signature
/// reader needs.
#[derive(Debug, Clone)]
pub struct SignedData {
    /// CMS SignedData version — 1, 3, 4, or 5 (RFC 5652 §5.1).
    pub version: u64,
    /// `digestAlgorithms` SET — each entry is (oid_arcs, params_raw_bytes).
    pub digest_algorithms: Vec<(Vec<u64>, Vec<u8>)>,
    /// `encapContentInfo.eContentType` OID arcs. For attached PDF
    /// signatures this is `id-data` (1.2.840.113549.1.7.1); for
    /// detached PAdES signatures it's still `id-data` but the
    /// `eContent` octets are absent — the bytes to verify are the
    /// PDF byte ranges in `/ByteRange`.
    pub encap_content_type: Vec<u64>,
    /// `encapContentInfo.eContent` octets — `Some(bytes)` for
    /// attached signatures, `None` when omitted (typical PAdES /
    /// detached). The bytes here are the OCTET STRING body — no DER
    /// header, no `[0]` wrapper.
    pub encap_content_octets: Option<Vec<u8>>,
    /// `certificates[0] IMPLICIT CertificateSet OPTIONAL` — each
    /// entry is the raw DER bytes of one `CertificateChoices`
    /// alternative (typically an X.509 v3 SEQUENCE; we surface every
    /// alternative shape as opaque DER so the caller can dispatch on
    /// the outer tag). Empty vec when the field was absent.
    pub certs: Vec<Vec<u8>>,
    /// `crls[1] IMPLICIT RevocationInfoChoices OPTIONAL` — each
    /// entry is the raw DER bytes of one `RevocationInfoChoices`
    /// alternative (typically an X.509 `CertificateList` SEQUENCE).
    /// Empty vec when the field was absent.
    pub crls: Vec<Vec<u8>>,
    /// `signerInfos SET OF SignerInfo` — typically one entry for a
    /// single-signer PDF, but the spec permits multiple.
    pub signer_infos: Vec<SignerInfo>,
}

/// Parse a CMS `ContentInfo` whose `contentType` is `id-signedData`
/// (`1.2.840.113549.1.7.2`), returning the inner [`SignedData`].
///
/// Round-19 entry point — symmetric to
/// [`super::cms::parse_envelope`] for the EnvelopedData side.
pub fn parse_signed_data(data: &[u8]) -> Result<SignedData, PdfError> {
    let (body, rest) = read_sequence(data)?;
    if !rest.is_empty() {
        return Err(PdfError::other(
            "CMS SignedData: trailing bytes after ContentInfo SEQUENCE",
        ));
    }
    let (oid, rest) = read_oid(body)?;
    if oid != OID_SIGNED_DATA {
        return Err(PdfError::other(format!(
            "CMS SignedData: ContentInfo contentType must be id-signedData (got {oid:?})"
        )));
    }
    let (content, rest) = read_context(rest, 0)?;
    if !rest.is_empty() {
        return Err(PdfError::other(
            "CMS SignedData: trailing bytes after [0] EXPLICIT content",
        ));
    }
    parse_signed_data_inner(content)
}

/// Parse a bare `SignedData` SEQUENCE (no surrounding ContentInfo).
pub fn parse_signed_data_inner(data: &[u8]) -> Result<SignedData, PdfError> {
    let (body, rest) = read_sequence(data)?;
    if !rest.is_empty() {
        return Err(PdfError::other(
            "CMS SignedData: trailing bytes after SignedData SEQUENCE",
        ));
    }
    let (version, body) = read_integer_u64(body)?;
    if version > 5 {
        return Err(PdfError::other(format!(
            "CMS SignedData: unsupported version {version}"
        )));
    }
    // digestAlgorithms SET OF AlgorithmIdentifier.
    let (da_set, body) = read_set(body)?;
    let mut digest_algorithms: Vec<(Vec<u64>, Vec<u8>)> = Vec::new();
    let mut cursor = da_set;
    while !cursor.is_empty() {
        let (alg_seq, after) = read_sequence(cursor)?;
        let (alg_oid, alg_params) = read_oid(alg_seq)?;
        digest_algorithms.push((alg_oid, alg_params.to_vec()));
        cursor = after;
    }

    // EncapsulatedContentInfo ::= SEQUENCE {
    //   eContentType OBJECT IDENTIFIER,
    //   eContent [0] EXPLICIT OCTET STRING OPTIONAL
    // }
    let (eci, body) = read_sequence(body)?;
    let (eci_oid, eci_rest) = read_oid(eci)?;
    let (eci_econtent_opt, eci_rest) = maybe_read_context(eci_rest, 0)?;
    if !eci_rest.is_empty() {
        return Err(PdfError::other(
            "CMS SignedData: trailing bytes after EncapsulatedContentInfo",
        ));
    }
    let encap_content_octets = match eci_econtent_opt {
        Some(b) => {
            // `[0] EXPLICIT OCTET STRING` — body of the [0] wrapper is
            // a universal OCTET STRING TLV. Some legacy PAdES emit the
            // body as the raw octets directly (without the inner OCTET
            // STRING wrapper); we accept either form.
            if let Ok((tlv, rest_inner)) = read_tlv(b) {
                if rest_inner.is_empty()
                    && tlv.class == Class::Universal
                    && tlv.tag_number == tag::OCTET_STRING
                {
                    Some(tlv.body.to_vec())
                } else {
                    Some(b.to_vec())
                }
            } else {
                Some(b.to_vec())
            }
        }
        None => None,
    };

    // certificates [0] IMPLICIT CertificateSet OPTIONAL
    let mut cursor = body;
    let mut certs: Vec<Vec<u8>> = Vec::new();
    if !cursor.is_empty() {
        let (peek, _) = read_tlv(cursor)?;
        if peek.class == Class::ContextSpecific && peek.tag_number == 0 {
            let (set_body, after) = read_tlv(cursor)?;
            certs = split_set_into_raw_entries(set_body.body)?;
            cursor = after;
        }
    }
    // crls [1] IMPLICIT RevocationInfoChoices OPTIONAL
    let mut crls: Vec<Vec<u8>> = Vec::new();
    if !cursor.is_empty() {
        let (peek, _) = read_tlv(cursor)?;
        if peek.class == Class::ContextSpecific && peek.tag_number == 1 {
            let (set_body, after) = read_tlv(cursor)?;
            crls = split_set_into_raw_entries(set_body.body)?;
            cursor = after;
        }
    }

    // signerInfos SET OF SignerInfo.
    let (si_set, after_si) = read_set(cursor)?;
    if !after_si.is_empty() {
        return Err(PdfError::other(
            "CMS SignedData: trailing bytes after signerInfos SET",
        ));
    }
    let mut signer_infos: Vec<SignerInfo> = Vec::new();
    let mut si_cursor = si_set;
    while !si_cursor.is_empty() {
        let (info, tail) = parse_signer_info(si_cursor)?;
        signer_infos.push(info);
        si_cursor = tail;
    }
    if signer_infos.is_empty() {
        return Err(PdfError::other(
            "CMS SignedData: signerInfos SET must contain at least one SignerInfo",
        ));
    }

    Ok(SignedData {
        version,
        digest_algorithms,
        encap_content_type: eci_oid,
        encap_content_octets,
        certs,
        crls,
        signer_infos,
    })
}

/// Parse one `SignerInfo` SEQUENCE per RFC 5652 §5.3.
fn parse_signer_info(data: &[u8]) -> Result<(SignerInfo, &[u8]), PdfError> {
    let (body, tail) = read_sequence(data)?;
    let (version, body) = read_integer_u64(body)?;
    if version != 1 && version != 3 {
        return Err(PdfError::other(format!(
            "CMS SignedData: unsupported SignerInfo version {version} (expected 1 or 3)"
        )));
    }
    // SignerIdentifier — same CHOICE shape as RecipientIdentifier.
    let (sid, body) = if version == 1 {
        let (ias_body, rest) = read_sequence(body)?;
        let (issuer_tlv, ias_after_issuer) = read_tlv(ias_body)?;
        if issuer_tlv.class != Class::Universal || issuer_tlv.tag_number != tag::SEQUENCE {
            return Err(PdfError::other(
                "CMS SignedData: SignerInfo IAS issuer must be a SEQUENCE",
            ));
        }
        let issuer_total = ias_body.len() - ias_after_issuer.len();
        let issuer_der = ias_body[..issuer_total].to_vec();
        let (serial_body, _) = read_integer_bytes(ias_after_issuer)?;
        (
            SignerIdentifier::IssuerAndSerial(IssuerAndSerial {
                issuer_der,
                serial: serial_body.to_vec(),
            }),
            rest,
        )
    } else {
        // [0] IMPLICIT OCTET STRING (SubjectKeyIdentifier).
        let (tlv, rest) = read_tlv(body)?;
        if tlv.class != Class::ContextSpecific || tlv.tag_number != 0 {
            return Err(PdfError::other(format!(
                "CMS SignedData: SignerInfo[v=3] expects [0] SubjectKeyIdentifier (got class={:?} tag={})",
                tlv.class, tlv.tag_number
            )));
        }
        if tlv.constructed {
            return Err(PdfError::other(
                "CMS SignedData: SignerInfo SKI must be primitive [0] IMPLICIT OCTET STRING",
            ));
        }
        (
            SignerIdentifier::SubjectKeyIdentifier(tlv.body.to_vec()),
            rest,
        )
    };

    // digestAlgorithm AlgorithmIdentifier
    let (da_seq, body) = read_sequence(body)?;
    let (da_oid, da_params) = read_oid(da_seq)?;
    let digest_algorithm_oid = da_oid;
    let digest_algorithm_params = da_params.to_vec();

    // [0] IMPLICIT signedAttrs SET OF Attribute OPTIONAL.
    let mut cursor = body;
    let mut signed_attrs: Vec<Attribute> = Vec::new();
    let mut signed_attrs_der: Option<Vec<u8>> = None;
    if !cursor.is_empty() {
        let (peek, _) = read_tlv(cursor)?;
        if peek.class == Class::ContextSpecific && peek.tag_number == 0 {
            let (sa_tlv, after) = read_tlv(cursor)?;
            signed_attrs_der = Some(sa_tlv.body.to_vec());
            signed_attrs = split_attributes(sa_tlv.body)?;
            cursor = after;
        }
    }

    // signatureAlgorithm AlgorithmIdentifier
    let (sa_seq, body) = read_sequence(cursor)?;
    let (sa_oid, sa_params) = read_oid(sa_seq)?;
    let signature_algorithm_oid = sa_oid;
    let signature_algorithm_params = sa_params.to_vec();

    // signature OCTET STRING
    let (sig_bytes, body) = read_octet_string(body)?;
    let signature = sig_bytes.to_vec();

    // [1] IMPLICIT unsignedAttrs SET OF Attribute OPTIONAL
    let mut cursor = body;
    let mut unsigned_attrs: Vec<Attribute> = Vec::new();
    if !cursor.is_empty() {
        let (peek, _) = read_tlv(cursor)?;
        if peek.class == Class::ContextSpecific && peek.tag_number == 1 {
            let (ua_tlv, after) = read_tlv(cursor)?;
            unsigned_attrs = split_attributes(ua_tlv.body)?;
            cursor = after;
        }
    }
    if !cursor.is_empty() {
        return Err(PdfError::other(
            "CMS SignedData: trailing bytes after SignerInfo body",
        ));
    }

    Ok((
        SignerInfo {
            version,
            sid,
            digest_algorithm_oid,
            digest_algorithm_params,
            signed_attrs,
            signed_attrs_der,
            signature_algorithm_oid,
            signature_algorithm_params,
            signature,
            unsigned_attrs,
        },
        tail,
    ))
}

/// Decompose a SET-of-Attribute body into a Vec of typed attributes.
fn split_attributes(body: &[u8]) -> Result<Vec<Attribute>, PdfError> {
    let mut out = Vec::new();
    let mut cursor = body;
    while !cursor.is_empty() {
        let (attr_seq, after) = read_sequence(cursor)?;
        let (oid, attr_rest) = read_oid(attr_seq)?;
        // attrValues SET OF AttributeValue.
        let (set_tlv, after_set) = read_expected(attr_rest, Class::Universal, tag::SET)?;
        if !after_set.is_empty() {
            return Err(PdfError::other(
                "CMS SignedData: Attribute has trailing bytes after attrValues SET",
            ));
        }
        // Split the SET body into raw entries.
        let mut values: Vec<Vec<u8>> = Vec::new();
        let mut vcursor = set_tlv.body;
        while !vcursor.is_empty() {
            let before = vcursor.len();
            let (_tlv, after_v) = read_tlv(vcursor)?;
            let consumed = before - after_v.len();
            values.push(vcursor[..consumed].to_vec());
            vcursor = after_v;
        }
        out.push(Attribute { oid, values });
        cursor = after;
    }
    Ok(out)
}

/// Split a SET body (or any concatenation of TLVs) into a Vec where
/// each entry is the raw DER bytes (tag + length + body) of one TLV.
/// Mirrors [`super::cms::parse_originator_info`]'s helper for the
/// `certs[]` / `crls[]` arms.
fn split_set_into_raw_entries(set_body: &[u8]) -> Result<Vec<Vec<u8>>, PdfError> {
    let mut out = Vec::new();
    let mut cursor = set_body;
    while !cursor.is_empty() {
        let before_len = cursor.len();
        let (_tlv, after) = read_tlv(cursor)?;
        let consumed = before_len - after.len();
        out.push(cursor[..consumed].to_vec());
        cursor = after;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubsec::der;

    /// Hand-build a minimal SignedData ContentInfo with one IAS signer
    /// and an attached `eContent` octets payload, then re-parse it.
    /// Exercises the "v=1 IAS, signed attrs absent, eContent attached"
    /// branch — the simplest case the parser handles end-to-end.
    #[test]
    fn parse_minimal_signed_data_v1_ias() {
        let issuer_der = der::write_sequence(b"O=Round-19 Signer");
        let serial = vec![0x01, 0x42];
        let digest_oid = vec![2u64, 16, 840, 1, 101, 3, 4, 2, 1]; // sha256
        let signature_oid = vec![1u64, 2, 840, 113549, 1, 1, 1]; // rsaEncryption
        let signature_bytes = vec![0xAAu8; 256];

        // SignerInfo body
        let mut si_body = der::write_integer_u64(1); // v1
        let ias_body = {
            let mut b = issuer_der.clone();
            b.extend_from_slice(&der::write_integer_bytes(&serial));
            b
        };
        si_body.extend_from_slice(&der::write_sequence(&ias_body));
        // digestAlgorithm
        let da_alg = {
            let mut b = der::write_oid(&digest_oid);
            b.extend_from_slice(&der::write_null());
            der::write_sequence(&b)
        };
        si_body.extend_from_slice(&da_alg);
        // signatureAlgorithm
        let sig_alg = {
            let mut b = der::write_oid(&signature_oid);
            b.extend_from_slice(&der::write_null());
            der::write_sequence(&b)
        };
        si_body.extend_from_slice(&sig_alg);
        // signature OCTET STRING
        si_body.extend_from_slice(&der::write_octet_string(&signature_bytes));
        let signer_info = der::write_sequence(&si_body);

        // digestAlgorithms SET
        let da_set = der::write_set(&da_alg);

        // EncapsulatedContentInfo
        let payload = b"OXIDEAV-attached-econtent-bytes";
        let eci_body = {
            let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 1]); // id-data
                                                                          // [0] EXPLICIT OCTET STRING
            let octet = der::write_octet_string(payload);
            b.extend_from_slice(&der::write_context_constructed(0, &octet));
            b
        };
        let eci = der::write_sequence(&eci_body);

        // signerInfos SET
        let si_set = der::write_set(&signer_info);

        // SignedData SEQUENCE
        let mut sd_body = der::write_integer_u64(1);
        sd_body.extend_from_slice(&da_set);
        sd_body.extend_from_slice(&eci);
        sd_body.extend_from_slice(&si_set);
        let sd = der::write_sequence(&sd_body);

        // Outer ContentInfo
        let outer_body = {
            let mut b = der::write_oid(&OID_SIGNED_DATA);
            b.extend_from_slice(&der::write_context_constructed(0, &sd));
            b
        };
        let envelope = der::write_sequence(&outer_body);

        let parsed = parse_signed_data(&envelope).expect("parse SignedData");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.digest_algorithms.len(), 1);
        assert_eq!(parsed.digest_algorithms[0].0, digest_oid);
        assert_eq!(parsed.encap_content_type, vec![1, 2, 840, 113549, 1, 7, 1]);
        assert_eq!(parsed.encap_content_octets.as_deref(), Some(&payload[..]));
        assert!(parsed.certs.is_empty());
        assert!(parsed.crls.is_empty());
        assert_eq!(parsed.signer_infos.len(), 1);
        let si = &parsed.signer_infos[0];
        assert_eq!(si.version, 1);
        match &si.sid {
            SignerIdentifier::IssuerAndSerial(ias) => {
                assert_eq!(ias.issuer_der, issuer_der);
                assert_eq!(ias.serial, serial);
            }
            other => panic!("expected IAS got {other:?}"),
        }
        assert_eq!(si.digest_algorithm_oid, digest_oid);
        assert_eq!(si.signature_algorithm_oid, signature_oid);
        assert_eq!(si.signature, signature_bytes);
        assert!(si.signed_attrs.is_empty());
        assert!(si.signed_attrs_der.is_none());
        assert!(si.unsigned_attrs.is_empty());
    }

    /// SignedData with one v=3 SKI signer + signed attrs — exercises
    /// the optional `[0] IMPLICIT SET OF Attribute` parse + the SKI
    /// SignerIdentifier branch.
    #[test]
    fn parse_signed_data_v3_ski_with_signed_attrs() {
        let signer_ski = vec![0xCDu8; 20];
        let digest_oid = vec![2u64, 16, 840, 1, 101, 3, 4, 2, 1]; // sha256
        let signature_oid = vec![1u64, 2, 840, 10045, 4, 3, 2]; // ecdsa-with-SHA256
        let signature_bytes = vec![0xBBu8; 72];

        // signedAttr: contentType = id-data
        let attr_oid = vec![1u64, 2, 840, 113549, 1, 9, 3]; // contentType
        let attr_value = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 1]); // id-data
        let attr_seq_body = {
            let mut b = der::write_oid(&attr_oid);
            b.extend_from_slice(&der::write_set(&attr_value));
            b
        };
        let attr_seq = der::write_sequence(&attr_seq_body);
        // signedAttrs is `[0] IMPLICIT SET OF Attribute` — emit a
        // context-specific constructed [0] wrapping the SET body
        // (the IMPLICIT replaces the universal SET tag).
        let signed_attrs_implicit_body = attr_seq.clone();
        let signed_attrs_tlv = der::write_tlv(
            der::Class::ContextSpecific,
            true,
            0,
            &signed_attrs_implicit_body,
        );

        // SignerInfo
        let mut si_body = der::write_integer_u64(3); // v3
                                                     // [0] IMPLICIT SubjectKeyIdentifier (OCTET STRING) — primitive context-specific.
        si_body.extend_from_slice(&der::write_context_primitive(0, &signer_ski));
        let da_alg = {
            let mut b = der::write_oid(&digest_oid);
            b.extend_from_slice(&der::write_null());
            der::write_sequence(&b)
        };
        si_body.extend_from_slice(&da_alg);
        si_body.extend_from_slice(&signed_attrs_tlv);
        let sig_alg = {
            let mut b = der::write_oid(&signature_oid);
            b.extend_from_slice(&der::write_null());
            der::write_sequence(&b)
        };
        si_body.extend_from_slice(&sig_alg);
        si_body.extend_from_slice(&der::write_octet_string(&signature_bytes));
        let signer_info = der::write_sequence(&si_body);

        let da_set = der::write_set(&da_alg);
        // No eContent — detached signature shape.
        let eci_body = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 1]);
        let eci = der::write_sequence(&eci_body);
        let si_set = der::write_set(&signer_info);

        let mut sd_body = der::write_integer_u64(3); // v3 since signers use v3
        sd_body.extend_from_slice(&da_set);
        sd_body.extend_from_slice(&eci);
        sd_body.extend_from_slice(&si_set);
        let sd = der::write_sequence(&sd_body);

        let outer_body = {
            let mut b = der::write_oid(&OID_SIGNED_DATA);
            b.extend_from_slice(&der::write_context_constructed(0, &sd));
            b
        };
        let envelope = der::write_sequence(&outer_body);

        let parsed = parse_signed_data(&envelope).expect("parse v3 SKI SignedData");
        assert_eq!(parsed.version, 3);
        assert!(parsed.encap_content_octets.is_none(), "detached signature");
        let si = &parsed.signer_infos[0];
        match &si.sid {
            SignerIdentifier::SubjectKeyIdentifier(b) => assert_eq!(b, &signer_ski),
            other => panic!("expected SKI got {other:?}"),
        }
        assert_eq!(si.signed_attrs.len(), 1);
        assert_eq!(si.signed_attrs[0].oid, attr_oid);
        assert_eq!(si.signed_attrs[0].values.len(), 1);
        assert!(si.signed_attrs_der.is_some());
        assert_eq!(si.signature, signature_bytes);
    }

    #[test]
    fn rejects_envelope_with_wrong_oid() {
        // A bare ContentInfo whose OID is id-envelopedData (1.2.840.113549.1.7.3)
        // — parse_signed_data must refuse it.
        let inner = der::write_sequence(&der::write_integer_u64(0));
        let outer_body = {
            let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 3]);
            b.extend_from_slice(&der::write_context_constructed(0, &inner));
            b
        };
        let envelope = der::write_sequence(&outer_body);
        let err = parse_signed_data(&envelope).expect_err("must reject");
        let msg = format!("{err}");
        assert!(msg.contains("id-signedData"), "{msg}");
    }
}
