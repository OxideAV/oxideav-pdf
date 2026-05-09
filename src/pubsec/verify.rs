//! Round-20 — CMS `SignedData` signature verification (RFC 5652 §5.4 +
//! §11.2).
//!
//! Picks up where round-19's [`super::signed_data::parse_signed_data`]
//! left off: given a parsed [`SignerInfo`] + the certificate set
//! collected from the SignedData (or any caller-supplied trust store),
//! resolve the signer's certificate, hash the signed bytes per
//! `digestAlgorithm`, and verify the resulting digest against
//! `signature` per `signatureAlgorithm`.
//!
//! ## What "the signed bytes" means
//!
//! Per RFC 5652 §5.4:
//!
//! > The result of the message digest calculation process depends on
//! > whether the `signedAttrs` field is present.
//! >
//! > * **`signedAttrs` absent** — the input to the message digest is
//! >   the encapsulated content (`eContent`) value bytes only (i.e.
//! >   the OCTET STRING body).
//! > * **`signedAttrs` present** — the input to the **signature**
//! >   computation is the **DER encoding of the SignedAttributes
//! >   value**. The encoding MUST be the universal SET tag (`0x31`),
//! >   NOT the implicit `[0]` tag the wire form uses.
//!
//! Round-19 captured the wire bytes of the `[0] IMPLICIT` body in
//! [`SignerInfo::signed_attrs_der`]. Round-20 re-tags them with the
//! universal SET identifier before hashing.
//!
//! Detached signatures (`eContent` absent — by far the most common
//! shape in PAdES) cannot be verified through this entry point alone:
//! the caller must hash the document's `/ByteRange` covered bytes,
//! then either pass them as `attached_content` (so we substitute them
//! for the missing `eContent`) **or** supply `signed_attrs` containing
//! the `messageDigest` attribute that already names that hash.
//!
//! ## Algorithm dispatch
//!
//! | digestAlgorithm OID                       | hash    |
//! |-------------------------------------------|---------|
//! | 1.3.14.3.2.26                             | SHA-1   |
//! | 2.16.840.1.101.3.4.2.1                    | SHA-256 |
//! | 2.16.840.1.101.3.4.2.2                    | SHA-384 |
//! | 2.16.840.1.101.3.4.2.3                    | SHA-512 |
//!
//! | signatureAlgorithm OID                    | scheme              |
//! |-------------------------------------------|---------------------|
//! | 1.2.840.113549.1.1.1   (rsaEncryption)    | RSA-PKCS#1 v1.5     |
//! | 1.2.840.113549.1.1.5   (sha1WithRSA)      | RSA-PKCS#1 v1.5     |
//! | 1.2.840.113549.1.1.11  (sha256WithRSA)    | RSA-PKCS#1 v1.5     |
//! | 1.2.840.113549.1.1.12  (sha384WithRSA)    | RSA-PKCS#1 v1.5     |
//! | 1.2.840.113549.1.1.13  (sha512WithRSA)    | RSA-PKCS#1 v1.5     |
//! | 1.2.840.113549.1.1.10  (id-RSASSA-PSS)    | RSA-PSS             |
//! | 1.2.840.10045.2.1      (id-ecPublicKey)   | ECDSA               |
//! | 1.2.840.10045.4.1      (ecdsa-with-SHA1)  | ECDSA               |
//! | 1.2.840.10045.4.3.2    (ecdsa-with-SHA256)| ECDSA               |
//! | 1.2.840.10045.4.3.3    (ecdsa-with-SHA384)| ECDSA               |
//! | 1.2.840.10045.4.3.4    (ecdsa-with-SHA512)| ECDSA               |
//!
//! ECDSA curve dispatch is by the cert's
//! `subjectPublicKeyInfo.algorithm.parameters` named-curve OID:
//!
//! | named-curve OID         | curve   |
//! |-------------------------|---------|
//! | 1.2.840.10045.3.1.7     | P-256   |
//! | 1.3.132.0.34            | P-384   |
//! | 1.3.132.0.35            | P-521   |
//!
//! ## Provenance
//!
//! Implemented from RFC 5652 §5.4 + RFC 8017 (PKCS#1 v2.2 — RSA-PKCS#1
//! v1.5 + RSA-PSS) + RFC 5754 (NIST hash OIDs in CMS) + RFC 5758
//! (ECDSA-with-SHA-{256,384,512} OIDs in CMS) + RFC 5280 §4 (X.509
//! AlgorithmIdentifier shapes). No third-party CMS / OpenSSL source
//! consulted.

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pss::Pss;
use rsa::{traits::SignatureScheme, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::error::PdfError;

use super::der::{read_octet_string, read_oid, write_set, write_tlv, Class};
use super::signed_data::{Attribute, SignedData, SignerIdentifier, SignerInfo};
use super::x509::Certificate;

// ---------------------------------------------------------------------
// Algorithm OIDs (RFC 5754 + RFC 5758 + RFC 8017)
// ---------------------------------------------------------------------

/// 1.3.14.3.2.26 — SHA-1 (RFC 3279 §2.2.1).
pub const OID_SHA1: [u64; 6] = [1, 3, 14, 3, 2, 26];
/// 2.16.840.1.101.3.4.2.1 — SHA-256 (RFC 5754 §2.1).
pub const OID_SHA256: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 2, 1];
/// 2.16.840.1.101.3.4.2.2 — SHA-384 (RFC 5754 §2.2).
pub const OID_SHA384: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 2, 2];
/// 2.16.840.1.101.3.4.2.3 — SHA-512 (RFC 5754 §2.3).
pub const OID_SHA512: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 2, 3];

/// 1.2.840.113549.1.1.1 — rsaEncryption (RSA-PKCS#1 v1.5 — RFC 8017).
pub const OID_RSA_ENCRYPTION: [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];
/// 1.2.840.113549.1.1.5 — sha1WithRSAEncryption (RFC 8017).
pub const OID_SHA1_WITH_RSA: [u64; 7] = [1, 2, 840, 113549, 1, 1, 5];
/// 1.2.840.113549.1.1.11 — sha256WithRSAEncryption (RFC 8017).
pub const OID_SHA256_WITH_RSA: [u64; 7] = [1, 2, 840, 113549, 1, 1, 11];
/// 1.2.840.113549.1.1.12 — sha384WithRSAEncryption (RFC 8017).
pub const OID_SHA384_WITH_RSA: [u64; 7] = [1, 2, 840, 113549, 1, 1, 12];
/// 1.2.840.113549.1.1.13 — sha512WithRSAEncryption (RFC 8017).
pub const OID_SHA512_WITH_RSA: [u64; 7] = [1, 2, 840, 113549, 1, 1, 13];
/// 1.2.840.113549.1.1.10 — id-RSASSA-PSS (RFC 8017 §A.2.4).
pub const OID_RSA_PSS: [u64; 7] = [1, 2, 840, 113549, 1, 1, 10];

/// 1.2.840.10045.2.1 — id-ecPublicKey (RFC 5480 §2.1.1).
pub const OID_EC_PUBLIC_KEY: [u64; 6] = [1, 2, 840, 10045, 2, 1];
/// 1.2.840.10045.4.1 — ecdsa-with-SHA1 (RFC 3279).
pub const OID_ECDSA_WITH_SHA1: [u64; 6] = [1, 2, 840, 10045, 4, 1];
/// 1.2.840.10045.4.3.2 — ecdsa-with-SHA256 (RFC 5758 §3.2).
pub const OID_ECDSA_WITH_SHA256: [u64; 7] = [1, 2, 840, 10045, 4, 3, 2];
/// 1.2.840.10045.4.3.3 — ecdsa-with-SHA384 (RFC 5758 §3.2).
pub const OID_ECDSA_WITH_SHA384: [u64; 7] = [1, 2, 840, 10045, 4, 3, 3];
/// 1.2.840.10045.4.3.4 — ecdsa-with-SHA512 (RFC 5758 §3.2).
pub const OID_ECDSA_WITH_SHA512: [u64; 7] = [1, 2, 840, 10045, 4, 3, 4];

/// 1.2.840.10045.3.1.7 — secp256r1 / P-256 (RFC 5480 §2.1.1.1).
pub const OID_NAMED_CURVE_P256: [u64; 7] = [1, 2, 840, 10045, 3, 1, 7];
/// 1.3.132.0.34 — secp384r1 / P-384 (RFC 5480 §2.1.1.1).
pub const OID_NAMED_CURVE_P384: [u64; 5] = [1, 3, 132, 0, 34];
/// 1.3.132.0.35 — secp521r1 / P-521 (RFC 5480 §2.1.1.1).
pub const OID_NAMED_CURVE_P521: [u64; 5] = [1, 3, 132, 0, 35];

/// 1.2.840.113549.1.9.4 — id-messageDigest (RFC 5652 §11.2).
pub const OID_ATTR_MESSAGE_DIGEST: [u64; 7] = [1, 2, 840, 113549, 1, 9, 4];

// ---------------------------------------------------------------------
// Hash dispatch
// ---------------------------------------------------------------------

/// Identify the hash function the `digestAlgorithm` OID names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// Map a digestAlgorithm OID to its [`HashAlg`].
    pub fn from_oid(oid: &[u64]) -> Option<Self> {
        if oid == OID_SHA1 {
            Some(Self::Sha1)
        } else if oid == OID_SHA256 {
            Some(Self::Sha256)
        } else if oid == OID_SHA384 {
            Some(Self::Sha384)
        } else if oid == OID_SHA512 {
            Some(Self::Sha512)
        } else {
            None
        }
    }

    /// Hash an arbitrary byte slice with the selected algorithm.
    pub fn hash(self, input: &[u8]) -> Vec<u8> {
        // `sha1::Digest` and `sha2::Digest` are the same re-exported
        // `digest::Digest` trait — one import covers both crates' types.
        use sha2::Digest as _;
        match self {
            Self::Sha1 => Sha1::digest(input).to_vec(),
            Self::Sha256 => Sha256::digest(input).to_vec(),
            Self::Sha384 => Sha384::digest(input).to_vec(),
            Self::Sha512 => Sha512::digest(input).to_vec(),
        }
    }
}

// ---------------------------------------------------------------------
// Signature-algorithm dispatch
// ---------------------------------------------------------------------

/// Identify the signature scheme the `signatureAlgorithm` OID names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlg {
    /// RSA-PKCS#1 v1.5 (RFC 8017 §8.2). The `digestAlgorithm` is supplied
    /// separately via `SignerInfo.digest_algorithm_oid` — the
    /// `sha*WithRSA` combined OIDs are mapped to this same scheme.
    RsaPkcs1v15,
    /// RSA-PSS (RFC 8017 §8.1).
    RsaPss,
    /// ECDSA. Curve dispatch is by the cert SPKI's named-curve OID.
    Ecdsa,
}

impl SignatureAlg {
    /// Map a `signatureAlgorithm` OID to its [`SignatureAlg`].
    pub fn from_oid(oid: &[u64]) -> Option<Self> {
        if oid == OID_RSA_ENCRYPTION
            || oid == OID_SHA1_WITH_RSA
            || oid == OID_SHA256_WITH_RSA
            || oid == OID_SHA384_WITH_RSA
            || oid == OID_SHA512_WITH_RSA
        {
            Some(Self::RsaPkcs1v15)
        } else if oid == OID_RSA_PSS {
            Some(Self::RsaPss)
        } else if oid == OID_EC_PUBLIC_KEY
            || oid == OID_ECDSA_WITH_SHA1
            || oid == OID_ECDSA_WITH_SHA256
            || oid == OID_ECDSA_WITH_SHA384
            || oid == OID_ECDSA_WITH_SHA512
        {
            Some(Self::Ecdsa)
        } else {
            None
        }
    }
}

/// Named-curve identifier extracted from a cert SPKI for ECDSA dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    /// Map an `id-ecPublicKey` named-curve OID to a curve tag.
    ///
    /// The named-curve OID lives in the `parameters` slot of the SPKI's
    /// `AlgorithmIdentifier` (RFC 5480 §2.1.1) — itself a primitive
    /// OID TLV that we re-parse here.
    pub fn from_named_curve_params(params_der: &[u8]) -> Option<Self> {
        let (oid, rest) = read_oid(params_der).ok()?;
        if !rest.is_empty() {
            return None;
        }
        if oid == OID_NAMED_CURVE_P256 {
            Some(Self::P256)
        } else if oid == OID_NAMED_CURVE_P384 {
            Some(Self::P384)
        } else if oid == OID_NAMED_CURVE_P521 {
            Some(Self::P521)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------
// Cert resolution
// ---------------------------------------------------------------------

/// Find the certificate in `certs` whose identity matches `sid`.
///
/// `IssuerAndSerial`: byte-compare `(issuer_der, serial)`.
/// `SubjectKeyIdentifier`: compare the SHA-1 of the cert's SPKI BIT
/// STRING contents (RFC 5280 §4.2.1.2 method 1).
///
/// Returns `None` when no certificate in `certs` matches.
pub fn resolve_signer_cert<'a>(
    sid: &SignerIdentifier,
    certs: &'a [Certificate],
) -> Option<&'a Certificate> {
    for cert in certs {
        match sid {
            SignerIdentifier::IssuerAndSerial(ias) => {
                if cert.issuer_der == ias.issuer_der && cert.serial == ias.serial {
                    return Some(cert);
                }
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => {
                if let Some(cert_ski) = cert.subject_key_identifier() {
                    if &cert_ski == ski {
                        return Some(cert);
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------
// signed_attrs re-encoding (RFC 5652 §5.4)
// ---------------------------------------------------------------------

/// Re-encode a `[0] IMPLICIT SignedAttributes` body as the universal
/// SET form the verifier hashes per RFC 5652 §5.4.
///
/// The wire form is an `IMPLICIT [0]` tag (`0xA0`) — the universal SET
/// identifier (`0x31`) is replaced by the implicit context tag. To
/// hash, we have to put the universal tag back. This is a straight
/// `write_tlv(Universal, constructed=true, tag=SET)` over the same body
/// bytes.
pub fn signed_attrs_to_be_signed(signed_attrs_der: &[u8]) -> Vec<u8> {
    write_set(signed_attrs_der)
}

/// Find the `messageDigest` (OID 1.2.840.113549.1.9.4) attribute in a
/// `SignedAttributes` SET and return the OCTET STRING body it carries.
///
/// Per RFC 5652 §11.2 the attribute is a SET with a single
/// `messageDigest OCTET STRING` inside.
pub fn message_digest_attr(attrs: &[Attribute]) -> Option<Vec<u8>> {
    for a in attrs {
        if a.oid == OID_ATTR_MESSAGE_DIGEST {
            // Each attrValue is an OCTET STRING TLV — pull the bytes
            // out of the first value.
            if let Some(v) = a.values.first() {
                if let Ok((bytes, _)) = read_octet_string(v) {
                    return Some(bytes.to_vec());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------
// Attached-content selection
// ---------------------------------------------------------------------

/// What the verifier should treat as the encapsulated content.
///
/// In a self-contained `SignedData` the parser surfaces the eContent
/// octets via [`SignedData::encap_content_octets`]; for detached
/// signatures (PAdES, PDF /Sig with /ByteRange) the caller must hash
/// the relevant document bytes themselves and pass them in here.
#[derive(Debug, Clone, Copy)]
pub enum AttachedContent<'a> {
    /// Use the eContent octets the SignedData blob already carries.
    /// The verifier returns an error when the SignedData is detached
    /// (eContent absent).
    FromEContent(&'a SignedData),
    /// Use the supplied bytes as the message body (typically the bytes
    /// the PDF `/ByteRange` covers, for detached PAdES signatures).
    External(&'a [u8]),
}

// ---------------------------------------------------------------------
// Top-level entry point
// ---------------------------------------------------------------------

/// Verify a single SignerInfo against the supplied cert pool + content.
///
/// Returns `Ok(true)` on a verified signature, `Ok(false)` on a
/// well-formed but invalid signature, and `Err` on a structural problem
/// (unknown algorithm OID, missing certificate, malformed cert SPKI).
///
/// Per RFC 5652 §5.4:
///
/// * If `signed_attrs` is **present**: hash the canonical DER form
///   of the SignedAttributes SET (universal SET tag) under
///   `digestAlgorithm`, and verify that hash against `signature` under
///   `signatureAlgorithm`.
///
///   Additionally, the `messageDigest` signed attribute MUST equal the
///   hash of the encapsulated content (RFC 5652 §11.2). We check that
///   too — failing on a mismatch — so a tampered eContent fails even
///   when the outer signature still verifies against an unrelated
///   attribute set.
///
/// * If `signed_attrs` is **absent**: hash the encapsulated content
///   directly and verify that hash against `signature`.
pub fn verify_signature(
    signer: &SignerInfo,
    certs: &[Certificate],
    content: AttachedContent<'_>,
) -> Result<bool, PdfError> {
    let hash = HashAlg::from_oid(&signer.digest_algorithm_oid).ok_or_else(|| {
        PdfError::other(format!(
            "CMS verify: unsupported digestAlgorithm OID {:?}",
            signer.digest_algorithm_oid
        ))
    })?;
    let sig_alg = SignatureAlg::from_oid(&signer.signature_algorithm_oid).ok_or_else(|| {
        PdfError::other(format!(
            "CMS verify: unsupported signatureAlgorithm OID {:?}",
            signer.signature_algorithm_oid
        ))
    })?;
    let cert = resolve_signer_cert(&signer.sid, certs).ok_or_else(|| {
        PdfError::other("CMS verify: no certificate in pool matches the signer identifier")
    })?;

    // Compute the hash the signature was supposed to be made over.
    let message_digest_to_verify: Vec<u8> = if let Some(sa_body) = &signer.signed_attrs_der {
        // Per RFC 5652 §5.4, if signedAttrs is present the signature is
        // over the DER encoding of the SignedAttributes SET. We also
        // check the messageDigest attribute matches the eContent hash.
        let content_bytes = resolve_content_bytes(&content)?;
        let content_hash = hash.hash(content_bytes);
        let md_attr = message_digest_attr(&signer.signed_attrs).ok_or_else(|| {
            PdfError::other(
                "CMS verify: signed_attrs present but messageDigest attribute is missing",
            )
        })?;
        if md_attr != content_hash {
            // The signed messageDigest attribute does not match the
            // encapsulated content — the content was tampered with.
            return Ok(false);
        }
        let to_be_signed = signed_attrs_to_be_signed(sa_body);
        hash.hash(&to_be_signed)
    } else {
        let content_bytes = resolve_content_bytes(&content)?;
        hash.hash(content_bytes)
    };

    // Dispatch by signature scheme.
    match sig_alg {
        SignatureAlg::RsaPkcs1v15 => {
            verify_rsa_pkcs1v15(cert, hash, &message_digest_to_verify, &signer.signature)
        }
        SignatureAlg::RsaPss => {
            verify_rsa_pss(cert, hash, &message_digest_to_verify, &signer.signature)
        }
        SignatureAlg::Ecdsa => {
            verify_ecdsa(cert, hash, &message_digest_to_verify, &signer.signature)
        }
    }
}

fn resolve_content_bytes<'a>(content: &'a AttachedContent<'a>) -> Result<&'a [u8], PdfError> {
    match content {
        AttachedContent::FromEContent(sd) => sd.encap_content_octets.as_deref().ok_or_else(|| {
            PdfError::other("CMS verify: detached signature requires AttachedContent::External")
        }),
        AttachedContent::External(bytes) => Ok(bytes),
    }
}

// ---------------------------------------------------------------------
// Per-scheme verifiers
// ---------------------------------------------------------------------

/// Decode the cert's SPKI BIT STRING contents as an RSA public key
/// (PKCS#1 RSAPublicKey SEQUENCE { n INTEGER, e INTEGER }).
fn rsa_pubkey_from_cert(cert: &Certificate) -> Result<RsaPublicKey, PdfError> {
    let spki = cert
        .spki_pubkey_bits
        .as_deref()
        .ok_or_else(|| PdfError::other("CMS verify: signer cert SPKI bytes unavailable"))?;
    // SPKI BIT STRING contents = DER of `RSAPublicKey ::= SEQUENCE { n
    // INTEGER, e INTEGER }`. The `rsa` crate's `pkcs1` helper accepts
    // the DER bytes directly.
    use rsa::pkcs1::DecodeRsaPublicKey;
    RsaPublicKey::from_pkcs1_der(spki)
        .map_err(|e| PdfError::other(format!("CMS verify: RSA public key parse: {e}")))
}

fn verify_rsa_pkcs1v15(
    cert: &Certificate,
    hash: HashAlg,
    message_digest: &[u8],
    signature: &[u8],
) -> Result<bool, PdfError> {
    let pubkey = rsa_pubkey_from_cert(cert)?;
    let scheme: Pkcs1v15Sign = match hash {
        HashAlg::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
        HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    };
    Ok(scheme.verify(&pubkey, message_digest, signature).is_ok())
}

fn verify_rsa_pss(
    cert: &Certificate,
    hash: HashAlg,
    message_digest: &[u8],
    signature: &[u8],
) -> Result<bool, PdfError> {
    let pubkey = rsa_pubkey_from_cert(cert)?;
    // PSS is parameterised by the digest used for both the hash inside
    // the EM construction and the MGF1. Salt length defaults to the
    // hash output length per the RFC 8017 recommendation.
    let scheme = match hash {
        HashAlg::Sha1 => Pss::new::<Sha1>(),
        HashAlg::Sha256 => Pss::new::<Sha256>(),
        HashAlg::Sha384 => Pss::new::<Sha384>(),
        HashAlg::Sha512 => Pss::new::<Sha512>(),
    };
    Ok(scheme.verify(&pubkey, message_digest, signature).is_ok())
}

fn verify_ecdsa(
    cert: &Certificate,
    hash: HashAlg,
    message_digest: &[u8],
    signature_der: &[u8],
) -> Result<bool, PdfError> {
    // Pick the curve from the cert's SPKI named-curve parameters.
    let params = cert.spki_algorithm_params.as_deref().ok_or_else(|| {
        PdfError::other("CMS verify: ECDSA requires named-curve parameters in cert SPKI")
    })?;
    let curve = EcCurve::from_named_curve_params(params)
        .ok_or_else(|| PdfError::other("CMS verify: ECDSA cert names an unsupported curve"))?;
    // SPKI public-key BIT STRING contents = SEC1-encoded EC point.
    let spki = cert
        .spki_pubkey_bits
        .as_deref()
        .ok_or_else(|| PdfError::other("CMS verify: signer cert SPKI bytes unavailable"))?;

    // ECDSA over a `signature_der` ASN.1 SEQUENCE { r INTEGER, s INTEGER }.
    // CMS always uses the DER form (RFC 5754 §3.2). The hash output
    // length passed in `message_digest` is whatever `hash` produced.
    let _ = (hash, message_digest); // used by per-curve dispatch

    match curve {
        EcCurve::P256 => verify_ecdsa_p256(spki, message_digest, signature_der),
        EcCurve::P384 => verify_ecdsa_p384(spki, message_digest, signature_der),
        EcCurve::P521 => verify_ecdsa_p521(spki, message_digest, signature_der),
    }
}

fn verify_ecdsa_p256(spki: &[u8], digest: &[u8], sig_der: &[u8]) -> Result<bool, PdfError> {
    use p256::ecdsa::{Signature, VerifyingKey};
    use rsa::signature::hazmat::PrehashVerifier;
    let vk = match VerifyingKey::from_sec1_bytes(spki) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let sig = match Signature::from_der(sig_der) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    Ok(vk.verify_prehash(digest, &sig).is_ok())
}

fn verify_ecdsa_p384(spki: &[u8], digest: &[u8], sig_der: &[u8]) -> Result<bool, PdfError> {
    use p384::ecdsa::{Signature, VerifyingKey};
    use rsa::signature::hazmat::PrehashVerifier;
    let vk = match VerifyingKey::from_sec1_bytes(spki) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let sig = match Signature::from_der(sig_der) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    Ok(vk.verify_prehash(digest, &sig).is_ok())
}

fn verify_ecdsa_p521(spki: &[u8], digest: &[u8], sig_der: &[u8]) -> Result<bool, PdfError> {
    use p521::ecdsa::{Signature, VerifyingKey};
    use rsa::signature::hazmat::PrehashVerifier;
    let vk = match VerifyingKey::from_sec1_bytes(spki) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let sig = match Signature::from_der(sig_der) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    Ok(vk.verify_prehash(digest, &sig).is_ok())
}

// ---------------------------------------------------------------------
// Helpers used by tests + by callers building synthetic SignedData
// ---------------------------------------------------------------------

/// Convenience: build the `messageDigest` signed-attribute (RFC 5652
/// §11.2) for a content hash, returning the DER bytes of one
/// `Attribute` SEQUENCE. The caller stitches multiple attributes
/// together and wraps the result in an `IMPLICIT [0]` tag for the
/// SignerInfo wire form.
pub fn build_message_digest_attribute_der(content_hash: &[u8]) -> Vec<u8> {
    use super::der::{write_octet_string, write_oid, write_sequence};
    let oid = write_oid(&OID_ATTR_MESSAGE_DIGEST);
    let value = write_octet_string(content_hash);
    let value_set = write_set(&value);
    let mut body = oid;
    body.extend_from_slice(&value_set);
    write_sequence(&body)
}

/// Convenience: pack a sequence of pre-encoded `Attribute` DER bytes
/// into a wire-form `[0] IMPLICIT SET` (the body the parser surfaces as
/// `signed_attrs_der`).
pub fn pack_signed_attrs_implicit(attrs_der: &[Vec<u8>]) -> Vec<u8> {
    // The body bytes are simply the concatenation of the per-attribute
    // SEQUENCE TLVs — the SET ordering is not enforced by us (the
    // verifier hashes whatever's there, so DER canonicalisation only
    // matters when the producer cares about deterministic encoding).
    let mut body = Vec::new();
    for a in attrs_der {
        body.extend_from_slice(a);
    }
    body
}

/// Build a `[0] IMPLICIT` TLV around an already-packed signed_attrs
/// body — useful for stitching together a SignerInfo by hand.
pub fn implicit_signed_attrs_tlv(attrs_body: &[u8]) -> Vec<u8> {
    write_tlv(Class::ContextSpecific, true, 0, attrs_body)
}

/// Build the inner contents of a `SubjectPublicKeyInfo` BIT STRING for
/// an RSA key — i.e. the PKCS#1 `RSAPublicKey ::= SEQUENCE { n INTEGER,
/// e INTEGER }` DER. The caller wraps it in a BIT STRING + the SPKI
/// AlgorithmIdentifier when synthesising a full cert.
pub fn rsa_pubkey_to_pkcs1_der(pubkey: &RsaPublicKey) -> Vec<u8> {
    use rsa::pkcs1::EncodeRsaPublicKey;
    pubkey
        .to_pkcs1_der()
        .expect("RSA public-key PKCS#1 encode infallible")
        .as_bytes()
        .to_vec()
}

/// Round-trip a raw PKCS#1 `RSAPublicKey` SEQUENCE into a public key
/// the `rsa` crate can verify with — only used by the test code to
/// build synthetic certs.
pub fn parse_rsa_pubkey_pkcs1(der: &[u8]) -> Result<RsaPublicKey, PdfError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    RsaPublicKey::from_pkcs1_der(der)
        .map_err(|e| PdfError::other(format!("RSA pubkey decode: {e}")))
}

/// Read an RSA INTEGER component out of an RSAPublicKey SEQUENCE — used
/// by the synthetic cert builders so they can copy the `(n, e)` pair
/// into a freshly-built BIT STRING.
pub fn rsa_pubkey_components(pubkey: &RsaPublicKey) -> (Vec<u8>, Vec<u8>) {
    use rsa::traits::PublicKeyParts;
    let n = pubkey.n();
    let e = pubkey.e();
    (n.to_bytes_be(), e.to_bytes_be())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubsec::cms::IssuerAndSerial;
    use crate::pubsec::der;
    use crate::pubsec::signed_data::SignerIdentifier;

    // -----------------------------------------------------------------
    // Round-trip helpers
    // -----------------------------------------------------------------

    /// Build a minimal X.509-shaped cert whose SPKI carries `spki_pubkey_bits`
    /// under the `rsaEncryption` algorithm. Only the fields the verifier
    /// dispatches on are populated.
    fn fake_rsa_cert(issuer_der: Vec<u8>, serial: Vec<u8>, rsa_pkcs1_der: Vec<u8>) -> Certificate {
        Certificate {
            issuer_der,
            serial,
            spki_pubkey_bits: Some(rsa_pkcs1_der),
            spki_algorithm_oid: Some(OID_RSA_ENCRYPTION.to_vec()),
            spki_algorithm_params: Some(der::write_null()),
            ..Default::default()
        }
    }

    /// Build a minimal cert whose SPKI carries an `id-ecPublicKey` key
    /// (SEC1-encoded EC point) on the named curve.
    fn fake_ec_cert(
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
        sec1_pubkey: Vec<u8>,
        named_curve_oid: &[u64],
    ) -> Certificate {
        Certificate {
            issuer_der,
            serial,
            spki_pubkey_bits: Some(sec1_pubkey),
            spki_algorithm_oid: Some(OID_EC_PUBLIC_KEY.to_vec()),
            spki_algorithm_params: Some(der::write_oid(named_curve_oid)),
            ..Default::default()
        }
    }

    fn ias_signer(issuer_der: &[u8], serial: &[u8]) -> SignerIdentifier {
        SignerIdentifier::IssuerAndSerial(IssuerAndSerial {
            issuer_der: issuer_der.to_vec(),
            serial: serial.to_vec(),
        })
    }

    // -----------------------------------------------------------------
    // Hash dispatch
    // -----------------------------------------------------------------

    #[test]
    fn hash_alg_dispatch_round_trip() {
        assert_eq!(HashAlg::from_oid(&OID_SHA1), Some(HashAlg::Sha1));
        assert_eq!(HashAlg::from_oid(&OID_SHA256), Some(HashAlg::Sha256));
        assert_eq!(HashAlg::from_oid(&OID_SHA384), Some(HashAlg::Sha384));
        assert_eq!(HashAlg::from_oid(&OID_SHA512), Some(HashAlg::Sha512));
        assert!(HashAlg::from_oid(&[1, 2, 3, 4]).is_none());
    }

    #[test]
    fn signed_attrs_to_be_signed_replaces_implicit_tag() {
        // [0] IMPLICIT body bytes are simply re-tagged with universal
        // SET (0x31). Body contents are unchanged.
        let body = b"--ATTR-SET-BODY--";
        let out = signed_attrs_to_be_signed(body);
        assert_eq!(out[0], 0x31, "leading byte should be universal SET");
        // The body bytes survive intact at the tail.
        assert!(out.windows(body.len()).any(|w| w == &body[..]));
    }

    // -----------------------------------------------------------------
    // RSA-PKCS#1 v1.5 — sign with rsa::pkcs1v15::SigningKey then verify
    // through `verify_signature` with a synthetic SignerInfo + cert pool.
    // -----------------------------------------------------------------

    fn rsa_sign_pkcs1v15_sha256(priv_key: &rsa::RsaPrivateKey, msg_digest: &[u8]) -> Vec<u8> {
        let scheme: Pkcs1v15Sign = Pkcs1v15Sign::new::<Sha256>();
        scheme
            .sign(None::<&mut rsa::rand_core::OsRng>, priv_key, msg_digest)
            .expect("RSA-PKCS1v15 sign")
    }

    #[test]
    fn rsa_pkcs1v15_sha256_with_signed_attrs_verifies() {
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);

        let issuer_der = der::write_sequence(b"O=Round-20 RSA Signer");
        let serial = vec![0x42, 0x01];
        let pubkey_pkcs1 = rsa_pubkey_to_pkcs1_der(&pub_key);
        let cert = fake_rsa_cert(issuer_der.clone(), serial.clone(), pubkey_pkcs1);

        // Encapsulated content + its SHA-256.
        let payload = b"OXIDEAV-ROUND-20-CONTENT-PAYLOAD";
        let content_hash = HashAlg::Sha256.hash(payload);

        // Build a signed-attrs body containing a single messageDigest
        // attribute matching the content hash.
        let md_attr = build_message_digest_attribute_der(&content_hash);
        let attrs_body = pack_signed_attrs_implicit(&[md_attr]);

        // Sign over the universal-SET re-tagging of the attrs body.
        let to_be_signed = signed_attrs_to_be_signed(&attrs_body);
        let tbs_hash = HashAlg::Sha256.hash(&to_be_signed);
        let signature = rsa_sign_pkcs1v15_sha256(&priv_key, &tbs_hash);

        // Stitch a SignerInfo by hand.
        let signer = SignerInfo {
            version: 1,
            sid: ias_signer(&issuer_der, &serial),
            digest_algorithm_oid: OID_SHA256.to_vec(),
            digest_algorithm_params: Vec::new(),
            signed_attrs: vec![Attribute {
                oid: OID_ATTR_MESSAGE_DIGEST.to_vec(),
                values: vec![der::write_octet_string(&content_hash)],
            }],
            signed_attrs_der: Some(attrs_body),
            signature_algorithm_oid: OID_RSA_ENCRYPTION.to_vec(),
            signature_algorithm_params: Vec::new(),
            signature,
            unsigned_attrs: Vec::new(),
        };

        let ok = verify_signature(&signer, &[cert], AttachedContent::External(payload))
            .expect("verify dispatch");
        assert!(
            ok,
            "RSA-PKCS1v15 + SHA-256 verifier should accept signature"
        );
    }

    #[test]
    fn rsa_pkcs1v15_sha256_no_signed_attrs_verifies() {
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let issuer_der = der::write_sequence(b"O=Round-20 No-Attr");
        let serial = vec![0x77];
        let pubkey_pkcs1 = rsa_pubkey_to_pkcs1_der(&pub_key);
        let cert = fake_rsa_cert(issuer_der.clone(), serial.clone(), pubkey_pkcs1);

        let payload = b"NO-ATTR-PAYLOAD";
        let payload_hash = HashAlg::Sha256.hash(payload);
        let signature = rsa_sign_pkcs1v15_sha256(&priv_key, &payload_hash);

        let signer = SignerInfo {
            version: 1,
            sid: ias_signer(&issuer_der, &serial),
            digest_algorithm_oid: OID_SHA256.to_vec(),
            digest_algorithm_params: Vec::new(),
            signed_attrs: Vec::new(),
            signed_attrs_der: None,
            signature_algorithm_oid: OID_RSA_ENCRYPTION.to_vec(),
            signature_algorithm_params: Vec::new(),
            signature,
            unsigned_attrs: Vec::new(),
        };

        let ok = verify_signature(&signer, &[cert], AttachedContent::External(payload))
            .expect("verify dispatch");
        assert!(ok);
    }

    #[test]
    fn rsa_pkcs1v15_tampered_content_fails_via_message_digest_check() {
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let issuer_der = der::write_sequence(b"O=Tamper-RSA");
        let serial = vec![0x66];
        let cert = fake_rsa_cert(
            issuer_der.clone(),
            serial.clone(),
            rsa_pubkey_to_pkcs1_der(&pub_key),
        );
        let payload = b"ORIGINAL-CONTENT";
        let content_hash = HashAlg::Sha256.hash(payload);
        let md_attr = build_message_digest_attribute_der(&content_hash);
        let attrs_body = pack_signed_attrs_implicit(&[md_attr]);
        let tbs_hash = HashAlg::Sha256.hash(&signed_attrs_to_be_signed(&attrs_body));
        let signature = rsa_sign_pkcs1v15_sha256(&priv_key, &tbs_hash);

        let signer = SignerInfo {
            version: 1,
            sid: ias_signer(&issuer_der, &serial),
            digest_algorithm_oid: OID_SHA256.to_vec(),
            digest_algorithm_params: Vec::new(),
            signed_attrs: vec![Attribute {
                oid: OID_ATTR_MESSAGE_DIGEST.to_vec(),
                values: vec![der::write_octet_string(&content_hash)],
            }],
            signed_attrs_der: Some(attrs_body),
            signature_algorithm_oid: OID_RSA_ENCRYPTION.to_vec(),
            signature_algorithm_params: Vec::new(),
            signature,
            unsigned_attrs: Vec::new(),
        };

        // Pass a tampered payload — verification must fail because the
        // messageDigest attribute no longer matches the content hash.
        let tampered = b"TAMPERED-CONTENT";
        let ok = verify_signature(&signer, &[cert], AttachedContent::External(tampered))
            .expect("verify dispatch");
        assert!(!ok, "tampered content must fail messageDigest check");
    }

    #[test]
    fn rsa_pkcs1v15_tampered_signature_byte_fails() {
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let issuer_der = der::write_sequence(b"O=Bit-Flip");
        let serial = vec![0x55];
        let cert = fake_rsa_cert(
            issuer_der.clone(),
            serial.clone(),
            rsa_pubkey_to_pkcs1_der(&pub_key),
        );
        let payload = b"OK-CONTENT";
        let payload_hash = HashAlg::Sha256.hash(payload);
        let mut signature = rsa_sign_pkcs1v15_sha256(&priv_key, &payload_hash);
        signature[0] ^= 0x01;

        let signer = SignerInfo {
            version: 1,
            sid: ias_signer(&issuer_der, &serial),
            digest_algorithm_oid: OID_SHA256.to_vec(),
            digest_algorithm_params: Vec::new(),
            signed_attrs: Vec::new(),
            signed_attrs_der: None,
            signature_algorithm_oid: OID_RSA_ENCRYPTION.to_vec(),
            signature_algorithm_params: Vec::new(),
            signature,
            unsigned_attrs: Vec::new(),
        };
        let ok = verify_signature(&signer, &[cert], AttachedContent::External(payload))
            .expect("verify dispatch");
        assert!(!ok, "single-bit-flipped signature must not verify");
    }

    #[test]
    fn cert_not_in_pool_returns_error() {
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let payload = b"some-content";
        let payload_hash = HashAlg::Sha256.hash(payload);
        let signature = rsa_sign_pkcs1v15_sha256(&priv_key, &payload_hash);
        let cert = fake_rsa_cert(
            der::write_sequence(b"O=NotInPool"),
            vec![0xAA],
            rsa_pubkey_to_pkcs1_der(&pub_key),
        );
        let signer = SignerInfo {
            version: 1,
            sid: ias_signer(b"O=DifferentIssuer", &[0xBB]),
            digest_algorithm_oid: OID_SHA256.to_vec(),
            digest_algorithm_params: Vec::new(),
            signed_attrs: Vec::new(),
            signed_attrs_der: None,
            signature_algorithm_oid: OID_RSA_ENCRYPTION.to_vec(),
            signature_algorithm_params: Vec::new(),
            signature,
            unsigned_attrs: Vec::new(),
        };
        let err = verify_signature(&signer, &[cert], AttachedContent::External(payload))
            .expect_err("must error when cert not found");
        assert!(format!("{err}").contains("no certificate"));
    }

    // -----------------------------------------------------------------
    // RSA-PSS
    // -----------------------------------------------------------------

    #[test]
    fn rsa_pss_sha256_verifies() {
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let issuer_der = der::write_sequence(b"O=Round-20 PSS");
        let serial = vec![0x12];
        let cert = fake_rsa_cert(
            issuer_der.clone(),
            serial.clone(),
            rsa_pubkey_to_pkcs1_der(&pub_key),
        );

        let payload = b"PSS-CONTENT";
        let payload_hash = HashAlg::Sha256.hash(payload);
        let scheme = Pss::new::<Sha256>();
        let signature = scheme
            .sign(Some(&mut rng), &priv_key, &payload_hash)
            .expect("RSA-PSS sign");

        let signer = SignerInfo {
            version: 1,
            sid: ias_signer(&issuer_der, &serial),
            digest_algorithm_oid: OID_SHA256.to_vec(),
            digest_algorithm_params: Vec::new(),
            signed_attrs: Vec::new(),
            signed_attrs_der: None,
            signature_algorithm_oid: OID_RSA_PSS.to_vec(),
            signature_algorithm_params: Vec::new(),
            signature,
            unsigned_attrs: Vec::new(),
        };
        let ok = verify_signature(&signer, &[cert], AttachedContent::External(payload))
            .expect("dispatch");
        assert!(ok);
    }

    // -----------------------------------------------------------------
    // ECDSA
    // -----------------------------------------------------------------

    #[test]
    fn ecdsa_p256_sha256_verifies() {
        use p256::ecdsa::signature::Signer as _;
        use p256::ecdsa::{Signature, SigningKey};
        let scalar = [0x21u8; 32];
        let signing_key = SigningKey::from_slice(&scalar).expect("scalar");
        let verifying_key = signing_key.verifying_key();
        let pub_sec1 = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let issuer_der = der::write_sequence(b"O=Round-20 P-256");
        let serial = vec![0xC0, 0xFE];
        let cert = fake_ec_cert(
            issuer_der.clone(),
            serial.clone(),
            pub_sec1,
            &OID_NAMED_CURVE_P256,
        );

        let payload = b"OXIDEAV-ECDSA-P256-PAYLOAD";
        let sig: Signature = signing_key.sign(payload);
        let sig_der = sig.to_der().as_bytes().to_vec();

        let signer = SignerInfo {
            version: 1,
            sid: ias_signer(&issuer_der, &serial),
            digest_algorithm_oid: OID_SHA256.to_vec(),
            digest_algorithm_params: Vec::new(),
            signed_attrs: Vec::new(),
            signed_attrs_der: None,
            signature_algorithm_oid: OID_ECDSA_WITH_SHA256.to_vec(),
            signature_algorithm_params: Vec::new(),
            signature: sig_der,
            unsigned_attrs: Vec::new(),
        };
        let ok = verify_signature(&signer, &[cert], AttachedContent::External(payload))
            .expect("dispatch");
        assert!(ok);
    }

    #[test]
    fn ecdsa_p384_sha384_verifies() {
        use p384::ecdsa::signature::Signer as _;
        use p384::ecdsa::{Signature, SigningKey};
        let scalar = [0x35u8; 48];
        let signing_key = SigningKey::from_slice(&scalar).expect("scalar");
        let verifying_key = signing_key.verifying_key();
        let pub_sec1 = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        let issuer_der = der::write_sequence(b"O=Round-20 P-384");
        let serial = vec![0xCA, 0xFE];
        let cert = fake_ec_cert(
            issuer_der.clone(),
            serial.clone(),
            pub_sec1,
            &OID_NAMED_CURVE_P384,
        );
        let payload = b"OXIDEAV-ECDSA-P384-PAYLOAD";
        let sig: Signature = signing_key.sign(payload);
        let sig_der = sig.to_der().as_bytes().to_vec();
        let signer = SignerInfo {
            version: 1,
            sid: ias_signer(&issuer_der, &serial),
            digest_algorithm_oid: OID_SHA384.to_vec(),
            digest_algorithm_params: Vec::new(),
            signed_attrs: Vec::new(),
            signed_attrs_der: None,
            signature_algorithm_oid: OID_ECDSA_WITH_SHA384.to_vec(),
            signature_algorithm_params: Vec::new(),
            signature: sig_der,
            unsigned_attrs: Vec::new(),
        };
        let ok = verify_signature(&signer, &[cert], AttachedContent::External(payload))
            .expect("dispatch");
        assert!(ok);
    }

    #[test]
    fn ecdsa_p521_sha512_verifies() {
        use p521::ecdsa::signature::Signer as _;
        use p521::ecdsa::{Signature, SigningKey, VerifyingKey};
        // P-521 scalar = 66 bytes, but only 521 bits are valid; using
        // a small non-zero scalar (with high bits zero) is fine.
        let mut scalar = [0u8; 66];
        scalar[1] = 0x01;
        scalar[65] = 0x42;
        let signing_key = SigningKey::from_slice(&scalar).expect("scalar");
        // p521 0.13.3's `signing_key.verifying_key()` is gated by a
        // non-existent `verifying` cargo feature; route through the
        // `From<&SigningKey>` impl instead which is unconditionally
        // available when the `ecdsa` feature is on.
        let verifying_key = VerifyingKey::from(&signing_key);
        let pub_sec1 = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        let issuer_der = der::write_sequence(b"O=Round-20 P-521");
        let serial = vec![0x52, 0x21];
        let cert = fake_ec_cert(
            issuer_der.clone(),
            serial.clone(),
            pub_sec1,
            &OID_NAMED_CURVE_P521,
        );
        let payload = b"OXIDEAV-ECDSA-P521-PAYLOAD";
        let sig: Signature = signing_key.sign(payload);
        let sig_der = sig.to_der().as_bytes().to_vec();
        let signer = SignerInfo {
            version: 1,
            sid: ias_signer(&issuer_der, &serial),
            digest_algorithm_oid: OID_SHA512.to_vec(),
            digest_algorithm_params: Vec::new(),
            signed_attrs: Vec::new(),
            signed_attrs_der: None,
            signature_algorithm_oid: OID_ECDSA_WITH_SHA512.to_vec(),
            signature_algorithm_params: Vec::new(),
            signature: sig_der,
            unsigned_attrs: Vec::new(),
        };
        let ok = verify_signature(&signer, &[cert], AttachedContent::External(payload))
            .expect("dispatch");
        assert!(ok);
    }

    #[test]
    fn ecdsa_p256_tampered_signature_fails() {
        use p256::ecdsa::signature::Signer as _;
        use p256::ecdsa::{Signature, SigningKey};
        let scalar = [0x21u8; 32];
        let signing_key = SigningKey::from_slice(&scalar).expect("scalar");
        let pub_sec1 = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let issuer_der = der::write_sequence(b"O=Tamper-EC");
        let serial = vec![0x99];
        let cert = fake_ec_cert(
            issuer_der.clone(),
            serial.clone(),
            pub_sec1,
            &OID_NAMED_CURVE_P256,
        );
        let payload = b"good-content";
        let sig: Signature = signing_key.sign(payload);
        let mut sig_der = sig.to_der().as_bytes().to_vec();
        // Flip a byte deep in the signature where the SEQUENCE header
        // is unaffected (offset 6 lies inside the `r` INTEGER body).
        sig_der[6] ^= 0xFF;
        let signer = SignerInfo {
            version: 1,
            sid: ias_signer(&issuer_der, &serial),
            digest_algorithm_oid: OID_SHA256.to_vec(),
            digest_algorithm_params: Vec::new(),
            signed_attrs: Vec::new(),
            signed_attrs_der: None,
            signature_algorithm_oid: OID_ECDSA_WITH_SHA256.to_vec(),
            signature_algorithm_params: Vec::new(),
            signature: sig_der,
            unsigned_attrs: Vec::new(),
        };
        let ok = verify_signature(&signer, &[cert], AttachedContent::External(payload))
            .expect("dispatch");
        assert!(!ok);
    }

    // -----------------------------------------------------------------
    // SignerIdentifier dispatch
    // -----------------------------------------------------------------

    #[test]
    fn ski_resolution_picks_matching_cert() {
        // The cert pool carries one cert with a known SPKI; signer
        // refers to it by SKI (SHA-1 of the SPKI bytes).
        use sha1::Digest;
        let pubkey_bits = b"OXIDEAV-PUBSEC-VERIFY-SKI-BITS-OK".to_vec();
        let ski = sha1::Sha1::digest(&pubkey_bits).to_vec();
        let cert = Certificate {
            issuer_der: der::write_sequence(b"O=SKI-Cert"),
            serial: vec![0x01],
            spki_pubkey_bits: Some(pubkey_bits),
            spki_algorithm_oid: Some(OID_RSA_ENCRYPTION.to_vec()),
            spki_algorithm_params: Some(der::write_null()),
            ..Default::default()
        };
        let sid = SignerIdentifier::SubjectKeyIdentifier(ski.clone());
        let pool = vec![cert.clone()];
        let resolved = resolve_signer_cert(&sid, &pool).expect("found");
        assert_eq!(resolved.serial, cert.serial);
        // A different SKI fails to resolve.
        let sid2 = SignerIdentifier::SubjectKeyIdentifier(vec![0u8; 20]);
        let pool2 = vec![cert];
        assert!(resolve_signer_cert(&sid2, &pool2).is_none());
    }
}
