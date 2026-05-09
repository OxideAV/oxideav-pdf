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
    OID_AES128_CBC, OID_AES256_CBC, OID_DATA, OID_DES_EDE3_CBC, OID_ENVELOPED_DATA, OID_RC2_CBC,
    OID_RC4, OID_RSA_ENCRYPTION,
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

/// **Round-17 read-only test fixture** — build an `EnvelopedData`
/// ContentInfo whose content-encryption algorithm is RC2-CBC (RFC 2268
/// + RFC 3217 §3 + RFC 3370 §5.1). The CEK is the raw RC2 key bytes
/// (length matches `effective_key_bits / 8` rounded up); IV is 8 bytes;
/// padding is PKCS#7. The parameters SEQUENCE carries the RFC 3370
/// `rc2ParameterVersion` mapping for the supplied `effective_key_bits`
/// (40 → 160, 64 → 120, 128 → 58; other values pass through verbatim).
///
/// PDF 2.0 deprecates RC2 and we provide NO encode-side public API for
/// new files — this helper exists only so the read-side decoder can be
/// unit-tested. Marked `#[doc(hidden)]` to keep it off the public
/// surface (writer code must use AES).
#[doc(hidden)]
pub fn build_envelope_rc2_cbc(
    recipients: &[RecipientPlain],
    plaintext: &[u8],
    cek: &[u8],
    effective_key_bits: u32,
    iv: &[u8; 8],
) -> Vec<u8> {
    let encrypted = rc2_cbc_encrypt_padded(cek, effective_key_bits, iv, plaintext);
    // Build params SEQUENCE { INTEGER rc2ParameterVersion, OCTET STRING iv }.
    let version_byte: u32 = match effective_key_bits {
        40 => 160,
        64 => 120,
        128 => 58,
        v => v,
    };
    let mut params_body = super::der::write_integer_u64(version_byte as u64);
    params_body.extend_from_slice(&super::der::write_octet_string(iv));
    let params = super::der::write_sequence(&params_body);
    build_envelope_inner_raw_params(recipients, &OID_RC2_CBC, &params, &encrypted)
}

/// **Round-17 read-only test fixture** — build an `EnvelopedData`
/// ContentInfo whose content-encryption algorithm is DES-EDE3-CBC
/// (3DES, RFC 3370 §5.2 / RFC 5652 §12.4). The CEK is the 24-byte
/// concatenation of the three DES keys; IV is 8 bytes; padding is
/// PKCS#7. Parameters are a single OCTET STRING containing the IV.
///
/// PDF 2.0 deprecates 3DES and we provide NO encode-side public API for
/// new files. Marked `#[doc(hidden)]` for the same reason as
/// [`build_envelope_rc2_cbc`].
#[doc(hidden)]
pub fn build_envelope_des_ede3_cbc(
    recipients: &[RecipientPlain],
    plaintext: &[u8],
    cek: &[u8; 24],
    iv: &[u8; 8],
) -> Vec<u8> {
    let encrypted = des_ede3_cbc_encrypt_padded(cek, iv, plaintext);
    // Params for 3DES is a bare OCTET STRING wrapping the IV.
    let params = super::der::write_octet_string(iv);
    build_envelope_inner_raw_params(recipients, &OID_DES_EDE3_CBC, &params, &encrypted)
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

/// Round-17: same as [`build_envelope_inner`] except the
/// `AlgorithmIdentifier`'s `parameters` is supplied raw (already DER-encoded).
/// Used by the RC2 / 3DES test fixtures whose parameters shape isn't a
/// simple "OCTET STRING wrapping a 16-byte IV" — RC2's params are a
/// SEQUENCE { INTEGER version, OCTET STRING iv } and 3DES's are a bare
/// 8-byte OCTET STRING.
fn build_envelope_inner_raw_params(
    recipients: &[RecipientPlain],
    content_alg_oid: &[u64],
    raw_params: &[u8],
    encrypted_content: &[u8],
) -> Vec<u8> {
    let envelope_version: u64 = if recipients
        .iter()
        .any(|r| matches!(r.rid, RecipientIdRef::SubjectKeyIdentifier { .. }))
    {
        2
    } else {
        0
    };
    let mut ri_set_body = Vec::new();
    for r in recipients {
        ri_set_body.extend_from_slice(&build_ktri(r));
    }
    let ri_set = write_set(&ri_set_body);
    let alg_id = {
        let mut body = write_oid(content_alg_oid);
        body.extend_from_slice(raw_params);
        write_sequence(&body)
    };
    let eci = {
        let mut body = write_oid(&OID_DATA);
        body.extend_from_slice(&alg_id);
        body.extend_from_slice(&write_context_primitive(0, encrypted_content));
        write_sequence(&body)
    };
    let enveloped_body = {
        let mut b = write_integer_u64(envelope_version);
        b.extend_from_slice(&ri_set);
        b.extend_from_slice(&eci);
        b
    };
    let enveloped = write_sequence(&enveloped_body);
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

/// Round-17 read-only fixture helper: RC2-CBC encrypt with PKCS#7
/// padding. Goes through `Rc2::new_with_eff_key_len` to honour the
/// RFC 2268 §6 effective-key-bits parameter independently of the raw
/// key length (RFC 3370 §5.1 lets the two diverge).
fn rc2_cbc_encrypt_padded(
    key: &[u8],
    effective_key_bits: u32,
    iv: &[u8; 8],
    data: &[u8],
) -> Vec<u8> {
    use cbc::cipher::{BlockEncryptMut, InnerIvInit};
    use rc2::Rc2;
    let cipher = Rc2::new_with_eff_key_len(key, effective_key_bits as usize);
    let enc = cbc::Encryptor::<Rc2>::inner_iv_slice_init(cipher, iv).expect("RC2 IV init");
    let pad_block = (data.len() / 8) + 1;
    let mut buf = vec![0u8; pad_block * 8];
    let n = enc
        .encrypt_padded_b2b_mut::<cbc::cipher::block_padding::Pkcs7>(data, &mut buf)
        .expect("PKCS7 padding")
        .len();
    buf.truncate(n);
    buf
}

/// Round-17 read-only fixture helper: 3DES-CBC encrypt with PKCS#7
/// padding. The 24-byte key is treated as the concatenation of three
/// 8-byte DES sub-keys (RFC 5652 §12.4 / RFC 3370 §5.2).
fn des_ede3_cbc_encrypt_padded(key: &[u8; 24], iv: &[u8; 8], data: &[u8]) -> Vec<u8> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use des::TdesEde3;
    type Enc = cbc::Encryptor<TdesEde3>;
    let enc = Enc::new(key.into(), iv.into());
    let pad_block = (data.len() / 8) + 1;
    let mut buf = vec![0u8; pad_block * 8];
    let n = enc
        .encrypt_padded_b2b_mut::<cbc::cipher::block_padding::Pkcs7>(data, &mut buf)
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

// ───────── Round-12: KARI builder (decoder-only helper) ─────────

/// Originator side of a KARI slot — mirrors RFC 5652 §6.2.2's
/// `OriginatorIdentifierOrKey` CHOICE. Used by [`build_envelope_kari`]
/// to assemble fixture envelopes for the round-12 KARI decoder unit
/// + integration tests.
#[derive(Debug, Clone)]
pub enum OriginatorIdRef {
    /// Originator identified by issuer + serial.
    IssuerAndSerial {
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
    },
    /// Originator identified by SubjectKeyIdentifier (raw OCTET STRING
    /// body). Encoded as `[0] IMPLICIT OCTET STRING`.
    SubjectKeyIdentifier { ski: Vec<u8> },
    /// In-band originator public key. `algorithm_oid` names the curve
    /// / group; `algorithm_params` is appended after the OID inside
    /// the AlgorithmIdentifier SEQUENCE; `public_key` is the BIT
    /// STRING contents (without the leading unused-bits byte). Encoded
    /// as `[1] IMPLICIT OriginatorPublicKey`.
    OriginatorKey {
        algorithm_oid: Vec<u64>,
        algorithm_params: Vec<u8>,
        public_key: Vec<u8>,
    },
}

/// Recipient identifier shape inside one `RecipientEncryptedKey` slot
/// of a KARI envelope (RFC 5652 §6.2.2 — `KeyAgreeRecipientIdentifier`).
#[derive(Debug, Clone)]
pub enum KariRecipientIdRef {
    /// Legacy `IssuerAndSerialNumber` form.
    IssuerAndSerial {
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
    },
    /// `[0] IMPLICIT RecipientKeyIdentifier` carrying just the SKI
    /// (no `date` / `other` attributes — those are OPTIONAL and the
    /// decoder ignores them anyway).
    RecipientKeyIdentifier { ski: Vec<u8> },
}

/// One recipient slot inside a KARI envelope. `encrypted_key` is the
/// already-wrapped CEK (the test fixture supplies it pre-wrapped — we
/// don't perform DH/ECDH key agreement in this crate).
#[derive(Debug, Clone)]
pub struct KariRecipientPlain {
    pub rid: KariRecipientIdRef,
    pub encrypted_key: Vec<u8>,
}

/// Build a CMS `EnvelopedData` ContentInfo whose RecipientInfos SET
/// contains a single `[1] IMPLICIT KeyAgreeRecipientInfo` carrying the
/// supplied originator + UKM + recipientEncryptedKeys. The content is
/// AES-256-CBC-encrypted with `cek` + `iv`.
///
/// Use cases: round-12 decoder fixtures (see `tests/pubsec_kari.rs`).
/// We do NOT implement the wrap algorithm — `encrypted_key` for each
/// recipient slot is whatever bytes the caller chooses, since the
/// pubsec module surfaces the KARI structurally rather than unwrapping
/// it (DH/ECDH key agreement + RFC 5753 KDFs are explicitly out of
/// scope for round 12).
///
/// `key_encryption_oid` names the KEA combined KDF + key-wrap (RFC
/// 5753 §7.1 — e.g. `dhSinglePass-stdDH-sha256kdf-scheme`); we also
/// accept the bare wrap OID (`id-aes128-wrap`).
#[allow(clippy::too_many_arguments)]
pub fn build_envelope_kari_aes256(
    originator: &OriginatorIdRef,
    ukm: Option<&[u8]>,
    key_encryption_oid: &[u64],
    key_encryption_params: &[u8],
    recipient_keys: &[KariRecipientPlain],
    plaintext: &[u8],
    cek: &[u8; 32],
    iv: &[u8; 16],
) -> Vec<u8> {
    let encrypted = aes256_cbc_encrypt_padded(cek, iv, plaintext);
    build_envelope_kari_inner(
        originator,
        ukm,
        key_encryption_oid,
        key_encryption_params,
        recipient_keys,
        &OID_AES256_CBC,
        Some(iv),
        &encrypted,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_envelope_kari_inner(
    originator: &OriginatorIdRef,
    ukm: Option<&[u8]>,
    key_encryption_oid: &[u64],
    key_encryption_params: &[u8],
    recipient_keys: &[KariRecipientPlain],
    content_alg_oid: &[u64],
    iv: Option<&[u8; 16]>,
    encrypted_content: &[u8],
) -> Vec<u8> {
    use super::der::{
        write_context_constructed, write_context_primitive, write_oid, write_sequence,
    };
    // EnvelopedData version 3 (because at least one RecipientInfo is
    // KARI, per RFC 5652 §6.1 — version is the highest among entries).
    let envelope_version: u64 = 2;
    // Build the KARI body.
    let kari_body = build_kari(
        originator,
        ukm,
        key_encryption_oid,
        key_encryption_params,
        recipient_keys,
    );
    // Wrap as `[1] IMPLICIT KeyAgreeRecipientInfo` — the [1] tag
    // replaces the SEQUENCE's universal tag (so we hand-encode rather
    // than calling write_sequence).
    let kari_tagged =
        super::der::write_tlv(super::der::Class::ContextSpecific, true, 1, &kari_body);
    // RecipientInfos SET.
    let ri_set = super::der::write_set(&kari_tagged);
    // EncryptedContentInfo.
    let alg_id = {
        let mut body = write_oid(content_alg_oid);
        match iv {
            Some(iv) => body.extend_from_slice(&super::der::write_octet_string(iv)),
            None => body.extend_from_slice(&super::der::write_null()),
        }
        write_sequence(&body)
    };
    let eci = {
        let mut body = write_oid(&OID_DATA);
        body.extend_from_slice(&alg_id);
        body.extend_from_slice(&write_context_primitive(0, encrypted_content));
        write_sequence(&body)
    };
    // EnvelopedData SEQUENCE.
    let enveloped_body = {
        let mut b = super::der::write_integer_u64(envelope_version);
        b.extend_from_slice(&ri_set);
        b.extend_from_slice(&eci);
        b
    };
    let enveloped = write_sequence(&enveloped_body);
    // ContentInfo.
    let outer = {
        let mut b = write_oid(&OID_ENVELOPED_DATA);
        b.extend_from_slice(&write_context_constructed(0, &enveloped));
        b
    };
    write_sequence(&outer)
}

fn build_kari(
    originator: &OriginatorIdRef,
    ukm: Option<&[u8]>,
    key_encryption_oid: &[u64],
    key_encryption_params: &[u8],
    recipient_keys: &[KariRecipientPlain],
) -> Vec<u8> {
    use super::der::{
        write_context_constructed, write_context_primitive, write_octet_string, write_oid,
        write_sequence,
    };
    // KARI body bytes:
    //   version (3)
    //   [0] EXPLICIT OriginatorIdentifierOrKey
    //   [1] EXPLICIT UserKeyingMaterial OPTIONAL
    //   keyEncryptionAlgorithm
    //   recipientEncryptedKeys
    let mut body = super::der::write_integer_u64(3);
    let originator_inner = match originator {
        OriginatorIdRef::IssuerAndSerial { issuer_der, serial } => {
            let serial_int = super::der::write_integer_bytes(serial);
            let mut ias_body = Vec::with_capacity(issuer_der.len() + serial_int.len());
            ias_body.extend_from_slice(issuer_der);
            ias_body.extend_from_slice(&serial_int);
            write_sequence(&ias_body)
        }
        OriginatorIdRef::SubjectKeyIdentifier { ski } => write_context_primitive(0, ski),
        OriginatorIdRef::OriginatorKey {
            algorithm_oid,
            algorithm_params,
            public_key,
        } => {
            // OriginatorPublicKey ::= SEQUENCE { algorithm AlgorithmIdentifier, publicKey BIT STRING }
            let alg = {
                let mut b = write_oid(algorithm_oid);
                b.extend_from_slice(algorithm_params);
                write_sequence(&b)
            };
            // BIT STRING — leading 0x00 unused-bits byte then contents.
            let mut bs = vec![0x00];
            bs.extend_from_slice(public_key);
            let bit_string = super::der::write_tlv(
                super::der::Class::Universal,
                false,
                3, // BIT STRING tag
                &bs,
            );
            let mut opk_body = alg;
            opk_body.extend_from_slice(&bit_string);
            // [1] IMPLICIT OriginatorPublicKey — implicit tag replaces
            // the SEQUENCE's universal tag, so emit constructed [1]
            // around the body.
            super::der::write_tlv(super::der::Class::ContextSpecific, true, 1, &opk_body)
        }
    };
    body.extend_from_slice(&write_context_constructed(0, &originator_inner));
    if let Some(ukm) = ukm {
        // [1] EXPLICIT UserKeyingMaterial — body is OCTET STRING.
        body.extend_from_slice(&write_context_constructed(1, &write_octet_string(ukm)));
    }
    // KeyEncryptionAlgorithmIdentifier.
    let kea_seq = {
        let mut b = write_oid(key_encryption_oid);
        b.extend_from_slice(key_encryption_params);
        write_sequence(&b)
    };
    body.extend_from_slice(&kea_seq);
    // recipientEncryptedKeys SEQUENCE OF RecipientEncryptedKey.
    let mut reks = Vec::new();
    for r in recipient_keys {
        let rid_bytes = match &r.rid {
            KariRecipientIdRef::IssuerAndSerial { issuer_der, serial } => {
                let serial_int = super::der::write_integer_bytes(serial);
                let mut ias_body = Vec::with_capacity(issuer_der.len() + serial_int.len());
                ias_body.extend_from_slice(issuer_der);
                ias_body.extend_from_slice(&serial_int);
                write_sequence(&ias_body)
            }
            KariRecipientIdRef::RecipientKeyIdentifier { ski } => {
                // [0] IMPLICIT RecipientKeyIdentifier — body is the
                // RKID's SEQUENCE contents (one OCTET STRING for the
                // SKI; no date / other).
                let inner = write_octet_string(ski);
                super::der::write_tlv(super::der::Class::ContextSpecific, true, 0, &inner)
            }
        };
        let mut rek_body = rid_bytes;
        rek_body.extend_from_slice(&write_octet_string(&r.encrypted_key));
        reks.extend_from_slice(&write_sequence(&rek_body));
    }
    body.extend_from_slice(&write_sequence(&reks));
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubsec::cms::{parse_envelope, RecipientInfoVariant};

    /// Round-trip: build a single-recipient KARI envelope by hand,
    /// parse it back, assert structural fields match.
    #[test]
    fn kari_envelope_round_trips_through_parser() {
        let originator_pubkey = b"OXIDEAV-ECDH-ORIGINATOR-FAKE-PT!".to_vec();
        let ukm = b"OXIDEAV-UKM-1234".to_vec();
        let originator = OriginatorIdRef::OriginatorKey {
            // ecPublicKey OID 1.2.840.10045.2.1.
            algorithm_oid: vec![1, 2, 840, 10045, 2, 1],
            // Named curve P-256 OID 1.2.840.10045.3.1.7 — encoded as
            // an OBJECT IDENTIFIER inside the AlgorithmIdentifier.
            algorithm_params: super::super::der::write_oid(&[1, 2, 840, 10045, 3, 1, 7]),
            public_key: originator_pubkey.clone(),
        };
        // dhSinglePass-stdDH-sha256kdf-scheme OID 1.3.133.16.840.63.0.11.1.
        let kea_oid = vec![1u64, 3, 133, 16, 840, 63, 0, 11, 1];
        // The KEA params for this combined KDF wrap is itself an
        // AlgorithmIdentifier naming id-aes256-wrap.
        let aes256_wrap_oid = [2u64, 16, 840, 1, 101, 3, 4, 1, 45];
        let kea_params =
            super::super::der::write_sequence(&{ super::super::der::write_oid(&aes256_wrap_oid) });
        let recipient_ski = vec![0xCDu8; 20];
        let wrapped_cek = vec![0xDEu8; 40]; // arbitrary fake-wrap output
        let rek = KariRecipientPlain {
            rid: KariRecipientIdRef::RecipientKeyIdentifier {
                ski: recipient_ski.clone(),
            },
            encrypted_key: wrapped_cek.clone(),
        };
        let plaintext = b"OXIDEAV-KARI-FIXTURE-PLAINTEXT-32";
        let envelope = build_envelope_kari_aes256(
            &originator,
            Some(&ukm),
            &kea_oid,
            &kea_params,
            &[rek],
            plaintext,
            &[0xAAu8; 32],
            &[0xBBu8; 16],
        );
        let parsed = parse_envelope(&envelope).expect("parse");
        // Round-12 KTRI-only view should be empty (we only added a
        // KARI slot).
        assert!(parsed.recipients.is_empty());
        assert_eq!(parsed.all_recipients.len(), 1);
        match &parsed.all_recipients[0] {
            RecipientInfoVariant::KeyAgree(kari) => {
                assert_eq!(kari.key_encryption_oid, kea_oid);
                assert_eq!(kari.ukm, ukm);
                assert_eq!(kari.recipient_encrypted_keys.len(), 1);
                match &kari.recipient_encrypted_keys[0].rid {
                    crate::pubsec::cms::KeyAgreeRecipientId::RecipientKeyIdentifier { ski } => {
                        assert_eq!(ski, &recipient_ski);
                    }
                    other => panic!("expected RKID got {other:?}"),
                }
                assert_eq!(kari.recipient_encrypted_keys[0].encrypted_key, wrapped_cek);
                match &kari.originator {
                    crate::pubsec::cms::OriginatorId::OriginatorKey(opk) => {
                        assert_eq!(opk.public_key, originator_pubkey);
                    }
                    other => panic!("expected OriginatorKey got {other:?}"),
                }
            }
            other => panic!("expected KARI got {other:?}"),
        }
    }

    /// KARI with `IssuerAndSerial` recipient + `SubjectKeyIdentifier`
    /// originator — exercises both alternate CHOICE arms.
    #[test]
    fn kari_envelope_with_ias_recipient_and_ski_originator() {
        let issuer_der = super::super::der::write_sequence(b"O=KARI Test CA");
        let serial = vec![0x99, 0x42];
        let originator_ski = vec![0xEEu8; 20];
        let originator = OriginatorIdRef::SubjectKeyIdentifier {
            ski: originator_ski.clone(),
        };
        let kea_oid = vec![1u64, 3, 132, 1, 11, 3]; // dhSinglePass-stdDH-sha512kdf-scheme
        let rek = KariRecipientPlain {
            rid: KariRecipientIdRef::IssuerAndSerial {
                issuer_der: issuer_der.clone(),
                serial: serial.clone(),
            },
            encrypted_key: vec![0xFFu8; 24],
        };
        let envelope = build_envelope_kari_aes256(
            &originator,
            None, // no UKM
            &kea_oid,
            &[],
            &[rek],
            b"plaintext-bytes-padding-",
            &[0x33u8; 32],
            &[0x44u8; 16],
        );
        let parsed = parse_envelope(&envelope).expect("parse");
        match &parsed.all_recipients[0] {
            RecipientInfoVariant::KeyAgree(kari) => {
                assert_eq!(kari.ukm, Vec::<u8>::new());
                match &kari.originator {
                    crate::pubsec::cms::OriginatorId::SubjectKeyIdentifier(b) => {
                        assert_eq!(b, &originator_ski);
                    }
                    _ => panic!("expected SKI originator"),
                }
                match &kari.recipient_encrypted_keys[0].rid {
                    crate::pubsec::cms::KeyAgreeRecipientId::IssuerAndSerial(ias) => {
                        assert_eq!(ias.issuer_der, issuer_der);
                        assert_eq!(ias.serial, serial);
                    }
                    _ => panic!("expected IAS recipient"),
                }
            }
            _ => panic!("expected KARI"),
        }
    }
}
