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
//! ## Round-11 additions
//!
//! * **Writer / encoder side** — the writer can now emit
//!   public-key-encrypted PDFs symmetric to the round-10 reader.
//!   See [`PubSecEncoderConfig`] + [`PubSecRecipient`] +
//!   [`crate::write_pdf_from_scene_pubsec_encrypted`].
//! * **`SubjectKeyIdentifier` recipient matching** — CMS v2
//!   RecipientIdentifier wired through the parser + matcher per
//!   RFC 5652 §6.2.1 + RFC 5280 §4.2.1.2 method 1. Both forms
//!   are supported on read; the writer emits IAS by default but
//!   accepts SKI per-recipient.
//!
//! ## Round-12 additions
//!
//! * **Per-crypt-filter recipient lists** — multiple named crypt
//!   filters under `/CF`, each with its own `/Recipients` array. The
//!   matcher tries every CF in turn; the first CF that contains a
//!   recipient slot matching the user's certificate determines the
//!   permissions surfaced. ISO 32000-1 §7.6.4.2 + §7.6.5.4 explicitly
//!   permit different permission masks per recipient set (the "read
//!   only" recipient is in one CF, the "full access" recipient in
//!   another — both can decrypt with their respective rights). The
//!   public read-side API is unchanged (the matched CF's permissions
//!   are surfaced through the returned [`StandardHandler`] same as
//!   before); the [`open_with_certificate_with_permissions`] variant
//!   surfaces both the handler and the per-CF P value.
//! * **CMS KARI variant** (decoder side, RFC 5652 §6.2.2) — KeyAgree
//!   recipients (ECDH / DH) are now parsed structurally. The
//!   originator + UKM + recipientEncryptedKeys fields are surfaced via
//!   [`crate::pubsec::cms::RecipientInfoVariant::KeyAgree`]; the
//!   [`open_with_certificate`] handler still requires KTRI for actual
//!   unwrap because RFC 5753 KDF + key-wrap implementations are out of
//!   scope here. Mixed-recipient envelopes (KTRI + KARI) decode
//!   correctly via the KTRI side.
//!
//! ## Round-14 additions
//!
//! * **KARI unwrap** (RFC 5753 §7.1 + RFC 3394) — closes the round-12
//!   deferral. P-256 ECDH + X9.63-SHA-256 KDF + AES Key Wrap (128 /
//!   192 / 256 bit). Surfaces as the `OID_DH_SINGLE_PASS_STDDH_SHA256_KDF`
//!   KEA OID.
//! * **`PubSecCredential::from_parsed_ec_p256`** + `with_ec_p256_scalar`
//!   constructors — populate the EC private scalar slot so a
//!   credential can open both KTRI (RSA) and KARI (ECDH) envelopes.
//!
//! ## Round-15 additions
//!
//! * **P-384 + X25519 KARI variants** (RFC 5753 §7.1.4 +
//!   RFC 8418 §2.1) — `dhSinglePass-stdDH-sha384kdf-scheme` (P-384) +
//!   X25519 with the secg-scheme `dhSinglePass-stdDH-sha256kdf-scheme`
//!   binding. Generic [`kari::x963_kdf`] + curve-tagged
//!   [`kari::EcRecipient`]; the legacy P-256 entry point
//!   [`kari::unwrap_kari_p256`] still works.
//! * **`PubSecCredential::from_parsed_ec`** + `with_ec_scalar` —
//!   populate the EC slot for any supported curve via
//!   [`kari::KariCurve`]. The round-14 `_p256` variants forward here.
//! * **Writer-side `crate::write_pdf_from_scene_pubsec_kari`** — the
//!   symmetric encode-side helper for KARI envelopes (the round-11/12
//!   pubsec writer was KTRI-only). Each [`crate::KariRecipient`] picks
//!   the curve + cert; the writer derives the ephemeral keypair, runs
//!   the right ECDH primitive, KDFs the KEK, and AES-KWs the CEK.
//!
//! ## Round-16 additions
//!
//! * **P-521 KARI** (RFC 5753 §7.1.4) — `dhSinglePass-stdDH-sha512kdf-scheme`,
//!   OID 1.3.132.1.11.3. Closes the NIST KARI curve coverage; same
//!   builder + reader path as P-256 / P-384 with X9.63-SHA-512 KDF +
//!   AES-128/192/256-WRAP.
//! * **RFC 8418 §2.2 HKDF binding for X25519** —
//!   `dhSinglePass-stdDH-hkdf-sha256/384/512-scheme`, OIDs
//!   `1.2.840.113549.1.9.16.3.{19,20,21}`. The X25519
//!   `KariRecipient::x25519_hkdf_*` constructors switch the KDF on the
//!   writer side; the reader auto-routes by parsing the KEA OID into a
//!   [`kari::KariKdf`].
//!
//! ## Round-18 additions
//!
//! * **`OriginatorInfo certs[] / crls[]` surface** (RFC 5652 §10.2.1).
//!   The `EnvelopedData.originatorInfo` field — previously parsed and
//!   silently dropped — is now exposed via
//!   [`cms::EnvelopedData::originator_info`] returning
//!   `Option<&cms::OriginatorInfo>`. Each entry is the raw DER bytes of
//!   one CertificateChoices / RevocationInfoChoices alternative.
//! * **`RecipientKeyIdentifier { date, other }` parse**
//!   (RFC 5652 §6.2.2). The OPTIONAL `date GeneralizedTime` and
//!   `other OtherKeyAttribute` fields of an RKID — previously dropped
//!   — are now captured. New
//!   [`TrustStore::find_with_temporal_validity`] uses the RKID `date`
//!   to pick among multiple certs sharing an SKI the one whose
//!   validity window contains the instant. Useful for long-lived
//!   archives where the same recipient identity has been re-certified
//!   multiple times.
//! * **`Certificate.validity` extraction** (RFC 5280 §4.1.2.5). The
//!   `notBefore` / `notAfter` window is now captured, with `UTCTime`
//!   normalised to `GeneralizedTime` (RFC 5280 §4.1.2.5.1's 1950..2049
//!   pivot) so envelope `GeneralizedTime` instants byte-compare
//!   directly. New helper [`x509::time_within`].
//!
//! ## Remaining deferrals
//!
//! * X448 KARI (no vetted pure-Rust implementation in the workspace
//!   yet — RFC 8418 §2 + RFC 7748 spec is wired through, the
//!   `KariCurve` enum just needs an `X448` variant once a crate lands).
//! * RC2 `rc2ParameterVersion` writer-side encode (read-only currently;
//!   PDF 2.0 deprecates RC2 so the writer always emits AES — exposing
//!   an RC2 encoder would only serve archive-replay tooling).
//! * Document-level XMP metadata stream end-to-end (the writer doesn't
//!   currently emit XMP `/Metadata` streams; the reader could surface
//!   them as opaque DER for ISO 32000-1 §14.3.2 / Adobe XMP Spec).

pub mod cms;
pub mod cms_build;
pub mod der;
pub mod encode;
pub mod kari;
pub mod trust;
pub mod x509;

pub use encode::{
    KariRecipient, PubSecCfGroup, PubSecEncoderConfig, PubSecEncryptionState, PubSecKariConfig,
    PubSecMultiCfConfig, PubSecRecipient,
};
pub use trust::{CertRef, TrustStore};

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
/// the matching private key (RSA for KTRI envelopes, EC for round-14
/// KARI envelopes). The certificate identifier (`IssuerAndSerialNumber`
/// from RFC 5280) is extracted from the certificate's DER body.
///
/// Round 14 adds the optional `ec_private_scalar` slot — the
/// recipient's raw P-256 SEC1 scalar (32 bytes). When present, KARI
/// envelopes matching the same certificate can also be unwrapped (RFC
/// 5753 §7.1 + RFC 3394). When absent, KARI envelopes are skipped
/// (the original round-12 behaviour).
///
/// Round 15 generalises the EC slot to carry a [`kari::KariCurve`] tag
/// alongside the scalar, so the same credential can open KARI
/// envelopes on any of the supported curves (P-256 / P-384 / X25519).
/// The `from_parsed_ec_p256` / `with_ec_p256_scalar` round-14 helpers
/// keep working — they default the curve to [`kari::KariCurve::P256`].
pub struct PubSecCredential {
    pub(crate) cert: x509::Certificate,
    pub(crate) private_key: Option<rsa::RsaPrivateKey>,
    /// Optional EC private scalar + curve tag — populates the KARI
    /// unwrap path. When `None`, KARI recipient slots that match this
    /// certificate's RID are silently skipped.
    pub(crate) ec_private: Option<(kari::KariCurve, Vec<u8>)>,
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
        Ok(Self {
            cert,
            private_key: Some(private_key),
            ec_private: None,
        })
    }

    /// Build directly from a parsed certificate + RSA key — used by
    /// fixture builders inside the crate (and by integration tests
    /// in `tests/pubsec.rs`).
    #[doc(hidden)]
    pub fn from_parsed(cert: x509::Certificate, private_key: rsa::RsaPrivateKey) -> Self {
        Self {
            cert,
            private_key: Some(private_key),
            ec_private: None,
        }
    }

    /// Round-14: build a credential from a parsed certificate + a
    /// P-256 SEC1 raw private scalar (32 bytes). Used to open a
    /// KARI-encrypted PDF whose recipient slot matches this certificate.
    ///
    /// The `cert.spki_pubkey_bits` slot — when populated — is used to
    /// match the recipient's `RecipientKeyIdentifier(SKI)` form. For
    /// an EC certificate, `spki_pubkey_bits` is the SEC1-encoded
    /// public point.
    pub fn from_parsed_ec_p256(cert: x509::Certificate, ec_private_scalar: Vec<u8>) -> Self {
        Self::from_parsed_ec(cert, kari::KariCurve::P256, ec_private_scalar)
    }

    /// Round-15: build a credential from a parsed certificate + an EC
    /// private scalar on the supplied curve. Pass [`kari::KariCurve::P384`]
    /// or [`kari::KariCurve::X25519`] for the round-15 curves.
    pub fn from_parsed_ec(
        cert: x509::Certificate,
        curve: kari::KariCurve,
        ec_private_scalar: Vec<u8>,
    ) -> Self {
        Self {
            cert,
            private_key: None,
            ec_private: Some((curve, ec_private_scalar)),
        }
    }

    /// Round-14: extend an existing credential with a P-256 EC private
    /// scalar. Allows a single credential to unwrap both KTRI (RSA)
    /// and KARI (ECDH) envelopes — typical for a recipient who carries
    /// both a long-term RSA cert and a separate EC cert under the same
    /// identity.
    pub fn with_ec_p256_scalar(self, ec_private_scalar: Vec<u8>) -> Self {
        self.with_ec_scalar(kari::KariCurve::P256, ec_private_scalar)
    }

    /// Round-15: extend an existing credential with an EC scalar on
    /// the supplied curve.
    pub fn with_ec_scalar(mut self, curve: kari::KariCurve, ec_private_scalar: Vec<u8>) -> Self {
        self.ec_private = Some((curve, ec_private_scalar));
        self
    }
}

/// Per-CF surface returned by [`open_with_certificate_with_permissions`].
/// The standard [`open_with_certificate`] discards the permission /
/// CF-name fields and surfaces only the [`StandardHandler`] for
/// backwards compatibility with round-10 callers.
#[derive(Debug, Clone)]
pub struct PubSecMatch {
    /// File-encryption handler the matched CF derived. Feeds straight
    /// into the per-object decrypt path.
    pub handler: StandardHandler,
    /// Permission mask carried by the matched envelope's plaintext
    /// trailer (4-byte signed integer, per ISO 32000-1 §7.6.4.3 / ISO
    /// 32000-2 §7.6.5.3). `None` when the envelope plaintext is the
    /// 20-byte seed alone.
    pub permissions: Option<i32>,
    /// Name of the crypt filter under `/CF` whose `/Recipients` slot
    /// matched. `None` for the document-level `/Recipients` path used
    /// by `s3` / `s4` (no per-CF differentiation possible).
    pub crypt_filter_name: Option<String>,
}

/// Open a public-key-encrypted PDF given the trailer's `/Encrypt`
/// dict and the user's credential. Returns the file-encryption
/// handler the matched recipient set produced.
///
/// For `s5` envelopes that thread different permission sets through
/// distinct named crypt filters (per ISO 32000-1 §7.6.4.2 + §7.6.5.4),
/// every `/CF /<name> /Recipients` array is tried in declaration
/// order. The first CF whose recipient slot matches the user's
/// certificate determines the file encryption key + permissions.
///
/// Returns `Ok(None)` when no recipient slot in any envelope matches
/// the supplied certificate (analogous to a wrong password).
pub fn open_with_certificate(
    encrypt: &Dict,
    credential: &PubSecCredential,
) -> Result<Option<StandardHandler>, PdfError> {
    Ok(open_with_certificate_with_permissions(encrypt, credential)?.map(|m| m.handler))
}

/// Round-17: variant of [`open_with_certificate`] that consults a
/// [`TrustStore`] for KARI envelopes whose `OriginatorIdentifierOrKey`
/// is `IssuerAndSerial` or `SubjectKeyIdentifier` (RFC 5652 §6.2.2)
/// rather than the in-band `OriginatorPublicKey` form.
///
/// When the originator side is a long-term cert reference, the trust
/// store provides the originator's public point (extracted from the
/// referenced certificate's SPKI BIT STRING contents). The recipient's
/// own credential supplies the EC private scalar as before.
///
/// In-band `OriginatorPublicKey` envelopes still work without
/// consulting the trust store — the lookup path is only triggered for
/// the long-term-cert forms.
pub fn open_with_certificate_and_trust_store(
    encrypt: &Dict,
    credential: &PubSecCredential,
    trust_store: &TrustStore,
) -> Result<Option<StandardHandler>, PdfError> {
    Ok(
        open_with_certificate_and_trust_store_with_permissions(encrypt, credential, trust_store)?
            .map(|m| m.handler),
    )
}

/// Round-17: extended trust-store entry point that surfaces the matched
/// CF's name + envelope permissions alongside the handler. Same role as
/// [`open_with_certificate_with_permissions`] but for the trust-store
/// path.
pub fn open_with_certificate_and_trust_store_with_permissions(
    encrypt: &Dict,
    credential: &PubSecCredential,
    trust_store: &TrustStore,
) -> Result<Option<PubSecMatch>, PdfError> {
    open_inner(encrypt, credential, Some(trust_store))
}

/// Round-12 extended entry point — same matching rules as
/// [`open_with_certificate`] but surfaces the matched CF's name +
/// envelope permissions alongside the handler. Lets a caller display
/// "you have read-only access via the `ReadOnlyCF` recipient set"
/// without re-parsing the trailer.
pub fn open_with_certificate_with_permissions(
    encrypt: &Dict,
    credential: &PubSecCredential,
) -> Result<Option<PubSecMatch>, PdfError> {
    open_inner(encrypt, credential, None)
}

fn open_inner(
    encrypt: &Dict,
    credential: &PubSecCredential,
    trust_store: Option<&TrustStore>,
) -> Result<Option<PubSecMatch>, PdfError> {
    let sub_filter = PubSecSubFilter::from_dict(encrypt)?;
    let candidates = collect_recipient_arrays(encrypt)?;
    if candidates.is_empty() {
        return Err(PdfError::other(
            "PDF pubsec: no /Recipients arrays found (document-level or per-CF)",
        ));
    }

    let encrypt_metadata = match encrypt
        .entries()
        .iter()
        .find(|(k, _)| k == "EncryptMetadata")
    {
        Some((_, Object::Bool(b))) => *b,
        _ => true,
    };

    // Walk every CF candidate, then within it walk every recipient
    // blob until one matches. ISO 32000-1 §7.6.4.2: "There shall be
    // only one PKCS#7 object per unique set of access permissions; if
    // a recipient appears in more than one list, the permissions used
    // shall be those in the first matching list."
    for candidate in &candidates {
        for blob in &candidate.blobs {
            let envelope = cms::parse_envelope(blob)?;
            let Some(plaintext) = try_unwrap(&envelope, credential, trust_store)? else {
                continue;
            };
            // Plaintext is `seed (20 bytes) [|| 4 bytes permissions]`.
            if plaintext.len() < 20 {
                return Err(PdfError::other(format!(
                    "PDF pubsec: enveloped content too short ({} < 20 bytes)",
                    plaintext.len()
                )));
            }
            let seed = &plaintext[..20];
            let permissions = if plaintext.len() >= 24 {
                // ISO 32000-2 stores MSB-first; ISO 32000-1 stores
                // LSB-first. We pick by SubFilter.
                let p_bytes = &plaintext[20..24];
                let p_arr: [u8; 4] = [p_bytes[0], p_bytes[1], p_bytes[2], p_bytes[3]];
                let p = match sub_filter {
                    PubSecSubFilter::Pkcs7S5V5 => i32::from_be_bytes(p_arr),
                    _ => i32::from_le_bytes(p_arr),
                };
                Some(p)
            } else {
                None
            };

            // Per-CF candidate determines its own algorithm + key
            // length (the dict-level CFM is overridden when the
            // matched filter has its own CFM).
            let (method, revision) = candidate
                .method_revision
                .unwrap_or_else(|| default_method_revision(sub_filter));
            let default_key_bits = match sub_filter {
                PubSecSubFilter::Pkcs7S3 => 40,
                PubSecSubFilter::Pkcs7S4 => 128,
                PubSecSubFilter::Pkcs7S5V4 { .. } => 128,
                PubSecSubFilter::Pkcs7S5V5 => 256,
            };
            let key_bits = candidate.key_length_bits.unwrap_or(default_key_bits);
            let key = derive_file_key(
                sub_filter,
                seed,
                &candidate.blobs,
                encrypt_metadata,
                key_bits,
            );
            return Ok(Some(PubSecMatch {
                handler: StandardHandler {
                    key,
                    method,
                    revision,
                },
                permissions,
                crypt_filter_name: candidate.cf_name.clone(),
            }));
        }
    }
    Ok(None)
}

fn default_method_revision(sub_filter: PubSecSubFilter) -> (CryptMethod, u8) {
    match sub_filter {
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
    }
}

/// One candidate recipient set — either the document-level
/// `/Recipients` (for `s3` / `s4`) or one named crypt filter under
/// `/CF` (for `s5`). For per-CF candidates the CFM + Length determine
/// the symmetric algorithm; the document-level fallback inherits from
/// the encrypt dict (`StmF` lookup or default 128-bit RC4).
struct RecipientCandidate {
    /// Named crypt filter the candidate originated from. `None` for
    /// the document-level `/Recipients` slot.
    cf_name: Option<String>,
    /// One PKCS#7 EnvelopedData blob per "permission set".
    blobs: Vec<Vec<u8>>,
    /// Per-CF key length override (None = inherit from dict-level).
    key_length_bits: Option<usize>,
    /// Per-CF (method, revision) override (None = inherit from
    /// dict-level via `default_method_revision`).
    method_revision: Option<(CryptMethod, u8)>,
}

/// Collect every `/Recipients` candidate the encrypt dict references.
///
/// Round 12 generalises the round-10/11 single-CF lookup: we walk
/// every named crypt filter under `/CF`, surfacing each filter's
/// `/Recipients` (when present) plus its `/CFM` + `/Length` overrides.
/// The document-level `/Recipients` slot is also surfaced where
/// applicable (always for `s3` / `s4`; as a "compatibility-fallback"
/// for `s5` when no per-CF list matched).
///
/// Returned candidates are walked in order — the first one whose
/// recipient slot matches the user's certificate wins, mirroring ISO
/// 32000-1 §7.6.4.2's first-match rule.
fn collect_recipient_arrays(encrypt: &Dict) -> Result<Vec<RecipientCandidate>, PdfError> {
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
    let mut out: Vec<RecipientCandidate> = Vec::new();

    if sub == "adbe.pkcs7.s5" {
        // Walk every CF entry. Track the StmF candidate so it lands
        // first (callers typically default to the StmF crypt filter).
        let cf = match lookup(encrypt, "CF") {
            Some(Object::Dict(d)) => d,
            _ => return Err(PdfError::other("PDF pubsec: s5 requires /CF dictionary")),
        };
        let stmf_name: Option<String> = match lookup(encrypt, "StmF") {
            Some(Object::Name(n)) => Some(n),
            _ => None,
        };
        let mut entries = cf.entries().to_vec();
        // Move the StmF entry to the front so its candidate is tried
        // first — round-10 single-CF callers rely on the StmF being
        // the "default" recipient set.
        if let Some(name) = stmf_name.as_ref() {
            if let Some(pos) = entries.iter().position(|(k, _)| k == name) {
                let entry = entries.remove(pos);
                entries.insert(0, entry);
            }
        }
        for (name, entry) in &entries {
            let Object::Dict(filter) = entry else {
                continue;
            };
            let Some(recipients_obj) = lookup(filter, "Recipients") else {
                continue;
            };
            let blobs = recipients_to_blobs(&recipients_obj)?;
            if blobs.is_empty() {
                continue;
            }
            let cfm = match lookup(filter, "CFM") {
                Some(Object::Name(n)) => Some(n),
                _ => None,
            };
            let length = match lookup(filter, "Length") {
                Some(Object::Integer(n)) => Some(n as usize),
                _ => None,
            };
            // Map CFM to (method, revision, default key length).
            let method_revision = cfm.as_deref().and_then(|c| match c {
                "V2" => Some((CryptMethod::Rc4, 4u8)),
                "AESV2" => Some((CryptMethod::Aes128, 4u8)),
                "AESV3" => Some((CryptMethod::Aes256, 6u8)),
                _ => None,
            });
            let key_length_bits = match cfm.as_deref() {
                Some("AESV2") => Some(128),
                Some("AESV3") => Some(256),
                _ => length.map(|len| {
                    // /CF /Length is in bytes per Table 25 of ISO
                    // 32000-1 (the dict-level /Length is in bits).
                    len * 8
                }),
            };
            out.push(RecipientCandidate {
                cf_name: Some(name.clone()),
                blobs,
                key_length_bits,
                method_revision,
            });
        }
        // Compatibility fallback: top-level /Recipients (some s5
        // writers — including round-11's own — emit it for legacy
        // readers).
        if let Some(top) = lookup(encrypt, "Recipients") {
            let blobs = recipients_to_blobs(&top)?;
            // Avoid duplicating a CF candidate's blobs.
            let already = out.iter().any(|c| c.blobs == blobs);
            if !already && !blobs.is_empty() {
                out.push(RecipientCandidate {
                    cf_name: None,
                    blobs,
                    key_length_bits: None,
                    method_revision: None,
                });
            }
        }
    } else {
        // s3 / s4 — document-level /Recipients only.
        let top = lookup(encrypt, "Recipients").ok_or_else(|| {
            PdfError::other("PDF pubsec: /Recipients missing for s3/s4 SubFilter")
        })?;
        let blobs = recipients_to_blobs(&top)?;
        out.push(RecipientCandidate {
            cf_name: None,
            blobs,
            key_length_bits: None,
            method_revision: None,
        });
    }
    Ok(out)
}

fn recipients_to_blobs(array: &Object) -> Result<Vec<Vec<u8>>, PdfError> {
    match array {
        Object::Array(items) => items
            .iter()
            .map(|item| match item {
                Object::LiteralString(s) | Object::HexString(s) => Ok(s.clone()),
                other => Err(PdfError::other(format!(
                    "PDF pubsec: /Recipients element must be a string (got {other:?})"
                ))),
            })
            .collect(),
        // PDF 2.0 accepts a single string for per-stream recipients;
        // surface as a one-element list.
        Object::LiteralString(s) | Object::HexString(s) => Ok(vec![s.clone()]),
        other => Err(PdfError::other(format!(
            "PDF pubsec: /Recipients must be an array of strings (got {other:?})"
        ))),
    }
}

/// Find a recipient slot in `envelope` whose RecipientIdentifier
/// matches `credential.cert`, derive the CEK (KTRI: RSA decrypt;
/// KARI: ECDH + KDF + AES Key Wrap unwrap), and use it to decrypt the
/// envelope's encrypted content. Returns the plaintext (the seed +
/// permissions blob), or `None` if no recipient matched.
///
/// Two RecipientIdentifier forms are matched (RFC 5652 §6.2.1 + RFC
/// 5280 §4.2.1.2):
/// 1. **IssuerAndSerialNumber (CMS v0)** — byte-compare the recipient
///    slot's `(issuer_der, serial)` against the user cert's same pair.
/// 2. **SubjectKeyIdentifier (CMS v2)** — byte-compare the recipient
///    slot's SKI octet string against `SHA-1(SPKI BIT STRING contents)`
///    of the user cert (RFC 5280 §4.2.1.2 method 1).
///
/// Round 14: KARI variants (RFC 5652 §6.2.2 + RFC 5753 §7.1) are
/// unwrapped when the credential carries an EC private scalar (see
/// [`PubSecCredential::from_parsed_ec_p256`]). KARI envelopes whose
/// scheme isn't `dhSinglePass-stdDH-sha256kdf-scheme` (P-256 +
/// X9.63-SHA-256 KDF + AES-KW) are skipped silently — a future round
/// extends this matcher with P-384 / P-521 / X25519.
///
/// Round 17: when the KARI envelope's `OriginatorIdentifierOrKey` is
/// `IssuerAndSerial` or `SubjectKeyIdentifier`, the supplied optional
/// `trust_store` is consulted to recover the originator's public point
/// from the long-term cert. `None` keeps the round-14 behaviour
/// (long-term-cert KARIs are skipped silently).
fn try_unwrap(
    envelope: &cms::EnvelopedData,
    credential: &PubSecCredential,
    trust_store: Option<&TrustStore>,
) -> Result<Option<Vec<u8>>, PdfError> {
    let our_issuer = &credential.cert.issuer_der;
    let our_serial = &credential.cert.serial;
    let our_ski = credential.cert.subject_key_identifier();

    // Walk every RecipientInfo in declaration order — KTRI + KARI.
    for variant in &envelope.all_recipients {
        match variant {
            cms::RecipientInfoVariant::KeyTrans(recipient) => {
                let matched = match &recipient.rid {
                    cms::RecipientId::IssuerAndSerial(ias) => {
                        &ias.issuer_der == our_issuer && &ias.serial == our_serial
                    }
                    cms::RecipientId::SubjectKeyIdentifier(ski) => match &our_ski {
                        Some(our) => ski == our,
                        None => false,
                    },
                };
                if !matched {
                    continue;
                }
                let Some(rsa_key) = credential.private_key.as_ref() else {
                    // No RSA key on this credential — can't open KTRI.
                    continue;
                };
                let cek = rsa_key
                    .decrypt(rsa::Pkcs1v15Encrypt, &recipient.encrypted_key)
                    .map_err(|e| PdfError::other(format!("PDF pubsec: RSA decrypt failed: {e}")))?;
                let plaintext = decrypt_envelope_content(
                    &envelope.content_encryption,
                    &cek,
                    &envelope.encrypted_content,
                )?;
                return Ok(Some(plaintext));
            }
            cms::RecipientInfoVariant::KeyAgree(kari) => {
                // KARI: round-14 P-256 + round-15 P-384 / X25519 +
                // round-16 P-521 + RFC 8418 §2.2 HKDF-X25519 paths.
                // Skip envelopes whose KEA OID names an unsupported
                // KDF, or one not paired with the credential's curve.
                let Some((curve, ec_scalar)) = credential.ec_private.as_ref() else {
                    continue;
                };
                let Some(kdf) = kari::KariKdf::from_kea_oid(&kari.key_encryption_oid) else {
                    continue;
                };
                if !kdf.is_valid_for(*curve) {
                    continue;
                }
                let Some(slot) = kari::match_kari_slot(
                    kari,
                    our_issuer,
                    our_serial,
                    credential.cert.spki_pubkey_bits.as_deref(),
                ) else {
                    continue;
                };
                let recipient = kari::EcRecipient {
                    curve: *curve,
                    private_scalar: ec_scalar.clone(),
                    public_point_sec1: credential.cert.spki_pubkey_bits.clone().unwrap_or_default(),
                };
                let cek = kari::unwrap_kari_with_trust_store(kari, slot, &recipient, trust_store)?;
                let plaintext = decrypt_envelope_content(
                    &envelope.content_encryption,
                    &cek,
                    &envelope.encrypted_content,
                )?;
                return Ok(Some(plaintext));
            }
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
        // Round-17 read-only legacy CMS content encryption — RC2 / 3DES.
        // PDF 2.0 deprecates both; we accept on decode only so legacy
        // archives still open. Keying material lengths follow RFC 3370.
        cms::ContentEncryption::Rc2Cbc {
            effective_key_bits,
            iv,
        } => rc2_cbc_decrypt(cek, *effective_key_bits, iv, ciphertext),
        cms::ContentEncryption::DesEde3Cbc { iv } => des_ede3_cbc_decrypt(cek, iv, ciphertext),
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

/// Round-17 read-only: decrypt an RC2-CBC envelope content. RC2 is a
/// 64-bit block cipher (RFC 2268) — the IV is 8 bytes, blocks are
/// 8 bytes, padding is PKCS#7. The CEK length is the raw key length;
/// `effective_key_bits` is the RC2 effective-key parameter from RFC 2268
/// §6 (configured independently of the raw key length per RFC 3370 §5.1).
///
/// PDF 2.0 deprecates RC2 entirely; this path exists to open legacy
/// archives only. No encode-side support.
fn rc2_cbc_decrypt(
    cek: &[u8],
    effective_key_bits: u32,
    iv: &[u8; 8],
    ct: &[u8],
) -> Result<Vec<u8>, PdfError> {
    use cbc::cipher::{BlockDecryptMut, InnerIvInit};
    use rc2::Rc2;
    if ct.len() % 8 != 0 {
        return Err(PdfError::other(format!(
            "PDF pubsec: RC2-CBC ciphertext {} not block-aligned (8-byte blocks)",
            ct.len()
        )));
    }
    if cek.is_empty() || cek.len() > 128 {
        return Err(PdfError::other(format!(
            "PDF pubsec: RC2 CEK length {} out of RFC 2268 range (1..=128 bytes)",
            cek.len()
        )));
    }
    // `rc2`'s public `KeyInit::new_from_slice` always sets eff_key_len =
    // 8 * key.len(). To honour RFC 3370's separate effective-key
    // parameter we construct the cipher via `new_with_eff_key_len` and
    // wrap it into a CBC decryptor through `InnerIvInit`.
    let cipher = Rc2::new_with_eff_key_len(cek, effective_key_bits as usize);
    let dec = cbc::Decryptor::<Rc2>::inner_iv_slice_init(cipher, iv)
        .map_err(|e| PdfError::other(format!("PDF pubsec: RC2-CBC IV init failed: {e}")))?;
    let mut buf = ct.to_vec();
    let pt = dec
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| PdfError::other(format!("PDF pubsec: RC2-CBC unpad: {e:?}")))?;
    Ok(pt.to_vec())
}

/// Round-17 read-only: decrypt a 3DES-CBC (DES-EDE3-CBC) envelope
/// content. The CEK is the 24-byte concatenation of the three single-DES
/// keys (RFC 3370 §5.2 / RFC 5652 §12.4); the IV is 8 bytes; blocks are
/// 8 bytes; padding is PKCS#7.
///
/// PDF 2.0 deprecates 3DES; this path exists to open legacy archives
/// only. No encode-side support.
fn des_ede3_cbc_decrypt(cek: &[u8], iv: &[u8; 8], ct: &[u8]) -> Result<Vec<u8>, PdfError> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    use des::TdesEde3;
    if ct.len() % 8 != 0 {
        return Err(PdfError::other(format!(
            "PDF pubsec: 3DES-CBC ciphertext {} not block-aligned (8-byte blocks)",
            ct.len()
        )));
    }
    if cek.len() != 24 {
        return Err(PdfError::other(format!(
            "PDF pubsec: 3DES (TdesEde3) CEK must be 24 bytes (got {})",
            cek.len()
        )));
    }
    type Dec = cbc::Decryptor<TdesEde3>;
    let dec = <Dec as KeyIvInit>::new_from_slices(cek, iv)
        .map_err(|e| PdfError::other(format!("PDF pubsec: 3DES-CBC init failed: {e}")))?;
    let mut buf = ct.to_vec();
    let pt = dec
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| PdfError::other(format!("PDF pubsec: 3DES-CBC unpad: {e:?}")))?;
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
        build_envelope_aes128, build_envelope_aes256, build_envelope_rc4, rsa_pkcs1_encrypt,
        RecipientPlain,
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
            spki_pubkey_bits: None,
            validity: None,
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
        let encrypted_key = rsa_pkcs1_encrypt(&pub_key, &cek).unwrap();
        let envelope_der = build_envelope_rc4(
            &[RecipientPlain::ias(
                issuer_der.clone(),
                serial.clone(),
                encrypted_key,
            )],
            &plaintext,
            &cek,
        );
        let credential = PubSecCredential::from_parsed(fake_cert(&issuer_der, &serial), priv_key);
        let encrypt = make_encrypt_dict("adbe.pkcs7.s4", 2, &[envelope_der]);
        let handler = open_with_certificate(&encrypt, &credential)
            .expect("open ok")
            .expect("matched recipient");
        assert_eq!(handler.method, CryptMethod::Rc4);
        assert_eq!(handler.revision, 3);
        assert_eq!(handler.key.len(), 16);
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
            &[RecipientPlain::ias(
                issuer_der.clone(),
                serial.clone(),
                encrypted_key,
            )],
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
            &[RecipientPlain::ias(
                issuer_der.clone(),
                vec![0x01],
                encrypted_key,
            )],
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
            &[RecipientPlain::ias(
                issuer_der.clone(),
                serial.clone(),
                encrypted_key,
            )],
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
