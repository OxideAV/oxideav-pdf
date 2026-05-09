//! PDF public-key security handler — *writer / encoder* side
//! (round 11).
//!
//! Mirrors [`super::open_with_certificate`]: starting from a
//! [`PubSecEncoderConfig`] (a SubFilter selection + a list of
//! [`PubSecRecipient`]s, each carrying an X.509 cert + RSA public
//! key), produce
//!
//! 1. A symmetric file encryption key the writer feeds to the
//!    same [`crate::decrypt::StandardHandler`] the password-based
//!    encoder uses for per-object string + stream encryption.
//! 2. A CMS `EnvelopedData` (one per envelope; each envelope wraps
//!    the same content-encryption key to every recipient slot)
//!    encoded into a `/Recipients`-array blob.
//! 3. The `/Encrypt` dictionary literal that goes into the trailer
//!    (Filter `/Adobe.PPKLite` + SubFilter + V/R/Length/P/CF/StmF/StrF
//!    /Recipients shaping per ISO 32000-1 §7.6.4 + ISO 32000-2 §7.6.5).
//!
//! Provenance: ISO 32000-1 §7.6.4 + ISO 32000-2 §7.6.5 + RFC 5652 §6
//! + RFC 5280 §4.2.1.2 only.

use crate::decrypt::{CryptMethod, StandardHandler};
use crate::error::PdfError;
use crate::objects::{Dict, Object};

use super::cms_build::{
    build_envelope_aes128, build_envelope_aes256, build_envelope_rc4, rsa_pkcs1_encrypt,
    RecipientIdRef, RecipientPlain,
};
use super::PubSecSubFilter;

/// Recipient identification + public key for an emitted public-key
/// envelope. Either form of RFC 5652 §6.2.1 RecipientIdentifier is
/// supported — `IssuerAndSerial` (CMS v0) or `SubjectKeyIdentifier`
/// (CMS v2).
#[derive(Debug, Clone)]
pub struct PubSecRecipient {
    /// Recipient identifier — IAS or SKI.
    pub rid: RecipientIdRef,
    /// Recipient's RSA public key. Used to wrap the
    /// content-encryption key with `RSAES-PKCS1-v1_5`.
    pub public_key: rsa::RsaPublicKey,
}

impl PubSecRecipient {
    /// Build a recipient from an `IssuerAndSerialNumber` pair plus an
    /// `rsa::RsaPublicKey`.
    pub fn from_issuer_and_serial(
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
        public_key: rsa::RsaPublicKey,
    ) -> Self {
        Self {
            rid: RecipientIdRef::IssuerAndSerial { issuer_der, serial },
            public_key,
        }
    }

    /// Build a recipient from a SubjectKeyIdentifier (20-byte SHA-1 of
    /// the cert's SPKI BIT STRING contents — RFC 5280 §4.2.1.2 method
    /// 1) plus an `rsa::RsaPublicKey`.
    pub fn from_subject_key_identifier(ski: Vec<u8>, public_key: rsa::RsaPublicKey) -> Self {
        Self {
            rid: RecipientIdRef::SubjectKeyIdentifier { ski },
            public_key,
        }
    }

    /// Build a recipient from a parsed [`super::x509::Certificate`].
    /// Uses the `IssuerAndSerial` form by default; callers wanting
    /// SKI matching should use [`Self::from_subject_key_identifier`]
    /// after pulling the SKI out of the cert.
    pub fn from_certificate(
        cert: &super::x509::Certificate,
        public_key: rsa::RsaPublicKey,
    ) -> Self {
        Self::from_issuer_and_serial(cert.issuer_der.clone(), cert.serial.clone(), public_key)
    }
}

/// Writer-side configuration for the public-key security handler.
/// Picks one of the four PDF SubFilters and lists the recipients
/// that may open the resulting file.
#[derive(Debug, Clone)]
pub struct PubSecEncoderConfig {
    /// SubFilter — selects symmetric algorithm + (V, R) pair.
    pub sub_filter: PubSecSubFilter,
    /// 32-bit signed permissions value (§7.6.3.2 Table 22). Same
    /// shape as the password-handler's `EncryptionConfig::p`.
    pub p: i32,
    /// Whether the document metadata stream is encrypted (R≥4).
    /// Wired into both the `/EncryptMetadata` dict entry and the
    /// `0xFFFFFFFF` opt-in tail of the SHA-1 / SHA-256 file-key
    /// derivation when false (§7.6.4.3 / §7.6.5.3).
    pub encrypt_metadata: bool,
    /// Recipients that may open the document. Each gets its own
    /// `KeyTransRecipientInfo` slot in the CMS `EnvelopedData` —
    /// the wrapped CEK is the same content-encryption key for every
    /// recipient in the same envelope, so any one of them can open
    /// the PDF.
    pub recipients: Vec<PubSecRecipient>,
    /// 20-byte seed prefixed to the envelope plaintext. Pinned for
    /// determinism in tests; production callers should use a fresh
    /// random per file.
    pub seed: [u8; 20],
    /// Content-encryption key (CEK). Length must match the SubFilter:
    /// 16 bytes for s3 (RC4-40 keys are 16 bytes per ISO 32000-1
    /// §7.6.4.3 — the 40-bit subset is selected via /Length only),
    /// 16 bytes for s4 / s5-V4-AESV2, 32 bytes for s5-V5-AESV3.
    pub cek: Vec<u8>,
    /// AES CBC IV for the envelope's encrypted content (s5 only).
    /// Ignored for s3 / s4 (RC4 — no IV).
    pub envelope_iv: [u8; 16],
    /// IV used for per-object AES encryption (16 bytes). Tests pin;
    /// production callers should override per-object.
    pub aes_iv: [u8; 16],
}

impl PubSecEncoderConfig {
    /// Default config for `adbe.pkcs7.s4` (RC4-128, V=2, SHA-1).
    pub fn pkcs7_s4(recipients: Vec<PubSecRecipient>) -> Self {
        Self {
            sub_filter: PubSecSubFilter::Pkcs7S4,
            p: -4,
            encrypt_metadata: true,
            recipients,
            seed: [0x33; 20],
            cek: vec![0xA1u8; 16],
            envelope_iv: [0; 16],
            aes_iv: [0; 16],
        }
    }

    /// Default config for `adbe.pkcs7.s5` V=4 + AESV2 (AES-128, SHA-1).
    pub fn pkcs7_s5_v4_aes128(recipients: Vec<PubSecRecipient>) -> Self {
        Self {
            sub_filter: PubSecSubFilter::Pkcs7S5V4 { aes: true },
            p: -4,
            encrypt_metadata: true,
            recipients,
            seed: [0x44; 20],
            cek: vec![0xB2u8; 16],
            envelope_iv: [0x77; 16],
            aes_iv: [0; 16],
        }
    }

    /// Default config for `adbe.pkcs7.s5` V=5 + AESV3 (AES-256, SHA-256).
    pub fn pkcs7_s5_v5_aes256(recipients: Vec<PubSecRecipient>) -> Self {
        Self {
            sub_filter: PubSecSubFilter::Pkcs7S5V5,
            p: -4,
            encrypt_metadata: true,
            recipients,
            seed: [0x55; 20],
            cek: vec![0xC3u8; 32],
            envelope_iv: [0x77; 16],
            aes_iv: [0; 16],
        }
    }
}

/// Result of building the writer-side public-key state — symmetric to
/// the password-based [`crate::encrypt::EncryptionState`]. Callers
/// install the handler / encrypt_dict on a `Document` exactly as the
/// password-based encoder does.
#[derive(Debug, Clone)]
pub struct PubSecEncryptionState {
    /// File encryption handler (key + per-object method + revision).
    pub handler: StandardHandler,
    /// `/Encrypt` dictionary literal to thread into the trailer.
    pub encrypt_dict: Dict,
    /// Per-object AES IV.
    pub aes_iv: [u8; 16],
    /// Permanent file identifier — placed in `/ID[0]`. Public-key
    /// PDFs still need an /ID array; we generate a deterministic
    /// 16-byte one (or accept a caller-supplied override via
    /// [`crate::write_pdf_from_scene_pubsec_encrypted`]).
    pub file_id: Vec<u8>,
}

impl PubSecEncryptionState {
    /// Convert to the password-handler [`crate::encrypt::EncryptionState`]
    /// shape so the writer can install it on `Document::encryption`
    /// without duplicating the per-object encryption paths. The
    /// resulting state's `encrypt_dict` is `/Filter /Adobe.PPKLite`
    /// (not `/Filter /Standard`) — every other slot is identical.
    pub fn into_encryption_state(self) -> crate::encrypt::EncryptionState {
        crate::encrypt::EncryptionState {
            handler: self.handler,
            encrypt_dict: self.encrypt_dict,
            file_id: self.file_id,
            aes_iv: self.aes_iv,
        }
    }

    /// Build the writer-side state from a [`PubSecEncoderConfig`]. The
    /// returned `encrypt_dict` is symmetric to what
    /// [`super::open_with_certificate`] consumes.
    pub fn build(config: &PubSecEncoderConfig) -> Result<Self, PdfError> {
        if config.recipients.is_empty() {
            return Err(PdfError::other(
                "PDF pubsec encode: at least one recipient is required",
            ));
        }
        let key_length_bits = key_length_bits(config.sub_filter);
        let n = key_length_bits / 8;
        if config.cek.len() != n {
            return Err(PdfError::other(format!(
                "PDF pubsec encode: CEK must be {} bytes for SubFilter {:?} (got {})",
                n,
                config.sub_filter,
                config.cek.len()
            )));
        }

        // Build the envelope plaintext: 20-byte seed + 4-byte
        // permissions. ISO 32000-1 §7.6.4.3 specifies LSB-first ("least
        // significant byte first"); ISO 32000-2 §7.6.5.3 corrects that
        // to MSB-first. Pick by SubFilter — V=5 takes MSB.
        let mut plaintext = Vec::with_capacity(24);
        plaintext.extend_from_slice(&config.seed);
        let p_bytes = match config.sub_filter {
            PubSecSubFilter::Pkcs7S5V5 => (config.p as u32).to_be_bytes(),
            _ => (config.p as u32).to_le_bytes(),
        };
        plaintext.extend_from_slice(&p_bytes);

        // Pre-compute every recipient's wrapped CEK. Each recipient
        // gets its own RSA-PKCS1-v1.5 wrap (the random RSA padding
        // makes the encrypted_key field different per recipient even
        // when the underlying CEK + public key match).
        let mut slots: Vec<RecipientPlain> = Vec::with_capacity(config.recipients.len());
        for r in &config.recipients {
            let encrypted_key = rsa_pkcs1_encrypt(&r.public_key, &config.cek)?;
            slots.push(RecipientPlain {
                rid: r.rid.clone(),
                encrypted_key,
            });
        }

        // Build the CMS envelope DER per content-encryption algorithm.
        let envelope_der =
            match config.sub_filter {
                PubSecSubFilter::Pkcs7S3 | PubSecSubFilter::Pkcs7S4 => {
                    build_envelope_rc4(&slots, &plaintext, &config.cek)
                }
                PubSecSubFilter::Pkcs7S5V4 { aes: false } => {
                    // RC4 path (CFM=V2).
                    build_envelope_rc4(&slots, &plaintext, &config.cek)
                }
                PubSecSubFilter::Pkcs7S5V4 { aes: true } => {
                    let cek16: [u8; 16] =
                        config.cek.as_slice().try_into().map_err(|_| {
                            PdfError::other("PDF pubsec encode: AES-128 CEK length")
                        })?;
                    build_envelope_aes128(&slots, &plaintext, &cek16, &config.envelope_iv)
                }
                PubSecSubFilter::Pkcs7S5V5 => {
                    let cek32: [u8; 32] =
                        config.cek.as_slice().try_into().map_err(|_| {
                            PdfError::other("PDF pubsec encode: AES-256 CEK length")
                        })?;
                    build_envelope_aes256(&slots, &plaintext, &cek32, &config.envelope_iv)
                }
            };

        // File encryption key derivation per §7.6.4.3 / §7.6.5.3.
        let recipients_blobs = vec![envelope_der.clone()];
        let file_key = derive_file_key(
            config.sub_filter,
            &config.seed,
            &recipients_blobs,
            config.encrypt_metadata,
            key_length_bits,
        );

        let (method, revision) = match config.sub_filter {
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
        let handler = StandardHandler {
            key: file_key,
            method,
            revision,
        };

        // Build the /Encrypt dict literal.
        let encrypt_dict = build_encrypt_dict(config, &envelope_der, key_length_bits)?;

        Ok(Self {
            handler,
            encrypt_dict,
            aes_iv: config.aes_iv,
            file_id: b"OXIDEAV-PUBSEC-ID-0123456789ABCD".to_vec(),
        })
    }

    /// Override the file ID (16+ bytes recommended).
    pub fn with_file_id(mut self, file_id: Vec<u8>) -> Self {
        self.file_id = file_id;
        self
    }
}

// ───────── Round-12: per-permission-set recipient lists ─────────

/// One permission-set inside a public-key-encrypted PDF. Each group
/// emits one PKCS#7 `EnvelopedData` whose plaintext carries the
/// supplied permission mask `p`; only the recipients listed here can
/// open with those permissions.
///
/// Per ISO 32000-1 §7.6.4.2 + §7.6.5.4: "There shall be one PKCS#7
/// object per unique set of access permissions; if a recipient appears
/// in more than one list, the permissions used shall be those in the
/// first matching list." The file encryption key is derived from
/// `SHA(seed_of_matched_envelope ‖ all_envelope_blobs_in_array_order)`
/// — every envelope in the `/Recipients` array contributes to the
/// hash regardless of which one matched, so all recipients share the
/// same per-object encryption key while seeing different permissions.
///
/// The round-12 multi-CF encoder ALSO supports separate
/// [`PubSecMultiCfConfig::cf_groups`] when the caller wants the
/// `/CF` dict to enumerate distinct CRYPT FILTERS (each with its
/// own list); see [`PubSecMultiCfConfig`] for the shape.
#[derive(Debug, Clone)]
pub struct PubSecCfGroup {
    /// Name under `/CF` — typically a descriptive label like
    /// `OwnerCryptFilter` or `ReadOnlyCryptFilter`. Must match the
    /// dictionary-key ASCII alphabet (no `/` prefix; the encoder adds
    /// it).
    pub name: String,
    /// Permission mask for this group (4-byte signed integer per ISO
    /// 32000-1 §7.6.3.2 Table 22).
    pub p: i32,
    /// Recipients allowed to open with this permission set. The same
    /// recipient may appear in multiple groups; the round-12 reader's
    /// first-CF-match rule applies (the group order is the order
    /// supplied here, with the StmF entry sorted to the front).
    pub recipients: Vec<PubSecRecipient>,
    /// Per-group seed (round-trips deterministically; production
    /// callers should override with fresh random per group).
    pub seed: [u8; 20],
    /// Per-group content-encryption key. Length must match the parent
    /// config's SubFilter (16 / 32 bytes).
    pub cek: Vec<u8>,
    /// Per-group AES-CBC envelope IV (s5 only).
    pub envelope_iv: [u8; 16],
}

impl PubSecCfGroup {
    /// Convenience constructor: full access (`p = -4`) for AES-256.
    pub fn full_access_aes256(name: impl Into<String>, recipients: Vec<PubSecRecipient>) -> Self {
        Self {
            name: name.into(),
            p: -4,
            recipients,
            seed: [0xA1; 20],
            cek: vec![0xCAu8; 32],
            envelope_iv: [0x77; 16],
        }
    }

    /// Convenience constructor: read-only (`p` clears the print + modify
    /// + extract bits per Table 22). The mask `0xFFFF_F0BF` corresponds
    ///   to "view + accessibility-extract only".
    pub fn read_only_aes256(name: impl Into<String>, recipients: Vec<PubSecRecipient>) -> Self {
        Self {
            name: name.into(),
            p: i32::from_be_bytes([0xFF, 0xFF, 0xF0, 0xBF]),
            recipients,
            seed: [0xB2; 20],
            cek: vec![0xDBu8; 32],
            envelope_iv: [0x88; 16],
        }
    }
}

/// Configuration for a multi-permission-set public-key-encrypted PDF
/// — one `EnvelopedData` per [`PubSecCfGroup`], all threaded into a
/// single `/Recipients` array (which is itself referenced from one
/// or more `/CF` entries).
///
/// Every group's envelope wraps the SAME 20-byte seed and the SAME
/// content-encryption key (per ISO 32000-1 §7.6.4.3 / ISO 32000-2
/// §7.6.5.3 — the file encryption key is derived from
/// `SHA(seed ‖ ALL recipient blobs)`, so the seed must be identical
/// across envelopes for every reader to converge on the same file
/// key). Per-recipient differences surface only as different
/// permission masks in each envelope's plaintext trailer.
#[derive(Debug, Clone)]
pub struct PubSecMultiCfConfig {
    /// Symmetric algorithm + key size — `s5` only. `s3` / `s4` reject
    /// at build time.
    pub sub_filter: PubSecSubFilter,
    /// Whether the document metadata stream is encrypted.
    pub encrypt_metadata: bool,
    /// One permission-set per `PubSecCfGroup`. Must contain at least
    /// one group; the first group's name becomes the dict-level
    /// `/StmF` + `/StrF` CF entry. The CFs all reference the same
    /// `/Recipients` array (containing every group's envelope), so
    /// any matching recipient — regardless of which CF they were
    /// nominally tied to — recovers the file key. Each group's
    /// `seed` field is overridden by `shared_seed` at build time to
    /// guarantee key-derivation convergence; the per-group `seed`
    /// slot stays in the API for forward compatibility (round-13
    /// might add per-stream key streams).
    pub groups: Vec<PubSecCfGroup>,
    /// Per-object AES IV (round-trip determinism only).
    pub aes_iv: [u8; 16],
    /// Shared content-encryption key bytes — must match the
    /// SubFilter's key length (16 for AES-128, 32 for AES-256).
    pub shared_cek: Vec<u8>,
    /// Shared 20-byte seed mixed into the file-key derivation. Must
    /// match across every envelope or the multi-recipient story
    /// breaks (different recipients would derive different file
    /// keys). Defaulted by the test fixtures to `[0xA1; 20]`.
    pub shared_seed: [u8; 20],
}

impl PubSecMultiCfConfig {
    /// Build the writer-side state. Every group's envelope wraps the
    /// SAME shared CEK to that group's recipients with that group's
    /// permission mask; all envelopes go into one `/Recipients`
    /// array. The file encryption key is derived from
    /// `SHA(seed_of_first_group ‖ all_envelopes)` per §7.6.4.3 /
    /// §7.6.5.3.
    pub fn build(self) -> Result<PubSecEncryptionState, PdfError> {
        if self.groups.is_empty() {
            return Err(PdfError::other(
                "PDF pubsec multi-CF: at least one group required",
            ));
        }
        if !matches!(
            self.sub_filter,
            PubSecSubFilter::Pkcs7S5V4 { .. } | PubSecSubFilter::Pkcs7S5V5
        ) {
            return Err(PdfError::other(
                "PDF pubsec multi-CF: only s5 SubFilters support per-CF recipients",
            ));
        }
        let key_length_bits = key_length_bits(self.sub_filter);
        let n = key_length_bits / 8;
        if self.shared_cek.len() != n {
            return Err(PdfError::other(format!(
                "PDF pubsec multi-CF: shared CEK must be {} bytes (got {})",
                n,
                self.shared_cek.len()
            )));
        }
        for g in &self.groups {
            if g.recipients.is_empty() {
                return Err(PdfError::other(format!(
                    "PDF pubsec multi-CF: group {} has no recipients",
                    g.name
                )));
            }
        }
        let mut group_envelopes: Vec<Vec<u8>> = Vec::with_capacity(self.groups.len());
        for g in &self.groups {
            let mut plaintext = Vec::with_capacity(24);
            // The seed is SHARED across every envelope so every
            // reader (regardless of which envelope matched) hashes
            // over the same input and derives the same file key.
            plaintext.extend_from_slice(&self.shared_seed);
            // ISO 32000-2 stores MSB-first for V=5; ISO 32000-1
            // (V≤4) stores LSB-first.
            let p_bytes = match self.sub_filter {
                PubSecSubFilter::Pkcs7S5V5 => (g.p as u32).to_be_bytes(),
                _ => (g.p as u32).to_le_bytes(),
            };
            plaintext.extend_from_slice(&p_bytes);
            // Each recipient gets its own RSA-wrap of the SHARED CEK.
            let mut slots: Vec<RecipientPlain> = Vec::with_capacity(g.recipients.len());
            for r in &g.recipients {
                let encrypted_key = rsa_pkcs1_encrypt(&r.public_key, &self.shared_cek)?;
                slots.push(RecipientPlain {
                    rid: r.rid.clone(),
                    encrypted_key,
                });
            }
            let envelope = match self.sub_filter {
                PubSecSubFilter::Pkcs7S5V4 { aes: false } => {
                    super::cms_build::build_envelope_rc4(&slots, &plaintext, &self.shared_cek)
                }
                PubSecSubFilter::Pkcs7S5V4 { aes: true } => {
                    let cek16: [u8; 16] =
                        self.shared_cek.as_slice().try_into().map_err(|_| {
                            PdfError::other("PDF pubsec multi-CF: AES-128 CEK length")
                        })?;
                    super::cms_build::build_envelope_aes128(
                        &slots,
                        &plaintext,
                        &cek16,
                        &g.envelope_iv,
                    )
                }
                PubSecSubFilter::Pkcs7S5V5 => {
                    let cek32: [u8; 32] =
                        self.shared_cek.as_slice().try_into().map_err(|_| {
                            PdfError::other("PDF pubsec multi-CF: AES-256 CEK length")
                        })?;
                    super::cms_build::build_envelope_aes256(
                        &slots,
                        &plaintext,
                        &cek32,
                        &g.envelope_iv,
                    )
                }
                _ => unreachable!(),
            };
            group_envelopes.push(envelope);
        }
        // File-encryption key — derived from the SHARED seed hashed
        // over EVERY envelope in declaration order. Any reader who
        // matches a slot in ANY envelope recovers the same key
        // because the seed is identical across envelopes and they
        // all hash over the full envelope set.
        let file_key = derive_file_key(
            self.sub_filter,
            &self.shared_seed,
            &group_envelopes,
            self.encrypt_metadata,
            key_length_bits,
        );
        let (method, revision) = match self.sub_filter {
            PubSecSubFilter::Pkcs7S5V4 { aes } => (
                if aes {
                    CryptMethod::Aes128
                } else {
                    CryptMethod::Rc4
                },
                4u8,
            ),
            PubSecSubFilter::Pkcs7S5V5 => (CryptMethod::Aes256, 6),
            _ => unreachable!(),
        };
        let handler = StandardHandler {
            key: file_key,
            method,
            revision,
        };
        let encrypt_dict = build_multi_cf_encrypt_dict(
            self.sub_filter,
            self.encrypt_metadata,
            &self.groups,
            &group_envelopes,
            key_length_bits,
        )?;
        Ok(PubSecEncryptionState {
            handler,
            encrypt_dict,
            aes_iv: self.aes_iv,
            file_id: b"OXIDEAV-PUBSEC-MULTICF-ID-12345!".to_vec(),
        })
    }
}

/// Build the `/Encrypt` dictionary literal for a multi-permission-set
/// public-key-encrypted PDF.
///
/// Each named CF in the `/CF` dict carries the FULL `/Recipients`
/// array (every envelope, not just that CF's own group). This is the
/// only shape that lets every reader — regardless of which envelope
/// they matched — derive the same file encryption key per ISO 32000-1
/// §7.6.4.3 (the hash is over the entire ordered envelope set).
///
/// Readers tell which CF they're "in" by which envelope they matched:
/// the round-12 match path exposes `crypt_filter_name` so the caller
/// can map matched-envelope index → CF group.
fn build_multi_cf_encrypt_dict(
    sub_filter: PubSecSubFilter,
    encrypt_metadata: bool,
    groups: &[PubSecCfGroup],
    envelopes: &[Vec<u8>],
    key_length_bits: usize,
) -> Result<Dict, PdfError> {
    let (sub_filter_name, v, r, cfm) = match sub_filter {
        PubSecSubFilter::Pkcs7S5V4 { aes: true } => ("adbe.pkcs7.s5", 4, 4, "AESV2"),
        PubSecSubFilter::Pkcs7S5V4 { aes: false } => ("adbe.pkcs7.s5", 4, 4, "V2"),
        PubSecSubFilter::Pkcs7S5V5 => ("adbe.pkcs7.s5", 5, 6, "AESV3"),
        _ => {
            return Err(PdfError::other(
                "PDF pubsec multi-CF: only s5 SubFilters supported",
            ))
        }
    };
    let cf_length_bytes = (key_length_bits / 8) as i64;
    // Each CF entry holds the SAME (full) /Recipients array — only
    // the per-envelope permission masks differ. This shape mirrors
    // the way Adobe Acrobat emits multi-permission PPKLite docs.
    let full_recipients = Object::Array(
        envelopes
            .iter()
            .map(|e| Object::LiteralString(e.clone()))
            .collect(),
    );
    let mut cf = Dict::new();
    for g in groups {
        let inner = Dict::new()
            .with("Type", Object::Name("CryptFilter".into()))
            .with("CFM", Object::Name(cfm.into()))
            .with("Length", Object::Integer(cf_length_bytes))
            .with("Recipients", full_recipients.clone());
        cf.set(&g.name, Object::Dict(inner));
    }
    let stmf_name = groups[0].name.clone();
    let mut dict = Dict::new()
        .with("Filter", Object::Name("Adobe.PPKLite".into()))
        .with("SubFilter", Object::Name(sub_filter_name.into()))
        .with("V", Object::Integer(v))
        .with("R", Object::Integer(r))
        .with("Length", Object::Integer(key_length_bits as i64))
        // Dict-level /P is the FIRST group's permission mask
        // (round-trippable via the round-12 multi-match path).
        .with("P", Object::Integer(groups[0].p as i64))
        .with("CF", Object::Dict(cf))
        .with("StmF", Object::Name(stmf_name.clone()))
        .with("StrF", Object::Name(stmf_name));
    if !encrypt_metadata {
        dict.set("EncryptMetadata", Object::Bool(false));
    }
    Ok(dict)
}

fn key_length_bits(sub: PubSecSubFilter) -> usize {
    match sub {
        PubSecSubFilter::Pkcs7S3 => 40,
        PubSecSubFilter::Pkcs7S4 => 128,
        PubSecSubFilter::Pkcs7S5V4 { .. } => 128,
        PubSecSubFilter::Pkcs7S5V5 => 256,
    }
}

fn derive_file_key(
    sub: PubSecSubFilter,
    seed: &[u8],
    recipients_blobs: &[Vec<u8>],
    encrypt_metadata: bool,
    key_length_bits: usize,
) -> Vec<u8> {
    let n = key_length_bits / 8;
    let mut input = Vec::with_capacity(20);
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

fn build_encrypt_dict(
    config: &PubSecEncoderConfig,
    envelope_der: &[u8],
    key_length_bits: usize,
) -> Result<Dict, PdfError> {
    let (sub_filter_name, v, r) = match config.sub_filter {
        PubSecSubFilter::Pkcs7S3 => ("adbe.pkcs7.s3", 1, 2),
        PubSecSubFilter::Pkcs7S4 => ("adbe.pkcs7.s4", 2, 3),
        PubSecSubFilter::Pkcs7S5V4 { .. } => ("adbe.pkcs7.s5", 4, 4),
        PubSecSubFilter::Pkcs7S5V5 => ("adbe.pkcs7.s5", 5, 6),
    };

    let mut dict = Dict::new()
        .with("Filter", Object::Name("Adobe.PPKLite".into()))
        .with("SubFilter", Object::Name(sub_filter_name.into()))
        .with("V", Object::Integer(v))
        .with("R", Object::Integer(r))
        .with("Length", Object::Integer(key_length_bits as i64))
        .with("P", Object::Integer(config.p as i64));

    if !config.encrypt_metadata {
        dict.set("EncryptMetadata", Object::Bool(false));
    }

    let recipients_arr = Object::Array(vec![Object::LiteralString(envelope_der.to_vec())]);

    match config.sub_filter {
        PubSecSubFilter::Pkcs7S3 | PubSecSubFilter::Pkcs7S4 => {
            // s3 / s4: /Recipients lives at the top level.
            dict.set("Recipients", recipients_arr);
        }
        PubSecSubFilter::Pkcs7S5V4 { aes } => {
            // s5 V=4: /Recipients lives in /CF /<F>. Per ISO 32000-1
            // Table 27 the recipients array also appears at the
            // top-level /Recipients for compatibility; we mirror the
            // round-10 fixture builder which emits both.
            let cfm = if aes { "AESV2" } else { "V2" };
            let std_cf = Dict::new()
                .with("Type", Object::Name("CryptFilter".into()))
                .with("CFM", Object::Name(cfm.into()))
                .with("Length", Object::Integer(16))
                .with("Recipients", recipients_arr.clone());
            let cf = Dict::new().with("DefaultCryptFilter", Object::Dict(std_cf));
            dict.set("CF", Object::Dict(cf));
            dict.set("StmF", Object::Name("DefaultCryptFilter".into()));
            dict.set("StrF", Object::Name("DefaultCryptFilter".into()));
            dict.set("Recipients", recipients_arr);
        }
        PubSecSubFilter::Pkcs7S5V5 => {
            // s5 V=5: AESV3 crypt filter, recipients in /CF.
            let std_cf = Dict::new()
                .with("Type", Object::Name("CryptFilter".into()))
                .with("CFM", Object::Name("AESV3".into()))
                .with("Length", Object::Integer(32))
                .with("Recipients", recipients_arr.clone());
            let cf = Dict::new().with("DefaultCryptFilter", Object::Dict(std_cf));
            dict.set("CF", Object::Dict(cf));
            dict.set("StmF", Object::Name("DefaultCryptFilter".into()));
            dict.set("StrF", Object::Name("DefaultCryptFilter".into()));
            dict.set("Recipients", recipients_arr);
        }
    }

    Ok(dict)
}

// ───────── Round-15: writer-side KARI envelope ─────────

/// One KARI recipient slot the writer will emit. The recipient is
/// identified by their X.509 certificate (issuer + serial — KARI
/// `RecipientEncryptedKey` IAS form), and `recipient_pub_bytes` carries
/// their public key in the curve's encoded form (SEC1 uncompressed for
/// P-256 / P-384 / P-521, raw 32-byte u-coordinate for X25519).
#[derive(Debug, Clone)]
pub struct KariRecipient {
    /// Recipient certificate's issuer DER (a SEQUENCE — same shape as
    /// [`super::cms_build::RecipientIdRef::IssuerAndSerial::issuer_der`]).
    pub issuer_der: Vec<u8>,
    /// Recipient cert's serial number INTEGER body bytes.
    pub serial: Vec<u8>,
    /// Curve the recipient's keypair lives on. Determines the ECDH
    /// primitive + ephemeral keypair shape the writer will emit.
    pub curve: super::kari::KariCurve,
    /// KDF binding the writer will encode in
    /// `KeyAgreeRecipientInfo.keyEncryptionAlgorithm`. Defaults via the
    /// per-curve constructors to [`super::kari::KariCurve::default_kdf`]:
    /// RFC 5753 §7.1.4 X9.63 with the matching hash for NIST curves;
    /// RFC 8418 §2.1 X9.63-SHA-256 for X25519. Use the
    /// `x25519_hkdf_*` constructors to switch X25519 to the modern RFC
    /// 8418 §2.2 HKDF binding.
    pub kdf: super::kari::KariKdf,
    /// Recipient's encoded public key. SEC1 uncompressed point for
    /// NIST curves; raw 32-byte u-coordinate for X25519.
    pub recipient_pub_bytes: Vec<u8>,
    /// Ephemeral private scalar used for THIS recipient's wrap. Each
    /// recipient gets its own ephemeral keypair so the writer can mix
    /// curves across recipients in a single envelope (one KARI per
    /// curve / ephemeral). Tests pin to a deterministic value;
    /// production callers should use a fresh random scalar per
    /// recipient.
    pub ephemeral_scalar: Vec<u8>,
}

impl KariRecipient {
    /// Build a P-256 recipient (X9.63-SHA-256 KDF per RFC 5753 §7.1.4).
    pub fn p256(
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
        recipient_pub_sec1: Vec<u8>,
        ephemeral_scalar: Vec<u8>,
    ) -> Self {
        Self {
            issuer_der,
            serial,
            curve: super::kari::KariCurve::P256,
            kdf: super::kari::KariKdf::X963Sha256,
            recipient_pub_bytes: recipient_pub_sec1,
            ephemeral_scalar,
        }
    }

    /// Build a P-384 recipient (X9.63-SHA-384 KDF per RFC 5753 §7.1.4).
    pub fn p384(
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
        recipient_pub_sec1: Vec<u8>,
        ephemeral_scalar: Vec<u8>,
    ) -> Self {
        Self {
            issuer_der,
            serial,
            curve: super::kari::KariCurve::P384,
            kdf: super::kari::KariKdf::X963Sha384,
            recipient_pub_bytes: recipient_pub_sec1,
            ephemeral_scalar,
        }
    }

    /// Round-16: build a P-521 recipient (X9.63-SHA-512 KDF per RFC
    /// 5753 §7.1.4 — `dhSinglePass-stdDH-sha512kdf-scheme`,
    /// OID 1.3.132.1.11.3).
    pub fn p521(
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
        recipient_pub_sec1: Vec<u8>,
        ephemeral_scalar: Vec<u8>,
    ) -> Self {
        Self {
            issuer_der,
            serial,
            curve: super::kari::KariCurve::P521,
            kdf: super::kari::KariKdf::X963Sha512,
            recipient_pub_bytes: recipient_pub_sec1,
            ephemeral_scalar,
        }
    }

    /// Build an X25519 recipient with the legacy X9.63-SHA-256 KDF
    /// binding (RFC 8418 §2.1).
    pub fn x25519(
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
        recipient_pub_x25519: Vec<u8>,
        ephemeral_scalar: Vec<u8>,
    ) -> Self {
        Self {
            issuer_der,
            serial,
            curve: super::kari::KariCurve::X25519,
            kdf: super::kari::KariKdf::X963Sha256,
            recipient_pub_bytes: recipient_pub_x25519,
            ephemeral_scalar,
        }
    }

    /// Round-16: build an X25519 recipient with the modern HKDF-SHA-256
    /// KDF binding (RFC 8418 §2.2 — `dhSinglePass-stdDH-hkdf-sha256-scheme`,
    /// smime-alg 19).
    pub fn x25519_hkdf_sha256(
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
        recipient_pub_x25519: Vec<u8>,
        ephemeral_scalar: Vec<u8>,
    ) -> Self {
        Self {
            issuer_der,
            serial,
            curve: super::kari::KariCurve::X25519,
            kdf: super::kari::KariKdf::HkdfSha256,
            recipient_pub_bytes: recipient_pub_x25519,
            ephemeral_scalar,
        }
    }

    /// Round-16: build an X25519 recipient with HKDF-SHA-384 (RFC 8418
    /// §2.2 — `dhSinglePass-stdDH-hkdf-sha384-scheme`, smime-alg 20).
    pub fn x25519_hkdf_sha384(
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
        recipient_pub_x25519: Vec<u8>,
        ephemeral_scalar: Vec<u8>,
    ) -> Self {
        Self {
            issuer_der,
            serial,
            curve: super::kari::KariCurve::X25519,
            kdf: super::kari::KariKdf::HkdfSha384,
            recipient_pub_bytes: recipient_pub_x25519,
            ephemeral_scalar,
        }
    }

    /// Round-16: build an X25519 recipient with HKDF-SHA-512 (RFC 8418
    /// §2.2 — `dhSinglePass-stdDH-hkdf-sha512-scheme`, smime-alg 21).
    pub fn x25519_hkdf_sha512(
        issuer_der: Vec<u8>,
        serial: Vec<u8>,
        recipient_pub_x25519: Vec<u8>,
        ephemeral_scalar: Vec<u8>,
    ) -> Self {
        Self {
            issuer_der,
            serial,
            curve: super::kari::KariCurve::X25519,
            kdf: super::kari::KariKdf::HkdfSha512,
            recipient_pub_bytes: recipient_pub_x25519,
            ephemeral_scalar,
        }
    }
}

/// Configuration for a writer-side KARI public-key envelope. AES-256
/// content + AES-256-WRAP (the round-15 baseline; AES-128 / AES-192
/// wrap variants are reachable through [`super::kari::wrap_cek_for_recipient`]
/// directly if a caller needs them).
///
/// Each recipient gets its own KARI in the RecipientInfos SET — that's
/// the only way to mix curves cleanly because a single KARI's
/// `keyEncryptionAlgorithm` binds one (curve, KDF) pair (RFC 5652
/// §6.2.2 + RFC 5753 §3.1). All KARIs wrap the same CEK so any
/// matching recipient recovers the same AES-256 file content.
#[derive(Debug, Clone)]
pub struct PubSecKariConfig {
    /// 32-bit signed permissions value (§7.6.3.2 Table 22).
    pub p: i32,
    /// Whether the document metadata stream is encrypted. Plumbed into
    /// both the `/EncryptMetadata` dict entry and the `0xFFFFFFFF`
    /// opt-in tail of the SHA-256 file-key derivation when false.
    pub encrypt_metadata: bool,
    /// One [`KariRecipient`] per recipient certificate.
    pub recipients: Vec<KariRecipient>,
    /// Optional UKM (UserKeyingMaterial) mixed into the X9.63 KDF on
    /// both sides. Same UKM is used for every recipient's wrap (RFC
    /// 5753 §7.2 — the UKM is per-KARI). `None` for "absent".
    pub ukm: Option<Vec<u8>>,
    /// 20-byte seed prefixed to the envelope plaintext. Tests pin for
    /// determinism.
    pub seed: [u8; 20],
    /// 32-byte content-encryption key. AES-256.
    pub cek: [u8; 32],
    /// AES-256-CBC envelope IV.
    pub envelope_iv: [u8; 16],
    /// Per-object AES IV.
    pub aes_iv: [u8; 16],
}

impl PubSecKariConfig {
    /// Default config for AES-256 KARI with deterministic test
    /// constants. Production callers should override `seed`, `cek`,
    /// `envelope_iv`, `aes_iv`, and each recipient's `ephemeral_scalar`
    /// with fresh random bytes.
    pub fn aes256(recipients: Vec<KariRecipient>) -> Self {
        Self {
            p: -4,
            encrypt_metadata: true,
            recipients,
            ukm: None,
            seed: [0x6Au8; 20],
            cek: [0x9Cu8; 32],
            envelope_iv: [0x77; 16],
            aes_iv: [0; 16],
        }
    }
}

impl PubSecEncryptionState {
    /// Round-15: build the writer-side state for a KARI-encrypted PDF.
    /// Emits one CMS `EnvelopedData` containing one
    /// `KeyAgreeRecipientInfo` per recipient (each one sized to its own
    /// curve), all wrapping the same shared CEK with AES-256-WRAP.
    /// Symmetric to the round-14 reader path: the resulting
    /// `/Encrypt` dict opens via [`super::open_with_certificate`] when
    /// the recipient passes a [`PubSecCredential`] carrying their EC
    /// scalar.
    pub fn build_kari(config: &PubSecKariConfig) -> Result<Self, PdfError> {
        if config.recipients.is_empty() {
            return Err(PdfError::other(
                "PDF pubsec KARI encode: at least one recipient is required",
            ));
        }
        // Plaintext: 20-byte seed + 4-byte permissions (V=5 / AES-256
        // takes MSB-first per ISO 32000-2 §7.6.5.3).
        let mut plaintext = Vec::with_capacity(24);
        plaintext.extend_from_slice(&config.seed);
        plaintext.extend_from_slice(&(config.p as u32).to_be_bytes());

        // Build each recipient's KARI: ephemeral keypair, ECDH against
        // recipient pub, KDF, AES-KW. Each KARI carries one
        // RecipientEncryptedKey because the KEA pinpoints one curve.
        let wrap = super::kari::WrapAlgorithm::Aes256;
        let mut karis: Vec<Vec<u8>> = Vec::with_capacity(config.recipients.len());
        for r in &config.recipients {
            if r.recipient_pub_bytes.len() != r.curve.pub_point_len() {
                return Err(PdfError::other(format!(
                    "PDF pubsec KARI encode: recipient pub_bytes {} != expected {} for {:?}",
                    r.recipient_pub_bytes.len(),
                    r.curve.pub_point_len(),
                    r.curve
                )));
            }
            let (originator_pub, wrapped) = super::kari::wrap_cek_for_recipient_with_kdf(
                r.curve,
                r.kdf,
                &r.ephemeral_scalar,
                &r.recipient_pub_bytes,
                config.ukm.as_deref(),
                &config.cek,
                wrap,
            )?;
            // KEA params = AlgorithmIdentifier of the wrap.
            let kea_params = super::der::write_sequence(&super::der::write_oid(wrap.oid()));
            let originator = super::cms_build::OriginatorIdRef::OriginatorKey {
                algorithm_oid: r.curve.algorithm_oid().to_vec(),
                algorithm_params: r.curve.algorithm_params(),
                public_key: originator_pub,
            };
            let recipient_slot = super::cms_build::KariRecipientPlain {
                rid: super::cms_build::KariRecipientIdRef::IssuerAndSerial {
                    issuer_der: r.issuer_der.clone(),
                    serial: r.serial.clone(),
                },
                encrypted_key: wrapped,
            };
            // We build ONE envelope per KARI with the same CEK + IV
            // for the content; the per-recipient envelope's CMS layout
            // carries just that recipient's KARI. Then we splice all
            // KARIs into the one outer EnvelopedData below. The KEA
            // OID is the recipient's KDF OID (so the same envelope can
            // mix X9.63 + HKDF X25519 recipients).
            let envelope = super::cms_build::build_envelope_kari_aes256(
                &originator,
                config.ukm.as_deref(),
                r.kdf.kea_oid(),
                &kea_params,
                &[recipient_slot],
                &plaintext,
                &config.cek,
                &config.envelope_iv,
            );
            karis.push(envelope);
        }
        // The /Recipients array carries one envelope blob per
        // recipient — every reader hashes over the entire ordered set
        // to derive the file key, so all recipients converge on the
        // same AES-256 file key (the seed is identical across
        // envelopes via the shared `config.seed`).
        let key_length_bits = 256usize;
        let file_key = derive_file_key(
            PubSecSubFilter::Pkcs7S5V5,
            &config.seed,
            &karis,
            config.encrypt_metadata,
            key_length_bits,
        );
        let handler = StandardHandler {
            key: file_key,
            method: CryptMethod::Aes256,
            revision: 6,
        };
        // /Encrypt dict — same shape as the round-11/12 KTRI s5/V=5
        // path, just with the KARI envelopes in /Recipients.
        let recipients_arr = Object::Array(
            karis
                .iter()
                .map(|e| Object::LiteralString(e.clone()))
                .collect(),
        );
        let std_cf = Dict::new()
            .with("Type", Object::Name("CryptFilter".into()))
            .with("CFM", Object::Name("AESV3".into()))
            .with("Length", Object::Integer(32))
            .with("Recipients", recipients_arr.clone());
        let cf = Dict::new().with("DefaultCryptFilter", Object::Dict(std_cf));
        let mut dict = Dict::new()
            .with("Filter", Object::Name("Adobe.PPKLite".into()))
            .with("SubFilter", Object::Name("adbe.pkcs7.s5".into()))
            .with("V", Object::Integer(5))
            .with("R", Object::Integer(6))
            .with("Length", Object::Integer(256))
            .with("P", Object::Integer(config.p as i64))
            .with("CF", Object::Dict(cf))
            .with("StmF", Object::Name("DefaultCryptFilter".into()))
            .with("StrF", Object::Name("DefaultCryptFilter".into()))
            .with("Recipients", recipients_arr);
        if !config.encrypt_metadata {
            dict.set("EncryptMetadata", Object::Bool(false));
        }
        Ok(PubSecEncryptionState {
            handler,
            encrypt_dict: dict,
            aes_iv: config.aes_iv,
            file_id: b"OXIDEAV-PUBSEC-KARI-ID-12345!XYZ".to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::open_with_certificate;
    use super::*;
    use crate::pubsec::x509::Certificate;
    use crate::pubsec::PubSecCredential;

    fn keypair() -> (rsa::RsaPrivateKey, rsa::RsaPublicKey) {
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        (priv_key, pub_key)
    }

    fn fake_cert(issuer_der: Vec<u8>, serial: Vec<u8>) -> Certificate {
        Certificate {
            issuer_der,
            serial,
            spki_pubkey_bits: None,
        }
    }

    #[test]
    fn s4_writer_then_reader_round_trip_via_ias() {
        let (priv_key, pub_key) = keypair();
        let issuer_der = super::super::der::write_sequence(b"O=enc-test");
        let serial = vec![0x10, 0x20];
        let cfg = PubSecEncoderConfig::pkcs7_s4(vec![PubSecRecipient::from_issuer_and_serial(
            issuer_der.clone(),
            serial.clone(),
            pub_key,
        )]);
        let state = PubSecEncryptionState::build(&cfg).expect("build");
        // Open the resulting /Encrypt dict via the round-10 reader
        // path — it should derive the same handler.
        let cred = PubSecCredential::from_parsed(fake_cert(issuer_der, serial), priv_key);
        let handler = open_with_certificate(&state.encrypt_dict, &cred)
            .expect("open ok")
            .expect("matched");
        assert_eq!(handler.method, state.handler.method);
        assert_eq!(handler.revision, state.handler.revision);
        assert_eq!(handler.key, state.handler.key);
    }

    #[test]
    fn s5_v4_aes128_writer_then_reader_round_trip() {
        let (priv_key, pub_key) = keypair();
        let issuer_der = super::super::der::write_sequence(b"O=enc-aes-128");
        let serial = vec![0x05];
        let cfg =
            PubSecEncoderConfig::pkcs7_s5_v4_aes128(vec![PubSecRecipient::from_issuer_and_serial(
                issuer_der.clone(),
                serial.clone(),
                pub_key,
            )]);
        let state = PubSecEncryptionState::build(&cfg).expect("build");
        let cred = PubSecCredential::from_parsed(fake_cert(issuer_der, serial), priv_key);
        let handler = open_with_certificate(&state.encrypt_dict, &cred)
            .expect("open")
            .expect("matched");
        assert_eq!(handler.method, CryptMethod::Aes128);
        assert_eq!(handler.revision, 4);
    }

    #[test]
    fn s5_v5_aes256_writer_then_reader_round_trip() {
        let (priv_key, pub_key) = keypair();
        let issuer_der = super::super::der::write_sequence(b"O=enc-aes-256");
        let serial = vec![0x42, 0x01];
        let cfg =
            PubSecEncoderConfig::pkcs7_s5_v5_aes256(vec![PubSecRecipient::from_issuer_and_serial(
                issuer_der.clone(),
                serial.clone(),
                pub_key,
            )]);
        let state = PubSecEncryptionState::build(&cfg).expect("build");
        let cred = PubSecCredential::from_parsed(fake_cert(issuer_der, serial), priv_key);
        let handler = open_with_certificate(&state.encrypt_dict, &cred)
            .expect("open")
            .expect("matched");
        assert_eq!(handler.method, CryptMethod::Aes256);
        assert_eq!(handler.revision, 6);
        assert_eq!(handler.key.len(), 32);
    }

    #[test]
    fn s5_v5_writer_via_ski_recipient_form() {
        // Build a synthetic full-SPKI cert and use its SKI to match.
        let (priv_key, pub_key) = keypair();
        // Fake "SPKI BIT STRING contents" — sha1(it) is the SKI.
        let pubkey_bits = b"OXIDEAV-PUBSEC-WRITER-SKI-MATCH!".to_vec();
        use sha1::Digest;
        let ski = sha1::Sha1::digest(&pubkey_bits).to_vec();
        let mut cfg = PubSecEncoderConfig::pkcs7_s5_v5_aes256(vec![
            PubSecRecipient::from_subject_key_identifier(ski.clone(), pub_key),
        ]);
        cfg.seed = [0xAB; 20];
        let state = PubSecEncryptionState::build(&cfg).expect("build");
        // Construct a credential whose cert has the same SPKI bytes —
        // open_with_certificate computes SHA-1 internally.
        let cred = PubSecCredential::from_parsed(
            Certificate {
                issuer_der: vec![],
                serial: vec![],
                spki_pubkey_bits: Some(pubkey_bits),
            },
            priv_key,
        );
        let handler = open_with_certificate(&state.encrypt_dict, &cred)
            .expect("open")
            .expect("SKI matched");
        assert_eq!(handler.method, CryptMethod::Aes256);
        assert_eq!(handler.key.len(), 32);
    }

    #[test]
    fn empty_recipients_rejected() {
        let cfg = PubSecEncoderConfig::pkcs7_s5_v5_aes256(vec![]);
        let err = PubSecEncryptionState::build(&cfg).unwrap_err();
        assert!(format!("{err}").contains("at least one recipient"));
    }
}
