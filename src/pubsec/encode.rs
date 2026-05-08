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
