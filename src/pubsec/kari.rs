//! Round-14 / round-15 / round-16: KARI unwrap — RFC 5753 / RFC 8418
//! ECDH key agreement + RFC 3394 AES Key Wrap. Round 14 closed the
//! round-12 deferral by surfacing the wrapped CEK on P-256; round 15
//! extended coverage to P-384 (NIST FIPS 186-4) and X25519 (RFC 7748
//! / RFC 8418 §2.1) and added the symmetric writer-side helper
//! [`wrap_cek_for_recipient`] used by `write_pdf_from_scene_pubsec_kari`;
//! round 16 closes both the curve coverage (P-521 — NIST FIPS 186-4
//! `secp521r1` + X9.63-SHA-512 KDF) and the modern KDF binding (RFC
//! 8418 §2.2 HKDF for X25519 — `dhSinglePass-stdDH-hkdf-sha256/384/512-scheme`,
//! smime-alg 19 / 20 / 21).
//!
//! ## Coverage
//!
//! | Curve  | KDF                  | Wrap                 | OID for KEA scheme                       |
//! |--------|----------------------|----------------------|------------------------------------------|
//! | P-256  | X9.63 + SHA-256      | AES-128/192/256-WRAP | 1.3.132.1.11.1 (`stdDH-sha256kdf`)       |
//! | P-384  | X9.63 + SHA-384      | AES-128/192/256-WRAP | 1.3.132.1.11.2 (`stdDH-sha384kdf`)       |
//! | P-521  | X9.63 + SHA-512      | AES-128/192/256-WRAP | 1.3.132.1.11.3 (`stdDH-sha512kdf`)       |
//! | X25519 | X9.63 + SHA-256      | AES-128/192/256-WRAP | 1.3.132.1.11.1 (`stdDH-sha256kdf`)       |
//! | X25519 | HKDF-SHA-256         | AES-128/192/256-WRAP | 1.2.840.113549.1.9.16.3.19 (`hkdf-sha256`) |
//! | X25519 | HKDF-SHA-384         | AES-128/192/256-WRAP | 1.2.840.113549.1.9.16.3.20 (`hkdf-sha384`) |
//! | X25519 | HKDF-SHA-512         | AES-128/192/256-WRAP | 1.2.840.113549.1.9.16.3.21 (`hkdf-sha512`) |
//!
//! For X25519 we follow RFC 8418 §2.1 (X9.63 binding, secg-scheme OID
//! family) AND RFC 8418 §2.2 (HKDF binding, smime-alg OID family). The
//! per-recipient choice is carried in [`KariKdf`]; the writer's
//! [`KariRecipient`] carries it explicitly while the reader infers
//! the KDF from the parsed `KeyAgreeRecipientInfo.keyEncryptionAlgorithm`
//! OID. X448 is deferred until a vetted pure-Rust crate appears.
//!
//! ## Algorithm summary (RFC 5753 §3.1 + §7.1, RFC 3394 §2.2.2)
//!
//! 1. The recipient parses the originator's encoded SEC1 EC point
//!    (`OriginatorPublicKey.public_key`) into a P-256 `PublicKey`.
//! 2. The recipient computes the shared secret `Z` via ECDH —
//!    `Z = (privateKey · originatorPublicKey).x` — yielding the
//!    fixed-length 32-byte SEC1 X-coordinate.
//! 3. The KEK is derived via the X9.63 KDF (`hash(Z || counter ||
//!    sharedInfo)` looped, output truncated to the wrap key length).
//!    `sharedInfo` is the DER `ECC-CMS-SharedInfo` ASN.1 structure
//!    holding the wrap algorithm OID + optional UKM + intended key
//!    bit-length suffix (RFC 5753 §7.2).
//! 4. The recipient unwraps the CEK from `RecipientEncryptedKey.encryptedKey`
//!    using AES Key Wrap (RFC 3394) with the derived KEK.
//!
//! Provenance: RFC 5753 §3.1 / §7.1 / §7.2 + RFC 3394 §2.2.2 + RFC
//! 5652 §6.2.2 + NIST SP 800-56A only. `p256` + `aes-kw` docs.rs.

use crate::error::PdfError;

use super::cms::{
    KeyAgreeRecipientId, KeyAgreeRecipientInfo, OriginatorId, OriginatorPublicKey,
    RecipientEncryptedKey,
};
use super::der::{read_oid, read_sequence, write_oid, write_sequence};

/// OID `1.2.840.10045.2.1` — ecPublicKey (RFC 5480 §2.1.1). Identifies
/// an EC public key inside `OriginatorPublicKey.algorithm`.
pub const OID_EC_PUBLIC_KEY: [u64; 6] = [1, 2, 840, 10045, 2, 1];

/// OID `1.2.840.10045.3.1.7` — secp256r1 / NIST P-256 (RFC 5480 §2.1.1.1).
pub const OID_SECP256R1: [u64; 7] = [1, 2, 840, 10045, 3, 1, 7];

/// OID `1.3.132.0.34` — secp384r1 / NIST P-384 (RFC 5480 §2.1.1.1 +
/// SECG SEC 2). Same encoding as P-256: a named-curve OID inside the
/// `ecPublicKey` AlgorithmIdentifier's `parameters`.
pub const OID_SECP384R1: [u64; 5] = [1, 3, 132, 0, 34];

/// OID `1.3.132.0.35` — secp521r1 / NIST P-521 (RFC 5480 §2.1.1.1 +
/// SECG SEC 2). Round-16: same encoding shape as P-256 / P-384 — a
/// named-curve OID inside the `ecPublicKey` AlgorithmIdentifier's
/// `parameters`.
pub const OID_SECP521R1: [u64; 5] = [1, 3, 132, 0, 35];

/// OID `1.3.101.110` — `id-X25519` (RFC 8410 §3 — the curve identifier
/// used by both X.509 SPKIs and CMS KARI's `OriginatorPublicKey`). RFC
/// 8418 §2 mandates an absent `parameters` field (no OID nor NULL) for
/// the AlgorithmIdentifier carrying this OID.
pub const OID_X25519: [u64; 4] = [1, 3, 101, 110];

/// OID `1.3.132.1.11.1` — `dhSinglePass-stdDH-sha256kdf-scheme` (RFC
/// 5753 §7.1.4 + RFC 8418 §2.1). Combined ECDH + X9.63-SHA-256 KDF
/// identifier. Used for both P-256 and X25519 in the round-15 dispatch.
pub const OID_DH_SINGLE_PASS_STDDH_SHA256_KDF: [u64; 6] = [1, 3, 132, 1, 11, 1];

/// OID `1.3.132.1.11.2` — `dhSinglePass-stdDH-sha384kdf-scheme` (RFC
/// 5753 §7.1.4). Combined ECDH + X9.63-SHA-384 KDF identifier. Round-15
/// dispatch binds this to P-384.
pub const OID_DH_SINGLE_PASS_STDDH_SHA384_KDF: [u64; 6] = [1, 3, 132, 1, 11, 2];

/// OID `1.3.132.1.11.3` — `dhSinglePass-stdDH-sha512kdf-scheme` (RFC
/// 5753 §7.1.4). Combined ECDH + X9.63-SHA-512 KDF identifier.
/// Round-16 dispatch binds this to P-521.
pub const OID_DH_SINGLE_PASS_STDDH_SHA512_KDF: [u64; 6] = [1, 3, 132, 1, 11, 3];

/// OID `1.2.840.113549.1.9.16.3.19` — `dhSinglePass-stdDH-hkdf-sha256-scheme`
/// (RFC 8418 §2.2, smime-alg 19). Combined ECDH + HKDF-SHA-256 KDF
/// identifier. Round-16 dispatch routes X25519 (and any other DH/ECDH
/// curve) to HKDF-SHA-256 when the `keyEncryptionAlgorithm` carries
/// this OID instead of the X9.63 family.
pub const OID_DH_SINGLE_PASS_STDDH_HKDF_SHA256_SCHEME: [u64; 9] =
    [1, 2, 840, 113549, 1, 9, 16, 3, 19];

/// OID `1.2.840.113549.1.9.16.3.20` — `dhSinglePass-stdDH-hkdf-sha384-scheme`
/// (RFC 8418 §2.2, smime-alg 20). Combined ECDH + HKDF-SHA-384 KDF
/// identifier.
pub const OID_DH_SINGLE_PASS_STDDH_HKDF_SHA384_SCHEME: [u64; 9] =
    [1, 2, 840, 113549, 1, 9, 16, 3, 20];

/// OID `1.2.840.113549.1.9.16.3.21` — `dhSinglePass-stdDH-hkdf-sha512-scheme`
/// (RFC 8418 §2.2, smime-alg 21). Combined ECDH + HKDF-SHA-512 KDF
/// identifier.
pub const OID_DH_SINGLE_PASS_STDDH_HKDF_SHA512_SCHEME: [u64; 9] =
    [1, 2, 840, 113549, 1, 9, 16, 3, 21];

/// OID `2.16.840.1.101.3.4.1.5` — `id-aes128-wrap` (RFC 5649 §3 / RFC
/// 3394 §3 OID list).
pub const OID_AES128_WRAP: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 1, 5];

/// OID `2.16.840.1.101.3.4.1.25` — `id-aes192-wrap`.
pub const OID_AES192_WRAP: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 1, 25];

/// OID `2.16.840.1.101.3.4.1.45` — `id-aes256-wrap`.
pub const OID_AES256_WRAP: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 1, 45];

/// AES wrap variants supported by the round-14 KARI unwrap path. The
/// width determines both the KEK byte length the X9.63 KDF emits and
/// the AES-KW variant used to unwrap the CEK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapAlgorithm {
    /// `id-aes128-wrap`: 128-bit KEK + AES-128 key wrap.
    Aes128,
    /// `id-aes192-wrap`: 192-bit KEK + AES-192 key wrap.
    Aes192,
    /// `id-aes256-wrap`: 256-bit KEK + AES-256 key wrap.
    Aes256,
}

impl WrapAlgorithm {
    /// KEK byte length the X9.63 KDF must emit for this wrap.
    pub fn kek_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    /// OID arcs for the wrap algorithm — used to rebuild
    /// `ECC-CMS-SharedInfo` for the KDF call.
    pub fn oid(self) -> &'static [u64] {
        match self {
            Self::Aes128 => &OID_AES128_WRAP,
            Self::Aes192 => &OID_AES192_WRAP,
            Self::Aes256 => &OID_AES256_WRAP,
        }
    }

    /// Resolve the wrap algorithm from its OID arcs. Returns `None`
    /// for unsupported wrap OIDs (callers surface a structured error).
    pub fn from_oid(oid: &[u64]) -> Option<Self> {
        if oid == OID_AES128_WRAP {
            Some(Self::Aes128)
        } else if oid == OID_AES192_WRAP {
            Some(Self::Aes192)
        } else if oid == OID_AES256_WRAP {
            Some(Self::Aes256)
        } else {
            None
        }
    }
}

/// Curves the round-16 dispatch can route to. Selects the ECDH
/// primitive (P-256 / P-384 / P-521 / X25519). The KDF binding is
/// curve-fixed for the NIST curves per RFC 5753 §7.1.4 (P-256 →
/// SHA-256, P-384 → SHA-384, P-521 → SHA-512) and configurable via
/// [`KariKdf`] for X25519 per RFC 8418 §2.1 + §2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KariCurve {
    /// NIST P-256 (`secp256r1`) + X9.63-SHA-256 KDF. KEA OID is
    /// [`OID_DH_SINGLE_PASS_STDDH_SHA256_KDF`].
    P256,
    /// NIST P-384 (`secp384r1`) + X9.63-SHA-384 KDF. KEA OID is
    /// [`OID_DH_SINGLE_PASS_STDDH_SHA384_KDF`].
    P384,
    /// NIST P-521 (`secp521r1`) + X9.63-SHA-512 KDF. KEA OID is
    /// [`OID_DH_SINGLE_PASS_STDDH_SHA512_KDF`].
    P521,
    /// X25519 (`id-X25519`, RFC 7748 / RFC 8410). KDF defaults to the
    /// X9.63-SHA-256 binding (RFC 8418 §2.1, KEA OID
    /// [`OID_DH_SINGLE_PASS_STDDH_SHA256_KDF`]); the modern HKDF
    /// binding (RFC 8418 §2.2) is selectable on the writer side via
    /// [`KariKdf::HkdfSha256`] / `HkdfSha384` / `HkdfSha512`.
    X25519,
}

impl KariCurve {
    /// Curve OID arcs that go inside the `OriginatorPublicKey.algorithm`
    /// AlgorithmIdentifier — for the EC curves it's `ecPublicKey` +
    /// named-curve param; for X25519 it's `id-X25519` directly.
    pub fn algorithm_oid(self) -> &'static [u64] {
        match self {
            Self::P256 | Self::P384 | Self::P521 => &OID_EC_PUBLIC_KEY,
            Self::X25519 => &OID_X25519,
        }
    }

    /// Bytes that go into the AlgorithmIdentifier's `parameters` slot.
    /// For NIST curves this is the named-curve OID DER; X25519 has no
    /// parameters per RFC 8410 §3 (the slot is absent rather than NULL).
    pub fn algorithm_params(self) -> Vec<u8> {
        match self {
            Self::P256 => write_oid(&OID_SECP256R1),
            Self::P384 => write_oid(&OID_SECP384R1),
            Self::P521 => write_oid(&OID_SECP521R1),
            Self::X25519 => Vec::new(),
        }
    }

    /// Default KEA OID the writer puts in
    /// `KeyAgreeRecipientInfo.keyEncryptionAlgorithm` for this curve
    /// when no explicit [`KariKdf`] override is supplied. Encodes the
    /// (curve → X9.63 KDF) binding from RFC 5753 §7.1.4 / RFC 8418
    /// §2.1: P-256/X25519 → SHA-256; P-384 → SHA-384; P-521 → SHA-512.
    pub fn kea_oid(self) -> &'static [u64] {
        match self {
            Self::P256 | Self::X25519 => &OID_DH_SINGLE_PASS_STDDH_SHA256_KDF,
            Self::P384 => &OID_DH_SINGLE_PASS_STDDH_SHA384_KDF,
            Self::P521 => &OID_DH_SINGLE_PASS_STDDH_SHA512_KDF,
        }
    }

    /// Default KDF for this curve. NIST curves are pinned by RFC 5753
    /// §7.1.4; X25519 defaults to X9.63-SHA-256 per RFC 8418 §2.1
    /// (the HKDF variants are explicit-opt-in on the writer side).
    pub fn default_kdf(self) -> KariKdf {
        match self {
            Self::P256 | Self::X25519 => KariKdf::X963Sha256,
            Self::P384 => KariKdf::X963Sha384,
            Self::P521 => KariKdf::X963Sha512,
        }
    }

    /// Length of the encoded public point this curve emits (and accepts
    /// from the originator). Used by the writer's input validation.
    pub fn pub_point_len(self) -> usize {
        match self {
            // SEC1 uncompressed: 1 + 2*field_bytes.
            Self::P256 => 65,
            Self::P384 => 97,
            // P-521 field is 521 bits → 66-byte coordinates → 1 + 132 = 133.
            Self::P521 => 133,
            // X25519 raw u-coordinate (RFC 7748 §5).
            Self::X25519 => 32,
        }
    }
}

/// KDF flavour used to derive the KEK from the ECDH shared secret.
///
/// * **X9.63 family** — RFC 5753 §7.1.2 / NIST SP 800-56A §5.6.2.1.
///   Mandated for the NIST curves (P-256 → SHA-256, P-384 → SHA-384,
///   P-521 → SHA-512); also one of the two valid X25519 bindings (RFC
///   8418 §2.1 — uses [`OID_DH_SINGLE_PASS_STDDH_SHA256_KDF`] in the
///   secg-scheme arc).
/// * **HKDF family** — RFC 5869 + RFC 8418 §2.2. The modern X25519
///   binding: `salt = ukm` (or absent), `IKM = ECDH shared secret`,
///   `info = DER(ECC-CMS-SharedInfo)`, output truncated to the wrap
///   KEK length. KEA OIDs sit in the smime-alg arc
///   `1.2.840.113549.1.9.16.3.{19,20,21}` (HKDF-SHA-256 / 384 / 512).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KariKdf {
    /// X9.63 KDF with SHA-256 (RFC 5753 §7.1.2 + §7.1.4 secg-scheme).
    /// Default for P-256 + X25519.
    X963Sha256,
    /// X9.63 KDF with SHA-384 (RFC 5753 §7.1.4 secg-scheme). Default
    /// for P-384.
    X963Sha384,
    /// X9.63 KDF with SHA-512 (RFC 5753 §7.1.4 secg-scheme). Default
    /// for P-521.
    X963Sha512,
    /// HKDF-SHA-256 (RFC 5869 + RFC 8418 §2.2 — smime-alg 19,
    /// `dhSinglePass-stdDH-hkdf-sha256-scheme`).
    HkdfSha256,
    /// HKDF-SHA-384 (RFC 5869 + RFC 8418 §2.2 — smime-alg 20,
    /// `dhSinglePass-stdDH-hkdf-sha384-scheme`).
    HkdfSha384,
    /// HKDF-SHA-512 (RFC 5869 + RFC 8418 §2.2 — smime-alg 21,
    /// `dhSinglePass-stdDH-hkdf-sha512-scheme`).
    HkdfSha512,
}

impl KariKdf {
    /// KEA OID the writer puts in
    /// `KeyAgreeRecipientInfo.keyEncryptionAlgorithm` for this KDF.
    /// The wrap algorithm OID lives separately in the KEA's
    /// `parameters` field (RFC 5753 §7.1.4 / RFC 8418 §2.2).
    pub fn kea_oid(self) -> &'static [u64] {
        match self {
            Self::X963Sha256 => &OID_DH_SINGLE_PASS_STDDH_SHA256_KDF,
            Self::X963Sha384 => &OID_DH_SINGLE_PASS_STDDH_SHA384_KDF,
            Self::X963Sha512 => &OID_DH_SINGLE_PASS_STDDH_SHA512_KDF,
            Self::HkdfSha256 => &OID_DH_SINGLE_PASS_STDDH_HKDF_SHA256_SCHEME,
            Self::HkdfSha384 => &OID_DH_SINGLE_PASS_STDDH_HKDF_SHA384_SCHEME,
            Self::HkdfSha512 => &OID_DH_SINGLE_PASS_STDDH_HKDF_SHA512_SCHEME,
        }
    }

    /// Resolve the KDF from a parsed KEA OID. Returns `None` for any
    /// OID that doesn't name one of the six supported KDF schemes.
    pub fn from_kea_oid(oid: &[u64]) -> Option<Self> {
        if oid == OID_DH_SINGLE_PASS_STDDH_SHA256_KDF {
            Some(Self::X963Sha256)
        } else if oid == OID_DH_SINGLE_PASS_STDDH_SHA384_KDF {
            Some(Self::X963Sha384)
        } else if oid == OID_DH_SINGLE_PASS_STDDH_SHA512_KDF {
            Some(Self::X963Sha512)
        } else if oid == OID_DH_SINGLE_PASS_STDDH_HKDF_SHA256_SCHEME {
            Some(Self::HkdfSha256)
        } else if oid == OID_DH_SINGLE_PASS_STDDH_HKDF_SHA384_SCHEME {
            Some(Self::HkdfSha384)
        } else if oid == OID_DH_SINGLE_PASS_STDDH_HKDF_SHA512_SCHEME {
            Some(Self::HkdfSha512)
        } else {
            None
        }
    }

    /// Validate the KDF / curve pairing per the RFCs:
    /// * NIST curves (P-256/P-384/P-521) MUST use X9.63 with the
    ///   matching SHA hash (RFC 5753 §7.1.4).
    /// * X25519 MAY use any of the X9.63-SHA-256 (RFC 8418 §2.1) or
    ///   HKDF-SHA-256/384/512 (RFC 8418 §2.2) schemes; SHA-384 and
    ///   SHA-512 X9.63 bindings are NOT defined for X25519.
    pub fn is_valid_for(self, curve: KariCurve) -> bool {
        match curve {
            KariCurve::P256 => self == Self::X963Sha256,
            KariCurve::P384 => self == Self::X963Sha384,
            KariCurve::P521 => self == Self::X963Sha512,
            KariCurve::X25519 => matches!(
                self,
                Self::X963Sha256 | Self::HkdfSha256 | Self::HkdfSha384 | Self::HkdfSha512
            ),
        }
    }
}

/// X9.63 Key Derivation Function (NIST SP 800-56A §5.6.2.1, RFC 5753
/// §7.1.2) generic over the underlying hash.
///
/// Input: shared secret `z` (the ECDH X-coordinate, or for X25519 the
/// 32-byte u-coordinate result), `shared_info` (the DER
/// `ECC-CMS-SharedInfo`), and the desired output length. Output:
/// `keydatalen` bytes.
///
/// Implementation per RFC 5753 §7.1.2:
/// ```text
/// for counter = 1 to ceil(keydatalen / hashlen):
///     K_counter = hash(z || counter (32-bit big-endian) || shared_info)
/// keydata = (K_1 || K_2 || ...) truncated to keydatalen bytes
/// ```
pub fn x963_kdf<H: sha2::Digest>(z: &[u8], shared_info: &[u8], keydatalen: usize) -> Vec<u8> {
    let hashlen = <H as sha2::Digest>::output_size();
    let n = keydatalen.div_ceil(hashlen);
    let mut out = Vec::with_capacity(n * hashlen);
    for counter in 1u32..=(n as u32) {
        let mut h = H::new();
        h.update(z);
        h.update(counter.to_be_bytes());
        h.update(shared_info);
        out.extend_from_slice(&h.finalize());
    }
    out.truncate(keydatalen);
    out
}

/// Convenience wrapper that pins X9.63 KDF to SHA-256 — the round-14
/// hot path. Round-15 callers use the generic [`x963_kdf`] directly.
pub fn x963_kdf_sha256(z: &[u8], shared_info: &[u8], keydatalen: usize) -> Vec<u8> {
    x963_kdf::<sha2::Sha256>(z, shared_info, keydatalen)
}

/// HKDF-SHA-256 KEK derivation per RFC 5869 + RFC 8418 §2.2.
/// `salt` is the UKM (or an empty slice when UKM is absent), `ikm` is
/// the ECDH shared secret `Z`, `info` is the DER `ECC-CMS-SharedInfo`,
/// and the output is `keydatalen` bytes. Computes
/// `HKDF-Extract(salt, ikm)` followed by `HKDF-Expand(prk, info, keydatalen)`.
pub fn hkdf_kdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], keydatalen: usize) -> Vec<u8> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(salt_opt, ikm);
    let mut okm = vec![0u8; keydatalen];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA-256 keydatalen within 255 * HashLen");
    okm
}

/// HKDF-SHA-384 KEK derivation per RFC 5869 + RFC 8418 §2.2.
pub fn hkdf_kdf_sha384(salt: &[u8], ikm: &[u8], info: &[u8], keydatalen: usize) -> Vec<u8> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = hkdf::Hkdf::<sha2::Sha384>::new(salt_opt, ikm);
    let mut okm = vec![0u8; keydatalen];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA-384 keydatalen within 255 * HashLen");
    okm
}

/// HKDF-SHA-512 KEK derivation per RFC 5869 + RFC 8418 §2.2.
pub fn hkdf_kdf_sha512(salt: &[u8], ikm: &[u8], info: &[u8], keydatalen: usize) -> Vec<u8> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = hkdf::Hkdf::<sha2::Sha512>::new(salt_opt, ikm);
    let mut okm = vec![0u8; keydatalen];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA-512 keydatalen within 255 * HashLen");
    okm
}

/// Dispatch helper: derive the KEK for the supplied [`KariKdf`] using
/// the right primitive. For X9.63 the `ukm` parameter is folded into
/// `shared_info` by the caller (it's already in the
/// `ECC-CMS-SharedInfo`); for HKDF the UKM is the salt per RFC 8418
/// §2.2 and is supplied separately.
pub fn derive_kek(
    kdf: KariKdf,
    z: &[u8],
    ukm: Option<&[u8]>,
    shared_info: &[u8],
    keydatalen: usize,
) -> Vec<u8> {
    match kdf {
        KariKdf::X963Sha256 => x963_kdf::<sha2::Sha256>(z, shared_info, keydatalen),
        KariKdf::X963Sha384 => x963_kdf::<sha2::Sha384>(z, shared_info, keydatalen),
        KariKdf::X963Sha512 => x963_kdf::<sha2::Sha512>(z, shared_info, keydatalen),
        KariKdf::HkdfSha256 => hkdf_kdf_sha256(ukm.unwrap_or(&[]), z, shared_info, keydatalen),
        KariKdf::HkdfSha384 => hkdf_kdf_sha384(ukm.unwrap_or(&[]), z, shared_info, keydatalen),
        KariKdf::HkdfSha512 => hkdf_kdf_sha512(ukm.unwrap_or(&[]), z, shared_info, keydatalen),
    }
}

/// Build the `ECC-CMS-SharedInfo` DER structure (RFC 5753 §7.2). Used
/// as the `sharedInfo` input to the X9.63 KDF.
///
/// ```asn.1
/// ECC-CMS-SharedInfo ::= SEQUENCE {
///   keyInfo         AlgorithmIdentifier,  -- the wrap algorithm
///   entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
///   suppPubInfo [2] EXPLICIT OCTET STRING       -- the keylen, big-endian 32-bit
/// }
/// ```
///
/// `wrap_oid` is the OID of the wrap algorithm (e.g. `id-aes128-wrap`).
/// `entity_u_info` is the optional UKM (RFC 5652 §6.2.2 — KARI's
/// `ukm`). `key_bit_length` is the wrap's KEK length in bits (128 /
/// 192 / 256).
pub fn build_ecc_cms_shared_info(
    wrap_oid: &[u64],
    entity_u_info: Option<&[u8]>,
    key_bit_length: u32,
) -> Vec<u8> {
    use super::der::{write_context_constructed, write_octet_string, write_tlv, Class};
    // keyInfo AlgorithmIdentifier — wrap OID + (no parameters per RFC
    // 3394 / RFC 5649 OID list; the AlgorithmIdentifier carries the
    // OID alone).
    let key_info = write_sequence(&write_oid(wrap_oid));
    let mut body = key_info;
    if let Some(ukm) = entity_u_info {
        body.extend_from_slice(&write_context_constructed(0, &write_octet_string(ukm)));
    }
    // suppPubInfo [2] EXPLICIT OCTET STRING — the keylen as a 32-bit
    // big-endian integer (NOT a DER INTEGER) per RFC 5753 §7.2.
    let supp_pub_body = write_octet_string(&key_bit_length.to_be_bytes());
    body.extend_from_slice(&write_tlv(Class::ContextSpecific, true, 2, &supp_pub_body));
    write_sequence(&body)
}

/// Recipient's EC private key material — round-14 surface for the
/// KARI unwrap path. The same struct serves every curve in
/// [`KariCurve`]: scalar length is 32 bytes for P-256 / X25519 and 48
/// bytes for P-384; `public_point_sec1` carries the SEC1-encoded
/// uncompressed point (P-256 / P-384) or the raw 32-byte u-coordinate
/// (X25519).
#[derive(Debug, Clone)]
pub struct EcRecipient {
    /// Curve the scalar / point belong to. Defaults to [`KariCurve::P256`]
    /// for backwards-compat with round-14 callers via [`Self::p256`].
    pub curve: KariCurve,
    /// Raw scalar bytes (big-endian SEC1 for NIST curves; native
    /// little-endian-clamped for X25519 per RFC 7748 §5).
    pub private_scalar: Vec<u8>,
    /// Encoded public point. SEC1 uncompressed `0x04 || X || Y` for
    /// P-256 / P-384; raw 32-byte u-coordinate for X25519. Used to
    /// match the recipient's SubjectKeyIdentifier when the KARI's
    /// `RecipientEncryptedKey` slot uses the SKI form (RFC 5280
    /// §4.2.1.2 method 1 hashes the SubjectPublicKeyInfo BIT STRING
    /// contents — for EC keys the SEC1 point, for X25519 the raw
    /// public key bytes per RFC 8410 §4).
    pub public_point_sec1: Vec<u8>,
}

impl EcRecipient {
    /// Build a P-256 recipient (round-14 compatibility constructor —
    /// keeps existing call sites working without naming `KariCurve`).
    pub fn p256(private_scalar: Vec<u8>, public_point_sec1: Vec<u8>) -> Self {
        Self {
            curve: KariCurve::P256,
            private_scalar,
            public_point_sec1,
        }
    }

    /// Build a P-384 recipient.
    pub fn p384(private_scalar: Vec<u8>, public_point_sec1: Vec<u8>) -> Self {
        Self {
            curve: KariCurve::P384,
            private_scalar,
            public_point_sec1,
        }
    }

    /// Build a P-521 recipient. `private_scalar` is the 66-byte SEC1
    /// scalar + `public_point_sec1` is the 133-byte SEC1 uncompressed
    /// point.
    pub fn p521(private_scalar: Vec<u8>, public_point_sec1: Vec<u8>) -> Self {
        Self {
            curve: KariCurve::P521,
            private_scalar,
            public_point_sec1,
        }
    }

    /// Build an X25519 recipient. `private_scalar` is the 32-byte
    /// secret + `public_point_sec1` is the 32-byte raw u-coordinate
    /// (RFC 7748 §5).
    pub fn x25519(private_scalar: Vec<u8>, public_point_sec1: Vec<u8>) -> Self {
        Self {
            curve: KariCurve::X25519,
            private_scalar,
            public_point_sec1,
        }
    }
}

/// Unwrap a CEK from a KARI recipient slot using ECDH (P-256) +
/// X9.63-SHA-256 KDF + AES Key Wrap. Round-14 entry point — kept for
/// backwards compatibility; new callers should use [`unwrap_kari`]
/// which dispatches across every supported curve.
///
/// `recipient` selects which slot in `kari.recipient_encrypted_keys`
/// to unwrap. Caller is responsible for matching the slot's RID to
/// the recipient's certificate; this function performs the
/// cryptographic unwrap given a matched slot.
pub fn unwrap_kari_p256(
    kari: &KeyAgreeRecipientInfo,
    recipient_slot: &RecipientEncryptedKey,
    recipient: &EcRecipient,
) -> Result<Vec<u8>, PdfError> {
    if recipient.curve != KariCurve::P256 {
        return Err(PdfError::other(format!(
            "PDF pubsec KARI: unwrap_kari_p256 invoked with {:?} recipient",
            recipient.curve
        )));
    }
    unwrap_kari(kari, recipient_slot, recipient)
}

/// Unified KARI unwrap dispatch (round 15 / round 16). Pulls the KDF
/// and wrap algorithm and UKM out of the KARI envelope, validates that
/// the parsed KDF is one the recipient's curve permits per RFC 5753 /
/// RFC 8418, runs the right ECDH primitive, derives the KEK with the
/// chosen KDF (X9.63 or HKDF), and AES-KW unwraps the CEK.
pub fn unwrap_kari(
    kari: &KeyAgreeRecipientInfo,
    recipient_slot: &RecipientEncryptedKey,
    recipient: &EcRecipient,
) -> Result<Vec<u8>, PdfError> {
    // 1. Resolve the KDF from the KEA OID + cross-check it's a binding
    //    the recipient's curve permits (RFC 5753 §7.1.4 / RFC 8418).
    let kdf = KariKdf::from_kea_oid(&kari.key_encryption_oid).ok_or_else(|| {
        PdfError::other(format!(
            "PDF pubsec KARI: unsupported KEA OID {:?} (no matching KDF scheme)",
            kari.key_encryption_oid
        ))
    })?;
    if !kdf.is_valid_for(recipient.curve) {
        return Err(PdfError::other(format!(
            "PDF pubsec KARI: KDF {:?} is not a valid binding for curve {:?} \
             (RFC 5753 §7.1.4 / RFC 8418 §2)",
            kdf, recipient.curve,
        )));
    }
    // 2. Pull the wrap AlgorithmIdentifier out of the KEA params.
    let (wrap_seq, rest) = read_sequence(&kari.key_encryption_params)?;
    if !rest.is_empty() {
        return Err(PdfError::other(
            "PDF pubsec KARI: trailing bytes after KEA wrap AlgorithmIdentifier",
        ));
    }
    let (wrap_oid, _wrap_params) = read_oid(wrap_seq)?;
    let wrap = WrapAlgorithm::from_oid(&wrap_oid).ok_or_else(|| {
        PdfError::other(format!(
            "PDF pubsec KARI: unsupported wrap algorithm OID {wrap_oid:?}"
        ))
    })?;
    // 3. Pull the originator's public point + check the curve matches.
    let originator_point = match &kari.originator {
        OriginatorId::OriginatorKey(opk) => extract_originator_point(opk, recipient.curve)?,
        OriginatorId::IssuerAndSerial(_) | OriginatorId::SubjectKeyIdentifier(_) => {
            return Err(PdfError::other(
                "PDF pubsec KARI: originator must be OriginatorPublicKey \
                 (IssuerAndSerial / SubjectKeyIdentifier require an out-of-band \
                 originator certificate lookup, which is out of scope here)",
            ))
        }
    };
    // 4. ECDH key agreement, dispatched on curve.
    let z = ecdh_z(
        recipient.curve,
        &recipient.private_scalar,
        &originator_point,
    )?;
    // 5. Build ECC-CMS-SharedInfo using the wrap OID + UKM.
    //    RFC 8418 §2.2 spells out that the HKDF binding still consumes
    //    the SAME `ECC-CMS-SharedInfo` value as `info` — only the salt
    //    handling differs (UKM → salt for HKDF; UKM goes inside
    //    sharedInfo for X9.63).
    let ukm = if kari.ukm.is_empty() {
        None
    } else {
        Some(kari.ukm.as_slice())
    };
    let shared_info = build_ecc_cms_shared_info(wrap.oid(), ukm, (wrap.kek_len() * 8) as u32);
    // 6. KDF → KEK (X9.63 or HKDF, per the parsed KEA OID).
    let kek = derive_kek(kdf, &z, ukm, &shared_info, wrap.kek_len());
    // 7. AES Key Wrap unwrap (RFC 3394).
    aes_kw_unwrap(wrap, &kek, &recipient_slot.encrypted_key)
}

/// Run ECDH on the supplied curve and return the shared-secret bytes
/// (`Z`) per RFC 5753 §3.1 / RFC 8418 §2 — the X-coordinate for NIST
/// curves and the raw u-coordinate for X25519.
fn ecdh_z(curve: KariCurve, scalar: &[u8], originator_point: &[u8]) -> Result<Vec<u8>, PdfError> {
    match curve {
        KariCurve::P256 => {
            use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};
            let secret = SecretKey::from_slice(scalar).map_err(|e| {
                PdfError::other(format!(
                    "PDF pubsec KARI: invalid P-256 private scalar: {e}"
                ))
            })?;
            let originator = PublicKey::from_sec1_bytes(originator_point).map_err(|e| {
                PdfError::other(format!(
                    "PDF pubsec KARI: invalid P-256 originator SEC1 point: {e}"
                ))
            })?;
            let shared = diffie_hellman(secret.to_nonzero_scalar(), originator.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        KariCurve::P384 => {
            use p384::{ecdh::diffie_hellman, PublicKey, SecretKey};
            let secret = SecretKey::from_slice(scalar).map_err(|e| {
                PdfError::other(format!(
                    "PDF pubsec KARI: invalid P-384 private scalar: {e}"
                ))
            })?;
            let originator = PublicKey::from_sec1_bytes(originator_point).map_err(|e| {
                PdfError::other(format!(
                    "PDF pubsec KARI: invalid P-384 originator SEC1 point: {e}"
                ))
            })?;
            let shared = diffie_hellman(secret.to_nonzero_scalar(), originator.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        KariCurve::P521 => {
            use p521::{ecdh::diffie_hellman, PublicKey, SecretKey};
            let secret = SecretKey::from_slice(scalar).map_err(|e| {
                PdfError::other(format!(
                    "PDF pubsec KARI: invalid P-521 private scalar: {e}"
                ))
            })?;
            let originator = PublicKey::from_sec1_bytes(originator_point).map_err(|e| {
                PdfError::other(format!(
                    "PDF pubsec KARI: invalid P-521 originator SEC1 point: {e}"
                ))
            })?;
            let shared = diffie_hellman(secret.to_nonzero_scalar(), originator.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        KariCurve::X25519 => {
            use x25519_dalek::{PublicKey, StaticSecret};
            if scalar.len() != 32 {
                return Err(PdfError::other(format!(
                    "PDF pubsec KARI: X25519 scalar must be 32 bytes (got {})",
                    scalar.len()
                )));
            }
            if originator_point.len() != 32 {
                return Err(PdfError::other(format!(
                    "PDF pubsec KARI: X25519 originator point must be 32 bytes (got {})",
                    originator_point.len()
                )));
            }
            let mut s_arr = [0u8; 32];
            s_arr.copy_from_slice(scalar);
            let secret = StaticSecret::from(s_arr);
            let mut p_arr = [0u8; 32];
            p_arr.copy_from_slice(originator_point);
            let pub_point = PublicKey::from(p_arr);
            let shared = secret.diffie_hellman(&pub_point);
            // RFC 8418 §3 — abort if the shared secret is all-zero
            // (small-subgroup / contributory check).
            if shared.as_bytes().iter().all(|b| *b == 0) {
                return Err(PdfError::other(
                    "PDF pubsec KARI: X25519 shared secret is all-zero (RFC 8418 §3 reject)",
                ));
            }
            Ok(shared.as_bytes().to_vec())
        }
    }
}

/// AES Key Wrap unwrap helper — split out of [`unwrap_kari`] to
/// share the wrap dispatch with the symmetric writer-side wrap
/// helper [`wrap_cek_for_recipient`].
fn aes_kw_unwrap(wrap: WrapAlgorithm, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, PdfError> {
    use aes_kw::{KekAes128, KekAes192, KekAes256};
    match wrap {
        WrapAlgorithm::Aes128 => {
            let kek_arr: [u8; 16] = kek
                .try_into()
                .map_err(|_| PdfError::other("PDF pubsec KARI: AES-128 KEK length mismatch"))?;
            KekAes128::from(kek_arr)
                .unwrap_vec(wrapped)
                .map_err(|e| PdfError::other(format!("PDF pubsec KARI: AES-KW unwrap failed: {e}")))
        }
        WrapAlgorithm::Aes192 => {
            let kek_arr: [u8; 24] = kek
                .try_into()
                .map_err(|_| PdfError::other("PDF pubsec KARI: AES-192 KEK length mismatch"))?;
            KekAes192::from(kek_arr)
                .unwrap_vec(wrapped)
                .map_err(|e| PdfError::other(format!("PDF pubsec KARI: AES-KW unwrap failed: {e}")))
        }
        WrapAlgorithm::Aes256 => {
            let kek_arr: [u8; 32] = kek
                .try_into()
                .map_err(|_| PdfError::other("PDF pubsec KARI: AES-256 KEK length mismatch"))?;
            KekAes256::from(kek_arr)
                .unwrap_vec(wrapped)
                .map_err(|e| PdfError::other(format!("PDF pubsec KARI: AES-KW unwrap failed: {e}")))
        }
    }
}

fn aes_kw_wrap(wrap: WrapAlgorithm, kek: &[u8], cek: &[u8]) -> Result<Vec<u8>, PdfError> {
    use aes_kw::{KekAes128, KekAes192, KekAes256};
    match wrap {
        WrapAlgorithm::Aes128 => {
            let kek_arr: [u8; 16] = kek
                .try_into()
                .map_err(|_| PdfError::other("PDF pubsec KARI: AES-128 KEK length mismatch"))?;
            KekAes128::from(kek_arr)
                .wrap_vec(cek)
                .map_err(|e| PdfError::other(format!("PDF pubsec KARI: AES-KW wrap failed: {e}")))
        }
        WrapAlgorithm::Aes192 => {
            let kek_arr: [u8; 24] = kek
                .try_into()
                .map_err(|_| PdfError::other("PDF pubsec KARI: AES-192 KEK length mismatch"))?;
            KekAes192::from(kek_arr)
                .wrap_vec(cek)
                .map_err(|e| PdfError::other(format!("PDF pubsec KARI: AES-KW wrap failed: {e}")))
        }
        WrapAlgorithm::Aes256 => {
            let kek_arr: [u8; 32] = kek
                .try_into()
                .map_err(|_| PdfError::other("PDF pubsec KARI: AES-256 KEK length mismatch"))?;
            KekAes256::from(kek_arr)
                .wrap_vec(cek)
                .map_err(|e| PdfError::other(format!("PDF pubsec KARI: AES-KW wrap failed: {e}")))
        }
    }
}

/// Pull the originator's public point out of `OriginatorPublicKey` and
/// verify it matches the expected curve. NIST curves carry an
/// `ecPublicKey` AlgorithmIdentifier with the named-curve OID in
/// `parameters` (RFC 5480 §2.1.1); X25519 carries `id-X25519` directly
/// with no parameters (RFC 8410 §3 + RFC 8418 §2).
fn extract_originator_point(
    opk: &OriginatorPublicKey,
    expected: KariCurve,
) -> Result<Vec<u8>, PdfError> {
    match expected {
        KariCurve::P256 | KariCurve::P384 | KariCurve::P521 => {
            if opk.algorithm_oid != OID_EC_PUBLIC_KEY {
                return Err(PdfError::other(format!(
                    "PDF pubsec KARI: originator algorithm OID {:?} is not ecPublicKey",
                    opk.algorithm_oid
                )));
            }
            let (curve_oid, _rest) = read_oid(&opk.algorithm_params)?;
            let want: &[u64] = match expected {
                KariCurve::P256 => &OID_SECP256R1,
                KariCurve::P384 => &OID_SECP384R1,
                KariCurve::P521 => &OID_SECP521R1,
                KariCurve::X25519 => unreachable!(),
            };
            if curve_oid != want {
                return Err(PdfError::other(format!(
                    "PDF pubsec KARI: originator curve OID {curve_oid:?} \
                     does not match expected {want:?}"
                )));
            }
            Ok(opk.public_key.clone())
        }
        KariCurve::X25519 => {
            if opk.algorithm_oid != OID_X25519 {
                return Err(PdfError::other(format!(
                    "PDF pubsec KARI: originator algorithm OID {:?} is not id-X25519",
                    opk.algorithm_oid
                )));
            }
            // RFC 8410 §3: parameters MUST be absent. We tolerate an
            // empty slice as well as a NULL TLV for compatibility with
            // writers that emit one anyway.
            Ok(opk.public_key.clone())
        }
    }
}

/// Identify which slot in a KARI's `recipient_encrypted_keys`
/// corresponds to the supplied recipient. Returns the matching slot
/// or `None` when no slot matches.
///
/// Two RID forms are supported (RFC 5652 §6.2.2):
/// * `IssuerAndSerial` — match the user cert's `(issuer_der, serial)`.
/// * `RecipientKeyIdentifier(SKI)` — match the SHA-1 of the user
///   cert's SubjectPublicKeyInfo BIT STRING contents (RFC 5280
///   §4.2.1.2 method 1). For an EC cert the SPKI BIT STRING contents
///   is the SEC1-encoded point itself.
pub fn match_kari_slot<'a>(
    kari: &'a KeyAgreeRecipientInfo,
    issuer_der: &[u8],
    serial: &[u8],
    spki_pubkey_bits: Option<&[u8]>,
) -> Option<&'a RecipientEncryptedKey> {
    use sha1::Digest;
    let our_ski = spki_pubkey_bits.map(|b| sha1::Sha1::digest(b).to_vec());
    for slot in &kari.recipient_encrypted_keys {
        match &slot.rid {
            KeyAgreeRecipientId::IssuerAndSerial(ias) => {
                if ias.issuer_der == issuer_der && ias.serial == serial {
                    return Some(slot);
                }
            }
            KeyAgreeRecipientId::RecipientKeyIdentifier { ski } => {
                if let Some(our) = our_ski.as_ref() {
                    if ski == our {
                        return Some(slot);
                    }
                }
            }
        }
    }
    None
}

// ───────── Encoder side ─────────

/// Wrap a CEK for one P-256 ECDH recipient. Round-14 entry point —
/// kept for backwards compatibility; round-15 callers prefer
/// [`wrap_cek_for_recipient`] which dispatches across every supported
/// curve.
///
/// Returns `(originator_public_sec1, wrapped_cek)`. `recipient_pub_sec1`
/// is the recipient's SEC1-encoded uncompressed public point
/// (`0x04 || X || Y`, 65 bytes). `cek` is the content-encryption key
/// to wrap.
#[doc(hidden)]
pub fn wrap_cek_for_p256_recipient(
    ephemeral_scalar: &[u8],
    recipient_pub_sec1: &[u8],
    ukm: Option<&[u8]>,
    cek: &[u8],
    wrap: WrapAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), PdfError> {
    wrap_cek_for_recipient(
        KariCurve::P256,
        ephemeral_scalar,
        recipient_pub_sec1,
        ukm,
        cek,
        wrap,
    )
}

/// Round-15 / round-16: wrap a CEK for one ECDH recipient on the
/// supplied curve. Returns `(originator_public_bytes, wrapped_cek)`
/// where `originator_public_bytes` is the SEC1 uncompressed point for
/// NIST curves or the raw 32-byte u-coordinate for X25519. The bytes
/// are directly suitable for plugging into the
/// `cms_build::build_envelope_kari_aes256` fixture builder's
/// `OriginatorIdRef::OriginatorKey.public_key` field.
///
/// `ephemeral_scalar` is the ephemeral private key bytes (32 for P-256
/// / X25519, 48 for P-384, 66 for P-521). `recipient_pub_bytes` is the
/// recipient's public point in the curve's encoded form.
///
/// The KDF is the curve's [`default_kdf`](KariCurve::default_kdf) —
/// X9.63 + the canonical hash for that curve (NIST → matching SHA;
/// X25519 → SHA-256 per RFC 8418 §2.1). Use
/// [`wrap_cek_for_recipient_with_kdf`] to override (e.g. to bind X25519
/// to HKDF-SHA-256 / 384 / 512 per RFC 8418 §2.2).
pub fn wrap_cek_for_recipient(
    curve: KariCurve,
    ephemeral_scalar: &[u8],
    recipient_pub_bytes: &[u8],
    ukm: Option<&[u8]>,
    cek: &[u8],
    wrap: WrapAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), PdfError> {
    wrap_cek_for_recipient_with_kdf(
        curve,
        curve.default_kdf(),
        ephemeral_scalar,
        recipient_pub_bytes,
        ukm,
        cek,
        wrap,
    )
}

/// Round-16: wrap a CEK with an explicit [`KariKdf`] override. Same
/// dispatch as [`wrap_cek_for_recipient`] except the KDF is supplied
/// directly; the (curve, KDF) pair must be permitted by RFC 5753 /
/// RFC 8418 (see [`KariKdf::is_valid_for`]).
#[allow(clippy::too_many_arguments)]
pub fn wrap_cek_for_recipient_with_kdf(
    curve: KariCurve,
    kdf: KariKdf,
    ephemeral_scalar: &[u8],
    recipient_pub_bytes: &[u8],
    ukm: Option<&[u8]>,
    cek: &[u8],
    wrap: WrapAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), PdfError> {
    if !kdf.is_valid_for(curve) {
        return Err(PdfError::other(format!(
            "PDF pubsec KARI build: KDF {kdf:?} is not a valid binding \
             for curve {curve:?} (RFC 5753 §7.1.4 / RFC 8418 §2)"
        )));
    }
    let (originator_pub, z) = match curve {
        KariCurve::P256 => {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};
            let secret = SecretKey::from_slice(ephemeral_scalar).map_err(|e| {
                PdfError::other(format!("PDF pubsec KARI build: bad P-256 ephemeral: {e}"))
            })?;
            let originator_point = secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            let recipient_public =
                PublicKey::from_sec1_bytes(recipient_pub_bytes).map_err(|e| {
                    PdfError::other(format!(
                        "PDF pubsec KARI build: bad P-256 recipient SEC1 point: {e}"
                    ))
                })?;
            let shared = diffie_hellman(secret.to_nonzero_scalar(), recipient_public.as_affine());
            (originator_point, shared.raw_secret_bytes().to_vec())
        }
        KariCurve::P384 => {
            use p384::elliptic_curve::sec1::ToEncodedPoint;
            use p384::{ecdh::diffie_hellman, PublicKey, SecretKey};
            let secret = SecretKey::from_slice(ephemeral_scalar).map_err(|e| {
                PdfError::other(format!("PDF pubsec KARI build: bad P-384 ephemeral: {e}"))
            })?;
            let originator_point = secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            let recipient_public =
                PublicKey::from_sec1_bytes(recipient_pub_bytes).map_err(|e| {
                    PdfError::other(format!(
                        "PDF pubsec KARI build: bad P-384 recipient SEC1 point: {e}"
                    ))
                })?;
            let shared = diffie_hellman(secret.to_nonzero_scalar(), recipient_public.as_affine());
            (originator_point, shared.raw_secret_bytes().to_vec())
        }
        KariCurve::P521 => {
            use p521::elliptic_curve::sec1::ToEncodedPoint;
            use p521::{ecdh::diffie_hellman, PublicKey, SecretKey};
            let secret = SecretKey::from_slice(ephemeral_scalar).map_err(|e| {
                PdfError::other(format!("PDF pubsec KARI build: bad P-521 ephemeral: {e}"))
            })?;
            let originator_point = secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            let recipient_public =
                PublicKey::from_sec1_bytes(recipient_pub_bytes).map_err(|e| {
                    PdfError::other(format!(
                        "PDF pubsec KARI build: bad P-521 recipient SEC1 point: {e}"
                    ))
                })?;
            let shared = diffie_hellman(secret.to_nonzero_scalar(), recipient_public.as_affine());
            (originator_point, shared.raw_secret_bytes().to_vec())
        }
        KariCurve::X25519 => {
            use x25519_dalek::{PublicKey, StaticSecret};
            if ephemeral_scalar.len() != 32 {
                return Err(PdfError::other(format!(
                    "PDF pubsec KARI build: X25519 ephemeral must be 32 bytes (got {})",
                    ephemeral_scalar.len()
                )));
            }
            if recipient_pub_bytes.len() != 32 {
                return Err(PdfError::other(format!(
                    "PDF pubsec KARI build: X25519 recipient point must be 32 bytes (got {})",
                    recipient_pub_bytes.len()
                )));
            }
            let mut s_arr = [0u8; 32];
            s_arr.copy_from_slice(ephemeral_scalar);
            let secret = StaticSecret::from(s_arr);
            let originator_pub = PublicKey::from(&secret).as_bytes().to_vec();
            let mut p_arr = [0u8; 32];
            p_arr.copy_from_slice(recipient_pub_bytes);
            let recipient_public = PublicKey::from(p_arr);
            let shared = secret.diffie_hellman(&recipient_public);
            if shared.as_bytes().iter().all(|b| *b == 0) {
                return Err(PdfError::other(
                    "PDF pubsec KARI build: X25519 shared secret is all-zero \
                     (RFC 8418 §3 reject — bad recipient public key)",
                ));
            }
            (originator_pub, shared.as_bytes().to_vec())
        }
    };
    let shared_info = build_ecc_cms_shared_info(wrap.oid(), ukm, (wrap.kek_len() * 8) as u32);
    let kek = derive_kek(kdf, &z, ukm, &shared_info, wrap.kek_len());
    let wrapped = aes_kw_wrap(wrap, &kek, cek)?;
    Ok((originator_pub, wrapped))
}

#[cfg(test)]
mod tests {
    use super::super::der::read_octet_string;
    use super::*;

    /// X9.63 KDF SHA-256 vector (RFC 5753 §A — the published vector
    /// uses SHA-256 and a 16-byte output). Inputs from RFC 5753 §A.1
    /// (the example doesn't appear there directly; we cross-check
    /// against the algorithm by re-running it byte-for-byte from a
    /// known small input).
    #[test]
    fn x963_kdf_sha256_one_block() {
        // For a single block (keydatalen = hashlen), the output is
        // `SHA-256(z || 0x00000001 || sharedInfo)`.
        let z = [0x42u8; 32];
        let shared_info = [0x99u8; 8];
        let out = x963_kdf_sha256(&z, &shared_info, 32);
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(z);
        h.update(1u32.to_be_bytes());
        h.update(shared_info);
        let want = h.finalize().to_vec();
        assert_eq!(out, want);
    }

    #[test]
    fn x963_kdf_sha256_two_blocks_truncated() {
        // 40-byte output crosses one SHA-256 block boundary (32 →
        // counter rolls to 2 and we take 8 bytes from K_2).
        let z = [0x33u8; 32];
        let shared_info = [0x77u8; 4];
        let out = x963_kdf_sha256(&z, &shared_info, 40);
        use sha2::Digest;
        let mut h1 = sha2::Sha256::new();
        h1.update(z);
        h1.update(1u32.to_be_bytes());
        h1.update(shared_info);
        let k1 = h1.finalize().to_vec();
        let mut h2 = sha2::Sha256::new();
        h2.update(z);
        h2.update(2u32.to_be_bytes());
        h2.update(shared_info);
        let k2 = h2.finalize().to_vec();
        let mut want = k1;
        want.extend_from_slice(&k2[..8]);
        assert_eq!(out, want);
        assert_eq!(out.len(), 40);
    }

    #[test]
    fn shared_info_round_trip_minimal() {
        // No UKM — only the keyInfo + suppPubInfo[2].
        let bytes = build_ecc_cms_shared_info(&OID_AES256_WRAP, None, 256);
        // Outer SEQUENCE.
        let (body, rest) = read_sequence(&bytes).unwrap();
        assert!(rest.is_empty());
        // keyInfo SEQUENCE { wrap_oid }
        let (key_info_body, after_ki) = read_sequence(body).unwrap();
        let (oid, after_oid) = read_oid(key_info_body).unwrap();
        assert_eq!(oid, OID_AES256_WRAP);
        assert!(after_oid.is_empty());
        // suppPubInfo [2] EXPLICIT OCTET STRING containing 4 bytes
        // (256u32 BE).
        let (tlv, _tail) = super::super::der::read_tlv(after_ki).unwrap();
        assert_eq!(tlv.tag_number, 2);
        let (k, _) = read_octet_string(tlv.body).unwrap();
        assert_eq!(k, &[0x00, 0x00, 0x01, 0x00]); // 256 in BE
    }

    #[test]
    fn shared_info_with_ukm() {
        let bytes = build_ecc_cms_shared_info(&OID_AES128_WRAP, Some(b"UKM-bytes"), 128);
        // Walk: SEQUENCE { keyInfo, [0] EXPLICIT OS, [2] EXPLICIT OS }
        let (body, _) = read_sequence(&bytes).unwrap();
        let (_ki_body, after_ki) = read_sequence(body).unwrap();
        let (tlv0, after_tlv0) = super::super::der::read_tlv(after_ki).unwrap();
        assert_eq!(tlv0.tag_number, 0);
        let (ukm_bytes, _) = read_octet_string(tlv0.body).unwrap();
        assert_eq!(ukm_bytes, b"UKM-bytes");
        let (tlv2, _) = super::super::der::read_tlv(after_tlv0).unwrap();
        assert_eq!(tlv2.tag_number, 2);
    }

    #[test]
    fn wrap_oid_round_trip() {
        for w in [
            WrapAlgorithm::Aes128,
            WrapAlgorithm::Aes192,
            WrapAlgorithm::Aes256,
        ] {
            assert_eq!(WrapAlgorithm::from_oid(w.oid()), Some(w));
        }
        assert_eq!(WrapAlgorithm::from_oid(&[1, 2, 3]), None);
    }

    /// End-to-end ECDH P-256 + X9.63 SHA-256 KDF + AES-256 KW unwrap
    /// round-trip. We generate one ephemeral keypair (originator) +
    /// one recipient keypair, wrap a CEK on the originator side, then
    /// unwrap it on the recipient side and assert byte equality.
    #[test]
    fn p256_aes256_wrap_unwrap_round_trip() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::SecretKey;
        // Deterministic test scalars (each is a valid non-zero P-256
        // scalar — well within the curve order).
        let ephemeral_scalar = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let recipient_scalar = [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
            0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
            0x3D, 0x3E, 0x3F, 0x40,
        ];
        let recipient_secret = SecretKey::from_slice(&recipient_scalar).unwrap();
        let recipient_pub_sec1 = recipient_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let cek = vec![0xAAu8; 32];
        let ukm = b"OXIDEAV-UKM-RT-1";
        let (originator_point, wrapped) = wrap_cek_for_p256_recipient(
            &ephemeral_scalar,
            &recipient_pub_sec1,
            Some(ukm),
            &cek,
            WrapAlgorithm::Aes256,
        )
        .expect("wrap");
        // Build the synthetic KARI to feed into the unwrap path.
        let kari = KeyAgreeRecipientInfo {
            originator: OriginatorId::OriginatorKey(OriginatorPublicKey {
                algorithm_oid: OID_EC_PUBLIC_KEY.to_vec(),
                algorithm_params: write_oid(&OID_SECP256R1),
                public_key: originator_point,
            }),
            ukm: ukm.to_vec(),
            key_encryption_oid: OID_DH_SINGLE_PASS_STDDH_SHA256_KDF.to_vec(),
            key_encryption_params: write_sequence(&write_oid(&OID_AES256_WRAP)),
            recipient_encrypted_keys: vec![RecipientEncryptedKey {
                rid: KeyAgreeRecipientId::RecipientKeyIdentifier {
                    ski: vec![0xCDu8; 20],
                },
                encrypted_key: wrapped,
            }],
        };
        let recipient = EcRecipient::p256(recipient_scalar.to_vec(), recipient_pub_sec1);
        let unwrapped =
            unwrap_kari_p256(&kari, &kari.recipient_encrypted_keys[0], &recipient).expect("unwrap");
        assert_eq!(unwrapped, cek);
    }

    /// AES-128-WRAP variant of the round-trip. Same setup, smaller KEK.
    #[test]
    fn p256_aes128_wrap_unwrap_round_trip() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::SecretKey;
        let ephemeral_scalar = [0x77u8; 32];
        let recipient_scalar = [0x55u8; 32];
        let recipient_secret = SecretKey::from_slice(&recipient_scalar).unwrap();
        let recipient_pub_sec1 = recipient_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let cek = vec![0xBBu8; 16];
        let (originator_point, wrapped) = wrap_cek_for_p256_recipient(
            &ephemeral_scalar,
            &recipient_pub_sec1,
            None,
            &cek,
            WrapAlgorithm::Aes128,
        )
        .expect("wrap");
        let kari = KeyAgreeRecipientInfo {
            originator: OriginatorId::OriginatorKey(OriginatorPublicKey {
                algorithm_oid: OID_EC_PUBLIC_KEY.to_vec(),
                algorithm_params: write_oid(&OID_SECP256R1),
                public_key: originator_point,
            }),
            ukm: Vec::new(),
            key_encryption_oid: OID_DH_SINGLE_PASS_STDDH_SHA256_KDF.to_vec(),
            key_encryption_params: write_sequence(&write_oid(&OID_AES128_WRAP)),
            recipient_encrypted_keys: vec![RecipientEncryptedKey {
                rid: KeyAgreeRecipientId::RecipientKeyIdentifier {
                    ski: vec![0xEEu8; 20],
                },
                encrypted_key: wrapped,
            }],
        };
        let recipient = EcRecipient::p256(recipient_scalar.to_vec(), recipient_pub_sec1);
        let unwrapped =
            unwrap_kari_p256(&kari, &kari.recipient_encrypted_keys[0], &recipient).expect("unwrap");
        assert_eq!(unwrapped, cek);
    }

    #[test]
    fn unsupported_kea_oid_errors() {
        let kari = KeyAgreeRecipientInfo {
            originator: OriginatorId::OriginatorKey(OriginatorPublicKey {
                algorithm_oid: OID_EC_PUBLIC_KEY.to_vec(),
                algorithm_params: write_oid(&OID_SECP256R1),
                public_key: vec![0x04; 65],
            }),
            ukm: Vec::new(),
            // wrong OID for a P-256 recipient — sha384 KDF (P-384 binding).
            key_encryption_oid: OID_DH_SINGLE_PASS_STDDH_SHA384_KDF.to_vec(),
            key_encryption_params: write_sequence(&write_oid(&OID_AES256_WRAP)),
            recipient_encrypted_keys: vec![RecipientEncryptedKey {
                rid: KeyAgreeRecipientId::RecipientKeyIdentifier {
                    ski: vec![0xCD; 20],
                },
                encrypted_key: vec![0; 40],
            }],
        };
        let recipient = EcRecipient::p256(vec![0x55; 32], vec![0x04; 65]);
        let err =
            unwrap_kari_p256(&kari, &kari.recipient_encrypted_keys[0], &recipient).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("does not match curve")
                || msg.contains("KEA OID")
                || msg.contains("not a valid binding"),
            "unexpected error: {msg}"
        );
    }

    /// P-384 ECDH + X9.63-SHA-384 KDF + AES-256 KW unwrap round trip
    /// (round-15 P-384 path).
    #[test]
    fn p384_aes256_wrap_unwrap_round_trip() {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        use p384::SecretKey;
        // 48-byte deterministic scalars for P-384.
        let ephemeral_scalar = [0x42u8; 48];
        let recipient_scalar = [0x77u8; 48];
        let recipient_secret = SecretKey::from_slice(&recipient_scalar).unwrap();
        let recipient_pub = recipient_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let cek = vec![0x9Au8; 32];
        let ukm = b"OXIDEAV-UKM-P384";
        let (originator_pub, wrapped) = wrap_cek_for_recipient(
            KariCurve::P384,
            &ephemeral_scalar,
            &recipient_pub,
            Some(ukm),
            &cek,
            WrapAlgorithm::Aes256,
        )
        .expect("wrap P-384");
        // P-384 SEC1 uncompressed point = 1 + 2*48 = 97 bytes.
        assert_eq!(originator_pub.len(), 97);
        let kari = KeyAgreeRecipientInfo {
            originator: OriginatorId::OriginatorKey(OriginatorPublicKey {
                algorithm_oid: OID_EC_PUBLIC_KEY.to_vec(),
                algorithm_params: write_oid(&OID_SECP384R1),
                public_key: originator_pub,
            }),
            ukm: ukm.to_vec(),
            key_encryption_oid: OID_DH_SINGLE_PASS_STDDH_SHA384_KDF.to_vec(),
            key_encryption_params: write_sequence(&write_oid(&OID_AES256_WRAP)),
            recipient_encrypted_keys: vec![RecipientEncryptedKey {
                rid: KeyAgreeRecipientId::RecipientKeyIdentifier {
                    ski: vec![0x33u8; 20],
                },
                encrypted_key: wrapped,
            }],
        };
        let recipient = EcRecipient::p384(recipient_scalar.to_vec(), recipient_pub);
        let unwrapped =
            unwrap_kari(&kari, &kari.recipient_encrypted_keys[0], &recipient).expect("unwrap");
        assert_eq!(unwrapped, cek);
    }

    /// X25519 ECDH + X9.63-SHA-256 KDF + AES-128 KW unwrap round trip
    /// (round-15 X25519 path per RFC 8418).
    #[test]
    fn x25519_aes128_wrap_unwrap_round_trip() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let recipient_scalar_arr = [0x44u8; 32];
        let secret = StaticSecret::from(recipient_scalar_arr);
        let recipient_pub = PublicKey::from(&secret).as_bytes().to_vec();
        let ephemeral_scalar = [0x66u8; 32];
        let cek = vec![0xC1u8; 16];
        let (originator_pub, wrapped) = wrap_cek_for_recipient(
            KariCurve::X25519,
            &ephemeral_scalar,
            &recipient_pub,
            None,
            &cek,
            WrapAlgorithm::Aes128,
        )
        .expect("wrap X25519");
        // X25519 raw u-coordinate = 32 bytes.
        assert_eq!(originator_pub.len(), 32);
        let kari = KeyAgreeRecipientInfo {
            originator: OriginatorId::OriginatorKey(OriginatorPublicKey {
                algorithm_oid: OID_X25519.to_vec(),
                // RFC 8410 §3 — parameters absent.
                algorithm_params: Vec::new(),
                public_key: originator_pub,
            }),
            ukm: Vec::new(),
            key_encryption_oid: OID_DH_SINGLE_PASS_STDDH_SHA256_KDF.to_vec(),
            key_encryption_params: write_sequence(&write_oid(&OID_AES128_WRAP)),
            recipient_encrypted_keys: vec![RecipientEncryptedKey {
                rid: KeyAgreeRecipientId::RecipientKeyIdentifier {
                    ski: vec![0xABu8; 20],
                },
                encrypted_key: wrapped,
            }],
        };
        let recipient = EcRecipient::x25519(recipient_scalar_arr.to_vec(), recipient_pub);
        let unwrapped =
            unwrap_kari(&kari, &kari.recipient_encrypted_keys[0], &recipient).expect("unwrap");
        assert_eq!(unwrapped, cek);
    }

    /// X9.63 KDF SHA-384 vector check — single block emits
    /// `SHA-384(z || 0x00000001 || sharedInfo)`.
    #[test]
    fn x963_kdf_sha384_one_block() {
        let z = [0x42u8; 48];
        let shared_info = [0x99u8; 8];
        let out = x963_kdf::<sha2::Sha384>(&z, &shared_info, 48);
        use sha2::Digest;
        let mut h = sha2::Sha384::new();
        h.update(z);
        h.update(1u32.to_be_bytes());
        h.update(shared_info);
        let want = h.finalize().to_vec();
        assert_eq!(out, want);
    }

    /// Curve dispatch sanity: every curve's `kea_oid()` round-trips
    /// through `algorithm_oid()` consistently and the helpers all
    /// agree on the same OID family.
    #[test]
    fn curve_oid_dispatch_consistency() {
        assert_eq!(
            KariCurve::P256.kea_oid(),
            &OID_DH_SINGLE_PASS_STDDH_SHA256_KDF
        );
        assert_eq!(
            KariCurve::P384.kea_oid(),
            &OID_DH_SINGLE_PASS_STDDH_SHA384_KDF
        );
        assert_eq!(
            KariCurve::P521.kea_oid(),
            &OID_DH_SINGLE_PASS_STDDH_SHA512_KDF
        );
        assert_eq!(
            KariCurve::X25519.kea_oid(),
            &OID_DH_SINGLE_PASS_STDDH_SHA256_KDF
        );
        assert_eq!(KariCurve::P256.algorithm_oid(), &OID_EC_PUBLIC_KEY);
        assert_eq!(KariCurve::P384.algorithm_oid(), &OID_EC_PUBLIC_KEY);
        assert_eq!(KariCurve::P521.algorithm_oid(), &OID_EC_PUBLIC_KEY);
        assert_eq!(KariCurve::X25519.algorithm_oid(), &OID_X25519);
        // Default KDF mapping per RFC 5753 §7.1.4 / RFC 8418 §2.1.
        assert_eq!(KariCurve::P256.default_kdf(), KariKdf::X963Sha256);
        assert_eq!(KariCurve::P384.default_kdf(), KariKdf::X963Sha384);
        assert_eq!(KariCurve::P521.default_kdf(), KariKdf::X963Sha512);
        assert_eq!(KariCurve::X25519.default_kdf(), KariKdf::X963Sha256);
    }

    /// X9.63 KDF SHA-512 vector check — single block emits
    /// `SHA-512(z || 0x00000001 || sharedInfo)`.
    #[test]
    fn x963_kdf_sha512_one_block() {
        let z = [0x42u8; 66];
        let shared_info = [0x99u8; 8];
        let out = x963_kdf::<sha2::Sha512>(&z, &shared_info, 64);
        use sha2::Digest;
        let mut h = sha2::Sha512::new();
        h.update(z);
        h.update(1u32.to_be_bytes());
        h.update(shared_info);
        let want = h.finalize().to_vec();
        assert_eq!(out, want);
    }

    /// HKDF dispatch round-trip: `derive_kek` + RFC 5869's primitives
    /// agree byte-for-byte. Sanity-checks the salt-from-UKM wiring.
    #[test]
    fn hkdf_kek_matches_rfc5869() {
        let z = [0x10u8; 32];
        let ukm = b"OXIDEAV-UKM-RFC8418";
        let info = build_ecc_cms_shared_info(&OID_AES256_WRAP, Some(ukm), 256);
        // derive_kek path.
        let got = derive_kek(KariKdf::HkdfSha256, &z, Some(ukm), &info, 32);
        // Direct hkdf primitive call — same inputs.
        let want = {
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(ukm), &z);
            let mut okm = [0u8; 32];
            hk.expand(&info, &mut okm).unwrap();
            okm.to_vec()
        };
        assert_eq!(got, want);
        // Sanity: empty UKM ⇒ salt absent (None), not Some(empty).
        let got_no_salt = derive_kek(KariKdf::HkdfSha256, &z, None, &info, 32);
        let want_no_salt = {
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &z);
            let mut okm = [0u8; 32];
            hk.expand(&info, &mut okm).unwrap();
            okm.to_vec()
        };
        assert_eq!(got_no_salt, want_no_salt);
    }

    /// `KariKdf::is_valid_for` enforces the RFC 5753 / RFC 8418 pairing
    /// matrix: NIST curves are pinned to one X9.63 SHA hash; X25519
    /// accepts X9.63-SHA-256 + every HKDF flavour, and rejects the
    /// SHA-384 / SHA-512 X9.63 bindings (those are NIST-only).
    #[test]
    fn kdf_curve_pairing_matrix() {
        // P-256 — only X9.63-SHA-256.
        assert!(KariKdf::X963Sha256.is_valid_for(KariCurve::P256));
        assert!(!KariKdf::X963Sha384.is_valid_for(KariCurve::P256));
        assert!(!KariKdf::X963Sha512.is_valid_for(KariCurve::P256));
        assert!(!KariKdf::HkdfSha256.is_valid_for(KariCurve::P256));
        // P-384 — only X9.63-SHA-384.
        assert!(KariKdf::X963Sha384.is_valid_for(KariCurve::P384));
        assert!(!KariKdf::X963Sha256.is_valid_for(KariCurve::P384));
        assert!(!KariKdf::HkdfSha384.is_valid_for(KariCurve::P384));
        // P-521 — only X9.63-SHA-512.
        assert!(KariKdf::X963Sha512.is_valid_for(KariCurve::P521));
        assert!(!KariKdf::X963Sha384.is_valid_for(KariCurve::P521));
        assert!(!KariKdf::HkdfSha512.is_valid_for(KariCurve::P521));
        // X25519 — X9.63-SHA-256 + every HKDF flavour.
        assert!(KariKdf::X963Sha256.is_valid_for(KariCurve::X25519));
        assert!(KariKdf::HkdfSha256.is_valid_for(KariCurve::X25519));
        assert!(KariKdf::HkdfSha384.is_valid_for(KariCurve::X25519));
        assert!(KariKdf::HkdfSha512.is_valid_for(KariCurve::X25519));
        // X9.63 SHA-384 / 512 are NOT defined for X25519 in the RFCs.
        assert!(!KariKdf::X963Sha384.is_valid_for(KariCurve::X25519));
        assert!(!KariKdf::X963Sha512.is_valid_for(KariCurve::X25519));
    }

    /// Round-16: P-521 ECDH + X9.63-SHA-512 KDF + AES-256 KW unwrap
    /// round trip.
    #[test]
    fn p521_aes256_wrap_unwrap_round_trip() {
        use p521::elliptic_curve::sec1::ToEncodedPoint;
        use p521::SecretKey;
        // 66-byte deterministic scalars for P-521. The first byte
        // carries only 1 bit of the 521-bit field, so we lead with
        // 0x00 to keep the scalar comfortably below the curve order n
        // (≈ 2^521). The remaining 65 bytes are an arbitrary pattern.
        let mut ephemeral_scalar = [0x42u8; 66];
        ephemeral_scalar[0] = 0x00;
        let mut recipient_scalar = [0x77u8; 66];
        recipient_scalar[0] = 0x00;
        let recipient_secret = SecretKey::from_slice(&recipient_scalar).unwrap();
        let recipient_pub = recipient_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let cek = vec![0x9Au8; 32];
        let ukm = b"OXIDEAV-UKM-P521";
        let (originator_pub, wrapped) = wrap_cek_for_recipient(
            KariCurve::P521,
            &ephemeral_scalar,
            &recipient_pub,
            Some(ukm),
            &cek,
            WrapAlgorithm::Aes256,
        )
        .expect("wrap P-521");
        // P-521 SEC1 uncompressed point = 1 + 2*66 = 133 bytes.
        assert_eq!(originator_pub.len(), 133);
        let kari = KeyAgreeRecipientInfo {
            originator: OriginatorId::OriginatorKey(OriginatorPublicKey {
                algorithm_oid: OID_EC_PUBLIC_KEY.to_vec(),
                algorithm_params: write_oid(&OID_SECP521R1),
                public_key: originator_pub,
            }),
            ukm: ukm.to_vec(),
            key_encryption_oid: OID_DH_SINGLE_PASS_STDDH_SHA512_KDF.to_vec(),
            key_encryption_params: write_sequence(&write_oid(&OID_AES256_WRAP)),
            recipient_encrypted_keys: vec![RecipientEncryptedKey {
                rid: KeyAgreeRecipientId::RecipientKeyIdentifier {
                    ski: vec![0x33u8; 20],
                },
                encrypted_key: wrapped,
            }],
        };
        let recipient = EcRecipient::p521(recipient_scalar.to_vec(), recipient_pub);
        let unwrapped =
            unwrap_kari(&kari, &kari.recipient_encrypted_keys[0], &recipient).expect("unwrap");
        assert_eq!(unwrapped, cek);
    }

    /// Round-16: X25519 ECDH + HKDF-SHA-256 KDF + AES-128 KW round trip
    /// (RFC 8418 §2.2 — `dhSinglePass-stdDH-hkdf-sha256-scheme`).
    #[test]
    fn x25519_hkdf_sha256_aes128_wrap_unwrap_round_trip() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let recipient_scalar_arr = [0x44u8; 32];
        let secret = StaticSecret::from(recipient_scalar_arr);
        let recipient_pub = PublicKey::from(&secret).as_bytes().to_vec();
        let ephemeral_scalar = [0x66u8; 32];
        let cek = vec![0xC1u8; 16];
        let ukm = b"OXIDEAV-UKM-RFC8418-22";
        let (originator_pub, wrapped) = wrap_cek_for_recipient_with_kdf(
            KariCurve::X25519,
            KariKdf::HkdfSha256,
            &ephemeral_scalar,
            &recipient_pub,
            Some(ukm),
            &cek,
            WrapAlgorithm::Aes128,
        )
        .expect("wrap X25519 HKDF");
        let kari = KeyAgreeRecipientInfo {
            originator: OriginatorId::OriginatorKey(OriginatorPublicKey {
                algorithm_oid: OID_X25519.to_vec(),
                algorithm_params: Vec::new(),
                public_key: originator_pub,
            }),
            ukm: ukm.to_vec(),
            key_encryption_oid: OID_DH_SINGLE_PASS_STDDH_HKDF_SHA256_SCHEME.to_vec(),
            key_encryption_params: write_sequence(&write_oid(&OID_AES128_WRAP)),
            recipient_encrypted_keys: vec![RecipientEncryptedKey {
                rid: KeyAgreeRecipientId::RecipientKeyIdentifier {
                    ski: vec![0xABu8; 20],
                },
                encrypted_key: wrapped,
            }],
        };
        let recipient = EcRecipient::x25519(recipient_scalar_arr.to_vec(), recipient_pub);
        let unwrapped =
            unwrap_kari(&kari, &kari.recipient_encrypted_keys[0], &recipient).expect("unwrap");
        assert_eq!(unwrapped, cek);
    }

    /// Round-16: X25519 ECDH + HKDF-SHA-384 KDF + AES-256 KW round trip
    /// (RFC 8418 §2.2 — `dhSinglePass-stdDH-hkdf-sha384-scheme`).
    /// Exercises the absent-UKM (salt = None) path.
    #[test]
    fn x25519_hkdf_sha384_aes256_no_ukm_round_trip() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let recipient_scalar_arr = [0x55u8; 32];
        let secret = StaticSecret::from(recipient_scalar_arr);
        let recipient_pub = PublicKey::from(&secret).as_bytes().to_vec();
        let ephemeral_scalar = [0xA6u8; 32];
        let cek = vec![0xD2u8; 32];
        let (originator_pub, wrapped) = wrap_cek_for_recipient_with_kdf(
            KariCurve::X25519,
            KariKdf::HkdfSha384,
            &ephemeral_scalar,
            &recipient_pub,
            None,
            &cek,
            WrapAlgorithm::Aes256,
        )
        .expect("wrap X25519 HKDF-384");
        let kari = KeyAgreeRecipientInfo {
            originator: OriginatorId::OriginatorKey(OriginatorPublicKey {
                algorithm_oid: OID_X25519.to_vec(),
                algorithm_params: Vec::new(),
                public_key: originator_pub,
            }),
            ukm: Vec::new(),
            key_encryption_oid: OID_DH_SINGLE_PASS_STDDH_HKDF_SHA384_SCHEME.to_vec(),
            key_encryption_params: write_sequence(&write_oid(&OID_AES256_WRAP)),
            recipient_encrypted_keys: vec![RecipientEncryptedKey {
                rid: KeyAgreeRecipientId::RecipientKeyIdentifier {
                    ski: vec![0xCDu8; 20],
                },
                encrypted_key: wrapped,
            }],
        };
        let recipient = EcRecipient::x25519(recipient_scalar_arr.to_vec(), recipient_pub);
        let unwrapped =
            unwrap_kari(&kari, &kari.recipient_encrypted_keys[0], &recipient).expect("unwrap");
        assert_eq!(unwrapped, cek);
    }

    /// Round-16: X25519 ECDH + HKDF-SHA-512 KDF + AES-256 KW round trip
    /// (RFC 8418 §2.2 — `dhSinglePass-stdDH-hkdf-sha512-scheme`).
    #[test]
    fn x25519_hkdf_sha512_aes256_wrap_unwrap_round_trip() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let recipient_scalar_arr = [0x77u8; 32];
        let secret = StaticSecret::from(recipient_scalar_arr);
        let recipient_pub = PublicKey::from(&secret).as_bytes().to_vec();
        let ephemeral_scalar = [0xE3u8; 32];
        let cek = vec![0xF1u8; 32];
        let ukm = b"UKM-512";
        let (originator_pub, wrapped) = wrap_cek_for_recipient_with_kdf(
            KariCurve::X25519,
            KariKdf::HkdfSha512,
            &ephemeral_scalar,
            &recipient_pub,
            Some(ukm),
            &cek,
            WrapAlgorithm::Aes256,
        )
        .expect("wrap X25519 HKDF-512");
        let kari = KeyAgreeRecipientInfo {
            originator: OriginatorId::OriginatorKey(OriginatorPublicKey {
                algorithm_oid: OID_X25519.to_vec(),
                algorithm_params: Vec::new(),
                public_key: originator_pub,
            }),
            ukm: ukm.to_vec(),
            key_encryption_oid: OID_DH_SINGLE_PASS_STDDH_HKDF_SHA512_SCHEME.to_vec(),
            key_encryption_params: write_sequence(&write_oid(&OID_AES256_WRAP)),
            recipient_encrypted_keys: vec![RecipientEncryptedKey {
                rid: KeyAgreeRecipientId::RecipientKeyIdentifier {
                    ski: vec![0xEFu8; 20],
                },
                encrypted_key: wrapped,
            }],
        };
        let recipient = EcRecipient::x25519(recipient_scalar_arr.to_vec(), recipient_pub);
        let unwrapped =
            unwrap_kari(&kari, &kari.recipient_encrypted_keys[0], &recipient).expect("unwrap");
        assert_eq!(unwrapped, cek);
    }

    /// `wrap_cek_for_recipient_with_kdf` rejects an X9.63-SHA-512 KDF
    /// against an X25519 curve at build time (the pairing is illegal
    /// per RFC 8418 §2 — only X9.63-SHA-256 + HKDF flavours are
    /// permitted).
    #[test]
    fn invalid_kdf_curve_pairing_rejected_at_build() {
        let err = wrap_cek_for_recipient_with_kdf(
            KariCurve::X25519,
            KariKdf::X963Sha512,
            &[0u8; 32],
            &[0u8; 32],
            None,
            &[0u8; 32],
            WrapAlgorithm::Aes256,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not a valid binding"),
            "unexpected error: {msg}"
        );
    }
}
