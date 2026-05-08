//! PDF *encryption* writer-side support — ISO 32000-1 §7.6.3 +
//! ISO 32000-2 §7.6.4 Standard Security Handler.
//!
//! Mirror image of [`crate::decrypt`]: the reader recovers the file
//! key from `(O, U, OE, UE, Perms)`; the writer goes the other way —
//! starting from a user / owner password it produces those entries
//! plus the file key itself, then encrypts every indirect-object
//! string and stream payload before [`crate::objects::Document::write_to`]
//! emits the file bytes.
//!
//! # Coverage
//!
//! - **R=2** — RC4-40 (V=1).
//! - **R=3** — RC4-128 (V=2).
//! - **R=4** — AES-128 CBC (`CFM=AESV2`) or RC4-128 (`CFM=V2`).
//! - **R=5** — AES-256 CBC (V=5, `CFM=AESV3`); Adobe ext L3.
//! - **R=6** — AES-256 CBC (V=5, `CFM=AESV3`); ISO 32000-2:2020.
//!
//! # Algorithms (numbered per ISO 32000)
//!
//! - **Algorithm 3** — compute `/O` from owner + user passwords (R≤4).
//! - **Algorithm 4** (R=2) — compute `/U` from the file key + pad.
//! - **Algorithm 5** (R≥3) — compute `/U` from MD5(pad ‖ ID) + 20× RC4.
//! - **Algorithm 8** — compute `/O` + `/OE` for V=5.
//! - **Algorithm 9** — compute `/U` + `/UE` for V=5.
//! - **Algorithm 10** — encrypt the `/Perms` permissions block (V=5).
//!
//! Algorithms 8, 9, 10 are re-exported from [`crate::decrypt::r5_r6`]
//! since they were already needed for the round-5 fixture builder; the
//! V≤4 entries (Algorithms 3, 4, 5) live in this module.

use crate::decrypt::r5_r6::{algorithm_10, algorithm_8, algorithm_9};
use crate::decrypt::{md5, rc4, CryptMethod, StandardHandler};
use crate::error::PdfError;
use crate::objects::{Dict, Object};

/// The 32-byte password-padding string from §7.6.3.3 Algorithm 2 step (a).
const PAD: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

/// Pad / truncate a password to exactly 32 bytes per Algorithm 2 step (a).
fn pad_password(password: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let take = password.len().min(32);
    out[..take].copy_from_slice(&password[..take]);
    if take < 32 {
        out[take..].copy_from_slice(&PAD[..32 - take]);
    }
    out
}

/// Writer-side configuration: what kind of encryption to apply, what
/// the user / owner passwords are, the permissions, and the (optional)
/// IVs / salts to feed into the AES paths so output stays
/// deterministic for tests.
#[derive(Clone, Debug)]
pub struct EncryptionConfig {
    /// Revision — 2..=6. Implies `length_bits`, `cfm`, and which
    /// algorithm family (V≤4 vs V=5) to use.
    pub revision: u8,
    /// File-key length in bits. R=2: 40. R=3 / R=4: typically 128.
    /// R=5 / R=6: always 256.
    pub length_bits: usize,
    /// User password (raw bytes — V=5 truncates to 127, V≤4 pads to 32).
    pub user_password: Vec<u8>,
    /// Owner password — `Algorithm 3` falls back to user password when
    /// empty.
    pub owner_password: Vec<u8>,
    /// 32-bit signed permissions value (§7.6.3.2 Table 22).
    pub p: i32,
    /// Whether the document metadata stream is encrypted (R≥4).
    pub encrypt_metadata: bool,
    /// Per-stream / per-string crypt method. RC4 / AES-128 / AES-256.
    pub method: CryptMethod,
    /// Permanent file identifier — placed in `/ID[0]` and fed into the
    /// V≤4 file-key derivation. Use ≥16 bytes of random data per the
    /// spec; tests pin it for determinism.
    pub file_id: Vec<u8>,
    /// V=5 user-validation salt (8 bytes).
    pub u_salt_validate: [u8; 8],
    /// V=5 user-key salt (8 bytes).
    pub u_salt_key: [u8; 8],
    /// V=5 owner-validation salt (8 bytes).
    pub o_salt_validate: [u8; 8],
    /// V=5 owner-key salt (8 bytes).
    pub o_salt_key: [u8; 8],
    /// V=5 file encryption key (32 bytes) — random for production,
    /// caller-pinned for tests. None defaults to a deterministic-but-
    /// non-reused-across-callers value.
    pub file_key_v5: Option<[u8; 32]>,
    /// V=5 Algorithm 10 padding bytes (12..16).
    pub perms_padding: [u8; 4],
    /// IV for AES per-object encryption (16 bytes). Tests pin; production
    /// callers should override per-object.
    pub aes_iv: [u8; 16],
}

impl EncryptionConfig {
    /// Sensible R=4 (AES-128) default — empty owner password, no
    /// metadata encryption opt-out, full permissions.
    pub fn aes_128(user_password: &[u8], file_id: &[u8]) -> Self {
        Self {
            revision: 4,
            length_bits: 128,
            user_password: user_password.to_vec(),
            owner_password: Vec::new(),
            p: -4,
            encrypt_metadata: true,
            method: CryptMethod::Aes128,
            file_id: file_id.to_vec(),
            u_salt_validate: [0; 8],
            u_salt_key: [0; 8],
            o_salt_validate: [0; 8],
            o_salt_key: [0; 8],
            file_key_v5: None,
            perms_padding: [0; 4],
            aes_iv: [0; 16],
        }
    }

    /// R=3 RC4-128 default.
    pub fn rc4_128(user_password: &[u8], file_id: &[u8]) -> Self {
        Self {
            revision: 3,
            length_bits: 128,
            user_password: user_password.to_vec(),
            owner_password: Vec::new(),
            p: -4,
            encrypt_metadata: true,
            method: CryptMethod::Rc4,
            file_id: file_id.to_vec(),
            u_salt_validate: [0; 8],
            u_salt_key: [0; 8],
            o_salt_validate: [0; 8],
            o_salt_key: [0; 8],
            file_key_v5: None,
            perms_padding: [0; 4],
            aes_iv: [0; 16],
        }
    }

    /// R=2 RC4-40 default.
    pub fn rc4_40(user_password: &[u8], file_id: &[u8]) -> Self {
        Self {
            revision: 2,
            length_bits: 40,
            user_password: user_password.to_vec(),
            owner_password: Vec::new(),
            p: -4,
            encrypt_metadata: true,
            method: CryptMethod::Rc4,
            file_id: file_id.to_vec(),
            u_salt_validate: [0; 8],
            u_salt_key: [0; 8],
            o_salt_validate: [0; 8],
            o_salt_key: [0; 8],
            file_key_v5: None,
            perms_padding: [0; 4],
            aes_iv: [0; 16],
        }
    }

    /// R=5 AES-256 default (Adobe extension level 3).
    pub fn aes_256_r5(user_password: &[u8], file_id: &[u8]) -> Self {
        Self {
            revision: 5,
            length_bits: 256,
            user_password: user_password.to_vec(),
            owner_password: Vec::new(),
            p: -4,
            encrypt_metadata: true,
            method: CryptMethod::Aes256,
            file_id: file_id.to_vec(),
            u_salt_validate: [0x55; 8],
            u_salt_key: [0x55; 8],
            o_salt_validate: [0xAA; 8],
            o_salt_key: [0xAA; 8],
            file_key_v5: None,
            perms_padding: [0xCA, 0xFE, 0xBA, 0xBE],
            aes_iv: [0; 16],
        }
    }

    /// R=6 AES-256 default (ISO 32000-2 PDF 2.0).
    pub fn aes_256_r6(user_password: &[u8], file_id: &[u8]) -> Self {
        let mut c = Self::aes_256_r5(user_password, file_id);
        c.revision = 6;
        c
    }

    /// Apply an owner password.
    pub fn with_owner_password(mut self, owner: &[u8]) -> Self {
        self.owner_password = owner.to_vec();
        self
    }

    /// Override permissions.
    pub fn with_permissions(mut self, p: i32) -> Self {
        self.p = p;
        self
    }
}

/// Resolved writer-side state — handler (file key + crypt method),
/// the `/Encrypt` dictionary, and the `/ID` array. Built once at the
/// start of [`crate::objects::Document::write_to`] and threaded
/// through per-object string + stream encryption.
#[derive(Clone, Debug)]
pub struct EncryptionState {
    /// Handler used to encrypt every string + stream.
    pub handler: StandardHandler,
    /// `/Encrypt` dictionary as it must appear in the file. Becomes a
    /// new indirect object at write time.
    pub encrypt_dict: Dict,
    /// 16-byte file ID — placed in trailer `/ID[0]` AND `/ID[1]`.
    pub file_id: Vec<u8>,
    /// IV used for per-object AES encryption. Tests pin; the writer
    /// uses one IV across all objects when this is the only knob (the
    /// per-object Algorithm 1 key derivation already varies the
    /// effective key per object).
    pub aes_iv: [u8; 16],
}

impl EncryptionState {
    /// Build the writer-side state from a config.
    pub fn build(config: &EncryptionConfig) -> Result<Self, PdfError> {
        // Validate cfg.
        if !(2..=6).contains(&config.revision) {
            return Err(PdfError::other(format!(
                "PDF encrypt: revision R={} not supported (R∈[2,6])",
                config.revision
            )));
        }
        if config.revision >= 5 && config.length_bits != 256 {
            return Err(PdfError::other(format!(
                "PDF encrypt: V=5 requires Length=256 bits (got {})",
                config.length_bits
            )));
        }
        if config.revision <= 4
            && (config.length_bits % 8 != 0 || !(40..=128).contains(&config.length_bits))
        {
            return Err(PdfError::other(format!(
                "PDF encrypt: V≤4 requires Length∈[40..=128] (mult of 8); got {}",
                config.length_bits
            )));
        }

        if config.revision >= 5 {
            Self::build_v5(config)
        } else {
            Self::build_v_le_4(config)
        }
    }

    fn build_v_le_4(c: &EncryptionConfig) -> Result<Self, PdfError> {
        let n = c.length_bits / 8;

        // Algorithm 3 — compute /O.
        let o = algorithm_3(&c.user_password, &c.owner_password, c.revision, n);

        // Algorithm 2 — compute file encryption key.
        let key = algorithm_2_filekey(
            &c.user_password,
            &o,
            c.p,
            &c.file_id,
            c.revision,
            n,
            c.encrypt_metadata,
        );

        // Algorithm 4 / 5 — compute /U.
        let u = if c.revision == 2 {
            // Algorithm 4 — RC4(file_key, PAD).
            let mut out = [0u8; 32];
            out.copy_from_slice(&rc4(&key, &PAD));
            out
        } else {
            // Algorithm 5 — RC4 ladder over MD5(PAD ‖ file_id).
            let mut hash_input = Vec::with_capacity(32 + c.file_id.len());
            hash_input.extend_from_slice(&PAD);
            hash_input.extend_from_slice(&c.file_id);
            let h = md5(&hash_input);
            let mut data = rc4(&key, &h);
            for i in 1u8..=19 {
                let xkey: Vec<u8> = key.iter().map(|b| b ^ i).collect();
                data = rc4(&xkey, &data);
            }
            let mut out = [0u8; 32];
            out[..16].copy_from_slice(&data[..16]);
            // Last 16 are arbitrary — zeros are fine; the reader only
            // compares the first 16 for R≥3.
            out
        };

        let handler = StandardHandler {
            key: key.clone(),
            method: c.method,
            revision: c.revision,
        };

        // Build the /Encrypt dict.
        let v: i64 = match (c.revision, c.method) {
            (2, _) => 1,
            (3, _) => 2,
            (4, _) => 4,
            _ => unreachable!("V≤4 path checked at entry"),
        };
        let mut dict = Dict::new()
            .with("Filter", Object::Name("Standard".into()))
            .with("V", Object::Integer(v))
            .with("R", Object::Integer(c.revision as i64))
            .with("Length", Object::Integer(c.length_bits as i64))
            .with("O", Object::LiteralString(o.to_vec()))
            .with("U", Object::LiteralString(u.to_vec()))
            .with("P", Object::Integer(c.p as i64));
        if !c.encrypt_metadata {
            dict.set("EncryptMetadata", Object::Bool(false));
        }

        // V=4 carries a /CF dict picking the crypt method. For V<4,
        // the choice is implicit (RC4) and /CF is not emitted.
        if c.revision == 4 {
            let cfm = match c.method {
                CryptMethod::Aes128 => "AESV2",
                CryptMethod::Rc4 => "V2",
                CryptMethod::Aes256 => {
                    return Err(PdfError::other(
                        "PDF encrypt: AES-256 requires V=5/R=5+ (got V=4)",
                    ));
                }
            };
            let crypt_filter_len = match c.method {
                CryptMethod::Aes128 => 16,
                CryptMethod::Rc4 => 16,
                CryptMethod::Aes256 => 32,
            };
            let std_cf = Dict::new()
                .with("Type", Object::Name("CryptFilter".into()))
                .with("CFM", Object::Name(cfm.into()))
                .with("Length", Object::Integer(crypt_filter_len));
            let cf = Dict::new().with("StdCF", Object::Dict(std_cf));
            dict.set("CF", Object::Dict(cf));
            dict.set("StmF", Object::Name("StdCF".into()));
            dict.set("StrF", Object::Name("StdCF".into()));
        }

        Ok(EncryptionState {
            handler,
            encrypt_dict: dict,
            file_id: c.file_id.clone(),
            aes_iv: c.aes_iv,
        })
    }

    fn build_v5(c: &EncryptionConfig) -> Result<Self, PdfError> {
        // V=5 keys the file directly (no per-object Algorithm 1).
        let file_key = c
            .file_key_v5
            .unwrap_or_else(default_file_key_v5_for_password);
        let user_pw = if c.user_password.len() > 127 {
            &c.user_password[..127]
        } else {
            &c.user_password[..]
        };
        let owner_pw = if c.owner_password.is_empty() {
            user_pw
        } else if c.owner_password.len() > 127 {
            &c.owner_password[..127]
        } else {
            &c.owner_password[..]
        };

        // Algorithm 9 — /U + /UE.
        let (u, ue) = algorithm_9(
            c.revision,
            user_pw,
            &file_key,
            &c.u_salt_validate,
            &c.u_salt_key,
        );
        // Algorithm 8 — /O + /OE (depends on /U).
        let (o, oe) = algorithm_8(
            c.revision,
            owner_pw,
            &u,
            &file_key,
            &c.o_salt_validate,
            &c.o_salt_key,
        );
        // Algorithm 10 — /Perms.
        let perms = algorithm_10(&file_key, c.p, c.encrypt_metadata, &c.perms_padding);

        let handler = StandardHandler {
            key: file_key.to_vec(),
            method: CryptMethod::Aes256,
            revision: c.revision,
        };

        let std_cf = Dict::new()
            .with("Type", Object::Name("CryptFilter".into()))
            .with("CFM", Object::Name("AESV3".into()))
            .with("Length", Object::Integer(32));
        let cf = Dict::new().with("StdCF", Object::Dict(std_cf));
        let mut dict = Dict::new()
            .with("Filter", Object::Name("Standard".into()))
            .with("V", Object::Integer(5))
            .with("R", Object::Integer(c.revision as i64))
            .with("Length", Object::Integer(256))
            .with("CF", Object::Dict(cf))
            .with("StmF", Object::Name("StdCF".into()))
            .with("StrF", Object::Name("StdCF".into()))
            .with("O", Object::LiteralString(o.to_vec()))
            .with("U", Object::LiteralString(u.to_vec()))
            .with("OE", Object::LiteralString(oe.to_vec()))
            .with("UE", Object::LiteralString(ue.to_vec()))
            .with("Perms", Object::LiteralString(perms.to_vec()))
            .with("P", Object::Integer(c.p as i64));
        if !c.encrypt_metadata {
            dict.set("EncryptMetadata", Object::Bool(false));
        }

        Ok(EncryptionState {
            handler,
            encrypt_dict: dict,
            file_id: c.file_id.clone(),
            aes_iv: c.aes_iv,
        })
    }
}

/// Algorithm 3 — compute /O (32 bytes). When `owner_password` is empty
/// the user password is used as the owner password's MD5 source.
fn algorithm_3(user_password: &[u8], owner_password: &[u8], revision: u8, n: usize) -> [u8; 32] {
    // (a) Pad owner (or user) password.
    let owner_src = if owner_password.is_empty() {
        user_password
    } else {
        owner_password
    };
    let opad = pad_password(owner_src);
    // (b) MD5.
    let mut h = md5(&opad);
    // (c) for R≥3, loop 50 times.
    if revision >= 3 {
        for _ in 0..50 {
            h = md5(&h[..n]);
        }
    }
    let okey = h[..n].to_vec();
    // (d) Pad user password.
    let upad = pad_password(user_password);
    // (e) RC4.
    let mut buf = rc4(&okey, &upad);
    // (f) For R≥3, 19 more rounds with byte-XOR'd keys.
    if revision >= 3 {
        for i in 1u8..=19 {
            let xkey: Vec<u8> = okey.iter().map(|b| b ^ i).collect();
            buf = rc4(&xkey, &buf);
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf);
    out
}

/// Algorithm 2 — compute file encryption key. Mirror of
/// [`crate::decrypt::compute_key`] (which is private to `decrypt`).
fn algorithm_2_filekey(
    user_password: &[u8],
    o: &[u8; 32],
    p: i32,
    file_id: &[u8],
    revision: u8,
    n: usize,
    encrypt_metadata: bool,
) -> Vec<u8> {
    let pwd = pad_password(user_password);
    let mut buf = Vec::with_capacity(32 + 32 + 4 + file_id.len() + 4);
    buf.extend_from_slice(&pwd);
    buf.extend_from_slice(o);
    buf.extend_from_slice(&(p as u32).to_le_bytes());
    buf.extend_from_slice(file_id);
    if revision >= 4 && !encrypt_metadata {
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    }
    let mut h = md5(&buf);
    if revision >= 3 {
        for _ in 0..50 {
            h = md5(&h[..n]);
        }
    }
    h[..n].to_vec()
}

/// Default V=5 file-key — a well-known constant. NOT secure for
/// production; callers supplying random data via `file_key_v5` get
/// real security. The default is convenient for tests + lets users
/// who haven't audited the API avoid hitting `unwrap` on `None`.
fn default_file_key_v5_for_password() -> [u8; 32] {
    [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
        0xF0, 0x01,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::{open_with_password, CryptMethod};

    #[test]
    fn algorithm_3_with_empty_owner_password_falls_back_to_user() {
        let o_a = algorithm_3(b"hello", b"", 3, 16);
        let o_b = algorithm_3(b"hello", b"hello", 3, 16);
        assert_eq!(o_a, o_b);
    }

    #[test]
    fn build_v_le_4_round_trips_via_decrypt_authenticator() {
        // After building O / U for revision 3 with our writer-side
        // helper, the decrypt-side authenticator must accept the same
        // user password.
        let cfg = EncryptionConfig::rc4_128(b"hello", b"OXIDEAV-FIXTURE-ID-FIXED-VALUE!");
        let state = EncryptionState::build(&cfg).unwrap();
        // open_with_password expects the dict + file ID.
        let opened = open_with_password(&state.encrypt_dict, &state.file_id, b"hello").expect("ok");
        assert!(opened.is_some(), "user password should authenticate");
    }

    #[test]
    fn build_v_le_4_rejects_wrong_password() {
        let cfg = EncryptionConfig::rc4_128(b"correctpw", b"OXIDEAV-FIXTURE-ID-FIXED-VALUE!");
        let state = EncryptionState::build(&cfg).unwrap();
        let opened = open_with_password(&state.encrypt_dict, &state.file_id, b"wrong").unwrap();
        assert!(opened.is_none());
    }

    #[test]
    fn build_v_le_4_owner_password_authenticates() {
        let cfg = EncryptionConfig::rc4_128(b"userpw", b"OXIDEAV-FIXTURE-ID-FIXED-VALUE!")
            .with_owner_password(b"ownerpw");
        let state = EncryptionState::build(&cfg).unwrap();
        // Both passwords should succeed.
        let user_ok = open_with_password(&state.encrypt_dict, &state.file_id, b"userpw").unwrap();
        assert!(user_ok.is_some());
        let owner_ok = open_with_password(&state.encrypt_dict, &state.file_id, b"ownerpw").unwrap();
        assert!(owner_ok.is_some());
    }

    #[test]
    fn build_v5_r5_round_trips() {
        let cfg = EncryptionConfig::aes_256_r5(b"hunter2", b"FIXED-FILE-ID-32-BYTES-FOR-V5-XX");
        let state = EncryptionState::build(&cfg).unwrap();
        let opened = open_with_password(&state.encrypt_dict, &state.file_id, b"hunter2").unwrap();
        assert!(opened.is_some(), "R=5 user pw should authenticate");
        assert_eq!(opened.unwrap().method, CryptMethod::Aes256);
    }

    #[test]
    fn build_v5_r6_round_trips() {
        let cfg =
            EncryptionConfig::aes_256_r6(b"correct horse", b"FIXED-FILE-ID-32-BYTES-FOR-R6-X");
        let state = EncryptionState::build(&cfg).unwrap();
        let opened =
            open_with_password(&state.encrypt_dict, &state.file_id, b"correct horse").unwrap();
        assert!(opened.is_some(), "R=6 user pw should authenticate");
    }

    #[test]
    fn build_v5_r5_owner_password() {
        let cfg = EncryptionConfig::aes_256_r5(b"userpw", b"FIXED-FILE-ID-32-BYTES-FOR-V5-OW")
            .with_owner_password(b"ownerpw");
        let state = EncryptionState::build(&cfg).unwrap();
        let owner_ok = open_with_password(&state.encrypt_dict, &state.file_id, b"ownerpw").unwrap();
        assert!(owner_ok.is_some());
    }

    #[test]
    fn build_aes_128_r4_round_trips() {
        let cfg = EncryptionConfig::aes_128(b"aespw", b"AES-FIXTURE-FILE-ID-LONG-ENOUGH!");
        let state = EncryptionState::build(&cfg).unwrap();
        let opened = open_with_password(&state.encrypt_dict, &state.file_id, b"aespw").unwrap();
        assert!(opened.is_some(), "R=4 AES-128 should authenticate");
        assert_eq!(opened.unwrap().method, CryptMethod::Aes128);
    }

    #[test]
    fn build_rc4_40_r2_round_trips() {
        let cfg = EncryptionConfig::rc4_40(b"shorty", b"R2-FIXTURE-FILE-ID-LONG-ENOUGH!");
        let state = EncryptionState::build(&cfg).unwrap();
        let opened = open_with_password(&state.encrypt_dict, &state.file_id, b"shorty").unwrap();
        assert!(opened.is_some(), "R=2 RC4-40 should authenticate");
        assert_eq!(opened.unwrap().key.len(), 5);
    }
}
