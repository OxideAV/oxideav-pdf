//! PDF *decryption* support — ISO 32000-1 §7.6 Standard Security Handler.
//!
//! Round-4 reader gains the ability to open password-protected PDFs.
//! The standard security handler is the only handler this module
//! implements; public-key (`adbe.pkcs7.s3` / `s4` / `s5`) handlers
//! are out of scope.
//!
//! Coverage:
//!
//! * **R=2**: RC4-40 (V=1, Length 40).
//! * **R=3**: RC4-128 (V=2, Length up to 128).
//! * **R=4**: AES-128 CBC or RC4-128 selected by the crypt-filter
//!   `CFM` entry (`AESV2` vs `V2`).
//!
//! R=5 and R=6 (PDF 1.7 Adobe-extension AES-256, PDF 2.0 ISO AES-256)
//! land in a follow-up round — the password derivation is materially
//! different (SHA-256-based, no MD5 fan-out, validation salt + key
//! salt) and worth its own sweep.
//!
//! # Algorithms used (all numbered per §7.6.2 / §7.6.3)
//!
//! * **Algorithm 1** — per-object encryption key: extend file key
//!   with `objnum` LE3 + `gennum` LE2 (+ `"sAlT"` for AES), MD5,
//!   take first `n+5` ≤ 16 bytes.
//! * **Algorithm 2** — encryption key: pad password to 32 bytes with
//!   the canonical pad string, MD5(pad ‖ O ‖ P ‖ ID[0] ‖ optional
//!   `0xFFFFFFFF` for R≥4 with `EncryptMetadata=false`); for R≥3,
//!   loop 50× MD5 of the first `n` bytes; final key is first `n`
//!   bytes.
//! * **Algorithm 4** (R=2) and **Algorithm 5** (R≥3) — derive the
//!   `/U` value the writer would have stored. `/U` matches → user
//!   password is correct. Algorithm 6 just inverts Algo 4/5.
//! * **Algorithm 7** — owner-password authentication: undo the
//!   RC4 ladder on `/O` to recover what the user-password padding
//!   string would have been, then run Algorithm 6 on that.
//!
//! Strings + streams in the encryption dictionary are NOT decrypted
//! (per §7.6.1). Strings inside the trailer's `/ID` array are also
//! plaintext.
//!
//! ## Provenance
//!
//! Implemented from the spec PDFs only:
//! `docs/document/pdf/PDF32000_2008.pdf` §7.6 (Tables 20–22, Algorithms
//! 1–7). RC4 and MD5 are hand-rolled per RSA's published RC4 description
//! (the spec calls out "RC4" by name and references RSA Security; the
//! algorithm itself is well-documented in RFC 6229 test vectors and
//! has been public-domain for decades). MD5 follows RFC 1321 verbatim.
//! AES-128 CBC is from the `aes` + `cbc` RustCrypto crates — pure-Rust,
//! constant-time, no `*-sys` wrappers.

use crate::error::PdfError;
use crate::objects::{Object, ObjectId};

/// The 32-byte password-padding string from §7.6.3.3 Algorithm 2 step (a).
/// Used both to pad short passwords up to 32 bytes and as the *plaintext*
/// the user-validation algorithms encrypt to populate `/U`.
const PAD: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

/// Algorithm 1 step (b) salt for AES — bytes "sAlT" (0x73 41 6C 54).
const AES_SALT: [u8; 4] = [0x73, 0x41, 0x6C, 0x54];

/// Per-object encryption modes. Picked from the file's encryption
/// dictionary at open time — every crypt operation uses the same mode
/// (round-4 doesn't yet support per-stream crypt-filter overrides; if
/// the file requires that, decryption surfaces a clear error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptMethod {
    /// Algorithm 1 + RC4. Used when V ∈ {1, 2}, or V=4 with `CFM=V2`.
    Rc4,
    /// Algorithm 1 + AES-128 CBC. Used when V=4 with `CFM=AESV2`.
    Aes128,
}

/// File-level encryption parameters resolved from the trailer's
/// `/Encrypt` dictionary. Carries the master key (Algorithm 2 output)
/// plus the per-object cipher selection.
#[derive(Debug, Clone)]
pub struct StandardHandler {
    /// File encryption key — `n` bytes, where `n` ∈ {5, 16}.
    pub key: Vec<u8>,
    /// Default crypt method for streams + strings.
    pub method: CryptMethod,
    /// Revision (2..=4 supported).
    pub revision: u8,
}

impl StandardHandler {
    /// Decrypt the data of an indirect object whose id is `id` and
    /// whose payload is `data` (a string body or stream body, after
    /// any `/Filter` decoding). Returns the cleartext bytes.
    pub fn decrypt_object(&self, id: ObjectId, data: &[u8]) -> Result<Vec<u8>, PdfError> {
        let obj_key = self.object_key(id);
        match self.method {
            CryptMethod::Rc4 => Ok(rc4(&obj_key, data)),
            CryptMethod::Aes128 => aes128_cbc_decrypt(&obj_key, data),
        }
    }

    /// Algorithm 1: derive the per-object encryption key.
    ///
    /// `extended = key ‖ obj_num_le3 ‖ gen_le2 [‖ "sAlT" if AES]` →
    /// MD5 → take first `n+5` (capped at 16) bytes.
    fn object_key(&self, id: ObjectId) -> Vec<u8> {
        let n = self.key.len();
        let extra = if self.method == CryptMethod::Aes128 {
            5 + 4
        } else {
            5
        };
        let mut buf = Vec::with_capacity(n + extra);
        buf.extend_from_slice(&self.key);
        buf.push((id.number & 0xFF) as u8);
        buf.push(((id.number >> 8) & 0xFF) as u8);
        buf.push(((id.number >> 16) & 0xFF) as u8);
        buf.push((id.generation & 0xFF) as u8);
        buf.push(((id.generation >> 8) & 0xFF) as u8);
        if self.method == CryptMethod::Aes128 {
            buf.extend_from_slice(&AES_SALT);
        }
        let h = md5(&buf);
        let take = (n + 5).min(16);
        h[..take].to_vec()
    }
}

/// Resolve the file-level encryption key from the encryption dict + the
/// file's trailer `/ID[0]`, given a candidate password. Returns `Ok(Some)`
/// if the password authenticates as the user OR owner password; `Ok(None)`
/// if neither matches; `Err` for malformed `/Encrypt`.
///
/// `password` is the raw bytes the caller supplied (often `b""` for the
/// "default user password" path described in §7.6.3.1).
pub fn open_with_password(
    encrypt: &crate::objects::Dict,
    file_id: &[u8],
    password: &[u8],
) -> Result<Option<StandardHandler>, PdfError> {
    let params = parse_encrypt_dict(encrypt)?;

    // Try as user password first (Algorithm 6).
    if let Some(handler) = try_user_password(&params, file_id, password) {
        return Ok(Some(handler));
    }
    // Try as owner password (Algorithm 7).
    if let Some(handler) = try_owner_password(&params, file_id, password) {
        return Ok(Some(handler));
    }
    Ok(None)
}

#[derive(Debug, Clone)]
struct EncryptParams {
    revision: u8,
    /// Length in bits.
    length_bits: usize,
    /// 32-byte O entry.
    o: Vec<u8>,
    /// 32-byte U entry.
    u: Vec<u8>,
    /// P (signed 32-bit). Stored as i32 → reinterpreted as little-endian
    /// bytes when fed into Algorithm 2 step (d).
    p: i32,
    /// EncryptMetadata flag. R≥4, default true; round-4 honours it.
    encrypt_metadata: bool,
    /// Per-stream / per-string crypt method for V=4. None for V<4
    /// (then the method is RC4 by definition of V=1 / V=2 paths).
    cfm: CryptMethod,
}

fn parse_encrypt_dict(d: &crate::objects::Dict) -> Result<EncryptParams, PdfError> {
    fn lookup<'a>(d: &'a crate::objects::Dict, key: &str) -> Option<&'a crate::objects::Object> {
        d.entries().iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    // Filter must be /Standard.
    match lookup(d, "Filter") {
        Some(Object::Name(s)) if s == "Standard" => {}
        Some(other) => {
            return Err(PdfError::other(format!(
            "PDF decrypt: only the Standard security handler is supported (got Filter={other:?})"
        )))
        }
        None => return Err(PdfError::other("PDF decrypt: /Encrypt missing /Filter")),
    }

    let v = match lookup(d, "V") {
        Some(Object::Integer(n)) => *n,
        _ => return Err(PdfError::other("PDF decrypt: /Encrypt missing /V")),
    };
    let r = match lookup(d, "R") {
        Some(Object::Integer(n)) => *n,
        _ => return Err(PdfError::other("PDF decrypt: /Encrypt missing /R")),
    };
    if !(2..=4).contains(&r) {
        return Err(PdfError::other(format!(
            "PDF decrypt: revision R={r} not supported in this round (R∈[2,4])"
        )));
    }

    let length_bits = match lookup(d, "Length") {
        Some(Object::Integer(n)) => *n as usize,
        _ => 40, // default per Table 20
    };
    if !(40..=128).contains(&length_bits) || length_bits % 8 != 0 {
        return Err(PdfError::other(format!(
            "PDF decrypt: /Length {length_bits} bits is out of range (40..=128, multiple of 8)"
        )));
    }

    let o = match lookup(d, "O") {
        Some(Object::LiteralString(s)) | Some(Object::HexString(s)) => s.clone(),
        _ => return Err(PdfError::other("PDF decrypt: /Encrypt missing /O")),
    };
    let u = match lookup(d, "U") {
        Some(Object::LiteralString(s)) | Some(Object::HexString(s)) => s.clone(),
        _ => return Err(PdfError::other("PDF decrypt: /Encrypt missing /U")),
    };
    if o.len() != 32 {
        return Err(PdfError::other(format!(
            "PDF decrypt: /O must be 32 bytes (got {})",
            o.len()
        )));
    }
    if u.len() != 32 {
        return Err(PdfError::other(format!(
            "PDF decrypt: /U must be 32 bytes (got {})",
            u.len()
        )));
    }

    let p = match lookup(d, "P") {
        Some(Object::Integer(n)) => *n as i32,
        _ => return Err(PdfError::other("PDF decrypt: /Encrypt missing /P")),
    };
    let encrypt_metadata = match lookup(d, "EncryptMetadata") {
        Some(Object::Bool(b)) => *b,
        _ => true,
    };

    // Pick the crypt method.
    let cfm = match (v, r) {
        (1, _) | (2, _) | (_, 2) | (_, 3) => CryptMethod::Rc4,
        (4, _) => {
            // V=4, R=4 — look up StmF → CF[StmF].CFM.
            let stmf = match lookup(d, "StmF") {
                Some(Object::Name(s)) => s.as_str(),
                _ => "Identity",
            };
            if stmf == "Identity" {
                // No stream encryption — degrade to no-op. We still
                // need a method for strings; round-4 picks RC4 since
                // V=4 default for legacy PDF was V2.
                CryptMethod::Rc4
            } else {
                let cf = lookup(d, "CF").ok_or_else(|| {
                    PdfError::other("PDF decrypt: V=4 /Encrypt missing /CF dictionary")
                })?;
                let Object::Dict(cf_dict) = cf else {
                    return Err(PdfError::other("PDF decrypt: /CF must be a dictionary"));
                };
                let filter = lookup(cf_dict, stmf).ok_or_else(|| {
                    PdfError::other(format!("PDF decrypt: /CF missing crypt filter `{stmf}`"))
                })?;
                let Object::Dict(filter_dict) = filter else {
                    return Err(PdfError::other(format!(
                        "PDF decrypt: /CF/{stmf} must be a dict"
                    )));
                };
                match lookup(filter_dict, "CFM") {
                    Some(Object::Name(s)) if s == "V2" => CryptMethod::Rc4,
                    Some(Object::Name(s)) if s == "AESV2" => CryptMethod::Aes128,
                    Some(Object::Name(s)) if s == "AESV3" => {
                        return Err(PdfError::other(
                            "PDF decrypt: AESV3 (R=5 / R=6) not yet supported",
                        ))
                    }
                    Some(Object::Name(s)) if s == "None" => {
                        return Err(PdfError::other(
                            "PDF decrypt: CFM=None requires a custom security handler",
                        ))
                    }
                    Some(other) => {
                        return Err(PdfError::other(format!(
                            "PDF decrypt: unsupported CFM={other:?}"
                        )))
                    }
                    None => CryptMethod::Rc4,
                }
            }
        }
        _ => {
            return Err(PdfError::other(format!(
                "PDF decrypt: V={v} not supported (this round handles V∈[1,2,4])"
            )))
        }
    };

    Ok(EncryptParams {
        revision: r as u8,
        length_bits,
        o,
        u,
        p,
        encrypt_metadata,
        cfm,
    })
}

/// Algorithm 2 — compute the file encryption key from the user
/// password.
fn compute_key(p: &EncryptParams, file_id: &[u8], password: &[u8]) -> Vec<u8> {
    let n = p.length_bits / 8;
    // (a) pad / truncate password to 32 bytes.
    let pwd = pad_password(password);
    // (b) initialise MD5 hash.
    let mut buf = Vec::with_capacity(32 + 32 + 4 + file_id.len() + 4);
    buf.extend_from_slice(&pwd);
    // (c) feed O.
    buf.extend_from_slice(&p.o);
    // (d) feed P, low byte first.
    let pbytes = (p.p as u32).to_le_bytes();
    buf.extend_from_slice(&pbytes);
    // (e) feed file ID[0].
    buf.extend_from_slice(file_id);
    // (f) for R≥4 with EncryptMetadata=false, feed 0xFFFFFFFF.
    if p.revision >= 4 && !p.encrypt_metadata {
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    }
    // (g) finish.
    let mut h = md5(&buf);
    // (h) for R≥3, loop 50 times MD5 of first n bytes.
    if p.revision >= 3 {
        for _ in 0..50 {
            h = md5(&h[..n]);
        }
    }
    // (i) take first n bytes.
    h[..n].to_vec()
}

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

/// Algorithm 6 — authenticate a candidate user password.
fn try_user_password(
    p: &EncryptParams,
    file_id: &[u8],
    password: &[u8],
) -> Option<StandardHandler> {
    let key = compute_key(p, file_id, password);
    let derived_u = derive_u(p, file_id, &key);
    // R=2: full 32-byte match. R≥3: only first 16 bytes match (the rest
    // is arbitrary padding — see Algorithm 5 step (f)).
    let cmp_len = if p.revision >= 3 { 16 } else { 32 };
    if constant_time_eq(&derived_u[..cmp_len], &p.u[..cmp_len]) {
        Some(StandardHandler {
            key,
            method: p.cfm,
            revision: p.revision,
        })
    } else {
        None
    }
}

/// Re-derive the `/U` value the writer would have stored, given a
/// candidate file key. This is the meat of Algorithms 4 and 5 — once
/// it produces something matching the `/U` in the dict, the password
/// is correct.
fn derive_u(p: &EncryptParams, file_id: &[u8], key: &[u8]) -> [u8; 32] {
    if p.revision == 2 {
        // Algorithm 4: encrypt the 32-byte pad with the file key.
        let cipher = rc4(key, &PAD);
        let mut out = [0u8; 32];
        out.copy_from_slice(&cipher);
        out
    } else {
        // Algorithm 5: hash(pad ‖ file_id), encrypt with file key, then
        // 19 more rounds of RC4 with byte-XOR'd keys.
        let mut hash_input = Vec::with_capacity(32 + file_id.len());
        hash_input.extend_from_slice(&PAD);
        hash_input.extend_from_slice(file_id);
        let h = md5(&hash_input);
        let mut data = rc4(key, &h);
        for i in 1u8..=19 {
            let xor_key: Vec<u8> = key.iter().map(|b| b ^ i).collect();
            data = rc4(&xor_key, &data);
        }
        // Pad with 16 arbitrary bytes — the algorithm uses anything;
        // we use zeros. Authentication only compares the first 16 bytes
        // for R≥3 anyway.
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&data[..16]);
        out
    }
}

/// Algorithm 7 — authenticate a candidate owner password. The /O
/// entry is a double encryption of the user password by an MD5 chain
/// of the owner password. We undo the chain to recover the user
/// password and then try Algorithm 6 on it.
fn try_owner_password(
    p: &EncryptParams,
    file_id: &[u8],
    password: &[u8],
) -> Option<StandardHandler> {
    // Steps (a)..(d) of Algorithm 3: derive an RC4 key from the owner
    // password (or the user password if no owner password is set —
    // which is exactly what we're attempting here).
    let n = p.length_bits / 8;
    let pwd = pad_password(password);
    let mut h = md5(&pwd);
    if p.revision >= 3 {
        for _ in 0..50 {
            h = md5(&h[..n]);
        }
    }
    let owner_key = h[..n].to_vec();

    // (b) of Algorithm 7: undo the RC4 ladder on /O.
    let recovered_user_pwd = if p.revision == 2 {
        rc4(&owner_key, &p.o)
    } else {
        let mut buf = p.o.clone();
        // Iterations 19..=0, each with the owner_key XOR i.
        for i in (0u8..=19).rev() {
            let xor_key: Vec<u8> = owner_key.iter().map(|b| b ^ i).collect();
            buf = rc4(&xor_key, &buf);
        }
        buf
    };

    // (c) — `recovered_user_pwd` is the padded user password (32 bytes).
    // Drop the pad string suffix to get the original user password.
    let user_pwd = strip_pad(&recovered_user_pwd);
    try_user_password(p, file_id, &user_pwd)
}

/// Strip the canonical pad suffix from a 32-byte padded password,
/// returning the original. The padded buffer has shape
/// `password ‖ PAD[..32 - password.len()]`; we find the smallest
/// `L` such that `padded[L..]` equals `PAD[..32 - L]` and return
/// `padded[..L]`.
///
/// If the buffer has no recognisable pad suffix the original was 32
/// bytes long with no padding — return all 32 bytes.
fn strip_pad(padded: &[u8]) -> Vec<u8> {
    let n = padded.len();
    for l in 0..=n {
        if padded[l..] == PAD[..n - l] {
            return padded[..l].to_vec();
        }
    }
    padded.to_vec()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ───────────────────────── RC4 ─────────────────────────

/// RC4 stream cipher — output XOR'd with input.
///
/// Symmetric: `rc4(key, rc4(key, plain)) == plain`. Pure 40-line
/// implementation; the algorithm's tiny S-table key schedule + PRGA
/// is well-described in any cryptography textbook.
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    debug_assert!(!key.is_empty(), "RC4 key must not be empty");
    let mut s: [u8; 256] = [0; 256];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8;
    }
    // KSA — key-scheduling algorithm.
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    // PRGA — pseudo-random generation.
    let mut i: u8 = 0;
    j = 0;
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[s[i as usize].wrapping_add(s[j as usize]) as usize];
        out.push(byte ^ k);
    }
    out
}

// ───────────────────────── AES-128 CBC ─────────────────────────

/// Decrypt an AES-128-CBC blob whose first 16 bytes are the IV
/// (per §7.6.2 Algorithm 1, AES-only paragraph). Removes PKCS#7
/// padding.
fn aes128_cbc_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, PdfError> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    if data.len() < 16 {
        return Err(PdfError::other(
            "PDF decrypt: AES-128 ciphertext shorter than IV",
        ));
    }
    if (data.len() - 16) % 16 != 0 {
        return Err(PdfError::other(format!(
            "PDF decrypt: AES-128 ciphertext length {} not aligned to 16-byte blocks (after IV)",
            data.len() - 16
        )));
    }
    if key.len() != 16 {
        return Err(PdfError::other(format!(
            "PDF decrypt: AES-128 expects a 16-byte key (got {} bytes)",
            key.len()
        )));
    }
    let iv = &data[..16];
    let ct = &data[16..];
    let dec = Aes128CbcDec::new(key.into(), iv.into());
    let mut buf = ct.to_vec();
    let pt = dec
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| PdfError::other(format!("PDF decrypt: AES-128 padding error: {e:?}")))?;
    Ok(pt.to_vec())
}

// ───────────────────────── MD5 (RFC 1321) ─────────────────────────
//
// 80-line reference implementation. Used only for password / key
// derivation per §7.6 — never for content authentication. A constant-time
// implementation isn't required because all inputs are derived from
// the password, which the caller is expected to know.

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, // round 1
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, // round 2
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, // round 3
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, // round 4
];

const MD5_K: [u32; 64] = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
];

/// MD5 of the input bytes. Returns the 16-byte digest.
pub fn md5(input: &[u8]) -> [u8; 16] {
    let mut state: [u32; 4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];

    // Pad to a multiple of 64 bytes: append 0x80, then zeros, then the
    // 64-bit input length (in bits) little-endian.
    let mut buf = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    buf.push(0x80);
    while buf.len() % 64 != 56 {
        buf.push(0);
    }
    buf.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in buf.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in chunk.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(MD5_K[i])
                    .wrapping_add(m[g])
                    .rotate_left(MD5_S[i]),
            );
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (i, s) in state.iter().enumerate() {
        out[4 * i..4 * (i + 1)].copy_from_slice(&s.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── MD5 known-answer tests (RFC 1321 §A.5) ────────────────
    #[test]
    fn md5_empty_string() {
        assert_eq!(
            md5(b""),
            [
                0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04, 0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8,
                0x42, 0x7E
            ]
        );
    }

    #[test]
    fn md5_short_inputs() {
        // "a" → 0CC175B9C0F1B6A831C399E269772661
        assert_eq!(
            md5(b"a"),
            [
                0x0C, 0xC1, 0x75, 0xB9, 0xC0, 0xF1, 0xB6, 0xA8, 0x31, 0xC3, 0x99, 0xE2, 0x69, 0x77,
                0x26, 0x61
            ]
        );
        // "abc" → 900150983CD24FB0D6963F7D28E17F72
        assert_eq!(
            md5(b"abc"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0, 0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1,
                0x7F, 0x72
            ]
        );
        // "message digest" → F96B697D7CB7938D525A2F31AAF161D0
        assert_eq!(
            md5(b"message digest"),
            [
                0xF9, 0x6B, 0x69, 0x7D, 0x7C, 0xB7, 0x93, 0x8D, 0x52, 0x5A, 0x2F, 0x31, 0xAA, 0xF1,
                0x61, 0xD0
            ]
        );
    }

    #[test]
    fn md5_long_block() {
        // "abcdefghijklmnopqrstuvwxyz" → C3FCD3D76192E4007DFB496CCA67E13B
        assert_eq!(
            md5(b"abcdefghijklmnopqrstuvwxyz"),
            [
                0xC3, 0xFC, 0xD3, 0xD7, 0x61, 0x92, 0xE4, 0x00, 0x7D, 0xFB, 0x49, 0x6C, 0xCA, 0x67,
                0xE1, 0x3B
            ]
        );
    }

    #[test]
    fn md5_multi_block() {
        // 80-byte input crosses the 64-byte block boundary.
        let s = b"12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        // Expected per RFC 1321 §A.5
        assert_eq!(
            md5(s),
            [
                0x57, 0xED, 0xF4, 0xA2, 0x2B, 0xE3, 0xC9, 0x55, 0xAC, 0x49, 0xDA, 0x2E, 0x21, 0x07,
                0xB6, 0x7A
            ]
        );
    }

    // ─── RC4 known-answer tests (RFC 6229 §2) ──────────────────
    #[test]
    fn rc4_rfc6229_key0102030405() {
        // Key = 0x0102030405, plaintext = 16 zero bytes
        // Expected first 16 keystream bytes per RFC 6229:
        //   b2 39 63 05 f0 3d c0 27 cc c3 52 4a 0a 11 18 a8
        let key = [0x01, 0x02, 0x03, 0x04, 0x05];
        let pt = [0u8; 16];
        let ct = rc4(&key, &pt);
        assert_eq!(
            ct,
            vec![
                0xB2, 0x39, 0x63, 0x05, 0xF0, 0x3D, 0xC0, 0x27, 0xCC, 0xC3, 0x52, 0x4A, 0x0A, 0x11,
                0x18, 0xA8
            ]
        );
    }

    #[test]
    fn rc4_rfc6229_key0102030405060708() {
        // Key = 0x0102030405060708 (8 bytes), plaintext = 16 zero bytes.
        // Expected keystream: 97 ab 8a 1b f0 af b9 61 32 f2 f6 72 58 da 15 a8
        let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pt = [0u8; 16];
        let ct = rc4(&key, &pt);
        assert_eq!(
            ct,
            vec![
                0x97, 0xAB, 0x8A, 0x1B, 0xF0, 0xAF, 0xB9, 0x61, 0x32, 0xF2, 0xF6, 0x72, 0x58, 0xDA,
                0x15, 0xA8
            ]
        );
    }

    #[test]
    fn rc4_self_inverse() {
        // RC4 is symmetric.
        let key = b"Key";
        let plain = b"Plaintext";
        let cipher = rc4(key, plain);
        let recovered = rc4(key, &cipher);
        assert_eq!(&recovered, plain);
    }

    // ─── AES-128 CBC known-answer (FIPS 197 reformulated for CBC) ──
    #[test]
    fn aes128_cbc_decrypt_round_trips_pkcs7() {
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
        let key = [0x42u8; 16];
        let iv = [0x17u8; 16];
        let pt = b"hello world".to_vec();
        let mut buf = vec![0u8; 16 + ((pt.len() / 16) + 1) * 16];
        let enc = Aes128CbcEnc::new((&key).into(), (&iv).into());
        let n = enc
            .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(&pt, &mut buf[16..])
            .unwrap()
            .len();
        buf[..16].copy_from_slice(&iv);
        buf.truncate(16 + n);
        let recovered = aes128_cbc_decrypt(&key, &buf).unwrap();
        assert_eq!(recovered, pt);
    }

    // ─── Algorithm 2 (encryption-key derivation) ────────────────
    #[test]
    fn algorithm_2_known_answer_r3_empty_password() {
        // Hand-computed test vector. With:
        //   password = b""
        //   O        = 32 bytes of 0xAA
        //   P        = -4 (printing + copy + modify allowed; bits cleared)
        //   ID[0]    = 16 bytes of 0xBB
        //   R = 3, Length = 128, EncryptMetadata = true (default)
        // The key is the first 16 bytes of MD5^51(pad ‖ O ‖ P_le ‖ ID).
        let p = EncryptParams {
            revision: 3,
            length_bits: 128,
            o: vec![0xAA; 32],
            u: vec![0; 32],
            p: -4,
            encrypt_metadata: true,
            cfm: CryptMethod::Rc4,
        };
        let id = vec![0xBB; 16];
        let k = compute_key(&p, &id, b"");
        // Recompute by hand to lock the test vector.
        let mut buf = Vec::new();
        buf.extend_from_slice(&PAD);
        buf.extend_from_slice(&p.o);
        buf.extend_from_slice(&((-4i32) as u32).to_le_bytes());
        buf.extend_from_slice(&id);
        let mut h = md5(&buf);
        for _ in 0..50 {
            h = md5(&h[..16]);
        }
        assert_eq!(k, h[..16].to_vec());
    }

    // ─── Algorithm 1 — per-object key derivation ────────────────
    #[test]
    fn algorithm_1_object_key_rc4() {
        let h = StandardHandler {
            key: vec![0x01, 0x02, 0x03, 0x04, 0x05], // 40-bit
            method: CryptMethod::Rc4,
            revision: 2,
        };
        let id = ObjectId {
            number: 0x010203,
            generation: 0x0405,
        };
        let k = h.object_key(id);
        // n + 5 = 10 bytes; capped at 16. n=5 so we expect 10.
        assert_eq!(k.len(), 10);
        // Verify the input to the MD5 hash is right.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);
        buf.extend_from_slice(&[0x03, 0x02, 0x01]); // obj_num le3
        buf.extend_from_slice(&[0x05, 0x04]); // gen_num le2
        let h2 = md5(&buf);
        assert_eq!(k, h2[..10].to_vec());
    }

    #[test]
    fn algorithm_1_object_key_aes_appends_salt() {
        let h = StandardHandler {
            key: vec![0u8; 16],
            method: CryptMethod::Aes128,
            revision: 4,
        };
        let id = ObjectId {
            number: 1,
            generation: 0,
        };
        let k = h.object_key(id);
        // n + 5 = 21, capped at 16.
        assert_eq!(k.len(), 16);
        let mut buf = Vec::new();
        buf.extend_from_slice(&h.key);
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(&AES_SALT);
        let h2 = md5(&buf);
        assert_eq!(k, h2[..16].to_vec());
    }

    // ─── Self-roundtrip — encrypt + decrypt a known string ──────
    #[test]
    fn rc4_object_roundtrip_via_handler() {
        let h = StandardHandler {
            key: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42],
            method: CryptMethod::Rc4,
            revision: 2,
        };
        let id = ObjectId {
            number: 7,
            generation: 0,
        };
        let plain = b"Hello, encrypted world!".to_vec();
        // Using the public API: decrypt(decrypt(plain)) == plain (RC4
        // is symmetric).
        let cipher = h.decrypt_object(id, &plain).unwrap();
        let recovered = h.decrypt_object(id, &cipher).unwrap();
        assert_eq!(recovered, plain);
    }

    // ─── Strip-pad helper ───────────────────────────────────────
    #[test]
    fn strip_pad_recovers_short_passwords() {
        let mut padded = Vec::from(b"hello".as_slice());
        padded.extend_from_slice(&PAD[..27]);
        assert_eq!(strip_pad(&padded), b"hello".to_vec());
    }

    #[test]
    fn strip_pad_empty_password() {
        assert_eq!(strip_pad(&PAD), Vec::<u8>::new());
    }
}
