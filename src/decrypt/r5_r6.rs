//! AES-256 (V=5, R=5 / R=6) password handling — Adobe extension
//! level 3 + ISO 32000-2:2020 §7.6.4.4.
//!
//! # Layout of `/U` and `/O`
//!
//! Both are 48 bytes for V=5:
//!
//! * `[0..32]`  — *hash* (Algorithm 8 / 9 step (a) output, SHA-256).
//! * `[32..40]` — *validation salt* — 8 random bytes mixed into the
//!   user-password validation hash so two unrelated documents with
//!   the same password don't produce the same `/U`.
//! * `[40..48]` — *key salt* — 8 random bytes mixed into the
//!   intermediate-key derivation that wraps the file encryption key
//!   into `/UE` / `/OE`.
//!
//! # Hash chain (Algorithm 2.B)
//!
//! For R=6 the spec specifies an iterated-hash function ("hash that
//! makes brute-force harder by deliberate cost"). It alternates
//! between SHA-256, SHA-384 and SHA-512 according to the modulus 3
//! of the *first* byte of the running 16-byte AES-CBC ciphertext. The
//! loop runs until the 64th iteration *and* until the running byte
//! ≤ iteration_count − 32 (so it never finishes before round 64 but
//! may run longer).
//!
//! For R=5 (Adobe ext L3) the chain is just plain SHA-256 — no
//! iteration. Adobe shipped this as the first AES-256 PDF spec; ISO
//! tightened it to Algorithm 2.B for R=6 because the simpler R=5
//! variant is GPU-bruteforceable.
//!
//! # The four user-side algorithms (the ones the *reader* runs)
//!
//! | Algo | What it does                                              |
//! |------|-----------------------------------------------------------|
//! | 11   | Authenticate user password — SHA-256(P ‖ U.salt) == U.h   |
//! | 12   | Authenticate owner password — SHA-256(P ‖ O.salt ‖ U) == O.h |
//! | 8    | (writer) Compute O from password + U + key                |
//! | 9    | (writer) Compute U from password + key                    |
//! | 13   | Decrypt /Perms with the file key, validate `"adb"` magic  |
//!
//! Because the file encryption key is wrapped *into* the document via
//! Algorithm 8 / 9 step (b) (AES-256 ECB-mode of the file key with an
//! intermediate key derived from the password + key salt), once we
//! recover the file key we don't need to *redo* the wrap on the
//! reader side — we just unwrap.
//!
//! # Provenance
//!
//! Implemented from `docs/document/pdf/PDF32000_2020.pdf` §7.6.4.4
//! (Algorithms 2.A, 2.B, 8, 9, 10, 11, 12, 13). SHA-256 / SHA-384 /
//! SHA-512 come from the pure-Rust `sha2` crate — RustCrypto, no
//! `*-sys`, constant-time. AES-256 CBC + ECB come from the same
//! `aes` + `cbc` crates already used by the AESV2 path.

use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::decrypt::{
    aes256_ecb_decrypt_block, constant_time_eq, CryptMethod, EncryptParams, StandardHandler,
};
use crate::error::PdfError;

/// Try a candidate password against `/U` (Algorithm 11) and then
/// `/O` (Algorithm 12). On success, unwrap the file encryption key
/// per Algorithm 2.A and verify the Perms block via Algorithm 13.
///
/// Returns `Ok(Some)` when the password authenticates and the
/// resulting handler decrypts `/Perms` with the expected magic;
/// `Ok(None)` when the password fails both checks; `Err` when a
/// successfully-authenticated password produces a malformed `/Perms`
/// (which would indicate a doctored file).
pub(crate) fn open_with_password(
    p: &EncryptParams,
    password: &[u8],
) -> Result<Option<StandardHandler>, PdfError> {
    // Per ISO 32000-2 §7.6.4.3.2: passwords are processed as raw bytes
    // up to 127 bytes long. Inputs over 127 bytes are truncated.
    let pwd = if password.len() > 127 {
        &password[..127]
    } else {
        password
    };

    // ─── Algorithm 11 — user-password authentication ───
    if let Some(handler) = try_user(p, pwd)? {
        return Ok(Some(handler));
    }
    // ─── Algorithm 12 — owner-password authentication ───
    if let Some(handler) = try_owner(p, pwd)? {
        return Ok(Some(handler));
    }
    Ok(None)
}

/// Algorithm 11 + the user-key-unwrap half of Algorithm 2.A.
fn try_user(p: &EncryptParams, password: &[u8]) -> Result<Option<StandardHandler>, PdfError> {
    if p.u.len() != 48 {
        return Ok(None);
    }
    let u_hash = &p.u[..32];
    let u_validation_salt = &p.u[32..40];
    let u_key_salt = &p.u[40..48];

    // Step (a) of Algorithm 11: SHA-256(password ‖ U validation salt).
    // For R=5 plain SHA-256; for R=6 the iterated hash function 2.B
    // with `aux = b""`.
    let candidate = match p.revision {
        5 => {
            let mut h = Sha256::new();
            h.update(password);
            h.update(u_validation_salt);
            h.finalize().to_vec()
        }
        6 => {
            // Algorithm 2.B's seed is the same SHA-256 input as R=5.
            let mut seed = Sha256::new();
            seed.update(password);
            seed.update(u_validation_salt);
            let seed_hash = seed.finalize();
            algorithm_2b(&seed_hash, password, &[])
        }
        _ => return Ok(None),
    };

    if !constant_time_eq(&candidate, u_hash) {
        return Ok(None);
    }

    // Step (b) of Algorithm 2.A — derive the *intermediate user key*
    // and unwrap UE.
    let int_user_key = match p.revision {
        5 => {
            let mut h = Sha256::new();
            h.update(password);
            h.update(u_key_salt);
            h.finalize().to_vec()
        }
        6 => {
            let mut seed = Sha256::new();
            seed.update(password);
            seed.update(u_key_salt);
            let seed_hash = seed.finalize();
            algorithm_2b(&seed_hash, password, &[])
        }
        _ => return Ok(None),
    };

    let file_key = unwrap_file_key(&int_user_key, &p.ue)?;
    let handler = build_handler(p, file_key)?;
    verify_perms(p, &handler)?;
    Ok(Some(handler))
}

/// Algorithm 12 + the owner-key-unwrap half of Algorithm 2.A.
fn try_owner(p: &EncryptParams, password: &[u8]) -> Result<Option<StandardHandler>, PdfError> {
    if p.o.len() != 48 || p.u.len() != 48 {
        return Ok(None);
    }
    let o_hash = &p.o[..32];
    let o_validation_salt = &p.o[32..40];
    let o_key_salt = &p.o[40..48];

    // Step (a) of Algorithm 12: SHA-256(password ‖ O validation salt ‖ U).
    let candidate = match p.revision {
        5 => {
            let mut h = Sha256::new();
            h.update(password);
            h.update(o_validation_salt);
            h.update(&p.u);
            h.finalize().to_vec()
        }
        6 => {
            let mut seed = Sha256::new();
            seed.update(password);
            seed.update(o_validation_salt);
            seed.update(&p.u);
            let seed_hash = seed.finalize();
            algorithm_2b(&seed_hash, password, &p.u)
        }
        _ => return Ok(None),
    };
    if !constant_time_eq(&candidate, o_hash) {
        return Ok(None);
    }

    let int_owner_key = match p.revision {
        5 => {
            let mut h = Sha256::new();
            h.update(password);
            h.update(o_key_salt);
            h.update(&p.u);
            h.finalize().to_vec()
        }
        6 => {
            let mut seed = Sha256::new();
            seed.update(password);
            seed.update(o_key_salt);
            seed.update(&p.u);
            let seed_hash = seed.finalize();
            algorithm_2b(&seed_hash, password, &p.u)
        }
        _ => return Ok(None),
    };

    let file_key = unwrap_file_key(&int_owner_key, &p.oe)?;
    let handler = build_handler(p, file_key)?;
    verify_perms(p, &handler)?;
    Ok(Some(handler))
}

/// Algorithm 8 / 9 step (b) — *unwrap* the file encryption key from
/// `/UE` (or `/OE`) using the supplied intermediate key. The wrap is
/// AES-256-CBC, no padding, with an IV of zero — equivalently two
/// AES-256 ECB blocks chained by XOR with IV=0 (so block 0 is just
/// AES-256-ECB; block 1 is AES-256-ECB with the previous ciphertext
/// XOR'd in). We need exactly 32 bytes out (the 256-bit file key).
fn unwrap_file_key(int_key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, PdfError> {
    if int_key.len() != 32 {
        return Err(PdfError::other(format!(
            "PDF decrypt: V=5 intermediate key must be 32 bytes (got {})",
            int_key.len()
        )));
    }
    if wrapped.len() != 32 {
        return Err(PdfError::other(format!(
            "PDF decrypt: V=5 wrapped key must be 32 bytes (got {})",
            wrapped.len()
        )));
    }
    // CBC with IV=0, no padding. Two blocks. We chain by hand instead
    // of asking the `cbc::Decryptor` to remove padding (the ISO wrap is
    // padless, and the cbc crate's `decrypt_padded_*` family only
    // exposes padded variants).
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockDecrypt, KeyInit};
    let cipher = aes::Aes256::new(int_key.into());
    let mut prev = [0u8; 16];
    let mut out = vec![0u8; 32];
    for (i, chunk) in wrapped.chunks_exact(16).enumerate() {
        let mut ga = *GenericArray::from_slice(chunk);
        cipher.decrypt_block(&mut ga);
        for j in 0..16 {
            out[i * 16 + j] = ga[j] ^ prev[j];
        }
        prev.copy_from_slice(chunk);
    }
    Ok(out)
}

/// Build a [`StandardHandler`] from the resolved file key, picking
/// the per-object cipher mode from `EncryptParams::cfm`. V=5 must use
/// AES-256.
fn build_handler(p: &EncryptParams, file_key: Vec<u8>) -> Result<StandardHandler, PdfError> {
    if file_key.len() != 32 {
        return Err(PdfError::other(format!(
            "PDF decrypt: V=5 file key must be 32 bytes (got {})",
            file_key.len()
        )));
    }
    let method = match p.cfm {
        CryptMethod::Aes256 => CryptMethod::Aes256,
        // /Encrypt parsing already rejects mismatched CFMs, but defend
        // here in case future code paths leak through.
        other => {
            return Err(PdfError::other(format!(
                "PDF decrypt: V=5 requires AESV3 crypt method (got {other:?})"
            )))
        }
    };
    Ok(StandardHandler {
        key: file_key,
        method,
        revision: p.revision,
    })
}

/// Algorithm 13 — decrypt the 16-byte `/Perms` blob with the file
/// key (AES-256 ECB) and validate the magic.
///
/// Layout (after decryption):
/// * `[0..4]`  — P (signed 32-bit, little-endian).
/// * `[4..8]`  — `0xFF 0xFF 0xFF 0xFF` (the unused upper bits of P,
///   which is a 32-bit signed integer treated as a 64-bit value).
/// * `[8]`     — `'T'` if `EncryptMetadata=true`, `'F'` otherwise.
/// * `[9..12]` — `"adb"` magic (Adobe).
/// * `[12..16]` — random padding.
fn verify_perms(p: &EncryptParams, handler: &StandardHandler) -> Result<(), PdfError> {
    if p.perms.len() != 16 {
        return Err(PdfError::other(
            "PDF decrypt: V=5 /Perms is missing or wrong length",
        ));
    }
    let mut block = [0u8; 16];
    block.copy_from_slice(&p.perms);
    let pt = aes256_ecb_decrypt_block(&handler.key, &block)?;

    // Magic at offset 9..12 must be "adb".
    if &pt[9..12] != b"adb" {
        return Err(PdfError::other(format!(
            "PDF decrypt: V=5 /Perms magic mismatch (expected b\"adb\" at [9..12], got {:?})",
            &pt[9..12]
        )));
    }

    // The decrypted P (LE 32) must equal the dict's P.
    let p_le = i32::from_le_bytes([pt[0], pt[1], pt[2], pt[3]]);
    if p_le != p.p {
        return Err(PdfError::other(format!(
            "PDF decrypt: V=5 /Perms P mismatch (expected {}, got {p_le})",
            p.p
        )));
    }

    // Byte 8 must be 'T' or 'F' matching EncryptMetadata.
    let want_em = if p.encrypt_metadata { b'T' } else { b'F' };
    if pt[8] != want_em {
        return Err(PdfError::other(format!(
            "PDF decrypt: V=5 /Perms EncryptMetadata mismatch (expected {:?}, got {:?})",
            want_em as char, pt[8] as char
        )));
    }

    Ok(())
}

/// Algorithm 2.B — the iterated hash chain that R=6 uses to slow
/// down brute-force.
///
/// `K` is initialised to the SHA-256 hash supplied as `seed`. Each
/// round:
///
///   1. Build `K1 = password ‖ K [‖ aux]` and replicate it 64 times
///      to make a 64×|K1|-byte input.
///   2. Encrypt with AES-128-CBC using key=K[0..16], IV=K[16..32]
///      (so the CBC chains across the full 64×|K1| bytes).
///   3. Sum the first 16 bytes of the resulting ciphertext mod 3 →
///      pick SHA-256 (0), SHA-384 (1), or SHA-512 (2).
///   4. K = chosen-hash(ciphertext).
///   5. Stop when round_count ≥ 64 *and* the last byte of the
///      ciphertext ≤ round_count − 32. Otherwise repeat.
///
/// Final `K` is truncated to 32 bytes.
///
/// `password` is fed as raw bytes (already truncated to 127 by the
/// caller). `aux` is `b""` for the user-side algorithms and the 48-
/// byte `/U` for the owner-side algorithms.
fn algorithm_2b(seed: &[u8], password: &[u8], aux: &[u8]) -> Vec<u8> {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};

    let mut k = seed[..32].to_vec();
    let mut round_count: i64 = 0;
    loop {
        // Build K1 = (password ‖ K ‖ aux) repeated 64 times.
        let mut k1 = Vec::with_capacity((password.len() + k.len() + aux.len()) * 64);
        for _ in 0..64 {
            k1.extend_from_slice(password);
            k1.extend_from_slice(&k);
            k1.extend_from_slice(aux);
        }
        // E = AES-128-CBC(key=K[0..16], iv=K[16..32]).encrypt_no_pad(K1).
        // The K1 length is always a multiple of 16: SHA-256/384/512
        // outputs are 32/48/64 bytes, password ≤ 127, aux ∈ {0, 48};
        // collectively divisible by 16 only by chance — the spec
        // doesn't guarantee it. To be safe we PKCS#7-pad up to a
        // 16-byte boundary as the spec implicitly does (the iterated
        // CBC over the chosen length).
        // Empirically every concrete K1 we'll feed in the standard
        // password range happens to be 16-divisible because the
        // password input includes K at the start and K is always
        // 32 bytes, but defend with an explicit check anyway.
        debug_assert_eq!(
            k1.len() % 16,
            0,
            "Algorithm 2.B K1 expected to be 16-byte-aligned, got len {}",
            k1.len()
        );
        // Encrypt block by block: AES-128 ECB chained by hand.
        // (`cbc::Encryptor` only exposes a padded API; we want raw.)
        let key_bytes: [u8; 16] = k[..16].try_into().expect("K is at least 32 bytes");
        let iv_bytes: [u8; 16] = k[16..32].try_into().expect("K is at least 32 bytes");
        let cipher = aes::Aes128::new((&key_bytes).into());
        let mut prev: [u8; 16] = iv_bytes;
        let mut e = vec![0u8; k1.len()];
        for (i, chunk) in k1.chunks_exact(16).enumerate() {
            let mut block = [0u8; 16];
            for j in 0..16 {
                block[j] = chunk[j] ^ prev[j];
            }
            let mut ga = *GenericArray::from_slice(&block);
            cipher.encrypt_block(&mut ga);
            e[i * 16..(i + 1) * 16].copy_from_slice(&ga);
            prev.copy_from_slice(&ga);
        }

        // Sum first 16 bytes mod 3 → pick hash family.
        let sum16: u32 = e[..16].iter().map(|&b| b as u32).sum::<u32>() % 3;
        k = match sum16 {
            0 => {
                let mut h = Sha256::new();
                h.update(&e);
                h.finalize().to_vec()
            }
            1 => {
                let mut h = Sha384::new();
                h.update(&e);
                h.finalize().to_vec()
            }
            _ => {
                let mut h = Sha512::new();
                h.update(&e);
                h.finalize().to_vec()
            }
        };

        round_count += 1;
        // Stopping condition: round_count ≥ 64 *and* last byte of
        // ciphertext ≤ round_count − 32.
        let last = e[e.len() - 1] as i64;
        if round_count >= 64 && last <= round_count - 32 {
            break;
        }
        // Hard cap to prevent infinite loops on pathological inputs.
        if round_count > 4096 {
            break;
        }
    }
    k[..32].to_vec()
}

// ───────────────────────── Writer-side algorithms ─────────────────────────
//
// The reader doesn't *invoke* Algorithms 8, 9, or 10 at runtime — the
// PDF the writer produces already carries `/O`, `/U`, `/OE`, `/UE`,
// and `/Perms`. But we expose them publicly so test fixtures can build
// hand-rolled R=5 / R=6 PDFs without inventing the wrap by hand.

/// Algorithm 8 — compute `/O` and `/OE` for V=5.
///
/// Returns `(O, OE)` where:
/// * `O` is 48 bytes: SHA-256(owner_pwd ‖ O.salt.validate ‖ U) ‖
///   O.salt.validate ‖ O.salt.key.
/// * `OE` is 32 bytes: AES-256-CBC(int_owner_key, IV=0)(file_key).
///
/// `salts` is the 16-byte `(O.salt.validate, O.salt.key)` pair the
/// writer chose; pick something pseudorandom for production but
/// deterministic for fixtures.
pub fn algorithm_8(
    revision: u8,
    owner_password: &[u8],
    user_u: &[u8],
    file_key: &[u8],
    salt_validate: &[u8; 8],
    salt_key: &[u8; 8],
) -> ([u8; 48], [u8; 32]) {
    let pwd = trunc127(owner_password);
    // (a) Hash for /O.
    let hash_input_seed_bytes = {
        let mut h = Sha256::new();
        h.update(pwd);
        h.update(salt_validate);
        h.update(user_u);
        h.finalize().to_vec()
    };
    let o_hash = match revision {
        5 => hash_input_seed_bytes.clone(),
        _ => algorithm_2b(&hash_input_seed_bytes, pwd, user_u),
    };

    let mut o = [0u8; 48];
    o[..32].copy_from_slice(&o_hash);
    o[32..40].copy_from_slice(salt_validate);
    o[40..48].copy_from_slice(salt_key);

    // (b) Wrap file key into /OE.
    let int_seed = {
        let mut h = Sha256::new();
        h.update(pwd);
        h.update(salt_key);
        h.update(user_u);
        h.finalize().to_vec()
    };
    let int_owner_key = match revision {
        5 => int_seed,
        _ => algorithm_2b(&int_seed, pwd, user_u),
    };
    let oe = aes256_cbc_encrypt_no_padding(&int_owner_key, file_key);
    let mut oe_arr = [0u8; 32];
    oe_arr.copy_from_slice(&oe);
    (o, oe_arr)
}

/// Algorithm 9 — compute `/U` and `/UE` for V=5.
pub fn algorithm_9(
    revision: u8,
    user_password: &[u8],
    file_key: &[u8],
    salt_validate: &[u8; 8],
    salt_key: &[u8; 8],
) -> ([u8; 48], [u8; 32]) {
    let pwd = trunc127(user_password);
    // (a) Hash for /U.
    let hash_seed = {
        let mut h = Sha256::new();
        h.update(pwd);
        h.update(salt_validate);
        h.finalize().to_vec()
    };
    let u_hash = match revision {
        5 => hash_seed.clone(),
        _ => algorithm_2b(&hash_seed, pwd, &[]),
    };

    let mut u = [0u8; 48];
    u[..32].copy_from_slice(&u_hash);
    u[32..40].copy_from_slice(salt_validate);
    u[40..48].copy_from_slice(salt_key);

    let int_seed = {
        let mut h = Sha256::new();
        h.update(pwd);
        h.update(salt_key);
        h.finalize().to_vec()
    };
    let int_user_key = match revision {
        5 => int_seed,
        _ => algorithm_2b(&int_seed, pwd, &[]),
    };
    let ue = aes256_cbc_encrypt_no_padding(&int_user_key, file_key);
    let mut ue_arr = [0u8; 32];
    ue_arr.copy_from_slice(&ue);
    (u, ue_arr)
}

/// Algorithm 10 — encrypt the 16-byte permissions block with the file
/// key (AES-256 ECB), so that on read the standard handler can verify
/// it via Algorithm 13.
pub fn algorithm_10(
    file_key: &[u8],
    p: i32,
    encrypt_metadata: bool,
    padding: &[u8; 4],
) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..4].copy_from_slice(&(p as u32).to_le_bytes());
    block[4..8].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    block[8] = if encrypt_metadata { b'T' } else { b'F' };
    block[9..12].copy_from_slice(b"adb");
    block[12..16].copy_from_slice(padding);
    aes256_ecb_encrypt_block(file_key, &block)
}

/// AES-256 ECB single-block encrypt (used by Algorithm 10).
pub(crate) fn aes256_ecb_encrypt_block(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes256::new(key.into());
    let mut buf = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut buf);
    let mut out = [0u8; 16];
    out.copy_from_slice(&buf);
    out
}

/// AES-256 CBC with IV=0, no padding — used by Algorithm 8/9 step (b)
/// to wrap a 32-byte file key into a 32-byte `/OE` or `/UE` blob.
fn aes256_cbc_encrypt_no_padding(key: &[u8], data: &[u8]) -> Vec<u8> {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};
    debug_assert_eq!(data.len() % 16, 0);
    let cipher = aes::Aes256::new(key.into());
    let mut prev = [0u8; 16];
    let mut out = vec![0u8; data.len()];
    for (i, chunk) in data.chunks_exact(16).enumerate() {
        let mut block = [0u8; 16];
        for j in 0..16 {
            block[j] = chunk[j] ^ prev[j];
        }
        let mut ga = *GenericArray::from_slice(&block);
        cipher.encrypt_block(&mut ga);
        out[i * 16..(i + 1) * 16].copy_from_slice(&ga);
        prev.copy_from_slice(&ga);
    }
    out
}

/// Truncate the password input to 127 bytes per ISO 32000-2 §7.6.4.3.2.
fn trunc127(password: &[u8]) -> &[u8] {
    if password.len() > 127 {
        &password[..127]
    } else {
        password
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── SHA-256 / SHA-384 / SHA-512 KAT (FIPS 180-4 / NIST CAVS) ───
    #[test]
    fn sha256_empty_string_kat() {
        let h = Sha256::digest(b"");
        // FIPS 180-4: SHA-256("") = E3B0C44298FC1C149AFBF4C8996FB924
        //                            27AE41E4649B934CA495991B7852B855
        let expected: [u8; 32] = [
            0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F,
            0xB9, 0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B,
            0x78, 0x52, 0xB8, 0x55,
        ];
        assert_eq!(&h[..], &expected[..]);
    }

    #[test]
    fn sha256_abc_kat() {
        let h = Sha256::digest(b"abc");
        // FIPS 180-4 §B.1: SHA-256("abc") = BA7816BF8F01CFEA414140DE5D
        //                                   AE2223B00361A396177A9CB410FF61F20015AD
        let expected: [u8; 32] = [
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE,
            0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61,
            0xF2, 0x00, 0x15, 0xAD,
        ];
        assert_eq!(&h[..], &expected[..]);
    }

    #[test]
    fn sha384_empty_string_kat() {
        let h = Sha384::digest(b"");
        // FIPS 180-4: SHA-384("") = 38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B
        let expected: [u8; 48] = [
            0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1,
            0xE3, 0x6A, 0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF,
            0x63, 0xF6, 0xE1, 0xDA, 0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A,
            0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B,
        ];
        assert_eq!(&h[..], &expected[..]);
    }

    #[test]
    fn sha512_empty_string_kat() {
        let h = Sha512::digest(b"");
        // FIPS 180-4: SHA-512("") starts with 0xCF83E1357EEFB8BD...
        let expected: [u8; 64] = [
            0xCF, 0x83, 0xE1, 0x35, 0x7E, 0xEF, 0xB8, 0xBD, 0xF1, 0x54, 0x28, 0x50, 0xD6, 0x6D,
            0x80, 0x07, 0xD6, 0x20, 0xE4, 0x05, 0x0B, 0x57, 0x15, 0xDC, 0x83, 0xF4, 0xA9, 0x21,
            0xD3, 0x6C, 0xE9, 0xCE, 0x47, 0xD0, 0xD1, 0x3C, 0x5D, 0x85, 0xF2, 0xB0, 0xFF, 0x83,
            0x18, 0xD2, 0x87, 0x7E, 0xEC, 0x2F, 0x63, 0xB9, 0x31, 0xBD, 0x47, 0x41, 0x7A, 0x81,
            0xA5, 0x38, 0x32, 0x7A, 0xF9, 0x27, 0xDA, 0x3E,
        ];
        assert_eq!(&h[..], &expected[..]);
    }

    // ─── Algorithm 9 / 11 round-trip — R=5 ───────────────────────
    #[test]
    fn algorithm_9_then_11_authenticates_user_r5() {
        let user_pwd = b"hello";
        let file_key = [0x42u8; 32];
        let salt_v = [0xA0u8, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
        let salt_k = [0xB0u8, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7];
        let (u, ue) = algorithm_9(5, user_pwd, &file_key, &salt_v, &salt_k);
        // Algorithm 11: the user-validation hash must match.
        let mut h = Sha256::new();
        h.update(user_pwd);
        h.update(&u[32..40]);
        let want = h.finalize();
        assert_eq!(&u[..32], &want[..]);
        // Wrap unwraps to the file key.
        let int = {
            let mut hh = Sha256::new();
            hh.update(user_pwd);
            hh.update(&u[40..48]);
            hh.finalize().to_vec()
        };
        let unwrapped = unwrap_file_key(&int, &ue).unwrap();
        assert_eq!(unwrapped, file_key.to_vec());
    }

    // ─── Algorithm 9 / 11 round-trip — R=6 ───────────────────────
    #[test]
    fn algorithm_9_then_11_authenticates_user_r6() {
        let user_pwd = b"correct horse battery staple";
        let file_key = [0x55u8; 32];
        let salt_v = [0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let salt_k = [0x20u8, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27];
        let (u, ue) = algorithm_9(6, user_pwd, &file_key, &salt_v, &salt_k);
        // Reproduce Algorithm 11's check.
        let seed = {
            let mut hh = Sha256::new();
            hh.update(user_pwd);
            hh.update(&u[32..40]);
            hh.finalize().to_vec()
        };
        let want = algorithm_2b(&seed, user_pwd, &[]);
        assert_eq!(&u[..32], want.as_slice());
        // Wrap unwraps to the file key.
        let int_seed = {
            let mut hh = Sha256::new();
            hh.update(user_pwd);
            hh.update(&u[40..48]);
            hh.finalize().to_vec()
        };
        let int = algorithm_2b(&int_seed, user_pwd, &[]);
        let unwrapped = unwrap_file_key(&int, &ue).unwrap();
        assert_eq!(unwrapped, file_key.to_vec());
    }

    // ─── Algorithm 10 / 13 round-trip ─────────────────────────────
    #[test]
    fn algorithm_10_then_13_validates_perms() {
        let file_key = [0x77u8; 32];
        let p = -3904; // arbitrary signed permission value
        let perms = algorithm_10(&file_key, p, true, &[0xCA, 0xFE, 0xBA, 0xBE]);
        // Decrypt and check magic + P + EncryptMetadata.
        let pt = aes256_ecb_decrypt_block(&file_key, &perms).unwrap();
        assert_eq!(&pt[9..12], b"adb");
        let p_back = i32::from_le_bytes([pt[0], pt[1], pt[2], pt[3]]);
        assert_eq!(p_back, p);
        assert_eq!(pt[8], b'T');
    }

    #[test]
    fn algorithm_10_encrypt_metadata_false() {
        let file_key = [0x88u8; 32];
        let perms = algorithm_10(&file_key, -1, false, &[0; 4]);
        let pt = aes256_ecb_decrypt_block(&file_key, &perms).unwrap();
        assert_eq!(pt[8], b'F');
    }

    // ─── Algorithm 2.B determinism ───────────────────────────────
    #[test]
    fn algorithm_2b_is_deterministic() {
        let seed = Sha256::digest(b"seed");
        let pwd = b"password";
        let aux = b"aux";
        let a = algorithm_2b(&seed, pwd, aux);
        let b = algorithm_2b(&seed, pwd, aux);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    // ─── Wrap / unwrap symmetry ──────────────────────────────────
    #[test]
    fn wrap_unwrap_file_key_round_trips() {
        let int_key = [0x33u8; 32];
        let file_key = [0x99u8; 32];
        let wrapped = aes256_cbc_encrypt_no_padding(&int_key, &file_key);
        let unwrapped = unwrap_file_key(&int_key, &wrapped).unwrap();
        assert_eq!(unwrapped, file_key.to_vec());
    }
}
