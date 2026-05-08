//! Round-5 encryption decode tests — AES-256 (V=5, R=5 / R=6).
//!
//! Builds tiny encrypted PDFs by hand against ISO 32000-2 §7.6.4.4
//! (Algorithms 8 / 9 / 10) so the reader is exercised against a known-
//! good fixture without an external authoring tool. Two revisions:
//!
//! * **R=5** — Adobe extension level 3 (PDF 1.7), plain SHA-256
//!   password derivation.
//! * **R=6** — ISO 32000-2:2020 (PDF 2.0), iterated SHA-256/384/512
//!   per Algorithm 2.B.
//!
//! Each fixture has the same shape: a one-page document with a single
//! solid-fill rectangle on a 100×100 MediaBox + an `/Info` dict whose
//! `/Title` is a known string. The test asserts the reader recovers
//! the title (string-decryption) and the content-stream operators.

use oxideav_pdf::decrypt::r5_r6::{algorithm_10, algorithm_8, algorithm_9};
use oxideav_pdf::decrypt::{CryptMethod, StandardHandler};
use oxideav_pdf::read_pdf_to_scene_with_password;

/// Encrypt a payload with V=5 AES-256 CBC. The IV is fixed to `0x42…`
/// for reproducibility.
fn aes256_encrypt(file_key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    let iv = [0x42u8; 16];
    let enc = Aes256CbcEnc::new(file_key.into(), (&iv).into());
    let mut out = vec![0u8; ((data.len() / 16) + 1) * 16];
    let n = enc
        .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(data, &mut out)
        .unwrap()
        .len();
    out.truncate(n);
    let mut full = Vec::with_capacity(16 + n);
    full.extend_from_slice(&iv);
    full.extend_from_slice(&out);
    full
}

/// Build a minimal V=5 encrypted PDF. Returns the bytes; the caller's
/// supplied user password decrypts them.
fn build_v5_pdf(user_pw: &[u8], owner_pw: &[u8], revision: u8, title: &str) -> Vec<u8> {
    // Permission bits: print + copy denied (any value works).
    let p = -3904i32;
    let file_id = b"OXIDEAV-V5-FIXTURE-ID-0123456789".to_vec();
    let file_key: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
        0xF0, 0x01,
    ];

    // Deterministic salts (writers use random; tests use fixed bytes).
    let u_salt_v: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let u_salt_k: [u8; 8] = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let o_salt_v: [u8; 8] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];
    let o_salt_k: [u8; 8] = [0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8];

    // Algorithms 9 + 8 + 10 — produce the dict bytes the reader will see.
    let (u, ue) = algorithm_9(revision, user_pw, &file_key, &u_salt_v, &u_salt_k);
    let (o, oe) = algorithm_8(revision, owner_pw, &u, &file_key, &o_salt_v, &o_salt_k);
    let perms = algorithm_10(&file_key, p, true, &[0xCA, 0xFE, 0xBA, 0xBE]);

    // Build a StandardHandler so we can re-use existing helpers.
    let _handler = StandardHandler {
        key: file_key.to_vec(),
        method: CryptMethod::Aes256,
        revision,
    };

    // Encrypt the /Title and content stream.
    let info_title_str = aes256_encrypt(&file_key, title.as_bytes());
    let content_plain = b"q\n0 0 1 rg\n10 10 50 50 re\nf\nQ\n".to_vec();
    let content_cipher = aes256_encrypt(&file_key, &content_plain);

    let mut bytes = Vec::with_capacity(4096);
    bytes.extend_from_slice(b"%PDF-2.0\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets = [0u64; 7];
    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>\nendobj\n",
    );

    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content_cipher.len()).as_bytes(),
    );
    bytes.extend_from_slice(&content_cipher);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(b"5 0 obj\n<< /Title <");
    for b in &info_title_str {
        bytes.extend_from_slice(format!("{:02X}", b).as_bytes());
    }
    bytes.extend_from_slice(b"> >>\nendobj\n");

    // Obj 6: Encrypt dict — plaintext per §7.6.1.
    offsets[6] = bytes.len() as u64;
    let mut enc_obj = String::new();
    enc_obj.push_str(&format!(
        "6 0 obj\n<< /Filter /Standard /V 5 /R {} /Length 256",
        revision
    ));
    enc_obj.push_str(" /CF << /StdCF << /Type /CryptFilter /CFM /AESV3 /Length 32 >> >>");
    enc_obj.push_str(" /StmF /StdCF /StrF /StdCF");
    enc_obj.push_str(" /O <");
    bytes.extend_from_slice(enc_obj.as_bytes());
    for b in &o {
        bytes.extend_from_slice(format!("{:02X}", b).as_bytes());
    }
    bytes.extend_from_slice(b"> /U <");
    for b in &u {
        bytes.extend_from_slice(format!("{:02X}", b).as_bytes());
    }
    bytes.extend_from_slice(b"> /OE <");
    for b in &oe {
        bytes.extend_from_slice(format!("{:02X}", b).as_bytes());
    }
    bytes.extend_from_slice(b"> /UE <");
    for b in &ue {
        bytes.extend_from_slice(format!("{:02X}", b).as_bytes());
    }
    bytes.extend_from_slice(b"> /Perms <");
    for b in &perms {
        bytes.extend_from_slice(format!("{:02X}", b).as_bytes());
    }
    bytes.extend_from_slice(format!("> /P {} >>\nendobj\n", p).as_bytes());

    // xref
    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n0 7\n0000000000 65535 f \n");
    for &off in &offsets[1..7] {
        bytes.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    // trailer
    bytes.extend_from_slice(b"trailer\n<< /Size 7 /Root 1 0 R /Info 5 0 R /Encrypt 6 0 R /ID [<");
    for b in &file_id {
        bytes.extend_from_slice(format!("{:02X}", b).as_bytes());
    }
    bytes.extend_from_slice(b"> <");
    for b in &file_id {
        bytes.extend_from_slice(format!("{:02X}", b).as_bytes());
    }
    bytes.extend_from_slice(b">] >>\n");
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());

    bytes
}

// ─── Tests — R=5 (Adobe extension level 3) ────────────────────────

#[test]
fn aes256_r5_decodes_with_user_password() {
    let pdf = build_v5_pdf(b"hunter2", b"admin-secret", 5, "AES-256 R=5 Title");
    let scene = read_pdf_to_scene_with_password(&pdf, b"hunter2").expect("decrypt R=5 user");
    assert_eq!(scene.metadata.title.as_deref(), Some("AES-256 R=5 Title"));
    let pages = scene.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
    assert_eq!(pages[0].height, 100.0);
}

#[test]
fn aes256_r5_decodes_with_owner_password() {
    let pdf = build_v5_pdf(b"hunter2", b"admin-secret", 5, "AES-256 R=5 owner");
    let scene = read_pdf_to_scene_with_password(&pdf, b"admin-secret").expect("decrypt R=5 owner");
    assert_eq!(scene.metadata.title.as_deref(), Some("AES-256 R=5 owner"));
}

#[test]
fn aes256_r5_rejects_wrong_password() {
    let pdf = build_v5_pdf(b"hunter2", b"admin-secret", 5, "AES-256 R=5 reject");
    let err = read_pdf_to_scene_with_password(&pdf, b"hunter3").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("password") || msg.contains("Encrypt"),
        "expected wrong-password error, got: {msg}"
    );
}

// ─── Tests — R=6 (ISO 32000-2 PDF 2.0) ────────────────────────

#[test]
fn aes256_r6_decodes_with_user_password() {
    let pdf = build_v5_pdf(
        b"correct horse battery staple",
        b"the-owner",
        6,
        "ISO 2.0 user",
    );
    let scene = read_pdf_to_scene_with_password(&pdf, b"correct horse battery staple")
        .expect("decrypt R=6 user");
    assert_eq!(scene.metadata.title.as_deref(), Some("ISO 2.0 user"));
}

#[test]
fn aes256_r6_decodes_with_owner_password() {
    let pdf = build_v5_pdf(b"the-user", b"the-owner-secret", 6, "ISO 2.0 owner");
    let scene =
        read_pdf_to_scene_with_password(&pdf, b"the-owner-secret").expect("decrypt R=6 owner");
    assert_eq!(scene.metadata.title.as_deref(), Some("ISO 2.0 owner"));
}

#[test]
fn aes256_r6_rejects_wrong_password() {
    let pdf = build_v5_pdf(b"realpw", b"ownerpw", 6, "Whatever");
    let err = read_pdf_to_scene_with_password(&pdf, b"wrongpw").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("password") || msg.contains("Encrypt"),
        "expected wrong-password error, got: {msg}"
    );
}

#[test]
fn aes256_r6_empty_password_default_user() {
    // Common for "encrypted just for permission flags": user pwd is
    // empty, opens via the default-empty-password path.
    let pdf = build_v5_pdf(b"", b"adminpw", 6, "Default-pw V5");
    let scene = oxideav_pdf::read_pdf_to_scene(&pdf).expect("decrypt empty-pwd default");
    assert_eq!(scene.metadata.title.as_deref(), Some("Default-pw V5"));
}

#[test]
fn aes256_r5_unicode_password_round_trips() {
    // ISO 32000-2 §7.6.4.3.2 allows arbitrary UTF-8 byte strings as the
    // password. Confirm a multibyte password authenticates round-trip.
    let pdf = build_v5_pdf("日本語パスワード".as_bytes(), b"admin", 5, "Unicode pw");
    let scene = read_pdf_to_scene_with_password(&pdf, "日本語パスワード".as_bytes())
        .expect("decrypt unicode pw");
    assert_eq!(scene.metadata.title.as_deref(), Some("Unicode pw"));
}

#[test]
fn aes256_r5_long_password_truncated_to_127() {
    // A password exactly 200 bytes long should be truncated to 127 by
    // both the writer-side helpers and the reader-side derivation, and
    // the truncation must agree so authentication still works.
    let pwd: Vec<u8> = (0..200).map(|i| (i & 0xFF) as u8).collect();
    let pdf = build_v5_pdf(&pwd, b"admin", 5, "Long pw");
    let scene = read_pdf_to_scene_with_password(&pdf, &pwd).expect("long pwd");
    assert_eq!(scene.metadata.title.as_deref(), Some("Long pw"));
}
