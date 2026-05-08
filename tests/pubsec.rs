//! Round-10 public-key encryption decode tests.
//!
//! Builds tiny public-key-encrypted PDFs by hand against the spec
//! (ISO 32000-1 §7.6.4 / ISO 32000-2 §7.6.5) and verifies the
//! reader's certificate-based open path can decrypt them
//! end-to-end. Three SubFilters are covered:
//!
//! * **`adbe.pkcs7.s4`** — RC4-128, V=2, SHA-1 file-key derivation.
//! * **`adbe.pkcs7.s5`, V=4, AESV2** — AES-128 CBC, SHA-1.
//! * **`adbe.pkcs7.s5`, V=5, AESV3** — AES-256 CBC, SHA-256
//!   (no per-object Algorithm 1; file key feeds AES-256 directly).
//!
//! The fixture builder constructs:
//!  - a fresh RSA-2048 keypair (used as both the user's identity key
//!    and the document-encryption recipient);
//!  - a synthetic minimal X.509 v3 certificate that carries a
//!    matching `IssuerAndSerialNumber` for the recipient slot;
//!  - a CMS `EnvelopedData` whose recipient slot wraps the
//!    content-encryption key with `RSAES-PKCS1-v1_5`;
//!  - a one-page PDF with `/Title` (encrypted string) + a
//!    rectangle content stream (encrypted stream).
//!
//! No external library code is consulted — RFC 5652 + RFC 5280 +
//! ISO 32000-1 §7.6.4 only.

use oxideav_pdf::decrypt::{md5, rc4, CryptMethod, StandardHandler};
use oxideav_pdf::pubsec::{
    cms::{OID_AES128_CBC, OID_AES256_CBC, OID_DATA, OID_ENVELOPED_DATA, OID_RSA_ENCRYPTION},
    der,
    x509::Certificate,
    PubSecCredential,
};
use oxideav_pdf::read_pdf_to_scene_with_certificate;

// ───────── Fixture helpers ─────────

fn rsa_keypair() -> (rsa::RsaPrivateKey, rsa::RsaPublicKey) {
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    (priv_key, pub_key)
}

fn rsa_pkcs1_encrypt(pub_key: &rsa::RsaPublicKey, data: &[u8]) -> Vec<u8> {
    let mut rng = rsa::rand_core::OsRng;
    pub_key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, data)
        .expect("RSA encrypt")
}

fn aes_cbc_encrypt_pkcs7(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    let pad_block = (data.len() / 16) + 1;
    let mut buf = vec![0u8; pad_block * 16];
    if key.len() == 16 {
        type E = cbc::Encryptor<aes::Aes128>;
        let n = E::new(key.into(), iv.into())
            .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(data, &mut buf)
            .unwrap()
            .len();
        buf.truncate(n);
    } else if key.len() == 32 {
        type E = cbc::Encryptor<aes::Aes256>;
        let n = E::new(key.into(), iv.into())
            .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(data, &mut buf)
            .unwrap()
            .len();
        buf.truncate(n);
    } else {
        panic!("unsupported key size");
    }
    buf
}

/// Build a CMS `EnvelopedData` ContentInfo whose enveloped data is
/// the supplied `plaintext` (typically 20-byte seed + 4-byte
/// permissions). Returns the DER bytes.
fn build_envelope(
    issuer_der: &[u8],
    serial: &[u8],
    pub_key: &rsa::RsaPublicKey,
    cek: &[u8],
    iv: &[u8; 16],
    plaintext: &[u8],
    aes_oid: &[u64],
) -> Vec<u8> {
    let encrypted_key = rsa_pkcs1_encrypt(pub_key, cek);
    let serial_int = der::write_integer_bytes(serial);
    let ias_body = {
        let mut b = Vec::with_capacity(issuer_der.len() + serial_int.len());
        b.extend_from_slice(issuer_der);
        b.extend_from_slice(&serial_int);
        b
    };
    let ias = der::write_sequence(&ias_body);
    let kea = der::write_sequence(&{
        let mut b = der::write_oid(&OID_RSA_ENCRYPTION);
        b.extend_from_slice(&der::write_null());
        b
    });
    let ktri = der::write_sequence(&{
        let mut b = der::write_integer_u64(0);
        b.extend_from_slice(&ias);
        b.extend_from_slice(&kea);
        b.extend_from_slice(&der::write_octet_string(&encrypted_key));
        b
    });
    let ri_set = der::write_set(&ktri);

    let encrypted_content = aes_cbc_encrypt_pkcs7(cek, iv, plaintext);
    let alg_id = der::write_sequence(&{
        let mut b = der::write_oid(aes_oid);
        b.extend_from_slice(&der::write_octet_string(iv));
        b
    });
    let eci = der::write_sequence(&{
        let mut b = der::write_oid(&OID_DATA);
        b.extend_from_slice(&alg_id);
        b.extend_from_slice(&der::write_context_primitive(0, &encrypted_content));
        b
    });
    let enveloped = der::write_sequence(&{
        let mut b = der::write_integer_u64(0);
        b.extend_from_slice(&ri_set);
        b.extend_from_slice(&eci);
        b
    });
    der::write_sequence(&{
        let mut b = der::write_oid(&OID_ENVELOPED_DATA);
        b.extend_from_slice(&der::write_context_constructed(0, &enveloped));
        b
    })
}

/// Build a CMS envelope using RC4 to encrypt the payload.
fn build_envelope_rc4(
    issuer_der: &[u8],
    serial: &[u8],
    pub_key: &rsa::RsaPublicKey,
    cek: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    // RC4 OID 1.2.840.113549.3.4.
    let rc4_oid = [1u64, 2, 840, 113549, 3, 4];
    let encrypted_key = rsa_pkcs1_encrypt(pub_key, cek);
    let serial_int = der::write_integer_bytes(serial);
    let ias_body = {
        let mut b = Vec::with_capacity(issuer_der.len() + serial_int.len());
        b.extend_from_slice(issuer_der);
        b.extend_from_slice(&serial_int);
        b
    };
    let ias = der::write_sequence(&ias_body);
    let kea = der::write_sequence(&{
        let mut b = der::write_oid(&OID_RSA_ENCRYPTION);
        b.extend_from_slice(&der::write_null());
        b
    });
    let ktri = der::write_sequence(&{
        let mut b = der::write_integer_u64(0);
        b.extend_from_slice(&ias);
        b.extend_from_slice(&kea);
        b.extend_from_slice(&der::write_octet_string(&encrypted_key));
        b
    });
    let ri_set = der::write_set(&ktri);

    let encrypted_content = rc4(cek, plaintext);
    let alg_id = der::write_sequence(&{
        let mut b = der::write_oid(&rc4_oid);
        b.extend_from_slice(&der::write_null());
        b
    });
    let eci = der::write_sequence(&{
        let mut b = der::write_oid(&OID_DATA);
        b.extend_from_slice(&alg_id);
        b.extend_from_slice(&der::write_context_primitive(0, &encrypted_content));
        b
    });
    let enveloped = der::write_sequence(&{
        let mut b = der::write_integer_u64(0);
        b.extend_from_slice(&ri_set);
        b.extend_from_slice(&eci);
        b
    });
    der::write_sequence(&{
        let mut b = der::write_oid(&OID_ENVELOPED_DATA);
        b.extend_from_slice(&der::write_context_constructed(0, &enveloped));
        b
    })
}

/// Compute the file encryption key per ISO 32000-1 §7.6.4.3 (SHA-1
/// over seed + recipient blobs, optionally + 0xFFFFFFFF).
fn derive_file_key_sha1(seed: &[u8], recipients: &[Vec<u8>], n: usize) -> Vec<u8> {
    use sha1::Digest;
    let mut input = Vec::new();
    input.extend_from_slice(seed);
    for blob in recipients {
        input.extend_from_slice(blob);
    }
    let h = sha1::Sha1::digest(&input);
    h[..n].to_vec()
}

/// Compute the file encryption key per ISO 32000-2 §7.6.5.3 (SHA-256
/// over seed + recipient blobs, optionally + 0xFFFFFFFF).
fn derive_file_key_sha256(seed: &[u8], recipients: &[Vec<u8>], n: usize) -> Vec<u8> {
    use sha2::Digest;
    let mut input = Vec::new();
    input.extend_from_slice(seed);
    for blob in recipients {
        input.extend_from_slice(blob);
    }
    let h = sha2::Sha256::digest(&input);
    h[..n].to_vec()
}

/// Encrypt object content with Algorithm 1 + RC4 / AES-128 / AES-256
/// per ISO 32000 §7.6.2 — same shape as
/// `tests/encryption.rs::encrypt_with` but operating from an already-
/// derived `StandardHandler` (which is what the public-key path
/// produces).
fn encrypt_with_object_key(handler: &StandardHandler, id: u32, data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let key = handler.key.clone();
    let n = key.len();
    if handler.method == CryptMethod::Aes256 {
        // No per-object derivation.
        let iv = [0x55u8; 16];
        let pad_block = (data.len() / 16) + 1;
        let mut buf = vec![0u8; pad_block * 16];
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        let bytes = Aes256CbcEnc::new((&key[..]).into(), (&iv).into())
            .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(data, &mut buf)
            .unwrap()
            .len();
        buf.truncate(bytes);
        let mut full = Vec::with_capacity(16 + bytes);
        full.extend_from_slice(&iv);
        full.extend_from_slice(&buf);
        return full;
    }

    let mut buf = Vec::with_capacity(n + 9);
    buf.extend_from_slice(&key);
    buf.push((id & 0xFF) as u8);
    buf.push(((id >> 8) & 0xFF) as u8);
    buf.push(((id >> 16) & 0xFF) as u8);
    buf.push(0); // gen low
    buf.push(0); // gen high
    let aes_mode = handler.method == CryptMethod::Aes128;
    if aes_mode {
        buf.extend_from_slice(&[0x73, 0x41, 0x6C, 0x54]);
    }
    let h = md5(&buf);
    let take = (n + 5).min(16);
    let obj_key = &h[..take];

    if aes_mode {
        let iv = [0x42u8; 16];
        let enc = Aes128CbcEnc::new(obj_key.into(), (&iv).into());
        let mut out = vec![0u8; ((data.len() / 16) + 1) * 16];
        let bytes = enc
            .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(data, &mut out)
            .unwrap()
            .len();
        out.truncate(bytes);
        let mut full = Vec::with_capacity(16 + bytes);
        full.extend_from_slice(&iv);
        full.extend_from_slice(&out);
        full
    } else {
        rc4(obj_key, data)
    }
}

#[derive(Clone, Copy)]
enum Profile {
    /// `adbe.pkcs7.s4` — RC4-128, V=2.
    PkS4,
    /// `adbe.pkcs7.s5` V=4 + AESV2 — AES-128 CBC.
    PkS5V4Aes128,
    /// `adbe.pkcs7.s5` V=5 + AESV3 — AES-256 CBC.
    PkS5V5Aes256,
}

/// Build a one-page public-key-encrypted PDF that the round-10
/// reader should be able to open with the matching cert+key.
fn build_pubsec_pdf(profile: Profile, title: &str) -> (Vec<u8>, PubSecCredential) {
    let (priv_key, pub_key) = rsa_keypair();
    let issuer_der = der::write_sequence(b"O=OxideAV pubsec test");
    let serial = vec![0x10, 0x20, 0x30];

    // Pick the document encryption parameters per profile.
    let (sub_filter, v, length_bits, alg_oid, method, revision) = match profile {
        Profile::PkS4 => ("adbe.pkcs7.s4", 2, 128, None, CryptMethod::Rc4, 3u8),
        Profile::PkS5V4Aes128 => (
            "adbe.pkcs7.s5",
            4,
            128,
            Some(OID_AES128_CBC),
            CryptMethod::Aes128,
            4,
        ),
        Profile::PkS5V5Aes256 => (
            "adbe.pkcs7.s5",
            5,
            256,
            Some(OID_AES256_CBC),
            CryptMethod::Aes256,
            6,
        ),
    };

    // CEK + IV for the envelope.
    let cek_bytes: Vec<u8> = match profile {
        Profile::PkS4 => vec![0xA1u8; 16], // RC4-128 key
        Profile::PkS5V4Aes128 => vec![0xB2u8; 16],
        Profile::PkS5V5Aes256 => vec![0xC3u8; 32],
    };
    let env_iv = [0x77u8; 16];

    // Plaintext = 20-byte seed + 4-byte permissions (LE for ISO 32000-1,
    // MSB for ISO 32000-2 — but we don't read the permission bytes
    // back, only the seed, so the ordering doesn't matter for this
    // test).
    let seed = [0x5Au8; 20];
    let mut plaintext = Vec::with_capacity(24);
    plaintext.extend_from_slice(&seed);
    plaintext.extend_from_slice(&((-4i32) as u32).to_le_bytes());

    // Build the recipient envelope.
    let envelope = match profile {
        Profile::PkS4 => build_envelope_rc4(&issuer_der, &serial, &pub_key, &cek_bytes, &plaintext),
        _ => build_envelope(
            &issuer_der,
            &serial,
            &pub_key,
            &cek_bytes,
            &env_iv,
            &plaintext,
            &alg_oid.unwrap(),
        ),
    };

    // Derive the file encryption key (matches `crate::pubsec` exactly).
    let file_key = if matches!(profile, Profile::PkS5V5Aes256) {
        derive_file_key_sha256(&seed, std::slice::from_ref(&envelope), length_bits / 8)
    } else {
        derive_file_key_sha1(&seed, std::slice::from_ref(&envelope), length_bits / 8)
    };

    let handler = StandardHandler {
        key: file_key.clone(),
        method,
        revision,
    };

    // ─── Build PDF objects ───
    let info_title_str = encrypt_with_object_key(&handler, 5, title.as_bytes());
    let content_plain = b"q\n1 0 0 rg\n10 10 50 50 re\nf\nQ\n".to_vec();
    let content_cipher = encrypt_with_object_key(&handler, 4, &content_plain);

    let mut bytes = Vec::with_capacity(4096);
    // Use PDF 1.6 for AES-128 / AES-256.
    let header = if v >= 4 {
        b"%PDF-1.6\n%\xE2\xE3\xCF\xD3\n".as_slice()
    } else {
        b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".as_slice()
    };
    bytes.extend_from_slice(header);
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

    offsets[6] = bytes.len() as u64;
    let recipients_hex: String = {
        let mut s = String::new();
        for byte in &envelope {
            s.push_str(&format!("{:02X}", byte));
        }
        s
    };
    let encrypt_dict = match profile {
        Profile::PkS4 => format!(
            "6 0 obj\n<< /Filter /Adobe.PPKLite /SubFilter /{sub_filter} /V {v} /R {revision} \
             /Length {length_bits} /P -4 /Recipients [<{recipients}>] >>\nendobj\n",
            sub_filter = sub_filter,
            recipients = recipients_hex,
        ),
        Profile::PkS5V4Aes128 => format!(
            "6 0 obj\n<< /Filter /Adobe.PPKLite /SubFilter /{sub_filter} /V {v} /R {revision} \
             /Length {length_bits} /P -4 \
             /CF << /DefaultCryptFilter << /CFM /AESV2 /Length 16 /Recipients [<{recipients}>] >> >> \
             /StmF /DefaultCryptFilter /StrF /DefaultCryptFilter \
             /Recipients [<{recipients}>] >>\nendobj\n",
            sub_filter = sub_filter,
            recipients = recipients_hex,
        ),
        Profile::PkS5V5Aes256 => format!(
            "6 0 obj\n<< /Filter /Adobe.PPKLite /SubFilter /{sub_filter} /V {v} /R {revision} \
             /Length {length_bits} /P -4 \
             /CF << /DefaultCryptFilter << /CFM /AESV3 /Length 32 /Recipients [<{recipients}>] >> >> \
             /StmF /DefaultCryptFilter /StrF /DefaultCryptFilter \
             /Recipients [<{recipients}>] >>\nendobj\n",
            sub_filter = sub_filter,
            recipients = recipients_hex,
        ),
    };
    bytes.extend_from_slice(encrypt_dict.as_bytes());

    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n0 7\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for &off in &offsets[1..7] {
        bytes.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }

    let file_id = b"OXIDEAV-PUBSEC-FILE-ID-0123456!".to_vec();
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

    let cert = Certificate { issuer_der, serial };
    let credential = PubSecCredential::from_parsed(cert, priv_key);
    (bytes, credential)
}

// ───────── Tests ─────────

#[test]
fn s4_rc4_128_decodes_with_certificate() {
    let (pdf, cred) = build_pubsec_pdf(Profile::PkS4, "PubSec S4 Title");
    let scene = read_pdf_to_scene_with_certificate(&pdf, &cred).expect("decrypt s4");
    assert_eq!(scene.metadata.title.as_deref(), Some("PubSec S4 Title"));
    let pages = scene.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
    assert_eq!(pages[0].height, 100.0);
}

#[test]
fn s5_v4_aes128_decodes_with_certificate() {
    let (pdf, cred) = build_pubsec_pdf(Profile::PkS5V4Aes128, "S5/V4 AES-128");
    let scene = read_pdf_to_scene_with_certificate(&pdf, &cred).expect("decrypt s5/v4");
    assert_eq!(scene.metadata.title.as_deref(), Some("S5/V4 AES-128"));
}

#[test]
fn s5_v5_aes256_decodes_with_certificate() {
    let (pdf, cred) = build_pubsec_pdf(Profile::PkS5V5Aes256, "S5/V5 AES-256");
    let scene = read_pdf_to_scene_with_certificate(&pdf, &cred).expect("decrypt s5/v5");
    assert_eq!(scene.metadata.title.as_deref(), Some("S5/V5 AES-256"));
}

#[test]
fn wrong_certificate_serial_returns_error() {
    let (pdf, _correct) = build_pubsec_pdf(Profile::PkS5V5Aes256, "Owner-only");
    // Construct a fresh credential with the SAME issuer but a
    // different serial — the recipient slot's IssuerAndSerialNumber
    // won't match.
    let (priv_key, _pub) = rsa_keypair();
    let bad_cred = PubSecCredential::from_parsed(
        Certificate {
            issuer_der: der::write_sequence(b"O=OxideAV pubsec test"),
            serial: vec![0xFF, 0xFF, 0xFF],
        },
        priv_key,
    );
    let err = read_pdf_to_scene_with_certificate(&pdf, &bad_cred).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("certificate did not match"),
        "expected wrong-cert error, got: {msg}"
    );
}

#[test]
fn open_unencrypted_pdf_via_certificate_works() {
    // Sanity: when there's no /Encrypt, the cert path falls through
    // and reads the PDF normally (analogous to `open_with_password`
    // accepting any password on an unencrypted PDF). Use the
    // round-1 writer to produce a known-good PDF — far more robust
    // than hand-writing the xref offsets.
    use oxideav_core::vector::{FillRule, Group, Node, Paint, Path, PathNode, Rgba, VectorFrame};
    use oxideav_core::TimeBase;
    let mut p = Path::new();
    p.move_to(oxideav_core::vector::Point::new(10.0, 10.0))
        .line_to(oxideav_core::vector::Point::new(110.0, 10.0))
        .line_to(oxideav_core::vector::Point::new(110.0, 60.0))
        .line_to(oxideav_core::vector::Point::new(10.0, 60.0))
        .close();
    let frame = VectorFrame {
        width: 200.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(0xFF, 0x80, 0x00))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let pdf = oxideav_pdf::write_pdf(&frame).expect("write");
    let (priv_key, _pub) = rsa_keypair();
    let cred = PubSecCredential::from_parsed(
        Certificate {
            issuer_der: der::write_sequence(b"O=anything"),
            serial: vec![0x01],
        },
        priv_key,
    );
    let scene = read_pdf_to_scene_with_certificate(&pdf, &cred).expect("plain PDF");
    assert!(!scene.pages.unwrap().is_empty());
}
