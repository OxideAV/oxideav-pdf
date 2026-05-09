//! Round-14 integration tests — KARI envelope decode end-to-end.
//!
//! Builds tiny KARI-encrypted PDFs by hand (P-256 ECDH originator +
//! AES-256 KW recipient slot + AES-256-CBC content envelope), then
//! verifies the round-10 reader path
//! (`read_pdf_to_scene_with_certificate`) decrypts them given a
//! credential carrying the recipient's EC private scalar.
//!
//! Provenance: ISO 32000-1 §7.6.4 + ISO 32000-2 §7.6.5 + RFC 5652
//! §6.2.2 + RFC 5753 §7.1 + RFC 3394 only.

use oxideav_pdf::decrypt::{md5, CryptMethod, StandardHandler};
use oxideav_pdf::pubsec::cms_build::{
    build_envelope_kari_aes256, KariRecipientIdRef, KariRecipientPlain, OriginatorIdRef,
};
use oxideav_pdf::pubsec::der;
use oxideav_pdf::pubsec::kari::{
    wrap_cek_for_p256_recipient, WrapAlgorithm, OID_DH_SINGLE_PASS_STDDH_SHA256_KDF,
    OID_EC_PUBLIC_KEY, OID_SECP256R1,
};
use oxideav_pdf::pubsec::x509::Certificate;
use oxideav_pdf::{read_pdf_to_scene_with_certificate, PubSecCredential};

/// AES-256 CBC encrypt + PKCS#7 pad — used to build the per-object
/// content stream whose key is the SHA-256-derived file key.
fn aes256_cbc_pkcs7(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    type E = cbc::Encryptor<aes::Aes256>;
    let pad_block = (data.len() / 16) + 1;
    let mut buf = vec![0u8; pad_block * 16];
    let n = E::new(key.into(), iv.into())
        .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(data, &mut buf)
        .unwrap()
        .len();
    buf.truncate(n);
    buf
}

/// Encrypt one object with AES-256 CBC (no per-object derivation —
/// ISO 32000-2 §7.6.4.4 / §7.6.4.5 for AESV3).
fn encrypt_object_aes256(handler: &StandardHandler, _id: u32, data: &[u8]) -> Vec<u8> {
    assert_eq!(handler.method, CryptMethod::Aes256);
    let iv = [0x55u8; 16];
    let key32: [u8; 32] = handler.key.as_slice().try_into().expect("AES-256 key");
    let ct = aes256_cbc_pkcs7(&key32, &iv, data);
    let mut out = Vec::with_capacity(16 + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    out
}

/// SHA-256 file-key derivation per ISO 32000-2 §7.6.5.3 (no metadata
/// suffix — `EncryptMetadata=true`).
fn derive_file_key_sha256(seed: &[u8], envelopes: &[Vec<u8>], n: usize) -> Vec<u8> {
    use sha2::Digest;
    let mut input = Vec::new();
    input.extend_from_slice(seed);
    for e in envelopes {
        input.extend_from_slice(e);
    }
    let h = sha2::Sha256::digest(&input);
    h[..n].to_vec()
}

/// Generate a deterministic test P-256 keypair from a 32-byte seed
/// scalar. Returns `(scalar_bytes, sec1_uncompressed_point_bytes)`.
fn p256_keypair_from(scalar: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    let sk = SecretKey::from_slice(scalar).expect("scalar valid");
    let point = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
    (scalar.to_vec(), point)
}

/// Build an AES-256 KARI-encrypted PDF that the round-14 reader path
/// can open with the matching EC recipient credential. Returns
/// `(pdf_bytes, credential)`.
fn build_kari_pubsec_pdf(title: &str) -> (Vec<u8>, PubSecCredential) {
    // Recipient's EC keypair.
    let recipient_seed: [u8; 32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x40,
    ];
    let (recipient_scalar, recipient_pub_sec1) = p256_keypair_from(&recipient_seed);
    // Originator's ephemeral keypair (sender side).
    let ephemeral_seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];

    // Synthetic recipient cert info (round-10 pattern — minimal IAS
    // matching, no real X.509 body needed since the spki_pubkey_bits
    // is supplied directly).
    let issuer_der = der::write_sequence(b"O=OxideAV KARI test");
    let serial = vec![0xC0, 0xCA, 0xFE];

    // Content-encryption key (AES-256) + envelope IV. The CEK doubles
    // as the file encryption key derivation input — actually no, the
    // file key is derived from `SHA-256(seed || envelope)`; the CEK
    // is what the envelope's contents decrypt with.
    let cek: [u8; 32] = [0xAAu8; 32];
    let env_iv: [u8; 16] = [0xBBu8; 16];
    // 20-byte seed + 4-byte permissions (MSB for ISO 32000-2).
    let seed = [0x5Au8; 20];
    let mut plaintext = Vec::with_capacity(24);
    plaintext.extend_from_slice(&seed);
    plaintext.extend_from_slice(&((-4i32) as u32).to_be_bytes());

    // Wrap the CEK on the originator side using P-256 ECDH + X9.63
    // SHA-256 KDF + AES-256 KW.
    let ukm = b"OXIDEAV-UKM-RT-1";
    let (originator_point, wrapped_cek) = wrap_cek_for_p256_recipient(
        &ephemeral_seed,
        &recipient_pub_sec1,
        Some(ukm),
        &cek,
        WrapAlgorithm::Aes256,
    )
    .expect("wrap CEK");

    // Build the KARI envelope DER.
    let originator = OriginatorIdRef::OriginatorKey {
        algorithm_oid: OID_EC_PUBLIC_KEY.to_vec(),
        algorithm_params: der::write_oid(&OID_SECP256R1),
        public_key: originator_point,
    };
    // KARI keyEncryptionAlgorithm parameters = AES-256-WRAP AlgorithmIdentifier.
    let aes256_wrap_oid = [2u64, 16, 840, 1, 101, 3, 4, 1, 45];
    let kea_params = der::write_sequence(&der::write_oid(&aes256_wrap_oid));
    let recipient_slot = KariRecipientPlain {
        rid: KariRecipientIdRef::IssuerAndSerial {
            issuer_der: issuer_der.clone(),
            serial: serial.clone(),
        },
        encrypted_key: wrapped_cek,
    };
    let envelope = build_envelope_kari_aes256(
        &originator,
        Some(ukm),
        &OID_DH_SINGLE_PASS_STDDH_SHA256_KDF,
        &kea_params,
        &[recipient_slot],
        &plaintext,
        &cek,
        &env_iv,
    );

    // Derive the file encryption key (32 bytes for AES-256 / V=5).
    let file_key = derive_file_key_sha256(&seed, std::slice::from_ref(&envelope), 32);
    let handler = StandardHandler {
        key: file_key,
        method: CryptMethod::Aes256,
        revision: 6,
    };
    // unused but kept for completeness so the compiler doesn't complain
    let _ = md5(b"x");

    // Build per-object encrypted streams.
    let info_title_str = encrypt_object_aes256(&handler, 5, title.as_bytes());
    let content_plain = b"q\n0 0 1 rg\n10 10 80 80 re\nf\nQ\n".to_vec();
    let content_cipher = encrypt_object_aes256(&handler, 4, &content_plain);

    // Hand-assemble a minimal PDF structurally identical to the round-10
    // pubsec.rs fixture, with the KARI envelope blob as `/Recipients`.
    let mut bytes = Vec::with_capacity(8192);
    bytes.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
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
    let encrypt_dict = format!(
        "6 0 obj\n<< /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.s5 /V 5 /R 6 \
         /Length 256 /P -4 \
         /CF << /DefaultCryptFilter << /CFM /AESV3 /Length 32 /Recipients [<{recipients}>] >> >> \
         /StmF /DefaultCryptFilter /StrF /DefaultCryptFilter \
         /Recipients [<{recipients}>] >>\nendobj\n",
        recipients = recipients_hex,
    );
    bytes.extend_from_slice(encrypt_dict.as_bytes());

    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n0 7\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for &off in &offsets[1..7] {
        bytes.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }

    let file_id = b"OXIDEAV-PUBSEC-KARI-ID-0123456!".to_vec();
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

    // Build a credential carrying the recipient's EC private scalar.
    // The cert's issuer + serial match the recipient slot's RID; the
    // spki_pubkey_bits slot carries the SEC1 point so the SKI form
    // would also match (we use IAS here, so it's only there for
    // completeness).
    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub_sec1),
        validity: None,
        ..Default::default()
    };
    let credential = PubSecCredential::from_parsed_ec_p256(cert, recipient_scalar);
    (bytes, credential)
}

#[test]
fn kari_p256_aes256_decodes_with_certificate() {
    let (pdf, cred) = build_kari_pubsec_pdf("KARI Round 14 Title");
    let scene = read_pdf_to_scene_with_certificate(&pdf, &cred).expect("KARI decrypt");
    assert_eq!(scene.metadata.title.as_deref(), Some("KARI Round 14 Title"));
    let pages = scene.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
    assert_eq!(pages[0].height, 100.0);
}

/// SKI-form recipient slot — the recipient is identified by the
/// SHA-1 of its SubjectPublicKeyInfo BIT STRING contents (RFC 5280
/// §4.2.1.2 method 1). For an EC cert the SPKI BIT STRING contents
/// is the SEC1-encoded point, so SHA-1(point) is the SKI we plant
/// in both the recipient slot and the credential's cert.
#[test]
fn kari_p256_ski_form_decodes_with_certificate() {
    use sha1::Digest;
    // Recipient EC keypair.
    let recipient_seed: [u8; 32] = [0x77u8; 32];
    let (recipient_scalar, recipient_pub_sec1) = p256_keypair_from(&recipient_seed);
    let recipient_ski = sha1::Sha1::digest(&recipient_pub_sec1).to_vec();
    // Originator ephemeral.
    let ephemeral_seed: [u8; 32] = [0x33u8; 32];
    let cek: [u8; 32] = [0x9Fu8; 32];
    let env_iv: [u8; 16] = [0x88u8; 16];
    let seed = [0xCDu8; 20];
    let mut plaintext = Vec::with_capacity(24);
    plaintext.extend_from_slice(&seed);
    plaintext.extend_from_slice(&((-4i32) as u32).to_be_bytes());

    let (originator_point, wrapped_cek) = wrap_cek_for_p256_recipient(
        &ephemeral_seed,
        &recipient_pub_sec1,
        None,
        &cek,
        WrapAlgorithm::Aes256,
    )
    .expect("wrap");
    let originator = OriginatorIdRef::OriginatorKey {
        algorithm_oid: OID_EC_PUBLIC_KEY.to_vec(),
        algorithm_params: der::write_oid(&OID_SECP256R1),
        public_key: originator_point,
    };
    let kea_params = der::write_sequence(&der::write_oid(&[2u64, 16, 840, 1, 101, 3, 4, 1, 45]));
    let recipient_slot = KariRecipientPlain {
        rid: KariRecipientIdRef::RecipientKeyIdentifier {
            ski: recipient_ski.clone(),
            date: None,
            other: None,
        },
        encrypted_key: wrapped_cek,
    };
    let envelope = build_envelope_kari_aes256(
        &originator,
        None,
        &OID_DH_SINGLE_PASS_STDDH_SHA256_KDF,
        &kea_params,
        &[recipient_slot],
        &plaintext,
        &cek,
        &env_iv,
    );

    let file_key = derive_file_key_sha256(&seed, std::slice::from_ref(&envelope), 32);
    let handler = StandardHandler {
        key: file_key,
        method: CryptMethod::Aes256,
        revision: 6,
    };

    let title = "KARI SKI form Title";
    let info_title_str = encrypt_object_aes256(&handler, 5, title.as_bytes());
    let content_cipher = encrypt_object_aes256(&handler, 4, b"q\n0 1 0 rg\n10 10 80 80 re\nf\nQ\n");

    // Same minimal PDF skeleton.
    let mut bytes = Vec::with_capacity(8192);
    bytes.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
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
    let encrypt_dict = format!(
        "6 0 obj\n<< /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.s5 /V 5 /R 6 \
         /Length 256 /P -4 \
         /CF << /DefaultCryptFilter << /CFM /AESV3 /Length 32 /Recipients [<{recipients}>] >> >> \
         /StmF /DefaultCryptFilter /StrF /DefaultCryptFilter \
         /Recipients [<{recipients}>] >>\nendobj\n",
        recipients = recipients_hex,
    );
    bytes.extend_from_slice(encrypt_dict.as_bytes());
    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n0 7\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for &off in &offsets[1..7] {
        bytes.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    let file_id = b"OXIDEAV-PUBSEC-KARI-SKI-0123!XYZ".to_vec();
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

    // Cert: dummy issuer + serial (not used because RID is SKI), but
    // the spki_pubkey_bits drives the SHA-1 SKI hash.
    let cert = Certificate {
        issuer_der: der::write_sequence(b"O=Other"),
        serial: vec![0xFF],
        spki_pubkey_bits: Some(recipient_pub_sec1),
        validity: None,
        ..Default::default()
    };
    let credential = PubSecCredential::from_parsed_ec_p256(cert, recipient_scalar);

    let scene = read_pdf_to_scene_with_certificate(&bytes, &credential).expect("KARI SKI decrypt");
    assert_eq!(scene.metadata.title.as_deref(), Some(title));
}

/// Wrong EC private key → file decrypts with wrong CEK → returns the
/// "no certificate matched" error path. (The reader can't actually
/// distinguish "wrong key produced garbage" from "no recipient
/// matched" because AES-CBC has no integrity check; we expect either
/// the certificate-mismatch error or a decrypt error from PKCS#7
/// padding validation.)
#[test]
fn kari_wrong_ec_key_does_not_decrypt() {
    let (pdf, _correct) = build_kari_pubsec_pdf("doc");
    // Build a totally different recipient.
    let rogue_seed: [u8; 32] = [0x99u8; 32];
    let (rogue_scalar, rogue_pub) = p256_keypair_from(&rogue_seed);
    // Use a wholly different identity so even the IAS doesn't match
    // the recipient slot — the matcher stops before attempting unwrap.
    let cert = Certificate {
        issuer_der: der::write_sequence(b"O=Rogue"),
        serial: vec![0xEE],
        spki_pubkey_bits: Some(rogue_pub),
        validity: None,
        ..Default::default()
    };
    let bad_cred = PubSecCredential::from_parsed_ec_p256(cert, rogue_scalar);
    let err = read_pdf_to_scene_with_certificate(&pdf, &bad_cred).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("certificate did not match") || msg.contains("decrypt"),
        "unexpected error: {msg}"
    );
}
