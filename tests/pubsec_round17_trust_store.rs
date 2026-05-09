//! Round-17 — long-term originator certificate via [`TrustStore`].
//!
//! Builds KARI-encrypted PDFs whose `OriginatorIdentifierOrKey` is the
//! `IssuerAndSerial` or `SubjectKeyIdentifier` form (RFC 5652 §6.2.2)
//! rather than the in-band `OriginatorPublicKey` form. The recipient
//! looks up the originator cert in their own [`TrustStore`] and pulls
//! the SEC1-encoded public point from the cert's SPKI bits — the rest
//! of the unwrap (ECDH + KDF + AES-KW) is identical to the round-14
//! in-band path.
//!
//! Provenance: RFC 5652 §6.2.2 (`OriginatorIdentifierOrKey` CHOICE) +
//! RFC 5280 §4.1.2.2 / §4.2.1.2 + RFC 5480 §2.2 + RFC 5753 §7.1 +
//! RFC 3394 only.

use oxideav_pdf::decrypt::{CryptMethod, StandardHandler};
use oxideav_pdf::pubsec::cms_build::{
    build_envelope_kari_aes256, KariRecipientIdRef, KariRecipientPlain, OriginatorIdRef,
};
use oxideav_pdf::pubsec::der;
use oxideav_pdf::pubsec::kari::{
    wrap_cek_for_p256_recipient, KariCurve, WrapAlgorithm, OID_DH_SINGLE_PASS_STDDH_SHA256_KDF,
};
use oxideav_pdf::pubsec::x509::Certificate;
use oxideav_pdf::{
    read_pdf_to_scene_with_certificate, read_pdf_to_scene_with_certificate_and_trust_store,
    CertRef, PubSecCredential, TrustStore,
};

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

fn p256_keypair_from(scalar: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    let sk = SecretKey::from_slice(scalar).expect("scalar valid");
    let point = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
    (scalar.to_vec(), point)
}

/// Build a KARI-encrypted PDF whose originator side is a long-term
/// `IssuerAndSerial` or `SubjectKeyIdentifier` reference (the recipient
/// is expected to resolve the originator cert through a TrustStore).
///
/// Returns `(pdf_bytes, recipient_cert, recipient_scalar, originator_cert)`.
/// Test caller installs `originator_cert` into a TrustStore + opens with
/// the recipient credential.
#[allow(clippy::too_many_arguments)]
fn build_kari_pubsec_pdf_long_term_originator(
    title: &str,
    use_ski_originator: bool,
) -> (Vec<u8>, Certificate, Vec<u8>, Certificate) {
    // Recipient's EC keypair.
    let recipient_seed: [u8; 32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x40,
    ];
    let (recipient_scalar, recipient_pub_sec1) = p256_keypair_from(&recipient_seed);

    // Originator's static / long-term EC keypair (referenced from the
    // envelope by IAS or SKI).
    let originator_seed: [u8; 32] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
        0x8E, 0x8F,
    ];
    let (_originator_scalar, originator_pub_sec1) = p256_keypair_from(&originator_seed);

    // Recipient cert (synthetic — the round-14 fixture pattern).
    let recipient_issuer_der = der::write_sequence(b"O=OxideAV recipient CA");
    let recipient_serial = vec![0xC0, 0xCA, 0xFE];
    let recipient_cert = Certificate {
        issuer_der: recipient_issuer_der.clone(),
        serial: recipient_serial.clone(),
        spki_pubkey_bits: Some(recipient_pub_sec1.clone()),
    };

    // Originator long-term cert. Stored in the trust store under both
    // forms (IAS + SKI). The SPKI BIT STRING contents IS the SEC1
    // public point per RFC 5480 §2.2.
    let originator_issuer_der = der::write_sequence(b"O=OxideAV originator CA");
    let originator_serial = vec![0xBE, 0xEF, 0x42];
    let originator_cert = Certificate {
        issuer_der: originator_issuer_der.clone(),
        serial: originator_serial.clone(),
        spki_pubkey_bits: Some(originator_pub_sec1.clone()),
    };
    let originator_ski = originator_cert.subject_key_identifier().expect("SKI");

    // The originator side normally generates an EPHEMERAL keypair per
    // envelope, but for the long-term-cert form the originator IS the
    // long-term key — so we ECDH against the static keypair.
    let cek: [u8; 32] = [0xAAu8; 32];
    let env_iv: [u8; 16] = [0xBBu8; 16];
    let seed = [0x5Au8; 20];
    let mut plaintext = Vec::with_capacity(24);
    plaintext.extend_from_slice(&seed);
    plaintext.extend_from_slice(&((-4i32) as u32).to_be_bytes());

    // Wrap the CEK using the static long-term originator scalar.
    let ukm = b"OXIDEAV-RT-17-LONG-TERM-1";
    let (originator_pub_returned, wrapped_cek) = wrap_cek_for_p256_recipient(
        &originator_seed, // long-term scalar (NOT a fresh ephemeral)
        &recipient_pub_sec1,
        Some(ukm),
        &cek,
        WrapAlgorithm::Aes256,
    )
    .expect("wrap CEK");
    // Sanity check: the originator public the wrap helper returns must
    // match what we put in the trust store.
    assert_eq!(originator_pub_returned, originator_pub_sec1);

    // Build the KARI envelope DER with a long-term-cert originator
    // identifier.
    let originator_id = if use_ski_originator {
        OriginatorIdRef::SubjectKeyIdentifier {
            ski: originator_ski.clone(),
        }
    } else {
        OriginatorIdRef::IssuerAndSerial {
            issuer_der: originator_issuer_der.clone(),
            serial: originator_serial.clone(),
        }
    };
    let aes256_wrap_oid = [2u64, 16, 840, 1, 101, 3, 4, 1, 45];
    let kea_params = der::write_sequence(&der::write_oid(&aes256_wrap_oid));
    let recipient_slot = KariRecipientPlain {
        rid: KariRecipientIdRef::IssuerAndSerial {
            issuer_der: recipient_issuer_der.clone(),
            serial: recipient_serial.clone(),
        },
        encrypted_key: wrapped_cek,
    };
    let envelope = build_envelope_kari_aes256(
        &originator_id,
        Some(ukm),
        &OID_DH_SINGLE_PASS_STDDH_SHA256_KDF,
        &kea_params,
        &[recipient_slot],
        &plaintext,
        &cek,
        &env_iv,
    );

    // File-key derivation (matches `derive_file_key_sha256`).
    let file_key = derive_file_key_sha256(&seed, std::slice::from_ref(&envelope), 32);
    let handler = StandardHandler {
        key: file_key,
        method: CryptMethod::Aes256,
        revision: 6,
    };

    let info_title_str = encrypt_object_aes256(&handler, 5, title.as_bytes());
    let content_plain = b"q\n0 0 1 rg\n10 10 80 80 re\nf\nQ\n".to_vec();
    let content_cipher = encrypt_object_aes256(&handler, 4, &content_plain);

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
    bytes.extend_from_slice(
        format!(
            "6 0 obj\n<< /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.s5 /V 5 /R 6 /Length 256 \
             /P -4 /CF << /DefaultCryptFilter << /Type /CryptFilter /CFM /AESV3 /Length 32 \
             /Recipients [<{recipients_hex}>] >> >> /StmF /DefaultCryptFilter \
             /StrF /DefaultCryptFilter /Recipients [<{recipients_hex}>] >>\nendobj\n"
        )
        .as_bytes(),
    );

    let xref_off = bytes.len();
    bytes.extend_from_slice(b"xref\n0 7\n0000000000 65535 f \n");
    for off in &offsets[1..] {
        bytes.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    bytes.extend_from_slice(
        format!(
            "trailer\n<< /Size 7 /Root 1 0 R /Info 5 0 R /Encrypt 6 0 R \
             /ID [<00112233445566778899AABBCCDDEEFF> <FFEEDDCCBBAA99887766554433221100>] >>\n\
             startxref\n{xref_off}\n%%EOF\n",
        )
        .as_bytes(),
    );
    (bytes, recipient_cert, recipient_scalar, originator_cert)
}

#[test]
fn long_term_ias_originator_via_trust_store() {
    let (pdf, recipient_cert, recipient_scalar, originator_cert) =
        build_kari_pubsec_pdf_long_term_originator("KARI long-term IAS", false);
    let cred = PubSecCredential::from_parsed_ec(recipient_cert, KariCurve::P256, recipient_scalar);

    // Sanity check: without the trust store, the unwrap MUST refuse —
    // the originator is identified by IAS and we cannot resolve it.
    let no_store_err = read_pdf_to_scene_with_certificate(&pdf, &cred).unwrap_err();
    let msg = format!("{no_store_err}");
    assert!(
        msg.contains("TrustStore") || msg.contains("OriginatorPublicKey"),
        "unexpected error without trust store: {msg}"
    );

    // With the trust store loaded — round-trip.
    let mut store = TrustStore::new();
    store.insert_certificate(originator_cert);
    let opened = read_pdf_to_scene_with_certificate_and_trust_store(&pdf, &cred, &store)
        .expect("trust-store IAS round-trip");
    assert_eq!(opened.metadata.title.as_deref(), Some("KARI long-term IAS"));
}

#[test]
fn long_term_ski_originator_via_trust_store() {
    let (pdf, recipient_cert, recipient_scalar, originator_cert) =
        build_kari_pubsec_pdf_long_term_originator("KARI long-term SKI", true);
    let cred = PubSecCredential::from_parsed_ec(recipient_cert, KariCurve::P256, recipient_scalar);
    let mut store = TrustStore::new();
    store.insert_certificate(originator_cert);
    let opened = read_pdf_to_scene_with_certificate_and_trust_store(&pdf, &cred, &store)
        .expect("trust-store SKI round-trip");
    assert_eq!(opened.metadata.title.as_deref(), Some("KARI long-term SKI"));
}

#[test]
fn missing_originator_cert_in_trust_store_fails_cleanly() {
    let (pdf, recipient_cert, recipient_scalar, _originator_cert) =
        build_kari_pubsec_pdf_long_term_originator("KARI missing cert", false);
    let cred = PubSecCredential::from_parsed_ec(recipient_cert, KariCurve::P256, recipient_scalar);

    // Trust store is populated with a DIFFERENT cert (wrong issuer) —
    // the lookup must miss + the open must fail.
    let mut store = TrustStore::new();
    store.insert(
        CertRef::IssuerAndSerial {
            issuer_der: der::write_sequence(b"O=Wrong CA"),
            serial: vec![0xFF, 0xEE],
        },
        Certificate {
            issuer_der: der::write_sequence(b"O=Wrong CA"),
            serial: vec![0xFF, 0xEE],
            spki_pubkey_bits: Some(vec![0x04; 65]),
        },
    );
    let err = read_pdf_to_scene_with_certificate_and_trust_store(&pdf, &cred, &store).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("not found in TrustStore") || msg.contains("did not match"),
        "unexpected error: {msg}"
    );
}

#[test]
fn wrong_originator_cert_in_trust_store_fails_cleanly() {
    // A trust store entry exists under the right key, but its
    // SPKI bits are the wrong public point — ECDH succeeds but yields
    // the wrong shared secret, which makes AES-KW fail.
    let (pdf, recipient_cert, recipient_scalar, originator_cert) =
        build_kari_pubsec_pdf_long_term_originator("KARI wrong cert", false);
    let cred = PubSecCredential::from_parsed_ec(recipient_cert, KariCurve::P256, recipient_scalar);

    // Replace the cert's SPKI bits with a different but well-formed
    // P-256 public point.
    let wrong_seed = [0xCDu8; 32];
    let (_wrong_scalar, wrong_pub) = p256_keypair_from(&wrong_seed);
    let mut wrong_cert = originator_cert.clone();
    wrong_cert.spki_pubkey_bits = Some(wrong_pub);

    let mut store = TrustStore::new();
    store.insert_certificate(wrong_cert);

    let err = read_pdf_to_scene_with_certificate_and_trust_store(&pdf, &cred, &store).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("AES-KW") || msg.contains("unwrap") || msg.contains("decrypt"),
        "unexpected error: {msg}"
    );
}
