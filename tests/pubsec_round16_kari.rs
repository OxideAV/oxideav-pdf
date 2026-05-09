//! Round-16 integration tests — P-521 + RFC 8418 §2.2 HKDF-SHA-256/384/512
//! KARI encode + read round-trips. Builds a real PDF via
//! [`oxideav_pdf::write_pdf_from_scene_pubsec_kari`] and re-opens it
//! through the round-14 reader entry point
//! [`oxideav_pdf::read_pdf_to_scene_with_certificate`].
//!
//! Provenance: ISO 32000-1 §7.6.4 + ISO 32000-2 §7.6.5 + RFC 5652
//! §6.2.2 + RFC 5753 §7.1.4 + RFC 8418 §2.1 + §2.2 + RFC 5869 (HKDF) +
//! RFC 3394 only.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::pubsec::der;
use oxideav_pdf::pubsec::kari::KariCurve;
use oxideav_pdf::pubsec::x509::Certificate;
use oxideav_pdf::{
    read_pdf_to_scene_with_certificate, write_pdf_from_scene_pubsec_kari, KariRecipient,
    PubSecCredential, PubSecKariConfig,
};
use oxideav_scene::{Page, Scene};

fn small_scene(title: &str) -> Scene {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(90.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(90.0, 90.0)));
    p.commands.push(PathCommand::LineTo(Point::new(10.0, 90.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 100.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(40, 200, 80))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let metadata = oxideav_scene::Metadata {
        title: Some(title.to_string()),
        ..Default::default()
    };
    Scene {
        pages: Some(vec![Page {
            content: frame,
            width: 100.0,
            height: 100.0,
            label: None,
            orientation: 0,
        }]),
        metadata,
        ..Scene::default()
    }
}

/// P-521 keypair from a deterministic 66-byte scalar. Leading byte
/// pinned to 0x00 so the scalar stays below the curve order n.
fn p521_keypair(mut scalar: [u8; 66]) -> (Vec<u8>, Vec<u8>) {
    scalar[0] = 0x00;
    use p521::elliptic_curve::sec1::ToEncodedPoint;
    use p521::SecretKey;
    let sk = SecretKey::from_slice(&scalar).expect("scalar valid");
    let pub_sec1 = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
    (scalar.to_vec(), pub_sec1)
}

/// X25519 keypair from a deterministic 32-byte scalar.
fn x25519_keypair(scalar_arr: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(scalar_arr);
    let pub_bytes = PublicKey::from(&secret).as_bytes().to_vec();
    (scalar_arr.to_vec(), pub_bytes)
}

/// Round-16 P-521 writer + reader round-trip — exercises the
/// `dhSinglePass-stdDH-sha512kdf-scheme` path end-to-end (RFC 5753
/// §7.1.4, OID 1.3.132.1.11.3).
#[test]
fn p521_kari_writer_then_reader_round_trip() {
    let (recipient_scalar, recipient_pub) = p521_keypair([0x42; 66]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI P-521 round-trip");
    let serial = vec![0x05, 0x21];
    let mut ephemeral_scalar = [0x88u8; 66];
    ephemeral_scalar[0] = 0x00;
    let recipient = KariRecipient::p521(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        ephemeral_scalar.to_vec(),
    );
    let scene = small_scene("KARI P-521 writer round-trip");
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI P-521 PDF");

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::P521, recipient_scalar);
    let opened =
        read_pdf_to_scene_with_certificate(&pdf, &cred).expect("read P-521 KARI round-trip");
    assert_eq!(
        opened.metadata.title.as_deref(),
        Some("KARI P-521 writer round-trip")
    );
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
}

/// Round-16: X25519 + RFC 8418 §2.2 HKDF-SHA-256 binding round-trip.
/// `dhSinglePass-stdDH-hkdf-sha256-scheme`, smime-alg 19.
#[test]
fn x25519_hkdf_sha256_kari_writer_then_reader_round_trip() {
    let (recipient_scalar, recipient_pub) = x25519_keypair([0x35; 32]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI X25519 HKDF-256");
    let serial = vec![0x19];
    let recipient = KariRecipient::x25519_hkdf_sha256(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0x66; 32],
    );
    let mut cfg = PubSecKariConfig::aes256(vec![recipient]);
    // HKDF salt = ukm: exercise the present-UKM path.
    cfg.ukm = Some(b"OXIDEAV-RFC8418-2-2-UKM".to_vec());
    let scene = small_scene("KARI X25519 HKDF-SHA-256 round-trip");
    let pdf =
        write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI X25519 HKDF-256 PDF");

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::X25519, recipient_scalar);
    let opened = read_pdf_to_scene_with_certificate(&pdf, &cred)
        .expect("read X25519 HKDF-256 KARI round-trip");
    assert_eq!(
        opened.metadata.title.as_deref(),
        Some("KARI X25519 HKDF-SHA-256 round-trip")
    );
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

/// Round-16: X25519 + RFC 8418 §2.2 HKDF-SHA-384 binding round-trip
/// (smime-alg 20). Exercises the absent-UKM (salt = None) path.
#[test]
fn x25519_hkdf_sha384_kari_writer_then_reader_round_trip() {
    let (recipient_scalar, recipient_pub) = x25519_keypair([0x84; 32]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI X25519 HKDF-384");
    let serial = vec![0x20];
    let recipient = KariRecipient::x25519_hkdf_sha384(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0xC4; 32],
    );
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    // No UKM — verifies the HKDF salt-absent path is wired correctly.
    assert!(cfg.ukm.is_none());
    let scene = small_scene("KARI X25519 HKDF-SHA-384 round-trip");
    let pdf =
        write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI X25519 HKDF-384 PDF");

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::X25519, recipient_scalar);
    let opened = read_pdf_to_scene_with_certificate(&pdf, &cred)
        .expect("read X25519 HKDF-384 KARI round-trip");
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

/// Round-16: X25519 + RFC 8418 §2.2 HKDF-SHA-512 binding round-trip
/// (smime-alg 21).
#[test]
fn x25519_hkdf_sha512_kari_writer_then_reader_round_trip() {
    let (recipient_scalar, recipient_pub) = x25519_keypair([0x12; 32]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI X25519 HKDF-512");
    let serial = vec![0x21];
    let recipient = KariRecipient::x25519_hkdf_sha512(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0xE9; 32],
    );
    let mut cfg = PubSecKariConfig::aes256(vec![recipient]);
    cfg.ukm = Some(b"hkdf-sha-512-ukm".to_vec());
    let scene = small_scene("KARI X25519 HKDF-SHA-512 round-trip");
    let pdf =
        write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI X25519 HKDF-512 PDF");

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::X25519, recipient_scalar);
    let opened = read_pdf_to_scene_with_certificate(&pdf, &cred)
        .expect("read X25519 HKDF-512 KARI round-trip");
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

/// Round-16 negative: a P-256 credential cannot open a P-521 KARI
/// envelope (the curve mismatch is caught structurally).
#[test]
fn p256_credential_does_not_open_p521_kari() {
    let (_, recipient_pub) = p521_keypair([0x55; 66]);
    let issuer_der = der::write_sequence(b"O=OxideAV negative");
    let serial = vec![0x99];
    let mut ephemeral_scalar = [0xAAu8; 66];
    ephemeral_scalar[0] = 0x00;
    let recipient = KariRecipient::p521(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub,
        ephemeral_scalar.to_vec(),
    );
    let scene = small_scene("KARI P-521 negative");
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write");

    // A P-256 credential — wrong curve. Reader should refuse to match
    // (the KEA OID names sha512kdf which is only valid for P-521).
    let bad_scalar = [0xCCu8; 32];
    let bad_cert = Certificate {
        issuer_der: der::write_sequence(b"O=Rogue"),
        serial: vec![0xEE],
        spki_pubkey_bits: Some(vec![0x04; 65]),
        validity: None,
    };
    let bad_cred = PubSecCredential::from_parsed_ec(bad_cert, KariCurve::P256, bad_scalar.to_vec());
    let err = read_pdf_to_scene_with_certificate(&pdf, &bad_cred).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("certificate did not match") || msg.contains("decrypt"),
        "unexpected error: {msg}"
    );
}

/// Round-16 negative: an X25519 credential targeting the X9.63 binding
/// cannot open an HKDF-bound envelope when the credential curve says
/// X25519 — it CAN, because both bindings are valid for X25519. So the
/// real negative is "wrong scalar fails to decrypt." This test confirms
/// the matcher does NOT silently accept a wrong scalar on the HKDF
/// binding (we'd see an AES-KW unwrap failure).
#[test]
fn wrong_x25519_scalar_fails_hkdf_decrypt() {
    let (_, recipient_pub) = x25519_keypair([0x77; 32]);
    let issuer_der = der::write_sequence(b"O=OxideAV X25519 HKDF neg");
    let serial = vec![0x01];
    let recipient = KariRecipient::x25519_hkdf_sha256(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub,
        vec![0x33; 32],
    );
    let scene = small_scene("doc");
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write");

    // Same identity (issuer/serial), but a *different* X25519 scalar.
    // The matcher will pick the slot but unwrap with the wrong KEK,
    // causing AES-KW to fail.
    let (rogue_scalar, rogue_pub) = x25519_keypair([0x99; 32]);
    let bad_cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(rogue_pub),
        validity: None,
    };
    let bad_cred = PubSecCredential::from_parsed_ec(bad_cert, KariCurve::X25519, rogue_scalar);
    let err = read_pdf_to_scene_with_certificate(&pdf, &bad_cred).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("AES-KW") || msg.contains("unwrap") || msg.contains("decrypt"),
        "unexpected error: {msg}"
    );
}
