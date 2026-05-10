//! Round-24 integration tests — X448 KARI encode + read round-trips
//! across the four RFC 8418 binding flavours valid for X448 (X9.63 with
//! SHA-512 + HKDF SHA-256/384/512). Builds a real PDF via
//! [`oxideav_pdf::write_pdf_from_scene_pubsec_kari`] and re-opens it
//! through the round-14 reader entry point
//! [`oxideav_pdf::read_pdf_to_scene_with_certificate`], symmetric to
//! the round-16 X25519 + P-521 coverage.
//!
//! Provenance: ISO 32000-1 §7.6.4 + ISO 32000-2 §7.6.5 + RFC 5652
//! §6.2.2 + RFC 7748 §5 + RFC 8410 §3 + RFC 8418 §2.1 + §2.2 + RFC 5869
//! (HKDF) + RFC 3394 only.

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
                fill: Some(Paint::Solid(Rgba::opaque(60, 130, 220))),
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

/// X448 keypair from a deterministic 56-byte scalar (RFC 7748 §5
/// clamping is applied inside the `x448` crate at scalar load).
fn x448_keypair(scalar_arr: [u8; 56]) -> (Vec<u8>, Vec<u8>) {
    use x448::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(scalar_arr);
    let pub_bytes = PublicKey::from(&secret).as_bytes().to_vec();
    (scalar_arr.to_vec(), pub_bytes)
}

/// Round-24 X448 + X9.63-SHA-512 writer + reader round-trip — exercises
/// the default KARI binding for X448 (`dhSinglePass-stdDH-sha512kdf-scheme`,
/// OID 1.3.132.1.11.3 — the security-strength match for X448's 224-bit
/// level per RFC 8418 §2.1).
#[test]
fn x448_x963_sha512_kari_writer_then_reader_round_trip() {
    let (recipient_scalar, recipient_pub) = x448_keypair([0x42; 56]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI X448 X9.63-512");
    let serial = vec![0x04, 0x48];
    let recipient = KariRecipient::x448(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0x88; 56],
    );
    let mut cfg = PubSecKariConfig::aes256(vec![recipient]);
    cfg.ukm = Some(b"OXIDEAV-X448-963-512-UKM".to_vec());
    let scene = small_scene("KARI X448 X9.63-SHA-512 round-trip");
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI X448 PDF");

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
        ..Default::default()
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::X448, recipient_scalar);
    let opened =
        read_pdf_to_scene_with_certificate(&pdf, &cred).expect("read X448 KARI round-trip");
    assert_eq!(
        opened.metadata.title.as_deref(),
        Some("KARI X448 X9.63-SHA-512 round-trip")
    );
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
}

/// Round-24: X448 + RFC 8418 §2.2 HKDF-SHA-256 binding round-trip.
/// `dhSinglePass-stdDH-hkdf-sha256-scheme`, smime-alg 19. Exercises the
/// present-UKM (HKDF salt) path.
#[test]
fn x448_hkdf_sha256_kari_writer_then_reader_round_trip() {
    let (recipient_scalar, recipient_pub) = x448_keypair([0x35; 56]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI X448 HKDF-256");
    let serial = vec![0x19];
    let recipient = KariRecipient::x448_hkdf_sha256(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0x66; 56],
    );
    let mut cfg = PubSecKariConfig::aes256(vec![recipient]);
    cfg.ukm = Some(b"OXIDEAV-X448-HKDF-256-UKM".to_vec());
    let scene = small_scene("KARI X448 HKDF-SHA-256 round-trip");
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI X448 HKDF-256 PDF");

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
        ..Default::default()
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::X448, recipient_scalar);
    let opened = read_pdf_to_scene_with_certificate(&pdf, &cred)
        .expect("read X448 HKDF-256 KARI round-trip");
    assert_eq!(
        opened.metadata.title.as_deref(),
        Some("KARI X448 HKDF-SHA-256 round-trip")
    );
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

/// Round-24: X448 + RFC 8418 §2.2 HKDF-SHA-384 binding round-trip
/// (smime-alg 20). Exercises the absent-UKM (salt = None) path.
#[test]
fn x448_hkdf_sha384_kari_writer_then_reader_round_trip() {
    let (recipient_scalar, recipient_pub) = x448_keypair([0x84; 56]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI X448 HKDF-384");
    let serial = vec![0x20];
    let recipient = KariRecipient::x448_hkdf_sha384(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0xC4; 56],
    );
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    // No UKM — verifies the HKDF salt-absent path is wired correctly
    // for X448 just as it is for X25519.
    assert!(cfg.ukm.is_none());
    let scene = small_scene("KARI X448 HKDF-SHA-384 round-trip");
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI X448 HKDF-384 PDF");

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
        ..Default::default()
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::X448, recipient_scalar);
    let opened = read_pdf_to_scene_with_certificate(&pdf, &cred)
        .expect("read X448 HKDF-384 KARI round-trip");
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

/// Round-24: X448 + RFC 8418 §2.2 HKDF-SHA-512 binding round-trip
/// (smime-alg 21 — the security-strength match under the modern HKDF
/// binding for X448's 224-bit level).
#[test]
fn x448_hkdf_sha512_kari_writer_then_reader_round_trip() {
    let (recipient_scalar, recipient_pub) = x448_keypair([0x12; 56]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI X448 HKDF-512");
    let serial = vec![0x21];
    let recipient = KariRecipient::x448_hkdf_sha512(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0xE9; 56],
    );
    let mut cfg = PubSecKariConfig::aes256(vec![recipient]);
    cfg.ukm = Some(b"x448-hkdf-sha-512-ukm".to_vec());
    let scene = small_scene("KARI X448 HKDF-SHA-512 round-trip");
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI X448 HKDF-512 PDF");

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
        ..Default::default()
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::X448, recipient_scalar);
    let opened = read_pdf_to_scene_with_certificate(&pdf, &cred)
        .expect("read X448 HKDF-512 KARI round-trip");
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

/// Round-24 negative: an X25519 credential cannot open an X448 KARI
/// envelope (the curve mismatch is caught structurally — the KEA OID
/// names sha512kdf which is not a valid binding for X25519 per the
/// `is_valid_for` matrix).
#[test]
fn x25519_credential_does_not_open_x448_kari() {
    let (_, recipient_pub) = x448_keypair([0x55; 56]);
    let issuer_der = der::write_sequence(b"O=OxideAV X448 negative");
    let serial = vec![0x99];
    let recipient = KariRecipient::x448(issuer_der, serial, recipient_pub, vec![0xAA; 56]);
    let scene = small_scene("KARI X448 cross-curve negative");
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write");

    // X25519 credential — wrong curve. Reader should refuse to match
    // (the KEA OID names sha512kdf which X25519 is not bound to in our
    // `is_valid_for` matrix).
    let bad_scalar = [0xCCu8; 32];
    let bad_cert = Certificate {
        issuer_der: der::write_sequence(b"O=Rogue X25519"),
        serial: vec![0xEE],
        spki_pubkey_bits: Some(vec![0x66u8; 32]),
        validity: None,
        ..Default::default()
    };
    let bad_cred =
        PubSecCredential::from_parsed_ec(bad_cert, KariCurve::X25519, bad_scalar.to_vec());
    let err = read_pdf_to_scene_with_certificate(&pdf, &bad_cred).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("certificate did not match") || msg.contains("decrypt"),
        "unexpected error: {msg}"
    );
}

/// Round-24 negative: a wrong X448 scalar against the same identity
/// (same issuer/serial pair) fails AES-KW unwrap — the matcher picks
/// the slot but unwraps with a wrong KEK. Symmetric to the X25519
/// HKDF wrong-scalar test in round-16 coverage.
#[test]
fn wrong_x448_scalar_fails_decrypt() {
    let (_, recipient_pub) = x448_keypair([0x77; 56]);
    let issuer_der = der::write_sequence(b"O=OxideAV X448 wrong-scalar");
    let serial = vec![0x01];
    let recipient = KariRecipient::x448_hkdf_sha512(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub,
        vec![0x33; 56],
    );
    let scene = small_scene("doc");
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write");

    // Same identity (issuer/serial), but a *different* X448 scalar.
    let (rogue_scalar, rogue_pub) = x448_keypair([0x99; 56]);
    let bad_cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(rogue_pub),
        validity: None,
        ..Default::default()
    };
    let bad_cred = PubSecCredential::from_parsed_ec(bad_cert, KariCurve::X448, rogue_scalar);
    let err = read_pdf_to_scene_with_certificate(&pdf, &bad_cred).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("AES-KW") || msg.contains("unwrap") || msg.contains("decrypt"),
        "unexpected error: {msg}"
    );
}

/// Round-24: multi-curve mixed envelope — one KARI envelope contains
/// one X448 recipient AND one X25519 recipient, both wrapping the same
/// AES-256 CEK. Either credential opens the document. Mirrors the
/// round-15/16 multi-curve mix tests.
#[test]
fn x448_mixed_with_x25519_in_one_envelope() {
    use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Secret};
    let (x448_scalar, x448_pub) = x448_keypair([0x7Au8; 56]);
    let x25519_scalar_arr = [0x1Bu8; 32];
    let x25519_secret = X25519Secret::from(x25519_scalar_arr);
    let x25519_pub = X25519Pub::from(&x25519_secret).as_bytes().to_vec();

    let x448_issuer = der::write_sequence(b"O=OxideAV mixed X448");
    let x448_serial = vec![0xAA];
    let x25519_issuer = der::write_sequence(b"O=OxideAV mixed X25519");
    let x25519_serial = vec![0xBB];

    let r_x448 = KariRecipient::x448(
        x448_issuer.clone(),
        x448_serial.clone(),
        x448_pub.clone(),
        vec![0x91u8; 56],
    );
    let r_x25519 = KariRecipient::x25519_hkdf_sha256(
        x25519_issuer.clone(),
        x25519_serial.clone(),
        x25519_pub.clone(),
        vec![0x55u8; 32],
    );
    let mut cfg = PubSecKariConfig::aes256(vec![r_x448, r_x25519]);
    cfg.ukm = Some(b"mixed-x448-x25519".to_vec());
    let scene = small_scene("KARI mixed X448 + X25519");
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write mixed");

    // Open as the X448 recipient.
    let x448_cert = Certificate {
        issuer_der: x448_issuer,
        serial: x448_serial,
        spki_pubkey_bits: Some(x448_pub),
        validity: None,
        ..Default::default()
    };
    let x448_cred = PubSecCredential::from_parsed_ec(x448_cert, KariCurve::X448, x448_scalar);
    let opened_a = read_pdf_to_scene_with_certificate(&pdf, &x448_cred).expect("open as X448");
    assert_eq!(
        opened_a.metadata.title.as_deref(),
        Some("KARI mixed X448 + X25519")
    );

    // Open the same PDF as the X25519 recipient.
    let x25519_cert = Certificate {
        issuer_der: x25519_issuer,
        serial: x25519_serial,
        spki_pubkey_bits: Some(x25519_pub),
        validity: None,
        ..Default::default()
    };
    let x25519_cred = PubSecCredential::from_parsed_ec(
        x25519_cert,
        KariCurve::X25519,
        x25519_scalar_arr.to_vec(),
    );
    let opened_b = read_pdf_to_scene_with_certificate(&pdf, &x25519_cred).expect("open as X25519");
    assert_eq!(
        opened_b.metadata.title.as_deref(),
        Some("KARI mixed X448 + X25519")
    );
}
