//! Round-15 integration tests — KARI encode + read round-trips for
//! P-256 / P-384 / X25519. Builds a real PDF via the new writer entry
//! point [`oxideav_pdf::write_pdf_from_scene_pubsec_kari`] and re-opens
//! it through the round-14 reader path
//! [`oxideav_pdf::read_pdf_to_scene_with_certificate`].
//!
//! Provenance: ISO 32000-1 §7.6.4 + ISO 32000-2 §7.6.5 + RFC 5652
//! §6.2.2 + RFC 5753 §7.1.4 + RFC 8418 §2.1 + RFC 3394 only.

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

/// P-256 keypair from a deterministic 32-byte scalar.
fn p256_keypair(scalar: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    let sk = SecretKey::from_slice(scalar).expect("scalar valid");
    let pub_sec1 = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
    (scalar.to_vec(), pub_sec1)
}

/// P-384 keypair from a deterministic 48-byte scalar.
fn p384_keypair(scalar: &[u8; 48]) -> (Vec<u8>, Vec<u8>) {
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    use p384::SecretKey;
    let sk = SecretKey::from_slice(scalar).expect("scalar valid");
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

/// P-256 writer + reader round-trip — the round-14 curve, exercised
/// through the new round-15 writer path.
#[test]
fn p256_kari_writer_then_reader_round_trip() {
    let (recipient_scalar, recipient_pub) = p256_keypair(&[0x21; 32]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI P-256 round-trip");
    let serial = vec![0xC0, 0xCA, 0xFE];
    let recipient = KariRecipient::p256(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        // Deterministic ephemeral.
        vec![0x55; 32],
    );
    let scene = small_scene("KARI P-256 writer round-trip");
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI P-256 PDF");

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
        ..Default::default()
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::P256, recipient_scalar);
    let opened =
        read_pdf_to_scene_with_certificate(&pdf, &cred).expect("read P-256 KARI round-trip");
    assert_eq!(
        opened.metadata.title.as_deref(),
        Some("KARI P-256 writer round-trip")
    );
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
}

/// P-384 writer + reader round-trip — exercises the round-15
/// `dhSinglePass-stdDH-sha384kdf-scheme` path end-to-end.
#[test]
fn p384_kari_writer_then_reader_round_trip() {
    let (recipient_scalar, recipient_pub) = p384_keypair(&[0x42; 48]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI P-384 round-trip");
    let serial = vec![0x12, 0x34, 0x56];
    let recipient = KariRecipient::p384(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0x88; 48],
    );
    let scene = small_scene("KARI P-384 writer round-trip");
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI P-384 PDF");

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
        ..Default::default()
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::P384, recipient_scalar);
    let opened =
        read_pdf_to_scene_with_certificate(&pdf, &cred).expect("read P-384 KARI round-trip");
    assert_eq!(
        opened.metadata.title.as_deref(),
        Some("KARI P-384 writer round-trip")
    );
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

/// X25519 writer + reader round-trip — exercises the round-15
/// RFC 8418 §2.1 X9.63-SHA-256 binding path end-to-end.
#[test]
fn x25519_kari_writer_then_reader_round_trip() {
    let (recipient_scalar, recipient_pub) = x25519_keypair([0x35; 32]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI X25519 round-trip");
    let serial = vec![0x99, 0x42];
    let recipient = KariRecipient::x25519(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0x66; 32],
    );
    let scene = small_scene("KARI X25519 writer round-trip");
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI X25519 PDF");

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
        ..Default::default()
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::X25519, recipient_scalar);
    let opened =
        read_pdf_to_scene_with_certificate(&pdf, &cred).expect("read X25519 KARI round-trip");
    assert_eq!(
        opened.metadata.title.as_deref(),
        Some("KARI X25519 writer round-trip")
    );
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

/// Wrong-key on a writer-emitted KARI envelope must fail (the matcher
/// stops at IAS mismatch — same surface as the round-14 negative test
/// for the read path).
#[test]
fn wrong_curve_key_does_not_decrypt_writer_kari() {
    let (_, recipient_pub) = p256_keypair(&[0x77; 32]);
    let issuer_der = der::write_sequence(b"O=OxideAV writer-kari neg");
    let serial = vec![0x01];
    let recipient = KariRecipient::p256(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub,
        vec![0x33; 32],
    );
    let scene = small_scene("doc");
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write");

    // A rogue recipient with a totally different identity.
    let (rogue_scalar, rogue_pub) = p256_keypair(&[0x99; 32]);
    let cert = Certificate {
        issuer_der: der::write_sequence(b"O=Rogue"),
        serial: vec![0xEE],
        spki_pubkey_bits: Some(rogue_pub),
        validity: None,
        ..Default::default()
    };
    let bad_cred = PubSecCredential::from_parsed_ec(cert, KariCurve::P256, rogue_scalar);
    let err = read_pdf_to_scene_with_certificate(&pdf, &bad_cred).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("certificate did not match") || msg.contains("decrypt"),
        "unexpected error: {msg}"
    );
}
