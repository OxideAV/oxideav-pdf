//! Round-17 — `/EncryptMetadata false` end-to-end through the KARI
//! writer + reader path.
//!
//! Counterpart to `tests/encrypt_metadata_false.rs` for the password
//! standard handler (KTRI). The round-15/16 KARI writer already plumbs
//! `PubSecKariConfig::encrypt_metadata` into both the `/Encrypt` dict
//! entry AND the `0xFFFFFFFF` opt-in tail of the SHA-256 file-key
//! derivation per ISO 32000-2 §7.6.5.3 — this test simply confirms
//! both legs of that wiring round-trip when `encrypt_metadata = false`.
//!
//! Provenance: ISO 32000-1 §7.6.3.2 + ISO 32000-2 §7.6.5.3 + RFC 5652
//! §6.2.2 + RFC 5753 §7.1 only.

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
    Scene {
        pages: Some(vec![Page {
            content: frame,
            width: 100.0,
            height: 100.0,
            label: None,
            orientation: 0,
        }]),
        metadata: oxideav_scene::Metadata {
            title: Some(title.to_string()),
            author: Some("Round 17".into()),
            ..Default::default()
        },
        ..Scene::default()
    }
}

fn p256_keypair(scalar: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    let sk = SecretKey::from_slice(scalar).expect("scalar valid");
    let pub_sec1 = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
    (scalar.to_vec(), pub_sec1)
}

#[test]
fn p256_kari_with_encrypt_metadata_false_round_trips() {
    let (recipient_scalar, recipient_pub) = p256_keypair(&[0x21; 32]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI EncryptMetadata=false");
    let serial = vec![0x17, 0x01];
    let recipient = KariRecipient::p256(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0x55; 32],
    );
    let scene = small_scene("Cleartext-meta KARI P-256");

    let mut cfg = PubSecKariConfig::aes256(vec![recipient]);
    cfg.encrypt_metadata = false;

    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI EM=false PDF");
    let s = String::from_utf8_lossy(&pdf);
    assert!(
        s.contains("/EncryptMetadata false"),
        "/Encrypt dict must carry /EncryptMetadata false (round-17 KARI EM=false)"
    );

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
        ..Default::default()
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::P256, recipient_scalar);
    let opened =
        read_pdf_to_scene_with_certificate(&pdf, &cred).expect("read KARI EM=false round-trip");
    assert_eq!(
        opened.metadata.title.as_deref(),
        Some("Cleartext-meta KARI P-256")
    );
    assert_eq!(opened.metadata.author.as_deref(), Some("Round 17"));
    let pages = opened.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

#[test]
fn p256_kari_default_encrypt_metadata_true_does_not_emit_flag() {
    // Regression: the default `encrypt_metadata = true` path must NOT
    // emit `/EncryptMetadata false` (only the false case is signalled
    // — same convention the password standard handler uses).
    let (recipient_scalar, recipient_pub) = p256_keypair(&[0x33; 32]);
    let issuer_der = der::write_sequence(b"O=OxideAV KARI EM-default");
    let serial = vec![0x17, 0x02];
    let recipient = KariRecipient::p256(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0x66; 32],
    );
    let scene = small_scene("Default-meta KARI");
    let cfg = PubSecKariConfig::aes256(vec![recipient]);
    assert!(cfg.encrypt_metadata, "default should be true");
    let pdf = write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI default PDF");
    let s = String::from_utf8_lossy(&pdf);
    assert!(
        !s.contains("/EncryptMetadata false"),
        "default-true KARI must not emit /EncryptMetadata false"
    );
    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
        ..Default::default()
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::P256, recipient_scalar);
    let opened =
        read_pdf_to_scene_with_certificate(&pdf, &cred).expect("read KARI default round-trip");
    assert_eq!(opened.metadata.title.as_deref(), Some("Default-meta KARI"));
}

#[test]
fn x25519_kari_with_encrypt_metadata_false_round_trips() {
    // Same surface for X25519: the `0xFFFFFFFF` SHA-256 tail is
    // identical regardless of the KARI curve — it's a property of the
    // file-key derivation step, not the envelope's KEA scheme.
    use x25519_dalek::{PublicKey, StaticSecret};
    let scalar_arr = [0x88u8; 32];
    let secret = StaticSecret::from(scalar_arr);
    let recipient_pub = PublicKey::from(&secret).as_bytes().to_vec();

    let issuer_der = der::write_sequence(b"O=OxideAV KARI X25519 EM=false");
    let serial = vec![0x17, 0x03];
    let recipient = KariRecipient::x25519(
        issuer_der.clone(),
        serial.clone(),
        recipient_pub.clone(),
        vec![0xAA; 32],
    );
    let scene = small_scene("Cleartext-meta KARI X25519");

    let mut cfg = PubSecKariConfig::aes256(vec![recipient]);
    cfg.encrypt_metadata = false;

    let pdf =
        write_pdf_from_scene_pubsec_kari(&scene, &cfg).expect("write KARI X25519 EM=false PDF");
    assert!(String::from_utf8_lossy(&pdf).contains("/EncryptMetadata false"));

    let cert = Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(recipient_pub),
        validity: None,
        ..Default::default()
    };
    let cred = PubSecCredential::from_parsed_ec(cert, KariCurve::X25519, scalar_arr.to_vec());
    let opened = read_pdf_to_scene_with_certificate(&pdf, &cred)
        .expect("read KARI X25519 EM=false round-trip");
    assert_eq!(
        opened.metadata.title.as_deref(),
        Some("Cleartext-meta KARI X25519")
    );
}
