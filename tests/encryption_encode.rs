//! Round-6 encryption *encode* tests — write side of the standard
//! security handler.
//!
//! Each test builds a Scene, asks the writer to emit it as an encrypted
//! PDF for one of the supported revision/method combinations, then
//! pipes the bytes through `read_pdf_to_scene_with_password` and
//! confirms strings + content streams round-trip.
//!
//! Two flavours of round-trip are covered:
//!
//! 1. `encode → decrypt` (single direction): the writer-derived
//!    `/Encrypt` dict + per-object encryption authenticate cleanly
//!    against the reader's `decrypt::open_with_password`.
//! 2. `encode → decrypt → re-encode → decrypt` (full bounce): the
//!    decoded scene re-encrypts to a fresh PDF that itself decrypts.
//!    Catches any non-symmetric corner of the encrypt path (RC4 is
//!    trivially symmetric; AES depends on PKCS#7 + IV handling, which
//!    is exercised by the second pass).

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::encrypt::EncryptionConfig;
use oxideav_pdf::{read_pdf_to_scene_with_password, write_pdf_from_scene_encrypted, PdfError};
use oxideav_scene::{Metadata, Page, Scene};

/// Build a minimal one-page scene with the provided title in /Info.
fn make_scene(title: &str) -> Scene {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(60.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(60.0, 60.0)));
    p.commands.push(PathCommand::LineTo(Point::new(10.0, 60.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 100.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(255, 0, 0))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let mut page = Page::new(100.0, 100.0);
    page.content = frame;
    let metadata = Metadata {
        title: Some(title.into()),
        author: Some("oxideav-pdf round-6".into()),
        ..Metadata::default()
    };
    Scene {
        pages: Some(vec![page]),
        metadata,
        ..Scene::default()
    }
}

/// Glue helper — delegate to the public encrypted writer.
fn write_encrypted(scene: &Scene, config: &EncryptionConfig) -> Result<Vec<u8>, PdfError> {
    write_pdf_from_scene_encrypted(scene, config)
}

// ─── Per-revision round-trips ─────────────────────────────────────

#[test]
fn encode_then_decrypt_r2_rc4_40() {
    let scene = make_scene("R=2 round trip");
    let cfg = EncryptionConfig::rc4_40(b"hunter2", b"OXIDEAV-ENCODE-R2-FIXED-FILE-ID!");
    let pdf = write_encrypted(&scene, &cfg).expect("write encrypted R=2");
    // Verify the trailer carries /Encrypt + /ID.
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/Encrypt"));
    assert!(s.contains("/Filter /Standard"));
    assert!(s.contains("/V 1"));
    assert!(s.contains("/R 2"));
    // Round-trip via the reader.
    let parsed = read_pdf_to_scene_with_password(&pdf, b"hunter2").expect("decrypt R=2");
    assert_eq!(parsed.metadata.title.as_deref(), Some("R=2 round trip"));
}

#[test]
fn encode_then_decrypt_r3_rc4_128() {
    let scene = make_scene("R=3 round trip");
    let cfg = EncryptionConfig::rc4_128(b"correct horse", b"OXIDEAV-ENCODE-R3-FIXED-FILE-ID!");
    let pdf = write_encrypted(&scene, &cfg).expect("write encrypted R=3");
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/V 2"));
    assert!(s.contains("/R 3"));
    let parsed = read_pdf_to_scene_with_password(&pdf, b"correct horse").expect("decrypt R=3");
    assert_eq!(parsed.metadata.title.as_deref(), Some("R=3 round trip"));
}

#[test]
fn encode_then_decrypt_r4_aes_128() {
    let scene = make_scene("R=4 AES round trip");
    let cfg = EncryptionConfig::aes_128(b"aespw", b"OXIDEAV-ENCODE-R4-FIXED-FILE-ID!");
    let pdf = write_encrypted(&scene, &cfg).expect("write encrypted R=4");
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/V 4"));
    assert!(s.contains("/R 4"));
    assert!(s.contains("/CFM /AESV2"));
    let parsed = read_pdf_to_scene_with_password(&pdf, b"aespw").expect("decrypt R=4");
    assert_eq!(parsed.metadata.title.as_deref(), Some("R=4 AES round trip"));
}

#[test]
fn encode_then_decrypt_r4_rc4_via_v4() {
    let scene = make_scene("R=4 RC4 round trip");
    let mut cfg = EncryptionConfig::aes_128(b"rc4pw", b"OXIDEAV-ENCODE-R4RC4-FIXED-FID!");
    cfg.method = oxideav_pdf::decrypt::CryptMethod::Rc4;
    let pdf = write_encrypted(&scene, &cfg).expect("write encrypted R=4 RC4");
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/V 4"));
    assert!(s.contains("/CFM /V2"));
    let parsed = read_pdf_to_scene_with_password(&pdf, b"rc4pw").expect("decrypt R=4 RC4");
    assert_eq!(parsed.metadata.title.as_deref(), Some("R=4 RC4 round trip"));
}

#[test]
fn encode_then_decrypt_r5_aes_256_adobe_l3() {
    let scene = make_scene("R=5 AES-256 round trip");
    let cfg = EncryptionConfig::aes_256_r5(b"hunter2", b"OXIDEAV-ENCODE-R5-FIXED-FILE-ID!");
    let pdf = write_encrypted(&scene, &cfg).expect("write encrypted R=5");
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/V 5"));
    assert!(s.contains("/R 5"));
    assert!(s.contains("/CFM /AESV3"));
    let parsed = read_pdf_to_scene_with_password(&pdf, b"hunter2").expect("decrypt R=5");
    assert_eq!(
        parsed.metadata.title.as_deref(),
        Some("R=5 AES-256 round trip")
    );
}

#[test]
fn encode_then_decrypt_r6_iso_2_0() {
    let scene = make_scene("R=6 ISO 2.0 round trip");
    let cfg = EncryptionConfig::aes_256_r6(b"battery staple", b"OXIDEAV-ENCODE-R6-FIXED-FILE-ID!");
    let pdf = write_encrypted(&scene, &cfg).expect("write encrypted R=6");
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/V 5"));
    assert!(s.contains("/R 6"));
    assert!(s.starts_with("%PDF-2.0"));
    let parsed = read_pdf_to_scene_with_password(&pdf, b"battery staple").expect("decrypt R=6");
    assert_eq!(
        parsed.metadata.title.as_deref(),
        Some("R=6 ISO 2.0 round trip")
    );
}

// ─── Wrong-password rejection ─────────────────────────────────────

#[test]
fn encoded_pdf_rejects_wrong_password_r3() {
    let scene = make_scene("Reject");
    let cfg = EncryptionConfig::rc4_128(b"realpw", b"OXIDEAV-ENCODE-WRONG-FILE-ID-XX!");
    let pdf = write_encrypted(&scene, &cfg).expect("write encrypted");
    let err = read_pdf_to_scene_with_password(&pdf, b"wrongpw").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("password") || msg.contains("Encrypt"),
        "expected wrong-password error, got: {msg}"
    );
}

#[test]
fn encoded_pdf_rejects_wrong_password_r6() {
    let scene = make_scene("Reject 2");
    let cfg = EncryptionConfig::aes_256_r6(b"realpw", b"OXIDEAV-ENCODE-WRONG-V5-FILE-ID!");
    let pdf = write_encrypted(&scene, &cfg).expect("write encrypted");
    let err = read_pdf_to_scene_with_password(&pdf, b"nope").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("password") || msg.contains("Encrypt"));
}

// ─── Owner-password authentication ────────────────────────────────

#[test]
fn encoded_pdf_accepts_owner_password_r3() {
    let scene = make_scene("Owner R3");
    let cfg = EncryptionConfig::rc4_128(b"userpw", b"OXIDEAV-ENCODE-OWNER-R3-FILE-ID!")
        .with_owner_password(b"ownerpw");
    let pdf = write_encrypted(&scene, &cfg).expect("write encrypted");
    let parsed_user = read_pdf_to_scene_with_password(&pdf, b"userpw").expect("user");
    assert_eq!(parsed_user.metadata.title.as_deref(), Some("Owner R3"));
    let parsed_owner = read_pdf_to_scene_with_password(&pdf, b"ownerpw").expect("owner");
    assert_eq!(parsed_owner.metadata.title.as_deref(), Some("Owner R3"));
}

#[test]
fn encoded_pdf_accepts_owner_password_r6() {
    let scene = make_scene("Owner R6");
    let cfg = EncryptionConfig::aes_256_r6(b"userpw", b"OXIDEAV-ENCODE-OWNER-R6-FILE-ID!")
        .with_owner_password(b"ownerpw");
    let pdf = write_encrypted(&scene, &cfg).expect("write encrypted");
    let parsed_user = read_pdf_to_scene_with_password(&pdf, b"userpw").expect("user");
    assert_eq!(parsed_user.metadata.title.as_deref(), Some("Owner R6"));
    let parsed_owner = read_pdf_to_scene_with_password(&pdf, b"ownerpw").expect("owner");
    assert_eq!(parsed_owner.metadata.title.as_deref(), Some("Owner R6"));
}

// ─── Full bounce (encode → decrypt → re-encode → decrypt) ─────────

fn bounce_round_trip(cfg_factory: impl Fn(&[u8], &[u8]) -> EncryptionConfig, password: &[u8]) {
    let scene = make_scene("Bounce title");
    let cfg1 = cfg_factory(password, b"OXIDEAV-BOUNCE-FILE-ID-FIXED-XX!");
    let pdf1 = write_encrypted(&scene, &cfg1).expect("encrypt 1");
    let parsed = read_pdf_to_scene_with_password(&pdf1, password).expect("decrypt 1");
    assert_eq!(parsed.metadata.title.as_deref(), Some("Bounce title"));
    // Re-encode using a fresh file ID to confirm we're really running
    // the writer afresh, not just bit-copying.
    let cfg2 = cfg_factory(password, b"OXIDEAV-BOUNCE-FILE-ID-2ND-PASS!");
    let pdf2 = write_encrypted(&parsed, &cfg2).expect("encrypt 2");
    let parsed2 = read_pdf_to_scene_with_password(&pdf2, password).expect("decrypt 2");
    assert_eq!(parsed2.metadata.title.as_deref(), Some("Bounce title"));
}

#[test]
fn full_bounce_r2() {
    bounce_round_trip(EncryptionConfig::rc4_40, b"r2pw");
}

#[test]
fn full_bounce_r3() {
    bounce_round_trip(EncryptionConfig::rc4_128, b"r3pw");
}

#[test]
fn full_bounce_r4_aes_128() {
    bounce_round_trip(EncryptionConfig::aes_128, b"r4pw");
}

#[test]
fn full_bounce_r5_aes_256() {
    bounce_round_trip(EncryptionConfig::aes_256_r5, b"r5pw");
}

#[test]
fn full_bounce_r6_aes_256() {
    bounce_round_trip(EncryptionConfig::aes_256_r6, b"r6pw");
}

// ─── String + stream both encrypted ────────────────────────────────

#[test]
fn encoded_pdf_encrypts_content_stream_bytes_r3() {
    let scene = make_scene("Stream check");
    let cfg = EncryptionConfig::rc4_128(b"streampw", b"OXIDEAV-STREAM-CHECK-FID-OK-XX!");
    let pdf = write_encrypted(&scene, &cfg).expect("encrypt");
    // The unencrypted content stream contains "10 10 50 50 re" + "f" or
    // ends with "Q\n". After encryption the stream payload should NOT
    // contain those plaintext sequences.
    assert!(
        !pdf.windows(8).any(|w| w == b"\nq\n10 10"),
        "content stream appears to be unencrypted"
    );
    // Reader recovers the operators.
    let parsed = read_pdf_to_scene_with_password(&pdf, b"streampw").expect("decrypt");
    assert!(parsed.pages.is_some());
}
