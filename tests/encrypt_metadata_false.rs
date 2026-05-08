//! Round-8 `/EncryptMetadata false` end-to-end tests.
//!
//! ISO 32000-1 §7.6.3.2 (Table 21) plus §7.6.4 lets the standard
//! security handler opt the document's metadata stream out of the
//! per-object encryption while keeping the rest of the file
//! encrypted. The use case is XMP search/metadata extraction by
//! cloud indexers that don't have the PDF password — the rendered
//! content stays encrypted, but `/Title`, `/Author`, etc. remain
//! cleartext.
//!
//! On the writer side, `EncryptionConfig::encrypt_metadata = false`
//! emits `/EncryptMetadata false` into the `/Encrypt` dictionary and
//! (for V=5) feeds the flag into Algorithm 10's `/Perms` block. On
//! the reader side, the decryption handler's per-object key
//! derivation honours the flag (Algorithm 2 step (f)).
//!
//! This test confirms the round-trip: an encrypted PDF with
//! `/EncryptMetadata false` decrypts identically to one with
//! `/EncryptMetadata true` (modulo the metadata stream's own
//! treatment) given the right password.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::encrypt::EncryptionConfig;
use oxideav_pdf::{read_pdf_to_scene_with_password, write_pdf_from_scene_encrypted};
use oxideav_scene::{Metadata, Page, Scene};

fn make_scene(title: &str, author: &str) -> Scene {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(60.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(60.0, 60.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 100.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(0, 128, 255))),
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
    Scene {
        pages: Some(vec![page]),
        metadata: Metadata {
            title: Some(title.into()),
            author: Some(author.into()),
            ..Metadata::default()
        },
        ..Scene::default()
    }
}

#[test]
fn encrypt_metadata_false_lands_in_encrypt_dict_r4() {
    // R=4 (V=4) — the EncryptMetadata flag is just a dict key.
    let scene = make_scene("Cleartext-meta R4", "Round 8");
    let mut cfg = EncryptionConfig::aes_128(b"hunter2", b"FILE-ID-16-BYTES");
    cfg.encrypt_metadata = false;
    let pdf = write_pdf_from_scene_encrypted(&scene, &cfg)
        .expect("encrypted PDF with EncryptMetadata=false");
    let s = String::from_utf8_lossy(&pdf);
    assert!(
        s.contains("/EncryptMetadata false"),
        "/Encrypt dict must carry /EncryptMetadata false"
    );
}

#[test]
fn encrypt_metadata_false_lands_in_encrypt_dict_r6() {
    // R=6 (V=5) — the flag is also folded into Algorithm 10's
    // /Perms block.
    let scene = make_scene("Cleartext-meta R6", "Round 8");
    let mut cfg = EncryptionConfig::aes_256_r6(b"hunter2", b"FILE-ID-16-BYTES");
    cfg.encrypt_metadata = false;
    let pdf = write_pdf_from_scene_encrypted(&scene, &cfg)
        .expect("encrypted PDF with EncryptMetadata=false");
    let s = String::from_utf8_lossy(&pdf);
    assert!(
        s.contains("/EncryptMetadata false"),
        "V=5 /Encrypt dict must also carry /EncryptMetadata false"
    );
}

#[test]
fn encrypt_metadata_false_round_trips_r4_aes128() {
    let scene = make_scene("Cleartext-meta R4 AES", "Round 8 verifier");
    let mut cfg = EncryptionConfig::aes_128(b"hunter2", b"FILE-ID-16-BYTES");
    cfg.encrypt_metadata = false;
    let pdf = write_pdf_from_scene_encrypted(&scene, &cfg).expect("write");
    let parsed = read_pdf_to_scene_with_password(&pdf, b"hunter2").expect("decrypt");
    assert_eq!(
        parsed.metadata.title.as_deref(),
        Some("Cleartext-meta R4 AES")
    );
    assert_eq!(parsed.metadata.author.as_deref(), Some("Round 8 verifier"));
    let pages = parsed.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

#[test]
fn encrypt_metadata_false_round_trips_r3_rc4_128() {
    // R=3 ignores EncryptMetadata in the dict per Table 21
    // (it's a R≥4 feature) but the writer still emits the flag for
    // tooling compatibility — the file must still round-trip.
    let scene = make_scene("Cleartext-meta R3", "Round 8");
    let mut cfg = EncryptionConfig::rc4_128(b"hunter2", b"FILE-ID-16-BYTES");
    cfg.encrypt_metadata = false;
    let pdf = write_pdf_from_scene_encrypted(&scene, &cfg).expect("write");
    let parsed = read_pdf_to_scene_with_password(&pdf, b"hunter2").expect("decrypt");
    assert_eq!(parsed.metadata.title.as_deref(), Some("Cleartext-meta R3"));
}

#[test]
fn encrypt_metadata_false_round_trips_r6_aes256() {
    let scene = make_scene("Cleartext-meta R6 AES", "Round 8");
    let mut cfg = EncryptionConfig::aes_256_r6(b"hunter2", b"FILE-ID-16-BYTES");
    cfg.encrypt_metadata = false;
    let pdf = write_pdf_from_scene_encrypted(&scene, &cfg).expect("write");
    let parsed = read_pdf_to_scene_with_password(&pdf, b"hunter2").expect("decrypt R=6");
    assert_eq!(
        parsed.metadata.title.as_deref(),
        Some("Cleartext-meta R6 AES")
    );
}

#[test]
fn encrypt_metadata_true_default_preserves_round_trip() {
    // Flip side: the default `encrypt_metadata=true` must still
    // round-trip — a regression check.
    let scene = make_scene("Encrypted-meta R4", "Round 8");
    let cfg = EncryptionConfig::aes_128(b"hunter2", b"FILE-ID-16-BYTES");
    assert!(cfg.encrypt_metadata, "default should be true");
    let pdf = write_pdf_from_scene_encrypted(&scene, &cfg).expect("write");
    let s = String::from_utf8_lossy(&pdf);
    assert!(
        !s.contains("/EncryptMetadata false"),
        "default true must NOT emit the flag (only the false case is signalled)"
    );
    let parsed = read_pdf_to_scene_with_password(&pdf, b"hunter2").expect("decrypt");
    assert_eq!(parsed.metadata.title.as_deref(), Some("Encrypted-meta R4"));
}
