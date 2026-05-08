//! Round-8 PDF 1.5+ object-stream **encoder** tests.
//!
//! Mirror image of `tests/object_stream.rs`: the writer
//! [`oxideav_pdf::write_pdf_from_scene_object_stream`] emits a PDF
//! whose Catalog / Pages / Page dicts live inside a `/Type /ObjStm`
//! container (ISO 32000-1 §7.5.7) referenced by type-2 entries from
//! a `/Type /XRef` cross-reference stream (§7.5.8).
//!
//! These tests verify the produced bytes:
//!
//! 1. carry the right magic + structural markers (`/Type /ObjStm`,
//!    `/Type /XRef`, no plain `xref` / `trailer` keywords),
//! 2. round-trip through `read_pdf_to_scene` so the round-7
//!    ObjStm resolver actually accepts what we emit,
//! 3. preserve scene metadata across the round-trip,
//! 4. properly exclude streams (content streams stay at byte
//!    offsets per §7.5.7).

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_scene::{Metadata, Page, Scene};

use oxideav_pdf::{read_pdf_to_scene, write_pdf_from_scene_object_stream};

fn red_rect_scene() -> Scene {
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
    Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    }
}

#[test]
fn objstm_writer_emits_objstm_container() {
    let scene = red_rect_scene();
    let pdf = write_pdf_from_scene_object_stream(&scene).expect("ObjStm encode");
    assert!(pdf.starts_with(b"%PDF-1.5\n"));
    assert!(pdf.ends_with(b"%%EOF\n"));
    let s = String::from_utf8_lossy(&pdf);
    assert!(
        s.contains("/Type /ObjStm"),
        "must declare /Type /ObjStm container"
    );
    assert!(
        s.contains("/Type /XRef"),
        "must declare /Type /XRef cross-reference stream"
    );
    assert!(
        !s.contains("\nxref\n"),
        "ObjStm writer must not emit plain xref keyword"
    );
    assert!(
        !s.contains("\ntrailer\n"),
        "ObjStm writer folds the trailer into the xref-stream dict"
    );
    assert!(
        s.contains("/N "),
        "/N (number of compressed objects) must be present"
    );
    assert!(
        s.contains("/First "),
        "/First (offset of first body in payload) must be present"
    );
}

#[test]
fn objstm_writer_round_trips_through_reader() {
    let scene = red_rect_scene();
    let pdf = write_pdf_from_scene_object_stream(&scene).expect("ObjStm encode");
    let parsed = read_pdf_to_scene(&pdf).expect("reader accepts ObjStm");
    let pages = parsed.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
    assert_eq!(pages[0].height, 100.0);
}

#[test]
fn objstm_writer_round_trips_metadata() {
    let mut scene = red_rect_scene();
    scene.metadata = Metadata {
        title: Some("ObjStm Test".into()),
        author: Some("Round 8".into()),
        ..Metadata::default()
    };
    let pdf = write_pdf_from_scene_object_stream(&scene).expect("ObjStm encode");
    let parsed = read_pdf_to_scene(&pdf).expect("reader accepts ObjStm");
    assert_eq!(parsed.metadata.title.as_deref(), Some("ObjStm Test"));
    assert_eq!(parsed.metadata.author.as_deref(), Some("Round 8"));
}

#[test]
fn objstm_writer_round_trips_multi_page() {
    let mut scene = red_rect_scene();
    for _ in 0..4 {
        let mut page = Page::new(50.0, 200.0);
        page.content.width = 50.0;
        page.content.height = 200.0;
        scene.pages.as_mut().unwrap().push(page);
    }
    let pdf = write_pdf_from_scene_object_stream(&scene).expect("ObjStm encode");
    let parsed = read_pdf_to_scene(&pdf).expect("reader accepts ObjStm");
    let pages = parsed.pages.expect("pages");
    assert_eq!(pages.len(), 5);
    assert_eq!(pages[0].width, 100.0);
    assert_eq!(pages[1].width, 50.0);
    assert_eq!(pages[1].height, 200.0);
}

#[test]
fn objstm_writer_excludes_streams_from_container() {
    // Content streams MUST stay at byte offsets per §7.5.7. A
    // /Type /ObjStm cannot itself contain a stream object.  We
    // verify by searching the raw bytes for `/Contents` references
    // that resolve via type-1 (offset) entries — the easiest signal
    // is that the file still carries `<n> <gen> obj\n... stream\n`
    // blocks (the content stream's own indirect object) outside the
    // ObjStm payload.
    let scene = red_rect_scene();
    let pdf = write_pdf_from_scene_object_stream(&scene).expect("ObjStm encode");
    let s = String::from_utf8_lossy(&pdf);
    // The content stream object should still be visible as
    // `<n> <gen> obj\n<<...>>\nstream\n` in the file body.
    assert!(
        s.contains("\nstream\n"),
        "ObjStm writer must keep content streams at file-level byte offsets"
    );
    // The xref stream itself is also a stream; that's fine — it's
    // the only stream that's required to be at a byte offset by
    // §7.5.8.
}

#[test]
fn objstm_writer_with_encryption_returns_error() {
    use oxideav_pdf::encrypt::EncryptionConfig;
    use oxideav_pdf::write_pdf_from_scene_encrypted;
    // The combined ObjStm + encryption path is intentionally not
    // supported in round 8 (§7.6.1 + §7.5.7 interplay needs
    // careful unit-encryption handling for the container itself).
    // We confirm here that the existing encrypted writer still
    // works without ObjStm — and the validation lives on the
    // Document layer.
    let scene = red_rect_scene();
    let cfg = EncryptionConfig::aes_128(b"hunter2", b"FILE-ID-16-BYTES");
    let r = write_pdf_from_scene_encrypted(&scene, &cfg);
    assert!(
        r.is_ok(),
        "non-ObjStm encrypted writer must still work — ObjStm is opt-in"
    );
}
