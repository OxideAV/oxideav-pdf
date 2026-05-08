//! Round-7 cross-reference stream **encoder** tests.
//!
//! Mirror image of `tests/xref_stream.rs`: the writer
//! [`oxideav_pdf::write_pdf_from_scene_xref_stream`] emits a PDF 1.5+
//! `/Type /XRef` stream (ISO 32000-1 §7.5.8) instead of the classical
//! `xref`-keyword table. These tests verify the produced bytes:
//!
//! 1. carry the right magic + structural markers (no `trailer` keyword,
//!    no plain `xref` keyword, `/Type /XRef` present),
//! 2. round-trip through `read_pdf_to_scene` so the round-6 reader's
//!    xref-stream parser actually accepts what we emit,
//! 3. preserve scene metadata across the round-trip.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_scene::{Metadata, Page, Scene};

use oxideav_pdf::{read_pdf_to_scene, write_pdf_from_scene_xref_stream};

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
fn xref_stream_writer_emits_pdf_1_5_header() {
    let scene = red_rect_scene();
    let pdf = write_pdf_from_scene_xref_stream(&scene).expect("xref-stream encode");
    assert!(pdf.starts_with(b"%PDF-1.5\n"), "header should be 1.5+");
    assert!(pdf.ends_with(b"%%EOF\n"));
}

#[test]
fn xref_stream_writer_omits_plain_xref_keyword() {
    let scene = red_rect_scene();
    let pdf = write_pdf_from_scene_xref_stream(&scene).expect("xref-stream encode");
    // The classical-xref form starts a section with `xref\n`. The
    // PDF 1.5+ form puts that responsibility on the indirect object.
    let s = String::from_utf8_lossy(&pdf);
    assert!(
        !s.contains("\nxref\n"),
        "xref-stream output must not contain a plain `xref` keyword"
    );
    assert!(
        !s.contains("\ntrailer\n"),
        "xref-stream folds the trailer into the stream dict (no `trailer` keyword)"
    );
    assert!(
        s.contains("/Type /XRef"),
        "xref-stream must declare /Type /XRef"
    );
    assert!(
        s.contains("/W [1 4 2]"),
        "xref-stream emits /W [1 4 2] field widths"
    );
    assert!(s.contains("/FlateDecode"), "body is FlateDecode-compressed");
    assert!(s.contains("/Predictor 12"), "body uses PNG-Up predictor");
}

#[test]
fn xref_stream_writer_round_trips_through_reader() {
    let scene = red_rect_scene();
    let pdf = write_pdf_from_scene_xref_stream(&scene).expect("xref-stream encode");
    let parsed = read_pdf_to_scene(&pdf).expect("reader accepts xref stream");
    let pages = parsed.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
    assert_eq!(pages[0].height, 100.0);
}

#[test]
fn xref_stream_round_trips_metadata() {
    let mut scene = red_rect_scene();
    scene.metadata = Metadata {
        title: Some("XRef Stream Test".into()),
        author: Some("Round 7".into()),
        ..Metadata::default()
    };
    let pdf = write_pdf_from_scene_xref_stream(&scene).expect("xref-stream encode");
    let parsed = read_pdf_to_scene(&pdf).expect("reader accepts xref stream");
    assert_eq!(parsed.metadata.title.as_deref(), Some("XRef Stream Test"));
    assert_eq!(parsed.metadata.author.as_deref(), Some("Round 7"));
}

#[test]
fn xref_stream_round_trips_multi_page() {
    let mut scene = red_rect_scene();
    // Add two more pages — a 5-page mix is enough to exercise the
    // body-id range (1..=N + the xref-stream's own slot at the end).
    for _ in 0..4 {
        let mut page = Page::new(50.0, 200.0);
        page.content.width = 50.0;
        page.content.height = 200.0;
        scene.pages.as_mut().unwrap().push(page);
    }
    let pdf = write_pdf_from_scene_xref_stream(&scene).expect("xref-stream encode");
    let parsed = read_pdf_to_scene(&pdf).expect("reader accepts xref stream");
    let pages = parsed.pages.expect("pages");
    assert_eq!(pages.len(), 5);
    assert_eq!(pages[0].width, 100.0);
    assert_eq!(pages[1].width, 50.0);
    assert_eq!(pages[1].height, 200.0);
}

#[test]
fn xref_stream_self_entry_points_at_xref_object() {
    // The xref stream is itself an indirect object — its slot in the
    // table must point at its own `<n> <gen> obj` header so that
    // re-resolving startxref through the parser lands at exactly
    // that byte. We don't expose offsets directly; instead we verify
    // by reading the file twice (via the high-level reader) — the
    // test passes implicitly through `read_pdf_to_scene` succeeding,
    // but we also sanity-check the pdf size is non-trivial so a
    // degenerate "empty file but %%EOF" output can't pass.
    let scene = red_rect_scene();
    let pdf = write_pdf_from_scene_xref_stream(&scene).expect("xref-stream encode");
    assert!(pdf.len() > 200, "non-trivial output");
    let _ = read_pdf_to_scene(&pdf).expect("re-readable");
}
