//! Round-8 PDF incremental-update tests (ISO 32000-1 §7.5.6).
//!
//! Verifies that [`oxideav_pdf::write_pdf_incremental_update`]:
//!
//! 1. produces a file whose tail carries `/Prev` pointing back at the
//!    original revision's xref offset,
//! 2. round-trips through `read_pdf_to_scene` returning the merged
//!    page list (old + new pages) under the merged `/Pages` tree,
//! 3. preserves the original revision's bytes verbatim — a partial
//!    reader that only follows `startxref` and ignores `/Prev` would
//!    still see the original page count (this is the "Fast Web View"
//!    contract that lets old PDF readers open new revisions safely).

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_scene::{Page, Scene};

use oxideav_pdf::{read_pdf_to_scene, write_pdf_from_scene, write_pdf_incremental_update};

fn one_page_scene() -> Scene {
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

fn green_rect_page(w: f32, h: f32) -> Page {
    let mut path = Path::new();
    path.commands
        .push(PathCommand::MoveTo(Point::new(0.0, 0.0)));
    path.commands.push(PathCommand::LineTo(Point::new(w, 0.0)));
    path.commands.push(PathCommand::LineTo(Point::new(w, h)));
    path.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: w,
        height: h,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path,
                fill: Some(Paint::Solid(Rgba::opaque(0, 255, 0))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let mut page = Page::new(w, h);
    page.content = frame;
    page
}

#[test]
fn incremental_update_preserves_original_bytes() {
    let scene = one_page_scene();
    let original = write_pdf_from_scene(&scene).expect("original PDF");
    let updated =
        write_pdf_incremental_update(&original, &[green_rect_page(50.0, 200.0)]).expect("update");
    assert!(
        updated.starts_with(&original),
        "incremental update must append to (not rewrite) the original bytes"
    );
    assert!(updated.len() > original.len(), "update must grow the file");
    assert!(updated.ends_with(b"%%EOF\n"));
}

#[test]
fn incremental_update_carries_prev_pointer() {
    let scene = one_page_scene();
    let original = write_pdf_from_scene(&scene).expect("original PDF");
    let updated =
        write_pdf_incremental_update(&original, &[green_rect_page(50.0, 200.0)]).expect("update");
    let s = String::from_utf8_lossy(&updated);
    assert!(
        s.contains("/Prev "),
        "incremental update trailer must carry /Prev pointing at the previous xref"
    );
}

#[test]
fn incremental_update_round_trips_through_reader() {
    let scene = one_page_scene();
    let original = write_pdf_from_scene(&scene).expect("original PDF");
    let updated = write_pdf_incremental_update(
        &original,
        &[green_rect_page(50.0, 200.0), green_rect_page(80.0, 80.0)],
    )
    .expect("update");

    let parsed = read_pdf_to_scene(&updated).expect("reader follows /Prev");
    let pages = parsed.pages.expect("pages");
    assert_eq!(pages.len(), 3, "merged tree should expose all 3 pages");
    assert_eq!(pages[0].width, 100.0);
    assert_eq!(pages[1].width, 50.0);
    assert_eq!(pages[1].height, 200.0);
    assert_eq!(pages[2].width, 80.0);
}

#[test]
fn double_incremental_update_round_trips() {
    // Three revisions chained via /Prev — the reader walks from the
    // newest backwards and merges the trees.
    let scene = one_page_scene();
    let r1 = write_pdf_from_scene(&scene).expect("r1");
    let r2 = write_pdf_incremental_update(&r1, &[green_rect_page(50.0, 200.0)]).expect("r2");
    let r3 = write_pdf_incremental_update(&r2, &[green_rect_page(80.0, 80.0)]).expect("r3");

    let parsed = read_pdf_to_scene(&r3).expect("reader follows /Prev twice");
    let pages = parsed.pages.expect("pages");
    assert_eq!(
        pages.len(),
        3,
        "two-level chain must expose all 3 pages (orig + r2 + r3)"
    );
}

#[test]
fn incremental_update_rejects_non_pdf_input() {
    let r = write_pdf_incremental_update(b"not a pdf", &[green_rect_page(50.0, 50.0)]);
    assert!(r.is_err());
}
