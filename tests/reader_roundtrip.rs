//! Round-3 reader vs writer roundtrip coverage.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_scene::{Metadata, Page, Scene};

fn rect_frame(w: f32, h: f32, color: Rgba) -> VectorFrame {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(w - 10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(w - 10.0, h - 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(10.0, h - 10.0)));
    p.commands.push(PathCommand::Close);
    VectorFrame {
        width: w,
        height: h,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(color)),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    }
}

fn page_with(w: f32, h: f32, color: Rgba) -> Page {
    let mut page = Page::new(w, h);
    page.content = rect_frame(w, h, color);
    page
}

#[test]
fn writer_then_reader_preserves_page_count_and_dimensions() {
    let scene = Scene {
        pages: Some(vec![
            page_with(595.0, 842.0, Rgba::opaque(255, 0, 0)),
            page_with(842.0, 595.0, Rgba::opaque(0, 255, 0)),
            page_with(612.0, 792.0, Rgba::opaque(0, 0, 255)),
        ]),
        ..Scene::default()
    };
    let pdf = oxideav_pdf::write_pdf_from_scene(&scene).expect("write");
    let parsed = oxideav_pdf::read_pdf_to_scene(&pdf).expect("read");
    let pages = parsed.pages.expect("pages");
    assert_eq!(pages.len(), 3);
    assert_eq!((pages[0].width, pages[0].height), (595.0, 842.0));
    assert_eq!((pages[1].width, pages[1].height), (842.0, 595.0));
    assert_eq!((pages[2].width, pages[2].height), (612.0, 792.0));
}

#[test]
fn writer_then_reader_preserves_full_metadata() {
    let mut custom = std::collections::BTreeMap::new();
    custom.insert("dc:rights".into(), "(c) 2026 Karpeles Lab Inc.".into());
    custom.insert("Trapped".into(), "False".into());
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        metadata: Metadata {
            title: Some("Round 3 reader".into()),
            author: Some("Mark".into()),
            subject: Some("Roundtrip test".into()),
            keywords: vec!["pdf".into(), "reader".into(), "roundtrip".into()],
            creator: Some("MyApp 1.0".into()),
            producer: Some("oxideav-pdf 0.0.x".into()),
            created_at: Some("2026-05-04T12:30:45Z".into()),
            modified_at: Some("2026-05-04T13:00:00+09:00".into()),
            custom,
        },
        ..Scene::default()
    };
    let pdf = oxideav_pdf::write_pdf_from_scene(&scene).unwrap();
    let parsed = oxideav_pdf::read_pdf_to_scene(&pdf).unwrap();
    let m = &parsed.metadata;
    assert_eq!(m.title.as_deref(), Some("Round 3 reader"));
    assert_eq!(m.author.as_deref(), Some("Mark"));
    assert_eq!(m.subject.as_deref(), Some("Roundtrip test"));
    assert_eq!(m.creator.as_deref(), Some("MyApp 1.0"));
    assert_eq!(m.producer.as_deref(), Some("oxideav-pdf 0.0.x"));
    assert_eq!(
        m.keywords,
        vec![
            "pdf".to_string(),
            "reader".to_string(),
            "roundtrip".to_string()
        ]
    );
    assert_eq!(m.created_at.as_deref(), Some("2026-05-04T12:30:45Z"));
    assert_eq!(m.modified_at.as_deref(), Some("2026-05-04T13:00:00+09:00"));
    assert_eq!(
        m.custom.get("dc:rights").map(String::as_str),
        Some("(c) 2026 Karpeles Lab Inc.")
    );
    assert_eq!(m.custom.get("Trapped").map(String::as_str), Some("False"));
}

#[test]
fn writer_then_reader_preserves_path_geometry() {
    let scene = Scene {
        pages: Some(vec![page_with(200.0, 100.0, Rgba::opaque(128, 64, 0))]),
        ..Scene::default()
    };
    let pdf = oxideav_pdf::write_pdf_from_scene(&scene).unwrap();
    let parsed = oxideav_pdf::read_pdf_to_scene(&pdf).unwrap();
    let pages = parsed.pages.expect("pages");
    let path_node = find_first_path(&pages[0].content.root).expect("path");
    // Recover the four vertices the writer emitted.
    let cmds = &path_node.path.commands;
    assert_eq!(cmds.len(), 5);
    if let PathCommand::MoveTo(p) = cmds[0] {
        assert!((p.x - 10.0).abs() < 1e-3 && (p.y - 10.0).abs() < 1e-3);
    } else {
        panic!("expected MoveTo");
    }
    assert!(matches!(cmds[4], PathCommand::Close));
    // The fill colour round-trips bit-exactly because the writer +
    // reader both quantise to 8-bit.
    match &path_node.fill {
        Some(Paint::Solid(rgba)) => assert_eq!((rgba.r, rgba.g, rgba.b), (128, 64, 0)),
        other => panic!("unexpected fill: {other:?}"),
    }
}

#[test]
fn reader_rejects_empty_input() {
    let err = oxideav_pdf::read_pdf_to_scene(b"").unwrap_err();
    assert!(format!("{err}").contains("PDF"));
}

#[test]
fn reader_handles_minimal_writer_output_for_default_metadata() {
    // Even a scene with NO metadata fields must read back as a valid
    // multi-page Scene with `metadata == Metadata::default()`.
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(255, 255, 255))]),
        ..Scene::default()
    };
    let pdf = oxideav_pdf::write_pdf_from_scene(&scene).unwrap();
    let parsed = oxideav_pdf::read_pdf_to_scene(&pdf).unwrap();
    assert!(parsed.metadata.title.is_none());
    assert!(parsed.metadata.custom.is_empty());
    let pages = parsed.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

fn find_first_path(group: &Group) -> Option<&PathNode> {
    for child in &group.children {
        match child {
            Node::Path(p) => return Some(p),
            Node::Group(g) => {
                if let Some(p) = find_first_path(g) {
                    return Some(p);
                }
            }
            _ => {}
        }
    }
    None
}
