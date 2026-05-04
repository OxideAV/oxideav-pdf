//! Round-2 multi-page output via [`oxideav_pdf::write_pdf_from_scene`].

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_scene::{Page, Scene};

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
fn empty_pages_field_is_rejected() {
    let scene = Scene::default();
    let err = oxideav_pdf::write_pdf_from_scene(&scene).unwrap_err();
    assert!(format!("{err}").contains("pages mode"));
}

#[test]
fn explicit_empty_pages_vec_is_rejected() {
    let scene = Scene {
        pages: Some(Vec::new()),
        ..Scene::default()
    };
    let err = oxideav_pdf::write_pdf_from_scene(&scene).unwrap_err();
    assert!(format!("{err}").contains("pages mode"));
}

#[test]
fn multi_page_emits_one_page_per_scene_page() {
    let scene = Scene {
        pages: Some(vec![
            page_with(595.0, 842.0, Rgba::opaque(255, 0, 0)),
            page_with(842.0, 595.0, Rgba::opaque(0, 255, 0)),
            page_with(612.0, 792.0, Rgba::opaque(0, 0, 255)),
        ]),
        ..Scene::default()
    };
    let bytes = oxideav_pdf::write_pdf_from_scene(&scene).expect("write_pdf_from_scene");

    // Header / trailer
    assert!(bytes.starts_with(b"%PDF-1.4\n"));
    assert!(bytes.ends_with(b"%%EOF\n"));

    let s = String::from_utf8_lossy(&bytes);

    // Catalog + Pages tree with Count == 3.
    assert!(s.contains("/Type /Catalog"));
    assert!(s.contains("/Type /Pages"));
    assert!(s.contains("/Count 3"));

    // Per-page /MediaBox dims should reflect each page's own size.
    assert!(s.contains("/MediaBox [0 0 595 842]"));
    assert!(s.contains("/MediaBox [0 0 842 595]"));
    assert!(s.contains("/MediaBox [0 0 612 792]"));

    // Per-page colours should appear in the content streams.
    // Red = (1, 0, 0), Green = (0, 1, 0), Blue = (0, 0, 1).
    assert!(s.contains("1 0 0 rg"));
    assert!(s.contains("0 1 0 rg"));
    assert!(s.contains("0 0 1 rg"));
}

#[test]
fn standard_metadata_lands_in_info_dict() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        metadata: oxideav_scene::Metadata {
            title: Some("My Doc".into()),
            author: Some("Mark".into()),
            subject: Some("Round 2 test".into()),
            keywords: vec!["pdf".into(), "scene".into()],
            creator: Some("MyDrawingApp 4.2".into()),
            producer: Some("oxideav-pdf 0.0.2".into()),
            created_at: Some("2026-05-04T12:30:45Z".into()),
            modified_at: Some("2026-05-04T13:00:00+09:00".into()),
            ..oxideav_scene::Metadata::default()
        },
        ..Scene::default()
    };
    let bytes = oxideav_pdf::write_pdf_from_scene(&scene).unwrap();
    let s = String::from_utf8_lossy(&bytes);

    // Trailer references /Info.
    assert!(s.contains("/Info "));
    // Standard keys.
    assert!(s.contains("/Title (My Doc)"));
    assert!(s.contains("/Author (Mark)"));
    assert!(s.contains("/Subject (Round 2 test)"));
    assert!(s.contains("/Keywords (pdf, scene)"));
    assert!(s.contains("/Creator (MyDrawingApp 4.2)"));
    assert!(s.contains("/Producer (oxideav-pdf 0.0.2)"));
    assert!(s.contains("/CreationDate (D:20260504123045Z)"));
    assert!(s.contains("/ModDate (D:20260504130000+09'00')"));
}

#[test]
fn no_metadata_omits_info_dict() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let bytes = oxideav_pdf::write_pdf_from_scene(&scene).unwrap();
    let s = String::from_utf8_lossy(&bytes);

    // Trailer should not reference /Info when scene has no metadata.
    let trailer_pos = s.find("trailer").expect("trailer present");
    let trailer = &s[trailer_pos..];
    assert!(
        !trailer.contains("/Info"),
        "no metadata → no /Info ref in trailer; trailer was: {trailer}"
    );
}
