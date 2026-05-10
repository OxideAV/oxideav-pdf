//! Round-25 — outline (bookmark) tree + Link annotation round-trips.
//!
//! ISO 32000-1 §12.3.3 (outlines) + §12.5.6.5 (Link annotations).
//! Verifies that:
//!
//!  * a writer-side `OutlineSpec` forest survives a write → parse
//!    cycle byte-for-byte at the structural level (titles, parent /
//!    child shape, /Count signs);
//!  * the explicit-array `/Dest` form lowers + parses back to the
//!    same `OutlineDestination` variant;
//!  * Link annotations (internal go-to + external URI) emit on the
//!    correct page's `/Annots` array and round-trip back through the
//!    reader;
//!  * empty outlines + empty links produce a clean document
//!    (byte-identical-shape to `write_pdf_from_scene`);
//!  * out-of-range page indices are caught at write time.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    read_pdf_links, read_pdf_outline, read_pdf_to_scene, write_pdf_from_scene,
    write_pdf_from_scene_with_outlines, write_pdf_from_scene_with_outlines_and_links,
    LinkAnnotationSpec, LinkTarget, OutlineDestination, OutlineSpec, PdfLinkTarget,
};
use oxideav_scene::{Page, Scene};

fn red_page(w: f32, h: f32) -> Page {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(w - 10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(w - 10.0, h - 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(10.0, h - 10.0)));
    p.commands.push(PathCommand::Close);
    let mut page = Page::new(w, h);
    page.content = VectorFrame {
        width: w,
        height: h,
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
    page
}

fn three_page_scene() -> Scene {
    Scene {
        pages: Some(vec![
            red_page(200.0, 100.0),
            red_page(300.0, 200.0),
            red_page(400.0, 300.0),
        ]),
        ..Scene::default()
    }
}

#[test]
fn write_pdf_with_outlines_emits_outlines_keyword_in_catalog() {
    let scene = three_page_scene();
    let outlines = vec![
        OutlineSpec::page("Cover", 0),
        OutlineSpec::page("Chapter 1", 1),
        OutlineSpec::page("Chapter 2", 2),
    ];
    let bytes = write_pdf_from_scene_with_outlines(&scene, &outlines).unwrap();
    let s = String::from_utf8_lossy(&bytes);
    assert!(s.contains("/Outlines"), "PDF must reference /Outlines");
    assert!(
        s.contains("/Type /Outlines"),
        "PDF must declare an outline root"
    );
    assert!(s.contains("/Title (Cover)"));
    assert!(s.contains("/Title (Chapter 1)"));
    assert!(s.contains("/Title (Chapter 2)"));
    // Three top-level visible items ⇒ outline-root /Count 3.
    assert!(s.contains("/Count 3"));
}

#[test]
fn outline_roundtrip_three_top_level_bookmarks() {
    let scene = three_page_scene();
    let outlines = vec![
        OutlineSpec::page("Cover", 0),
        OutlineSpec::page("Chapter 1", 1),
        OutlineSpec::page("Chapter 2", 2),
    ];
    let bytes = write_pdf_from_scene_with_outlines(&scene, &outlines).unwrap();
    let mut reader = DocumentReader::open(&bytes).unwrap();
    let parsed = read_pdf_outline(&mut reader).unwrap().unwrap();
    assert_eq!(parsed.count, Some(3));
    assert_eq!(parsed.roots.len(), 3);
    assert_eq!(parsed.roots[0].title, "Cover");
    assert_eq!(parsed.roots[1].title, "Chapter 1");
    assert_eq!(parsed.roots[2].title, "Chapter 2");
    // Each leaf points at the right page (Fit on page_index N).
    for (i, node) in parsed.roots.iter().enumerate() {
        assert_eq!(
            node.destination,
            Some(OutlineDestination::Fit { page_index: i }),
            "destination for top-level item {i}"
        );
        assert!(node.children.is_empty(), "no nested children");
    }
}

#[test]
fn outline_roundtrip_nested_open_chapter() {
    let scene = three_page_scene();
    // One top-level open chapter with two children.
    let mut chap = OutlineSpec::page("Chapter 1", 0);
    chap.open = true;
    let chap = chap
        .with_child(OutlineSpec::page("Section 1.1", 1))
        .with_child(OutlineSpec::page("Section 1.2", 2));
    let outlines = vec![chap];
    let bytes = write_pdf_from_scene_with_outlines(&scene, &outlines).unwrap();
    let mut reader = DocumentReader::open(&bytes).unwrap();
    let parsed = read_pdf_outline(&mut reader).unwrap().unwrap();
    // 1 top-level + 2 visible children = 3 visible total.
    assert_eq!(parsed.count, Some(3));
    assert_eq!(parsed.roots.len(), 1);
    let chap = &parsed.roots[0];
    assert_eq!(chap.title, "Chapter 1");
    assert!(chap.is_open(), "open child group must report is_open()");
    assert_eq!(chap.count, Some(2)); // open ⇒ +visible_descendants
    assert_eq!(chap.children.len(), 2);
    assert_eq!(chap.children[0].title, "Section 1.1");
    assert_eq!(chap.children[1].title, "Section 1.2");
}

#[test]
fn outline_roundtrip_nested_closed_chapter_negates_count() {
    let scene = three_page_scene();
    // Default is `open = false` — closed chapter ⇒ negative /Count.
    let chap = OutlineSpec::page("Chapter 1", 0)
        .with_child(OutlineSpec::page("Sec 1.1", 1))
        .with_child(OutlineSpec::page("Sec 1.2", 2));
    let outlines = vec![chap];
    let bytes = write_pdf_from_scene_with_outlines(&scene, &outlines).unwrap();
    let mut reader = DocumentReader::open(&bytes).unwrap();
    let parsed = read_pdf_outline(&mut reader).unwrap().unwrap();
    // Top level visible only — children hidden behind closed chapter.
    assert_eq!(parsed.count, Some(1));
    let chap = &parsed.roots[0];
    assert_eq!(chap.count, Some(-2)); // closed ⇒ -|hidden|
    assert!(!chap.is_open());
    assert_eq!(chap.children.len(), 2);
}

#[test]
fn outline_destination_xyz_and_fitr_roundtrip_geometry() {
    let scene = three_page_scene();
    let mut xyz = OutlineSpec::page("Top of Chapter 2", 1);
    xyz.destination = OutlineDestination::Xyz {
        page_index: 1,
        left: Some(10.0),
        top: Some(180.0),
        zoom: Some(1.5),
    };
    let mut fitr = OutlineSpec::page("Detail in Chapter 3", 2);
    fitr.destination = OutlineDestination::FitR {
        page_index: 2,
        left: 50.0,
        bottom: 50.0,
        right: 350.0,
        top: 250.0,
    };
    let outlines = vec![xyz, fitr];
    let bytes = write_pdf_from_scene_with_outlines(&scene, &outlines).unwrap();
    let mut reader = DocumentReader::open(&bytes).unwrap();
    let parsed = read_pdf_outline(&mut reader).unwrap().unwrap();
    assert_eq!(parsed.roots.len(), 2);
    assert_eq!(
        parsed.roots[0].destination,
        Some(OutlineDestination::Xyz {
            page_index: 1,
            left: Some(10.0),
            top: Some(180.0),
            zoom: Some(1.5),
        })
    );
    assert_eq!(
        parsed.roots[1].destination,
        Some(OutlineDestination::FitR {
            page_index: 2,
            left: 50.0,
            bottom: 50.0,
            right: 350.0,
            top: 250.0,
        })
    );
}

#[test]
fn outline_unicode_title_roundtrip() {
    let scene = three_page_scene();
    let outlines = vec![OutlineSpec::page("第一章", 0)];
    let bytes = write_pdf_from_scene_with_outlines(&scene, &outlines).unwrap();
    let mut reader = DocumentReader::open(&bytes).unwrap();
    let parsed = read_pdf_outline(&mut reader).unwrap().unwrap();
    assert_eq!(parsed.roots[0].title, "第一章");
}

#[test]
fn outline_out_of_range_page_index_is_writer_error() {
    let scene = three_page_scene();
    let outlines = vec![OutlineSpec::page("Off-end", 99)];
    let err = write_pdf_from_scene_with_outlines(&scene, &outlines).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Off-end"),
        "error must name the offending entry"
    );
    assert!(msg.contains("out of range"), "error must explain reason");
}

#[test]
fn outline_absent_returns_none() {
    let scene = three_page_scene();
    let bytes = write_pdf_from_scene(&scene).unwrap();
    let mut reader = DocumentReader::open(&bytes).unwrap();
    let parsed = read_pdf_outline(&mut reader).unwrap();
    assert!(parsed.is_none(), "no /Outlines ⇒ Ok(None)");
}

#[test]
fn link_internal_goto_roundtrip() {
    let scene = three_page_scene();
    let links = vec![LinkAnnotationSpec {
        source_page_index: 0,
        rect: [10.0, 10.0, 100.0, 30.0],
        target: LinkTarget::Internal(OutlineDestination::Fit { page_index: 2 }),
    }];
    let bytes = write_pdf_from_scene_with_outlines_and_links(&scene, &[], &links).unwrap();
    let mut reader = DocumentReader::open(&bytes).unwrap();
    let parsed = read_pdf_links(&mut reader).unwrap();
    assert_eq!(parsed.len(), 1);
    let link = &parsed[0];
    assert_eq!(link.source_page_index, 0);
    assert_eq!(link.rect, [10.0, 10.0, 100.0, 30.0]);
    match &link.target {
        Some(PdfLinkTarget::Internal(OutlineDestination::Fit { page_index })) => {
            assert_eq!(*page_index, 2);
        }
        other => panic!("expected internal Fit, got {other:?}"),
    }
}

#[test]
fn link_uri_roundtrip() {
    let scene = three_page_scene();
    let links = vec![LinkAnnotationSpec {
        source_page_index: 1,
        rect: [50.0, 80.0, 250.0, 100.0],
        target: LinkTarget::Uri("https://example.org/docs?page=42".into()),
    }];
    let bytes = write_pdf_from_scene_with_outlines_and_links(&scene, &[], &links).unwrap();
    let mut reader = DocumentReader::open(&bytes).unwrap();
    let parsed = read_pdf_links(&mut reader).unwrap();
    assert_eq!(parsed.len(), 1);
    let link = &parsed[0];
    assert_eq!(link.source_page_index, 1);
    match &link.target {
        Some(PdfLinkTarget::Uri(s)) => assert_eq!(s, "https://example.org/docs?page=42"),
        other => panic!("expected URI, got {other:?}"),
    }
}

#[test]
fn link_emits_subtype_and_action_in_pdf_bytes() {
    let scene = three_page_scene();
    let links = vec![LinkAnnotationSpec {
        source_page_index: 0,
        rect: [0.0, 0.0, 50.0, 20.0],
        target: LinkTarget::Uri("mailto:test@example.org".into()),
    }];
    let bytes = write_pdf_from_scene_with_outlines_and_links(&scene, &[], &links).unwrap();
    let s = String::from_utf8_lossy(&bytes);
    assert!(s.contains("/Subtype /Link"));
    assert!(s.contains("/S /URI"));
    assert!(s.contains("(mailto:test@example.org)"));
    assert!(s.contains("/Annots ["));
}

#[test]
fn link_grouped_by_source_page_into_distinct_annot_arrays() {
    let scene = three_page_scene();
    let links = vec![
        LinkAnnotationSpec {
            source_page_index: 0,
            rect: [0.0, 0.0, 10.0, 10.0],
            target: LinkTarget::Uri("https://a.example".into()),
        },
        LinkAnnotationSpec {
            source_page_index: 2,
            rect: [0.0, 0.0, 10.0, 10.0],
            target: LinkTarget::Uri("https://b.example".into()),
        },
        LinkAnnotationSpec {
            source_page_index: 0,
            rect: [20.0, 20.0, 40.0, 40.0],
            target: LinkTarget::Uri("https://c.example".into()),
        },
    ];
    let bytes = write_pdf_from_scene_with_outlines_and_links(&scene, &[], &links).unwrap();
    let mut reader = DocumentReader::open(&bytes).unwrap();
    let parsed = read_pdf_links(&mut reader).unwrap();
    assert_eq!(parsed.len(), 3);
    let n_on_page_0 = parsed.iter().filter(|l| l.source_page_index == 0).count();
    let n_on_page_1 = parsed.iter().filter(|l| l.source_page_index == 1).count();
    let n_on_page_2 = parsed.iter().filter(|l| l.source_page_index == 2).count();
    assert_eq!(n_on_page_0, 2);
    assert_eq!(n_on_page_1, 0);
    assert_eq!(n_on_page_2, 1);
}

#[test]
fn link_out_of_range_source_page_is_writer_error() {
    let scene = three_page_scene();
    let links = vec![LinkAnnotationSpec {
        source_page_index: 99,
        rect: [0.0, 0.0, 10.0, 10.0],
        target: LinkTarget::Uri("https://example".into()),
    }];
    let err = write_pdf_from_scene_with_outlines_and_links(&scene, &[], &links).unwrap_err();
    assert!(err.to_string().contains("source_page_index 99"));
}

#[test]
fn link_internal_target_out_of_range_is_writer_error() {
    let scene = three_page_scene();
    let links = vec![LinkAnnotationSpec {
        source_page_index: 0,
        rect: [0.0, 0.0, 10.0, 10.0],
        target: LinkTarget::Internal(OutlineDestination::Fit { page_index: 99 }),
    }];
    let err = write_pdf_from_scene_with_outlines_and_links(&scene, &[], &links).unwrap_err();
    assert!(err.to_string().contains("destination page_index 99"));
}

#[test]
fn outlines_and_links_combined_roundtrip() {
    let scene = three_page_scene();
    let outlines = vec![
        OutlineSpec::page("Cover", 0)
            .with_child(OutlineSpec::page("Foreword", 0))
            .with_child(OutlineSpec::page("Preface", 0)),
        OutlineSpec::page("Chapter 1", 1),
    ];
    let links = vec![
        LinkAnnotationSpec {
            source_page_index: 0,
            rect: [10.0, 50.0, 90.0, 70.0],
            target: LinkTarget::Internal(OutlineDestination::Fit { page_index: 1 }),
        },
        LinkAnnotationSpec {
            source_page_index: 1,
            rect: [120.0, 80.0, 280.0, 100.0],
            target: LinkTarget::Uri("https://example.org/about".into()),
        },
    ];
    let bytes = write_pdf_from_scene_with_outlines_and_links(&scene, &outlines, &links).unwrap();

    // Page bytes still parse as a valid Scene with the right page count.
    let scene_back = read_pdf_to_scene(&bytes).unwrap();
    let pages_back = scene_back.pages.expect("scene has pages");
    assert_eq!(pages_back.len(), 3);

    // Outlines round-trip end-to-end.
    let mut reader = DocumentReader::open(&bytes).unwrap();
    let outline = read_pdf_outline(&mut reader).unwrap().unwrap();
    assert_eq!(outline.roots.len(), 2);
    assert_eq!(outline.roots[0].title, "Cover");
    assert_eq!(outline.roots[0].children.len(), 2);
    assert_eq!(outline.roots[0].children[0].title, "Foreword");

    // Links round-trip end-to-end.
    let parsed_links = read_pdf_links(&mut reader).unwrap();
    assert_eq!(parsed_links.len(), 2);
    assert!(parsed_links.iter().any(|l| matches!(
        &l.target,
        Some(PdfLinkTarget::Internal(OutlineDestination::Fit {
            page_index: 1
        }))
    )));
    assert!(parsed_links.iter().any(
        |l| matches!(&l.target, Some(PdfLinkTarget::Uri(s)) if s == "https://example.org/about")
    ));
}

#[test]
fn empty_outlines_and_links_match_baseline_byte_shape() {
    let scene = three_page_scene();
    let baseline = write_pdf_from_scene(&scene).unwrap();
    let with_empty = write_pdf_from_scene_with_outlines_and_links(&scene, &[], &[]).unwrap();
    // Same-byte baseline isn't strictly guaranteed (the writer's
    // pre-allocation hint differs), but the parsed scene must match.
    let from_baseline = read_pdf_to_scene(&baseline).unwrap();
    let from_empty = read_pdf_to_scene(&with_empty).unwrap();
    assert_eq!(
        from_baseline.pages.unwrap().len(),
        from_empty.pages.unwrap().len()
    );
    // No outline / link surfaces should appear.
    let mut reader = DocumentReader::open(&with_empty).unwrap();
    assert!(read_pdf_outline(&mut reader).unwrap().is_none());
    assert!(read_pdf_links(&mut reader).unwrap().is_empty());
}
