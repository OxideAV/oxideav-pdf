//! Round-32 — general annotations writer end-to-end tests
//! (ISO 32000-1 §12.5.6).
//!
//! Validates that [`oxideav_pdf::write_pdf_with_annotations`] emits a
//! PDF whose page-level `/Annots` arrays contain matching annotation
//! dicts for every supported §12.5.6 subtype: Text, Link, FreeText,
//! Highlight/Underline/Squiggly/StrikeOut, Stamp, Square, Circle, Ink.
//!
//! Round-trip is validated via the round-26 generic annotation reader
//! ([`oxideav_pdf::read_pdf_annotations`]); external acceptance via
//! `qpdf --check` when the binary is on `PATH`.

use std::process::{Command, Stdio};

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    read_pdf_annotations, write_pdf_with_annotations, Annotation, AnnotationKind, FreeTextQuadding,
    TextMarkupVariant, WriterAnnotationKind,
};
use oxideav_scene::{Page, Scene};

fn one_page_scene() -> Scene {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(190.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(190.0, 190.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 300.0,
        height: 300.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(0, 0, 0))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let mut page = Page::new(300.0, 300.0);
    page.content = frame;
    Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    }
}

fn three_page_scene() -> Scene {
    let mk_page = |w: f32, h: f32| {
        let mut path = Path::new();
        path.commands
            .push(PathCommand::MoveTo(Point::new(5.0, 5.0)));
        path.commands
            .push(PathCommand::LineTo(Point::new(w - 5.0, 5.0)));
        path.commands.push(PathCommand::Close);
        let frame = VectorFrame {
            width: w,
            height: h,
            view_box: None,
            root: Group {
                children: vec![Node::Path(PathNode {
                    path,
                    fill: Some(Paint::Solid(Rgba::opaque(0, 0, 0))),
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
    };
    Scene {
        pages: Some(vec![
            mk_page(300.0, 300.0),
            mk_page(300.0, 300.0),
            mk_page(300.0, 300.0),
        ]),
        ..Scene::default()
    }
}

fn default_annot(rect: [f32; 4], kind: WriterAnnotationKind) -> Annotation {
    Annotation {
        source_page_index: 0,
        rect,
        author: None,
        modified: None,
        flags: None,
        colour: None,
        border: None,
        kind,
    }
}

#[test]
fn text_annotation_roundtrips_through_reader() {
    let scene = one_page_scene();
    let annot = Annotation {
        source_page_index: 0,
        rect: [10.0, 20.0, 30.0, 40.0],
        author: Some("Jane Reviewer".into()),
        modified: Some("D:20260514120000Z".into()),
        flags: Some(4),
        colour: Some(vec![1.0, 1.0, 0.0]),
        border: None,
        kind: WriterAnnotationKind::Text {
            contents: "Please clarify this paragraph.".into(),
            icon: Some("Comment".into()),
            open: true,
        },
    };
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write annotated pdf");
    assert!(pdf.starts_with(b"%PDF-1."));

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 1);
    let a = &anns[0];
    assert_eq!(a.source_page_index, 0);
    assert_eq!(a.rect, [10.0, 20.0, 30.0, 40.0]);
    assert_eq!(
        a.contents.as_deref(),
        Some("Please clarify this paragraph.")
    );
    match &a.kind {
        AnnotationKind::Text { open, icon, .. } => {
            assert!(*open);
            assert_eq!(icon, "Comment");
        }
        other => panic!("expected /Text annotation, got {other:?}"),
    }
}

#[test]
fn link_uri_annotation_roundtrips_through_reader() {
    let scene = one_page_scene();
    let annot = default_annot(
        [40.0, 50.0, 200.0, 70.0],
        WriterAnnotationKind::Link {
            uri: "https://example.com/oxideav".into(),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Link { target } => match target {
            Some(oxideav_pdf::PdfLinkTarget::Uri(u)) => {
                assert_eq!(u, "https://example.com/oxideav");
            }
            other => panic!("expected URI link target, got {other:?}"),
        },
        other => panic!("expected /Link annotation, got {other:?}"),
    }
}

#[test]
fn freetext_annotation_roundtrips_with_quadding() {
    let scene = one_page_scene();
    let annot = default_annot(
        [50.0, 100.0, 250.0, 150.0],
        WriterAnnotationKind::FreeText {
            contents: "Overlay header text".into(),
            default_appearance: Some("/Helv 14 Tf 0 0 0.6 rg".into()),
            quadding: FreeTextQuadding::Center,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::FreeText {
            default_appearance,
            quadding,
            ..
        } => {
            assert_eq!(
                default_appearance.as_deref(),
                Some("/Helv 14 Tf 0 0 0.6 rg")
            );
            assert_eq!(*quadding, 1);
        }
        other => panic!("expected /FreeText annotation, got {other:?}"),
    }
    assert_eq!(anns[0].contents.as_deref(), Some("Overlay header text"));
}

#[test]
fn highlight_annotation_carries_quadpoints() {
    let scene = one_page_scene();
    // Two highlighted runs ⇒ 16 quad-point reals.
    let qp = vec![
        [50.0, 90.0, 150.0, 90.0, 50.0, 100.0, 150.0, 100.0],
        [50.0, 70.0, 150.0, 70.0, 50.0, 80.0, 150.0, 80.0],
    ];
    let annot = Annotation {
        colour: Some(vec![1.0, 1.0, 0.0]),
        ..default_annot(
            [50.0, 70.0, 150.0, 100.0],
            WriterAnnotationKind::Highlight {
                quad_points: qp.clone(),
            },
        )
    };
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::TextMarkup {
            variant,
            quad_points,
        } => {
            assert_eq!(*variant, TextMarkupVariant::Highlight);
            assert_eq!(quad_points.len(), 16);
        }
        other => panic!("expected /Highlight TextMarkup, got {other:?}"),
    }
}

#[test]
fn underline_squiggly_strikeout_all_round_trip() {
    let scene = one_page_scene();
    let qp = vec![[20.0, 20.0, 80.0, 20.0, 20.0, 30.0, 80.0, 30.0]];
    let annots = vec![
        default_annot(
            [20.0, 20.0, 80.0, 30.0],
            WriterAnnotationKind::Underline {
                quad_points: qp.clone(),
            },
        ),
        default_annot(
            [20.0, 40.0, 80.0, 50.0],
            WriterAnnotationKind::Squiggly {
                quad_points: qp.clone(),
            },
        ),
        default_annot(
            [20.0, 60.0, 80.0, 70.0],
            WriterAnnotationKind::StrikeOut { quad_points: qp },
        ),
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 3);
    let variants: Vec<TextMarkupVariant> = anns
        .iter()
        .filter_map(|a| match &a.kind {
            AnnotationKind::TextMarkup { variant, .. } => Some(*variant),
            _ => None,
        })
        .collect();
    assert!(variants.contains(&TextMarkupVariant::Underline));
    assert!(variants.contains(&TextMarkupVariant::Squiggly));
    assert!(variants.contains(&TextMarkupVariant::StrikeOut));
}

#[test]
fn stamp_annotation_carries_icon_name() {
    let scene = one_page_scene();
    let annot = default_annot(
        [100.0, 100.0, 200.0, 150.0],
        WriterAnnotationKind::Stamp {
            icon: Some("Approved".into()),
            contents: Some("OK to publish".into()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Stamp { icon } => assert_eq!(icon, "Approved"),
        other => panic!("expected /Stamp, got {other:?}"),
    }
    assert_eq!(anns[0].contents.as_deref(), Some("OK to publish"));
}

#[test]
fn stamp_without_icon_defaults_to_draft() {
    let scene = one_page_scene();
    let annot = default_annot(
        [100.0, 100.0, 200.0, 150.0],
        WriterAnnotationKind::Stamp {
            icon: None,
            contents: None,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    match &anns[0].kind {
        AnnotationKind::Stamp { icon } => assert_eq!(icon, "Draft"),
        other => panic!("expected /Stamp, got {other:?}"),
    }
}

#[test]
fn square_and_circle_annotations_round_trip() {
    let scene = one_page_scene();
    let annots = vec![
        default_annot(
            [40.0, 40.0, 140.0, 90.0],
            WriterAnnotationKind::Square {
                interior_colour: Some(vec![0.8, 0.8, 1.0]),
                line_width: Some(1.5),
            },
        ),
        default_annot(
            [160.0, 40.0, 260.0, 90.0],
            WriterAnnotationKind::Circle {
                interior_colour: None,
                line_width: Some(2.0),
            },
        ),
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 2);
    let mut got_square = false;
    let mut got_circle = false;
    for a in &anns {
        match &a.kind {
            AnnotationKind::Geometry { is_square, .. } => {
                if *is_square {
                    got_square = true;
                } else {
                    got_circle = true;
                }
            }
            _ => panic!("expected Geometry"),
        }
    }
    assert!(got_square && got_circle);
}

#[test]
fn ink_annotation_emits_inklist() {
    let scene = one_page_scene();
    let annot = default_annot(
        [20.0, 200.0, 280.0, 280.0],
        WriterAnnotationKind::Ink {
            strokes: vec![
                vec![30.0, 210.0, 80.0, 250.0, 130.0, 230.0],
                vec![150.0, 220.0, 200.0, 270.0, 260.0, 240.0],
            ],
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    // Round-197 closed the reader's Ink decode (`AnnotationKind::Ink`).
    // We confirm both the wire shape and the structured round-trip.
    let contains = |needle: &[u8]| pdf.windows(needle.len()).any(|w| w == needle);
    assert!(
        contains(b"/Ink"),
        "missing /Ink subtype name in serialised PDF"
    );
    assert!(
        contains(b"/InkList"),
        "missing /InkList entry in serialised PDF"
    );

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Ink { ink_list } => {
            assert_eq!(ink_list.len(), 2);
            assert_eq!(
                ink_list[0],
                vec![30.0_f32, 210.0, 80.0, 250.0, 130.0, 230.0]
            );
            assert_eq!(
                ink_list[1],
                vec![150.0_f32, 220.0, 200.0, 270.0, 260.0, 240.0]
            );
        }
        other => panic!("expected Ink, got {other:?}"),
    }
}

#[test]
fn annotations_across_multiple_pages_land_on_correct_pages() {
    let scene = three_page_scene();
    let annots = vec![
        Annotation {
            source_page_index: 0,
            ..default_annot(
                [10.0, 10.0, 50.0, 30.0],
                WriterAnnotationKind::Text {
                    contents: "page 0".into(),
                    icon: None,
                    open: false,
                },
            )
        },
        Annotation {
            source_page_index: 2,
            ..default_annot(
                [10.0, 10.0, 50.0, 30.0],
                WriterAnnotationKind::Text {
                    contents: "page 2".into(),
                    icon: None,
                    open: false,
                },
            )
        },
        Annotation {
            source_page_index: 2,
            ..default_annot(
                [60.0, 10.0, 100.0, 30.0],
                WriterAnnotationKind::Link {
                    uri: "https://example.com/p2".into(),
                },
            )
        },
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 3);

    let p0_count = anns.iter().filter(|a| a.source_page_index == 0).count();
    let p1_count = anns.iter().filter(|a| a.source_page_index == 1).count();
    let p2_count = anns.iter().filter(|a| a.source_page_index == 2).count();
    assert_eq!(p0_count, 1);
    assert_eq!(p1_count, 0);
    assert_eq!(p2_count, 2);
}

#[test]
fn rejects_annotation_on_out_of_range_page() {
    let scene = one_page_scene();
    let bad = Annotation {
        source_page_index: 5,
        ..default_annot(
            [10.0, 10.0, 30.0, 30.0],
            WriterAnnotationKind::Text {
                contents: "oops".into(),
                icon: None,
                open: false,
            },
        )
    };
    let err = write_pdf_with_annotations(&scene, &[bad]).expect_err("should reject");
    let msg = format!("{err}");
    assert!(msg.contains("out of range"), "msg = {msg}");
}

#[test]
fn rejects_ink_with_no_strokes() {
    let scene = one_page_scene();
    let bad = default_annot(
        [10.0, 10.0, 30.0, 30.0],
        WriterAnnotationKind::Ink { strokes: vec![] },
    );
    let err = write_pdf_with_annotations(&scene, &[bad]).expect_err("should reject");
    let msg = format!("{err}");
    assert!(msg.contains("no strokes"), "msg = {msg}");
}

#[test]
fn rejects_ink_with_odd_coord_count() {
    let scene = one_page_scene();
    let bad = default_annot(
        [10.0, 10.0, 30.0, 30.0],
        WriterAnnotationKind::Ink {
            strokes: vec![vec![1.0, 2.0, 3.0]],
        },
    );
    let err = write_pdf_with_annotations(&scene, &[bad]).expect_err("should reject");
    let msg = format!("{err}");
    assert!(msg.contains("even number of coords"), "msg = {msg}");
}

#[test]
fn rejects_empty_text_markup_quadpoints() {
    let scene = one_page_scene();
    let bad = default_annot(
        [10.0, 10.0, 30.0, 30.0],
        WriterAnnotationKind::Highlight {
            quad_points: vec![],
        },
    );
    let err = write_pdf_with_annotations(&scene, &[bad]).expect_err("should reject");
    let msg = format!("{err}");
    assert!(msg.contains("QuadPoints"), "msg = {msg}");
}

// ---------------------------------------------------------------------
// External oracle.
// ---------------------------------------------------------------------

fn tool_exists(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn write_temp_pdf(pdf: &[u8], stem: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("oxideav-pdf-{stem}-{pid}-{nanos}.pdf"));
    std::fs::write(&path, pdf).expect("temp pdf write");
    path
}

#[test]
fn qpdf_check_accepts_mixed_annotation_pdf() {
    if !tool_exists("qpdf") {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    let scene = one_page_scene();
    let qp = vec![[40.0, 40.0, 100.0, 40.0, 40.0, 50.0, 100.0, 50.0]];
    let annots = vec![
        default_annot(
            [10.0, 10.0, 30.0, 30.0],
            WriterAnnotationKind::Text {
                contents: "Note".into(),
                icon: Some("Comment".into()),
                open: false,
            },
        ),
        default_annot(
            [40.0, 60.0, 200.0, 80.0],
            WriterAnnotationKind::Link {
                uri: "https://example.com".into(),
            },
        ),
        default_annot(
            [40.0, 100.0, 200.0, 130.0],
            WriterAnnotationKind::FreeText {
                contents: "header".into(),
                default_appearance: None,
                quadding: FreeTextQuadding::Right,
            },
        ),
        Annotation {
            colour: Some(vec![1.0, 1.0, 0.0]),
            ..default_annot(
                [40.0, 40.0, 100.0, 50.0],
                WriterAnnotationKind::Highlight {
                    quad_points: qp.clone(),
                },
            )
        },
        default_annot(
            [40.0, 150.0, 140.0, 200.0],
            WriterAnnotationKind::Stamp {
                icon: Some("Confidential".into()),
                contents: None,
            },
        ),
        default_annot(
            [160.0, 150.0, 260.0, 200.0],
            WriterAnnotationKind::Square {
                interior_colour: Some(vec![0.8, 0.8, 1.0]),
                line_width: Some(1.0),
            },
        ),
        default_annot(
            [20.0, 230.0, 280.0, 280.0],
            WriterAnnotationKind::Ink {
                strokes: vec![vec![30.0, 240.0, 100.0, 260.0, 200.0, 250.0]],
            },
        ),
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let path = write_temp_pdf(&pdf, "annot-r32");
    let ok = Command::new("qpdf")
        .args(["--check", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "qpdf --check rejected the annotated PDF");
}
