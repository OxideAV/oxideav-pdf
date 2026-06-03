//! Round-227 — `/Line` / `/Polygon` / `/PolyLine` annotation writer
//! end-to-end tests (ISO 32000-1 §12.5.6.7 + §12.5.6.9).
//!
//! Validates that [`oxideav_pdf::write_pdf_with_annotations`] emits a
//! PDF whose page-level `/Annots` arrays contain matching annotation
//! dicts for the three line-family subtypes the round-197 reader
//! already decodes — closing the writer-side symmetry for that family.
//!
//! Round-trip is exercised against the round-26/round-197 generic
//! annotation reader ([`oxideav_pdf::read_pdf_annotations`]).

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    read_pdf_annotations, write_pdf_with_annotations, Annotation, AnnotationKind,
    WriterAnnotationKind,
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

// ────────────────────────────────────────────────────────────────────
// §12.5.6.7 Line annotation (Table 175).
// ────────────────────────────────────────────────────────────────────

#[test]
fn line_minimal_required_l_only_roundtrips() {
    // Table 175: only `/L` is required; every other field is optional
    // and defaults apply when absent.
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 110.0, 60.0],
        WriterAnnotationKind::Line {
            endpoints: [10.0, 20.0, 110.0, 60.0],
            line_endings: None,
            interior_colour: None,
            leader_line: None,
            leader_line_extension: None,
            leader_line_offset: None,
            cap: false,
            intent: None,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Line {
            l,
            line_endings,
            interior_colour,
            leader_line,
            leader_line_extension,
            leader_line_offset,
            cap,
            intent,
        } => {
            assert_eq!(*l, [10.0, 20.0, 110.0, 60.0]);
            assert!(line_endings.is_none());
            assert!(interior_colour.is_none());
            assert!(leader_line.is_none());
            assert!(leader_line_extension.is_none());
            assert!(leader_line_offset.is_none());
            // Table 175 default for /Cap is false ⇒ absent on the
            // wire ⇒ false back through the reader.
            assert!(!*cap);
            assert!(intent.is_none());
        }
        other => panic!("expected /Line annotation, got {other:?}"),
    }
}

#[test]
fn line_with_endings_and_leader_geometry_roundtrips() {
    // §12.5.6.7 Table 175 + Table 176: a fully-populated /Line.
    let scene = one_page_scene();
    let annot = default_annot(
        [0.0, 0.0, 200.0, 100.0],
        WriterAnnotationKind::Line {
            endpoints: [10.0, 20.0, 190.0, 80.0],
            line_endings: Some(["OpenArrow".to_string(), "ClosedArrow".to_string()]),
            interior_colour: Some(vec![1.0, 0.0, 0.0]),
            leader_line: Some(8.0),
            leader_line_extension: Some(3.5),
            leader_line_offset: Some(1.0),
            cap: true,
            intent: Some("LineArrow".to_string()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Line {
            l,
            line_endings,
            interior_colour,
            leader_line,
            leader_line_extension,
            leader_line_offset,
            cap,
            intent,
        } => {
            assert_eq!(*l, [10.0, 20.0, 190.0, 80.0]);
            let le = line_endings.as_ref().expect("/LE must survive round-trip");
            assert_eq!(le[0], "OpenArrow");
            assert_eq!(le[1], "ClosedArrow");
            assert_eq!(interior_colour.as_deref(), Some(&[1.0, 0.0, 0.0][..]));
            assert_eq!(*leader_line, Some(8.0));
            assert_eq!(*leader_line_extension, Some(3.5));
            assert_eq!(*leader_line_offset, Some(1.0));
            assert!(*cap);
            assert_eq!(intent.as_deref(), Some("LineArrow"));
        }
        other => panic!("expected /Line annotation, got {other:?}"),
    }
}

#[test]
fn line_dict_omits_cap_when_false() {
    // Round-trip-tight: Table 175 says /Cap defaults to false, so the
    // writer must leave it off when the caller passes `cap: false`.
    // This keeps a write-then-read cycle from drifting through the
    // "absent → false" branch on the reader side.
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 110.0, 60.0],
        WriterAnnotationKind::Line {
            endpoints: [10.0, 20.0, 110.0, 60.0],
            line_endings: None,
            interior_colour: None,
            leader_line: None,
            leader_line_extension: None,
            leader_line_offset: None,
            cap: false,
            intent: None,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    // The annotation dict is somewhere in the body — search for the
    // /Subtype /Line marker and confirm there is no /Cap key in the
    // surrounding bytes (a stricter byte-level check than the reader
    // round-trip alone would catch, since the reader collapses
    // absent → false anyway).
    let needle = b"/Subtype /Line";
    let pos = pdf
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("/Subtype /Line marker present in body");
    // Scan up to the end of the dict (next `>>`).
    let end = pdf[pos..]
        .windows(2)
        .position(|w| w == b">>")
        .map(|i| pos + i)
        .expect("dict terminator present");
    let dict_slice = &pdf[pos..end];
    assert!(
        !dict_slice.windows(4).any(|w| w == b"/Cap"),
        "writer must omit /Cap when caller passes cap: false (Table 175 default)"
    );
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.9 Polygon / PolyLine annotations (Table 178).
// ────────────────────────────────────────────────────────────────────

#[test]
fn polygon_minimal_vertices_only_roundtrips() {
    let scene = one_page_scene();
    let verts = vec![10.0, 10.0, 100.0, 10.0, 100.0, 100.0, 10.0, 100.0];
    let annot = default_annot(
        [10.0, 10.0, 100.0, 100.0],
        WriterAnnotationKind::Polygon {
            vertices: verts.clone(),
            interior_colour: None,
            intent: None,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::PolygonOrPolyLine {
            is_polygon,
            vertices,
            line_endings,
            interior_colour,
            intent,
        } => {
            assert!(*is_polygon);
            assert_eq!(vertices, &verts);
            assert!(line_endings.is_none());
            assert!(interior_colour.is_none());
            assert!(intent.is_none());
        }
        other => panic!("expected /Polygon annotation, got {other:?}"),
    }
}

#[test]
fn polygon_with_interior_colour_and_intent_roundtrips() {
    let scene = one_page_scene();
    let verts = vec![20.0, 20.0, 80.0, 20.0, 80.0, 80.0];
    let annot = default_annot(
        [20.0, 20.0, 80.0, 80.0],
        WriterAnnotationKind::Polygon {
            vertices: verts.clone(),
            interior_colour: Some(vec![0.7, 0.7, 0.95]),
            intent: Some("PolygonCloud".to_string()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::PolygonOrPolyLine {
            is_polygon,
            vertices,
            interior_colour,
            intent,
            ..
        } => {
            assert!(*is_polygon);
            assert_eq!(vertices, &verts);
            assert_eq!(interior_colour.as_deref(), Some(&[0.7, 0.7, 0.95][..]));
            assert_eq!(intent.as_deref(), Some("PolygonCloud"));
        }
        other => panic!("expected /Polygon annotation, got {other:?}"),
    }
}

#[test]
fn polyline_minimal_vertices_only_roundtrips() {
    let scene = one_page_scene();
    let verts = vec![5.0, 5.0, 25.0, 25.0, 50.0, 50.0];
    let annot = default_annot(
        [5.0, 5.0, 50.0, 50.0],
        WriterAnnotationKind::PolyLine {
            vertices: verts.clone(),
            line_endings: None,
            interior_colour: None,
            intent: None,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::PolygonOrPolyLine {
            is_polygon,
            vertices,
            line_endings,
            ..
        } => {
            assert!(!*is_polygon);
            assert_eq!(vertices, &verts);
            assert!(line_endings.is_none());
        }
        other => panic!("expected /PolyLine annotation, got {other:?}"),
    }
}

#[test]
fn polyline_with_endings_roundtrips() {
    // §12.5.6.9: /PolyLine's /LE is the same two-name shape Table 176
    // gives Line — Polygon doesn't use /LE in practice (its segments
    // close back to the start).
    let scene = one_page_scene();
    let verts = vec![10.0, 10.0, 90.0, 10.0, 90.0, 90.0];
    let annot = default_annot(
        [10.0, 10.0, 90.0, 90.0],
        WriterAnnotationKind::PolyLine {
            vertices: verts.clone(),
            line_endings: Some(["Circle".to_string(), "OpenArrow".to_string()]),
            interior_colour: Some(vec![0.0, 0.5, 1.0]),
            intent: Some("PolyLineDimension".to_string()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::PolygonOrPolyLine {
            is_polygon,
            vertices,
            line_endings,
            interior_colour,
            intent,
        } => {
            assert!(!*is_polygon);
            assert_eq!(vertices, &verts);
            let le = line_endings
                .as_ref()
                .expect("/LE must survive round-trip on PolyLine");
            assert_eq!(le[0], "Circle");
            assert_eq!(le[1], "OpenArrow");
            assert_eq!(interior_colour.as_deref(), Some(&[0.0, 0.5, 1.0][..]));
            assert_eq!(intent.as_deref(), Some("PolyLineDimension"));
        }
        other => panic!("expected /PolyLine annotation, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// Validation guards.
// ────────────────────────────────────────────────────────────────────

#[test]
fn polygon_rejects_odd_vertex_count() {
    let scene = one_page_scene();
    let annot = default_annot(
        [0.0, 0.0, 100.0, 100.0],
        WriterAnnotationKind::Polygon {
            vertices: vec![10.0, 10.0, 50.0],
            interior_colour: None,
            intent: None,
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot])
        .expect_err("odd-length /Vertices must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("/Vertices"), "error mentions /Vertices: {msg}");
}

#[test]
fn polyline_rejects_under_two_vertices() {
    let scene = one_page_scene();
    let annot = default_annot(
        [0.0, 0.0, 100.0, 100.0],
        WriterAnnotationKind::PolyLine {
            vertices: vec![10.0, 10.0],
            line_endings: None,
            interior_colour: None,
            intent: None,
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot])
        .expect_err("single-vertex polyline must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("/Vertices"), "error mentions /Vertices: {msg}");
}

// ────────────────────────────────────────────────────────────────────
// Cross-subtype enumeration on a single page.
// ────────────────────────────────────────────────────────────────────

#[test]
fn line_polygon_polyline_share_one_page() {
    let scene = one_page_scene();
    let annots = vec![
        default_annot(
            [10.0, 20.0, 110.0, 60.0],
            WriterAnnotationKind::Line {
                endpoints: [10.0, 20.0, 110.0, 60.0],
                line_endings: None,
                interior_colour: None,
                leader_line: None,
                leader_line_extension: None,
                leader_line_offset: None,
                cap: false,
                intent: None,
            },
        ),
        default_annot(
            [10.0, 10.0, 100.0, 100.0],
            WriterAnnotationKind::Polygon {
                vertices: vec![10.0, 10.0, 100.0, 10.0, 100.0, 100.0, 10.0, 100.0],
                interior_colour: None,
                intent: None,
            },
        ),
        default_annot(
            [5.0, 5.0, 80.0, 80.0],
            WriterAnnotationKind::PolyLine {
                vertices: vec![5.0, 5.0, 40.0, 20.0, 80.0, 80.0],
                line_endings: None,
                interior_colour: None,
                intent: None,
            },
        ),
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let read_back = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(read_back.len(), 3);

    let mut saw_line = false;
    let mut saw_polygon = false;
    let mut saw_polyline = false;
    for a in &read_back {
        match &a.kind {
            AnnotationKind::Line { .. } => saw_line = true,
            AnnotationKind::PolygonOrPolyLine { is_polygon, .. } => {
                if *is_polygon {
                    saw_polygon = true;
                } else {
                    saw_polyline = true;
                }
            }
            other => panic!("unexpected subtype on round-trip: {other:?}"),
        }
    }
    assert!(saw_line && saw_polygon && saw_polyline);
}
