//! Round-257 — `/PrinterMark` annotation-writer end-to-end tests
//! (ISO 32000-1 §12.5.6.20 Table 362).
//!
//! Validates that [`oxideav_pdf::write_pdf_with_annotations`] handles
//! the [`oxideav_pdf::WriterAnnotationKind::PrinterMark`] variant by
//! emitting the `/Subtype /PrinterMark` annotation dict plus the
//! optional `/MN` mark-name Name. Round-trip through the round-215
//! generic annotation reader confirms the wire bits match.
//!
//! Provenance: ISO 32000-1:2008 §12.5.6.20 Table 362 (printer's-mark
//! annotation entries). The crate's docs/document/pdf/PDF32000_2008.pdf
//! is the sole source for every Table 362 entry encoded by this writer.

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
// §12.5.6.20 PrinterMark — bare form, no `/MN`.
// ────────────────────────────────────────────────────────────────────

/// Minimal PrinterMark annotation — no `/MN` entry. Table 362 makes
/// the entry optional; the writer should emit `/Subtype /PrinterMark`
/// and omit `/MN`, and the round-215 reader should round-trip with
/// `mark_name: None` (its lookup falls into the `_ => None` arm when
/// the entry is absent).
#[test]
fn printer_mark_bare_no_mn_roundtrips() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::PrinterMark { mark_name: None },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");

    let pdf_str = String::from_utf8_lossy(&pdf);
    assert!(
        pdf_str.contains("/Subtype /PrinterMark"),
        "annotation /Subtype /PrinterMark not emitted",
    );
    assert!(
        !pdf_str.contains("/MN"),
        "/MN should be omitted when mark_name is None",
    );

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 1, "exactly one annotation expected");
    match &anns[0].kind {
        AnnotationKind::PrinterMark { mark_name } => {
            assert!(mark_name.is_none(), "/MN should round-trip as None");
        }
        other => panic!("expected PrinterMark, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.20 PrinterMark — `/MN` taxonomy round-trip across the four
// commonly observed mark-name values.
// ────────────────────────────────────────────────────────────────────

/// `/MN /ColorBar` — colour-bar production mark. Pin the per-process
/// colour reference strip on the page edge.
#[test]
fn printer_mark_color_bar_roundtrips() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::PrinterMark {
            mark_name: Some("ColorBar".to_string()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");

    let pdf_str = String::from_utf8_lossy(&pdf);
    assert!(
        pdf_str.contains("/Subtype /PrinterMark"),
        "/Subtype /PrinterMark not emitted",
    );
    assert!(
        pdf_str.contains("/MN /ColorBar"),
        "/MN /ColorBar not emitted",
    );

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::PrinterMark { mark_name } => {
            assert_eq!(mark_name.as_deref(), Some("ColorBar"));
        }
        other => panic!("expected PrinterMark, got {other:?}"),
    }
}

/// `/MN /RegistrationTarget` — multi-process alignment crosshair.
#[test]
fn printer_mark_registration_target_roundtrips() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::PrinterMark {
            mark_name: Some("RegistrationTarget".to_string()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    match &anns[0].kind {
        AnnotationKind::PrinterMark { mark_name } => {
            assert_eq!(mark_name.as_deref(), Some("RegistrationTarget"));
        }
        other => panic!("expected PrinterMark, got {other:?}"),
    }
}

/// `/MN /CutMark` — trim-line / cut-line marker.
#[test]
fn printer_mark_cut_mark_roundtrips() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::PrinterMark {
            mark_name: Some("CutMark".to_string()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    match &anns[0].kind {
        AnnotationKind::PrinterMark { mark_name } => {
            assert_eq!(mark_name.as_deref(), Some("CutMark"));
        }
        other => panic!("expected PrinterMark, got {other:?}"),
    }
}

/// `/MN /PageInformation` — page-information sidebar. Sheet number,
/// job id, plate name, etc.
#[test]
fn printer_mark_page_information_roundtrips() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::PrinterMark {
            mark_name: Some("PageInformation".to_string()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    match &anns[0].kind {
        AnnotationKind::PrinterMark { mark_name } => {
            assert_eq!(mark_name.as_deref(), Some("PageInformation"));
        }
        other => panic!("expected PrinterMark, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.20 PrinterMark — non-standard /MN values pass through.
// ────────────────────────────────────────────────────────────────────

/// Table 362 does NOT enumerate a closed taxonomy — any Name passes
/// through verbatim. A bespoke production-tool mark name (`Marks_v3`)
/// should round-trip unchanged so a colour-management consumer can
/// match its own private vocabulary.
#[test]
fn printer_mark_arbitrary_name_roundtrips() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::PrinterMark {
            mark_name: Some("MyProductionTool_Marks_v3".to_string()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    match &anns[0].kind {
        AnnotationKind::PrinterMark { mark_name } => {
            assert_eq!(mark_name.as_deref(), Some("MyProductionTool_Marks_v3"));
        }
        other => panic!("expected PrinterMark, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// Cross-page + cross-subtype composite — a print-production PDF that
// stamps a colour bar + registration target + cut mark on one page,
// and a page-information sidebar on a second page.
// ────────────────────────────────────────────────────────────────────

fn two_page_scene() -> Scene {
    let mut s = one_page_scene();
    // Clone the single page so the second page has the same content
    // frame and dimensions — the round-215 reader walks both pages'
    // /Annots arrays regardless.
    let pages = s.pages.as_mut().unwrap();
    let page = pages[0].clone();
    pages.push(page);
    s
}

#[test]
fn printer_mark_multi_page_composite_roundtrips() {
    let scene = two_page_scene();
    let annots = vec![
        // Page 0 — colour bar across the bottom of the sheet.
        Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 300.0, 12.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: WriterAnnotationKind::PrinterMark {
                mark_name: Some("ColorBar".to_string()),
            },
        },
        // Page 0 — registration target top-left corner.
        Annotation {
            source_page_index: 0,
            rect: [4.0, 286.0, 16.0, 298.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: WriterAnnotationKind::PrinterMark {
                mark_name: Some("RegistrationTarget".to_string()),
            },
        },
        // Page 0 — cut mark bottom-right corner.
        Annotation {
            source_page_index: 0,
            rect: [284.0, 2.0, 298.0, 16.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: WriterAnnotationKind::PrinterMark {
                mark_name: Some("CutMark".to_string()),
            },
        },
        // Page 1 — page-information sidebar; no /MN on the second
        // example to exercise the absent-equals-None reader branch.
        Annotation {
            source_page_index: 1,
            rect: [280.0, 100.0, 300.0, 200.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: WriterAnnotationKind::PrinterMark { mark_name: None },
        },
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let read = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(read.len(), 4, "all four PrinterMarks should surface");

    // The annotation order across the two pages matches the input
    // bucket order (page 0 first, page 1 second). Match by
    // source_page_index + mark name to guard against re-ordering
    // surprises.
    let mut by_name: std::collections::BTreeMap<(usize, Option<String>), usize> =
        std::collections::BTreeMap::new();
    for a in &read {
        match &a.kind {
            AnnotationKind::PrinterMark { mark_name } => {
                *by_name
                    .entry((a.source_page_index, mark_name.clone()))
                    .or_insert(0) += 1;
            }
            other => panic!("expected PrinterMark, got {other:?}"),
        }
    }
    assert_eq!(
        by_name.get(&(0, Some("ColorBar".to_string()))).copied(),
        Some(1),
    );
    assert_eq!(
        by_name
            .get(&(0, Some("RegistrationTarget".to_string())))
            .copied(),
        Some(1),
    );
    assert_eq!(
        by_name.get(&(0, Some("CutMark".to_string()))).copied(),
        Some(1),
    );
    assert_eq!(by_name.get(&(1, None)).copied(), Some(1));
}

// ────────────────────────────────────────────────────────────────────
// Validation rejects — empty /MN string.
// ────────────────────────────────────────────────────────────────────

/// `Some(String::new())` is rejected because §7.3.5 requires a Name
/// token to be at least one byte; a zero-byte mark name would
/// serialise as a bare `/` token that the round-215 reader cannot
/// distinguish from the absent-entry case.
#[test]
fn printer_mark_empty_mn_rejected() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::PrinterMark {
            mark_name: Some(String::new()),
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot]).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("/PrinterMark"),
        "error mentions /PrinterMark: {msg}",
    );
    assert!(msg.contains("/MN"), "error mentions /MN: {msg}");
}

// ────────────────────────────────────────────────────────────────────
// Cross-subtype composite — PrinterMark + Watermark on one page.
// Production-press PDFs often combine a fixed-print watermark
// ("DRAFT", "INTERNAL") with one or more printer's marks. Exercise
// both in a single annotations slice to confirm the round-215 reader's
// subtype dispatch surfaces both correctly.
// ────────────────────────────────────────────────────────────────────

#[test]
fn printer_mark_with_watermark_on_same_page_roundtrips() {
    let scene = one_page_scene();
    let annots = vec![
        Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 30.0, 40.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: WriterAnnotationKind::PrinterMark {
                mark_name: Some("ColorBar".to_string()),
            },
        },
        Annotation {
            source_page_index: 0,
            rect: [50.0, 50.0, 250.0, 250.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: WriterAnnotationKind::Watermark { fixed_print: None },
        },
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let read = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(read.len(), 2);
    let pm_count = read
        .iter()
        .filter(|a| matches!(a.kind, AnnotationKind::PrinterMark { .. }))
        .count();
    let wm_count = read
        .iter()
        .filter(|a| matches!(a.kind, AnnotationKind::Watermark { .. }))
        .count();
    assert_eq!(pm_count, 1, "one PrinterMark expected");
    assert_eq!(wm_count, 1, "one Watermark expected");
}
