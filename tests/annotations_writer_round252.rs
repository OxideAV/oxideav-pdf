//! Round-252 — `/Watermark` annotation-writer end-to-end tests
//! (ISO 32000-1 §12.5.6.22 Table 190 + §12.5.6.22 Table 191).
//!
//! Validates that [`oxideav_pdf::write_pdf_with_annotations`] handles
//! the [`oxideav_pdf::WriterAnnotationKind::Watermark`] variant by
//! emitting (a) the `/Subtype /Watermark` annotation dict and
//! (b) when supplied, the inline `/FixedPrint` sub-dict carrying the
//! Table 191 entries `/Type /FixedPrint`, `/Matrix`, `/H`, and `/V`.
//! Round-trip through the round-204 generic annotation reader confirms
//! the wire bits match.
//!
//! Provenance: ISO 32000-1:2008 §12.5.6.22 Table 190 (watermark
//! annotation entries) + Table 191 (fixed-print sub-dict entries). The
//! crate's docs/document/pdf/PDF32000_2008.pdf is the sole source for
//! every Table 190 / Table 191 entry encoded by this writer.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    read_pdf_annotations, write_pdf_with_annotations, Annotation, AnnotationKind, FixedPrintSpec,
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
// §12.5.6.22 Watermark annotation (Table 190) — bare form, no
// `/FixedPrint`.
// ────────────────────────────────────────────────────────────────────

/// Minimal Watermark annotation — no `/FixedPrint` sub-dict. Per
/// Table 190 the entry "shall be drawn without any special
/// consideration for the dimensions of the target media." The writer
/// should emit `/Subtype /Watermark` and omit `/FixedPrint`, and the
/// round-204 reader should round-trip with `fixed_print: None`.
#[test]
fn watermark_bare_no_fixed_print_roundtrips() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::Watermark { fixed_print: None },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");

    // Wire-level sanity — `/Subtype /Watermark` present, no
    // `/FixedPrint` entry.
    let pdf_str = String::from_utf8_lossy(&pdf);
    assert!(
        pdf_str.contains("/Subtype /Watermark"),
        "annotation /Subtype /Watermark not emitted",
    );
    assert!(
        !pdf_str.contains("/FixedPrint"),
        "/FixedPrint should be omitted when fixed_print is None",
    );

    // Round-204 annotation-reader round-trip.
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 1, "exactly one annotation expected");
    match &anns[0].kind {
        AnnotationKind::Watermark { fixed_print } => {
            assert!(
                fixed_print.is_none(),
                "/FixedPrint should round-trip as None",
            );
        }
        other => panic!("expected Watermark, got {other:?}"),
    }
}

/// Watermark with an empty `Some(FixedPrintSpec::default())` — the
/// minimal opt-in to media-relative rendering. The writer should emit
/// the bare `/Type /FixedPrint` marker dict (no /Matrix, /H, or /V
/// overrides), and the round-204 reader should surface a
/// `FixedPrint::default()` (identity matrix, h=v=0).
#[test]
fn watermark_empty_fixed_print_emits_marker_only() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::Watermark {
            fixed_print: Some(FixedPrintSpec::default()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let pdf_str = String::from_utf8_lossy(&pdf);

    // `/Type /FixedPrint` marker required per Table 191.
    assert!(
        pdf_str.contains("/Type /FixedPrint"),
        "/Type /FixedPrint marker not emitted",
    );
    // No overrides — the default values should be omitted per
    // Table 191.
    assert!(
        !pdf_str.contains("/Matrix"),
        "/Matrix should be omitted when matrix is None (Table 191 default identity)",
    );
    // /H and /V can appear as substrings of other names — pin to
    // explicit `/H ` / `/V ` followed by a value. We don't expect
    // them at all in the empty-override case.
    assert!(
        !pdf_str.contains("/H 0"),
        "/H should be omitted when h is None (Table 191 default 0)",
    );
    assert!(
        !pdf_str.contains("/V 0"),
        "/V should be omitted when v is None (Table 191 default 0)",
    );

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Watermark { fixed_print } => {
            let fp = fixed_print
                .as_ref()
                .expect("/FixedPrint should round-trip as Some");
            // Reader returns Table 191 defaults for absent entries:
            // identity matrix, h=0, v=0.
            assert_eq!(
                fp.matrix,
                [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
                "/Matrix reader-side default should be identity (Table 191)",
            );
            assert_eq!(fp.h, 0.0);
            assert_eq!(fp.v, 0.0);
        }
        other => panic!("expected Watermark, got {other:?}"),
    }
}

/// Watermark with explicit `/Matrix`, `/H`, and `/V` overrides —
/// exercises every Table 191 entry. The writer should emit all three
/// non-default entries, and the round-204 reader should surface the
/// exact values back.
#[test]
fn watermark_full_fixed_print_overrides_roundtrip() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::Watermark {
            fixed_print: Some(FixedPrintSpec {
                // 2× scale, translate +36 +72 (one-inch right + one-
                // inch top in default user space @ 72 dpi).
                matrix: Some([2.0, 0.0, 0.0, 2.0, 36.0, 72.0]),
                // 50% across the printed media horizontally.
                h: Some(0.5),
                // 25% down the printed media vertically.
                v: Some(0.25),
            }),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let pdf_str = String::from_utf8_lossy(&pdf);

    // Each Table 191 entry present at the wire level.
    assert!(
        pdf_str.contains("/Type /FixedPrint"),
        "/Type /FixedPrint marker not emitted",
    );
    assert!(
        pdf_str.contains("/Matrix"),
        "/Matrix should be emitted when an explicit override is set",
    );

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Watermark { fixed_print } => {
            let fp = fixed_print
                .as_ref()
                .expect("/FixedPrint should round-trip as Some");
            // Matrix entries round-trip via f32 ⇒ f64 ⇒ f32; values
            // chosen so the conversions are exact.
            assert_eq!(fp.matrix, [2.0, 0.0, 0.0, 2.0, 36.0, 72.0]);
            assert!(
                (fp.h - 0.5).abs() < 1e-6,
                "/H round-trip should preserve 0.5 (got {})",
                fp.h,
            );
            assert!(
                (fp.v - 0.25).abs() < 1e-6,
                "/V round-trip should preserve 0.25 (got {})",
                fp.v,
            );
        }
        other => panic!("expected Watermark, got {other:?}"),
    }
}

/// Watermark cross-page composite — two pages, one Watermark per
/// page. Exercises the `source_page_index` dispatch alongside the
/// fixed-print writer.
#[test]
fn watermark_per_page_composite_roundtrips() {
    // Two-page scene.
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(190.0, 10.0)));
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
    let mut page_a = Page::new(300.0, 300.0);
    page_a.content = frame.clone();
    let mut page_b = Page::new(300.0, 300.0);
    page_b.content = frame;
    let scene = Scene {
        pages: Some(vec![page_a, page_b]),
        ..Scene::default()
    };

    let annots = vec![
        Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 30.0, 40.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: WriterAnnotationKind::Watermark { fixed_print: None },
        },
        Annotation {
            source_page_index: 1,
            rect: [50.0, 60.0, 70.0, 80.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: WriterAnnotationKind::Watermark {
                fixed_print: Some(FixedPrintSpec {
                    matrix: None,
                    h: Some(0.5),
                    v: Some(0.5),
                }),
            },
        },
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 2);
    // Page-0 annotation has no /FixedPrint.
    match &anns[0].kind {
        AnnotationKind::Watermark { fixed_print } => {
            assert!(fixed_print.is_none());
        }
        other => panic!("expected Watermark on page 0, got {other:?}"),
    }
    // Page-1 annotation has /FixedPrint with /H = /V = 0.5.
    match &anns[1].kind {
        AnnotationKind::Watermark { fixed_print } => {
            let fp = fixed_print.as_ref().expect("/FixedPrint on page 1");
            assert!((fp.h - 0.5).abs() < 1e-6);
            assert!((fp.v - 0.5).abs() < 1e-6);
        }
        other => panic!("expected Watermark on page 1, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// Validation rejects.
// ────────────────────────────────────────────────────────────────────

/// Per Table 191 "negative values should not be used, since they may
/// cause content to be drawn off the page." The writer surfaces that
/// as a hard reject so a downstream renderer sees only in-range
/// fixed-print metadata.
#[test]
fn watermark_validation_rejects_negative_h() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::Watermark {
            fixed_print: Some(FixedPrintSpec {
                matrix: None,
                h: Some(-0.1),
                v: None,
            }),
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot]).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("/H") && msg.contains("non-negative"),
        "error mentions /H non-negative requirement: {msg}",
    );
}

/// Symmetric check for `/V`.
#[test]
fn watermark_validation_rejects_negative_v() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::Watermark {
            fixed_print: Some(FixedPrintSpec {
                matrix: None,
                h: None,
                v: Some(-0.5),
            }),
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot]).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("/V") && msg.contains("non-negative"),
        "error mentions /V non-negative requirement: {msg}",
    );
}

/// `/Matrix` slots must all be finite (NaN / infinity would describe
/// an undefined affine transform per §8.3.4).
#[test]
fn watermark_validation_rejects_nan_in_matrix() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::Watermark {
            fixed_print: Some(FixedPrintSpec {
                matrix: Some([1.0, 0.0, 0.0, f32::NAN, 0.0, 0.0]),
                h: None,
                v: None,
            }),
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot]).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("/Matrix") && msg.contains("finite"),
        "error mentions /Matrix finite requirement: {msg}",
    );
}
