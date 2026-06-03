//! Round-220 — `/Subtype /3D` decoder in the round-26 reader
//! (ISO 32000-1 §13.6.2 Table 298 + Table 299 activation dict).
//!
//! Before this round 3D annotations fell through to
//! [`AnnotationKind::Other { subtype: "3D" }`], so any 3D-aware
//! forensic walk had to special-case the stringly-typed name.
//!
//! Coverage validated end-to-end against hand-synthesised PDFs:
//!
//! * §13.6.2 Table 298 — `/3DD` (artwork stream ref), `/3DV`
//!   (initial view selector — all four spec shapes), `/3DA`
//!   (activation dict), `/3DI` (interactive flag, default `true`),
//!   `/3DB` (3D view box rectangle).
//! * §13.6.2 Table 299 — `/A`, `/AIS`, `/D`, `/DIS`, plus the
//!   PDF 1.7 `/TB` and `/NP` flags.

use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{read_pdf_annotations, AnnotationKind, ThreeDActivation, ThreeDViewSelector};

fn read_annots(pdf: &[u8]) -> Vec<oxideav_pdf::PdfAnnotation> {
    let mut r = DocumentReader::open(pdf).unwrap();
    read_pdf_annotations(&mut r).unwrap()
}

/// Minimal one-page PDF with the supplied per-page annotation dicts
/// spliced into the page's `/Annots` array. Object numbering follows
/// the round-215 / round-209 / round-204 / round-197 shape.
///
/// Objects 5..N are emitted verbatim from `extra_obj_bodies` so each
/// test can attach a 3D-stream stub, an activation sub-dict, etc.
fn synth_pdf_with_objects(extra_obj_bodies: &[&str], annot_refs: &[u32]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"%PDF-1.7\n%");
    body.extend_from_slice(&[0xe2, 0xe3, 0xcf, 0xd3]);
    body.push(b'\n');
    let mut offsets: Vec<usize> = Vec::new();
    let push_obj = |body: &mut Vec<u8>, offsets: &mut Vec<usize>, n: u32, content: &str| {
        offsets.push(body.len());
        body.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", n, content).as_bytes());
    };
    push_obj(
        &mut body,
        &mut offsets,
        1,
        "<< /Type /Catalog /Pages 2 0 R >>",
    );
    push_obj(
        &mut body,
        &mut offsets,
        2,
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    );
    let annot_arr = annot_refs
        .iter()
        .map(|n| format!("{} 0 R", n))
        .collect::<Vec<_>>()
        .join(" ");
    let page_dict = format!(
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
         /Contents 4 0 R /Resources << >> /Annots [{}] >>",
        annot_arr
    );
    push_obj(&mut body, &mut offsets, 3, &page_dict);
    push_obj(
        &mut body,
        &mut offsets,
        4,
        "<< /Length 0 >>\nstream\n\nendstream",
    );
    for (i, ob) in extra_obj_bodies.iter().enumerate() {
        push_obj(&mut body, &mut offsets, 5 + i as u32, ob);
    }
    let xref_off = body.len();
    let n_objs = 5 + extra_obj_bodies.len();
    body.extend_from_slice(format!("xref\n0 {}\n", n_objs).as_bytes());
    body.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        body.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    body.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            n_objs, xref_off
        )
        .as_bytes(),
    );
    body
}

// ────────────────────────────────────────────────────────────────────
// §13.6.2 Table 298 — minimal annot: required `/3DD` only
// ────────────────────────────────────────────────────────────────────

#[test]
fn three_d_minimal_3dd_only() {
    // Object 5 = the 3D annotation; object 6 = the 3D stream stub.
    let annot = "<< /Type /Annot /Subtype /3D /Rect [10 20 110 120] \
                 /3DD 6 0 R >>";
    // Stand-in for a §13.6.3 3D stream — the reader doesn't decode
    // the payload; it only preserves the ObjectId so the caller can
    // re-resolve through their own pipeline.
    let stream_stub = "<< /Type /3D /Subtype /U3D /Length 0 >>\nstream\n\nendstream";
    let pdf = synth_pdf_with_objects(&[annot, stream_stub], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::ThreeD {
            artwork,
            view,
            activation,
            interactive,
            view_box,
        } => {
            assert_eq!(artwork.map(|id| id.number), Some(6));
            assert!(view.is_none(), "no /3DV ⇒ None");
            // No /3DA ⇒ all-None activation (per Table 298 the spec
            // defaults are applied at render time).
            assert_eq!(activation, &ThreeDActivation::default());
            // Table 298 /3DI default is `true`.
            assert!(*interactive);
            assert!(view_box.is_none());
        }
        other => panic!("expected ThreeD, got {:?}", other),
    }
    assert_eq!(annots[0].rect, [10.0, 20.0, 110.0, 120.0]);
}

// ────────────────────────────────────────────────────────────────────
// §13.6.2 Table 298 — /3DV selector: all four spec shapes
// ────────────────────────────────────────────────────────────────────

#[test]
fn three_d_view_selector_indirect_view_ref() {
    let annot = "<< /Type /Annot /Subtype /3D /Rect [0 0 100 100] \
                 /3DD 7 0 R /3DV 6 0 R >>";
    let view_stub = "<< /Type /3DView /XN (default) >>";
    let stream_stub = "<< /Type /3D /Subtype /U3D /Length 0 >>\nstream\n\nendstream";
    let pdf = synth_pdf_with_objects(&[annot, view_stub, stream_stub], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::ThreeD { view, .. } => match view {
            Some(ThreeDViewSelector::View(id)) => assert_eq!(id.number, 6),
            other => panic!("expected View, got {:?}", other),
        },
        other => panic!("expected ThreeD, got {:?}", other),
    }
}

#[test]
fn three_d_view_selector_integer_va_index() {
    let annot = "<< /Type /Annot /Subtype /3D /Rect [0 0 100 100] \
                 /3DD 6 0 R /3DV 2 >>";
    let stream_stub = "<< /Type /3D /Subtype /U3D /Length 0 >>\nstream\n\nendstream";
    let pdf = synth_pdf_with_objects(&[annot, stream_stub], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::ThreeD { view, .. } => match view {
            Some(ThreeDViewSelector::Index(n)) => assert_eq!(*n, 2),
            other => panic!("expected Index, got {:?}", other),
        },
        other => panic!("expected ThreeD, got {:?}", other),
    }
}

#[test]
fn three_d_view_selector_text_string_matches_in() {
    // Text string selecting a /VA entry by its /IN match key.
    let annot = "<< /Type /Annot /Subtype /3D /Rect [0 0 100 100] \
                 /3DD 6 0 R /3DV (Top View) >>";
    let stream_stub = "<< /Type /3D /Subtype /U3D /Length 0 >>\nstream\n\nendstream";
    let pdf = synth_pdf_with_objects(&[annot, stream_stub], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::ThreeD { view, .. } => match view {
            Some(ThreeDViewSelector::Name(s)) => assert_eq!(s, "Top View"),
            other => panic!("expected Name, got {:?}", other),
        },
        other => panic!("expected ThreeD, got {:?}", other),
    }
}

#[test]
fn three_d_view_selector_symbolic_f_l_d() {
    // /F = first /VA entry.
    let annot = "<< /Type /Annot /Subtype /3D /Rect [0 0 100 100] \
                 /3DD 6 0 R /3DV /F >>";
    let stream_stub = "<< /Type /3D /Subtype /U3D /Length 0 >>\nstream\n\nendstream";
    let pdf = synth_pdf_with_objects(&[annot, stream_stub], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::ThreeD { view, .. } => match view {
            Some(ThreeDViewSelector::Symbolic(s)) => assert_eq!(s, "F"),
            other => panic!("expected Symbolic, got {:?}", other),
        },
        other => panic!("expected ThreeD, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// §13.6.2 Table 299 — /3DA activation dict, full field set
// ────────────────────────────────────────────────────────────────────

#[test]
fn three_d_full_activation_dict_inline() {
    // Inline /3DA with every Table-299 field populated.
    let annot = "<< /Type /Annot /Subtype /3D /Rect [0 0 100 100] \
                 /3DD 6 0 R \
                 /3DA << /A /PO /AIS /I /D /XD /DIS /L /TB false /NP true >> \
                 /3DI false /3DB [-50 -50 50 50] >>";
    let stream_stub = "<< /Type /3D /Subtype /U3D /Length 0 >>\nstream\n\nendstream";
    let pdf = synth_pdf_with_objects(&[annot, stream_stub], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::ThreeD {
            activation,
            interactive,
            view_box,
            ..
        } => {
            assert_eq!(activation.activation_when.as_deref(), Some("PO"));
            assert_eq!(activation.artwork_state_on_activation.as_deref(), Some("I"));
            assert_eq!(activation.deactivation_when.as_deref(), Some("XD"));
            assert_eq!(
                activation.artwork_state_on_deactivation.as_deref(),
                Some("L")
            );
            assert_eq!(activation.toolbar, Some(false));
            assert_eq!(activation.navigation_panel, Some(true));
            assert!(!*interactive);
            assert_eq!(*view_box, Some([-50.0, -50.0, 50.0, 50.0]));
        }
        other => panic!("expected ThreeD, got {:?}", other),
    }
}

#[test]
fn three_d_activation_via_indirect_reference() {
    // /3DA carried as an indirect reference is decoded after a deref.
    let annot = "<< /Type /Annot /Subtype /3D /Rect [0 0 100 100] \
                 /3DD 6 0 R /3DA 7 0 R >>";
    let stream_stub = "<< /Type /3D /Subtype /U3D /Length 0 >>\nstream\n\nendstream";
    let activation_dict = "<< /A /PV /D /PC >>";
    let pdf = synth_pdf_with_objects(&[annot, stream_stub, activation_dict], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::ThreeD { activation, .. } => {
            assert_eq!(activation.activation_when.as_deref(), Some("PV"));
            assert_eq!(activation.deactivation_when.as_deref(), Some("PC"));
            assert!(activation.artwork_state_on_activation.is_none());
            assert!(activation.toolbar.is_none());
        }
        other => panic!("expected ThreeD, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// Round-trip the round-204/209/215 tolerance contract
// ────────────────────────────────────────────────────────────────────

#[test]
fn three_d_without_3dd_still_surfaces() {
    // No /3DD — spec says it's required, but the round-26 reader
    // contract is "best-effort enumeration"; the annotation must
    // still appear as ThreeD with `artwork: None`.
    let annot = "<< /Type /Annot /Subtype /3D /Rect [0 0 100 100] >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::ThreeD {
            artwork,
            interactive,
            ..
        } => {
            assert!(artwork.is_none());
            // /3DI still defaults to true even without /3DD.
            assert!(*interactive);
        }
        other => panic!("expected ThreeD, got {:?}", other),
    }
}

#[test]
fn three_d_view_box_with_non_numeric_entry_drops_to_none() {
    // /3DB carrying a non-numeric element drops to None rather than
    // surfacing garbage — matches the round-204 /FixedPrint Matrix
    // tolerance pattern.
    let annot = "<< /Type /Annot /Subtype /3D /Rect [0 0 100 100] \
                 /3DD 6 0 R /3DB [-50 -50 50 /Bogus] >>";
    let stream_stub = "<< /Type /3D /Subtype /U3D /Length 0 >>\nstream\n\nendstream";
    let pdf = synth_pdf_with_objects(&[annot, stream_stub], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::ThreeD { view_box, .. } => {
            assert!(view_box.is_none());
        }
        other => panic!("expected ThreeD, got {:?}", other),
    }
}

#[test]
fn three_d_unknown_activation_name_preserved_verbatim() {
    // Producer emits an unknown Name in /A — the reader keeps it
    // verbatim rather than dropping the field, so a forensic walk
    // still sees what the file actually said.
    let annot = "<< /Type /Annot /Subtype /3D /Rect [0 0 100 100] \
                 /3DD 6 0 R /3DA << /A /CustomTrigger >> >>";
    let stream_stub = "<< /Type /3D /Subtype /U3D /Length 0 >>\nstream\n\nendstream";
    let pdf = synth_pdf_with_objects(&[annot, stream_stub], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::ThreeD { activation, .. } => {
            assert_eq!(activation.activation_when.as_deref(), Some("CustomTrigger"));
        }
        other => panic!("expected ThreeD, got {:?}", other),
    }
}
