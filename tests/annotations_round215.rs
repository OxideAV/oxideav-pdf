//! Round-215 — two more §12.5.6 annotation subtypes in the round-26
//! reader: **PrinterMark** (§12.5.6.20 Table 362) and **TrapNet**
//! (§12.5.6.21 Table 366).
//!
//! Both were previously falling through to `AnnotationKind::Other`.
//! Neither has any cross-crate plumbing dependency: the appearance
//! stream that does the actual rendering for both subtypes is a Form
//! XObject already reachable through the §8.10 Form-XObject walker,
//! so the round-215 surface is the *annotation-dict-local* metadata
//! that distinguishes a PrinterMark from a vanilla appearance-only
//! annotation, and the trap-network bookkeeping fields a regenerator
//! needs to decide whether the cached traps are still valid.
//!
//! Coverage of the spec tables:
//!
//! * §12.5.6.20 Table 362 (PrinterMark) — `/MN` mark name.
//! * §12.5.6.21 Table 366 (TrapNet) — `/LastModified`, `/Version`,
//!   `/AnnotStates`, `/FontFauxing`.
//!
//! Round-trip is validated against minimal hand-synthesised PDFs (the
//! same shape as `tests/annotations_round197.rs` /
//! `tests/annotations_round204.rs` / `tests/annotations_round209.rs`).

use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{read_pdf_annotations, AnnotationKind};

/// Helper — open the synthesised PDF and walk its annotations.
fn read_annots(pdf: &[u8]) -> Vec<oxideav_pdf::PdfAnnotation> {
    let mut r = DocumentReader::open(pdf).unwrap();
    read_pdf_annotations(&mut r).unwrap()
}

/// Minimal one-page PDF with the supplied per-page annotation dicts
/// spliced into the page's `/Annots` array. Object numbering:
///   1 Catalog
///   2 Pages
///   3 Page
///   4 Empty content stream
///   5..N annotation dicts (or supporting objects: form XObjects,
///   font dicts referenced by /FontFauxing, …)
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
// §12.5.6.20 PrinterMark annotation (Table 362).
// ────────────────────────────────────────────────────────────────────

#[test]
fn printer_mark_with_explicit_mn_name() {
    // The canonical use case: a colour bar.
    let annot = "<< /Type /Annot /Subtype /PrinterMark /Rect [0 0 50 10] \
                 /F 132 /MN /ColorBar >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::PrinterMark { mark_name } => {
            assert_eq!(mark_name.as_deref(), Some("ColorBar"));
        }
        other => panic!("expected PrinterMark, got {:?}", other),
    }
    // Common Table 164 fields still decode the same way the long
    // tail does — /F 132 = Print(2) + Locked(7) + ReadOnly(6).
    assert_eq!(annots[0].flags, 132);
}

#[test]
fn printer_mark_with_registration_target_name() {
    let annot = "<< /Type /Annot /Subtype /PrinterMark /Rect [0 0 30 30] \
                 /MN /RegistrationTarget >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::PrinterMark { mark_name } => {
            assert_eq!(mark_name.as_deref(), Some("RegistrationTarget"));
        }
        other => panic!("expected PrinterMark, got {:?}", other),
    }
}

#[test]
fn printer_mark_with_missing_mn_surfaces_none() {
    // Table 362 makes /MN optional — a producer that only emits the
    // appearance stream still enumerates as PrinterMark, just with
    // mark_name = None.
    let annot = "<< /Type /Annot /Subtype /PrinterMark /Rect [0 0 10 10] >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::PrinterMark { mark_name } => assert!(mark_name.is_none()),
        other => panic!("expected PrinterMark, got {:?}", other),
    }
}

#[test]
fn printer_mark_with_non_name_mn_ignores_entry() {
    // A literal-string /MN (not a Name) — malformed per Table 362 but
    // tolerant reader surfaces the annot with mark_name=None rather
    // than dropping it. Forensic enumeration > strict spec parsing.
    let annot = "<< /Type /Annot /Subtype /PrinterMark /Rect [0 0 10 10] \
                 /MN (CustomCutMark) >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::PrinterMark { mark_name } => assert!(mark_name.is_none()),
        other => panic!("expected PrinterMark, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.21 TrapNet annotation (Table 366).
// ────────────────────────────────────────────────────────────────────

#[test]
fn trapnet_with_last_modified_form() {
    // The simpler of the two mutually-exclusive shapes — a single
    // /LastModified date.
    let annot = "<< /Type /Annot /Subtype /TrapNet /Rect [0 0 200 200] \
                 /F 132 /LastModified (D:20260603120000Z) >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::TrapNet {
            last_modified,
            version,
            annot_states,
            font_fauxing,
        } => {
            assert_eq!(last_modified.as_deref(), Some("D:20260603120000Z"));
            assert!(version.is_none());
            assert!(annot_states.is_none());
            assert!(font_fauxing.is_none());
        }
        other => panic!("expected TrapNet, got {:?}", other),
    }
}

#[test]
fn trapnet_with_version_and_annotstates_form() {
    // The richer shape — /Version array of refs to invalidation-
    // sensitive objects, plus /AnnotStates capturing the page's
    // appearance state at the moment the trap network was generated.
    // We also exercise /FontFauxing to cover all four optional fields
    // in one shot.
    let annot = "<< /Type /Annot /Subtype /TrapNet /Rect [0 0 200 200] \
                 /Version [6 0 R 7 0 R] \
                 /AnnotStates [/Down /Up null] \
                 /FontFauxing [8 0 R] >>";
    // Supporting objects — only need to exist so the references are
    // valid; their bodies are placeholders.
    let resource = "<< >>";
    let resource2 = "<< >>";
    let font = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
    let pdf = synth_pdf_with_objects(&[annot, resource, resource2, font], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::TrapNet {
            last_modified,
            version,
            annot_states,
            font_fauxing,
        } => {
            assert!(last_modified.is_none());
            let v = version.as_ref().expect("/Version present");
            assert_eq!(v.len(), 2);
            assert_eq!(v[0].number, 6);
            assert_eq!(v[1].number, 7);
            let s = annot_states.as_ref().expect("/AnnotStates present");
            assert_eq!(s.len(), 3);
            assert_eq!(s[0].as_deref(), Some("Down"));
            assert_eq!(s[1].as_deref(), Some("Up"));
            // The spec allows null entries for annotations with no /AS.
            assert!(s[2].is_none());
            let f = font_fauxing.as_ref().expect("/FontFauxing present");
            assert_eq!(f.len(), 1);
            assert_eq!(f[0].number, 8);
        }
        other => panic!("expected TrapNet, got {:?}", other),
    }
}

#[test]
fn trapnet_with_only_subtype_enumerates_with_all_none() {
    // A bare TrapNet with no Version / LastModified / AnnotStates /
    // FontFauxing — strictly malformed per Table 366 (either
    // LastModified or the Version+AnnotStates pair is required), but
    // the tolerant reader still surfaces the annot so a forensic
    // walker can flag the gap.
    let annot = "<< /Type /Annot /Subtype /TrapNet /Rect [0 0 200 200] >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::TrapNet {
            last_modified,
            version,
            annot_states,
            font_fauxing,
        } => {
            assert!(last_modified.is_none());
            assert!(version.is_none());
            assert!(annot_states.is_none());
            assert!(font_fauxing.is_none());
        }
        other => panic!("expected TrapNet, got {:?}", other),
    }
}

#[test]
fn trapnet_version_array_drops_non_reference_elements() {
    // Per Table 366 every /Version entry is "an unordered array of
    // all objects [identifying] elements of the page description";
    // the spec phrasing implies indirect references because the
    // referenced content lives outside the annot dict. A direct
    // integer / dict in the array is malformed — we drop it silently
    // rather than fail the whole decode.
    let annot = "<< /Type /Annot /Subtype /TrapNet /Rect [0 0 200 200] \
                 /Version [6 0 R 42 7 0 R (junk)] >>";
    let resource = "<< >>";
    let resource2 = "<< >>";
    let pdf = synth_pdf_with_objects(&[annot, resource, resource2], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::TrapNet { version, .. } => {
            let v = version.as_ref().unwrap();
            // Only the two well-formed references survive.
            assert_eq!(v.len(), 2);
            assert_eq!(v[0].number, 6);
            assert_eq!(v[1].number, 7);
        }
        other => panic!("expected TrapNet, got {:?}", other),
    }
}

#[test]
fn trapnet_empty_arrays_round_trip_as_some_empty() {
    // The reader distinguishes "absent" (None) from "explicitly
    // empty" (Some(vec![])) — a producer that emits /Version [] is
    // saying "no invalidation candidates", which is semantically
    // distinct from "I didn't track invalidation at all".
    let annot = "<< /Type /Annot /Subtype /TrapNet /Rect [0 0 200 200] \
                 /Version [] /AnnotStates [] /FontFauxing [] >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::TrapNet {
            version,
            annot_states,
            font_fauxing,
            ..
        } => {
            assert_eq!(version.as_ref().map(|v| v.len()), Some(0));
            assert_eq!(annot_states.as_ref().map(|v| v.len()), Some(0));
            assert_eq!(font_fauxing.as_ref().map(|v| v.len()), Some(0));
        }
        other => panic!("expected TrapNet, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// Cross-subtype: round-215's two new variants coexist with the long
// tail surfaced by round-197 / round-204 / round-209.
// ────────────────────────────────────────────────────────────────────

#[test]
fn round215_subtypes_enumerate_alongside_long_tail() {
    let printer_mark = "<< /Type /Annot /Subtype /PrinterMark /Rect [0 0 30 30] \
                        /MN /CutMark >>";
    let trap_net = "<< /Type /Annot /Subtype /TrapNet /Rect [0 0 200 200] \
                    /LastModified (D:20260101000000Z) >>";
    // /Projection still falls through to AnnotationKind::Other —
    // round-215 (along with round-220 lifting /3D and round-242
    // lifting /RichMedia out into their own structured variants)
    // keeps it on the long-tail Other side.
    let projection_a = "<< /Type /Annot /Subtype /Projection /Rect [0 0 10 10] >>";
    let projection_b = "<< /Type /Annot /Subtype /Projection /Rect [10 10 30 30] >>";
    let pdf = synth_pdf_with_objects(
        &[printer_mark, trap_net, projection_a, projection_b],
        &[5, 6, 7, 8],
    );
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 4);
    assert!(matches!(annots[0].kind, AnnotationKind::PrinterMark { .. }));
    assert!(matches!(annots[1].kind, AnnotationKind::TrapNet { .. }));
    match &annots[2].kind {
        AnnotationKind::Other { subtype } => assert_eq!(subtype, "Projection"),
        other => panic!("expected Other(\"Projection\"), got {:?}", other),
    }
    match &annots[3].kind {
        AnnotationKind::Other { subtype } => assert_eq!(subtype, "Projection"),
        other => panic!("expected Other(\"Projection\"), got {:?}", other),
    }
}
