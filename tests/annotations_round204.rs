//! Round-204 — two new §12.5.6 annotation subtypes in the round-26
//! reader: **Watermark** (§12.5.6.22 Table 190 + Table 191 FixedPrint)
//! and **Redact** (§12.5.6.23 Table 192).
//!
//! Both are structurally clean (no cross-crate AV plumbing needed).
//! The round-204 reader is non-destructive — it surfaces the redact
//! metadata so a privacy-audit tool can enumerate what *would* be
//! removed by a compliant redactor without actually performing the
//! removal (the destructive content-removal step described by
//! §12.5.6.23 NOTE is a separate higher-level pass).
//!
//! Coverage of the spec tables:
//!
//! * §12.5.6.22 Table 190 (Watermark) — `/FixedPrint` indirect ref.
//! * §12.5.6.22 Table 191 (FixedPrint) — `/Type`, `/Matrix`, `/H`, `/V`.
//! * §12.5.6.23 Table 192 (Redact) — `/QuadPoints`, `/IC`, `/RO`,
//!   `/OverlayText`, `/Repeat`, `/DA`, `/Q`.
//!
//! Round-trip is validated against minimal hand-synthesised PDFs (the
//! same shape as `tests/annotations_round197.rs`).

use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{read_pdf_annotations, AnnotationKind, FixedPrint};

/// Minimal one-page PDF with the supplied per-page annotation dicts
/// spliced into the page's `/Annots` array. Object numbering:
///   1 Catalog
///   2 Pages
///   3 Page
///   4 Empty content stream
///   5..N annotation dicts (or supporting filespecs / fixed-print
///   dicts / Form XObjects)
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
// §12.5.6.22 Watermark annotation (Table 190).
// ────────────────────────────────────────────────────────────────────

#[test]
fn watermark_annotation_without_fixed_print() {
    // Table 190's `/FixedPrint` entry is optional; a Watermark with
    // only the required `/Subtype /Watermark` surfaces fixed_print =
    // None per the spec's "drawn without any special consideration
    // for the dimensions of the target media" rule.
    let pdf = synth_pdf_with_objects(
        &["<< /Type /Annot /Subtype /Watermark /Rect [10 10 110 60] >>"],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Watermark { fixed_print } => {
            assert!(fixed_print.is_none(), "absent /FixedPrint ⇒ None");
        }
        other => panic!("expected Watermark, got {:?}", other),
    }
}

#[test]
fn watermark_annotation_with_indirect_fixed_print_full() {
    // Spec example from §12.5.6.22: `/Matrix [1 0 0 1 72 -72]` for a
    // one-inch right + one-inch down offset, plus `/V 1.0` to translate
    // the watermark a full height upward.
    let pdf = synth_pdf_with_objects(
        &[
            // 5: Watermark annotation pointing at 6
            "<< /Type /Annot /Subtype /Watermark /Rect [0 0 100 50] \
             /FixedPrint 6 0 R >>",
            // 6: FixedPrint dict
            "<< /Type /FixedPrint /Matrix [1 0 0 1 72 -72] /H 0 /V 1.0 >>",
        ],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Watermark { fixed_print } => {
            let fp = fixed_print.as_ref().expect("present /FixedPrint");
            assert_eq!(fp.matrix, [1.0, 0.0, 0.0, 1.0, 72.0, -72.0]);
            assert_eq!(fp.h, 0.0);
            assert_eq!(fp.v, 1.0);
        }
        other => panic!("expected Watermark, got {:?}", other),
    }
}

#[test]
fn watermark_fixed_print_defaults_apply_when_entries_absent() {
    // Per Table 191 each entry defaults — /Matrix → identity, /H → 0,
    // /V → 0. An empty FixedPrint sub-dict (just the /Type) should
    // surface the all-default value.
    let pdf = synth_pdf_with_objects(
        &[
            "<< /Type /Annot /Subtype /Watermark /Rect [0 0 100 50] \
             /FixedPrint 6 0 R >>",
            "<< /Type /FixedPrint >>",
        ],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::Watermark { fixed_print } => {
            let fp = fixed_print.as_ref().unwrap();
            assert_eq!(fp, &FixedPrint::default());
            // And explicitly: identity matrix + zero translation.
            assert_eq!(fp.matrix, [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);
            assert_eq!(fp.h, 0.0);
            assert_eq!(fp.v, 0.0);
        }
        other => panic!("expected Watermark, got {:?}", other),
    }
}

#[test]
fn watermark_fixed_print_partial_entries_keep_defaults() {
    // `/H` alone — `/Matrix` defaults to identity, `/V` defaults to 0.
    let pdf = synth_pdf_with_objects(
        &[
            "<< /Type /Annot /Subtype /Watermark /Rect [0 0 100 50] \
             /FixedPrint 6 0 R >>",
            "<< /Type /FixedPrint /H 0.5 >>",
        ],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::Watermark { fixed_print } => {
            let fp = fixed_print.as_ref().unwrap();
            assert_eq!(fp.matrix, [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);
            assert_eq!(fp.h, 0.5);
            assert_eq!(fp.v, 0.0);
        }
        other => panic!("expected Watermark, got {:?}", other),
    }
}

#[test]
fn watermark_inline_fixed_print_dict_is_decoded() {
    // /FixedPrint may also be a direct sub-dictionary, not just an
    // indirect reference (the spec text reads "shall be a dictionary"
    // without mandating indirection).
    let pdf = synth_pdf_with_objects(
        &["<< /Type /Annot /Subtype /Watermark /Rect [0 0 50 50] \
           /FixedPrint << /Type /FixedPrint /H 0.25 /V 0.75 >> >>"],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::Watermark { fixed_print } => {
            let fp = fixed_print.as_ref().unwrap();
            assert_eq!(fp.h, 0.25);
            assert_eq!(fp.v, 0.75);
        }
        other => panic!("expected Watermark, got {:?}", other),
    }
}

#[test]
fn watermark_fixed_print_malformed_matrix_falls_back_to_identity() {
    // A 5-element /Matrix is malformed per Table 191 (which spells out
    // a six-number affine). Round-204 surfaces the rest of the dict
    // with the matrix reverting to identity rather than refusing the
    // whole watermark.
    let pdf = synth_pdf_with_objects(
        &[
            "<< /Type /Annot /Subtype /Watermark /Rect [0 0 50 50] \
             /FixedPrint 6 0 R >>",
            "<< /Type /FixedPrint /Matrix [1 0 0 1 72] /H 0.1 >>",
        ],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::Watermark { fixed_print } => {
            let fp = fixed_print.as_ref().unwrap();
            assert_eq!(fp.matrix, [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);
            assert_eq!(fp.h, 0.1);
        }
        other => panic!("expected Watermark, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.23 Redact annotation (Table 192).
// ────────────────────────────────────────────────────────────────────

#[test]
fn redact_annotation_with_quadpoints_and_overlay_text() {
    // Quad covers one rectangle (8 reals — top-left, top-right,
    // bottom-left, bottom-right per the §12.5.6.10 convention Table 192
    // re-uses) plus DeviceRGB interior + overlay text.
    let pdf = synth_pdf_with_objects(
        &["<< /Type /Annot /Subtype /Redact /Rect [10 20 110 60] \
           /QuadPoints [10 60 110 60 10 20 110 20] \
           /IC [1.0 0.0 0.0] \
           /OverlayText (REDACTED) \
           /Repeat true \
           /DA (/Helv 12 Tf 0 g) \
           /Q 1 >>"],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Redact {
            quad_points,
            interior_colour,
            overlay_form,
            overlay_text,
            repeat,
            default_appearance,
            quadding,
        } => {
            assert_eq!(
                quad_points.as_deref(),
                Some(&[10.0, 60.0, 110.0, 60.0, 10.0, 20.0, 110.0, 20.0][..])
            );
            assert_eq!(*interior_colour, Some([1.0, 0.0, 0.0]));
            assert!(overlay_form.is_none(), "absent /RO ⇒ None");
            assert_eq!(overlay_text.as_deref(), Some("REDACTED"));
            assert!(*repeat);
            assert_eq!(default_appearance.as_deref(), Some("/Helv 12 Tf 0 g"));
            assert_eq!(*quadding, 1);
        }
        other => panic!("expected Redact, got {:?}", other),
    }
}

#[test]
fn redact_annotation_falls_back_to_rect_when_quadpoints_absent() {
    // Per Table 192: "If [QuadPoints] is not present, the Rect entry
    // denotes the content region that is intended to be removed."
    // Round-204 surfaces quad_points = None to signal "use Rect".
    let pdf = synth_pdf_with_objects(
        &["<< /Type /Annot /Subtype /Redact /Rect [0 0 100 100] >>"],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Redact {
            quad_points,
            interior_colour,
            overlay_form,
            overlay_text,
            repeat,
            default_appearance,
            quadding,
        } => {
            assert!(quad_points.is_none(), "absent ⇒ caller falls back to Rect");
            assert!(interior_colour.is_none());
            assert!(overlay_form.is_none());
            assert!(overlay_text.is_none());
            assert!(!*repeat, "default per Table 192");
            assert!(default_appearance.is_none());
            assert_eq!(*quadding, 0, "default per Table 192");
        }
        other => panic!("expected Redact, got {:?}", other),
    }
}

#[test]
fn redact_annotation_carries_ro_reference_to_form_xobject() {
    // `/RO` is an indirect reference to a Form XObject (§8.10) that
    // takes precedence over /IC + /OverlayText per Table 192. Round-204
    // preserves the ObjectId so callers can re-resolve the appearance;
    // payload decoding stays out of the annotation reader's scope.
    let pdf = synth_pdf_with_objects(
        &[
            // 5: Redact pointing at 6
            "<< /Type /Annot /Subtype /Redact /Rect [0 0 100 100] \
             /RO 6 0 R \
             /IC [0.5 0.5 0.5] \
             /OverlayText (ignored by spec when RO is present) >>",
            // 6: Form XObject stub
            "<< /Type /XObject /Subtype /Form /BBox [0 0 100 100] \
             /Length 0 >>\nstream\n\nendstream",
        ],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::Redact {
            overlay_form,
            interior_colour,
            overlay_text,
            ..
        } => {
            let oid = overlay_form.expect("/RO present");
            assert_eq!(oid.number, 6);
            // /IC + /OverlayText still surface verbatim — the spec's
            // "ignored if RO is present" rule is a *rendering*
            // contract, not a parsing one. Callers know to skip them
            // when overlay_form.is_some().
            assert_eq!(interior_colour.as_ref().unwrap()[0], 0.5);
            assert!(overlay_text.is_some());
        }
        other => panic!("expected Redact, got {:?}", other),
    }
}

#[test]
fn redact_interior_colour_rejects_non_devicergb_shapes() {
    // Table 192 constrains /IC to three DeviceRGB components ("an
    // array of three numbers in the range 0.0 to 1.0 specifying the
    // components, in the DeviceRGB colour space"). A 4-component CMYK
    // or 1-component Gray shape gets dropped to None rather than
    // silently mis-typed.
    let pdf = synth_pdf_with_objects(
        &["<< /Type /Annot /Subtype /Redact /Rect [0 0 50 50] \
           /IC [0.1 0.2 0.3 0.4] >>"],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::Redact {
            interior_colour, ..
        } => {
            assert!(
                interior_colour.is_none(),
                "4-component /IC violates DeviceRGB-only rule"
            );
        }
        other => panic!("expected Redact, got {:?}", other),
    }
}

#[test]
fn redact_multi_quad_region_is_preserved_in_order() {
    // 16 reals = 2 quadrilaterals (8N where N=2). The flat array is
    // surfaced exactly as the spec defines so a downstream consumer
    // can re-pair the coordinates.
    let pdf = synth_pdf_with_objects(
        &["<< /Type /Annot /Subtype /Redact /Rect [0 0 200 100] \
           /QuadPoints [0 100 100 100 0 0 100 0 \
                        100 100 200 100 100 0 200 0] >>"],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::Redact { quad_points, .. } => {
            let qp = quad_points.as_deref().unwrap();
            assert_eq!(qp.len(), 16);
            assert_eq!(
                qp,
                &[
                    0.0, 100.0, 100.0, 100.0, 0.0, 0.0, 100.0, 0.0, 100.0, 100.0, 200.0, 100.0,
                    100.0, 0.0, 200.0, 0.0,
                ][..]
            );
        }
        other => panic!("expected Redact, got {:?}", other),
    }
}

#[test]
fn redact_quadding_out_of_range_clamps_per_table_192() {
    // /Q legal values per Table 192 are 0..=2. Out-of-range integer is
    // clamped to the nearest valid value (same shape as the FreeText
    // /Q decoder in round 26).
    let pdf = synth_pdf_with_objects(
        &["<< /Type /Annot /Subtype /Redact /Rect [0 0 50 50] \
           /OverlayText (X) /DA (/F 12 Tf) /Q 9 >>"],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::Redact { quadding, .. } => {
            assert_eq!(
                *quadding, 2,
                "9 clamps to the table's max (right-justified)"
            );
        }
        other => panic!("expected Redact, got {:?}", other),
    }
}

#[test]
fn redact_repeat_defaults_to_false_when_omitted() {
    // Table 192: "Default value: false."
    let pdf = synth_pdf_with_objects(
        &["<< /Type /Annot /Subtype /Redact /Rect [0 0 50 50] \
           /OverlayText (R) /DA (/F 8 Tf) >>"],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::Redact { repeat, .. } => {
            assert!(!*repeat);
        }
        other => panic!("expected Redact, got {:?}", other),
    }
}

#[test]
fn redact_default_appearance_decodes_utf16be_overlay_text() {
    // /OverlayText is a "text string" per Table 192, which means
    // §7.9.2.2 applies: UTF-16BE-with-BOM (FEFF) hex strings decode to
    // Unicode. "中文" = U+4E2D U+6587.
    let pdf = synth_pdf_with_objects(
        &["<< /Type /Annot /Subtype /Redact /Rect [0 0 50 50] \
           /OverlayText <FEFF4E2D6587> /DA (/F 12 Tf) >>"],
        &[5],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::Redact { overlay_text, .. } => {
            assert_eq!(overlay_text.as_deref(), Some("中文"));
        }
        other => panic!("expected Redact, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// Cross-subtype: the round-26 enumeration sees both new subtypes
// alongside the existing round-197 long-tail subtypes.
// ────────────────────────────────────────────────────────────────────

#[test]
fn watermark_and_redact_alongside_round197_subtypes() {
    // A single page mixing Watermark + Redact + Line (round-197) +
    // Text (round-26) makes sure the new variants don't perturb the
    // existing decoder's match arms.
    let pdf = synth_pdf_with_objects(
        &[
            // 5: Watermark
            "<< /Type /Annot /Subtype /Watermark /Rect [0 0 100 50] \
             /FixedPrint 9 0 R >>",
            // 6: Redact
            "<< /Type /Annot /Subtype /Redact /Rect [10 10 90 90] \
             /OverlayText (X) /DA (/F 12 Tf) >>",
            // 7: Line (round-197 sanity check)
            "<< /Type /Annot /Subtype /Line /Rect [0 0 100 100] \
             /L [0 0 100 100] >>",
            // 8: Text (round-26 sanity check)
            "<< /Type /Annot /Subtype /Text /Rect [0 0 20 20] \
             /Contents (Hello) >>",
            // 9: FixedPrint dict (5 references it)
            "<< /Type /FixedPrint /H 0.5 >>",
        ],
        &[5, 6, 7, 8],
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 4);
    assert!(matches!(anns[0].kind, AnnotationKind::Watermark { .. }));
    assert!(matches!(anns[1].kind, AnnotationKind::Redact { .. }));
    assert!(matches!(anns[2].kind, AnnotationKind::Line { .. }));
    assert!(matches!(anns[3].kind, AnnotationKind::Text { .. }));
}
