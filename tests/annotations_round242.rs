//! Round-242 — `/Subtype /RichMedia` decoder in the round-26
//! annotation reader (ISO 32000-2 §13.7.2 Table 333).
//!
//! Before this round, the PDF 2.0 rich-media annotation fell through
//! to [`AnnotationKind::Other { subtype: "RichMedia" }`], so any
//! rich-media-aware forensic walk had to special-case the
//! stringly-typed name and re-resolve the `/RichMediaContent` /
//! `/RichMediaSettings` entries themselves.
//!
//! Coverage validated end-to-end against hand-synthesised PDFs:
//!
//! * §13.7.2 Table 333 — `/RichMediaContent` (Required, references a
//!   Table 341 dictionary), `/RichMediaSettings` (Optional,
//!   references a Table 334 dictionary).
//! * Tolerance: a malformed annot missing the spec-required
//!   `/RichMediaContent` still surfaces with `content: None` rather
//!   than dropping the annotation — matches the round-220 `/3D`
//!   tolerance contract.

use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{read_pdf_annotations, AnnotationKind};

fn read_annots(pdf: &[u8]) -> Vec<oxideav_pdf::PdfAnnotation> {
    let mut r = DocumentReader::open(pdf).unwrap();
    read_pdf_annotations(&mut r).unwrap()
}

/// Minimal one-page PDF with the supplied per-page annotation dicts
/// spliced into the page's `/Annots` array. Object numbering follows
/// the round-220 / round-215 / round-209 shape.
///
/// Objects 5..N are emitted verbatim from `extra_obj_bodies` so each
/// test can attach a Table-341 RichMediaContent stub, a Table-334
/// RichMediaSettings stub, etc.
fn synth_pdf_with_objects(extra_obj_bodies: &[&str], annot_refs: &[u32]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"%PDF-2.0\n%");
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
// §13.7.2 Table 333 — minimal annot: required /RichMediaContent only
// ────────────────────────────────────────────────────────────────────

#[test]
fn richmedia_minimal_content_only() {
    // Object 5 = the RichMedia annotation; object 6 = the Table-341
    // RichMediaContent stub. The reader doesn't decode the content
    // dict — it preserves the ObjectId so the caller can re-resolve
    // through their own walker.
    let annot = "<< /Type /Annot /Subtype /RichMedia /Rect [10 20 110 120] \
                 /RichMediaContent 6 0 R >>";
    let content_stub = "<< /Type /RichMediaContent /Assets << >> >>";
    let pdf = synth_pdf_with_objects(&[annot, content_stub], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::RichMedia { content, settings } => {
            assert_eq!(content.map(|id| id.number), Some(6));
            assert!(
                settings.is_none(),
                "no /RichMediaSettings ⇒ None (Table 333 Optional)"
            );
        }
        other => panic!("expected RichMedia, got {:?}", other),
    }
    assert_eq!(annots[0].rect, [10.0, 20.0, 110.0, 120.0]);
}

// ────────────────────────────────────────────────────────────────────
// §13.7.2 Table 333 — both content + settings populated
// ────────────────────────────────────────────────────────────────────

#[test]
fn richmedia_with_content_and_settings() {
    let annot = "<< /Type /Annot /Subtype /RichMedia /Rect [0 0 100 100] \
                 /RichMediaContent 6 0 R /RichMediaSettings 7 0 R >>";
    let content_stub = "<< /Type /RichMediaContent /Assets << >> /Configurations [] >>";
    let settings_stub = "<< /Type /RichMediaSettings /Activation << /Condition /XA >> >>";
    let pdf = synth_pdf_with_objects(&[annot, content_stub, settings_stub], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::RichMedia { content, settings } => {
            assert_eq!(content.map(|id| id.number), Some(6));
            assert_eq!(settings.map(|id| id.number), Some(7));
        }
        other => panic!("expected RichMedia, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// Tolerance: missing required /RichMediaContent still enumerates
// ────────────────────────────────────────────────────────────────────

#[test]
fn richmedia_without_content_still_surfaces() {
    // Table 333 marks /RichMediaContent as Required; the round-26
    // reader contract is "best-effort enumeration", so the annotation
    // still appears as RichMedia with `content: None` rather than
    // being dropped or downgraded to AnnotationKind::Other. Matches
    // the round-220 /3D and round-209 Sound tolerance.
    let annot = "<< /Type /Annot /Subtype /RichMedia /Rect [0 0 100 100] >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::RichMedia { content, settings } => {
            assert!(content.is_none());
            assert!(settings.is_none());
        }
        other => panic!("expected RichMedia, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// Tolerance: inlined-dict shape preserved as None (we only surface
// indirect refs — callers requiring full inline decoding can pull
// the dict themselves via DocumentReader)
// ────────────────────────────────────────────────────────────────────

#[test]
fn richmedia_inline_content_dict_surfaces_as_none() {
    // Some producers emit /RichMediaContent as an inline dict rather
    // than an indirect ref. The reader signals "non-ref shape" with
    // None — callers re-walking the raw dict can still decode it,
    // but the annotation enumerator stays type-correct.
    let annot = "<< /Type /Annot /Subtype /RichMedia /Rect [0 0 100 100] \
                 /RichMediaContent << /Type /RichMediaContent >> >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::RichMedia { content, settings } => {
            assert!(
                content.is_none(),
                "inline /RichMediaContent dict ⇒ None (we surface refs only)"
            );
            assert!(settings.is_none());
        }
        other => panic!("expected RichMedia, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// Multi-annotation enumeration: RichMedia alongside other §12.5.6
// subtypes round-trips without affecting the rest of the page.
// ────────────────────────────────────────────────────────────────────

#[test]
fn richmedia_does_not_break_sibling_annots() {
    // A Text annot and a RichMedia annot sharing one page — round 242
    // must surface both without re-routing the Text annot through the
    // Other catch-all.
    let text_annot = "<< /Type /Annot /Subtype /Text /Rect [0 0 50 50] \
                      /Contents (note) /Name /Comment >>";
    let rm_annot = "<< /Type /Annot /Subtype /RichMedia /Rect [100 0 200 100] \
                    /RichMediaContent 7 0 R >>";
    let content_stub = "<< /Type /RichMediaContent >>";
    let pdf = synth_pdf_with_objects(&[text_annot, rm_annot, content_stub], &[5, 6]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 2);
    assert!(matches!(annots[0].kind, AnnotationKind::Text { .. }));
    match &annots[1].kind {
        AnnotationKind::RichMedia { content, .. } => {
            assert_eq!(content.map(|id| id.number), Some(7));
        }
        other => panic!("expected RichMedia, got {:?}", other),
    }
}
