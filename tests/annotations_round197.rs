//! Round-197 — six new §12.5.6 annotation subtypes in the round-26
//! reader (Line / Polygon / PolyLine / Ink / Caret / Popup /
//! FileAttachment).
//!
//! Coverage of the spec tables:
//!
//! * §12.5.6.7 Table 175 (Line) — `/L`, `/LE`, `/IC`, `/LL`, `/LLE`,
//!   `/LLO`, `/Cap`, `/IT`.
//! * §12.5.6.9 Table 178 (Polygon / PolyLine) — `/Vertices`, `/LE`,
//!   `/IC`, `/IT`.
//! * §12.5.6.13 Table 182 (Ink) — `/InkList`.
//! * §12.5.6.11 Table 180 (Caret) — `/RD`, `/Sy`.
//! * §12.5.6.14 Table 183 (Popup) — `/Parent`, `/Open`.
//! * §12.5.6.15 Table 184 (FileAttachment) — `/FS`, `/Name`. The
//!   `/UF`-preferred file-name resolution path mirrors the round-33
//!   attachment reader.
//!
//! Round-trip is validated against minimal hand-synthesised PDFs (the
//! same shape as `tests/annotations_round26.rs`) so the assertions
//! are exact on every byte the spec calls out.

use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{read_pdf_annotations, AnnotationKind};

/// Minimal one-page PDF with the supplied per-page annotation dicts
/// spliced into the page's `/Annots` array. Object numbering:
///   1 Catalog
///   2 Pages
///   3 Page
///   4 Empty content stream
///   5..N annotation dicts (or supporting filespecs)
fn synth_pdf_with_annotations(annot_bodies: &[&str]) -> Vec<u8> {
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
    let mut annot_refs = String::new();
    for i in 0..annot_bodies.len() {
        if !annot_refs.is_empty() {
            annot_refs.push(' ');
        }
        annot_refs.push_str(&format!("{} 0 R", 5 + i));
    }
    let page_dict = format!(
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
         /Contents 4 0 R /Resources << >> /Annots [{}] >>",
        annot_refs
    );
    push_obj(&mut body, &mut offsets, 3, &page_dict);
    push_obj(
        &mut body,
        &mut offsets,
        4,
        "<< /Length 0 >>\nstream\n\nendstream",
    );
    for (i, ab) in annot_bodies.iter().enumerate() {
        push_obj(&mut body, &mut offsets, 5 + i as u32, ab);
    }
    let xref_off = body.len();
    let n_objs = 5 + annot_bodies.len();
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
// §12.5.6.7 Line annotation (Table 175).
// ────────────────────────────────────────────────────────────────────

#[test]
fn line_annotation_minimal_required_fields() {
    // Required `/L` only — all PDF-1.4..1.6 optional fields absent.
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Line /Rect [10 20 110 60] \
         /L [10 20 110 60] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
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
            assert!(line_endings.is_none(), "default is /None /None per spec");
            assert!(interior_colour.is_none());
            assert!(leader_line.is_none());
            assert!(leader_line_extension.is_none());
            assert!(leader_line_offset.is_none());
            assert!(!*cap);
            assert!(intent.is_none());
        }
        other => panic!("expected Line, got {other:?}"),
    }
}

#[test]
fn line_annotation_full_with_leader_and_caption() {
    // PDF 1.7 LineArrow with leader geometry + caption flag.
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Line /Rect [0 0 200 50] \
         /L [10 25 190 25] /LE [/OpenArrow /ClosedArrow] \
         /IC [0.8 0.2 0.1] /LL 12 /LLE 4 /LLO 2 \
         /Cap true /IT /LineArrow \
         /Contents (caption text) >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    assert_eq!(anns[0].contents.as_deref(), Some("caption text"));
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
            assert_eq!(*l, [10.0, 25.0, 190.0, 25.0]);
            let le = line_endings.as_ref().expect("LE present");
            assert_eq!(le[0], "OpenArrow");
            assert_eq!(le[1], "ClosedArrow");
            let ic = interior_colour.as_ref().expect("IC present");
            assert_eq!(ic.len(), 3);
            assert!((ic[0] - 0.8).abs() < 1e-6);
            assert_eq!(*leader_line, Some(12.0));
            assert_eq!(*leader_line_extension, Some(4.0));
            assert_eq!(*leader_line_offset, Some(2.0));
            assert!(*cap);
            assert_eq!(intent.as_deref(), Some("LineArrow"));
        }
        other => panic!("expected Line, got {other:?}"),
    }
}

#[test]
fn line_annotation_missing_required_l_surfaces_zero_placeholder() {
    // Malformed Line dict — /L absent. The tolerant reader still
    // surfaces the annotation with a zero placeholder rather than
    // dropping it on the floor.
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Line /Rect [0 0 100 20] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Line { l, .. } => assert_eq!(*l, [0.0, 0.0, 0.0, 0.0]),
        other => panic!("expected Line, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.9 Polygon / PolyLine (Table 178).
// ────────────────────────────────────────────────────────────────────

#[test]
fn polygon_annotation_with_cloud_intent() {
    let pdf =
        synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Polygon /Rect [0 0 200 200] \
         /Vertices [20 20 180 20 180 180 20 180] \
         /IC [0.1 0.2 0.3] /IT /PolygonCloud >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
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
            assert_eq!(
                *vertices,
                vec![20.0_f32, 20.0, 180.0, 20.0, 180.0, 180.0, 20.0, 180.0]
            );
            // Spec: /LE meaningful only on PolyLine; here absent.
            assert!(line_endings.is_none());
            let ic = interior_colour.as_ref().expect("IC present");
            assert_eq!(ic.len(), 3);
            assert_eq!(intent.as_deref(), Some("PolygonCloud"));
        }
        other => panic!("expected PolygonOrPolyLine, got {other:?}"),
    }
}

#[test]
fn polyline_annotation_with_line_endings() {
    let pdf =
        synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /PolyLine /Rect [0 0 200 200] \
         /Vertices [10 10 50 50 90 30] \
         /LE [/None /OpenArrow] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::PolygonOrPolyLine {
            is_polygon,
            vertices,
            line_endings,
            ..
        } => {
            assert!(!*is_polygon);
            assert_eq!(*vertices, vec![10.0_f32, 10.0, 50.0, 50.0, 90.0, 30.0]);
            let le = line_endings.as_ref().expect("LE present");
            assert_eq!(le[0], "None");
            assert_eq!(le[1], "OpenArrow");
        }
        other => panic!("expected PolygonOrPolyLine, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.13 Ink (Table 182). Round-trip target for the round-32
// writer is exercised by tests/annotations_writer_round32.rs.
// ────────────────────────────────────────────────────────────────────

#[test]
fn ink_annotation_multi_stroke() {
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Ink /Rect [0 0 200 200] \
         /InkList [[10 10 30 50 60 40] [80 80 120 100]] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Ink { ink_list } => {
            assert_eq!(ink_list.len(), 2);
            assert_eq!(ink_list[0], vec![10.0_f32, 10.0, 30.0, 50.0, 60.0, 40.0]);
            assert_eq!(ink_list[1], vec![80.0_f32, 80.0, 120.0, 100.0]);
        }
        other => panic!("expected Ink, got {other:?}"),
    }
}

#[test]
fn ink_annotation_empty_list_surfaces_empty_vec() {
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Ink /Rect [0 0 200 200] \
         /InkList [] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Ink { ink_list } => assert!(ink_list.is_empty()),
        other => panic!("expected Ink, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.11 Caret (Table 180).
// ────────────────────────────────────────────────────────────────────

#[test]
fn caret_annotation_with_paragraph_symbol() {
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Caret /Rect [50 60 70 80] \
         /RD [1 2 3 4] /Sy /P >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Caret { rect_diffs, symbol } => {
            assert_eq!(*rect_diffs, Some([1.0, 2.0, 3.0, 4.0]));
            assert_eq!(symbol, "P");
        }
        other => panic!("expected Caret, got {other:?}"),
    }
}

#[test]
fn caret_annotation_default_symbol_is_none() {
    let pdf =
        synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Caret /Rect [50 60 70 80] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Caret { rect_diffs, symbol } => {
            assert!(rect_diffs.is_none());
            assert_eq!(symbol, "None");
        }
        other => panic!("expected Caret, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.14 Popup (Table 183).
// ────────────────────────────────────────────────────────────────────

#[test]
fn popup_annotation_with_parent_reference() {
    // Annot 5: Text (the parent markup), Annot 6: Popup pointing at it.
    let pdf = synth_pdf_with_annotations(&[
        "<< /Type /Annot /Subtype /Text /Rect [10 10 30 30] \
         /Contents (the text being commented on) >>",
        "<< /Type /Annot /Subtype /Popup /Rect [100 100 300 200] \
         /Parent 5 0 R /Open true >>",
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 2);
    match &anns[1].kind {
        AnnotationKind::Popup { parent, open } => {
            let p = parent.expect("Parent indirect ref");
            assert_eq!(p.number, 5);
            assert_eq!(p.generation, 0);
            assert!(*open);
        }
        other => panic!("expected Popup, got {other:?}"),
    }
}

#[test]
fn popup_annotation_no_parent_still_surfaces() {
    let pdf =
        synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Popup /Rect [0 0 100 100] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Popup { parent, open } => {
            assert!(parent.is_none());
            assert!(!*open);
        }
        other => panic!("expected Popup, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.15 FileAttachment (Table 184).
// ────────────────────────────────────────────────────────────────────

#[test]
fn file_attachment_annotation_default_icon_pushpin() {
    // Annot 5 is the FileAttachment; Object 6 is the filespec dict.
    let pdf = synth_pdf_with_annotations(&[
        "<< /Type /Annot /Subtype /FileAttachment /Rect [10 10 30 30] \
         /FS 6 0 R >>",
        "<< /Type /Filespec /F (notes.txt) /UF (notes.txt) >>",
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    // The 6-object inflates from the page tree's annotation array as
    // a "secondary annotation"; the reader skips non-Subtype dicts.
    // We expect exactly the FileAttachment.
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::FileAttachment {
            icon,
            file_name,
            filespec,
        } => {
            assert_eq!(icon, "PushPin");
            assert_eq!(file_name.as_deref(), Some("notes.txt"));
            let f = filespec.expect("FS indirect ref");
            assert_eq!(f.number, 6);
        }
        other => panic!("expected FileAttachment, got {other:?}"),
    }
}

#[test]
fn file_attachment_annotation_with_explicit_icon() {
    let pdf = synth_pdf_with_annotations(&[
        "<< /Type /Annot /Subtype /FileAttachment /Rect [10 10 30 30] \
         /FS 6 0 R /Name /Paperclip >>",
        "<< /Type /Filespec /F (data.csv) >>",
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::FileAttachment {
            icon, file_name, ..
        } => {
            assert_eq!(icon, "Paperclip");
            assert_eq!(file_name.as_deref(), Some("data.csv"));
        }
        other => panic!("expected FileAttachment, got {other:?}"),
    }
}

#[test]
fn file_attachment_annotation_prefers_uf_over_f_per_7_11_2() {
    // §7.11.2 Table 43 — /UF (UTF-16BE-with-BOM) takes precedence
    // over /F (PDFDocEncoded) when both present. Use a unicode name
    // in /UF to make the override observable.
    let pdf = synth_pdf_with_annotations(&[
        "<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 30 30] \
         /FS 6 0 R >>",
        "<< /Type /Filespec /F (notes.txt) \
         /UF <FEFF006E006F0074006500730055006E006900>  >>",
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::FileAttachment { file_name, .. } => {
            // FE FF 00 6E 00 6F 00 74 00 65 00 73 00 55 00 6E 00 69 00
            // = "notesUni" + dangling 00 byte → from_utf16_lossy keeps
            // the well-formed prefix and substitutes U+FFFD on the
            // unpaired 0x0000 high byte at the end (which decodes as
            // U+0000 NUL — UTF-16 doesn't surrogate-pair this).
            // The substring "notesUni" must appear; the exact tail is
            // not stable across rust stdlib minor releases.
            let s = file_name.as_deref().expect("UF resolved");
            assert!(
                s.starts_with("notesUni"),
                "expected UF-decoded prefix, got {s:?}"
            );
        }
        other => panic!("expected FileAttachment, got {other:?}"),
    }
}

#[test]
fn file_attachment_annotation_missing_fs_still_surfaces() {
    let pdf = synth_pdf_with_annotations(&[
        "<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 30 30] >>",
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::FileAttachment {
            icon,
            file_name,
            filespec,
        } => {
            assert_eq!(icon, "PushPin");
            assert!(file_name.is_none());
            assert!(filespec.is_none());
        }
        other => panic!("expected FileAttachment, got {other:?}"),
    }
}

#[test]
fn unknown_subtype_still_falls_through_to_other() {
    // Confirm new structured-variant rounds don't shadow the existing
    // Other fallback for subtypes that still aren't structurally
    // decoded. Round-204 lifted /Redact + /Watermark out; round-209
    // lifted /Sound + /Movie + /Screen; round-215 lifted /PrinterMark +
    // /TrapNet; round-220 lifted /3D (§13.6.2 Table 298); round-242
    // lifted /RichMedia (ISO 32000-2 §13.7.2 Table 333). The remaining
    // long-tail subtype (/Projection) and any authoring-tool extension
    // are still surfaced as AnnotationKind::Other so callers walking
    // forensic / archival PDFs get a complete enumeration even for the
    // long tail.
    let pdf = synth_pdf_with_annotations(&[
        "<< /Type /Annot /Subtype /Projection /Rect [0 0 30 30] >>",
        "<< /Type /Annot /Subtype /CustomToolExt /Rect [0 0 30 30] >>",
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 2);
    match &anns[0].kind {
        AnnotationKind::Other { subtype } => assert_eq!(subtype, "Projection"),
        other => panic!("expected Other(Projection), got {other:?}"),
    }
    match &anns[1].kind {
        AnnotationKind::Other { subtype } => assert_eq!(subtype, "CustomToolExt"),
        other => panic!("expected Other(CustomToolExt), got {other:?}"),
    }
}
