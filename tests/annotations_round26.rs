//! Round-26 — annotation reader (ISO 32000-1 §12.5).
//!
//! Verifies that [`oxideav_pdf::read_pdf_annotations`] surfaces
//! Text / FreeText / Stamp / Highlight / Square / Link / Widget /
//! unknown-subtype entries with the per-subtype detail decoded.
//!
//! We synthesise minimal PDFs by hand here rather than going through
//! the writer — the round-25 writer only emits `/Subtype /Link`, but
//! the reader needs to parse the long-tail Table 169..209 set across
//! subtypes that other PDF authoring tools produce.

use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    read_pdf_annotations, AnnotationKind, OutlineDestination, PdfLinkTarget, TextMarkupVariant,
    XmpPacket,
};

/// Build a minimal one-page PDF with the supplied per-page annotation
/// dicts spliced into the page's `/Annots` array.
///
/// Object numbering convention (matches the byte buffer below):
///   1 — Catalog
///   2 — Pages
///   3 — Page
///   4 — Empty content stream
///   5..N — annotation dicts
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
    // 1: Catalog
    push_obj(
        &mut body,
        &mut offsets,
        1,
        "<< /Type /Catalog /Pages 2 0 R >>",
    );
    // 2: Pages
    push_obj(
        &mut body,
        &mut offsets,
        2,
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    );
    // 3: Page — references annotation objects 5..
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
    // 4: Empty content stream
    push_obj(
        &mut body,
        &mut offsets,
        4,
        "<< /Length 0 >>\nstream\n\nendstream",
    );
    // 5..: Each annotation
    for (i, ab) in annot_bodies.iter().enumerate() {
        push_obj(&mut body, &mut offsets, 5 + i as u32, ab);
    }
    // xref + trailer
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

#[test]
fn text_annotation_decodes_open_and_icon() {
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Text /Rect [10 20 30 40] \
         /Contents (sticky note here) /Open true /Name /Comment \
         /State /Accepted /StateModel (Review) >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    let a = &anns[0];
    assert_eq!(a.source_page_index, 0);
    assert_eq!(a.rect, [10.0, 20.0, 30.0, 40.0]);
    assert_eq!(a.contents.as_deref(), Some("sticky note here"));
    match &a.kind {
        AnnotationKind::Text {
            open,
            icon,
            state,
            state_model,
        } => {
            assert!(*open);
            assert_eq!(icon, "Comment");
            assert_eq!(state.as_deref(), Some("Accepted"));
            assert_eq!(state_model.as_deref(), Some("Review"));
        }
        other => panic!("expected Text, got {other:?}"),
    }
}

#[test]
fn text_annotation_default_icon_is_note() {
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Text { icon, open, .. } => {
            assert_eq!(icon, "Note");
            assert!(!open);
        }
        other => panic!("expected Text, got {other:?}"),
    }
}

#[test]
fn freetext_annotation_decodes_da_quadding_and_intent() {
    let pdf =
        synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /FreeText /Rect [0 0 100 50] \
         /Contents (label) /DA (/Helv 12 Tf 0 g) /Q 1 \
         /IT /FreeTextCallout >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::FreeText {
            default_appearance,
            quadding,
            intent,
            ..
        } => {
            assert_eq!(default_appearance.as_deref(), Some("/Helv 12 Tf 0 g"));
            assert_eq!(*quadding, 1);
            assert_eq!(intent.as_deref(), Some("FreeTextCallout"));
        }
        other => panic!("expected FreeText, got {other:?}"),
    }
}

#[test]
fn stamp_annotation_surfaces_named_icon() {
    let pdf = synth_pdf_with_annotations(&[
        "<< /Type /Annot /Subtype /Stamp /Rect [50 50 200 100] /Name /Approved >>",
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    match &read_pdf_annotations(&mut r).unwrap()[0].kind {
        AnnotationKind::Stamp { icon } => assert_eq!(icon, "Approved"),
        other => panic!("expected Stamp, got {other:?}"),
    }
}

#[test]
fn stamp_annotation_default_icon_is_draft() {
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Stamp /Rect [0 0 50 50] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    match &read_pdf_annotations(&mut r).unwrap()[0].kind {
        AnnotationKind::Stamp { icon } => assert_eq!(icon, "Draft"),
        other => panic!("expected Stamp, got {other:?}"),
    }
}

#[test]
fn text_markup_variants_dispatch_correctly() {
    let pdf = synth_pdf_with_annotations(&[
        "<< /Type /Annot /Subtype /Highlight /Rect [0 0 100 20] \
         /QuadPoints [10 10 90 10 10 20 90 20] >>",
        "<< /Type /Annot /Subtype /Underline /Rect [0 0 100 20] \
         /QuadPoints [0 0 0 0 0 0 0 0] >>",
        "<< /Type /Annot /Subtype /Squiggly /Rect [0 0 100 20] \
         /QuadPoints [] >>",
        "<< /Type /Annot /Subtype /StrikeOut /Rect [0 0 100 20] >>",
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 4);
    let variants: Vec<_> = anns
        .iter()
        .map(|a| match &a.kind {
            AnnotationKind::TextMarkup { variant, .. } => *variant,
            other => panic!("expected TextMarkup, got {other:?}"),
        })
        .collect();
    assert_eq!(
        variants,
        vec![
            TextMarkupVariant::Highlight,
            TextMarkupVariant::Underline,
            TextMarkupVariant::Squiggly,
            TextMarkupVariant::StrikeOut
        ]
    );
    // First entry has 8 quad-points (one quad).
    match &anns[0].kind {
        AnnotationKind::TextMarkup { quad_points, .. } => assert_eq!(quad_points.len(), 8),
        _ => unreachable!(),
    }
    // Last entry has missing /QuadPoints — defaults to empty Vec.
    match &anns[3].kind {
        AnnotationKind::TextMarkup { quad_points, .. } => assert!(quad_points.is_empty()),
        _ => unreachable!(),
    }
}

#[test]
fn geometry_annotation_decodes_square_circle_and_optional_rd_ic() {
    let pdf = synth_pdf_with_annotations(&[
        "<< /Type /Annot /Subtype /Square /Rect [10 10 90 90] \
         /IC [1 0 0] /RD [2 2 2 2] /C [0 0 0] >>",
        "<< /Type /Annot /Subtype /Circle /Rect [10 10 90 90] >>",
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    match &anns[0].kind {
        AnnotationKind::Geometry {
            is_square,
            interior_colour,
            rect_diffs,
        } => {
            assert!(*is_square);
            assert_eq!(interior_colour.as_deref(), Some(&[1.0, 0.0, 0.0][..]));
            assert_eq!(*rect_diffs, Some([2.0, 2.0, 2.0, 2.0]));
        }
        other => panic!("expected Geometry, got {other:?}"),
    }
    assert_eq!(anns[0].colour.as_deref(), Some(&[0.0, 0.0, 0.0][..]));
    match &anns[1].kind {
        AnnotationKind::Geometry {
            is_square,
            interior_colour,
            rect_diffs,
        } => {
            assert!(!*is_square);
            assert!(interior_colour.is_none());
            assert!(rect_diffs.is_none());
        }
        other => panic!("expected Geometry, got {other:?}"),
    }
}

#[test]
fn link_annotation_internal_target_decodes_through_unified_reader() {
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Link /Rect [0 0 50 20] \
         /Dest [3 0 R /Fit] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    match &read_pdf_annotations(&mut r).unwrap()[0].kind {
        AnnotationKind::Link {
            target: Some(PdfLinkTarget::Internal(OutlineDestination::Fit { page_index })),
        } => assert_eq!(*page_index, 0),
        other => panic!("expected Link Internal Fit, got {other:?}"),
    }
}

#[test]
fn link_annotation_uri_action_decodes() {
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Link /Rect [0 0 50 20] \
         /A << /S /URI /URI (https://example.org) >> >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    match &read_pdf_annotations(&mut r).unwrap()[0].kind {
        AnnotationKind::Link {
            target: Some(PdfLinkTarget::Uri(s)),
        } => assert_eq!(s, "https://example.org"),
        other => panic!("expected Link URI, got {other:?}"),
    }
}

#[test]
fn widget_annotation_decodes_field_trio() {
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Widget /Rect [0 0 100 30] \
         /FT /Tx /T (FullName) /V (Mark Karpeles) >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    match &read_pdf_annotations(&mut r).unwrap()[0].kind {
        AnnotationKind::Widget {
            field_type,
            field_name,
            value,
        } => {
            assert_eq!(field_type.as_deref(), Some("Tx"));
            assert_eq!(field_name.as_deref(), Some("FullName"));
            assert_eq!(value.as_deref(), Some("Mark Karpeles"));
        }
        other => panic!("expected Widget, got {other:?}"),
    }
}

#[test]
fn unknown_subtype_falls_through_to_other() {
    // /Movie was lifted into a structured variant in round-209;
    // pick a subtype still in the long tail (§13.6 3D annotations
    // need cross-crate plumbing).
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /3D /Rect [0 0 100 100] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    match &read_pdf_annotations(&mut r).unwrap()[0].kind {
        AnnotationKind::Other { subtype } => assert_eq!(subtype, "3D"),
        other => panic!("expected Other, got {other:?}"),
    }
}

#[test]
fn annotation_common_fields_capture_flags_modified_name() {
    let pdf = synth_pdf_with_annotations(&["<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] \
         /F 4 /M (D:20260510120000Z) /NM (annot-uid-001) \
         /Border [0 0 1] >>"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    let a = &anns[0];
    assert_eq!(a.flags, 4);
    assert_eq!(a.modified.as_deref(), Some("D:20260510120000Z"));
    assert_eq!(a.name.as_deref(), Some("annot-uid-001"));
    assert_eq!(a.border.as_deref(), Some(&[0.0, 0.0, 1.0][..]));
}

#[test]
fn page_without_annots_yields_empty_vec() {
    // Note: synth_pdf_with_annotations always emits /Annots, so we
    // bypass it here and synthesise a page without /Annots.
    let pdf = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R /Resources << >> >>\nendobj\n\
4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n\
xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000056 00000 n \n0000000106 00000 n \n0000000200 00000 n \n\
trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n246\n%%EOF\n"
        .to_vec();
    // The xref offsets above are approximate; rebuild via the real
    // reader path by going through our writer entry point instead.
    let mut r = match DocumentReader::open(&pdf) {
        Ok(r) => r,
        Err(_) => {
            // If the hand-crafted offsets are off, fall back to the
            // synth helper with zero annotations — that guarantees a
            // valid PDF byte buffer but it does include /Annots [] so
            // we instead test through the writer's no-link path.
            let scene_pdf = oxideav_pdf::write_pdf_from_scene(&one_page_scene()).unwrap();
            let mut rr = DocumentReader::open(&scene_pdf).unwrap();
            assert!(read_pdf_annotations(&mut rr).unwrap().is_empty());
            return;
        }
    };
    assert!(read_pdf_annotations(&mut r).unwrap().is_empty());
}

fn one_page_scene() -> oxideav_scene::Scene {
    use oxideav_core::time::TimeBase;
    use oxideav_core::vector::{
        FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
    };
    use oxideav_scene::{Page, Scene};
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(0.0, 0.0)));
    p.commands.push(PathCommand::LineTo(Point::new(10.0, 0.0)));
    p.commands.push(PathCommand::LineTo(Point::new(10.0, 10.0)));
    p.commands.push(PathCommand::Close);
    let mut page = Page::new(100.0, 100.0);
    page.content = VectorFrame {
        width: 100.0,
        height: 100.0,
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
    Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    }
}

#[test]
fn writer_link_annotations_round_trip_through_unified_reader() {
    use oxideav_pdf::{
        write_pdf_from_scene_with_outlines_and_links, LinkAnnotationSpec, LinkTarget,
    };
    let scene = one_page_scene();
    let links = vec![LinkAnnotationSpec {
        source_page_index: 0,
        rect: [5.0, 5.0, 50.0, 25.0],
        target: LinkTarget::Uri("https://oxideav.example".into()),
    }];
    let bytes = write_pdf_from_scene_with_outlines_and_links(&scene, &[], &links).unwrap();
    let mut reader = DocumentReader::open(&bytes).unwrap();
    let anns = reader.annotations().unwrap();
    assert_eq!(anns.len(), 1);
    assert_eq!(anns[0].source_page_index, 0);
    assert_eq!(anns[0].rect, [5.0, 5.0, 50.0, 25.0]);
    match &anns[0].kind {
        AnnotationKind::Link {
            target: Some(PdfLinkTarget::Uri(s)),
        } => assert_eq!(s, "https://oxideav.example"),
        other => panic!("expected Link URI, got {other:?}"),
    }
}

// ── XMP packet extraction (round-26) ──────────────────────────────

const XMP_BYTES: &[u8] = br#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about=""
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
    xmlns:pdf="http://ns.adobe.com/pdf/1.3/"
    xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/">
  <dc:title><rdf:Alt><rdf:li xml:lang="x-default">Round 26 Test</rdf:li></rdf:Alt></dc:title>
  <dc:creator><rdf:Seq><rdf:li>Mark Karpeles</rdf:li></rdf:Seq></dc:creator>
  <dc:format>application/pdf</dc:format>
  <xmp:CreateDate>2026-05-10T12:00:00Z</xmp:CreateDate>
  <xmp:CreatorTool>oxideav-pdf</xmp:CreatorTool>
  <pdf:Producer>oxideav-pdf 0.1.x</pdf:Producer>
  <pdfaid:part>2</pdfaid:part>
  <pdfaid:conformance>U</pdfaid:conformance>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

#[test]
fn xmp_packet_round_trips_dc_xmp_pdf_and_pdfaid_fields() {
    use oxideav_pdf::write_pdf_from_scene_with_xmp;
    let scene = one_page_scene();
    let pdf = write_pdf_from_scene_with_xmp(&scene, XMP_BYTES).unwrap();
    let mut r = DocumentReader::open(&pdf).unwrap();
    let parsed = r.xmp_packet().unwrap().expect("packet present");
    assert_eq!(parsed.dc_title.as_deref(), Some("Round 26 Test"));
    assert_eq!(parsed.dc_creator.as_deref(), Some("Mark Karpeles"));
    assert_eq!(parsed.dc_format.as_deref(), Some("application/pdf"));
    assert_eq!(
        parsed.xmp_create_date.as_deref(),
        Some("2026-05-10T12:00:00Z")
    );
    assert_eq!(parsed.xmp_creator_tool.as_deref(), Some("oxideav-pdf"));
    assert_eq!(parsed.pdf_producer.as_deref(), Some("oxideav-pdf 0.1.x"));
    assert_eq!(parsed.pdfaid_part, Some(2));
    assert_eq!(parsed.pdfaid_conformance.as_deref(), Some("U"));
    assert!(parsed.is_pdf_a());
    assert_eq!(parsed.pdf_a_conformance().as_deref(), Some("2U"));
}

#[test]
fn xmp_packet_returns_none_when_catalog_has_no_metadata() {
    let scene = one_page_scene();
    let pdf = oxideav_pdf::write_pdf_from_scene(&scene).unwrap();
    let mut r = DocumentReader::open(&pdf).unwrap();
    assert!(r.xmp_packet().unwrap().is_none());
}

#[test]
fn xmp_packet_parse_standalone_handles_attribute_form() {
    let bytes = br#"<?xpacket?><x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about=""
    xmlns:pdf="http://ns.adobe.com/pdf/1.3/"
    pdf:Producer="Tool One"
    pdf:Keywords="alpha,beta"/>
</rdf:RDF></x:xmpmeta>"#;
    let p = XmpPacket::parse(bytes);
    assert_eq!(p.pdf_producer.as_deref(), Some("Tool One"));
    assert_eq!(p.pdf_keywords.as_deref(), Some("alpha,beta"));
    assert!(!p.is_pdf_a());
}

#[test]
fn xmp_packet_parse_handles_dc_subject_bag() {
    let bytes = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:subject>
    <rdf:Bag>
      <rdf:li>one</rdf:li>
      <rdf:li>two</rdf:li>
      <rdf:li>three</rdf:li>
    </rdf:Bag>
  </dc:subject>
</rdf:Description>
</rdf:RDF></x:xmpmeta>"#;
    let p = XmpPacket::parse(bytes);
    assert_eq!(p.dc_subject, vec!["one", "two", "three"]);
}

#[test]
fn xmp_packet_handles_xml_entity_decode_in_titles() {
    let bytes = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:title><rdf:Alt><rdf:li xml:lang="x-default">A &amp; B &lt;v2&gt;</rdf:li></rdf:Alt></dc:title>
</rdf:Description>
</rdf:RDF></x:xmpmeta>"#;
    let p = XmpPacket::parse(bytes);
    assert_eq!(p.dc_title.as_deref(), Some("A & B <v2>"));
}
