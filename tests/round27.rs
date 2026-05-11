//! Round-27 integration tests.
//!
//! Covers the three new reader surfaces:
//! 1. Linearization parameter dictionary parse (ISO 32000-1 §F.2).
//! 2. Object-hierarchy validator (§7.7.2 + §7.7.3).
//! 3. PDF/A conformance detection beyond the XMP tag (ISO 19005-x).

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::{
    hierarchy::IssueSeverity,
    pdfa::{PdfACatalogSignals, PdfAConformance},
    DocumentReader,
};
use oxideav_pdf::{
    parse_linearization_dict, verify_pdf_hierarchy, write_pdf_from_scene,
    write_pdf_from_scene_linearized, write_pdf_from_scene_with_xmp, XmpPacket,
};
use oxideav_scene::{Page, Scene};

fn page_with(w: f32, h: f32, color: Rgba) -> Page {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(w - 10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(w - 10.0, h - 10.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: w,
        height: h,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(color)),
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
}

// ──────────────── Linearization Parameter Dictionary ────────────────

#[test]
fn linearization_parse_writer_output_three_pages() {
    let scene = Scene {
        pages: Some(vec![
            page_with(100.0, 100.0, Rgba::opaque(255, 0, 0)),
            page_with(200.0, 150.0, Rgba::opaque(0, 255, 0)),
            page_with(300.0, 200.0, Rgba::opaque(0, 0, 255)),
        ]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene_linearized(&scene).expect("write_pdf_from_scene_linearized");
    let lin = parse_linearization_dict(&pdf)
        .expect("parse_linearization_dict")
        .expect("linearized file must return Some");
    assert_eq!(lin.linearized, 1.0);
    assert_eq!(lin.file_length, pdf.len() as u64);
    assert_eq!(lin.page_count, 3);
    lin.verify(&pdf).expect("verify against actual file bytes");
}

#[test]
fn linearization_returns_none_for_plain_writer_output() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene(&scene).expect("write_pdf_from_scene");
    let lin = parse_linearization_dict(&pdf).expect("parse_linearization_dict");
    assert!(lin.is_none(), "plain PDF returns None — got {lin:?}");
}

#[test]
fn linearization_main_xref_offset_points_at_xref_keyword() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene_linearized(&scene).expect("linearize");
    let lin = parse_linearization_dict(&pdf)
        .expect("parse")
        .expect("Some");
    // The main xref in a linearized file is at /T — and starts with `xref\n`.
    let off = lin.main_xref_offset as usize;
    assert!(off < pdf.len());
    assert_eq!(&pdf[off..off + 5], b"xref\n");
}

#[test]
fn linearization_via_documentreader_accessor() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene_linearized(&scene).expect("linearize");
    let reader = DocumentReader::open(&pdf).expect("open");
    let lin = reader
        .linearization()
        .expect("linearization()")
        .expect("Some");
    assert_eq!(lin.linearized, 1.0);
    assert_eq!(lin.page_count, 1);
}

#[test]
fn linearization_via_documentreader_plain_pdf() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene(&scene).expect("write");
    let reader = DocumentReader::open(&pdf).expect("open");
    let lin = reader.linearization().expect("linearization()");
    assert!(lin.is_none(), "plain PDF returns None");
}

// ──────────────── Object Hierarchy Validator ────────────────

#[test]
fn hierarchy_validator_passes_writer_output_multi_page() {
    let scene = Scene {
        pages: Some(vec![
            page_with(100.0, 100.0, Rgba::opaque(255, 0, 0)),
            page_with(200.0, 200.0, Rgba::opaque(0, 255, 0)),
            page_with(300.0, 200.0, Rgba::opaque(0, 0, 255)),
        ]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene(&scene).expect("write");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let report = verify_pdf_hierarchy(&mut reader).expect("verify");
    assert_eq!(report.page_count, 3);
    assert!(report.is_valid(), "writer must produce valid hierarchy");
    let err_count = report
        .issues
        .iter()
        .filter(|i| i.severity == IssueSeverity::Error)
        .count();
    assert_eq!(err_count, 0);
}

#[test]
fn hierarchy_validator_passes_writer_output_single_page() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene(&scene).expect("write");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let report = verify_pdf_hierarchy(&mut reader).expect("verify");
    assert_eq!(report.page_count, 1);
    assert_eq!(report.max_depth, 1);
    assert!(report.is_valid());
}

#[test]
fn hierarchy_validator_via_documentreader() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene(&scene).expect("write");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let report = reader.verify_hierarchy().expect("verify_hierarchy");
    assert!(report.is_valid());
    assert_eq!(report.page_count, 1);
}

#[test]
fn hierarchy_validator_linearized_output_is_clean() {
    let scene = Scene {
        pages: Some(vec![
            page_with(100.0, 100.0, Rgba::opaque(255, 0, 0)),
            page_with(200.0, 150.0, Rgba::opaque(0, 255, 0)),
        ]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene_linearized(&scene).expect("linearize");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let report = reader.verify_hierarchy().expect("verify");
    assert!(
        report.is_valid(),
        "linearized output must pass hierarchy check; got {:?}",
        report.issues
    );
    assert_eq!(report.page_count, 2);
}

// ──────────────── PDF/A Conformance Detection ────────────────

#[test]
fn pdfa_signals_writer_output_has_no_signals() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene(&scene).expect("write");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let sig = reader.pdfa_signals().expect("pdfa_signals");
    assert!(!sig.has_xmp_metadata);
    assert!(!sig.has_struct_tree_root);
    assert!(!sig.mark_info_marked);
    assert!(sig.catalog_lang.is_none());
    assert_eq!(sig.output_intent_count, 0);
}

#[test]
fn pdfa_signals_xmp_only_doc_surfaces_metadata_signal() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let xmp = br#"<?xpacket begin=""?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/">
  <pdfaid:part>2</pdfaid:part>
  <pdfaid:conformance>B</pdfaid:conformance>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;
    let pdf = write_pdf_from_scene_with_xmp(&scene, xmp).expect("write_with_xmp");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let sig = reader.pdfa_signals().expect("pdfa_signals");
    assert!(
        sig.has_xmp_metadata,
        "doc written with /Metadata must surface that signal"
    );
}

#[test]
fn pdfa_conformance_doc_without_xmp_returns_undeclared() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene(&scene).expect("write");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let conf = reader.pdfa_conformance().expect("pdfa_conformance");
    assert!(!conf.is_declared());
    assert!(conf.structurally_sound);
    assert!(!conf.claim_inconsistent);
}

#[test]
fn pdfa_conformance_xmp_b_claim_flags_missing_output_intents() {
    // A doc that CLAIMS PDF/A-2B in XMP but lacks /OutputIntents is
    // non-conformant per ISO 19005-2 §6.2.2.
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let xmp = br#"<?xpacket begin=""?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/">
  <pdfaid:part>2</pdfaid:part>
  <pdfaid:conformance>B</pdfaid:conformance>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;
    let pdf = write_pdf_from_scene_with_xmp(&scene, xmp).expect("write_with_xmp");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let conf = reader.pdfa_conformance().expect("pdfa_conformance");
    assert!(conf.is_declared());
    assert_eq!(conf.declared, Some((2u8, "B".into())));
    assert!(conf.claim_inconsistent, "missing /OutputIntents must flag");
    assert!(conf
        .inconsistencies
        .iter()
        .any(|s| s.contains("OutputIntents")));
    assert_eq!(conf.designator().as_deref(), Some("2B"));
}

#[test]
fn pdfa_conformance_synthetic_a_level_lacks_structtreeroot() {
    // Hand-constructed signals to exercise the A-level branch
    // without needing a writer-side StructTreeRoot.
    let sig = PdfACatalogSignals {
        has_xmp_metadata: true,
        output_intent_count: 1,
        mark_info_marked: false,
        has_struct_tree_root: false,
        ..Default::default()
    };
    let xmp = XmpPacket {
        pdfaid_part: Some(1),
        pdfaid_conformance: Some("A".into()),
        ..XmpPacket::default()
    };
    let conf = PdfAConformance::from_signals_and_xmp(&sig, Some(&xmp));
    assert!(conf.claim_inconsistent);
    assert!(!conf.structurally_sound);
    assert!(conf
        .inconsistencies
        .iter()
        .any(|s| s.contains("StructTreeRoot")));
    assert!(conf
        .inconsistencies
        .iter()
        .any(|s| s.contains("Marked is not true")));
}

#[test]
fn pdfa_conformance_synthetic_a_level_full_structure_is_sound() {
    let sig = PdfACatalogSignals {
        has_xmp_metadata: true,
        output_intent_count: 1,
        mark_info_marked: true,
        has_struct_tree_root: true,
        catalog_lang: Some("en-US".into()),
        ..Default::default()
    };
    let xmp = XmpPacket {
        pdfaid_part: Some(2),
        pdfaid_conformance: Some("A".into()),
        ..XmpPacket::default()
    };
    let conf = PdfAConformance::from_signals_and_xmp(&sig, Some(&xmp));
    assert!(conf.structurally_sound);
    assert!(!conf.claim_inconsistent);
    assert_eq!(conf.designator().as_deref(), Some("2A"));
}
