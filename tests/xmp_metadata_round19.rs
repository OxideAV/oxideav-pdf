//! Round-19 — document-level XMP `/Metadata` stream end-to-end
//! (ISO 32000-1 §14.3.2 + Adobe XMP Spec 2012).
//!
//! Writer-side: [`oxideav_pdf::write_pdf_from_scene_with_xmp`] attaches
//! the supplied XMP packet to the catalog's `/Metadata` entry as a
//! `/Type /Metadata /Subtype /XML` stream. Reader-side:
//! [`oxideav_pdf::reader::DocumentReader::xmp_metadata`] surfaces the
//! same bytes back. The XMP packet is round-tripped byte-for-byte.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::{reader::DocumentReader, write_pdf_from_scene_with_xmp};
use oxideav_scene::{Page, Scene};

fn scene_with_one_page() -> Scene {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(0.0, 0.0)));
    p.commands.push(PathCommand::LineTo(Point::new(50.0, 0.0)));
    p.commands.push(PathCommand::LineTo(Point::new(50.0, 50.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 100.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(64, 128, 192))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let mut page = Page::new(100.0, 100.0);
    page.content = frame;
    Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    }
}

const SAMPLE_XMP: &[u8] = b"<?xpacket begin=\"\xEF\xBB\xBF\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n\
  <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
    <rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\n\
      <dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">Round 19 XMP Test</rdf:li></rdf:Alt></dc:title>\n\
    </rdf:Description>\n\
  </rdf:RDF>\n\
</x:xmpmeta>\n\
<?xpacket end=\"w\"?>\n";

#[test]
fn xmp_metadata_round_trips_byte_for_byte() {
    let scene = scene_with_one_page();
    let pdf = write_pdf_from_scene_with_xmp(&scene, SAMPLE_XMP).expect("write");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let recovered = reader
        .xmp_metadata()
        .expect("read xmp")
        .expect("metadata present");
    assert_eq!(recovered, SAMPLE_XMP);
}

#[test]
fn writer_emits_metadata_dict_with_subtype_xml() {
    let scene = scene_with_one_page();
    let pdf = write_pdf_from_scene_with_xmp(&scene, SAMPLE_XMP).expect("write");
    let bytes = String::from_utf8_lossy(&pdf);
    // Catalog should reference /Metadata; the metadata stream itself
    // should declare /Type /Metadata + /Subtype /XML per §14.3.2.
    assert!(bytes.contains("/Metadata"), "catalog missing /Metadata key");
    assert!(
        bytes.contains("/Type /Metadata") || bytes.contains("/Type/Metadata"),
        "metadata stream missing /Type /Metadata"
    );
    assert!(
        bytes.contains("/Subtype /XML") || bytes.contains("/Subtype/XML"),
        "metadata stream missing /Subtype /XML"
    );
}

#[test]
fn reader_returns_none_when_no_metadata_attached() {
    // Use the standard write_pdf_from_scene which does NOT attach XMP.
    let scene = scene_with_one_page();
    let pdf = oxideav_pdf::write_pdf_from_scene(&scene).expect("write");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let recovered = reader.xmp_metadata().expect("xmp lookup");
    assert!(
        recovered.is_none(),
        "expected no metadata, got {:?}",
        recovered
    );
}

#[test]
fn xmp_metadata_handles_binary_payload() {
    // §14.3.2 only recommends UTF-8 RDF/XML — our writer takes raw bytes
    // and surfaces them unchanged. Verify a binary payload survives.
    let scene = scene_with_one_page();
    let payload: Vec<u8> = (0u8..=255).collect();
    let pdf = write_pdf_from_scene_with_xmp(&scene, &payload).expect("write");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let recovered = reader.xmp_metadata().expect("read").expect("present");
    assert_eq!(recovered, payload);
}

#[test]
fn xmp_metadata_round_trips_with_scene_metadata_too() {
    // XMP and /Info should coexist: §14.3.3 keeps /Info; §14.3.2 adds
    // a parallel XMP stream. Round-trip both.
    let mut scene = scene_with_one_page();
    scene.metadata = oxideav_scene::Metadata {
        title: Some("Combined doc".into()),
        author: Some("Round 19".into()),
        ..Default::default()
    };
    let pdf = write_pdf_from_scene_with_xmp(&scene, SAMPLE_XMP).expect("write");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let recovered = reader.xmp_metadata().expect("read").expect("present");
    assert_eq!(recovered, SAMPLE_XMP);
    // /Info should still parse via the scene round-trip helper.
    let parsed = oxideav_pdf::reader::read_pdf_to_scene(&pdf).expect("read scene");
    assert_eq!(parsed.metadata.title.as_deref(), Some("Combined doc"));
    assert_eq!(parsed.metadata.author.as_deref(), Some("Round 19"));
}
