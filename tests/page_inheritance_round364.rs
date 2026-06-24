//! Round-364 inheritable page attribute resolution test
//! (ISO 32000-1 §7.7.3.4 "Inheritance of Page Attributes").
//!
//! `MediaBox` and `Resources` (along with `CropBox` and `Rotate`) are
//! inheritable: a leaf page that omits them takes the value from the
//! nearest ancestor `/Pages` node. Before round 364 the reader read
//! only directly-attached `/MediaBox` and `/Resources`, so a document
//! that hangs one resource dictionary (or one media box) on the page
//! tree root rendered empty / A4-defaulted. This test builds a page
//! that defines *neither* on the leaf and verifies both resolve from
//! the parent — proven end-to-end by a `Do` against a Form XObject
//! whose name lives only in the inherited `/Resources /XObject`.

use oxideav_core::vector::{Node, Paint};
use oxideav_pdf::read_pdf_to_scene;

fn collect_fills(group: &oxideav_core::vector::Group, out: &mut Vec<(u8, u8, u8)>) {
    for child in &group.children {
        match child {
            Node::Path(p) => {
                if let Some(Paint::Solid(c)) = &p.fill {
                    out.push((c.r, c.g, c.b));
                }
            }
            Node::Group(g) => collect_fills(g, out),
            _ => {}
        }
    }
}

/// Build a single-page PDF whose leaf page omits both `/MediaBox` and
/// `/Resources`; the `/Pages` parent carries `/MediaBox [0 0 300 400]`
/// and `/Resources << /XObject << /Fm0 5 0 R >> >>`. The page content
/// paints `/Fm0` (a red triangle Form XObject), which can only resolve
/// if the inherited `/Resources` is found.
fn build_inherited_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 6] = [0; 6];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    // 2 = Pages node carrying the inheritable /MediaBox + /Resources.
    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 \
          /MediaBox [0 0 300 400] \
          /Resources << /XObject << /Fm0 5 0 R >> >> \
          >>\nendobj\n",
    );

    let content: &[u8] = b"/Fm0 Do\n";
    let form_content: &[u8] = b"1 0 0 rg 0 0 m 50 50 l 50 0 l h f\n";

    // 5 = Form XObject stream.
    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XObject /Subtype /Form /BBox [0 0 50 50] /Length {} >>\nstream\n",
            form_content.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(form_content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // 3 = leaf Page: NO /MediaBox, NO /Resources — both inherited.
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n");

    // 4 = Content stream.
    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // xref + trailer.
    let n = offsets.len();
    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n");
    bytes.extend_from_slice(format!("0 {n}\n").as_bytes());
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1) {
        bytes.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(b"trailer\n");
    bytes.extend_from_slice(format!("<< /Size {n} /Root 1 0 R >>\n").as_bytes());
    bytes.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    bytes
}

#[test]
fn inherited_media_box_sets_page_dimensions() {
    let pdf = build_inherited_pdf();
    assert!(pdf.len() <= 10 * 1024, "fixture under 10 KB");

    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let pages = scene.pages.as_ref().expect("scene has pages");
    assert_eq!(pages.len(), 1);
    // /MediaBox [0 0 300 400] inherited from the /Pages parent — NOT
    // the A4 (595×842) default the leaf would have fallen back to.
    assert_eq!(pages[0].width, 300.0);
    assert_eq!(pages[0].height, 400.0);
}

#[test]
fn inherited_resources_resolve_form_xobject() {
    let pdf = build_inherited_pdf();
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert_eq!(
        fills,
        vec![(255, 0, 0)],
        "the form named only in the inherited /Resources paints, got {fills:?}"
    );
}

/// Build a single-page PDF whose `/Pages` parent carries
/// `/Rotate <parent_rotate>`; the leaf page carries the literal
/// `leaf_page_extra` entries (e.g. its own `/Rotate` override or none).
fn build_rotate_pdf(parent_rotate: &str, leaf_page_extra: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(512);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 5] = [0; 5];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 \
             /MediaBox [0 0 200 200] {parent_rotate} >>\nendobj\n"
        )
        .as_bytes(),
    );

    let content: &[u8] = b"q Q\n";

    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R {leaf_page_extra} >>\nendobj\n"
        )
        .as_bytes(),
    );

    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    let n = offsets.len();
    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n");
    bytes.extend_from_slice(format!("0 {n}\n").as_bytes());
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1) {
        bytes.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(b"trailer\n");
    bytes.extend_from_slice(format!("<< /Size {n} /Root 1 0 R >>\n").as_bytes());
    bytes.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    bytes
}

fn page_orientation(pdf: &[u8]) -> u16 {
    let scene = read_pdf_to_scene(pdf).expect("read PDF to scene");
    scene.pages.as_ref().unwrap()[0].orientation
}

#[test]
fn rotate_inherited_from_parent() {
    // /Rotate 90 on the /Pages parent, leaf overrides nothing.
    let pdf = build_rotate_pdf("/Rotate 90", "");
    assert_eq!(page_orientation(&pdf), 90);
}

#[test]
fn rotate_leaf_overrides_parent() {
    // Parent says 90, leaf says 270 — the leaf's own value wins.
    let pdf = build_rotate_pdf("/Rotate 90", "/Rotate 270");
    assert_eq!(page_orientation(&pdf), 270);
}

#[test]
fn rotate_negative_normalises_into_canonical_range() {
    // -90 (a multiple of 90) normalises to 270 clockwise.
    let pdf = build_rotate_pdf("/Rotate -90", "");
    assert_eq!(page_orientation(&pdf), 270);
}

#[test]
fn rotate_non_multiple_of_90_falls_back_to_zero() {
    // 45 is not a multiple of 90 (malformed) → default 0.
    let pdf = build_rotate_pdf("/Rotate 45", "");
    assert_eq!(page_orientation(&pdf), 0);
}

#[test]
fn rotate_absent_defaults_to_zero() {
    let pdf = build_rotate_pdf("", "");
    assert_eq!(page_orientation(&pdf), 0);
}
