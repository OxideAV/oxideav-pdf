//! Round-369 CIE-based `/Resources /ColorSpace` resolution end-to-end
//! test (ISO 32000-1 §8.6.5.2 CalGray, §8.6.5.3 CalRGB, §8.6.5.4 Lab).
//!
//! Before this round the content-stream parser resolved the device
//! families plus ICCBased / Indexed / Separation / DeviceN resource
//! colour spaces, but a `cs` naming a `[/CalGray …]`, `[/CalRGB …]`, or
//! `[/Lab …]` array collapsed to `Unknown` and the following `sc`/`scn`
//! fell back to black. This round decodes each CIE-based space to a CIE
//! 1931 XYZ value (per its `/WhitePoint` / `/Gamma` / `/Matrix` /
//! `/Range`) and reduces it to device RGB through the standard sRGB
//! display colorimetry.
//!
//! A hand-built single-page PDF paints three triangles, each in a
//! different CIE-based resource colour space, all driving the same
//! observable result so the assertions stay device-independent:
//!
//! * `/CS0 = [/CalGray << /WhitePoint … >>]` — `1 sc` (full gray A=1.0)
//!   → device white.
//! * `/CS1 = [/CalRGB << /WhitePoint … >>]` (identity gamma + matrix) —
//!   `0 0 0 scn` (all-zero) → black.
//! * `/CS2 = [/Lab << /WhitePoint … /Range … >>]` — `100 0 0 scn`
//!   (L*=100, a*=b*=0) → device white.

use oxideav_core::vector::{Node, Paint};
use oxideav_pdf::read_pdf_to_scene;

/// Build the round-369 CIE colour-space fixture in memory. All three
/// resource colour spaces are inline arrays carrying their colour-space
/// dictionary directly (the form §8.6.5 prescribes).
fn build_cie_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 5] = [0; 5];

    // 1 = Catalog
    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    // 2 = Pages
    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // Three triangles, one per CIE space, all → white/black extremes.
    let content: &[u8] = b"/CS0 cs 1 sc 0 0 m 10 10 l 10 0 l h f \
                           /CS1 cs 0 0 0 scn 20 0 m 30 10 l 30 0 l h f \
                           /CS2 cs 100 0 0 scn 40 0 m 50 10 l 50 0 l h f\n";

    // 3 = Page. /Resources /ColorSpace maps the three CIE spaces inline.
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
          /Contents 4 0 R \
          /Resources << /ColorSpace << \
            /CS0 [/CalGray << /WhitePoint [0.9505 1.0 1.089] >>] \
            /CS1 [/CalRGB << /WhitePoint [0.9505 1.0 1.089] >>] \
            /CS2 [/Lab << /WhitePoint [0.9505 1.0 1.089] /Range [-128 127 -128 127] >>] \
          >> >> \
          >>\nendobj\n",
    );

    // 4 = Content stream.
    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // xref
    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n");
    bytes.extend_from_slice(b"0 5\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1) {
        bytes.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    bytes.extend_from_slice(b"trailer\n");
    bytes.extend_from_slice(b"<< /Size 5 /Root 1 0 R >>\n");
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());

    bytes
}

fn fill_rgb(node: &Node) -> (u8, u8, u8) {
    let Node::Path(p) = node else {
        panic!("expected painted path node");
    };
    match &p.fill {
        Some(Paint::Solid(c)) => (c.r, c.g, c.b),
        other => panic!("unexpected fill: {other:?}"),
    }
}

#[test]
fn cie_resource_colour_spaces_resolve() {
    let pdf = build_cie_pdf();
    assert!(pdf.len() <= 10 * 1024, "fixture under 10 KB");

    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let pages = scene.pages.as_ref().expect("scene has pages");
    assert_eq!(pages.len(), 1);

    let root = &pages[0].content.root;
    assert_eq!(root.children.len(), 3, "three painted paths");

    // CS0 CalGray, A = 1.0 → device white.
    assert_eq!(
        fill_rgb(&root.children[0]),
        (255, 255, 255),
        "CalGray white"
    );
    // CS1 CalRGB, (0,0,0) → black.
    assert_eq!(fill_rgb(&root.children[1]), (0, 0, 0), "CalRGB black");
    // CS2 Lab, L*=100 a*=b*=0 → device white.
    assert_eq!(fill_rgb(&root.children[2]), (255, 255, 255), "Lab white");
}
