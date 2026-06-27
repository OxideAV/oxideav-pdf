//! Round-377 clipped `sh` shading-paint test (ISO 32000-1 §8.7.4.5).
//!
//! The `name sh` operator paints the shading across the current clipping
//! region. The reader now fills the active clip path with the equivalent
//! scene gradient (axial → `Paint::LinearGradient`, radial →
//! `Paint::RadialGradient`) in addition to surfacing the `ContentShading`
//! event, so a clipped `sh` gradient becomes visible in the `Scene`.
//!
//! A single-page PDF clips to a rectangle (`W n`), then paints an axial
//! black→white `sh` over that clip.

use oxideav_core::vector::{Node, Paint};
use oxideav_pdf::read_pdf_to_scene;

fn build_clipped_sh_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 5] = [0; 5];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // Clip to a 20..80 square, then paint the /Sh0 axial shading over it.
    let content: &[u8] = b"20 20 60 60 re W n /Sh0 sh\n";

    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
          /Contents 4 0 R \
          /Resources << /Shading << /Sh0 << \
            /ShadingType 2 /ColorSpace /DeviceRGB \
            /Coords [20 0 80 0] \
            /Function << /FunctionType 2 /Domain [0 1] \
              /C0 [0 0 0] /C1 [1 1 1] /N 1 >> \
          >> >> >> \
          >>\nendobj\n",
    );

    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

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

fn first_linear_gradient(node: &Node) -> Option<&oxideav_core::vector::LinearGradient> {
    match node {
        Node::Path(p) => match &p.fill {
            Some(Paint::LinearGradient(lg)) => Some(lg),
            _ => None,
        },
        Node::Group(g) => g.children.iter().find_map(first_linear_gradient),
        _ => None,
    }
}

#[test]
fn clipped_sh_paints_gradient_into_scene() {
    let pdf = build_clipped_sh_pdf();
    let scene = read_pdf_to_scene(&pdf).expect("read clipped-sh PDF");
    let pages = scene.pages.as_ref().expect("scene has pages");
    let page = &pages[0];

    let lg = page
        .content
        .root
        .children
        .iter()
        .find_map(first_linear_gradient)
        .expect("clipped axial sh should produce a LinearGradient fill");

    // Axis [20 0 80 0] under identity CTM.
    assert!((lg.start.x - 20.0).abs() < 1e-2, "start.x = {}", lg.start.x);
    assert!((lg.end.x - 80.0).abs() < 1e-2, "end.x = {}", lg.end.x);
    assert!(!lg.stops.is_empty());
    // First stop black, last white.
    let (r0, g0, b0) = (
        lg.stops[0].color.r,
        lg.stops[0].color.g,
        lg.stops[0].color.b,
    );
    assert_eq!((r0, g0, b0), (0, 0, 0));
    let last = lg.stops.last().unwrap();
    assert_eq!((last.color.r, last.color.g, last.color.b), (255, 255, 255));
}
