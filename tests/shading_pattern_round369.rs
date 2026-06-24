//! Round-369 shading-pattern fill end-to-end test (ISO 32000-1
//! §8.7.3.3 Shading Patterns + §8.7.4.5 axial shadings).
//!
//! A `scn /P0` fill whose `/P0` is a `/PatternType 2` shading pattern
//! now paints the equivalent scene gradient instead of the conservative
//! black fallback. The reader resolves `/Resources /Pattern`, evaluates
//! the pattern's axial `/Shading` through the same machinery the `sh`
//! operator uses, and maps the shading axis into device space through
//! the pattern `/Matrix` composed with the CTM.
//!
//! A hand-built single-page PDF declares one shading pattern (an axial
//! black→white ramp along `[0 0 100 0]`) and fills one triangle with it.

use oxideav_core::vector::{Node, Paint};
use oxideav_pdf::read_pdf_to_scene;

fn build_shading_pattern_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 5] = [0; 5];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // /Pattern cs selects the Pattern colour space, /P0 scn the pattern.
    let content: &[u8] = b"/Pattern cs /P0 scn 0 0 m 100 0 l 100 100 l h f\n";

    // 3 = Page with an inline /Resources /Pattern /P0 = shading pattern.
    // The shading is an axial Type 2 over DeviceRGB with a Type 2
    // black→white function along the x axis.
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
          /Contents 4 0 R \
          /Resources << /Pattern << /P0 << \
            /Type /Pattern /PatternType 2 \
            /Shading << /ShadingType 2 /ColorSpace /DeviceRGB \
              /Coords [0 0 100 0] \
              /Function << /FunctionType 2 /Domain [0 1] \
                /C0 [0 0 0] /C1 [1 1 1] /N 1 >> \
            >> \
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

/// Recurse into the scene tree to find the first painted path's fill.
fn first_fill(node: &Node) -> Option<&Paint> {
    match node {
        Node::Path(p) => p.fill.as_ref(),
        Node::Group(g) => g.children.iter().find_map(first_fill),
        _ => None,
    }
}

#[test]
fn shading_pattern_fill_resolves_to_gradient() {
    let pdf = build_shading_pattern_pdf();
    assert!(pdf.len() <= 10 * 1024, "fixture under 10 KB");

    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let pages = scene.pages.as_ref().expect("scene has pages");
    assert_eq!(pages.len(), 1);

    let fill = pages[0]
        .content
        .root
        .children
        .iter()
        .find_map(first_fill)
        .expect("a painted path with a fill");
    let Paint::LinearGradient(lg) = fill else {
        panic!("expected a linear gradient fill, got {fill:?}");
    };
    // Axis [0 0 100 0] under identity CTM + no Matrix.
    assert!((lg.start.x - 0.0).abs() < 1e-2 && (lg.end.x - 100.0).abs() < 1e-2);
    assert!(!lg.stops.is_empty());
    // First stop black, last white.
    assert_eq!(
        (
            lg.stops[0].color.r,
            lg.stops[0].color.g,
            lg.stops[0].color.b
        ),
        (0, 0, 0)
    );
    let last = lg.stops.last().unwrap();
    assert_eq!((last.color.r, last.color.g, last.color.b), (255, 255, 255));
}
