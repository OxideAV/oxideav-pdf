//! Round-275 `/Resources /ColorSpace` resolution end-to-end test
//! (ISO 32000-1 §8.6.8 Table 74 + §8.6.5.5 ICCBased + §8.6.6.3 Indexed).
//!
//! Before round 275 the content-stream parser resolved only the device
//! colour-space *names* (`/DeviceGray` / `/DeviceRGB` / `/DeviceCMYK`)
//! in a `cs` / `CS` operator; any `cs` naming a `/Resources /ColorSpace`
//! key collapsed to `Unknown` and the following `sc`/`scn` fell back to
//! black. This round plumbs the page's resolved `/Resources /ColorSpace`
//! subdictionary into the parser and reduces two non-CIE families to a
//! device fallback:
//!
//! * **ICCBased** (§8.6.5.5) — `/Alternate` device space if present,
//!   else `/N` (1/3/4) → DeviceGray / DeviceRGB / DeviceCMYK. The ICC
//!   profile bytes themselves are never interpreted.
//! * **Indexed** (§8.6.6.3) — a single index component selects an
//!   `m`-byte entry from the colour table, scaled `0..255` → the base
//!   device component range.
//!
//! A hand-built single-page PDF carries:
//!
//! * Object 5: an ICCBased profile *stream* (`/N 3`, no `/Alternate`)
//!   referenced as `[/ICCBased 5 0 R]` from `/CS0`. The reader resolves
//!   the stream → its dict → DeviceRGB.
//! * Object 6: an Indexed lookup *stream* (the PDF 1.2 stream form,
//!   FlateDecode-able but here stored raw) carrying three RGB entries;
//!   referenced as `[/Indexed /DeviceRGB 2 6 0 R]` from `/CS1`.
//!
//! The content stream paints two triangles: the first fills via
//! `/CS0 cs 1 0 0 sc` (ICCBased→DeviceRGB red), the second via
//! `/CS1 cs 1 sc` (Indexed entry 1 = green).

use oxideav_core::vector::{Node, Paint};
use oxideav_pdf::read_pdf_to_scene;

/// Build the round-275 `/Resources /ColorSpace` fixture in memory. Both
/// resource colour spaces reference an *indirect stream* so the reader
/// is forced through `resolve_color_space_resources`'s
/// stream-dereference path (not just an inline-array shortcut).
fn build_color_space_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 7] = [0; 7];

    // 1 = Catalog
    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    // 2 = Pages
    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // First triangle: ICCBased(N=3)→DeviceRGB red.
    // Second triangle: Indexed entry 1 → green.
    let content: &[u8] = b"/CS0 cs 1 0 0 sc 0 0 m 10 10 l 10 0 l h f \
                           /CS1 cs 1 sc 20 0 m 30 10 l 30 0 l h f\n";

    // 5 = ICCBased profile stream. `/N 3` (no /Alternate) → DeviceRGB.
    // The stream body is a dummy profile placeholder — never parsed.
    offsets[5] = bytes.len() as u64;
    let icc_body: &[u8] = b"ICCPROFILEDUMMYBYTES";
    bytes.extend_from_slice(
        format!("5 0 obj\n<< /N 3 /Length {} >>\nstream\n", icc_body.len()).as_bytes(),
    );
    bytes.extend_from_slice(icc_body);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // 6 = Indexed lookup stream: 3 RGB entries (hival 2).
    //   entry 0 = black, entry 1 = green, entry 2 = blue.
    offsets[6] = bytes.len() as u64;
    let lookup: [u8; 9] = [
        0x00, 0x00, 0x00, // 0 black
        0x00, 0xFF, 0x00, // 1 green
        0x00, 0x00, 0xFF, // 2 blue
    ];
    bytes
        .extend_from_slice(format!("6 0 obj\n<< /Length {} >>\nstream\n", lookup.len()).as_bytes());
    bytes.extend_from_slice(&lookup);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // 3 = Page. /Resources /ColorSpace maps /CS0 → ICCBased array and
    // /CS1 → Indexed array, both referencing the streams indirectly.
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
          /Contents 4 0 R \
          /Resources << /ColorSpace << \
            /CS0 [/ICCBased 5 0 R] \
            /CS1 [/Indexed /DeviceRGB 2 6 0 R] \
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
    bytes.extend_from_slice(b"0 7\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1) {
        bytes.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    bytes.extend_from_slice(b"trailer\n");
    bytes.extend_from_slice(b"<< /Size 7 /Root 1 0 R >>\n");
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
fn icc_based_and_indexed_resource_colour_spaces_resolve() {
    let pdf = build_color_space_pdf();
    assert!(pdf.len() <= 10 * 1024, "fixture under 10 KB");

    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let pages = scene.pages.as_ref().expect("scene has pages");
    assert_eq!(pages.len(), 1);

    let root = &pages[0].content.root;
    // Two painted triangles at the content stream's top level (no q/Q).
    assert_eq!(root.children.len(), 2, "two painted paths");

    // First: /CS0 (ICCBased N=3 → DeviceRGB) `1 0 0 sc` → red.
    assert_eq!(fill_rgb(&root.children[0]), (255, 0, 0), "ICCBased red");

    // Second: /CS1 (Indexed /DeviceRGB) `1 sc` → entry 1 = green.
    assert_eq!(fill_rgb(&root.children[1]), (0, 255, 0), "Indexed green");
}
