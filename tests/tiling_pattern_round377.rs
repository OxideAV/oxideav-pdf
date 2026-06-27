//! Round-377 tiling-pattern fill end-to-end test (ISO 32000-1 §8.7.3
//! Tiling Patterns — `/PatternType 1`).
//!
//! A `scn /P0` fill whose `/P0` is a `/PatternType 1` *tiling* pattern
//! now replicates the pattern cell across the filled region instead of
//! the conservative black fallback. The reader resolves
//! `/Resources /Pattern`, decodes the cell content stream, parses it
//! against the pattern's own `/Resources`, and tiles the cell at integer
//! multiples of `/XStep` / `/YStep` (§8.7.3.1) within the fill region,
//! anchoring the lattice to page space through the pattern `/Matrix`
//! (§8.7.2 NOTE 1).
//!
//! The cell here is a 50×50 coloured (`/PaintType 1`) cell painting a
//! red square; a 100×100 fill region should therefore produce several
//! red-filled tiles.

use oxideav_core::vector::{Node, Paint, Rgba};
use oxideav_pdf::read_pdf_to_scene;

fn build_tiling_pattern_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 6] = [0; 6];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // Page content: select the Pattern colour space, install the tiling
    // pattern as the nonstroking colour, fill a 100×100 rectangle.
    let content: &[u8] = b"/Pattern cs /P0 scn 0 0 100 100 re f\n";

    // 3 = Page. /Resources /Pattern /P0 = a tiling pattern (object 5).
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
          /Contents 4 0 R \
          /Resources << /Pattern << /P0 5 0 R >> >> \
          >>\nendobj\n",
    );

    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // 5 = the /PatternType 1 tiling pattern. The cell paints a red
    // 40×40 square; BBox is 50×50, XStep = YStep = 50.
    let cell: &[u8] = b"1 0 0 rg 5 5 40 40 re f\n";
    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /Pattern /PatternType 1 /PaintType 1 /TilingType 1 \
             /BBox [0 0 50 50] /XStep 50 /YStep 50 \
             /Resources << >> /Length {} >>\nstream\n",
            cell.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(cell);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n");
    bytes.extend_from_slice(b"0 6\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1) {
        bytes.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    bytes.extend_from_slice(b"trailer\n");
    bytes.extend_from_slice(b"<< /Size 6 /Root 1 0 R >>\n");
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());

    bytes
}

/// Collect every solid fill colour painted anywhere in the node tree.
fn collect_solid_fills(node: &Node, out: &mut Vec<Rgba>) {
    match node {
        Node::Path(p) => {
            if let Some(Paint::Solid(c)) = &p.fill {
                out.push(*c);
            }
        }
        Node::Group(g) => {
            for c in &g.children {
                collect_solid_fills(c, out);
            }
        }
        _ => {}
    }
}

/// Count the number of `Node::Group` nodes anywhere in the tree (the
/// tiled cells are each a clipped group).
fn count_groups(node: &Node) -> usize {
    match node {
        Node::Group(g) => 1 + g.children.iter().map(count_groups).sum::<usize>(),
        _ => 0,
    }
}

#[test]
fn tiling_pattern_fill_replicates_cell() {
    let pdf = build_tiling_pattern_pdf();
    let scene = read_pdf_to_scene(&pdf).expect("read tiling-pattern PDF");
    let pages = scene.pages.as_ref().expect("scene has pages");
    let page = &pages[0];

    let mut fills = Vec::new();
    for node in &page.content.root.children {
        collect_solid_fills(node, &mut fills);
    }

    // The cell paints a red square; every painted tile should carry the
    // red fill from the cell content stream (PaintType 1, §8.7.3.2).
    let red = Rgba::opaque(0xFF, 0x00, 0x00);
    let red_count = fills.iter().filter(|c| **c == red).count();
    assert!(
        red_count >= 4,
        "expected the 50×50 cell tiled across the 100×100 region to paint \
         several red squares; got {red_count} red fills out of {} total",
        fills.len(),
    );

    // The black fallback (round-118) would have produced exactly one
    // black-filled path for the whole region; the tiling fill must NOT
    // leave a single black region fill behind.
    let black = Rgba::opaque(0x00, 0x00, 0x00);
    assert_eq!(
        fills.iter().filter(|c| **c == black).count(),
        0,
        "tiling fill must replace the conservative black region fill"
    );
}

#[test]
fn tiling_pattern_emits_clipped_tile_groups() {
    let pdf = build_tiling_pattern_pdf();
    let scene = read_pdf_to_scene(&pdf).expect("read tiling-pattern PDF");
    let pages = scene.pages.as_ref().expect("scene has pages");
    let page = &pages[0];

    let groups: usize = page.content.root.children.iter().map(count_groups).sum();
    assert!(
        groups >= 4,
        "the tiling fill should emit one clipped group per tile (plus the \
         region-clip wrapper); got {groups}"
    );
}

/// An *uncoloured* (`/PaintType 2`) tiling pattern (§8.7.3.3): the cell
/// content carries no colour and is poured with the underlying colour the
/// `scn` supplies (`0 0 1 /P0 scn` → blue). The `[/Pattern /DeviceRGB]`
/// colour space is selected via a `/Resources /ColorSpace` key.
fn build_uncoloured_tiling_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 6] = [0; 6];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // /Cs1 cs selects the [/Pattern /DeviceRGB] space; `0 0 1 /P0 scn`
    // installs the uncoloured pattern poured with blue.
    let content: &[u8] = b"/Cs1 cs 0 0 1 /P0 scn 0 0 100 100 re f\n";

    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
          /Contents 4 0 R \
          /Resources << \
            /ColorSpace << /Cs1 [ /Pattern /DeviceRGB ] >> \
            /Pattern << /P0 5 0 R >> \
          >> >>\nendobj\n",
    );

    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // The cell paints a 40×40 square with NO colour operator (uncoloured
    // — the fill colour is whatever is in force when the cell runs).
    let cell: &[u8] = b"5 5 40 40 re f\n";
    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /Pattern /PatternType 1 /PaintType 2 /TilingType 1 \
             /BBox [0 0 50 50] /XStep 50 /YStep 50 \
             /Resources << >> /Length {} >>\nstream\n",
            cell.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(cell);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n");
    bytes.extend_from_slice(b"0 6\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1) {
        bytes.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    bytes.extend_from_slice(b"trailer\n");
    bytes.extend_from_slice(b"<< /Size 6 /Root 1 0 R >>\n");
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());

    bytes
}

#[test]
fn uncoloured_tiling_pattern_pours_underlying_color() {
    let pdf = build_uncoloured_tiling_pdf();
    let scene = read_pdf_to_scene(&pdf).expect("read uncoloured tiling-pattern PDF");
    let pages = scene.pages.as_ref().expect("scene has pages");
    let page = &pages[0];

    let mut fills = Vec::new();
    for node in &page.content.root.children {
        collect_solid_fills(node, &mut fills);
    }

    // Every tile's stencil square must be poured with the supplied blue,
    // not black (the cell carried no colour of its own).
    let blue = Rgba::opaque(0x00, 0x00, 0xFF);
    let blue_count = fills.iter().filter(|c| **c == blue).count();
    assert!(
        blue_count >= 4,
        "expected the uncoloured cell tiled across the region to be poured \
         with blue; got {blue_count} blue fills out of {} total",
        fills.len(),
    );
    let black = Rgba::opaque(0x00, 0x00, 0x00);
    assert_eq!(
        fills.iter().filter(|c| **c == black).count(),
        0,
        "an uncoloured tiling pour must not leave black fills"
    );
}
