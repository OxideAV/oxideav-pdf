//! Round-381 — Type 3 font glyph painting into the Scene (§9.6.5).
//!
//! Unlike Type 1 / TrueType fonts (whose outlines live in an external
//! font program a software renderer must rasterise), a Type 3 font's
//! glyphs are themselves *content streams* of PDF graphics operators
//! (`/CharProcs`). The reader therefore paints each shown glyph as
//! vector geometry: it resolves the character code through `/Encoding`
//! (`/Differences`) to a glyph name (§9.6.6.1), looks the name up in
//! `/CharProcs` to get the glyph-description stream (§9.6.5 step a–b),
//! and splices the parsed geometry into the scene tree under the glyph's
//! text-rendering matrix — the concatenation of the text space in force
//! and the font's `/FontMatrix` (§9.4.4 / §9.6.5 step c).
//!
//! The font here is the two-glyph example from ISO 32000-1:2008 §9.6.5
//! (a filled square `/square` and a filled triangle `/triangle`,
//! selected by codes 97/98). Showing the string `(ab)` at a `Td` origin
//! must produce two spliced glyph groups whose transforms place the
//! 750-unit glyph-space marks at the right page coordinates.
//!
//! Provenance: ISO 32000-1:2008 §9.6.5 (Type 3 Fonts — including the
//! worked example and Table 113 `d0` / `d1`), §9.4.4 (Text Space
//! Details), §9.6.6.1 (Character Encoding). PDF bytes are hand-assembled
//! here; no third-party PDF library was consulted.

use oxideav_core::vector::{Node, PathCommand, Point};
use oxideav_pdf::read_pdf_to_scene;

/// Assemble a one-page PDF whose single Type 3 font is the §9.6.5 example
/// (square + triangle), shown via `content` against a `/F0` resource.
/// `font_matrix` and the d0/d1 leading operator of each glyph are
/// parameterised so individual tests can probe the matrix scale and the
/// shape-only (`d1`) vs. self-coloured (`d0`) split.
fn build_type3_glyph_pdf(content: &[u8], font_matrix: &str) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut offs: Vec<usize> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    offs.push(buf.len());
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offs.push(buf.len());
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");

    offs.push(buf.len());
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
          /Resources << /Font << /F0 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
    );

    // 4 = the Type 3 font dict (§9.6.5 example).
    offs.push(buf.len());
    let font = format!(
        "4 0 obj\n<< /Type /Font /Subtype /Type3 /FontBBox [0 0 750 750] \
         /FontMatrix {font_matrix} /CharProcs 6 0 R \
         /Encoding << /Type /Encoding /Differences [97 /square /triangle] >> \
         /FirstChar 97 /LastChar 98 /Widths [1000 1000] >>\nendobj\n"
    );
    buf.extend_from_slice(font.as_bytes());

    // 5 = the page content stream — show "ab" at (100,700), size 12.
    offs.push(buf.len());
    let header = format!("5 0 obj\n<< /Length {} >>\nstream\n", content.len());
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    // 6 = /CharProcs dict.
    offs.push(buf.len());
    buf.extend_from_slice(b"6 0 obj\n<< /square 7 0 R /triangle 8 0 R >>\nendobj\n");

    // 7 = /square glyph description: a 750×750 filled square (d1 — shape
    // only, the §9.6.5 example uses d1).
    let square: &[u8] = b"1000 0 0 0 750 750 d1\n0 0 750 750 re\nf\n";
    offs.push(buf.len());
    buf.extend_from_slice(format!("7 0 obj\n<< /Length {} >>\nstream\n", square.len()).as_bytes());
    buf.extend_from_slice(square);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    // 8 = /triangle glyph description (d1 — shape only).
    let triangle: &[u8] = b"1000 0 0 0 750 750 d1\n0 0 m\n375 750 l\n750 0 l\nf\n";
    offs.push(buf.len());
    buf.extend_from_slice(
        format!("8 0 obj\n<< /Length {} >>\nstream\n", triangle.len()).as_bytes(),
    );
    buf.extend_from_slice(triangle);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    // xref + trailer (objects 1..=8).
    let xref_off = buf.len();
    let count = offs.len() + 1; // + free object 0
    buf.extend_from_slice(format!("xref\n0 {count}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for o in &offs {
        buf.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n")
            .as_bytes(),
    );
    buf
}

/// Recursively gather every `MoveTo` / `LineTo` path point in the tree,
/// after applying each enclosing group's transform — so a glyph painted
/// in 750-unit glyph space surfaces here in page coordinates.
fn gather_points(node: &Node, ctm: oxideav_core::vector::Transform2D, out: &mut Vec<Point>) {
    match node {
        Node::Path(p) => {
            for cmd in &p.path.commands {
                let pt = match cmd {
                    PathCommand::MoveTo(pt) | PathCommand::LineTo(pt) => *pt,
                    _ => continue,
                };
                out.push(ctm.apply(pt));
            }
        }
        Node::Group(g) => {
            let next = ctm.compose(&g.transform);
            for c in &g.children {
                gather_points(c, next, out);
            }
        }
        _ => {}
    }
}

/// Count the number of `Node::Group` nodes anywhere in the tree.
fn count_groups(node: &Node) -> usize {
    match node {
        Node::Group(g) => 1 + g.children.iter().map(count_groups).sum::<usize>(),
        _ => 0,
    }
}

fn point_near(points: &[Point], x: f32, y: f32) -> bool {
    points
        .iter()
        .any(|p| (p.x - x).abs() < 1e-2 && (p.y - y).abs() < 1e-2)
}

/// Showing `(ab)` with the §9.6.5 example font splices two glyph groups,
/// and the square glyph's 750-unit corner lands at the page coordinate
/// the text-rendering matrix dictates.
#[test]
fn type3_glyphs_paint_into_scene() {
    // size 12, FontMatrix 0.001 → glyph scale 0.012. Td origin (100,700).
    let content = b"BT /F0 12 Tf 100 700 Td (ab) Tj ET";
    let pdf = build_type3_glyph_pdf(content, "[0.001 0 0 0.001 0 0]");
    let scene = read_pdf_to_scene(&pdf).expect("read Type 3 PDF");
    let pages = scene.pages.as_ref().expect("scene has pages");
    let page = &pages[0];

    // Two glyph groups must have been spliced (plus possibly wrappers).
    let groups: usize = page.content.root.children.iter().map(count_groups).sum();
    assert!(
        groups >= 2,
        "expected at least two spliced Type 3 glyph groups; got {groups}"
    );

    let id = oxideav_core::vector::Transform2D::identity();
    let mut points = Vec::new();
    for n in &page.content.root.children {
        gather_points(n, id, &mut points);
    }
    assert!(
        !points.is_empty(),
        "Type 3 glyphs must paint path geometry into the scene"
    );

    // The square glyph 'a' (first show): glyph-space corner (0,0) → page
    // (100, 700); corner (750,750) → (100 + 750·0.012, 700 + 750·0.012)
    // = (109, 709).
    assert!(
        point_near(&points, 100.0, 700.0),
        "square's (0,0) corner should land at the text origin (100,700)"
    );
    assert!(
        point_near(&points, 109.0, 709.0),
        "square's (750,750) corner should land at (109,709); got {points:?}"
    );

    // The triangle glyph 'b' is shown after 'a' advances by its width:
    // width 1000 · FontMatrix 0.001 · size 12 = 12 → x origin = 112.
    // Its apex (375,750) → (112 + 375·0.012, 700 + 750·0.012)
    // = (116.5, 709).
    assert!(
        point_near(&points, 116.5, 709.0),
        "triangle apex should land at (116.5,709); got {points:?}"
    );
}

/// A larger `/FontMatrix` horizontal scale enlarges the painted glyph in
/// page space by the same factor — the §9.6.5 glyph-space-to-text-space
/// mapping is honoured at paint time, not just for the width advance.
#[test]
fn type3_glyph_paint_scales_with_font_matrix() {
    // FontMatrix 0.01 (ten times the default), size 12 → glyph scale 0.12.
    let content = b"BT /F0 12 Tf 100 700 Td (a) Tj ET";
    let pdf = build_type3_glyph_pdf(content, "[0.01 0 0 0.01 0 0]");
    let scene = read_pdf_to_scene(&pdf).expect("read Type 3 PDF");
    let pages = scene.pages.as_ref().expect("scene has pages");
    let page = &pages[0];

    let id = oxideav_core::vector::Transform2D::identity();
    let mut points = Vec::new();
    for n in &page.content.root.children {
        gather_points(n, id, &mut points);
    }
    // (750,750) → (100 + 750·0.12, 700 + 750·0.12) = (190, 790).
    assert!(
        point_near(&points, 190.0, 790.0),
        "with FontMatrix 0.01 the square's far corner should reach (190,790); got {points:?}"
    );
}

/// Text render mode 3 (invisible — the OCR layer, §9.3.6) suppresses
/// Type 3 glyph painting: no geometry should reach the scene.
#[test]
fn type3_invisible_mode_paints_nothing() {
    let content = b"BT /F0 12 Tf 3 Tr 100 700 Td (ab) Tj ET";
    let pdf = build_type3_glyph_pdf(content, "[0.001 0 0 0.001 0 0]");
    let scene = read_pdf_to_scene(&pdf).expect("read Type 3 PDF");
    let pages = scene.pages.as_ref().expect("scene has pages");
    let page = &pages[0];

    let id = oxideav_core::vector::Transform2D::identity();
    let mut points = Vec::new();
    for n in &page.content.root.children {
        gather_points(n, id, &mut points);
    }
    assert!(
        points.is_empty(),
        "invisible text-render mode 3 must paint no Type 3 glyph geometry; got {points:?}"
    );
}
