//! Single-page rectangle path → PDF round-trip.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathNode, Point, Rgba, VectorFrame,
};

#[test]
fn single_rect_emits_valid_pdf_envelope() {
    let mut p = Path::new();
    p.move_to(Point::new(10.0, 10.0))
        .line_to(Point::new(110.0, 10.0))
        .line_to(Point::new(110.0, 60.0))
        .line_to(Point::new(10.0, 60.0))
        .close();

    let frame = VectorFrame {
        width: 200.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(255, 128, 0))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };

    let bytes = oxideav_pdf::write_pdf(&frame).expect("write_pdf");

    // Header / trailer envelope -----------------------------------
    assert!(bytes.starts_with(b"%PDF-1.4\n"));
    assert!(bytes.ends_with(b"%%EOF\n"));
    assert!(contains(&bytes, b"\nxref\n"));
    assert!(contains(&bytes, b"\ntrailer\n"));
    assert!(contains(&bytes, b"\nstartxref\n"));

    // Catalog / Pages tree ----------------------------------------
    assert!(contains(&bytes, b"/Type /Catalog"));
    assert!(contains(&bytes, b"/Type /Pages"));
    assert!(contains(&bytes, b"/Type /Page"));

    // MediaBox should reflect the 200 × 100 frame -----------------
    assert!(contains(&bytes, b"/MediaBox [0 0 200 100]"));

    // Path operators in order: m → l → l → l → h → f --------------
    let s = std::str::from_utf8(&bytes).expect("valid utf-8");
    let m_pos = s.find(" m\n").expect("m operator");
    // Between the first `m` and the `h`, there should be at least
    // three `l` operators.
    let h_pos = s.find("h\n").expect("h operator");
    assert!(m_pos < h_pos);
    let segment = &s[m_pos..h_pos];
    let l_count = segment.matches(" l\n").count();
    assert!(
        l_count >= 3,
        "expected ≥3 l operators between m and h, got {l_count}"
    );
    // Fill rule defaults to non-zero → `f` (not `f*`).
    assert!(s.contains("\nf\n"));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
