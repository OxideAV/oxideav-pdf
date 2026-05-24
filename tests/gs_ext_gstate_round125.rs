//! Round-125 `gs` ExtGState resolution end-to-end test
//! (ISO 32000-1 §8.4.5 + Table 57 + Table 58).
//!
//! A hand-built single-page PDF carries a `/Resources /ExtGState`
//! dictionary with one parameter dict (`/GS1`) holding the round-125
//! Table-58 subset the reader honours: line width (`LW`), line cap
//! (`LC`), line join (`LJ`), miter limit (`ML`), dash pattern (`D`),
//! stroking alpha (`CA`), and nonstroking alpha (`ca`). The page's
//! content stream:
//!
//! ```text
//! q
//!     /GS1 gs        % applies LW/LC/LJ/ML/D/CA/ca cumulatively
//!     1 0 0 RG       % stroke red (which CA = 0.5 then halves)
//!     1 1 0 rg       % fill yellow (which ca = 0.25 then quarters)
//!     0 0 m  10 10 l h B
//! Q
//! ```
//!
//! Round-trip through [`read_pdf_to_scene`] surfaces a single
//! [`PathNode`] whose [`Stroke`] reflects every Table-58 value the
//! reader applied (width, cap, join, miter, dash, alpha) and whose
//! fill colour carries the nonstroking alpha multiplier.
//!
//! Fixture: hand-built in `build_gs_pdf` — under 1 KB. A copy is
//! committed at `tests/fixtures/gs_ext_gstate.pdf` and the two byte
//! sequences are required to match (`fixture_round_trips`), the same
//! discipline the round-122 hybrid-xrefstm test follows.

use oxideav_core::vector::{LineCap, LineJoin, Node, Paint};
use oxideav_pdf::objects::{Dict, Object};
use oxideav_pdf::read_pdf_to_scene;
use oxideav_pdf::reader::content::parse_content_stream_with_resources;
use oxideav_pdf::reader::DocumentReader;

/// Build the same `/Resources /ExtGState` + `gs`-using PDF that lives
/// at `tests/fixtures/gs_ext_gstate.pdf`. Kept byte-stable so the
/// fixture-vs-builder check has a single source of truth.
fn build_gs_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 6] = [0; 6];

    // 1 = Catalog
    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    // 2 = Pages
    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // 4 = Content stream. Build it first so we know its /Length before
    // emitting the stream wrapper.
    //
    // The stream sets a Table-58 `gs` against /GS1 inside a single q/Q
    // bracket, then strokes + fills a triangle so both alpha constants
    // are exercised on the same painted node.
    let content: &[u8] = b"q /GS1 gs 1 0 0 RG 1 1 0 rg 0 0 m 10 10 l 10 0 l h B Q\n";

    // 5 = ExtGState parameter dict (referenced from /Resources). This
    // is the dict the reader walks per Table 58. Order: LW LC LJ ML D
    // CA ca — every honoured key in one parameter dictionary so the
    // test exercises the cumulative-merge path in a single `gs` call.
    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"5 0 obj\n<< /Type /ExtGState \
          /LW 4.5 \
          /LC 1 \
          /LJ 2 \
          /ML 7.5 \
          /D [[5 2] 1] \
          /CA 0.5 \
          /ca 0.25 \
          >>\nendobj\n",
    );

    // 3 = Page. /Resources carries an inline /ExtGState dict with
    // /GS1 pointing at object 5 (an indirect reference so the reader
    // is forced through `resolve_ext_gstate`'s indirect-dereference
    // path, not just the inline-dict shortcut).
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
          /Contents 4 0 R \
          /Resources << /ExtGState << /GS1 5 0 R >> >> \
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
    bytes.extend_from_slice(b"0 6\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    bytes.extend_from_slice(format!("{:010} 00000 n \n", offsets[1]).as_bytes());
    bytes.extend_from_slice(format!("{:010} 00000 n \n", offsets[2]).as_bytes());
    bytes.extend_from_slice(format!("{:010} 00000 n \n", offsets[3]).as_bytes());
    bytes.extend_from_slice(format!("{:010} 00000 n \n", offsets[4]).as_bytes());
    bytes.extend_from_slice(format!("{:010} 00000 n \n", offsets[5]).as_bytes());
    bytes.extend_from_slice(b"trailer\n");
    bytes.extend_from_slice(b"<< /Size 6 /Root 1 0 R >>\n");
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());

    bytes
}

#[test]
fn fixture_round_trips_in_memory_and_on_disk() {
    let mem = build_gs_pdf();
    let disk = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/gs_ext_gstate.pdf"
    ))
    .expect("checked-in gs_ext_gstate.pdf fixture");
    assert_eq!(
        mem, disk,
        "in-memory builder must produce the same bytes as the committed fixture"
    );
    // Round 125's hand-built fixture stays well under the per-fixture
    // 10 KB ceiling the round prompt sets.
    assert!(
        disk.len() <= 10 * 1024,
        "fixture must fit ≤10 KB ({} bytes)",
        disk.len()
    );
}

/// End-to-end: parse the PDF, walk the catalog → pages → contents +
/// resources, and verify every honoured Table-58 entry reaches the
/// painted node.
#[test]
fn gs_ext_gstate_lands_lw_lc_lj_ml_d_ca_ca() {
    let pdf = build_gs_pdf();
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");

    let pages = scene.pages.as_ref().expect("scene has pages");
    assert_eq!(pages.len(), 1);
    let page = &pages[0];

    // The content stream is `q /GS1 gs … 0 0 m 10 10 l 10 0 l h B Q`
    // — exactly one painted triangle inside one q/Q group.
    let root = &page.content.root;
    assert_eq!(root.children.len(), 1, "one nested group");
    let Node::Group(g) = &root.children[0] else {
        panic!("expected nested group node");
    };
    assert_eq!(g.children.len(), 1, "one painted path");
    let Node::Path(pn) = &g.children[0] else {
        panic!("expected painted path");
    };

    // Stroke: LW=4.5, LC=Round, LJ=Bevel, ML=7.5, D=[[5,2] 1], CA=0.5.
    let s = pn.stroke.as_ref().expect("path is stroked (B operator)");
    assert!((s.width - 4.5).abs() < 1e-3, "LW=4.5 (got {})", s.width);
    assert!(matches!(s.cap, LineCap::Round), "LC=1 → Round");
    assert!(matches!(s.join, LineJoin::Bevel), "LJ=2 → Bevel");
    assert!(
        (s.miter_limit - 7.5).abs() < 1e-3,
        "ML=7.5 (got {})",
        s.miter_limit
    );
    let dash = s.dash.as_ref().expect("D set");
    assert_eq!(dash.array, vec![5.0, 2.0], "D = [[5 2] 1]");
    assert!((dash.offset - 1.0).abs() < 1e-3, "D phase = 1");

    // CA=0.5 halves the stroke alpha (255 → 128). RGB stays the red
    // the `1 0 0 RG` set.
    let Paint::Solid(sc) = &s.paint else {
        panic!("solid stroke expected");
    };
    assert_eq!((sc.r, sc.g, sc.b), (255, 0, 0), "stroke red");
    assert_eq!(sc.a, 128, "CA=0.5 → α=128");

    // ca=0.25 quarters the nonstroking alpha (255 → 64). RGB stays
    // the yellow the `1 1 0 rg` set.
    let Some(Paint::Solid(fc)) = &pn.fill else {
        panic!("solid fill expected (B fills then strokes)");
    };
    assert_eq!((fc.r, fc.g, fc.b), (255, 255, 0), "fill yellow");
    assert_eq!(fc.a, 64, "ca=0.25 → α=64");
}

/// Sanity-check the content-stream parser at the unit level too: even
/// with the resources dict in hand the dispatch table is the same one
/// the doc walker uses, so a stand-alone parse_with_resources call on
/// a `gs`-only snippet must produce the same stroke/fill state.
#[test]
fn parse_content_stream_with_resources_honours_table_58() {
    let mut ext = Dict::new();
    ext.set(
        "GS1",
        Object::Dict(
            Dict::new()
                .with("LW", Object::Real(4.5))
                .with("LC", Object::Integer(1))
                .with("LJ", Object::Integer(2))
                .with("ML", Object::Real(7.5))
                .with(
                    "D",
                    Object::Array(vec![
                        Object::Array(vec![Object::Real(5.0), Object::Real(2.0)]),
                        Object::Real(1.0),
                    ]),
                )
                .with("CA", Object::Real(0.5))
                .with("ca", Object::Real(0.25)),
        ),
    );
    let bytes = b"q /GS1 gs 1 0 0 RG 1 1 0 rg 0 0 m 10 10 l 10 0 l h B Q\n";
    let root =
        parse_content_stream_with_resources(bytes, Some(&ext)).expect("parse with ExtGState");
    let Node::Group(g) = &root.children[0] else {
        panic!()
    };
    let Node::Path(p) = &g.children[0] else {
        panic!()
    };
    let s = p.stroke.as_ref().expect("stroke");
    assert!((s.width - 4.5).abs() < 1e-3);
    let Paint::Solid(sc) = &s.paint else { panic!() };
    assert_eq!(sc.a, 128);
    let Some(Paint::Solid(fc)) = &p.fill else {
        panic!()
    };
    assert_eq!(fc.a, 64);
}

/// A `gs` against an undefined ExtGState name (or with no
/// `/Resources /ExtGState` dict at all) is a tolerated no-op — the
/// preceding `2.5 w` stroke width still wins.
#[test]
fn gs_without_matching_ext_gstate_is_no_op() {
    // PDF with /Resources but no /ExtGState — `gs` must drop silently.
    let mut bytes: Vec<u8> = Vec::with_capacity(512);
    bytes.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: [u64; 5] = [0; 5];
    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
          /Contents 4 0 R /Resources << >> >>\nendobj\n",
    );
    let content = b"q 2.5 w /GS_MISSING gs 0 0 m 10 10 l S Q\n";
    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");
    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n0 5\n0000000000 65535 f \n");
    for off in offsets.iter().skip(1) {
        bytes.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    bytes.extend_from_slice(b"trailer\n<< /Size 5 /Root 1 0 R >>\n");
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());

    let scene = read_pdf_to_scene(&bytes).expect("parse no-ExtGState PDF");
    let page = &scene.pages.as_ref().unwrap()[0];
    let Node::Group(g) = &page.content.root.children[0] else {
        panic!()
    };
    let Node::Path(p) = &g.children[0] else {
        panic!()
    };
    let s = p.stroke.as_ref().expect("stroke");
    // The bare `2.5 w` set the width — gs against the missing name
    // didn't reset it.
    assert!((s.width - 2.5).abs() < 1e-3);
}

/// Confirm the [`DocumentReader`] surface is the same one walking the
/// ExtGState resolution path (the public reader-state entry — not just
/// the `read_pdf_to_scene` free-function shortcut).
#[test]
fn document_reader_open_succeeds_on_gs_pdf() {
    let pdf = build_gs_pdf();
    let _r = DocumentReader::open(&pdf).expect("DocumentReader::open on /gs fixture");
}
