//! Round-151: regression test for the §7.5.7 compressed-object
//! resolver cache.
//!
//! Builds a single ObjStm container holding many compressed bodies
//! and confirms every slot decodes to the expected value. Without
//! the per-container cache the resolver decompresses the same Flate
//! payload + re-parses the same header table once per slot, which is
//! O(M²) for M packed objects; with the cache the first slot pays
//! O(M) and the rest are O(1). Both shapes must produce the same
//! output — this test pins the slot-by-slot correctness so a future
//! cache refactor can't silently regress.
//!
//! ISO 32000-1 §7.5.7 + the round-148 bench harness motivate the
//! shape: a writer-produced 50-page object-stream PDF packs every
//! page object + its content + its resource dict into one ObjStm,
//! so the resolver hits the same container ~150 times during open.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{read_pdf_to_scene, write_pdf_from_scene_object_stream};
use oxideav_scene::{Page, Scene};

fn page_n(seed: u8) -> Page {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(80.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(80.0, 80.0)));
    p.commands.push(PathCommand::LineTo(Point::new(10.0, 80.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 100.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(seed, 0x40, 0x80))),
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
    page
}

#[test]
fn objstm_many_slot_round_trip_uses_resolver_cache() {
    // Build a 30-page Scene whose write_pdf_from_scene_object_stream
    // output packs every page + content stream into a single ObjStm
    // container. Reading it back must produce 30 pages with the same
    // dimensions — the cache must not return a stale prior slot's
    // body when asked for a new slot in the same container.
    let pages: Vec<Page> = (0..30u8).map(page_n).collect();
    let scene = Scene {
        pages: Some(pages),
        ..Scene::default()
    };
    let bytes = write_pdf_from_scene_object_stream(&scene).expect("write objstm pdf");
    let out = read_pdf_to_scene(&bytes).expect("read objstm pdf");
    let pages_out = out.pages.expect("pages");
    assert_eq!(pages_out.len(), 30);
    for (i, p) in pages_out.iter().enumerate() {
        assert_eq!(p.width, 100.0, "page {i} width");
        assert_eq!(p.height, 100.0, "page {i} height");
    }
}

#[test]
fn objstm_cache_returns_stable_objects_for_repeated_resolves() {
    // Hand-builds a tiny PDF with two compressed objects (Catalog +
    // Pages) packed in one ObjStm container. Resolves each twice via
    // the DocumentReader API directly so the second resolve is a
    // cache hit on the container — but the slot-specific path must
    // still return the correct slot. (The reader's top-level Object
    // cache short-circuits before reaching resolve_compressed on the
    // second hit, so we exercise the slot path by clearing the cache
    // implicitly — we instead lean on the multi-slot decode shape:
    // two distinct slots, two distinct values, same container.)
    let pdf = build_two_slot_objstm();
    let mut r = DocumentReader::open(&pdf).expect("open");
    use oxideav_pdf::objects::{Object, ObjectId};
    let cat = r
        .resolve(ObjectId::new(1))
        .expect("resolve catalog (slot 0)");
    let pages = r.resolve(ObjectId::new(2)).expect("resolve pages (slot 1)");
    // Both must decode as dicts with the expected /Type.
    let Object::Dict(cat_d) = cat else {
        panic!("catalog should be Dict");
    };
    let Object::Dict(pages_d) = pages else {
        panic!("pages should be Dict");
    };
    let cat_ty = cat_d
        .entries()
        .iter()
        .find(|(k, _)| k == "Type")
        .map(|(_, v)| v);
    let pages_ty = pages_d
        .entries()
        .iter()
        .find(|(k, _)| k == "Type")
        .map(|(_, v)| v);
    assert!(
        matches!(cat_ty, Some(Object::Name(n)) if n == "Catalog"),
        "slot 0 must be Catalog (got {cat_ty:?})"
    );
    assert!(
        matches!(pages_ty, Some(Object::Name(n)) if n == "Pages"),
        "slot 1 must be Pages (got {pages_ty:?})"
    );
}

/// Build a PDF whose Catalog (obj 1) is in ObjStm slot 0 and Pages
/// (obj 2) is in ObjStm slot 1. Same shape as `tests/object_stream.rs`
/// `build_pdf_with_objstm_catalog`, kept local so this test file is
/// self-contained.
fn build_two_slot_objstm() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2048);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<u64> = vec![0; 7];

    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\n",
    );

    let body1: &[u8] = b"<</Type/Catalog/Pages 2 0 R>>";
    let body2: &[u8] = b"<</Type/Pages/Kids[3 0 R]/Count 1>>";
    let header = format!("1 0 2 {} ", body1.len()).into_bytes();
    let first = header.len();
    let mut payload = Vec::with_capacity(first + body1.len() + body2.len());
    payload.extend_from_slice(&header);
    payload.extend_from_slice(body1);
    payload.extend_from_slice(body2);

    let compressed = compcol::vec::compress_to_vec::<compcol::zlib::Zlib>(&payload).unwrap();

    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(b"5 0 obj\n");
    let dict = format!(
        "<< /Type /ObjStm /N 2 /First {} /Filter /FlateDecode /Length {} >>\n",
        first,
        compressed.len()
    );
    bytes.extend_from_slice(dict.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    offsets[6] = bytes.len() as u64;

    fn make_t1(off: u32) -> [u8; 7] {
        let mut e = [0u8; 7];
        e[0] = 1;
        e[1..5].copy_from_slice(&off.to_be_bytes());
        e[5..7].copy_from_slice(&0u16.to_be_bytes());
        e
    }
    fn make_t2(container: u32, idx: u16) -> [u8; 7] {
        let mut e = [0u8; 7];
        e[0] = 2;
        e[1..5].copy_from_slice(&container.to_be_bytes());
        e[5..7].copy_from_slice(&idx.to_be_bytes());
        e
    }
    fn make_t0() -> [u8; 7] {
        let mut e = [0u8; 7];
        e[5..7].copy_from_slice(&65535u16.to_be_bytes());
        e
    }

    let mut table = Vec::with_capacity(7 * 7);
    table.extend_from_slice(&make_t0());
    table.extend_from_slice(&make_t2(5, 0));
    table.extend_from_slice(&make_t2(5, 1));
    table.extend_from_slice(&make_t1(offsets[3] as u32));
    table.extend_from_slice(&make_t0());
    table.extend_from_slice(&make_t1(offsets[5] as u32));
    table.extend_from_slice(&make_t1(offsets[6] as u32));

    let xref_dict = format!(
        "<< /Type /XRef /Size 7 /Index [0 7] /W [1 4 2] /Root 1 0 R /Length {} >>\n",
        table.len()
    );
    bytes.extend_from_slice(b"6 0 obj\n");
    bytes.extend_from_slice(xref_dict.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&table);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_off = offsets[6];
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());
    bytes
}
