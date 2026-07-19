//! Round-418 — shared §7.9.6 name-tree / §7.9.7 number-tree walkers.
//!
//! Builds a document carrying a two-level name tree (root `/Kids` →
//! one leaf + one intermediate → leaf, each with `/Limits`) and a
//! number tree, then exercises:
//!
//! * `name_tree_entries` — full enumeration across levels;
//! * `name_tree_lookup` — `/Limits`-guided descent, including a miss
//!   that the limits prune before any leaf is touched;
//! * `number_tree_entries` — integer keys in tree order;
//! * tolerance — a malformed kid entry is skipped, not fatal.
//!
//! Provenance: ISO 32000-1:2008 §7.9.6 (Tables 36) + §7.9.7
//! (Table 37), including the chemical-elements shape of the §7.9.6
//! example (root → intermediate → leaf with Limits at every non-root
//! node).

use oxideav_pdf::objects::{Object, ObjectId};
use oxideav_pdf::reader::{
    name_tree_entries, name_tree_lookup, number_tree_entries, DocumentReader,
};

/// Assemble a classic-xref PDF from `(object_number, body)` pairs.
fn build_pdf(objects: &[(u32, &str)]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let max_id = objects.iter().map(|(n, _)| *n).max().unwrap_or(0);
    let mut offsets = vec![0u64; (max_id + 1) as usize];
    for (num, body) in objects {
        offsets[*num as usize] = bytes.len() as u64;
        bytes.extend_from_slice(format!("{num} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(format!("xref\n0 {}\n", max_id + 1).as_bytes());
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets[1..] {
        bytes.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    bytes
        .extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\n", max_id + 1).as_bytes());
    bytes.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    bytes
}

/// Document skeleton + a two-level name tree at object 4 and a number
/// tree at object 8.
fn fixture() -> Vec<u8> {
    build_pdf(&[
        (1, "<< /Type /Catalog /Pages 2 0 R >>"),
        (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>"),
        // Name tree: root → [leaf 5, intermediate 6 → leaf 7].
        (4, "<< /Kids [5 0 R 6 0 R] >>"),
        (
            5,
            "<< /Limits [(alpha) (beta)] /Names [(alpha) 10 (beta) 20] >>",
        ),
        (6, "<< /Limits [(delta) (zeta)] /Kids [7 0 R] >>"),
        (
            7,
            "<< /Limits [(delta) (zeta)] /Names [(delta) 30 (zeta) 40] >>",
        ),
        // Number tree: root → leaf.
        (8, "<< /Kids [9 0 R] >>"),
        (9, "<< /Limits [0 7] /Nums [0 (a) 4 (b) 7 (c)] >>"),
        // Malformed name tree: one kid is an integer, one is fine.
        (10, "<< /Kids [11 0 R 5 0 R] >>"),
        (11, "42"),
    ])
}

fn root_dict(reader: &mut DocumentReader<'_>, num: u32) -> oxideav_pdf::objects::Dict {
    match reader.resolve(ObjectId::new(num)).expect("resolve node") {
        Object::Dict(d) => d,
        other => panic!("object {num} should be a dict, got {other:?}"),
    }
}

#[test]
fn name_tree_enumerates_across_levels() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let root = root_dict(&mut reader, 4);
    let entries = name_tree_entries(&mut reader, &root).expect("walk");
    let keys: Vec<&[u8]> = entries.iter().map(|(k, _)| k.as_slice()).collect();
    assert_eq!(
        keys,
        vec![
            b"alpha".as_slice(),
            b"beta".as_slice(),
            b"delta".as_slice(),
            b"zeta".as_slice()
        ]
    );
    let values: Vec<i64> = entries
        .iter()
        .map(|(_, v)| match v {
            Object::Integer(n) => *n,
            other => panic!("expected integer value, got {other:?}"),
        })
        .collect();
    assert_eq!(values, vec![10, 20, 30, 40]);
}

#[test]
fn name_tree_lookup_descends_by_limits() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let root = root_dict(&mut reader, 4);
    let hit = name_tree_lookup(&mut reader, &root, b"delta").expect("lookup");
    assert!(
        matches!(hit, Some(Object::Integer(30))),
        "expected Some(Integer(30)), got {hit:?}"
    );
    // A key lexically outside every /Limits window resolves to None.
    let miss = name_tree_lookup(&mut reader, &root, b"omega").expect("lookup");
    assert!(miss.is_none(), "expected None, got {miss:?}");
    // A key inside a window but absent from the leaf also misses.
    let miss2 = name_tree_lookup(&mut reader, &root, b"epsilon").expect("lookup");
    assert!(miss2.is_none(), "expected None, got {miss2:?}");
}

#[test]
fn number_tree_enumerates_integer_keys() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let root = root_dict(&mut reader, 8);
    let entries = number_tree_entries(&mut reader, &root).expect("walk");
    let keys: Vec<i64> = entries.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![0, 4, 7]);
}

#[test]
fn malformed_kid_is_skipped_not_fatal() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let root = root_dict(&mut reader, 10);
    let entries = name_tree_entries(&mut reader, &root).expect("walk");
    // The integer kid is skipped; the well-formed leaf still yields.
    let keys: Vec<&[u8]> = entries.iter().map(|(k, _)| k.as_slice()).collect();
    assert_eq!(keys, vec![b"alpha".as_slice(), b"beta".as_slice()]);
}

#[test]
fn attachments_still_walk_after_shared_tree_refactor() {
    // The attachments reader now routes through the shared walker —
    // guard the writer → reader attachment round-trip end-to-end.
    use oxideav_core::time::TimeBase;
    use oxideav_core::vector::{Group, VectorFrame};
    use oxideav_pdf::{read_pdf_attachments, write_pdf_with_attachments, Attachment};
    use oxideav_scene::{Page, Scene};

    let mut page = Page::new(200.0, 200.0);
    page.content = VectorFrame {
        width: 200.0,
        height: 200.0,
        view_box: None,
        root: Group::default(),
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let scene = Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    };
    let spec = Attachment::new("hello.txt", b"payload".to_vec());
    let pdf = write_pdf_with_attachments(&scene, &[spec]).expect("write");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let got = read_pdf_attachments(&mut reader).expect("read");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].name, "hello.txt");
    assert_eq!(got[0].bytes, b"payload");
}
