//! Round-194 — PDF 2.0 Associated Files (`/AFRelationship` + `/AF`)
//! end-to-end tests (ISO 32000-2 §7.11.3 Table 44 + §14.13.3 + §14.13.4).
//!
//! Validates that an [`oxideav_pdf::Attachment`] whose
//! `with_af_relationship` builder is invoked:
//!
//! * Emits `/AFRelationship /<Name>` on its filespec dict.
//! * Has its filespec reference appear in the **catalog** `/AF` array
//!   (§14.13.3 + §7.7.2 Table 29).
//! * Has its filespec reference also appear in the per-**page** `/AF`
//!   array (§14.13.4 + §7.7.3.3 page object) when the attachment also
//!   carries a `FileAttachment` annotation on that page.
//! * Round-trips back through [`oxideav_pdf::read_pdf_attachments`] as
//!   the same [`oxideav_pdf::AfRelationship`] variant.
//!
//! Attachments without a relationship MUST preserve the round-33 byte
//! shape exactly — no `/AFRelationship` Name and no `/AF` arrays.
//!
//! When `qpdf` is on PATH, `qpdf --check` is invoked as an opaque
//! black-box validator on the writer output.

use std::process::{Command, Stdio};

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{read_pdf_attachments, write_pdf_with_attachments, AfRelationship, Attachment};
use oxideav_scene::{Page, Scene};

fn mk_page(w: f32, h: f32) -> Page {
    let mut path = Path::new();
    path.commands
        .push(PathCommand::MoveTo(Point::new(5.0, 5.0)));
    path.commands
        .push(PathCommand::LineTo(Point::new(w - 5.0, 5.0)));
    path.commands
        .push(PathCommand::LineTo(Point::new(w - 5.0, h - 5.0)));
    path.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: w,
        height: h,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path,
                fill: Some(Paint::Solid(Rgba::opaque(0, 0, 0))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let mut page = Page::new(w, h);
    page.content = frame;
    page
}

fn two_page_scene() -> Scene {
    Scene {
        pages: Some(vec![mk_page(300.0, 300.0), mk_page(300.0, 300.0)]),
        ..Scene::default()
    }
}

fn tool_exists(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn write_temp_pdf(pdf: &[u8], stem: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("oxideav-pdf-{stem}-{pid}-{nanos}.pdf"));
    std::fs::write(&path, pdf).expect("temp pdf write");
    path
}

// ---------------------------------------------------------------------
// 1. Writer-side wire shape — bytes contain the new entries.
// ---------------------------------------------------------------------

#[test]
fn filespec_carries_afrelationship_name_when_set() {
    let scene = two_page_scene();
    let attachments = vec![Attachment::new("invoice.xml", b"<x/>".to_vec())
        .with_mime_type("application/xml")
        .with_af_relationship(AfRelationship::Source)];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    let s = String::from_utf8_lossy(&pdf);
    assert!(
        s.contains("/AFRelationship /Source"),
        "filespec should carry /AFRelationship /Source on the wire — \
         got:\n{s}"
    );
}

#[test]
fn catalog_af_array_populated_for_associated_attachments() {
    let scene = two_page_scene();
    let attachments = vec![
        // Two associated, one plain.
        Attachment::new("invoice.xml", b"<x/>".to_vec())
            .with_mime_type("application/xml")
            .with_af_relationship(AfRelationship::Source),
        Attachment::new("notes.txt", b"hi".to_vec()).with_mime_type("text/plain"),
        Attachment::new("schema.xsd", b"<s/>".to_vec())
            .with_mime_type("application/xml")
            .with_af_relationship(AfRelationship::Schema),
    ];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    let s = String::from_utf8_lossy(&pdf);

    // The catalog dict (object 1) must carry an /AF entry whose array
    // length equals the count of attachments that opted in (2 here).
    // Locate it by scanning the catalog header `/Type /Catalog`.
    let cat_pos = s
        .find("/Type /Catalog")
        .expect("catalog header missing in PDF");
    let cat_end = s[cat_pos..].find(">>").expect("catalog close") + cat_pos;
    let cat_slice = &s[cat_pos..cat_end];
    assert!(
        cat_slice.contains("/AF "),
        "catalog should carry /AF key; got: {cat_slice}"
    );
    // Count `0 R` occurrences inside `/AF [ ... ]`.
    let af_start = cat_slice.find("/AF [").or_else(|| cat_slice.find("/AF["));
    let af_start = af_start.expect("catalog /AF should be an array literal");
    let af_end = cat_slice[af_start..].find(']').expect("catalog /AF close") + af_start;
    let af_slice = &cat_slice[af_start..af_end];
    let refs = af_slice.matches(" R").count();
    assert_eq!(
        refs, 2,
        "catalog /AF should contain 2 references (Source + Schema); \
         got: {af_slice}"
    );
}

#[test]
fn page_af_array_populated_when_annotation_and_relationship_both_set() {
    let scene = two_page_scene();
    let attachments = vec![Attachment::new("data.csv", b"a,b\n".to_vec())
        .with_mime_type("text/csv")
        .with_af_relationship(AfRelationship::Data)
        .with_annotation(1, [50.0, 50.0, 70.0, 70.0])];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    let s = String::from_utf8_lossy(&pdf);

    // The page object on page index 1 must carry /AF in its dict.
    // We locate page objects by scanning for the `/Type /Page` (not
    // `/Pages`) marker. Use a coarse pattern: `/Type /Page\n`-shaped
    // boundary.
    let mut found_page_af = false;
    for (i, _) in s.match_indices("/Type /Page") {
        // Skip `/Type /Pages` matches.
        let after = &s.as_bytes()[i + "/Type /Page".len()..];
        if after.starts_with(b"s") {
            continue;
        }
        let end = s[i..].find(">>").map(|e| e + i).unwrap_or(s.len());
        let page_slice = &s[i..end];
        if page_slice.contains("/AF ") {
            found_page_af = true;
            break;
        }
    }
    assert!(
        found_page_af,
        "page object should carry /AF key when both annotation and \
         relationship are set; PDF body:\n{s}"
    );
}

#[test]
fn writer_preserves_round33_shape_when_no_relationship_set() {
    // Sanity: an attachment that does NOT call with_af_relationship
    // must NOT emit /AFRelationship or /AF anywhere — that protects the
    // round-33 byte shape from regressing.
    let scene = two_page_scene();
    let attachments = vec![Attachment::new("notes.txt", b"hi".to_vec())
        .with_mime_type("text/plain")
        .with_annotation(0, [10.0, 10.0, 30.0, 30.0])];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    let s = String::from_utf8_lossy(&pdf);
    assert!(
        !s.contains("/AFRelationship"),
        "no /AFRelationship expected when not set; got:\n{s}"
    );
    // Catalog should not carry /AF in this path.
    let cat_pos = s.find("/Type /Catalog").expect("catalog header");
    let cat_end = s[cat_pos..].find(">>").expect("catalog close") + cat_pos;
    let cat_slice = &s[cat_pos..cat_end];
    assert!(
        !cat_slice.contains("/AF "),
        "catalog should not carry /AF when no attachment is associated; \
         got: {cat_slice}"
    );
}

// ---------------------------------------------------------------------
// 2. Reader-side roundtrip — relationship comes back intact.
// ---------------------------------------------------------------------

#[test]
fn reader_surfaces_each_enumerated_relationship() {
    // Cover every variant so future name-table edits trip a test.
    let cases: &[(AfRelationship, &str)] = &[
        (AfRelationship::Source, "source.xml"),
        (AfRelationship::Data, "data.csv"),
        (AfRelationship::Alternative, "alt.wav"),
        (AfRelationship::Supplement, "mathml.xml"),
        (AfRelationship::EncryptedPayload, "payload.bin"),
        (AfRelationship::FormData, "form.xml"),
        (AfRelationship::Schema, "schema.xsd"),
        (AfRelationship::Unspecified, "misc.dat"),
    ];
    let scene = two_page_scene();
    let attachments: Vec<Attachment> = cases
        .iter()
        .map(|(rel, name)| {
            Attachment::new(*name, format!("payload for {name}").into_bytes())
                .with_mime_type("application/octet-stream")
                .with_af_relationship(*rel)
        })
        .collect();
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let got = read_pdf_attachments(&mut r).expect("read");
    assert_eq!(got.len(), cases.len());

    for (expected_rel, name) in cases {
        let found = got
            .iter()
            .find(|a| a.name == *name)
            .unwrap_or_else(|| panic!("attachment {name} missing from reader output"));
        assert_eq!(
            found.af_relationship,
            Some(*expected_rel),
            "relationship round-trip mismatch for {name}"
        );
    }
}

#[test]
fn reader_returns_none_when_attachment_has_no_relationship() {
    let scene = two_page_scene();
    let attachments = vec![Attachment::new("plain.txt", b"hi".to_vec())];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let got = read_pdf_attachments(&mut r).expect("read");
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].af_relationship, None,
        "no relationship should surface as None (not a default-coerced Unspecified)"
    );
}

#[test]
fn reader_distinguishes_explicit_unspecified_from_absence() {
    // PDF/A-3 (and the spec's NOTE 2 on /AFRelationship) recommend
    // writing `/Unspecified` only when no other value applies. This
    // test pins the writer + reader behaviour so a reader can tell a
    // PDF 1.x attachment from a PDF 2.0 producer that explicitly chose
    // Unspecified.
    let scene = two_page_scene();
    let attachments = vec![
        Attachment::new("plain.txt", b"x".to_vec()),
        Attachment::new("tagged.txt", b"y".to_vec())
            .with_af_relationship(AfRelationship::Unspecified),
    ];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let mut got = read_pdf_attachments(&mut r).expect("read");
    got.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(got[0].name, "plain.txt");
    assert_eq!(got[0].af_relationship, None);
    assert_eq!(got[1].name, "tagged.txt");
    assert_eq!(got[1].af_relationship, Some(AfRelationship::Unspecified));
}

// ---------------------------------------------------------------------
// 3. Black-box validator — qpdf --check accepts the writer output.
// ---------------------------------------------------------------------

#[test]
fn qpdf_check_accepts_associated_files_pdf() {
    if !tool_exists("qpdf") {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    let scene = two_page_scene();
    let attachments = vec![
        Attachment::new("invoice.xml", b"<x>1</x>".to_vec())
            .with_mime_type("application/xml")
            .with_af_relationship(AfRelationship::Source),
        Attachment::new("data.csv", b"id,val\n1,2\n".to_vec())
            .with_mime_type("text/csv")
            .with_af_relationship(AfRelationship::Data)
            .with_annotation(0, [10.0, 10.0, 30.0, 30.0]),
    ];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    let path = write_temp_pdf(&pdf, "qpdf-af-r194");
    let path_str = path.to_string_lossy().to_string();
    let ok = Command::new("qpdf")
        .args(["--check", &path_str])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "qpdf --check rejected the associated-files PDF");
}
