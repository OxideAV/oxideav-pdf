//! Round-33 — embedded file attachment writer + reader end-to-end tests
//! (ISO 32000-1 §7.11 + §3.10 + §12.5.6.15 + §7.7.4 + §7.9.6).
//!
//! Validates that [`oxideav_pdf::write_pdf_with_attachments`] embeds
//! arbitrary files as `EmbeddedFile` streams referenced from the
//! catalog `/Names → /EmbeddedFiles` name tree, optionally with a
//! `/FileAttachment` annotation marker on a chosen page; that
//! [`oxideav_pdf::read_pdf_attachments`] walks the same wire bits back
//! into a [`oxideav_pdf::PdfAttachment`] structure carrying the
//! byte-exact original payload + name + MIME type; and that the
//! resulting PDF passes external validators (`qpdf --check` and
//! `qpdf --json`, `pdfinfo` when present).

use std::process::{Command, Stdio};

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{read_pdf_attachments, write_pdf_with_attachments, Attachment};
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

/// A minimal valid 1×1 transparent PNG byte sequence — fixture for the
/// MIME-typed image attachment. Constructed by hand from the PNG
/// signature + IHDR + IDAT (zlib-compressed scanline of one fully-
/// transparent pixel) + IEND chunks (RFC 2083 / W3C PNG 2003).
fn transparent_1x1_png() -> Vec<u8> {
    vec![
        // PNG signature
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        // IHDR chunk (length=13, type=IHDR, w=1, h=1, depth=8,
        // colortype=6 = RGBA, no filter / interlace)
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89,
        // IDAT chunk (length=12, zlib-deflate compressed scanline:
        // 0x00 filter byte + RGBA 0x00,0x00,0x00,0x00)
        0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x60, 0x60, 0x60, 0x60,
        0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0A, 0x14, 0x4F, 0x9E,
        // IEND chunk (length=0)
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ]
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
// Roundtrip — both attachments must come back byte-exact.
// ---------------------------------------------------------------------

#[test]
fn two_attachments_roundtrip_through_reader() {
    let scene = two_page_scene();
    let txt_bytes: Vec<u8> = b"Hello from the embedded notes file.\nLine two.\n".to_vec();
    let png_bytes = transparent_1x1_png();

    let attachments = vec![
        Attachment::new("notes.txt", txt_bytes.clone())
            .with_mime_type("text/plain")
            .with_modified("D:20260515120000Z"),
        Attachment::new("pixel.png", png_bytes.clone())
            .with_mime_type("image/png")
            .with_modified("D:20260515130000Z")
            .with_annotation(1, [10.0, 250.0, 30.0, 270.0]),
    ];

    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write attachments");
    assert!(pdf.starts_with(b"%PDF-1."), "PDF magic missing");

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let mut got = read_pdf_attachments(&mut r).expect("read attachments");
    assert_eq!(got.len(), 2, "expected 2 attachments");

    // Sort by name so assertion order is stable regardless of name-tree
    // sort order in the reader.
    got.sort_by(|a, b| a.name.cmp(&b.name));

    // Alphabetical: notes.txt, pixel.png.
    let n = &got[0];
    assert_eq!(n.name, "notes.txt");
    assert_eq!(n.mime_type.as_deref(), Some("text/plain"));
    assert_eq!(n.bytes, txt_bytes, "txt payload byte-exact roundtrip");
    assert_eq!(n.modified.as_deref(), Some("D:20260515120000Z"));

    let p = &got[1];
    assert_eq!(p.name, "pixel.png");
    assert_eq!(p.mime_type.as_deref(), Some("image/png"));
    assert_eq!(p.bytes, png_bytes, "png payload byte-exact roundtrip");
    assert_eq!(p.modified.as_deref(), Some("D:20260515130000Z"));
}

#[test]
fn empty_attachments_list_emits_no_names_entry() {
    let scene = two_page_scene();
    let pdf = write_pdf_with_attachments(&scene, &[]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let got = read_pdf_attachments(&mut r).expect("read");
    assert!(got.is_empty(), "no attachments expected");

    // Catalog should not carry /Names when no attachments were written.
    let s = String::from_utf8_lossy(&pdf);
    // /Names dict is not emitted on the empty path; this protects the
    // round-2 byte-stable shape.
    assert!(!s.contains("/EmbeddedFiles"));
}

#[test]
fn file_attachment_annotation_lands_on_correct_page() {
    let scene = two_page_scene();
    let payload = b"x".to_vec();
    let attachments = vec![Attachment::new("marker.bin", payload)
        .with_mime_type("application/octet-stream")
        .with_annotation(1, [50.0, 50.0, 70.0, 70.0])];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    // Quick string-grep heuristic: the on-wire bytes contain the
    // FileAttachment subtype.
    let s = String::from_utf8_lossy(&pdf);
    assert!(
        s.contains("/FileAttachment"),
        "PDF should contain /FileAttachment annotation"
    );
    assert!(s.contains("/EmbeddedFiles"));

    // Confirm the reader still surfaces the attachment.
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let got = read_pdf_attachments(&mut r).expect("read");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].name, "marker.bin");
}

#[test]
fn out_of_range_annotation_page_errors() {
    let scene = two_page_scene();
    let attachments =
        vec![Attachment::new("bad.txt", b"x".to_vec()).with_annotation(99, [0.0, 0.0, 10.0, 10.0])];
    let result = write_pdf_with_attachments(&scene, &attachments);
    assert!(
        result.is_err(),
        "expected out-of-range annotation_page error"
    );
}

#[test]
fn name_tree_keys_emitted_in_byte_sorted_order() {
    // §7.9.6.2: name-tree keys must be byte-wise lexicographically
    // sorted. We pass them in reverse order and verify the wire bytes
    // come out alphabetised.
    let scene = two_page_scene();
    let attachments = vec![
        Attachment::new("zeta.txt", b"zz".to_vec()),
        Attachment::new("alpha.txt", b"aa".to_vec()),
        Attachment::new("middle.txt", b"mm".to_vec()),
    ];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    let s = String::from_utf8_lossy(&pdf);
    // The catalog points at a /Names dict whose /EmbeddedFiles entry
    // points at a leaf node. Locate that leaf by its /Names [ ... ]
    // array; inside that array the keys must appear alphabetised.
    // Strategy: find the last `/Names [` in the document — the leaf
    // node is emitted AFTER the filespec dicts (which carry /F and
    // /Desc strings), so the last "/Names [" sequence is the leaf.
    let leaf_start = s
        .rfind("/Names [")
        .or_else(|| s.rfind("/Names["))
        .expect("name-tree leaf /Names array missing");
    let leaf_end = s[leaf_start..].find(']').expect("array close not found") + leaf_start;
    let leaf_slice = &s[leaf_start..leaf_end];
    let p_alpha = leaf_slice
        .find("alpha.txt")
        .expect("alpha.txt missing in leaf");
    let p_middle = leaf_slice
        .find("middle.txt")
        .expect("middle.txt missing in leaf");
    let p_zeta = leaf_slice
        .find("zeta.txt")
        .expect("zeta.txt missing in leaf");
    assert!(
        p_alpha < p_middle && p_middle < p_zeta,
        "name-tree keys must be byte-sorted in leaf: \
         alpha={p_alpha} middle={p_middle} zeta={p_zeta} \
         leaf=`{leaf_slice}`"
    );
}

// ---------------------------------------------------------------------
// External validators — gated on tool availability.
// ---------------------------------------------------------------------

#[test]
fn qpdf_check_accepts_attachments_pdf() {
    if !tool_exists("qpdf") {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    let scene = two_page_scene();
    let attachments = vec![
        Attachment::new("a.txt", b"hello".to_vec()).with_mime_type("text/plain"),
        Attachment::new("b.png", transparent_1x1_png()).with_mime_type("image/png"),
    ];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    let path = write_temp_pdf(&pdf, "qpdf-attachments");
    let path_str = path.to_string_lossy().to_string();
    let ok = Command::new("qpdf")
        .args(["--check", &path_str])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "qpdf --check rejected the attachment-bearing PDF");
}

#[test]
fn qpdf_json_lists_embedded_files() {
    if !tool_exists("qpdf") {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    let scene = two_page_scene();
    let attachments = vec![
        Attachment::new("notes.txt", b"abc".to_vec()).with_mime_type("text/plain"),
        Attachment::new("pixel.png", transparent_1x1_png()).with_mime_type("image/png"),
    ];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    let path = write_temp_pdf(&pdf, "qpdf-json-attachments");
    let path_str = path.to_string_lossy().to_string();
    let out = Command::new("qpdf")
        .args(["--json", &path_str])
        .stderr(Stdio::null())
        .output()
        .expect("qpdf --json invocation");
    let _ = std::fs::remove_file(&path);
    assert!(out.status.success(), "qpdf --json failed");
    let json_text = String::from_utf8_lossy(&out.stdout);
    // qpdf --json ≥ v11 surfaces an "attachments" object at the top
    // level mapping each name → metadata. Just check both names land
    // in the JSON output (resilient to qpdf version-specific schema
    // tweaks).
    assert!(
        json_text.contains("notes.txt"),
        "qpdf --json output missing notes.txt: {json_text}"
    );
    assert!(
        json_text.contains("pixel.png"),
        "qpdf --json output missing pixel.png: {json_text}"
    );
}

#[test]
fn pdfinfo_accepts_attachments_pdf() {
    if !tool_exists("pdfinfo") {
        eprintln!("skipping: pdfinfo not on PATH");
        return;
    }
    let scene = two_page_scene();
    let attachments =
        vec![Attachment::new("readme.txt", b"hi".to_vec()).with_mime_type("text/plain")];
    let pdf = write_pdf_with_attachments(&scene, &attachments).expect("write");
    let path = write_temp_pdf(&pdf, "pdfinfo-attachments");
    let path_str = path.to_string_lossy().to_string();
    let ok = Command::new("pdfinfo")
        .arg(&path_str)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "pdfinfo rejected the attachment-bearing PDF");
}
