//! Round-238 — `/FileAttachment` annotation-writer end-to-end tests
//! (ISO 32000-1 §12.5.6.15 Table 184 + §7.11.3 Table 44 + §7.11.4
//! Table 45 + §7.7.4 + §7.9.6).
//!
//! Validates that [`oxideav_pdf::write_pdf_with_annotations`] handles
//! the [`oxideav_pdf::WriterAnnotationKind::FileAttachment`] variant by
//! emitting (a) a `/Type /EmbeddedFile` stream object carrying the
//! supplied bytes, (b) a `/Type /Filespec` dict naming the file, (c) a
//! catalog `/Names → /EmbeddedFiles` name tree leaf keyed on the
//! filename, and (d) the `/Subtype /FileAttachment` annotation dict
//! whose `/FS` entry points at the filespec. Round-trip through the
//! round-197 generic annotation reader plus the round-33 embedded-file
//! enumerator confirms the wire bits match.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    read_pdf_annotations, read_pdf_attachments, write_pdf_with_annotations, Annotation,
    AnnotationKind, WriterAnnotationKind,
};
use oxideav_scene::{Page, Scene};

fn one_page_scene() -> Scene {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(190.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(190.0, 190.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 300.0,
        height: 300.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(0, 0, 0))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let mut page = Page::new(300.0, 300.0);
    page.content = frame;
    Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    }
}

fn default_annot(rect: [f32; 4], kind: WriterAnnotationKind) -> Annotation {
    Annotation {
        source_page_index: 0,
        rect,
        author: None,
        modified: None,
        flags: None,
        colour: None,
        border: None,
        kind,
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.15 FileAttachment annotation (Table 184).
// ────────────────────────────────────────────────────────────────────

/// Minimal FileAttachment — ASCII filename, no MIME type, default
/// `/PushPin` icon. The annotation round-trips through the generic
/// annotation reader, and the embedded file body round-trips through
/// the round-33 attachment enumerator.
#[test]
fn file_attachment_minimal_ascii_roundtrips() {
    let scene = one_page_scene();
    let payload = b"hello, pdf attachment\n".to_vec();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::FileAttachment {
            icon: None,
            file_name: "notes.txt".into(),
            file_bytes: payload.clone(),
            mime_type: None,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");

    // Wire-level sanity — every required Table 184 / Table 44 / Table 45
    // marker shows up at least once.
    let pdf_str = String::from_utf8_lossy(&pdf);
    assert!(
        pdf_str.contains("/Subtype /FileAttachment"),
        "annotation /Subtype not emitted",
    );
    assert!(
        pdf_str.contains("/Type /Filespec"),
        "filespec dict not emitted",
    );
    assert!(
        pdf_str.contains("/Type /EmbeddedFile"),
        "embedded-file stream not emitted",
    );
    assert!(
        pdf_str.contains("/Name /PushPin"),
        "default /PushPin icon not emitted",
    );
    assert!(
        pdf_str.contains("/EmbeddedFiles"),
        "catalog /Names → /EmbeddedFiles tree not emitted",
    );

    // Annotation-reader round-trip — the FileAttachment kind reports
    // the same file name and a filespec ObjectId we can correlate
    // with the embedded-file enumerator.
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 1, "exactly one annotation expected");
    let filespec_from_annot = match &anns[0].kind {
        AnnotationKind::FileAttachment {
            icon,
            file_name,
            filespec,
        } => {
            assert_eq!(icon, "PushPin");
            assert_eq!(file_name.as_deref(), Some("notes.txt"));
            assert!(filespec.is_some(), "/FS should be an indirect reference");
            *filespec
        }
        other => panic!("expected FileAttachment, got {other:?}"),
    };

    // Attachment-reader round-trip — same file appears in the
    // EmbeddedFiles name tree with the original bytes.
    let mut r2 = DocumentReader::open(&pdf).expect("reader open");
    let atts = read_pdf_attachments(&mut r2).expect("read attachments");
    assert_eq!(atts.len(), 1, "exactly one embedded file expected");
    assert_eq!(atts[0].name, "notes.txt");
    assert_eq!(atts[0].bytes, payload);
    // The filespec ObjectId surfaced by the annotation reader must
    // refer to a real filespec dict — there's no public API to
    // dereference it directly from a test, but we can at least
    // assert the value is Some (above) and that the attachment
    // count matches the annotation count.
    assert!(filespec_from_annot.is_some());
}

/// Non-ASCII file name (UTF-16BE/with-BOM `/UF`) plus an explicit
/// MIME type and a non-default icon. The reader prefers `/UF` over
/// `/F` per §7.11.2 Table 43, so the round-tripped name must
/// round-trip through the UTF-16BE encoding without loss.
#[test]
fn file_attachment_utf16_name_with_mime_roundtrips() {
    let scene = one_page_scene();
    // PNG magic + IHDR start — enough bytes to make compression
    // actually shrink the body so we exercise the FlateDecode branch
    // in the embedded-file emitter.
    let mut payload: Vec<u8> =
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01".to_vec();
    // Pad with a repeating pattern that compresses well so the
    // FlateDecode branch is taken.
    payload.extend(std::iter::repeat(0xAB).take(256));
    let annot = default_annot(
        [50.0, 50.0, 70.0, 70.0],
        WriterAnnotationKind::FileAttachment {
            icon: Some("Paperclip".into()),
            file_name: "résumé-α.png".into(),
            file_bytes: payload.clone(),
            mime_type: Some("image/png".into()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");

    let pdf_str = String::from_utf8_lossy(&pdf);
    // Custom icon emitted as a Name.
    assert!(pdf_str.contains("/Name /Paperclip"));
    // MIME type lands on the embedded-file stream as a /Subtype Name
    // (the slash is `#xx`-escaped per the Name-alphabet rules in
    // §7.3.5 — `image/png` ⇒ `image#2Fpng`).
    assert!(
        pdf_str.contains("/Subtype /image#2Fpng"),
        "MIME type not emitted on stream",
    );
    // Compression should have shrunk the body ⇒ /Filter /FlateDecode
    // emitted on the stream dict.
    assert!(
        pdf_str.contains("/Filter /FlateDecode"),
        "expected FlateDecode on compressible payload",
    );

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::FileAttachment {
            icon, file_name, ..
        } => {
            assert_eq!(icon, "Paperclip");
            assert_eq!(file_name.as_deref(), Some("résumé-α.png"));
        }
        other => panic!("expected FileAttachment, got {other:?}"),
    }

    let mut r2 = DocumentReader::open(&pdf).expect("reader open");
    let atts = read_pdf_attachments(&mut r2).expect("read attachments");
    assert_eq!(atts.len(), 1);
    assert_eq!(atts[0].name, "résumé-α.png");
    assert_eq!(atts[0].bytes, payload);
}

/// Two FileAttachment annotations on the same page — both files
/// surface from the embedded-files name tree (sorted lexically per
/// §7.9.6.2) and both annotations land on the page's `/Annots`
/// array.
#[test]
fn file_attachment_two_files_share_name_tree() {
    let scene = one_page_scene();
    let bytes_a = b"alpha file body".to_vec();
    let bytes_z = b"zeta file body".to_vec();
    let annot_a = default_annot(
        [10.0, 10.0, 20.0, 20.0],
        WriterAnnotationKind::FileAttachment {
            icon: None,
            file_name: "alpha.bin".into(),
            file_bytes: bytes_a.clone(),
            mime_type: None,
        },
    );
    let annot_z = default_annot(
        [80.0, 80.0, 90.0, 90.0],
        WriterAnnotationKind::FileAttachment {
            icon: Some("GraphPushPin".into()),
            file_name: "zeta.bin".into(),
            file_bytes: bytes_z.clone(),
            mime_type: Some("application/octet-stream".into()),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot_a, annot_z]).expect("write");

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 2, "two annotations expected");
    // The annotation reader returns annotations in /Annots order,
    // which is the order we pushed them above.
    let names: Vec<Option<&str>> = anns
        .iter()
        .map(|a| match &a.kind {
            AnnotationKind::FileAttachment { file_name, .. } => file_name.as_deref(),
            _ => None,
        })
        .collect();
    assert_eq!(names, vec![Some("alpha.bin"), Some("zeta.bin")]);

    let mut r2 = DocumentReader::open(&pdf).expect("reader open");
    let atts = read_pdf_attachments(&mut r2).expect("read attachments");
    assert_eq!(atts.len(), 2);
    // The name-tree leaf sorts keys byte-wise per §7.9.6.2 — the
    // reader walks the leaf in order, so `alpha` precedes `zeta`.
    assert_eq!(atts[0].name, "alpha.bin");
    assert_eq!(atts[0].bytes, bytes_a);
    assert_eq!(atts[1].name, "zeta.bin");
    assert_eq!(atts[1].bytes, bytes_z);
}

/// Empty `file_name` is rejected at validation — §7.11.2 requires a
/// non-empty file name on every filespec.
#[test]
fn file_attachment_empty_name_rejected() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::FileAttachment {
            icon: None,
            file_name: String::new(),
            file_bytes: b"x".to_vec(),
            mime_type: None,
        },
    );
    let err =
        write_pdf_with_annotations(&scene, &[annot]).expect_err("empty file_name must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("file_name is empty"),
        "expected empty-name error, got {msg}",
    );
}
