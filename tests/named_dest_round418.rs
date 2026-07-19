//! Round-418 — named destinations (ISO 32000-1 §12.3.2.3).
//!
//! A destination referred to by name instead of the explicit Table
//! 151 array, defined by either the PDF 1.1 catalogue `/Dests`
//! dictionary or the PDF 1.2+ `/Names → /Dests` name tree. The
//! fixture defines both sources — including one key defined in both
//! with *different* targets, to pin the tree-wins merge — and routes
//! names through every §12.3.2.3 value shape:
//!
//! * a bare explicit array (`(Both)` / `/Legacy`);
//! * a dictionary with a `/D` entry (`(chap1)` — the NOTE 2 form);
//! * an outline item whose `/Dest` is a byte string;
//! * a Link annotation whose `/Dest` is a byte string, plus one
//!   naming an undefined destination.

use std::process::{Command, Stdio};

use oxideav_pdf::reader::{
    links, named_destinations, outline, resolve_named_destination, DocumentReader, PdfLinkTarget,
};
use oxideav_pdf::OutlineDestination;

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

/// Two-page document with both §12.3.2.3 named-destination sources,
/// an outline using a named dest, and two named-dest links.
fn fixture() -> Vec<u8> {
    build_pdf(&[
        (
            1,
            "<< /Type /Catalog /Pages 2 0 R /Outlines 8 0 R /Names 5 0 R /Dests 4 0 R >>",
        ),
        (2, "<< /Type /Pages /Kids [3 0 R 12 0 R] /Count 2 >>"),
        (
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Annots [11 0 R 13 0 R] >>",
        ),
        (
            12,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> >>",
        ),
        // PDF 1.1 catalogue /Dests dictionary. /Both points at PAGE 0
        // here — the name tree redefines it onto page 1, and the tree
        // must win.
        (4, "<< /Legacy [12 0 R /Fit] /Both [3 0 R /Fit] >>"),
        // PDF 1.2+ /Names → /Dests name tree.
        (5, "<< /Dests 6 0 R >>"),
        (6, "<< /Kids [7 0 R] >>"),
        (
            7,
            "<< /Limits [(Both) (chap1)] /Names [(Both) [12 0 R /Fit] (chap1) 10 0 R] >>",
        ),
        // §12.3.2.3 NOTE 2 — dictionary-with-/D value form.
        (10, "<< /D [12 0 R /XYZ 10 20 1.5] >>"),
        // Outline with a named /Dest byte string.
        (8, "<< /Type /Outlines /First 9 0 R /Last 9 0 R /Count 1 >>"),
        (9, "<< /Title (Chapter 1) /Parent 8 0 R /Dest (chap1) >>"),
        // Links: defined name + undefined name.
        (
            11,
            "<< /Type /Annot /Subtype /Link /Rect [0 0 50 50] /Dest (Both) >>",
        ),
        (
            13,
            "<< /Type /Annot /Subtype /Link /Rect [50 50 100 100] /Dest /Nowhere >>",
        ),
    ])
}

#[test]
fn named_destinations_merge_both_sources_tree_wins() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let dests = named_destinations(&mut reader).expect("named_destinations");
    let names: Vec<&str> = dests.iter().map(|d| d.name.as_str()).collect();
    // §7.9.6 byte-wise order: "Both" (0x42…) < "Legacy" (0x4C…) <
    // "chap1" (0x63…).
    assert_eq!(names, vec!["Both", "Legacy", "chap1"]);

    // /Both is defined in both sources; the name-tree target (page
    // index 1) must win over the catalogue-dict target (page 0).
    let both = &dests[0];
    assert_eq!(
        both.destination,
        Some(OutlineDestination::Fit { page_index: 1 })
    );

    // /Legacy only exists in the catalogue dictionary.
    let legacy = &dests[1];
    assert_eq!(
        legacy.destination,
        Some(OutlineDestination::Fit { page_index: 1 })
    );

    // (chap1) routes through the dictionary-with-/D value form.
    let chap1 = &dests[2];
    assert_eq!(
        chap1.destination,
        Some(OutlineDestination::Xyz {
            page_index: 1,
            left: Some(10.0),
            top: Some(20.0),
            zoom: Some(1.5),
        })
    );
}

#[test]
fn resolve_single_names_without_enumerating() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    assert_eq!(
        resolve_named_destination(&mut reader, b"Both").expect("resolve"),
        Some(OutlineDestination::Fit { page_index: 1 })
    );
    assert_eq!(
        resolve_named_destination(&mut reader, b"Legacy").expect("resolve"),
        Some(OutlineDestination::Fit { page_index: 1 })
    );
    assert_eq!(
        resolve_named_destination(&mut reader, b"chap1").expect("resolve"),
        Some(OutlineDestination::Xyz {
            page_index: 1,
            left: Some(10.0),
            top: Some(20.0),
            zoom: Some(1.5),
        })
    );
    assert_eq!(
        resolve_named_destination(&mut reader, b"absent").expect("resolve"),
        None
    );
}

#[test]
fn outline_named_dest_resolves_to_structured_destination() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let tree = outline(&mut reader).expect("outline").expect("present");
    assert_eq!(tree.roots.len(), 1);
    let item = &tree.roots[0];
    assert_eq!(item.title, "Chapter 1");
    // The named dest now resolves …
    assert_eq!(
        item.destination,
        Some(OutlineDestination::Xyz {
            page_index: 1,
            left: Some(10.0),
            top: Some(20.0),
            zoom: Some(1.5),
        })
    );
    // … and the name itself stays observable.
    assert_eq!(item.raw_dest.as_deref(), Some("named:chap1"));
}

#[test]
fn link_named_dest_resolves_undefined_stays_named() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let all = links(&mut reader).expect("links");
    assert_eq!(all.len(), 2);
    match &all[0].target {
        Some(PdfLinkTarget::Internal(OutlineDestination::Fit { page_index })) => {
            assert_eq!(*page_index, 1);
        }
        other => panic!("expected Internal Fit, got {other:?}"),
    }
    match &all[1].target {
        Some(PdfLinkTarget::Named(name)) => assert_eq!(name, "Nowhere"),
        other => panic!("expected Named, got {other:?}"),
    }
}

#[test]
fn document_without_named_dests_is_unaffected() {
    // No /Dests, no /Names — outline explicit dests keep working and
    // the named surface enumerates empty.
    let pdf = build_pdf(&[
        (1, "<< /Type /Catalog /Pages 2 0 R /Outlines 4 0 R >>"),
        (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>"),
        (4, "<< /Type /Outlines /First 5 0 R /Last 5 0 R /Count 1 >>"),
        (5, "<< /Title (Top) /Parent 4 0 R /Dest [3 0 R /Fit] >>"),
    ]);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    assert!(named_destinations(&mut reader)
        .expect("named_destinations")
        .is_empty());
    let tree = outline(&mut reader).expect("outline").expect("present");
    assert_eq!(
        tree.roots[0].destination,
        Some(OutlineDestination::Fit { page_index: 0 })
    );
}

#[test]
fn qpdf_check_accepts_named_dest_fixture() {
    // Black-box structural validation of the hand-built fixture.
    let ok = Command::new("qpdf").arg("--version").output().is_ok();
    if !ok {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    let pdf = fixture();
    let dir = std::env::temp_dir();
    let path = dir.join(format!("oxideav-pdf-named-dest-{}.pdf", std::process::id()));
    std::fs::write(&path, &pdf).expect("temp pdf write");
    let status = Command::new("qpdf")
        .args(["--check", &path.to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&path);
    assert!(status, "qpdf --check rejected the named-dest fixture");
}
