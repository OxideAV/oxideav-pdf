//! Round-418 — page labels (ISO 32000-1 §12.4.2 Table 159).
//!
//! End-to-end fixture reproducing the §12.4.2 EXAMPLE tree — three
//! labelling ranges: lowercase Roman front matter, decimal body, and
//! a prefixed decimal appendix starting at `/St 8` — over a nine-page
//! document, plus number-tree `/Kids` indirection, a UTF-16BE `/P`
//! prefix, and the no-`/PageLabels` case.

use std::process::{Command, Stdio};

use oxideav_pdf::reader::{page_label_ranges, page_labels, DocumentReader, PageLabelStyle};

/// Assemble a classic-xref PDF from `(object_number, body)` pairs.
fn build_pdf(objects: &[(u32, String)]) -> Vec<u8> {
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

/// Nine-page document with the §12.4.2 EXAMPLE `/PageLabels`, split
/// across number-tree `/Kids` (root → two leaves).
fn fixture() -> Vec<(u32, String)> {
    let mut objects: Vec<(u32, String)> = vec![
        (
            1,
            "<< /Type /Catalog /Pages 2 0 R /PageLabels 12 0 R >>".into(),
        ),
        (
            2,
            format!(
                "<< /Type /Pages /Kids [{}] /Count 9 >>",
                (3..12)
                    .map(|n| format!("{n} 0 R"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        ),
    ];
    for n in 3..12u32 {
        objects.push((
            n,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>".into(),
        ));
    }
    objects.push((12, "<< /Kids [13 0 R 14 0 R] >>".into()));
    objects.push((
        13,
        "<< /Limits [0 4] /Nums [0 << /S /r >> 4 << /S /D >>] >>".into(),
    ));
    objects.push((
        14,
        "<< /Limits [7 7] /Nums [7 << /S /D /P (A-) /St 8 >>] >>".into(),
    ));
    objects
}

fn fixture_bytes() -> Vec<u8> {
    build_pdf(&fixture())
}

#[test]
fn spec_example_yields_expected_labels() {
    let pdf = fixture_bytes();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let labels = page_labels(&mut reader)
        .expect("page_labels")
        .expect("some");
    assert_eq!(
        labels,
        vec!["i", "ii", "iii", "iv", "1", "2", "3", "A-8", "A-9"]
    );
}

#[test]
fn ranges_surface_raw_table_159_fields() {
    let pdf = fixture_bytes();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let ranges = page_label_ranges(&mut reader)
        .expect("page_label_ranges")
        .expect("some");
    assert_eq!(ranges.len(), 3);
    assert_eq!(ranges[0].start_index, 0);
    assert_eq!(ranges[0].style, Some(PageLabelStyle::RomanLower));
    assert_eq!(ranges[1].start_index, 4);
    assert_eq!(ranges[1].style, Some(PageLabelStyle::Decimal));
    assert_eq!(ranges[2].start_index, 7);
    assert_eq!(ranges[2].prefix, "A-");
    assert_eq!(ranges[2].start_value, 8);
}

#[test]
fn utf16be_prefix_decodes() {
    // /P as a UTF-16BE hex string with BOM: "§" U+00A7 + "-".
    let objects: Vec<(u32, String)> = vec![
        (
            1,
            "<< /Type /Catalog /Pages 2 0 R /PageLabels << /Nums [0 << /S /D /P <FEFF00A7002D> >>] >> >>"
                .into(),
        ),
        (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into()),
        (
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>".into(),
        ),
    ];
    let pdf = build_pdf(&objects);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let labels = page_labels(&mut reader)
        .expect("page_labels")
        .expect("some");
    assert_eq!(labels, vec!["\u{A7}-1"]);
}

#[test]
fn no_page_labels_entry_returns_none() {
    let pdf = build_pdf(&[
        (1, "<< /Type /Catalog /Pages 2 0 R >>".into()),
        (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into()),
        (
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>".into(),
        ),
    ]);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    assert!(page_labels(&mut reader).expect("page_labels").is_none());
    assert!(page_label_ranges(&mut reader)
        .expect("page_label_ranges")
        .is_none());
}

#[test]
fn qpdf_check_accepts_page_label_fixture() {
    let ok = Command::new("qpdf").arg("--version").output().is_ok();
    if !ok {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    let pdf = fixture_bytes();
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "oxideav-pdf-page-labels-{}.pdf",
        std::process::id()
    ));
    std::fs::write(&path, &pdf).expect("temp pdf write");
    let status = Command::new("qpdf")
        .args(["--check", &path.to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&path);
    assert!(status, "qpdf --check rejected the page-label fixture");
}
