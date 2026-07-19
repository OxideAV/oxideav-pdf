//! Round-418 — article threads (ISO 32000-1 §12.4.3 Tables 160/161).
//!
//! A two-page fixture with one two-bead article running page 0 →
//! page 1 (the bead ring closed circularly per Table 161: the last
//! bead's `/N` refers back to the first) plus a titled `/I` info
//! dictionary, and a malformed thread whose ring never closes.

use oxideav_pdf::reader::{threads, DocumentReader};

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

fn fixture() -> Vec<u8> {
    build_pdf(&[
        (
            1,
            "<< /Type /Catalog /Pages 2 0 R /Threads [5 0 R 8 0 R] >>",
        ),
        (2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>"),
        (
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /B [6 0 R] >>",
        ),
        (
            4,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /B [7 0 R] >>",
        ),
        // Thread 1: two beads, ring closed (7's /N -> 6).
        (
            5,
            "<< /Type /Thread /F 6 0 R /I << /Title (Feature story) /Author (A. Writer) >> >>",
        ),
        (
            6,
            "<< /Type /Bead /T 5 0 R /N 7 0 R /V 7 0 R /P 3 0 R /R [10 100 90 190] >>",
        ),
        (
            7,
            "<< /Type /Bead /N 6 0 R /V 6 0 R /P 4 0 R /R [10 10 90 90] >>",
        ),
        // Thread 2 (malformed): the /N chain runs 9 -> 10 -> 11 and
        // then cycles 11 -> 10 without ever returning to the first
        // bead /F names, so the ring never closes — the reader's
        // visited-set must terminate the walk.
        (8, "<< /Type /Thread /F 9 0 R >>"),
        (9, "<< /Type /Bead /N 10 0 R /V 11 0 R /P 3 0 R >>"),
        (10, "<< /Type /Bead /N 11 0 R /V 9 0 R /P 4 0 R >>"),
        (11, "<< /Type /Bead /N 10 0 R /V 10 0 R /P 3 0 R >>"),
    ])
}

#[test]
fn thread_ring_unrolls_with_info_and_pages() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let all = threads(&mut reader).expect("threads");
    assert_eq!(all.len(), 2);

    let t = &all[0];
    assert_eq!(t.title.as_deref(), Some("Feature story"));
    assert_eq!(t.author.as_deref(), Some("A. Writer"));
    assert_eq!(t.beads.len(), 2, "ring closure must stop the walk");
    assert_eq!(t.beads[0].page_index, Some(0));
    assert_eq!(t.beads[0].rect, Some([10.0, 100.0, 90.0, 190.0]));
    assert_eq!(t.beads[1].page_index, Some(1));
    assert_eq!(t.beads[1].rect, Some([10.0, 10.0, 90.0, 90.0]));
}

#[test]
fn malformed_ring_terminates_on_revisit() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let all = threads(&mut reader).expect("threads");
    // Beads 10 and 11 cycle without returning to /F: the visited-set
    // stops the walk after each bead is seen once (9, 10, 11).
    assert_eq!(all[1].beads.len(), 3);
    assert_eq!(all[1].title, None);
}

#[test]
fn document_without_threads_is_empty() {
    let pdf = build_pdf(&[
        (1, "<< /Type /Catalog /Pages 2 0 R >>"),
        (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>"),
    ]);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    assert!(threads(&mut reader).expect("threads").is_empty());
}
