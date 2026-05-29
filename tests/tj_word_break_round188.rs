//! Round-188 — `TJ` position-adjustment word breaks.
//!
//! ISO 32000-1 §9.4.3 (Table 109, `TJ`): a numeric array element is
//! expressed in thousandths of a text-space unit and is *subtracted*
//! from the current horizontal coordinate, so a negative number opens a
//! rightward gap before the next glyph (Figure 46). Many producers emit
//! the inter-word space purely as such a displacement, with no literal
//! space glyph in the strings. The reader recovers a U+0020 when the gap
//! exceeds the extraction threshold while leaving the figure's tight
//! intra-word kerns (−120 / −95) joined.
//!
//! Provenance: ISO 32000-1:2008 §9.4.3 (Text-Showing Operators),
//! Figure 46. No third-party PDF library was consulted.

use oxideav_pdf::reader::DocumentReader;

/// Minimal one-page PDF whose single Helvetica/WinAnsi font carries the
/// content stream `content`.
fn build_pdf(content: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let off_1 = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    let off_2 = buf.len();
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    let off_3 = buf.len();
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
          /Resources << /Font << /F0 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
    );
    let off_4 = buf.len();
    buf.extend_from_slice(
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
          /Encoding /WinAnsiEncoding >>\nendobj\n",
    );
    let off_5 = buf.len();
    let header = format!("5 0 obj\n<< /Length {} >>\nstream\n", content.len());
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_off = buf.len();
    let offs = [0, off_1, off_2, off_3, off_4, off_5];
    let mut xref = String::from("xref\n0 6\n0000000000 65535 f \n");
    for &o in &offs[1..] {
        xref.push_str(&format!("{o:010} 00000 n \n"));
    }
    buf.extend_from_slice(xref.as_bytes());
    let trailer = format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n");
    buf.extend_from_slice(trailer.as_bytes());
    buf
}

fn extract(content: &[u8]) -> String {
    let pdf = build_pdf(content);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    runs.into_iter().map(|r| r.text).collect()
}

#[test]
fn large_negative_tj_adjustment_inserts_word_space() {
    // No literal space in the strings; the word boundary lives entirely
    // in the −400 displacement (0.40 em ≥ 0.25 em threshold).
    let text = extract(b"BT /F0 12 Tf 72 712 Td [(hello) -400 (world)] TJ ET");
    assert_eq!(text, "hello world");
}

#[test]
fn small_negative_kern_stays_joined() {
    // ISO 32000-1 Figure 46 kerns (−120 / −95) are intra-word micro-
    // spacing inside "AWAY" and must NOT split the word.
    let text = extract(b"BT /F0 12 Tf 72 712 Td [(A) -120 (W) -120 (A) -95 (Y)] TJ ET");
    assert_eq!(text, "AWAY");
}

#[test]
fn positive_adjustment_never_breaks() {
    // A positive number pulls the next glyph leftward (overlap); it can
    // never open a rightward gap, so no space is inserted.
    let text = extract(b"BT /F0 12 Tf 72 712 Td [(over) 500 (lap)] TJ ET");
    assert_eq!(text, "overlap");
}

#[test]
fn accumulated_small_kerns_cross_threshold() {
    // Two −150 kerns with no glyph between them sum to a 0.30 em gap,
    // crossing the 0.25 em word-break threshold.
    let text = extract(b"BT /F0 12 Tf 72 712 Td [(foo) -150 -150 (bar)] TJ ET");
    assert_eq!(text, "foo bar");
}

#[test]
fn explicit_space_not_doubled_by_adjustment() {
    // A string that already ends in a space followed by a big negative
    // adjustment must not produce a double space.
    let text = extract(b"BT /F0 12 Tf 72 712 Td [(hello ) -400 (world)] TJ ET");
    assert_eq!(text, "hello world");
}

#[test]
fn leading_adjustment_emits_no_dangling_space() {
    // A negative adjustment before the first string must not prefix the
    // run with a space.
    let text = extract(b"BT /F0 12 Tf 72 712 Td [-400 (hello)] TJ ET");
    assert_eq!(text, "hello");
}
