//! Round-349 — text-matrix advance between text-showing operators.
//!
//! Exercises the §9.4.3 / §9.4.4 horizontal text-space displacement
//! end-to-end through the public `text_extraction()` API: two `Tj`
//! shows on a single line, with no intervening `Td`/`Tm`, must report
//! distinct origins separated by the first string's accumulated glyph
//! advances (resolved from an *indirect* `/Widths` array, so the
//! document-level `resolve_font_widths` deref path is covered).
//!
//! Provenance: ISO 32000-1:2008 §9.2.4 (Glyph Positioning and
//! Metrics), §9.3 (Text State Parameters and Operators), §9.4.3 / §9.4.4
//! (Text-Showing Operators / Text Space Details), §9.6.2.1 (Type 1
//! /Widths), §9.7.4.3 (Glyph Metrics in CIDFonts). Staged PDF bytes are
//! hand-assembled here; no third-party PDF library was consulted.

use oxideav_pdf::reader::DocumentReader;

/// Assemble a one-page PDF whose single Type1 font carries an
/// *indirect* `/Widths` array (`/Widths 7 0 R`) so the reader must
/// dereference it. `first_char` + `widths` define the advance table
/// (glyph-space thousandths); `content` is the page content stream.
fn build_pdf_indirect_widths(content: &[u8], first_char: i64, widths: &[i64]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut offs: Vec<usize> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    offs.push(buf.len());
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offs.push(buf.len());
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");

    offs.push(buf.len());
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
          /Resources << /Font << /F0 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
    );

    // Font dict — /Widths is an indirect reference to object 7.
    offs.push(buf.len());
    let font = format!(
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
         /Encoding /WinAnsiEncoding /FirstChar {first_char} /LastChar {} \
         /Widths 7 0 R >>\nendobj\n",
        first_char + widths.len() as i64 - 1
    );
    buf.extend_from_slice(font.as_bytes());

    // Content stream.
    offs.push(buf.len());
    let header = format!("5 0 obj\n<< /Length {} >>\nstream\n", content.len());
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    // Object 6 — unused placeholder so the xref numbering is dense and
    // the indirect /Widths can be object 7 (keeps the builder simple).
    offs.push(buf.len());
    buf.extend_from_slice(b"6 0 obj\n<< >>\nendobj\n");

    // Object 7 — the /Widths array.
    offs.push(buf.len());
    let widths_str = widths
        .iter()
        .map(|w| w.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let warr = format!("7 0 obj\n[ {widths_str} ]\nendobj\n");
    buf.extend_from_slice(warr.as_bytes());

    // xref + trailer (objects 1..=7).
    let xref_off = buf.len();
    let count = offs.len() + 1; // + free object 0
    buf.extend_from_slice(format!("xref\n0 {count}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for o in &offs {
        buf.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n")
            .as_bytes(),
    );
    buf
}

/// Two `Tj` shows on one line: the second run's x-origin equals the
/// first plus the sum of the first string's glyph advances, resolved
/// from the indirect `/Widths` array (§9.4.4).
#[test]
fn two_tj_on_one_line_report_distinct_origins() {
    // 'A'=65 → 500, 'B'=66 → 750 (glyph-space thousandths).
    let content = b"BT /F0 10 Tf 100 700 Td (AB) Tj (C) Tj ET";
    let pdf = build_pdf_indirect_widths(content, 65, &[500, 750, 250]);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 2, "two runs");
    assert_eq!(runs[0].text, "AB");
    assert_eq!(runs[1].text, "C");
    // First run at the Td origin.
    assert!((runs[0].position.0 - 100.0).abs() < 1e-3);
    assert!((runs[0].position.1 - 700.0).abs() < 1e-3);
    // Second run advanced by 'A'(500) + 'B'(750) = 1250/1000 * 10 = 12.5.
    assert!(
        (runs[1].position.0 - 112.5).abs() < 1e-3,
        "expected 112.5, got {}",
        runs[1].position.0
    );
    assert!((runs[1].position.1 - 700.0).abs() < 1e-3);
}

/// `Tc` (character spacing) and `Tz` (horizontal scaling) feed the
/// advance, so the second run's origin reflects them (§9.3.2 / §9.3.4 /
/// §9.4.4).
#[test]
fn tc_and_tz_shift_the_following_run_origin() {
    // 'A'=65 → 1000.
    let content = b"BT /F0 10 Tf 3 Tc 50 Tz 0 700 Td (A) Tj (B) Tj ET";
    let pdf = build_pdf_indirect_widths(content, 65, &[1000, 1000]);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 2);
    // Advance of 'A' = (1000/1000*10 + 3) * 0.5 = (10 + 3) * 0.5 = 6.5.
    assert!(
        (runs[1].position.0 - 6.5).abs() < 1e-3,
        "expected 6.5, got {}",
        runs[1].position.0
    );
}

/// A run after a `T*` newline returns to the line's start x (the
/// per-glyph advance does NOT leak across an explicit line move),
/// confirming the advance only affects same-line consecutive shows.
#[test]
fn advance_does_not_leak_past_an_explicit_line_move() {
    let content = b"BT /F0 10 Tf 12 TL 40 700 Td (AAAA) Tj T* (B) Tj ET";
    let pdf = build_pdf_indirect_widths(content, 65, &[1000, 1000]);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[1].text, "B");
    // After T*, x returns to the line origin (40) — the per-glyph
    // advance from the first run does not leak across the line move —
    // and y drops by the leading (12).
    assert!(
        (runs[1].position.0 - 40.0).abs() < 1e-3,
        "expected 40.0, got {}",
        runs[1].position.0
    );
    assert!(
        (runs[1].position.1 - (700.0 - 12.0)).abs() < 1e-3,
        "expected 688.0, got {}",
        runs[1].position.1
    );
}
