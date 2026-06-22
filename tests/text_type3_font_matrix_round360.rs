//! Round-360 — Type 3 font advance via `/FontMatrix` (§9.6.5).
//!
//! A Type 3 font's `/Widths` are expressed in glyph space and scaled
//! into text space by the font's `/FontMatrix`, *not* by the 1/1000
//! convention that Type1 / TrueType widths follow. This exercises that
//! distinction end-to-end through the public `text_extraction()` API:
//! the same numeric width produces a ten-times-larger advance when the
//! `/FontMatrix` horizontal scale is `0.01` instead of the default
//! `0.001`.
//!
//! Provenance: ISO 32000-1:2008 §9.2.4 (Glyph Positioning and Metrics),
//! §9.4.4 (Text Space Details), §9.6.5 (Type 3 Fonts — "These widths
//! shall be interpreted in glyph space as specified by FontMatrix").
//! Staged PDF bytes are hand-assembled here; no third-party PDF library
//! was consulted.

use oxideav_pdf::reader::DocumentReader;

/// Assemble a one-page PDF whose single Type 3 font carries the given
/// `/FontMatrix` and an inline `/Widths` array. The font has empty
/// `/CharProcs` and an `/Encoding` mapping code 65 → `a65` — text
/// extraction only needs the advance metrics, not the glyph procedures.
fn build_pdf_type3(content: &[u8], font_matrix: &str, first_char: i64, widths: &[i64]) -> Vec<u8> {
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

    // Type 3 font dict.
    offs.push(buf.len());
    let widths_str = widths
        .iter()
        .map(|w| w.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let font = format!(
        "4 0 obj\n<< /Type /Font /Subtype /Type3 /FontBBox [0 0 750 750] \
         /FontMatrix {font_matrix} /CharProcs << >> \
         /Encoding << /Type /Encoding /Differences [65 /a65] >> \
         /FirstChar {first_char} /LastChar {} /Widths [ {widths_str} ] >>\nendobj\n",
        first_char + widths.len() as i64 - 1
    );
    buf.extend_from_slice(font.as_bytes());

    // Content stream.
    offs.push(buf.len());
    let header = format!("5 0 obj\n<< /Length {} >>\nstream\n", content.len());
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    // xref + trailer (objects 1..=5).
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

/// A Type 3 font with `/FontMatrix [0.01 …]` (ten times the default
/// `0.001`) advances ten times as far as the bare-1/1000 reading: a
/// stored width of 50 yields `50 · 0.01 · 10 = 5.0`, not `0.5`.
#[test]
fn type3_font_matrix_scales_the_advance() {
    let content = b"BT /F0 10 Tf 100 700 Td (A) Tj (A) Tj ET";
    let pdf = build_pdf_type3(content, "[0.01 0 0 0.01 0 0]", 65, &[50]);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 2, "two runs");
    // First run at the Td origin.
    assert!((runs[0].position.0 - 100.0).abs() < 1e-3);
    // Second run advanced by 50 · 0.01 · 10 = 5.0 → x = 105.0.
    assert!(
        (runs[1].position.0 - 105.0).abs() < 1e-3,
        "expected 105.0, got {}",
        runs[1].position.0
    );
}

/// A Type 3 font with the default `/FontMatrix [0.001 …]` reproduces the
/// Type1 1/1000 advance: width 500 → `500 · 0.001 · 10 = 5.0`.
#[test]
fn type3_default_font_matrix_is_one_thousandth() {
    let content = b"BT /F0 10 Tf 100 700 Td (A) Tj (A) Tj ET";
    let pdf = build_pdf_type3(content, "[0.001 0 0 0.001 0 0]", 65, &[500]);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 2);
    assert!(
        (runs[1].position.0 - 105.0).abs() < 1e-3,
        "expected 105.0, got {}",
        runs[1].position.0
    );
}
