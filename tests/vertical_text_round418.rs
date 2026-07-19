//! Round-418 — vertical writing mode metrics (ISO 32000-1 §9.7.4.3 +
//! §9.4.4).
//!
//! A Type 0 font under `Identity-V` (or an embedded CMap with
//! `/WMode 1`) advances the text matrix *vertically*: the §9.4.4
//! displacement is `ty = (w1 − Tj/1000)·Tfs + Tc + Tw` with `w1`
//! drawn from the CIDFont's `/W2` runs (fallback `/DW2[1]`, default
//! −1000) and the horizontal scaling `Th` **not** applied (the
//! §9.4.4 equations scale only `tx` by `Th`). The fixture shows one
//! column of vertical text and pins:
//!
//! * successive shows stack by the CID-keyed `/W2` displacement
//!   (negative `w1y` moves down the column, §9.7.4.3 NOTE) — both
//!   the `cfirst clast w1y v1x v1y` range form and the
//!   `c [w1y v1x v1y]` array form;
//! * a CID outside `/W2` falls back to `/DW2[1]`;
//! * a `TJ` numeric adjustment lands on the **vertical** coordinate
//!   (`−Tj/1000 × Tfs`), unscaled by an in-force `Tz` horizontal
//!   scaling;
//! * x stays constant down the column.

use oxideav_pdf::reader::{extract_text, DocumentReader};

/// Assemble a classic-xref PDF from `(object_number, body)` pairs.
fn build_pdf(objects: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let max_id = objects.iter().map(|(n, _)| *n).max().unwrap_or(0);
    let mut offsets = vec![0u64; (max_id + 1) as usize];
    for (num, body) in objects {
        offsets[*num as usize] = bytes.len() as u64;
        bytes.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(b"\nendobj\n");
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

fn stream_body(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("<< /Length {} >>\nstream\n", payload.len()).as_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\nendstream");
    out
}

/// Identity-V font at size 10. `/W2` gives CID 0x41 a −800
/// displacement (range form `65 65 -800 400 880`) and CID 0x42 a
/// −600 one (array form `66 [-600 400 880]`); CID 0x43 falls back to
/// `/DW2 [880 -500]`.
///
/// Content (one column at x = 100, top y = 700):
///
/// 1. `(\x00\x43) Tj` — DW2 fallback: −0.5 × 10 = −5.
/// 2. `(\x00\x41) Tj` — /W2 range form: −8.
/// 3. `50 Tz [(\x00\x41) -500 (\x00\x42)] TJ` — glyph −8, kern
///    `−(−500)/1000 × 10 = +5` (no `Th`), glyph −6 ⇒ −9 total.
/// 4. `(\x00\x42) Tj` — observes the TJ's accumulated displacement.
fn fixture() -> Vec<u8> {
    let content: &[u8] = b"BT /F0 10 Tf 100 700 Td (\x00\x43) Tj (\x00\x41) Tj \
50 Tz [(\x00\x41) -500 (\x00\x42)] TJ (\x00\x42) Tj ET";
    let objects: Vec<(u32, Vec<u8>)> = vec![
        (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec()),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /Font << /F0 5 0 R >> >> /Contents 4 0 R >>"
                .to_vec(),
        ),
        (4, stream_body(content)),
        (
            5,
            b"<< /Type /Font /Subtype /Type0 /BaseFont /Test \
              /Encoding /Identity-V /DescendantFonts [6 0 R] >>"
                .to_vec(),
        ),
        (
            6,
            b"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test \
              /CIDSystemInfo << /Registry (Test) /Ordering (Test) /Supplement 0 >> \
              /DW 1000 /DW2 [880 -500] \
              /W2 [65 65 -800 400 880 66 [-600 400 880]] >>"
                .to_vec(),
        ),
    ];
    build_pdf(&objects)
}

#[test]
fn vertical_shows_stack_downward_by_w2_and_dw2() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let extraction = extract_text(&mut reader).expect("extract");
    assert_eq!(extraction.runs.len(), 4, "four shows, four runs");

    // Run 0 at the Td origin.
    let (x0, y0) = extraction.runs[0].position;
    assert!((x0 - 100.0).abs() < 0.01, "col x=100, got {x0}");
    assert!((y0 - 700.0).abs() < 0.01, "start y=700, got {y0}");

    // After CID 0x43: /DW2[1] = −500 → −5.
    let (x1, y1) = extraction.runs[1].position;
    assert!((x1 - 100.0).abs() < 0.01, "x constant, got {x1}");
    assert!((y1 - 695.0).abs() < 0.01, "y=695 after DW2 -500, got {y1}");

    // After CID 0x41: /W2 range form w1y = −800 → −8.
    let (_, y2) = extraction.runs[2].position;
    assert!((y2 - 687.0).abs() < 0.01, "y=687 after -800 w1y, got {y2}");
}

#[test]
fn vertical_tj_kern_lands_vertically_without_th() {
    let pdf = fixture();
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let extraction = extract_text(&mut reader).expect("extract");

    // The TJ starts at y = 687 and accumulates: CID 0x41 glyph −8,
    // −500 kern → +5 (Th = 50% must NOT scale it: a horizontal-style
    // `× Th` would give +2.5), CID 0x42 glyph −6 — net −9.
    let (x3, y3) = extraction.runs[3].position;
    assert!(
        (y3 - 678.0).abs() < 0.01,
        "y=678 after TJ (-8 +5 -6), got {y3}"
    );
    // A horizontal-kern regression would move x instead.
    assert!((x3 - 100.0).abs() < 0.01, "x constant, got {x3}");
}
