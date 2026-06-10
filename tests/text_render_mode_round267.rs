//! Round-267 — text rendering mode (`Tr`) surfaced on every [`TextRun`].
//!
//! Before this round the content-stream walker dropped the `Tr` operand
//! (batched with `Tc`/`Tw`/`Tz`/`Ts` as "geometry-only state we don't
//! act on"), so a text-extraction consumer could not tell visible body
//! text apart from the *invisible* (`3 Tr`) OCR layer that scanned PDFs
//! stack behind a page image. This round tracks the most-recent `Tr`
//! (ISO 32000-1:2008 §9.3.6, Table 106) and stamps it onto each run, so
//! `run.render_mode` resolves to a typed [`TextRenderMode`] and
//! `render_mode.paints_glyphs()` filters the OCR layer in one call.
//!
//! Provenance: ISO 32000-1:2008 §9.3.1 (default text state — render
//! mode 0), §9.3.6 + Table 106 (the eight `Tr` modes), Table 105 (`Tr`
//! is a graphics-state text parameter, so it persists across `BT`/`ET`
//! and is saved / restored by `q`/`Q`). No third-party PDF library was
//! consulted.

use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::TextRenderMode;

/// Build a minimal single-page PDF whose page content stream is
/// `content` and whose `/Resources /Font /F0` is a stock Helvetica
/// (WinAnsi) simple font — enough for `Tj` text extraction without a
/// `/ToUnicode` CMap.
fn build_pdf(content: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let off_1 = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    let off_2 = buf.len();
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    let off_3 = buf.len();
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F0 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
    );
    let off_4 = buf.len();
    buf.extend_from_slice(
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n",
    );
    let off_5 = buf.len();
    let content_header = format!("5 0 obj\n<< /Length {} >>\nstream\n", content.len());
    buf.extend_from_slice(content_header.as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n0 6\n");
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for o in [off_1, off_2, off_3, off_4, off_5] {
        let line = format!("{:010} 00000 n \n", o);
        buf.extend_from_slice(line.as_bytes());
    }
    buf.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R >>\n");
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

#[test]
fn default_render_mode_is_fill() {
    // No `Tr` issued — §9.3.1 default text state is render mode 0 (fill).
    let pdf = build_pdf(b"BT /F0 12 Tf 50 700 Td (visible) Tj ET");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "visible");
    assert_eq!(runs[0].render_mode, TextRenderMode::Fill);
    assert!(runs[0].render_mode.paints_glyphs());
}

#[test]
fn invisible_mode_three_is_recorded_and_filterable() {
    // `3 Tr` selects the invisible mode — the OCR text layer scanned
    // PDFs stack behind a page image. Text still extracts (searchable),
    // but `paints_glyphs()` is false so a "what the eye sees" consumer
    // drops it.
    let pdf = build_pdf(b"BT /F0 12 Tf 50 700 Td 3 Tr (ocr-layer) Tj ET");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "ocr-layer");
    assert_eq!(runs[0].render_mode, TextRenderMode::Invisible);
    assert!(!runs[0].render_mode.paints_glyphs());
}

#[test]
fn render_mode_persists_across_shows_until_reset() {
    // `Tr` is graphics-state text parameter (Table 105): it stays in
    // force across shows until an explicit reset. Three shows: the first
    // inherits the default fill, then `3 Tr` makes the second invisible,
    // then `0 Tr` restores fill for the third.
    let content = b"BT /F0 12 Tf 50 700 Td (a) Tj 3 Tr (b) Tj 0 Tr (c) Tj ET";
    let pdf = build_pdf(content);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0].render_mode, TextRenderMode::Fill);
    assert_eq!(runs[1].render_mode, TextRenderMode::Invisible);
    assert_eq!(runs[2].render_mode, TextRenderMode::Fill);
}

#[test]
fn render_mode_survives_bt_et_boundary() {
    // Table 105: `Tr` is NOT reset by `BT` (only the text matrix +
    // text-line matrix are). A `3 Tr` set in the first text object stays
    // in force for a show in the second text object.
    let content = b"BT /F0 12 Tf 50 700 Td 3 Tr (one) Tj ET BT /F0 12 Tf 50 680 Td (two) Tj ET";
    let pdf = build_pdf(content);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].render_mode, TextRenderMode::Invisible);
    assert_eq!(runs[1].render_mode, TextRenderMode::Invisible);
}

#[test]
fn render_mode_saved_and_restored_by_q_capital_q() {
    // §8.4.2: `Q` restores the graphics state `q` saved, including the
    // text render mode. A `3 Tr` set inside the `q`/`Q` bracket must not
    // leak past the `Q`.
    let content = b"BT /F0 12 Tf 50 700 Td (before) Tj q 3 Tr (inside) Tj Q (after) Tj ET";
    let pdf = build_pdf(content);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0].render_mode, TextRenderMode::Fill);
    assert_eq!(runs[1].render_mode, TextRenderMode::Invisible);
    assert_eq!(
        runs[2].render_mode,
        TextRenderMode::Fill,
        "q/Q restored fill"
    );
}

#[test]
fn clip_only_mode_seven_paints_no_glyphs() {
    // `7 Tr` (clip only) adds the glyph outlines to the clip path
    // without painting any marks — `paints_glyphs()` is false, like the
    // invisible mode.
    let pdf = build_pdf(b"BT /F0 12 Tf 50 700 Td 7 Tr (clip) Tj ET");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].render_mode, TextRenderMode::Clip);
    assert!(!runs[0].render_mode.paints_glyphs());
}

#[test]
fn every_table_106_operand_maps_to_its_typed_mode() {
    // Table 106 enumerates exactly 0..=7; out-of-range values fall back
    // to the §9.3.1 default (fill), matching the reader's lenient stance.
    let expected = [
        (0, TextRenderMode::Fill),
        (1, TextRenderMode::Stroke),
        (2, TextRenderMode::FillStroke),
        (3, TextRenderMode::Invisible),
        (4, TextRenderMode::FillClip),
        (5, TextRenderMode::StrokeClip),
        (6, TextRenderMode::FillStrokeClip),
        (7, TextRenderMode::Clip),
        (8, TextRenderMode::Fill),
        (-1, TextRenderMode::Fill),
    ];
    for (operand, mode) in expected {
        assert_eq!(
            TextRenderMode::from_operand(operand),
            mode,
            "operand {operand}"
        );
    }
}
