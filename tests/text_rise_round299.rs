//! Round-299 — text rise (`Ts`) folded into every [`TextRun`] origin.
//!
//! Before this round the content-stream extraction walker dropped the
//! `Ts` operand (batched with `Tc`/`Tw`/`Tz` as "geometry-only state we
//! don't act on"), so a `4 Ts` superscript reported the same `position`
//! as the surrounding baseline text — a layout / accessibility consumer
//! could not tell a superscript footnote marker apart from inline body
//! text. This round tracks the most-recent `Ts` (ISO 32000-1:2008
//! §9.4.4 + §9.3.7, Table 105) and applies it to each run's origin: per
//! the text-rendering matrix the rise translates the rendering origin by
//! `Trise` along the text matrix's vertical basis, so the run's
//! `position` is shifted from the baseline and the raw rise value is
//! also surfaced on `TextRun::text_rise`.
//!
//! Provenance: ISO 32000-1:2008 §9.3.1 (default text state — rise 0),
//! §9.3.7 (text rise), §9.4.4 (text-rendering matrix — `Trise` is the
//! vertical translation), Table 105 (`Ts` is a graphics-state text
//! parameter, so it persists across `BT`/`ET` and is saved / restored
//! by `q`/`Q`). No third-party PDF library was consulted.

use oxideav_pdf::reader::DocumentReader;

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

fn extract(content: &[u8]) -> Vec<oxideav_pdf::TextRun> {
    let pdf = build_pdf(content);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    reader.text_extraction().expect("extract").runs
}

#[test]
fn default_text_rise_is_zero() {
    // No `Ts` issued — §9.3.1 default text state is rise 0; the origin is
    // the bare text-matrix translation.
    let runs = extract(b"BT /F0 12 Tf 50 700 Td (baseline) Tj ET");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "baseline");
    assert_eq!(runs[0].text_rise, 0.0);
    assert_eq!(runs[0].position, (50.0, 700.0));
}

#[test]
fn positive_rise_raises_the_origin() {
    // `4 Ts` superscript — §9.4.4 raises the rendering origin by Trise
    // along the (axis-aligned) text matrix's vertical basis, so the
    // reported y is the baseline + 4.
    let runs = extract(b"BT /F0 12 Tf 50 700 Td 4 Ts (super) Tj ET");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text_rise, 4.0);
    assert_eq!(runs[0].position, (50.0, 704.0));
}

#[test]
fn negative_rise_lowers_the_origin() {
    // `-3 Ts` subscript — lowers the origin below the baseline.
    let runs = extract(b"BT /F0 12 Tf 50 700 Td -3 Ts (sub) Tj ET");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text_rise, -3.0);
    assert_eq!(runs[0].position, (50.0, 697.0));
}

#[test]
fn rise_persists_across_shows_until_reset() {
    // `Ts` is a graphics-state text parameter (Table 105): it stays in
    // force across shows until an explicit reset. Three shows: baseline,
    // then `5 Ts` superscript, then `0 Ts` restores the baseline.
    let content = b"BT /F0 12 Tf 50 700 Td (a) Tj 5 Ts (b) Tj 0 Ts (c) Tj ET";
    let runs = extract(content);
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0].text_rise, 0.0);
    assert_eq!(runs[1].text_rise, 5.0);
    assert_eq!(runs[2].text_rise, 0.0);
    // The Td origin is unchanged across the three shows (no further
    // positioning), so only the rise distinguishes their y.
    assert_eq!(runs[0].position.1, 700.0);
    assert_eq!(runs[1].position.1, 705.0);
    assert_eq!(runs[2].position.1, 700.0);
}

#[test]
fn rise_survives_bt_et_boundary() {
    // Table 105: `Ts` is NOT reset by `BT` (only the text matrix +
    // text-line matrix are). A `6 Ts` set in the first text object stays
    // in force for a show in the second text object.
    let content = b"BT /F0 12 Tf 50 700 Td 6 Ts (one) Tj ET BT /F0 12 Tf 50 680 Td (two) Tj ET";
    let runs = extract(content);
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].text_rise, 6.0);
    assert_eq!(runs[0].position, (50.0, 706.0));
    assert_eq!(runs[1].text_rise, 6.0);
    assert_eq!(runs[1].position, (50.0, 686.0));
}

#[test]
fn rise_saved_and_restored_by_q_capital_q() {
    // §8.4.2: `Q` restores the graphics state `q` saved, including the
    // text rise. A `7 Ts` set inside the `q`/`Q` bracket must not leak
    // past the `Q`.
    let content = b"BT /F0 12 Tf 50 700 Td (before) Tj q 7 Ts (inside) Tj Q (after) Tj ET";
    let runs = extract(content);
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0].text_rise, 0.0);
    assert_eq!(runs[1].text_rise, 7.0);
    assert_eq!(runs[2].text_rise, 0.0, "q/Q restored the baseline rise");
    assert_eq!(runs[2].position, (50.0, 700.0));
}

#[test]
fn rise_maps_through_a_rotated_text_matrix() {
    // §9.4.4 — the rise translates the origin along `Tm`'s vertical
    // basis `(c, d)`, not the device y-axis. A 90° CCW `Tm`
    // `[0 1 -1 0 e f]` makes the vertical basis `(-1, 0)`, so a `10 Ts`
    // rise shifts the origin by `(-10, 0)` rather than `(0, +10)`.
    //   x = c*rise + e = (-1)*10 + 100 = 90
    //   y = d*rise + f =   0 *10 + 200 = 200
    let content = b"BT /F0 12 Tf 0 1 -1 0 100 200 Tm 10 Ts (rot) Tj ET";
    let runs = extract(content);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text_rise, 10.0);
    assert_eq!(runs[0].position, (90.0, 200.0));
}
