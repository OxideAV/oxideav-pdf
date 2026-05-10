//! Round-22 — text extraction end-to-end.
//!
//! Builds minimal PDF 1.4 byte streams with various font / encoding
//! combinations and checks the text walker recovers the expected
//! Unicode string in stream order.
//!
//! Provenance: ISO 32000-1 §9 (Text), §9.10 (Extraction of Text Content),
//! Adobe Tech Note #5014 (CMap & CIDFont Files Specification). No
//! third-party PDF library was consulted.

use oxideav_pdf::reader::DocumentReader;

// ──────────────────────── small fixture builders ────────────────────────

/// Build a minimal valid PDF 1.4 document with one page whose content
/// stream is `content`, and whose `/Resources /Font` dict carries a
/// single font registered as `font_resource_name` (e.g. `F0`).
///
/// `font_dict_body` is the dictionary body in PDF syntax (without the
/// surrounding `<< >>`). E.g. `"/Type /Font /Subtype /Type1 /BaseFont
/// /Helvetica /Encoding /WinAnsiEncoding"`.
///
/// When `tounicode_stream` is `Some`, an extra indirect object is
/// appended that holds the supplied CMap bytes (FlateDecode is *not*
/// applied — kept as a literal stream so the tests can paste the
/// canonical `bfchar` / `bfrange` form straight from the PDF spec).
/// The font dict is then extended with `/ToUnicode N 0 R`.
fn build_pdf_with_text(
    content: &[u8],
    font_resource_name: &str,
    font_dict_body: &str,
    tounicode_stream: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    // Object 1 = Catalog.
    let off_1 = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    // Object 2 = Pages root.
    let off_2 = buf.len();
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    // Object 3 = Page leaf.
    let off_3 = buf.len();
    let page_dict = format!(
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /{font_resource_name} 4 0 R >> >> /Contents 5 0 R >>\nendobj\n"
    );
    buf.extend_from_slice(page_dict.as_bytes());
    // Object 4 = Font dict.
    let off_4 = buf.len();
    let mut font_obj = format!("4 0 obj\n<< {font_dict_body}");
    if tounicode_stream.is_some() {
        font_obj.push_str(" /ToUnicode 6 0 R");
    }
    font_obj.push_str(" >>\nendobj\n");
    buf.extend_from_slice(font_obj.as_bytes());
    // Object 5 = Content stream.
    let off_5 = buf.len();
    let content_obj_header = format!("5 0 obj\n<< /Length {} >>\nstream\n", content.len());
    buf.extend_from_slice(content_obj_header.as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    let off_6 = buf.len();
    let object_count = if let Some(cmap) = tounicode_stream {
        let header = format!("6 0 obj\n<< /Length {} >>\nstream\n", cmap.len());
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(cmap);
        buf.extend_from_slice(b"\nendstream\nendobj\n");
        7
    } else {
        6
    };

    // xref + trailer.
    let xref_off = buf.len();
    buf.extend_from_slice(format!("xref\n0 {object_count}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    let mut offs = vec![off_1, off_2, off_3, off_4, off_5];
    if tounicode_stream.is_some() {
        offs.push(off_6);
    }
    for o in offs {
        let line = format!("{:010} 00000 n \n", o);
        buf.extend_from_slice(line.as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {object_count} /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n")
            .as_bytes(),
    );
    buf
}

// ──────────────────────── Tests ────────────────────────

#[test]
fn simple_tj_winansi_helvetica_run() {
    // BT /F0 12 Tf 100 200 Td (Hello) Tj ET
    let content = b"BT /F0 12 Tf 100 200 Td (Hello) Tj ET";
    let pdf = build_pdf_with_text(
        content,
        "F0",
        "/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding",
        None,
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1, "exactly one run");
    assert_eq!(runs[0].text, "Hello");
    assert_eq!(runs[0].font_name, "F0");
    assert!((runs[0].font_size - 12.0).abs() < 1e-3);
    assert!((runs[0].position.0 - 100.0).abs() < 1e-3);
    assert!((runs[0].position.1 - 200.0).abs() < 1e-3);
}

#[test]
fn winansi_smart_quote_recovered() {
    // 0x93 = U+201C left smart quote in WinAnsi.
    let content = b"BT /F0 12 Tf 0 0 Td <93> Tj ET";
    let pdf = build_pdf_with_text(
        content,
        "F0",
        "/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding",
        None,
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "\u{201C}");
}

#[test]
fn tj_array_with_kern_offsets_concatenates_text() {
    // BT /F0 12 Tf 0 0 Td [(He) -120 (llo) -50 ( World)] TJ ET
    let content = b"BT /F0 12 Tf 0 0 Td [(He) -120 (llo) -50 ( World)] TJ ET";
    let pdf = build_pdf_with_text(
        content,
        "F0",
        "/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding",
        None,
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "Hello World");
}

#[test]
fn tounicode_identity_h_type0_cid_run() {
    // Two CIDs: <0001> → 'H', <0002> → 'i'.
    // Show string: <00010002>  → "Hi"
    let cmap = br#"
/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Adobe-Identity-UCS def
/CMapType 2 def
1 begincodespacerange <0000> <FFFF> endcodespacerange
2 beginbfchar
<0001> <0048>
<0002> <0069>
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end
"#;
    let content = b"BT /F0 14 Tf 50 700 Td <00010002> Tj ET";
    let font_dict = "/Type /Font /Subtype /Type0 /BaseFont /Embedded+CIDFont /Encoding /Identity-H /DescendantFonts [<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Embedded+CIDFont /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /CIDToGIDMap /Identity >>]";
    let pdf = build_pdf_with_text(content, "F0", font_dict, Some(cmap));
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "Hi");
    assert_eq!(runs[0].font_name, "F0");
    assert!((runs[0].font_size - 14.0).abs() < 1e-3);
}

#[test]
fn nested_q_q_save_restore_text_state() {
    // q /F0 12 Tf BT (Outer) Tj ET q /F0 24 Tf BT (Inner) Tj ET Q
    // After Q, font size restores to 12 — but we never use it again,
    // just verify the two emitted runs have the right sizes.
    let content = b"q BT /F0 12 Tf 0 0 Td (Outer) Tj ET Q q BT /F0 24 Tf 0 0 Td (Inner) Tj ET Q";
    let pdf = build_pdf_with_text(
        content,
        "F0",
        "/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding",
        None,
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].text, "Outer");
    assert!((runs[0].font_size - 12.0).abs() < 1e-3);
    assert_eq!(runs[1].text, "Inner");
    assert!((runs[1].font_size - 24.0).abs() < 1e-3);
}

#[test]
fn td_advances_text_position() {
    // Two consecutive Td-then-show pairs; verify the second run's
    // position is the cumulative translation.
    let content = b"BT /F0 12 Tf 100 700 Td (Line1) Tj 0 -14 Td (Line2) Tj ET";
    let pdf = build_pdf_with_text(
        content,
        "F0",
        "/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding",
        None,
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].text, "Line1");
    assert_eq!(runs[0].position, (100.0, 700.0));
    assert_eq!(runs[1].text, "Line2");
    // Second Td: translate (0,-14) relative to the first's text-line
    // matrix ⇒ (100, 686).
    assert!((runs[1].position.0 - 100.0).abs() < 1e-3);
    assert!((runs[1].position.1 - 686.0).abs() < 1e-3);
}

#[test]
fn tm_directly_sets_text_matrix() {
    // 1 0 0 1 250 500 Tm — translate to (250, 500).
    let content = b"BT /F0 10 Tf 1 0 0 1 250 500 Tm (Tm) Tj ET";
    let pdf = build_pdf_with_text(
        content,
        "F0",
        "/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding",
        None,
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs[0].position, (250.0, 500.0));
}

#[test]
fn quote_apostrophe_does_implicit_t_star_then_show() {
    // ' is shorthand for `T*` then `Tj`. Set leading to 14, then
    // emit a string with `'`.
    let content = b"BT /F0 12 Tf 14 TL 100 700 Td (First) Tj (Second) ' ET";
    let pdf = build_pdf_with_text(
        content,
        "F0",
        "/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding",
        None,
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].text, "First");
    assert_eq!(runs[1].text, "Second");
    // Second run should be at (100, 686) after T*-with-leading-14.
    assert!((runs[1].position.0 - 100.0).abs() < 1e-3);
    assert!((runs[1].position.1 - 686.0).abs() < 1e-3);
}

#[test]
fn double_quote_sets_word_char_spacing_and_shows() {
    // aw ac string " — round-22 only checks the shown string.
    let content = b"BT /F0 12 Tf 12 TL 0 0 Td 1 2 (Spaced) \" ET";
    let pdf = build_pdf_with_text(
        content,
        "F0",
        "/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding",
        None,
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "Spaced");
}

#[test]
fn flat_text_concatenates_with_single_space() {
    let content = b"BT /F0 12 Tf 0 0 Td (Hello) Tj 50 0 Td (World) Tj ET";
    let pdf = build_pdf_with_text(
        content,
        "F0",
        "/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding",
        None,
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let extraction = reader.text_extraction().expect("extract");
    assert_eq!(extraction.flat_text(), "Hello World");
}

#[test]
fn tounicode_bfrange_scalar_form() {
    // Map CIDs 0x10..0x12 → 'A'..'C' via bfrange scalar form.
    // Content shows <100B 11 0B 12> — three bytes of CIDs (each 2-wide).
    let cmap = br#"
begincmap
/CMapType 2 def
1 begincodespacerange <0000> <FFFF> endcodespacerange
1 beginbfrange
<0010> <0012> <0041>
endbfrange
endcmap
"#;
    let content = b"BT /F0 14 Tf 0 0 Td <001000110012> Tj ET";
    let font_dict = "/Type /Font /Subtype /Type0 /BaseFont /Embedded+Demo /Encoding /Identity-H /DescendantFonts [<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Embedded+Demo /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /CIDToGIDMap /Identity >>]";
    let pdf = build_pdf_with_text(content, "F0", font_dict, Some(cmap));
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "ABC");
}

#[test]
fn extraction_returns_empty_for_pdf_without_text() {
    // No BT/ET; just an empty content stream.
    let content = b"";
    let pdf = build_pdf_with_text(
        content,
        "F0",
        "/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding",
        None,
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let extraction = reader.text_extraction().expect("extract");
    assert!(extraction.runs.is_empty());
    assert_eq!(extraction.flat_text(), "");
}

#[test]
fn identity_h_without_tounicode_falls_back_to_bmp() {
    // <0048 0069> → CIDs 0x0048, 0x0069. With Identity-H and NO
    // /ToUnicode, the walker treats CIDs as code points → "Hi".
    let content = b"BT /F0 12 Tf 0 0 Td <00480069> Tj ET";
    let font_dict = "/Type /Font /Subtype /Type0 /BaseFont /Some+Font /Encoding /Identity-H /DescendantFonts [<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Some+Font /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /CIDToGIDMap /Identity >>]";
    let pdf = build_pdf_with_text(content, "F0", font_dict, None);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "Hi");
}

// ─────────────────────── pdftotext cross-check ───────────────────────

/// Cross-check one extraction against `pdftotext` (poppler) as a
/// black-box validator. Only runs when the binary is on PATH; on CI
/// environments without poppler installed, the test is a no-op rather
/// than failing — `pdftotext` is a build-environment convenience, not a
/// runtime dependency.
#[test]
fn cross_check_against_pdftotext() {
    if which_pdftotext().is_none() {
        eprintln!("pdftotext not on PATH — skipping cross-check");
        return;
    }
    // A simple WinAnsi Helvetica run that pdftotext handles trivially.
    let content = b"BT /F0 12 Tf 100 700 Td (Hello PDF World) Tj ET";
    let pdf = build_pdf_with_text(
        content,
        "F0",
        "/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding",
        None,
    );

    // Our extraction.
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let our_runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(our_runs.len(), 1);
    let ours = our_runs[0].text.clone();

    // pdftotext -raw <pdf> -.
    let tmp = std::env::temp_dir().join("oxideav_pdf_r22_cross.pdf");
    std::fs::write(&tmp, &pdf).expect("write tmp pdf");
    let out = std::process::Command::new("pdftotext")
        .arg("-raw")
        .arg(&tmp)
        .arg("-")
        .output()
        .expect("invoke pdftotext");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        out.status.success(),
        "pdftotext failed: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let theirs = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    assert_eq!(
        ours.trim(),
        theirs,
        "our extraction `{ours}` differs from pdftotext `{theirs}`"
    );
}

fn which_pdftotext() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("pdftotext");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
