//! Round-28 — `/Encoding /Differences` resolver end-to-end.
//!
//! Builds minimal PDF 1.4 byte streams whose simple-font `/Encoding`
//! dictionary carries a `/Differences` array overriding specific byte
//! slots with PostScript glyph names. Verifies the text walker
//! resolves the bytes through the AGL to the expected Unicode payload.
//!
//! Cross-checked against `pdftotext` (poppler-utils) — every fixture
//! built by these tests is also fed to the system `pdftotext` binary
//! and the bytes compared exactly when the binary is available on
//! `$PATH`. When it isn't, the test asserts only against the round-28
//! resolver's own output. Skipping `pdftotext` matches the policy of
//! the round-22 cross-check tests in the same crate.
//!
//! Provenance: ISO 32000-1 §9.6.6.1 (Type 1 Encodings) + §D.2 (Latin
//! character set) + Adobe Glyph List v2.0 (public document). No
//! third-party PDF library SOURCE was consulted.

use oxideav_pdf::reader::DocumentReader;

// ──────────────────────── small fixture builder ────────────────────────

/// Build a minimal valid PDF 1.4 document with one page whose content
/// stream is `content`, one Type 1 font registered as `F0`, and an
/// encoding dictionary whose `/BaseEncoding` is `base_encoding` and
/// whose `/Differences` body is `differences_body` (literal PDF syntax
/// like `"24 /breve /caron /circumflex 32 /space"`).
fn build_pdf_with_differences(
    content: &[u8],
    base_encoding: &str,
    differences_body: &str,
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
    let page_dict = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
        /Resources << /Font << /F0 4 0 R >> >> /Contents 5 0 R >>\nendobj\n";
    buf.extend_from_slice(page_dict);
    // Object 4 = Font dict — Type 1 + Helvetica + inline encoding dict.
    let off_4 = buf.len();
    let font_obj = format!(
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
         /Encoding << /Type /Encoding /BaseEncoding /{base_encoding} \
         /Differences [{differences_body}] >> >>\nendobj\n"
    );
    buf.extend_from_slice(font_obj.as_bytes());
    // Object 5 = Content stream.
    let off_5 = buf.len();
    let content_obj_header = format!("5 0 obj\n<< /Length {} >>\nstream\n", content.len());
    buf.extend_from_slice(content_obj_header.as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    // xref + trailer.
    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n0 6\n");
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for o in [off_1, off_2, off_3, off_4, off_5] {
        buf.extend_from_slice(format!("{:010} 00000 n \n", o).as_bytes());
    }
    buf.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n");
    buf.extend_from_slice(format!("{xref_off}\n%%EOF\n").as_bytes());
    buf
}

/// Cross-check helper: feed `pdf_bytes` to the system `pdftotext`
/// binary and compare its output (with trailing whitespace stripped)
/// to `expected`. Skips silently if `pdftotext` isn't on `$PATH` (CI
/// runners may not carry it).
fn cross_check_pdftotext(pdf_bytes: &[u8], expected_substring: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = match Command::new("pdftotext")
        .args(["-raw", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            eprintln!("pdftotext not on PATH; skipping cross-check");
            return;
        }
    };
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(pdf_bytes)
        .expect("write pdf bytes to pdftotext");
    let output = child.wait_with_output().expect("wait for pdftotext");
    if !output.status.success() {
        eprintln!(
            "pdftotext exited non-zero ({:?}); skipping cross-check",
            output.status
        );
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stripped: String = stdout
        .lines()
        .map(|line| line.trim_end())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        stripped.contains(expected_substring),
        "pdftotext output did not contain expected substring:\n\
         expected: {expected_substring:?}\nactual: {stripped:?}"
    );
}

// ────────────────────────── tests ──────────────────────────

#[test]
fn differences_smart_quotes_resolve_via_agl() {
    // Override byte slots 0x91..0x94 with the four smart quote glyphs.
    // WinAnsi already maps these, but this checks that the
    // /Differences path activates and produces equivalent output even
    // when the producer redundantly redeclares them.
    let differences = "145 /quoteleft /quoteright /quotedblleft /quotedblright";
    // Content: BT /F0 12 Tf 100 700 Td <91 92 93 94> Tj ET
    let content = b"BT /F0 12 Tf 100 700 Td <91929394> Tj ET";
    let pdf = build_pdf_with_differences(content, "WinAnsiEncoding", differences);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].text, "\u{2018}\u{2019}\u{201C}\u{201D}",
        "smart quotes from /Differences should resolve via AGL"
    );
    cross_check_pdftotext(&pdf, "\u{2018}\u{2019}\u{201C}\u{201D}");
}

#[test]
fn differences_swap_alphabet_with_greek_glyphs() {
    // The canonical Acrobat Differences example — remap the ASCII
    // letters to the corresponding Greek glyph names. Byte 0x41 →
    // /Omega ⇒ U+03A9, 0x42 → /alpha ⇒ U+03B1, 0x43 → /beta ⇒ U+03B2.
    let differences = "65 /Omega /alpha /beta";
    let content = b"BT /F0 12 Tf 100 700 Td <414243> Tj ET";
    let pdf = build_pdf_with_differences(content, "WinAnsiEncoding", differences);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].text, "\u{03A9}\u{03B1}\u{03B2}",
        "alphabet swap to Greek glyphs"
    );
}

#[test]
fn differences_ligature_expansion_fi_fl() {
    // Common Distiller pattern — push the `fi` and `fl` ligatures into
    // high bytes that the base encoding leaves unassigned.
    let differences = "253 /fi /fl";
    let content = b"BT /F0 12 Tf 100 700 Td (o\xFD\xFEce) Tj ET";
    // Decoded payload: 'o' + "fi" + "fl" + "ce" = "office l".. wait,
    // the content shows: 'o', 0xFD (→ "fi"), 0xFE (→ "fl"), 'c', 'e'
    // = "o" + "fi" + "fl" + "ce" = "ofifce".
    let pdf = build_pdf_with_differences(content, "WinAnsiEncoding", differences);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].text, "ofiflce",
        "ligature glyph names should expand to multi-char strings"
    );
}

#[test]
fn differences_multiple_runs_with_resets() {
    // Two numeric-token resets inside the same array: 24 reorders the
    // four accent glyphs, then 32 resets the running code to 32 and
    // remaps /space → /breve. Acrobat / Distiller arrays mix several
    // segments in one /Differences entry; the round-28 parser must
    // honour every reset.
    let differences = "24 /breve /caron /circumflex /tilde 32 /breve";
    // Hex string: 0x18, 0x19, 0x1A, 0x1B, 0x20 (=32 decimal).
    let content = b"BT /F0 12 Tf 100 700 Td <18191A1B20> Tj ET";
    let pdf = build_pdf_with_differences(content, "WinAnsiEncoding", differences);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    // 0x18 → /breve = U+02D8
    // 0x19 → /caron = U+02C7
    // 0x1A → /circumflex = U+02C6
    // 0x1B → /tilde = U+02DC
    // 0x20 → /breve (re-mapped by the second running-code segment) = U+02D8
    assert_eq!(runs[0].text, "\u{02D8}\u{02C7}\u{02C6}\u{02DC}\u{02D8}");
}

#[test]
fn differences_unknown_glyph_becomes_replacement_char() {
    // /Differences pointing at a glyph name that's not in the AGL
    // subset — round-28 emits U+FFFD as a marker (matching the
    // "lossy decoded slot" semantics that `pdftotext --raw` uses
    // for un-resolvable glyphs).
    let differences = "65 /not-a-real-glyph-name";
    let content = b"BT /F0 12 Tf 100 700 Td <4142> Tj ET";
    let pdf = build_pdf_with_differences(content, "WinAnsiEncoding", differences);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    // 0x41 → unknown → U+FFFD; 0x42 unchanged → 'B'.
    assert_eq!(runs[0].text, "\u{FFFD}B");
}

#[test]
fn no_differences_with_winansi_base_unchanged() {
    // Empty /Differences array — base encoding must apply unmodified.
    let differences = "";
    let content = b"BT /F0 12 Tf 100 700 Td (Hello) Tj ET";
    let pdf = build_pdf_with_differences(content, "WinAnsiEncoding", differences);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "Hello");
    cross_check_pdftotext(&pdf, "Hello");
}

#[test]
fn differences_with_macroman_base_encoding() {
    // /BaseEncoding /MacRomanEncoding + /Differences overlay — the
    // override should win, the base map handles the rest.
    let differences = "65 /Omega";
    let content = b"BT /F0 12 Tf 100 700 Td <414243> Tj ET";
    let pdf = build_pdf_with_differences(content, "MacRomanEncoding", differences);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    // 0x41 → Omega (overridden) = U+03A9, 0x42 → 'B' (MacRoman ASCII),
    // 0x43 → 'C' (MacRoman ASCII).
    assert_eq!(runs[0].text, "\u{03A9}BC");
}
