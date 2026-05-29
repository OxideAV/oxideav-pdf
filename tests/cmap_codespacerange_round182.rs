//! Round-182 — `/ToUnicode` CMap with mixed-width `codespacerange`
//! entries.
//!
//! Closes the round-22 gap where `CMap::parse` ignored every
//! `codespacerange` block and the decoder fell back to a single byte-
//! width inferred from the first `bfchar` source. Real-world CJK
//! CMaps (Adobe-Japan1, Adobe-GB1, Adobe-CNS1, Adobe-Korea1) routinely
//! declare a 1-byte ASCII passthrough alongside the 2-byte CJK
//! territory; before this round the second territory's first byte was
//! mis-decoded as a standalone CID, dropping the second byte of every
//! CJK glyph from extraction output.
//!
//! This test builds a minimal PDF with a Type 0 / Identity-H font
//! whose `/ToUnicode` CMap declares:
//!
//!   2 begincodespacerange
//!   <00> <7F>
//!   <8140> <FCFC>
//!   endcodespacerange
//!
//! plus two `bfchar` slots — one in each codespace — and confirms a
//! content stream `<41 81 40>` (ASCII 'A' followed by a 2-byte CJK
//! sequence) extracts as `"A\u{4E00}"`.
//!
//! Provenance: ISO 32000-1:2008 §9.10.3 ("ToUnicode CMaps"), Adobe
//! Tech Note #5411 ("ToUnicode CMap File Tutorial") §2, Adobe Tech
//! Note #5014 ("CMap and CIDFont Files Specification") §3.1
//! (codespacerange byte-component matching rule). No third-party PDF
//! library was consulted.

use oxideav_pdf::reader::DocumentReader;

/// Build a minimal single-page PDF whose page content stream is
/// `content`, whose `/Resources /Font /F0` is a Type 0 Identity-H
/// CIDFontType2 font, and whose font dict carries `/ToUnicode 6 0 R`
/// pointing at the literal `cmap` bytes (no FlateDecode — easier to
/// audit the test as written).
fn build_pdf_with_cmap(content: &[u8], cmap: &[u8]) -> Vec<u8> {
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
        b"4 0 obj\n<< /Type /Font /Subtype /Type0 /BaseFont /Embedded+CIDFont /Encoding /Identity-H /DescendantFonts [<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Embedded+CIDFont /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /CIDToGIDMap /Identity >>] /ToUnicode 6 0 R >>\nendobj\n",
    );
    let off_5 = buf.len();
    let content_header = format!("5 0 obj\n<< /Length {} >>\nstream\n", content.len());
    buf.extend_from_slice(content_header.as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");
    let off_6 = buf.len();
    let cmap_header = format!("6 0 obj\n<< /Length {} >>\nstream\n", cmap.len());
    buf.extend_from_slice(cmap_header.as_bytes());
    buf.extend_from_slice(cmap);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n0 7\n");
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for o in [off_1, off_2, off_3, off_4, off_5, off_6] {
        let line = format!("{:010} 00000 n \n", o);
        buf.extend_from_slice(line.as_bytes());
    }
    buf.extend_from_slice(b"trailer\n<< /Size 7 /Root 1 0 R >>\n");
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

#[test]
fn mixed_width_codespacerange_decodes_ascii_then_cjk() {
    // ToUnicode CMap with 1-byte ASCII + 2-byte CJK codespaces.
    // `<41>` (ASCII 'A') maps to U+0041; `<8140>` maps to U+4E00.
    let cmap = b"\
/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Adobe-Identity-UCS def
/CMapType 2 def
2 begincodespacerange
<00> <7F>
<8140> <FCFC>
endcodespacerange
1 beginbfchar
<41> <0041>
endbfchar
1 beginbfchar
<8140> <4E00>
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end
";
    // Content stream shows the 3-byte string `<41 81 40>` — one byte
    // in the ASCII codespace, two bytes in the CJK codespace.
    let content = b"BT /F0 14 Tf 50 700 Td <418140> Tj ET";
    let pdf = build_pdf_with_cmap(content, cmap);

    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1, "exactly one Tj show expected");
    assert_eq!(
        runs[0].text, "A\u{4E00}",
        "ASCII 'A' (1-byte codespace) + U+4E00 (2-byte codespace)"
    );
}

#[test]
fn mixed_width_codespacerange_out_of_codespace_emits_replacement() {
    // Single 1-byte codespace <00>..<7F>, with one bfchar entry. A
    // content stream byte of 0xFF is outside every codespace; per
    // Adobe Tech Note #5411 §2 the decoder emits U+FFFD and resumes
    // at the next byte, so 0xFF 0x41 → "\u{FFFD}A".
    let cmap = b"\
begincmap
1 begincodespacerange
<00> <7F>
endcodespacerange
1 beginbfchar
<41> <0041>
endbfchar
endcmap
";
    let content = b"BT /F0 14 Tf 50 700 Td <FF41> Tj ET";
    let pdf = build_pdf_with_cmap(content, cmap);

    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "\u{FFFD}A");
}

#[test]
fn mixed_width_codespacerange_component_wise_rejects_inter_range_byte() {
    // The Adobe Tech Note #5014 §3.1 rule: 2-byte codespace
    // <8140>..<FCFC> covers exactly the input pairs whose first byte
    // is in [0x81..=0xFC] AND whose second byte is in [0x40..=0xFC].
    // The input `<8139>` is OUT (low byte 0x39 < 0x40) — even though
    // a naïve linear u32 interval `0x8140..=0xFCFC` would include
    // 0x8139. The decoder must refuse the 2-byte match and emit a
    // single replacement char, advancing one byte.
    //
    // We then feed a valid 2-byte sequence `<8140>` afterwards to
    // prove the decoder resumes correctly.
    let cmap = b"\
begincmap
1 begincodespacerange
<8140> <FCFC>
endcodespacerange
1 beginbfchar
<8140> <4E00>
endbfchar
endcmap
";
    // Input bytes: 0x81 0x39 0x81 0x40
    //   Position 0: 0x81 — 1-byte width attempted, no 1-byte
    //               codespace declared, so try 2-byte: 0x81 0x39 — low
    //               byte 0x39 < 0x40 → out of [0x40..=0xFC] component
    //               bound → no match → emit U+FFFD, advance 1.
    //   Position 1: 0x39 — out (no codespace covers it) → emit
    //               U+FFFD, advance 1.
    //   Position 2: 0x81 0x40 — in 2-byte codespace, maps to U+4E00.
    // Result: "\u{FFFD}\u{FFFD}\u{4E00}".
    let content = b"BT /F0 14 Tf 50 700 Td <81398140> Tj ET";
    let pdf = build_pdf_with_cmap(content, cmap);

    let mut reader = DocumentReader::open(&pdf).expect("open");
    let runs = reader.text_extraction().expect("extract").runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].text, "\u{FFFD}\u{FFFD}\u{4E00}");
}
