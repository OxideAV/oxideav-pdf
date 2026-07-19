//! Round-418 — Type 0 fonts with an **embedded CMap `/Encoding`**
//! (ISO 32000-1 §9.7.5.3 + §9.7.6.2), end to end.
//!
//! The fixture uses a Shift-JIS-shaped mixed-width CMap (1-byte ASCII
//! territory + a 2-byte territory, following the §9.7.5.4 example's
//! structure): codes `41 42` are single bytes, `81 40` is one 2-byte
//! code, `7E` hits a `cidchar` single. The descendant CIDFont's `/W`
//! array is keyed by **CID** (§9.7.4.3), so correct §9.4.4 advances
//! prove the code → CID mapping runs ahead of the width lookup — an
//! Identity reader would split the same bytes into 2-byte pairs and
//! land the following run at the wrong origin.
//!
//! With a `/ToUnicode` CMap present the extracted text is fully
//! Unicode-correct; without one, each §9.7.6.2-extracted code emits
//! exactly one U+FFFD marker (CIDs index glyphs, not characters — no
//! Unicode source exists), pinning segmentation.

use oxideav_pdf::reader::{extract_text, DocumentReader};

/// Assemble a classic-xref PDF from `(object_number, body)` pairs
/// (bodies may contain binary stream payloads).
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

/// A stream object body: dict (sans `/Length`) + payload.
fn stream_body(dict_extra: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(
        format!("<< /Length {} {} >>\nstream\n", payload.len(), dict_extra).as_bytes(),
    );
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\nendstream");
    out
}

/// The embedded `/Encoding` CMap: mixed 1-byte + 2-byte codespaces,
/// a cidrange per territory, one cidchar single.
const ENCODING_CMAP: &[u8] = b"%!PS-Adobe-3.0 Resource-CMap
/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CMapName /Test-H def
/CMapType 1 def
2 begincodespacerange
<00> <7F>
<8140> <FCFC>
endcodespacerange
2 begincidrange
<20> <7D> 1
<8140> <817E> 100
endcidrange
1 begincidchar
<7E> 99
endcidchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end
";

/// A `/ToUnicode` CMap over the same codespaces: ASCII passthrough
/// singles plus the 2-byte code mapped to U+3042.
const TO_UNICODE_CMAP: &[u8] = b"/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
2 begincodespacerange
<00> <7F>
<8140> <FCFC>
endcodespacerange
2 beginbfrange
<20> <7D> <0020>
<7E> <7E> <007E>
endbfrange
1 beginbfchar
<8140> <3042>
endbfchar
endcmap
end
end
";

/// Content: two shows — `(AB<8140>)` then `(<7E>)` — with no `Td`
/// between them, so the second run's origin depends entirely on the
/// first show's §9.4.4 advances.
const CONTENT: &[u8] = b"BT /F0 10 Tf 50 700 Td (AB\x81\x40) Tj (\x7E) Tj ET";

/// CIDs: `A` 0x41 -> 1 + (0x41-0x20) = 34; `B` -> 35; <8140> -> 100;
/// <7E> -> cidchar 99. /W widths: 34:500, 35:600, 100:800, 99:700.
fn fixture(with_to_unicode: bool) -> Vec<u8> {
    let font_extra = if with_to_unicode {
        " /ToUnicode 8 0 R"
    } else {
        ""
    };
    let mut objects: Vec<(u32, Vec<u8>)> = vec![
        (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec()),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /Font << /F0 5 0 R >> >> /Contents 4 0 R >>"
                .to_vec(),
        ),
        (4, stream_body("", CONTENT)),
        (
            5,
            format!(
                "<< /Type /Font /Subtype /Type0 /BaseFont /Test \
                 /Encoding 7 0 R /DescendantFonts [6 0 R]{font_extra} >>"
            )
            .into_bytes(),
        ),
        (
            6,
            b"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test \
              /CIDSystemInfo << /Registry (Test) /Ordering (Test) /Supplement 0 >> \
              /DW 1000 /W [34 [500] 35 [600] 99 [700] 100 [800]] >>"
                .to_vec(),
        ),
        (
            7,
            stream_body(
                "/Type /CMap /CMapName /Test-H \
                 /CIDSystemInfo << /Registry (Test) /Ordering (Test) /Supplement 0 >>",
                ENCODING_CMAP,
            ),
        ),
    ];
    if with_to_unicode {
        objects.push((8, stream_body("", TO_UNICODE_CMAP)));
    }
    build_pdf(&objects)
}

#[test]
fn to_unicode_text_with_embedded_cmap_advances() {
    let pdf = fixture(true);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let extraction = extract_text(&mut reader).expect("extract");
    assert_eq!(extraction.runs.len(), 2, "two Tj shows, two runs");

    // Unicode via /ToUnicode: mixed-width segmentation.
    assert_eq!(extraction.runs[0].text, "AB\u{3042}");
    assert_eq!(extraction.runs[1].text, "~");

    // Advances via the embedded CMap's code → CID mapping into /W:
    // (500 + 600 + 800) / 1000 × 10 = 19.0 past x = 50.
    let (x0, y0) = extraction.runs[0].position;
    assert!((x0 - 50.0).abs() < 0.01, "run 0 at x=50, got {x0}");
    assert!((y0 - 700.0).abs() < 0.01, "run 0 at y=700, got {y0}");
    let x1 = extraction.runs[1].position.0;
    assert!(
        (x1 - 69.0).abs() < 0.01,
        "run 1 must advance by CID-mapped /W widths to x=69, got {x1}"
    );
}

#[test]
fn without_to_unicode_segmentation_still_correct() {
    let pdf = fixture(false);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let extraction = extract_text(&mut reader).expect("extract");
    assert_eq!(extraction.runs.len(), 2);

    // No Unicode source: exactly one U+FFFD per extracted code —
    // three codes in the first show (1 + 1 + 2 bytes), one in the
    // second.
    assert_eq!(extraction.runs[0].text, "\u{FFFD}\u{FFFD}\u{FFFD}");
    assert_eq!(extraction.runs[1].text, "\u{FFFD}");

    // The advances are Unicode-independent.
    let x1 = extraction.runs[1].position.0;
    assert!(
        (x1 - 69.0).abs() < 0.01,
        "run 1 must advance by CID-mapped /W widths to x=69, got {x1}"
    );
}

#[test]
fn identity_encoding_unchanged_by_cmap_support() {
    // Regression guard: an Identity-H font still segments 2-byte
    // codes with CID = code.
    let objects: Vec<(u32, Vec<u8>)> = vec![
        (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec()),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /Font << /F0 5 0 R >> >> /Contents 4 0 R >>"
                .to_vec(),
        ),
        (
            4,
            stream_body("", b"BT /F0 10 Tf 50 700 Td (\x00\x41) Tj (\x00\x42) Tj ET"),
        ),
        (
            5,
            b"<< /Type /Font /Subtype /Type0 /BaseFont /Test \
              /Encoding /Identity-H /DescendantFonts [6 0 R] >>"
                .to_vec(),
        ),
        (
            6,
            b"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test \
              /CIDSystemInfo << /Registry (Test) /Ordering (Test) /Supplement 0 >> \
              /DW 1000 /W [65 [250]] >>"
                .to_vec(),
        ),
    ];
    let pdf = build_pdf(&objects);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let extraction = extract_text(&mut reader).expect("extract");
    assert_eq!(extraction.runs.len(), 2);
    assert_eq!(extraction.runs[0].text, "A");
    // CID 65 has width 250: 0.25 × 10 = 2.5 past x = 50.
    let x1 = extraction.runs[1].position.0;
    assert!((x1 - 52.5).abs() < 0.01, "expected x=52.5, got {x1}");
}
