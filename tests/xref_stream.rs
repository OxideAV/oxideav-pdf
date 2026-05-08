//! Round-6 cross-reference stream decode tests.
//!
//! Builds tiny PDF fixtures that use the PDF 1.5+ `/Type /XRef` stream
//! form (ISO 32000-1 §7.5.8) instead of the plain `xref`-keyword table.
//! Each fixture is the smallest legal shape — a Catalog + a Pages tree
//! with a single empty Page — so the test exercises the xref-stream
//! reader without needing the full content-stream decoder.

use std::io::Write;

use oxideav_pdf::read_pdf_to_scene;

/// Build a hand-rolled XRef-stream-protected PDF. The xref data is
/// uncompressed (no FlateDecode) so we can verify the binary format
/// directly; a separate test below covers the FlateDecode + Predictor 12
/// path the writer would actually use.
fn build_uncompressed_xref_stream_pdf() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2048);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets = [0u64; 5];
    // Obj 1: Catalog
    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    // Obj 2: Pages
    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    // Obj 3: Page
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\n",
    );
    // Obj 4: XRef stream itself.
    offsets[4] = bytes.len() as u64;

    // Each entry is W=[1 4 2] = 7 bytes (type, offset, generation).
    // Index = [0 5] (5 objects, 0..=4).
    // Entry 0: type 0 (free), next=0, gen=65535.
    // Entry 1: type 1, offset=offsets[1], gen=0.
    // Entry 2..=4: same shape.
    // Entry for the XRef stream itself: type 1, offset=offsets[4].
    fn make_entry(t: u8, f2: u32, f3: u16) -> [u8; 7] {
        let mut out = [0u8; 7];
        out[0] = t;
        out[1..5].copy_from_slice(&f2.to_be_bytes());
        out[5..7].copy_from_slice(&f3.to_be_bytes());
        out
    }
    let mut table = Vec::with_capacity(5 * 7);
    table.extend_from_slice(&make_entry(0, 0, 65535)); // free head
    table.extend_from_slice(&make_entry(1, offsets[1] as u32, 0));
    table.extend_from_slice(&make_entry(1, offsets[2] as u32, 0));
    table.extend_from_slice(&make_entry(1, offsets[3] as u32, 0));
    table.extend_from_slice(&make_entry(1, offsets[4] as u32, 0));

    let xref_dict_str = format!(
        "<< /Type /XRef /Size 5 /Index [0 5] /W [1 4 2] /Root 1 0 R /Length {} >>\n",
        table.len()
    );
    bytes.extend_from_slice(b"4 0 obj\n");
    bytes.extend_from_slice(xref_dict_str.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&table);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_off = offsets[4];
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());
    bytes
}

/// Build an XRef-stream PDF with FlateDecode + /Predictor 12 (PNG-up).
/// Layout matches what most modern writers produce so the predictor
/// path is exercised against a realistic input shape.
fn build_compressed_xref_stream_pdf_with_predictor() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4096);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets = [0u64; 5];
    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\n",
    );
    offsets[4] = bytes.len() as u64;

    // Same W = [1 4 2] = 7-byte entries. PNG-up predictor 12 prepends
    // a 1-byte tag (0x02) per row, where each "row" is one xref entry.
    fn make_entry(t: u8, f2: u32, f3: u16) -> [u8; 7] {
        let mut out = [0u8; 7];
        out[0] = t;
        out[1..5].copy_from_slice(&f2.to_be_bytes());
        out[5..7].copy_from_slice(&f3.to_be_bytes());
        out
    }
    let raw_entries = vec![
        make_entry(0, 0, 65535),
        make_entry(1, offsets[1] as u32, 0),
        make_entry(1, offsets[2] as u32, 0),
        make_entry(1, offsets[3] as u32, 0),
        make_entry(1, offsets[4] as u32, 0),
    ];
    let mut predictor_input = Vec::with_capacity(5 * 8);
    let mut prev = [0u8; 7];
    for entry in &raw_entries {
        predictor_input.push(0x02); // PNG-up tag.
        for i in 0..7 {
            // Encoded byte = current - previous (PNG-up forward).
            predictor_input.push(entry[i].wrapping_sub(prev[i]));
        }
        prev = *entry;
    }
    // FlateDecode-compress the predictor input.
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&predictor_input).unwrap();
    let compressed = enc.finish().unwrap();

    let xref_dict_str = format!(
        "<< /Type /XRef /Size 5 /Index [0 5] /W [1 4 2] /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >> /Root 1 0 R /Length {} >>\n",
        compressed.len()
    );
    bytes.extend_from_slice(b"4 0 obj\n");
    bytes.extend_from_slice(xref_dict_str.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_off = offsets[4];
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());
    bytes
}

#[test]
fn xref_stream_uncompressed_decodes_to_scene() {
    let pdf = build_uncompressed_xref_stream_pdf();
    let scene = read_pdf_to_scene(&pdf).expect("xref stream decode");
    let pages = scene.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
    assert_eq!(pages[0].height, 100.0);
}

#[test]
fn xref_stream_with_flate_predictor_12_decodes() {
    let pdf = build_compressed_xref_stream_pdf_with_predictor();
    let scene = read_pdf_to_scene(&pdf).expect("xref stream + predictor decode");
    let pages = scene.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
}
