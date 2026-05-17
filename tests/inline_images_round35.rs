//! Round-35 — Inline-image extraction from PDF content streams.
//!
//! Builds minimal PDF 1.4 byte streams that paint one or more inline
//! images (`BI … ID … EI` per ISO 32000-1 §8.9.7) inside their page
//! content streams, then asserts that
//! [`oxideav_pdf::reader::DocumentReader::inline_images`] surfaces
//! every payload byte-identically, decodes every abbreviated key,
//! routes terminal-codec filter tags correctly, and dedupes the
//! source-page bookkeeping.
//!
//! Provenance: ISO 32000-1:2008 §7.4 (Filters), §7.4.3 (ASCII85),
//! §7.4.4 (Flate), §7.4.5 (RunLength), §7.4.8 (DCTDecode), §8.9.7
//! (Inline Images, Tables 92+93). No third-party PDF library was
//! consulted.

use oxideav_pdf::reader::{ColorSpace, DocumentReader, InlineImageFilter};

/// Build a single-page PDF whose content stream is just `<content>`.
/// Object IDs: 1=catalog, 2=pages, 3=page, 4=contents.
fn build_single_page_pdf(content: &[u8]) -> Vec<u8> {
    build_multi_page_pdf(&[content])
}

/// Build an N-page PDF whose page-i content stream is `contents[i]`.
fn build_multi_page_pdf(contents: &[&[u8]]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: Vec<(u32, usize)> = Vec::new();

    // Catalog.
    let off = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets.push((1, off));

    // Pages tree.
    let n = contents.len() as u32;
    let mut kids = String::new();
    for i in 0..n {
        // Pages 3, 5, 7, … (page leaves) and 4, 6, 8, … (their content streams).
        let page_id = 3 + 2 * i;
        kids.push_str(&format!("{page_id} 0 R "));
    }
    let off = buf.len();
    buf.extend_from_slice(
        format!("2 0 obj\n<< /Type /Pages /Count {n} /Kids [{kids}] >>\nendobj\n").as_bytes(),
    );
    offsets.push((2, off));

    // Per page: leaf + contents.
    for (i, content) in contents.iter().enumerate() {
        let page_id = 3 + 2 * i as u32;
        let contents_id = page_id + 1;
        let off = buf.len();
        let dict = format!(
            "{page_id} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents {contents_id} 0 R >>\nendobj\n"
        );
        buf.extend_from_slice(dict.as_bytes());
        offsets.push((page_id, off));

        let off = buf.len();
        let header = format!(
            "{contents_id} 0 obj\n<< /Length {} >>\nstream\n",
            content.len()
        );
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(content);
        buf.extend_from_slice(b"\nendstream\nendobj\n");
        offsets.push((contents_id, off));
    }

    // xref + trailer.
    let xref_off = buf.len();
    let max_id = offsets.iter().map(|(id, _)| *id).max().unwrap_or(1);
    let count = (max_id + 1) as usize;
    buf.extend_from_slice(format!("xref\n0 {count}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    let mut by_id: Vec<usize> = vec![usize::MAX; count];
    for (id, off) in &offsets {
        by_id[*id as usize] = *off;
    }
    for off in by_id.iter().skip(1) {
        if *off == usize::MAX {
            buf.extend_from_slice(b"0000000000 00000 f \n");
        } else {
            buf.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
        }
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n")
            .as_bytes(),
    );
    buf
}

// ──────────────────────── tests ────────────────────────

#[test]
fn one_inline_image_with_raw_payload_roundtrips() {
    // 4x1 grayscale, 8 bpc: 4 bytes raw.
    let content: &[u8] = b"q\nBI\n/W 4 /H 1 /CS /G /BPC 8\nID\n\x10\x20\x30\x40\nEI\nQ\n";
    let pdf = build_single_page_pdf(content);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.inline_images().unwrap();
    assert_eq!(images.len(), 1, "expected one inline image");
    let img = &images[0];
    assert_eq!(img.width, 4);
    assert_eq!(img.height, 1);
    assert_eq!(img.bits_per_component, 8);
    assert_eq!(img.color_space, ColorSpace::DeviceGray);
    assert_eq!(img.filter, InlineImageFilter::Raw);
    assert_eq!(img.data, [0x10, 0x20, 0x30, 0x40]);
    assert_eq!(img.source_page_index, 1, "1-based page index");
}

#[test]
fn dct_inline_image_keeps_jpeg_bytes_intact() {
    // Tiny "JPEG"-ish blob — we don't decode it; we just preserve
    // the byte payload and tag the filter correctly.
    let jpeg: &[u8] = &[
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF, 0xD9,
    ];
    let mut content: Vec<u8> = b"q\nBI /W 8 /H 8 /CS /RGB /F /DCT ID\n".to_vec();
    content.extend_from_slice(jpeg);
    content.extend_from_slice(b"\nEI\nQ\n");
    let pdf = build_single_page_pdf(&content);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.inline_images().unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].filter, InlineImageFilter::DctDecode);
    assert_eq!(images[0].data, jpeg);
    assert_eq!(images[0].color_space, ColorSpace::DeviceRGB);
}

#[test]
fn ascii85_wrapped_inline_image_unwraps_to_raw_payload() {
    // ASCII85 of "Man " (4 bytes) is "9jqo^".
    let content: &[u8] = b"q\nBI /W 4 /H 1 /CS /G /BPC 8 /F /A85 ID\n9jqo^~>\nEI\nQ\n";
    let pdf = build_single_page_pdf(content);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.inline_images().unwrap();
    assert_eq!(images.len(), 1);
    let img = &images[0];
    assert_eq!(img.data, b"Man ");
    assert_eq!(img.filter, InlineImageFilter::Raw);
}

#[test]
fn multiple_inline_images_on_one_page_returned_in_stream_order() {
    let content: &[u8] = b"q\n\
        BI /W 1 /H 1 /CS /G /BPC 8 ID\n\xAA\nEI\n\
        BI /W 1 /H 1 /CS /G /BPC 8 ID\n\xBB\nEI\n\
        BI /W 1 /H 1 /CS /G /BPC 8 ID\n\xCC\nEI\nQ\n";
    let pdf = build_single_page_pdf(content);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.inline_images().unwrap();
    assert_eq!(images.len(), 3);
    assert_eq!(images[0].data, [0xAA]);
    assert_eq!(images[1].data, [0xBB]);
    assert_eq!(images[2].data, [0xCC]);
}

#[test]
fn inline_images_across_two_pages_carry_correct_page_index() {
    let p1: &[u8] = b"q\nBI /W 1 /H 1 /CS /G /BPC 8 ID\n\xAA\nEI\nQ\n";
    let p2: &[u8] = b"q\nBI /W 1 /H 1 /CS /G /BPC 8 ID\n\xBB\nEI\nQ\n";
    let pdf = build_multi_page_pdf(&[p1, p2]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.inline_images().unwrap();
    assert_eq!(images.len(), 2);
    assert_eq!(images[0].source_page_index, 1);
    assert_eq!(images[1].source_page_index, 2);
    assert_eq!(images[0].data, [0xAA]);
    assert_eq!(images[1].data, [0xBB]);
}

#[test]
fn image_mask_inline_image_surfaces_with_im_flag() {
    // /IM true marks an image mask: 1 bpc, gray, fill colour from
    // current path-paint state. The payload is 1 byte covering an
    // 8x1 bitmap row.
    let content: &[u8] = b"q\nBI /W 8 /H 1 /IM true ID\n\xFF\nEI\nQ\n";
    let pdf = build_single_page_pdf(content);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.inline_images().unwrap();
    assert_eq!(images.len(), 1);
    let img = &images[0];
    assert!(img.image_mask);
    assert_eq!(img.bits_per_component, 1);
    assert_eq!(img.color_space, ColorSpace::DeviceGray);
    assert_eq!(img.data, [0xFF]);
}

#[test]
fn inline_image_payload_containing_ei_substring_is_preserved() {
    // Embedded `EI` (no surrounding whitespace) must NOT terminate
    // the inline image. The real terminator comes after a newline.
    let content: &[u8] = b"q\nBI /W 6 /H 1 /CS /G /BPC 8 ID\nEIfoo!\nEI\nQ\n";
    let pdf = build_single_page_pdf(content);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.inline_images().unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(&images[0].data, b"EIfoo!");
}

#[test]
fn malformed_inline_image_propagates_an_error() {
    // No terminating EI.
    let content: &[u8] = b"q\nBI /W 1 /H 1 /CS /G /BPC 8 ID\n\xAA";
    let pdf = build_single_page_pdf(content);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let err = r.inline_images().unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("EI"),
        "expected error mentioning EI, got: {msg}"
    );
}

#[test]
fn long_form_keys_are_accepted() {
    // Some authoring tools emit long-form keys (`/Width` / `/Height` /
    // `/ColorSpace`) inside BI dicts even though §8.9.7 prescribes
    // the abbreviated forms. We accept both.
    let content: &[u8] =
        b"q\nBI /Width 2 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 ID\n\xAB\xCD\nEI\nQ\n";
    let pdf = build_single_page_pdf(content);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.inline_images().unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].width, 2);
    assert_eq!(images[0].height, 1);
    assert_eq!(images[0].data, [0xAB, 0xCD]);
}

#[test]
fn rl_wrapping_filter_peels_correctly() {
    // RunLengthDecode: tag 0 = 1 literal byte, then payload byte;
    // EOD = 128.
    // We want the decoded payload to be [0x42].
    let content: &[u8] = b"q\nBI /W 1 /H 1 /CS /G /BPC 8 /F /RL ID\n\x00\x42\x80\nEI\nQ\n";
    let pdf = build_single_page_pdf(content);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.inline_images().unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].data, [0x42]);
    assert_eq!(images[0].filter, InlineImageFilter::Raw);
}

#[test]
fn page_without_inline_images_returns_empty_vec() {
    let content: &[u8] = b"q 100 0 0 100 0 0 cm Q\n";
    let pdf = build_single_page_pdf(content);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.inline_images().unwrap();
    assert!(images.is_empty());
}

#[test]
fn empty_document_returns_no_inline_images() {
    // Pages tree present but with zero leaves.
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n");
    let off1 = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    let off2 = buf.len();
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n");
    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n0 3\n0000000000 65535 f \n");
    buf.extend_from_slice(format!("{:010} 00000 n \n", off1).as_bytes());
    buf.extend_from_slice(format!("{:010} 00000 n \n", off2).as_bytes());
    buf.extend_from_slice(
        format!("trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n").as_bytes(),
    );
    let mut r = DocumentReader::open(&buf).unwrap();
    let images = r.inline_images().unwrap();
    assert!(images.is_empty());
}

#[test]
fn comment_before_bi_does_not_swallow_it() {
    // A `%` comment line ending in a newline must not cause the
    // walker to drift past the BI keyword on the next line.
    let content: &[u8] = b"q\n% leading comment line\nBI /W 1 /H 1 /CS /G /BPC 8 ID\n\xCC\nEI\nQ\n";
    let pdf = build_single_page_pdf(content);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.inline_images().unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].data, [0xCC]);
}
