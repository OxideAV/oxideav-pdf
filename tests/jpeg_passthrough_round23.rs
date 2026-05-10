//! Round-23 — JPEG passthrough on `/Filter /DCTDecode` Image XObjects.
//!
//! Builds minimal PDF 1.4 byte streams with one or more embedded JPEG
//! Image XObjects (single-filter `/DCTDecode`, multi-filter
//! `[/ASCII85Decode /DCTDecode]`, `/DeviceRGB` / `/DeviceCMYK` /
//! `/DeviceGray`, multi-page documents, indexed-color wrapping) and
//! checks that [`oxideav_pdf::reader::DocumentReader::image_xobjects`]
//! surfaces every JPEG payload byte-identically and skips
//! non-DCTDecode XObjects.
//!
//! Cross-checked against `pdfimages -all` (poppler-utils) when the
//! binary is on PATH — the dump must be byte-identical to the input
//! JPEG payload (DCTDecode is a passthrough, no transcoding).
//!
//! Provenance: ISO 32000-1 §7.4.8 (DCTDecode), §7.4.3
//! (ASCII85Decode), §8.9 (Image XObjects), Adobe PostScript Language
//! Reference Manual (Appendix C, base-85). No third-party PDF library
//! was consulted.

use oxideav_pdf::reader::{ColorSpace, DocumentReader};

// 8x8 RGB JPEG — JFIF baseline, components=3, precision=8. 285 bytes,
// generated once with ImageMagick (`magick -size 8x8 xc:'rgb(200,50,100)'
// jpeg:test.jpg`) and committed inline so the test is hermetic.
const JPEG_8X8_RGB: &[u8] = &[
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x03, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03,
    0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x06, 0x04, 0x04, 0x04, 0x04, 0x04, 0x08, 0x06,
    0x06, 0x05, 0x06, 0x09, 0x08, 0x0a, 0x0a, 0x09, 0x08, 0x09, 0x09, 0x0a, 0x0c, 0x0f, 0x0c, 0x0a,
    0x0b, 0x0e, 0x0b, 0x09, 0x09, 0x0d, 0x11, 0x0d, 0x0e, 0x0f, 0x10, 0x10, 0x11, 0x10, 0x0a, 0x0c,
    0x12, 0x13, 0x12, 0x10, 0x13, 0x0f, 0x10, 0x10, 0x10, 0xff, 0xdb, 0x00, 0x43, 0x01, 0x03, 0x03,
    0x03, 0x04, 0x03, 0x04, 0x08, 0x04, 0x04, 0x08, 0x10, 0x0b, 0x09, 0x0b, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0xff, 0xc0,
    0x00, 0x11, 0x08, 0x00, 0x08, 0x00, 0x08, 0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11,
    0x01, 0xff, 0xc4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xff, 0xc4, 0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xc4, 0x00,
    0x15, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x08, 0xff, 0xc4, 0x00, 0x14, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xda, 0x00, 0x0c, 0x03, 0x01,
    0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3f, 0x00, 0x37, 0x15, 0xeb, 0xff, 0xd9,
];

// 4x4 grayscale JPEG — JFIF baseline, components=1. 159 bytes.
const JPEG_4X4_GRAY: &[u8] = &[
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x03, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03,
    0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x06, 0x04, 0x04, 0x04, 0x04, 0x04, 0x08, 0x06,
    0x06, 0x05, 0x06, 0x09, 0x08, 0x0a, 0x0a, 0x09, 0x08, 0x09, 0x09, 0x0a, 0x0c, 0x0f, 0x0c, 0x0a,
    0x0b, 0x0e, 0x0b, 0x09, 0x09, 0x0d, 0x11, 0x0d, 0x0e, 0x0f, 0x10, 0x10, 0x11, 0x10, 0x0a, 0x0c,
    0x12, 0x13, 0x12, 0x10, 0x13, 0x0f, 0x10, 0x10, 0x10, 0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x04,
    0x00, 0x04, 0x01, 0x01, 0x11, 0x00, 0xff, 0xc4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xc4, 0x00, 0x14,
    0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x3f, 0xff, 0xd9,
];

// 4x4 CMYK JPEG — Adobe APP14 marker for the YCCK color transform,
// components=4, precision=8. 290 bytes.
const JPEG_4X4_CMYK: &[u8] = &[
    0xff, 0xd8, 0xff, 0xee, 0x00, 0x0e, 0x41, 0x64, 0x6f, 0x62, 0x65, 0x00, 0x64, 0x00, 0x00, 0x00,
    0x00, 0x02, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x03, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03, 0x02, 0x02,
    0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x06, 0x04, 0x04, 0x04, 0x04, 0x04, 0x08, 0x06, 0x06, 0x05,
    0x06, 0x09, 0x08, 0x0a, 0x0a, 0x09, 0x08, 0x09, 0x09, 0x0a, 0x0c, 0x0f, 0x0c, 0x0a, 0x0b, 0x0e,
    0x0b, 0x09, 0x09, 0x0d, 0x11, 0x0d, 0x0e, 0x0f, 0x10, 0x10, 0x11, 0x10, 0x0a, 0x0c, 0x12, 0x13,
    0x12, 0x10, 0x13, 0x0f, 0x10, 0x10, 0x10, 0xff, 0xdb, 0x00, 0x43, 0x01, 0x03, 0x03, 0x03, 0x04,
    0x03, 0x04, 0x08, 0x04, 0x04, 0x08, 0x10, 0x0b, 0x09, 0x0b, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0xff, 0xc0, 0x00, 0x14,
    0x08, 0x00, 0x04, 0x00, 0x04, 0x04, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, 0x04,
    0x11, 0x00, 0xff, 0xc4, 0x00, 0x15, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x08, 0xff, 0xc4, 0x00, 0x14, 0x10, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xc4, 0x00, 0x14, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0xff, 0xc4, 0x00, 0x14, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xda, 0x00, 0x0e, 0x04,
    0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x04, 0x00, 0x00, 0x3f, 0x00, 0x0e, 0x24, 0x50, 0xb2, 0xdf,
    0xff, 0xd9,
];

// ──────────────────────── PDF builder ────────────────────────

/// Build a single-page PDF whose `/Resources /XObject` dict contains
/// one Image XObject with a single `/DCTDecode` filter and the
/// supplied `image_dict_extra` entries (e.g. `/ColorSpace`, `/Width`,
/// `/Height`, `/BitsPerComponent`). XObject is allocated at object
/// id 5 (after catalog/pages/page/contents = 1..4).
fn build_pdf_with_one_jpeg(
    image_data: &[u8],
    image_dict_extra: &str,
    xobject_resource_name: &str,
) -> Vec<u8> {
    build_pdf_with_xobjects(
        &[(
            xobject_resource_name,
            5,
            image_data,
            "/Filter /DCTDecode",
            image_dict_extra,
        )],
        true,
    )
}

/// Build a single- or multi-page PDF carrying a sequence of XObject
/// stream definitions. Each entry is `(resource_name, object_id,
/// stream_bytes, filter_clause, extra_dict)`. Object id 1 = catalog,
/// 2 = pages root, 3 = page-1 leaf, 4 = page-1 contents stream;
/// for multi-page builds 5 = page-2 leaf, 6 = page-2 contents stream,
/// XObject ids start at 7. For single-page builds XObject ids start
/// at 5. The content stream is `q 100 0 0 100 0 0 cm /<name> Do Q`
/// for every xobject — `pdfimages` only reports XObjects that are
/// actually drawn.
fn build_pdf_with_xobjects(
    xobjects: &[(&str, u32, &[u8], &str, &str)],
    single_page: bool,
) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: Vec<(u32, usize)> = Vec::new();

    let off = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets.push((1, off));

    if single_page {
        let off = buf.len();
        buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
        offsets.push((2, off));
    } else {
        let off = buf.len();
        buf.extend_from_slice(
            b"2 0 obj\n<< /Type /Pages /Count 2 /Kids [3 0 R 5 0 R] >>\nendobj\n",
        );
        offsets.push((2, off));
    }

    // Build the /XObject subdict for the page resources.
    let mut xobj_subdict = String::from("<<");
    for (name, id, _, _, _) in xobjects {
        xobj_subdict.push_str(&format!(" /{name} {id} 0 R"));
    }
    xobj_subdict.push_str(" >>");

    // Content stream — paint every XObject so pdfimages picks it up.
    let mut content = String::new();
    for (name, _, _, _, _) in xobjects {
        content.push_str(&format!("q 100 0 0 100 0 0 cm /{name} Do Q\n"));
    }
    let content_bytes = content.into_bytes();

    let off = buf.len();
    let page_dict = format!(
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject {xobj_subdict} >> /Contents 4 0 R >>\nendobj\n"
    );
    buf.extend_from_slice(page_dict.as_bytes());
    offsets.push((3, off));

    let off = buf.len();
    let cs_header = format!("4 0 obj\n<< /Length {} >>\nstream\n", content_bytes.len());
    buf.extend_from_slice(cs_header.as_bytes());
    buf.extend_from_slice(&content_bytes);
    buf.extend_from_slice(b"\nendstream\nendobj\n");
    offsets.push((4, off));

    if !single_page {
        let off = buf.len();
        let page_dict = format!(
            "5 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject {xobj_subdict} >> /Contents 6 0 R >>\nendobj\n"
        );
        buf.extend_from_slice(page_dict.as_bytes());
        offsets.push((5, off));

        let off = buf.len();
        let cs_header = format!("6 0 obj\n<< /Length {} >>\nstream\n", content_bytes.len());
        buf.extend_from_slice(cs_header.as_bytes());
        buf.extend_from_slice(&content_bytes);
        buf.extend_from_slice(b"\nendstream\nendobj\n");
        offsets.push((6, off));
    }

    for (_, id, data, filter_clause, extra) in xobjects {
        let off = buf.len();
        let header = format!(
            "{id} 0 obj\n<< /Type /XObject /Subtype /Image {filter_clause} /Length {} {extra} >>\nstream\n",
            data.len()
        );
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(data);
        buf.extend_from_slice(b"\nendstream\nendobj\n");
        offsets.push((*id, off));
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
            // Free slot — produce a free-list line so the count
            // matches.
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

// ──────────────────────── ASCII85 encoder ────────────────────────
// Test-only encoder used to construct the multi-filter wrapping case.

fn encode_ascii85(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 5 / 4 + 4);
    let mut i = 0;
    while i + 4 <= input.len() {
        let v = u32::from_be_bytes([input[i], input[i + 1], input[i + 2], input[i + 3]]) as u64;
        if v == 0 {
            out.push(b'z');
        } else {
            let mut digits = [0u8; 5];
            let mut x = v;
            for d in digits.iter_mut().rev() {
                *d = (x % 85) as u8;
                x /= 85;
            }
            for d in digits {
                out.push(d + b'!');
            }
        }
        i += 4;
    }
    let rem = input.len() - i;
    if rem > 0 {
        let mut group = [0u8; 4];
        group[..rem].copy_from_slice(&input[i..]);
        let v = u32::from_be_bytes(group) as u64;
        let mut digits = [0u8; 5];
        let mut x = v;
        for d in digits.iter_mut().rev() {
            *d = (x % 85) as u8;
            x /= 85;
        }
        // Emit rem+1 digits (the partial-group convention).
        for d in &digits[..rem + 1] {
            out.push(*d + b'!');
        }
    }
    out.push(b'~');
    out.push(b'>');
    out
}

// ──────────────────────── Tests ────────────────────────

#[test]
fn single_jpeg_xobject_roundtrips_byte_identical() {
    let pdf = build_pdf_with_one_jpeg(
        JPEG_8X8_RGB,
        "/Width 8 /Height 8 /ColorSpace /DeviceRGB /BitsPerComponent 8",
        "Im0",
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.image_xobjects().unwrap();
    assert_eq!(images.len(), 1, "expected one JPEG XObject");
    let (_id, img) = &images[0];
    assert_eq!(img.width, 8);
    assert_eq!(img.height, 8);
    assert_eq!(img.color_space, ColorSpace::DeviceRGB);
    assert_eq!(img.bits_per_component, 8);
    assert_eq!(
        img.data, JPEG_8X8_RGB,
        "extracted JPEG bytes must equal the source bytes (DCTDecode is passthrough)"
    );
}

#[test]
fn ascii85_wrapped_jpeg_xobject_unwraps_and_roundtrips() {
    let encoded = encode_ascii85(JPEG_8X8_RGB);
    let pdf = build_pdf_with_xobjects(
        &[(
            "Im0",
            5,
            &encoded,
            "/Filter [/ASCII85Decode /DCTDecode]",
            "/Width 8 /Height 8 /ColorSpace /DeviceRGB /BitsPerComponent 8",
        )],
        true,
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.image_xobjects().unwrap();
    assert_eq!(images.len(), 1);
    let (_id, img) = &images[0];
    assert_eq!(
        img.data, JPEG_8X8_RGB,
        "ASCII85 wrapping must be peeled off; DCTDecode payload must equal the source JPEG"
    );
}

#[test]
fn multi_jpeg_xobjects_across_one_page_returned_in_order() {
    let pdf = build_pdf_with_xobjects(
        &[
            (
                "Im0",
                5,
                JPEG_8X8_RGB,
                "/Filter /DCTDecode",
                "/Width 8 /Height 8 /ColorSpace /DeviceRGB /BitsPerComponent 8",
            ),
            (
                "Im1",
                6,
                JPEG_4X4_GRAY,
                "/Filter /DCTDecode",
                "/Width 4 /Height 4 /ColorSpace /DeviceGray /BitsPerComponent 8",
            ),
        ],
        true,
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.image_xobjects().unwrap();
    assert_eq!(images.len(), 2);
    let (_id_rgb, rgb) = images
        .iter()
        .find(|(_, img)| img.color_space == ColorSpace::DeviceRGB)
        .expect("RGB JPEG present");
    let (_id_gray, gray) = images
        .iter()
        .find(|(_, img)| img.color_space == ColorSpace::DeviceGray)
        .expect("Gray JPEG present");
    assert_eq!(rgb.data, JPEG_8X8_RGB);
    assert_eq!(gray.data, JPEG_4X4_GRAY);
    assert_eq!(rgb.width, 8);
    assert_eq!(gray.width, 4);
}

#[test]
fn cmyk_jpeg_xobject_surfaces_devicecmyk_color_space() {
    let pdf = build_pdf_with_one_jpeg(
        JPEG_4X4_CMYK,
        "/Width 4 /Height 4 /ColorSpace /DeviceCMYK /BitsPerComponent 8",
        "Im0",
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.image_xobjects().unwrap();
    assert_eq!(images.len(), 1);
    let (_id, img) = &images[0];
    assert_eq!(img.color_space, ColorSpace::DeviceCMYK);
    assert_eq!(img.data, JPEG_4X4_CMYK);
    assert_eq!(img.width, 4);
    assert_eq!(img.height, 4);
}

#[test]
fn flate_decoded_xobject_is_skipped() {
    // FlateDecode-only XObject (no DCTDecode tail) must not appear in
    // the JPEG passthrough surface — the round-23 walker is JPEG-only.
    let payload: Vec<u8> = (0u8..16).cycle().take(64).collect();
    let mut compressed = Vec::new();
    {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = ZlibEncoder::new(&mut compressed, Compression::default());
        enc.write_all(&payload).unwrap();
        enc.finish().unwrap();
    }
    let pdf = build_pdf_with_xobjects(
        &[(
            "Im0",
            5,
            &compressed,
            "/Filter /FlateDecode",
            "/Width 8 /Height 8 /ColorSpace /DeviceRGB /BitsPerComponent 8",
        )],
        true,
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.image_xobjects().unwrap();
    assert!(
        images.is_empty(),
        "Flate-only Image XObject must NOT surface from the JPEG passthrough walker"
    );
}

#[test]
fn multiple_jpegs_across_multiple_pages() {
    // Two pages, each /Resources /XObject lists both Im0 + Im1 (so
    // each page draws both XObjects). The walker must return both
    // exactly once (deduplicated) regardless of how many pages cite
    // them.
    let pdf = build_pdf_with_xobjects(
        &[
            (
                "Im0",
                7,
                JPEG_8X8_RGB,
                "/Filter /DCTDecode",
                "/Width 8 /Height 8 /ColorSpace /DeviceRGB /BitsPerComponent 8",
            ),
            (
                "Im1",
                8,
                JPEG_4X4_GRAY,
                "/Filter /DCTDecode",
                "/Width 4 /Height 4 /ColorSpace /DeviceGray /BitsPerComponent 8",
            ),
        ],
        false,
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.image_xobjects().unwrap();
    assert_eq!(
        images.len(),
        2,
        "two XObjects across two pages — each returned once"
    );
    assert!(images.iter().any(|(_, img)| img.data == JPEG_8X8_RGB));
    assert!(images.iter().any(|(_, img)| img.data == JPEG_4X4_GRAY));
}

#[test]
fn xobject_referenced_from_two_pages_is_returned_once() {
    // Two pages, both /Resources /XObject point at the same Im0 ref.
    // XObject must live at id ≥ 7 in multi-page (ids 1..6 are
    // catalog/pages/page1/contents1/page2/contents2).
    let pdf = build_pdf_with_xobjects(
        &[(
            "Im0",
            7,
            JPEG_8X8_RGB,
            "/Filter /DCTDecode",
            "/Width 8 /Height 8 /ColorSpace /DeviceRGB /BitsPerComponent 8",
        )],
        false,
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.image_xobjects().unwrap();
    assert_eq!(
        images.len(),
        1,
        "shared Im0 must be deduplicated across pages"
    );
}

#[test]
fn indexed_color_space_array_surfaces_indexed_variant() {
    // /ColorSpace [/Indexed /DeviceRGB 255 <00 00 00 ...>] — JPEG bytes
    // are still the raw 8x8 RGB JPEG; the indexed wrapper is on the
    // PDF side. (Real-world DCTDecode rarely lives under an Indexed
    // base — we test the path so the variant is reachable.)
    let pdf = build_pdf_with_one_jpeg(
        JPEG_8X8_RGB,
        "/Width 8 /Height 8 /ColorSpace [/Indexed /DeviceRGB 255 <0000FF>] /BitsPerComponent 8",
        "Im0",
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let images = r.image_xobjects().unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].1.color_space, ColorSpace::Indexed);
    assert_eq!(images[0].1.data, JPEG_8X8_RGB);
}

// ──────────────────────── Cross-check: `pdfimages -all` ────────────────────────

/// Black-box cross-check: when `pdfimages` (poppler-utils) is on PATH,
/// run it against our synthesised PDF and compare its raw extraction
/// to our `image_xobjects()` output.
///
/// `pdfimages -all` writes the JPEG bytes to `<prefix>-NNN.jpg` for
/// DCTDecode XObjects. Since DCTDecode is a passthrough, the output
/// must be byte-identical to both the original JPEG fixture *and* our
/// reader's output.
#[test]
fn cross_check_against_pdfimages() {
    if std::process::Command::new("pdfimages")
        .arg("-v")
        .output()
        .is_err()
    {
        eprintln!("pdfimages not on PATH — skipping cross-check");
        return;
    }
    let pdf = build_pdf_with_one_jpeg(
        JPEG_8X8_RGB,
        "/Width 8 /Height 8 /ColorSpace /DeviceRGB /BitsPerComponent 8",
        "Im0",
    );
    let dir = tempdir();
    let pdf_path = dir.join("oxideav-r23.pdf");
    std::fs::write(&pdf_path, &pdf).unwrap();
    let prefix = dir.join("img");
    let output = std::process::Command::new("pdfimages")
        .arg("-all")
        .arg(&pdf_path)
        .arg(&prefix)
        .output()
        .expect("pdfimages spawn");
    assert!(
        output.status.success(),
        "pdfimages failed: status={:?}\nstderr: {}\nstdout: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );

    // pdfimages writes `<prefix>-NNN.<ext>` where NNN is the image
    // index (zero-padded to 3 digits in poppler ≥ 0.83). Find any
    // `.jpg` file in the dir starting with `img-`.
    let mut found: Option<Vec<u8>> = None;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("img-") && name_str.ends_with(".jpg") {
            found = Some(std::fs::read(entry.path()).unwrap());
            break;
        }
    }
    let pdfimages_out = found.unwrap_or_else(|| {
        let mut listing = String::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            listing.push_str(&format!("  {}\n", entry.file_name().to_string_lossy()));
        }
        panic!("pdfimages -all did not produce a .jpg file under {dir:?}. Files:\n{listing}")
    });
    assert_eq!(
        pdfimages_out, JPEG_8X8_RGB,
        "pdfimages must reproduce the JPEG bytes byte-for-byte (DCTDecode is passthrough)"
    );
    let mut r = DocumentReader::open(&pdf).unwrap();
    let ours = r.image_xobjects().unwrap();
    assert_eq!(ours.len(), 1);
    assert_eq!(
        ours[0].1.data, pdfimages_out,
        "our image_xobjects() output must equal pdfimages -all"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&dir);
}

fn tempdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("oxideav-pdf-r23-{nonce}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}
