//! Round-406 inline-image scene splicing (ISO 32000-1 §8.9.7).
//!
//! A `BI … ID … EI` inline image whose payload the crate decodes
//! end-to-end is now painted into the `Scene` as a `Node::Image`,
//! mirroring the `Do` Image-XObject splice: device / inline-Indexed /
//! named colour spaces, the `/D` (`/Decode`) array, and `/IM true`
//! stencils poured with the current nonstroking colour. Terminal-codec
//! payloads (`/DCT` …) stay event-only on the `inline_images` surface.

use oxideav_core::vector::{Group, ImageRef, Node};
use oxideav_pdf::read_pdf_to_scene;
use oxideav_pdf::reader::DocumentReader;

/// Assemble a classic-xref one-page PDF whose content stream is
/// `content` and whose page `/Resources` body is `resources`.
fn one_page_pdf(resources: &str, content: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<usize> = Vec::new();
    offsets.push(buf.len());
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets.push(buf.len());
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offsets.push(buf.len());
    buf.extend_from_slice(
        format!(
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
             /Resources << {resources} >> /Contents 4 0 R >>\nendobj\n"
        )
        .as_bytes(),
    );
    offsets.push(buf.len());
    buf.extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");
    let n = offsets.len() + 1;
    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n");
    buf.extend_from_slice(format!("0 {n}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(b"trailer\n");
    buf.extend_from_slice(format!("<< /Size {n} /Root 1 0 R >>\n").as_bytes());
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

fn find_images(group: &Group, out: &mut Vec<ImageRef>) {
    for child in &group.children {
        match child {
            Node::Image(img) => out.push(img.clone()),
            Node::Group(g) => find_images(g, out),
            Node::SoftMask { content, .. } => match content.as_ref() {
                Node::Group(g) => find_images(g, out),
                Node::Image(img) => out.push(img.clone()),
                _ => {}
            },
            _ => {}
        }
    }
}

fn spliced_images(pdf: &[u8]) -> Vec<ImageRef> {
    let scene = read_pdf_to_scene(pdf).expect("read");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let mut images = Vec::new();
    find_images(root, &mut images);
    images
}

fn pixels(img: &ImageRef) -> Vec<[u8; 4]> {
    img.frame.planes[0]
        .data
        .chunks_exact(4)
        .map(|c| [c[0], c[1], c[2], c[3]])
        .collect()
}

#[test]
fn raw_rgb_inline_image_splices() {
    // 2×1 raw DeviceRGB: red, green.
    let mut content = b"q 100 0 0 100 0 0 cm BI /W 2 /H 1 /CS /RGB /BPC 8 ID ".to_vec();
    content.extend_from_slice(&[255, 0, 0, 0, 255, 0]);
    content.extend_from_slice(b" EI Q");
    let images = spliced_images(&one_page_pdf("", &content));
    assert_eq!(images.len(), 1);
    let img = &images[0];
    assert_eq!((img.bounds.width, img.bounds.height), (2.0, 1.0));
    assert_eq!((img.transform.a, img.transform.d), (0.5, 1.0));
    let px = pixels(img);
    assert_eq!(px[0], [255, 0, 0, 255]);
    assert_eq!(px[1], [0, 255, 0, 255]);
}

#[test]
fn gray_1bit_inline_image_with_decode_flip() {
    // 2×2 at 1 bpc DeviceGray, Decode [1 0]: code 1 → black,
    // code 0 → white. Rows are byte-aligned. Row 0 = 1,0; row 1 = 0,1.
    let mut content = b"BI /W 2 /H 2 /CS /G /BPC 1 /D [1 0] ID ".to_vec();
    content.extend_from_slice(&[0b1000_0000, 0b0100_0000]);
    content.extend_from_slice(b" EI");
    let images = spliced_images(&one_page_pdf("", &content));
    assert_eq!(images.len(), 1);
    let px = pixels(&images[0]);
    assert_eq!(px[0], [0, 0, 0, 255], "code 1 inverted → black");
    assert_eq!(px[1], [255, 255, 255, 255]);
    assert_eq!(px[2], [255, 255, 255, 255]);
    assert_eq!(px[3], [0, 0, 0, 255]);
}

#[test]
fn inline_indexed_array_splices_and_tags_indexed() {
    // 4×1 at 2 bpc through an inline [/I /RGB 3 <…>] palette
    // (Table 94 abbreviations).
    let mut content =
        b"BI /W 4 /H 1 /CS [/I /RGB 3 <FF0000 00FF00 0000FF FFFF00>] /BPC 2 ID ".to_vec();
    content.extend_from_slice(&[0b0001_1011]);
    content.extend_from_slice(b" EI");
    let pdf = one_page_pdf("", &content);
    let images = spliced_images(&pdf);
    assert_eq!(images.len(), 1);
    let px = pixels(&images[0]);
    assert_eq!(px[0], [255, 0, 0, 255]);
    assert_eq!(px[1], [0, 255, 0, 255]);
    assert_eq!(px[2], [0, 0, 255, 255]);
    assert_eq!(px[3], [255, 255, 0, 255]);
    // The public event surface now tags the array shape as Indexed
    // (it previously fell through to the DeviceRGB default).
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let events = reader.inline_images().expect("inline images");
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].color_space,
        oxideav_pdf::reader::ColorSpace::Indexed
    );
}

#[test]
fn inline_stencil_mask_pours_fill_color() {
    // §8.9.6.2 via /IM true: default Decode [0 1] — sample 0 paints
    // with the teal fill set before BI, sample 1 masks out.
    let mut content = b"q 0 0.5 0.5 rg BI /W 2 /H 1 /IM true ID ".to_vec();
    content.extend_from_slice(&[0b0100_0000]);
    content.extend_from_slice(b" EI Q");
    let images = spliced_images(&one_page_pdf("", &content));
    assert_eq!(images.len(), 1);
    let px = pixels(&images[0]);
    assert_eq!(px[0], [0, 128, 128, 255], "sample 0 → fill colour");
    assert_eq!(px[1][3], 0, "sample 1 → masked out");
}

#[test]
fn inline_image_with_named_color_space_resource() {
    // §8.9.5.2: a non-device /CS name refers to the page's
    // /Resources /ColorSpace subdictionary — here an Indexed palette.
    let mut content = b"BI /W 2 /H 1 /CS /Pal /BPC 8 ID ".to_vec();
    content.extend_from_slice(&[0, 1]);
    content.extend_from_slice(b" EI");
    let pdf = one_page_pdf(
        "/ColorSpace << /Pal [/Indexed /DeviceRGB 1 <FF8000 0080FF>] >>",
        &content,
    );
    let images = spliced_images(&pdf);
    assert_eq!(images.len(), 1);
    let px = pixels(&images[0]);
    assert_eq!(px[0], [255, 128, 0, 255]);
    assert_eq!(px[1], [0, 128, 255, 255]);
}

#[test]
fn dct_inline_image_stays_event_only() {
    // A /DCT terminal filter is not decodable here — event surface
    // only, no scene splice.
    let mut content = b"BI /W 8 /H 8 /CS /RGB /BPC 8 /F /DCT ID ".to_vec();
    content.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xD9]);
    content.extend_from_slice(b" EI");
    let pdf = one_page_pdf("", &content);
    assert!(spliced_images(&pdf).is_empty(), "no scene splice");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    assert_eq!(reader.inline_images().expect("events").len(), 1);
}

#[test]
fn surrounding_shapes_survive_inline_splice() {
    // The splice must not disturb the operator stream around it: a
    // rect fill before and after the inline image both land.
    let mut content = b"0 0 1 rg 10 10 20 20 re f BI /W 1 /H 1 /CS /G /BPC 8 ID ".to_vec();
    content.extend_from_slice(&[128]);
    content.extend_from_slice(b" EI 1 0 0 rg 40 40 20 20 re f");
    let pdf = one_page_pdf("", &content);
    let scene = read_pdf_to_scene(&pdf).expect("read");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    fn count_paths(g: &Group) -> usize {
        g.children
            .iter()
            .map(|c| match c {
                Node::Path(_) => 1,
                Node::Group(g) => count_paths(g),
                _ => 0,
            })
            .sum()
    }
    assert_eq!(count_paths(root), 2, "both rects painted");
    let mut images = Vec::new();
    find_images(root, &mut images);
    assert_eq!(images.len(), 1, "inline image spliced between them");
}
