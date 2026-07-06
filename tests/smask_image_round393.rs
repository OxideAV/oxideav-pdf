//! Round-393 soft-mask *image* surfacing (ISO 32000-1 §11.6.5.3
//! "Soft-Mask Images", Tables 145 + 146).
//!
//! An image XObject may carry its own per-sample alpha as a subsidiary
//! image XObject in its `/SMask` entry ("This mask, if present, shall
//! override any explicit or colour key mask specified by the image
//! dictionary's Mask entry"). The `image_xobjects()` walker now
//! surfaces it: `PdfImageXObject.smask` carries the subsidiary's
//! dimensions, `/BitsPerComponent`, the decoded gray samples (when the
//! filter chain is decodable), and the `/Matte` preblending colour
//! (Table 146) when the parent's samples were premultiplied.

use oxideav_pdf::reader::DocumentReader;

// Minimal JPEG payload — the walker surfaces DCTDecode streams
// verbatim without validating them, so a marker-only stub suffices.
const JPEG_STUB: &[u8] = &[0xff, 0xd8, 0xff, 0xd9];

/// Gray mask samples: a 4×4 ramp, stored unfiltered.
const MASK_SAMPLES: &[u8] = &[
    0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240,
];

fn build_pdf(smask_ref: &str, matte: &str) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<(u32, usize)> = Vec::new();

    offsets.push((1, buf.len()));
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets.push((2, buf.len()));
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");

    offsets.push((3, buf.len()));
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
          /Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>\nendobj\n",
    );

    let content = b"q 100 0 0 100 0 0 cm /Im0 Do Q\n";
    offsets.push((4, buf.len()));
    buf.extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    // 5 = the parent DCTDecode image, carrying /SMask.
    offsets.push((5, buf.len()));
    buf.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XObject /Subtype /Image /Width 8 /Height 8 \
             /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode \
             {smask_ref}/Length {} >>\nstream\n",
            JPEG_STUB.len()
        )
        .as_bytes(),
    );
    buf.extend_from_slice(JPEG_STUB);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    // 6 = the subsidiary soft-mask image (Table 145: /DeviceGray).
    offsets.push((6, buf.len()));
    buf.extend_from_slice(
        format!(
            "6 0 obj\n<< /Type /XObject /Subtype /Image /Width 4 /Height 4 \
             /ColorSpace /DeviceGray /BitsPerComponent 8 {matte}/Length {} >>\nstream\n",
            MASK_SAMPLES.len()
        )
        .as_bytes(),
    );
    buf.extend_from_slice(MASK_SAMPLES);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    // xref + trailer.
    let n = offsets.len() + 1;
    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n");
    buf.extend_from_slice(format!("0 {n}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for (_, off) in &offsets {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(b"trailer\n");
    buf.extend_from_slice(format!("<< /Size {n} /Root 1 0 R >>\n").as_bytes());
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

#[test]
fn smask_image_surfaces_on_the_walker() {
    let pdf = build_pdf("/SMask 6 0 R ", "/Matte [0.5 0.25 0.75] ");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let images = reader.image_xobjects().expect("walk");
    assert_eq!(images.len(), 1);
    let (_, img) = &images[0];
    assert_eq!(img.data, JPEG_STUB, "parent JPEG payload untouched");

    let smask = img.smask.as_ref().expect("soft-mask image surfaced");
    assert_eq!((smask.width, smask.height), (4, 4));
    assert_eq!(smask.bits_per_component, 8);
    assert_eq!(
        smask.data.as_deref(),
        Some(MASK_SAMPLES),
        "unfiltered gray samples decode verbatim"
    );
    assert_eq!(
        smask.matte.as_deref(),
        Some(&[0.5, 0.25, 0.75][..]),
        "the Table 146 /Matte preblending colour"
    );
}

#[test]
fn image_without_smask_surfaces_none() {
    let pdf = build_pdf("", "");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let images = reader.image_xobjects().expect("walk");
    assert_eq!(images.len(), 1);
    assert!(images[0].1.smask.is_none(), "no /SMask entry → None");
}

#[test]
fn smask_without_matte_surfaces_none_matte() {
    let pdf = build_pdf("/SMask 6 0 R ", "");
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let images = reader.image_xobjects().expect("walk");
    let smask = images[0].1.smask.as_ref().expect("smask surfaced");
    assert!(smask.matte.is_none(), "not preblended → no matte");
}
