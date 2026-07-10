//! Round-406 image sample-format + masking coverage (ISO 32000-1
//! §8.9.5.2 + §8.9.6).
//!
//! The scene-splicing image decoder now covers the full §8.9.5.2
//! sample model: `/BitsPerComponent` 1 / 2 / 4 / 8 / 16 with
//! byte-aligned rows, the `/Decode` array (Table 90 defaults), every
//! colour space the crate reduces to device RGB (device families,
//! `Indexed`, CIE-based, `Separation` / `DeviceN` tint transforms,
//! named `/Resources /ColorSpace` keys), `/ImageMask` stencils poured
//! with the nonstroking colour (§8.9.6.2), explicit `/Mask` stencil
//! streams (§8.9.6.3), colour-key `/Mask` ranges (§8.9.6.4), and the
//! Table 89 rule that `/SMask` overrides `/Mask`.

use oxideav_core::vector::{Group, ImageRef, Node};
use oxideav_pdf::read_pdf_to_scene;

/// Assemble a classic-xref PDF from numbered object bodies (each body
/// is everything between `N 0 obj` and `endobj`). Object 1 must be the
/// catalog.
fn build_pdf(objects: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<(u32, usize)> = Vec::new();
    for (num, body) in objects {
        offsets.push((*num, buf.len()));
        buf.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        buf.extend_from_slice(body);
        buf.extend_from_slice(b"\nendobj\n");
    }
    let n = objects.iter().map(|(num, _)| *num).max().unwrap_or(0) + 1;
    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n");
    buf.extend_from_slice(format!("0 {n}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for num in 1..n {
        let off = offsets
            .iter()
            .find(|(o, _)| *o == num)
            .map(|(_, off)| *off)
            .unwrap_or(0);
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(b"trailer\n");
    buf.extend_from_slice(format!("<< /Size {n} /Root 1 0 R >>\n").as_bytes());
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

fn stream_obj(dict_body: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("<< {} /Length {} >>\nstream\n", dict_body, payload.len()).as_bytes(),
    );
    body.extend_from_slice(payload);
    body.extend_from_slice(b"\nendstream");
    body
}

/// One-page document scaffold: catalog (1), pages (2), page (3) with
/// `/Resources` body `resources`, contents (4) = `content`. Extra
/// objects (5+) follow.
fn one_page_pdf(resources: &str, content: &[u8], extra: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    let mut objects: Vec<(u32, Vec<u8>)> = vec![
        (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
        (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>".to_vec()),
        (
            3,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
                 /Resources << {resources} >> /Contents 4 0 R >>"
            )
            .into_bytes(),
        ),
        (4, stream_obj("", content)),
    ];
    objects.extend(extra);
    build_pdf(&objects)
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

fn single_image(pdf: &[u8]) -> ImageRef {
    let scene = read_pdf_to_scene(pdf).expect("read");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let mut images = Vec::new();
    find_images(root, &mut images);
    assert_eq!(images.len(), 1, "exactly one spliced image expected");
    images.remove(0)
}

fn pixels(img: &ImageRef) -> Vec<[u8; 4]> {
    img.frame.planes[0]
        .data
        .chunks_exact(4)
        .map(|c| [c[0], c[1], c[2], c[3]])
        .collect()
}

#[test]
fn gray_4bit_decode_inverted_rows_byte_aligned() {
    // 3×2 at 4 bpc DeviceGray: each row = 12 data bits → 2 bytes
    // (§8.9.3 byte-aligned rows). Decode [1 0] inverts (§8.9.5.2
    // NOTE 3). Row 0 codes: 0x0, 0xF, 0x8; row 1: 0xF, 0x0, 0xF.
    let data = [0x0Fu8, 0x80, 0xF0, 0xF0];
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![(
            5,
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 3 /Height 2 \
                 /ColorSpace /DeviceGray /BitsPerComponent 4 /Decode [1 0]",
                &data,
            ),
        )],
    );
    let img = single_image(&pdf);
    assert_eq!((img.bounds.width, img.bounds.height), (3.0, 2.0));
    let px = pixels(&img);
    assert_eq!(px[0], [255, 255, 255, 255], "code 0 inverted → white");
    assert_eq!(px[1], [0, 0, 0, 255], "code 15 inverted → black");
    assert_eq!(px[2][0], 119, "code 8 → 1 − 8/15 ≈ 0.467 → 119");
    assert_eq!(px[3], [0, 0, 0, 255]);
    assert_eq!(px[4], [255, 255, 255, 255]);
    assert_eq!(px[5], [0, 0, 0, 255]);
}

#[test]
fn cmyk_16bit_image_reduces_to_rgb() {
    // 2×1 at 16 bpc DeviceCMYK, big-endian codes: pure cyan and pure
    // key-black.
    let data = [
        0xFFu8, 0xFF, 0, 0, 0, 0, 0, 0, // (1,0,0,0) cyan
        0, 0, 0, 0, 0, 0, 0xFF, 0xFF, // (0,0,0,1) black
    ];
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![(
            5,
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                 /ColorSpace /DeviceCMYK /BitsPerComponent 16",
                &data,
            ),
        )],
    );
    let px = pixels(&single_image(&pdf));
    assert_eq!(px[0], [0, 255, 255, 255], "cyan");
    assert_eq!(px[1], [0, 0, 0, 255], "key black");
}

#[test]
fn indexed_2bit_image_via_named_color_space() {
    // The image /ColorSpace is a *name* resolved through the page's
    // /Resources /ColorSpace subdictionary (§8.9.5.2), an Indexed
    // space with an inline hex lookup string. 4×1 at 2 bpc — codes
    // 0..3 pass through unchanged (Table 90 Indexed default).
    let data = [0b0001_1011u8];
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >> \
         /ColorSpace << /Pal [/Indexed /DeviceRGB 3 \
         <FF0000 00FF00 0000FF FFFF00>] >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![(
            5,
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 4 /Height 1 \
                 /ColorSpace /Pal /BitsPerComponent 2",
                &data,
            ),
        )],
    );
    let px = pixels(&single_image(&pdf));
    assert_eq!(px[0], [255, 0, 0, 255]);
    assert_eq!(px[1], [0, 255, 0, 255]);
    assert_eq!(px[2], [0, 0, 255, 255]);
    assert_eq!(px[3], [255, 255, 0, 255]);
}

#[test]
fn separation_image_through_type2_tint_transform() {
    // A /Separation colour space with an exponential (Type 2) tint
    // transform into DeviceRGB: tint 0 → C0 (white), tint 1 → C1
    // (full red). 2×1 at 8 bpc.
    let data = [0u8, 255];
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![(
            5,
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                 /ColorSpace [/Separation /Spot /DeviceRGB \
                 << /FunctionType 2 /Domain [0 1] /N 1 \
                 /C0 [1 1 1] /C1 [1 0 0] >>] /BitsPerComponent 8",
                &data,
            ),
        )],
    );
    let px = pixels(&single_image(&pdf));
    assert_eq!(px[0], [255, 255, 255, 255], "tint 0 → C0 white");
    assert_eq!(px[1], [255, 0, 0, 255], "tint 1 → C1 red");
}

#[test]
fn image_mask_stencil_paints_nonstroking_color() {
    // §8.9.6.2 — /ImageMask true: with the default Decode [0 1] a
    // sample of 0 marks the page with the current nonstroking colour
    // and 1 leaves it unchanged. 2×2 at the mandatory 1 bpc; the
    // content stream sets an orange fill before Do.
    let data = [0b0100_0000u8, 0b1000_0000]; // rows: (0,1) / (1,0)
    let pdf = one_page_pdf(
        "/XObject << /St 5 0 R >>",
        b"q 1.0 0.5 0.0 rg 100 0 0 100 0 0 cm /St Do Q",
        vec![(
            5,
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 2 /Height 2 \
                 /ImageMask true /BitsPerComponent 1",
                &data,
            ),
        )],
    );
    let px = pixels(&single_image(&pdf));
    assert_eq!(px[0], [255, 128, 0, 255], "sample 0 → orange fill");
    assert_eq!(px[1][3], 0, "sample 1 → masked out");
    assert_eq!(px[2][3], 0);
    assert_eq!(px[3], [255, 128, 0, 255]);
}

#[test]
fn image_mask_stencil_decode_flip() {
    // Decode [1 0] reverses the stencil meanings (§8.9.6.2).
    let data = [0b1000_0000u8];
    let pdf = one_page_pdf(
        "/XObject << /St 5 0 R >>",
        b"q 0 0 1 rg 100 0 0 100 0 0 cm /St Do Q",
        vec![(
            5,
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                 /ImageMask true /Decode [1 0]",
                &data,
            ),
        )],
    );
    let px = pixels(&single_image(&pdf));
    assert_eq!(px[0], [0, 0, 255, 255], "sample 1 flipped → painted blue");
    assert_eq!(px[1][3], 0, "sample 0 flipped → masked");
}

#[test]
fn explicit_mask_stream_masks_base_image() {
    // §8.9.6.3 — the /Mask entry is an /ImageMask stencil at a
    // *different* resolution (1×1 → resampled onto the 2×1 base):
    // decoded sample 1 masks everything out here.
    let base = [255u8, 0, 0, 0, 255, 0]; // red, green
    let mask = [0b1000_0000u8]; // sample 1 → masked (default Decode)
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![
            (
                5,
                stream_obj(
                    "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                     /ColorSpace /DeviceRGB /BitsPerComponent 8 /Mask 6 0 R",
                    &base,
                ),
            ),
            (
                6,
                stream_obj(
                    "/Type /XObject /Subtype /Image /Width 1 /Height 1 \
                     /ImageMask true",
                    &mask,
                ),
            ),
        ],
    );
    let px = pixels(&single_image(&pdf));
    assert_eq!(px[0], [255, 0, 0, 0], "masked out, colour retained");
    assert_eq!(px[1], [0, 255, 0, 0], "masked out");
}

#[test]
fn color_key_mask_ranges_test_raw_codes() {
    // §8.9.6.4 — /Mask [ min max … ] masks pixels whose *pre-Decode*
    // codes all fall in range. Green (0,255,0) falls inside
    // [0 50 200 255 0 50]; red and blue do not.
    let base = [
        255u8, 0, 0, // red — R out of range
        0, 255, 0, // green — masked
        0, 0, 255, // blue — G and B out of range
    ];
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![(
            5,
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 3 /Height 1 \
                 /ColorSpace /DeviceRGB /BitsPerComponent 8 \
                 /Mask [0 50 200 255 0 50]",
                &base,
            ),
        )],
    );
    let px = pixels(&single_image(&pdf));
    assert_eq!(px[0], [255, 0, 0, 255], "red painted");
    assert_eq!(px[1], [0, 255, 0, 0], "green colour-key masked");
    assert_eq!(px[2], [0, 0, 255, 255], "blue painted");
}

#[test]
fn smask_overrides_mask_per_table_89() {
    // Table 89: a /SMask "shall override the current soft mask in the
    // graphics state as well as the image's Mask entry". The colour
    // key below would mask every pixel; the 2-pixel /SMask must win.
    let base = [10u8, 10, 10, 10, 10, 10];
    let smask = [255u8, 64];
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![
            (
                5,
                stream_obj(
                    "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                     /ColorSpace /DeviceRGB /BitsPerComponent 8 \
                     /Mask [0 20 0 20 0 20] /SMask 6 0 R",
                    &base,
                ),
            ),
            (
                6,
                stream_obj(
                    "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                     /ColorSpace /DeviceGray /BitsPerComponent 8",
                    &smask,
                ),
            ),
        ],
    );
    let px = pixels(&single_image(&pdf));
    assert_eq!(px[0][3], 255, "SMask alpha wins over colour key");
    assert_eq!(px[1][3], 64);
}

#[test]
fn smask_low_bit_depth_with_decode() {
    // The /SMask path now honours sub-byte /BitsPerComponent and its
    // own /Decode array: 2×1 at 1 bpc with Decode [1 0] — code 0 →
    // alpha 1.0, code 1 → alpha 0.0.
    let base = [200u8, 100, 50, 50, 100, 200];
    let smask = [0b0100_0000u8]; // codes 0, 1
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![
            (
                5,
                stream_obj(
                    "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                     /ColorSpace /DeviceRGB /BitsPerComponent 8 /SMask 6 0 R",
                    &base,
                ),
            ),
            (
                6,
                stream_obj(
                    "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                     /ColorSpace /DeviceGray /BitsPerComponent 1 /Decode [1 0]",
                    &smask,
                ),
            ),
        ],
    );
    let px = pixels(&single_image(&pdf));
    assert_eq!(px[0], [200, 100, 50, 255]);
    assert_eq!(px[1], [50, 100, 200, 0]);
}

#[test]
fn calgray_image_reduces_through_cie_pipeline() {
    // An 8-bpc /CalGray image (D65 white point, gamma 1): black and
    // white endpoints must land exactly; the CIE reduction handles the
    // rest.
    let data = [0u8, 255];
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![(
            5,
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                 /ColorSpace [/CalGray << /WhitePoint [0.9505 1.0 1.089] >>] \
                 /BitsPerComponent 8",
                &data,
            ),
        )],
    );
    let px = pixels(&single_image(&pdf));
    assert_eq!(px[0], [0, 0, 0, 255], "gray 0 → black");
    assert_eq!(px[1][3], 255);
    assert!(px[1][0] > 250, "gray 1 → white-ish, got {:?}", px[1]);
}

#[test]
fn lab_image_uses_range_scaled_decode_default() {
    // A /Lab image's default Decode is [0 100 amin amax bmin bmax]
    // (Table 90). Code 255 on L* with a*/b* mid-range (0 under the
    // symmetric default range) must land near white; code 0 near
    // black.
    let data = [255u8, 128, 128, 0, 128, 128];
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![(
            5,
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                 /ColorSpace [/Lab << /WhitePoint [0.9505 1.0 1.089] \
                 /Range [-100 100 -100 100] >>] /BitsPerComponent 8",
                &data,
            ),
        )],
    );
    let px = pixels(&single_image(&pdf));
    assert!(
        px[0][0] > 240 && px[0][1] > 240 && px[0][2] > 240,
        "L*=100 a*≈0 b*≈0 → near white, got {:?}",
        px[0]
    );
    assert!(
        px[1][0] < 15 && px[1][1] < 15 && px[1][2] < 15,
        "L*=0 → near black, got {:?}",
        px[1]
    );
}

#[test]
fn device_n_image_through_type4_tint_transform() {
    // A 2-colorant /DeviceN image mapped into DeviceRGB by a Type 4
    // (PostScript calculator) tint transform: r = t1, g = t2, b = 0.
    let data = [
        255u8, 0, // (1, 0) → red
        0, 255, // (0, 1) → green
        255, 255, // (1, 1) → yellow
    ];
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![
            (
                5,
                stream_obj(
                    "/Type /XObject /Subtype /Image /Width 3 /Height 1 \
                     /ColorSpace [/DeviceN [/InkA /InkB] /DeviceRGB 6 0 R] \
                     /BitsPerComponent 8",
                    &data,
                ),
            ),
            (
                6,
                // The two tints stay on the operand stack; pushing 0
                // yields exactly (t1, t2, 0) as the RGB outputs.
                stream_obj(
                    "/FunctionType 4 /Domain [0 1 0 1] /Range [0 1 0 1 0 1]",
                    b"{ 0 }",
                ),
            ),
        ],
    );
    let px = pixels(&single_image(&pdf));
    assert_eq!(px[0], [255, 0, 0, 255], "tints (1,0) → red");
    assert_eq!(px[1], [0, 255, 0, 255], "tints (0,1) → green");
    assert_eq!(px[2], [255, 255, 0, 255], "tints (1,1) → yellow");
}

#[test]
fn unknown_color_space_stays_passthrough() {
    // A colour space the crate can't reduce (bare /Pattern) leaves the
    // image on the passthrough surface — no scene splice, no panic.
    let data = [0u8; 4];
    let pdf = one_page_pdf(
        "/XObject << /Im0 5 0 R >>",
        b"q 100 0 0 100 0 0 cm /Im0 Do Q",
        vec![(
            5,
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 2 /Height 2 \
                 /ColorSpace /Pattern /BitsPerComponent 8",
                &data,
            ),
        )],
    );
    let scene = read_pdf_to_scene(&pdf).expect("read");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let mut images = Vec::new();
    find_images(root, &mut images);
    assert!(images.is_empty(), "Pattern-space image is not spliced");
}
