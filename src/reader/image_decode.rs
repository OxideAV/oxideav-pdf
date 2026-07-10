//! Image sample decoding (ISO 32000-1 §8.9.5.2) for scene splicing.
//!
//! A PDF image's data stream is "initially decomposed into integers in
//! the domain 0 to 2ⁿ−1, where n is the value of the image dictionary's
//! `BitsPerComponent` entry". Samples pack most-significant-bit first,
//! colour components interleave sample by sample, and "each row of
//! sample data shall begin on a byte boundary" — a row whose data bits
//! are not a multiple of 8 is padded with bits a conforming reader
//! shall ignore (§8.9.3). The `Decode` array then maps each integer
//! linearly into a component value in the image's colour space
//! (§8.9.5.2, defaults per Table 90), and the colour space reduces the
//! component tuple to device RGB — the same
//! [`rgba_from_components`] reduction the `sc`/`scn` path uses.
//!
//! Masking (§8.9.6) is folded into the produced alpha channel:
//!
//! * **Colour-key masking** (§8.9.6.4) tests each pixel's raw
//!   pre-`Decode` codes against the `/Mask` array's `2 × n` ranges —
//!   a pixel whose components all fall inside is not painted.
//! * **Stencil coverage** ([`decode_stencil_coverage`]) decodes the
//!   1-bit-per-sample payload of an `/ImageMask true` stencil
//!   (§8.9.6.2) or an explicit `/Mask` image (§8.9.6.3) to a per-pixel
//!   paint/skip plane: with the default `Decode [0 1]` a sample of 0
//!   marks the page and 1 leaves it unchanged; `Decode [1 0]` reverses
//!   the meanings.

use super::content::{rgba_from_components, ColorSpaceKind};

/// Widths §8.9.5.1 Table 89 permits for `BitsPerComponent`.
fn valid_bpc(bpc: u32) -> bool {
    matches!(bpc, 1 | 2 | 4 | 8 | 16)
}

/// Bytes per image row: `ceil(width × components × bpc / 8)`
/// (§8.9.3 — each row begins on a byte boundary). `None` on overflow.
fn row_stride(width: u32, n_comps: usize, bpc: u32) -> Option<usize> {
    (width as usize)
        .checked_mul(n_comps)?
        .checked_mul(bpc as usize)?
        .checked_add(7)
        .map(|bits| bits / 8)
}

/// Read the `index`-th `bpc`-bit code of a byte-aligned row, MSB-first
/// (§8.9.3: "packed consecutively … high-order bit first").
#[inline]
fn read_code(row: &[u8], index: usize, bpc: u32) -> u16 {
    match bpc {
        8 => row[index] as u16,
        16 => u16::from_be_bytes([row[index * 2], row[index * 2 + 1]]),
        _ => {
            // 1 / 2 / 4 bits — sub-byte packing, high-order bits first.
            let bit = index * bpc as usize;
            let byte = row[bit / 8];
            let shift = 8 - (bit % 8) as u32 - bpc;
            ((byte >> shift) as u16) & ((1u16 << bpc) - 1)
        }
    }
}

/// The Table 90 default `Decode` array for colour space `cs` at
/// `bpc` bits with `n` components: `[0 1]` per component for the
/// device / CIE-A(BC) / Separation / DeviceN families (ICCBased is
/// already reduced to its device alternate upstream), `[0 2ⁿ−1]` for
/// `Indexed` ("component values that index a colour table are passed
/// through unchanged"), and `[0 100 amin amax bmin bmax]` for `Lab`.
fn default_decode(cs: &ColorSpaceKind, bpc: u32, n: usize) -> Vec<f32> {
    match cs {
        ColorSpaceKind::Indexed { .. } => vec![0.0, ((1u32 << bpc) - 1) as f32],
        ColorSpaceKind::Lab { range, .. } => {
            vec![0.0, 100.0, range[0], range[1], range[2], range[3]]
        }
        _ => {
            let mut d = Vec::with_capacity(2 * n);
            for _ in 0..n {
                d.extend_from_slice(&[0.0, 1.0]);
            }
            d
        }
    }
}

/// §8.9.5.2 linear map of an integer sample code onto
/// `[dmin, dmax]`: `y = dmin + x · (dmax − dmin) / (2ⁿ − 1)`.
#[inline]
fn decode_map(code: u16, max_code: f32, dmin: f32, dmax: f32) -> f32 {
    dmin + (code as f32) * (dmax - dmin) / max_code
}

/// Decode a colour image's sample payload to straight RGBA8 (row 0 =
/// the image's top row, §8.9.4).
///
/// * `data` — the filter-decoded stream payload.
/// * `bpc` — `/BitsPerComponent` (1 / 2 / 4 / 8 / 16).
/// * `cs` — the resolved colour space; its component count fixes the
///   per-pixel code count.
/// * `decode` — the `/Decode` array when present (must hold `2 × n`
///   numbers to be honoured; a malformed length falls back to the
///   Table 90 default).
/// * `color_key` — the `/Mask` colour-key ranges (§8.9.6.4), one
///   `(min, max)` pair per component, tested against the raw
///   pre-`Decode` codes; a fully in-range pixel gets alpha 0.
///
/// Returns `None` when the shape is undecodable (unknown colour
/// space, bad `bpc`, short payload, arithmetic overflow) so the image
/// stays on the passthrough surface. A pixel whose colour-space
/// reduction fails (e.g. a `/None` Separation colorant, which
/// produces no visible output) decodes as fully transparent.
pub(crate) fn decode_image_to_rgba(
    data: &[u8],
    width: u32,
    height: u32,
    bpc: u32,
    cs: &ColorSpaceKind,
    decode: Option<&[f32]>,
    color_key: Option<&[(u16, u16)]>,
) -> Option<Vec<u8>> {
    let n = cs.components()?;
    if !valid_bpc(bpc) || width == 0 || height == 0 {
        return None;
    }
    let decode_vec;
    let decode = match decode {
        Some(d) if d.len() == 2 * n => d,
        _ => {
            decode_vec = default_decode(cs, bpc, n);
            &decode_vec
        }
    };
    let key = match color_key {
        Some(k) if k.len() == n => Some(k),
        Some(_) => return None,
        None => None,
    };
    let stride = row_stride(width, n, bpc)?;
    if data.len() < stride.checked_mul(height as usize)? {
        return None;
    }
    let max_code = ((1u32 << bpc) - 1) as f32;
    let mut rgba = Vec::with_capacity((width as usize) * (height as usize) * 4);

    // Fast path: one component at ≤ 8 bits — precompute a code → RGBA
    // lookup table (≤ 256 entries) instead of reducing per pixel. This
    // covers DeviceGray, Indexed, CalGray, and Separation images, where
    // per-pixel tint-transform evaluation would dominate.
    let lut: Option<Vec<[u8; 4]>> = if n == 1 && bpc <= 8 {
        Some(
            (0..=((1u32 << bpc) - 1) as u16)
                .map(|code| {
                    let v = decode_map(code, max_code, decode[0], decode[1]);
                    match rgba_from_components(cs, &[v]) {
                        Some(c) => [c.r, c.g, c.b, c.a],
                        None => [0, 0, 0, 0],
                    }
                })
                .collect(),
        )
    } else {
        None
    };

    let mut comps = vec![0.0f32; n];
    for y in 0..height as usize {
        let row = &data[y * stride..(y + 1) * stride];
        for x in 0..width as usize {
            if let Some(lut) = &lut {
                let code = read_code(row, x, bpc);
                let mut px = lut[code as usize];
                if let Some(key) = key {
                    if key[0].0 <= code && code <= key[0].1 {
                        px[3] = 0;
                    }
                }
                rgba.extend_from_slice(&px);
                continue;
            }
            let mut masked = key.is_some();
            for (c, comp) in comps.iter_mut().enumerate() {
                let code = read_code(row, x * n + c, bpc);
                if let Some(key) = key {
                    masked &= key[c].0 <= code && code <= key[c].1;
                }
                *comp = decode_map(code, max_code, decode[2 * c], decode[2 * c + 1]);
            }
            match rgba_from_components(cs, &comps) {
                Some(c) => rgba.extend_from_slice(&[c.r, c.g, c.b, if masked { 0 } else { c.a }]),
                None => rgba.extend_from_slice(&[0, 0, 0, 0]),
            }
        }
    }
    Some(rgba)
}

/// Decode a 1-bit-per-sample stencil payload (§8.9.6.2) to a per-pixel
/// coverage plane: 255 = mark the page, 0 = leave the previous
/// contents unchanged. With the default `Decode [0 1]` a sample value
/// of 0 marks the page; `decode_flip` (`Decode [1 0]`) reverses the
/// meanings. Rows are byte-aligned (§8.9.3).
pub(crate) fn decode_stencil_coverage(
    data: &[u8],
    width: u32,
    height: u32,
    decode_flip: bool,
) -> Option<Vec<u8>> {
    if width == 0 || height == 0 {
        return None;
    }
    let stride = row_stride(width, 1, 1)?;
    if data.len() < stride.checked_mul(height as usize)? {
        return None;
    }
    let mut coverage = Vec::with_capacity((width as usize) * (height as usize));
    for y in 0..height as usize {
        let row = &data[y * stride..(y + 1) * stride];
        for x in 0..width as usize {
            let bit = (row[x / 8] >> (7 - (x % 8) as u32)) & 1;
            let paint = (bit == 0) != decode_flip;
            coverage.push(if paint { 255 } else { 0 });
        }
    }
    Some(coverage)
}

/// Decode a `/DeviceGray` plane (an image `/SMask`'s alpha source,
/// §11.6.5.3 Table 145) at any supported `bpc`, honouring the
/// `/Decode` array. Each output byte is the decoded gray value scaled
/// to `0..=255`.
pub(crate) fn decode_gray_plane(
    data: &[u8],
    width: u32,
    height: u32,
    bpc: u32,
    decode: Option<&[f32]>,
) -> Option<Vec<u8>> {
    let rgba = decode_image_to_rgba(
        data,
        width,
        height,
        bpc,
        &ColorSpaceKind::DeviceGray,
        decode,
        None,
    )?;
    Some(rgba.chunks_exact(4).map(|px| px[0]).collect())
}

/// Nearest-neighbour resample of a per-pixel plane from `sw × sh` to
/// `dw × dh` (§8.9.6.3: a base image and its mask "need not have the
/// same resolution … but since all images shall be defined on the unit
/// square in user space, their boundaries on the page will coincide").
pub(crate) fn resample_nearest(src: &[u8], sw: u32, sh: u32, dw: u32, dh: u32) -> Option<Vec<u8>> {
    if sw == 0 || sh == 0 || dw == 0 || dh == 0 || src.len() < (sw as usize) * (sh as usize) {
        return None;
    }
    if (sw, sh) == (dw, dh) {
        return Some(src[..(sw as usize) * (sh as usize)].to_vec());
    }
    let mut out = Vec::with_capacity((dw as usize) * (dh as usize));
    for y in 0..dh {
        let sy = (y as u64 * sh as u64 / dh as u64).min(sh as u64 - 1) as usize;
        for x in 0..dw {
            let sx = (x as u64 * sw as u64 / dw as u64).min(sw as u64 - 1) as usize;
            out.push(src[sy * sw as usize + sx]);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gray_1bit_rows_are_byte_aligned() {
        // 3×2 at 1 bpc: each row occupies one byte (3 data bits + 5 pad
        // bits, §8.9.3). Row 0 = 1,0,1  row 1 = 0,1,0.
        let data = [0b1010_0000u8, 0b0100_0000];
        let rgba = decode_image_to_rgba(&data, 3, 2, 1, &ColorSpaceKind::DeviceGray, None, None)
            .expect("decodable");
        let px = |i: usize| &rgba[i * 4..i * 4 + 4];
        assert_eq!(px(0), &[255, 255, 255, 255]); // code 1 → 1.0 → white
        assert_eq!(px(1), &[0, 0, 0, 255]);
        assert_eq!(px(2), &[255, 255, 255, 255]);
        assert_eq!(px(3), &[0, 0, 0, 255]);
        assert_eq!(px(4), &[255, 255, 255, 255]);
        assert_eq!(px(5), &[0, 0, 0, 255]);
    }

    #[test]
    fn decode_array_inverts_gray() {
        // §8.9.5.2 NOTE 3 — Decode [1 0] inverts intensities.
        let data = [0u8, 255];
        let rgba = decode_image_to_rgba(
            &data,
            2,
            1,
            8,
            &ColorSpaceKind::DeviceGray,
            Some(&[1.0, 0.0]),
            None,
        )
        .expect("decodable");
        assert_eq!(&rgba[0..4], &[255, 255, 255, 255]);
        assert_eq!(&rgba[4..8], &[0, 0, 0, 255]);
    }

    #[test]
    fn cmyk_reduces_to_rgb() {
        // Pure cyan (1,0,0,0) → (0,255,255); pure black K → (0,0,0).
        let data = [255u8, 0, 0, 0, 0, 0, 0, 255];
        let rgba = decode_image_to_rgba(&data, 2, 1, 8, &ColorSpaceKind::DeviceCmyk, None, None)
            .expect("decodable");
        assert_eq!(&rgba[0..4], &[0, 255, 255, 255]);
        assert_eq!(&rgba[4..8], &[0, 0, 0, 255]);
    }

    #[test]
    fn indexed_2bit_palette_lookup() {
        // 4-entry RGB palette at 2 bpc; codes pass through unchanged
        // (Table 90 Indexed default [0 2ⁿ−1]).
        let table = vec![
            255, 0, 0, // 0 red
            0, 255, 0, // 1 green
            0, 0, 255, // 2 blue
            255, 255, 0, // 3 yellow
        ];
        let cs = ColorSpaceKind::Indexed {
            base: Box::new(ColorSpaceKind::DeviceRgb),
            hival: 3,
            table,
        };
        // 4×1 pixels: codes 0,1,2,3 → one byte 0b00_01_10_11.
        let data = [0b0001_1011u8];
        let rgba = decode_image_to_rgba(&data, 4, 1, 2, &cs, None, None).expect("decodable");
        assert_eq!(&rgba[0..4], &[255, 0, 0, 255]);
        assert_eq!(&rgba[4..8], &[0, 255, 0, 255]);
        assert_eq!(&rgba[8..12], &[0, 0, 255, 255]);
        assert_eq!(&rgba[12..16], &[255, 255, 0, 255]);
    }

    #[test]
    fn sixteen_bit_big_endian_codes() {
        // 16-bit samples are big-endian ("high-order bit first").
        let data = [0xFFu8, 0xFF, 0x00, 0x00, 0x80, 0x00];
        let rgba = decode_image_to_rgba(&data, 3, 1, 16, &ColorSpaceKind::DeviceGray, None, None)
            .expect("decodable");
        assert_eq!(&rgba[0..4], &[255, 255, 255, 255]);
        assert_eq!(&rgba[4..8], &[0, 0, 0, 255]);
        assert_eq!(rgba[8], 128); // 0x8000/0xFFFF ≈ 0.5
    }

    #[test]
    fn color_key_masks_in_range_codes() {
        // §8.9.6.4 — raw codes tested pre-Decode; all-components-in-
        // range pixels get alpha 0.
        let data = [10u8, 20, 30, 200, 20, 30, 10, 99, 30];
        let key = [(0u16, 50u16), (0, 50), (0, 50)];
        let rgba =
            decode_image_to_rgba(&data, 3, 1, 8, &ColorSpaceKind::DeviceRgb, None, Some(&key))
                .expect("decodable");
        assert_eq!(rgba[3], 0, "all components in range → masked");
        assert_eq!(rgba[7], 255, "red 200 out of range → painted");
        assert_eq!(rgba[11], 255, "green 99 out of range → painted");
    }

    #[test]
    fn stencil_coverage_default_and_flipped() {
        // 2×2 at 1 bpc, one byte per row: samples (1,0) / (0,1).
        let data = [0b1000_0000u8, 0b0100_0000];
        let cov = decode_stencil_coverage(&data, 2, 2, false).expect("decodable");
        // Default Decode [0 1]: 0 marks the page.
        assert_eq!(cov, vec![0, 255, 255, 0]);
        let flipped = decode_stencil_coverage(&data, 2, 2, true).expect("decodable");
        assert_eq!(flipped, vec![255, 0, 0, 255]);
    }

    #[test]
    fn short_payload_is_rejected() {
        assert!(
            decode_image_to_rgba(&[0u8; 5], 2, 2, 8, &ColorSpaceKind::DeviceRgb, None, None)
                .is_none()
        );
        assert!(decode_stencil_coverage(&[0u8], 9, 2, false).is_none());
    }

    #[test]
    fn resample_nearest_scales_plane() {
        let plane = [10u8, 20, 30, 40]; // 2×2
        let up = resample_nearest(&plane, 2, 2, 4, 4).expect("resample");
        assert_eq!(up.len(), 16);
        assert_eq!(up[0], 10);
        assert_eq!(up[3], 20);
        assert_eq!(up[15], 40);
        let same = resample_nearest(&plane, 2, 2, 2, 2).expect("identity");
        assert_eq!(same, plane);
    }
}
