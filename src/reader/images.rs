//! JPEG-passthrough Image XObject extraction (round 23).
//!
//! Walks every page's `/Resources /XObject` subdict and surfaces every
//! Image XObject whose `/Filter` is `/DCTDecode` (with optional
//! upstream wrapping filters such as `/ASCII85Decode` or
//! `/ASCIIHexDecode`). The returned [`PdfImageXObject`] carries the
//! raw JPEG bytes — the unmodified DCT-encoded payload, ready to be
//! handed to a JPEG decoder (`oxideav-jpeg`, `image-rs`, libjpeg,
//! poppler's `pdfimages -all`, …) without any further filter step.
//!
//! ## Why JPEG passthrough specifically
//!
//! ISO 32000-1 §7.4.8 (DCTDecode) says the encoded data is a JPEG-1
//! interchange-format stream as defined in ISO/IEC 10918-1 (the
//! original "JFIF" Huffman-table-included shape). PDF readers don't
//! transcode it — they hand it straight to the platform JPEG
//! decoder. That makes the per-XObject byte payload, after the
//! upstream ASCII filters are unwrapped (if any), a self-contained
//! JFIF / JPEG-1 file. Dumping it verbatim is the standard
//! "extract JPEGs from a PDF" tool path (`pdfimages -all` works the
//! same way — it's what the round-23 cross-check exercises).
//!
//! ## Out of scope for round 23
//!
//! - **Re-encoding.** We don't decode the JPEG and we don't re-emit it.
//!   The point is to expose the bytes so a downstream JPEG decoder can
//!   take over.
//! - **Inline images** (`BI ... ID ... EI`, §8.9.7). Round 23 only
//!   walks XObjects — inline images are a content-stream-level concern
//!   and would land in the content-stream walker.
//! - **JBIG2, JPEG2000 (JPXDecode), CCITT Fax** (§7.4.9 / §7.4.10 /
//!   §7.4.7). Each is a separate filter; round 23 only handles
//!   `/DCTDecode`. The walker silently skips XObjects with other
//!   `/Filter` values so it stays composable as more filters are
//!   added.
//! - **/Decode** (per-component clamp / negate). DCTDecode JPEGs in
//!   the wild rarely carry one; when present, the decoder takes the
//!   array directly. We don't apply it on the way out — the caller
//!   gets the raw JPEG bytes.
//!
//! ## Provenance
//!
//! ISO 32000-1:2008 §7.4 (Filters), §7.4.2 (ASCIIHexDecode), §7.4.3
//! (ASCII85Decode), §7.4.8 (DCTDecode), §8.9 (Image XObjects). No
//! third-party PDF library was consulted.

use std::collections::HashSet;

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::reader::document::DocumentReader;

// ────────────────────────── public surface ──────────────────────────

/// Color-space tag attached to a [`PdfImageXObject`].
///
/// PDF colour-space objects are richer than this enum — a real
/// renderer needs to track ICC profiles, calibrated RGB, lab, etc. —
/// but for JPEG passthrough we only need to surface the four most
/// common families a JPEG can claim to be in (the JPEG payload itself
/// dictates whether it's 1-channel grayscale, 3-channel YCbCr→RGB, or
/// 4-channel CMYK; the PDF /ColorSpace is a hint to the JPEG decoder
/// about how the channels should be re-interpreted on the page).
///
/// `Indexed` is the special case where the PDF wraps a JPEG (which is
/// itself grayscale or RGB) inside an indexed color space — it's
/// vanishingly rare with DCTDecode, but we surface the variant so
/// downstream code can detect + special-case it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ColorSpace {
    /// `/DeviceRGB` — 3 channels, non-calibrated RGB.
    DeviceRGB,
    /// `/DeviceCMYK` — 4 channels, non-calibrated CMYK. JPEGs in CMYK
    /// are common in prepress workflows; the JPEG decoder needs to
    /// know not to apply YCbCr→RGB on the 4-channel form.
    DeviceCMYK,
    /// `/DeviceGray` — 1 channel, non-calibrated grayscale.
    DeviceGray,
    /// `[/Indexed <base> <hival> <lookup>]` — palette-based color
    /// space. The JPEG payload is itself either gray or RGB; the
    /// indexed wrapper applies on the PDF side.
    Indexed,
    /// Anything else (ICCBased, CalGray, CalRGB, Lab, Pattern,
    /// Separation, DeviceN, …). The JPEG bytes are still valid; the
    /// caller may need to consult an ICC profile to render the page
    /// accurately.
    Other(String),
}

impl ColorSpace {
    fn from_object(obj: &Object) -> Self {
        match obj {
            Object::Name(n) => match n.as_str() {
                "DeviceRGB" | "RGB" => ColorSpace::DeviceRGB,
                "DeviceCMYK" | "CMYK" => ColorSpace::DeviceCMYK,
                "DeviceGray" | "G" => ColorSpace::DeviceGray,
                other => ColorSpace::Other(other.to_owned()),
            },
            Object::Array(items) => match items.first() {
                Some(Object::Name(n)) if n == "Indexed" => ColorSpace::Indexed,
                Some(Object::Name(n)) => ColorSpace::Other(n.clone()),
                _ => ColorSpace::Other(String::new()),
            },
            _ => ColorSpace::Other(String::new()),
        }
    }
}

/// A JPEG-passthrough Image XObject surfaced by
/// [`DocumentReader::image_xobjects`].
///
/// `data` is the raw, ready-to-decode JPEG byte sequence — exactly
/// the bytes a JPEG decoder needs to reconstruct the image. Any
/// upstream wrapping filters (e.g. `/ASCII85Decode` in `/Filter
/// [/ASCII85Decode /DCTDecode]`) have been peeled off; the trailing
/// `/DCTDecode` filter is left as-is because applying it *is* the
/// JPEG decode step.
///
/// `width` / `height` come from the XObject's `/Width` / `/Height`
/// entries (§8.9.5.1) — the PDF dictionary's authoritative values.
/// They should match the JPEG's intrinsic SOF0 marker dimensions; if
/// they don't, the PDF dictionary wins for layout and the decoder
/// re-samples on the way out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdfImageXObject {
    /// Raw JPEG bytes — a self-contained JPEG-1 / JFIF stream ready
    /// to be passed to a JPEG decoder.
    pub data: Vec<u8>,
    /// `/Width` from the XObject dict.
    pub width: u32,
    /// `/Height` from the XObject dict.
    pub height: u32,
    /// `/ColorSpace` mapped to a [`ColorSpace`] tag.
    pub color_space: ColorSpace,
    /// `/BitsPerComponent` — 8 for the JPEG-1 baseline path; 12 for
    /// the (rare) DCTDecode-with-12-bit-extended-process JPEGs.
    /// Defaults to 8 when the dict is silent (the spec says it's
    /// required, but real-world PDFs occasionally omit it for
    /// JPEG XObjects since the JPEG itself carries the value).
    pub bits_per_component: u8,
}

impl<'a> DocumentReader<'a> {
    /// Walk every page's resource tree and return every JPEG-passthrough
    /// Image XObject in stream order — one entry per surfaced
    /// `(ObjectRef, PdfImageXObject)` pair. The same XObject referenced
    /// from multiple pages is returned once (deduplicated by
    /// [`ObjectId`]) so callers don't have to filter.
    ///
    /// Image XObjects with non-DCTDecode filters (FlateDecode,
    /// CCITTFaxDecode, JBIG2Decode, JPXDecode, …) are silently skipped
    /// — they exist on the page but aren't part of the JPEG passthrough
    /// surface this round delivers.
    ///
    /// See module documentation for the byte-level contract.
    pub fn image_xobjects(&mut self) -> Result<Vec<(ObjectId, PdfImageXObject)>, PdfError> {
        image_xobjects(self)
    }
}

// ────────────────────────── walker ──────────────────────────

pub fn image_xobjects(
    reader: &mut DocumentReader<'_>,
) -> Result<Vec<(ObjectId, PdfImageXObject)>, PdfError> {
    let root_id = reader.xref().root()?;
    let catalog_obj = reader.resolve(root_id)?;
    let Object::Dict(catalog) = catalog_obj else {
        return Err(PdfError::other(format!(
            "PDF image extraction: /Root must be a dictionary (got {catalog_obj:?})"
        )));
    };
    let pages_ref = catalog
        .entries()
        .iter()
        .find(|(k, _)| k == "Pages")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| PdfError::other("PDF image extraction: catalog missing /Pages"))?;
    let Object::Reference(pages_root_id) = pages_ref else {
        return Err(PdfError::other(format!(
            "PDF image extraction: catalog /Pages must be a reference (got {pages_ref:?})"
        )));
    };
    let mut leaves = Vec::new();
    walk_pages(reader, pages_root_id, &mut leaves)?;
    let mut out = Vec::new();
    let mut seen: HashSet<ObjectId> = HashSet::new();
    for leaf in leaves {
        collect_page_xobjects(reader, leaf, &mut out, &mut seen)?;
    }
    Ok(out)
}

fn walk_pages(
    reader: &mut DocumentReader<'_>,
    node_id: ObjectId,
    out: &mut Vec<ObjectId>,
) -> Result<(), PdfError> {
    let node = reader.resolve(node_id)?;
    let Object::Dict(d) = node else {
        return Err(PdfError::other(format!(
            "PDF image extraction: /Pages node {node_id:?} is not a dict"
        )));
    };
    let kind = d
        .entries()
        .iter()
        .find(|(k, _)| k == "Type")
        .and_then(|(_, v)| match v {
            Object::Name(s) => Some(s.as_str()),
            _ => None,
        });
    match kind {
        Some("Page") => {
            out.push(node_id);
            Ok(())
        }
        Some("Pages") => {
            let kids = d
                .entries()
                .iter()
                .find(|(k, _)| k == "Kids")
                .map(|(_, v)| v.clone())
                .ok_or_else(|| {
                    PdfError::other(format!(
                        "PDF image extraction: /Pages node {node_id:?} missing /Kids"
                    ))
                })?;
            let Object::Array(items) = kids else {
                return Err(PdfError::other(format!(
                    "PDF image extraction: /Kids must be an array on {node_id:?}"
                )));
            };
            for item in items {
                if let Object::Reference(id) = item {
                    walk_pages(reader, id, out)?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn collect_page_xobjects(
    reader: &mut DocumentReader<'_>,
    page_id: ObjectId,
    out: &mut Vec<(ObjectId, PdfImageXObject)>,
    seen: &mut HashSet<ObjectId>,
) -> Result<(), PdfError> {
    let page_obj = reader.resolve(page_id)?;
    let Object::Dict(page_dict) = page_obj else {
        return Ok(());
    };

    let resources = page_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Resources")
        .map(|(_, v)| v.clone());
    let resources = match resources {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(()),
    };
    let Object::Dict(rdict) = resources else {
        return Ok(());
    };

    let xobject_obj = rdict
        .entries()
        .iter()
        .find(|(k, _)| k == "XObject")
        .map(|(_, v)| v.clone());
    let Some(xobject_obj) = xobject_obj else {
        return Ok(());
    };
    let xobject_obj = match xobject_obj {
        Object::Reference(id) => reader.resolve(id)?,
        other => other,
    };
    let Object::Dict(xobject_dict) = xobject_obj else {
        return Ok(());
    };

    // Per /Resources /XObject entry: (resource-name → reference-to-XObject-stream).
    // Only direct references are surfaced; inline streams under a
    // resource name aren't a shape the writer emits and aren't a shape
    // §8.9 documents (XObjects must be indirect objects).
    let entries: Vec<(String, ObjectId)> = xobject_dict
        .entries()
        .iter()
        .filter_map(|(name, val)| match val {
            Object::Reference(id) => Some((name.clone(), *id)),
            _ => None,
        })
        .collect();
    for (_name, id) in entries {
        if !seen.insert(id) {
            continue;
        }
        let resolved = reader.resolve(id)?;
        if let Some(jpeg) = try_extract_jpeg(reader, &resolved)? {
            out.push((id, jpeg));
        }
    }
    Ok(())
}

/// If `obj` is an Image XObject whose /Filter chain ends in
/// `/DCTDecode` (with no other terminal filter), return the
/// passthrough payload; otherwise return `Ok(None)`.
fn try_extract_jpeg(
    reader: &mut DocumentReader<'_>,
    obj: &Object,
) -> Result<Option<PdfImageXObject>, PdfError> {
    let Object::Stream(s) = obj else {
        return Ok(None);
    };
    // Subtype must be /Image (XObjects are tagged with /Type /XObject
    // + /Subtype /Image per §8.8 / §8.9.5). /Type /XObject is required
    // by the spec but real-world writers occasionally omit it; we
    // accept either presence.
    let subtype = s.dict.entries().iter().find(|(k, _)| k == "Subtype");
    if !matches!(subtype, Some((_, Object::Name(n))) if n == "Image") {
        return Ok(None);
    }

    // /Filter is required for DCTDecode XObjects (the whole point is
    // to defer decoding). Accept a single-name `/Filter /DCTDecode` or
    // an array form `[ ... /DCTDecode ]`. The DCTDecode filter must be
    // the last entry — anything after it would attempt to interpret
    // the JPEG output as something else, which the spec doesn't define.
    let filter = s
        .dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Filter")
        .map(|(_, v)| v);
    let chain: Vec<String> = match filter {
        Some(Object::Name(n)) => vec![n.clone()],
        Some(Object::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let Object::Name(n) = item else {
                    return Ok(None);
                };
                out.push(n.clone());
            }
            out
        }
        _ => return Ok(None),
    };
    let Some(last) = chain.last() else {
        return Ok(None);
    };
    if last != "DCTDecode" {
        return Ok(None);
    }

    // Apply every filter *up to but not including* the trailing DCTDecode.
    let mut payload = s.data.clone();
    for filter_name in &chain[..chain.len() - 1] {
        payload = match filter_name.as_str() {
            "ASCII85Decode" | "A85" => decode_ascii85(&payload)?,
            "ASCIIHexDecode" | "AHx" => decode_ascii_hex(&payload)?,
            "FlateDecode" | "Fl" => flate_decompress(&payload)?,
            // Other wrapping filters (LZWDecode, RunLengthDecode,
            // CCITTFaxDecode, …) are not in scope for round 23 — surface
            // the XObject as "not JPEG passthrough" so the caller
            // doesn't get a corrupted stream.
            _ => return Ok(None),
        };
    }

    // Width / Height (§8.9.5.1) — required, integers.
    let width = lookup_int(&s.dict, "Width")
        .ok_or_else(|| PdfError::other("PDF image extraction: Image XObject missing /Width"))?;
    let height = lookup_int(&s.dict, "Height")
        .ok_or_else(|| PdfError::other("PDF image extraction: Image XObject missing /Height"))?;
    if width < 0 || height < 0 {
        return Err(PdfError::other(format!(
            "PDF image extraction: negative /Width or /Height ({width}, {height})"
        )));
    }

    // /ColorSpace — required for image XObjects unless /ImageMask true
    // (§8.9.5.1). Resolve a reference if it is one. Default to
    // DeviceRGB so we always return *some* tag for a malformed file.
    let cs_obj = s
        .dict
        .entries()
        .iter()
        .find(|(k, _)| k == "ColorSpace")
        .map(|(_, v)| v.clone());
    let cs_obj = match cs_obj {
        Some(Object::Reference(id)) => Some(reader.resolve(id)?),
        other => other,
    };
    let color_space = match cs_obj {
        Some(o) => ColorSpace::from_object(&o),
        None => ColorSpace::DeviceRGB,
    };

    // /BitsPerComponent — 8 for baseline JPEG, 12 for the extended
    // 12-bit process. Default to 8 when omitted (some real-world PDFs
    // do that for JPEG XObjects since the JPEG itself carries it).
    let bpc = lookup_int(&s.dict, "BitsPerComponent").unwrap_or(8);
    if !(1..=16).contains(&bpc) {
        return Err(PdfError::other(format!(
            "PDF image extraction: implausible /BitsPerComponent {bpc}"
        )));
    }

    Ok(Some(PdfImageXObject {
        data: payload,
        width: width as u32,
        height: height as u32,
        color_space,
        bits_per_component: bpc as u8,
    }))
}

fn lookup_int(d: &Dict, key: &str) -> Option<i64> {
    d.entries()
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            Object::Integer(n) => Some(*n),
            Object::Real(f) => Some(*f as i64),
            _ => None,
        })
}

// ────────────────────────── filter unwrappers ──────────────────────────

fn flate_decompress(input: &[u8]) -> Result<Vec<u8>, PdfError> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut out = Vec::new();
    let mut dec = ZlibDecoder::new(input);
    dec.read_to_end(&mut out)
        .map_err(|e| PdfError::other(format!("PDF image extraction: FlateDecode failed: {e}")))?;
    Ok(out)
}

/// ASCII85Decode (ISO 32000-1 §7.4.3) — five base-85 ASCII characters
/// in the range `!`..`u` encode four bytes. `z` is a shorthand for
/// four zero bytes. Whitespace is ignored. The stream ends at `~>`.
/// Partial groups are padded with `u` (84) on encode and truncated to
/// the equivalent number of bytes on decode (1..=4 bytes per
/// `n`-character partial group, where `n` ∈ {2, 3, 4, 5}).
fn decode_ascii85(input: &[u8]) -> Result<Vec<u8>, PdfError> {
    let mut out = Vec::with_capacity(input.len() * 4 / 5);
    let mut group: [u8; 5] = [0; 5];
    let mut filled: usize = 0;
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        i += 1;
        // EOD marker `~>` per §7.4.3.
        if b == b'~' {
            if i < input.len() && input[i] == b'>' {
                break;
            }
            return Err(PdfError::other(
                "PDF image extraction: ASCII85 stray '~' (expected '~>')",
            ));
        }
        // Whitespace (space, \t, \n, \r, FF, NUL) — ignore.
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0C | 0x00) {
            continue;
        }
        // 'z' shorthand for four zero bytes — only valid when the
        // group is empty.
        if b == b'z' {
            if filled != 0 {
                return Err(PdfError::other(
                    "PDF image extraction: ASCII85 'z' shorthand mid-group",
                ));
            }
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        if !(b'!'..=b'u').contains(&b) {
            return Err(PdfError::other(format!(
                "PDF image extraction: ASCII85 illegal byte {b:#x}"
            )));
        }
        group[filled] = b - b'!';
        filled += 1;
        if filled == 5 {
            decode_ascii85_group_full(&group, &mut out);
            filled = 0;
        }
    }
    if filled == 1 {
        return Err(PdfError::other(
            "PDF image extraction: ASCII85 trailing 1-character group is illegal",
        ));
    }
    if filled > 1 {
        // Pad to 5 with the highest digit (84 = 'u' - '!') and emit
        // (filled - 1) bytes — see §7.4.3.
        for slot in group.iter_mut().skip(filled) {
            *slot = 84;
        }
        let mut tmp = Vec::with_capacity(4);
        decode_ascii85_group_full(&group, &mut tmp);
        out.extend_from_slice(&tmp[..filled - 1]);
    }
    Ok(out)
}

fn decode_ascii85_group_full(group: &[u8; 5], out: &mut Vec<u8>) {
    let value: u64 = group.iter().fold(0u64, |acc, &d| acc * 85 + d as u64);
    out.push(((value >> 24) & 0xFF) as u8);
    out.push(((value >> 16) & 0xFF) as u8);
    out.push(((value >> 8) & 0xFF) as u8);
    out.push((value & 0xFF) as u8);
}

/// ASCIIHexDecode (ISO 32000-1 §7.4.2) — pairs of hex digits, with
/// whitespace ignored, terminated by `>`. An odd trailing nibble
/// is treated as if followed by a `0` per §7.4.2.
fn decode_ascii_hex(input: &[u8]) -> Result<Vec<u8>, PdfError> {
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut high: Option<u8> = None;
    for &b in input {
        if b == b'>' {
            break;
        }
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0C | 0x00) {
            continue;
        }
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => {
                return Err(PdfError::other(format!(
                    "PDF image extraction: ASCIIHex illegal byte {b:#x}"
                )))
            }
        };
        match high.take() {
            None => high = Some(nibble),
            Some(h) => out.push((h << 4) | nibble),
        }
    }
    if let Some(h) = high {
        out.push(h << 4);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii85_decodes_canonical_man_example() {
        // The canonical "easy as ABC" example from §7.4.3 / Adobe
        // PostScript Language Reference Manual: encoding "Man " (4
        // bytes 0x4D 0x61 0x6E 0x20 = 0x4D616E20 = 1296127776) as
        // five base-85 digits 9 jqo^ ... actually `9jqo^` → decode
        // back to "Man ".
        let encoded = b"9jqo^~>";
        let out = decode_ascii85(encoded).unwrap();
        assert_eq!(out, b"Man ");
    }

    #[test]
    fn ascii85_z_shorthand_decodes_four_zero_bytes() {
        let out = decode_ascii85(b"z~>").unwrap();
        assert_eq!(out, [0u8, 0, 0, 0]);
    }

    #[test]
    fn ascii85_full_group_decodes_four_bytes() {
        // "Hell" — base-85 of 0x48656C6C = "87cUR" per the canonical
        // Adobe PostScript Language Reference Manual encoding.
        let encoded = b"87cUR~>";
        let out = decode_ascii85(encoded).unwrap();
        assert_eq!(out, b"Hell");
    }

    #[test]
    fn ascii85_partial_group_decodes_three_bytes_from_four_chars() {
        // "Hel" (3 bytes) → ASCII85 partial group "87cT" (4 chars,
        // the 5th char is implicit / synthesised on decode).
        let encoded = b"87cT~>";
        let out = decode_ascii85(encoded).unwrap();
        assert_eq!(out, b"Hel");
    }

    #[test]
    fn ascii85_partial_group_decodes_two_bytes_from_three_chars() {
        // "He" (2 bytes) → ASCII85 partial group "87_" (3 chars).
        let encoded = b"87_~>";
        let out = decode_ascii85(encoded).unwrap();
        assert_eq!(out, b"He");
    }

    #[test]
    fn ascii85_skips_whitespace_in_group() {
        let out = decode_ascii85(b"9j\nqo^~>").unwrap();
        assert_eq!(out, b"Man ");
    }

    #[test]
    fn ascii85_rejects_lone_trailing_char() {
        assert!(decode_ascii85(b"9j!~>").is_err() || decode_ascii85(b"9~>").is_err());
        // The single trailing char path is the second case — make
        // sure it surfaces an error.
        assert!(decode_ascii85(b"9~>").is_err());
    }

    #[test]
    fn ascii_hex_basic() {
        let out = decode_ascii_hex(b"48656C6C6F>").unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn ascii_hex_skips_whitespace() {
        let out = decode_ascii_hex(b"48 65 6C\n6C 6F>").unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn ascii_hex_odd_nibble_pads_zero() {
        // "414" → 0x41, 0x40 (last nibble padded with zero per §7.4.2).
        let out = decode_ascii_hex(b"414>").unwrap();
        assert_eq!(out, [0x41u8, 0x40]);
    }

    #[test]
    fn color_space_from_name_recognises_devicergb() {
        assert_eq!(
            ColorSpace::from_object(&Object::Name("DeviceRGB".into())),
            ColorSpace::DeviceRGB
        );
        assert_eq!(
            ColorSpace::from_object(&Object::Name("DeviceCMYK".into())),
            ColorSpace::DeviceCMYK
        );
        assert_eq!(
            ColorSpace::from_object(&Object::Name("DeviceGray".into())),
            ColorSpace::DeviceGray
        );
    }

    #[test]
    fn color_space_from_indexed_array() {
        let cs = Object::Array(vec![
            Object::Name("Indexed".into()),
            Object::Name("DeviceRGB".into()),
            Object::Integer(255),
            Object::HexString(b"".to_vec()),
        ]);
        assert_eq!(ColorSpace::from_object(&cs), ColorSpace::Indexed);
    }
}
