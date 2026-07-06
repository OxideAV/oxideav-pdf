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
#[derive(Clone, Debug, PartialEq)]
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
    /// The image's **soft-mask image** (§11.6.5.3) — the subsidiary
    /// image XObject named by the parent dict's `/SMask` entry, which
    /// supplies per-sample alpha for the parent ("This mask, if
    /// present, shall override any explicit or colour key mask
    /// specified by the image dictionary's Mask entry"). `None` when
    /// the parent has no `/SMask` or the entry is unusable.
    pub smask: Option<SoftMaskImage>,
}

/// A soft-mask image (§11.6.5.3 Tables 145 + 146): the subsidiary
/// `/SMask` image XObject supplying per-sample alpha for its parent.
/// Per Table 145 its colour space is required to be `/DeviceGray`, so
/// the decoded samples are single-component gray values.
#[derive(Clone, Debug, PartialEq)]
pub struct SoftMaskImage {
    /// `/Width` of the mask (Table 145: independent of the parent's
    /// unless `/Matte` is present — both map onto the unit square).
    pub width: u32,
    /// `/Height` of the mask.
    pub height: u32,
    /// `/BitsPerComponent` (required, Table 145).
    pub bits_per_component: u8,
    /// The decoded mask samples (the `/Filter` chain applied), when
    /// the chain is one this crate decodes (Flate / LZW / ASCII /
    /// RunLength / none). `None` for image-codec filters (DCTDecode /
    /// JPXDecode / …) — the raw stream still lives in the document.
    pub data: Option<Vec<u8>>,
    /// `/Matte` (Table 146) — the preblending matte colour, in the
    /// *parent* image's colour space, when the parent's samples were
    /// premultiplied against it. `None` = not preblended.
    pub matte: Option<Vec<f32>>,
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
            "ASCII85Decode" | "A85" => crate::reader::filters::ascii85_decode(&payload)?,
            "ASCIIHexDecode" | "AHx" => crate::reader::filters::ascii_hex_decode(&payload)?,
            "FlateDecode" | "Fl" => crate::reader::filters::flate_decompress(&payload)?,
            "RunLengthDecode" | "RL" => crate::reader::filters::run_length_decode(&payload)?,
            // LZWDecode (§7.4.4.2) — round 98. `/EarlyChange` defaults
            // to 1; a wrapping LZW layer ahead of DCTDecode is rare but
            // legal, so peel it like the other generic filters.
            "LZWDecode" | "LZW" => crate::reader::filters::lzw_decode(&payload)?,
            // Other wrapping filters (CCITTFaxDecode, …) are not in
            // scope — surface the XObject as "not JPEG passthrough" so
            // the caller doesn't get a corrupted stream.
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

    // /SMask (§11.6.4.3 + §11.6.5.3) — a subsidiary image XObject
    // holding per-sample alpha for this image.
    let smask = extract_soft_mask_image(reader, &s.dict)?;

    Ok(Some(PdfImageXObject {
        data: payload,
        width: width as u32,
        height: height as u32,
        color_space,
        bits_per_component: bpc as u8,
        smask,
    }))
}

/// Resolve `parent_dict`'s `/SMask` entry into a [`SoftMaskImage`]
/// (§11.6.5.3). Tolerant: a missing / non-stream / malformed entry
/// returns `Ok(None)` rather than failing the parent's extraction.
fn extract_soft_mask_image(
    reader: &mut DocumentReader<'_>,
    parent_dict: &Dict,
) -> Result<Option<SoftMaskImage>, PdfError> {
    let sm = parent_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "SMask")
        .map(|(_, v)| v.clone());
    let sm = match sm {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Stream(s) = sm else {
        return Ok(None);
    };
    // Table 145: /Subtype shall be /Image, /ColorSpace shall be
    // /DeviceGray, /ImageMask shall be false or absent.
    let subtype = s.dict.entries().iter().find(|(k, _)| k == "Subtype");
    if !matches!(subtype, Some((_, Object::Name(n))) if n == "Image") {
        return Ok(None);
    }
    let (Some(width), Some(height)) = (lookup_int(&s.dict, "Width"), lookup_int(&s.dict, "Height"))
    else {
        return Ok(None);
    };
    if width < 0 || height < 0 {
        return Ok(None);
    }
    let bpc = lookup_int(&s.dict, "BitsPerComponent").unwrap_or(8);
    if !(1..=16).contains(&bpc) {
        return Ok(None);
    }
    // Decode the sample stream when the filter chain is decodable
    // (Flate / LZW / ASCII / RunLength / none). An image-codec filter
    // (DCTDecode / JPXDecode / …) surfaces `data: None`.
    let data = crate::reader::document::decode_stream(&s).ok();
    // /Matte (Table 146): n numbers in the parent's colour space.
    let matte = s
        .dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Matte")
        .and_then(|(_, v)| match v {
            Object::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Object::Integer(n) => out.push(*n as f32),
                        Object::Real(n) => out.push(*n as f32),
                        _ => return None,
                    }
                }
                Some(out)
            }
            _ => None,
        });
    Ok(Some(SoftMaskImage {
        width: width as u32,
        height: height as u32,
        bits_per_component: bpc as u8,
        data,
        matte,
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

#[cfg(test)]
mod tests {
    use super::*;

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
