//! Inline-image extraction from PDF content streams (round 35).
//!
//! Walks every page's content stream looking for the inline-image
//! triplet defined in ISO 32000-1 §8.9.7 — `BI` (begin image), an
//! image dictionary written with abbreviated keys, `ID` (image data),
//! a raw byte payload, and `EI` (end image). Inline images are the
//! content-stream-level counterpart to the Image XObjects round 23
//! surfaces — the two are functionally the same picture but live in
//! different parts of the PDF.
//!
//! ## Why inline images exist at all
//!
//! Spec §8.9.7: inline images are intended for *small* raster blobs
//! (the spec mentions "no more than 4 KB" as the heuristic) that
//! aren't worth giving their own indirect object. Authoring tools
//! that emit a lot of tiny raster glyphs (ticks, bullets, fake-glyph
//! workarounds) save indirect-object overhead by inlining them.
//! Real-world PDFs use them sparingly but they show up — `pdfimages -all`
//! covers them, so a reader that wants byte-parity with poppler needs
//! to surface them too.
//!
//! ## What round 35 surfaces
//!
//! For every inline image found in any page's content stream:
//!
//! * The image dictionary's `/W` (width), `/H` (height), `/CS`
//!   (color-space), `/BPC` (bits-per-component), and `/F` (filter
//!   chain) — both abbreviated (`/W`/`/H`/…) and long (`/Width`/
//!   `/Height`/…) keys are accepted per Table 92.
//! * The raw image-data payload between the `ID` and `EI` markers
//!   (with any wrapping ASCII filters peeled — see "filter coverage"
//!   below).
//! * A pointer back to the page (1-based index + page `ObjectId`)
//!   the inline image was painted on, so callers can locate it.
//!
//! ## Filter coverage in round 35
//!
//! Wrapping filters that the spec defines unambiguously (per §7.4 /
//! Table 8) and that have a deterministic byte-level inverse are
//! unwrapped on the way out — every filter the round-23 XObject
//! walker already handles:
//!
//! * `/A85` (`/ASCII85Decode`)
//! * `/AHx` (`/ASCIIHexDecode`)
//! * `/Fl`  (`/FlateDecode`)
//! * `/RL`  (`/RunLengthDecode`)
//! * `/LZW` (`/LZWDecode`)
//!
//! The terminal filter (the *last* entry in the chain) is *not*
//! applied — `/DCT` / `/JPX` / `/JBIG2` / `/CCF` are codec filters
//! whose decode step *is* the JPEG / JPEG2000 / JBIG2 / CCITT-Fax
//! decoder a downstream library handles. They surface as
//! [`InlineImageFilter`] tags on the [`PdfInlineImage`] so callers
//! can route correctly. When there is no terminal codec filter (just
//! `/Fl` / no filter at all) the payload is the raw pixel byte
//! sequence at the dictionary's declared bit-depth.
//!
//! ## Parser shape — why a separate parser
//!
//! The inline-image triplet is the *one* PDF content-stream construct
//! whose lexer rules differ from the surrounding operator stream:
//! between `ID` and `EI` the bytes are *raw* — they can contain any
//! sequence including bytes that would otherwise tokenize as
//! delimiters (`(`, `<`, `[`, `%`). The §8.9.7 termination rule is:
//! `EI` is the *first* occurrence of the byte sequence `EI` that is
//! preceded by a whitespace byte (0x00 / \t / \n / \r / \f / space)
//! and followed by another whitespace byte or end-of-stream. The
//! round-35 walker enforces this rule rather than re-using the
//! content.rs operator tokeniser (which would mis-frame the data).
//!
//! ## Provenance
//!
//! ISO 32000-1:2008 §7.4 (Filters), §7.4.2 (ASCIIHexDecode), §7.4.3
//! (ASCII85Decode), §7.4.4 (LZW + Flate, predictor function), §7.4.5
//! (RunLengthDecode), §7.4.8 (DCTDecode), §7.4.9 (CCITTFaxDecode),
//! §7.4.10 (JBIG2Decode + JPXDecode), §8.9.7 (Inline Images, Table
//! 92 abbreviated keys + Table 93 abbreviated filter names). No
//! third-party PDF library was consulted.

use std::str;

use crate::error::PdfError;
use crate::objects::ObjectId;
use crate::reader::document::DocumentReader;
use crate::reader::images::ColorSpace;
use crate::reader::text::collect_page_leaves;

// ────────────────────────── public surface ──────────────────────────

/// Terminal codec filter declared by an inline image's `/F` entry.
///
/// Marks how a downstream decoder should interpret the [`PdfInlineImage::data`]
/// byte payload. `Raw` means the payload is the literal pixel byte
/// sequence at the declared bit-depth (no terminal codec filter — the
/// dictionary may or may not list a non-codec filter like `/Fl` in the
/// chain, but those are peeled before the payload reaches the caller).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InlineImageFilter {
    /// No terminal codec filter — payload is raw pixel bytes. Real
    /// PDFs use this most often for small inline images.
    Raw,
    /// `/DCTDecode` (`/DCT`) — payload is a JPEG-1 / JFIF stream
    /// ready for a JPEG decoder, exactly the same shape the round-23
    /// XObject walker surfaces.
    DctDecode,
    /// `/JPXDecode` (`/JPX`) — payload is a JPEG 2000 codestream.
    JpxDecode,
    /// `/JBIG2Decode` (`/JBIG2`) — payload is a JBIG2 codestream.
    Jbig2Decode,
    /// `/CCITTFaxDecode` (`/CCF`) — payload is a CCITT T.4 / T.6
    /// fax-encoded stream. (`/DecodeParms` carries the per-stream
    /// `/K` / `/Columns` / `/Rows` parameters; round 35 surfaces the
    /// raw bytes only.)
    CcittFaxDecode,
}

/// One inline image surfaced by [`DocumentReader::inline_images`].
///
/// All fields except `data` come from the inline-image dictionary
/// between `BI` and `ID`. `data` is the raw byte payload between
/// `ID` and `EI` with any wrapping ASCII filters (`/A85`, `/AHx`)
/// and `/Fl` / `/RL` already peeled off — only the terminal codec
/// filter (`/DCT`, `/JPX`, `/JBIG2`, `/CCF`, if any) is left in
/// place for a downstream decoder.
///
/// `source_page_index` is the 1-based page number the inline image
/// was painted on; `source_page_obj` is the page leaf's
/// [`ObjectId`] so callers can disambiguate when pages have
/// duplicate indices (rare but the round-29 marked-text path
/// already exposes both for the same reason).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdfInlineImage {
    /// Inline-image payload — after wrapping non-codec filters are
    /// peeled, terminal codec filter (if any) left in place.
    pub data: Vec<u8>,
    /// `/W` (or `/Width`) — pixel width.
    pub width: u32,
    /// `/H` (or `/Height`) — pixel height.
    pub height: u32,
    /// `/CS` (or `/ColorSpace`) mapped to a [`ColorSpace`] tag. The
    /// inline-image abbreviated forms `/G` `/RGB` `/CMYK` `/I` from
    /// Table 93 map to `DeviceGray` / `DeviceRGB` / `DeviceCMYK` /
    /// `Indexed` respectively.
    pub color_space: ColorSpace,
    /// `/BPC` (or `/BitsPerComponent`) — bits per component (1, 2,
    /// 4, 8, or 16). Defaults to 8 when the dict is silent or the
    /// payload's terminal filter is `/JPX` (`/JPXDecode` defines its
    /// own bit-depth per codestream).
    pub bits_per_component: u8,
    /// Terminal codec filter (if any) — see [`InlineImageFilter`].
    pub filter: InlineImageFilter,
    /// `/IM true` flag (image mask): a 1-bit-per-pixel stencil where
    /// the source colour comes from the current fill colour rather
    /// than from the payload. The payload is still the 1-bit
    /// stencil; the renderer combines it with `Tj`'s active colour.
    pub image_mask: bool,
    /// 1-based index of the page this inline image was painted on.
    pub source_page_index: u32,
    /// `ObjectId` of the page leaf — useful when two pages share an
    /// index (the round-29 marked-text path already pairs both).
    pub source_page_obj: ObjectId,
}

impl<'a> DocumentReader<'a> {
    /// Walk every page's content stream and return every inline image
    /// (`BI … ID … EI` triplet per ISO 32000-1 §8.9.7) in stream
    /// order — one entry per inline image surfaced.
    ///
    /// See [module documentation](self) for the byte-level contract,
    /// filter coverage, and parser-framing rule.
    pub fn inline_images(&mut self) -> Result<Vec<PdfInlineImage>, PdfError> {
        inline_images(self)
    }
}

// ────────────────────────── walker ──────────────────────────

pub fn inline_images(reader: &mut DocumentReader<'_>) -> Result<Vec<PdfInlineImage>, PdfError> {
    let leaves = collect_page_leaves(reader)?;
    let mut out = Vec::new();
    for (page_index, leaf) in leaves.iter().enumerate() {
        let content = match crate::reader::text::concatenate_page_contents(reader, *leaf)? {
            Some(b) => b,
            None => continue,
        };
        for image in extract_inline_images_from_stream(&content)? {
            out.push(PdfInlineImage {
                source_page_index: (page_index as u32) + 1,
                source_page_obj: *leaf,
                ..image
            });
        }
    }
    Ok(out)
}

// ────────────────────────── parser ──────────────────────────

/// Public-but-pub(crate) for the per-page driver. Walks a single
/// content-stream byte sequence and emits one [`PdfInlineImage`] per
/// inline image (`BI … ID … EI`) found. `source_page_index` and
/// `source_page_obj` are filled in by the per-page driver — the
/// returned images carry placeholder values for those fields.
pub fn extract_inline_images_from_stream(bytes: &[u8]) -> Result<Vec<PdfInlineImage>, PdfError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // Skip until we find the `BI` keyword. `BI` is a 2-byte
        // operator token: it must be preceded by whitespace / SOF /
        // delimiter (i.e. not be a substring of a longer keyword like
        // `BIM`) and followed by whitespace / delimiter.
        let Some(bi_start) = find_keyword(bytes, b"BI", i) else {
            break;
        };
        // Parse the inline-image dict + ID + raw payload + EI.
        let (image, end) = parse_one_inline_image(bytes, bi_start + 2)?;
        out.push(image);
        i = end;
    }
    Ok(out)
}

/// Find the next position in `bytes` (starting at `from`) where the
/// 2-byte keyword `kw` appears as a standalone operator token — i.e.
/// preceded by a whitespace / delimiter byte (or SOF) and followed by
/// a whitespace / delimiter byte (or EOF).
fn find_keyword(bytes: &[u8], kw: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + kw.len() <= bytes.len() {
        if &bytes[i..i + kw.len()] == kw {
            let prev_ok = i == 0 || is_ws_or_delim(bytes[i - 1]);
            let next_ok = i + kw.len() == bytes.len() || is_ws_or_delim(bytes[i + kw.len()]);
            if prev_ok && next_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn is_ws_or_delim(b: u8) -> bool {
    matches!(
        b,
        0x00 | b'\t'
            | b'\n'
            | 0x0C
            | b'\r'
            | b' '
            | b'('
            | b')'
            | b'<'
            | b'>'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'/'
            | b'%'
    )
}

fn is_ws(b: u8) -> bool {
    matches!(b, 0x00 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

/// Parse the bytes starting just past the `BI` keyword: an
/// abbreviated inline-image dict, then the `ID` keyword, then the raw
/// payload up to `EI`. Returns the parsed image and the byte offset
/// in the parent stream just past the `EI` keyword.
fn parse_one_inline_image(bytes: &[u8], mut i: usize) -> Result<(PdfInlineImage, usize), PdfError> {
    // Inline-image dict: a sequence of `/Name <value>` pairs until
    // the `ID` keyword. Values may be names, numbers, strings,
    // arrays, dicts, or booleans. We collect them as raw key/value
    // bytes and decode the keys we care about (W, H, BPC, CS, F, DP,
    // IM); the rest are accepted and ignored.
    let mut dict_entries: Vec<(String, DictValue)> = Vec::new();
    loop {
        i = skip_ws_and_comments(bytes, i);
        if i + 2 <= bytes.len() && &bytes[i..i + 2] == b"ID" {
            // `ID` keyword — must be followed by exactly one
            // whitespace byte (the data-introducer). Per §8.9.7
            // Note 1, the single byte after `ID` is the start of
            // the image data; a *second* whitespace byte (after the
            // single delimiter) is part of the payload.
            let next = i + 2;
            if next >= bytes.len() || !is_ws(bytes[next]) {
                return Err(PdfError::other(
                    "PDF inline image: `ID` must be followed by exactly one whitespace byte",
                ));
            }
            i = next + 1;
            break;
        }
        if i >= bytes.len() {
            return Err(PdfError::other(
                "PDF inline image: stream ended before `ID` keyword",
            ));
        }
        // Expect a `/Name` key.
        if bytes[i] != b'/' {
            return Err(PdfError::other(format!(
                "PDF inline image: expected `/Key` in BI dict at byte {i} (got {:#x})",
                bytes[i]
            )));
        }
        let (key, after_key) = read_name(bytes, i)?;
        i = skip_ws_and_comments(bytes, after_key);
        if i >= bytes.len() {
            return Err(PdfError::other(format!(
                "PDF inline image: stream ended after key `{key}` in BI dict"
            )));
        }
        let (val, after_val) = read_dict_value(bytes, i)?;
        dict_entries.push((key, val));
        i = after_val;
    }

    // We're now at the first byte of the image payload. Find the
    // matching `EI` per §8.9.7: the first occurrence of "EI" preceded
    // by whitespace and followed by whitespace / EOF.
    let payload_start = i;
    let ei_offset = find_inline_image_ei(bytes, payload_start)
        .ok_or_else(|| PdfError::other("PDF inline image: no terminating `EI` keyword found"))?;
    // Per §8.9.7 the whitespace byte immediately preceding `EI` is
    // the spec delimiter rather than part of the payload — strip
    // exactly one. Any earlier whitespace bytes belong to the data.
    let payload_end = if ei_offset > payload_start && is_ws(bytes[ei_offset - 1]) {
        ei_offset - 1
    } else {
        ei_offset
    };
    let payload = bytes[payload_start..payload_end].to_vec();
    let resume = ei_offset + 2; // past the `EI`.

    // Decode the dict entries.
    let mut width: Option<u32> = None;
    let mut height: Option<u32> = None;
    let mut bpc: Option<u8> = None;
    let mut cs: Option<ColorSpace> = None;
    let mut filter_names: Vec<String> = Vec::new();
    let mut image_mask = false;
    for (key, val) in &dict_entries {
        match key.as_str() {
            "W" | "Width" => width = val.as_u32(),
            "H" | "Height" => height = val.as_u32(),
            "BPC" | "BitsPerComponent" => bpc = val.as_u8(),
            "IM" | "ImageMask" => image_mask = val.as_bool().unwrap_or(false),
            "CS" | "ColorSpace" => cs = val.as_color_space(),
            "F" | "Filter" => filter_names = val.as_name_list(),
            _ => {} // Ignored — Decode, DecodeParms, Intent, …
        }
    }

    // §8.9.5 / §8.9.7 — /Width and /Height are required (for the
    // round-35 surface; an image mask has the same fields, so we
    // require both regardless). /BitsPerComponent defaults: 1 for an
    // image mask, 8 for everything else.
    let width = width.ok_or_else(|| PdfError::other("PDF inline image: missing /W"))?;
    let height = height.ok_or_else(|| PdfError::other("PDF inline image: missing /H"))?;
    let bpc_default: u8 = if image_mask { 1 } else { 8 };
    let bpc = bpc.unwrap_or(bpc_default);

    // Apply non-terminal wrapping filters (ASCII unwrapping, then
    // FlateDecode / RunLengthDecode); leave the terminal codec
    // filter (DCT / JPX / JBIG2 / CCF) in place so the caller hands
    // the payload to a real codec.
    let (peeled, terminal) = peel_inline_filters(payload, &filter_names)?;

    // Image mask payloads have no /CS — they're 1-bit stencils.
    let color_space = if image_mask {
        ColorSpace::DeviceGray
    } else {
        cs.unwrap_or(ColorSpace::DeviceRGB)
    };

    Ok((
        PdfInlineImage {
            data: peeled,
            width,
            height,
            color_space,
            bits_per_component: bpc,
            filter: terminal,
            image_mask,
            source_page_index: 0,
            source_page_obj: ObjectId {
                number: 0,
                generation: 0,
            },
        },
        resume,
    ))
}

/// §8.9.7 EI-locator: first occurrence of `EI` such that the
/// preceding byte is whitespace and the following byte is
/// whitespace or EOF.
fn find_inline_image_ei(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 2 <= bytes.len() {
        if &bytes[i..i + 2] == b"EI" {
            let prev_ok = i > 0 && is_ws(bytes[i - 1]);
            let next_ok = i + 2 == bytes.len() || is_ws_or_delim(bytes[i + 2]);
            if prev_ok && next_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

// ────────────────────────── dict value parsing ──────────────────────────

/// A loosely-typed value parsed out of an inline-image dictionary. We
/// don't need a full PDF object parser here — just enough to round-
/// trip the values §8.9.7 / Table 92 enumerates.
#[derive(Clone, Debug)]
enum DictValue {
    Name(String),
    Integer(i64),
    #[allow(dead_code)]
    Real(f64),
    Bool(bool),
    NameList(Vec<String>),
    /// Anything else — arrays of non-names, strings, dicts, etc. Kept
    /// as raw bytes for round 35; future rounds may upgrade.
    #[allow(dead_code)]
    Raw(Vec<u8>),
}

impl DictValue {
    fn as_u32(&self) -> Option<u32> {
        match self {
            DictValue::Integer(n) if *n >= 0 => Some(*n as u32),
            DictValue::Real(f) if *f >= 0.0 => Some(*f as u32),
            _ => None,
        }
    }
    fn as_u8(&self) -> Option<u8> {
        match self {
            DictValue::Integer(n) if (1..=16).contains(n) => Some(*n as u8),
            _ => None,
        }
    }
    fn as_bool(&self) -> Option<bool> {
        match self {
            DictValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
    fn as_color_space(&self) -> Option<ColorSpace> {
        // Table 93 inline-image colour-space abbreviations: G / RGB /
        // CMYK / I (Indexed). Long names also accepted.
        match self {
            DictValue::Name(n) => Some(match n.as_str() {
                "G" | "DeviceGray" => ColorSpace::DeviceGray,
                "RGB" | "DeviceRGB" => ColorSpace::DeviceRGB,
                "CMYK" | "DeviceCMYK" => ColorSpace::DeviceCMYK,
                "I" | "Indexed" => ColorSpace::Indexed,
                other => ColorSpace::Other(other.to_owned()),
            }),
            _ => None,
        }
    }
    fn as_name_list(&self) -> Vec<String> {
        match self {
            DictValue::Name(n) => vec![n.clone()],
            DictValue::NameList(v) => v.clone(),
            _ => Vec::new(),
        }
    }
}

fn read_name(bytes: &[u8], from: usize) -> Result<(String, usize), PdfError> {
    debug_assert_eq!(bytes[from], b'/');
    let mut end = from + 1;
    while end < bytes.len() {
        let b = bytes[end];
        if is_ws(b)
            || matches!(
                b,
                b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
            )
        {
            break;
        }
        end += 1;
    }
    let name = String::from_utf8_lossy(&bytes[from + 1..end]).into_owned();
    Ok((name, end))
}

fn read_dict_value(bytes: &[u8], from: usize) -> Result<(DictValue, usize), PdfError> {
    let b = bytes[from];
    if b == b'/' {
        let (name, end) = read_name(bytes, from)?;
        return Ok((DictValue::Name(name), end));
    }
    if b == b't' && bytes.len() >= from + 4 && &bytes[from..from + 4] == b"true" {
        return Ok((DictValue::Bool(true), from + 4));
    }
    if b == b'f' && bytes.len() >= from + 5 && &bytes[from..from + 5] == b"false" {
        return Ok((DictValue::Bool(false), from + 5));
    }
    if b == b'[' {
        // Array — for our purposes only matters when it's a list of
        // /Name (e.g. /F [/A85 /Fl]). Parse the array body collecting
        // names; bail out if we see anything else.
        let mut i = from + 1;
        let mut names: Vec<String> = Vec::new();
        let mut had_non_name = false;
        loop {
            i = skip_ws_and_comments(bytes, i);
            if i >= bytes.len() {
                return Err(PdfError::other(
                    "PDF inline image: unterminated `[` in BI dict",
                ));
            }
            if bytes[i] == b']' {
                i += 1;
                break;
            }
            if bytes[i] == b'/' {
                let (n, end) = read_name(bytes, i)?;
                names.push(n);
                i = end;
            } else {
                // Skip a number token (the only other thing we expect
                // is something like `/Decode [0 1]` — we don't use it
                // but we should walk past it cleanly).
                had_non_name = true;
                let end = skip_token(bytes, i);
                if end == i {
                    return Err(PdfError::other(format!(
                        "PDF inline image: unexpected byte {:#x} in BI dict array",
                        bytes[i]
                    )));
                }
                i = end;
            }
        }
        if had_non_name {
            return Ok((DictValue::Raw(bytes[from..i].to_vec()), i));
        }
        return Ok((DictValue::NameList(names), i));
    }
    if b == b'<' && bytes.get(from + 1) == Some(&b'<') {
        // Nested dict (e.g. /DP <</K -1>>) — skip the body.
        let end = skip_balanced_dict(bytes, from)?;
        return Ok((DictValue::Raw(bytes[from..end].to_vec()), end));
    }
    if b == b'<' {
        // Hex string — skip to the matching `>`.
        let mut end = from + 1;
        while end < bytes.len() && bytes[end] != b'>' {
            end += 1;
        }
        if end < bytes.len() {
            end += 1;
        }
        return Ok((DictValue::Raw(bytes[from..end].to_vec()), end));
    }
    if b == b'(' {
        // Literal string — track balanced parens with backslash
        // escape per §7.3.4.2.
        let mut end = from + 1;
        let mut depth = 1i32;
        while end < bytes.len() && depth > 0 {
            match bytes[end] {
                b'\\' => end = end.saturating_add(2),
                b'(' => {
                    depth += 1;
                    end += 1;
                }
                b')' => {
                    depth -= 1;
                    end += 1;
                }
                _ => end += 1,
            }
        }
        // §7.3.4.2: a `\` at the last byte of the input would push
        // `end` past `bytes.len()` via the `end += 2` above, which
        // would then trip a slice-index panic on the return below.
        // Clamp so a malformed-but-truncated escape is reported as
        // an open string rather than a panic.
        let end = end.min(bytes.len());
        return Ok((DictValue::Raw(bytes[from..end].to_vec()), end));
    }
    if matches!(b, b'+' | b'-' | b'.' | b'0'..=b'9') {
        // Number — integer or real.
        let mut end = from;
        if matches!(bytes[end], b'+' | b'-') {
            end += 1;
        }
        let mut saw_dot = false;
        let mut saw_digit = false;
        while end < bytes.len() {
            let c = bytes[end];
            if c.is_ascii_digit() {
                end += 1;
                saw_digit = true;
            } else if c == b'.' && !saw_dot {
                end += 1;
                saw_dot = true;
            } else {
                break;
            }
        }
        if !saw_digit {
            return Err(PdfError::other(format!(
                "PDF inline image: malformed number at byte {from}"
            )));
        }
        let s = str::from_utf8(&bytes[from..end]).map_err(|_| {
            PdfError::other(format!("PDF inline image: non-UTF-8 number at byte {from}"))
        })?;
        if saw_dot {
            let f: f64 = s
                .parse()
                .map_err(|_| PdfError::other(format!("PDF inline image: bad real `{s}`")))?;
            return Ok((DictValue::Real(f), end));
        }
        let n: i64 = s
            .parse()
            .map_err(|_| PdfError::other(format!("PDF inline image: bad integer `{s}`")))?;
        return Ok((DictValue::Integer(n), end));
    }
    Err(PdfError::other(format!(
        "PDF inline image: unrecognised value token starting with {:#x} at byte {from}",
        b
    )))
}

fn skip_ws_and_comments(bytes: &[u8], mut i: usize) -> usize {
    loop {
        while i < bytes.len() && is_ws(bytes[i]) {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'%' {
            while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b'\r' {
                i += 1;
            }
            continue;
        }
        return i;
    }
}

fn skip_token(bytes: &[u8], from: usize) -> usize {
    let mut end = from;
    while end < bytes.len()
        && !is_ws(bytes[end])
        && !matches!(bytes[end], b'/' | b'[' | b']' | b'(' | b')' | b'<' | b'>')
    {
        end += 1;
    }
    end
}

fn skip_balanced_dict(bytes: &[u8], from: usize) -> Result<usize, PdfError> {
    debug_assert!(bytes[from] == b'<' && bytes.get(from + 1) == Some(&b'<'));
    let mut i = from + 2;
    let mut depth = 1i32;
    while i + 1 < bytes.len() && depth > 0 {
        if bytes[i] == b'<' && bytes[i + 1] == b'<' {
            depth += 1;
            i += 2;
        } else if bytes[i] == b'>' && bytes[i + 1] == b'>' {
            depth -= 1;
            i += 2;
        } else if bytes[i] == b'(' {
            // skip literal string
            let mut depth2 = 1i32;
            i += 1;
            while i < bytes.len() && depth2 > 0 {
                match bytes[i] {
                    b'\\' => i += 2,
                    b'(' => {
                        depth2 += 1;
                        i += 1;
                    }
                    b')' => {
                        depth2 -= 1;
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
        } else {
            i += 1;
        }
    }
    if depth != 0 {
        return Err(PdfError::other(
            "PDF inline image: unterminated `<<` in BI dict",
        ));
    }
    Ok(i)
}

// ────────────────────────── filter dispatch ──────────────────────────

fn peel_inline_filters(
    mut payload: Vec<u8>,
    chain: &[String],
) -> Result<(Vec<u8>, InlineImageFilter), PdfError> {
    // The terminal filter — if it's a codec filter — is left in place
    // and reported through [`InlineImageFilter`]; everything before
    // it is unwrapped here.
    let (terminal_name, peel_count) = match chain.last().map(|s| s.as_str()) {
        Some("DCT" | "DCTDecode") => (InlineImageFilter::DctDecode, chain.len() - 1),
        Some("JPX" | "JPXDecode") => (InlineImageFilter::JpxDecode, chain.len() - 1),
        Some("JBIG2" | "JBIG2Decode") => (InlineImageFilter::Jbig2Decode, chain.len() - 1),
        Some("CCF" | "CCITTFaxDecode") => (InlineImageFilter::CcittFaxDecode, chain.len() - 1),
        _ => (InlineImageFilter::Raw, chain.len()),
    };
    for filter in &chain[..peel_count] {
        payload = match filter.as_str() {
            "A85" | "ASCII85Decode" => crate::reader::filters::ascii85_decode(&payload)?,
            "AHx" | "ASCIIHexDecode" => crate::reader::filters::ascii_hex_decode(&payload)?,
            "Fl" | "FlateDecode" => crate::reader::filters::flate_decompress(&payload)?,
            "RL" | "RunLengthDecode" => crate::reader::filters::run_length_decode(&payload)?,
            // LZWDecode (§7.4.4.2) — round 98, default `/EarlyChange` 1.
            "LZW" | "LZWDecode" => crate::reader::filters::lzw_decode(&payload)?,
            other => {
                return Err(PdfError::other(format!(
                    "PDF inline image: unsupported wrapping filter `{other}`"
                )));
            }
        };
    }
    Ok((payload, terminal_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_bi_keyword_at_start() {
        let stream = b"BI /W 4 /H 4 ID 0123456789ABCDEF EI";
        let pos = find_keyword(stream, b"BI", 0).unwrap();
        assert_eq!(pos, 0);
    }

    #[test]
    fn finds_bi_keyword_after_other_ops() {
        let stream = b"q 100 0 0 100 0 0 cm BI /W 1 /H 1 /BPC 8 /CS /G ID \x42 EI Q";
        let pos = find_keyword(stream, b"BI", 0).unwrap();
        assert_eq!(&stream[pos..pos + 2], b"BI");
    }

    #[test]
    fn rejects_bi_substring_inside_longer_kw() {
        // `BIM` is not the `BI` operator.
        let stream = b"q BIM ID 0 EI Q";
        assert!(find_keyword(stream, b"BI", 0).is_none());
    }

    #[test]
    fn ei_termination_requires_surrounding_ws() {
        // The "EI" inside the payload (no surrounding ws) is NOT the
        // terminator; the real terminator follows a space.
        let stream = b"abcEIxyz EI rest";
        let pos = find_inline_image_ei(stream, 0).unwrap();
        // Position points at the real `EI` (after the space).
        assert_eq!(&stream[pos..pos + 2], b"EI");
        assert!(pos > 4); // skipped the bogus inline one
    }

    #[test]
    fn extracts_one_inline_image_minimal() {
        // Payload bytes: 0x00 0x01 0x02 0x03.
        let stream: &[u8] = b"BI /W 1 /H 4 /CS /G /BPC 8 ID \x00\x01\x02\x03 EI";
        let images = extract_inline_images_from_stream(stream).unwrap();
        assert_eq!(images.len(), 1);
        let img = &images[0];
        assert_eq!(img.width, 1);
        assert_eq!(img.height, 4);
        assert_eq!(img.bits_per_component, 8);
        assert_eq!(img.color_space, ColorSpace::DeviceGray);
        assert_eq!(img.data, [0x00, 0x01, 0x02, 0x03]);
        assert_eq!(img.filter, InlineImageFilter::Raw);
    }

    #[test]
    fn extracts_dct_inline_image_preserves_payload() {
        // Tiny "JPEG"-looking payload; the parser should keep the
        // bytes as-is and tag the filter as DctDecode.
        let payload: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let mut stream: Vec<u8> = b"BI /W 8 /H 8 /CS /RGB /F /DCT ID ".to_vec();
        stream.extend_from_slice(payload);
        stream.extend_from_slice(b" EI");
        let images = extract_inline_images_from_stream(&stream).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].filter, InlineImageFilter::DctDecode);
        assert_eq!(images[0].data, payload);
        assert_eq!(images[0].color_space, ColorSpace::DeviceRGB);
    }

    #[test]
    fn image_mask_defaults_to_1bpc_devicegray() {
        let stream: &[u8] = b"BI /W 8 /H 8 /IM true ID \xFF EI";
        let images = extract_inline_images_from_stream(stream).unwrap();
        assert_eq!(images.len(), 1);
        assert!(images[0].image_mask);
        assert_eq!(images[0].bits_per_component, 1);
        assert_eq!(images[0].color_space, ColorSpace::DeviceGray);
    }

    #[test]
    fn long_keys_accepted_alongside_abbreviated() {
        let stream: &[u8] =
            b"BI /Width 2 /Height 2 /ColorSpace /DeviceGray /BitsPerComponent 4 ID \x12\x34 EI";
        let images = extract_inline_images_from_stream(stream).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].width, 2);
        assert_eq!(images[0].height, 2);
        assert_eq!(images[0].bits_per_component, 4);
    }

    #[test]
    fn filter_list_with_a85_wrapper_peels_correctly() {
        // Wrap the payload [0x4D 0x61 0x6E 0x20] = "Man " in ASCII85
        // and verify the peel.
        let raw: &[u8] = &[0x4D, 0x61, 0x6E, 0x20];
        let mut stream: Vec<u8> = b"BI /W 4 /H 1 /CS /G /F [/A85] ID ".to_vec();
        // "Man " encodes to "9jqo^" + the EOD marker "~>" in ASCII85.
        stream.extend_from_slice(b"9jqo^~>");
        stream.extend_from_slice(b" EI");
        let images = extract_inline_images_from_stream(&stream).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].data, raw);
        assert_eq!(images[0].filter, InlineImageFilter::Raw);
    }

    #[test]
    fn two_inline_images_in_one_stream() {
        let stream: &[u8] =
            b"BI /W 1 /H 1 /CS /G /BPC 8 ID \xAA EI BI /W 1 /H 1 /CS /G /BPC 8 ID \xBB EI";
        let images = extract_inline_images_from_stream(stream).unwrap();
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].data, [0xAA]);
        assert_eq!(images[1].data, [0xBB]);
    }

    #[test]
    fn payload_containing_ei_substring_is_preserved() {
        // The bytes `E I` (with no surrounding whitespace) should NOT
        // be treated as a terminator. The real terminator follows a
        // space.
        let stream: &[u8] = b"BI /W 5 /H 1 /CS /G /BPC 8 ID EIfoo EI";
        let images = extract_inline_images_from_stream(stream).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(&images[0].data, b"EIfoo");
    }

    #[test]
    fn unterminated_inline_image_errors() {
        let stream: &[u8] = b"BI /W 1 /H 1 /CS /G /BPC 8 ID \xAA";
        let err = extract_inline_images_from_stream(stream).unwrap_err();
        assert!(err.to_string().contains("EI"));
    }

    #[test]
    fn rejects_missing_width() {
        let stream: &[u8] = b"BI /H 1 /CS /G ID \xAA EI";
        let err = extract_inline_images_from_stream(stream).unwrap_err();
        assert!(err.to_string().contains("/W"));
    }
}
