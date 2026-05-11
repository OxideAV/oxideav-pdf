//! PDF text extraction — content-stream walker that emits text runs
//! with font + position resolved.
//!
//! Round 22 implementation. The walker is the read-side complement to
//! the (still-deferred) writer-side text emission path. It scans every
//! page's `/Contents` stream, tracks the text matrix `Tm` per ISO
//! 32000-1 §9.4.4, decodes `Tj` / `TJ` / `'` / `"` operands, and emits
//! one [`TextRun`] per show operator. The decoded string is reconstructed
//! by mapping the encoded bytes back to Unicode through whichever route
//! the page-level `/Font` resource describes:
//!
//! 1. **Type 0 / CIDFontType0 / CIDFontType2 with `/ToUnicode`** — parse
//!    the CMap stream's `bfchar` / `bfrange` mappings (ISO 32000-1
//!    §9.10.3) and look each 2-byte CID up in the result map.
//! 2. **Identity-H / Identity-V without `/ToUnicode`** — interpret each
//!    CID as the equivalent BMP code point (lossy fallback; matches what
//!    `pdftotext --raw` does for fonts with no `/ToUnicode` slice).
//! 3. **Simple fonts (Type1, TrueType) with `/Encoding /WinAnsiEncoding`**
//!    — apply the WinAnsi byte-to-Unicode table.
//! 4. **Simple fonts with no recognised encoding** — return raw bytes as
//!    Latin-1 (the writer never emits this shape; included so the round
//!    is robust against hand-laid PDFs from older tooling).
//!
//! Reading-order reconstruction (column / paragraph segmentation) is a
//! future-round followup. The runs come out in stream order — exactly
//! the way the page's painter would have laid them down.
//!
//! ## Provenance
//!
//! ISO 32000-1:2008 §9 (Text), §9.4 (Text Objects), §9.6 (Simple Fonts),
//! §9.7 (Composite Fonts), §9.10 (Extraction of Text Content), Adobe
//! Tech Note #5014 (CMap & CIDFont Files Specification). No third-party
//! PDF library was consulted.

use std::collections::HashMap;
use std::str;

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::reader::document::{decode_stream, DocumentReader};
use crate::reader::encoding::{
    apply_encoding_differences, parse_encoding_differences, BaseEncoding, EncodingMap,
};

// ────────────────────────── public surface ──────────────────────────

/// One contiguous text-show output by the content-stream walker.
///
/// Position is the text-space origin of the run at the moment the show
/// operator fired (text-matrix `e` / `f`). Font size carries the `Tf`
/// argument verbatim — note that PDF text-space is multiplied by the
/// CTM scaling, so the rendered glyph size on paper is `font_size *
/// CTM_scale`. Round-22 callers that only need the raw `Tf` value
/// (e.g. for keyword search) can ignore the CTM; renderers that want
/// physical size should multiply by the CTM extracted from the
/// reader's group walker.
#[derive(Clone, Debug, PartialEq)]
pub struct TextRun {
    /// Decoded Unicode payload — the result of mapping every encoded
    /// byte / CID through the font's `/ToUnicode` CMap (or the
    /// identity / WinAnsi fallbacks documented above).
    pub text: String,
    /// `(x, y)` in PDF user space — the text-matrix origin at the
    /// moment of the show.
    pub position: (f32, f32),
    /// The PDF resource name of the font (`/F0`, `/F12`, etc.) — the
    /// `/Tf` operand, with the leading `/` stripped. Empty when the
    /// content stream issues a show without a preceding `Tf`
    /// (malformed but tolerated).
    pub font_name: String,
    /// Font size as supplied to the `Tf` operator.
    pub font_size: f32,
}

/// One [`TextRun`] together with the marked-content tag stack it was
/// emitted under (ISO 32000-1 §14.6 — Tagged PDF). Round-29 piggybacks
/// on the same content-stream walker as [`extract_text`]; the only
/// difference is that this variant records the most-recently-opened
/// `BDC` block's `/MCID` (if any) and the indirect-object number of
/// the page the run came from. The reading-order layout pass under
/// [`crate::reader::layout`] consumes these to assemble runs in the
/// order the StructTreeRoot's `/K` tree dictates (rather than the
/// raster x/y order [`extract_text`] returns).
#[derive(Clone, Debug, PartialEq)]
pub struct MarkedTextRun {
    /// The visual text run — same shape as [`TextRun`].
    pub run: TextRun,
    /// Most recently opened marked-content `/MCID` integer at the moment
    /// of the show. `None` when no enclosing `BDC` block declared
    /// `/MCID` (e.g. plain `BMC … EMC` decorative groupings).
    pub mcid: Option<u32>,
    /// PDF object number of the page the run came from. The reading-
    /// order layout pass keys MCID lookups by `(page_obj_num, mcid)`
    /// because a Tagged PDF may emit MCID 0 on every page.
    pub page_obj_num: u32,
    /// Zero-based page index in walk order (0 for the first page found).
    pub page_index: u32,
}

/// All text runs collected from one page (or one whole document — the
/// caller decides whether to merge across pages).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PdfTextExtraction {
    pub runs: Vec<TextRun>,
}

/// All [`MarkedTextRun`]s collected from every page in walk order.
/// Round-29 helper that the layout pass consumes; the runs themselves
/// are still emitted in raster (content-stream) order — it's the
/// `mcid` tag that lets the layout pass reorder them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PdfMarkedTextExtraction {
    pub runs: Vec<MarkedTextRun>,
}

impl PdfTextExtraction {
    /// Concatenate every run's text with a single space between them.
    /// Convenience for callers that only need a flat document-level
    /// blob (e.g. keyword search). A real layout engine would walk the
    /// individual runs + positions to reconstruct lines / paragraphs.
    pub fn flat_text(&self) -> String {
        self.runs
            .iter()
            .map(|r| r.text.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl<'a> DocumentReader<'a> {
    /// Extract every text run from every page in stream order.
    ///
    /// See [`PdfTextExtraction`]. This is a thin wrapper around
    /// [`extract_text`] that walks the catalog → /Pages tree, resolves
    /// each page's `/Resources /Font` dict, and feeds the page's
    /// concatenated `/Contents` stream into the walker.
    pub fn text_extraction(&mut self) -> Result<PdfTextExtraction, PdfError> {
        extract_text(self)
    }

    /// Round-29: extract every text run alongside the marked-content
    /// `/MCID` tag the show was issued under (ISO 32000-1 §14.6 + §14.8).
    /// Pair with [`crate::reader::layout::read_in_logical_order`] to
    /// reorder the resulting runs by the StructTreeRoot's logical
    /// `/K` tree.
    pub fn marked_text_extraction(&mut self) -> Result<PdfMarkedTextExtraction, PdfError> {
        extract_text_marked(self)
    }
}

// ────────────────────────── walker entry point ──────────────────────────

/// Walk every page in `reader`'s catalog and collect text runs in
/// stream order.
pub fn extract_text(reader: &mut DocumentReader<'_>) -> Result<PdfTextExtraction, PdfError> {
    let leaves = collect_page_leaves(reader)?;
    let mut out = PdfTextExtraction::default();
    for leaf in leaves {
        extract_page(reader, leaf, &mut out)?;
    }
    Ok(out)
}

/// Round-29: walk every page in `reader`'s catalog and collect
/// marked-content-tagged text runs in stream order. The `mcid` slot
/// reflects the most-recently-opened `BDC … EMC` block's `/MCID`
/// integer; runs outside any `BDC` block (or inside a `BMC` block,
/// which has no MCID) get `mcid = None`.
pub fn extract_text_marked(
    reader: &mut DocumentReader<'_>,
) -> Result<PdfMarkedTextExtraction, PdfError> {
    let leaves = collect_page_leaves(reader)?;
    let mut out = PdfMarkedTextExtraction::default();
    for (page_index, leaf) in leaves.into_iter().enumerate() {
        extract_page_marked(reader, leaf, page_index as u32, &mut out)?;
    }
    Ok(out)
}

/// Walk catalog → /Pages tree and collect every leaf page's
/// [`ObjectId`] in document order. Shared between [`extract_text`] and
/// [`extract_text_marked`].
pub(crate) fn collect_page_leaves(
    reader: &mut DocumentReader<'_>,
) -> Result<Vec<ObjectId>, PdfError> {
    let root_id = reader.xref().root()?;
    let catalog_obj = reader.resolve(root_id)?;
    let Object::Dict(catalog) = catalog_obj else {
        return Err(PdfError::other(format!(
            "PDF text extraction: /Root must be a dictionary (got {catalog_obj:?})"
        )));
    };
    let pages_ref = catalog
        .entries()
        .iter()
        .find(|(k, _)| k == "Pages")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| PdfError::other("PDF text extraction: catalog missing /Pages"))?;
    let Object::Reference(pages_root_id) = pages_ref else {
        return Err(PdfError::other(format!(
            "PDF text extraction: catalog /Pages must be a reference (got {pages_ref:?})"
        )));
    };
    let mut leaves = Vec::new();
    walk_pages(reader, pages_root_id, &mut leaves)?;
    Ok(leaves)
}

fn walk_pages(
    reader: &mut DocumentReader<'_>,
    node_id: ObjectId,
    out: &mut Vec<ObjectId>,
) -> Result<(), PdfError> {
    let node = reader.resolve(node_id)?;
    let Object::Dict(d) = node else {
        return Err(PdfError::other(format!(
            "PDF text extraction: /Pages node {node_id:?} is not a dict"
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
                        "PDF text extraction: /Pages node {node_id:?} missing /Kids"
                    ))
                })?;
            let Object::Array(items) = kids else {
                return Err(PdfError::other(format!(
                    "PDF text extraction: /Kids must be an array on {node_id:?}"
                )));
            };
            for item in items {
                if let Object::Reference(id) = item {
                    walk_pages(reader, id, out)?;
                }
            }
            Ok(())
        }
        _ => {
            // Unknown — skip silently. Avoids breaking on hand-laid
            // PDFs whose intermediate /Pages nodes omit /Type.
            Ok(())
        }
    }
}

/// Per-font byte→Unicode decoders keyed by `/Resources /Font` slot.
type PageFonts = HashMap<String, FontDecoder>;

/// Resolve a page leaf into the pieces the text walker needs:
/// per-font byte→Unicode decoders + the concatenated content stream.
/// Returns `None` when the page has no `/Contents` (a perfectly valid
/// blank page — emit nothing).
fn load_page_for_text(
    reader: &mut DocumentReader<'_>,
    page_id: ObjectId,
) -> Result<Option<(PageFonts, Vec<u8>)>, PdfError> {
    let page_obj = reader.resolve(page_id)?;
    let Object::Dict(page_dict) = page_obj else {
        return Ok(None);
    };

    // Resolve the page's /Resources /Font subdict — each entry maps a
    // resource name (`F0`) to a font dictionary. Inheritance from
    // /Pages parents is round-22 deferred; the writer always attaches
    // /Resources directly to the leaf page.
    let resources = page_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Resources")
        .map(|(_, v)| v.clone());
    let resources = match resources {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let mut fonts: HashMap<String, FontDecoder> = HashMap::new();
    if let Object::Dict(rdict) = resources {
        let font_dict = rdict
            .entries()
            .iter()
            .find(|(k, _)| k == "Font")
            .map(|(_, v)| v.clone());
        if let Some(font_obj) = font_dict {
            let font_obj = match font_obj {
                Object::Reference(id) => reader.resolve(id)?,
                other => other,
            };
            if let Object::Dict(fd) = font_obj {
                for (name, val) in fd.entries() {
                    let resolved = match val {
                        Object::Reference(id) => reader.resolve(*id)?,
                        other => other.clone(),
                    };
                    if let Object::Dict(font_d) = resolved {
                        let decoder = FontDecoder::from_dict(reader, &font_d)?;
                        fonts.insert(name.clone(), decoder);
                    }
                }
            }
        }
    }

    // Concatenate /Contents.
    let contents_obj = page_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Contents")
        .map(|(_, v)| v.clone());
    let content_bytes = match contents_obj {
        Some(Object::Reference(id)) => extract_stream_data(reader, id)?,
        Some(Object::Array(items)) => {
            let mut all = Vec::new();
            for item in items {
                if let Object::Reference(id) = item {
                    all.extend_from_slice(&extract_stream_data(reader, id)?);
                    all.push(b'\n');
                }
            }
            all
        }
        _ => return Ok(None),
    };

    Ok(Some((fonts, content_bytes)))
}

fn extract_page(
    reader: &mut DocumentReader<'_>,
    page_id: ObjectId,
    out: &mut PdfTextExtraction,
) -> Result<(), PdfError> {
    let Some((fonts, content_bytes)) = load_page_for_text(reader, page_id)? else {
        return Ok(());
    };
    let mut walker = TextWalker::new(fonts);
    walker.parse(&content_bytes)?;
    out.runs.extend(walker.into_runs());
    Ok(())
}

fn extract_page_marked(
    reader: &mut DocumentReader<'_>,
    page_id: ObjectId,
    page_index: u32,
    out: &mut PdfMarkedTextExtraction,
) -> Result<(), PdfError> {
    let Some((fonts, content_bytes)) = load_page_for_text(reader, page_id)? else {
        return Ok(());
    };
    let mut walker = TextWalker::new(fonts);
    walker.track_mcid = true;
    walker.parse(&content_bytes)?;
    let runs = walker.into_runs_with_mcid();
    for (run, mcid) in runs {
        out.runs.push(MarkedTextRun {
            run,
            mcid,
            page_obj_num: page_id.number,
            page_index,
        });
    }
    Ok(())
}

fn extract_stream_data(reader: &mut DocumentReader<'_>, id: ObjectId) -> Result<Vec<u8>, PdfError> {
    let obj = reader.resolve(id)?;
    let Object::Stream(s) = obj else {
        return Err(PdfError::other(format!(
            "PDF text extraction: object {id:?} expected to be a Stream"
        )));
    };
    decode_stream(&s)
}

// ────────────────────────── font decoder ──────────────────────────

/// Per-font byte-to-Unicode decoder. The variant is picked at
/// `/Resources /Font /Fx` resolution time and reused for every
/// subsequent `Tj` / `TJ` / `'` / `"` operand against that font.
#[derive(Clone, Debug)]
enum FontDecoder {
    /// `/ToUnicode` CMap supplied — every show operand is split into
    /// 2-byte CIDs (or 1-byte codes for simple fonts whose CMap also
    /// uses the 2-byte path) and looked up.
    ToUnicode { map: CMap, cid_width: u8 },
    /// Identity-H / Identity-V without /ToUnicode — interpret each
    /// 2-byte CID as the equivalent BMP code point.
    IdentityNoCMap,
    /// Simple font (Type1 / TrueType / Type3) with a resolved
    /// 256-entry byte → Unicode table. Captures every variant of
    /// ISO 32000-1 §9.6.6.1 — named base encodings, encoding-dict
    /// `/BaseEncoding` + `/Differences`, and the implicit
    /// StandardEncoding default. Replaces the old `WinAnsi` /
    /// `MacRoman` enum tags so a single code path handles every
    /// simple-font encoding variant (round 28).
    ///
    /// Boxed because the 256-entry table dwarfs the other variants
    /// and `clippy::large_enum_variant` flags the unboxed form.
    SimpleMap(Box<EncodingMap>),
    /// No discernible encoding — fall back to Latin-1 byte → code
    /// point (identity for ASCII; reasonable for CP1252 punctuation).
    Latin1,
}

impl FontDecoder {
    fn from_dict(reader: &mut DocumentReader<'_>, font: &Dict) -> Result<FontDecoder, PdfError> {
        // 1. /ToUnicode wins regardless of the /Subtype — even simple
        // fonts may carry one (PDF/UA mandates it for text extraction).
        let to_unicode = font
            .entries()
            .iter()
            .find(|(k, _)| k == "ToUnicode")
            .map(|(_, v)| v.clone());
        if let Some(tu) = to_unicode {
            let stream_obj = match tu {
                Object::Reference(id) => reader.resolve(id)?,
                other => other,
            };
            if let Object::Stream(s) = stream_obj {
                let bytes = decode_stream(&s)?;
                let map = CMap::parse(&bytes)?;
                let cid_width = map.byte_width;
                return Ok(FontDecoder::ToUnicode { map, cid_width });
            }
        }

        // 2. Composite font (Type0) without /ToUnicode — Identity-H/V.
        let subtype = font
            .entries()
            .iter()
            .find(|(k, _)| k == "Subtype")
            .and_then(|(_, v)| match v {
                Object::Name(s) => Some(s.as_str()),
                _ => None,
            })
            .unwrap_or("");
        if subtype == "Type0" {
            // /Encoding tells us Identity-H / Identity-V vs a named
            // CMap. Round-22 supports the identities (the only ones
            // the writer would ever emit).
            let enc = font
                .entries()
                .iter()
                .find(|(k, _)| k == "Encoding")
                .map(|(_, v)| v.clone());
            if let Some(Object::Name(name)) = enc {
                if name == "Identity-H" || name == "Identity-V" {
                    return Ok(FontDecoder::IdentityNoCMap);
                }
            }
            // Unknown composite — Identity is the safest default.
            return Ok(FontDecoder::IdentityNoCMap);
        }

        // 3. Simple font with named /Encoding.
        let enc = font
            .entries()
            .iter()
            .find(|(k, _)| k == "Encoding")
            .map(|(_, v)| v.clone());
        if let Some(Object::Name(name)) = enc {
            if let Some(base) = BaseEncoding::from_name(name.as_str()) {
                return Ok(FontDecoder::SimpleMap(Box::new(EncodingMap::from_base(
                    base,
                ))));
            }
            // Unknown base name — fall back to Latin-1.
            return Ok(FontDecoder::Latin1);
        }
        // /Encoding may also be a dict — `/BaseEncoding` + `/Differences`
        // per ISO 32000-1 §9.6.6.1. Round 28 honours both: the
        // /Differences array overrides specific byte slots from the
        // base map, and each glyph name is resolved through the AGL.
        if let Some(Object::Dict(enc_d)) = enc {
            // Resolve the base map. Per the spec, when /BaseEncoding
            // is absent the default depends on the font subtype — for
            // Type1 / Type3 it's the font's built-in encoding (which
            // we don't have access to here, so we use Standard as the
            // closest documented fallback); for TrueType it's the
            // implementation-defined platform encoding (we use
            // WinAnsi because Acrobat / Distiller default to it).
            let base_name = enc_d
                .entries()
                .iter()
                .find(|(k, _)| k == "BaseEncoding")
                .and_then(|(_, v)| match v {
                    Object::Name(s) => Some(s.clone()),
                    _ => None,
                });
            let base_map = match base_name.as_deref().and_then(BaseEncoding::from_name) {
                Some(b) => EncodingMap::from_base(b),
                None => {
                    // No (recognised) /BaseEncoding — pick a sensible
                    // default per the font subtype.
                    let default = match subtype {
                        "TrueType" => BaseEncoding::WinAnsi,
                        _ => BaseEncoding::Standard,
                    };
                    EncodingMap::from_base(default)
                }
            };
            // Overlay /Differences if present.
            let diffs_obj = enc_d
                .entries()
                .iter()
                .find(|(k, _)| k == "Differences")
                .map(|(_, v)| v.clone());
            let final_map = match diffs_obj {
                Some(arr @ Object::Array(_)) => {
                    let diffs = parse_encoding_differences(&arr)?;
                    apply_encoding_differences(&base_map, &diffs)
                }
                _ => base_map,
            };
            return Ok(FontDecoder::SimpleMap(Box::new(final_map)));
        }
        // Default for Type1 / Type3 with no /Encoding is
        // StandardEncoding (§9.6.6.1). TrueType with no /Encoding is
        // implementation-dependent — use WinAnsi.
        let default = match subtype {
            "TrueType" => BaseEncoding::WinAnsi,
            "Type1" | "Type3" | "MMType1" => BaseEncoding::Standard,
            _ => return Ok(FontDecoder::Latin1),
        };
        Ok(FontDecoder::SimpleMap(Box::new(EncodingMap::from_base(
            default,
        ))))
    }

    /// Decode a `Tj` / `TJ` operand byte-string into Unicode.
    fn decode(&self, bytes: &[u8]) -> String {
        match self {
            FontDecoder::ToUnicode { map, cid_width } => {
                let mut out = String::new();
                let w = *cid_width as usize;
                let mut i = 0;
                while i + w <= bytes.len() {
                    let cid = match w {
                        1 => bytes[i] as u32,
                        2 => ((bytes[i] as u32) << 8) | (bytes[i + 1] as u32),
                        _ => {
                            // Unsupported width — skip the rest.
                            break;
                        }
                    };
                    if let Some(s) = map.lookup(cid) {
                        out.push_str(s);
                    } else {
                        // Unmapped CID — emit U+FFFD as a marker so
                        // callers know decoding was lossy at that
                        // offset.
                        out.push('\u{FFFD}');
                    }
                    i += w;
                }
                out
            }
            FontDecoder::IdentityNoCMap => {
                // 2-byte CID → BMP code point.
                let mut out = String::new();
                let mut i = 0;
                while i + 2 <= bytes.len() {
                    let cp = ((bytes[i] as u32) << 8) | (bytes[i + 1] as u32);
                    if let Some(c) = char::from_u32(cp) {
                        out.push(c);
                    }
                    i += 2;
                }
                out
            }
            FontDecoder::SimpleMap(map) => map.decode(bytes),
            FontDecoder::Latin1 => bytes.iter().map(|&b| b as char).collect(),
        }
    }
}

// ────────────────────────── CMap parser ──────────────────────────

/// A parsed `/ToUnicode` CMap — the minimal slice ISO 32000-1 §9.10.3
/// allows: `bfchar` and `bfrange` blocks. The CMap header may declare
/// codespace ranges; we infer the byte width from the first observed
/// `bfchar` / `bfrange` source key length (1 or 2 — the only widths the
/// PDF spec allows for a CIDFont).
#[derive(Clone, Debug, Default)]
pub(crate) struct CMap {
    /// CID (interpreted as u32) → UTF-8 string. Multi-character target
    /// strings (ligatures, combining marks) are common — `<FB01>` for
    /// `fi` is the canonical example.
    table: HashMap<u32, String>,
    /// Inferred from the first bfchar/bfrange source operand. 1 for
    /// simple fonts (rare — usually accompanied by a tiny WinAnsi-ish
    /// table), 2 for the standard CIDFont case.
    pub(crate) byte_width: u8,
}

impl CMap {
    pub(crate) fn parse(bytes: &[u8]) -> Result<CMap, PdfError> {
        let mut cm = CMap {
            byte_width: 2, // canonical default; bfchar/bfrange may override
            ..CMap::default()
        };
        let mut i = 0;
        while i < bytes.len() {
            // Skip whitespace + comments.
            i = skip_ws_and_comments(bytes, i);
            if i >= bytes.len() {
                break;
            }
            // bfchar block: `N beginbfchar … endbfchar`.
            if let Some(rest) = peek_keyword(bytes, i, b"beginbfchar") {
                i = rest;
                i = parse_bfchar(bytes, i, &mut cm)?;
                continue;
            }
            if let Some(rest) = peek_keyword(bytes, i, b"beginbfrange") {
                i = rest;
                i = parse_bfrange(bytes, i, &mut cm)?;
                continue;
            }
            // Skip any other token — the CMap header (`CMapName`,
            // `CIDSystemInfo`, `codespacerange`, etc.) is ignored;
            // we only care about the bfchar/bfrange payload.
            i = skip_token(bytes, i);
        }
        Ok(cm)
    }

    fn lookup(&self, cid: u32) -> Option<&str> {
        self.table.get(&cid).map(|s| s.as_str())
    }
}

fn parse_bfchar(bytes: &[u8], mut i: usize, cm: &mut CMap) -> Result<usize, PdfError> {
    loop {
        i = skip_ws_and_comments(bytes, i);
        if i >= bytes.len() {
            return Err(PdfError::other("PDF CMap: unterminated beginbfchar block"));
        }
        if let Some(rest) = peek_keyword(bytes, i, b"endbfchar") {
            return Ok(rest);
        }
        // Two hex strings: <src> <dst>
        let (src_bytes, after_src) = read_hex_string_payload(bytes, i)?;
        i = after_src;
        i = skip_ws_and_comments(bytes, i);
        let (dst_bytes, after_dst) = read_hex_string_payload(bytes, i)?;
        i = after_dst;
        // Capture byte_width from the first src.
        if !src_bytes.is_empty() {
            cm.byte_width = src_bytes.len() as u8;
        }
        let cid = bytes_to_u32(&src_bytes);
        let s = utf16be_to_string(&dst_bytes);
        cm.table.insert(cid, s);
    }
}

fn parse_bfrange(bytes: &[u8], mut i: usize, cm: &mut CMap) -> Result<usize, PdfError> {
    loop {
        i = skip_ws_and_comments(bytes, i);
        if i >= bytes.len() {
            return Err(PdfError::other("PDF CMap: unterminated beginbfrange block"));
        }
        if let Some(rest) = peek_keyword(bytes, i, b"endbfrange") {
            return Ok(rest);
        }
        let (lo_bytes, after_lo) = read_hex_string_payload(bytes, i)?;
        i = after_lo;
        i = skip_ws_and_comments(bytes, i);
        let (hi_bytes, after_hi) = read_hex_string_payload(bytes, i)?;
        i = after_hi;
        if !lo_bytes.is_empty() {
            cm.byte_width = lo_bytes.len() as u8;
        }
        let lo = bytes_to_u32(&lo_bytes);
        let hi = bytes_to_u32(&hi_bytes);
        i = skip_ws_and_comments(bytes, i);
        // Two shapes per ISO 32000-1 §9.10.3:
        //   <lo> <hi> <dst-start>      -- consecutive scalar dst
        //   <lo> <hi> [ <dst0> <dst1> ... ] -- per-source explicit list
        if i < bytes.len() && bytes[i] == b'[' {
            // Array form.
            i += 1;
            let mut dst_idx = 0u32;
            loop {
                i = skip_ws_and_comments(bytes, i);
                if i >= bytes.len() {
                    return Err(PdfError::other("PDF CMap: unterminated bfrange array"));
                }
                if bytes[i] == b']' {
                    i += 1;
                    break;
                }
                let (dst_bytes, after) = read_hex_string_payload(bytes, i)?;
                i = after;
                let s = utf16be_to_string(&dst_bytes);
                let cid = lo + dst_idx;
                if cid > hi {
                    // More entries than the range — PDF generators
                    // sometimes do this; ignore extras.
                    continue;
                }
                cm.table.insert(cid, s);
                dst_idx += 1;
            }
        } else {
            // Scalar form — (hi - lo + 1) consecutive dst code points.
            let (dst_bytes, after) = read_hex_string_payload(bytes, i)?;
            i = after;
            // Treat the dst as a UTF-16BE string; only the LAST code unit
            // increments per the PDF spec ("if the range is N codes long,
            // the destinations are <dst_start>, <dst_start+1>, …"). We
            // implement the simplified rule: increment the trailing
            // 16-bit unit (or 8-bit if the dst is a single byte).
            let dst_str = utf16be_to_string(&dst_bytes);
            let count = hi.saturating_sub(lo) + 1;
            // Decompose the dst string into chars; for the
            // single-char-target case (the common one), iterate chars.
            if dst_str.chars().count() == 1 {
                let base = dst_str.chars().next().unwrap() as u32;
                for k in 0..count {
                    let cid = lo + k;
                    if let Some(c) = char::from_u32(base + k) {
                        cm.table.insert(cid, String::from(c));
                    }
                }
            } else {
                // Multi-char dst (ligature etc.) — only the first source
                // gets the explicit string; the rest get the
                // last-char-incremented form.
                let mut chars: Vec<char> = dst_str.chars().collect();
                for k in 0..count {
                    let cid = lo + k;
                    cm.table.insert(cid, chars.iter().collect::<String>());
                    if let Some(last) = chars.last_mut() {
                        if let Some(next) = char::from_u32(*last as u32 + 1) {
                            *last = next;
                        }
                    }
                }
            }
        }
    }
}

fn read_hex_string_payload(bytes: &[u8], start: usize) -> Result<(Vec<u8>, usize), PdfError> {
    if start >= bytes.len() || bytes[start] != b'<' {
        return Err(PdfError::other(format!(
            "PDF CMap: expected hex string at byte {start}"
        )));
    }
    let mut nibbles = Vec::new();
    let mut i = start + 1;
    while i < bytes.len() && bytes[i] != b'>' {
        let b = bytes[i];
        if let Some(v) = hex_nibble(b) {
            nibbles.push(v);
        } else if !is_ws(b) {
            // Some CMap producers embed `,` or other separators —
            // skip them per the spec's "ignore non-hex" guidance.
        }
        i += 1;
    }
    if i >= bytes.len() {
        return Err(PdfError::other(
            "PDF CMap: unterminated hex string in bfchar/bfrange",
        ));
    }
    // Skip the closing `>`.
    i += 1;
    // Pad odd-length to even with a trailing 0 (PDF §7.3.4.3).
    if nibbles.len() % 2 == 1 {
        nibbles.push(0);
    }
    let mut out = Vec::with_capacity(nibbles.len() / 2);
    for pair in nibbles.chunks_exact(2) {
        out.push((pair[0] << 4) | pair[1]);
    }
    Ok((out, i))
}

fn bytes_to_u32(b: &[u8]) -> u32 {
    let mut v = 0u32;
    for &x in b {
        v = (v << 8) | (x as u32);
    }
    v
}

fn utf16be_to_string(b: &[u8]) -> String {
    // PDF /ToUnicode dst is UTF-16BE per ISO 32000-1 §9.10.3. A single
    // byte is treated as one Latin-1 char (some hand-crafted CMaps for
    // simple fonts do this).
    if b.len() == 1 {
        return String::from(b[0] as char);
    }
    let mut units: Vec<u16> = Vec::with_capacity(b.len() / 2);
    for chunk in b.chunks_exact(2) {
        units.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&units)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}

fn is_ws(b: u8) -> bool {
    matches!(b, 0x00 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

fn skip_ws_and_comments(bytes: &[u8], mut i: usize) -> usize {
    loop {
        while i < bytes.len() && is_ws(bytes[i]) {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'%' {
            // PostScript-style comment to EOL.
            while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b'\r' {
                i += 1;
            }
            continue;
        }
        return i;
    }
}

fn peek_keyword(bytes: &[u8], i: usize, kw: &[u8]) -> Option<usize> {
    if i + kw.len() > bytes.len() {
        return None;
    }
    if &bytes[i..i + kw.len()] != kw {
        return None;
    }
    let after = i + kw.len();
    // Word boundary — next char must be ws / EOF / delim.
    if after < bytes.len() {
        let b = bytes[after];
        if !is_ws(b) && !matches!(b, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'/' | b'%') {
            return None;
        }
    }
    Some(after)
}

/// Skip exactly one CMap "thing" — a hex string, literal string, array,
/// dict, name, number, or bare keyword — and return the index PAST it.
/// **Always advances at least one byte** so callers using this in a loop
/// can't spin forever, even on input shapes the function doesn't
/// recognise.
fn skip_token(bytes: &[u8], i: usize) -> usize {
    if i >= bytes.len() {
        return i;
    }
    let b = bytes[i];
    // `<<` dict — must be checked BEFORE the bare `<` hex string.
    if b == b'<' && bytes.get(i + 1) == Some(&b'<') {
        let mut depth = 1u32;
        let mut j = i + 2;
        while j + 1 < bytes.len() && depth > 0 {
            if bytes[j] == b'<' && bytes[j + 1] == b'<' {
                depth += 1;
                j += 2;
                continue;
            }
            if bytes[j] == b'>' && bytes[j + 1] == b'>' {
                depth -= 1;
                j += 2;
                continue;
            }
            j += 1;
        }
        return j;
    }
    if b == b'<' {
        // Hex string.
        let mut j = i + 1;
        while j < bytes.len() && bytes[j] != b'>' {
            j += 1;
        }
        return j.saturating_add(1).min(bytes.len());
    }
    if b == b'(' {
        // Literal string — track depth.
        let mut depth = 1u32;
        let mut j = i + 1;
        while j < bytes.len() && depth > 0 {
            let c = bytes[j];
            if c == b'\\' && j + 1 < bytes.len() {
                j += 2;
                continue;
            }
            if c == b'(' {
                depth += 1;
            }
            if c == b')' {
                depth -= 1;
            }
            j += 1;
        }
        return j;
    }
    if b == b'[' {
        let mut depth = 1u32;
        let mut j = i + 1;
        while j < bytes.len() && depth > 0 {
            let c = bytes[j];
            if c == b'[' {
                depth += 1;
            } else if c == b']' {
                depth -= 1;
            }
            j += 1;
        }
        return j;
    }
    // Name `/foo`, number, or bare keyword — read until whitespace OR
    // a structural delimiter. Always consume the leading byte first so
    // we make forward progress on a single delimiter (`>`, `]`, `}`,
    // `%`) the parser doesn't otherwise recognise.
    let mut j = i + 1;
    while j < bytes.len()
        && !is_ws(bytes[j])
        && !matches!(
            bytes[j],
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
    {
        j += 1;
    }
    j
}

// ────────────────────────── content-stream walker ──────────────────────────

/// Per-page text-state walker. PDF interleaves text-matrix updates
/// (`Td`, `TD`, `Tm`, `T*`) with show operators (`Tj`, `TJ`, `'`, `"`)
/// inside a `BT` / `ET` block. We accumulate the current text-matrix +
/// font + size and emit one [`TextRun`] per show.
struct TextWalker {
    fonts: HashMap<String, FontDecoder>,
    runs: Vec<TextRun>,
    /// Parallel to `runs`: the MCID in scope at the moment of each
    /// emit. Populated even when `track_mcid` is false (it's free —
    /// just a `Vec<Option<u32>>` of `None`s). Round-29 marked-text
    /// extraction reads this; the round-22 raster path ignores it.
    run_mcids: Vec<Option<u32>>,

    // Operand stack — same shape as the path walker but text-flavoured
    // (we accept hex strings + literal strings as "string" operands and
    // arrays-of-stringy-stuff for `TJ`).
    operands: Vec<TextOperand>,

    // ── text state ──────────────────────────────────────────────────
    /// `true` between BT and ET.
    in_text: bool,
    /// Most recent /Tf operand (resource name without leading '/').
    cur_font: String,
    /// Most recent /Tf size.
    cur_size: f32,
    /// Text matrix `Tm`. Represented by its 2D affine components
    /// `[a b c d e f]`. Reset to identity at every BT.
    tm: [f32; 6],
    /// Text-line matrix — Td / TD / T* operate against this; Tm /
    /// '/" reset it. Same shape as `tm`.
    tlm: [f32; 6],
    /// Leading (Tl) — distance between baselines. Used by T* and "/'.
    leading: f32,
    /// Saved text states — one entry per `q`. We don't push the whole
    /// graphics state (paint, transform, etc.) since the path walker
    /// already covers those; just the text-relevant slots.
    saved: Vec<SavedTextState>,

    // ── marked-content state ────────────────────────────────────────
    /// Round-29 toggle: when `true`, `BDC`/`BMC`/`EMC` push and pop
    /// onto `mcid_stack` and emitted runs carry the top of the stack
    /// in `run_mcids`. When `false`, BDC/BMC/EMC are still tolerated
    /// (operands are dropped) but no per-run MCID is recorded.
    track_mcid: bool,
    /// Stack of `/MCID` integers (or `None` for `BDC` blocks whose
    /// property dict has no MCID, and for `BMC` blocks). The top of
    /// the stack is what `emit_show` stamps into `run_mcids`.
    mcid_stack: Vec<Option<u32>>,
}

#[derive(Clone, Debug)]
enum TextOperand {
    Number(f32),
    String(Vec<u8>),
    /// `TJ` array — alternating strings and numeric kern offsets.
    Array(Vec<TJItem>),
    Name(String),
    /// Inline dict literal `<<...>>`. We don't keep the full dict —
    /// only the `/MCID` hint we scanned out of it (None when the dict
    /// has no MCID slot). Used by `BDC` to push a marked-content frame.
    Dict {
        mcid: Option<u32>,
    },
}

#[derive(Clone, Debug)]
enum TJItem {
    Str(Vec<u8>),
    /// Kerning offset in *text-space units / 1000* (positive = move
    /// glyph rightwards by `f / 1000 * font_size` in user space). The
    /// field is preserved for round-23+ layout reconstruction; the
    /// round-22 walker drops it because it doesn't change the textual
    /// payload, only the typographic spacing.
    #[allow(dead_code)]
    Kern(f32),
}

#[derive(Clone, Debug)]
struct SavedTextState {
    font: String,
    size: f32,
    tm: [f32; 6],
    tlm: [f32; 6],
    leading: f32,
}

impl TextWalker {
    fn new(fonts: HashMap<String, FontDecoder>) -> Self {
        Self {
            fonts,
            runs: Vec::new(),
            run_mcids: Vec::new(),
            operands: Vec::new(),
            in_text: false,
            cur_font: String::new(),
            cur_size: 0.0,
            tm: identity(),
            tlm: identity(),
            leading: 0.0,
            saved: Vec::new(),
            track_mcid: false,
            mcid_stack: Vec::new(),
        }
    }

    fn into_runs(self) -> Vec<TextRun> {
        self.runs
    }

    fn into_runs_with_mcid(self) -> Vec<(TextRun, Option<u32>)> {
        self.runs.into_iter().zip(self.run_mcids).collect()
    }

    fn parse(&mut self, input: &[u8]) -> Result<(), PdfError> {
        let mut i = 0;
        while i < input.len() {
            let b = input[i];
            if is_ws(b) {
                i += 1;
                continue;
            }
            if b == b'%' {
                while i < input.len() && input[i] != b'\n' && input[i] != b'\r' {
                    i += 1;
                }
                continue;
            }
            if b == b'(' {
                let (end, payload) = read_literal_string(input, i)?;
                self.operands.push(TextOperand::String(payload));
                i = end;
                continue;
            }
            if b == b'<' && input.get(i + 1) != Some(&b'<') {
                let (payload, end) = read_hex_string_payload(input, i)?;
                self.operands.push(TextOperand::String(payload));
                i = end;
                continue;
            }
            if b == b'<' && input.get(i + 1) == Some(&b'<') {
                // Dict literal. We scan it for an `/MCID <int>` slot
                // (so `BDC` operands can recover the marked-content
                // identifier) but do NOT keep arbitrary dict payload
                // on the operand stack — only the MCID hint, encoded
                // as a special `TextOperand::Dict { mcid }` value.
                let start = i;
                let mut depth = 1u32;
                i += 2;
                while i + 1 < input.len() && depth > 0 {
                    if input[i] == b'<' && input[i + 1] == b'<' {
                        depth += 1;
                        i += 2;
                    } else if input[i] == b'>' && input[i + 1] == b'>' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                let mcid = scan_inline_mcid(&input[start..i]);
                self.operands.push(TextOperand::Dict { mcid });
                continue;
            }
            if b == b'[' {
                let (end, items) = read_tj_array(input, i)?;
                self.operands.push(TextOperand::Array(items));
                i = end;
                continue;
            }
            if b == b'/' {
                let mut end = i + 1;
                while end < input.len() && !is_ws(input[end]) && !is_delim(input[end]) {
                    end += 1;
                }
                let name = String::from_utf8_lossy(&input[i + 1..end]).into_owned();
                self.operands.push(TextOperand::Name(name));
                i = end;
                continue;
            }
            if matches!(b, b'+' | b'-' | b'.' | b'0'..=b'9') {
                let mut end = i;
                if matches!(input[end], b'+' | b'-') {
                    end += 1;
                }
                let mut saw_digit = false;
                let mut saw_dot = false;
                while end < input.len() {
                    let c = input[end];
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
                    let kw_end = scan_kw_end(input, i);
                    self.dispatch(&input[i..kw_end])?;
                    i = kw_end;
                    continue;
                }
                let s = str::from_utf8(&input[i..end]).map_err(|_| {
                    PdfError::other(format!("PDF text walker: non-UTF-8 number at byte {i}"))
                })?;
                let f: f32 = s.parse().map_err(|_| {
                    PdfError::other(format!("PDF text walker: invalid number `{s}` at byte {i}"))
                })?;
                self.operands.push(TextOperand::Number(f));
                i = end;
                continue;
            }
            // Keyword.
            let kw_end = scan_kw_end(input, i);
            if kw_end == i {
                i += 1;
                continue;
            }
            self.dispatch(&input[i..kw_end])?;
            i = kw_end;
        }
        Ok(())
    }

    fn dispatch(&mut self, op: &[u8]) -> Result<(), PdfError> {
        match op {
            b"q" => {
                self.saved.push(SavedTextState {
                    font: self.cur_font.clone(),
                    size: self.cur_size,
                    tm: self.tm,
                    tlm: self.tlm,
                    leading: self.leading,
                });
                self.operands.clear();
            }
            b"Q" => {
                if let Some(s) = self.saved.pop() {
                    self.cur_font = s.font;
                    self.cur_size = s.size;
                    self.tm = s.tm;
                    self.tlm = s.tlm;
                    self.leading = s.leading;
                }
                self.operands.clear();
            }
            b"BT" => {
                self.in_text = true;
                self.tm = identity();
                self.tlm = identity();
                self.operands.clear();
            }
            b"ET" => {
                self.in_text = false;
                self.operands.clear();
            }
            b"Tf" => {
                // /Name size Tf
                let size = self.pop_num().unwrap_or(0.0);
                let name = self.pop_name().unwrap_or_default();
                self.cur_font = name;
                self.cur_size = size;
                self.operands.clear();
            }
            b"Tm" => {
                // a b c d e f Tm — set both Tm and Tlm.
                let nums = self.take_n(6);
                if let Some(n) = nums {
                    self.tm = n;
                    self.tlm = n;
                }
            }
            b"Td" => {
                // tx ty Td — Tlm = translate(tx,ty) * Tlm; Tm = Tlm.
                let nums = self.take_n(2);
                if let Some(n) = nums {
                    let tx = n[0];
                    let ty = n[1];
                    let translate = [1.0, 0.0, 0.0, 1.0, tx, ty];
                    self.tlm = mul(translate, self.tlm);
                    self.tm = self.tlm;
                }
            }
            b"TD" => {
                // tx ty TD — like Td, but also sets leading = -ty.
                let nums = self.take_n(2);
                if let Some(n) = nums {
                    let tx = n[0];
                    let ty = n[1];
                    self.leading = -ty;
                    let translate = [1.0, 0.0, 0.0, 1.0, tx, ty];
                    self.tlm = mul(translate, self.tlm);
                    self.tm = self.tlm;
                }
            }
            b"TL" => {
                if let Some(n) = self.pop_num() {
                    self.leading = n;
                }
            }
            b"T*" => {
                // Move to next line: Td(0, -leading).
                let translate = [1.0, 0.0, 0.0, 1.0, 0.0, -self.leading];
                self.tlm = mul(translate, self.tlm);
                self.tm = self.tlm;
                self.operands.clear();
            }
            b"Tj" => {
                let s = self.pop_string().unwrap_or_default();
                self.emit_show(&s);
            }
            b"TJ" => {
                let arr = self.pop_array().unwrap_or_default();
                let mut buf = Vec::new();
                for item in arr {
                    match item {
                        TJItem::Str(b) => buf.extend_from_slice(&b),
                        // Kerning offsets don't change the text content;
                        // a future-round layout pass would translate
                        // them into spaces or word breaks.
                        TJItem::Kern(_) => {}
                    }
                }
                self.emit_show(&buf);
            }
            b"'" => {
                // Move-and-show: T*, then Tj.
                let translate = [1.0, 0.0, 0.0, 1.0, 0.0, -self.leading];
                self.tlm = mul(translate, self.tlm);
                self.tm = self.tlm;
                let s = self.pop_string().unwrap_or_default();
                self.emit_show(&s);
            }
            b"\"" => {
                // aw ac string " — set Tw, Tc, T*, Tj.
                let s = self.pop_string().unwrap_or_default();
                let _ac = self.pop_num().unwrap_or(0.0);
                let _aw = self.pop_num().unwrap_or(0.0);
                let translate = [1.0, 0.0, 0.0, 1.0, 0.0, -self.leading];
                self.tlm = mul(translate, self.tlm);
                self.tm = self.tlm;
                self.emit_show(&s);
            }
            // Other text-state operators we record-but-don't-act-on.
            b"Tc" | b"Tw" | b"Tz" | b"Tr" | b"Ts" => {
                self.operands.clear();
            }
            // Marked-content operators (ISO 32000-1 §14.6).
            b"BDC" => {
                // tag properties BDC. Pop properties, then tag.
                let mcid = match self.operands.pop() {
                    Some(TextOperand::Dict { mcid }) => mcid,
                    Some(TextOperand::Name(_)) => {
                        // /Properties resource ref — round-29 doesn't
                        // resolve indirect property dicts (the writer
                        // never emits them; pdftotext likewise treats
                        // unresolved property refs as MCID-less).
                        None
                    }
                    Some(other) => {
                        self.operands.push(other);
                        None
                    }
                    None => None,
                };
                let _tag = self.pop_name();
                if self.track_mcid {
                    self.mcid_stack.push(mcid);
                }
                self.operands.clear();
            }
            b"BMC" => {
                // tag BMC — no properties dict, no MCID.
                let _tag = self.pop_name();
                if self.track_mcid {
                    self.mcid_stack.push(None);
                }
                self.operands.clear();
            }
            b"EMC" => {
                if self.track_mcid {
                    self.mcid_stack.pop();
                }
                self.operands.clear();
            }
            b"MP" => {
                // tag MP — marked-point with no properties.
                self.operands.clear();
            }
            b"DP" => {
                // tag properties DP — marked-point with properties.
                self.operands.clear();
            }
            // Anything else (path / colour / state operators) — drop the
            // operands and continue.
            _ => {
                self.operands.clear();
            }
        }
        Ok(())
    }

    fn pop_num(&mut self) -> Option<f32> {
        match self.operands.pop()? {
            TextOperand::Number(n) => Some(n),
            other => {
                self.operands.push(other);
                None
            }
        }
    }

    fn pop_name(&mut self) -> Option<String> {
        match self.operands.pop()? {
            TextOperand::Name(s) => Some(s),
            other => {
                self.operands.push(other);
                None
            }
        }
    }

    fn pop_string(&mut self) -> Option<Vec<u8>> {
        match self.operands.pop()? {
            TextOperand::String(s) => Some(s),
            other => {
                self.operands.push(other);
                None
            }
        }
    }

    fn pop_array(&mut self) -> Option<Vec<TJItem>> {
        match self.operands.pop()? {
            TextOperand::Array(a) => Some(a),
            other => {
                self.operands.push(other);
                None
            }
        }
    }

    fn take_n(&mut self, n: usize) -> Option<[f32; 6]> {
        if self.operands.len() < n {
            self.operands.clear();
            return None;
        }
        let split = self.operands.len() - n;
        let tail: Vec<TextOperand> = self.operands.drain(split..).collect();
        let mut nums = [0.0f32; 6];
        for (i, op) in tail.into_iter().enumerate() {
            match op {
                TextOperand::Number(f) => nums[i] = f,
                _ => return None,
            }
        }
        Some(nums)
    }

    fn emit_show(&mut self, bytes: &[u8]) {
        if !self.in_text {
            // Show outside BT/ET — malformed but tolerate; the writer
            // wouldn't emit this.
            self.operands.clear();
            return;
        }
        let decoder = self.fonts.get(&self.cur_font);
        let text = match decoder {
            Some(d) => d.decode(bytes),
            None => {
                // No font resolved — fall back to Latin-1 bytes so the
                // run isn't dropped silently.
                bytes.iter().map(|&b| b as char).collect()
            }
        };
        self.runs.push(TextRun {
            text,
            position: (self.tm[4], self.tm[5]),
            font_name: self.cur_font.clone(),
            font_size: self.cur_size,
        });
        // Stamp the current MCID (top of stack) onto the run.
        let cur_mcid = self.mcid_stack.last().copied().unwrap_or(None);
        self.run_mcids.push(cur_mcid);
        self.operands.clear();
    }
}

// ────────────────────────── helpers ──────────────────────────

fn identity() -> [f32; 6] {
    [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
}

/// 2D affine matrix multiply: result = a * b. Both are
/// `[a b c d e f]` PDF text matrices interpreted as
/// `[ a b 0 ; c d 0 ; e f 1 ]` per ISO 32000-1 §8.3.4.
fn mul(a: [f32; 6], b: [f32; 6]) -> [f32; 6] {
    [
        a[0] * b[0] + a[1] * b[2],
        a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2],
        a[2] * b[1] + a[3] * b[3],
        a[4] * b[0] + a[5] * b[2] + b[4],
        a[4] * b[1] + a[5] * b[3] + b[5],
    ]
}

fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn scan_kw_end(input: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < input.len() && !is_ws(input[end]) && !is_delim(input[end]) {
        end += 1;
    }
    end
}

/// Best-effort scan of a top-level inline-dict slice (`<<...>>`) for
/// `/MCID <integer>`. We only care about the MCID at the dict's top
/// level — nested dicts are skipped wholesale. Whitespace tolerant;
/// returns `None` if no `/MCID` key is present.
fn scan_inline_mcid(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 || &bytes[..2] != b"<<" {
        return None;
    }
    let body = &bytes[2..bytes.len().saturating_sub(2)];
    let mut i = 0;
    let mut depth = 0u32;
    while i < body.len() {
        let b = body[i];
        if is_ws(b) {
            i += 1;
            continue;
        }
        if b == b'<' && body.get(i + 1) == Some(&b'<') {
            depth += 1;
            i += 2;
            continue;
        }
        if b == b'>' && body.get(i + 1) == Some(&b'>') {
            depth = depth.saturating_sub(1);
            i += 2;
            continue;
        }
        if depth > 0 {
            // Inside a nested dict — skip.
            i += 1;
            continue;
        }
        if b == b'/' {
            // Read name.
            let mut end = i + 1;
            while end < body.len() && !is_ws(body[end]) && !is_delim(body[end]) {
                end += 1;
            }
            let name = &body[i + 1..end];
            i = end;
            if name == b"MCID" {
                // Skip ws.
                while i < body.len() && is_ws(body[i]) {
                    i += 1;
                }
                // Read integer.
                let mut e = i;
                while e < body.len() && (body[e].is_ascii_digit() || body[e] == b'-') {
                    e += 1;
                }
                if e == i {
                    return None;
                }
                let s = std::str::from_utf8(&body[i..e]).ok()?;
                return s.parse::<u32>().ok();
            }
            // Else: skip the value that follows.
            continue;
        }
        // Skip any other top-level token.
        i += 1;
    }
    None
}

fn read_literal_string(input: &[u8], start: usize) -> Result<(usize, Vec<u8>), PdfError> {
    let mut end = start + 1;
    let mut depth = 1u32;
    let mut decoded = Vec::new();
    while end < input.len() {
        let b = input[end];
        if b == b'\\' {
            end += 1;
            if end >= input.len() {
                break;
            }
            // Handle escapes per ISO 32000-1 §7.3.4.2.
            let c = input[end];
            match c {
                b'n' => {
                    decoded.push(b'\n');
                    end += 1;
                }
                b'r' => {
                    decoded.push(b'\r');
                    end += 1;
                }
                b't' => {
                    decoded.push(b'\t');
                    end += 1;
                }
                b'b' => {
                    decoded.push(0x08);
                    end += 1;
                }
                b'f' => {
                    decoded.push(0x0C);
                    end += 1;
                }
                b'(' | b')' | b'\\' => {
                    decoded.push(c);
                    end += 1;
                }
                b'\n' | b'\r' => {
                    // Line continuation — skip CR/LF/CRLF.
                    end += 1;
                    if c == b'\r' && end < input.len() && input[end] == b'\n' {
                        end += 1;
                    }
                }
                b'0'..=b'7' => {
                    // Octal escape — up to 3 digits.
                    let mut v = 0u32;
                    let mut k = 0;
                    while k < 3 && end < input.len() && matches!(input[end], b'0'..=b'7') {
                        v = v * 8 + (input[end] - b'0') as u32;
                        end += 1;
                        k += 1;
                    }
                    decoded.push((v & 0xFF) as u8);
                }
                _ => {
                    decoded.push(c);
                    end += 1;
                }
            }
            continue;
        }
        if b == b'(' {
            depth += 1;
            decoded.push(b);
            end += 1;
            continue;
        }
        if b == b')' {
            depth -= 1;
            if depth == 0 {
                end += 1;
                return Ok((end, decoded));
            }
            decoded.push(b);
            end += 1;
            continue;
        }
        decoded.push(b);
        end += 1;
    }
    Err(PdfError::other(
        "PDF text walker: unterminated literal string",
    ))
}

fn read_tj_array(input: &[u8], start: usize) -> Result<(usize, Vec<TJItem>), PdfError> {
    let mut i = start + 1;
    let mut items = Vec::new();
    loop {
        i = {
            let mut k = i;
            while k < input.len() && (is_ws(input[k]) || input[k] == b'\n') {
                k += 1;
            }
            k
        };
        if i >= input.len() {
            return Err(PdfError::other("PDF text walker: unterminated TJ array"));
        }
        if input[i] == b']' {
            return Ok((i + 1, items));
        }
        if input[i] == b'(' {
            let (end, payload) = read_literal_string(input, i)?;
            items.push(TJItem::Str(payload));
            i = end;
            continue;
        }
        if input[i] == b'<' && input.get(i + 1) != Some(&b'<') {
            let (payload, end) = read_hex_string_payload(input, i)?;
            items.push(TJItem::Str(payload));
            i = end;
            continue;
        }
        if matches!(input[i], b'+' | b'-' | b'.' | b'0'..=b'9') {
            let mut end = i;
            if matches!(input[end], b'+' | b'-') {
                end += 1;
            }
            let mut saw_dot = false;
            while end < input.len()
                && (input[end].is_ascii_digit() || (input[end] == b'.' && !saw_dot))
            {
                if input[end] == b'.' {
                    saw_dot = true;
                }
                end += 1;
            }
            if let Ok(s) = str::from_utf8(&input[i..end]) {
                if let Ok(f) = s.parse::<f32>() {
                    items.push(TJItem::Kern(f));
                }
            }
            i = end;
            continue;
        }
        // Skip unknown bytes inside the array.
        i += 1;
    }
}

// Encoding tables have moved to `crate::reader::encoding` — round 28
// replaced the inline match-based helpers with a 256-entry
// `EncodingMap` that also accommodates `/Differences` overlays and
// multi-character ligature glyphs.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmap_bfchar_simple() {
        let cmap = b"
        /CIDInit /ProcSet findresource begin
        12 dict begin
        beginbfchar
        <0001> <0041>
        <0002> <0042>
        <0003> <0043>
        endbfchar
        ";
        let parsed = CMap::parse(cmap).unwrap();
        assert_eq!(parsed.byte_width, 2);
        assert_eq!(parsed.lookup(1), Some("A"));
        assert_eq!(parsed.lookup(2), Some("B"));
        assert_eq!(parsed.lookup(3), Some("C"));
    }

    #[test]
    fn cmap_bfrange_scalar_form() {
        // <0010> <0012> <0041> → 0x10→A, 0x11→B, 0x12→C
        let cmap = b"beginbfrange <0010> <0012> <0041> endbfrange";
        let parsed = CMap::parse(cmap).unwrap();
        assert_eq!(parsed.lookup(0x10), Some("A"));
        assert_eq!(parsed.lookup(0x11), Some("B"));
        assert_eq!(parsed.lookup(0x12), Some("C"));
    }

    #[test]
    fn cmap_bfrange_array_form() {
        // <0001> <0003> [ <0041> <0042> <0043> ]
        let cmap = b"beginbfrange <0001> <0003> [ <0041> <0042> <0043> ] endbfrange";
        let parsed = CMap::parse(cmap).unwrap();
        assert_eq!(parsed.lookup(1), Some("A"));
        assert_eq!(parsed.lookup(2), Some("B"));
        assert_eq!(parsed.lookup(3), Some("C"));
    }

    #[test]
    fn winansi_smart_quote_via_encoding_map() {
        // 0x93 = U+201C left double smart quote — verifies the
        // round-28 `EncodingMap` path produces the same bytes the
        // old inline `winansi_to_char` match did.
        let m = EncodingMap::from_base(BaseEncoding::WinAnsi);
        assert_eq!(m.decode(&[0x93]), "\u{201C}");
        assert_eq!(m.decode(b"A"), "A");
    }

    #[test]
    fn flat_text_joins_runs_with_spaces() {
        let pe = PdfTextExtraction {
            runs: vec![
                TextRun {
                    text: "Hello".into(),
                    position: (0.0, 0.0),
                    font_name: "F0".into(),
                    font_size: 12.0,
                },
                TextRun {
                    text: "World".into(),
                    position: (40.0, 0.0),
                    font_name: "F0".into(),
                    font_size: 12.0,
                },
            ],
        };
        assert_eq!(pe.flat_text(), "Hello World");
    }

    #[test]
    fn tm_matrix_multiply_translates() {
        let id = identity();
        let trans = [1.0, 0.0, 0.0, 1.0, 100.0, 200.0];
        let r = mul(trans, id);
        assert_eq!(r[4], 100.0);
        assert_eq!(r[5], 200.0);
    }

    #[test]
    fn cmap_bfchar_multichar_target() {
        // <0001> <00660069> → "fi" ligature (U+0066 U+0069)
        let cmap = b"beginbfchar <0001> <00660069> endbfchar";
        let parsed = CMap::parse(cmap).unwrap();
        assert_eq!(parsed.lookup(1), Some("fi"));
    }

    #[test]
    fn read_literal_string_handles_escapes() {
        let input = b"(Hello\\nWorld)";
        let (end, payload) = read_literal_string(input, 0).unwrap();
        assert_eq!(end, input.len());
        assert_eq!(payload, b"Hello\nWorld");
    }

    #[test]
    fn read_literal_string_handles_octal() {
        // \101 = 'A'.
        let input = b"(\\101BC)";
        let (_, payload) = read_literal_string(input, 0).unwrap();
        assert_eq!(payload, b"ABC");
    }

    #[test]
    fn read_tj_array_alternates_strings_and_kerns() {
        let input = b"[(Hi) -120 (World)]";
        let (_, items) = read_tj_array(input, 0).unwrap();
        assert_eq!(items.len(), 3);
        assert!(matches!(&items[0], TJItem::Str(s) if s == b"Hi"));
        assert!(matches!(&items[1], TJItem::Kern(k) if (*k - -120.0).abs() < 1e-3));
        assert!(matches!(&items[2], TJItem::Str(s) if s == b"World"));
    }
}
