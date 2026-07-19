//! Round-418 — **embedded CMap files** as a Type 0 font's `/Encoding`
//! (ISO 32000-1 §9.7.5.3 Table 120 + §9.7.5.4 + §9.7.6.2 + §9.7.6.3).
//!
//! A composite font whose encoding is not one of the predefined CMap
//! names carries a stream defining the mapping from character codes
//! to CIDs. The stream body is a PostScript-syntax CMap file; the
//! slice a conforming PDF reader needs (per the §9.7.5.4 constraints,
//! which bar `bfchar` from an `/Encoding` CMap and pin the font
//! number to 0) is:
//!
//! * `begincodespacerange … endcodespacerange` — the per-width input
//!   byte territory (§9.7.6.2: codes are matched by increasing
//!   length, each byte component-wise within the range bounds; code
//!   length ≤ 4).
//! * `begincidchar / begincidrange` — code → CID mappings (a range
//!   maps consecutive codes to consecutive CIDs).
//! * `beginnotdefchar / beginnotdefrange` — substitute CIDs consulted
//!   when the normal mapping fails (§9.7.6.3).
//! * `usecmap` — inherited mappings. Per §9.7.5.4 (a), a CMap using
//!   the in-stream `usecmap` operator must also identify the base in
//!   the stream dictionary's `/UseCMap` entry, so this reader
//!   resolves inheritance from the dictionary entry (stream form
//!   parsed recursively; the predefined `Identity-H` / `Identity-V`
//!   names synthesized directly) and skips the in-stream token.
//!
//! The §9.7.6.3 rules for invalid codes are implemented: a byte
//! sequence matching no codespace consumes the width chosen by the
//! partial-match algorithm (longest partial match, ties to the
//! shortest range) and maps through the notdef chain to CID 0.
//!
//! `/WMode` (Table 120) is surfaced for callers that lay out
//! vertical text; it does not affect the code → CID mapping.

use std::collections::HashMap;

use crate::error::PdfError;
use crate::objects::{Object, Stream};
use crate::reader::document::{decode_stream, DocumentReader};
use crate::reader::text::{
    bytes_to_u32, peek_keyword, read_hex_string_payload, skip_token, skip_ws_and_comments,
    CodespaceRange,
};

/// One `<lo> <hi> cid` mapping from a `begincidrange` (or
/// `beginnotdefrange`) block. Membership is byte-component-wise, like
/// a codespace range; the CID offset is the linear code difference.
#[derive(Clone, Debug)]
struct CidRange {
    lo: Vec<u8>,
    hi: Vec<u8>,
    cid_start: u32,
}

impl CidRange {
    fn width(&self) -> u8 {
        self.lo.len() as u8
    }

    /// True when `code` (already known to be `width` bytes wide) lies
    /// inside this range — component-wise membership against
    /// `lo..=hi`, checked on the big-endian byte expansion.
    fn contains(&self, width: u8, code: u32) -> bool {
        if self.width() != width {
            return false;
        }
        let w = self.lo.len();
        for (k, (lo_b, hi_b)) in self.lo.iter().zip(self.hi.iter()).enumerate() {
            let shift = 8 * (w - 1 - k);
            let b = ((code >> shift) & 0xFF) as u8;
            if b < *lo_b || b > *hi_b {
                return false;
            }
        }
        true
    }

    /// CID for `code` under the **cidrange** rule: consecutive codes
    /// map to consecutive CIDs from `cid_start` (§9.7.6.2 — "the
    /// mappings defined by … corresponding operators for ranges").
    fn lookup(&self, width: u8, code: u32) -> Option<u32> {
        if !self.contains(width, code) {
            return None;
        }
        let lo_v = bytes_to_u32(&self.lo);
        Some(self.cid_start.wrapping_add(code.wrapping_sub(lo_v)))
    }

    /// CID for `code` under the **notdefrange** rule: every code in
    /// the range substitutes the same CID (§9.7.6.3 — a notdef
    /// mapping yields "a substitute character selector", one CID for
    /// the whole range, mirroring the simple-font `.notdef` glyph).
    fn lookup_constant(&self, width: u8, code: u32) -> Option<u32> {
        self.contains(width, code).then_some(self.cid_start)
    }
}

/// A parsed CID CMap — the code → CID half of a Type 0 font's
/// `/Encoding` when it is an embedded stream.
#[derive(Clone, Debug, Default)]
pub(crate) struct CidCMap {
    /// Declared codespace ranges (all widths, declaration order kept
    /// for the §9.7.6.3 tie-break scans).
    codespaces: Vec<CodespaceRange>,
    /// `cidchar` singles, keyed by `(width, code)` — the width keeps
    /// `<20>` and `<0020>` distinct per the §9.7.6.2 "codes of that
    /// length" rule.
    chars: HashMap<(u8, u32), u32>,
    /// `cidrange` runs, scanned in declaration order.
    ranges: Vec<CidRange>,
    /// `notdefchar` singles.
    notdef_chars: HashMap<(u8, u32), u32>,
    /// `notdefrange` runs.
    notdef_ranges: Vec<CidRange>,
    /// Table 120 `/WMode` — 0 horizontal (default), 1 vertical.
    pub(crate) wmode: u8,
}

/// Depth bound on `/UseCMap` chains (a conforming file needs 1).
const MAX_USECMAP_DEPTH: usize = 8;

impl CidCMap {
    /// Parse a CMap stream body (§9.7.5.4 syntax subset). Unknown
    /// tokens — the PostScript scaffolding, `CIDSystemInfo`, comments
    /// — are skipped; only the code-mapping operators are load-bearing.
    pub(crate) fn parse(bytes: &[u8]) -> Result<CidCMap, PdfError> {
        let mut cm = CidCMap::default();
        let mut i = 0;
        while i < bytes.len() {
            i = skip_ws_and_comments(bytes, i);
            if i >= bytes.len() {
                break;
            }
            if let Some(rest) = peek_keyword(bytes, i, b"begincodespacerange") {
                i = parse_codespace_block(bytes, rest, &mut cm.codespaces)?;
                continue;
            }
            if let Some(rest) = peek_keyword(bytes, i, b"begincidchar") {
                i = parse_char_block(bytes, rest, b"endcidchar", &mut cm.chars)?;
                continue;
            }
            if let Some(rest) = peek_keyword(bytes, i, b"begincidrange") {
                i = parse_range_block(bytes, rest, b"endcidrange", &mut cm.ranges)?;
                continue;
            }
            if let Some(rest) = peek_keyword(bytes, i, b"beginnotdefchar") {
                i = parse_char_block(bytes, rest, b"endnotdefchar", &mut cm.notdef_chars)?;
                continue;
            }
            if let Some(rest) = peek_keyword(bytes, i, b"beginnotdefrange") {
                i = parse_range_block(bytes, rest, b"endnotdefrange", &mut cm.notdef_ranges)?;
                continue;
            }
            // `usecmap` (and everything else) skips: inheritance is
            // resolved from the stream dictionary's /UseCMap entry
            // per the §9.7.5.4 (a) pairing requirement.
            i = skip_token(bytes, i);
        }
        Ok(cm)
    }

    /// Parse a CMap `/Encoding` stream including its Table 120 stream
    /// dictionary (`/WMode`, `/UseCMap` inheritance chain).
    pub(crate) fn from_stream(
        reader: &mut DocumentReader<'_>,
        stream: &Stream,
        depth: usize,
    ) -> Result<CidCMap, PdfError> {
        let bytes = decode_stream(stream)?;
        let mut cm = CidCMap::parse(&bytes)?;
        cm.wmode = stream
            .dict
            .entries()
            .iter()
            .find(|(k, _)| k == "WMode")
            .and_then(|(_, v)| match v {
                Object::Integer(1) => Some(1),
                _ => None,
            })
            .unwrap_or(0);
        // /UseCMap chain (bounded).
        if depth < MAX_USECMAP_DEPTH {
            let use_obj = stream
                .dict
                .entries()
                .iter()
                .find(|(k, _)| k == "UseCMap")
                .map(|(_, v)| v.clone());
            match use_obj {
                Some(Object::Name(name)) => {
                    if name == "Identity-H" || name == "Identity-V" {
                        cm.merge_base(CidCMap::identity());
                    }
                    // Any other predefined name would need the Adobe
                    // character-collection CMap data, which ISO 32000
                    // does not carry — the overlay's own mappings
                    // still apply (tolerant degradation).
                }
                Some(obj) => {
                    if let Ok(Object::Stream(base)) = reader.deref(obj) {
                        let base_cm = CidCMap::from_stream(reader, &base, depth + 1)?;
                        cm.merge_base(base_cm);
                    }
                }
                None => {}
            }
        }
        Ok(cm)
    }

    /// The Identity mapping (2-byte codes, CID = code) — the shape of
    /// the predefined Identity-H / Identity-V CMaps, used as a
    /// `/UseCMap` base.
    pub(crate) fn identity() -> CidCMap {
        CidCMap {
            codespaces: vec![CodespaceRange {
                lo: vec![0x00, 0x00],
                hi: vec![0xFF, 0xFF],
            }],
            ranges: vec![CidRange {
                lo: vec![0x00, 0x00],
                hi: vec![0xFF, 0xFF],
                cid_start: 0,
            }],
            ..CidCMap::default()
        }
    }

    /// Fold `base` under `self` per the §9.7.5.3 `/UseCMap` rule:
    /// "the referencing CMap shall specify only the character
    /// mappings that differ from the referenced CMap" — so `self`'s
    /// entries stay authoritative and `base`'s fill the rest.
    fn merge_base(&mut self, base: CidCMap) {
        for (key, cid) in base.chars {
            self.chars.entry(key).or_insert(cid);
        }
        // Range scan order makes the overlay win: `self` ranges are
        // consulted before appended base ranges (chars always win
        // over ranges, matching the §9.7.6.2 "looked up in the
        // character code mappings" single-code precedence).
        self.ranges.extend(base.ranges);
        for (key, cid) in base.notdef_chars {
            self.notdef_chars.entry(key).or_insert(cid);
        }
        self.notdef_ranges.extend(base.notdef_ranges);
        self.codespaces.extend(base.codespaces);
    }

    /// Extract the next character code from `bytes` per §9.7.6.2 —
    /// match against 1-byte codespace ranges first, then longer, up
    /// to 4 — returning `(consumed, Some((width, code)))`. When no
    /// codespace matches, the §9.7.6.3 partial-match rules choose how
    /// many bytes to consume and the result is `(consumed, None)`
    /// (an invalid code — the caller substitutes via notdef / CID 0).
    ///
    /// Always consumes ≥ 1 byte; `bytes` must be non-empty.
    pub(crate) fn next_code(&self, bytes: &[u8]) -> (usize, Option<(u8, u32)>) {
        debug_assert!(!bytes.is_empty());
        if self.codespaces.is_empty() {
            // Malformed CMap with no codespace declaration: fall back
            // to the 2-byte convention (the overwhelmingly common
            // composite shape), clamped to the input.
            let w = 2usize.min(bytes.len());
            return (w, Some((w as u8, bytes_to_u32(&bytes[..w]))));
        }
        // §9.7.6.2 — successively longer codes until a match.
        for width in 1..=4usize {
            if width > bytes.len() {
                break;
            }
            for cs in self.codespaces.iter().filter(|c| c.width() == width) {
                if cs.matches(bytes) {
                    return (width, Some((width as u8, bytes_to_u32(&bytes[..width]))));
                }
            }
        }
        // §9.7.6.3 — invalid code. Choose the best partially matching
        // codespace range: longest per-byte partial match; ties go to
        // the range with the shortest codes; no partial match at all
        // (first byte matches no range's first byte) also picks the
        // shortest-code range.
        let mut best_partial = 0usize;
        let mut best_width = self.codespaces.iter().map(|c| c.width()).min().unwrap_or(1);
        for cs in &self.codespaces {
            let p = cs.partial_match_len(bytes);
            let better = p > best_partial || (p == best_partial && cs.width() < best_width);
            if p > 0 && better {
                best_partial = p;
                best_width = cs.width();
            }
        }
        (best_width.min(bytes.len()).max(1), None)
    }

    /// Map an extracted code to a CID per §9.7.6.2 + §9.7.6.3:
    /// character mappings (singles, then ranges in declaration
    /// order), then notdef mappings, then CID 0.
    pub(crate) fn cid_for_code(&self, code: Option<(u8, u32)>) -> u32 {
        let Some((width, code)) = code else {
            return 0;
        };
        if let Some(cid) = self.chars.get(&(width, code)) {
            return *cid;
        }
        for r in &self.ranges {
            if let Some(cid) = r.lookup(width, code) {
                return cid;
            }
        }
        if let Some(cid) = self.notdef_chars.get(&(width, code)) {
            return *cid;
        }
        for r in &self.notdef_ranges {
            if let Some(cid) = r.lookup_constant(width, code) {
                return cid;
            }
        }
        0
    }

    /// Split a show-operand byte string into CIDs.
    pub(crate) fn cids(&self, bytes: &[u8]) -> Vec<u32> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let (consumed, code) = self.next_code(&bytes[i..]);
            out.push(self.cid_for_code(code));
            i += consumed.max(1);
        }
        out
    }

    /// Number of codes the operand splits into (for callers that
    /// only need the glyph count).
    pub(crate) fn code_count(&self, bytes: &[u8]) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i < bytes.len() {
            let (consumed, _) = self.next_code(&bytes[i..]);
            count += 1;
            i += consumed.max(1);
        }
        count
    }
}

impl CodespaceRange {
    /// Length of the longest input prefix that stays inside this
    /// range's per-byte bounds (≤ the range width) — the §9.7.6.3
    /// partial-match measure.
    fn partial_match_len(&self, bytes: &[u8]) -> usize {
        let mut n = 0;
        for (b, (lo, hi)) in bytes.iter().zip(self.lo.iter().zip(self.hi.iter())) {
            if b < lo || b > hi {
                break;
            }
            n += 1;
        }
        n
    }
}

/// `N begincodespacerange <lo> <hi> … endcodespacerange`.
fn parse_codespace_block(
    bytes: &[u8],
    mut i: usize,
    out: &mut Vec<CodespaceRange>,
) -> Result<usize, PdfError> {
    loop {
        i = skip_ws_and_comments(bytes, i);
        if i >= bytes.len() {
            return Err(PdfError::other(
                "PDF CID CMap: unterminated begincodespacerange block",
            ));
        }
        if let Some(rest) = peek_keyword(bytes, i, b"endcodespacerange") {
            return Ok(rest);
        }
        let (lo, after_lo) = read_hex_string_payload(bytes, i)?;
        i = skip_ws_and_comments(bytes, after_lo);
        let (hi, after_hi) = read_hex_string_payload(bytes, i)?;
        i = after_hi;
        // Same tolerances as the ToUnicode parser: equal non-zero
        // widths only, capped at the 4-byte ceiling.
        if lo.is_empty() || hi.is_empty() || lo.len() != hi.len() || lo.len() > 4 {
            continue;
        }
        out.push(CodespaceRange { lo, hi });
    }
}

/// `N begin(cid|notdef)char <src> dst … end…char` — dst is a plain
/// decimal integer CID.
fn parse_char_block(
    bytes: &[u8],
    mut i: usize,
    end_kw: &[u8],
    out: &mut HashMap<(u8, u32), u32>,
) -> Result<usize, PdfError> {
    loop {
        i = skip_ws_and_comments(bytes, i);
        if i >= bytes.len() {
            return Err(PdfError::other("PDF CID CMap: unterminated char block"));
        }
        if let Some(rest) = peek_keyword(bytes, i, end_kw) {
            return Ok(rest);
        }
        let (src, after_src) = read_hex_string_payload(bytes, i)?;
        i = skip_ws_and_comments(bytes, after_src);
        let (cid, after_cid) = read_integer(bytes, i)?;
        i = after_cid;
        if src.is_empty() || src.len() > 4 {
            continue;
        }
        out.insert((src.len() as u8, bytes_to_u32(&src)), cid);
    }
}

/// `N begin(cid|notdef)range <lo> <hi> cid … end…range`.
fn parse_range_block(
    bytes: &[u8],
    mut i: usize,
    end_kw: &[u8],
    out: &mut Vec<CidRange>,
) -> Result<usize, PdfError> {
    loop {
        i = skip_ws_and_comments(bytes, i);
        if i >= bytes.len() {
            return Err(PdfError::other("PDF CID CMap: unterminated range block"));
        }
        if let Some(rest) = peek_keyword(bytes, i, end_kw) {
            return Ok(rest);
        }
        let (lo, after_lo) = read_hex_string_payload(bytes, i)?;
        i = skip_ws_and_comments(bytes, after_lo);
        let (hi, after_hi) = read_hex_string_payload(bytes, i)?;
        i = skip_ws_and_comments(bytes, after_hi);
        let (cid_start, after_cid) = read_integer(bytes, i)?;
        i = after_cid;
        if lo.is_empty() || hi.is_empty() || lo.len() != hi.len() || lo.len() > 4 {
            continue;
        }
        out.push(CidRange { lo, hi, cid_start });
    }
}

/// A bare decimal (optionally signed, clamped at 0) integer token.
fn read_integer(bytes: &[u8], start: usize) -> Result<(u32, usize), PdfError> {
    let mut i = start;
    let mut negative = false;
    if i < bytes.len() && (bytes[i] == b'-' || bytes[i] == b'+') {
        negative = bytes[i] == b'-';
        i += 1;
    }
    let digits_start = i;
    let mut value: u64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        value = (value * 10 + (bytes[i] - b'0') as u64).min(u32::MAX as u64);
        i += 1;
    }
    if i == digits_start {
        return Err(PdfError::other(format!(
            "PDF CID CMap: expected integer at byte {start}"
        )));
    }
    // A negative CID is out of spec — clamp to 0 tolerantly.
    Ok((if negative { 0 } else { value as u32 }, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Shift-JIS-shaped mixed-width CMap, following the §9.7.5.4
    /// example's structure (different, small numbers).
    const SAMPLE: &[u8] = b"%!PS-Adobe-3.0 Resource-CMap
/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CMapName /Test-H def
/CMapType 1 def
/WMode 0 def
2 begincodespacerange
<00> <7F>
<8140> <FCFC>
endcodespacerange
1 beginnotdefrange
<00> <1F> 500
endnotdefrange
2 begincidrange
<20> <7D> 1
<8140> <817E> 100
endcidrange
1 begincidchar
<7E> 99
endcidchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end
";

    #[test]
    fn parses_and_maps_singles_ranges_notdef() {
        let cm = CidCMap::parse(SAMPLE).expect("parse");
        // cidrange: <20>..<7D> starts at CID 1.
        assert_eq!(cm.cid_for_code(Some((1, 0x20))), 1);
        assert_eq!(cm.cid_for_code(Some((1, 0x41))), 1 + (0x41 - 0x20));
        // cidchar single.
        assert_eq!(cm.cid_for_code(Some((1, 0x7E))), 99);
        // 2-byte range.
        assert_eq!(cm.cid_for_code(Some((2, 0x8140))), 100);
        assert_eq!(cm.cid_for_code(Some((2, 0x8151))), 100 + 0x11);
        // notdef range serves the control bytes.
        assert_eq!(cm.cid_for_code(Some((1, 0x05))), 500);
        // Unmapped in-codespace code → CID 0.
        assert_eq!(cm.cid_for_code(Some((1, 0x7F))), 0);
        // Invalid code (no codespace) → CID 0.
        assert_eq!(cm.cid_for_code(None), 0);
    }

    #[test]
    fn segmentation_matches_shortest_codespace_first() {
        let cm = CidCMap::parse(SAMPLE).expect("parse");
        // "A" (1-byte), then 0x81 0x40 (2-byte), then "~".
        let cids = cm.cids(&[0x41, 0x81, 0x40, 0x7E]);
        assert_eq!(cids, vec![1 + (0x41 - 0x20), 100, 99]);
        assert_eq!(cm.code_count(&[0x41, 0x81, 0x40, 0x7E]), 3);
    }

    #[test]
    fn invalid_code_consumes_partial_match_width() {
        let cm = CidCMap::parse(SAMPLE).expect("parse");
        // 0x81 opens the 2-byte codespace but 0x20 is outside its
        // second-byte bounds (0x40..0xFC): §9.7.6.3(b) chooses the
        // longest partial match (the 2-byte range), so 2 bytes are
        // consumed and the code maps to CID 0. The following byte
        // then decodes normally.
        let (consumed, code) = cm.next_code(&[0x81, 0x20, 0x41]);
        assert_eq!(consumed, 2);
        assert_eq!(code, None);
        let cids = cm.cids(&[0x81, 0x20, 0x41]);
        assert_eq!(cids, vec![0, 1 + (0x41 - 0x20)]);
    }

    #[test]
    fn first_byte_matching_nothing_consumes_shortest_width() {
        // Only a 2-byte codespace; a first byte outside every range's
        // first-byte bounds triggers §9.7.6.3(a): the range with the
        // shortest codes (the only one — 2 bytes) sets the consumed
        // width.
        let cm = CidCMap::parse(
            b"1 begincodespacerange <8140> <FCFC> endcodespacerange \
              1 begincidrange <8140> <817E> 7 endcidrange",
        )
        .expect("parse");
        let (consumed, code) = cm.next_code(&[0x20, 0x81, 0x40]);
        assert_eq!(consumed, 2);
        assert_eq!(code, None);
    }

    #[test]
    fn identity_base_via_merge() {
        let mut cm = CidCMap::parse(
            b"1 begincodespacerange <0000> <FFFF> endcodespacerange \
              1 begincidrange <0041> <0041> 9000 endcidrange",
        )
        .expect("parse");
        cm.merge_base(CidCMap::identity());
        // The overlay's own mapping wins …
        assert_eq!(cm.cid_for_code(Some((2, 0x0041))), 9000);
        // … and everything else falls through to identity.
        assert_eq!(cm.cid_for_code(Some((2, 0x0042))), 0x0042);
    }

    #[test]
    fn empty_codespaces_default_to_two_byte_codes() {
        let cm = CidCMap::parse(b"1 begincidrange <0020> <007E> 1 endcidrange").expect("parse");
        let cids = cm.cids(&[0x00, 0x41, 0x00, 0x42]);
        assert_eq!(cids, vec![1 + (0x41 - 0x20), 1 + (0x42 - 0x20)]);
    }
}
