//! Compact Font Format reader — just enough of Adobe Technical Note
//! #5176 (`docs/text/opentype/spec/5176.CFF.pdf`) to recover a font's
//! glyph names, built-in encoding and (for CID-keyed fonts) its
//! GID → CID charset, for text extraction (ISO 32000-1 §9.6.6.2 /
//! §9.10.2). Outlines are never interpreted.
//!
//! Every read is bounds-checked; a malformed program yields `None` (or
//! the partial data read so far) and never panics.

use crate::reader::font_tables::{
    EXPERT_CHARSET, EXPERT_ENCODING, EXPERT_SUBSET_CHARSET, STANDARD_ENCODING, STANDARD_STRINGS,
};

/// Number of predefined strings (§10: SIDs `0..nStdStrings`).
const N_STD_STRINGS: usize = 391;

/// What one built-in code selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodeTarget {
    /// A predefined encoding (§12 Table 16) or a supplement (Table 15)
    /// names the glyph by SID.
    Sid(u16),
    /// A custom encoding (§12 Tables 11–13) names it by GID.
    Gid(u16),
}

/// The parsed parts of the first font of a CFF FontSet.
#[derive(Clone, Debug)]
pub(crate) struct CffFont {
    /// GID → SID (name-keyed) or GID → CID (CID-keyed); index 0 is
    /// `.notdef` / CID 0.
    charset: Vec<u16>,
    /// Non-standard strings (String INDEX, SID `391..`).
    strings: Vec<Vec<u8>>,
    /// Built-in encoding, code → glyph; empty for CID-keyed fonts.
    encoding: Vec<Option<CodeTarget>>,
    /// `Registry`, `Ordering`, `Supplement` when the Top DICT starts
    /// with `ROS` (§9 Table 10) — a CID-keyed font.
    ros: Option<(String, String, i64)>,
    /// GIDs whose Type 2 charstring draws nothing (a space glyph).
    blank: Vec<bool>,
}

/// One INDEX (§5 Table 7): object byte ranges into the font data, and
/// the offset just past the INDEX.
struct Index {
    items: Vec<(usize, usize)>,
    end: usize,
}

fn card16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

fn offset(d: &[u8], at: usize, size: usize) -> Option<usize> {
    if !(1..=4).contains(&size) {
        return None;
    }
    let bytes = d.get(at..at + size)?;
    Some(bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize))
}

fn read_index(d: &[u8], at: usize) -> Option<Index> {
    let count = card16(d, at)? as usize;
    if count == 0 {
        return Some(Index {
            items: Vec::new(),
            end: at + 2,
        });
    }
    let off_size = *d.get(at + 2)? as usize;
    let offsets_at = at + 3;
    // Offsets are relative to the byte preceding the object data.
    let data_base = offsets_at.checked_add((count + 1).checked_mul(off_size)?)? - 1;
    // Bound the allocation by what the data can actually hold.
    if count > d.len() {
        return None;
    }
    let mut items = Vec::with_capacity(count);
    let mut prev = offset(d, offsets_at, off_size)?;
    for i in 1..=count {
        let next = offset(d, offsets_at + i * off_size, off_size)?;
        if next < prev {
            return None;
        }
        let (s, e) = (data_base.checked_add(prev)?, data_base.checked_add(next)?);
        if e > d.len() {
            return None;
        }
        items.push((s, e));
        prev = next;
    }
    let end = data_base.checked_add(prev)?;
    Some(Index { items, end })
}

/// A DICT operand (§4 Table 3 / Table 5); reals keep only their
/// integer part, which every operator read here (offsets, SIDs,
/// supplement) needs.
fn dict_entries(d: &[u8]) -> Vec<(u16, Vec<i64>)> {
    let mut out = Vec::new();
    let mut operands: Vec<i64> = Vec::new();
    let mut i = 0;
    while i < d.len() {
        let b0 = d[i];
        match b0 {
            0..=21 => {
                let op = if b0 == 12 {
                    i += 1;
                    match d.get(i) {
                        Some(&b1) => 1200 + b1 as u16,
                        None => break,
                    }
                } else {
                    b0 as u16
                };
                out.push((op, std::mem::take(&mut operands)));
                i += 1;
            }
            28 => {
                let Some(v) = card16(d, i + 1) else { break };
                operands.push(v as i16 as i64);
                i += 3;
            }
            29 => {
                let Some(b) = d.get(i + 1..i + 5) else { break };
                operands.push(i32::from_be_bytes([b[0], b[1], b[2], b[3]]) as i64);
                i += 5;
            }
            30 => {
                // Real: nibbles up to an 0xf terminator.
                let mut text = String::new();
                i += 1;
                'real: while i < d.len() {
                    for nib in [d[i] >> 4, d[i] & 0xf] {
                        match nib {
                            0..=9 => text.push((b'0' + nib) as char),
                            0xa => text.push('.'),
                            0xb => text.push('E'),
                            0xc => text.push_str("E-"),
                            0xe => text.push('-'),
                            0xf => {
                                i += 1;
                                break 'real;
                            }
                            _ => {}
                        }
                    }
                    i += 1;
                }
                operands.push(text.parse::<f64>().map(|v| v as i64).unwrap_or(0));
            }
            32..=246 => {
                operands.push(b0 as i64 - 139);
                i += 1;
            }
            247..=250 => {
                let Some(&b1) = d.get(i + 1) else { break };
                operands.push((b0 as i64 - 247) * 256 + b1 as i64 + 108);
                i += 2;
            }
            251..=254 => {
                let Some(&b1) = d.get(i + 1) else { break };
                operands.push(-(b0 as i64 - 251) * 256 - b1 as i64 - 108);
                i += 2;
            }
            // Reserved bytes (22–27, 31, 255): stop rather than guess.
            _ => break,
        }
        if operands.len() > 48 {
            break;
        }
    }
    out
}

impl CffFont {
    /// Parse a bare CFF FontSet (`/FontFile3 /Subtype /Type1C` or
    /// `/CIDFontType0C`, or an OpenType `CFF ` table) and keep its
    /// first font.
    pub(crate) fn parse(d: &[u8]) -> Option<CffFont> {
        // §6 Header: major version 1; hdrSize locates the Name INDEX.
        if *d.first()? != 1 {
            return None;
        }
        let hdr_size = *d.get(2)? as usize;
        let names = read_index(d, hdr_size)?;
        let top = read_index(d, names.end)?;
        let strings_idx = read_index(d, top.end)?;
        let &(ts, te) = top.items.first()?;
        let top_dict = dict_entries(&d[ts..te]);
        let get = |op: u16| {
            top_dict
                .iter()
                .find(|(o, _)| *o == op)
                .map(|(_, v)| v.as_slice())
        };
        let strings: Vec<Vec<u8>> = strings_idx
            .items
            .iter()
            .map(|&(s, e)| d[s..e].to_vec())
            .collect();

        let char_strings_at = usize::try_from(*get(17)?.first()?).ok()?;
        let char_strings = read_index(d, char_strings_at)?;
        let n_glyphs = char_strings.items.len();
        if n_glyphs == 0 {
            return None;
        }
        let charstring_type = get(1206).and_then(|v| v.first().copied()).unwrap_or(2);
        let blank = char_strings
            .items
            .iter()
            .map(|&(s, e)| charstring_type == 2 && is_blank_type2(&d[s..e]))
            .collect();

        let mut font = CffFont {
            charset: Vec::new(),
            strings,
            encoding: Vec::new(),
            ros: None,
            blank,
        };
        if let Some(ros) = get(1230)
            && ros.len() >= 3
        {
            let reg = font.sid_string(ros[0] as u16).unwrap_or_default();
            let ord = font.sid_string(ros[1] as u16).unwrap_or_default();
            font.ros = Some((reg, ord, ros[2]));
        }

        let charset_op = get(15).and_then(|v| v.first().copied()).unwrap_or(0);
        font.charset = read_charset(d, charset_op, n_glyphs, font.ros.is_some())?;

        if font.ros.is_none() {
            let enc_op = get(16).and_then(|v| v.first().copied()).unwrap_or(0);
            font.encoding = read_encoding(d, enc_op).unwrap_or_default();
        }
        Some(font)
    }

    /// True for a CID-keyed font (Top DICT `ROS`).
    pub(crate) fn is_cid(&self) -> bool {
        self.ros.is_some()
    }

    /// `(Registry, Ordering, Supplement)` of a CID-keyed font.
    pub(crate) fn ros(&self) -> Option<(&str, &str, i64)> {
        self.ros
            .as_ref()
            .map(|(r, o, s)| (r.as_str(), o.as_str(), *s))
    }

    /// The string a SID names (§10).
    fn sid_string(&self, sid: u16) -> Option<String> {
        let sid = sid as usize;
        if sid < N_STD_STRINGS {
            return Some(STANDARD_STRINGS[sid].to_owned());
        }
        let bytes = self.strings.get(sid - N_STD_STRINGS)?;
        Some(bytes.iter().map(|&b| b as char).collect())
    }

    /// Number of glyphs (the CharStrings INDEX count).
    pub(crate) fn glyph_count(&self) -> usize {
        self.charset.len()
    }

    /// The glyph name of `gid` in a name-keyed font.
    pub(crate) fn glyph_name(&self, gid: u16) -> Option<String> {
        if self.is_cid() {
            return None;
        }
        self.sid_string(*self.charset.get(gid as usize)?)
    }

    /// The CID of `gid` in a CID-keyed font (§13 / §18: the charset
    /// holds CIDs).
    pub(crate) fn gid_to_cid(&self, gid: u16) -> Option<u16> {
        if !self.is_cid() {
            return None;
        }
        self.charset.get(gid as usize).copied()
    }

    /// True when glyph `gid`'s charstring paints nothing.
    pub(crate) fn is_blank(&self, gid: u16) -> bool {
        self.blank.get(gid as usize).copied().unwrap_or(false)
    }

    /// The glyph name the built-in encoding assigns to `code`.
    pub(crate) fn code_glyph_name(&self, code: u8) -> Option<String> {
        match self.encoding.get(code as usize).copied().flatten()? {
            CodeTarget::Sid(sid) => self.sid_string(sid),
            CodeTarget::Gid(gid) => self.glyph_name(gid),
        }
    }

    /// The GID of the glyph named `name`, searching the charset.
    pub(crate) fn gid_of_name(&self, name: &str) -> Option<u16> {
        if self.is_cid() {
            return None;
        }
        (0..self.charset.len()).find_map(|gid| {
            (self.sid_string(self.charset[gid]).as_deref() == Some(name)).then_some(gid as u16)
        })
    }
}

/// True for a Type 2 charstring (TN #5177) that reaches `endchar`
/// having only declared a width and stem hints — no `moveto` starts a
/// path, and `endchar` carries no accented-character operands. A
/// charstring that calls a subroutine, uses `hintmask` / `cntrmask`
/// or any other operator is not judged blank.
fn is_blank_type2(cs: &[u8]) -> bool {
    let mut args = 0usize;
    let mut i = 0;
    while i < cs.len() {
        let b = cs[i];
        match b {
            28 => {
                args += 1;
                i += 3;
            }
            32..=246 => {
                args += 1;
                i += 1;
            }
            247..=254 => {
                args += 1;
                i += 2;
            }
            255 => {
                args += 1;
                i += 5;
            }
            // hstem, vstem, hstemhm, vstemhm: hints only.
            1 | 3 | 18 | 23 => {
                args = 0;
                i += 1;
            }
            // endchar: blank unless it is the four-argument accent
            // composition form (a width may precede).
            14 => return args <= 1,
            _ => return false,
        }
    }
    false
}

/// §13 charset: predefined ids 0–2 (Table 22) or formats 0 / 1 / 2.
fn read_charset(d: &[u8], op: i64, n_glyphs: usize, cid: bool) -> Option<Vec<u16>> {
    let mut out = Vec::with_capacity(n_glyphs.min(65536));
    out.push(0u16);
    if !cid && (0..=2).contains(&op) {
        match op {
            0 => out.extend((1..n_glyphs.min(229)).map(|s| s as u16)),
            1 => out.extend(EXPERT_CHARSET.iter().take(n_glyphs - 1)),
            _ => out.extend(EXPERT_SUBSET_CHARSET.iter().take(n_glyphs - 1)),
        }
        out.resize(n_glyphs, 0);
        return Some(out);
    }
    let at = usize::try_from(op).ok()?;
    let format = *d.get(at)?;
    let mut p = at + 1;
    match format {
        0 => {
            while out.len() < n_glyphs {
                out.push(card16(d, p)?);
                p += 2;
            }
        }
        1 | 2 => {
            while out.len() < n_glyphs {
                let first = card16(d, p)?;
                let n_left = if format == 1 {
                    *d.get(p + 2)? as usize
                } else {
                    card16(d, p + 2)? as usize
                };
                p += if format == 1 { 3 } else { 4 };
                for k in 0..=n_left {
                    if out.len() >= n_glyphs {
                        break;
                    }
                    out.push(first.wrapping_add(k as u16));
                }
            }
        }
        _ => return None,
    }
    Some(out)
}

/// §12 encoding: predefined ids 0 / 1 (Table 16) or formats 0 / 1,
/// with the supplement of Tables 14–15 when the format's high bit is
/// set.
fn read_encoding(d: &[u8], op: i64) -> Option<Vec<Option<CodeTarget>>> {
    let mut out = vec![None; 256];
    if op == 0 || op == 1 {
        let table = if op == 0 {
            &STANDARD_ENCODING
        } else {
            &EXPERT_ENCODING
        };
        for (code, &sid) in table.iter().enumerate() {
            if sid != 0 {
                out[code] = Some(CodeTarget::Sid(sid));
            }
        }
        return Some(out);
    }
    let at = usize::try_from(op).ok()?;
    let format = *d.get(at)?;
    let mut p = at + 1;
    match format & 0x7f {
        0 => {
            let n = *d.get(p)? as usize;
            p += 1;
            for gid in 1..=n {
                let code = *d.get(p)? as usize;
                out[code] = Some(CodeTarget::Gid(gid as u16));
                p += 1;
            }
        }
        1 => {
            let n_ranges = *d.get(p)? as usize;
            p += 1;
            let mut gid = 1u16;
            for _ in 0..n_ranges {
                let first = *d.get(p)? as usize;
                let n_left = *d.get(p + 1)? as usize;
                p += 2;
                for k in 0..=n_left {
                    if let Some(slot) = out.get_mut(first + k) {
                        *slot = Some(CodeTarget::Gid(gid));
                    }
                    gid = gid.wrapping_add(1);
                }
            }
        }
        _ => return None,
    }
    if format & 0x80 != 0 {
        let n_sups = *d.get(p)? as usize;
        p += 1;
        for _ in 0..n_sups {
            let code = *d.get(p)? as usize;
            let sid = card16(d, p + 1)?;
            out[code] = Some(CodeTarget::Sid(sid));
            p += 3;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a DICT integer the §4 Table 3 way (5-byte form).
    fn int(v: i32) -> Vec<u8> {
        let mut o = vec![29];
        o.extend_from_slice(&v.to_be_bytes());
        o
    }

    fn index(items: &[&[u8]]) -> Vec<u8> {
        let mut o = (items.len() as u16).to_be_bytes().to_vec();
        if items.is_empty() {
            return o;
        }
        o.push(4);
        let mut off = 1u32;
        o.extend_from_slice(&off.to_be_bytes());
        for it in items {
            off += it.len() as u32;
            o.extend_from_slice(&off.to_be_bytes());
        }
        for it in items {
            o.extend_from_slice(it);
        }
        o
    }

    /// A name-keyed font with glyphs `.notdef A Bee` (custom SID for
    /// "Bee"), a format-0 charset and a format-1 encoding with a
    /// supplement.
    fn build(cid: bool) -> Vec<u8> {
        let header = [1u8, 0, 4, 4];
        let name = index(&[b"Test"]);
        let strings = index(&[b"Bee", b"Adobe", b"Japan1"]);
        let gsubrs = index(&[]);
        // GID 0 and 2 blank (width + endchar), GID 1 draws.
        let charstrings = index(&[&[14], &[139, 139, 21, 14], &[189, 14]]);
        // Layout: header, name, top (fixed size), strings, gsubrs,
        // charset, encoding, charstrings.
        let top_len = |top: &[u8]| index(&[top]).len();
        let mk_top = |cs: i32, enc: i32, chs: i32| {
            let mut t = Vec::new();
            if cid {
                t.extend(int(392));
                t.extend(int(393));
                t.extend(int(2));
                t.extend([12, 30]);
            }
            t.extend(int(cs));
            t.push(15);
            if !cid {
                t.extend(int(enc));
                t.push(16);
            }
            t.extend(int(chs));
            t.push(17);
            t
        };
        let probe = mk_top(0, 0, 0);
        let base = header.len() + name.len() + top_len(&probe) + strings.len() + gsubrs.len();
        // charset format 0: SIDs for GID 1, 2 (A = 34, Bee = 391), or
        // CIDs 100, 101 for the CID-keyed variant.
        let charset: Vec<u8> = if cid {
            vec![0, 0, 100, 0, 101]
        } else {
            vec![0, 0, 34, 0x01, 0x87]
        };
        // encoding format 1 | 0x80: one range 65..=66 → GIDs 1, 2;
        // supplement code 97 → SID 34 ("A").
        let encoding: Vec<u8> = vec![0x81, 1, 65, 1, 1, 97, 0, 34];
        let cs_at = base;
        let enc_at = cs_at + charset.len();
        let chs_at = enc_at + encoding.len();
        let top = mk_top(cs_at as i32, enc_at as i32, chs_at as i32);
        let mut out = header.to_vec();
        out.extend(name);
        out.extend(index(&[&top]));
        out.extend(strings);
        out.extend(gsubrs);
        out.extend(charset);
        out.extend(encoding);
        out.extend(charstrings);
        out
    }

    #[test]
    fn name_keyed_charset_and_encoding() {
        let f = CffFont::parse(&build(false)).expect("parse");
        assert!(!f.is_cid());
        assert_eq!(f.glyph_count(), 3);
        assert_eq!(f.glyph_name(1).as_deref(), Some("A"));
        assert_eq!(f.glyph_name(2).as_deref(), Some("Bee"));
        assert_eq!(f.code_glyph_name(65).as_deref(), Some("A"));
        assert_eq!(f.code_glyph_name(66).as_deref(), Some("Bee"));
        assert_eq!(f.code_glyph_name(97).as_deref(), Some("A"));
        assert_eq!(f.code_glyph_name(98), None);
        assert_eq!(f.gid_of_name("Bee"), Some(2));
        assert!(!f.is_blank(1));
        assert!(f.is_blank(2));
    }

    #[test]
    fn cid_keyed_charset_and_ros() {
        let f = CffFont::parse(&build(true)).expect("parse");
        assert!(f.is_cid());
        assert_eq!(f.ros(), Some(("Adobe", "Japan1", 2)));
        assert_eq!(f.gid_to_cid(1), Some(100));
        assert_eq!(f.gid_to_cid(2), Some(101));
        assert_eq!(f.code_glyph_name(65), None);
    }

    #[test]
    fn predefined_tables_line_up() {
        // Appendix B: code 0x41 is SID 34 "A" in Standard Encoding.
        assert_eq!(STANDARD_STRINGS[STANDARD_ENCODING[0x41] as usize], "A");
        assert_eq!(
            STANDARD_STRINGS[EXPERT_ENCODING[0x24] as usize],
            "dollaroldstyle"
        );
        assert_eq!(STANDARD_STRINGS[EXPERT_CHARSET[0] as usize], "space");
        assert_eq!(STANDARD_STRINGS[390], "Semibold");
    }

    #[test]
    fn truncated_input_is_rejected_without_panic() {
        let full = build(false);
        for n in 0..full.len() {
            let _ = CffFont::parse(&full[..n]);
        }
        assert!(CffFont::parse(&[]).is_none());
    }
}
