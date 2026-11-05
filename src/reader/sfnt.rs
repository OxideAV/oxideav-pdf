//! sfnt (TrueType / OpenType) reader — the table directory, the
//! `cmap` character-to-glyph subtables and the `post` glyph names,
//! which is what text extraction needs from an embedded `/FontFile2`
//! or OpenType `/FontFile3` (ISO 32000-1 §9.6.6.4, §9.10.2).
//!
//! Sources: `docs/text/opentype/otspec-otff.html` (table directory),
//! `otspec-cmap.html` (subtable formats 0 / 4 / 6 / 12),
//! `otspec-post.html` + `post-standard-mac-glyph-names.md` (`post`
//! versions 1.0 / 2.0 / 2.5). Glyph outlines are never interpreted.
//! Every read is bounds-checked; malformed tables yield `None` or an
//! empty mapping, never a panic.

use std::collections::HashMap;

use crate::reader::font_tables::MAC_GLYPH_NAMES;

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// An sfnt font: the raw data and its table directory.
#[derive(Clone, Debug)]
pub(crate) struct Sfnt<'a> {
    data: &'a [u8],
    tables: Vec<([u8; 4], usize, usize)>,
}

/// One `cmap` subtable, decoded to a code → GID map.
#[derive(Clone, Debug, Default)]
pub(crate) struct CmapSubtable {
    pub platform: u16,
    pub encoding: u16,
    pub map: HashMap<u32, u16>,
}

impl<'a> Sfnt<'a> {
    /// Parse the table directory (sfntVersion `0x00010000`, `OTTO` or
    /// the legacy `true`).
    pub(crate) fn parse(data: &'a [u8]) -> Option<Sfnt<'a>> {
        let version = u32_at(data, 0)?;
        if !matches!(version, 0x0001_0000 | 0x4F54_544F | 0x7472_7565) {
            return None;
        }
        let num_tables = u16_at(data, 4)? as usize;
        let mut tables = Vec::with_capacity(num_tables.min(256));
        for i in 0..num_tables {
            let rec = 12 + i * 16;
            let tag: [u8; 4] = data.get(rec..rec + 4)?.try_into().ok()?;
            let off = u32_at(data, rec + 8)? as usize;
            let len = u32_at(data, rec + 12)? as usize;
            // A record pointing past the data is dropped, the rest kept
            // (subsetters truncate trailing tables).
            if off.checked_add(len).is_some_and(|e| e <= data.len()) {
                tables.push((tag, off, len));
            }
        }
        Some(Sfnt { data, tables })
    }

    /// The bytes of the table tagged `tag`.
    pub(crate) fn table(&self, tag: &[u8; 4]) -> Option<&'a [u8]> {
        self.tables
            .iter()
            .find(|(t, _, _)| t == tag)
            .map(|&(_, off, len)| &self.data[off..off + len])
    }

    /// `maxp.numGlyphs`.
    pub(crate) fn num_glyphs(&self) -> Option<u16> {
        u16_at(self.table(b"maxp")?, 4)
    }

    /// Per GID, true when the glyph has no outline (`loca[n] ==
    /// loca[n+1]`, `otspec-loca`; short or long form per
    /// `head.indexToLocFormat`). Empty for CFF-outline fonts.
    pub(crate) fn blank_glyphs(&self) -> Vec<bool> {
        let (Some(head), Some(loca), Some(n)) =
            (self.table(b"head"), self.table(b"loca"), self.num_glyphs())
        else {
            return Vec::new();
        };
        let long = match u16_at(head, 50) {
            Some(0) => false,
            Some(1) => true,
            _ => return Vec::new(),
        };
        let off = |i: usize| {
            if long {
                u32_at(loca, 4 * i)
            } else {
                u16_at(loca, 2 * i).map(|v| u32::from(v) * 2)
            }
        };
        (0..n as usize)
            .map(|g| matches!((off(g), off(g + 1)), (Some(a), Some(b)) if a == b))
            .collect()
    }

    /// Every `cmap` subtable this reader understands (formats 0, 4, 6,
    /// 12), in directory order.
    pub(crate) fn cmap_subtables(&self) -> Vec<CmapSubtable> {
        let Some(cmap) = self.table(b"cmap") else {
            return Vec::new();
        };
        let n = u16_at(cmap, 2).unwrap_or(0) as usize;
        let mut out = Vec::new();
        for i in 0..n {
            let rec = 4 + i * 8;
            let (Some(platform), Some(encoding), Some(off)) = (
                u16_at(cmap, rec),
                u16_at(cmap, rec + 2),
                u32_at(cmap, rec + 4),
            ) else {
                break;
            };
            if let Some(map) = cmap.get(off as usize..).and_then(parse_cmap_subtable) {
                out.push(CmapSubtable {
                    platform,
                    encoding,
                    map,
                });
            }
        }
        out
    }

    /// GID → glyph name from the `post` table (versions 1.0, 2.0, 2.5);
    /// empty for 3.0 or an unreadable table.
    pub(crate) fn post_glyph_names(&self) -> Vec<Option<String>> {
        let Some(post) = self.table(b"post") else {
            return Vec::new();
        };
        let Some(version) = u32_at(post, 0) else {
            return Vec::new();
        };
        let mac = |i: usize| MAC_GLYPH_NAMES.get(i).map(|s| (*s).to_owned());
        match version {
            0x0001_0000 => (0..MAC_GLYPH_NAMES.len()).map(mac).collect(),
            0x0002_0000 => {
                let Some(n) = u16_at(post, 32) else {
                    return Vec::new();
                };
                let n = n as usize;
                // Custom names: Pascal strings after the index array.
                let mut custom: Vec<String> = Vec::new();
                let mut p = 34 + 2 * n;
                while let Some(&len) = post.get(p) {
                    let Some(s) = post.get(p + 1..p + 1 + len as usize) else {
                        break;
                    };
                    custom.push(s.iter().map(|&b| b as char).collect());
                    p += 1 + len as usize;
                }
                (0..n)
                    .map(|g| {
                        let idx = u16_at(post, 34 + 2 * g)? as usize;
                        if idx < 258 {
                            mac(idx)
                        } else {
                            custom.get(idx - 258).cloned()
                        }
                    })
                    .collect()
            }
            0x0002_5000 => {
                let Some(n) = u16_at(post, 32) else {
                    return Vec::new();
                };
                (0..n as usize)
                    .map(|g| {
                        let off = *post.get(34 + g)? as i8 as isize;
                        let idx = (g as isize).checked_add(off)?;
                        mac(usize::try_from(idx).ok()?)
                    })
                    .collect()
            }
            _ => Vec::new(),
        }
    }
}

/// Decode one `cmap` subtable starting at `d[0]`.
fn parse_cmap_subtable(d: &[u8]) -> Option<HashMap<u32, u16>> {
    let format = u16_at(d, 0)?;
    let mut map = HashMap::new();
    match format {
        0 => {
            for code in 0..256usize {
                let gid = *d.get(6 + code)? as u16;
                if gid != 0 {
                    map.insert(code as u32, gid);
                }
            }
        }
        4 => {
            let seg_x2 = u16_at(d, 6)? as usize;
            let seg = seg_x2 / 2;
            let ends = 14;
            let starts = ends + seg_x2 + 2;
            let deltas = starts + seg_x2;
            let ranges = deltas + seg_x2;
            for i in 0..seg {
                let end = u16_at(d, ends + 2 * i)? as u32;
                let start = u16_at(d, starts + 2 * i)? as u32;
                let delta = u16_at(d, deltas + 2 * i)?;
                let range_at = ranges + 2 * i;
                let range_off = u16_at(d, range_at)? as usize;
                if start > end {
                    continue;
                }
                for c in start..=end {
                    if c == 0xFFFF {
                        break;
                    }
                    let gid = if range_off == 0 {
                        (c as u16).wrapping_add(delta)
                    } else {
                        // glyphId = *(idRangeOffset[i]/2 + (c -
                        // startCode[i]) + &idRangeOffset[i])
                        let at = range_at + range_off + 2 * (c - start) as usize;
                        match u16_at(d, at) {
                            Some(0) | None => 0,
                            Some(g) => g.wrapping_add(delta),
                        }
                    };
                    if gid != 0 {
                        map.insert(c, gid);
                    }
                }
            }
        }
        6 => {
            let first = u16_at(d, 6)? as u32;
            let count = u16_at(d, 8)? as u32;
            for k in 0..count {
                let gid = u16_at(d, 10 + 2 * k as usize)?;
                if gid != 0 {
                    map.insert(first + k, gid);
                }
            }
        }
        12 => {
            let n = u32_at(d, 12)? as usize;
            for g in 0..n {
                let rec = 16 + g * 12;
                let start = u32_at(d, rec)?;
                let end = u32_at(d, rec + 4)?;
                let gid0 = u32_at(d, rec + 8)?;
                // Bound pathological groups; Unicode stops at 0x10FFFF.
                if end < start || end > 0x10FFFF {
                    continue;
                }
                for c in start..=end {
                    let gid = gid0.wrapping_add(c - start);
                    if gid != 0 && gid <= 0xFFFF {
                        map.insert(c, gid as u16);
                    }
                }
            }
        }
        _ => return None,
    }
    Some(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sfnt(tables: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0, 1, 0, 0];
        out.extend((tables.len() as u16).to_be_bytes());
        out.extend([0u8; 6]);
        let mut off = 12 + 16 * tables.len();
        let mut body: Vec<u8> = Vec::new();
        for (tag, data) in tables {
            out.extend(*tag);
            out.extend([0u8; 4]);
            out.extend((off as u32).to_be_bytes());
            out.extend((data.len() as u32).to_be_bytes());
            body.extend(data);
            off += data.len();
        }
        out.extend(body);
        out
    }

    fn be16(v: &[u16]) -> Vec<u8> {
        v.iter().flat_map(|x| x.to_be_bytes()).collect()
    }

    #[test]
    fn cmap_format4_and_post_v2() {
        // Format 4, two segments: 0x41..=0x42 → 1, 2 (delta) and the
        // 0xFFFF terminator.
        let mut f4 = be16(&[4, 0, 0, 4, 0, 0, 0]);
        f4.extend(be16(&[0x42, 0xFFFF, 0, 0x41, 0xFFFF]));
        f4.extend(be16(&[(1u16).wrapping_sub(0x41), 1, 0, 0]));
        let mut cmap = be16(&[0, 1, 3, 1]);
        cmap.extend(12u32.to_be_bytes());
        cmap.extend(f4);
        // post 2.0: three glyphs `.notdef`, `A` (mac 36), custom "Bee".
        let mut post = 0x0002_0000u32.to_be_bytes().to_vec();
        post.extend([0u8; 28]);
        post.extend(be16(&[3, 0, 36, 258]));
        post.extend([3, b'B', b'e', b'e']);
        let maxp = [0u8, 0, 0x50, 0, 0, 3].to_vec();
        let font = sfnt(&[(b"cmap", cmap), (b"maxp", maxp), (b"post", post)]);
        let s = Sfnt::parse(&font).expect("sfnt");
        assert_eq!(s.num_glyphs(), Some(3));
        let subs = s.cmap_subtables();
        assert_eq!(subs.len(), 1);
        assert_eq!((subs[0].platform, subs[0].encoding), (3, 1));
        assert_eq!(subs[0].map.get(&0x41), Some(&1));
        assert_eq!(subs[0].map.get(&0x42), Some(&2));
        let names = s.post_glyph_names();
        assert_eq!(names[1].as_deref(), Some("A"));
        assert_eq!(names[2].as_deref(), Some("Bee"));
    }

    #[test]
    fn truncated_tables_do_not_panic() {
        let font = sfnt(&[(b"cmap", be16(&[0, 1, 3, 1, 0, 12, 4, 0, 0, 9]))]);
        for n in 0..font.len() {
            if let Some(s) = Sfnt::parse(&font[..n]) {
                let _ = s.cmap_subtables();
                let _ = s.post_glyph_names();
            }
        }
    }
}
