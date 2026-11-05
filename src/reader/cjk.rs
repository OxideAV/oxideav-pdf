//! Predefined CJK CMaps (ISO 32000-1 §9.7.5.2 Table 118) and the
//! CID → Unicode step of §9.10.2 for the Adobe character collections.
//!
//! A Type 0 font may name a predefined CMap (`90ms-RKSJ-H`,
//! `GBK-EUC-H`, `UniJIS-UCS2-H`, …) instead of embedding one, and a
//! CIDFont may draw its glyphs from the Adobe-Japan1 / GB1 / CNS1 /
//! Korea1 / KR collections. ISO 32000 defines the mechanism but not
//! the tables; they are Adobe's published CMap resources, staged with
//! their BSD-3-Clause licence under `docs/document/pdf/cmap-resources/`.
//!
//! Rather than bundling the 16 MB of PostScript CMap files, the crate
//! carries one generated table (`data/cjk_cmaps.bin`, ~320 KB of
//! zlib) holding, per collection, the CID → Unicode map taken from
//! the collection's `cid2code.txt` UTF-32 column (for Adobe-Japan1 the
//! JIS X 0208 / 0212 databases' canonical value first; a CID that only
//! legacy CMaps select takes the character its code denotes in a
//! sibling CMap of the same encoding), and per non-Unicode
//! predefined CMap its codespace ranges and code → CID runs (with
//! `usecmap` inheritance resolved, a `-V` CMap stored as its
//! differences from the `-H` one). The Unicode-encoded CMaps
//! (`Uni…-UCS2/UTF8/UTF16/UTF32`) need no table: their codes *are*
//! Unicode. Where a CID still has several Unicode values the lowest
//! code point is used (a choice §9.10.2's last paragraph leaves to the
//! reader). The table decompresses lazily on first use.
//!
//! The whole module is behind the default-on `cjk-cmaps` feature;
//! without it every lookup answers `None` and composite fonts fall
//! back to the Identity behaviour.
//!
//! Generated-table format (all integers LEB128 varints, `sv` =
//! zig-zag signed): `"OXCJK\x02"`, collection count, then per
//! collection `name`, CID count, CID → Unicode runs, Unicode → CID
//! runs; then the CMap count and per CMap `name`, collection index,
//! WMode, parent (`0` or index + 1), codespace ranges `(w, lo[w],
//! hi[w])`, and for each code width 1..=4 its code → CID runs. A run
//! list is a count followed by `(Δstart, sv Δtarget, len − 1)`
//! triples, each delta taken from the previous run's end.
//!
//! The data tables reproduced in `data/cjk_cmaps.bin` carry Adobe's
//! notice: Copyright 1990-2023 Adobe. All rights reserved. Redistribution
//! and use in source and binary forms, with or without modification, are
//! permitted provided that the following conditions are met:
//! Redistributions of source code must retain the above copyright notice,
//! this list of conditions and the following disclaimer. Redistributions
//! in binary form must reproduce the above copyright notice, this list of
//! conditions and the following disclaimer in the documentation and/or
//! other materials provided with the distribution. Neither the name of
//! Adobe nor the names of its contributors may be used to endorse or
//! promote products derived from this software without specific prior
//! written permission. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS
//! AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//! INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//! MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
//! IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
//! ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//! DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
//! GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//! INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
//! IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
//! OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
//! ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::reader::cid_cmap::CidCMap;
use crate::reader::text::CodespaceRange;

/// The Unicode encoding form a `Uni…` predefined CMap uses
/// (§9.7.5.2: names containing UCS2 / UTF16 / UTF8 / UTF32).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnicodeForm {
    Ucs2,
    Utf16,
    Utf8,
    Utf32,
}

/// A predefined `/Encoding` name, resolved.
#[derive(Clone, Debug)]
pub(crate) enum Predefined {
    /// `Identity-H` / `Identity-V`, and the `Adobe-<Ordering>-<n>`
    /// identity CMaps: 2-byte codes, CID = code.
    Identity {
        collection: Option<usize>,
        wmode: u8,
    },
    /// A `Uni…` CMap: the code is a Unicode value in `form`.
    Unicode {
        form: UnicodeForm,
        collection: Option<usize>,
        wmode: u8,
    },
    /// A legacy-encoding CMap (Shift-JIS, EUC, GBK, Big Five, …) from
    /// the generated table.
    Legacy { index: usize },
}

impl Predefined {
    /// Writing mode (§9.7.5 `WMode`): 1 for the vertical CMaps.
    pub(crate) fn wmode(&self) -> u8 {
        match self {
            Predefined::Identity { wmode, .. } | Predefined::Unicode { wmode, .. } => *wmode,
            Predefined::Legacy { index } => data().map(|d| d.cmaps[*index].wmode).unwrap_or(0),
        }
    }

    /// The character collection the CMap's CIDs index.
    pub(crate) fn collection(&self) -> Option<usize> {
        match self {
            Predefined::Identity { collection, .. } | Predefined::Unicode { collection, .. } => {
                *collection
            }
            Predefined::Legacy { index } => data().map(|d| d.cmaps[*index].collection),
        }
    }

    /// Split the next code off `bytes` (non-empty): `(consumed, CID,
    /// Unicode text when the code itself is Unicode)`.
    pub(crate) fn next(&self, bytes: &[u8]) -> (usize, u32, Option<String>) {
        match self {
            Predefined::Identity { .. } => {
                if bytes.len() < 2 {
                    return (bytes.len(), 0, None);
                }
                (2, u32::from(u16::from_be_bytes([bytes[0], bytes[1]])), None)
            }
            Predefined::Unicode {
                form, collection, ..
            } => {
                let (n, cp) = next_unicode(*form, bytes);
                let text = cp.and_then(char::from_u32).map(String::from);
                let cid = cp
                    .zip(*collection)
                    .and_then(|(u, c)| unicode_to_cid(c, u))
                    .unwrap_or(0);
                (n, cid, text)
            }
            Predefined::Legacy { index } => {
                let Some(d) = data() else {
                    return (1, 0, None);
                };
                let cm = &d.cmaps[*index];
                let (n, code) = cm.segmenter.next_code(bytes);
                let cid = code
                    .and_then(|(w, c)| d.legacy_cid(*index, w, c))
                    .unwrap_or(0);
                (n.max(1), cid, None)
            }
        }
    }
}

/// Decode one code of a Unicode-form CMap: `(consumed, code point)`.
fn next_unicode(form: UnicodeForm, b: &[u8]) -> (usize, Option<u32>) {
    let be16 = |i: usize| {
        b.get(i..i + 2)
            .map(|s| u32::from(u16::from_be_bytes([s[0], s[1]])))
    };
    match form {
        UnicodeForm::Ucs2 => match be16(0) {
            Some(u) => (2, Some(u)),
            None => (b.len(), None),
        },
        UnicodeForm::Utf16 => match be16(0) {
            Some(hi @ 0xD800..=0xDBFF) => match be16(2) {
                Some(lo @ 0xDC00..=0xDFFF) => {
                    (4, Some(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)))
                }
                _ => (2, None),
            },
            Some(u) => (2, Some(u)),
            None => (b.len(), None),
        },
        UnicodeForm::Utf32 => match b.get(..4) {
            Some(s) => (4, Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))),
            None => (b.len(), None),
        },
        UnicodeForm::Utf8 => {
            let lead = b[0];
            let (n, init) = match lead {
                0x00..=0x7F => return (1, Some(u32::from(lead))),
                0xC0..=0xDF => (2, u32::from(lead & 0x1F)),
                0xE0..=0xEF => (3, u32::from(lead & 0x0F)),
                0xF0..=0xF7 => (4, u32::from(lead & 0x07)),
                _ => return (1, None),
            };
            let Some(tail) = b.get(1..n) else {
                return (b.len(), None);
            };
            let cp = tail
                .iter()
                .fold(init, |acc, &t| (acc << 6) | u32::from(t & 0x3F));
            (n, Some(cp))
        }
    }
}

/// Resolve a predefined CMap name (§9.7.5.2 Table 118 and the Adobe
/// resources beyond it).
pub(crate) fn predefined(name: &str) -> Option<Predefined> {
    let wmode = u8::from(name.ends_with("-V"));
    if name == "Identity-H" || name == "Identity-V" {
        return Some(Predefined::Identity {
            collection: None,
            wmode,
        });
    }
    if let Some(rest) = name.strip_prefix("Adobe-") {
        // `Adobe-Japan1-7` etc.: identity CMaps over one collection.
        let ordering = rest.rsplit_once('-').map(|(o, _)| o)?;
        let collection = collection_index(ordering)?;
        return Some(Predefined::Identity {
            collection: Some(collection),
            wmode: 0,
        });
    }
    if let Some(rest) = name.strip_prefix("Uni") {
        let ordering = [
            ("JIS", "Japan1"),
            ("GB", "GB1"),
            ("CNS", "CNS1"),
            ("KS", "Korea1"),
            ("AKR", "KR"),
        ]
        .iter()
        .find(|(p, _)| {
            rest.strip_prefix(p).is_some_and(|r| {
                r.starts_with('-')
                    || r.starts_with("2004")
                    || r.starts_with("X0213")
                    || r.starts_with("Pro")
            })
        })
        .map(|(_, o)| *o)?;
        let form = if name.contains("UCS2") {
            UnicodeForm::Ucs2
        } else if name.contains("UTF16") {
            UnicodeForm::Utf16
        } else if name.contains("UTF32") {
            UnicodeForm::Utf32
        } else if name.contains("UTF8") {
            UnicodeForm::Utf8
        } else {
            return None;
        };
        return Some(Predefined::Unicode {
            form,
            collection: collection_index(ordering),
            wmode,
        });
    }
    let d = data()?;
    let index = d.cmaps.iter().position(|c| c.name == name)?;
    Some(Predefined::Legacy { index })
}

/// Index of the collection whose `/Ordering` is `ordering`.
pub(crate) fn collection_index(ordering: &str) -> Option<usize> {
    data()?
        .collections
        .iter()
        .position(|c| c.ordering == ordering)
}

/// §9.10.2 step (e): the Unicode text of `cid` in `collection`.
pub(crate) fn cid_to_unicode(collection: usize, cid: u32) -> Option<char> {
    let c = data()?.collections.get(collection)?;
    run_lookup(&c.cid_runs, cid).and_then(char::from_u32)
}

/// The CID a `Uni…` CMap of `collection` maps Unicode value `u` to.
pub(crate) fn unicode_to_cid(collection: usize, u: u32) -> Option<u32> {
    let c = data()?.collections.get(collection)?;
    run_lookup(&c.uni_runs, u)
}

/// `(start, target, len)` runs sorted by `start`; binary search.
fn run_lookup(runs: &[(u32, u32, u32)], key: u32) -> Option<u32> {
    let i = runs.partition_point(|r| r.0 <= key).checked_sub(1)?;
    let (s, t, l) = runs[i];
    (key - s < l).then(|| t + (key - s))
}

struct Collection {
    ordering: String,
    cid_runs: Vec<(u32, u32, u32)>,
    uni_runs: Vec<(u32, u32, u32)>,
}

struct LegacyCMap {
    name: String,
    collection: usize,
    wmode: u8,
    parent: Option<usize>,
    /// Codespace-only CMap driving the §9.7.6.2 code segmentation.
    segmenter: CidCMap,
    /// Code → CID runs per code width 1..=4.
    runs: [Vec<(u32, u32, u32)>; 4],
}

struct Data {
    collections: Vec<Collection>,
    cmaps: Vec<LegacyCMap>,
}

impl Data {
    /// CID of `(width, code)` in CMap `index`, then its `usecmap`
    /// parent chain.
    fn legacy_cid(&self, mut index: usize, width: u8, code: u32) -> Option<u32> {
        for _ in 0..8 {
            let cm = self.cmaps.get(index)?;
            let runs = cm.runs.get(usize::from(width).checked_sub(1)?)?;
            if let Some(cid) = run_lookup(runs, code) {
                return Some(cid);
            }
            index = cm.parent?;
        }
        None
    }
}

#[cfg(feature = "cjk-cmaps")]
fn data() -> Option<&'static Data> {
    static DATA: std::sync::OnceLock<Option<Data>> = std::sync::OnceLock::new();
    DATA.get_or_init(|| {
        let raw = crate::zlib::flate_decompress(include_bytes!("data/cjk_cmaps.bin")).ok()?;
        parse_data(&raw)
    })
    .as_ref()
}

#[cfg(not(feature = "cjk-cmaps"))]
fn data() -> Option<&'static Data> {
    None
}

struct Cursor<'a> {
    d: &'a [u8],
    p: usize,
}

impl Cursor<'_> {
    fn uv(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for shift in (0..35).step_by(7) {
            let b = *self.d.get(self.p)?;
            self.p += 1;
            v |= u32::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn sv(&mut self) -> Option<i64> {
        let v = i64::from(self.uv()?);
        Some(if v & 1 == 0 { v >> 1 } else { -((v + 1) >> 1) })
    }

    fn bytes(&mut self, n: usize) -> Option<&[u8]> {
        let s = self.d.get(self.p..self.p + n)?;
        self.p += n;
        Some(s)
    }

    fn string(&mut self) -> Option<String> {
        let n = self.uv()? as usize;
        Some(String::from_utf8_lossy(self.bytes(n)?).into_owned())
    }

    fn runs(&mut self) -> Option<Vec<(u32, u32, u32)>> {
        let n = self.uv()? as usize;
        let mut out = Vec::with_capacity(n.min(1 << 20));
        let (mut pa, mut pb) = (0i64, 0i64);
        for _ in 0..n {
            let a = pa + i64::from(self.uv()?);
            let b = pb + self.sv()?;
            let l = i64::from(self.uv()?) + 1;
            out.push((u32::try_from(a).ok()?, u32::try_from(b).ok()?, l as u32));
            pa = a + l;
            pb = b + l;
        }
        Some(out)
    }
}

#[cfg_attr(not(feature = "cjk-cmaps"), allow(dead_code))]
fn parse_data(raw: &[u8]) -> Option<Data> {
    let mut c = Cursor { d: raw, p: 0 };
    if c.bytes(6)? != b"OXCJK\x02" {
        return None;
    }
    let n_coll = c.uv()? as usize;
    let mut collections = Vec::with_capacity(n_coll);
    for _ in 0..n_coll {
        let ordering = c.string()?;
        let _n_cids = c.uv()?;
        let cid_runs = c.runs()?;
        let uni_runs = c.runs()?;
        collections.push(Collection {
            ordering,
            cid_runs,
            uni_runs,
        });
    }
    let n_cmaps = c.uv()? as usize;
    let mut cmaps: Vec<LegacyCMap> = Vec::with_capacity(n_cmaps);
    for _ in 0..n_cmaps {
        let name = c.string()?;
        let collection = c.uv()? as usize;
        let wmode = c.uv()? as u8;
        let parent = c.uv()?.checked_sub(1).map(|p| p as usize);
        let n_cs = c.uv()? as usize;
        let mut codespaces = Vec::with_capacity(n_cs);
        for _ in 0..n_cs {
            let w = c.uv()? as usize;
            let lo = c.bytes(w)?.to_vec();
            let hi = c.bytes(w)?.to_vec();
            codespaces.push(CodespaceRange { lo, hi });
        }
        // A `-V` CMap stores only the codespaces its parent lacks.
        if let Some(p) = parent {
            codespaces.extend(cmaps.get(p)?.segmenter.codespaces().iter().cloned());
        }
        let runs = [c.runs()?, c.runs()?, c.runs()?, c.runs()?];
        cmaps.push(LegacyCMap {
            name,
            collection,
            wmode,
            parent,
            segmenter: CidCMap::from_codespaces(codespaces),
            runs,
        });
    }
    Some(Data { collections, cmaps })
}

#[cfg(all(test, feature = "cjk-cmaps"))]
mod tests {
    use super::*;

    #[test]
    fn table_loads_every_collection() {
        let d = data().expect("table");
        let names: Vec<&str> = d.collections.iter().map(|c| c.ordering.as_str()).collect();
        assert_eq!(names, ["Japan1", "GB1", "CNS1", "Korea1", "KR"]);
        assert!(d.cmaps.len() > 90);
    }

    #[test]
    fn shift_jis_cmap_maps_to_japan1_cids_and_unicode() {
        // 90ms-RKSJ-H: <8140> <817e> 633 (IDEOGRAPHIC SPACE, per the
        // JIS X 0208 database);
        // single-byte <20>..<7d> → CID 231.. (proportional Roman).
        let p = predefined("90ms-RKSJ-H").expect("known CMap");
        assert_eq!(p.wmode(), 0);
        let japan1 = collection_index("Japan1").unwrap();
        assert_eq!(p.collection(), Some(japan1));
        let (n, cid, text) = p.next(&[0x81, 0x40, 0x41]);
        assert_eq!((n, cid, text), (2, 633, None));
        assert_eq!(cid_to_unicode(japan1, 633), Some('\u{3000}'));
        let (n, cid, _) = p.next(&[0x41]);
        assert_eq!((n, cid), (1, 231 + 0x21));
        assert_eq!(cid_to_unicode(japan1, cid), Some('A'));
        // Hiragana あ is 0x82A0 in Shift-JIS.
        let (_, cid, _) = p.next(&[0x82, 0xA0]);
        assert_eq!(cid_to_unicode(japan1, cid), Some('あ'));
    }

    #[test]
    fn vertical_cmap_inherits_from_horizontal() {
        let v = predefined("90ms-RKSJ-V").expect("known CMap");
        assert_eq!(v.wmode(), 1);
        let (_, cid, _) = v.next(&[0x82, 0xA0]);
        let japan1 = collection_index("Japan1").unwrap();
        assert_eq!(cid_to_unicode(japan1, cid), Some('あ'));
    }

    #[test]
    fn unicode_cmaps_decode_codes_directly() {
        let p = predefined("UniJIS-UCS2-H").expect("Uni CMap");
        let (n, cid, text) = p.next(&[0x30, 0x42]);
        assert_eq!((n, text.as_deref()), (2, Some("あ")));
        let japan1 = collection_index("Japan1").unwrap();
        assert_eq!(cid_to_unicode(japan1, cid), Some('あ'));
        let p = predefined("UniGB-UTF16-H").unwrap();
        let (n, _, text) = p.next(&[0xD8, 0x40, 0xDC, 0x00]);
        assert_eq!((n, text.as_deref()), (4, Some("\u{20000}")));
        let p = predefined("UniKS-UTF8-H").unwrap();
        let (n, _, text) = p.next("가".as_bytes());
        assert_eq!((n, text.as_deref()), (3, Some("가")));
    }

    #[test]
    fn gbk_big5_and_korean_cmaps() {
        // 中 = GBK D6D0, Big Five A4A4, KS X 1001 (EUC) F1E9.
        for (name, ordering, code) in [
            ("GBK-EUC-H", "GB1", [0xD6u8, 0xD0]),
            ("B5pc-H", "CNS1", [0xA4, 0xA4]),
            ("KSC-EUC-H", "Korea1", [0xF1, 0xE9]),
        ] {
            let p = predefined(name).expect(name);
            let (_, cid, _) = p.next(&code);
            let coll = collection_index(ordering).unwrap();
            assert_eq!(cid_to_unicode(coll, cid), Some('中'), "{name}");
        }
    }
}
