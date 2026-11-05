//! Unicode recovery from embedded font programs and the Adobe
//! character collections, for fonts that carry no `/ToUnicode` CMap
//! (ISO 32000-1 §9.10.2's second and third methods, and the "mapping
//! of its choosing" its last paragraph allows).
//!
//! * **Type 1 / CFF built-in encodings** (§9.6.6.2): a `/FontFile3`
//!   `/Type1C` program (or an OpenType one whose `CFF ` table is
//!   name-keyed) maps codes to glyph names through its own encoding
//!   (TN #5176 §12); names resolve through the Adobe Glyph List.
//! * **TrueType** (§9.6.6.4): a symbolic font selects glyphs through
//!   its `(3,0)` subtable (codes `0x00..`, `0xF000..`, `0xF100..`,
//!   `0xF200..`) or `(1,0)` subtable; a glyph's text then comes from
//!   the font's Unicode `cmap` subtables run backwards, or its `post`
//!   name through the AGL.
//! * **CIDFonts** (§9.7.4): `CIDToGIDMap` (Type 2) or the CFF charset
//!   (Type 0) reach the glyph; collections named by
//!   `/CIDSystemInfo` (Adobe-Japan1 / GB1 / CNS1 / Korea1 / KR) map
//!   CIDs to Unicode through [`crate::reader::cjk`].
//!
//! Glyph names no source maps (`/G12`, `/g250` — glyph-index names
//! some converters write) are looked up in the program to find the
//! glyph, then its text as above.

use std::collections::HashMap;
use std::rc::Rc;

use crate::objects::{Dict, Object};
use crate::reader::cff::CffFont;
use crate::reader::cid_cmap::CidCMap;
use crate::reader::cjk::{self, Predefined};
use crate::reader::document::{DocumentReader, decode_stream};
use crate::reader::encoding::{EncodingMap, glyph_name_to_unicode};
use crate::reader::sfnt::{CmapSubtable, Sfnt};

pub(crate) fn dict_get<'a>(d: &'a Dict, key: &str) -> Option<&'a Object> {
    d.entries().iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn dict_name<'a>(d: &'a Dict, key: &str) -> Option<&'a str> {
    match dict_get(d, key)? {
        Object::Name(n) => Some(n.as_str()),
        _ => None,
    }
}

/// Resolve `key` of `d` to a dictionary.
pub(crate) fn resolve_dict(reader: &mut DocumentReader<'_>, d: &Dict, key: &str) -> Option<Dict> {
    match reader.deref(dict_get(d, key)?.clone()).ok()? {
        Object::Dict(d) => Some(d),
        _ => None,
    }
}

/// The outline technology of an embedded program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// `/FontFile` — Type 1 (its encoding is read by the caller from
    /// the cleartext portion).
    Type1,
    /// Bare CFF (`/FontFile3 /Type1C` / `/CIDFontType0C`) or an
    /// OpenType wrapper around a `CFF ` table.
    Cff,
    /// TrueType outlines (`/FontFile2`, or OpenType with `glyf`).
    TrueType,
}

/// An embedded font program, reduced to what text extraction needs.
#[derive(Clone, Debug)]
pub(crate) struct EmbeddedFont {
    kind: Kind,
    cff: Option<CffFont>,
    cmaps: Vec<CmapSubtable>,
    post_names: Vec<Option<String>>,
    /// TrueType GIDs without an outline.
    blank: Vec<bool>,
    /// GID → Unicode scalar, from the Unicode `cmap` subtables run
    /// backwards; the lowest code point wins for a glyph several codes
    /// select. (The `(1,0)` / `(3,0)` subtables of an embedded subset
    /// are keyed by the PDF's own codes, not characters, so they are
    /// no Unicode source.)
    gid_unicode: HashMap<u16, u32>,
}

impl EmbeddedFont {
    /// Load the program behind `font_descriptor`'s `/FontFile`,
    /// `/FontFile2` or `/FontFile3` (§9.9 Table 126).
    pub(crate) fn load(reader: &mut DocumentReader<'_>, descriptor: &Dict) -> Option<EmbeddedFont> {
        for (key, kind) in [
            ("FontFile2", Kind::TrueType),
            ("FontFile3", Kind::Cff),
            ("FontFile", Kind::Type1),
        ] {
            let Some(obj) = dict_get(descriptor, key) else {
                continue;
            };
            let Ok(Object::Stream(stream)) = reader.deref(obj.clone()) else {
                continue;
            };
            let Ok(bytes) = decode_stream(&stream) else {
                continue;
            };
            return Self::from_program(kind, &bytes);
        }
        None
    }

    fn from_program(kind: Kind, bytes: &[u8]) -> Option<EmbeddedFont> {
        let mut font = EmbeddedFont {
            kind,
            cff: None,
            cmaps: Vec::new(),
            post_names: Vec::new(),
            blank: Vec::new(),
            gid_unicode: HashMap::new(),
        };
        match kind {
            Kind::Type1 => {}
            Kind::Cff | Kind::TrueType => {
                if let Some(sfnt) = Sfnt::parse(bytes) {
                    font.cmaps = sfnt.cmap_subtables();
                    font.post_names = sfnt.post_glyph_names();
                    font.blank = sfnt.blank_glyphs();
                    if let Some(cff) = sfnt.table(b"CFF ") {
                        font.cff = CffFont::parse(cff);
                        font.kind = Kind::Cff;
                    } else {
                        font.kind = Kind::TrueType;
                    }
                } else if kind == Kind::Cff {
                    font.cff = Some(CffFont::parse(bytes)?);
                } else {
                    return None;
                }
            }
        }
        font.build_gid_unicode();
        Some(font)
    }

    fn build_gid_unicode(&mut self) {
        let put = |map: &mut HashMap<u16, u32>, gid: u16, u: u32| {
            let slot = map.entry(gid).or_insert(u);
            if u < *slot {
                *slot = u;
            }
        };
        let mut map = HashMap::new();
        for sub in &self.cmaps {
            let unicode = matches!((sub.platform, sub.encoding), (0, _) | (3, 1) | (3, 10));
            if !unicode {
                continue;
            }
            for (&code, &gid) in &sub.map {
                put(&mut map, gid, code);
            }
        }
        // Drop control characters a cmap may route to a glyph.
        map.retain(|_, u| *u >= 0x20 && !(0x7F..0xA0).contains(u));
        self.gid_unicode = map;
    }

    /// True for a TrueType-outline program.
    pub(crate) fn is_truetype(&self) -> bool {
        self.kind == Kind::TrueType
    }

    /// True when the program can give any glyph a Unicode value.
    pub(crate) fn has_text_source(&self) -> bool {
        !self.gid_unicode.is_empty()
            || self.post_names.iter().any(Option::is_some)
            || self.cff.as_ref().is_some_and(|c| !c.is_cid())
    }

    /// The CFF program, when there is one.
    pub(crate) fn cff(&self) -> Option<&CffFont> {
        self.cff.as_ref()
    }

    fn glyph_name(&self, gid: u16) -> Option<String> {
        if let Some(cff) = &self.cff
            && let Some(n) = cff.glyph_name(gid)
        {
            return Some(n);
        }
        self.post_names.get(gid as usize).cloned().flatten()
    }

    /// True when glyph `gid` paints nothing (no TrueType outline, or
    /// a Type 2 charstring with no path).
    fn is_blank(&self, gid: u16) -> bool {
        self.blank.get(gid as usize).copied().unwrap_or(false)
            || self.cff.as_ref().is_some_and(|c| c.is_blank(gid))
    }

    /// The text of glyph `gid`: a Unicode `cmap` that selects it, else
    /// its glyph name through the AGL, else — for a glyph that paints
    /// nothing — a space (the §9.10.2 "mapping of its choosing" for an
    /// otherwise unmappable code; it keeps word boundaries that
    /// converters draw with nameless space glyphs).
    pub(crate) fn gid_text(&self, gid: u16) -> Option<String> {
        if gid == 0 {
            return None;
        }
        if let Some(c) = self.gid_unicode.get(&gid).copied().and_then(char::from_u32) {
            return Some(c.to_string());
        }
        if let Some(text) = self
            .glyph_name(gid)
            .and_then(|n| glyph_name_to_unicode(&n).map(|s| s.into_owned()))
            .filter(|s| !s.is_empty())
        {
            return Some(text);
        }
        self.is_blank(gid).then(|| " ".to_owned())
    }

    fn gid_of_name(&self, name: &str) -> Option<u16> {
        if let Some(cff) = &self.cff
            && let Some(g) = cff.gid_of_name(name)
        {
            return Some(g);
        }
        self.post_names
            .iter()
            .position(|n| n.as_deref() == Some(name))
            .map(|g| g as u16)
    }

    /// Text for a glyph name the AGL does not know, found through the
    /// program: the named glyph's text per [`Self::gid_text`].
    pub(crate) fn name_text(&self, name: &str) -> Option<String> {
        self.gid_text(self.gid_of_name(name)?)
    }

    /// The built-in encoding of a CFF program (TN #5176 §12), as
    /// code → text: each code's glyph name through the AGL, or the
    /// glyph's `cmap` Unicode for names the AGL lacks.
    pub(crate) fn cff_builtin_encoding(&self) -> Option<EncodingMap> {
        let cff = self.cff.as_ref()?;
        if cff.is_cid() {
            return None;
        }
        let mut map = EncodingMap::new();
        let mut any = false;
        for code in 0..=255u8 {
            let Some(name) = cff.code_glyph_name(code) else {
                continue;
            };
            let text = glyph_name_to_unicode(&name)
                .map(|s| s.into_owned())
                .filter(|s| !s.is_empty())
                .or_else(|| self.name_text(&name));
            if let Some(t) = text {
                map.set_string(code, &t);
                any = true;
            }
        }
        any.then_some(map)
    }

    /// §9.6.6.4 symbolic TrueType: the glyph `code` selects through
    /// the `(3,0)` subtable (in whichever of the four code ranges it
    /// populates) or the `(1,0)` subtable.
    fn symbolic_gid(&self, code: u8) -> Option<u16> {
        if let Some(sub) = self
            .cmaps
            .iter()
            .find(|s| (s.platform, s.encoding) == (3, 0))
        {
            for high in [0x0000u32, 0xF000, 0xF100, 0xF200] {
                if let Some(&g) = sub.map.get(&(high | u32::from(code))) {
                    return Some(g);
                }
            }
            return None;
        }
        let sub = self
            .cmaps
            .iter()
            .find(|s| (s.platform, s.encoding) == (1, 0))?;
        sub.map.get(&u32::from(code)).copied()
    }

    /// The text a symbolic TrueType font shows for `code`.
    pub(crate) fn symbolic_code_text(&self, code: u8) -> Option<String> {
        self.gid_text(self.symbolic_gid(code)?)
    }
}

/// The CID → glyph step of a CIDFont (§9.7.4.2 `CIDToGIDMap`, or the
/// CFF charset of a CID-keyed Type 0 program).
#[derive(Clone, Debug)]
enum CidToGid {
    Identity,
    /// `CIDToGIDMap` stream: big-endian GID per CID.
    Map(Vec<u16>),
    /// CID-keyed CFF: CID → GID by inverting the charset.
    Charset(HashMap<u16, u16>),
}

impl CidToGid {
    fn gid(&self, cid: u32) -> Option<u16> {
        match self {
            CidToGid::Identity => u16::try_from(cid).ok(),
            CidToGid::Map(m) => m.get(cid as usize).copied(),
            CidToGid::Charset(m) => m.get(&u16::try_from(cid).ok()?).copied(),
        }
    }
}

/// CID → Unicode for one descendant CIDFont.
#[derive(Clone, Debug)]
pub(crate) struct CidText {
    /// Adobe collection index (from `/CIDSystemInfo`, the CFF `ROS`
    /// or a predefined CMap).
    collection: Option<usize>,
    font: Option<Rc<EmbeddedFont>>,
    cid_to_gid: CidToGid,
    /// The program's glyphs are the authority (TrueType CIDFonts,
    /// name-keyed CFF): a CIDSystemInfo collection is only a fallback
    /// — Identity-encoded TrueType subsets routinely declare a
    /// collection their GIDs do not follow.
    prefer_font: bool,
}

impl CidText {
    /// Build from the Type 0 font's descendant CIDFont; `encoding_collection`
    /// is the collection a predefined `/Encoding` CMap names.
    pub(crate) fn from_type0(
        reader: &mut DocumentReader<'_>,
        type0: &Dict,
        encoding_collection: Option<usize>,
    ) -> CidText {
        let cid_font = descendant(reader, type0);
        let mut collection = encoding_collection;
        let mut font = None;
        let mut cid_to_gid = CidToGid::Identity;
        let mut prefer_font = false;
        if let Some(cf) = &cid_font {
            if collection.is_none()
                && let Some(info) = resolve_dict(reader, cf, "CIDSystemInfo")
            {
                let registry = string_of(dict_get(&info, "Registry"));
                let ordering = string_of(dict_get(&info, "Ordering"));
                if registry.as_deref() == Some("Adobe") {
                    collection = ordering.as_deref().and_then(cjk::collection_index);
                }
            }
            let subtype = dict_name(cf, "Subtype").unwrap_or("");
            if let Some(desc) = resolve_dict(reader, cf, "FontDescriptor") {
                font = EmbeddedFont::load(reader, &desc);
            }
            if subtype == "CIDFontType2" {
                prefer_font = true;
                if let Some(obj) = dict_get(cf, "CIDToGIDMap")
                    && let Ok(Object::Stream(s)) = reader.deref(obj.clone())
                    && let Ok(bytes) = decode_stream(&s)
                {
                    let (pairs, _) = bytes.as_chunks::<2>();
                    cid_to_gid =
                        CidToGid::Map(pairs.iter().map(|&p| u16::from_be_bytes(p)).collect());
                }
            } else if let Some(cff) = font.as_ref().and_then(EmbeddedFont::cff) {
                if cff.is_cid() {
                    let mut inv = HashMap::new();
                    for gid in 0..cff.glyph_count() {
                        if let Some(cid) = cff.gid_to_cid(gid as u16) {
                            inv.entry(cid).or_insert(gid as u16);
                        }
                    }
                    cid_to_gid = CidToGid::Charset(inv);
                    if collection.is_none()
                        && let Some(("Adobe", ordering, _)) = cff.ros()
                    {
                        collection = cjk::collection_index(ordering);
                    }
                } else {
                    prefer_font = true;
                }
            } else if font.is_some() {
                prefer_font = true;
            }
        }
        let font = font.filter(EmbeddedFont::has_text_source).map(Rc::new);
        CidText {
            collection,
            font,
            cid_to_gid,
            prefer_font,
        }
    }

    /// True when some source can map CIDs to text.
    pub(crate) fn is_available(&self) -> bool {
        self.collection.is_some() || self.font.is_some()
    }

    /// The text of `cid`.
    pub(crate) fn text(&self, cid: u32) -> Option<String> {
        let from_font = || {
            let font = self.font.as_ref()?;
            font.gid_text(self.cid_to_gid.gid(cid)?)
        };
        let from_collection = || {
            cjk::cid_to_unicode(self.collection?, cid)
                .filter(|c| *c != '\u{0}')
                .map(String::from)
        };
        if self.prefer_font {
            from_font().or_else(from_collection)
        } else {
            from_collection().or_else(from_font)
        }
    }
}

fn string_of(o: Option<&Object>) -> Option<String> {
    match o? {
        Object::LiteralString(b) | Object::HexString(b) => {
            Some(b.iter().map(|&c| c as char).collect())
        }
        Object::Name(n) => Some(n.clone()),
        _ => None,
    }
}

/// The sole descendant CIDFont dictionary of a Type 0 font.
pub(crate) fn descendant(reader: &mut DocumentReader<'_>, type0: &Dict) -> Option<Dict> {
    let arr = reader
        .deref(dict_get(type0, "DescendantFonts")?.clone())
        .ok()?;
    let first = match arr {
        Object::Array(items) => items.into_iter().next()?,
        other => other,
    };
    match reader.deref(first).ok()? {
        Object::Dict(d) => Some(d),
        _ => None,
    }
}

/// How a Type 0 font's codes become CIDs (§9.7.5–§9.7.6).
#[derive(Clone, Debug)]
pub(crate) enum CompositeEncoding {
    /// Embedded CMap stream (§9.7.5.3).
    Embedded(Box<CidCMap>),
    /// A predefined CMap name (§9.7.5.2), Identity included.
    Predefined(Predefined),
}

impl CompositeEncoding {
    /// Resolve a Type 0 font's `/Encoding`; anything unreadable is
    /// Identity-H.
    pub(crate) fn from_type0(reader: &mut DocumentReader<'_>, type0: &Dict) -> CompositeEncoding {
        let identity = || {
            CompositeEncoding::Predefined(Predefined::Identity {
                collection: None,
                wmode: 0,
            })
        };
        match dict_get(type0, "Encoding").cloned() {
            Some(Object::Name(name)) => cjk::predefined(&name)
                .map(CompositeEncoding::Predefined)
                .unwrap_or_else(|| {
                    CompositeEncoding::Predefined(Predefined::Identity {
                        collection: None,
                        wmode: u8::from(name.ends_with("-V")),
                    })
                }),
            Some(obj) => {
                if let Ok(Object::Stream(stream)) = reader.deref(obj)
                    && let Ok(cm) = CidCMap::from_stream(reader, &stream, 0)
                {
                    return CompositeEncoding::Embedded(Box::new(cm));
                }
                identity()
            }
            None => identity(),
        }
    }

    /// Writing mode (§9.7.5 `WMode`).
    pub(crate) fn wmode(&self) -> u8 {
        match self {
            CompositeEncoding::Embedded(cm) => cm.wmode,
            CompositeEncoding::Predefined(p) => p.wmode(),
        }
    }

    /// The collection a predefined CMap's CIDs index.
    pub(crate) fn collection(&self) -> Option<usize> {
        match self {
            CompositeEncoding::Embedded(_) => None,
            CompositeEncoding::Predefined(p) => p.collection(),
        }
    }

    /// True for the plain 2-byte Identity mapping.
    pub(crate) fn is_identity(&self) -> bool {
        matches!(
            self,
            CompositeEncoding::Predefined(Predefined::Identity { .. })
        )
    }

    /// Split the next code off non-empty `bytes`: `(consumed, CID,
    /// Unicode text when the code itself is Unicode)`.
    pub(crate) fn next(&self, bytes: &[u8]) -> (usize, u32, Option<String>) {
        match self {
            CompositeEncoding::Embedded(cm) => {
                let (n, code) = cm.next_code(bytes);
                (n.max(1), cm.cid_for_code(code), None)
            }
            CompositeEncoding::Predefined(p) => {
                let (n, cid, text) = p.next(bytes);
                (n.max(1), cid, text)
            }
        }
    }
}
