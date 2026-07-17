//! PDF simple-font encoding resolver — `/Encoding` dictionary +
//! `/Differences` array → 256-entry byte → Unicode map.
//!
//! ISO 32000-1:2008 §9.6.6.1 "Type 1 Encodings" defines a simple
//! font's `/Encoding` as either a single name
//! (`WinAnsiEncoding` / `MacRomanEncoding` / `MacExpertEncoding` /
//! `StandardEncoding`) or a dictionary with a `/BaseEncoding` name
//! and an optional `/Differences` array. The array is a flat sequence
//! of *(code, glyph-name, glyph-name, …, code, glyph-name, …)*: every
//! numeric starts a new run of code points, and every following name
//! token is the glyph at the next consecutive code. Each glyph name is
//! mapped to a Unicode scalar value via the Adobe Glyph List
//! (`docs/document/pdf/agl/subset.txt`).
//!
//! Round 28 wires this resolver into the text-extraction path so a
//! simple font whose `/Encoding` carries `/Differences` decodes to the
//! correct Unicode payload (matching what `pdftotext` produces).
//!
//! ## Provenance
//!
//! ISO 32000-1:2008 §9.6.6.1 (Type 1 Encodings) + §D.2 (Latin character
//! set) for the encoding tables; Adobe Glyph List v2.0 (public document,
//! 5 Sep 2002) for the glyph-name → Unicode mapping. No third-party PDF
//! library SOURCE was consulted.

use crate::error::PdfError;
use crate::objects::Object;
use std::borrow::Cow;

/// One `/Differences` array override: at code point `code`, the
/// rendering glyph is `glyph_name`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodingOverride {
    pub code: u8,
    pub glyph_name: String,
}

/// Parsed `/Differences` array — flat list of `(code, name)` overrides.
///
/// Internally just a `Vec`; the resolver applies them in order on top of
/// a base 256-entry table. Iterates in document order so a later entry
/// for the same code wins (matching what Acrobat / Distiller does when
/// a malformed PDF lists the same code twice).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EncodingDifferences {
    pub overrides: Vec<EncodingOverride>,
}

impl EncodingDifferences {
    pub fn is_empty(&self) -> bool {
        self.overrides.is_empty()
    }

    pub fn len(&self) -> usize {
        self.overrides.len()
    }
}

/// The named base encodings ISO 32000-1 §9.6.6.1 + §D.2 define for
/// simple Type 1 / TrueType fonts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseEncoding {
    WinAnsi,
    MacRoman,
    MacExpert,
    /// ISO 32000-1 §D.2 "Standard" — the Adobe Type 1 standard encoding
    /// (also the implicit default when a Type 1 font omits `/Encoding`).
    Standard,
    /// Symbol encoding — non-Latin glyph repertoire (Greek + math). Used
    /// by the built-in Symbol font.
    Symbol,
    /// ZapfDingbats encoding — the built-in dingbat font's repertoire.
    ZapfDingbats,
}

impl BaseEncoding {
    pub fn from_name(name: &str) -> Option<BaseEncoding> {
        Some(match name {
            "WinAnsiEncoding" => BaseEncoding::WinAnsi,
            "MacRomanEncoding" => BaseEncoding::MacRoman,
            "MacExpertEncoding" => BaseEncoding::MacExpert,
            "StandardEncoding" => BaseEncoding::Standard,
            "SymbolEncoding" => BaseEncoding::Symbol,
            "ZapfDingbatsEncoding" => BaseEncoding::ZapfDingbats,
            _ => return None,
        })
    }
}

/// 256-entry byte → Unicode (UTF-8 string) map. Most entries hold a
/// single `char` but the AGL also defines ligature glyphs whose
/// expansion is multi-character (`/fi` → "fi"), so the slot has to
/// accommodate a short `String`. Slots for unassigned bytes hold the
/// empty string — the decoder emits U+FFFD when it sees one.
#[derive(Clone, Debug)]
pub struct EncodingMap {
    table: [String; 256],
}

impl Default for EncodingMap {
    fn default() -> Self {
        Self::new()
    }
}

impl EncodingMap {
    pub fn new() -> Self {
        Self {
            table: std::array::from_fn(|_| String::new()),
        }
    }

    pub fn set_char(&mut self, code: u8, c: char) {
        self.table[code as usize] = String::from(c);
    }

    pub fn set_string(&mut self, code: u8, s: &str) {
        self.table[code as usize] = s.to_owned();
    }

    /// Look up one byte. Returns the empty slice when unassigned (caller
    /// substitutes U+FFFD).
    pub fn lookup(&self, code: u8) -> &str {
        &self.table[code as usize]
    }

    /// Decode a `Tj` / `TJ` byte string into Unicode by walking the
    /// table. Unassigned codes become U+FFFD.
    pub fn decode(&self, bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len());
        for &b in bytes {
            let slot = self.lookup(b);
            if slot.is_empty() {
                out.push('\u{FFFD}');
            } else {
                out.push_str(slot);
            }
        }
        out
    }

    /// Build a map from a named [`BaseEncoding`].
    pub fn from_base(base: BaseEncoding) -> EncodingMap {
        let mut m = EncodingMap::new();
        match base {
            BaseEncoding::WinAnsi => fill_winansi(&mut m),
            BaseEncoding::MacRoman => fill_macroman(&mut m),
            BaseEncoding::MacExpert => fill_macexpert(&mut m),
            BaseEncoding::Standard => fill_standard(&mut m),
            BaseEncoding::Symbol => fill_symbol(&mut m),
            BaseEncoding::ZapfDingbats => fill_zapfdingbats(&mut m),
        }
        m
    }
}

// ────────────────────────── /Differences parser ──────────────────────────

/// Parse a `/Differences` array — flat `[N name1 name2 … M nameK …]`.
///
/// Numeric tokens reset the running code; each successive name maps to
/// the next consecutive code (running code is post-incremented). Tokens
/// that are neither a number nor a `Name` are skipped silently — older
/// `acroread` writers occasionally embed `null` or a comment-like
/// reference in there and the spec mandates we tolerate that.
///
/// Returns `Ok(EncodingDifferences::default())` for an empty array;
/// returns `Err` only when the supplied `Object` isn't an `Array` (the
/// caller must have already pulled the array out of the encoding
/// dictionary's `/Differences` slot).
pub fn parse_encoding_differences(arr: &Object) -> Result<EncodingDifferences, PdfError> {
    let items = match arr {
        Object::Array(v) => v,
        _ => {
            return Err(PdfError::other(format!(
                "PDF encoding: /Differences must be an array (got {arr:?})"
            )));
        }
    };
    let mut out = EncodingDifferences::default();
    let mut running: Option<u32> = None;
    for item in items {
        match item {
            Object::Integer(n) if (0..=255).contains(n) => {
                running = Some(*n as u32);
            }
            Object::Real(r) => {
                let v = *r as i64;
                if (0..=255).contains(&v) {
                    running = Some(v as u32);
                }
            }
            Object::Name(name) => {
                if let Some(code) = running {
                    if code <= 255 {
                        out.overrides.push(EncodingOverride {
                            code: code as u8,
                            glyph_name: name.clone(),
                        });
                    }
                    running = Some(code + 1);
                }
            }
            _ => {
                // Unknown token — skip. Per the spec we just keep
                // walking, so a malformed entry doesn't poison the
                // rest of the array.
            }
        }
    }
    Ok(out)
}

/// Overlay `differences` on top of `base`, returning a fresh map. The
/// base map is left untouched (cheap clone — `String` allocations are
/// per-entry).
pub fn apply_encoding_differences(
    base: &EncodingMap,
    differences: &EncodingDifferences,
) -> EncodingMap {
    let mut out = base.clone();
    for ov in &differences.overrides {
        if let Some(s) = glyph_name_to_unicode(&ov.glyph_name) {
            out.set_string(ov.code, s.as_ref());
        } else {
            // Unknown glyph — leave the slot empty so the decoder emits
            // U+FFFD. We do NOT propagate the raw glyph name as text —
            // that would be worse than the replacement char (callers
            // running keyword search would match the literal name).
            out.set_string(ov.code, "");
        }
    }
    out
}

// ────────────────────────── glyph-name → Unicode ──────────────────────────

/// Adobe Glyph List lookup. Returns the UTF-8 expansion of a PostScript
/// glyph name (multi-char for ligatures like `/fi`, single-char for the
/// common case). Returns `None` for unknown names — the caller emits
/// U+FFFD as a marker.
///
/// The table here is a transcription of the AGL subset under
/// `docs/document/pdf/agl/subset.txt`. The PDF spec (§D.2 + §9.6.6.1)
/// defines a fixed Latin repertoire that the four named encodings draw
/// from; that's what we ship. Extending the table for non-Latin glyphs
/// (CJK, Cyrillic, Devanagari) is a future-round followup.
///
/// In addition to the static AGL subset, this resolver honours the
/// Adobe Glyph List Public Implementation Notes §3 `uniXXXX...` /
/// `uXXXXXXXX` Unicode-by-name escape forms (round 175). Producers
/// occasionally emit these escapes directly in a `/Differences` array
/// rather than the AGL-aliased name (e.g. `/uni201C` instead of
/// `/quotedblleft`), and the spec mandates we honour them.
// Internal: glyph-name lookup plumbing behind the text extractor (exposed for tests).
#[doc(hidden)]
pub fn glyph_name_to_unicode(name: &str) -> Option<Cow<'static, str>> {
    // Special PDF-spec aliases — `.notdef` is rendered as nothing, the
    // `uniXXXX` / `uXXXXXXXX` forms are Unicode-by-name escapes that the
    // AGL Public Implementation Notes (§3) mandates we honour first.
    if name == ".notdef" || name.is_empty() {
        return Some(Cow::Borrowed(""));
    }
    // Linear scan of the AGL subset first — the AGL alias is preferred
    // when both forms resolve (a producer that emits `/A` and the
    // AGL-aliased `/uni0041` should reach the same result, but the
    // static-table hit avoids an allocation). The table is small enough
    // that a hash map's setup cost outweighs the savings for the typical
    // `/Differences` array (≤ 32 entries).
    for (n, s) in AGL_SUBSET {
        if *n == name {
            return Some(Cow::Borrowed(*s));
        }
    }
    // Fall through to the `uniXXXX` / `uXXXXXXXX` decoder.
    uni_prefix_decode(name).map(Cow::Owned)
}

/// Adobe Glyph List Public Implementation Notes §3 — `uniXXXX...`
/// (one or more consecutive 4-hex-digit BMP code points) and
/// `uXXXXXXXX` (a single 4-to-6-hex-digit code point, including
/// supplementary planes).
///
/// The two forms differ in their hex-digit count discipline:
///
/// 1. **`uni` prefix** — the remainder is split into consecutive
///    4-character groups. Each group is a BMP code point (one of
///    `U+0000..=U+D7FF` or `U+E000..=U+FFFD`). Surrogate halves
///    (`U+D800..=U+DFFF`) are rejected. The decoded characters are
///    concatenated (this is how a producer encodes a multi-character
///    ligature without an AGL alias).
/// 2. **`u` prefix** — the remainder is exactly 4, 5, or 6
///    uppercase hex digits, denoting one Unicode scalar value. The
///    value must be a valid `char` (`<= 0x10FFFF`, not a surrogate)
///    and must not be `0xFFFF` (the "shall not be a noncharacter"
///    rule from the AGL Public Implementation Notes).
///
/// Returns `None` for any name that doesn't match either shape
/// strictly — the caller falls back to its unknown-glyph branch.
fn uni_prefix_decode(name: &str) -> Option<String> {
    if let Some(rest) = name.strip_prefix("uni") {
        // BMP-group form. The trailing characters must split cleanly
        // into 4-digit groups.
        if rest.is_empty() || rest.len() % 4 != 0 {
            return None;
        }
        let mut out = String::with_capacity(rest.len() / 4);
        for chunk in rest.as_bytes().chunks(4) {
            // SAFETY: chunks of 4 ASCII bytes are always valid UTF-8.
            let hex = std::str::from_utf8(chunk).ok()?;
            // AGL PIN §3 mandates uppercase ASCII hex. Reject
            // lowercase / mixed-case to keep the canonical form clean
            // (some producers write lowercase; treat them as unknown).
            if !is_uppercase_hex(hex) {
                return None;
            }
            let cp = u32::from_str_radix(hex, 16).ok()?;
            // Surrogate halves and noncharacter U+FFFF rejected.
            if (0xD800..=0xDFFF).contains(&cp) || cp == 0xFFFF {
                return None;
            }
            let c = char::from_u32(cp)?;
            out.push(c);
        }
        Some(out)
    } else if let Some(rest) = name.strip_prefix('u') {
        // Single-codepoint form, 4..=6 hex digits, supplementary
        // planes allowed.
        if !(4..=6).contains(&rest.len()) {
            return None;
        }
        if !is_uppercase_hex(rest) {
            return None;
        }
        let cp = u32::from_str_radix(rest, 16).ok()?;
        if (0xD800..=0xDFFF).contains(&cp) || cp == 0xFFFF {
            return None;
        }
        let c = char::from_u32(cp)?;
        Some(c.to_string())
    } else {
        None
    }
}

/// Returns true iff every byte in `s` is `0..=9` / `A..=F`. AGL PIN
/// §3 specifies uppercase; we treat lowercase as a non-match so a
/// `/u00ff` doesn't collide with the canonical `/u00FF`.
fn is_uppercase_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

/// The shipping AGL subset. Held as an array literal so the binary
/// embeds it verbatim; a build script that generates this from
/// `subset.txt` would be churn for negligible win.
const AGL_SUBSET: &[(&str, &str)] = &[
    // ── Basic Latin (§D.2 names that match the AGL) ──
    ("space", " "),
    ("exclam", "!"),
    ("quotedbl", "\""),
    ("numbersign", "#"),
    ("dollar", "$"),
    ("percent", "%"),
    ("ampersand", "&"),
    ("quoteright", "\u{2019}"),
    ("quotesingle", "'"),
    ("parenleft", "("),
    ("parenright", ")"),
    ("asterisk", "*"),
    ("plus", "+"),
    ("comma", ","),
    ("hyphen", "-"),
    ("period", "."),
    ("slash", "/"),
    ("zero", "0"),
    ("one", "1"),
    ("two", "2"),
    ("three", "3"),
    ("four", "4"),
    ("five", "5"),
    ("six", "6"),
    ("seven", "7"),
    ("eight", "8"),
    ("nine", "9"),
    ("colon", ":"),
    ("semicolon", ";"),
    ("less", "<"),
    ("equal", "="),
    ("greater", ">"),
    ("question", "?"),
    ("at", "@"),
    ("A", "A"),
    ("B", "B"),
    ("C", "C"),
    ("D", "D"),
    ("E", "E"),
    ("F", "F"),
    ("G", "G"),
    ("H", "H"),
    ("I", "I"),
    ("J", "J"),
    ("K", "K"),
    ("L", "L"),
    ("M", "M"),
    ("N", "N"),
    ("O", "O"),
    ("P", "P"),
    ("Q", "Q"),
    ("R", "R"),
    ("S", "S"),
    ("T", "T"),
    ("U", "U"),
    ("V", "V"),
    ("W", "W"),
    ("X", "X"),
    ("Y", "Y"),
    ("Z", "Z"),
    ("bracketleft", "["),
    ("backslash", "\\"),
    ("bracketright", "]"),
    ("asciicircum", "^"),
    ("underscore", "_"),
    ("quoteleft", "\u{2018}"),
    ("grave", "`"),
    ("a", "a"),
    ("b", "b"),
    ("c", "c"),
    ("d", "d"),
    ("e", "e"),
    ("f", "f"),
    ("g", "g"),
    ("h", "h"),
    ("i", "i"),
    ("j", "j"),
    ("k", "k"),
    ("l", "l"),
    ("m", "m"),
    ("n", "n"),
    ("o", "o"),
    ("p", "p"),
    ("q", "q"),
    ("r", "r"),
    ("s", "s"),
    ("t", "t"),
    ("u", "u"),
    ("v", "v"),
    ("w", "w"),
    ("x", "x"),
    ("y", "y"),
    ("z", "z"),
    ("braceleft", "{"),
    ("bar", "|"),
    ("braceright", "}"),
    ("asciitilde", "~"),
    // ── Latin-1 supplement (§D.2 Standard + WinAnsi shared names) ──
    ("exclamdown", "\u{00A1}"),
    ("cent", "\u{00A2}"),
    ("sterling", "\u{00A3}"),
    ("currency", "\u{00A4}"),
    ("yen", "\u{00A5}"),
    ("brokenbar", "\u{00A6}"),
    ("section", "\u{00A7}"),
    ("dieresis", "\u{00A8}"),
    ("copyright", "\u{00A9}"),
    ("ordfeminine", "\u{00AA}"),
    ("guillemotleft", "\u{00AB}"),
    ("logicalnot", "\u{00AC}"),
    ("hyphensoft", "\u{00AD}"),
    ("registered", "\u{00AE}"),
    ("macron", "\u{00AF}"),
    ("degree", "\u{00B0}"),
    ("plusminus", "\u{00B1}"),
    ("twosuperior", "\u{00B2}"),
    ("threesuperior", "\u{00B3}"),
    ("acute", "\u{00B4}"),
    ("mu", "\u{00B5}"),
    ("paragraph", "\u{00B6}"),
    ("periodcentered", "\u{00B7}"),
    ("cedilla", "\u{00B8}"),
    ("onesuperior", "\u{00B9}"),
    ("ordmasculine", "\u{00BA}"),
    ("guillemotright", "\u{00BB}"),
    ("onequarter", "\u{00BC}"),
    ("onehalf", "\u{00BD}"),
    ("threequarters", "\u{00BE}"),
    ("questiondown", "\u{00BF}"),
    ("Agrave", "\u{00C0}"),
    ("Aacute", "\u{00C1}"),
    ("Acircumflex", "\u{00C2}"),
    ("Atilde", "\u{00C3}"),
    ("Adieresis", "\u{00C4}"),
    ("Aring", "\u{00C5}"),
    ("AE", "\u{00C6}"),
    ("Ccedilla", "\u{00C7}"),
    ("Egrave", "\u{00C8}"),
    ("Eacute", "\u{00C9}"),
    ("Ecircumflex", "\u{00CA}"),
    ("Edieresis", "\u{00CB}"),
    ("Igrave", "\u{00CC}"),
    ("Iacute", "\u{00CD}"),
    ("Icircumflex", "\u{00CE}"),
    ("Idieresis", "\u{00CF}"),
    ("Eth", "\u{00D0}"),
    ("Ntilde", "\u{00D1}"),
    ("Ograve", "\u{00D2}"),
    ("Oacute", "\u{00D3}"),
    ("Ocircumflex", "\u{00D4}"),
    ("Otilde", "\u{00D5}"),
    ("Odieresis", "\u{00D6}"),
    ("multiply", "\u{00D7}"),
    ("Oslash", "\u{00D8}"),
    ("Ugrave", "\u{00D9}"),
    ("Uacute", "\u{00DA}"),
    ("Ucircumflex", "\u{00DB}"),
    ("Udieresis", "\u{00DC}"),
    ("Yacute", "\u{00DD}"),
    ("Thorn", "\u{00DE}"),
    ("germandbls", "\u{00DF}"),
    ("agrave", "\u{00E0}"),
    ("aacute", "\u{00E1}"),
    ("acircumflex", "\u{00E2}"),
    ("atilde", "\u{00E3}"),
    ("adieresis", "\u{00E4}"),
    ("aring", "\u{00E5}"),
    ("ae", "\u{00E6}"),
    ("ccedilla", "\u{00E7}"),
    ("egrave", "\u{00E8}"),
    ("eacute", "\u{00E9}"),
    ("ecircumflex", "\u{00EA}"),
    ("edieresis", "\u{00EB}"),
    ("igrave", "\u{00EC}"),
    ("iacute", "\u{00ED}"),
    ("icircumflex", "\u{00EE}"),
    ("idieresis", "\u{00EF}"),
    ("eth", "\u{00F0}"),
    ("ntilde", "\u{00F1}"),
    ("ograve", "\u{00F2}"),
    ("oacute", "\u{00F3}"),
    ("ocircumflex", "\u{00F4}"),
    ("otilde", "\u{00F5}"),
    ("odieresis", "\u{00F6}"),
    ("divide", "\u{00F7}"),
    ("oslash", "\u{00F8}"),
    ("ugrave", "\u{00F9}"),
    ("uacute", "\u{00FA}"),
    ("ucircumflex", "\u{00FB}"),
    ("udieresis", "\u{00FC}"),
    ("yacute", "\u{00FD}"),
    ("thorn", "\u{00FE}"),
    ("ydieresis", "\u{00FF}"),
    // ── European Latin extensions ──
    ("Lslash", "\u{0141}"),
    ("lslash", "\u{0142}"),
    ("Scaron", "\u{0160}"),
    ("scaron", "\u{0161}"),
    ("OE", "\u{0152}"),
    ("oe", "\u{0153}"),
    ("Ydieresis", "\u{0178}"),
    ("Zcaron", "\u{017D}"),
    ("zcaron", "\u{017E}"),
    ("florin", "\u{0192}"),
    ("circumflex", "\u{02C6}"),
    ("tilde", "\u{02DC}"),
    ("caron", "\u{02C7}"),
    ("breve", "\u{02D8}"),
    ("dotaccent", "\u{02D9}"),
    ("ring", "\u{02DA}"),
    ("ogonek", "\u{02DB}"),
    ("hungarumlaut", "\u{02DD}"),
    // ── Greek (math text) ──
    ("Alpha", "\u{0391}"),
    ("Beta", "\u{0392}"),
    ("Gamma", "\u{0393}"),
    ("Delta", "\u{0394}"),
    ("Epsilon", "\u{0395}"),
    ("Zeta", "\u{0396}"),
    ("Eta", "\u{0397}"),
    ("Theta", "\u{0398}"),
    ("Iota", "\u{0399}"),
    ("Kappa", "\u{039A}"),
    ("Lambda", "\u{039B}"),
    ("Mu", "\u{039C}"),
    ("Nu", "\u{039D}"),
    ("Xi", "\u{039E}"),
    ("Omicron", "\u{039F}"),
    ("Pi", "\u{03A0}"),
    ("Rho", "\u{03A1}"),
    ("Sigma", "\u{03A3}"),
    ("Tau", "\u{03A4}"),
    ("Upsilon", "\u{03A5}"),
    ("Phi", "\u{03A6}"),
    ("Chi", "\u{03A7}"),
    ("Psi", "\u{03A8}"),
    ("Omega", "\u{03A9}"),
    ("alpha", "\u{03B1}"),
    ("beta", "\u{03B2}"),
    ("gamma", "\u{03B3}"),
    ("delta", "\u{03B4}"),
    ("epsilon", "\u{03B5}"),
    ("zeta", "\u{03B6}"),
    ("eta", "\u{03B7}"),
    ("theta", "\u{03B8}"),
    ("iota", "\u{03B9}"),
    ("kappa", "\u{03BA}"),
    ("lambda", "\u{03BB}"),
    ("nu", "\u{03BD}"),
    ("xi", "\u{03BE}"),
    ("omicron", "\u{03BF}"),
    ("pi", "\u{03C0}"),
    ("rho", "\u{03C1}"),
    ("sigma", "\u{03C3}"),
    ("tau", "\u{03C4}"),
    ("upsilon", "\u{03C5}"),
    ("phi", "\u{03C6}"),
    ("chi", "\u{03C7}"),
    ("psi", "\u{03C8}"),
    ("omega", "\u{03C9}"),
    // ── Punctuation / dashes / quotes ──
    ("endash", "\u{2013}"),
    ("emdash", "\u{2014}"),
    ("quotesinglbase", "\u{201A}"),
    ("quotedblbase", "\u{201E}"),
    ("quotedblleft", "\u{201C}"),
    ("quotedblright", "\u{201D}"),
    ("dagger", "\u{2020}"),
    ("daggerdbl", "\u{2021}"),
    ("bullet", "\u{2022}"),
    ("ellipsis", "\u{2026}"),
    ("perthousand", "\u{2030}"),
    ("guilsinglleft", "\u{2039}"),
    ("guilsinglright", "\u{203A}"),
    ("Euro", "\u{20AC}"),
    ("trademark", "\u{2122}"),
    // ── Fractions ──
    ("onethird", "\u{2153}"),
    ("twothirds", "\u{2154}"),
    ("oneeighth", "\u{215B}"),
    ("threeeighths", "\u{215C}"),
    ("fiveeighths", "\u{215D}"),
    ("seveneighths", "\u{215E}"),
    // ── Math + arrows ──
    ("minus", "\u{2212}"),
    ("fraction", "\u{2044}"),
    ("infinity", "\u{221E}"),
    ("notequal", "\u{2260}"),
    ("lessequal", "\u{2264}"),
    ("greaterequal", "\u{2265}"),
    ("arrowleft", "\u{2190}"),
    ("arrowup", "\u{2191}"),
    ("arrowright", "\u{2192}"),
    ("arrowdown", "\u{2193}"),
    ("arrowboth", "\u{2194}"),
    ("arrowdblleft", "\u{21D0}"),
    ("arrowdblup", "\u{21D1}"),
    ("arrowdblright", "\u{21D2}"),
    ("arrowdbldown", "\u{21D3}"),
    ("arrowdblboth", "\u{21D4}"),
    ("partialdiff", "\u{2202}"),
    ("gradient", "\u{2207}"),
    ("product", "\u{220F}"),
    ("summation", "\u{2211}"),
    ("radical", "\u{221A}"),
    ("proportional", "\u{221D}"),
    ("integral", "\u{222B}"),
    ("approxequal", "\u{2248}"),
    ("equivalence", "\u{2261}"),
    ("lozenge", "\u{25CA}"),
    ("notelement", "\u{2209}"),
    ("element", "\u{2208}"),
    ("emptyset", "\u{2205}"),
    ("intersection", "\u{2229}"),
    ("union", "\u{222A}"),
    ("logicalor", "\u{2228}"),
    ("logicaland", "\u{2227}"),
    ("universal", "\u{2200}"),
    ("existential", "\u{2203}"),
    // ── Ligatures ──
    ("fi", "fi"),
    ("fl", "fl"),
    // ── Bullets / shapes ──
    ("filledbox", "\u{25A0}"),
    ("emptybox", "\u{25A1}"),
    ("filledrect", "\u{25AC}"),
    ("triagup", "\u{25B2}"),
    ("triagrt", "\u{25BA}"),
    ("triagdn", "\u{25BC}"),
    ("triaglf", "\u{25C4}"),
    ("circle", "\u{25CB}"),
    ("filledcircle", "\u{25CF}"),
    ("heart", "\u{2665}"),
    ("musicalnote", "\u{266A}"),
    ("musicalnotedbl", "\u{266B}"),
];

// ────────────────────────── base-encoding tables ──────────────────────────

/// WinAnsiEncoding (CP1252) — ISO 32000-1 Annex D.2 Table D.2 "Latin
/// Character Set". The 32 control bytes are unassigned; we leave them
/// empty so the decoder emits U+FFFD when it sees one. Bytes 0x20..0x7E
/// are plain ASCII; 0x80..0x9F are the Microsoft Windows code-page-1252
/// punctuation overlay; 0xA0..0xFF round-trip 1:1 to Latin-1 with a few
/// CP1252-specific swaps (the spec table is canonical).
fn fill_winansi(m: &mut EncodingMap) {
    // ASCII printable.
    for b in 0x20u8..=0x7E {
        m.set_char(b, b as char);
    }
    // CP1252 punctuation overlay (0x80..0x9F).
    let overlay: &[(u8, char)] = &[
        (0x80, '\u{20AC}'),
        (0x82, '\u{201A}'),
        (0x83, '\u{0192}'),
        (0x84, '\u{201E}'),
        (0x85, '\u{2026}'),
        (0x86, '\u{2020}'),
        (0x87, '\u{2021}'),
        (0x88, '\u{02C6}'),
        (0x89, '\u{2030}'),
        (0x8A, '\u{0160}'),
        (0x8B, '\u{2039}'),
        (0x8C, '\u{0152}'),
        (0x8E, '\u{017D}'),
        (0x91, '\u{2018}'),
        (0x92, '\u{2019}'),
        (0x93, '\u{201C}'),
        (0x94, '\u{201D}'),
        (0x95, '\u{2022}'),
        (0x96, '\u{2013}'),
        (0x97, '\u{2014}'),
        (0x98, '\u{02DC}'),
        (0x99, '\u{2122}'),
        (0x9A, '\u{0161}'),
        (0x9B, '\u{203A}'),
        (0x9C, '\u{0153}'),
        (0x9E, '\u{017E}'),
        (0x9F, '\u{0178}'),
    ];
    for (b, c) in overlay {
        m.set_char(*b, *c);
    }
    // Latin-1 supplement (0xA0..0xFF).
    for b in 0xA0u8..=0xFF {
        m.set_char(b, b as char);
    }
}

/// MacRomanEncoding — ISO 32000-1 Annex D.2 Table D.2 (the "Mac" column).
fn fill_macroman(m: &mut EncodingMap) {
    // ASCII printable.
    for b in 0x20u8..=0x7E {
        m.set_char(b, b as char);
    }
    // Bytes 0x80..0xFF — the canonical Mac Roman table.
    let table: &[(u8, char)] = &[
        (0x80, '\u{00C4}'),
        (0x81, '\u{00C5}'),
        (0x82, '\u{00C7}'),
        (0x83, '\u{00C9}'),
        (0x84, '\u{00D1}'),
        (0x85, '\u{00D6}'),
        (0x86, '\u{00DC}'),
        (0x87, '\u{00E1}'),
        (0x88, '\u{00E0}'),
        (0x89, '\u{00E2}'),
        (0x8A, '\u{00E4}'),
        (0x8B, '\u{00E3}'),
        (0x8C, '\u{00E5}'),
        (0x8D, '\u{00E7}'),
        (0x8E, '\u{00E9}'),
        (0x8F, '\u{00E8}'),
        (0x90, '\u{00EA}'),
        (0x91, '\u{00EB}'),
        (0x92, '\u{00ED}'),
        (0x93, '\u{00EC}'),
        (0x94, '\u{00EE}'),
        (0x95, '\u{00EF}'),
        (0x96, '\u{00F1}'),
        (0x97, '\u{00F3}'),
        (0x98, '\u{00F2}'),
        (0x99, '\u{00F4}'),
        (0x9A, '\u{00F6}'),
        (0x9B, '\u{00F5}'),
        (0x9C, '\u{00FA}'),
        (0x9D, '\u{00F9}'),
        (0x9E, '\u{00FB}'),
        (0x9F, '\u{00FC}'),
        (0xA0, '\u{2020}'),
        (0xA1, '\u{00B0}'),
        (0xA2, '\u{00A2}'),
        (0xA3, '\u{00A3}'),
        (0xA4, '\u{00A7}'),
        (0xA5, '\u{2022}'),
        (0xA6, '\u{00B6}'),
        (0xA7, '\u{00DF}'),
        (0xA8, '\u{00AE}'),
        (0xA9, '\u{00A9}'),
        (0xAA, '\u{2122}'),
        (0xAB, '\u{00B4}'),
        (0xAC, '\u{00A8}'),
        (0xAD, '\u{2260}'),
        (0xAE, '\u{00C6}'),
        (0xAF, '\u{00D8}'),
        (0xB0, '\u{221E}'),
        (0xB1, '\u{00B1}'),
        (0xB2, '\u{2264}'),
        (0xB3, '\u{2265}'),
        (0xB4, '\u{00A5}'),
        (0xB5, '\u{00B5}'),
        (0xB6, '\u{2202}'),
        (0xB7, '\u{2211}'),
        (0xB8, '\u{220F}'),
        (0xB9, '\u{03C0}'),
        (0xBA, '\u{222B}'),
        (0xBB, '\u{00AA}'),
        (0xBC, '\u{00BA}'),
        (0xBD, '\u{03A9}'),
        (0xBE, '\u{00E6}'),
        (0xBF, '\u{00F8}'),
        (0xC0, '\u{00BF}'),
        (0xC1, '\u{00A1}'),
        (0xC2, '\u{00AC}'),
        (0xC3, '\u{221A}'),
        (0xC4, '\u{0192}'),
        (0xC5, '\u{2248}'),
        (0xC6, '\u{2206}'),
        (0xC7, '\u{00AB}'),
        (0xC8, '\u{00BB}'),
        (0xC9, '\u{2026}'),
        (0xCA, '\u{00A0}'),
        (0xCB, '\u{00C0}'),
        (0xCC, '\u{00C3}'),
        (0xCD, '\u{00D5}'),
        (0xCE, '\u{0152}'),
        (0xCF, '\u{0153}'),
        (0xD0, '\u{2013}'),
        (0xD1, '\u{2014}'),
        (0xD2, '\u{201C}'),
        (0xD3, '\u{201D}'),
        (0xD4, '\u{2018}'),
        (0xD5, '\u{2019}'),
        (0xD6, '\u{00F7}'),
        (0xD7, '\u{25CA}'),
        (0xD8, '\u{00FF}'),
        (0xD9, '\u{0178}'),
        (0xDA, '\u{2044}'),
        (0xDB, '\u{20AC}'),
        (0xDC, '\u{2039}'),
        (0xDD, '\u{203A}'),
        (0xDE, '\u{FB01}'),
        (0xDF, '\u{FB02}'),
        (0xE0, '\u{2021}'),
        (0xE1, '\u{00B7}'),
        (0xE2, '\u{201A}'),
        (0xE3, '\u{201E}'),
        (0xE4, '\u{2030}'),
        (0xE5, '\u{00C2}'),
        (0xE6, '\u{00CA}'),
        (0xE7, '\u{00C1}'),
        (0xE8, '\u{00CB}'),
        (0xE9, '\u{00C8}'),
        (0xEA, '\u{00CD}'),
        (0xEB, '\u{00CE}'),
        (0xEC, '\u{00CF}'),
        (0xED, '\u{00CC}'),
        (0xEE, '\u{00D3}'),
        (0xEF, '\u{00D4}'),
        (0xF1, '\u{00D2}'),
        (0xF2, '\u{00DA}'),
        (0xF3, '\u{00DB}'),
        (0xF4, '\u{00D9}'),
        (0xF5, '\u{0131}'),
        (0xF6, '\u{02C6}'),
        (0xF7, '\u{02DC}'),
        (0xF8, '\u{00AF}'),
        (0xF9, '\u{02D8}'),
        (0xFA, '\u{02D9}'),
        (0xFB, '\u{02DA}'),
        (0xFC, '\u{00B8}'),
        (0xFD, '\u{02DD}'),
        (0xFE, '\u{02DB}'),
        (0xFF, '\u{02C7}'),
    ];
    for (b, c) in table {
        m.set_char(*b, *c);
    }
}

/// MacExpertEncoding — ISO 32000-1 Annex D.4. Only the slots that have a
/// commonly-recognised Unicode equivalent are populated; the rest stay
/// unassigned. This is the rarest encoding in practice — text-extraction
/// almost never sees it.
fn fill_macexpert(m: &mut EncodingMap) {
    // The spec table is very sparse — we transcribe just the entries
    // whose AGL name has a Unicode glyph today.
    let table: &[(u8, char)] = &[
        (0x20, ' '),
        (0x21, '\u{F721}'),
        (0x22, '\u{F6F8}'),
        (0x23, '\u{F7A2}'),
        (0x24, '\u{F724}'),
        (0x25, '\u{F6E4}'),
        (0x26, '\u{F726}'),
        (0x27, '\u{F7B4}'),
        (0x28, '\u{207D}'),
        (0x29, '\u{207E}'),
        (0x2A, '\u{2022}'),
        (0x2B, '\u{2024}'),
        (0x2C, ','),
        (0x2D, '-'),
        (0x2E, '.'),
        (0x2F, '\u{2044}'),
        (0x30, '\u{F730}'),
        (0x31, '\u{F731}'),
        (0x32, '\u{F732}'),
        (0x33, '\u{F733}'),
        (0x34, '\u{F734}'),
        (0x35, '\u{F735}'),
        (0x36, '\u{F736}'),
        (0x37, '\u{F737}'),
        (0x38, '\u{F738}'),
        (0x39, '\u{F739}'),
        (0x3A, ':'),
        (0x3B, ';'),
        (0x3D, '\u{F6DE}'),
        (0x3F, '\u{F73F}'),
    ];
    for (b, c) in table {
        m.set_char(*b, *c);
    }
}

/// StandardEncoding — ISO 32000-1 Annex D.2 (Adobe Type 1 Standard
/// encoding, the implicit default when a Type 1 font omits `/Encoding`).
/// Bytes 0x20..0x7E + a small upper-byte set (0xA1..0xFA).
fn fill_standard(m: &mut EncodingMap) {
    // Most of 0x20..0x7E matches ASCII.
    for b in 0x20u8..=0x7E {
        m.set_char(b, b as char);
    }
    // Per Annex D.2, a few code points in the printable ASCII range
    // overlap the AGL names that are NOT plain ASCII (e.g. 0x27 in
    // StandardEncoding is `quoteright` → U+2019, not U+0027).
    m.set_char(0x27, '\u{2019}'); // quoteright
    m.set_char(0x60, '\u{2018}'); // quoteleft
    m.set_char(0x22, '"'); // quotedbl
                           // Upper bytes — the "Standard Latin" extras.
    let upper: &[(u8, char)] = &[
        (0xA1, '\u{00A1}'),
        (0xA2, '\u{00A2}'),
        (0xA3, '\u{00A3}'),
        (0xA4, '\u{2044}'),
        (0xA5, '\u{00A5}'),
        (0xA6, '\u{0192}'),
        (0xA7, '\u{00A7}'),
        (0xA8, '\u{00A4}'),
        (0xA9, '\''),
        (0xAA, '\u{201C}'),
        (0xAB, '\u{00AB}'),
        (0xAC, '\u{2039}'),
        (0xAD, '\u{203A}'),
        (0xAE, '\u{FB01}'),
        (0xAF, '\u{FB02}'),
        (0xB1, '\u{2013}'),
        (0xB2, '\u{2020}'),
        (0xB3, '\u{2021}'),
        (0xB4, '\u{00B7}'),
        (0xB6, '\u{00B6}'),
        (0xB7, '\u{2022}'),
        (0xB8, '\u{201A}'),
        (0xB9, '\u{201E}'),
        (0xBA, '\u{201D}'),
        (0xBB, '\u{00BB}'),
        (0xBC, '\u{2026}'),
        (0xBD, '\u{2030}'),
        (0xBF, '\u{00BF}'),
        (0xC1, '\u{0060}'),
        (0xC2, '\u{00B4}'),
        (0xC3, '\u{02C6}'),
        (0xC4, '\u{02DC}'),
        (0xC5, '\u{00AF}'),
        (0xC6, '\u{02D8}'),
        (0xC7, '\u{02D9}'),
        (0xC8, '\u{00A8}'),
        (0xCA, '\u{02DA}'),
        (0xCB, '\u{00B8}'),
        (0xCD, '\u{02DD}'),
        (0xCE, '\u{02DB}'),
        (0xCF, '\u{02C7}'),
        (0xD0, '\u{2014}'),
        (0xE1, '\u{00C6}'),
        (0xE3, '\u{00AA}'),
        (0xE8, '\u{0141}'),
        (0xE9, '\u{00D8}'),
        (0xEA, '\u{0152}'),
        (0xEB, '\u{00BA}'),
        (0xF1, '\u{00E6}'),
        (0xF5, '\u{0131}'),
        (0xF8, '\u{0142}'),
        (0xF9, '\u{00F8}'),
        (0xFA, '\u{0153}'),
        (0xFB, '\u{00DF}'),
    ];
    for (b, c) in upper {
        m.set_char(*b, *c);
    }
}

/// SymbolEncoding — ISO 32000-1 Annex D.5 (Symbol font's built-in
/// encoding — Greek + math). Sparse; only the spec entries.
fn fill_symbol(m: &mut EncodingMap) {
    let table: &[(u8, char)] = &[
        (0x20, ' '),
        (0x21, '!'),
        (0x22, '\u{2200}'), // universal
        (0x23, '#'),
        (0x24, '\u{2203}'), // existential
        (0x25, '%'),
        (0x26, '&'),
        (0x27, '\u{220B}'),
        (0x28, '('),
        (0x29, ')'),
        (0x2A, '\u{2217}'),
        (0x2B, '+'),
        (0x2C, ','),
        (0x2D, '\u{2212}'),
        (0x2E, '.'),
        (0x2F, '/'),
        (0x30, '0'),
        (0x31, '1'),
        (0x32, '2'),
        (0x33, '3'),
        (0x34, '4'),
        (0x35, '5'),
        (0x36, '6'),
        (0x37, '7'),
        (0x38, '8'),
        (0x39, '9'),
        (0x3A, ':'),
        (0x3B, ';'),
        (0x3C, '<'),
        (0x3D, '='),
        (0x3E, '>'),
        (0x3F, '?'),
        (0x40, '\u{2245}'),
        (0x41, '\u{0391}'),
        (0x42, '\u{0392}'),
        (0x43, '\u{03A7}'),
        (0x44, '\u{0394}'),
        (0x45, '\u{0395}'),
        (0x46, '\u{03A6}'),
        (0x47, '\u{0393}'),
        (0x48, '\u{0397}'),
        (0x49, '\u{0399}'),
        (0x4A, '\u{03D1}'),
        (0x4B, '\u{039A}'),
        (0x4C, '\u{039B}'),
        (0x4D, '\u{039C}'),
        (0x4E, '\u{039D}'),
        (0x4F, '\u{039F}'),
        (0x50, '\u{03A0}'),
        (0x51, '\u{0398}'),
        (0x52, '\u{03A1}'),
        (0x53, '\u{03A3}'),
        (0x54, '\u{03A4}'),
        (0x55, '\u{03A5}'),
        (0x56, '\u{03C2}'),
        (0x57, '\u{03A9}'),
        (0x58, '\u{039E}'),
        (0x59, '\u{03A8}'),
        (0x5A, '\u{0396}'),
        (0x61, '\u{03B1}'),
        (0x62, '\u{03B2}'),
        (0x63, '\u{03C7}'),
        (0x64, '\u{03B4}'),
        (0x65, '\u{03B5}'),
        (0x66, '\u{03C6}'),
        (0x67, '\u{03B3}'),
        (0x68, '\u{03B7}'),
        (0x69, '\u{03B9}'),
        (0x6A, '\u{03D5}'),
        (0x6B, '\u{03BA}'),
        (0x6C, '\u{03BB}'),
        (0x6D, '\u{03BC}'),
        (0x6E, '\u{03BD}'),
        (0x6F, '\u{03BF}'),
        (0x70, '\u{03C0}'),
        (0x71, '\u{03B8}'),
        (0x72, '\u{03C1}'),
        (0x73, '\u{03C3}'),
        (0x74, '\u{03C4}'),
        (0x75, '\u{03C5}'),
        (0x76, '\u{03D6}'),
        (0x77, '\u{03C9}'),
        (0x78, '\u{03BE}'),
        (0x79, '\u{03C8}'),
        (0x7A, '\u{03B6}'),
    ];
    for (b, c) in table {
        m.set_char(*b, *c);
    }
}

/// ZapfDingbatsEncoding — ISO 32000-1 Annex D.6 (the bundled dingbats
/// font's built-in encoding). Sparse subset; full table is round-29+.
fn fill_zapfdingbats(m: &mut EncodingMap) {
    let table: &[(u8, char)] = &[
        (0x20, ' '),
        (0x21, '\u{2701}'),
        (0x22, '\u{2702}'),
        (0x23, '\u{2703}'),
        (0x24, '\u{2704}'),
        (0x25, '\u{260E}'),
        (0x26, '\u{2706}'),
        (0x27, '\u{2707}'),
        (0x28, '\u{2708}'),
        (0x29, '\u{2709}'),
        (0x2A, '\u{261B}'),
        (0x2B, '\u{261E}'),
        (0x2C, '\u{270C}'),
        (0x2D, '\u{270D}'),
        (0x2E, '\u{270E}'),
        (0x2F, '\u{270F}'),
        (0x30, '\u{2710}'),
        (0x31, '\u{2711}'),
        (0x32, '\u{2712}'),
        (0x33, '\u{2713}'),
        (0x34, '\u{2714}'),
        (0x35, '\u{2715}'),
        (0x36, '\u{2716}'),
        (0x37, '\u{2717}'),
        (0x38, '\u{2718}'),
        (0x39, '\u{2719}'),
        (0x3A, '\u{271A}'),
        (0x3B, '\u{271B}'),
        (0x3C, '\u{271C}'),
        (0x3D, '\u{271D}'),
        (0x3E, '\u{271E}'),
        (0x3F, '\u{271F}'),
        (0x40, '\u{2720}'),
        (0x41, '\u{2721}'),
        (0x42, '\u{2722}'),
        (0x43, '\u{2723}'),
    ];
    for (b, c) in table {
        m.set_char(*b, *c);
    }
}

// ────────────────────────── tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Object {
        Object::Name(s.to_string())
    }
    fn int(n: i64) -> Object {
        Object::Integer(n)
    }

    #[test]
    fn parse_simple_differences_array() {
        // [24 /breve /caron /circumflex 32 /space]
        let arr = Object::Array(vec![
            int(24),
            name("breve"),
            name("caron"),
            name("circumflex"),
            int(32),
            name("space"),
        ]);
        let d = parse_encoding_differences(&arr).unwrap();
        assert_eq!(d.overrides.len(), 4);
        assert_eq!(d.overrides[0].code, 24);
        assert_eq!(d.overrides[0].glyph_name, "breve");
        assert_eq!(d.overrides[1].code, 25);
        assert_eq!(d.overrides[1].glyph_name, "caron");
        assert_eq!(d.overrides[2].code, 26);
        assert_eq!(d.overrides[2].glyph_name, "circumflex");
        assert_eq!(d.overrides[3].code, 32);
        assert_eq!(d.overrides[3].glyph_name, "space");
    }

    #[test]
    fn parse_differences_skips_unknown_tokens() {
        // [24 /breve null /caron]  → null is skipped, caron lands at 25.
        let arr = Object::Array(vec![int(24), name("breve"), Object::Null, name("caron")]);
        let d = parse_encoding_differences(&arr).unwrap();
        assert_eq!(d.overrides.len(), 2);
        assert_eq!(d.overrides[0].code, 24);
        assert_eq!(d.overrides[1].code, 25);
        assert_eq!(d.overrides[1].glyph_name, "caron");
    }

    #[test]
    fn parse_differences_real_coerced() {
        // [24.0 /breve]
        let arr = Object::Array(vec![Object::Real(24.0), name("breve")]);
        let d = parse_encoding_differences(&arr).unwrap();
        assert_eq!(d.overrides.len(), 1);
        assert_eq!(d.overrides[0].code, 24);
    }

    #[test]
    fn parse_differences_rejects_non_array() {
        let r = parse_encoding_differences(&Object::Null);
        assert!(r.is_err());
    }

    #[test]
    fn agl_lookup_basic_latin() {
        assert_eq!(glyph_name_to_unicode("A").as_deref(), Some("A"));
        assert_eq!(glyph_name_to_unicode("space").as_deref(), Some(" "));
        assert_eq!(glyph_name_to_unicode("zero").as_deref(), Some("0"));
    }

    #[test]
    fn agl_lookup_smart_quotes() {
        assert_eq!(
            glyph_name_to_unicode("quoteright").as_deref(),
            Some("\u{2019}")
        );
        assert_eq!(
            glyph_name_to_unicode("quotedblleft").as_deref(),
            Some("\u{201C}")
        );
    }

    #[test]
    fn agl_lookup_ligature() {
        assert_eq!(glyph_name_to_unicode("fi").as_deref(), Some("fi"));
        assert_eq!(glyph_name_to_unicode("fl").as_deref(), Some("fl"));
    }

    #[test]
    fn agl_lookup_notdef_is_empty() {
        assert_eq!(glyph_name_to_unicode(".notdef").as_deref(), Some(""));
    }

    #[test]
    fn agl_lookup_unknown() {
        assert!(glyph_name_to_unicode("notaglyphname").is_none());
    }

    #[test]
    fn agl_uni_bmp_single_group() {
        // AGL PIN §3 — `uniXXXX` for one BMP codepoint.
        assert_eq!(
            glyph_name_to_unicode("uni201C").as_deref(),
            Some("\u{201C}")
        );
        assert_eq!(
            glyph_name_to_unicode("uni2019").as_deref(),
            Some("\u{2019}")
        );
        // BMP edge — U+0041 ('A'). Static table preferred when `/A` is
        // emitted, but the escape resolves through this path too.
        assert_eq!(glyph_name_to_unicode("uni0041").as_deref(), Some("A"));
    }

    #[test]
    fn agl_uni_bmp_multi_group() {
        // Multi-group concatenation per AGL PIN §3 — two codepoints
        // glued into one glyph name.
        assert_eq!(
            glyph_name_to_unicode("uni20142019").as_deref(),
            Some("\u{2014}\u{2019}")
        );
    }

    #[test]
    fn agl_uni_supplementary_plane() {
        // `uXXXXXXXX` form for a supplementary-plane codepoint.
        // U+1F600 GRINNING FACE — encoded as 5 hex chars.
        assert_eq!(
            glyph_name_to_unicode("u1F600").as_deref(),
            Some("\u{1F600}")
        );
        // Full 6-char form for the highest valid Unicode (U+10FFFF).
        assert_eq!(
            glyph_name_to_unicode("u10FFFF").as_deref(),
            Some("\u{10FFFF}")
        );
        // 4-digit `u` form is also valid per AGL PIN §3.
        assert_eq!(glyph_name_to_unicode("u00A9").as_deref(), Some("\u{00A9}"));
    }

    #[test]
    fn agl_uni_rejects_surrogate_halves() {
        // U+D800 is the start of the surrogate range — must not decode.
        assert!(glyph_name_to_unicode("uniD800").is_none());
        assert!(glyph_name_to_unicode("uniDFFF").is_none());
        assert!(glyph_name_to_unicode("uD800").is_none());
    }

    #[test]
    fn agl_uni_rejects_ffff_noncharacter() {
        // AGL PIN §3 carves out U+FFFF.
        assert!(glyph_name_to_unicode("uniFFFF").is_none());
        assert!(glyph_name_to_unicode("uFFFF").is_none());
    }

    #[test]
    fn agl_uni_rejects_misshapen_input() {
        // `uni` with a remainder not divisible by 4 — reject.
        assert!(glyph_name_to_unicode("uni20").is_none());
        assert!(glyph_name_to_unicode("uni20142").is_none());
        // `uni` with no remainder — reject.
        assert!(glyph_name_to_unicode("uni").is_none());
        // `u` with too-few or too-many hex digits — reject.
        assert!(glyph_name_to_unicode("u041").is_none());
        assert!(glyph_name_to_unicode("u1234567").is_none());
        // `u` over U+10FFFF — reject (char::from_u32 returns None).
        assert!(glyph_name_to_unicode("u110000").is_none());
        // Lowercase hex — AGL canon is uppercase, reject so the
        // ambiguity doesn't propagate into the encoding table.
        assert!(glyph_name_to_unicode("uni201c").is_none());
        assert!(glyph_name_to_unicode("u1f600").is_none());
        // Non-hex bytes in the suffix — reject.
        assert!(glyph_name_to_unicode("uniZZZZ").is_none());
        // The bare `u` / `uni` prefix on a real AGL name (e.g.
        // `university` — not in the AGL subset) must not be mistaken
        // for the escape form.
        assert!(glyph_name_to_unicode("university").is_none());
    }

    #[test]
    fn agl_uni_escape_in_differences() {
        // End-to-end: a `/Differences` override that uses the
        // `uniXXXX` escape decodes to the correct Unicode payload.
        let base = EncodingMap::from_base(BaseEncoding::WinAnsi);
        let diffs = EncodingDifferences {
            overrides: vec![
                EncodingOverride {
                    code: 0x80,
                    glyph_name: "uni201C".to_string(),
                },
                EncodingOverride {
                    code: 0x81,
                    glyph_name: "u1F600".to_string(),
                },
            ],
        };
        let out = apply_encoding_differences(&base, &diffs);
        assert_eq!(out.decode(&[0x80]), "\u{201C}");
        assert_eq!(out.decode(&[0x81]), "\u{1F600}");
    }

    #[test]
    fn winansi_base_map_decodes_ascii_and_smart_quote() {
        let m = EncodingMap::from_base(BaseEncoding::WinAnsi);
        assert_eq!(m.decode(b"Hello"), "Hello");
        // 0x93 = U+201C in CP1252.
        assert_eq!(m.decode(&[0x93]), "\u{201C}");
    }

    #[test]
    fn apply_differences_overrides_base_map() {
        // Start with WinAnsi (0x41 = 'A'). Override 0x41 → /Omega.
        let base = EncodingMap::from_base(BaseEncoding::WinAnsi);
        let diffs = EncodingDifferences {
            overrides: vec![EncodingOverride {
                code: 0x41,
                glyph_name: "Omega".to_string(),
            }],
        };
        let out = apply_encoding_differences(&base, &diffs);
        assert_eq!(out.decode(&[0x41]), "\u{03A9}"); // Greek capital Omega
                                                     // Sibling codes unchanged.
        assert_eq!(out.decode(&[0x42]), "B");
    }

    #[test]
    fn apply_differences_unknown_glyph_becomes_replacement() {
        let base = EncodingMap::from_base(BaseEncoding::WinAnsi);
        let diffs = EncodingDifferences {
            overrides: vec![EncodingOverride {
                code: 0x41,
                glyph_name: "not-a-real-glyph-name".to_string(),
            }],
        };
        let out = apply_encoding_differences(&base, &diffs);
        // 0x41 slot is now empty → decode emits U+FFFD.
        assert_eq!(out.decode(&[0x41]), "\u{FFFD}");
    }

    #[test]
    fn apply_differences_ligature_expands() {
        let base = EncodingMap::from_base(BaseEncoding::WinAnsi);
        let diffs = EncodingDifferences {
            overrides: vec![EncodingOverride {
                code: 0xFD,
                glyph_name: "fi".to_string(),
            }],
        };
        let out = apply_encoding_differences(&base, &diffs);
        assert_eq!(out.decode(&[0xFD]), "fi");
    }

    #[test]
    fn macroman_base_map_smart_quotes() {
        let m = EncodingMap::from_base(BaseEncoding::MacRoman);
        // MacRoman 0xD2 = U+201C left double smart quote.
        assert_eq!(m.decode(&[0xD2]), "\u{201C}");
    }

    #[test]
    fn standard_base_map_quotes() {
        let m = EncodingMap::from_base(BaseEncoding::Standard);
        // Standard 0x27 = quoteright = U+2019, not ASCII apostrophe.
        assert_eq!(m.decode(&[0x27]), "\u{2019}");
    }

    #[test]
    fn symbol_base_map_alpha() {
        let m = EncodingMap::from_base(BaseEncoding::Symbol);
        // Symbol 0x41 = uppercase Alpha = U+0391.
        assert_eq!(m.decode(&[0x41]), "\u{0391}");
        // Symbol 0x70 = lowercase pi = U+03C0.
        assert_eq!(m.decode(&[0x70]), "\u{03C0}");
    }

    #[test]
    fn base_encoding_name_recognition() {
        assert_eq!(
            BaseEncoding::from_name("WinAnsiEncoding"),
            Some(BaseEncoding::WinAnsi)
        );
        assert_eq!(
            BaseEncoding::from_name("MacRomanEncoding"),
            Some(BaseEncoding::MacRoman)
        );
        assert_eq!(BaseEncoding::from_name("not-a-real-name"), None);
    }

    #[test]
    fn unassigned_code_decodes_to_replacement() {
        let m = EncodingMap::from_base(BaseEncoding::Standard);
        // StandardEncoding has nothing at 0x00 — must come back as FFFD.
        assert_eq!(m.decode(&[0x00]), "\u{FFFD}");
    }
}
