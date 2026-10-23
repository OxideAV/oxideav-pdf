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
//! `TJ` numeric position adjustments are read per ISO 32000-1 §9.4.3
//! (Table 109 + Figure 46): a rightward gap wider than a quarter-em is
//! recovered as an inter-word space, so words a producer separated with
//! a bare displacement (no literal space glyph) extract correctly while
//! tight intra-word kerning stays joined. See [`TextWalker::emit_show_tj`].
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

use std::collections::{HashMap, HashSet};
use std::str;

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::reader::cid_cmap::CidCMap;
use crate::reader::document::{DocumentReader, decode_stream};
use crate::reader::encoding::{
    BaseEncoding, EncodingMap, apply_encoding_differences, parse_encoding_differences,
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
#[non_exhaustive]
pub struct TextRun {
    /// Decoded Unicode payload — the result of mapping every encoded
    /// byte / CID through the font's `/ToUnicode` CMap (or the
    /// identity / WinAnsi fallbacks documented above).
    pub text: String,
    /// `(x, y)` in PDF user space — the origin at which the run's
    /// glyphs begin. This is the text-matrix origin adjusted by the
    /// text rise `Ts` (ISO 32000-1 §9.4.4): per the text-rendering
    /// matrix the rise translates the rendering origin by `Trise`
    /// along the text matrix's vertical basis, so a `4 Ts` superscript
    /// reports a `position` shifted up from the surrounding baseline
    /// rather than colliding with it. When no `Ts` is in force the
    /// rise is `0` and the position is the bare text-matrix origin.
    pub position: (f32, f32),
    /// The PDF resource name of the font (`/F0`, `/F12`, etc.) — the
    /// `/Tf` operand, with the leading `/` stripped. Empty when the
    /// content stream issues a show without a preceding `Tf`
    /// (malformed but tolerated).
    pub font_name: String,
    /// Font size as supplied to the `Tf` operator.
    pub font_size: f32,
    /// Text rendering mode in force at the moment of the show — the
    /// most recent `Tr` operand (ISO 32000-1 §9.3.6, Table 106),
    /// defaulting to [`TextRenderMode::Fill`] when no `Tr` preceded
    /// the show. The load-bearing case for extraction consumers is
    /// [`TextRenderMode::Invisible`] (`3 Tr`): the unpainted OCR text
    /// layer scanners stack behind a page image. A keyword-search
    /// consumer keeps it; a "what the human sees" consumer drops it.
    pub render_mode: TextRenderMode,
    /// Text rise in force at the moment of the show — the most recent
    /// `Ts` operand (ISO 32000-1 §9.4.4 + §9.3.7, Table 105),
    /// expressed in unscaled text-space units, defaulting to `0.0`
    /// when no `Ts` preceded the show. A positive rise raises the
    /// baseline (superscript); a negative rise lowers it (subscript).
    /// The geometric effect is already folded into [`Self::position`];
    /// this raw value lets a layout / accessibility consumer classify
    /// a run as super/subscript without reverse-engineering the offset
    /// from the position delta.
    pub text_rise: f32,
    /// The text matrix `Tm` (`[a b c d e f]`, ISO 32000-1 §9.4.2) in
    /// force when the show fired — before the run's own advance and
    /// without the rise folded in. Its first column `(a, b)` is the
    /// baseline direction and `hypot(a, b) × font_size` the rendered
    /// em; [`Self::end`] maps the run's advance through it. Identity
    /// for a run assembled by hand.
    pub text_matrix: [f32; 6],
    /// The §9.4.4 displacement `(tx, ty)` the run's glyphs produced,
    /// in unscaled text-space units (glyph advances × `Tfs`, plus
    /// `Tc` / `Tw` / `TJ` kerns, × `Th` horizontally). `ty` is non-zero
    /// only in vertical writing mode. `(0, 0)` when the font declared
    /// no metrics, so [`Self::end`] then coincides with the origin.
    pub advance: (f32, f32),
}

impl TextRun {
    /// A run with the text-state defaults (`Fill`, no rise, identity
    /// text matrix, no advance). Builders set the rest with the
    /// `with_*` methods.
    pub fn new(
        text: impl Into<String>,
        position: (f32, f32),
        font_name: impl Into<String>,
        font_size: f32,
    ) -> Self {
        Self {
            text: text.into(),
            position,
            font_name: font_name.into(),
            font_size,
            render_mode: TextRenderMode::Fill,
            text_rise: 0.0,
            text_matrix: identity(),
            advance: (0.0, 0.0),
        }
    }

    /// Set the text rendering mode.
    pub fn with_render_mode(mut self, mode: TextRenderMode) -> Self {
        self.render_mode = mode;
        self
    }

    /// Set the text rise.
    pub fn with_text_rise(mut self, rise: f32) -> Self {
        self.text_rise = rise;
        self
    }

    /// Set the text matrix in force at the show.
    pub fn with_text_matrix(mut self, tm: [f32; 6]) -> Self {
        self.text_matrix = tm;
        self
    }

    /// Set the run's unscaled text-space advance.
    pub fn with_advance(mut self, advance: (f32, f32)) -> Self {
        self.advance = advance;
        self
    }

    /// The point in user space where the run's glyphs end — the origin
    /// the next show on the same line starts from — on the same
    /// (rise-adjusted) baseline as [`Self::position`].
    pub fn end(&self) -> (f32, f32) {
        let m = self.text_matrix;
        let (tx, ty) = self.advance;
        let (x, y) = self.position;
        (x + m[0] * tx + m[2] * ty, y + m[1] * tx + m[3] * ty)
    }

    /// The rendered em of the run: `font_size` scaled by the text
    /// matrix's horizontal basis. `font_size` alone when the matrix
    /// is degenerate.
    pub fn em(&self) -> f32 {
        let m = self.text_matrix;
        let s = (m[0] * m[0] + m[1] * m[1]).sqrt();
        if s > 0.0 && s.is_finite() {
            self.font_size * s
        } else {
            self.font_size
        }
    }

    /// Writing direction: `true` when the run advanced vertically
    /// (a `WMode 1` font) rather than along the baseline.
    pub fn is_vertical(&self) -> bool {
        self.advance.0 == 0.0 && self.advance.1 != 0.0
    }
}

/// Text rendering mode — the integer argument to the `Tr` operator
/// (ISO 32000-1 §9.3.6, Table 106). Determines whether the glyphs of a
/// text run are filled, stroked, used as a clipping boundary, or left
/// unpainted entirely. Surfaced on every [`TextRun`] so an extraction
/// consumer can distinguish visible body text from the invisible
/// (`3 Tr`) OCR layer that scanned PDFs hide behind a page image, and
/// from the clip-only (`7 Tr`) modes that paint no marks at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TextRenderMode {
    /// `0` — fill text (the default when no `Tr` is issued).
    #[default]
    Fill,
    /// `1` — stroke text.
    Stroke,
    /// `2` — fill, then stroke text.
    FillStroke,
    /// `3` — neither fill nor stroke (invisible). The OCR text layer
    /// behind a scanned-page image uses this so the glyphs are
    /// searchable / selectable but never painted.
    Invisible,
    /// `4` — fill text and add to the path for clipping.
    FillClip,
    /// `5` — stroke text and add to the path for clipping.
    StrokeClip,
    /// `6` — fill, then stroke text and add to the path for clipping.
    FillStrokeClip,
    /// `7` — add text to the path for clipping (no fill, no stroke).
    Clip,
}

impl TextRenderMode {
    /// Resolve a `Tr` operand integer to its typed mode. Table 106
    /// enumerates exactly `0..=7`; out-of-range values are tolerated by
    /// mapping back to [`TextRenderMode::Fill`] (the §9.3.1 default
    /// text state), matching the reader's lenient stance elsewhere.
    pub fn from_operand(n: i64) -> Self {
        match n {
            0 => Self::Fill,
            1 => Self::Stroke,
            2 => Self::FillStroke,
            3 => Self::Invisible,
            4 => Self::FillClip,
            5 => Self::StrokeClip,
            6 => Self::FillStrokeClip,
            7 => Self::Clip,
            _ => Self::Fill,
        }
    }

    /// Whether glyphs in this mode paint any visible marks. `false`
    /// only for [`TextRenderMode::Invisible`] (`3`) and
    /// [`TextRenderMode::Clip`] (`7`) — the two modes that add nothing
    /// to the page raster. Lets a "visible text only" consumer filter
    /// the OCR layer out in one call.
    pub fn paints_glyphs(self) -> bool {
        !matches!(self, Self::Invisible | Self::Clip)
    }
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
        assemble_text(&self.runs)
    }

    /// The runs assembled into lines — see [`assemble_text`] for the
    /// word-gap and line-break rules.
    pub fn lines(&self) -> Vec<String> {
        assemble_text(&self.runs)
            .split('\n')
            .map(str::to_owned)
            .collect()
    }
}

/// Assemble text runs into words and lines from their geometry.
///
/// Producers lay text down in very different granularities: one show
/// per word with the inter-word gap as a `TJ` kern or a `Td` move
/// (pdfTeX), one show per word plus a separate space glyph (cairo), or
/// one show per glyph with a `Td` between every pair (Skia, many
/// browser print paths). Joining runs with a fixed separator therefore
/// either glues words together or spaces every letter out. This pass
/// instead walks the runs in the given order and decides each boundary
/// from the geometry the walker recorded on the runs:
///
/// * **Line break** — the next run's baseline (its origin projected on
///   the perpendicular of the previous run's baseline direction) moves
///   by more than half the larger em, or the run starts more than half
///   an em *behind* the previous run's end on the same baseline (a new
///   line or column that happens to share the baseline).
/// * **Word break** — on the same line, the gap between the previous
///   run's [`TextRun::end`] and the next run's origin is at least
///   [`WORD_GAP_EM`] of the smaller em plus the line's letter spacing.
///   Glyph-level kerns stay below that; a space advance (0.2–0.35 em
///   in text faces, 0.17 em for TeX's most-shrunk interword glue)
///   lands above it. The letter spacing is measured on the line
///   itself when it is laid down glyph by glyph (see
///   [`letter_spacing_estimate`]), so tracked headings keep their
///   words. A literal space glyph on either side of the boundary is
///   kept as is, never doubled.
/// * **Otherwise** the runs are glued, so per-glyph shows rebuild
///   their word.
///
/// A line whose letters are mostly right-to-left script is painted in
/// visual order (leftmost glyph first); it is reversed back into
/// logical order, see [`reorder_bidi_line`].
///
/// Runs whose text is empty contribute nothing but do not move the
/// previous run's end. Vertical-writing runs use the perpendicular
/// axis as their line axis. The thresholds are extraction heuristics
/// — the spec defines the geometry, not a word-break rule — and are
/// shared with the `TJ` in-run kern rule ([`TextWalker::WORD_BREAK_GAP`]).
pub fn assemble_text(runs: &[TextRun]) -> String {
    // 1. Group into lines.
    let mut lines: Vec<Vec<&TextRun>> = Vec::new();
    let mut cur: Vec<&TextRun> = Vec::new();
    for run in runs.iter().filter(|r| !r.text.is_empty()) {
        if let Some(prev) = cur.last()
            && starts_new_line(prev, run)
        {
            lines.push(std::mem::take(&mut cur));
        }
        cur.push(run);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    // 2. Words within each line.
    let mut out = String::new();
    for (li, line) in lines.iter().enumerate() {
        if li > 0 {
            out.push('\n');
        }
        let gaps: Vec<(f32, f32)> = line.windows(2).map(|w| run_gap(w[0], w[1])).collect();
        let singles: Vec<bool> = line.iter().map(|r| is_single_glyph(&r.text)).collect();
        // Letter spacing in user units: the estimate works in em
        // fractions of each pair's smaller font, so normalise the gaps.
        let rel: Vec<f32> = gaps
            .iter()
            .map(|(g, em)| if *em > 0.0 { g / em } else { 0.0 })
            .collect();
        let ls_em = letter_spacing_estimate(&singles, &rel, 1.0);
        let mut text = String::new();
        for (i, run) in line.iter().enumerate() {
            if i > 0 {
                let (gap, em) = gaps[i - 1];
                if gap >= (WORD_GAP_EM + ls_em) * em
                    && !text.ends_with(char::is_whitespace)
                    && !run.text.starts_with(char::is_whitespace)
                {
                    text.push(' ');
                }
            }
            text.push_str(&run.text);
        }
        while text.ends_with(' ') {
            text.pop();
        }
        out.push_str(&reorder_bidi_line(&text));
    }
    out
}

/// Minimum same-line gap, as a fraction of the smaller run's em, that
/// [`assemble_text`] reads as an inter-word space (before the line's
/// letter spacing is added).
pub const WORD_GAP_EM: f32 = 0.15;

/// Baseline offset, as a fraction of the larger em, beyond which two
/// runs are on different lines.
const LINE_SHIFT_EM: f32 = 0.5;

/// Backtrack along the baseline, as a fraction of the larger em,
/// beyond which a run on the same baseline starts a new line.
const BACKTRACK_EM: f32 = 0.5;

/// Largest gap, in em, that can still be letter spacing rather than a
/// word gap.
const MAX_LETTER_SPACING_EM: f32 = 0.3;

/// Unit baseline direction and its perpendicular for a run, from the
/// text matrix (the vertical-writing axis for a `WMode 1` run).
fn run_axes(r: &TextRun) -> ((f32, f32), (f32, f32)) {
    let m = r.text_matrix;
    let (ax, ay) = if r.is_vertical() {
        // Vertical runs advance along -y of text space.
        (-m[2], -m[3])
    } else {
        (m[0], m[1])
    };
    let len = (ax * ax + ay * ay).sqrt();
    let u = if len > 0.0 && len.is_finite() {
        (ax / len, ay / len)
    } else {
        (1.0, 0.0)
    };
    (u, (-u.1, u.0))
}

fn dot(a: (f32, f32), b: (f32, f32)) -> f32 {
    a.0 * b.0 + a.1 * b.1
}

fn em_pair(p: &TextRun, r: &TextRun) -> (f32, f32) {
    let em_p = p.em().abs();
    let em_r = r.em().abs();
    let big = em_p.max(em_r).max(1e-3);
    let small = if em_p > 0.0 && em_r > 0.0 {
        em_p.min(em_r)
    } else {
        big
    };
    (big, small)
}

/// Whether `r` starts a new line after `p`: a baseline shift, or a
/// backtrack along the baseline past `p`'s end.
fn starts_new_line(p: &TextRun, r: &TextRun) -> bool {
    let (u, v) = run_axes(p);
    let (em_big, _) = em_pair(p, r);
    let across = dot(r.position, v) - dot(p.position, v);
    if across.abs() > LINE_SHIFT_EM * em_big {
        return true;
    }
    let gap = dot(r.position, u) - dot(p.end(), u);
    gap < -BACKTRACK_EM * em_big
}

/// Gap along the baseline from `p`'s end to `r`'s origin (user units,
/// rightward positive) and the pair's smaller em.
fn run_gap(p: &TextRun, r: &TextRun) -> (f32, f32) {
    let (u, _) = run_axes(p);
    let (_, em_small) = em_pair(p, r);
    (dot(r.position, u) - dot(p.end(), u), em_small)
}

/// One letter or digit's worth of text: a single alphanumeric
/// character. Punctuation does not count (a comma is followed by a
/// word gap, not by letter spacing), nor does a ligature that decoded
/// to several characters.
fn is_single_glyph(text: &str) -> bool {
    let mut chars = text.chars();
    matches!((chars.next(), chars.next()), (Some(c), None) if c.is_alphanumeric())
}

/// Letter spacing of a line laid down glyph by glyph.
///
/// `singles[i]` says whether piece `i` is one glyph, `gaps[i]` is the
/// gap between pieces `i` and `i + 1` in units where `em` is one em.
/// When at least half of the pieces are single glyphs and two or more
/// positive gaps between adjacent single glyphs stay under
/// [`MAX_LETTER_SPACING_EM`], the smallest of those is the tracking
/// every glyph received and a word gap is that much wider than usual.
/// Per-word layouts and kerned `TJ` arrays yield `0`.
fn letter_spacing_estimate(singles: &[bool], gaps: &[f32], em: f32) -> f32 {
    let n = singles.len();
    if n < 3 || singles.iter().filter(|s| **s).count() * 2 < n {
        return 0.0;
    }
    let cap = MAX_LETTER_SPACING_EM * em;
    let mut best: Option<f32> = None;
    let mut count = 0usize;
    for (i, g) in gaps.iter().enumerate() {
        if singles[i] && singles.get(i + 1).copied().unwrap_or(false) && *g > 0.0 && *g <= cap {
            count += 1;
            best = Some(best.map_or(*g, |b: f32| b.min(*g)));
        }
    }
    if count >= 2 { best.unwrap_or(0.0) } else { 0.0 }
}

/// Whether a character belongs to a right-to-left script block
/// (Hebrew, Arabic, Syriac, Thaana, NKo, Samaritan, Mandaic, Arabic
/// Extended / Presentation Forms).
fn is_rtl_char(c: char) -> bool {
    matches!(
        c as u32,
        0x0590..=0x08FF | 0xFB1D..=0xFDFF | 0xFE70..=0xFEFF | 0x1_0800..=0x1_0FFF | 0x1_E800..=0x1_EFFF
    )
}

/// Combining mark that stays attached to the preceding base character
/// when a run is reversed (Hebrew points, Arabic harakat, general
/// combining diacriticals, variation selectors).
fn is_combining_mark(c: char) -> bool {
    matches!(
        c as u32,
        0x0300..=0x036F
            | 0x0483..=0x0489
            | 0x0591..=0x05BD
            | 0x05BF
            | 0x05C1..=0x05C2
            | 0x05C4..=0x05C5
            | 0x05C7
            | 0x0610..=0x061A
            | 0x064B..=0x065F
            | 0x0670
            | 0x06D6..=0x06DC
            | 0x06DF..=0x06E4
            | 0x06E7..=0x06E8
            | 0x06EA..=0x06ED
            | 0x0711
            | 0x0730..=0x074A
            | 0x07A6..=0x07B0
            | 0x07EB..=0x07F3
            | 0x0816..=0x082D
            | 0x08D3..=0x08FF
            | 0x200C..=0x200D
            | 0xFE00..=0xFE0F
    )
}

fn mirror_bracket(c: char) -> char {
    match c {
        '(' => ')',
        ')' => '(',
        '[' => ']',
        ']' => '[',
        '{' => '}',
        '}' => '{',
        '<' => '>',
        '>' => '<',
        '«' => '»',
        '»' => '«',
        '‹' => '›',
        '›' => '‹',
        other => other,
    }
}

/// Reverse a visual-order span into logical order: grapheme-wise (a
/// combining mark follows its base, a lam-alef ligature that one glyph
/// decoded to stays lam-then-alef), mirroring paired brackets.
fn reverse_visual(span: &str) -> String {
    let mut clusters: Vec<String> = Vec::new();
    for c in span.chars() {
        let lam_alef =
            matches!(c, 'ا' | 'أ' | 'إ' | 'آ') && clusters.last().is_some_and(|l| l == "ل");
        if (is_combining_mark(c) || lam_alef) && !clusters.is_empty() {
            clusters.last_mut().unwrap().push(c);
        } else {
            clusters.push(mirror_bracket(c).to_string());
        }
    }
    clusters.iter().rev().flat_map(|s| s.chars()).collect()
}

/// Put a line painted in visual order back into logical order.
///
/// Right-to-left text is drawn leftmost glyph first, so the extracted
/// characters come out reversed. When right-to-left letters outnumber
/// left-to-right letters the whole line is reversed (its punctuation
/// and digits were positioned for a right-to-left paragraph); in a
/// left-to-right line only the maximal spans of right-to-left letters,
/// with the neutrals between them, are reversed. Digit runs inside a
/// reversed span are flipped back so numbers keep their order.
pub fn reorder_bidi_line(line: &str) -> String {
    let rtl = line.chars().filter(|c| is_rtl_char(*c)).count();
    if rtl == 0 {
        return line.to_owned();
    }
    let ltr = line
        .chars()
        .filter(|c| c.is_alphabetic() && !is_rtl_char(*c) && !is_combining_mark(*c))
        .count();
    let restore_digits = |s: String| -> String {
        // Digits inside a reversed span were reversed too; flip each
        // maximal digit run back.
        let chars: Vec<char> = s.chars().collect();
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                let mut j = i;
                while j < chars.len()
                    && (chars[j].is_ascii_digit()
                        || (chars[j] == '.' || chars[j] == ',')
                            && j + 1 < chars.len()
                            && chars[j + 1].is_ascii_digit())
                {
                    j += 1;
                }
                out.extend(chars[i..j].iter().rev());
                i = j;
            } else {
                out.push(chars[i]);
                i += 1;
            }
        }
        out
    };
    if rtl > ltr {
        return restore_digits(reverse_visual(line));
    }
    // Mixed line: reverse each maximal RTL span (letters plus the
    // neutrals strictly between them).
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < chars.len() {
        if !is_rtl_char(chars[i]) {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        // Extend to the last RTL letter reachable through neutrals.
        let mut end = i + 1;
        let mut last_rtl = i;
        while end < chars.len() {
            let c = chars[end];
            if is_rtl_char(c) || is_combining_mark(c) {
                last_rtl = end;
            } else if c.is_alphabetic() {
                break;
            }
            end += 1;
        }
        let span: String = chars[i..=last_rtl].iter().collect();
        out.push_str(&restore_digits(reverse_visual(&span)));
        i = last_rtl + 1;
    }
    out
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
/// Concatenate the `/Contents` stream(s) of a page leaf into a single
/// byte buffer (an inter-stream separator is added so a stream that
/// ends without a trailing newline can't accidentally fuse the start
/// of the next stream's first operator into the end of its own last).
/// Returns `Ok(None)` when the page has no `/Contents` (a perfectly
/// valid blank page).
///
/// Exposed `pub` for sibling reader modules that need the same content
/// stream view (e.g. inline-image extraction) without rebuilding the
/// `/Resources /Font` walker the round-22 text extractor needs.
// Internal: shared content-stream plumbing for sibling reader modules (exposed for tests).
#[doc(hidden)]
pub fn concatenate_page_contents(
    reader: &mut DocumentReader<'_>,
    page_id: ObjectId,
) -> Result<Option<Vec<u8>>, PdfError> {
    let page_obj = reader.resolve(page_id)?;
    let Object::Dict(page_dict) = page_obj else {
        return Ok(None);
    };
    let contents_obj = page_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Contents")
        .map(|(_, v)| v.clone());
    let bytes = match contents_obj {
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
    Ok(Some(bytes))
}

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
    let mut visited: HashSet<u32> = HashSet::new();
    walk_pages_inner(reader, node_id, out, &mut visited, 0)
}

/// Bounded: a visited-set drops re-visited node ids (a malformed
/// `/Pages` tree can self-reference — `2 0 obj << /Kids [2 0 R] >>`
/// previously recursed to a stack overflow, caught by the round-418
/// parse fuzzer) and the depth is capped like the Scene-side walker.
fn walk_pages_inner(
    reader: &mut DocumentReader<'_>,
    node_id: ObjectId,
    out: &mut Vec<ObjectId>,
    visited: &mut HashSet<u32>,
    depth: u32,
) -> Result<(), PdfError> {
    if depth > 64 || !visited.insert(node_id.number) || out.len() > 100_000 {
        return Ok(());
    }
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
                    walk_pages_inner(reader, id, out, visited, depth + 1)?;
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

/// Per-font horizontal advance metrics (glyph-space thousandths),
/// used by the extraction walker to apply the §9.4.4 text-space
/// displacement and so report a distinct origin for each text run on a
/// line that lacks explicit `Td` / `Tm` repositioning.
///
/// Resolved by [`build_font_advance`] from the font dictionary at
/// page-load time (where the [`DocumentReader`] is available to
/// dereference indirect `/Widths` / `/W` arrays).
#[derive(Clone, Debug)]
enum FontAdvance {
    /// Simple font (one byte per code, §9.6): `widths[code − first]`,
    /// falling back to `missing` outside the array's range. `text_scale`
    /// converts a stored width into text-space units (§9.2.4): `0.001`
    /// for Type1 / TrueType, or the horizontal `/FontMatrix` component
    /// for a Type 3 font, whose `/Widths` are in glyph space (§9.6.5).
    Simple {
        first: i64,
        widths: Vec<f32>,
        missing: f32,
        text_scale: f32,
    },
    /// Composite font (§9.7.4.3) — see [`CidAdvance`].
    Cid(Box<CidAdvance>),
    /// A standard-14 face without `/Widths` (§9.6.2.2 lets a producer
    /// omit them): widths from the built-in AFM tables, looked up by
    /// the glyph's Unicode text under the font's encoding, or by code
    /// under the face's own built-in encoding when no `/Encoding`
    /// applies or the text is unknown to the table.
    Std14 {
        metrics: &'static crate::reader::std14_metrics::Std14Metrics,
        encoding: Option<Box<EncodingMap>>,
        missing: f32,
    },
    /// No resolvable widths — every glyph advances 0 (prior behaviour).
    None,
}

/// Composite-font advance metrics (§9.7.4.3): the `/DW` + `/W`
/// horizontal widths, the optional embedded-CMap code → CID mapping
/// (§9.7.5.3 — `None` means the Identity two-bytes-per-code
/// convention), and the vertical-writing metrics used when the CMap
/// selects `WMode` 1: `/DW2[1]` + the `w1y` components of `/W2`.
///
/// The §9.7.4.3 position vector `v` relates the horizontal and
/// vertical writing *origins of an individual glyph's rendering*; it
/// does not enter the §9.4.4 text-matrix update, so the extraction
/// walker (which reports accumulated run origins) parses past it.
#[derive(Clone, Debug)]
struct CidAdvance {
    /// `/DW` (default 1000).
    default: f32,
    /// `/W` runs — `(start_cid, per-CID widths)`.
    ranges: Vec<(i64, Vec<f32>)>,
    /// Embedded `/Encoding` CMap (§9.7.5.3), when present.
    cmap: Option<Box<CidCMap>>,
    /// Writing mode: 0 horizontal, 1 vertical (§9.7.5 `WMode` — from
    /// the `Identity-V` name or the embedded CMap's `/WMode`).
    wmode: u8,
    /// `/DW2[1]` — default vertical displacement `w1y` (default
    /// −1000 per Table 117).
    v_default: f32,
    /// `/W2` runs — `(start_cid, per-CID w1y)`.
    v_ranges: Vec<(i64, Vec<f32>)>,
}

impl CidAdvance {
    /// Vertical displacement `w1y` for `cid` (§9.7.4.3 `/W2`, falling
    /// back to `/DW2[1]`).
    fn vertical(&self, cid: i64) -> f32 {
        for (start, run) in &self.v_ranges {
            let off = cid - start;
            if off >= 0 && (off as usize) < run.len() {
                return run[off as usize];
            }
        }
        self.v_default
    }
}

impl FontAdvance {
    fn width(&self, code: i64) -> f32 {
        match self {
            FontAdvance::Simple {
                first,
                widths,
                missing,
                ..
            } => {
                let idx = code - first;
                if idx >= 0 && (idx as usize) < widths.len() {
                    widths[idx as usize]
                } else {
                    *missing
                }
            }
            FontAdvance::Cid(cid) => {
                for (start, run) in &cid.ranges {
                    let off = code - start;
                    if off >= 0 && (off as usize) < run.len() {
                        return run[off as usize];
                    }
                }
                cid.default
            }
            FontAdvance::Std14 {
                metrics,
                encoding,
                missing,
            } => {
                let Ok(code) = u8::try_from(code) else {
                    return *missing;
                };
                let by_text = encoding.as_ref().and_then(|enc| {
                    let t = enc.lookup(code);
                    (!t.is_empty())
                        .then(|| metrics.width_by_unicode(t))
                        .flatten()
                });
                by_text
                    .or_else(|| metrics.width_by_code(code))
                    .map(f32::from)
                    .unwrap_or(*missing)
            }
            FontAdvance::None => 0.0,
        }
    }

    /// True when this font advances vertically (§9.4.4 `ty` path).
    fn is_vertical(&self) -> bool {
        matches!(self, FontAdvance::Cid(cid) if cid.wmode == 1)
    }

    /// Factor converting a [`Self::width`] result into text-space units
    /// (§9.2.4). Type1 / TrueType and composite fonts use `0.001`; a
    /// Type 3 font carries its `/FontMatrix` horizontal scale, since its
    /// widths are in glyph space (§9.6.5).
    fn text_scale(&self) -> f32 {
        match self {
            FontAdvance::Simple { text_scale, .. } => *text_scale,
            _ => 0.001,
        }
    }
}

/// Read a font dictionary's horizontal advance metrics into a
/// [`FontAdvance`] (§9.6.2.1 simple `/Widths`; §9.7.4.3 composite
/// `/W` + `/DW`). Indirect `/Widths`, `/FontDescriptor`,
/// `/DescendantFonts` and `/W` references are dereferenced through
/// `reader`.
fn build_font_advance(reader: &mut DocumentReader<'_>, font: &Dict) -> FontAdvance {
    let subtype = font
        .entries()
        .iter()
        .find_map(|(k, v)| match (k.as_str(), v) {
            ("Subtype", Object::Name(s)) => Some(s.as_str()),
            _ => None,
        });
    if subtype == Some("Type0") {
        return build_cid_advance(reader, font);
    }
    let first = font
        .entries()
        .iter()
        .find(|(k, _)| k == "FirstChar")
        .and_then(|(_, v)| obj_as_i64(v))
        .unwrap_or(0);
    let widths_obj = font
        .entries()
        .iter()
        .find(|(k, _)| k == "Widths")
        .map(|(_, v)| v.clone());
    let widths_obj = match widths_obj {
        Some(Object::Reference(id)) => reader.resolve(id).ok(),
        other => other,
    };
    let widths: Vec<f32> = match widths_obj {
        Some(Object::Array(items)) => items.iter().map(|o| obj_as_f32(o).unwrap_or(0.0)).collect(),
        _ => Vec::new(),
    };
    // /MissingWidth lives in the /FontDescriptor (§9.8.1 Table 122).
    let descr = font
        .entries()
        .iter()
        .find(|(k, _)| k == "FontDescriptor")
        .map(|(_, v)| v.clone());
    let descr = match descr {
        Some(Object::Reference(id)) => reader.resolve(id).ok(),
        other => other,
    };
    let missing = match descr {
        Some(Object::Dict(d)) => d
            .entries()
            .iter()
            .find(|(k, _)| k == "MissingWidth")
            .and_then(|(_, v)| obj_as_f32(v))
            .unwrap_or(0.0),
        _ => 0.0,
    };
    if widths.is_empty() {
        // §9.6.2.2: the standard 14 fonts may omit /Widths — take the
        // AFM metrics, keyed through whatever encoding the dict sets.
        let base_font = font
            .entries()
            .iter()
            .find_map(|(k, v)| match (k.as_str(), v) {
                ("BaseFont", Object::Name(s)) => Some(s.as_str()),
                _ => None,
            });
        if let Some(metrics) = base_font.and_then(crate::reader::std14_metrics::resolve) {
            let encoding = match FontDecoder::simple_from_encoding(
                reader,
                font,
                subtype.unwrap_or("Type1"),
                None,
            ) {
                Ok(FontDecoder::SimpleMap(m)) => Some(m),
                _ => None,
            };
            return FontAdvance::Std14 {
                metrics,
                encoding,
                missing,
            };
        }
        return FontAdvance::None;
    }
    // §9.6.5: a Type 3 font's /Widths are in glyph space and scaled to
    // text space by the /FontMatrix horizontal component. Type1 /
    // TrueType widths are already in thousandths of text space.
    let text_scale = if subtype == Some("Type3") {
        font.entries()
            .iter()
            .find(|(k, _)| k == "FontMatrix")
            .and_then(|(_, v)| match v {
                Object::Array(items) if items.len() == 6 => obj_as_f32(&items[0]),
                _ => None,
            })
            .filter(|s| s.is_finite())
            .unwrap_or(0.001)
    } else {
        0.001
    };
    FontAdvance::Simple {
        first,
        widths,
        missing,
        text_scale,
    }
}

/// Resolve a Type0 font's descendant CIDFont advance metrics
/// (§9.7.4.3): `/DW` default + `/W` per-CID runs.
fn build_cid_advance(reader: &mut DocumentReader<'_>, font: &Dict) -> FontAdvance {
    // §9.7.5.3 — an /Encoding that is an embedded CMap stream drives
    // both code segmentation and the code → CID mapping ahead of the
    // /W width lookup. A Name (Identity-H / Identity-V, or a
    // predefined CMap this crate has no data tables for) leaves the
    // Identity two-bytes-per-code behaviour. The writing mode
    // (§9.7.5 WMode) comes from the Identity-V name or the embedded
    // CMap's /WMode and selects the §9.4.4 ty displacement path.
    let enc_obj = font
        .entries()
        .iter()
        .find(|(k, _)| k == "Encoding")
        .map(|(_, v)| v.clone());
    let mut wmode = 0u8;
    let mut cmap: Option<Box<CidCMap>> = None;
    match enc_obj {
        Some(Object::Name(name)) if name == "Identity-V" => wmode = 1,
        Some(Object::Name(_)) => {}
        Some(obj) => {
            if let Ok(Object::Stream(stream)) = reader.deref(obj)
                && let Ok(cm) = CidCMap::from_stream(reader, &stream, 0)
            {
                wmode = cm.wmode;
                cmap = Some(Box::new(cm));
            }
        }
        None => {}
    }
    let desc_obj = font
        .entries()
        .iter()
        .find(|(k, _)| k == "DescendantFonts")
        .map(|(_, v)| v.clone());
    let desc_obj = match desc_obj {
        Some(Object::Reference(id)) => reader.resolve(id).ok(),
        other => other,
    };
    // Pull the sole CIDFont dict out of the (usually one-element) array.
    let cid_obj = match desc_obj {
        Some(Object::Array(items)) => items.into_iter().next(),
        Some(Object::Dict(d)) => Some(Object::Dict(d)),
        _ => None,
    };
    let cid_obj = match cid_obj {
        Some(Object::Reference(id)) => reader.resolve(id).ok(),
        other => other,
    };
    let Some(Object::Dict(cid_font)) = cid_obj else {
        return FontAdvance::Cid(Box::new(CidAdvance {
            default: 1000.0,
            ranges: Vec::new(),
            cmap,
            wmode,
            v_default: -1000.0,
            v_ranges: Vec::new(),
        }));
    };
    let default = cid_font
        .entries()
        .iter()
        .find(|(k, _)| k == "DW")
        .and_then(|(_, v)| obj_as_f32(v))
        .unwrap_or(1000.0);
    let w_obj = cid_font
        .entries()
        .iter()
        .find(|(k, _)| k == "W")
        .map(|(_, v)| v.clone());
    let w_obj = match w_obj {
        Some(Object::Reference(id)) => reader.resolve(id).ok(),
        other => other,
    };
    let ranges = match w_obj {
        Some(Object::Array(items)) => parse_w_array(&items),
        _ => Vec::new(),
    };
    // §9.7.4.3 vertical metrics: /DW2 [v_y w1y] (default [880 −1000])
    // and /W2. Only the displacement components enter the §9.4.4
    // text-matrix update; position vectors are parsed past.
    let v_default = cid_font
        .entries()
        .iter()
        .find(|(k, _)| k == "DW2")
        .and_then(|(_, v)| match v {
            Object::Array(items) if items.len() == 2 => obj_as_f32(&items[1]),
            _ => None,
        })
        .unwrap_or(-1000.0);
    let w2_obj = cid_font
        .entries()
        .iter()
        .find(|(k, _)| k == "W2")
        .map(|(_, v)| v.clone());
    let w2_obj = match w2_obj {
        Some(Object::Reference(id)) => reader.resolve(id).ok(),
        other => other,
    };
    let v_ranges = match w2_obj {
        Some(Object::Array(items)) => parse_w2_array(&items),
        _ => Vec::new(),
    };
    FontAdvance::Cid(Box::new(CidAdvance {
        default,
        ranges,
        cmap,
        wmode,
        v_default,
        v_ranges,
    }))
}

/// Parse a CIDFont `/W2` array (§9.7.4.3) into `(start_cid, w1y)`
/// runs. Groups are `c [w1y v1x v1y …]` (numbers in threes — only
/// the displacement component is kept) or
/// `cfirst clast w1y v1x v1y`.
fn parse_w2_array(items: &[Object]) -> Vec<(i64, Vec<f32>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < items.len() {
        let Some(c) = obj_as_i64(&items[i]) else {
            i += 1;
            continue;
        };
        match items.get(i + 1) {
            Some(Object::Array(triples)) => {
                let run: Vec<f32> = triples
                    .chunks(3)
                    .filter_map(|g| g.first().and_then(obj_as_f32))
                    .collect();
                out.push((c, run));
                i += 2;
            }
            Some(obj) => {
                let clast = obj_as_i64(obj);
                let w1y = items.get(i + 2).and_then(obj_as_f32);
                // Positions i+3 / i+4 hold v1x / v1y — skipped.
                match (clast, w1y) {
                    (Some(clast), Some(w1y)) if clast >= c => {
                        let count = (clast - c + 1).min(1 << 20) as usize;
                        out.push((c, vec![w1y; count]));
                        i += 5;
                    }
                    _ => i += 1,
                }
            }
            None => break,
        }
    }
    out
}

/// Parse a CIDFont `/W` array (§9.7.4.3) into `(start_cid, widths)`
/// runs. Groups are `c [w1 … wn]` or `cfirst clast w`.
fn parse_w_array(items: &[Object]) -> Vec<(i64, Vec<f32>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < items.len() {
        let Some(c) = obj_as_i64(&items[i]) else {
            i += 1;
            continue;
        };
        match items.get(i + 1) {
            Some(Object::Array(ws)) => {
                let run: Vec<f32> = ws.iter().map(|o| obj_as_f32(o).unwrap_or(0.0)).collect();
                out.push((c, run));
                i += 2;
            }
            Some(obj) => {
                let clast = obj_as_i64(obj);
                let w = items.get(i + 2).and_then(obj_as_f32);
                match (clast, w) {
                    (Some(clast), Some(w)) if clast >= c => {
                        let count = (clast - c + 1).min(1 << 20) as usize;
                        out.push((c, vec![w; count]));
                        i += 3;
                    }
                    _ => i += 1,
                }
            }
            None => break,
        }
    }
    out
}

fn obj_as_f32(o: &Object) -> Option<f32> {
    match o {
        Object::Integer(i) => Some(*i as f32),
        Object::Real(r) => Some(*r as f32),
        _ => None,
    }
}

fn obj_as_i64(o: &Object) -> Option<i64> {
    match o {
        Object::Integer(i) => Some(*i),
        Object::Real(r) => Some(*r as i64),
        _ => None,
    }
}

/// Resolve a page leaf into the pieces the text walker needs:
/// per-font byte→Unicode decoders + the concatenated content stream.
/// Returns `None` when the page has no `/Contents` (a perfectly valid
/// blank page — emit nothing).
type PageAdvances = HashMap<String, FontAdvance>;

fn load_page_for_text(
    reader: &mut DocumentReader<'_>,
    page_id: ObjectId,
) -> Result<Option<(PageFonts, PageAdvances, Vec<u8>)>, PdfError> {
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
    let mut advances: HashMap<String, FontAdvance> = HashMap::new();
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
                        let advance = build_font_advance(reader, &font_d);
                        advances.insert(name.clone(), advance);
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

    Ok(Some((fonts, advances, content_bytes)))
}

fn extract_page(
    reader: &mut DocumentReader<'_>,
    page_id: ObjectId,
    out: &mut PdfTextExtraction,
) -> Result<(), PdfError> {
    let Some((fonts, advances, content_bytes)) = load_page_for_text(reader, page_id)? else {
        return Ok(());
    };
    let mut walker = TextWalker::new(fonts, advances);
    // A malformed page keeps the runs it produced up to the fault;
    // the rest of the document still extracts.
    let _ = walker.parse(&content_bytes);
    out.runs.extend(walker.into_runs());
    Ok(())
}

fn extract_page_marked(
    reader: &mut DocumentReader<'_>,
    page_id: ObjectId,
    page_index: u32,
    out: &mut PdfMarkedTextExtraction,
) -> Result<(), PdfError> {
    let Some((fonts, advances, content_bytes)) = load_page_for_text(reader, page_id)? else {
        return Ok(());
    };
    let mut walker = TextWalker::new(fonts, advances);
    walker.track_mcid = true;
    let _ = walker.parse(&content_bytes);
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
    /// Type 0 font whose `/Encoding` is an **embedded CMap stream**
    /// (§9.7.5.3) and which carries no `/ToUnicode`. The code → CID
    /// mapping is known, but a CID indexes a glyph collection, not a
    /// character — there is no Unicode source — so each shown code
    /// emits U+FFFD as an explicit lossy marker while segmentation
    /// (and therefore glyph counts and §9.4.4 advances) follows the
    /// CMap's codespace widths. Supply a `/ToUnicode` CMap for real
    /// text recovery (§9.10.2's first method).
    CidEncoding { cmap: Box<CidCMap> },
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
    /// Simple font (Type1 / TrueType / Type3) with a `/ToUnicode`
    /// CMap. A simple font's codes are single bytes whatever the
    /// CMap's `codespacerange` claims (InDesign writes `<0000>
    /// <FFFF>` over one-byte `bfchar` sources), so every byte is
    /// looked up on its own; a byte the CMap leaves out falls back to
    /// the font's encoding (§9.10.2's second method) rather than
    /// U+FFFD.
    SimpleToUnicode {
        map: CMap,
        fallback: Option<Box<EncodingMap>>,
    },
    /// No discernible encoding — fall back to Latin-1 byte → code
    /// point (identity for ASCII; reasonable for CP1252 punctuation).
    Latin1,
}

impl FontDecoder {
    fn from_dict(reader: &mut DocumentReader<'_>, font: &Dict) -> Result<FontDecoder, PdfError> {
        let subtype = font
            .entries()
            .iter()
            .find(|(k, _)| k == "Subtype")
            .and_then(|(_, v)| match v {
                Object::Name(s) => Some(s.as_str()),
                _ => None,
            })
            .unwrap_or("");
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
                if subtype == "Type0" {
                    return Ok(FontDecoder::ToUnicode { map, cid_width });
                }
                let builtin = embedded_type1_encoding(reader, font);
                let fallback = match Self::simple_from_encoding(reader, font, subtype, builtin)? {
                    FontDecoder::SimpleMap(m) => Some(m),
                    _ => None,
                };
                return Ok(FontDecoder::SimpleToUnicode { map, fallback });
            }
        }

        // 2. Composite font (Type0) without /ToUnicode — Identity-H/V.
        if subtype == "Type0" {
            // /Encoding is one of (§9.7.6.1 Table 121): the
            // Identity-H / Identity-V predefined names, another
            // predefined CMap name, or an embedded CMap stream
            // (§9.7.5.3).
            let enc = font
                .entries()
                .iter()
                .find(|(k, _)| k == "Encoding")
                .map(|(_, v)| v.clone());
            match enc {
                Some(Object::Name(_)) => {
                    // Identity-H / Identity-V decode as CID = code.
                    // The other predefined CMap names index Adobe
                    // character collections whose data tables ISO
                    // 32000 does not carry — Identity is the safest
                    // in-spec fallback for those too.
                    return Ok(FontDecoder::IdentityNoCMap);
                }
                Some(obj) => {
                    if let Ok(Object::Stream(stream)) = reader.deref(obj)
                        && let Ok(cmap) = CidCMap::from_stream(reader, &stream, 0)
                    {
                        return Ok(FontDecoder::CidEncoding {
                            cmap: Box::new(cmap),
                        });
                    }
                    return Ok(FontDecoder::IdentityNoCMap);
                }
                None => return Ok(FontDecoder::IdentityNoCMap),
            }
        }
        let builtin = embedded_type1_encoding(reader, font);
        Self::simple_from_encoding(reader, font, subtype, builtin)
    }

    /// The simple-font decoder from `/Encoding` (§9.6.6) over the
    /// font's built-in encoding: `embedded` is the one read out of an
    /// embedded Type 1 program when there is one.
    fn simple_from_encoding(
        reader: &mut DocumentReader<'_>,
        font: &Dict,
        subtype: &str,
        embedded: Option<EncodingMap>,
    ) -> Result<FontDecoder, PdfError> {
        // The built-in encoding of a standard-14 Symbol / ZapfDingbats
        // face is its own set (Annex D.5 / D.6), not StandardEncoding;
        // it is the base when no /Encoding or no /BaseEncoding says
        // otherwise.
        let builtin = font
            .entries()
            .iter()
            .find_map(|(k, v)| match (k.as_str(), v) {
                ("BaseFont", Object::Name(s)) => crate::reader::std14_metrics::resolve(s),
                _ => None,
            })
            .filter(|m| m.is_symbolic())
            .map(|m| {
                if m.name == "Symbol" {
                    BaseEncoding::Symbol
                } else {
                    BaseEncoding::ZapfDingbats
                }
            });
        // 3. Simple font with named /Encoding. The entry is often an
        // indirect reference to the encoding dict (pdfTeX, Ghostscript).
        let enc = font
            .entries()
            .iter()
            .find(|(k, _)| k == "Encoding")
            .map(|(_, v)| v.clone());
        let enc = match enc {
            Some(Object::Reference(id)) => reader.resolve(id).ok(),
            other => other,
        };
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
                None => match embedded {
                    // §9.6.6.1: without /BaseEncoding the differences
                    // apply over the font's built-in encoding.
                    Some(m) => m,
                    None => {
                        // The built-in encoding when it is a known
                        // one, else a sensible default per subtype.
                        let default = builtin.unwrap_or(match subtype {
                            "TrueType" => BaseEncoding::WinAnsi,
                            _ => BaseEncoding::Standard,
                        });
                        EncodingMap::from_base(default)
                    }
                },
            };
            // Overlay /Differences if present.
            let diffs_obj = enc_d
                .entries()
                .iter()
                .find(|(k, _)| k == "Differences")
                .map(|(_, v)| v.clone());
            let diffs_obj = match diffs_obj {
                Some(Object::Reference(id)) => reader.resolve(id).ok(),
                other => other,
            };
            let final_map = match diffs_obj {
                Some(arr @ Object::Array(_)) => {
                    let diffs = parse_encoding_differences(&arr)?;
                    apply_encoding_differences(&base_map, &diffs)
                }
                _ => base_map,
            };
            return Ok(FontDecoder::SimpleMap(Box::new(final_map)));
        }
        // Default for Type1 / Type3 with no /Encoding is the font's
        // built-in encoding — StandardEncoding for the Latin faces
        // (§9.6.6.1). TrueType with no /Encoding is
        // implementation-dependent — use WinAnsi.
        if let Some(m) = embedded {
            return Ok(FontDecoder::SimpleMap(Box::new(m)));
        }
        if let Some(b) = builtin {
            return Ok(FontDecoder::SimpleMap(Box::new(EncodingMap::from_base(b))));
        }
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
                // When the CMap declared `codespacerange` entries, walk
                // bytes left-to-right per Adobe Tech Note #5411 §2 +
                // Tech Note #5014 §3.1: at each position, try each
                // codespace in declaration order and pick the first
                // whose `lo..=hi` byte-component bounds cover the
                // candidate input prefix. Unmatched input advances by
                // one byte and emits U+FFFD. This is what makes
                // mixed-width CMaps (1-byte ASCII passthrough alongside
                // a 2-byte CJK territory) decode correctly.
                if !map.codespaces.is_empty() {
                    // An invalid code (§9.7.6.3) consumes the length
                    // of the shortest codespace its first byte
                    // partially matches; producers write `<0002>
                    // <3a2f>` meaning the linear CID range, which the
                    // byte-wise rule rejects for most codes, and this
                    // rule still steps them two bytes at a time. With
                    // no partial match either, a CMap whose codespaces
                    // all share one width still steps by that width
                    // (a ToUnicode codespace only has to settle the
                    // code length).
                    let uniform = map.uniform_codespace_width();
                    let mut i = 0;
                    while i < bytes.len() {
                        let matched = map
                            .match_codespace_width(&bytes[i..])
                            .or_else(|| map.partial_match_width(bytes[i]))
                            .or(uniform)
                            .filter(|w| i + w <= bytes.len());
                        if let Some(w) = matched {
                            let cid = bytes_to_u32(&bytes[i..i + w]);
                            if let Some(s) = map.lookup(cid) {
                                out.push_str(s);
                            } else {
                                out.push('\u{FFFD}');
                            }
                            i += w;
                        } else {
                            // No codespace covered this position. Adobe
                            // Tech Note #5411 §2 says the decoder
                            // should emit U+FFFD for the unmatched
                            // prefix and resume scanning; we resume at
                            // the next byte (the conservative choice
                            // that doesn't drop subsequent in-codespace
                            // input).
                            out.push('\u{FFFD}');
                            i += 1;
                        }
                    }
                    return out;
                }
                // No codespacerange declared — fall back to the legacy
                // single-width decode using the width inferred from the
                // first bfchar / bfrange source operand. Handles hand-
                // crafted CMaps that omit the §9.10.3 mandatory header.
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
            FontDecoder::CidEncoding { cmap } => {
                // Correct segmentation, no Unicode source: one
                // U+FFFD marker per §9.7.6.2-extracted code.
                let mut out = String::new();
                let mut i = 0;
                while i < bytes.len() {
                    let (consumed, _code) = cmap.next_code(&bytes[i..]);
                    out.push('\u{FFFD}');
                    i += consumed.max(1);
                }
                out
            }
            FontDecoder::SimpleMap(map) => map.decode(bytes),
            FontDecoder::SimpleToUnicode { map, fallback } => {
                let mut out = String::new();
                for &b in bytes {
                    if let Some(s) = map.lookup(b as u32) {
                        out.push_str(s);
                    } else if let Some(enc) = fallback {
                        let s = enc.lookup(b);
                        if s.is_empty() {
                            out.push(b as char);
                        } else {
                            out.push_str(s);
                        }
                    } else {
                        out.push(b as char);
                    }
                }
                out
            }
            FontDecoder::Latin1 => bytes.iter().map(|&b| b as char).collect(),
        }
    }
}

// ────────────────────────── embedded Type 1 encoding ──────────────────────────

/// The built-in encoding of an embedded Type 1 font program
/// (`/FontFile`, §9.9 Table 126): the `/Encoding` entry of the
/// cleartext portion — either `StandardEncoding` or an array filled
/// by `dup <code> /<glyph> put` lines. `None` when the font is not an
/// embedded Type 1 or its program carries no readable encoding.
fn embedded_type1_encoding(reader: &mut DocumentReader<'_>, font: &Dict) -> Option<EncodingMap> {
    let descr = font
        .entries()
        .iter()
        .find(|(k, _)| k == "FontDescriptor")
        .map(|(_, v)| v.clone())?;
    let Ok(Object::Dict(descr)) = reader.deref(descr) else {
        return None;
    };
    let file = descr
        .entries()
        .iter()
        .find(|(k, _)| k == "FontFile")
        .map(|(_, v)| v.clone())?;
    let Ok(Object::Stream(stream)) = reader.deref(file) else {
        return None;
    };
    let bytes = decode_stream(&stream).ok()?;
    parse_type1_cleartext_encoding(&bytes)
}

/// Parse the `/Encoding` of a Type 1 program's cleartext (everything
/// before `eexec`): `StandardEncoding`, or `256 array` followed by
/// one `dup <code> /<name> put` per assigned slot up to the closing
/// `readonly def` / `def`.
fn parse_type1_cleartext_encoding(program: &[u8]) -> Option<EncodingMap> {
    let clear_end = find_bytes(program, b"eexec").unwrap_or(program.len());
    let clear = &program[..clear_end];
    let enc_at = find_bytes(clear, b"/Encoding")?;
    let after = &clear[enc_at + "/Encoding".len()..];
    let mut i = 0;
    while i < after.len() && is_ws(after[i]) {
        i += 1;
    }
    if after[i..].starts_with(b"StandardEncoding") {
        return Some(EncodingMap::from_base(BaseEncoding::Standard));
    }
    let mut map = EncodingMap::new();
    let mut any = false;
    let mut pos = i;
    while pos < after.len() {
        // Next token.
        while pos < after.len() && is_ws(after[pos]) {
            pos += 1;
        }
        let start = pos;
        while pos < after.len() && !is_ws(after[pos]) {
            pos += 1;
        }
        let tok = &after[start..pos];
        if tok.is_empty() {
            break;
        }
        if tok == b"dup" {
            while pos < after.len() && is_ws(after[pos]) {
                pos += 1;
            }
            let num_start = pos;
            while pos < after.len() && after[pos].is_ascii_digit() {
                pos += 1;
            }
            let code = str::from_utf8(&after[num_start..pos])
                .ok()
                .and_then(|s| s.parse::<u32>().ok());
            while pos < after.len() && is_ws(after[pos]) {
                pos += 1;
            }
            if pos < after.len() && after[pos] == b'/' {
                let name_start = pos + 1;
                let mut k = name_start;
                while k < after.len() && !is_ws(after[k]) && !is_delim(after[k]) {
                    k += 1;
                }
                if let (Some(code), Ok(name)) = (code, str::from_utf8(&after[name_start..k]))
                    && code < 256
                    && let Some(text) = crate::reader::encoding::glyph_name_to_unicode(name)
                {
                    map.set_string(code as u8, text.as_ref());
                    any = true;
                }
                pos = k;
            }
        } else if (tok == b"def" || tok == b"readonly") && any {
            break;
        }
    }
    any.then_some(map)
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

// ────────────────────────── CMap parser ──────────────────────────

/// One `<lo> <hi>` pair declared inside a `begincodespacerange` /
/// `endcodespacerange` block. The codespace's byte width is the length
/// of `lo` (and `hi`), and `lo` / `hi` carry the inclusive bounds of
/// the in-codespace input byte sequences for that width.
///
/// Adobe Tech Note #5411 ("ToUnicode CMap File Tutorial") §2 + Adobe
/// Tech Note #5014 §3.1 spell out the per-byte hierarchical match: a
/// codespace `<8140>..<FCFC>` accepts the 2-byte input `8175` if and
/// only if **each byte** falls inside the corresponding `lo[i]..hi[i]`
/// slot — *not* the linear u32 interval `bytes_to_u32(lo)..bytes_to_u32(hi)`.
/// (That hierarchical rule is what lets a CJK CMap declare
/// `<00> <80>` for ASCII passthrough and `<8140> <FCFC>` for the
/// Shift-JIS-shaped two-byte territory without the two-byte range
/// implicitly covering `<8181>..<8189>` etc. that the linear u32
/// interval would imply.)
#[derive(Clone, Debug)]
pub(crate) struct CodespaceRange {
    pub lo: Vec<u8>,
    pub hi: Vec<u8>,
}

impl CodespaceRange {
    pub(crate) fn width(&self) -> usize {
        self.lo.len()
    }

    /// True iff `bytes[..self.width()]` is component-wise inside
    /// `lo..=hi` per Adobe Tech Note #5014 §3.1.
    pub(crate) fn matches(&self, bytes: &[u8]) -> bool {
        let w = self.width();
        if bytes.len() < w {
            return false;
        }
        bytes[..w]
            .iter()
            .zip(self.lo.iter().zip(self.hi.iter()))
            .all(|(b, (lo, hi))| b >= lo && b <= hi)
    }
}

/// A parsed `/ToUnicode` CMap (ISO 32000-1 §9.10.3 + Adobe Tech Note
/// #5411 "ToUnicode CMap File Tutorial" + Adobe Tech Note #5014
/// "CMap & CIDFont Files Specification"). The parser covers the slice
/// the spec mandates for text-extraction CMaps:
///
/// * `begincodespacerange ... endcodespacerange` — the per-width input
///   byte territory the CMap is defined over. Mixed widths (e.g. a
///   1-byte ASCII passthrough alongside a 2-byte CJK territory) are
///   captured per range, not collapsed to a single global width.
/// * `beginbfchar ... endbfchar` — explicit `<src> -> <dst>` Unicode
///   mappings.
/// * `beginbfrange ... endbfrange` — `<lo> <hi> <dst>` (scalar) /
///   `<lo> <hi> [<dst0> <dst1> …]` (per-source array) Unicode
///   mappings.
#[derive(Clone, Debug, Default)]
pub(crate) struct CMap {
    /// CID (interpreted as u32) → UTF-8 string. Multi-character target
    /// strings (ligatures, combining marks) are common — `<FB01>` for
    /// `fi` is the canonical example.
    table: HashMap<u32, String>,
    /// Inferred from the first bfchar/bfrange source operand. 1 for
    /// simple fonts (rare — usually accompanied by a tiny WinAnsi-ish
    /// table), 2 for the standard CIDFont case. Used as the fallback
    /// width when no `codespacerange` block was declared (legacy / hand-
    /// crafted CMaps that omit the §9.10.3 mandatory header).
    pub(crate) byte_width: u8,
    /// Declared `codespacerange` entries, in declaration order. When
    /// non-empty, the decoder walks input bytes left-to-right, trying
    /// each codespace's width in declaration order at every position
    /// and selecting the first whose `lo..=hi` byte-component bounds
    /// cover the candidate input prefix. This is what makes mixed-width
    /// CMaps (the Adobe-Japan1 / Adobe-GB1 family) decode correctly —
    /// a 1-byte ASCII range and a 2-byte CJK range coexist in the same
    /// CMap and the per-codespace width selection picks the right one
    /// per input byte position.
    pub(crate) codespaces: Vec<CodespaceRange>,
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
            if let Some(rest) = peek_keyword(bytes, i, b"begincodespacerange") {
                i = rest;
                i = parse_codespacerange(bytes, i, &mut cm)?;
                continue;
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
            // `CIDSystemInfo`, etc.) and any non-bf / non-codespace
            // blocks (`cidchar`, `cidrange`, `notdefchar`, `notdefrange`,
            // …) are ignored: only the bf / codespace surface is
            // load-bearing for Unicode extraction.
            i = skip_token(bytes, i);
        }
        Ok(cm)
    }

    fn lookup(&self, cid: u32) -> Option<&str> {
        self.table.get(&cid).map(|s| s.as_str())
    }

    /// Find the codespace whose width-prefix of `bytes` matches per the
    /// Adobe Tech Note #5014 §3.1 byte-component rule, returning the
    /// matched width (1..=4). `None` when no codespace matches at this
    /// position. Codespaces are walked in declaration order so a CMap
    /// that lists `<00><7F>` (1 byte) before `<8140><FCFC>` (2 bytes)
    /// picks 1 byte for `0x41` and 2 bytes for `0x81 0x40`, matching
    /// what the §9.10.3 decoder is required to do.
    /// §9.7.6.3: the length of the shortest codespace whose first-byte
    /// bounds admit `first` — how many bytes an invalid code starting
    /// with that byte consumes.
    fn partial_match_width(&self, first: u8) -> Option<usize> {
        self.codespaces
            .iter()
            .filter(|cs| !cs.lo.is_empty() && cs.lo[0] <= first && first <= cs.hi[0])
            .map(CodespaceRange::width)
            .min()
    }

    /// The single byte width every declared codespace shares, if so.
    fn uniform_codespace_width(&self) -> Option<usize> {
        let w = self.codespaces.first()?.width();
        self.codespaces
            .iter()
            .all(|cs| cs.width() == w)
            .then_some(w)
    }

    fn match_codespace_width(&self, bytes: &[u8]) -> Option<usize> {
        for cs in &self.codespaces {
            if cs.matches(bytes) {
                return Some(cs.width());
            }
        }
        None
    }
}

fn parse_codespacerange(bytes: &[u8], mut i: usize, cm: &mut CMap) -> Result<usize, PdfError> {
    loop {
        i = skip_ws_and_comments(bytes, i);
        if i >= bytes.len() {
            return Err(PdfError::other(
                "PDF CMap: unterminated begincodespacerange block",
            ));
        }
        if let Some(rest) = peek_keyword(bytes, i, b"endcodespacerange") {
            return Ok(rest);
        }
        // One codespace entry: `<lo> <hi>`. Both hex strings must share
        // the same byte width (the codespace width) per Adobe Tech Note
        // #5014 §3.1 / Tech Note #5411 §2. A `lo`/`hi` pair whose
        // widths diverge is ill-formed; we skip it tolerantly so a
        // malformed CMap doesn't deny the rest of the document.
        let (lo, after_lo) = read_hex_string_payload(bytes, i)?;
        i = after_lo;
        i = skip_ws_and_comments(bytes, i);
        let (hi, after_hi) = read_hex_string_payload(bytes, i)?;
        i = after_hi;
        if lo.is_empty() || hi.is_empty() || lo.len() != hi.len() {
            continue;
        }
        // Cap width at 4 (the Adobe Tech Note #5014 §3.1 ceiling: PS
        // CMaps allow 1..=4 byte codespaces). Anything wider is an
        // out-of-spec CMap; ignore the entry rather than risk an
        // unbounded width that the decoder can't handle anyway.
        if lo.len() > 4 {
            continue;
        }
        cm.codespaces.push(CodespaceRange { lo, hi });
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
        // Capture byte_width from the first src — only used as a
        // fallback when no codespacerange block was declared.
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
            // Number of source codes the range covers. A well-formed
            // `/ToUnicode` bfrange varies only the low-order byte of the
            // source codespace (Adobe Tech Note #5411 §2 + ISO 32000-1
            // §9.10.3), so a legitimate range is at most 256 codes; a
            // hostile CMap can instead declare `<0000> <FFFFFFFF>`, whose
            // 2^32-iteration expansion is a denial-of-service (each
            // iteration is cheap and `char::from_u32` rejects most values,
            // so it spins CPU-bound without growing memory). Cap the span
            // at a generous ceiling that still covers any realistic
            // multi-byte range; the tail of an over-long range is dropped
            // rather than expanded (tolerant degradation — the rest of the
            // document still extracts). `saturating_add` also avoids the
            // `+1` overflow when `hi == u32::MAX`.
            const MAX_BFRANGE_SPAN: u32 = 0x1_0000;
            let count = hi
                .saturating_sub(lo)
                .saturating_add(1)
                .min(MAX_BFRANGE_SPAN);
            // Decompose the dst string into chars; for the
            // single-char-target case (the common one), iterate chars.
            if dst_str.chars().count() == 1 {
                let base = dst_str.chars().next().unwrap() as u32;
                for k in 0..count {
                    let cid = lo.saturating_add(k);
                    if let Some(c) = char::from_u32(base.saturating_add(k)) {
                        cm.table.insert(cid, String::from(c));
                    }
                }
            } else {
                // Multi-char dst (ligature etc.) — only the first source
                // gets the explicit string; the rest get the
                // last-char-incremented form.
                let mut chars: Vec<char> = dst_str.chars().collect();
                for k in 0..count {
                    let cid = lo.saturating_add(k);
                    cm.table.insert(cid, chars.iter().collect::<String>());
                    if let Some(last) = chars.last_mut()
                        && let Some(next) = char::from_u32(*last as u32 + 1)
                    {
                        *last = next;
                    }
                }
            }
        }
    }
}

pub(crate) fn read_hex_string_payload(
    bytes: &[u8],
    start: usize,
) -> Result<(Vec<u8>, usize), PdfError> {
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
    for pair in nibbles.as_chunks::<2>().0 {
        out.push((pair[0] << 4) | pair[1]);
    }
    Ok((out, i))
}

pub(crate) fn bytes_to_u32(b: &[u8]) -> u32 {
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
    for chunk in b.as_chunks::<2>().0 {
        units.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&units)
}

pub(crate) fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}

pub(crate) fn is_ws(b: u8) -> bool {
    matches!(b, 0x00 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

pub(crate) fn skip_ws_and_comments(bytes: &[u8], mut i: usize) -> usize {
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

pub(crate) fn peek_keyword(bytes: &[u8], i: usize, kw: &[u8]) -> Option<usize> {
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
pub(crate) fn skip_token(bytes: &[u8], i: usize) -> usize {
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
    /// Per-font horizontal advance metrics (§9.4.4), keyed like
    /// `fonts`. Drives the post-show text-matrix advance.
    advances: HashMap<String, FontAdvance>,
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
    /// Text rendering mode (`Tr`) — §9.3.6 Table 106. Persists across
    /// show operators and is reset to the §9.3.1 default
    /// ([`TextRenderMode::Fill`]) only by an explicit `0 Tr`, never by
    /// `BT` (Table 105: `Tr` is a graphics-state text parameter, not a
    /// text-object parameter). Saved / restored by `q` / `Q`.
    render_mode: TextRenderMode,
    /// Text rise (`Ts`) — §9.4.4 + §9.3.7 Table 105, in unscaled
    /// text-space units. Persists across show operators and is reset
    /// to the §9.3.1 default `0.0` only by an explicit `0 Ts`, never by
    /// `BT` (Table 105: `Ts` is a graphics-state text parameter, not a
    /// text-object parameter). Saved / restored by `q` / `Q`.
    text_rise: f32,
    /// Character spacing `Tc` (§9.3.2), unscaled text-space units.
    /// Added to every glyph's §9.4.4 advance. Default 0.0.
    char_spacing: f32,
    /// Word spacing `Tw` (§9.3.3), unscaled text-space units. Added to
    /// single-byte code-32 glyphs in the §9.4.4 advance. Default 0.0.
    word_spacing: f32,
    /// Horizontal scaling `Th` (§9.3.4) as a fraction (`scale ÷ 100`).
    /// Scales the §9.4.4 horizontal advance. Default 1.0.
    horiz_scale: f32,
    /// Displacement accumulated by the current show operator
    /// (unscaled text space); reset before each show, stored on the
    /// run afterwards as [`TextRun::advance`].
    run_advance: (f32, f32),
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
    /// One frame per open `BDC` / `BMC` (always maintained, unlike
    /// `mcid_stack`): `Some` when the block declared `/ActualText`.
    actual_stack: Vec<Option<ActualSpan>>,
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
        /// `/ActualText` (§14.9.4) scanned out of the dict, decoded
        /// from PDFDocEncoding / UTF-16BE.
        actual_text: Option<String>,
    },
}

/// One open marked-content frame's replacement text: the `/ActualText`
/// a `BDC` declared (§14.9.4) and the index of the run that carries
/// it once the first show inside the span fired. Later shows in the
/// same span add no run; they extend that run's advance.
#[derive(Clone, Debug)]
struct ActualSpan {
    text: String,
    run: Option<usize>,
}

#[derive(Clone, Debug)]
enum TJItem {
    Str(Vec<u8>),
    /// Numeric `TJ` position adjustment, in thousandths of a text-space
    /// unit (ISO 32000-1 §9.4.3, Table 109). The value is *subtracted*
    /// from the horizontal coordinate: a negative number opens a
    /// rightward gap before the next glyph (Figure 46), a positive one
    /// pulls it leftward. `emit_show_tj` turns a gap wider than
    /// [`TextWalker::WORD_BREAK_GAP`] into an inter-word space.
    Kern(f32),
}

#[derive(Clone, Debug)]
struct SavedTextState {
    font: String,
    size: f32,
    tm: [f32; 6],
    tlm: [f32; 6],
    leading: f32,
    render_mode: TextRenderMode,
    text_rise: f32,
    char_spacing: f32,
    word_spacing: f32,
    horiz_scale: f32,
}

impl TextWalker {
    fn new(fonts: HashMap<String, FontDecoder>, advances: HashMap<String, FontAdvance>) -> Self {
        Self {
            fonts,
            advances,
            runs: Vec::new(),
            run_mcids: Vec::new(),
            operands: Vec::new(),
            in_text: false,
            cur_font: String::new(),
            cur_size: 0.0,
            tm: identity(),
            tlm: identity(),
            leading: 0.0,
            render_mode: TextRenderMode::Fill,
            text_rise: 0.0,
            char_spacing: 0.0,
            word_spacing: 0.0,
            horiz_scale: 1.0,
            run_advance: (0.0, 0.0),
            saved: Vec::new(),
            track_mcid: false,
            mcid_stack: Vec::new(),
            actual_stack: Vec::new(),
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
                while i < input.len() && depth > 0 {
                    if input[i] == b'<' && input.get(i + 1) == Some(&b'<') {
                        depth += 1;
                        i += 2;
                    } else if input[i] == b'>' && input.get(i + 1) == Some(&b'>') {
                        depth -= 1;
                        i += 2;
                    } else if input[i] == b'(' {
                        // A string value: its bytes never open or
                        // close a nesting level.
                        i = read_literal_string(input, i)
                            .map(|(e, _)| e)
                            .unwrap_or(input.len());
                    } else if input[i] == b'<' {
                        // Hex string: `<FEFF00AD>>>` ends the string
                        // first, then the dict.
                        i = read_hex_string_payload(input, i)
                            .map(|(_, e)| e)
                            .unwrap_or(input.len());
                    } else {
                        i += 1;
                    }
                }
                let (mcid, actual_text) = scan_inline_props(&input[start..i]);
                self.operands.push(TextOperand::Dict { mcid, actual_text });
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
            if &input[i..kw_end] == b"BI" {
                // Inline image (§8.9.7): the payload between `ID` and
                // `EI` is arbitrary bytes — a `(` in it would otherwise
                // be read as a string running to the end of the stream.
                i = skip_inline_image(input, kw_end);
                self.operands.clear();
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
                    render_mode: self.render_mode,
                    text_rise: self.text_rise,
                    char_spacing: self.char_spacing,
                    word_spacing: self.word_spacing,
                    horiz_scale: self.horiz_scale,
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
                    self.render_mode = s.render_mode;
                    self.text_rise = s.text_rise;
                    self.char_spacing = s.char_spacing;
                    self.word_spacing = s.word_spacing;
                    self.horiz_scale = s.horiz_scale;
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
                self.emit_show_tj(&arr);
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
                // aw ac string " — set Tw, Tc, T*, Tj (§9.4.3 /
                // Table 109).
                let s = self.pop_string().unwrap_or_default();
                let ac = self.pop_num().unwrap_or(0.0);
                let aw = self.pop_num().unwrap_or(0.0);
                self.word_spacing = aw;
                self.char_spacing = ac;
                let translate = [1.0, 0.0, 0.0, 1.0, 0.0, -self.leading];
                self.tlm = mul(translate, self.tlm);
                self.tm = self.tlm;
                self.emit_show(&s);
            }
            b"Tr" => {
                // render mode Tr — §9.3.6 Table 106. The single integer
                // operand selects fill / stroke / clip / invisible. We
                // record it so each emitted run carries the mode in force
                // (extraction consumers filter the `3 Tr` OCR layer on
                // it); the actual fill/stroke/clip painting it implies is
                // a renderer concern this extraction walker doesn't reach.
                if let Some(n) = self.pop_num() {
                    self.render_mode = TextRenderMode::from_operand(n as i64);
                }
                self.operands.clear();
            }
            b"Ts" => {
                // rise Ts — §9.4.4 + §9.3.7 Table 105. The single
                // number operand shifts the text-rendering origin
                // vertically (superscript / subscript) in unscaled
                // text-space units. We record it so each emitted run's
                // origin reflects the rise (see `push_run`); a `0 Ts`
                // restores the baseline per the §9.3.1 default.
                if let Some(n) = self.pop_num() {
                    self.text_rise = n;
                }
                self.operands.clear();
            }
            // Char / word spacing and horizontal scale feed the §9.4.4
            // advance so a following run's origin reflects them.
            b"Tc" => {
                if let Some(n) = self.pop_num() {
                    self.char_spacing = n;
                }
                self.operands.clear();
            }
            b"Tw" => {
                if let Some(n) = self.pop_num() {
                    self.word_spacing = n;
                }
                self.operands.clear();
            }
            b"Tz" => {
                if let Some(n) = self.pop_num() {
                    self.horiz_scale = n / 100.0;
                }
                self.operands.clear();
            }
            // Marked-content operators (ISO 32000-1 §14.6).
            b"BDC" => {
                // tag properties BDC. Pop properties, then tag.
                let mut actual_text = None;
                let mcid = match self.operands.pop() {
                    Some(TextOperand::Dict {
                        mcid,
                        actual_text: at,
                    }) => {
                        actual_text = at;
                        mcid
                    }
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
                self.actual_stack
                    .push(actual_text.map(|text| ActualSpan { text, run: None }));
                self.operands.clear();
            }
            b"BMC" => {
                // tag BMC — no properties dict, no MCID.
                let _tag = self.pop_name();
                if self.track_mcid {
                    self.mcid_stack.push(None);
                }
                self.actual_stack.push(None);
                self.operands.clear();
            }
            b"EMC" => {
                if self.track_mcid {
                    self.mcid_stack.pop();
                }
                self.actual_stack.pop();
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

    /// Decode a single show-operand byte string through the current
    /// font's decoder (Latin-1 fallback when no font resolved).
    fn decode_bytes(&self, bytes: &[u8]) -> String {
        match self.fonts.get(&self.cur_font) {
            Some(d) => d.decode(bytes),
            // No font resolved — fall back to Latin-1 bytes so the run
            // isn't dropped silently.
            None => bytes.iter().map(|&b| b as char).collect(),
        }
    }

    fn emit_show(&mut self, bytes: &[u8]) {
        if !self.in_text {
            // Show outside BT/ET — malformed but tolerate; the writer
            // wouldn't emit this.
            self.operands.clear();
            return;
        }
        let text = self.decode_bytes(bytes);
        let span_run = self.begin_span_run(|| text);
        // §9.4.4 — advance Tm past the shown glyphs so a following show
        // on the same line starts at the correct origin.
        self.run_advance = (0.0, 0.0);
        self.advance_bytes(bytes);
        self.end_span_run(span_run);
        self.operands.clear();
    }

    /// `TJ` show: decode each string element and translate the numeric
    /// position adjustments between them into word breaks.
    ///
    /// ISO 32000-1 §9.4.3 (Table 109, `TJ`): a numeric array element is
    /// expressed in thousandths of a text-space unit and is *subtracted*
    /// from the current horizontal coordinate, so a **negative** number
    /// opens a rightward gap before the next glyph (Figure 46). Small
    /// negative kerns (the figure's −120 / −95 between letters of "AWAY")
    /// are intra-word micro-spacing and must not split a word; a gap that
    /// exceeds [`Self::WORD_BREAK_GAP`] of an em is the unglyphed
    /// inter-word space many producers emit in place of a literal space
    /// character. A single U+0020 is inserted there so text extracted
    /// from such streams reads `hello world`, not `helloworld`.
    ///
    /// The threshold is an extraction-layer heuristic (the spec defines
    /// the geometry, not a word-break rule). It is intentionally above
    /// the figure's −120 kern so spec EXAMPLE-class kerning stays joined.
    fn emit_show_tj(&mut self, arr: &[TJItem]) {
        if !self.in_text {
            self.operands.clear();
            return;
        }
        // Kerns ahead of the first string move the origin the first
        // glyph is drawn at (pdfTeX opens a new font's array with the
        // interword gap: `/F45 Tf [-724(Bold)…]TJ`); apply them before
        // the run is recorded so its position — and the gap the line
        // assembler measures from the previous run — is the glyph's.
        let first_str = arr
            .iter()
            .position(|it| matches!(it, TJItem::Str(_)))
            .unwrap_or(arr.len());
        for item in &arr[..first_str] {
            if let TJItem::Kern(adj) = item {
                self.advance_kern(*adj);
            }
        }
        let arr = &arr[first_str..];
        // Decode every string once; the gaps between consecutive
        // strings (thousandths of an em, rightward positive) feed the
        // letter-spacing estimate and the word-break rule.
        let mut pieces: Vec<String> = Vec::new();
        let mut gaps: Vec<f32> = Vec::new();
        let mut pending_gap = 0.0f32;
        for item in arr {
            match item {
                TJItem::Str(b) => {
                    if !pieces.is_empty() {
                        gaps.push(pending_gap);
                    }
                    pending_gap = 0.0;
                    pieces.push(self.decode_bytes(b));
                }
                // Numeric adjustment: subtracted from the horizontal
                // coordinate, so negate to get the rightward gap. Positive
                // numbers pull the next glyph leftward (overlap / negative
                // kern) and never open a word break.
                TJItem::Kern(adj) => pending_gap += -adj,
            }
        }
        let ls = letter_spacing_estimate(
            pieces
                .iter()
                .map(|t| is_single_glyph(t))
                .collect::<Vec<_>>()
                .as_slice(),
            &gaps,
            1000.0,
        );
        let mut text = String::new();
        for (i, piece) in pieces.iter().enumerate() {
            if i > 0
                && gaps[i - 1] >= Self::WORD_BREAK_GAP + ls
                && !text.is_empty()
                && !text.ends_with(' ')
            {
                text.push(' ');
            }
            text.push_str(piece);
        }
        // Record the run at the array's start origin, then advance Tm
        // through every element (glyph widths + per-element kerns,
        // §9.4.3 / §9.4.4) so a following show is correctly positioned.
        let span_run = self.begin_span_run(|| text);
        self.run_advance = (0.0, 0.0);
        for item in arr {
            match item {
                TJItem::Str(b) => self.advance_bytes(b),
                TJItem::Kern(adj) => self.advance_kern(*adj),
            }
        }
        self.end_span_run(span_run);
        self.operands.clear();
    }

    /// Start the run for a show: outside an `/ActualText` span the
    /// decoded `text` becomes a new run; inside one, the span's
    /// replacement text is the run — pushed on the span's first show,
    /// reused (and extended by [`Self::end_span_run`]) on later ones.
    /// Returns the index of a span run to extend, if any.
    fn begin_span_run(&mut self, text: impl FnOnce() -> String) -> Option<usize> {
        let span = self.actual_stack.iter_mut().rev().find_map(|f| f.as_mut());
        match span {
            None => {
                self.push_run(text());
                None
            }
            Some(span) => match span.run {
                Some(idx) => Some(idx),
                None => {
                    let replacement = span.text.clone();
                    let idx = self.runs.len();
                    span.run = Some(idx);
                    self.push_run(replacement);
                    None
                }
            },
        }
    }

    /// Close the show begun by [`Self::begin_span_run`]: store the
    /// accumulated advance on a fresh run, or move an existing span
    /// run's end to the current text origin.
    fn end_span_run(&mut self, span_run: Option<usize>) {
        match span_run {
            None => self.finish_run_advance(),
            Some(idx) => {
                self.run_advance = (0.0, 0.0);
                let tm = self.tm;
                if let Some(run) = self.runs.get_mut(idx) {
                    let m = run.text_matrix;
                    let (dx, dy) = (tm[4] - m[4], tm[5] - m[5]);
                    let det = m[0] * m[3] - m[1] * m[2];
                    if det.abs() > 1e-9 {
                        run.advance =
                            ((dx * m[3] - dy * m[2]) / det, (dy * m[0] - dx * m[1]) / det);
                    }
                }
            }
        }
    }

    /// Append a decoded run at the current text position + font, stamping
    /// the in-scope MCID.
    fn push_run(&mut self, text: String) {
        // §9.4.4 — the text-rendering origin is the text-space point
        // `(0, Trise)` mapped through the text matrix `Tm`. With
        // `tm = [a b c d e f]` the bare origin `(0,0)` maps to
        // `(e, f)`; adding the rise along `Tm`'s vertical basis gives
        // `(c·Trise + e, d·Trise + f)`. For the common axis-aligned
        // `Tm` (`c == 0`, `d == 1`) this is simply `(e, f + Trise)`.
        let rise = self.text_rise;
        let x = self.tm[2] * rise + self.tm[4];
        let y = self.tm[3] * rise + self.tm[5];
        self.runs.push(TextRun {
            text,
            position: (x, y),
            font_name: self.cur_font.clone(),
            font_size: self.cur_size,
            render_mode: self.render_mode,
            text_rise: rise,
            text_matrix: self.tm,
            advance: (0.0, 0.0),
        });
        // Stamp the current MCID (top of stack) onto the run.
        let cur_mcid = self.mcid_stack.last().copied().unwrap_or(None);
        self.run_mcids.push(cur_mcid);
    }

    /// Advance the text matrix `Tm` by the §9.4.4 displacement of every
    /// glyph in `bytes`:
    ///
    /// ```text
    /// tx = ((w0 − Tj/1000)·Tfs + Tc + Tw)·Th
    /// ```
    ///
    /// (with `Tj = 0`; `TJ` kerns go through [`Self::advance_kern`]).
    /// `w0` is the current font's per-glyph advance (glyph-space
    /// thousandths); `Tw` applies only to single-byte code 32. Composite
    /// Identity fonts step two bytes per CID. A zero-advance font
    /// (`FontAdvance::None`) still moves by the `Tc`/`Tw`/`Th` spacing.
    fn advance_bytes(&mut self, bytes: &[u8]) {
        let tfs = self.cur_size;
        let th = self.horiz_scale;
        let tc = self.char_spacing;
        let adv = self.advances.get(&self.cur_font).cloned();
        let adv = adv.unwrap_or(FontAdvance::None);
        let scale = adv.text_scale();
        if let FontAdvance::Cid(cid) = &adv {
            let vertical = cid.wmode == 1;
            if let Some(cmap) = &cid.cmap {
                // Embedded-CMap composite (§9.7.6.2): extract codes
                // at the codespace widths, map each to its CID, then
                // apply the §9.4.4 displacement. Word spacing applies
                // only to a *single-byte* code 32 (§9.3.3 — "It shall
                // not apply to occurrences of the byte value 32 in
                // multiple-byte codes").
                let mut i = 0;
                while i < bytes.len() {
                    let (consumed, code) = cmap.next_code(&bytes[i..]);
                    let cid_val = cmap.cid_for_code(code) as i64;
                    let tw = if consumed == 1 && bytes[i] == 32 {
                        self.word_spacing
                    } else {
                        0.0
                    };
                    if vertical {
                        // §9.4.4: ty = (w1 − Tj/1000)·Tfs + Tc + Tw —
                        // the horizontal-scaling Th does not apply.
                        let w1 = cid.vertical(cid_val) * scale;
                        self.translate_tm_v(w1 * tfs + tc + tw);
                    } else {
                        let w0 = adv.width(cid_val) * scale;
                        self.translate_tm((w0 * tfs + tc + tw) * th);
                    }
                    i += consumed.max(1);
                }
            } else {
                // Identity CMap: two bytes per code, CID = code. A
                // 2-byte code never triggers word spacing (§9.3.3).
                let mut i = 0;
                while i + 1 < bytes.len() {
                    let code = ((bytes[i] as i64) << 8) | bytes[i + 1] as i64;
                    if vertical {
                        let w1 = cid.vertical(code) * scale;
                        self.translate_tm_v(w1 * tfs + tc);
                    } else {
                        let w0 = adv.width(code) * scale;
                        self.translate_tm((w0 * tfs + tc) * th);
                    }
                    i += 2;
                }
            }
        } else {
            for &b in bytes {
                let w0 = adv.width(b as i64) * scale;
                let tw = if b == 32 { self.word_spacing } else { 0.0 };
                let tx = (w0 * tfs + tc + tw) * th;
                self.translate_tm(tx);
            }
        }
    }

    /// Apply a `TJ` numeric kern (§9.4.3 + §9.4.4): in horizontal
    /// writing the adjustment translates `Tm` by
    /// `−adj/1000 × Tfs × Th`; in vertical writing by
    /// `−adj/1000 × Tfs` on the vertical axis (`Th` applies only to
    /// horizontal writing per the §9.4.4 displacement equations).
    fn advance_kern(&mut self, adj: f32) {
        let vertical = self
            .advances
            .get(&self.cur_font)
            .map(FontAdvance::is_vertical)
            .unwrap_or(false);
        if vertical {
            let ty = -adj / 1000.0 * self.cur_size;
            self.translate_tm_v(ty);
        } else {
            let tx = -adj / 1000.0 * self.cur_size * self.horiz_scale;
            self.translate_tm(tx);
        }
    }

    /// Translate `Tm` by `(tx, 0)` in text space
    /// (`Tm = [1 0 0 1 tx 0] × Tm`).
    fn translate_tm(&mut self, tx: f32) {
        let translate = [1.0, 0.0, 0.0, 1.0, tx, 0.0];
        self.tm = mul(translate, self.tm);
        self.run_advance.0 += tx;
    }

    /// Translate `Tm` by `(0, ty)` in text space — the §9.4.4
    /// vertical-writing update (`Tm = [1 0 0 1 0 ty] × Tm`).
    fn translate_tm_v(&mut self, ty: f32) {
        let translate = [1.0, 0.0, 0.0, 1.0, 0.0, ty];
        self.tm = mul(translate, self.tm);
        self.run_advance.1 += ty;
    }

    /// Store the displacement accumulated since the last `push_run` on
    /// that run.
    fn finish_run_advance(&mut self) {
        if let Some(run) = self.runs.last_mut() {
            run.advance = self.run_advance;
        }
        self.run_advance = (0.0, 0.0);
    }

    /// Minimum rightward `TJ` gap, in thousandths of an em, that the
    /// text extractor treats as an inter-word space rather than
    /// intra-word kerning — [`WORD_GAP_EM`] in thousandths. 0.15 em is
    /// above the ISO 32000-1 Figure 46 kerns (−120 / −95) and below
    /// the narrowest real space advance (TeX's fully shrunk interword
    /// glue is ~0.17 em in Times, 0.22 em in Computer Modern; text
    /// faces place a space at 0.2–0.35 em), so word boundaries a
    /// producer encoded purely as a `TJ` displacement are recovered
    /// without false-splitting kerned text.
    const WORD_BREAK_GAP: f32 = WORD_GAP_EM * 1000.0;
}

// ────────────────────────── helpers ──────────────────────────

/// Skip a `BI … ID … EI` inline image whose `BI` keyword ended at
/// `after_bi`; returns the offset just past `EI` (or the end of the
/// stream when no delimited `EI` follows).
fn skip_inline_image(input: &[u8], after_bi: usize) -> usize {
    use crate::reader::inline_images::{find_inline_image_ei, parse_one_inline_image};
    match parse_one_inline_image(input, after_bi) {
        Ok((_, resume)) => resume,
        Err(_) => find_inline_image_ei(input, after_bi)
            .map(|ei| ei + 2)
            .unwrap_or(input.len()),
    }
}

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
/// `/MCID <integer>` and `/ActualText <string>` (§14.9.4). Only the
/// dict's top level is read — nested dicts are skipped wholesale, and
/// string values are stepped over as strings so their bytes can't
/// open or close a nesting level. Whitespace tolerant.
fn scan_inline_props(bytes: &[u8]) -> (Option<u32>, Option<String>) {
    let mut mcid = None;
    let mut actual = None;
    if bytes.len() < 4 || &bytes[..2] != b"<<" {
        return (mcid, actual);
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
        if b == b'(' {
            i = match read_literal_string(body, i) {
                Ok((end, _)) => end,
                Err(_) => body.len(),
            };
            continue;
        }
        if b == b'<' {
            i = match read_hex_string_payload(body, i) {
                Ok((_, end)) => end,
                Err(_) => body.len(),
            };
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
            while i < body.len() && is_ws(body[i]) {
                i += 1;
            }
            if name == b"MCID" {
                let mut e = i;
                while e < body.len() && (body[e].is_ascii_digit() || body[e] == b'-') {
                    e += 1;
                }
                if e > i {
                    mcid = std::str::from_utf8(&body[i..e])
                        .ok()
                        .and_then(|s| s.parse::<u32>().ok());
                }
                i = e;
            } else if name == b"ActualText" {
                let payload = match body.get(i) {
                    Some(b'(') => read_literal_string(body, i).ok(),
                    Some(b'<') => read_hex_string_payload(body, i)
                        .ok()
                        .map(|(v, end)| (end, v)),
                    _ => None,
                };
                if let Some((end, raw)) = payload {
                    actual = Some(decode_text_string_bytes(&raw));
                    i = end;
                }
            }
            continue;
        }
        // Skip any other top-level token.
        i += 1;
    }
    (mcid, actual)
}

/// PDF text string (§7.9.2.2): UTF-16BE behind a `FE FF` byte-order
/// mark, UTF-8 behind the `EF BB BF` mark, else PDFDocEncoding, which
/// coincides with Latin-1 for the characters that matter here.
fn decode_text_string_bytes(b: &[u8]) -> String {
    if b.len() >= 2 && b[0] == 0xFE && b[1] == 0xFF {
        let utf16: Vec<u16> = b[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&utf16)
    } else if b.len() >= 3 && b[..3] == [0xEF, 0xBB, 0xBF] {
        String::from_utf8_lossy(&b[3..]).into_owned()
    } else {
        b.iter().map(|&c| c as char).collect()
    }
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
            if let Ok(s) = str::from_utf8(&input[i..end])
                && let Ok(f) = s.parse::<f32>()
            {
                items.push(TJItem::Kern(f));
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
                TextRun::new("Hello", (0.0, 0.0), "F0", 12.0).with_advance((30.0, 0.0)),
                TextRun::new("World", (40.0, 0.0), "F0", 12.0).with_advance((30.0, 0.0)),
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
    fn cmap_codespacerange_single_width_parses() {
        let cmap = b"\
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
2 beginbfchar
<0041> <0041>
<0042> <0042>
endbfchar
";
        let parsed = CMap::parse(cmap).unwrap();
        assert_eq!(parsed.codespaces.len(), 1);
        assert_eq!(parsed.codespaces[0].width(), 2);
        assert_eq!(parsed.codespaces[0].lo, vec![0x00, 0x00]);
        assert_eq!(parsed.codespaces[0].hi, vec![0xFF, 0xFF]);
    }

    #[test]
    fn cmap_codespacerange_mixed_width_parses_and_selects() {
        // 1-byte territory <00>..<7F> (ASCII) plus a 2-byte territory
        // <8140>..<FCFC> (Shift-JIS-shaped).
        let cmap = b"\
2 begincodespacerange
<00> <7F>
<8140> <FCFC>
endcodespacerange
";
        let parsed = CMap::parse(cmap).unwrap();
        assert_eq!(parsed.codespaces.len(), 2);
        // 0x41 in the 1-byte range.
        assert_eq!(parsed.match_codespace_width(&[0x41]), Some(1));
        // 0x81 0x40 in the 2-byte range — first byte 0x81 is outside
        // [0x00..=0x7F], so the 1-byte codespace doesn't match; the
        // 2-byte one does.
        assert_eq!(parsed.match_codespace_width(&[0x81, 0x40]), Some(2));
        // 0x81 0x39: first byte in 2-byte's [0x81..=0xFC], second byte
        // 0x39 BELOW 2-byte's [0x40..=0xFC] — Tech Note #5014 §3.1
        // component-wise rule says NO MATCH. (The linear u32 interval
        // 0x8140..=0xFCFC would match — exactly the bug we're closing.)
        assert_eq!(parsed.match_codespace_width(&[0x81, 0x39]), None);
        // 0xFD outside both ranges.
        assert_eq!(parsed.match_codespace_width(&[0xFD]), None);
    }

    #[test]
    fn cmap_codespacerange_component_wise_match() {
        // The §3.1 rule: the canonical Shift-JIS-ish range
        // <8140>..<FCFC> excludes <8130> (low byte below 0x40) and
        // <FD00> (high byte above 0xFC). This is the test that nails
        // the difference between byte-component bounds and a linear
        // u32 interval.
        let cmap = b"1 begincodespacerange <8140> <FCFC> endcodespacerange";
        let parsed = CMap::parse(cmap).unwrap();
        assert_eq!(parsed.match_codespace_width(&[0x81, 0x40]), Some(2));
        assert_eq!(parsed.match_codespace_width(&[0xFC, 0xFC]), Some(2));
        assert_eq!(parsed.match_codespace_width(&[0x81, 0x39]), None);
        assert_eq!(parsed.match_codespace_width(&[0xFD, 0x00]), None);
    }

    #[test]
    fn cmap_codespacerange_skips_mismatched_widths() {
        // A malformed entry whose <lo> and <hi> widths diverge is
        // dropped tolerantly; the well-formed entry that follows is
        // still captured.
        let cmap = b"\
2 begincodespacerange
<00> <FFFF>
<0000> <FFFF>
endcodespacerange
";
        let parsed = CMap::parse(cmap).unwrap();
        assert_eq!(parsed.codespaces.len(), 1);
        assert_eq!(parsed.codespaces[0].width(), 2);
    }

    #[test]
    fn cmap_decode_mixed_width_picks_per_position() {
        // 1-byte ASCII <00>..<7F> alongside 2-byte <8140>..<FCFC>.
        // <00>..<7F> maps each byte to itself (handled by a bfchar
        // entry for <41>); <8140> maps to U+4E00 (the canonical CJK
        // "one"). Input bytes: 0x41 0x81 0x40 → "A" + U+4E00.
        let cmap = b"\
2 begincodespacerange
<00> <7F>
<8140> <FCFC>
endcodespacerange
1 beginbfchar
<41> <0041>
endbfchar
1 beginbfchar
<8140> <4E00>
endbfchar
";
        let parsed = CMap::parse(cmap).unwrap();
        let decoder = FontDecoder::ToUnicode {
            map: parsed,
            cid_width: 1, // ignored when codespaces are present
        };
        let s = decoder.decode(&[0x41, 0x81, 0x40]);
        assert_eq!(s, "A\u{4E00}");
    }

    #[test]
    fn cmap_decode_unmapped_in_codespace_emits_replacement() {
        // <00>..<FF> 1-byte territory, no bfchar entries. Every input
        // byte is in-codespace but unmapped — each must surface as
        // U+FFFD per Adobe Tech Note #5411 §2.
        let cmap = b"1 begincodespacerange <00> <FF> endcodespacerange";
        let parsed = CMap::parse(cmap).unwrap();
        let decoder = FontDecoder::ToUnicode {
            map: parsed,
            cid_width: 1,
        };
        let s = decoder.decode(&[0x41, 0x42]);
        assert_eq!(s, "\u{FFFD}\u{FFFD}");
    }

    #[test]
    fn cmap_decode_out_of_codespace_emits_replacement_and_advances() {
        // <00>..<7F> 1-byte codespace only. Input 0xFF is OUT of every
        // declared codespace; the decoder emits U+FFFD and advances
        // one byte so a following in-codespace byte still resolves.
        let cmap = b"\
1 begincodespacerange
<00> <7F>
endcodespacerange
1 beginbfchar
<41> <0041>
endbfchar
";
        let parsed = CMap::parse(cmap).unwrap();
        let decoder = FontDecoder::ToUnicode {
            map: parsed,
            cid_width: 1,
        };
        let s = decoder.decode(&[0xFF, 0x41]);
        assert_eq!(s, "\u{FFFD}A");
    }

    #[test]
    fn cmap_decode_legacy_no_codespacerange_uses_byte_width_fallback() {
        // No codespacerange — the decoder falls back to the legacy
        // single-width path that uses `byte_width` inferred from the
        // first bfchar source operand. Hand-crafted CMaps that omit
        // the §9.10.3 mandatory header still decode.
        let cmap = b"beginbfchar <0041> <0048> <0042> <0069> endbfchar";
        let parsed = CMap::parse(cmap).unwrap();
        assert!(parsed.codespaces.is_empty());
        assert_eq!(parsed.byte_width, 2);
        let decoder = FontDecoder::ToUnicode {
            map: parsed,
            cid_width: 2,
        };
        let s = decoder.decode(&[0x00, 0x41, 0x00, 0x42]);
        assert_eq!(s, "Hi");
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
