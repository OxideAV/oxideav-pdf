//! Geometric reading order for untagged pages.
//!
//! A content stream paints text in whatever order its producer found
//! convenient: running headers last, the right column before the left,
//! every link after the body text in its own font. ISO 32000-1 §14.8.2.3
//! is explicit that page content order is not the logical order unless
//! the document is tagged. This module rebuilds a reading order from
//! the geometry of the runs alone:
//!
//! 1. **Segments.** Runs are grouped into lines in painting order
//!    ([`crate::reader::text`]'s baseline-shift / backtrack rule) and
//!    each line is cut where two consecutive runs stand more than
//!    [`SEGMENT_GAP_EM`] apart, so a row painted across a gutter yields
//!    one segment per column. Every segment gets coordinates in the
//!    frame of its own writing direction: `s` along the baseline, `t`
//!    across it (lines progress toward smaller `t`). Segments are
//!    handled per writing direction, so rotated text and vertical
//!    writing (lines progressing right to left) are laid out in their
//!    own frame and never interleave with the upright text.
//! 2. **Columns.** A region is searched for a *gutter*: a band along
//!    `s` that segments stand on either side of. Segments reaching
//!    across the band (titles, full-width paragraphs, centred page
//!    numbers) are *spanners*; they cut the region into sections, and
//!    in each section the left side is read before the right side. A
//!    gutter is only accepted when both sides hold running text, or
//!    when their baselines do not line up — so a table (short cells on
//!    shared baselines) is left alone and reads row by row.
//! 3. **Rows.** A region without a gutter is read top to bottom;
//!    segments sharing a baseline form one output line, left to right.
//!
//! Options add the textual clean-ups a reader expects: a word hyphenated
//! across a line end is joined, presentation-form ligatures are spelled
//! out, invisible (render mode 3) text can be dropped.

use crate::reader::text::{
    TextRenderMode, TextRun, dot, line_text, reorder_bidi_line, run_axes, run_gap, stream_lines,
};

/// The order in which the text of a page is assembled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TextOrder {
    /// The order the content stream paints the text in.
    Stream,
    /// Reading order rebuilt from the geometry of the runs: columns
    /// left to right, lines top to bottom, table rows kept together.
    Geometric,
    /// The logical structure tree of a Tagged PDF (ISO 32000-1 §14.8)
    /// where the document carries a usable one, [`Self::Geometric`]
    /// otherwise. Only meaningful to the document-level entry points
    /// ([`crate::reader::DocumentReader::text`]); a bare run list has
    /// no structure tree and is laid out geometrically.
    #[default]
    Structure,
}

/// How runs are assembled into text.
///
/// ```
/// use oxideav_pdf::reader::{TextLayoutOptions, TextOrder};
/// let opts = TextLayoutOptions::new()
///     .with_order(TextOrder::Stream)
///     .with_join_hyphenated(false);
/// assert_eq!(opts.order(), TextOrder::Stream);
/// ```
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct TextLayoutOptions {
    order: TextOrder,
    join_hyphenated: bool,
    expand_ligatures: bool,
    include_invisible: bool,
    include_artifacts: bool,
    page_separator: String,
}

impl Default for TextLayoutOptions {
    fn default() -> Self {
        Self {
            order: TextOrder::default(),
            join_hyphenated: true,
            expand_ligatures: true,
            include_invisible: true,
            include_artifacts: true,
            page_separator: "\n".to_owned(),
        }
    }
}

impl TextLayoutOptions {
    /// The defaults: the structure tree's order for a Tagged PDF and
    /// geometric reading order otherwise, hyphenated line ends
    /// joined, ligatures spelled out, invisible text and artifacts
    /// kept, pages separated by a line feed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Choose the assembly order.
    pub fn with_order(mut self, order: TextOrder) -> Self {
        self.order = order;
        self
    }

    /// Join a word hyphenated across a line end (`speci-` / `fied` →
    /// `specified`). The hyphen is dropped when the next line starts
    /// with a lowercase letter; a compound that happened to break at
    /// its hyphen loses it, which is why this can be switched off.
    pub fn with_join_hyphenated(mut self, on: bool) -> Self {
        self.join_hyphenated = on;
        self
    }

    /// Spell out the Latin presentation-form ligatures (U+FB00–U+FB06:
    /// `ﬁ` → `fi`).
    pub fn with_expand_ligatures(mut self, on: bool) -> Self {
        self.expand_ligatures = on;
        self
    }

    /// Keep text shown in render mode 3 (ISO 32000-1 §9.3.6 — neither
    /// filled nor stroked: the recognised-text layer behind a scanned
    /// page). Off drops it, leaving what a viewer displays.
    pub fn with_include_invisible(mut self, on: bool) -> Self {
        self.include_invisible = on;
        self
    }

    /// Keep the text a Tagged PDF marks as an artifact (ISO 32000-1
    /// §14.8.2.2: running headers and footers, page numbers,
    /// watermarks) when reading in [`TextOrder::Structure`]: it follows
    /// the logical content of its page. Off leaves the document's
    /// logical content alone. The other orders read what is painted
    /// and keep artifacts regardless.
    pub fn with_include_artifacts(mut self, on: bool) -> Self {
        self.include_artifacts = on;
        self
    }

    /// The string placed between pages (default `"\n"`; `"\u{c}"` for a
    /// form feed).
    pub fn with_page_separator(mut self, sep: impl Into<String>) -> Self {
        self.page_separator = sep.into();
        self
    }

    /// The assembly order.
    pub fn order(&self) -> TextOrder {
        self.order
    }

    /// Whether hyphenated line ends are joined.
    pub fn join_hyphenated(&self) -> bool {
        self.join_hyphenated
    }

    /// Whether presentation-form ligatures are spelled out.
    pub fn expand_ligatures(&self) -> bool {
        self.expand_ligatures
    }

    /// Whether render-mode-3 text is kept.
    pub fn include_invisible(&self) -> bool {
        self.include_invisible
    }

    /// Whether artifacts are kept in structure order.
    pub fn include_artifacts(&self) -> bool {
        self.include_artifacts
    }

    /// The string placed between pages.
    pub fn page_separator(&self) -> &str {
        &self.page_separator
    }
}

/// Gap between two consecutive runs of a painted line, in em, past
/// which the line is cut into separate segments (cells of a row, or
/// the two columns of a row painted across a gutter). Word gaps of a
/// justified line stay below it.
const SEGMENT_GAP_EM: f32 = 1.2;

/// Narrowest gutter, in em of the region's typical text: three
/// quarters of the left column's lines end at least this far before
/// the right column's edge.
const GUTTER_MIN_EM: f32 = 0.6;

/// How far, in em, a left-column line may reach past the right
/// column's edge (advance widths are approximate when a font's
/// metrics are) before it counts as spanning both columns.
const COLUMN_OVERHANG_EM: f32 = 0.3;

/// Baseline distance, in em, within which two segments can be pieces
/// of one line painted out of order.
const ROW_MERGE_TOLERANCE_EM: f32 = 0.1;

/// Widest gap, in em, across which such pieces are joined (an ample
/// word gap; a gutter between columns is wider).
const ROW_MERGE_GAP_EM: f32 = 0.5;

/// Overlap, in em, two pieces may have and still be joined.
const ROW_MERGE_OVERLAP_EM: f32 = 0.25;

/// Baseline distance, in em, within which two segments share a row.
const ROW_TOLERANCE_EM: f32 = 0.4;

/// Regions with more segments than this are read row by row without a
/// column search (bounds the work on hostile pages).
const MAX_COLUMN_SEARCH: usize = 4000;

/// Nesting bound of the column search.
const MAX_COLUMN_DEPTH: u32 = 6;

/// A piece of one painted line, in the frame of its writing direction.
struct Segment {
    /// Start and end along the baseline.
    s0: f32,
    s1: f32,
    /// Baseline position across the writing direction.
    t: f32,
    em: f32,
    words: u32,
    /// The text, without the white space it was painted with at
    /// either end …
    text: String,
    /// … which is remembered here, so that pieces joined later keep
    /// their word boundary.
    space_before: bool,
    space_after: bool,
}

/// Assemble the runs of ONE page into text.
///
/// With [`TextOrder::Stream`] the lines come out in painting order
/// (see [`crate::reader::assemble_text`]); otherwise in the geometric
/// reading order described in the [module documentation](self).
pub fn layout_page_text(runs: &[TextRun], opts: &TextLayoutOptions) -> String {
    let filtered: Vec<TextRun>;
    let runs = if opts.include_invisible {
        runs
    } else {
        filtered = runs
            .iter()
            .filter(|r| r.render_mode != TextRenderMode::Invisible)
            .cloned()
            .collect();
        &filtered
    };
    let lines = stream_lines(runs);
    let mut rows: Vec<String> = Vec::new();
    if opts.order == TextOrder::Stream {
        rows.extend(lines.iter().map(|l| line_text(l)));
    } else {
        // One layout per writing direction, most text first.
        let mut groups: Vec<(i32, Vec<Segment>)> = Vec::new();
        for line in &lines {
            let key = direction_key(line[0]);
            let slot = match groups.iter().position(|(k, _)| *k == key) {
                Some(i) => i,
                None => {
                    groups.push((key, Vec::new()));
                    groups.len() - 1
                }
            };
            cut_segments(line, &mut groups[slot].1);
        }
        // Stable: equal weights keep first-painted first.
        groups.sort_by_key(|(_, segs)| {
            std::cmp::Reverse(segs.iter().map(|s| s.text.len()).sum::<usize>())
        });
        for (_, segs) in &mut groups {
            merge_row_neighbours(segs);
            let segs = &*segs;
            let mut order: Vec<Vec<usize>> = Vec::new();
            read_region(segs, (0..segs.len()).collect(), 0, &mut order);
            for row in order {
                let mut text = String::new();
                for i in row {
                    if !text.is_empty() {
                        text.push(' ');
                    }
                    text.push_str(&segs[i].text);
                }
                rows.push(text);
            }
        }
    }
    finish_rows(rows, opts)
}

/// Clean-ups shared by every order: hyphen joins, ligatures, bidi.
pub(crate) fn finish_rows(mut rows: Vec<String>, opts: &TextLayoutOptions) -> String {
    rows.retain(|r| !r.is_empty());
    if opts.join_hyphenated {
        join_hyphenated_rows(&mut rows);
    }
    let mut out = String::new();
    for (i, row) in rows.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let row = reorder_bidi_line(row);
        if opts.expand_ligatures {
            push_expanding_ligatures(&mut out, &row);
        } else {
            out.push_str(&row);
        }
    }
    out
}

/// The frame of a run: the unit direction its text advances in, and
/// the unit direction lines are stacked *against* (successive lines
/// stand at decreasing coordinates along it). For horizontal writing
/// that is the glyphs' up direction — the text matrix's second basis
/// vector (times the sign of the font size), which stays right when
/// the matrix mirrors the text; for
/// vertical writing, where columns follow one another right to left,
/// the matrix's first basis vector.
fn frame(run: &TextRun) -> ((f32, f32), (f32, f32)) {
    let (u, perp) = run_axes(run);
    let m = run.text_matrix;
    let (vx, vy) = if run.is_vertical() {
        (m[0], m[1])
    } else if run.font_size < 0.0 {
        // A negative font size turns the glyphs over (producers pair
        // it with a mirrored matrix): up is the other way.
        (-m[2], -m[3])
    } else {
        (m[2], m[3])
    };
    let len = (vx * vx + vy * vy).sqrt();
    if len > 0.0 && len.is_finite() {
        (u, (vx / len, vy / len))
    } else {
        (u, perp)
    }
}

/// Writing direction of a line, quantised to whole degrees, and
/// whether its frame is mirrored.
fn direction_key(run: &TextRun) -> i32 {
    let (u, v) = frame(run);
    let deg = u.1.atan2(u.0).to_degrees().round() as i32;
    let mirrored = u.0 * v.1 - u.1 * v.0 < 0.0;
    deg.rem_euclid(360) + if mirrored { 360 } else { 0 }
}

/// Cut one painted line into segments at wide gaps.
fn cut_segments(line: &[&TextRun], out: &mut Vec<Segment>) {
    let (u, v) = frame(line[0]);
    let mut start = 0;
    for i in 1..=line.len() {
        let cut = i == line.len() || {
            let (gap, em) = run_gap(line[i - 1], line[i]);
            gap > SEGMENT_GAP_EM * em
        };
        if !cut {
            continue;
        }
        let piece = &line[start..i];
        start = i;
        let raw = line_text(piece);
        let text = raw.trim();
        if text.is_empty() {
            continue;
        }
        let space_before = raw.starts_with(char::is_whitespace);
        // `line_text` drops trailing spaces; look at the run itself.
        let space_after = raw.ends_with(char::is_whitespace)
            || piece
                .last()
                .is_some_and(|r| r.text.ends_with(char::is_whitespace));
        let text = text.to_owned();
        let mut s0 = f32::INFINITY;
        let mut s1 = f32::NEG_INFINITY;
        let mut em = 0.0f32;
        let mut t = 0.0f32;
        for r in piece {
            let a = dot(r.position, u);
            let b = dot(r.end(), u);
            s0 = s0.min(a.min(b));
            s1 = s1.max(a.max(b));
            // The baseline of the line is that of its largest text
            // (a superscript rides above it).
            let e = r.em().abs();
            if e > em {
                em = e;
                t = dot(r.position, v);
            }
        }
        if !(s0.is_finite() && s1.is_finite() && t.is_finite()) {
            continue;
        }
        let em = if em.is_finite() && em > 0.0 { em } else { 1.0 };
        // A font without metrics has no advance: give the text a
        // nominal half em per character so it still has an extent.
        if s1 - s0 < 0.01 * em {
            s1 = s0 + 0.5 * em * text.chars().count() as f32;
        }
        out.push(Segment {
            s0,
            s1,
            t,
            em,
            words: text.split_whitespace().count() as u32,
            text,
            space_before,
            space_after,
        });
    }
}

/// Join segments that continue one another on a baseline.
///
/// A line is not always painted left to right in one go: link text is
/// often shown after the body text it sits in, a right-aligned number
/// digit group by digit group from the right. Two segments on one
/// baseline closer than [`ROW_MERGE_GAP_EM`] are one piece of text —
/// glued when they touch, a space between them otherwise.
fn merge_row_neighbours(segs: &mut Vec<Segment>) {
    if segs.len() < 2 {
        return;
    }
    let mut order: Vec<usize> = (0..segs.len()).collect();
    order.sort_by(|a, b| {
        segs[*b]
            .t
            .total_cmp(&segs[*a].t)
            .then(segs[*a].s0.total_cmp(&segs[*b].s0))
    });
    let mut taken: Vec<Option<Segment>> = std::mem::take(segs).into_iter().map(Some).collect();
    let mut i = 0;
    while i < order.len() {
        // Segments within a hair of the head's baseline, by `s0`.
        let head_t = taken[order[i]].as_ref().map_or(0.0, |s| s.t);
        let head_em = taken[order[i]].as_ref().map_or(1.0, |s| s.em);
        let mut j = i + 1;
        while j < order.len()
            && taken[order[j]]
                .as_ref()
                .is_some_and(|s| head_t - s.t <= ROW_MERGE_TOLERANCE_EM * head_em.min(s.em))
        {
            j += 1;
        }
        let mut row: Vec<Segment> = order[i..j]
            .iter()
            .filter_map(|k| taken[*k].take())
            .collect();
        row.sort_by(|a, b| a.s0.total_cmp(&b.s0));
        let mut cur: Option<Segment> = None;
        for seg in row {
            match cur.as_mut() {
                Some(c) => {
                    let em = c.em.min(seg.em);
                    let gap = seg.s0 - c.s1;
                    if gap >= -ROW_MERGE_OVERLAP_EM * em && gap <= ROW_MERGE_GAP_EM * em {
                        if gap >= crate::reader::text::WORD_GAP_EM * em
                            || c.space_after
                            || seg.space_before
                        {
                            c.text.push(' ');
                        }
                        c.text.push_str(&seg.text);
                        c.space_after = seg.space_after;
                        c.s1 = c.s1.max(seg.s1);
                        if seg.em > c.em {
                            c.em = seg.em;
                            c.t = seg.t;
                        }
                        c.words = c.text.split_whitespace().count() as u32;
                    } else {
                        segs.push(std::mem::replace(c, seg));
                    }
                }
                None => cur = Some(seg),
            }
        }
        segs.extend(cur);
        i = j;
    }
}

/// Order the segments `idx` of a region into output rows.
fn read_region(segs: &[Segment], idx: Vec<usize>, depth: u32, out: &mut Vec<Vec<usize>>) {
    if idx.len() >= 6
        && idx.len() <= MAX_COLUMN_SEARCH
        && depth < MAX_COLUMN_DEPTH
        && let Some((left, spanners, right)) = find_gutter(segs, &idx)
    {
        // Spanners, top to bottom, delimit the sections.
        let mut spanners = spanners;
        spanners.sort_by(|a, b| segs[*b].t.total_cmp(&segs[*a].t));
        let mut left = left;
        let mut right = right;
        for k in 0..=spanners.len() {
            let floor = spanners.get(k).map_or(f32::NEG_INFINITY, |i| segs[*i].t);
            let (l_here, l_rest): (Vec<usize>, Vec<usize>) =
                left.into_iter().partition(|i| segs[*i].t > floor);
            let (r_here, r_rest): (Vec<usize>, Vec<usize>) =
                right.into_iter().partition(|i| segs[*i].t > floor);
            left = l_rest;
            right = r_rest;
            if !l_here.is_empty() {
                read_region(segs, l_here, depth + 1, out);
            }
            if !r_here.is_empty() {
                read_region(segs, r_here, depth + 1, out);
            }
            if let Some(&i) = spanners.get(k) {
                // Column segments on the spanner's own baseline are
                // part of its row.
                let tol = ROW_TOLERANCE_EM * segs[i].em;
                let on_row = |j: &usize| segs[i].t - segs[*j].t <= tol;
                let mut row = vec![i];
                let (mates, rest): (Vec<usize>, Vec<usize>) = left.into_iter().partition(on_row);
                row.extend(mates);
                left = rest;
                let (mates, rest): (Vec<usize>, Vec<usize>) = right.into_iter().partition(on_row);
                row.extend(mates);
                right = rest;
                row.sort_by(|a, b| segs[*a].s0.total_cmp(&segs[*b].s0));
                out.push(row);
            }
        }
        return;
    }
    read_rows(segs, idx, out);
}

/// Top to bottom, segments on one baseline left to right.
fn read_rows(segs: &[Segment], mut idx: Vec<usize>, out: &mut Vec<Vec<usize>>) {
    idx.sort_by(|a, b| segs[*b].t.total_cmp(&segs[*a].t));
    let mut i = 0;
    while i < idx.len() {
        let head = &segs[idx[i]];
        let mut j = i + 1;
        while j < idx.len() {
            let s = &segs[idx[j]];
            if head.t - s.t > ROW_TOLERANCE_EM * head.em.min(s.em) {
                break;
            }
            j += 1;
        }
        let mut row = idx[i..j].to_vec();
        row.sort_by(|a, b| segs[*a].s0.total_cmp(&segs[*b].s0));
        out.push(row);
        i = j;
    }
}

/// Median of a non-empty list (upper median).
fn median(mut v: Vec<f32>) -> f32 {
    v.sort_by(f32::total_cmp);
    v[v.len() / 2]
}

/// `(left, spanners, right)` when the region has a column gutter.
fn find_gutter(segs: &[Segment], idx: &[usize]) -> Option<(Vec<usize>, Vec<usize>, Vec<usize>)> {
    let n = idx.len();
    let em = median(idx.iter().map(|i| segs[*i].em).collect());
    let eps = 0.05 * em;
    let overhang = COLUMN_OVERHANG_EM * em;
    let mut starts: Vec<f32> = idx.iter().map(|i| segs[*i].s0).collect();
    starts.sort_by(f32::total_cmp);
    // Candidate column edges: positions where three or more segments
    // start. Ranked by how few segments reach across them.
    let mut candidates: Vec<(usize, usize, f32)> = Vec::new();
    let mut k = 0;
    while k < starts.len() {
        let edge = starts[k];
        let mut m = k + 1;
        while m < starts.len() && starts[m] - edge <= eps {
            m += 1;
        }
        let support = m - k;
        k = m;
        if support < 3 {
            continue;
        }
        let crossing = idx
            .iter()
            .filter(|i| segs[**i].s0 < edge - eps && segs[**i].s1 > edge + overhang)
            .count();
        candidates.push((crossing, support, edge));
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    for &(_, _, edge) in candidates.iter().take(8) {
        let mut left = Vec::new();
        let mut right = Vec::new();
        let mut spanners = Vec::new();
        for &i in idx {
            let s = &segs[i];
            if s.s0 >= edge - eps {
                right.push(i);
            } else if s.s1 <= edge + overhang {
                left.push(i);
            } else {
                spanners.push(i);
            }
        }
        if left.len() < 3 || right.len() < 3 {
            continue;
        }
        // Most of the left side must stop short of the edge: that is
        // the gutter.
        let mut ends: Vec<f32> = left.iter().map(|i| segs[*i].s1).collect();
        ends.sort_by(f32::total_cmp);
        if edge - ends[(ends.len() * 3) / 4] < GUTTER_MIN_EM * em {
            continue;
        }
        // Columns hold most of the region; what reaches across them is
        // the exception.
        if (left.len() + right.len()) * 5 < n * 2
            || spanners.len() > 2 * left.len().min(right.len())
        {
            continue;
        }
        if side_by_side_rows(segs, &left, &right, &spanners) < 3 {
            continue;
        }
        let running =
            |side: &[usize]| median(side.iter().map(|i| segs[*i].words as f32).collect()) >= 3.0;
        if (running(&left) && running(&right)) || !baselines_aligned(segs, &left, &right) {
            return Some((left, spanners, right));
        }
    }
    None
}

/// Rows the two sides have next to each other: over the sections the
/// spanners delimit, the sum of the smaller side's segment count.
fn side_by_side_rows(
    segs: &[Segment],
    left: &[usize],
    right: &[usize],
    spanners: &[usize],
) -> usize {
    let mut cuts: Vec<f32> = spanners.iter().map(|i| segs[*i].t).collect();
    cuts.sort_by(|a, b| b.total_cmp(a));
    let section = |t: f32| cuts.partition_point(|c| *c >= t);
    let mut l = vec![0usize; cuts.len() + 1];
    let mut r = vec![0usize; cuts.len() + 1];
    for i in left {
        l[section(segs[*i].t)] += 1;
    }
    for i in right {
        r[section(segs[*i].t)] += 1;
    }
    l.iter().zip(&r).map(|(a, b)| *a.min(b)).sum()
}

/// Whether most left segments have a right segment on their baseline
/// (the signature of table rows rather than independent columns).
fn baselines_aligned(segs: &[Segment], left: &[usize], right: &[usize]) -> bool {
    let mut ts: Vec<f32> = right.iter().map(|i| segs[*i].t).collect();
    ts.sort_by(f32::total_cmp);
    let aligned = left
        .iter()
        .filter(|i| {
            let s = &segs[**i];
            let tol = 0.15 * s.em;
            let k = ts.partition_point(|t| *t < s.t - tol);
            ts.get(k).is_some_and(|t| *t <= s.t + tol)
        })
        .count();
    aligned * 10 >= left.len() * 3
}

/// Join words hyphenated across row ends: the hyphen goes, and the
/// rest of the word moves up from the next row.
fn join_hyphenated_rows(rows: &mut Vec<String>) {
    let mut out: Vec<String> = Vec::with_capacity(rows.len());
    for row in rows.drain(..) {
        let Some(prev) = out.last_mut().filter(|prev| breaks_word(prev, &row)) else {
            out.push(row);
            continue;
        };
        prev.pop();
        let word_end = row.find(char::is_whitespace).unwrap_or(row.len());
        prev.push_str(&row[..word_end]);
        let rest = row[word_end..].trim_start();
        if !rest.is_empty() {
            out.push(rest.to_owned());
        }
    }
    *rows = out;
}

/// Whether `row` ends in a hyphen that splits a word continued on
/// `next`: a letter before the hyphen, a lowercase letter after it.
fn breaks_word(row: &str, next: &str) -> bool {
    let mut back = row.chars().rev();
    matches!(back.next(), Some('-' | '\u{ad}' | '\u{2010}'))
        && back.next().is_some_and(char::is_alphabetic)
        && next.chars().next().is_some_and(char::is_lowercase)
}

/// Append `text`, spelling out U+FB00–U+FB06.
fn push_expanding_ligatures(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '\u{fb00}' => out.push_str("ff"),
            '\u{fb01}' => out.push_str("fi"),
            '\u{fb02}' => out.push_str("fl"),
            '\u{fb03}' => out.push_str("ffi"),
            '\u{fb04}' => out.push_str("ffl"),
            '\u{fb05}' => out.push_str("ſt"),
            '\u{fb06}' => out.push_str("st"),
            _ => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str, x: f32, y: f32) -> TextRun {
        // 10-unit em, half an em per character.
        TextRun::new(text, (x, y), "F", 10.0).with_advance((5.0 * text.chars().count() as f32, 0.0))
    }

    #[test]
    fn two_columns_painted_row_by_row_read_column_by_column() {
        let mut runs = Vec::new();
        for i in 0..5 {
            let y = 700.0 - 12.0 * i as f32;
            runs.push(run(&format!("left column line {i} goes here"), 50.0, y));
            runs.push(run(
                &format!("right column line {i} goes here"),
                320.0,
                y + 3.0,
            ));
        }
        let text = layout_page_text(&runs, &TextLayoutOptions::new());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 10);
        assert!(lines[..5].iter().all(|l| l.starts_with("left")));
        assert!(lines[5..].iter().all(|l| l.starts_with("right")));
    }

    #[test]
    fn title_and_footer_span_the_columns() {
        let mut runs = vec![run("page footer in the middle of the page", 150.0, 40.0)];
        for i in 0..4 {
            let y = 700.0 - 12.0 * i as f32;
            runs.push(run(&format!("right text line number {i}"), 320.0, y));
        }
        for i in 0..4 {
            let y = 700.0 - 12.0 * i as f32;
            runs.push(run(&format!("left text line number {i}"), 50.0, y));
        }
        runs.push(run(
            "A title that runs across both of the columns of the page",
            50.0,
            740.0,
        ));
        let text = layout_page_text(&runs, &TextLayoutOptions::new());
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("A title"));
        assert!(lines[1].starts_with("left"));
        assert!(lines[5].starts_with("right"));
        assert!(lines[9].starts_with("page footer"));
    }

    #[test]
    fn table_rows_stay_together() {
        let mut runs = Vec::new();
        // Painted column by column.
        for i in 0..5 {
            runs.push(run(&format!("key{i}"), 50.0, 700.0 - 12.0 * i as f32));
        }
        for i in 0..5 {
            runs.push(run(&format!("value{i}"), 200.0, 700.0 - 12.0 * i as f32));
        }
        let text = layout_page_text(&runs, &TextLayoutOptions::new());
        assert_eq!(
            text,
            "key0 value0\nkey1 value1\nkey2 value2\nkey3 value3\nkey4 value4"
        );
    }

    #[test]
    fn hyphenated_line_end_joins() {
        let runs = vec![
            run("the format is speci-", 50.0, 700.0),
            run("fied in the annex and is well-", 50.0, 688.0),
            run("Known", 50.0, 676.0),
        ];
        let text = layout_page_text(&runs, &TextLayoutOptions::new());
        assert_eq!(
            text,
            "the format is specified\nin the annex and is well-\nKnown"
        );
        let kept = layout_page_text(&runs, &TextLayoutOptions::new().with_join_hyphenated(false));
        assert!(kept.starts_with("the format is speci-\nfied"));
    }

    #[test]
    fn ligatures_and_invisible_text_options() {
        let runs = vec![
            run("e\u{fb03}cient \u{fb01}le", 50.0, 700.0),
            run("hidden", 50.0, 680.0).with_render_mode(TextRenderMode::Invisible),
        ];
        assert_eq!(
            layout_page_text(&runs, &TextLayoutOptions::new()),
            "efficient file\nhidden"
        );
        assert_eq!(
            layout_page_text(
                &runs,
                &TextLayoutOptions::new()
                    .with_include_invisible(false)
                    .with_expand_ligatures(false)
            ),
            "e\u{fb03}cient \u{fb01}le"
        );
    }

    #[test]
    fn rotated_text_is_laid_out_apart() {
        // A margin note rotated a quarter turn, painted between lines.
        let up = [0.0, 1.0, -1.0, 0.0, 0.0, 0.0];
        let runs = vec![
            run("first line of the page", 50.0, 700.0),
            run("margin", 20.0, 300.0).with_text_matrix(up),
            run("second line of the page", 50.0, 688.0),
        ];
        let text = layout_page_text(&runs, &TextLayoutOptions::new());
        assert_eq!(
            text,
            "first line of the page\nsecond line of the page\nmargin"
        );
    }

    #[test]
    fn stream_order_is_kept_on_request() {
        let runs = vec![run("footer", 50.0, 40.0), run("body", 50.0, 700.0)];
        let stream = TextLayoutOptions::new().with_order(TextOrder::Stream);
        assert_eq!(layout_page_text(&runs, &stream), "footer\nbody");
        assert_eq!(
            layout_page_text(&runs, &TextLayoutOptions::new()),
            "body\nfooter"
        );
    }
}
