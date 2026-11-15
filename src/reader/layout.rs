//! Reading-order layout pass for Tagged PDFs (round 29).
//!
//! Plain raster (content-stream) order does not give logical reading
//! order for multi-column / multi-block layouts: the painter would
//! lay column 1's first row, column 2's first row, then column 1's
//! second row, etc., as it raster-scanned the page from top to bottom.
//! Tagged PDF (ISO 32000-1 §14.8) factors logical structure out of
//! visual layout: the catalog's `/StructTreeRoot` carries a tree of
//! `/StructElem`s (sections, paragraphs, list items, table rows…)
//! whose leaves are `MarkedContentReference`s (MCIDs) — integers that
//! cross-reference the page's `/Span <</MCID n>> BDC … EMC`-bracketed
//! content-stream slices. Walking the tree in document order and
//! resolving each MCID to its painted text run gives us the
//! author-intended reading order, regardless of where the runs
//! actually appear on paper.
//!
//! This module's [`read_in_logical_order`] performs that walk:
//!
//! 1. Open the catalog → find `/StructTreeRoot` (if absent, return a
//!    `Raster`-tagged result that delegates to
//!    [`crate::reader::extract_text`]).
//! 2. Walk every page in document order, run the round-22 text walker
//!    with MCID tracking enabled (round-29 addition), and bucket each
//!    [`crate::reader::text::MarkedTextRun`] by `(page_obj_num, mcid)`.
//! 3. Recurse the StructTreeRoot's `/K` tree. For every leaf that's
//!    either a bare integer (MCID into the parent's `/Pg` page) or a
//!    `<</Type /MCR /Pg n /MCID m>>` dict (MCID into the named page),
//!    look up the corresponding bucket and emit its runs in
//!    accumulation order. For every kid that's a `<</Type /StructElem
//!    …>>` (or an indirect ref to one), recurse into its `/K`.
//!
//! The walker is permissive — unknown `/S` (structure-type) names are
//! recursed into anyway (they're decorative — the spec encourages
//! user-defined types — and any text under them still belongs in
//! logical order). `/OBJR` (object reference) leaves are skipped:
//! they reference annotations, not content, so they carry no text.
//!
//! ## Provenance
//!
//! ISO 32000-1:2008 §14.6 (Marked Content), §14.7 (Logical Structure),
//! §14.8 (Tagged PDF). No third-party PDF library was consulted.

use std::collections::{HashMap, HashSet};

use crate::error::PdfError;
use crate::objects::{Object, ObjectId};
use crate::reader::document::DocumentReader;
use crate::reader::reading::{TextLayoutOptions, TextOrder, layout_page_text};
use crate::reader::text::{TextRun, extract_text, extract_text_marked};

// ────────────────────────── public surface ──────────────────────────

/// Which path produced the [`ReadingOrderText`] runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LayoutMode {
    /// The document carries a `/StructTreeRoot` whose `/K` tree was
    /// walked to produce logical reading order. Multi-column / table
    /// layouts come out in author-intended sequence.
    Tagged,
    /// The document does not have a structure tree (or had one that
    /// was empty / unwalkable); the runs are the same raster-order
    /// runs [`crate::reader::extract_text`] would have produced.
    Raster,
}

/// Output of [`read_in_logical_order`]: the run sequence plus the
/// flag that tells the caller which path produced them.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct ReadingOrderText {
    pub mode: LayoutMode,
    pub runs: Vec<TextRun>,
}

impl ReadingOrderText {
    /// Concatenate every run's text with a space between them — the
    /// reading-order analogue of
    /// [`crate::reader::PdfTextExtraction::flat_text`].
    pub fn flat_text(&self) -> String {
        crate::reader::text::assemble_text(&self.runs)
    }
}

impl<'a> DocumentReader<'a> {
    /// Round-29: extract every text run in *logical* reading order
    /// per the document's `/StructTreeRoot` walk (ISO 32000-1 §14.8).
    /// See [`read_in_logical_order`] for the full contract.
    pub fn read_in_logical_order(&mut self) -> Result<ReadingOrderText, PdfError> {
        read_in_logical_order(self)
    }

    /// The document's text, assembled as `opts` asks.
    ///
    /// With [`TextOrder::Structure`] (the default) a Tagged PDF is
    /// read in the order of its logical structure tree (ISO 32000-1
    /// §14.8), each page's artifacts (running headers, page numbers)
    /// after its logical content, and any other document in geometric
    /// reading order, page by page; see
    /// [`TextLayoutOptions`] for the other choices.
    ///
    /// ```no_run
    /// use oxideav_pdf::reader::{DocumentReader, TextLayoutOptions};
    /// let bytes = std::fs::read("in.pdf").unwrap();
    /// let mut doc = DocumentReader::open(&bytes).unwrap();
    /// let text = doc.text(&TextLayoutOptions::new()).unwrap();
    /// ```
    pub fn text(&mut self, opts: &TextLayoutOptions) -> Result<String, PdfError> {
        if opts.order() == TextOrder::Structure
            && let Some(text) = structure_text(self, opts)?
        {
            return Ok(text);
        }
        Ok(self.text_extraction()?.text_with(opts))
    }
}

/// Walk the document's logical structure tree and emit text runs in
/// reading order. Falls back to raster order when no `/StructTreeRoot`
/// is present.
pub fn read_in_logical_order(
    reader: &mut DocumentReader<'_>,
) -> Result<ReadingOrderText, PdfError> {
    // Resolve catalog → StructTreeRoot (if any).
    let root_id = reader.xref().root()?;
    let catalog_obj = reader.resolve(root_id)?;
    let Object::Dict(catalog) = catalog_obj else {
        // Malformed catalog — fall back to raster.
        let runs = extract_text(reader)?.runs;
        return Ok(ReadingOrderText {
            mode: LayoutMode::Raster,
            runs,
        });
    };
    let str_root_obj = catalog
        .entries()
        .iter()
        .find(|(k, _)| k == "StructTreeRoot")
        .map(|(_, v)| v.clone());
    let str_root_obj = match str_root_obj {
        Some(o) => o,
        None => {
            let runs = extract_text(reader)?.runs;
            return Ok(ReadingOrderText {
                mode: LayoutMode::Raster,
                runs,
            });
        }
    };
    let str_root = reader.deref(str_root_obj)?;
    let Object::Dict(str_root_dict) = str_root else {
        let runs = extract_text(reader)?.runs;
        return Ok(ReadingOrderText {
            mode: LayoutMode::Raster,
            runs,
        });
    };

    // Bucket every MCID-tagged text run by (page_obj_num, mcid).
    // Runs that have NO MCID (decorative `BMC … EMC` blocks, or shows
    // outside any marked-content bracket) are dropped: the spec
    // promises every Tagged-PDF text-show is inside a marked-content
    // sequence, and untagged paint outside the structure tree wouldn't
    // have a logical position to slot into anyway.
    let marked = extract_text_marked(reader)?;
    let mut buckets: HashMap<(u32, u32), Vec<TextRun>> = HashMap::new();
    for mr in marked.runs {
        if let Some(mcid) = mr.mcid {
            buckets
                .entry((mr.page_obj_num, mcid))
                .or_default()
                .push(mr.run);
        }
    }

    // Walk the structure tree.
    let mut out = Vec::new();
    for key in logical_keys(reader, &str_root_dict)? {
        if let Some(runs) = buckets.get(&key) {
            out.extend(runs.iter().cloned());
        }
    }

    // If the tree walk produced *no* runs but we did see tagged runs,
    // the structure tree is empty / malformed — fall back to raster
    // order rather than returning empty output.
    if out.is_empty() && !buckets.is_empty() {
        let runs = extract_text(reader)?.runs;
        return Ok(ReadingOrderText {
            mode: LayoutMode::Raster,
            runs,
        });
    }

    Ok(ReadingOrderText {
        mode: LayoutMode::Tagged,
        runs: out,
    })
}

// ────────────────────────── walker ──────────────────────────

/// The marked-content items `(page object number, MCID)` the
/// structure tree references, in logical order (§14.7.2: the order of
/// the `/K` entries, depth first).
fn logical_keys(
    reader: &mut DocumentReader<'_>,
    str_root: &crate::objects::Dict,
) -> Result<Vec<(u32, u32)>, PdfError> {
    let mut out = Vec::new();
    let mut visited = HashSet::new();
    let mut ctx = StructWalkCtx {
        out: &mut out,
        visited: &mut visited,
        cur_page: None,
        depth: 0,
    };
    walk_struct_node(reader, str_root, &mut ctx)?;
    Ok(out)
}

/// The document's `/StructTreeRoot` dictionary, when it has one.
fn struct_tree_root(reader: &mut DocumentReader<'_>) -> Option<crate::objects::Dict> {
    let root_id = reader.xref().root().ok()?;
    let Ok(Object::Dict(catalog)) = reader.resolve(root_id) else {
        return None;
    };
    let entry = catalog
        .entries()
        .iter()
        .find(|(k, _)| k == "StructTreeRoot")
        .map(|(_, v)| v.clone())?;
    match reader.deref(entry) {
        Ok(Object::Dict(d)) => Some(d),
        _ => None,
    }
}

/// The document's text in the order of its logical structure tree
/// (ISO 32000-1 §14.7, §14.8), or `None` when the document is not
/// tagged or its tree does not account for most of the text (in which
/// case the caller lays the pages out geometrically).
///
/// The marked-content items come out in the order the tree references
/// them. Text the tree does not reference — artifacts (§14.8.2.2 —
/// running headers, page numbers; dropped when the options say so)
/// and unmarked content — is laid out geometrically after the logical
/// content of its page.
pub(crate) fn structure_text(
    reader: &mut DocumentReader<'_>,
    opts: &TextLayoutOptions,
) -> Result<Option<String>, PdfError> {
    let Some(root) = struct_tree_root(reader) else {
        return Ok(None);
    };
    let marked = extract_text_marked(reader)?;
    let keys = logical_keys(reader, &root)?;
    if keys.is_empty() {
        return Ok(None);
    }
    // Runs of each marked-content item, by index into `marked.runs`.
    let mut buckets: HashMap<(u32, u32), Vec<usize>> = HashMap::new();
    for (i, mr) in marked.runs.iter().enumerate() {
        if let Some(mcid) = mr.mcid
            && !mr.artifact
        {
            buckets.entry((mr.page_obj_num, mcid)).or_default().push(i);
        }
    }
    let weight = |i: usize| marked.runs[i].run.text.trim().chars().count();
    let mut placed = vec![false; marked.runs.len()];
    // (page index, runs) groups in logical order: consecutive items of
    // one page form one group.
    let mut groups: Vec<(u32, Vec<TextRun>)> = Vec::new();
    let mut in_tree = 0usize;
    for key in keys {
        let Some(items) = buckets.remove(&key) else {
            continue;
        };
        for i in items {
            let mr = &marked.runs[i];
            placed[i] = true;
            in_tree += weight(i);
            match groups.last_mut() {
                Some((page, runs)) if *page == mr.page_index => runs.push(mr.run.clone()),
                _ => groups.push((mr.page_index, vec![mr.run.clone()])),
            }
        }
    }
    let content: usize = (0..marked.runs.len())
        .filter(|i| !marked.runs[*i].artifact)
        .map(weight)
        .sum();
    // A tree that leaves most of the text out is not a description of
    // this document's reading order.
    if in_tree * 2 < content {
        return Ok(None);
    }
    // Text outside the tree, per page.
    let mut loose: HashMap<u32, Vec<TextRun>> = HashMap::new();
    let mut loose_pages: Vec<u32> = Vec::new();
    for (i, mr) in marked.runs.iter().enumerate() {
        if !placed[i] && (opts.include_artifacts() || !mr.artifact) {
            let slot = loose.entry(mr.page_index).or_default();
            if slot.is_empty() {
                loose_pages.push(mr.page_index);
            }
            slot.push(mr.run.clone());
        }
    }
    let stream = opts.clone().with_order(TextOrder::Stream);
    let geometric = opts.clone().with_order(TextOrder::Geometric);
    let mut parts: Vec<String> = Vec::new();
    let mut flush_loose = |page: u32, parts: &mut Vec<String>| {
        if let Some(runs) = loose.remove(&page) {
            parts.push(layout_page_text(&runs, &geometric));
        }
    };
    // The page's loose text follows its last group.
    let last_group: HashMap<u32, usize> = groups
        .iter()
        .enumerate()
        .map(|(gi, (page, _))| (*page, gi))
        .collect();
    for (gi, (page, runs)) in groups.iter().enumerate() {
        parts.push(layout_page_text(runs, &stream));
        if last_group.get(page) == Some(&gi) {
            flush_loose(*page, &mut parts);
        }
    }
    for page in loose_pages {
        flush_loose(page, &mut parts);
    }
    parts.retain(|p| !p.is_empty());
    Ok(Some(parts.join("\n")))
}

struct StructWalkCtx<'a> {
    out: &'a mut Vec<(u32, u32)>,
    visited: &'a mut HashSet<ObjectId>,
    /// Current `/Pg` in scope. Inherited from ancestor StructElem when
    /// a child MCR doesn't override it. `None` when no ancestor has
    /// declared `/Pg` yet.
    cur_page: Option<u32>,
    /// Recursion-depth guard so a malformed cycle (which `visited`
    /// should already prevent for indirect refs) can't blow the stack
    /// via inline anonymous dicts.
    depth: u32,
}

const MAX_STRUCT_DEPTH: u32 = 64;

/// Bound on marked-content references collected from one tree.
const MAX_STRUCT_ITEMS: usize = 4_000_000;

fn walk_struct_node(
    reader: &mut DocumentReader<'_>,
    node: &crate::objects::Dict,
    ctx: &mut StructWalkCtx<'_>,
) -> Result<(), PdfError> {
    if ctx.depth > MAX_STRUCT_DEPTH {
        return Ok(());
    }
    ctx.depth += 1;

    // Pick up the node's own /Pg if it has one (StructElem-only field;
    // StructTreeRoot doesn't carry /Pg per ISO 32000-1 §14.7.2 Table
    // 322, but inheriting from any ancestor that does is the spec
    // contract for resolving bare-integer MCID kids).
    let saved_page = ctx.cur_page;
    if let Some(Object::Reference(pg_id)) = node
        .entries()
        .iter()
        .find(|(k, _)| k == "Pg")
        .map(|(_, v)| v.clone())
    {
        ctx.cur_page = Some(pg_id.number);
    }

    // Visit every kid in `/K` order. `/K` is one of:
    //   (a) an integer literal (an MCID into ctx.cur_page)
    //   (b) a dict (MCR / OBJR / nested StructElem)
    //   (c) an indirect reference to (b)
    //   (d) an array of (a)/(b)/(c)
    if let Some(k_obj) = node
        .entries()
        .iter()
        .find(|(k, _)| k == "K")
        .map(|(_, v)| v.clone())
    {
        visit_k(reader, k_obj, ctx)?;
    }

    ctx.cur_page = saved_page;
    ctx.depth -= 1;
    Ok(())
}

fn visit_k(
    reader: &mut DocumentReader<'_>,
    kid: Object,
    ctx: &mut StructWalkCtx<'_>,
) -> Result<(), PdfError> {
    match kid {
        Object::Integer(mcid) => {
            // Bare-integer MCID into ctx.cur_page.
            if let (Some(pg), Ok(mcid_u)) = (ctx.cur_page, u32::try_from(mcid))
                && ctx.out.len() < MAX_STRUCT_ITEMS
            {
                ctx.out.push((pg, mcid_u));
            }
            Ok(())
        }
        Object::Array(items) => {
            for item in items {
                visit_k(reader, item, ctx)?;
            }
            Ok(())
        }
        Object::Reference(id) => {
            if !ctx.visited.insert(id) {
                // Cycle guard.
                return Ok(());
            }
            let resolved = reader.resolve(id)?;
            // Don't re-visit the same indirect again from elsewhere
            // in the tree (would also be a cycle).
            visit_k(reader, resolved, ctx)?;
            Ok(())
        }
        Object::Dict(d) => {
            // Inspect /Type — could be:
            //   /MCR   — marked-content reference (leaf)
            //   /OBJR  — object reference (annotation; no text)
            //   /StructElem (or no /Type) — recurse into nested element
            let ty = d
                .entries()
                .iter()
                .find(|(k, _)| k == "Type")
                .and_then(|(_, v)| match v {
                    Object::Name(s) => Some(s.as_str()),
                    _ => None,
                });
            match ty {
                Some("MCR") => {
                    // Optional /Pg overrides ancestor.
                    let pg = match d
                        .entries()
                        .iter()
                        .find(|(k, _)| k == "Pg")
                        .map(|(_, v)| v.clone())
                    {
                        Some(Object::Reference(id)) => Some(id.number),
                        _ => ctx.cur_page,
                    };
                    let mcid = d
                        .entries()
                        .iter()
                        .find(|(k, _)| k == "MCID")
                        .and_then(|(_, v)| match v {
                            Object::Integer(n) => u32::try_from(*n).ok(),
                            _ => None,
                        });
                    if let (Some(pg), Some(mcid)) = (pg, mcid)
                        && ctx.out.len() < MAX_STRUCT_ITEMS
                    {
                        ctx.out.push((pg, mcid));
                    }
                    Ok(())
                }
                Some("OBJR") => {
                    // Object reference to an annotation — no text.
                    Ok(())
                }
                _ => {
                    // /StructElem (or a non-spec dict — recurse anyway).
                    walk_struct_node(reader, &d, ctx)
                }
            }
        }
        _ => Ok(()),
    }
}

// ────────────────────────── tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_text_joins_runs_with_spaces() {
        let r = ReadingOrderText {
            mode: LayoutMode::Tagged,
            runs: vec![
                TextRun::new("Hello", (0.0, 0.0), "F0", 12.0).with_advance((30.0, 0.0)),
                TextRun::new("World", (40.0, 0.0), "F0", 12.0).with_advance((30.0, 0.0)),
            ],
        };
        assert_eq!(r.flat_text(), "Hello World");
    }
}
