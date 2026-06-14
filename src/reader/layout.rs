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
use crate::reader::text::{extract_text, extract_text_marked, TextRun};

// ────────────────────────── public surface ──────────────────────────

/// Which path produced the [`ReadingOrderText`] runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
pub struct ReadingOrderText {
    pub mode: LayoutMode,
    pub runs: Vec<TextRun>,
}

impl ReadingOrderText {
    /// Concatenate every run's text with a space between them — the
    /// reading-order analogue of
    /// [`crate::reader::PdfTextExtraction::flat_text`].
    pub fn flat_text(&self) -> String {
        self.runs
            .iter()
            .map(|r| r.text.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl<'a> DocumentReader<'a> {
    /// Round-29: extract every text run in *logical* reading order
    /// per the document's `/StructTreeRoot` walk (ISO 32000-1 §14.8).
    /// See [`read_in_logical_order`] for the full contract.
    pub fn read_in_logical_order(&mut self) -> Result<ReadingOrderText, PdfError> {
        read_in_logical_order(self)
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
    let mut visited = HashSet::new();
    let mut ctx = StructWalkCtx {
        out: &mut out,
        buckets: &buckets,
        visited: &mut visited,
        cur_page: None,
        depth: 0,
    };
    walk_struct_node(reader, &str_root_dict, &mut ctx)?;

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

struct StructWalkCtx<'a> {
    out: &'a mut Vec<TextRun>,
    buckets: &'a HashMap<(u32, u32), Vec<TextRun>>,
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
            if let (Some(pg), Ok(mcid_u)) = (ctx.cur_page, u32::try_from(mcid)) {
                if let Some(runs) = ctx.buckets.get(&(pg, mcid_u)) {
                    ctx.out.extend(runs.iter().cloned());
                }
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
                    if let (Some(pg), Some(mcid)) = (pg, mcid) {
                        if let Some(runs) = ctx.buckets.get(&(pg, mcid)) {
                            ctx.out.extend(runs.iter().cloned());
                        }
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
                TextRun {
                    text: "Hello".into(),
                    position: (0.0, 0.0),
                    font_name: "F0".into(),
                    font_size: 12.0,
                    render_mode: crate::reader::text::TextRenderMode::Fill,
                    text_rise: 0.0,
                },
                TextRun {
                    text: "World".into(),
                    position: (40.0, 0.0),
                    font_name: "F0".into(),
                    font_size: 12.0,
                    render_mode: crate::reader::text::TextRenderMode::Fill,
                    text_rise: 0.0,
                },
            ],
        };
        assert_eq!(r.flat_text(), "Hello World");
    }
}
