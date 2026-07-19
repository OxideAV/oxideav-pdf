//! Round-25 — PDF outline (bookmark) tree reader.
//!
//! Walks the catalog → `/Outlines` → tree of outline-item dicts per
//! ISO 32000-1 §12.3.3 (Tables 152 + 153) and surfaces each bookmark
//! as an [`OutlineNode`]. The doubly-linked-list `/First` / `/Last` /
//! `/Next` / `/Prev` shape collapses back to a parent-owned `children`
//! vec — the more usable form for callers walking a bookmark tree.
//!
//! Each leaf's `/Dest` (or `/A << /S /GoTo /D ... >>`) is parsed back
//! into an [`crate::outline::OutlineDestination`]; the page-ref
//! component is resolved against the document's page index list so
//! the destination's `page_index()` matches the writer-side input
//! (0-based, in `/Pages` tree DFS order).
//!
//! A **named** destination (`/Dest` as a Name or byte string,
//! §12.3.2.3) resolves through the document's named-destination
//! sources — the catalogue `/Dests` dictionary and the `/Names →
//! /Dests` name tree (round 418) — so `destination` carries the
//! structured form whenever the name is defined; `raw_dest` retains
//! the `named:<name>` text either way. Destinations this reader still
//! can't structure (remote go-to, unresolvable names, exotic action
//! chains) surface as `destination = None` with the original raw text
//! in [`OutlineNode::raw_dest`] — the tree is still walked end-to-end
//! rather than aborting, so callers that just want the title
//! hierarchy still get a usable result.
//!
//! Cycle detection: outline trees are required to be acyclic
//! (Table 153's /Parent / /Prev / /Next forms a strict tree), but a
//! malformed PDF could close a /Next cycle. The walker carries a
//! visited-set keyed by outline-item id and aborts the level when a
//! cycle is observed (returns the prefix walked so far).

use std::collections::{HashMap, HashSet};

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::outline::OutlineDestination;
use crate::reader::document::DocumentReader;
use crate::reader::named_dest::{named_dest_map, ResolvedNamedDest};
use crate::reader::nametree::decode_key_text;

/// The raw-name → resolved-destination lookaside built once per walk
/// (§12.3.2.3). Empty for the (common) document with no named dests.
type NamedDests = HashMap<Vec<u8>, ResolvedNamedDest>;

/// One node in the parsed outline tree.
#[derive(Debug, Clone)]
pub struct OutlineNode {
    /// `/Title` text (decoded — `LiteralString` PDFDocEncoding or
    /// `HexString` UTF-16BE with BOM).
    pub title: String,
    /// `/Dest` parsed back to a structured destination — an explicit
    /// array per Table 151, or (round 418) a named destination
    /// (§12.3.2.3 Name / byte string) resolved through the
    /// catalogue's named-destination sources. `/A` `/GoTo` action
    /// destinations decode the same way. `None` when the destination
    /// is absent, remote, or names an undefined entry; the raw text
    /// is retained in [`Self::raw_dest`].
    pub destination: Option<OutlineDestination>,
    /// Verbatim text of the `/Dest` entry — `named:<name>` for a
    /// named destination (kept even when `destination` resolved, so
    /// the name itself stays observable), or the raw array text when
    /// the structured parse fell back to `None`.
    pub raw_dest: Option<String>,
    /// `/Count` value when present. Per Table 153, a positive value
    /// means "open with N visible descendants"; a negative value
    /// means "closed with |N| hidden descendants"; absent means "no
    /// descendants".
    pub count: Option<i64>,
    /// Resolved children — the `/First` / `/Next` chain expanded back
    /// into a parent-owned vec.
    pub children: Vec<OutlineNode>,
}

impl OutlineNode {
    /// Sum-of-self-and-descendants — the "visible item" count a
    /// conforming reader would sum across an entirely-open tree.
    pub fn descendant_count(&self) -> usize {
        1 + self
            .children
            .iter()
            .map(Self::descendant_count)
            .sum::<usize>()
    }

    /// True when the outline item is open (per `/Count` sign).
    pub fn is_open(&self) -> bool {
        // Open ⇔ Count > 0 (or absent and there are no children).
        match self.count {
            Some(n) => n > 0,
            None => self.children.is_empty(),
        }
    }
}

/// Top-level outline-tree result.
///
/// `roots` carries the top-level bookmarks in Catalog order; `count`
/// is the value of the outline dict's own `/Count` entry per Table
/// 152 (when present).
#[derive(Debug, Clone, Default)]
pub struct PdfOutline {
    pub roots: Vec<OutlineNode>,
    pub count: Option<i64>,
}

/// Walk the catalog → `/Outlines` → tree, returning every bookmark
/// as a structured [`PdfOutline`]. Returns `Ok(None)` when the
/// catalog has no `/Outlines` entry (a perfectly valid bookmark-free
/// document).
pub fn outline(reader: &mut DocumentReader<'_>) -> Result<Option<PdfOutline>, PdfError> {
    // Build a 0-based page-index map so each `/Dest [<page-ref> ...]`
    // can resolve back to the same index the writer started from,
    // plus the §12.3.2.3 named-destination lookaside (empty when the
    // document defines none).
    let page_index_map = build_page_index_map(reader)?;
    let named_dests = named_dest_map(reader, &page_index_map)?;

    let root_id = reader.xref().root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog_dict) = catalog else {
        return Err(PdfError::other(format!(
            "PDF outline reader: /Root must be a dict (got {catalog:?})"
        )));
    };
    let outlines_obj = catalog_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Outlines")
        .map(|(_, v)| v.clone());
    let Some(outlines_obj) = outlines_obj else {
        return Ok(None);
    };
    let outline_root_id = match outlines_obj {
        Object::Reference(id) => id,
        _ => {
            return Err(PdfError::other(
                "PDF outline reader: /Outlines must be an indirect reference",
            ));
        }
    };

    let outline_root_dict = match reader.resolve(outline_root_id)? {
        Object::Dict(d) => d,
        other => {
            return Err(PdfError::other(format!(
                "PDF outline reader: outline root resolves to non-dict ({other:?})"
            )));
        }
    };

    let count = outline_root_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Count")
        .and_then(|(_, v)| match v {
            Object::Integer(n) => Some(*n),
            _ => None,
        });

    let first_id = outline_root_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "First")
        .and_then(|(_, v)| match v {
            Object::Reference(id) => Some(*id),
            _ => None,
        });

    let roots = match first_id {
        Some(first) => walk_level(reader, first, &page_index_map, &named_dests)?,
        None => Vec::new(),
    };

    Ok(Some(PdfOutline { roots, count }))
}

/// Walk one level of the outline, starting at `first_id` and
/// following `/Next` until exhausted (or a cycle is hit). Per item
/// also recurses through `/First` to collect the children.
fn walk_level(
    reader: &mut DocumentReader<'_>,
    first_id: ObjectId,
    page_index_map: &HashMap<u32, usize>,
    named_dests: &NamedDests,
) -> Result<Vec<OutlineNode>, PdfError> {
    let mut out = Vec::new();
    let mut visited: HashSet<u32> = HashSet::new();
    let mut cur = Some(first_id);
    while let Some(id) = cur {
        // Cycle guard — refuse to walk through a node we've already
        // emitted at this level.
        if !visited.insert(id.number) {
            break;
        }
        // Cap the level length defensively (a malformed PDF could
        // chain billions of items via /Next).
        if out.len() > 10_000 {
            break;
        }

        let item = match reader.resolve(id)? {
            Object::Dict(d) => d,
            other => {
                return Err(PdfError::other(format!(
                    "PDF outline reader: outline item {id:?} is not a dict (got {other:?})"
                )));
            }
        };

        let title = decode_text(
            item.entries()
                .iter()
                .find(|(k, _)| k == "Title")
                .map(|(_, v)| v),
        );
        let (destination, raw_dest) =
            decode_dest_or_action(reader, &item, page_index_map, named_dests)?;
        let count = item
            .entries()
            .iter()
            .find(|(k, _)| k == "Count")
            .and_then(|(_, v)| match v {
                Object::Integer(n) => Some(*n),
                _ => None,
            });

        let children = match item
            .entries()
            .iter()
            .find(|(k, _)| k == "First")
            .and_then(|(_, v)| match v {
                Object::Reference(id) => Some(*id),
                _ => None,
            }) {
            Some(child_first) => walk_level(reader, child_first, page_index_map, named_dests)?,
            None => Vec::new(),
        };

        out.push(OutlineNode {
            title: title.unwrap_or_default(),
            destination,
            raw_dest,
            count,
            children,
        });

        cur = item
            .entries()
            .iter()
            .find(|(k, _)| k == "Next")
            .and_then(|(_, v)| match v {
                Object::Reference(id) => Some(*id),
                _ => None,
            });
    }
    Ok(out)
}

/// Try to extract a structured destination from the outline item.
/// Falls back to a raw text representation when the destination is a
/// named one (Name / byte-string) or hides behind a `/A << /S /GoTo
/// /D ... >>` action chain.
fn decode_dest_or_action(
    reader: &mut DocumentReader<'_>,
    item: &Dict,
    page_index_map: &HashMap<u32, usize>,
    named_dests: &NamedDests,
) -> Result<(Option<OutlineDestination>, Option<String>), PdfError> {
    // /Dest takes precedence over /A per Table 153.
    if let Some(dest) = item
        .entries()
        .iter()
        .find(|(k, _)| k == "Dest")
        .map(|(_, v)| v.clone())
    {
        return Ok(decode_dest_value(
            reader,
            dest,
            page_index_map,
            Some(named_dests),
        ));
    }
    if let Some(action) = item
        .entries()
        .iter()
        .find(|(k, _)| k == "A")
        .map(|(_, v)| v.clone())
    {
        let action = reader.deref(action)?;
        if let Object::Dict(adict) = action {
            // /S /GoTo + /D <dest>.
            let is_goto = matches!(
                adict.entries().iter().find(|(k, _)| k == "S").map(|(_, v)| v),
                Some(Object::Name(s)) if s == "GoTo"
            );
            if is_goto {
                if let Some(d) = adict
                    .entries()
                    .iter()
                    .find(|(k, _)| k == "D")
                    .map(|(_, v)| v.clone())
                {
                    return Ok(decode_dest_value(
                        reader,
                        d,
                        page_index_map,
                        Some(named_dests),
                    ));
                }
            }
            // /S /URI — surface the URI text in raw_dest.
            let is_uri = matches!(
                adict.entries().iter().find(|(k, _)| k == "S").map(|(_, v)| v),
                Some(Object::Name(s)) if s == "URI"
            );
            if is_uri {
                let uri =
                    adict
                        .entries()
                        .iter()
                        .find(|(k, _)| k == "URI")
                        .and_then(|(_, v)| match v {
                            Object::LiteralString(b) | Object::HexString(b) => {
                                Some(String::from_utf8_lossy(b).into_owned())
                            }
                            _ => None,
                        });
                return Ok((None, uri.map(|s| format!("uri:{s}"))));
            }
        }
    }
    Ok((None, None))
}

/// Decode a `/Dest` (or action `/D`) value into a structured
/// [`OutlineDestination`]: an explicit array parses per Table 151; a
/// Name / byte string (§12.3.2.3 named destination) consults the
/// `named` lookaside when one is supplied. The raw text is retained
/// alongside either way — `named:<name>` for names (resolved or
/// not), the array text when an explicit parse falls back to `None`.
///
/// `named` is `None` when decoding a named destination's *own*
/// target, so a malformed name-valued entry cannot recurse.
pub(crate) fn decode_dest_value(
    reader: &mut DocumentReader<'_>,
    dest: Object,
    page_index_map: &HashMap<u32, usize>,
    named: Option<&NamedDests>,
) -> (Option<OutlineDestination>, Option<String>) {
    let dest = match reader.deref(dest) {
        Ok(d) => d,
        Err(_) => return (None, Some("<unresolvable>".into())),
    };
    match dest {
        Object::Array(items) => match decode_explicit_dest(&items, page_index_map) {
            Some(d) => (Some(d), None),
            None => (None, Some(format_array_dest(&items))),
        },
        Object::Name(s) => named_lookup(named, s.as_bytes()),
        Object::LiteralString(b) | Object::HexString(b) => named_lookup(named, &b),
        _ => (None, None),
    }
}

/// Parse `[ <page-ref> /Mode ... ]` per ISO 32000-1 Table 151.
fn decode_explicit_dest(
    items: &[Object],
    page_index_map: &HashMap<u32, usize>,
) -> Option<OutlineDestination> {
    if items.len() < 2 {
        return None;
    }
    let page_index = match &items[0] {
        Object::Reference(id) => *page_index_map.get(&id.number)?,
        // Remote-go-to dests use an integer page number — round-25
        // doesn't surface them; fall through to None.
        _ => return None,
    };
    let mode = match &items[1] {
        Object::Name(n) => n.as_str(),
        _ => return None,
    };

    // Optional-numeric helper: PDF Real / Integer / Null.
    let opt = |o: Option<&Object>| match o {
        Some(Object::Real(f)) => Some(*f as f32),
        Some(Object::Integer(n)) => Some(*n as f32),
        Some(Object::Null) | None => None,
        _ => None,
    };
    let req = |o: Option<&Object>| -> Option<f32> {
        match o {
            Some(Object::Real(f)) => Some(*f as f32),
            Some(Object::Integer(n)) => Some(*n as f32),
            _ => None,
        }
    };

    match mode {
        "XYZ" => Some(OutlineDestination::Xyz {
            page_index,
            left: opt(items.get(2)),
            top: opt(items.get(3)),
            zoom: opt(items.get(4)).filter(|z| *z != 0.0),
        }),
        "Fit" => Some(OutlineDestination::Fit { page_index }),
        "FitH" => Some(OutlineDestination::FitH {
            page_index,
            top: opt(items.get(2)),
        }),
        "FitV" => Some(OutlineDestination::FitV {
            page_index,
            left: opt(items.get(2)),
        }),
        "FitR" => Some(OutlineDestination::FitR {
            page_index,
            left: req(items.get(2))?,
            bottom: req(items.get(3))?,
            right: req(items.get(4))?,
            top: req(items.get(5))?,
        }),
        "FitB" => Some(OutlineDestination::FitB { page_index }),
        "FitBH" => Some(OutlineDestination::FitBH {
            page_index,
            top: opt(items.get(2)),
        }),
        "FitBV" => Some(OutlineDestination::FitBV {
            page_index,
            left: opt(items.get(2)),
        }),
        _ => None,
    }
}

/// Consult the named-destination lookaside for `raw` (§12.3.2.3).
/// The `named:<name>` display text keeps the name observable whether
/// or not resolution produced a structured destination; `None` for
/// the lookaside (the named-dest module decoding its own targets)
/// never resolves, so a name-valued named-dest entry cannot loop.
fn named_lookup(
    named: Option<&NamedDests>,
    raw: &[u8],
) -> (Option<OutlineDestination>, Option<String>) {
    let display = format!("named:{}", decode_key_text(raw));
    let dest = named.and_then(|m| m.get(raw)).and_then(|(d, _)| d.clone());
    (dest, Some(display))
}

fn format_array_dest(items: &[Object]) -> String {
    let mut out = String::from("[");
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        match it {
            Object::Reference(id) => out.push_str(&format!("{} 0 R", id.number)),
            Object::Name(n) => {
                out.push('/');
                out.push_str(n);
            }
            Object::Integer(n) => out.push_str(&n.to_string()),
            Object::Real(f) => out.push_str(&format!("{f}")),
            Object::Null => out.push_str("null"),
            _ => out.push('?'),
        }
    }
    out.push(']');
    out
}

/// Walk the `/Pages` tree (DFS) to produce a `page-object-id-number
/// → 0-based-DFS-index` map. Mirrors the writer's emission order so
/// destinations round-trip cleanly. Cached behaviour is fine — we
/// only call this once per outline read.
pub(crate) fn build_page_index_map(
    reader: &mut DocumentReader<'_>,
) -> Result<HashMap<u32, usize>, PdfError> {
    let root_id = reader.xref().root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog_dict) = catalog else {
        return Ok(HashMap::new());
    };
    let pages_ref = catalog_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Pages")
        .and_then(|(_, v)| match v {
            Object::Reference(id) => Some(*id),
            _ => None,
        });
    let Some(pages_root) = pages_ref else {
        return Ok(HashMap::new());
    };
    let mut leaves: Vec<u32> = Vec::new();
    walk_pages(reader, pages_root, &mut leaves)?;
    Ok(leaves
        .into_iter()
        .enumerate()
        .map(|(i, n)| (n, i))
        .collect())
}

pub(crate) fn walk_pages(
    reader: &mut DocumentReader<'_>,
    node_id: ObjectId,
    out: &mut Vec<u32>,
) -> Result<(), PdfError> {
    let node = reader.resolve(node_id)?;
    let Object::Dict(d) = node else {
        return Ok(());
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
            out.push(node_id.number);
        }
        Some("Pages") | None => {
            if let Some(Object::Array(kids)) = d
                .entries()
                .iter()
                .find(|(k, _)| k == "Kids")
                .map(|(_, v)| v)
            {
                for it in kids.clone() {
                    if let Object::Reference(id) = it {
                        // Bound the recursion depth defensively.
                        if out.len() > 100_000 {
                            return Ok(());
                        }
                        walk_pages(reader, id, out)?;
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn decode_text(o: Option<&Object>) -> Option<String> {
    match o? {
        Object::LiteralString(b) => Some(String::from_utf8_lossy(b).into_owned()),
        Object::HexString(b) => {
            if b.len() >= 2 && b[0] == 0xFE && b[1] == 0xFF {
                let utf16: Vec<u16> = b[2..]
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Some(String::from_utf16_lossy(&utf16))
            } else {
                Some(String::from_utf8_lossy(b).into_owned())
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descendant_count_sums_recursively() {
        let leaf = OutlineNode {
            title: "leaf".into(),
            destination: None,
            raw_dest: None,
            count: None,
            children: Vec::new(),
        };
        let parent = OutlineNode {
            title: "parent".into(),
            destination: None,
            raw_dest: None,
            count: Some(2),
            children: vec![leaf.clone(), leaf.clone()],
        };
        assert_eq!(parent.descendant_count(), 3);
    }

    #[test]
    fn is_open_recognises_count_sign() {
        let mut n = OutlineNode {
            title: "x".into(),
            destination: None,
            raw_dest: None,
            count: Some(2),
            children: Vec::new(),
        };
        assert!(n.is_open());
        n.count = Some(-2);
        assert!(!n.is_open());
        n.count = None;
        assert!(n.is_open()); // childless / absent treated as open
    }

    #[test]
    fn explicit_dest_fit_decodes() {
        let map: HashMap<u32, usize> = [(7u32, 3usize)].into_iter().collect();
        let arr = vec![
            Object::Reference(ObjectId::new(7)),
            Object::Name("Fit".into()),
        ];
        let d = decode_explicit_dest(&arr, &map).unwrap();
        assert_eq!(d, OutlineDestination::Fit { page_index: 3 });
    }

    #[test]
    fn explicit_dest_xyz_decodes_with_nulls() {
        let map: HashMap<u32, usize> = [(11u32, 5usize)].into_iter().collect();
        let arr = vec![
            Object::Reference(ObjectId::new(11)),
            Object::Name("XYZ".into()),
            Object::Null,
            Object::Integer(800),
            Object::Integer(0), // 0 zoom → None per Table 151
        ];
        let d = decode_explicit_dest(&arr, &map).unwrap();
        assert_eq!(
            d,
            OutlineDestination::Xyz {
                page_index: 5,
                left: None,
                top: Some(800.0),
                zoom: None,
            }
        );
    }

    #[test]
    fn explicit_dest_fitr_requires_four_numbers() {
        let map: HashMap<u32, usize> = [(2u32, 0usize)].into_iter().collect();
        let arr = vec![
            Object::Reference(ObjectId::new(2)),
            Object::Name("FitR".into()),
            Object::Real(10.0),
            Object::Real(20.0),
            Object::Real(30.0),
            Object::Real(40.0),
        ];
        let d = decode_explicit_dest(&arr, &map).unwrap();
        assert_eq!(
            d,
            OutlineDestination::FitR {
                page_index: 0,
                left: 10.0,
                bottom: 20.0,
                right: 30.0,
                top: 40.0,
            }
        );
    }

    #[test]
    fn explicit_dest_unknown_mode_returns_none() {
        let map: HashMap<u32, usize> = [(3u32, 1usize)].into_iter().collect();
        let arr = vec![
            Object::Reference(ObjectId::new(3)),
            Object::Name("Unknown".into()),
        ];
        assert!(decode_explicit_dest(&arr, &map).is_none());
    }
}
