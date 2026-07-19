//! Round-418 — **article threads** reader (ISO 32000-1 §12.4.3).
//!
//! An *article* represents logically connected but physically
//! discontiguous content — a news story starting on page 1 and
//! continuing on page 5. The catalogue's optional `/Threads` entry is
//! an array of thread dictionaries (Table 160); each thread's `/F`
//! points at the first *bead* (Table 161), and beads chain circularly
//! through `/N` (next) / `/V` (previous) — "In the last bead, this
//! entry shall refer to the first bead" — each carrying the page it
//! appears on (`/P`) and its rectangle (`/R`).
//!
//! [`threads`] walks the array and each bead ring into parent-owned
//! [`PdfThread`] values. The `/N` walk stops when it returns to the
//! first bead (the conforming circular shape) or revisits any bead
//! (a malformed ring), and is length-capped. Thread information
//! dictionaries (`/I` — document-information syntax per §14.3.3)
//! surface their common text entries.

use std::collections::HashSet;

use crate::error::PdfError;
use crate::objects::{Dict, Object};
use crate::reader::document::DocumentReader;
use crate::reader::nametree::decode_key_text;
use crate::reader::outline::build_page_index_map;

/// One bead on an article thread (Table 161).
#[derive(Debug, Clone, PartialEq)]
pub struct PdfBead {
    /// 0-based index (in `/Pages` DFS order) of the page carrying the
    /// bead — resolved from `/P`. `None` when `/P` is absent or
    /// doesn't resolve to a page in the tree.
    pub page_index: Option<usize>,
    /// `/R` — bead rectangle in default user space.
    pub rect: Option<[f32; 4]>,
}

/// One article thread (Table 160) with its beads in reading order.
#[derive(Debug, Clone, Default)]
pub struct PdfThread {
    /// `/I` `/Title`, when present (document-information syntax,
    /// §14.3.3).
    pub title: Option<String>,
    /// `/I` `/Author`, when present.
    pub author: Option<String>,
    /// `/I` `/Subject`, when present.
    pub subject: Option<String>,
    /// The bead ring, unrolled from `/F` through `/N` until the walk
    /// returns to the first bead.
    pub beads: Vec<PdfBead>,
}

/// Hard cap on beads walked per thread — a crafted `/N` chain that
/// never closes cannot run away.
const MAX_BEADS: usize = 10_000;

/// Walk the catalogue's `/Threads` array (§12.4.3). Returns
/// `Ok(vec![])` when the catalogue has no `/Threads` entry — the
/// overwhelmingly common case.
pub fn threads(reader: &mut DocumentReader<'_>) -> Result<Vec<PdfThread>, PdfError> {
    let root_id = reader.xref().root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog_dict) = catalog else {
        return Ok(Vec::new());
    };
    let threads_obj = catalog_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Threads")
        .map(|(_, v)| v.clone());
    let Some(threads_obj) = threads_obj else {
        return Ok(Vec::new());
    };
    let items = match reader.deref(threads_obj)? {
        Object::Array(items) => items,
        _ => return Ok(Vec::new()),
    };
    let page_index_map = build_page_index_map(reader)?;

    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let thread_dict = match reader.deref(item)? {
            Object::Dict(d) => d,
            _ => continue, // malformed entry — skip
        };
        out.push(read_thread(reader, &thread_dict, &page_index_map)?);
    }
    Ok(out)
}

fn read_thread(
    reader: &mut DocumentReader<'_>,
    thread: &Dict,
    page_index_map: &std::collections::HashMap<u32, usize>,
) -> Result<PdfThread, PdfError> {
    let mut result = PdfThread::default();

    // /I — thread information dictionary (document-info syntax).
    if let Some(info_obj) = dict_get(thread, "I") {
        if let Ok(Object::Dict(info)) = reader.deref(info_obj) {
            result.title = text_entry(&info, "Title");
            result.author = text_entry(&info, "Author");
            result.subject = text_entry(&info, "Subject");
        }
    }

    // /F — first bead; unroll the circular /N ring.
    let Some(first_obj) = dict_get(thread, "F") else {
        return Ok(result);
    };
    let first_id = match first_obj {
        Object::Reference(id) => Some(id.number),
        _ => None,
    };
    let mut visited: HashSet<u32> = HashSet::new();
    if let Some(n) = first_id {
        visited.insert(n);
    }
    let mut cur = Some(first_obj);
    while let Some(obj) = cur {
        if result.beads.len() >= MAX_BEADS {
            break;
        }
        let bead = match reader.deref(obj)? {
            Object::Dict(d) => d,
            _ => break,
        };
        result.beads.push(read_bead(&bead, page_index_map));
        // Follow /N; stop at the ring closure (back to /F) or on a
        // malformed revisit.
        cur = match dict_get(&bead, "N") {
            Some(Object::Reference(id)) => {
                if Some(id.number) == first_id || !visited.insert(id.number) {
                    None
                } else {
                    Some(Object::Reference(id))
                }
            }
            // /N is required and shall be an indirect reference; a
            // direct dict here would defeat the ring-closure check,
            // so the walk ends (tolerant truncation).
            _ => None,
        };
    }
    Ok(result)
}

fn read_bead(bead: &Dict, page_index_map: &std::collections::HashMap<u32, usize>) -> PdfBead {
    let page_index = match dict_get(bead, "P") {
        Some(Object::Reference(id)) => page_index_map.get(&id.number).copied(),
        _ => None,
    };
    let rect = match dict_get(bead, "R") {
        Some(Object::Array(items)) if items.len() == 4 => {
            let mut r = [0f32; 4];
            let mut ok = true;
            for (i, it) in items.iter().enumerate() {
                match it {
                    Object::Real(f) => r[i] = *f as f32,
                    Object::Integer(n) => r[i] = *n as f32,
                    _ => ok = false,
                }
            }
            ok.then_some(r)
        }
        _ => None,
    };
    PdfBead { page_index, rect }
}

fn dict_get(d: &Dict, key: &str) -> Option<Object> {
    d.entries()
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
}

fn text_entry(d: &Dict, key: &str) -> Option<String> {
    match dict_get(d, key) {
        Some(Object::LiteralString(b)) | Some(Object::HexString(b)) => Some(decode_key_text(&b)),
        _ => None,
    }
}
