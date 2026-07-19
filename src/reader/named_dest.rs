//! Round-418 — **named destinations** reader (ISO 32000-1 §12.3.2.3).
//!
//! A destination may be referred to indirectly by a name object
//! (PDF 1.1) or a byte string (PDF 1.2) instead of the explicit
//! `[page /Mode …]` array of Table 151. Two document-level structures
//! define the correspondence:
//!
//! * the **`/Dests` entry in the document catalogue** (PDF 1.1) — a
//!   dictionary whose keys are destination names; and
//! * the **`/Dests` entry in the catalogue's `/Names` dictionary**
//!   (PDF 1.2+, §7.7.4) — a name tree (§7.9.6) mapping name strings
//!   to destinations.
//!
//! In both, the value is "either an array defining the destination,
//! using the syntax shown in Table 151, or a dictionary with a `D`
//! entry whose value is such an array" (§12.3.2.3).
//!
//! [`named_destinations`] enumerates both sources into a merged list.
//! A document may carry both forms (§12.3.2.3 NOTE 3); on a key
//! defined in both, the **name-tree entry wins** here — it is the
//! PDF 1.2+ mechanism the spec steers producers toward ("applications
//! should use the string form of representation in the Dests name
//! tree"). [`resolve_named_destination`] resolves one name without
//! enumerating, using the §7.9.6 `/Limits`-guided tree descent.
//!
//! The outline (§12.3.3) and Link-annotation (§12.5.6.5) readers
//! consume the same machinery: a bookmark or link whose `/Dest` is a
//! Name or byte string now resolves to a structured
//! [`OutlineDestination`] instead of surfacing raw text only.

use std::collections::HashMap;

use crate::error::PdfError;
use crate::objects::{Dict, Object};
use crate::outline::OutlineDestination;
use crate::reader::document::DocumentReader;
use crate::reader::nametree::{decode_key_text, name_tree_entries, name_tree_lookup};
use crate::reader::outline::{build_page_index_map, decode_dest_value};

/// One named destination, from either §12.3.2.3 source.
#[derive(Debug, Clone)]
pub struct NamedDestination {
    /// The destination name, decoded for display (UTF-16BE when the
    /// §7.9.2.2 BOM prefix is present, UTF-8-lossy otherwise).
    pub name: String,
    /// The raw name bytes — the byte-wise §7.9.6 key. This is the
    /// form a `/Dest` name or byte string must match exactly.
    pub raw_name: Vec<u8>,
    /// The structured Table 151 destination, when the target parses
    /// to an explicit-array form whose page reference resolves.
    pub destination: Option<OutlineDestination>,
    /// Raw text of the target when the structured parse fell back to
    /// `None` (mirrors [`crate::reader::OutlineNode::raw_dest`]).
    pub raw_dest: Option<String>,
}

/// Enumerate every named destination the document defines — the
/// catalogue `/Dests` dictionary (PDF 1.1) merged with the `/Names`
/// → `/Dests` name tree (PDF 1.2+), tree entries winning on a shared
/// key. Returns `Ok(vec![])` when the document defines neither.
pub fn named_destinations(
    reader: &mut DocumentReader<'_>,
) -> Result<Vec<NamedDestination>, PdfError> {
    let page_index_map = build_page_index_map(reader)?;
    let map = named_dest_map(reader, &page_index_map)?;
    let mut out: Vec<NamedDestination> = map
        .into_iter()
        .map(|(raw_name, (destination, raw_dest))| NamedDestination {
            name: decode_key_text(&raw_name),
            raw_name,
            destination,
            raw_dest,
        })
        .collect();
    // The merge map is unordered — present the result sorted by the
    // §7.9.6 byte-wise key order (the order a conforming name tree
    // stores them in).
    out.sort_by(|a, b| a.raw_name.cmp(&b.raw_name));
    Ok(out)
}

/// Resolve a single destination name to its structured Table 151
/// form, without enumerating the whole tree: the `/Names → /Dests`
/// name tree is descended via its `/Limits` windows first (the
/// §12.3.2.3 precedence used throughout this module), then the
/// catalogue `/Dests` dictionary is consulted. `None` when the name
/// is not defined or its target doesn't parse to an explicit array
/// with a resolvable page.
pub fn resolve_named_destination(
    reader: &mut DocumentReader<'_>,
    name: &[u8],
) -> Result<Option<OutlineDestination>, PdfError> {
    let page_index_map = build_page_index_map(reader)?;
    // 1. /Names → /Dests name tree.
    if let Some(tree_root) = names_dests_root(reader)? {
        if let Some(value) = name_tree_lookup(reader, &tree_root, name)? {
            let (dest, _raw) = decode_target(reader, value, &page_index_map)?;
            if dest.is_some() {
                return Ok(dest);
            }
        }
    }
    // 2. Catalogue /Dests dictionary (PDF 1.1 — keys are Names).
    if let Some(dests_dict) = catalog_dests_dict(reader)? {
        let hit = dests_dict
            .entries()
            .iter()
            .find(|(k, _)| k.as_bytes() == name)
            .map(|(_, v)| v.clone());
        if let Some(value) = hit {
            let (dest, _raw) = decode_target(reader, value, &page_index_map)?;
            return Ok(dest);
        }
    }
    Ok(None)
}

/// The decoded value half of the merge map: `(structured destination,
/// raw fallback text)` — the same pair shape `decode_dest_value`
/// produces for explicit destinations.
pub(crate) type ResolvedNamedDest = (Option<OutlineDestination>, Option<String>);

/// Build the merged raw-name → resolved-destination map both
/// navigation readers (outline, link) consult. Empty when the
/// document defines no named destinations — callers can skip the
/// lookaside entirely in that (overwhelmingly common) case.
pub(crate) fn named_dest_map(
    reader: &mut DocumentReader<'_>,
    page_index_map: &HashMap<u32, usize>,
) -> Result<HashMap<Vec<u8>, ResolvedNamedDest>, PdfError> {
    let mut map: HashMap<Vec<u8>, ResolvedNamedDest> = HashMap::new();
    // PDF 1.1 catalogue /Dests dictionary first …
    if let Some(dests_dict) = catalog_dests_dict(reader)? {
        // First occurrence wins within the dictionary (the crate's
        // duplicate-key rule).
        let entries: Vec<(Vec<u8>, Object)> = dests_dict
            .entries()
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.clone()))
            .collect();
        for (raw_name, value) in entries {
            if map.contains_key(&raw_name) {
                continue;
            }
            let resolved = decode_target(reader, value, page_index_map)?;
            map.insert(raw_name, resolved);
        }
    }
    // … then the PDF 1.2+ name tree, overriding on shared keys.
    if let Some(tree_root) = names_dests_root(reader)? {
        for (raw_name, value) in name_tree_entries(reader, &tree_root)? {
            let resolved = decode_target(reader, value, page_index_map)?;
            map.insert(raw_name, resolved);
        }
    }
    Ok(map)
}

/// Normalise a named-destination *target* per §12.3.2.3 — the value
/// is an explicit-destination array, or a dictionary whose `/D` entry
/// is one — then decode it. A nested Name / byte-string target is
/// malformed (the spec's two forms only) and surfaces as raw text; no
/// recursive name resolution is attempted, so a self-referential
/// entry cannot loop.
fn decode_target(
    reader: &mut DocumentReader<'_>,
    value: Object,
    page_index_map: &HashMap<u32, usize>,
) -> Result<ResolvedNamedDest, PdfError> {
    let value = match reader.deref(value) {
        Ok(v) => v,
        Err(_) => return Ok((None, Some("<unresolvable>".into()))),
    };
    let value = match value {
        Object::Dict(d) => {
            let inner = d
                .entries()
                .iter()
                .find(|(k, _)| k == "D")
                .map(|(_, v)| v.clone());
            match inner {
                Some(v) => v,
                None => return Ok((None, Some("<dict without /D>".into()))),
            }
        }
        other => other,
    };
    Ok(decode_dest_value(reader, value, page_index_map, None))
}

/// The catalogue's `/Dests` dictionary (PDF 1.1 form), when present.
fn catalog_dests_dict(reader: &mut DocumentReader<'_>) -> Result<Option<Dict>, PdfError> {
    let Some(value) = catalog_entry(reader, "Dests")? else {
        return Ok(None);
    };
    match reader.deref(value)? {
        Object::Dict(d) => Ok(Some(d)),
        _ => Ok(None),
    }
}

/// The `/Names → /Dests` name-tree root node, when present.
fn names_dests_root(reader: &mut DocumentReader<'_>) -> Result<Option<Dict>, PdfError> {
    let Some(names_obj) = catalog_entry(reader, "Names")? else {
        return Ok(None);
    };
    let names_dict = match reader.deref(names_obj)? {
        Object::Dict(d) => d,
        _ => return Ok(None),
    };
    let dests_obj = names_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Dests")
        .map(|(_, v)| v.clone());
    let Some(dests_obj) = dests_obj else {
        return Ok(None);
    };
    match reader.deref(dests_obj)? {
        Object::Dict(d) => Ok(Some(d)),
        _ => Ok(None),
    }
}

/// One catalogue entry by key, unresolved.
fn catalog_entry(reader: &mut DocumentReader<'_>, key: &str) -> Result<Option<Object>, PdfError> {
    let root_id = reader.xref().root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog_dict) = catalog else {
        return Ok(None);
    };
    Ok(catalog_dict
        .entries()
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone()))
}
