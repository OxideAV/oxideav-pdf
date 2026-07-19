//! Shared walkers for **name trees** (ISO 32000-1 §7.9.6 Table 36) and
//! **number trees** (§7.9.7 Table 37).
//!
//! Several document-level structures hang off one of these two shapes:
//! the `/Names` dictionary's `/Dests` / `/EmbeddedFiles` /
//! `/JavaScript` subtrees are name trees (§7.7.4 Table 31), while
//! `/PageLabels` and the structure tree's `/ParentTree` are number
//! trees (§7.7.2 Table 28 + §14.7.4.4). Prior to round 418 each
//! consumer carried its own ad-hoc walk; this module centralises the
//! §7.9.6 node taxonomy so every consumer gets the same bounds and
//! cycle guards:
//!
//! * A tree node is a dictionary. The **root** carries either `/Kids`
//!   (indirect refs to child nodes) or the leaf payload (`/Names` /
//!   `/Nums`) but not both; **intermediate** nodes carry `/Limits` +
//!   `/Kids`; **leaf** nodes carry `/Limits` + the payload array of
//!   `[key₁ value₁ key₂ value₂ …]` pairs.
//! * Name-tree keys are byte strings compared byte-by-byte (§7.9.6 —
//!   "keys shall be compared for equality on a simple byte-by-byte
//!   basis"); number-tree keys are integers in ascending order.
//!
//! The walkers are **tolerant**: a malformed branch (non-dict kid,
//! non-string key, missing payload) is skipped rather than failing the
//! whole tree, matching the crate's other best-effort enumeration
//! surfaces. Recursion is depth-bounded, the output is size-capped,
//! and re-visiting a node object id aborts that branch (a conforming
//! tree is acyclic; a crafted one may not be).

use std::collections::HashSet;

use crate::error::PdfError;
use crate::objects::{Dict, Object};
use crate::reader::document::DocumentReader;

/// Hard recursion bound — deeper trees are treated as malformed and
/// the over-deep branch is dropped. A balanced tree of depth 32 could
/// hold far more entries than [`MAX_ENTRIES`] allows anyway.
const MAX_DEPTH: usize = 32;

/// Hard cap on collected entries, shared by both tree kinds.
const MAX_ENTRIES: usize = 100_000;

/// Enumerate every `(key, value)` pair of a **name tree** rooted at
/// `root`, in tree order (§7.9.6 mandates ascending lexical order for
/// a conforming file; a malformed file's order is surfaced as-is).
///
/// Keys are returned as raw byte strings — §7.9.6 allows any
/// self-consistent encoding and requires byte-wise comparison, so no
/// text decoding is applied here. Callers that display keys can BOM-
/// sniff for UTF-16BE per §7.9.2.2. A key that is a Name object
/// (tolerated: some producers write name-tree keys as Names) yields
/// the name's bytes.
pub fn name_tree_entries(
    reader: &mut DocumentReader<'_>,
    root: &Dict,
) -> Result<Vec<(Vec<u8>, Object)>, PdfError> {
    let mut out = Vec::new();
    let mut visited = HashSet::new();
    walk(
        reader,
        root,
        "Names",
        &mut visited,
        0,
        &mut |k, v, out_len| {
            if out_len >= MAX_ENTRIES {
                return false;
            }
            if let Some(bytes) = key_bytes(k) {
                out.push((bytes, v));
            }
            true
        },
    )?;
    Ok(out)
}

/// Enumerate every `(key, value)` pair of a **number tree** rooted at
/// `root`, in tree order. Non-integer keys are skipped.
pub fn number_tree_entries(
    reader: &mut DocumentReader<'_>,
    root: &Dict,
) -> Result<Vec<(i64, Object)>, PdfError> {
    let mut out = Vec::new();
    let mut visited = HashSet::new();
    walk(
        reader,
        root,
        "Nums",
        &mut visited,
        0,
        &mut |k, v, out_len| {
            if out_len >= MAX_ENTRIES {
                return false;
            }
            if let Object::Integer(n) = k {
                out.push((n, v));
            }
            true
        },
    )?;
    Ok(out)
}

/// Look up a single key in a **name tree** without enumerating it,
/// descending through `/Kids` guided by each node's `/Limits` pair
/// (§7.9.6 — the two-string array bounding the keys under that node).
///
/// A node whose `/Limits` entry is absent or malformed is descended
/// into unconditionally (tolerant reading — the pruning is an
/// optimisation, not a correctness requirement), so a lookup on a
/// sloppy tree still finds its key.
pub fn name_tree_lookup(
    reader: &mut DocumentReader<'_>,
    root: &Dict,
    key: &[u8],
) -> Result<Option<Object>, PdfError> {
    let mut visited = HashSet::new();
    lookup_node(reader, root, key, &mut visited, 0)
}

fn lookup_node(
    reader: &mut DocumentReader<'_>,
    node: &Dict,
    key: &[u8],
    visited: &mut HashSet<u32>,
    depth: usize,
) -> Result<Option<Object>, PdfError> {
    if depth > MAX_DEPTH {
        return Ok(None);
    }
    // Leaf (or Names-carrying root): scan the pair array.
    if let Some(Object::Array(items)) = dict_get(node, "Names") {
        let mut iter = items.iter();
        while let (Some(k), Some(v)) = (iter.next(), iter.next()) {
            if key_bytes(k.clone()).as_deref() == Some(key) {
                return Ok(Some(v.clone()));
            }
        }
        return Ok(None);
    }
    // Intermediate (or Kids-carrying root): descend, pruning by
    // /Limits where the bounds are well-formed.
    let Some(kids_obj) = dict_get(node, "Kids") else {
        return Ok(None);
    };
    let kids = match reader.deref(kids_obj)? {
        Object::Array(items) => items,
        _ => return Ok(None),
    };
    for kid in kids {
        let kid_dict = match kid {
            Object::Reference(id) => {
                if !visited.insert(id.number) {
                    continue; // cycle — skip this branch
                }
                match reader.resolve(id)? {
                    Object::Dict(d) => d,
                    _ => continue,
                }
            }
            Object::Dict(d) => d,
            _ => continue,
        };
        if let Some((lo, hi)) = limits_bytes(&kid_dict) {
            // §7.9.6: byte-by-byte lexical comparison.
            if key < lo.as_slice() || key > hi.as_slice() {
                continue;
            }
        }
        if let Some(found) = lookup_node(reader, &kid_dict, key, visited, depth + 1)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// Shared DFS over the §7.9.6 / §7.9.7 node shape. `payload_key` is
/// `"Names"` or `"Nums"`; `emit` receives each raw key object and
/// value (plus the current emitted count) and returns `false` to stop
/// the walk (size cap reached).
fn walk(
    reader: &mut DocumentReader<'_>,
    node: &Dict,
    payload_key: &str,
    visited: &mut HashSet<u32>,
    depth: usize,
    emit: &mut dyn FnMut(Object, Object, usize) -> bool,
) -> Result<(), PdfError> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    // Leaf node (or single-node root).
    if let Some(payload) = dict_get(node, payload_key) {
        let items = match reader.deref(payload)? {
            Object::Array(items) => items,
            _ => return Ok(()),
        };
        let mut count = 0usize;
        let mut iter = items.into_iter();
        while let (Some(k), Some(v)) = (iter.next(), iter.next()) {
            if !emit(k, v, count) {
                return Ok(());
            }
            count += 1;
        }
        return Ok(());
    }
    // Intermediate node (or root with /Kids).
    let Some(kids_obj) = dict_get(node, "Kids") else {
        return Ok(());
    };
    let kids = match reader.deref(kids_obj)? {
        Object::Array(items) => items,
        _ => return Ok(()),
    };
    for kid in kids {
        let kid_dict = match kid {
            Object::Reference(id) => {
                if !visited.insert(id.number) {
                    continue; // cycle — skip
                }
                match reader.resolve(id)? {
                    Object::Dict(d) => d,
                    _ => continue,
                }
            }
            Object::Dict(d) => d,
            _ => continue,
        };
        walk(reader, &kid_dict, payload_key, visited, depth + 1, emit)?;
    }
    Ok(())
}

/// Raw byte form of a name-tree key object. Strings pass their bytes
/// through untouched (§7.9.6 byte-wise semantics); a Name object is
/// tolerated and yields its bytes; anything else is not a key.
fn key_bytes(obj: Object) -> Option<Vec<u8>> {
    match obj {
        Object::LiteralString(b) | Object::HexString(b) => Some(b),
        Object::Name(s) => Some(s.into_bytes()),
        _ => None,
    }
}

/// The `/Limits [least greatest]` pair of a name-tree node as raw
/// bytes, when present and well-formed.
fn limits_bytes(node: &Dict) -> Option<(Vec<u8>, Vec<u8>)> {
    let Some(Object::Array(items)) = dict_get(node, "Limits") else {
        return None;
    };
    if items.len() != 2 {
        return None;
    }
    let lo = key_bytes(items[0].clone())?;
    let hi = key_bytes(items[1].clone())?;
    Some((lo, hi))
}

/// First-match dictionary getter (the crate's dictionaries preserve
/// entry order; duplicate keys resolve to the first occurrence, the
/// same rule the other readers apply).
fn dict_get(d: &Dict, key: &str) -> Option<Object> {
    d.entries()
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
}

/// Decode a name-tree key's bytes for display: UTF-16BE when the
/// §7.9.2.2 BOM prefix is present, UTF-8-lossy otherwise.
pub fn decode_key_text(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        let utf16: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&utf16)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_bytes_accepts_strings_and_names() {
        assert_eq!(
            key_bytes(Object::LiteralString(b"abc".to_vec())).as_deref(),
            Some(b"abc".as_slice())
        );
        assert_eq!(
            key_bytes(Object::HexString(vec![0x01, 0x02])).as_deref(),
            Some([0x01, 0x02].as_slice())
        );
        assert_eq!(
            key_bytes(Object::Name("N1".into())).as_deref(),
            Some(b"N1".as_slice())
        );
        assert_eq!(key_bytes(Object::Integer(3)), None);
    }

    #[test]
    fn decode_key_text_bom_sniffs() {
        assert_eq!(decode_key_text(b"plain"), "plain");
        assert_eq!(decode_key_text(&[0xFE, 0xFF, 0x00, 0x41]), "A");
    }
}
