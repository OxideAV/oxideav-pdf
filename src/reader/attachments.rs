//! Round-33 — embedded file attachment reader
//! (ISO 32000-1 §7.11 + §3.10 + §7.7.4 + §7.9.6).
//!
//! Walks the catalog's `/Names → /EmbeddedFiles` name tree, surfacing
//! each registered file specification (`/Filespec`) as a structured
//! [`PdfAttachment`] carrying:
//!
//! * The user-visible file name (preferring `/UF` UTF-16BE over `/F`
//!   PDFDocEncoded per §7.11.2 Table 43).
//! * The MIME type from the embedded-file stream's `/Subtype` per
//!   §7.11.4 Table 45 (when present — the writer always emits it but
//!   third-party PDFs sometimes omit it).
//! * The decoded file payload (the embedded-file stream's body, with
//!   `/Filter` reversed if needed — `FlateDecode` is the only filter
//!   the symmetric writer emits, but we handle the no-filter case too).
//! * The optional `/Params /ModDate` modification date (raw PDF date
//!   string, no parse).
//!
//! This is the reader-side counterpart to
//! [`crate::write_pdf_with_attachments`]. The walker is best-effort —
//! malformed entries are skipped silently rather than aborting the
//! whole tree (matches the round-26 annotation reader's contract).

use crate::error::PdfError;
use crate::objects::{Dict, Object};
use crate::reader::document::{decode_stream, DocumentReader};

/// One embedded-file attachment surfaced by [`attachments`].
#[derive(Debug, Clone)]
pub struct PdfAttachment {
    /// File name from `/UF` (UTF-16BE) or `/F` (PDFDocEncoded). The
    /// reader prefers `/UF` when present per §7.11.2 Table 43.
    pub name: String,
    /// MIME type from the embedded-file stream's `/Subtype`. `None`
    /// when omitted by the producer.
    pub mime_type: Option<String>,
    /// Decoded file payload — `/Filter`-reversed bytes.
    pub bytes: Vec<u8>,
    /// `/Params /ModDate` modification date (raw PDF date string,
    /// `D:YYYYMMDDHHmmSSOHH'mm'` per §7.9.4). `None` when absent.
    pub modified: Option<String>,
}

/// Walk the catalog → `/Names → /EmbeddedFiles` name tree and surface
/// every embedded file as a structured [`PdfAttachment`].
///
/// Returns `Ok(vec![])` when:
///
/// * The catalog has no `/Names` entry, or
/// * `/Names` is present but has no `/EmbeddedFiles` sub-entry, or
/// * The `/EmbeddedFiles` name tree is empty.
///
/// Returns [`PdfError::Other`] only when the catalog itself can't be
/// resolved or doesn't decode to a Dict — every other malformed branch
/// is skipped.
pub fn attachments(reader: &mut DocumentReader<'_>) -> Result<Vec<PdfAttachment>, PdfError> {
    let root_id = reader.xref().root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog_dict) = catalog else {
        return Err(PdfError::other(format!(
            "PDF attachments reader: /Root must be a dict (got {catalog:?})"
        )));
    };

    // Walk to /Names dict.
    let names_obj = catalog_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Names")
        .map(|(_, v)| v.clone());
    let Some(names_obj) = names_obj else {
        return Ok(Vec::new());
    };
    let names_dict = match reader.deref(names_obj)? {
        Object::Dict(d) => d,
        _ => return Ok(Vec::new()),
    };

    // /EmbeddedFiles entry.
    let ef_obj = names_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "EmbeddedFiles")
        .map(|(_, v)| v.clone());
    let Some(ef_obj) = ef_obj else {
        return Ok(Vec::new());
    };
    let root_node = match reader.deref(ef_obj)? {
        Object::Dict(d) => d,
        _ => return Ok(Vec::new()),
    };

    // Walk the name tree, collecting (name, filespec_ref) pairs.
    let mut entries: Vec<(String, Object)> = Vec::new();
    walk_name_tree(reader, &root_node, &mut entries, 0)?;

    // Resolve each filespec → PdfAttachment.
    let mut out = Vec::with_capacity(entries.len());
    for (name, filespec_value) in entries {
        // Resolve filespec dict.
        let filespec_dict = match reader.deref(filespec_value)? {
            Object::Dict(d) => d,
            _ => continue, // skip malformed entry
        };
        // The /UF key in the filespec dict overrides the name-tree key
        // when present (ISO 32000-1 §7.11.3). Fall back to /F, then to
        // the name-tree key.
        let resolved_name = decode_filespec_name(&filespec_dict).unwrap_or(name);

        // /EF dict — pointer to the embedded-file stream.
        let ef_entry = filespec_dict
            .entries()
            .iter()
            .find(|(k, _)| k == "EF")
            .map(|(_, v)| v.clone());
        let Some(ef_entry) = ef_entry else {
            continue;
        };
        let ef_dict = match reader.deref(ef_entry)? {
            Object::Dict(d) => d,
            _ => continue,
        };
        // Prefer /UF in the EF dict (PDF 1.7+); fall back to /F.
        let stream_ref = ef_dict
            .entries()
            .iter()
            .find(|(k, _)| k == "UF")
            .or_else(|| ef_dict.entries().iter().find(|(k, _)| k == "F"))
            .map(|(_, v)| v.clone());
        let Some(stream_ref) = stream_ref else {
            continue;
        };
        let stream_obj = match reader.deref(stream_ref)? {
            Object::Stream(s) => s,
            _ => continue,
        };

        let mime_type = stream_obj
            .dict
            .entries()
            .iter()
            .find(|(k, _)| k == "Subtype")
            .and_then(|(_, v)| match v {
                Object::Name(s) => Some(s.clone()),
                _ => None,
            });

        let modified = read_params_moddate(&stream_obj.dict);

        let bytes = decode_stream(&stream_obj)?;

        out.push(PdfAttachment {
            name: resolved_name,
            mime_type,
            bytes,
            modified,
        });
    }

    Ok(out)
}

/// Walk a name-tree node — either an intermediate node (carrying
/// `/Kids` whose entries are sub-node refs) or a leaf (carrying
/// `/Names [key value …]`). Per §7.9.6.
///
/// Bounded recursion (depth ≤ 32) so a malformed tree can't blow the
/// stack.
fn walk_name_tree(
    reader: &mut DocumentReader<'_>,
    node: &Dict,
    out: &mut Vec<(String, Object)>,
    depth: usize,
) -> Result<(), PdfError> {
    if depth > 32 {
        return Ok(()); // defensive — bound recursion
    }
    if out.len() > 100_000 {
        return Ok(()); // defensive — bound output
    }
    // Leaf node: `/Names [key1 val1 key2 val2 …]`.
    if let Some(Object::Array(items)) = node
        .entries()
        .iter()
        .find(|(k, _)| k == "Names")
        .map(|(_, v)| v)
    {
        let mut iter = items.iter();
        while let (Some(key_obj), Some(val_obj)) = (iter.next(), iter.next()) {
            let Some(key) = decode_text_obj(key_obj) else {
                continue;
            };
            out.push((key, val_obj.clone()));
        }
        return Ok(());
    }
    // Intermediate node: `/Kids [child-ref child-ref …]`.
    if let Some(kids_obj) = node
        .entries()
        .iter()
        .find(|(k, _)| k == "Kids")
        .map(|(_, v)| v.clone())
    {
        let kids = match reader.deref(kids_obj)? {
            Object::Array(items) => items,
            _ => return Ok(()),
        };
        for kid in kids {
            let kid_dict = match reader.deref(kid)? {
                Object::Dict(d) => d,
                _ => continue,
            };
            walk_name_tree(reader, &kid_dict, out, depth + 1)?;
        }
    }
    Ok(())
}

/// Decode the `/UF` (preferred, PDF 1.7+) or `/F` filename entry from
/// a `/Filespec` dict. UTF-16BE-with-BOM hex strings decode to a
/// String; ASCII literal strings pass through.
fn decode_filespec_name(filespec: &Dict) -> Option<String> {
    let pick = filespec
        .entries()
        .iter()
        .find(|(k, _)| k == "UF")
        .or_else(|| filespec.entries().iter().find(|(k, _)| k == "F"));
    pick.and_then(|(_, v)| decode_text_obj(v))
}

/// Decode a `/Params /ModDate` entry from the embedded-file stream
/// dict. Returns the raw PDF date string with no parse.
fn read_params_moddate(dict: &Dict) -> Option<String> {
    let params = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Params")
        .map(|(_, v)| v)?;
    let params_dict = match params {
        Object::Dict(d) => d,
        _ => return None,
    };
    params_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "ModDate")
        .and_then(|(_, v)| decode_text_obj(v))
}

/// Decode a PDF text object into a `String`. Mirrors the round-25
/// outline-title decoder: literal-string → UTF-8 lossy; hex-string →
/// UTF-16BE when prefixed with the BOM, else UTF-8 lossy.
fn decode_text_obj(obj: &Object) -> Option<String> {
    match obj {
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
        Object::Name(s) => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_text_obj_literal_string_passes_through() {
        let s = decode_text_obj(&Object::LiteralString(b"hello".to_vec()));
        assert_eq!(s.as_deref(), Some("hello"));
    }

    #[test]
    fn decode_text_obj_utf16be_hex_decodes() {
        // FEFF + UTF-16BE "Hi" = FEFF 0048 0069
        let s = decode_text_obj(&Object::HexString(vec![0xFE, 0xFF, 0x00, 0x48, 0x00, 0x69]));
        assert_eq!(s.as_deref(), Some("Hi"));
    }

    #[test]
    fn decode_text_obj_hex_without_bom_treated_as_utf8() {
        let s = decode_text_obj(&Object::HexString(b"hello".to_vec()));
        assert_eq!(s.as_deref(), Some("hello"));
    }
}
