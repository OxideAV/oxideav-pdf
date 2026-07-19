//! Round-25 — PDF Link annotation reader (ISO 32000-1 §12.5.6.5).
//!
//! Walks every page's `/Annots` array, filters down to entries whose
//! `/Subtype` is `/Link`, and surfaces them as [`PdfLink`] values.
//! Each link's destination decodes to either an
//! [`crate::outline::OutlineDestination`] (internal go-to) or a URI
//! (`/A << /S /URI /URI (...) >>`). A **named** destination (`/Dest`
//! as a Name or byte string, §12.3.2.3) resolves through the
//! document's named-destination sources (round 418) and surfaces as
//! `Internal`; only a name the document doesn't define stays
//! [`PdfLinkTarget::Named`].
//!
//! Pages without annotations or without any Link entries return an
//! empty Vec. Malformed annotation dicts are skipped (best-effort
//! enumeration matches the round-21 `/Sig` reader's contract).

use std::collections::HashMap;

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::outline::OutlineDestination;
use crate::reader::document::DocumentReader;
use crate::reader::named_dest::{named_dest_map, ResolvedNamedDest};
use crate::reader::nametree::decode_key_text;
use crate::reader::outline::build_page_index_map;

/// The raw-name → resolved-destination lookaside built once per walk
/// (§12.3.2.3). Empty for the (common) document with no named dests.
type NamedDests = HashMap<Vec<u8>, ResolvedNamedDest>;

/// One Link annotation, ready for a caller to follow.
#[derive(Debug, Clone)]
pub struct PdfLink {
    /// 0-based page index — which page in DFS order carries this
    /// annotation in its `/Annots` array.
    pub source_page_index: usize,
    /// `/Rect` — clickable bounding rectangle in default user space
    /// (PDF coordinates, origin bottom-left).
    pub rect: [f32; 4],
    /// Where the link points. `None` when the annotation has neither
    /// a `/Dest` nor an `/A` action this reader recognises (rare —
    /// most PDFs in the wild populate at least one).
    pub target: Option<PdfLinkTarget>,
}

/// What a [`PdfLink`] points to.
#[derive(Debug, Clone)]
pub enum PdfLinkTarget {
    /// In-document jump.
    Internal(OutlineDestination),
    /// External URI (HTTP, mailto, etc.).
    Uri(String),
    /// A named destination (`/Dest` was a Name or string instead of
    /// the explicit array form) that the document does **not** define
    /// in either §12.3.2.3 source (catalogue `/Dests` dictionary or
    /// `/Names → /Dests` name tree) — a defined name resolves to
    /// [`Self::Internal`] since round 418. The string is the display
    /// form of the undefined name.
    Named(String),
}

/// Walk every page in DFS order, collecting every Link annotation.
/// The result keeps the source page-index baked in so callers don't
/// have to re-thread it.
pub fn links(reader: &mut DocumentReader<'_>) -> Result<Vec<PdfLink>, PdfError> {
    let page_index_map = build_page_index_map(reader)?;
    let named_dests = named_dest_map(reader, &page_index_map)?;
    // Inverse: position-in-DFS → ObjectId.
    let mut pages_by_index: Vec<ObjectId> = Vec::with_capacity(page_index_map.len());
    pages_by_index.resize(page_index_map.len(), ObjectId::new(0));
    for (n, idx) in &page_index_map {
        pages_by_index[*idx] = ObjectId::new(*n);
    }

    let mut out = Vec::new();
    for (idx, page_id) in pages_by_index.iter().enumerate() {
        // page-id 0 is impossible (PDF allocates from 1), so it's a
        // sentinel for "this slot was never populated" — skip.
        if page_id.number == 0 {
            continue;
        }
        let page = match reader.resolve(*page_id)? {
            Object::Dict(d) => d,
            _ => continue,
        };
        let annots_obj = page
            .entries()
            .iter()
            .find(|(k, _)| k == "Annots")
            .map(|(_, v)| v.clone());
        let Some(annots_obj) = annots_obj else {
            continue;
        };
        // /Annots may be inline array or indirect reference to one.
        let annots_obj = reader.deref(annots_obj)?;
        let Object::Array(items) = annots_obj else {
            continue;
        };
        for item in items {
            let annot = match reader.deref(item)? {
                Object::Dict(d) => d,
                _ => continue,
            };
            let is_link = matches!(
                annot.entries().iter().find(|(k, _)| k == "Subtype").map(|(_, v)| v),
                Some(Object::Name(s)) if s == "Link"
            );
            if !is_link {
                continue;
            }
            if let Some(link) = decode_link(reader, &annot, idx, &page_index_map, &named_dests)? {
                out.push(link);
            }
        }
    }
    Ok(out)
}

fn decode_link(
    reader: &mut DocumentReader<'_>,
    annot: &Dict,
    page_index: usize,
    page_index_map: &HashMap<u32, usize>,
    named_dests: &NamedDests,
) -> Result<Option<PdfLink>, PdfError> {
    let rect = match annot
        .entries()
        .iter()
        .find(|(k, _)| k == "Rect")
        .map(|(_, v)| v)
    {
        Some(Object::Array(items)) if items.len() == 4 => {
            let mut out = [0f32; 4];
            for (i, it) in items.iter().enumerate() {
                out[i] = match it {
                    Object::Real(f) => *f as f32,
                    Object::Integer(n) => *n as f32,
                    _ => return Ok(None),
                };
            }
            out
        }
        _ => return Ok(None),
    };

    let target = decode_link_target(reader, annot, page_index_map, named_dests)?;

    Ok(Some(PdfLink {
        source_page_index: page_index,
        rect,
        target,
    }))
}

fn decode_link_target(
    reader: &mut DocumentReader<'_>,
    annot: &Dict,
    page_index_map: &HashMap<u32, usize>,
    named_dests: &NamedDests,
) -> Result<Option<PdfLinkTarget>, PdfError> {
    // /Dest takes precedence over /A per Table 173.
    if let Some(dest) = annot
        .entries()
        .iter()
        .find(|(k, _)| k == "Dest")
        .map(|(_, v)| v.clone())
    {
        let dest = reader.deref(dest)?;
        return Ok(decode_dest_value(dest, page_index_map, named_dests));
    }
    if let Some(action) = annot
        .entries()
        .iter()
        .find(|(k, _)| k == "A")
        .map(|(_, v)| v.clone())
    {
        let action = reader.deref(action)?;
        if let Object::Dict(adict) = action {
            let s_kind =
                adict
                    .entries()
                    .iter()
                    .find(|(k, _)| k == "S")
                    .and_then(|(_, v)| match v {
                        Object::Name(s) => Some(s.clone()),
                        _ => None,
                    });
            match s_kind.as_deref() {
                Some("URI") => {
                    let uri = adict.entries().iter().find(|(k, _)| k == "URI").and_then(
                        |(_, v)| match v {
                            Object::LiteralString(b) | Object::HexString(b) => {
                                Some(String::from_utf8_lossy(b).into_owned())
                            }
                            _ => None,
                        },
                    );
                    return Ok(uri.map(PdfLinkTarget::Uri));
                }
                Some("GoTo") => {
                    if let Some(d) = adict
                        .entries()
                        .iter()
                        .find(|(k, _)| k == "D")
                        .map(|(_, v)| v.clone())
                    {
                        let d = reader.deref(d)?;
                        return Ok(decode_dest_value(d, page_index_map, named_dests));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(None)
}

fn decode_dest_value(
    dest: Object,
    page_index_map: &HashMap<u32, usize>,
    named_dests: &NamedDests,
) -> Option<PdfLinkTarget> {
    match dest {
        Object::Array(items) => {
            decode_explicit_dest(&items, page_index_map).map(PdfLinkTarget::Internal)
        }
        Object::Name(s) => named_target(named_dests, s.as_bytes()),
        Object::LiteralString(b) | Object::HexString(b) => named_target(named_dests, &b),
        _ => None,
    }
}

/// §12.3.2.3 — a defined name becomes `Internal`; an undefined one
/// stays `Named` with its display text.
fn named_target(named_dests: &NamedDests, raw: &[u8]) -> Option<PdfLinkTarget> {
    match named_dests.get(raw).and_then(|(d, _)| d.clone()) {
        Some(dest) => Some(PdfLinkTarget::Internal(dest)),
        None => Some(PdfLinkTarget::Named(decode_key_text(raw))),
    }
}

fn decode_explicit_dest(
    items: &[Object],
    page_index_map: &HashMap<u32, usize>,
) -> Option<OutlineDestination> {
    if items.len() < 2 {
        return None;
    }
    let page_index = match &items[0] {
        Object::Reference(id) => *page_index_map.get(&id.number)?,
        _ => return None,
    };
    let mode = match &items[1] {
        Object::Name(n) => n.as_str(),
        _ => return None,
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_dest_value_named_byte_string() {
        // Undefined name → stays Named.
        let v = decode_dest_value(
            Object::LiteralString(b"Chap6.begin".to_vec()),
            &HashMap::new(),
            &HashMap::new(),
        );
        match v {
            Some(PdfLinkTarget::Named(s)) => assert_eq!(s, "Chap6.begin"),
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[test]
    fn decode_dest_value_named_resolves_to_internal() {
        // Defined name → resolves to Internal per §12.3.2.3.
        let mut named: NamedDests = HashMap::new();
        named.insert(
            b"Chap6.begin".to_vec(),
            (Some(OutlineDestination::Fit { page_index: 4 }), None),
        );
        let v = decode_dest_value(
            Object::LiteralString(b"Chap6.begin".to_vec()),
            &HashMap::new(),
            &named,
        );
        match v {
            Some(PdfLinkTarget::Internal(OutlineDestination::Fit { page_index })) => {
                assert_eq!(page_index, 4);
            }
            other => panic!("expected Internal Fit, got {other:?}"),
        }
    }

    #[test]
    fn decode_dest_value_array_fit_resolves_page_index() {
        let mut map = HashMap::new();
        map.insert(7u32, 3usize);
        let v = decode_dest_value(
            Object::Array(vec![
                Object::Reference(ObjectId::new(7)),
                Object::Name("Fit".into()),
            ]),
            &map,
            &HashMap::new(),
        );
        match v {
            Some(PdfLinkTarget::Internal(OutlineDestination::Fit { page_index })) => {
                assert_eq!(page_index, 3);
            }
            other => panic!("expected Internal Fit, got {other:?}"),
        }
    }

    #[test]
    fn decode_explicit_dest_xyz_with_zoom_zero_is_none() {
        let mut map = HashMap::new();
        map.insert(2u32, 0usize);
        let arr = vec![
            Object::Reference(ObjectId::new(2)),
            Object::Name("XYZ".into()),
            Object::Real(10.0),
            Object::Real(20.0),
            Object::Real(0.0),
        ];
        let d = decode_explicit_dest(&arr, &map).unwrap();
        assert_eq!(
            d,
            OutlineDestination::Xyz {
                page_index: 0,
                left: Some(10.0),
                top: Some(20.0),
                zoom: None,
            }
        );
    }
}
