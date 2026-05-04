//! Top-level reader — bytes → resolved [`Document`] / [`Scene`].
//!
//! Glues [`crate::reader::xref`] (locate + parse cross-reference
//! table) and [`crate::reader::parse`] (decode an indirect object at
//! a given byte offset) into a one-shot pipeline:
//!
//! 1. [`load_xref`] — locate `startxref`, parse the xref table,
//!    keep the trailer dict.
//! 2. [`fetch_object`] — given an [`ObjectId`], seek to the byte
//!    offset, decode the indirect object's body (recursively
//!    resolving references on demand).
//! 3. [`read_pdf_to_scene`] — top-level entry point: bytes →
//!    [`oxideav_scene::Scene`] in pages mode. Walks the catalog →
//!    pages tree → per-page Contents → content-stream parser, and
//!    extracts /Info → [`Metadata`].
//!
//! Round 3 supports PDF 1.4 with a simple xref + uncompressed object
//! streams. FlateDecode-compressed Contents streams **are** decoded
//! here — the writer FlateDecode-compresses image XObjects + may
//! later compress content streams; supporting it now keeps the
//! reader symmetric with the writer's output. Object streams (PDF
//! 1.5+) and encryption are deferred to round 4+.

use std::collections::HashMap;
use std::io::Read;

use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Rgba, VectorFrame,
};
use oxideav_core::TimeBase;
use oxideav_scene::{Metadata, Page, Scene};

use crate::error::PdfError;
use crate::objects::{Object, ObjectId, Stream};
use crate::reader::content::parse_content_stream;
use crate::reader::parse::Parser;
use crate::reader::xref::{parse_xref, XrefTable};

/// A read-time view of the PDF document — owns the byte slice plus a
/// resolved cross-reference table and a small object cache. Indirect
/// objects are decoded lazily via [`Self::resolve`].
pub struct DocumentReader<'a> {
    input: &'a [u8],
    xref: XrefTable,
    cache: HashMap<ObjectId, Object>,
}

impl<'a> DocumentReader<'a> {
    /// Parse the cross-reference table + trailer for `input`. The
    /// per-object body decoder is on-demand — call [`Self::resolve`]
    /// for each indirect object you need.
    pub fn open(input: &'a [u8]) -> Result<Self, PdfError> {
        let xref = parse_xref(input)?;
        Ok(Self {
            input,
            xref,
            cache: HashMap::new(),
        })
    }

    /// The trailer dict (carries `/Root`, optional `/Info`, etc.).
    pub fn xref(&self) -> &XrefTable {
        &self.xref
    }

    /// Decode the indirect object at `id`. Cached on first hit so a
    /// second `resolve(id)` is O(1).
    pub fn resolve(&mut self, id: ObjectId) -> Result<Object, PdfError> {
        if let Some(o) = self.cache.get(&id) {
            return Ok(o.clone());
        }
        let off = self
            .xref
            .offset_of(id)
            .ok_or_else(|| PdfError::other(format!("PDF reader: object {id:?} not in xref")))?;
        let mut p = Parser::new(self.input);
        p.lexer_mut().seek(off as usize);
        let (parsed_id, body) = p.parse_indirect()?;
        if parsed_id != id {
            return Err(PdfError::other(format!(
                "PDF reader: xref points to wrong object — wanted {id:?}, got {parsed_id:?}"
            )));
        }
        self.cache.insert(id, body.clone());
        Ok(body)
    }

    /// If `obj` is `Object::Reference`, follow it (recursively) until
    /// a non-reference value resolves. Returns the deref'd value.
    pub fn deref(&mut self, obj: Object) -> Result<Object, PdfError> {
        let mut cur = obj;
        let mut hops = 0;
        while let Object::Reference(id) = cur {
            cur = self.resolve(id)?;
            hops += 1;
            if hops > 16 {
                return Err(PdfError::other(
                    "PDF reader: indirect-reference chain too deep (>16 hops)",
                ));
            }
        }
        Ok(cur)
    }
}

/// Convenience — open + read straight into a [`Scene`] in pages mode.
/// Inverse of [`crate::write_pdf_from_scene`] for PDFs the writer
/// would produce.
///
/// Returns `Err` for:
/// - Malformed xref / trailer (round-3 only handles plain xref tables;
///   PDF 1.5+ /XRef streams surface as parse errors).
/// - Encrypted PDFs (the trailer's `/Encrypt` is rejected — round-4+).
/// - Documents that decode to zero pages (catalog → pages tree
///   walked but no Page leaves found).
pub fn read_pdf_to_scene(input: &[u8]) -> Result<Scene, PdfError> {
    let mut reader = DocumentReader::open(input)?;

    // Encryption check — present an early, actionable error rather
    // than emitting garbled paths.
    if reader
        .xref
        .trailer
        .entries()
        .iter()
        .any(|(k, _)| k == "Encrypt")
    {
        return Err(PdfError::other(
            "PDF reader: encrypted PDFs are not supported — round-3 limitation",
        ));
    }

    // Catalog → /Pages reference.
    let root_id = reader.xref.root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog) = catalog else {
        return Err(PdfError::other(format!(
            "PDF reader: /Root must be a dictionary (got {catalog:?})"
        )));
    };
    let pages_ref = catalog
        .entries()
        .iter()
        .find(|(k, _)| k == "Pages")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| PdfError::other("PDF reader: catalog missing /Pages"))?;
    let Object::Reference(pages_root_id) = pages_ref else {
        return Err(PdfError::other(format!(
            "PDF reader: catalog /Pages must be an indirect reference (got {pages_ref:?})"
        )));
    };

    // Walk the /Pages tree depth-first into a flat list of Page leaf
    // ids.
    let mut leaves = Vec::new();
    walk_pages_tree(&mut reader, pages_root_id, &mut leaves)?;
    if leaves.is_empty() {
        return Err(PdfError::other(
            "PDF reader: /Pages tree contained no Page leaves",
        ));
    }

    // Decode each Page → oxideav_scene::Page.
    let mut scene_pages = Vec::with_capacity(leaves.len());
    for leaf_id in leaves {
        scene_pages.push(decode_page(&mut reader, leaf_id)?);
    }

    // /Info → Metadata.
    let metadata = if let Some(info_id) = reader.xref.info() {
        let info = reader.resolve(info_id)?;
        decode_metadata(info)?
    } else {
        Metadata::default()
    };

    Ok(Scene {
        pages: Some(scene_pages),
        metadata,
        ..Scene::default()
    })
}

fn walk_pages_tree(
    reader: &mut DocumentReader<'_>,
    node_id: ObjectId,
    out: &mut Vec<ObjectId>,
) -> Result<(), PdfError> {
    let node = reader.resolve(node_id)?;
    let Object::Dict(d) = node else {
        return Err(PdfError::other(format!(
            "PDF reader: pages-tree node {node_id:?} is not a dict"
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
                    PdfError::other(format!("PDF reader: /Pages node {node_id:?} missing /Kids"))
                })?;
            let Object::Array(items) = kids else {
                return Err(PdfError::other(format!(
                    "PDF reader: /Kids must be an array on {node_id:?}"
                )));
            };
            for item in items {
                if let Object::Reference(id) = item {
                    walk_pages_tree(reader, id, out)?;
                }
            }
            Ok(())
        }
        _ => Err(PdfError::other(format!(
            "PDF reader: pages-tree node {node_id:?} has unknown /Type {kind:?}"
        ))),
    }
}

fn decode_page(reader: &mut DocumentReader<'_>, page_id: ObjectId) -> Result<Page, PdfError> {
    let page_obj = reader.resolve(page_id)?;
    let Object::Dict(page_dict) = page_obj else {
        return Err(PdfError::other(format!(
            "PDF reader: page {page_id:?} is not a dict"
        )));
    };

    // /MediaBox is required for the leaf page (or inherited from a
    // parent — round-3 only handles directly-attached media boxes;
    // inheritance lands in round 4 if the writer ever needs it).
    let media_box = page_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "MediaBox")
        .map(|(_, v)| v.clone());
    let (width, height) = match media_box {
        Some(Object::Array(items)) if items.len() == 4 => {
            let llx = number_to_f32(&items[0])?;
            let lly = number_to_f32(&items[1])?;
            let urx = number_to_f32(&items[2])?;
            let ury = number_to_f32(&items[3])?;
            ((urx - llx).abs(), (ury - lly).abs())
        }
        Some(other) => {
            return Err(PdfError::other(format!(
                "PDF reader: /MediaBox must be a 4-array (got {other:?})"
            )));
        }
        None => {
            // Round-3: no inheritance walk. Default to A4 portrait
            // so the page object is still constructible.
            (595.0, 842.0)
        }
    };

    // /Contents is one stream OR an array of streams. Concatenate.
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
        Some(other) => {
            return Err(PdfError::other(format!(
                "PDF reader: /Contents must be a Stream or array (got {other:?})"
            )));
        }
        None => Vec::new(),
    };

    let root = parse_content_stream(&content_bytes)?;
    let mut page = Page::new(width, height);
    page.content = VectorFrame {
        width,
        height,
        view_box: None,
        root,
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    Ok(page)
}

fn extract_stream_data(reader: &mut DocumentReader<'_>, id: ObjectId) -> Result<Vec<u8>, PdfError> {
    let obj = reader.resolve(id)?;
    let Object::Stream(s) = obj else {
        return Err(PdfError::other(format!(
            "PDF reader: object {id:?} expected to be a Stream (got {obj:?})"
        )));
    };
    decode_stream(&s)
}

/// Apply the stream's `/Filter` (if any) to recover the raw payload.
/// Round 3 supports `FlateDecode` only — the only filter the writer
/// emits (DCTDecode, CCITTFaxDecode, etc. land in round 4+).
pub fn decode_stream(stream: &Stream) -> Result<Vec<u8>, PdfError> {
    let filter = stream
        .dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Filter")
        .map(|(_, v)| v.clone());
    match filter {
        None => Ok(stream.data.clone()),
        Some(Object::Name(name)) if name == "FlateDecode" => flate_decompress(&stream.data),
        Some(Object::Array(items)) => {
            // Filter chain — apply in order. Round-3 only handles
            // FlateDecode in this position.
            let mut data = stream.data.clone();
            for item in items {
                let Object::Name(name) = item else {
                    return Err(PdfError::other(format!(
                        "PDF reader: /Filter chain item must be a Name (got {item:?})"
                    )));
                };
                if name != "FlateDecode" {
                    return Err(PdfError::other(format!(
                        "PDF reader: filter `{name}` not yet supported (round-3 = FlateDecode only)"
                    )));
                }
                data = flate_decompress(&data)?;
            }
            Ok(data)
        }
        Some(Object::Name(name)) => Err(PdfError::other(format!(
            "PDF reader: filter `{name}` not yet supported (round-3 = FlateDecode only)"
        ))),
        Some(other) => Err(PdfError::other(format!(
            "PDF reader: /Filter must be a Name or array of Names (got {other:?})"
        ))),
    }
}

fn flate_decompress(input: &[u8]) -> Result<Vec<u8>, PdfError> {
    use flate2::read::ZlibDecoder;
    let mut out = Vec::new();
    let mut dec = ZlibDecoder::new(input);
    dec.read_to_end(&mut out)
        .map_err(|e| PdfError::other(format!("PDF reader: FlateDecode failed: {e}")))?;
    Ok(out)
}

fn decode_metadata(info: Object) -> Result<Metadata, PdfError> {
    let Object::Dict(d) = info else {
        return Err(PdfError::other(format!(
            "PDF reader: /Info must be a dict (got {info:?})"
        )));
    };
    let mut m = Metadata::default();
    for (k, v) in d.entries() {
        match k.as_str() {
            "Title" => m.title = decode_text(v),
            "Author" => m.author = decode_text(v),
            "Subject" => m.subject = decode_text(v),
            "Keywords" => {
                if let Some(s) = decode_text(v) {
                    // Reverse the writer's `keywords.join(", ")` —
                    // split + trim. Falls back to a single-element
                    // vec when the string has no separator.
                    m.keywords = s.split(',').map(|p| p.trim().to_owned()).collect();
                }
            }
            "Creator" => m.creator = decode_text(v),
            "Producer" => m.producer = decode_text(v),
            "CreationDate" => m.created_at = decode_text(v).map(pdf_date_to_iso8601),
            "ModDate" => m.modified_at = decode_text(v).map(pdf_date_to_iso8601),
            other => {
                if let Some(s) = decode_text(v) {
                    m.custom.insert(other.to_owned(), s);
                }
            }
        }
    }
    Ok(m)
}

/// Convert a PDF date `D:YYYYMMDDHHmmSSOHH'mm'` back to ISO-8601.
/// Inputs that don't start with `D:` are returned as-is so the
/// scene's metadata round-trip is lossless for non-date strings.
pub fn pdf_date_to_iso8601(s: String) -> String {
    let bytes = s.as_bytes();
    if !bytes.starts_with(b"D:") {
        return s;
    }
    let rest = &bytes[2..];
    if rest.len() < 4 {
        return s.clone();
    }
    let mut out = String::with_capacity(25);
    let year = &rest[0..4.min(rest.len())];
    out.push_str(&String::from_utf8_lossy(year));
    if rest.len() >= 6 {
        out.push('-');
        out.push_str(&String::from_utf8_lossy(&rest[4..6]));
    }
    if rest.len() >= 8 {
        out.push('-');
        out.push_str(&String::from_utf8_lossy(&rest[6..8]));
    }
    if rest.len() >= 10 {
        out.push('T');
        out.push_str(&String::from_utf8_lossy(&rest[8..10]));
    }
    if rest.len() >= 12 {
        out.push(':');
        out.push_str(&String::from_utf8_lossy(&rest[10..12]));
    }
    if rest.len() >= 14 {
        out.push(':');
        out.push_str(&String::from_utf8_lossy(&rest[12..14]));
    }
    // Zone designator.
    if rest.len() == 15 && rest[14] == b'Z' {
        out.push('Z');
    } else if rest.len() >= 17 && (rest[14] == b'+' || rest[14] == b'-') {
        // ±HH'mm'  → ±HH:mm
        out.push(rest[14] as char);
        out.push_str(&String::from_utf8_lossy(&rest[15..17]));
        // Skip the apostrophe; mm follows.
        if rest.len() >= 20 && rest[17] == b'\'' {
            out.push(':');
            out.push_str(&String::from_utf8_lossy(&rest[18..20]));
        }
    }
    out
}

fn decode_text(v: &Object) -> Option<String> {
    match v {
        Object::LiteralString(b) => Some(String::from_utf8_lossy(b).into_owned()),
        Object::HexString(b) => {
            // The writer uses UTF-16BE-with-BOM for non-ASCII; decode
            // back to a Rust String.
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

fn number_to_f32(o: &Object) -> Result<f32, PdfError> {
    match o {
        Object::Integer(n) => Ok(*n as f32),
        Object::Real(f) => Ok(*f as f32),
        other => Err(PdfError::other(format!(
            "PDF reader: expected number, got {other:?}"
        ))),
    }
}

// Suppress dead-code warning on a small helper that the round-3
// Scene assembly doesn't yet use — keeps the writer/reader symmetry
// obvious and lets round-4+ wire it up.
#[allow(dead_code)]
fn empty_root() -> Group {
    Group::default()
}

#[allow(dead_code)]
fn empty_path_node() -> PathNode {
    PathNode {
        path: Path {
            commands: vec![PathCommand::Close],
        },
        fill: Some(Paint::Solid(Rgba::opaque(0, 0, 0))),
        stroke: None,
        fill_rule: FillRule::NonZero,
    }
}

// `Node` is referenced by our parsed content stream output — make
// sure the import isn't pruned by dead-code analysis when this
// commit's tests don't directly observe a Node variant.
#[allow(dead_code)]
fn _node_imported(_: Node) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_pdf_from_scene;

    fn make_scene_with_one_red_rect() -> Scene {
        use oxideav_core::vector::{
            FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
        };
        let mut p = Path::new();
        p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
        p.commands.push(PathCommand::LineTo(Point::new(90.0, 10.0)));
        p.commands.push(PathCommand::LineTo(Point::new(90.0, 90.0)));
        p.commands.push(PathCommand::LineTo(Point::new(10.0, 90.0)));
        p.commands.push(PathCommand::Close);
        let frame = VectorFrame {
            width: 100.0,
            height: 100.0,
            view_box: None,
            root: Group {
                children: vec![Node::Path(PathNode {
                    path: p,
                    fill: Some(Paint::Solid(Rgba::opaque(255, 0, 0))),
                    stroke: None,
                    fill_rule: FillRule::NonZero,
                })],
                ..Group::default()
            },
            pts: None,
            time_base: TimeBase::new(1, 1),
        };
        let mut page = Page::new(100.0, 100.0);
        page.content = frame;
        Scene {
            pages: Some(vec![page]),
            ..Scene::default()
        }
    }

    #[test]
    fn read_pdf_to_scene_roundtrip_single_page() {
        let scene = make_scene_with_one_red_rect();
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        let pages = parsed.pages.expect("scene has pages");
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].width, 100.0);
        assert_eq!(pages[0].height, 100.0);
        // Walk the rebuilt vector frame for a path with the red fill.
        let root = &pages[0].content.root;
        // The reader produces a top-level frame containing one
        // `q ... Q`-derived child group; that child group contains
        // the path node.
        // The reader's q/Q nesting mirrors the writer's emission:
        //   root q (frame group walker)
        //     per-path q
        //       path
        //     Q
        //   Q
        // — so the path is two Group hops below the root.
        let path_node = find_first_path(root).expect("at least one PathNode in the tree");
        match &path_node.fill {
            Some(Paint::Solid(rgba)) => assert_eq!((rgba.r, rgba.g, rgba.b), (255, 0, 0)),
            other => panic!("expected solid red, got {other:?}"),
        }
    }

    fn find_first_path(group: &Group) -> Option<&PathNode> {
        for child in &group.children {
            match child {
                Node::Path(p) => return Some(p),
                Node::Group(g) => {
                    if let Some(p) = find_first_path(g) {
                        return Some(p);
                    }
                }
                _ => {}
            }
        }
        None
    }

    #[test]
    fn read_pdf_to_scene_roundtrip_multi_page() {
        use oxideav_core::vector::Rgba;
        let mut scene = make_scene_with_one_red_rect();
        let mut p2 = Page::new(200.0, 100.0);
        p2.content.width = 200.0;
        p2.content.height = 100.0;
        // Make a green rect on page 2.
        use oxideav_core::vector::{Group, Node, Paint, Path, PathCommand, PathNode, Point};
        let mut path = Path::new();
        path.commands
            .push(PathCommand::MoveTo(Point::new(0.0, 0.0)));
        path.commands
            .push(PathCommand::LineTo(Point::new(50.0, 0.0)));
        path.commands
            .push(PathCommand::LineTo(Point::new(50.0, 50.0)));
        path.commands.push(PathCommand::Close);
        p2.content.root = Group {
            children: vec![Node::Path(PathNode {
                path,
                fill: Some(Paint::Solid(Rgba::opaque(0, 255, 0))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        };
        scene.pages.as_mut().unwrap().push(p2);
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        let pages = parsed.pages.expect("scene has pages");
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].width, 100.0);
        assert_eq!(pages[1].width, 200.0);
    }

    #[test]
    fn read_pdf_metadata_roundtrip() {
        let mut scene = make_scene_with_one_red_rect();
        scene.metadata = Metadata {
            title: Some("Round 3 Doc".into()),
            author: Some("Mark".into()),
            subject: Some("Reader test".into()),
            keywords: vec!["pdf".into(), "round3".into()],
            creator: Some("MyApp".into()),
            producer: Some("oxideav-pdf".into()),
            created_at: Some("2026-05-04T12:30:45Z".into()),
            modified_at: Some("2026-05-04T13:00:00Z".into()),
            ..Metadata::default()
        };
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        assert_eq!(parsed.metadata.title.as_deref(), Some("Round 3 Doc"));
        assert_eq!(parsed.metadata.author.as_deref(), Some("Mark"));
        assert_eq!(parsed.metadata.subject.as_deref(), Some("Reader test"));
        assert_eq!(parsed.metadata.creator.as_deref(), Some("MyApp"));
        assert_eq!(parsed.metadata.producer.as_deref(), Some("oxideav-pdf"));
        assert_eq!(
            parsed.metadata.keywords,
            vec!["pdf".to_string(), "round3".to_string()]
        );
        // PDF dates round-trip through `pdf_date_to_iso8601`.
        assert_eq!(
            parsed.metadata.created_at.as_deref(),
            Some("2026-05-04T12:30:45Z")
        );
    }

    #[test]
    fn read_pdf_custom_metadata_roundtrip() {
        let mut scene = make_scene_with_one_red_rect();
        let mut custom = std::collections::BTreeMap::new();
        custom.insert("dc:rights".into(), "(c) 2026 Karpeles".into());
        custom.insert("Trapped".into(), "False".into());
        scene.metadata = Metadata {
            custom,
            ..Metadata::default()
        };
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        assert_eq!(
            parsed.metadata.custom.get("dc:rights").map(String::as_str),
            Some("(c) 2026 Karpeles")
        );
        assert_eq!(
            parsed.metadata.custom.get("Trapped").map(String::as_str),
            Some("False")
        );
    }

    #[test]
    fn read_pdf_unicode_metadata_roundtrip() {
        let mut scene = make_scene_with_one_red_rect();
        scene.metadata = Metadata {
            title: Some("日本語".into()),
            ..Metadata::default()
        };
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        assert_eq!(parsed.metadata.title.as_deref(), Some("日本語"));
    }

    #[test]
    fn pdf_date_to_iso8601_format() {
        assert_eq!(
            pdf_date_to_iso8601("D:20260504123045Z".to_string()),
            "2026-05-04T12:30:45Z"
        );
        assert_eq!(
            pdf_date_to_iso8601("D:20260504123045+09'00'".to_string()),
            "2026-05-04T12:30:45+09:00"
        );
    }

    #[test]
    fn no_metadata_yields_default() {
        let scene = make_scene_with_one_red_rect();
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        assert!(parsed.metadata.title.is_none());
        assert!(parsed.metadata.custom.is_empty());
    }
}
