//! Top-level PDF writer.
//!
//! [`write_pdf`] is the one-shot single-page entry point: it takes an
//! [`oxideav_core::VectorFrame`], walks the scene graph, emits a
//! single-page PDF 1.4 document, and returns the bytes.
//!
//! [`write_pdf_from_scene`] is the round-2 multi-page entry point: it
//! takes an [`oxideav_scene::Scene`] in pages mode and emits one PDF
//! Page per [`oxideav_scene::Page`].
//!
//! The walker lives in [`emit_group`] — it dispatches each [`Node`]
//! variant to the matching [`crate::operators`] helper, and remembers
//! any gradient / opacity / image it encounters via the
//! [`crate::resources::ResourceCollector`] so the page's `/Resources`
//! dictionary stays in sync.

use oxideav_core::vector::{FillRule, Group, ImageRef, Node, PathNode, VectorFrame};
use oxideav_scene::Scene;

use crate::encrypt::{EncryptionConfig, EncryptionState};
use crate::error::PdfError;
use crate::info::{build_info_dict, has_metadata};
use crate::objects::{Dict, Document, Object, Stream};
use crate::operators::{
    concat_matrix, emit_clip_marker, emit_path, paint, restore, save, set_ext_gstate,
    set_fill_paint, set_stroke_style, OpBuf, PaintMode,
};
use crate::page::{build_page, build_pages, PageInput};
use crate::reader::xref::{find_startxref_offset, parse_xref};
use crate::resources::ResourceCollector;

/// Render a [`VectorFrame`] as a single-page PDF 1.4 document.
///
/// Round 1: only the geometry / paint / image surface listed in the
/// crate README is emitted. Future rounds will add text, JPEG
/// passthrough, multi-page, etc.
pub fn write_pdf(frame: &VectorFrame) -> Result<Vec<u8>, PdfError> {
    let (content, resources) = render_frame(frame);

    let mut doc = Document::new();
    let _ = build_page(&mut doc, frame, content, &resources);

    let mut out = Vec::with_capacity(2048);
    doc.write_to(&mut out)?;
    Ok(out)
}

/// Render a [`Scene`] in pages mode as a multi-page PDF 1.4 document.
///
/// Round 2 entry point — accepts only paged scenes (`scene.pages` is
/// `Some(non-empty)`) and emits one PDF Page per [`oxideav_scene::Page`],
/// each carrying its own MediaBox derived from the page's own width /
/// height.
///
/// Returns [`PdfError::Other`] if `scene.pages` is `None` or
/// `Some(empty)` — the scene is in timeline mode and the PNG / MP4 /
/// RTMP writers (not this crate) should handle it.
///
/// `scene.metadata` is wired into the PDF `/Info` dictionary via
/// [`build_info_dict`]. Standard fields (`Title`, `Author`, `Subject`,
/// `Keywords`, `Creator`, `Producer`, `CreationDate`, `ModDate`) land
/// directly; the [`oxideav_scene::Metadata::custom`] map flows into
/// the same dict as additional keys (ISO 32000-1 §14.3.3 allows
/// arbitrary `/Info` entries).
pub fn write_pdf_from_scene(scene: &Scene) -> Result<Vec<u8>, PdfError> {
    let pages = scene
        .pages
        .as_ref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            PdfError::other(
                "write_pdf_from_scene: scene is not in pages mode (scene.pages is None or empty)",
            )
        })?;

    // Render each page's vector content into its own (op-buf,
    // resources) pair so per-page resource tables stay independent.
    // Holding the rendered bytes + resources in a `Vec` lets us hand
    // borrowed references to the page builder in one shot.
    struct Rendered<'a> {
        frame: &'a VectorFrame,
        width: f32,
        height: f32,
        content_bytes: Vec<u8>,
        resources: ResourceCollector,
    }
    let rendered: Vec<Rendered<'_>> = pages
        .iter()
        .map(|page| {
            let (content_bytes, resources) = render_frame(&page.content);
            Rendered {
                frame: &page.content,
                width: page.width,
                height: page.height,
                content_bytes,
                resources,
            }
        })
        .collect();

    let inputs: Vec<PageInput<'_>> = rendered
        .into_iter()
        .map(|r| PageInput {
            width: r.width,
            height: r.height,
            content_bytes: r.content_bytes,
            resources: r.resources,
            frame: r.frame,
        })
        .collect();

    let mut doc = Document::new();
    let _ = build_pages(&mut doc, inputs);

    // Wire scene metadata into /Info and link from the trailer. Skip
    // when no field is populated so trivial documents stay byte-stable
    // with the round-2-A multi-page-only output.
    if has_metadata(&scene.metadata) {
        let info_id = doc.add(Object::Dict(build_info_dict(&scene.metadata)));
        doc.info = Some(info_id);
    }

    let mut out = Vec::with_capacity(4096);
    doc.write_to(&mut out)?;
    Ok(out)
}

/// Render a [`Scene`] in pages mode as a multi-page PDF document and
/// emit a PDF 1.5+ cross-reference *stream* (`/Type /XRef`,
/// ISO 32000-1 §7.5.8) instead of the classical `xref`-keyword table.
///
/// Round-7 mirror of the round-6 reader. The xref-stream form is the
/// only way to keep an incremental-update chain compact past ~50 pages
/// (the classical 20-byte-per-entry table grows linearly), and is the
/// prerequisite for `/Type /ObjStm` object-stream embedding.
///
/// The on-wire emission uses `/W [1 4 2]` field widths, FlateDecode +
/// PNG-Up `/Predictor 12` body — the exact shape the round-6 reader's
/// predictor reversal already accepts.
pub fn write_pdf_from_scene_xref_stream(scene: &Scene) -> Result<Vec<u8>, PdfError> {
    let pages = scene
        .pages
        .as_ref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            PdfError::other(
                "write_pdf_from_scene_xref_stream: scene is not in pages mode (scene.pages is None or empty)",
            )
        })?;

    struct Rendered<'a> {
        frame: &'a VectorFrame,
        width: f32,
        height: f32,
        content_bytes: Vec<u8>,
        resources: ResourceCollector,
    }
    let rendered: Vec<Rendered<'_>> = pages
        .iter()
        .map(|page| {
            let (content_bytes, resources) = render_frame(&page.content);
            Rendered {
                frame: &page.content,
                width: page.width,
                height: page.height,
                content_bytes,
                resources,
            }
        })
        .collect();

    let inputs: Vec<PageInput<'_>> = rendered
        .into_iter()
        .map(|r| PageInput {
            width: r.width,
            height: r.height,
            content_bytes: r.content_bytes,
            resources: r.resources,
            frame: r.frame,
        })
        .collect();

    let mut doc = Document::new();
    let _ = build_pages(&mut doc, inputs);
    if has_metadata(&scene.metadata) {
        let info_id = doc.add(Object::Dict(build_info_dict(&scene.metadata)));
        doc.info = Some(info_id);
    }
    doc.xref_stream = true;

    let mut out = Vec::with_capacity(4096);
    doc.write_to(&mut out)?;
    Ok(out)
}

/// Render a [`Scene`] in pages mode as a multi-page PDF document and
/// emit a PDF 1.5+ cross-reference stream **plus** a `/Type /ObjStm`
/// object-stream container (ISO 32000-1 §7.5.7) that holds every
/// compressible indirect object (every dict that isn't a stream and
/// isn't the document Catalog). Pairs with the round-7 reader's
/// ObjStm resolver — bytes round-trip through
/// [`crate::read_pdf_to_scene`].
///
/// ObjStm packing is the natural pair to the xref-stream encoder:
/// real-world PDFs at 50+ pages need both at once or the file size
/// quickly grows past what an `xref` table alone is good for. The
/// trade-off versus [`write_pdf_from_scene_xref_stream`] is a
/// modestly smaller file (the dict overhead on every Page,
/// Resources, Pages-tree node disappears) at the cost of one extra
/// indirect object (the ObjStm container) and a hard PDF 1.5+
/// reader-version requirement.
///
/// Stream objects (content streams, image XObjects, the xref stream
/// itself) cannot live inside an ObjStm per §7.5.7 — they remain at
/// their own byte offsets.
pub fn write_pdf_from_scene_object_stream(scene: &Scene) -> Result<Vec<u8>, PdfError> {
    let pages = scene
        .pages
        .as_ref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            PdfError::other(
                "write_pdf_from_scene_object_stream: scene is not in pages mode (scene.pages is None or empty)",
            )
        })?;

    struct Rendered<'a> {
        frame: &'a VectorFrame,
        width: f32,
        height: f32,
        content_bytes: Vec<u8>,
        resources: ResourceCollector,
    }
    let rendered: Vec<Rendered<'_>> = pages
        .iter()
        .map(|page| {
            let (content_bytes, resources) = render_frame(&page.content);
            Rendered {
                frame: &page.content,
                width: page.width,
                height: page.height,
                content_bytes,
                resources,
            }
        })
        .collect();

    let inputs: Vec<PageInput<'_>> = rendered
        .into_iter()
        .map(|r| PageInput {
            width: r.width,
            height: r.height,
            content_bytes: r.content_bytes,
            resources: r.resources,
            frame: r.frame,
        })
        .collect();

    let mut doc = Document::new();
    let _ = build_pages(&mut doc, inputs);
    if has_metadata(&scene.metadata) {
        let info_id = doc.add(Object::Dict(build_info_dict(&scene.metadata)));
        doc.info = Some(info_id);
    }
    doc.xref_stream = true;
    doc.object_stream = true;

    let mut out = Vec::with_capacity(4096);
    doc.write_to(&mut out)?;
    Ok(out)
}

/// Append an incremental update to a previously-written PDF
/// (ISO 32000-1 §7.5.6). The new revision adds one or more pages
/// (whichever pages aren't already in the original document) by
/// emitting fresh indirect objects past the previous file's id
/// range, a new cross-reference section that lists only the changed
/// slots, and a trailer (or xref-stream dict) carrying
/// `/Prev <prev_xref_off>` so the PDF reader can chain the two
/// revisions.
///
/// The contract is:
///
/// 1. `prev_pdf` is a complete PDF previously emitted by
///    [`write_pdf_from_scene`] (classical xref form). The function
///    parses its trailer to recover the previous `/Size`, `/Root`,
///    and existing object id range.
/// 2. `additional_pages` are new pages to append; they get fresh
///    object ids past the previous max. The catalog's `/Pages`
///    tree is rewritten in the new revision (one indirect-object
///    update at the existing pages-tree id) so the page list now
///    includes both old and new kids.
/// 3. The output is `prev_pdf || new-objects || new-xref || trailer
///    || %%EOF` — readers that ignore `/Prev` (very few; none of
///    the modern open-source ones) see the prior revision; readers
///    that follow `/Prev` see the merged revision.
///
/// The new-revision payload is unencrypted regardless of the prior
/// file's encryption state — round 8 doesn't yet rebuild the
/// encryption handler from the trailer's `/Encrypt`. Pass
/// unencrypted PDFs only.
pub fn write_pdf_incremental_update(
    prev_pdf: &[u8],
    additional_pages: &[oxideav_scene::Page],
) -> Result<Vec<u8>, PdfError> {
    let prev_xref_off = find_startxref_offset(prev_pdf)?;
    let prev_table = parse_xref(prev_pdf)?;
    let prev_root = prev_table.root()?;

    // Previous /Size — required so the new trailer's /Size is at
    // least as large as the old (PDF readers require a monotonic
    // /Size when chaining /Prev). Falls back to the maximum id
    // observed in the entries when the trailer doesn't carry one.
    let prev_size_from_trailer = prev_table
        .trailer
        .entries()
        .iter()
        .find(|(k, _)| k == "Size")
        .and_then(|(_, v)| match v {
            Object::Integer(n) if *n >= 0 => Some(*n as u32),
            _ => None,
        });
    let prev_max_id = prev_table.entries.keys().copied().max().unwrap_or(0);
    let prev_size = prev_size_from_trailer.unwrap_or(prev_max_id + 1);

    // Find the catalog's /Pages reference + the existing /Pages
    // dict so we can rewrite it with the new kids appended. We
    // re-parse via a fresh DocumentReader so the existing pages
    // tree comes back as `Object::Dict` we can mutate.
    let mut reader = crate::reader::document::DocumentReader::open(prev_pdf)?;
    let catalog = reader.resolve(prev_root)?;
    let Object::Dict(catalog_dict) = catalog else {
        return Err(PdfError::other(
            "write_pdf_incremental_update: previous /Root is not a Dict",
        ));
    };
    let pages_tree_id = match catalog_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Pages")
        .map(|(_, v)| v)
    {
        Some(Object::Reference(id)) => *id,
        _ => {
            return Err(PdfError::other(
                "write_pdf_incremental_update: previous catalog missing /Pages reference",
            ))
        }
    };
    let pages_tree = reader.resolve(pages_tree_id)?;
    let Object::Dict(pages_tree_dict) = pages_tree else {
        return Err(PdfError::other(
            "write_pdf_incremental_update: previous /Pages tree is not a Dict",
        ));
    };
    let prev_kids: Vec<Object> = pages_tree_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Kids")
        .and_then(|(_, v)| match v {
            Object::Array(items) => Some(items.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let prev_count = match pages_tree_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Count")
        .map(|(_, v)| v)
    {
        Some(Object::Integer(n)) => *n,
        _ => prev_kids.len() as i64,
    };

    // Build the new-revision Document. ID allocation starts past the
    // previous max; the existing `pages_tree_id` is reused (the new
    // revision overwrites it).
    let mut doc = Document::new();
    doc.set_next_id(prev_max_id + 1);

    // Render the new pages.
    struct Rendered {
        width: f32,
        height: f32,
        content_bytes: Vec<u8>,
        resources: ResourceCollector,
    }
    let rendered: Vec<Rendered> = additional_pages
        .iter()
        .map(|page| {
            let (content_bytes, resources) = render_frame(&page.content);
            Rendered {
                width: page.width,
                height: page.height,
                content_bytes,
                resources,
            }
        })
        .collect();

    // Emit each new page: Page dict + Resources + Contents.
    let mut new_kids = prev_kids.clone();
    let mut changed_ids: Vec<u32> = Vec::new();
    for r in rendered {
        let page_id = doc.allocate_id();
        let resources_id = doc.allocate_id();
        let contents_id = doc.allocate_id();

        let media_box = Object::Array(vec![
            Object::Real(0.0),
            Object::Real(0.0),
            Object::Real(r.width as f64),
            Object::Real(r.height as f64),
        ]);

        doc.add_object(
            page_id,
            Object::Dict(
                Dict::new()
                    .with("Type", Object::Name("Page".into()))
                    .with("Parent", Object::Reference(pages_tree_id))
                    .with("MediaBox", media_box)
                    .with("Resources", Object::Reference(resources_id))
                    .with("Contents", Object::Reference(contents_id)),
            ),
        );
        let res_obj = r.resources.flatten_into_resources_dict(&mut doc);
        doc.add_object(resources_id, res_obj);
        doc.add_object(
            contents_id,
            Object::Stream(Stream::new(Dict::new(), r.content_bytes)),
        );
        new_kids.push(Object::Reference(page_id));
        changed_ids.push(page_id.number);
        changed_ids.push(resources_id.number);
        changed_ids.push(contents_id.number);
    }

    // Rewrite the /Pages tree dict at the same id — that's what
    // makes the new revision an *update* rather than an append: any
    // reader that follows /Prev sees the new kids list, while one
    // that ignores /Prev still resolves to the previous list.
    doc.add_object(
        pages_tree_id,
        Object::Dict(
            Dict::new()
                .with("Type", Object::Name("Pages".into()))
                .with("Kids", Object::Array(new_kids))
                .with(
                    "Count",
                    Object::Integer(prev_count + additional_pages.len() as i64),
                ),
        ),
    );
    changed_ids.push(pages_tree_id.number);
    doc.root = Some(prev_root);
    doc.prev_xref_offset = Some(prev_xref_off);
    doc.min_size = Some(prev_size);
    let mut all_changed_ids = changed_ids.clone();
    all_changed_ids.sort_unstable();
    all_changed_ids.dedup();
    doc.xref_only_ids = Some(all_changed_ids);

    // Append to the previous bytes verbatim.
    let mut out = prev_pdf.to_vec();
    // Ensure the previous bytes ended on a line break — some viewers
    // treat trailing-NL as required between revisions.
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    doc.write_to(&mut out)?;
    Ok(out)
}

/// Render a [`Scene`] in pages mode as a multi-page PDF document with
/// the standard security handler applied. Identical to
/// [`write_pdf_from_scene`] except every string + stream payload is
/// encrypted under the supplied [`EncryptionConfig`] before the body
/// is serialised, and the trailer carries `/Encrypt <ref>` + the
/// matching `/ID` array.
///
/// Round-6 supports R=2 / R=3 / R=4 / R=5 / R=6 — see
/// [`crate::encrypt`] for per-revision details. The reader's
/// [`crate::read_pdf_to_scene_with_password`] decrypts the resulting
/// bytes when given the supplied user (or owner) password.
pub fn write_pdf_from_scene_encrypted(
    scene: &Scene,
    config: &EncryptionConfig,
) -> Result<Vec<u8>, PdfError> {
    let pages = scene
        .pages
        .as_ref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            PdfError::other(
                "write_pdf_from_scene_encrypted: scene is not in pages mode (scene.pages is None or empty)",
            )
        })?;

    struct Rendered<'a> {
        frame: &'a VectorFrame,
        width: f32,
        height: f32,
        content_bytes: Vec<u8>,
        resources: ResourceCollector,
    }
    let rendered: Vec<Rendered<'_>> = pages
        .iter()
        .map(|page| {
            let (content_bytes, resources) = render_frame(&page.content);
            Rendered {
                frame: &page.content,
                width: page.width,
                height: page.height,
                content_bytes,
                resources,
            }
        })
        .collect();

    let inputs: Vec<PageInput<'_>> = rendered
        .into_iter()
        .map(|r| PageInput {
            width: r.width,
            height: r.height,
            content_bytes: r.content_bytes,
            resources: r.resources,
            frame: r.frame,
        })
        .collect();

    let mut doc = Document::new();
    let _ = build_pages(&mut doc, inputs);
    if has_metadata(&scene.metadata) {
        let info_id = doc.add(Object::Dict(build_info_dict(&scene.metadata)));
        doc.info = Some(info_id);
    }
    doc.encryption = Some(EncryptionState::build(config)?);

    let mut out = Vec::with_capacity(4096);
    doc.write_to(&mut out)?;
    Ok(out)
}

/// Walk a single [`VectorFrame`] into a content stream + the per-page
/// [`ResourceCollector`]. Shared by [`write_pdf`] and
/// [`write_pdf_from_scene`].
fn render_frame(frame: &VectorFrame) -> (Vec<u8>, ResourceCollector) {
    let mut op = OpBuf::new();
    let mut resources = ResourceCollector::new();
    emit_group(&mut op, &frame.root, &mut resources);
    (op.into_bytes(), resources)
}

fn emit_group(op: &mut OpBuf, group: &Group, resources: &mut ResourceCollector) {
    save(op);

    if !group.transform.is_identity() {
        concat_matrix(op, &group.transform);
    }

    // Group opacity becomes an ExtGState dict carrying both the
    // fill alpha (`/ca`) and the stroke alpha (`/CA`) — PDF treats
    // them as independent state and a single SVG `opacity` should
    // affect both. Skip when fully opaque (the default) so the
    // common case stays clean.
    if (group.opacity - 1.0).abs() > 1e-6 {
        let name = resources.add_opacity(group.opacity);
        set_ext_gstate(op, &name);
    }

    // Clip path — PDF makes the just-constructed path the current
    // clip via `W` (or `W*`) followed by `n` (paint-as-no-op). The
    // clip stays in effect until the matching `Q` pops the
    // graphics state, which we emit after the children.
    if let Some(clip) = &group.clip {
        emit_path(op, clip);
        // The fill rule for clips on `Group` isn't carried by the
        // IR — mirror the SVG convention (non-zero by default).
        emit_clip_marker(op, FillRule::NonZero);
    }

    for child in &group.children {
        emit_node(op, child, resources);
    }

    restore(op);
}

fn emit_node(op: &mut OpBuf, node: &Node, resources: &mut ResourceCollector) {
    match node {
        Node::Group(g) => emit_group(op, g, resources),
        Node::Path(p) => emit_path_node(op, p, resources),
        Node::Image(img) => emit_image(op, img, resources),
        // Node is `#[non_exhaustive]` (text / mask / filter variants
        // will land in future rounds). Round 1 silently skips
        // unknown node kinds so the writer stays forward-compatible.
        _ => {}
    }
}

fn emit_path_node(op: &mut OpBuf, node: &PathNode, resources: &mut ResourceCollector) {
    if node.path.commands.is_empty() {
        return;
    }
    if node.fill.is_none() && node.stroke.is_none() {
        // Nothing to do — drawing a path without a fill or stroke
        // would still consume the path slot, and emitting `n`
        // (no-op paint) is harmless but pointless.
        return;
    }

    // q ... Q so per-path paint state doesn't leak.
    save(op);

    if let Some(stroke) = &node.stroke {
        // `set_stroke_style` also sets the stroke colour (or
        // pattern), so it must come before any fill setter to keep
        // the side-effects on `Resources` correctly ordered.
        set_stroke_style(op, stroke, resources);
    }
    if let Some(fill) = &node.fill {
        set_fill_paint(op, fill, resources);
    }

    emit_path(op, &node.path);

    let mode = match (node.fill.is_some(), node.stroke.is_some()) {
        (true, true) => PaintMode::FillStroke,
        (true, false) => PaintMode::Fill,
        (false, true) => PaintMode::Stroke,
        (false, false) => PaintMode::None,
    };
    paint(op, mode, node.fill_rule);

    restore(op);
}

fn emit_image(op: &mut OpBuf, image: &ImageRef, resources: &mut ResourceCollector) {
    // VideoFrame carries no width / height / pixel-format on its own;
    // the bounds rectangle on the ImageRef is the only source of
    // truth for the painted size. The frame's plane data is assumed
    // to be straight RGBA8 — the contract of round 1.
    let width = image.bounds.width.round() as u32;
    let height = image.bounds.height.round() as u32;
    let Some(name) = resources.add_rgba_image(&image.frame, width, height) else {
        return;
    };

    // PDF Do paints an image XObject in unit space (the image fills
    // the [0,1] x [0,1] square after the CTM), so we install a CTM
    // that scales it to bounds.width × bounds.height and translates
    // it to bounds.x / bounds.y. Image coordinates are inherently
    // y-up in PDF, but the image data row 0 is conventionally the
    // top — flipping with a y-scale of -1 matches the SVG / vector
    // convention.
    save(op);

    if !image.transform.is_identity() {
        concat_matrix(op, &image.transform);
    }

    let bx = image.bounds.x;
    let by = image.bounds.y;
    let bw = image.bounds.width;
    let bh = image.bounds.height;
    // CTM = T(bx, by + bh) * S(bw, -bh) — flip vertically so row 0
    // appears at the top of the painted area.
    let ctm = oxideav_core::vector::Transform2D {
        a: bw,
        b: 0.0,
        c: 0.0,
        d: -bh,
        e: bx,
        f: by + bh,
    };
    concat_matrix(op, &ctm);

    // The actual paint operator: `/Im<n> Do`.
    let mut bytes = Vec::with_capacity(name.len() + 5);
    bytes.push(b'/');
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(b" Do\n");
    op.append_raw(&bytes);

    restore(op);
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxideav_core::time::TimeBase;
    use oxideav_core::vector::{Group, Paint, Path, PathCommand, Point, Rgba};

    fn rect_frame(width: f32, height: f32, color: Rgba) -> VectorFrame {
        let mut p = Path::new();
        p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
        p.commands
            .push(PathCommand::LineTo(Point::new(width - 10.0, 10.0)));
        p.commands
            .push(PathCommand::LineTo(Point::new(width - 10.0, height - 10.0)));
        p.commands
            .push(PathCommand::LineTo(Point::new(10.0, height - 10.0)));
        p.commands.push(PathCommand::Close);

        VectorFrame {
            width,
            height,
            view_box: None,
            root: Group {
                children: vec![Node::Path(PathNode {
                    path: p,
                    fill: Some(Paint::Solid(color)),
                    stroke: None,
                    fill_rule: FillRule::NonZero,
                })],
                ..Group::default()
            },
            pts: None,
            time_base: TimeBase::new(1, 1),
        }
    }

    #[test]
    fn write_pdf_starts_with_header_and_ends_with_eof() {
        let frame = rect_frame(200.0, 100.0, Rgba::opaque(255, 128, 0));
        let bytes = write_pdf(&frame).unwrap();
        assert!(bytes.starts_with(b"%PDF-1.4\n"));
        assert!(bytes.ends_with(b"%%EOF\n"));
    }

    #[test]
    fn write_pdf_emits_basic_path_operators() {
        let frame = rect_frame(200.0, 100.0, Rgba::opaque(0, 0, 0));
        let bytes = write_pdf(&frame).unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains(" m\n"));
        assert!(s.contains(" l\n"));
        assert!(s.contains("h\n"));
        assert!(s.contains("f\n"));
    }

    #[test]
    fn empty_root_still_produces_valid_skeleton() {
        let frame = VectorFrame {
            width: 10.0,
            height: 10.0,
            view_box: None,
            root: Group::default(),
            pts: None,
            time_base: TimeBase::new(1, 1),
        };
        let bytes = write_pdf(&frame).unwrap();
        assert!(bytes.starts_with(b"%PDF-1.4\n"));
        assert!(bytes.ends_with(b"%%EOF\n"));
    }
}
