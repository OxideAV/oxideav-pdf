//! Page object construction.
//!
//! The Page object glues together: media box (from the page's
//! [`oxideav_core::vector::VectorFrame`] dimensions), `/Resources`
//! (built by the [`crate::resources::ResourceCollector`]), and
//! `/Contents` (the content stream — the byte string of operators
//! emitted by [`crate::operators`]).
//!
//! Round 1 shipped a single-page builder ([`build_page`]); round 2 adds
//! the multi-page entry point ([`build_pages`]) used by
//! [`crate::writer::write_pdf_from_scene`].

use oxideav_core::vector::VectorFrame;

use crate::objects::{Dict, Document, Object, ObjectId, Stream};
use crate::resources::ResourceCollector;

/// Result of [`build_page`]. Carries the ids the caller needs to
/// finish wiring the catalog.
pub struct PageBuild {
    pub page_id: ObjectId,
    pub pages_tree_id: ObjectId,
    pub catalog_id: ObjectId,
}

/// Result of [`build_pages`] — the catalog id, the pages-tree id, and
/// the per-page object ids in input order.
pub struct PagesBuild {
    pub catalog_id: ObjectId,
    pub pages_tree_id: ObjectId,
    pub page_ids: Vec<ObjectId>,
}

/// One page worth of pre-emitted state — the raw content stream bytes,
/// the [`ResourceCollector`] that backs the per-page `/Resources` dict,
/// and the page geometry the `/MediaBox` is derived from. The writer
/// builds one of these per [`oxideav_scene::Page`] before handing them
/// to [`build_pages`].
pub struct PageInput<'a> {
    pub width: f32,
    pub height: f32,
    pub content_bytes: Vec<u8>,
    pub resources: ResourceCollector,
    /// The frame the content was emitted from — only its `width` and
    /// `height` matter to the page builder, but accepting the whole
    /// frame keeps the boundary noise-free for callers that already
    /// have one in hand.
    pub frame: &'a VectorFrame,
}

/// Stitch a single-page PDF document together.
///
/// `frame` provides the media box dimensions; `content_bytes` is the
/// already-emitted content stream (one big text-encoded byte string of
/// PDF operators); `resources` carries everything the content stream
/// references via name (`/GSx`, `/Patx`, `/Imx`).
///
/// Adds 4 indirect objects to `doc`: Catalog, Pages tree, Page,
/// Resources dict. (Plus per-resource sub-objects already added by
/// [`ResourceCollector::flatten_into_resources_dict`].)
pub fn build_page(
    doc: &mut Document,
    frame: &VectorFrame,
    content_bytes: Vec<u8>,
    resources: &ResourceCollector,
) -> PageBuild {
    // Allocate ids up front so cross-references resolve.
    let catalog_id = doc.allocate_id();
    let pages_id = doc.allocate_id();
    let page_id = doc.allocate_id();
    let resources_id = doc.allocate_id();
    let contents_id = doc.allocate_id();

    // Media box — PDF 1.4 puts the origin at the bottom-left and the
    // y-axis pointing up. The vector IR uses SVG conventions
    // (origin top-left, y down). We don't flip in the writer because
    // doing so silently changes hand-authored vector content; the
    // caller can wrap a `Group` with a `Transform2D::scale(1, -1)` +
    // `Transform2D::translate(0, height)` if they want the visible
    // PDF orientation. The MediaBox itself is just `[0 0 W H]` —
    // anything outside is clipped at render time.
    let media_box = media_box_array(frame.width, frame.height);

    // Catalog ----------------------------------------------------
    doc.add_object(
        catalog_id,
        Object::Dict(
            Dict::new()
                .with("Type", Object::Name("Catalog".into()))
                .with("Pages", Object::Reference(pages_id)),
        ),
    );

    // Pages tree -------------------------------------------------
    doc.add_object(
        pages_id,
        Object::Dict(
            Dict::new()
                .with("Type", Object::Name("Pages".into()))
                .with("Kids", Object::Array(vec![Object::Reference(page_id)]))
                .with("Count", Object::Integer(1)),
        ),
    );

    // Page -------------------------------------------------------
    doc.add_object(
        page_id,
        Object::Dict(
            Dict::new()
                .with("Type", Object::Name("Page".into()))
                .with("Parent", Object::Reference(pages_id))
                .with("MediaBox", media_box)
                .with("Resources", Object::Reference(resources_id))
                .with("Contents", Object::Reference(contents_id)),
        ),
    );

    // Resources --------------------------------------------------
    let res_obj = resources.flatten_into_resources_dict(doc);
    doc.add_object(resources_id, res_obj);

    // Contents stream --------------------------------------------
    let mut content_dict = Dict::new();
    // Round 1 uses uncompressed content streams — they tend to be
    // small for vector content (a few hundred bytes per shape) and
    // staying uncompressed makes `qpdf --check` / `pdftotext` debug
    // round-trips trivial. Round 2 should switch to FlateDecode
    // when the stream exceeds some threshold (~1 KB).
    let _ = &mut content_dict; // explicit to keep the intent visible
    doc.add_object(
        contents_id,
        Object::Stream(Stream::new(content_dict, content_bytes)),
    );

    doc.root = Some(catalog_id);

    PageBuild {
        page_id,
        pages_tree_id: pages_id,
        catalog_id,
    }
}

/// Multi-page document builder. Walks `inputs` in order, emitting one
/// PDF Page object per entry, all hung off a single `/Pages` tree
/// rooted by a single `/Catalog`.
///
/// Each page carries its own `/MediaBox` (per-page width/height),
/// `/Resources` (independent — gradients / images / opacity dicts
/// from one page do not leak into another's resource table), and
/// `/Contents`. Page label / orientation are not yet round-tripped —
/// see [`crate::writer::write_pdf_from_scene`] for the round-2
/// deferrals.
pub fn build_pages(doc: &mut Document, inputs: Vec<PageInput<'_>>) -> PagesBuild {
    // Even an empty `inputs` list still needs a catalog + a pages tree
    // (PDF readers refuse a trailer without a /Root → /Pages chain).
    // The caller is responsible for passing at least one page in
    // practice; we guard the empty case so the unit test for
    // `build_pages(empty)` doesn't panic.
    let catalog_id = doc.allocate_id();
    let pages_id = doc.allocate_id();

    // Allocate page ids up front so the /Pages tree can list its kids
    // before any per-page object is built.
    let page_ids: Vec<ObjectId> = (0..inputs.len()).map(|_| doc.allocate_id()).collect();

    // Catalog ----------------------------------------------------
    doc.add_object(
        catalog_id,
        Object::Dict(
            Dict::new()
                .with("Type", Object::Name("Catalog".into()))
                .with("Pages", Object::Reference(pages_id)),
        ),
    );

    // Pages tree -------------------------------------------------
    let kids = page_ids.iter().map(|id| Object::Reference(*id)).collect();
    doc.add_object(
        pages_id,
        Object::Dict(
            Dict::new()
                .with("Type", Object::Name("Pages".into()))
                .with("Kids", Object::Array(kids))
                .with("Count", Object::Integer(page_ids.len() as i64)),
        ),
    );

    // Per-page Page + Resources + Contents -----------------------
    for (page_id, input) in page_ids.iter().zip(inputs.into_iter()) {
        let resources_id = doc.allocate_id();
        let contents_id = doc.allocate_id();

        let media_box = media_box_array(input.width, input.height);

        doc.add_object(
            *page_id,
            Object::Dict(
                Dict::new()
                    .with("Type", Object::Name("Page".into()))
                    .with("Parent", Object::Reference(pages_id))
                    .with("MediaBox", media_box)
                    .with("Resources", Object::Reference(resources_id))
                    .with("Contents", Object::Reference(contents_id)),
            ),
        );

        let res_obj = input.resources.flatten_into_resources_dict(doc);
        doc.add_object(resources_id, res_obj);

        // Round 1's content stream is uncompressed — same policy here
        // for the same reasons (qpdf-debuggable, small for vector).
        doc.add_object(
            contents_id,
            Object::Stream(Stream::new(Dict::new(), input.content_bytes)),
        );
    }

    doc.root = Some(catalog_id);

    PagesBuild {
        catalog_id,
        pages_tree_id: pages_id,
        page_ids,
    }
}

fn media_box_array(width: f32, height: f32) -> Object {
    Object::Array(vec![
        Object::Real(0.0),
        Object::Real(0.0),
        Object::Real(width as f64),
        Object::Real(height as f64),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxideav_core::time::TimeBase;
    use oxideav_core::vector::Group;

    fn empty_frame(w: f32, h: f32) -> VectorFrame {
        VectorFrame {
            width: w,
            height: h,
            view_box: None,
            root: Group::default(),
            pts: None,
            time_base: TimeBase::new(1, 1),
        }
    }

    #[test]
    fn build_page_assembles_catalog_pages_page_resources_contents() {
        let frame = empty_frame(100.0, 50.0);
        let mut doc = Document::new();
        let res = ResourceCollector::new();
        let pb = build_page(&mut doc, &frame, b"% empty\n".to_vec(), &res);
        assert_eq!(pb.catalog_id.number, 1);
        assert_eq!(pb.pages_tree_id.number, 2);
        assert_eq!(pb.page_id.number, 3);
        // 5 objects: catalog, pages, page, resources, contents.
        assert_eq!(doc.object_count(), 5);
    }

    #[test]
    fn build_pages_emits_one_page_per_input() {
        let f1 = empty_frame(200.0, 100.0);
        let f2 = empty_frame(300.0, 400.0);
        let inputs = vec![
            PageInput {
                width: f1.width,
                height: f1.height,
                content_bytes: b"% page 1\n".to_vec(),
                resources: ResourceCollector::new(),
                frame: &f1,
            },
            PageInput {
                width: f2.width,
                height: f2.height,
                content_bytes: b"% page 2\n".to_vec(),
                resources: ResourceCollector::new(),
                frame: &f2,
            },
        ];
        let mut doc = Document::new();
        let pb = build_pages(&mut doc, inputs);
        assert_eq!(pb.page_ids.len(), 2);
        // catalog + pages + 2 * (page + resources + contents) = 8.
        assert_eq!(doc.object_count(), 8);

        // Serialise + grep for both /MediaBox values to confirm
        // per-page geometry actually lands on the correct page.
        let mut bytes = Vec::new();
        doc.write_to(&mut bytes).unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("/MediaBox [0 0 200 100]"));
        assert!(s.contains("/MediaBox [0 0 300 400]"));
        assert!(s.contains("/Count 2"));
    }
}
