//! Page object construction.
//!
//! The Page object glues together: media box (from the
//! [`oxideav_core::vector::VectorFrame`] dimensions), `/Resources` (built
//! by the [`crate::resources::ResourceCollector`]), and `/Contents` (the
//! content stream — the byte string of operators emitted by
//! [`crate::operators`]).
//!
//! Single-page round 1: one `Page`, attached to a single-element `Pages`
//! tree, attached to a `Catalog`.

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
    let media_box = Object::Array(vec![
        Object::Real(0.0),
        Object::Real(0.0),
        Object::Real(frame.width as f64),
        Object::Real(frame.height as f64),
    ]);

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

#[cfg(test)]
mod tests {
    use super::*;
    use oxideav_core::time::TimeBase;
    use oxideav_core::vector::Group;

    #[test]
    fn build_page_assembles_catalog_pages_page_resources_contents() {
        let frame = VectorFrame {
            width: 100.0,
            height: 50.0,
            view_box: None,
            root: Group::default(),
            pts: None,
            time_base: TimeBase::new(1, 1),
        };
        let mut doc = Document::new();
        let res = ResourceCollector::new();
        let pb = build_page(&mut doc, &frame, b"% empty\n".to_vec(), &res);
        assert_eq!(pb.catalog_id.number, 1);
        assert_eq!(pb.pages_tree_id.number, 2);
        assert_eq!(pb.page_id.number, 3);
        // 5 objects: catalog, pages, page, resources, contents.
        assert_eq!(doc.object_count(), 5);
    }
}
