//! Round-25: PDF outline (bookmark) tree + Link annotation specs.
//!
//! Writer-side scaffolding for ISO 32000-1 §12.3.3 (Document Outline)
//! and §12.5.6.5 (Link Annotations). The reader-side parsers live in
//! [`crate::reader::outline`] and [`crate::reader::link`]. Together
//! they round-trip the bookmark tree + the per-page link annotation
//! list a typical "PDF report with hyperlinks" carries.
//!
//! Both spec sections share a common notion: an *explicit destination*
//! is `[ page-ref /Mode … ]` per ISO 32000-1 §12.3.2.2 Table 151. The
//! [`OutlineDestination`] enum below covers the subset that doesn't
//! depend on viewer-side magnification preferences (so `/XYZ`, `/Fit`,
//! `/FitH`, `/FitR`) — the most common in practice and the ones a
//! reader-side round-trip can observe directly. The remaining `/FitV`,
//! `/FitB`, `/FitBH`, `/FitBV` shapes serialise / deserialise too via
//! the same lowering machinery.
//!
//! No types from outside this crate are needed — the writer functions
//! accept page indices (0-based, matching the order of
//! [`oxideav_scene::Scene::pages`]) and resolve them to the writer's
//! per-page object ids internally.

/// One node in the writer-side outline (bookmark) tree.
///
/// Mirrors ISO 32000-1 Table 153 (Outline item dictionary) — but only
/// the entries the writer needs at construction time:
///
/// * `title` — the user-visible text (`/Title`).
/// * `destination` — what the conforming reader navigates to when the
///   bookmark is activated (`/Dest`).
/// * `children` — nested outline items, recursively. The writer is
///   responsible for materialising the spec's doubly-linked
///   `/First` / `/Last` / `/Next` / `/Prev` shape from this tree.
/// * `open` — the spec's "open / closed" sign on `/Count`. When
///   `true`, descendants are visible at document open; when `false`,
///   they're hidden behind the disclosure triangle. Defaults to
///   `false` so trees stay compact in the conforming reader's UI.
///
/// The optional appearance entries `/C` (text colour) and `/F` (style
/// flags — bold / italic) are deferred to a follow-up round.
#[derive(Clone, Debug)]
pub struct OutlineSpec {
    pub title: String,
    pub destination: OutlineDestination,
    pub children: Vec<OutlineSpec>,
    pub open: bool,
}

impl OutlineSpec {
    /// Convenience constructor — a leaf bookmark with the default
    /// (`Fit`-page) destination on the requested 0-based page index.
    pub fn page(title: impl Into<String>, page_index: usize) -> Self {
        Self {
            title: title.into(),
            destination: OutlineDestination::Fit { page_index },
            children: Vec::new(),
            open: false,
        }
    }

    /// Builder-style child-attach. Returns `self` for chaining.
    pub fn with_child(mut self, child: OutlineSpec) -> Self {
        self.children.push(child);
        self
    }
}

/// One PDF *explicit destination* (ISO 32000-1 §12.3.2.2 Table 151).
///
/// Every variant carries the 0-based page index in the
/// [`oxideav_scene::Scene::pages`] vector — the writer rewrites it to
/// the matching `<n> 0 R` page reference at emission time.
///
/// The four `Fit*` magnification variants whose syntax doesn't depend
/// on geometry (`Fit`, `FitB`) are unparameterised; the four that do
/// take their geometry parameters in default user-space units (no
/// transform pre-applied) per the spec.
#[derive(Clone, Debug, PartialEq)]
pub enum OutlineDestination {
    /// `[ page /XYZ left top zoom ]` — top-left corner at `(left,
    /// top)`, page magnified by `zoom`. `None` means "retain current
    /// viewer setting" per Table 151. A zoom of `Some(0.0)` is
    /// equivalent to `None` per the spec.
    Xyz {
        page_index: usize,
        left: Option<f32>,
        top: Option<f32>,
        zoom: Option<f32>,
    },
    /// `[ page /Fit ]` — entire page in window.
    Fit { page_index: usize },
    /// `[ page /FitH top ]` — fit page width, vertical at `top`.
    FitH { page_index: usize, top: Option<f32> },
    /// `[ page /FitV left ]` — fit page height, horizontal at `left`.
    FitV {
        page_index: usize,
        left: Option<f32>,
    },
    /// `[ page /FitR left bottom right top ]` — fit a specific rect.
    FitR {
        page_index: usize,
        left: f32,
        bottom: f32,
        right: f32,
        top: f32,
    },
    /// `[ page /FitB ]` — fit page bounding box (PDF 1.1).
    FitB { page_index: usize },
    /// `[ page /FitBH top ]` — fit page bbox width, vertical at `top`.
    FitBH { page_index: usize, top: Option<f32> },
    /// `[ page /FitBV left ]` — fit page bbox height, horizontal at
    /// `left`.
    FitBV {
        page_index: usize,
        left: Option<f32>,
    },
}

impl OutlineDestination {
    /// The 0-based page index this destination refers to.
    pub fn page_index(&self) -> usize {
        match *self {
            Self::Xyz { page_index, .. }
            | Self::Fit { page_index }
            | Self::FitH { page_index, .. }
            | Self::FitV { page_index, .. }
            | Self::FitR { page_index, .. }
            | Self::FitB { page_index }
            | Self::FitBH { page_index, .. }
            | Self::FitBV { page_index, .. } => page_index,
        }
    }
}

/// One Link annotation spec (ISO 32000-1 §12.5.6.5 Table 173).
///
/// The annotation's clickable area is a single rectangle in default
/// user-space coordinates (no `QuadPoints` support for this round —
/// `QuadPoints` lands when the next round wires text annotations).
/// The action is either an internal go-to destination (`/Dest`, by
/// far the more common form for "link to another page in the same
/// document") or an external URI (`/A << /S /URI /URI (...) >>`).
#[derive(Clone, Debug)]
pub struct LinkAnnotationSpec {
    /// 0-based index of the page this annotation lives on.
    pub source_page_index: usize,
    /// `/Rect [ llx lly urx ury ]` — clickable bounding rectangle, in
    /// default user space (no transform applied). PDF coordinates,
    /// origin bottom-left.
    pub rect: [f32; 4],
    /// Where the link goes. `Internal` lowers to `/Dest`; `Uri`
    /// lowers to `/A << /S /URI /URI (...) >>`.
    pub target: LinkTarget,
}

/// Where a [`LinkAnnotationSpec`] points.
#[derive(Clone, Debug)]
pub enum LinkTarget {
    /// In-document jump — go-to destination per §12.3.2.
    Internal(OutlineDestination),
    /// External URI per §12.6.4.7 (URI Action). Stored as a raw byte
    /// string; the writer literal-string-encodes it (so `(`/`)` /
    /// `\` escape correctly).
    Uri(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outline_page_helper_builds_fit_leaf() {
        let leaf = OutlineSpec::page("Chapter 1", 3);
        assert_eq!(leaf.title, "Chapter 1");
        assert_eq!(leaf.destination, OutlineDestination::Fit { page_index: 3 });
        assert!(leaf.children.is_empty());
        assert!(!leaf.open);
    }

    #[test]
    fn outline_with_child_chains() {
        let tree = OutlineSpec::page("Root", 0)
            .with_child(OutlineSpec::page("Sub A", 1))
            .with_child(OutlineSpec::page("Sub B", 2));
        assert_eq!(tree.children.len(), 2);
        assert_eq!(tree.children[0].title, "Sub A");
    }

    #[test]
    fn destination_page_index_threads_through_every_variant() {
        assert_eq!(OutlineDestination::Fit { page_index: 7 }.page_index(), 7);
        assert_eq!(
            OutlineDestination::Xyz {
                page_index: 4,
                left: Some(0.0),
                top: Some(800.0),
                zoom: None
            }
            .page_index(),
            4
        );
        assert_eq!(
            OutlineDestination::FitR {
                page_index: 2,
                left: 0.0,
                bottom: 0.0,
                right: 100.0,
                top: 100.0,
            }
            .page_index(),
            2
        );
    }
}
