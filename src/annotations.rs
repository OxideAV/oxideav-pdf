//! Round-32 — general annotations writer (ISO 32000-1 §12.5).
//!
//! Symmetric writer side of the round-26 generic annotation reader
//! ([`crate::reader::annotations`]). Where round 25 emitted only
//! `/Subtype /Link` and round 31 emitted `/Subtype /Widget`, round 32
//! covers the rest of the §12.5.6 subtype taxonomy that authoring tools
//! actually use in the wild:
//!
//! * **`/Text`** sticky-note (§12.5.6.4, Table 172) —
//!   [`AnnotationKind::Text`]: `/Contents`, `/Name` icon, `/Open`.
//! * **`/FreeText`** in-page text overlay (§12.5.6.6, Table 174) —
//!   [`AnnotationKind::FreeText`]: `/Contents`, `/DA` default appearance,
//!   `/Q` quadding.
//! * **`/Stamp`** rubber-stamp (§12.5.6.13, Table 184) —
//!   [`AnnotationKind::Stamp`]: `/Name` icon identifier, optional
//!   `/Contents` description.
//! * **`/Highlight`** / **`/Underline`** / **`/Squiggly`** /
//!   **`/StrikeOut`** text-markup family (§12.5.6.10, Table 179) —
//!   [`AnnotationKind::Highlight`] et al.: `/QuadPoints`.
//! * **`/Link`** (§12.5.6.5, Table 173) —
//!   [`AnnotationKind::Link`]: external URI (re-uses the same shape as
//!   round 25's [`crate::LinkAnnotationSpec`]).
//! * **`/Square`** / **`/Circle`** geometric markup (§12.5.6.8,
//!   Table 177) — [`AnnotationKind::Square`] /
//!   [`AnnotationKind::Circle`]: `/IC` interior colour, `/BS /W` line
//!   width.
//! * **`/Ink`** freehand scribble (§12.5.6.13, Table 185) —
//!   [`AnnotationKind::Ink`]: `/InkList` an array of stroke
//!   point-sequences.
//!
//! Round 227 extends the writer with three more §12.5.6 subtypes that
//! the round-197 reader already decodes, closing the symmetry for the
//! markup-line family:
//!
//! * **`/Line`** straight-line markup (§12.5.6.7, Table 175) —
//!   [`AnnotationKind::Line`]: required `/L` two-endpoint array, plus
//!   the Table 175 optional fields (`/LE` line-ending pair, `/IC`
//!   interior colour, `/LL` / `/LLE` / `/LLO` leader-line geometry,
//!   `/Cap` caption flag, `/IT` intent name).
//! * **`/Polygon`** and **`/PolyLine`** polygon / polyline markup
//!   (§12.5.6.9, Table 178) — [`AnnotationKind::Polygon`] /
//!   [`AnnotationKind::PolyLine`]: `/Vertices` flat vertex array plus
//!   the Table 178 optional fields (`/LE` line-ending pair — PolyLine
//!   only per spec, `/IC` interior colour, `/IT` intent name).
//!
//! The writer also carries every cross-subtype Table 164 field
//! ([`Annotation::author`], `/M` modified-date, `/F` flags, `/C`
//! colour, `/Border`).
//!
//! Provenance: ISO 32000-1 §12.5 (annotation framework), §12.5.2
//! (annotation dict common fields, Table 164), and the individual
//! §12.5.6.X subtype tables enumerated above. No third-party PDF
//! source consulted.

use oxideav_scene::Scene;

use crate::error::PdfError;
use crate::info::{build_info_dict, has_metadata};
use crate::objects::{Dict, Document, Object, ObjectId};
use crate::page::{build_pages, PageInput};
use crate::resources::ResourceCollector;
use crate::writer::render_frame_for_linearize as render_frame;

// ---------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------

/// One annotation to attach to a page.
///
/// Mirrors the round-26 reader's [`crate::reader::PdfAnnotation`] shape
/// — the cross-subtype Table 164 fields hang off the struct, the
/// per-subtype payload off [`Self::kind`].
#[derive(Debug, Clone)]
pub struct Annotation {
    /// 0-based page index — which page the annotation lives on.
    pub source_page_index: usize,
    /// `/Rect [llx lly urx ury]` — annotation rectangle in default
    /// user space (PDF coordinates, origin bottom-left).
    pub rect: [f32; 4],
    /// `/T` — author / title-bar string. Most viewers display this in
    /// the pop-up note's title bar. Optional per Table 164.
    pub author: Option<String>,
    /// `/M` — last-modified date string (raw PDF date form
    /// `D:YYYYMMDDHHmmSSOHH'mm'` per §7.9.4). Caller is responsible
    /// for the format — the writer passes it through verbatim.
    pub modified: Option<String>,
    /// `/F` — annotation flag word (Table 167). Common values:
    /// 0 = no flags, 4 = Print (bit 3 set). When `None`, the writer
    /// emits 4 (Print) so the annotation prints by default.
    pub flags: Option<u32>,
    /// `/C` — colour. 0/1/3/4 numbers per §12.5.2:
    /// `[]` = transparent, `[g]` = grey, `[r g b]` = RGB,
    /// `[c m y k]` = CMYK. `None` ⇒ entry omitted.
    pub colour: Option<Vec<f32>>,
    /// `/Border [hradius vradius width]` or `[hr vr w dash]`. When
    /// `None`, defaults to `[0 0 0]` (no visible border).
    pub border: Option<Vec<f32>>,
    /// Per-subtype payload.
    pub kind: AnnotationKind,
}

/// Per-subtype annotation payload — round 32 covers the five
/// most-common interactive PDF annotation families per §12.5.6
/// (Text, Link, FreeText, Highlight/Underline/Squiggly/StrikeOut,
/// Stamp) plus three additional ones (Square, Circle, Ink) that
/// show up in markup-heavy PDFs (review / proof workflows).
#[derive(Debug, Clone)]
pub enum AnnotationKind {
    /// `/Subtype /Text` — sticky-note (§12.5.6.4, Table 172).
    Text {
        /// `/Contents` — the user-visible note text.
        contents: String,
        /// `/Name` — icon identifier (`Comment`, `Note`, `Help`,
        /// `NewParagraph`, `Paragraph`, `Insert`). Defaults to `Note`
        /// per Table 172 when `None`.
        icon: Option<String>,
        /// `/Open` — true ⇒ pop-up displayed at document open.
        open: bool,
    },
    /// `/Subtype /Link` — hyperlink (§12.5.6.5, Table 173). Round 32
    /// covers only the URI form; in-document goto-destination links
    /// already have the richer [`crate::LinkAnnotationSpec`] surface
    /// from round 25.
    Link {
        /// External URI (`/A << /S /URI /URI (...) >>`).
        uri: String,
    },
    /// `/Subtype /FreeText` — in-page text overlay (§12.5.6.6, Table 174).
    FreeText {
        /// `/Contents` — the rendered text.
        contents: String,
        /// `/DA` default appearance string (a content-stream snippet
        /// per §12.7.3.3 — `/Helv 12 Tf 0 g`-style). `None` ⇒ writer
        /// supplies `(/Helv 12 Tf 0 g)`.
        default_appearance: Option<String>,
        /// `/Q` quadding: 0 left, 1 centre, 2 right.
        quadding: FreeTextQuadding,
    },
    /// `/Subtype /Highlight` (§12.5.6.10, Table 179).
    Highlight {
        /// `/QuadPoints` — 8N reals per Table 179. Each 8-tuple gives
        /// the four corners of one highlighted region.
        quad_points: Vec<[f32; 8]>,
    },
    /// `/Subtype /Underline` (§12.5.6.10, Table 179).
    Underline { quad_points: Vec<[f32; 8]> },
    /// `/Subtype /Squiggly` (§12.5.6.10, Table 179).
    Squiggly { quad_points: Vec<[f32; 8]> },
    /// `/Subtype /StrikeOut` (§12.5.6.10, Table 179).
    StrikeOut { quad_points: Vec<[f32; 8]> },
    /// `/Subtype /Stamp` — rubber-stamp (§12.5.6.13, Table 184).
    Stamp {
        /// `/Name` — icon identifier. Standard set per Table 184:
        /// `Approved`, `Experimental`, `NotApproved`, `AsIs`,
        /// `Expired`, `NotForPublicRelease`, `Confidential`, `Final`,
        /// `Sold`, `Departmental`, `ForComment`, `TopSecret`, `Draft`,
        /// `ForPublicRelease`. Defaults to `Draft` per Table 184 when
        /// `None`.
        icon: Option<String>,
        /// `/Contents` — optional description text.
        contents: Option<String>,
    },
    /// `/Subtype /Square` — rectangle markup (§12.5.6.8, Table 177).
    Square {
        /// `/IC` interior colour. `None` ⇒ outline-only.
        interior_colour: Option<Vec<f32>>,
        /// `/BS /W` — border-style line width. `None` ⇒ omitted
        /// (viewer-default).
        line_width: Option<f32>,
    },
    /// `/Subtype /Circle` — ellipse markup (§12.5.6.8, Table 177).
    Circle {
        /// `/IC` interior colour. `None` ⇒ outline-only.
        interior_colour: Option<Vec<f32>>,
        /// `/BS /W` — border-style line width. `None` ⇒ omitted.
        line_width: Option<f32>,
    },
    /// `/Subtype /Ink` — freehand scribble (§12.5.6.13, Table 185).
    Ink {
        /// `/InkList` — each inner vec is a single stroke as a flat
        /// list of `[x0, y0, x1, y1, …]` reals.
        strokes: Vec<Vec<f32>>,
    },
    /// `/Subtype /Line` — straight-line markup (§12.5.6.7, Table 175,
    /// round 227). Two-endpoint line on the page; the outer
    /// [`Annotation::rect`] is the bounding box, the `/L` four-real
    /// array carries the line itself.
    Line {
        /// `/L [x1 y1 x2 y2]` — line endpoints in default user space.
        /// Required per Table 175.
        endpoints: [f32; 4],
        /// `/LE [name1 name2]` — two-element line-ending styles
        /// (Table 176 enumerates `None`, `Square`, `Circle`, `Diamond`,
        /// `OpenArrow`, `ClosedArrow`, `Butt`, `ROpenArrow`,
        /// `RClosedArrow`, `Slash`). Defaults to `[/None /None]` per
        /// Table 175 when `None` (the writer omits the entry, matching
        /// the round-197 reader's "absent → default" contract).
        line_endings: Option<[String; 2]>,
        /// `/IC` interior colour for filled line-ending shapes. Same
        /// 0/1/3/4-component layout as outer `/C`. `None` ⇒ entry
        /// omitted.
        interior_colour: Option<Vec<f32>>,
        /// `/LL` leader-line length, in default user-space units.
        /// `None` ⇒ entry omitted (Table 175 default 0).
        leader_line: Option<f32>,
        /// `/LLE` leader-line extension length (≥ 0). `None` ⇒ entry
        /// omitted (Table 175 default 0).
        leader_line_extension: Option<f32>,
        /// `/LLO` leader-line offset (PDF 1.7, ≥ 0). `None` ⇒ entry
        /// omitted.
        leader_line_offset: Option<f32>,
        /// `/Cap` — emits `/Cap true` when set. Table 175 default
        /// `false` ⇒ writer omits the entry on `false` so a
        /// round-trip through the round-197 reader yields the same
        /// "absent → false" shape.
        cap: bool,
        /// `/IT` intent (`LineArrow` / `LineDimension`). `None` ⇒
        /// entry omitted.
        intent: Option<String>,
    },
    /// `/Subtype /Polygon` — closed polygon markup (§12.5.6.9,
    /// Table 178, round 227). Carries the `/Vertices` flat vertex
    /// array plus the Table 178 optional fields.
    Polygon {
        /// `/Vertices [x1 y1 x2 y2 …]` — alternating coordinates in
        /// default user space. Required per Table 178.
        vertices: Vec<f32>,
        /// `/IC` interior colour. Same layout as the outer `/C`. The
        /// spec lists `/LE` for both Polygon and PolyLine but Table 178
        /// notes it "Default value: [/None /None]"; the writer omits
        /// it on Polygon to match the more-conformant
        /// `/PolyLine`-only practice — callers that need a Polygon
        /// with explicit line endings should use [`Self::PolyLine`]
        /// instead.
        interior_colour: Option<Vec<f32>>,
        /// `/IT` intent (`PolygonCloud`, `PolygonDimension`). `None`
        /// ⇒ entry omitted.
        intent: Option<String>,
    },
    /// `/Subtype /PolyLine` — open polyline markup (§12.5.6.9,
    /// Table 178, round 227). Carries the `/Vertices` flat vertex
    /// array plus the Table 178 optional fields (`/LE`, `/IC`, `/IT`).
    PolyLine {
        /// `/Vertices [x1 y1 x2 y2 …]` — alternating coordinates in
        /// default user space. Required per Table 178.
        vertices: Vec<f32>,
        /// `/LE [name1 name2]` — start/end line endings. Same name
        /// taxonomy as [`Self::Line`]. `None` ⇒ entry omitted (spec
        /// default `[/None /None]`).
        line_endings: Option<[String; 2]>,
        /// `/IC` interior colour. Same layout as the outer `/C`.
        /// `None` ⇒ entry omitted.
        interior_colour: Option<Vec<f32>>,
        /// `/IT` intent (`PolyLineDimension`). `None` ⇒ entry
        /// omitted.
        intent: Option<String>,
    },
}

/// `/Q` quadding (justification) for [`AnnotationKind::FreeText`].
/// Matches §12.5.6.6 Table 174 numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FreeTextQuadding {
    /// 0 — left-justified (default).
    #[default]
    Left,
    /// 1 — centred.
    Center,
    /// 2 — right-justified.
    Right,
}

impl FreeTextQuadding {
    fn as_int(self) -> i64 {
        match self {
            Self::Left => 0,
            Self::Center => 1,
            Self::Right => 2,
        }
    }
}

/// Default appearance string (`/DA`) when an annotation doesn't carry
/// its own — Helvetica 12pt black per §12.7.3.3.
const DEFAULT_FREETEXT_DA: &str = "/Helv 12 Tf 0 g";

/// Render a [`Scene`] in pages mode + a slice of [`Annotation`]s and
/// return the serialised PDF bytes.
///
/// Constraints:
///
/// * `scene` must be in pages mode (same contract as
///   [`crate::write_pdf_from_scene`]).
/// * Each annotation's `source_page_index` must be `< scene.pages.len()`.
///
/// Wire-level shape: every annotation becomes one indirect dict carrying
/// `/Type /Annot /Subtype /X /Rect …` per §12.5.2 Table 164 + the
/// matching subtype's §12.5.6.X table. Each page's `/Annots` is the
/// array of references to its annotations.
pub fn write_pdf_with_annotations(
    scene: &Scene,
    annotations: &[Annotation],
) -> Result<Vec<u8>, PdfError> {
    let pages = scene
        .pages
        .as_ref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            PdfError::other(
                "write_pdf_with_annotations: scene is not in pages mode (scene.pages is None or empty)",
            )
        })?;
    let n_pages = pages.len();

    validate_annotations(annotations, n_pages)?;

    struct Rendered<'a> {
        frame: &'a oxideav_core::vector::VectorFrame,
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
    let pages_build = build_pages(&mut doc, inputs);

    if has_metadata(&scene.metadata) {
        let info_id = doc.add(Object::Dict(build_info_dict(&scene.metadata)));
        doc.info = Some(info_id);
    }

    // ---- Emit each annotation as an indirect object, bucketed by
    // ---- source page.
    let mut by_page: Vec<Vec<ObjectId>> = (0..n_pages).map(|_| Vec::new()).collect();
    for annot in annotations {
        let dict = build_annotation_dict(annot, pages_build.page_ids[annot.source_page_index])?;
        let id = doc.add(Object::Dict(dict));
        by_page[annot.source_page_index].push(id);
    }

    // ---- Patch each page's /Annots array.
    for (page_idx, annot_ids) in by_page.iter().enumerate() {
        if annot_ids.is_empty() {
            continue;
        }
        let page_id = pages_build.page_ids[page_idx];
        let page_obj = doc.object_mut(page_id).ok_or_else(|| {
            PdfError::other("write_pdf_with_annotations: page id missing after build_pages")
        })?;
        if let Object::Dict(d) = page_obj {
            d.set(
                "Annots",
                Object::Array(annot_ids.iter().map(|i| Object::Reference(*i)).collect()),
            );
        } else {
            return Err(PdfError::other(
                "write_pdf_with_annotations: page object is not a Dict",
            ));
        }
    }

    let mut out = Vec::with_capacity(4096);
    doc.write_to(&mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------

fn validate_annotations(annotations: &[Annotation], n_pages: usize) -> Result<(), PdfError> {
    for (i, a) in annotations.iter().enumerate() {
        if a.source_page_index >= n_pages {
            return Err(PdfError::other(format!(
                "write_pdf_with_annotations: annotation #{i} source_page_index {} \
                 out of range (scene has {n_pages} page(s))",
                a.source_page_index,
            )));
        }
        match &a.kind {
            AnnotationKind::Ink { strokes } => {
                if strokes.is_empty() {
                    return Err(PdfError::other(format!(
                        "write_pdf_with_annotations: annotation #{i} /Ink has no strokes",
                    )));
                }
                for (j, s) in strokes.iter().enumerate() {
                    if s.len() < 2 || s.len() % 2 != 0 {
                        return Err(PdfError::other(format!(
                            "write_pdf_with_annotations: annotation #{i} /Ink stroke #{j} \
                             needs an even number of coords ≥ 2 (got {})",
                            s.len()
                        )));
                    }
                }
            }
            AnnotationKind::Highlight { quad_points }
            | AnnotationKind::Underline { quad_points }
            | AnnotationKind::Squiggly { quad_points }
            | AnnotationKind::StrikeOut { quad_points }
                if quad_points.is_empty() =>
            {
                return Err(PdfError::other(format!(
                    "write_pdf_with_annotations: annotation #{i} text-markup \
                     /QuadPoints array is empty",
                )));
            }
            // §12.5.6.9 Table 178: /Vertices is a flat (x, y) list,
            // so length must be even and ≥ 4 (two vertices for a
            // degenerate single-edge polyline; closed polygons need
            // at least three vertices ≥ 6 coords but that's a
            // higher-level check — Adobe's own polygon flattener
            // emits two-vertex degenerate cases for collapsed
            // markup edits).
            AnnotationKind::Polygon { vertices, .. }
            | AnnotationKind::PolyLine { vertices, .. }
                if vertices.len() < 4 || vertices.len() % 2 != 0 =>
            {
                return Err(PdfError::other(format!(
                    "write_pdf_with_annotations: annotation #{i} polygon/polyline \
                     /Vertices needs an even number of coords ≥ 4 (got {})",
                    vertices.len()
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

fn rect_array(rect: [f32; 4]) -> Object {
    Object::Array(rect.iter().map(|v| Object::Real(*v as f64)).collect())
}

fn colour_array(values: &[f32]) -> Object {
    Object::Array(values.iter().map(|v| Object::Real(*v as f64)).collect())
}

fn border_array(values: &[f32]) -> Object {
    Object::Array(values.iter().map(|v| Object::Real(*v as f64)).collect())
}

/// PDF "text string" form per §7.9.2.2.1 — ASCII passes through as a
/// literal string; non-ASCII becomes UTF-16BE-with-BOM in a hex
/// string. Identical to [`crate::acroform`]'s `text_string`.
fn text_string(s: &str) -> Object {
    if s.bytes().all(|b| b.is_ascii() && b != 0) {
        Object::LiteralString(s.as_bytes().to_vec())
    } else {
        let mut bytes = vec![0xFE, 0xFF];
        for cp in s.encode_utf16() {
            bytes.push((cp >> 8) as u8);
            bytes.push((cp & 0xFF) as u8);
        }
        Object::HexString(bytes)
    }
}

fn flatten_quad_points(qp: &[[f32; 8]]) -> Object {
    let mut out: Vec<Object> = Vec::with_capacity(qp.len() * 8);
    for tuple in qp {
        for v in tuple {
            out.push(Object::Real(*v as f64));
        }
    }
    Object::Array(out)
}

fn build_annotation_dict(annot: &Annotation, page_id: ObjectId) -> Result<Dict, PdfError> {
    let mut d = Dict::new()
        .with("Type", Object::Name("Annot".into()))
        .with("Rect", rect_array(annot.rect))
        .with("P", Object::Reference(page_id))
        .with("F", Object::Integer(annot.flags.unwrap_or(4) as i64));

    if let Some(t) = &annot.author {
        d.set("T", text_string(t));
    }
    if let Some(m) = &annot.modified {
        d.set("M", text_string(m));
    }
    if let Some(c) = &annot.colour {
        d.set("C", colour_array(c));
    }
    if let Some(b) = &annot.border {
        d.set("Border", border_array(b));
    } else {
        d.set(
            "Border",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(0),
            ]),
        );
    }

    match &annot.kind {
        AnnotationKind::Text {
            contents,
            icon,
            open,
        } => {
            d.set("Subtype", Object::Name("Text".into()));
            d.set("Contents", text_string(contents));
            d.set(
                "Name",
                Object::Name(icon.clone().unwrap_or_else(|| "Note".into())),
            );
            d.set("Open", Object::Bool(*open));
        }
        AnnotationKind::Link { uri } => {
            d.set("Subtype", Object::Name("Link".into()));
            let action = Dict::new()
                .with("Type", Object::Name("Action".into()))
                .with("S", Object::Name("URI".into()))
                .with("URI", Object::LiteralString(uri.as_bytes().to_vec()));
            d.set("A", Object::Dict(action));
        }
        AnnotationKind::FreeText {
            contents,
            default_appearance,
            quadding,
        } => {
            d.set("Subtype", Object::Name("FreeText".into()));
            d.set("Contents", text_string(contents));
            let da = default_appearance.as_deref().unwrap_or(DEFAULT_FREETEXT_DA);
            d.set("DA", Object::LiteralString(da.as_bytes().to_vec()));
            d.set("Q", Object::Integer(quadding.as_int()));
        }
        AnnotationKind::Highlight { quad_points } => {
            d.set("Subtype", Object::Name("Highlight".into()));
            d.set("QuadPoints", flatten_quad_points(quad_points));
        }
        AnnotationKind::Underline { quad_points } => {
            d.set("Subtype", Object::Name("Underline".into()));
            d.set("QuadPoints", flatten_quad_points(quad_points));
        }
        AnnotationKind::Squiggly { quad_points } => {
            d.set("Subtype", Object::Name("Squiggly".into()));
            d.set("QuadPoints", flatten_quad_points(quad_points));
        }
        AnnotationKind::StrikeOut { quad_points } => {
            d.set("Subtype", Object::Name("StrikeOut".into()));
            d.set("QuadPoints", flatten_quad_points(quad_points));
        }
        AnnotationKind::Stamp { icon, contents } => {
            d.set("Subtype", Object::Name("Stamp".into()));
            d.set(
                "Name",
                Object::Name(icon.clone().unwrap_or_else(|| "Draft".into())),
            );
            if let Some(c) = contents {
                d.set("Contents", text_string(c));
            }
        }
        AnnotationKind::Square {
            interior_colour,
            line_width,
        } => {
            d.set("Subtype", Object::Name("Square".into()));
            if let Some(ic) = interior_colour {
                d.set("IC", colour_array(ic));
            }
            if let Some(w) = line_width {
                let bs = Dict::new()
                    .with("Type", Object::Name("Border".into()))
                    .with("W", Object::Real(*w as f64));
                d.set("BS", Object::Dict(bs));
            }
        }
        AnnotationKind::Circle {
            interior_colour,
            line_width,
        } => {
            d.set("Subtype", Object::Name("Circle".into()));
            if let Some(ic) = interior_colour {
                d.set("IC", colour_array(ic));
            }
            if let Some(w) = line_width {
                let bs = Dict::new()
                    .with("Type", Object::Name("Border".into()))
                    .with("W", Object::Real(*w as f64));
                d.set("BS", Object::Dict(bs));
            }
        }
        AnnotationKind::Ink { strokes } => {
            d.set("Subtype", Object::Name("Ink".into()));
            let mut inklist: Vec<Object> = Vec::with_capacity(strokes.len());
            for stroke in strokes {
                let pts: Vec<Object> = stroke.iter().map(|v| Object::Real(*v as f64)).collect();
                inklist.push(Object::Array(pts));
            }
            d.set("InkList", Object::Array(inklist));
        }
        AnnotationKind::Line {
            endpoints,
            line_endings,
            interior_colour,
            leader_line,
            leader_line_extension,
            leader_line_offset,
            cap,
            intent,
        } => {
            d.set("Subtype", Object::Name("Line".into()));
            // /L — required four-real array per Table 175.
            d.set(
                "L",
                Object::Array(endpoints.iter().map(|v| Object::Real(*v as f64)).collect()),
            );
            if let Some(le) = line_endings {
                d.set("LE", line_ending_pair(le));
            }
            if let Some(ic) = interior_colour {
                d.set("IC", colour_array(ic));
            }
            if let Some(ll) = leader_line {
                d.set("LL", Object::Real(*ll as f64));
            }
            if let Some(lle) = leader_line_extension {
                d.set("LLE", Object::Real(*lle as f64));
            }
            if let Some(llo) = leader_line_offset {
                d.set("LLO", Object::Real(*llo as f64));
            }
            // /Cap defaults to false per Table 175 — only emit when
            // true so a round-trip through the round-197 reader yields
            // an absence-equals-default shape on the inverse direction.
            if *cap {
                d.set("Cap", Object::Bool(true));
            }
            if let Some(it) = intent {
                d.set("IT", Object::Name(it.clone()));
            }
        }
        AnnotationKind::Polygon {
            vertices,
            interior_colour,
            intent,
        } => {
            d.set("Subtype", Object::Name("Polygon".into()));
            d.set(
                "Vertices",
                Object::Array(vertices.iter().map(|v| Object::Real(*v as f64)).collect()),
            );
            if let Some(ic) = interior_colour {
                d.set("IC", colour_array(ic));
            }
            if let Some(it) = intent {
                d.set("IT", Object::Name(it.clone()));
            }
        }
        AnnotationKind::PolyLine {
            vertices,
            line_endings,
            interior_colour,
            intent,
        } => {
            d.set("Subtype", Object::Name("PolyLine".into()));
            d.set(
                "Vertices",
                Object::Array(vertices.iter().map(|v| Object::Real(*v as f64)).collect()),
            );
            if let Some(le) = line_endings {
                d.set("LE", line_ending_pair(le));
            }
            if let Some(ic) = interior_colour {
                d.set("IC", colour_array(ic));
            }
            if let Some(it) = intent {
                d.set("IT", Object::Name(it.clone()));
            }
        }
    }

    Ok(d)
}

/// Encode a two-element line-ending name pair (§12.5.6.7 Table 176)
/// as a `[name1 name2]` PDF array. Used by `/Line` and `/PolyLine`.
fn line_ending_pair(pair: &[String; 2]) -> Object {
    Object::Array(vec![
        Object::Name(pair[0].clone()),
        Object::Name(pair[1].clone()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_freetext_da_is_helvetica_12pt_black() {
        // §12.7.3.3.
        assert_eq!(DEFAULT_FREETEXT_DA, "/Helv 12 Tf 0 g");
    }

    #[test]
    fn quadding_int_values_match_table_174() {
        assert_eq!(FreeTextQuadding::Left.as_int(), 0);
        assert_eq!(FreeTextQuadding::Center.as_int(), 1);
        assert_eq!(FreeTextQuadding::Right.as_int(), 2);
    }

    #[test]
    fn rect_array_emits_four_reals() {
        match rect_array([1.0, 2.0, 3.0, 4.0]) {
            Object::Array(a) => assert_eq!(a.len(), 4),
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn flatten_quad_points_concatenates_each_tuple() {
        let qp = vec![[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0], [10.0; 8]];
        match flatten_quad_points(&qp) {
            Object::Array(a) => assert_eq!(a.len(), 16),
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn text_string_uses_literal_for_ascii() {
        match text_string("hello") {
            Object::LiteralString(bytes) => assert_eq!(bytes, b"hello"),
            _ => panic!("expected literal string"),
        }
    }

    #[test]
    fn text_string_uses_hex_utf16_for_non_ascii() {
        match text_string("héllo") {
            Object::HexString(bytes) => {
                // BOM + UTF-16BE; length must be even and >= 2.
                assert!(bytes.len() >= 2);
                assert_eq!(&bytes[..2], &[0xFE, 0xFF]);
            }
            _ => panic!("expected hex string"),
        }
    }

    #[test]
    fn line_ending_pair_emits_two_name_objects() {
        // §12.5.6.7 Table 176.
        match line_ending_pair(&["OpenArrow".to_string(), "ClosedArrow".to_string()]) {
            Object::Array(items) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(items[0], Object::Name(ref n) if n == "OpenArrow"));
                assert!(matches!(items[1], Object::Name(ref n) if n == "ClosedArrow"));
            }
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn polygon_polyline_validation_rejects_odd_vertex_count() {
        // §12.5.6.9 Table 178 — /Vertices is a flat (x, y) list.
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Polygon {
                vertices: vec![10.0, 10.0, 20.0],
                interior_colour: None,
                intent: None,
            },
        }];
        assert!(validate_annotations(&annots, 1).is_err());
    }

    #[test]
    fn polygon_polyline_validation_rejects_under_two_vertices() {
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::PolyLine {
                vertices: vec![10.0, 10.0],
                line_endings: None,
                interior_colour: None,
                intent: None,
            },
        }];
        assert!(validate_annotations(&annots, 1).is_err());
    }

    #[test]
    fn polygon_polyline_validation_accepts_two_vertex_degenerate_case() {
        // Two vertices = single edge — Adobe collapsed-markup edits
        // routinely emit this shape, so the writer accepts it.
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::PolyLine {
                vertices: vec![10.0, 10.0, 90.0, 90.0],
                line_endings: None,
                interior_colour: None,
                intent: None,
            },
        }];
        assert!(validate_annotations(&annots, 1).is_ok());
    }

    #[test]
    fn line_writer_emits_l_endpoints_and_omits_cap_when_false() {
        // §12.5.6.7 Table 175 — /Cap default is false; the writer
        // omits the entry to keep the round-trip through the
        // round-197 reader's "absent → false" branch tight.
        let annot = Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Line {
                endpoints: [10.0, 20.0, 110.0, 60.0],
                line_endings: None,
                interior_colour: None,
                leader_line: None,
                leader_line_extension: None,
                leader_line_offset: None,
                cap: false,
                intent: None,
            },
        };
        let d = build_annotation_dict(&annot, ObjectId::new(3)).unwrap();
        // /L present with four reals.
        let l = d
            .entries()
            .iter()
            .find(|(k, _)| k == "L")
            .expect("/L emitted");
        match &l.1 {
            Object::Array(items) => assert_eq!(items.len(), 4),
            _ => panic!("/L should be a four-real array"),
        }
        // /Cap absent (default false per Table 175).
        assert!(!d.entries().iter().any(|(k, _)| k == "Cap"));
    }
}
