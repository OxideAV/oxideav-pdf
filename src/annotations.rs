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
//! Round 232 closes the **markup-editing pair** the round-197 reader
//! already decodes:
//!
//! * **`/Caret`** text-edit caret (§12.5.6.11, Table 180) —
//!   [`AnnotationKind::Caret`]: `/RD` rectangle differences (the
//!   caret figure inset inside the outer `/Rect`), `/Sy` symbol name
//!   (`P` for the paragraph-mark glyph, `None` for the bare caret).
//! * **`/Popup`** text-editing window (§12.5.6.14, Table 183) —
//!   [`AnnotationKind::Popup`]: `/Parent` indirect reference to the
//!   parent markup annotation (encoded by index into the same
//!   `annotations` slice so the writer can resolve it to the actual
//!   on-wire object id after every annotation has been allocated),
//!   plus the `/Open` initial-visibility flag.
//!
//! Round 238 folds the **embedded-file marker** subtype into the
//! generic annotation surface so callers no longer have to drop down
//! to the round-33 attachments writer when they only need one file
//! pinned to a page:
//!
//! * **`/FileAttachment`** (§12.5.6.15, Table 184) —
//!   [`AnnotationKind::FileAttachment`]: writer additionally emits a
//!   `/Type /EmbeddedFile` stream (§7.11.4 Table 45) + a
//!   `/Type /Filespec` dict (§7.11.3 Table 44) + a catalog
//!   `/Names → /EmbeddedFiles` entry (§7.7.4 + §7.9.6) per
//!   FileAttachment annotation, then wires the annotation's `/FS`
//!   entry to the filespec. The round-33 `read_pdf_attachments`
//!   enumerator therefore sees the same files round-tripped.
//!
//! Round 245 closes the writer-side symmetry for the round-209
//! reader's **multimedia-anchor** family by adding the simpler of the
//! three subtypes — the §13.3 sound object is a self-describing
//! stream + metadata dict, and a `/Sound` annotation is just a pinned
//! reference to one:
//!
//! * **`/Sound`** (§12.5.6.16, Table 185) —
//!   [`AnnotationKind::Sound`]: writer additionally emits a
//!   `/Type /Sound` stream object (§13.3, Table 294) carrying the raw
//!   sample bytes plus the `/R` sample rate, `/C` channel count, `/B`
//!   bits-per-sample, and `/E` encoding metadata; the annotation's
//!   `/Sound` entry resolves to that stream's indirect reference, and
//!   the `/Name` icon (`Speaker` default per Table 185) selects the
//!   on-page glyph the viewer renders. The round-209
//!   `read_pdf_annotations` enumerator surfaces the same dict back
//!   verbatim.
//!
//! Round 252 closes the writer-side symmetry for the round-204 reader's
//! **fixed-print** annotation:
//!
//! * **`/Watermark`** (§12.5.6.22, Table 190 + Table 191) —
//!   [`AnnotationKind::Watermark`]: writer emits the bare
//!   `/Subtype /Watermark` annotation plus an optional `/FixedPrint`
//!   sub-dict (`/Type /FixedPrint` + `/Matrix` six-number affine
//!   transform + `/H` / `/V` printed-media translation percentages).
//!   Table 191 makes every entry but `/Type` optional with explicit
//!   defaults (`/Matrix` = identity, `/H` = `/V` = 0); the writer omits
//!   the defaults so a round-trip through the round-204
//!   `read_pdf_annotations` enumerator yields the same
//!   "absent → default" reader contract producer files use. The
//!   sub-dict is emitted inline (no separate indirect object) because
//!   Table 191 doesn't require it to be indirect and inline keeps the
//!   wire bytes smaller for the common fixed-print marker.
//!
//! Round 257 closes the writer-side symmetry for the round-215 reader's
//! **production-printer-mark** annotation:
//!
//! * **`/PrinterMark`** (§12.5.6.20, Table 362) —
//!   [`AnnotationKind::PrinterMark`]: writer emits the bare
//!   `/Subtype /PrinterMark` annotation plus the optional `/MN`
//!   mark-name Name (`ColorBar` / `RegistrationTarget` / `CutMark` /
//!   `PageInformation`, …). Table 362 makes `/MN` optional; the
//!   writer omits the entry when the caller passes `None` so a
//!   round-trip through the round-215 `read_pdf_annotations`
//!   enumerator yields the same "absent → None" reader shape. An
//!   empty `Some(String::new())` is rejected at validation time per
//!   §7.3.5 (Name tokens must be at least one byte). The Table-363
//!   `/MarkStyle` and `/Colorants` entries hang off the form-XObject
//!   appearance stream referenced from `/AP /N` (not the annotation
//!   dict itself), and stay routed through the §8.10 Form XObject
//!   walker — out of scope for this round just as they are for the
//!   round-215 reader.
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

use crate::attachments::{
    emit_embedded_file_stream, emit_embedded_files_name_tree, emit_filespec_dict, Attachment,
};
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
    /// `/Subtype /Caret` — text-edit caret marker (§12.5.6.11,
    /// Table 180, round 232). Indicates the presence of text edits at
    /// the position of the outer [`Annotation::rect`]. Optional
    /// `/RD` shrinks the caret figure inside the rectangle (e.g. when
    /// `/Sy /P` displays a paragraph mark whose bounds exceed the bare
    /// caret); `/Sy` selects the rendered symbol.
    Caret {
        /// `/RD` rectangle differences `[left top right bottom]`,
        /// each ≥ 0. The four values are the inset of the caret
        /// figure inside the outer `/Rect`. `None` ⇒ entry omitted
        /// (the caret fills the rectangle).
        rect_diffs: Option<[f32; 4]>,
        /// `/Sy` — caret symbol selector per Table 180.
        symbol: CaretSymbol,
    },
    /// `/Subtype /Popup` — text-entry pop-up window (§12.5.6.14,
    /// Table 183, round 232). A Popup is the editing surface for a
    /// markup parent (Text, FreeText, Highlight, Caret, …); it carries
    /// no appearance of its own and exists only to display the
    /// parent's `/Contents` for editing.
    ///
    /// The `/Parent` field is normatively an indirect reference per
    /// Table 183; the writer takes a 0-based index into the same
    /// `annotations` slice as [`Self::parent_index`] and resolves it
    /// to the actual on-wire object id after every annotation has
    /// been allocated.
    Popup {
        /// 0-based index into the `annotations` slice passed to
        /// [`write_pdf_with_annotations`] identifying the parent
        /// markup annotation whose `/Contents` / `/M` / `/C` / `/T`
        /// fields override this Popup's per Table 183. `None` ⇒
        /// `/Parent` entry omitted (the spec example in §12.5.6.14
        /// treats this as malformed — a Popup with no parent has no
        /// editing target — but tolerant readers still surface the
        /// dict, so the writer permits it).
        parent_index: Option<usize>,
        /// `/Open` — `true` ⇒ pop-up displayed at document open. Per
        /// Table 183 the default is `false`; the writer omits the
        /// entry on `false` so a round-trip through the round-197
        /// reader yields the same "absent → false" shape.
        open: bool,
    },
    /// `/Subtype /FileAttachment` — embedded-file marker (§12.5.6.15
    /// Table 184, round 238). The on-page paperclip / push-pin icon
    /// for a file embedded inside the PDF.
    ///
    /// Writing one of these causes the writer to additionally emit
    /// (a) a `/Type /EmbeddedFile` stream object carrying
    /// `file_bytes` (FlateDecode-compressed when smaller),
    /// (b) a `/Type /Filespec` dictionary naming `file_name` and
    /// pointing at the stream via `/EF`, and (c) a catalog
    /// `/Names → /EmbeddedFiles` name tree entry keyed on
    /// `file_name` so the round-33 `read_pdf_attachments` enumerator
    /// surfaces the same file. The annotation's `/FS` entry holds
    /// the indirect reference to the filespec dict per Table 184.
    FileAttachment {
        /// `/Name` icon identifier — Table 184 enumerates
        /// `PushPin` (default), `GraphPushPin`, `PaperclipTag`, and
        /// the more general `Graph` / `Paperclip` / `Tag` names.
        /// `None` ⇒ writer emits `/PushPin`.
        icon: Option<String>,
        /// User-visible file name written into the filespec's `/F`
        /// (PDFDocEncoded literal when ASCII) and `/UF` (UTF-16BE
        /// hex with BOM) entries per §7.11.2 Table 43, and used as
        /// the name-tree key per §7.7.4 + §7.9.6.
        file_name: String,
        /// Body of the `/Type /EmbeddedFile` stream object — the
        /// raw bytes the viewer will save when the user extracts
        /// the attachment.
        file_bytes: Vec<u8>,
        /// `/Subtype` on the embedded-file stream (a MIME type per
        /// §7.11.4 Table 45) + `/Desc` text on the filespec dict.
        /// `None` ⇒ neither entry emitted.
        mime_type: Option<String>,
    },
    /// `/Subtype /Sound` — sound annotation (§12.5.6.16 Table 185,
    /// round 245). The annotation pins a `/Sound` stream object to a
    /// page; activation plays the sample data through the viewer's
    /// audio output. The §13.3 stream (Table 294) is materialised by
    /// the writer's pre-pass, and the annotation's `/Sound` entry
    /// resolves to that stream's indirect reference.
    Sound {
        /// `/Name` icon identifier — Table 185 names `Speaker`
        /// (default) and `Mic`. Authoring tools may extend this set;
        /// `None` ⇒ writer emits `/Speaker`.
        icon: Option<String>,
        /// `/R` sampling rate, in samples per second per channel
        /// (§13.3 Table 294). Required. Common conforming values per
        /// the §13.3 portability guidance are `8000`, `11025`, and
        /// `22050`; the writer accepts any positive value.
        sampling_rate: f32,
        /// `/C` number of channels (§13.3 Table 294). Default value
        /// `1`. The §13.3 portability guidance recommends `1` or `2`;
        /// the writer accepts any value ≥ 1 and omits the entry when
        /// it equals the spec default to round-trip an
        /// absent-equals-default reader contract.
        channels: u32,
        /// `/B` bits per sample value per channel (§13.3 Table 294).
        /// Default value `8`. The writer accepts any value ≥ 1 and
        /// omits the entry when it equals the spec default.
        bits_per_sample: u32,
        /// `/E` encoding format for the sample data (§13.3 Table 294).
        /// Default value [`SoundEncoding::Raw`]. The writer omits the
        /// entry when this variant is set so a write-then-read cycle
        /// surfaces an absent-equals-default reader shape.
        encoding: SoundEncoding,
        /// Raw sample bytes that form the §13.3 stream body. Byte
        /// order is big-endian for samples larger than 8 bits per
        /// the §13.3 packing rule (caller responsibility — the writer
        /// passes the buffer through verbatim). For stereo samples,
        /// the caller interleaves left then right per channel per the
        /// §13.3 interleave rule.
        sound_samples: Vec<u8>,
    },
    /// `/Subtype /PrinterMark` — production printer's mark
    /// (§12.5.6.20 Table 362, round 257). PDF 1.4. The on-page
    /// registration target, colour bar, cut mark, or page-information
    /// bar a print-production tool stamps onto every output sheet.
    ///
    /// Per Table 362 the only annotation-dict-local entry is the
    /// optional `/MN` (mark-name) Name identifying the type of mark
    /// (e.g. `ColorBar`, `RegistrationTarget`, `CutMark`,
    /// `PageInformation`). The actual mark graphics live in the
    /// form-XObject appearance stream referenced from `/AP /N`; the
    /// `/MarkStyle` and `/Colorants` entries in Table 363 hang off
    /// that form XObject, not the annot dict — so they are out of
    /// scope for the round-257 writer just as they are for the
    /// round-215 reader.
    ///
    /// `None` ⇒ writer omits `/MN` entirely, matching the spec's
    /// "optional" wording and the round-215 reader's "absent → None"
    /// shape. Per Table 362 a PrinterMark annotation should additionally
    /// carry `/Type /PrinterMark` (in addition to the §12.5.2 Table 164
    /// `/Type /Annot`) — the writer emits that marker via the
    /// `/Subtype` slot, which is what every observed producer relies
    /// on (the second `/Type` entry is rarely emitted in the wild
    /// because the §12.5.2 `/Type /Annot` slot already designates the
    /// dictionary as an annotation).
    PrinterMark {
        /// `/MN` — arbitrary Name identifying the kind of mark
        /// (Table 362). `None` ⇒ entry omitted (the spec makes it
        /// optional). Common values include `ColorBar`,
        /// `RegistrationTarget`, `CutMark`, `PageInformation`; the
        /// spec does not enumerate a closed set, so the writer
        /// passes any caller-supplied Name through verbatim.
        ///
        /// An empty `Some(String::new())` is rejected at validation
        /// time — a Name token is required to be at least one byte
        /// per §7.3.5, and a zero-byte mark name would not identify
        /// any taxonomy entry.
        mark_name: Option<String>,
    },
    /// `/Subtype /Watermark` — fixed-print graphics (§12.5.6.22
    /// Table 190, round 252). Used for content that prints at a fixed
    /// size + position regardless of the dimensions of the printed
    /// page — page-number stamps, copyright marks, "DRAFT" overlays
    /// laid out per Table 191's media-relative geometry.
    ///
    /// Per Table 190 the only sub-entry is the optional `/FixedPrint`
    /// dict (carried here as [`FixedPrintSpec`]). `None` leaves the
    /// `/FixedPrint` entry off the annotation dict, matching the
    /// Table 190 wording: *"If this entry is not present, the
    /// annotation shall be drawn without any special consideration for
    /// the dimensions of the target media."*
    Watermark {
        /// `/FixedPrint` sub-dict (§12.5.6.22 Table 191). `None` ⇒
        /// entry omitted (the watermark draws without media-relative
        /// positioning, per Table 190).
        fixed_print: Option<FixedPrintSpec>,
    },
}

/// `/E` encoding selector for [`AnnotationKind::Sound`] sample data
/// (ISO 32000-1 §13.3 Table 294). Table 294 lists four values; the
/// default is [`Self::Raw`] (unsigned in the range 0..=2^B − 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SoundEncoding {
    /// `/E /Raw` — unsigned values in the range 0..=2^B − 1
    /// (default per Table 294). The writer omits the `/E` entry on
    /// this variant so a write-then-read cycle through the round-209
    /// reader yields the same "absent → Raw" branch.
    #[default]
    Raw,
    /// `/E /Signed` — two's-complement signed values.
    Signed,
    /// `/E /muLaw` — μ-law encoded samples (§13.3 portability
    /// guidance pairs this with `R=8000`, `C=1`, `B=8`).
    MuLaw,
    /// `/E /ALaw` — A-law encoded samples.
    ALaw,
}

impl SoundEncoding {
    fn as_name(self) -> Option<&'static str> {
        match self {
            // Default per Table 294 — omit the /E entry.
            Self::Raw => None,
            Self::Signed => Some("Signed"),
            Self::MuLaw => Some("muLaw"),
            Self::ALaw => Some("ALaw"),
        }
    }
}

/// `/FixedPrint` sub-dict for [`AnnotationKind::Watermark`] (ISO 32000-1
/// §12.5.6.22 Table 191, round 252). Every field is optional with an
/// explicit Table 191 default; the writer omits each entry whose value
/// equals the default so a write-then-read cycle through the round-204
/// `read_pdf_annotations` enumerator yields the same
/// "absent → default" reader shape producer files use.
///
/// Mirrors the reader-side [`crate::FixedPrint`] decoded struct shape
/// so callers can copy fields directly between the two when manipulating
/// existing watermarks.
///
/// Default-constructed (`FixedPrintSpec::default()`) sets every entry
/// to `None` so the writer emits the bare `/Type /FixedPrint` marker
/// dict — the most-minimal way to opt a Watermark in to media-relative
/// rendering without overriding any geometry.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FixedPrintSpec {
    /// `/Matrix [a b c d e f]` — affine transform applied to the
    /// annotation rectangle before rendering. `None` ⇒ writer omits
    /// the entry (Table 191 default is the identity matrix
    /// `[1 0 0 1 0 0]`).
    pub matrix: Option<[f32; 6]>,
    /// `/H` — horizontal translation as a fraction of the target media
    /// width (`1.0` = 100 %, `0.0` = 0 %). `None` ⇒ writer omits the
    /// entry (Table 191 default `0`).
    pub h: Option<f32>,
    /// `/V` — vertical translation as a fraction of the target media
    /// height. `None` ⇒ writer omits the entry (Table 191 default `0`).
    pub v: Option<f32>,
}

/// `/Sy` symbol selector for [`AnnotationKind::Caret`] (ISO 32000-1
/// §12.5.6.11 Table 180). Table 180 lists two values: `P` (a new
/// paragraph mark should be associated with the caret) and `None`
/// (no symbol). The default is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaretSymbol {
    /// `/Sy /None` — no symbol displayed (default per Table 180).
    /// The writer omits the entry when this variant is set so a
    /// round-trip through the round-197 reader yields the same
    /// "absent → None" shape.
    #[default]
    None,
    /// `/Sy /P` — the paragraph symbol (¶) is associated with the
    /// caret. Spec-defined Table 180 value.
    Paragraph,
}

impl CaretSymbol {
    fn as_name(self) -> Option<&'static str> {
        match self {
            // Default per Table 180 — omit the /Sy entry.
            Self::None => None,
            Self::Paragraph => Some("P"),
        }
    }
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

    // ---- Pass 1: allocate one id per annotation up front, so the
    //              Popup subtype's `/Parent` indirect reference
    //              (§12.5.6.14 Table 183) can resolve to the actual
    //              on-wire id of its parent markup annotation.
    let annotation_ids: Vec<ObjectId> = (0..annotations.len()).map(|_| doc.allocate_id()).collect();

    // ---- Pre-pass: emit one `/Type /EmbeddedFile` stream + one
    //                `/Type /Filespec` dict per [`AnnotationKind::FileAttachment`]
    //                (§12.5.6.15 Table 184) so the annotation dict's `/FS`
    //                entry can resolve to a real indirect reference. The
    //                catalog `/Names → /EmbeddedFiles` name tree is
    //                materialised after every filespec is in place
    //                (§7.7.4 + §7.9.6).
    //
    // The same pre-pass emits one `/Type /Sound` stream per
    // [`AnnotationKind::Sound`] (§12.5.6.16 + §13.3 Table 294) so the
    // annotation dict's `/Sound` entry resolves to a real indirect
    // reference. The two emit branches are unrelated wire-wise but
    // share the pre-pass slot so a single iteration covers both.
    let mut filespec_ids: Vec<Option<ObjectId>> = vec![None; annotations.len()];
    let mut sound_stream_ids: Vec<Option<ObjectId>> = vec![None; annotations.len()];
    let mut name_tree_entries: Vec<(String, ObjectId)> = Vec::new();
    for (i, annot) in annotations.iter().enumerate() {
        match &annot.kind {
            AnnotationKind::FileAttachment {
                file_name,
                file_bytes,
                mime_type,
                ..
            } => {
                // Build a transient Attachment so we can re-use the round-33
                // stream + filespec emitters byte-for-byte. The annotation
                // marker (`annotation_*` fields) is unused here because this
                // path already builds the /Subtype /FileAttachment dict
                // itself via `build_annotation_dict`.
                let mut attach = Attachment::new(file_name.clone(), file_bytes.clone());
                if let Some(mime) = mime_type {
                    attach = attach.with_mime_type(mime.clone());
                }
                let stream_id = emit_embedded_file_stream(&mut doc, &attach);
                let filespec_id = emit_filespec_dict(&mut doc, &attach, stream_id);
                filespec_ids[i] = Some(filespec_id);
                name_tree_entries.push((file_name.clone(), filespec_id));
            }
            AnnotationKind::Sound {
                sampling_rate,
                channels,
                bits_per_sample,
                encoding,
                sound_samples,
                ..
            } => {
                let stream_id = emit_sound_stream(
                    &mut doc,
                    *sampling_rate,
                    *channels,
                    *bits_per_sample,
                    *encoding,
                    sound_samples.clone(),
                );
                sound_stream_ids[i] = Some(stream_id);
            }
            _ => {}
        }
    }
    // §7.7.4 + §7.9.6 — wire the name tree onto the catalog when at
    // least one /FileAttachment annotation contributed a filespec.
    if !name_tree_entries.is_empty() {
        let names_dict_id = emit_embedded_files_name_tree(&mut doc, &mut name_tree_entries);
        let catalog = doc.object_mut(pages_build.catalog_id).ok_or_else(|| {
            PdfError::other(
                "write_pdf_with_annotations: catalog id missing for /Names patch (FileAttachment)",
            )
        })?;
        if let Object::Dict(d) = catalog {
            d.set("Names", Object::Reference(names_dict_id));
        } else {
            return Err(PdfError::other(
                "write_pdf_with_annotations: catalog object is not a Dict",
            ));
        }
    }

    // ---- Pre-pass: §12.5.5 normal appearance streams. Each
    //      geometry-determined annotation kind gets a form-XObject
    //      appearance whose /BBox is the annotation /Rect, referenced
    //      from the dict's /AP << /N … >> so conforming readers render
    //      the authored appearance instead of a handler-invented one.
    let appearance_ids: Vec<Option<ObjectId>> = annotations
        .iter()
        .map(|annot| {
            build_normal_appearance(annot)
                .map(|content| emit_appearance_stream(&mut doc, content, annot.rect))
        })
        .collect();

    // ---- Pass 2: build each annotation dict + commit it under its
    //              pre-allocated id, bucketing by source page so the
    //              `/Annots` array can be patched onto each page after.
    let mut by_page: Vec<Vec<ObjectId>> = (0..n_pages).map(|_| Vec::new()).collect();
    for (i, annot) in annotations.iter().enumerate() {
        let mut dict = build_annotation_dict(
            annot,
            pages_build.page_ids[annot.source_page_index],
            &annotation_ids,
            filespec_ids[i],
            sound_stream_ids[i],
        )?;
        if let Some(ap_id) = appearance_ids[i] {
            dict.set(
                "AP",
                Object::Dict(Dict::new().with("N", Object::Reference(ap_id))),
            );
        }
        doc.add_object(annotation_ids[i], Object::Dict(dict));
        by_page[annot.source_page_index].push(annotation_ids[i]);
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
    let n_annots = annotations.len();
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
            // §12.5.6.11 Table 180 — every /RD component must be ≥ 0
            // and the inset must fit inside the outer /Rect (the
            // top+bottom inset shall be < /Rect height, the
            // left+right inset shall be < /Rect width).
            AnnotationKind::Caret {
                rect_diffs: Some(rd),
                ..
            } => {
                if rd.iter().any(|v| *v < 0.0) {
                    return Err(PdfError::other(format!(
                        "write_pdf_with_annotations: annotation #{i} /Caret /RD \
                         components must all be ≥ 0 (got {rd:?})",
                    )));
                }
                let width = a.rect[2] - a.rect[0];
                let height = a.rect[3] - a.rect[1];
                if rd[0] + rd[2] >= width || rd[1] + rd[3] >= height {
                    return Err(PdfError::other(format!(
                        "write_pdf_with_annotations: annotation #{i} /Caret /RD \
                         inset must fit inside /Rect (rd={rd:?}, rect={:?})",
                        a.rect,
                    )));
                }
            }
            // §12.5.6.14 Table 183 — /Parent is normatively an
            // indirect reference; the writer takes a 0-based index
            // into the same annotations slice. The index must be in
            // range and may not point at the Popup itself (a Popup
            // can't be its own parent — that would be a self-cycle
            // on dereference).
            AnnotationKind::Popup {
                parent_index: Some(idx),
                ..
            } => {
                if *idx >= n_annots {
                    return Err(PdfError::other(format!(
                        "write_pdf_with_annotations: annotation #{i} /Popup parent_index {idx} \
                         out of range (only {n_annots} annotation(s) supplied)",
                    )));
                }
                if *idx == i {
                    return Err(PdfError::other(format!(
                        "write_pdf_with_annotations: annotation #{i} /Popup parent_index points \
                         at itself; a Popup cannot be its own /Parent (§12.5.6.14)",
                    )));
                }
                // The §12.5.6.14 text describes a Popup as the
                // editing surface for a *markup* parent — Popup
                // pointing at another Popup makes no semantic sense
                // (no parent contents to display).
                if matches!(annotations[*idx].kind, AnnotationKind::Popup { .. }) {
                    return Err(PdfError::other(format!(
                        "write_pdf_with_annotations: annotation #{i} /Popup parent_index {idx} \
                         points at another /Popup; the parent must be a markup annotation \
                         per §12.5.6.14",
                    )));
                }
            }
            // §12.5.6.15 Table 184 — every /FileAttachment carries a
            // mandatory /FS filespec; an empty `file_name` would
            // produce a filespec whose /F + /UF are zero-length text
            // strings, which §7.11.2 forbids (a file name must
            // identify a file). The byte buffer itself MAY be empty
            // (a zero-byte attachment is valid per Table 45).
            AnnotationKind::FileAttachment { file_name, .. } if file_name.is_empty() => {
                return Err(PdfError::other(format!(
                    "write_pdf_with_annotations: annotation #{i} /FileAttachment \
                     file_name is empty (§7.11.2 requires a non-empty file name)",
                )));
            }
            // §13.3 Table 294 — /R sampling rate is required and the
            // §13.3 text requires it to be a positive samples-per-
            // second count. /C and /B carry defaults (1 and 8) but
            // values of 0 would describe a zero-channel or zero-bit
            // stream that has no playable content. The sample buffer
            // itself is required (§12.5.6.16 Table 185 marks /Sound
            // mandatory and §13.3 describes the stream as containing
            // sample values that define the sound — an empty buffer
            // would describe a zero-second silence rather than a
            // playable sound).
            AnnotationKind::Sound {
                sampling_rate,
                channels,
                bits_per_sample,
                sound_samples,
                ..
            } => {
                // Use `<=` (rather than `!( > 0.0)`) so the comparison
                // covers NaN — `NaN <= 0.0` is false, but a NaN sample
                // rate is non-finite and should still be rejected;
                // add an explicit `is_finite` guard alongside.
                if !sampling_rate.is_finite() || *sampling_rate <= 0.0 {
                    return Err(PdfError::other(format!(
                        "write_pdf_with_annotations: annotation #{i} /Sound sampling_rate \
                         must be a positive finite value (got {sampling_rate}) — §13.3 /R is samples/sec",
                    )));
                }
                if *channels == 0 {
                    return Err(PdfError::other(format!(
                        "write_pdf_with_annotations: annotation #{i} /Sound channels must be \
                         ≥ 1 (§13.3 /C is the channel count)",
                    )));
                }
                if *bits_per_sample == 0 {
                    return Err(PdfError::other(format!(
                        "write_pdf_with_annotations: annotation #{i} /Sound bits_per_sample \
                         must be ≥ 1 (§13.3 /B is bits per sample value)",
                    )));
                }
                if sound_samples.is_empty() {
                    return Err(PdfError::other(format!(
                        "write_pdf_with_annotations: annotation #{i} /Sound sound_samples is \
                         empty (§12.5.6.16 /Sound stream carries the sample data)",
                    )));
                }
            }
            // §12.5.6.22 Table 191 — every /FixedPrint sub-dict value is
            // optional with an explicit numeric default. The spec is
            // explicit that negative /H or /V values "should not be
            // used, since they may cause content to be drawn off the
            // page" — we surface that producer guidance as a hard
            // writer reject so a downstream PDF renderer sees only
            // in-range fixed-print metadata. /Matrix entries that are
            // non-finite would produce an undefined affine transform
            // (the §8.3.4 transform composition assumes finite reals),
            // so a NaN or infinity in any /Matrix slot is also rejected.
            AnnotationKind::Watermark {
                fixed_print: Some(fp),
            } => {
                if let Some(m) = fp.matrix {
                    if m.iter().any(|v| !v.is_finite()) {
                        return Err(PdfError::other(format!(
                            "write_pdf_with_annotations: annotation #{i} /Watermark \
                             /FixedPrint /Matrix entries must all be finite (got {m:?})",
                        )));
                    }
                }
                if let Some(h) = fp.h {
                    if !h.is_finite() || h < 0.0 {
                        return Err(PdfError::other(format!(
                            "write_pdf_with_annotations: annotation #{i} /Watermark \
                             /FixedPrint /H must be a finite non-negative number \
                             (got {h}) — §12.5.6.22 Table 191 negative-values warning",
                        )));
                    }
                }
                if let Some(v) = fp.v {
                    if !v.is_finite() || v < 0.0 {
                        return Err(PdfError::other(format!(
                            "write_pdf_with_annotations: annotation #{i} /Watermark \
                             /FixedPrint /V must be a finite non-negative number \
                             (got {v}) — §12.5.6.22 Table 191 negative-values warning",
                        )));
                    }
                }
            }
            // §12.5.6.20 Table 362 — /MN is a PDF Name. §7.3.5 requires
            // a Name to be at least one byte; an empty mark name would
            // not identify any taxonomy entry and would serialise as a
            // bare `/` token that round-trips as the absent-entry case
            // (silently dropping the caller's intent). Reject it.
            AnnotationKind::PrinterMark {
                mark_name: Some(name),
            } if name.is_empty() => {
                return Err(PdfError::other(format!(
                    "write_pdf_with_annotations: annotation #{i} /PrinterMark \
                     /MN mark name must be non-empty (§7.3.5 / §12.5.6.20 Table 362)",
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

/// Emit one `/Type /XObject /Subtype /Form` appearance stream
/// (§12.5.5 — "Each appearance stream is a form XObject") whose
/// `/BBox` equals the annotation `/Rect`, so the §12.5.5 placement
/// algorithm maps it onto the rectangle by identity and the content
/// operators paint directly in default-user-space coordinates.
fn emit_appearance_stream(doc: &mut Document, content: Vec<u8>, bbox: [f32; 4]) -> ObjectId {
    let dict = Dict::new()
        .with("Type", Object::Name("XObject".into()))
        .with("Subtype", Object::Name("Form".into()))
        .with("BBox", rect_array(bbox));
    doc.add(Object::Stream(crate::objects::Stream::new(dict, content)))
}

/// Append the colour operator for a Table 164-shape colour array
/// (0 / 1 / 3 / 4 components — transparent / DeviceGray / DeviceRGB /
/// DeviceCMYK) to appearance-stream content. `fill` selects the
/// non-stroking (`g` / `rg` / `k`) vs stroking (`G` / `RG` / `K`)
/// operator family. Returns `false` (nothing appended) for the
/// zero-component "no colour; transparent" form or an arity the table
/// doesn't define.
fn push_colour_op(out: &mut String, comps: &[f32], fill: bool) -> bool {
    use crate::operators::format_real;
    let op = match (comps.len(), fill) {
        (1, true) => "g",
        (1, false) => "G",
        (3, true) => "rg",
        (3, false) => "RG",
        (4, true) => "k",
        (4, false) => "K",
        _ => return false,
    };
    for c in comps {
        out.push_str(&format_real(f64::from(*c)));
        out.push(' ');
    }
    out.push_str(op);
    out.push('\n');
    true
}

/// Cubic-Bézier circle constant: the control-point offset that makes
/// four cubic segments approximate a quarter arc, `4·(√2 − 1)/3`.
const ARC_KAPPA: f32 = 0.552_284_8;

/// §12.5.5 — build the normal-appearance content stream for an
/// annotation whose visual is fully determined by its dictionary
/// geometry. Returns `None` for kinds whose presentation is
/// viewer-supplied (Text note icons, Stamp artwork, Popup windows, …)
/// or whose effective paint is empty (no interior colour and a
/// zero-width / transparent border).
///
/// The content paints in default user space (the emitted form's
/// `/BBox` is the annotation `/Rect` with an identity `/Matrix`, so
/// the §12.5.5 placement is the identity map).
fn build_normal_appearance(annot: &Annotation) -> Option<Vec<u8>> {
    use crate::operators::format_real;
    let fr = |v: f32| format_real(f64::from(v));

    // Stroke colour: /C per Table 164 (None ⇒ the conventional black;
    // an explicit empty array ⇒ transparent, i.e. no stroke).
    let stroke_comps: Option<&[f32]> = match &annot.colour {
        Some(c) if c.is_empty() => None,
        Some(c) => Some(c.as_slice()),
        None => Some(&[0.0f32; 1][..]),
    };

    match &annot.kind {
        AnnotationKind::Square {
            interior_colour,
            line_width,
        }
        | AnnotationKind::Circle {
            interior_colour,
            line_width,
        } => {
            // §12.5.6.8 — the rectangle / ellipse is inscribed within
            // /Rect; §12.5.4 — the border is drawn completely inside
            // the annotation rectangle, hence the half-width inset.
            let w = line_width.unwrap_or(1.0).max(0.0);
            let fill_comps = interior_colour.as_deref().filter(|c| !c.is_empty());
            let stroking = w > 0.0 && stroke_comps.is_some();
            let filling = fill_comps.is_some();
            if !filling && !stroking {
                return None;
            }
            let mut ops = String::new();
            let mut painted_colour = false;
            if let Some(c) = fill_comps {
                painted_colour |= push_colour_op(&mut ops, c, true);
            }
            if stroking {
                if let Some(c) = stroke_comps {
                    painted_colour |= push_colour_op(&mut ops, c, false);
                }
                ops.push_str(&fr(w));
                ops.push_str(" w\n");
            }
            if !painted_colour {
                return None;
            }
            let inset = if stroking { w / 2.0 } else { 0.0 };
            let (x0, y0) = (annot.rect[0] + inset, annot.rect[1] + inset);
            let (x1, y1) = (annot.rect[2] - inset, annot.rect[3] - inset);
            if x1 <= x0 || y1 <= y0 {
                return None;
            }
            if matches!(annot.kind, AnnotationKind::Square { .. }) {
                ops.push_str(&format!(
                    "{} {} {} {} re\n",
                    fr(x0),
                    fr(y0),
                    fr(x1 - x0),
                    fr(y1 - y0)
                ));
            } else {
                // Ellipse inscribed in the (inset) rectangle as four
                // cubic quarter-arcs.
                let (cx, cy) = ((x0 + x1) / 2.0, (y0 + y1) / 2.0);
                let (rx, ry) = ((x1 - x0) / 2.0, (y1 - y0) / 2.0);
                let (kx, ky) = (rx * ARC_KAPPA, ry * ARC_KAPPA);
                ops.push_str(&format!("{} {} m\n", fr(cx + rx), fr(cy)));
                for (c1, c2, end) in [
                    ((cx + rx, cy + ky), (cx + kx, cy + ry), (cx, cy + ry)),
                    ((cx - kx, cy + ry), (cx - rx, cy + ky), (cx - rx, cy)),
                    ((cx - rx, cy - ky), (cx - kx, cy - ry), (cx, cy - ry)),
                    ((cx + kx, cy - ry), (cx + rx, cy - ky), (cx + rx, cy)),
                ] {
                    ops.push_str(&format!(
                        "{} {} {} {} {} {} c\n",
                        fr(c1.0),
                        fr(c1.1),
                        fr(c2.0),
                        fr(c2.1),
                        fr(end.0),
                        fr(end.1)
                    ));
                }
                ops.push_str("h\n");
            }
            ops.push_str(match (filling, stroking) {
                (true, true) => "B\n",
                (true, false) => "f\n",
                _ => "S\n",
            });
            Some(ops.into_bytes())
        }
        AnnotationKind::Line { endpoints, .. } => {
            // §12.5.6.7 — a straight line from (x1,y1) to (x2,y2)
            // (the /L entry; /Rect is only the bounding box). The
            // Table 176 line-ending glyphs (/LE) are not drawn.
            let c = stroke_comps?;
            let mut ops = String::new();
            if !push_colour_op(&mut ops, c, false) {
                return None;
            }
            ops.push_str(&fr(annotation_border_width(annot)));
            ops.push_str(" w\n");
            ops.push_str(&format!(
                "{} {} m\n{} {} l\nS\n",
                fr(endpoints[0]),
                fr(endpoints[1]),
                fr(endpoints[2]),
                fr(endpoints[3])
            ));
            Some(ops.into_bytes())
        }
        AnnotationKind::Ink { strokes } => {
            // §12.5.6.13 — each /InkList entry is one freehand stroke;
            // points are connected by straight lines (the spec permits
            // "straight lines or curves").
            let c = stroke_comps?;
            let mut ops = String::new();
            if !push_colour_op(&mut ops, c, false) {
                return None;
            }
            ops.push_str(&fr(annotation_border_width(annot)));
            ops.push_str(" w\n1 J 1 j\n"); // round caps + joins
            let mut any = false;
            for stroke in strokes {
                if stroke.len() < 4 {
                    continue;
                }
                any = true;
                ops.push_str(&format!("{} {} m\n", fr(stroke[0]), fr(stroke[1])));
                for xy in stroke.chunks_exact(2).skip(1) {
                    ops.push_str(&format!("{} {} l\n", fr(xy[0]), fr(xy[1])));
                }
            }
            if !any {
                return None;
            }
            ops.push_str("S\n");
            Some(ops.into_bytes())
        }
        AnnotationKind::Polygon {
            vertices,
            interior_colour,
            ..
        }
        | AnnotationKind::PolyLine {
            vertices,
            interior_colour,
            ..
        } => {
            // §12.5.6.9 — vertices connected by straight lines; a
            // Polygon implicitly closes (first to last vertex) and may
            // fill its interior with /IC, a PolyLine stays open (its
            // /IC colours only the Table 176 endings, which are not
            // drawn here).
            if vertices.len() < 4 {
                return None;
            }
            let closed = matches!(annot.kind, AnnotationKind::Polygon { .. });
            let fill_comps = if closed {
                interior_colour.as_deref().filter(|c| !c.is_empty())
            } else {
                None
            };
            let mut ops = String::new();
            let mut painted = false;
            if let Some(c) = fill_comps {
                painted |= push_colour_op(&mut ops, c, true);
            }
            let stroking = if let Some(c) = stroke_comps {
                let ok = push_colour_op(&mut ops, c, false);
                if ok {
                    ops.push_str(&fr(annotation_border_width(annot)));
                    ops.push_str(" w\n");
                }
                painted |= ok;
                ok
            } else {
                false
            };
            if !painted {
                return None;
            }
            ops.push_str(&format!("{} {} m\n", fr(vertices[0]), fr(vertices[1])));
            for xy in vertices.chunks_exact(2).skip(1) {
                ops.push_str(&format!("{} {} l\n", fr(xy[0]), fr(xy[1])));
            }
            if closed {
                ops.push_str("h\n");
            }
            ops.push_str(match (fill_comps.is_some(), stroking) {
                (true, true) => "B\n",
                (true, false) => "f\n",
                _ => "S\n",
            });
            Some(ops.into_bytes())
        }
        _ => None,
    }
}

/// The stroke width for a line-family appearance: the `/Border` array
/// width component when the caller supplied one (Table 164 `[hr vr
/// w]`), else the §12.5.4 "neither `Border` nor `BS` present" default
/// of 1. A non-finite / negative width clamps to the default.
fn annotation_border_width(annot: &Annotation) -> f32 {
    match annot.border.as_ref().and_then(|b| b.get(2)).copied() {
        Some(w) if w.is_finite() && w > 0.0 => w,
        _ => 1.0,
    }
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

fn build_annotation_dict(
    annot: &Annotation,
    page_id: ObjectId,
    annotation_ids: &[ObjectId],
    filespec_id: Option<ObjectId>,
    sound_stream_id: Option<ObjectId>,
) -> Result<Dict, PdfError> {
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
        AnnotationKind::Caret { rect_diffs, symbol } => {
            // §12.5.6.11 Table 180.
            d.set("Subtype", Object::Name("Caret".into()));
            if let Some(rd) = rect_diffs {
                d.set(
                    "RD",
                    Object::Array(rd.iter().map(|v| Object::Real(*v as f64)).collect()),
                );
            }
            // /Sy default is /None per Table 180 ⇒ writer omits the
            // entry on `CaretSymbol::None` so a write-then-read cycle
            // through the round-197 reader yields the same
            // "absent → None symbol" branch.
            if let Some(name) = symbol.as_name() {
                d.set("Sy", Object::Name(name.into()));
            }
        }
        AnnotationKind::Popup { parent_index, open } => {
            // §12.5.6.14 Table 183.
            d.set("Subtype", Object::Name("Popup".into()));
            if let Some(idx) = parent_index {
                // Validation (see validate_annotations) guarantees idx
                // is in range — defensive indexing here would only
                // mask a future skipped-validation regression.
                d.set("Parent", Object::Reference(annotation_ids[*idx]));
            }
            // /Open default is false per Table 183 ⇒ writer omits the
            // entry on `false` so a round-trip through the round-197
            // reader yields the same "absent → false" branch.
            if *open {
                d.set("Open", Object::Bool(true));
            }
        }
        AnnotationKind::FileAttachment { icon, .. } => {
            // §12.5.6.15 Table 184.
            d.set("Subtype", Object::Name("FileAttachment".into()));
            // /FS — indirect reference to the filespec dict materialised
            // in the pre-pass above. The unwrap is safe because the
            // pre-pass populates `filespec_id` for every FileAttachment
            // before this dispatch runs; a None here would signal a
            // skipped pre-pass and is treated as a hard internal error
            // rather than silently emitting an incomplete dict.
            let fs = filespec_id.ok_or_else(|| {
                PdfError::other(
                    "build_annotation_dict: /FileAttachment is missing its filespec id \
                     (pre-pass skipped?)",
                )
            })?;
            d.set("FS", Object::Reference(fs));
            // /Name — defaults to /PushPin per Table 184.
            let icon_name = icon.clone().unwrap_or_else(|| "PushPin".into());
            d.set("Name", Object::Name(icon_name));
        }
        AnnotationKind::Sound { icon, .. } => {
            // §12.5.6.16 Table 185.
            d.set("Subtype", Object::Name("Sound".into()));
            // /Sound — indirect reference to the §13.3 sound stream
            // materialised in the pre-pass. Same defensive contract as
            // the FileAttachment /FS handling: a None here would mean
            // the pre-pass was skipped and a silent omission would
            // produce a malformed annotation per Table 185.
            let snd = sound_stream_id.ok_or_else(|| {
                PdfError::other(
                    "build_annotation_dict: /Sound is missing its stream id \
                     (pre-pass skipped?)",
                )
            })?;
            d.set("Sound", Object::Reference(snd));
            // /Name — defaults to /Speaker per Table 185.
            let icon_name = icon.clone().unwrap_or_else(|| "Speaker".into());
            d.set("Name", Object::Name(icon_name));
        }
        AnnotationKind::PrinterMark { mark_name } => {
            // §12.5.6.20 Table 362. Two `/Type`-style markers are
            // associated with a PrinterMark dictionary: the outer
            // `/Type /Annot` (§12.5.2 Table 164, already set above)
            // identifies the dictionary as an annotation, and the
            // `/Subtype /PrinterMark` set here selects the §12.5.6.20
            // sub-kind. Table 362 lists a *second* `/Type
            // /PrinterMark` slot on the dict alongside `/Subtype`; in
            // practice no producer emits both because the §12.5.2
            // `/Type /Annot` already designates the dictionary as an
            // annotation and `/Subtype /PrinterMark` distinguishes it
            // — the round-215 reader's `find_entry(annot, "MN")` lookup
            // is the wire contract we round-trip, so we omit the
            // redundant `/Type /PrinterMark` Table-362 slot and emit
            // only `/Subtype`.
            d.set("Subtype", Object::Name("PrinterMark".into()));
            // /MN — optional mark-name Name (`ColorBar`,
            // `RegistrationTarget`, `CutMark`, `PageInformation`, …).
            // When `None` the entry is omitted so the round-215
            // reader's `match find_entry(annot, "MN")` falls into the
            // `_ => None` branch — the absent → None contract.
            if let Some(name) = mark_name {
                d.set("MN", Object::Name(name.clone()));
            }
        }
        AnnotationKind::Watermark { fixed_print } => {
            // §12.5.6.22 Table 190.
            d.set("Subtype", Object::Name("Watermark".into()));
            // /FixedPrint — optional inline sub-dict (§12.5.6.22
            // Table 191). Per Table 190 the absence of the entry means
            // the watermark renders without media-relative geometry —
            // a None here therefore leaves /FixedPrint off the
            // annotation dict.
            if let Some(fp) = fixed_print {
                d.set("FixedPrint", Object::Dict(build_fixed_print_dict(fp)));
            }
        }
    }

    Ok(d)
}

/// Build the inline `/FixedPrint` sub-dict (§12.5.6.22 Table 191) for a
/// [`AnnotationKind::Watermark`]. Default-value omissions per Table 191:
/// * `/Matrix` is omitted when the caller passes `None` (Table 191
///   default identity); a `Some([1,0,0,1,0,0])` is treated as an
///   explicit identity opt-in and the entry is still emitted, since the
///   caller distinguished "absent" from "explicitly identity".
/// * `/H` is omitted when the caller passes `None` (Table 191 default
///   `0`); a `Some(0.0)` is emitted verbatim.
/// * `/V` is omitted when the caller passes `None` (Table 191 default
///   `0`); a `Some(0.0)` is emitted verbatim.
///
/// The omissions keep a write-then-read cycle through the round-204
/// `read_pdf_annotations` enumerator on the same "absent → default"
/// branch the reader uses for producer files that left the defaults
/// implicit. The `/Type /FixedPrint` marker is required per Table 191
/// and always emitted.
fn build_fixed_print_dict(fp: &FixedPrintSpec) -> Dict {
    let mut d = Dict::new().with("Type", Object::Name("FixedPrint".into()));
    if let Some(m) = fp.matrix {
        d.set(
            "Matrix",
            Object::Array(m.iter().map(|v| Object::Real(*v as f64)).collect()),
        );
    }
    if let Some(h) = fp.h {
        d.set("H", Object::Real(h as f64));
    }
    if let Some(v) = fp.v {
        d.set("V", Object::Real(v as f64));
    }
    d
}

/// Emit one `/Type /Sound` stream object per §13.3 Table 294 carrying
/// the raw sample bytes plus the `/R` sample rate, `/C` channels,
/// `/B` bits per sample, and `/E` encoding metadata. Returns the
/// stream's indirect-reference id for the caller to wire onto the
/// annotation dict's `/Sound` entry.
///
/// Default-value omissions per Table 294:
/// * `/C` is omitted when it equals 1.
/// * `/B` is omitted when it equals 8.
/// * `/E` is omitted on [`SoundEncoding::Raw`] (the spec default).
///
/// The omissions keep a write-then-read cycle through the round-209
/// `read_pdf_annotations` enumerator on the same "absent → default"
/// branch the reader uses for producer files that left the defaults
/// implicit.
fn emit_sound_stream(
    doc: &mut Document,
    sampling_rate: f32,
    channels: u32,
    bits_per_sample: u32,
    encoding: SoundEncoding,
    sound_samples: Vec<u8>,
) -> ObjectId {
    let mut dict = Dict::new()
        .with("Type", Object::Name("Sound".into()))
        // /R is required per Table 294 — always emitted.
        .with("R", Object::Real(sampling_rate as f64));
    // /C default is 1 ⇒ omit when it equals the default.
    if channels != 1 {
        dict.set("C", Object::Integer(channels as i64));
    }
    // /B default is 8 ⇒ omit when it equals the default.
    if bits_per_sample != 8 {
        dict.set("B", Object::Integer(bits_per_sample as i64));
    }
    // /E default is /Raw ⇒ omit when it equals the default.
    if let Some(name) = encoding.as_name() {
        dict.set("E", Object::Name(name.into()));
    }
    doc.add(Object::Stream(crate::objects::Stream::new(
        dict,
        sound_samples,
    )))
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
    fn caret_symbol_default_is_none_and_omits_sy_entry() {
        // §12.5.6.11 Table 180.
        assert_eq!(CaretSymbol::default(), CaretSymbol::None);
        assert!(CaretSymbol::None.as_name().is_none());
        assert_eq!(CaretSymbol::Paragraph.as_name(), Some("P"));
    }

    #[test]
    fn caret_writer_emits_subtype_and_omits_default_fields() {
        // §12.5.6.11 Table 180 — bare-caret form: no /RD, no /Sy.
        let annot = Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 50.0, 60.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Caret {
                rect_diffs: None,
                symbol: CaretSymbol::None,
            },
        };
        let d = build_annotation_dict(&annot, ObjectId::new(3), &[ObjectId::new(99)], None, None)
            .unwrap();
        let subtype = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Subtype")
            .expect("/Subtype emitted");
        assert!(matches!(&subtype.1, Object::Name(n) if n == "Caret"));
        // Default per Table 180 — /Sy absent.
        assert!(!d.entries().iter().any(|(k, _)| k == "Sy"));
        // No inset supplied — /RD absent.
        assert!(!d.entries().iter().any(|(k, _)| k == "RD"));
    }

    #[test]
    fn caret_writer_emits_sy_p_when_paragraph_set() {
        let annot = Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 50.0, 60.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Caret {
                rect_diffs: Some([1.0, 2.0, 3.0, 4.0]),
                symbol: CaretSymbol::Paragraph,
            },
        };
        let d = build_annotation_dict(&annot, ObjectId::new(3), &[ObjectId::new(99)], None, None)
            .unwrap();
        let sy = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Sy")
            .expect("/Sy emitted");
        assert!(matches!(&sy.1, Object::Name(n) if n == "P"));
        let rd = d
            .entries()
            .iter()
            .find(|(k, _)| k == "RD")
            .expect("/RD emitted");
        match &rd.1 {
            Object::Array(items) => assert_eq!(items.len(), 4),
            _ => panic!("/RD should be a four-real array"),
        }
    }

    #[test]
    fn caret_validation_rejects_negative_rd() {
        // §12.5.6.11 Table 180 — each component shall be ≥ 0.
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Caret {
                rect_diffs: Some([-1.0, 0.0, 0.0, 0.0]),
                symbol: CaretSymbol::None,
            },
        }];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("/RD"), "error mentions /RD: {msg}");
    }

    #[test]
    fn caret_validation_rejects_inset_exceeding_rect() {
        // §12.5.6.11 Table 180 — left+right and top+bottom insets
        // must each fit inside the outer /Rect.
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 10.0, 10.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Caret {
                rect_diffs: Some([6.0, 6.0, 6.0, 6.0]),
                symbol: CaretSymbol::None,
            },
        }];
        assert!(validate_annotations(&annots, 1).is_err());
    }

    #[test]
    fn popup_writer_resolves_parent_index_to_pre_allocated_id() {
        // §12.5.6.14 Table 183 — the writer wires /Parent to the
        // indirect reference of the annotation at index `parent_index`
        // in the same slice.
        let annot = Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 110.0, 60.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Popup {
                parent_index: Some(0),
                open: true,
            },
        };
        // Simulate the pass-1 allocations: ids 41 + 42 reserved for
        // a two-annotation batch where this Popup is the second
        // (index 1) and the parent markup is at index 0 ⇒ /Parent
        // should resolve to id 41.
        let pre_allocated = vec![ObjectId::new(41), ObjectId::new(42)];
        let d =
            build_annotation_dict(&annot, ObjectId::new(3), &pre_allocated, None, None).unwrap();
        let parent = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Parent")
            .expect("/Parent emitted");
        match &parent.1 {
            Object::Reference(id) => assert_eq!(id.number, 41),
            _ => panic!("/Parent should be an indirect reference"),
        }
        // /Open true ⇒ entry emitted.
        let open = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Open")
            .expect("/Open emitted");
        assert!(matches!(&open.1, Object::Bool(true)));
    }

    #[test]
    fn popup_writer_omits_open_when_default_false() {
        // §12.5.6.14 Table 183 — /Open default is false ⇒ writer
        // omits the entry on `false`.
        let annot = Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 110.0, 60.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Popup {
                parent_index: None,
                open: false,
            },
        };
        let d = build_annotation_dict(&annot, ObjectId::new(3), &[ObjectId::new(99)], None, None)
            .unwrap();
        assert!(!d.entries().iter().any(|(k, _)| k == "Open"));
        // No parent supplied ⇒ /Parent absent (the tolerant-reader
        // contract surfaces the dict; the spec considers this
        // malformed but permitted on the read side).
        assert!(!d.entries().iter().any(|(k, _)| k == "Parent"));
    }

    #[test]
    fn popup_validation_rejects_out_of_range_parent_index() {
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Popup {
                parent_index: Some(42),
                open: false,
            },
        }];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("parent_index"), "error mentions index: {msg}");
    }

    #[test]
    fn popup_validation_rejects_self_parent() {
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Popup {
                parent_index: Some(0),
                open: false,
            },
        }];
        assert!(validate_annotations(&annots, 1).is_err());
    }

    #[test]
    fn popup_validation_rejects_popup_parent_pointing_at_popup() {
        // §12.5.6.14 — parent must be a markup annotation, not
        // another Popup.
        let annots = vec![
            Annotation {
                source_page_index: 0,
                rect: [0.0, 0.0, 100.0, 100.0],
                author: None,
                modified: None,
                flags: None,
                colour: None,
                border: None,
                kind: AnnotationKind::Popup {
                    parent_index: None,
                    open: false,
                },
            },
            Annotation {
                source_page_index: 0,
                rect: [0.0, 0.0, 100.0, 100.0],
                author: None,
                modified: None,
                flags: None,
                colour: None,
                border: None,
                kind: AnnotationKind::Popup {
                    parent_index: Some(0),
                    open: false,
                },
            },
        ];
        assert!(validate_annotations(&annots, 1).is_err());
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
        let d = build_annotation_dict(&annot, ObjectId::new(3), &[ObjectId::new(99)], None, None)
            .unwrap();
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

    // ────────────────────────────────────────────────────────────────
    // §12.5.6.16 + §13.3 Sound annotation (Table 185 + Table 294).
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn sound_encoding_default_is_raw_and_omits_e_entry() {
        // §13.3 Table 294 — /E default is /Raw.
        assert_eq!(SoundEncoding::default(), SoundEncoding::Raw);
        assert!(SoundEncoding::Raw.as_name().is_none());
        assert_eq!(SoundEncoding::Signed.as_name(), Some("Signed"));
        assert_eq!(SoundEncoding::MuLaw.as_name(), Some("muLaw"));
        assert_eq!(SoundEncoding::ALaw.as_name(), Some("ALaw"));
    }

    #[test]
    fn sound_writer_emits_subtype_and_name_default_speaker() {
        // §12.5.6.16 Table 185 — bare Sound annotation: /Sound stream
        // ref (synthesised here with a dummy id since the unit test
        // skips the pre-pass) plus /Name defaulting to /Speaker.
        let annot = Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 30.0, 40.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Sound {
                icon: None,
                sampling_rate: 22050.0,
                channels: 1,
                bits_per_sample: 8,
                encoding: SoundEncoding::Raw,
                sound_samples: vec![0x80; 64],
            },
        };
        let d = build_annotation_dict(
            &annot,
            ObjectId::new(3),
            &[ObjectId::new(99)],
            None,
            Some(ObjectId::new(77)),
        )
        .unwrap();
        let subtype = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Subtype")
            .expect("/Subtype emitted");
        assert!(matches!(&subtype.1, Object::Name(n) if n == "Sound"));
        let snd = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Sound")
            .expect("/Sound emitted");
        assert!(matches!(&snd.1, Object::Reference(id) if id.number == 77));
        let name = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Name")
            .expect("/Name emitted");
        assert!(matches!(&name.1, Object::Name(n) if n == "Speaker"));
    }

    #[test]
    fn sound_writer_emits_custom_icon_when_supplied() {
        // §12.5.6.16 Table 185 — /Name /Mic for a microphone-recorded
        // sound annotation.
        let annot = Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 30.0, 40.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Sound {
                icon: Some("Mic".into()),
                sampling_rate: 8000.0,
                channels: 1,
                bits_per_sample: 8,
                encoding: SoundEncoding::MuLaw,
                sound_samples: vec![0xFF; 16],
            },
        };
        let d = build_annotation_dict(
            &annot,
            ObjectId::new(3),
            &[ObjectId::new(99)],
            None,
            Some(ObjectId::new(42)),
        )
        .unwrap();
        let name = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Name")
            .expect("/Name emitted");
        assert!(matches!(&name.1, Object::Name(n) if n == "Mic"));
    }

    #[test]
    fn sound_writer_errors_when_sound_stream_id_missing() {
        // Defensive guard — a pre-pass that skipped allocating the
        // sound stream must surface a hard error rather than emit a
        // dict whose /Sound entry points at nothing.
        let annot = Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 30.0, 40.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Sound {
                icon: None,
                sampling_rate: 8000.0,
                channels: 1,
                bits_per_sample: 8,
                encoding: SoundEncoding::Raw,
                sound_samples: vec![0; 4],
            },
        };
        let res = build_annotation_dict(&annot, ObjectId::new(3), &[ObjectId::new(99)], None, None);
        assert!(res.is_err());
    }

    #[test]
    fn sound_validation_rejects_zero_sampling_rate() {
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Sound {
                icon: None,
                sampling_rate: 0.0,
                channels: 1,
                bits_per_sample: 8,
                encoding: SoundEncoding::Raw,
                sound_samples: vec![0; 4],
            },
        }];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("sampling_rate"), "error mentions rate: {msg}");
    }

    #[test]
    fn sound_validation_rejects_zero_channels() {
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Sound {
                icon: None,
                sampling_rate: 8000.0,
                channels: 0,
                bits_per_sample: 8,
                encoding: SoundEncoding::Raw,
                sound_samples: vec![0; 4],
            },
        }];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("channels"), "error mentions channels: {msg}");
    }

    #[test]
    fn sound_validation_rejects_zero_bits_per_sample() {
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Sound {
                icon: None,
                sampling_rate: 8000.0,
                channels: 1,
                bits_per_sample: 0,
                encoding: SoundEncoding::Raw,
                sound_samples: vec![0; 4],
            },
        }];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("bits_per_sample"),
            "error mentions bits: {msg}"
        );
    }

    #[test]
    fn sound_validation_rejects_empty_sample_buffer() {
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Sound {
                icon: None,
                sampling_rate: 8000.0,
                channels: 1,
                bits_per_sample: 8,
                encoding: SoundEncoding::Raw,
                sound_samples: Vec::new(),
            },
        }];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("sound_samples"),
            "error mentions buffer: {msg}"
        );
    }

    #[test]
    fn sound_validation_rejects_negative_sampling_rate() {
        // §13.3 /R is samples/sec — must be positive.
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Sound {
                icon: None,
                sampling_rate: -22050.0,
                channels: 1,
                bits_per_sample: 8,
                encoding: SoundEncoding::Raw,
                sound_samples: vec![0; 4],
            },
        }];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("sampling_rate"), "error mentions rate: {msg}");
    }

    // ────────────────────────────────────────────────────────────────
    // Round 252 — §12.5.6.22 Watermark (Table 190) + §12.5.6.22
    // FixedPrint sub-dict (Table 191).
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn fixed_print_spec_default_is_all_absent() {
        // The default-constructed FixedPrintSpec has every per-field
        // override set to None so the writer emits only the
        // `/Type /FixedPrint` marker entry.
        let fp = FixedPrintSpec::default();
        assert!(fp.matrix.is_none());
        assert!(fp.h.is_none());
        assert!(fp.v.is_none());
        let d = build_fixed_print_dict(&fp);
        // Exactly one entry — `/Type /FixedPrint`.
        assert_eq!(d.entries().len(), 1);
        let (k, v) = &d.entries()[0];
        assert_eq!(k, "Type");
        assert!(matches!(v, Object::Name(n) if n == "FixedPrint"));
    }

    #[test]
    fn watermark_writer_emits_subtype_and_omits_fixed_print_when_none() {
        // §12.5.6.22 Table 190 — bare Watermark annotation with no
        // /FixedPrint sub-dict. Per Table 190 the entry "shall be
        // drawn without any special consideration for the dimensions
        // of the target media" — surface that as the entry being
        // absent.
        let annot = Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 30.0, 40.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Watermark { fixed_print: None },
        };
        let d = build_annotation_dict(&annot, ObjectId::new(3), &[ObjectId::new(99)], None, None)
            .unwrap();
        let subtype = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Subtype")
            .expect("/Subtype emitted");
        assert!(matches!(&subtype.1, Object::Name(n) if n == "Watermark"));
        assert!(
            d.entries().iter().all(|(k, _)| k != "FixedPrint"),
            "/FixedPrint should be omitted when fixed_print is None",
        );
    }

    #[test]
    fn watermark_writer_emits_fixed_print_with_overrides() {
        // §12.5.6.22 Table 191 — explicit /Matrix + /H + /V overrides
        // round-trip into a /FixedPrint sub-dict where each entry
        // appears verbatim.
        let annot = Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 30.0, 40.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Watermark {
                fixed_print: Some(FixedPrintSpec {
                    matrix: Some([2.0, 0.0, 0.0, 2.0, 36.0, 72.0]),
                    h: Some(0.5),
                    v: Some(0.25),
                }),
            },
        };
        let d = build_annotation_dict(&annot, ObjectId::new(3), &[ObjectId::new(99)], None, None)
            .unwrap();
        let fp_obj = d
            .entries()
            .iter()
            .find(|(k, _)| k == "FixedPrint")
            .map(|(_, v)| v)
            .expect("/FixedPrint emitted");
        let Object::Dict(fp) = fp_obj else {
            panic!("/FixedPrint should be an inline dict, got {fp_obj:?}");
        };
        // /Type /FixedPrint marker required per Table 191.
        let t = fp
            .entries()
            .iter()
            .find(|(k, _)| k == "Type")
            .expect("/Type emitted");
        assert!(matches!(&t.1, Object::Name(n) if n == "FixedPrint"));
        // /Matrix six-real array.
        let m = fp
            .entries()
            .iter()
            .find(|(k, _)| k == "Matrix")
            .expect("/Matrix emitted");
        let Object::Array(items) = &m.1 else {
            panic!("/Matrix should be an array, got {:?}", m.1);
        };
        assert_eq!(items.len(), 6);
        // /H + /V emitted as reals.
        assert!(fp
            .entries()
            .iter()
            .any(|(k, v)| k == "H" && matches!(v, Object::Real(r) if (*r - 0.5).abs() < 1e-6)));
        assert!(fp
            .entries()
            .iter()
            .any(|(k, v)| k == "V" && matches!(v, Object::Real(r) if (*r - 0.25).abs() < 1e-6)));
    }

    #[test]
    fn watermark_writer_minimum_fixed_print_emits_type_marker_only() {
        // §12.5.6.22 Table 191 — a Some(FixedPrintSpec::default()) is
        // the minimal opt-in to media-relative rendering and emits
        // exactly the `/Type /FixedPrint` marker (no /Matrix, /H, or
        // /V overrides).
        let annot = Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 30.0, 40.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Watermark {
                fixed_print: Some(FixedPrintSpec::default()),
            },
        };
        let d = build_annotation_dict(&annot, ObjectId::new(3), &[ObjectId::new(99)], None, None)
            .unwrap();
        let fp_obj = d
            .entries()
            .iter()
            .find(|(k, _)| k == "FixedPrint")
            .map(|(_, v)| v)
            .expect("/FixedPrint emitted");
        let Object::Dict(fp) = fp_obj else {
            panic!("/FixedPrint should be an inline dict, got {fp_obj:?}");
        };
        assert_eq!(fp.entries().len(), 1);
        assert!(fp
            .entries()
            .iter()
            .all(|(k, _)| !matches!(k.as_str(), "Matrix" | "H" | "V")));
    }

    #[test]
    fn watermark_validation_rejects_negative_h() {
        // Table 191 "negative values should not be used" — surface as
        // a writer reject.
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Watermark {
                fixed_print: Some(FixedPrintSpec {
                    matrix: None,
                    h: Some(-0.1),
                    v: None,
                }),
            },
        }];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("/H") && msg.contains("non-negative"),
            "error mentions /H non-negative requirement: {msg}",
        );
    }

    #[test]
    fn watermark_validation_rejects_negative_v() {
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Watermark {
                fixed_print: Some(FixedPrintSpec {
                    matrix: None,
                    h: None,
                    v: Some(-1.0),
                }),
            },
        }];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("/V") && msg.contains("non-negative"),
            "error mentions /V non-negative requirement: {msg}",
        );
    }

    #[test]
    fn watermark_validation_rejects_non_finite_matrix() {
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Watermark {
                fixed_print: Some(FixedPrintSpec {
                    matrix: Some([1.0, 0.0, 0.0, f32::NAN, 0.0, 0.0]),
                    h: None,
                    v: None,
                }),
            },
        }];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("/Matrix") && msg.contains("finite"),
            "error mentions /Matrix finite requirement: {msg}",
        );
    }

    #[test]
    fn watermark_validation_rejects_non_finite_h() {
        let annots = vec![Annotation {
            source_page_index: 0,
            rect: [0.0, 0.0, 100.0, 100.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::Watermark {
                fixed_print: Some(FixedPrintSpec {
                    matrix: None,
                    h: Some(f32::INFINITY),
                    v: None,
                }),
            },
        }];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("/H") && msg.contains("finite"),
            "error mentions /H finite requirement: {msg}",
        );
    }

    // ────────────────────────────────────────────────────────────────
    // Round 257 — §12.5.6.20 PrinterMark (Table 362).
    // ────────────────────────────────────────────────────────────────

    fn printer_mark_annot(mark_name: Option<&str>) -> Annotation {
        Annotation {
            source_page_index: 0,
            rect: [10.0, 20.0, 30.0, 40.0],
            author: None,
            modified: None,
            flags: None,
            colour: None,
            border: None,
            kind: AnnotationKind::PrinterMark {
                mark_name: mark_name.map(str::to_string),
            },
        }
    }

    #[test]
    fn printer_mark_writer_emits_subtype_and_omits_mn_when_none() {
        // §12.5.6.20 Table 362 — bare PrinterMark annotation with no
        // /MN entry. The round-215 reader's `match find_entry(annot,
        // "MN")` lookup falls into `_ => None` when /MN is absent;
        // emit the absent-equals-None shape.
        let annot = printer_mark_annot(None);
        let d = build_annotation_dict(&annot, ObjectId::new(3), &[ObjectId::new(99)], None, None)
            .unwrap();
        let subtype = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Subtype")
            .expect("/Subtype emitted");
        assert!(matches!(&subtype.1, Object::Name(n) if n == "PrinterMark"));
        assert!(
            d.entries().iter().all(|(k, _)| k != "MN"),
            "/MN should be omitted when mark_name is None",
        );
        // §12.5.6.20 Table 362's redundant `/Type /PrinterMark` slot
        // is intentionally NOT emitted — the §12.5.2 `/Type /Annot`
        // already designates the dictionary as an annotation, and the
        // /Subtype lookup is what every observed producer + the
        // round-215 reader rely on.
        let type_entries: Vec<&Object> = d
            .entries()
            .iter()
            .filter_map(|(k, v)| if k == "Type" { Some(v) } else { None })
            .collect();
        assert_eq!(type_entries.len(), 1, "exactly one /Type entry");
        assert!(matches!(type_entries[0], Object::Name(n) if n == "Annot"));
    }

    #[test]
    fn printer_mark_writer_emits_mn_when_some() {
        // §12.5.6.20 Table 362 — `/MN /ColorBar` colour-bar variant.
        let annot = printer_mark_annot(Some("ColorBar"));
        let d = build_annotation_dict(&annot, ObjectId::new(3), &[ObjectId::new(99)], None, None)
            .unwrap();
        let mn = d
            .entries()
            .iter()
            .find(|(k, _)| k == "MN")
            .expect("/MN emitted");
        assert!(matches!(&mn.1, Object::Name(n) if n == "ColorBar"));
    }

    #[test]
    fn printer_mark_writer_passes_arbitrary_mark_name_through_verbatim() {
        // Table 362 lists no closed taxonomy — pass any caller-supplied
        // Name through unchanged so a colour-management tool can match
        // its own private mark vocabulary.
        let annot = printer_mark_annot(Some("MyProductionTool_CornerCalibrator"));
        let d = build_annotation_dict(&annot, ObjectId::new(3), &[ObjectId::new(99)], None, None)
            .unwrap();
        let mn = d
            .entries()
            .iter()
            .find(|(k, _)| k == "MN")
            .expect("/MN emitted");
        assert!(
            matches!(&mn.1, Object::Name(n) if n == "MyProductionTool_CornerCalibrator"),
            "/MN passes any Name through verbatim",
        );
    }

    #[test]
    fn printer_mark_validation_rejects_empty_mark_name() {
        // §7.3.5 + §12.5.6.20 Table 362 — a /MN Name token must be at
        // least one byte; an empty Some("") would serialise as a bare
        // `/` token that round-trips as the absent-entry case.
        let annots = vec![printer_mark_annot(Some(""))];
        let err = validate_annotations(&annots, 1).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("/PrinterMark") && msg.contains("/MN"),
            "error mentions /PrinterMark /MN: {msg}",
        );
        assert!(
            msg.contains("non-empty"),
            "error mentions non-empty requirement: {msg}",
        );
    }

    #[test]
    fn printer_mark_validation_accepts_none_and_non_empty_some() {
        // The validation guard fires only on `Some(empty)`. Both
        // `None` and `Some("CutMark")` pass.
        let annots = vec![
            printer_mark_annot(None),
            printer_mark_annot(Some("CutMark")),
            printer_mark_annot(Some("RegistrationTarget")),
            printer_mark_annot(Some("PageInformation")),
        ];
        validate_annotations(&annots, 1).expect("all four PrinterMark variants validate");
    }
}
