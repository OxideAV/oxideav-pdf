//! Round-26 — generic annotation reader (ISO 32000-1 §12.5).
//!
//! Walks every page's `/Annots` array and surfaces each entry as a
//! [`PdfAnnotation`] carrying the union of common Table 164 fields
//! (`/Rect`, `/Contents`, `/NM`, `/M`, `/F`, `/Border`, `/C` colour)
//! plus the per-subtype Table 169..209 entries this round handles:
//!
//! * **`/Text`** (§12.5.6.4 Table 172) — sticky-note: `/Open`,
//!   `/Name` icon, `/State`, `/StateModel`.
//! * **`/FreeText`** (§12.5.6.6 Table 174) — in-page text box: `/DA`
//!   default appearance string, `/Q` justification, `/RC` rich
//!   content, `/IT` intent.
//! * **`/Stamp`** (§12.5.6.13 Table 184) — rubber-stamp: `/Name` icon
//!   identifier (`Approved`, `Confidential`, etc.).
//! * **`/Highlight`** / **`/Underline`** / **`/Squiggly`** /
//!   **`/StrikeOut`** (§12.5.6.10 Table 179) — text-markup: `/QuadPoints`.
//! * **`/Square`** / **`/Circle`** (§12.5.6.8 Table 177) — geometry:
//!   `/IC` interior colour, `/RD` rectangle differences.
//! * **`/Link`** (§12.5.6.5 Table 173) — re-uses [`crate::reader::link`]'s
//!   target decoder so callers get the same go-to / URI dispatch.
//! * **`/Widget`** (§12.5.6.19 Table 188) — form-field hosting; field
//!   metadata (FT, T, V) is surfaced when present.
//! * **`/Line`** (§12.5.6.7 Table 175, round 197) — straight-line
//!   markup: `/L` two-endpoint coordinates, `/LE` line-ending
//!   styles, `/IC` interior colour, `/LL` / `/LLE` / `/LLO` leader
//!   geometry, `/Cap` caption flag, `/IT` intent.
//! * **`/Polygon`** / **`/PolyLine`** (§12.5.6.9 Table 178, round 197)
//!   — `/Vertices` 2N reals, `/LE` line endings (PolyLine only per
//!   spec but surfaced uniformly), `/IC`, `/IT` intent
//!   (`PolygonCloud` / `PolyLineDimension` / `PolygonDimension`).
//! * **`/Ink`** (§12.5.6.13 Table 182, round 197) — `/InkList` of
//!   strokes, each one a flat `[x0 y0 x1 y1 …]` array (round-trips
//!   the round-32 `write_pdf_with_annotations` Ink writer).
//! * **`/Caret`** (§12.5.6.11 Table 180, round 197) — `/RD`
//!   rectangle differences, `/Sy` paragraph-symbol (`P` / `None`).
//! * **`/Popup`** (§12.5.6.14 Table 183, round 197) — `/Open` flag
//!   plus the parent annotation reference (`/Parent`) preserved as
//!   an [`ObjectId`] so callers can correlate a pop-up with its
//!   markup parent.
//! * **`/FileAttachment`** (§12.5.6.15 Table 184, round 197) —
//!   `/Name` icon (`GraphPushPin` / `PaperclipTag` / `PushPin`
//!   default) and the referenced `/FS` filespec's user-visible name
//!   resolved through the same `/UF`-preferred / `/F` fallback path
//!   the round-33 attachment reader uses. Round-trips the round-33
//!   `write_pdf_with_attachments` annotation marker.
//! * **`/Watermark`** (§12.5.6.22 Table 190, round 204) — fixed-print
//!   positioning surfaced through [`FixedPrint`] (Table 191): the
//!   `/Matrix` affine + `/H` / `/V` media-relative percentages that
//!   make a watermark render at the same absolute position on every
//!   printed sheet regardless of the destination media size.
//! * **`/Redact`** (§12.5.6.23 Table 192, round 204) — non-destructive
//!   redaction marker: `/QuadPoints` content region, `/IC` interior
//!   fill, `/RO` overlay-appearance Form XObject (preserved as an
//!   `ObjectId`), `/OverlayText` + `/Repeat` + `/DA` + `/Q` overlay
//!   text. Round-204 enumerates these for privacy-audit consumers; the
//!   destructive content-removal step described by §12.5.6.23 NOTE is
//!   a separate higher-level pass and is *not* applied by the reader.
//! * **`/Sound`** (§12.5.6.16 Table 185, round 209) — sound annotation:
//!   the required `/Sound` stream object preserved as an [`ObjectId`]
//!   (so callers can re-resolve the §13.3 sound object themselves —
//!   playback is out of scope for this crate, which doesn't bundle an
//!   audio decoder), plus the `/Name` icon (`Speaker` default per
//!   Table 185, or `Mic`, or an authoring-tool extension).
//! * **`/Movie`** (§12.5.6.17 Table 186, round 209) — movie annotation:
//!   `/T` title (used by §12.6.4.9 movie actions to look up the
//!   annotation), the required `/Movie` dictionary preserved as an
//!   [`ObjectId`] when it's an indirect reference (the §13.4 movie
//!   metadata itself is out of scope — this crate doesn't decode video),
//!   and `/A` collapsed to a [`MovieActivation`] tri-state that captures
//!   the boolean shorthand and the optional movie-activation dict.
//! * **`/Screen`** (§12.5.6.18 Table 187, round 209) — screen
//!   annotation: `/T` title, plus the appearance-characteristics
//!   `/MK` dictionary, `/A` action, and `/AA` additional-actions
//!   indirect references preserved as [`ObjectId`]s so callers can
//!   re-resolve them through the reader. Screen annotations exist to
//!   anchor §12.6.4.13 rendition actions to a region of the page;
//!   round-209 surfaces enough metadata to enumerate them without
//!   pulling rendition-action plumbing into this crate.
//! * **`/PrinterMark`** (§12.5.6.20 Table 362, round 215) — production
//!   printer's mark (PDF 1.4 — registration target, colour bar, cut
//!   mark, page-information bar). The `/MN` mark-name Name is
//!   surfaced verbatim; the actual graphics live in the form-XObject
//!   appearance stream referenced from `/AP /N` and stay routed
//!   through the §8.10 Form XObject walker.
//! * **`/TrapNet`** (§12.5.6.21 Table 366, round 215) — page-level
//!   trap-network annotation (PDF 1.3). Per spec there is at most one
//!   per page and it must be the last `/Annots` entry. Surfaces
//!   `/LastModified` (when the producer used the date-watermark form)
//!   *or* the `/Version` + `/AnnotStates` pair (when it used the
//!   object-tracking form), plus the optional `/FontFauxing` array of
//!   substituted-font references — enough for a trap-network
//!   regenerator to decide whether the cached traps are still valid.
//! * **`/3D`** (§13.6.2 Table 298, round 220) — 3D artwork annotation
//!   (PDF 1.6). Surfaces the `/3DD` artwork reference (the §13.6.3 U3D
//!   / PRC stream or §13.6.3.3 reference dictionary, preserved as
//!   [`ObjectId`] — this crate does not decode 3D artwork), the `/3DV`
//!   initial-view selector collapsed into a [`ThreeDViewSelector`]
//!   four-shape union (view-dict ref / `/VA` index / `/IN`-matching
//!   string / `F` / `L` / `D` symbolic), the `/3DA` activation
//!   dictionary surfaced through [`ThreeDActivation`] (Table 299:
//!   `/A`, `/AIS`, `/D`, `/DIS`, plus the PDF 1.7 `/TB` and `/NP`
//!   toolbar/navigation-panel flags), the `/3DI` interactive-use flag
//!   (default `true` per Table 298), and the `/3DB` 3D view box
//!   rectangle (default per spec is `/Rect` re-expressed in the
//!   annotation's target coordinate system — the caller computes that
//!   from the outer `PdfAnnotation::rect` field when the entry is
//!   absent).
//!
//! Unknown subtypes still come back as [`AnnotationKind::Other`] with
//! the raw `/Subtype` name — callers walking forensic / archival PDFs
//! get a complete enumeration even for the long tail (RichMedia,
//! Projection, …).
//!
//! Pages without `/Annots` contribute zero entries; a malformed annot
//! dict is skipped (best-effort enumeration matches the round-21
//! `/Sig` reader's contract).

use std::collections::HashMap;

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::reader::document::DocumentReader;
use crate::reader::link::PdfLinkTarget;
use crate::reader::outline::build_page_index_map;

/// One annotation entry surfaced by [`annotations`].
///
/// The fields are the cross-subtype intersection; per-subtype detail
/// hangs off [`Self::kind`].
#[derive(Debug, Clone)]
pub struct PdfAnnotation {
    /// 0-based page index — which page in DFS order carries this
    /// annotation in its `/Annots` array.
    pub source_page_index: usize,
    /// `/Rect` — annotation rectangle in default user space (PDF
    /// coordinates, origin bottom-left).
    pub rect: [f32; 4],
    /// `/Contents` — text content (description / title for sticky
    /// notes, raw text for FreeText).
    pub contents: Option<String>,
    /// `/NM` — annotation name (UID per Table 164). Optional; many
    /// authoring tools omit it.
    pub name: Option<String>,
    /// `/M` — last-modified date (raw PDF date string, no parse).
    pub modified: Option<String>,
    /// `/F` — annotation flag word (Table 167). Bit 0 = Invisible,
    /// bit 1 = Hidden, bit 2 = Print, bit 3 = NoZoom, bit 4 = NoRotate,
    /// bit 5 = NoView, bit 6 = ReadOnly, bit 7 = Locked, bit 8 =
    /// ToggleNoView, bit 9 = LockedContents.
    pub flags: u32,
    /// `/C` — colour: 0/1/3/4 numbers (Transparent / Gray / RGB / CMYK).
    pub colour: Option<Vec<f32>>,
    /// `/Border` — `[hr vr w]` or `[hr vr w dash]`. Most PDFs ship the
    /// 3-element variant; round-26 surfaces it untouched.
    pub border: Option<Vec<f32>>,
    /// `/AP` — §12.5.5 appearance-dictionary summary (Table 168).
    /// `None` when the annotation carries no appearance dictionary.
    pub appearance: Option<AnnotationAppearance>,
    /// `/AS` — the appearance state selecting the applicable stream
    /// from an appearance subdictionary (required by Table 164 when
    /// `/AP` contains one or more subdictionaries).
    pub appearance_state: Option<String>,
    /// Per-subtype payload.
    pub kind: AnnotationKind,
}

/// Summary of an annotation's §12.5.5 appearance dictionary
/// (Table 168) as surfaced on [`PdfAnnotation::appearance`].
///
/// Each of the three entries (`/N` normal — required, `/R` rollover,
/// `/D` down) is either a single appearance stream or a subdictionary
/// of streams keyed by appearance state; [`Self::states`] is the
/// union of state names across all three (empty when every present
/// entry is a single stream).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnnotationAppearance {
    /// `/N` — normal appearance present (Table 168 requires it, but
    /// the enumeration is tolerant of producers that omit it).
    pub has_normal: bool,
    /// `/R` — rollover appearance present (defaults to `/N` per
    /// Table 168 when absent).
    pub has_rollover: bool,
    /// `/D` — down appearance present (defaults to `/N`).
    pub has_down: bool,
    /// Union of appearance-state names across the `/N` / `/R` / `/D`
    /// subdictionaries, sorted and de-duplicated.
    pub states: Vec<String>,
}

/// Per-subtype annotation payload.
///
/// The `/Subtype` name from §12.5.6 maps to one of these variants;
/// unknown subtypes fall through to [`Self::Other`].
#[derive(Debug, Clone)]
pub enum AnnotationKind {
    /// `/Subtype /Text` — sticky-note (§12.5.6.4 Table 172).
    Text {
        /// `/Open` — true ⇒ pop-up displayed at document open.
        open: bool,
        /// `/Name` — icon identifier (`Comment`, `Note`, `Help`,
        /// `NewParagraph`, `Paragraph`, `Insert`, plus authoring-tool
        /// extensions). Defaults to `Note` per Table 172.
        icon: String,
        /// `/State` + `/StateModel` — review or marked state.
        state: Option<String>,
        state_model: Option<String>,
    },
    /// `/Subtype /FreeText` — in-page text box (§12.5.6.6 Table 174).
    FreeText {
        /// `/DA` default appearance string (a content-stream snippet
        /// per §12.7.3.3 — `/Helv 12 Tf 0 g`-style).
        default_appearance: Option<String>,
        /// `/Q` — quadding (justification): 0 left-justified
        /// (default), 1 centred, 2 right-justified.
        quadding: u8,
        /// `/RC` rich content (XHTML).
        rich_content: Option<String>,
        /// `/IT` intent — `FreeText`, `FreeTextCallout`, `FreeTextTypeWriter`.
        intent: Option<String>,
    },
    /// `/Subtype /Stamp` — rubber-stamp (§12.5.6.13 Table 184).
    Stamp {
        /// `/Name` icon identifier — `Approved`, `Experimental`,
        /// `NotApproved`, `AsIs`, `Expired`, `NotForPublicRelease`,
        /// `Confidential`, `Final`, `Sold`, `Departmental`,
        /// `ForComment`, `TopSecret`, `Draft`, `ForPublicRelease`.
        /// Defaults to `Draft` per Table 184.
        icon: String,
    },
    /// Text-markup family (§12.5.6.10 Table 179).
    TextMarkup {
        /// Which markup variant: `Highlight`, `Underline`, `Squiggly`,
        /// `StrikeOut`.
        variant: TextMarkupVariant,
        /// `/QuadPoints` — 8N reals giving the quads of every region
        /// covered by the markup. PDF 2.0 changed the legal vertex
        /// order; round-26 surfaces the raw list untouched.
        quad_points: Vec<f32>,
    },
    /// `/Subtype /Square` or `/Circle` (§12.5.6.8 Table 177).
    Geometry {
        /// `Square` ⇒ true; `Circle` ⇒ false.
        is_square: bool,
        /// `/IC` interior colour — same shape as outer `/C`.
        interior_colour: Option<Vec<f32>>,
        /// `/RD` rectangle differences — `[left top right bottom]`
        /// inset of the geometric figure inside `/Rect`. Optional.
        rect_diffs: Option<[f32; 4]>,
    },
    /// `/Subtype /Link` — go-to / URI link (§12.5.6.5 Table 173).
    /// Target decoded the same way [`crate::reader::link`] does it.
    Link { target: Option<PdfLinkTarget> },
    /// `/Subtype /Widget` — interactive form widget (§12.5.6.19
    /// Table 188 + §12.7.4 Table 220 field-shared keys). Round-26
    /// surfaces the field-trio `(field_type, field_name, value)`
    /// when the widget dictionary is the field dictionary itself
    /// (the most common shape).
    Widget {
        /// `/FT` — field type Name (`Btn`, `Tx`, `Ch`, `Sig`).
        field_type: Option<String>,
        /// `/T` — partial field name.
        field_name: Option<String>,
        /// `/V` — current value text (Names + strings collapse to a
        /// String form; `null` ⇒ `None`).
        value: Option<String>,
    },
    /// `/Subtype /Line` — straight-line markup (§12.5.6.7 Table 175,
    /// round 197). Two-endpoint line on the page; the `Rect` field
    /// is the bounding box, the `L` endpoints carry the line itself.
    Line {
        /// `/L` — `[x1 y1 x2 y2]` endpoints in default user space.
        /// Required per Table 175.
        l: [f32; 4],
        /// `/LE` — two-element line-ending styles. Per Table 175 the
        /// default is `[/None /None]`; the spec values are listed in
        /// Table 176 (`Square`, `Circle`, `Diamond`, `OpenArrow`,
        /// `ClosedArrow`, `None`, `Butt`, `ROpenArrow`,
        /// `RClosedArrow`, `Slash`). Round-197 surfaces them raw —
        /// callers that care about rendering compare strings.
        line_endings: Option<[String; 2]>,
        /// `/IC` interior colour for filled line-ending shapes (same
        /// 0/1/3/4-component layout as the outer `/C`).
        interior_colour: Option<Vec<f32>>,
        /// `/LL` — leader-line length, in default user-space units.
        /// Positive values lead clockwise from start→end (per spec
        /// Figure 60). `None` when omitted (default 0 per Table 175).
        leader_line: Option<f32>,
        /// `/LLE` — leader-line extension length (≥ 0). `None` when
        /// omitted (default 0 per Table 175).
        leader_line_extension: Option<f32>,
        /// `/LLO` — leader-line offset (PDF 1.7, ≥ 0). `None` when
        /// omitted.
        leader_line_offset: Option<f32>,
        /// `/Cap` — true iff the Contents / RC text should be drawn
        /// as a caption on the line (Figure 61 / 62). Defaults to
        /// false per Table 175.
        cap: bool,
        /// `/IT` intent (`LineArrow` / `LineDimension`); raw name
        /// preserved.
        intent: Option<String>,
    },
    /// `/Subtype /Polygon` or `/Subtype /PolyLine` — closed-polygon
    /// or open-polyline markup (§12.5.6.9 Table 178, round 197).
    PolygonOrPolyLine {
        /// `true` for `Polygon`, `false` for `PolyLine`.
        is_polygon: bool,
        /// `/Vertices` — alternating `[x1 y1 x2 y2 …]` in default
        /// user space.
        vertices: Vec<f32>,
        /// `/LE` line endings (PolyLine only per spec). Same two-name
        /// shape as `Line::line_endings`.
        line_endings: Option<[String; 2]>,
        /// `/IC` interior colour (same layout as Line).
        interior_colour: Option<Vec<f32>>,
        /// `/IT` intent — `PolygonCloud`, `PolyLineDimension`,
        /// `PolygonDimension`.
        intent: Option<String>,
    },
    /// `/Subtype /Ink` — freehand scribble (§12.5.6.13 Table 182,
    /// round 197). Round-trip target for the round-32
    /// `write_pdf_with_annotations` Ink writer.
    Ink {
        /// `/InkList` — one `Vec<f32>` per stroked path, each a flat
        /// `[x0 y0 x1 y1 …]` series in default user space.
        ink_list: Vec<Vec<f32>>,
    },
    /// `/Subtype /Caret` — text-edit caret (§12.5.6.11 Table 180,
    /// round 197).
    Caret {
        /// `/RD` rectangle differences inside `/Rect`, optional.
        rect_diffs: Option<[f32; 4]>,
        /// `/Sy` — paragraph symbol. `P` ⇒ paragraph mark, `None`
        /// ⇒ no symbol. Defaults to `None` per Table 180.
        symbol: String,
    },
    /// `/Subtype /Popup` — text editor for a markup parent
    /// (§12.5.6.14 Table 183, round 197). Per Table 169 Popup is not
    /// itself a markup type — it hangs off a parent markup annot via
    /// `/Parent` (an indirect reference per Table 183).
    Popup {
        /// `/Parent` — indirect reference to the parent markup
        /// annotation, preserved as an [`ObjectId`] so callers can
        /// re-resolve. `None` when omitted (the spec considers this
        /// malformed — Popup with no parent has no editing target —
        /// but tolerant readers still surface the dict).
        parent: Option<ObjectId>,
        /// `/Open` — initial visibility (defaults to false per
        /// Table 183).
        open: bool,
    },
    /// `/Subtype /Watermark` — fixed-position printed graphics
    /// (§12.5.6.22 Table 190, round 204). Round-204 surfaces the
    /// optional `/FixedPrint` dict (§12.5.6.22 Table 191): printing
    /// applications use the `/Matrix` + `/H` / `/V` percentages to
    /// position the watermark relative to the *printed* media (not
    /// the PDF page), so a screen viewer and a print path render
    /// the same dict differently.
    Watermark {
        /// Decoded `/FixedPrint` dictionary, when present. `None`
        /// means the watermark has no media-relative positioning —
        /// per Table 190 it is then drawn without any special
        /// consideration for the dimensions of the target media.
        fixed_print: Option<FixedPrint>,
    },
    /// `/Subtype /Redact` — redaction marker (§12.5.6.23 Table 192,
    /// round 204). The round-26 reader is *non-destructive*: it
    /// surfaces every redact dict it can decode, but applying the
    /// redaction (actually destroying the underlying content) is a
    /// separate higher-level pass. This variant carries the spec's
    /// content-region + overlay-appearance fields verbatim so a
    /// privacy-audit tool can enumerate what *would* be removed by a
    /// PDF 1.7-compliant redactor without invoking that destructive
    /// path.
    Redact {
        /// `/QuadPoints` — 8N reals giving the quads of the content
        /// region intended for removal. When omitted the spec falls
        /// back to the outer `/Rect`; round-204 surfaces `None` so
        /// callers can distinguish "explicit empty" vs "use Rect".
        quad_points: Option<Vec<f32>>,
        /// `/IC` — DeviceRGB fill applied after content removal
        /// (three components in 0..=1). Ignored by the spec when
        /// `/RO` is present.
        interior_colour: Option<[f32; 3]>,
        /// `/RO` indirect reference — Form XObject overlay
        /// appearance (§8.10). Round-204 surfaces the `ObjectId`
        /// so callers can re-resolve; payload decoding is left to
        /// the consumer because the overlay stream is a generic
        /// Form XObject (`/Subtype /Form`), not a redact-specific
        /// shape.
        overlay_form: Option<ObjectId>,
        /// `/OverlayText` — text-string drawn over the redacted
        /// region after removal. Ignored per spec when `/RO` is
        /// present.
        overlay_text: Option<String>,
        /// `/Repeat` — `true` ⇒ the overlay text tiles to fill the
        /// region. Defaults to `false` per Table 192. Ignored when
        /// `/RO` is present.
        repeat: bool,
        /// `/DA` — appearance string for the overlay text (the
        /// `/Helv 12 Tf 0 g`-style content snippet from §12.7.3.3).
        /// "Required if OverlayText is present, ignored otherwise"
        /// per Table 192; surfaced as raw bytes so callers can
        /// re-feed the snippet through the content-stream parser.
        default_appearance: Option<String>,
        /// `/Q` — overlay-text justification: 0 left (default), 1
        /// centre, 2 right. Ignored when `/RO` is present.
        quadding: u8,
    },
    /// `/Subtype /FileAttachment` — embedded-file marker
    /// (§12.5.6.15 Table 184, round 197). Round-trip target for the
    /// round-33 `write_pdf_with_attachments` annotation marker.
    FileAttachment {
        /// `/Name` icon — defaults to `PushPin` per Table 184. The
        /// spec also names `GraphPushPin` and `PaperclipTag`;
        /// additional names may be supported.
        icon: String,
        /// User-visible file name resolved from the `/FS` filespec.
        /// Prefers `/UF` (UTF-16BE-with-BOM) over `/F`
        /// (PDFDocEncoded) per §7.11.2 Table 43, matching the
        /// round-33 attachment reader's behaviour. `None` when the
        /// filespec is missing, unresolvable, or carries neither
        /// name field.
        file_name: Option<String>,
        /// `/FS` filespec indirect-reference target, preserved so
        /// callers can correlate the annotation with an entry from
        /// `read_pdf_attachments` (same `ObjectId`). `None` when the
        /// `/FS` entry is a direct dictionary rather than a
        /// reference (rare but legal — the spec only requires the
        /// entry to be a "file specification").
        filespec: Option<ObjectId>,
    },
    /// `/Subtype /Sound` — sound annotation (§12.5.6.16 Table 185,
    /// round 209). The §13.3 sound stream itself is preserved as an
    /// `ObjectId` rather than decoded — this crate doesn't bundle an
    /// audio decoder, and consumers that care about playback already
    /// route raw streams through one of the workspace's audio codec
    /// crates. The sound stream is required per Table 185; a Sound
    /// annotation that lacks `/Sound` (malformed) surfaces `None` and
    /// is still enumerated rather than dropped, matching the round-197
    /// tolerant-reader contract every other subtype follows.
    Sound {
        /// `/Sound` indirect reference — §13.3 sound stream object.
        /// Preserved verbatim so callers can re-resolve the stream
        /// dictionary (sample rate, channels, encoding, bytes) on
        /// demand. `None` when the entry is absent or a direct
        /// stream (no indirect target to surface).
        sound: Option<ObjectId>,
        /// `/Name` icon identifier — `Speaker` (default per Table 185),
        /// `Mic`, or an authoring-tool extension name.
        icon: String,
    },
    /// `/Subtype /Movie` — movie annotation (§12.5.6.17 Table 186,
    /// round 209). The §13.4 movie metadata is preserved as an
    /// `ObjectId` when it's an indirect reference rather than decoded
    /// — this crate doesn't decode video; consumers route the resolved
    /// movie dict through the appropriate video codec crate themselves.
    Movie {
        /// `/T` title — text string §12.6.4.9 movie actions use to
        /// look up this annotation by name. Optional per Table 186.
        title: Option<String>,
        /// `/Movie` — §13.4 movie dictionary. Preserved as `ObjectId`
        /// when the entry is an indirect reference (the common shape
        /// because the movie dict carries large indirect data blocks);
        /// surfaced as `None` when the dict is inline (rare — the
        /// outer Movie annotation dict and inline movie dict would
        /// share the same key namespace, which the spec example in
        /// §13.4 does not do). Required per Table 186; malformed
        /// dicts still enumerate to keep audit-walks complete.
        movie: Option<ObjectId>,
        /// `/A` activation — tri-state collapse of the spec's
        /// "boolean or dictionary" shape. `MovieActivation::Play` for
        /// `true` (the Table 186 default), `MovieActivation::Dont` for
        /// `false`, `MovieActivation::Custom(id)` for an indirect
        /// reference to a movie-activation dict (preserved verbatim
        /// so callers can re-resolve the §13.4 activation parameters).
        activation: MovieActivation,
    },
    /// `/Subtype /Screen` — screen annotation (§12.5.6.18 Table 187,
    /// round 209). Screen annotations exist to anchor §12.6.4.13
    /// rendition actions to a region of a page; round-209 surfaces the
    /// title, the appearance-characteristics `/MK` dict reference, and
    /// the `/A` / `/AA` action references. Rendition-action decoding
    /// itself is downstream of round-26 actions and remains out of
    /// scope for the annotation reader.
    Screen {
        /// `/T` — title of the screen annotation. Optional per
        /// Table 187.
        title: Option<String>,
        /// `/MK` — appearance characteristics dictionary (Table 189)
        /// preserved as `ObjectId` when the entry is an indirect
        /// reference. The `/I` sub-entry of this dict provides the
        /// icon used by `/AP`; round-209 doesn't traverse `/MK` itself
        /// because the same dict shape is used by Widget annotations
        /// (and is therefore better surfaced through a shared decoder
        /// in a follow-up round).
        appearance_chars: Option<ObjectId>,
        /// `/A` — action triggered when the annotation is activated.
        /// Preserved as `ObjectId` so callers can re-resolve through
        /// the round-36 `actions` reader. Inline action dicts are not
        /// surfaced here because the round-36 reader walks indirect
        /// actions anyway and a screen annotation's `/A` is, in
        /// practice, always an indirect reference to a rendition
        /// action dict (§12.6.4.13).
        action: Option<ObjectId>,
        /// `/AA` — additional-actions dictionary (§12.6.3 Trigger
        /// Events) for event-driven behaviour (page-open, mouse-down,
        /// focus-gain, …). Preserved as `ObjectId`; the round-36
        /// `actions` reader handles the per-trigger walk.
        additional_actions: Option<ObjectId>,
    },
    /// `/Subtype /PrinterMark` — production printer's mark
    /// (§12.5.6.20 + Table 362, round 215). PDF 1.4. Carries the
    /// optional `/MN` mark-name identifier (e.g. `ColorBar`,
    /// `RegistrationTarget`, `CutMark`). The actual mark glyphs live
    /// in the form-XObject appearance stream referenced from `/AP /N`;
    /// the round-26 reader doesn't surface appearance streams (those
    /// stay routed through the §8.10 Form XObject walker), so the
    /// round-215 enumeration is the mark-type metadata only.
    PrinterMark {
        /// `/MN` — arbitrary mark-name Name identifying the type of
        /// printer's mark (Table 362). `None` when the producer
        /// omitted the entry (the spec makes it optional). Common
        /// values seen in the wild include `ColorBar`,
        /// `RegistrationTarget`, `CutMark`, `PageInformation`, but
        /// the spec does not enumerate a closed set — the raw Name is
        /// preserved verbatim so a colour-management tool can match
        /// its own taxonomy.
        mark_name: Option<String>,
    },
    /// `/Subtype /TrapNet` — page-level trap network
    /// (§12.5.6.21 + Table 366, round 215). PDF 1.3. Carries either
    /// the `/LastModified` date *or* the `/Version` + `/AnnotStates`
    /// pair (the spec rules these out as mutually exclusive); the
    /// optional `/FontFauxing` array of font references is also
    /// surfaced so a trap-network validator can detect substitutions.
    /// Per §12.5.6.21 a page has at most one TrapNet annotation, and
    /// it must be the last element of the page's `/Annots` array —
    /// the round-26 walker enumerates whatever the producer wrote.
    TrapNet {
        /// `/LastModified` — date string per §7.9.4 (PDF `D:` form),
        /// when present. The spec marks this "Required if Version
        /// and AnnotStates are absent" so a well-formed TrapNet
        /// annotation has either this or the version-array pair.
        last_modified: Option<String>,
        /// `/Version` — unordered array of indirect references to
        /// every object whose change would invalidate the trap
        /// network. Surfaced as a `Vec<ObjectId>` so a regenerator
        /// can enumerate the candidates. `None` when the entry is
        /// absent (in which case `/LastModified` carries the
        /// invalidation watermark).
        version: Option<Vec<ObjectId>>,
        /// `/AnnotStates` — appearance-state Names (one per
        /// per-page annotation, in the page's `/Annots` order). The
        /// spec allows a `null` element for annotations with no
        /// `/AS` entry; the reader surfaces `None` for those slots.
        /// `None` at the outer level when the entry is absent.
        annot_states: Option<Vec<Option<String>>>,
        /// `/FontFauxing` — references to fonts substituted during
        /// trap-network generation. `None` when the entry is absent.
        font_fauxing: Option<Vec<ObjectId>>,
    },
    /// `/Subtype /3D` — 3D artwork annotation (§13.6.2 Table 298,
    /// round 220). PDF 1.6. Surfaces the artwork reference, the
    /// initial view selector, the activation behaviour, the
    /// interactive-use flag, and the 3D view box. The actual 3D
    /// stream (§13.6.3 U3D / PRC payload) is preserved as
    /// [`ObjectId`] — this crate does not decode 3D artwork.
    ThreeD {
        /// `/3DD` — the 3D stream (§13.6.3) or 3D reference dict
        /// (§13.6.3.3) that carries the artwork. Required per
        /// Table 298. Surfaced as `ObjectId` when an indirect
        /// reference (the common shape — both streams and reference
        /// dicts are always indirect); `None` if the producer
        /// inlined a dict directly or omitted the key entirely
        /// (the reader is tolerant of the latter so a forensic
        /// walk still surfaces the annotation skeleton).
        artwork: Option<ObjectId>,
        /// `/3DV` — the initial view to use when the annotation
        /// is activated. Spec types this as one of: a 3D view
        /// dictionary (indirect ref), an integer index into the
        /// stream's `/VA` array, a text string matching a view's
        /// `/IN` entry, or a Name `F` / `L` / `D` selecting the
        /// first / last / default `/VA` entry. `None` when absent
        /// (Table 298 default: "the default view in the 3D stream
        /// object specified by 3DD").
        view: Option<ThreeDViewSelector>,
        /// `/3DA` — activation dictionary (Table 299) that governs
        /// when the annotation activates / deactivates and what
        /// state the artwork instance shall be in. Defaults are
        /// applied per Table 299 when the entry is absent (the
        /// reader returns `Some(ThreeDActivation::default())`) so
        /// the spec's "Default value: an activation dictionary
        /// containing default values for all its entries" is
        /// honoured at the API level.
        activation: ThreeDActivation,
        /// `/3DI` — interactive-use flag. `true` ⇒ a conforming
        /// reader should expose interactive rotate/pan/zoom
        /// controls; `false` ⇒ the artwork is driven entirely by
        /// scripts/animations. Defaults to `true` per Table 298
        /// when absent.
        interactive: bool,
        /// `/3DB` — the 3D view box (rectangle in the annotation's
        /// target coordinate system; the origin is the centre of
        /// the annotation rectangle). `None` when absent; the
        /// spec default is the annotation's `/Rect` expressed in
        /// the target coordinate system, i.e. `[-w/2 -h/2 w/2 h/2]`,
        /// which the caller can compute from the outer
        /// `PdfAnnotation::rect` field if needed.
        view_box: Option<[f32; 4]>,
    },
    /// Subtype this round doesn't decode — name surfaced verbatim.
    Other { subtype: String },
}

/// `/3DV` initial-view selector for [`AnnotationKind::ThreeD`] (Table
/// 298, round 220). Per spec the `/3DV` slot may carry any of four
/// shapes; this enum is the lossless union of those.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreeDViewSelector {
    /// Indirect reference to a 3D view dictionary (§13.6.4).
    View(ObjectId),
    /// Integer index into the 3D stream's `/VA` view array.
    Index(i64),
    /// Text-string match against a view's `/IN` (internal name).
    Name(String),
    /// Symbolic selector — `F` / `L` / `D` for first / last / default
    /// `/VA` entry per Table 298. Anything else is preserved
    /// verbatim so a forensic walk doesn't lose the producer's
    /// extension.
    Symbolic(String),
}

/// Decoded `/3DA` activation dictionary (Table 299) for
/// [`AnnotationKind::ThreeD`] (round 220). All fields are optional
/// and each one's `None` shape means "absent" (the per-field defaults
/// described in the variant docstrings are applied at the time the
/// caller decides to *render* the annotation; the reader stays
/// lossless about presence-vs-default to keep round-trip diagnostics
/// possible).
#[derive(Debug, Clone, PartialEq)]
pub struct ThreeDActivation {
    /// `/A` — activation circumstance: `PO` / `PV` / `XA`. Default
    /// `XA` (the annotation stays inactive until explicit user
    /// action). Preserved verbatim so unknown extension Names
    /// pass through.
    pub activation_when: Option<String>,
    /// `/AIS` — artwork state on activation: `I` (instantiated,
    /// scripts off) or `L` (live, scripts on). Default `L`.
    pub artwork_state_on_activation: Option<String>,
    /// `/D` — deactivation circumstance: `PC` / `PI` / `XD`.
    /// Default `PI` (deactivate when the page becomes invisible).
    pub deactivation_when: Option<String>,
    /// `/DIS` — artwork state on deactivation: `U` (uninstantiated),
    /// `I` (instantiated), or `L` (live). Default `U`.
    pub artwork_state_on_deactivation: Option<String>,
    /// `/TB` (PDF 1.7) — show interactive toolbar by default.
    /// Spec default `true`.
    pub toolbar: Option<bool>,
    /// `/NP` (PDF 1.7) — show navigation panel (model tree / view
    /// switcher) by default. Spec default `false`.
    pub navigation_panel: Option<bool>,
}

impl Default for ThreeDActivation {
    /// All-`None` value — semantically equivalent to "no `/3DA` entry
    /// at all", per Table 298's "Default value: an activation
    /// dictionary containing default values for all its entries"
    /// language. Each field's documented spec default applies.
    fn default() -> Self {
        Self {
            activation_when: None,
            artwork_state_on_activation: None,
            deactivation_when: None,
            artwork_state_on_deactivation: None,
            toolbar: None,
            navigation_panel: None,
        }
    }
}

/// `/A` activation tri-state for [`AnnotationKind::Movie`] (Table 186,
/// round 209). The spec types `/A` as "boolean or dictionary":
/// `true` ⇒ play with defaults, `false` ⇒ don't play, dict ⇒ a
/// movie-activation dictionary with custom parameters (volume, rate,
/// `/Start`, `/Duration`, …). The default when `/A` is absent is
/// `true` per Table 186 — so a malformed annotation that omits `/A`
/// entirely surfaces `MovieActivation::Play`, matching what a
/// conforming reader would do when rendering it.
#[derive(Debug, Clone, PartialEq)]
pub enum MovieActivation {
    /// `/A true` (or `/A` absent — Table 186 default).
    Play,
    /// `/A false` — explicit suppression.
    Dont,
    /// `/A << … >>` as an indirect reference — custom movie-activation
    /// dict (§13.4 movie activation parameters). Preserved as
    /// `ObjectId` so callers can re-resolve.
    Custom(ObjectId),
}

/// Text-markup variant tag for [`AnnotationKind::TextMarkup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextMarkupVariant {
    Highlight,
    Underline,
    Squiggly,
    StrikeOut,
}

/// Decoded `/FixedPrint` dictionary for [`AnnotationKind::Watermark`]
/// (ISO 32000-1 §12.5.6.22 Table 191, round 204). All entries are
/// optional except `/Type`; the round-204 reader carries `/Matrix`
/// (defaulting to identity per spec), `/H`, and `/V` (each defaulting
/// to `0.0` per spec).
#[derive(Debug, Clone, PartialEq)]
pub struct FixedPrint {
    /// `/Matrix` — six-number affine transform applied to the
    /// annotation rectangle before rendering. Defaults to the
    /// identity matrix `[1 0 0 1 0 0]` when omitted.
    pub matrix: [f32; 6],
    /// `/H` — horizontal translation as a fraction of the printed
    /// media width (`1.0` ≡ 100%). Defaults to `0.0` when omitted.
    /// Per Table 191 negative values are not recommended (content
    /// may render off-page).
    pub h: f32,
    /// `/V` — vertical translation as a fraction of the printed
    /// media height. Defaults to `0.0` when omitted.
    pub v: f32,
}

impl Default for FixedPrint {
    fn default() -> Self {
        Self {
            // PDF identity transform (§8.3.4) — `a=1 b=0 c=0 d=1 e=0 f=0`.
            matrix: [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
            h: 0.0,
            v: 0.0,
        }
    }
}

/// Walk every page in DFS order, collecting every annotation.
///
/// Pages without `/Annots` contribute zero entries; malformed
/// annotation dicts are skipped silently.
pub fn annotations(reader: &mut DocumentReader<'_>) -> Result<Vec<PdfAnnotation>, PdfError> {
    let page_index_map = build_page_index_map(reader)?;
    let mut pages_by_index: Vec<ObjectId> = Vec::with_capacity(page_index_map.len());
    pages_by_index.resize(page_index_map.len(), ObjectId::new(0));
    for (n, idx) in &page_index_map {
        pages_by_index[*idx] = ObjectId::new(*n);
    }

    let mut out = Vec::new();
    for (idx, page_id) in pages_by_index.iter().enumerate() {
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
        let annots_obj = reader.deref(annots_obj)?;
        let Object::Array(items) = annots_obj else {
            continue;
        };
        for item in items {
            let annot = match reader.deref(item)? {
                Object::Dict(d) => d,
                _ => continue,
            };
            if let Some(parsed) = decode_annotation(reader, &annot, idx, &page_index_map)? {
                out.push(parsed);
            }
        }
    }
    Ok(out)
}

fn decode_annotation(
    reader: &mut DocumentReader<'_>,
    annot: &Dict,
    page_index: usize,
    page_index_map: &HashMap<u32, usize>,
) -> Result<Option<PdfAnnotation>, PdfError> {
    let rect = match find_entry(annot, "Rect") {
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

    let subtype = match find_entry(annot, "Subtype") {
        Some(Object::Name(s)) => s.clone(),
        _ => return Ok(None),
    };

    let contents = decode_text_string(find_entry(annot, "Contents"));
    let name = decode_text_string(find_entry(annot, "NM"));
    let modified = decode_text_string(find_entry(annot, "M"));
    let flags = match find_entry(annot, "F") {
        Some(Object::Integer(n)) => *n as u32,
        _ => 0,
    };
    let colour = decode_real_array(find_entry(annot, "C"));
    let border = decode_real_array(find_entry(annot, "Border"));
    let appearance = decode_appearance_summary(reader, annot)?;
    let appearance_state = match find_entry(annot, "AS") {
        Some(Object::Name(s)) => Some(s.clone()),
        _ => None,
    };

    let kind = match subtype.as_str() {
        "Text" => AnnotationKind::Text {
            open: matches!(find_entry(annot, "Open"), Some(Object::Bool(true))),
            icon: match find_entry(annot, "Name") {
                Some(Object::Name(s)) => s.clone(),
                _ => "Note".into(),
            },
            state: decode_text_string(find_entry(annot, "State")),
            state_model: decode_text_string(find_entry(annot, "StateModel")),
        },
        "FreeText" => AnnotationKind::FreeText {
            default_appearance: decode_text_string(find_entry(annot, "DA")),
            quadding: match find_entry(annot, "Q") {
                Some(Object::Integer(n)) => (*n).clamp(0, 2) as u8,
                _ => 0,
            },
            rich_content: decode_text_string(find_entry(annot, "RC")),
            intent: match find_entry(annot, "IT") {
                Some(Object::Name(s)) => Some(s.clone()),
                _ => None,
            },
        },
        "Stamp" => AnnotationKind::Stamp {
            icon: match find_entry(annot, "Name") {
                Some(Object::Name(s)) => s.clone(),
                _ => "Draft".into(),
            },
        },
        "Highlight" => AnnotationKind::TextMarkup {
            variant: TextMarkupVariant::Highlight,
            quad_points: decode_real_array(find_entry(annot, "QuadPoints")).unwrap_or_default(),
        },
        "Underline" => AnnotationKind::TextMarkup {
            variant: TextMarkupVariant::Underline,
            quad_points: decode_real_array(find_entry(annot, "QuadPoints")).unwrap_or_default(),
        },
        "Squiggly" => AnnotationKind::TextMarkup {
            variant: TextMarkupVariant::Squiggly,
            quad_points: decode_real_array(find_entry(annot, "QuadPoints")).unwrap_or_default(),
        },
        "StrikeOut" => AnnotationKind::TextMarkup {
            variant: TextMarkupVariant::StrikeOut,
            quad_points: decode_real_array(find_entry(annot, "QuadPoints")).unwrap_or_default(),
        },
        "Square" | "Circle" => AnnotationKind::Geometry {
            is_square: subtype == "Square",
            interior_colour: decode_real_array(find_entry(annot, "IC")),
            rect_diffs: decode_rect_diffs(find_entry(annot, "RD")),
        },
        "Link" => AnnotationKind::Link {
            target: decode_link_target(reader, annot, page_index_map)?,
        },
        "Widget" => AnnotationKind::Widget {
            field_type: match find_entry(annot, "FT") {
                Some(Object::Name(s)) => Some(s.clone()),
                _ => None,
            },
            field_name: decode_text_string(find_entry(annot, "T")),
            value: decode_field_value(find_entry(annot, "V")),
        },
        // Round 197 — §12.5.6.7 Line annotation (Table 175).
        "Line" => {
            // `/L` is required per Table 175 — without it we still
            // surface the dict but supply a zero-length placeholder
            // so callers don't have to special-case Option. This
            // matches the tolerant-reader contract every other
            // subtype follows.
            let l = decode_rect_diffs(find_entry(annot, "L")).unwrap_or([0.0; 4]);
            AnnotationKind::Line {
                l,
                line_endings: decode_two_name_array(find_entry(annot, "LE")),
                interior_colour: decode_real_array(find_entry(annot, "IC")),
                leader_line: decode_real(find_entry(annot, "LL")),
                leader_line_extension: decode_real(find_entry(annot, "LLE")),
                leader_line_offset: decode_real(find_entry(annot, "LLO")),
                cap: matches!(find_entry(annot, "Cap"), Some(Object::Bool(true))),
                intent: match find_entry(annot, "IT") {
                    Some(Object::Name(s)) => Some(s.clone()),
                    _ => None,
                },
            }
        }
        // Round 197 — §12.5.6.9 Polygon / PolyLine (Table 178).
        "Polygon" | "PolyLine" => AnnotationKind::PolygonOrPolyLine {
            is_polygon: subtype == "Polygon",
            vertices: decode_real_array(find_entry(annot, "Vertices")).unwrap_or_default(),
            line_endings: decode_two_name_array(find_entry(annot, "LE")),
            interior_colour: decode_real_array(find_entry(annot, "IC")),
            intent: match find_entry(annot, "IT") {
                Some(Object::Name(s)) => Some(s.clone()),
                _ => None,
            },
        },
        // Round 197 — §12.5.6.13 Ink (Table 182).
        "Ink" => AnnotationKind::Ink {
            ink_list: decode_ink_list(find_entry(annot, "InkList")),
        },
        // Round 197 — §12.5.6.11 Caret (Table 180).
        "Caret" => AnnotationKind::Caret {
            rect_diffs: decode_rect_diffs(find_entry(annot, "RD")),
            symbol: match find_entry(annot, "Sy") {
                Some(Object::Name(s)) => s.clone(),
                _ => "None".to_string(),
            },
        },
        // Round 197 — §12.5.6.14 Popup (Table 183). The Parent
        // entry is normatively an indirect reference per Table 183;
        // we surface the target id when present.
        "Popup" => AnnotationKind::Popup {
            parent: match find_entry(annot, "Parent") {
                Some(Object::Reference(id)) => Some(*id),
                _ => None,
            },
            open: matches!(find_entry(annot, "Open"), Some(Object::Bool(true))),
        },
        // Round 204 — §12.5.6.22 Watermark (Table 190).
        // The required keys are just `/Subtype /Watermark`; the
        // structural payload is the optional `/FixedPrint` sub-dict
        // (Table 191) that carries media-relative positioning.
        "Watermark" => {
            let fixed_print = match find_entry(annot, "FixedPrint").cloned() {
                Some(o) => {
                    let resolved = reader.deref(o)?;
                    decode_fixed_print(&resolved)
                }
                None => None,
            };
            AnnotationKind::Watermark { fixed_print }
        }
        // Round 204 — §12.5.6.23 Redact (Table 192).
        // Non-destructive enumeration only — the redact-application
        // step (actually removing content) is a separate higher-level
        // pass per spec NOTE in §12.5.6.23.
        "Redact" => {
            let quad_points = decode_real_array(find_entry(annot, "QuadPoints"));
            // Table 192 constrains /IC to three DeviceRGB components.
            // Anything else (a stray 4-CMYK or 1-Gray) gets dropped:
            // the spec is explicit ("three numbers in the range 0.0 to
            // 1.0").
            let interior_colour = decode_real_array(find_entry(annot, "IC")).and_then(|v| {
                if v.len() == 3 {
                    Some([v[0], v[1], v[2]])
                } else {
                    None
                }
            });
            // /RO is an indirect ref to a Form XObject (§8.10);
            // preserve as ObjectId so callers can re-resolve.
            let overlay_form = match find_entry(annot, "RO") {
                Some(Object::Reference(id)) => Some(*id),
                _ => None,
            };
            let overlay_text = decode_text_string(find_entry(annot, "OverlayText"));
            let repeat = matches!(find_entry(annot, "Repeat"), Some(Object::Bool(true)));
            let default_appearance = decode_text_string(find_entry(annot, "DA"));
            let quadding = match find_entry(annot, "Q") {
                Some(Object::Integer(n)) => (*n).clamp(0, 2) as u8,
                _ => 0,
            };
            AnnotationKind::Redact {
                quad_points,
                interior_colour,
                overlay_form,
                overlay_text,
                repeat,
                default_appearance,
                quadding,
            }
        }
        // Round 197 — §12.5.6.15 FileAttachment (Table 184).
        // Resolves the user-visible filename through the same
        // /UF-preferred / /F-fallback path the round-33 attachment
        // reader uses (§7.11.2 Table 43).
        "FileAttachment" => {
            let (filespec_id, filespec_dict) = match find_entry(annot, "FS") {
                Some(Object::Reference(id)) => {
                    let resolved = reader.resolve(*id)?;
                    let dict = match resolved {
                        Object::Dict(d) => Some(d),
                        _ => None,
                    };
                    (Some(*id), dict)
                }
                Some(Object::Dict(d)) => (None, Some(d.clone())),
                _ => (None, None),
            };
            let file_name = filespec_dict.as_ref().and_then(decode_filespec_name);
            AnnotationKind::FileAttachment {
                icon: match find_entry(annot, "Name") {
                    Some(Object::Name(s)) => s.clone(),
                    _ => "PushPin".to_string(),
                },
                file_name,
                filespec: filespec_id,
            }
        }
        // Round 209 — §12.5.6.16 Sound (Table 185). The §13.3 sound
        // stream is preserved as ObjectId rather than decoded; this
        // crate doesn't carry an audio decoder.
        "Sound" => AnnotationKind::Sound {
            sound: match find_entry(annot, "Sound") {
                Some(Object::Reference(id)) => Some(*id),
                _ => None,
            },
            icon: match find_entry(annot, "Name") {
                Some(Object::Name(s)) => s.clone(),
                _ => "Speaker".to_string(),
            },
        },
        // Round 209 — §12.5.6.17 Movie (Table 186). The §13.4 movie
        // dict is preserved as ObjectId. The `/A` entry is normatively
        // typed "boolean or dictionary"; round-209 collapses that to
        // MovieActivation::{Play, Dont, Custom(id)}.
        "Movie" => {
            let activation = match find_entry(annot, "A") {
                Some(Object::Bool(true)) => MovieActivation::Play,
                Some(Object::Bool(false)) => MovieActivation::Dont,
                Some(Object::Reference(id)) => MovieActivation::Custom(*id),
                // Table 186 default when /A is absent is true.
                None => MovieActivation::Play,
                // Inline dict, integer, or other shape — neither
                // boolean nor a resolvable indirect ref. Default to
                // Play per Table 186 rather than dropping the annot.
                _ => MovieActivation::Play,
            };
            AnnotationKind::Movie {
                title: decode_text_string(find_entry(annot, "T")),
                movie: match find_entry(annot, "Movie") {
                    Some(Object::Reference(id)) => Some(*id),
                    _ => None,
                },
                activation,
            }
        }
        // Round 209 — §12.5.6.18 Screen (Table 187). Anchor for
        // §12.6.4.13 rendition actions; round-209 surfaces title +
        // MK/A/AA refs so callers can enumerate without pulling
        // rendition-action plumbing into the annotation reader.
        "Screen" => AnnotationKind::Screen {
            title: decode_text_string(find_entry(annot, "T")),
            appearance_chars: match find_entry(annot, "MK") {
                Some(Object::Reference(id)) => Some(*id),
                _ => None,
            },
            action: match find_entry(annot, "A") {
                Some(Object::Reference(id)) => Some(*id),
                _ => None,
            },
            additional_actions: match find_entry(annot, "AA") {
                Some(Object::Reference(id)) => Some(*id),
                _ => None,
            },
        },
        // Round 220 — §13.6.2 3D annotation (Table 298). The §13.6.3
        // U3D / PRC stream is preserved as ObjectId rather than
        // decoded; this crate does not carry a 3D-artwork decoder.
        // The `/3DA` activation dict (Table 299) is decoded into a
        // ThreeDActivation; an absent /3DA surfaces as the default
        // value per Table 298.
        "3D" => {
            let artwork = match find_entry(annot, "3DD") {
                Some(Object::Reference(id)) => Some(*id),
                _ => None,
            };
            let view = decode_three_d_view_selector(find_entry(annot, "3DV"));
            let activation = match find_entry(annot, "3DA").cloned() {
                Some(o) => {
                    let resolved = reader.deref(o)?;
                    decode_three_d_activation(&resolved).unwrap_or_default()
                }
                None => ThreeDActivation::default(),
            };
            // Table 298 default for /3DI is `true`.
            let interactive = match find_entry(annot, "3DI") {
                Some(Object::Bool(b)) => *b,
                _ => true,
            };
            let view_box = match find_entry(annot, "3DB") {
                Some(Object::Array(items)) if items.len() == 4 => {
                    let mut out = [0f32; 4];
                    let mut ok = true;
                    for (i, it) in items.iter().enumerate() {
                        match it {
                            Object::Real(f) => out[i] = *f as f32,
                            Object::Integer(n) => out[i] = *n as f32,
                            _ => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if ok {
                        Some(out)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            AnnotationKind::ThreeD {
                artwork,
                view,
                activation,
                interactive,
                view_box,
            }
        }
        // Round 215 — §12.5.6.20 PrinterMark (Table 362). Only `/MN`
        // is annotation-dict-local; the rest of Table 362's optional
        // appearance fields (`/MarkStyle`, `/Colorants` in Table 363)
        // live on the *form-XObject* referenced from `/AP /N`, not on
        // the annot dict itself. The Form XObject walker is the right
        // home for those — round-215 only surfaces the §12.5.6.20
        // payload that distinguishes a PrinterMark from a generic
        // appearance-only annot.
        "PrinterMark" => AnnotationKind::PrinterMark {
            mark_name: match find_entry(annot, "MN") {
                Some(Object::Name(s)) => Some(s.clone()),
                _ => None,
            },
        },
        // Round 215 — §12.5.6.21 TrapNet (Table 366). All three of
        // /LastModified, /Version, /AnnotStates, and /FontFauxing are
        // surfaced; the spec's "either LastModified or
        // (Version + AnnotStates)" mutual-exclusion is encoded as the
        // outer Option pair — a tolerant reader does not reject an
        // annot that violates it (no real producer mixes them, but a
        // forensic walk should still enumerate what the producer
        // actually wrote).
        "TrapNet" => {
            let last_modified = decode_text_string(find_entry(annot, "LastModified"));
            let version = decode_indirect_ref_array(find_entry(annot, "Version"));
            let annot_states = decode_optional_name_array(find_entry(annot, "AnnotStates"));
            let font_fauxing = decode_indirect_ref_array(find_entry(annot, "FontFauxing"));
            AnnotationKind::TrapNet {
                last_modified,
                version,
                annot_states,
                font_fauxing,
            }
        }
        other => AnnotationKind::Other {
            subtype: other.to_string(),
        },
    };

    Ok(Some(PdfAnnotation {
        source_page_index: page_index,
        rect,
        contents,
        name,
        modified,
        flags,
        colour,
        border,
        appearance,
        appearance_state,
        kind,
    }))
}

/// Decode the `/AP` appearance dictionary (§12.5.5 Table 168) into an
/// [`AnnotationAppearance`] summary: which of `/N` / `/R` / `/D` are
/// present, plus the union of appearance-state names across any
/// subdictionary-form entries.
fn decode_appearance_summary(
    reader: &mut DocumentReader<'_>,
    annot: &Dict,
) -> Result<Option<AnnotationAppearance>, PdfError> {
    let ap = match find_entry(annot, "AP").cloned() {
        Some(obj) => match reader.deref(obj) {
            Ok(Object::Dict(d)) => d,
            _ => return Ok(None),
        },
        None => return Ok(None),
    };
    let mut summary = AnnotationAppearance::default();
    let mut states: Vec<String> = Vec::new();
    for (key, flag) in [("N", 0usize), ("R", 1), ("D", 2)] {
        let Some(entry) = find_entry(&ap, key).cloned() else {
            continue;
        };
        match flag {
            0 => summary.has_normal = true,
            1 => summary.has_rollover = true,
            _ => summary.has_down = true,
        }
        // A subdictionary entry defines one stream per appearance
        // state; collect the state names. (A single-stream entry —
        // the common form — resolves to a Stream and adds nothing.)
        if let Ok(Object::Dict(sub)) = reader.deref(entry) {
            for (state, _) in sub.entries() {
                states.push(state.clone());
            }
        }
    }
    states.sort();
    states.dedup();
    summary.states = states;
    Ok(Some(summary))
}

/// Resolve `/Dest` or `/A << /S … >>` for a Link annotation. Mirrors
/// the round-25 link reader exactly so the two surfaces stay in sync.
fn decode_link_target(
    reader: &mut DocumentReader<'_>,
    annot: &Dict,
    page_index_map: &HashMap<u32, usize>,
) -> Result<Option<PdfLinkTarget>, PdfError> {
    if let Some(dest) = find_entry(annot, "Dest").cloned() {
        let dest = reader.deref(dest)?;
        return Ok(decode_dest_value(dest, page_index_map));
    }
    if let Some(action) = find_entry(annot, "A").cloned() {
        let action = reader.deref(action)?;
        if let Object::Dict(adict) = action {
            let s_kind = find_entry(&adict, "S").and_then(|v| match v {
                Object::Name(s) => Some(s.clone()),
                _ => None,
            });
            match s_kind.as_deref() {
                Some("URI") => {
                    let uri = find_entry(&adict, "URI").and_then(|v| match v {
                        Object::LiteralString(b) | Object::HexString(b) => {
                            Some(String::from_utf8_lossy(b).into_owned())
                        }
                        _ => None,
                    });
                    return Ok(uri.map(PdfLinkTarget::Uri));
                }
                Some("GoTo") => {
                    if let Some(d) = find_entry(&adict, "D").cloned() {
                        let d = reader.deref(d)?;
                        return Ok(decode_dest_value(d, page_index_map));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(None)
}

fn decode_dest_value(dest: Object, page_index_map: &HashMap<u32, usize>) -> Option<PdfLinkTarget> {
    match dest {
        Object::Array(items) => {
            decode_explicit_dest(&items, page_index_map).map(PdfLinkTarget::Internal)
        }
        Object::Name(s) => Some(PdfLinkTarget::Named(s)),
        Object::LiteralString(b) | Object::HexString(b) => Some(PdfLinkTarget::Named(
            String::from_utf8_lossy(&b).into_owned(),
        )),
        _ => None,
    }
}

fn decode_explicit_dest(
    items: &[Object],
    page_index_map: &HashMap<u32, usize>,
) -> Option<crate::outline::OutlineDestination> {
    use crate::outline::OutlineDestination;
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

fn find_entry<'d>(d: &'d Dict, key: &str) -> Option<&'d Object> {
    d.entries().iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn decode_real_array(o: Option<&Object>) -> Option<Vec<f32>> {
    match o? {
        Object::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                match it {
                    Object::Real(f) => out.push(*f as f32),
                    Object::Integer(n) => out.push(*n as f32),
                    _ => return None,
                }
            }
            Some(out)
        }
        _ => None,
    }
}

fn decode_rect_diffs(o: Option<&Object>) -> Option<[f32; 4]> {
    let v = decode_real_array(o)?;
    if v.len() == 4 {
        Some([v[0], v[1], v[2], v[3]])
    } else {
        None
    }
}

/// Decode a single Real / Integer numeric Object as `f32`. Used for
/// Table 175's leader-line scalars (`/LL`, `/LLE`, `/LLO`).
fn decode_real(o: Option<&Object>) -> Option<f32> {
    match o? {
        Object::Real(f) => Some(*f as f32),
        Object::Integer(n) => Some(*n as f32),
        _ => None,
    }
}

/// Decode a two-element Name array — `/LE` line endings per
/// Table 176, e.g. `[/OpenArrow /ClosedArrow]`. Returns `None` when
/// the array is missing, the wrong length, or contains non-Name
/// elements. The spec defaults to `[/None /None]` when absent (round
/// 197 surfaces the absence as `None` so callers can distinguish a
/// producer that explicitly wrote the default).
fn decode_two_name_array(o: Option<&Object>) -> Option<[String; 2]> {
    let arr = match o? {
        Object::Array(items) => items,
        _ => return None,
    };
    if arr.len() != 2 {
        return None;
    }
    let a = match &arr[0] {
        Object::Name(s) => s.clone(),
        _ => return None,
    };
    let b = match &arr[1] {
        Object::Name(s) => s.clone(),
        _ => return None,
    };
    Some([a, b])
}

/// Decode an `/InkList` — an array of arrays, each inner array a flat
/// `[x0 y0 x1 y1 …]` series in default user space (Table 182).
/// Malformed inner elements (non-array entries, non-numeric coords)
/// are skipped silently — best-effort enumeration matches the rest of
/// the annotation reader.
fn decode_ink_list(o: Option<&Object>) -> Vec<Vec<f32>> {
    let Some(Object::Array(strokes)) = o else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(strokes.len());
    for s in strokes {
        let Object::Array(coords) = s else { continue };
        let mut flat = Vec::with_capacity(coords.len());
        let mut ok = true;
        for c in coords {
            match c {
                Object::Real(f) => flat.push(*f as f32),
                Object::Integer(n) => flat.push(*n as f32),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            out.push(flat);
        }
    }
    out
}

/// Decode a `/FixedPrint` sub-dict (§12.5.6.22 Table 191) into the
/// round-204 [`FixedPrint`] struct. Returns `None` only when the
/// resolved object is not a dictionary at all — a dict whose entries
/// are all absent yields the all-default value (identity matrix,
/// H=V=0.0) so the presence-vs-absence signal at the outer
/// `AnnotationKind::Watermark { fixed_print }` slot stays meaningful.
///
/// Per Table 191 the `/Type /FixedPrint` marker is required; we don't
/// re-validate it here because a malformed type marker shouldn't strip
/// the structural payload from a forensic enumeration. A `/Matrix`
/// whose array isn't exactly six numbers reverts to the identity
/// default rather than failing the whole decode.
fn decode_fixed_print(o: &Object) -> Option<FixedPrint> {
    let Object::Dict(d) = o else {
        return None;
    };
    let mut out = FixedPrint::default();
    if let Some(Object::Array(items)) = find_entry(d, "Matrix") {
        if items.len() == 6 {
            let mut tmp = [0f32; 6];
            let mut ok = true;
            for (i, it) in items.iter().enumerate() {
                match it {
                    Object::Real(f) => tmp[i] = *f as f32,
                    Object::Integer(n) => tmp[i] = *n as f32,
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                out.matrix = tmp;
            }
        }
    }
    if let Some(v) = decode_real(find_entry(d, "H")) {
        out.h = v;
    }
    if let Some(v) = decode_real(find_entry(d, "V")) {
        out.v = v;
    }
    Some(out)
}

/// Decode an array of indirect references — `/Version` and
/// `/FontFauxing` per Table 366. Non-reference elements (a direct dict
/// snuck into a `/Version` slot, a null, …) are dropped silently so a
/// best-effort enumeration still surfaces the references the producer
/// did emit. Returns `None` when the entry is absent or not an array
/// at all; an empty array surfaces as `Some(vec![])` so callers can
/// distinguish "absent" from "explicitly empty".
fn decode_indirect_ref_array(o: Option<&Object>) -> Option<Vec<ObjectId>> {
    let Object::Array(items) = o? else {
        return None;
    };
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        if let Object::Reference(id) = it {
            out.push(*id);
        }
    }
    Some(out)
}

/// Decode `/AnnotStates` per Table 366 — an array of `Name` or `null`
/// (one slot per per-page annotation, in `/Annots` order). The spec
/// allows the null shape for annotations with no `/AS` entry; the
/// reader surfaces `None` for those slots and `Some(name)` for the
/// rest. Returns `None` at the outer level when the entry is absent or
/// not an array; an empty array round-trips as `Some(vec![])`.
fn decode_optional_name_array(o: Option<&Object>) -> Option<Vec<Option<String>>> {
    let Object::Array(items) = o? else {
        return None;
    };
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match it {
            Object::Name(s) => out.push(Some(s.clone())),
            Object::Null => out.push(None),
            // Per spec the entries are Name-or-null; any other shape is
            // malformed. Drop the slot rather than the whole array so
            // enumeration still surfaces the well-formed neighbours.
            _ => out.push(None),
        }
    }
    Some(out)
}

/// Decode the user-visible name from a `/Filespec` dict, preferring
/// `/UF` (UTF-16BE-with-BOM, PDF 1.7+) over `/F` (PDFDocEncoded) per
/// §7.11.2 Table 43. Mirrors the round-33 attachment reader's
/// `decode_filespec_name` so FileAttachment annotations and embedded
/// files report identical names.
fn decode_filespec_name(filespec: &Dict) -> Option<String> {
    let pick = filespec
        .entries()
        .iter()
        .find(|(k, _)| k == "UF")
        .or_else(|| filespec.entries().iter().find(|(k, _)| k == "F"));
    decode_text_string(pick.map(|(_, v)| v))
}

/// PDF "text string" decode — handles literal-PDFDocEncoding and
/// hex-UTF-16BE-with-BOM per §7.9.2.2.
fn decode_text_string(o: Option<&Object>) -> Option<String> {
    match o? {
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

/// Field value decode — `/V` may be a string, name, number, or array
/// (multi-select choice fields). Round-26 collapses the common forms
/// to a single String; richer field-value support is out of scope.
fn decode_field_value(o: Option<&Object>) -> Option<String> {
    match o? {
        Object::LiteralString(b) | Object::HexString(b) => Some(decode_pdf_string_bytes(b)),
        Object::Name(s) => Some(s.clone()),
        Object::Integer(n) => Some(n.to_string()),
        Object::Real(f) => Some(f.to_string()),
        Object::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn decode_pdf_string_bytes(b: &[u8]) -> String {
    if b.len() >= 2 && b[0] == 0xFE && b[1] == 0xFF {
        let utf16: Vec<u16> = b[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&utf16)
    } else {
        String::from_utf8_lossy(b).into_owned()
    }
}

/// Decode the `/3DV` initial-view selector for a `/3D` annotation
/// (Table 298, round 220). Returns `None` only when the entry is
/// absent or has a shape that doesn't fit any of the four spec
/// alternatives (indirect ref, integer, text string, Name). The four
/// spec alternatives become the four [`ThreeDViewSelector`] variants.
fn decode_three_d_view_selector(o: Option<&Object>) -> Option<ThreeDViewSelector> {
    match o? {
        Object::Reference(id) => Some(ThreeDViewSelector::View(*id)),
        Object::Integer(n) => Some(ThreeDViewSelector::Index(*n)),
        Object::LiteralString(b) | Object::HexString(b) => {
            Some(ThreeDViewSelector::Name(decode_pdf_string_bytes(b)))
        }
        Object::Name(s) => Some(ThreeDViewSelector::Symbolic(s.clone())),
        _ => None,
    }
}

/// Decode the `/3DA` activation dictionary (Table 299, round 220).
/// Returns `None` only when the resolved object is not a dictionary —
/// a dict whose entries are all absent yields `ThreeDActivation`
/// with every field `None` (semantically equivalent to "no /3DA at
/// all", in which case Table 298 says the per-field spec defaults
/// apply). Unknown Name values for `/A` / `/AIS` / `/D` / `/DIS` are
/// preserved verbatim so the caller still sees what the producer
/// wrote — the spec enumerations are open-ended in practice (some
/// producers emit `PV` variants that newer revisions never added to
/// the formal list).
fn decode_three_d_activation(o: &Object) -> Option<ThreeDActivation> {
    let Object::Dict(d) = o else {
        return None;
    };
    let activation_when = match find_entry(d, "A") {
        Some(Object::Name(s)) => Some(s.clone()),
        _ => None,
    };
    let artwork_state_on_activation = match find_entry(d, "AIS") {
        Some(Object::Name(s)) => Some(s.clone()),
        _ => None,
    };
    let deactivation_when = match find_entry(d, "D") {
        Some(Object::Name(s)) => Some(s.clone()),
        _ => None,
    };
    let artwork_state_on_deactivation = match find_entry(d, "DIS") {
        Some(Object::Name(s)) => Some(s.clone()),
        _ => None,
    };
    let toolbar = match find_entry(d, "TB") {
        Some(Object::Bool(b)) => Some(*b),
        _ => None,
    };
    let navigation_panel = match find_entry(d, "NP") {
        Some(Object::Bool(b)) => Some(*b),
        _ => None,
    };
    Some(ThreeDActivation {
        activation_when,
        artwork_state_on_activation,
        deactivation_when,
        artwork_state_on_deactivation,
        toolbar,
        navigation_panel,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_text_string_handles_utf16be_bom() {
        let o = Object::HexString(vec![0xFE, 0xFF, 0x4E, 0x2D, 0x65, 0x87]);
        let s = decode_text_string(Some(&o)).unwrap();
        // 中文 = U+4E2D U+6587
        assert_eq!(s, "中文");
    }

    #[test]
    fn decode_text_string_handles_literal_ascii() {
        let o = Object::LiteralString(b"hello".to_vec());
        let s = decode_text_string(Some(&o)).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn decode_real_array_mixes_int_and_real() {
        let o = Object::Array(vec![
            Object::Integer(1),
            Object::Real(2.5),
            Object::Integer(3),
        ]);
        let v = decode_real_array(Some(&o)).unwrap();
        assert_eq!(v, vec![1.0, 2.5, 3.0]);
    }

    #[test]
    fn decode_real_array_rejects_non_numeric() {
        let o = Object::Array(vec![Object::Integer(1), Object::Name("x".into())]);
        assert!(decode_real_array(Some(&o)).is_none());
    }

    #[test]
    fn decode_rect_diffs_requires_four_entries() {
        let o = Object::Array(vec![
            Object::Real(1.0),
            Object::Real(2.0),
            Object::Real(3.0),
            Object::Real(4.0),
        ]);
        assert_eq!(decode_rect_diffs(Some(&o)), Some([1.0, 2.0, 3.0, 4.0]));
        let bad = Object::Array(vec![Object::Real(1.0)]);
        assert!(decode_rect_diffs(Some(&bad)).is_none());
    }

    #[test]
    fn decode_field_value_collapses_primitives() {
        assert_eq!(
            decode_field_value(Some(&Object::Integer(42))),
            Some("42".into())
        );
        assert_eq!(
            decode_field_value(Some(&Object::Bool(true))),
            Some("true".into())
        );
        assert_eq!(
            decode_field_value(Some(&Object::Name("Yes".into()))),
            Some("Yes".into())
        );
        assert_eq!(
            decode_field_value(Some(&Object::LiteralString(b"abc".to_vec()))),
            Some("abc".into())
        );
        assert_eq!(decode_field_value(Some(&Object::Null)), None);
    }
}
