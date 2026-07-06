//! PDF content-stream operator parser — inverse of [`crate::operators`].
//!
//! Walks the operator stream emitted by a per-page Contents object and
//! reconstructs the [`oxideav_core::vector::Group`] tree that the
//! writer originally walked. The mapping is the same one the writer
//! uses, run in reverse:
//!
//! | PDF operator         | Vector IR                                |
//! |----------------------|------------------------------------------|
//! | `q` / `Q`            | enter / leave a child [`Group`]          |
//! | `cm`                 | concat into the current group's transform |
//! | `m` / `l` / `c` / `h`| [`PathCommand::MoveTo`] / `LineTo` / `CubicCurveTo` / `Close` |
//! | `v` / `y`            | shorthand cubic — lifted to a full `c`   |
//! | `re`                 | rectangle subpath (m + 3*l + h)          |
//! | `f` / `f*`           | fill (NonZero / EvenOdd)                 |
//! | `S`                  | stroke                                   |
//! | `B` / `B*`           | fill + stroke                            |
//! | `b` / `b*`           | close + fill + stroke                    |
//! | `n`                  | no-op paint (consume current path)       |
//! | `W` / `W*`           | clip — assigns to the current group's `clip` |
//! | `rg` / `RG`          | fill / stroke colour (DeviceRGB)         |
//! | `g` / `G`            | grayscale fill / stroke (round-3 maps to RGB triplet) |
//! | `k` / `K`            | DeviceCMYK fill / stroke — converted to RGB per §10.3.5 |
//! | `w` / `J` / `j` / `M`| stroke width / cap / join / miter limit  |
//! | `d`                  | dash array + offset                      |
//! | `cs` / `CS`          | select nonstroking / stroking colour space (device families resolved directly; round 275 resolves `/Resources /ColorSpace` keys that reduce to an ICCBased or Indexed device fallback) |
//! | `sc` / `scn` / `SC` / `SCN` | colour value in the current space — DeviceGray / DeviceRGB / DeviceCMYK components honoured (§8.6.8); round 275 adds Indexed-table index lookup (§8.6.6.3) |
//! | `gs`                 | ExtGState resource lookup — round 125 resolves `LW` / `LC` / `LJ` / `ML` / `D` / `CA` / `ca` from the page's `/Resources /ExtGState` dict |
//!
//! ExtGState lookup (round 125): when a page's `/Resources /ExtGState`
//! dictionary is plumbed in via [`parse_content_stream_with_resources`],
//! a `/GSx gs` operator looks the named subdict up against Table 58
//! (ISO 32000-1 §8.4.5) and applies the cumulative-merge subset that
//! the IR can carry: line width (`LW`), line cap (`LC`), line join
//! (`LJ`), miter limit (`ML`), dash pattern (`D`), and the stroking /
//! nonstroking alpha constants (`CA` / `ca`) per §11.6.4.4. Soft mask
//! (`SMask`), blend mode (`BM`), overprint (`OP` / `op` / `OPM`),
//! transfer / halftone / black-generation, font (`Font`), and rendering
//! intent (`RI`) are silently ignored — they require IR plumbing that
//! the round-3 vector model doesn't carry yet. Unknown keys are tolerated
//! per §8.4.5 ("any combination of parameter entries"). Without the
//! resource-aware entry point, `gs` is still treated as a tolerated
//! no-op so legacy `parse_content_stream` callers don't regress.
//!
//! Text-show resolution (round 128): when the page's `/Resources /Font`
//! subdictionary is also plumbed in via [`parse_content_stream_full`], the
//! `BT … ET` text-object operators (ISO 32000-1 §9.4 + Table 105) are
//! parsed: a `Tf` (`/Fx 12 Tf`) records the active font + size, `Tm` /
//! `Td` / `TD` / `T*` update the text matrix per §9.4.4 Table 108, and
//! every `Tj` / `TJ` / `'` / `"` show operator emits one [`ContentTextShow`]
//! event carrying the raw operand bytes, font resource name (with the
//! resolved font dictionary handed back via `font_dict`), font size, and
//! text-matrix origin at the moment of the show. The events come back
//! alongside the painted `root` group in a [`ParsedContent`] struct; the
//! reader's higher-level text-extraction walker (round 22) still owns the
//! byte→Unicode decoding, but the new entry point lets a consumer that
//! already has the page's `/Resources /Font` resolved get a font-aware
//! show stream straight from the vector-content parser. Without the
//! resource-aware entry point, `Tj` / `TJ` / `Tf` / … keep their
//! round-3 no-op behaviour so existing callers don't regress.
//!
//! Colour-space tracking (round 118): `cs` / `CS` record which device
//! colour family is active so a following `sc` / `scn` (or `SC` /
//! `SCN`) interprets its operands correctly — `/DeviceRGB cs 1 0 0 sc`
//! now produces red, where the round-3 parser collapsed every
//! `sc`/`scn` to black. The parser still does not reach into the
//! page's `/Resources /ColorSpace` dict for non-device colour-space
//! keys, nor for gradient / pattern lookups — those land later (the
//! top-level walker that has the resolved Document). A `/Pat0 scn`
//! pair, a CIE-based / Indexed / Separation / DeviceN space, or any
//! unresolved resource key produces a black solid fill (matches the
//! writer's "unknown-paint fallback", so the roundtrip stays
//! semantically conservative).
//!
//! Text-showing operators (`BT` / `ET` / `Tj` / `TJ` / `'` / `"`) are
//! parsed when the page's `/Resources /Font` dictionary is plumbed in
//! via [`parse_content_stream_full`] and surface as
//! [`ContentTextShow`] events on the returned [`ParsedContent`]. The
//! legacy [`parse_content_stream`] and
//! [`parse_content_stream_with_resources`] entry points drop them
//! silently to preserve round-3 / round-125 callers' behaviour.

use std::collections::{BTreeMap, BTreeSet};
use std::str;

use std::rc::Rc;

use oxideav_core::vector::{
    DashPattern, FillRule, GradientStop, Group, ImageRef, LineCap, LineJoin, LinearGradient,
    MaskKind, Node, Paint, Path, PathCommand, PathNode, Point, RadialGradient, Rect, Rgba,
    SpreadMethod, Stroke, Transform2D,
};
use oxideav_core::{VideoFrame, VideoPlane};

use crate::error::PdfError;
use crate::objects::{Dict, Object};
use crate::reader::inline_images::{find_inline_image_ei, parse_one_inline_image, PdfInlineImage};

/// Parse a content-stream byte sequence into a single [`Group`]
/// containing every shape painted by the stream. Nested `q`/`Q`
/// brackets become nested `Node::Group` children. The returned root
/// group has identity transform; per-`q` transforms live on the
/// child groups.
///
/// `gs` operators are tolerated (operands dropped) since this entry
/// point has no view of the page's `/Resources` dictionary. Callers
/// that have already resolved the page resources should use
/// [`parse_content_stream_with_resources`] so a `/GSx gs` can apply
/// the named graphics-state parameter dictionary's entries to the
/// current state per ISO 32000-1 §8.4.5.
///
/// Text-show operators (`BT … Tj/TJ/'/'" … ET`) are skipped silently;
/// callers that need them should route through
/// [`parse_content_stream_full`] with a resolved `/Resources /Font`
/// dictionary attached.
pub fn parse_content_stream(input: &[u8]) -> Result<Group, PdfError> {
    let mut state = State::new(None, None, None, None, None);
    state.parse(input)?;
    Ok(state.finish().root)
}

/// Parse a content-stream with the page's resolved `/Resources
/// /ExtGState` subdictionary attached. A `/Name gs` operator looks
/// `Name` up in `ext_gstate` and applies the entries Table 58 defines
/// that map cleanly onto the round-3 vector IR (`LW`, `LC`, `LJ`,
/// `ML`, `D`, `CA`, `ca`).
///
/// The dictionary is read-only — keys are resolved by name lookup, no
/// indirect-reference following is attempted (the caller is expected
/// to have already resolved every child dict). When `ext_gstate` is
/// `None` or doesn't contain the named entry, the `gs` operator
/// silently no-ops, matching the round-3 fallback behaviour.
///
/// Text-show events are still skipped — see [`parse_content_stream_full`]
/// for the entry point that also plumbs `/Resources /Font`.
pub fn parse_content_stream_with_resources(
    input: &[u8],
    ext_gstate: Option<&Dict>,
) -> Result<Group, PdfError> {
    let mut state = State::new(ext_gstate, None, None, None, None);
    state.parse(input)?;
    Ok(state.finish().root)
}

/// Parse a content-stream with both the page's resolved `/Resources
/// /ExtGState` and `/Resources /Font` subdictionaries attached. In
/// addition to the round-125 `gs` resolution path, every text-object
/// operator inside a `BT … ET` block (ISO 32000-1 §9.4 + Table 105)
/// is honoured: `Tf` records the active font name + size,
/// `Tm`/`Td`/`TD`/`T*` update the text matrix per §9.4.4 Table 108,
/// and each `Tj`/`TJ`/`'`/`"` show operator emits one
/// [`ContentTextShow`] event into the returned [`ParsedContent`].
///
/// Both resource dictionaries are read-only — keys are resolved by
/// name lookup, no indirect-reference following is attempted (the
/// caller is expected to have already resolved every child dict via
/// the helpers in [`crate::reader::document`]). When `font_resources`
/// is `None` or doesn't contain the `Tf`-named font, the show event
/// still fires but its `font_dict` is `None` so the consumer knows
/// the font wasn't resolved.
pub fn parse_content_stream_full(
    input: &[u8],
    ext_gstate: Option<&Dict>,
    font_resources: Option<&Dict>,
) -> Result<ParsedContent, PdfError> {
    parse_content_stream_full_with_shading(input, ext_gstate, font_resources, None)
}

/// Parse a content-stream with the page's resolved `/Resources
/// /ExtGState`, `/Resources /Font`, and `/Resources /Shading`
/// subdictionaries attached. Same as [`parse_content_stream_full`]
/// plus dispatch for the §8.7.4.5 `name sh` operator: each `sh`
/// records one [`ContentShading`] event into
/// [`ParsedContent::shadings`] capturing the shading resource name,
/// the resolved shading dictionary from `/Resources /Shading`, the
/// effective CTM at the moment of the paint, and the current clip
/// path (the `W`/`W*`-committed region for the active `q` frame).
///
/// The shading dictionary is not interpreted — its `ShadingType`,
/// `ColorSpace`, `Coords`, `Function`, etc. (§8.7.4.5 Tables 78..86)
/// stay verbatim so the caller can either route them through a
/// dedicated shading-resolver or attach them to a downstream IR.
///
/// `shading_resources` follows the same one-hop-indirect contract as
/// `ext_gstate` and `font_resources`: callers go through
/// [`crate::reader::document::resolve_shading_resources`] to get a
/// resolved dict whose per-name entries are direct `Object::Dict`
/// values. When `shading_resources` is `None` or doesn't contain the
/// `sh`-named key, the event still fires but its `shading_dict` is
/// `None` so the consumer knows the resource wasn't resolved.
pub fn parse_content_stream_full_with_shading(
    input: &[u8],
    ext_gstate: Option<&Dict>,
    font_resources: Option<&Dict>,
    shading_resources: Option<&Dict>,
) -> Result<ParsedContent, PdfError> {
    parse_content_stream_full_with_color_space(
        input,
        ext_gstate,
        font_resources,
        shading_resources,
        None,
    )
}

/// Parse a content-stream with the page's resolved `/Resources`
/// `/ExtGState`, `/Font`, `/Shading`, **and `/ColorSpace`**
/// subdictionaries attached. Same as
/// [`parse_content_stream_full_with_shading`] plus round-275
/// colour-space resolution: a `cs` / `CS` operator naming a key in the
/// `/Resources /ColorSpace` dict (rather than a bare device family
/// `/DeviceGray` / `/DeviceRGB` / `/DeviceCMYK`) is resolved against it
/// per ISO 32000-1 §8.6.8 Table 74 + §8.6.5 + §8.6.6.
///
/// Two non-CIE resource colour-space families reduce to a device
/// fallback the round-118 parser previously collapsed to black:
///
/// * **`ICCBased`** (§8.6.5.5) — the `/Alternate` device space is used
///   when present, otherwise the profile's `/N` component count selects
///   DeviceGray (1) / DeviceRGB (3) / DeviceCMYK (4). The ICC profile
///   bytes themselves are not interpreted (the spec authorises exactly
///   this fallback for a reader that does not process the profile).
/// * **`Indexed`** (§8.6.6.3) — when the base reduces to a device
///   family, a subsequent `sc`/`scn` index selects the corresponding
///   `m`-byte entry from the resolved colour table (index rounded to
///   nearest, clamped into `0..=hival`, each byte scaled `0..255 →`
///   the component range).
///
/// CalRGB / CalGray / Lab (CIE-based, need a gamut-mapping pass),
/// Separation / DeviceN (need tint-transform function evaluation), and
/// `/Pattern` keep the conservative black fallback.
///
/// `color_space_resources` follows the same one-hop-resolved contract
/// as the other resource dicts: callers go through
/// [`crate::reader::document::resolve_color_space_resources`] to get a
/// dict whose per-name entries are resolved colour-space `Object`s
/// (ICC profile streams replaced by their dictionaries, Indexed lookup
/// streams replaced by their decoded bytes). When
/// `color_space_resources` is `None` or doesn't contain the named key,
/// a non-device `cs`/`CS` stays `Unknown` and `sc`/`scn` keeps the
/// black fallback, matching round-118 behaviour.
pub fn parse_content_stream_full_with_color_space(
    input: &[u8],
    ext_gstate: Option<&Dict>,
    font_resources: Option<&Dict>,
    shading_resources: Option<&Dict>,
    color_space_resources: Option<&Dict>,
) -> Result<ParsedContent, PdfError> {
    parse_content_stream_full_with_properties(
        input,
        ext_gstate,
        font_resources,
        shading_resources,
        color_space_resources,
        None,
    )
}

/// Parse a content-stream with the page's resolved `/Resources`
/// `/ExtGState`, `/Font`, `/Shading`, `/ColorSpace`, **and
/// `/Properties`** subdictionaries attached. Same as
/// [`parse_content_stream_full_with_color_space`] plus dispatch for the
/// §14.6 marked-content operators (Table 320):
///
/// * `tag MP` / `tag properties DP` — a marked-content **point**.
/// * `tag BMC` / `tag properties BDC` — **begin** a marked-content
///   sequence, terminated by a balancing `EMC`.
/// * `EMC` — **end** the most recent `BMC`/`BDC` sequence.
///
/// Each operator records one [`ContentMarkedContent`] into
/// [`ParsedContent::marked_content`] in stream order, carrying the
/// operator discriminator, the `tag` name, the resolved property list
/// (`DP`/`BDC` only), and the sequence-nesting depth. The walker does
/// not interpret the property list — its entries (`/OC`, `/MCID`,
/// `/ActualText`, `/Alt`, …) stay verbatim for a downstream consumer.
///
/// The `properties` operand of `DP`/`BDC` is resolved per §14.6.2:
/// an inline `<< … >>` dictionary is captured directly; a `/Name`
/// operand is looked up in `properties_resources` (the page's resolved
/// `/Resources /Properties` subdictionary). `properties_resources`
/// follows the same one-hop-indirect contract as the other resource
/// dicts: callers go through
/// [`crate::reader::document::resolve_properties_resources`] to get a
/// dict whose per-name entries are direct `Object::Dict` values. When
/// `properties_resources` is `None` or doesn't contain the named key,
/// the event still fires but its `properties` stays `None`.
pub fn parse_content_stream_full_with_properties(
    input: &[u8],
    ext_gstate: Option<&Dict>,
    font_resources: Option<&Dict>,
    shading_resources: Option<&Dict>,
    color_space_resources: Option<&Dict>,
    properties_resources: Option<&Dict>,
) -> Result<ParsedContent, PdfError> {
    let mut state = State::new(
        ext_gstate,
        font_resources,
        shading_resources,
        color_space_resources,
        properties_resources,
    );
    state.parse(input)?;
    Ok(state.finish())
}

/// Like [`parse_content_stream_full_with_properties`] but also accepts
/// the page's pre-parsed Form XObjects (§8.10), keyed by `/Resources
/// /XObject` resource name (leading `/` stripped). When a `name Do`
/// operator references one of these, the form's content — already
/// parsed into a [`Group`] whose `transform` is the form's `/Matrix`
/// and whose `clip` is the `/BBox` rectangle — is spliced into the
/// scene tree under the current CTM (§8.10.1's q / concat-Matrix /
/// clip-BBox / paint / Q algorithm). A `Do` naming an unknown form
/// (or any Image XObject, which is surfaced separately by
/// [`crate::reader::images`]) stays a tolerated no-op.
///
/// The forms are pre-parsed by the caller
/// ([`crate::reader::document::resolve_xobject_forms`]) so this parser
/// never touches the reader: each form's own `/Resources` are resolved
/// and its content recursively parsed before the map is built, with a
/// depth guard against nested-form cycles.
#[allow(clippy::too_many_arguments)]
pub fn parse_content_stream_full_with_xobjects(
    input: &[u8],
    ext_gstate: Option<&Dict>,
    font_resources: Option<&Dict>,
    shading_resources: Option<&Dict>,
    color_space_resources: Option<&Dict>,
    properties_resources: Option<&Dict>,
    xobject_forms: Option<&BTreeMap<String, Group>>,
) -> Result<ParsedContent, PdfError> {
    let mut state = State::new(
        ext_gstate,
        font_resources,
        shading_resources,
        color_space_resources,
        properties_resources,
    )
    .with_xobject_forms(xobject_forms);
    state.parse(input)?;
    Ok(state.finish())
}

/// [`parse_content_stream_full_with_xobjects`] plus the page's
/// `/Resources /Pattern` subdictionary, so a `scn`/`SCN` shading-pattern
/// fill (`/PatternType 2`, §8.7.3.3 + §8.7.4.5) paints the equivalent
/// scene gradient instead of falling back to black. Each pattern entry's
/// `/Shading` is evaluated through the same axial / radial machinery the
/// `sh` operator uses; the shading `Coords` are mapped to device space
/// through the pattern `/Matrix` composed with the CTM in effect.
#[allow(clippy::too_many_arguments)]
pub fn parse_content_stream_full_with_patterns(
    input: &[u8],
    ext_gstate: Option<&Dict>,
    font_resources: Option<&Dict>,
    shading_resources: Option<&Dict>,
    color_space_resources: Option<&Dict>,
    properties_resources: Option<&Dict>,
    xobject_forms: Option<&BTreeMap<String, Group>>,
    pattern_resources: Option<&Dict>,
) -> Result<ParsedContent, PdfError> {
    let mut state = State::new(
        ext_gstate,
        font_resources,
        shading_resources,
        color_space_resources,
        properties_resources,
    )
    .with_xobject_forms(xobject_forms)
    .with_pattern_resources(pattern_resources);
    state.parse(input)?;
    Ok(state.finish())
}

/// Like [`parse_content_stream_full_with_patterns`] but also accepts the
/// page's pre-parsed `/PatternType 1` tiling patterns (§8.7.3), so a
/// `scn`/`SCN` fill naming a tiling pattern replicates its pattern cell
/// across the filled region instead of falling back to black. Each entry
/// is a [`TilingPattern`] carrying the cell content parsed into a
/// [`Group`] (against the pattern's own `/Resources`), the `/BBox` clip,
/// the `/XStep` / `/YStep` spacing, and the pattern `/Matrix`.
#[allow(clippy::too_many_arguments)]
pub fn parse_content_stream_full_with_tiling(
    input: &[u8],
    ext_gstate: Option<&Dict>,
    font_resources: Option<&Dict>,
    shading_resources: Option<&Dict>,
    color_space_resources: Option<&Dict>,
    properties_resources: Option<&Dict>,
    xobject_forms: Option<&BTreeMap<String, Group>>,
    pattern_resources: Option<&Dict>,
    tiling_patterns: Option<&BTreeMap<String, TilingPattern>>,
) -> Result<ParsedContent, PdfError> {
    let mut state = State::new(
        ext_gstate,
        font_resources,
        shading_resources,
        color_space_resources,
        properties_resources,
    )
    .with_xobject_forms(xobject_forms)
    .with_pattern_resources(pattern_resources)
    .with_tiling_patterns(tiling_patterns);
    state.parse(input)?;
    Ok(state.finish())
}

/// Like [`parse_content_stream_full_with_tiling`] but also accepts the
/// page's pre-parsed Type 3 fonts (§9.6.5), so a `Tj`/`TJ`/`'`/`"` show
/// selecting a Type 3 font paints each glyph's `/CharProcs` description
/// into the scene tree as vector geometry — the one simple-font family
/// whose glyphs are themselves content streams and therefore need no
/// external glyph rasteriser. Each entry is a [`Type3Font`] carrying the
/// `/FontMatrix`, the `/Encoding` code→glyph-name map, and every glyph
/// description pre-parsed into a [`Group`] against the font's own
/// `/Resources`.
#[allow(clippy::too_many_arguments)]
pub fn parse_content_stream_full_with_type3(
    input: &[u8],
    ext_gstate: Option<&Dict>,
    font_resources: Option<&Dict>,
    shading_resources: Option<&Dict>,
    color_space_resources: Option<&Dict>,
    properties_resources: Option<&Dict>,
    xobject_forms: Option<&BTreeMap<String, Group>>,
    pattern_resources: Option<&Dict>,
    tiling_patterns: Option<&BTreeMap<String, TilingPattern>>,
    type3_fonts: Option<&BTreeMap<String, Type3Font>>,
) -> Result<ParsedContent, PdfError> {
    let mut state = State::new(
        ext_gstate,
        font_resources,
        shading_resources,
        color_space_resources,
        properties_resources,
    )
    .with_xobject_forms(xobject_forms)
    .with_pattern_resources(pattern_resources)
    .with_tiling_patterns(tiling_patterns)
    .with_type3_fonts(type3_fonts);
    state.parse(input)?;
    Ok(state.finish())
}

/// Like [`parse_content_stream_full_with_type3`] but also accepts the
/// pre-resolved `/ExtGState /SMask` soft masks (§11.6.5.2), keyed by
/// ExtGState resource name. A `gs` naming an entry establishes it as
/// the current soft mask (§11.6.4.3); every subsequently painted
/// object (path, form splice, clipped `sh`, tiling fill, Type 3
/// glyph) is wrapped in a [`Node::SoftMask`] whose `mask` subtree is
/// the `/G` transparency group at `/Matrix ∘ CTM-at-gs-time` and whose
/// `mask_kind` maps `/Luminosity` → [`MaskKind::Luminance`] and
/// `/Alpha` → [`MaskKind::Alpha`]. `/SMask /None` — and a `Q`
/// restoring a state saved before the mask was set — clears it.
#[allow(clippy::too_many_arguments)]
pub fn parse_content_stream_full_with_soft_masks(
    input: &[u8],
    ext_gstate: Option<&Dict>,
    font_resources: Option<&Dict>,
    shading_resources: Option<&Dict>,
    color_space_resources: Option<&Dict>,
    properties_resources: Option<&Dict>,
    xobject_forms: Option<&BTreeMap<String, Group>>,
    pattern_resources: Option<&Dict>,
    tiling_patterns: Option<&BTreeMap<String, TilingPattern>>,
    type3_fonts: Option<&BTreeMap<String, Type3Font>>,
    soft_masks: Option<&BTreeMap<String, ResolvedSoftMask>>,
    transparency_groups: Option<&BTreeSet<String>>,
    image_xobjects: Option<&BTreeMap<String, ResolvedImageXObject>>,
) -> Result<ParsedContent, PdfError> {
    let mut state = State::new(
        ext_gstate,
        font_resources,
        shading_resources,
        color_space_resources,
        properties_resources,
    )
    .with_xobject_forms(xobject_forms)
    .with_pattern_resources(pattern_resources)
    .with_tiling_patterns(tiling_patterns)
    .with_type3_fonts(type3_fonts)
    .with_soft_masks(soft_masks)
    .with_transparency_groups(transparency_groups)
    .with_image_xobjects(image_xobjects);
    state.parse(input)?;
    Ok(state.finish())
}

/// Output of [`parse_content_stream_full`] — the painted-shapes group
/// (same as the round-3 / round-125 entry points return) plus the
/// stream-order list of text-show events the round-128 walker
/// surfaces when `/Resources /Font` is plumbed in.
#[derive(Clone, Debug, Default)]
pub struct ParsedContent {
    /// Painted-shapes group — identical to the `Group` returned by
    /// [`parse_content_stream`] / [`parse_content_stream_with_resources`].
    pub root: Group,
    /// Every `Tj`/`TJ`/`'`/`"` show, in stream order. Decoding the
    /// raw bytes to Unicode is the caller's responsibility (the
    /// round-22 [`crate::reader::text::extract_text`] walker owns that
    /// path); this surface gives a resource-resolved view of the show
    /// operators for tooling that wants something narrower than the
    /// full text-extraction pipeline.
    pub text_shows: Vec<ContentTextShow>,
    /// Every `name sh` shading-paint event surfaced by
    /// [`parse_content_stream_full_with_shading`] when
    /// `/Resources /Shading` is plumbed in. One entry per `sh`
    /// operator in stream order. Empty when no `sh` operator fired
    /// or when the legacy entry points (`parse_content_stream`,
    /// `parse_content_stream_with_resources`, the no-shading
    /// `parse_content_stream_full`) are used.
    pub shadings: Vec<ContentShading>,
    /// Every marked-content operator (`MP`/`DP`/`BMC`/`BDC`/`EMC`,
    /// §14.6 Table 320) seen by the walker, in stream order. One entry
    /// per operator. Like [`text_shows`](Self::text_shows) and
    /// [`shadings`](Self::shadings), these events surface from every
    /// `ParsedContent`-returning entry point — `MP`/`BMC`/`EMC` carry
    /// no property list, and a `DP`/`BDC` whose `properties` operand is
    /// a `/Name` simply lands with `properties = None` unless
    /// `/Resources /Properties` was plumbed in via
    /// [`parse_content_stream_full_with_properties`]. Inline `<< … >>`
    /// property lists are captured regardless of the entry point. The
    /// `Group`-returning legacy entries (`parse_content_stream`,
    /// `parse_content_stream_with_resources`) discard the whole
    /// `ParsedContent`, so the events are unobservable there.
    pub marked_content: Vec<ContentMarkedContent>,
    /// Every `BI … ID … EI` inline image (§8.9.7) the walker saw, in
    /// stream order — one entry per inline image, carrying its
    /// resolved dictionary + payload and the CTM / clip in force at
    /// the `BI`. Surfaced from every `ParsedContent`-returning entry
    /// point (the resolution needs no `/Resources` plumbing — an
    /// inline image is self-contained). The `Group`-returning legacy
    /// entries discard the whole `ParsedContent`, but they still
    /// consume the `BI … EI` correctly so the surrounding shapes
    /// survive.
    pub inline_images: Vec<ContentInlineImage>,
}

/// One `Tj`/`TJ`/`'`/`"` text-show event surfaced by
/// [`parse_content_stream_full`]. The raw operand bytes are preserved
/// verbatim — escape-decoded for literal strings and hex-pair-decoded
/// for hex strings — so a consumer that wants byte→Unicode mapping can
/// route them through whatever decoder its `font_dict` calls for.
#[derive(Clone, Debug)]
pub struct ContentTextShow {
    /// Font resource name as named by the most recent `Tf`, with the
    /// leading `/` stripped (e.g. `"F1"`). Empty when the content
    /// stream issued a show without a preceding `Tf` (malformed but
    /// tolerated).
    pub font_name: String,
    /// Font size from the most recent `Tf`. `0.0` if no `Tf` was seen.
    pub font_size: f32,
    /// Resolved font dictionary from `/Resources /Font /<font_name>`,
    /// or `None` when the font wasn't found in the supplied
    /// `font_resources` (or no `font_resources` was supplied).
    pub font_dict: Option<Dict>,
    /// Concatenated payload bytes — for `Tj` and `'` the single
    /// operand; for `"` the trailing string operand; for `TJ` the
    /// strings inside the array, concatenated in array order (the
    /// per-element numeric displacements aren't applied because they
    /// only affect glyph kerning, not the decoded text).
    pub bytes: Vec<u8>,
    /// Text-matrix origin `(e, f)` in user space at the moment the
    /// show fired — the position the first glyph would have been
    /// painted at. Reflects every `Tm`/`Td`/`TD`/`T*` update issued
    /// inside the enclosing `BT … ET` (the matrix resets to identity
    /// at every `BT`).
    pub position: (f32, f32),
    /// Which show operator produced this event (`Tj` / `TJ` / `'` /
    /// `"`). Lets a downstream consumer reconstruct the original
    /// operator stream verbatim.
    pub operator: TextShowOp,
}

/// Discriminator for [`ContentTextShow::operator`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextShowOp {
    /// `string Tj` — show one string.
    Tj,
    /// `[(s1) num1 (s2) num2 …] TJ` — show with per-element kerning.
    TJ,
    /// `' string` — move to the next line, then show (`T* Tj`).
    SingleQuote,
    /// `"`a_w a_c string"`` — set word + char spacing, move to next
    /// line, then show.
    DoubleQuote,
}

/// One `BI … ID … EI` inline-image event surfaced by the
/// content-stream walker (ISO 32000-1 §8.9.7). Unlike an Image
/// XObject (which is named and resolved through `/Resources
/// /XObject`), an inline image carries its dictionary + payload
/// directly in the content stream, so the walker is the only place
/// it can be observed with the correct graphics-state context.
///
/// The walker does NOT decode the payload into pixels — that belongs
/// to the image pipeline. It captures the resolved
/// [`PdfInlineImage`] (dictionary + filter-peeled payload, per
/// [`crate::reader::inline_images`]) together with the placement
/// context that §8.9 / §8.7.3.4 require to position it:
///
/// * `ctm` — the composed current transformation matrix at the `BI`.
///   An inline image is painted into the unit square `0 ≤ x,y ≤ 1`
///   in image space, mapped to user space by the CTM (§8.9.5.1), so
///   `ctm` is exactly the placement matrix.
/// * `clip` — the most recent `W`/`W*`-committed clip path in force,
///   or `None`. The image is subject to it (§8.5.4).
#[derive(Clone, Debug)]
pub struct ContentInlineImage {
    /// The resolved inline image — dictionary fields (width, height,
    /// colour space, bits-per-component, terminal codec filter,
    /// image-mask flag) plus the wrapping-filter-peeled payload.
    pub image: PdfInlineImage,
    /// Composed current transformation matrix at the moment of the
    /// `BI` operator. Maps the unit-square image space to user space
    /// (§8.9.5.1).
    pub ctm: Transform2D,
    /// Active clip path (most recent `W`/`W*` commit in the live `q`
    /// frame), or `None` when no clip is in force (§8.5.4).
    pub clip: Option<Path>,
}

/// One `name sh` shading-paint event surfaced by
/// [`parse_content_stream_full_with_shading`]. ISO 32000-1 §8.7.4.5
/// defines `sh` as "paint the shape and colour shading described by
/// a shading dictionary, subject to the current clipping path". This
/// surface captures every input that determines the painted region
/// and colour:
///
/// * `name` — the shading-resource key the operator named (leading
///   `/` stripped).
/// * `shading_dict` — the resolved shading dictionary from
///   `/Resources /Shading /<name>`, or `None` when the caller didn't
///   plumb in `shading_resources` (or when the name wasn't a key in
///   the supplied resources).
/// * `ctm` — the composed current transformation matrix at the
///   moment of the paint (every `cm` in every enclosing `q` frame,
///   composed root-to-leaf). All coordinates inside `shading_dict`
///   are interpreted relative to this transform per §8.7.4.5
///   ("interpreted relative to the current user space").
/// * `clip` — the most recent `W`/`W*`-committed clip path in the
///   active `q` frame, or `None` when no clip is in force. The
///   shading is subject to this region (§8.7.4.5 "subject to the
///   current clipping path").
#[derive(Clone, Debug)]
pub struct ContentShading {
    /// Shading-resource key the `sh` operator named, with the
    /// leading `/` stripped (e.g. `"Sh1"`). Empty when the operator
    /// was issued without a `/Name` operand (malformed but
    /// tolerated, mirroring the round-128 `Tj`-without-`Tf` stance).
    pub name: String,
    /// Resolved shading dictionary from `/Resources /Shading
    /// /<name>`, or `None` when the caller didn't plumb in
    /// `shading_resources` (the legacy entry points) or when the
    /// name wasn't a key in the supplied resources.
    pub shading_dict: Option<Dict>,
    /// Effective CTM at the moment of the paint — composed of every
    /// `cm` operator in every enclosing `q` frame, root-to-leaf.
    pub ctm: Transform2D,
    /// Active clip path from the current `q` frame's most recent
    /// `W`/`W*`. `None` when no clip is in force.
    pub clip: Option<Path>,
    /// Evaluated mesh geometry for a Type 4–7 shading (free-form /
    /// lattice-form Gouraud triangle mesh, Coons patch mesh, or
    /// tensor-product patch mesh, §8.7.4.5.5–8.7.4.5.8). `None` for an
    /// axial / radial / function-based shading (Types 1–3, which carry
    /// their colour in the `Function` entry rather than a mesh stream),
    /// for a shading the caller didn't plumb resources for, or for a
    /// mesh whose stream / colour space / function couldn't be reduced
    /// to evaluated RGB vertices. Coordinates are in the shading's
    /// target coordinate space (pre-`ctm`); apply `ctm` to map them to
    /// device space.
    pub mesh: Option<MeshShading>,
    /// Evaluated gradient geometry + sampled colour stops for a Type 1–3
    /// shading (function-based / axial / radial, §8.7.4.5.2–4). `None`
    /// for a Type 4–7 mesh shading (use [`mesh`](Self::mesh) instead),
    /// for a shading the caller didn't plumb resources for, or for a
    /// shading whose colour space / function couldn't be evaluated.
    /// Coordinates are in the shading's target coordinate space
    /// (pre-`ctm`).
    pub gradient: Option<ShadingGradient>,
}

/// Evaluated geometry + sampled colour for a Type 1–3 shading
/// (§8.7.4.5.2–4). The colour function is sampled at a fixed resolution
/// so a downstream rasteriser sees concrete RGB stops rather than an
/// abstract function object; the geometry (axis / circles / domain
/// rectangle) and `Extend` flags are carried so the consumer can map a
/// device-space point to its parametric value.
#[derive(Clone, Debug, PartialEq)]
pub enum ShadingGradient {
    /// Type 2 (axial) shading (§8.7.4.5.3): a colour blend along the
    /// linear axis from `(x0, y0)` to `(x1, y1)`.
    Axial {
        /// Axis endpoints `[x0, y0, x1, y1]` (`Coords`) in target space.
        coords: [f32; 4],
        /// `Extend` flags `[before, after]` (§8.7.4.5.3).
        extend: [bool; 2],
        /// Colour stops sampled uniformly across the `Domain` `[t0, t1]`,
        /// from `t0` (first) to `t1` (last).
        stops: Vec<Rgba>,
    },
    /// Type 3 (radial) shading (§8.7.4.5.4): a colour blend between the
    /// circle `(x0, y0, r0)` and `(x1, y1, r1)`.
    Radial {
        /// Circle parameters `[x0, y0, r0, x1, y1, r1]` (`Coords`).
        coords: [f32; 6],
        /// `Extend` flags `[before, after]` (§8.7.4.5.4).
        extend: [bool; 2],
        /// Colour stops sampled uniformly across the `Domain` `[t0, t1]`,
        /// from the starting circle (`s = 0`) to the ending circle
        /// (`s = 1`).
        stops: Vec<Rgba>,
    },
    /// Type 1 (function-based) shading (§8.7.4.5.2): the colour at every
    /// point of the `Domain` rectangle is the value of a 2-in / n-out
    /// function. Sampled onto a uniform grid over the domain.
    FunctionBased {
        /// Domain rectangle `[xmin, xmax, ymin, ymax]` (`Domain`).
        domain: [f32; 4],
        /// `Matrix` mapping the domain rectangle into target space.
        matrix: Transform2D,
        /// Grid width / height (samples per axis).
        grid: (usize, usize),
        /// `grid.0 × grid.1` sampled colours, row-major with the first
        /// (x) axis varying fastest; sample `(i, j)` at index
        /// `j * grid.0 + i` corresponds to domain point
        /// `(xmin + i·dx, ymin + j·dy)`.
        samples: Vec<Rgba>,
    },
}

/// Evaluated geometry + colour for a Type 4–7 shading (§8.7.4.5.5–8).
/// All four mesh types reduce to either a list of Gouraud-shaded
/// triangles (Types 4 and 5) or a list of colour patches each bounded
/// by four cubic Bézier curves (Types 6 and 7), so this enum carries
/// the two shapes. Every coordinate is in the shading's target
/// coordinate space (the pre-`ctm` space the stream's `Decode` array
/// maps into); every colour is already reduced to device RGB through
/// the shading's colour space (and its optional parametric `Function`).
#[derive(Clone, Debug, PartialEq)]
pub enum MeshShading {
    /// Types 4 (free-form) and 5 (lattice-form) Gouraud-shaded triangle
    /// meshes. Each triangle carries three [`MeshVertex`]es; the
    /// interior colour is the Gouraud (barycentric-linear) interpolation
    /// of the three vertex colours.
    Triangles(Vec<MeshTriangle>),
    /// Types 6 (Coons) and 7 (tensor-product) patch meshes. Each patch
    /// is a bicubic surface bounded by four cubic Bézier curves with a
    /// colour at each of its four corners (bilinearly interpolated over
    /// the patch interior).
    Patches(Vec<MeshPatch>),
}

/// One Gouraud-shaded triangle of a Type 4 / Type 5 mesh (§8.7.4.5.5).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MeshTriangle {
    /// The three vertices, in stream order. The shaded colour at an
    /// interior point is the barycentric-linear blend of the three
    /// vertex colours (Gouraud interpolation).
    pub vertices: [MeshVertex; 3],
}

/// One vertex of a Gouraud triangle mesh: a target-space coordinate
/// plus its evaluated device-RGB colour (§8.7.4.5.5).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MeshVertex {
    /// Vertex coordinate in the shading's target coordinate space
    /// (pre-`ctm`).
    pub point: Point,
    /// Evaluated device-RGB colour at the vertex.
    pub color: Rgba,
}

/// One colour patch of a Type 6 (Coons) / Type 7 (tensor-product) patch
/// mesh (§8.7.4.5.7–8). The patch geometry is a bicubic surface; Type 6
/// patches are stored as the equivalent tensor-product patch (the four
/// internal control points derived from the boundary curves per the
/// §8.7.4.5.8 conversion equations), so both types share this 4×4
/// control-point representation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MeshPatch {
    /// The 16 tensor-product control points `p[col][row]` (§8.7.4.5.8
    /// Figure 32) in the shading's target coordinate space. For a Type 6
    /// Coons patch the four internal points (`p[1][1]`, `p[1][2]`,
    /// `p[2][1]`, `p[2][2]`) are computed from the boundary curves.
    pub control_points: [[Point; 4]; 4],
    /// The four corner colours, in the §8.7.4.5.7 corner order
    /// (`c1`=`p00`, `c2`=`p03`, `c3`=`p33`, `c4`=`p30`). The patch
    /// interior colour is the bilinear interpolation of these four.
    pub corner_colors: [Rgba; 4],
}

/// One marked-content operator surfaced by
/// [`parse_content_stream_full_with_properties`]. ISO 32000-1 §14.6
/// defines five marked-content operators (Table 320) that fall into
/// two shapes:
///
/// * **Points** — `MP` (`tag`) and `DP` (`tag properties`) designate a
///   single marked-content point in the stream.
/// * **Sequences** — `BMC` (`tag`) and `BDC` (`tag properties`) begin a
///   sequence terminated by a balancing `EMC`.
///
/// One [`ContentMarkedContent`] is recorded per operator in stream
/// order, so a downstream consumer can reconstruct the marked-content
/// tree (e.g. to find an `/OC` membership tag for optional content,
/// §8.11.3.2, or an `/ActualText` / `/Alt` accessibility entry,
/// §14.9.4). The walker does **not** interpret the property list — its
/// entries stay verbatim in `properties` so a downstream consumer can
/// resolve `/OC`, `/MCID`, `/ActualText`, etc. as it sees fit.
#[derive(Clone, Debug)]
pub struct ContentMarkedContent {
    /// Which marked-content operator produced this event.
    pub operator: MarkedContentOp,
    /// The `tag` operand — a `Name` indicating the role or significance
    /// of the marked content (e.g. `"OC"`, `"Span"`, `"P"`), leading
    /// `/` stripped. `EMC` carries no tag, so its `tag` is empty.
    pub tag: String,
    /// The resolved property list for `DP` / `BDC` (§14.6.2): either the
    /// inline `<< … >>` dictionary written directly after the tag, or
    /// the dictionary named in `/Resources /Properties` when the
    /// operand was a `/Name`. `None` for `MP` / `BMC` / `EMC` (which
    /// carry no property list) and for a `DP` / `BDC` whose `/Name`
    /// operand wasn't resolvable against the supplied
    /// `properties_resources`.
    pub properties: Option<Dict>,
    /// Nesting depth at the moment the operator fired, counting
    /// `BMC`/`BDC`-opened sequences only (`MP`/`DP` points do not nest).
    /// `BMC`/`BDC` report the depth of the sequence they open (0 for a
    /// top-level sequence); the matching `EMC` reports the same depth;
    /// `MP`/`DP` report the depth of the sequence that encloses them
    /// (0 when not inside any). An unbalanced `EMC` (no open sequence)
    /// reports depth 0 and is tolerated.
    pub depth: u32,
}

/// Discriminator for [`ContentMarkedContent::operator`] (ISO 32000-1
/// §14.6 Table 320).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkedContentOp {
    /// `tag MP` — designate a marked-content point.
    Mp,
    /// `tag properties DP` — marked-content point with a property list.
    Dp,
    /// `tag BMC` — begin a marked-content sequence.
    Bmc,
    /// `tag properties BDC` — begin a sequence with a property list.
    Bdc,
    /// `EMC` — end the most recent `BMC`/`BDC` sequence.
    Emc,
}

// ───────────────────────── parser state ─────────────────────────

/// Per-graphics-state tracker. Pushed on `q`, popped on `Q`. The
/// active state is `stack.last_mut().unwrap()`; the always-present
/// root frame collects whatever the input emits before any explicit
/// `q`/`Q`.
struct State<'a> {
    /// Argument stack — operands are pushed as the parser scans
    /// numbers, names, arrays; an operator keyword consumes them.
    operands: Vec<Operand>,
    /// Group stack mirroring PDF's graphics-state stack.
    stack: Vec<Frame>,
    /// Current path being built (the most recent `m`/`l`/`c`/`re`
    /// sequence). `None` after a paint operator commits it.
    current_path: Option<Path>,
    /// Tracking for the current path's last endpoint — needed to
    /// handle the shorthand cubics `v` (use current pt as c1) and
    /// `y` (use end pt as c2).
    current_point: Point,
    /// Last set fill / stroke paint state. Reset on each `q`/`Q`
    /// (PDF graphics state) since `q` saves the entire colour /
    /// stroke state and `Q` restores it.
    fill_paint: Option<Paint>,
    stroke_paint: Option<Paint>,
    /// Current nonstroking colour space, selected by `cs` (§8.6.8
    /// Table 74). `sc`/`scn` interpret their numeric operands against
    /// it. Defaults to `DeviceGray` per §8.6.3 Table 73 (the initial
    /// colour space for nonstroking operations).
    fill_cs: ColorSpaceKind,
    /// Current stroking colour space, selected by `CS`.
    stroke_cs: ColorSpaceKind,
    stroke_width: f32,
    line_cap: LineCap,
    line_join: LineJoin,
    miter_limit: f32,
    dash: Option<DashPattern>,
    /// Current nonstroking alpha constant (`ca`, §11.6.4.4 + Table
    /// 58). Multiplied into the fill paint's per-channel alpha at
    /// `commit_path`. Initial value 1.0 per the table.
    fill_alpha: f32,
    /// Current stroking alpha constant (`CA`, §11.6.4.4 + Table 58).
    /// Mirror of `fill_alpha` for the stroke side.
    stroke_alpha: f32,
    /// Page's `/Resources /ExtGState` subdictionary, if the caller
    /// went through [`parse_content_stream_with_resources`] — `None`
    /// for the legacy entry point. Used by the `gs` dispatcher to
    /// look up the named parameter dict per §8.4.5.
    ext_gstate: Option<&'a Dict>,
    /// Page's `/Resources /Font` subdictionary, if the caller went
    /// through [`parse_content_stream_full`] — `None` otherwise. Each
    /// per-name entry should already be a direct `Object::Dict`
    /// (single-hop indirect references dereferenced by
    /// `reader::document::resolve_font_resources`). When this is
    /// `Some`, `Tj`/`TJ`/`'`/`"` operators emit
    /// [`ContentTextShow`] events; when it's `None`, text-show
    /// operators stay round-3-no-op.
    font_resources: Option<&'a Dict>,
    /// Page's `/Resources /Shading` subdictionary, if the caller
    /// went through [`parse_content_stream_full_with_shading`] —
    /// `None` otherwise. Each per-name entry should already be a
    /// direct `Object::Dict` (single-hop indirect references
    /// dereferenced by `reader::document::resolve_shading_resources`).
    /// When this is `Some`, a `sh` operator emits a
    /// [`ContentShading`] with `shading_dict` populated; when it's
    /// `None`, the event still fires (so the consumer sees the
    /// operator + name + CTM + clip) but `shading_dict` stays
    /// `None`.
    shading_resources: Option<&'a Dict>,
    /// Page's `/Resources /ColorSpace` subdictionary, if the caller
    /// went through [`parse_content_stream_full_with_color_space`] —
    /// `None` otherwise. Each per-name entry is the resolved
    /// colour-space `Object` (a bare device `/Name`, an `[/ICCBased
    /// <dict>]` array with the ICC profile stream replaced by its
    /// dictionary, or an `[/Indexed base hival lookup]` array with the
    /// lookup stream replaced by its decoded bytes), produced by
    /// [`crate::reader::document::resolve_color_space_resources`]. When
    /// this is `Some`, a `cs`/`CS` naming a key in it resolves against
    /// it (§8.6.5.5 ICCBased + §8.6.6.3 Indexed device fallbacks); when
    /// it's `None`, a non-device `cs`/`CS` name stays `Unknown`,
    /// matching the round-118 conservative black fallback.
    color_space_resources: Option<&'a Dict>,
    /// Page's `/Resources /Properties` subdictionary, if the caller
    /// went through [`parse_content_stream_full_with_properties`] —
    /// `None` otherwise. A `DP` / `BDC` whose `properties` operand is a
    /// `/Name` (rather than an inline `<< … >>` dictionary, §14.6.2)
    /// looks the name up here. Each per-name entry should already be a
    /// direct `Object::Dict` (single-hop indirect references
    /// dereferenced by
    /// `reader::document::resolve_properties_resources`). When this is
    /// `None` or doesn't contain the named key, the marked-content
    /// event still fires but its `properties` stays `None`.
    properties_resources: Option<&'a Dict>,
    /// Open `BMC`/`BDC` sequence count (§14.6). Incremented after a
    /// `BMC`/`BDC`, decremented before a matching `EMC` (saturating at
    /// 0 so an unbalanced `EMC` is tolerated). Reported as the
    /// `ContentMarkedContent::depth` of each event.
    mc_depth: u32,
    /// Stream-order marked-content events accumulated for the
    /// [`ParsedContent::marked_content`] return slot.
    marked_content: Vec<ContentMarkedContent>,
    /// Currently-selected font: name (Tf operand, leading `/`
    /// stripped) + size. Reset on each `Tf`. Cleared when no `Tf`
    /// has been seen yet — `Tj` then emits with an empty `font_name`
    /// and `font_size = 0.0`.
    current_font: Option<(String, f32)>,
    /// Text matrix `Tm` (§9.4.4 — six-element matrix
    /// `[ a b c d e f ]`). Reset to identity by every `BT`; updated
    /// by `Tm`, `Td`, `TD`, `T*`, and the implicit `T*` inside `'`
    /// and `"`.
    text_matrix: Transform2D,
    /// Text line matrix `Tlm` — duplicated from `Tm` by every
    /// `BT`/`Td`/`TD`/`Tm`, advanced (combined with leading) by
    /// `T*`/`'`/`"` to give the next line's origin (§9.4.4 "the text
    /// line matrix … records the start of the next line").
    text_line_matrix: Transform2D,
    /// Text leading `TL` (§9.3.5) — the y-step `T*` uses. Defaults
    /// to 0.0 per Table 105. Set by `TL` and by the implicit `TL` a
    /// `"` operator emits.
    text_leading: f32,
    /// Character spacing `Tc` (§9.3.2) in unscaled text-space units.
    /// Added to the horizontal component of every glyph's
    /// displacement (§9.4.4). Default 0.0 (Table 105). Set by `Tc`,
    /// and by the implicit `Tc` a `"` operator emits.
    char_spacing: f32,
    /// Word spacing `Tw` (§9.3.3) in unscaled text-space units.
    /// Added to the displacement of every single-byte code 32
    /// (ASCII space) glyph (§9.4.4). Default 0.0 (Table 105). Set by
    /// `Tw`, and by the implicit `Tw` a `"` operator emits.
    word_spacing: f32,
    /// Horizontal scaling `Th` (§9.3.4), stored as a fraction
    /// (`scale ÷ 100`). Scales the horizontal text-space displacement
    /// (§9.4.4). Default 1.0 (Table 105 default `100`). Set by `Tz`.
    horiz_scale: f32,
    /// Whether the parser is currently inside a `BT … ET` text
    /// object (§9.4 — operators outside a `BT` are silently ignored
    /// per Table 105). Toggled by `BT` (`true`) and `ET` (`false`).
    in_text_object: bool,
    /// Stream-order text-show events accumulated for the round-128
    /// [`ParsedContent::text_shows`] return slot.
    text_shows: Vec<ContentTextShow>,
    /// Stream-order `sh`-paint events accumulated for the round-259
    /// [`ParsedContent::shadings`] return slot.
    shadings: Vec<ContentShading>,
    /// Stream-order `BI … ID … EI` inline-image events accumulated for
    /// the [`ParsedContent::inline_images`] return slot.
    inline_images: Vec<ContentInlineImage>,
    /// Pre-parsed Form XObjects from the page's `/Resources /XObject`
    /// subdictionary, keyed by resource name (leading `/` stripped),
    /// supplied by [`parse_content_stream_full_with_xobjects`] — `None`
    /// for the legacy entry points. Each value is the form's content
    /// stream already parsed into a [`Group`] (§8.10.1) whose
    /// `transform` is the form's `/Matrix` and whose `clip` is the
    /// `/BBox` rectangle, so a `name Do` against it splices the group
    /// under the current CTM with a single clone. When this is `None`
    /// or doesn't contain the named key, `Do` stays a tolerated no-op
    /// (matching the round-3 drop). Image XObjects are not stored here
    /// — they are surfaced through the dedicated
    /// [`crate::reader::images`] walker.
    xobject_forms: Option<&'a BTreeMap<String, Group>>,
    /// Page's `/Resources /Pattern` subdictionary, if plumbed in. Each
    /// per-name entry is the pattern's resolved dictionary (for a
    /// `/PatternType 2` shading pattern, its `/Shading` subdictionary is
    /// folded in place exactly like `/Resources /Shading` entries, so a
    /// `scn /Pname` fill can evaluate the shading's gradient). When this
    /// is `None` or the named pattern isn't a renderable shading
    /// pattern, a `scn` pattern operand keeps the conservative black
    /// fallback (the round-3 behaviour).
    pattern_resources: Option<&'a Dict>,
    /// Pre-parsed `/PatternType 1` tiling patterns from the page's
    /// `/Resources /Pattern` subdictionary, keyed by resource name,
    /// supplied by [`parse_content_stream_full_with_tiling`] (§8.7.3).
    /// Each value carries the pattern cell already parsed into a
    /// [`Group`] plus its `/BBox` clip, `/XStep` / `/YStep` spacing,
    /// `/Matrix`, and `/PaintType`, so a `scn /Pname` fill naming a
    /// tiling pattern replicates the cell across the filled region
    /// (§8.7.3.1) instead of the conservative black fallback. When this
    /// is `None` or the named pattern isn't a tiling pattern, a `scn`
    /// pattern operand keeps the black fallback.
    tiling_patterns: Option<&'a BTreeMap<String, TilingPattern>>,
    /// Name of the active `/PatternType 1` tiling pattern for the
    /// nonstroking colour, set by a `scn /Pname` whose `/Pname` resolves
    /// to a [`TilingPattern`]. Consumed (and cleared by a subsequent
    /// non-pattern colour operator) at `commit_path` fill time to tile
    /// the painted region. `None` when no tiling fill is in force.
    fill_tiling: Option<String>,
    /// Underlying colour for an *uncoloured* (`/PaintType 2`) tiling
    /// pattern fill (§8.7.3.3): the numeric components a `scn` supplies
    /// before the pattern name, in the Pattern colour space's underlying
    /// space (read by component count — 1 gray / 3 RGB / 4 CMYK). The
    /// cell is a stencil poured with this colour. `None` for a coloured
    /// (`/PaintType 1`) pattern or when no components were supplied.
    fill_tiling_color: Option<Rgba>,
    /// Name of the active tiling pattern for the stroking colour
    /// (`SCN /Pname`). Strokes are not tiled — a tiling-stroke pattern
    /// keeps the black fallback — but the name is tracked symmetrically
    /// so a stroking `SCN /Pname` clears the previous solid stroke
    /// rather than leaving a stale colour.
    stroke_tiling: Option<String>,
    /// Pre-parsed Type 3 fonts (§9.6.5) from the page's
    /// `/Resources /Font` subdictionary, keyed by font resource name
    /// (leading `/` stripped), supplied by
    /// [`parse_content_stream_full_with_type3`]. When a `Tj`/`TJ`/`'`/`"`
    /// show runs under a font name present here, each character code's
    /// glyph description [`Group`] is spliced into the scene tree at the
    /// glyph's text-rendering matrix (§9.4.4) composed with the font's
    /// `/FontMatrix`. When this is `None` or the active font isn't a
    /// Type 3 font, text-show operators stay event-only on the vector
    /// side (Type 1 / TrueType / Type 0 outlines need a glyph
    /// rasteriser this walker doesn't carry).
    type3_fonts: Option<&'a BTreeMap<String, Type3Font>>,
    /// Text rendering mode `Tr` (§9.3.6 Table 106). Only mode `3`
    /// (invisible — the OCR layer) suppresses Type 3 glyph painting;
    /// every other mode paints. Default `0` (fill). Tracked here only
    /// for the Type 3 paint path; the dedicated text-extraction walker
    /// surfaces the mode independently.
    text_render_mode: i64,
    /// Text rise `Ts` (§9.4.4) in unscaled text-space units — the
    /// vertical offset baked into the text-rendering matrix's `f`
    /// component. Raises (positive) / lowers (negative) the glyph
    /// baseline. Default `0.0`.
    text_rise: f32,
    /// Re-entrancy guard for the Type 3 glyph paint path. A glyph
    /// description is itself a content stream that may show text in
    /// another (or the same) Type 3 font; this caps the nesting so a
    /// self-referential `/CharProcs` entry can't recurse without bound.
    type3_depth: u32,
    /// Pre-resolved `/ExtGState /SMask` soft-mask dictionaries
    /// (§11.6.5.2), keyed by ExtGState resource name, supplied by
    /// [`parse_content_stream_full_with_soft_masks`]. When a `gs`
    /// names an entry present here, the mask becomes the current soft
    /// mask (§11.6.4.3) and subsequently painted objects are wrapped
    /// in [`Node::SoftMask`]. `None` (the legacy entry points) leaves
    /// `/SMask` a tolerated no-op.
    soft_masks: Option<&'a BTreeMap<String, ResolvedSoftMask>>,
    /// The soft mask currently in force (§11.6.4.3). Part of the
    /// graphics state — bracketed by `q`/`Q` via [`GStateSnapshot`].
    active_smask: Option<ActiveSoftMask>,
    /// Names (within `xobject_forms`) of the forms that are
    /// *transparency-group* XObjects — a `/Group` entry whose subtype
    /// `/S` is `/Transparency` (§11.6.6 Table 147). A `Do` on one
    /// composites the group's results into the parent as a unit, so
    /// the §11.6.4.4 nonstroking alpha constant lands on the spliced
    /// group's opacity ("The nonstroking alpha constant shall also be
    /// applied when painting a transparency group's results onto its
    /// backdrop"). An ordinary form — no `/Group` entry — "shall not
    /// be subject to any grouping behaviour for transparency
    /// purposes".
    transparency_groups: Option<&'a BTreeSet<String>>,
    /// Pre-decoded Image XObjects (§8.9.5) from the page's
    /// `/Resources /XObject` subdictionary, keyed by resource name. A
    /// `Do` naming one splices a [`Node::Image`] into the scene — the
    /// image fills the unit square of the space the `Do` executes in
    /// (§8.9.5.2), with sample (0,0) on the top edge. `None` (or a
    /// name not present, e.g. an undecodable codec payload) keeps the
    /// image-`Do` a scene no-op, surfaced separately by the
    /// passthrough walker.
    image_xobjects: Option<&'a BTreeMap<String, ResolvedImageXObject>>,
}

/// A `/PatternType 1` tiling pattern (§8.7.3) reduced to what the
/// content walker needs to replicate its cell across a filled region:
/// the cell's content pre-parsed into a [`Group`] (against the pattern's
/// own `/Resources`), the `/BBox` clip rectangle, the `/XStep` / `/YStep`
/// replication spacing, the `/Matrix` mapping pattern space to the page's
/// default coordinate system (§8.7.2 NOTE 1), and the `/PaintType`
/// (1 = coloured, 2 = uncoloured stencil).
#[derive(Clone, Debug)]
pub struct TilingPattern {
    /// Cell content stream parsed into a group (its `/Resources` already
    /// resolved). Each tile clones this group under a per-tile transform.
    pub cell: Group,
    /// `/BBox` — `[llx, lly, urx, ury]` in pattern space; clips each
    /// tile (§8.7.3.1 Table 75).
    pub bbox: [f32; 4],
    /// `/XStep` — horizontal replication interval in pattern space.
    /// Non-zero per Table 75.
    pub xstep: f32,
    /// `/YStep` — vertical replication interval in pattern space.
    pub ystep: f32,
    /// `/Matrix` — maps pattern space to the parent content stream's
    /// default coordinate space (§8.7.2). Identity when absent.
    pub matrix: Transform2D,
    /// `/PaintType` — 1 (coloured: cell carries its own colours) or 2
    /// (uncoloured: cell is a stencil poured with the current colour).
    pub paint_type: i64,
}

/// A Type 3 font (§9.6.5) reduced to what the content walker needs to
/// paint its glyphs as vector geometry. Unlike Type 1 / TrueType fonts
/// — whose glyph outlines live in an external font program that a
/// software renderer would have to rasterise — a Type 3 font defines
/// each glyph as a *content stream* of PDF graphics operators
/// (`/CharProcs`). Those operators are exactly the marking operators
/// this walker already understands, so each glyph description can be
/// pre-parsed into a [`Group`] and spliced into the scene tree at the
/// glyph's text-rendering matrix.
///
/// Per §9.6.5 the conforming reader, for each shown character code:
///   a) looks the code up in `/Encoding` (`/Differences`) to get a
///      glyph name;
///   b) looks the glyph name up in `/CharProcs` to get a glyph
///      description stream (no key → no glyph painted);
///   c) invokes the description with the CTM set to the concatenation
///      of `/FontMatrix` and the text space in effect at show time.
#[derive(Clone, Debug)]
pub struct Type3Font {
    /// `/FontMatrix` — maps glyph space to text space (§9.2.4). Each
    /// glyph `Group` is painted under `text_render_matrix ∘ FontMatrix`.
    pub font_matrix: Transform2D,
    /// Code → glyph name, built from `/Encoding /Differences` (§9.6.6.1).
    /// A code absent here paints nothing.
    pub encoding: BTreeMap<u8, String>,
    /// Glyph name → pre-parsed glyph description. Each value is the
    /// `/CharProcs` content stream (with its leading `d0` / `d1`
    /// stripped, §9.6.5 Table 113) parsed against the font's own
    /// `/Resources` into a [`Group`]. A glyph name in `encoding` but
    /// not here paints nothing.
    pub glyphs: BTreeMap<String, Group>,
    /// Glyph names whose description began with `d1` (§9.6.5 Table 113):
    /// the glyph specifies *shape only*, and its colour comes from the
    /// graphics state in force when the text-showing operator runs. A
    /// `d0` glyph (or one with neither) specifies its own colour and is
    /// painted with the colours baked into its `Group`.
    pub shape_only: BTreeSet<String>,
}

/// An `/ExtGState /SMask` soft-mask dictionary (§11.6.5.2 Table 144)
/// resolved to what the content walker needs to composite painted
/// objects through it: the `/G` transparency-group XObject pre-parsed
/// into a [`Group`] (its `/Matrix` on the group transform, its `/BBox`
/// as the group clip, its content parsed against its own
/// `/Resources`), and the `/S` subtype mapped onto the core IR's
/// [`MaskKind`] — `/Luminosity` (§11.5.3, the group's computed colour
/// converted to a single-component luminosity) becomes
/// [`MaskKind::Luminance`], `/Alpha` (§11.5.2, the group's computed
/// alpha with colours disregarded) becomes [`MaskKind::Alpha`].
#[derive(Clone, Debug)]
pub struct ResolvedSoftMask {
    /// `/S` — the mask-derivation subtype (Table 144).
    pub kind: MaskKind,
    /// `/G` — the transparency-group XObject parsed into a group
    /// exactly like a `Do`-spliced Form XObject (§8.10.1). For a
    /// luminosity mask whose dictionary carries a `/BC` backdrop
    /// colour, the group's first child is the backdrop: a `/BBox`
    /// rectangle poured with `/BC` *under* the group content —
    /// §11.6.5.2, "the transparency group XObject G shall be
    /// composited with a fully opaque backdrop whose colour is
    /// everywhere defined by the soft-mask dictionary's BC entry"
    /// (default: black, which the unpainted mask area already
    /// evaluates to, so no rectangle is inserted).
    pub mask: Group,
}

/// An Image XObject (§8.9.5) decoded to straight RGBA8 for splicing
/// into the `Scene` at `Do` time. Only the fully-decodable shape is
/// resolved here — a filter chain the crate decodes end-to-end
/// (Flate / LZW / ASCII / RunLength / none), `/BitsPerComponent 8`,
/// and a `/DeviceRGB` or `/DeviceGray` colour space — optionally
/// combined with a same-shape `/SMask` soft-mask image (§11.6.5.3)
/// supplying the alpha channel. Image-codec payloads (DCTDecode /
/// JPXDecode / …) stay on the [`crate::reader::images`] passthrough
/// walker.
#[derive(Clone, Debug)]
pub struct ResolvedImageXObject {
    /// `/Width` in samples.
    pub width: u32,
    /// `/Height` in samples.
    pub height: u32,
    /// Straight (non-premultiplied) RGBA8, row-major, row 0 = the
    /// image's top row (§8.9.5.2 sample (0,0)).
    pub rgba: Vec<u8>,
}

/// The soft mask currently in force in the graphics state (§11.6.4.3),
/// established by a `gs` whose parameter dictionary carried an
/// `/SMask` soft-mask dictionary and cleared by `/SMask /None` (or a
/// `Q` restoring a state saved before the mask was set).
#[derive(Clone)]
struct ActiveSoftMask {
    /// The resolved `/G` group, shared so per-paint wrapping doesn't
    /// deep-clone until a painted node actually needs it.
    mask: Rc<Node>,
    /// `/S` subtype mapped to the IR mask kind.
    kind: MaskKind,
    /// User-space CTM at the moment the mask was established — §11.6.5.2:
    /// "The mask's coordinate system shall be defined by concatenating
    /// the … Matrix entry in the transparency group's form dictionary
    /// with the current transformation matrix at the moment the soft
    /// mask is established in the graphics state with the gs operator."
    /// (`Matrix` is already on the mask group's transform.)
    ctm: Transform2D,
}

struct Frame {
    /// Transform applied to this group via `cm` operators since `q`.
    transform: Transform2D,
    /// Children accumulated while this `q` is active.
    children: Vec<Node>,
    /// Clip path, if a `W`/`W*` was issued.
    clip: Option<Path>,
    /// Snapshot of the device-independent graphics-state parameters
    /// (§8.4.1 Table 52) taken by the `q` that opened this frame, so the
    /// matching `Q` can "restore the graphics state by removing the most
    /// recently saved state from the stack and making it the current
    /// state" (§8.4.4 Table 57). The root frame — which no `q` opened —
    /// carries `None` and restores nothing.
    saved: Option<Box<GStateSnapshot>>,
}

/// The subset of §8.4.1 Table 52 graphics-state parameters this walker
/// tracks as mutable `State` fields, captured on `q` and restored on
/// `Q`. The CTM and clipping path are excluded — they live on [`Frame`]
/// itself (the nested-group structure *is* their save/restore). The
/// text-object matrices (`Tm` / `Tlm`) are also excluded: they are not
/// graphics-state parameters (§9.4.2 — they exist only within a
/// `BT`…`ET` block), unlike the Table 52 *text state* parameters
/// (`Tc` / `Tw` / `Th` / `Tl` / font / `Tmode` / `Trise`) which are
/// saved here.
struct GStateSnapshot {
    fill_paint: Option<Paint>,
    stroke_paint: Option<Paint>,
    fill_cs: ColorSpaceKind,
    stroke_cs: ColorSpaceKind,
    stroke_width: f32,
    line_cap: LineCap,
    line_join: LineJoin,
    miter_limit: f32,
    dash: Option<DashPattern>,
    fill_alpha: f32,
    stroke_alpha: f32,
    current_font: Option<(String, f32)>,
    text_leading: f32,
    char_spacing: f32,
    word_spacing: f32,
    horiz_scale: f32,
    text_render_mode: i64,
    text_rise: f32,
    fill_tiling: Option<String>,
    fill_tiling_color: Option<Rgba>,
    stroke_tiling: Option<String>,
    /// Current soft mask (§11.6.4.3 Table 52 — part of the graphics
    /// state, so saved/restored with the rest of the snapshot).
    active_smask: Option<ActiveSoftMask>,
}

#[derive(Clone, Debug)]
enum Operand {
    Number(f32),
    /// Heterogeneous PDF array `[ ... ]`. The `d` operator filters
    /// out non-`Number` elements; `TJ` walks the mix of strings +
    /// numbers in array order.
    Array(Vec<ArrayElem>),
    /// Name operand. Read by `cs` / `CS` (to pick the colour space)
    /// and by `sc` / `scn` (a trailing `/Name` marks a Pattern fill,
    /// §8.7.3.3) and by `Tf` (font resource name). Resource lookups
    /// against `/Resources` for non-device colour spaces / gradients
    /// / patterns still land later, when the page's resolved
    /// Document is available.
    Name(String),
    /// Literal-or-hex PDF string `(...)` / `<...>`. Held as raw
    /// bytes (escape-decoded for literal strings, hex-pair-decoded
    /// for hex strings); consumed by `Tj` / `'` / `"`.
    String(Vec<u8>),
    /// Inline dictionary `<< … >>`. The only content-stream operators
    /// that take one are the §14.6.2 property-list carriers `DP` /
    /// `BDC` (the `properties` operand may be written inline when every
    /// value is a direct object). Held verbatim so the marked-content
    /// dispatcher can surface it as `ContentMarkedContent::properties`.
    Dict(Dict),
}

/// One element of a PDF content-stream array operand `[ ... ]`. PDF
/// arrays inside content streams carry either numbers (the `d`
/// operator's dash-array) or a mix of numbers + strings (the `TJ`
/// operator's per-element kerning displacements). We keep both shapes
/// in a single enum so the parser can stay agnostic until the
/// consuming operator dispatches.
#[derive(Clone, Debug)]
enum ArrayElem {
    Number(f32),
    String(Vec<u8>),
}

/// One element of a `TJ` array, used while advancing the text matrix
/// (§9.4.3 / §9.4.4): a shown string or a numeric kern adjustment
/// (thousandths of a text-space unit).
enum TjElem {
    Str(Vec<u8>),
    Kern(f32),
}

/// A PDF function (ISO 32000-1 §7.10) reduced to the two
/// function types this content parser can evaluate at a 1-input call
/// site (Separation tint transforms, §8.6.6.4):
///
/// * **Type 0** (sampled, §7.10.2) — a sample table read from the
///   stream body, with the §7.10.2 Encode/Decode linear mappings and
///   Order-1 linear interpolation between adjacent samples.
/// * **Type 2** (exponential interpolation, §7.10.3) —
///   `f(x) = C0 + x^N · (C1 − C0)`, one input, `n` outputs.
/// * **Type 3** (stitching, §7.10.4) — a 1-input function partitioned
///   across `k` subdomains, each evaluated by a child [`PdfFunction`].
/// * **Type 4** (PostScript calculator, §7.10.5) — a small stack
///   machine over the §7.10.5 / Annex B operator subset. The program
///   text is folded into the dictionary under `__Program` by
///   `prepare_function_object`; [`PdfFunction::parse`] tokenises it into
///   a nested expression tree and [`PdfFunction::eval`] runs it with the
///   1-input call site's argument seeded on the operand stack.
///
/// All carry the §7.10.1 Table 38 `Domain` (always 1-input here) and the
/// `Range` — required for Type 0 and Type 4, optional output-clip for
/// Type 2/3. A malformed program leaves the owning Separation space
/// `Unknown` (conservative black fallback).
#[derive(Clone, Debug, PartialEq)]
enum PdfFunction {
    /// §7.10.3 Type 2: exponential interpolation between `c0` and `c1`
    /// with exponent `n`. `domain` is `[d0, d1]` (input clip);
    /// `range`, when present, is `2·outputs` output-clip bounds.
    Exponential {
        domain: [f32; 2],
        range: Option<Vec<f32>>,
        c0: Vec<f32>,
        c1: Vec<f32>,
        n: f32,
    },
    /// §7.10.4 Type 3: stitching. `domain` is `[d0, d1]`; `functions`
    /// are the `k` child functions; `bounds` are the `k−1` interior
    /// partition points; `encode` is the `2·k` per-subdomain input
    /// remapping. `range`, when present, clips the final outputs.
    Stitching {
        domain: [f32; 2],
        range: Option<Vec<f32>>,
        functions: Vec<PdfFunction>,
        bounds: Vec<f32>,
        encode: Vec<f32>,
    },
    /// §7.10.2 Type 0: a sampled function with `m` input dimensions.
    /// `domain` is the `2·m` input clip (`[d0_0, d1_0, d0_1, d1_1, …]`);
    /// `range` is the required `2·n` output clip; `size` is the per-axis
    /// sample count (length `m`); `n` is the output dimensionality;
    /// `encode` is the `2·m` input→table mapping (default
    /// `[0, size_0−1, 0, size_1−1, …]`); `decode` is the `2·n`
    /// sample→output mapping (default `= range`); `samples` holds each
    /// sample value already widened to `f32` in storage order — the
    /// first input dimension varies fastest, output `j` of flat sample
    /// index `s` at `s·n + j` (§7.10.2 "the sample values in the first
    /// dimension vary fastest … values shall be stored in the same order
    /// as Range") — normalised out of the `[0, 2^BitsPerSample − 1]`
    /// integer interval before Decode. `order` is the §7.10.2 `/Order`
    /// interpolation degree: `1` for multilinear, `3` for the cubic-spline
    /// tensor blend (a per-axis cubic that passes through the four nearest
    /// samples). Per §7.10.2, a `/Size` below 4 on an axis falls back to
    /// linear interpolation on that axis even when `order == 3`.
    Sampled {
        domain: Vec<f32>,
        range: Vec<f32>,
        size: Vec<usize>,
        n: usize,
        encode: Vec<f32>,
        decode: Vec<f32>,
        samples: Vec<f32>,
        order: u8,
    },
    /// §7.10.5 Type 4: a PostScript-calculator program. `domain` is the
    /// `2·m` input clip (one `[d0 d1]` pair per input variable — a
    /// 1-input call site supplies `m = 1`, a DeviceN tint transform
    /// supplies one pair per colorant); `range` is the required `2·n`
    /// output clip (its length also fixes the number of output
    /// components taken off the final operand stack); `program` is the
    /// parsed top-level expression (the body inside the outermost
    /// `{ }`).
    Calculator {
        domain: Vec<f32>,
        range: Vec<f32>,
        program: Vec<PsToken>,
    },
}

/// One token in a parsed Type 4 (PostScript-calculator) program
/// (§7.10.5). The language has no strings, arrays, names, procedures, or
/// variables — only numbers, booleans, the Table 42 operators, and brace
/// blocks used as the operands of `if` / `ifelse`.
#[derive(Clone, Debug, PartialEq)]
enum PsToken {
    /// A numeric literal (integer or real; both stored as `f32`).
    Number(f32),
    /// The `true` / `false` boolean literals.
    Bool(bool),
    /// One of the Table 42 operators, stored as its lower-case keyword.
    Op(PsOp),
    /// A `{ … }` brace block — a procedure operand for `if` / `ifelse`.
    /// Never executed directly; only consumed by the conditional
    /// operators that follow it.
    Block(Vec<PsToken>),
}

/// The §7.10.5 Table 42 / Annex B operator set permitted in a Type 4
/// function. `if` / `ifelse` are handled structurally against preceding
/// [`PsToken::Block`]s, so they are part of this set too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PsOp {
    // B.2 Arithmetic.
    Abs,
    Add,
    Atan,
    Ceiling,
    Cos,
    Cvi,
    Cvr,
    Div,
    Exp,
    Floor,
    Idiv,
    Ln,
    Log,
    Mod,
    Mul,
    Neg,
    Round,
    Sin,
    Sqrt,
    Sub,
    Truncate,
    // B.3 Relational / boolean / bitwise.
    And,
    Bitshift,
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
    Ne,
    Not,
    Or,
    Xor,
    // B.4 Conditional.
    If,
    Ifelse,
    // B.5 Stack.
    Copy,
    Dup,
    Exch,
    Index,
    Pop,
    Roll,
}

impl PsOp {
    /// Map a lower-case operator keyword to its [`PsOp`], or `None` for
    /// an unknown token (a syntax error, §7.10.5.2).
    fn from_keyword(kw: &str) -> Option<PsOp> {
        Some(match kw {
            "abs" => PsOp::Abs,
            "add" => PsOp::Add,
            "atan" => PsOp::Atan,
            "ceiling" => PsOp::Ceiling,
            "cos" => PsOp::Cos,
            "cvi" => PsOp::Cvi,
            "cvr" => PsOp::Cvr,
            "div" => PsOp::Div,
            "exp" => PsOp::Exp,
            "floor" => PsOp::Floor,
            "idiv" => PsOp::Idiv,
            "ln" => PsOp::Ln,
            "log" => PsOp::Log,
            "mod" => PsOp::Mod,
            "mul" => PsOp::Mul,
            "neg" => PsOp::Neg,
            "round" => PsOp::Round,
            "sin" => PsOp::Sin,
            "sqrt" => PsOp::Sqrt,
            "sub" => PsOp::Sub,
            "truncate" => PsOp::Truncate,
            "and" => PsOp::And,
            "bitshift" => PsOp::Bitshift,
            "eq" => PsOp::Eq,
            "ge" => PsOp::Ge,
            "gt" => PsOp::Gt,
            "le" => PsOp::Le,
            "lt" => PsOp::Lt,
            "ne" => PsOp::Ne,
            "not" => PsOp::Not,
            "or" => PsOp::Or,
            "xor" => PsOp::Xor,
            "if" => PsOp::If,
            "ifelse" => PsOp::Ifelse,
            "copy" => PsOp::Copy,
            "dup" => PsOp::Dup,
            "exch" => PsOp::Exch,
            "index" => PsOp::Index,
            "pop" => PsOp::Pop,
            "roll" => PsOp::Roll,
            _ => return None,
        })
    }
}

/// A value on the Type 4 operand stack: a number or a boolean (§7.10.5
/// permits integers, reals, and booleans only). Integers and reals are
/// both held as `f32`; the few integer-only operators (`idiv`, `mod`,
/// bitwise ops) convert on demand.
#[derive(Clone, Copy, Debug, PartialEq)]
enum PsValue {
    Num(f32),
    Bool(bool),
}

impl PdfFunction {
    /// Parse a resolved function dictionary (already normalised by
    /// `prepare_function_object`) into an evaluable [`PdfFunction`].
    /// Type 0 reads its decoded sample body from the `__Samples` entry
    /// `prepare_function_object` folds in; Type 2/3 are pure dictionary
    /// forms. Returns `None` for a Type 4 function (only its dictionary
    /// is reachable here), a Type 0 with more than one input dimension,
    /// a missing/invalid `/FunctionType`, or a malformed dictionary —
    /// every such case leaves the owning Separation space unevaluable.
    fn parse(obj: &Object) -> Option<PdfFunction> {
        let Object::Dict(dict) = obj else {
            return None;
        };
        let get = |key: &str| {
            dict.entries()
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
        };
        let range = get("Range").and_then(read_num_array);
        match get("FunctionType").and_then(number_as_i64) {
            Some(0) => {
                // §7.10.2 Table 39. `m` input dimensions (any number);
                // /Range is required and gives the output dimensionality
                // n. /Domain has 2·m entries (one [d0 d1] pair per axis).
                let domain = get("Domain").and_then(read_num_array)?;
                if domain.is_empty() || domain.len() % 2 != 0 {
                    return None;
                }
                let range = range?;
                if range.is_empty() || range.len() % 2 != 0 {
                    return None;
                }
                let n = range.len() / 2;
                // /Order ∈ {1, 3} (§7.10.2): 1 = linear (multilinear over
                // m axes), 3 = cubic spline. Any other value is malformed
                // and leaves the owning space unevaluable. Default is 1.
                let order = match get("Order").and_then(number_as_i64) {
                    Some(1) | None => 1u8,
                    Some(3) => 3u8,
                    Some(_) => return None,
                };
                // /Size is an array of m positive integers; m must match
                // /Domain's pair count.
                let size_arr = get("Size").and_then(read_num_array)?;
                let m = domain.len() / 2;
                if size_arr.len() != m {
                    return None;
                }
                let mut size = Vec::with_capacity(m);
                for s in &size_arr {
                    if !s.is_finite() || *s < 1.0 {
                        return None;
                    }
                    size.push(*s as usize);
                }
                // /BitsPerSample ∈ {1,2,4,8,12,16,24,32}.
                let bps = get("BitsPerSample").and_then(number_as_i64)?;
                if !matches!(bps, 1 | 2 | 4 | 8 | 12 | 16 | 24 | 32) {
                    return None;
                }
                let bps = bps as u32;
                // /Encode default [0 (Size_i−1)] per axis; /Decode
                // default = Range.
                let encode = match get("Encode").and_then(read_num_array) {
                    Some(e) if e.len() == 2 * m => e,
                    Some(_) => return None,
                    None => {
                        let mut e = Vec::with_capacity(2 * m);
                        for &sz in &size {
                            e.push(0.0);
                            e.push((sz as f32) - 1.0);
                        }
                        e
                    }
                };
                let decode = get("Decode")
                    .and_then(read_num_array)
                    .unwrap_or_else(|| range.clone());
                if decode.len() != 2 * n {
                    return None;
                }
                // Total sample count = (∏ Size_i) · n. Guard the product
                // against overflow for an adversarial /Size.
                let mut total: usize = 1;
                for &sz in &size {
                    total = total.checked_mul(sz)?;
                }
                let count = total.checked_mul(n)?;
                // Sample body folded in by `prepare_function_object`.
                let raw = match get("__Samples") {
                    Some(Object::HexString(bytes)) => bytes.as_slice(),
                    _ => return None,
                };
                let samples = unpack_samples(raw, bps, count)?;
                Some(PdfFunction::Sampled {
                    domain,
                    range,
                    size,
                    n,
                    encode,
                    decode,
                    samples,
                    order,
                })
            }
            Some(2) => {
                // §7.10.3 Table 40. A Type 2 function has exactly one
                // input (Domain is a single [d0 d1] pair). C0 defaults to
                // [0.0], C1 to [1.0].
                let domain = get("Domain").and_then(read_num_pair)?;
                let c0 = get("C0")
                    .and_then(read_num_array)
                    .unwrap_or_else(|| vec![0.0]);
                let c1 = get("C1")
                    .and_then(read_num_array)
                    .unwrap_or_else(|| vec![1.0]);
                let n = get("N").and_then(number_as_f32)?;
                if c0.len() != c1.len() || c0.is_empty() {
                    return None;
                }
                Some(PdfFunction::Exponential {
                    domain,
                    range,
                    c0,
                    c1,
                    n,
                })
            }
            Some(3) => {
                // §7.10.4 Table 41. A Type 3 stitching function has
                // exactly one input (Domain is a single [d0 d1] pair).
                let domain = get("Domain").and_then(read_num_pair)?;
                let Some(Object::Array(fs)) = get("Functions") else {
                    return None;
                };
                let functions: Vec<PdfFunction> =
                    fs.iter().map(PdfFunction::parse).collect::<Option<_>>()?;
                if functions.is_empty() {
                    return None;
                }
                let bounds = get("Bounds").and_then(read_num_array).unwrap_or_default();
                let encode = get("Encode").and_then(read_num_array)?;
                // k functions ⇒ k−1 bounds and 2·k encode pairs.
                if bounds.len() + 1 != functions.len() || encode.len() != 2 * functions.len() {
                    return None;
                }
                Some(PdfFunction::Stitching {
                    domain,
                    range,
                    functions,
                    bounds,
                    encode,
                })
            }
            Some(4) => {
                // §7.10.5 Table 38: Domain and Range are both required.
                // Domain carries 2·m entries (one [d0 d1] pair per input
                // variable — `m` inputs for a DeviceN tint transform);
                // Range fixes the output dimensionality n.
                let domain = get("Domain").and_then(read_num_array)?;
                if domain.is_empty() || domain.len() % 2 != 0 {
                    return None;
                }
                let range = range?;
                if range.is_empty() || range.len() % 2 != 0 {
                    return None;
                }
                // The decoded program source, folded in by
                // `prepare_function_object` under `__Program`.
                let src = match get("__Program") {
                    Some(Object::HexString(bytes)) => bytes.as_slice(),
                    _ => return None,
                };
                let program = parse_ps_program(src)?;
                Some(PdfFunction::Calculator {
                    domain,
                    range,
                    program,
                })
            }
            _ => None,
        }
    }

    /// Evaluate this 1-input function at `x`, returning the output
    /// component vector. A thin wrapper over [`eval_n`](Self::eval_n) for
    /// the single-input call sites (Separation tint transforms, Type 3
    /// child functions).
    fn eval(&self, x: f32) -> Vec<f32> {
        self.eval_n(&[x])
    }

    /// Evaluate this function at the `m`-component input vector `inputs`,
    /// returning the output component vector. Inputs are clipped to
    /// `Domain` and outputs to `Range` (§7.10.1). Type 2 (exponential)
    /// and Type 3 (stitching) are intrinsically 1-input and read
    /// `inputs[0]` (a missing first input is treated as `0.0`); Type 0
    /// (sampled) and Type 4 (calculator) consume all `m` inputs.
    fn eval_n(&self, inputs: &[f32]) -> Vec<f32> {
        let first = inputs.first().copied().unwrap_or(0.0);
        match self {
            PdfFunction::Exponential {
                domain,
                range,
                c0,
                c1,
                n,
            } => {
                let xc = first.clamp(domain[0], domain[1]);
                // y_j = C0_j + x^N · (C1_j − C0_j), §7.10.3 Table 40.
                let xn = xc.powf(*n);
                let mut out: Vec<f32> = c0
                    .iter()
                    .zip(c1.iter())
                    .map(|(&a, &b)| a + xn * (b - a))
                    .collect();
                clip_to_range(&mut out, range.as_deref());
                out
            }
            PdfFunction::Stitching {
                domain,
                range,
                functions,
                bounds,
                encode,
            } => {
                let xc = first.clamp(domain[0], domain[1]);
                // Find subdomain i: the half-open interval [b_{i-1}, b_i)
                // (the last is closed on the right), §7.10.4. b_{-1} =
                // Domain0, b_{k-1} = Domain1.
                let k = functions.len();
                let mut i = 0;
                while i < bounds.len() && xc >= bounds[i] {
                    i += 1;
                }
                let lo = if i == 0 { domain[0] } else { bounds[i - 1] };
                let hi = if i == k - 1 { domain[1] } else { bounds[i] };
                // Encode x into the child function's domain. If the
                // subdomain is degenerate (lo == hi, the §7.10.4
                // last-bound-equals-Domain1 case), use Encode_{2i}.
                let xprime = if (hi - lo).abs() < f32::EPSILON {
                    encode[2 * i]
                } else {
                    interpolate(xc, lo, hi, encode[2 * i], encode[2 * i + 1])
                };
                let mut out = functions[i].eval(xprime);
                clip_to_range(&mut out, range.as_deref());
                out
            }
            PdfFunction::Sampled {
                domain,
                range,
                size,
                n,
                encode,
                decode,
                samples,
                order,
            } => eval_sampled(
                inputs, domain, range, size, *n, encode, decode, samples, *order,
            ),
            PdfFunction::Calculator {
                domain,
                range,
                program,
            } => {
                // §7.10.5: the input variables form the initial operand
                // stack, in order, each clipped to its Domain pair.
                let m = domain.len() / 2;
                let n = range.len() / 2;
                let mut stack: Vec<PsValue> = Vec::with_capacity(m);
                for i in 0..m {
                    let xi = inputs.get(i).copied().unwrap_or(0.0);
                    stack.push(PsValue::Num(xi.clamp(domain[2 * i], domain[2 * i + 1])));
                }
                if exec_ps(program, &mut stack).is_err() {
                    // §7.10.5.2 execution error (stack under/overflow,
                    // type error, undefined result). Fall back to black.
                    return vec![0.0; n];
                }
                // The items remaining after execution are the outputs.
                // It is an error for the count to differ from Range's n
                // (§7.10.5) or for any to be non-numeric; treat both as
                // the conservative black fallback.
                if stack.len() != n {
                    return vec![0.0; n];
                }
                let mut out = Vec::with_capacity(n);
                for v in &stack {
                    match v {
                        PsValue::Num(f) => out.push(*f),
                        PsValue::Bool(_) => return vec![0.0; n],
                    }
                }
                clip_to_range(&mut out, Some(range));
                out
            }
        }
    }

    /// The number of input variables `m` this function consumes. Type 2
    /// (exponential) and Type 3 (stitching) are 1-input by definition
    /// (§7.10.3 / §7.10.4); Type 0 (sampled) and Type 4 (calculator)
    /// derive `m` from their `Domain` pair count. Used to validate a
    /// DeviceN tint transform's arity against the colorant count
    /// (§8.6.6.5).
    fn input_arity(&self) -> usize {
        match self {
            PdfFunction::Exponential { .. } | PdfFunction::Stitching { .. } => 1,
            PdfFunction::Sampled { size, .. } => size.len(),
            PdfFunction::Calculator { domain, .. } => domain.len() / 2,
        }
    }

    /// The number of output components `n` this function produces, when
    /// statically known. Type 0 carries `n` directly; Type 2's arity is
    /// `C0`'s length; Type 4's is `Range`'s pair count. Type 3
    /// (stitching) returns `None` — its output arity follows its child
    /// functions, which a DeviceN tint transform never is (its tint
    /// transform is the top-level n-in/m-out function). Used to validate
    /// a DeviceN tint transform's output against the alternate space's
    /// component count (§8.6.6.5).
    fn output_arity(&self) -> Option<usize> {
        match self {
            PdfFunction::Sampled { n, .. } => Some(*n),
            PdfFunction::Exponential { c0, .. } => Some(c0.len()),
            PdfFunction::Calculator { range, .. } => Some(range.len() / 2),
            PdfFunction::Stitching { .. } => None,
        }
    }
}

/// Maximum operand-stack depth for a Type 4 program. §7.10.5 requires at
/// least 100 entries and explicitly makes overflowing the stack an
/// error; this is also the guard that keeps an adversarial `dup`-loop
/// program bounded.
const PS_STACK_LIMIT: usize = 100;

/// Tokenise + parse a Type 4 (PostScript-calculator) program body
/// (§7.10.5). The whole program is wrapped in an outermost `{ }`; this
/// returns the token sequence *inside* that brace. Brace blocks nested
/// for `if` / `ifelse` become [`PsToken::Block`]s. Returns `None` for a
/// syntax error (§7.10.5.2): unmatched braces, a non-numeric / unknown
/// token, or missing outer braces.
fn parse_ps_program(src: &[u8]) -> Option<Vec<PsToken>> {
    // The grammar is whitespace-separated; the only special characters
    // are the curly braces. A real number is `[+-]?digits[.digits]` and
    // the spec language has no other lexical forms.
    let mut words: Vec<&[u8]> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in src.iter().enumerate() {
        if b == b'{' || b == b'}' {
            if let Some(s) = start.take() {
                words.push(&src[s..i]);
            }
            words.push(&src[i..i + 1]);
        } else if b.is_ascii_whitespace() {
            if let Some(s) = start.take() {
                words.push(&src[s..i]);
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        words.push(&src[s..]);
    }
    // The first non-empty token must be the opening brace; the matching
    // close brace must be the last. Parse the body between them.
    let mut iter = words.into_iter().peekable();
    if iter.next() != Some(b"{") {
        return None;
    }
    let (body, closed) = parse_ps_block(&mut iter)?;
    // After the top-level block closes, nothing else may follow.
    if !closed || iter.next().is_some() {
        return None;
    }
    Some(body)
}

/// Parse the contents of one brace block up to (and consuming) its
/// closing `}`. Returns the token list plus whether a matching `}` was
/// actually seen (`false` ⇒ unterminated block ⇒ caller reports a syntax
/// error).
fn parse_ps_block<'a, I>(iter: &mut std::iter::Peekable<I>) -> Option<(Vec<PsToken>, bool)>
where
    I: Iterator<Item = &'a [u8]>,
{
    let mut tokens = Vec::new();
    while let Some(w) = iter.next() {
        match w {
            b"}" => return Some((tokens, true)),
            b"{" => {
                let (inner, closed) = parse_ps_block(iter)?;
                if !closed {
                    return None;
                }
                tokens.push(PsToken::Block(inner));
            }
            b"true" => tokens.push(PsToken::Bool(true)),
            b"false" => tokens.push(PsToken::Bool(false)),
            other => {
                let text = str::from_utf8(other).ok()?;
                if let Ok(num) = text.parse::<f32>() {
                    tokens.push(PsToken::Number(num));
                } else if let Some(op) = PsOp::from_keyword(text) {
                    tokens.push(PsToken::Op(op));
                } else {
                    // Unknown token — a syntax error.
                    return None;
                }
            }
        }
    }
    // Ran out of tokens without a closing brace.
    Some((tokens, false))
}

/// Execute a parsed Type 4 token sequence against the operand `stack`
/// (§7.10.5). Returns `Err(())` on any execution error — stack
/// under/overflow, a type error, or an undefined result (§7.10.5.2) —
/// which the caller maps to the conservative black fallback.
fn exec_ps(tokens: &[PsToken], stack: &mut Vec<PsValue>) -> Result<(), ()> {
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            PsToken::Number(f) => push(stack, PsValue::Num(*f))?,
            PsToken::Bool(b) => push(stack, PsValue::Bool(*b))?,
            // A bare block on the operand path is only meaningful as the
            // operand of the `if` / `ifelse` that follows it; those are
            // handled when the operator token is reached, so a block by
            // itself (without a following conditional) is a syntax-shaped
            // error we treat as an execution error.
            PsToken::Block(_) => {
                // Look ahead: `bool { proc } if` or
                // `bool { p1 } { p2 } ifelse`.
                let proc1 = match &tokens[i] {
                    PsToken::Block(b) => b,
                    _ => unreachable!(),
                };
                match tokens.get(i + 1) {
                    Some(PsToken::Op(PsOp::If)) => {
                        let cond = pop_bool(stack)?;
                        if cond {
                            exec_ps(proc1, stack)?;
                        }
                        i += 2;
                        continue;
                    }
                    Some(PsToken::Block(proc2)) => {
                        // Expect `ifelse` after the second block.
                        if tokens.get(i + 2) != Some(&PsToken::Op(PsOp::Ifelse)) {
                            return Err(());
                        }
                        let cond = pop_bool(stack)?;
                        if cond {
                            exec_ps(proc1, stack)?;
                        } else {
                            exec_ps(proc2, stack)?;
                        }
                        i += 3;
                        continue;
                    }
                    _ => return Err(()),
                }
            }
            PsToken::Op(op) => exec_ps_op(*op, stack)?,
        }
        i += 1;
    }
    Ok(())
}

/// Push a value, enforcing the §7.10.5 100-entry stack ceiling
/// (overflow is an error).
fn push(stack: &mut Vec<PsValue>, v: PsValue) -> Result<(), ()> {
    if stack.len() >= PS_STACK_LIMIT {
        return Err(());
    }
    stack.push(v);
    Ok(())
}

/// Pop a numeric operand; a non-number or empty stack is an error.
fn pop_num(stack: &mut Vec<PsValue>) -> Result<f32, ()> {
    match stack.pop() {
        Some(PsValue::Num(f)) => Ok(f),
        _ => Err(()),
    }
}

/// Pop a boolean operand; a non-boolean or empty stack is an error.
fn pop_bool(stack: &mut Vec<PsValue>) -> Result<bool, ()> {
    match stack.pop() {
        Some(PsValue::Bool(b)) => Ok(b),
        _ => Err(()),
    }
}

/// Pop a value usable as an integer (§B.3 bitwise / B.2 idiv·mod). The
/// number must be integral within `f32` range; a non-number or a value
/// outside the i32 range is an error.
fn pop_int(stack: &mut Vec<PsValue>) -> Result<i32, ()> {
    let f = pop_num(stack)?;
    if !f.is_finite() || f.fract() != 0.0 || f < i32::MIN as f32 || f > i32::MAX as f32 {
        return Err(());
    }
    Ok(f as i32)
}

/// Execute a single non-conditional operator against the stack
/// (§7.10.5 / Annex B). `if` / `ifelse` never reach here — they are
/// handled structurally in [`exec_ps`].
fn exec_ps_op(op: PsOp, stack: &mut Vec<PsValue>) -> Result<(), ()> {
    match op {
        // ---- B.2 Arithmetic ------------------------------------------
        PsOp::Add => {
            let (a, b) = (pop_num(stack)?, pop_num(stack)?);
            push(stack, PsValue::Num(b + a))
        }
        PsOp::Sub => {
            let (a, b) = (pop_num(stack)?, pop_num(stack)?);
            push(stack, PsValue::Num(b - a))
        }
        PsOp::Mul => {
            let (a, b) = (pop_num(stack)?, pop_num(stack)?);
            push(stack, PsValue::Num(b * a))
        }
        PsOp::Div => {
            let a = pop_num(stack)?;
            let b = pop_num(stack)?;
            if a == 0.0 {
                return Err(()); // division by zero ⇒ undefined result
            }
            push(stack, PsValue::Num(b / a))
        }
        PsOp::Idiv => {
            let a = pop_int(stack)?;
            let b = pop_int(stack)?;
            if a == 0 {
                return Err(());
            }
            push(stack, PsValue::Num((b / a) as f32))
        }
        PsOp::Mod => {
            let a = pop_int(stack)?;
            let b = pop_int(stack)?;
            if a == 0 {
                return Err(());
            }
            // PostScript `mod` takes the sign of the dividend (Rust `%`
            // already does this for integers).
            push(stack, PsValue::Num((b % a) as f32))
        }
        PsOp::Neg => {
            let a = pop_num(stack)?;
            push(stack, PsValue::Num(-a))
        }
        PsOp::Abs => {
            let a = pop_num(stack)?;
            push(stack, PsValue::Num(a.abs()))
        }
        PsOp::Ceiling => {
            let a = pop_num(stack)?;
            push(stack, PsValue::Num(a.ceil()))
        }
        PsOp::Floor => {
            let a = pop_num(stack)?;
            push(stack, PsValue::Num(a.floor()))
        }
        PsOp::Round => {
            let a = pop_num(stack)?;
            // PostScript rounds half away from zero, matching `f32::round`.
            push(stack, PsValue::Num(a.round()))
        }
        PsOp::Truncate => {
            let a = pop_num(stack)?;
            push(stack, PsValue::Num(a.trunc()))
        }
        PsOp::Sqrt => {
            let a = pop_num(stack)?;
            if a < 0.0 {
                return Err(()); // range error
            }
            push(stack, PsValue::Num(a.sqrt()))
        }
        PsOp::Sin => {
            let a = pop_num(stack)?;
            push(stack, PsValue::Num(a.to_radians().sin()))
        }
        PsOp::Cos => {
            let a = pop_num(stack)?;
            push(stack, PsValue::Num(a.to_radians().cos()))
        }
        PsOp::Atan => {
            // num den atan angle — result in degrees, normalised to
            // [0, 360) (PostScript semantics).
            let den = pop_num(stack)?;
            let num = pop_num(stack)?;
            if num == 0.0 && den == 0.0 {
                return Err(()); // undefined
            }
            let mut deg = num.atan2(den).to_degrees();
            if deg < 0.0 {
                deg += 360.0;
            }
            push(stack, PsValue::Num(deg))
        }
        PsOp::Exp => {
            // base exponent exp real.
            let exponent = pop_num(stack)?;
            let base = pop_num(stack)?;
            let r = base.powf(exponent);
            if !r.is_finite() {
                return Err(());
            }
            push(stack, PsValue::Num(r))
        }
        PsOp::Ln => {
            let a = pop_num(stack)?;
            if a <= 0.0 {
                return Err(());
            }
            push(stack, PsValue::Num(a.ln()))
        }
        PsOp::Log => {
            let a = pop_num(stack)?;
            if a <= 0.0 {
                return Err(());
            }
            push(stack, PsValue::Num(a.log10()))
        }
        PsOp::Cvi => {
            // Convert to integer by truncation toward zero.
            let a = pop_num(stack)?;
            push(stack, PsValue::Num(a.trunc()))
        }
        PsOp::Cvr => {
            // Convert to real — already an f32, a no-op type assertion.
            let a = pop_num(stack)?;
            push(stack, PsValue::Num(a))
        }
        // ---- B.3 Relational / boolean / bitwise ----------------------
        PsOp::Eq => {
            let (a, b) = (stack.pop().ok_or(())?, stack.pop().ok_or(())?);
            push(stack, PsValue::Bool(b == a))
        }
        PsOp::Ne => {
            let (a, b) = (stack.pop().ok_or(())?, stack.pop().ok_or(())?);
            push(stack, PsValue::Bool(b != a))
        }
        PsOp::Gt => {
            let (a, b) = (pop_num(stack)?, pop_num(stack)?);
            push(stack, PsValue::Bool(b > a))
        }
        PsOp::Ge => {
            let (a, b) = (pop_num(stack)?, pop_num(stack)?);
            push(stack, PsValue::Bool(b >= a))
        }
        PsOp::Lt => {
            let (a, b) = (pop_num(stack)?, pop_num(stack)?);
            push(stack, PsValue::Bool(b < a))
        }
        PsOp::Le => {
            let (a, b) = (pop_num(stack)?, pop_num(stack)?);
            push(stack, PsValue::Bool(b <= a))
        }
        PsOp::And => bool_or_bitwise(stack, |x, y| x & y, |x, y| x && y),
        PsOp::Or => bool_or_bitwise(stack, |x, y| x | y, |x, y| x || y),
        PsOp::Xor => bool_or_bitwise(stack, |x, y| x ^ y, |x, y| x != y),
        PsOp::Not => {
            // Logical not on a bool, bitwise not on an int (§B.3).
            match stack.pop() {
                Some(PsValue::Bool(b)) => push(stack, PsValue::Bool(!b)),
                Some(PsValue::Num(f)) => push(stack, PsValue::Num(!integer_value(f)? as f32)),
                _ => Err(()),
            }
        }
        PsOp::Bitshift => {
            // int1 shift bitshift int2 (positive shift is left, §B.3).
            let shift = pop_int(stack)?;
            let v = pop_int(stack)?;
            let r = if shift >= 0 {
                if shift >= 32 {
                    0
                } else {
                    v.wrapping_shl(shift as u32)
                }
            } else {
                let s = (-shift) as u32;
                if s >= 32 {
                    0
                } else {
                    v >> s
                }
            };
            push(stack, PsValue::Num(r as f32))
        }
        // ---- B.5 Stack -----------------------------------------------
        PsOp::Pop => {
            stack.pop().ok_or(())?;
            Ok(())
        }
        PsOp::Exch => {
            let len = stack.len();
            if len < 2 {
                return Err(());
            }
            stack.swap(len - 1, len - 2);
            Ok(())
        }
        PsOp::Dup => {
            let top = *stack.last().ok_or(())?;
            push(stack, top)
        }
        PsOp::Copy => {
            // any1 … anyn n copy any1 … anyn any1 … anyn (§B.5).
            let n = pop_int(stack)?;
            if n < 0 {
                return Err(());
            }
            let n = n as usize;
            let len = stack.len();
            if n > len {
                return Err(());
            }
            if stack.len() + n > PS_STACK_LIMIT {
                return Err(());
            }
            for k in 0..n {
                stack.push(stack[len - n + k]);
            }
            Ok(())
        }
        PsOp::Index => {
            // anyn … any0 n index anyn … any0 anyn (§B.5): duplicate the
            // element n positions down from the top (0 = top).
            let n = pop_int(stack)?;
            if n < 0 {
                return Err(());
            }
            let n = n as usize;
            let len = stack.len();
            if n >= len {
                return Err(());
            }
            push(stack, stack[len - 1 - n])
        }
        PsOp::Roll => {
            // anyn-1 … any0 n j roll — circularly roll the top n elements
            // up by j (§B.5).
            let j = pop_int(stack)?;
            let n = pop_int(stack)?;
            if n < 0 {
                return Err(());
            }
            let n = n as usize;
            let len = stack.len();
            if n > len {
                return Err(());
            }
            if n > 0 {
                let base = len - n;
                let slice = &mut stack[base..];
                // Positive j rotates "up" (toward the top): the top
                // element moves down. `rotate_right(k)` moves the last k
                // elements to the front, matching a roll-up by k.
                let k = j.rem_euclid(n as i32) as usize;
                slice.rotate_right(k);
            }
            Ok(())
        }
        // if / ifelse are handled structurally in exec_ps.
        PsOp::If | PsOp::Ifelse => Err(()),
    }
}

/// Coerce an `f32` operand to an `i32` for a bitwise operator, erroring
/// on a non-integral or out-of-range value (§B.3 bitwise ops are
/// integer-only).
fn integer_value(f: f32) -> Result<i32, ()> {
    if !f.is_finite() || f.fract() != 0.0 || f < i32::MIN as f32 || f > i32::MAX as f32 {
        return Err(());
    }
    Ok(f as i32)
}

/// Implement `and` / `or` / `xor`, which are logical on two booleans and
/// bitwise on two integers (§B.3). A mixed pair is a type error.
fn bool_or_bitwise(
    stack: &mut Vec<PsValue>,
    bitwise: fn(i32, i32) -> i32,
    logical: fn(bool, bool) -> bool,
) -> Result<(), ()> {
    let a = stack.pop().ok_or(())?;
    let b = stack.pop().ok_or(())?;
    match (b, a) {
        (PsValue::Bool(x), PsValue::Bool(y)) => push(stack, PsValue::Bool(logical(x, y))),
        (PsValue::Num(x), PsValue::Num(y)) => {
            let xi = integer_value(x)?;
            let yi = integer_value(y)?;
            push(stack, PsValue::Num(bitwise(xi, yi) as f32))
        }
        _ => Err(()),
    }
}

/// §7.10.2 / §7.10.4 linear `Interpolate`: the `y` value on the line
/// through `(xmin, ymin)` and `(xmax, ymax)`. A zero-width input
/// interval maps to `ymin` (avoids a divide-by-zero; callers handle the
/// degenerate stitching case before calling).
fn interpolate(x: f32, xmin: f32, xmax: f32, ymin: f32, ymax: f32) -> f32 {
    if (xmax - xmin).abs() < f32::EPSILON {
        return ymin;
    }
    ymin + (x - xmin) * (ymax - ymin) / (xmax - xmin)
}

/// Clip each output value into its `Range` pair (§7.10.1): output `j` is
/// clamped into `[Range_{2j}, Range_{2j+1}]`. A `None` range leaves the
/// outputs unclipped.
fn clip_to_range(out: &mut [f32], range: Option<&[f32]>) {
    if let Some(r) = range {
        for (j, v) in out.iter_mut().enumerate() {
            if let (Some(&lo), Some(&hi)) = (r.get(2 * j), r.get(2 * j + 1)) {
                *v = v.clamp(lo, hi);
            }
        }
    }
}

/// Read a `[a b]` two-number array (a function `/Domain` for a 1-input
/// function, §7.10.1 Table 38).
fn read_num_pair(obj: &Object) -> Option<[f32; 2]> {
    let Object::Array(items) = obj else {
        return None;
    };
    if items.len() != 2 {
        return None;
    }
    Some([number_as_f32(&items[0])?, number_as_f32(&items[1])?])
}

/// Unpack `count` sample values of `bps` bits each from a §7.10.2
/// sample stream, normalising each raw integer code into `[0.0, 1.0]`
/// by dividing by `2^bps − 1`. The bytes form a continuous bit stream
/// with the high-order bit of each byte first and no padding at value
/// boundaries; values run output-fastest then input-axis (storage
/// order). Returns `None` if the stream is too short to hold `count`
/// values. `bps` is one of {1,2,4,8,12,16,24,32}, so a value never
/// spans more than 32 bits.
fn unpack_samples(raw: &[u8], bps: u32, count: usize) -> Option<Vec<f32>> {
    let total_bits = (count as u64).checked_mul(bps as u64)?;
    if (raw.len() as u64) * 8 < total_bits {
        return None;
    }
    let max_code = ((1u64 << bps) - 1) as f32;
    let mut out = Vec::with_capacity(count);
    let mut bit_pos: u64 = 0;
    for _ in 0..count {
        let mut code: u64 = 0;
        for _ in 0..bps {
            let byte = raw[(bit_pos / 8) as usize];
            let bit = (byte >> (7 - (bit_pos % 8) as u32)) & 1;
            code = (code << 1) | (bit as u64);
            bit_pos += 1;
        }
        out.push((code as f32) / max_code);
    }
    Some(out)
}

/// The §7.10.2 cubic-spline basis weights for a fractional position `t`
/// in `[0, 1]` between the two central samples of a four-sample window
/// `[p_{-1}, p_0, p_1, p_2]`. These are the Catmull-Rom weights — the
/// cubic that passes through all four samples and reproduces `p_0` at
/// `t = 0` and `p_1` at `t = 1` (so the curve interpolates, not merely
/// approximates, the sample points the spec requires it to pass
/// through). Returned in window order `[w_{-1}, w_0, w_1, w_2]`; the
/// weights sum to 1 for every `t`, so a constant sample table is
/// reproduced exactly. At `t = 0` this collapses to `[0, 1, 0, 0]` and
/// at `t = 1` to `[0, 0, 1, 0]`, matching the linear blend at the knots.
fn cubic_weights(t: f32) -> [f32; 4] {
    let t2 = t * t;
    let t3 = t2 * t;
    // Catmull-Rom (tension 0.5) cardinal basis.
    [
        -0.5 * t3 + t2 - 0.5 * t,
        1.5 * t3 - 2.5 * t2 + 1.0,
        -1.5 * t3 + 2.0 * t2 + 0.5 * t,
        0.5 * t3 - 0.5 * t2,
    ]
}

/// One axis's interpolation contributions: a short list of
/// `(sample index on this axis, weight)` pairs whose weights sum to 1.
/// Order-1 yields up to two entries (the two bracketing samples);
/// Order-3 yields up to four (the cubic window). The full sample blend
/// is the tensor product of these per-axis contribution lists.
type AxisTaps = smallvec_like::Taps;

/// A tiny fixed-capacity tap list (max 4 entries — the widest axis
/// window is the Order-3 cubic). Avoids a heap allocation per axis per
/// evaluation, which matters because tint transforms are called once
/// per painted sample.
mod smallvec_like {
    /// Up to four `(index, weight)` taps for one input axis.
    #[derive(Clone, Copy)]
    pub(super) struct Taps {
        pub(super) items: [(usize, f32); 4],
        pub(super) len: usize,
    }

    impl Taps {
        pub(super) fn new() -> Self {
            Taps {
                items: [(0, 0.0); 4],
                len: 0,
            }
        }
        pub(super) fn push(&mut self, idx: usize, w: f32) {
            self.items[self.len] = (idx, w);
            self.len += 1;
        }
        pub(super) fn as_slice(&self) -> &[(usize, f32)] {
            &self.items[..self.len]
        }
    }
}

/// Evaluate an `m`-input Type 0 (sampled) function (§7.10.2) at the
/// `inputs` vector. Each input `x_i` is clipped to its `Domain` pair,
/// encoded into the sample-table axis `[0, Size_i − 1]`, and split into
/// a base index plus fraction. With `order == 1` the output is the
/// multilinear blend of the `2^m` surrounding grid corners; with
/// `order == 3` it is the tensor-product cubic-spline blend over the
/// four nearest samples per axis (§7.10.2 "cubic spline
/// interpolation"). Per §7.10.2, an axis whose `Size < 4` cannot carry a
/// cubic window and falls back to linear on that axis. The blend is then
/// decoded into the output range and clipped to `Range`. The sample
/// table stores the first input dimension fastest (`flat =
/// i_0 + Size_0·(i_1 + Size_1·(i_2 + …))`) with `n` interleaved outputs
/// per grid point.
#[allow(clippy::too_many_arguments)]
fn eval_sampled(
    inputs: &[f32],
    domain: &[f32],
    range: &[f32],
    size: &[usize],
    n: usize,
    encode: &[f32],
    decode: &[f32],
    samples: &[f32],
    order: u8,
) -> Vec<f32> {
    let m = size.len();
    // Per-axis tap lists (index + weight contributions) and strides.
    let mut taps: Vec<AxisTaps> = Vec::with_capacity(m);
    for i in 0..m {
        let xi = inputs.get(i).copied().unwrap_or(0.0);
        let xc = xi.clamp(domain[2 * i], domain[2 * i + 1]);
        let e = interpolate(
            xc,
            domain[2 * i],
            domain[2 * i + 1],
            encode[2 * i],
            encode[2 * i + 1],
        );
        let last = size[i] - 1;
        let e = e.clamp(0.0, last as f32);
        let i0 = e.floor() as usize;
        let frac = e - (i0 as f32);
        let mut t = AxisTaps::new();
        // Order-3 requires Size ≥ 4 to form the four-sample cubic window
        // (§7.10.2: "If Size is less than 4, … Order 3 shall be
        // ignored"). Otherwise interpolate linearly between the two
        // bracketing samples.
        if order == 3 && size[i] >= 4 {
            // Window indices i0−1, i0, i0+1, i0+2, each clamped to the
            // axis so an edge window reuses the boundary sample (the
            // weights still sum to 1, giving an extrapolation-free clamp
            // at the table edges).
            let w = cubic_weights(frac);
            let lo = i0 as isize - 1;
            for (k, &wk) in w.iter().enumerate() {
                let idx = (lo + k as isize).clamp(0, last as isize) as usize;
                if wk != 0.0 {
                    t.push(idx, wk);
                }
            }
        } else {
            let up = (i0 + 1).min(last);
            t.push(i0, 1.0 - frac);
            if frac != 0.0 && up != i0 {
                t.push(up, frac);
            }
        }
        taps.push(t);
    }
    // Tensor-product accumulation over the cartesian product of the
    // per-axis taps. `combo` indexes one tap per axis; the contribution
    // weight is the product of the chosen per-axis weights and the flat
    // sample offset is Σ idx_i · stride_i (axis 0 varies fastest).
    let mut out = vec![0.0f32; n];
    let mut idx_in_axis = vec![0usize; m];
    loop {
        let mut weight = 1.0f32;
        let mut flat = 0usize;
        let mut stride = 1usize;
        for i in 0..m {
            let (idx, w) = taps[i].as_slice()[idx_in_axis[i]];
            weight *= w;
            flat += idx * stride;
            stride *= size[i];
        }
        if weight != 0.0 {
            let off = flat * n;
            for (j, acc) in out.iter_mut().enumerate() {
                *acc += weight * samples[off + j];
            }
        }
        // Odometer increment across the per-axis tap lists.
        let mut axis = 0;
        loop {
            if axis == m {
                // All combinations exhausted.
                idx_in_axis.clear();
                break;
            }
            idx_in_axis[axis] += 1;
            if idx_in_axis[axis] < taps[axis].as_slice().len() {
                break;
            }
            idx_in_axis[axis] = 0;
            axis += 1;
        }
        if idx_in_axis.is_empty() {
            break;
        }
    }
    // Decode each blended sample [0,1] → output range, clip to Range.
    for (j, v) in out.iter_mut().enumerate() {
        *v = interpolate(*v, 0.0, 1.0, decode[2 * j], decode[2 * j + 1]);
    }
    clip_to_range(&mut out, Some(range));
    out
}

/// Read an all-numeric array into a `Vec<f32>` (function `/C0`, `/C1`,
/// `/Range`, `/Bounds`, `/Encode`). Returns `None` if the object isn't
/// an array or any element isn't a number.
fn read_num_array(obj: &Object) -> Option<Vec<f32>> {
    let Object::Array(items) = obj else {
        return None;
    };
    items.iter().map(number_as_f32).collect()
}

/// Which colour space the current `sc`/`scn` (or `SC`/`SCN`) operands
/// are interpreted in, as established by the most recent `cs` / `CS`
/// operator (ISO 32000-1 §8.6.8 Table 74). The three device families
/// — whose component counts are fixed and whose component → RGB
/// mapping needs no `/Resources` lookup — are tracked directly. When
/// the page's `/Resources /ColorSpace` subdictionary is plumbed in
/// (round 275, [`parse_content_stream_full_with_color_space`]), a
/// named key resolving to an `ICCBased` stream maps to its device
/// alternate (§8.6.5.5) and a named key resolving to an `Indexed`
/// array carries its base + colour table for `sc`/`scn` index lookups
/// (§8.6.6.3). Every other space (Pattern, CIE-based CalRGB/CalGray/
/// Lab, Separation, DeviceN, or any key the parser can't resolve)
/// collapses to `Unknown`, for which `sc`/`scn` keep the conservative
/// black fallback.
#[derive(Clone, Debug, PartialEq)]
enum ColorSpaceKind {
    /// `/DeviceGray` — one component (§8.6.4.2).
    DeviceGray,
    /// `/DeviceRGB` — three components (§8.6.4.3).
    DeviceRgb,
    /// `/DeviceCMYK` — four components (§8.6.4.4).
    DeviceCmyk,
    /// An `/Indexed` space (§8.6.6.3): a single index component selects
    /// a `base`-space colour from `table`. `base` is the device family
    /// the table entries are interpreted in; `hival` is the maximum
    /// valid index; `table` is the `(hival+1) * base.components()`
    /// resolved lookup bytes (each scaled 0..255 → component range).
    Indexed {
        base: Box<ColorSpaceKind>,
        hival: u32,
        table: Vec<u8>,
    },
    /// A `/Separation` space (§8.6.6.4): a single tint component in
    /// `0.0..=1.0` is mapped through `tint` (the tint-transform
    /// function, §7.10) into `alt`-space component values, which `alt`
    /// then renders to RGB. `alt` is the alternate device family (the
    /// only families this round renders); `tint` is the evaluable
    /// function (Type 0 sampled / Type 2 / Type 3). The special colorant names `All` and
    /// `None` are folded in at resolve time (`None` → no paint, `All`
    /// applied through the alternate as a single tint).
    Separation {
        alt: Box<ColorSpaceKind>,
        tint: PdfFunction,
        /// `true` for the special `/None` colorant — painting produces
        /// no visible output (§8.6.6.4), so `sc`/`scn` yields no paint.
        none_colorant: bool,
    },
    /// A `/DeviceN` space (§8.6.6.5): `n_in` tint components (one per
    /// entry in the colour space's `names` array, in stream order) are
    /// mapped through `tint` (an `n_in`-in / m-out tint-transform
    /// function, §7.10) into `alt`-space component values, which `alt`
    /// then renders to RGB. `alt` is the alternate device family (the
    /// only families this round renders); `tint` is an evaluable Type 0
    /// (sampled) / Type 4 (PostScript-calculator) function — the
    /// multi-input families a DeviceN tint transform uses. `all_none` is
    /// set when every colorant name is `/None`: such a space always
    /// discards its output and never reverts to the alternate
    /// (§8.6.6.5).
    DeviceN {
        n_in: usize,
        alt: Box<ColorSpaceKind>,
        tint: PdfFunction,
        all_none: bool,
    },
    /// A `/CalGray` space (§8.6.5.2): one component decoded by `gamma`
    /// and scaled by the `white` point `[XW YW ZW]` to a CIE XYZ value,
    /// then mapped to device RGB.
    CalGray { white: [f32; 3], gamma: f32 },
    /// A `/CalRGB` space (§8.6.5.3): three components decoded by the
    /// per-channel `gamma` `[GR GG GB]`, multiplied by the 3×3 `matrix`
    /// `[XA YA ZA XB YB ZB XC YC ZC]` to a CIE XYZ value, then mapped to
    /// device RGB.
    CalRgb { gamma: [f32; 3], matrix: [f32; 9] },
    /// A `/Lab` space (§8.6.5.4): the L*a*b* triple (L* in 0..=100,
    /// a*/b* clamped into `range` `[amin amax bmin bmax]`) mapped to a
    /// CIE XYZ value through the implicit two-stage transform scaled by
    /// the `white` point, then to device RGB.
    Lab { white: [f32; 3], range: [f32; 4] },
    /// Any space the parser doesn't resolve to a device family, a
    /// device-based Indexed space, a device-alternate Separation, or a
    /// device-alternate DeviceN — `/Pattern`, a CIE-based CalRGB /
    /// CalGray / Lab space, a Separation/DeviceN whose tint transform
    /// isn't an evaluable function or whose alternate isn't a device
    /// family, or a `/Resources /ColorSpace` key whose definition the
    /// parser can't reduce to a device fallback.
    Unknown,
}

impl ColorSpaceKind {
    /// Map a `cs` / `CS` name operand to a tracked colour space without
    /// consulting `/Resources`. The three device-family names are
    /// recognised directly (§8.6.4.1); everything else — including
    /// `/Pattern` and any resource key — is `Unknown` until
    /// [`resolve_with_resources`](Self::resolve_with_resources) gets a
    /// chance to look the key up.
    fn from_name(name: &str) -> Self {
        match name {
            "DeviceGray" | "G" => ColorSpaceKind::DeviceGray,
            "DeviceRGB" | "RGB" => ColorSpaceKind::DeviceRgb,
            "DeviceCMYK" | "CMYK" => ColorSpaceKind::DeviceCmyk,
            _ => ColorSpaceKind::Unknown,
        }
    }

    /// Number of numeric components an `sc`/`scn` carries in this
    /// space. `Indexed` always carries a single index component
    /// (§8.6.6.3). `None` for `Unknown` (where the count is unknowable
    /// without resolving the resource definition).
    fn components(&self) -> Option<usize> {
        match self {
            ColorSpaceKind::DeviceGray => Some(1),
            ColorSpaceKind::DeviceRgb => Some(3),
            ColorSpaceKind::DeviceCmyk => Some(4),
            ColorSpaceKind::Indexed { .. } => Some(1),
            // §8.6.6.4: a Separation colour value is a single tint
            // component, regardless of the alternate space's arity.
            ColorSpaceKind::Separation { .. } => Some(1),
            // §8.6.6.5: a DeviceN colour value carries one tint per
            // colorant name, in the names-array order.
            ColorSpaceKind::DeviceN { n_in, .. } => Some(*n_in),
            // §8.6.5.2: a CIE-based A space carries one component.
            ColorSpaceKind::CalGray { .. } => Some(1),
            // §8.6.5.3 / §8.6.5.4: a CIE-based ABC space carries three.
            ColorSpaceKind::CalRgb { .. } | ColorSpaceKind::Lab { .. } => Some(3),
            ColorSpaceKind::Unknown => None,
        }
    }

    /// Resolve a `cs` / `CS` name against the page's `/Resources
    /// /ColorSpace` subdictionary (when one is plumbed in). The three
    /// device-family names short-circuit to themselves (a resource key
    /// can't shadow them per §8.6.8 Table 74). Otherwise the named
    /// entry's resolved `Object` is interpreted per
    /// [`color_space_from_object`]; an absent key (or one this round
    /// can't reduce to a device fallback) stays `Unknown`, preserving
    /// the conservative black fallback.
    fn resolve_with_resources(name: &str, resources: Option<&Dict>) -> Self {
        let direct = ColorSpaceKind::from_name(name);
        if direct != ColorSpaceKind::Unknown {
            return direct;
        }
        let Some(res) = resources else {
            return ColorSpaceKind::Unknown;
        };
        match res.entries().iter().find(|(k, _)| k == name) {
            Some((_, obj)) => color_space_from_object(obj),
            None => ColorSpaceKind::Unknown,
        }
    }
}

/// Interpret a resolved `/Resources /ColorSpace` entry (already
/// fully-dereferenced by
/// [`crate::reader::document::resolve_color_space_resources`]) as a
/// tracked [`ColorSpaceKind`].
///
/// Recognised, all reducible to a device family without CIE colour
/// science:
///
/// * A bare device name (`/DeviceGray` / `/DeviceRGB` / `/DeviceCMYK`).
/// * `[ /ICCBased << /N n /Alternate alt … >> ]` — §8.6.5.5: the
///   `/Alternate` space is used when present, otherwise `/N` (1/3/4)
///   selects DeviceGray / DeviceRGB / DeviceCMYK exactly as the spec's
///   "if this entry is omitted … the colour space that shall be used
///   is DeviceGray, DeviceRGB, or DeviceCMYK, depending on whether the
///   value of N is 1, 3, or 4" fallback prescribes. The ICC profile
///   bytes themselves are not interpreted.
/// * `[ /Indexed base hival lookup ]` — §8.6.6.3: when `base` reduces
///   to a device family, the resolved lookup bytes are carried so
///   `sc`/`scn` can index the table.
///
/// CalRGB / CalGray / Lab (CIE-based, need a gamut-mapping pass),
/// Separation / DeviceN (need tint-transform function evaluation), and
/// `/Pattern` all stay `Unknown`.
fn color_space_from_object(obj: &Object) -> ColorSpaceKind {
    match obj {
        Object::Name(n) => ColorSpaceKind::from_name(n),
        Object::Array(items) => match items.first() {
            Some(Object::Name(family)) if family == "ICCBased" => icc_based_from_array(items),
            Some(Object::Name(family)) if family == "Indexed" => indexed_from_array(items),
            Some(Object::Name(family)) if family == "Separation" => separation_from_array(items),
            Some(Object::Name(family)) if family == "DeviceN" => device_n_from_array(items),
            Some(Object::Name(family)) if family == "CalGray" => cal_gray_from_array(items),
            Some(Object::Name(family)) if family == "CalRGB" => cal_rgb_from_array(items),
            Some(Object::Name(family)) if family == "Lab" => lab_from_array(items),
            _ => ColorSpaceKind::Unknown,
        },
        _ => ColorSpaceKind::Unknown,
    }
}

/// Reduce `[ /ICCBased << /N n /Alternate alt … >> ]` to its device
/// fallback per §8.6.5.5. The stream's dictionary is surfaced as the
/// second array element (the document-level resolver replaces the ICC
/// profile stream with its dictionary). `/Alternate` wins when it
/// itself reduces to a device family; otherwise `/N` selects the
/// device space.
fn icc_based_from_array(items: &[Object]) -> ColorSpaceKind {
    let Some(Object::Dict(dict)) = items.get(1) else {
        return ColorSpaceKind::Unknown;
    };
    if let Some((_, alt)) = dict.entries().iter().find(|(k, _)| k == "Alternate") {
        let resolved = color_space_from_object(alt);
        if resolved != ColorSpaceKind::Unknown {
            return resolved;
        }
    }
    match dict.entries().iter().find(|(k, _)| k == "N") {
        Some((_, Object::Integer(1))) => ColorSpaceKind::DeviceGray,
        Some((_, Object::Integer(3))) => ColorSpaceKind::DeviceRgb,
        Some((_, Object::Integer(4))) => ColorSpaceKind::DeviceCmyk,
        _ => ColorSpaceKind::Unknown,
    }
}

/// Reduce `[ /Indexed base hival lookup ]` to a tracked `Indexed`
/// space per §8.6.6.3. The base must itself reduce to a device family
/// (the only families whose table entries this round can interpret);
/// `hival` must be a non-negative integer ≤ 255; the lookup parameter
/// must be a resolved byte string (the document-level resolver
/// replaces a lookup *stream* with its decoded bytes as a
/// `HexString`). Any deviation collapses to `Unknown`.
fn indexed_from_array(items: &[Object]) -> ColorSpaceKind {
    if items.len() < 4 {
        return ColorSpaceKind::Unknown;
    }
    let base = color_space_from_object(&items[1]);
    // §8.6.6.3 forbids a Pattern, Indexed, Separation, or DeviceN base.
    // Device families and the CIE-based families (CalGray / CalRGB /
    // Lab) are permitted; their table entries are decoded per
    // `indexed_color`. `components()` is `None` only for `Unknown`,
    // which is also rejected. The table's per-entry byte count `m`
    // follows from the base at lookup time; a short table is tolerated
    // by returning no colour for an out-of-range slot rather than
    // rejecting the whole space here.
    if base.components().is_none()
        || matches!(
            base,
            ColorSpaceKind::Indexed { .. }
                | ColorSpaceKind::Separation { .. }
                | ColorSpaceKind::DeviceN { .. }
        )
    {
        return ColorSpaceKind::Unknown;
    }
    let hival = match &items[2] {
        Object::Integer(n) if *n >= 0 && *n <= 255 => *n as u32,
        _ => return ColorSpaceKind::Unknown,
    };
    let table = match &items[3] {
        Object::LiteralString(b) | Object::HexString(b) => b.clone(),
        _ => return ColorSpaceKind::Unknown,
    };
    ColorSpaceKind::Indexed {
        base: Box::new(base),
        hival,
        table,
    }
}

/// Reduce `[ /Separation name alternateSpace tintTransform ]` to a
/// tracked `Separation` space per ISO 32000-1 §8.6.6.4.
///
/// The space resolves only when the alternate reduces to a device
/// family (DeviceGray / DeviceRGB / DeviceCMYK) or a CIE-based family
/// (CalGray / CalRGB / Lab) — the families this round renders — and the
/// tint transform parses as an evaluable Type 0 (sampled) / Type 2 /
/// Type 3 function ([`PdfFunction::parse`]). An `Indexed`/`Separation`/
/// `DeviceN` alternate (forbidden by §8.6.6.4 anyway), an unresolvable
/// alternate, or a Type 4 tint transform collapses to `Unknown`,
/// preserving the conservative black fallback.
///
/// The special colorant names `All` and `None` (§8.6.6.4): for these a
/// conforming reader ignores the alternate and tint transform. `None`
/// produces no visible output, so it is tracked as a Separation whose
/// `none_colorant` flag suppresses any paint. `All` applies a single
/// tint to all colorants; with no per-colorant device model here, it is
/// approximated through the alternate exactly like a named colorant
/// when one is supplied, otherwise it stays `Unknown`.
fn separation_from_array(items: &[Object]) -> ColorSpaceKind {
    if items.len() < 4 {
        return ColorSpaceKind::Unknown;
    }
    let none_colorant = matches!(&items[1], Object::Name(n) if n == "None");
    let alt = color_space_from_object(&items[2]);
    // §8.6.6.4: the alternate "may not be another special colour space
    // (Pattern, Indexed, Separation, or DeviceN)" — `components()` is
    // `None` for `Unknown`, and an Indexed/Separation/DeviceN alternate
    // is rejected by matching their variants.
    if alt.components().is_none()
        || matches!(
            alt,
            ColorSpaceKind::Indexed { .. }
                | ColorSpaceKind::Separation { .. }
                | ColorSpaceKind::DeviceN { .. }
        )
    {
        // A `/None` colorant ignores the alternate entirely (no visible
        // output), so it still resolves even with a degenerate
        // alternate; everything else needs a renderable alternate.
        if none_colorant {
            return ColorSpaceKind::Separation {
                alt: Box::new(ColorSpaceKind::DeviceGray),
                tint: PdfFunction::Exponential {
                    domain: [0.0, 1.0],
                    range: None,
                    c0: vec![0.0],
                    c1: vec![0.0],
                    n: 1.0,
                },
                none_colorant: true,
            };
        }
        return ColorSpaceKind::Unknown;
    }
    let Some(tint) = PdfFunction::parse(&items[3]) else {
        return ColorSpaceKind::Unknown;
    };
    ColorSpaceKind::Separation {
        alt: Box::new(alt),
        tint,
        none_colorant,
    }
}

/// Reduce `[ /DeviceN names alternateSpace tintTransform (attributes) ]`
/// to a tracked `DeviceN` space per ISO 32000-1 §8.6.6.5.
///
/// `names` is the array of `n_in` colorant names; its length fixes the
/// number of tint components an `sc`/`scn` carries. The space resolves
/// only when the alternate reduces to a device family (DeviceGray /
/// DeviceRGB / DeviceCMYK) or a CIE-based family (CalGray / CalRGB /
/// Lab) — the families this round renders — and the
/// `n_in`-input tint transform parses as an evaluable function. A
/// special-space alternate (forbidden by §8.6.6.5 anyway),
/// or a tint transform whose input arity doesn't match `n_in` or whose
/// output arity doesn't match the alternate's component count, collapses
/// to `Unknown`, preserving the conservative black fallback. The
/// optional `attributes` dictionary (NChannel `/Subtype`, `/Colorants`,
/// `/Process`, `/MixingHints`) is not consulted — a conforming reader
/// that does not use those custom-blending hints renders through the
/// supplied alternate + tint transform (§8.6.6.5), which is what this
/// does.
///
/// §8.6.6.5: when every colorant name is `/None` the space always
/// discards its output (`all_none`); the parser still resolves it so the
/// `sc`/`scn` operand count is known and no paint is produced.
fn device_n_from_array(items: &[Object]) -> ColorSpaceKind {
    if items.len() < 4 {
        return ColorSpaceKind::Unknown;
    }
    let Object::Array(name_objs) = &items[1] else {
        return ColorSpaceKind::Unknown;
    };
    if name_objs.is_empty() {
        return ColorSpaceKind::Unknown;
    }
    let mut all_none = true;
    for nm in name_objs {
        match nm {
            Object::Name(n) => {
                if n != "None" {
                    all_none = false;
                }
            }
            // A non-name entry in the names array is malformed.
            _ => return ColorSpaceKind::Unknown,
        }
    }
    let n_in = name_objs.len();
    let alt = color_space_from_object(&items[2]);
    // §8.6.6.5: the alternate "shall not be another special colour space
    // (Pattern, Indexed, Separation, or DeviceN)". A device family or a
    // CIE-based family (CalGray = 1, CalRGB / Lab = 3) is renderable;
    // its component count fixes the required tint-transform output arity.
    let alt_comps = match &alt {
        ColorSpaceKind::DeviceGray | ColorSpaceKind::CalGray { .. } => 1,
        ColorSpaceKind::DeviceRgb | ColorSpaceKind::CalRgb { .. } | ColorSpaceKind::Lab { .. } => 3,
        ColorSpaceKind::DeviceCmyk => 4,
        _ => return ColorSpaceKind::Unknown,
    };
    // An all-None space never reverts to the alternate, so the tint
    // transform is irrelevant; track it with a no-op tint so the operand
    // count is known and `scn` yields no paint.
    if all_none {
        return ColorSpaceKind::DeviceN {
            n_in,
            alt: Box::new(alt),
            tint: PdfFunction::Exponential {
                domain: [0.0, 1.0],
                range: None,
                c0: vec![0.0],
                c1: vec![0.0],
                n: 1.0,
            },
            all_none: true,
        };
    }
    let Some(tint) = PdfFunction::parse(&items[3]) else {
        return ColorSpaceKind::Unknown;
    };
    // The tint transform must be n_in-in / alt_comps-out (§8.6.6.5). A
    // mismatch is a malformed space — fall back to the black behaviour.
    if tint.input_arity() != n_in || tint.output_arity() != Some(alt_comps) {
        return ColorSpaceKind::Unknown;
    }
    ColorSpaceKind::DeviceN {
        n_in,
        alt: Box::new(alt),
        tint,
        all_none: false,
    }
}

/// Read a fixed-length array of numbers from a colour-space dictionary
/// entry — used for `WhitePoint`/`BlackPoint` (3), `Gamma` (3),
/// `Matrix` (9), and `Range` (4). Returns `None` when the key is
/// absent, not an array, the wrong length, or carries a non-number.
fn read_fixed_num_array<const N: usize>(dict: &Dict, key: &str) -> Option<[f32; N]> {
    let (_, obj) = dict.entries().iter().find(|(k, _)| k == key)?;
    let nums = read_num_array(obj)?;
    if nums.len() != N {
        return None;
    }
    let mut out = [0.0f32; N];
    out.copy_from_slice(&nums);
    Some(out)
}

/// Validate a `WhitePoint` per §8.6.5.2–4: `XW` and `ZW` shall be
/// positive and `YW` shall be 1.0. A non-conforming white point makes
/// the whole CIE space unrenderable, so the caller falls back to
/// `Unknown` (conservative black).
fn valid_white_point(w: [f32; 3]) -> bool {
    w[0] > 0.0 && w[2] > 0.0 && (w[1] - 1.0).abs() < 1e-4 && w.iter().all(|c| c.is_finite())
}

/// Reduce `[ /CalGray << /WhitePoint … /Gamma g >> ]` to a tracked
/// `CalGray` space per §8.6.5.2. `WhitePoint` is required and validated;
/// `Gamma` is an optional positive number (default 1.0).
fn cal_gray_from_array(items: &[Object]) -> ColorSpaceKind {
    let Some(Object::Dict(dict)) = items.get(1) else {
        return ColorSpaceKind::Unknown;
    };
    let Some(white) = read_fixed_num_array::<3>(dict, "WhitePoint") else {
        return ColorSpaceKind::Unknown;
    };
    if !valid_white_point(white) {
        return ColorSpaceKind::Unknown;
    }
    let gamma = match dict.entries().iter().find(|(k, _)| k == "Gamma") {
        Some((_, obj)) => match number_as_f32(obj) {
            Some(g) if g > 0.0 && g.is_finite() => g,
            // A present-but-malformed Gamma collapses the space.
            _ => return ColorSpaceKind::Unknown,
        },
        None => 1.0,
    };
    ColorSpaceKind::CalGray { white, gamma }
}

/// Reduce `[ /CalRGB << /WhitePoint … /Gamma [..] /Matrix [..] >> ]` to
/// a tracked `CalRgb` space per §8.6.5.3. `WhitePoint` is required and
/// validated; `Gamma` (default `[1 1 1]`) and `Matrix` (default
/// identity) are optional. The white point is not separately stored —
/// it is already folded into the `Matrix` columns by the producer, and
/// §8.6.5.3's transform reads only Gamma + Matrix.
fn cal_rgb_from_array(items: &[Object]) -> ColorSpaceKind {
    let Some(Object::Dict(dict)) = items.get(1) else {
        return ColorSpaceKind::Unknown;
    };
    let Some(white) = read_fixed_num_array::<3>(dict, "WhitePoint") else {
        return ColorSpaceKind::Unknown;
    };
    if !valid_white_point(white) {
        return ColorSpaceKind::Unknown;
    }
    let gamma = match dict.entries().iter().find(|(k, _)| k == "Gamma") {
        Some(_) => match read_fixed_num_array::<3>(dict, "Gamma") {
            Some(g) if g.iter().all(|x| *x > 0.0 && x.is_finite()) => g,
            _ => return ColorSpaceKind::Unknown,
        },
        None => [1.0, 1.0, 1.0],
    };
    let matrix = match dict.entries().iter().find(|(k, _)| k == "Matrix") {
        Some(_) => match read_fixed_num_array::<9>(dict, "Matrix") {
            Some(m) if m.iter().all(|x| x.is_finite()) => m,
            _ => return ColorSpaceKind::Unknown,
        },
        // Identity matrix default per Table 64.
        None => [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
    };
    ColorSpaceKind::CalRgb { gamma, matrix }
}

/// Reduce `[ /Lab << /WhitePoint … /Range [..] >> ]` to a tracked `Lab`
/// space per §8.6.5.4. `WhitePoint` is required and validated; `Range`
/// (default `[-100 100 -100 100]`) bounds the a*/b* components. A
/// malformed `Range` (wrong length, non-number, or min > max) collapses
/// the space.
fn lab_from_array(items: &[Object]) -> ColorSpaceKind {
    let Some(Object::Dict(dict)) = items.get(1) else {
        return ColorSpaceKind::Unknown;
    };
    let Some(white) = read_fixed_num_array::<3>(dict, "WhitePoint") else {
        return ColorSpaceKind::Unknown;
    };
    if !valid_white_point(white) {
        return ColorSpaceKind::Unknown;
    }
    let range = match dict.entries().iter().find(|(k, _)| k == "Range") {
        Some(_) => match read_fixed_num_array::<4>(dict, "Range") {
            Some(r) if r.iter().all(|x| x.is_finite()) && r[0] <= r[1] && r[2] <= r[3] => r,
            _ => return ColorSpaceKind::Unknown,
        },
        None => [-100.0, 100.0, -100.0, 100.0],
    };
    ColorSpaceKind::Lab { white, range }
}

impl<'a> State<'a> {
    fn new(
        ext_gstate: Option<&'a Dict>,
        font_resources: Option<&'a Dict>,
        shading_resources: Option<&'a Dict>,
        color_space_resources: Option<&'a Dict>,
        properties_resources: Option<&'a Dict>,
    ) -> Self {
        Self {
            operands: Vec::new(),
            stack: vec![Frame::new()],
            current_path: None,
            current_point: Point::default(),
            fill_paint: None,
            stroke_paint: None,
            fill_cs: ColorSpaceKind::DeviceGray,
            stroke_cs: ColorSpaceKind::DeviceGray,
            stroke_width: 1.0,
            line_cap: LineCap::Butt,
            line_join: LineJoin::Miter,
            miter_limit: 10.0,
            dash: None,
            fill_alpha: 1.0,
            stroke_alpha: 1.0,
            ext_gstate,
            font_resources,
            shading_resources,
            color_space_resources,
            properties_resources,
            mc_depth: 0,
            marked_content: Vec::new(),
            current_font: None,
            text_matrix: Transform2D::identity(),
            text_line_matrix: Transform2D::identity(),
            text_leading: 0.0,
            char_spacing: 0.0,
            word_spacing: 0.0,
            horiz_scale: 1.0,
            in_text_object: false,
            text_shows: Vec::new(),
            shadings: Vec::new(),
            inline_images: Vec::new(),
            xobject_forms: None,
            pattern_resources: None,
            tiling_patterns: None,
            fill_tiling: None,
            fill_tiling_color: None,
            stroke_tiling: None,
            type3_fonts: None,
            text_render_mode: 0,
            text_rise: 0.0,
            type3_depth: 0,
            soft_masks: None,
            active_smask: None,
            transparency_groups: None,
            image_xobjects: None,
        }
    }

    /// Attach the page's pre-parsed Form XObjects (§8.10) so the `Do`
    /// operator can splice a named form's content into the scene tree.
    /// Used by [`parse_content_stream_full_with_xobjects`]; the legacy
    /// entry points leave this `None` and `Do` stays a no-op.
    fn with_xobject_forms(mut self, forms: Option<&'a BTreeMap<String, Group>>) -> Self {
        self.xobject_forms = forms;
        self
    }

    /// Attach the page's `/Resources /Pattern` subdictionary (§8.7.3) so
    /// a `scn /Pname` shading-pattern fill (`/PatternType 2`) can paint
    /// a gradient. The legacy entry points leave this `None` and a
    /// pattern fill stays the conservative black fallback.
    fn with_pattern_resources(mut self, patterns: Option<&'a Dict>) -> Self {
        self.pattern_resources = patterns;
        self
    }

    /// Attach the page's pre-parsed `/PatternType 1` tiling patterns
    /// (§8.7.3) so a `scn /Pname` tiling-pattern fill replicates its cell
    /// across the painted region. The legacy entry points leave this
    /// `None` and a tiling-pattern fill stays the conservative black
    /// fallback.
    fn with_tiling_patterns(
        mut self,
        patterns: Option<&'a BTreeMap<String, TilingPattern>>,
    ) -> Self {
        self.tiling_patterns = patterns;
        self
    }

    /// Attach the page's pre-parsed Type 3 fonts (§9.6.5) so a
    /// `Tj`/`TJ`/`'`/`"` show under a Type 3 font paints each glyph's
    /// `/CharProcs` description into the scene tree. The legacy entry
    /// points leave this `None` and text shows stay event-only on the
    /// vector side.
    fn with_type3_fonts(mut self, fonts: Option<&'a BTreeMap<String, Type3Font>>) -> Self {
        self.type3_fonts = fonts;
        self
    }

    /// Attach the pre-resolved `/ExtGState /SMask` soft masks
    /// (§11.6.5.2) so a `gs` naming one establishes it as the current
    /// soft mask and painted objects composite through it as
    /// [`Node::SoftMask`]. The legacy entry points leave this `None`
    /// and `/SMask` stays a tolerated no-op.
    fn with_soft_masks(mut self, masks: Option<&'a BTreeMap<String, ResolvedSoftMask>>) -> Self {
        self.soft_masks = masks;
        self
    }

    /// Mark which pre-parsed forms are transparency-group XObjects
    /// (§11.6.6) so `Do` applies group-level compositing semantics.
    fn with_transparency_groups(mut self, groups: Option<&'a BTreeSet<String>>) -> Self {
        self.transparency_groups = groups;
        self
    }

    /// Attach the pre-decoded Image XObjects (§8.9.5) so a `Do`
    /// naming one splices a [`Node::Image`] into the scene.
    fn with_image_xobjects(
        mut self,
        images: Option<&'a BTreeMap<String, ResolvedImageXObject>>,
    ) -> Self {
        self.image_xobjects = images;
        self
    }

    fn finish(mut self) -> ParsedContent {
        // Unwind any unmatched `q` frames by promoting them in order
        // — the input was malformed but we'd rather salvage what we
        // can than refuse the whole document.
        while self.stack.len() > 1 {
            self.pop_q();
        }
        let root = self.stack.pop().expect("root frame present");
        ParsedContent {
            root: Group {
                transform: root.transform,
                opacity: 1.0,
                clip: root.clip,
                children: root.children,
                ..Group::default()
            },
            text_shows: self.text_shows,
            shadings: self.shadings,
            marked_content: self.marked_content,
            inline_images: self.inline_images,
        }
    }

    fn current(&mut self) -> &mut Frame {
        self.stack.last_mut().expect("at least the root frame")
    }

    /// Capture the Table 52 parameters `q` saves (§8.4.4).
    fn snapshot_gstate(&self) -> GStateSnapshot {
        GStateSnapshot {
            fill_paint: self.fill_paint.clone(),
            stroke_paint: self.stroke_paint.clone(),
            fill_cs: self.fill_cs.clone(),
            stroke_cs: self.stroke_cs.clone(),
            stroke_width: self.stroke_width,
            line_cap: self.line_cap,
            line_join: self.line_join,
            miter_limit: self.miter_limit,
            dash: self.dash.clone(),
            fill_alpha: self.fill_alpha,
            stroke_alpha: self.stroke_alpha,
            current_font: self.current_font.clone(),
            text_leading: self.text_leading,
            char_spacing: self.char_spacing,
            word_spacing: self.word_spacing,
            horiz_scale: self.horiz_scale,
            text_render_mode: self.text_render_mode,
            text_rise: self.text_rise,
            fill_tiling: self.fill_tiling.clone(),
            fill_tiling_color: self.fill_tiling_color,
            stroke_tiling: self.stroke_tiling.clone(),
            active_smask: self.active_smask.clone(),
        }
    }

    /// Reinstate the parameters the matching `q` saved (§8.4.4 `Q`).
    fn restore_gstate(&mut self, s: GStateSnapshot) {
        self.fill_paint = s.fill_paint;
        self.stroke_paint = s.stroke_paint;
        self.fill_cs = s.fill_cs;
        self.stroke_cs = s.stroke_cs;
        self.stroke_width = s.stroke_width;
        self.line_cap = s.line_cap;
        self.line_join = s.line_join;
        self.miter_limit = s.miter_limit;
        self.dash = s.dash;
        self.fill_alpha = s.fill_alpha;
        self.stroke_alpha = s.stroke_alpha;
        self.current_font = s.current_font;
        self.text_leading = s.text_leading;
        self.char_spacing = s.char_spacing;
        self.word_spacing = s.word_spacing;
        self.horiz_scale = s.horiz_scale;
        self.text_render_mode = s.text_render_mode;
        self.text_rise = s.text_rise;
        self.fill_tiling = s.fill_tiling;
        self.fill_tiling_color = s.fill_tiling_color;
        self.stroke_tiling = s.stroke_tiling;
        self.active_smask = s.active_smask;
    }

    /// Wrap a freshly painted node in the current soft mask
    /// (§11.6.4.3 — "At most one mask input … shall be provided to any
    /// PDF compositing operation") and attach it to the current frame.
    /// With no mask in force this is a plain push.
    fn push_painted(&mut self, node: Node) {
        let node = self.wrap_soft_mask(node, self.effective_ctm());
        self.current().children.push(node);
    }

    /// Wrap `node` in the active soft mask, if any. `local_to_user` is
    /// the transform from the coordinate space `node` sits in (the
    /// frame it will be attached to) up to user space — the mask's
    /// coordinate system is `/Matrix ∘ CTM-at-gs-time` (§11.6.5.2), so
    /// the mask subtree is re-expressed relative to the node's local
    /// space by `inverse(local_to_user) ∘ ctm_gs`. In the common case
    /// (mask established and used under the same CTM) that composes to
    /// the identity.
    fn wrap_soft_mask(&self, node: Node, local_to_user: Transform2D) -> Node {
        let Some(sm) = &self.active_smask else {
            return node;
        };
        let rel = match invert_transform(local_to_user) {
            Some(inv) => compose(inv, sm.ctm),
            // A singular CTM collapses everything painted under it
            // anyway; anchor the mask in user space as a fallback.
            None => sm.ctm,
        };
        Node::SoftMask {
            mask: Box::new(Node::Group(Group {
                transform: rel,
                children: vec![(*sm.mask).clone()],
                ..Group::default()
            })),
            mask_kind: sm.kind,
            content: Box::new(node),
        }
    }

    fn push_q(&mut self) {
        // `q` saves the entire graphics state (§8.4.4 Table 57). The
        // CTM + clip save/restore is structural (each frame nests a
        // `Group`); the rest of the Table 52 parameters are snapshotted
        // here and restored by the matching `Q` in `pop_q`.
        let mut frame = Frame::new();
        frame.saved = Some(Box::new(self.snapshot_gstate()));
        self.stack.push(frame);
    }

    fn pop_q(&mut self) {
        // Only pop if we have more than the root frame — otherwise
        // ignore the unbalanced `Q` per the writer's "permissive
        // recovery" stance.
        if self.stack.len() <= 1 {
            return;
        }
        let mut frame = self.stack.pop().unwrap();
        if let Some(saved) = frame.saved.take() {
            self.restore_gstate(*saved);
        }
        // Translate the frame into a Node::Group child of its parent
        // — but skip empty groups (just `q Q` with nothing in
        // between is a no-op for the IR).
        if frame.is_effectively_empty() {
            return;
        }
        let g = Group {
            transform: frame.transform,
            opacity: 1.0,
            clip: frame.clip,
            children: frame.children,
            ..Group::default()
        };
        self.current().children.push(Node::Group(g));
    }

    /// Handle one keyword (operator). Operands have already been
    /// pushed to `self.operands`.
    fn dispatch(&mut self, op: &[u8]) -> Result<(), PdfError> {
        match op {
            // Graphics state -------------------------------------
            b"q" => {
                self.push_q();
            }
            b"Q" => {
                self.pop_q();
            }
            b"cm" => {
                let nums = self.take_numbers(6)?;
                let t = Transform2D {
                    a: nums[0],
                    b: nums[1],
                    c: nums[2],
                    d: nums[3],
                    e: nums[4],
                    f: nums[5],
                };
                let frame = self.current();
                frame.transform = compose(frame.transform, t);
            }
            b"gs" => {
                // `/Name gs` — Table 57 sets graphics-state parameters
                // from the named dict in `/Resources /ExtGState`
                // (§8.4.5). When the resource map is available we apply
                // the Table 58 entries that map cleanly onto the
                // round-3 vector IR (LW / LC / LJ / ML / D / CA / ca);
                // every other key (SMask, BM, OP / op / OPM, BG / UCR /
                // TR / HT, Font, RI, SA, AIS, TK, FL, SM) is silently
                // tolerated per "any combination of parameter entries".
                let name = match self.operands.last() {
                    Some(Operand::Name(n)) => Some(n.clone()),
                    _ => None,
                };
                self.operands.clear();
                if let (Some(name), Some(ext_gstate)) = (name, self.ext_gstate) {
                    if let Some(dict) = lookup_dict(ext_gstate, &name) {
                        self.apply_ext_gstate(dict);
                        self.apply_soft_mask_entry(&name, dict);
                    }
                }
            }

            // Path construction ----------------------------------
            b"m" => {
                let p = self.take_point()?;
                let path = self.path_mut();
                path.commands.push(PathCommand::MoveTo(p));
                self.current_point = p;
            }
            b"l" => {
                let p = self.take_point()?;
                let path = self.path_mut();
                path.commands.push(PathCommand::LineTo(p));
                self.current_point = p;
            }
            b"c" => {
                let nums = self.take_numbers(6)?;
                let c1 = Point::new(nums[0], nums[1]);
                let c2 = Point::new(nums[2], nums[3]);
                let end = Point::new(nums[4], nums[5]);
                let path = self.path_mut();
                path.commands
                    .push(PathCommand::CubicCurveTo { c1, c2, end });
                self.current_point = end;
            }
            b"v" => {
                // Shorthand cubic: c1 = current point.
                let nums = self.take_numbers(4)?;
                let c1 = self.current_point;
                let c2 = Point::new(nums[0], nums[1]);
                let end = Point::new(nums[2], nums[3]);
                let path = self.path_mut();
                path.commands
                    .push(PathCommand::CubicCurveTo { c1, c2, end });
                self.current_point = end;
            }
            b"y" => {
                // Shorthand cubic: c2 = end.
                let nums = self.take_numbers(4)?;
                let c1 = Point::new(nums[0], nums[1]);
                let end = Point::new(nums[2], nums[3]);
                let c2 = end;
                let path = self.path_mut();
                path.commands
                    .push(PathCommand::CubicCurveTo { c1, c2, end });
                self.current_point = end;
            }
            b"re" => {
                // x y w h re — a rectangle as a closed subpath.
                let nums = self.take_numbers(4)?;
                let (x, y, w, h) = (nums[0], nums[1], nums[2], nums[3]);
                let path = self.path_mut();
                path.commands.push(PathCommand::MoveTo(Point::new(x, y)));
                path.commands
                    .push(PathCommand::LineTo(Point::new(x + w, y)));
                path.commands
                    .push(PathCommand::LineTo(Point::new(x + w, y + h)));
                path.commands
                    .push(PathCommand::LineTo(Point::new(x, y + h)));
                path.commands.push(PathCommand::Close);
                self.current_point = Point::new(x, y);
            }
            b"h" => {
                let path = self.path_mut();
                path.commands.push(PathCommand::Close);
            }

            // Painting -------------------------------------------
            b"f" | b"F" => self.commit_path(true, false, FillRule::NonZero),
            b"f*" => self.commit_path(true, false, FillRule::EvenOdd),
            b"S" => self.commit_path(false, true, FillRule::NonZero),
            b"s" => {
                // s = h + S — implicit close before stroke.
                if let Some(p) = &mut self.current_path {
                    p.commands.push(PathCommand::Close);
                }
                self.commit_path(false, true, FillRule::NonZero);
            }
            b"B" => self.commit_path(true, true, FillRule::NonZero),
            b"B*" => self.commit_path(true, true, FillRule::EvenOdd),
            b"b" => {
                if let Some(p) = &mut self.current_path {
                    p.commands.push(PathCommand::Close);
                }
                self.commit_path(true, true, FillRule::NonZero);
            }
            b"b*" => {
                if let Some(p) = &mut self.current_path {
                    p.commands.push(PathCommand::Close);
                }
                self.commit_path(true, true, FillRule::EvenOdd);
            }
            b"n" => {
                // No-op paint — drop the current path.
                self.current_path = None;
                self.operands.clear();
            }

            // Clip --------------------------------------------------
            b"W" | b"W*" => {
                // The clip operator consumes the current path as the
                // clip region — but in PDF the clip is committed by
                // the next paint operator, conventionally `n`. We
                // record it onto the current frame here; if the
                // upcoming paint is `n` it'll just discard the path
                // (which we've already moved into `clip`).
                if let Some(p) = self.current_path.take() {
                    self.current().clip = Some(p);
                }
                self.operands.clear();
            }

            // Colour ----------------------------------------------
            b"rg" => {
                // `rg` implicitly sets DeviceRGB nonstroking space
                // (§8.6.8 Table 74) — track it so a later bare `sc`
                // resolves in RGB.
                let nums = self.take_numbers(3)?;
                self.fill_cs = ColorSpaceKind::DeviceRgb;
                self.fill_tiling = None;
                self.fill_tiling_color = None;
                self.fill_paint = Some(Paint::Solid(rgb_from_unit(nums[0], nums[1], nums[2])));
            }
            b"RG" => {
                let nums = self.take_numbers(3)?;
                self.stroke_cs = ColorSpaceKind::DeviceRgb;
                self.stroke_tiling = None;
                self.stroke_paint = Some(Paint::Solid(rgb_from_unit(nums[0], nums[1], nums[2])));
            }
            b"g" => {
                let nums = self.take_numbers(1)?;
                self.fill_cs = ColorSpaceKind::DeviceGray;
                self.fill_tiling = None;
                self.fill_tiling_color = None;
                self.fill_paint = Some(Paint::Solid(rgb_from_unit(nums[0], nums[0], nums[0])));
            }
            b"G" => {
                let nums = self.take_numbers(1)?;
                self.stroke_cs = ColorSpaceKind::DeviceGray;
                self.stroke_tiling = None;
                self.stroke_paint = Some(Paint::Solid(rgb_from_unit(nums[0], nums[0], nums[0])));
            }
            b"k" | b"K" => {
                // DeviceCMYK fill (`k`) / stroke (`K`). The IR carries
                // only RGB, so convert per ISO 32000-1 §10.3.5
                // (DeviceCMYK → DeviceRGB): a simple operation that does
                // not involve black generation or undercolour removal.
                // The operator also sets the implicit colour space.
                let nums = self.take_numbers(4)?;
                let p = Some(Paint::Solid(rgb_from_cmyk(
                    nums[0], nums[1], nums[2], nums[3],
                )));
                if op == b"K" {
                    self.stroke_cs = ColorSpaceKind::DeviceCmyk;
                    self.stroke_tiling = None;
                    self.stroke_paint = p;
                } else {
                    self.fill_cs = ColorSpaceKind::DeviceCmyk;
                    self.fill_tiling = None;
                    self.fill_tiling_color = None;
                    self.fill_paint = p;
                }
            }
            b"sc" | b"scn" => {
                // `sc`/`scn` set the nonstroking colour in whatever
                // space the most-recent `cs` selected (§8.6.8). When
                // that's a device family with a fixed component count,
                // interpret the numeric operands directly; otherwise
                // (Pattern, an unresolved resource colour space, or a
                // trailing `/Name` pattern operand) keep the round-3
                // conservative black fallback.
                // A `/PatternType 1` tiling-pattern operand defers to
                // `commit_path`, which replicates the cell across the
                // filled region; record it (and clear any stale shading
                // paint). A non-tiling operand clears the tiling state.
                self.fill_tiling = self.tiling_pattern_name_from_operand();
                // For an uncoloured (`/PaintType 2`) pattern, capture the
                // underlying colour the cell stencil is poured with from
                // the numeric operands preceding the name (§8.7.3.3).
                self.fill_tiling_color = self
                    .fill_tiling
                    .as_ref()
                    .and_then(|n| self.uncoloured_tiling_color(n));
                let paint = self
                    .color_from_components(&self.fill_cs.clone())
                    .or_else(|| self.pattern_paint_from_operand());
                self.fill_paint = paint.or_else(|| {
                    self.fill_paint
                        .clone()
                        .or(Some(Paint::Solid(Rgba::opaque(0, 0, 0))))
                });
                self.operands.clear();
            }
            b"SC" | b"SCN" => {
                self.stroke_tiling = self.tiling_pattern_name_from_operand();
                let paint = self
                    .color_from_components(&self.stroke_cs.clone())
                    .or_else(|| self.pattern_paint_from_operand());
                self.stroke_paint = paint.or_else(|| {
                    self.stroke_paint
                        .clone()
                        .or(Some(Paint::Solid(Rgba::opaque(0, 0, 0))))
                });
                self.operands.clear();
            }
            b"cs" => {
                // Nonstroking colour-space switch — last operand is a
                // /Name. Record the space so a following `sc`/`scn`
                // knows how to read its components. Setting a device
                // colour space initialises the current colour to its
                // black/zero value per §8.6.4.2..4 ("Setting … shall
                // initialize the corresponding current colour to 0.0").
                self.fill_cs = self.take_color_space_name();
                self.fill_tiling = None;
                self.fill_tiling_color = None;
                self.fill_paint = initial_color_for(&self.fill_cs);
                self.operands.clear();
            }
            b"CS" => {
                self.stroke_cs = self.take_color_space_name();
                self.stroke_tiling = None;
                self.stroke_paint = initial_color_for(&self.stroke_cs);
                self.operands.clear();
            }

            // Stroke style -----------------------------------------
            b"w" => {
                let nums = self.take_numbers(1)?;
                self.stroke_width = nums[0];
            }
            b"J" => {
                let nums = self.take_numbers(1)?;
                self.line_cap = match nums[0] as i32 {
                    0 => LineCap::Butt,
                    1 => LineCap::Round,
                    2 => LineCap::Square,
                    _ => LineCap::Butt,
                };
            }
            b"j" => {
                let nums = self.take_numbers(1)?;
                self.line_join = match nums[0] as i32 {
                    0 => LineJoin::Miter,
                    1 => LineJoin::Round,
                    2 => LineJoin::Bevel,
                    _ => LineJoin::Miter,
                };
            }
            b"M" => {
                let nums = self.take_numbers(1)?;
                self.miter_limit = nums[0];
            }
            b"d" => {
                // [array] offset d. The array carries numbers only
                // — strings inside a `d`-array are malformed PDF and
                // are dropped (rather than refused) for tolerance.
                if self.operands.len() < 2 {
                    self.operands.clear();
                    return Ok(());
                }
                let offset = match self.operands.pop().unwrap() {
                    Operand::Number(n) => n,
                    _ => 0.0,
                };
                let array = match self.operands.pop().unwrap() {
                    Operand::Array(v) => v
                        .into_iter()
                        .filter_map(|el| match el {
                            ArrayElem::Number(n) => Some(n),
                            ArrayElem::String(_) => None,
                        })
                        .collect::<Vec<f32>>(),
                    _ => Vec::new(),
                };
                self.dash = if array.is_empty() {
                    None
                } else {
                    Some(DashPattern { array, offset })
                };
                self.operands.clear();
            }

            // Text-object brackets (§9.4 + Table 105) -------------
            b"BT" => {
                // §9.4 — every BT resets the text matrix + text line
                // matrix to identity. Leading + font carry across BT
                // boundaries per §9.3 Table 105 NOTE 1.
                self.text_matrix = Transform2D::identity();
                self.text_line_matrix = Transform2D::identity();
                self.in_text_object = true;
                self.operands.clear();
            }
            b"ET" => {
                self.in_text_object = false;
                self.operands.clear();
            }

            // Text state — §9.3 + Table 105 ------------------------
            b"Tf" => {
                // /Fx size Tf — last two operands are the font
                // resource name + the size.
                let size = match self.operands.last() {
                    Some(Operand::Number(n)) => *n,
                    _ => 0.0,
                };
                let name = match self.operands.iter().rev().nth(1) {
                    Some(Operand::Name(s)) => s.clone(),
                    _ => String::new(),
                };
                self.current_font = Some((name, size));
                self.operands.clear();
            }
            b"TL" => {
                // single-number text leading.
                if let Some(Operand::Number(n)) = self.operands.last() {
                    self.text_leading = *n;
                }
                self.operands.clear();
            }
            b"Tc" => {
                // charSpace Tc — set character spacing (§9.3.2). Feeds
                // the §9.4.4 displacement so consecutive shows on a
                // line advance correctly.
                if let Some(Operand::Number(n)) = self.operands.last() {
                    self.char_spacing = *n;
                }
                self.operands.clear();
            }
            b"Tw" => {
                // wordSpace Tw — set word spacing (§9.3.3). Applied to
                // single-byte code-32 glyphs in the §9.4.4
                // displacement.
                if let Some(Operand::Number(n)) = self.operands.last() {
                    self.word_spacing = *n;
                }
                self.operands.clear();
            }
            b"Tz" => {
                // scale Tz — set horizontal scaling (§9.3.4). The
                // operand is a percentage; Th is `scale ÷ 100`.
                if let Some(Operand::Number(n)) = self.operands.last() {
                    self.horiz_scale = *n / 100.0;
                }
                self.operands.clear();
            }
            b"Tr" => {
                // `render Tr` — text rendering mode (§9.3.6 Table 106).
                // Mode 3 (invisible) suppresses Type 3 glyph painting;
                // every other mode paints. The mode also affects the
                // fill/stroke split for outline fonts, which is moot on
                // the vector side here.
                if let Some(Operand::Number(n)) = self.operands.last() {
                    self.text_render_mode = *n as i64;
                }
                self.operands.clear();
            }
            b"Ts" => {
                // `rise Ts` — text rise (§9.4.4), the vertical offset
                // baked into the text-rendering matrix. Tracked for the
                // Type 3 glyph paint path.
                if let Some(Operand::Number(n)) = self.operands.last() {
                    self.text_rise = *n;
                }
                self.operands.clear();
            }

            // Text positioning — §9.4.2 + Table 108 ---------------
            b"Td" => {
                // tx ty Td — text-line-matrix moves by (tx, ty);
                // text matrix copies from it.
                if let Ok(nums) = self.take_numbers(2) {
                    let (tx, ty) = (nums[0], nums[1]);
                    let m = Transform2D {
                        a: 1.0,
                        b: 0.0,
                        c: 0.0,
                        d: 1.0,
                        e: tx,
                        f: ty,
                    };
                    self.text_line_matrix = compose(self.text_line_matrix, m);
                    self.text_matrix = self.text_line_matrix;
                }
                self.operands.clear();
            }
            b"TD" => {
                // tx ty TD — equivalent to "-ty TL tx ty Td".
                if let Ok(nums) = self.take_numbers(2) {
                    let (tx, ty) = (nums[0], nums[1]);
                    self.text_leading = -ty;
                    let m = Transform2D {
                        a: 1.0,
                        b: 0.0,
                        c: 0.0,
                        d: 1.0,
                        e: tx,
                        f: ty,
                    };
                    self.text_line_matrix = compose(self.text_line_matrix, m);
                    self.text_matrix = self.text_line_matrix;
                }
                self.operands.clear();
            }
            b"Tm" => {
                // a b c d e f Tm — set text matrix + text line matrix
                // to the six-element matrix verbatim.
                if let Ok(nums) = self.take_numbers(6) {
                    let m = Transform2D {
                        a: nums[0],
                        b: nums[1],
                        c: nums[2],
                        d: nums[3],
                        e: nums[4],
                        f: nums[5],
                    };
                    self.text_matrix = m;
                    self.text_line_matrix = m;
                }
                self.operands.clear();
            }
            b"T*" => {
                // Move to the next line — `0 -Tl Td`. (Note the sign:
                // §9.4.2 Table 108 says `0 -Tl Td`; `text_leading` is
                // already the positive y-step, so the displacement is
                // `(0, -Tl)`.)
                let leading = self.text_leading;
                let m = Transform2D {
                    a: 1.0,
                    b: 0.0,
                    c: 0.0,
                    d: 1.0,
                    e: 0.0,
                    f: -leading,
                };
                self.text_line_matrix = compose(self.text_line_matrix, m);
                self.text_matrix = self.text_line_matrix;
                self.operands.clear();
            }

            // Text showing — §9.4.3 + Table 109 -------------------
            b"Tj" => {
                // string Tj
                let bytes = match self.operands.last() {
                    Some(Operand::String(s)) => s.clone(),
                    _ => Vec::new(),
                };
                let metrics = self.current_font_metrics();
                self.emit_text_show(bytes.clone(), TextShowOp::Tj);
                // §9.6.5 — a Type 3 font paints each glyph's /CharProcs
                // description into the scene at the current text origin,
                // before Tm advances.
                self.paint_type3_show(&bytes);
                // §9.4.4 — advance Tm by the shown glyphs so a
                // following show on the same line starts at the right
                // origin.
                self.advance_text(&bytes, &metrics);
                self.operands.clear();
            }
            b"TJ" => {
                // [(s1) num1 (s2) num2 …] TJ — show the strings in
                // array order, advancing the text matrix between each
                // glyph (§9.4.4) and applying the per-element numeric
                // kern adjustments (§9.4.3: a number `Tj` translates
                // Tm by `−Tj/1000 × Tfs × Th`). The decoded payload
                // surfaced on the event is the concatenation of every
                // string element.
                let metrics = self.current_font_metrics();
                let mut bytes = Vec::new();
                let mut elements: Vec<TjElem> = Vec::new();
                if let Some(Operand::Array(items)) = self.operands.last() {
                    for el in items {
                        match el {
                            ArrayElem::String(s) => {
                                bytes.extend_from_slice(s);
                                elements.push(TjElem::Str(s.clone()));
                            }
                            ArrayElem::Number(n) => elements.push(TjElem::Kern(*n)),
                        }
                    }
                }
                // Record the show at the array's start origin first.
                self.emit_text_show(bytes, TextShowOp::TJ);
                let tfs = self.current_font.as_ref().map(|(_, s)| *s).unwrap_or(0.0);
                let th = self.horiz_scale;
                for el in elements {
                    match el {
                        TjElem::Str(s) => {
                            // §9.6.5 — paint Type 3 glyphs at this
                            // element's origin, then advance Tm past
                            // them (so the next element / kern starts
                            // at the right place).
                            self.paint_type3_show(&s);
                            self.advance_text(&s, &metrics);
                        }
                        TjElem::Kern(adj) => {
                            // A positive kern moves the next glyph
                            // *left* (§9.4.3): tx = −adj/1000 × Tfs × Th.
                            let tx = -adj / 1000.0 * tfs * th;
                            self.translate_text(tx);
                        }
                    }
                }
                self.operands.clear();
            }
            b"'" => {
                // ' string — T* then Tj. Implicit line-advance per
                // Table 109.
                let leading = self.text_leading;
                let m = Transform2D {
                    a: 1.0,
                    b: 0.0,
                    c: 0.0,
                    d: 1.0,
                    e: 0.0,
                    f: -leading,
                };
                self.text_line_matrix = compose(self.text_line_matrix, m);
                self.text_matrix = self.text_line_matrix;
                let bytes = match self.operands.last() {
                    Some(Operand::String(s)) => s.clone(),
                    _ => Vec::new(),
                };
                let metrics = self.current_font_metrics();
                self.emit_text_show(bytes.clone(), TextShowOp::SingleQuote);
                self.paint_type3_show(&bytes);
                self.advance_text(&bytes, &metrics);
                self.operands.clear();
            }
            b"\"" => {
                // aw ac string " — set word spacing (aw) + char spacing
                // (ac), do an implicit T*, then show like Tj
                // (§9.4.3 / Table 109). The two leading numeric
                // operands set Tw and Tc for this and subsequent shows.
                let (aw, ac) = match (
                    self.operands.iter().rev().nth(2),
                    self.operands.iter().rev().nth(1),
                ) {
                    (Some(Operand::Number(aw)), Some(Operand::Number(ac))) => (*aw, *ac),
                    _ => (self.word_spacing, self.char_spacing),
                };
                self.word_spacing = aw;
                self.char_spacing = ac;
                let leading = self.text_leading;
                let m = Transform2D {
                    a: 1.0,
                    b: 0.0,
                    c: 0.0,
                    d: 1.0,
                    e: 0.0,
                    f: -leading,
                };
                self.text_line_matrix = compose(self.text_line_matrix, m);
                self.text_matrix = self.text_line_matrix;
                let bytes = match self.operands.last() {
                    Some(Operand::String(s)) => s.clone(),
                    _ => Vec::new(),
                };
                let metrics = self.current_font_metrics();
                self.emit_text_show(bytes.clone(), TextShowOp::DoubleQuote);
                self.paint_type3_show(&bytes);
                self.advance_text(&bytes, &metrics);
                self.operands.clear();
            }

            // Type 3 glyph metrics (§9.6.5 Table 113) ---------------
            b"d0" | b"d1" => {
                // `wx wy d0` / `wx wy llx lly urx ury d1` — declare the
                // glyph's width (and, for d1, bounding box). These only
                // appear as the first operator of a /CharProcs glyph
                // description; the width is already taken from the
                // font's /Widths array (§9.6.5) and the bbox is purely
                // advisory, so the marks are produced by the path /
                // image operators that follow. Drop the operands so the
                // numbers don't leak into the next operator.
                self.operands.clear();
            }

            // XObject paint ----------------------------------------
            b"Do" => {
                // `/Name Do` — paint an external object (§8.8). A Form
                // XObject (§8.10) is spliced into the scene tree here;
                // an Image XObject is left to the dedicated
                // [`crate::reader::images`] walker (round-3 no-op on the
                // scene side).
                //
                // §8.10.1 specifies the Do-on-form algorithm as:
                //   a) q (save graphics state)
                //   b) concat the form's /Matrix with the CTM
                //   c) clip to the form's /BBox
                //   d) paint the form's content stream
                //   e) Q (restore)
                //
                // The pre-parsed form `Group` already carries /Matrix in
                // its `transform` and the /BBox rectangle in its `clip`,
                // so pushing it as a child of the current frame applies
                // (b)+(c) under the frame's accumulated `cm` CTM — the
                // q/Q bracket is implicit in the nested-group boundary.
                let name = match self.operands.last() {
                    Some(Operand::Name(n)) => n.clone(),
                    _ => String::new(),
                };
                if !name.is_empty() {
                    // Image XObject (§8.9.5.2): the image fills the
                    // unit square of the current space, sample (0,0)
                    // on the top edge. The `ImageRef` convention
                    // (established by this crate's writer) doubles
                    // `bounds` as the pixel dimensions with data row 0
                    // at the top of the rect, so the splice is
                    // `bounds = (0, 0, w, h)` under a `1/w × 1/h`
                    // scale: the writer's own `T(bx, by+bh)·S(bw,-bh)`
                    // placement composed with that scale reproduces
                    // the §8.9.5.2 unit-square map exactly (the two
                    // vertical flips cancel), making the node
                    // writer-round-trippable.
                    if let Some(img) = self.image_xobjects.and_then(|m| m.get(&name)) {
                        let node = Node::Image(ImageRef {
                            frame: Box::new(VideoFrame {
                                pts: None,
                                planes: vec![VideoPlane {
                                    stride: img.width as usize * 4,
                                    data: img.rgba.clone(),
                                }],
                            }),
                            bounds: Rect::new(0.0, 0.0, img.width as f32, img.height as f32),
                            transform: Transform2D {
                                a: 1.0 / img.width as f32,
                                b: 0.0,
                                c: 0.0,
                                d: 1.0 / img.height as f32,
                                e: 0.0,
                                f: 0.0,
                            },
                        });
                        self.push_painted(node);
                        self.operands.clear();
                        return Ok(());
                    }
                    if let Some(form) = self.xobject_forms.and_then(|m| m.get(&name)) {
                        if !form.children.is_empty() {
                            let mut group = form.clone();
                            // §11.6.6 — a *transparency-group* XObject
                            // composites into its parent as a unit, so
                            // the current nonstroking alpha constant
                            // applies to the group's results
                            // (§11.6.4.4), not to each object inside
                            // it. (The group's own content already
                            // parsed with fresh state — blend Normal,
                            // alphas 1.0, soft mask None — per the
                            // §11.6.6 initialisation rule, so nothing
                            // is applied twice.) An ordinary form gets
                            // no grouping behaviour.
                            if self.fill_alpha < 1.0
                                && self
                                    .transparency_groups
                                    .is_some_and(|set| set.contains(&name))
                            {
                                group.opacity *= self.fill_alpha;
                            }
                            self.push_painted(Node::Group(group));
                        }
                    }
                }
                self.operands.clear();
            }

            // Shading paint (§8.7.4.5) -----------------------------
            b"sh" => {
                // `name sh` — paint the shape and colour shading
                // described by a shading dictionary, subject to the
                // current clipping path. The current colour in the
                // graphics state is neither used nor altered.
                //
                // We record one [`ContentShading`] event per `sh` so
                // a downstream consumer can resolve the shading
                // dictionary's `ShadingType` / `ColorSpace` /
                // `Coords` / `Function` (Tables 78..86) into a
                // concrete paint. The walker does NOT interpret the
                // shading dictionary itself — that would require
                // colour-space resolution + function evaluation
                // (§7.10) + the per-type geometry rules (axial /
                // radial / Gouraud / Coons / tensor), all of which
                // belong in a dedicated shading-resolver crate or
                // module.
                let name = match self.operands.last() {
                    Some(Operand::Name(n)) => n.clone(),
                    _ => String::new(),
                };
                let shading_dict = match (self.shading_resources, name.as_str()) {
                    (Some(res), n) if !n.is_empty() => lookup_dict(res, n).cloned(),
                    _ => None,
                };
                // A Type 4–7 (mesh) shading is evaluated into its
                // device-space triangle / patch geometry; a Type 1–3
                // (function-based / axial / radial) shading is evaluated
                // into sampled-colour gradient stops. Exactly one of
                // `mesh` / `gradient` is populated (or neither, when the
                // shading can't be reduced).
                let mesh = shading_dict
                    .as_ref()
                    .and_then(|d| evaluate_mesh_shading(d, self.color_space_resources));
                let gradient = shading_dict
                    .as_ref()
                    .and_then(|d| evaluate_gradient_shading(d, self.color_space_resources));
                let ctm = self.effective_ctm();
                let clip = self.current_clip();
                // Paint a clipped axial / radial `sh` into the scene: the
                // shading fills the current clipping region (§8.7.4.5). The
                // clip path is in the current frame's local coordinate
                // basis — the same basis the shading `Coords` are written
                // in — so the gradient maps into it by identity (the
                // frame's accumulated `cm` is applied once when the node is
                // rendered). We only paint when a clip is in force; an
                // unclipped `sh` would fill the whole page, which we leave
                // to the `ContentShading` event rather than synthesising a
                // page-sized fill. Type 1 (function-based) and mesh
                // shadings have no `Paint` analogue and stay event-only.
                if let Some(clip_path) = &clip {
                    if let Some(paint) = gradient
                        .as_ref()
                        .and_then(|g| gradient_to_paint(g, Transform2D::identity()))
                    {
                        let node = Node::Path(PathNode {
                            path: clip_path.clone(),
                            fill: Some(apply_alpha(paint, self.fill_alpha)),
                            stroke: None,
                            fill_rule: FillRule::NonZero,
                        });
                        self.push_painted(node);
                    }
                }
                self.shadings.push(ContentShading {
                    name,
                    shading_dict,
                    ctm,
                    clip,
                    mesh,
                    gradient,
                });
                self.operands.clear();
            }

            // Marked content (§14.6 Table 320) ---------------------
            b"MP" => {
                // `tag MP` — marked-content point. The point sits
                // inside whatever sequence is currently open, so its
                // reported depth is the current open-sequence count.
                let tag = self.last_name_operand();
                let depth = self.mc_depth;
                self.marked_content.push(ContentMarkedContent {
                    operator: MarkedContentOp::Mp,
                    tag,
                    properties: None,
                    depth,
                });
                self.operands.clear();
            }
            b"DP" => {
                // `tag properties DP` — marked-content point with a
                // property list. `properties` is the operand after the
                // tag (an inline dict or a /Name into /Properties).
                let (tag, properties) = self.marked_content_tag_props();
                let depth = self.mc_depth;
                self.marked_content.push(ContentMarkedContent {
                    operator: MarkedContentOp::Dp,
                    tag,
                    properties,
                    depth,
                });
                self.operands.clear();
            }
            b"BMC" => {
                // `tag BMC` — begin a marked-content sequence. The
                // sequence's own depth is the current count *before*
                // we open it; the count then increments.
                let tag = self.last_name_operand();
                let depth = self.mc_depth;
                self.marked_content.push(ContentMarkedContent {
                    operator: MarkedContentOp::Bmc,
                    tag,
                    properties: None,
                    depth,
                });
                self.mc_depth = self.mc_depth.saturating_add(1);
                self.operands.clear();
            }
            b"BDC" => {
                // `tag properties BDC` — begin a sequence with a
                // property list.
                let (tag, properties) = self.marked_content_tag_props();
                let depth = self.mc_depth;
                self.marked_content.push(ContentMarkedContent {
                    operator: MarkedContentOp::Bdc,
                    tag,
                    properties,
                    depth,
                });
                self.mc_depth = self.mc_depth.saturating_add(1);
                self.operands.clear();
            }
            b"EMC" => {
                // End the most recent `BMC`/`BDC` sequence. Decrement
                // first (saturating, so an unbalanced `EMC` reports
                // depth 0 and is tolerated) and report the depth of the
                // sequence it closes.
                self.mc_depth = self.mc_depth.saturating_sub(1);
                let depth = self.mc_depth;
                self.marked_content.push(ContentMarkedContent {
                    operator: MarkedContentOp::Emc,
                    tag: String::new(),
                    properties: None,
                    depth,
                });
                self.operands.clear();
            }

            // Everything else --------------------------------------
            _ => {
                self.operands.clear();
            }
        }
        Ok(())
    }

    /// The most-recent `Name` operand (leading `/` already stripped at
    /// scan time), or empty when none was pushed. Used by the no-
    /// property marked-content operators `MP` / `BMC` whose only
    /// operand is the tag name.
    fn last_name_operand(&self) -> String {
        self.operands
            .iter()
            .rev()
            .find_map(|o| match o {
                Operand::Name(n) => Some(n.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// Resolve the `tag properties` operand pair for `DP` / `BDC`
    /// (§14.6 Table 320). The operands are `tag` then `properties` in
    /// stream order, so on the stack `properties` is last and `tag` is
    /// the `Name` before it.
    ///
    /// * `tag` — the first `Name` operand.
    /// * `properties` — resolved per §14.6.2: an inline `Operand::Dict`
    ///   is captured directly; an `Operand::Name` is looked up in the
    ///   `/Resources /Properties` subdictionary (`properties_resources`)
    ///   and dereferenced one hop into a `Dict`. `None` when the operand
    ///   is absent, isn't a dict/name, or the name doesn't resolve.
    fn marked_content_tag_props(&self) -> (String, Option<Dict>) {
        // tag is the first Name from the bottom; properties is the last
        // operand. A well-formed `tag properties` pair has the tag as
        // the earliest Name operand.
        let tag = self
            .operands
            .iter()
            .find_map(|o| match o {
                Operand::Name(n) => Some(n.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let properties = match self.operands.last() {
            Some(Operand::Dict(d)) => Some(d.clone()),
            // A `/Name` properties operand — but only when it isn't the
            // tag itself (a bare `tag BDC`-shaped misuse with no real
            // property operand should resolve to `None`, not loop the
            // tag name back through /Properties).
            Some(Operand::Name(n)) if self.operands.len() >= 2 => self
                .properties_resources
                .and_then(|res| lookup_dict(res, n).cloned()),
            _ => None,
        };
        (tag, properties)
    }

    /// Compose every frame's `transform` from the root down to the
    /// current top frame. PDF's CTM is the accumulated product of
    /// every `cm` since the start of the content stream (across `q`
    /// frames — a `Q` pops the frame and discards its transform, but
    /// while the frame is live its transform composes with the
    /// ancestor frames').
    ///
    /// Mirrors the convention `commit_path` uses when it emits a
    /// `Node::Path` into the current frame: the path's coordinates
    /// are in the local frame's space; the frame's transform is the
    /// `cm` accumulation since the most recent `q`. To get user-space
    /// coordinates we have to compose root-to-leaf, which is what
    /// this helper returns.
    fn effective_ctm(&self) -> Transform2D {
        let mut acc = Transform2D::identity();
        for frame in &self.stack {
            acc = compose(acc, frame.transform);
        }
        acc
    }

    /// Return a clone of the most recent `W`/`W*`-committed clip
    /// path in the active frame. `None` when the current frame has
    /// no clip in force (in PDF the clip is per-`q` — a `Q` restores
    /// the parent frame's clip; we expose only the current frame's
    /// clip because the parent's was already in force before we
    /// entered the child `q`).
    fn current_clip(&self) -> Option<Path> {
        self.stack.last().and_then(|f| f.clip.clone())
    }

    fn commit_path(&mut self, fill: bool, stroke: bool, rule: FillRule) {
        let Some(path) = self.current_path.take() else {
            self.operands.clear();
            return;
        };
        // A `/PatternType 1` tiling-pattern fill (§8.7.3) replicates the
        // pattern cell across the filled region instead of painting a
        // solid colour. When one is active, emit the tiled cells (clipped
        // to `path`) and drop the solid fill on the PathNode — the stroke,
        // if any, still paints below.
        let tiled = if fill {
            self.emit_tiling_fill(&path, rule)
        } else {
            false
        };
        let fill_paint = if fill && !tiled {
            let base = self
                .fill_paint
                .clone()
                .unwrap_or(Paint::Solid(Rgba::opaque(0, 0, 0)));
            Some(apply_alpha(base, self.fill_alpha))
        } else {
            None
        };
        let stroke_obj = if stroke {
            let stroke_paint = self
                .stroke_paint
                .clone()
                .unwrap_or(Paint::Solid(Rgba::opaque(0, 0, 0)));
            Some(Stroke {
                width: self.stroke_width,
                paint: apply_alpha(stroke_paint, self.stroke_alpha),
                cap: self.line_cap,
                join: self.line_join,
                miter_limit: self.miter_limit,
                dash: self.dash.clone(),
            })
        } else {
            None
        };
        let node = Node::Path(PathNode {
            path,
            fill: fill_paint,
            stroke: stroke_obj,
            fill_rule: rule,
        });
        self.push_painted(node);
        self.operands.clear();
    }

    /// Replicate the active `/PatternType 1` tiling pattern's cell
    /// across the region bounded by `fill_path` (§8.7.3.1). Returns
    /// `true` when a tiling fill was emitted (so [`commit_path`] drops
    /// the solid fill), `false` otherwise (no tiling pattern active or
    /// resolvable — the caller keeps its existing fill).
    ///
    /// Geometry (§8.7.2 NOTE 1 + §8.7.3.1):
    /// * The pattern `/Matrix` maps pattern space to the page's default
    ///   (initial) coordinate space — the root frame's local space —
    ///   independent of any `cm` in force at paint time. The tiled group
    ///   is therefore emitted as a child of the **root** frame, with each
    ///   tile placed at `Matrix · translate(i·XStep, j·YStep)`.
    /// * Each tile clones the cell `Group` and clips it to the `/BBox`.
    /// * The fill region clips the whole tiling: `fill_path` is mapped
    ///   from the current frame's local space into root-local space
    ///   (composing the frames above the root) and used as the group clip.
    /// * The `i`/`j` index range is the cell-origin lattice covering the
    ///   fill region's bounding box, mapped back through the inverse of
    ///   the pattern matrix; the tile count is hard-capped so a huge fill
    ///   over a tiny step can't explode.
    fn emit_tiling_fill(&mut self, fill_path: &Path, rule: FillRule) -> bool {
        let Some(name) = self.fill_tiling.clone() else {
            return false;
        };
        let Some(pat) = self.tiling_patterns.and_then(|m| m.get(&name)) else {
            return false;
        };
        if pat.cell.children.is_empty() {
            return false;
        }
        let xstep = pat.xstep;
        let ystep = pat.ystep;
        if !xstep.is_finite() || !ystep.is_finite() || xstep == 0.0 || ystep == 0.0 {
            return false;
        }
        // Map `fill_path` from the current frame's local space into the
        // root frame's local space (= compose of every frame above the
        // root). At the root frame this is identity.
        let mut above_root = Transform2D::identity();
        for frame in self.stack.iter().skip(1) {
            above_root = compose(above_root, frame.transform);
        }
        let region_path = transform_path(fill_path, above_root);
        let Some((rx0, ry0, rx1, ry1)) = path_bounds(&region_path) else {
            return false;
        };
        // Invert the pattern matrix to map the region bbox corners into
        // pattern space and bound the tile lattice.
        let Some(inv) = invert_transform(pat.matrix) else {
            return false;
        };
        let corners = [
            inv.apply(Point::new(rx0, ry0)),
            inv.apply(Point::new(rx1, ry0)),
            inv.apply(Point::new(rx0, ry1)),
            inv.apply(Point::new(rx1, ry1)),
        ];
        let (mut px0, mut py0, mut px1, mut py1) = (
            f32::INFINITY,
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::NEG_INFINITY,
        );
        for c in corners {
            if !c.x.is_finite() || !c.y.is_finite() {
                return false;
            }
            px0 = px0.min(c.x);
            py0 = py0.min(c.y);
            px1 = px1.max(c.x);
            py1 = py1.max(c.y);
        }
        // Tile-index range over the pattern-space bbox, padded by one
        // cell each side so a cell whose /BBox overhangs its step still
        // covers the region edges.
        let i_lo = (px0 / xstep).floor() as i64 - 1;
        let i_hi = (px1 / xstep).ceil() as i64 + 1;
        let j_lo = (py0 / ystep).floor() as i64 - 1;
        let j_hi = (py1 / ystep).ceil() as i64 + 1;
        // Normalise so the range is well-ordered regardless of a negative
        // XStep / YStep (Table 75 allows either sign).
        let (i_lo, i_hi) = (i_lo.min(i_hi), i_lo.max(i_hi));
        let (j_lo, j_hi) = (j_lo.min(j_hi), j_lo.max(j_hi));
        let tile_count = (i_hi - i_lo + 1).saturating_mul(j_hi - j_lo + 1);
        if tile_count <= 0 || tile_count > MAX_TILING_CELLS {
            return false;
        }
        // The /BBox clip (pattern space) applied per tile.
        let bbox_clip = rect_path(pat.bbox[0], pat.bbox[1], pat.bbox[2], pat.bbox[3]);
        // An uncoloured (`/PaintType 2`) cell is a stencil poured with
        // the underlying colour the `scn` supplied (§8.7.3.3); default to
        // black when none was given. A coloured cell keeps its own paint.
        let stencil_color = if pat.paint_type == 2 {
            Some(self.fill_tiling_color.unwrap_or(Rgba::opaque(0, 0, 0)))
        } else {
            None
        };
        let mut tiles: Vec<Node> = Vec::new();
        for j in j_lo..=j_hi {
            for i in i_lo..=i_hi {
                let placement = compose(
                    pat.matrix,
                    Transform2D::translate(i as f32 * xstep, j as f32 * ystep),
                );
                let mut cell = pat.cell.clone();
                cell.transform = placement;
                // Clip the cell to its /BBox (pattern space).
                cell.clip = Some(bbox_clip.clone());
                if let Some(color) = stencil_color {
                    for child in &mut cell.children {
                        recolor_node(child, color);
                    }
                }
                tiles.push(Node::Group(cell));
            }
        }
        if tiles.is_empty() {
            return false;
        }
        // One group, clipped to the fill region (root-local space),
        // holding every tile. Pushed onto the root frame so the pattern
        // stays anchored to page space (§8.7.2 NOTE 1).
        let mut region_clip = region_path;
        // Preserve the fill rule on the clip path (NonZero vs EvenOdd
        // from the `f` / `f*` operator) per §8.5.3.3.
        let _ = rule;
        if region_clip.commands.is_empty() {
            return false;
        }
        // Intersect with any clip already in force on the current frame,
        // mapped to root space, by nesting: outer group carries the
        // active clip, inner the fill region. We keep it simple — the
        // fill region is the dominant clip for the tiling.
        let group = Group {
            transform: Transform2D::identity(),
            opacity: 1.0,
            clip: Some(std::mem::take(&mut region_clip)),
            children: tiles,
            ..Group::default()
        };
        // The tiled group is attached to the *root* frame (its lattice
        // is anchored to the page's default space, §8.7.2 NOTE 1), so
        // the soft-mask wrap — if one is in force — is expressed
        // relative to root-local space rather than the current frame's.
        let node = self.wrap_soft_mask(Node::Group(group), self.stack[0].transform);
        self.stack[0].children.push(node);
        true
    }

    /// Emit one [`ContentTextShow`] event for the current state. Only
    /// fired when `in_text_object` is `true` and the caller plumbed
    /// in `/Resources /Font` (so we have a meaningful font_dict to
    /// hand back); outside a `BT` or without font resources the show
    /// silently drops so the legacy `parse_content_stream` /
    /// `parse_content_stream_with_resources` callers don't see new
    /// behaviour.
    ///
    /// The position is the text-matrix origin `(e, f)` at the moment
    /// of the show — §9.4.4 Table 108's `Tm = [a b c d e f]`.
    fn emit_text_show(&mut self, bytes: Vec<u8>, operator: TextShowOp) {
        if !self.in_text_object || self.font_resources.is_none() {
            return;
        }
        let (font_name, font_size) = match &self.current_font {
            Some((n, s)) => (n.clone(), *s),
            None => (String::new(), 0.0),
        };
        let font_dict = match self.font_resources {
            Some(fr) if !font_name.is_empty() => lookup_dict(fr, &font_name).cloned(),
            _ => None,
        };
        self.text_shows.push(ContentTextShow {
            font_name,
            font_size,
            font_dict,
            bytes,
            position: (self.text_matrix.e, self.text_matrix.f),
            operator,
        });
    }

    /// Resolve the currently-selected font (`Tf` name) into
    /// [`FontMetrics`]. Returns [`FontMetrics::None`] when no font is
    /// set, the name isn't in `/Resources /Font`, or the dict carries
    /// no resolvable width data.
    fn current_font_metrics(&self) -> FontMetrics {
        let name = match &self.current_font {
            Some((n, _)) if !n.is_empty() => n.as_str(),
            _ => return FontMetrics::None,
        };
        match self.font_resources.and_then(|fr| lookup_dict(fr, name)) {
            Some(d) => build_font_metrics(d),
            None => FontMetrics::None,
        }
    }

    /// Advance the text matrix `Tm` by the displacement of every glyph
    /// in `bytes`, per §9.4.4. `metrics` supplies the per-glyph widths;
    /// the current `char_spacing` / `word_spacing` / `horiz_scale` /
    /// font size feed the displacement equation
    ///
    /// ```text
    /// tx = ((w0 − Tj/1000)·Tfs + Tc + Tw)·Th
    /// ```
    ///
    /// with `Tj = 0` (the per-element `TJ` kern is applied separately).
    /// `Tw` is added only for the single-byte code 32 (ASCII space) per
    /// §9.3.3. Word/char spacing and `Th` scaling are applied even when
    /// `metrics` is [`FontMetrics::None`] (`w0 = 0`), so spacing-only
    /// adjustments still move the origin.
    fn advance_text(&mut self, bytes: &[u8], metrics: &FontMetrics) {
        let tfs = self.current_font.as_ref().map(|(_, s)| *s).unwrap_or(0.0);
        let th = self.horiz_scale;
        let tc = self.char_spacing;
        // Convert a stored width to text-space units: 1/1000 for
        // Type1 / TrueType / composite, the Type 3 /FontMatrix scale for
        // a Type 3 font (§9.2.4 / §9.6.5).
        let scale = metrics.text_scale();
        if metrics.two_byte() {
            // Composite Identity font: each code is two bytes, CID =
            // code; Tw never applies to multi-byte codes (§9.3.3).
            let mut i = 0;
            while i + 1 < bytes.len() {
                let cid = ((bytes[i] as i64) << 8) | bytes[i + 1] as i64;
                let w0 = metrics.width(cid) * scale;
                let tx = (w0 * tfs + tc) * th;
                self.translate_text(tx);
                i += 2;
            }
        } else {
            for &b in bytes {
                let w0 = metrics.width(b as i64) * scale;
                let tw = if b == 32 { self.word_spacing } else { 0.0 };
                let tx = (w0 * tfs + tc + tw) * th;
                self.translate_text(tx);
            }
        }
    }

    /// Paint a Type 3 font's glyphs for one shown byte string into the
    /// scene tree (§9.6.5). For each byte the walker resolves the glyph
    /// name via the font's `/Encoding`, looks the description `Group` up
    /// in `/CharProcs`, and splices it under the glyph's text-rendering
    /// matrix (§9.4.4):
    ///
    /// ```text
    /// T_rm = [ Tfs·Th  0      0 ]   [ a b 0 ]
    ///        [ 0       Tfs    0 ] × [ c d 0 ] × Tm    (then CTM on pop)
    ///        [ 0       Trise  1 ]   [ e f 1 ]
    /// ```
    ///
    /// where `[a b c d e f]` is the font's `/FontMatrix`. The frame's
    /// accumulated `cm` CTM is applied when the frame is popped, so the
    /// spliced group's transform is `Tm ∘ textState ∘ FontMatrix`. The
    /// text matrix is advanced separately by [`Self::advance_text`].
    ///
    /// Mode `3` (invisible, §9.3.6) paints nothing. A glyph name absent
    /// from `/Encoding` or `/CharProcs` paints nothing (§9.6.5 step b).
    /// Re-entrancy (a glyph that itself shows Type 3 text) is depth-
    /// bounded by `type3_depth`.
    fn paint_type3_show(&mut self, bytes: &[u8]) {
        // Invisible text-render mode shows no marks (§9.3.6 mode 3).
        if self.text_render_mode == 3 {
            return;
        }
        if self.type3_depth >= MAX_TYPE3_DEPTH {
            return;
        }
        let font_name = match &self.current_font {
            Some((n, _)) if !n.is_empty() => n.clone(),
            _ => return,
        };
        let font = match self.type3_fonts.and_then(|m| m.get(&font_name)) {
            Some(f) => f,
            None => return,
        };
        let tfs = self.current_font.as_ref().map(|(_, s)| *s).unwrap_or(0.0);
        let th = self.horiz_scale;
        let tc = self.char_spacing;
        let word_spacing = self.word_spacing;
        let rise = self.text_rise;
        // Per-show graphics-state scale (the text-rendering-matrix's
        // leftmost factor, §9.4.4). FontMatrix sits inside this; the
        // per-glyph text matrix outside; CTM (frame.transform) is applied
        // on frame pop.
        let text_state = Transform2D {
            a: tfs * th,
            b: 0.0,
            c: 0.0,
            d: tfs,
            e: 0.0,
            f: rise,
        };
        // Width metrics so the glyph origin advances *between* the bytes
        // of a single show (the caller's `advance_text` only moves
        // `self.text_matrix` once, after the whole string). We walk a
        // local running matrix so painting and the caller's advance stay
        // independent.
        let metrics = self.current_font_metrics();
        let scale = metrics.text_scale();
        // The current fill colour the graphics state supplies — a
        // shape-only (`d1`) glyph (§9.6.5 Table 113) is painted with this
        // colour rather than any colour baked into its description
        // (NOTE 2: the text-showing operators paint glyphs in the current
        // colour). Self-coloured (`d0`) glyphs keep their own colours.
        let fill_color = match &self.fill_paint {
            Some(Paint::Solid(c)) => *c,
            _ => Rgba::opaque(0, 0, 0),
        };
        let mut tm = self.text_matrix;
        // Build the spliceable glyph nodes while only `font` (an
        // immutable borrow of `self.type3_fonts`) is held, then splice
        // them in one pass — `self.current()` needs `&mut self`, which
        // can't overlap the `font` borrow. Only matched glyph groups are
        // cloned (not the whole font).
        let mut nodes: Vec<Node> = Vec::new();
        for &b in bytes {
            if let Some((glyph_name, glyph)) = font
                .encoding
                .get(&b)
                .and_then(|n| font.glyphs.get(n).map(|g| (n, g)))
            {
                if !glyph.children.is_empty() {
                    // group transform = Tm ∘ text_state ∘ FontMatrix
                    let outer = compose(tm, text_state);
                    let g_xform = compose(outer, font.font_matrix);
                    let mut children = glyph.children.clone();
                    // §9.6.5 — a `d1` shape-only glyph takes the current
                    // fill colour, not its own; recolour its paints.
                    if font.shape_only.contains(glyph_name) {
                        for child in &mut children {
                            recolor_node(child, fill_color);
                        }
                    }
                    nodes.push(Node::Group(Group {
                        transform: g_xform,
                        children,
                        ..Group::default()
                    }));
                }
            }
            // Advance the local running matrix by this glyph's
            // displacement (§9.4.4) so the next glyph in the string paints
            // at the right origin. `Tw` applies only to the single-byte
            // space (code 32, §9.3.3).
            let w0 = metrics.width(b as i64) * scale;
            let tw = if b == 32 { word_spacing } else { 0.0 };
            let tx = (w0 * tfs + tc + tw) * th;
            tm = compose(
                tm,
                Transform2D {
                    a: 1.0,
                    b: 0.0,
                    c: 0.0,
                    d: 1.0,
                    e: tx,
                    f: 0.0,
                },
            );
        }
        if nodes.is_empty() {
            return;
        }
        // The depth guard brackets the splice: a glyph description that
        // itself painted Type 3 text did so while building `glyph` (at
        // resolve time), so the runtime guard simply caps how deep a
        // single show's nodes nest before they're attached here.
        self.type3_depth += 1;
        // Each glyph is an elementary object for compositing purposes
        // (§11.6.4.2) — the active soft mask wraps every one.
        if self.active_smask.is_some() {
            let ctm = self.effective_ctm();
            for node in nodes {
                let wrapped = self.wrap_soft_mask(node, ctm);
                self.current().children.push(wrapped);
            }
        } else {
            self.current().children.extend(nodes);
        }
        self.type3_depth -= 1;
    }

    /// Translate the text matrix by `(tx, 0)` in text space — the
    /// horizontal-writing displacement of §9.4.4
    /// (`Tm_new = [1 0 0 1 tx 0] × Tm`).
    fn translate_text(&mut self, tx: f32) {
        let m = Transform2D {
            a: 1.0,
            b: 0.0,
            c: 0.0,
            d: 1.0,
            e: tx,
            f: 0.0,
        };
        self.text_matrix = compose(self.text_matrix, m);
    }

    /// Apply the entries of a `/Type /ExtGState` parameter dictionary
    /// to the current state (Table 58). Only the keys whose effect
    /// fits the round-3 vector IR are honoured; the rest are silently
    /// ignored — the spec explicitly allows partial dicts ("any
    /// combination of parameter entries"). Values are cumulative —
    /// previous settings persist until explicitly overridden, matching
    /// the §8.4.5 "results of gs shall be cumulative" rule.
    fn apply_ext_gstate(&mut self, dict: &Dict) {
        for (k, v) in dict.entries() {
            match k.as_str() {
                "LW" => {
                    if let Some(n) = number_as_f32(v) {
                        self.stroke_width = n;
                    }
                }
                "LC" => {
                    if let Some(i) = number_as_i64(v) {
                        self.line_cap = match i {
                            0 => LineCap::Butt,
                            1 => LineCap::Round,
                            2 => LineCap::Square,
                            _ => self.line_cap,
                        };
                    }
                }
                "LJ" => {
                    if let Some(i) = number_as_i64(v) {
                        self.line_join = match i {
                            0 => LineJoin::Miter,
                            1 => LineJoin::Round,
                            2 => LineJoin::Bevel,
                            _ => self.line_join,
                        };
                    }
                }
                "ML" => {
                    if let Some(n) = number_as_f32(v) {
                        self.miter_limit = n;
                    }
                }
                "D" => {
                    // `[dashArray dashPhase]` two-element array — Table
                    // 58. Matches the `d` operator's pair shape.
                    if let Some((array, offset)) = parse_dash_pair(v) {
                        self.dash = if array.is_empty() {
                            None
                        } else {
                            Some(DashPattern { array, offset })
                        };
                    }
                }
                "CA" => {
                    if let Some(n) = number_as_f32(v) {
                        self.stroke_alpha = n.clamp(0.0, 1.0);
                    }
                }
                "ca" => {
                    if let Some(n) = number_as_f32(v) {
                        self.fill_alpha = n.clamp(0.0, 1.0);
                    }
                }
                // `SMask` is handled by `apply_soft_mask_entry` (the
                // dispatcher passes the ExtGState resource *name*,
                // which the pre-resolved soft-mask map is keyed by).
                //
                // Tolerated-but-unhandled keys (Table 58):
                //   Type, RI, OP, op, OPM, Font, BG, BG2, UCR, UCR2,
                //   TR, TR2, HT, FL, SM, SA, BM, AIS, TK.
                _ => {}
            }
        }
    }

    /// Handle the `/SMask` entry of a `gs` parameter dictionary
    /// (§11.6.4.3): the name `None` denotes the absence of a soft mask
    /// ("the mask shape or opacity shall be implicitly 1.0
    /// everywhere"); a soft-mask dictionary establishes the current
    /// soft mask, resolved through the pre-parsed map keyed by the
    /// ExtGState resource name. A dictionary that didn't resolve (bad
    /// `/G`, unknown `/S`) also clears the mask — painting unmasked is
    /// the same tolerant degradation every other unresolvable resource
    /// takes, and safer than leaving a stale mask in force.
    fn apply_soft_mask_entry(&mut self, gs_name: &str, dict: &Dict) {
        let Some(value) = dict
            .entries()
            .iter()
            .find(|(k, _)| k == "SMask")
            .map(|(_, v)| v)
        else {
            return;
        };
        if matches!(value, Object::Name(n) if n == "None") {
            self.active_smask = None;
            return;
        }
        match self.soft_masks.and_then(|m| m.get(gs_name)) {
            Some(resolved) => {
                self.active_smask = Some(ActiveSoftMask {
                    mask: Rc::new(Node::Group(resolved.mask.clone())),
                    kind: resolved.kind,
                    ctm: self.effective_ctm(),
                });
            }
            None => {
                self.active_smask = None;
            }
        }
    }

    fn path_mut(&mut self) -> &mut Path {
        if self.current_path.is_none() {
            self.current_path = Some(Path::new());
        }
        self.current_path.as_mut().unwrap()
    }

    fn take_numbers(&mut self, n: usize) -> Result<Vec<f32>, PdfError> {
        if self.operands.len() < n {
            return Err(PdfError::other(format!(
                "PDF content parser: operator needed {n} numeric operands, got {}",
                self.operands.len()
            )));
        }
        let split = self.operands.len() - n;
        let tail: Vec<Operand> = self.operands.drain(split..).collect();
        let mut out = Vec::with_capacity(n);
        for op in tail {
            match op {
                Operand::Number(f) => out.push(f),
                other => {
                    return Err(PdfError::other(format!(
                        "PDF content parser: expected numeric operand, got {other:?}"
                    )));
                }
            }
        }
        Ok(out)
    }

    fn take_point(&mut self) -> Result<Point, PdfError> {
        let nums = self.take_numbers(2)?;
        Ok(Point::new(nums[0], nums[1]))
    }

    /// Resolve an `sc`/`scn` (or `SC`/`SCN`) operand list into a
    /// [`Paint`] for the given colour space. Returns `None` when the
    /// space is `Unknown`, when a trailing `/Name` pattern operand is
    /// present (Pattern colour space, §8.7.3.3 — `c1 … cn /name scn`),
    /// or when the numeric-operand count doesn't match the device
    /// family's component count. In those cases the caller falls back
    /// to the conservative black behaviour.
    fn color_from_components(&self, cs: &ColorSpaceKind) -> Option<Paint> {
        let want = cs.components()?;
        // A trailing `/Name` operand marks a Pattern fill — no device
        // colour to read.
        if matches!(self.operands.last(), Some(Operand::Name(_))) {
            return None;
        }
        // Count the trailing numeric operands.
        let nums: Vec<f32> = self
            .operands
            .iter()
            .rev()
            .take_while(|o| matches!(o, Operand::Number(_)))
            .filter_map(|o| match o {
                Operand::Number(n) => Some(*n),
                _ => None,
            })
            .collect();
        if nums.len() < want {
            return None;
        }
        // `nums` was collected reversed; take the last `want` of them
        // in stream order.
        let comps: Vec<f32> = nums.iter().take(want).rev().copied().collect();
        Some(match cs {
            ColorSpaceKind::DeviceGray => Paint::Solid(rgb_from_unit(comps[0], comps[0], comps[0])),
            ColorSpaceKind::DeviceRgb => Paint::Solid(rgb_from_unit(comps[0], comps[1], comps[2])),
            ColorSpaceKind::DeviceCmyk => {
                Paint::Solid(rgb_from_cmyk(comps[0], comps[1], comps[2], comps[3]))
            }
            ColorSpaceKind::Indexed { base, hival, table } => {
                return indexed_color(base, *hival, table, comps[0])
            }
            ColorSpaceKind::Separation {
                alt,
                tint,
                none_colorant,
            } => return separation_color(alt, tint, *none_colorant, comps[0]),
            ColorSpaceKind::DeviceN {
                alt,
                tint,
                all_none,
                ..
            } => return device_n_color(alt, tint, *all_none, &comps),
            ColorSpaceKind::CalGray { .. }
            | ColorSpaceKind::CalRgb { .. }
            | ColorSpaceKind::Lab { .. } => return cie_color(cs, &comps),
            ColorSpaceKind::Unknown => unreachable!("components() returned Some"),
        })
    }

    /// Pop the trailing `/Name` operand of a `cs` / `CS` operator and
    /// map it to a tracked colour space, consulting the page's
    /// `/Resources /ColorSpace` subdictionary (round 275) for
    /// non-device names. A `cs` with no name operand (malformed) leaves
    /// the space `Unknown`.
    fn take_color_space_name(&mut self) -> ColorSpaceKind {
        match self.operands.last() {
            Some(Operand::Name(n)) => {
                ColorSpaceKind::resolve_with_resources(n, self.color_space_resources)
            }
            _ => ColorSpaceKind::Unknown,
        }
    }

    /// Resolve a `scn`/`SCN` trailing `/Name` operand as a shading
    /// pattern (§8.7.3.3 + §8.7.4.5) and, when it is a `/PatternType 2`
    /// pattern carrying an axial / radial `/Shading`, return the
    /// equivalent scene gradient [`Paint`]. The shading's `Coords` are
    /// mapped from pattern space into device space through the pattern's
    /// `/Matrix` composed with the current CTM (§8.7.3.1: a pattern's
    /// matrix maps pattern space to the default coordinate space of the
    /// page, then the CTM in effect applies). Returns `None` when no
    /// pattern resources are plumbed in, the name isn't a renderable
    /// shading pattern, or the shading is function-based / mesh (no
    /// linear/radial scene analogue).
    fn pattern_paint_from_operand(&self) -> Option<Paint> {
        let name = match self.operands.last() {
            Some(Operand::Name(n)) => n.as_str(),
            _ => return None,
        };
        let pat = lookup_dict(self.pattern_resources?, name)?;
        let get = |k: &str| pat.entries().iter().find(|(kk, _)| kk == k).map(|(_, v)| v);
        // Only shading patterns (PatternType 2) map to a scene gradient.
        if get("PatternType").and_then(number_as_i64) != Some(2) {
            return None;
        }
        let Some(Object::Dict(shading)) = get("Shading") else {
            return None;
        };
        let gradient = evaluate_gradient_shading(shading, self.color_space_resources)?;
        let pattern_matrix = match get("Matrix").and_then(read_num_array) {
            Some(m) if m.len() == 6 => Transform2D {
                a: m[0],
                b: m[1],
                c: m[2],
                d: m[3],
                e: m[4],
                f: m[5],
            },
            // A malformed Matrix is rejected; an absent one defaults to
            // identity (§8.7.3.1).
            Some(_) => return None,
            None => Transform2D::identity(),
        };
        let to_target = compose(self.effective_ctm(), pattern_matrix);
        gradient_to_paint(&gradient, to_target)
    }

    /// If the trailing `scn`/`SCN` operand names a pre-parsed
    /// `/PatternType 1` tiling pattern (§8.7.3), return its name so
    /// `commit_path` can replicate the cell across the painted region.
    /// Returns `None` when no tiling patterns are plumbed in or the
    /// operand isn't a tiling-pattern name (e.g. a numeric colour, a
    /// shading-pattern name, or an unknown name).
    fn tiling_pattern_name_from_operand(&self) -> Option<String> {
        let name = match self.operands.last() {
            Some(Operand::Name(n)) => n.as_str(),
            _ => return None,
        };
        if self.tiling_patterns?.contains_key(name) {
            Some(name.to_string())
        } else {
            None
        }
    }

    /// For an *uncoloured* (`/PaintType 2`) tiling pattern named `name`,
    /// read the underlying colour the cell stencil is poured with from
    /// the numeric operands a `scn`/`SCN` supplies before the pattern
    /// name (§8.7.3.3). The underlying space is the second element of the
    /// `[/Pattern base]` colour space; this round reads it by component
    /// count (1 → DeviceGray, 3 → DeviceRGB, 4 → DeviceCMYK), which
    /// covers the device underlying spaces. Returns `None` for a coloured
    /// (`/PaintType 1`) pattern, when no numeric operands precede the
    /// name, or when the count isn't a device arity.
    fn uncoloured_tiling_color(&self, name: &str) -> Option<Rgba> {
        let pat = self.tiling_patterns?.get(name)?;
        if pat.paint_type != 2 {
            return None;
        }
        // The operands are `[c0 .. cn] /Pname`; collect the numeric
        // components that precede the trailing name.
        let comps: Vec<f32> = self
            .operands
            .iter()
            .filter_map(|o| match o {
                Operand::Number(n) => Some(*n),
                _ => None,
            })
            .collect();
        let paint = match comps.len() {
            1 => Paint::Solid(rgb_from_unit(comps[0], comps[0], comps[0])),
            3 => Paint::Solid(rgb_from_unit(comps[0], comps[1], comps[2])),
            4 => Paint::Solid(rgb_from_cmyk(comps[0], comps[1], comps[2], comps[3])),
            _ => return None,
        };
        match paint {
            Paint::Solid(c) => Some(c),
            _ => None,
        }
    }

    fn parse(&mut self, input: &[u8]) -> Result<(), PdfError> {
        let mut i = 0;
        while i < input.len() {
            let b = input[i];
            if is_whitespace(b) {
                i += 1;
                continue;
            }
            if b == b'%' {
                // Comment to end of line.
                while i < input.len() && input[i] != b'\n' && input[i] != b'\r' {
                    i += 1;
                }
                continue;
            }
            if b == b'(' {
                // Literal-string operand — keep the escape-decoded
                // bytes (`Tj` / `'` / `"` consume them).
                let (end, bytes) = read_literal_string(input, i)?;
                self.operands.push(Operand::String(bytes));
                i = end;
                continue;
            }
            if b == b'<' && input.get(i + 1) == Some(&b'<') {
                // Inline dictionary `<< … >>` operand — the §14.6.2
                // property list a `DP`/`BDC` may carry directly. Reuse
                // the object parser over the tail so nested arrays /
                // dicts / strings inside the property list are handled
                // by the same battle-tested code the body parser uses;
                // `position()` tells us how many bytes it consumed.
                let mut p = crate::reader::parse::Parser::new(&input[i..]);
                match p.parse_object() {
                    Ok(Some(Object::Dict(d))) => {
                        self.operands.push(Operand::Dict(d));
                        i += p.position();
                        continue;
                    }
                    // A malformed or non-dict `<<` — skip the opening
                    // delimiter and resync rather than abort the whole
                    // stream (mirrors the round-3 salvage stance).
                    _ => {
                        i += 2;
                        continue;
                    }
                }
            }
            if b == b'<' && input.get(i + 1) != Some(&b'<') {
                // Hex-string operand — decode pairs into bytes.
                let (end, bytes) = read_hex_string(input, i)?;
                self.operands.push(Operand::String(bytes));
                i = end;
                continue;
            }
            if b == b'[' {
                // Array operand — for the dash array `[5 3] 0 d`
                // (numbers only), the `TJ` operator `[(s1) num1 …]`
                // (strings + numbers), and any other inline array.
                let (end, items) = read_array(input, i)?;
                self.operands.push(Operand::Array(items));
                i = end;
                continue;
            }
            if b == b'/' {
                // Name operand.
                let mut end = i + 1;
                while end < input.len() && !is_whitespace(input[end]) && !is_delimiter(input[end]) {
                    end += 1;
                }
                // We don't bother decoding #xx in content-stream
                // names — round-3 callers never produce such names.
                let name = String::from_utf8_lossy(&input[i + 1..end]).into_owned();
                self.operands.push(Operand::Name(name));
                i = end;
                continue;
            }
            if matches!(b, b'+' | b'-' | b'.' | b'0'..=b'9') {
                // Number operand — exact-arithmetic fast conversion
                // with a `str::parse` fallback for out-of-range
                // significands (see `scan_number`).
                match scan_number(input, i) {
                    NumScan::Fast(end, f) => {
                        self.operands.push(Operand::Number(f));
                        i = end;
                        continue;
                    }
                    NumScan::Slow(end) => {
                        let s = str::from_utf8(&input[i..end]).map_err(|_| {
                            PdfError::other(format!(
                                "PDF content parser: non-UTF-8 number at byte {i}"
                            ))
                        })?;
                        let f: f32 = s.parse().map_err(|_| {
                            PdfError::other(format!(
                                "PDF content parser: invalid number `{s}` at byte {i}"
                            ))
                        })?;
                        self.operands.push(Operand::Number(f));
                        i = end;
                        continue;
                    }
                    NumScan::NotANumber => {
                        // Bare sign / dot — fall through to keyword
                        // handling.
                        let kw_end = scan_keyword_end(input, i);
                        let kw = &input[i..kw_end];
                        self.dispatch(kw)?;
                        i = kw_end;
                        continue;
                    }
                }
            }
            // Anything else is a keyword (operator).
            let kw_end = scan_keyword_end(input, i);
            if kw_end == i {
                // Unrecognised single byte — skip to avoid infinite
                // loop.
                i += 1;
                continue;
            }
            let kw = &input[i..kw_end];
            // `BI` opens an inline image (§8.9.7). Its raw payload
            // between `ID` and `EI` can contain *any* bytes — including
            // sequences that look like operators / numbers — so it must
            // be consumed by the inline-image framer rather than tokenized
            // by this loop. We hand the framer the bytes from just past
            // `BI` and resume past the framer's reported `EI`.
            if kw == b"BI" {
                i = self.consume_inline_image(input, kw_end);
                continue;
            }
            self.dispatch(kw)?;
            i = kw_end;
        }
        Ok(())
    }

    /// Consume a `BI … ID … EI` inline image (§8.9.7) starting just past
    /// the `BI` keyword (`after_bi`). Records a [`ContentInlineImage`]
    /// event with the CTM + clip in force, and returns the byte offset
    /// to resume parsing at (just past `EI`).
    ///
    /// The pre-`BI` operands are cleared (an inline image takes no
    /// operands; any stragglers are tolerated and dropped). On a
    /// malformed dictionary the framer returns an error — we salvage by
    /// scanning forward to the next `EI` so the rest of the content
    /// stream still parses, rather than aborting the whole document.
    fn consume_inline_image(&mut self, input: &[u8], after_bi: usize) -> usize {
        self.operands.clear();
        match parse_one_inline_image(input, after_bi) {
            Ok((image, resume)) => {
                let ctm = self.effective_ctm();
                let clip = self.current_clip();
                self.inline_images
                    .push(ContentInlineImage { image, ctm, clip });
                resume
            }
            // Salvage: skip to the next `EI` (past it) so the trailing
            // content stream survives a malformed inline-image dict.
            Err(_) => match find_inline_image_ei(input, after_bi) {
                Some(ei) => ei + 2,
                // No `EI` at all — consume the rest of the stream.
                None => input.len(),
            },
        }
    }
}

impl Frame {
    fn new() -> Self {
        Self {
            transform: Transform2D::identity(),
            children: Vec::new(),
            clip: None,
            saved: None,
        }
    }

    fn is_effectively_empty(&self) -> bool {
        self.children.is_empty() && self.clip.is_none() && self.transform.is_identity()
    }
}

// ───────────────────────── helpers ─────────────────────────

fn is_whitespace(b: u8) -> bool {
    matches!(b, 0x00 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

fn is_delimiter(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn rgb_from_unit(r: f32, g: f32, b: f32) -> Rgba {
    Rgba::opaque(unit_to_byte(r), unit_to_byte(g), unit_to_byte(b))
}

/// The current colour established by a bare `cs` / `CS` before any
/// `sc`/`scn`. Per §8.6.4.2..4 setting a device colour space
/// initialises the colour to its 0.0 value (black for Gray/RGB,
/// `0 0 0 1`-equivalent — also black — for CMYK). For an unresolved
/// space we leave the paint cleared so the existing black fallback in
/// `commit_path` applies if nothing further is set.
fn initial_color_for(cs: &ColorSpaceKind) -> Option<Paint> {
    match cs {
        ColorSpaceKind::DeviceGray | ColorSpaceKind::DeviceRgb | ColorSpaceKind::DeviceCmyk => {
            Some(Paint::Solid(Rgba::opaque(0, 0, 0)))
        }
        // §8.6.6.3: "Setting the current … colour space to an Indexed
        // colour space shall initialize the corresponding current
        // colour to 0" — i.e. table entry 0.
        ColorSpaceKind::Indexed { base, hival, table } => indexed_color(base, *hival, table, 0.0),
        // §8.6.6.4: "The initial value for both the stroking and
        // nonstroking colour in the graphics state shall be 1.0" — i.e.
        // the maximum tint, evaluated through the tint transform.
        ColorSpaceKind::Separation {
            alt,
            tint,
            none_colorant,
        } => separation_color(alt, tint, *none_colorant, 1.0),
        // §8.6.6.5: "each component shall be given an initial value of
        // 1.0" — the maximum tint on every colorant, run through the
        // tint transform.
        ColorSpaceKind::DeviceN {
            n_in,
            alt,
            tint,
            all_none,
        } => device_n_color(alt, tint, *all_none, &vec![1.0; *n_in]),
        // §8.6.5: "Setting the current stroking or nonstroking colour
        // space to any CIE-based colour space shall initialize all
        // components of the corresponding current colour to 0.0." For
        // Lab the a*/b* zero is clamped into Range by `cie_color`.
        ColorSpaceKind::CalGray { .. } => cie_color(cs, &[0.0]),
        ColorSpaceKind::CalRgb { .. } | ColorSpaceKind::Lab { .. } => {
            cie_color(cs, &[0.0, 0.0, 0.0])
        }
        ColorSpaceKind::Unknown => None,
    }
}

/// Resolve a single `sc`/`scn` index against an `/Indexed` colour
/// table per ISO 32000-1 §8.6.6.3. The `index` operand is rounded to
/// the nearest integer and clamped into `0..=hival` ("If the value is
/// a real number, it shall be rounded to the nearest integer; if it is
/// outside the range 0 to hival, it shall be adjusted to the nearest
/// value within that range"). Each of the base space's `m` components
/// is one table byte scaled `0..255 → 0.0..1.0`, then mapped to RGB
/// through the base device family. Returns `None` when the table is
/// too short to hold the selected entry (a malformed/truncated lookup)
/// so the conservative black fallback applies.
fn indexed_color(base: &ColorSpaceKind, hival: u32, table: &[u8], index: f32) -> Option<Paint> {
    let m = base.components()?;
    // Round to nearest, clamp into [0, hival].
    let idx = if index.is_finite() {
        let r = index.round();
        r.clamp(0.0, hival as f32) as u32
    } else {
        0
    };
    let start = (idx as usize).checked_mul(m)?;
    let entry = table.get(start..start + m)?;
    let unit = |i: usize| entry[i] as f32 / 255.0;
    Some(match base {
        ColorSpaceKind::DeviceGray => Paint::Solid(rgb_from_unit(unit(0), unit(0), unit(0))),
        ColorSpaceKind::DeviceRgb => Paint::Solid(rgb_from_unit(unit(0), unit(1), unit(2))),
        ColorSpaceKind::DeviceCmyk => {
            Paint::Solid(rgb_from_cmyk(unit(0), unit(1), unit(2), unit(3)))
        }
        // §8.6.6.3: a CIE-based base is permitted. Each table byte is
        // decoded `0..255 → 0.0..1.0` then mapped into the base
        // component's own range before the CIE → RGB transform. CalGray
        // / CalRGB components already lie in 0.0..1.0; for Lab the L*
        // component spans 0..100 and a*/b* span the space's `range`.
        ColorSpaceKind::CalGray { .. } | ColorSpaceKind::CalRgb { .. } => {
            cie_color(base, &(0..m).map(unit).collect::<Vec<_>>())?
        }
        ColorSpaceKind::Lab { range, .. } => {
            let l = unit(0) * 100.0;
            let a = range[0] + unit(1) * (range[1] - range[0]);
            let b = range[2] + unit(2) * (range[3] - range[2]);
            cie_color(base, &[l, a, b])?
        }
        // An `Indexed`, `Separation`, or `DeviceN` base is forbidden by
        // §8.6.6.3 (and rejected by `indexed_from_array`), so these are
        // unreachable in practice; fall back to black for total safety.
        ColorSpaceKind::Indexed { .. }
        | ColorSpaceKind::Separation { .. }
        | ColorSpaceKind::DeviceN { .. }
        | ColorSpaceKind::Unknown => Paint::Solid(Rgba::opaque(0, 0, 0)),
    })
}

/// Resolve a single `sc`/`scn` tint operand against a `/Separation`
/// colour space per ISO 32000-1 §8.6.6.4. The tint is clamped into the
/// `0.0..=1.0` colour range, run through the tint-transform function to
/// produce the alternate space's component values, then those
/// components are rendered to RGB through the alternate device family.
///
/// A `/None` colorant produces no visible output (`None` paint, so the
/// caller leaves the path unpainted). A component-count mismatch between
/// the tint transform's output and the alternate family — a malformed
/// space — yields `None` (conservative black fallback).
fn separation_color(
    alt: &ColorSpaceKind,
    tint: &PdfFunction,
    none_colorant: bool,
    tint_value: f32,
) -> Option<Paint> {
    if none_colorant {
        return None;
    }
    let t = tint_value.clamp(0.0, 1.0);
    let comps = tint.eval(t);
    paint_from_alt_components(alt, &comps)
}

/// Render a tint-transform output vector through a Separation / DeviceN
/// *alternate* colour space (§8.6.6.4–5). The alternate may be a device
/// family or a CIE-based family (CalGray / CalRGB / Lab) — both are
/// rendered to RGB; the Lab alternate interprets its three components as
/// an L*a*b* triple (the tint transform is responsible for emitting them
/// in the alternate's own range). Returns `None` for an arity mismatch
/// or a non-renderable alternate, preserving the conservative black
/// fallback.
fn paint_from_alt_components(alt: &ColorSpaceKind, comps: &[f32]) -> Option<Paint> {
    match alt {
        ColorSpaceKind::DeviceGray | ColorSpaceKind::DeviceRgb | ColorSpaceKind::DeviceCmyk => {
            paint_from_device_components(alt, comps)
        }
        ColorSpaceKind::CalGray { .. }
        | ColorSpaceKind::CalRgb { .. }
        | ColorSpaceKind::Lab { .. } => cie_color(alt, comps),
        _ => None,
    }
}

/// Resolve an `sc`/`scn` tint-component vector against a `/DeviceN`
/// colour space per ISO 32000-1 §8.6.6.5. Each of the `n_in` tints is
/// clamped into `0.0..=1.0`, the whole vector is run through the n-in /
/// m-out tint-transform function to produce the alternate space's `m`
/// component values, and those are rendered to RGB through the alternate
/// device family.
///
/// An all-`/None` space (`all_none`) discards its output (no paint, like
/// a Separation `/None` colorant). A component-count mismatch between the
/// tint transform's output and the alternate family yields `None`
/// (conservative black fallback) — though `device_n_from_array` already
/// validates the arity at resolve time, so this is defence in depth.
fn device_n_color(
    alt: &ColorSpaceKind,
    tint: &PdfFunction,
    all_none: bool,
    tints: &[f32],
) -> Option<Paint> {
    if all_none {
        return None;
    }
    let clamped: Vec<f32> = tints.iter().map(|t| t.clamp(0.0, 1.0)).collect();
    let comps = tint.eval_n(&clamped);
    paint_from_alt_components(alt, &comps)
}

/// Resolve an `sc`/`scn` component vector against a CIE-based colour
/// space (CalGray §8.6.5.2, CalRGB §8.6.5.3, Lab §8.6.5.4) to a
/// [`Paint`]. `comps` carries one component for CalGray, three for
/// CalRGB / Lab. Lab's a*/b* operands are clamped into the space's
/// `range` "without error indication" (§8.6.5.4 Range). Returns `None`
/// for a component-count mismatch or a non-CIE space.
fn cie_color(cs: &ColorSpaceKind, comps: &[f32]) -> Option<Paint> {
    match cs {
        ColorSpaceKind::CalGray { white, gamma } if comps.len() == 1 => {
            Some(Paint::Solid(cal_gray_color(*white, *gamma, comps[0])))
        }
        ColorSpaceKind::CalRgb { gamma, matrix } if comps.len() == 3 => Some(Paint::Solid(
            cal_rgb_color(*gamma, *matrix, [comps[0], comps[1], comps[2]]),
        )),
        ColorSpaceKind::Lab { white, range } if comps.len() == 3 => {
            let a = comps[1].clamp(range[0], range[1]);
            let b = comps[2].clamp(range[2], range[3]);
            Some(Paint::Solid(lab_color(*white, [comps[0], a, b])))
        }
        _ => None,
    }
}

/// Render a device colour space's component values to a [`Paint`].
/// Returns `None` when the count doesn't match the family's arity (a
/// non-device family is also rejected — only the three device families
/// have a direct component → RGB mapping).
fn paint_from_device_components(cs: &ColorSpaceKind, comps: &[f32]) -> Option<Paint> {
    match cs {
        ColorSpaceKind::DeviceGray if comps.len() == 1 => {
            Some(Paint::Solid(rgb_from_unit(comps[0], comps[0], comps[0])))
        }
        ColorSpaceKind::DeviceRgb if comps.len() == 3 => {
            Some(Paint::Solid(rgb_from_unit(comps[0], comps[1], comps[2])))
        }
        ColorSpaceKind::DeviceCmyk if comps.len() == 4 => Some(Paint::Solid(rgb_from_cmyk(
            comps[0], comps[1], comps[2], comps[3],
        ))),
        _ => None,
    }
}

// ───────────────── mesh shadings (§8.7.4.5.5–8) ──────────────────

/// Convert a `count`-component colour value in colour space `cs` to a
/// device-RGB [`Rgba`]. Reuses the same colour-space machinery the
/// `sc`/`scn` path uses (device families, `Indexed` table lookup,
/// `Separation` / `DeviceN` tint transforms), so a mesh vertex / patch
/// corner colour is reduced exactly as a fill colour would be. Returns
/// `None` for an `Unknown` space or a component-count mismatch.
fn rgba_from_components(cs: &ColorSpaceKind, comps: &[f32]) -> Option<Rgba> {
    let paint = match cs {
        ColorSpaceKind::DeviceGray | ColorSpaceKind::DeviceRgb | ColorSpaceKind::DeviceCmyk => {
            paint_from_device_components(cs, comps)?
        }
        ColorSpaceKind::Indexed { base, hival, table } => {
            indexed_color(base, *hival, table, *comps.first()?)?
        }
        ColorSpaceKind::Separation {
            alt,
            tint,
            none_colorant,
        } => separation_color(alt, tint, *none_colorant, *comps.first()?)?,
        ColorSpaceKind::DeviceN {
            alt,
            tint,
            all_none,
            ..
        } => device_n_color(alt, tint, *all_none, comps)?,
        ColorSpaceKind::CalGray { .. }
        | ColorSpaceKind::CalRgb { .. }
        | ColorSpaceKind::Lab { .. } => cie_color(cs, comps)?,
        ColorSpaceKind::Unknown => return None,
    };
    match paint {
        Paint::Solid(rgba) => Some(rgba),
        _ => None,
    }
}

/// A little-endian-free MSB-first bit reader over a mesh stream body.
/// `read(bits)` pulls the next `bits` bits, most-significant first
/// (§8.7.4.5.5: "reading in sequence from higher-order to lower-order
/// bit positions"); `align_byte` discards the remaining bits of the
/// current byte (each vertex / patch element occupies a whole number of
/// bytes — the trailing pad bits "shall be ignored").
struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    /// Read `bits` (1..=32) bits MSB-first as an unsigned integer.
    /// Returns `None` when the stream is exhausted.
    fn read(&mut self, bits: u32) -> Option<u64> {
        let mut code: u64 = 0;
        for _ in 0..bits {
            let byte = *self.data.get(self.bit_pos / 8)?;
            let bit = (byte >> (7 - (self.bit_pos % 8) as u32)) & 1;
            code = (code << 1) | (bit as u64);
            self.bit_pos += 1;
        }
        Some(code)
    }

    /// Advance to the next byte boundary (each mesh element — vertex or
    /// patch — is byte-aligned, §8.7.4.5.5).
    fn align_byte(&mut self) {
        if self.bit_pos % 8 != 0 {
            self.bit_pos = self.bit_pos.div_ceil(8) * 8;
        }
    }

    /// `true` once the reader has consumed at least one whole byte and
    /// no further byte-aligned element can be read (used to terminate a
    /// patch / triangle stream that provides a whole number of elements).
    fn at_end(&self) -> bool {
        self.bit_pos / 8 >= self.data.len()
    }
}

/// Decode an integer coordinate / colour code in `[0, 2^bits − 1]` to
/// its target value via the §8.9.5.2 `Decode` linear map (the same
/// `Interpolate` the image Decode array uses).
fn decode_value(code: u64, bits: u32, dmin: f32, dmax: f32) -> f32 {
    let max_code = if bits >= 32 {
        u32::MAX as f32
    } else {
        ((1u64 << bits) - 1) as f32
    };
    if max_code == 0.0 {
        return dmin;
    }
    dmin + (code as f32) * (dmax - dmin) / max_code
}

/// Parse + evaluate a Type 4–7 (mesh) shading dictionary (§8.7.4.5.5–8)
/// into its device-space [`MeshShading`] geometry. Returns `None` for a
/// Type 1–3 shading, a missing / malformed stream body (the
/// `resolve_shading_resources` `__MeshData` fold), an unresolved colour
/// space, or any structural error in the bit-packed stream. The colour
/// at each vertex / corner is reduced to device RGB through the
/// shading's `ColorSpace` and (when present) its parametric `Function`.
/// Crate-internal test accessor for [`evaluate_mesh_shading`] so the
/// `document` module's integration test can drive the evaluator over a
/// dict its `resolve_shading_resources` produced.
#[cfg(test)]
pub(crate) fn evaluate_mesh_shading_for_test(dict: &Dict) -> Option<MeshShading> {
    evaluate_mesh_shading(dict, None)
}

/// Resolve a shading dictionary's `/ColorSpace` entry to a tracked
/// [`ColorSpaceKind`] (§8.7.4.5.2). The entry is usually an inline array
/// (`[/CalRGB …]`, `[/ICCBased …]`, a device name, …) which
/// [`color_space_from_object`] interprets directly. PDF also permits a
/// shading's `/ColorSpace` to be a *name* referring to the page's
/// `/Resources /ColorSpace` subdictionary; when the object is a bare
/// non-device name and `color_space_resources` is plumbed in, the name
/// is resolved through it (the same path `cs`/`CS` uses).
fn shading_color_space(obj: &Object, color_space_resources: Option<&Dict>) -> ColorSpaceKind {
    if let Object::Name(n) = obj {
        return ColorSpaceKind::resolve_with_resources(n, color_space_resources);
    }
    color_space_from_object(obj)
}

fn evaluate_mesh_shading(dict: &Dict, color_space_resources: Option<&Dict>) -> Option<MeshShading> {
    let get = |key: &str| {
        dict.entries()
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    };
    let shading_type = get("ShadingType").and_then(number_as_i64)?;
    if !(4..=7).contains(&shading_type) {
        return None;
    }
    let cs = shading_color_space(get("ColorSpace")?, color_space_resources);
    if cs == ColorSpaceKind::Unknown {
        return None;
    }
    // §8.7.4.5.5: the colour-component count comes from the colour
    // space — unless a `/Function` entry is present, in which case the
    // stream carries a single parametric value `t` per vertex / corner
    // and the function maps it to the space's components.
    let func = parse_shading_function(get("Function"));
    let n_color = if func.is_some() { 1 } else { cs.components()? };
    let bits_coord = get("BitsPerCoordinate").and_then(number_as_i64)? as u32;
    if !matches!(bits_coord, 1 | 2 | 4 | 8 | 12 | 16 | 24 | 32) {
        return None;
    }
    let bits_comp = get("BitsPerComponent").and_then(number_as_i64)? as u32;
    if !matches!(bits_comp, 1 | 2 | 4 | 8 | 12 | 16) {
        return None;
    }
    let decode = get("Decode").and_then(read_num_array)?;
    // Decode: [ xmin xmax ymin ymax c1min c1max … ]. Two coordinate
    // pairs + one pair per colour component.
    if decode.len() != 4 + 2 * n_color {
        return None;
    }
    let raw = match get("__MeshData") {
        Some(Object::HexString(bytes)) => bytes.as_slice(),
        _ => return None,
    };
    // §8.7.4.5.5 / §8.7.4.5.7: `BitsPerFlag` is required for Type 4
    // (free-form triangle mesh) and Type 6/7 (patch meshes); Type 5
    // (lattice) carries no edge flags, so its flag width is irrelevant.
    let bits_flag = if shading_type == 5 {
        0
    } else {
        let bf = get("BitsPerFlag").and_then(number_as_i64)? as u32;
        if !matches!(bf, 2 | 4 | 8) {
            return None;
        }
        bf
    };
    let evaluator = MeshEvaluator {
        cs: &cs,
        func: func.as_ref(),
        n_color,
        bits_coord,
        bits_comp,
        bits_flag,
        decode: &decode,
    };
    match shading_type {
        4 => evaluator.eval_type4(raw),
        5 => {
            let vpr = get("VerticesPerRow").and_then(number_as_i64)?;
            if vpr < 2 {
                return None;
            }
            evaluator.eval_type5(raw, vpr as usize)
        }
        6 => evaluator.eval_patch(raw, bits_flag, false),
        7 => evaluator.eval_patch(raw, bits_flag, true),
        _ => None,
    }
}

/// Number of colour stops sampled across an axial / radial shading's
/// parametric domain (§8.7.4.5.3–4). 64 evenly-spaced samples capture a
/// smooth gradient at typical output resolutions; a downstream consumer
/// interpolates between adjacent stops.
const GRADIENT_STOPS: usize = 64;
/// Per-axis sample count for a Type 1 (function-based) shading's domain
/// grid (§8.7.4.5.2). 16×16 = 256 samples balances fidelity vs. size for
/// the general 2-in / n-out colour function.
const FUNCTION_GRID: usize = 16;

/// Parse + evaluate a Type 1–3 (function-based / axial / radial) shading
/// dictionary (§8.7.4.5.2–4) into its geometry + sampled colour stops.
/// Returns `None` for a Type 4–7 mesh shading (use
/// [`evaluate_mesh_shading`]), an unresolved colour space, a missing /
/// malformed `Function`, or malformed geometry. The colour function is
/// evaluated across the parametric `Domain` and each result reduced to
/// device RGB through the shading's `ColorSpace`.
/// Convert evenly-spaced shading colour samples into `[GradientStop]`
/// with offsets `i / (n − 1)` across `0.0..=1.0`. A single sample is
/// pinned at offset 0.0.
fn stops_to_gradient_stops(stops: &[Rgba]) -> Vec<GradientStop> {
    let n = stops.len();
    stops
        .iter()
        .enumerate()
        .map(|(i, c)| GradientStop {
            offset: if n <= 1 {
                0.0
            } else {
                i as f32 / (n - 1) as f32
            },
            color: *c,
        })
        .collect()
}

/// Map the `Extend` flags of an axial / radial shading to a scene
/// [`SpreadMethod`]. PDF only has "extend" (pad) or "don't extend"; the
/// scene's `Pad` covers the extend-true case, and a non-extending
/// shading is also approximated as `Pad` (the colour outside the axis is
/// undefined in PDF — clamping is the conservative choice).
fn extend_to_spread(_extend: [bool; 2]) -> SpreadMethod {
    SpreadMethod::Pad
}

/// Convert an evaluated [`ShadingGradient`] (axial or radial) into a
/// scene [`Paint`] gradient, mapping the shading `Coords` from shading
/// space into target space through `to_target` (the pattern `/Matrix`
/// composed with the current CTM). A function-based (Type 1) shading has
/// no single scene-gradient analogue and yields `None`. The radial
/// radii are scaled by the geometric-mean scale factor of `to_target`
/// (PDF shading-pattern matrices are typically uniform-scale, so this is
/// exact in the common case and a reasonable approximation otherwise).
fn gradient_to_paint(g: &ShadingGradient, to_target: Transform2D) -> Option<Paint> {
    let scale = {
        // |det|^(1/2) — the uniform-equivalent linear scale of the 2×2
        // part of the affine map.
        let det = (to_target.a * to_target.d - to_target.b * to_target.c).abs();
        det.sqrt()
    };
    match g {
        ShadingGradient::Axial {
            coords,
            extend,
            stops,
        } => {
            let start = to_target.apply(Point::new(coords[0], coords[1]));
            let end = to_target.apply(Point::new(coords[2], coords[3]));
            Some(Paint::LinearGradient(LinearGradient {
                start,
                end,
                stops: stops_to_gradient_stops(stops),
                spread: extend_to_spread(*extend),
            }))
        }
        ShadingGradient::Radial {
            coords,
            extend,
            stops,
        } => {
            // Map the ending circle (the one the stops sweep toward) to
            // the scene's outer circle; the starting circle becomes the
            // focal point. r1 is the outer radius.
            let focal = to_target.apply(Point::new(coords[0], coords[1]));
            let center = to_target.apply(Point::new(coords[3], coords[4]));
            let radius = coords[5] * scale;
            Some(Paint::RadialGradient(RadialGradient {
                center,
                radius,
                focal: Some(focal),
                stops: stops_to_gradient_stops(stops),
                spread: extend_to_spread(*extend),
            }))
        }
        // A function-based shading paints a 2-D colour field with no
        // linear/radial scene analogue.
        ShadingGradient::FunctionBased { .. } => None,
    }
}

fn evaluate_gradient_shading(
    dict: &Dict,
    color_space_resources: Option<&Dict>,
) -> Option<ShadingGradient> {
    let get = |key: &str| {
        dict.entries()
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    };
    let shading_type = get("ShadingType").and_then(number_as_i64)?;
    if !(1..=3).contains(&shading_type) {
        return None;
    }
    let cs = shading_color_space(get("ColorSpace")?, color_space_resources);
    if cs == ColorSpaceKind::Unknown {
        return None;
    }
    let func = parse_shading_function(get("Function"))?;
    let extend = match get("Extend") {
        Some(Object::Array(items)) if items.len() == 2 => [
            matches!(items[0], Object::Bool(true)),
            matches!(items[1], Object::Bool(true)),
        ],
        _ => [false, false],
    };
    match shading_type {
        2 => {
            // §8.7.4.5.3: Coords = [x0 y0 x1 y1]; Domain = [t0 t1]
            // (default [0 1]). Sample the function across [t0, t1].
            let coords_v = get("Coords").and_then(read_num_array)?;
            if coords_v.len() != 4 {
                return None;
            }
            let coords = [coords_v[0], coords_v[1], coords_v[2], coords_v[3]];
            let (t0, t1) = shading_domain(get("Domain"));
            let stops = sample_stops(&cs, &func, t0, t1)?;
            Some(ShadingGradient::Axial {
                coords,
                extend,
                stops,
            })
        }
        3 => {
            // §8.7.4.5.4: Coords = [x0 y0 r0 x1 y1 r1].
            let coords_v = get("Coords").and_then(read_num_array)?;
            if coords_v.len() != 6 {
                return None;
            }
            let coords = [
                coords_v[0],
                coords_v[1],
                coords_v[2],
                coords_v[3],
                coords_v[4],
                coords_v[5],
            ];
            let (t0, t1) = shading_domain(get("Domain"));
            let stops = sample_stops(&cs, &func, t0, t1)?;
            Some(ShadingGradient::Radial {
                coords,
                extend,
                stops,
            })
        }
        1 => {
            // §8.7.4.5.2: Domain = [xmin xmax ymin ymax] (default
            // [0 1 0 1]); Matrix maps the domain into target space; the
            // 2-in / n-out Function gives the colour at each domain
            // point. Sample onto a FUNCTION_GRID × FUNCTION_GRID grid.
            let domain = match get("Domain").and_then(read_num_array) {
                Some(d) if d.len() == 4 => [d[0], d[1], d[2], d[3]],
                Some(_) => return None,
                None => [0.0, 1.0, 0.0, 1.0],
            };
            let matrix = match get("Matrix").and_then(read_num_array) {
                Some(m) if m.len() == 6 => Transform2D {
                    a: m[0],
                    b: m[1],
                    c: m[2],
                    d: m[3],
                    e: m[4],
                    f: m[5],
                },
                Some(_) => return None,
                None => Transform2D::identity(),
            };
            let nx = FUNCTION_GRID;
            let ny = FUNCTION_GRID;
            let mut samples = Vec::with_capacity(nx * ny);
            for j in 0..ny {
                let y = lerp_domain(domain[2], domain[3], j, ny);
                for i in 0..nx {
                    let x = lerp_domain(domain[0], domain[1], i, nx);
                    let comps = func.eval_n(&[x, y]);
                    samples.push(rgba_from_components(&cs, &comps)?);
                }
            }
            Some(ShadingGradient::FunctionBased {
                domain,
                matrix,
                grid: (nx, ny),
                samples,
            })
        }
        _ => None,
    }
}

/// Read a shading's optional `/Domain` `[t0 t1]` entry (§8.7.4.5.3–4),
/// defaulting to `[0.0, 1.0]`.
fn shading_domain(obj: Option<&Object>) -> (f32, f32) {
    match obj.and_then(read_num_array) {
        Some(d) if d.len() == 2 => (d[0], d[1]),
        _ => (0.0, 1.0),
    }
}

/// The `k`-th of `n` uniform samples across `[lo, hi]` (inclusive of both
/// endpoints when `n > 1`).
fn lerp_domain(lo: f32, hi: f32, k: usize, n: usize) -> f32 {
    if n <= 1 {
        return lo;
    }
    lo + (hi - lo) * (k as f32) / ((n - 1) as f32)
}

/// Sample an axial / radial shading's colour function at
/// [`GRADIENT_STOPS`] uniform parametric values across `[t0, t1]`,
/// reducing each to device RGB. Returns `None` if any sample's colour
/// can't be reduced (unresolved alternate, arity mismatch).
fn sample_stops(
    cs: &ColorSpaceKind,
    func: &ShadingFunction,
    t0: f32,
    t1: f32,
) -> Option<Vec<Rgba>> {
    let mut stops = Vec::with_capacity(GRADIENT_STOPS);
    for k in 0..GRADIENT_STOPS {
        let t = lerp_domain(t0, t1, k, GRADIENT_STOPS);
        let comps = func.eval(t);
        stops.push(rgba_from_components(cs, &comps)?);
    }
    Some(stops)
}

/// Parse a shading's optional `/Function` entry (§8.7.4.5.5) — either a
/// single 1-in / n-out function or an array of n 1-in / 1-out functions
/// (`resolve_shading_resources` has already made each self-contained).
/// `None` for an absent / unparseable entry, in which case the stream
/// carries explicit colour components rather than a parametric value.
fn parse_shading_function(obj: Option<&Object>) -> Option<ShadingFunction> {
    match obj? {
        Object::Array(items) => {
            let parts: Vec<PdfFunction> = items
                .iter()
                .map(PdfFunction::parse)
                .collect::<Option<_>>()?;
            if parts.is_empty() {
                return None;
            }
            Some(ShadingFunction::Array(parts))
        }
        single => Some(ShadingFunction::Single(PdfFunction::parse(single)?)),
    }
}

/// A shading's parametric colour function (§8.7.4.5.5): the stream gives
/// one value `t` per vertex / corner, mapped to the colour space's
/// components by either one `n`-out function or `n` 1-out functions.
enum ShadingFunction {
    Single(PdfFunction),
    Array(Vec<PdfFunction>),
}

impl ShadingFunction {
    /// Evaluate at parametric value `t`, returning the colour-space
    /// component vector.
    fn eval(&self, t: f32) -> Vec<f32> {
        self.eval_n(&[t])
    }

    /// Evaluate at the `m`-input vector `inputs` (one input for axial /
    /// radial / mesh §8.7.4.5.5 functions, two for a Type 1
    /// function-based shading, §8.7.4.5.2), returning the colour-space
    /// component vector. A `Single` n-out function consumes all inputs;
    /// an `Array` of 1-out functions feeds the same inputs to each and
    /// concatenates their first outputs.
    fn eval_n(&self, inputs: &[f32]) -> Vec<f32> {
        match self {
            ShadingFunction::Single(f) => f.eval_n(inputs),
            ShadingFunction::Array(fs) => fs
                .iter()
                .filter_map(|f| f.eval_n(inputs).first().copied())
                .collect(),
        }
    }
}

/// Bundled mesh-stream parameters threaded through the per-type
/// evaluators (Type 4 free-form, Type 5 lattice, Type 6/7 patch).
struct MeshEvaluator<'a> {
    cs: &'a ColorSpaceKind,
    func: Option<&'a ShadingFunction>,
    n_color: usize,
    bits_coord: u32,
    bits_comp: u32,
    /// `BitsPerFlag` (§8.7.4.5.5) — the edge-flag width for Type 4
    /// (free-form) triangle meshes and Type 6/7 patch meshes. `0` for
    /// Type 5 (lattice-form), which carries no edge flags.
    bits_flag: u32,
    decode: &'a [f32],
}

impl MeshEvaluator<'_> {
    /// Read + decode one vertex coordinate pair from `r` using the
    /// `Decode` array's first two pairs.
    fn read_point(&self, r: &mut BitReader) -> Option<Point> {
        let xc = r.read(self.bits_coord)?;
        let yc = r.read(self.bits_coord)?;
        let x = decode_value(xc, self.bits_coord, self.decode[0], self.decode[1]);
        let y = decode_value(yc, self.bits_coord, self.decode[2], self.decode[3]);
        Some(Point::new(x, y))
    }

    /// Read + decode one vertex / corner colour from `r`. When the
    /// shading has a `/Function`, the stream carries a single parametric
    /// value `t` (decoded against the first colour-Decode pair) that the
    /// function maps to the colour-space components; otherwise it carries
    /// `n_color` raw components.
    fn read_color(&self, r: &mut BitReader) -> Option<Rgba> {
        if let Some(func) = self.func {
            let code = r.read(self.bits_comp)?;
            let t = decode_value(code, self.bits_comp, self.decode[4], self.decode[5]);
            let comps = func.eval(t);
            rgba_from_components(self.cs, &comps)
        } else {
            let mut comps = Vec::with_capacity(self.n_color);
            for i in 0..self.n_color {
                let code = r.read(self.bits_comp)?;
                let dmin = self.decode[4 + 2 * i];
                let dmax = self.decode[5 + 2 * i];
                comps.push(decode_value(code, self.bits_comp, dmin, dmax));
            }
            rgba_from_components(self.cs, &comps)
        }
    }

    /// Read one full vertex (point + colour), byte-aligned afterwards.
    fn read_vertex(&self, r: &mut BitReader) -> Option<MeshVertex> {
        let point = self.read_point(r)?;
        let color = self.read_color(r)?;
        r.align_byte();
        Some(MeshVertex { point, color })
    }

    /// §8.7.4.5.5 Type 4: free-form Gouraud triangle mesh. Each vertex
    /// carries an edge flag (`f = 0` starts a new triangle; `f = 1`/`2`
    /// continues from the previous one).
    fn eval_type4(&self, raw: &[u8]) -> Option<MeshShading> {
        let bits_flag = self.bits_flag;
        let mut r = BitReader::new(raw);
        let mut triangles: Vec<MeshTriangle> = Vec::new();
        // The three vertices of the most recent triangle, in stream
        // order (va, vb, vc) per Figure 25.
        let mut prev: Option<[MeshVertex; 3]> = None;
        loop {
            if r.at_end() {
                break;
            }
            let f = match r.read(bits_flag) {
                Some(v) => v & 0b11,
                None => break,
            };
            let v = self.read_vertex(&mut r)?;
            match f {
                0 => {
                    // Start a new triangle: this vertex plus the next
                    // two (whose own flags are ignored, §8.7.4.5.5).
                    r.read(bits_flag)?;
                    let vb = self.read_vertex(&mut r)?;
                    r.read(bits_flag)?;
                    let vc = self.read_vertex(&mut r)?;
                    let tri = [v, vb, vc];
                    triangles.push(MeshTriangle { vertices: tri });
                    prev = Some(tri);
                }
                1 => {
                    // Continue on side vbc: new triangle (vb, vc, vd).
                    let [_va, vb, vc] = prev?;
                    let tri = [vb, vc, v];
                    triangles.push(MeshTriangle { vertices: tri });
                    prev = Some(tri);
                }
                2 => {
                    // Continue on side vac: new triangle (va, vc, vd).
                    let [va, _vb, vc] = prev?;
                    let tri = [va, vc, v];
                    triangles.push(MeshTriangle { vertices: tri });
                    prev = Some(tri);
                }
                _ => return None,
            }
        }
        if triangles.is_empty() {
            return None;
        }
        Some(MeshShading::Triangles(triangles))
    }

    /// §8.7.4.5.6 Type 5: lattice-form Gouraud triangle mesh. Vertices
    /// are laid out row-major (`VerticesPerRow` per row, no edge flags);
    /// adjacent rows form two triangles per cell (§8.7.4.5.6).
    fn eval_type5(&self, raw: &[u8], vpr: usize) -> Option<MeshShading> {
        let mut r = BitReader::new(raw);
        let mut rows: Vec<Vec<MeshVertex>> = Vec::new();
        loop {
            if r.at_end() {
                break;
            }
            let mut row = Vec::with_capacity(vpr);
            for _ in 0..vpr {
                match self.read_vertex(&mut r) {
                    Some(v) => row.push(v),
                    None => break,
                }
            }
            if row.len() != vpr {
                break;
            }
            rows.push(row);
        }
        if rows.len() < 2 {
            return None;
        }
        let mut triangles = Vec::new();
        for i in 0..rows.len() - 1 {
            for j in 0..vpr - 1 {
                // (V_i,j, V_i,j+1, V_i+1,j) and
                // (V_i,j+1, V_i+1,j, V_i+1,j+1), §8.7.4.5.6.
                let a = rows[i][j];
                let b = rows[i][j + 1];
                let c = rows[i + 1][j];
                let d = rows[i + 1][j + 1];
                triangles.push(MeshTriangle {
                    vertices: [a, b, c],
                });
                triangles.push(MeshTriangle {
                    vertices: [b, c, d],
                });
            }
        }
        Some(MeshShading::Triangles(triangles))
    }

    /// §8.7.4.5.7–8 Type 6 / 7: Coons / tensor-product patch mesh.
    /// `tensor` selects the 16-control-point tensor layout (Type 7) vs
    /// the 12-control-point Coons layout (Type 6); a Coons patch is
    /// expanded to the equivalent tensor patch via the §8.7.4.5.8
    /// internal-control-point equations.
    fn eval_patch(&self, raw: &[u8], bits_flag: u32, tensor: bool) -> Option<MeshShading> {
        let mut r = BitReader::new(raw);
        let mut patches: Vec<MeshPatch> = Vec::new();
        // Coordinate count per patch element: 12 boundary control points
        // (Coons) or 16 (tensor); a continuation patch (`f != 0`)
        // supplies only the 8 / 12 *new* points.
        loop {
            if r.at_end() {
                break;
            }
            let f = match r.read(bits_flag) {
                Some(v) => v & 0b11,
                None => break,
            };
            let new_pts = if f == 0 {
                if tensor {
                    16
                } else {
                    12
                }
            } else if tensor {
                12
            } else {
                8
            };
            let mut pts = Vec::with_capacity(new_pts);
            for _ in 0..new_pts {
                pts.push(self.read_point(&mut r)?);
            }
            let new_cols = if f == 0 { 4 } else { 2 };
            let mut cols = Vec::with_capacity(new_cols);
            for _ in 0..new_cols {
                cols.push(self.read_color(&mut r)?);
            }
            r.align_byte();
            let patch = build_patch(f, tensor, &pts, &cols, patches.last())?;
            patches.push(patch);
        }
        if patches.is_empty() {
            return None;
        }
        Some(MeshShading::Patches(patches))
    }
}

/// Assemble one Coons / tensor patch from its freshly-read control
/// points + corner colours and the previous patch's edge data
/// (§8.7.4.5.7 Table 85 / §8.7.4.5.8 Table 86).
///
/// The 16 tensor control points are addressed as `p[col][row]`
/// (`p[i][j]` = `pij` in Figure 32). For a tensor patch (`tensor =
/// true`) the 16 explicit points arrive in the Table 86 stream order;
/// for a Coons patch (`tensor = false`) the 12 boundary points arrive in
/// the Table 85 order (= the 12 boundary entries of the tensor order)
/// and the four internal points are derived from the boundary curves via
/// the §8.7.4.5.8 conversion equations. A continuation patch (`f != 0`)
/// inherits four boundary points + two corner colours from the previous
/// patch's shared edge.
fn build_patch(
    f: u64,
    tensor: bool,
    new_pts: &[Point],
    new_cols: &[Rgba],
    prev: Option<&MeshPatch>,
) -> Option<MeshPatch> {
    // The tensor stream order of the 16 points (Table 86, f=0), as
    // (col, row) indices into p[col][row]:
    //   p00 p01 p02 p03 p13 p23 p33 p32 p31 p30 p20 p10 p11 p12 p22 p21
    const TENSOR_ORDER: [(usize, usize); 16] = [
        (0, 0),
        (0, 1),
        (0, 2),
        (0, 3),
        (1, 3),
        (2, 3),
        (3, 3),
        (3, 2),
        (3, 1),
        (3, 0),
        (2, 0),
        (1, 0),
        (1, 1),
        (1, 2),
        (2, 2),
        (2, 1),
    ];
    // For a continuation patch the stream supplies the *new* points,
    // which fill the tensor-order slots starting at index 4 (Coons) /
    // index 4 (tensor) — the first four entries are the shared edge,
    // inherited below. Table 85/86 list the new points starting with
    // p13/x5; the first four tensor-order slots (the shared edge) are
    // not in the stream.
    let mut p = [[Point::new(0.0, 0.0); 4]; 4];
    // For tensor patches we always work in the 16-slot order. For Coons
    // patches only the 12 boundary slots (the first 12 entries of
    // TENSOR_ORDER) are populated from the stream; the four internal
    // slots are the last four entries.
    let boundary_slots = 12usize;
    if f == 0 {
        let count = if tensor { 16 } else { boundary_slots };
        if new_pts.len() != count {
            return None;
        }
        for (k, &pt) in new_pts.iter().enumerate() {
            let (c, rr) = TENSOR_ORDER[k];
            p[c][rr] = pt;
        }
    } else {
        let prev = prev?;
        // Inherit the four shared-edge boundary points from the previous
        // patch per the edge flag (§8.7.4.5.8 Table 86 — the same four
        // tensor-order slots 0..3 are filled from the previous patch's
        // selected edge). The mapping is expressed via the previous
        // patch's `p[col][row]`.
        let shared: [(usize, usize); 4] = match f {
            1 => [(0, 3), (1, 3), (2, 3), (3, 3)], // prev top edge (p03 p13 p23 p33)
            2 => [(3, 3), (3, 2), (3, 1), (3, 0)], // prev right edge (p33 p32 p31 p30)
            3 => [(3, 0), (2, 0), (1, 0), (0, 0)], // prev bottom edge (p30 p20 p10 p00)
            _ => return None,
        };
        // Tensor-order slots 0..3 (p00 p01 p02 p03) take the previous
        // patch's shared-edge points.
        for (k, &(c, rr)) in shared.iter().enumerate() {
            let (tc, trr) = TENSOR_ORDER[k];
            p[tc][trr] = prev.control_points[c][rr];
        }
        // The remaining new points fill tensor-order slots 4..count.
        let count = if tensor { 16 } else { boundary_slots };
        if new_pts.len() != count - 4 {
            return None;
        }
        for (k, &pt) in new_pts.iter().enumerate() {
            let (c, rr) = TENSOR_ORDER[k + 4];
            p[c][rr] = pt;
        }
    }
    // For a Coons patch, derive the four internal control points from
    // the boundary curves (§8.7.4.5.8 conversion equations).
    if !tensor {
        p[1][1] = coons_internal(
            p[0][0], p[0][1], p[1][0], p[0][3], p[3][0], p[3][1], p[1][3], p[3][3],
        );
        p[1][2] = coons_internal(
            p[0][3], p[0][2], p[1][3], p[0][0], p[3][3], p[3][2], p[1][0], p[3][0],
        );
        p[2][1] = coons_internal(
            p[3][0], p[3][1], p[2][0], p[3][3], p[0][0], p[0][1], p[2][3], p[0][3],
        );
        p[2][2] = coons_internal(
            p[3][3], p[3][2], p[2][3], p[3][0], p[0][3], p[0][2], p[2][0], p[0][0],
        );
    }
    // Corner colours: c1=p00, c2=p03, c3=p33, c4=p30 (§8.7.4.5.7).
    let corner_colors: [Rgba; 4] = if f == 0 {
        if new_cols.len() != 4 {
            return None;
        }
        [new_cols[0], new_cols[1], new_cols[2], new_cols[3]]
    } else {
        let prev = prev?;
        if new_cols.len() != 2 {
            return None;
        }
        // Two corner colours inherited from the previous patch's shared
        // edge, two read from the stream (§8.7.4.5.7 Table 85 /
        // §8.7.4.5.8 Table 86: c1 c2 inherited, c3 c4 = the new pair).
        let (c1, c2) = match f {
            1 => (prev.corner_colors[1], prev.corner_colors[2]), // c1=c2prev c2=c3prev
            2 => (prev.corner_colors[2], prev.corner_colors[3]), // c1=c3prev c2=c4prev
            3 => (prev.corner_colors[3], prev.corner_colors[0]), // c1=c4prev c2=c1prev
            _ => return None,
        };
        [c1, c2, new_cols[0], new_cols[1]]
    };
    Some(MeshPatch {
        control_points: p,
        corner_colors,
    })
}

/// One internal-control-point of a Coons patch, derived from the
/// boundary control points per the §8.7.4.5.8 conversion equation
///
/// ```text
/// p = 1/9 × [ −4·a + 6·(b + c) − 2·(d + e) + 3·(f + g) − 1·h ]
/// ```
///
/// The four `p11`/`p12`/`p21`/`p22` equations share this shape with
/// different point assignments; the caller supplies them in
/// `(a, b, c, d, e, f, g, h)` order.
#[allow(clippy::too_many_arguments)]
fn coons_internal(
    a: Point,
    b: Point,
    c: Point,
    d: Point,
    e: Point,
    f: Point,
    g: Point,
    h: Point,
) -> Point {
    let comp = |a: f32, b: f32, c: f32, d: f32, e: f32, f: f32, g: f32, h: f32| -> f32 {
        (-4.0 * a + 6.0 * (b + c) - 2.0 * (d + e) + 3.0 * (f + g) - h) / 9.0
    };
    Point::new(
        comp(a.x, b.x, c.x, d.x, e.x, f.x, g.x, h.x),
        comp(a.y, b.y, c.y, d.y, e.y, f.y, g.y, h.y),
    )
}

/// Convert a DeviceCMYK colour value to DeviceRGB per ISO 32000-1
/// §10.3.5 ("Conversion from DeviceCMYK to DeviceRGB"):
///
/// ```text
/// red   = 1.0 − min(1.0, cyan    + black)
/// green = 1.0 − min(1.0, magenta + black)
/// blue  = 1.0 − min(1.0, yellow  + black)
/// ```
///
/// The black component is added to each of the other components, which
/// are then converted to their complementary colours by subtracting
/// each from 1.0. No black generation or undercolour removal is
/// involved. Components are clamped into 0.0..=1.0 first so an
/// out-of-range operand cannot escape the 1.0 ceiling (§10.3.4 NOTE 4
/// applies the same nearest-valid-value substitution without error).
fn rgb_from_cmyk(cyan: f32, magenta: f32, yellow: f32, black: f32) -> Rgba {
    let c = cyan.clamp(0.0, 1.0);
    let m = magenta.clamp(0.0, 1.0);
    let y = yellow.clamp(0.0, 1.0);
    let k = black.clamp(0.0, 1.0);
    let red = 1.0 - (c + k).min(1.0);
    let green = 1.0 - (m + k).min(1.0);
    let blue = 1.0 - (y + k).min(1.0);
    rgb_from_unit(red, green, blue)
}

fn unit_to_byte(f: f32) -> u8 {
    (f.clamp(0.0, 1.0) * 255.0).round() as u8
}

// ───────────── CIE-based colour science (§8.6.5.2–4) ──────────────
//
// The CalGray (§8.6.5.2), CalRGB (§8.6.5.3) and Lab (§8.6.5.4) spaces
// produce a CIE 1931 XYZ tristimulus value through the per-space
// transformations defined in their respective sub-clauses (gamma decode
// + WhitePoint scale for CalGray, gamma decode + 3×3 Matrix for CalRGB,
// the implicit L*a*b* → XYZ stages for Lab). §10.2 ("CIE-Based Colour
// to Device Colour") then gamut-maps XYZ onto the output device. With
// no physical device model in a software renderer the conventional
// reduction is to the sRGB display space: a fixed XYZ → linear-RGB
// matrix followed by the sRGB opto-electronic transfer encoding. This
// is the standard sRGB colorimetry (IEC 61966-2-1), reproduced here
// from first principles — not derived from any third-party renderer.

/// Encode one linear-light RGB component (0.0..=1.0) with the sRGB
/// transfer function. Values are clamped into range first; the
/// piecewise curve has a small linear segment near black and a
/// 1/2.4-power segment above the `0.0031308` breakpoint.
fn srgb_encode(c: f32) -> f32 {
    let c = c.clamp(0.0, 1.0);
    if c <= 0.003_130_8 {
        12.92 * c
    } else {
        1.055 * c.powf(1.0 / 2.4) - 0.055
    }
}

/// Map a CIE 1931 XYZ tristimulus value to a device-RGB [`Rgba`] via
/// the sRGB display space. The XYZ → linear-sRGB matrix is the standard
/// D65 sRGB primaries inverse; each linear component is then sRGB-
/// encoded and quantised. Out-of-gamut components are clamped to
/// `0.0..=1.0` "without error indication" in the spirit of §8.6.5's
/// component-clamping rule.
fn rgb_from_xyz(x: f32, y: f32, z: f32) -> Rgba {
    let r = 3.240_625_5 * x - 1.537_208 * y - 0.498_628_6 * z;
    let g = -0.968_930_7 * x + 1.875_756_1 * y + 0.041_517_5 * z;
    let b = 0.055_710_1 * x - 0.204_021_1 * y + 1.056_995_9 * z;
    rgb_from_unit(srgb_encode(r), srgb_encode(g), srgb_encode(b))
}

/// CalGray (§8.6.5.2): decode the single gray component `a` by the
/// `gamma` exponent and scale by the white point `[xw, yw, zw]` to get
/// XYZ, then map to RGB. `a` is clamped into `0.0..=1.0` per the
/// CIE-based-A component range.
fn cal_gray_color(white: [f32; 3], gamma: f32, a: f32) -> Rgba {
    let a = a.clamp(0.0, 1.0);
    let decoded = a.powf(gamma);
    rgb_from_xyz(white[0] * decoded, white[1] * decoded, white[2] * decoded)
}

/// CalRGB (§8.6.5.3): decode the A/B/C components by their per-channel
/// `gamma` exponents, multiply the decoded vector by the 3×3 `matrix`
/// (`[xa ya za xb yb zb xc yc zc]`, column-major per component) to get
/// XYZ, then map to RGB. Components are clamped into `0.0..=1.0`.
fn cal_rgb_color(gamma: [f32; 3], matrix: [f32; 9], abc: [f32; 3]) -> Rgba {
    let da = abc[0].clamp(0.0, 1.0).powf(gamma[0]);
    let db = abc[1].clamp(0.0, 1.0).powf(gamma[1]);
    let dc = abc[2].clamp(0.0, 1.0).powf(gamma[2]);
    // X = XA·A^GR + XB·B^GG + XC·C^GB, and likewise for Y, Z.
    let x = matrix[0] * da + matrix[3] * db + matrix[6] * dc;
    let y = matrix[1] * da + matrix[4] * db + matrix[7] * dc;
    let z = matrix[2] * da + matrix[5] * db + matrix[8] * dc;
    rgb_from_xyz(x, y, z)
}

/// The §8.6.5.4 `g(x)` reverse-companding function used by both the Lab
/// → XYZ stage.
fn lab_g(x: f32) -> f32 {
    // 6/29 = 0.206896…; below the breakpoint the linear segment with
    // slope 108/841 and offset 4/29 applies.
    if x >= 6.0 / 29.0 {
        x * x * x
    } else {
        (108.0 / 841.0) * (x - 4.0 / 29.0)
    }
}

/// Lab (§8.6.5.4): map the `[l, a, b]` triple (L* in 0..=100, a*/b*
/// already clamped into the space's `Range`) to XYZ through the implicit
/// two-stage transform, scaling by the white point `[xw, yw, zw]`, then
/// to RGB.
fn lab_color(white: [f32; 3], lab: [f32; 3]) -> Rgba {
    let l = lab[0].clamp(0.0, 100.0);
    let m_base = (l + 16.0) / 116.0;
    let l_in = m_base + lab[1] / 500.0;
    let n_in = m_base - lab[2] / 200.0;
    rgb_from_xyz(
        white[0] * lab_g(l_in),
        white[1] * lab_g(m_base),
        white[2] * lab_g(n_in),
    )
}

/// Hard ceiling on the number of pattern cells a single tiling fill may
/// emit (§8.7.3). A fill region many multiples of XStep/YStep wide could
/// otherwise produce an unbounded node count; past this cap the fill
/// falls back to its solid colour rather than tiling.
const MAX_TILING_CELLS: i64 = 4096;

/// Re-entrancy ceiling for the Type 3 glyph paint path (§9.6.5). A
/// glyph description is itself a content stream and may show text in
/// another Type 3 font; this caps the nesting so a `/CharProcs` entry
/// that (directly or transitively) shows itself terminates.
const MAX_TYPE3_DEPTH: u32 = 8;

/// Recolour every painted path in a node subtree to a single solid
/// colour — the stencil-pour operation for an uncoloured (`/PaintType 2`)
/// tiling pattern cell (§8.7.3.3). A `/PaintType 2` cell carries no
/// colour of its own, so each fill / stroke that *is* present is repainted
/// with the underlying colour the `scn` supplied. Paths with no fill /
/// stroke (pure clip / construction paths) are left untouched; group
/// transforms / clips are preserved.
fn recolor_node(node: &mut Node, color: Rgba) {
    match node {
        Node::Path(p) => {
            if p.fill.is_some() {
                p.fill = Some(Paint::Solid(color));
            }
            if let Some(stroke) = &mut p.stroke {
                stroke.paint = Paint::Solid(color);
            }
        }
        Node::Group(g) => {
            for child in &mut g.children {
                recolor_node(child, color);
            }
        }
        _ => {}
    }
}

/// A closed rectangular subpath `[llx, lly] → [urx, ury]` (the four
/// corners + `Close`). Used as a tiling pattern cell's `/BBox` clip and
/// to build the per-tile clip rectangle.
fn rect_path(x0: f32, y0: f32, x1: f32, y1: f32) -> Path {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(x0, y0)));
    p.commands.push(PathCommand::LineTo(Point::new(x1, y0)));
    p.commands.push(PathCommand::LineTo(Point::new(x1, y1)));
    p.commands.push(PathCommand::LineTo(Point::new(x0, y1)));
    p.commands.push(PathCommand::Close);
    p
}

/// Apply an affine transform to every coordinate of a path's commands,
/// returning a new path in the transformed space. Control points of
/// curve commands are mapped too (affine maps preserve Béziers). `Close`
/// carries no coordinate. `ArcTo` is mapped by its endpoint only — the
/// reader never constructs arc commands in a content stream (the writer
/// flattens arcs to cubics), so this branch is a best-effort passthrough.
fn transform_path(path: &Path, m: Transform2D) -> Path {
    let mut out = Path::new();
    out.commands.reserve(path.commands.len());
    for cmd in &path.commands {
        let mapped = match *cmd {
            PathCommand::MoveTo(p) => PathCommand::MoveTo(m.apply(p)),
            PathCommand::LineTo(p) => PathCommand::LineTo(m.apply(p)),
            PathCommand::QuadCurveTo { control, end } => PathCommand::QuadCurveTo {
                control: m.apply(control),
                end: m.apply(end),
            },
            PathCommand::CubicCurveTo { c1, c2, end } => PathCommand::CubicCurveTo {
                c1: m.apply(c1),
                c2: m.apply(c2),
                end: m.apply(end),
            },
            PathCommand::ArcTo {
                rx,
                ry,
                x_axis_rot,
                large_arc,
                sweep,
                end,
            } => PathCommand::ArcTo {
                rx,
                ry,
                x_axis_rot,
                large_arc,
                sweep,
                end: m.apply(end),
            },
            PathCommand::Close => PathCommand::Close,
            _ => *cmd,
        };
        out.commands.push(mapped);
    }
    out
}

/// Axis-aligned bounding box `(min_x, min_y, max_x, max_y)` over every
/// coordinate a path touches (anchor + control points — a conservative
/// superset of the true Bézier hull, which is all the tiling lattice
/// needs). Returns `None` for an empty path or one whose coordinates are
/// non-finite.
fn path_bounds(path: &Path) -> Option<(f32, f32, f32, f32)> {
    let (mut x0, mut y0, mut x1, mut y1) = (
        f32::INFINITY,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NEG_INFINITY,
    );
    let mut acc = |p: Point| {
        x0 = x0.min(p.x);
        y0 = y0.min(p.y);
        x1 = x1.max(p.x);
        y1 = y1.max(p.y);
    };
    for cmd in &path.commands {
        match *cmd {
            PathCommand::MoveTo(p) | PathCommand::LineTo(p) => acc(p),
            PathCommand::QuadCurveTo { control, end } => {
                acc(control);
                acc(end);
            }
            PathCommand::CubicCurveTo { c1, c2, end } => {
                acc(c1);
                acc(c2);
                acc(end);
            }
            PathCommand::ArcTo { end, .. } => acc(end),
            PathCommand::Close => {}
            _ => {}
        }
    }
    if x0.is_finite() && y0.is_finite() && x1.is_finite() && y1.is_finite() && x0 <= x1 && y0 <= y1
    {
        Some((x0, y0, x1, y1))
    } else {
        None
    }
}

/// Invert an affine transform `[a b c d e f]`. Returns `None` when the
/// linear part is singular (zero determinant) — a degenerate pattern
/// matrix that maps every tile to a line/point, for which no tiling can
/// be computed.
fn invert_transform(m: Transform2D) -> Option<Transform2D> {
    let det = m.a * m.d - m.b * m.c;
    if !det.is_finite() || det.abs() < f32::EPSILON {
        return None;
    }
    let inv_det = 1.0 / det;
    let a = m.d * inv_det;
    let b = -m.b * inv_det;
    let c = -m.c * inv_det;
    let d = m.a * inv_det;
    // Translation of the inverse: −(linear⁻¹ · [e f]).
    let e = -(a * m.e + c * m.f);
    let f = -(b * m.e + d * m.f);
    let inv = Transform2D { a, b, c, d, e, f };
    if [inv.a, inv.b, inv.c, inv.d, inv.e, inv.f]
        .iter()
        .all(|v| v.is_finite())
    {
        Some(inv)
    } else {
        None
    }
}

fn compose(a: Transform2D, b: Transform2D) -> Transform2D {
    // PDF `cm` post-concatenates: new CTM = b * old CTM. In the
    // SVG/IR convention, group.transform applies to the children
    // *before* any parent transform — so when we encounter a `cm`
    // inside a frame whose existing transform is `a`, the resulting
    // group transform is `a * b`.
    Transform2D {
        a: a.a * b.a + a.c * b.b,
        b: a.b * b.a + a.d * b.b,
        c: a.a * b.c + a.c * b.d,
        d: a.b * b.c + a.d * b.d,
        e: a.a * b.e + a.c * b.f + a.e,
        f: a.b * b.e + a.d * b.f + a.f,
    }
}

fn scan_keyword_end(input: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < input.len() && !is_whitespace(input[end]) && !is_delimiter(input[end]) {
        end += 1;
    }
    end
}

/// Exact f32 powers of ten for the fast decimal→binary path. Every
/// entry is exactly representable: 10^k = 5^k·2^k and 5^10 =
/// 9 765 625 < 2^24, so the table stops at 10^10.
const POW10_F32: [f32; 11] = [1.0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10];

/// Result of scanning one §7.3.3 numeric operand in a content stream.
enum NumScan {
    /// No digit was consumed — the bytes at `start` are a bare sign /
    /// dot keyword, not a number. The cursor is unchanged.
    NotANumber,
    /// Number scanned **and** converted on the exact-arithmetic fast
    /// path; the first field is the byte after the number.
    Fast(usize, f32),
    /// Number scanned but outside the fast-path range (significand ≥
    /// 2^24 or more than 10 fractional digits); the payload is the
    /// byte after the number — the caller re-parses the scanned bytes
    /// through `str::parse` with its own error policy.
    Slow(usize),
}

/// Scan a numeric operand starting at `start` (whose byte must be
/// `+` / `-` / `.` / digit) and convert it without the UTF-8 +
/// general-purpose float-parse round trip when exact arithmetic
/// allows.
///
/// A content-stream number is `sign? digits? ("." digits?)?` — no
/// exponent (§7.3.3) — so its value is `significand / 10^frac`. When
/// the significand is `< 2^24` (exact in f32) and `frac ≤ 10` (the
/// divisor is exact in f32, see [`POW10_F32`]), IEEE-754 division of
/// two exact operands is correctly rounded, and the correctly rounded
/// result is unique — bit-identical to what `str::parse::<f32>`
/// returns for the same bytes. Anything wider falls back to
/// [`NumScan::Slow`].
fn scan_number(input: &[u8], start: usize) -> NumScan {
    let mut end = start;
    let neg = input[end] == b'-';
    if matches!(input[end], b'+' | b'-') {
        end += 1;
    }
    let mut mant: u64 = 0;
    let mut frac: usize = 0;
    let mut saw_digit = false;
    let mut saw_dot = false;
    // Set once the significand stops being tracked exactly (≥ ~17
    // digits); forces the slow path.
    let mut wide = false;
    while end < input.len() {
        let c = input[end];
        if c.is_ascii_digit() {
            saw_digit = true;
            if mant < (1 << 56) {
                mant = mant * 10 + (c - b'0') as u64;
            } else {
                wide = true;
            }
            if saw_dot {
                frac += 1;
            }
            end += 1;
        } else if c == b'.' && !saw_dot {
            saw_dot = true;
            end += 1;
        } else {
            break;
        }
    }
    if !saw_digit {
        return NumScan::NotANumber;
    }
    if !wide && mant < (1 << 24) && frac <= 10 {
        let q = mant as f32 / POW10_F32[frac];
        NumScan::Fast(end, if neg { -q } else { q })
    } else {
        NumScan::Slow(end)
    }
}

/// Decode a PDF literal string `( … )` per ISO 32000-1 §7.3.4.2 —
/// nested parentheses balance; the escape sequences `\n \r \t \b \f
/// \( \) \\` produce their familiar byte, an octal escape `\ddd`
/// (1..3 digits) produces that byte, a line-continuation `\<EOL>` is
/// dropped, and any other `\c` falls through to the literal `c`. The
/// returned `Vec<u8>` is the raw bytes the operator should see; the
/// byte→Unicode mapping (per the active font's encoding) is the
/// caller's job.
fn read_literal_string(input: &[u8], start: usize) -> Result<(usize, Vec<u8>), PdfError> {
    let mut end = start + 1;
    let mut depth = 1u32;
    let mut decoded = Vec::new();
    while end < input.len() {
        let b = input[end];
        if b == b'\\' {
            end += 1;
            if end >= input.len() {
                break;
            }
            let esc = input[end];
            match esc {
                b'n' => {
                    decoded.push(b'\n');
                    end += 1;
                }
                b'r' => {
                    decoded.push(b'\r');
                    end += 1;
                }
                b't' => {
                    decoded.push(b'\t');
                    end += 1;
                }
                b'b' => {
                    decoded.push(0x08);
                    end += 1;
                }
                b'f' => {
                    decoded.push(0x0C);
                    end += 1;
                }
                b'(' | b')' | b'\\' => {
                    decoded.push(esc);
                    end += 1;
                }
                b'\n' => {
                    end += 1;
                }
                b'\r' => {
                    end += 1;
                    if end < input.len() && input[end] == b'\n' {
                        end += 1;
                    }
                }
                d if d.is_ascii_digit() => {
                    // Octal escape \ddd — up to three octal digits.
                    let mut val: u16 = 0;
                    let mut n = 0;
                    while n < 3 && end < input.len() {
                        let c = input[end];
                        if !(b'0'..=b'7').contains(&c) {
                            break;
                        }
                        val = val * 8 + (c - b'0') as u16;
                        end += 1;
                        n += 1;
                    }
                    decoded.push((val & 0xFF) as u8);
                }
                other => {
                    // Unknown escape — the spec says the backslash is
                    // dropped and the following byte is taken as is.
                    decoded.push(other);
                    end += 1;
                }
            }
            continue;
        }
        if b == b'(' {
            depth += 1;
        }
        if b == b')' {
            depth -= 1;
            if depth == 0 {
                end += 1;
                return Ok((end, decoded));
            }
        }
        decoded.push(b);
        end += 1;
    }
    Err(PdfError::other(
        "PDF content parser: unterminated literal string",
    ))
}

/// Decode a PDF hex string `< … >` per ISO 32000-1 §7.3.4.3 —
/// whitespace inside the angle brackets is skipped; a trailing odd
/// digit is implicitly padded with `0`. The returned `Vec<u8>` holds
/// one byte per hex pair.
fn read_hex_string(input: &[u8], start: usize) -> Result<(usize, Vec<u8>), PdfError> {
    let mut end = start + 1;
    let mut nibbles: Vec<u8> = Vec::new();
    while end < input.len() {
        let c = input[end];
        if c == b'>' {
            // Pad a trailing odd nibble per §7.3.4.3.
            if nibbles.len() % 2 == 1 {
                nibbles.push(0);
            }
            let mut out = Vec::with_capacity(nibbles.len() / 2);
            for pair in nibbles.chunks(2) {
                out.push((pair[0] << 4) | pair[1]);
            }
            return Ok((end + 1, out));
        }
        if let Some(v) = hex_nibble(c) {
            nibbles.push(v);
        }
        // else: any other byte (including whitespace) is silently
        // skipped per §7.3.4.3.
        end += 1;
    }
    Err(PdfError::other(
        "PDF content parser: unterminated hex string",
    ))
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(10 + c - b'a'),
        b'A'..=b'F' => Some(10 + c - b'A'),
        _ => None,
    }
}

/// Look up a name key in a dictionary and unwrap it as a nested
/// [`Dict`]. Returns `None` for missing keys or non-dict values. The
/// `gs` resolver uses this against `/Resources /ExtGState`. Indirect
/// references are not followed — the caller is expected to have
/// already resolved each subdict (the wiring in
/// `reader::document::page_resource_dict` does this).
fn lookup_dict<'a>(dict: &'a Dict, key: &str) -> Option<&'a Dict> {
    dict.entries()
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            Object::Dict(d) => Some(d),
            _ => None,
        })
}

/// Per-glyph horizontal advance metrics resolved from a font
/// dictionary, in glyph-space units (thousandths of a text-space
/// unit; §9.2.4). Used by the text-showing operators to apply the
/// §9.4.4 displacement and so advance the text matrix between
/// consecutive glyphs / shows.
///
/// Built by [`build_font_metrics`] from the already-resolved
/// `/Resources /Font /Fx` dictionary. The walker requires the
/// document-level resolver to have deep-resolved the width data
/// (`/Widths` array entries, and for composite fonts the descendant
/// CIDFont's `/W` / `/DW`) so the values are direct numerics here —
/// matching the one-hop-resolved resource contract the rest of the
/// walker relies on.
#[derive(Clone, Debug)]
enum FontMetrics {
    /// Simple font (Type1 / TrueType / Type3, §9.6): one byte per
    /// code. `widths[code − first_char]` gives the advance; codes
    /// outside `[first_char, first_char + widths.len())` use
    /// `missing_width`. `text_scale` converts a stored width into
    /// text-space units (§9.2.4): `0.001` for Type1 / TrueType (their
    /// widths are in thousandths of text space), or the horizontal
    /// component of the Type 3 `/FontMatrix` (§9.6.5 — Type 3 widths are
    /// in glyph space, interpreted through `/FontMatrix`).
    Simple {
        first_char: i64,
        widths: Vec<f32>,
        missing_width: f32,
        text_scale: f32,
    },
    /// Composite (Type0) font (§9.7): two bytes per code under the
    /// Identity-H/V CMaps the writer emits, where the CID equals the
    /// code. `default_width` is the CIDFont `/DW` (default 1000);
    /// `ranges` are the parsed `/W` entries (start CID, run of
    /// per-CID widths).
    Cid {
        default_width: f32,
        ranges: Vec<(i64, Vec<f32>)>,
        two_byte: bool,
    },
    /// No width data could be resolved — every glyph advances by 0,
    /// so consecutive shows keep the prior behaviour of reporting the
    /// run origin without a per-glyph step.
    None,
}

impl FontMetrics {
    /// Horizontal advance (glyph-space, thousandths) for one code.
    /// `is_cid` callers pass the CID; simple-font callers pass the
    /// byte. Returns 0.0 for [`FontMetrics::None`].
    fn width(&self, code: i64) -> f32 {
        match self {
            FontMetrics::Simple {
                first_char,
                widths,
                missing_width,
                ..
            } => {
                let idx = code - first_char;
                if idx >= 0 && (idx as usize) < widths.len() {
                    widths[idx as usize]
                } else {
                    *missing_width
                }
            }
            FontMetrics::Cid {
                default_width,
                ranges,
                ..
            } => {
                for (start, run) in ranges {
                    let off = code - start;
                    if off >= 0 && (off as usize) < run.len() {
                        return run[off as usize];
                    }
                }
                *default_width
            }
            FontMetrics::None => 0.0,
        }
    }

    /// Whether codes are two bytes wide (composite Identity fonts).
    fn two_byte(&self) -> bool {
        matches!(self, FontMetrics::Cid { two_byte: true, .. })
    }

    /// Factor converting a [`Self::width`] result into text-space units
    /// for the §9.4.4 displacement (§9.2.4). Type1 / TrueType widths are
    /// thousandths of text space (`0.001`); a Type 3 font carries the
    /// horizontal `/FontMatrix` scale instead, since its widths live in
    /// glyph space. Composite fonts are thousandths (`/W` / `/DW` are in
    /// glyph space with the standard 1000-unit em).
    fn text_scale(&self) -> f32 {
        match self {
            FontMetrics::Simple { text_scale, .. } => *text_scale,
            _ => 0.001,
        }
    }
}

/// Resolve a font dictionary into [`FontMetrics`].
///
/// * **Simple fonts** (§9.6.2.1, Table 111): `/FirstChar`, `/Widths`
///   (array of numbers), and `/MissingWidth` (from `/FontDescriptor`,
///   default 0). When `/Widths` is absent the metrics are
///   [`FontMetrics::None`] — the standard-14 base fonts omit `/Widths`
///   and their built-in AFM metrics aren't available clean-room here.
/// * **Composite (Type0) fonts** (§9.7.4.3): the descendant CIDFont's
///   `/W` array (two-or-three-element groups, §9.7.4.3) and `/DW`
///   default (default 1000). The walker only resolves the Identity
///   CMaps, where CID = 2-byte code.
fn build_font_metrics(font: &Dict) -> FontMetrics {
    let subtype = font
        .entries()
        .iter()
        .find_map(|(k, v)| match (k.as_str(), v) {
            ("Subtype", Object::Name(s)) => Some(s.as_str()),
            _ => None,
        });
    if subtype == Some("Type0") {
        return build_cid_metrics(font);
    }

    // Simple font: /FirstChar + /Widths (+ /MissingWidth in the
    // /FontDescriptor). When the document-level resolver has
    // dereferenced /Widths it is a direct Array of numbers here.
    let first_char = font
        .entries()
        .iter()
        .find(|(k, _)| k == "FirstChar")
        .and_then(|(_, v)| number_as_i64(v))
        .unwrap_or(0);
    let widths = match font.entries().iter().find(|(k, _)| k == "Widths") {
        Some((_, Object::Array(items))) => items
            .iter()
            .map(|o| number_as_f32(o).unwrap_or(0.0))
            .collect(),
        _ => Vec::new(),
    };
    if widths.is_empty() {
        return FontMetrics::None;
    }
    let missing_width = font
        .entries()
        .iter()
        .find(|(k, _)| k == "FontDescriptor")
        .and_then(|(_, v)| match v {
            Object::Dict(d) => d
                .entries()
                .iter()
                .find(|(k, _)| k == "MissingWidth")
                .and_then(|(_, v)| number_as_f32(v)),
            _ => None,
        })
        .unwrap_or(0.0);
    // §9.6.5: a Type 3 font's /Widths are in glyph space, scaled into
    // text space by its /FontMatrix horizontal component (matrix `a`).
    // Type1 / TrueType widths are already in thousandths of text space.
    // Other simple fonts default to the 1000-unit em.
    let text_scale = if subtype == Some("Type3") {
        font.entries()
            .iter()
            .find(|(k, _)| k == "FontMatrix")
            .and_then(|(_, v)| match v {
                Object::Array(items) if items.len() == 6 => number_as_f32(&items[0]),
                _ => None,
            })
            .filter(|s| s.is_finite())
            .unwrap_or(0.001)
    } else {
        0.001
    };
    FontMetrics::Simple {
        first_char,
        widths,
        missing_width,
        text_scale,
    }
}

/// Resolve a Type0 font's descendant CIDFont metrics (§9.7.4.3).
///
/// The descendant CIDFont sits in `/DescendantFonts` (a one-element
/// array). Its `/DW` is the default width (default 1000) and `/W` is
/// the per-CID width array. `/W` groups are either `c [w1 w2 … wn]`
/// (consecutive widths starting at CID `c`) or `cfirst clast w` (the
/// single width `w` for every CID in `[cfirst, clast]`).
fn build_cid_metrics(font: &Dict) -> FontMetrics {
    // /Encoding decides the code width. Identity-H/V (the only CMaps
    // the writer emits, and the only ones the walker resolves) are
    // two-byte, CID = code. A non-Identity named CMap or an embedded
    // CMap stream can't be resolved clean-room here, so the safest
    // default is the two-byte Identity assumption.
    let two_byte = true;
    let descendant = font
        .entries()
        .iter()
        .find(|(k, _)| k == "DescendantFonts")
        .and_then(|(_, v)| match v {
            // The document-level resolver flattens the one-element
            // array to the CIDFont dict directly, or leaves it as an
            // array whose first element is the dict.
            Object::Dict(d) => Some(d.clone()),
            Object::Array(items) => items.iter().find_map(|o| match o {
                Object::Dict(d) => Some(d.clone()),
                _ => None,
            }),
            _ => None,
        });
    let Some(cid_font) = descendant else {
        return FontMetrics::Cid {
            default_width: 1000.0,
            ranges: Vec::new(),
            two_byte,
        };
    };
    let default_width = cid_font
        .entries()
        .iter()
        .find(|(k, _)| k == "DW")
        .and_then(|(_, v)| number_as_f32(v))
        .unwrap_or(1000.0);
    let ranges = match cid_font.entries().iter().find(|(k, _)| k == "W") {
        Some((_, Object::Array(items))) => parse_cid_widths(items),
        _ => Vec::new(),
    };
    FontMetrics::Cid {
        default_width,
        ranges,
        two_byte,
    }
}

/// Parse a CIDFont `/W` array (§9.7.4.3) into `(start_cid, widths)`
/// runs. Tolerates malformed groups by skipping forward.
fn parse_cid_widths(items: &[Object]) -> Vec<(i64, Vec<f32>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < items.len() {
        let Some(c) = number_as_i64(&items[i]) else {
            i += 1;
            continue;
        };
        match items.get(i + 1) {
            // `c [w1 w2 … wn]` — explicit per-CID widths.
            Some(Object::Array(ws)) => {
                let run: Vec<f32> = ws.iter().map(|o| number_as_f32(o).unwrap_or(0.0)).collect();
                out.push((c, run));
                i += 2;
            }
            // `cfirst clast w` — one width over a CID range.
            Some(obj) => {
                let clast = number_as_i64(obj);
                let w = items.get(i + 2).and_then(number_as_f32);
                match (clast, w) {
                    (Some(clast), Some(w)) if clast >= c => {
                        let count = (clast - c + 1).min(1 << 20) as usize;
                        out.push((c, vec![w; count]));
                        i += 3;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }
            None => break,
        }
    }
    out
}

/// Multiply a [`Paint`]'s carried alpha by a Table 58 alpha constant
/// (`CA` / `ca`, §11.6.4.4). For `Paint::Solid` the multiplication
/// lands on the `Rgba::a` channel directly; other paint variants
/// (gradients, the writer's pattern shading) pass through unchanged
/// because the round-3 IR has no per-stop alpha field — partial
/// gradient transparency would need a transparency-group XObject
/// hand-off the reader doesn't yet emit.
fn apply_alpha(paint: Paint, alpha: f32) -> Paint {
    if (alpha - 1.0).abs() < f32::EPSILON {
        return paint;
    }
    match paint {
        Paint::Solid(rgba) => {
            let base = rgba.a as f32 / 255.0;
            let combined = (base * alpha).clamp(0.0, 1.0);
            Paint::Solid(Rgba::new(
                rgba.r,
                rgba.g,
                rgba.b,
                (combined * 255.0).round() as u8,
            ))
        }
        other => other,
    }
}

/// Read an [`Object`] as an `f32`, accepting either `Integer` or
/// `Real`. Returns `None` for other variants.
fn number_as_f32(obj: &Object) -> Option<f32> {
    match obj {
        Object::Integer(i) => Some(*i as f32),
        Object::Real(r) => Some(*r as f32),
        _ => None,
    }
}

/// Read an [`Object`] as an `i64`, accepting `Integer` or `Real`
/// (truncating the fractional part — Table 58 `LC` / `LJ` are spec'd
/// as integers but tolerating real-typed encoders matches the
/// "force into valid range" tolerance §8.4 NOTE 1 calls out).
fn number_as_i64(obj: &Object) -> Option<i64> {
    match obj {
        Object::Integer(i) => Some(*i),
        Object::Real(r) => Some(*r as i64),
        _ => None,
    }
}

/// Parse a Table 58 `D` value: `[dashArray dashPhase]` two-element
/// array, where `dashArray` is itself an array of numbers and
/// `dashPhase` is a single integer (treated as a number for parity
/// with the `d` operator).
fn parse_dash_pair(obj: &Object) -> Option<(Vec<f32>, f32)> {
    let Object::Array(items) = obj else {
        return None;
    };
    if items.len() != 2 {
        return None;
    }
    let Object::Array(arr_items) = &items[0] else {
        return None;
    };
    let mut array = Vec::with_capacity(arr_items.len());
    for it in arr_items {
        array.push(number_as_f32(it)?);
    }
    let offset = number_as_f32(&items[1])?;
    Some((array, offset))
}

/// Read a heterogeneous PDF array `[ … ]` starting at the `[` byte.
/// Items may be numbers (the `d` operator's dash-array shape) or
/// strings (the `TJ` operator's mix of `(s) num (s) num`). Other
/// nested values (sub-arrays, dicts, names) inside a content-stream
/// array are not produced by the writer and we don't try to surface
/// them; bytes that aren't whitespace, a number lead, a `(`/`<`, or a
/// `]` are skipped to keep tolerant of hand-laid streams.
fn read_array(input: &[u8], start: usize) -> Result<(usize, Vec<ArrayElem>), PdfError> {
    let mut end = start + 1;
    let mut items: Vec<ArrayElem> = Vec::new();
    while end < input.len() && input[end] != b']' {
        let b = input[end];
        if is_whitespace(b) {
            end += 1;
            continue;
        }
        if b == b'(' {
            let (next, bytes) = read_literal_string(input, end)?;
            items.push(ArrayElem::String(bytes));
            end = next;
            continue;
        }
        if b == b'<' && input.get(end + 1) != Some(&b'<') {
            let (next, bytes) = read_hex_string(input, end)?;
            items.push(ArrayElem::String(bytes));
            end = next;
            continue;
        }
        if matches!(b, b'+' | b'-' | b'.' | b'0'..=b'9') {
            let nstart = end;
            match scan_number(input, nstart) {
                NumScan::Fast(next, f) => {
                    items.push(ArrayElem::Number(f));
                    end = next;
                }
                NumScan::Slow(next) => {
                    // Tolerant: a number `str::parse` rejects is
                    // dropped, matching the historical policy.
                    if let Ok(s) = str::from_utf8(&input[nstart..next]) {
                        if let Ok(f) = s.parse::<f32>() {
                            items.push(ArrayElem::Number(f));
                        }
                    }
                    end = next;
                }
                NumScan::NotANumber => {
                    // Bare sign / dot — historical behaviour consumed
                    // the sign byte(s) scanned so far and dropped
                    // them; re-create that by advancing past the
                    // non-number prefix one byte at a time.
                    end = nstart + 1;
                }
            }
            continue;
        }
        // Tolerant skip for anything else.
        end += 1;
    }
    if end < input.len() {
        end += 1;
    } // skip `]`
    Ok((end, items))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &[u8]) -> Group {
        parse_content_stream(input).unwrap()
    }

    /// `scan_number` must be **bit-identical** to `str::parse::<f32>`
    /// on every byte string the §7.3.3 number grammar admits — that's
    /// the contract that lets the content tokenizer skip the UTF-8 +
    /// general-float-parse round trip.
    #[test]
    fn scan_number_matches_str_parse_bitwise() {
        let mut cases: Vec<String> = vec![
            "0",
            "-0",
            "+0",
            "5",
            "-5",
            "+5",
            "5.",
            "-5.",
            ".5",
            "-.5",
            "+.5",
            "0.5",
            "595.0",
            "842.75",
            "0.0001",
            "-0.0001",
            "123456",
            "-123456",
            "16777215",
            "16777216",
            "16777217",
            "-16777216",
            "999999999",
            "0.1234567890",
            "0.12345678901",
            "3.14159265358979",
            "1000000.25",
            "-1000000.25",
            "0.000000001",
            "99999999999999999999",
            "-99999999999999999999.5",
            "00042",
            "-00042.50",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        // Deterministic generated sweep: every digit count 1..=12 on
        // both sides of the dot, signed and unsigned.
        let mut state = 0x1234_5678u32;
        let mut xs = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        for _ in 0..2000 {
            let int_len = (xs() % 13) as usize;
            let frac_len = (xs() % 13) as usize;
            if int_len == 0 && frac_len == 0 {
                continue;
            }
            let mut s = String::new();
            match xs() % 3 {
                0 => s.push('-'),
                1 => s.push('+'),
                _ => {}
            }
            for _ in 0..int_len {
                s.push(char::from(b'0' + (xs() % 10) as u8));
            }
            if frac_len > 0 {
                s.push('.');
                for _ in 0..frac_len {
                    s.push(char::from(b'0' + (xs() % 10) as u8));
                }
            }
            cases.push(s);
        }
        for case in &cases {
            let bytes = case.as_bytes();
            let expected: f32 = case.parse().unwrap_or_else(|_| panic!("parse {case}"));
            match scan_number(bytes, 0) {
                NumScan::Fast(end, got) => {
                    assert_eq!(end, bytes.len(), "consumed all of `{case}`");
                    assert_eq!(
                        got.to_bits(),
                        expected.to_bits(),
                        "`{case}`: fast {got} vs parse {expected}"
                    );
                }
                NumScan::Slow(end) => {
                    assert_eq!(end, bytes.len(), "consumed all of `{case}`");
                    // Slow path re-parses through str::parse — identical
                    // by construction.
                }
                NumScan::NotANumber => panic!("`{case}` should scan as a number"),
            }
        }
    }

    #[test]
    fn scan_number_rejects_bare_sign_and_dot() {
        for case in [&b"-"[..], b"+", b".", b"-.", b"+.", b"-x", b".)"] {
            assert!(
                matches!(scan_number(case, 0), NumScan::NotANumber),
                "{case:?} must not scan as a number"
            );
        }
    }

    #[test]
    fn scan_number_stops_at_delimiters_and_whitespace() {
        // `]` after a TJ adjustment, space between operands, an
        // operator straight after the digits.
        let input = b"-12.5]";
        match scan_number(input, 0) {
            NumScan::Fast(end, v) => {
                assert_eq!(end, 5);
                assert_eq!(v.to_bits(), (-12.5f32).to_bits());
            }
            _ => panic!("expected fast scan"),
        }
        let input = b"7 0 R";
        match scan_number(input, 0) {
            NumScan::Fast(end, v) => {
                assert_eq!(end, 1);
                assert_eq!(v, 7.0);
            }
            _ => panic!("expected fast scan"),
        }
        // Second dot terminates the number (next token starts at it).
        let input = b"1.2.3";
        match scan_number(input, 0) {
            NumScan::Fast(end, v) => {
                assert_eq!(end, 3);
                assert_eq!(v.to_bits(), (1.2f32).to_bits());
            }
            _ => panic!("expected fast scan"),
        }
    }

    #[test]
    fn empty_content_yields_empty_group() {
        let g = parse(b"");
        assert!(g.children.is_empty());
        assert!(g.clip.is_none());
    }

    #[test]
    fn rect_fill_round_trips() {
        // The writer would emit something like:
        //   q 1 0 0 rg 10 10 m 110 10 l 110 60 l 10 60 l h f Q
        let bytes = b"q 1 0 0 rg 10 10 m 110 10 l 110 60 l 10 60 l h f Q\n";
        let root = parse(bytes);
        // One child group containing the path.
        assert_eq!(root.children.len(), 1);
        let Node::Group(g) = &root.children[0] else {
            panic!("expected group")
        };
        assert_eq!(g.children.len(), 1);
        let Node::Path(pn) = &g.children[0] else {
            panic!("expected path")
        };
        // 4 verts + close = 5 commands.
        assert_eq!(pn.path.commands.len(), 5);
        assert!(matches!(pn.path.commands[0], PathCommand::MoveTo(p) if (p.x - 10.0).abs() < 1e-3));
        assert!(matches!(pn.path.commands[4], PathCommand::Close));
        assert_eq!(pn.fill_rule, FillRule::NonZero);
        // Fill is solid red.
        match &pn.fill {
            Some(Paint::Solid(r)) => assert_eq!((r.r, r.g, r.b), (255, 0, 0)),
            other => panic!("unexpected fill: {other:?}"),
        }
        assert!(pn.stroke.is_none());
    }

    #[test]
    fn nested_q_groups_are_promoted_to_node_groups() {
        let bytes = b"q q 1 0 0 1 5 5 cm 0 0 m 10 10 l S Q Q\n";
        let root = parse(bytes);
        assert_eq!(root.children.len(), 1);
        let Node::Group(outer) = &root.children[0] else {
            panic!()
        };
        assert_eq!(outer.children.len(), 1);
        let Node::Group(inner) = &outer.children[0] else {
            panic!()
        };
        // Inner group has the cm transform.
        assert!(!inner.transform.is_identity());
        assert_eq!(inner.children.len(), 1);
    }

    #[test]
    fn rectangle_operator_re_expands_to_subpath() {
        // 10 20 30 40 re → subpath of M(10,20), L(40,20), L(40,60), L(10,60), h
        let bytes = b"q 0.5 0.5 0.5 rg 10 20 30 40 re f Q\n";
        let root = parse(bytes);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        assert_eq!(p.path.commands.len(), 5);
        assert!(
            matches!(p.path.commands[0], PathCommand::MoveTo(pp) if pp.x == 10.0 && pp.y == 20.0)
        );
        assert!(
            matches!(p.path.commands[1], PathCommand::LineTo(pp) if pp.x == 40.0 && pp.y == 20.0)
        );
        assert!(
            matches!(p.path.commands[2], PathCommand::LineTo(pp) if pp.x == 40.0 && pp.y == 60.0)
        );
        assert!(
            matches!(p.path.commands[3], PathCommand::LineTo(pp) if pp.x == 10.0 && pp.y == 60.0)
        );
        assert!(matches!(p.path.commands[4], PathCommand::Close));
    }

    #[test]
    fn cubic_curve_roundtrips() {
        let bytes = b"q 0 0 m 1 1 2 1 3 0 c S Q\n";
        let root = parse(bytes);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        assert!(matches!(
            p.path.commands[1],
            PathCommand::CubicCurveTo { c1, c2, end }
                if c1.x == 1.0 && c1.y == 1.0 && c2.x == 2.0 && c2.y == 1.0 && end.x == 3.0 && end.y == 0.0
        ));
    }

    #[test]
    fn fill_rule_evenodd_recognised() {
        let bytes = b"q 0 0 m 10 0 l 10 10 l h f* Q\n";
        let root = parse(bytes);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        assert_eq!(p.fill_rule, FillRule::EvenOdd);
    }

    #[test]
    fn cm_translate_lands_on_group_transform() {
        let bytes = b"q 1 0 0 1 100 200 cm 0 0 m 5 5 l S Q\n";
        let root = parse(bytes);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        assert!((g.transform.e - 100.0).abs() < 1e-3);
        assert!((g.transform.f - 200.0).abs() < 1e-3);
    }

    #[test]
    fn stroke_style_w_j_m_d_recorded() {
        let bytes = b"q 2.5 w 1 J 2 j 8 M [5 3] 1 d 0 0 0 RG 0 0 m 10 10 l S Q\n";
        let root = parse(bytes);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        let s = p.stroke.as_ref().expect("stroke set");
        assert!((s.width - 2.5).abs() < 1e-3);
        assert!(matches!(s.cap, LineCap::Round));
        assert!(matches!(s.join, LineJoin::Bevel));
        assert!((s.miter_limit - 8.0).abs() < 1e-3);
        let dash = s.dash.as_ref().expect("dash set");
        assert_eq!(dash.array, vec![5.0, 3.0]);
        assert!((dash.offset - 1.0).abs() < 1e-3);
    }

    #[test]
    fn clip_w_assigns_to_group_clip() {
        // Clip operator: build a path, hit `W`, then `n` to consume.
        let bytes =
            b"q 10 10 m 50 10 l 50 50 l 10 50 l h W n 0 0 0 rg 20 20 m 30 20 l 30 30 l h f Q\n";
        let root = parse(bytes);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        assert!(g.clip.is_some());
        // The triangle painted afterwards lives as a child node.
        assert_eq!(g.children.len(), 1);
    }

    /// §10.3.5 fundamental cases: pure inks convert to their RGB
    /// complements, and pure black yields RGB black.
    #[test]
    fn cmyk_pure_inks_convert_per_10_3_5() {
        // cyan=1 → red=1−min(1,1+0)=0, green=blue=1 → (0,255,255).
        assert_eq!(rgb_from_cmyk(1.0, 0.0, 0.0, 0.0), Rgba::opaque(0, 255, 255));
        // magenta=1 → (255,0,255).
        assert_eq!(rgb_from_cmyk(0.0, 1.0, 0.0, 0.0), Rgba::opaque(255, 0, 255));
        // yellow=1 → (255,255,0).
        assert_eq!(rgb_from_cmyk(0.0, 0.0, 1.0, 0.0), Rgba::opaque(255, 255, 0));
        // black=1 → every channel 1−min(1,0+1)=0 → (0,0,0).
        assert_eq!(rgb_from_cmyk(0.0, 0.0, 0.0, 1.0), Rgba::opaque(0, 0, 0));
        // all zero → white.
        assert_eq!(
            rgb_from_cmyk(0.0, 0.0, 0.0, 0.0),
            Rgba::opaque(255, 255, 255)
        );
    }

    /// The `min(1.0, comp + black)` ceiling caps the sum so an ink
    /// plus black never wraps past full saturation.
    #[test]
    fn cmyk_component_plus_black_clamps_at_one() {
        // cyan=0.7 black=0.7 → red=1−min(1,1.4)=0; green/blue=1−0.7=0.3.
        let r = rgb_from_cmyk(0.7, 0.0, 0.0, 0.7);
        assert_eq!(r.r, 0);
        assert_eq!(r.g, (0.3f32 * 255.0).round() as u8);
        assert_eq!(r.b, (0.3f32 * 255.0).round() as u8);
    }

    /// Out-of-range operands are clamped before the formula (§10.3.4
    /// NOTE 4 nearest-valid-value substitution).
    #[test]
    fn cmyk_out_of_range_operands_clamp() {
        // Negative and >1 operands behave as 0.0 / 1.0.
        assert_eq!(
            rgb_from_cmyk(-0.5, 2.0, 0.0, 0.0),
            rgb_from_cmyk(0.0, 1.0, 0.0, 0.0)
        );
    }

    /// End-to-end through the content parser: `k` sets the fill paint,
    /// `K` sets the stroke paint, both via the §10.3.5 conversion.
    #[test]
    fn k_and_upper_k_operators_apply_cmyk_conversion() {
        // Fill = pure cyan (0,255,255); stroke = pure magenta (255,0,255).
        let bytes = b"q 1 0 0 0 k 0 1 0 0 K 0 0 m 10 10 l 10 0 l h B Q\n";
        let root = parse(bytes);
        let Node::Group(g) = &root.children[0] else {
            panic!("expected group")
        };
        let Node::Path(p) = &g.children[0] else {
            panic!("expected path")
        };
        match &p.fill {
            Some(Paint::Solid(c)) => assert_eq!((c.r, c.g, c.b), (0, 255, 255)),
            other => panic!("unexpected fill: {other:?}"),
        }
        let s = p.stroke.as_ref().expect("stroke set");
        match &s.paint {
            Paint::Solid(c) => assert_eq!((c.r, c.g, c.b), (255, 0, 255)),
            other => panic!("unexpected stroke paint: {other:?}"),
        }
    }

    // ── Colour-space selection: `cs` / `CS` + `sc` / `scn` (round 118) ──

    /// Helper: parse a stream and return the first painted path node.
    fn first_path(bytes: &[u8]) -> PathNode {
        let root = parse(bytes);
        let Node::Group(g) = &root.children[0] else {
            panic!("expected group");
        };
        let Node::Path(p) = &g.children[0] else {
            panic!("expected path");
        };
        p.clone()
    }

    fn fill_rgb(p: &PathNode) -> (u8, u8, u8) {
        match &p.fill {
            Some(Paint::Solid(c)) => (c.r, c.g, c.b),
            other => panic!("unexpected fill: {other:?}"),
        }
    }

    /// `/DeviceRGB cs 1 0 0 sc` selects DeviceRGB then sets a red fill
    /// (§8.6.8). Before round 118 the parser collapsed every `sc` to
    /// black; the spec example `/DeviceRGB CS  red green blue SC`
    /// (§8.6.4.3) is the stroking analogue.
    #[test]
    fn cs_devicergb_then_sc_sets_rgb_fill() {
        let bytes = b"q /DeviceRGB cs 1 0 0 sc 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(fill_rgb(&first_path(bytes)), (255, 0, 0));
    }

    /// `/DeviceGray cs 0.5 sc` — one-component grey (§8.6.4.2).
    #[test]
    fn cs_devicegray_then_sc_sets_gray_fill() {
        let bytes = b"q /DeviceGray cs 0.5 sc 0 0 m 10 10 l 10 0 l h f Q\n";
        let (r, g, b) = fill_rgb(&first_path(bytes));
        let expect = (0.5f32 * 255.0).round() as u8;
        assert_eq!((r, g, b), (expect, expect, expect));
    }

    /// `/DeviceCMYK cs 1 0 0 0 scn` — pure cyan via the §10.3.5
    /// conversion, matching the `1 0 0 0 k` operator's result.
    #[test]
    fn cs_devicecmyk_then_scn_sets_cmyk_fill() {
        let bytes = b"q /DeviceCMYK cs 1 0 0 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(fill_rgb(&first_path(bytes)), (0, 255, 255));
    }

    /// Stroking side: `/DeviceRGB CS 0 1 0 SC` sets a green stroke.
    #[test]
    fn upper_cs_and_upper_sc_set_stroke_color() {
        let bytes = b"q /DeviceRGB CS 0 1 0 SC 0 0 m 10 10 l S Q\n";
        let p = first_path(bytes);
        let s = p.stroke.as_ref().expect("stroke set");
        match &s.paint {
            Paint::Solid(c) => assert_eq!((c.r, c.g, c.b), (0, 255, 0)),
            other => panic!("unexpected stroke paint: {other:?}"),
        }
    }

    /// A `/Pattern cs … /P0 scn` pair carries a `/Name` operand and an
    /// unknown space — the parser keeps the conservative black fallback
    /// rather than misreading the pattern name as colour components.
    #[test]
    fn pattern_scn_keeps_black_fallback() {
        let bytes = b"q /Pattern cs /P0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(fill_rgb(&first_path(bytes)), (0, 0, 0));
    }

    /// Build a `/PatternType 2` (shading-pattern) dict wrapping an axial
    /// shading from `coords` with a black→white function, optionally with
    /// a `/Matrix`.
    fn shading_pattern(coords: [f32; 4], matrix: Option<[f32; 6]>) -> Dict {
        let shading = Dict::new()
            .with("ShadingType", Object::Integer(2))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with(
                "Coords",
                Object::Array(coords.into_iter().map(|n| Object::Real(n as f64)).collect()),
            )
            .with("Function", exp_black_to_white());
        let mut d = Dict::new()
            .with("PatternType", Object::Integer(2))
            .with("Shading", Object::Dict(shading));
        if let Some(m) = matrix {
            d.set(
                "Matrix",
                Object::Array(m.into_iter().map(|n| Object::Real(n as f64)).collect()),
            );
        }
        d
    }

    /// Parse with `/Resources /Pattern` plumbed in, return the first
    /// painted path's fill `Paint`.
    fn first_fill_with_pattern(bytes: &[u8], patterns: &Dict) -> Paint {
        let parsed = parse_content_stream_full_with_patterns(
            bytes,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(patterns),
        )
        .unwrap();
        let Node::Group(g) = &parsed.root.children[0] else {
            panic!("expected group");
        };
        let Node::Path(p) = &g.children[0] else {
            panic!("expected path");
        };
        p.fill.clone().expect("path has a fill")
    }

    /// A `/Pattern cs /P0 scn` fill whose `/P0` is a `/PatternType 2`
    /// axial shading pattern paints a `Paint::LinearGradient`, not the
    /// black fallback. The gradient runs along the shading axis and its
    /// stops sweep black → white.
    #[test]
    fn shading_pattern_axial_paints_linear_gradient() {
        let pat = Dict::new().with(
            "P0",
            Object::Dict(shading_pattern([0.0, 0.0, 100.0, 0.0], None)),
        );
        let bytes = b"q /Pattern cs /P0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        let Paint::LinearGradient(lg) = first_fill_with_pattern(bytes, &pat) else {
            panic!("expected a linear gradient");
        };
        // Identity CTM + no Matrix: axis endpoints pass through verbatim.
        assert!((lg.start.x - 0.0).abs() < 1e-3 && (lg.start.y - 0.0).abs() < 1e-3);
        assert!((lg.end.x - 100.0).abs() < 1e-3 && (lg.end.y - 0.0).abs() < 1e-3);
        assert_eq!(lg.stops.len(), 64);
        assert_eq!((lg.stops[0].color.r, lg.stops[0].color.g), (0, 0));
        let last = lg.stops.last().unwrap();
        assert_eq!((last.color.r, last.color.g, last.color.b), (255, 255, 255));
        // Offsets span 0.0..=1.0 monotonically.
        assert!((lg.stops[0].offset - 0.0).abs() < 1e-6);
        assert!((last.offset - 1.0).abs() < 1e-6);
    }

    /// The pattern's `/Matrix` maps the shading axis into target space:
    /// a translate-by-(50, 20) matrix shifts both endpoints.
    #[test]
    fn shading_pattern_matrix_transforms_axis() {
        let pat = Dict::new().with(
            "P0",
            Object::Dict(shading_pattern(
                [0.0, 0.0, 100.0, 0.0],
                Some([1.0, 0.0, 0.0, 1.0, 50.0, 20.0]),
            )),
        );
        let bytes = b"q /Pattern cs /P0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        let Paint::LinearGradient(lg) = first_fill_with_pattern(bytes, &pat) else {
            panic!("expected a linear gradient");
        };
        assert!((lg.start.x - 50.0).abs() < 1e-3 && (lg.start.y - 20.0).abs() < 1e-3);
        assert!((lg.end.x - 150.0).abs() < 1e-3 && (lg.end.y - 20.0).abs() < 1e-3);
    }

    /// A radial shading pattern paints a `Paint::RadialGradient` whose
    /// outer circle is the shading's ending circle.
    #[test]
    fn shading_pattern_radial_paints_radial_gradient() {
        let shading = Dict::new()
            .with("ShadingType", Object::Integer(3))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with(
                "Coords",
                Object::Array(
                    [10.0, 20.0, 0.0, 10.0, 20.0, 40.0]
                        .into_iter()
                        .map(|n: f64| Object::Real(n))
                        .collect(),
                ),
            )
            .with("Function", exp_black_to_white());
        let pat = Dict::new().with(
            "P0",
            Object::Dict(
                Dict::new()
                    .with("PatternType", Object::Integer(2))
                    .with("Shading", Object::Dict(shading)),
            ),
        );
        let bytes = b"q /Pattern cs /P0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        let Paint::RadialGradient(rg) = first_fill_with_pattern(bytes, &pat) else {
            panic!("expected a radial gradient");
        };
        assert!((rg.center.x - 10.0).abs() < 1e-3 && (rg.center.y - 20.0).abs() < 1e-3);
        assert!((rg.radius - 40.0).abs() < 1e-3);
        assert_eq!(rg.stops.len(), 64);
    }

    /// A `/PatternType 1` (tiling) pattern has no scene-gradient analogue
    /// this round — the fill stays the black fallback.
    #[test]
    fn tiling_pattern_keeps_black_fallback() {
        let pat = Dict::new().with(
            "P0",
            Object::Dict(Dict::new().with("PatternType", Object::Integer(1))),
        );
        let bytes = b"q /Pattern cs /P0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        match first_fill_with_pattern(bytes, &pat) {
            Paint::Solid(c) => assert_eq!((c.r, c.g, c.b), (0, 0, 0)),
            other => panic!("expected black solid fallback, got {other:?}"),
        }
    }

    /// A `cs` naming an unresolved `/Resources /ColorSpace` key (here a
    /// CIE-based `/CS0`) is `Unknown`: a following `sc` can't be
    /// interpreted without the resource definition, so the fill stays
    /// black.
    #[test]
    fn unknown_resource_colorspace_sc_keeps_black_fallback() {
        let bytes = b"q /CS0 cs 0.2 0.4 0.6 sc 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(fill_rgb(&first_path(bytes)), (0, 0, 0));
    }

    /// Setting a device colour space with a bare `cs` (no following
    /// `sc`) initialises the colour to black per §8.6.4.2..4.
    #[test]
    fn bare_cs_initialises_color_to_black() {
        let bytes = b"q /DeviceRGB cs 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(fill_rgb(&first_path(bytes)), (0, 0, 0));
    }

    /// `sc`/`scn` interpret operands in whatever the *last* `cs`
    /// selected — switching spaces mid-stream re-routes the next colour.
    #[test]
    fn switching_colorspace_reroutes_following_sc() {
        let bytes = b"q /DeviceGray cs 1 sc /DeviceRGB cs 0 0 1 sc \
                      0 0 m 10 10 l 10 0 l h f Q\n";
        // Final colour is the DeviceRGB blue, not the grey white.
        assert_eq!(fill_rgb(&first_path(bytes)), (0, 0, 255));
    }

    /// `from_name` maps the three device families (long + abbreviated
    /// inline-image spellings) and routes everything else to `Unknown`.
    #[test]
    fn color_space_from_name_table() {
        assert_eq!(
            ColorSpaceKind::from_name("DeviceGray"),
            ColorSpaceKind::DeviceGray
        );
        assert_eq!(ColorSpaceKind::from_name("G"), ColorSpaceKind::DeviceGray);
        assert_eq!(
            ColorSpaceKind::from_name("DeviceRGB"),
            ColorSpaceKind::DeviceRgb
        );
        assert_eq!(ColorSpaceKind::from_name("RGB"), ColorSpaceKind::DeviceRgb);
        assert_eq!(
            ColorSpaceKind::from_name("DeviceCMYK"),
            ColorSpaceKind::DeviceCmyk
        );
        assert_eq!(
            ColorSpaceKind::from_name("CMYK"),
            ColorSpaceKind::DeviceCmyk
        );
        assert_eq!(
            ColorSpaceKind::from_name("Pattern"),
            ColorSpaceKind::Unknown
        );
        assert_eq!(ColorSpaceKind::from_name("CS0"), ColorSpaceKind::Unknown);
    }

    // ── Resource colour-space resolution (round 275) ──────────────

    /// Helper: parse with a `/Resources /ColorSpace` dict plumbed in,
    /// return the first painted path's fill RGB.
    fn first_fill_with_cs(bytes: &[u8], cs: &Dict) -> (u8, u8, u8) {
        let parsed =
            parse_content_stream_full_with_color_space(bytes, None, None, None, Some(cs)).unwrap();
        let Node::Group(g) = &parsed.root.children[0] else {
            panic!("expected group");
        };
        let Node::Path(p) = &g.children[0] else {
            panic!("expected path");
        };
        match &p.fill {
            Some(Paint::Solid(c)) => (c.r, c.g, c.b),
            other => panic!("unexpected fill: {other:?}"),
        }
    }

    /// `[ /ICCBased << /N 3 >> ]` with no `/Alternate` reduces to
    /// DeviceRGB per §8.6.5.5; a following `sc` reads three components.
    #[test]
    fn icc_based_n3_resolves_devicergb() {
        let arr = Object::Array(vec![
            Object::Name("ICCBased".into()),
            Object::Dict(Dict::new().with("N", Object::Integer(3))),
        ]);
        assert_eq!(color_space_from_object(&arr), ColorSpaceKind::DeviceRgb);

        let cs = Dict::new().with("CS0", arr);
        let bytes = b"q /CS0 cs 1 0 0 sc 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 0, 0));
    }

    /// `/N 1` → DeviceGray, `/N 4` → DeviceCMYK (§8.6.5.5 fallback).
    #[test]
    fn icc_based_n1_and_n4_resolve_gray_and_cmyk() {
        let gray = Object::Array(vec![
            Object::Name("ICCBased".into()),
            Object::Dict(Dict::new().with("N", Object::Integer(1))),
        ]);
        assert_eq!(color_space_from_object(&gray), ColorSpaceKind::DeviceGray);
        let cmyk = Object::Array(vec![
            Object::Name("ICCBased".into()),
            Object::Dict(Dict::new().with("N", Object::Integer(4))),
        ]);
        assert_eq!(color_space_from_object(&cmyk), ColorSpaceKind::DeviceCmyk);

        // End-to-end: N=4 CMYK pure cyan → (0,255,255).
        let cs = Dict::new().with("CS0", cmyk);
        let bytes = b"q /CS0 cs 1 0 0 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 255, 255));
    }

    /// `/Alternate` overrides the `/N` fallback when present and
    /// reducible (§8.6.5.5 — "an alternate colour space that shall be
    /// used in case the one specified in the stream data is not
    /// supported").
    #[test]
    fn icc_based_alternate_wins_over_n() {
        // N says 3 but /Alternate names DeviceCMYK (a deliberately
        // mismatched fixture to prove the Alternate path is taken).
        let arr = Object::Array(vec![
            Object::Name("ICCBased".into()),
            Object::Dict(
                Dict::new()
                    .with("N", Object::Integer(3))
                    .with("Alternate", Object::Name("DeviceCMYK".into())),
            ),
        ]);
        assert_eq!(color_space_from_object(&arr), ColorSpaceKind::DeviceCmyk);
    }

    /// An ICCBased dict with no `/N` and no reducible `/Alternate`
    /// stays `Unknown` (the round-118 black fallback).
    #[test]
    fn icc_based_without_n_is_unknown() {
        let arr = Object::Array(vec![
            Object::Name("ICCBased".into()),
            Object::Dict(Dict::new()),
        ]);
        assert_eq!(color_space_from_object(&arr), ColorSpaceKind::Unknown);
    }

    /// `[ /Indexed /DeviceRGB 2 <000000 FF0000 00FF00> ]` — the
    /// §8.6.6.3 Example 1 shape. `1 sc` selects entry 1 (red).
    #[test]
    fn indexed_devicergb_index_selects_table_entry() {
        // hival 2 → 3 entries × 3 bytes = 9 bytes.
        let table = vec![
            0x00, 0x00, 0x00, // entry 0 = black
            0xFF, 0x00, 0x00, // entry 1 = red
            0x00, 0xFF, 0x00, // entry 2 = green
        ];
        let arr = Object::Array(vec![
            Object::Name("Indexed".into()),
            Object::Name("DeviceRGB".into()),
            Object::Integer(2),
            Object::HexString(table),
        ]);
        let cs = Dict::new().with("CS0", arr);

        // index 1 → red.
        let bytes = b"q /CS0 cs 1 sc 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 0, 0));
    }

    /// Bare `cs` to an Indexed space initialises the colour to table
    /// entry 0 per §8.6.6.3 ("shall initialize the corresponding
    /// current colour to 0").
    #[test]
    fn indexed_bare_cs_uses_entry_zero() {
        let table = vec![0x10, 0x20, 0x30, 0xFF, 0xFF, 0xFF];
        let arr = Object::Array(vec![
            Object::Name("Indexed".into()),
            Object::Name("DeviceRGB".into()),
            Object::Integer(1),
            Object::HexString(table),
        ]);
        let cs = Dict::new().with("CS0", arr);
        // No `sc` — bare `cs` should leave the entry-0 colour in force.
        let bytes = b"q /CS0 cs 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0x10, 0x20, 0x30));
    }

    /// An out-of-range index is clamped to `0..=hival` and a fractional
    /// index rounds to nearest (§8.6.6.3).
    #[test]
    fn indexed_index_rounds_and_clamps() {
        let table = vec![
            0x00, 0x00, 0x00, // 0
            0x40, 0x40, 0x40, // 1
            0x80, 0x80, 0x80, // 2
        ];
        let mk = |arr| Dict::new().with("CS0", arr);
        let arr = || {
            Object::Array(vec![
                Object::Name("Indexed".into()),
                Object::Name("DeviceRGB".into()),
                Object::Integer(2),
                Object::HexString(table.clone()),
            ])
        };
        // 1.6 rounds to 2 → 0x80.
        let bytes = b"q /CS0 cs 1.6 sc 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &mk(arr())), (0x80, 0x80, 0x80));
        // 9 clamps to hival=2 → 0x80.
        let bytes = b"q /CS0 cs 9 sc 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &mk(arr())), (0x80, 0x80, 0x80));
        // -3 clamps to 0 → black.
        let bytes = b"q /CS0 cs -3 sc 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &mk(arr())), (0x00, 0x00, 0x00));
    }

    /// An Indexed base that doesn't reduce to a device family (here a
    /// CIE-based `/Lab`) stays `Unknown` — no table lookup is possible.
    #[test]
    fn indexed_nondevice_base_is_unknown() {
        let arr = Object::Array(vec![
            Object::Name("Indexed".into()),
            Object::Name("Lab".into()),
            Object::Integer(1),
            Object::HexString(vec![0, 0, 0, 1, 1, 1]),
        ]);
        assert_eq!(color_space_from_object(&arr), ColorSpaceKind::Unknown);
    }

    /// A truncated Indexed table (too short for the selected entry)
    /// produces no colour, so the prior colour is retained — here the
    /// entry-0 colour the bare `cs` initialised — rather than reading
    /// past the buffer. `indexed_color` returns `None` for the missing
    /// slot.
    #[test]
    fn indexed_truncated_table_returns_none_for_missing_slot() {
        // hival 2 declared but only entry 0 (black) is present.
        let table = vec![0x00, 0x00, 0x00];
        let base = ColorSpaceKind::DeviceRgb;
        // Entry 0 resolves.
        assert!(indexed_color(&base, 2, &table, 0.0).is_some());
        // Entry 2 is past the buffer → None (no out-of-bounds read).
        assert!(indexed_color(&base, 2, &table, 2.0).is_none());

        // End-to-end: bare `cs` sets entry 0 (black); the truncated
        // `2 sc` returns None so the fill stays the entry-0 black.
        let arr = Object::Array(vec![
            Object::Name("Indexed".into()),
            Object::Name("DeviceRGB".into()),
            Object::Integer(2),
            Object::HexString(table),
        ]);
        let cs = Dict::new().with("CS0", arr);
        let bytes = b"q /CS0 cs 2 sc 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 0, 0));
    }

    /// A device family name in `cs` still resolves directly even when a
    /// `/Resources /ColorSpace` dict is present (a resource key cannot
    /// shadow a device family per §8.6.8 Table 74).
    #[test]
    fn device_name_resolves_without_consulting_resources() {
        let cs = Dict::new().with("DeviceRGB", Object::Name("DeviceGray".into()));
        let bytes = b"q /DeviceRGB cs 1 0 0 sc 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 0, 0));
    }

    /// Without a plumbed-in `/ColorSpace` dict, a resource key stays
    /// `Unknown` (round-118 behaviour preserved).
    #[test]
    fn resource_key_without_resources_stays_unknown() {
        assert_eq!(
            ColorSpaceKind::resolve_with_resources("CS0", None),
            ColorSpaceKind::Unknown
        );
    }

    // ── PDF functions §7.10 + Separation colour space §8.6.6.4 ──

    fn num_arr(vals: &[f32]) -> Object {
        Object::Array(vals.iter().map(|v| Object::Real(*v as f64)).collect())
    }

    /// A Type 2 exponential dict (§7.10.3): `f(x)=C0+x^N·(C1−C0)`.
    fn type2(c0: &[f32], c1: &[f32], n: f32) -> Object {
        Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(2))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with("C0", num_arr(c0))
                .with("C1", num_arr(c1))
                .with("N", Object::Real(n as f64)),
        )
    }

    /// `f(x)=C0+x^N·(C1−C0)` at x=0 is C0, at x=1 is C1, and at the
    /// midpoint for N=1 it is the average (§7.10.3 Table 40).
    #[test]
    fn type2_exponential_interpolates() {
        let f = PdfFunction::parse(&type2(&[0.0, 0.0, 0.0, 0.0], &[1.0, 0.0, 0.0, 0.0], 1.0))
            .expect("type 2 parses");
        assert_eq!(f.eval(0.0), vec![0.0, 0.0, 0.0, 0.0]);
        assert_eq!(f.eval(1.0), vec![1.0, 0.0, 0.0, 0.0]);
        assert_eq!(f.eval(0.5), vec![0.5, 0.0, 0.0, 0.0]);
    }

    /// N=2 makes the interpolation quadratic in x: at x=0.5, x^N=0.25.
    #[test]
    fn type2_exponent_two_is_quadratic() {
        let f = PdfFunction::parse(&type2(&[0.0], &[1.0], 2.0)).expect("parses");
        assert!((f.eval(0.5)[0] - 0.25).abs() < 1e-6);
    }

    /// `/Range` clips each output into `[Range_2j, Range_2j+1]`
    /// (§7.10.1): a C1 of 2.0 with Range `[0 1]` clips to 1.0 at x=1.
    #[test]
    fn type2_range_clips_output() {
        let dict = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(2))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with("Range", num_arr(&[0.0, 1.0]))
                .with("C0", num_arr(&[0.0]))
                .with("C1", num_arr(&[2.0]))
                .with("N", Object::Integer(1)),
        );
        let f = PdfFunction::parse(&dict).expect("parses");
        assert_eq!(f.eval(1.0), vec![1.0]);
    }

    /// A Type 3 stitching function (§7.10.4): two Type 2 children split
    /// at Bounds=0.5, each Encode'd onto `[0 1]`. The §7.10.4 EXAMPLE
    /// `g(x)=f(1−x)` shape (Encode `[1 0]`) is exercised on the first
    /// child to prove the per-subdomain input remap.
    #[test]
    fn type3_stitching_routes_to_subdomain() {
        // child 0: f0(x)=x (C0=0,C1=1,N=1); child 1: f1(x)=1−x via
        // C0=1,C1=0. Bounds [0.5], Encode [0 1 0 1] (identity remap).
        let dict = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(3))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with(
                    "Functions",
                    Object::Array(vec![type2(&[0.0], &[1.0], 1.0), type2(&[1.0], &[0.0], 1.0)]),
                )
                .with("Bounds", num_arr(&[0.5]))
                .with("Encode", num_arr(&[0.0, 1.0, 0.0, 1.0])),
        );
        let f = PdfFunction::parse(&dict).expect("type 3 parses");
        // x=0.25 → subdomain 0, remapped onto [0,1]: Interpolate(0.25,
        // 0, 0.5, 0, 1) = 0.5 → f0(0.5)=0.5.
        assert!((f.eval(0.25)[0] - 0.5).abs() < 1e-6);
        // x=0.75 → subdomain 1, Interpolate(0.75, 0.5, 1, 0, 1)=0.5 →
        // f1(0.5)=0.5.
        assert!((f.eval(0.75)[0] - 0.5).abs() < 1e-6);
        // x=1.0 (last subdomain, closed on the right) → f1(1.0)=0.0.
        assert!(f.eval(1.0)[0].abs() < 1e-6);
    }

    /// A Type 0 dictionary stripped of its sample body (`__Samples`)
    /// and a Type 4 dictionary stripped of its program body
    /// (`__Program`) are not evaluable here — `parse` returns `None`.
    #[test]
    fn type0_without_samples_and_type4_without_program_are_not_evaluable() {
        let t0 = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with("Range", num_arr(&[0.0, 1.0]))
                .with("Size", num_arr(&[2.0]))
                .with("BitsPerSample", Object::Integer(8)),
        );
        // No __Samples entry → parse cannot reach the sample table.
        assert!(PdfFunction::parse(&t0).is_none());
        // A Type 4 with Domain + Range but no folded program body cannot
        // be tokenised, so it is not evaluable.
        let t4 = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(4))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with("Range", num_arr(&[0.0, 1.0])),
        );
        assert!(PdfFunction::parse(&t4).is_none());
    }

    /// Build a self-contained Type 0 sampled function dictionary with an
    /// 8-bit, single-input, single-output sample table whose decoded
    /// body lives under `__Samples` (the shape `prepare_function_object`
    /// produces). `codes` are the raw 0..=255 sample codes in input
    /// order.
    fn type0_8bit(domain: &[f32], range: &[f32], codes: &[u8]) -> Object {
        Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(domain))
                .with("Range", num_arr(range))
                .with("Size", num_arr(&[codes.len() as f32]))
                .with("BitsPerSample", Object::Integer(8))
                .with("__Samples", Object::HexString(codes.to_vec())),
        )
    }

    /// §7.10.2: an 8-bit two-sample identity table over `[0,1] → [0,1]`
    /// evaluates by linear interpolation between the endpoints, and the
    /// endpoints decode exactly (0 → 0.0, 255 → 1.0).
    #[test]
    fn type0_8bit_linear_identity() {
        let f = PdfFunction::parse(&type0_8bit(&[0.0, 1.0], &[0.0, 1.0], &[0, 255]))
            .expect("type0 parses");
        assert!((f.eval(0.0)[0] - 0.0).abs() < 1e-6);
        assert!((f.eval(1.0)[0] - 1.0).abs() < 1e-6);
        // Midpoint: e = Interpolate(0.5, 0,1, 0, 1) = 0.5, blend of the
        // two codes (0.0 and 1.0) → 0.5.
        assert!((f.eval(0.5)[0] - 0.5).abs() < 1e-6);
    }

    /// §7.10.2 Decode: a non-default `/Decode` remaps the [0,1] sample
    /// codes into the output range. With Decode [0 10] the 255 code
    /// decodes to 10.0, the 0 code to 0.0, midpoint 5.0.
    #[test]
    fn type0_decode_remaps_outputs() {
        let f = PdfFunction::parse(&Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with("Range", num_arr(&[0.0, 10.0]))
                .with("Size", num_arr(&[2.0]))
                .with("BitsPerSample", Object::Integer(8))
                .with("Decode", num_arr(&[0.0, 10.0]))
                .with("__Samples", Object::HexString(vec![0, 255])),
        ))
        .expect("type0 parses");
        assert!((f.eval(0.0)[0] - 0.0).abs() < 1e-5);
        assert!((f.eval(1.0)[0] - 10.0).abs() < 1e-5);
        assert!((f.eval(0.5)[0] - 5.0).abs() < 1e-5);
    }

    /// §7.10.2 multi-output: a single-sample (Size 1) table with two
    /// outputs maps every input to the lone sample, decoded per output.
    #[test]
    fn type0_single_sample_multi_output() {
        let f = PdfFunction::parse(&Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with("Range", num_arr(&[0.0, 1.0, 0.0, 1.0]))
                .with("Size", num_arr(&[1.0]))
                .with("BitsPerSample", Object::Integer(8))
                // one input index, two outputs: codes 255, 0.
                .with("__Samples", Object::HexString(vec![255, 0])),
        ))
        .expect("type0 parses");
        let out = f.eval(0.42);
        assert_eq!(out.len(), 2);
        assert!((out[0] - 1.0).abs() < 1e-5);
        assert!((out[1] - 0.0).abs() < 1e-5);
    }

    /// §7.10.2 1-bit packing: a 4-sample 1-bit table reads the
    /// high-order bit of the byte first (codes 1,0,1,0 → 0x A0 = 1010
    /// 0000) and interpolates between adjacent samples.
    #[test]
    fn type0_1bit_packing_msb_first() {
        let f = PdfFunction::parse(&Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with("Range", num_arr(&[0.0, 1.0]))
                .with("Size", num_arr(&[4.0]))
                .with("BitsPerSample", Object::Integer(1))
                .with("Encode", num_arr(&[0.0, 3.0]))
                .with("__Samples", Object::HexString(vec![0b1010_0000])),
        ))
        .expect("type0 parses");
        // index 0 → code 1 → 1.0; index 1 → code 0 → 0.0; index 2 → 1.0.
        assert!((f.eval(0.0)[0] - 1.0).abs() < 1e-6);
        assert!((f.eval(1.0 / 3.0)[0] - 0.0).abs() < 1e-5);
        assert!((f.eval(2.0 / 3.0)[0] - 1.0).abs() < 1e-5);
    }

    /// §7.10.2 with two input dimensions: bilinear interpolation over a
    /// 2×2 sample grid. Samples are stored first-dimension-fastest:
    /// f(0,0)=0, f(1,0)=255, f(0,1)=128, f(1,1)=64 (raw 8-bit codes,
    /// normalised by 255 before Decode = Range = [0,1]). The corners must
    /// reproduce exactly; the centre is the average of all four.
    #[test]
    fn type0_bilinear_2x2_grid() {
        let t0 = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(&[0.0, 1.0, 0.0, 1.0]))
                .with("Range", num_arr(&[0.0, 1.0]))
                .with("Size", num_arr(&[2.0, 2.0]))
                .with("BitsPerSample", Object::Integer(8))
                .with("__Samples", Object::HexString(vec![0, 255, 128, 64])),
        );
        let f = PdfFunction::parse(&t0).expect("2-input type0 parses");
        // Corners are exact.
        assert!((f.eval_n(&[0.0, 0.0])[0] - 0.0).abs() < 1e-6);
        assert!((f.eval_n(&[1.0, 0.0])[0] - 1.0).abs() < 1e-6);
        assert!((f.eval_n(&[0.0, 1.0])[0] - 128.0 / 255.0).abs() < 1e-6);
        assert!((f.eval_n(&[1.0, 1.0])[0] - 64.0 / 255.0).abs() < 1e-6);
        // Centre = mean of the four corners.
        let mean = (0.0 + 255.0 + 128.0 + 64.0) / 4.0 / 255.0;
        assert!((f.eval_n(&[0.5, 0.5])[0] - mean).abs() < 1e-6);
        // Midpoint of the bottom edge = mean of f(0,0) and f(1,0).
        assert!((f.eval_n(&[0.5, 0.0])[0] - 0.5).abs() < 1e-6);
    }

    /// §7.10.2 Order-3 (cubic spline) is accepted and carried through to
    /// evaluation. The interpolant must pass through the sample knots
    /// (it interpolates, not approximates) — at integer encoded
    /// positions the result equals the corresponding sample exactly.
    #[test]
    fn type0_order_3_passes_through_knots() {
        // 4 samples on [0,3]; Encode maps Domain [0,3] → table [0,3].
        let t0 = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(&[0.0, 3.0]))
                .with("Range", num_arr(&[0.0, 1.0]))
                .with("Size", num_arr(&[4.0]))
                .with("BitsPerSample", Object::Integer(8))
                .with("Order", Object::Integer(3))
                .with("__Samples", Object::HexString(vec![0, 85, 170, 255])),
        );
        let f = PdfFunction::parse(&t0).expect("order-3 sampled function parses");
        let expect = [0.0, 85.0 / 255.0, 170.0 / 255.0, 1.0];
        for (k, &e) in expect.iter().enumerate() {
            let got = f.eval_n(&[k as f32])[0];
            assert!((got - e).abs() < 1e-6, "knot {k}: got {got}, want {e}");
        }
    }

    /// §7.10.2 cubic-spline weights sum to 1 for every fractional
    /// position, so a constant sample table reproduces that constant
    /// everywhere (no overshoot for a flat curve).
    #[test]
    fn type0_order_3_constant_table_is_flat() {
        let t0 = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(&[0.0, 3.0]))
                .with("Range", num_arr(&[0.0, 1.0]))
                .with("Size", num_arr(&[4.0]))
                .with("BitsPerSample", Object::Integer(8))
                .with("Order", Object::Integer(3))
                .with("__Samples", Object::HexString(vec![128, 128, 128, 128])),
        );
        let f = PdfFunction::parse(&t0).expect("parses");
        for &x in &[0.0f32, 0.3, 1.0, 1.7, 2.5, 3.0] {
            let got = f.eval_n(&[x])[0];
            assert!((got - 128.0 / 255.0).abs() < 1e-6, "x={x}: got {got}");
        }
    }

    /// §7.10.2: a `/Size` below 4 cannot carry a cubic window, so
    /// `/Order 3` is ignored on that axis and the function interpolates
    /// linearly. With 2 samples 0 and 255, the midpoint is exactly 0.5.
    #[test]
    fn type0_order_3_falls_back_to_linear_below_size_4() {
        let t0 = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with("Range", num_arr(&[0.0, 1.0]))
                .with("Size", num_arr(&[2.0]))
                .with("BitsPerSample", Object::Integer(8))
                .with("Order", Object::Integer(3))
                .with("__Samples", Object::HexString(vec![0, 255])),
        );
        let f = PdfFunction::parse(&t0).expect("parses");
        assert!((f.eval_n(&[0.5])[0] - 0.5).abs() < 1e-6);
        assert!((f.eval_n(&[0.0])[0] - 0.0).abs() < 1e-6);
        assert!((f.eval_n(&[1.0])[0] - 1.0).abs() < 1e-6);
    }

    /// A malformed `/Order` (neither 1 nor 3) leaves the function
    /// unevaluable, per §7.10.2 Table 39 ("Valid values shall be 1 and
    /// 3").
    #[test]
    fn type0_invalid_order_is_rejected() {
        let t0 = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with("Range", num_arr(&[0.0, 1.0]))
                .with("Size", num_arr(&[4.0]))
                .with("BitsPerSample", Object::Integer(8))
                .with("Order", Object::Integer(2))
                .with("__Samples", Object::HexString(vec![0, 85, 170, 255])),
        );
        assert!(PdfFunction::parse(&t0).is_none());
    }

    /// Order-1 (linear) remains the default and is unaffected by the
    /// cubic path: a 4-sample ramp interpolates linearly at the
    /// midpoints when no `/Order` is given.
    #[test]
    fn type0_default_order_is_linear() {
        let t0 = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(&[0.0, 3.0]))
                .with("Range", num_arr(&[0.0, 1.0]))
                .with("Size", num_arr(&[4.0]))
                .with("BitsPerSample", Object::Integer(8))
                .with("__Samples", Object::HexString(vec![0, 85, 170, 255])),
        );
        let f = PdfFunction::parse(&t0).expect("parses");
        // Linear midpoint between samples 1 and 2 (85 and 170).
        let mid = (85.0 + 170.0) / 2.0 / 255.0;
        assert!((f.eval_n(&[1.5])[0] - mid).abs() < 1e-6);
    }

    // ── Type 4 PostScript-calculator functions §7.10.5 ──────────────

    /// Build a self-contained Type 4 function dictionary: the program
    /// `src` (including its outer braces) is folded into `__Program` the
    /// same way `prepare_function_object` does for a real stream.
    fn type4(domain: &[f32], range: &[f32], src: &str) -> Object {
        Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(4))
                .with("Domain", num_arr(domain))
                .with("Range", num_arr(range))
                .with("__Program", Object::HexString(src.as_bytes().to_vec())),
        )
    }

    /// An empty program `{ }` leaves the single seeded input untouched —
    /// the simplest exercise of the whole pipeline (fold → parse →
    /// tokenise → exec → clip) for a 1-input call site (§7.10.5).
    #[test]
    fn type4_identity_program() {
        let f = PdfFunction::parse(&type4(&[0.0, 1.0], &[0.0, 1.0], "{ }"))
            .expect("type4 identity parses");
        // Empty program leaves the seeded input on the stack.
        assert!((f.eval(0.25)[0] - 0.25).abs() < 1e-6);
        assert!((f.eval(0.9)[0] - 0.9).abs() < 1e-6);
    }

    /// Arithmetic operators (§B.2): `{ 2 mul }` doubles the input,
    /// clipped to Range.
    #[test]
    fn type4_arithmetic_mul_and_range_clip() {
        let f = PdfFunction::parse(&type4(&[0.0, 1.0], &[0.0, 1.0], "{ 2 mul }")).expect("parses");
        assert!((f.eval(0.25)[0] - 0.5).abs() < 1e-6);
        // 2·0.8 = 1.6 clips to the Range ceiling 1.0.
        assert!((f.eval(0.8)[0] - 1.0).abs() < 1e-6);
    }

    /// `{ 1 exch sub }` computes 1 − x (the canonical invert tint
    /// transform), exercising `exch` (§B.5) + `sub` (§B.2).
    #[test]
    fn type4_invert_with_exch_sub() {
        let f =
            PdfFunction::parse(&type4(&[0.0, 1.0], &[0.0, 1.0], "{ 1 exch sub }")).expect("parses");
        assert!((f.eval(0.0)[0] - 1.0).abs() < 1e-6);
        assert!((f.eval(1.0)[0] - 0.0).abs() < 1e-6);
        assert!((f.eval(0.3)[0] - 0.7).abs() < 1e-6);
    }

    /// `dup` (§B.5) duplicates the input so a 1-in program can emit two
    /// outputs (here `{ dup }` → a 2-component DeviceGray-pair Range).
    #[test]
    fn type4_dup_emits_two_outputs() {
        let f = PdfFunction::parse(&type4(&[0.0, 1.0], &[0.0, 1.0, 0.0, 1.0], "{ dup }"))
            .expect("parses");
        let out = f.eval(0.4);
        assert_eq!(out.len(), 2);
        assert!((out[0] - 0.4).abs() < 1e-6);
        assert!((out[1] - 0.4).abs() < 1e-6);
    }

    /// Conditional `ifelse` (§B.4): a threshold function emitting 0 below
    /// 0.5 and 1 at/above it.
    #[test]
    fn type4_ifelse_threshold() {
        let f = PdfFunction::parse(&type4(
            &[0.0, 1.0],
            &[0.0, 1.0],
            "{ 0.5 ge { 1 } { 0 } ifelse }",
        ))
        .expect("parses");
        assert!((f.eval(0.2)[0] - 0.0).abs() < 1e-6);
        assert!((f.eval(0.5)[0] - 1.0).abs() < 1e-6);
        assert!((f.eval(0.9)[0] - 1.0).abs() < 1e-6);
    }

    /// Single-branch `if` (§B.4): clamp negatives — `{ dup 0 lt { pop 0 }
    /// if }` leaves the input unless it is below 0, where it is replaced
    /// by 0. (Domain already clips to ≥0 here, so the branch is the
    /// false path and the value passes through.)
    #[test]
    fn type4_single_branch_if() {
        let f = PdfFunction::parse(&type4(
            &[0.0, 1.0],
            &[0.0, 1.0],
            "{ dup 0 lt { pop 0 } if }",
        ))
        .expect("parses");
        assert!((f.eval(0.6)[0] - 0.6).abs() < 1e-6);
    }

    /// `roll` (§B.5): `{ 3 1 roll }` rotates the top three elements up by
    /// one. Seed three inputs via `dup`s, then verify the rotation order.
    #[test]
    fn type4_roll_rotates_stack() {
        // Program: push 10, push 20 (now stack: x 10 20), then 3 1 roll.
        // Per §B.5 with n=3,j=1 the input [x,10,20] becomes [20,x,10].
        let f = PdfFunction::parse(&type4(
            &[0.0, 100.0],
            &[0.0, 100.0, 0.0, 100.0, 0.0, 100.0],
            "{ 10 20 3 1 roll }",
        ))
        .expect("parses");
        let out = f.eval(5.0);
        assert_eq!(out.len(), 3);
        assert_eq!((out[0], out[1], out[2]), (20.0, 5.0, 10.0));
    }

    /// `index` (§B.5): `{ 0 index }` duplicates the top element (n=0).
    #[test]
    fn type4_index_copies_nth() {
        let f = PdfFunction::parse(&type4(&[0.0, 1.0], &[0.0, 1.0, 0.0, 1.0], "{ 0 index }"))
            .expect("parses");
        let out = f.eval(0.7);
        assert_eq!(out.len(), 2);
        assert!((out[0] - 0.7).abs() < 1e-6 && (out[1] - 0.7).abs() < 1e-6);
    }

    /// Boolean / relational chain: `{ 0.5 gt { 1 } { 0 } ifelse }` plus
    /// a `not` round-trip through the boolean path.
    #[test]
    fn type4_boolean_not_and_relational() {
        let f = PdfFunction::parse(&type4(
            &[0.0, 1.0],
            &[0.0, 1.0],
            "{ 0.5 gt not { 0 } { 1 } ifelse }",
        ))
        .expect("parses");
        // x=0.9 > 0.5 ⇒ true, not ⇒ false ⇒ second branch ⇒ 1.
        assert!((f.eval(0.9)[0] - 1.0).abs() < 1e-6);
        // x=0.2 > 0.5 ⇒ false, not ⇒ true ⇒ first branch ⇒ 0.
        assert!((f.eval(0.2)[0] - 0.0).abs() < 1e-6);
    }

    /// An execution error (here division by zero, §7.10.5.2) yields the
    /// conservative black fallback (all-zero output of Range's arity).
    #[test]
    fn type4_division_by_zero_falls_back_to_black() {
        let f = PdfFunction::parse(&type4(&[0.0, 1.0], &[0.0, 1.0], "{ 0 div }")).expect("parses");
        assert_eq!(f.eval(0.5), vec![0.0]);
    }

    /// A program whose leftover-operand count differs from Range's arity
    /// is an error (§7.10.5): black fallback rather than a wrong colour.
    #[test]
    fn type4_output_arity_mismatch_falls_back() {
        // `{ pop }` leaves zero operands but Range wants one.
        let f = PdfFunction::parse(&type4(&[0.0, 1.0], &[0.0, 1.0], "{ pop }")).expect("parses");
        assert_eq!(f.eval(0.5), vec![0.0]);
    }

    /// Syntax errors (§7.10.5.2) make `parse` reject the function:
    /// unbalanced braces, missing outer braces, and unknown tokens.
    #[test]
    fn type4_syntax_errors_reject() {
        // Missing outer braces.
        assert!(PdfFunction::parse(&type4(&[0.0, 1.0], &[0.0, 1.0], "2 mul")).is_none());
        // Unbalanced (unterminated) brace.
        assert!(PdfFunction::parse(&type4(&[0.0, 1.0], &[0.0, 1.0], "{ 2 mul")).is_none());
        // Trailing tokens after the outer block close.
        assert!(PdfFunction::parse(&type4(&[0.0, 1.0], &[0.0, 1.0], "{ } 3")).is_none());
        // Unknown operator token.
        assert!(PdfFunction::parse(&type4(&[0.0, 1.0], &[0.0, 1.0], "{ frobnicate }")).is_none());
    }

    /// A Type 4 tint transform drives a real Separation `scn` end to end:
    /// `{ 1 exch sub }` over a DeviceGray alternate inverts the tint, so
    /// `1 scn` (full ink) → gray 0.0 → black.
    #[test]
    fn type4_separation_scn_end_to_end() {
        let arr = separation(
            "Spot",
            Object::Name("DeviceGray".into()),
            type4(&[0.0, 1.0], &[0.0, 1.0], "{ 1 exch sub }"),
        );
        let cs = Dict::new().with("CS0", arr);
        // tint 1.0 → 1−1 = 0.0 gray → black.
        let bytes = b"q /CS0 cs 1 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 0, 0));
        // tint 0.0 → 1−0 = 1.0 gray → white.
        let bytes = b"q /CS0 cs 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 255, 255));
    }

    // ── DeviceN colour spaces §8.6.6.5 ──────────────────────────────

    /// Build a `[ /DeviceN [names…] alt tint ]` array (§8.6.6.5).
    fn device_n(names: &[&str], alt: Object, tint: Object) -> Object {
        Object::Array(vec![
            Object::Name("DeviceN".into()),
            Object::Array(names.iter().map(|n| Object::Name((*n).into())).collect()),
            alt,
            tint,
        ])
    }

    /// A two-colorant DeviceN over DeviceRGB whose tint transform is a
    /// Type 4 program: `{ exch }` swaps the two tints so the (red, blue)
    /// inputs map to (blue, 0-stub, red)? No — keep it concrete: a 2-in
    /// 3-out program `{ 0 exch }` would mis-count. Use an explicit
    /// duotone: inputs (a, b) → RGB (a, 0, b).
    #[test]
    fn device_n_duotone_type4_maps_to_rgb() {
        // 2 inputs, 3 outputs. Program: stack starts [a b]; emit a, 0, b.
        // `{ 0 exch }` → [a 0 b]? Starting [a b]: push 0 → [a b 0];
        // exch → [a 0 b]. Exactly (a, 0, b).
        let tint = type4(
            &[0.0, 1.0, 0.0, 1.0],
            &[0.0, 1.0, 0.0, 1.0, 0.0, 1.0],
            "{ 0 exch }",
        );
        let arr = device_n(&["Red", "Blue"], Object::Name("DeviceRGB".into()), tint);
        // arity check: 2-in / 3-out over DeviceRGB.
        assert!(matches!(
            color_space_from_object(&arr),
            ColorSpaceKind::DeviceN { n_in: 2, .. }
        ));
        let cs = Dict::new().with("CS0", arr);
        // scn supplies the two tints in names order: Red=1.0, Blue=0.5.
        // → RGB (1.0, 0.0, 0.5) → (255, 0, 128).
        let bytes = b"q /CS0 cs 1 0.5 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 0, 128));
    }

    /// A DeviceN tint transform that is a 2-input Type 0 (sampled)
    /// function exercises the multilinear sampled path end-to-end. The
    /// 2×2×(n=1) grid maps (a,b) bilinearly; the single output drives a
    /// DeviceGray alternate.
    #[test]
    fn device_n_type0_sampled_bilinear_to_gray() {
        let tint = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(0))
                .with("Domain", num_arr(&[0.0, 1.0, 0.0, 1.0]))
                .with("Range", num_arr(&[0.0, 1.0]))
                .with("Size", num_arr(&[2.0, 2.0]))
                .with("BitsPerSample", Object::Integer(8))
                // f(0,0)=0, f(1,0)=255, f(0,1)=255, f(1,1)=255.
                .with("__Samples", Object::HexString(vec![0, 255, 255, 255])),
        );
        let arr = device_n(&["A", "B"], Object::Name("DeviceGray".into()), tint);
        let cs = Dict::new().with("CS0", arr);
        // (a,b) = (1,0) → f=255/255=1.0 gray → white.
        let bytes = b"q /CS0 cs 1 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 255, 255));
        // (a,b) = (0,0) → f=0 gray → black.
        let bytes = b"q /CS0 cs 0 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 0, 0));
    }

    /// §8.6.6.5: the initial DeviceN colour is every component at 1.0 — a
    /// bare `cs` with no `scn` paints the full-tint colour.
    #[test]
    fn device_n_bare_cs_uses_full_tint() {
        // 2-in/3-out: (a,b) → RGB (a, 0, b). At the 1.0/1.0 default →
        // RGB (1,0,1) magenta.
        let tint = type4(
            &[0.0, 1.0, 0.0, 1.0],
            &[0.0, 1.0, 0.0, 1.0, 0.0, 1.0],
            "{ 0 exch }",
        );
        let arr = device_n(&["Red", "Blue"], Object::Name("DeviceRGB".into()), tint);
        let cs = Dict::new().with("CS0", arr);
        let bytes = b"q /CS0 cs 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 0, 255));
    }

    /// §8.6.6.5: an all-`/None` DeviceN space always discards its output
    /// — `scn` produces no paint, so the path keeps the conservative
    /// black fallback rather than reverting to the alternate.
    #[test]
    fn device_n_all_none_discards_output() {
        let tint = type4(
            &[0.0, 1.0, 0.0, 1.0],
            &[0.0, 1.0, 0.0, 1.0, 0.0, 1.0],
            "{ 0 exch }",
        );
        let arr = device_n(&["None", "None"], Object::Name("DeviceRGB".into()), tint);
        assert!(matches!(
            color_space_from_object(&arr),
            ColorSpaceKind::DeviceN { all_none: true, .. }
        ));
        let cs = Dict::new().with("CS0", arr);
        // scn yields no paint → caller's conservative black fallback.
        let bytes = b"q /CS0 cs 1 1 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 0, 0));
    }

    /// §8.6.6.5: a tint transform whose input arity doesn't match the
    /// colorant count collapses the space to `Unknown` (black fallback).
    #[test]
    fn device_n_arity_mismatch_falls_back() {
        // 3 colorant names but a 2-input tint transform → mismatch.
        let tint = type4(&[0.0, 1.0, 0.0, 1.0], &[0.0, 1.0], "{ add }");
        let arr = device_n(&["A", "B", "C"], Object::Name("DeviceGray".into()), tint);
        assert_eq!(color_space_from_object(&arr), ColorSpaceKind::Unknown);
    }

    /// §8.6.6.5: a non-device (e.g. another special) alternate collapses
    /// the DeviceN space to `Unknown`.
    #[test]
    fn device_n_nondevice_alternate_falls_back() {
        let tint = type4(&[0.0, 1.0, 0.0, 1.0], &[0.0, 1.0], "{ add }");
        // Alternate is a Pattern name → not a device family.
        let arr = device_n(&["A", "B"], Object::Name("Pattern".into()), tint);
        assert_eq!(color_space_from_object(&arr), ColorSpaceKind::Unknown);
    }

    /// `parse_ps_program` tokenises numbers, booleans, nested blocks, and
    /// operators into the expected tree (the DoubleDot §7.10.5 example).
    #[test]
    fn type4_parses_doubledot_example() {
        // { 360 mul sin 2 div exch 360 mul sin 2 div add }
        let prog =
            parse_ps_program(b"{ 360 mul sin 2 div exch 360 mul sin 2 div add }").expect("parses");
        assert_eq!(prog.first(), Some(&PsToken::Number(360.0)));
        assert_eq!(prog.get(1), Some(&PsToken::Op(PsOp::Mul)));
        assert_eq!(prog.last(), Some(&PsToken::Op(PsOp::Add)));
    }

    /// Build a `[ /Separation name alt tint ]` array (§8.6.6.4).
    fn separation(name: &str, alt: Object, tint: Object) -> Object {
        Object::Array(vec![
            Object::Name("Separation".into()),
            Object::Name(name.into()),
            alt,
            tint,
        ])
    }

    /// §8.6.6.4 EXAMPLE 2 shape: a Separation over DeviceCMYK with a
    /// linear tint transform mapping tint → CMYK. At tint=1.0 the
    /// alternate components are the full C1; rendered through §10.3.5.
    #[test]
    fn separation_cmyk_tint_maps_through_alternate() {
        // tint transform: pure cyan at full tint (C1 = [1 0 0 0]).
        let tint = type2(&[0.0, 0.0, 0.0, 0.0], &[1.0, 0.0, 0.0, 0.0], 1.0);
        let arr = separation("LogoGreen", Object::Name("DeviceCMYK".into()), tint);
        let cs = Dict::new().with("CS0", arr);
        // 1.0 scn → CMYK (1,0,0,0) → §10.3.5 → (0,255,255) cyan.
        let bytes = b"q /CS0 cs 1 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 255, 255));
        // 0.0 scn → CMYK (0,0,0,0) → white.
        let bytes = b"q /CS0 cs 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 255, 255));
    }

    /// §8.6.6.4: the initial Separation colour is tint 1.0 — a bare
    /// `cs` with no `scn` paints the full-tint colour, not black.
    #[test]
    fn separation_bare_cs_uses_full_tint() {
        let tint = type2(&[1.0], &[0.0], 1.0); // gray: tint 1 → 0.0 (black)
        let arr = separation("Spot", Object::Name("DeviceGray".into()), tint);
        let cs = Dict::new().with("CS0", arr);
        // Bare cs → tint 1.0 → gray 0.0 → black.
        let bytes = b"q /CS0 cs 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 0, 0));
        // Explicit 0 scn → gray 1.0 → white, proving 1.0 was the default.
        let bytes = b"q /CS0 cs 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 255, 255));
    }

    /// A Type 3 stitching tint transform drives a Separation end-to-end.
    #[test]
    fn separation_with_type3_tint() {
        let tint = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(3))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with(
                    "Functions",
                    Object::Array(vec![type2(&[0.0], &[0.5], 1.0), type2(&[0.5], &[1.0], 1.0)]),
                )
                .with("Bounds", num_arr(&[0.5]))
                .with("Encode", num_arr(&[0.0, 1.0, 0.0, 1.0])),
        );
        let arr = separation("Spot", Object::Name("DeviceGray".into()), tint);
        let cs = Dict::new().with("CS0", arr);
        // tint 0.75 → subdomain 1, x'=0.5 → f1(0.5)=0.75 gray → 191.
        let bytes = b"q /CS0 cs 0.75 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        let (r, g, b) = first_fill_with_cs(bytes, &cs);
        let expect = (0.75f32 * 255.0).round() as u8;
        assert_eq!((r, g, b), (expect, expect, expect));
    }

    /// A Type 0 (sampled) tint transform drives a Separation over
    /// DeviceGray end-to-end through the content parser. The two-sample
    /// 8-bit table maps tint 1.0 → gray 0.0 (black), proving the
    /// `__Samples`-folded sampled function is evaluated by `scn`.
    #[test]
    fn separation_with_type0_tint() {
        // tint → gray, inverted: code at index 0 is 255 (gray 1.0),
        // index 1 is 0 (gray 0.0). Encode default [0 1].
        let tint = type0_8bit(&[0.0, 1.0], &[0.0, 1.0], &[255, 0]);
        let arr = separation("Spot", Object::Name("DeviceGray".into()), tint);
        let cs = Dict::new().with("CS0", arr);
        // tint 1.0 → gray 0.0 → black.
        let bytes = b"q /CS0 cs 1 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 0, 0));
        // tint 0.0 → gray 1.0 → white.
        let bytes = b"q /CS0 cs 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 255, 255));
    }

    /// The special `/None` colorant produces no visible output
    /// (§8.6.6.4): `scn` yields no paint, so the prior (default black)
    /// fill stands and no spurious colour is read.
    #[test]
    fn separation_none_colorant_produces_no_paint() {
        let arr = separation(
            "None",
            Object::Name("DeviceGray".into()),
            type2(&[0.0], &[1.0], 1.0),
        );
        let cs = Dict::new().with("CS0", arr);
        let bytes = b"q /CS0 cs 0.5 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        // No paint from the None colorant → commit_path's black fallback.
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 0, 0));
    }

    /// A Separation whose alternate is a non-device (CIE-based) space
    /// stays `Unknown` — this round renders only device alternates, so
    /// the conservative black fallback applies.
    #[test]
    fn separation_nondevice_alternate_is_unknown() {
        let arr = separation(
            "Spot",
            Object::Name("Lab".into()),
            type2(&[0.0], &[1.0], 1.0),
        );
        assert_eq!(color_space_from_object(&arr), ColorSpaceKind::Unknown);
    }

    /// A Separation whose tint transform is a Type 4 with no folded
    /// program body (unevaluable) stays `Unknown`.
    #[test]
    fn separation_unevaluable_tint_is_unknown() {
        let t4 = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(4))
                .with("Domain", num_arr(&[0.0, 1.0]))
                .with("Range", num_arr(&[0.0, 1.0])),
        );
        let arr = separation("Spot", Object::Name("DeviceGray".into()), t4);
        assert_eq!(color_space_from_object(&arr), ColorSpaceKind::Unknown);
    }

    /// A Separation tint operand outside `0.0..=1.0` is clamped into the
    /// colour range before the transform (§8.6.6.4).
    #[test]
    fn separation_tint_clamped_to_unit_range() {
        let tint = type2(&[0.0], &[1.0], 1.0); // gray identity
        let arr = separation("Spot", Object::Name("DeviceGray".into()), tint);
        let cs = Dict::new().with("CS0", arr);
        // 5.0 clamps to 1.0 → gray 1.0 → white.
        let bytes = b"q /CS0 cs 5 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 255, 255));
    }

    // ── ExtGState `gs` resolution (round 125, ISO 32000-1 §8.4.5) ──

    /// Helper: build a `/Resources /ExtGState` dictionary with a
    /// single named graphics-state parameter dict.
    fn ext_gstate_with(name: &str, dict: Dict) -> Dict {
        Dict::new().with(name, Object::Dict(dict))
    }

    fn parse_with(input: &[u8], ext: &Dict) -> Group {
        parse_content_stream_with_resources(input, Some(ext)).unwrap()
    }

    /// `LW` (line width) — Table 58.
    #[test]
    fn gs_applies_line_width_lw() {
        let ext = ext_gstate_with(
            "GS1",
            Dict::new()
                .with("Type", Object::Name("ExtGState".into()))
                .with("LW", Object::Real(3.5)),
        );
        let bytes = b"q /GS1 gs 0 0 m 10 10 l S Q\n";
        let root = parse_with(bytes, &ext);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        let s = p.stroke.as_ref().expect("stroke set");
        assert!((s.width - 3.5).abs() < 1e-3);
    }

    /// `LC` + `LJ` + `ML` — cap, join, miter limit.
    #[test]
    fn gs_applies_lc_lj_ml() {
        let ext = ext_gstate_with(
            "GS1",
            Dict::new()
                .with("LC", Object::Integer(1)) // Round
                .with("LJ", Object::Integer(2)) // Bevel
                .with("ML", Object::Real(7.5)),
        );
        let bytes = b"q /GS1 gs 0 0 m 10 10 l S Q\n";
        let root = parse_with(bytes, &ext);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        let s = p.stroke.as_ref().expect("stroke set");
        assert!(matches!(s.cap, LineCap::Round));
        assert!(matches!(s.join, LineJoin::Bevel));
        assert!((s.miter_limit - 7.5).abs() < 1e-3);
    }

    /// `D` — dash pattern as `[ [dashArray] dashPhase ]`.
    #[test]
    fn gs_applies_d_dash_pattern() {
        let ext = ext_gstate_with(
            "GS1",
            Dict::new().with(
                "D",
                Object::Array(vec![
                    Object::Array(vec![Object::Real(4.0), Object::Real(2.0)]),
                    Object::Real(1.0),
                ]),
            ),
        );
        let bytes = b"q /GS1 gs 0 0 m 10 10 l S Q\n";
        let root = parse_with(bytes, &ext);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        let s = p.stroke.as_ref().expect("stroke set");
        let dash = s.dash.as_ref().expect("dash set");
        assert_eq!(dash.array, vec![4.0, 2.0]);
        assert!((dash.offset - 1.0).abs() < 1e-3);
    }

    /// `ca` — nonstroking alpha constant multiplies into the fill
    /// colour's alpha (§11.6.4.4).
    #[test]
    fn gs_applies_ca_to_fill_alpha() {
        let ext = ext_gstate_with("GS1", Dict::new().with("ca", Object::Real(0.5)));
        // 1 0 0 rg paints opaque red — gs ca=0.5 → final alpha 128.
        let bytes = b"q 1 0 0 rg /GS1 gs 0 0 m 10 10 l 10 0 l h f Q\n";
        let root = parse_with(bytes, &ext);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        let Some(Paint::Solid(c)) = &p.fill else {
            panic!("fill")
        };
        assert_eq!((c.r, c.g, c.b), (255, 0, 0));
        // 1.0 * 0.5 * 255 = 127.5 → rounds to 128.
        assert_eq!(c.a, 128);
    }

    /// `CA` — stroking alpha constant lands on the stroke's paint.
    #[test]
    fn gs_applies_cap_ca_to_stroke_alpha() {
        let ext = ext_gstate_with("GS1", Dict::new().with("CA", Object::Real(0.25)));
        let bytes = b"q 0 1 0 RG /GS1 gs 0 0 m 10 10 l S Q\n";
        let root = parse_with(bytes, &ext);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        let s = p.stroke.as_ref().expect("stroke set");
        let Paint::Solid(c) = &s.paint else { panic!() };
        assert_eq!((c.r, c.g, c.b), (0, 255, 0));
        // 1.0 * 0.25 * 255 = 63.75 → rounds to 64.
        assert_eq!(c.a, 64);
    }

    /// `Q` restores the fill colour and the nonstroking alpha constant
    /// saved by the matching `q` (§8.4.4 Table 57 — "restore the
    /// graphics state … making it the current state").
    #[test]
    fn q_restores_fill_colour_and_alpha() {
        let ext = ext_gstate_with("GS1", Dict::new().with("ca", Object::Real(0.5)));
        // Inside the bracket: red at alpha 0.5. After `Q`: the initial
        // state — black fill (§8.6.3 initial colour) at alpha 1.0.
        let bytes = b"q 1 0 0 rg /GS1 gs Q 0 0 m 10 10 l 10 0 l h f\n";
        let root = parse_with(bytes, &ext);
        let Node::Path(p) = &root.children[0] else {
            panic!("expected root-level path, got {:?}", root.children[0]);
        };
        let Some(Paint::Solid(c)) = &p.fill else {
            panic!("fill")
        };
        assert_eq!((c.r, c.g, c.b, c.a), (0, 0, 0, 255));
    }

    /// `Q` restores the line state (width / cap / join / dash) the
    /// bracket changed (§8.4.4).
    #[test]
    fn q_restores_line_state() {
        let ext = Dict::new();
        let bytes = b"q 5 w 1 J 1 j [4 2] 1 d Q 0 0 m 10 10 l S\n";
        let root = parse_with(bytes, &ext);
        let Node::Path(p) = &root.children[0] else {
            panic!("expected root-level path");
        };
        let s = p.stroke.as_ref().expect("stroke set");
        assert!((s.width - 1.0).abs() < 1e-6, "width restored to 1.0");
        assert!(matches!(s.cap, LineCap::Butt));
        assert!(matches!(s.join, LineJoin::Miter));
        assert!(s.dash.is_none(), "dash restored to solid");
    }

    /// Nested `q … q … Q … Q` brackets restore level by level.
    #[test]
    fn nested_q_restores_outer_colour() {
        let ext = Dict::new();
        // Outer bracket paints red; inner bracket switches to green,
        // pops, and the path painted after the inner `Q` must be red.
        let bytes = b"q 1 0 0 rg q 0 1 0 rg Q 0 0 m 10 10 l 10 0 l h f Q\n";
        let root = parse_with(bytes, &ext);
        let Node::Group(g) = &root.children[0] else {
            panic!("outer q group");
        };
        let Node::Path(p) = &g.children[0] else {
            panic!("path inside outer bracket");
        };
        let Some(Paint::Solid(c)) = &p.fill else {
            panic!("fill")
        };
        assert_eq!((c.r, c.g, c.b), (255, 0, 0), "outer red restored");
    }

    // ── /SMask soft masks (§11.6.4.3 + §11.6.5.2) ──

    /// Build a soft-mask map with one entry (`GS1`) whose mask group
    /// is a white 10×10 square.
    fn smask_map(kind: MaskKind) -> BTreeMap<String, ResolvedSoftMask> {
        let mut p = Path::new();
        p.commands.push(PathCommand::MoveTo(Point::new(0.0, 0.0)));
        p.commands.push(PathCommand::LineTo(Point::new(10.0, 0.0)));
        p.commands.push(PathCommand::LineTo(Point::new(10.0, 10.0)));
        p.commands.push(PathCommand::LineTo(Point::new(0.0, 10.0)));
        p.commands.push(PathCommand::Close);
        let mask = Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(255, 255, 255))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        };
        let mut m = BTreeMap::new();
        m.insert("GS1".to_string(), ResolvedSoftMask { kind, mask });
        m
    }

    /// ExtGState resources where `GS1` carries an `/SMask` soft-mask
    /// dictionary and `GS2` carries `/SMask /None`.
    fn smask_ext_gstate() -> Dict {
        let sm = Dict::new()
            .with("Type", Object::Name("Mask".into()))
            .with("S", Object::Name("Luminosity".into()));
        let mut ext = Dict::new();
        ext.set(
            "GS1",
            Object::Dict(
                Dict::new()
                    .with("Type", Object::Name("ExtGState".into()))
                    .with("SMask", Object::Dict(sm)),
            ),
        );
        ext.set(
            "GS2",
            Object::Dict(
                Dict::new()
                    .with("Type", Object::Name("ExtGState".into()))
                    .with("SMask", Object::Name("None".into())),
            ),
        );
        ext
    }

    fn parse_with_smask(
        input: &[u8],
        ext: &Dict,
        masks: &BTreeMap<String, ResolvedSoftMask>,
    ) -> Group {
        parse_content_stream_full_with_soft_masks(
            input,
            Some(ext),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(masks),
            None,
            None,
        )
        .unwrap()
        .root
    }

    /// A path painted under an established soft mask is wrapped in
    /// `Node::SoftMask` with the resolved kind and mask geometry.
    #[test]
    fn smask_wraps_painted_path() {
        let ext = smask_ext_gstate();
        let masks = smask_map(MaskKind::Luminance);
        let bytes = b"q /GS1 gs 1 0 0 rg 0 0 m 20 0 l 20 20 l h f Q\n";
        let root = parse_with_smask(bytes, &ext, &masks);
        let Node::Group(g) = &root.children[0] else {
            panic!("q frame group");
        };
        let Node::SoftMask {
            mask,
            mask_kind,
            content,
        } = &g.children[0]
        else {
            panic!("expected SoftMask wrap, got {:?}", g.children[0]);
        };
        assert_eq!(*mask_kind, MaskKind::Luminance);
        // Content is the red path.
        let Node::Path(p) = content.as_ref() else {
            panic!("content path");
        };
        let Some(Paint::Solid(c)) = &p.fill else {
            panic!("fill");
        };
        assert_eq!((c.r, c.g, c.b), (255, 0, 0));
        // Mask subtree carries the white square, under an identity
        // relative transform (mask established and used at the same
        // CTM).
        let Node::Group(mg) = mask.as_ref() else {
            panic!("mask group");
        };
        assert!(mg.transform.is_identity(), "same-CTM mask is identity");
        let Node::Group(inner) = &mg.children[0] else {
            panic!("resolved mask group");
        };
        assert!(matches!(inner.children[0], Node::Path(_)));
    }

    /// `/SMask /None` clears the mask — later paints are unwrapped.
    #[test]
    fn smask_none_resets() {
        let ext = smask_ext_gstate();
        let masks = smask_map(MaskKind::Luminance);
        let bytes = b"/GS1 gs /GS2 gs 0 0 m 20 0 l 20 20 l h f\n";
        let root = parse_with_smask(bytes, &ext, &masks);
        assert!(
            matches!(root.children[0], Node::Path(_)),
            "path painted unmasked after /SMask /None, got {:?}",
            root.children[0]
        );
    }

    /// The soft mask is part of the graphics state — a `Q` restores
    /// the state saved before the mask was established (§8.4.4).
    #[test]
    fn smask_restored_by_q() {
        let ext = smask_ext_gstate();
        let masks = smask_map(MaskKind::Luminance);
        let bytes = b"q /GS1 gs Q 0 0 m 20 0 l 20 20 l h f\n";
        let root = parse_with_smask(bytes, &ext, &masks);
        assert!(
            matches!(root.children[0], Node::Path(_)),
            "path painted unmasked after Q, got {:?}",
            root.children[0]
        );
    }

    /// `/S /Alpha` maps onto `MaskKind::Alpha` (§11.5.2).
    #[test]
    fn smask_alpha_subtype() {
        let ext = smask_ext_gstate();
        let masks = smask_map(MaskKind::Alpha);
        let bytes = b"q /GS1 gs 0 0 m 20 0 l 20 20 l h f Q\n";
        let root = parse_with_smask(bytes, &ext, &masks);
        let Node::Group(g) = &root.children[0] else {
            panic!("q frame group");
        };
        let Node::SoftMask { mask_kind, .. } = &g.children[0] else {
            panic!("SoftMask wrap");
        };
        assert_eq!(*mask_kind, MaskKind::Alpha);
    }

    /// The mask's coordinate system is fixed at `gs` time
    /// (§11.6.5.2): painting under a later `cm` re-expresses the mask
    /// by the inverse of the intervening transform.
    #[test]
    fn smask_anchored_to_gs_time_ctm() {
        let ext = smask_ext_gstate();
        let masks = smask_map(MaskKind::Luminance);
        // Mask established at identity; the paint happens under a 2×
        // scale, so the mask subtree must carry the 0.5× inverse to
        // stay anchored where it was established.
        let bytes = b"/GS1 gs q 2 0 0 2 0 0 cm 0 0 m 20 0 l 20 20 l h f Q\n";
        let root = parse_with_smask(bytes, &ext, &masks);
        let Node::Group(g) = &root.children[0] else {
            panic!("q frame group");
        };
        let Node::SoftMask { mask, .. } = &g.children[0] else {
            panic!("SoftMask wrap, got {:?}", g.children[0]);
        };
        let Node::Group(mg) = mask.as_ref() else {
            panic!("mask group");
        };
        assert!((mg.transform.a - 0.5).abs() < 1e-6);
        assert!((mg.transform.d - 0.5).abs() < 1e-6);
    }

    /// A `gs` against an undefined ExtGState name is a tolerated no-op
    /// — the existing stroke/colour state passes through unchanged.
    #[test]
    fn gs_unknown_name_is_no_op() {
        let ext = ext_gstate_with("GS1", Dict::new().with("LW", Object::Real(9.0)));
        let bytes = b"q 2.5 w /GS_OTHER gs 0 0 m 10 10 l S Q\n";
        let root = parse_with(bytes, &ext);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        let s = p.stroke.as_ref().expect("stroke");
        // The earlier `2.5 w` still wins — GS_OTHER isn't in the dict.
        assert!((s.width - 2.5).abs() < 1e-3);
    }

    /// Multiple `gs` invocations cumulate (Table 58 — "results of gs
    /// shall be cumulative") so an earlier `LW` survives a later `gs`
    /// that touches only `CA`.
    #[test]
    fn multiple_gs_invocations_cumulate() {
        let mut ext = Dict::new();
        ext.set(
            "GW",
            Object::Dict(Dict::new().with("LW", Object::Real(4.0))),
        );
        ext.set(
            "GA",
            Object::Dict(Dict::new().with("CA", Object::Real(0.5))),
        );
        let bytes = b"q /GW gs /GA gs 1 0 0 RG 0 0 m 10 10 l S Q\n";
        let root = parse_with(bytes, &ext);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        let s = p.stroke.as_ref().expect("stroke");
        assert!((s.width - 4.0).abs() < 1e-3);
        let Paint::Solid(c) = &s.paint else { panic!() };
        assert_eq!(c.a, 128);
    }

    /// Without the resource-aware entry point, `gs` is a tolerated
    /// no-op — the legacy `parse_content_stream` path must not change.
    #[test]
    fn legacy_parse_content_stream_drops_gs_operands() {
        let bytes = b"q 2.5 w /GS1 gs 0 0 m 10 10 l S Q\n";
        let root = parse_content_stream(bytes).unwrap();
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        let s = p.stroke.as_ref().expect("stroke");
        assert!((s.width - 2.5).abs() < 1e-3);
    }

    /// Unhandled Table 58 keys (BM, OP, SMask, RI, …) are tolerated
    /// silently — the spec explicitly allows "any combination of
    /// parameter entries" including ones a reader can't honour.
    #[test]
    fn gs_unknown_table_58_keys_are_tolerated() {
        let ext = ext_gstate_with(
            "GS1",
            Dict::new()
                .with("BM", Object::Name("Multiply".into()))
                .with("OP", Object::Bool(true))
                .with("RI", Object::Name("Perceptual".into()))
                .with("LW", Object::Real(2.0)),
        );
        let bytes = b"q /GS1 gs 0 0 m 10 10 l S Q\n";
        let root = parse_with(bytes, &ext);
        let Node::Group(g) = &root.children[0] else {
            panic!()
        };
        let Node::Path(p) = &g.children[0] else {
            panic!()
        };
        let s = p.stroke.as_ref().expect("stroke set");
        // The honoured LW reaches the stroke even though BM / OP / RI
        // were also present.
        assert!((s.width - 2.0).abs() < 1e-3);
    }

    /// `apply_alpha` on a solid keeps RGB and scales the existing
    /// alpha — composes with any pre-set alpha rather than overwriting
    /// it.
    #[test]
    fn apply_alpha_composes_with_existing_alpha() {
        let base = Paint::Solid(Rgba::new(100, 200, 50, 200));
        let out = apply_alpha(base, 0.5);
        let Paint::Solid(c) = out else { panic!() };
        // 200/255 * 0.5 * 255 = 100.
        assert_eq!((c.r, c.g, c.b), (100, 200, 50));
        assert_eq!(c.a, 100);
    }

    /// `apply_alpha` short-circuits at α=1.0 (no-op).
    #[test]
    fn apply_alpha_unit_is_identity() {
        let base = Paint::Solid(Rgba::new(10, 20, 30, 200));
        let out = apply_alpha(base, 1.0);
        let Paint::Solid(c) = out else { panic!() };
        assert_eq!(c.a, 200);
    }

    /// `parse_dash_pair` decodes the `[ [dashArray] dashPhase ]`
    /// two-element shape Table 58 specifies.
    #[test]
    fn parse_dash_pair_two_element_array() {
        let obj = Object::Array(vec![
            Object::Array(vec![Object::Real(2.0), Object::Real(1.0)]),
            Object::Integer(3),
        ]);
        let (arr, off) = parse_dash_pair(&obj).expect("parses");
        assert_eq!(arr, vec![2.0, 1.0]);
        assert!((off - 3.0).abs() < 1e-3);
    }

    /// `parse_dash_pair` rejects malformed shapes.
    #[test]
    fn parse_dash_pair_rejects_malformed() {
        // Not an array.
        assert!(parse_dash_pair(&Object::Integer(0)).is_none());
        // Wrong arity.
        assert!(parse_dash_pair(&Object::Array(vec![Object::Integer(0)])).is_none());
        // First element isn't an array.
        assert!(
            parse_dash_pair(&Object::Array(vec![Object::Integer(0), Object::Integer(0)])).is_none()
        );
    }

    // ── Font resource plumbing + text show (round 128, ISO 32000-1 §9.4) ──

    /// Helper: build a `/Resources /Font` dictionary with one named
    /// simple-font descriptor. The dict shape mirrors what
    /// `resolve_font_resources` hands back from the document walker.
    fn font_res_with(name: &str, dict: Dict) -> Dict {
        Dict::new().with(name, Object::Dict(dict))
    }

    fn parse_full(input: &[u8], ext: Option<&Dict>, fonts: Option<&Dict>) -> ParsedContent {
        parse_content_stream_full(input, ext, fonts).unwrap()
    }

    /// A plain `BT … Tj … ET` with `/F1 12 Tf` surfaces one
    /// [`ContentTextShow`] with the font name + size + decoded
    /// literal-string bytes attached.
    #[test]
    fn tj_emits_one_text_show_with_font_and_size() {
        let f1 = Dict::new()
            .with("Type", Object::Name("Font".into()))
            .with("Subtype", Object::Name("Type1".into()))
            .with("BaseFont", Object::Name("Helvetica".into()));
        let fonts = font_res_with("F1", f1);
        let bytes = b"BT /F1 12 Tf 72 712 Td (Hello) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 1);
        let show = &p.text_shows[0];
        assert_eq!(show.font_name, "F1");
        assert!((show.font_size - 12.0).abs() < 1e-3);
        assert_eq!(show.bytes, b"Hello");
        assert!((show.position.0 - 72.0).abs() < 1e-3);
        assert!((show.position.1 - 712.0).abs() < 1e-3);
        assert!(matches!(show.operator, TextShowOp::Tj));
        assert!(show.font_dict.is_some());
    }

    /// `TJ` accepts `[ (s1) num1 (s2) num2 … ]`; the strings are
    /// concatenated in array order, numeric kerns dropped.
    #[test]
    fn tj_array_concatenates_strings_and_drops_kerns() {
        let fonts = font_res_with("F1", Dict::new());
        let bytes = b"BT /F1 10 Tf 0 0 Td [(Hel) -250 (lo) -120 (!)] TJ ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 1);
        let show = &p.text_shows[0];
        assert_eq!(show.bytes, b"Hello!");
        assert!(matches!(show.operator, TextShowOp::TJ));
    }

    /// `'` (single-quote) does the implicit `T*` line-advance first.
    /// With `TL = 14` the y-step is `-14`. Form: `string '`.
    #[test]
    fn single_quote_does_implicit_t_star_then_show() {
        let fonts = font_res_with("F1", Dict::new());
        let bytes = b"BT /F1 12 Tf 14 TL 0 100 Td (first) Tj (second) ' ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 2);
        assert_eq!(p.text_shows[0].bytes, b"first");
        assert!((p.text_shows[0].position.1 - 100.0).abs() < 1e-3);
        assert_eq!(p.text_shows[1].bytes, b"second");
        // T* moves down by TL: y = 100 - 14 = 86.
        assert!((p.text_shows[1].position.1 - 86.0).abs() < 1e-3);
        assert!(matches!(p.text_shows[1].operator, TextShowOp::SingleQuote));
    }

    /// `"` (double-quote) consumes its leading `aw ac` numbers then
    /// does the implicit `T*` + show. We don't track aw/ac but the
    /// line-advance must still fire. Form: `aw ac string "`.
    #[test]
    fn double_quote_does_implicit_t_star_then_show() {
        let fonts = font_res_with("F1", Dict::new());
        let bytes = b"BT /F1 12 Tf 10 TL 0 100 Td (first) Tj 1 2 (second) \" ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 2);
        assert_eq!(p.text_shows[1].bytes, b"second");
        assert!((p.text_shows[1].position.1 - 90.0).abs() < 1e-3);
        assert!(matches!(p.text_shows[1].operator, TextShowOp::DoubleQuote));
    }

    /// `Tm` sets the text matrix verbatim — origin = (e, f).
    #[test]
    fn tm_sets_text_matrix_directly() {
        let fonts = font_res_with("F1", Dict::new());
        let bytes = b"BT /F1 10 Tf 1 0 0 1 50 600 Tm (P) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 1);
        assert!((p.text_shows[0].position.0 - 50.0).abs() < 1e-3);
        assert!((p.text_shows[0].position.1 - 600.0).abs() < 1e-3);
    }

    /// `BT` resets the text matrix — runs from a prior `BT … ET`
    /// don't bleed into the next text object's position.
    #[test]
    fn bt_resets_text_matrix() {
        let fonts = font_res_with("F1", Dict::new());
        let bytes = b"BT /F1 12 Tf 100 200 Td (A) Tj ET BT /F1 12 Tf 0 0 Td (B) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 2);
        assert!((p.text_shows[0].position.0 - 100.0).abs() < 1e-3);
        // The second BT zeros out the matrix, then 0 0 Td adds (0,0).
        assert!(p.text_shows[1].position.0.abs() < 1e-3);
        assert!(p.text_shows[1].position.1.abs() < 1e-3);
    }

    /// `Tj` against a font *name* that isn't in the resources dict
    /// still surfaces the show — `font_dict` is `None` so the
    /// consumer knows the font wasn't resolved.
    #[test]
    fn tj_with_unknown_font_name_still_emits_show_with_none_dict() {
        let fonts = font_res_with("F1", Dict::new());
        let bytes = b"BT /F_OTHER 12 Tf 0 0 Td (Hi) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 1);
        assert_eq!(p.text_shows[0].font_name, "F_OTHER");
        assert_eq!(p.text_shows[0].bytes, b"Hi");
        assert!(p.text_shows[0].font_dict.is_none());
    }

    /// Without `font_resources` (the round-3 / round-125 entry
    /// points), text shows never emit — backward compatibility.
    #[test]
    fn legacy_entry_points_drop_tj_silently() {
        let bytes = b"BT /F1 12 Tf 0 0 Td (Hello) Tj ET\n";
        let r1 = parse_content_stream(bytes).unwrap();
        // No painted geometry — text doesn't reach the IR.
        assert!(r1.children.is_empty());
        let r2 = parse_content_stream_with_resources(bytes, None).unwrap();
        assert!(r2.children.is_empty());
    }

    /// `Tj` *outside* a `BT … ET` block is silently ignored — §9.4 +
    /// Table 105 says text-state operators are only valid inside a
    /// text object.
    #[test]
    fn tj_outside_text_object_is_dropped() {
        let fonts = font_res_with("F1", Dict::new());
        // No BT — stray Tj must not emit.
        let bytes = b"(stray) Tj\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 0);
    }

    /// Hex-string operands (`<48656C6C6F>` = `Hello`) decode through
    /// the same path as literal strings.
    #[test]
    fn hex_string_operand_decodes_for_tj() {
        let fonts = font_res_with("F1", Dict::new());
        let bytes = b"BT /F1 12 Tf 0 0 Td <48656C6C6F> Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 1);
        assert_eq!(p.text_shows[0].bytes, b"Hello");
    }

    /// Octal escape sequence `\101` = `'A'` (=0o101) in a literal
    /// string operand decodes to the right byte.
    #[test]
    fn literal_string_octal_escape() {
        let fonts = font_res_with("F1", Dict::new());
        let bytes = b"BT /F1 12 Tf 0 0 Td (\\101\\102\\103) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows[0].bytes, b"ABC");
    }

    /// Newline + tab + paren escapes round-trip.
    #[test]
    fn literal_string_named_escapes() {
        let fonts = font_res_with("F1", Dict::new());
        let bytes = b"BT /F1 12 Tf 0 0 Td (a\\nb\\tc\\(d\\)) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows[0].bytes, b"a\nb\tc(d)");
    }

    /// Painted geometry still lands in the IR even when a `BT … ET`
    /// runs in the same stream — text + paths coexist cleanly.
    #[test]
    fn text_and_path_coexist_in_one_stream() {
        let fonts = font_res_with("F1", Dict::new());
        let bytes = b"q 0 0 m 10 10 l 10 0 l h f BT /F1 12 Tf 0 0 Td (X) Tj ET Q\n";
        let p = parse_full(bytes, None, Some(&fonts));
        // One painted group with one path child.
        assert_eq!(p.root.children.len(), 1);
        let Node::Group(g) = &p.root.children[0] else {
            panic!()
        };
        assert!(matches!(g.children[0], Node::Path(_)));
        assert_eq!(p.text_shows.len(), 1);
        assert_eq!(p.text_shows[0].bytes, b"X");
    }

    /// `read_hex_string` pads a trailing odd nibble with 0 per
    /// §7.3.4.3.
    #[test]
    fn hex_string_pads_trailing_odd_nibble() {
        let (end, bytes) = read_hex_string(b"<4>x", 0).unwrap();
        assert_eq!(end, 3);
        assert_eq!(bytes, vec![0x40]);
    }

    /// `read_hex_string` skips whitespace and is case-insensitive
    /// on letters.
    #[test]
    fn hex_string_skips_whitespace_and_is_case_insensitive() {
        let (_end, bytes) = read_hex_string(b"<4a 5C>", 0).unwrap();
        assert_eq!(bytes, vec![0x4A, 0x5C]);
    }

    // ── `sh` shading-paint event (round 259, ISO 32000-1 §8.7.4.5) ──

    /// Helper: build a `/Resources /Shading` dictionary with one
    /// named shading. Mirrors `font_res_with` for the round-259
    /// shading-resources plumbing.
    fn shading_res_with(name: &str, dict: Dict) -> Dict {
        Dict::new().with(name, Object::Dict(dict))
    }

    fn parse_with_shading(
        input: &[u8],
        ext: Option<&Dict>,
        fonts: Option<&Dict>,
        shadings: Option<&Dict>,
    ) -> ParsedContent {
        parse_content_stream_full_with_shading(input, ext, fonts, shadings).unwrap()
    }

    /// `/Sh1 sh` with `/Resources /Shading /Sh1 = << /ShadingType 2 … >>`
    /// surfaces one [`ContentShading`] with the name + resolved dict.
    #[test]
    fn sh_emits_one_shading_event_with_resolved_dict() {
        // A minimal Type 2 (axial) shading dict per §8.7.4.5.3
        // Table 80 — we only check the dispatch surfaces it
        // verbatim; the round-259 walker doesn't interpret entries.
        let sh1 = Dict::new()
            .with("ShadingType", Object::Integer(2))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with(
                "Coords",
                Object::Array(vec![
                    Object::Real(0.0),
                    Object::Real(0.0),
                    Object::Real(100.0),
                    Object::Real(0.0),
                ]),
            );
        let shadings = shading_res_with("Sh1", sh1);
        // `q ... /Sh1 sh ... Q` — paint the shading in the current
        // user space (no `cm`, so CTM = identity).
        let bytes = b"q /Sh1 sh Q\n";
        let p = parse_with_shading(bytes, None, None, Some(&shadings));
        assert_eq!(p.shadings.len(), 1);
        let s = &p.shadings[0];
        assert_eq!(s.name, "Sh1");
        let dict = s.shading_dict.as_ref().expect("resolved");
        // ShadingType entry made it through.
        let st = dict
            .entries()
            .iter()
            .find(|(k, _)| k == "ShadingType")
            .map(|(_, v)| v.clone());
        assert!(matches!(st, Some(Object::Integer(2))));
        // CTM is identity (no `cm` issued).
        assert!((s.ctm.a - 1.0).abs() < 1e-6);
        assert!((s.ctm.d - 1.0).abs() < 1e-6);
        assert!(s.ctm.b.abs() < 1e-6);
        assert!(s.ctm.c.abs() < 1e-6);
        assert!(s.ctm.e.abs() < 1e-6);
        assert!(s.ctm.f.abs() < 1e-6);
        // No clip in force.
        assert!(s.clip.is_none());
    }

    /// `cm` issued before `sh` is captured in the event's CTM. The
    /// spec example in §8.7.4.5.4 paints `/Sh1 sh` after a
    /// `27.7843 0.0000 0.0000 -27.7843 310.2461 121.1521 cm` — the
    /// CTM is the composed matrix at the moment of paint.
    #[test]
    fn sh_captures_effective_ctm_from_cm() {
        let sh1 = Dict::new().with("ShadingType", Object::Integer(2));
        let shadings = shading_res_with("Sh1", sh1);
        // q ... cm ... /Sh1 sh ... Q
        let bytes = b"q 27.7843 0.0 0.0 -27.7843 310.2461 121.1521 cm /Sh1 sh Q\n";
        let p = parse_with_shading(bytes, None, None, Some(&shadings));
        assert_eq!(p.shadings.len(), 1);
        let s = &p.shadings[0];
        assert!((s.ctm.a - 27.7843).abs() < 1e-3);
        assert!(s.ctm.b.abs() < 1e-3);
        assert!(s.ctm.c.abs() < 1e-3);
        assert!((s.ctm.d - -27.7843).abs() < 1e-3);
        assert!((s.ctm.e - 310.2461).abs() < 1e-3);
        assert!((s.ctm.f - 121.1521).abs() < 1e-3);
    }

    /// `cm` operators in nested `q` frames compose root-to-leaf —
    /// the event's CTM reflects every transform in force.
    #[test]
    fn sh_composes_nested_cm_across_q_frames() {
        let sh1 = Dict::new();
        let shadings = shading_res_with("Sh1", sh1);
        // Outer q: translate(10, 20). Inner q: translate(5, 0).
        // Effective CTM at `sh`: translate(15, 20).
        let bytes = b"q 1 0 0 1 10 20 cm q 1 0 0 1 5 0 cm /Sh1 sh Q Q\n";
        let p = parse_with_shading(bytes, None, None, Some(&shadings));
        assert_eq!(p.shadings.len(), 1);
        let s = &p.shadings[0];
        assert!((s.ctm.e - 15.0).abs() < 1e-3);
        assert!((s.ctm.f - 20.0).abs() < 1e-3);
        assert!((s.ctm.a - 1.0).abs() < 1e-3);
        assert!((s.ctm.d - 1.0).abs() < 1e-3);
    }

    /// A `W n` clip committed before `sh` is captured in the
    /// event's `clip` slot.
    #[test]
    fn sh_captures_active_clip_path() {
        let sh1 = Dict::new();
        let shadings = shading_res_with("Sh1", sh1);
        // q ... 0 0 100 50 re W n /Sh1 sh Q — a rectangle clip
        // committed before the paint.
        let bytes = b"q 0 0 100 50 re W n /Sh1 sh Q\n";
        let p = parse_with_shading(bytes, None, None, Some(&shadings));
        assert_eq!(p.shadings.len(), 1);
        let s = &p.shadings[0];
        let clip = s.clip.as_ref().expect("clip in force");
        // The `re` operator expands into MoveTo + 3 LineTo + Close.
        assert!(!clip.commands.is_empty());
    }

    /// `sh` against a shading name not in the resources dict still
    /// emits the event — `shading_dict` is `None` so the consumer
    /// knows the resource wasn't resolved. Mirrors the
    /// `Tj`-with-unknown-font tolerance contract.
    #[test]
    fn sh_with_unknown_name_still_emits_event_with_none_dict() {
        let shadings = shading_res_with("Sh1", Dict::new());
        let bytes = b"q /Other sh Q\n";
        let p = parse_with_shading(bytes, None, None, Some(&shadings));
        assert_eq!(p.shadings.len(), 1);
        let s = &p.shadings[0];
        assert_eq!(s.name, "Other");
        assert!(s.shading_dict.is_none());
    }

    /// Without `shading_resources` plumbed in (the legacy entry
    /// points), `sh` still surfaces the event so callers see the
    /// operator + name + CTM + clip — only `shading_dict` is `None`.
    #[test]
    fn sh_without_shading_resources_emits_event_with_none_dict() {
        let bytes = b"q 1 0 0 1 50 60 cm /Sh1 sh Q\n";
        let p = parse_with_shading(bytes, None, None, None);
        assert_eq!(p.shadings.len(), 1);
        let s = &p.shadings[0];
        assert_eq!(s.name, "Sh1");
        assert!(s.shading_dict.is_none());
        assert!((s.ctm.e - 50.0).abs() < 1e-3);
        assert!((s.ctm.f - 60.0).abs() < 1e-3);
    }

    /// Multiple `sh` events in stream order all surface; each
    /// event's CTM reflects the matrix at *its* moment of paint.
    #[test]
    fn sh_multiple_events_surface_in_stream_order() {
        let shadings = Dict::new()
            .with("Sh1", Object::Dict(Dict::new()))
            .with("Sh2", Object::Dict(Dict::new()));
        // Two `sh`s in two different `q` frames with different
        // transforms.
        let bytes = b"q 1 0 0 1 10 20 cm /Sh1 sh Q q 1 0 0 1 30 40 cm /Sh2 sh Q\n";
        let p = parse_with_shading(bytes, None, None, Some(&shadings));
        assert_eq!(p.shadings.len(), 2);
        assert_eq!(p.shadings[0].name, "Sh1");
        assert!((p.shadings[0].ctm.e - 10.0).abs() < 1e-3);
        assert!((p.shadings[0].ctm.f - 20.0).abs() < 1e-3);
        assert_eq!(p.shadings[1].name, "Sh2");
        assert!((p.shadings[1].ctm.e - 30.0).abs() < 1e-3);
        assert!((p.shadings[1].ctm.f - 40.0).abs() < 1e-3);
    }

    /// `parse_content_stream_full` (no shading resources) keeps its
    /// existing surface — the new `shadings` slot is populated only
    /// when a `sh` operator fires, and the resolved dict slot stays
    /// `None` because the caller didn't plumb resources.
    #[test]
    fn parse_content_stream_full_still_drops_sh_with_none_dict() {
        // Goes through the legacy entry point — no shading
        // resources.
        let bytes = b"q /Sh1 sh Q\n";
        let p = parse_content_stream_full(bytes, None, None).unwrap();
        assert_eq!(p.shadings.len(), 1);
        assert_eq!(p.shadings[0].name, "Sh1");
        assert!(p.shadings[0].shading_dict.is_none());
    }

    /// Content streams without any `sh` operator surface an empty
    /// `shadings` slot regardless of whether resources were
    /// plumbed in.
    #[test]
    fn shadings_empty_when_no_sh_operator() {
        let shadings = shading_res_with("Sh1", Dict::new());
        let bytes = b"q 100 100 m 200 200 l S Q\n";
        let p = parse_with_shading(bytes, None, None, Some(&shadings));
        assert!(p.shadings.is_empty());
    }

    // ───────────── mesh shadings (§8.7.4.5.5–8) ──────────────

    /// A tiny MSB-first bit writer mirroring [`BitReader`], used to
    /// hand-assemble mesh stream bodies in the tests.
    struct BitWriter {
        bytes: Vec<u8>,
        bit: u32,
    }
    impl BitWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                bit: 0,
            }
        }
        fn write(&mut self, value: u64, bits: u32) {
            for i in (0..bits).rev() {
                if self.bit == 0 {
                    self.bytes.push(0);
                }
                let b = ((value >> i) & 1) as u8;
                let last = self.bytes.len() - 1;
                self.bytes[last] |= b << (7 - self.bit);
                self.bit = (self.bit + 1) % 8;
            }
        }
        fn align(&mut self) {
            self.bit = 0;
        }
        fn finish(mut self) -> Vec<u8> {
            self.align();
            self.bytes
        }
    }

    fn decode_rgb8() -> Object {
        // [ xmin xmax ymin ymax rmin rmax gmin gmax bmin bmax ] for an
        // 8-bit coordinate / colour DeviceRGB mesh over a 0..1 unit box.
        Object::Array(
            [0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0]
                .into_iter()
                .map(Object::Real)
                .collect(),
        )
    }

    /// Type 4 free-form Gouraud mesh: one all-red / green / blue
    /// triangle decodes to three coloured vertices.
    #[test]
    fn mesh_type4_single_triangle_decodes_vertices() {
        let mut w = BitWriter::new();
        // f=0, (0,0) red ; ignored-flag, (1,0) green ; ignored, (0,1) blue.
        // 8-bit coords, 8-bit components, 8-bit flag.
        let vert = |w: &mut BitWriter, flag: u64, x: u64, y: u64, r: u64, g: u64, b: u64| {
            w.write(flag, 8);
            w.write(x, 8);
            w.write(y, 8);
            w.write(r, 8);
            w.write(g, 8);
            w.write(b, 8);
            w.align();
        };
        vert(&mut w, 0, 0, 0, 255, 0, 0);
        vert(&mut w, 0, 255, 0, 0, 255, 0);
        vert(&mut w, 0, 0, 255, 0, 0, 255);
        let data = w.finish();
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(4))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with("BitsPerCoordinate", Object::Integer(8))
            .with("BitsPerComponent", Object::Integer(8))
            .with("BitsPerFlag", Object::Integer(8))
            .with("Decode", decode_rgb8())
            .with("__MeshData", Object::HexString(data));
        let mesh = evaluate_mesh_shading(&dict, None).expect("mesh evaluated");
        let MeshShading::Triangles(tris) = mesh else {
            panic!("expected triangles")
        };
        assert_eq!(tris.len(), 1);
        let v = tris[0].vertices;
        assert!((v[0].point.x - 0.0).abs() < 1e-4 && (v[0].point.y - 0.0).abs() < 1e-4);
        assert_eq!((v[0].color.r, v[0].color.g, v[0].color.b), (255, 0, 0));
        assert!((v[1].point.x - 1.0).abs() < 1e-4);
        assert_eq!((v[1].color.r, v[1].color.g, v[1].color.b), (0, 255, 0));
        assert!((v[2].point.y - 1.0).abs() < 1e-4);
        assert_eq!((v[2].color.r, v[2].color.g, v[2].color.b), (0, 0, 255));
    }

    /// Type 4 edge-flag continuation: a second vertex with `f=1` reuses
    /// (vb, vc) of the first triangle (§8.7.4.5.5 Figure 25).
    #[test]
    fn mesh_type4_edge_flag_continuation() {
        let mut w = BitWriter::new();
        let vert = |w: &mut BitWriter, flag: u64, x: u64, y: u64, r: u64, g: u64, b: u64| {
            w.write(flag, 8);
            w.write(x, 8);
            w.write(y, 8);
            w.write(r, 8);
            w.write(g, 8);
            w.write(b, 8);
            w.align();
        };
        vert(&mut w, 0, 0, 0, 255, 0, 0); // va
        vert(&mut w, 0, 255, 0, 0, 255, 0); // vb
        vert(&mut w, 0, 0, 255, 0, 0, 255); // vc
        vert(&mut w, 1, 255, 255, 255, 255, 0); // vd on side vbc
        let data = w.finish();
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(4))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with("BitsPerCoordinate", Object::Integer(8))
            .with("BitsPerComponent", Object::Integer(8))
            .with("BitsPerFlag", Object::Integer(8))
            .with("Decode", decode_rgb8())
            .with("__MeshData", Object::HexString(data));
        let MeshShading::Triangles(tris) = evaluate_mesh_shading(&dict, None).unwrap() else {
            panic!()
        };
        assert_eq!(tris.len(), 2);
        // Second triangle = (vb, vc, vd).
        let t2 = tris[1].vertices;
        assert!((t2[0].point.x - 1.0).abs() < 1e-4 && t2[0].point.y.abs() < 1e-4); // vb
        assert!(t2[1].point.x.abs() < 1e-4 && (t2[1].point.y - 1.0).abs() < 1e-4); // vc
        assert!((t2[2].point.x - 1.0).abs() < 1e-4 && (t2[2].point.y - 1.0).abs() < 1e-4); // vd
        assert_eq!((t2[2].color.r, t2[2].color.g, t2[2].color.b), (255, 255, 0));
    }

    /// Type 5 lattice mesh: a 2×2 lattice (2 rows, 2 vertices/row)
    /// builds two triangles per the §8.7.4.5.6 triplet rule.
    #[test]
    fn mesh_type5_lattice_two_by_two() {
        let mut w = BitWriter::new();
        let vert = |w: &mut BitWriter, x: u64, y: u64, r: u64, g: u64, b: u64| {
            w.write(x, 8);
            w.write(y, 8);
            w.write(r, 8);
            w.write(g, 8);
            w.write(b, 8);
            w.align();
        };
        // Row 0: (0,0) red, (1,0) green. Row 1: (0,1) blue, (1,1) white.
        vert(&mut w, 0, 0, 255, 0, 0);
        vert(&mut w, 255, 0, 0, 255, 0);
        vert(&mut w, 0, 255, 0, 0, 255);
        vert(&mut w, 255, 255, 255, 255, 255);
        let data = w.finish();
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(5))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with("BitsPerCoordinate", Object::Integer(8))
            .with("BitsPerComponent", Object::Integer(8))
            .with("VerticesPerRow", Object::Integer(2))
            .with("Decode", decode_rgb8())
            .with("__MeshData", Object::HexString(data));
        let MeshShading::Triangles(tris) = evaluate_mesh_shading(&dict, None).unwrap() else {
            panic!()
        };
        // One cell → two triangles.
        assert_eq!(tris.len(), 2);
        // First triangle = (V00, V01, V10) = red, green, blue.
        let t = tris[0].vertices;
        assert_eq!((t[0].color.r, t[0].color.g, t[0].color.b), (255, 0, 0));
        assert_eq!((t[1].color.r, t[1].color.g, t[1].color.b), (0, 255, 0));
        assert_eq!((t[2].color.r, t[2].color.g, t[2].color.b), (0, 0, 255));
    }

    /// Type 6 Coons patch (single patch, `f=0`): 12 boundary points +
    /// 4 corner colours decode; the four internal control points are
    /// derived, and corner colours land at p00/p03/p33/p30.
    #[test]
    fn mesh_type6_coons_single_patch() {
        let mut w = BitWriter::new();
        w.write(0, 8); // edge flag f=0
                       // 12 boundary points. Lay out a unit square traced in the
                       // Coons order (p00 p01 p02 p03 p13 p23 p33 p32 p31 p30 p20 p10).
        let pts: [(u64, u64); 12] = [
            (0, 0),     // p00
            (0, 85),    // p01
            (0, 170),   // p02
            (0, 255),   // p03
            (85, 255),  // p13
            (170, 255), // p23
            (255, 255), // p33
            (255, 170), // p32
            (255, 85),  // p31
            (255, 0),   // p30
            (170, 0),   // p20
            (85, 0),    // p10
        ];
        for (x, y) in pts {
            w.write(x, 8);
            w.write(y, 8);
        }
        // Four corner colours c1..c4 (p00 red, p03 green, p33 blue, p30 white).
        let cols: [(u64, u64, u64); 4] = [(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 255)];
        for (r, g, b) in cols {
            w.write(r, 8);
            w.write(g, 8);
            w.write(b, 8);
        }
        w.align();
        let data = w.finish();
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(6))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with("BitsPerCoordinate", Object::Integer(8))
            .with("BitsPerComponent", Object::Integer(8))
            .with("BitsPerFlag", Object::Integer(8))
            .with("Decode", decode_rgb8())
            .with("__MeshData", Object::HexString(data));
        let MeshShading::Patches(patches) = evaluate_mesh_shading(&dict, None).unwrap() else {
            panic!("expected patches")
        };
        assert_eq!(patches.len(), 1);
        let p = &patches[0];
        // Corners decode.
        assert!((p.control_points[0][0].x).abs() < 1e-4); // p00 at (0,0)
        assert!((p.control_points[3][3].x - 1.0).abs() < 1e-4); // p33 at (1,1)
        assert_eq!(
            (
                p.corner_colors[0].r,
                p.corner_colors[0].g,
                p.corner_colors[0].b
            ),
            (255, 0, 0)
        );
        assert_eq!(
            (
                p.corner_colors[2].r,
                p.corner_colors[2].g,
                p.corner_colors[2].b
            ),
            (0, 0, 255)
        );
        // For a flat unit-square patch, the derived internal points lie
        // inside the unit square (sanity bound).
        for c in 1..=2 {
            for rr in 1..=2 {
                let ip = p.control_points[c][rr];
                assert!(ip.x > -0.5 && ip.x < 1.5, "internal x in range");
                assert!(ip.y > -0.5 && ip.y < 1.5, "internal y in range");
            }
        }
    }

    /// Type 7 tensor patch (single patch, `f=0`): 16 control points +
    /// 4 corner colours decode in the Table 86 stream order.
    #[test]
    fn mesh_type7_tensor_single_patch() {
        let mut w = BitWriter::new();
        w.write(0, 8); // f=0
                       // 16 points in tensor stream order; we only check the four
                       // corners land at the right (col,row) slots.
                       // Order: p00 p01 p02 p03 p13 p23 p33 p32 p31 p30 p20 p10 p11 p12 p22 p21
        let pts: [(u64, u64); 16] = [
            (0, 0),     // p00
            (0, 85),    // p01
            (0, 170),   // p02
            (0, 255),   // p03
            (85, 255),  // p13
            (170, 255), // p23
            (255, 255), // p33
            (255, 170), // p32
            (255, 85),  // p31
            (255, 0),   // p30
            (170, 0),   // p20
            (85, 0),    // p10
            (85, 85),   // p11
            (85, 170),  // p12
            (170, 170), // p22
            (170, 85),  // p21
        ];
        for (x, y) in pts {
            w.write(x, 8);
            w.write(y, 8);
        }
        for (r, g, b) in [(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0)] {
            w.write(r, 8);
            w.write(g, 8);
            w.write(b, 8);
        }
        w.align();
        let data = w.finish();
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(7))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with("BitsPerCoordinate", Object::Integer(8))
            .with("BitsPerComponent", Object::Integer(8))
            .with("BitsPerFlag", Object::Integer(8))
            .with("Decode", decode_rgb8())
            .with("__MeshData", Object::HexString(data));
        let MeshShading::Patches(patches) = evaluate_mesh_shading(&dict, None).unwrap() else {
            panic!()
        };
        assert_eq!(patches.len(), 1);
        let p = &patches[0];
        // Tensor internal point p11 decodes to (85,85)→(~0.333,~0.333).
        assert!((p.control_points[1][1].x - 85.0 / 255.0).abs() < 1e-3);
        assert!((p.control_points[2][2].y - 170.0 / 255.0).abs() < 1e-3);
        assert_eq!(
            (
                p.corner_colors[3].r,
                p.corner_colors[3].g,
                p.corner_colors[3].b
            ),
            (255, 255, 0)
        );
    }

    /// Type 6 Coons patch continuation (`f=1`): the second patch supplies
    /// only 8 new boundary points + 2 corner colours; the four shared
    /// boundary points and two corner colours are inherited from the
    /// previous patch's top edge (§8.7.4.5.7 Table 85, f=1).
    #[test]
    fn mesh_type6_coons_edge_flag_continuation() {
        let mut w = BitWriter::new();
        // Patch A (f=0): unit-square boundary, corners red/green/blue/white.
        w.write(0, 8);
        let pts_a: [(u64, u64); 12] = [
            (0, 0),
            (0, 85),
            (0, 170),
            (0, 255),
            (85, 255),
            (170, 255),
            (255, 255),
            (255, 170),
            (255, 85),
            (255, 0),
            (170, 0),
            (85, 0),
        ];
        for (x, y) in pts_a {
            w.write(x, 8);
            w.write(y, 8);
        }
        for (r, g, b) in [(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 255)] {
            w.write(r, 8);
            w.write(g, 8);
            w.write(b, 8);
        }
        w.align();
        // Patch B (f=1): 8 new boundary points (the points after the
        // shared edge in Coons order) + 2 new corner colours.
        w.write(1, 8);
        for k in 0..8u64 {
            // Arbitrary distinct coordinates above the unit square.
            w.write(255, 8);
            w.write((k * 30).min(255), 8);
        }
        // c3, c4 of the new patch (yellow, magenta).
        for (r, g, b) in [(255, 255, 0), (255, 0, 255)] {
            w.write(r, 8);
            w.write(g, 8);
            w.write(b, 8);
        }
        w.align();
        let data = w.finish();
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(6))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with("BitsPerCoordinate", Object::Integer(8))
            .with("BitsPerComponent", Object::Integer(8))
            .with("BitsPerFlag", Object::Integer(8))
            .with("Decode", decode_rgb8())
            .with("__MeshData", Object::HexString(data));
        let MeshShading::Patches(patches) = evaluate_mesh_shading(&dict, None).unwrap() else {
            panic!()
        };
        assert_eq!(patches.len(), 2);
        let b = &patches[1];
        let a = &patches[0];
        // Patch B inherits patch A's top edge (p03 p13 p23 p33) as its
        // own p00 p01 p02 p03 (§8.7.4.5.8 Table 86 f=1 geometry).
        assert_eq!(b.control_points[0][0], a.control_points[0][3]); // B.p00 = A.p03
        assert_eq!(b.control_points[0][3], a.control_points[3][3]); // B.p03 = A.p33
                                                                    // Patch B inherits c1=c2prev (green), c2=c3prev (blue).
        assert_eq!(
            (
                b.corner_colors[0].r,
                b.corner_colors[0].g,
                b.corner_colors[0].b
            ),
            (0, 255, 0)
        );
        assert_eq!(
            (
                b.corner_colors[1].r,
                b.corner_colors[1].g,
                b.corner_colors[1].b
            ),
            (0, 0, 255)
        );
        // c3, c4 of patch B are the new pair (yellow, magenta).
        assert_eq!(
            (
                b.corner_colors[2].r,
                b.corner_colors[2].g,
                b.corner_colors[2].b
            ),
            (255, 255, 0)
        );
        assert_eq!(
            (
                b.corner_colors[3].r,
                b.corner_colors[3].g,
                b.corner_colors[3].b
            ),
            (255, 0, 255)
        );
    }

    /// A shading with a `/Function` entry carries a single parametric
    /// value `t` per vertex; the function maps it to colour components
    /// (§8.7.4.5.5). A Type 2 exponential from black→white renders the
    /// midpoint vertex as mid-grey.
    #[test]
    fn mesh_type4_with_parametric_function() {
        let mut w = BitWriter::new();
        // 8-bit coords, 8-bit single parametric component, 8-bit flag.
        let vert = |w: &mut BitWriter, x: u64, y: u64, t: u64| {
            w.write(0, 8); // f=0
            w.write(x, 8);
            w.write(y, 8);
            w.write(t, 8);
            w.align();
        };
        vert(&mut w, 0, 0, 0); // t=0 → black
        vert(&mut w, 255, 0, 255); // t=1 → white
        vert(&mut w, 0, 255, 128); // t≈0.5 → mid grey
        let data = w.finish();
        // Type 2 exponential: 1-in / 3-out, C0=[0 0 0], C1=[1 1 1], N=1.
        let func = Dict::new()
            .with("FunctionType", Object::Integer(2))
            .with(
                "Domain",
                Object::Array(vec![Object::Real(0.0), Object::Real(1.0)]),
            )
            .with(
                "C0",
                Object::Array(vec![
                    Object::Real(0.0),
                    Object::Real(0.0),
                    Object::Real(0.0),
                ]),
            )
            .with(
                "C1",
                Object::Array(vec![
                    Object::Real(1.0),
                    Object::Real(1.0),
                    Object::Real(1.0),
                ]),
            )
            .with("N", Object::Real(1.0));
        // With a Function the Decode array has only one colour pair.
        let decode = Object::Array(
            [0.0, 1.0, 0.0, 1.0, 0.0, 1.0]
                .into_iter()
                .map(Object::Real)
                .collect(),
        );
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(4))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with("BitsPerCoordinate", Object::Integer(8))
            .with("BitsPerComponent", Object::Integer(8))
            .with("BitsPerFlag", Object::Integer(8))
            .with("Decode", decode)
            .with("Function", Object::Dict(func))
            .with("__MeshData", Object::HexString(data));
        let MeshShading::Triangles(tris) = evaluate_mesh_shading(&dict, None).unwrap() else {
            panic!()
        };
        let v = tris[0].vertices;
        assert_eq!((v[0].color.r, v[0].color.g, v[0].color.b), (0, 0, 0));
        assert_eq!((v[1].color.r, v[1].color.g, v[1].color.b), (255, 255, 255));
        // t=128/255 ≈ 0.502 → ~128 grey.
        assert!((v[2].color.r as i32 - 128).abs() <= 1);
        assert_eq!(v[2].color.r, v[2].color.g);
        assert_eq!(v[2].color.g, v[2].color.b);
    }

    /// A Type 1–3 shading (axial) leaves `mesh` `None` — only Types 4–7
    /// carry mesh geometry.
    #[test]
    fn mesh_none_for_axial_shading() {
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(2))
            .with("ColorSpace", Object::Name("DeviceRGB".into()));
        assert!(evaluate_mesh_shading(&dict, None).is_none());
    }

    /// An `sh` paint of a Type 4 mesh surfaces the evaluated geometry on
    /// the `ContentShading` event (end-to-end through the `sh` operator).
    #[test]
    fn sh_surfaces_evaluated_mesh() {
        let mut w = BitWriter::new();
        let vert = |w: &mut BitWriter, x: u64, y: u64, r: u64, g: u64, b: u64| {
            w.write(0, 8);
            w.write(x, 8);
            w.write(y, 8);
            w.write(r, 8);
            w.write(g, 8);
            w.write(b, 8);
            w.align();
        };
        vert(&mut w, 0, 0, 255, 0, 0);
        vert(&mut w, 255, 0, 0, 255, 0);
        vert(&mut w, 0, 255, 0, 0, 255);
        let data = w.finish();
        let sh1 = Dict::new()
            .with("ShadingType", Object::Integer(4))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with("BitsPerCoordinate", Object::Integer(8))
            .with("BitsPerComponent", Object::Integer(8))
            .with("BitsPerFlag", Object::Integer(8))
            .with("Decode", decode_rgb8())
            .with("__MeshData", Object::HexString(data));
        let shadings = shading_res_with("Sh1", sh1);
        let bytes = b"q /Sh1 sh Q\n";
        let p = parse_with_shading(bytes, None, None, Some(&shadings));
        assert_eq!(p.shadings.len(), 1);
        let mesh = p.shadings[0].mesh.as_ref().expect("mesh surfaced");
        let MeshShading::Triangles(tris) = mesh else {
            panic!()
        };
        assert_eq!(tris.len(), 1);
    }

    // ─────────── gradient shadings (Types 1–3, §8.7.4.5.2–4) ───────────

    /// Build a Type 2 (exponential) function dict from black→white.
    fn exp_black_to_white() -> Object {
        Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(2))
                .with(
                    "Domain",
                    Object::Array(vec![Object::Real(0.0), Object::Real(1.0)]),
                )
                .with(
                    "C0",
                    Object::Array(vec![
                        Object::Real(0.0),
                        Object::Real(0.0),
                        Object::Real(0.0),
                    ]),
                )
                .with(
                    "C1",
                    Object::Array(vec![
                        Object::Real(1.0),
                        Object::Real(1.0),
                        Object::Real(1.0),
                    ]),
                )
                .with("N", Object::Real(1.0)),
        )
    }

    /// Type 2 axial shading: geometry + 64 colour stops from black to
    /// white across the default domain `[0, 1]` (§8.7.4.5.3).
    #[test]
    fn gradient_type2_axial_samples_stops() {
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(2))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with(
                "Coords",
                Object::Array(vec![
                    Object::Real(0.0),
                    Object::Real(0.0),
                    Object::Real(100.0),
                    Object::Real(0.0),
                ]),
            )
            .with("Function", exp_black_to_white())
            .with(
                "Extend",
                Object::Array(vec![Object::Bool(true), Object::Bool(false)]),
            );
        let g = evaluate_gradient_shading(&dict, None).expect("gradient");
        let ShadingGradient::Axial {
            coords,
            extend,
            stops,
        } = g
        else {
            panic!("expected axial")
        };
        assert_eq!(coords, [0.0, 0.0, 100.0, 0.0]);
        assert_eq!(extend, [true, false]);
        assert_eq!(stops.len(), 64);
        // First stop t=0 → black, last t=1 → white.
        assert_eq!((stops[0].r, stops[0].g, stops[0].b), (0, 0, 0));
        assert_eq!((stops[63].r, stops[63].g, stops[63].b), (255, 255, 255));
        // Monotonic increase (linear N=1 exponential).
        assert!(stops[32].r > stops[0].r && stops[32].r < stops[63].r);
    }

    /// Type 3 radial shading: six-number `Coords` + stops (§8.7.4.5.4).
    #[test]
    fn gradient_type3_radial_samples_stops() {
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(3))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with(
                "Coords",
                Object::Array(
                    [0.0, 0.0, 0.0, 0.0, 0.0, 50.0]
                        .into_iter()
                        .map(Object::Real)
                        .collect(),
                ),
            )
            .with("Function", exp_black_to_white());
        let g = evaluate_gradient_shading(&dict, None).expect("gradient");
        let ShadingGradient::Radial {
            coords,
            extend,
            stops,
        } = g
        else {
            panic!("expected radial")
        };
        assert_eq!(coords, [0.0, 0.0, 0.0, 0.0, 0.0, 50.0]);
        assert_eq!(extend, [false, false]); // default
        assert_eq!(stops.len(), 64);
        assert_eq!((stops[0].r, stops[0].g, stops[0].b), (0, 0, 0));
    }

    /// `shading_color_space` resolves a bare-name `/ColorSpace` against
    /// the page's `/Resources /ColorSpace` subdictionary (§8.7.4.5.2). A
    /// device name still short-circuits; an inline array is interpreted
    /// directly; a resource key resolves through the dict.
    #[test]
    fn shading_color_space_resolves_resource_key() {
        // Bare device name: no resource lookup needed.
        assert_eq!(
            shading_color_space(&Object::Name("DeviceRGB".into()), None),
            ColorSpaceKind::DeviceRgb
        );
        // A resource key `/CS0` → CalRGB.
        let cal_rgb = Object::Array(vec![
            Object::Name("CalRGB".into()),
            Object::Dict(Dict::new().with(
                "WhitePoint",
                Object::Array(vec![
                    Object::Real(0.9505),
                    Object::Real(1.0),
                    Object::Real(1.089),
                ]),
            )),
        ]);
        let res = Dict::new().with("CS0", cal_rgb);
        assert!(matches!(
            shading_color_space(&Object::Name("CS0".into()), Some(&res)),
            ColorSpaceKind::CalRgb { .. }
        ));
        // Unknown key with no resources stays Unknown.
        assert_eq!(
            shading_color_space(&Object::Name("CS9".into()), None),
            ColorSpaceKind::Unknown
        );
    }

    /// An axial (Type 2) shading whose `/ColorSpace` is a *named*
    /// resource key resolving to a CIE-based CalGray space evaluates its
    /// gradient stops through that space instead of failing. Previously
    /// a name `/ColorSpace` collapsed to `Unknown` and dropped the
    /// gradient.
    #[test]
    fn gradient_named_resource_colour_space_resolves() {
        // CalGray colour function: single-component black→white ramp.
        let func = Object::Dict(
            Dict::new()
                .with("FunctionType", Object::Integer(2))
                .with(
                    "Domain",
                    Object::Array(vec![Object::Real(0.0), Object::Real(1.0)]),
                )
                .with("C0", Object::Array(vec![Object::Real(0.0)]))
                .with("C1", Object::Array(vec![Object::Real(1.0)]))
                .with("N", Object::Real(1.0)),
        );
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(2))
            .with("ColorSpace", Object::Name("CSGray".into()))
            .with(
                "Coords",
                Object::Array(
                    [0.0, 0.0, 100.0, 0.0]
                        .into_iter()
                        .map(Object::Real)
                        .collect(),
                ),
            )
            .with("Function", func);
        let cal_gray = Object::Array(vec![
            Object::Name("CalGray".into()),
            Object::Dict(Dict::new().with(
                "WhitePoint",
                Object::Array(vec![
                    Object::Real(0.9505),
                    Object::Real(1.0),
                    Object::Real(1.089),
                ]),
            )),
        ]);
        let res = Dict::new().with("CSGray", cal_gray);
        // Without resources the name can't resolve → no gradient.
        assert!(evaluate_gradient_shading(&dict, None).is_none());
        // With resources the CalGray space resolves and stops sample.
        let g = evaluate_gradient_shading(&dict, Some(&res)).expect("gradient");
        let ShadingGradient::Axial { stops, .. } = g else {
            panic!("expected axial");
        };
        assert_eq!(stops.len(), 64);
        // t=0 → gray A=0 → black; t=1 → gray A=1 → white.
        assert_eq!((stops[0].r, stops[0].g, stops[0].b), (0, 0, 0));
        assert_eq!((stops[63].r, stops[63].g, stops[63].b), (255, 255, 255));
    }

    /// Type 1 function-based shading: a 2-in / 3-out Type 4 calculator
    /// returning `(x, y, 0)` samples onto the domain grid (§8.7.4.5.2).
    #[test]
    fn gradient_type1_function_based_grid() {
        // A Type 4 (PostScript-calculator) program that discards its two
        // inputs and returns constant mid-grey `0.5 0.5 0.5`, so every
        // grid sample is independent of (x, y) and easy to verify.
        let program = b"{ pop pop 0.5 0.5 0.5 }".to_vec();
        let func = Dict::new()
            .with("FunctionType", Object::Integer(4))
            .with(
                "Domain",
                Object::Array(vec![
                    Object::Real(0.0),
                    Object::Real(1.0),
                    Object::Real(0.0),
                    Object::Real(1.0),
                ]),
            )
            .with(
                "Range",
                Object::Array(vec![
                    Object::Real(0.0),
                    Object::Real(1.0),
                    Object::Real(0.0),
                    Object::Real(1.0),
                    Object::Real(0.0),
                    Object::Real(1.0),
                ]),
            )
            .with("__Program", Object::HexString(program));
        let dict = Dict::new()
            .with("ShadingType", Object::Integer(1))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with("Function", Object::Dict(func));
        let g = evaluate_gradient_shading(&dict, None).expect("gradient");
        let ShadingGradient::FunctionBased {
            domain,
            grid,
            samples,
            ..
        } = g
        else {
            panic!("expected function-based")
        };
        assert_eq!(domain, [0.0, 1.0, 0.0, 1.0]); // default
        assert_eq!(grid, (16, 16));
        assert_eq!(samples.len(), 256);
        // Constant mid-grey program → every sample ~128.
        for s in &samples {
            assert!((s.r as i32 - 128).abs() <= 1);
            assert_eq!(s.r, s.g);
            assert_eq!(s.g, s.b);
        }
    }

    /// A Type 4–7 mesh shading leaves `gradient` `None`; a Type 1–3
    /// shading leaves `mesh` `None` — the two surfaces are exclusive.
    #[test]
    fn gradient_and_mesh_are_exclusive() {
        let axial = Dict::new()
            .with("ShadingType", Object::Integer(2))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with(
                "Coords",
                Object::Array(vec![
                    Object::Real(0.0),
                    Object::Real(0.0),
                    Object::Real(1.0),
                    Object::Real(0.0),
                ]),
            )
            .with("Function", exp_black_to_white());
        assert!(evaluate_mesh_shading(&axial, None).is_none());
        assert!(evaluate_gradient_shading(&axial, None).is_some());
    }

    /// `sh` of a Type 2 axial shading surfaces the gradient on the
    /// `ContentShading` event (end-to-end through the operator).
    #[test]
    fn sh_surfaces_evaluated_gradient() {
        let sh1 = Dict::new()
            .with("ShadingType", Object::Integer(2))
            .with("ColorSpace", Object::Name("DeviceRGB".into()))
            .with(
                "Coords",
                Object::Array(vec![
                    Object::Real(0.0),
                    Object::Real(0.0),
                    Object::Real(72.0),
                    Object::Real(0.0),
                ]),
            )
            .with("Function", exp_black_to_white());
        let shadings = shading_res_with("Sh1", sh1);
        let bytes = b"q /Sh1 sh Q\n";
        let p = parse_with_shading(bytes, None, None, Some(&shadings));
        assert_eq!(p.shadings.len(), 1);
        assert!(p.shadings[0].mesh.is_none());
        let g = p.shadings[0].gradient.as_ref().expect("gradient surfaced");
        assert!(matches!(g, ShadingGradient::Axial { .. }));
    }

    /// Build a simple font with explicit per-code `/Widths` so the
    /// §9.4.4 advance can be exercised. Each ASCII code from
    /// `first_char` onward gets the given width (glyph-space units).
    fn simple_font_with_widths(first_char: i64, widths: &[i64]) -> Dict {
        let arr: Vec<Object> = widths.iter().map(|w| Object::Integer(*w)).collect();
        Dict::new()
            .with("Type", Object::Name("Font".into()))
            .with("Subtype", Object::Name("Type1".into()))
            .with("FirstChar", Object::Integer(first_char))
            .with("Widths", Object::Array(arr))
    }

    /// Two consecutive `Tj` operators on the same line: the second
    /// show's origin equals the first plus the sum of the first
    /// string's glyph advances (§9.4.4). Without the advance both
    /// would report the same x.
    #[test]
    fn consecutive_tj_advances_text_matrix_by_widths() {
        // 'A' = 65, 'B' = 66 — first_char 65, widths 500 / 250
        // (glyph-space thousandths).
        let f1 = simple_font_with_widths(65, &[500, 250]);
        let fonts = font_res_with("F1", f1);
        // Font size 10 ⇒ each unit-thousandth contributes size/1000.
        let bytes = b"BT /F1 10 Tf 0 700 Td (A) Tj (B) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 2);
        // First show at the run origin.
        assert!((p.text_shows[0].position.0 - 0.0).abs() < 1e-3);
        // Second show advanced by 'A' width = 500/1000 * 10 = 5.0.
        assert!(
            (p.text_shows[1].position.0 - 5.0).abs() < 1e-3,
            "got {}",
            p.text_shows[1].position.0
        );
        assert!((p.text_shows[1].position.1 - 700.0).abs() < 1e-3);
    }

    /// §9.6.5: a Type 3 font's `/Widths` are in glyph space and scaled
    /// into text space by the `/FontMatrix` horizontal component, not by
    /// the 1/1000 Type1 convention. A FontMatrix of `[0.01 …]` (ten
    /// times the default `0.001`) makes a stored width of 50 advance by
    /// `50 · 0.01 · size`, i.e. ten times what the /1000 rule would give.
    #[test]
    fn type3_font_advances_via_font_matrix() {
        let f1 = Dict::new()
            .with("Type", Object::Name("Font".into()))
            .with("Subtype", Object::Name("Type3".into()))
            .with("FirstChar", Object::Integer(65))
            .with("Widths", Object::Array(vec![Object::Integer(50)]))
            .with(
                "FontMatrix",
                Object::Array(vec![
                    Object::Real(0.01),
                    Object::Real(0.0),
                    Object::Real(0.0),
                    Object::Real(0.01),
                    Object::Real(0.0),
                    Object::Real(0.0),
                ]),
            );
        let fonts = font_res_with("F1", f1);
        // 'A' advance = width(50) · FontMatrix.a(0.01) · size(10) = 5.0.
        let bytes = b"BT /F1 10 Tf 0 700 Td (A) Tj (A) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 2);
        assert!(
            (p.text_shows[1].position.0 - 5.0).abs() < 1e-3,
            "got {}",
            p.text_shows[1].position.0
        );
    }

    /// A Type 3 font with the default `/FontMatrix [0.001 …]` advances
    /// exactly like a Type1 font of the same `/Widths` — the 1/1000
    /// equivalence the default matrix encodes.
    #[test]
    fn type3_default_font_matrix_matches_type1() {
        let f1 = Dict::new()
            .with("Type", Object::Name("Font".into()))
            .with("Subtype", Object::Name("Type3".into()))
            .with("FirstChar", Object::Integer(65))
            .with("Widths", Object::Array(vec![Object::Integer(500)]))
            .with(
                "FontMatrix",
                Object::Array(vec![
                    Object::Real(0.001),
                    Object::Real(0.0),
                    Object::Real(0.0),
                    Object::Real(0.001),
                    Object::Real(0.0),
                    Object::Real(0.0),
                ]),
            );
        let fonts = font_res_with("F1", f1);
        // 500 · 0.001 · 10 = 5.0, same as the Type1 width-500 case.
        let bytes = b"BT /F1 10 Tf 0 700 Td (A) Tj (A) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert!((p.text_shows[1].position.0 - 5.0).abs() < 1e-3);
    }

    /// Character spacing `Tc` adds to every glyph's advance (§9.3.2 /
    /// §9.4.4); word spacing `Tw` adds only to ASCII-space glyphs.
    #[test]
    fn tc_tw_feed_the_advance() {
        // Codes: space(32)=250, 'A'(65)=500. first_char 32, the
        // widths array spans 32..=65.
        let mut widths = vec![0i64; 66 - 32];
        widths[0] = 250; // space
        widths[65 - 32] = 500; // 'A'
        let f1 = simple_font_with_widths(32, &widths);
        let fonts = font_res_with("F1", f1);
        // Tc=2, Tw=3, size 10. Show "A A" (three glyphs); the second
        // Tj origin is the sum of all three advances:
        //   'A'  : (500/1000*10 + 2)        = 7
        //   ' '  : (250/1000*10 + 2 + 3)    = 7.5
        //   'A'  : (500/1000*10 + 2)        = 7
        // Second Tj origin = 7 + 7.5 + 7 = 21.5.
        let bytes = b"BT /F1 10 Tf 2 Tc 3 Tw 0 0 Td (A A) Tj (X) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 2);
        assert!(
            (p.text_shows[1].position.0 - 21.5).abs() < 1e-3,
            "got {}",
            p.text_shows[1].position.0
        );
    }

    /// Horizontal scaling `Tz` scales the whole horizontal advance
    /// (§9.3.4 / §9.4.4).
    #[test]
    fn tz_scales_the_advance() {
        let f1 = simple_font_with_widths(65, &[1000]);
        let fonts = font_res_with("F1", f1);
        // Tz 50 ⇒ Th = 0.5. 'A' advance = 1000/1000*10*0.5 = 5.0.
        let bytes = b"BT /F1 10 Tf 50 Tz 0 0 Td (A) Tj (A) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 2);
        assert!(
            (p.text_shows[1].position.0 - 5.0).abs() < 1e-3,
            "got {}",
            p.text_shows[1].position.0
        );
    }

    /// A `TJ` array applies the per-element kern adjustments (§9.4.3:
    /// `tx = −adj/1000 × Tfs × Th`) in addition to the glyph widths.
    #[test]
    fn tj_array_kern_adjusts_origin() {
        let f1 = simple_font_with_widths(65, &[1000, 1000]); // 'A','B'
        let fonts = font_res_with("F1", f1);
        // [ (A) -100 (B) ] : 'A' advance = 10, kern -(-100)/1000*10 =
        // +1, so total advance through the array before the next show
        // = 10 + 1 + (B advance 10) = 21.
        let bytes = b"BT /F1 10 Tf 0 0 Td [(A) -100 (B)] TJ (C) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 2);
        assert!(
            (p.text_shows[1].position.0 - 21.0).abs() < 1e-3,
            "got {}",
            p.text_shows[1].position.0
        );
    }

    /// A composite (Type0 / Identity-H) font advances by two-byte
    /// CIDs read from the `/W` array, defaulting to `/DW` (§9.7.4.3).
    #[test]
    fn type0_cid_font_advances_by_w_array() {
        // Descendant CIDFont: DW 1000, W = [ 1 [500] ] ⇒ CID 1 = 500.
        let cidfont = Dict::new()
            .with("Type", Object::Name("Font".into()))
            .with("Subtype", Object::Name("CIDFontType2".into()))
            .with("DW", Object::Integer(1000))
            .with(
                "W",
                Object::Array(vec![
                    Object::Integer(1),
                    Object::Array(vec![Object::Integer(500)]),
                ]),
            );
        let f0 = Dict::new()
            .with("Type", Object::Name("Font".into()))
            .with("Subtype", Object::Name("Type0".into()))
            .with("Encoding", Object::Name("Identity-H".into()))
            .with("DescendantFonts", Object::Dict(cidfont));
        let fonts = font_res_with("F0", f0);
        // Two 2-byte codes: <0001> (CID 1, width 500) then <0002>
        // (CID 2, default 1000). Show <00010002>, then a second show.
        // Advance = (500/1000 + 1000/1000) * 10 = 15.
        let bytes = b"BT /F0 10 Tf 0 0 Td <00010002> Tj (X) Tj ET\n";
        let p = parse_full(bytes, None, Some(&fonts));
        assert_eq!(p.text_shows.len(), 2);
        assert!(
            (p.text_shows[1].position.0 - 15.0).abs() < 1e-3,
            "got {}",
            p.text_shows[1].position.0
        );
    }

    // ── CIE-based colour spaces (§8.6.5.2–4) ──────────────────────

    /// The D65 white point used throughout the §8.6.5 examples.
    const D65: [f32; 3] = [0.9505, 1.0000, 1.0890];

    /// `srgb_encode` matches the IEC 61966-2-1 piecewise curve at its
    /// reference points: 0 → 0, 1 → 1, and the `0.0031308` linear-segment
    /// breakpoint maps continuously.
    #[test]
    fn srgb_encode_reference_points() {
        assert!((srgb_encode(0.0) - 0.0).abs() < 1e-6);
        assert!((srgb_encode(1.0) - 1.0).abs() < 1e-6);
        // At the breakpoint both branches agree to within rounding.
        let bp = 0.003_130_8;
        let lin = 12.92 * bp;
        assert!((srgb_encode(bp) - lin).abs() < 1e-4);
        // A mid value lands on the power segment (≈ 0.7354 for 0.5).
        assert!((srgb_encode(0.5) - 0.735_36).abs() < 1e-3);
    }

    /// A CalGray colour space's full-on gray (A = 1.0) under the D65
    /// white point maps to (very near) white; A = 0.0 maps to black.
    #[test]
    fn cal_gray_endpoints() {
        let white = cal_gray_color(D65, 1.0, 1.0);
        assert_eq!((white.r, white.g, white.b), (255, 255, 255));
        let black = cal_gray_color(D65, 1.0, 0.0);
        assert_eq!((black.r, black.g, black.b), (0, 0, 0));
    }

    /// A CalGray gamma > 1 darkens a mid gray relative to gamma 1 (the
    /// decode raises A to the gamma power before the white-point scale).
    #[test]
    fn cal_gray_gamma_darkens_midtones() {
        let g1 = cal_gray_color(D65, 1.0, 0.5).r;
        let g22 = cal_gray_color(D65, 2.2, 0.5).r;
        assert!(g22 < g1, "gamma 2.2 ({g22}) should darken vs 1.0 ({g1})");
    }

    /// The §8.6.5.3 CalRGB example (D65, 1.8 gammas, Trinitron matrix):
    /// the all-zero colour is black; full-on (1,1,1) is light.
    #[test]
    fn cal_rgb_example_endpoints() {
        let matrix = [
            0.4497, 0.2446, 0.0252, 0.3163, 0.6720, 0.1412, 0.1845, 0.0833, 0.9227,
        ];
        let gamma = [1.8, 1.8, 1.8];
        let black = cal_rgb_color(gamma, matrix, [0.0, 0.0, 0.0]);
        assert_eq!((black.r, black.g, black.b), (0, 0, 0));
        let white = cal_rgb_color(gamma, matrix, [1.0, 1.0, 1.0]);
        // The matrix columns sum to ≈ D65, so (1,1,1) is near-white.
        assert!(white.r > 230 && white.g > 230 && white.b > 230);
        // A pure-red input (A only) yields a red-dominant device colour.
        let red = cal_rgb_color(gamma, matrix, [1.0, 0.0, 0.0]);
        assert!(red.r > red.g && red.r > red.b);
    }

    /// Lab `g(x)` is continuous at the `6/29` breakpoint and cubes above
    /// it.
    #[test]
    fn lab_g_breakpoint_continuous() {
        let bp = 6.0 / 29.0;
        let cube = bp * bp * bp;
        assert!((lab_g(bp) - cube).abs() < 1e-6);
        // Above: g(0.5) = 0.125.
        assert!((lab_g(0.5) - 0.125).abs() < 1e-6);
    }

    /// L* = 100 with a* = b* = 0 under D65 is the reference white;
    /// L* = 0 is black. Both achromatic.
    #[test]
    fn lab_neutral_axis() {
        let white = lab_color(D65, [100.0, 0.0, 0.0]);
        assert_eq!((white.r, white.g, white.b), (255, 255, 255));
        let black = lab_color(D65, [0.0, 0.0, 0.0]);
        assert_eq!((black.r, black.g, black.b), (0, 0, 0));
        // A neutral mid grey (L*=50, a=b=0) is achromatic: r≈g≈b.
        let grey = lab_color(D65, [50.0, 0.0, 0.0]);
        assert!(grey.r.abs_diff(grey.g) <= 2 && grey.g.abs_diff(grey.b) <= 2);
    }

    /// Positive a* pushes the colour toward red/magenta (more red than
    /// green); positive b* toward yellow (more red+green than blue).
    #[test]
    fn lab_chroma_axes_direction() {
        let reddish = lab_color(D65, [60.0, 60.0, 0.0]);
        assert!(reddish.r > reddish.g, "+a* should be red-dominant");
        let yellowish = lab_color(D65, [80.0, 0.0, 70.0]);
        assert!(
            yellowish.r > yellowish.b && yellowish.g > yellowish.b,
            "+b* should be yellow (low blue)"
        );
    }

    // ── CIE space resolution from the colour-space dictionary ─────

    /// `[ /CalGray << /WhitePoint [..] /Gamma g >> ]` resolves to a
    /// `CalGray` carrying the white point + gamma; a missing Gamma
    /// defaults to 1.0; a missing/invalid WhitePoint collapses.
    #[test]
    fn cal_gray_resolves_from_array() {
        let arr = Object::Array(vec![
            Object::Name("CalGray".into()),
            Object::Dict(
                Dict::new()
                    .with(
                        "WhitePoint",
                        Object::Array(vec![
                            Object::Real(0.9505),
                            Object::Real(1.0),
                            Object::Real(1.089),
                        ]),
                    )
                    .with("Gamma", Object::Real(2.222)),
            ),
        ]);
        match color_space_from_object(&arr) {
            ColorSpaceKind::CalGray { white, gamma } => {
                assert!((white[1] - 1.0).abs() < 1e-6);
                assert!((gamma - 2.222).abs() < 1e-6);
            }
            other => panic!("expected CalGray, got {other:?}"),
        }
        // YW != 1.0 is non-conforming → Unknown.
        let bad = Object::Array(vec![
            Object::Name("CalGray".into()),
            Object::Dict(Dict::new().with(
                "WhitePoint",
                Object::Array(vec![
                    Object::Real(0.95),
                    Object::Real(0.5),
                    Object::Real(1.0),
                ]),
            )),
        ]);
        assert_eq!(color_space_from_object(&bad), ColorSpaceKind::Unknown);
    }

    /// End-to-end: a `/Resources /ColorSpace /CS0 = [/CalGray …]`,
    /// `/CS0 cs 1 sc` paints white (A = 1.0 full gray).
    #[test]
    fn cal_gray_end_to_end_white() {
        let arr = Object::Array(vec![
            Object::Name("CalGray".into()),
            Object::Dict(Dict::new().with(
                "WhitePoint",
                Object::Array(vec![
                    Object::Real(0.9505),
                    Object::Real(1.0),
                    Object::Real(1.089),
                ]),
            )),
        ]);
        let cs = Dict::new().with("CS0", arr);
        let bytes = b"q /CS0 cs 1 sc 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 255, 255));
    }

    /// End-to-end: a `/Lab` space with the default Range, `1 sc`-style
    /// three-component `scn` of `100 0 0` paints white.
    #[test]
    fn lab_end_to_end_white() {
        let arr = Object::Array(vec![
            Object::Name("Lab".into()),
            Object::Dict(
                Dict::new()
                    .with(
                        "WhitePoint",
                        Object::Array(vec![
                            Object::Real(0.9505),
                            Object::Real(1.0),
                            Object::Real(1.089),
                        ]),
                    )
                    .with(
                        "Range",
                        Object::Array(vec![
                            Object::Integer(-128),
                            Object::Integer(127),
                            Object::Integer(-128),
                            Object::Integer(127),
                        ]),
                    ),
            ),
        ]);
        match color_space_from_object(&arr) {
            ColorSpaceKind::Lab { range, .. } => {
                assert_eq!(range, [-128.0, 127.0, -128.0, 127.0]);
            }
            other => panic!("expected Lab, got {other:?}"),
        }
        let cs = Dict::new().with("CS0", arr);
        let bytes = b"q /CS0 cs 100 0 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 255, 255));
    }

    /// A CalRGB resource resolves and its `scn` reads three components;
    /// a missing Matrix defaults to identity, a missing Gamma to [1 1 1].
    #[test]
    fn cal_rgb_resolves_default_matrix() {
        let arr = Object::Array(vec![
            Object::Name("CalRGB".into()),
            Object::Dict(Dict::new().with(
                "WhitePoint",
                Object::Array(vec![
                    Object::Real(0.9505),
                    Object::Real(1.0),
                    Object::Real(1.089),
                ]),
            )),
        ]);
        match color_space_from_object(&arr) {
            ColorSpaceKind::CalRgb { gamma, matrix } => {
                assert_eq!(gamma, [1.0, 1.0, 1.0]);
                assert_eq!(matrix, [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]);
            }
            other => panic!("expected CalRgb, got {other:?}"),
        }
        // Identity matrix: (1,1,1) → XYZ (1,1,1), well above D65 white,
        // clamps to device white.
        let cs = Dict::new().with("CS0", arr);
        let bytes = b"q /CS0 cs 1 1 1 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        let (r, g, b) = first_fill_with_cs(bytes, &cs);
        assert!(r > 230 && g > 230 && b > 230);
    }

    // ── CIE-based alternates for Separation / DeviceN (§8.6.6.4–5) ─

    /// `[ /CalGray << /WhitePoint [..] >> ]` as an inline object for use
    /// as a Separation / DeviceN alternate.
    fn cal_gray_obj() -> Object {
        Object::Array(vec![
            Object::Name("CalGray".into()),
            Object::Dict(Dict::new().with(
                "WhitePoint",
                Object::Array(vec![
                    Object::Real(0.9505),
                    Object::Real(1.0),
                    Object::Real(1.089),
                ]),
            )),
        ])
    }

    fn lab_obj() -> Object {
        Object::Array(vec![
            Object::Name("Lab".into()),
            Object::Dict(Dict::new().with(
                "WhitePoint",
                Object::Array(vec![
                    Object::Real(0.9505),
                    Object::Real(1.0),
                    Object::Real(1.089),
                ]),
            )),
        ])
    }

    /// A Separation over a CalGray alternate (§8.6.6.4 permits a
    /// CIE-based alternate). The tint transform maps `t → A` (the gray
    /// component); at full tint A = 1.0 → device white, at zero → black.
    #[test]
    fn separation_calgray_alternate_renders() {
        // 1-in / 1-out: C0 = 0.0, C1 = 1.0 (identity tint → gray A).
        let tint = type2(&[0.0], &[1.0], 1.0);
        let arr = separation("Spot", cal_gray_obj(), tint);
        match color_space_from_object(&arr) {
            ColorSpaceKind::Separation { alt, .. } => {
                assert!(matches!(*alt, ColorSpaceKind::CalGray { .. }));
            }
            other => panic!("expected Separation/CalGray, got {other:?}"),
        }
        let cs = Dict::new().with("CS0", arr);
        // tint 1.0 → A = 1.0 → white.
        let bytes = b"q /CS0 cs 1 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 255, 255));
        // tint 0.0 → A = 0.0 → black.
        let bytes = b"q /CS0 cs 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 0, 0));
    }

    /// A two-colorant DeviceN over a Lab alternate. A Type 4 program
    /// maps the two tints to an L*a*b* triple: `(t0, t1) → (100·t0, 0,
    /// 0)` — a neutral grey ramp. At (1,*) L* = 100 → white.
    #[test]
    fn device_n_lab_alternate_renders() {
        // 2-in / 3-out. Stack starts [t0 t1]. Program:
        //   pop          → [t0]
        //   100 mul      → [100·t0]
        //   0 0          → [100·t0 0 0]  (L*, a*, b*)
        let tint = type4(
            &[0.0, 1.0, 0.0, 1.0],
            &[0.0, 100.0, -128.0, 127.0, -128.0, 127.0],
            "{ pop 100 mul 0 0 }",
        );
        let arr = device_n(&["C0", "C1"], lab_obj(), tint);
        match color_space_from_object(&arr) {
            ColorSpaceKind::DeviceN { alt, n_in, .. } => {
                assert_eq!(n_in, 2);
                assert!(matches!(*alt, ColorSpaceKind::Lab { .. }));
            }
            other => panic!("expected DeviceN/Lab, got {other:?}"),
        }
        let cs = Dict::new().with("CS0", arr);
        // (1, 0) → L* = 100, a*=b*=0 → white.
        let bytes = b"q /CS0 cs 1 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (255, 255, 255));
        // (0, 0) → L* = 0 → black.
        let bytes = b"q /CS0 cs 0 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 0, 0));
    }

    /// A DeviceN whose tint-transform output arity (2) doesn't match the
    /// CalRGB alternate's component count (3) is rejected at resolve time
    /// — the conservative black fallback applies.
    #[test]
    fn device_n_cie_alternate_arity_mismatch_rejected() {
        let cal_rgb = Object::Array(vec![
            Object::Name("CalRGB".into()),
            Object::Dict(Dict::new().with(
                "WhitePoint",
                Object::Array(vec![
                    Object::Real(0.9505),
                    Object::Real(1.0),
                    Object::Real(1.089),
                ]),
            )),
        ]);
        // 1-in / 2-out tint, but CalRGB needs 3 outputs.
        let tint = type2(&[0.0, 0.0], &[1.0, 1.0], 1.0);
        let arr = device_n(&["C0"], cal_rgb, tint);
        assert_eq!(color_space_from_object(&arr), ColorSpaceKind::Unknown);
    }

    /// An `/Indexed` space with a CIE-based (CalRGB) base (§8.6.6.3
    /// permits a CIE base). The 2-entry colour table holds two CalRGB
    /// triples; entry 0 = (1,1,1) → a bright colour through the identity
    /// CalRGB (XYZ (1,1,1) is brighter than the D65 white, so the sRGB
    /// reduction is near-white but not pure white), entry 1 = (0,0,0) →
    /// black.
    #[test]
    fn indexed_calrgb_base_renders() {
        let cal_rgb = Object::Array(vec![
            Object::Name("CalRGB".into()),
            Object::Dict(Dict::new().with(
                "WhitePoint",
                Object::Array(vec![
                    Object::Real(0.9505),
                    Object::Real(1.0),
                    Object::Real(1.089),
                ]),
            )),
        ]);
        // hival = 1; table = [255 255 255  0 0 0] (entry 0 max, 1 black).
        let table = Object::HexString(vec![255, 255, 255, 0, 0, 0]);
        let arr = Object::Array(vec![
            Object::Name("Indexed".into()),
            cal_rgb,
            Object::Integer(1),
            table,
        ]);
        match color_space_from_object(&arr) {
            ColorSpaceKind::Indexed { base, hival, .. } => {
                assert_eq!(hival, 1);
                assert!(matches!(*base, ColorSpaceKind::CalRgb { .. }));
            }
            other => panic!("expected Indexed/CalRGB, got {other:?}"),
        }
        let cs = Dict::new().with("CS0", arr);
        // index 0 → entry (1,1,1) → bright near-white.
        let bytes = b"q /CS0 cs 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        let (r, g, b) = first_fill_with_cs(bytes, &cs);
        assert!(r > 230 && g > 230 && b > 230, "entry 0 got ({r},{g},{b})");
        // index 1 → entry (0,0,0) → black.
        let bytes = b"q /CS0 cs 1 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        assert_eq!(first_fill_with_cs(bytes, &cs), (0, 0, 0));
    }

    /// An `/Indexed` space with a `/Lab` base: the table bytes decode
    /// through the L*/Range scaling. Entry 0's L* byte 255 → L*=100 with
    /// a*=b* mid-range (byte 128) → near-white; verifying the Lab branch
    /// of `indexed_color` is reached (no panic, a plausible bright
    /// colour).
    #[test]
    fn indexed_lab_base_decodes_table() {
        let lab = Object::Array(vec![
            Object::Name("Lab".into()),
            Object::Dict(
                Dict::new()
                    .with(
                        "WhitePoint",
                        Object::Array(vec![
                            Object::Real(0.9505),
                            Object::Real(1.0),
                            Object::Real(1.089),
                        ]),
                    )
                    .with(
                        "Range",
                        Object::Array(vec![
                            Object::Integer(-128),
                            Object::Integer(127),
                            Object::Integer(-128),
                            Object::Integer(127),
                        ]),
                    ),
            ),
        ]);
        // hival 0, one entry: L*-byte 255 (→100), a*/b* bytes 128
        // (→ ≈ -0.5, near-neutral). A bright near-white.
        let table = Object::HexString(vec![255, 128, 128]);
        let arr = Object::Array(vec![
            Object::Name("Indexed".into()),
            lab,
            Object::Integer(0),
            table,
        ]);
        let cs = Dict::new().with("CS0", arr);
        let bytes = b"q /CS0 cs 0 scn 0 0 m 10 10 l 10 0 l h f Q\n";
        let (r, g, b) = first_fill_with_cs(bytes, &cs);
        // L*=100 neutral → a bright achromatic colour.
        assert!(r > 230 && g > 230 && b > 230, "got ({r},{g},{b})");
    }
}
