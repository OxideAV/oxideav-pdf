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

use std::str;

use oxideav_core::vector::{
    DashPattern, FillRule, Group, LineCap, LineJoin, Node, Paint, Path, PathCommand, PathNode,
    Point, Rgba, Stroke, Transform2D,
};

use crate::error::PdfError;
use crate::objects::{Dict, Object};

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
    let mut state = State::new(None, None, None, None);
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
    let mut state = State::new(ext_gstate, None, None, None);
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
    let mut state = State::new(
        ext_gstate,
        font_resources,
        shading_resources,
        color_space_resources,
    );
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
}

struct Frame {
    /// Transform applied to this group via `cm` operators since `q`.
    transform: Transform2D,
    /// Children accumulated while this `q` is active.
    children: Vec<Node>,
    /// Clip path, if a `W`/`W*` was issued.
    clip: Option<Path>,
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
    /// Any space the parser doesn't resolve to a device family or a
    /// device-based Indexed space — `/Pattern`, a CIE-based CalRGB /
    /// CalGray / Lab space, a Separation / DeviceN space, or a
    /// `/Resources /ColorSpace` key whose definition the parser can't
    /// reduce to a device fallback.
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
    // The base must reduce to a device family — `components()` is `None`
    // for `Unknown`, and §8.6.6.3 forbids an Indexed (or Pattern) base,
    // so a nested `Indexed` is rejected too. The table's per-entry byte
    // count `m` follows from the base at lookup time (`indexed_color`);
    // a short table is tolerated by returning no colour for an
    // out-of-range slot rather than rejecting the whole space here.
    if base.components().is_none() || matches!(base, ColorSpaceKind::Indexed { .. }) {
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

impl<'a> State<'a> {
    fn new(
        ext_gstate: Option<&'a Dict>,
        font_resources: Option<&'a Dict>,
        shading_resources: Option<&'a Dict>,
        color_space_resources: Option<&'a Dict>,
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
            current_font: None,
            text_matrix: Transform2D::identity(),
            text_line_matrix: Transform2D::identity(),
            text_leading: 0.0,
            in_text_object: false,
            text_shows: Vec::new(),
            shadings: Vec::new(),
        }
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
        }
    }

    fn current(&mut self) -> &mut Frame {
        self.stack.last_mut().expect("at least the root frame")
    }

    fn push_q(&mut self) {
        self.stack.push(Frame::new());
    }

    fn pop_q(&mut self) {
        // Only pop if we have more than the root frame — otherwise
        // ignore the unbalanced `Q` per the writer's "permissive
        // recovery" stance.
        if self.stack.len() <= 1 {
            return;
        }
        let frame = self.stack.pop().unwrap();
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
                self.fill_paint = Some(Paint::Solid(rgb_from_unit(nums[0], nums[1], nums[2])));
            }
            b"RG" => {
                let nums = self.take_numbers(3)?;
                self.stroke_cs = ColorSpaceKind::DeviceRgb;
                self.stroke_paint = Some(Paint::Solid(rgb_from_unit(nums[0], nums[1], nums[2])));
            }
            b"g" => {
                let nums = self.take_numbers(1)?;
                self.fill_cs = ColorSpaceKind::DeviceGray;
                self.fill_paint = Some(Paint::Solid(rgb_from_unit(nums[0], nums[0], nums[0])));
            }
            b"G" => {
                let nums = self.take_numbers(1)?;
                self.stroke_cs = ColorSpaceKind::DeviceGray;
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
                    self.stroke_paint = p;
                } else {
                    self.fill_cs = ColorSpaceKind::DeviceCmyk;
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
                let paint = self.color_from_components(&self.fill_cs.clone());
                self.fill_paint = paint.or_else(|| {
                    self.fill_paint
                        .clone()
                        .or(Some(Paint::Solid(Rgba::opaque(0, 0, 0))))
                });
                self.operands.clear();
            }
            b"SC" | b"SCN" => {
                let paint = self.color_from_components(&self.stroke_cs.clone());
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
                self.fill_paint = initial_color_for(&self.fill_cs);
                self.operands.clear();
            }
            b"CS" => {
                self.stroke_cs = self.take_color_space_name();
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
            b"Tc" | b"Tw" | b"Tz" | b"Tr" | b"Ts" => {
                // Char-spacing / word-spacing / horizontal scale /
                // rendering mode / rise — round-128 doesn't track
                // these (they only affect glyph positioning, not the
                // decoded text or the run origin). Drop operands.
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
                self.emit_text_show(bytes, TextShowOp::Tj);
                self.operands.clear();
            }
            b"TJ" => {
                // [(s1) num1 (s2) num2 …] TJ — concatenate the
                // strings in array order. Per-element numeric
                // displacements affect glyph kerning but not the
                // decoded payload.
                let mut bytes = Vec::new();
                if let Some(Operand::Array(items)) = self.operands.last() {
                    for el in items {
                        if let ArrayElem::String(s) = el {
                            bytes.extend_from_slice(s);
                        }
                    }
                }
                self.emit_text_show(bytes, TextShowOp::TJ);
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
                self.emit_text_show(bytes, TextShowOp::SingleQuote);
                self.operands.clear();
            }
            b"\"" => {
                // aw ac string " — set word + char spacing (which we
                // don't track), implicit T*, then Tj.
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
                self.emit_text_show(bytes, TextShowOp::DoubleQuote);
                self.operands.clear();
            }

            // XObject paint ----------------------------------------
            b"Do" => {
                // /Imx Do — paint an image XObject. Round-3 doesn't
                // resolve XObject images yet (round-4+), drop.
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
                let ctm = self.effective_ctm();
                let clip = self.current_clip();
                self.shadings.push(ContentShading {
                    name,
                    shading_dict,
                    ctm,
                    clip,
                });
                self.operands.clear();
            }

            // Marked-content + everything else ---------------------
            _ => {
                self.operands.clear();
            }
        }
        Ok(())
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
        let fill_paint = if fill {
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
        self.current().children.push(node);
        self.operands.clear();
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
                // Tolerated-but-unhandled keys (Table 58):
                //   Type, RI, OP, op, OPM, Font, BG, BG2, UCR, UCR2,
                //   TR, TR2, HT, FL, SM, SA, BM, SMask, AIS, TK.
                _ => {}
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
            self.dispatch(kw)?;
            i = kw_end;
        }
        Ok(())
    }
}

impl Frame {
    fn new() -> Self {
        Self {
            transform: Transform2D::identity(),
            children: Vec::new(),
            clip: None,
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
        // `indexed_from_array` rejects a non-device base, and a nested
        // `Indexed` base is forbidden by §8.6.6.3, so these are
        // unreachable in practice; fall back to black for total safety.
        ColorSpaceKind::Indexed { .. } | ColorSpaceKind::Unknown => {
            Paint::Solid(Rgba::opaque(0, 0, 0))
        }
    })
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
}
