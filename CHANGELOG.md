# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4](https://github.com/OxideAV/oxideav-pdf/compare/v0.1.3...v0.1.4) - 2026-06-15

### Other

- evaluate /Separation colour space with Type 2/3 tint transforms (§8.6.6.4 + §7.10)
- round-306 — /FlateDecode on workspace compcol, drop flate2
- round-299 — text rise (Ts) folded into TextRun origin (§9.4.4)
- round-292 — marked-content operators (§14.6 Table 320)
- round-285 depth-mode profiling — exact-arithmetic fast path for content-stream numbers (§7.3.3)
- reader r275: resolve ICCBased + Indexed /Resources /ColorSpace in cs/CS
- round-267 — text render mode (Tr) on every TextRun (§9.3.6 Table 106)
- round-259 — sh shading-paint operator (§8.7.4.5)
- round-257 — /PrinterMark §12.5.6.20 writer (Table 362)
- round-252 — /Watermark §12.5.6.22 writer (Table 190 + Table 191 FixedPrint)
- drop release-plz.toml — use release-plz defaults across the workspace
- round-245 — /Sound §12.5.6.16 + §13.3 writer subtype
- add /FileAttachment writer (round 238, §12.5.6.15 Table 184)
- round-232 — Caret + Popup §12.5.6 annotation subtypes
- round-227 — three §12.5.6 line-family annotation subtypes (Line/Polygon/PolyLine)
- round-220 — §13.6.2 /3D annotation subtype (Table 298 + Table 299)
- round-215 — two §12.5.6 annotation subtypes (PrinterMark/TrapNet)
- round-209 — three §12.5.6 annotation subtypes (Sound/Movie/Screen)
- round-204 — two §12.5.6 annotation subtypes (Watermark/Redact)
- round-197 — six §12.5.6 annotation subtypes (Line/Polygon/PolyLine/Ink/Caret/Popup/FileAttachment)

### Added

- reader (round 311): the `/Separation` colour space (ISO 32000-1
  §8.6.6.4) is now evaluated when its alternate reduces to a device
  family. A single tint component (`0.0..=1.0`) is run through the
  space's tint-transform function (§7.10) to the alternate space's
  components, which render to RGB; the round-118 parser collapsed every
  Separation `sc`/`scn` to black. This adds a self-contained evaluator
  for the dictionary-shaped **Type 2** (exponential interpolation,
  §7.10.3 — `f(x) = C0 + x^N · (C1 − C0)`) and **Type 3** (stitching,
  §7.10.4 — `k` subdomains partitioned by `Bounds`, each child reached
  after the `Encode`/`Interpolate` input remap) functions, honouring
  the §7.10.1 Table 38 `Domain` (input clip) and optional `Range`
  (per-output clip). The Separation tint is clamped into the §8.6.6.4
  colour range, the initial colour is tint `1.0` per the spec, and the
  special colorant names `/All` and `/None` are recognised (`/None`
  produces no visible output). A Separation with a non-device alternate
  (CIE-based / Indexed / another special space) or a Type 0 (sampled) /
  Type 4 (PostScript-calculator) tint transform stays unevaluated with
  the conservative black fallback. The document-level resolver
  normalises `[ /Separation name alt tintTransform ]` (alternate
  prepared recursively, tint-transform dereferenced and — for Type 3 —
  its `/Functions` sub-functions prepared in turn) so the content
  parser sees a self-contained array, mirroring the round-275
  `ICCBased` / `Indexed` normalisation. Adds thirteen tests covering
  the function evaluator and the end-to-end Separation paths. DeviceN
  (multi-input tint transforms) and Type 0/4 functions remain a
  follow-up.

### Changed

- compression (round 306): `/FlateDecode` (ISO 32000-1 §7.4.4) now
  runs on `compcol`, the workspace-wide DEFLATE/zlib backend (the
  same crate png/tiff/mov/id3 already use), replacing the third-party
  `flate2`/`miniz_oxide` dependency. Every FlateDecode site — the
  reader's content-stream and cross-reference-stream inflate paths,
  and the writer's image-XObject, object-stream, cross-reference-
  stream, and embedded-file-stream deflate paths — routes through a
  single private `zlib` module (`flate_compress` / `flate_decompress`).
  Output is byte-identical across the swap: all 1061 tests, including
  the full write→read round-trip suite, pass unchanged.

### Added

- reader (round 299): text rise (`Ts`, ISO 32000-1 §9.4.4 + §9.3.7
  Table 105) is now folded into every `TextRun` returned by
  `DocumentReader::text_extraction`. The walker previously dropped the
  `Ts` operand (batched with `Tc`/`Tw`/`Tz` as geometry-only state),
  so a `4 Ts` superscript reported the same `position` as the
  surrounding baseline text. The walker now tracks the most-recent
  `Ts` and applies it to each run's origin per the text-rendering
  matrix — the rise translates the rendering origin by `Trise` along
  the text matrix's vertical basis `(c, d)`, so for the common
  axis-aligned matrix `position.1` is the baseline plus the rise, and
  for a rotated `Tm` the offset follows the rotated basis. The raw
  rise is also surfaced on the new `TextRun::text_rise` field so a
  layout / accessibility consumer can classify a run as
  super/subscript without reverse-engineering the offset. `Ts`
  persists across `BT`/`ET` (Table 105 — graphics-state text
  parameter) and is saved / restored by `q`/`Q`; an explicit `0 Ts`
  restores the §9.3.1 default baseline. Adds seven end-to-end tests in
  `tests/text_rise_round299.rs`. `TextRun` gains the `text_rise`
  field (additive).

### Changed

- reader (round 285, depth-mode profiling): content-stream numeric
  operands now convert straight from the scanned bytes through an
  exact-arithmetic fast path instead of the UTF-8 validation +
  general-purpose `str::parse::<f32>` round trip. A §7.3.3 number is
  `sign? digits? ("." digits?)?` — no exponent — so its value is
  `significand / 10^frac`; when the significand is < 2^24 (exact in
  f32) and the fraction is ≤ 10 digits (10^10 = 5^10·2^10 with 5^10 <
  2^24, so the divisor is exact in f32), IEEE-754 division of two
  exact operands is correctly rounded and therefore bit-identical to
  the general parser's result. Wider inputs fall back to `str::parse`
  unchanged, and a 2000-case generated parity test asserts the
  bit-identity contract. Sampling profile of the bytes→Scene path on
  120-page / ~220-segment-per-page writer-emitted documents ranked
  decimal→f32 conversion as the top hotspot (~33% of samples:
  `str::from_utf8` + the generic decimal-float parser); the fast path
  cuts whole-document `read_pdf_to_scene` wall-clock by ≈ 29–31%
  across all three container flavours (classic xref 2.91 → 2.06
  ms/doc, xref-stream 2.96 → 2.05, ObjStm 3.02 → 2.11) with
  byte-identical parsed-scene serialization and extracted-text hashes
  on the fixture corpus. The reproducible harness is
  `examples/profile_read.rs` (prints per-scenario wall-clock + FNV-1a
  output fingerprints; run before/after any reader change).

### Added

- reader (round 292): content-stream **marked-content operators**
  (ISO 32000-1 §14.6 Table 320) are now surfaced. The new
  [`parse_content_stream_full_with_properties`] entry point and the
  page walker dispatch `MP` (`tag`) / `DP` (`tag properties`)
  marked-content **points** and `BMC` (`tag`) / `BDC`
  (`tag properties`) / `EMC` sequence **brackets**, emitting one
  [`ContentMarkedContent`] per operator into
  [`ParsedContent::marked_content`] in stream order — carrying the
  operator discriminator ([`MarkedContentOp`]), the `tag` Name, the
  resolved property list (`DP`/`BDC` only), and the sequence-nesting
  depth. The `properties` operand is resolved per §14.6.2: an inline
  `<< … >>` dictionary is captured directly (a new content-stream
  inline-dictionary operand, parsed via the same object parser the
  body uses), and a `/Name` operand is dereferenced one hop through
  the page's `/Resources /Properties` subdictionary
  (`resolve_properties_resources`). The walker does not interpret the
  property list — its entries (`/OC`, `/MCID`, `/ActualText`, `/Alt`,
  …) stay verbatim so a downstream consumer can route optional-content
  membership or accessibility metadata as it sees fit. Nesting depth is
  tracked across `BMC`/`BDC`/`EMC` with a saturating counter so an
  unbalanced `EMC` is tolerated at depth 0. Like the round-128
  `text_shows` and round-259 `shadings`, the events surface from every
  `ParsedContent`-returning entry point; named-property resolution and
  the page-walker plumbing are what the new entry adds.
- reader (round 275): content-stream `cs` / `CS` operators now resolve
  `/Resources /ColorSpace` keys that reduce to a device fallback,
  closing two cases the round-118 parser collapsed to opaque black
  (ISO 32000-1 §8.6.8 Table 74). **`ICCBased`** (§8.6.5.5) maps to its
  `/Alternate` device space when present, otherwise to the profile's
  `/N` component count → DeviceGray (1) / DeviceRGB (3) / DeviceCMYK
  (4) — the exact fallback the spec authorises for a reader that does
  not process the embedded ICC profile (the profile bytes are never
  interpreted). **`Indexed`** (§8.6.6.3) with a device base lets a
  subsequent `sc`/`scn` index select an `m`-byte colour-table entry
  (index rounded to nearest + clamped into `0..=hival`; each byte
  scaled `0..255` → the base component range; bare `cs` initialises to
  entry 0). The new
  `reader::content::parse_content_stream_full_with_color_space` entry
  point takes the resolved `/ColorSpace` dict; a new document-level
  `resolve_color_space_resources` helper dereferences it one hop,
  replacing an ICC profile stream with its dictionary and an Indexed
  lookup stream (PDF 1.2) with its decoded bytes so the parser sees a
  self-contained value. CalRGB / CalGray / Lab (CIE-based) and
  Separation / DeviceN keep the black fallback — they need a
  gamut-mapping pass or tint-transform evaluation this round doesn't
  carry. The legacy entry points keep their round-118 behaviour.
- reader (round 267): text rendering mode (`Tr`) is now tracked by the
  text-extraction walker and surfaced on every `TextRun`
  (ISO 32000-1 §9.3.6, Table 106). A new typed `TextRenderMode` enum
  (`Fill` / `Stroke` / `FillStroke` / `Invisible` / `FillClip` /
  `StrokeClip` / `FillStrokeClip` / `Clip`) carries the mode in force
  at the moment of each show, defaulting to `Fill` per the §9.3.1
  default text state. The load-bearing case is `Invisible` (`3 Tr`),
  the unpainted OCR text layer scanned PDFs stack behind a page image:
  `TextRun::render_mode` lets a keyword-search consumer keep it while a
  "what the eye sees" consumer drops it via
  `TextRenderMode::paints_glyphs()` (false only for the `Invisible` and
  clip-only `Clip` modes). The mode persists across `BT`/`ET` (Table
  105 — `Tr` is a graphics-state text parameter, not a text-object
  parameter) and is saved / restored by `q`/`Q`.
  `TextRenderMode::from_operand` maps the Table 106 operand `0..=7` to
  its variant, falling back to `Fill` for out-of-range values.
- reader (round 259): one new content-stream operator in the §8
  walker — `sh` (ISO 32000-1 §8.7.4.5, "Paint the shape and colour
  shading described by a shading dictionary"). The walker now
  dispatches `name sh` rather than dropping it through the
  unknown-operator catch-all: each `sh` records one
  `ContentShading` event into a new `ParsedContent::shadings` slot
  capturing the shading-resource name (operand, leading `/`
  stripped), the resolved shading dictionary from
  `/Resources /Shading /<name>` (or `None` when unresolved), the
  effective CTM at the moment of paint (composed product of every
  enclosing `q` frame's `cm` accumulation, root-to-leaf), and the
  active `W`/`W*`-committed clip path (or `None`). The walker does
  **not** interpret the shading dictionary itself — `ShadingType`,
  `ColorSpace`, `Coords`, `Function`, etc. (§8.7.4.5 Tables 78..86)
  stay verbatim on the surface so a downstream consumer can route
  them through a dedicated shading-resolver. New public entry point
  `parse_content_stream_full_with_shading(content, ext_gstate,
  font_resources, shading_resources)` plumbs the page's resolved
  `/Resources /Shading` subdictionary in alongside the round-125
  `/ExtGState` and round-128 `/Font` resource paths; existing
  `parse_content_stream_full` forwards through it with `None`
  shading_resources so callers that don't care about shading paint
  see no behavioural change (their `parsed.shadings` slot still
  populates for every `sh` they encounter, just with
  `shading_dict = None`). Document-level page loading
  (`read_pdf_to_scene` and its password/certificate-bearing
  siblings) automatically plumbs the shading resources into the
  content-stream walker via the new `resolve_shading_resources`
  helper, mirroring the `resolve_ext_gstate` /
  `resolve_font_resources` one-hop-indirect contract: each per-name
  shading entry is resolved into a direct `Object::Dict`, with
  `Object::Stream` shading objects (Type 4..7 — free-form Gouraud,
  lattice Gouraud, Coons, and tensor-product patches — are
  stream-shaped per §8.7.4.5.5..8) surfacing their stream `dict` so
  the Table 78 + per-type entries stay reachable. Coordinates inside
  the shading dictionary are interpreted relative to the captured
  `ctm` (§8.7.4.5 NOTE 1: "All coordinates in the shading dictionary
  are interpreted relative to the current user space"), and the
  painted region is bounded by the captured `clip` per §8.7.4.5
  ("subject to the current clipping path"). Adds 9 new in-module
  tests in `src/reader/content.rs` covering the resolved-dict
  round-trip with a Type 2 (axial) shading shape, CTM capture from a
  single `cm` (spec §8.7.4.5.4 worked example numerics), nested-`q`
  CTM composition root-to-leaf, active-clip capture via a `re W n`
  sequence, the unknown-name `shading_dict = None` tolerance branch
  mirroring the round-128 unknown-`Tf` contract, the no-resources
  tolerance branch (legacy entry point still sees the event with
  populated CTM but `None` dict), stream-order multi-event ordering
  with per-event independent CTMs, the
  `parse_content_stream_full`-compat surface, and the no-`sh`
  empty-slot return shape. The new `ContentShading` /
  `parse_content_stream_full_with_shading` symbols re-exported from
  `crate::reader`.

- annotations (round 257): one new `/Subtype` encoder in the
  round-32 writer (`write_pdf_with_annotations`) — **PrinterMark**
  (§12.5.6.20 Table 362), closing the writer-side symmetry for the
  production-printer-mark annotation the round-215 reader already
  decodes. The new `WriterAnnotationKind::PrinterMark` variant
  carries the optional `/MN` (mark-name) `Name` selector — common
  Table 362 values include `/ColorBar`, `/RegistrationTarget`,
  `/CutMark`, `/PageInformation`, but the spec does not enumerate a
  closed set so any caller-supplied Name passes through verbatim.
  `mark_name: None` omits the `/MN` entry entirely (round-215
  reader's `find_entry(annot, "MN")` lookup falls into `_ => None`
  on absent), mirroring the absent-equals-default reader contract
  every other round-32 writer subtype uses. Validation rejects
  `Some(String::new())` per §7.3.5 (a `Name` token must be at least
  one byte; a zero-byte mark name would serialise as a bare `/`
  token round-tripping as the absent case). The Table-363
  `/MarkStyle` and `/Colorants` entries hang off the form-XObject
  appearance stream referenced from `/AP /N` (not the annotation
  dict), and stay routed through the §8.10 Form XObject walker —
  out of scope for this round just as they are for the round-215
  reader. Round-tripped through `read_pdf_annotations` (matching
  `mark_name` across the four `ColorBar` / `RegistrationTarget` /
  `CutMark` / `PageInformation` Table-362 examples, plus a bespoke
  `MyProductionTool_Marks_v3` value, and the absent-`/MN` `None`
  case). Adds 9 new tests in `tests/annotations_writer_round257.rs`
  covering the bare no-`/MN` round-trip, each of the four Table-362
  taxonomy values (`ColorBar` / `RegistrationTarget` / `CutMark` /
  `PageInformation`), a bespoke arbitrary-Name round-trip, a
  two-page composite (three `PrinterMark`s on page 0, an absent-`/MN`
  `PrinterMark` on page 1), a cross-subtype composite
  (`PrinterMark` + `Watermark` on one page exercising the
  round-215 reader's subtype dispatch), and the empty-`/MN`
  validation reject; +5 unit tests in `src/annotations.rs` covering
  the `Subtype` + redundant-`/Type` omission shape, the `/MN`
  emission for `Some`, the arbitrary-Name passthrough, the
  empty-string reject branch, and the `None` + non-empty `Some`
  acceptance set.

- annotations (round 252): one new `/Subtype` encoder in the
  round-32 writer (`write_pdf_with_annotations`) — **Watermark**
  (§12.5.6.22 Table 190 + Table 191), closing the writer-side
  symmetry for the fixed-print annotation the round-204 reader
  already decodes. The new `WriterAnnotationKind::Watermark` variant
  carries an optional `FixedPrintSpec` sub-dict mirroring the
  round-204 reader-side `FixedPrint` shape — `/Matrix` six-number
  affine transform, `/H` and `/V` printed-media translation
  percentages. Each `FixedPrintSpec` field is `Option<…>`; the writer
  omits any entry whose value is `None`, so a
  `Some(FixedPrintSpec::default())` produces the minimal
  `/Type /FixedPrint` marker dict and a write-then-read cycle through
  `read_pdf_annotations` lands on the same "absent → default" reader
  branch producer files use. Watermarks constructed with
  `fixed_print: None` skip the `/FixedPrint` entry entirely, matching
  the Table 190 wording: "If this entry is not present, the
  annotation shall be drawn without any special consideration for the
  dimensions of the target media." Validation rejects negative `/H`
  / `/V` (Table 191 "negative values should not be used") and any
  `/Matrix` slot that is not finite (NaN or infinity would describe
  an undefined affine transform per §8.3.4). Round-tripped through
  `read_pdf_annotations` (matching `FixedPrint.matrix`, `h`, `v`).
  Adds 7 new tests in `tests/annotations_writer_round252.rs` covering
  the bare no-`/FixedPrint` round-trip, the
  `Some(FixedPrintSpec::default())` minimum opt-in (writer emits only
  the `/Type /FixedPrint` marker; reader returns Table 191 defaults),
  a full `/Matrix` + `/H` + `/V` override round-trip, a two-page
  composite (Watermark with no `FixedPrint` on page 0, Watermark with
  `/H` = `/V` = 0.5 on page 1), and three validation rejects
  (negative `/H`, negative `/V`, NaN-in-`/Matrix`); +8 unit tests in
  `src/annotations.rs` covering the `FixedPrintSpec::default()`
  all-absent shape, the `/Subtype` + `/FixedPrint` omission shapes,
  the marker-only / full-override emission shapes, and every
  validation branch.

- annotations (round 245): one new `/Subtype` encoder in the
  round-32 writer (`write_pdf_with_annotations`) — **Sound**
  (§12.5.6.16 Table 185 + §13.3 Table 294), closing the writer-side
  symmetry for the multimedia-anchor pair the round-209 reader
  already decodes. The new `WriterAnnotationKind::Sound` variant
  carries the raw sample bytes, the sampling rate, channel count,
  bits-per-sample, encoding selector, and an optional `/Name` icon
  (default `/Speaker` per Table 185). The writer's pre-pass now
  materialises one `/Type /Sound` stream object per Sound annotation
  with the `/R` rate (required), `/C` channel count, `/B`
  bits-per-sample, and `/E` encoding entries, emitting only the
  non-default values so the round-209 reader's
  absent-equals-default contract is preserved on round-trip. A new
  `SoundEncoding` enum exposes the §13.3 Table 294 encoding choices
  (`Raw` default, `Signed`, `MuLaw`, `ALaw`). Validation rejects a
  non-finite sample rate, a non-positive sample rate, zero channels,
  zero bits-per-sample, and an empty sample buffer (all four
  produce a stream that would carry no playable content per §13.3).
  Round-tripped through `read_pdf_annotations` (matching `icon` and
  the `/Sound` stream `ObjectId`). Adds 10 new tests in
  `tests/annotations_writer_round245.rs` covering the
  default-fields-omitted bare form, the µ-law 8 kHz mono telephony
  configuration, a stereo 16-bit signed configuration that exercises
  every explicit Table 294 entry, A-law encoding, six validation
  rejects (zero rate, NaN rate, zero channels, zero bits,
  empty-buffer, negative rate is covered as a unit test), and a
  cross-subtype composite (Text + Sound + FileAttachment on one
  page); +10 unit tests in `src/annotations.rs` covering the
  `SoundEncoding::as_name` helper, the per-annotation
  pre-pass-allocated stream-id resolution in the Sound arm,
  default-icon emission, the defensive-error path on a missing
  sound-stream id, and every validation branch.

- annotations (round 238): one new `/Subtype` encoder in the
  round-32 writer (`write_pdf_with_annotations`) — **FileAttachment**
  (§12.5.6.15 Table 184), closing the writer-side symmetry for the
  embedded-file marker the round-197 reader already decodes through
  the round-33 `read_pdf_attachments` enumerator. The new
  `WriterAnnotationKind::FileAttachment` variant carries the file
  name, raw bytes, an optional `mime_type`, and an optional `/Name`
  icon (default `/PushPin` per Table 184). The writer now emits a
  pre-pass that materialises one `/Type /EmbeddedFile` stream
  (§7.11.4 Table 45 — FlateDecode-compressed when smaller), one
  `/Type /Filespec` dict (§7.11.3 Table 44 — `/F` PDFDocEncoded,
  `/UF` UTF-16BE-with-BOM, `/EF` pointing at the stream), and one
  catalog `/Names → /EmbeddedFiles` name-tree leaf entry (§7.7.4 +
  §7.9.6.2 — keys sorted byte-wise) per FileAttachment annotation,
  before the annotation dict itself emits `/FS` resolving to the
  filespec. Validation rejects an empty `file_name` (§7.11.2
  requires a non-empty name on every filespec). Round-tripped
  through `read_pdf_annotations` (matching `icon`, `file_name`,
  `filespec` ObjectId) and through `read_pdf_attachments` (matching
  body bytes). Three attachment-side helpers
  (`emit_embedded_file_stream`, `emit_filespec_dict`,
  `emit_embedded_files_name_tree`) are now `pub(crate)` so the
  annotations module reuses the round-33 byte shape verbatim
  instead of duplicating Table-44 / Table-45 layout logic.

- annotations (round 232): two new `/Subtype` encoders in the
  round-32 writer (`write_pdf_with_annotations`) — **Caret**
  (§12.5.6.11 Table 180) and **Popup** (§12.5.6.14 Table 183),
  closing the writer-side symmetry for the markup-editing pair the
  round-197 reader already decodes. `WriterAnnotationKind::Caret`
  carries the optional `/RD` rectangle differences (validated
  non-negative + inset must fit inside the outer `/Rect` per
  Table 180) and a new `CaretSymbol` enum modelling the Table 180
  `/Sy` choice (`None` default, `Paragraph` for `/Sy /P`); the
  writer omits `/Sy` on the default `None` variant so a write-then
  -read cycle through `read_pdf_annotations` yields the same
  "absent → \"None\"" reader branch. `WriterAnnotationKind::Popup`
  carries an optional `parent_index: Option<usize>` that the writer
  resolves to the actual on-wire object id of the parent markup
  annotation (the dispatch loop now allocates ids up front, then
  builds the annotation dicts under the pre-allocated ids so an
  earlier-in-the-slice Popup can reference a later-in-the-slice
  parent); validation rejects out-of-range, self-cycle, and
  Popup-pointing-at-Popup configurations. The Popup writer also
  omits `/Open` when the caller passes `false`, matching the
  Table 183 default. Adds 12 new tests in
  `tests/annotations_writer_round232.rs` covering bare-Caret /
  Caret-with-paragraph-symbol round-trip, a byte-level check that
  `/Sy` is absent on `CaretSymbol::None`, four Caret validation
  rejects, bare-Popup / Popup-with-Text-parent round-trip
  (asserting the reader-side `/Parent` indirect reference resolves
  back to the Text annotation's dict), a byte-level check that
  `/Open` is absent on `open: false`, three Popup validation
  rejects, and a cross-subtype composite (Caret + FreeText +
  open-Popup-on-FreeText on one page); +9 unit tests in
  `src/annotations.rs` covering the new `CaretSymbol::as_name`
  helper, the per-annotation pre-allocated-id resolution in the
  Popup arm, default-field-omission for Caret + Popup, and every
  new validation branch.
- annotations (round 227): three new `/Subtype` encoders in the
  round-32 writer (`write_pdf_with_annotations`) — **Line**
  (§12.5.6.7 Table 175), **Polygon** (§12.5.6.9 Table 178), and
  **PolyLine** (§12.5.6.9 Table 178), closing the writer-side
  symmetry for the round-197 reader's line-family decode. The new
  `WriterAnnotationKind::Line` carries the required `/L`
  four-real endpoints array plus every Table 175 optional field
  (`/LE` two-name array per Table 176, `/IC` interior colour,
  `/LL` / `/LLE` / `/LLO` leader-line geometry, `/Cap` caption
  flag, `/IT` intent name); `WriterAnnotationKind::Polygon` and
  `WriterAnnotationKind::PolyLine` carry the required `/Vertices`
  flat coordinate list (validated to be even-length ≥ 4) plus
  the Table 178 optional fields (`/LE` for PolyLine — Polygon
  closes back to its start so the spec entry is omitted — `/IC`
  interior colour, `/IT` intent). The writer is round-trip-tight:
  every default-value field omits its entry on the wire so a
  write-then-read cycle through `read_pdf_annotations` yields the
  same `AnnotationKind::Line` / `AnnotationKind::PolygonOrPolyLine`
  shape the round-197 reader test expects (e.g. `/Cap false` is
  emitted as an absent key, matching the reader's
  `matches!(find_entry(annot, "Cap"), Some(Object::Bool(true)))`
  branch). Adds 10 new tests in `tests/annotations_writer_round227.rs`
  covering minimal-required-fields round-trip on all three
  subtypes, a fully-populated Line, a fully-populated PolyLine, an
  Polygon-with-IC + intent, validation rejects (odd `/Vertices`
  count, single-vertex polyline), a byte-level check that the
  writer omits `/Cap` when the caller passes `cap: false`, and a
  cross-subtype enumeration on a single page; +4 unit tests in
  `src/annotations.rs` (the new `line_ending_pair` helper, two
  `validate_annotations` shapes, and a build-dict shape check).
  The reader is unchanged — round 197 already decodes these
  subtypes; round 227 closes the symmetric writer.
- annotations (round 220): `/Subtype /3D` decoder in the round-26
  generic annotation reader — **3D** (§13.6.2 Table 298, PDF 1.6 —
  3D artwork annotation, the means by which U3D / PRC artwork is
  embedded in a PDF). Before this round 3D annotations fell through
  to `AnnotationKind::Other { subtype: "3D" }`, so callers walking
  forensic / archival PDFs had to special-case the stringly-typed
  name. The new `AnnotationKind::ThreeD` variant surfaces the `/3DD`
  artwork reference (the §13.6.3 stream or §13.6.3.3 reference
  dictionary, preserved as `ObjectId` — this crate does not decode
  the 3D payload), the `/3DV` initial-view selector collapsed into
  a `ThreeDViewSelector` four-shape union (view-dict ref / `/VA`
  index / `/IN`-matching string / `F`/`L`/`D` symbolic, matching
  the four spec alternatives), the `/3DA` activation dictionary
  surfaced through a new `ThreeDActivation` struct that carries
  every Table 299 field (`/A`, `/AIS`, `/D`, `/DIS`, plus the
  PDF 1.7 `/TB` and `/NP` toolbar/navigation-panel flags), the
  `/3DI` interactive-use flag (default `true` per Table 298 when
  absent), and the `/3DB` 3D view box rectangle. The activation
  dict is resolved through `DocumentReader::deref` so both inline
  and indirect-ref forms decode uniformly. Unknown Name values for
  `/A` / `/AIS` / `/D` / `/DIS` are preserved verbatim so a
  forensic walk still sees what the producer wrote (the spec
  enumerations are open-ended in practice). The only annotation
  subtypes still falling through to `AnnotationKind::Other` are now
  the PDF 1.7 Adobe-extension `/RichMedia` (Annex H multimedia,
  needs Flash / video plumbing this crate does not carry) and the
  occasional `/Projection` extension — well into the long-tail
  forensic-only territory.
- annotations (round 215): two more `/Subtype` decoders in the
  round-26 generic annotation reader — **PrinterMark** (§12.5.6.20
  Table 362, PDF 1.4 — production printer's mark, e.g. registration
  target / colour bar / cut mark / page-information bar; the `/MN`
  mark-name Name is surfaced verbatim through a new
  `AnnotationKind::PrinterMark { mark_name }` variant so a
  colour-management tool can match its own taxonomy without
  pattern-matching on Table 362's open-ended set), and **TrapNet**
  (§12.5.6.21 Table 366, PDF 1.3 — page-level trap network; the
  reader surfaces `/LastModified` *or* the `/Version` +
  `/AnnotStates` pair — Table 366 makes them mutually exclusive
  but the reader stays tolerant of malformed annots — plus the
  optional `/FontFauxing` array of substituted-font references,
  enough for a trap-network regenerator to decide whether the
  cached traps are still valid). Before this round both subtypes
  fell through to `AnnotationKind::Other { subtype }`; pre-press /
  print-production audit walks were therefore invisible to the
  reader. The actual mark glyphs / trap geometry still live in the
  Form-XObject appearance streams referenced from `/AP /N`
  (§8.10) — round-215 is the annotation-dict-local metadata only.
  3D / RichMedia / Projection remain on the long-tail `Other` side
  since they need cross-crate plumbing (§13.6 3D graphics +
  ISO 32000-2 §13.7 rich-media). Adds two helper functions
  (`decode_indirect_ref_array` for `/Version` + `/FontFauxing` and
  `decode_optional_name_array` for `/AnnotStates`' Name-or-null
  shape per Table 366) and 10 new tests in
  `tests/annotations_round215.rs` covering both subtypes (explicit
  `/MN`, missing `/MN` falling back to `None`, the two TrapNet
  forms, malformed-element tolerance, empty-array vs absent-array
  distinction, and long-tail coexistence with 3D / RichMedia).
- annotations (round 209): three new `/Subtype` decoders in the
  round-26 generic annotation reader — **Sound** (§12.5.6.16
  Table 185 — required `/Sound` indirect stream surfaced as an
  `ObjectId` so callers re-resolve the §13.3 sound object through
  their own audio codec plumbing — this crate doesn't bundle an
  audio decoder — plus the `/Name` icon defaulting to `Speaker`
  per Table 185), **Movie** (§12.5.6.17 Table 186 — optional `/T`
  title used by §12.6.4.9 movie actions, the required `/Movie`
  dict preserved as an `ObjectId` so callers route the §13.4
  metadata through their own video plumbing, and `/A` collapsed
  to a new [`MovieActivation`] tri-state — `Play` for `true` or
  absent per Table 186 default, `Dont` for `false`, `Custom(id)`
  for an indirect reference to a §13.4 movie-activation dict),
  and **Screen** (§12.5.6.18 Table 187 — `/T` title, plus
  appearance-characteristics `/MK` + action `/A` +
  additional-actions `/AA` indirect refs preserved as
  `ObjectId`s so callers re-resolve through the round-36
  `actions` reader and the §12.6.4.13 rendition-action target).
  Before this round all three subtypes fell through to
  `AnnotationKind::Other { subtype }`; the long tail of audio /
  video annotation metadata was therefore invisible to PDF
  forensic / archival walks even though the underlying objects
  carry rich structural information. The reader is tolerant of
  malformed dicts (a Sound annotation that lacks the required
  `/Sound` stream surfaces `sound: None` with the default icon;
  a Movie annotation without `/Movie` enumerates with
  `movie: None` rather than being dropped). `/A` on a Screen
  annotation is *only* surfaced when it's an indirect reference;
  inline action dicts surface `action: None` and let callers
  walk the raw annotation dict themselves through
  [`reader::DocumentReader`] — the round-36 `actions` reader
  already handles indirect actions, so this keeps the surface
  small without losing recoverability. 3D / RichMedia / TrapNet
  / PrinterMark / Projection still fall through to
  `AnnotationKind::Other` since they need cross-crate plumbing
  (§13.6 3D graphics + ISO 32000-2 §13.7 rich-media). Adds 13
  new tests in `tests/annotations_round209.rs` covering absent
  vs. inline vs. indirect `/Sound`, the Table 186 `/A` tri-state
  (default-Play / explicit-true / explicit-false / indirect dict
  → Custom), UTF-16BE-with-BOM `/T` decode, the bare
  `/Subtype /Screen` zero-metadata case, the inline `/A`
  short-circuit, and cross-subtype enumeration alongside the
  round-197 / round-204 long tail. The round-26
  `unknown_subtype_falls_through_to_other` test and the round-197
  long-tail enumeration test were both updated to use `/3D` +
  `/RichMedia` as their unknown-subtype placeholders now that
  `/Sound` / `/Movie` / `/Screen` are structurally decoded.
- annotations (round 204): two new `/Subtype` decoders in the
  round-26 generic annotation reader — **Watermark** (§12.5.6.22
  Table 190 — optional `/FixedPrint` indirect ref surfaced through
  a new [`FixedPrint`] struct carrying Table 191's `/Matrix` six-
  number affine plus `/H` / `/V` media-relative percentages, each
  reverting to its Table 191 default when the entry is absent so
  partial dicts decode cleanly) and **Redact** (§12.5.6.23
  Table 192 — `/QuadPoints` content region, three-component
  DeviceRGB `/IC` interior fill, `/RO` overlay-appearance Form
  XObject preserved as an `ObjectId` for callers to re-resolve,
  `/OverlayText` + `/Repeat` + `/DA` + `/Q` overlay text). Before
  this round both subtypes fell through to
  `AnnotationKind::Other { subtype }`. The redact reader is
  non-destructive: it surfaces the metadata so a privacy-audit
  consumer can enumerate what *would* be removed by a PDF
  1.7-compliant redactor without performing the destructive
  content-removal step described by §12.5.6.23 NOTE. `/IC` that
  isn't exactly three DeviceRGB components is rejected to `None`
  rather than silently mis-typed (Table 192 explicitly constrains
  it to three numbers); a malformed six-number `/Matrix` reverts
  to the identity default rather than refusing the whole
  watermark. Movie / Sound / Screen / 3D / RichMedia still fall
  through to `AnnotationKind::Other` since they need cross-crate
  plumbing (audio/video streams + rendition actions +
  structure-tree integration). Adds 15 new tests in
  `tests/annotations_round204.rs` covering absent vs. inline vs.
  indirect `/FixedPrint`, Table 191 default propagation, the
  `/RO`-vs-`/IC`-vs-`/OverlayText` precedence shape from Table
  192, UTF-16BE-with-BOM `/OverlayText` decode, multi-quad
  `/QuadPoints` preservation, and cross-subtype enumeration
  alongside the round-197 long-tail.
- annotations (round 197): six new `/Subtype` decoders in the
  round-26 generic annotation reader — **Line** (§12.5.6.7
  Table 175 — `/L`, `/LE`, `/IC`, `/LL`, `/LLE`, `/LLO`, `/Cap`,
  `/IT`), **Polygon** + **PolyLine** (§12.5.6.9 Table 178 —
  `/Vertices`, `/LE`, `/IC`, `/IT`), **Ink** (§12.5.6.13 Table 182
  — `/InkList`, closes the round-trip with the round-32
  `write_pdf_with_annotations` Ink writer), **Caret** (§12.5.6.11
  Table 180 — `/RD`, `/Sy`), **Popup** (§12.5.6.14 Table 183 —
  `/Parent` indirect ref preserved as `ObjectId`, `/Open`), and
  **FileAttachment** (§12.5.6.15 Table 184 — `/Name` icon,
  filespec-resolved user-visible name via the same
  `/UF`-preferred / `/F` fallback path the round-33 attachment
  reader uses; closes the round-trip with the round-33
  `write_pdf_with_attachments` annotation marker). Before this
  round all six subtypes fell through to `AnnotationKind::Other
  { subtype }` — they round-tripped structurally (the writer's
  output decoded back as Other) but callers couldn't see the
  structured payload. The reader is tolerant of malformed dicts
  (a Line without `/L` surfaces `[0; 4]`; an Ink with an empty
  `/InkList` surfaces an empty Vec; a FileAttachment without
  `/FS` surfaces `file_name: None`). Movie / Sound / Screen /
  Redact / Watermark / 3D / RichMedia still fall through to
  `AnnotationKind::Other` since they need cross-crate plumbing
  (audio/video streams + rendition actions + structure-tree
  integration). Round 204 lifts /Redact and /Watermark out of
  this fallback set. Adds 16 new tests in
  `tests/annotations_round197.rs`; the round-32 writer test
  `ink_annotation_emits_inklist` was updated to assert the new
  structured shape (was previously asserting `Other("Ink")`).
- attachments (round 194): PDF 2.0 Associated Files — `/AFRelationship`
  on filespec dicts + `/AF` arrays on the catalog and per page
  (ISO 32000-2 §7.11.3 Table 44 + §14.13.3 + §14.13.4). New
  `AfRelationship` enum covers the eight enumerated values
  (`Source`, `Data`, `Alternative`, `Supplement`, `EncryptedPayload`,
  `FormData`, `Schema`, `Unspecified`); builder
  `Attachment::with_af_relationship(rel)` opts an attachment into the
  associated-files semantics. Page-level `/AF` is populated only when
  the attachment also carries a `FileAttachment` annotation on that
  page. Attachments without an explicit relationship preserve the
  round-33 byte shape exactly — no `/AFRelationship` Name, no `/AF`
  arrays. Reader-side `PdfAttachment` gains a matching
  `af_relationship: Option<AfRelationship>` field; vendor /
  second-class Names (§Annex E) surface as `None` rather than being
  coerced into one of the enumerated values. `qpdf --check` accepts
  the writer output. Eight new tests in
  `tests/af_relationship_round194.rs` cover the writer wire shape,
  all eight reader round-trips, the explicit-`Unspecified` vs.
  absence distinction, and qpdf validation.

## [0.1.3](https://github.com/OxideAV/oxideav-pdf/compare/v0.1.2...v0.1.3) - 2026-05-30

### Other

- §7.5.7 reject Type-2 entry whose container is itself Type-2 (fuzz fix)
- §9.4.3 TJ position-adjustment word-break recovery
- §9.10.3 ToUnicode CMap codespacerange (mixed-width decode)
- AGL Public Implementation Notes §3 uniXXXX/uXXXXXXXX escapes
- round 151: §7.5.7 compressed-object resolver cache (17.6× ObjStm open)
- round 148: Criterion bench harness for reader hot paths
- round 145: cargo-fuzz harness + two reader hardenings
- §7.5.8.3 XRef-stream forward-compat for unknown entry types
- resolve Tj/TJ text-show against /Resources /Font (Table 105+108+109)
- pin tests/fixtures/* to binary in .gitattributes
- resolve gs operator against /Resources /ExtGState (Table 58)
- §7.5.8.4 hybrid-reference /XRefStm merge in parse_xref
- honour cs/CS colour-space selection for sc/scn operators

### Other

- reader: §7.5.7 compressed-object resolver now rejects a Type-2 xref entry whose container is itself declared as a Type-2 entry, before re-entering the resolver (round 191). The spec normatively forbids nested object streams, so this configuration is statically detectable from the xref table — and pre-fix `resolve(N)` would call `decode_objstm_container(wanted=N, container=N)` which called `self.resolve(N)` again, looping until the call stack overflowed. Caught by the scheduled Fuzz workflow (run 26628044506) against pre-r188 master 98ff5a3 — a crafted hybrid-reference file (`tests/fixtures/fuzz_objstm_self_container_cycle.bin`) whose §7.5.8 XRef stream declared the catalog (object 1) as compressed inside container 1 triggered an `AddressSanitizer: stack-overflow` abort. The reader now surfaces a clean `PdfError::Other` citing the §7.5.7 rule. Also adds a hard `MAX_PARSE_DEPTH = 256` ceiling to `Parser::parse_array` / `parse_dict_or_stream` so a sibling crafted input of `[[[[...]]]]` thousands deep produces a recoverable error instead of overflowing the thread stack. Three new tests pin the fix (one fuzz regression, two parser depth-guard unit tests)
- reader: §9.4.3 `TJ` numeric position adjustments now drive inter-word-space recovery in text extraction (round 188). Per Table 109 + Figure 46 a `TJ` array number is expressed in thousandths of a text-space unit and is *subtracted* from the horizontal coordinate, so a negative number opens a rightward gap before the next glyph. Many producers encode the space between two words purely as such a displacement, with no literal space glyph in the strings; before this round the walker concatenated every `TJ` string fragment and dropped the numeric elements outright, extracting `helloworld` from text that reads `hello world`. The walker now accumulates the rightward gap (negated adjustment, summed across consecutive numeric elements) between string fragments and inserts a single U+0020 when it reaches a quarter-em (`WORD_BREAK_GAP = 250` thousandths). The threshold sits above the ISO 32000-1 Figure 46 intra-word kerns (−120 / −95 inside "AWAY", which stay joined) and below a typical space advance, so genuine word boundaries are recovered without false-splitting tightly-kerned runs. Positive adjustments (leftward / overlap) never break; an adjustment before the first fragment emits no leading space; a fragment already ending in a space is not doubled. Adds 6 end-to-end tests in `tests/tj_word_break_round188.rs` (large-gap break, small-kern join, positive-adjustment join, accumulated-kern threshold crossing, no double space, no dangling leading space)
- reader: §9.10.3 `/ToUnicode` CMap parser now captures `begincodespacerange ... endcodespacerange` entries and the `FontDecoder::ToUnicode` decode path uses them to select the per-byte-position width per Adobe Tech Note #5411 §2 + Tech Note #5014 §3.1's byte-component matching rule (round 182). Before this round the parser skipped every codespacerange block and the decoder assumed a single global width derived from the first `bfchar` source operand, silently mis-decoding any CMap that mixed a 1-byte ASCII passthrough with a 2-byte CJK territory (Adobe-Japan1 / Adobe-GB1 / Adobe-CNS1 / Adobe-Korea1 shape). The per-codespace match is byte-component (`<8140>..<FCFC>` accepts `81 75` but rejects `81 39` — low byte 0x39 below the [0x40..=0xFC] bound) — not a linear u32 interval, which is what the naive comparison would get wrong. Out-of-codespace input emits U+FFFD and advances one byte so subsequent in-codespace bytes still resolve. CMaps that omit the §9.10.3 mandatory codespacerange header (legacy / hand-crafted) keep decoding through the existing single-width fallback path. Adds 8 CMap-parser unit tests (single-width parse, mixed-width parse + width selection, component-wise reject of inter-range bytes, tolerant skip of mismatched-width entries, decode of all three paths, legacy fallback) plus 3 end-to-end integration tests in `tests/cmap_codespacerange_round182.rs`
- reader: AGL Public Implementation Notes §3 `uniXXXX...` / `uXXXXXXXX` Unicode-by-name escape forms now resolve through `glyph_name_to_unicode` for `/Encoding /Differences` overrides (round 175). `/uni201C` → U+201C; `/u1F600` → U+1F600 GRINNING FACE (supplementary planes reachable via the `u` 4-/5-/6-hex-digit form); multi-codepoint `uni`-chained groups concatenate per spec (`/uni20142019` → U+2014 U+2019). Surrogate halves (U+D800..=U+DFFF), the U+FFFF noncharacter, lowercase hex, and misshapen suffixes (non-multiple-of-4 length, off-codepoint width) are rejected per AGL PIN. The static AGL subset is consulted first so the common case stays allocation-free; `glyph_name_to_unicode` now returns `Option<Cow<'static, str>>`. Adds 7 unit tests covering the BMP single-group, BMP multi-group, supplementary-plane, surrogate-reject, FFFF-reject, malformed-input, and end-to-end `/Differences` paths
- reader: §7.5.7 compressed-object resolver now memoises each ObjStm container's Flate-decompressed payload + parsed header slot table on first access (`DocumentReader::objstm_cache`). Resolving the M compressed objects packed into one container drops from O(M²) (every call re-decompressed the full payload and re-parsed every header pair) to O(M) for the first call + O(1) per subsequent slot. Round-148 ObjStm bench (`open_fifty_page_object_stream`) measured 3.10 MiB/s → 54.6 MiB/s on macOS-aarch64 (≈ 17.6× wall-clock, -94% time); classic-xref + xref-stream paths unaffected (within ±3% noise)
- bench: Criterion bench harness under `benches/` with three binaries — `reader_open` drives `read_pdf_to_scene` against writer-emitted single-page / 10-page classic-xref docs and 50-page §7.5.8 xref-stream + §7.5.7 ObjStm docs; `xref` drives `parse_xref` against the same document families to isolate the §7.5.4 / §7.5.8 cross-reference parser cost; `content_stream` drives `parse_content_stream` against four synthetic operator-stream bodies (short single-rectangle path, 100 small polygons, 50 nested `q ... Q` save/restore brackets with `W n` clip paths, 500-group mixed-realistic mix). Writer cost paid in setup outside the timed region. Adds `criterion = "0.5"` dev-dep
- fuzz: cargo-fuzz harness with three targets — `parse` drives `read_pdf_to_scene` + `parse_linearization_dict` + `extract_inline_images_from_stream` + `parse_content_stream`; `xref` drives `parse_xref` + `find_startxref_offset` + `parse_xref_at` (incl. fuzz-derived out-of-range offsets); `decrypt` drives `read_pdf_to_scene_with_password` with a fuzz-derived password split out of the input. Seeded with the existing in-tree PDF fixtures (font_resources, gs_ext_gstate, hybrid_xrefstm) plus minimal scaffolds (header_only, startxref_only, empty). Daily 30-min split CI run via `.github/workflows/fuzz.yml`
- reader: §7.7.3.2 /Pages tree walk bounded by depth (≤ 256) and a visited-node set so a cyclic /Kids chain (caught by the round-145 fuzz harness, `tests/fixtures/fuzz_parse_pages_cycle.bin`) is rejected as a malformed tree instead of recursing forever
- reader: §8.9.7 inline-image dict parser clamps the §7.3.4.2 literal-string scan's `end` to the buffer length so a trailing `\` at the last byte no longer trips a slice-index panic (round-145 fuzz, `tests/fixtures/fuzz_parse_inline_image_string_escape.bin`)
- reader: §7.5.8.3 XRef-stream forward-compat — unknown entry types (≥3) now resolve as null-object references per spec instead of erroring out, and the W-array zero-width defaults (w[0]=0 ⇒ type 1, w[2]=0 ⇒ generation 0) get explicit coverage in `tests/xref_stream_round131.rs` alongside multi-subsection `/Index` and predictor-1 (default) Flate paths
- reader: §9.4 `Tj` / `TJ` / `'` / `"` text-show operators resolve fonts through `/Resources /Font` (round-128); a new `parse_content_stream_full(input, ext_gstate, fonts)` entry returns a `ParsedContent { root, text_shows }` carrying one `ContentTextShow` per show with the resolved font dict, font size, decoded operand bytes, text-matrix origin, and originating operator. Mirrors the round-125 `gs` plumbing shape; `BT`/`ET`/`Tf`/`Tm`/`Td`/`TD`/`T*`/`TL` text-state operators are honoured per §9.4.2 + Table 108. Legacy `parse_content_stream` / `parse_content_stream_with_resources` entry points keep their round-3 / round-125 no-op behaviour
- reader: §8.4.5 `gs` operator resolves named ExtGState dicts from `/Resources /ExtGState` and applies the Table-58 subset that maps onto the round-3 vector IR (LW / LC / LJ / ML / D / CA / ca); other Table-58 keys (BM, OP, SMask, RI, Font, …) are tolerated as no-ops per "any combination of parameter entries"
- reader: §7.5.8.4 hybrid-reference (`/XRefStm`) merge in `parse_xref`

## [0.1.2](https://github.com/OxideAV/oxideav-pdf/compare/v0.1.1...v0.1.2) - 2026-05-24

### Other

- convert DeviceCMYK k/K content-stream colour to RGB (§10.3.5)
- round 104: /DecodeParms /Predictor post-filter in decode_stream (§7.4.4.4)
- round 98: §7.4.4.2 LZWDecode stream filter
- round 95: §8.11 Optional Content (OCG / OCMD) reader
- resolve indirect stream /Length on the reader path
- document-action enumeration (ISO 32000-1 §12.6 + §12.7.5 + §7.7.4 + §7.9.6)
- inline-image extraction from PDF content streams (ISO 32000-1 §8.9.7 + §7.4)
- RFC 3161 Document Time-Stamp writer + reader (ISO 32000-1 §12.8.5 + RFC 3161 §2.4 + RFC 5652 §5)
- embedded file attachment writer + reader (ISO 32000-1 §7.11 + §3.10 + §12.5.6.15 + §7.7.4 + §7.9.6)
- general annotations writer (ISO 32000-1 §12.5.6)
- AcroForm interactive-widget writer (ISO 32000-1 §12.7)
- PDF /Sig annotation writer (ISO 32000-1 §12.7.4.5 + §12.8.1 + RFC 5652 §5 + §5.4 + §11.2)
- reading-order layout pass over Tagged PDF StructTreeRoot (ISO 32000-1 §14.6 + §14.7 + §14.8)
- simple-font /Encoding /Differences resolver wired into text extraction (ISO 32000-1 §9.6.6.1 + §D.2 + AGL v2.0)
- linearization param dict + hierarchy validator + PDF/A signals
- annotations beyond Link (Text/FreeText/Stamp/markup/geometry/Widget) + XMP packet field extraction (DC/XMP/PDF/PDF-A)
- PDF outline (bookmarks) tree + Link annotations
- CMS KARI X448 ECDH (RFC 7748 §5 + RFC 8410 §3 + RFC 8418 §2.1+§2.2)
- JPEG passthrough on /DCTDecode Image XObjects (ISO 32000-1 §7.4.8 + §8.9)
- PDF text extraction (ISO 32000-1 §9 + §9.10)
- PDF /Sig annotation reader (ISO 32000-1 §12.7.4.5 + §12.8.1)

### Added

- Round 118: **Colour-space selection for `sc` / `scn` content-stream
  operators** (ISO 32000-1:2008 §8.6.8 Table 74 + §8.6.4). The
  content-stream parser now tracks the nonstroking / stroking colour
  space established by the `cs` / `CS` operator and interprets the
  following `sc` / `scn` (or `SC` / `SCN`) operands against it.
  Previously every `sc`/`scn` collapsed to opaque black regardless of
  operands, so a document that set colour via `/DeviceRGB cs 1 0 0 sc`
  (rather than the `1 0 0 rg` shorthand) rendered black. The three
  device families are resolved by name — `/DeviceGray` (1 component),
  `/DeviceRGB` (3), `/DeviceCMYK` (4, via the §10.3.5 conversion) —
  including their abbreviated inline-image spellings (`G` / `RGB` /
  `CMYK`). The implicit-space operators (`g`/`rg`/`k` and `G`/`RG`/`K`)
  now also record their colour space so a subsequent bare `sc`/`scn`
  resolves correctly (§8.6.8: "g, rg, and k … set the … colour space
  implicitly"), and a bare `cs`/`CS` initialises the current colour to
  black per §8.6.4.2..4. The `/Pattern` colour space, a trailing
  `/Name` pattern operand (§8.7.3.3), CIE-based / Indexed / Separation
  / DeviceN spaces, and any unresolved `/Resources /ColorSpace` key all
  keep the conservative black fallback — resolving non-device spaces
  needs the page's `/Resources` dict, which this layer doesn't yet have.
  Verified with per-family `cs`+`sc` round-trips, the stroking `CS`+`SC`
  path, mid-stream colour-space switching, the Pattern `/P0 scn`
  fallback, an unresolved-resource-key fallback, the bare-`cs`
  initialisation, and the name-table mapping (10 new unit tests).

- Round 115: **DeviceCMYK content-stream colour** (`k` / `K`
  operators, ISO 32000-1:2008 §8.6.4.4 + §10.3.5). The content-stream
  parser previously discarded the four CMYK operands and fell back to
  opaque black for both fill (`k`) and stroke (`K`). It now converts
  the colour to the IR's DeviceRGB via the spec's §10.3.5
  ("Conversion from DeviceCMYK to DeviceRGB") formula — a simple
  operation that involves no black generation or undercolour removal:
  `red = 1 − min(1, cyan + black)`, `green = 1 − min(1, magenta +
  black)`, `blue = 1 − min(1, yellow + black)`. The new
  `rgb_from_cmyk` helper clamps each operand into `0.0..=1.0` first so
  an out-of-range value is substituted with the nearest valid one
  without error (§10.3.4 NOTE 4), and the `min(1.0, …)` ceiling caps
  ink+black so the sum cannot wrap past full saturation. Pure cyan
  now reconstructs as `(0,255,255)`, magenta `(255,0,255)`, yellow
  `(255,255,0)`, and `0 0 0 1 k` as black — instead of every CMYK
  colour collapsing to black. Verified with the pure-ink cases, the
  ink+black clamp, out-of-range clamping, and an end-to-end `k`/`K`
  content-stream round-trip.

- Round 104: **`/DecodeParms /Predictor` post-filter** (ISO 32000-1:2008
  §7.4.4.4) is now applied by the central `decode_stream` dispatch for
  `FlateDecode` / `LZWDecode` streams, not just the xref-stream path.
  New `oxideav_pdf::reader::filters::apply_predictor` + `PredictorParams`
  reverse the pre-compression differencing: PNG predictors
  (`/Predictor 10..=15`, Table 10 — the per-row tag chooses None / Sub /
  Up / Average / Paeth per Table 9, with neighbours taken
  `bpp = ceil(Colors * BitsPerComponent / 8)` bytes back) and TIFF
  Predictor 2 (`/Predictor 2` — per-component left differencing with
  sub-byte 1/2/4-bit components unpacked, summed modulo `2^bpc`, and
  repacked; 8- and 16-bit run byte/word-wise). `/Colors`,
  `/BitsPerComponent`, and `/Columns` come from the matching
  `/DecodeParms` slot (Table 8 defaults 1 / 8 / 1); `/Predictor 1` (or a
  stream with no `/DecodeParms`) is an unchanged passthrough. This
  un-mangles real-world Flate/LZW image XObjects and content streams
  that PDF writers difference before compressing. Verified with PNG
  (Sub / Up / Average / Paeth) and TIFF-2 (8-bit / RGB-interleaved /
  4-bit) round-trips plus an end-to-end `decode_stream` Flate+PNG-Up
  test.

- Round 98: **`LZWDecode` stream filter** (ISO 32000-1:2008 §7.4.4.2).
  New `oxideav_pdf::reader::filters::lzw_decode` /
  `lzw_decode_with_early_change` implement variable-width
  (9..=12-bit) MSB-first LZW — the TIFF 6.0 flavour — with the
  clear-table (256) / EOD (257) control codes, the KwKwK
  self-reference special case, the §7.4.4.3 `/EarlyChange` parameter
  (default `1`), and graceful partial decode on a truncated stream.
  The central `decode_stream` dispatch is reworked to apply all
  generic decompression filters (`FlateDecode` / `LZWDecode` /
  `ASCII85Decode` / `ASCIIHexDecode` / `RunLengthDecode`) in `/Filter`
  array order, so chains like `[/ASCII85Decode /LZWDecode]` (§7.4.4
  Example 2) round-trip, reading the per-slot `/DecodeParms`. The
  round-23 image-XObject and round-35 inline-image filter peels gain
  LZW too. Terminal image-codec filters (DCT / JPX / JBIG2 / CCITTFax)
  still route to the dedicated image walkers. Validated against the
  §7.4.4.2 Example 2 packed vector.

- Round 95: **Optional Content (OCG / OCMD) reader** (ISO 32000-1
  §8.11 + §7.7.2 Table 28). New `oxideav_pdf::reader::ocg` module +
  `DocumentReader::optional_content()` accessor walk the catalog's
  `/OCProperties` entry and surface every Optional Content Group (the
  toggleable "layers" PDFs use for CAD drawings, multi-language
  alternates, watermark / content separations) along with the default
  configuration dictionary and any alternate `/Configs`. Each group
  carries its indirect-object id, `/Name` UI label, optional
  `/Intent` (`View` / `Design`), and decoded `/Usage` subkeys
  (language / zoom / print / view / export / page-element). The
  configuration's `/BaseState` (`ON` / `OFF` / `Unchanged`) + `/ON` +
  `/OFF` arrays apply per §8.11.4.5 algorithm steps (a)+(b)+(c),
  yielding a `HashMap<ObjectId, bool>` of resolved visibility states.
  `OptionalContent::states_for_config(&alt)` re-resolves under an
  alternate configuration so callers can switch.
  Optional Content Membership Dictionaries (OCMDs, Table 99) are also
  covered — `parse_membership(reader, dict)` decodes the `/OCGs`
  reference list, the `/P` visibility policy (`AllOn` / `AnyOn` /
  `AnyOff` / `AllOff` — default `AnyOn`), and the `/VE` visibility
  expression (PDF 1.6 — `[/And e…]` / `[/Or e…]` / `[/Not e]`,
  recursively nested, 32-deep cycle guard).
  `OptionalContent::evaluate_membership(&mem)` plugs an OCMD into the
  current state map and returns the boolean visibility per
  §8.11.2.2's NOTE 2 (when `/VE` is present, the expression wins over
  `/P`). The configuration's `/Order` array parses into a tree of
  `OcOrderItem::Group` leaves and `OcOrderItem::Subtree { label,
  items }` nodes — both the labelled-collection form (Table 101
  EXAMPLE 1 — `[(Frog Anatomy) g1 g2]`) and the sublayer-nesting form
  (EXAMPLE 2 — `[g1 [g2 g3]]`) are recognised. PDFs without
  `/OCProperties` surface as `Ok(None)` so callers branch cleanly on
  "this document is not layered".  Verified against the §8.11 spec
  examples + hand-rolled minimal PDFs covering every state-resolution
  branch; 17 unit tests + 10 integration tests, all green.

- Round 91: **Indirect `/Length` resolution on stream objects** (ISO
  32000-1 §7.3.8.2 + §7.3.10 Example 3). The reader can now open PDFs
  whose stream dictionaries express `/Length` as an indirect reference
  (`<< /Length 8 0 R >>`) — the spec-blessed one-pass-writer shape
  used by every PDF whose encoder doesn't know the compressed body
  size before deflating it. `Parser::parse_indirect_with_length_resolver`
  takes a `&mut dyn LengthResolver` (blanket-impl'd for closures); the
  no-op `NoLengthResolver` keeps the resolver-less path (used by the
  xref-stream parser, where the xref table isn't built yet) rejecting
  the indirect form per §7.5.8's effective direct-integer requirement.
  `DocumentReader::resolve` wires a closure that looks up the
  length-carrying integer object via the xref table and patches the
  resolved direct integer back into the stream dictionary so
  downstream consumers (`decode_stream`, encryption length tracking)
  never see the stale `Reference`. Round-91 motivator:
  `docs/video/mpeg1/ISO_IEC_11172-2-MPEG1-Video-1993.pdf` (cited in
  the round-90 cli-convert smoke as failing to open) now reads
  end-to-end. `tests/indirect_length_round91.rs` covers (1) a
  hand-rolled minimal PDF with an indirect-length stream, (2) the
  same shape with `/Filter /FlateDecode` (the real-world combination),
  and (3) the MPEG-1 spec PDF — `verify_hierarchy` walks every page
  without error.

- Round 36: **Document-action enumeration** (ISO 32000-1 §12.6 + §12.7.5
  + §7.7.4 + §7.9.6). New `oxideav_pdf::reader::actions` module +
  `DocumentReader::actions()` accessor walk every place an action can
  hide in a PDF and surface each as a `PdfAction` with a typed
  `ActionTrigger` (where it lives) + `ActionKind` (what it does) +
  `chain_depth` (position in any `/Next` chain).

  Sources walked, in order: Catalog `/OpenAction` (single action — the
  destination-array form is purely navigation and is skipped), Catalog
  `/AA` (Table 197 — `WC`/`WS`/`DS`/`WP`/`DP`), per-page `/AA` (Table
  196 — `O`/`C`), per-annotation `/A` + `/AA` (Table 165 — `E`/`X`/`D`/
  `U`/`Fo`/`Bl`/`PO`/`PC`/`PV`/`PI`), per-form-field `/A` + `/AA` via
  the `/AcroForm /Fields` tree with `/Kids` recursion bounded at depth
  32, and finally the Catalog `/Names /JavaScript` name tree (Tables
  31 + §7.9.6.2 — depth-32 + 100k-leaf-cap safeguards).

  Each action's `/Next` chain (Table 198) is followed recursively to a
  depth bound of 32, with the carrier + every chained-`/Next` action
  surfacing as its own entry with progressively-higher `chain_depth`.
  An indirect-reference `visited` set cuts malformed cycles.

  Per-type payload decode covers Table 198's 18 action types:

  * `GoTo` (§12.6.4.2 Table 199) — page-index resolved for explicit
    `[<page-ref> mode args]` destinations through the round-25 outline
    page-index map; named-destination shape preserved verbatim.
  * `GoToR` (§12.6.4.3 Table 200), `GoToE` (§12.6.4.4 Table 201) —
    Filespec `/F` decoded (string OR `/UF`/`/F` from a `/Filespec` dict)
    + raw `/D` destination.
  * `Launch` (§12.6.4.5 Table 202) — `/F` filename + `/NewWindow`.
  * `URI` (§12.6.4.7 Table 206) — URI text + `/IsMap` flag.
  * `JavaScript` (§12.6.4.16 Table 217) — `/JS` source recovered from
    literal-string, hex-string, or stream form with multi-encoding BOM
    detection (UTF-8 `EF BB BF`, UTF-16BE `FE FF`, UTF-16LE `FF FE`,
    PDFDocEncoding fallback).
  * `SubmitForm` (§12.7.5.2 Tables 236+237) — `/F` URL + `/Flags`
    bitfield.
  * `ResetForm` (§12.7.5.3 Table 239), `ImportData` (§12.7.5.4 Table 240),
    `Hide` (§12.6.4.10 Table 209) — H flag default true, `/T` target,
    `Named` (§12.6.4.11 Table 211) — `/N` predefined-action name,
    `SetOCGState` (§12.6.4.12 Table 212) — On/Off/Toggle counter
    extracted from the state-array's flat `[mode ocg-ref … mode ocg-ref
    …]` form.
  * Unit variants for the remaining types (`Thread`, `Sound`, `Movie`,
    `Rendition`, `Trans`, `GoTo3DView`).
  * `Other { kind }` for unknown `/S` values — the raw action-type name
    surfaces verbatim so callers walking forensic / future-spec PDFs
    still get a complete enumeration.

  Why this surface matters: PDFs in the wild can trigger JavaScript on
  open (`/OpenAction`), navigate to a remote file (`/GoToR`), launch a
  binary (`/Launch`), or submit a form to a URL (`/SubmitForm`) — all
  forensic / sandbox-review indicators. Until this round, callers had
  to thread the round-25 `links()` (Link annots only) + round-26
  `annotations()` (annotation slots only) APIs together by hand. The
  round-36 walker unifies them into a single "what can this PDF *do*?"
  surface.

  New public surface (re-exported at the crate root):

  * `pub struct PdfAction { trigger: ActionTrigger, kind: ActionKind,
    chain_depth: u32 }` — one decoded action.
  * `pub enum ActionTrigger { CatalogOpen, Catalog { event },
    Page { page_index, event }, Annotation { page_index, subtype,
    event }, FormField { field_name, event }, NamedJavaScript { name } }`.
  * `pub enum ActionKind { GoTo, GoToR, GoToE, Launch, Thread, Uri,
    Sound, Movie, Hide, Named, SubmitForm, ResetForm, ImportData,
    JavaScript, SetOcgState, Rendition, Trans, GoTo3DView, Other }` —
    18 typed variants + the catch-all.
  * `pub fn DocumentReader::actions(&mut self) ->
    Result<Vec<PdfAction>, PdfError>` — entry point.
  * Free fn `oxideav_pdf::reader::actions(reader)` for callers that
    prefer the standalone surface.
  * Crate-root alias `oxideav_pdf::read_pdf_actions`.

  16 new integration tests in `tests/actions_round36.rs` covering
  every trigger source (Catalog OpenAction + AA, Page AA, Annotation A
  + AA, FormField A + AA, Names/JavaScript name tree), `/Next` chain
  expansion + cycle detection, JavaScript multi-encoding (literal +
  UTF-16BE-BOM hex), explicit `/GoTo` page-index resolution, `/Hide`
  flag default, `/SetOCGState` counter, unknown `/S` fall-through,
  and the empty-actions case. All pass.

- Round 35: **Inline-image extraction from PDF content streams** (ISO
  32000-1 §7.4 + §7.4.5 + §8.9.7 + Tables 92+93). Walks every page's
  content stream and surfaces every `BI … ID … EI` triplet as a
  [`PdfInlineImage`], byte-equivalent to what `pdfimages -all` extracts
  for the same construct. Complements the round-23 Image XObject
  walker (`/DCTDecode` XObjects) — the two paths together cover every
  raster shape PDFs ship.

  Why inline images need their own walker: §8.9.7 changes the lexer
  rules between `ID` and `EI` — the bytes are literal raw, with no
  delimiter / string / comment interpretation, terminated by the
  *first* occurrence of `EI` that's preceded by whitespace and
  followed by whitespace or EOF. The round-3 / round-22 content-
  stream tokenisers can't reach inside this region without
  mis-framing the data, so round 35 ships a dedicated parser.

  New public surface (re-exported at the crate root):

  * `pub struct PdfInlineImage { data, width, height, color_space,
    bits_per_component, filter, image_mask, source_page_index,
    source_page_obj }` — `data` is the raw payload after wrapping
    non-codec filters (`/A85` / `/AHx` / `/Fl` / `/RL`) are peeled;
    the terminal codec filter is left in place and reported through
    `filter`.
  * `pub enum InlineImageFilter { Raw, DctDecode, JpxDecode,
    Jbig2Decode, CcittFaxDecode }` — terminal codec filter tag.
  * `pub fn DocumentReader::inline_images(&mut self) ->
    Result<Vec<PdfInlineImage>, PdfError>` — entry point.
  * Free fn `oxideav_pdf::reader::inline_images(reader)` for callers
    that prefer the standalone surface.
  * Crate-root alias `oxideav_pdf::read_pdf_inline_images`.

  Filter coverage mirrors the round-23 XObject walker exactly:
  wrapping `/A85`, `/AHx`, `/Fl`, `/RL` are peeled before the
  payload reaches the caller; `/DCT`, `/JPX`, `/JBIG2`, `/CCF`
  remain in place and surface as `InlineImageFilter` tags. Both
  abbreviated (Table 93: `/G`, `/RGB`, `/CMYK`, `/I`, `/A85`, …)
  and long-form (`/DeviceGray`, `/DeviceRGB`, `/ASCII85Decode`, …)
  names are accepted on input per §8.9.7 paragraph 4.

  Internal refactor: hoisted the small set of byte-level filter
  decoders the round-23 image-XObject walker carried inline into a
  new shared `oxideav_pdf::reader::filters` module
  (`flate_decompress`, `ascii85_decode`, `ascii_hex_decode`,
  `run_length_decode`). Both the round-23 XObject path and the new
  round-35 inline path call into the same decoders, so adding a
  filter (`/LZW`, `/CCF`) in a future round gives both walkers the
  new coverage at once. Existing tests for the moved code remain in
  the new module, preserving coverage.

  Validation:

  * `tests/inline_images_round35.rs` — 13 integration tests:
    raw payload roundtrip, `/DCT` terminal-filter passthrough,
    `/A85` wrapping unwrapped to "Man " (canonical ISO 32000-1
    §7.4.3 example), `/RL` wrapping unwrapped, multi-page page-index
    tracking, embedded-`EI`-substring tolerance, `/IM true` image-
    mask defaults (1 bpc / DeviceGray), long-form key acceptance,
    no-inline-image and empty-document edge cases, comment-before-BI
    framing.
  * 13 module-level unit tests under
    `src/reader/inline_images.rs::tests`: keyword finder boundary
    rules (preceded / followed by whitespace), `EI`-locator framing,
    minimal extractor, DCT-payload preservation, image-mask
    defaults, long-form keys, `/A85` peel, multi-image stream,
    embedded-`EI`, unterminated-image error, missing-`/W` error.
  * 4 new unit tests under `src/reader/filters.rs::tests` cover the
    `RunLengthDecode` paths (literal run, repeat run, mixed runs,
    implicit EOF) that the round-23 walker didn't previously
    exercise.

  Provenance: ISO 32000-1:2008 §7.4 (Filters), §7.4.2 (ASCII Hex),
  §7.4.3 (ASCII85), §7.4.4 (Flate), §7.4.5 (RunLength), §7.4.8
  (DCT), §7.4.9 (CCITT Fax), §7.4.10 (JBIG2 / JPX), §8.9.7 (Inline
  Images, Tables 92 abbreviated keys + 93 abbreviated filter
  names). No third-party PDF library was consulted.

- Round 34: **RFC 3161 Document Time-Stamp writer + reader** (ISO
  32000-1 §12.8.5 + RFC 3161 §2.4 + RFC 5652 §5). Appends an
  incremental-update revision whose new `/FT /Sig` field carries a
  signature dictionary with `/Type /DocTimeStamp`, `/SubFilter
  /ETSI.RFC3161`, and a `/Contents <…hex…>` blob holding a full RFC
  3161 `TimeStampToken` (a CMS `SignedData` ContentInfo wrapping a
  `TSTInfo` SEQUENCE).

  The async TSA flow surfaces as a `TsaSigner` trait — implementations
  send a `MessageImprint { hash_alg, hashed_message }` to a remote
  TSA over HTTP and return the embedded `timeStampToken`. The in-tree
  `MockTsaSigner` short-circuits the network round-trip with a
  self-signed RSA-2048 / SHA-256 token — handy for tests and for
  self-contained roundtrips.

  New public surface:

  * `pub fn add_document_timestamp<T: TsaSigner>(pdf: &[u8], tsa: &T)
    -> Result<Vec<u8>, PdfError>` — entry point; uses the round-30
    byte-range placeholder pattern so a doc-timestamp coexists with
    one or more regular signatures (ISO 32000-1 §7.5.6).
  * `pub trait TsaSigner { fn timestamp(&self, imprint:
    &MessageImprint) -> Result<Vec<u8>, PdfError>; }`.
  * `pub struct MessageImprint { hash_alg, hashed_message }` per RFC
    3161 §2.4.1.
  * `pub struct MockTsaSigner` — reference impl that builds a self-
    signed RFC 3161 TST around a fresh RSA-2048 / SHA-256 SignerInfo.
  * `pub fn build_tst_info(imprint, policy_oid, serial, gen_time)
    -> Vec<u8>` — DER builder for the `TSTInfo` SEQUENCE.
  * `pub fn wrap_tst_in_signed_data(tst_info_der, signer_issuer_der,
    signer_serial, cert_chain, signed_attrs_body, signature_bytes)
    -> Vec<u8>` — RFC 5652 §5 CMS wrapper for the TST.
  * `pub struct PdfDocTimestamp` + `pub fn doc_timestamps(reader)
    -> Result<Vec<PdfDocTimestamp>, PdfError>` — reader-side surface
    that separates doc-timestamps from regular signatures.
  * `pub fn PdfSignature::is_doc_timestamp(&self) -> bool`.

  Validation:

  * `tests/doc_timestamp_round34.rs` builds a doubly-signed PDF
    (one round-30 regular signature + one round-34 doc-timestamp),
    re-opens the bytes, and asserts the reader surfaces each
    separately. The embedded TST's `messageImprint.hashedMessage`
    is byte-equal to SHA-256 of `pdf[a..a+b] ‖ pdf[c..c+d]`.
  * `qpdf --check` accepts the output (incremental-update revision
    is well-formed per ISO 32000-1 §7.5.6).
  * `openssl ts -verify` accepts the TST when present on PATH
    (with the self-signed-chain caveat — `messageImprint` matches
    in every observed run).

- Round 33: **Embedded file attachment writer + reader** (ISO 32000-1
  §7.11 + §3.10 + §12.5.6.15 + §7.7.4 + §7.9.6). Embeds arbitrary
  files inside the PDF as `/Type /EmbeddedFile` streams, registers
  each file in the catalog `/Names → /EmbeddedFiles` name tree, and
  optionally drops a `/FileAttachment` annotation marker (paperclip /
  push-pin) on a chosen page so a viewer can extract the file with a
  click.

  The embedded-file stream body is FlateDecode-compressed when that
  shrinks the result; otherwise stored cleartext. Each filespec
  carries `/F` (PDFDocEncoded name), `/UF` (UTF-16BE name — required
  for non-ASCII names per §7.11.2 Table 43), and `/EF /F` + `/EF /UF`
  pointing at the same embedded-file stream. The MIME type lowers to
  `/Subtype` per §7.11.4 Table 45 (the `/` byte is `#2F`-escaped per
  §7.3.5 Name encoding rules).

  Name-tree keys are emitted in byte-wise lexicographic order per
  §7.9.6.2. The writer uses a single leaf node — sufficient for the
  realistic case (typical PDF has fewer than ~64 attachments); a
  branching name tree would be needed only for very large
  attachment tables.

  New public surface (re-exported at the crate root):

  * `pub fn write_pdf_with_attachments(scene: &Scene, attachments:
    &[Attachment]) -> Result<Vec<u8>, PdfError>`
  * `pub fn write_pdf_with_annotations_and_attachments(scene: &Scene,
    annotations: &[Annotation], attachments: &[Attachment]) ->
    Result<Vec<u8>, PdfError>` (combined entry point)
  * `pub struct Attachment { name, bytes, mime_type, modified,
    annotation_page, annotation_rect, annotation_icon }` with
    builder-style `with_mime_type` / `with_modified` /
    `with_annotation` methods.
  * `pub fn read_pdf_attachments(reader: &mut DocumentReader) ->
    Result<Vec<PdfAttachment>, PdfError>` — walks the catalog →
    `/Names → /EmbeddedFiles` name tree (with bounded recursion for
    intermediate-node `/Kids`), surfaces each entry as a
    `PdfAttachment { name, mime_type, bytes, modified }` carrying
    the byte-exact decoded payload.

  Validation:

  * Every test under `tests/attachments_round33.rs` round-trips
    attachments through the writer + reader pair and asserts the
    payload bytes are byte-exact.
  * `qpdf --check` accepts the produced PDFs; `qpdf --json` lists
    each embedded file by name.
  * `pdfinfo` accepts the output.

  Tests:

  * `two_attachments_roundtrip_through_reader` — .txt + .png across
    a 2-page document.
  * `empty_attachments_list_emits_no_names_entry` — defensive: no
    catalog `/Names` when nothing to attach.
  * `file_attachment_annotation_lands_on_correct_page` — paperclip
    marker emits on the requested page.
  * `out_of_range_annotation_page_errors` — defensive page-index
    bound check.
  * `name_tree_keys_emitted_in_byte_sorted_order` — §7.9.6.2
    name-tree key ordering invariant.
  * `qpdf_check_accepts_attachments_pdf` /
    `qpdf_json_lists_embedded_files` — external validation gated
    on `qpdf` being on `PATH`.
  * `pdfinfo_accepts_attachments_pdf` — external validation gated
    on `pdfinfo` being on `PATH`.

- Round 32: **General annotations writer** (ISO 32000-1 §12.5.6).
  Symmetric writer-side counterpart of the round-26 generic
  annotation reader. Where round 25 emitted only `/Subtype /Link`
  (in-document destinations) and round 31 emitted `/Subtype /Widget`
  (interactive form fields), round 32 covers the rest of the
  §12.5.6 subtype taxonomy that authoring tools produce in the wild:

  * **`/Text`** sticky-note (§12.5.6.4, Table 172) —
    `AnnotationKind::Text` with `/Contents`, `/Name` icon
    (defaulting to `Note`), and `/Open`.
  * **`/Link`** external-URI hyperlink (§12.5.6.5, Table 173) —
    `AnnotationKind::Link` lowers to `/A << /S /URI /URI (uri) >>`.
    (In-document goto-destination links keep the richer round-25
    `LinkAnnotationSpec` surface.)
  * **`/FreeText`** in-page text overlay (§12.5.6.6, Table 174) —
    `AnnotationKind::FreeText` with `/Contents`, `/DA` default
    appearance, and `/Q` quadding via `FreeTextQuadding {Left, Center,
    Right}` (0/1/2 per Table 174).
  * **`/Highlight`** / **`/Underline`** / **`/Squiggly`** /
    **`/StrikeOut`** text-markup family (§12.5.6.10, Table 179) —
    each variant carries `/QuadPoints` as `Vec<[f32; 8]>` (one quad
    per region) flattened into the spec's `8N`-real array.
  * **`/Stamp`** rubber-stamp (§12.5.6.13, Table 184) —
    `AnnotationKind::Stamp` with `/Name` icon (defaulting to `Draft`)
    + optional `/Contents` description.
  * **`/Square`** / **`/Circle`** geometric markup (§12.5.6.8,
    Table 177) — `/IC` interior colour + `/BS /W` line-width.
  * **`/Ink`** freehand scribble (§12.5.6.13, Table 185) —
    `AnnotationKind::Ink` with `/InkList` (each stroke is a flat
    list of `[x0, y0, x1, y1, …]` reals).

  Every annotation also carries the Table 164 cross-subtype fields:
  `/T` author, `/M` modified-date string (raw PDF date form per
  §7.9.4), `/F` flag word (defaulting to 4 = Print bit 3),
  `/C` colour, and `/Border` (defaulting to `[0 0 0]`).

  New public surface under `oxideav_pdf::annotations` (re-exported
  at the crate root):

  * `pub fn write_pdf_with_annotations(scene: &Scene, annotations:
    &[Annotation]) -> Result<Vec<u8>, PdfError>`
  * `pub struct Annotation { source_page_index, rect, author,
    modified, flags, colour, border, kind }`
  * `pub enum AnnotationKind` (re-exported as `WriterAnnotationKind`
    at the crate root to avoid colliding with the reader's
    `AnnotationKind`)
  * `pub enum FreeTextQuadding { Left, Center, Right }`

  Tests under `tests/annotations_writer_round32.rs`:

  * `text_annotation_roundtrips_through_reader` — `/Text` +
    `/Contents` + `/Open` + `/Name` round-trip via the round-26
    reader.
  * `link_uri_annotation_roundtrips_through_reader` — `/Link`
    `/A /S /URI` decode by the round-25/26 link target decoder.
  * `freetext_annotation_roundtrips_with_quadding` — `/FreeText`
    `/DA` + `/Q` round-trip.
  * `highlight_annotation_carries_quadpoints` — 8N `/QuadPoints`
    array shape.
  * `underline_squiggly_strikeout_all_round_trip` — every
    text-markup variant.
  * `stamp_annotation_carries_icon_name` +
    `stamp_without_icon_defaults_to_draft` — Table 184 icon
    behaviour.
  * `square_and_circle_annotations_round_trip` — geometric markup
    with interior colour + line width.
  * `ink_annotation_emits_inklist` — `/Ink` survives round-trip
    and surfaces via the reader's `Other("Ink")` fallthrough.
  * `annotations_across_multiple_pages_land_on_correct_pages` —
    `source_page_index` routes annotations to the right page's
    `/Annots` array.
  * `rejects_annotation_on_out_of_range_page`,
    `rejects_ink_with_no_strokes`,
    `rejects_ink_with_odd_coord_count`,
    `rejects_empty_text_markup_quadpoints` — error-path coverage.
  * `qpdf_check_accepts_mixed_annotation_pdf` — external `qpdf
    --check` oracle accepts a PDF carrying Text + Link + FreeText
    + Highlight + Stamp + Square + Ink in one document.

- Round 31: **AcroForm interactive-widget writer** (ISO 32000-1 §12.7).
  Writer-side counterpart of the round-26 `AnnotationKind::Widget`
  reader. Given a `Scene` in pages mode + a slice of `FormField`
  specs, [`oxideav_pdf::write_pdf_with_form`] emits a PDF whose
  Catalog carries `/AcroForm` and whose page-level `/Annots` arrays
  carry the matching widget annotations.

  All four canonical field types per §12.7.4 land:

  * **Text field** (`/FT /Tx`, §12.7.4.3) — `FormFieldText` with
    optional default value, `/MaxLen`, `/Q` justification
    (`FieldJustification::{Left,Center,Right}` → 0/1/2 per Table 222),
    and `/Ff` bit 12 (multi-line) per Table 228.
  * **Checkbox** (`/FT /Btn`, §12.7.4.2.3) — `FormFieldCheckbox`
    keyed by `/Yes` (checked) and `/Off` (unchecked) appearance states
    per Table 228. `/V`, `/DV`, and `/AS` are kept consistent.
  * **Radio group** (`/FT /Btn` with `/Ff` Radio + NoToggleToOff bits,
    §12.7.4.2.2) — `FormFieldRadioGroup` becomes one aggregate field
    with `/Kids` referring to one widget annotation per option; the
    selected option's `/AS` carries its export-value Name, the others
    carry `/Off`.
  * **Choice** (`/FT /Ch`, §12.7.4.4) — `FormFieldChoice` with
    `/Opt` array, optional `/V`, and `/Ff` bit 18 (Combo) per Table 230.
  * **Signature** (`/FT /Sig`, §12.7.4.5) — `FormFieldSignature`
    wraps a `Box<dyn Signer>` + `SignerIdentity`; re-uses the
    round-30 `/Contents` placeholder pattern with a size-stable layout
    (`Object::HexString` of `CONTENTS_HEX_LEN/2` bytes for the
    placeholder, all four `/ByteRange` slots emitted as
    `BYTE_RANGE_SLOT_MAX = 99_999_999` so the array body has a fixed
    8-digit-per-slot byte width). One signature field per call.

  The AcroForm dict carries `/Fields`, `/DA "(/Helv 12 Tf 0 g)"` per
  §12.7.3.3 (caller can override per-field via `default_appearance`),
  `/NeedAppearances true` (so viewers regenerate `/AP` from `/DA` at
  open time — keeps the writer from having to draw glyph-perfect
  appearance streams), and `/SigFlags 3` (SignaturesExist | AppendOnly)
  when a signature field is present.

  New public surface under `oxideav_pdf::acroform` (re-exported at
  the crate root):

  * `pub fn write_pdf_with_form(scene: &Scene, form_fields:
    &[FormField]) -> Result<Vec<u8>, PdfError>`
  * `pub enum FormField { Text, Checkbox, RadioGroup, Choice,
    Signature }`
  * `FormFieldText`, `FormFieldCheckbox`, `FormFieldRadioGroup`,
    `RadioOption`, `FormFieldChoice`, `FormFieldSignature`
  * `FieldJustification { Left, Center, Right }`

  Tests under `tests/acroform_writer.rs`:

  * `text_field_emits_valid_acroform` — `/AcroForm` + `/FT /Tx` +
    value round-trip through the round-26 reader.
  * `checkbox_in_checked_state_renders` — `/V /Yes` after roundtrip;
    `checkbox_in_unchecked_state_renders` — `/V /Off`.
  * `radio_group_emits_consistent_state` — exactly one `/AS` is the
    selected export value, the others are `/Off`.
  * `choice_field_round_trips` — `/Opt` array, `/V`, and combo `/Ff`
    bit emit.
  * `signature_field_combines_with_sig_writer` — full sign + verify
    round-trip with RSA-PKCS#1 v1.5 + SHA-256.
  * `qpdf_check_accepts_text_and_checkbox_form` — external
    `qpdf --check` oracle.
  * `rejects_field_on_out_of_range_page`,
    `rejects_multiple_signature_fields` — error-path coverage.

- Round 30: **PDF `/Sig` annotation writer** (ISO 32000-1 §12.7.4.5 +
  §12.8.1 + RFC 5652 §5 + §5.4 + §11.2). Symmetric encoder side of
  the round-21 reader + round-27 verifier: given an
  [`oxideav_scene::Scene`] + a [`Signer`] + a signer-cert chain, the
  new writer emits a signed PDF whose AcroForm contains a `/FT /Sig`
  terminal field whose `/V` points at a signature dictionary
  (`/Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached`)
  carrying valid `/ByteRange` placeholders + a hex-encoded CMS
  `SignedData` `ContentInfo` blob. The classic "ByteRange-placeholder
  fill-in" pattern of §12.8.1.1 is implemented end-to-end:

  Step 1 — the base PDF is rendered via the existing
  `write_pdf_from_scene`.

  Step 2 — an incremental-update revision (§7.5.6) is appended that
  overrides the Catalog with `/AcroForm <ref>`, plus an AcroForm
  dict (`/Fields [<sig-field-ref>] /SigFlags 3`), a Sig form
  field (`/FT /Sig /T (Signature1)`), and a Sig dictionary with
  fixed-width `/ByteRange` (4 × 10-digit slots) +
  `/Contents <0…0>` (8192 hex chars = 4096 raw bytes — enough
  for any RSA-2048 / ECDSA-P256 SHA-256 SignedData with a single
  signer + cert).

  Step 3 — `/ByteRange` is patched in place with the actual offsets
  (the four integers themselves are inside the signed range, so they
  reach their final value BEFORE the hash is computed).

  Step 4 — the bytes named by `/ByteRange` are SHA-256-hashed, the
  hash is wrapped into a CAdES-BES-style `signedAttrs` SET
  (`contentType` 1.2.840.113549.1.9.3 = id-data, `messageDigest`
  1.2.840.113549.1.9.4 = SHA-256(signed) per RFC 5652 §11.2), the
  SET is canonical-re-tagged from `[0] IMPLICIT` to the universal
  SET tag per §5.4 and hashed, and the resulting digest is signed by
  the `Signer`.

  Step 5 — the signature is wrapped in a CMS `SignedData`
  `ContentInfo` (version=1, single SignerInfo,
  `IssuerAndSerialNumber` slot, full cert chain in the
  SET-of-CertificateChoices field, detached `eContent`),
  hex-encoded, and overwritten into the `/Contents` placeholder
  (length-preserving — the bytes between `<` and `>` are the
  EXCLUDED range under `/ByteRange`, so this write does not
  invalidate the hash computed in step 4).

  New public surface under `oxideav_pdf::sig`:

  * `pub trait Signer { fn algorithm() -> SigningAlgorithm; fn
    sign(&self, tbs_hash: &[u8]) -> Result<Vec<u8>, PdfError>; }`
    — abstract signing primitive; user plugs in whatever crypto
    stack they want (`ring`, hardware token, HSM, ...). The trait
    receives a SHA-2 digest and returns wire-form signature octets
    (PKCS#1 v1.5 padded big-endian for RSA, DER-encoded
    `Ecdsa-Sig-Value` for ECDSA).
  * `SigningAlgorithm { RsaPkcs1v15Sha256, EcdsaP256Sha256 }` —
    enum of the two algorithm slots round 30 ships; the writer
    picks the right CMS `digestAlgorithm` (SHA-256) +
    `signatureAlgorithm` (rsaEncryption / ecdsa-with-SHA256) OIDs
    based on the implementor's choice.
  * `RsaPkcs1v15Sha256Signer` / `EcdsaP256Sha256Signer` —
    reference `Signer` impls that wrap the in-crate `rsa` / `p256`
    deps (no new crypto deps added for the writer).
  * `SignerIdentity { issuer_der, serial, cert_chain }` —
    decoupled identity bundle; `from_signer_cert_der(der)` is the
    convenience constructor for the typical single-cert
    self-signed deployment.
  * `SigWriter::new(scene, signer, identity).sign() -> Vec<u8>` —
    the builder.
  * `sign_pdf_from_scene(scene, signer, identity) -> Vec<u8>` —
    one-shot convenience wrapper.
  * `pkcs7_wrap_signed_data(algorithm, issuer_der, serial,
    cert_chain, signed_attrs_body, signature_bytes) -> Vec<u8>` —
    standalone CMS DER builder; useful when stitching a signed PDF
    together at a lower level than `SigWriter`.

  Six integration tests under `tests/sig_writer_round30.rs` cover:

  * RSA-PKCS#1 v1.5 + SHA-256 round-trip (writer → round-21
    reader → round-20 `verify_signature` end-to-end).
  * ECDSA-P256 + SHA-256 round-trip.
  * `/ByteRange` placeholder filled correctly (start = 0, second
    range starts at the `>` after a fixed 8192-byte-wide
    `/Contents` gap, two ranges cover everything but the gap, last
    byte of range 1 is `<`, first byte of range 2 is `>`).
  * Tamper-detection (flipping a body byte fails the
    `messageDigest` cross-check per RFC 5652 §11.2).
  * `qpdf --check` accepts the RSA-signed PDF.
  * `qpdf --check` accepts the ECDSA-signed PDF.

  Provenance: ISO 32000-1 §12.7.4.5 + §12.8.1 + §7.5.6 (incremental
  updates) + RFC 5652 §5 + §5.4 + §11.1 (`contentType` attribute) +
  §11.2 (`messageDigest` attribute) + RFC 5754 §2 (SHA-256 with NULL
  params in CMS) + RFC 5753 §2.1 (ECDSA `Ecdsa-Sig-Value` SEQUENCE).
  No third-party PDF / CMS source consulted.

- Round 29: **Reading-order layout pass over Tagged PDF
  StructTreeRoot** (ISO 32000-1 §14.6 + §14.7 + §14.8). New
  `oxideav_pdf::reader::layout::read_in_logical_order(reader)` — and
  the convenience `DocumentReader::read_in_logical_order()` — walks
  the catalog's `/StructTreeRoot /K` tree and emits text runs in
  *author-intended* reading order rather than the painter's raster
  order. For a 2-column document, raster extraction interleaves
  column 1's first row, column 2's first row, column 1's second row,
  …; the round-29 pass walks `[Sect_col1, Sect_col2]` and emits all
  of column 1 before any of column 2. The walker handles every leaf
  shape ISO 32000-1 §14.7.4.4 defines:
  * Bare-integer MCID kids resolve against the inheritable `/Pg`
    field on the nearest ancestor.
  * `<</Type /MCR /Pg p /MCID m>>` marked-content references override
    the inherited `/Pg`, supporting Tagged tables whose rows draw
    from multiple pages.
  * `<</Type /OBJR …>>` object references (annotations, not content)
    are skipped — they carry no text.
  * Nested `/StructElem` kids (Sect inside Div inside …) recurse;
    indirect refs are followed with a 64-deep cycle guard.
  Documents *without* a `/StructTreeRoot` (or a malformed / empty
  tree) fall back to the existing raster-order extraction with
  `LayoutMode::Raster` set on the return so callers can branch.

  The pass piggybacks on a round-29 addition to the round-22 text
  walker: the new `extract_text_marked(reader)` (and matching
  `DocumentReader::marked_text_extraction()`) emits every text run
  alongside the marked-content `/MCID` it was painted under (ISO
  32000-1 §14.6 — `BDC` / `BMC` / `EMC` operators). The walker
  recognises `BDC` / `BMC` / `EMC` / `MP` / `DP` keywords and parses
  the `/MCID` slot out of inline `<</MCID n>>` property dicts at the
  top level. New public surfaces under `oxideav_pdf::reader`:
  * `MarkedTextRun { run, mcid, page_obj_num, page_index }`
  * `PdfMarkedTextExtraction { runs }`
  * `LayoutMode { Tagged, Raster }`
  * `ReadingOrderText { mode, runs }` (with `flat_text()`)

  Seven fixtures under `tests/reading_order_round29.rs` cover:
  two-column tagged-PDF logical reordering vs. raster baseline,
  non-tagged fallback, cross-page MCRs (`/MCR /Pg ... /MCID ...`),
  marked-text MCID accounting, and nested `/Sect > /P > MCID`
  recursion. No external library was consulted.

- Round 28: **Simple-font `/Encoding /Differences` resolver wired into
  text extraction** (ISO 32000-1 §9.6.6.1 + §D.2 + Adobe Glyph List v2.0
  public document). When a simple Type1 / TrueType / Type3 font carries
  an encoding *dictionary* (not just a name) the reader now overlays the
  `/Differences` array onto the `/BaseEncoding` map before mapping bytes
  back to Unicode. Three new public surfaces under
  `oxideav_pdf::reader::encoding`:
  * `parse_encoding_differences(arr) -> EncodingDifferences` walks the
    flat `[N name1 name2 … M nameK …]` form per §9.6.6.1 — numeric
    tokens reset the running code, names land at consecutive slots,
    unknown tokens are tolerated. Honours `Object::Integer` AND
    `Object::Real` numeric forms.
  * `apply_encoding_differences(&base, &diffs) -> EncodingMap` overlays
    one parsed array on top of any of the six named `BaseEncoding`
    variants (`WinAnsi` / `MacRoman` / `MacExpert` / `Standard` /
    `Symbol` / `ZapfDingbats`). Unknown glyph names leave the slot
    empty so the decoder emits U+FFFD as a marker (matching what
    `pdftotext --raw` does for un-resolvable glyphs).
  * `EncodingMap::from_base(BaseEncoding)` ships a 256-entry table per
    Annex D.2 / D.4 / D.5 / D.6 plus the Adobe Type 1 Standard
    encoding. Multi-character glyph expansions (`/fi` → "fi", `/fl` →
    "fl") are accommodated; the table slot is a short `String` rather
    than a single `char`.

  The Adobe Glyph List subset shipped with the resolver covers the
  PostScript Latin character set, common Greek letters, smart-quote /
  dash / fraction set, math operators, arrows, and the `/fi` and `/fl`
  ligatures — about 320 glyph names. Extension to the full ~4280-line
  AGL is round-29+. Glyph list staged under
  `docs/document/pdf/agl/subset.txt` and the README there cites the AGL
  v2.0 public-document source. Seven new fixtures under
  `tests/encoding_differences_round28.rs` cover smart-quote overrides,
  Greek glyph remap, `/fi` / `/fl` ligature expansion, multi-segment
  arrays with running-code resets, unknown-glyph replacement-char
  fallback, empty `/Differences`, and `/MacRomanEncoding` base
  encoding. Three of them feed the fixture PDF to a system `pdftotext`
  binary when available and assert the extracted text contains the
  expected substring.

- Round 27: **Linearization Parameter Dictionary reader + Object
  Hierarchy validator + PDF/A conformance detection beyond XMP**
  (ISO 32000-1 §F.2 + §7.7.2 + §7.7.3 / ISO 19005-1..4 §6.x).
  Three new reader-side surfaces:
  * `parse_linearization_dict(bytes) -> Result<Option<LinearizationParams>>`
    and `DocumentReader::linearization()` parse the `/Linearized 1 /L /H
    [off len] /O /E /N /T` first-object dictionary every Fast-Web-View
    PDF emits in its head (§F.3.3 — entirely within first 1024 bytes).
    Round 9's writer-side emission now has its reader-side complement.
    `LinearizationParams::verify(&bytes)` cross-checks `/L` against the
    actual file length and bounds-checks `/T`, `/E`, `/H`. The parser
    returns `Ok(None)` for plain (non-linearized) files so callers can
    branch on the Option. Hint-table decoding (Annex F.4) is round 28+.
  * `verify_pdf_hierarchy(reader) -> Result<HierarchyReport>` (and
    `DocumentReader::verify_hierarchy()`) walks Catalog → Pages → Page
    and collects every spec divergence as a `HierarchyIssue` with
    `IssueSeverity::Error` or `Warning`: Catalog `/Type` + `/Pages`
    presence (§7.7.2 Table 28), `/Pages` node `/Type` / `/Kids` /
    `/Count` (§7.7.3.2 Table 29), `/Page` leaf `/Parent` back-reference
    + `/MediaBox` presence (§7.7.3.3 Table 30), cycle detection with
    a 32-hop depth guard. Never aborts the walk — surfaces every issue
    at once so a downstream tool can `report.is_valid()` or filter by
    severity.
  * `read_pdf_pdfa_signals(reader) -> Result<PdfACatalogSignals>` (and
    `DocumentReader::pdfa_signals()` + `::pdfa_conformance()`) surface
    the structural PDF/A signals from the catalog independently of the
    XMP `pdfaid:part` claim: `/MarkInfo /Marked|UserProperties|Suspects`,
    `/StructTreeRoot` presence, `/Lang`, `/OutputIntents` count, and
    `/Metadata` presence. `PdfAConformance::from_signals_and_xmp` cross-
    verifies the XMP-declared part + conformance against the structural
    prerequisites ISO 19005-1 §6.2.2 / §6.7 / §6.8 require — an `A`-level
    claim missing `/MarkInfo /Marked true` or `/StructTreeRoot` flags
    `claim_inconsistent = true` with a free-form diagnostic.
  Tested end-to-end with +33 tests (15 integration in `tests/round27.rs`
  + 10 unit in `src/reader/linearize.rs` + 4 unit in
  `src/reader/hierarchy.rs` + 7 unit in `src/reader/pdfa.rs`).

- Round 26: **Annotations beyond Link + XMP packet field extraction**
  (ISO 32000-1 §12.5.6 Tables 169..209 + §14.3.2 / Adobe XMP Spec
  2012 / ISO 16684-1 / ISO 19005-1..3 §6.x). New reader entry
  `DocumentReader::annotations()` (free function: `read_pdf_annotations`)
  walks every page's `/Annots` array and surfaces every entry as a
  `PdfAnnotation`. Per-subtype payload covers `/Text` (§12.5.6.4 Table
  172 — `/Open`, `/Name` icon, `/State`, `/StateModel`), `/FreeText`
  (§12.5.6.6 Table 174 — `/DA`, `/Q` quadding, `/RC`, `/IT` intent),
  `/Stamp` (§12.5.6.13 Table 184 — icon name), the four text-markup
  variants `/Highlight` / `/Underline` / `/Squiggly` / `/StrikeOut`
  (§12.5.6.10 Table 179 — `/QuadPoints`), `/Square` + `/Circle`
  (§12.5.6.8 Table 177 — `/IC`, `/RD`), `/Link` (re-uses round-25's
  go-to / URI dispatch), and `/Widget` (§12.5.6.19 Table 188 + §12.7.4
  Table 220 — `/FT`, `/T`, `/V`). Unknown subtypes surface as
  `AnnotationKind::Other { subtype }`. Common Table 164 fields
  (`/Rect`, `/Contents`, `/NM`, `/M`, `/F`, `/C`, `/Border`) are
  decoded for every subtype.
  New `DocumentReader::xmp_packet()` (and `XmpPacket::parse(bytes)` for
  callers with the raw bytes already in hand) parses the document-level
  XMP packet round-19 surfaces into a structured view of the most-used
  Dublin Core (`dc:title` through `rdf:Alt` / `dc:creator` through
  `rdf:Seq` / `dc:subject` `rdf:Bag` / `dc:rights` / `dc:format`),
  XMP Basic (`xmp:CreateDate` / `xmp:ModifyDate` / `xmp:MetadataDate`
  / `xmp:CreatorTool`), PDF schema (`pdf:Producer` / `pdf:Keywords` /
  `pdf:PDFVersion` / `pdf:Trapped`), and PDF/A identification schema
  (`pdfaid:part` / `pdfaid:conformance`) fields. Element-body and
  attribute forms both recognised; the standard five XML entities
  (`&amp;` / `&lt;` / `&gt;` / `&quot;` / `&apos;`) plus numeric
  character references decode. `XmpPacket::is_pdf_a()` and
  `pdf_a_conformance()` collapse the pair into a `1B`-style designator
  for PDF/A conformance detection. Tested end-to-end with +36 tests
  (19 integration in `tests/annotations_round26.rs` covering every
  subtype dispatch, common-field decode, page-without-annots baseline,
  unified-reader round-trip of the writer's Link annotations, XMP
  Dublin Core / XMP Basic / PDF / PDF/A identification, attribute-form
  XMP, XML-entity decode, and absent-XMP `None`; +6 unit tests in
  `src/reader/annotation.rs` and +11 unit tests in `src/reader/xmp.rs`).
- Round 25: **Document outline (bookmarks) + Link annotations**
  (ISO 32000-1 §12.3.3 Tables 152+153 + §12.5.6.5 Table 173 + §12.3.2
  Table 151 destinations). New writer entry points
  `write_pdf_from_scene_with_outlines` + `…_with_outlines_and_links`
  attach a `/Outlines` tree to the catalog and per-page `/Annots
  [/Subtype /Link]` arrays without disturbing the existing single-/
  multi-page entry points. New reader functions `read_pdf_outline`
  + `read_pdf_links` walk the bookmark tree (the doubly-linked
  `/First`/`/Last`/`/Next`/`/Prev` shape collapses back into a
  parent-owned `children` Vec) and per-page link list. Destinations
  cover all eight Table 151 forms — `Xyz` / `Fit` / `FitH` / `FitV`
  / `FitR` / `FitB` / `FitBH` / `FitBV` — with `null` retain-current
  semantics on the optional numerics. Link targets cover both
  internal `/Dest <explicit-array>` go-to and external
  `/A << /S /URI /URI (...) >>` action forms. Outline `/Count`
  honours the open / closed sign per Table 153 (open ⇒
  +visible_descendants; closed ⇒ -|hidden_descendants|), and the
  reader's `OutlineNode::is_open()` / `descendant_count()` helpers
  expose the same convention to callers. Tested end-to-end with
  `+19 tests` (16 integration in `tests/outline_round25.rs` covering
  three-bookmark catalog, nested open/closed chapters, every dest
  variant, Unicode title, URI + go-to link, multi-page link
  grouping, out-of-range writer rejection, combined outline+link
  round-trip, and empty-input baseline; +13 unit tests across
  `src/outline.rs` + `src/reader/outline.rs` + `src/reader/link.rs`).
- Round 24: **CMS KARI X448 ECDH** (RFC 7748 §5 + RFC 8410 §3 + RFC 8418
  §2.1 + §2.2). New `KariCurve::X448` joins the existing P-256/P-384/
  P-521/X25519 dispatch — `id-X448` (OID 1.3.101.111), 56-byte raw
  u-coordinate keys, 224-bit security level. Default KDF binding is
  X9.63-SHA-512 (security-strength match); HKDF SHA-256/384/512 are
  also valid via the new `KariRecipient::x448_hkdf_*` constructors.
  Reader (`unwrap_kari` / `read_pdf_to_scene_with_certificate`) and
  writer (`write_pdf_from_scene_pubsec_kari`) both handle X448 KARI
  envelopes through the existing entry points. RFC 7748 §6.2
  Alice/Bob test vector cross-checked byte-for-byte. Backed by the
  pure-Rust `x448` (RustCrypto / `ed448-goldilocks`) crate.
- Round 23: **JPEG passthrough on `/Filter /DCTDecode` Image XObjects**
  (ISO 32000-1 §7.4.8 + §8.9). New `DocumentReader::image_xobjects()`
  walks every page's `/Resources /XObject` subdict and surfaces every
  Image XObject whose final filter is `/DCTDecode`. The returned
  `PdfImageXObject` carries the unmodified JPEG bytes (ready for any
  JPEG decoder), the `/Width` / `/Height`, the `/ColorSpace`
  (`DeviceRGB` / `DeviceCMYK` / `DeviceGray` / `Indexed` / `Other`),
  and the `/BitsPerComponent`. Wrapping `/ASCII85Decode` /
  `/ASCIIHexDecode` / `/FlateDecode` filters preceding `/DCTDecode` are
  unwrapped before the JPEG payload is returned. Cross-checked against
  `pdfimages -all` (poppler-utils) as a black-box validator — extracted
  bytes are byte-identical to both the source JPEG and `pdfimages`'s
  dump.
- Round 22: text extraction. `DocumentReader::text_extraction()` walks
  every page's content stream and emits `TextRun`s (text + position +
  font name + font size) for `Tj` / `TJ` / `'` / `"` operators. Maps
  encoded glyphs back to Unicode through embedded `/ToUnicode` CMaps
  (`bfchar` / `bfrange` per ISO 32000-1 §9.10.3), Identity-H Type 0
  CIDs, WinAnsiEncoding, and MacRomanEncoding (Annex D.2). Cross-checked
  against `pdftotext` (poppler) as a black-box validator.

## [0.1.1](https://github.com/OxideAV/oxideav-pdf/compare/v0.1.0...v0.1.1) - 2026-05-09

### Other

- CMS SignedData signature verification (RFC 5652 §5.4)
- XMP /Metadata stream end-to-end + CMS SignedData parser scaffolding
- round-18 docs: refresh pubsec module-level deferrals list
- OriginatorInfo certs[]/crls[] surface + RKID date/other parse + temporal trust-store lookup
- TrustStore originator lookup + RC2/3DES decode + KARI EM=false test
- KARI P-521 + RFC 8418 §2.2 HKDF binding for X25519
- round-15 KARI multi-curve + writer entry-point
- KARI multi-curve (P-384 + X25519) + writer-side encode
- KARI unwrap (P-256 ECDH + RFC 5753 KDF + RFC 3394 AES-KW)
- round 13 emits per-page hint table entries
- page-offset hint table per-page entries (Annex F.4.1)
- per-CF recipient lists + CMS KARI decoder
- public-key encryption encode + SubjectKeyIdentifier matching
- public-key encryption decode (adbe.pkcs7.s3/s4/s5)
- linearization (Fast Web View) + ObjStm-with-encryption combo
- ObjStm encoder + incremental updates + EncryptMetadata false
- xref-stream encode + ObjStm resolve + /Crypt /Identity
- encryption encode + XRef stream decode
- round-5 AES-256 standard handler (R=5 Adobe ext + R=6 ISO 2.0)
- round-4 standard-handler decryption (RC4-40 / RC4-128 / AES-128)
- reframe FFI claim — HW-engine crates use OS FFI by necessity
- drop stale REGISTRARS / with_all_features intra-doc links
- drop dead `linkme` dep
- auto-register via oxideav_core::register! macro (linkme distributed slice)
- unify entry point on register(&mut RuntimeContext) ([#502](https://github.com/OxideAV/oxideav-pdf/pull/502))
- release v0.0.3 ([#2](https://github.com/OxideAV/oxideav-pdf/pull/2))

### Added

- Round-21: **PDF `/Sig` annotation reader** (ISO 32000-1 §12.7.4.5
  + §12.8.1) — closes the round-20 follow-up that surfaced
  `pubsec::verify::verify_signature` without a way to feed it real
  PDF signatures. New `reader::sig::PdfSignature` carries the parsed
  `[a, b, c, d]` `/ByteRange`, the hex-decoded `/Contents` blob, the
  `/SubFilter` name (`adbe.pkcs7.detached` /
  `ETSI.CAdES.detached` etc.), the optional metadata fields
  (`/Name`, `/Reason`, `/Location`, `/ContactInfo`, `/M`), and — for
  the CMS-detached SubFilters — the parsed
  [`pubsec::signed_data::SignedData`] (CMS trim handles trailing
  zero-padding bytes after the outer SEQUENCE, which Adobe and iText
  routinely emit when the `/Contents` hex budget exceeds the actual
  signature size). `DocumentReader::signatures()` walks the catalog
  → `/AcroForm /Fields` tree honouring `/FT` inheritance through
  non-terminal `/Kids` parents per ISO 32000-1 §12.7.3.1 (a parent
  carrying `/FT /Sig` propagates to its child fields), and is
  tolerant of unsigned slots (a Sig field whose `/V` is absent —
  common for "approval line still pending" templates), of malformed
  `/Contents` blobs, and of documents without an `/AcroForm`
  (returns an empty Vec). New `PdfSignature::signed_message(pdf)`
  helper concatenates the two `/ByteRange`-named slices into the
  byte string the signing tool hashed; pass it as
  `AttachedContent::External(...)` to the round-20
  `verify_signature` for end-to-end verification. Tested end-to-end
  with a hand-laid PDF 1.4 fixture carrying one
  `adbe.pkcs7.detached` signature signed with RSA-PKCS#1 v1.5 +
  SHA-256 over a `signedAttrs` set with the RFC 5652 §11.2
  `messageDigest` cross-check; tamper detection (flip a byte outside
  `/Contents`) is also exercised. `+14 tests` (8 integration in
  `tests/sig_round21.rs` + 6 unit in `src/reader/sig.rs`). The
  writer side (laying out an `/AcroForm /Fields` with reservable
  `/Contents` / `/ByteRange` slots so a downstream signing tool can
  fill them in place) is the round-22+ follow-up.

- Round-20: **CMS `SignedData` signature verification** (RFC 5652 §5.4 +
  §11.2 + RFC 8017 + RFC 5754 + RFC 5758). Closes the round-19 deferral
  that surfaced parsed `SignerInfo` bytes without a verifier. New
  `pubsec::verify::verify_signature(signer, certs, content) -> Result<bool>`
  resolves the signer's certificate from a pool by `IssuerAndSerial` or
  `SubjectKeyIdentifier`, hashes the canonical (universal-SET-tag)
  re-encoding of `signedAttrs` (or the raw eContent when `signedAttrs`
  is absent) per `digestAlgorithm`, and verifies the resulting hash
  against `signature` per `signatureAlgorithm`. Hash side: SHA-1 /
  SHA-256 / SHA-384 / SHA-512 via the existing `sha1` + `sha2` deps.
  Signature side: RSA-PKCS#1 v1.5 (the `rsaEncryption` + four
  `sha*WithRSA` OIDs all map here), RSA-PSS (`id-RSASSA-PSS`), and
  ECDSA on P-256 / P-384 / P-521 (curve dispatch by the cert SPKI's
  named-curve OID per RFC 5480 §2.1.1.1). When `signedAttrs` is
  present, the verifier also cross-checks the `messageDigest`
  attribute against the eContent hash per RFC 5652 §11.2 — so a
  tampered eContent still fails even when the outer signature
  verifies against intact attrs. Detached signatures (PAdES — eContent
  absent) feed the document bytes through a new
  `AttachedContent::External(&[u8])` parameter. New helpers
  `signed_attrs_to_be_signed`, `build_message_digest_attribute_der`,
  `pack_signed_attrs_implicit`, `implicit_signed_attrs_tlv`,
  `rsa_pubkey_to_pkcs1_der` for fixture builders. New OID constants
  `OID_SHA1` / `OID_SHA256` / `OID_SHA384` / `OID_SHA512` /
  `OID_RSA_ENCRYPTION` / `OID_SHA{1,256,384,512}_WITH_RSA` /
  `OID_RSA_PSS` / `OID_EC_PUBLIC_KEY` /
  `OID_ECDSA_WITH_SHA{1,256,384,512}` /
  `OID_NAMED_CURVE_P{256,384,521}` / `OID_ATTR_MESSAGE_DIGEST`.
- Round-20: **`x509::Certificate.spki_algorithm_oid` +
  `spki_algorithm_params`** — the SPKI's `AlgorithmIdentifier` is now
  captured (in addition to the BIT STRING contents already extracted
  in round 11) so the verifier can route ECDSA on the named-curve OID
  without re-parsing the certificate. `Certificate` now derives
  `Default`, so test fixtures can use `..Default::default()` for the
  optional fields.
- Round-20 tests: 20 new tests — 13 `pubsec::verify` unit tests
  (hash-OID dispatch, signed_attrs SET re-tag, RSA-PKCS1v15 with
  signedAttrs, RSA-PKCS1v15 without signedAttrs, content-tamper via
  messageDigest mismatch, single-bit signature flip rejection,
  cert-not-in-pool error, RSA-PSS, ECDSA-P256/384/521, ECDSA-P256
  signature-tamper rejection, SKI signer resolution) + 7
  `tests/pubsec_round20_signed_data_verify.rs` end-to-end integration
  tests (full SignedData ContentInfo → parse → verify, four algorithm
  combinations from the round dispatch sheet, both tamper paths,
  cert-not-in-pool, OID re-export visibility).

- Round-19: **Document-level XMP `/Metadata` stream end-to-end**
  (ISO 32000-1 §14.3.2 + Adobe XMP Spec 2012). Closes the round-17
  `EncryptMetadata=false` carve-out by giving the PDF a place to put
  the unencrypted document-level XMP packet. Writer entry point
  `write_pdf_from_scene_with_xmp(scene, xmp_bytes)` attaches the raw
  XMP RDF/XML payload to the catalog as a `/Type /Metadata /Subtype
  /XML` stream object — no `/Filter` per §14.3.2 (so archival-system
  grep tools can index the packet without decompressing). Reader
  accessor `DocumentReader::xmp_metadata() -> Result<Option<Vec<u8>>>`
  resolves the `/Metadata` indirect reference, decodes the stream, and
  returns the raw XMP bytes (caller does any XML / RDF parse). New
  `Document::object_mut` mutation helper enables the post-`build_pages`
  catalog patch.
- Round-19: **CMS `SignedData` parser scaffolding** (RFC 5652 §5,
  PKCS#7). Builds on the existing CMS DER + X.509 + EnvelopedData
  infrastructure to add parser-side recognition of `id-signedData`
  (OID `1.2.840.113549.1.7.2`) — the content type that wraps every PDF
  digital signature (ISO 32000-1 §12.8). New
  `pubsec::signed_data::SignedData { version, digest_algorithms,
  encap_content_type, encap_content_octets, certs, crls, signer_infos }`
  with one-shot accessor `parse_signed_data(der_bytes) ->
  Result<SignedData, PdfError>`. New
  `pubsec::signed_data::SignerInfo { version, sid, digest_algorithm_oid,
  digest_algorithm_params, signed_attrs, signed_attrs_der,
  signature_algorithm_oid, signature_algorithm_params, signature,
  unsigned_attrs }` exposes both the structural decode (signed +
  unsigned attribute lists with raw-DER values, IAS / SKI signer
  identifier) and the verification-helper bytes (raw `signed_attrs`
  DER body, ready for the SET-tag re-encode RFC 5652 §5.4 mandates
  before hashing). New `pubsec::signed_data::SignerIdentifier` mirrors
  the IAS / SKI CHOICE the CMS RecipientId already exposes for the
  envelope side. New OID constant `pubsec::cms::OID_SIGNED_DATA`.
  Signature verification (hash-then-verify dispatch per
  `digestAlgorithm` + `signatureAlgorithm`) is deferred to round 20.
- Round-19 tests: 13 new tests — 3 `pubsec::signed_data` unit tests
  (v=1 IAS attached signature, v=3 SKI with signed attrs, wrong-OID
  rejection) + 5 `tests/xmp_metadata_round19.rs` (byte-for-byte XMP
  round-trip, dict-shape inspection, no-metadata-returns-None,
  binary-payload survives, XMP coexists with `/Info`) + 5
  `tests/pubsec_round19_signed_data.rs` (attached SignedData parse
  with all fields surfaced, certs[] surfacing, wrong-OID rejection,
  truncated-blob rejection, empty-signerInfos rejection).
- Round-18: **CMS `OriginatorInfo` `certs[]` / `crls[]` surface**. The
  `EnvelopedData.originatorInfo` field (RFC 5652 §10.2.1 — `[0] IMPLICIT
  OriginatorInfo OPTIONAL`) was previously parsed-and-discarded. New
  `pubsec::cms::OriginatorInfo { certs: Vec<Vec<u8>>, crls: Vec<Vec<u8>> }`
  carries each `CertificateChoices` / `RevocationInfoChoices` entry as
  raw DER (preserving the outer tag + length, so callers can re-parse
  without reconstruction). New accessor
  `EnvelopedData::originator_info() -> Option<&OriginatorInfo>` returns
  `Some` only when the envelope carried a non-empty `OriginatorInfo`.
  Test fixture `pubsec::cms_build::build_envelope_aes256_with_originator_info`
  emits the bundled-cert form for the round-trip integration test.
- Round-18: **`RecipientKeyIdentifier { date, other }` parse + temporal
  trust-store lookup**. Per RFC 5652 §6.2.2 the RKID SEQUENCE may carry
  OPTIONAL `date GeneralizedTime` + `other OtherKeyAttribute` fields;
  round 17 ignored both. Round 18 captures them on the parser side
  (new `pubsec::cms::OtherKeyAttribute { key_attr_id: Vec<u64>, key_attr:
  Vec<u8> }`; the `KeyAgreeRecipientId::RecipientKeyIdentifier` arm
  gains `date: Option<Vec<u8>>` + `other: Option<OtherKeyAttribute>`
  fields), AND the encode-side fixture (`KariRecipientIdRef::RecipientKeyIdentifier`
  in `cms_build`) emits both OPTIONAL fields when populated.
  New `TrustStore::find_with_temporal_validity(ski, instant: Option<&[u8]>)`
  picks among multiple certs sharing an SKI the one whose validity
  window contains the supplied instant — useful for long-lived archives
  where the same recipient identity has been re-certified multiple
  times (yearly cert rotation preserving the SubjectKey). The
  `Certificate` parser now also extracts the `(not_before, not_after)`
  validity window, normalising `UTCTime` to `GeneralizedTime` per RFC
  5280 §4.1.2.5.1's 1950..2049 pivot so envelope `GeneralizedTime`
  bytes byte-compare directly against the cert's window. New helper
  `pubsec::x509::time_within(instant, not_before, not_after) -> bool`.
- Round-18 tests: 14 new tests — 3 `pubsec::trust` unit tests (temporal
  pick / temporal-skip-without-window / x509 validity round-trip) +
  4 `tests/pubsec_round18_originator_info.rs` (round-trip with both
  certs+crls, envelope-without-OI surfaces None, certs-only without
  CRLs, default-empty) + 7 `tests/pubsec_round18_rkid_temporal.rs`
  (RKID round-trip with date+other / date-only / other-only / neither,
  temporal lookup picks active generation, returns None outside any
  window, falls back to single-entry lookup when instant is None).
- Round-17: **Long-term originator cert via TrustStore**. Closes the
  RFC 5652 §6.2.2 `OriginatorIdentifierOrKey` `IssuerAndSerial` /
  `SubjectKeyIdentifier` decoder gap — when a KARI envelope identifies
  the originator by long-term cert reference rather than carrying its
  public point in-band, the recipient resolves the cert through a
  caller-supplied `TrustStore`. New types `pubsec::trust::TrustStore`
  + `pubsec::trust::CertRef` (re-exported as `oxideav_pdf::TrustStore`
  / `oxideav_pdf::CertRef`); new entry points
  `read_pdf_to_scene_with_certificate_and_trust_store(pdf, &cred, &store)`
  + `pubsec::open_with_certificate_and_trust_store(...)` +
  `..._with_permissions(...)`. New helper
  `pubsec::kari::unwrap_kari_with_trust_store(kari, slot, recipient,
  Option<&TrustStore>)` dispatches the lookup and pulls the
  originator's encoded public point straight out of the cert's SPKI BIT
  STRING contents (SEC1 uncompressed for NIST EC curves per RFC 5480
  §2.2; raw 32-byte u-coordinate for X25519 per RFC 8410 §4). Backwards
  compatible: the existing `read_pdf_to_scene_with_certificate` /
  `open_with_certificate` paths still refuse long-term-cert originators
  with a structured error.
- Round-17: **RC2 / 3DES envelope content decode (read-only)**. Adds
  decode support for `EncryptedContentInfo.contentEncryptionAlgorithm`
  values that legacy CMS envelopes may carry: RC2-CBC
  (OID `1.2.840.113549.3.2`, RFC 2268 + RFC 3217 §3 + RFC 3370 §5.1
  with the `rc2ParameterVersion` ↔ effective-key-bits mapping at
  160→40, 120→64, 58→128) and DES-EDE3-CBC / 3DES
  (OID `1.2.840.113549.3.7`, RFC 3370 §5.2 / RFC 5652 §12.4). New
  `pubsec::cms::ContentEncryption::Rc2Cbc { effective_key_bits, iv }` +
  `pubsec::cms::ContentEncryption::DesEde3Cbc { iv }` enum variants;
  RC2 dispatch goes through `Rc2::new_with_eff_key_len` to honour the
  RFC 3370 §5.1 effective-key parameter independently of the raw key
  length. Hidden test fixtures `pubsec::cms_build::build_envelope_rc2_cbc`
  + `..._des_ede3_cbc` (`#[doc(hidden)]`) so the read-only path is
  testable without exposing an encode-side public API. **PDF 2.0
  deprecates both algorithms** — no encode-side support is provided;
  the writer always uses AES. New deps: `rc2` 0.8 + `des` 0.8
  (RustCrypto, pure-Rust).
- Round-17: **`/EncryptMetadata false` × KARI end-to-end test**. Adds
  three integration tests confirming that
  `PubSecKariConfig::encrypt_metadata = false` round-trips through both
  the `/Encrypt` dict entry AND the SHA-256 file-key derivation's
  `0xFFFFFFFF` opt-in tail (ISO 32000-2 §7.6.5.3) for both P-256 ECDH
  and X25519 KARI envelopes — symmetric to the round-8 KTRI coverage
  in `tests/encrypt_metadata_false.rs`. The plumbing was already
  present from round 15; round 17 closes the test-coverage gap.
- Round-17 tests: 16 new tests — 4 `pubsec::trust` unit tests
  (IAS / SKI / dual-form-insert round-trips + SPKI-absent skip path) +
  3 `tests/pubsec_round17_kari_encrypt_metadata_false.rs` integration
  tests + 4 `tests/pubsec_round17_trust_store.rs` integration tests
  (long-term IAS originator + long-term SKI originator + missing-cert
  negative + wrong-cert AES-KW-failure negative) + 5
  `tests/pubsec_round17_rc2_3des.rs` integration tests (RC2-CBC parse +
  RC2-CBC round-trip + RC2-CBC 64-bit-effective-key round-trip +
  3DES-CBC parse + 3DES-CBC round-trip).

- Round-16: **P-521 KARI + RFC 8418 §2.2 HKDF binding for X25519**.
  Closes the NIST KARI curve coverage and adds the modern HKDF KDF
  family for X25519. New `pubsec::kari::KariCurve::P521` variant +
  `EcRecipient::p521` constructor + `KariRecipient::p521` writer
  constructor — bound to `dhSinglePass-stdDH-sha512kdf-scheme`
  (OID `1.3.132.1.11.3`) + X9.63-SHA-512 KDF per RFC 5753 §7.1.4.
  New `KariKdf` enum with `X963Sha256/384/512` + `HkdfSha256/384/512`
  arms (and `KariKdf::from_kea_oid` / `is_valid_for(curve)` helpers
  enforcing the RFC 5753 / RFC 8418 pairing matrix). New writer
  constructors `KariRecipient::x25519_hkdf_sha256/384/512` switch the
  X25519 binding from the legacy X9.63-SHA-256 (RFC 8418 §2.1) to the
  modern HKDF family — `dhSinglePass-stdDH-hkdf-sha256/384/512-scheme`
  OIDs `1.2.840.113549.1.9.16.3.{19,20,21}` per RFC 8418 §2.2. Per
  RFC 8418 §2.2: HKDF-Extract uses `salt = ukm` (or absent when UKM
  is missing) and `IKM = ECDH shared secret`; HKDF-Expand consumes
  the same DER `ECC-CMS-SharedInfo` structure as the X9.63 path.
  Reader auto-routes by parsing the KEA OID into `KariKdf` (no
  caller-side opt-in needed). New helpers `derive_kek` (KDF dispatch)
  + `hkdf_kdf_sha256/384/512` (RFC 5869 wrappers). The round-15
  `wrap_cek_for_recipient` keeps its signature; new
  `wrap_cek_for_recipient_with_kdf` accepts an explicit `KariKdf`
  override. Provenance: RFC 5753 §7.1.4 + RFC 5869 + RFC 8418 §2.2 +
  NIST FIPS 186-4 (P-521 curve) + NIST SP 800-56C only. New deps:
  `p521` 0.13 (`ecdh` + `std`) + `hkdf` 0.12.
- Round-16 tests: 11 new tests — 5 `pubsec::kari` unit tests (P-521 +
  AES-256 KW round-trip, X25519 + HKDF-SHA-256/384/512 + AES-128/256
  KW round-trips, KDF/curve pairing matrix coverage, HKDF dispatch
  byte-equivalence with `hkdf` crate primitive, X9.63-SHA-512 KDF
  one-block, build-time KDF/curve mismatch rejection) + 6 integration
  tests in `tests/pubsec_round16_kari.rs` (P-521 writer→reader
  round-trip, X25519 HKDF-SHA-256/384/512 writer→reader round-trips
  with UKM-present/absent variants, P-256-credential-against-P-521
  negative, wrong-X25519-scalar-against-HKDF negative).

- Round-15: **KARI multi-curve + writer-side encode**. Extends the
  round-14 KARI unwrap path to **P-384** (`dhSinglePass-stdDH-sha384kdf-scheme`,
  OID `1.3.132.1.11.2`, X9.63-SHA-384 KDF) and **X25519** (RFC 8418
  §2.1 — secg-scheme `1.3.132.1.11.1` X9.63-SHA-256 binding +
  `id-X25519` `1.3.101.110` curve OID). New `pubsec::kari::KariCurve`
  enum + `EcRecipient::p256/p384/x25519` constructors + generic
  `x963_kdf::<H: sha2::Digest>` (the SHA-256 wrapper
  `x963_kdf_sha256` is kept). Single dispatcher `unwrap_kari` routes
  on the recipient's curve; the round-14 `unwrap_kari_p256` entry
  point still works. New `PubSecCredential::from_parsed_ec(cert,
  curve, scalar)` + `with_ec_scalar(curve, scalar)` (round-14
  `_p256` variants forward here). Provenance: RFC 5753 §7.1.4 + RFC
  8418 §2.1 + RFC 8410 §3 + RFC 7748 §5 only. New deps: `p384` 0.13
  (`ecdh` + `std`) + `x25519-dalek` 2 (`static_secrets`).
- Round-15 writer: **`write_pdf_from_scene_pubsec_kari(scene, &PubSecKariConfig)`**.
  Symmetric to the round-11 `write_pdf_from_scene_pubsec_encrypted`
  KTRI path. Each `KariRecipient { curve, issuer/serial, recipient_pub_bytes,
  ephemeral_scalar }` becomes one CMS `EnvelopedData` carrying its
  own `KeyAgreeRecipientInfo` (one per recipient because the KEA
  pinpoints one curve per KARI); all envelopes wrap the same shared
  CEK with AES-256-WRAP and decrypt to the same AES-256 file content.
  New public types: `PubSecKariConfig::aes256(recipients)` +
  `KariRecipient::p256/p384/x25519` + `PubSecEncryptionState::build_kari`.
  The round-15 `wrap_cek_for_recipient(curve, ephemeral_scalar,
  recipient_pub_bytes, ukm, cek, wrap)` is the public dispatch
  helper used by `build_kari` (the round-14 P-256-only
  `wrap_cek_for_p256_recipient` forwards here).
- Round-15 tests: 8 new tests — 4 `pubsec::kari` unit tests
  (P-384 + AES-256 KW round trip, X25519 + AES-128 KW round trip,
  X9.63-SHA-384 KDF one-block, curve dispatch consistency) + 4
  integration tests in `tests/pubsec_round15_kari.rs` (P-256 / P-384 /
  X25519 writer→reader round-trips through the new
  `write_pdf_from_scene_pubsec_kari`, plus a wrong-key negative path).

- Round-14: **KARI unwrap** (RFC 5753 §7.1 + RFC 3394) — closes the
  round-12 deferral. P-256 ECDH key agreement + RFC 5753 §7.1.2 X9.63
  KDF with SHA-256 + RFC 3394 AES Key Wrap (128 / 192 / 256 bit) for
  the `dhSinglePass-stdDH-sha256kdf-scheme` KEA OID
  (`1.3.132.1.11.1`). New `pubsec::kari` module:
  `unwrap_kari_p256(kari, slot, &EcRecipient)` performs the full
  ECDH + KDF + AES-KW recovery; `x963_kdf_sha256` + `build_ecc_cms_shared_info`
  are the public KDF-input helpers. New
  `PubSecCredential::from_parsed_ec_p256(cert, ec_scalar)` +
  `with_ec_p256_scalar(scalar)` constructors plumb a P-256 SEC1 raw
  private scalar into the credential. The reader's `try_unwrap` now
  walks `all_recipients` (KTRI + KARI) — KARI slots whose
  `keyEncryptionAlgorithm` matches `dhSinglePass-stdDH-sha256kdf-scheme`
  and whose RID matches the credential's cert are unwrapped via P-256;
  unsupported KEA OIDs / mismatched RIDs are skipped silently so a
  mixed-recipient envelope (KTRI + KARI) opens via either side. New
  deps: `p256` 0.13 (with `ecdh` + `std` features) + `aes-kw` 0.2
  (with `alloc` feature). Provenance: RFC 5753 §3.1 / §7.1 / §7.2 +
  RFC 3394 §2.2.2 + RFC 5652 §6.2.2 + NIST SP 800-56A only. Decoder
  side; encoder-side `wrap_cek_for_p256_recipient` is a `#[doc(hidden)]`
  fixture helper used by the round-14 integration tests. P-384 / P-521
  / X25519 stay deferred (the structural parser already accepts every
  curve via `OriginatorPublicKey.algorithm`).
- Round-14 tests: 11 new tests — 8 `pubsec::kari` unit tests
  (X9.63-SHA-256 KDF one-block + truncated-multi-block, ECC-CMS-SharedInfo
  builder with + without UKM, wrap-OID round trip, P-256 + AES-128 KW
  round trip, P-256 + AES-256 KW round trip, unsupported-KEA-OID
  error path) + 3 integration tests in `tests/pubsec_round14_kari.rs`
  (`adbe.pkcs7.s5` V=5 KARI-encrypted PDF round-trip via
  `read_pdf_to_scene_with_certificate` — IAS form, SKI form, wrong
  EC key error path).

- Round-12: **per-crypt-filter recipient lists** — multiple named
  crypt filters under `/CF`, each with its own permission mask, all
  sharing one `/Recipients` array of multi-envelope PKCS#7 blobs (one
  envelope per permission set). New
  `write_pdf_from_scene_pubsec_multi_cf(scene, PubSecMultiCfConfig)`
  + `PubSecCfGroup` (group = one permission set: full-access /
  read-only constructors provided). The reader gains
  `open_with_certificate_with_permissions` returning a `PubSecMatch
  { handler, permissions, crypt_filter_name }`, so a caller can
  surface "you have read-only access" alongside the decrypted scene.
  Per ISO 32000-1 §7.6.4.2 + §7.6.5.4, every recipient walks every
  envelope; the first match wins. Provenance: ISO 32000-1 §7.6.4.2 +
  §7.6.5.4 only.
- Round-12: **CMS KARI decoder** (RFC 5652 §6.2.2) — KeyAgreeRecipientInfo
  parsing. Surfaces originator (IAS / SKI / OriginatorPublicKey) +
  ukm + keyEncryptionAlgorithm OID + recipientEncryptedKeys via the
  new `cms::RecipientInfoVariant::KeyAgree` arm + `KeyAgreeRecipientInfo`
  / `OriginatorId` / `KeyAgreeRecipientId` types. KARI envelopes
  (alone or mixed with KTRI) parse cleanly through `parse_envelope`;
  the KTRI side still drives the actual unwrap (DH/ECDH key
  agreement + RFC 5753 KDFs are out of scope). Encoder-side helper
  `cms_build::build_envelope_kari_aes256` builds fixture envelopes.
  Provenance: RFC 5652 §6.2.2 only.
- Round-12 tests: 9 new tests — 7 round-12 integration tests in
  `tests/pubsec_round12.rs` (multi-CF round-trip + permissions
  surfacing + neither-group-matches + non-s5-rejection +
  empty-groups-rejection + KARI structural parse + mixed-KARI/KTRI),
  2 unit tests in `cms_build` (KARI round-trip + alternate-CHOICE
  KARI variant).

- Round-11 writer: **public-key encryption encode** — the symmetric
  encoder side of round 10. New top-level
  `write_pdf_from_scene_pubsec_encrypted(scene, &PubSecEncoderConfig)`
  emits PDFs whose `/Encrypt /Filter` is `/Adobe.PPKLite` and whose
  `/Recipients` array carries one CMS `EnvelopedData` (RFC 5652 §6.1)
  per access-permission set. `PubSecEncoderConfig` constructors:
  `pkcs7_s4` (RC4-128 / SHA-1), `pkcs7_s5_v4_aes128` (AES-128 CBC /
  SHA-1), `pkcs7_s5_v5_aes256` (AES-256 CBC / SHA-256). Each
  recipient's content-encryption key is RSA-PKCS1-v1.5 wrapped to its
  public key; the file encryption key is `SHA-1/SHA-256(seed ‖
  envelope_blob [‖ 0xFFFFFFFF])` per ISO 32000-1 §7.6.4.3 / ISO
  32000-2 §7.6.5.3. The `cms_build` module is promoted from `pub(crate)
  test-only` to `pub` and gains a `build_envelope_rc4` helper +
  `RecipientPlain::ias` / `::ski` constructors. `PubSecEncryptionState`
  produces a `EncryptionState` shape so the writer reuses the
  password-handler's per-object encryption walker without duplication.
- Round-11: **`SubjectKeyIdentifier` recipient matching** (CMS v2 per
  RFC 5652 §6.2.1). Previously the parser errored on the v=2 KTRI
  variant; round 11 wires it through. `cms::RecipientId` becomes a
  CHOICE-shaped enum with `IssuerAndSerial` and
  `SubjectKeyIdentifier(Vec<u8>)` arms; `pubsec::open_with_certificate`
  accepts either form, computing the cert's SKI as
  `SHA-1(SubjectPublicKeyInfo BIT STRING contents)` (RFC 5280
  §4.2.1.2 method 1). `x509::Certificate` extends with
  `spki_pubkey_bits` + `subject_key_identifier()` accessor; the
  X.509 parser now walks past `issuer` to `subjectPublicKeyInfo`
  (best-effort — synthetic test certs that truncate after `issuer`
  silently leave `spki_pubkey_bits = None`).
- Round-11 writer: **linearization F.4.2 / F.4.3 / F.4.4 hint
  tables** — shared-object (24-byte zero header), thumbnail (28-byte
  zero header), outline (14-byte zero header). The hint stream's
  dict gains `/S` (shared-object table offset), `/T` (thumbnail
  table offset), `/O` (outline table offset). Entry sections stay
  empty (we generate no shared objects / thumbnails / outlines), so
  readers parsing these tables conclude there's nothing to consume —
  but the structural completeness lets `qpdf --linearize-check` and
  similar tools see a fully-formed hint stream.
- Round-11 tests: 11 new tests — 4 lib unit tests for the
  shared/thumbnail/outline hint table builders + the hint-stream
  dict /S/T/O presence; 4 lib unit tests for the writer-side
  encoder (s4 / s5-V4-AES128 / s5-V5-AES256 round-trip via
  `open_with_certificate` + a SKI-form variant + an empty-recipients
  rejection); 5 integration tests in `tests/pubsec.rs` exercising
  the full writer→reader pipeline including a two-recipients-either
  -opens scenario and an SKI-form round trip; 1 X.509 unit test for
  the SPKI extractor / SHA-1 SKI computation.

- Round-10 reader: **public-key encryption decode** for the
  `adbe.pkcs7.s3` / `s4` / `s5` SubFilters of the public-key
  security handler (ISO 32000-1 §7.6.4 + ISO 32000-2 §7.6.5).
  New `pubsec` module + top-level `PubSecCredential` (X.509 cert
  + RSA private key) + `read_pdf_to_scene_with_certificate`. The
  reader parses each `/Recipients` CMS `EnvelopedData` (RFC 5652
  §6.1) — minimal in-tree DER + CMS parsers, no external library
  code consulted — matches a recipient slot by
  `IssuerAndSerialNumber`, RSA-PKCS1-v1.5 unwraps the
  content-encryption key, then decrypts the envelope contents
  (RC4 / AES-128 CBC / AES-256 CBC). The file encryption key is
  the first n/8 bytes of `SHA-1(seed || all_recipient_blobs)`
  for the V≤4 paths and `SHA-256(...)` for the AES-256 path,
  per §7.6.4.3 / §7.6.5.3. Reader hands the resulting key off
  to the existing `decrypt::StandardHandler` so per-object
  string + stream decryption uses the same Algorithm 1 path the
  password-based reader already exercises. Encoder side is round 11+.
- Round-10 deps: pure-Rust `rsa` (RustCrypto, RSAES-PKCS1-v1_5)
  and `sha1` (RustCrypto). No `*-sys` wrappers; both crates are
  used purely on the decoder path. The CMS / X.509 / DER parsers
  are hand-rolled from RFC 5652 / RFC 5280 / X.690 — no
  pkcs / cms / x509-cert crate dependency.
- Round-10 tests: 17 new tests — 12 unit tests covering the DER
  TLV parser/writer round-trip, OID encoding, an AES-256 CMS
  envelope round-trip, X.509 issuer/serial extraction from a
  synthetic certificate, and `open_with_certificate` against
  s4 / s5-V4 / s5-V5 envelopes; 5 integration tests in
  `tests/pubsec.rs` building a complete public-key-encrypted PDF
  + verifying `read_pdf_to_scene_with_certificate` recovers
  the encrypted `/Title` + content stream end-to-end across
  RC4-128, AES-128 CBC, and AES-256 CBC profiles, plus a wrong-
  certificate negative test and an unencrypted-PDF passthrough.

- Round-9 writer: **Linearization (Fast Web View)**, ISO 32000-1
  §7.5.6 + Annex F. New `write_pdf_from_scene_linearized(scene)`
  emits a PDF whose first 1024 bytes carry a complete linearization
  parameter dictionary (`/Linearized 1` + `/L` + `/H` + `/O` +
  `/E` + `/N` + `/T`); the layout follows Annex F.3.1 (header,
  lin-dict, first-page xref, catalog, hint stream, first-page
  section, remaining pages, main xref). `startxref` at EOF points
  at the first-page xref (per F.3.11); the first-page trailer's
  `/Prev` points at the main xref (per F.3.4). The output remains
  a valid plain PDF — readers ignoring `/Linearized` still see
  the same Catalog + Pages tree + page content. Hint stream emits
  the mandatory page offset hint table only (Tables F.3 + F.4);
  shared-object / thumbnail / generic hints (F.4.2 / F.4.3 /
  F.4.4 / F.4.5 / F.4.6) are deferred. Two-pass emission:
  placeholder values are written 10-digit zero-padded so the
  patch step preserves byte alignment.
- Round-9 writer: **ObjStm + encryption combined path**
  (`write_pdf_from_scene_object_stream_encrypted`). Lifts the
  round-8 "ObjStm OR encryption, not both" guard per the §7.5.7
  carve-out: "In an encrypted file (i.e., entire object stream
  is encrypted), strings occurring anywhere in an object stream
  shall not be separately encrypted." The ObjStm container body
  is encrypted as a unit using the container's own object id as
  the per-object key seed; compressed bodies inside it are NOT
  separately encrypted. Round-trips through the round-7 reader
  with `read_pdf_to_scene_with_password`.
- Round-9 tests: 23 new tests — 13 in `tests/linearization.rs`
  covering the lin-dict-in-first-1024-bytes invariant, /L/N/O/E
  consistency with actual file shape, startxref → first-page xref,
  first-page trailer /Prev → main xref, single + multi-page
  round-trips through the reader; 10 unit tests in `src/linearize.rs`
  for the same; one new test in `tests/object_stream_encode.rs`
  for the ObjStm + encryption combo round-trip.

- Round-8 writer: **object-stream encoder** (`/Type /ObjStm`,
  ISO 32000-1 §7.5.7). New `Document::object_stream` flag
  (requires `xref_stream = true`) packs every compressible
  indirect object — every dict that isn't a stream, the Catalog,
  or the Encrypt object — into one ObjStm container per
  revision. The xref stream's type-2 entries point at the
  container; pairs with the round-7 reader-side resolver. New
  one-shot entry point `write_pdf_from_scene_object_stream`.
  Stream objects remain at byte offsets (§7.5.7 forbids
  embedding them).
- Round-8 writer: **incremental updates** (`/Prev`,
  ISO 32000-1 §7.5.6). New `write_pdf_incremental_update(prev_pdf,
  &new_pages)` appends a new revision to a previously-written
  PDF: re-renders the new pages with fresh ids past the prior
  maximum, rewrites the `/Pages` tree at its existing id
  (so the new kids list overrides), emits a new xref subsection
  listing only the changed slots, and writes a trailer with
  `/Prev` pointing at the previous xref offset. Original bytes
  are preserved verbatim — partial readers that ignore `/Prev`
  see the original revision unchanged.
- Round-8 reader: `parse_xref` now follows the trailer's `/Prev`
  chain (up to 32 hops, cycle-detected) and merges older xref
  sections beneath the newest. Newer revisions win on overlap.
- Round-8 tests: 17 new integration tests across
  `tests/object_stream_encode.rs` (6), `tests/incremental_update.rs`
  (5), and `tests/encrypt_metadata_false.rs` (6) covering
  encoder→reader round-trips, multi-page packing, two-level
  `/Prev` chaining, original-bytes preservation, and the
  `/EncryptMetadata false` end-to-end matrix (R=3 / R=4 / R=6).
- `Document::set_next_id` + `Document::next_id` accessors so
  the incremental-update writer can resume id allocation past
  a previously-written revision's maximum.

- Round-7 writer: cross-reference *stream* (`/Type /XRef`,
  ISO 32000-1 §7.5.8) emission. Mirror of the round-6 reader —
  `/W [1 4 2]` field widths, FlateDecode + PNG-Up `/Predictor 12`
  body, trailer dict folded into the stream's own dictionary. New
  `Document::xref_stream` flag + `write_pdf_from_scene_xref_stream`
  one-shot entry point. Header bumped to PDF 1.5 when active.
- Round-7 reader: PDF 1.5+ **object-stream resolver**
  (`/Type /ObjStm`, ISO 32000-1 §7.5.7). `DocumentReader::resolve`
  now walks `XrefEntry::Compressed` slots — fetches the containing
  ObjStm, parses its `(obj_num offset)` header, and slices out the
  matching body. Header object-number mismatches surface as parse
  errors. Pairs naturally with the round-7 xref-stream encoder.
- Round-7 reader+writer: per-stream `/Filter /Crypt` `/Identity`
  opt-out (ISO 32000-1 §7.6.5 + §7.4.10). Streams whose first filter
  is `/Crypt` and whose `/DecodeParms /Name` is `/Identity` (or
  absent — Table 24 default) bypass per-object encryption on both
  encode and decode paths. The classic consumer is XMP metadata
  that needs to remain searchable in encrypted PDFs.

- Round-6 writer: standard-security-handler **encryption** for the
  full revision range — R=2 / R=3 / R=4 (RC4 + AES-128) / R=5 / R=6
  (AES-256). New `encrypt::EncryptionConfig` builder + `encrypt::EncryptionState`
  installed on `Document::encryption`; `write_pdf_from_scene_encrypted`
  one-shot entry point. Implements Algorithms 3, 4, 5 (V≤4) plus
  reuses 8, 9, 10 from `decrypt::r5_r6` (V=5). Round-trip tested across
  all five revisions including full encode → decrypt → re-encode →
  decrypt bounce, owner-password authentication, wrong-password
  rejection, and content-stream encryption verification.
- Round-6 reader: PDF 1.5+ cross-reference *streams* (`/Type /XRef`,
  ISO 32000-1 §7.5.8). Binary `/W [w1 w2 w3]` field decoding, optional
  `/Index` subsections, optional `/Filter /FlateDecode` body, full
  PNG-Up `/Predictor 12` (and 10..15 fallback handling) reversal.
  `XrefEntry::Compressed` variant added for type-2 entries (the
  object-stream resolver itself is the next round).
- Bug fix: `tests/external_validation.rs` `qpdf --check` test was
  piping bytes through stdin, which qpdf ≥ 11 rejects (`-` is not
  treated as stdin). Switched to a temp-file path so qpdf opens it
  by name.
- Round-4 reader: standard-security-handler decryption (ISO 32000-1
  §7.6) for revisions R=2 (RC4-40), R=3 (RC4-128), and R=4 (AES-128
  CBC or RC4-128 via `CFM`).
- Round-5 reader: AES-256 standard-handler decryption for **R=5**
  (PDF 1.7 Adobe extension level 3) and **R=6** (ISO 32000-2:2020
  PDF 2.0). Implements Algorithms 2.A, 2.B, 8, 9, 10, 11, 12 and 13
  from ISO 32000-2 §7.6.4.4 — full coverage of the AESV3 era.
- `decrypt::r5_r6` module exposing `algorithm_8` / `algorithm_9` /
  `algorithm_10` for fixture builders, plus the SHA-256/384/512
  iterated hash chain of Algorithm 2.B.
- `CryptMethod::Aes256` variant (V=5 file-key direct AES-256 CBC,
  no per-object Algorithm 1 derivation).
- `EncryptParams` is extended with `oe`, `ue`, `perms` slots that
  the reader populates for V=5 PDFs (32 / 32 / 16 bytes).
- `read_pdf_to_scene_with_password()` and
  `DocumentReader::open_with_password()` public APIs.
- `decrypt` module exposing `StandardHandler`, `CryptMethod`, plus
  hand-rolled `rc4()` / `md5()` (RFC 1321) and AES-128 CBC via the
  `aes` + `cbc` RustCrypto crates.
- New `sha2` (RustCrypto) dep for SHA-256/384/512 — pure-Rust, no
  `*-sys`. Used only by the V=5 password derivation path.
- ~32 new tests: SHA-256/384/512 FIPS 180-4 known-answers,
  Algorithm 9 → 11 user-auth round-trip (R=5 + R=6), Algorithm 10
  → 13 Perms round-trip, Algorithm 2.B determinism, file-key
  wrap/unwrap, and end-to-end fixture decode for R=5 + R=6 covering
  user / owner / wrong / empty / Unicode / >127-byte passwords.

## [0.1.0](https://github.com/OxideAV/oxideav-pdf/compare/v0.0.2...v0.1.0) - 2026-05-04

### Other

- promote to 0.1
- clippy 1.95: drop useless .into_iter() in zip; switch test literal off PI
- round 3: top-level walker — bytes → Scene roundtrip
- round 3: content-stream operator parser (inverse of operators.rs)
- round 3: cross-reference table + trailer parser
- round 3: PDF object parser (tokens → Object tree)
- round 3: PDF reader scaffold + tokenizer (ISO 32000-1 §7.2)
- round 2: scene Metadata::custom map → /Info custom keys
- round 2: scene Metadata standard fields → PDF /Info dict
- round 2: multi-page output via write_pdf_from_scene

## [0.0.2](https://github.com/OxideAV/oxideav-pdf/compare/v0.0.1...v0.0.2) - 2026-05-03

### Other

- use from_utf8_lossy for output containing the binary marker
- silence remaining lints from `-D warnings`

## [0.0.1] - 2026-05-04

### Added

- Round 1 PDF writer that emits a single-page PDF 1.4 document from an
  `oxideav_core::VectorFrame`.
- PDF imaging-model mapping for paths (move/line/cubic/quadratic-as-cubic
  /arc-as-cubic/close), solid + linear/radial gradient fills, strokes
  (width/cap/join/miter/dash), `Transform2D` (`cm`), `Group` (`q`/`Q`),
  group opacity (ExtGState `/ca` + `/CA`), clip paths (`W n`), and
  fill rules (`f` / `f*` / `B` / `B*`).
- FlateDecode `Image` XObjects for embedded uncompressed RGBA frames.
- `register()` adding a PDF encoder to `oxideav_core::CodecRegistry`
  and a write-only `pdf` muxer to `oxideav_core::ContainerRegistry`.
