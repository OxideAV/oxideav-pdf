# oxideav-pdf

Pure-Rust **PDF writer + reader** for the oxideav framework. The writer
emits PDF 1.4+ vector documents from
[`VectorFrame`](https://docs.rs/oxideav-core) /
[`Scene`](https://docs.rs/oxideav-scene) inputs (paths stay paths, fills
stay fills); the reader walks bytes back into a `Scene`, with optional
decryption for password- and certificate-protected files. Zero C
dependencies.

Part of the [oxideav](https://github.com/OxideAV/oxideav-workspace)
framework — a pure-Rust media stack. Implemented from ISO 32000-1:2008
and ISO 32000-2:2020 (no C codec libraries linked or wrapped, no `*-sys`
crates).

## Vector writing

The writer emits the full vector IR:

- **Paths**: `MoveTo` (`m`), `LineTo` (`l`), `CubicCurveTo` (`c`),
  `QuadCurveTo` (lifted to cubic), `ArcTo` (flattened to cubic per
  SVG 1.1 Appendix F.6.5), `Close` (`h`).
- **Fills**: `Paint::Solid` (DeviceRGB `sc`), `Paint::LinearGradient`
  (axial shading, `Pattern Type 2` + `Function Type 2`),
  `Paint::RadialGradient` (radial shading, `Function Type 3`).
- **Strokes**: width (`w`), cap (`J`), join (`j`), miter limit (`M`),
  dash pattern (`d`).
- **Transforms**: each `Group::transform` emits one `cm` operator.
- **Groups**: `q … Q` save/restore brackets; group opacity becomes an
  `ExtGState` resource referenced via `/GSx gs`.
- **Clip paths** (`W n` / `W* n`) and **fill rules** (`NonZero` /
  `EvenOdd`).
- **Embedded raster**: an `ImageRef` whose `VideoFrame` is RGBA8 lands
  as a FlateDecode `Image` XObject painted with `Do`.

```rust,ignore
let pdf = oxideav_pdf::write_pdf(&vector_frame)?;        // single VectorFrame
let pdf = oxideav_pdf::write_pdf_from_scene(&scene)?;    // multi-page Scene
```

## File structure: xref tables, streams, ObjStm, linearization

Both reader and writer support every PDF file-structure form:

- **Classic `xref` table** (PDF 1.0–1.4) — the writer's default, also
  accepted on input.
- **Cross-reference streams** (PDF 1.5, §7.5.8) — `/Type /XRef` with
  `/W`-packed big-endian fields, Flate-compressed with `/Predictor 12`.
  Opt in via [`write_pdf_from_scene_xref_stream`]. Hybrid-reference
  files (§7.5.8.4 — classic subsection plus an `/XRefStm` supplement)
  are merged on the read path with the spec resolution order and a
  newer-wins policy; `/Prev` and `/XRefStm` chains are bounded and
  cycle-guarded. Unknown entry types resolve to null per §7.5.8.3.
- **Object streams** (`/Type /ObjStm`, §7.5.7) — the reader resolves
  `Compressed` entries; the writer packs every compressible indirect
  object into one container via [`write_pdf_from_scene_object_stream`].
- **Linearization (Fast Web View)** (§7.5.6 + Annex F) — 
  [`write_pdf_from_scene_linearized`] emits a complete linearization
  parameter dictionary in the first 1024 bytes plus a hint stream with
  per-page offset entries. The output is also a valid plain PDF.
- **Incremental updates** (§7.5.6) —
  [`write_pdf_incremental_update`] appends a new revision (changed slots
  + `/Prev`); the reader follows the `/Prev` chain, newest-wins.

Indirect stream `/Length` references (§7.3.10) are resolved against the
xref table — the shape every one-pass writer produces.

The reader resolves the inheritable page attributes `MediaBox`,
`Resources`, and `Rotate` (§7.7.3.4) by walking the leaf page's
`/Parent` chain, so a document that defines them once on an intermediate
`/Pages` node renders at the right size, with its fonts / XObjects /
shadings in scope, and with the correct clockwise rotation on
`Page::orientation` (normalised to `0` / `90` / `180` / `270`). The walk
is depth-bounded and cycle-guarded.

## Stream filters

`decode_stream` recovers a stream's raw payload by applying its
`/Filter` (single `Name` or `Array` chain) in array order:

- **`/FlateDecode`** — zlib DEFLATE; the writer's default.
- **`/LZWDecode`** — variable-width (9–12-bit) MSB-first LZW with the
  `/EarlyChange` parameter honoured.
- **`/ASCII85Decode`**, **`/ASCIIHexDecode`**, **`/RunLengthDecode`** —
  in single + chain position, including the inline-image abbreviations.
- **`/DecodeParms /Predictor`** post-filter — PNG predictors (`10..=15`)
  and TIFF Predictor 2, with sub-byte `/BitsPerComponent` handling.

Terminal image-codec filters (`/DCTDecode`, `/JPXDecode`,
`/JBIG2Decode`, `/CCITTFaxDecode`) are not decoded here — they route to
the dedicated image walkers that hand the opaque payload to a codec
crate.

The DEFLATE/zlib layer runs on [`compcol`](https://crates.io/crates/compcol),
the workspace-wide pure-Rust compression collection.

## Encryption

### Password (standard security handler)

Reader and writer cover the full revision range ISO 32000 defines:
R=2 (RC4-40), R=3 (RC4-128), R=4 (AES-128 CBC or RC4-128 via `CFM`),
R=5 (AES-256, Adobe extension level 3), R=6 (AES-256, ISO 32000-2:2020,
Algorithm 2.B iterated hash chain + `/Perms` validation). Both user and
owner passwords authenticate; the empty user password is tried first.

```rust,ignore
// Read — empty user password tried automatically.
let scene = oxideav_pdf::read_pdf_to_scene(&pdf)
    .or_else(|_| oxideav_pdf::read_pdf_to_scene_with_password(&pdf, b"hunter2"))?;

// Write.
use oxideav_pdf::encrypt::EncryptionConfig;
let cfg = EncryptionConfig::aes_256_r6(b"hunter2", b"FILE-ID-16-BYTES");
let pdf = oxideav_pdf::write_pdf_from_scene_encrypted(&scene, &cfg)?;
```

A stream may opt out of per-object encryption via `/Crypt /Identity`
(§7.6.5) on both read and write — the classic case is searchable XMP
metadata in an encrypted file.

### Public-key (certificate)

Reader and writer handle public-key-encrypted PDFs under the
`adbe.pkcs7.s3` / `s4` / `s5` SubFilters (ISO 32000-1 §7.6.4 +
ISO 32000-2 §7.6.5):

- **KTRI** (key transport) — `RSAES-PKCS1-v1_5`, matched by
  `IssuerAndSerialNumber` or `SubjectKeyIdentifier`.
- **KARI** (key agreement) — ECDH on P-256 / P-384 / P-521, X25519, and
  X448, with X9.63 and HKDF KDFs and RFC 3394 AES Key Wrap.

Content algorithms RC4 / AES-128 / AES-256 CBC encode and decode;
legacy RC2-CBC and DES-EDE3-CBC decode (read-only). Long-term-cert
originators resolve through a `TrustStore`, with temporal-validity
lookup for multi-generation archives.

```rust,ignore
use oxideav_pdf::{read_pdf_to_scene_with_certificate, PubSecCredential};
let credential = PubSecCredential::from_der(&cert_der, &pkcs8_der)?;
let scene = read_pdf_to_scene_with_certificate(&pdf_bytes, &credential)?;
```

Writer entry points: [`write_pdf_from_scene_pubsec_encrypted`],
[`write_pdf_from_scene_pubsec_kari`] (key-agreement recipients), and
[`write_pdf_from_scene_pubsec_multi_cf`] (per-crypt-filter permission
sets, each its own envelope).

## Digital signatures

The `sig` module emits signed PDFs with valid `/ByteRange` + CMS
`SignedData` `/Contents` blobs (ISO 32000-1 §12.7.4.5 + §12.8.1 +
RFC 5652). The placeholder-fill-in pattern is implemented end-to-end; a
[`Signer`] trait decouples the crypto (reference
[`RsaPkcs1v15Sha256Signer`] / [`EcdsaP256Sha256Signer`] provided, or
bring your own HSM).

```rust,ignore
use oxideav_pdf::{sign_pdf_from_scene, RsaPkcs1v15Sha256Signer, SignerIdentity};
let signer = RsaPkcs1v15Sha256Signer::new(private_key);
let identity = SignerIdentity::from_signer_cert_der(cert_der)?;
let signed_pdf = sign_pdf_from_scene(&scene, &signer, identity)?;
```

[`add_document_timestamp`] appends an RFC 3161 Document Time-Stamp
revision (§12.8.5) via a [`TsaSigner`] integration seam.

Verification: `pubsec::verify::verify_signature` resolves the signer
cert from a pool, hashes the canonical `signedAttrs` re-encoding, and
verifies against `signature`. Hash: SHA-1 / SHA-256 / SHA-384 /
SHA-512. Signature: RSA-PKCS#1 v1.5, RSA-PSS, and ECDSA on P-256 /
P-384 / P-521; the `messageDigest` attribute is cross-checked against
the eContent hash, and detached (PAdES) signatures are supported.
`DocumentReader::signatures()` surfaces each `/Sig` field with its
`/ByteRange`, `/Contents`, `/SubFilter`, metadata, and parsed
`SignedData`; `PdfSignature::signed_message` rebuilds the hashed bytes
for an end-to-end verify.

## Reader extraction surfaces

[`DocumentReader::open`] gives access to a family of extraction walkers:

- **Text extraction** — `text_extraction()` emits one `TextRun` per
  `Tj` / `TJ` / `'` / `"` show with text-matrix origin, font + size, and
  Unicode mapping via `/ToUnicode` CMap (mixed-width codespaces honoured)
  or simple-font encoding (`WinAnsi` / `MacRoman` / `/Differences` over
  the Adobe Glyph List, including `uniXXXX` / `uXXXXXXXX` escapes). `TJ`
  word-break gaps are recovered, and each run carries its text render
  mode (`Tr` — including the invisible OCR layer) and text rise (`Ts`).
  Consecutive shows on one line advance the text origin per §9.4.4
  (`tx = ((w0 − Tj/1000)·Tfs + Tc + Tw)·Th`) using per-glyph `/Widths`
  (simple) or `/W` / `/DW` (Type0 Identity) metrics, so runs without an
  explicit `Td` / `Tm` still get distinct positions. Type 3 font widths
  are scaled into text space by the font's `/FontMatrix` (§9.6.5), not
  the 1/1000 Type1 convention.
- **Logical reading order** — `read_in_logical_order()` walks the
  `/StructTreeRoot` tree (Tagged PDF, §14.6–14.8) and emits runs in
  author order, falling back to raster order when no struct tree exists.
- **Image XObjects** — `image_xobjects()` surfaces every `/DCTDecode`
  Image XObject as a self-contained JPEG stream with dimensions,
  colour space, and bits-per-component.
- **Inline images** — `inline_images()` surfaces every `BI … ID … EI`
  triplet (§8.9.7) with its filter tag. The content-stream walker also
  consumes inline images in place (so a binary payload no longer
  corrupts the surrounding shapes or aborts the parse) and reports each
  on `ParsedContent::inline_images` as a `ContentInlineImage` with the
  CTM (unit-square → user-space placement) and active clip.
- **Annotations** — `annotations()` decodes the §12.5.6 subtype taxonomy
  (Text, FreeText, the markup variants, Line, Polygon, PolyLine, Ink,
  Caret, Popup, FileAttachment, Watermark, Redact, Sound, Movie, Screen,
  PrinterMark, TrapNet, 3D, …) with common Table 164 fields.
- **Optional content / OCG layers** — `optional_content()` resolves
  group visibility from `/OCProperties` (§8.11), including OCMD
  membership and `/VE` visibility expressions.
- **Actions** — `actions()` enumerates every action carrier (catalog /
  page / annotation / form-field `/AA` + `/A`, JavaScript name tree),
  following `/Next` chains, with per-type payload decode.
- **XMP metadata** — `xmp_packet()` parses the document `/Metadata`
  packet into a structured `XmpPacket` (Dublin Core, XMP Basic, PDF
  schema, PDF/A identification).
- **Embedded attachments** — [`read_pdf_attachments`] walks the
  `/Names → /EmbeddedFiles` name tree, surfacing PDF 2.0 Associated
  Files (`/AFRelationship`).

## Content-stream colour & state

The content parser honours DeviceGray / DeviceRGB / DeviceCMYK (`g` /
`rg` / `k` and the `cs`/`CS` + `sc`/`scn` forms, §8.6), resource colour
spaces (`ICCBased` via `/Alternate` or `/N`; `Indexed`; the CIE-based
families `CalGray` (§8.6.5.2), `CalRGB` (§8.6.5.3) and `Lab` (§8.6.5.4),
each decoded to CIE 1931 XYZ via its `/WhitePoint` / `/Gamma` / `/Matrix`
/ `/Range` and reduced to device RGB through the standard sRGB display
colorimetry; `Separation` and
`DeviceN` (§8.6.6.5) with Type 0 sampled / Type 2 / Type 3 / Type 4
PostScript-calculator tint transforms, §7.10 — Type 0 sampled functions
interpolate over any number of input dimensions, `/Order 1` multilinear
or `/Order 3` cubic-spline (a per-axis Catmull-Rom blend through the four
nearest knots, with the §7.10.2 `/Size < 4` linear fallback), so a
multi-colorant DeviceN tint transform maps through its device
alternate), the `gs` ExtGState operator (line state
+ alpha, cumulative), `Tj`/`TJ` text shows resolved against
`/Resources /Font`, and the marked-content operators
(`BMC`/`BDC`/`EMC`/`MP`/`DP`, §14.6) with named-property resolution.

**Form XObjects** (§8.10) painted via `name Do` are spliced into the
`Scene`: the page's `/Resources /XObject` subdictionary is resolved, each
`/Subtype /Form` entry's content stream decoded and recursively parsed
against its own `/Resources` (including nested Form XObjects), and the
result becomes a nested `Group` carrying the form's `/Matrix` as its
transform and the `/BBox` rectangle as its clip — the §8.10.1
q / concat-Matrix / clip-BBox / paint / Q algorithm. Form recursion is
depth-bounded and cycle-guarded, so a self-referential appearance stream
terminates. Image XObjects stay a vector-side no-op (surfaced separately
by `image_xobjects()`).

**Type 3 font glyphs** (§9.6.5) are painted into the `Scene` as vector
geometry. A Type 3 font is the one simple-font family whose glyphs are
themselves content streams (`/CharProcs`) of PDF marking operators — no
external font program, so no glyph rasteriser is needed. On a
`Tj` / `TJ` / `'` / `"` show under a Type 3 font, the reader resolves
each character code through `/Encoding /Differences` to a glyph name
(§9.6.6.1), looks the name up in `/CharProcs` to get its description
stream (parsed against the font's own `/Resources` into a `Group`), and
splices that group at the glyph's text-rendering matrix —
`Tm ∘ [Tfs·Th 0 0 Tfs 0 Trise] ∘ /FontMatrix` (§9.4.4) — advancing the
glyph origin between the bytes of a single show by each glyph's
`/Widths` displacement. The `d0` / `d1` glyph-metric operators
(Table 113) are consumed (the width comes from `/Widths`, the bbox is
advisory); render mode 3 (invisible OCR layer) paints nothing, and a
glyph absent from `/Encoding` or `/CharProcs` is skipped. Glyph
descriptions that themselves show Type 3 text are depth-bounded.

The `sh` shading-paint operator (§8.7.4.5) surfaces a `ContentShading`
event per paint with the resolved shading dictionary, the effective CTM,
and the active clip. A **clipped** axial / radial `sh` is additionally
painted into the `Scene`: the active clip path is filled with the
equivalent `Paint::LinearGradient` / `Paint::RadialGradient`, so a
gradient drawn by `… W n /Sh sh` is visible rather than event-only. (An
unclipped `sh` would fill the whole page, so it stays event-only;
function-based and mesh shadings have no `Paint` analogue.) **Type 1–3
shadings** (function-based / axial /
radial, §8.7.4.5.2–4) are evaluated to geometry + sampled colour stops
on `ContentShading::gradient`: an axial shading carries its axis
endpoints + `Extend` flags + 64 RGB stops across the parametric domain; a
radial shading carries its two circles + stops; a function-based shading
carries its domain rectangle + `Matrix` + a 16×16 RGB sample grid of its
2-in/n-out colour function. **Type 4–7 (mesh) shadings** (§8.7.4.5.5–8)
are evaluated to device-space geometry on `ContentShading::mesh`:
free-form
(Type 4) and lattice-form (Type 5) Gouraud triangle meshes become a list
of triangles with per-vertex RGB; Coons (Type 6) and tensor-product
(Type 7) patch meshes become a list of bicubic patches with four corner
colours (Coons patches expanded to the 16-control-point tensor form via
the §8.7.4.5.8 internal-control-point equations). The bit-packed stream
body is unpacked at the dictionary's `BitsPerCoordinate` /
`BitsPerComponent` / `BitsPerFlag` widths, decoded through the `Decode`
array (§8.9.5.2), and each vertex / corner colour reduced through the
shading's `ColorSpace` and optional parametric `/Function`. Edge-flag
triangle/patch continuation (Tables 85/86) is honoured. `mesh` and
`gradient` are mutually exclusive — a Type 1–3 shading populates
`gradient` (and leaves `mesh` `None`), a Type 4–7 shading the reverse. A
shading's `/ColorSpace` may be an inline array or a *named*
`/Resources /ColorSpace` key (resolved like `cs`/`CS`).

**Shading-pattern fills** (`/PatternType 2`, §8.7.3.3) paint directly
into the `Scene`: a `scn`/`SCN` whose `/Pattern` operand names a shading
pattern becomes a `Paint::LinearGradient` (axial) or
`Paint::RadialGradient` (radial), with the shading axis / circles mapped
to device space through the pattern `/Matrix` composed with the CTM.

**Tiling-pattern fills** (`/PatternType 1`, §8.7.3) replicate the pattern
cell across the filled region. Each tiling pattern's cell content stream
is decoded and parsed against its own `/Resources` (fonts, ExtGState,
shadings, colour spaces, nested Form XObjects, even nested tiling
patterns) into a cell `Group`; a `scn`/`SCN` naming the pattern then
tiles that cell at integer multiples of `/XStep` / `/YStep` (§8.7.3.1)
over the painted region's bounding box, clipping each tile to the cell
`/BBox` and the whole tiling to the fill path. The cell lattice is
anchored to the page's default coordinate space through the pattern
`/Matrix` independent of any `cm` in force (§8.7.2 NOTE 1); the tile
count is hard-capped (4096) and a degenerate / singular pattern matrix
falls back to black. A coloured cell (`/PaintType 1`) paints with its
own colours; an **uncoloured** cell (`/PaintType 2`, §8.7.3.3) is a
stencil poured with the underlying colour the `scn` supplies before the
pattern name (`c… /Pname scn`, read by component count — gray / RGB /
CMYK), so the same cell shape tiles different regions in different
colours.

## Interactive-form & annotation writers

- [`write_pdf_with_form`] emits an `/AcroForm` with Text, Checkbox,
  Radio, Choice, and Signature widgets (§12.7.4).
- [`write_pdf_with_annotations`] emits the §12.5.6 subtype taxonomy
  symmetric to the reader (Text, Link, FreeText, the markup variants,
  Square, Circle, Ink, Line, Polygon, PolyLine, Caret, Popup,
  FileAttachment, Sound, Watermark, PrinterMark).
- [`write_pdf_with_attachments`] embeds files as `/EmbeddedFile` streams
  with `/Filespec` dictionaries in the `/Names → /EmbeddedFiles` tree,
  optionally with `/FileAttachment` annotation markers and PDF 2.0
  `/AFRelationship`.
- [`write_pdf_from_scene_with_outlines`] /
  [`write_pdf_from_scene_with_xmp`] add document outline and XMP packet.

## Fuzzing & benchmarks

A cargo-fuzz harness lives under `fuzz/` with three decode-side targets
(`parse`, `xref`, `decrypt`) asserting the public reader entry points
always return a `Result` rather than panicking, aborting, or OOMing.
The corpus is seeded with in-tree fixtures; a hard parse-depth ceiling
and cycle guards protect the resolver and parser. CI runs the suite
daily.

Three Criterion bench binaries under `benches/` measure the reader hot
paths (`reader_open`, `xref`, `content_stream`) against writer-emitted
PDFs. `examples/profile_read.rs` is a reproducible profiling harness for
the bytes → `Scene` path.

```sh
cargo bench -p oxideav-pdf --bench reader_open
```

## Deferred

- Writer-side `BT … Tj … ET` text emission for `Node::Text` (the
  reader-side extraction surface is complete).
- Writer-side JPEG passthrough on `ImageRef` (needs core IR support for
  raw codec bytes; the reader-side surface is complete).
- Ed25519 / Ed448 signature dispatch in `pubsec::verify`.
- Transparency groups beyond per-`Group` `/ca` + `/CA` opacity.
- DeviceN `/Attributes` NChannel custom-blending hints (`/Colorants`,
  `/Process`, `/MixingHints`); the space still renders through its
  `alternateSpace` + `tintTransform`, which §8.6.6.5 permits.

## Usage

```toml
[dependencies]
oxideav-core = "0.1"
oxideav-pdf  = "0.0"
```

```rust
use oxideav_core::{
    FillRule, Group, Node, Paint, Path, PathNode, Point, Rgba, TimeBase,
    VectorFrame,
};

let mut p = Path::new();
p.move_to(Point::new(10.0, 10.0))
    .line_to(Point::new(110.0, 10.0))
    .line_to(Point::new(110.0, 60.0))
    .line_to(Point::new(10.0, 60.0))
    .close();

let frame = VectorFrame {
    width: 200.0,
    height: 100.0,
    view_box: None,
    root: Group {
        children: vec![Node::Path(PathNode {
            path: p,
            fill: Some(Paint::Solid(Rgba::opaque(0xFF, 0x80, 0x00))),
            stroke: None,
            fill_rule: FillRule::NonZero,
        })],
        ..Group::default()
    },
    pts: None,
    time_base: TimeBase::new(1, 1),
};

let pdf = oxideav_pdf::write_pdf(&frame).expect("vector → PDF");
std::fs::write("out.pdf", pdf).unwrap();
# Ok::<(), Box<dyn std::error::Error>>(())
```

## License

MIT — see [LICENSE](LICENSE).
