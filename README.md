# oxideav-pdf

Pure-Rust **PDF writer + reader** for the oxideav framework. The
writer emits PDF 1.4 vector documents from
[`VectorFrame`](https://docs.rs/oxideav-core) /
[`Scene`](https://docs.rs/oxideav-scene) inputs (paths stay paths,
fills stay fills); the reader walks bytes back into a Scene, with
optional decryption for password-protected files. Zero C dependencies.

Part of the [oxideav](https://github.com/OxideAV/oxideav-workspace) framework — a pure-Rust media stack. Codec, container, and filter crates are implemented from the spec (no C codec libraries linked or wrapped, no `*-sys` crates).

## What round 1 supports

- **Paths**: `MoveTo` (`m`), `LineTo` (`l`), `CubicCurveTo` (`c`),
  `QuadCurveTo` (lifted to cubic via the `2/3 * (control - endpoint)`
  trick), `ArcTo` (flattened to cubic per SVG 1.1 Appendix F.6.5),
  `Close` (`h`).
- **Fills**: `Paint::Solid` (DeviceRGB `sc`), `Paint::LinearGradient`
  (axial pattern shading, `Pattern Type 2` + `Function Type 2`),
  `Paint::RadialGradient` (radial shading, `Function Type 3`).
- **Strokes**: width (`w`), cap (`J`), join (`j`), miter limit (`M`),
  dash pattern (`d`).
- **Transforms**: every `Group::transform` emits one `cm` operator.
- **Groups**: `q ... Q` save/restore brackets around children. Group
  opacity becomes an `ExtGState` resource referenced via `/GSx gs`.
- **Clip paths**: emitted before the children's content stream as `W n`
  (or `W* n` for even-odd fill rule).
- **Fill rules**: `NonZero` (`f` / `B`) vs. `EvenOdd` (`f*` / `B*`).
- **Embedded raster**: `ImageRef` whose underlying `VideoFrame` is
  RGBA8 lands as a FlateDecode `Image` XObject and is painted with `Do`.

## Encryption decode (full Standard handler)

The reader handles **password-protected PDFs** under the standard
security handler across the full revision range ISO 32000 defines:

- **R=2** — RC4-40 (V=1, `Length=40`).
- **R=3** — RC4-128 (V=2, `Length=128`).
- **R=4** — AES-128 CBC or RC4-128, picked from the crypt-filter
  `CFM` (`AESV2` vs `V2`).
- **R=5** — AES-256 CBC, V=5, `CFM=AESV3`. Adobe extension level 3
  (PDF 1.7); plain SHA-256 password derivation with validation +
  key salts.
- **R=6** — AES-256 CBC, V=5, `CFM=AESV3`. ISO 32000-2:2020
  (PDF 2.0); iterated SHA-256/384/512 hash chain (Algorithm 2.B)
  plus `/Perms` block validation (Algorithm 13).

Both user and owner passwords authenticate (Algorithms 6 + 7 for
R≤4; Algorithms 11 + 12 for R≥5); the default empty user password
is tried first so PDFs encrypted "just for permission flags" open
with no caller intervention. Strings and stream payloads are
decrypted via per-object keys (Algorithm 1) for R≤4 and via the
file key directly (no per-object derivation) for R≥5.

```rust
let pdf = std::fs::read("locked.pdf")?;
// Default API tries the empty user password.
match oxideav_pdf::read_pdf_to_scene(&pdf) {
    Ok(scene) => println!("opened: {} pages", scene.pages.unwrap().len()),
    Err(_)    => {
        // Password-protected — supply one.
        let scene = oxideav_pdf::read_pdf_to_scene_with_password(&pdf, b"hunter2")?;
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Public-key handlers (`adbe.pkcs7.s3` / `s4` / `s5`) and per-stream
crypt-filter overrides land in a follow-up round.

## Encryption encode (writer side)

The writer emits password-protected PDFs across the same revision range
the reader handles. [`oxideav_pdf::write_pdf_from_scene_encrypted`]
takes a [`Scene`] and an [`encrypt::EncryptionConfig`] and produces
bytes that round-trip through `read_pdf_to_scene_with_password`:

```rust
use oxideav_pdf::encrypt::EncryptionConfig;

let cfg = EncryptionConfig::aes_256_r6(b"hunter2", b"FILE-ID-16-BYTES");
let pdf = oxideav_pdf::write_pdf_from_scene_encrypted(&scene, &cfg)?;
# Ok::<(), oxideav_pdf::PdfError>(())
```

Writer-side coverage matches the reader: R=2 (RC4-40), R=3 (RC4-128),
R=4 (AES-128 / RC4 via `CFM`), R=5 (Adobe ext L3), R=6 (ISO 2.0).
`/O`, `/U`, `/OE`, `/UE`, and `/Perms` come from the canonical
algorithms (3, 4, 5 for V≤4; 8, 9, 10 for V=5); per-object key
derivation is Algorithm 1 (V≤4) or the file key directly (V=5).

## Cross-reference streams

Both reader and writer support the binary cross-reference *stream*
form introduced in PDF 1.5 (ISO 32000-1 §7.5.8): a `/Type /XRef`
stream object whose body packs each entry into `/W [w1 w2 w3]`
big-endian fields, Flate-compressed with `/Predictor 12` (PNG-Up).
The classical `xref`-keyword form (PDF 1.0..1.4) is also accepted
on input and remains the writer's default; opt into the stream form
via [`oxideav_pdf::write_pdf_from_scene_xref_stream`].

## Object streams

Both reader and writer support PDF 1.5+ object streams
(`/Type /ObjStm`, ISO 32000-1 §7.5.7). The reader resolves
`Compressed` xref entries by fetching the containing object stream,
parsing its `(obj_num offset)` header, and returning the body bytes
from the matching slot. The writer packs every compressible
indirect object (every dict that isn't a stream and isn't the
Catalog) into one ObjStm container — opt in via
[`oxideav_pdf::write_pdf_from_scene_object_stream`]. Stream objects
(content streams, image XObjects, the xref stream itself) cannot be
compressed per §7.5.7 and remain at their own byte offsets.

## Incremental updates

[`oxideav_pdf::write_pdf_incremental_update`] appends new revisions
to a previously-written PDF per ISO 32000-1 §7.5.6 — the new
revision's body is appended verbatim, followed by a new xref
subsection that lists only the changed slots, plus a trailer
carrying `/Prev <prev_xref_off>` pointing back at the original
revision. The reader follows the `/Prev` chain and merges entries:
the newest revision wins on overlap.

```rust,ignore
let original = oxideav_pdf::write_pdf_from_scene(&scene_v1)?;
// ... time passes; user adds two pages ...
let updated = oxideav_pdf::write_pdf_incremental_update(&original, &new_pages)?;
// `updated` starts with `original` byte-for-byte, then appends.
```

## Per-stream `/Crypt /Identity` opt-out

ISO 32000-1 §7.6.5 lets a single stream opt out of per-object
encryption by listing `/Crypt` as its first `/Filter` with
`/DecodeParms /Name /Identity` (or no `/Name` — the default per
§7.4.10 Table 24). The writer leaves such streams untouched while
encrypting the rest of the file; the reader applies the same rule
on input. The classic consumer is XMP metadata streams that need to
remain searchable in encrypted PDFs.

## Deferred

- Text (waiting on `Node::Text`; will use Type 0 fonts with a
  CIDFont built via `oxideav-ttf`/`oxideav-otf`).
- JPEG passthrough on `ImageRef` (DCTDecode XObject) — needs core
  IR support for "raw codec bytes" alongside the decoded VideoFrame.
- Public-key security handlers (`adbe.pkcs7.*`).
- Linearization (§7.5.6 "Fast Web View" structural reorganisation).
- Combined ObjStm + encryption (round 8 emits one or the other,
  not both — the §7.6.1 + §7.5.7 unit-encryption interplay needs
  careful handling).
- Transparency groups beyond a per-`Group` `/ca`+`/CA` opacity.

## Usage

```toml
[dependencies]
oxideav-core = "0.1"
oxideav-pdf  = "0.0"
```

```rust
use oxideav_core::{
    FillRule, Group, Node, Paint, Path, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_core::TimeBase;

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
