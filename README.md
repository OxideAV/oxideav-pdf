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

## Round-4 reader: encryption decode

The reader handles **password-protected PDFs** under the standard
security handler (ISO 32000-1 §7.6) for revisions 2/3/4:

- **R=2** — RC4-40 (V=1, `Length=40`).
- **R=3** — RC4-128 (V=2, `Length=128`).
- **R=4** — AES-128 CBC or RC4-128, picked from the crypt-filter
  `CFM` (`AESV2` vs `V2`).

Both user and owner passwords authenticate (Algorithms 6 + 7); the
default empty user password is tried first so PDFs that are encrypted
"just for permission flags" open with no caller intervention. Strings
and stream payloads are decrypted via per-object keys (Algorithm 1).

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

R=5 / R=6 (AES-256, PDF 1.7 Adobe extension and PDF 2.0 ISO blessed),
public-key handlers (`adbe.pkcs7.s3` / `s4` / `s5`), and per-stream
crypt-filter overrides land in a follow-up round.

## Deferred

- Text (waiting on `Node::Text`; will use Type 0 fonts with a
  CIDFont built via `oxideav-ttf`/`oxideav-otf`).
- JPEG passthrough on `ImageRef` (DCTDecode XObject).
- Encryption *encode* (write side; the reader decrypts but the writer
  doesn't yet emit `/Encrypt`).
- AES-256 (R=5/R=6) and public-key security handlers.
- Cross-reference streams (PDF 1.5+ `/Type /XRef`).
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
