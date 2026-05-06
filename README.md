# oxideav-pdf

Pure-Rust **PDF writer** for the oxideav framework. Round 1 emits a
single-page PDF 1.4 document from a vector-graphics
[`VectorFrame`](https://docs.rs/oxideav-core) — paths stay paths, fills
stay fills, no rasterisation along the way. Zero C dependencies.

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

## Round-2 deferrals

- Text (waiting on `Node::Text`; will use Type 0 fonts with a
  CIDFont built via `oxideav-ttf`/`oxideav-otf`).
- JPEG passthrough on `ImageRef` (DCTDecode XObject).
- Multi-page documents.
- Transparency groups beyond a per-`Group` `/ca`+`/CA` opacity.
- PDF reading (this crate is write-only by design — a parser would be
  a separate `oxideav-pdf-parse` crate).

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
