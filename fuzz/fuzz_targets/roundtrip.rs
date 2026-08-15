#![no_main]

//! Write → read round-trip fuzz harness.
//!
//! The other targets attack the reader with hostile bytes. This one
//! attacks the **writer** with a valid-by-construction document plan
//! and then feeds the writer's own output back through the reader, so
//! it exercises the encode surface and the write→read contract:
//!
//!   1. A [`oxideav_core::vector::VectorFrame`] page plan is built
//!      deterministically from the fuzz input — path geometry, fills
//!      (solid + axial/radial gradients), strokes (width / cap / join /
//!      miter / dash), a group transform, clip, and opacity. Some
//!      coordinates are the raw fuzz bytes reinterpreted as `f32`, so
//!      the writer sees NaN / ±Inf / subnormal / extreme values — the
//!      numeric-emission path (§7.3.3 real-object syntax) must produce
//!      a well-formed file or a clean `Err`, never a panic.
//!   2. The plan is written through **every** serialiser variant: the
//!      single-frame `write_pdf`, the multi-page `write_pdf_from_scene`,
//!      the §7.5.8 cross-reference-stream writer, the §7.5.7
//!      object-stream writer, and the §7.5.6 linearized writer — the
//!      distinct §7.5 file-structure state machines.
//!   3. Each `Ok` output is fed back through `read_pdf_to_scene` and a
//!      couple of extraction walkers, and used as the base revision for
//!      an incremental-update append (§7.5.6). The writer's own output
//!      must always re-open without panicking.
//!
//! Contract: every call returns to its caller. A `panic!`,
//! `unwrap()` on `None`, slice-OOB, integer-overflow in debug, or OOM
//! abort is a finding and fails the fuzzer.

use libfuzzer_sys::fuzz_target;
use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, GradientStop, Group, LineCap, LineJoin, LinearGradient, Node, Paint, Path,
    PathCommand, PathNode, Point, RadialGradient, Rgba, SpreadMethod, Stroke, Transform2D,
    VectorFrame,
};
use oxideav_pdf::{
    read_pdf_outline, read_pdf_to_scene, write_pdf, write_pdf_from_scene,
    write_pdf_from_scene_linearized, write_pdf_from_scene_object_stream,
    write_pdf_from_scene_xref_stream, write_pdf_incremental_update,
};
use oxideav_scene::{Page, Scene};

/// A tiny big-endian byte cursor. Exhausted reads return `0`, so the
/// builder is total over any input length.
struct Cur<'a> {
    d: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(d: &'a [u8]) -> Self {
        Cur { d, i: 0 }
    }
    fn u8(&mut self) -> u8 {
        let v = self.d.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        u16::from(self.u8()) << 8 | u16::from(self.u8())
    }
    /// A "tame" coordinate: a finite value in roughly `-1024..=1024`.
    fn coord(&mut self) -> f32 {
        (i32::from(self.u16()) - 32768) as f32 / 32.0
    }
    /// A hostile coordinate: the raw 4 fuzz bytes reinterpreted as
    /// `f32`, so NaN / ±Inf / subnormal / huge magnitudes all reach
    /// the writer.
    fn wild_f32(&mut self) -> f32 {
        f32::from_bits(
            u32::from(self.u8()) << 24
                | u32::from(self.u8()) << 16
                | u32::from(self.u8()) << 8
                | u32::from(self.u8()),
        )
    }
    /// A coordinate that is *usually* tame but sometimes hostile.
    fn maybe_wild(&mut self) -> f32 {
        if self.u8() & 0x03 == 0 {
            self.wild_f32()
        } else {
            self.coord()
        }
    }
    fn point(&mut self) -> Point {
        Point::new(self.maybe_wild(), self.maybe_wild())
    }
    fn rgba(&mut self) -> Rgba {
        Rgba::new(self.u8(), self.u8(), self.u8(), self.u8())
    }
    fn done(&self) -> bool {
        self.i >= self.d.len()
    }
}

fn build_paint(c: &mut Cur) -> Paint {
    match c.u8() % 3 {
        0 => Paint::Solid(c.rgba()),
        1 => {
            let g = LinearGradient::new(c.point(), c.point())
                .with_stops(vec![
                    GradientStop::new(0.0, c.rgba()),
                    GradientStop::new(c.maybe_wild(), c.rgba()),
                    GradientStop::new(1.0, c.rgba()),
                ])
                .with_spread(match c.u8() % 3 {
                    0 => SpreadMethod::Pad,
                    1 => SpreadMethod::Reflect,
                    _ => SpreadMethod::Repeat,
                });
            Paint::LinearGradient(g)
        }
        _ => {
            let g = RadialGradient::new(c.point(), c.maybe_wild())
                .with_focal(c.point())
                .with_stops(vec![
                    GradientStop::new(0.0, c.rgba()),
                    GradientStop::new(1.0, c.rgba()),
                ]);
            Paint::RadialGradient(g)
        }
    }
}

fn build_path(c: &mut Cur) -> Path {
    let mut p = Path::new();
    let n = (c.u8() % 12) as usize + 1;
    for _ in 0..n {
        match c.u8() % 6 {
            0 => p.commands.push(PathCommand::MoveTo(c.point())),
            1 => p.commands.push(PathCommand::LineTo(c.point())),
            2 => p.commands.push(PathCommand::QuadCurveTo {
                control: c.point(),
                end: c.point(),
            }),
            3 => p.commands.push(PathCommand::CubicCurveTo {
                c1: c.point(),
                c2: c.point(),
                end: c.point(),
            }),
            4 => p.commands.push(PathCommand::ArcTo {
                rx: c.maybe_wild(),
                ry: c.maybe_wild(),
                x_axis_rot: c.maybe_wild(),
                large_arc: c.u8() & 1 == 1,
                sweep: c.u8() & 1 == 1,
                end: c.point(),
            }),
            _ => p.commands.push(PathCommand::Close),
        }
    }
    p
}

fn build_stroke(c: &mut Cur) -> Stroke {
    let mut s = Stroke::new(c.maybe_wild(), build_paint(c));
    s.cap = match c.u8() % 3 {
        0 => LineCap::Butt,
        1 => LineCap::Round,
        _ => LineCap::Square,
    };
    s.join = match c.u8() % 3 {
        0 => LineJoin::Miter,
        1 => LineJoin::Round,
        _ => LineJoin::Bevel,
    };
    s.miter_limit = c.maybe_wild();
    s
}

fn build_node(c: &mut Cur, depth: u8) -> Node {
    // Occasionally nest a group; bounded so the plan stays small.
    if depth < 3 && c.u8() % 5 == 0 {
        Node::Group(build_group(c, depth + 1))
    } else {
        let mut pn = PathNode::new(build_path(c));
        if c.u8() & 1 == 1 {
            pn.fill = Some(build_paint(c));
        }
        if c.u8() & 1 == 1 {
            pn.stroke = Some(build_stroke(c));
        }
        pn.fill_rule = if c.u8() & 1 == 1 {
            FillRule::EvenOdd
        } else {
            FillRule::NonZero
        };
        Node::Path(pn)
    }
}

fn build_group(c: &mut Cur, depth: u8) -> Group {
    let mut g = Group::default();
    g.opacity = f32::from(c.u8()) / 255.0;
    if c.u8() & 1 == 1 {
        g.transform = Transform2D {
            a: c.maybe_wild(),
            b: c.maybe_wild(),
            c: c.maybe_wild(),
            d: c.maybe_wild(),
            e: c.maybe_wild(),
            f: c.maybe_wild(),
        };
    }
    if c.u8() % 4 == 0 {
        g.clip = Some(build_path(c));
    }
    let n = (c.u8() % 6) as usize + 1;
    for _ in 0..n {
        if c.done() {
            break;
        }
        g.children.push(build_node(c, depth));
    }
    g
}

fn build_frame(c: &mut Cur) -> VectorFrame {
    VectorFrame {
        width: if c.u8() & 1 == 1 {
            c.maybe_wild()
        } else {
            f32::from(c.u16()).max(1.0)
        },
        height: if c.u8() & 1 == 1 {
            c.maybe_wild()
        } else {
            f32::from(c.u16()).max(1.0)
        },
        view_box: None,
        root: build_group(c, 0),
        pts: None,
        time_base: TimeBase::new(1, 1),
    }
}

/// Feed a serialised document back through the reader — it must always
/// re-open without panicking, and the extraction walkers must survive
/// the writer's own output.
fn reopen(pdf: &[u8]) {
    let _ = read_pdf_to_scene(pdf);
    if let Ok(_scene) = read_pdf_to_scene(pdf) {
        if let Ok(mut r) = oxideav_pdf::reader::DocumentReader::open(pdf) {
            let _ = read_pdf_outline(&mut r);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cur::new(data);

    // Single-frame writer.
    let frame = build_frame(&mut c);
    if let Ok(pdf) = write_pdf(&frame) {
        reopen(&pdf);
    }

    // Multi-page Scene (1..=3 pages), driven through every file
    // structure variant.
    let page_count = (c.u8() % 3) as usize + 1;
    let mut pages = Vec::with_capacity(page_count);
    for _ in 0..page_count {
        let f = build_frame(&mut c);
        let mut page = Page::new(f.width.max(1.0).min(14400.0), f.height.max(1.0).min(14400.0));
        page.content = f;
        pages.push(page);
    }
    let scene = Scene {
        pages: Some(pages),
        ..Scene::default()
    };

    let mut base: Option<Vec<u8>> = None;
    if let Ok(pdf) = write_pdf_from_scene(&scene) {
        reopen(&pdf);
        base = Some(pdf);
    }
    if let Ok(pdf) = write_pdf_from_scene_xref_stream(&scene) {
        reopen(&pdf);
    }
    if let Ok(pdf) = write_pdf_from_scene_object_stream(&scene) {
        reopen(&pdf);
    }
    if let Ok(pdf) = write_pdf_from_scene_linearized(&scene) {
        reopen(&pdf);
    }

    // Incremental update (§7.5.6): append one more page to a valid
    // base revision, then re-open the appended file.
    if let Some(base_pdf) = base {
        let extra = build_frame(&mut c);
        let mut extra_page = Page::new(
            extra.width.max(1.0).min(14400.0),
            extra.height.max(1.0).min(14400.0),
        );
        extra_page.content = extra;
        if let Ok(updated) = write_pdf_incremental_update(&base_pdf, &[extra_page]) {
            reopen(&updated);
        }
    }
});
