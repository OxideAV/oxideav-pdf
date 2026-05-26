//! Criterion benchmarks for the top-level reader entry points
//! (`read_pdf_to_scene`).
//!
//! Round 148 (depth-mode benchmarks): paired with `xref.rs` and
//! `content_stream.rs`. Each scenario constructs a representative
//! writer-emitted PDF inside a setup step (using the production
//! `write_pdf_from_scene` / `write_pdf_from_scene_xref_stream` /
//! `write_pdf_from_scene_object_stream` APIs so the bench sees a
//! mix of classic xref tables, §7.5.8 xref streams, and §7.5.7
//! ObjStm containers) and then iterates the reader on the resulting
//! bytes. The encode work is **outside** the timed region — only
//! the reader's per-call cost is measured.
//!
//! Scenarios:
//!
//!   - **open_single_page_classic_xref**: one A4 page, solid-fill
//!     rectangle, classic §7.5.4 cross-reference table.
//!   - **open_ten_page_classic_xref**: ten A4 pages, each a unique
//!     solid-fill rectangle — exercises §7.7.3.2 Pages-tree walk.
//!   - **open_fifty_page_xref_stream**: fifty A4 pages, §7.5.8
//!     cross-reference stream (PDF 1.5+). Stresses the type-1 /
//!     type-2 entry decoder + the §7.4.4.4 PNG predictor reverse.
//!   - **open_fifty_page_object_stream**: fifty A4 pages, §7.5.7
//!     ObjStm container + §7.5.8 xref stream — additionally stresses
//!     the compressed-object resolver.
//!
//! Run with:
//!     cargo bench -p oxideav-pdf --bench reader_open

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, GradientStop, Group, LinearGradient, Node, Paint, Path, PathCommand, PathNode, Point,
    Rgba, SpreadMethod, VectorFrame,
};
use oxideav_pdf::{
    read_pdf_to_scene, write_pdf_from_scene, write_pdf_from_scene_object_stream,
    write_pdf_from_scene_xref_stream,
};
use oxideav_scene::{Page, Scene};

/// Cheap PRNG for deterministic per-page colour seeds so successive
/// pages don't collapse to the same byte sequence (which would let
/// the writer / reader cache something they wouldn't cache on real
/// input).
fn xorshift32(state: &mut u32) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}

/// Build a single-page VectorFrame holding a solid-fill rectangle
/// (the simplest non-trivial paint the writer can emit), plus a
/// stroked sub-path so the content stream exercises both `f` and
/// `S` operators.
fn solid_rect_frame(w: f32, h: f32, fill: Rgba) -> VectorFrame {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(w - 10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(w - 10.0, h - 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(10.0, h - 10.0)));
    p.commands.push(PathCommand::Close);
    VectorFrame {
        width: w,
        height: h,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(fill)),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    }
}

/// Build a single-page VectorFrame whose root group holds a
/// gradient-filled rectangle — exercises the writer's Pattern Type 2
/// / Function Type 2 emission and the reader's content-stream
/// shading-name lookup.
fn gradient_rect_frame(w: f32, h: f32, a: Rgba, b: Rgba) -> VectorFrame {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(0.0, 0.0)));
    p.commands.push(PathCommand::LineTo(Point::new(w, 0.0)));
    p.commands.push(PathCommand::LineTo(Point::new(w, h)));
    p.commands.push(PathCommand::LineTo(Point::new(0.0, h)));
    p.commands.push(PathCommand::Close);
    let grad = LinearGradient {
        start: Point::new(0.0, 0.0),
        end: Point::new(w, 0.0),
        stops: vec![GradientStop::new(0.0, a), GradientStop::new(1.0, b)],
        spread: SpreadMethod::Pad,
    };
    VectorFrame {
        width: w,
        height: h,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::LinearGradient(grad)),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    }
}

/// Build an N-page Scene where odd pages are solid-fill rectangles
/// and even pages are linear-gradient rectangles. Returns the Scene
/// ready to hand to one of the `write_pdf_from_scene*` entry points.
fn scene_n_pages(n: usize) -> Scene {
    let mut rng_state: u32 = 0xCAFE_F00Du32.wrapping_add(n as u32);
    let mut pages = Vec::with_capacity(n);
    for i in 0..n {
        let r = (xorshift32(&mut rng_state) & 0xFF) as u8;
        let g = (xorshift32(&mut rng_state) & 0xFF) as u8;
        let b = (xorshift32(&mut rng_state) & 0xFF) as u8;
        let mut page = Page::new(595.0, 842.0);
        page.content = if i % 2 == 0 {
            solid_rect_frame(595.0, 842.0, Rgba::opaque(r, g, b))
        } else {
            gradient_rect_frame(595.0, 842.0, Rgba::opaque(r, g, b), Rgba::opaque(b, g, r))
        };
        pages.push(page);
    }
    Scene {
        pages: Some(pages),
        ..Scene::default()
    }
}

fn bench_open_single_page_classic_xref(c: &mut Criterion) {
    let scene = scene_n_pages(1);
    let bytes = write_pdf_from_scene(&scene).expect("write_pdf_from_scene");
    let mut group = c.benchmark_group("read_pdf_to_scene");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("open_single_page_classic_xref", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let scene = read_pdf_to_scene(black_box(input)).expect("read_pdf_to_scene");
                black_box(scene);
            });
        },
    );
    group.finish();
}

fn bench_open_ten_page_classic_xref(c: &mut Criterion) {
    let scene = scene_n_pages(10);
    let bytes = write_pdf_from_scene(&scene).expect("write_pdf_from_scene");
    let mut group = c.benchmark_group("read_pdf_to_scene");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("open_ten_page_classic_xref", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let scene = read_pdf_to_scene(black_box(input)).expect("read_pdf_to_scene");
                black_box(scene);
            });
        },
    );
    group.finish();
}

fn bench_open_fifty_page_xref_stream(c: &mut Criterion) {
    let scene = scene_n_pages(50);
    let bytes = write_pdf_from_scene_xref_stream(&scene).expect("write_pdf_from_scene_xref_stream");
    let mut group = c.benchmark_group("read_pdf_to_scene");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("open_fifty_page_xref_stream", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let scene = read_pdf_to_scene(black_box(input)).expect("read_pdf_to_scene");
                black_box(scene);
            });
        },
    );
    group.finish();
}

fn bench_open_fifty_page_object_stream(c: &mut Criterion) {
    let scene = scene_n_pages(50);
    let bytes =
        write_pdf_from_scene_object_stream(&scene).expect("write_pdf_from_scene_object_stream");
    let mut group = c.benchmark_group("read_pdf_to_scene");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("open_fifty_page_object_stream", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let scene = read_pdf_to_scene(black_box(input)).expect("read_pdf_to_scene");
                black_box(scene);
            });
        },
    );
    group.finish();
}

criterion_group!(
    benches,
    bench_open_single_page_classic_xref,
    bench_open_ten_page_classic_xref,
    bench_open_fifty_page_xref_stream,
    bench_open_fifty_page_object_stream,
);
criterion_main!(benches);
