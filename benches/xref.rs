//! Criterion benchmarks for the cross-reference parsers
//! (§7.5.4 classic table + §7.5.8 cross-reference stream).
//!
//! Round 148 (depth-mode benchmarks): paired with `reader_open.rs`
//! and `content_stream.rs`. Each scenario constructs a representative
//! writer-emitted PDF inside a setup step and then iterates only the
//! xref parser (`parse_xref`) on the resulting bytes. The encode
//! work is **outside** the timed region — only the parser's per-call
//! cost is measured.
//!
//! Scenarios:
//!
//!   - **parse_xref_classic_table_10p**: ten A4 pages, classic §7.5.4
//!     cross-reference table. Exercises the keyword `xref`/`trailer`
//!     walker + per-entry ASCII slot parsing.
//!   - **parse_xref_classic_table_50p**: fifty A4 pages, same code
//!     path but more entries.
//!   - **parse_xref_stream_50p**: fifty A4 pages, §7.5.8 cross-
//!     reference stream (PDF 1.5+). Exercises the §7.4.4.4 PNG
//!     predictor reverse + the type-0/1/2 entry decoder.
//!   - **parse_xref_stream_with_objstm_50p**: fifty A4 pages, §7.5.7
//!     ObjStm container + §7.5.8 xref stream. Same xref-stream cost
//!     as the previous case but with type-2 entries pointing into
//!     the ObjStm.
//!
//! Run with:
//!     cargo bench -p oxideav-pdf --bench xref

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::xref::parse_xref;
use oxideav_pdf::{
    write_pdf_from_scene, write_pdf_from_scene_object_stream, write_pdf_from_scene_xref_stream,
};
use oxideav_scene::{Page, Scene};

fn xorshift32(state: &mut u32) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}

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

fn scene_n_pages(n: usize) -> Scene {
    let mut rng_state: u32 = 0xC0DE_BEEFu32.wrapping_add(n as u32);
    let mut pages = Vec::with_capacity(n);
    for _ in 0..n {
        let r = (xorshift32(&mut rng_state) & 0xFF) as u8;
        let g = (xorshift32(&mut rng_state) & 0xFF) as u8;
        let b = (xorshift32(&mut rng_state) & 0xFF) as u8;
        let mut page = Page::new(595.0, 842.0);
        page.content = solid_rect_frame(595.0, 842.0, Rgba::opaque(r, g, b));
        pages.push(page);
    }
    Scene {
        pages: Some(pages),
        ..Scene::default()
    }
}

fn bench_xref_classic_10p(c: &mut Criterion) {
    let scene = scene_n_pages(10);
    let bytes = write_pdf_from_scene(&scene).expect("write_pdf_from_scene");
    let mut group = c.benchmark_group("parse_xref");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("parse_xref_classic_table_10p", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let xref = parse_xref(black_box(input)).expect("parse_xref");
                black_box(xref);
            });
        },
    );
    group.finish();
}

fn bench_xref_classic_50p(c: &mut Criterion) {
    let scene = scene_n_pages(50);
    let bytes = write_pdf_from_scene(&scene).expect("write_pdf_from_scene");
    let mut group = c.benchmark_group("parse_xref");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("parse_xref_classic_table_50p", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let xref = parse_xref(black_box(input)).expect("parse_xref");
                black_box(xref);
            });
        },
    );
    group.finish();
}

fn bench_xref_stream_50p(c: &mut Criterion) {
    let scene = scene_n_pages(50);
    let bytes = write_pdf_from_scene_xref_stream(&scene).expect("write_pdf_from_scene_xref_stream");
    let mut group = c.benchmark_group("parse_xref");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("parse_xref_stream_50p", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let xref = parse_xref(black_box(input)).expect("parse_xref");
                black_box(xref);
            });
        },
    );
    group.finish();
}

fn bench_xref_stream_with_objstm_50p(c: &mut Criterion) {
    let scene = scene_n_pages(50);
    let bytes =
        write_pdf_from_scene_object_stream(&scene).expect("write_pdf_from_scene_object_stream");
    let mut group = c.benchmark_group("parse_xref");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("parse_xref_stream_with_objstm_50p", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let xref = parse_xref(black_box(input)).expect("parse_xref");
                black_box(xref);
            });
        },
    );
    group.finish();
}

criterion_group!(
    benches,
    bench_xref_classic_10p,
    bench_xref_classic_50p,
    bench_xref_stream_50p,
    bench_xref_stream_with_objstm_50p,
);
criterion_main!(benches);
