//! Criterion benchmarks for the content-stream walker
//! (`parse_content_stream`, ISO 32000-1 §8 + §9).
//!
//! Round 148 (depth-mode benchmarks): paired with `reader_open.rs`
//! and `xref.rs`. Each scenario builds a synthetic content-stream
//! body (the raw byte sequence that lives inside a `stream ... endstream`
//! pair on a Page) of varying complexity and iterates only the
//! content-stream walker on it. The bytes are built inside the setup
//! step and held outside the timed region.
//!
//! Scenarios:
//!
//!   - **content_short_path_only**: ~20 operator tokens — `m`, `l`,
//!     `h`, `f` for a single closed rectangle plus a dash-pattern
//!     stroke. Measures the per-call dispatch overhead.
//!   - **content_long_path_100**: 100 sub-paths, each one a small
//!     polygon — measures the per-operator throughput in the
//!     painting hot path.
//!   - **content_groups_and_clips**: 50 nested `q ... Q` save /
//!     restore brackets each with a `W n` clip-path operator and a
//!     `cm` transform — exercises the state-stack mutations.
//!   - **content_mixed_realistic**: 500-operator mix of `cm`, `q`,
//!     `Q`, path painting (`m`, `l`, `c`, `h`, `f`, `B`, `S`), and
//!     colour-space selection (`rg`, `RG`) — representative of a
//!     real one-page vector document.
//!
//! Run with:
//!     cargo bench -p oxideav-pdf --bench content_stream

use std::fmt::Write as _;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use oxideav_pdf::reader::content::parse_content_stream;

fn xorshift32(state: &mut u32) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}

/// Build a short content stream: one closed rectangle filled with a
/// solid colour plus one dash-patterned stroke. ~20 operator tokens.
fn build_short_path() -> Vec<u8> {
    let mut s = String::with_capacity(128);
    s.push_str("1 0 0 rg\n");
    s.push_str("10 10 m\n");
    s.push_str("100 10 l\n");
    s.push_str("100 60 l\n");
    s.push_str("10 60 l\n");
    s.push_str("h\n");
    s.push_str("f\n");
    s.push_str("0 0 1 RG\n");
    s.push_str("2 w\n");
    s.push_str("[3 3] 0 d\n");
    s.push_str("20 20 m\n");
    s.push_str("80 20 l\n");
    s.push_str("S\n");
    s.into_bytes()
}

/// Build a long content stream with `n_sub` independent small
/// polygons. Each polygon is a closed 5-point path painted with the
/// current fill colour. Measures per-operator throughput in the
/// painting hot path.
fn build_long_path(n_sub: usize) -> Vec<u8> {
    let mut s = String::with_capacity(n_sub * 80);
    s.push_str("0.5 0.5 0.5 rg\n");
    let mut rng: u32 = 0xDEAD_BEEF;
    for _ in 0..n_sub {
        let x = (xorshift32(&mut rng) % 500) as f32;
        let y = (xorshift32(&mut rng) % 700) as f32;
        let _ = write!(
            s,
            "{x} {y} m\n{xa} {ya} l\n{xb} {yb} l\n{xc} {yc} l\n{xd} {yd} l\nh\nf\n",
            x = x,
            y = y,
            xa = x + 10.0,
            ya = y,
            xb = x + 12.0,
            yb = y + 8.0,
            xc = x + 6.0,
            yc = y + 14.0,
            xd = x - 2.0,
            yd = y + 8.0,
        );
    }
    s.into_bytes()
}

/// Build a content stream that nests `n_levels` `q ... Q` save /
/// restore brackets, each with a `cm` transform and a `W n` clip
/// path. Exercises the state-stack mutations.
fn build_groups_and_clips(n_levels: usize) -> Vec<u8> {
    let mut s = String::with_capacity(n_levels * 64);
    for i in 0..n_levels {
        let dx = (i as f32) * 1.5;
        let dy = (i as f32) * 0.7;
        let _ = write!(s, "q\n1 0 0 1 {dx} {dy} cm\n");
        let _ = write!(
            s,
            "{x0} {y0} m\n{x1} {y0} l\n{x1} {y1} l\n{x0} {y1} l\nh\nW n\n",
            x0 = 5.0,
            y0 = 5.0,
            x1 = 100.0 + dx,
            y1 = 100.0 + dy,
        );
        s.push_str("0.2 0.4 0.6 rg\n");
        s.push_str("10 10 m 50 10 l 50 50 l 10 50 l h f\n");
    }
    for _ in 0..n_levels {
        s.push_str("Q\n");
    }
    s.into_bytes()
}

/// Build a 500-operator mixed-realistic stream: a sequence of
/// `q ... Q` brackets each holding a `cm`, a path with cubic curves
/// (`c`), a fill (`f` or `B`), and an occasional stroke (`S`).
/// Representative of a real one-page vector document.
fn build_mixed_realistic(n_groups: usize) -> Vec<u8> {
    let mut s = String::with_capacity(n_groups * 256);
    let mut rng: u32 = 0xFACE_F00D;
    for i in 0..n_groups {
        let r = (xorshift32(&mut rng) & 0xFF) as f32 / 255.0;
        let g = (xorshift32(&mut rng) & 0xFF) as f32 / 255.0;
        let b = (xorshift32(&mut rng) & 0xFF) as f32 / 255.0;
        let x = (i as f32) * 7.0 % 500.0;
        let y = (i as f32) * 5.0 % 700.0;
        let _ = writeln!(s, "q\n1 0 0 1 {x} {y} cm");
        let _ = writeln!(s, "{r:.3} {g:.3} {b:.3} rg");
        let _ = writeln!(s, "0 0 m");
        let _ = writeln!(
            s,
            "{c1x} {c1y} {c2x} {c2y} {ex} {ey} c",
            c1x = 5.0,
            c1y = 10.0,
            c2x = 15.0,
            c2y = 10.0,
            ex = 20.0,
            ey = 0.0,
        );
        let _ = writeln!(
            s,
            "{c1x} {c1y} {c2x} {c2y} {ex} {ey} c",
            c1x = 25.0,
            c1y = -10.0,
            c2x = 35.0,
            c2y = -10.0,
            ex = 40.0,
            ey = 0.0,
        );
        s.push_str("h\n");
        if i % 3 == 0 {
            s.push_str("0 0 0 RG\n1 w\nB\n");
        } else {
            s.push_str("f\n");
        }
        s.push_str("Q\n");
    }
    s.into_bytes()
}

fn bench_short_path(c: &mut Criterion) {
    let bytes = build_short_path();
    let mut group = c.benchmark_group("parse_content_stream");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("content_short_path_only", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let g = parse_content_stream(black_box(input)).expect("parse_content_stream");
                black_box(g);
            });
        },
    );
    group.finish();
}

fn bench_long_path(c: &mut Criterion) {
    let bytes = build_long_path(100);
    let mut group = c.benchmark_group("parse_content_stream");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("content_long_path_100", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let g = parse_content_stream(black_box(input)).expect("parse_content_stream");
                black_box(g);
            });
        },
    );
    group.finish();
}

fn bench_groups_and_clips(c: &mut Criterion) {
    let bytes = build_groups_and_clips(50);
    let mut group = c.benchmark_group("parse_content_stream");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("content_groups_and_clips", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let g = parse_content_stream(black_box(input)).expect("parse_content_stream");
                black_box(g);
            });
        },
    );
    group.finish();
}

fn bench_mixed_realistic(c: &mut Criterion) {
    // 500 groups × ~8 operators each ≈ 4000 operator tokens.
    let bytes = build_mixed_realistic(500);
    let mut group = c.benchmark_group("parse_content_stream");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("content_mixed_realistic", bytes.len()),
        &bytes,
        |b, input| {
            b.iter(|| {
                let g = parse_content_stream(black_box(input)).expect("parse_content_stream");
                black_box(g);
            });
        },
    );
    group.finish();
}

criterion_group!(
    benches,
    bench_short_path,
    bench_long_path,
    bench_groups_and_clips,
    bench_mixed_realistic,
);
criterion_main!(benches);
