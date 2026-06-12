//! Profiling harness for the bytes → Scene read path.
//!
//! Round 285 (depth-mode profiling): builds three writer-emitted PDFs
//! (classic §7.5.4 xref table, §7.5.8 xref stream, §7.5.7 ObjStm
//! container) with deliberately heavy content streams — many pages,
//! many path segments per page, alternating solid / gradient fills —
//! then loops `read_pdf_to_scene` over each and reports:
//!
//!   - total wall-clock per scenario (the timed region is ONLY the
//!     reader; writer setup is outside),
//!   - per-iteration mean,
//!   - an FNV-1a 64-bit hash over the `{:?}` serialization of the
//!     parsed `Scene` — the output-identity fingerprint used to prove
//!     optimizations are behaviour-preserving.
//!
//! Run (release, sequential — profiling must not share the CPU):
//!
//!     CARGO_TARGET_DIR=/tmp/oxideav-pdf-target \
//!     cargo run -p oxideav-pdf --release --example profile_read -j 4
//!
//! Attach a sampling profiler to the running process to rank
//! hotspots; the harness prints its PID and runs long enough
//! (hundreds of iterations) for stable samples.

use std::time::Instant;

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, GradientStop, Group, LinearGradient, Node, Paint, Path, PathCommand, PathNode, Point,
    Rgba, SpreadMethod, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    extract_pdf_text, read_pdf_to_scene, write_pdf_from_scene, write_pdf_from_scene_object_stream,
    write_pdf_from_scene_xref_stream,
};
use oxideav_scene::{Page, Scene};

/// Cheap deterministic PRNG so successive pages / segments differ
/// byte-for-byte (defeats any caching the reader might do on
/// identical content streams).
fn xorshift32(state: &mut u32) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}

/// FNV-1a 64-bit over a byte slice — the output-identity fingerprint.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// One page with `segments` line/curve segments — a dense content
/// stream so the §8.5 path-operator tokenizer dominates, the way a
/// real vector-heavy page would.
fn dense_frame(w: f32, h: f32, segments: usize, rng: &mut u32) -> VectorFrame {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(
        (xorshift32(rng) % 500) as f32 + 0.25,
        (xorshift32(rng) % 800) as f32 + 0.5,
    )));
    for i in 0..segments {
        let x = (xorshift32(rng) % 500) as f32 + 0.125;
        let y = (xorshift32(rng) % 800) as f32 + 0.375;
        if i % 3 == 0 {
            p.commands.push(PathCommand::CubicCurveTo {
                c1: Point::new(x * 0.5, y * 0.25),
                c2: Point::new(x * 0.75, y * 0.5),
                end: Point::new(x, y),
            });
        } else {
            p.commands.push(PathCommand::LineTo(Point::new(x, y)));
        }
    }
    p.commands.push(PathCommand::Close);
    let fill = if segments % 2 == 0 {
        Paint::Solid(Rgba::opaque(
            (xorshift32(rng) & 0xFF) as u8,
            (xorshift32(rng) & 0xFF) as u8,
            (xorshift32(rng) & 0xFF) as u8,
        ))
    } else {
        Paint::LinearGradient(LinearGradient {
            start: Point::new(0.0, 0.0),
            end: Point::new(w, h),
            stops: vec![
                GradientStop::new(0.0, Rgba::opaque(10, 20, 30)),
                GradientStop::new(1.0, Rgba::opaque(200, 150, 100)),
            ],
            spread: SpreadMethod::Pad,
        })
    };
    VectorFrame {
        width: w,
        height: h,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(fill),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    }
}

fn scene_pages(pages: usize, segments_per_page: usize) -> Scene {
    let mut rng: u32 = 0xCAFE_F00D;
    let mut out = Vec::with_capacity(pages);
    for i in 0..pages {
        let mut page = Page::new(595.0, 842.0);
        page.content = dense_frame(595.0, 842.0, segments_per_page + (i % 7), &mut rng);
        out.push(page);
    }
    Scene {
        pages: Some(out),
        ..Scene::default()
    }
}

fn run_scenario(name: &str, bytes: &[u8], iters: usize) {
    // Hash once for output identity, outside the timed loop.
    let scene = read_pdf_to_scene(bytes).expect("read_pdf_to_scene");
    let fingerprint = fnv1a64(format!("{scene:?}").as_bytes());

    let start = Instant::now();
    for _ in 0..iters {
        let s = read_pdf_to_scene(std::hint::black_box(bytes)).expect("read_pdf_to_scene");
        std::hint::black_box(&s);
    }
    let elapsed = start.elapsed();
    println!(
        "{name}: {} bytes, {iters} iters, total {:.3}s, mean {:.3}ms/iter, scene-hash {fingerprint:016x}",
        bytes.len(),
        elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1000.0 / iters as f64,
    );
}

/// Output-identity fingerprints for the on-disk fixture corpus:
/// parsed-scene `{:?}` hash + extracted-text hash per `.pdf` under
/// `tests/fixtures/`. Run before and after an optimization — every
/// line must be byte-identical.
fn fixture_fingerprints() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .expect("fixtures dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "pdf"))
        .collect();
    paths.sort();
    for path in paths {
        let bytes = std::fs::read(&path).expect("read fixture");
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let scene_hash = match read_pdf_to_scene(&bytes) {
            Ok(scene) => format!("{:016x}", fnv1a64(format!("{scene:?}").as_bytes())),
            Err(e) => format!("scene-err:{:016x}", fnv1a64(e.to_string().as_bytes())),
        };
        let text_hash = match DocumentReader::open(&bytes)
            .and_then(|mut r| extract_pdf_text(&mut r).map(|t| t.flat_text()))
        {
            Ok(text) => format!("{:016x}", fnv1a64(text.as_bytes())),
            Err(e) => format!("text-err:{:016x}", fnv1a64(e.to_string().as_bytes())),
        };
        println!("fixture {name}: scene {scene_hash}, text {text_hash}");
    }
}

fn main() {
    println!("pid {}", std::process::id());
    fixture_fingerprints();

    let scene = scene_pages(120, 220);
    let classic = write_pdf_from_scene(&scene).expect("write classic");
    let xref_stream = write_pdf_from_scene_xref_stream(&scene).expect("write xref stream");
    let objstm = write_pdf_from_scene_object_stream(&scene).expect("write objstm");

    let iters: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(60);

    run_scenario("classic_xref_120p", &classic, iters);
    run_scenario("xref_stream_120p", &xref_stream, iters);
    run_scenario("objstm_120p", &objstm, iters);
}
