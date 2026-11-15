//! Timing harness for text extraction:
//! `cargo run --release --example profile_text -- file.pdf [iterations]`.
//!
//! Each iteration opens the document, extracts the runs of every page
//! and lays the text out; the three stages are timed apart and the
//! medians reported with the page rate. The process prints its PID and
//! can be given enough iterations for a sampling profiler to attach.

use std::time::{Duration, Instant};

use oxideav_pdf::reader::{DocumentReader, TextLayoutOptions, TextOrder};

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args
        .first()
        .expect("usage: profile_text file.pdf [iterations]");
    let iterations: usize = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(5);
    let bytes = std::fs::read(path).expect("read input");
    eprintln!("pid {}", std::process::id());
    let opts = TextLayoutOptions::new().with_order(TextOrder::Geometric);
    let (mut open, mut extract, mut layout) = (Vec::new(), Vec::new(), Vec::new());
    let (mut pages, mut runs, mut chars) = (0, 0, 0);
    for _ in 0..iterations.max(1) {
        let t0 = Instant::now();
        let mut reader = DocumentReader::open(&bytes).expect("open pdf");
        let t1 = Instant::now();
        let ex = reader.text_extraction().expect("extract text");
        let t2 = Instant::now();
        let text = ex.text_with(&opts);
        let t3 = Instant::now();
        open.push(t1 - t0);
        extract.push(t2 - t1);
        layout.push(t3 - t2);
        pages = ex.pages().count();
        runs = ex.runs.len();
        chars = text.chars().count();
    }
    let (open, extract, layout) = (median(open), median(extract), median(layout));
    let total = open + extract + layout;
    println!("{pages} pages, {runs} runs, {chars} characters; median of {iterations}");
    println!("open     {:9.3} ms", open.as_secs_f64() * 1e3);
    println!("extract  {:9.3} ms", extract.as_secs_f64() * 1e3);
    println!("layout   {:9.3} ms", layout.as_secs_f64() * 1e3);
    println!(
        "total    {:9.3} ms  ({:.0} pages/s)",
        total.as_secs_f64() * 1e3,
        pages as f64 / total.as_secs_f64()
    );
}
