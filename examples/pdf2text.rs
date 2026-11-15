//! Dump a PDF's extracted text: `cargo run --example pdf2text -- file.pdf [--runs]`.
//!
//! Without `--runs` prints the text (a Tagged PDF in the order of its
//! structure tree, anything else in geometric reading order); with it,
//! one line per run (position, font, size, text) for debugging word /
//! line assembly. `--geometric` / `--stream` choose the order,
//! `--keep-hyphens` keeps words hyphenated across line ends,
//! `--visible` drops render-mode-3 text, `--no-artifacts` drops a
//! Tagged PDF's page furniture, `--page N` keeps one page.

use oxideav_pdf::reader::DocumentReader;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runs = args.iter().any(|a| a == "--runs");
    let path = args
        .iter()
        .find(|a| !a.starts_with("--") && a.parse::<usize>().is_err())
        .expect("usage: pdf2text file.pdf [--runs]");
    let bytes = std::fs::read(path).expect("read input");
    let mut reader = DocumentReader::open(&bytes).expect("open pdf");
    let mut ex = reader.text_extraction().expect("extract text");
    // `--page N` (1-based) keeps one page.
    let mut single_page = false;
    if let Some(n) = args
        .iter()
        .position(|a| a == "--page")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<usize>().ok())
    {
        let page: Vec<_> = ex
            .pages()
            .nth(n.saturating_sub(1))
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        single_page = true;
        ex.runs = page;
        ex.page_starts = vec![0];
    }
    if runs {
        for r in &ex.runs {
            let end = r.end();
            println!(
                "{:8.2} {:8.2} -> {:8.2} em {:5.1} {:>6} {:?}",
                r.position.0,
                r.position.1,
                end.0,
                r.em(),
                r.font_name,
                r.text
            );
        }
    } else {
        use oxideav_pdf::reader::{TextLayoutOptions, TextOrder};
        let mut opts = TextLayoutOptions::new();
        if args.iter().any(|a| a == "--stream") {
            opts = opts.with_order(TextOrder::Stream);
        }
        if args.iter().any(|a| a == "--geometric") {
            opts = opts.with_order(TextOrder::Geometric);
        }
        if args.iter().any(|a| a == "--keep-hyphens") {
            opts = opts.with_join_hyphenated(false);
        }
        if args.iter().any(|a| a == "--no-artifacts") {
            opts = opts.with_include_artifacts(false);
        }
        if args.iter().any(|a| a == "--visible") {
            opts = opts.with_include_invisible(false);
        }
        if single_page {
            println!("{}", ex.text_with(&opts));
        } else {
            println!("{}", reader.text(&opts).expect("layout text"));
        }
    }
}
