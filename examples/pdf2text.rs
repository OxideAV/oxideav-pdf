//! Dump a PDF's extracted text: `cargo run --example pdf2text -- file.pdf [--runs]`.
//!
//! Without `--runs` prints the flat text; with it, one line per run
//! (position, font, size, text) for debugging word / line assembly.

use oxideav_pdf::reader::DocumentReader;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runs = args.iter().any(|a| a == "--runs");
    let path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .expect("usage: pdf2text file.pdf [--runs]");
    let bytes = std::fs::read(path).expect("read input");
    let mut reader = DocumentReader::open(&bytes).expect("open pdf");
    let ex = reader.text_extraction().expect("extract text");
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
        println!("{}", ex.flat_text());
    }
}
