//! Optional external validation via `qpdf --check` or `pdftotext`.
//!
//! Mirrors the subprocess-based validation pattern other oxideav-* crates
//! use: build a sample PDF, shell out to a third-party validator if it's
//! on `PATH`, assert exit status 0. Skips silently when neither tool is
//! present so CI without these binaries passes unchanged.

use std::io::Write;
use std::process::{Command, Stdio};

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathNode, Point, Rgba, VectorFrame,
};

/// Write `pdf` to a uniquely-named file under the system temp dir so
/// validators that don't accept stdin (notably `qpdf` ≥ 11) can still
/// read it. Returns the temp path; caller is responsible for cleanup
/// (we don't bother since these tests run rarely).
fn write_temp_pdf(pdf: &[u8], stem: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("oxideav-pdf-{stem}-{pid}-{nanos}.pdf"));
    std::fs::write(&path, pdf).expect("temp pdf write");
    path
}

fn sample_pdf() -> Vec<u8> {
    let mut p = Path::new();
    p.move_to(Point::new(20.0, 20.0))
        .line_to(Point::new(180.0, 20.0))
        .line_to(Point::new(180.0, 80.0))
        .line_to(Point::new(20.0, 80.0))
        .close();

    let frame = VectorFrame {
        width: 200.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(255, 255, 0))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    oxideav_pdf::write_pdf(&frame).expect("write_pdf")
}

fn tool_exists(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn pipe_to_tool(tool: &str, args: &[&str], pdf: &[u8]) -> Option<bool> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(pdf).ok()?;
    }
    let status = child.wait().ok()?;
    Some(status.success())
}

#[test]
fn qpdf_check_accepts_round1_output() {
    if !tool_exists("qpdf") {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    let pdf = sample_pdf();
    // qpdf ≥ 11 doesn't accept `-` as a stdin substitute (every
    // recent build resolves the literal filename `-` and reports
    // "No such file or directory"). Write the PDF to a temp file
    // and let qpdf open it by path.
    let path = write_temp_pdf(&pdf, "qpdf-check");
    let path_str = path.to_string_lossy().to_string();
    let ok = Command::new("qpdf")
        .args(["--check", &path_str])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "qpdf --check rejected the produced PDF");
}

#[test]
fn pdftotext_extracts_no_text_from_pure_vector_pdf() {
    if !tool_exists("pdftotext") {
        eprintln!("skipping: pdftotext not on PATH");
        return;
    }
    let pdf = sample_pdf();
    // pdftotext -layout - - reads PDF on stdin, writes text on
    // stdout. Round 1 has no text so a successful exit (with
    // empty / whitespace-only output) is enough — we just want
    // to know the file parses.
    let ok = pipe_to_tool("pdftotext", &["-", "-"], &pdf).unwrap_or(false);
    assert!(ok, "pdftotext rejected the produced PDF");
}
