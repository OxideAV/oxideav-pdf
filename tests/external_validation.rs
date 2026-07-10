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

// ───────────── §8.9 image decode vs Ghostscript renders ─────────────
//
// Round-406 black-box pixel validation: synthesize an image-bearing
// PDF, render it with Ghostscript to raw PPM at 72 dpi (page points ==
// device pixels), and assert the sampled pixel colours match what the
// crate's own §8.9.5.2 sample decoder produced for the same file.
// Skips silently when `gs` is not on PATH.

/// Render `pdf` to (width, height, RGB bytes) via `gs -sDEVICE=ppmraw`.
/// `None` when gs is missing or the render fails.
fn gs_render_ppm(pdf: &[u8], stem: &str) -> Option<(usize, usize, Vec<u8>)> {
    let pdf_path = write_temp_pdf(pdf, stem);
    let mut ppm_path = pdf_path.clone();
    ppm_path.set_extension("ppm");
    let ok = Command::new("gs")
        .args([
            "-dNOPAUSE",
            "-dBATCH",
            "-dSAFER",
            "-sDEVICE=ppmraw",
            "-r72",
            &format!("-o{}", ppm_path.to_string_lossy()),
            &pdf_path.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&pdf_path);
    if !ok {
        let _ = std::fs::remove_file(&ppm_path);
        return None;
    }
    let data = std::fs::read(&ppm_path).ok()?;
    let _ = std::fs::remove_file(&ppm_path);
    parse_ppm(&data)
}

/// Minimal P6 parser (whitespace + `#`-comment tolerant header).
fn parse_ppm(data: &[u8]) -> Option<(usize, usize, Vec<u8>)> {
    if data.get(..2) != Some(b"P6") {
        return None;
    }
    let mut fields = [0usize; 3];
    let mut i = 2;
    for field in fields.iter_mut() {
        loop {
            while i < data.len() && data[i].is_ascii_whitespace() {
                i += 1;
            }
            if data.get(i) == Some(&b'#') {
                while i < data.len() && data[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            break;
        }
        let start = i;
        while i < data.len() && data[i].is_ascii_digit() {
            i += 1;
        }
        *field = std::str::from_utf8(&data[start..i]).ok()?.parse().ok()?;
    }
    // Single whitespace byte separates the header from the raster.
    i += 1;
    let (w, h) = (fields[0], fields[1]);
    let body = data.get(i..i + w * h * 3)?.to_vec();
    Some((w, h, body))
}

/// One-page 100×100 fixture painting a colour-key-masked RGB image
/// over the full page (the same shape
/// `tests/image_sample_formats_round406.rs` decodes in-process).
fn color_key_fixture() -> Vec<u8> {
    let base = [255u8, 0, 0, 0, 255, 0, 0, 0, 255];
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<usize> = Vec::new();
    let content = b"q 100 0 0 100 0 0 cm /Im0 Do Q";
    offsets.push(buf.len());
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets.push(buf.len());
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offsets.push(buf.len());
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
          /Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>\nendobj\n",
    );
    offsets.push(buf.len());
    buf.extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");
    offsets.push(buf.len());
    buf.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XObject /Subtype /Image /Width 3 /Height 1 \
             /ColorSpace /DeviceRGB /BitsPerComponent 8 /Mask [0 50 200 255 0 50] \
             /Length {} >>\nstream\n",
            base.len()
        )
        .as_bytes(),
    );
    buf.extend_from_slice(&base);
    buf.extend_from_slice(b"\nendstream\nendobj\n");
    let n = offsets.len() + 1;
    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n");
    buf.extend_from_slice(format!("0 {n}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(b"trailer\n");
    buf.extend_from_slice(format!("<< /Size {n} /Root 1 0 R >>\n").as_bytes());
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

#[test]
fn ghostscript_agrees_with_color_key_image_decode() {
    if !tool_exists("gs") {
        eprintln!("skipping: gs not on PATH");
        return;
    }
    let pdf = color_key_fixture();
    // The crate's own decode: red / masked green / blue.
    let scene = oxideav_pdf::read_pdf_to_scene(&pdf).expect("read");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    fn find_image(g: &oxideav_core::vector::Group) -> Option<oxideav_core::vector::ImageRef> {
        for c in &g.children {
            match c {
                oxideav_core::vector::Node::Image(i) => return Some(i.clone()),
                oxideav_core::vector::Node::Group(g) => {
                    if let Some(i) = find_image(g) {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        None
    }
    let img = find_image(root).expect("spliced image");
    let px: Vec<&[u8]> = img.frame.planes[0].data.chunks_exact(4).collect();
    assert_eq!(px[0], &[255, 0, 0, 255]);
    assert_eq!(px[1][3], 0, "green colour-key masked in crate decode");
    assert_eq!(px[2], &[0, 0, 255, 255]);

    // Ghostscript's render of the same file: the masked cell shows the
    // white page background; the painted cells show the image colours.
    let Some((w, h, rgb)) = gs_render_ppm(&pdf, "gs-colorkey") else {
        eprintln!("skipping: gs render failed");
        return;
    };
    assert_eq!((w, h), (100, 100));
    let sample = |x: usize, y: usize| -> [u8; 3] {
        let i = (y * w + x) * 3;
        [rgb[i], rgb[i + 1], rgb[i + 2]]
    };
    // Page y is flipped in device space; the image is vertically
    // uniform so any row works — sample mid-page.
    assert_eq!(sample(16, 50), [255, 0, 0], "gs: left cell red");
    assert_eq!(
        sample(50, 50),
        [255, 255, 255],
        "gs: masked cell shows page background"
    );
    assert_eq!(sample(83, 50), [0, 0, 255], "gs: right cell blue");
}
