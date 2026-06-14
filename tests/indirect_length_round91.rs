//! Round-91: ISO 32000-1 §7.3.10 Example 3 — a stream's `/Length` may
//! be an indirect reference (`<< /Length 8 0 R >>`) deferring the size
//! until after the body for one-pass writers. The reader must consult
//! the xref table to fetch the integer.
//!
//! Coverage:
//!
//! 1. Hand-rolled minimal PDF with an indirect-length stream → opens
//!    + resolves correctly.
//! 2. The same shape combined with `/Filter /FlateDecode` (the common
//!    real-world combination) → decodes to the expected payload.
//! 3. A real-world spec PDF
//!    (`docs/video/mpeg1/ISO_IEC_11172-2-MPEG1-Video-1993.pdf`) whose
//!    content streams use indirect /Length end-to-end — opens without
//!    error, walks the catalog, surfaces at least one page.
//!
//! Each test reads only its own crate state and one spec PDF as
//! opaque bytes — no FFmpeg / qpdf / pdfium source consulted.

use oxideav_pdf::objects::{Object, ObjectId};
use oxideav_pdf::reader::DocumentReader;
use std::io::Write as _;

/// Build a tiny PDF whose object 4 is a stream with `/Length 5 0 R`
/// and whose object 5 is the integer carrying the length. The
/// resulting bytes are valid per ISO 32000-1 §7.3.10 Example 3.
fn minimal_pdf_with_indirect_length(stream_body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    // Header.
    out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    // index 0 = free entry head; objects 1..=5 follow in order.
    let mut offsets: Vec<usize> = vec![0];
    // Object 1: catalog.
    offsets.push(out.len());
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    // Object 2: pages tree.
    offsets.push(out.len());
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    // Object 3: page node — references object 4 as its content stream.
    offsets.push(out.len());
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
          /Contents 4 0 R /Resources << >> >>\nendobj\n",
    );
    // Object 4: the stream — indirect /Length pointing at object 5.
    offsets.push(out.len());
    out.extend_from_slice(b"4 0 obj\n<< /Length 5 0 R >>\nstream\n");
    out.extend_from_slice(stream_body);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    // Object 5: the length integer.
    offsets.push(out.len());
    write!(out, "5 0 obj\n{}\nendobj\n", stream_body.len()).unwrap();
    // xref.
    let xref_pos = out.len();
    writeln!(out, "xref\n0 6").unwrap();
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1) {
        writeln!(out, "{off:010} 00000 n ").unwrap();
    }
    // trailer.
    writeln!(out, "trailer\n<< /Size 6 /Root 1 0 R >>").unwrap();
    writeln!(out, "startxref\n{xref_pos}\n%%EOF").unwrap();
    out
}

#[test]
fn reader_resolves_indirect_length_on_content_stream() {
    let body = b"BT /F1 12 Tf 72 700 Td (Hello) Tj ET";
    let pdf = minimal_pdf_with_indirect_length(body);
    let mut r = DocumentReader::open(&pdf).expect("opens");
    // Object 4 is the indirect-length stream — resolving it should
    // return a Stream whose body matches `body` exactly. The dict's
    // /Length entry must have been patched from `Reference(5,0)` to
    // the resolved direct integer.
    let obj = r.resolve(ObjectId::new(4)).expect("resolves stream");
    let Object::Stream(s) = obj else {
        panic!("expected Stream, got {obj:?}")
    };
    assert_eq!(s.data, body.to_vec());
    let length = s
        .dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Length")
        .map(|(_, v)| v.clone());
    assert!(
        matches!(length, Some(Object::Integer(n)) if n == body.len() as i64),
        "Length should be patched to direct integer, got {length:?}"
    );
}

#[test]
fn reader_resolves_indirect_length_with_flate_filter() {
    // Round-91 real-world combination: indirect /Length on a
    // FlateDecode-compressed content stream — the writer-emitted shape
    // for one-pass producers that can't predict the compressed length
    // until after deflating the body.
    let raw = b"BT /F1 12 Tf 72 700 Td (Hello indirect length) Tj ET";
    let compressed = compcol::vec::compress_to_vec::<compcol::zlib::Zlib>(raw).unwrap();

    // Assemble manually so the stream dict carries both /Length 5 0 R
    // and /Filter /FlateDecode.
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<usize> = vec![0];
    offsets.push(out.len());
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets.push(out.len());
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offsets.push(out.len());
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
          /Contents 4 0 R /Resources << >> >>\nendobj\n",
    );
    offsets.push(out.len());
    out.extend_from_slice(b"4 0 obj\n<< /Length 5 0 R /Filter /FlateDecode >>\nstream\n");
    out.extend_from_slice(&compressed);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    offsets.push(out.len());
    write!(out, "5 0 obj\n{}\nendobj\n", compressed.len()).unwrap();
    let xref_pos = out.len();
    writeln!(out, "xref\n0 6").unwrap();
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1) {
        writeln!(out, "{off:010} 00000 n ").unwrap();
    }
    writeln!(out, "trailer\n<< /Size 6 /Root 1 0 R >>").unwrap();
    writeln!(out, "startxref\n{xref_pos}\n%%EOF").unwrap();

    let mut r = DocumentReader::open(&out).expect("opens");
    let obj = r.resolve(ObjectId::new(4)).expect("resolves stream");
    let Object::Stream(s) = obj else {
        panic!("expected Stream, got {obj:?}")
    };
    // The raw (encoded) bytes match the compressed payload exactly.
    assert_eq!(s.data, compressed);
    // decode_stream applies the /Filter and yields the cleartext.
    let cleartext = oxideav_pdf::reader::document::decode_stream(&s).expect("decode");
    assert_eq!(cleartext, raw.to_vec());
}

#[test]
fn reader_opens_real_spec_pdf_with_indirect_length_streams() {
    // Round-91 motivator: cli-convert smoke against
    // docs/video/mpeg1/ISO_IEC_11172-2-MPEG1-Video-1993.pdf used to
    // fail because that PDF expresses every content-stream /Length as
    // an indirect reference. With the resolver wired in, the reader
    // opens the file and resolves the catalog without erroring.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("video")
        .join("mpeg1")
        .join("ISO_IEC_11172-2-MPEG1-Video-1993.pdf");
    if !path.exists() {
        // Spec PDF is in-tree; skip gracefully on the off chance it's
        // gitignored locally.
        eprintln!("note: {} missing — skipping", path.display());
        return;
    }
    let bytes = std::fs::read(&path).expect("read spec PDF");
    let mut r = DocumentReader::open(&bytes).expect("opens real spec PDF");
    // Walk the catalog → pages tree → first page. The hierarchy walk
    // is the cheapest way to exercise the stream resolver across many
    // objects (every page has at least one /Contents stream whose
    // /Length is indirect in this PDF).
    let report = r.verify_hierarchy().expect("hierarchy walk");
    // verify_hierarchy is permissive — it surfaces issues without
    // erroring. What matters here is that the walker completed; many
    // intermediate `resolve()` calls had to succeed against
    // indirect-length streams to get this far.
    assert!(
        report.page_count > 0,
        "expected to walk at least one page, got {report:?}"
    );
}
