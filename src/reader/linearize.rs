//! Round-27 — Linearization Parameter Dictionary reader (ISO 32000-1
//! §F.2 + Annex F.3).
//!
//! Round 9 added the writer-side emission of linearized ("Fast Web
//! View") PDFs in [`crate::linearize`]; this module is the read-side
//! complement. The linearization parameter dictionary is the FIRST
//! indirect object in a linearized file (§F.3.3: "shall be entirely
//! contained within the first 1024 bytes of the PDF file") and carries
//! the structural offsets a streaming reader needs to fetch + render
//! the first page without downloading the rest:
//!
//! | Key  | Type    | Required | Meaning                                                |
//! |------|---------|----------|--------------------------------------------------------|
//! | `/Linearized` | number  | yes | Version number — always `1` for Annex F.        |
//! | `/L`          | integer | yes | Total file length in bytes.                     |
//! | `/H`          | array   | yes | Primary hint-stream `[offset length]` pair      |
//! | `/O`          | integer | yes | Object number of the first page's `/Page` dict. |
//! | `/E`          | integer | yes | Byte offset of the end of the first-page section. |
//! | `/N`          | integer | yes | Total page count in the document.               |
//! | `/T`          | integer | yes | Byte offset of the main cross-reference section.|
//!
//! Two design notes:
//!
//! * **Plain (non-linearized) files are NOT errors** — the parser
//!   returns `Ok(None)` when the file's first object isn't a
//!   linearization parameter dictionary, so callers can branch on the
//!   `Option` without a try/catch dance.
//! * **No `/Linearized` value coercion** — the spec leaves the version
//!   as "a number" rather than fixing it at `1`. We surface the value
//!   verbatim (as an `f64`) so future versions parse without changes.
//!
//! Scope: parse only. Hint-table decoding (Annex F.4 — the
//! page-offset + shared-object + thumbnail + outline tables packed
//! inside the hint stream) is out of scope; a downstream tool that
//! actually streams the file from network would consume those, but
//! the parameter dict alone is what tells a viewer the file is
//! linearized and where the main xref lives. Hint-table decoders are
//! a round-28+ follow-up.

use crate::error::PdfError;
use crate::objects::{Dict, Object};
use crate::reader::parse::Parser;

/// Parsed `/Linearized` parameter dictionary per ISO 32000-1 §F.2.
///
/// Returned by [`parse_linearization_dict`] (and from
/// [`crate::reader::DocumentReader::linearization`]). All field names
/// match the PDF dict keys exactly; the `linearized` field is the
/// numeric version (always `1.0` for current Annex F).
#[derive(Debug, Clone, PartialEq)]
pub struct LinearizationParams {
    /// `/Linearized` — the version number (always `1` in published
    /// PDF specs; surfaced as `f64` so the parser tolerates the
    /// theoretical "future version" case).
    pub linearized: f64,
    /// `/L` — total file length in bytes. Must equal `input.len()`
    /// for a non-truncated linearized file; the parser does NOT
    /// enforce this (callers may want to surface a mismatch as a
    /// "truncated" diagnostic rather than a hard parse error).
    pub file_length: u64,
    /// `/H` — primary hint stream `[offset, length]` (the first two
    /// integers in the `/H` array). Tables F.3 / F.4 / F.5 / F.6
    /// / F.7 live inside this hint stream. Some files emit
    /// `[off1 len1 off2 len2]` for split hint streams; we surface
    /// only the first pair (the mandatory primary).
    pub hint_offset: u64,
    pub hint_length: u64,
    /// `/H` overflow / secondary hint stream `[offset, length]`,
    /// when present. Optional per §F.2.
    pub hint_overflow: Option<(u64, u64)>,
    /// `/O` — object number of the first page's `/Page` indirect
    /// object. Section F.3.6 anchors the first-page section at this
    /// indirect object's byte offset.
    pub first_page_object_number: u32,
    /// `/E` — byte offset of the end of the first-page section
    /// (one past the last byte of the first page's contents
    /// stream). A streaming reader can stop downloading once it has
    /// `[0, E)` and `[main_xref_off, file_length)`.
    pub end_of_first_page: u64,
    /// `/N` — total page count in the document.
    pub page_count: u32,
    /// `/T` — byte offset of the main cross-reference section
    /// (the one referenced by `startxref` in non-linearized files).
    /// `startxref` at the end of a linearized file actually points
    /// at the first-page xref; `/T` is the way to find the main one.
    pub main_xref_offset: u64,
}

impl LinearizationParams {
    /// Try to parse the linearization parameter dictionary from the
    /// start of a PDF file.
    ///
    /// Returns `Ok(None)` when:
    /// * The file is too short to contain a linearization parameter
    ///   dict (< 16 bytes; the spec requires the first 1024 bytes).
    /// * The first indirect object isn't a dictionary, or it is a
    ///   dictionary but doesn't carry `/Linearized`.
    ///
    /// Returns `Err(PdfError::Other)` when `/Linearized` IS present
    /// but a required key is missing or malformed — the file
    /// declares itself linearized but doesn't honour the contract.
    pub fn parse(input: &[u8]) -> Result<Option<Self>, PdfError> {
        parse_linearization_dict(input)
    }

    /// Verify the parameter dict matches the actual file bytes —
    /// `/L` equals `input.len()` and `/T` points within bounds.
    /// Returns `Ok(())` when consistent; `Err` lists the first
    /// mismatch. Pure diagnostic — `parse` accepts malformed
    /// values without consulting the file bytes.
    pub fn verify(&self, input: &[u8]) -> Result<(), PdfError> {
        if self.file_length != input.len() as u64 {
            return Err(PdfError::other(format!(
                "PDF linearization: /L = {} but file is {} bytes (truncated or extended?)",
                self.file_length,
                input.len()
            )));
        }
        if self.main_xref_offset >= input.len() as u64 {
            return Err(PdfError::other(format!(
                "PDF linearization: /T = {} points past end of file ({} bytes)",
                self.main_xref_offset,
                input.len()
            )));
        }
        if self.end_of_first_page > input.len() as u64 {
            return Err(PdfError::other(format!(
                "PDF linearization: /E = {} points past end of file ({} bytes)",
                self.end_of_first_page,
                input.len()
            )));
        }
        if self.hint_offset >= input.len() as u64 {
            return Err(PdfError::other(format!(
                "PDF linearization: /H[0] = {} points past end of file ({} bytes)",
                self.hint_offset,
                input.len()
            )));
        }
        if self.hint_offset + self.hint_length > input.len() as u64 {
            return Err(PdfError::other(format!(
                "PDF linearization: /H stream extends past end of file ({} + {} > {})",
                self.hint_offset,
                self.hint_length,
                input.len()
            )));
        }
        if self.page_count == 0 {
            return Err(PdfError::other(
                "PDF linearization: /N = 0 — linearized file must declare ≥1 page",
            ));
        }
        Ok(())
    }
}

/// Parse the linearization parameter dictionary, if present.
///
/// Per §F.3.3 the parameter dictionary lives within the first 1024
/// bytes of the file. We scan only that prefix to keep the
/// non-linearized fast path cheap.
pub fn parse_linearization_dict(input: &[u8]) -> Result<Option<LinearizationParams>, PdfError> {
    // §F.3.3: lin-dict is entirely within the first 1024 bytes. We
    // accept a bit more slack (up to 2048) so a marginally bloated
    // dict still parses — the worst case is a writer that pads
    // /L /H /T integers to 10 digits each.
    if input.len() < 16 {
        return Ok(None);
    }
    let scan_end = 2048.min(input.len());
    let head = &input[..scan_end];

    // Locate the first `obj` keyword. Skipping the `%PDF-x.y` header
    // and any binary marker comment, the first byte-offset that
    // tokenises as an indirect object header is where the
    // linearization param dict lives.
    let obj_pos = match find_first_obj_header(head) {
        Some(p) => p,
        None => return Ok(None),
    };

    let mut p = Parser::new(input);
    p.lexer_mut().seek(obj_pos);
    // parse_indirect requires `<n> <gen> obj`. The first object in a
    // linearized file is always 1-generation-0, but we don't enforce
    // that — the spec only fixes the lin-dict's *position*, not its
    // object number.
    let (_id, body) = match p.parse_indirect() {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let Object::Dict(d) = body else {
        return Ok(None);
    };

    // Not a lin-dict if it lacks /Linearized — that's the only key
    // that distinguishes a lin-dict from any other PDF dict (eg. a
    // first-object Catalog if the writer skipped linearization).
    let Some(_) = lookup(&d, "Linearized") else {
        return Ok(None);
    };

    // Now require every key. Per §F.2 they're all REQ.
    let linearized = require_number(&d, "Linearized")?;
    let file_length = require_uint(&d, "L")?;
    let (hint_offset, hint_length, hint_overflow) = require_hint_array(&d)?;
    let first_page_object_number = require_uint(&d, "O")? as u32;
    let end_of_first_page = require_uint(&d, "E")?;
    let page_count = require_uint(&d, "N")? as u32;
    let main_xref_offset = require_uint(&d, "T")?;

    Ok(Some(LinearizationParams {
        linearized,
        file_length,
        hint_offset,
        hint_length,
        hint_overflow,
        first_page_object_number,
        end_of_first_page,
        page_count,
        main_xref_offset,
    }))
}

/// Locate the first `<n> <gen> obj` indirect-object header in
/// `head`. We scan for the literal `" obj"` keyword and walk
/// backwards past two non-negative integers — cheaper than running
/// the full lexer over the binary marker comment that immediately
/// follows the `%PDF-x.y` header line.
fn find_first_obj_header(head: &[u8]) -> Option<usize> {
    let needle = b" obj";
    let mut search = 0usize;
    while let Some(rel) = window_find(&head[search..], needle) {
        let pos = search + rel;
        // Walk back over two whitespace-separated integers. If the
        // bytes immediately before " obj" match `<gen-digit>+
        // <space> <n-digit>+`, the integer just before the second
        // whitespace gap is the indirect object number.
        let header_start = match scan_back_two_ints(head, pos) {
            Some(p) => p,
            None => {
                search = pos + needle.len();
                continue;
            }
        };
        return Some(header_start);
    }
    None
}

/// Substring search using the standard `windows().position()` form.
fn window_find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Walk back from `space_before_obj_pos` (the position of the ` `
/// in ` obj`) over `<gen> <space> <n>` and return the byte offset of
/// the first digit of `<n>`. The lexer can re-anchor there and parse
/// the full `<n> <gen> obj` indirect-object header.
fn scan_back_two_ints(input: &[u8], space_before_obj_pos: usize) -> Option<usize> {
    // Walk back over `<gen>` digits.
    let mut p = space_before_obj_pos;
    if p == 0 {
        return None;
    }
    p -= 1;
    while p > 0 && input[p].is_ascii_digit() {
        p -= 1;
    }
    // Either we hit a non-digit (the space between `<n>` and `<gen>`)
    // or we hit the start of input.
    if !input[p].is_ascii_whitespace() {
        return None;
    }
    // Walk back through the whitespace.
    while p > 0 && input[p].is_ascii_whitespace() {
        p -= 1;
    }
    // Walk back over `<n>` digits.
    if !input[p].is_ascii_digit() {
        return None;
    }
    while p > 0 && input[p].is_ascii_digit() {
        p -= 1;
    }
    // The byte at `p` is now either a digit (if `<n>` ran to the
    // file start) or a whitespace / EOL byte just before `<n>`.
    if input[p].is_ascii_digit() {
        Some(p)
    } else {
        Some(p + 1)
    }
}

fn lookup<'d>(d: &'d Dict, k: &str) -> Option<&'d Object> {
    d.entries().iter().find(|(kk, _)| kk == k).map(|(_, v)| v)
}

fn require_number(d: &Dict, k: &str) -> Result<f64, PdfError> {
    match lookup(d, k) {
        Some(Object::Integer(n)) => Ok(*n as f64),
        Some(Object::Real(f)) => Ok(*f),
        Some(other) => Err(PdfError::other(format!(
            "PDF linearization: /{k} must be a number (got {other:?})"
        ))),
        None => Err(PdfError::other(format!(
            "PDF linearization: missing required /{k}"
        ))),
    }
}

fn require_uint(d: &Dict, k: &str) -> Result<u64, PdfError> {
    match lookup(d, k) {
        Some(Object::Integer(n)) if *n >= 0 => Ok(*n as u64),
        Some(Object::Integer(n)) => Err(PdfError::other(format!(
            "PDF linearization: /{k} must be non-negative (got {n})"
        ))),
        Some(other) => Err(PdfError::other(format!(
            "PDF linearization: /{k} must be an integer (got {other:?})"
        ))),
        None => Err(PdfError::other(format!(
            "PDF linearization: missing required /{k}"
        ))),
    }
}

/// `/H` is `[off len]` or `[off len off2 len2]`. We require the
/// first pair and surface the second pair when present.
#[allow(clippy::type_complexity)]
fn require_hint_array(d: &Dict) -> Result<(u64, u64, Option<(u64, u64)>), PdfError> {
    let Some(obj) = lookup(d, "H") else {
        return Err(PdfError::other("PDF linearization: missing required /H"));
    };
    let Object::Array(items) = obj else {
        return Err(PdfError::other(format!(
            "PDF linearization: /H must be an array (got {obj:?})"
        )));
    };
    if items.len() < 2 || items.len() % 2 != 0 {
        return Err(PdfError::other(format!(
            "PDF linearization: /H must have 2 or 4 elements (got {})",
            items.len()
        )));
    }
    let as_uint = |o: &Object, ix: usize| -> Result<u64, PdfError> {
        match o {
            Object::Integer(n) if *n >= 0 => Ok(*n as u64),
            _ => Err(PdfError::other(format!(
                "PDF linearization: /H[{ix}] must be a non-negative integer (got {o:?})"
            ))),
        }
    };
    let off = as_uint(&items[0], 0)?;
    let len = as_uint(&items[1], 1)?;
    let overflow = if items.len() >= 4 {
        Some((as_uint(&items[2], 2)?, as_uint(&items[3], 3)?))
    } else {
        None
    };
    Ok((off, len, overflow))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linearize::write_pdf_linearized;
    use crate::writer::write_pdf_from_scene;
    use oxideav_core::time::TimeBase;
    use oxideav_core::vector::{
        FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
    };
    use oxideav_scene::{Page, Scene};

    fn rect_frame(w: f32, h: f32, color: Rgba) -> VectorFrame {
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
                    fill: Some(Paint::Solid(color)),
                    stroke: None,
                    fill_rule: FillRule::NonZero,
                })],
                ..Group::default()
            },
            pts: None,
            time_base: TimeBase::new(1, 1),
        }
    }

    fn page_with(w: f32, h: f32, color: Rgba) -> Page {
        let mut page = Page::new(w, h);
        page.content = rect_frame(w, h, color);
        page
    }

    fn linearized_scene_3_pages() -> Vec<u8> {
        let scene = Scene {
            pages: Some(vec![
                page_with(100.0, 100.0, Rgba::opaque(255, 0, 0)),
                page_with(200.0, 150.0, Rgba::opaque(0, 255, 0)),
                page_with(300.0, 200.0, Rgba::opaque(0, 0, 255)),
            ]),
            ..Scene::default()
        };
        write_pdf_linearized(&scene).expect("linearize")
    }

    #[test]
    fn parses_linearization_dict_from_writer_output() {
        let pdf = linearized_scene_3_pages();
        let lin = LinearizationParams::parse(&pdf)
            .expect("parse")
            .expect("Some");
        assert_eq!(lin.linearized, 1.0);
        assert_eq!(lin.file_length, pdf.len() as u64);
        assert_eq!(lin.page_count, 3);
    }

    #[test]
    fn parsed_linearization_main_xref_actually_holds_xref() {
        let pdf = linearized_scene_3_pages();
        let lin = LinearizationParams::parse(&pdf)
            .expect("parse")
            .expect("Some");
        // The byte sequence at `main_xref_offset` should start with `xref\n`.
        let off = lin.main_xref_offset as usize;
        assert_eq!(
            &pdf[off..off + 5],
            b"xref\n",
            "/T must point at the main xref section"
        );
    }

    #[test]
    fn parsed_linearization_first_page_object_at_byte_offset_matches() {
        let pdf = linearized_scene_3_pages();
        let lin = LinearizationParams::parse(&pdf)
            .expect("parse")
            .expect("Some");
        // The first-page object number must appear as a `<n> 0 obj`
        // somewhere in the file. Round-9 emits page 1 as a header
        // `<O> 0 obj` — search for it.
        let needle = format!("{} 0 obj", lin.first_page_object_number);
        let pos = pdf
            .windows(needle.len())
            .position(|w| w == needle.as_bytes())
            .expect("first-page obj header present");
        assert!(pos > 0);
    }

    #[test]
    fn verify_succeeds_for_writer_output() {
        let pdf = linearized_scene_3_pages();
        let lin = LinearizationParams::parse(&pdf)
            .expect("parse")
            .expect("Some");
        lin.verify(&pdf).expect("verify clean");
    }

    #[test]
    fn verify_fails_when_l_mismatches_actual_length() {
        let pdf = linearized_scene_3_pages();
        let mut lin = LinearizationParams::parse(&pdf)
            .expect("parse")
            .expect("Some");
        lin.file_length += 1;
        let err = lin.verify(&pdf).expect_err("must reject");
        let msg = format!("{err}");
        assert!(msg.contains("/L = "), "msg = {msg:?}");
    }

    #[test]
    fn non_linearized_pdf_returns_none() {
        let scene = Scene {
            pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
            ..Scene::default()
        };
        let pdf = write_pdf_from_scene(&scene).expect("write");
        // The first object is the Catalog, not a /Linearized param dict.
        let lin = LinearizationParams::parse(&pdf).expect("parse");
        assert!(
            lin.is_none(),
            "non-linearized PDF must parse to None, got {lin:?}"
        );
    }

    #[test]
    fn empty_input_returns_none() {
        assert!(LinearizationParams::parse(b"").expect("parse").is_none());
        assert!(LinearizationParams::parse(b"%PDF-1.7\n%%EOF\n")
            .expect("parse")
            .is_none());
    }

    #[test]
    fn malformed_input_returns_none() {
        // No `obj` keyword anywhere — parser returns None, not Err.
        let stub = b"%PDF-1.5\n\xE2\xE3\xCF\xD3 no obj here at all\n%%EOF\n";
        assert!(LinearizationParams::parse(stub).expect("parse").is_none());
    }

    #[test]
    fn rejects_lin_dict_missing_required_key() {
        // Hand-rolled minimal first object that LOOKS like a
        // lin-dict (has /Linearized 1) but is missing /L.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
        bytes.extend_from_slice(b"1 0 obj\n<< /Linearized 1 >>\nendobj\n");
        bytes.extend_from_slice(
            b"xref\n0 1\n0000000000 65535 f \ntrailer\n<<>>\nstartxref\n0\n%%EOF\n",
        );
        let err = LinearizationParams::parse(&bytes).expect_err("must reject");
        let msg = format!("{err}");
        assert!(msg.contains("/L"), "msg = {msg:?}");
    }

    #[test]
    fn rejects_hint_array_with_odd_length() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
        bytes.extend_from_slice(
            b"1 0 obj\n<< /Linearized 1 /L 100 /H [ 50 ] /O 2 /E 80 /N 1 /T 90 >>\nendobj\n",
        );
        bytes.extend_from_slice(
            b"xref\n0 1\n0000000000 65535 f \ntrailer\n<<>>\nstartxref\n0\n%%EOF\n",
        );
        let err = LinearizationParams::parse(&bytes).expect_err("must reject /H length");
        let msg = format!("{err}");
        assert!(msg.contains("/H"), "msg = {msg:?}");
    }

    #[test]
    fn accepts_hint_array_with_four_elements() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
        bytes.extend_from_slice(
            b"1 0 obj\n<< /Linearized 1 /L 200 /H [ 50 30 100 20 ] /O 2 /E 80 /N 1 /T 180 >>\nendobj\n",
        );
        bytes.extend_from_slice(
            b"xref\n0 1\n0000000000 65535 f \ntrailer\n<<>>\nstartxref\n0\n%%EOF\n",
        );
        let lin = LinearizationParams::parse(&bytes)
            .expect("parse")
            .expect("Some");
        assert_eq!(lin.hint_offset, 50);
        assert_eq!(lin.hint_length, 30);
        assert_eq!(lin.hint_overflow, Some((100, 20)));
    }

    #[test]
    fn rejects_lin_dict_with_negative_int() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
        bytes.extend_from_slice(
            b"1 0 obj\n<< /Linearized 1 /L -1 /H [ 50 30 ] /O 2 /E 80 /N 1 /T 90 >>\nendobj\n",
        );
        bytes.extend_from_slice(
            b"xref\n0 1\n0000000000 65535 f \ntrailer\n<<>>\nstartxref\n0\n%%EOF\n",
        );
        let err = LinearizationParams::parse(&bytes).expect_err("must reject /L=-1");
        let msg = format!("{err}");
        assert!(msg.contains("/L"), "msg = {msg:?}");
    }

    #[test]
    fn scan_back_two_ints_finds_header_start() {
        // `   1 0 obj\n<<` — the call site supplies the position of
        // the space immediately before "obj"; helper should return
        // the offset of `1`.
        let buf = b"   1 0 obj\n<<";
        let space_pos = buf
            .windows(b" obj".len())
            .position(|w| w == b" obj")
            .unwrap();
        let start = scan_back_two_ints(buf, space_pos).expect("found");
        assert_eq!(&buf[start..start + 1], b"1");
    }
}
