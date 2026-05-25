//! Round-128 `Tj`/`TJ` text-show with `/Resources /Font` plumbing
//! end-to-end test (ISO 32000-1 §9.4 + Table 105 + Table 108 + Table 109).
//!
//! A hand-built single-page PDF carries a `/Resources /Font`
//! subdictionary with one Helvetica entry (`/F1`). The page's
//! content stream:
//!
//! ```text
//! BT
//!     /F1 12 Tf      % select font + size — round-128 captures both
//!     14 TL          % text leading (used by the implicit T* in ')
//!     72 712 Td      % move text origin to (72, 712)
//!     (Hello) Tj     % first show — operator Tj
//!     (World) '      % second show — operator ', implicit T* line-advance
//!     [(A) -120 (B)] TJ   % third show — TJ array, kern dropped
//! ET
//! ```
//!
//! The walker resolves `/F1` through the page's `/Resources /Font`
//! and emits three [`ContentTextShow`] events, each with the
//! resolved font dictionary, the `Tf`-recorded font size, the raw
//! decoded operand bytes, and the text-matrix origin at the moment
//! of the show. The plumbing shape mirrors the round-125 `gs`
//! resolver — `/Resources /Font` flows through
//! `resolve_font_resources` and then into
//! [`parse_content_stream_full`].
//!
//! Fixture: hand-built in `build_text_pdf` — well under 1 KB. A copy
//! is committed at `tests/fixtures/font_resources.pdf` and the two
//! byte sequences are required to match (`fixture_round_trips`), the
//! same discipline the round-122 hybrid-xrefstm + round-125
//! ExtGState tests follow.

use oxideav_pdf::objects::{Dict, Object};
use oxideav_pdf::read_pdf_to_scene;
use oxideav_pdf::reader::content::parse_content_stream_full;
use oxideav_pdf::reader::{ContentTextShow, DocumentReader, TextShowOp};

/// Build the same `/Resources /Font` + `Tj`/`'/`TJ`-using PDF that
/// lives at `tests/fixtures/font_resources.pdf`. Kept byte-stable so
/// the fixture-vs-builder check has a single source of truth.
fn build_text_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 6] = [0; 6];

    // 1 = Catalog
    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    // 2 = Pages
    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // The content stream — three text-show ops inside one BT…ET.
    let content: &[u8] =
        b"BT /F1 12 Tf 14 TL 72 712 Td (Hello) Tj (World) ' [(A) -120 (B)] TJ ET\n";

    // 5 = Font dict (referenced from /Resources /Font /F1). One
    // simple Type1 Helvetica descriptor — the round-128 reader uses
    // /BaseFont + /Subtype + /Encoding to know which decoder to pick
    // (round-22 path), but doesn't yet decode bytes itself; the
    // round-128 surface just hands the dict back so a downstream
    // consumer can do the byte→Unicode step.
    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 \
          /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n",
    );

    // 3 = Page. /Resources carries an inline /Font dict with /F1
    // pointing at object 5 (indirect — forces the reader through
    // `resolve_font_resources`'s single-hop indirect dereference
    // path, the same shape the round-125 `gs` resolver uses).
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
          /Contents 4 0 R \
          /Resources << /Font << /F1 5 0 R >> >> \
          >>\nendobj\n",
    );

    // 4 = Content stream.
    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // xref
    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n");
    bytes.extend_from_slice(b"0 6\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    bytes.extend_from_slice(format!("{:010} 00000 n \n", offsets[1]).as_bytes());
    bytes.extend_from_slice(format!("{:010} 00000 n \n", offsets[2]).as_bytes());
    bytes.extend_from_slice(format!("{:010} 00000 n \n", offsets[3]).as_bytes());
    bytes.extend_from_slice(format!("{:010} 00000 n \n", offsets[4]).as_bytes());
    bytes.extend_from_slice(format!("{:010} 00000 n \n", offsets[5]).as_bytes());
    bytes.extend_from_slice(b"trailer\n");
    bytes.extend_from_slice(b"<< /Size 6 /Root 1 0 R >>\n");
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());

    bytes
}

#[test]
fn fixture_round_trips_in_memory_and_on_disk() {
    let mem = build_text_pdf();
    let disk = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/font_resources.pdf"
    ))
    .expect("checked-in font_resources.pdf fixture");
    assert_eq!(
        mem, disk,
        "in-memory builder must produce the same bytes as the committed fixture"
    );
    // Round 128's hand-built fixture stays well under the per-fixture
    // 10 KB ceiling the round prompt sets.
    assert!(
        disk.len() <= 10 * 1024,
        "fixture must fit ≤10 KB ({} bytes)",
        disk.len()
    );
}

/// End-to-end: parse the PDF and confirm the round-3 walker still
/// accepts the page (text doesn't reach the IR's `Node` tree — it
/// surfaces through the round-128 [`ContentTextShow`] side channel on
/// the new [`parse_content_stream_full`] entry instead).
#[test]
fn read_pdf_to_scene_accepts_text_only_page() {
    let pdf = build_text_pdf();
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let pages = scene.pages.as_ref().expect("scene has pages");
    assert_eq!(pages.len(), 1);
    // The page's IR root has no painted geometry (a text-only page);
    // the text shows are surfaced through the parser entry — see the
    // `parse_content_stream_full_*` tests below.
    let root = &pages[0].content.root;
    assert!(root.children.is_empty(), "text-only page has no shapes");
}

/// The DocumentReader surface opens the fixture cleanly — the
/// round-125 ExtGState plumbing already validates page resources;
/// the round-128 font plumbing must not break that path.
#[test]
fn document_reader_open_succeeds_on_text_pdf() {
    let pdf = build_text_pdf();
    let _r = DocumentReader::open(&pdf).expect("DocumentReader::open on text PDF");
}

/// Unit-level: hand the same content stream + a `/Resources /Font`
/// dict to [`parse_content_stream_full`] directly and verify every
/// honoured Table-105/108/109 operator reaches the
/// [`ContentTextShow`] list.
#[test]
fn parse_content_stream_full_emits_three_text_shows() {
    let f1 = Dict::new()
        .with("Type", Object::Name("Font".into()))
        .with("Subtype", Object::Name("Type1".into()))
        .with("BaseFont", Object::Name("Helvetica".into()))
        .with("Encoding", Object::Name("WinAnsiEncoding".into()));
    let fonts = Dict::new().with("F1", Object::Dict(f1));

    let bytes = b"BT /F1 12 Tf 14 TL 72 712 Td (Hello) Tj (World) ' [(A) -120 (B)] TJ ET\n";
    let parsed =
        parse_content_stream_full(bytes, None, Some(&fonts)).expect("parse with /Resources /Font");

    assert_eq!(parsed.text_shows.len(), 3, "BT…ET emits 3 shows");

    // First show — `(Hello) Tj` at (72, 712), font F1 / size 12.
    let s0: &ContentTextShow = &parsed.text_shows[0];
    assert_eq!(s0.font_name, "F1");
    assert!((s0.font_size - 12.0).abs() < 1e-3);
    assert_eq!(s0.bytes, b"Hello");
    assert!((s0.position.0 - 72.0).abs() < 1e-3);
    assert!((s0.position.1 - 712.0).abs() < 1e-3);
    assert!(matches!(s0.operator, TextShowOp::Tj));
    let dict = s0.font_dict.as_ref().expect("F1 resolved");
    let subtype = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Subtype")
        .map(|(_, v)| v.clone());
    assert!(matches!(subtype, Some(Object::Name(ref n)) if n == "Type1"));

    // Second show — `(World) '` does the implicit T* line-advance
    // (TL=14 → y drops to 712-14=698). Operator carries SingleQuote.
    let s1 = &parsed.text_shows[1];
    assert_eq!(s1.bytes, b"World");
    assert!((s1.position.0 - 72.0).abs() < 1e-3);
    assert!(
        (s1.position.1 - 698.0).abs() < 1e-3,
        "T* drops y by TL: got {}",
        s1.position.1
    );
    assert!(matches!(s1.operator, TextShowOp::SingleQuote));

    // Third show — `[(A) -120 (B)] TJ` concatenates the strings,
    // drops the kern, operator TJ. Position is still the
    // post-`'` origin (no explicit movement between the two shows).
    let s2 = &parsed.text_shows[2];
    assert_eq!(s2.bytes, b"AB");
    assert!(matches!(s2.operator, TextShowOp::TJ));
}

/// A `/Resources /Font` dict that doesn't carry the `Tf`-named font
/// still emits the show — the consumer learns the font wasn't
/// resolved via `font_dict = None` rather than the show silently
/// disappearing.
#[test]
fn parse_content_stream_full_emits_show_with_unresolved_font() {
    let fonts = Dict::new().with("F1", Object::Dict(Dict::new()));
    let bytes = b"BT /F_UNKNOWN 10 Tf 0 0 Td (X) Tj ET\n";
    let parsed =
        parse_content_stream_full(bytes, None, Some(&fonts)).expect("parse with /Resources /Font");
    assert_eq!(parsed.text_shows.len(), 1);
    let s = &parsed.text_shows[0];
    assert_eq!(s.font_name, "F_UNKNOWN");
    assert_eq!(s.bytes, b"X");
    assert!(s.font_dict.is_none());
}

/// Without `/Resources /Font`, text-show operators silently no-op —
/// matches the round-3 / round-125 entry points' behaviour so
/// existing callers don't see new events appear.
#[test]
fn parse_content_stream_full_with_no_fonts_drops_shows() {
    let bytes = b"BT /F1 12 Tf 0 0 Td (Hello) Tj ET\n";
    let parsed = parse_content_stream_full(bytes, None, None).expect("parse without fonts");
    assert!(parsed.text_shows.is_empty());
    // The painted-geometry root still parses cleanly (text-only,
    // no shapes).
    assert!(parsed.root.children.is_empty());
}
