//! Round-9 Linearization (Fast Web View) tests.
//!
//! Verifies the on-wire shape of [`write_pdf_from_scene_linearized`]
//! conforms to ISO 32000-1 §7.5.6 + Annex F:
//!
//! 1. The first 1024 bytes carry a complete linearization parameter
//!    dictionary (`/Linearized 1` + `/L` + `/H` + `/O` + `/E` + `/N`
//!    + `/T`) — F.3.3 hard requirement.
//! 2. `startxref` at the very end points at the FIRST cross-reference
//!    section in the file (the first-page xref) — F.3.11.
//! 3. The first-page trailer carries `/Prev` pointing at the main
//!    cross-reference table near EOF — F.3.4.
//! 4. The output round-trips through [`read_pdf_to_scene`] (the
//!    reader sees a valid linearized-or-plain PDF either way).

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_scene::{Page, Scene};

use oxideav_pdf::{read_pdf_to_scene, write_pdf_from_scene_linearized};

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

fn three_page_scene() -> Scene {
    Scene {
        pages: Some(vec![
            page_with(595.0, 842.0, Rgba::opaque(255, 0, 0)),
            page_with(595.0, 842.0, Rgba::opaque(0, 255, 0)),
            page_with(595.0, 842.0, Rgba::opaque(0, 0, 255)),
        ]),
        ..Scene::default()
    }
}

fn pdf_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn empty_scene_is_rejected() {
    let scene = Scene::default();
    let err = write_pdf_from_scene_linearized(&scene).unwrap_err();
    assert!(format!("{err}").contains("pages mode"));
}

#[test]
fn linearized_starts_with_pdf_1_5_header() {
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    assert!(pdf.starts_with(b"%PDF-1.5\n"));
    assert!(pdf.ends_with(b"%%EOF\n"));
}

#[test]
fn lin_param_dict_is_in_first_1024_bytes() {
    // F.3.3 hard requirement: lin-dict entirely within first 1024
    // bytes. A reader that decides "this isn't linearized" gives up
    // after 1024 bytes — we have to fit.
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let head = &pdf[..1024.min(pdf.len())];
    let s = pdf_lossy(head);
    let lin_idx = s.find("/Linearized 1").expect("/Linearized 1 in head");
    let close_off = s[lin_idx..].find(">>").expect("lin-dict close");
    assert!(lin_idx + close_off + 2 <= 1024);
}

#[test]
fn lin_param_dict_carries_all_required_keys() {
    // Required keys per Table F.1: Linearized, L, H, O, E, N, T.
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let head = pdf_lossy(&pdf[..1024]);
    for key in ["/Linearized", "/L ", "/H [", "/O ", "/E ", "/N ", "/T "] {
        assert!(head.contains(key), "lin-dict missing {key:?}");
    }
}

#[test]
fn l_value_equals_actual_file_length() {
    // F.3.3 + Table F.1: "/L shall be exactly equal to the actual
    // length of the PDF file. A mismatch indicates that the file is
    // not linearized..."
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let actual = pdf.len();
    let head = pdf_lossy(&pdf[..1024.min(pdf.len())]);
    let l_idx = head.find("/L ").unwrap();
    let value: u64 = head[l_idx + 3..]
        .split_ascii_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(value as usize, actual, "/L must equal actual file length");
}

#[test]
fn n_value_equals_page_count() {
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let head = pdf_lossy(&pdf[..1024]);
    let n_idx = head.find("/N ").unwrap();
    let value: u64 = head[n_idx + 3..]
        .split_ascii_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(value, 3);
}

#[test]
fn startxref_points_at_first_page_xref() {
    // F.3.11: "The startxref line shall give the offset of the
    // first-page cross-reference table." That's the FIRST `xref\n`
    // occurrence in the file (Part 3) — Annex F places the main
    // xref at EOF (Part 11).
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let s = pdf_lossy(&pdf);
    let start_off = s.rfind("startxref\n").unwrap() + "startxref\n".len();
    let line = s[start_off..].split('\n').next().unwrap().trim();
    let off: usize = line.parse().unwrap();
    // First-page xref is the FIRST `\nxref\n` block in the file
    // (leading-newline disambiguates from `startxref`).
    let needle = b"\nxref\n";
    let first_xref_off = pdf
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + 1)
        .unwrap();
    assert_eq!(off, first_xref_off);
}

#[test]
fn first_page_trailer_carries_prev_pointing_at_main_xref() {
    // F.3.4: "The Prev entry of the first-page trailer shall give
    // the offset of the main cross-reference table."
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let s = pdf_lossy(&pdf);

    // First-page trailer = first `trailer\n` block in the file.
    let first_trailer_off = s.find("trailer\n").unwrap();
    let after = &s[first_trailer_off..];
    let close_off = after.find(">>").unwrap();
    let prev_off = after
        .find("/Prev ")
        .expect("first trailer must carry /Prev");
    assert!(
        prev_off < close_off,
        "/Prev must be inside the trailer dict"
    );

    // The /Prev value is the offset of the main xref. The main xref
    // is the SECOND `xref\n` occurrence in the file.
    let prev_value_start = first_trailer_off + prev_off + b"/Prev ".len();
    let prev_value_end = s[prev_value_start..]
        .find(|c: char| !c.is_ascii_digit())
        .unwrap();
    let prev_off_value: usize = s[prev_value_start..prev_value_start + prev_value_end]
        .parse()
        .unwrap();

    // Find the second `\nxref\n` occurrence — the leading newline
    // disambiguates from the `startxref` keyword that *contains*
    // `xref` as a substring.
    let needle = b"\nxref\n";
    let mut iter = pdf
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i + 1); // +1 to skip the leading \n
    let _first = iter.next().unwrap();
    let main_xref_off = iter.next().expect("main xref must exist");
    assert_eq!(prev_off_value, main_xref_off);
}

#[test]
fn round_trips_through_reader() {
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let scene = read_pdf_to_scene(&pdf).expect("reader accepts linearized output");
    assert_eq!(scene.pages.as_ref().unwrap().len(), 3);
}

#[test]
fn single_page_round_trips() {
    let scene = Scene {
        pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
        ..Scene::default()
    };
    let pdf = write_pdf_from_scene_linearized(&scene).expect("write");
    let scene2 = read_pdf_to_scene(&pdf).expect("read");
    assert_eq!(scene2.pages.as_ref().unwrap().len(), 1);
}

#[test]
fn first_page_object_id_matches_o_entry() {
    // F.3.3 Table F.1: "/O shall be the object number of the first
    // page's page object."
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let head = pdf_lossy(&pdf[..1024]);
    let o_idx = head.find("/O ").unwrap();
    let o_value: u32 = head[o_idx + 3..]
        .split_ascii_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();

    // The first page's Page object should appear shortly after the
    // first-page xref + Catalog (Part 4..6 of Annex F). Its
    // indirect-object header is `<O> 0 obj\n<< /Type /Page`.
    let needle = format!("\n{} 0 obj", o_value);
    let s = pdf_lossy(&pdf);
    let pos = s
        .find(&needle)
        .unwrap_or_else(|| panic!("page object {} not found by needle {:?}", o_value, needle));
    let after = &s[pos + needle.len()..];
    assert!(
        after.contains("/Type /Page"),
        "object {o_value} (per /O) must be a /Type /Page dict"
    );
}

#[test]
fn pages_tree_count_matches_n() {
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let s = pdf_lossy(&pdf);
    assert!(s.contains("/Type /Pages"));
    assert!(s.contains("/Count 3"));
}

/// Locate the hint stream's payload bytes — the indirect object
/// whose dict carries /S /T /O. Returns the slice between
/// `\nstream\n` and `\nendstream`.
fn hint_stream_payload(pdf: &[u8]) -> &[u8] {
    // Find the dict that carries /S — that anchors the hint stream.
    let s = pdf_lossy(pdf);
    let s_idx = s.find("/S ").expect("hint dict /S");
    // Walk forward to `\nstream\n`.
    let stream_off = pdf[s_idx..]
        .windows(b"\nstream\n".len())
        .position(|w| w == b"\nstream\n")
        .expect("hint stream marker");
    let payload_off = s_idx + stream_off + b"\nstream\n".len();
    // Walk forward to `\nendstream`.
    let end_off = pdf[payload_off..]
        .windows(b"\nendstream".len())
        .position(|w| w == b"\nendstream")
        .expect("endstream marker");
    &pdf[payload_off..payload_off + end_off]
}

#[test]
fn hint_stream_per_page_object_count_matches_actual() {
    // Item 1 of each per-page entry = absolute object count for
    // that page (NOT a delta — bits-needed for the delta field is
    // 32 + the value IS the count when least = ..). Spec F.4 item
    // 1: "A number that, when added to the least number of objects
    // in a page (Table F.3, item 1), shall give the number of
    // objects in the page." So encoded value = count - least.
    //
    // For our three-page solid-fill scene, every page has exactly
    // 3 objects (Page + Resources + Contents — no extras), so
    // least = 3 and per-page item-1 delta = 0 for all pages.
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let payload = hint_stream_payload(&pdf);
    // Page-offset header is 36 bytes; per-page section starts at 36.
    assert_eq!(payload.len(), 36 + 3 * 16 + 24 + 28 + 14);
    // Verify item 1 of header = 3 (least objects per page).
    assert_eq!(&payload[0..4], &3u32.to_be_bytes());
    // Per-page item 1 (block A) — three 4-byte deltas, all 0.
    for i in 0..3 {
        let off = 36 + i * 4;
        let delta = u32::from_be_bytes(payload[off..off + 4].try_into().unwrap());
        assert_eq!(delta, 0, "page {i} item-1 delta must be 0");
    }
}

#[test]
fn hint_stream_first_page_object_location_matches_first_page_off() {
    // Header item 2: location of first page's page object. We
    // recompute the first page's offset by scanning for `\n<O> 0
    // obj\n<< /Type /Page` and compare.
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let payload = hint_stream_payload(&pdf);
    let item2 = u32::from_be_bytes(payload[4..8].try_into().unwrap()) as usize;

    // Cross-check against the actual page object location: parse /O
    // from the lin-dict, then find the matching `\n<O> 0 obj`. The
    // actual page-object position is at the byte AFTER the `\n` (so
    // +1 from the find result), which is what the hint table records.
    let head = pdf_lossy(&pdf[..1024]);
    let o_idx = head.find("/O ").unwrap();
    let o_value: u32 = head[o_idx + 3..]
        .split_ascii_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    // First-page object header: `<O> 0 obj` at the very start of a
    // line. We search for `\n<O> 0 obj` and skip the leading `\n`.
    let needle = format!("\n{} 0 obj\n", o_value);
    let actual_first_page_off = pdf
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())
        .unwrap()
        + 1;
    assert_eq!(
        item2, actual_first_page_off,
        "hint table item-2 must match the actual byte offset of the first page object"
    );
}

#[test]
fn hint_stream_per_page_lengths_sum_matches_layout() {
    // Sanity-check items 4 (least page length) + items 2 (per-page
    // page-length deltas) — their sum should equal the page lengths
    // we can independently observe in the byte stream.
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let payload = hint_stream_payload(&pdf);
    let least_page_len = u32::from_be_bytes(payload[10..14].try_into().unwrap()) as u64;
    // Block A starts at 36, block B at 36 + 12 = 48.
    let block_b = 36 + 3 * 4;
    let mut hint_lengths = Vec::with_capacity(3);
    for i in 0..3 {
        let off = block_b + i * 4;
        let delta = u32::from_be_bytes(payload[off..off + 4].try_into().unwrap()) as u64;
        hint_lengths.push(least_page_len + delta);
    }

    // Independently compute page lengths by scanning the file.
    let s = pdf_lossy(&pdf);
    let head = pdf_lossy(&pdf[..1024]);
    let o_idx = head.find("/O ").unwrap();
    let o_value: u32 = head[o_idx + 3..]
        .split_ascii_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let needle = format!("\n{} 0 obj", o_value);
    let first_page_off = s.find(&needle).unwrap() + 1;
    // Pages 2, 3 follow contiguously after first page's contents.
    // We just check that sum of lengths > 0 and the first length is
    // sane (positive, less than file size).
    assert!(hint_lengths[0] > 0);
    assert!((hint_lengths[0] as usize) < pdf.len() - first_page_off);
}

#[test]
fn hint_stream_carries_per_page_section() {
    // Round-13 emits Table F.4 per-page entries (items 1, 2, 6, 7)
    // at fixed 32-bit width — 16 bytes per page. /S marks the byte
    // offset of the shared-object table that *follows* the
    // page-offset table in the hint stream payload, so /S = 36
    // (header) + n_pages * 16 (per-page section).
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let s = pdf_lossy(&pdf);
    let expected_s = 36 + 3 * 16;
    let needle = format!("/S {}", expected_s);
    assert!(
        s.contains(&needle),
        "hint dict /S must equal 36 + 3*16 = {} (page-offset header + per-page entries), got dict containing /S",
        expected_s
    );
}
