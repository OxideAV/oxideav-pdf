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

#[test]
fn hint_stream_is_36_bytes_minimum() {
    // The page offset hint table header is exactly 36 bytes (288
    // bits — F.3 items 1..13). With 0 bits-needed for every per-page
    // delta field, the per-page entries collapse and the whole hint
    // stream stays at 36 bytes payload (plus its dict + endobj).
    let pdf = write_pdf_from_scene_linearized(&three_page_scene()).expect("write");
    let s = pdf_lossy(&pdf);
    // Look for /S in the hint-stream dict — the hint stream is the
    // only stream that uses /S as a top-level key in this writer.
    assert!(s.contains("/S 36"), "hint table /S sentinel must be 36");
}
