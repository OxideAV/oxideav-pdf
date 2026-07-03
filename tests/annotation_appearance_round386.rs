//! Round-386 annotation appearance-stream painting end-to-end tests
//! (ISO 32000-1 §12.5.5 "Appearance Streams").
//!
//! Before round 386 the scene reader dropped every `/Annots`
//! annotation: an annotation whose visual presentation lives in its
//! `/AP /N` appearance stream (a Form XObject, §8.10) never reached
//! the `Scene`. This round resolves each page annotation's normal
//! appearance and splices it on top of the page content under the
//! §12.5.5 *Algorithm: Appearance streams*:
//!
//!   a) the appearance `/BBox` is transformed by its `/Matrix` and the
//!      smallest upright rectangle enclosing the resulting
//!      quadrilateral taken;
//!   b) a matrix `A` scales + translates that box onto the annotation
//!      `/Rect` (lower-left → lower-left, upper-right → upper-right);
//!   c) content maps through `AA = Matrix × A`.
//!
//! The fixtures are hand-built single-page PDFs exercising:
//!
//! * a Square annotation whose `/AP /N` red-square appearance lands
//!   inside `/Rect` with the non-uniform §12.5.5 scale;
//! * annotation content painting *after* (on top of) page content;
//! * a rotating `/Matrix` (step a's quadrilateral bounding box);
//! * an annotation without `/AP` staying scene-invisible;
//! * an appearance stream missing its `/BBox` painting nothing.

use oxideav_core::vector::{Group, Node, Paint, Transform2D};
use oxideav_pdf::read_pdf_to_scene;

/// Collect every `PathNode` fill colour in tree order (depth-first).
fn collect_fills(group: &Group, out: &mut Vec<(u8, u8, u8)>) {
    for child in &group.children {
        match child {
            Node::Path(p) => {
                if let Some(Paint::Solid(c)) = &p.fill {
                    out.push((c.r, c.g, c.b));
                }
            }
            Node::Group(g) => collect_fills(g, out),
            _ => {}
        }
    }
}

/// Find the first descendant group whose transform matches `want`
/// component-wise within 1e-4.
fn find_group_with_transform<'a>(group: &'a Group, want: &Transform2D) -> Option<&'a Group> {
    for child in &group.children {
        if let Node::Group(g) = child {
            let t = &g.transform;
            if (t.a - want.a).abs() < 1e-4
                && (t.b - want.b).abs() < 1e-4
                && (t.c - want.c).abs() < 1e-4
                && (t.d - want.d).abs() < 1e-4
                && (t.e - want.e).abs() < 1e-4
                && (t.f - want.f).abs() < 1e-4
            {
                return Some(g);
            }
            if let Some(found) = find_group_with_transform(g, want) {
                return Some(found);
            }
        }
    }
    None
}

fn classic_xref(mut bytes: Vec<u8>, offsets: &[u64]) -> Vec<u8> {
    let n = offsets.len();
    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(b"xref\n");
    bytes.extend_from_slice(format!("0 {n}\n").as_bytes());
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1) {
        bytes.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(b"trailer\n");
    bytes.extend_from_slice(format!("<< /Size {n} /Root 1 0 R >>\n").as_bytes());
    bytes.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    bytes
}

/// Build a single-page PDF with one annotation. The page content
/// paints a blue square; the annotation dict (object 6) carries
/// `rect` + the extra entries in `annot_extra`; the appearance form
/// (object 5) carries `form_dict_extra` (e.g. `/BBox` + `/Matrix`)
/// and paints `form_content`.
fn build_annot_pdf(rect: &str, annot_extra: &str, form_dict_extra: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: [u64; 7] = [0; 7];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] \
          /Contents 4 0 R /Annots [6 0 R] >>\nendobj\n",
    );

    // Page content: a blue square (paints before every annotation).
    let content: &[u8] = b"0 0 1 rg 0 0 10 10 re f\n";
    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // Appearance form: a red square filling its own BBox.
    let form_content: &[u8] = b"1 0 0 rg 0 0 10 10 re f\n";
    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XObject /Subtype /Form {form_dict_extra} /Length {} >>\nstream\n",
            form_content.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(form_content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    offsets[6] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "6 0 obj\n<< /Type /Annot /Subtype /Square /Rect {rect} {annot_extra} >>\nendobj\n"
        )
        .as_bytes(),
    );

    classic_xref(bytes, &offsets)
}

/// Build a single-page PDF whose annotation carries a stateful
/// appearance subdictionary `/AP << /N << /On 5 0 R /Off 7 0 R >> >>`
/// (§12.5.5 — checkbox-style appearance states). Object 5 paints red,
/// object 7 paints green; `annot_extra` supplies the `/AS` selector.
fn build_states_pdf(annot_extra: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: [u64; 8] = [0; 8];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] \
          /Contents 4 0 R /Annots [6 0 R] >>\nendobj\n",
    );

    let content: &[u8] = b"0 0 1 rg 0 0 10 10 re f\n";
    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    for (obj, colour) in [(5usize, "1 0 0"), (7usize, "0 1 0")] {
        let form_content = format!("{colour} rg 0 0 10 10 re f\n");
        offsets[obj] = bytes.len() as u64;
        bytes.extend_from_slice(
            format!(
                "{obj} 0 obj\n<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] \
                 /Length {} >>\nstream\n",
                form_content.len()
            )
            .as_bytes(),
        );
        bytes.extend_from_slice(form_content.as_bytes());
        bytes.extend_from_slice(b"\nendstream\nendobj\n");
    }

    offsets[6] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "6 0 obj\n<< /Type /Annot /Subtype /Widget /Rect [100 100 120 120] \
             /AP << /N << /On 5 0 R /Off 7 0 R >> >> {annot_extra} >>\nendobj\n"
        )
        .as_bytes(),
    );

    classic_xref(bytes, &offsets)
}

#[test]
fn appearance_state_selects_subdictionary_stream() {
    let scene = read_pdf_to_scene(&build_states_pdf("/AS /On")).expect("read");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert_eq!(
        fills,
        vec![(0, 0, 255), (255, 0, 0)],
        "/AS /On selects the On appearance stream"
    );

    let scene = read_pdf_to_scene(&build_states_pdf("/AS /Off")).expect("read");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert_eq!(
        fills,
        vec![(0, 0, 255), (0, 255, 0)],
        "/AS /Off selects the Off appearance stream"
    );
}

#[test]
fn appearance_state_missing_or_undefined_paints_nothing() {
    // No /AS at all — Table 164 requires it when /N is a
    // subdictionary; NOTE 3's reasonable behaviour is nothing.
    let scene = read_pdf_to_scene(&build_states_pdf("")).expect("read");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert_eq!(fills, vec![(0, 0, 255)]);

    // /AS designating a state the subdictionary doesn't define.
    let scene = read_pdf_to_scene(&build_states_pdf("/AS /Maybe")).expect("read");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert_eq!(fills, vec![(0, 0, 255)]);
}

#[test]
fn appearance_stream_paints_into_scene_at_rect() {
    // /BBox [0 0 10 10], identity /Matrix, /Rect [100 100 150 130]:
    // A = scale(5, 3) then translate(100, 100).
    let pdf = build_annot_pdf(
        "[100 100 150 130]",
        "/AP << /N 5 0 R >>",
        "/BBox [0 0 10 10]",
    );
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert_eq!(
        fills,
        vec![(0, 0, 255), (255, 0, 0)],
        "annotation appearance paints after (on top of) the page content"
    );

    let want = Transform2D {
        a: 5.0,
        b: 0.0,
        c: 0.0,
        d: 3.0,
        e: 100.0,
        f: 100.0,
    };
    assert!(
        find_group_with_transform(root, &want).is_some(),
        "the §12.5.5 placement matrix A maps BBox onto /Rect"
    );
}

#[test]
fn appearance_matrix_rotates_before_rect_mapping() {
    // /BBox [0 0 10 20] under /Matrix [0 1 -1 0 0 0] (90° CCW): the
    // transformed corners span [-20 0 0 10]. /Rect [50 50 90 70] is
    // 40×20, so A = scale(2, 2), e = 50 − 2·(−20) = 90, f = 50.
    let pdf = build_annot_pdf(
        "[50 50 90 70]",
        "/AP << /N 5 0 R >>",
        "/BBox [0 0 10 20] /Matrix [0 1 -1 0 0 0]",
    );
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let a = Transform2D {
        a: 2.0,
        b: 0.0,
        c: 0.0,
        d: 2.0,
        e: 90.0,
        f: 50.0,
    };
    let outer = find_group_with_transform(root, &a).expect("placement matrix A group");

    // The inner form group still carries the appearance /Matrix, so
    // content maps through AA = Matrix × A.
    let matrix = Transform2D {
        a: 0.0,
        b: 1.0,
        c: -1.0,
        d: 0.0,
        e: 0.0,
        f: 0.0,
    };
    assert!(
        find_group_with_transform(outer, &matrix).is_some(),
        "inner group keeps the appearance /Matrix"
    );
}

#[test]
fn hidden_and_noview_flags_suppress_painting() {
    // §12.5.3 Table 165 — Hidden is bit 2 (value 2), NoView bit 6
    // (value 32); Print (bit 3, value 4) does not suppress display.
    for (flags, expect_painted) in [(2u32, false), (32u32, false), (4u32, true)] {
        let pdf = build_annot_pdf(
            "[100 100 150 130]",
            &format!("/AP << /N 5 0 R >> /F {flags}"),
            "/BBox [0 0 10 10]",
        );
        let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
        let root = &scene.pages.as_ref().unwrap()[0].content.root;
        let mut fills = Vec::new();
        collect_fills(root, &mut fills);
        let want = if expect_painted {
            vec![(0, 0, 255), (255, 0, 0)]
        } else {
            vec![(0, 0, 255)]
        };
        assert_eq!(fills, want, "/F {flags}");
    }
}

#[test]
fn popup_annotation_never_paints() {
    // §12.5.6.14 — a pop-up annotation "shall have no appearance
    // stream … of its own"; one carrying an /AP anyway stays
    // page-invisible.
    let mut pdf = build_annot_pdf(
        "[100 100 150 130]",
        "/AP << /N 5 0 R >>",
        "/BBox [0 0 10 10]",
    );
    // Rewrite the fixture's /Subtype in place (same byte length).
    let needle = b"/Subtype /Square".as_slice();
    let pos = pdf
        .windows(needle.len())
        .rposition(|w| w == needle)
        .expect("annot subtype present");
    pdf[pos..pos + needle.len()].copy_from_slice(b"/Subtype /Popupp");
    pdf[pos + 15] = b' '; // "/Subtype /Popup " keeps offsets intact
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert_eq!(fills, vec![(0, 0, 255)]);
}

#[test]
fn annotation_without_ap_paints_nothing() {
    let pdf = build_annot_pdf("[100 100 150 130]", "", "/BBox [0 0 10 10]");
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert_eq!(
        fills,
        vec![(0, 0, 255)],
        "an annotation without /AP contributes nothing to the scene"
    );
}

#[test]
fn appearance_missing_bbox_paints_nothing() {
    // A form XObject without /BBox can't be mapped onto /Rect —
    // NOTE 3's "reasonable behaviour (such as displaying nothing)".
    let pdf = build_annot_pdf("[100 100 150 130]", "/AP << /N 5 0 R >>", "");
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert_eq!(fills, vec![(0, 0, 255)]);
}
