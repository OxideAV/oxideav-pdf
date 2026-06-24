//! Round-364 Form XObject (`Do`) scene-splicing end-to-end test
//! (ISO 32000-1 §8.10 "Form XObjects").
//!
//! Before round 364 the content-stream parser dropped every `Do`
//! operator: a Form XObject's content (the ubiquitous appearance-stream
//! / reusable-graphic / page-template carrier) never reached the
//! `Scene`. This round resolves a page's `/Resources /XObject`
//! subdictionary, recursively parses every `/Subtype /Form` entry into
//! a `Group`, and splices it at `Do` under the §8.10.1 algorithm:
//!
//!   a) q (save state)        — implicit in the nested-group boundary
//!   b) concat /Matrix · CTM  — the form group's `transform`
//!   c) clip to /BBox         — the form group's `clip`
//!   d) paint the form        — the form group's `children`
//!   e) Q (restore)           — implicit at the group boundary
//!
//! The fixtures are hand-built single-page PDFs (each well under 10 KB)
//! that exercise:
//!
//! * a plain form painted via `Do` (red triangle reaches the scene);
//! * the form's `/Matrix` landing on the spliced group transform;
//! * the form's `/BBox` landing on the spliced group clip;
//! * a form that itself paints a nested form via its own `Do`;
//! * a self-referential form (cycle guard — no hang, content still
//!   surfaces once);
//! * an Image XObject `Do` staying a scene no-op (surfaced separately).

use oxideav_core::vector::{Node, Paint, PathCommand};
use oxideav_pdf::read_pdf_to_scene;

/// Collect every `PathNode` fill colour in tree order (depth-first).
fn collect_fills(group: &oxideav_core::vector::Group, out: &mut Vec<(u8, u8, u8)>) {
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

/// Find the first descendant `Group` whose `transform` is a uniform 2×
/// scale (the spliced form group carrying the form `/Matrix
/// [2 0 0 2 0 0]`), distinguishing it from the page content's
/// translation-only `cm` frame group.
fn first_form_group(group: &oxideav_core::vector::Group) -> Option<&oxideav_core::vector::Group> {
    for child in &group.children {
        if let Node::Group(g) = child {
            if g.transform.a == 2.0 && g.transform.d == 2.0 {
                return Some(g);
            }
            if let Some(found) = first_form_group(g) {
                return Some(found);
            }
        }
    }
    None
}

/// Build a single-page PDF whose page content paints a Form XObject via
/// `Do`. The form (object 5) draws a red triangle; `/Matrix` scales it
/// 2× and `/BBox` clips it to `[0 0 50 50]`. The page content sets a
/// translation `cm` before the `Do` so the form lands under a
/// non-trivial CTM.
fn build_form_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 6] = [0; 6];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // Page content: translate, then paint the form.
    let content: &[u8] = b"q 1 0 0 1 10 20 cm /Fm0 Do Q\n";

    // Form XObject content: a red triangle.
    let form_content: &[u8] = b"1 0 0 rg 0 0 m 50 50 l 50 0 l h f\n";

    // 5 = Form XObject stream.
    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XObject /Subtype /Form /FormType 1 \
             /BBox [0 0 50 50] /Matrix [2 0 0 2 0 0] /Length {} >>\nstream\n",
            form_content.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(form_content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // 3 = Page. /Resources /XObject maps /Fm0 → the form stream.
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
          /Contents 4 0 R \
          /Resources << /XObject << /Fm0 5 0 R >> >> \
          >>\nendobj\n",
    );

    // 4 = Content stream.
    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    finish_pdf(bytes, &offsets)
}

/// Build a single-page PDF whose form (object 5) itself paints a nested
/// form (object 6, a green triangle) via its own `Do`. Verifies the
/// recursive resolution surfaces the inner content.
fn build_nested_form_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 7] = [0; 7];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    let content: &[u8] = b"/Fm0 Do\n";
    // Outer form paints its own red triangle then the nested form.
    let outer: &[u8] = b"1 0 0 rg 0 0 m 10 10 l 10 0 l h f /Fm1 Do\n";
    // Inner form paints a green triangle.
    let inner: &[u8] = b"0 1 0 rg 20 0 m 30 10 l 30 0 l h f\n";

    // 5 = outer form; references /Fm1 in its own /Resources.
    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XObject /Subtype /Form /BBox [0 0 100 100] \
             /Resources << /XObject << /Fm1 6 0 R >> >> /Length {} >>\nstream\n",
            outer.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(outer);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // 6 = inner form.
    offsets[6] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "6 0 obj\n<< /Type /XObject /Subtype /Form /BBox [0 0 100 100] /Length {} >>\nstream\n",
            inner.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(inner);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
          /Contents 4 0 R \
          /Resources << /XObject << /Fm0 5 0 R >> >> \
          >>\nendobj\n",
    );

    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    finish_pdf(bytes, &offsets)
}

/// Build a single-page PDF whose form (object 5) references *itself*
/// via its own `Do` — the cycle guard must break the loop while still
/// surfacing the form's own painted content once.
fn build_cyclic_form_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 6] = [0; 6];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    let content: &[u8] = b"/Fm0 Do\n";
    // The form paints a red triangle then re-invokes itself.
    let form: &[u8] = b"1 0 0 rg 0 0 m 10 10 l 10 0 l h f /Self Do\n";

    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XObject /Subtype /Form /BBox [0 0 100 100] \
             /Resources << /XObject << /Self 5 0 R >> >> /Length {} >>\nstream\n",
            form.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(form);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
          /Contents 4 0 R \
          /Resources << /XObject << /Fm0 5 0 R >> >> \
          >>\nendobj\n",
    );

    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    finish_pdf(bytes, &offsets)
}

/// Build a single-page PDF whose `Do` names an *Image* XObject — the
/// scene path must leave it a no-op (images are surfaced by the
/// dedicated walker, not spliced into the vector tree).
fn build_image_xobject_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 6] = [0; 6];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    let content: &[u8] = b"/Im0 Do\n";
    let img: &[u8] = &[0u8; 4];

    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XObject /Subtype /Image /Width 2 /Height 2 \
             /ColorSpace /DeviceGray /BitsPerComponent 8 /Length {} >>\nstream\n",
            img.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(img);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
          /Contents 4 0 R \
          /Resources << /XObject << /Im0 5 0 R >> >> \
          >>\nendobj\n",
    );

    offsets[4] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
    );
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    finish_pdf(bytes, &offsets)
}

/// Append the classic xref table + trailer for a fixture whose object
/// `offsets[i]` is the byte offset of object `i` (slot 0 is the free
/// head, written as `f`).
fn finish_pdf(mut bytes: Vec<u8>, offsets: &[u64]) -> Vec<u8> {
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

#[test]
fn form_xobject_do_splices_content_into_scene() {
    let pdf = build_form_pdf();
    assert!(pdf.len() <= 10 * 1024, "fixture under 10 KB");

    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let pages = scene.pages.as_ref().expect("scene has pages");
    assert_eq!(pages.len(), 1);

    let root = &pages[0].content.root;
    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert_eq!(
        fills,
        vec![(255, 0, 0)],
        "the form's red triangle reaches the scene exactly once"
    );
}

#[test]
fn form_xobject_matrix_lands_on_group_transform() {
    let pdf = build_form_pdf();
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let g = first_form_group(root).expect("the scaled form group exists");
    // /Matrix [2 0 0 2 0 0] — uniform 2× scale.
    assert_eq!(g.transform.a, 2.0);
    assert_eq!(g.transform.d, 2.0);
    assert_eq!(g.transform.b, 0.0);
    assert_eq!(g.transform.c, 0.0);
}

#[test]
fn form_xobject_bbox_lands_on_group_clip() {
    let pdf = build_form_pdf();
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let g = first_form_group(root).expect("the scaled form group exists");
    let clip = g.clip.as_ref().expect("/BBox produced a clip path");
    // BBox [0 0 50 50] → closed rectangle: M(0,0) L(50,0) L(50,50) L(0,50) close.
    assert_eq!(clip.commands.len(), 5);
    assert!(matches!(clip.commands[0], PathCommand::MoveTo(p) if p.x == 0.0 && p.y == 0.0));
    assert!(matches!(clip.commands[4], PathCommand::Close));
    // The far corner must be (50, 50).
    let has_far = clip
        .commands
        .iter()
        .any(|c| matches!(c, PathCommand::LineTo(p) if p.x == 50.0 && p.y == 50.0));
    assert!(has_far, "clip rectangle reaches the BBox far corner");
}

#[test]
fn nested_form_xobject_recurses() {
    let pdf = build_nested_form_pdf();
    assert!(pdf.len() <= 10 * 1024, "fixture under 10 KB");

    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    // Outer form's red triangle + inner form's green triangle, both
    // surfaced through the recursive resolution.
    assert!(
        fills.contains(&(255, 0, 0)),
        "outer form red triangle present, got {fills:?}"
    );
    assert!(
        fills.contains(&(0, 255, 0)),
        "nested form green triangle present, got {fills:?}"
    );
}

#[test]
fn cyclic_form_xobject_is_guarded() {
    let pdf = build_cyclic_form_pdf();
    // Must terminate (no infinite recursion) and still surface the
    // form's own painted content once.
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert_eq!(
        fills,
        vec![(255, 0, 0)],
        "self-referential form surfaces its content once, cycle broken"
    );
}

#[test]
fn image_xobject_do_is_scene_noop() {
    let pdf = build_image_xobject_pdf();
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let mut fills = Vec::new();
    collect_fills(root, &mut fills);
    assert!(
        fills.is_empty(),
        "an Image XObject Do does not splice vector geometry, got {fills:?}"
    );
    // The vector tree should have no painted children from the image.
    assert!(
        root.children.is_empty(),
        "image XObject leaves the scene tree empty on the vector side"
    );
}
