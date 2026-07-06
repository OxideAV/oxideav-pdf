//! Round-393 `/SMask` soft-mask end-to-end tests (ISO 32000-1
//! §11.6.4.3 "Mask Shape and Opacity" + §11.6.5.2 "Soft-Mask
//! Dictionaries").
//!
//! A `gs` whose parameter dictionary carries an `/SMask` soft-mask
//! dictionary establishes the current soft mask in the graphics state;
//! objects painted while it is in force composite through it. The
//! reader resolves the mask's `/G` transparency-group XObject exactly
//! like a `Do`-spliced form (§8.10.1 — `/Matrix` on the group
//! transform, `/BBox` as the group clip, content against its own
//! `/Resources`), maps `/S /Luminosity` → `MaskKind::Luminance` /
//! `/S /Alpha` → `MaskKind::Alpha` (§11.5.2 + §11.5.3), and wraps each
//! painted object in a `Node::SoftMask` whose `mask` subtree is the
//! group at `/Matrix ∘ CTM-at-gs-time` (§11.6.5.2).
//!
//! The fixtures are hand-built single-page PDFs:
//!
//! * a luminosity mask (`/G` paints a white square) over a red fill —
//!   the scene carries `Node::SoftMask { Luminance, path }`;
//! * an `/S /Alpha` variant → `MaskKind::Alpha`;
//! * `/SMask /None` re-set — the second fill paints unwrapped;
//! * the mask group's `/Matrix` + `/BBox` land on the mask subtree.

use oxideav_core::vector::{Group, MaskKind, Node, Paint};
use oxideav_pdf::read_pdf_to_scene;

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

/// Build a single-page PDF that paints a red square through a
/// luminosity (or alpha) soft mask whose `/G` group draws a white
/// square with `/Matrix [2 0 0 2 5 5]` and `/BBox [0 0 40 40]`.
///
/// * object 4 — page content: `q /GS0 gs …red fill… Q` then an
///   unmasked green fill after the bracket.
/// * object 5 — the mask's transparency-group XObject.
fn build_smask_pdf(subtype: &str, smask_value: Option<&str>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 6] = [0; 6];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // Page content: masked red fill, then unmasked green fill.
    let content: &[u8] = b"q /GS0 gs 1 0 0 rg 10 10 m 60 10 l 60 60 l 10 60 l h f Q \
          0 1 0 rg 70 10 m 90 10 l 90 30 l 70 30 l h f\n";

    // Mask group content: a white square.
    let mask_content: &[u8] = b"1 1 1 rg 0 0 m 20 0 l 20 20 l 0 20 l h f\n";

    // 5 = the /G transparency-group XObject.
    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XObject /Subtype /Form /FormType 1 \
             /BBox [0 0 40 40] /Matrix [2 0 0 2 5 5] \
             /Group << /S /Transparency /CS /DeviceGray >> \
             /Length {} >>\nstream\n",
            mask_content.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(mask_content);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // 3 = Page, with the /ExtGState /GS0 carrying the /SMask.
    let smask_entry = match smask_value {
        Some(v) => v.to_string(),
        None => format!("<< /Type /Mask /S /{subtype} /G 5 0 R >>"),
    };
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        format!(
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
             /Contents 4 0 R \
             /Resources << /ExtGState << /GS0 << /Type /ExtGState \
             /SMask {smask_entry} >> >> >> \
             >>\nendobj\n"
        )
        .as_bytes(),
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

/// Depth-first search for the first `Node::SoftMask` in the tree.
fn find_soft_mask(group: &Group) -> Option<(&Node, MaskKind, &Node)> {
    for child in &group.children {
        match child {
            Node::SoftMask {
                mask,
                mask_kind,
                content,
            } => return Some((mask.as_ref(), *mask_kind, content.as_ref())),
            Node::Group(g) => {
                if let Some(found) = find_soft_mask(g) {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

/// Collect every *unwrapped* solid path fill (fills inside a SoftMask
/// content subtree are not visited).
fn collect_bare_fills(group: &Group, out: &mut Vec<(u8, u8, u8)>) {
    for child in &group.children {
        match child {
            Node::Path(p) => {
                if let Some(Paint::Solid(c)) = &p.fill {
                    out.push((c.r, c.g, c.b));
                }
            }
            Node::Group(g) => collect_bare_fills(g, out),
            _ => {}
        }
    }
}

#[test]
fn luminosity_smask_wraps_masked_fill() {
    let pdf = build_smask_pdf("Luminosity", None);
    assert!(pdf.len() <= 10 * 1024, "fixture under 10 KB");

    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let pages = scene.pages.as_ref().expect("scene has pages");
    let root = &pages[0].content.root;

    let (mask, kind, content) = find_soft_mask(root).expect("SoftMask node in scene");
    assert_eq!(kind, MaskKind::Luminance);

    // The content is the red square.
    let Node::Path(p) = content else {
        panic!("masked content is the path, got {content:?}");
    };
    let Some(Paint::Solid(c)) = &p.fill else {
        panic!("solid fill");
    };
    assert_eq!((c.r, c.g, c.b), (255, 0, 0));

    // The mask subtree carries the /G group: /Matrix [2 0 0 2 5 5] on
    // the transform, /BBox as clip, white square inside.
    let Node::Group(anchor) = mask else {
        panic!("mask anchor group");
    };
    fn find_matrix_group(g: &Group) -> Option<&Group> {
        if (g.transform.a - 2.0).abs() < 1e-6 && (g.transform.e - 5.0).abs() < 1e-6 {
            return Some(g);
        }
        for c in &g.children {
            if let Node::Group(gg) = c {
                if let Some(found) = find_matrix_group(gg) {
                    return Some(found);
                }
            }
        }
        None
    }
    let mg = find_matrix_group(anchor).expect("/Matrix group in mask subtree");
    assert!(mg.clip.is_some(), "/BBox clip on the mask group");
    let mut mask_fills = Vec::new();
    collect_bare_fills(mg, &mut mask_fills);
    assert_eq!(mask_fills, vec![(255, 255, 255)], "white mask square");

    // The green fill painted after the Q is NOT masked.
    let mut bare = Vec::new();
    collect_bare_fills(root, &mut bare);
    assert!(
        bare.contains(&(0, 255, 0)),
        "post-bracket green fill paints unwrapped: {bare:?}"
    );
    assert!(
        !bare.contains(&(255, 0, 0)),
        "the red fill only exists inside the SoftMask wrap"
    );
}

#[test]
fn alpha_smask_maps_to_alpha_kind() {
    let pdf = build_smask_pdf("Alpha", None);
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let (_, kind, _) = find_soft_mask(root).expect("SoftMask node in scene");
    assert_eq!(kind, MaskKind::Alpha);
}

#[test]
fn smask_none_paints_unmasked() {
    let pdf = build_smask_pdf("Luminosity", Some("/None"));
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    assert!(
        find_soft_mask(root).is_none(),
        "/SMask /None never wraps anything"
    );
    let mut bare = Vec::new();
    collect_bare_fills(root, &mut bare);
    assert_eq!(bare, vec![(255, 0, 0), (0, 255, 0)], "both fills bare");
}

#[test]
fn bc_backdrop_pours_bbox_under_mask_content() {
    // /BC [0.5] on a /DeviceGray luminosity group — §11.6.5.2: the
    // group composites over a fully opaque backdrop of the /BC colour,
    // so the mask subtree's /Matrix group gains a first child: the
    // /BBox rectangle poured with 50 % gray, under the white square.
    let pdf = build_smask_pdf(
        "Luminosity",
        Some("<< /Type /Mask /S /Luminosity /G 5 0 R /BC [0.5] /TR /Identity >>"),
    );
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let (mask, kind, _) = find_soft_mask(root).expect("SoftMask node in scene");
    assert_eq!(kind, MaskKind::Luminance);
    let Node::Group(anchor) = mask else {
        panic!("mask anchor group");
    };
    let mut fills = Vec::new();
    collect_bare_fills(anchor, &mut fills);
    assert_eq!(
        fills,
        vec![(128, 128, 128), (255, 255, 255)],
        "backdrop first (under), group content second"
    );
}

#[test]
fn absent_bc_defaults_to_black_backdrop_without_rect() {
    // Default /BC is black (Table 144) — the unpainted mask area
    // already evaluates to zero luminosity, so no rectangle is
    // inserted and the mask subtree carries only the white square.
    let pdf = build_smask_pdf("Luminosity", None);
    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let (mask, _, _) = find_soft_mask(root).expect("SoftMask node in scene");
    let Node::Group(anchor) = mask else {
        panic!("mask anchor group");
    };
    let mut fills = Vec::new();
    collect_bare_fills(anchor, &mut fills);
    assert_eq!(fills, vec![(255, 255, 255)], "no backdrop rectangle");
}
