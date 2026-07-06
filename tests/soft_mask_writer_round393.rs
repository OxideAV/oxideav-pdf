//! Round-393 writer-side soft-mask tests (ISO 32000-1 §11.6.4.3 +
//! §11.6.5.2 + §11.6.6).
//!
//! `write_pdf` now emits a `Node::SoftMask` composite as a real PDF
//! soft mask: the mask subtree becomes a `/G` transparency-group form
//! XObject (with its own `/Resources` and a `/BBox` covering its
//! geometry), an `/ExtGState` entry carries the `/SMask` soft-mask
//! dictionary (`/S /Luminosity` for `MaskKind::Luminance`, `/S /Alpha`
//! for `MaskKind::Alpha`), and the content paints inside a `q /GSn gs
//! … Q` bracket. Because the reader grew the matching §11.6.5.2 paint
//! path this round, the writer's output round-trips: `write_pdf` →
//! `read_pdf_to_scene` reproduces a `Node::SoftMask` with the same
//! kind, mask geometry, and content.

use oxideav_core::vector::{
    FillRule, Group, MaskKind, Node, Paint, Path, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_core::TimeBase;
use oxideav_pdf::{read_pdf_to_scene, write_pdf};

fn rect_path(x0: f32, y0: f32, x1: f32, y1: f32) -> Path {
    let mut p = Path::new();
    p.move_to(Point::new(x0, y0))
        .line_to(Point::new(x1, y0))
        .line_to(Point::new(x1, y1))
        .line_to(Point::new(x0, y1))
        .close();
    p
}

fn filled_rect(x0: f32, y0: f32, x1: f32, y1: f32, color: Rgba) -> Node {
    Node::Path(PathNode {
        path: rect_path(x0, y0, x1, y1),
        fill: Some(Paint::Solid(color)),
        stroke: None,
        fill_rule: FillRule::NonZero,
    })
}

fn soft_mask_frame(kind: MaskKind) -> VectorFrame {
    // Mask: a white square over 20..60; content: a red square 10..80.
    let node = Node::SoftMask {
        mask: Box::new(filled_rect(
            20.0,
            20.0,
            60.0,
            60.0,
            Rgba::opaque(255, 255, 255),
        )),
        mask_kind: kind,
        content: Box::new(filled_rect(10.0, 10.0, 80.0, 80.0, Rgba::opaque(255, 0, 0))),
    };
    VectorFrame {
        width: 100.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![node],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    }
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

fn collect_fills(node: &Node, out: &mut Vec<(u8, u8, u8)>) {
    match node {
        Node::Path(p) => {
            if let Some(Paint::Solid(c)) = &p.fill {
                out.push((c.r, c.g, c.b));
            }
        }
        Node::Group(g) => {
            for c in &g.children {
                collect_fills(c, out);
            }
        }
        Node::SoftMask { content, .. } => collect_fills(content, out),
        _ => {}
    }
}

#[test]
fn writer_emits_smask_ext_gstate_and_group_xobject() {
    let pdf = write_pdf(&soft_mask_frame(MaskKind::Luminance)).expect("write");
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/SMask"), "SMask entry emitted");
    assert!(s.contains("/S /Luminosity"), "luminosity subtype");
    assert!(
        s.contains("/S /Transparency"),
        "the /G form is a transparency group (§11.6.6)"
    );
    assert!(s.contains("/Mask"), "/Type /Mask soft-mask dictionary");
}

#[test]
fn luminance_soft_mask_round_trips() {
    let pdf = write_pdf(&soft_mask_frame(MaskKind::Luminance)).expect("write");
    let scene = read_pdf_to_scene(&pdf).expect("read back");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let (mask, kind, content) = find_soft_mask(root).expect("SoftMask survives the round trip");
    assert_eq!(kind, MaskKind::Luminance);

    let mut content_fills = Vec::new();
    collect_fills(content, &mut content_fills);
    assert_eq!(content_fills, vec![(255, 0, 0)], "red content");

    let mut mask_fills = Vec::new();
    collect_fills(mask, &mut mask_fills);
    assert_eq!(mask_fills, vec![(255, 255, 255)], "white mask square");
}

#[test]
fn alpha_soft_mask_round_trips() {
    let pdf = write_pdf(&soft_mask_frame(MaskKind::Alpha)).expect("write");
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/S /Alpha"), "alpha subtype emitted");

    let scene = read_pdf_to_scene(&pdf).expect("read back");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let (_, kind, _) = find_soft_mask(root).expect("SoftMask survives");
    assert_eq!(kind, MaskKind::Alpha);
}

#[test]
fn empty_mask_subtree_emits_nothing() {
    // A mask with nothing renderable hides its content entirely
    // (luminosity 0 over the default black backdrop) — the writer
    // emits neither the gs nor the content.
    let node = Node::SoftMask {
        mask: Box::new(Node::Group(Group::default())),
        mask_kind: MaskKind::Luminance,
        content: Box::new(filled_rect(10.0, 10.0, 80.0, 80.0, Rgba::opaque(255, 0, 0))),
    };
    let frame = VectorFrame {
        width: 100.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![node],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let pdf = write_pdf(&frame).expect("write");
    let s = String::from_utf8_lossy(&pdf);
    assert!(!s.contains("/SMask"), "no SMask");

    let scene = read_pdf_to_scene(&pdf).expect("read back");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    let mut fills = Vec::new();
    for c in &root.children {
        collect_fills(c, &mut fills);
    }
    assert!(fills.is_empty(), "fully-masked content is not painted");
}

/// Black-box validation: `qpdf --check` accepts the soft-mask output.
/// Skips silently when qpdf isn't on PATH (mirrors
/// `external_validation.rs`).
#[test]
fn qpdf_check_accepts_soft_mask_output() {
    use std::process::Command;
    let have_qpdf = Command::new("qpdf")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !have_qpdf {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    let pdf = write_pdf(&soft_mask_frame(MaskKind::Luminance)).expect("write");
    let mut path = std::env::temp_dir();
    path.push(format!(
        "oxideav-pdf-smask-{}-{}.pdf",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&path, &pdf).expect("temp pdf write");
    let out = Command::new("qpdf")
        .arg("--check")
        .arg(&path)
        .output()
        .expect("run qpdf");
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "qpdf --check rejected the soft-mask PDF:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
