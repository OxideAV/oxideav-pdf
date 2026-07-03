//! Round-386 — writer-side annotation **appearance stream** generation
//! (ISO 32000-1 §12.5.5 "Appearance Streams").
//!
//! [`oxideav_pdf::write_pdf_with_annotations`] now emits a normal
//! (`/AP /N`) appearance stream — a form XObject whose `/BBox` is the
//! annotation `/Rect` — for every annotation kind whose visual is
//! fully determined by its dictionary geometry. This file exercises
//! the round-trip: writer-authored appearances resolve through the
//! reader's §12.5.5 appearance-paint path into the `Scene`, and the
//! `annotations()` walker reports the `/AP` summary.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    read_pdf_annotations, read_pdf_to_scene, write_pdf_with_annotations, Annotation,
    WriterAnnotationKind,
};
use oxideav_scene::{Page, Scene};

fn one_page_scene() -> Scene {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(190.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(190.0, 190.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 300.0,
        height: 300.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(0, 0, 0))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let mut page = Page::new(300.0, 300.0);
    page.content = frame;
    Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    }
}

fn annot(rect: [f32; 4], colour: Option<Vec<f32>>, kind: WriterAnnotationKind) -> Annotation {
    Annotation {
        source_page_index: 0,
        rect,
        author: None,
        modified: None,
        flags: None,
        colour,
        border: None,
        kind,
    }
}

/// Collect `(fill, stroke)` colour pairs of every `PathNode`,
/// depth-first.
type ColourPair = (Option<(u8, u8, u8)>, Option<(u8, u8, u8)>);
fn collect_paints(group: &Group, out: &mut Vec<ColourPair>) {
    for child in &group.children {
        match child {
            Node::Path(p) => {
                let fill = match &p.fill {
                    Some(Paint::Solid(c)) => Some((c.r, c.g, c.b)),
                    _ => None,
                };
                let stroke = match &p.stroke {
                    Some(s) => match &s.paint {
                        Paint::Solid(c) => Some((c.r, c.g, c.b)),
                        _ => None,
                    },
                    None => None,
                };
                out.push((fill, stroke));
            }
            Node::Group(g) => collect_paints(g, out),
            _ => {}
        }
    }
}

/// Collect every path's point list (flattened command endpoints) in
/// tree order.
fn collect_paths(group: &Group, out: &mut Vec<Vec<PathCommand>>) {
    for child in &group.children {
        match child {
            Node::Path(p) => out.push(p.path.commands.clone()),
            Node::Group(g) => collect_paths(g, out),
            _ => {}
        }
    }
}

#[test]
fn square_appearance_round_trips_into_scene() {
    let scene = one_page_scene();
    let annots = [annot(
        [100.0, 100.0, 160.0, 140.0],
        Some(vec![0.0, 0.0, 1.0]), // /C blue border
        WriterAnnotationKind::Square {
            interior_colour: Some(vec![1.0, 0.0, 0.0]), // /IC red
            line_width: Some(2.0),
        },
    )];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");

    // The reader surfaces the /AP summary…
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    let ap = anns[0].appearance.as_ref().expect("/AP emitted");
    assert!(ap.has_normal);

    // …and the §12.5.5 paint path lands the red-filled, blue-stroked
    // rectangle in the scene.
    let scene_back = read_pdf_to_scene(&pdf).expect("read back");
    let root = &scene_back.pages.as_ref().unwrap()[0].content.root;
    let mut paints = Vec::new();
    collect_paints(root, &mut paints);
    assert!(
        paints.contains(&(Some((255, 0, 0)), Some((0, 0, 255)))),
        "square appearance fill+stroke reach the scene: {paints:?}"
    );

    // §12.5.4 — the border is drawn completely inside /Rect: the `re`
    // rectangle is the rect inset by half the 2.0 line width.
    let mut paths = Vec::new();
    collect_paths(root, &mut paths);
    let has_inset_rect = paths.iter().any(|cmds| {
        cmds.iter().any(|c| match c {
            PathCommand::MoveTo(p) => (p.x - 101.0).abs() < 1e-3 && (p.y - 101.0).abs() < 1e-3,
            _ => false,
        })
    });
    assert!(has_inset_rect, "rect inset by w/2");
}

#[test]
fn circle_appearance_round_trips_into_scene() {
    let scene = one_page_scene();
    let annots = [annot(
        [50.0, 50.0, 150.0, 110.0],
        None, // /C absent → conventional black border
        WriterAnnotationKind::Circle {
            interior_colour: Some(vec![0.0, 1.0, 0.0]),
            line_width: Some(4.0),
        },
    )];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");

    let scene_back = read_pdf_to_scene(&pdf).expect("read back");
    let root = &scene_back.pages.as_ref().unwrap()[0].content.root;
    let mut paints = Vec::new();
    collect_paints(root, &mut paints);
    assert!(
        paints.contains(&(Some((0, 255, 0)), Some((0, 0, 0)))),
        "ellipse appearance fill+stroke reach the scene: {paints:?}"
    );

    // The ellipse is four cubic arcs starting at the right-most point
    // of the inset rect: rect [50 50 150 110] inset by 2 → centre
    // (100, 80), rx 48 → start (148, 80).
    let mut paths = Vec::new();
    collect_paths(root, &mut paths);
    let has_ellipse = paths.iter().any(|cmds| {
        let curves = cmds
            .iter()
            .filter(|c| matches!(c, PathCommand::CubicCurveTo { .. }))
            .count();
        curves == 4
            && cmds.iter().any(|c| match c {
                PathCommand::MoveTo(p) => (p.x - 148.0).abs() < 1e-3 && (p.y - 80.0).abs() < 1e-3,
                _ => false,
            })
    });
    assert!(has_ellipse, "four-arc ellipse in the scene");
}

#[test]
fn outline_only_and_fill_only_paint_modes() {
    let scene = one_page_scene();
    // Outline-only square (no /IC): stroke, no fill.
    let annots = [annot(
        [10.0, 10.0, 60.0, 60.0],
        Some(vec![1.0, 0.0, 0.0]),
        WriterAnnotationKind::Square {
            interior_colour: None,
            line_width: Some(1.0),
        },
    )];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let scene_back = read_pdf_to_scene(&pdf).expect("read back");
    let mut paints = Vec::new();
    collect_paints(
        &scene_back.pages.as_ref().unwrap()[0].content.root,
        &mut paints,
    );
    assert!(
        paints.contains(&(None, Some((255, 0, 0)))),
        "outline-only square: {paints:?}"
    );

    // Fill-only circle (zero-width border): fill, no stroke.
    let annots = [annot(
        [10.0, 10.0, 60.0, 60.0],
        None,
        WriterAnnotationKind::Circle {
            interior_colour: Some(vec![0.5]),
            line_width: Some(0.0),
        },
    )];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let scene_back = read_pdf_to_scene(&pdf).expect("read back");
    let mut paints = Vec::new();
    collect_paints(
        &scene_back.pages.as_ref().unwrap()[0].content.root,
        &mut paints,
    );
    assert!(
        paints.contains(&(Some((128, 128, 128)), None)),
        "fill-only circle: {paints:?}"
    );
}

/// One flat point list per scene path (MoveTo/LineTo endpoints only).
fn collect_polylines(group: &Group, out: &mut Vec<Vec<(f32, f32)>>) {
    let mut paths = Vec::new();
    collect_paths(group, &mut paths);
    for cmds in paths {
        let mut pts = Vec::new();
        for c in &cmds {
            match c {
                PathCommand::MoveTo(p) | PathCommand::LineTo(p) => pts.push((p.x, p.y)),
                _ => {}
            }
        }
        out.push(pts);
    }
}

#[test]
fn line_appearance_round_trips_into_scene() {
    let scene = one_page_scene();
    let annots = [annot(
        [10.0, 20.0, 110.0, 60.0],
        Some(vec![1.0, 0.0, 0.0]),
        WriterAnnotationKind::Line {
            endpoints: [10.0, 20.0, 110.0, 60.0],
            line_endings: None,
            interior_colour: None,
            leader_line: None,
            leader_line_extension: None,
            leader_line_offset: None,
            cap: false,
            intent: None,
        },
    )];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let scene_back = read_pdf_to_scene(&pdf).expect("read back");
    let root = &scene_back.pages.as_ref().unwrap()[0].content.root;
    let mut lines = Vec::new();
    collect_polylines(root, &mut lines);
    assert!(
        lines.contains(&vec![(10.0, 20.0), (110.0, 60.0)]),
        "/L endpoints stroked: {lines:?}"
    );
    let mut paints = Vec::new();
    collect_paints(root, &mut paints);
    assert!(paints.contains(&(None, Some((255, 0, 0)))));
}

#[test]
fn ink_appearance_round_trips_into_scene() {
    let scene = one_page_scene();
    let annots = [annot(
        [0.0, 0.0, 200.0, 200.0],
        None,
        WriterAnnotationKind::Ink {
            strokes: vec![
                vec![10.0, 10.0, 20.0, 30.0, 40.0, 25.0],
                vec![50.0, 50.0, 60.0, 60.0],
                vec![99.0, 99.0], // single point — nothing to stroke
            ],
        },
    )];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let scene_back = read_pdf_to_scene(&pdf).expect("read back");
    let root = &scene_back.pages.as_ref().unwrap()[0].content.root;
    let mut lines = Vec::new();
    collect_polylines(root, &mut lines);
    assert!(
        lines.contains(&vec![
            (10.0, 10.0),
            (20.0, 30.0),
            (40.0, 25.0),
            (50.0, 50.0),
            (60.0, 60.0)
        ]),
        "both ink strokes in one stroked path: {lines:?}"
    );
}

#[test]
fn polygon_and_polyline_appearances_round_trip() {
    let scene = one_page_scene();
    let annots = [
        annot(
            [0.0, 0.0, 100.0, 100.0],
            Some(vec![0.0, 0.0, 1.0]),
            WriterAnnotationKind::Polygon {
                vertices: vec![10.0, 10.0, 90.0, 10.0, 50.0, 90.0],
                interior_colour: Some(vec![1.0, 1.0, 0.0]),
                intent: None,
            },
        ),
        annot(
            [100.0, 100.0, 200.0, 200.0],
            Some(vec![0.0, 1.0, 0.0]),
            WriterAnnotationKind::PolyLine {
                vertices: vec![110.0, 110.0, 150.0, 190.0, 190.0, 110.0],
                line_endings: None,
                interior_colour: Some(vec![1.0, 0.0, 0.0]), // endings only — not drawn
                intent: None,
            },
        ),
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let scene_back = read_pdf_to_scene(&pdf).expect("read back");
    let root = &scene_back.pages.as_ref().unwrap()[0].content.root;

    let mut paints = Vec::new();
    collect_paints(root, &mut paints);
    assert!(
        paints.contains(&(Some((255, 255, 0)), Some((0, 0, 255)))),
        "polygon fills /IC and strokes /C: {paints:?}"
    );
    assert!(
        paints.contains(&(None, Some((0, 255, 0)))),
        "polyline strokes only (its /IC colours undrawn endings): {paints:?}"
    );

    // The polygon path closes; the polyline stays open.
    let mut paths = Vec::new();
    collect_paths(root, &mut paths);
    let polygon = paths
        .iter()
        .find(|cmds| {
            cmds.iter().any(
                |c| matches!(c, PathCommand::MoveTo(p) if (p.x - 10.0).abs() < 1e-3 && (p.y - 10.0).abs() < 1e-3),
            )
        })
        .expect("polygon path");
    assert!(polygon.iter().any(|c| matches!(c, PathCommand::Close)));
    let polyline = paths
        .iter()
        .find(|cmds| {
            cmds.iter()
                .any(|c| matches!(c, PathCommand::MoveTo(p) if (p.x - 110.0).abs() < 1e-3))
        })
        .expect("polyline path");
    assert!(!polyline.iter().any(|c| matches!(c, PathCommand::Close)));
}

#[test]
fn invisible_geometry_emits_no_appearance() {
    let scene = one_page_scene();
    // Transparent border (/C []) and no interior colour — nothing to
    // paint, so no /AP is emitted at all.
    let annots = [annot(
        [10.0, 10.0, 60.0, 60.0],
        Some(vec![]),
        WriterAnnotationKind::Square {
            interior_colour: None,
            line_width: Some(2.0),
        },
    )];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    assert!(anns[0].appearance.is_none(), "no /AP for empty paint");
}
