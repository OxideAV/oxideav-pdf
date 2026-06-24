//! Round-369 gradient round-trip: a `Paint::LinearGradient` /
//! `Paint::RadialGradient` fill survives `write_pdf` → `read_pdf_to_scene`.
//!
//! The writer emits a gradient fill as a `/PatternType 2` shading
//! pattern (Pattern Type 2 + Function Type 2 / Type 3, §8.7.3.3 +
//! §8.7.4.5). As of this round the reader resolves a `scn` shading-
//! pattern fill back into a scene gradient `Paint`, so a gradient fill
//! now makes the full round trip instead of degrading to black on read.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, GradientStop, Group, LinearGradient, Node, Paint, Path, PathNode, Point,
    RadialGradient, Rgba, SpreadMethod, VectorFrame,
};
use oxideav_pdf::{read_pdf_to_scene, write_pdf};

fn square_path() -> Path {
    let mut p = Path::new();
    p.move_to(Point::new(0.0, 0.0))
        .line_to(Point::new(100.0, 0.0))
        .line_to(Point::new(100.0, 80.0))
        .line_to(Point::new(0.0, 80.0))
        .close();
    p
}

fn frame_with_fill(fill: Paint) -> VectorFrame {
    VectorFrame {
        width: 100.0,
        height: 80.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: square_path(),
                fill: Some(fill),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    }
}

/// Find the first painted path's fill anywhere in the scene tree.
fn first_fill(node: &Node) -> Option<&Paint> {
    match node {
        Node::Path(p) => p.fill.as_ref(),
        Node::Group(g) => g.children.iter().find_map(first_fill),
        _ => None,
    }
}

#[test]
fn linear_gradient_survives_write_then_read() {
    let gradient = LinearGradient {
        start: Point::new(0.0, 0.0),
        end: Point::new(100.0, 0.0),
        stops: vec![
            GradientStop::new(0.0, Rgba::opaque(255, 0, 0)),
            GradientStop::new(1.0, Rgba::opaque(0, 0, 255)),
        ],
        spread: SpreadMethod::Pad,
    };
    let pdf = write_pdf(&frame_with_fill(Paint::LinearGradient(gradient))).expect("write");
    let scene = read_pdf_to_scene(&pdf).expect("read");
    let pages = scene.pages.as_ref().expect("pages");

    let fill = pages[0]
        .content
        .root
        .children
        .iter()
        .find_map(first_fill)
        .expect("a fill");
    let Paint::LinearGradient(lg) = fill else {
        panic!("expected a linear gradient after round-trip, got {fill:?}");
    };
    // Axis endpoints survive (PDF default user space matches the frame
    // here, so coords pass through up to the page-height Y flip).
    assert!(
        (lg.start.x - 0.0).abs() < 1.0 && (lg.end.x - 100.0).abs() < 1.0,
        "axis x endpoints: {:?} → {:?}",
        lg.start,
        lg.end
    );
    assert!(!lg.stops.is_empty());
    // First stop ≈ red, last ≈ blue (allowing sampling quantisation).
    let f = &lg.stops[0].color;
    let l = &lg.stops.last().unwrap().color;
    assert!(f.r > 200 && f.b < 60, "first stop red-ish: {f:?}");
    assert!(l.b > 200 && l.r < 60, "last stop blue-ish: {l:?}");
}

#[test]
fn radial_gradient_survives_write_then_read() {
    let gradient = RadialGradient {
        center: Point::new(50.0, 40.0),
        radius: 40.0,
        focal: None,
        stops: vec![
            GradientStop::new(0.0, Rgba::opaque(0, 255, 0)),
            GradientStop::new(1.0, Rgba::opaque(0, 0, 0)),
        ],
        spread: SpreadMethod::Pad,
    };
    let pdf = write_pdf(&frame_with_fill(Paint::RadialGradient(gradient))).expect("write");
    let scene = read_pdf_to_scene(&pdf).expect("read");
    let pages = scene.pages.as_ref().expect("pages");

    let fill = pages[0]
        .content
        .root
        .children
        .iter()
        .find_map(first_fill)
        .expect("a fill");
    let Paint::RadialGradient(rg) = fill else {
        panic!("expected a radial gradient after round-trip, got {fill:?}");
    };
    assert!((rg.radius - 40.0).abs() < 1.0, "radius: {}", rg.radius);
    assert!(!rg.stops.is_empty());
    let f = &rg.stops[0].color;
    assert!(f.g > 200 && f.r < 60, "first stop green-ish: {f:?}");
}
