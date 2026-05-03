//! Linear-gradient fill → Pattern Type 2 / Function Type 2 stitching.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, GradientStop, Group, LinearGradient, Node, Paint, Path, PathNode, Point, Rgba,
    SpreadMethod, VectorFrame,
};

#[test]
fn linear_gradient_emits_pattern_type_2_function_type_2() {
    let mut p = Path::new();
    p.move_to(Point::new(0.0, 0.0))
        .line_to(Point::new(100.0, 0.0))
        .line_to(Point::new(100.0, 50.0))
        .line_to(Point::new(0.0, 50.0))
        .close();

    let gradient = LinearGradient {
        start: Point::new(0.0, 0.0),
        end: Point::new(100.0, 0.0),
        stops: vec![
            GradientStop::new(0.0, Rgba::opaque(255, 0, 0)),
            GradientStop::new(1.0, Rgba::opaque(0, 0, 255)),
        ],
        spread: SpreadMethod::Pad,
    };

    let frame = VectorFrame {
        width: 100.0,
        height: 50.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::LinearGradient(gradient)),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };

    let bytes = oxideav_pdf::write_pdf(&frame).unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();

    // Pattern resource registered.
    assert!(s.contains("/Pattern"), "expected /Pattern resource");
    assert!(
        s.contains("/PatternType 2"),
        "expected PatternType 2 (shading pattern)"
    );

    // Shading is type 2 (axial) for linear gradients.
    assert!(s.contains("/ShadingType 2"));

    // The two-stop function: one Type-2 segment + a Type-3 stitcher.
    // (Two stops collapse to a single function call but the writer
    // wraps it in a Type-3 stitch even with only one segment to keep
    // the multi-stop and two-stop paths uniform.)
    assert!(s.contains("/FunctionType 2"));
    assert!(s.contains("/FunctionType 3"));

    // The content stream should select the Pattern colour space and
    // then name the pattern resource.
    assert!(s.contains("/Pattern cs"));
    assert!(s.contains("/Pat0 scn"));

    // Even-odd vs non-zero fill rule round-trip — gradient fill
    // defaults to non-zero -> `f`.
    assert!(s.contains("\nf\n"));
}
