//! Group opacity → ExtGState `/ca` + `/CA` round-trip.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathNode, Point, Rgba, VectorFrame,
};

#[test]
fn group_opacity_emits_extgstate_ca_and_capital_ca() {
    let mut p = Path::new();
    p.move_to(Point::new(10.0, 10.0))
        .line_to(Point::new(40.0, 10.0))
        .line_to(Point::new(40.0, 40.0))
        .line_to(Point::new(10.0, 40.0))
        .close();

    let frame = VectorFrame {
        width: 50.0,
        height: 50.0,
        view_box: None,
        root: Group {
            opacity: 0.5,
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(0, 128, 255))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };

    let bytes = oxideav_pdf::write_pdf(&frame).unwrap();
    // The PDF binary marker (`%\xE2\xE3\xCF\xD3`) sits in the header
    // and is not valid UTF-8 — use lossy conversion since we only
    // need to scan for ASCII operator strings.
    let s = String::from_utf8_lossy(&bytes);

    // ExtGState resource present + named GS0.
    assert!(s.contains("/ExtGState"));
    assert!(s.contains("/GS0"));

    // The state itself carries `/ca 0.5` (fill alpha) and `/CA 0.5`
    // (stroke alpha).
    assert!(s.contains("/ca 0.5"), "expected /ca 0.5 in ExtGState dict");
    assert!(s.contains("/CA 0.5"), "expected /CA 0.5 in ExtGState dict");

    // The content stream activates that state via `/GS0 gs`.
    assert!(s.contains("/GS0 gs"), "expected /GS0 gs in content stream");
}

#[test]
fn fully_opaque_group_emits_no_extgstate() {
    let frame = VectorFrame {
        width: 10.0,
        height: 10.0,
        view_box: None,
        root: Group {
            opacity: 1.0,
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let bytes = oxideav_pdf::write_pdf(&frame).unwrap();
    let s = String::from_utf8_lossy(&bytes);
    // No `/ExtGState` resource entry should be added when no group
    // needed alpha.
    assert!(!s.contains("/ExtGState"));
}
