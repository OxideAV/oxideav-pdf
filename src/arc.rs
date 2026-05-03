//! SVG elliptic-arc to cubic-Bezier flattening.
//!
//! Round-1 only need is to convert each [`PathCommand::ArcTo`] into a
//! sequence of `(c1, c2, end)` cubic segments so the operator emitter
//! can keep its dispatch trivial. The math follows SVG 1.1 Appendix
//! F.6.5 (endpoint→centre conversion) plus the well-known
//! quarter-circle cubic approximation `k = 4 * (sqrt(2) - 1) / 3` —
//! standard PDF / Postscript trick.

#[cfg(test)]
use oxideav_core::vector::PathCommand;
use oxideav_core::vector::Point;

/// Flatten one SVG elliptic arc segment from `start` to `end` into a
/// list of cubic segments. The emitter calls this once per
/// [`PathCommand::ArcTo`].
///
/// Returns `Vec<(c1, c2, end)>` ready for `emit_cubic`. An empty
/// result means the arc collapsed to a point (degenerate); the caller
/// should skip emitting anything in that case.
#[allow(clippy::too_many_arguments)]
pub fn svg_arc_to_cubics(
    start: Point,
    end: Point,
    rx_in: f32,
    ry_in: f32,
    x_axis_rot: f32,
    large_arc: bool,
    sweep: bool,
) -> Vec<(Point, Point, Point)> {
    // --- F.6.2 step 1: out-of-range radii / coincident endpoints ----
    if (start.x - end.x).abs() < 1e-6 && (start.y - end.y).abs() < 1e-6 {
        return Vec::new();
    }
    let mut rx = rx_in.abs();
    let mut ry = ry_in.abs();
    if rx < 1e-6 || ry < 1e-6 {
        // Degenerate radius — SVG says fall back to a straight line,
        // but the path emitter handles that by treating an empty
        // cubic list as a line via the next emission path. Keep the
        // shape simple: emit a single cubic with both control points
        // on the line segment.
        let third = Point::new(
            start.x + (end.x - start.x) / 3.0,
            start.y + (end.y - start.y) / 3.0,
        );
        let two_thirds = Point::new(
            start.x + 2.0 * (end.x - start.x) / 3.0,
            start.y + 2.0 * (end.y - start.y) / 3.0,
        );
        return vec![(third, two_thirds, end)];
    }

    let phi = x_axis_rot;
    let (sin_phi, cos_phi) = phi.sin_cos();

    // --- F.6.5 step 1: compute (x1', y1') (mid-frame coords) -------
    let dx = (start.x - end.x) / 2.0;
    let dy = (start.y - end.y) / 2.0;
    let x1p = cos_phi * dx + sin_phi * dy;
    let y1p = -sin_phi * dx + cos_phi * dy;

    // --- F.6.6 ensure radii large enough --------------------------
    let lambda = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry);
    if lambda > 1.0 {
        let s = lambda.sqrt();
        rx *= s;
        ry *= s;
    }

    // --- F.6.5 step 2: compute (cx', cy') --------------------------
    let rx_sq = rx * rx;
    let ry_sq = ry * ry;
    let x1p_sq = x1p * x1p;
    let y1p_sq = y1p * y1p;
    let mut numer = rx_sq * ry_sq - rx_sq * y1p_sq - ry_sq * x1p_sq;
    if numer < 0.0 {
        numer = 0.0;
    }
    let denom = rx_sq * y1p_sq + ry_sq * x1p_sq;
    let factor = if denom == 0.0 {
        0.0
    } else {
        (numer / denom).sqrt()
    };
    let sign = if large_arc == sweep { -1.0 } else { 1.0 };
    let cxp = sign * factor * (rx * y1p / ry);
    let cyp = sign * factor * -(ry * x1p / rx);

    // --- F.6.5 step 3: (cx, cy) in original frame ------------------
    let cx = cos_phi * cxp - sin_phi * cyp + (start.x + end.x) / 2.0;
    let cy = sin_phi * cxp + cos_phi * cyp + (start.y + end.y) / 2.0;

    // --- F.6.5 step 4: theta_1 + delta_theta -----------------------
    let ux = (x1p - cxp) / rx;
    let uy = (y1p - cyp) / ry;
    let vx = (-x1p - cxp) / rx;
    let vy = (-y1p - cyp) / ry;
    let theta_1 = angle((1.0, 0.0), (ux, uy));
    let mut delta_theta = angle((ux, uy), (vx, vy));
    if !sweep && delta_theta > 0.0 {
        delta_theta -= std::f32::consts::TAU;
    } else if sweep && delta_theta < 0.0 {
        delta_theta += std::f32::consts::TAU;
    }

    // --- Subdivide the parameter range into ≤90° quarters ---------
    let n_segments = (delta_theta.abs() / (std::f32::consts::PI / 2.0))
        .ceil()
        .max(1.0) as usize;
    let dtheta = delta_theta / n_segments as f32;
    // Cubic-bezier control distance for an arc of subtended angle
    // `dtheta` on the unit circle: `(4/3) * tan(dtheta / 4)`.
    let t = (4.0 / 3.0) * (dtheta / 4.0).tan();

    let mut out = Vec::with_capacity(n_segments);
    let mut theta = theta_1;
    let mut prev = unit_to_world(theta, cx, cy, rx, ry, sin_phi, cos_phi);
    for _ in 0..n_segments {
        let next_theta = theta + dtheta;
        let next = unit_to_world(next_theta, cx, cy, rx, ry, sin_phi, cos_phi);

        // Tangents at theta and next_theta on the unit ellipse, then
        // mapped back into world coordinates.
        let (sin_t, cos_t) = theta.sin_cos();
        let (sin_n, cos_n) = next_theta.sin_cos();

        let tan1 = unit_tangent_to_world(-sin_t, cos_t, rx, ry, sin_phi, cos_phi);
        let tan2 = unit_tangent_to_world(-sin_n, cos_n, rx, ry, sin_phi, cos_phi);

        let c1 = Point::new(prev.x + t * tan1.x, prev.y + t * tan1.y);
        let c2 = Point::new(next.x - t * tan2.x, next.y - t * tan2.y);
        let endp = if next_theta == theta_1 + delta_theta {
            // Snap final point exactly to the requested endpoint to
            // avoid sub-pixel drift accumulating across quarters.
            end
        } else {
            next
        };
        out.push((c1, c2, endp));
        prev = next;
        theta = next_theta;
    }
    // Snap the final segment's endpoint to the SVG-requested `end`.
    if let Some(last) = out.last_mut() {
        last.2 = end;
    }
    out
}

fn angle(u: (f32, f32), v: (f32, f32)) -> f32 {
    let dot = u.0 * v.0 + u.1 * v.1;
    let len = ((u.0 * u.0 + u.1 * u.1) * (v.0 * v.0 + v.1 * v.1)).sqrt();
    let cos = (dot / len).clamp(-1.0, 1.0);
    let sign = if u.0 * v.1 - u.1 * v.0 < 0.0 {
        -1.0
    } else {
        1.0
    };
    sign * cos.acos()
}

fn unit_to_world(
    theta: f32,
    cx: f32,
    cy: f32,
    rx: f32,
    ry: f32,
    sin_phi: f32,
    cos_phi: f32,
) -> Point {
    let (sin_t, cos_t) = theta.sin_cos();
    let x = rx * cos_t;
    let y = ry * sin_t;
    Point::new(
        cos_phi * x - sin_phi * y + cx,
        sin_phi * x + cos_phi * y + cy,
    )
}

fn unit_tangent_to_world(dx: f32, dy: f32, rx: f32, ry: f32, sin_phi: f32, cos_phi: f32) -> Point {
    let x = rx * dx;
    let y = ry * dy;
    Point::new(cos_phi * x - sin_phi * y, sin_phi * x + cos_phi * y)
}

/// Convenience used by tests: count how many cubic segments would be
/// produced by flattening `cmd` (zero for non-arc commands).
#[cfg(test)]
pub(crate) fn arc_cubic_count(cmd: PathCommand, current: Point) -> usize {
    match cmd {
        PathCommand::ArcTo {
            rx,
            ry,
            x_axis_rot,
            large_arc,
            sweep,
            end,
        } => svg_arc_to_cubics(current, end, rx, ry, x_axis_rot, large_arc, sweep).len(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coincident_endpoints_emit_nothing() {
        let segs = svg_arc_to_cubics(
            Point::new(10.0, 10.0),
            Point::new(10.0, 10.0),
            5.0,
            5.0,
            0.0,
            false,
            true,
        );
        assert!(segs.is_empty());
    }

    #[test]
    fn quarter_circle_emits_one_cubic() {
        // Quarter of a unit circle from (1,0) to (0,1), small arc.
        let segs = svg_arc_to_cubics(
            Point::new(1.0, 0.0),
            Point::new(0.0, 1.0),
            1.0,
            1.0,
            0.0,
            false,
            true,
        );
        assert_eq!(segs.len(), 1);
    }

    #[test]
    fn full_circle_via_two_180_arcs() {
        // SVG can't express a full circle in a single A command (start
        // == end is degenerate), but two large_arc segments give one.
        let half1 = svg_arc_to_cubics(
            Point::new(1.0, 0.0),
            Point::new(-1.0, 0.0),
            1.0,
            1.0,
            0.0,
            false,
            true,
        );
        let half2 = svg_arc_to_cubics(
            Point::new(-1.0, 0.0),
            Point::new(1.0, 0.0),
            1.0,
            1.0,
            0.0,
            false,
            true,
        );
        // Each half-circle should produce 2 quarter cubics.
        assert_eq!(half1.len(), 2);
        assert_eq!(half2.len(), 2);
    }

    #[test]
    fn endpoint_is_snapped_to_request() {
        let target = Point::new(7.0, -3.0);
        let segs = svg_arc_to_cubics(Point::new(0.0, 0.0), target, 10.0, 10.0, 0.5, false, true);
        let last = segs.last().unwrap();
        assert!((last.2.x - target.x).abs() < 1e-4);
        assert!((last.2.y - target.y).abs() < 1e-4);
    }

    #[test]
    fn arc_count_helper_matches_segment_count() {
        let cmd = PathCommand::ArcTo {
            rx: 1.0,
            ry: 1.0,
            x_axis_rot: 0.0,
            large_arc: false,
            sweep: true,
            end: Point::new(0.0, 1.0),
        };
        assert_eq!(arc_cubic_count(cmd, Point::new(1.0, 0.0)), 1);
    }
}
