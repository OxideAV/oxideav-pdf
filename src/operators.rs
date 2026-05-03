//! PDF content-stream operator emitter (ISO 32000-1 §8.5).
//!
//! All operators are written as ASCII text into a [`OpBuf`] (a thin
//! wrapper over `Vec<u8>` that handles the formatting nuances).
//! Numerics use the same compact "trim trailing zeros" form as the
//! object serializer (`objects::format_real` shares the policy).
//!
//! The full PDF operator surface is enormous; round 1 only emits the
//! intersection of "operators implied by the imaging-model mapping in
//! the workspace task description" and "operators we have a sane
//! mapping for from `oxideav_core::vector`". Anything outside that is
//! a future round's problem.

use crate::resources::ResourceCollector;
use oxideav_core::vector::{
    DashPattern, FillRule, LineCap, LineJoin, Paint, Path, PathCommand, Point, Rgba, Stroke,
    Transform2D,
};

/// Append-only byte buffer for an in-progress content stream. Wraps a
/// raw `Vec<u8>` so the operator helpers can stay infallible (no
/// I/O — every byte goes into RAM).
pub struct OpBuf {
    bytes: Vec<u8>,
}

impl OpBuf {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn write(&mut self, s: &[u8]) {
        self.bytes.extend_from_slice(s);
    }

    fn space(&mut self) {
        self.bytes.push(b' ');
    }

    fn newline(&mut self) {
        self.bytes.push(b'\n');
    }

    fn write_real(&mut self, f: f32) {
        self.write(format_real(f as f64).as_bytes());
    }

    /// Append an already-formatted byte sequence verbatim. Escape
    /// hatch for one-off operators (`/Imx Do`, etc.) that don't have
    /// a dedicated helper.
    pub fn append_raw(&mut self, bytes: &[u8]) {
        self.write(bytes);
    }
}

impl Default for OpBuf {
    fn default() -> Self {
        Self::new()
    }
}

// ───────────────────────── graphics state ─────────────────────────

/// `q` — push graphics state.
pub fn save(op: &mut OpBuf) {
    op.write(b"q");
    op.newline();
}

/// `Q` — pop graphics state.
pub fn restore(op: &mut OpBuf) {
    op.write(b"Q");
    op.newline();
}

/// `cm` — concat matrix to the CTM. Skipped when `t` is the identity
/// (PDF behaviour is unchanged in that case but the byte savings add
/// up across deep group trees).
pub fn concat_matrix(op: &mut OpBuf, t: &Transform2D) {
    if t.is_identity() {
        return;
    }
    op.write_real(t.a);
    op.space();
    op.write_real(t.b);
    op.space();
    op.write_real(t.c);
    op.space();
    op.write_real(t.d);
    op.space();
    op.write_real(t.e);
    op.space();
    op.write_real(t.f);
    op.space();
    op.write(b"cm");
    op.newline();
}

/// `/Name gs` — set graphic state from named ExtGState resource.
pub fn set_ext_gstate(op: &mut OpBuf, name: &str) {
    op.write(b"/");
    op.write(name.as_bytes());
    op.space();
    op.write(b"gs");
    op.newline();
}

// ───────────────────────── path construction ─────────────────────

/// Emit one [`Path`] as a sequence of `m / l / c / h` operators.
///
/// `QuadCurveTo` is lifted to cubic via the standard
/// `c1 = start + 2/3*(control - start)` /
/// `c2 = end   + 2/3*(control - end)` formula — PDF has no native
/// quadratic.
///
/// `ArcTo` is flattened to one or more cubic segments per SVG 1.1
/// Appendix F.6.5; the implementation lives in [`crate::arc`].
///
/// The function tracks the "current point" so quadratic / arc
/// segments can compute their start point correctly. Paths that begin
/// without an explicit `MoveTo` are emitted relative to (0, 0) — same
/// behaviour as PDF's path-construction rule for an undefined current
/// point.
pub fn emit_path(op: &mut OpBuf, path: &Path) {
    let mut current = Point::default();
    let mut subpath_start = Point::default();
    for cmd in &path.commands {
        match *cmd {
            PathCommand::MoveTo(p) => {
                op.write_real(p.x);
                op.space();
                op.write_real(p.y);
                op.space();
                op.write(b"m");
                op.newline();
                current = p;
                subpath_start = p;
            }
            PathCommand::LineTo(p) => {
                op.write_real(p.x);
                op.space();
                op.write_real(p.y);
                op.space();
                op.write(b"l");
                op.newline();
                current = p;
            }
            PathCommand::CubicCurveTo { c1, c2, end } => {
                emit_cubic(op, c1, c2, end);
                current = end;
            }
            PathCommand::QuadCurveTo { control, end } => {
                let c1 = Point::new(
                    current.x + (2.0 / 3.0) * (control.x - current.x),
                    current.y + (2.0 / 3.0) * (control.y - current.y),
                );
                let c2 = Point::new(
                    end.x + (2.0 / 3.0) * (control.x - end.x),
                    end.y + (2.0 / 3.0) * (control.y - end.y),
                );
                emit_cubic(op, c1, c2, end);
                current = end;
            }
            PathCommand::ArcTo {
                rx,
                ry,
                x_axis_rot,
                large_arc,
                sweep,
                end,
            } => {
                for (c1, c2, e) in crate::arc::svg_arc_to_cubics(
                    current, end, rx, ry, x_axis_rot, large_arc, sweep,
                ) {
                    emit_cubic(op, c1, c2, e);
                }
                current = end;
            }
            PathCommand::Close => {
                op.write(b"h");
                op.newline();
                current = subpath_start;
            }
        }
    }
}

fn emit_cubic(op: &mut OpBuf, c1: Point, c2: Point, end: Point) {
    op.write_real(c1.x);
    op.space();
    op.write_real(c1.y);
    op.space();
    op.write_real(c2.x);
    op.space();
    op.write_real(c2.y);
    op.space();
    op.write_real(end.x);
    op.space();
    op.write_real(end.y);
    op.space();
    op.write(b"c");
    op.newline();
}

// ───────────────────────── path painting ─────────────────────────

/// Emit `f` / `f*` / `B` / `B*` / `S` / `n` per `(has_fill, has_stroke,
/// fill_rule)`. `n` is "no-op paint" — used after `W`/`W*` to consume
/// the current path as a clip without painting it.
pub enum PaintMode {
    Fill,
    Stroke,
    FillStroke,
    None,
}

pub fn paint(op: &mut OpBuf, mode: PaintMode, fill_rule: FillRule) {
    let bytes: &[u8] = match (mode, fill_rule) {
        (PaintMode::Fill, FillRule::NonZero) => b"f",
        (PaintMode::Fill, FillRule::EvenOdd) => b"f*",
        (PaintMode::Stroke, _) => b"S",
        (PaintMode::FillStroke, FillRule::NonZero) => b"B",
        (PaintMode::FillStroke, FillRule::EvenOdd) => b"B*",
        (PaintMode::None, _) => b"n",
    };
    op.write(bytes);
    op.newline();
}

/// Emit `W` (or `W*`) followed by `n` so the just-constructed path
/// becomes the new clip without itself being painted.
pub fn emit_clip_marker(op: &mut OpBuf, fill_rule: FillRule) {
    match fill_rule {
        FillRule::NonZero => op.write(b"W"),
        FillRule::EvenOdd => op.write(b"W*"),
    }
    op.newline();
    paint(op, PaintMode::None, fill_rule);
}

// ───────────────────────── colour / paint ─────────────────────────

/// Emit colour-setting operators for the given fill paint. For
/// gradients this requires registering a Pattern resource via the
/// [`ResourceCollector`] and emitting `/Pat<n> scn` instead of
/// `r g b sc`.
pub fn set_fill_paint(op: &mut OpBuf, paint: &Paint, resources: &mut ResourceCollector) {
    match paint {
        Paint::Solid(rgba) => {
            emit_rgb(op, *rgba, /* stroke = */ false);
        }
        Paint::LinearGradient(g) => {
            let name = resources.add_linear_gradient(g);
            emit_pattern(op, &name, /* stroke = */ false);
        }
        Paint::RadialGradient(g) => {
            let name = resources.add_radial_gradient(g);
            emit_pattern(op, &name, /* stroke = */ false);
        }
    }
}

/// Same as [`set_fill_paint`] but for the stroke colour.
pub fn set_stroke_paint(op: &mut OpBuf, paint: &Paint, resources: &mut ResourceCollector) {
    match paint {
        Paint::Solid(rgba) => {
            emit_rgb(op, *rgba, /* stroke = */ true);
        }
        Paint::LinearGradient(g) => {
            let name = resources.add_linear_gradient(g);
            emit_pattern(op, &name, /* stroke = */ true);
        }
        Paint::RadialGradient(g) => {
            let name = resources.add_radial_gradient(g);
            emit_pattern(op, &name, /* stroke = */ true);
        }
    }
}

fn emit_rgb(op: &mut OpBuf, rgba: Rgba, stroke: bool) {
    let r = rgba.r as f32 / 255.0;
    let g = rgba.g as f32 / 255.0;
    let b = rgba.b as f32 / 255.0;
    op.write_real(r);
    op.space();
    op.write_real(g);
    op.space();
    op.write_real(b);
    op.space();
    op.write(if stroke { b"RG" } else { b"rg" });
    op.newline();
}

fn emit_pattern(op: &mut OpBuf, name: &str, stroke: bool) {
    // PDF Reference §8.6.8: to paint with a pattern in DeviceRGB, set
    // the colour space to `/Pattern` (CS / cs) then name the pattern
    // resource via SCN / scn. The Pattern colour space carries no
    // base — uncoloured patterns aren't used here, gradients are
    // shading patterns which are always coloured.
    op.write(if stroke {
        b"/Pattern CS"
    } else {
        b"/Pattern cs"
    });
    op.newline();
    op.write(b"/");
    op.write(name.as_bytes());
    op.space();
    op.write(if stroke { b"SCN" } else { b"scn" });
    op.newline();
}

// ───────────────────────── stroke style ─────────────────────────

/// Emit the `w / J / j / M / d` operators implied by `stroke`, then the
/// stroke colour.
pub fn set_stroke_style(op: &mut OpBuf, stroke: &Stroke, resources: &mut ResourceCollector) {
    op.write_real(stroke.width);
    op.space();
    op.write(b"w");
    op.newline();

    let cap = match stroke.cap {
        LineCap::Butt => 0,
        LineCap::Round => 1,
        LineCap::Square => 2,
    };
    op.write(format!("{} J", cap).as_bytes());
    op.newline();

    let join = match stroke.join {
        LineJoin::Miter => 0,
        LineJoin::Round => 1,
        LineJoin::Bevel => 2,
    };
    op.write(format!("{} j", join).as_bytes());
    op.newline();

    op.write_real(stroke.miter_limit);
    op.space();
    op.write(b"M");
    op.newline();

    if let Some(dash) = &stroke.dash {
        emit_dash(op, dash);
    } else {
        // Solid stroke — clear any inherited dash pattern.
        op.write(b"[] 0 d");
        op.newline();
    }

    set_stroke_paint(op, &stroke.paint, resources);
}

fn emit_dash(op: &mut OpBuf, dash: &DashPattern) {
    op.write(b"[");
    for (i, seg) in dash.array.iter().enumerate() {
        if i > 0 {
            op.space();
        }
        op.write_real(*seg);
    }
    op.write(b"] ");
    op.write_real(dash.offset);
    op.space();
    op.write(b"d");
    op.newline();
}

// ───────────────────────── shared formatting ─────────────────────

/// Reused by [`crate::resources`] for gradient function-table values.
pub fn format_real(f: f64) -> String {
    if !f.is_finite() {
        return "0".to_string();
    }
    if f.fract() == 0.0 && f.abs() < 1e16 {
        return format!("{}", f as i64);
    }
    let s = format!("{:.6}", f);
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "-" {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxideav_core::vector::PathNode;

    #[test]
    fn save_restore_produce_q_capital_q() {
        let mut op = OpBuf::new();
        save(&mut op);
        restore(&mut op);
        assert_eq!(op.into_bytes(), b"q\nQ\n");
    }

    #[test]
    fn identity_matrix_emits_nothing() {
        let mut op = OpBuf::new();
        concat_matrix(&mut op, &Transform2D::identity());
        assert!(op.as_bytes().is_empty());
    }

    #[test]
    fn translate_matrix_emits_cm() {
        let mut op = OpBuf::new();
        concat_matrix(&mut op, &Transform2D::translate(5.0, 10.0));
        assert_eq!(op.into_bytes(), b"1 0 0 1 5 10 cm\n");
    }

    #[test]
    fn rect_path_emits_m_l_l_l_h() {
        let mut p = Path::new();
        p.move_to(Point::new(10.0, 10.0))
            .line_to(Point::new(110.0, 10.0))
            .line_to(Point::new(110.0, 60.0))
            .line_to(Point::new(10.0, 60.0))
            .close();
        let mut op = OpBuf::new();
        emit_path(&mut op, &p);
        let s = String::from_utf8(op.into_bytes()).unwrap();
        assert!(s.contains("10 10 m"));
        assert!(s.contains("110 10 l"));
        assert!(s.contains("110 60 l"));
        assert!(s.contains("10 60 l"));
        assert!(s.contains("h"));
    }

    #[test]
    fn quad_lifts_to_cubic() {
        // start (0,0), control (3, 9), end (6, 0)
        // c1 = (0,0) + 2/3 * ((3,9)-(0,0)) = (2, 6)
        // c2 = (6,0) + 2/3 * ((3,9)-(6,0)) = (4, 6)
        let mut p = Path::new();
        p.move_to(Point::new(0.0, 0.0))
            .quad_to(Point::new(3.0, 9.0), Point::new(6.0, 0.0));
        let mut op = OpBuf::new();
        emit_path(&mut op, &p);
        let s = String::from_utf8(op.into_bytes()).unwrap();
        assert!(s.contains("2 6 4 6 6 0 c"));
    }

    #[test]
    fn fill_paint_solid_emits_rgb() {
        let mut op = OpBuf::new();
        let mut res = ResourceCollector::new();
        set_fill_paint(&mut op, &Paint::Solid(Rgba::opaque(255, 128, 0)), &mut res);
        let s = String::from_utf8(op.into_bytes()).unwrap();
        assert!(s.starts_with("1 0.501961 0 rg"));
    }

    #[test]
    fn paint_modes() {
        for (mode, rule, expected) in [
            (PaintMode::Fill, FillRule::NonZero, "f\n"),
            (PaintMode::Fill, FillRule::EvenOdd, "f*\n"),
            (PaintMode::Stroke, FillRule::NonZero, "S\n"),
            (PaintMode::FillStroke, FillRule::NonZero, "B\n"),
            (PaintMode::FillStroke, FillRule::EvenOdd, "B*\n"),
            (PaintMode::None, FillRule::NonZero, "n\n"),
        ] {
            let mut op = OpBuf::new();
            paint(&mut op, mode, rule);
            assert_eq!(op.into_bytes(), expected.as_bytes());
        }
    }

    #[test]
    fn stroke_style_emits_w_J_j_M_d() {
        let mut op = OpBuf::new();
        let mut res = ResourceCollector::new();
        let stroke = Stroke {
            width: 2.5,
            paint: Paint::Solid(Rgba::opaque(0, 0, 0)),
            cap: LineCap::Round,
            join: LineJoin::Bevel,
            miter_limit: 8.0,
            dash: Some(DashPattern {
                array: vec![5.0, 3.0],
                offset: 1.0,
            }),
        };
        set_stroke_style(&mut op, &stroke, &mut res);
        let s = String::from_utf8(op.into_bytes()).unwrap();
        assert!(s.contains("2.5 w"));
        assert!(s.contains("1 J"));
        assert!(s.contains("2 j"));
        assert!(s.contains("8 M"));
        assert!(s.contains("[5 3] 1 d"));
    }

    #[test]
    fn empty_path_writes_nothing() {
        let p = Path::new();
        let mut op = OpBuf::new();
        emit_path(&mut op, &p);
        assert!(op.as_bytes().is_empty());

        // PathNode round-trip sanity (no panics on default).
        let _node = PathNode {
            path: Path::new(),
            fill: None,
            stroke: None,
            fill_rule: FillRule::NonZero,
        };
    }
}
