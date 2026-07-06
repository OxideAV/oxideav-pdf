//! Round-393 Image-XObject scene splicing (ISO 32000-1 §8.9.5).
//!
//! A `Do` naming a straight-decodable Image XObject (Flate / LZW /
//! ASCII / RunLength filter chain, 8 bits/component, `/DeviceRGB` or
//! `/DeviceGray`) now splices a `Node::Image` into the `Scene`: the
//! image fills the unit square of the space the `Do` executes in
//! (§8.9.5.2 — sample (0,0) on the top edge, carried by the
//! self-inverse `[1 0 0 -1 0 1]` flip on the `ImageRef` transform),
//! and a `/SMask` soft-mask image (§11.6.5.3) becomes the alpha
//! channel of the straight-RGBA payload.
//!
//! This closes the writer→reader loop: `write_pdf` has always emitted
//! `ImageRef` as a FlateDecode RGB XObject + gray `/SMask`, and the
//! reader can now reconstruct that exact node — pixel data, alpha,
//! and placement.

use oxideav_core::vector::{Group, ImageRef, Node, Rect, Transform2D};
use oxideav_core::{TimeBase, VideoFrame, VideoPlane};
use oxideav_pdf::{read_pdf_to_scene, write_pdf};

/// 2×2 RGBA test pattern with distinct per-pixel colours and alphas.
const RGBA_2X2: [u8; 16] = [
    255, 0, 0, 255, // (0,0) opaque red
    0, 255, 0, 128, // (1,0) half-transparent green
    0, 0, 255, 64, // (0,1) quarter blue
    255, 255, 0, 0, // (1,1) fully transparent yellow
];

fn image_frame() -> oxideav_core::vector::VectorFrame {
    let node = Node::Image(ImageRef {
        frame: Box::new(VideoFrame {
            pts: None,
            planes: vec![VideoPlane {
                stride: 8,
                data: RGBA_2X2.to_vec(),
            }],
        }),
        // The writer's `ImageRef` contract reads the pixel dimensions
        // from `bounds`: a 2 by 2 image placed at (10, 20) spans
        // 2 by 2 user units (scaling, when wanted, rides `transform`).
        bounds: Rect::new(10.0, 20.0, 2.0, 2.0),
        transform: Transform2D::identity(),
    });
    oxideav_core::vector::VectorFrame {
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

fn find_image(group: &Group) -> Option<(&ImageRef, Transform2D)> {
    fn walk(group: &Group, t: Transform2D) -> Option<(&ImageRef, Transform2D)> {
        for child in &group.children {
            match child {
                Node::Image(img) => return Some((img, t)),
                Node::Group(g) => {
                    let t2 = Transform2D {
                        a: t.a * g.transform.a + t.c * g.transform.b,
                        b: t.b * g.transform.a + t.d * g.transform.b,
                        c: t.a * g.transform.c + t.c * g.transform.d,
                        d: t.b * g.transform.c + t.d * g.transform.d,
                        e: t.a * g.transform.e + t.c * g.transform.f + t.e,
                        f: t.b * g.transform.e + t.d * g.transform.f + t.f,
                    };
                    if let Some(found) = walk(g, t2) {
                        return Some(found);
                    }
                }
                Node::SoftMask { content, .. } => {
                    if let Node::Group(g) = content.as_ref() {
                        if let Some(found) = walk(g, t) {
                            return Some(found);
                        }
                    } else if let Node::Image(img) = content.as_ref() {
                        return Some((img, t));
                    }
                }
                _ => {}
            }
        }
        None
    }
    walk(group, Transform2D::identity())
}

#[test]
fn rgba_image_round_trips_through_write_and_read() {
    let pdf = write_pdf(&image_frame()).expect("write");
    let scene = read_pdf_to_scene(&pdf).expect("read back");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let (img, enclosing) = find_image(root).expect("Node::Image in the scene");

    // Pixel data — RGB + /SMask alpha recombined into straight RGBA.
    assert_eq!(img.frame.planes.len(), 1);
    assert_eq!(
        img.frame.planes[0].data, RGBA_2X2,
        "RGBA payload survives the split into RGB + /SMask and back"
    );

    // Placement: pixel-dimension bounds (the writer's `ImageRef`
    // contract reads image dimensions from `bounds`) under a 1/w × 1/h
    // scale collapsing them onto the §8.9.5.2 unit square; the
    // enclosing chain carries the writer's T(bx, by+bh)·S(bw, -bh)
    // placement, so composing the whole stack reproduces the authored
    // rect.
    assert_eq!(
        (
            img.bounds.x,
            img.bounds.y,
            img.bounds.width,
            img.bounds.height
        ),
        (0.0, 0.0, 2.0, 2.0)
    );
    assert_eq!(
        (img.transform.a, img.transform.d),
        (0.5, 0.5),
        "1/w × 1/h unit-square scale"
    );
    // Enclosing chain = T(10, 20+30) · S(40, -30): unit square maps to
    // the authored 40×30 rect at (10, 20).
    let total = {
        let g = &enclosing;
        let n = &img.transform;
        Transform2D {
            a: g.a * n.a + g.c * n.b,
            b: g.b * n.a + g.d * n.b,
            c: g.a * n.c + g.c * n.d,
            d: g.b * n.c + g.d * n.d,
            e: g.a * n.e + g.c * n.f + g.e,
            f: g.b * n.e + g.d * n.f + g.f,
        }
    };
    // Corners of the unit square under the total transform.
    let map = |x: f32, y: f32| {
        (
            total.a * x + total.c * y + total.e,
            total.b * x + total.d * y + total.f,
        )
    };
    let (x0, y0) = map(0.0, 0.0);
    let (x1, y1) = map(img.bounds.width, img.bounds.height);
    let (lx, hx) = (x0.min(x1), x0.max(x1));
    let (ly, hy) = (y0.min(y1), y0.max(y1));
    assert!(
        (lx - 10.0).abs() < 1e-3 && (hx - 12.0).abs() < 1e-3,
        "x span 10..12, got {lx}..{hx}"
    );
    assert!(
        (ly - 20.0).abs() < 1e-3 && (hy - 22.0).abs() < 1e-3,
        "y span 20..22, got {ly}..{hy}"
    );
}

#[test]
fn dct_image_stays_a_scene_no_op() {
    // A DCTDecode payload is not straight-decodable — it must stay on
    // the passthrough walker, not the scene.
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<(u32, usize)> = Vec::new();
    offsets.push((1, buf.len()));
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets.push((2, buf.len()));
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offsets.push((3, buf.len()));
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
          /Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>\nendobj\n",
    );
    let content = b"q 100 0 0 100 0 0 cm /Im0 Do Q\n";
    offsets.push((4, buf.len()));
    buf.extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");
    let jpeg = [0xffu8, 0xd8, 0xff, 0xd9];
    offsets.push((5, buf.len()));
    buf.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XObject /Subtype /Image /Width 8 /Height 8 \
             /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode \
             /Length {} >>\nstream\n",
            jpeg.len()
        )
        .as_bytes(),
    );
    buf.extend_from_slice(&jpeg);
    buf.extend_from_slice(b"\nendstream\nendobj\n");
    let n = offsets.len() + 1;
    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n");
    buf.extend_from_slice(format!("0 {n}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for (_, off) in &offsets {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(b"trailer\n");
    buf.extend_from_slice(format!("<< /Size {n} /Root 1 0 R >>\n").as_bytes());
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());

    let scene = read_pdf_to_scene(&buf).expect("read");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;
    assert!(
        find_image(root).is_none(),
        "DCTDecode image is not spliced into the scene"
    );
}
