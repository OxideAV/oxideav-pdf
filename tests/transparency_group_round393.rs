//! Round-393 transparency-group XObject tests (ISO 32000-1 §11.6.6
//! "Transparency Group XObjects").
//!
//! A form XObject with a `/Group` attributes dictionary of subtype
//! `/S /Transparency` composites into its parent *as a unit*: "The
//! nonstroking alpha constant shall also be applied when painting a
//! transparency group's results onto its backdrop" (§11.6.4.4), and
//! per the §11.6.6 initialisation rule the group's own content starts
//! from a fresh state (alphas 1.0, soft mask None) so nothing applies
//! twice. An ordinary form XObject — no `/Group` entry — "shall not be
//! subject to any grouping behaviour for transparency purposes".
//!
//! The fixture paints the same red-square form twice under a
//! `gs`-established `ca 0.5`: once as a transparency group (`/Fm0`)
//! and once as a plain form (`/Fm1`). The spliced `/Fm0` group carries
//! `opacity == 0.5`; the plain `/Fm1` group keeps `opacity == 1.0`.

use oxideav_core::vector::{Group, Node};
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

fn build_group_vs_plain_pdf() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets: [u64; 7] = [0; 7];

    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // Both forms painted under ca 0.5 established by /GS0.
    let content: &[u8] = b"q /GS0 gs /Fm0 Do 100 0 0 100 0 0 cm /Fm1 Do Q\n";
    let form_content: &[u8] = b"1 0 0 rg 0 0 m 20 0 l 20 20 l 0 20 l h f\n";

    // 5 = transparency-group form, 6 = plain form (same content).
    for (obj, extra) in [
        (5usize, "/Group << /S /Transparency /CS /DeviceRGB >> "),
        (6usize, ""),
    ] {
        offsets[obj] = bytes.len() as u64;
        bytes.extend_from_slice(
            format!(
                "{obj} 0 obj\n<< /Type /XObject /Subtype /Form /FormType 1 \
                 /BBox [0 0 20 20] {extra}/Length {} >>\nstream\n",
                form_content.len()
            )
            .as_bytes(),
        );
        bytes.extend_from_slice(form_content);
        bytes.extend_from_slice(b"\nendstream\nendobj\n");
    }

    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
          /Contents 4 0 R \
          /Resources << \
          /ExtGState << /GS0 << /Type /ExtGState /ca 0.5 >> >> \
          /XObject << /Fm0 5 0 R /Fm1 6 0 R >> >> \
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

/// Collect the opacity of every group that directly contains a path
/// (the spliced form groups), in tree order.
fn collect_form_opacities(group: &Group, out: &mut Vec<f32>) {
    for child in &group.children {
        if let Node::Group(g) = child {
            if g.children.iter().any(|c| matches!(c, Node::Path(_))) && g.clip.is_some() {
                // A spliced form group carries the /BBox clip.
                out.push(g.opacity);
            }
            collect_form_opacities(g, out);
        }
    }
}

#[test]
fn transparency_group_takes_group_level_alpha() {
    let pdf = build_group_vs_plain_pdf();
    assert!(pdf.len() <= 10 * 1024, "fixture under 10 KB");

    let scene = read_pdf_to_scene(&pdf).expect("read PDF to scene");
    let root = &scene.pages.as_ref().unwrap()[0].content.root;

    let mut opacities = Vec::new();
    collect_form_opacities(root, &mut opacities);
    assert_eq!(opacities.len(), 2, "both form splices found: {opacities:?}");
    assert!(
        (opacities[0] - 0.5).abs() < 1e-6,
        "the transparency-group form carries the ca 0.5 as group opacity, got {}",
        opacities[0]
    );
    assert!(
        (opacities[1] - 1.0).abs() < 1e-6,
        "the plain form gets no grouping behaviour, got {}",
        opacities[1]
    );
}
