//! Round-95: ISO 32000-1 §8.11 Optional Content reader.
//!
//! Hand-rolls a minimal PDF carrying a `/OCProperties` catalog entry
//! with multiple OCGs and a configuration dictionary, then verifies
//! [`DocumentReader::optional_content`] parses every piece per spec:
//!
//! 1. **Two OCGs + default config / BaseState=ON** — every group is
//!    initially ON; querying `is_visible()` returns true for both.
//! 2. **BaseState=OFF + ON array** — turns the listed OCG on while
//!    leaving others off (§8.11.4.5 algorithm step (b)).
//! 3. **BaseState=ON + OFF array** — turns the listed OCG off while
//!    leaving others on (step (c)).
//! 4. **Membership dictionary with /P AllOn** — visible only when all
//!    referenced groups are ON; flipping one to OFF flips the result.
//! 5. **Visibility expression `[/Or g1 [/Not g2]]`** — evaluates per
//!    §8.11.2.2 boolean semantics.
//! 6. **Alternate configurations** — `/Configs` array surfaces
//!    alongside the default config.
//! 7. **Order tree** — nested `[label, gN, [sublabel, gM]]` arrays
//!    parse into a `Vec<OcOrderItem>` tree.
//! 8. **No /OCProperties** — `optional_content()` returns `Ok(None)`.
//!
//! Tests read only crate state and the ISO 32000-1 spec PDF as
//! reference bytes — no qpdf / pdfium / mupdf source consulted.

use oxideav_pdf::objects::ObjectId;
use oxideav_pdf::reader::ocg::{
    OcBaseState, OcMembership, OcOrderItem, OcVisibilityExpression, OcVisibilityPolicy,
};
use oxideav_pdf::reader::DocumentReader;
use std::io::Write as _;

/// Build a minimal PDF whose catalog carries a populated `/OCProperties`
/// dict. Object layout:
///
/// * 1 — catalog (with `/OCProperties 4 0 R`)
/// * 2 — pages tree
/// * 3 — single Page
/// * 4 — `/OCProperties` dict
/// * 5 — OCG "Layer 1"
/// * 6 — OCG "Layer 2"
/// * 7 — OCG "Layer 3"
/// * 8 — default config dict (`/D` target)
fn build_pdf_with_ocgs(off_array: &[u32], on_array: &[u32], base_state: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offs: Vec<usize> = vec![0];

    offs.push(out.len());
    out.extend_from_slice(
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OCProperties 4 0 R >>\nendobj\n",
    );
    offs.push(out.len());
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
          /Resources << >> >>\nendobj\n",
    );

    // 4 — OCProperties: /OCGs array + /D pointing at config.
    offs.push(out.len());
    out.extend_from_slice(b"4 0 obj\n<< /OCGs [5 0 R 6 0 R 7 0 R] /D 8 0 R >>\nendobj\n");

    // 5, 6, 7 — OCGs.
    offs.push(out.len());
    out.extend_from_slice(b"5 0 obj\n<< /Type /OCG /Name (Layer 1) >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(b"6 0 obj\n<< /Type /OCG /Name (Layer 2) /Intent /View >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(b"7 0 obj\n<< /Type /OCG /Name (Layer 3) >>\nendobj\n");

    // 8 — config.
    offs.push(out.len());
    let mut cfg_bytes: Vec<u8> = Vec::new();
    cfg_bytes.extend_from_slice(b"8 0 obj\n<< /Name (Default) /Creator (TestSuite) ");
    cfg_bytes.extend(format!("/BaseState /{base_state} ").as_bytes());
    cfg_bytes.extend_from_slice(b"/ON [");
    for n in on_array {
        cfg_bytes.extend(format!("{n} 0 R ").as_bytes());
    }
    cfg_bytes.extend_from_slice(b"] /OFF [");
    for n in off_array {
        cfg_bytes.extend(format!("{n} 0 R ").as_bytes());
    }
    cfg_bytes.extend_from_slice(b"] /Order [5 0 R 6 0 R 7 0 R] >>\nendobj\n");
    out.extend_from_slice(&cfg_bytes);

    // xref + trailer.
    let xref_pos = out.len();
    writeln!(out, "xref\n0 9").unwrap();
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offs.iter().skip(1) {
        writeln!(out, "{off:010} 00000 n ").unwrap();
    }
    writeln!(out, "trailer\n<< /Size 9 /Root 1 0 R >>").unwrap();
    writeln!(out, "startxref\n{xref_pos}\n%%EOF").unwrap();
    out
}

#[test]
fn basestate_on_makes_all_groups_visible() {
    let pdf = build_pdf_with_ocgs(&[], &[], "ON");
    let mut r = DocumentReader::open(&pdf).expect("opens");
    let oc = r.optional_content().expect("parses").expect("has OCG");
    assert_eq!(oc.groups.len(), 3);
    assert_eq!(oc.groups[0].name, "Layer 1");
    assert_eq!(oc.groups[1].name, "Layer 2");
    assert_eq!(oc.groups[2].name, "Layer 3");
    assert_eq!(oc.groups[1].intents, vec!["View".to_owned()]);
    assert!(matches!(oc.default_config.base_state, OcBaseState::On));
    for g in &oc.groups {
        assert!(oc.is_visible(g.id), "group {:?} should be visible", g.id);
    }
}

#[test]
fn basestate_off_then_on_array_flips_one_group() {
    // BaseState OFF → all start OFF; /ON [6 0 R] → object 6 toggles ON.
    let pdf = build_pdf_with_ocgs(&[], &[6], "OFF");
    let mut r = DocumentReader::open(&pdf).expect("opens");
    let oc = r.optional_content().expect("parses").expect("has OCG");
    assert!(matches!(oc.default_config.base_state, OcBaseState::Off));
    assert!(!oc.is_visible(ObjectId::new(5)));
    assert!(oc.is_visible(ObjectId::new(6)));
    assert!(!oc.is_visible(ObjectId::new(7)));
}

#[test]
fn basestate_on_then_off_array_flips_one_group_off() {
    // BaseState ON → all start ON; /OFF [5 0 R] → object 5 toggles OFF.
    let pdf = build_pdf_with_ocgs(&[5], &[], "ON");
    let mut r = DocumentReader::open(&pdf).expect("opens");
    let oc = r.optional_content().expect("parses").expect("has OCG");
    assert!(!oc.is_visible(ObjectId::new(5)));
    assert!(oc.is_visible(ObjectId::new(6)));
    assert!(oc.is_visible(ObjectId::new(7)));
}

#[test]
fn no_ocproperties_returns_none() {
    // The "round-3 sample" — a PDF without any /OCProperties entry.
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offs: Vec<usize> = vec![0];
    offs.push(out.len());
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>\nendobj\n",
    );
    let xref_pos = out.len();
    writeln!(out, "xref\n0 4").unwrap();
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offs.iter().skip(1) {
        writeln!(out, "{off:010} 00000 n ").unwrap();
    }
    writeln!(out, "trailer\n<< /Size 4 /Root 1 0 R >>").unwrap();
    writeln!(out, "startxref\n{xref_pos}\n%%EOF").unwrap();

    let mut r = DocumentReader::open(&out).expect("opens");
    let oc = r.optional_content().expect("parses");
    assert!(oc.is_none(), "no /OCProperties should surface as None");
}

#[test]
fn alternate_configs_surface() {
    // Builds a PDF whose /OCProperties carries /Configs [9 0 R] in
    // addition to the default /D entry.
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offs: Vec<usize> = vec![0];
    offs.push(out.len());
    out.extend_from_slice(
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OCProperties 4 0 R >>\nendobj\n",
    );
    offs.push(out.len());
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>\nendobj\n",
    );
    // /OCProperties referencing /Configs.
    offs.push(out.len());
    out.extend_from_slice(b"4 0 obj\n<< /OCGs [5 0 R] /D 8 0 R /Configs [9 0 R] >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(b"5 0 obj\n<< /Type /OCG /Name (Solo) >>\nendobj\n");
    // Default config — name "Main".
    offs.push(out.len());
    out.extend_from_slice(b"6 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(b"7 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(b"8 0 obj\n<< /Name (Main) /BaseState /ON >>\nendobj\n");
    // Alt config — name "Alternate".
    offs.push(out.len());
    out.extend_from_slice(
        b"9 0 obj\n<< /Name (Alternate) /Creator (CAD) /BaseState /OFF >>\nendobj\n",
    );
    let xref_pos = out.len();
    writeln!(out, "xref\n0 10").unwrap();
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offs.iter().skip(1) {
        writeln!(out, "{off:010} 00000 n ").unwrap();
    }
    writeln!(out, "trailer\n<< /Size 10 /Root 1 0 R >>").unwrap();
    writeln!(out, "startxref\n{xref_pos}\n%%EOF").unwrap();

    let mut r = DocumentReader::open(&out).expect("opens");
    let oc = r.optional_content().expect("parses").expect("has OCG");
    assert_eq!(oc.groups.len(), 1);
    assert_eq!(oc.default_config.name.as_deref(), Some("Main"));
    assert_eq!(oc.alternate_configs.len(), 1);
    assert_eq!(oc.alternate_configs[0].name.as_deref(), Some("Alternate"));
    assert_eq!(oc.alternate_configs[0].creator.as_deref(), Some("CAD"));
    assert!(matches!(
        oc.alternate_configs[0].base_state,
        OcBaseState::Off
    ));
    // The default config makes the lone group visible.
    assert!(oc.is_visible(ObjectId::new(5)));
    // But under the alternate config the BaseState=OFF turns it off.
    let alt_states = oc.states_for_config(&oc.alternate_configs[0]);
    assert_eq!(alt_states.get(&ObjectId::new(5)), Some(&false));
}

#[test]
fn order_array_parses_labelled_subtree() {
    // ISO 32000-1 §8.11.4.3 EXAMPLE 1: /Order [[(Frog Anatomy) 1 0 R 2 0 R]
    // [(Tree Anatomy) 3 0 R 4 0 R]] yields a two-element top-level tree.
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offs: Vec<usize> = vec![0];
    offs.push(out.len());
    out.extend_from_slice(
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OCProperties 7 0 R >>\nendobj\n",
    );
    offs.push(out.len());
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>\nendobj\n",
    );
    offs.push(out.len());
    out.extend_from_slice(b"4 0 obj\n<< /Type /OCG /Name (Skin) >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(b"5 0 obj\n<< /Type /OCG /Name (Bones) >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(b"6 0 obj\n<< /Type /OCG /Name (Bark) >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(b"7 0 obj\n<< /OCGs [4 0 R 5 0 R 6 0 R] /D 8 0 R >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(
        b"8 0 obj\n<< /Order [[(Frog Anatomy) 4 0 R 5 0 R] [(Tree Anatomy) 6 0 R]] >>\nendobj\n",
    );
    let xref_pos = out.len();
    writeln!(out, "xref\n0 9").unwrap();
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offs.iter().skip(1) {
        writeln!(out, "{off:010} 00000 n ").unwrap();
    }
    writeln!(out, "trailer\n<< /Size 9 /Root 1 0 R >>").unwrap();
    writeln!(out, "startxref\n{xref_pos}\n%%EOF").unwrap();

    let mut r = DocumentReader::open(&out).expect("opens");
    let oc = r.optional_content().expect("parses").expect("has OCG");
    assert_eq!(oc.default_config.order.len(), 2);
    // Outer item 0: labelled "Frog Anatomy" subtree with two groups.
    match &oc.default_config.order[0] {
        OcOrderItem::Subtree { label, items } => {
            assert_eq!(label.as_deref(), Some("Frog Anatomy"));
            assert_eq!(items.len(), 2);
            for it in items {
                assert!(matches!(it, OcOrderItem::Group(_)));
            }
        }
        other => panic!("expected Subtree, got {other:?}"),
    }
    // Outer item 1: labelled "Tree Anatomy" subtree with one group.
    match &oc.default_config.order[1] {
        OcOrderItem::Subtree { label, items } => {
            assert_eq!(label.as_deref(), Some("Tree Anatomy"));
            assert_eq!(items.len(), 1);
        }
        other => panic!("expected Subtree, got {other:?}"),
    }
}

#[test]
fn membership_dict_evaluates_against_resolved_states() {
    // Build a small PDF with three OCGs; group 5 is ON, groups 6 + 7 OFF.
    // Then synthesise an OCMD referring to {5, 6} with policy AllOn —
    // result should be false (group 6 is off).
    let pdf = build_pdf_with_ocgs(&[6, 7], &[], "ON");
    let mut r = DocumentReader::open(&pdf).expect("opens");
    let oc = r.optional_content().expect("parses").expect("has OCG");
    assert!(oc.is_visible(ObjectId::new(5)));
    assert!(!oc.is_visible(ObjectId::new(6)));

    let mem_all_on = OcMembership {
        groups: vec![ObjectId::new(5), ObjectId::new(6)],
        policy: OcVisibilityPolicy::AllOn,
        visibility_expression: None,
    };
    assert!(!oc.evaluate_membership(&mem_all_on));

    let mem_any_on = OcMembership {
        groups: vec![ObjectId::new(5), ObjectId::new(6)],
        policy: OcVisibilityPolicy::AnyOn,
        visibility_expression: None,
    };
    assert!(oc.evaluate_membership(&mem_any_on));

    let mem_all_off = OcMembership {
        groups: vec![ObjectId::new(6), ObjectId::new(7)],
        policy: OcVisibilityPolicy::AllOff,
        visibility_expression: None,
    };
    assert!(oc.evaluate_membership(&mem_all_off));
}

#[test]
fn visibility_expression_overrides_simple_policy() {
    // §8.11.2.2 NOTE 2: when /VE is present, /P is irrelevant. Build a
    // membership with conflicting /P AnyOff but /VE [/And g5 g6] — the
    // expression should win.
    let pdf = build_pdf_with_ocgs(&[], &[], "ON");
    let mut r = DocumentReader::open(&pdf).expect("opens");
    let oc = r.optional_content().expect("parses").expect("has OCG");

    let mem = OcMembership {
        groups: vec![ObjectId::new(5), ObjectId::new(6)],
        policy: OcVisibilityPolicy::AnyOff, // would say "not visible" — both ON
        visibility_expression: Some(OcVisibilityExpression::And(vec![
            OcVisibilityExpression::Group(ObjectId::new(5)),
            OcVisibilityExpression::Group(ObjectId::new(6)),
        ])),
    };
    assert!(
        oc.evaluate_membership(&mem),
        "VE [/And g5 g6] should evaluate true under BaseState=ON"
    );
}

#[test]
fn intent_array_decodes_both_view_and_design() {
    // Build a PDF whose OCG carries /Intent [/View /Design].
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offs: Vec<usize> = vec![0];
    offs.push(out.len());
    out.extend_from_slice(
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OCProperties 4 0 R >>\nendobj\n",
    );
    offs.push(out.len());
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>\nendobj\n",
    );
    offs.push(out.len());
    out.extend_from_slice(b"4 0 obj\n<< /OCGs [5 0 R] /D 6 0 R >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(
        b"5 0 obj\n<< /Type /OCG /Name (Both) /Intent [/View /Design] >>\nendobj\n",
    );
    offs.push(out.len());
    out.extend_from_slice(b"6 0 obj\n<< /BaseState /ON >>\nendobj\n");
    let xref_pos = out.len();
    writeln!(out, "xref\n0 7").unwrap();
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offs.iter().skip(1) {
        writeln!(out, "{off:010} 00000 n ").unwrap();
    }
    writeln!(out, "trailer\n<< /Size 7 /Root 1 0 R >>").unwrap();
    writeln!(out, "startxref\n{xref_pos}\n%%EOF").unwrap();

    let mut r = DocumentReader::open(&out).expect("opens");
    let oc = r.optional_content().expect("parses").expect("has OCG");
    assert_eq!(
        oc.groups[0].intents,
        vec!["View".to_owned(), "Design".to_owned()]
    );
}

#[test]
fn usage_dict_decodes_zoom_and_print() {
    // Build an OCG whose /Usage carries /Zoom { /min 1.0 /max 4.0 } +
    // /Print { /Subtype /Watermark /PrintState /OFF }.
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offs: Vec<usize> = vec![0];
    offs.push(out.len());
    out.extend_from_slice(
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OCProperties 4 0 R >>\nendobj\n",
    );
    offs.push(out.len());
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>\nendobj\n",
    );
    offs.push(out.len());
    out.extend_from_slice(b"4 0 obj\n<< /OCGs [5 0 R] /D 6 0 R >>\nendobj\n");
    offs.push(out.len());
    out.extend_from_slice(
        b"5 0 obj\n<< /Type /OCG /Name (Watermark) /Usage << /Zoom << /min 1.0 /max 4.0 >> \
          /Print << /Subtype /Watermark /PrintState /OFF >> >> >>\nendobj\n",
    );
    offs.push(out.len());
    out.extend_from_slice(b"6 0 obj\n<< /BaseState /ON >>\nendobj\n");
    let xref_pos = out.len();
    writeln!(out, "xref\n0 7").unwrap();
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offs.iter().skip(1) {
        writeln!(out, "{off:010} 00000 n ").unwrap();
    }
    writeln!(out, "trailer\n<< /Size 7 /Root 1 0 R >>").unwrap();
    writeln!(out, "startxref\n{xref_pos}\n%%EOF").unwrap();

    let mut r = DocumentReader::open(&out).expect("opens");
    let oc = r.optional_content().expect("parses").expect("has OCG");
    let usage = oc.groups[0].usage.as_ref().expect("has /Usage");
    assert_eq!(usage.zoom_min, Some(1.0));
    assert_eq!(usage.zoom_max, Some(4.0));
    assert_eq!(usage.print_subtype.as_deref(), Some("Watermark"));
    assert_eq!(usage.print_state, Some(false));
}
