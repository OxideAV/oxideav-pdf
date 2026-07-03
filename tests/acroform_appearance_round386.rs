//! Round-386 — AcroForm widget **appearance stream** generation
//! (ISO 32000-1 §12.5.5 + §12.7.4.2.3).
//!
//! [`oxideav_pdf::write_pdf_with_form`] now emits self-contained
//! vector `/AP /N` state subdictionaries for check-box (`/Yes` +
//! `/Off`) and radio-button (`/<export>` + `/Off`) widgets, so a
//! viewer that honours `/AS` renders the authored appearance instead
//! of relying on the PDF 2.0-deprecated `/NeedAppearances`
//! regeneration. Round-trip is exercised through the reader's
//! §12.5.5 appearance-paint path (the `/AS` state selects the stream)
//! and the `annotations()` `/AP` summary.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    read_pdf_annotations, read_pdf_to_scene, write_pdf_with_form, FormField, FormFieldCheckbox,
    FormFieldRadioGroup, RadioOption,
};
use oxideav_scene::{Page, Scene};

fn one_page_scene() -> Scene {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(90.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(90.0, 90.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 200.0,
        height: 200.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(0, 0, 255))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let mut page = Page::new(200.0, 200.0);
    page.content = frame;
    Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    }
}

/// Count stroked (`stroke` set) and filled (`fill` set) paths in the
/// scene tree.
fn count_painted(group: &Group) -> (usize, usize) {
    let mut stroked = 0;
    let mut filled = 0;
    fn walk(group: &Group, stroked: &mut usize, filled: &mut usize) {
        for child in &group.children {
            match child {
                Node::Path(p) => {
                    if p.stroke.is_some() {
                        *stroked += 1;
                    }
                    if p.fill.is_some() {
                        *filled += 1;
                    }
                }
                Node::Group(g) => walk(g, stroked, filled),
                _ => {}
            }
        }
    }
    walk(group, &mut stroked, &mut filled);
    (stroked, filled)
}

fn checkbox(checked: bool) -> FormField {
    FormField::Checkbox(FormFieldCheckbox {
        name: "agree".into(),
        rect: [20.0, 20.0, 40.0, 40.0],
        page_index: 0,
        checked,
        default_appearance: None,
    })
}

#[test]
fn checkbox_appearance_states_surface_and_paint() {
    let scene = one_page_scene();

    // Checked: /AS /Yes selects the box + check-mark stream — two
    // stroked paths beyond the page's single filled triangle.
    let pdf = write_pdf_with_form(&scene, &[checkbox(true)]).expect("write");
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    assert_eq!(anns.len(), 1);
    let ap = anns[0].appearance.as_ref().expect("/AP emitted");
    assert!(ap.has_normal);
    assert_eq!(ap.states, vec!["Off".to_string(), "Yes".to_string()]);
    assert_eq!(anns[0].appearance_state.as_deref(), Some("Yes"));

    let back = read_pdf_to_scene(&pdf).expect("read back");
    let (stroked, filled) = count_painted(&back.pages.as_ref().unwrap()[0].content.root);
    assert_eq!(
        (stroked, filled),
        (2, 1),
        "checked box: border + check strokes, page triangle fill"
    );

    // Unchecked: /AS /Off selects the border-only stream.
    let pdf = write_pdf_with_form(&scene, &[checkbox(false)]).expect("write");
    let back = read_pdf_to_scene(&pdf).expect("read back");
    let (stroked, filled) = count_painted(&back.pages.as_ref().unwrap()[0].content.root);
    assert_eq!((stroked, filled), (1, 1), "unchecked box: border only");
}

#[test]
fn radio_appearance_states_paint_active_dot() {
    let scene = one_page_scene();
    let group = FormField::RadioGroup(FormFieldRadioGroup {
        name: "colour".into(),
        options: vec![
            RadioOption {
                export_value: "Red".into(),
                rect: [20.0, 60.0, 36.0, 76.0],
                page_index: 0,
            },
            RadioOption {
                export_value: "Green".into(),
                rect: [20.0, 90.0, 36.0, 106.0],
                page_index: 0,
            },
        ],
        value: Some("Green".into()),
    });
    let pdf = write_pdf_with_form(&scene, &[group]).expect("write");

    // Both kids carry the two-state /AP; their /AS names differ.
    let mut r = DocumentReader::open(&pdf).unwrap();
    let anns = read_pdf_annotations(&mut r).unwrap();
    let states: Vec<_> = anns
        .iter()
        .filter_map(|a| a.appearance_state.clone())
        .collect();
    assert!(states.contains(&"Off".to_string()), "{states:?}");
    assert!(states.contains(&"Green".to_string()), "{states:?}");

    // Painted scene: two ellipse borders (stroked) + one active dot
    // (filled) + the page triangle fill.
    let back = read_pdf_to_scene(&pdf).expect("read back");
    let (stroked, filled) = count_painted(&back.pages.as_ref().unwrap()[0].content.root);
    assert_eq!(
        (stroked, filled),
        (2, 2),
        "two radio borders, one dot + page fill"
    );
}
