//! Round-232 — `/Caret` + `/Popup` annotation-writer end-to-end tests
//! (ISO 32000-1 §12.5.6.11 Table 180 + §12.5.6.14 Table 183).
//!
//! Validates that [`oxideav_pdf::write_pdf_with_annotations`] emits
//! PDFs whose page-level `/Annots` arrays contain matching annotation
//! dicts for the two markup-editing subtypes the round-197 reader
//! already decodes — closing the writer-side symmetry for the
//! caret-with-editing-popup family.
//!
//! Round-trip is exercised against the round-26 / round-197 generic
//! annotation reader ([`oxideav_pdf::read_pdf_annotations`]).

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    read_pdf_annotations, write_pdf_with_annotations, Annotation, AnnotationKind, CaretSymbol,
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

fn default_annot(rect: [f32; 4], kind: WriterAnnotationKind) -> Annotation {
    Annotation {
        source_page_index: 0,
        rect,
        author: None,
        modified: None,
        flags: None,
        colour: None,
        border: None,
        kind,
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.11 Caret annotation (Table 180).
// ────────────────────────────────────────────────────────────────────

#[test]
fn caret_minimal_bare_caret_roundtrips() {
    // Table 180: every field is optional. A bare /Subtype /Caret with
    // just the outer /Rect should round-trip — /RD absent, /Sy
    // defaults to None.
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 18.0, 60.0],
        WriterAnnotationKind::Caret {
            rect_diffs: None,
            symbol: CaretSymbol::None,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Caret { rect_diffs, symbol } => {
            assert!(rect_diffs.is_none(), "no /RD when caller omits it");
            // Table 180 default ⇒ reader returns the literal string
            // "None" (the default symbol name).
            assert_eq!(symbol, "None");
        }
        other => panic!("expected /Caret, got {other:?}"),
    }
}

#[test]
fn caret_with_paragraph_symbol_and_rd_roundtrips() {
    // §12.5.6.11 Table 180 — /Sy /P + /RD inset.
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 110.0, 60.0],
        WriterAnnotationKind::Caret {
            rect_diffs: Some([2.0, 3.0, 4.0, 5.0]),
            symbol: CaretSymbol::Paragraph,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Caret { rect_diffs, symbol } => {
            assert_eq!(*rect_diffs, Some([2.0, 3.0, 4.0, 5.0]));
            assert_eq!(symbol, "P");
        }
        other => panic!("expected /Caret, got {other:?}"),
    }
}

#[test]
fn caret_dict_omits_sy_when_default_none() {
    // Table 180 default for /Sy is /None; byte-level check that the
    // writer leaves the entry off so a write-then-read cycle through
    // the round-197 reader's "absent → \"None\"" branch stays tight.
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 110.0, 60.0],
        WriterAnnotationKind::Caret {
            rect_diffs: None,
            symbol: CaretSymbol::None,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    // Locate the /Subtype /Caret dict in the body and confirm /Sy is
    // not in the surrounding entries.
    let needle = b"/Subtype /Caret";
    let pos = pdf
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("/Subtype /Caret marker present in body");
    let end = pdf[pos..]
        .windows(2)
        .position(|w| w == b">>")
        .map(|i| pos + i)
        .expect("dict terminator present");
    let dict_slice = &pdf[pos..end];
    assert!(
        !dict_slice.windows(3).any(|w| w == b"/Sy"),
        "writer must omit /Sy when CaretSymbol::None is set (Table 180 default)"
    );
}

#[test]
fn caret_writer_rejects_negative_rd() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 20.0, 110.0, 60.0],
        WriterAnnotationKind::Caret {
            rect_diffs: Some([-1.0, 0.0, 0.0, 0.0]),
            symbol: CaretSymbol::None,
        },
    );
    let err =
        write_pdf_with_annotations(&scene, &[annot]).expect_err("negative /RD must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("/RD"), "error mentions /RD: {msg}");
}

#[test]
fn caret_writer_rejects_rd_inset_exceeding_rect() {
    // Table 180: left+right shall be < /Rect width, top+bottom shall
    // be < /Rect height. /Rect here is 10×10; an inset of
    // [6 6 6 6] sums to 12 on each axis ⇒ rejected.
    let scene = one_page_scene();
    let annot = default_annot(
        [0.0, 0.0, 10.0, 10.0],
        WriterAnnotationKind::Caret {
            rect_diffs: Some([6.0, 6.0, 6.0, 6.0]),
            symbol: CaretSymbol::None,
        },
    );
    let err =
        write_pdf_with_annotations(&scene, &[annot]).expect_err("oversized /RD must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("/RD"), "error mentions /RD: {msg}");
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.14 Popup annotation (Table 183).
// ────────────────────────────────────────────────────────────────────

#[test]
fn popup_minimal_no_parent_roundtrips() {
    // Tolerant-reader contract: a Popup with no /Parent still parses
    // (§12.5.6.14 considers the shape malformed but the round-197
    // reader surfaces it as `parent: None`).
    let scene = one_page_scene();
    let annot = default_annot(
        [50.0, 50.0, 200.0, 150.0],
        WriterAnnotationKind::Popup {
            parent_index: None,
            open: false,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Popup { parent, open } => {
            assert!(parent.is_none(), "no /Parent when caller omits it");
            // Table 183 default ⇒ reader returns false on absent /Open.
            assert!(!*open);
        }
        other => panic!("expected /Popup, got {other:?}"),
    }
}

#[test]
fn popup_with_text_parent_resolves_indirect_reference() {
    // Table 183 — /Parent is normatively an indirect reference to the
    // parent markup annotation. The writer takes a 0-based index into
    // the same `annotations` slice and resolves it to the parent's
    // pre-allocated object id; the round-197 reader surfaces it as
    // the `parent: Some(ObjectId)` field. We can't predict the exact
    // id without rebuilding the writer's allocator, so the test
    // asserts presence + walks the cross-link back through the reader's
    // resolver to confirm it points at the Text parent.
    let scene = one_page_scene();
    let annots = vec![
        default_annot(
            [10.0, 10.0, 30.0, 30.0],
            WriterAnnotationKind::Text {
                contents: "Review note".into(),
                icon: Some("Comment".into()),
                open: false,
            },
        ),
        default_annot(
            [50.0, 50.0, 200.0, 150.0],
            WriterAnnotationKind::Popup {
                parent_index: Some(0),
                open: true,
            },
        ),
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let read_back = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(read_back.len(), 2);

    let parent_id = match &read_back[1].kind {
        AnnotationKind::Popup { parent, open } => {
            assert!(*open, "/Open true survives the round trip");
            parent.expect("/Parent indirect reference must be present")
        }
        other => panic!("expected /Popup at index 1, got {other:?}"),
    };

    // Resolve the /Parent id and confirm the dict it points at is the
    // Text annotation we emitted at index 0.
    let parent_obj = r
        .resolve(parent_id)
        .expect("parent id must resolve to a dict");
    let parent_dict = match parent_obj {
        oxideav_pdf::objects::Object::Dict(d) => d,
        other => panic!("expected dict at parent id, got {other:?}"),
    };
    let subtype = parent_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Subtype")
        .expect("/Subtype present on parent");
    assert!(
        matches!(&subtype.1, oxideav_pdf::objects::Object::Name(n) if n == "Text"),
        "/Parent must point at the Text annotation (got {:?})",
        subtype.1,
    );
}

#[test]
fn popup_dict_omits_open_when_default_false() {
    let scene = one_page_scene();
    let annot = default_annot(
        [50.0, 50.0, 200.0, 150.0],
        WriterAnnotationKind::Popup {
            parent_index: None,
            open: false,
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let needle = b"/Subtype /Popup";
    let pos = pdf
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("/Subtype /Popup marker present in body");
    let end = pdf[pos..]
        .windows(2)
        .position(|w| w == b">>")
        .map(|i| pos + i)
        .expect("dict terminator present");
    let dict_slice = &pdf[pos..end];
    assert!(
        !dict_slice.windows(5).any(|w| w == b"/Open"),
        "writer must omit /Open when caller passes open: false (Table 183 default)"
    );
}

#[test]
fn popup_writer_rejects_out_of_range_parent_index() {
    let scene = one_page_scene();
    let annot = default_annot(
        [50.0, 50.0, 200.0, 150.0],
        WriterAnnotationKind::Popup {
            parent_index: Some(42),
            open: false,
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot])
        .expect_err("out-of-range parent_index must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("parent_index"), "error mentions index: {msg}");
}

#[test]
fn popup_writer_rejects_self_parent_cycle() {
    let scene = one_page_scene();
    let annot = default_annot(
        [50.0, 50.0, 200.0, 150.0],
        WriterAnnotationKind::Popup {
            parent_index: Some(0),
            open: false,
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot])
        .expect_err("self-cycle parent_index must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("itself") || msg.contains("self"),
        "error explains: {msg}"
    );
}

#[test]
fn popup_writer_rejects_popup_parent() {
    // §12.5.6.14: the parent must be a markup annotation, not another
    // Popup (Popup has no /Contents of its own to display).
    let scene = one_page_scene();
    let annots = vec![
        default_annot(
            [10.0, 10.0, 30.0, 30.0],
            WriterAnnotationKind::Popup {
                parent_index: None,
                open: false,
            },
        ),
        default_annot(
            [50.0, 50.0, 200.0, 150.0],
            WriterAnnotationKind::Popup {
                parent_index: Some(0),
                open: false,
            },
        ),
    ];
    let err = write_pdf_with_annotations(&scene, &annots)
        .expect_err("Popup parent pointing at another Popup must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("markup"), "error mentions markup: {msg}");
}

// ────────────────────────────────────────────────────────────────────
// Cross-subtype enumeration on a single page.
// ────────────────────────────────────────────────────────────────────

#[test]
fn caret_and_popup_share_one_page_with_freetext_parent() {
    // A natural composite: a /Caret marking an edit position, plus a
    // /FreeText carrying the edit suggestion, plus a /Popup hanging
    // off the FreeText as the editing window.
    let scene = one_page_scene();
    let annots = vec![
        default_annot(
            [10.0, 20.0, 18.0, 60.0],
            WriterAnnotationKind::Caret {
                rect_diffs: None,
                symbol: CaretSymbol::Paragraph,
            },
        ),
        default_annot(
            [40.0, 100.0, 200.0, 130.0],
            WriterAnnotationKind::FreeText {
                contents: "rewrite this paragraph".into(),
                default_appearance: None,
                quadding: oxideav_pdf::FreeTextQuadding::Left,
            },
        ),
        default_annot(
            [50.0, 50.0, 200.0, 150.0],
            WriterAnnotationKind::Popup {
                parent_index: Some(1),
                open: true,
            },
        ),
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let read_back = read_pdf_annotations(&mut r).expect("read");
    assert_eq!(read_back.len(), 3);

    let mut saw_caret = false;
    let mut saw_freetext = false;
    let mut saw_popup_open = false;
    for a in &read_back {
        match &a.kind {
            AnnotationKind::Caret { symbol, .. } => {
                saw_caret = true;
                assert_eq!(symbol, "P");
            }
            AnnotationKind::FreeText { .. } => saw_freetext = true,
            AnnotationKind::Popup { parent, open } => {
                assert!(
                    parent.is_some(),
                    "/Parent must round-trip when parent_index is set"
                );
                assert!(*open);
                saw_popup_open = true;
            }
            other => panic!("unexpected subtype on round-trip: {other:?}"),
        }
    }
    assert!(saw_caret && saw_freetext && saw_popup_open);
}
