//! Round 292 — content-stream marked-content operators (ISO 32000-1
//! §14.6 Table 320).
//!
//! Exercises [`parse_content_stream_full_with_properties`], which
//! surfaces the five marked-content operators as
//! [`ContentMarkedContent`] events:
//!
//! * `tag MP` / `tag properties DP` — marked-content **points**.
//! * `tag BMC` / `tag properties BDC` — **begin** a sequence,
//!   terminated by a balancing `EMC`.
//! * `EMC` — **end** the most recent sequence.
//!
//! `properties` (`DP`/`BDC` only, §14.6.2) is either an inline
//! `<< … >>` dictionary written after the tag, or a `/Name` looked up
//! in the page's `/Resources /Properties` subdictionary.

use oxideav_pdf::objects::{Dict, Object};
use oxideav_pdf::reader::content::{parse_content_stream_full_with_properties, MarkedContentOp};

fn parse(
    input: &[u8],
    properties: Option<&Dict>,
) -> Vec<(MarkedContentOp, String, Option<Dict>, u32)> {
    let parsed =
        parse_content_stream_full_with_properties(input, None, None, None, None, properties)
            .expect("content stream parses");
    parsed
        .marked_content
        .into_iter()
        .map(|m| (m.operator, m.tag, m.properties, m.depth))
        .collect()
}

#[test]
fn bmc_emc_sequence_brackets_a_painted_path() {
    // BMC opens a tagged sequence; the EMC closes it. The path inside
    // still paints (the marked-content operators don't suppress
    // graphics).
    let input = b"/Span BMC\n10 10 50 50 re f\nEMC";
    let parsed =
        parse_content_stream_full_with_properties(input, None, None, None, None, None).unwrap();
    let mc = &parsed.marked_content;
    assert_eq!(mc.len(), 2);
    assert_eq!(mc[0].operator, MarkedContentOp::Bmc);
    assert_eq!(mc[0].tag, "Span");
    assert_eq!(mc[0].depth, 0);
    assert!(mc[0].properties.is_none());
    assert_eq!(mc[1].operator, MarkedContentOp::Emc);
    assert_eq!(mc[1].tag, "");
    assert_eq!(mc[1].depth, 0);
    // The rectangle still produced a painted child.
    assert!(
        !parsed.root.children.is_empty(),
        "the `re f` path inside the sequence still paints"
    );
}

#[test]
fn nested_sequences_track_depth() {
    // /OC BDC … (/P BMC … EMC) … EMC — the inner sequence reports
    // depth 1; both EMCs report the depth of the sequence they close.
    let input = b"/OC /MC0 BDC\n/P BMC\nEMC\nEMC";
    let mut props = Dict::new();
    props.set(
        "MC0",
        Object::Dict(Dict::new().with("Type", Object::Name("OCMD".into()))),
    );
    let events = parse(input, Some(&props));
    assert_eq!(events.len(), 4);
    // Outer BDC at depth 0, with the resolved /MC0 property list.
    assert_eq!(events[0].0, MarkedContentOp::Bdc);
    assert_eq!(events[0].1, "OC");
    assert_eq!(events[0].3, 0);
    let p = events[0].2.as_ref().expect("named property list resolved");
    assert!(matches!(
        p.entries().iter().find(|(k, _)| k == "Type").map(|(_, v)| v),
        Some(Object::Name(n)) if n == "OCMD"
    ));
    // Inner BMC at depth 1.
    assert_eq!(events[1].0, MarkedContentOp::Bmc);
    assert_eq!(events[1].1, "P");
    assert_eq!(events[1].3, 1);
    // Inner EMC closes the depth-1 sequence.
    assert_eq!(events[2].0, MarkedContentOp::Emc);
    assert_eq!(events[2].3, 1);
    // Outer EMC closes the depth-0 sequence.
    assert_eq!(events[3].0, MarkedContentOp::Emc);
    assert_eq!(events[3].3, 0);
}

#[test]
fn bdc_with_inline_property_dictionary() {
    // §14.6.2 — when every value is a direct object the property list
    // may be written inline as `<< … >>`.
    let input = b"/Span << /MCID 4 /ActualText (Hi) >> BDC\nEMC";
    let events = parse(input, None);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].0, MarkedContentOp::Bdc);
    assert_eq!(events[0].1, "Span");
    let p = events[0].2.as_ref().expect("inline property list captured");
    let mcid = p
        .entries()
        .iter()
        .find(|(k, _)| k == "MCID")
        .map(|(_, v)| v);
    assert!(matches!(mcid, Some(Object::Integer(4))));
    let at = p
        .entries()
        .iter()
        .find(|(k, _)| k == "ActualText")
        .map(|(_, v)| v);
    assert!(matches!(at, Some(Object::LiteralString(b)) if b == b"Hi"));
}

#[test]
fn dp_point_with_inline_properties() {
    // DP designates a single point (no EMC). Its depth is the
    // enclosing sequence's depth (0 here — not inside any sequence).
    let input = b"/Artifact << /Type /Pagination >> DP";
    let events = parse(input, None);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, MarkedContentOp::Dp);
    assert_eq!(events[0].1, "Artifact");
    assert_eq!(events[0].3, 0);
    let p = events[0].2.as_ref().expect("inline DP property list");
    assert!(matches!(
        p.entries().iter().find(|(k, _)| k == "Type").map(|(_, v)| v),
        Some(Object::Name(n)) if n == "Pagination"
    ));
}

#[test]
fn mp_point_carries_only_a_tag() {
    let input = b"/Bookmark MP";
    let events = parse(input, None);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, MarkedContentOp::Mp);
    assert_eq!(events[0].1, "Bookmark");
    assert!(events[0].2.is_none());
    assert_eq!(events[0].3, 0);
}

#[test]
fn mp_point_inside_a_sequence_reports_enclosing_depth() {
    // The point sits inside the open BMC sequence, so it reports
    // depth 1 (the count of open sequences), not 0.
    let input = b"/Span BMC\n/Pt MP\nEMC";
    let events = parse(input, None);
    assert_eq!(events.len(), 3);
    assert_eq!(events[1].0, MarkedContentOp::Mp);
    assert_eq!(events[1].1, "Pt");
    assert_eq!(events[1].3, 1);
}

#[test]
fn dp_named_property_list_resolves_against_resources() {
    let input = b"/OC /Layer1 DP";
    let mut props = Dict::new();
    props.set(
        "Layer1",
        Object::Dict(Dict::new().with("Type", Object::Name("OCG".into()))),
    );
    let events = parse(input, Some(&props));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, MarkedContentOp::Dp);
    assert_eq!(events[0].1, "OC");
    let p = events[0]
        .2
        .as_ref()
        .expect("named DP property list resolved");
    assert!(matches!(
        p.entries().iter().find(|(k, _)| k == "Type").map(|(_, v)| v),
        Some(Object::Name(n)) if n == "OCG"
    ));
}

#[test]
fn bdc_named_property_unresolved_when_resources_absent() {
    // The name doesn't resolve (no /Resources /Properties plumbed in),
    // so the event still fires but `properties` is None.
    let input = b"/OC /Missing BDC\nEMC";
    let events = parse(input, None);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].0, MarkedContentOp::Bdc);
    assert_eq!(events[0].1, "OC");
    assert!(events[0].2.is_none());
}

#[test]
fn unbalanced_emc_is_tolerated_at_depth_zero() {
    // An EMC with no open sequence saturates the depth at 0 rather
    // than underflowing.
    let input = b"EMC\n/Span BMC\nEMC\nEMC";
    let events = parse(input, None);
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].0, MarkedContentOp::Emc);
    assert_eq!(events[0].3, 0); // stray EMC, depth saturated at 0
    assert_eq!(events[1].0, MarkedContentOp::Bmc);
    assert_eq!(events[1].3, 0);
    assert_eq!(events[2].0, MarkedContentOp::Emc);
    assert_eq!(events[2].3, 0); // closes the one real sequence
    assert_eq!(events[3].0, MarkedContentOp::Emc);
    assert_eq!(events[3].3, 0); // second stray EMC, still 0
}

#[test]
fn round3_group_entry_point_skips_marked_content() {
    // The round-3 `parse_content_stream` entry returns only a `Group`
    // (no `ParsedContent`), so the marked-content events are
    // unobservable there — but the bracketed graphics still paint.
    let input = b"/Span BMC\n10 10 50 50 re f\nEMC";
    let group = oxideav_pdf::reader::content::parse_content_stream(input).unwrap();
    assert!(
        !group.children.is_empty(),
        "the `re f` path inside the sequence still paints"
    );
}

#[test]
fn parsed_content_entry_points_emit_marked_content_without_properties() {
    // Mirroring the round-128 `text_shows` / round-259 `shadings`
    // precedent, the `ParsedContent`-returning entry points surface
    // marked-content events even when no `/Resources /Properties` is
    // plumbed in — a `DP`/`BDC` naming a resource simply gets
    // `properties = None`. BMC/MP/EMC carry no property list, so they
    // are fully observable through `parse_content_stream_full` too.
    let input = b"/Span BMC\n10 10 50 50 re f\nEMC";
    let parsed =
        oxideav_pdf::reader::content::parse_content_stream_full(input, None, None).unwrap();
    assert_eq!(parsed.marked_content.len(), 2);
    assert_eq!(parsed.marked_content[0].operator, MarkedContentOp::Bmc);
    assert_eq!(parsed.marked_content[1].operator, MarkedContentOp::Emc);
    assert!(!parsed.root.children.is_empty());
}

#[test]
fn marked_content_around_text_show_preserves_both() {
    // BDC … (BT Tj ET) … EMC — the text show and the marked-content
    // brackets coexist in stream order (they nest separately per
    // §14.6 Table 320 note).
    let mut fonts = Dict::new();
    fonts.set(
        "F1",
        Object::Dict(
            Dict::new()
                .with("Type", Object::Name("Font".into()))
                .with("Subtype", Object::Name("Type1".into())),
        ),
    );
    let input = b"/Span << /MCID 0 >> BDC\nBT /F1 12 Tf (Hello) Tj ET\nEMC";
    let parsed =
        parse_content_stream_full_with_properties(input, None, Some(&fonts), None, None, None)
            .unwrap();
    assert_eq!(parsed.marked_content.len(), 2);
    assert_eq!(parsed.marked_content[0].operator, MarkedContentOp::Bdc);
    assert_eq!(parsed.marked_content[1].operator, MarkedContentOp::Emc);
    assert_eq!(parsed.text_shows.len(), 1);
    assert_eq!(parsed.text_shows[0].bytes, b"Hello");
}
