//! Round-374 — `BI … ID … EI` inline images integrated into the
//! content-stream walker (ISO 32000-1 §8.9.7).
//!
//! Before this round the walker tokenized the raw inline-image payload
//! as if it were operators/numbers, which corrupted the stream (and
//! could abort the whole parse with an "operator needed N operands"
//! error when the payload happened to spell an operator with too few
//! preceding numbers). The walker now hands `BI … EI` to the
//! inline-image framer, surfaces a [`ContentInlineImage`] event with
//! the CTM + clip in force, and resumes past `EI`.

use oxideav_core::vector::{Group, Node};
use oxideav_pdf::reader::content::{
    parse_content_stream, parse_content_stream_full, ContentInlineImage,
};
use oxideav_pdf::reader::inline_images::InlineImageFilter;

fn count_paths(grp: &Group) -> usize {
    let mut n = 0;
    for ch in &grp.children {
        match ch {
            Node::Path(_) => n += 1,
            Node::Group(g) => n += count_paths(g),
            _ => {}
        }
    }
    n
}

/// A raw (unfiltered) binary inline-image payload that spells operator
/// hazards must not corrupt the surrounding stream, and the post-`EI`
/// fill must survive.
#[test]
fn binary_payload_does_not_corrupt_surrounding_stream() {
    let mut s = Vec::new();
    s.extend_from_slice(b"q 1 0 0 1 0 0 cm\n");
    s.extend_from_slice(b"BI /W 2 /H 2 /CS /G /BPC 8 ID ");
    // 4 raw payload bytes, deliberately containing bytes that look like
    // the start of a `re` path and a newline.
    s.extend_from_slice(&[0x20, b'r', b'e', 0x0A]);
    s.extend_from_slice(b"EI\n");
    s.extend_from_slice(b"Q\n");
    s.extend_from_slice(b"10 10 50 50 re f\n");

    let g = parse_content_stream(&s).expect("parse must not abort on binary payload");
    assert_eq!(
        count_paths(&g),
        1,
        "exactly the post-EI fill should survive as a path"
    );
}

/// The walker surfaces one `ContentInlineImage` per `BI` with the
/// resolved dictionary fields (W/H/CS/BPC) and the CTM in force.
#[test]
fn inline_image_event_carries_dims_and_ctm() {
    let mut s = Vec::new();
    // Scale the unit image square to a 200×100 placement.
    s.extend_from_slice(b"q 200 0 0 100 30 40 cm\n");
    s.extend_from_slice(b"BI /W 4 /H 3 /CS /RGB /BPC 8 ID ");
    // 4*3*3 = 36 raw RGB bytes.
    s.extend_from_slice(&[0x11u8; 36]);
    s.extend_from_slice(b" EI\n");
    s.extend_from_slice(b"Q\n");

    let pc = parse_content_stream_full(&s, None, None).expect("parse");
    assert_eq!(pc.inline_images.len(), 1, "one inline image expected");
    let ii: &ContentInlineImage = &pc.inline_images[0];
    assert_eq!(ii.image.width, 4);
    assert_eq!(ii.image.height, 3);
    assert_eq!(ii.image.bits_per_component, 8);
    assert!(!ii.image.image_mask);
    assert!(matches!(ii.image.filter, InlineImageFilter::Raw));
    // The CTM should reflect the 200×100 scale + (30,40) translation.
    assert!((ii.ctm.a - 200.0).abs() < 1e-3, "ctm.a = {}", ii.ctm.a);
    assert!((ii.ctm.d - 100.0).abs() < 1e-3, "ctm.d = {}", ii.ctm.d);
    assert!((ii.ctm.e - 30.0).abs() < 1e-3, "ctm.e = {}", ii.ctm.e);
    assert!((ii.ctm.f - 40.0).abs() < 1e-3, "ctm.f = {}", ii.ctm.f);
}

/// An ASCII-hex (`/AHx`) wrapped payload is peeled by the framer; the
/// terminal filter is `None` after the wrapping hex unwrap.
#[test]
fn ascii_hex_wrapped_payload_is_peeled() {
    // 2x1 grayscale, 8bpc → 2 bytes raw → "00FF" hex.
    let s = b"BI /W 2 /H 1 /CS /G /BPC 8 /F /AHx ID\n00FF>\nEI\n".to_vec();
    let pc = parse_content_stream_full(&s, None, None).expect("parse");
    assert_eq!(pc.inline_images.len(), 1);
    let ii = &pc.inline_images[0];
    assert_eq!(ii.image.data, vec![0x00, 0xFF]);
    assert!(matches!(ii.image.filter, InlineImageFilter::Raw));
}

/// Two inline images in one stream produce two stream-ordered events.
#[test]
fn two_inline_images_stream_order() {
    let mut s = Vec::new();
    s.extend_from_slice(b"BI /W 1 /H 1 /CS /G /BPC 8 ID ");
    s.extend_from_slice(&[0xAA]);
    s.extend_from_slice(b" EI\n");
    s.extend_from_slice(b"BI /W 1 /H 1 /CS /G /BPC 8 ID ");
    s.extend_from_slice(&[0xBB]);
    s.extend_from_slice(b" EI\n");

    let pc = parse_content_stream_full(&s, None, None).expect("parse");
    assert_eq!(pc.inline_images.len(), 2);
    assert_eq!(pc.inline_images[0].image.data, vec![0xAA]);
    assert_eq!(pc.inline_images[1].image.data, vec![0xBB]);
}

/// An image mask (`/IM true`) is flagged and defaults to 1 bpc.
#[test]
fn image_mask_flagged() {
    // 8x1 1-bit stencil → 1 byte.
    let mut s = Vec::new();
    s.extend_from_slice(b"BI /W 8 /H 1 /IM true ID ");
    s.extend_from_slice(&[0b1010_1010]);
    s.extend_from_slice(b" EI\n");
    let pc = parse_content_stream_full(&s, None, None).expect("parse");
    assert_eq!(pc.inline_images.len(), 1);
    let ii = &pc.inline_images[0];
    assert!(ii.image.image_mask);
    assert_eq!(ii.image.bits_per_component, 1);
}

/// A malformed inline-image dict must not abort the whole stream — the
/// walker salvages by skipping to the next `EI`, and trailing shapes
/// survive (no inline-image event is recorded for the bad one).
#[test]
fn malformed_dict_salvages_to_next_ei() {
    let mut s = Vec::new();
    // `/W` with no value before `ID` is malformed.
    s.extend_from_slice(b"BI /W ID garbage payload bytes EI\n");
    s.extend_from_slice(b"10 10 50 50 re f\n");
    let g = parse_content_stream(&s).expect("salvage must not abort");
    assert_eq!(count_paths(&g), 1, "trailing fill survives salvage");
}
