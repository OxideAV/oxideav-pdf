//! Round 98 — `LZWDecode` filter (ISO 32000-1:2008 §7.4.4.2) wired
//! into the central `decode_stream` dispatch.
//!
//! The spec's §7.4.4.2 Example 2 gives a packed LZW stream
//! (`80 0B 60 50 22 0C 0C 85 01`) whose decode is the §7.4.4.2
//! Example 1 input (`45 45 45 45 45 65 45 45 45 66`). These tests
//! exercise that vector through the public stream-decode surface in
//! both the single-`/Filter /LZWDecode` form and the chained
//! `/Filter [/ASCII85Decode /LZWDecode]` form (§7.4.4 Example 2).

use oxideav_pdf::objects::{Dict, Object, Stream};
use oxideav_pdf::reader::document::decode_stream;
use oxideav_pdf::reader::filters::{lzw_decode, lzw_decode_with_early_change};

/// §7.4.4.2 Example 2 packed bytes.
const LZW_EXAMPLE_2: [u8; 9] = [0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01];
/// §7.4.4.2 Example 1 decoded bytes.
const LZW_EXAMPLE_1: [u8; 10] = [45, 45, 45, 45, 45, 65, 45, 45, 45, 66];

/// Minimal ASCII85 encoder (§7.4.3) — test-local so the chain test
/// stays self-contained without leaning on a writer-side filter.
fn ascii85_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in input.chunks(4) {
        let mut group = [0u8; 4];
        group[..chunk.len()].copy_from_slice(chunk);
        let value = u32::from_be_bytes(group);
        let mut digits = [0u8; 5];
        let mut v = value;
        for d in digits.iter_mut().rev() {
            *d = (v % 85) as u8 + b'!';
            v /= 85;
        }
        out.extend_from_slice(&digits[..chunk.len() + 1]);
    }
    out.extend_from_slice(b"~>");
    out
}

#[test]
fn decode_stream_single_lzw_filter() {
    let dict = Dict::new().with("Filter", Object::Name("LZWDecode".into()));
    let stream = Stream::new(dict, LZW_EXAMPLE_2.to_vec());
    let out = decode_stream(&stream).expect("LZWDecode");
    assert_eq!(out, LZW_EXAMPLE_1);
}

#[test]
fn decode_stream_lzw_abbreviated_name() {
    // Inline-image abbreviation `/LZW` (Table 93) is accepted too.
    let dict = Dict::new().with("Filter", Object::Name("LZW".into()));
    let stream = Stream::new(dict, LZW_EXAMPLE_2.to_vec());
    assert_eq!(decode_stream(&stream).unwrap(), LZW_EXAMPLE_1);
}

#[test]
fn decode_stream_ascii85_then_lzw_chain() {
    // /Filter [/ASCII85Decode /LZWDecode] — the §7.4.4 Example 2
    // chain. Apply filters in array order: un-A85, then un-LZW.
    let a85 = ascii85_encode(&LZW_EXAMPLE_2);
    let dict = Dict::new().with(
        "Filter",
        Object::Array(vec![
            Object::Name("ASCII85Decode".into()),
            Object::Name("LZWDecode".into()),
        ]),
    );
    let stream = Stream::new(dict, a85);
    let out = decode_stream(&stream).expect("ASCII85 -> LZW chain");
    assert_eq!(out, LZW_EXAMPLE_1);
}

#[test]
fn decode_stream_lzw_honours_early_change_zero() {
    // /DecodeParms << /EarlyChange 0 >> changes when the code width
    // grows. For this short Example-2 stream the table never reaches
    // the 9->10-bit boundary, so both EarlyChange settings decode the
    // same bytes — but the parameter must be threaded through without
    // error and the direct `lzw_decode_with_early_change(.., false)`
    // entry must agree with the stream-level decode.
    let parms = Dict::new().with("EarlyChange", Object::Integer(0));
    let dict = Dict::new()
        .with("Filter", Object::Name("LZWDecode".into()))
        .with("DecodeParms", Object::Dict(parms));
    let stream = Stream::new(dict, LZW_EXAMPLE_2.to_vec());
    let out = decode_stream(&stream).expect("LZW EarlyChange=0");
    assert_eq!(out, LZW_EXAMPLE_1);
    assert_eq!(
        lzw_decode_with_early_change(&LZW_EXAMPLE_2, false).unwrap(),
        LZW_EXAMPLE_1
    );
}

#[test]
fn public_lzw_decode_matches_spec_vector() {
    assert_eq!(lzw_decode(&LZW_EXAMPLE_2).unwrap(), LZW_EXAMPLE_1);
}
