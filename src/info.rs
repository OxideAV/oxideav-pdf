//! Document information dictionary (ISO 32000-1 §14.3.3).
//!
//! Maps [`oxideav_scene::Metadata`] onto the PDF `/Info` dictionary —
//! the standard keys (`/Title`, `/Author`, `/Subject`, `/Keywords`,
//! `/Creator`, `/Producer`, `/CreationDate`, `/ModDate`).
//!
//! `/Info` custom keys (round-tripping `Metadata::custom`) land in
//! the follow-up commit.
//!
//! # Date conversion
//!
//! The PDF date format from ISO 32000-1 §7.9.4 is
//! `D:YYYYMMDDHHmmSSOHH'mm'`, where `O` is `+`, `-`, or `Z` (UTC).
//! Scene metadata carries timestamps as ISO-8601 strings that
//! [`oxideav_scene`] doesn't parse (so it can stay codec-agnostic).
//! [`iso8601_to_pdf_date`] does the conversion: it accepts the most
//! common ISO-8601 surface (`YYYY-MM-DDTHH:MM:SS[.fff][Z|±HH:MM]`)
//! and emits the matching PDF date string. Inputs we can't parse are
//! passed through unchanged so the round-trip information isn't lost
//! — PDF readers tend to accept either form.

use oxideav_scene::Metadata;

use crate::objects::{Dict, Object};

/// True iff `metadata` carries any populated standard field. The
/// writer skips emitting the `/Info` dict entirely when this returns
/// false so trivial documents stay byte-stable with the round-1
/// output.
pub fn has_metadata(metadata: &Metadata) -> bool {
    metadata.title.is_some()
        || metadata.author.is_some()
        || metadata.subject.is_some()
        || !metadata.keywords.is_empty()
        || metadata.creator.is_some()
        || metadata.producer.is_some()
        || metadata.created_at.is_some()
        || metadata.modified_at.is_some()
}

/// Build the PDF `/Info` dictionary from a [`Metadata`]. Standard
/// keys land in the order ISO 32000-1 documents them.
pub fn build_info_dict(metadata: &Metadata) -> Dict {
    let mut info = Dict::new();
    if let Some(title) = &metadata.title {
        info.set("Title", text_string(title));
    }
    if let Some(author) = &metadata.author {
        info.set("Author", text_string(author));
    }
    if let Some(subject) = &metadata.subject {
        info.set("Subject", text_string(subject));
    }
    if !metadata.keywords.is_empty() {
        // PDF /Keywords is a single text string per §14.3.3 — comma-
        // separated is the convention every PDF producer uses.
        info.set("Keywords", text_string(&metadata.keywords.join(", ")));
    }
    if let Some(creator) = &metadata.creator {
        info.set("Creator", text_string(creator));
    }
    if let Some(producer) = &metadata.producer {
        info.set("Producer", text_string(producer));
    }
    if let Some(created_at) = &metadata.created_at {
        info.set(
            "CreationDate",
            text_string(&iso8601_to_pdf_date(created_at)),
        );
    }
    if let Some(modified_at) = &metadata.modified_at {
        info.set("ModDate", text_string(&iso8601_to_pdf_date(modified_at)));
    }
    info
}

/// PDF "text string" — a literal string. Round 2 emits PDFDocEncoding
/// as long as the input is plain ASCII (the common case for scene
/// metadata); non-ASCII inputs are written as a UTF-16BE-with-BOM
/// hex string per §7.9.2.2.1 so all of Unicode round-trips.
fn text_string(s: &str) -> Object {
    if s.bytes().all(|b| b.is_ascii() && b != 0) {
        // ASCII passes through PDFDocEncoding unchanged. Use the
        // literal-string form so escape rules apply for parens and
        // backslashes.
        Object::LiteralString(s.as_bytes().to_vec())
    } else {
        // Non-ASCII → UTF-16BE with the U+FEFF BOM (PDF treats this
        // BOM as the marker that the rest of the bytes are UTF-16BE
        // text). Hex string form keeps the bytes legible to debug
        // tooling.
        let mut bytes = vec![0xFE, 0xFF];
        for cp in s.encode_utf16() {
            bytes.push((cp >> 8) as u8);
            bytes.push((cp & 0xFF) as u8);
        }
        Object::HexString(bytes)
    }
}

/// Convert an ISO-8601 timestamp into the PDF date format from ISO
/// 32000-1 §7.9.4: `D:YYYYMMDDHHmmSSOHH'mm'`.
///
/// Accepts the common subset:
///
/// - `YYYY-MM-DD` (date only — emitted as `D:YYYYMMDD000000Z`)
/// - `YYYY-MM-DDTHH:MM:SS` (no zone — emitted with no zone suffix)
/// - `YYYY-MM-DDTHH:MM:SSZ` (UTC)
/// - `YYYY-MM-DDTHH:MM:SS.fff` (fractional seconds — discarded)
/// - `YYYY-MM-DDTHH:MM:SS±HH:MM` or `±HHMM` (offset)
///
/// Inputs the parser doesn't recognise are returned unchanged. PDF
/// readers tend to accept the raw ISO-8601 form too, so passing
/// through is a safer fallback than fabricating a date.
pub fn iso8601_to_pdf_date(s: &str) -> String {
    let bytes = s.as_bytes();

    // Need at least YYYY-MM-DD (10 chars).
    if bytes.len() < 10 {
        return s.to_string();
    }
    if !is_digit(bytes[0])
        || !is_digit(bytes[1])
        || !is_digit(bytes[2])
        || !is_digit(bytes[3])
        || bytes[4] != b'-'
        || !is_digit(bytes[5])
        || !is_digit(bytes[6])
        || bytes[7] != b'-'
        || !is_digit(bytes[8])
        || !is_digit(bytes[9])
    {
        return s.to_string();
    }

    let mut out = String::with_capacity(24);
    out.push_str("D:");
    out.push(bytes[0] as char);
    out.push(bytes[1] as char);
    out.push(bytes[2] as char);
    out.push(bytes[3] as char);
    out.push(bytes[5] as char);
    out.push(bytes[6] as char);
    out.push(bytes[8] as char);
    out.push(bytes[9] as char);

    // Date-only — pad time with zeros, default to UTC.
    if bytes.len() == 10 {
        out.push_str("000000Z");
        return out;
    }

    // Need 'T' or ' ' separator + at least HH:MM:SS (8 chars).
    if bytes.len() < 19 {
        out.push_str("000000Z");
        return out;
    }
    let sep = bytes[10];
    if sep != b'T' && sep != b' ' {
        return s.to_string();
    }
    if !is_digit(bytes[11])
        || !is_digit(bytes[12])
        || bytes[13] != b':'
        || !is_digit(bytes[14])
        || !is_digit(bytes[15])
        || bytes[16] != b':'
        || !is_digit(bytes[17])
        || !is_digit(bytes[18])
    {
        return s.to_string();
    }
    out.push(bytes[11] as char);
    out.push(bytes[12] as char);
    out.push(bytes[14] as char);
    out.push(bytes[15] as char);
    out.push(bytes[17] as char);
    out.push(bytes[18] as char);

    // Skip optional fractional seconds (.fff…) — not representable in
    // the PDF date format and rounded down by every reader anyway.
    let mut i = 19usize;
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        while i < bytes.len() && is_digit(bytes[i]) {
            i += 1;
        }
    }

    // Optional zone designator: 'Z' or ±HH:MM (or ±HHMM).
    if i >= bytes.len() {
        return out;
    }
    let z = bytes[i];
    if z == b'Z' || z == b'z' {
        out.push('Z');
        return out;
    }
    if z == b'+' || z == b'-' {
        // Need at least 5 trailing chars for ±HHMM, 6 for the colon
        // variant.
        if bytes.len() < i + 5 {
            return s.to_string();
        }
        let sign = z as char;
        let hh1 = bytes[i + 1];
        let hh2 = bytes[i + 2];
        let (mm1, mm2) = if bytes[i + 3] == b':' && bytes.len() >= i + 6 {
            (bytes[i + 4], bytes[i + 5])
        } else {
            (bytes[i + 3], bytes[i + 4])
        };
        if !is_digit(hh1) || !is_digit(hh2) || !is_digit(mm1) || !is_digit(mm2) {
            return s.to_string();
        }
        out.push(sign);
        out.push(hh1 as char);
        out.push(hh2 as char);
        out.push('\'');
        out.push(mm1 as char);
        out.push(mm2 as char);
        out.push('\'');
        return out;
    }

    // Unrecognised trailing characters → pass-through.
    s.to_string()
}

fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_full_with_z() {
        assert_eq!(
            iso8601_to_pdf_date("2026-05-04T12:30:45Z"),
            "D:20260504123045Z"
        );
    }

    #[test]
    fn iso8601_with_offset() {
        assert_eq!(
            iso8601_to_pdf_date("2026-05-04T12:30:45+09:00"),
            "D:20260504123045+09'00'"
        );
        assert_eq!(
            iso8601_to_pdf_date("2026-05-04T12:30:45-05:30"),
            "D:20260504123045-05'30'"
        );
    }

    #[test]
    fn iso8601_with_offset_no_colon() {
        assert_eq!(
            iso8601_to_pdf_date("2026-05-04T12:30:45+0900"),
            "D:20260504123045+09'00'"
        );
    }

    #[test]
    fn iso8601_with_fractional_seconds_drops_fraction() {
        assert_eq!(
            iso8601_to_pdf_date("2026-05-04T12:30:45.123Z"),
            "D:20260504123045Z"
        );
    }

    #[test]
    fn iso8601_date_only_pads_zeros() {
        assert_eq!(iso8601_to_pdf_date("2026-05-04"), "D:20260504000000Z");
    }

    #[test]
    fn iso8601_no_zone_emits_no_zone() {
        assert_eq!(
            iso8601_to_pdf_date("2026-05-04T12:30:45"),
            "D:20260504123045"
        );
    }

    #[test]
    fn iso8601_unparseable_passes_through() {
        assert_eq!(iso8601_to_pdf_date("not a date"), "not a date");
        assert_eq!(iso8601_to_pdf_date("2026/05/04"), "2026/05/04");
    }

    #[test]
    fn has_metadata_default_is_false() {
        assert!(!has_metadata(&Metadata::default()));
    }

    #[test]
    fn has_metadata_detects_any_field() {
        let m = Metadata {
            title: Some("hi".into()),
            ..Metadata::default()
        };
        assert!(has_metadata(&m));
        let m = Metadata {
            keywords: vec!["a".into()],
            ..Metadata::default()
        };
        assert!(has_metadata(&m));
    }

    #[test]
    fn build_info_dict_carries_standard_fields() {
        let m = Metadata {
            title: Some("Doc".into()),
            author: Some("Mark".into()),
            subject: Some("test".into()),
            keywords: vec!["pdf".into(), "test".into()],
            creator: Some("Author Tool".into()),
            producer: Some("oxideav-pdf".into()),
            created_at: Some("2026-05-04T12:30:45Z".into()),
            modified_at: Some("2026-05-04T13:00:00Z".into()),
            ..Metadata::default()
        };
        let d = build_info_dict(&m);
        let entries: Vec<&str> = d.entries().iter().map(|(k, _)| k.as_str()).collect();
        assert!(entries.contains(&"Title"));
        assert!(entries.contains(&"Author"));
        assert!(entries.contains(&"Subject"));
        assert!(entries.contains(&"Keywords"));
        assert!(entries.contains(&"Creator"));
        assert!(entries.contains(&"Producer"));
        assert!(entries.contains(&"CreationDate"));
        assert!(entries.contains(&"ModDate"));
    }

    #[test]
    fn unicode_text_string_emits_utf16be_with_bom() {
        let m = Metadata {
            title: Some("日本語".into()),
            ..Metadata::default()
        };
        let d = build_info_dict(&m);
        let title = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Title")
            .map(|(_, v)| v)
            .expect("Title set");
        match title {
            Object::HexString(b) => {
                assert_eq!(&b[0..2], &[0xFE, 0xFF], "BOM");
                // 3 chars * 2 bytes = 6 + BOM 2 = 8.
                assert_eq!(b.len(), 8);
            }
            other => panic!("expected hex string, got {other:?}"),
        }
    }
}
