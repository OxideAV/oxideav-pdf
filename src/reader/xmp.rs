//! Round-26 — XMP packet field extraction (ISO 32000-1 §14.3.2 + Adobe
//! XMP Specification, Sept-2012, ISO 16684-1).
//!
//! Round 19 surfaced the raw `/Metadata` packet bytes through
//! [`crate::reader::DocumentReader::xmp_metadata`]; this module adds
//! the small structured-field surface a "metadata" caller actually
//! wants — the most common Dublin Core, XMP Basic, and PDF-schema
//! entries, plus PDF/A conformance-level detection per ISO 19005-1
//! §6.7 / 19005-2 §6.6 / 19005-3 §6.6.
//!
//! The parser is deliberately byte-string rather than full XML — XMP
//! packets in the wild are mostly hand-crafted RDF/XML with predictable
//! shapes, and pulling in a full XML parser dep just for namespace-
//! qualified element scrapes is not worth the binary-size hit. The
//! shapes we recognise:
//!
//! * **Element body** — `<ns:Tag>...</ns:Tag>` returns the inner text
//!   verbatim (with the outer XML-entity decode applied: `&amp;` →
//!   `&`, `&lt;` → `<`, `&gt;` → `>`, `&quot;` → `"`, `&apos;` → `'`).
//! * **Attribute form** — `<rdf:Description ns:Tag="value" .../>`
//!   returns the attribute value with the same entity decode.
//! * **rdf:Alt / rdf:Bag / rdf:Seq language alternatives** —
//!   `<dc:title><rdf:Alt><rdf:li xml:lang="x-default">…</rdf:li>…</rdf:Alt></dc:title>`
//!   returns the first `rdf:li` body. The full alternative-language
//!   table is out of scope; round-26 picks the default-language
//!   sliver most consumers actually need.
//!
//! Unknown / missing fields surface as `None` — the parser never
//! errors. Empty packet ⇒ default-constructed [`XmpPacket`].

/// Structured view of an XMP packet's most useful fields.
///
/// All fields are best-effort scrapes — a malformed packet may
/// produce partial data. Round-trip with a writer is not in scope:
/// XMP is generally written by external tools (Adobe XMP SDK,
/// `exiftool`, …) and read by the consumer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XmpPacket {
    // ── Dublin Core (`dc:`, http://purl.org/dc/elements/1.1/) ────────
    /// `dc:title` — usually wrapped in `rdf:Alt` for language
    /// alternatives; we surface the default-language sliver.
    pub dc_title: Option<String>,
    /// `dc:creator` — author(s); we collapse the `rdf:Seq` to the
    /// first entry (the common case is exactly one creator).
    pub dc_creator: Option<String>,
    /// `dc:description` — same shape as `dc:title`.
    pub dc_description: Option<String>,
    /// `dc:subject` — `rdf:Bag` of keywords; we surface the full
    /// list in document order.
    pub dc_subject: Vec<String>,
    /// `dc:rights` — copyright statement; same shape as `dc:title`.
    pub dc_rights: Option<String>,
    /// `dc:format` — usually `application/pdf` for PDF documents.
    pub dc_format: Option<String>,

    // ── XMP Basic (`xmp:`, http://ns.adobe.com/xap/1.0/) ─────────────
    /// `xmp:CreateDate` — ISO 8601 date-time at first creation.
    pub xmp_create_date: Option<String>,
    /// `xmp:ModifyDate` — ISO 8601 date-time at last modification.
    pub xmp_modify_date: Option<String>,
    /// `xmp:MetadataDate` — ISO 8601 date-time the XMP packet itself
    /// was last touched.
    pub xmp_metadata_date: Option<String>,
    /// `xmp:CreatorTool` — application that authored the document
    /// (e.g. `Adobe InDesign 16.0`).
    pub xmp_creator_tool: Option<String>,

    // ── PDF schema (`pdf:`, http://ns.adobe.com/pdf/1.3/) ────────────
    /// `pdf:Producer` — application that wrote the PDF (often the
    /// same as `xmp:CreatorTool` but distinct in pipelines that
    /// separate authoring from rendering).
    pub pdf_producer: Option<String>,
    /// `pdf:Keywords` — same comma-separated list a PDF `/Info`
    /// dictionary's `/Keywords` would carry.
    pub pdf_keywords: Option<String>,
    /// `pdf:PDFVersion` — version of the PDF spec the file targets.
    pub pdf_version: Option<String>,
    /// `pdf:Trapped` — `True` / `False` / `Unknown` per Adobe's
    /// trapping convention.
    pub pdf_trapped: Option<String>,

    // ── PDF/A identification schema (`pdfaid:`,
    //     http://www.aiim.org/pdfa/ns/id/) ─────────────────────────
    /// `pdfaid:part` — PDF/A part (1, 2, 3, 4) per ISO 19005-x.
    pub pdfaid_part: Option<u8>,
    /// `pdfaid:conformance` — conformance level (`A`, `B`, `U`, `E`,
    /// `F`) per ISO 19005-x §6.x.
    pub pdfaid_conformance: Option<String>,
}

impl XmpPacket {
    /// Parse an XMP packet from the raw bytes returned by
    /// [`crate::reader::DocumentReader::xmp_metadata`]. Best-effort —
    /// missing fields surface as `None`, never errors.
    pub fn parse(bytes: &[u8]) -> Self {
        // Allow lossy UTF-8 — most XMP packets are ASCII-only or UTF-8;
        // a stray non-UTF-8 byte gets replaced with U+FFFD rather than
        // killing the whole parse.
        let owned;
        let s: &str = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                owned = String::from_utf8_lossy(bytes).into_owned();
                owned.as_str()
            }
        };

        Self {
            dc_title: extract_lang_alt(s, "dc:title").or_else(|| extract_attr(s, "dc:title")),
            dc_creator: extract_seq_first(s, "dc:creator")
                .or_else(|| extract_attr(s, "dc:creator")),
            dc_description: extract_lang_alt(s, "dc:description")
                .or_else(|| extract_attr(s, "dc:description")),
            dc_subject: extract_bag(s, "dc:subject"),
            dc_rights: extract_lang_alt(s, "dc:rights").or_else(|| extract_attr(s, "dc:rights")),
            dc_format: extract_text(s, "dc:format").or_else(|| extract_attr(s, "dc:format")),

            xmp_create_date: extract_text(s, "xmp:CreateDate")
                .or_else(|| extract_attr(s, "xmp:CreateDate")),
            xmp_modify_date: extract_text(s, "xmp:ModifyDate")
                .or_else(|| extract_attr(s, "xmp:ModifyDate")),
            xmp_metadata_date: extract_text(s, "xmp:MetadataDate")
                .or_else(|| extract_attr(s, "xmp:MetadataDate")),
            xmp_creator_tool: extract_text(s, "xmp:CreatorTool")
                .or_else(|| extract_attr(s, "xmp:CreatorTool")),

            pdf_producer: extract_text(s, "pdf:Producer")
                .or_else(|| extract_attr(s, "pdf:Producer")),
            pdf_keywords: extract_text(s, "pdf:Keywords")
                .or_else(|| extract_attr(s, "pdf:Keywords")),
            pdf_version: extract_text(s, "pdf:PDFVersion")
                .or_else(|| extract_attr(s, "pdf:PDFVersion")),
            pdf_trapped: extract_text(s, "pdf:Trapped").or_else(|| extract_attr(s, "pdf:Trapped")),

            pdfaid_part: extract_text(s, "pdfaid:part")
                .or_else(|| extract_attr(s, "pdfaid:part"))
                .and_then(|v| v.trim().parse::<u8>().ok()),
            pdfaid_conformance: extract_text(s, "pdfaid:conformance")
                .or_else(|| extract_attr(s, "pdfaid:conformance"))
                .map(|s| s.trim().to_string()),
        }
    }

    /// True when the packet declares a PDF/A identification (per
    /// ISO 19005-x §6.x) — at minimum `pdfaid:part` is set.
    pub fn is_pdf_a(&self) -> bool {
        self.pdfaid_part.is_some()
    }

    /// PDF/A conformance designator like `1B` or `2A` — concatenation
    /// of part + conformance — when both are declared.
    pub fn pdf_a_conformance(&self) -> Option<String> {
        Some(format!(
            "{}{}",
            self.pdfaid_part?,
            self.pdfaid_conformance.as_deref()?
        ))
    }
}

/// Find the inner text of `<ns:Tag>...</ns:Tag>`.
///
/// Skips packets without a matching open / close pair, returns the
/// trimmed inner text otherwise. The inner text is XML-entity-decoded.
fn extract_text(haystack: &str, tag: &str) -> Option<String> {
    // Build `<tag` and `</tag>` patterns. We accept `<tag>` (no
    // attributes) and `<tag attr="...">…` (with attributes).
    let open_pat = format!("<{}", tag);
    let close_pat = format!("</{}>", tag);
    let start_idx = haystack.find(&open_pat)?;
    // Walk past the open tag — find the next `>`.
    let after_open_name = start_idx + open_pat.len();
    // Reject `<tag-suffix>` matches (e.g. `dc:titleX`).
    let next_byte = haystack.as_bytes().get(after_open_name)?;
    if !is_tag_terminator(*next_byte) {
        // Try to find a later occurrence — keep searching.
        let rest_off = after_open_name;
        let rest = &haystack[rest_off..];
        if let Some(skip) = rest.find(&open_pat) {
            return extract_text(&haystack[rest_off + skip..], tag);
        }
        return None;
    }
    let close_brace_off = haystack[after_open_name..].find('>')? + after_open_name;
    // Self-closing form: `<tag .../>` — no inner text.
    if close_brace_off > 0 && haystack.as_bytes()[close_brace_off - 1] == b'/' {
        return None;
    }
    let body_start = close_brace_off + 1;
    let close_off = haystack[body_start..].find(&close_pat)? + body_start;
    let body = &haystack[body_start..close_off];
    Some(decode_entities(body.trim()))
}

/// Find an attribute value for `tag="value"` anywhere in the string.
///
/// Useful for the `<rdf:Description ns:Tag="value" .../>` shape that
/// XMP often uses for short fields.
fn extract_attr(haystack: &str, attr_name: &str) -> Option<String> {
    let pat = format!("{}=\"", attr_name);
    let mut search_from = 0usize;
    while let Some(rel) = haystack[search_from..].find(&pat) {
        let off = search_from + rel;
        // Make sure the byte before is a valid attr-separator (whitespace
        // or tag-open) — otherwise we matched a longer attribute name.
        if off > 0 {
            let prev = haystack.as_bytes()[off - 1];
            if !prev.is_ascii_whitespace() && prev != b'<' {
                search_from = off + pat.len();
                continue;
            }
        }
        let value_start = off + pat.len();
        let value_end = haystack[value_start..].find('"')? + value_start;
        return Some(decode_entities(&haystack[value_start..value_end]));
    }
    None
}

/// Find the first `<rdf:li>...</rdf:li>` inside `<ns:Tag><rdf:Alt>...`.
///
/// XMP's language-alternative pattern: dc:title etc. wrap their
/// localised values in `rdf:Alt`. The default-language entry is
/// usually first; we return its body. Falls back to plain
/// `extract_text` for tags that don't use the rdf:Alt wrapper.
fn extract_lang_alt(haystack: &str, tag: &str) -> Option<String> {
    let inner = extract_text(haystack, tag)?;
    extract_first_li(&inner).or(Some(inner))
}

/// Find the full `<rdf:Bag>` of `<rdf:li>...</rdf:li>` entries inside
/// `<ns:Tag>`.
fn extract_bag(haystack: &str, tag: &str) -> Vec<String> {
    let Some(inner) = extract_text(haystack, tag) else {
        return Vec::new();
    };
    extract_all_li(&inner)
}

/// Find the first `<rdf:li>...</rdf:li>` inside an `rdf:Seq` wrapper.
/// rdf:Seq is ordered; the first entry is the most-preferred value.
fn extract_seq_first(haystack: &str, tag: &str) -> Option<String> {
    let inner = extract_text(haystack, tag)?;
    extract_first_li(&inner).or(Some(inner))
}

fn extract_first_li(haystack: &str) -> Option<String> {
    extract_text(haystack, "rdf:li")
}

fn extract_all_li(haystack: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let open_pat = "<rdf:li";
    let close_pat = "</rdf:li>";
    while let Some(rel) = haystack[cursor..].find(open_pat) {
        let open_off = cursor + rel;
        let after_name = open_off + open_pat.len();
        let next_byte = match haystack.as_bytes().get(after_name) {
            Some(b) => *b,
            None => break,
        };
        if !is_tag_terminator(next_byte) {
            cursor = after_name;
            continue;
        }
        let Some(close_brace_rel) = haystack[after_name..].find('>') else {
            break;
        };
        let close_brace = after_name + close_brace_rel;
        // Self-closing — skip and advance.
        if close_brace > 0 && haystack.as_bytes()[close_brace - 1] == b'/' {
            cursor = close_brace + 1;
            continue;
        }
        let body_start = close_brace + 1;
        let Some(close_rel) = haystack[body_start..].find(close_pat) else {
            break;
        };
        let close_off = body_start + close_rel;
        out.push(decode_entities(haystack[body_start..close_off].trim()));
        cursor = close_off + close_pat.len();
    }
    out
}

fn is_tag_terminator(b: u8) -> bool {
    // After the tag *name*, any of: whitespace, attribute-sep `>`, or
    // self-close `/`. (`>` and `/` both signal end-of-name.)
    b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == b'>' || b == b'/'
}

/// Decode the standard five XML entities. Numeric character references
/// (`&#NNN;` / `&#xHEX;`) are also decoded for the BMP range.
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            // Push the byte; only ASCII reaches this branch when the
            // string is ASCII-only — for non-ASCII we restart at the
            // next `&` via the broader chunked path below.
            // To keep multi-byte UTF-8 sequences intact we use char
            // boundaries.
            let next_amp = s[i..].find('&').map(|p| i + p).unwrap_or(s.len());
            out.push_str(&s[i..next_amp]);
            i = next_amp;
            continue;
        }
        // Look for `;` within a small window.
        let semi = match s[i..(i + 12).min(s.len())].find(';') {
            Some(p) => i + p,
            None => {
                out.push('&');
                i += 1;
                continue;
            }
        };
        let entity = &s[i + 1..semi];
        let ch = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            other if other.starts_with('#') => {
                let body = &other[1..];
                let cp =
                    if let Some(hex) = body.strip_prefix('x').or_else(|| body.strip_prefix('X')) {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        body.parse::<u32>().ok()
                    };
                cp.and_then(char::from_u32)
            }
            _ => None,
        };
        match ch {
            Some(c) => {
                out.push(c);
                i = semi + 1;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY_XMP: &[u8] = br#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:xmp="http://ns.adobe.com/xap/1.0/"
        xmlns:pdf="http://ns.adobe.com/pdf/1.3/">
      <dc:title>
        <rdf:Alt>
          <rdf:li xml:lang="x-default">Tiny &amp; Test</rdf:li>
        </rdf:Alt>
      </dc:title>
      <dc:creator>
        <rdf:Seq>
          <rdf:li>Mark</rdf:li>
          <rdf:li>Other</rdf:li>
        </rdf:Seq>
      </dc:creator>
      <dc:subject>
        <rdf:Bag>
          <rdf:li>pdf</rdf:li>
          <rdf:li>xmp</rdf:li>
          <rdf:li>round-26</rdf:li>
        </rdf:Bag>
      </dc:subject>
      <xmp:CreateDate>2026-05-10T12:00:00Z</xmp:CreateDate>
      <xmp:CreatorTool>oxideav-pdf round 26</xmp:CreatorTool>
      <pdf:Producer>oxideav-pdf 0.1.x</pdf:Producer>
      <pdf:Keywords>foo,bar,baz</pdf:Keywords>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

    #[test]
    fn parses_dublin_core_title_through_lang_alt() {
        let p = XmpPacket::parse(TINY_XMP);
        assert_eq!(p.dc_title.as_deref(), Some("Tiny & Test"));
    }

    #[test]
    fn parses_dublin_core_creator_first_of_seq() {
        let p = XmpPacket::parse(TINY_XMP);
        assert_eq!(p.dc_creator.as_deref(), Some("Mark"));
    }

    #[test]
    fn parses_dublin_core_subject_bag_in_order() {
        let p = XmpPacket::parse(TINY_XMP);
        assert_eq!(p.dc_subject, vec!["pdf", "xmp", "round-26"]);
    }

    #[test]
    fn parses_xmp_basic_dates() {
        let p = XmpPacket::parse(TINY_XMP);
        assert_eq!(p.xmp_create_date.as_deref(), Some("2026-05-10T12:00:00Z"));
        assert_eq!(p.xmp_creator_tool.as_deref(), Some("oxideav-pdf round 26"));
    }

    #[test]
    fn parses_pdf_schema_producer_keywords() {
        let p = XmpPacket::parse(TINY_XMP);
        assert_eq!(p.pdf_producer.as_deref(), Some("oxideav-pdf 0.1.x"));
        assert_eq!(p.pdf_keywords.as_deref(), Some("foo,bar,baz"));
    }

    const PDFA_2B_XMP: &[u8] = br#"<?xpacket begin=""?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/">
  <pdfaid:part>2</pdfaid:part>
  <pdfaid:conformance>B</pdfaid:conformance>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

    #[test]
    fn detects_pdf_a_2b_conformance() {
        let p = XmpPacket::parse(PDFA_2B_XMP);
        assert!(p.is_pdf_a());
        assert_eq!(p.pdfaid_part, Some(2));
        assert_eq!(p.pdfaid_conformance.as_deref(), Some("B"));
        assert_eq!(p.pdf_a_conformance().as_deref(), Some("2B"));
    }

    const ATTR_FORM_XMP: &[u8] = br#"<?xpacket?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about=""
    xmlns:pdf="http://ns.adobe.com/pdf/1.3/"
    pdf:Producer="Inline Producer"
    pdf:Keywords="x,y,z"/>
</rdf:RDF>
</x:xmpmeta>"#;

    #[test]
    fn parses_pdf_producer_in_attribute_form() {
        let p = XmpPacket::parse(ATTR_FORM_XMP);
        assert_eq!(p.pdf_producer.as_deref(), Some("Inline Producer"));
        assert_eq!(p.pdf_keywords.as_deref(), Some("x,y,z"));
    }

    #[test]
    fn empty_input_yields_default() {
        let p = XmpPacket::parse(b"");
        assert_eq!(p, XmpPacket::default());
        assert!(!p.is_pdf_a());
    }

    #[test]
    fn entity_decode_handles_amp_lt_gt_quot_apos_and_numeric() {
        assert_eq!(decode_entities("a &amp; b"), "a & b");
        assert_eq!(decode_entities("&lt;tag&gt;"), "<tag>");
        assert_eq!(
            decode_entities("she said &quot;hi&quot;"),
            "she said \"hi\""
        );
        assert_eq!(decode_entities("it&apos;s"), "it's");
        assert_eq!(decode_entities("&#65;"), "A");
        assert_eq!(decode_entities("&#x4E2D;&#x6587;"), "中文");
    }

    #[test]
    fn extract_text_skips_close_only() {
        // `</dc:title>` without an opening tag must not match.
        let s = "<rdf:RDF></dc:title></rdf:RDF>";
        assert_eq!(extract_text(s, "dc:title"), None);
    }

    #[test]
    fn extract_text_handles_self_closing_form() {
        let s = r#"<rdf:Description xmlns:dc="..." dc:format="application/pdf"/>"#;
        // Self-closing — no inner text. Falls back to attribute form
        // at the call site.
        assert_eq!(extract_text(s, "dc:format"), None);
        assert_eq!(
            extract_attr(s, "dc:format").as_deref(),
            Some("application/pdf")
        );
    }

    #[test]
    fn extract_lang_alt_falls_back_to_plain_text() {
        // No rdf:Alt wrapper — return the trimmed body.
        let s = "<dc:title>Plain Body</dc:title>";
        assert_eq!(
            extract_lang_alt(s, "dc:title").as_deref(),
            Some("Plain Body")
        );
    }
}
