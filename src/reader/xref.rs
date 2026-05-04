//! PDF cross-reference table + trailer parser (ISO 32000-1 §7.5.4–§7.5.5).
//!
//! Locates the `startxref` offset by scanning backwards from EOF
//! (the `%%EOF` / `startxref` / xref-offset triple is always near
//! the end of the file), then parses the cross-reference subsection
//! list at that offset and the immediately-following trailer dict.
//!
//! Round 3 supports only **plain** xref tables (the `xref` keyword
//! followed by subsection headers and 20-byte entry lines, per §7.5.4).
//! Cross-reference *streams* (PDF 1.5+ — `/Type /XRef`) are deferred
//! to round 4+; see the crate README for the full list of round-3
//! deferrals.
//!
//! [`XrefTable`] turns into a [`Document`] of resolved indirect
//! objects via [`Document::from_bytes`] (round-3 commit 5). The
//! intermediate type lets the upcoming top-level walker resolve
//! indirect references on demand without re-parsing every object up
//! front.

use std::collections::HashMap;

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::reader::lex::{Lexer, TokenKind};
use crate::reader::parse::Parser;

/// One slot in the cross-reference table (§7.5.4 `Table 18`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefEntry {
    /// Free entry — points to the next free object via `next` and
    /// carries the generation number to use if the slot is reused.
    /// Round 3 doesn't read free entries beyond noting they exist;
    /// the head-of-list `0 65535 f` is the only `Free` we ever
    /// expect to encounter in writer-generated PDFs.
    Free { next: u32, generation: u16 },
    /// In-use entry — the indirect object is at `offset` bytes from
    /// the start of the file, with the given generation number.
    InUse { offset: u64, generation: u16 },
}

/// A parsed cross-reference table + trailer dict.
#[derive(Debug, Clone, Default)]
pub struct XrefTable {
    /// Object number → entry. Sparse — a 50-object PDF doesn't need
    /// 50 vec slots if some are never referenced.
    pub entries: HashMap<u32, XrefEntry>,
    /// The trailer dictionary that follows the xref subsection list.
    /// Carries `/Size`, `/Root`, optionally `/Info`, `/Prev`, `/ID`.
    pub trailer: Dict,
}

impl XrefTable {
    /// Look up the byte offset of an object by id. `None` if the id
    /// doesn't appear in the xref or its slot is `Free`.
    pub fn offset_of(&self, id: ObjectId) -> Option<u64> {
        match self.entries.get(&id.number)? {
            XrefEntry::InUse { offset, generation } if *generation == id.generation => {
                Some(*offset)
            }
            _ => None,
        }
    }

    /// Walk the trailer for the `/Root` reference. Returns
    /// `PdfError::Other` when missing — every conforming PDF must
    /// carry one (§7.5.5 Table 15).
    pub fn root(&self) -> Result<ObjectId, PdfError> {
        match self
            .trailer
            .entries()
            .iter()
            .find(|(k, _)| k == "Root")
            .map(|(_, v)| v)
        {
            Some(Object::Reference(id)) => Ok(*id),
            Some(other) => Err(PdfError::other(format!(
                "PDF reader: trailer /Root must be an indirect reference (got {other:?})"
            ))),
            None => Err(PdfError::other(
                "PDF reader: trailer is missing the required /Root entry",
            )),
        }
    }

    /// Optional `/Info` reference from the trailer. `None` when the
    /// PDF has no document-level info dict.
    pub fn info(&self) -> Option<ObjectId> {
        self.trailer
            .entries()
            .iter()
            .find(|(k, _)| k == "Info")
            .and_then(|(_, v)| match v {
                Object::Reference(id) => Some(*id),
                _ => None,
            })
    }
}

/// Locate the `startxref` byte-offset by scanning backwards from EOF
/// for the `startxref` keyword. The PDF spec requires the trailer to
/// end within the last 1024 bytes (Acrobat convention) — we scan the
/// last 4096 to be tolerant of unusually long trailers.
pub fn find_startxref_offset(input: &[u8]) -> Result<u64, PdfError> {
    if !input.contains(&b'%') {
        return Err(PdfError::other(
            "PDF reader: input has no `%` byte — does not look like a PDF",
        ));
    }
    let scan_start = input.len().saturating_sub(4096);
    let tail = &input[scan_start..];
    let needle = b"startxref";
    let local_pos = (0..tail.len().saturating_sub(needle.len()))
        .rev()
        .find(|&i| &tail[i..i + needle.len()] == needle)
        .ok_or_else(|| {
            PdfError::other(
                "PDF reader: no `startxref` keyword in last 4096 bytes — file truncated?",
            )
        })?;
    // Parse the integer that follows the keyword.
    let mut p = Parser::new(&input[scan_start + local_pos + needle.len()..]);
    let obj = p.parse_object()?.ok_or_else(|| {
        PdfError::other("PDF reader: `startxref` keyword has no offset following it")
    })?;
    let Object::Integer(n) = obj else {
        return Err(PdfError::other(format!(
            "PDF reader: `startxref` offset must be an integer (got {obj:?})"
        )));
    };
    if n < 0 {
        return Err(PdfError::other(format!(
            "PDF reader: `startxref` offset is negative ({n})"
        )));
    }
    Ok(n as u64)
}

/// Parse the cross-reference table at `xref_offset` and the trailer
/// dict that follows it.
pub fn parse_xref_at(input: &[u8], xref_offset: u64) -> Result<XrefTable, PdfError> {
    let xref_pos = xref_offset as usize;
    if xref_pos >= input.len() {
        return Err(PdfError::other(format!(
            "PDF reader: startxref offset {xref_offset} past end of file ({} bytes)",
            input.len()
        )));
    }

    let mut lex = Lexer::new(input);
    lex.seek(xref_pos);

    // First token must be the `xref` keyword.
    let kw = lex
        .next_token()?
        .ok_or_else(|| PdfError::other("PDF reader: empty xref table"))?;
    let TokenKind::Keyword(b"xref") = kw.kind else {
        return Err(PdfError::other(format!(
            "PDF reader: expected `xref` keyword at offset {xref_offset} (got {:?})",
            kw.kind
        )));
    };

    let mut entries: HashMap<u32, XrefEntry> = HashMap::new();
    loop {
        // Header line: `<first> <count>` integers, OR the `trailer`
        // keyword that ends the xref table.
        let next_tok = lex
            .next_token()?
            .ok_or_else(|| PdfError::other("PDF reader: truncated xref table"))?;
        let first = match next_tok.kind {
            TokenKind::Integer(n) => n,
            TokenKind::Keyword(b"trailer") => break,
            other => {
                return Err(PdfError::other(format!(
                    "PDF reader: expected xref subsection header or `trailer` (got {other:?}) at byte {}",
                    next_tok.start
                )));
            }
        };
        let count_tok = lex
            .next_token()?
            .ok_or_else(|| PdfError::other("PDF reader: xref subsection has no count"))?;
        let TokenKind::Integer(count) = count_tok.kind else {
            return Err(PdfError::other(format!(
                "PDF reader: xref subsection count must be an integer at byte {} (got {:?})",
                count_tok.start, count_tok.kind
            )));
        };
        if first < 0 || count < 0 {
            return Err(PdfError::other(format!(
                "PDF reader: negative xref subsection header `{first} {count}`"
            )));
        }
        // Each entry is exactly 20 bytes per §7.5.4: 10-digit offset,
        // ' ', 5-digit generation, ' ', 'n'/'f', 2-byte EOL. The
        // lexer's whitespace handling makes byte-precise parsing
        // tricky — we step the cursor and slice raw 20-byte windows.
        // Skip any whitespace between the count and the first entry.
        skip_whitespace(input, &mut lex);
        for i in 0..count {
            let off = lex.position();
            if off + 20 > input.len() {
                return Err(PdfError::other(format!(
                    "PDF reader: xref entry {first}+{i} truncated at byte {off}"
                )));
            }
            let entry = &input[off..off + 20];
            let parsed = parse_xref_entry(entry, off)?;
            entries.insert(first as u32 + i as u32, parsed);
            lex.seek(off + 20);
        }
    }

    // After the `trailer` keyword, the next object is the trailer dict.
    let mut p = Parser::from_lexer(lex);
    let dict_obj = p
        .parse_object()?
        .ok_or_else(|| PdfError::other("PDF reader: trailer dict missing"))?;
    let Object::Dict(trailer) = dict_obj else {
        return Err(PdfError::other(format!(
            "PDF reader: trailer dict must be a dictionary (got {dict_obj:?})"
        )));
    };

    Ok(XrefTable { entries, trailer })
}

/// One-shot top-level: scan startxref offset → parse xref table.
pub fn parse_xref(input: &[u8]) -> Result<XrefTable, PdfError> {
    let off = find_startxref_offset(input)?;
    parse_xref_at(input, off)
}

fn skip_whitespace(input: &[u8], lex: &mut Lexer<'_>) {
    let mut p = lex.position();
    while p < input.len()
        && (input[p] == b' ' || input[p] == b'\t' || input[p] == b'\r' || input[p] == b'\n')
    {
        p += 1;
    }
    lex.seek(p);
}

fn parse_xref_entry(bytes: &[u8], at: usize) -> Result<XrefEntry, PdfError> {
    debug_assert_eq!(bytes.len(), 20);
    // Format: NNNNNNNNNN GGGGG (n|f) EOL  (10 + 1 + 5 + 1 + 1 + 2 = 20)
    if bytes[10] != b' ' || bytes[16] != b' ' {
        return Err(PdfError::other(format!(
            "PDF reader: malformed xref entry at byte {at} (missing space separators)"
        )));
    }
    let off_str = std::str::from_utf8(&bytes[..10])
        .map_err(|_| PdfError::other(format!("PDF reader: non-ASCII xref offset at byte {at}")))?;
    let off: u64 = off_str.trim().parse().map_err(|_| {
        PdfError::other(format!(
            "PDF reader: invalid xref offset `{off_str}` at byte {at}"
        ))
    })?;
    let gen_str = std::str::from_utf8(&bytes[11..16]).map_err(|_| {
        PdfError::other(format!(
            "PDF reader: non-ASCII xref generation at byte {at}"
        ))
    })?;
    let generation: u16 = gen_str.trim().parse().map_err(|_| {
        PdfError::other(format!(
            "PDF reader: invalid xref generation `{gen_str}` at byte {at}"
        ))
    })?;
    let kind = bytes[17];
    match kind {
        b'n' => Ok(XrefEntry::InUse {
            offset: off,
            generation,
        }),
        b'f' => Ok(XrefEntry::Free {
            next: off as u32,
            generation,
        }),
        other => Err(PdfError::other(format!(
            "PDF reader: xref entry kind must be `n` or `f` at byte {at} (got `{}`)",
            other as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::write_pdf;
    use oxideav_core::time::TimeBase;
    use oxideav_core::vector::{
        FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
    };

    fn sample_pdf_bytes() -> Vec<u8> {
        let mut p = Path::new();
        p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
        p.commands.push(PathCommand::LineTo(Point::new(90.0, 10.0)));
        p.commands.push(PathCommand::LineTo(Point::new(90.0, 90.0)));
        p.commands.push(PathCommand::Close);
        let frame = VectorFrame {
            width: 100.0,
            height: 100.0,
            view_box: None,
            root: Group {
                children: vec![Node::Path(PathNode {
                    path: p,
                    fill: Some(Paint::Solid(Rgba::opaque(0, 128, 255))),
                    stroke: None,
                    fill_rule: FillRule::NonZero,
                })],
                ..Group::default()
            },
            pts: None,
            time_base: TimeBase::new(1, 1),
        };
        write_pdf(&frame).expect("write_pdf")
    }

    #[test]
    fn finds_startxref_in_writer_output() {
        let pdf = sample_pdf_bytes();
        let off = find_startxref_offset(&pdf).expect("startxref");
        assert!(off > 0);
        // The xref keyword must live exactly there.
        assert_eq!(&pdf[off as usize..off as usize + 4], b"xref");
    }

    #[test]
    fn parses_xref_table_for_writer_output() {
        let pdf = sample_pdf_bytes();
        let table = parse_xref(&pdf).expect("parse_xref");
        // Round-1 single-page docs have 5 indirect objects (catalog,
        // pages, page, resources, contents) — id 0 is the free-list
        // head, so entries count = 6.
        assert!(table.entries.len() >= 5);
        // The free-list head at id 0.
        assert!(matches!(
            table.entries.get(&0),
            Some(XrefEntry::Free {
                generation: 65535,
                ..
            })
        ));
        // Every other entry is in-use.
        for i in 1..=5 {
            assert!(
                matches!(table.entries.get(&i), Some(XrefEntry::InUse { .. })),
                "entry {i} should be InUse"
            );
        }
        // Trailer references /Root → catalog (id 1).
        let root = table.root().expect("trailer /Root");
        assert_eq!(root.number, 1);
    }

    #[test]
    fn xref_offset_lookup_round_trips() {
        let pdf = sample_pdf_bytes();
        let table = parse_xref(&pdf).expect("parse_xref");
        // Each in-use entry's offset must point at the start of the
        // matching `<n> <gen> obj` header.
        for (id_num, entry) in &table.entries {
            if let XrefEntry::InUse { offset, generation } = entry {
                let pos = *offset as usize;
                assert!(pos < pdf.len(), "offset out of range for id {id_num}");
                let expected = format!("{} {} obj", id_num, generation);
                let slice = &pdf[pos..(pos + expected.len()).min(pdf.len())];
                assert_eq!(
                    slice,
                    expected.as_bytes(),
                    "object {id_num} {generation} obj should be at offset {offset}"
                );
            }
        }
    }

    #[test]
    fn root_required_for_well_formed_pdf() {
        let pdf = sample_pdf_bytes();
        let table = parse_xref(&pdf).expect("parse_xref");
        let _ = table.root().expect("/Root must resolve");
    }

    #[test]
    fn info_optional() {
        // The round-1 writer doesn't emit an /Info entry, so this PDF
        // returns None.
        let pdf = sample_pdf_bytes();
        let table = parse_xref(&pdf).expect("parse_xref");
        assert!(table.info().is_none());
    }

    #[test]
    fn rejects_truncated_input() {
        let pdf = b"not even a pdf";
        let r = parse_xref(pdf);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_startxref_off_end_of_file() {
        // Locate the startxref byte position in the writer's output
        // (PDF starts with the binary marker so `from_utf8` would
        // fail — we scan as bytes).
        let mut pdf = sample_pdf_bytes();
        let needle = b"startxref";
        let pos = pdf
            .windows(needle.len())
            .rposition(|w| w == needle)
            .expect("startxref present");
        // Truncate at the keyword and re-append a huge offset.
        pdf.truncate(pos);
        pdf.extend_from_slice(b"startxref\n999999999\n%%EOF\n");
        let r = parse_xref(&pdf);
        assert!(r.is_err());
    }
}
