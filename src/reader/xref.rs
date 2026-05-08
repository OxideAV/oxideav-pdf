//! PDF cross-reference table + trailer parser (ISO 32000-1 §7.5.4–§7.5.5).
//!
//! Locates the `startxref` offset by scanning backwards from EOF
//! (the `%%EOF` / `startxref` / xref-offset triple is always near
//! the end of the file), then parses the cross-reference subsection
//! list at that offset and the immediately-following trailer dict.
//!
//! Two flavours of cross-reference table are accepted:
//!
//! * **Plain xref** (PDF 1.0..1.4) — the `xref` keyword followed by
//!   subsection headers and 20-byte entry lines, per §7.5.4.
//! * **XRef stream** (PDF 1.5+, §7.5.8) — the startxref offset points
//!   at an indirect object whose body is a stream with `/Type /XRef`,
//!   `/W [w1 w2 w3]` field widths, optional `/Index`, and optional
//!   `/Predictor 12` PNG-up filter on a `/FlateDecode` body. The
//!   stream's dict carries the same trailer-dict slots as the plain
//!   variant (`/Size`, `/Root`, `/Info`, `/Prev`, `/Encrypt`, `/ID`).
//!
//! [`XrefTable`] turns into a [`Document`] of resolved indirect
//! objects via the top-level walker — the intermediate type lets the
//! reader resolve indirect references on demand without re-parsing
//! every object up front.

use std::collections::HashMap;

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::reader::lex::{Lexer, TokenKind};
use crate::reader::parse::Parser;

/// One slot in the cross-reference table (§7.5.4 `Table 18` for plain
/// xref; §7.5.8 `Table 18` for the XRef-stream form which adds
/// `Compressed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefEntry {
    /// Free entry — points to the next free object via `next` and
    /// carries the generation number to use if the slot is reused.
    /// The head-of-list `0 65535 f` is the only `Free` we ever
    /// expect to encounter in writer-generated PDFs.
    Free { next: u32, generation: u16 },
    /// In-use entry — the indirect object is at `offset` bytes from
    /// the start of the file, with the given generation number.
    InUse { offset: u64, generation: u16 },
    /// Type 2 entry from an XRef stream — the object lives inside an
    /// object-stream container at `obj_stream_id`, occupying the slot
    /// at `index_within_stream`. The reader doesn't yet decode object
    /// streams (PDF 1.5+ `/Type /ObjStm`), but recording the entry
    /// keeps the xref shape lossless.
    Compressed {
        obj_stream_id: u32,
        index_within_stream: u32,
    },
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
    /// doesn't appear in the xref or its slot is `Free` / `Compressed`
    /// (the reader can't yet resolve compressed objects).
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
/// dict that follows it. Accepts both the plain `xref`-keyword form
/// (PDF 1.0..1.4, §7.5.4) and the XRef-stream form (PDF 1.5+, §7.5.8).
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

    // First token decides the flavour: `xref` keyword → plain table,
    // integer (the `<n> <gen> obj` of an XRef stream object) → §7.5.8.
    let kw = lex
        .next_token()?
        .ok_or_else(|| PdfError::other("PDF reader: empty xref table"))?;
    if let TokenKind::Integer(_) = kw.kind {
        // XRef stream: re-anchor and parse the indirect object at the
        // offset, then translate its body into a [`XrefTable`].
        return parse_xref_stream_at(input, xref_pos);
    }
    let TokenKind::Keyword(b"xref") = kw.kind else {
        return Err(PdfError::other(format!(
            "PDF reader: expected `xref` keyword or XRef stream object at offset {xref_offset} (got {:?})",
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

/// One-shot top-level: scan startxref offset → parse xref table,
/// then walk the trailer's `/Prev` chain (incremental updates;
/// ISO 32000-1 §7.5.6) merging older sections beneath. The newest
/// revision wins on overlap — a slot rewritten in revision N hides
/// the same slot from revision N-1.
///
/// The trailer dict returned belongs to the newest revision; the
/// `entries` map carries the merged view across all revisions.
pub fn parse_xref(input: &[u8]) -> Result<XrefTable, PdfError> {
    let mut current_off = find_startxref_offset(input)?;
    let mut newest = parse_xref_at(input, current_off)?;
    // The newest revision's table is correct for the slots it owns;
    // we only need to *fill in* slots that the newer revision didn't
    // re-declare.
    let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
    visited.insert(current_off);
    loop {
        let prev_off = newest
            .trailer
            .entries()
            .iter()
            .find(|(k, _)| k == "Prev")
            .and_then(|(_, v)| match v {
                Object::Integer(n) if *n >= 0 => Some(*n as u64),
                _ => None,
            });
        let Some(po) = prev_off else { break };
        if !visited.insert(po) {
            // Cycle in /Prev chain — refuse rather than loop forever.
            return Err(PdfError::other(
                "PDF reader: /Prev xref-section chain has a cycle",
            ));
        }
        if visited.len() > 32 {
            return Err(PdfError::other(
                "PDF reader: /Prev xref-section chain exceeds 32 hops — refusing",
            ));
        }
        let older = parse_xref_at(input, po)?;
        // Merge older entries beneath — only fill slots the newer
        // revision didn't declare. (HashMap::entry::or_insert
        // semantics.)
        for (id, entry) in older.entries {
            newest.entries.entry(id).or_insert(entry);
        }
        // Move /Prev into the in-progress trailer so the next loop
        // iteration sees the older section's /Prev (chains can be
        // longer than one hop).
        let mut next_trailer = older.trailer.clone();
        // Strip /Prev so we don't re-walk indefinitely if the older
        // section happened not to carry one. We keep the merged
        // table's trailer pointed at the newest revision's dict
        // values (above) — older.trailer is only used for its /Prev.
        next_trailer.set("Prev", Object::Null);
        // Record the older section's /Prev (if any) on the newest
        // table so the next loop iteration walks one more step.
        let older_prev = older
            .trailer
            .entries()
            .iter()
            .find(|(k, _)| k == "Prev")
            .and_then(|(_, v)| match v {
                Object::Integer(n) if *n >= 0 => Some(*n as u64),
                _ => None,
            });
        // Replace newest.trailer's /Prev with whatever the older
        // section pointed at (or remove it once chain ends).
        let mut new_trailer = Dict::new();
        for (k, v) in newest.trailer.entries() {
            if k != "Prev" {
                new_trailer.set(k, v.clone());
            }
        }
        if let Some(op) = older_prev {
            new_trailer.set("Prev", Object::Integer(op as i64));
        }
        newest.trailer = new_trailer;
        current_off = po;
    }
    let _ = current_off;
    Ok(newest)
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

/// Parse a PDF 1.5+ XRef stream object (§7.5.8) at the given byte
/// offset. Returns the same [`XrefTable`] shape the plain-xref parser
/// produces — the trailer dict pulls from the stream object's own
/// dictionary, and entries are decoded from the binary `/W`-formatted
/// body (after applying `/Filter` decoding + `/DecodeParms /Predictor`
/// reversal where present).
fn parse_xref_stream_at(input: &[u8], xref_pos: usize) -> Result<XrefTable, PdfError> {
    let mut p = Parser::new(input);
    p.lexer_mut().seek(xref_pos);
    let (_obj_id, body) = p.parse_indirect()?;
    let stream = match body {
        Object::Stream(s) => s,
        other => {
            return Err(PdfError::other(format!(
                "PDF reader: XRef stream object must be a Stream (got {other:?})"
            )));
        }
    };

    // The stream dict carries:
    //   /Type /XRef
    //   /Size  N            (one past the largest object number)
    //   /W     [w1 w2 w3]   (byte widths of the three fields per entry)
    //   /Index [s1 c1 ...]  (subsection list; default [0 Size])
    //   /Filter /FlateDecode
    //   /DecodeParms << /Predictor 12 /Columns N >> (optional)
    //   plus the standard trailer keys: /Root, /Info, /Encrypt, /Prev, /ID
    let dict = &stream.dict;
    let lookup = |k: &str| {
        dict.entries()
            .iter()
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.clone())
    };

    if !matches!(lookup("Type"), Some(Object::Name(ref n)) if n == "XRef") {
        return Err(PdfError::other(
            "PDF reader: XRef stream object missing /Type /XRef",
        ));
    }
    let size = match lookup("Size") {
        Some(Object::Integer(n)) if n >= 0 => n as u32,
        _ => return Err(PdfError::other("PDF reader: XRef stream missing /Size")),
    };
    let w = match lookup("W") {
        Some(Object::Array(items)) if items.len() == 3 => {
            let mut out = [0usize; 3];
            for (i, it) in items.iter().enumerate() {
                let Object::Integer(v) = it else {
                    return Err(PdfError::other(format!(
                        "PDF reader: XRef /W[{i}] must be an integer (got {it:?})"
                    )));
                };
                if *v < 0 || *v > 8 {
                    return Err(PdfError::other(format!(
                        "PDF reader: XRef /W[{i}] = {v} out of range [0..=8]"
                    )));
                }
                out[i] = *v as usize;
            }
            out
        }
        other => {
            return Err(PdfError::other(format!(
                "PDF reader: XRef stream /W must be a 3-array (got {other:?})"
            )));
        }
    };
    let index: Vec<(u32, u32)> = match lookup("Index") {
        Some(Object::Array(items)) => {
            if items.len() % 2 != 0 {
                return Err(PdfError::other(
                    "PDF reader: XRef /Index array length must be even",
                ));
            }
            items
                .chunks_exact(2)
                .map(|chunk| {
                    let (Object::Integer(s), Object::Integer(c)) = (&chunk[0], &chunk[1]) else {
                        return Err(PdfError::other(
                            "PDF reader: XRef /Index entries must be integers",
                        ));
                    };
                    if *s < 0 || *c < 0 {
                        return Err(PdfError::other(
                            "PDF reader: XRef /Index entries must be non-negative",
                        ));
                    }
                    Ok((*s as u32, *c as u32))
                })
                .collect::<Result<_, _>>()?
        }
        Some(other) => {
            return Err(PdfError::other(format!(
                "PDF reader: XRef /Index must be an array (got {other:?})"
            )));
        }
        None => vec![(0, size)],
    };

    // Step 1: apply /Filter (FlateDecode is the only one writers use).
    let raw = decode_xref_stream_body(&stream)?;

    // Step 2: undo predictor (PNG-up, /Predictor 12) if requested.
    let table_bytes = apply_predictor(&raw, dict, w[0] + w[1] + w[2])?;

    // Step 3: walk the binary table.
    let entry_size = w[0] + w[1] + w[2];
    if entry_size == 0 {
        return Err(PdfError::other(
            "PDF reader: XRef stream /W = [0 0 0] is degenerate",
        ));
    }
    let mut entries: HashMap<u32, XrefEntry> = HashMap::new();
    let mut cursor = 0usize;
    for (start, count) in &index {
        for offset_in_section in 0..*count {
            if cursor + entry_size > table_bytes.len() {
                return Err(PdfError::other(format!(
                    "PDF reader: XRef stream truncated at entry {start}+{offset_in_section} \
                     (cursor {cursor}, need {entry_size}, have {})",
                    table_bytes.len()
                )));
            }
            let chunk = &table_bytes[cursor..cursor + entry_size];
            cursor += entry_size;
            let (f1, f2, f3) = split_fields(chunk, w[0], w[1], w[2]);
            // f1 default = 1 when w[0] == 0 (§7.5.8.3).
            let kind = if w[0] == 0 { 1 } else { f1 };
            let id = start + offset_in_section;
            let entry = match kind {
                0 => XrefEntry::Free {
                    // f2 = next free obj number; f3 = generation.
                    next: f2 as u32,
                    generation: f3 as u16,
                },
                1 => XrefEntry::InUse {
                    offset: f2,
                    // /W default for w[2] is 0, in which case the spec
                    // says "0" generation.
                    generation: f3 as u16,
                },
                2 => XrefEntry::Compressed {
                    obj_stream_id: f2 as u32,
                    index_within_stream: f3 as u32,
                },
                other => {
                    return Err(PdfError::other(format!(
                        "PDF reader: XRef stream entry has unknown type {other} at id {id}"
                    )));
                }
            };
            entries.insert(id, entry);
        }
    }

    // The stream dict itself is the trailer dict (§7.5.8.2). Strip
    // entries that don't belong in a trailer (Length, Filter, etc.) so
    // downstream code can iterate it like a plain trailer.
    let trailer = filter_trailer_dict(dict);

    Ok(XrefTable { entries, trailer })
}

/// Apply the stream's `/Filter` to recover the raw xref bytes.
fn decode_xref_stream_body(stream: &crate::objects::Stream) -> Result<Vec<u8>, PdfError> {
    use std::io::Read;
    let filter = stream
        .dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Filter")
        .map(|(_, v)| v.clone());
    match filter {
        None => Ok(stream.data.clone()),
        Some(Object::Name(n)) if n == "FlateDecode" => {
            let mut dec = flate2::read::ZlibDecoder::new(stream.data.as_slice());
            let mut out = Vec::new();
            dec.read_to_end(&mut out).map_err(|e| {
                PdfError::other(format!("PDF reader: XRef stream FlateDecode failed: {e}"))
            })?;
            Ok(out)
        }
        Some(Object::Array(items)) => {
            // Filter chain — only FlateDecode is supported here.
            let mut data = stream.data.clone();
            for it in items {
                let Object::Name(n) = it else {
                    return Err(PdfError::other(
                        "PDF reader: XRef stream /Filter chain item must be a Name",
                    ));
                };
                if n != "FlateDecode" {
                    return Err(PdfError::other(format!(
                        "PDF reader: XRef stream filter `{n}` not supported"
                    )));
                }
                let mut dec = flate2::read::ZlibDecoder::new(data.as_slice());
                let mut out = Vec::new();
                dec.read_to_end(&mut out).map_err(|e| {
                    PdfError::other(format!("PDF reader: XRef stream FlateDecode failed: {e}"))
                })?;
                data = out;
            }
            Ok(data)
        }
        Some(Object::Name(n)) => Err(PdfError::other(format!(
            "PDF reader: XRef stream filter `{n}` not supported"
        ))),
        Some(other) => Err(PdfError::other(format!(
            "PDF reader: XRef stream /Filter must be a Name or array (got {other:?})"
        ))),
    }
}

/// Reverse PNG predictor 12 (PNG-up). The `up` predictor stores each
/// row as the byte-wise XOR difference from the previous row; the
/// stream's `/DecodeParms /Predictor` selects the active predictor and
/// `/Columns` gives the row width (in `/W` entry-bytes here).
///
/// Predictor values per §7.4.4.4:
/// * 1 = none (no transformation; pass through),
/// * 2 = TIFF predictor 2 (left differences — uncommon for xref),
/// * 10..=15 = PNG predictors with a 1-byte tag prefix per row.
///   Predictor 12 = PNG-Up. Predictor 15 = "optimum" — every row's
///   tag picks one of the five PNG predictors.
fn apply_predictor(raw: &[u8], dict: &Dict, entry_width: usize) -> Result<Vec<u8>, PdfError> {
    let parms = dict.entries().iter().find(|(k, _)| k == "DecodeParms");
    let Some((_, parms_obj)) = parms else {
        // No DecodeParms — assume Predictor 1 (no transformation).
        return Ok(raw.to_vec());
    };
    let Object::Dict(parms_dict) = parms_obj else {
        return Err(PdfError::other("PDF reader: /DecodeParms must be a dict"));
    };
    let predictor = parms_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Predictor")
        .map(|(_, v)| v.clone());
    let columns = parms_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Columns")
        .map(|(_, v)| v.clone());
    let p = match predictor {
        Some(Object::Integer(n)) => n,
        None => 1,
        other => {
            return Err(PdfError::other(format!(
                "PDF reader: /Predictor must be an integer (got {other:?})"
            )));
        }
    };
    if p == 1 {
        return Ok(raw.to_vec());
    }
    let columns = match columns {
        Some(Object::Integer(n)) if n > 0 => n as usize,
        Some(other) => {
            return Err(PdfError::other(format!(
                "PDF reader: /Columns must be a positive integer (got {other:?})"
            )));
        }
        // Default per §7.4.4.4 is 1, but for XRef streams the columns
        // width is the per-entry width.
        None => entry_width,
    };
    if !(10..=15).contains(&p) {
        return Err(PdfError::other(format!(
            "PDF reader: /Predictor {p} not yet supported (only PNG predictors 10..=15)"
        )));
    }
    // PNG predictors store one tag byte per row + `columns` data bytes.
    let row_size = columns + 1;
    if raw.len() % row_size != 0 {
        return Err(PdfError::other(format!(
            "PDF reader: predictor row size {row_size} doesn't divide raw len {}",
            raw.len()
        )));
    }
    let row_count = raw.len() / row_size;
    let mut out = Vec::with_capacity(row_count * columns);
    let mut prev_row = vec![0u8; columns];
    for row_idx in 0..row_count {
        let row = &raw[row_idx * row_size..(row_idx + 1) * row_size];
        let tag = row[0];
        let data = &row[1..];
        let mut decoded_row = vec![0u8; columns];
        match tag {
            0 => {
                // None.
                decoded_row.copy_from_slice(data);
            }
            1 => {
                // Sub: each byte = data[i] + decoded[i-1].
                for i in 0..columns {
                    let left = if i == 0 { 0 } else { decoded_row[i - 1] };
                    decoded_row[i] = data[i].wrapping_add(left);
                }
            }
            2 => {
                // Up: data[i] + prev_row[i].
                for i in 0..columns {
                    decoded_row[i] = data[i].wrapping_add(prev_row[i]);
                }
            }
            3 => {
                // Average: data[i] + floor((left + up) / 2).
                for i in 0..columns {
                    let left = if i == 0 {
                        0u16
                    } else {
                        decoded_row[i - 1] as u16
                    };
                    let up = prev_row[i] as u16;
                    decoded_row[i] = data[i].wrapping_add(((left + up) / 2) as u8);
                }
            }
            4 => {
                // Paeth.
                for i in 0..columns {
                    let left = if i == 0 {
                        0i16
                    } else {
                        decoded_row[i - 1] as i16
                    };
                    let up = prev_row[i] as i16;
                    let upper_left = if i == 0 { 0i16 } else { prev_row[i - 1] as i16 };
                    let p_pred = paeth_predictor(left, up, upper_left);
                    decoded_row[i] = data[i].wrapping_add(p_pred);
                }
            }
            other => {
                return Err(PdfError::other(format!(
                    "PDF reader: PNG predictor row tag {other} unknown"
                )));
            }
        }
        out.extend_from_slice(&decoded_row);
        prev_row = decoded_row;
    }
    Ok(out)
}

fn paeth_predictor(a: i16, b: i16, c: i16) -> u8 {
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    let r = if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    };
    r as u8
}

/// Read three big-endian integer fields of variable byte width from a
/// chunk of bytes. Sized like a u64 — XRef field widths are bounded
/// at 8 bytes per §7.5.8.3.
fn split_fields(chunk: &[u8], w1: usize, w2: usize, w3: usize) -> (u64, u64, u64) {
    fn read_be(s: &[u8]) -> u64 {
        let mut v: u64 = 0;
        for &b in s {
            v = (v << 8) | (b as u64);
        }
        v
    }
    let f1 = read_be(&chunk[..w1]);
    let f2 = read_be(&chunk[w1..w1 + w2]);
    let f3 = read_be(&chunk[w1 + w2..w1 + w2 + w3]);
    (f1, f2, f3)
}

/// Strip stream-only keys from an XRef-stream dictionary so it's safe
/// to treat as a trailer. The omitted keys are the ones that describe
/// the stream payload itself, not document-level metadata.
fn filter_trailer_dict(dict: &Dict) -> Dict {
    let stream_only = [
        "Type",
        "Filter",
        "DecodeParms",
        "Length",
        "F",
        "FFilter",
        "FDecodeParms",
        "DL",
        "W",
        "Index",
    ];
    let mut out = Dict::new();
    for (k, v) in dict.entries() {
        if !stream_only.contains(&k.as_str()) {
            out.set(k, v.clone());
        }
    }
    out
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
