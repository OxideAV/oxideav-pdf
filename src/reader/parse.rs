//! PDF object parser — [`Lexer`] tokens → [`Object`] tree.
//!
//! Round-3 Commit 2: builds on [`crate::reader::lex`] to recognise
//! every variant the writer can emit (numbers, names, strings,
//! arrays, dicts, indirect references, stream objects, null).
//!
//! Streams are matched by the trailing `stream`+EOL marker per ISO
//! 32000-1 §7.3.8. The body is sliced verbatim from the input — no
//! filter decoding here; the reader's stream object handler (round-3
//! commit 4) re-runs FlateDecode if the dictionary's `/Filter` says
//! so.
//!
//! Object streams (PDF 1.5+, `/Type /ObjStm`) are deliberately out of
//! scope for round 3 — the writer doesn't emit them and parsing them
//! requires a full /XRef stream walker. Round-4+.

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId, Stream};
use crate::reader::lex::{Lexer, Token, TokenKind};

/// Caller-supplied hook that resolves an indirect `/Length` reference
/// on a stream dictionary to the underlying integer.
///
/// ISO 32000-1 §7.3.10 Example 3 makes indirect `/Length` normative on
/// stream objects: a one-pass writer that doesn't know the encoded
/// stream size up front emits `<< /Length 8 0 R >>` and writes the
/// length-carrying integer object after the stream. A reader walking
/// such a PDF needs the xref table to fetch the integer.
///
/// The trait receives the [`ObjectId`] from the reference and is
/// expected to return the resolved integer (or a [`PdfError`] when the
/// target is missing / not an integer / a cycle is detected). Using a
/// trait (rather than a free `FnMut`) sidesteps the lifetime
/// gymnastics needed to thread an `Option<&mut dyn FnMut>` through
/// multiple recursive parse helpers — implementers just write a tiny
/// struct holding the borrowed state they need.
///
/// When the resolver is the unit no-op [`NoLengthResolver`] (the
/// [`Parser::parse_indirect`] / [`Parser::parse_object`] entry
/// points), an indirect `/Length` is rejected — that path is reserved
/// for xref-stream parsing, where the xref isn't built yet and the
/// spec (§7.5.8) effectively requires the direct-integer form anyway.
pub trait LengthResolver {
    /// Resolve the integer carried by the indirect object at
    /// `length_ref`. Returning `Err(_)` flows up the parse stack and
    /// aborts the stream-object decode.
    fn resolve_length(&mut self, length_ref: ObjectId) -> Result<i64, PdfError>;
}

/// No-op [`LengthResolver`] — every indirect `/Length` is rejected.
/// Used by [`Parser::parse_indirect`] and [`Parser::parse_object`] on
/// code paths where the xref table isn't built yet (the xref-stream
/// parser, the `parse_xref_stream_at` helper).
pub struct NoLengthResolver;

impl LengthResolver for NoLengthResolver {
    fn resolve_length(&mut self, _length_ref: ObjectId) -> Result<i64, PdfError> {
        Err(PdfError::other(
            "PDF parser: stream /Length is an indirect reference but no resolver \
             was supplied (call parse_indirect_with_length_resolver)",
        ))
    }
}

/// Blanket impl so closures with the same signature work as
/// [`LengthResolver`]s without writing a struct.
impl<F> LengthResolver for F
where
    F: FnMut(ObjectId) -> Result<i64, PdfError>,
{
    fn resolve_length(&mut self, length_ref: ObjectId) -> Result<i64, PdfError> {
        (self)(length_ref)
    }
}

/// Recursive-descent parser over a [`Lexer`].
pub struct Parser<'a> {
    lex: Lexer<'a>,
    /// Lookahead slot — when [`Self::peek`] reads a token, it stores
    /// it here so the next [`Self::next`] returns it instead of
    /// pulling from the lexer. Matches the conventional 1-token
    /// lookahead recursive-descent shape.
    peeked: Option<Token<'a>>,
}

impl<'a> Parser<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            lex: Lexer::new(input),
            peeked: None,
        }
    }

    /// Construct from an existing [`Lexer`] — used by the xref /
    /// trailer scanner so the same cursor state is shared.
    pub fn from_lexer(lex: Lexer<'a>) -> Self {
        Self { lex, peeked: None }
    }

    /// Borrow the underlying lexer (for `seek` / `slice` / `position`).
    pub fn lexer_mut(&mut self) -> &mut Lexer<'a> {
        // Drop any peeked token — its position cache is stale once the
        // caller moves the cursor.
        self.peeked = None;
        &mut self.lex
    }

    /// Current byte position. Returns the start of the peeked token
    /// when one is buffered (so the position reflects "the next
    /// token's start", not "wherever the lexer happens to be").
    pub fn position(&self) -> usize {
        if let Some(t) = &self.peeked {
            t.start
        } else {
            self.lex.position()
        }
    }

    fn next(&mut self) -> Result<Option<Token<'a>>, PdfError> {
        if let Some(t) = self.peeked.take() {
            return Ok(Some(t));
        }
        self.lex.next_token()
    }

    fn peek(&mut self) -> Result<Option<&Token<'a>>, PdfError> {
        if self.peeked.is_none() {
            self.peeked = self.lex.next_token()?;
        }
        Ok(self.peeked.as_ref())
    }

    /// Parse one [`Object`]. Returns `None` if the input is exhausted.
    ///
    /// Streams encountered with an indirect `/Length` (a `Reference`
    /// value rather than a direct integer) are rejected — call
    /// [`Self::parse_object_with_length_resolver`] from a context that
    /// can resolve the reference (typically the top-level
    /// [`crate::reader::document::DocumentReader::resolve`]).
    pub fn parse_object(&mut self) -> Result<Option<Object>, PdfError> {
        self.parse_object_with_length_resolver(&mut NoLengthResolver)
    }

    /// Variant of [`Self::parse_object`] that accepts a
    /// [`LengthResolver`] to resolve indirect `/Length` references on
    /// stream-object dictionaries per ISO 32000-1 §7.3.10 Example 3.
    pub fn parse_object_with_length_resolver(
        &mut self,
        resolver: &mut dyn LengthResolver,
    ) -> Result<Option<Object>, PdfError> {
        let Some(tok) = self.next()? else {
            return Ok(None);
        };
        Ok(Some(self.object_from_token(tok, resolver)?))
    }

    fn object_from_token(
        &mut self,
        tok: Token<'a>,
        resolver: &mut dyn LengthResolver,
    ) -> Result<Object, PdfError> {
        match tok.kind {
            TokenKind::Integer(n) => self.maybe_indirect_ref(n, tok.end),
            TokenKind::Real(f) => Ok(Object::Real(f)),
            TokenKind::Name(bytes) => Ok(Object::Name(String::from_utf8(bytes).map_err(|_| {
                PdfError::other(format!("PDF parser: non-UTF-8 name at byte {}", tok.start))
            })?)),
            TokenKind::LiteralString(bytes) => Ok(Object::LiteralString(bytes)),
            TokenKind::HexString(bytes) => Ok(Object::HexString(bytes)),
            TokenKind::ArrayStart => self.parse_array(resolver),
            TokenKind::DictStart => self.parse_dict_or_stream(tok.start, resolver),
            TokenKind::Keyword(kw) => match kw {
                b"true" => Ok(Object::Bool(true)),
                b"false" => Ok(Object::Bool(false)),
                b"null" => Ok(Object::Null),
                other => Err(PdfError::other(format!(
                    "PDF parser: unexpected keyword `{}` at byte {}",
                    String::from_utf8_lossy(other),
                    tok.start
                ))),
            },
            TokenKind::ArrayEnd => Err(PdfError::other(format!(
                "PDF parser: unexpected `]` at byte {}",
                tok.start
            ))),
            TokenKind::DictEnd => Err(PdfError::other(format!(
                "PDF parser: unexpected `>>` at byte {}",
                tok.start
            ))),
        }
    }

    /// An integer at the start of an object can be the front of an
    /// indirect reference (`<num> <gen> R`). Pull the next two tokens
    /// non-destructively and only consume them if they form `int int
    /// R`; otherwise fall back to a plain integer.
    fn maybe_indirect_ref(&mut self, n: i64, _start_end: usize) -> Result<Object, PdfError> {
        // We can't easily peek 2 ahead without nesting Option<Option<…>>.
        // Save the lexer position so we can roll back if the
        // lookahead doesn't match.
        let saved_pos = self.lex.position();
        let saved_peeked = self.peeked.clone();

        let t2 = self.next()?;
        let Some(t2) = t2 else {
            // EOF after the int — not a ref.
            return Ok(Object::Integer(n));
        };
        let TokenKind::Integer(gen) = t2.kind else {
            // Not int int — restore and emit Integer.
            self.peeked = Some(t2);
            // (saved positions don't need restoring — peeked covers
            // the next-token slot)
            let _ = saved_pos;
            let _ = saved_peeked;
            return Ok(Object::Integer(n));
        };
        let t3 = self.next()?;
        let Some(t3) = t3 else {
            // We've consumed gen — can't put two tokens back. Restore
            // via lexer rewind.
            self.lex.seek(saved_pos);
            self.peeked = saved_peeked;
            return Ok(Object::Integer(n));
        };
        let TokenKind::Keyword(b"R") = t3.kind else {
            // Not a ref — restore both consumed tokens by rewinding
            // the lexer to where we were before we touched it.
            self.lex.seek(saved_pos);
            self.peeked = saved_peeked;
            return Ok(Object::Integer(n));
        };
        if n < 1 || n > u32::MAX as i64 || gen < 0 || gen > u16::MAX as i64 {
            return Err(PdfError::other(format!(
                "PDF parser: indirect ref out of range `{n} {gen} R`"
            )));
        }
        Ok(Object::Reference(ObjectId {
            number: n as u32,
            generation: gen as u16,
        }))
    }

    fn parse_array(&mut self, resolver: &mut dyn LengthResolver) -> Result<Object, PdfError> {
        let mut items = Vec::new();
        loop {
            let tok = self.next()?.ok_or_else(|| {
                PdfError::other("PDF parser: unterminated array (EOF before `]`)")
            })?;
            if let TokenKind::ArrayEnd = tok.kind {
                return Ok(Object::Array(items));
            }
            items.push(self.object_from_token(tok, resolver)?);
        }
    }

    fn parse_dict_or_stream(
        &mut self,
        start: usize,
        resolver: &mut dyn LengthResolver,
    ) -> Result<Object, PdfError> {
        let mut dict = Dict::new();
        loop {
            let tok = self.next()?.ok_or_else(|| {
                PdfError::other(format!(
                    "PDF parser: unterminated dict starting at byte {start} (EOF before `>>`)"
                ))
            })?;
            if let TokenKind::DictEnd = tok.kind {
                break;
            }
            // Key must be a Name.
            let TokenKind::Name(key_bytes) = tok.kind else {
                return Err(PdfError::other(format!(
                    "PDF parser: dict key must be a Name at byte {} (got {:?})",
                    tok.start, tok.kind
                )));
            };
            let key = String::from_utf8(key_bytes).map_err(|_| {
                PdfError::other(format!(
                    "PDF parser: non-UTF-8 dict key at byte {}",
                    tok.start
                ))
            })?;
            // Value. Note: nested dict / array values inside a stream
            // dictionary are themselves direct objects (§7.3.8.1 — the
            // stream dict shall be a direct object). The resolver only
            // applies to the top-level /Length lookup, so nested calls
            // pass `None`.
            let val = self.parse_object()?.ok_or_else(|| {
                PdfError::other(format!(
                    "PDF parser: dict key `{key}` at byte {} has no value",
                    tok.start
                ))
            })?;
            dict.set(&key, val);
        }
        // Check whether this dict is a stream header — `stream` keyword
        // immediately follows (after optional whitespace).
        let after = self.peek()?.cloned();
        if let Some(t) = after {
            if let TokenKind::Keyword(b"stream") = t.kind {
                // Consume the `stream` keyword.
                let _ = self.next()?;
                // Per §7.3.8.1, the stream data starts immediately
                // after the EOL marker that follows the `stream`
                // keyword. The marker is CRLF or just LF.
                let raw = self.lex.input();
                let mut data_start = t.end;
                if data_start < raw.len() && raw[data_start] == b'\r' {
                    data_start += 1;
                }
                if data_start < raw.len() && raw[data_start] == b'\n' {
                    data_start += 1;
                }
                // /Length is required per §7.3.8.2 — use it to find
                // the body's end. ISO 32000-1 §7.3.10 Example 3
                // makes indirect /Length normative on stream objects
                // (`<< /Length 8 0 R >>` for one-pass writers). When a
                // resolver is supplied (the top-level
                // `DocumentReader::resolve` path), call it to fetch the
                // referenced integer; when no resolver is supplied
                // (the xref-stream parsing path, where the xref isn't
                // yet built) the indirect form is rejected.
                let length_obj = dict.entries().iter().find_map(|(k, v)| {
                    if k == "Length" {
                        Some(v.clone())
                    } else {
                        None
                    }
                });
                let len: usize = match length_obj {
                    Some(Object::Integer(n)) if n >= 0 => n as usize,
                    Some(Object::Reference(id)) => {
                        let resolved = resolver.resolve_length(id)?;
                        if resolved < 0 {
                            return Err(PdfError::other(format!(
                                "PDF parser: indirect /Length {id:?} resolved to \
                                 negative integer {resolved}"
                            )));
                        }
                        // Patch the dict so downstream consumers (e.g.
                        // `decode_stream`, encryption length tracking)
                        // see the resolved direct integer rather than
                        // the now-stale `Reference`.
                        dict.set("Length", Object::Integer(resolved));
                        resolved as usize
                    }
                    Some(other) => {
                        return Err(PdfError::other(format!(
                            "PDF parser: stream /Length must be a non-negative integer (got {other:?})"
                        )));
                    }
                    None => {
                        return Err(PdfError::other(
                            "PDF parser: stream object missing required /Length entry",
                        ));
                    }
                };
                let data_end = data_start.saturating_add(len).min(raw.len());
                let data = self.lex.slice(data_start, data_end).to_vec();
                // Skip the body + the EOL before `endstream` + the
                // `endstream` keyword itself.
                self.lex.seek(data_end);
                self.peeked = None;
                // Drop any whitespace + EOL between the data and
                // `endstream`.
                let endstream = self
                    .next()?
                    .ok_or_else(|| PdfError::other("PDF parser: stream missing `endstream`"))?;
                let TokenKind::Keyword(b"endstream") = endstream.kind else {
                    return Err(PdfError::other(format!(
                        "PDF parser: expected `endstream` after stream body at byte {} (got {:?})",
                        endstream.start, endstream.kind
                    )));
                };
                return Ok(Object::Stream(Stream::new(dict, data)));
            }
        }
        Ok(Object::Dict(dict))
    }

    /// Parse one indirect object (`<n> <gen> obj … endobj`). Returns
    /// `(ObjectId, Object)`. The caller is responsible for positioning
    /// the parser at the first byte of the indirect object header.
    ///
    /// Streams with an indirect `/Length` are rejected — use
    /// [`Self::parse_indirect_with_length_resolver`] from a context
    /// that has a built xref table.
    pub fn parse_indirect(&mut self) -> Result<(ObjectId, Object), PdfError> {
        self.parse_indirect_with_length_resolver(&mut NoLengthResolver)
    }

    /// Variant of [`Self::parse_indirect`] that accepts a
    /// [`LengthResolver`] to resolve indirect `/Length` references on
    /// stream-object dictionaries (ISO 32000-1 §7.3.10 Example 3).
    pub fn parse_indirect_with_length_resolver(
        &mut self,
        resolver: &mut dyn LengthResolver,
    ) -> Result<(ObjectId, Object), PdfError> {
        let n = self.expect_integer("indirect-object number")?;
        let gen = self.expect_integer("indirect-object generation")?;
        let obj_kw = self
            .next()?
            .ok_or_else(|| PdfError::other("PDF parser: unexpected EOF before `obj` keyword"))?;
        let TokenKind::Keyword(b"obj") = obj_kw.kind else {
            return Err(PdfError::other(format!(
                "PDF parser: expected `obj` keyword at byte {} (got {:?})",
                obj_kw.start, obj_kw.kind
            )));
        };
        let body = self
            .parse_object_with_length_resolver(resolver)?
            .ok_or_else(|| PdfError::other("PDF parser: indirect object missing body"))?;
        let endobj = self
            .next()?
            .ok_or_else(|| PdfError::other("PDF parser: indirect object missing `endobj`"))?;
        let TokenKind::Keyword(b"endobj") = endobj.kind else {
            return Err(PdfError::other(format!(
                "PDF parser: expected `endobj` at byte {} (got {:?})",
                endobj.start, endobj.kind
            )));
        };
        if n < 1 || n > u32::MAX as i64 || !(0..=u16::MAX as i64).contains(&gen) {
            return Err(PdfError::other(format!(
                "PDF parser: indirect-object id `{n} {gen}` out of range"
            )));
        }
        Ok((
            ObjectId {
                number: n as u32,
                generation: gen as u16,
            },
            body,
        ))
    }

    fn expect_integer(&mut self, what: &str) -> Result<i64, PdfError> {
        let tok = self
            .next()?
            .ok_or_else(|| PdfError::other(format!("PDF parser: expected {what}, got EOF")))?;
        match tok.kind {
            TokenKind::Integer(n) => Ok(n),
            other => Err(PdfError::other(format!(
                "PDF parser: expected {what} (integer), got {other:?} at byte {}",
                tok.start
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(input: &[u8]) -> Object {
        Parser::new(input)
            .parse_object()
            .unwrap()
            .expect("parsed object")
    }

    #[test]
    fn primitives_parse_to_objects() {
        assert!(matches!(parse_one(b"true"), Object::Bool(true)));
        assert!(matches!(parse_one(b"false"), Object::Bool(false)));
        assert!(matches!(parse_one(b"null"), Object::Null));
        assert!(matches!(parse_one(b"42"), Object::Integer(42)));
        match parse_one(b"2.5") {
            Object::Real(f) => assert!((f - 2.5).abs() < 1e-9),
            other => panic!("expected real, got {other:?}"),
        }
        match parse_one(b"(hello)") {
            Object::LiteralString(b) => assert_eq!(b, b"hello".to_vec()),
            other => panic!("expected literal string, got {other:?}"),
        }
        match parse_one(b"<48656C6C6F>") {
            Object::HexString(b) => assert_eq!(b, b"Hello".to_vec()),
            other => panic!("expected hex string, got {other:?}"),
        }
        match parse_one(b"/Pages") {
            Object::Name(s) => assert_eq!(s, "Pages"),
            other => panic!("expected name, got {other:?}"),
        }
    }

    #[test]
    fn array_parses_recursively() {
        let arr = parse_one(b"[1 2.5 (a) /b [3 4]]");
        let Object::Array(items) = arr else {
            panic!("expected array")
        };
        assert_eq!(items.len(), 5);
        assert!(matches!(items[0], Object::Integer(1)));
        assert!(matches!(items[1], Object::Real(_)));
        assert!(matches!(items[2], Object::LiteralString(_)));
        assert!(matches!(items[3], Object::Name(_)));
        assert!(matches!(items[4], Object::Array(_)));
    }

    #[test]
    fn dict_parses_with_named_keys() {
        let d = parse_one(b"<< /Type /Page /Count 3 /Kids [1 2 3] >>");
        let Object::Dict(d) = d else {
            panic!("expected dict")
        };
        let entries = d.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, "Type");
        assert_eq!(entries[1].0, "Count");
        assert_eq!(entries[2].0, "Kids");
    }

    #[test]
    fn indirect_reference_recognised() {
        let r = parse_one(b"5 0 R");
        let Object::Reference(id) = r else {
            panic!("expected ref")
        };
        assert_eq!(id.number, 5);
        assert_eq!(id.generation, 0);
    }

    #[test]
    fn integer_followed_by_non_ref_does_not_become_ref() {
        // `5 0` (without R) → array of two integers.
        let arr = parse_one(b"[5 0]");
        let Object::Array(items) = arr else {
            panic!("expected array")
        };
        assert_eq!(items.len(), 2);
        assert!(matches!(items[0], Object::Integer(5)));
        assert!(matches!(items[1], Object::Integer(0)));
    }

    #[test]
    fn indirect_object_round_trip() {
        let input = b"3 0 obj\n<< /Type /Page >>\nendobj\n";
        let mut p = Parser::new(input);
        let (id, body) = p.parse_indirect().unwrap();
        assert_eq!(id.number, 3);
        assert!(matches!(body, Object::Dict(_)));
    }

    #[test]
    fn stream_object_extracts_body_per_length() {
        let input = b"4 0 obj\n<< /Length 5 >>\nstream\nABCDE\nendstream\nendobj\n";
        let mut p = Parser::new(input);
        let (_, body) = p.parse_indirect().unwrap();
        let Object::Stream(s) = body else {
            panic!("expected stream")
        };
        assert_eq!(s.data, b"ABCDE".to_vec());
    }

    #[test]
    fn stream_with_crlf_eol_marker() {
        // After `stream`, the EOL can be CRLF (or LF). The body
        // begins immediately after the marker.
        let mut input = Vec::new();
        input.extend_from_slice(b"4 0 obj\n<< /Length 3 >>\nstream\r\nXYZ\nendstream\nendobj\n");
        let mut p = Parser::new(&input);
        let (_, body) = p.parse_indirect().unwrap();
        let Object::Stream(s) = body else {
            panic!("expected stream")
        };
        assert_eq!(s.data, b"XYZ".to_vec());
    }

    #[test]
    fn stream_indirect_length_without_resolver_is_rejected() {
        // /Length 7 0 R — an indirect reference; the resolver-less
        // entry point (used by the xref-stream parser, before any
        // xref table exists) must still reject this so a malformed
        // xref-stream object doesn't silently read past EOF.
        let input = b"4 0 obj\n<< /Length 7 0 R >>\nstream\nXYZ\nendstream\nendobj\n";
        let mut p = Parser::new(input);
        let err = p.parse_indirect().unwrap_err();
        assert!(format!("{err}").contains("indirect reference"));
    }

    #[test]
    fn stream_indirect_length_with_resolver_resolves() {
        // Round-91: ISO 32000-1 §7.3.10 Example 3 — stream's /Length
        // is an indirect reference; with a resolver, the parser
        // fetches the target integer and slices the body accordingly.
        let input = b"4 0 obj\n<< /Length 7 0 R >>\nstream\nXYZ\nendstream\nendobj\n";
        let mut p = Parser::new(input);
        let mut resolver = |id: ObjectId| -> Result<i64, PdfError> {
            assert_eq!(id, ObjectId::new(7));
            Ok(3)
        };
        let (id, body) = p
            .parse_indirect_with_length_resolver(&mut resolver)
            .unwrap();
        assert_eq!(id, ObjectId::new(4));
        let Object::Stream(s) = body else {
            panic!("expected stream, got {body:?}")
        };
        assert_eq!(s.data, b"XYZ".to_vec());
        // The dict should now carry the resolved direct integer so
        // downstream consumers (decoders, encryption) don't see the
        // stale Reference.
        let length = s
            .dict
            .entries()
            .iter()
            .find(|(k, _)| k == "Length")
            .map(|(_, v)| v.clone());
        assert!(matches!(length, Some(Object::Integer(3))));
    }

    #[test]
    fn stream_indirect_length_negative_resolution_errors() {
        // A resolver that returns a negative integer must be flagged
        // (a real PDF should never do this, but we don't trust input).
        let input = b"4 0 obj\n<< /Length 7 0 R >>\nstream\nXYZ\nendstream\nendobj\n";
        let mut p = Parser::new(input);
        let mut resolver = |_id: ObjectId| -> Result<i64, PdfError> { Ok(-1) };
        let err = p
            .parse_indirect_with_length_resolver(&mut resolver)
            .unwrap_err();
        assert!(format!("{err}").contains("negative"));
    }

    #[test]
    fn stream_indirect_length_resolver_error_propagates() {
        // The resolver may legitimately fail (missing xref entry,
        // wrong-typed target object). Errors flow up the parser.
        let input = b"4 0 obj\n<< /Length 7 0 R >>\nstream\nXYZ\nendstream\nendobj\n";
        let mut p = Parser::new(input);
        let mut resolver =
            |_id: ObjectId| -> Result<i64, PdfError> { Err(PdfError::other("test: not found")) };
        let err = p
            .parse_indirect_with_length_resolver(&mut resolver)
            .unwrap_err();
        assert!(format!("{err}").contains("not found"));
    }

    #[test]
    fn stream_missing_length_is_rejected() {
        let input = b"4 0 obj\n<< /Type /XObject >>\nstream\nXYZ\nendstream\nendobj\n";
        let mut p = Parser::new(input);
        let err = p.parse_indirect().unwrap_err();
        assert!(format!("{err}").contains("/Length"));
    }

    #[test]
    fn nested_dict_in_array() {
        // The bracket-state tracking has to handle dicts nested inside
        // arrays and vice versa.
        let arr = parse_one(b"[<< /A 1 >> << /B 2 >>]");
        let Object::Array(items) = arr else {
            panic!("expected array")
        };
        assert_eq!(items.len(), 2);
        assert!(matches!(items[0], Object::Dict(_)));
        assert!(matches!(items[1], Object::Dict(_)));
    }

    #[test]
    fn dict_with_indirect_reference_value() {
        let d = parse_one(b"<< /Pages 2 0 R >>");
        let Object::Dict(d) = d else {
            panic!("expected dict")
        };
        let entries = d.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "Pages");
        assert!(matches!(entries[0].1, Object::Reference(_)));
    }
}
