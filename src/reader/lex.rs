//! PDF tokenizer (ISO 32000-1 §7.2).
//!
//! Converts a byte slice into a stream of [`Token`]s. The lexer is
//! position-preserving — every token carries its `start` byte offset
//! into the input, so the higher-level object parser can:
//!
//! - decode a `stream` payload by jumping straight to the byte after
//!   the `stream` keyword's EOL (avoids re-scanning the body), and
//! - report errors with byte-level positions for debug tooling.
//!
//! The lexer never copies bytes; [`TokenKind::Name`],
//! [`TokenKind::LiteralString`], [`TokenKind::HexString`], and
//! [`TokenKind::Keyword`] all borrow from the input slice. The
//! object parser is in charge of escape decoding for literal strings
//! (the bytes between `(` and `)` — the lexer only matches the
//! delimiters and leaves the inner payload untouched).
//!
//! Round 3 only handles the surface our writer emits: numbers, names,
//! literal strings, hex strings, names, booleans, null, the standard
//! PDF keywords (`obj`, `endobj`, `stream`, `endstream`, `R`, `xref`,
//! `trailer`, `startxref`, `f`, `n`, `true`, `false`, `null`),
//! brackets `[`/`]` and dict markers `<<`/`>>`.

use crate::error::PdfError;

/// One token at a byte position.
#[derive(Debug, Clone, PartialEq)]
pub struct Token<'a> {
    pub start: usize,
    pub end: usize,
    pub kind: TokenKind<'a>,
}

/// Token payload. References into the input slice are zero-copy.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind<'a> {
    /// Integer (no `.`, no `e`/`E`). The bytes are the original
    /// digits + optional sign.
    Integer(i64),
    /// Real number (has `.`). Stored as the original string so the
    /// parser can re-format with the same precision policy.
    Real(f64),
    /// Name `/foo` — the bytes (without the leading `/`), already
    /// `#xx`-decoded.
    Name(Vec<u8>),
    /// Literal string `(...)`. Inner bytes only, with PDF escape
    /// sequences (`\n`, `\r`, `\t`, `\\`, `\(`, `\)`, octal `\nnn`,
    /// line-continuation `\<EOL>`) already decoded. Balanced parens
    /// inside a literal string are preserved verbatim per §7.3.4.2.
    LiteralString(Vec<u8>),
    /// Hex string `<...>`. Bytes are the **decoded** payload (every
    /// pair of hex digits produces one byte; an odd trailing nibble
    /// is left-aligned per §7.3.4.3).
    HexString(Vec<u8>),
    /// Bare ASCII identifier — keywords like `obj`, `endobj`, `R`,
    /// `true`, `false`, `null`, `xref`, `trailer`, `startxref`,
    /// `stream`, `endstream`, plus content-stream operators (`m`,
    /// `l`, `c`, `cm`, `q`, `Q`, `f`, `f*`, `S`, `B`, `B*`, `n`,
    /// `re`, `RG`, `rg`, `w`, etc.). The parser dispatches on the
    /// keyword text.
    Keyword(&'a [u8]),
    /// `[` — array start.
    ArrayStart,
    /// `]` — array end.
    ArrayEnd,
    /// `<<` — dictionary start.
    DictStart,
    /// `>>` — dictionary end.
    DictEnd,
}

/// Streaming tokenizer over a byte slice. Holds a cursor into the
/// input; advance with [`Lexer::next_token`].
pub struct Lexer<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Current byte offset.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Move the cursor to an absolute byte offset. Used by the object
    /// parser when it needs to re-anchor (e.g. after consuming the
    /// `stream` keyword + its EOL marker, the parser jumps the cursor
    /// past the binary payload directly).
    pub fn seek(&mut self, pos: usize) {
        self.pos = pos.min(self.input.len());
    }

    /// Peek at the byte at `offset` from the current position. Returns
    /// `None` past EOF.
    pub fn peek_byte(&self, offset: usize) -> Option<u8> {
        self.input.get(self.pos + offset).copied()
    }

    /// Borrow a slice of the input from `start` to `end` (clamped to
    /// the input length). Used by the object parser for stream-body
    /// extraction.
    pub fn slice(&self, start: usize, end: usize) -> &'a [u8] {
        let s = start.min(self.input.len());
        let e = end.min(self.input.len()).max(s);
        &self.input[s..e]
    }

    /// Whole input. Useful for the trailer / startxref scanner that
    /// works backward from EOF.
    pub fn input(&self) -> &'a [u8] {
        self.input
    }

    /// Read the next token. Returns `Ok(None)` at EOF.
    pub fn next_token(&mut self) -> Result<Option<Token<'a>>, PdfError> {
        self.skip_whitespace_and_comments();
        if self.pos >= self.input.len() {
            return Ok(None);
        }
        let start = self.pos;
        let b = self.input[self.pos];
        let tok = match b {
            b'[' => {
                self.pos += 1;
                Token {
                    start,
                    end: self.pos,
                    kind: TokenKind::ArrayStart,
                }
            }
            b']' => {
                self.pos += 1;
                Token {
                    start,
                    end: self.pos,
                    kind: TokenKind::ArrayEnd,
                }
            }
            b'<' => {
                if self.peek_byte(1) == Some(b'<') {
                    self.pos += 2;
                    Token {
                        start,
                        end: self.pos,
                        kind: TokenKind::DictStart,
                    }
                } else {
                    self.read_hex_string(start)?
                }
            }
            b'>' => {
                if self.peek_byte(1) == Some(b'>') {
                    self.pos += 2;
                    Token {
                        start,
                        end: self.pos,
                        kind: TokenKind::DictEnd,
                    }
                } else {
                    return Err(PdfError::other(format!(
                        "PDF lexer: unexpected `>` at byte {start} (need `>>` for dict end)"
                    )));
                }
            }
            b'(' => self.read_literal_string(start)?,
            b'/' => self.read_name(start)?,
            b'+' | b'-' | b'.' | b'0'..=b'9' => self.read_number(start)?,
            _ => self.read_keyword(start)?,
        };
        Ok(Some(tok))
    }

    /// Drop whitespace + `%`-line comments. The PDF spec treats both
    /// as "whitespace separating tokens" (§7.2.3 / §7.2.4).
    fn skip_whitespace_and_comments(&mut self) {
        while self.pos < self.input.len() {
            let b = self.input[self.pos];
            if is_whitespace(b) {
                self.pos += 1;
            } else if b == b'%' {
                while self.pos < self.input.len()
                    && self.input[self.pos] != b'\n'
                    && self.input[self.pos] != b'\r'
                {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn read_number(&mut self, start: usize) -> Result<Token<'a>, PdfError> {
        let mut end = start;
        // Optional sign.
        if self.input.get(end).is_some_and(|&b| b == b'+' || b == b'-') {
            end += 1;
        }
        let mut saw_dot = false;
        let mut saw_digit = false;
        while end < self.input.len() {
            let b = self.input[end];
            if b.is_ascii_digit() {
                saw_digit = true;
                end += 1;
            } else if b == b'.' && !saw_dot {
                saw_dot = true;
                end += 1;
            } else {
                break;
            }
        }
        if !saw_digit {
            // A bare sign or dot wasn't a number — fall back to the
            // keyword path so e.g. ".n" or "+e" surface as keywords
            // rather than a phantom 0.
            return self.read_keyword(start);
        }
        self.pos = end;
        let text = std::str::from_utf8(&self.input[start..end])
            .map_err(|_| PdfError::other(format!("PDF lexer: non-UTF-8 number at byte {start}")))?;
        let kind = if saw_dot {
            let f = text.parse::<f64>().map_err(|_| {
                PdfError::other(format!("PDF lexer: invalid real `{text}` at byte {start}"))
            })?;
            TokenKind::Real(f)
        } else {
            let n = text.parse::<i64>().map_err(|_| {
                PdfError::other(format!(
                    "PDF lexer: invalid integer `{text}` at byte {start}"
                ))
            })?;
            TokenKind::Integer(n)
        };
        Ok(Token { start, end, kind })
    }

    fn read_name(&mut self, start: usize) -> Result<Token<'a>, PdfError> {
        debug_assert_eq!(self.input[start], b'/');
        let mut end = start + 1;
        let mut decoded = Vec::with_capacity(16);
        while end < self.input.len() {
            let b = self.input[end];
            if is_delimiter(b) || is_whitespace(b) {
                break;
            }
            if b == b'#' {
                // Two-hex-digit escape per §7.3.5. Anything malformed
                // surfaces as an error rather than silently producing
                // a `#` byte — it'd corrupt downstream key lookups.
                let h1 = self.input.get(end + 1).copied().ok_or_else(|| {
                    PdfError::other(format!("PDF lexer: truncated #xx escape at byte {end}"))
                })?;
                let h2 = self.input.get(end + 2).copied().ok_or_else(|| {
                    PdfError::other(format!("PDF lexer: truncated #xx escape at byte {end}"))
                })?;
                let hi = hex_digit(h1).ok_or_else(|| {
                    PdfError::other(format!(
                        "PDF lexer: bad hex digit `{h1}` in name #xx at byte {end}"
                    ))
                })?;
                let lo = hex_digit(h2).ok_or_else(|| {
                    PdfError::other(format!(
                        "PDF lexer: bad hex digit `{h2}` in name #xx at byte {end}"
                    ))
                })?;
                decoded.push((hi << 4) | lo);
                end += 3;
            } else {
                decoded.push(b);
                end += 1;
            }
        }
        self.pos = end;
        Ok(Token {
            start,
            end,
            kind: TokenKind::Name(decoded),
        })
    }

    fn read_literal_string(&mut self, start: usize) -> Result<Token<'a>, PdfError> {
        debug_assert_eq!(self.input[start], b'(');
        let mut end = start + 1;
        let mut depth = 1u32;
        let mut decoded = Vec::with_capacity(32);
        while end < self.input.len() {
            let b = self.input[end];
            if b == b'\\' {
                end += 1;
                if end >= self.input.len() {
                    break;
                }
                let esc = self.input[end];
                match esc {
                    b'n' => {
                        decoded.push(b'\n');
                        end += 1;
                    }
                    b'r' => {
                        decoded.push(b'\r');
                        end += 1;
                    }
                    b't' => {
                        decoded.push(b'\t');
                        end += 1;
                    }
                    b'b' => {
                        decoded.push(0x08);
                        end += 1;
                    }
                    b'f' => {
                        decoded.push(0x0C);
                        end += 1;
                    }
                    b'\\' => {
                        decoded.push(b'\\');
                        end += 1;
                    }
                    b'(' => {
                        decoded.push(b'(');
                        end += 1;
                    }
                    b')' => {
                        decoded.push(b')');
                        end += 1;
                    }
                    b'\n' => {
                        // Line continuation — drop the LF.
                        end += 1;
                    }
                    b'\r' => {
                        end += 1;
                        if end < self.input.len() && self.input[end] == b'\n' {
                            end += 1;
                        }
                    }
                    b'0'..=b'7' => {
                        // Up to 3 octal digits.
                        let mut v = (esc - b'0') as u16;
                        end += 1;
                        for _ in 0..2 {
                            if end < self.input.len() && (b'0'..=b'7').contains(&self.input[end]) {
                                v = v * 8 + (self.input[end] - b'0') as u16;
                                end += 1;
                            } else {
                                break;
                            }
                        }
                        decoded.push((v & 0xFF) as u8);
                    }
                    other => {
                        // Unknown escape — per §7.3.4.2, the `\` is
                        // ignored and the next character passes
                        // through verbatim.
                        decoded.push(other);
                        end += 1;
                    }
                }
                continue;
            }
            if b == b'(' {
                depth += 1;
                decoded.push(b'(');
                end += 1;
                continue;
            }
            if b == b')' {
                depth -= 1;
                if depth == 0 {
                    end += 1;
                    self.pos = end;
                    return Ok(Token {
                        start,
                        end,
                        kind: TokenKind::LiteralString(decoded),
                    });
                }
                decoded.push(b')');
                end += 1;
                continue;
            }
            // Per §7.3.4.2, a literal string normalises CR / CRLF /
            // LF to a single LF inside the payload.
            if b == b'\r' {
                decoded.push(b'\n');
                end += 1;
                if end < self.input.len() && self.input[end] == b'\n' {
                    end += 1;
                }
                continue;
            }
            decoded.push(b);
            end += 1;
        }
        Err(PdfError::other(format!(
            "PDF lexer: unterminated literal string starting at byte {start}"
        )))
    }

    fn read_hex_string(&mut self, start: usize) -> Result<Token<'a>, PdfError> {
        debug_assert_eq!(self.input[start], b'<');
        let mut end = start + 1;
        let mut nibble: Option<u8> = None;
        let mut decoded = Vec::with_capacity(16);
        while end < self.input.len() {
            let b = self.input[end];
            if b == b'>' {
                if let Some(hi) = nibble {
                    // Odd trailing nibble — left-align per §7.3.4.3.
                    decoded.push(hi << 4);
                }
                end += 1;
                self.pos = end;
                return Ok(Token {
                    start,
                    end,
                    kind: TokenKind::HexString(decoded),
                });
            }
            if is_whitespace(b) {
                end += 1;
                continue;
            }
            let h = hex_digit(b).ok_or_else(|| {
                PdfError::other(format!(
                    "PDF lexer: bad hex digit `{b}` in hex string at byte {end}"
                ))
            })?;
            match nibble {
                None => nibble = Some(h),
                Some(hi) => {
                    decoded.push((hi << 4) | h);
                    nibble = None;
                }
            }
            end += 1;
        }
        Err(PdfError::other(format!(
            "PDF lexer: unterminated hex string starting at byte {start}"
        )))
    }

    fn read_keyword(&mut self, start: usize) -> Result<Token<'a>, PdfError> {
        let mut end = start;
        while end < self.input.len() {
            let b = self.input[end];
            if is_whitespace(b) || is_delimiter(b) {
                break;
            }
            end += 1;
        }
        if end == start {
            // Not a real keyword — single non-token byte. Skip and
            // recurse so the lexer doesn't loop forever.
            self.pos += 1;
            return Err(PdfError::other(format!(
                "PDF lexer: unrecognised byte `{}` at byte {start}",
                self.input[start]
            )));
        }
        self.pos = end;
        Ok(Token {
            start,
            end,
            kind: TokenKind::Keyword(&self.input[start..end]),
        })
    }
}

fn is_whitespace(b: u8) -> bool {
    // §7.2.3 — NUL, HT, LF, FF, CR, SP.
    matches!(b, 0x00 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

fn is_delimiter(b: u8) -> bool {
    // §7.2.3 — `( ) < > [ ] { } / %`.
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokenize(input: &[u8]) -> Vec<TokenKind<'_>> {
        let mut lex = Lexer::new(input);
        let mut out = Vec::new();
        while let Some(t) = lex.next_token().unwrap() {
            out.push(t.kind);
        }
        out
    }

    #[test]
    fn integers_and_reals() {
        assert_eq!(
            tokenize(b"42 -7 0 +3"),
            vec![
                TokenKind::Integer(42),
                TokenKind::Integer(-7),
                TokenKind::Integer(0),
                TokenKind::Integer(3),
            ]
        );
        let toks = tokenize(b"0.5 -1.25 .75");
        assert_eq!(toks.len(), 3);
        match toks[0] {
            TokenKind::Real(f) => assert!((f - 0.5).abs() < 1e-9),
            _ => panic!("expected real"),
        }
        match toks[1] {
            TokenKind::Real(f) => assert!((f + 1.25).abs() < 1e-9),
            _ => panic!("expected real"),
        }
        match toks[2] {
            TokenKind::Real(f) => assert!((f - 0.75).abs() < 1e-9),
            _ => panic!("expected real"),
        }
    }

    #[test]
    fn names_decode_hex_escapes() {
        let toks = tokenize(b"/Pages /a#20b /dc#3Arights");
        assert_eq!(toks.len(), 3);
        assert_eq!(toks[0], TokenKind::Name(b"Pages".to_vec()));
        assert_eq!(toks[1], TokenKind::Name(b"a b".to_vec()));
        assert_eq!(toks[2], TokenKind::Name(b"dc:rights".to_vec()));
    }

    #[test]
    fn literal_string_with_escapes() {
        let toks = tokenize(b"(hello\\nworld) (\\(c\\))");
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0], TokenKind::LiteralString(b"hello\nworld".to_vec()));
        assert_eq!(toks[1], TokenKind::LiteralString(b"(c)".to_vec()));
    }

    #[test]
    fn literal_string_balanced_parens() {
        // Per §7.3.4.2, balanced parens inside a literal string need
        // no escaping — the lexer has to track depth.
        let toks = tokenize(b"(a (b (c) d) e)");
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0], TokenKind::LiteralString(b"a (b (c) d) e".to_vec()));
    }

    #[test]
    fn literal_string_octal_escapes() {
        // \101 = 'A' (decimal 65)
        let toks = tokenize(b"(\\101BC)");
        assert_eq!(toks, vec![TokenKind::LiteralString(b"ABC".to_vec())]);
    }

    #[test]
    fn hex_string_decodes_pairs() {
        let toks = tokenize(b"<48656C6C6F>");
        assert_eq!(toks, vec![TokenKind::HexString(b"Hello".to_vec())]);
    }

    #[test]
    fn hex_string_odd_nibble_left_aligned() {
        // Per §7.3.4.3, an odd trailing nibble is left-aligned: <F> = 0xF0.
        let toks = tokenize(b"<F>");
        assert_eq!(toks, vec![TokenKind::HexString(vec![0xF0])]);
    }

    #[test]
    fn hex_string_with_whitespace_between_digits() {
        let toks = tokenize(b"<48 65 6C 6C 6F>");
        assert_eq!(toks, vec![TokenKind::HexString(b"Hello".to_vec())]);
    }

    #[test]
    fn dict_and_array_markers() {
        let toks = tokenize(b"<< /Type /Page >> [1 2 3]");
        assert_eq!(toks.len(), 9);
        assert_eq!(toks[0], TokenKind::DictStart);
        assert_eq!(toks[1], TokenKind::Name(b"Type".to_vec()));
        assert_eq!(toks[2], TokenKind::Name(b"Page".to_vec()));
        assert_eq!(toks[3], TokenKind::DictEnd);
        assert_eq!(toks[4], TokenKind::ArrayStart);
        assert_eq!(toks[5], TokenKind::Integer(1));
        assert_eq!(toks[6], TokenKind::Integer(2));
        assert_eq!(toks[7], TokenKind::Integer(3));
        assert_eq!(toks[8], TokenKind::ArrayEnd);
    }

    #[test]
    fn keywords_pass_through() {
        let toks =
            tokenize(b"obj endobj stream endstream R xref trailer startxref true false null");
        assert_eq!(toks.len(), 11);
        assert_eq!(toks[0], TokenKind::Keyword(b"obj"));
        assert_eq!(toks[1], TokenKind::Keyword(b"endobj"));
        assert_eq!(toks[2], TokenKind::Keyword(b"stream"));
        assert_eq!(toks[3], TokenKind::Keyword(b"endstream"));
        assert_eq!(toks[4], TokenKind::Keyword(b"R"));
        assert_eq!(toks[5], TokenKind::Keyword(b"xref"));
        assert_eq!(toks[6], TokenKind::Keyword(b"trailer"));
        assert_eq!(toks[7], TokenKind::Keyword(b"startxref"));
        assert_eq!(toks[8], TokenKind::Keyword(b"true"));
        assert_eq!(toks[9], TokenKind::Keyword(b"false"));
        assert_eq!(toks[10], TokenKind::Keyword(b"null"));
    }

    #[test]
    fn comments_are_skipped_like_whitespace() {
        let toks = tokenize(b"% header comment\n42 % trailing\n/Foo");
        assert_eq!(
            toks,
            vec![TokenKind::Integer(42), TokenKind::Name(b"Foo".to_vec())]
        );
    }

    #[test]
    fn position_advances_after_each_token() {
        let mut lex = Lexer::new(b"42 /foo");
        let t1 = lex.next_token().unwrap().unwrap();
        assert_eq!(t1.start, 0);
        assert_eq!(t1.end, 2);
        let t2 = lex.next_token().unwrap().unwrap();
        assert_eq!(t2.start, 3);
        assert_eq!(t2.end, 7);
        assert!(lex.next_token().unwrap().is_none());
    }

    #[test]
    fn seek_and_slice_helpers() {
        let mut lex = Lexer::new(b"obj\nstream\nABCDEF\nendstream\nendobj\n");
        // Skip past `obj`.
        let _ = lex.next_token().unwrap();
        // Skip past `stream`.
        let stream_tok = lex.next_token().unwrap().unwrap();
        assert!(matches!(stream_tok.kind, TokenKind::Keyword(b"stream")));
        // Per §7.3.8.1, the data starts at the byte after the EOL
        // marker (LF or CRLF). Seek there manually + slice.
        let data_start = stream_tok.end + 1; // skip the LF after `stream`
        let data_end = data_start + 6; // "ABCDEF"
        assert_eq!(lex.slice(data_start, data_end), b"ABCDEF");
        lex.seek(data_end);
        // Next non-whitespace token is `endstream`.
        let t = lex.next_token().unwrap().unwrap();
        assert_eq!(t.kind, TokenKind::Keyword(b"endstream"));
    }

    #[test]
    fn unterminated_literal_string_is_error() {
        let mut lex = Lexer::new(b"(hello");
        assert!(lex.next_token().is_err());
    }

    #[test]
    fn unterminated_hex_string_is_error() {
        let mut lex = Lexer::new(b"<48656C");
        assert!(lex.next_token().is_err());
    }
}
