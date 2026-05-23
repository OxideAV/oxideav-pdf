//! Shared, byte-level PDF stream-filter decoders.
//!
//! Round 35 hoists the small set of filter decoders the round-23
//! image-XObject walker carried internally into a shared module so
//! the round-35 inline-image walker can reuse the byte-identical
//! implementations. Adding more filters (`/LZW`, `/CCITTFax`, etc.)
//! in future rounds gives both walkers the new coverage at once.
//! Round 98 adds `LZWDecode` (§7.4.4.2).
//!
//! All decoders consume `&[u8]` input and return `Result<Vec<u8>,
//! PdfError>` — there is no state-machine surface, so each call is
//! self-contained and re-entrant.
//!
//! ## Provenance
//!
//! ISO 32000-1:2008 §7.4 (Filters), §7.4.2 (ASCIIHexDecode), §7.4.3
//! (ASCII85Decode), §7.4.4 (LZWDecode + FlateDecode), §7.4.4.2
//! (Details of LZW Encoding), §7.4.4.3 (`/EarlyChange` parameter),
//! §7.4.5 (RunLengthDecode). No third-party PDF library was
//! consulted.

use crate::error::PdfError;

/// FlateDecode — zlib-wrapped DEFLATE per §7.4.4 / RFC 1950 + RFC
/// 1951. The `/Predictor` post-filter (§7.4.4.4 PNG-Up etc.) is
/// **not** applied here — the caller decides whether to walk the
/// per-row predictor (xref streams + Image XObjects with
/// `/DecodeParms /Predictor n`); the round-35 image walkers don't
/// invoke it because Image XObject payloads carry their own
/// per-row predictor unwrapping inside the codec (DCT/JPX/...).
pub fn flate_decompress(input: &[u8]) -> Result<Vec<u8>, PdfError> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut out = Vec::new();
    let mut dec = ZlibDecoder::new(input);
    dec.read_to_end(&mut out)
        .map_err(|e| PdfError::other(format!("PDF filter: FlateDecode failed: {e}")))?;
    Ok(out)
}

/// ASCII85Decode (§7.4.3) — five base-85 ASCII characters in the
/// range `!`..`u` encode four bytes. `z` is a shorthand for four
/// zero bytes. Whitespace is ignored. The stream ends at `~>`.
/// Partial groups are padded with `u` (84) on encode and truncated
/// to the equivalent number of bytes on decode (1..=4 bytes per
/// `n`-character partial group, where `n` ∈ {2, 3, 4, 5}).
pub fn ascii85_decode(input: &[u8]) -> Result<Vec<u8>, PdfError> {
    let mut out = Vec::with_capacity(input.len() * 4 / 5);
    let mut group: [u8; 5] = [0; 5];
    let mut filled: usize = 0;
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        i += 1;
        // EOD marker `~>` per §7.4.3.
        if b == b'~' {
            if i < input.len() && input[i] == b'>' {
                break;
            }
            return Err(PdfError::other(
                "PDF filter: ASCII85 stray '~' (expected '~>')",
            ));
        }
        // Whitespace (space, \t, \n, \r, FF, NUL) — ignore.
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0C | 0x00) {
            continue;
        }
        // 'z' shorthand for four zero bytes — only valid when the
        // group is empty.
        if b == b'z' {
            if filled != 0 {
                return Err(PdfError::other(
                    "PDF filter: ASCII85 'z' shorthand mid-group",
                ));
            }
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        if !(b'!'..=b'u').contains(&b) {
            return Err(PdfError::other(format!(
                "PDF filter: ASCII85 illegal byte {b:#x}"
            )));
        }
        group[filled] = b - b'!';
        filled += 1;
        if filled == 5 {
            decode_ascii85_group_full(&group, &mut out);
            filled = 0;
        }
    }
    if filled == 1 {
        return Err(PdfError::other(
            "PDF filter: ASCII85 trailing 1-character group is illegal",
        ));
    }
    if filled > 1 {
        // Pad to 5 with the highest digit (84 = 'u' - '!') and emit
        // (filled - 1) bytes — see §7.4.3.
        for slot in group.iter_mut().skip(filled) {
            *slot = 84;
        }
        let mut tmp = Vec::with_capacity(4);
        decode_ascii85_group_full(&group, &mut tmp);
        out.extend_from_slice(&tmp[..filled - 1]);
    }
    Ok(out)
}

fn decode_ascii85_group_full(group: &[u8; 5], out: &mut Vec<u8>) {
    let value: u64 = group.iter().fold(0u64, |acc, &d| acc * 85 + d as u64);
    out.push(((value >> 24) & 0xFF) as u8);
    out.push(((value >> 16) & 0xFF) as u8);
    out.push(((value >> 8) & 0xFF) as u8);
    out.push((value & 0xFF) as u8);
}

/// ASCIIHexDecode (§7.4.2) — pairs of hex digits, with whitespace
/// ignored, terminated by `>`. An odd trailing nibble is treated as
/// if followed by a `0` per §7.4.2.
pub fn ascii_hex_decode(input: &[u8]) -> Result<Vec<u8>, PdfError> {
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut high: Option<u8> = None;
    for &b in input {
        if b == b'>' {
            break;
        }
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0C | 0x00) {
            continue;
        }
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => {
                return Err(PdfError::other(format!(
                    "PDF filter: ASCIIHex illegal byte {b:#x}"
                )))
            }
        };
        match high.take() {
            None => high = Some(nibble),
            Some(h) => out.push((h << 4) | nibble),
        }
    }
    if let Some(h) = high {
        out.push(h << 4);
    }
    Ok(out)
}

/// RunLengthDecode (§7.4.5) — a one-byte length tag steers each
/// subsequent run:
///
/// * `0..=127` (i.e. tag `n`): copy `n + 1` literal bytes from the
///   input.
/// * `129..=255` (i.e. tag `-n` two's-complement): repeat the next
///   single byte `2 - (tag as i8 as i32) = 257 - tag` times — i.e.
///   2 through 128 copies.
/// * `128` (EOD): end of stream.
///
/// Spec-conformant streams terminate with an explicit 128; we also
/// accept implicit EOF (some real-world writers omit the marker).
pub fn run_length_decode(input: &[u8]) -> Result<Vec<u8>, PdfError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < input.len() {
        let tag = input[i];
        i += 1;
        if tag == 128 {
            break;
        }
        if tag < 128 {
            let copy = tag as usize + 1;
            if i + copy > input.len() {
                return Err(PdfError::other(
                    "PDF filter: RunLengthDecode literal run exceeds input",
                ));
            }
            out.extend_from_slice(&input[i..i + copy]);
            i += copy;
        } else {
            // 129..=255: repeat-the-next-byte (257 - tag) times.
            let count = 257 - tag as usize;
            if i >= input.len() {
                return Err(PdfError::other(
                    "PDF filter: RunLengthDecode repeat-run missing byte",
                ));
            }
            let byte = input[i];
            i += 1;
            out.extend(std::iter::repeat(byte).take(count));
        }
    }
    Ok(out)
}

/// LZWDecode (§7.4.4.2) — variable-length (9..=12-bit) adaptive
/// Lempel-Ziv-Welch, the same flavour TIFF 6.0 uses.
///
/// Codes are packed MSB-first into a continuous bit stream that is
/// then split into bytes MSB-first, so a code may straddle a byte
/// boundary. The string table starts at 258 fixed entries (0..=255
/// single bytes, 256 = clear-table, 257 = EOD); each emitted code
/// appends one new entry (the previous output followed by the first
/// byte of the current output), and the code length grows by one bit
/// the moment the table is about to overflow the current width.
///
/// `early_change` mirrors the `/EarlyChange` optional parameter
/// (§7.4.4.3 Table 8): the default value `1` bumps the code length
/// one code *early* — i.e. the width grows when the next table entry
/// to be assigned is `2^width - 1` rather than `2^width`. Some
/// encoders set `0` to postpone the bump as long as possible. PDF's
/// default (and TIFF's behaviour) is `1`.
///
/// Convenience [`lzw_decode`] wraps this with the default
/// `early_change = 1`.
pub fn lzw_decode_with_early_change(input: &[u8], early_change: bool) -> Result<Vec<u8>, PdfError> {
    const CLEAR: u32 = 256;
    const EOD: u32 = 257;
    const FIRST_FREE: u32 = 258;
    const MAX_WIDTH: u32 = 12;

    // The table maps a code >= 258 to the byte sequence it expands to.
    // Codes 0..=255 are implicit single bytes; 256 / 257 are control.
    // We store only the dynamic (>= 258) entries, indexed by
    // `code - FIRST_FREE`.
    let mut table: Vec<Vec<u8>> = Vec::new();
    let early = if early_change { 1 } else { 0 };

    let mut out: Vec<u8> = Vec::new();
    let mut bit_buf: u32 = 0;
    let mut bit_cnt: u32 = 0;
    let mut byte_pos: usize = 0;
    let mut code_width: u32 = 9;
    // `previous`: the byte sequence emitted for the prior code, used
    // to synthesize the next dictionary entry. `None` right after a
    // clear / at the very start.
    let mut previous: Option<Vec<u8>> = None;

    // Expand `code` into the byte sequence it represents, given the
    // current table. Returns `None` for an out-of-range code that is
    // not the legal "next code" KwKwK special case (handled by the
    // caller).
    let expand = |code: u32, table: &[Vec<u8>]| -> Option<Vec<u8>> {
        if code < 256 {
            Some(vec![code as u8])
        } else if code >= FIRST_FREE {
            table.get((code - FIRST_FREE) as usize).cloned()
        } else {
            None // 256 / 257 are control codes, never expanded.
        }
    };

    loop {
        // Refill the bit buffer (MSB-first) until we have a full code
        // or run out of input.
        while bit_cnt < code_width {
            if byte_pos >= input.len() {
                // Ran out of bits before an explicit EOD. Spec says a
                // conformant stream ends with code 257, but real-world
                // writers sometimes truncate; accept what we have.
                return Ok(out);
            }
            bit_buf = (bit_buf << 8) | input[byte_pos] as u32;
            byte_pos += 1;
            bit_cnt += 8;
        }
        bit_cnt -= code_width;
        let code = (bit_buf >> bit_cnt) & ((1 << code_width) - 1);

        if code == EOD {
            break;
        }
        if code == CLEAR {
            table.clear();
            code_width = 9;
            previous = None;
            continue;
        }

        // Resolve the current code to its byte sequence. The classic
        // "KwKwK" case: the code is exactly the entry we are about to
        // create, valid only when it equals the next free code and a
        // previous sequence exists.
        let next_code = FIRST_FREE + table.len() as u32;
        let entry = match expand(code, &table) {
            Some(seq) => seq,
            None if code == next_code => {
                let prev = previous.as_ref().ok_or_else(|| {
                    PdfError::other("PDF filter: LZW first code references empty table")
                })?;
                let mut seq = prev.clone();
                seq.push(prev[0]);
                seq
            }
            None => {
                return Err(PdfError::other(format!(
                    "PDF filter: LZW code {code} out of range (next free {next_code})"
                )));
            }
        };

        out.extend_from_slice(&entry);

        // Append a new table entry: previous sequence + first byte of
        // the current entry. The very first code after a clear has no
        // previous, so it creates no entry.
        if let Some(prev) = previous.as_ref() {
            if next_code <= 4095 {
                let mut new_entry = prev.clone();
                new_entry.push(entry[0]);
                table.push(new_entry);
            }
        }
        previous = Some(entry);

        // Grow the code width once the table is about to need a wider
        // code. With `early_change = 1` (default) this happens one
        // entry early, matching TIFF / PDF default behaviour.
        let assigned = FIRST_FREE + table.len() as u32;
        if code_width < MAX_WIDTH && assigned + early >= (1 << code_width) {
            code_width += 1;
        }
    }

    Ok(out)
}

/// LZWDecode with the default `/EarlyChange` of `1` (§7.4.4.3) — the
/// flavour every PDF writer that uses LZW emits and the one TIFF 6.0
/// mandates. See [`lzw_decode_with_early_change`] for the parameter.
pub fn lzw_decode(input: &[u8]) -> Result<Vec<u8>, PdfError> {
    lzw_decode_with_early_change(input, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii85_decodes_canonical_man_example() {
        let encoded = b"9jqo^~>";
        let out = ascii85_decode(encoded).unwrap();
        assert_eq!(out, b"Man ");
    }

    #[test]
    fn ascii85_z_shorthand_decodes_four_zero_bytes() {
        let out = ascii85_decode(b"z~>").unwrap();
        assert_eq!(out, [0u8, 0, 0, 0]);
    }

    #[test]
    fn ascii_hex_basic() {
        let out = ascii_hex_decode(b"48656C6C6F>").unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn ascii_hex_odd_nibble_pads_zero() {
        let out = ascii_hex_decode(b"414>").unwrap();
        assert_eq!(out, [0x41u8, 0x40]);
    }

    #[test]
    fn run_length_literal_run() {
        // tag = 4 → copy 5 literal bytes; EOD = 128.
        let input = [4u8, b'h', b'e', b'l', b'l', b'o', 128];
        let out = run_length_decode(&input).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn run_length_repeat_run() {
        // tag = -3 → 4 copies of the next byte. 256 - 3 = 253, but
        // two's-complement -3 is 253; (257 - 253) = 4.
        let input = [253u8, b'x', 128];
        let out = run_length_decode(&input).unwrap();
        assert_eq!(out, b"xxxx");
    }

    #[test]
    fn run_length_mixed_runs() {
        // 1-byte literal "A" + 5-byte repeat of "B" + EOD.
        // tag 0 = 1 literal; tag (257-5)=252 = 5 repeats.
        let input = [0u8, b'A', 252, b'B', 128];
        let out = run_length_decode(&input).unwrap();
        assert_eq!(out, b"ABBBBB");
    }

    #[test]
    fn run_length_no_eod_accepts_eof() {
        let input = [4u8, b'h', b'e', b'l', b'l', b'o'];
        let out = run_length_decode(&input).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn lzw_decodes_spec_example_2() {
        // ISO 32000-1:2008 §7.4.4.2 Example 2 — the packed stream
        // `80 0B 60 50 22 0C 0C 85 01` decodes to the §7.4.4.2
        // Example 1 input `45 45 45 45 45 65 45 45 45 66`.
        let encoded = [0x80u8, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01];
        let out = lzw_decode(&encoded).unwrap();
        assert_eq!(out, [45u8, 45, 45, 45, 45, 65, 45, 45, 45, 66]);
    }

    #[test]
    fn lzw_handles_clear_then_eod_only() {
        // A bare clear-table (256) immediately followed by EOD (257),
        // packed 9-bit MSB-first: 100000000 100000001
        //   = 1 0000 0000 1 0000 0001 → 0x80 0x80 0x80 (24 bits used,
        //   18 significant, padded with 0). Decodes to empty output.
        // 256 = 0b1_0000_0000, 257 = 0b1_0000_0001.
        let bits: u32 = (256 << 9) | 257; // 18 bits.
        let packed = [
            ((bits >> 10) & 0xFF) as u8,
            ((bits >> 2) & 0xFF) as u8,
            ((bits << 6) & 0xFF) as u8,
        ];
        let out = lzw_decode(&packed).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn lzw_truncated_stream_returns_partial_not_error() {
        // First three bytes of Example 2 (`80 0B 60`) carry codes
        // 256 (clear) + 45 ('-') with 6 leftover bits — no EOD. A
        // reader that runs out of bits returns what it decoded so far
        // rather than erroring (real-world writers truncate).
        let out = lzw_decode(&[0x80u8, 0x0B, 0x60]).unwrap();
        assert_eq!(out, [45u8]);
    }

    #[test]
    fn lzw_round_trips_a_longer_payload() {
        // No encoder in-crate, so build a stream by hand that exercises
        // the KwKwK self-reference path. Hand-running the §7.4.4.2
        // encoder on input "aaaaaaaa" (8 'a's) yields the code stream:
        //   256 (clear), 97 ('a'), 258 ("aa"), 259 ("aaa"), 258 ("aa"),
        //   257 (EOD)
        // where 258="aa" is reached via the KwKwK special case on the
        // decoder's very next code. All codes are 9-bit (the table
        // never grows past 260, well under 511). Pack MSB-first.
        let codes = [256u32, 97, 258, 259, 258, 257];
        let mut bit_buf: u64 = 0;
        let mut bit_cnt = 0u32;
        let mut packed = Vec::new();
        for c in codes {
            bit_buf = (bit_buf << 9) | c as u64;
            bit_cnt += 9;
            while bit_cnt >= 8 {
                bit_cnt -= 8;
                packed.push(((bit_buf >> bit_cnt) & 0xFF) as u8);
            }
        }
        if bit_cnt > 0 {
            packed.push(((bit_buf << (8 - bit_cnt)) & 0xFF) as u8);
        }
        let out = lzw_decode(&packed).unwrap();
        assert_eq!(out, b"aaaaaaaa");
    }
}
