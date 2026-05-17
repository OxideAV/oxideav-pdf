//! Shared, byte-level PDF stream-filter decoders.
//!
//! Round 35 hoists the small set of filter decoders the round-23
//! image-XObject walker carried internally into a shared module so
//! the round-35 inline-image walker can reuse the byte-identical
//! implementations. Adding more filters (`/LZW`, `/CCITTFax`, etc.)
//! in future rounds gives both walkers the new coverage at once.
//!
//! All decoders consume `&[u8]` input and return `Result<Vec<u8>,
//! PdfError>` — there is no state-machine surface, so each call is
//! self-contained and re-entrant.
//!
//! ## Provenance
//!
//! ISO 32000-1:2008 §7.4 (Filters), §7.4.2 (ASCIIHexDecode), §7.4.3
//! (ASCII85Decode), §7.4.4 (FlateDecode), §7.4.5 (RunLengthDecode).
//! No third-party PDF library was consulted.

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
}
