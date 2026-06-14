//! Shared, byte-level PDF stream-filter decoders.
//!
//! Round 35 hoists the small set of filter decoders the round-23
//! image-XObject walker carried internally into a shared module so
//! the round-35 inline-image walker can reuse the byte-identical
//! implementations. Adding more filters (`/LZW`, `/CCITTFax`, etc.)
//! in future rounds gives both walkers the new coverage at once.
//! Round 98 adds `LZWDecode` (§7.4.4.2). Round 104 adds the
//! `/DecodeParms /Predictor` post-filter ([`apply_predictor`],
//! §7.4.4.4) shared by every Flate / LZW stream.
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
//! §7.4.4.4 (LZW and Flate Predictor Functions, Tables 8/9/10),
//! §7.4.5 (RunLengthDecode). PNG predictor algorithms per RFC 2083
//! §6 (the WWW Consortium recommendation the spec references). No
//! third-party PDF library was consulted.

use crate::error::PdfError;

/// FlateDecode — zlib-wrapped DEFLATE per §7.4.4 / RFC 1950 + RFC
/// 1951. This routine returns the inflated bytes only; the
/// `/DecodeParms /Predictor` post-filter (§7.4.4.4) is run separately
/// by [`apply_predictor`] when the caller's filter dispatch sees
/// `/Predictor` > 1 in the parameter dict (`decode_stream` chains the
/// two automatically as of round 104).
pub fn flate_decompress(input: &[u8]) -> Result<Vec<u8>, PdfError> {
    crate::zlib::flate_decompress(input)
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

/// The `/DecodeParms` predictor configuration for an `LZWDecode` /
/// `FlateDecode` stream (§7.4.4.4, Table 8). All four fields take the
/// spec defaults when the parameter dictionary omits them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PredictorParams {
    /// `/Predictor` (Table 10): `1` = none, `2` = TIFF Predictor 2,
    /// `10..=15` = PNG predictors (the row tag chooses which per row).
    pub predictor: i64,
    /// `/Colors` — interleaved colour components per sample (default 1).
    pub colors: usize,
    /// `/BitsPerComponent` — bits per colour component (default 8).
    pub bits_per_component: usize,
    /// `/Columns` — samples per row (default 1).
    pub columns: usize,
}

impl Default for PredictorParams {
    fn default() -> Self {
        // §7.4.4.4 Table 8 defaults.
        PredictorParams {
            predictor: 1,
            colors: 1,
            bits_per_component: 8,
            columns: 1,
        }
    }
}

/// Reverse the `/Predictor` post-filter that `LZWDecode` /
/// `FlateDecode` streams may apply before compression (§7.4.4.4).
///
/// Prediction replaces each sample with the difference from a
/// predictor function over earlier neighbouring samples so the
/// pre-compression data clusters toward 0; this routine undoes that
/// differencing on the decompressed bytes.
///
/// Two predictor groups are defined (Table 10):
///
/// * **TIFF Predictor 2** (`/Predictor 2`) — each colour component is
///   predicted to equal the corresponding component of the sample
///   immediately to its left. Operates at component granularity, so
///   sub-byte `/BitsPerComponent` (1 / 2 / 4) is unpacked per
///   component, differenced modulo `2^bpc`, and repacked.
/// * **PNG predictors** (`/Predictor 10..=15`) — each row carries a
///   one-byte algorithm tag (Table 9: 0 None / 1 Sub / 2 Up /
///   3 Average / 4 Paeth); the `/Predictor` value only signals "a PNG
///   predictor is in use" and the per-row tag is authoritative
///   (§7.4.4.4 ¶ "the specific predictor function used shall be
///   explicitly encoded in the incoming data"). PNG "left"/"upper-left"
///   neighbours are the bytes `bpp` positions back, where
///   `bpp = ceil(Colors * BitsPerComponent / 8)`.
///
/// `/Predictor 1` (the default) returns the input unchanged. Per the
/// shared assumptions, a row occupies a whole number of bytes (rounded
/// up) and samples outside the image contribute 0.
pub fn apply_predictor(data: &[u8], params: &PredictorParams) -> Result<Vec<u8>, PdfError> {
    if params.predictor <= 1 {
        // No prediction — pass through unchanged.
        return Ok(data.to_vec());
    }
    if params.colors == 0 || params.bits_per_component == 0 || params.columns == 0 {
        return Err(PdfError::other(
            "PDF filter: predictor /Colors, /BitsPerComponent, /Columns must be positive",
        ));
    }
    if !matches!(params.bits_per_component, 1 | 2 | 4 | 8 | 16) {
        return Err(PdfError::other(format!(
            "PDF filter: predictor /BitsPerComponent {} invalid (1, 2, 4, 8, 16)",
            params.bits_per_component
        )));
    }
    // Bits per pixel (sample) and the byte-rounded row width
    // (§7.4.4.4: "A row shall occupy a whole number of bytes").
    let bits_per_pixel = params.colors * params.bits_per_component;
    let row_bytes = bits_per_pixel
        .checked_mul(params.columns)
        .map(|b| b.div_ceil(8))
        .ok_or_else(|| PdfError::other("PDF filter: predictor row width overflow"))?;
    if row_bytes == 0 {
        return Ok(Vec::new());
    }

    match params.predictor {
        2 => tiff_predictor_2(data, params, row_bytes),
        10..=15 => png_predictor(data, bits_per_pixel.div_ceil(8).max(1), row_bytes),
        other => Err(PdfError::other(format!(
            "PDF filter: /Predictor {other} not supported (1, 2, 10..=15)"
        ))),
    }
}

/// TIFF Predictor 2 (§7.4.4.4 NOTE 1) — every component equals the
/// component `Colors` positions (one sample) to its left, modulo
/// `2^BitsPerComponent`. For the common 8-bit case this is a per-byte
/// running sum; sub-byte components are unpacked, summed, and repacked.
fn tiff_predictor_2(
    data: &[u8],
    params: &PredictorParams,
    row_bytes: usize,
) -> Result<Vec<u8>, PdfError> {
    if data.len() % row_bytes != 0 {
        return Err(PdfError::other(format!(
            "PDF filter: TIFF predictor row width {row_bytes} does not divide data length {}",
            data.len()
        )));
    }
    let mut out = data.to_vec();
    let bpc = params.bits_per_component;
    let comps_per_row = params.colors * params.columns;
    for row in out.chunks_mut(row_bytes) {
        if bpc == 8 {
            // Each byte is one component; predict from the component
            // `colors` bytes back (the same colour in the prior sample).
            for i in params.colors..row.len() {
                row[i] = row[i].wrapping_add(row[i - params.colors]);
            }
        } else if bpc == 16 {
            // Two bytes per component, big-endian; component i predicts
            // from component i - colors.
            let total = row.len() / 2;
            for i in params.colors..total {
                let prev = u16::from_be_bytes([
                    row[2 * (i - params.colors)],
                    row[2 * (i - params.colors) + 1],
                ]);
                let cur = u16::from_be_bytes([row[2 * i], row[2 * i + 1]]);
                let sum = cur.wrapping_add(prev).to_be_bytes();
                row[2 * i] = sum[0];
                row[2 * i + 1] = sum[1];
            }
        } else {
            // Sub-byte components (1 / 2 / 4 bits): unpack big-end
            // first, run the per-component sum, repack.
            let mask = (1u16 << bpc) - 1;
            let mut comps: Vec<u16> = Vec::with_capacity(comps_per_row);
            let mut bit = 0usize;
            for _ in 0..comps_per_row {
                let byte = row[bit / 8];
                let shift = 8 - bpc - (bit % 8);
                comps.push(((byte as u16) >> shift) & mask);
                bit += bpc;
            }
            for i in params.colors..comps.len() {
                comps[i] = (comps[i] + comps[i - params.colors]) & mask;
            }
            // Repack (clearing the data region first; trailing pad bits
            // stay 0 per the whole-byte-row rule).
            for b in row.iter_mut() {
                *b = 0;
            }
            let mut bit = 0usize;
            for c in comps {
                let shift = 8 - bpc - (bit % 8);
                row[bit / 8] |= ((c & mask) << shift) as u8;
                bit += bpc;
            }
        }
    }
    Ok(out)
}

/// PNG predictor group (§7.4.4.4, Table 9) — each input row is
/// `1 + row_bytes` long: a leading algorithm tag then the row data.
/// `bpp` is the byte distance to the "left"/"upper-left" neighbours.
fn png_predictor(data: &[u8], bpp: usize, row_bytes: usize) -> Result<Vec<u8>, PdfError> {
    let stride = row_bytes + 1;
    if data.len() % stride != 0 {
        return Err(PdfError::other(format!(
            "PDF filter: PNG predictor row stride {stride} does not divide data length {}",
            data.len()
        )));
    }
    let rows = data.len() / stride;
    let mut out = vec![0u8; rows * row_bytes];
    let mut prev = vec![0u8; row_bytes];
    for r in 0..rows {
        let tag = data[r * stride];
        let src = &data[r * stride + 1..r * stride + stride];
        let dst_start = r * row_bytes;
        for i in 0..row_bytes {
            let raw = src[i];
            let left = if i >= bpp {
                out[dst_start + i - bpp]
            } else {
                0
            };
            let up = prev[i];
            let up_left = if i >= bpp { prev[i - bpp] } else { 0 };
            let recon = match tag {
                0 => raw,                    // None
                1 => raw.wrapping_add(left), // Sub
                2 => raw.wrapping_add(up),   // Up
                3 => {
                    // Average — floor((left + up) / 2).
                    let avg = ((left as u16 + up as u16) / 2) as u8;
                    raw.wrapping_add(avg)
                }
                4 => raw.wrapping_add(paeth(left, up, up_left)), // Paeth
                other => {
                    return Err(PdfError::other(format!(
                        "PDF filter: PNG predictor row tag {other} unknown (0..=4)"
                    )))
                }
            };
            out[dst_start + i] = recon;
        }
        prev.copy_from_slice(&out[dst_start..dst_start + row_bytes]);
    }
    Ok(out)
}

/// PNG Paeth predictor (RFC 2083 §6.6) over the three byte neighbours.
fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (a, b, c) = (a as i16, b as i16, c as i16);
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
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

    #[test]
    fn predictor_1_passes_through() {
        let data = [1u8, 2, 3, 4, 5];
        let p = PredictorParams {
            predictor: 1,
            ..Default::default()
        };
        assert_eq!(apply_predictor(&data, &p).unwrap(), data);
    }

    #[test]
    fn png_up_predictor_round_trip() {
        // Two rows of 3 single-byte samples, Colors=1, BPC=8, bpp=1.
        // Original rows: [10,20,30] and [11,22,33].
        // PNG-Up encode (tag 2): row0 has no prior → stored as itself
        // (tag 0); row1 = row1 - row0 = [1,2,3] with tag 2.
        let encoded = [
            0u8, 10, 20, 30, // row 0: tag None, raw values
            2, 1, 2, 3, // row 1: tag Up, deltas from row 0
        ];
        let p = PredictorParams {
            predictor: 12, // PNG-Up signalled (per-row tag authoritative)
            colors: 1,
            bits_per_component: 8,
            columns: 3,
        };
        let out = apply_predictor(&encoded, &p).unwrap();
        assert_eq!(out, [10u8, 20, 30, 11, 22, 33]);
    }

    #[test]
    fn png_sub_predictor_respects_bpp() {
        // One row, Colors=3 (RGB), BPC=8 → bpp=3, columns=2 → 6 bytes.
        // Original: [R0=50,G0=60,B0=70, R1=55,G1=66,B1=77].
        // PNG-Sub (tag 1): each byte minus the byte bpp(=3) back; the
        // first sample has no left neighbour (treated as 0).
        // Encoded data = [50,60,70, 5,6,7].
        let encoded = [1u8, 50, 60, 70, 5, 6, 7];
        let p = PredictorParams {
            predictor: 11,
            colors: 3,
            bits_per_component: 8,
            columns: 2,
        };
        let out = apply_predictor(&encoded, &p).unwrap();
        assert_eq!(out, [50u8, 60, 70, 55, 66, 77]);
    }

    #[test]
    fn png_average_and_paeth_match_definitions() {
        // Single 1-byte-sample row exercising Average then Paeth.
        // Row 0 (tag None): [100]. Row 1 (tag Average): predict
        // floor((left=0 + up=100)/2)=50, raw stored = 30 → recon 80.
        // Row 2 (tag Paeth): left=0, up=80, up_left=0 → paeth=80; raw
        // stored 5 → recon 85.
        let encoded = [0u8, 100, 3, 30, 4, 5];
        let p = PredictorParams {
            predictor: 15,
            colors: 1,
            bits_per_component: 8,
            columns: 1,
        };
        let out = apply_predictor(&encoded, &p).unwrap();
        assert_eq!(out, [100u8, 80, 85]);
    }

    #[test]
    fn tiff_predictor_2_eight_bit() {
        // Colors=1, BPC=8, columns=4. Original row [5,10,15,20] encoded
        // as left-differences [5,5,5,5]; decode sums them back.
        let encoded = [5u8, 5, 5, 5];
        let p = PredictorParams {
            predictor: 2,
            colors: 1,
            bits_per_component: 8,
            columns: 4,
        };
        let out = apply_predictor(&encoded, &p).unwrap();
        assert_eq!(out, [5u8, 10, 15, 20]);
    }

    #[test]
    fn tiff_predictor_2_rgb_interleaved() {
        // Colors=3, BPC=8, columns=2 → 6 bytes. Original
        // [10,20,30, 40,60,80]; left-diff per component is
        // [10,20,30, 30,40,50] (sample 1 minus sample 0 per channel).
        let encoded = [10u8, 20, 30, 30, 40, 50];
        let p = PredictorParams {
            predictor: 2,
            colors: 3,
            bits_per_component: 8,
            columns: 2,
        };
        let out = apply_predictor(&encoded, &p).unwrap();
        assert_eq!(out, [10u8, 20, 30, 40, 60, 80]);
    }

    #[test]
    fn tiff_predictor_2_four_bit_components() {
        // Colors=1, BPC=4, columns=4 → 4 components in 2 bytes.
        // Original components [3,5,8,12]; left-diffs [3,2,3,4] modulo
        // 16. Packed big-end-first: byte0 = 0x32, byte1 = 0x34.
        let encoded = [0x32u8, 0x34];
        let p = PredictorParams {
            predictor: 2,
            colors: 1,
            bits_per_component: 4,
            columns: 4,
        };
        let out = apply_predictor(&encoded, &p).unwrap();
        // Reconstructed components [3,5,8,12] → packed 0x35, 0x8C.
        assert_eq!(out, [0x35u8, 0x8C]);
    }

    #[test]
    fn png_predictor_rejects_misaligned_data() {
        // 3-byte data with stride 4 (columns=3 + tag) does not divide.
        let p = PredictorParams {
            predictor: 12,
            colors: 1,
            bits_per_component: 8,
            columns: 3,
        };
        assert!(apply_predictor(&[2u8, 1, 2], &p).is_err());
    }
}
