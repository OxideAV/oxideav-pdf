#![no_main]

//! Stream-filter fuzz harness.
//!
//! Drives every §7.4 stream-decode primitive directly on
//! attacker-controlled bytes, bypassing the object/xref layer so a
//! single-byte mutation that would not survive end-to-end document
//! decode still reaches the decompressor state machines:
//!
//!   * [`ascii_hex_decode`] — §7.4.2 ASCIIHexDecode.
//!   * [`ascii85_decode`] — §7.4.3 ASCII85Decode (the base-85 group
//!     arithmetic and the `z` / `~>` special tokens).
//!   * [`run_length_decode`] — §7.4.5 RunLengthDecode (the length-byte
//!     run/literal state machine).
//!   * [`lzw_decode`] / [`lzw_decode_with_early_change`] — §7.4.4.2
//!     variable-width (9..=12-bit) LZW, both `/EarlyChange` settings.
//!     The dictionary-expansion path is the classic decompression-bomb
//!     surface: a short input can address a long dictionary entry, so
//!     the output size is what libFuzzer's `-rss_limit_mb` bounds.
//!   * [`flate_decompress`] — §7.4.4 FlateDecode (zlib / DEFLATE).
//!   * [`apply_predictor`] — §7.4.4.4 the PNG / TIFF predictor
//!     post-filter, driven with **attacker-controlled**
//!     `/Colors` / `/BitsPerComponent` / `/Columns` / `/Predictor`
//!     values pulled out of the fuzz input. The per-row byte-count
//!     arithmetic (`colors × bpc × columns`) is an integer-overflow /
//!     huge-allocation surface, so the params are fuzzed independently
//!     of the payload.
//!
//! Contract: every call returns to its caller. A `panic!`,
//! `unwrap()` on `None`, slice-OOB, integer-overflow in debug, or OOM
//! abort is a finding and fails the fuzzer.

use libfuzzer_sys::fuzz_target;
use oxideav_pdf::reader::filters::{
    apply_predictor, ascii85_decode, ascii_hex_decode, flate_decompress, lzw_decode,
    lzw_decode_with_early_change, run_length_decode, PredictorParams,
};

fuzz_target!(|data: &[u8]| {
    // The first 5 bytes (when present) parameterise the predictor
    // post-filter; the remainder is the shared payload every filter
    // decodes. Splitting this way lets the fuzzer drive wild
    // colors/columns/bpc combinations against the same body without
    // biasing the corpus.
    let (params_bytes, payload) = if data.len() >= 5 {
        (&data[..5], &data[5..])
    } else {
        (&[][..], data)
    };

    // Every filter runs on the shared payload — cheap, and each has a
    // distinct state machine.
    let _ = ascii_hex_decode(payload);
    let _ = ascii85_decode(payload);
    let _ = run_length_decode(payload);
    let _ = lzw_decode(payload);
    let _ = lzw_decode_with_early_change(payload, true);
    let _ = lzw_decode_with_early_change(payload, false);
    let _ = flate_decompress(payload);

    // Predictor post-filter with attacker-controlled geometry.
    if params_bytes.len() == 5 {
        // `/Predictor`: bias toward the spec-valid set (1 / 2 / 10..=15)
        // but let the raw byte through so out-of-range tags are also
        // exercised.
        let predictor = match params_bytes[0] % 8 {
            0 => 1,
            1 => 2,
            n => 8 + i64::from(n), // 10..=15
        };
        // Keep the geometry non-zero but attacker-scaled: a large
        // `columns` × `colors` × `bpc` row width must not overflow or
        // pre-allocate beyond what the payload can back.
        let colors = 1 + (params_bytes[1] as usize);
        let bits_per_component = match params_bytes[2] % 5 {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => 16,
        };
        let columns = usize::from(u16::from_le_bytes([params_bytes[3], params_bytes[4]]));
        let p = PredictorParams {
            predictor,
            colors,
            bits_per_component,
            columns,
        };
        let _ = apply_predictor(payload, &p);

        // Also drive the predictor over a Flate-inflated payload, the
        // real chain `decode_stream` builds for `/FlateDecode` with a
        // `/Predictor` parameter present.
        if let Ok(inflated) = flate_decompress(payload) {
            let _ = apply_predictor(&inflated, &p);
        }
    }
});
