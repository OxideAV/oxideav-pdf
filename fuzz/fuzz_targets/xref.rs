#![no_main]

//! Cross-reference parsing fuzz harness.
//!
//! Drives the §7.5.4 classic xref-table parser, the §7.5.8
//! cross-reference-stream parser, and the §7.5.8.4 hybrid-reference
//! merge directly — bypassing the rest of the reader. The xref is the
//! single most error-prone PDF surface: it is parsed by scanning
//! *backwards* from EOF for the `startxref` keyword, then jumping to
//! that file offset (attacker-controlled), then walking subsection
//! tables whose entry counts + first-object numbers are also
//! attacker-controlled. Stream xrefs add another layer: a
//! FlateDecoded payload + a /W width array + /Index array that drive
//! the per-entry byte-precision arithmetic.
//!
//! Two pairs of public entry points are fuzzed off the same input
//! bytes so the offset arithmetic is exercised at three different
//! abstraction levels:
//!
//!   * [`parse_xref`] — the high-level "find the xref and read it"
//!     entry point. Calls `find_startxref_offset` internally then
//!     dispatches to either the §7.5.4 classic walker or the §7.5.8
//!     stream walker.
//!   * [`find_startxref_offset`] + [`parse_xref_at`] — the two-step
//!     split. Driven separately so a malformed `startxref` keyword
//!     near EOF is fuzzed in isolation from the offset-jump path.
//!
//! Contract: every call returns to its caller. A `panic!`,
//! `unwrap()` on `None`, slice-OOB, integer-overflow in debug, or OOM
//! abort is a finding and fails the fuzzer.

use libfuzzer_sys::fuzz_target;
use oxideav_pdf::reader::xref::{find_startxref_offset, parse_xref, parse_xref_at};

fuzz_target!(|data: &[u8]| {
    let _ = parse_xref(data);

    // Two-step split: drive the EOF-scan and the offset-jump
    // independently so a malformed `startxref` keyword is exercised
    // in isolation. parse_xref_at also gets a fuzz-derived offset
    // pulled out of the input itself so we exercise wildly wrong
    // offsets (deep past EOF, into the header, into a stream body).
    if let Ok(off) = find_startxref_offset(data) {
        let _ = parse_xref_at(data, off);
    }
    if data.len() >= 8 {
        // Use the first 8 bytes as an arbitrary u64 offset. This is
        // deliberately not bounds-checked against `data.len()` — we
        // want parse_xref_at to handle the out-of-range case without
        // panicking.
        let off = u64::from_le_bytes(data[..8].try_into().unwrap());
        let _ = parse_xref_at(&data[8..], off);
    }
});
