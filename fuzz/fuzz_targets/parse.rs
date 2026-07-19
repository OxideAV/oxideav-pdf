#![no_main]

//! End-to-end PDF parse fuzz harness.
//!
//! Drives the full reader on arbitrary fuzz-supplied bytes. The
//! decoder must always return a `Result` and never panic / abort /
//! OOM, regardless of how malformed the input is.
//!
//! The contract under test is purely that the calls *return*: a
//! malformed file yields `Err(PdfError::…)`, a well-formed one yields
//! `Ok(Scene)`, and neither path may panic, integer-overflow in a
//! debug build, index out of bounds, or pre-allocate an
//! attacker-claimed object-count / stream-length / page-count buffer
//! that exceeds what the input could possibly back. Return values
//! are intentionally discarded.
//!
//! Four independent entry points are fuzzed off the same input bytes
//! because they map to distinct ISO 32000-1 §-sections with distinct
//! parsing state machines:
//!
//!   * [`read_pdf_to_scene`] — full §7.5 file structure + §7.8 page
//!     tree + §8 / §9 content streams. The bare (no-password) path
//!     dispatches §7.6 standard-handler decryption when the trailer
//!     names an /Encrypt dict but rejects encrypted files (the
//!     password-fuzzer harness handles that path instead).
//!   * [`parse_linearization_dict`] — §7.5.2 standalone parser for
//!     the first-object linearization parameter dictionary. Driven
//!     independently because it has its own offset / length / page
//!     count fields that are validated without consulting the rest
//!     of the xref.
//!   * [`extract_inline_images_from_stream`] — §8.9.7 BI / ID / EI
//!     inline-image scanner over a content-stream byte buffer.
//!     Walks the marker-state machine directly so an unterminated
//!     `BI` or an over-long inline-image payload is exercised in
//!     isolation from the rest of the reader.
//!   * [`parse_content_stream`] — §8 / §9 content-stream parser
//!     ([`oxideav_pdf::reader::parse_content_stream`]). Same input
//!     bytes interpreted as the body of a content stream so the §8
//!     operator dispatcher (q/Q, cm, ...) and the §9 text-state
//!     operators (Tf, Tj, TJ) get fuzzed without going through the
//!     enclosing /Page → /Contents reference chain.
//!
//! When the bytes open as a document, the round-418 catalog-level
//! extraction surfaces are additionally driven — each walks
//! attacker-controlled tree shapes with its own bounds and cycle
//! guards:
//!
//!   * [`outline`] + [`named_destinations`] — §12.3.3 bookmark tree
//!     and the §12.3.2.3 named-destination sources (catalogue
//!     `/Dests` dictionary + `/Names → /Dests` §7.9.6 name tree).
//!   * [`page_labels`] — §12.4.2 `/PageLabels` §7.9.7 number tree +
//!     label synthesis.
//!   * [`extract_text`] — §9 text extraction incl. the §9.7.5.3
//!     embedded-CMap code → CID machinery and the §9.10 /ToUnicode
//!     path.

use libfuzzer_sys::fuzz_target;
use oxideav_pdf::read_pdf_to_scene;
use oxideav_pdf::reader::content::parse_content_stream;
use oxideav_pdf::reader::inline_images::extract_inline_images_from_stream;
use oxideav_pdf::reader::linearize::parse_linearization_dict;
use oxideav_pdf::reader::{
    extract_text, named_destinations, outline, page_labels, DocumentReader,
};

fuzz_target!(|data: &[u8]| {
    let _ = read_pdf_to_scene(data);
    let _ = parse_linearization_dict(data);
    let _ = extract_inline_images_from_stream(data);
    let _ = parse_content_stream(data);
    if let Ok(mut reader) = DocumentReader::open(data) {
        let _ = outline(&mut reader);
        let _ = named_destinations(&mut reader);
        let _ = page_labels(&mut reader);
        let _ = extract_text(&mut reader);
    }
});
