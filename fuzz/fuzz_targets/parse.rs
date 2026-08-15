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
//! When the bytes open as a document, every catalog-level extraction
//! walker is additionally driven. Each walks an attacker-controlled
//! tree shape (the page tree, the §12.3.3 outline tree, the §7.9.6
//! name trees, the §12.5.6 annotation array, the §12.6 action chains,
//! the §12.4.3 article-thread bead rings, the §14.7 struct tree, the
//! §8.11 optional-content graph) with its own depth bound and cycle
//! guard, so a self-referential or over-deep tree is truncated rather
//! than blowing the stack:
//!
//!   * outline + named destinations — §12.3.3 / §12.3.2.3.
//!   * page labels — §12.4.2 `/PageLabels` §7.9.7 number tree.
//!   * text extraction — §9 incl. the §9.7.5.3 embedded-CMap
//!     code → CID machinery and the §9.10 /ToUnicode path.
//!   * annotations / actions / links — §12.5.6 / §12.6 / §12.5.6.5.
//!   * attachments — §7.11 `/EmbeddedFiles` name tree.
//!   * threads — §12.4.3 circular bead rings.
//!   * image + inline images — §8.9 XObject and inline scanners.
//!   * optional content — §8.11 `/OCProperties` graph.
//!   * logical reading order — §14.7 struct tree.
//!   * signatures + doc timestamps — §12.8 `/ByteRange` + CMS parse.
//!   * PDF/A signals + hierarchy verify + XMP packet — catalog scan.

use libfuzzer_sys::fuzz_target;
use oxideav_pdf::read_pdf_to_scene;
use oxideav_pdf::reader::content::parse_content_stream;
use oxideav_pdf::reader::inline_images::extract_inline_images_from_stream;
use oxideav_pdf::reader::linearize::parse_linearization_dict;
use oxideav_pdf::reader::{
    actions, annotations, attachments, doc_timestamps, extract_text, image_xobjects,
    inline_images, links, named_destinations, optional_content, outline, page_label_ranges,
    page_labels, pdfa_signals, read_in_logical_order, signatures, threads, verify_hierarchy,
    DocumentReader,
};

fuzz_target!(|data: &[u8]| {
    let _ = read_pdf_to_scene(data);
    let _ = parse_linearization_dict(data);
    let _ = extract_inline_images_from_stream(data);
    let _ = parse_content_stream(data);
    if let Ok(mut reader) = DocumentReader::open(data) {
        // §12.3 document navigation.
        let _ = outline(&mut reader);
        let _ = named_destinations(&mut reader);
        let _ = page_labels(&mut reader);
        let _ = page_label_ranges(&mut reader);
        // §9 text extraction + §14.7 logical order.
        let _ = extract_text(&mut reader);
        let _ = read_in_logical_order(&mut reader);
        // §12.5 / §12.6 annotation, link, and action trees.
        let _ = annotations(&mut reader);
        let _ = links(&mut reader);
        let _ = actions(&mut reader);
        // §7.11 attachments + §12.4.3 article threads.
        let _ = attachments(&mut reader);
        let _ = threads(&mut reader);
        // §8.9 image + inline-image XObject walkers.
        let _ = image_xobjects(&mut reader);
        let _ = inline_images(&mut reader);
        // §8.11 optional-content graph.
        let _ = optional_content(&mut reader);
        // §12.8 signatures / document timestamps.
        let _ = signatures(&mut reader);
        let _ = doc_timestamps(&mut reader);
        // Catalog-level integrity scans.
        let _ = pdfa_signals(&mut reader);
        let _ = verify_hierarchy(&mut reader);
        let _ = reader.xmp_packet();
    }
});
