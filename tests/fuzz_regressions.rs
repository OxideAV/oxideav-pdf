//! Regression tests for crashes discovered by the cargo-fuzz harness
//! under `fuzz/`. Each test feeds a captured crash artifact to the
//! same public entry point the fuzz target drove and asserts that the
//! call returns a `Result` rather than panicking / blowing the stack.
//!
//! When a new crash artifact is captured by the fuzz harness, copy
//! it from `fuzz/artifacts/<target>/crash-…` to
//! `tests/fixtures/fuzz_<target>_<short-name>.bin`, then add a test
//! here that asserts the bug is fixed.

use oxideav_pdf::read_pdf_to_scene;
use oxideav_pdf::reader::inline_images::extract_inline_images_from_stream;

/// Round 145 fuzz: a crafted PDF whose §7.7.3.2 /Pages tree
/// references its own /Kids back to the root produced infinite
/// recursion in `walk_pages_tree`, blowing the call stack under the
/// AddressSanitizer-instrumented fuzz harness. The fix bounds the
/// /Pages tree walk by both depth (≤ 256) and a visited-node set so
/// a cycle is detected and rejected as a malformed tree instead of
/// recursing forever.
#[test]
fn parse_walk_pages_tree_no_stack_overflow_on_cycle() {
    let bytes = include_bytes!("fixtures/fuzz_parse_pages_cycle.bin");
    // The exact error variant is intentionally unconstrained: what we
    // care about is the call *returning* (Ok or Err — anything but
    // SIGSEGV / SIGABRT from a stack-overflow). Pre-fix this aborts
    // under ASAN; post-fix it returns Err(PdfError::Other(…)) citing
    // the cycle or the depth cap.
    let _ = read_pdf_to_scene(bytes);
}

/// Round 145 fuzz: a malformed inline image whose §8.9.7 BI/ID/EI
/// dict carries a §7.3.4.2 literal string ending in a lone backslash
/// (so the in-string escape-skip pushes `end` past the buffer)
/// triggered a slice-index panic in `extract_inline_images_from_stream`.
/// The fix clamps the post-loop end to `bytes.len()` so a
/// truncated-but-malformed escape produces a soft open-string
/// result rather than a panic.
#[test]
fn parse_inline_image_string_escape_no_slice_panic() {
    let bytes = include_bytes!("fixtures/fuzz_parse_inline_image_string_escape.bin");
    // Both entry points — the wrapper (read_pdf_to_scene) and the
    // direct stream scanner — must return rather than panic.
    let _ = read_pdf_to_scene(bytes);
    let _ = extract_inline_images_from_stream(bytes);
}

/// Round 191 fuzz: a crafted hybrid-reference PDF whose §7.5.8 XRef
/// stream declared the catalog (object 1) as a §7.5.7 Type-2
/// compressed entry whose containing ObjStm is object 1 itself.
/// `resolve(1)` saw the compressed entry, called
/// `decode_objstm_container(wanted=1, container=1)`, which called
/// `self.resolve(1)` again — looping until the call stack overflowed
/// under the AddressSanitizer-instrumented fuzz harness. The fix
/// rejects any Type-2 entry whose container is itself a Type-2
/// entry before re-entering `resolve` (§7.5.7 normatively forbids
/// nested object streams, so the cycle is statically detectable
/// from the xref table).
///
/// Crash discovered: scheduled Fuzz workflow run 26628044506 against
/// pre-r188 master 98ff5a3, artifact
/// `crash-b5c79fc051a5101edb905232369d071e99f29c4d`.
#[test]
fn parse_objstm_self_container_no_stack_overflow() {
    let bytes = include_bytes!("fixtures/fuzz_objstm_self_container_cycle.bin");
    // Pre-fix this aborts via stack overflow (libfuzzer reports
    // `AddressSanitizer: stack-overflow`); post-fix it returns
    // `Err(PdfError::Other(…))` citing the §7.5.7 rule.
    let _ = read_pdf_to_scene(bytes);
    let _ = extract_inline_images_from_stream(bytes);
}
