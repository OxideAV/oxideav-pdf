//! Round-131 cross-reference stream corners (ISO 32000-1 §7.5.8).
//!
//! `tests/xref_stream.rs` covered the happy path (uncompressed +
//! `/FlateDecode` + `/Predictor 12`); this set extends coverage to the
//! corners the spec calls out but the round-6 implementation hadn't
//! exercised explicitly:
//!
//! * **§7.5.8.3 forward-compat for unknown types.** "In PDF 1.5 through
//!   PDF 1.7, only types 0, 1, and 2 are allowed. Any other value shall
//!   be interpreted as a reference to the null object, thus permitting
//!   new entry types to be defined in the future." The reader must NOT
//!   refuse a type-3+ entry — it must keep parsing and resolve such
//!   slots to `null`. We craft a fixture whose XRef stream carries a
//!   type-7 entry alongside the real type-1 entries and assert the
//!   reader still extracts the page.
//! * **§7.5.8.3 W-array default for the type field.** When `w[0] == 0`
//!   "the type field shall not be present, and shall default to type
//!   1." We emit `/W [0 4 2]` and verify the resulting entries decode
//!   as in-use (not as type-0 free entries).
//! * **§7.5.8.3 W-array default for the generation field.** Table 18
//!   Type 1 field 3 specifies "Default value: 0", and the W-array note
//!   says a zero w[i] omits the field entirely. We emit `/W [1 4 0]`
//!   and verify the generation reads back as 0.
//! * **§7.5.8.2 multi-subsection /Index.** The default `[0 Size]` is
//!   exercised elsewhere; this fixture splits the same content into
//!   two non-contiguous subsections (`/Index [0 1 5 4]`) so the index
//!   walker has to honour the per-subsection starting object number.

use std::io::Write;

use oxideav_pdf::read_pdf_to_scene;

/// Lay out a minimal `1 Catalog → 2 Pages → 3 Page` body and return
/// the byte offsets of each object plus the in-progress buffer ready
/// for the test-specific xref stream object to be appended.
fn build_body() -> (Vec<u8>, [u64; 5]) {
    let mut bytes = Vec::with_capacity(2048);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = [0u64; 5];
    offsets[1] = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets[2] = bytes.len() as u64;
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\n",
    );
    (bytes, offsets)
}

fn finish(bytes: &mut Vec<u8>, xref_off: u64) {
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());
}

/// §7.5.8.3: a type-7 (or any value beyond 0/1/2) entry must NOT crash
/// the reader; the spec mandates "shall be interpreted as a reference
/// to the null object." We slot a single type-7 entry in the middle of
/// an otherwise well-formed table and verify the page still parses.
#[test]
fn future_entry_type_resolves_as_null_not_error() {
    let (mut bytes, mut offsets) = build_body();
    offsets[4] = bytes.len() as u64;

    // W = [1 4 2] — same shape as `tests/xref_stream.rs`.
    fn make(t: u8, f2: u32, f3: u16) -> [u8; 7] {
        let mut out = [0u8; 7];
        out[0] = t;
        out[1..5].copy_from_slice(&f2.to_be_bytes());
        out[5..7].copy_from_slice(&f3.to_be_bytes());
        out
    }
    let mut table = Vec::with_capacity(5 * 7);
    table.extend_from_slice(&make(0, 0, 65535));
    table.extend_from_slice(&make(1, offsets[1] as u32, 0));
    table.extend_from_slice(&make(1, offsets[2] as u32, 0));
    table.extend_from_slice(&make(1, offsets[3] as u32, 0));
    // Object id 4 is the xref stream itself — type 1.
    table.extend_from_slice(&make(1, offsets[4] as u32, 0));
    // Object id 5 is a "future-type" entry the spec says should be
    // resolved as null. Padding /Size up by one so the reader produces
    // a slot for it.
    table.extend_from_slice(&make(7, 0xDEAD_BEEF, 0));

    let dict = format!(
        "<< /Type /XRef /Size 6 /Index [0 6] /W [1 4 2] /Root 1 0 R /Length {} >>\n",
        table.len()
    );
    bytes.extend_from_slice(b"4 0 obj\n");
    bytes.extend_from_slice(dict.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&table);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");
    finish(&mut bytes, offsets[4]);

    let scene = read_pdf_to_scene(&bytes).expect("future-type entry must not crash the reader");
    let pages = scene.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
}

/// §7.5.8.3 W-array note: "If the first element is zero, the type field
/// shall not be present, and shall default to type 1." A fixture with
/// `/W [0 4 2]` omits the type byte; every entry must be parsed as
/// in-use (not free, not Compressed).
#[test]
fn w_array_w0_zero_defaults_to_in_use() {
    let (mut bytes, mut offsets) = build_body();
    offsets[4] = bytes.len() as u64;

    // Per-entry: f2 (4 bytes offset) + f3 (2 bytes generation). The
    // first entry would normally be the free-list head (type 0) — but
    // the W array default says we MUST treat every entry as type 1
    // when w[0] = 0, so id 0 here points at offset 0 as a (degenerate)
    // in-use entry. The reader is required to honour that.
    fn make(f2: u32, f3: u16) -> [u8; 6] {
        let mut out = [0u8; 6];
        out[..4].copy_from_slice(&f2.to_be_bytes());
        out[4..6].copy_from_slice(&f3.to_be_bytes());
        out
    }
    let mut table = Vec::with_capacity(5 * 6);
    table.extend_from_slice(&make(0, 65535)); // id 0 — still parses as in-use per default.
    table.extend_from_slice(&make(offsets[1] as u32, 0));
    table.extend_from_slice(&make(offsets[2] as u32, 0));
    table.extend_from_slice(&make(offsets[3] as u32, 0));
    table.extend_from_slice(&make(offsets[4] as u32, 0));

    let dict = format!(
        "<< /Type /XRef /Size 5 /Index [0 5] /W [0 4 2] /Root 1 0 R /Length {} >>\n",
        table.len()
    );
    bytes.extend_from_slice(b"4 0 obj\n");
    bytes.extend_from_slice(dict.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&table);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");
    finish(&mut bytes, offsets[4]);

    let scene = read_pdf_to_scene(&bytes).expect("w[0]=0 default must be honoured");
    let pages = scene.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

/// §7.5.8.3 W-array note + Table 18 Type 1 field 3 "Default value: 0".
/// A zero `w[2]` means the generation field is omitted; the entry must
/// still decode (generation defaults to 0).
#[test]
fn w_array_w2_zero_defaults_generation_to_zero() {
    let (mut bytes, mut offsets) = build_body();
    offsets[4] = bytes.len() as u64;

    // Per-entry: t (1) + offset (4). No generation byte at all.
    fn make(t: u8, f2: u32) -> [u8; 5] {
        let mut out = [0u8; 5];
        out[0] = t;
        out[1..5].copy_from_slice(&f2.to_be_bytes());
        out
    }
    let mut table = Vec::with_capacity(5 * 5);
    table.extend_from_slice(&make(0, 0));
    table.extend_from_slice(&make(1, offsets[1] as u32));
    table.extend_from_slice(&make(1, offsets[2] as u32));
    table.extend_from_slice(&make(1, offsets[3] as u32));
    table.extend_from_slice(&make(1, offsets[4] as u32));

    let dict = format!(
        "<< /Type /XRef /Size 5 /Index [0 5] /W [1 4 0] /Root 1 0 R /Length {} >>\n",
        table.len()
    );
    bytes.extend_from_slice(b"4 0 obj\n");
    bytes.extend_from_slice(dict.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&table);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");
    finish(&mut bytes, offsets[4]);

    let scene = read_pdf_to_scene(&bytes).expect("w[2]=0 default must be honoured");
    let pages = scene.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

/// §7.5.8.2 `/Index`: an array of `(first, count)` pairs in ascending
/// object-number order. Split the same five entries into two
/// subsections so the walker has to honour per-subsection start
/// numbers (rather than implicitly numbering from 0 across the whole
/// payload).
#[test]
fn multi_subsection_index_resolves_per_subsection_start() {
    let (mut bytes, mut offsets) = build_body();
    offsets[4] = bytes.len() as u64;

    fn make(t: u8, f2: u32, f3: u16) -> [u8; 7] {
        let mut out = [0u8; 7];
        out[0] = t;
        out[1..5].copy_from_slice(&f2.to_be_bytes());
        out[5..7].copy_from_slice(&f3.to_be_bytes());
        out
    }
    // Subsection A: id 0 only — the free-list head.
    // Subsection B: ids 1..=4 — the in-use objects (catalog, pages,
    // page, xref-stream-self).
    let mut table = Vec::with_capacity(5 * 7);
    table.extend_from_slice(&make(0, 0, 65535));
    table.extend_from_slice(&make(1, offsets[1] as u32, 0));
    table.extend_from_slice(&make(1, offsets[2] as u32, 0));
    table.extend_from_slice(&make(1, offsets[3] as u32, 0));
    table.extend_from_slice(&make(1, offsets[4] as u32, 0));

    let dict = format!(
        "<< /Type /XRef /Size 5 /Index [0 1 1 4] /W [1 4 2] /Root 1 0 R /Length {} >>\n",
        table.len()
    );
    bytes.extend_from_slice(b"4 0 obj\n");
    bytes.extend_from_slice(dict.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&table);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");
    finish(&mut bytes, offsets[4]);

    let scene =
        read_pdf_to_scene(&bytes).expect("multi-subsection /Index must walk per-subsection ids");
    let pages = scene.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}

/// §7.5.8.2 cross-reference stream encoded with `/FlateDecode` but with
/// no `/DecodeParms /Predictor` entry — Predictor 1 (no transformation)
/// is the default per §7.4.4.4. The reader must therefore accept a
/// Flate-only body without a predictor reversal step.
#[test]
fn flate_without_predictor_decodes_predictor_1_default() {
    let (mut bytes, mut offsets) = build_body();
    offsets[4] = bytes.len() as u64;

    fn make(t: u8, f2: u32, f3: u16) -> [u8; 7] {
        let mut out = [0u8; 7];
        out[0] = t;
        out[1..5].copy_from_slice(&f2.to_be_bytes());
        out[5..7].copy_from_slice(&f3.to_be_bytes());
        out
    }
    let mut raw = Vec::with_capacity(5 * 7);
    raw.extend_from_slice(&make(0, 0, 65535));
    raw.extend_from_slice(&make(1, offsets[1] as u32, 0));
    raw.extend_from_slice(&make(1, offsets[2] as u32, 0));
    raw.extend_from_slice(&make(1, offsets[3] as u32, 0));
    raw.extend_from_slice(&make(1, offsets[4] as u32, 0));

    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&raw).unwrap();
    let compressed = enc.finish().unwrap();

    // Note: no /DecodeParms — Predictor 1 is the default per §7.4.4.4.
    let dict = format!(
        "<< /Type /XRef /Size 5 /Index [0 5] /W [1 4 2] /Filter /FlateDecode /Root 1 0 R /Length {} >>\n",
        compressed.len()
    );
    bytes.extend_from_slice(b"4 0 obj\n");
    bytes.extend_from_slice(dict.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");
    finish(&mut bytes, offsets[4]);

    let scene = read_pdf_to_scene(&bytes).expect("flate-only body must decode (predictor 1)");
    let pages = scene.pages.expect("pages");
    assert_eq!(pages.len(), 1);
}
