//! Round-7 PDF 1.5+ object-stream (`/Type /ObjStm`) resolver tests.
//!
//! Hand-builds tiny PDF fixtures where some "ordinary" indirect
//! objects (the Catalog and the Pages tree, here) live INSIDE an
//! `/Type /ObjStm` container rather than at their own byte offsets.
//! The xref stream's type-2 entries point at the container + index;
//! [`oxideav_pdf::read_pdf_to_scene`] is expected to walk through the
//! container and surface the Catalog as if it were a regular indirect
//! object.
//!
//! Per ISO 32000-1 §7.5.7, an ObjStm has:
//! * `/Type /ObjStm`
//! * `/N` — the number of compressed objects.
//! * `/First` — byte offset (within the *decoded* stream) of the
//!   first compressed-object body.
//! * payload = `obj_num_1 off_1 obj_num_2 off_2 ...` (decimal
//!   integers separated by whitespace) followed by the concatenated
//!   object bodies (without `n gen obj` / `endobj` wrappers).

use oxideav_pdf::read_pdf_to_scene;

/// Build a PDF where the Catalog (object 1) lives inside an ObjStm
/// container (object 5). The xref stream lists object 1 as a
/// type-2 entry pointing at object 5, slot 0.
fn build_pdf_with_objstm_catalog() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2048);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");

    // We pre-decide the layout:
    //   Obj 1: Catalog (compressed inside ObjStm @ obj 5, slot 0)
    //   Obj 2: Pages tree (compressed inside ObjStm @ obj 5, slot 1)
    //   Obj 3: Page (regular indirect, byte offset)
    //   Obj 4: never used (or could be a stream; we leave free)
    //   Obj 5: ObjStm (regular indirect)
    //   Obj 6: XRef stream

    let mut offsets: Vec<u64> = vec![0; 7];

    // Obj 3: Page — written as a regular indirect object.
    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\n",
    );

    // Build the ObjStm payload: header (decimal "obj_num offset"
    // pairs) followed by body bytes for each compressed object.
    let body1: &[u8] = b"<</Type/Catalog/Pages 2 0 R>>";
    let body2: &[u8] = b"<</Type/Pages/Kids[3 0 R]/Count 1>>";
    // Header lists offsets relative to /First (the start of the
    // body region). Slot 0 starts at 0; slot 1 at body1.len().
    let mut header = String::new();
    header.push_str(&format!("1 0 2 {} ", body1.len()));
    let header_bytes = header.into_bytes();
    let first = header_bytes.len();
    let mut payload = Vec::with_capacity(first + body1.len() + body2.len());
    payload.extend_from_slice(&header_bytes);
    payload.extend_from_slice(body1);
    payload.extend_from_slice(body2);

    // FlateDecode-compress the payload to exercise the same code
    // path the real-world writers use.
    let compressed = compcol::vec::compress_to_vec::<compcol::zlib::Zlib>(&payload).unwrap();

    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(b"5 0 obj\n");
    let dict = format!(
        "<< /Type /ObjStm /N 2 /First {} /Filter /FlateDecode /Length {} >>\n",
        first,
        compressed.len()
    );
    bytes.extend_from_slice(dict.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    // Obj 6: XRef stream. /W [1 4 2] = 7 bytes per entry.
    // Entries:
    //   id 0: type 0, free
    //   id 1: type 2, container=5, index=0
    //   id 2: type 2, container=5, index=1
    //   id 3: type 1, offset=offsets[3]
    //   id 4: type 0, free (skip)
    //   id 5: type 1, offset=offsets[5]
    //   id 6: type 1, offset=offsets[6] (set after we know it)
    offsets[6] = bytes.len() as u64;

    fn make_t1(off: u32) -> [u8; 7] {
        let mut e = [0u8; 7];
        e[0] = 1;
        e[1..5].copy_from_slice(&off.to_be_bytes());
        e[5..7].copy_from_slice(&0u16.to_be_bytes());
        e
    }
    fn make_t2(container: u32, idx: u16) -> [u8; 7] {
        let mut e = [0u8; 7];
        e[0] = 2;
        e[1..5].copy_from_slice(&container.to_be_bytes());
        e[5..7].copy_from_slice(&idx.to_be_bytes());
        e
    }
    fn make_t0() -> [u8; 7] {
        let mut e = [0u8; 7];
        e[0] = 0;
        e[1..5].copy_from_slice(&0u32.to_be_bytes());
        e[5..7].copy_from_slice(&65535u16.to_be_bytes());
        e
    }

    let mut table = Vec::with_capacity(7 * 7);
    table.extend_from_slice(&make_t0());
    table.extend_from_slice(&make_t2(5, 0));
    table.extend_from_slice(&make_t2(5, 1));
    table.extend_from_slice(&make_t1(offsets[3] as u32));
    table.extend_from_slice(&make_t0());
    table.extend_from_slice(&make_t1(offsets[5] as u32));
    table.extend_from_slice(&make_t1(offsets[6] as u32));

    let xref_dict = format!(
        "<< /Type /XRef /Size 7 /Index [0 7] /W [1 4 2] /Root 1 0 R /Length {} >>\n",
        table.len()
    );
    bytes.extend_from_slice(b"6 0 obj\n");
    bytes.extend_from_slice(xref_dict.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&table);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_off = offsets[6];
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());
    bytes
}

#[test]
fn objstm_resolver_decodes_compressed_catalog() {
    let pdf = build_pdf_with_objstm_catalog();
    let scene = read_pdf_to_scene(&pdf).expect("ObjStm-protected PDF should decode");
    let pages = scene.pages.expect("pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].width, 100.0);
    assert_eq!(pages[0].height, 100.0);
}

/// Build a fixture where the ObjStm's header has the wrong object
/// number for a slot — the resolver must reject it instead of
/// surfacing the wrong object.
fn build_pdf_with_objstm_header_mismatch() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2048);
    bytes.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<u64> = vec![0; 7];

    offsets[3] = bytes.len() as u64;
    bytes.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\n",
    );

    // Header claims slot 0 holds object 99 (not 1) — mismatch.
    let body1: &[u8] = b"<</Type/Catalog/Pages 2 0 R>>";
    let body2: &[u8] = b"<</Type/Pages/Kids[3 0 R]/Count 1>>";
    let mut header = String::new();
    header.push_str(&format!("99 0 2 {} ", body1.len()));
    let header_bytes = header.into_bytes();
    let first = header_bytes.len();
    let mut payload = Vec::with_capacity(first + body1.len() + body2.len());
    payload.extend_from_slice(&header_bytes);
    payload.extend_from_slice(body1);
    payload.extend_from_slice(body2);
    let compressed = compcol::vec::compress_to_vec::<compcol::zlib::Zlib>(&payload).unwrap();

    offsets[5] = bytes.len() as u64;
    bytes.extend_from_slice(b"5 0 obj\n");
    let dict = format!(
        "<< /Type /ObjStm /N 2 /First {} /Filter /FlateDecode /Length {} >>\n",
        first,
        compressed.len()
    );
    bytes.extend_from_slice(dict.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    offsets[6] = bytes.len() as u64;

    fn make_t1(off: u32) -> [u8; 7] {
        let mut e = [0u8; 7];
        e[0] = 1;
        e[1..5].copy_from_slice(&off.to_be_bytes());
        e[5..7].copy_from_slice(&0u16.to_be_bytes());
        e
    }
    fn make_t2(container: u32, idx: u16) -> [u8; 7] {
        let mut e = [0u8; 7];
        e[0] = 2;
        e[1..5].copy_from_slice(&container.to_be_bytes());
        e[5..7].copy_from_slice(&idx.to_be_bytes());
        e
    }
    fn make_t0() -> [u8; 7] {
        let mut e = [0u8; 7];
        e[5..7].copy_from_slice(&65535u16.to_be_bytes());
        e
    }

    let mut table = Vec::with_capacity(7 * 7);
    table.extend_from_slice(&make_t0());
    table.extend_from_slice(&make_t2(5, 0));
    table.extend_from_slice(&make_t2(5, 1));
    table.extend_from_slice(&make_t1(offsets[3] as u32));
    table.extend_from_slice(&make_t0());
    table.extend_from_slice(&make_t1(offsets[5] as u32));
    table.extend_from_slice(&make_t1(offsets[6] as u32));

    let xref_dict = format!(
        "<< /Type /XRef /Size 7 /Index [0 7] /W [1 4 2] /Root 1 0 R /Length {} >>\n",
        table.len()
    );
    bytes.extend_from_slice(b"6 0 obj\n");
    bytes.extend_from_slice(xref_dict.as_bytes());
    bytes.extend_from_slice(b"stream\n");
    bytes.extend_from_slice(&table);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_off = offsets[6];
    bytes.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_off).as_bytes());
    bytes
}

#[test]
fn objstm_resolver_rejects_header_object_number_mismatch() {
    let pdf = build_pdf_with_objstm_header_mismatch();
    let r = read_pdf_to_scene(&pdf);
    assert!(
        r.is_err(),
        "ObjStm header mismatch (claims obj 99, xref says obj 1) must be rejected"
    );
}
