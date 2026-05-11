//! Round-29 — reading-order layout pass over Tagged PDF
//! StructTreeRoot.
//!
//! Builds minimal PDF 1.5 byte streams with explicit `/StructTreeRoot
//! /K /StructElem /K [<MCID> ...]` trees, plus a non-tagged
//! sanity-check PDF, and verifies
//! [`oxideav_pdf::reader::read_in_logical_order`] emits text in the
//! author-intended sequence (column 1 top-to-bottom, then column 2)
//! rather than raster (top of page across both columns).
//!
//! Provenance: ISO 32000-1:2008 §14.6 (Marked Content), §14.7
//! (Logical Structure Tree), §14.8 (Tagged PDF). No third-party PDF
//! library was consulted.

use oxideav_pdf::reader::{DocumentReader, LayoutMode};

// ──────────────────────── PDF builder helpers ────────────────────────

/// Build a 2-column tagged PDF with one page where:
///   * Column 1's content is `col1_runs` (one MCID per run, allocated
///     sequentially starting at 0)
///   * Column 2's content is `col2_runs` (next MCIDs)
///   * The painted layout is *raster*: alternates col1 / col2 / col1 /
///     col2 / … so a naive raster extraction would interleave them
///     incorrectly.
///   * The StructTreeRoot's `/K` is `[Sect1, Sect2]` where Sect1
///     contains all of col1's MCIDs and Sect2 contains all of col2's.
fn build_two_column_tagged_pdf(col1_runs: &[&str], col2_runs: &[&str]) -> Vec<u8> {
    let mut content = String::new();
    let mut next_mcid = 0u32;
    let mut col1_mcids = Vec::new();
    let mut col2_mcids = Vec::new();
    let n = col1_runs.len().max(col2_runs.len());

    for i in 0..n {
        // Paint col1 row i first, then col2 row i.
        if let Some(s) = col1_runs.get(i) {
            let y = 700 - (i as i32 * 20);
            content.push_str(&format!(
                "/Span <</MCID {mcid}>> BDC\nBT /F0 12 Tf 50 {y} Td ({s}) Tj ET\nEMC\n",
                mcid = next_mcid,
                y = y,
                s = s
            ));
            col1_mcids.push(next_mcid);
            next_mcid += 1;
        }
        if let Some(s) = col2_runs.get(i) {
            let y = 700 - (i as i32 * 20);
            content.push_str(&format!(
                "/Span <</MCID {mcid}>> BDC\nBT /F0 12 Tf 320 {y} Td ({s}) Tj ET\nEMC\n",
                mcid = next_mcid,
                y = y,
                s = s
            ));
            col2_mcids.push(next_mcid);
            next_mcid += 1;
        }
    }
    let content = content.into_bytes();

    // Object layout (numbers chosen so they're easy to read in dumps):
    //   1 = Catalog
    //   2 = Pages root
    //   3 = Page leaf
    //   4 = Font
    //   5 = Content stream
    //   6 = StructTreeRoot
    //   7 = Sect1 (col1 container)
    //   8 = Sect2 (col2 container)
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offs = Vec::new();

    offs.push(buf.len());
    buf.extend_from_slice(
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /StructTreeRoot 6 0 R \
        /MarkInfo << /Marked true >> >>\nendobj\n",
    );

    offs.push(buf.len());
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");

    offs.push(buf.len());
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
        /Resources << /Font << /F0 4 0 R >> >> /Contents 5 0 R \
        /StructParents 0 >>\nendobj\n",
    );

    offs.push(buf.len());
    buf.extend_from_slice(
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
        /Encoding /WinAnsiEncoding >>\nendobj\n",
    );

    offs.push(buf.len());
    let header = format!("5 0 obj\n<< /Length {} >>\nstream\n", content.len());
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(&content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    offs.push(buf.len());
    buf.extend_from_slice(b"6 0 obj\n<< /Type /StructTreeRoot /K [7 0 R 8 0 R] >>\nendobj\n");

    // Sect1 and Sect2: /K is an array of bare-integer MCIDs, /Pg
    // points at page 3.
    offs.push(buf.len());
    let mut sect1 = String::from("7 0 obj\n<< /Type /StructElem /S /Sect /Pg 3 0 R /K [");
    for (idx, m) in col1_mcids.iter().enumerate() {
        if idx > 0 {
            sect1.push(' ');
        }
        sect1.push_str(&m.to_string());
    }
    sect1.push_str("] >>\nendobj\n");
    buf.extend_from_slice(sect1.as_bytes());

    offs.push(buf.len());
    let mut sect2 = String::from("8 0 obj\n<< /Type /StructElem /S /Sect /Pg 3 0 R /K [");
    for (idx, m) in col2_mcids.iter().enumerate() {
        if idx > 0 {
            sect2.push(' ');
        }
        sect2.push_str(&m.to_string());
    }
    sect2.push_str("] >>\nendobj\n");
    buf.extend_from_slice(sect2.as_bytes());

    finalize_xref(&mut buf, &offs);
    buf
}

/// Build a *non-tagged* PDF (no /StructTreeRoot, no /MarkInfo) so we
/// can verify the round-29 reader correctly falls back to raster.
fn build_non_tagged_pdf(content_runs: &[(&str, i32, i32)]) -> Vec<u8> {
    let mut content = String::new();
    for (s, x, y) in content_runs {
        content.push_str(&format!(
            "BT /F0 12 Tf {x} {y} Td ({s}) Tj ET\n",
            x = x,
            y = y,
            s = s
        ));
    }
    let content = content.into_bytes();

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offs = Vec::new();

    offs.push(buf.len());
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offs.push(buf.len());
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");

    offs.push(buf.len());
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
        /Resources << /Font << /F0 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
    );

    offs.push(buf.len());
    buf.extend_from_slice(
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
        /Encoding /WinAnsiEncoding >>\nendobj\n",
    );

    offs.push(buf.len());
    let header = format!("5 0 obj\n<< /Length {} >>\nstream\n", content.len());
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(&content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    finalize_xref(&mut buf, &offs);
    buf
}

/// Build a 2-page tagged PDF where the StructTreeRoot's first section
/// references MCIDs from page 1 and the second section references
/// MCIDs from page 2 — verifying the cross-page MCR /Pg override.
fn build_cross_page_tagged_pdf() -> Vec<u8> {
    // Page 1 paints "alpha" (MCID 0) and "gamma" (MCID 1).
    // Page 2 paints "beta" (MCID 0) and "delta" (MCID 1).
    // StructTreeRoot's /K is [Sect_AB, Sect_GD]:
    //   Sect_AB.K = [<<MCR Pg page1 MCID 0>> <<MCR Pg page2 MCID 0>>]
    //   Sect_GD.K = [<<MCR Pg page1 MCID 1>> <<MCR Pg page2 MCID 1>>]
    // Reading order should be: alpha, beta, gamma, delta.
    let p1_content = b"/Span <</MCID 0>> BDC\nBT /F0 12 Tf 50 700 Td (alpha) Tj ET\nEMC\n\
          /Span <</MCID 1>> BDC\nBT /F0 12 Tf 50 670 Td (gamma) Tj ET\nEMC\n";
    let p2_content = b"/Span <</MCID 0>> BDC\nBT /F0 12 Tf 50 700 Td (beta) Tj ET\nEMC\n\
          /Span <</MCID 1>> BDC\nBT /F0 12 Tf 50 670 Td (delta) Tj ET\nEMC\n";

    // Object map (we keep numbers fixed so the cross-references are
    // legible):
    //   1 = Catalog
    //   2 = Pages root
    //   3 = Page 1 leaf
    //   4 = Page 2 leaf
    //   5 = Font
    //   6 = Content stream page 1
    //   7 = Content stream page 2
    //   8 = StructTreeRoot
    //   9 = Sect_AB
    //  10 = Sect_GD
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offs = Vec::new();

    offs.push(buf.len());
    buf.extend_from_slice(
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /StructTreeRoot 8 0 R \
        /MarkInfo << /Marked true >> >>\nendobj\n",
    );

    offs.push(buf.len());
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 2 /Kids [3 0 R 4 0 R] >>\nendobj\n");

    offs.push(buf.len());
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
        /Resources << /Font << /F0 5 0 R >> >> /Contents 6 0 R \
        /StructParents 0 >>\nendobj\n",
    );

    offs.push(buf.len());
    buf.extend_from_slice(
        b"4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
        /Resources << /Font << /F0 5 0 R >> >> /Contents 7 0 R \
        /StructParents 1 >>\nendobj\n",
    );

    offs.push(buf.len());
    buf.extend_from_slice(
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
        /Encoding /WinAnsiEncoding >>\nendobj\n",
    );

    offs.push(buf.len());
    let h = format!("6 0 obj\n<< /Length {} >>\nstream\n", p1_content.len());
    buf.extend_from_slice(h.as_bytes());
    buf.extend_from_slice(p1_content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    offs.push(buf.len());
    let h = format!("7 0 obj\n<< /Length {} >>\nstream\n", p2_content.len());
    buf.extend_from_slice(h.as_bytes());
    buf.extend_from_slice(p2_content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    offs.push(buf.len());
    buf.extend_from_slice(b"8 0 obj\n<< /Type /StructTreeRoot /K [9 0 R 10 0 R] >>\nendobj\n");

    offs.push(buf.len());
    buf.extend_from_slice(
        b"9 0 obj\n<< /Type /StructElem /S /Sect /K [\
        << /Type /MCR /Pg 3 0 R /MCID 0 >>\
        << /Type /MCR /Pg 4 0 R /MCID 0 >>\
        ] >>\nendobj\n",
    );

    offs.push(buf.len());
    buf.extend_from_slice(
        b"10 0 obj\n<< /Type /StructElem /S /Sect /K [\
        << /Type /MCR /Pg 3 0 R /MCID 1 >>\
        << /Type /MCR /Pg 4 0 R /MCID 1 >>\
        ] >>\nendobj\n",
    );

    finalize_xref(&mut buf, &offs);
    buf
}

fn finalize_xref(buf: &mut Vec<u8>, offs: &[usize]) {
    let xref_off = buf.len();
    let count = offs.len() + 1;
    buf.extend_from_slice(format!("xref\n0 {count}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for o in offs {
        let line = format!("{o:010} 00000 n \n");
        buf.extend_from_slice(line.as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n")
            .as_bytes(),
    );
}

// ──────────────────────── Tests ────────────────────────

#[test]
fn two_column_tagged_pdf_emits_logical_reading_order() {
    // Painted raster order: A1 B1 A2 B2 A3 B3
    // Logical reading order: A1 A2 A3 B1 B2 B3
    let pdf = build_two_column_tagged_pdf(&["A1", "A2", "A3"], &["B1", "B2", "B3"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let result = r.read_in_logical_order().unwrap();
    assert_eq!(result.mode, LayoutMode::Tagged);
    let texts: Vec<String> = result.runs.iter().map(|r| r.text.clone()).collect();
    assert_eq!(texts, vec!["A1", "A2", "A3", "B1", "B2", "B3"]);
}

#[test]
fn raster_extraction_on_two_column_pdf_interleaves_incorrectly() {
    // Sanity check that raster *does* interleave (so we know the
    // tagged path is doing actual reordering, not just luck).
    let pdf = build_two_column_tagged_pdf(&["A1", "A2", "A3"], &["B1", "B2", "B3"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let raster = r.text_extraction().unwrap();
    let texts: Vec<String> = raster.runs.iter().map(|r| r.text.clone()).collect();
    assert_eq!(texts, vec!["A1", "B1", "A2", "B2", "A3", "B3"]);
}

#[test]
fn non_tagged_pdf_falls_back_to_raster_order() {
    // Painted in left-to-right, top-to-bottom order: H, W.
    let pdf = build_non_tagged_pdf(&[("Hello", 50, 700), ("World", 320, 700)]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let result = r.read_in_logical_order().unwrap();
    assert_eq!(result.mode, LayoutMode::Raster);
    let texts: Vec<String> = result.runs.iter().map(|r| r.text.clone()).collect();
    assert_eq!(texts, vec!["Hello", "World"]);
}

#[test]
fn tagged_pdf_with_cross_page_mcrs_spans_pages_in_logical_order() {
    let pdf = build_cross_page_tagged_pdf();
    let mut r = DocumentReader::open(&pdf).unwrap();
    let result = r.read_in_logical_order().unwrap();
    assert_eq!(result.mode, LayoutMode::Tagged);
    let texts: Vec<String> = result.runs.iter().map(|r| r.text.clone()).collect();
    // First section walks: page1 MCID 0 ("alpha"), then page2 MCID 0
    // ("beta"). Second section: page1 MCID 1 ("gamma"), then page2
    // MCID 1 ("delta").
    assert_eq!(texts, vec!["alpha", "beta", "gamma", "delta"]);
}

#[test]
fn marked_text_extraction_records_mcids() {
    let pdf = build_two_column_tagged_pdf(&["A1", "A2"], &["B1", "B2"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let marked = r.marked_text_extraction().unwrap();
    // 4 runs total — paint order is A1 B1 A2 B2, MCIDs 0..3.
    assert_eq!(marked.runs.len(), 4);
    assert_eq!(marked.runs[0].mcid, Some(0));
    assert_eq!(marked.runs[0].run.text, "A1");
    assert_eq!(marked.runs[1].mcid, Some(1));
    assert_eq!(marked.runs[1].run.text, "B1");
    assert_eq!(marked.runs[2].mcid, Some(2));
    assert_eq!(marked.runs[2].run.text, "A2");
    assert_eq!(marked.runs[3].mcid, Some(3));
    assert_eq!(marked.runs[3].run.text, "B2");
    // All should attribute to the same page object number (3 in our
    // hand-laid layout) and page index 0.
    for run in &marked.runs {
        assert_eq!(run.page_obj_num, 3);
        assert_eq!(run.page_index, 0);
    }
}

#[test]
fn nested_struct_elements_recurse_in_order() {
    // /Sect > /P > /Span tree: build a doc where the top section has
    // two paragraph children, each with their own MCID. Verifies the
    // recursive walk handles nested StructElems (not just flat
    // arrays-of-MCIDs).
    let content = b"\
        /Span <</MCID 0>> BDC\nBT /F0 12 Tf 50 700 Td (one) Tj ET\nEMC\n\
        /Span <</MCID 1>> BDC\nBT /F0 12 Tf 50 670 Td (two) Tj ET\nEMC\n";

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offs = Vec::new();

    offs.push(buf.len());
    buf.extend_from_slice(
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /StructTreeRoot 6 0 R \
        /MarkInfo << /Marked true >> >>\nendobj\n",
    );
    offs.push(buf.len());
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offs.push(buf.len());
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
        /Resources << /Font << /F0 4 0 R >> >> /Contents 5 0 R \
        /StructParents 0 >>\nendobj\n",
    );
    offs.push(buf.len());
    buf.extend_from_slice(
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
        /Encoding /WinAnsiEncoding >>\nendobj\n",
    );
    offs.push(buf.len());
    let h = format!("5 0 obj\n<< /Length {} >>\nstream\n", content.len());
    buf.extend_from_slice(h.as_bytes());
    buf.extend_from_slice(content);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    // 6 = StructTreeRoot. /K -> 7 (Sect)
    // 7 = Sect, /K -> [8 9] (two paragraphs)
    // 8 = P, /K = [0]
    // 9 = P, /K = [1]
    offs.push(buf.len());
    buf.extend_from_slice(b"6 0 obj\n<< /Type /StructTreeRoot /K [7 0 R] >>\nendobj\n");
    offs.push(buf.len());
    buf.extend_from_slice(
        b"7 0 obj\n<< /Type /StructElem /S /Sect /Pg 3 0 R /K [8 0 R 9 0 R] >>\nendobj\n",
    );
    offs.push(buf.len());
    buf.extend_from_slice(b"8 0 obj\n<< /Type /StructElem /S /P /Pg 3 0 R /K [0] >>\nendobj\n");
    offs.push(buf.len());
    buf.extend_from_slice(b"9 0 obj\n<< /Type /StructElem /S /P /Pg 3 0 R /K [1] >>\nendobj\n");

    finalize_xref(&mut buf, &offs);

    let mut r = DocumentReader::open(&buf).unwrap();
    let result = r.read_in_logical_order().unwrap();
    assert_eq!(result.mode, LayoutMode::Tagged);
    let texts: Vec<String> = result.runs.iter().map(|r| r.text.clone()).collect();
    assert_eq!(texts, vec!["one", "two"]);
}

#[test]
fn flat_text_concatenates_with_spaces() {
    let pdf = build_two_column_tagged_pdf(&["A1"], &["B1"]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let result = r.read_in_logical_order().unwrap();
    assert_eq!(result.flat_text(), "A1 B1");
}
