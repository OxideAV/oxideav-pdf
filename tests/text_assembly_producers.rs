//! Word and line assembly across producer layouts.
//!
//! The same sentence is laid down the way pdfTeX, cairo and Skia
//! (Chrome print) emit it — one `TJ` per line with kerned gaps, one
//! show per word with a separate space glyph, one show per glyph with
//! a `Td` between — and `flat_text()` must rebuild the words and lines
//! identically from each. Further cases cover `/ActualText` spans
//! (§14.9.4), letter-spaced text inside a `TJ` array and across
//! per-glyph shows, a simple font whose `/ToUnicode` declares a
//! two-byte codespace over one-byte codes, an inline image inside the
//! content stream, and a right-to-left line painted in visual order.
//!
//! Provenance: ISO 32000-1:2008 §9.4.3 / §9.4.4 (text showing and
//! text space), §9.10 (extraction of text content), §14.9.4
//! (replacement text), §8.9.7 (inline images). Staged PDF bytes are
//! hand-assembled here; no third-party PDF library was consulted.

use oxideav_pdf::reader::{assemble_text, reorder_bidi_line, DocumentReader, TextRun};

/// Assemble a one-page PDF. `fonts` are `(resource name, font object
/// body)` pairs; each body may reference `{tu}` for a ToUnicode
/// stream (object 10 + index) that `to_unicode` supplies, in order.
fn build_pdf(content: &[u8], fonts: &[(&str, String)], to_unicode: &[&str]) -> Vec<u8> {
    let mut objs: Vec<Vec<u8>> = Vec::new();
    objs.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    objs.push(b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>".to_vec());
    let font_res: String = fonts
        .iter()
        .enumerate()
        .map(|(i, (name, _))| format!("/{name} {} 0 R", 5 + i))
        .collect::<Vec<_>>()
        .join(" ");
    objs.push(
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << {font_res} >> >> /Contents 4 0 R >>"
        )
        .into_bytes(),
    );
    let mut c = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
    c.extend_from_slice(content);
    c.extend_from_slice(b"\nendstream");
    objs.push(c);
    let tu_base = 5 + fonts.len();
    for (i, (_, body)) in fonts.iter().enumerate() {
        let body = body.replace(
            "{tu}",
            &format!(
                "{} 0 R",
                tu_base + i.min(to_unicode.len().saturating_sub(1))
            ),
        );
        objs.push(body.into_bytes());
    }
    for tu in to_unicode {
        let mut s = format!("<< /Length {} >>\nstream\n", tu.len()).into_bytes();
        s.extend_from_slice(tu.as_bytes());
        s.extend_from_slice(b"\nendstream");
        objs.push(s);
    }
    let mut buf: Vec<u8> = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offs = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offs.push(buf.len());
        buf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        buf.extend_from_slice(o);
        buf.extend_from_slice(b"\nendobj\n");
    }
    let xref = buf.len();
    buf.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", offs.len() + 1).as_bytes());
    for o in &offs {
        buf.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            offs.len() + 1
        )
        .as_bytes(),
    );
    buf
}

fn flat(pdf: &[u8]) -> String {
    let mut r = DocumentReader::open(pdf).expect("open");
    r.text_extraction().expect("extract").flat_text()
}

/// Helvetica-like simple font: every code 32..=126 advances 500
/// except the space (278), so geometry is easy to reason about.
fn simple_font(widths_space: i64) -> String {
    let mut widths: Vec<String> = Vec::new();
    for code in 32..=126 {
        widths.push(if code == 32 {
            widths_space.to_string()
        } else {
            "500".into()
        });
    }
    format!(
        "<< /Type /Font /Subtype /TrueType /BaseFont /Helvetica /Encoding /WinAnsiEncoding \
         /FirstChar 32 /LastChar 126 /Widths [ {} ] >>",
        widths.join(" ")
    )
}

/// Identity-H composite font whose CIDs are the ASCII codes, with a
/// ToUnicode CMap; every glyph 500 wide, the space 278.
fn cid_font() -> (String, &'static str) {
    (
        "<< /Type /Font /Subtype /Type0 /BaseFont /Arial /Encoding /Identity-H \
         /DescendantFonts [ << /Type /Font /Subtype /CIDFontType2 /BaseFont /Arial \
         /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> \
         /DW 500 /W [ 32 [278] ] >> ] /ToUnicode {tu} >>"
            .to_string(),
        "/CIDInit /ProcSet findresource begin begincmap\n\
         1 begincodespacerange <0000> <FFFF> endcodespacerange\n\
         1 beginbfrange <0020> <007E> <0020> endbfrange\n\
         endcmap end",
    )
}

const SENTENCE: &str = "The quick brown fox";

#[test]
fn pdftex_layout_kerned_tj_arrays_and_leading_kern() {
    // One TJ per line; interword gaps are −333 kerns, a −20 kern is a
    // letter kern; the second font's array opens with the word gap.
    let content = b"BT /F0 10 Tf 72 700 Td \
        [(The)-333(qu)-20(ick)-333(brown)]TJ /F1 10 Tf [-333(fox)]TJ \
        0 -12 Td [(jumps)-333(over)]TJ ET";
    let pdf = build_pdf(
        content,
        &[("F0", simple_font(278)), ("F1", simple_font(278))],
        &[],
    );
    assert_eq!(flat(&pdf), "The quick brown fox\njumps over");
}

#[test]
fn cairo_layout_word_shows_with_type3_space_glyph() {
    // cairo: Tm scale 11 with Tf 1, each word a show in the text font
    // and every space a show in a one-glyph Type 3 font.
    let space_font = "<< /Type /Font /Subtype /Type3 /FontBBox [0 0 0 0] \
        /FontMatrix [0.001 0 0 0.001 0 0] /CharProcs << >> \
        /Encoding << /Type /Encoding /Differences [ 0 /space ] >> \
        /FirstChar 0 /LastChar 0 /Widths [ 278 ] /Resources << >> /ToUnicode {tu} >>";
    let space_tu = "/CIDInit /ProcSet findresource begin begincmap\n\
        1 begincodespacerange <00> <FF> endcodespacerange\n\
        1 beginbfchar <00> <0020> endbfchar\nendcmap end";
    let content = b"BT 11 0 0 -11 40 60 Tm /F0 1 Tf (The)Tj /F1 1 Tf <00>Tj /F0 1 Tf (quick)Tj \
        /F1 1 Tf <00>Tj /F0 1 Tf (brown)Tj /F1 1 Tf <00>Tj /F0 1 Tf (fox)Tj \
        11 0 0 -11 40 76 Tm (jumps)Tj /F1 1 Tf <00>Tj /F0 1 Tf (over)Tj ET";
    let pdf = build_pdf(
        content,
        &[("F0", simple_font(278)), ("F1", space_font.to_string())],
        &[space_tu],
    );
    assert_eq!(flat(&pdf), "The quick brown fox\njumps over");
}

#[test]
fn skia_layout_one_glyph_per_show_with_td_between() {
    // Skia: Identity-H CID font, `Tm` once per line, then one `Tj`
    // per glyph with a `Td` carrying the real advance. Spaces are
    // glyphs too.
    let (font, tu) = cid_font();
    let mut content = String::from("BT /F0 14 Tf 1 0 0 -1 40 53 Tm ");
    let mut x = 0.0f32;
    let mut first = true;
    let mut emit_line = |content: &mut String, line: &str, y: f32| {
        if !first {
            content.push_str(&format!("1 0 0 -1 40 {y} Tm "));
            x = 0.0;
        }
        first = false;
        for (i, ch) in line.chars().enumerate() {
            let adv = if ch == ' ' { 0.278 * 14.0 } else { 0.5 * 14.0 };
            if i > 0 {
                content.push_str(&format!("{x:.4} 0 Td "));
            }
            content.push_str(&format!("<{:04x}> Tj ", ch as u32));
            x = adv;
        }
    };
    emit_line(&mut content, SENTENCE, 53.0);
    emit_line(&mut content, "jumps over", 70.0);
    content.push_str("ET");
    let pdf = build_pdf(content.as_bytes(), &[("F0", font)], &[tu]);
    assert_eq!(flat(&pdf), "The quick brown fox\njumps over");
}

#[test]
fn actual_text_span_replaces_the_glyphs_shown_inside_it() {
    // Synthesised small caps (uppercase glyphs at two sizes) with the
    // lowercase ActualText, a soft hyphen carried as ActualText over
    // a visible hyphen, and a UTF-8 BOM form.
    let content = b"BT /F0 12 Tf 72 700 Td \
        /Span <</ActualText (S)>> BDC (S)Tj EMC \
        /F0 9 Tf /Span <</ActualText (mall)>> BDC (MALL)Tj EMC \
        /F0 12 Tf ( caps)Tj \
        /Span <</ActualText <FEFF00AD>>> BDC (-)Tj EMC \
        /Span <</ActualText <EFBBBFC3A9>>> BDC (e)Tj EMC ET";
    let pdf = build_pdf(content, &[("F0", simple_font(278))], &[]);
    assert_eq!(flat(&pdf), "Small caps\u{ad}é");
}

#[test]
fn actual_text_over_several_shows_is_one_run_whose_end_follows_the_last_show() {
    // Two glyph shows inside one span: one run, and the gap to the
    // following word is measured from the second glyph's end (`Td`
    // moves from the line matrix, so each offset is cumulative).
    let content = b"BT /F0 10 Tf 72 700 Td \
        /Span <</ActualText (fi)>> BDC (f)Tj 5 0 Td (i)Tj EMC 5 0 Td (ne)Tj 13 0 Td (day)Tj ET";
    let pdf = build_pdf(content, &[("F0", simple_font(278))], &[]);
    assert_eq!(flat(&pdf), "fine day");
}

#[test]
fn letter_spaced_tj_array_keeps_its_words() {
    // 2 px tracking at 12 pt = 0.167 em between every glyph; the word
    // gap is the space advance on top of that.
    let content = b"BT /F0 12 Tf 72 700 Td \
        [(L)-167(e)-167(t)-167(t)-167(e)-167(r)-167( )-167(s)-167(p)-167(a)-167(c)-167(e)-167(d)]TJ ET";
    let pdf = build_pdf(content, &[("F0", simple_font(278))], &[]);
    assert_eq!(flat(&pdf), "Letter spaced");
    // Without the space glyph the word gap is tracking + 0.3 em.
    let content = b"BT /F0 12 Tf 72 700 Td \
        [(L)-167(e)-167(t)-167(t)-167(e)-167(r)-467(s)-167(p)-167(a)-167(c)-167(e)-167(d)]TJ ET";
    let pdf = build_pdf(content, &[("F0", simple_font(278))], &[]);
    assert_eq!(flat(&pdf), "Letter spaced");
}

#[test]
fn letter_spaced_per_glyph_shows_keep_their_words() {
    // Skia with `letter-spacing: 3px` at 14 pt: each glyph's Td is the
    // advance plus 3 units; a word boundary adds the space advance.
    let (font, tu) = cid_font();
    let mut content = String::from("BT /F0 14 Tf 1 0 0 -1 40 53 Tm ");
    let mut pending = 0.0f32;
    for (i, ch) in "THREE PIXEL CAPS".chars().enumerate() {
        if ch == ' ' {
            pending += 0.278 * 14.0 + 3.0;
            continue;
        }
        if i > 0 {
            content.push_str(&format!("{pending:.4} 0 Td "));
        }
        content.push_str(&format!("<{:04x}> Tj ", ch as u32));
        pending = 0.5 * 14.0 + 3.0;
    }
    content.push_str("ET");
    let pdf = build_pdf(content.as_bytes(), &[("F0", font)], &[tu]);
    assert_eq!(flat(&pdf), "THREE PIXEL CAPS");
}

#[test]
fn punctuation_gaps_are_not_letter_spacing() {
    // Single-glyph pieces separated by word gaps around punctuation
    // (a Times line with kerned pairs) must not raise the threshold.
    let content = b"BT /F0 10 Tf 72 700 Td \
        [(T)35(ightly)-248(k)10(erned)-249(pairs:)-308(A)134(V)135(AST)74(,)-249(T)80(ofu,)-248(L)91(T)93(A,)-248(W)119(A)135(VE,)]TJ ET";
    let pdf = build_pdf(content, &[("F0", simple_font(278))], &[]);
    assert_eq!(flat(&pdf), "Tightly kerned pairs: AVAST, Tofu, LTA, WAVE,");
}

#[test]
fn simple_font_to_unicode_with_two_byte_codespace_decodes_per_byte() {
    // InDesign writes `<0000> <FFFF>` over one-byte bfchar sources on
    // a Type1 font; codes it leaves out fall back to the encoding.
    let font = "<< /Type /Font /Subtype /Type1 /BaseFont /SFPro \
        /Encoding << /BaseEncoding /WinAnsiEncoding /Differences [ 29 /fi ] >> \
        /FirstChar 29 /LastChar 126 /Widths [ {w} ] /ToUnicode {tu} >>"
        .replace("{w}", &vec!["500"; 98].join(" "));
    let tu = "/CIDInit /ProcSet findresource begin begincmap\n\
        1 begincodespacerange <0000> <FFFF> endcodespacerange\n\
        3 beginbfchar <1D> <FB01> <41> <0041> <70> <0070> endbfchar\nendcmap end";
    let content = b"BT /F0 10 Tf 72 700 Td (Ap\\035ne)Tj ET";
    let pdf = build_pdf(content, &[("F0", font)], &[tu]);
    assert_eq!(flat(&pdf), "Ap\u{fb01}ne");
}

#[test]
fn inline_image_payload_is_not_tokenised() {
    // The image bytes hold `(`, `BT` and a `Tj` — none of it is text,
    // and the shows after `EI` still extract.
    let content = b"BT /F0 10 Tf 72 700 Td (before)Tj ET \
        q 100 0 0 50 0 0 cm BI /W 4 /H 1 /BPC 8 /CS /G ID (BT\x00Tj\xff EI\nQ \
        BT /F0 10 Tf 72 680 Td (after)Tj ET";
    let pdf = build_pdf(content, &[("F0", simple_font(278))], &[]);
    assert_eq!(flat(&pdf), "before\nafter");
}

#[test]
fn right_to_left_line_painted_in_visual_order_is_reordered() {
    // Visual order (leftmost glyph first) of "שלום עולם" is the
    // reverse; a mixed line only flips the Hebrew span.
    assert_eq!(reorder_bidi_line("םלוע םולש"), "שלום עולם");
    assert_eq!(reorder_bidi_line("see םולש here"), "see שלום here");
    // Digits inside a reversed span keep their order; brackets mirror.
    // The glyph drawn leftmost for a logical `)` is the `(` shape.
    assert_eq!(reorder_bidi_line("(2024) םולש"), "שלום (2024)");
    // Lam-alef from one ligature glyph stays lam-then-alef.
    assert_eq!(reorder_bidi_line("رابتخلال"), "للاختبار");
    assert_eq!(reorder_bidi_line("plain ascii"), "plain ascii");
}

#[test]
fn assemble_text_glues_breaks_and_lines_by_geometry() {
    let run = |t: &str, x: f32, y: f32, adv: f32| {
        TextRun::new(t, (x, y), "F0", 10.0).with_advance((adv, 0.0))
    };
    let runs = vec![
        run("Hel", 0.0, 0.0, 15.0),
        run("lo", 15.0, 0.0, 10.0),      // glued: no gap
        run("world", 28.0, 0.0, 25.0),   // 3 units = 0.3 em: space
        run("next", 0.0, -12.0, 20.0),   // baseline moved: new line
        run("col", 300.0, -12.0, 15.0),  // far right, same line: space
        run("back", 100.0, -12.0, 20.0), // backtracks: new line
    ];
    assert_eq!(assemble_text(&runs), "Hello world\nnext col\nback");
    // A superscript (rise within half an em) stays on its line.
    let runs = vec![
        run("E", 0.0, 0.0, 6.0),
        TextRun::new("2", (6.0, 3.3), "F0", 7.0).with_advance((3.5, 0.0)),
        run(" is", 9.5, 0.0, 15.0),
    ];
    assert_eq!(assemble_text(&runs), "E2 is");
}
