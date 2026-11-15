//! Reading order and text clean-up through the document reader.
//!
//! Hand-assembled pages exercise the geometric reading order (columns,
//! spanning lines, table rows, lines painted out of order), the
//! structure-tree order of a Tagged PDF (artifacts, property lists
//! named from `/Properties`, marked content nested in a marked-content
//! item), the per-page layout of documents whose pages share
//! coordinates, and the `TJ` word-gap rules around character spacing.
//!
//! Provenance: ISO 32000-1:2008 §9.3.2 (character spacing), §9.4.3
//! (text-showing operators), §14.6 (marked content), §14.7 / §14.8
//! (logical structure, Tagged PDF, artifacts). The PDF bytes are built
//! here.

use oxideav_pdf::reader::{DocumentReader, TextLayoutOptions, TextOrder};

/// Serialise `objs` (object `i + 1` = `objs[i]`) with object 1 as the
/// catalog.
fn build(objs: &[String]) -> Vec<u8> {
    let mut buf: Vec<u8> = b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offs = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offs.push(buf.len());
        buf.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
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

fn stream(body: &str) -> String {
    format!("<< /Length {} >>\nstream\n{body}\nendstream", body.len())
}

/// Every code 32..=126 advances half an em.
fn font() -> String {
    let widths = vec!["500"; 95].join(" ");
    format!(
        "<< /Type /Font /Subtype /TrueType /BaseFont /Helvetica /Encoding /WinAnsiEncoding \
         /FirstChar 32 /LastChar 126 /Widths [ {widths} ] >>"
    )
}

/// A document of one page per content stream, all using font `/F0`.
fn pages(contents: &[&str]) -> Vec<u8> {
    let n = contents.len();
    let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", 4 + 2 * i)).collect();
    let mut objs = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        format!("<< /Type /Pages /Count {n} /Kids [ {} ] >>", kids.join(" ")),
        font(),
    ];
    for (i, c) in contents.iter().enumerate() {
        objs.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << /F0 3 0 R >> >> /Contents {} 0 R >>",
            5 + 2 * i
        ));
        objs.push(stream(c));
    }
    build(&objs)
}

fn text(pdf: &[u8], opts: &TextLayoutOptions) -> String {
    DocumentReader::open(pdf)
        .expect("open")
        .text(opts)
        .expect("text")
}

fn default_text(pdf: &[u8]) -> String {
    text(pdf, &TextLayoutOptions::new())
}

#[test]
fn two_columns_painted_right_first_read_left_first() {
    let mut c = String::from("BT /F0 10 Tf\n");
    for (x, name) in [(320, "right"), (60, "left")] {
        for i in 0..6 {
            c.push_str(&format!(
                "1 0 0 1 {x} {} Tm ({name} column, line {i} of the text) Tj\n",
                700 - 12 * i
            ));
        }
    }
    // The running head is painted last and spans both columns.
    c.push_str("1 0 0 1 60 750 Tm (A running head that reaches across both of the columns) Tj ET");
    let pdf = pages(&[&c]);
    let lines: Vec<String> = default_text(&pdf).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 13);
    assert!(lines[0].starts_with("A running head"));
    assert!(lines[1..7].iter().all(|l| l.starts_with("left column")));
    assert!(lines[7..].iter().all(|l| l.starts_with("right column")));
    // Painting order on request.
    let painted = text(
        &pdf,
        &TextLayoutOptions::new().with_order(TextOrder::Stream),
    );
    assert!(painted.starts_with("right column, line 0"));
    assert!(painted.ends_with("both of the columns"));
}

#[test]
fn table_painted_column_by_column_reads_row_by_row() {
    let mut c = String::from("BT /F0 10 Tf\n");
    for (x, cells) in [
        (60, ["Field", "Signature", "Version", "Flags"]),
        (200, ["Type", "UI8", "UI8", "UB"]),
        (300, ["Comment", "Always F", "File version", "Shall be 0"]),
    ] {
        for (i, cell) in cells.iter().enumerate() {
            c.push_str(&format!(
                "1 0 0 1 {x} {} Tm ({cell}) Tj\n",
                700 - 14 * i as i32
            ));
        }
    }
    c.push_str("ET");
    assert_eq!(
        default_text(&pages(&[&c])),
        "Field Type Comment\nSignature UI8 Always F\nVersion UI8 File version\nFlags UB Shall be 0"
    );
}

#[test]
fn pieces_painted_out_of_order_rejoin_their_line() {
    // A number painted from its last digit group backwards, then a
    // reference whose brackets and link text are shown after the body
    // text that surrounds them.
    let c = "BT /F0 10 Tf \
        1 0 0 1 110 700 Tm (587) Tj 1 0 0 1 105 700 Tm (.) Tj 1 0 0 1 100 700 Tm (0) Tj \
        1 0 0 1 60 680 Tm (see) Tj 1 0 0 1 125 680 Tm (. Then more) Tj \
        1 0 0 1 80 680 Tm ([) Tj (RFC6374) Tj (]) Tj ET";
    assert_eq!(
        default_text(&pages(&[c])),
        "0.587\nsee [RFC6374]. Then more"
    );
}

#[test]
fn pages_sharing_coordinates_stay_apart() {
    let a = "BT /F0 10 Tf 1 0 0 1 60 40 Tm (page one footer) Tj 1 0 0 1 60 700 Tm (page one body) Tj ET";
    let b = "BT /F0 10 Tf 1 0 0 1 60 700 Tm (page two body) Tj 1 0 0 1 60 40 Tm (page two footer) Tj ET";
    let pdf = pages(&[a, b]);
    assert_eq!(
        default_text(&pdf),
        "page one body\npage one footer\npage two body\npage two footer"
    );
    let ff = TextLayoutOptions::new().with_page_separator("\u{c}");
    assert_eq!(text(&pdf, &ff).matches('\u{c}').count(), 1);
    let mut r = DocumentReader::open(&pdf).expect("open");
    let ex = r.text_extraction().expect("extract");
    assert_eq!(ex.page_starts, vec![0, 2]);
    assert_eq!(ex.pages().count(), 2);
}

#[test]
fn character_spacing_taken_back_by_kerns_leaves_word_gaps() {
    // `Tc` of half an em, cancelled after every glyph but the word
    // ends (where the kern leaves a third of an em).
    let c = "BT /F0 1 Tf 10 0 0 10 60 700 Tm 0.503 Tc \
        [(R)508(T)499(C)499(P)172(P)535(a)508(c)540(k)536(e)507(t)144(F)595(o)508(r)499(m)500(a)508(t)] TJ ET";
    assert_eq!(default_text(&pages(&[c])), "RTCP Packet Format");
    // The glyphs of a longer string in such a line stand the full
    // character spacing apart.
    let c = "BT /F0 1 Tf 10 0 0 10 60 700 Tm 0.503 Tc \
        [(S)508(e)508(n)508(d)508(e)508(r)172(...)11(..)-429(2)508(9)] TJ ET";
    assert_eq!(default_text(&pages(&[c])), "Sender . . . . . 29");
}

#[test]
fn positive_character_spacing_over_whole_words_is_tracking() {
    // Whole words in strings under a wide `Tc`: the glyph spacing is
    // the tracking, and only the kerned gap is a word gap.
    let c = "BT /F0 10 Tf 60 700 Td 2 Tc [(WIDE)-400(HEAD)] TJ ET";
    assert_eq!(default_text(&pages(&[c])), "WIDE HEAD");
}

#[test]
fn word_gaps_between_short_pieces_are_not_tracking() {
    let c = "BT /F0 10 Tf 60 700 Td \
        [(Ful)-9.8(l)-291.5(r)-11.5(at)-11.1(e)-281.1(s)0.6(peech;)] TJ ET";
    assert_eq!(default_text(&pages(&[c])), "Full rate speech;");
}

#[test]
fn stray_control_code_in_a_show_reads_as_nothing() {
    let c = "BT /F0 10 Tf 60 700 Td (Corporate Headquarters\\r) Tj ET";
    assert_eq!(default_text(&pages(&[c])), "Corporate Headquarters");
}

#[test]
fn hyphenated_line_end_joins_unless_kept() {
    let c = "BT /F0 10 Tf 1 0 0 1 60 700 Tm (the value is speci-) Tj \
        1 0 0 1 60 688 Tm (fied below) Tj ET";
    let pdf = pages(&[c]);
    assert_eq!(default_text(&pdf), "the value is specified\nbelow");
    assert_eq!(
        text(&pdf, &TextLayoutOptions::new().with_join_hyphenated(false)),
        "the value is speci-\nfied below"
    );
}

#[test]
fn invisible_text_can_be_left_out() {
    let c = "BT /F0 10 Tf 1 0 0 1 60 700 Tm (printed) Tj 3 Tr 1 0 0 1 60 680 Tm (recognised) Tj ET";
    let pdf = pages(&[c]);
    assert_eq!(default_text(&pdf), "printed\nrecognised");
    assert_eq!(
        text(
            &pdf,
            &TextLayoutOptions::new().with_include_invisible(false)
        ),
        "printed"
    );
}

/// A tagged page: the second paragraph is painted first, a running
/// head is an artifact, one paragraph names its property list through
/// `/Properties`, one holds a nested `/Span`, and a stamp is neither
/// tagged nor an artifact.
fn tagged_pdf() -> Vec<u8> {
    let content = "BT /F0 10 Tf \
        /P << /MCID 1 >> BDC 1 0 0 1 60 600 Tm (Second paragraph.) Tj EMC \
        /Artifact << /Type /Pagination >> BDC 1 0 0 1 60 760 Tm (Running head) Tj EMC \
        /P /MC0 BDC 1 0 0 1 60 500 Tm (First paragraph,) Tj \
        /Span BMC 1 0 0 1 60 488 Tm (with a nested span.) Tj EMC EMC \
        1 0 0 1 60 300 Tm (Loose stamp) Tj \
        /P << /MCID 2 >> BDC 1 0 0 1 60 700 Tm (Third paragraph.) Tj EMC ET";
    build(&[
        "<< /Type /Catalog /Pages 2 0 R /StructTreeRoot 6 0 R /MarkInfo << /Marked true >> >>"
            .to_string(),
        "<< /Type /Pages /Count 1 /Kids [ 4 0 R ] >>".to_string(),
        font(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F0 3 0 R >> /Properties << /MC0 << /MCID 0 >> >> >> \
         /Contents 5 0 R >>"
            .to_string(),
        stream(content),
        "<< /Type /StructTreeRoot /K 7 0 R >>".to_string(),
        "<< /Type /StructElem /S /Document /P 6 0 R /Pg 4 0 R /K [ 8 0 R 9 0 R 10 0 R ] >>"
            .to_string(),
        "<< /Type /StructElem /S /P /P 7 0 R /K 0 >>".to_string(),
        "<< /Type /StructElem /S /P /P 7 0 R /K << /Type /MCR /Pg 4 0 R /MCID 1 >> >>".to_string(),
        "<< /Type /StructElem /S /P /P 7 0 R /K [ 2 ] >>".to_string(),
    ])
}

#[test]
fn tagged_document_reads_in_structure_order() {
    let pdf = tagged_pdf();
    // Artifacts and unmarked text follow the page's logical content.
    assert_eq!(
        default_text(&pdf),
        "First paragraph,\nwith a nested span.\nSecond paragraph.\nThird paragraph.\n\
         Running head\nLoose stamp"
    );
    assert_eq!(
        text(
            &pdf,
            &TextLayoutOptions::new().with_include_artifacts(false)
        ),
        "First paragraph,\nwith a nested span.\nSecond paragraph.\nThird paragraph.\nLoose stamp"
    );
    // The geometric order keeps everything that is painted.
    assert_eq!(
        text(
            &pdf,
            &TextLayoutOptions::new().with_order(TextOrder::Geometric)
        ),
        "Running head\nThird paragraph.\nSecond paragraph.\nFirst paragraph,\n\
         with a nested span.\nLoose stamp"
    );
}

#[test]
fn marked_runs_carry_inherited_mcid_and_artifact_flag() {
    let pdf = tagged_pdf();
    let mut r = DocumentReader::open(&pdf).expect("open");
    let marked = r.marked_text_extraction().expect("marked");
    let find = |needle: &str| {
        marked
            .runs
            .iter()
            .find(|m| m.run.text.contains(needle))
            .expect("run")
    };
    assert_eq!(find("First").mcid, Some(0));
    assert_eq!(find("nested").mcid, Some(0));
    assert!(find("Running").artifact);
    assert!(!find("Second").artifact);
    assert_eq!(find("Loose").mcid, None);
}

#[test]
fn structure_tree_that_misses_the_text_falls_back_to_geometry() {
    // The tree references one short item; most of the page is outside.
    let content = "BT /F0 10 Tf \
        1 0 0 1 60 600 Tm (A long second line that the tree knows nothing about) Tj \
        /P << /MCID 0 >> BDC 1 0 0 1 60 500 Tm (Tiny) Tj EMC \
        1 0 0 1 60 700 Tm (A long first line that the tree knows nothing about) Tj ET";
    let pdf = build(&[
        "<< /Type /Catalog /Pages 2 0 R /StructTreeRoot 6 0 R >>".to_string(),
        "<< /Type /Pages /Count 1 /Kids [ 4 0 R ] >>".to_string(),
        font(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F0 3 0 R >> >> /Contents 5 0 R >>"
            .to_string(),
        stream(content),
        "<< /Type /StructTreeRoot /K << /Type /StructElem /S /P /Pg 4 0 R /K 0 >> >>".to_string(),
    ]);
    assert_eq!(
        default_text(&pdf),
        "A long first line that the tree knows nothing about\n\
         A long second line that the tree knows nothing about\nTiny"
    );
}

#[test]
fn to_unicode_null_destination_falls_back_to_the_encoding() {
    // A producer that knows no Unicode value for its `fi` glyph maps
    // it to U+0000; the glyph name still says what it is.
    let cmap = "/CIDInit /ProcSet findresource begin begincmap\n\
        1 begincodespacerange <00> <FF> endcodespacerange\n\
        2 beginbfchar <1D> <0000> <53> <0053> endbfchar\nendcmap end";
    let widths = vec!["500"; 98].join(" ");
    let pdf = build(&[
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Count 1 /Kids [ 4 0 R ] >>".to_string(),
        format!(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Demo \
             /Encoding << /BaseEncoding /WinAnsiEncoding /Differences [ 29 /fi ] >> \
             /FirstChar 29 /LastChar 126 /Widths [ {widths} ] /ToUnicode 6 0 R >>"
        ),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F0 3 0 R >> >> /Contents 5 0 R >>"
            .to_string(),
        stream("BT /F0 10 Tf 60 700 Td (Speci\\035cation) Tj ET"),
        stream(cmap),
    ]);
    assert_eq!(default_text(&pdf), "Specification");
}

#[test]
fn composite_font_widths_given_as_an_indirect_array_are_used() {
    // `/W [ 0 7 0 R ]`: the width list is an object of its own. With
    // the widths (300 per glyph) the two words stand apart; with the
    // default width of 1000 the first would run over the second.
    let cmap = "/CIDInit /ProcSet findresource begin begincmap\n\
        1 begincodespacerange <0000> <FFFF> endcodespacerange\n\
        1 beginbfrange <0000> <007F> <0000> endbfrange\nendcmap end";
    let pdf = build(&[
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Count 1 /Kids [ 4 0 R ] >>".to_string(),
        "<< /Type /Font /Subtype /Type0 /BaseFont /Demo /Encoding /Identity-H \
         /DescendantFonts [ << /Type /Font /Subtype /CIDFontType2 /BaseFont /Demo \
         /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> \
         /W [ 0 7 0 R ] >> ] /ToUnicode 6 0 R >>"
            .to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F0 3 0 R >> >> /Contents 5 0 R >>"
            .to_string(),
        stream(
            "BT /F0 10 Tf 1 0 0 1 60 700 Tm <0063006900720063> Tj \
             1 0 0 1 72 700 Tm <007500690074> Tj ET",
        ),
        stream(cmap),
        format!("[ {} ]", vec!["300"; 128].join(" ")),
    ]);
    let mut r = DocumentReader::open(&pdf).expect("open");
    let ex = r.text_extraction().expect("extract");
    assert_eq!(ex.runs[0].advance.0, 12.0);
    assert_eq!(ex.flat_text(), "circuit");
}

#[test]
fn pages_outside_the_structure_tree_keep_their_place() {
    // Three pages; only the second is in the tree.
    let page = |contents: u32| {
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << /F0 3 0 R >> >> /Contents {contents} 0 R >>"
        )
    };
    let pdf = build(&[
        "<< /Type /Catalog /Pages 2 0 R /StructTreeRoot 10 0 R >>".to_string(),
        "<< /Type /Pages /Count 3 /Kids [ 4 0 R 6 0 R 8 0 R ] >>".to_string(),
        font(),
        page(5),
        stream("BT /F0 10 Tf 60 700 Td (Cover page) Tj ET"),
        page(7),
        stream("BT /F0 10 Tf 60 700 Td /P << /MCID 0 >> BDC (The body of the document) Tj EMC ET"),
        page(9),
        stream("BT /F0 10 Tf 60 700 Td (Back page) Tj ET"),
        "<< /Type /StructTreeRoot /K << /Type /StructElem /S /P /Pg 6 0 R /K 0 >> >>".to_string(),
    ]);
    assert_eq!(
        default_text(&pdf),
        "Cover page\nThe body of the document\nBack page"
    );
}

#[test]
fn forms_invoking_forms_cannot_multiply_the_work_without_bound() {
    // Seven forms, each painting the next two hundred times; the last
    // shows a word. Unbounded, that is 200^6 shows.
    let levels = 7;
    let mut objs = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Count 1 /Kids [ 4 0 R ] >>".to_string(),
        font(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F0 3 0 R >> /XObject << /X 6 0 R >> >> /Contents 5 0 R >>"
            .to_string(),
        stream("/X Do"),
    ];
    for level in 0..levels {
        let body = if level + 1 == levels {
            "0 0 m 10 10 l S BT /F0 10 Tf 60 700 Td (word) Tj ET".to_string()
        } else {
            "/X Do ".repeat(200)
        };
        let next = 7 + level;
        let resources = if level + 1 == levels {
            "/Font << /F0 3 0 R >>".to_string()
        } else {
            format!("/XObject << /X {next} 0 R >>")
        };
        objs.push(format!(
            "<< /Type /XObject /Subtype /Form /BBox [0 0 612 792] /Resources << {resources} >> \
             /Length {} >>\nstream\n{body}\nendstream",
            body.len()
        ));
    }
    let pdf = build(&objs);
    let mut r = DocumentReader::open(&pdf).expect("open");
    let started = std::time::Instant::now();
    let ex = r.text_extraction().expect("extract");
    // The budget lets a few hundred thousand shows through, not 200^6.
    assert!(!ex.runs.is_empty());
    assert!(ex.runs.len() <= 262_144, "{} runs", ex.runs.len());
    assert!(started.elapsed() < std::time::Duration::from_secs(120));
    // The scene path copies a form's nodes at every `Do`: the same
    // file must come back as a scene of bounded size.
    let started = std::time::Instant::now();
    let scene = oxideav_pdf::read_pdf_to_scene(&pdf).expect("scene");
    assert_eq!(scene.pages.as_ref().map(Vec::len), Some(1));
    assert!(started.elapsed() < std::time::Duration::from_secs(300));
}
