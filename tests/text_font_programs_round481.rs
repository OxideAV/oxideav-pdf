//! Round 481 — text extraction for fonts without a `/ToUnicode` CMap
//! (ISO 32000-1 §9.10.2), end to end over hand-assembled PDFs whose
//! embedded font programs are built byte by byte here:
//!
//! * CFF (`/FontFile3 /Type1C`) built-in encodings (§9.6.6.2, TN #5176
//!   §12) — names through the AGL, a nameless blank glyph as a space;
//! * TrueType (`/FontFile2`) symbolic `(3,0)` selection with `post`
//!   names, and glyph-index `/Differences` names resolved through the
//!   program's Unicode `cmap` (§9.6.6.4);
//! * CIDFontType2 Identity-H through the program's `cmap`, with and
//!   without a `/CIDToGIDMap` stream (§9.7.4.2);
//! * predefined CJK CMaps (§9.7.5.2) and Adobe collections — Shift-JIS,
//!   GBK, Big Five, KS X 1001, `Uni…-UCS2`, Identity + `/CIDSystemInfo`
//!   — and a `/ToUnicode` that leaves codes out falling back to them;
//! * the full Symbol encoding (Annex D.5) and AGL §2 name forms.

use oxideav_pdf::reader::{DocumentReader, extract_text};

fn build_pdf(objects: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut bytes: Vec<u8> = b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let max_id = objects.iter().map(|(n, _)| *n).max().unwrap_or(0);
    let mut offsets = vec![0u64; (max_id + 1) as usize];
    for (num, body) in objects {
        offsets[*num as usize] = bytes.len() as u64;
        bytes.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(b"\nendobj\n");
    }
    let xref_off = bytes.len() as u64;
    bytes.extend_from_slice(format!("xref\n0 {}\n", max_id + 1).as_bytes());
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets[1..] {
        bytes.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    bytes
        .extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\n", max_id + 1).as_bytes());
    bytes.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    bytes
}

fn stream_body(dict_extra: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("<< /Length {} {} >>\nstream\n", payload.len(), dict_extra).into_bytes();
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\nendstream");
    out
}

/// One page showing `content` with `/F0` = object 5; `extra` objects
/// start at 6.
fn page_doc(font: &str, content: &[u8], extra: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    let mut objects: Vec<(u32, Vec<u8>)> = vec![
        (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec()),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /Font << /F0 5 0 R >> >> /Contents 4 0 R >>"
                .to_vec(),
        ),
        (4, stream_body("", content)),
        (5, font.as_bytes().to_vec()),
    ];
    objects.extend(extra);
    build_pdf(&objects)
}

fn text_of(pdf: &[u8]) -> String {
    let mut reader = DocumentReader::open(pdf).expect("open");
    let ex = extract_text(&mut reader).expect("extract");
    ex.runs.iter().map(|r| r.text.as_str()).collect()
}

// ───────────────────────── CFF builder ─────────────────────────

fn cff_int(v: i32) -> Vec<u8> {
    let mut o = vec![29];
    o.extend_from_slice(&v.to_be_bytes());
    o
}

fn cff_index(items: &[&[u8]]) -> Vec<u8> {
    let mut o = (items.len() as u16).to_be_bytes().to_vec();
    if items.is_empty() {
        return o;
    }
    o.push(4);
    let mut off = 1u32;
    o.extend_from_slice(&off.to_be_bytes());
    for it in items {
        off += it.len() as u32;
        o.extend_from_slice(&off.to_be_bytes());
    }
    for it in items {
        o.extend_from_slice(it);
    }
    o
}

/// A name-keyed CFF font: glyphs `.notdef` + `names` (SIDs 391.. via
/// the String INDEX), all drawing a path except those in `blank`;
/// encoding format 0 assigning `codes[i]` to GID `i + 1`.
fn build_cff(names: &[&str], codes: &[u8], blank: &[&str]) -> Vec<u8> {
    let header = [1u8, 0, 4, 4];
    let name_index = cff_index(&[b"TestCFF"]);
    let strings: Vec<&[u8]> = names.iter().map(|n| n.as_bytes()).collect();
    let string_index = cff_index(&strings);
    let gsubrs = cff_index(&[]);
    let mut charset = vec![0u8];
    for i in 0..names.len() {
        charset.extend_from_slice(&(391 + i as u16).to_be_bytes());
    }
    let mut encoding = vec![0u8, codes.len() as u8];
    encoding.extend_from_slice(codes);
    let drawn: &[u8] = &[139, 139, 21, 139, 5, 14]; // rmoveto, rlineto, endchar
    let empty: &[u8] = &[189, 14]; // width, endchar
    let mut glyphs: Vec<&[u8]> = vec![&[14]];
    for n in names {
        glyphs.push(if blank.contains(n) { empty } else { drawn });
    }
    let charstrings = cff_index(&glyphs);
    let top = |cs: i32, enc: i32, chs: i32| {
        let mut t = cff_int(cs);
        t.push(15);
        t.extend(cff_int(enc));
        t.push(16);
        t.extend(cff_int(chs));
        t.push(17);
        t
    };
    let top_len = cff_index(&[&top(0, 0, 0)]).len();
    let cs_at = header.len() + name_index.len() + top_len + string_index.len() + gsubrs.len();
    let enc_at = cs_at + charset.len();
    let chs_at = enc_at + encoding.len();
    let mut out = header.to_vec();
    out.extend(name_index);
    out.extend(cff_index(&[&top(
        cs_at as i32,
        enc_at as i32,
        chs_at as i32,
    )]));
    out.extend(string_index);
    out.extend(gsubrs);
    out.extend(charset);
    out.extend(encoding);
    out.extend(charstrings);
    out
}

// ───────────────────────── sfnt builder ─────────────────────────

fn be16(v: &[u16]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_be_bytes()).collect()
}

/// A `cmap` format-4 subtable mapping each `(code, gid)` as its own
/// one-code segment, plus the 0xFFFF terminator.
fn cmap_format4(pairs: &[(u16, u16)]) -> Vec<u8> {
    let mut pairs = pairs.to_vec();
    pairs.sort();
    let pairs = &pairs[..];
    let seg = pairs.len() + 1;
    let mut ends: Vec<u16> = pairs.iter().map(|p| p.0).collect();
    ends.push(0xFFFF);
    let mut deltas: Vec<u16> = pairs.iter().map(|p| p.1.wrapping_sub(p.0)).collect();
    deltas.push(1);
    let mut body = be16(&[4, 0, 0, (seg * 2) as u16, 0, 0, 0]);
    body.extend(be16(&ends));
    body.extend(be16(&[0]));
    body.extend(be16(&ends)); // start == end per segment
    body.extend(be16(&deltas));
    body.extend(be16(&vec![0; seg]));
    let len = body.len() as u16;
    body[2..4].copy_from_slice(&len.to_be_bytes());
    body
}

/// One `cmap` subtable: platform, encoding, `(code, gid)` pairs.
type CmapSpec = (u16, u16, Vec<(u16, u16)>);

/// A TrueType program: `glyph_count` glyphs (GID 0 included), one
/// `cmap` subtable per `(platform, encoding, pairs)`, a `post` 2.0
/// naming GIDs from `names` (`None` = `.notdef` index), and `loca` /
/// `glyf` giving every glyph except those in `blank` a 2-byte outline.
fn build_ttf(
    glyph_count: u16,
    cmaps: &[CmapSpec],
    names: &[Option<&str>],
    blank: &[u16],
) -> Vec<u8> {
    let mut cmap = be16(&[0, cmaps.len() as u16]);
    let mut subs = Vec::new();
    let mut off = 4 + 8 * cmaps.len();
    for (p, e, pairs) in cmaps {
        let sub = cmap_format4(pairs);
        cmap.extend(be16(&[*p, *e]));
        cmap.extend((off as u32).to_be_bytes());
        off += sub.len();
        subs.push(sub);
    }
    for s in subs {
        cmap.extend(s);
    }
    let mut post = 0x0002_0000u32.to_be_bytes().to_vec();
    post.extend([0u8; 28]);
    post.extend(be16(&[glyph_count]));
    let mut custom = Vec::new();
    for g in 0..glyph_count as usize {
        match names.get(g).copied().flatten() {
            Some(n) => {
                post.extend(be16(&[258 + custom.len() as u16]));
                custom.push(n);
            }
            None => post.extend(be16(&[0])),
        }
    }
    for n in custom {
        post.push(n.len() as u8);
        post.extend(n.as_bytes());
    }
    let mut head = vec![0u8; 54];
    head[50..52].copy_from_slice(&0u16.to_be_bytes()); // short loca
    let mut loca = Vec::new();
    let mut glyf = Vec::new();
    for g in 0..glyph_count {
        loca.extend(((glyf.len() / 2) as u16).to_be_bytes());
        if g != 0 && !blank.contains(&g) {
            glyf.extend([0u8, 1]);
        }
    }
    loca.extend(((glyf.len() / 2) as u16).to_be_bytes());
    let mut maxp = 0x0000_5000u32.to_be_bytes().to_vec();
    maxp.extend(be16(&[glyph_count]));
    let tables: Vec<(&[u8; 4], Vec<u8>)> = vec![
        (b"cmap", cmap),
        (b"glyf", glyf),
        (b"head", head),
        (b"loca", loca),
        (b"maxp", maxp),
        (b"post", post),
    ];
    let mut out = vec![0, 1, 0, 0];
    out.extend(be16(&[tables.len() as u16, 0, 0, 0]));
    let mut off = 12 + 16 * tables.len();
    let mut body: Vec<u8> = Vec::new();
    for (tag, data) in &tables {
        out.extend(*tag);
        out.extend([0u8; 4]);
        out.extend((off as u32).to_be_bytes());
        out.extend((data.len() as u32).to_be_bytes());
        let mut d = data.clone();
        while d.len() % 4 != 0 {
            d.push(0);
        }
        off += d.len();
        body.extend(d);
    }
    out.extend(body);
    out
}

// ───────────────────────── CFF built-in encodings ─────────────────────────

#[test]
fn type1c_builtin_encoding_names_and_blank_space() {
    // Codes 1..4 → H, i, exclam, and a glyph named `G9` that draws
    // nothing: the AGL maps the first three, the blank one reads as a
    // space. No /Encoding, no /ToUnicode.
    let cff = build_cff(&["H", "i", "exclam", "G9"], &[1, 2, 3, 4], &["G9"]);
    let pdf = page_doc(
        "<< /Type /Font /Subtype /Type1 /BaseFont /ABCDEF+Test /FontDescriptor 6 0 R >>",
        b"BT /F0 12 Tf 72 700 Td <0102040102 03> Tj ET",
        vec![
            (
                6,
                b"<< /Type /FontDescriptor /FontName /ABCDEF+Test /Flags 4 \
                  /FontFile3 7 0 R >>"
                    .to_vec(),
            ),
            (7, stream_body("/Subtype /Type1C", &cff)),
        ],
    );
    assert_eq!(text_of(&pdf), "Hi Hi!");
}

#[test]
fn type1c_differences_override_builtin_and_keep_the_rest() {
    // /Differences without /BaseEncoding applies over the built-in
    // encoding (§9.6.6.1): code 2 becomes `a`, code 1 stays `H`.
    let cff = build_cff(&["H", "i", "a"], &[1, 2], &[]);
    let pdf = page_doc(
        "<< /Type /Font /Subtype /Type1 /BaseFont /Test /FontDescriptor 6 0 R \
           /Encoding << /Differences [2 /a] >> >>",
        b"BT /F0 12 Tf 72 700 Td <0102> Tj ET",
        vec![
            (
                6,
                b"<< /Type /FontDescriptor /Flags 4 /FontFile3 7 0 R >>".to_vec(),
            ),
            (7, stream_body("/Subtype /Type1C", &cff)),
        ],
    );
    assert_eq!(text_of(&pdf), "Ha");
}

// ───────────────────────── TrueType ─────────────────────────

#[test]
fn symbolic_truetype_selects_through_3_0_and_names_via_post() {
    // Symbolic, no /Encoding: codes 0x41.. select via the (3,0)
    // subtable's 0xF041.. range; the glyphs are named in `post`.
    let ttf = build_ttf(
        4,
        &[(3, 0, vec![(0xF041, 1), (0xF042, 2), (0xF043, 3)])],
        &[None, Some("H"), Some("i"), Some("exclam")],
        &[],
    );
    let pdf = page_doc(
        "<< /Type /Font /Subtype /TrueType /BaseFont /Sym /FontDescriptor 6 0 R >>",
        b"BT /F0 12 Tf 72 700 Td (ABC) Tj ET",
        vec![
            (
                6,
                b"<< /Type /FontDescriptor /Flags 4 /FontFile2 7 0 R >>".to_vec(),
            ),
            (7, stream_body("", &ttf)),
        ],
    );
    assert_eq!(text_of(&pdf), "Hi!");
}

#[test]
fn symbolic_subset_without_glyph_text_keeps_its_differences() {
    // A subset whose (3,0) cmap is keyed by the PDF's own codes and
    // that names nothing (`post` with only .notdef, no Unicode cmap):
    // the /Differences table stays authoritative.
    let ttf = build_ttf(3, &[(3, 0, vec![(0xF001, 1), (0xF002, 2)])], &[], &[]);
    let pdf = page_doc(
        "<< /Type /Font /Subtype /TrueType /BaseFont /ABCDEF+Arial /FontDescriptor 6 0 R \
           /Encoding << /BaseEncoding /WinAnsiEncoding /Differences [1 /O /K] >> >>",
        b"BT /F0 12 Tf 72 700 Td <0102> Tj ET",
        vec![
            (
                6,
                b"<< /Type /FontDescriptor /Flags 4 /FontFile2 7 0 R >>".to_vec(),
            ),
            (7, stream_body("", &ttf)),
        ],
    );
    assert_eq!(text_of(&pdf), "OK");
}

#[test]
fn glyph_index_difference_names_resolve_through_the_unicode_cmap() {
    // `/g7` is no AGL name; `post` names GID 1 `g7` and the (3,1)
    // subtable maps U+005A to GID 1 — so code 1 is "Z".
    let ttf = build_ttf(2, &[(3, 1, vec![(0x5A, 1)])], &[None, Some("g7")], &[]);
    let pdf = page_doc(
        "<< /Type /Font /Subtype /TrueType /BaseFont /T /FontDescriptor 6 0 R \
           /Encoding << /BaseEncoding /WinAnsiEncoding /Differences [1 /g7] >> >>",
        b"BT /F0 12 Tf 72 700 Td <01> Tj ET",
        vec![
            (
                6,
                b"<< /Type /FontDescriptor /Flags 32 /FontFile2 7 0 R >>".to_vec(),
            ),
            (7, stream_body("", &ttf)),
        ],
    );
    assert_eq!(text_of(&pdf), "Z");
}

// ───────────────────────── CIDFontType2 ─────────────────────────

fn cid_type2_doc(cid_to_gid: Option<&[u8]>, content: &[u8]) -> Vec<u8> {
    let ttf = build_ttf(
        7,
        &[(3, 1, vec![(0x4B, 6), (0x4F, 5), (0x20, 4)])],
        &[],
        &[4],
    );
    let map_entry = if cid_to_gid.is_some() {
        " /CIDToGIDMap 9 0 R"
    } else {
        ""
    };
    let mut extra = vec![
        (
            6,
            format!(
                "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /T \
                 /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> \
                 /FontDescriptor 7 0 R{map_entry} >>"
            )
            .into_bytes(),
        ),
        (
            7,
            b"<< /Type /FontDescriptor /Flags 4 /FontFile2 8 0 R >>".to_vec(),
        ),
        (8, stream_body("", &ttf)),
    ];
    if let Some(map) = cid_to_gid {
        extra.push((9, stream_body("", map)));
    }
    page_doc(
        "<< /Type /Font /Subtype /Type0 /BaseFont /T /Encoding /Identity-H \
           /DescendantFonts [6 0 R] >>",
        content,
        extra,
    )
}

#[test]
fn cid_truetype_identity_reads_glyphs_through_the_font_cmap() {
    // GIDs 5, 4, 6 → "O", " ", "K" by the (3,1) subtable run backwards.
    let pdf = cid_type2_doc(None, b"BT /F0 12 Tf 72 700 Td <000500040006> Tj ET");
    assert_eq!(text_of(&pdf), "O K");
}

#[test]
fn cid_truetype_cid_to_gid_map_stream() {
    // CID 1 → GID 5, CID 2 → GID 6.
    let map = [0u8, 0, 0, 5, 0, 6];
    let pdf = cid_type2_doc(Some(&map), b"BT /F0 12 Tf 72 700 Td <00010002> Tj ET");
    assert_eq!(text_of(&pdf), "OK");
}

// ───────────────────────── predefined CJK CMaps ─────────────────────────

fn cjk_doc(encoding: &str, ordering: &str, content: &[u8], to_unicode: Option<&[u8]>) -> Vec<u8> {
    let tu = if to_unicode.is_some() {
        " /ToUnicode 7 0 R"
    } else {
        ""
    };
    let mut extra = vec![(
        6,
        format!(
            "<< /Type /Font /Subtype /CIDFontType0 /BaseFont /CJK \
             /CIDSystemInfo << /Registry (Adobe) /Ordering ({ordering}) /Supplement 2 >> \
             /DW 1000 >>"
        )
        .into_bytes(),
    )];
    if let Some(tu) = to_unicode {
        extra.push((7, stream_body("", tu)));
    }
    page_doc(
        &format!(
            "<< /Type /Font /Subtype /Type0 /BaseFont /CJK /Encoding /{encoding} \
             /DescendantFonts [6 0 R]{tu} >>"
        ),
        content,
        extra,
    )
}

#[test]
#[cfg(feature = "cjk-cmaps")]
fn shift_jis_predefined_cmap() {
    // あ 82A0, い 82A2, then single-byte "A".
    let pdf = cjk_doc(
        "90ms-RKSJ-H",
        "Japan1",
        b"BT /F0 12 Tf 72 700 Td <82A082A241> Tj ET",
        None,
    );
    assert_eq!(text_of(&pdf), "あいA");
}

#[test]
#[cfg(feature = "cjk-cmaps")]
fn chinese_and_korean_predefined_cmaps() {
    for (enc, ordering, code) in [
        ("GBK-EUC-H", "GB1", "D6D0"),
        ("B5pc-H", "CNS1", "A4A4"),
        ("KSC-EUC-H", "Korea1", "F1E9"),
    ] {
        let content = format!("BT /F0 12 Tf 72 700 Td <{code}> Tj ET");
        let pdf = cjk_doc(enc, ordering, content.as_bytes(), None);
        assert_eq!(text_of(&pdf), "中", "{enc}");
    }
}

#[test]
fn unicode_predefined_cmap_reads_codes_as_unicode() {
    let pdf = cjk_doc(
        "UniJIS-UCS2-H",
        "Japan1",
        b"BT /F0 12 Tf 72 700 Td <30423044> Tj ET",
        None,
    );
    assert_eq!(text_of(&pdf), "あい");
}

#[test]
#[cfg(feature = "cjk-cmaps")]
fn identity_encoding_with_adobe_collection() {
    // CIDs 843 / 845 are あ / い in Adobe-Japan1; 633 the ideographic
    // space.
    let pdf = cjk_doc(
        "Identity-H",
        "Japan1",
        b"BT /F0 12 Tf 72 700 Td <034B0279034D> Tj ET",
        None,
    );
    assert_eq!(text_of(&pdf), "あ\u{3000}い");
}

#[test]
#[cfg(feature = "cjk-cmaps")]
fn to_unicode_gaps_fall_back_to_the_collection() {
    // The ToUnicode CMap covers only CID 843; CID 845 comes from the
    // Adobe-Japan1 table instead of U+FFFD.
    let tu = b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap
1 begincodespacerange <0000> <FFFF> endcodespacerange
1 beginbfchar <034B> <0058> endbfchar
endcmap end end";
    let pdf = cjk_doc(
        "Identity-H",
        "Japan1",
        b"BT /F0 12 Tf 72 700 Td <034B034D> Tj ET",
        Some(tu),
    );
    assert_eq!(text_of(&pdf), "Xい");
}

#[test]
#[cfg(feature = "cjk-cmaps")]
fn vertical_predefined_cmap_advances_down_the_column() {
    let pdf = cjk_doc(
        "90ms-RKSJ-V",
        "Japan1",
        b"BT /F0 10 Tf 300 700 Td <82A0> Tj <82A2> Tj ET",
        None,
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let ex = extract_text(&mut reader).expect("extract");
    assert_eq!(ex.runs.len(), 2);
    assert_eq!(ex.runs[0].text, "あ");
    assert_eq!(ex.runs[1].text, "い");
    // Same x, the second glyph one em (DW2 default 1000) further down.
    assert!((ex.runs[1].position.0 - 300.0).abs() < 0.01);
    assert!((ex.runs[1].position.1 - 690.0).abs() < 0.01);
}

// ───────────────────────── Symbol + AGL forms ─────────────────────────

#[test]
fn full_symbol_encoding() {
    // Annex D.5: 0x5F underscore, 0xA3 lessequal, 0xE5 summation,
    // 0xD6 radical — codes the old partial table left unmapped.
    let pdf = page_doc(
        "<< /Type /Font /Subtype /Type1 /BaseFont /Symbol >>",
        b"BT /F0 12 Tf 72 700 Td <5FA3E5D6> Tj ET",
        Vec::new(),
    );
    assert_eq!(text_of(&pdf), "_≤∑√");
}

#[test]
fn agl_suffix_and_ligature_component_names() {
    // AGL §2: `a.sc` drops its suffix, `f_f_i` maps component-wise,
    // `uni0041.alt` combines both rules, and the full list knows
    // `afii10017` (Cyrillic А).
    let pdf = page_doc(
        "<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman \
           /Encoding << /Differences [1 /a.sc /f_f_i /uni0041.alt /afii10017] >> >>",
        b"BT /F0 12 Tf 72 700 Td <01020304> Tj ET",
        Vec::new(),
    );
    assert_eq!(text_of(&pdf), "affiAА");
}

// ───────────────────────── page structure ─────────────────────────

#[test]
fn inherited_resources_and_indirect_contents_array() {
    // /Resources sits on the /Pages node (§7.7.3.4) and /Contents is
    // an indirect reference to an *array* of streams (§7.7.3.3).
    let objects: Vec<(u32, Vec<u8>)> = vec![
        (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
        (
            2,
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 \
              /Resources << /Font << /F0 5 0 R >> >> >>"
                .to_vec(),
        ),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>".to_vec(),
        ),
        (4, b"[6 0 R 7 0 R]".to_vec()),
        (
            5,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        ),
        (6, stream_body("", b"BT /F0 12 Tf 72 700 Td (Hello) Tj")),
        (7, stream_body("", b"( world) Tj ET")),
    ];
    assert_eq!(text_of(&build_pdf(&objects)), "Hello world");
}

#[test]
fn type3_blank_glyph_reads_as_space() {
    // cairo-style Type 3 space font: `/Differences [0 /0]`, glyph `0`
    // only declares its width — it paints nothing.
    let pdf = page_doc(
        "<< /Type /Font /Subtype /Type3 /FontBBox [0 0 0 0] \
           /FontMatrix [0.001 0 0 0.001 0 0] /CharProcs << /0 6 0 R /1 7 0 R >> \
           /Encoding << /Type /Encoding /Differences [0 /0 /1] >> \
           /FirstChar 0 /LastChar 1 /Widths [250 500] >>",
        b"BT /F0 12 Tf 72 700 Td <0001> Tj ET",
        vec![
            (6, stream_body("", b"250 0 d0")),
            (
                7,
                stream_body("", b"500 0 0 0 500 500 d1 0 0 m 500 500 l S"),
            ),
        ],
    );
    assert_eq!(text_of(&pdf), " \u{FFFD}");
}

#[test]
fn form_xobject_text_with_own_and_inherited_resources() {
    // The page paints form /Fm0 (own /Resources naming /F1) which
    // paints form /Fm1 (no /Resources — uses its invoker's, §7.8.3)
    // and itself again (a cycle, ignored).
    let objects: Vec<(u32, Vec<u8>)> = vec![
        (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec()),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /Font << /F0 5 0 R >> /XObject << /Fm0 6 0 R >> >> \
              /Contents 4 0 R >>"
                .to_vec(),
        ),
        (
            4,
            stream_body("", b"BT /F0 12 Tf 72 700 Td (Page) Tj ET /Fm0 Do"),
        ),
        (
            5,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        ),
        (
            6,
            stream_body(
                "/Type /XObject /Subtype /Form /BBox [0 0 612 792] \
                 /Resources << /Font << /F1 5 0 R >> /XObject << /Fm1 7 0 R /Fm0 6 0 R >> >>",
                b"BT /F1 12 Tf 72 600 Td (Form) Tj ET /Fm1 Do /Fm0 Do",
            ),
        ),
        (
            7,
            stream_body(
                "/Type /XObject /Subtype /Form /BBox [0 0 612 792]",
                b"BT /F1 12 Tf 72 500 Td (Nested) Tj ET",
            ),
        ),
    ];
    let pdf = build_pdf(&objects);
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let ex = extract_text(&mut reader).expect("extract");
    let texts: Vec<&str> = ex.runs.iter().map(|r| r.text.as_str()).collect();
    assert_eq!(texts, ["Page", "Form", "Nested"]);
}

// ───────────────────────── word assembly ─────────────────────────

#[test]
fn justified_glyph_by_glyph_line_keeps_its_word_gaps() {
    // One show per glyph, glyphs abutting inside words and 0.26 em
    // apart between them (a justified line without space glyphs):
    // the word gaps are not letter spacing.
    let mut content = b"BT /F0 10 Tf ".to_vec();
    let mut x = 72.0f32;
    for word in ["The", "JPEG", "Committee"] {
        for c in word.chars() {
            content.extend(format!("1 0 0 1 {x:.2} 700 Tm ({c}) Tj ").as_bytes());
            x += 6.0;
        }
        x += 2.6;
    }
    content.extend(b"ET");
    let pdf = page_doc(
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
        &content,
        Vec::new(),
    );
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let text = reader.text_extraction().expect("extract").flat_text();
    assert_eq!(text, "The JPEG Committee");
}

#[test]
fn tj_word_gaps_with_tiny_letter_kerns() {
    // Word gaps of ~250/1000 em next to ±1..4 letter kerns: the word
    // gaps are not the tracking (half the single-glyph pairs are word
    // gaps here).
    let pdf = page_doc(
        "<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman >>",
        b"BT /F0 12 Tf 72 700 Td [(this)-246(layer)-245(i)1(s)-246(s)4(pec)-6(i)1(fied.)\
          -490(I)-3(n)-248(s)4(ome)-251(c)4(ases)-6(,)]TJ ET",
        Vec::new(),
    );
    assert_eq!(text_of(&pdf), "this layer is specified. In some cases,");
}
