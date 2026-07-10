//! Round-406 robustness smoke over the §8.9.5.2 / §8.9.6 / §8.9.7
//! image-decode paths: deterministic single-byte mutations of
//! image-bearing fixtures must never panic the reader — a malformed
//! file yields `Err` (or a tolerantly-degraded `Ok`), never an abort.
//! The full fuzz suite (`fuzz/`) covers the open-ended search; this
//! test pins the new decode paths into the plain CI test run.

use oxideav_pdf::read_pdf_to_scene;

fn stream_obj(dict_body: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("<< {} /Length {} >>\nstream\n", dict_body, payload.len()).as_bytes(),
    );
    body.extend_from_slice(payload);
    body.extend_from_slice(b"\nendstream");
    body
}

fn one_page_pdf(resources: &str, content: &[u8], extra: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    let mut objects: Vec<(u32, Vec<u8>)> = vec![
        (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
        (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>".to_vec()),
        (
            3,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
                 /Resources << {resources} >> /Contents 4 0 R >>"
            )
            .into_bytes(),
        ),
        (4, stream_obj("", content)),
    ];
    objects.extend(extra);
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<(u32, usize)> = Vec::new();
    for (num, body) in &objects {
        offsets.push((*num, buf.len()));
        buf.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        buf.extend_from_slice(body);
        buf.extend_from_slice(b"\nendobj\n");
    }
    let n = objects.iter().map(|(num, _)| *num).max().unwrap_or(0) + 1;
    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n");
    buf.extend_from_slice(format!("0 {n}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for num in 1..n {
        let off = offsets
            .iter()
            .find(|(o, _)| *o == num)
            .map(|(_, off)| *off)
            .unwrap_or(0);
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(b"trailer\n");
    buf.extend_from_slice(format!("<< /Size {n} /Root 1 0 R >>\n").as_bytes());
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

/// The image-bearing fixture set: one per new decode path.
fn fixtures() -> Vec<Vec<u8>> {
    vec![
        // Colour-key masked RGB.
        one_page_pdf(
            "/XObject << /Im0 5 0 R >>",
            b"q 100 0 0 100 0 0 cm /Im0 Do Q",
            vec![(
                5,
                stream_obj(
                    "/Type /XObject /Subtype /Image /Width 3 /Height 1 \
                     /ColorSpace /DeviceRGB /BitsPerComponent 8 \
                     /Mask [0 50 200 255 0 50]",
                    &[255, 0, 0, 0, 255, 0, 0, 0, 255],
                ),
            )],
        ),
        // Stencil + explicit mask + SMask trio.
        one_page_pdf(
            "/XObject << /St 5 0 R /Im 6 0 R >>",
            b"q 1 0 0 rg 50 0 0 50 0 0 cm /St Do /Im Do Q",
            vec![
                (
                    5,
                    stream_obj(
                        "/Type /XObject /Subtype /Image /Width 2 /Height 2 \
                         /ImageMask true /Decode [1 0]",
                        &[0b0100_0000, 0b1000_0000],
                    ),
                ),
                (
                    6,
                    stream_obj(
                        "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                         /ColorSpace /DeviceRGB /BitsPerComponent 8 \
                         /Mask 7 0 R /SMask 8 0 R",
                        &[10, 20, 30, 40, 50, 60],
                    ),
                ),
                (
                    7,
                    stream_obj(
                        "/Type /XObject /Subtype /Image /Width 1 /Height 1 /ImageMask true",
                        &[0b1000_0000],
                    ),
                ),
                (
                    8,
                    stream_obj(
                        "/Type /XObject /Subtype /Image /Width 2 /Height 1 \
                         /ColorSpace /DeviceGray /BitsPerComponent 4 /Decode [1 0]",
                        &[0x0F],
                    ),
                ),
            ],
        ),
        // Indexed named colour space at 2 bpc.
        one_page_pdf(
            "/XObject << /Im0 5 0 R >> \
             /ColorSpace << /Pal [/Indexed /DeviceRGB 3 <FF0000 00FF00 0000FF FFFF00>] >>",
            b"q 100 0 0 100 0 0 cm /Im0 Do Q",
            vec![(
                5,
                stream_obj(
                    "/Type /XObject /Subtype /Image /Width 4 /Height 1 \
                     /ColorSpace /Pal /BitsPerComponent 2",
                    &[0b0001_1011],
                ),
            )],
        ),
        // Inline stencil + inline Indexed in one content stream.
        {
            let mut content = b"q 0 0.5 0.5 rg BI /W 2 /H 1 /IM true /D [1 0] ID ".to_vec();
            content.extend_from_slice(&[0b0100_0000]);
            content.extend_from_slice(
                b" EI Q q BI /W 4 /H 1 /CS [/I /RGB 3 <FF000000FF000000FFFFFF00>] /BPC 2 ID ",
            );
            content.extend_from_slice(&[0b0001_1011]);
            content.extend_from_slice(b" EI Q");
            one_page_pdf("", &content, vec![])
        },
    ]
}

#[test]
fn single_byte_mutations_never_panic() {
    for (fi, fixture) in fixtures().iter().enumerate() {
        // Pristine fixture must parse.
        read_pdf_to_scene(fixture).unwrap_or_else(|e| panic!("fixture {fi} pristine: {e:?}"));
        // Deterministic mutation sweep: XOR each 7th byte with three
        // patterns. ~3·len/7 reader invocations per fixture — cheap
        // enough for the plain test run, dense enough to hit the
        // image dicts, payloads, and inline dict bytes.
        for pos in (0..fixture.len()).step_by(7) {
            for pattern in [0xFFu8, 0x01, 0x80] {
                let mut mutated = fixture.clone();
                mutated[pos] ^= pattern;
                let _ = read_pdf_to_scene(&mutated);
            }
        }
    }
}

#[test]
fn truncations_never_panic() {
    for fixture in fixtures() {
        for len in (0..fixture.len()).step_by(13) {
            let _ = read_pdf_to_scene(&fixture[..len]);
        }
    }
}
