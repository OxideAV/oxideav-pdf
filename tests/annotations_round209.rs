//! Round-209 — three new §12.5.6 annotation subtypes in the round-26
//! reader: **Sound** (§12.5.6.16 Table 185), **Movie** (§12.5.6.17
//! Table 186), and **Screen** (§12.5.6.18 Table 187).
//!
//! All three were previously falling through to
//! `AnnotationKind::Other`. Round-209 surfaces them non-destructively
//! — the §13.3 sound stream, the §13.4 movie dictionary, and the
//! §12.6.4.13 rendition-action target are preserved as `ObjectId`s so
//! callers can re-resolve them through their own audio / video / action
//! plumbing (this crate doesn't decode audio or video, and rendition
//! actions are already handled by the round-36 `actions` reader).
//!
//! Coverage of the spec tables:
//!
//! * §12.5.6.16 Table 185 (Sound) — `/Sound` stream + `/Name` icon.
//! * §12.5.6.17 Table 186 (Movie) — `/T` title + `/Movie` dict +
//!   `/A` activation (boolean tri-state or indirect activation dict).
//! * §12.5.6.18 Table 187 (Screen) — `/T` title + `/MK` appearance
//!   characteristics + `/A` action + `/AA` additional-actions.
//!
//! Round-trip is validated against minimal hand-synthesised PDFs (the
//! same shape as `tests/annotations_round197.rs` and
//! `tests/annotations_round204.rs`).

use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{read_pdf_annotations, AnnotationKind, MovieActivation};

/// Helper — open the synthesised PDF and walk its annotations.
fn read_annots(pdf: &[u8]) -> Vec<oxideav_pdf::PdfAnnotation> {
    let mut r = DocumentReader::open(pdf).unwrap();
    read_pdf_annotations(&mut r).unwrap()
}

/// Minimal one-page PDF with the supplied per-page annotation dicts
/// spliced into the page's `/Annots` array. Object numbering:
///   1 Catalog
///   2 Pages
///   3 Page
///   4 Empty content stream
///   5..N annotation dicts (or supporting sound streams / movie dicts /
///   appearance-characteristic dicts / action dicts)
fn synth_pdf_with_objects(extra_obj_bodies: &[&str], annot_refs: &[u32]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"%PDF-1.7\n%");
    body.extend_from_slice(&[0xe2, 0xe3, 0xcf, 0xd3]);
    body.push(b'\n');
    let mut offsets: Vec<usize> = Vec::new();
    let push_obj = |body: &mut Vec<u8>, offsets: &mut Vec<usize>, n: u32, content: &str| {
        offsets.push(body.len());
        body.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", n, content).as_bytes());
    };
    push_obj(
        &mut body,
        &mut offsets,
        1,
        "<< /Type /Catalog /Pages 2 0 R >>",
    );
    push_obj(
        &mut body,
        &mut offsets,
        2,
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    );
    let annot_arr = annot_refs
        .iter()
        .map(|n| format!("{} 0 R", n))
        .collect::<Vec<_>>()
        .join(" ");
    let page_dict = format!(
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
         /Contents 4 0 R /Resources << >> /Annots [{}] >>",
        annot_arr
    );
    push_obj(&mut body, &mut offsets, 3, &page_dict);
    push_obj(
        &mut body,
        &mut offsets,
        4,
        "<< /Length 0 >>\nstream\n\nendstream",
    );
    for (i, ob) in extra_obj_bodies.iter().enumerate() {
        push_obj(&mut body, &mut offsets, 5 + i as u32, ob);
    }
    let xref_off = body.len();
    let n_objs = 5 + extra_obj_bodies.len();
    body.extend_from_slice(format!("xref\n0 {}\n", n_objs).as_bytes());
    body.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        body.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    body.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            n_objs, xref_off
        )
        .as_bytes(),
    );
    body
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.16 Sound annotation (Table 185).
// ────────────────────────────────────────────────────────────────────

#[test]
fn sound_annotation_with_indirect_stream_and_default_icon() {
    // Annot at obj 5 references a sound stream at obj 6. Table 185
    // makes `/Name` optional with default "Speaker".
    let annot = "<< /Type /Annot /Subtype /Sound /Rect [10 20 30 40] \
                 /Sound 6 0 R >>";
    let sound_stream = "<< /Type /Sound /R 22050 /C 1 /B 8 /E /Raw /Length 0 >>\n\
                        stream\n\nendstream";
    let pdf = synth_pdf_with_objects(&[annot, sound_stream], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::Sound { sound, icon } => {
            assert_eq!(sound.map(|id| id.number), Some(6));
            assert_eq!(icon, "Speaker");
        }
        other => panic!("expected Sound, got {:?}", other),
    }
}

#[test]
fn sound_annotation_carries_mic_icon() {
    let annot = "<< /Type /Annot /Subtype /Sound /Rect [0 0 10 10] \
                 /Sound 6 0 R /Name /Mic >>";
    let sound_stream = "<< /Type /Sound /R 22050 /Length 0 >>\nstream\n\nendstream";
    let pdf = synth_pdf_with_objects(&[annot, sound_stream], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::Sound { icon, .. } => assert_eq!(icon, "Mic"),
        other => panic!("expected Sound, got {:?}", other),
    }
}

#[test]
fn sound_annotation_tolerates_missing_sound_entry() {
    // Table 185 says /Sound is required; tolerant reader still
    // enumerates a malformed annot rather than dropping it, surfacing
    // None to signal the gap.
    let annot = "<< /Type /Annot /Subtype /Sound /Rect [0 0 10 10] >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::Sound { sound, icon } => {
            assert!(sound.is_none());
            // Default still applies.
            assert_eq!(icon, "Speaker");
        }
        other => panic!("expected Sound, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.17 Movie annotation (Table 186).
// ────────────────────────────────────────────────────────────────────

#[test]
fn movie_annotation_with_title_and_default_activation() {
    // Table 186 says `/A` defaults to true (Play) when omitted.
    let annot = "<< /Type /Annot /Subtype /Movie /Rect [0 0 100 100] \
                 /T (intro) /Movie 6 0 R >>";
    let movie_dict = "<< /F (intro.mov) >>";
    let pdf = synth_pdf_with_objects(&[annot, movie_dict], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::Movie {
            title,
            movie,
            activation,
        } => {
            assert_eq!(title.as_deref(), Some("intro"));
            assert_eq!(movie.map(|id| id.number), Some(6));
            assert_eq!(*activation, MovieActivation::Play);
        }
        other => panic!("expected Movie, got {:?}", other),
    }
}

#[test]
fn movie_annotation_with_explicit_a_true() {
    let annot = "<< /Type /Annot /Subtype /Movie /Rect [0 0 100 100] \
                 /T (a) /Movie 6 0 R /A true >>";
    let movie_dict = "<< /F (x.mov) >>";
    let pdf = synth_pdf_with_objects(&[annot, movie_dict], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::Movie { activation, .. } => {
            assert_eq!(*activation, MovieActivation::Play);
        }
        other => panic!("expected Movie, got {:?}", other),
    }
}

#[test]
fn movie_annotation_with_a_false_suppresses_playback() {
    let annot = "<< /Type /Annot /Subtype /Movie /Rect [0 0 100 100] \
                 /T (suppressed) /Movie 6 0 R /A false >>";
    let movie_dict = "<< /F (x.mov) >>";
    let pdf = synth_pdf_with_objects(&[annot, movie_dict], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::Movie { activation, .. } => {
            assert_eq!(*activation, MovieActivation::Dont);
        }
        other => panic!("expected Movie, got {:?}", other),
    }
}

#[test]
fn movie_annotation_with_indirect_activation_dict() {
    // /A may be a dictionary — round-209 surfaces the indirect ref as
    // Custom(id).
    let annot = "<< /Type /Annot /Subtype /Movie /Rect [0 0 100 100] \
                 /T (custom) /Movie 6 0 R /A 7 0 R >>";
    let movie_dict = "<< /F (x.mov) >>";
    let activation_dict = "<< /Start 0 /Duration 5000 /Volume 50 >>";
    let pdf = synth_pdf_with_objects(&[annot, movie_dict, activation_dict], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::Movie { activation, .. } => match activation {
            MovieActivation::Custom(id) => assert_eq!(id.number, 7),
            other => panic!("expected Custom, got {:?}", other),
        },
        other => panic!("expected Movie, got {:?}", other),
    }
}

#[test]
fn movie_annotation_tolerates_missing_movie_entry() {
    // Table 186 says /Movie is required; a malformed annot still
    // enumerates with movie=None rather than being dropped.
    let annot = "<< /Type /Annot /Subtype /Movie /Rect [0 0 100 100] /T (lonely) >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::Movie {
            title,
            movie,
            activation,
        } => {
            assert_eq!(title.as_deref(), Some("lonely"));
            assert!(movie.is_none());
            assert_eq!(*activation, MovieActivation::Play);
        }
        other => panic!("expected Movie, got {:?}", other),
    }
}

#[test]
fn movie_annotation_handles_utf16be_title() {
    // 中文 title encoded as hex UTF-16BE with BOM.
    let annot = "<< /Type /Annot /Subtype /Movie /Rect [0 0 100 100] \
                 /T <FEFF4E2D6587> /Movie 6 0 R >>";
    let movie_dict = "<< /F (x.mov) >>";
    let pdf = synth_pdf_with_objects(&[annot, movie_dict], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::Movie { title, .. } => {
            assert_eq!(title.as_deref(), Some("中文"));
        }
        other => panic!("expected Movie, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.18 Screen annotation (Table 187).
// ────────────────────────────────────────────────────────────────────

#[test]
fn screen_annotation_with_all_optional_entries() {
    let annot = "<< /Type /Annot /Subtype /Screen /Rect [0 0 320 240] \
                 /T (rendition target) \
                 /MK 6 0 R /A 7 0 R /AA 8 0 R >>";
    let mk = "<< /I 9 0 R >>";
    let action = "<< /Type /Action /S /Rendition >>";
    let additional_actions = "<< /PO << /S /Rendition >> >>";
    let icon = "<< /Type /XObject /Subtype /Form /BBox [0 0 1 1] /Length 0 >>\n\
                stream\n\nendstream";
    let pdf = synth_pdf_with_objects(&[annot, mk, action, additional_actions, icon], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::Screen {
            title,
            appearance_chars,
            action,
            additional_actions,
        } => {
            assert_eq!(title.as_deref(), Some("rendition target"));
            assert_eq!(appearance_chars.map(|id| id.number), Some(6));
            assert_eq!(action.map(|id| id.number), Some(7));
            assert_eq!(additional_actions.map(|id| id.number), Some(8));
        }
        other => panic!("expected Screen, got {:?}", other),
    }
}

#[test]
fn screen_annotation_with_only_subtype() {
    // Table 187 makes every entry except /Subtype optional — a bare
    // Screen annot enumerates with all-None metadata.
    let annot = "<< /Type /Annot /Subtype /Screen /Rect [0 0 10 10] >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::Screen {
            title,
            appearance_chars,
            action,
            additional_actions,
        } => {
            assert!(title.is_none());
            assert!(appearance_chars.is_none());
            assert!(action.is_none());
            assert!(additional_actions.is_none());
        }
        other => panic!("expected Screen, got {:?}", other),
    }
}

#[test]
fn screen_annotation_drops_inline_action_dict() {
    // Table 187 lets /A be either a direct dict or an indirect ref.
    // Round-209 only surfaces the indirect form (callers re-resolve
    // through the round-36 actions reader, which itself walks
    // indirect refs); an inline action dict round-trips structurally
    // but action=None signals "look at the raw dict yourself".
    let annot = "<< /Type /Annot /Subtype /Screen /Rect [0 0 10 10] \
                 /A << /Type /Action /S /JavaScript /JS (app.alert\\(1\\)) >> >>";
    let pdf = synth_pdf_with_objects(&[annot], &[5]);
    let annots = read_annots(&pdf);
    match &annots[0].kind {
        AnnotationKind::Screen { action, .. } => assert!(action.is_none()),
        other => panic!("expected Screen, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// Cross-subtype: round-209's three new variants coexist with the long
// tail surfaced by round-197 + round-204.
// ────────────────────────────────────────────────────────────────────

#[test]
fn round209_subtypes_enumerate_alongside_long_tail() {
    let sound = "<< /Type /Annot /Subtype /Sound /Rect [0 0 10 10] \
                 /Sound 9 0 R >>";
    let movie = "<< /Type /Annot /Subtype /Movie /Rect [0 0 10 10] \
                 /T (m) /Movie 10 0 R >>";
    let screen = "<< /Type /Annot /Subtype /Screen /Rect [0 0 10 10] \
                  /T (s) >>";
    // Anything still in the long tail (/Projection after round 220
    // lifted /3D and round 242 lifted /RichMedia out into their own
    // structured variants) keeps falling through to
    // AnnotationKind::Other.
    let projection = "<< /Type /Annot /Subtype /Projection /Rect [0 0 10 10] >>";
    let sound_stream = "<< /Length 0 >>\nstream\n\nendstream";
    let movie_dict = "<< /F (x.mov) >>";
    let pdf = synth_pdf_with_objects(
        &[sound, movie, screen, projection, sound_stream, movie_dict],
        &[5, 6, 7, 8],
    );
    let annots = read_annots(&pdf);
    assert_eq!(annots.len(), 4);
    assert!(matches!(annots[0].kind, AnnotationKind::Sound { .. }));
    assert!(matches!(annots[1].kind, AnnotationKind::Movie { .. }));
    assert!(matches!(annots[2].kind, AnnotationKind::Screen { .. }));
    match &annots[3].kind {
        AnnotationKind::Other { subtype } => assert_eq!(subtype, "Projection"),
        other => panic!("expected Other(\"Projection\"), got {:?}", other),
    }
}
