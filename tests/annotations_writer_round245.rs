//! Round-245 — `/Sound` annotation-writer end-to-end tests
//! (ISO 32000-1 §12.5.6.16 Table 185 + §13.3 Table 294).
//!
//! Validates that [`oxideav_pdf::write_pdf_with_annotations`] handles
//! the [`oxideav_pdf::WriterAnnotationKind::Sound`] variant by emitting
//! (a) a `/Type /Sound` stream object carrying the supplied sample
//! bytes with the §13.3 Table 294 entries `/R`, `/C`, `/B`, `/E`, and
//! (b) the `/Subtype /Sound` annotation dict whose `/Sound` entry
//! points at the stream and whose `/Name` carries the icon. Round-trip
//! through the round-209 generic annotation reader confirms the wire
//! bits match.
//!
//! Provenance: ISO 32000-1:2008 §12.5.6.16 Table 185 (sound annotation
//! entries) + §13.3 Table 294 (sound object stream entries). The
//! crate's docs/document/pdf/PDF32000_2008.pdf is the sole source for
//! every Table 185 / Table 294 entry encoded by this writer.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    read_pdf_annotations, write_pdf_with_annotations, Annotation, AnnotationKind, SoundEncoding,
    WriterAnnotationKind,
};
use oxideav_scene::{Page, Scene};

fn one_page_scene() -> Scene {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(190.0, 10.0)));
    p.commands
        .push(PathCommand::LineTo(Point::new(190.0, 190.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 300.0,
        height: 300.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(0, 0, 0))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        },
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    let mut page = Page::new(300.0, 300.0);
    page.content = frame;
    Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    }
}

fn default_annot(rect: [f32; 4], kind: WriterAnnotationKind) -> Annotation {
    Annotation {
        source_page_index: 0,
        rect,
        author: None,
        modified: None,
        flags: None,
        colour: None,
        border: None,
        kind,
    }
}

// ────────────────────────────────────────────────────────────────────
// §12.5.6.16 Sound annotation (Table 185) + §13.3 Sound object
// (Table 294).
// ────────────────────────────────────────────────────────────────────

/// Minimal Sound annotation — every §13.3 Table 294 field at its
/// default value, default `/Speaker` icon. The writer should emit the
/// `/Type /Sound` stream, the `/Subtype /Sound` annotation, and the
/// round-209 reader should round-trip the icon + the stream
/// ObjectId.
#[test]
fn sound_minimal_defaults_roundtrips() {
    let scene = one_page_scene();
    // 16 samples of 0x80 = mid-scale unsigned 8-bit audio.
    let samples = vec![0x80u8; 16];
    let annot = default_annot(
        [10.0, 20.0, 30.0, 40.0],
        WriterAnnotationKind::Sound {
            icon: None,
            sampling_rate: 22050.0,
            channels: 1,
            bits_per_sample: 8,
            encoding: SoundEncoding::Raw,
            sound_samples: samples.clone(),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");

    // Wire-level sanity — every required Table 185 / Table 294 marker
    // shows up at least once.
    let pdf_str = String::from_utf8_lossy(&pdf);
    assert!(
        pdf_str.contains("/Subtype /Sound"),
        "annotation /Subtype not emitted",
    );
    assert!(
        pdf_str.contains("/Type /Sound"),
        "sound stream /Type not emitted",
    );
    assert!(
        pdf_str.contains("/Name /Speaker"),
        "default /Speaker icon not emitted",
    );
    // /R is required per Table 294 — always present.
    assert!(pdf_str.contains("/R "), "/R sample rate not emitted");
    // /C default is 1 ⇒ omitted at the default value.
    assert!(
        !pdf_str.contains("/C 1"),
        "/C should be omitted at default value 1 per Table 294",
    );
    // /B default is 8 ⇒ omitted at the default value.
    assert!(
        !pdf_str.contains("/B 8"),
        "/B should be omitted at default value 8 per Table 294",
    );
    // /E default is /Raw ⇒ omitted at the default value.
    assert!(
        !pdf_str.contains("/E /Raw"),
        "/E should be omitted at default /Raw per Table 294",
    );

    // Round-209 annotation-reader round-trip — the Sound kind reports
    // the same icon and a stream ObjectId we can correlate with the
    // emitted stream.
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 1, "exactly one annotation expected");
    match &anns[0].kind {
        AnnotationKind::Sound { icon, sound } => {
            assert_eq!(icon, "Speaker", "icon should default to /Speaker");
            assert!(sound.is_some(), "/Sound should be an indirect reference");
        }
        other => panic!("expected Sound, got {other:?}"),
    }
}

/// Sound annotation with a non-default `/Mic` icon and an 8 kHz µ-law
/// configuration matching the §13.3 portability guidance for
/// telephony-style recordings.
#[test]
fn sound_mulaw_8khz_mono_emits_custom_fields() {
    let scene = one_page_scene();
    let samples = vec![0xFFu8; 64];
    let annot = default_annot(
        [50.0, 50.0, 70.0, 70.0],
        WriterAnnotationKind::Sound {
            icon: Some("Mic".into()),
            sampling_rate: 8000.0,
            channels: 1,
            bits_per_sample: 8,
            encoding: SoundEncoding::MuLaw,
            sound_samples: samples.clone(),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let pdf_str = String::from_utf8_lossy(&pdf);

    // Custom icon emitted as a Name.
    assert!(pdf_str.contains("/Name /Mic"), "/Name /Mic not emitted");
    // /E /muLaw emitted (non-default).
    assert!(
        pdf_str.contains("/E /muLaw"),
        "/E /muLaw should be emitted on non-default encoding",
    );
    // §13.3 portability guidance — /R 8000 for muLaw.
    assert!(
        pdf_str.contains("/R 8000"),
        "/R 8000 not emitted for µ-law portability sample rate",
    );

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Sound { icon, sound } => {
            assert_eq!(icon, "Mic");
            assert!(sound.is_some());
        }
        other => panic!("expected Sound, got {other:?}"),
    }
}

/// Sound annotation with stereo 16-bit signed samples — exercises the
/// non-default `/C 2`, `/B 16`, and `/E /Signed` entries.
#[test]
fn sound_stereo_16bit_signed_emits_all_explicit_entries() {
    let scene = one_page_scene();
    // 4 stereo frames × 2 channels × 2 bytes = 16 bytes. Big-endian
    // per the §13.3 packing rule (caller responsibility).
    let samples: Vec<u8> = vec![
        0x12, 0x34, 0x56, 0x78, // L sample 0, R sample 0
        0x00, 0x00, 0x7F, 0xFF, // L sample 1, R sample 1
        0x80, 0x00, 0x00, 0x00, // L sample 2, R sample 2
        0xFE, 0xDC, 0xBA, 0x98, // L sample 3, R sample 3
    ];
    let annot = default_annot(
        [100.0, 100.0, 120.0, 120.0],
        WriterAnnotationKind::Sound {
            icon: None,
            sampling_rate: 22050.0,
            channels: 2,
            bits_per_sample: 16,
            encoding: SoundEncoding::Signed,
            sound_samples: samples.clone(),
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let pdf_str = String::from_utf8_lossy(&pdf);

    // All three non-default entries present.
    assert!(pdf_str.contains("/C 2"), "/C 2 not emitted for stereo");
    assert!(
        pdf_str.contains("/B 16"),
        "/B 16 not emitted for 16-bit samples",
    );
    assert!(
        pdf_str.contains("/E /Signed"),
        "/E /Signed not emitted for two's-complement encoding",
    );

    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let anns = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(anns.len(), 1);
    match &anns[0].kind {
        AnnotationKind::Sound { sound, .. } => {
            assert!(sound.is_some(), "/Sound stream ref should be preserved");
        }
        other => panic!("expected Sound, got {other:?}"),
    }
}

/// Sound annotation with A-law encoding — exercises the third
/// non-Raw `/E` branch.
#[test]
fn sound_alaw_emits_e_alaw_name() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 10.0, 30.0, 30.0],
        WriterAnnotationKind::Sound {
            icon: None,
            sampling_rate: 8000.0,
            channels: 1,
            bits_per_sample: 8,
            encoding: SoundEncoding::ALaw,
            sound_samples: vec![0x55; 8],
        },
    );
    let pdf = write_pdf_with_annotations(&scene, &[annot]).expect("write");
    let pdf_str = String::from_utf8_lossy(&pdf);
    assert!(
        pdf_str.contains("/E /ALaw"),
        "/E /ALaw not emitted on ALaw encoding",
    );
}

// ────────────────────────────────────────────────────────────────────
// Validation rejects.
// ────────────────────────────────────────────────────────────────────

/// §13.3 /R must be positive — a zero or negative rate is rejected
/// before any wire bytes are emitted.
#[test]
fn sound_zero_sample_rate_rejected() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 10.0, 30.0, 30.0],
        WriterAnnotationKind::Sound {
            icon: None,
            sampling_rate: 0.0,
            channels: 1,
            bits_per_sample: 8,
            encoding: SoundEncoding::Raw,
            sound_samples: vec![0; 4],
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot]).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("sampling_rate"), "msg mentions rate: {msg}");
}

/// §13.3 /C must be ≥ 1 — a zero-channel stream is rejected.
#[test]
fn sound_zero_channels_rejected() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 10.0, 30.0, 30.0],
        WriterAnnotationKind::Sound {
            icon: None,
            sampling_rate: 8000.0,
            channels: 0,
            bits_per_sample: 8,
            encoding: SoundEncoding::Raw,
            sound_samples: vec![0; 4],
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot]).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("channels"), "msg mentions channels: {msg}");
}

/// §13.3 /B must be ≥ 1 — a zero-bit-per-sample stream is rejected.
#[test]
fn sound_zero_bits_rejected() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 10.0, 30.0, 30.0],
        WriterAnnotationKind::Sound {
            icon: None,
            sampling_rate: 8000.0,
            channels: 1,
            bits_per_sample: 0,
            encoding: SoundEncoding::Raw,
            sound_samples: vec![0; 4],
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot]).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("bits_per_sample"), "msg mentions bits: {msg}");
}

/// §13.3 /R must be a finite positive value — NaN is rejected (a
/// NaN /R would serialise as `nan` and break any conforming reader's
/// scalar parser).
#[test]
fn sound_nan_sample_rate_rejected() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 10.0, 30.0, 30.0],
        WriterAnnotationKind::Sound {
            icon: None,
            sampling_rate: f32::NAN,
            channels: 1,
            bits_per_sample: 8,
            encoding: SoundEncoding::Raw,
            sound_samples: vec![0; 4],
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot]).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("sampling_rate"), "msg mentions rate: {msg}");
}

/// §12.5.6.16 /Sound is the required carrier of the playable sample
/// data — an empty buffer is rejected.
#[test]
fn sound_empty_samples_rejected() {
    let scene = one_page_scene();
    let annot = default_annot(
        [10.0, 10.0, 30.0, 30.0],
        WriterAnnotationKind::Sound {
            icon: None,
            sampling_rate: 8000.0,
            channels: 1,
            bits_per_sample: 8,
            encoding: SoundEncoding::Raw,
            sound_samples: Vec::new(),
        },
    );
    let err = write_pdf_with_annotations(&scene, &[annot]).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("sound_samples"), "msg mentions buffer: {msg}");
}

// ────────────────────────────────────────────────────────────────────
// Cross-subtype composite: Sound + FreeText + FileAttachment + Text
// on one page. Confirms the writer's pre-pass loop handles the Sound
// branch alongside the FileAttachment branch correctly, and the
// round-209 reader enumerates every annotation in order.
// ────────────────────────────────────────────────────────────────────

#[test]
fn sound_cross_subtype_composite_roundtrips() {
    let scene = one_page_scene();
    let annots = vec![
        // Sticky note.
        default_annot(
            [10.0, 10.0, 30.0, 30.0],
            WriterAnnotationKind::Text {
                contents: "see audio".into(),
                icon: None,
                open: false,
            },
        ),
        // Sound annotation — default Speaker.
        default_annot(
            [40.0, 40.0, 60.0, 60.0],
            WriterAnnotationKind::Sound {
                icon: None,
                sampling_rate: 11025.0,
                channels: 1,
                bits_per_sample: 8,
                encoding: SoundEncoding::Raw,
                sound_samples: vec![0x80; 32],
            },
        ),
        // File attachment — exercises the other pre-pass branch.
        default_annot(
            [70.0, 70.0, 90.0, 90.0],
            WriterAnnotationKind::FileAttachment {
                icon: None,
                file_name: "transcript.txt".into(),
                file_bytes: b"hello".to_vec(),
                mime_type: None,
            },
        ),
    ];
    let pdf = write_pdf_with_annotations(&scene, &annots).expect("write");
    let mut r = DocumentReader::open(&pdf).expect("reader open");
    let read = read_pdf_annotations(&mut r).expect("read annotations");
    assert_eq!(read.len(), 3, "expected 3 annotations from composite");
    // Indices: 0 = Text, 1 = Sound, 2 = FileAttachment.
    assert!(matches!(&read[0].kind, AnnotationKind::Text { .. }));
    match &read[1].kind {
        AnnotationKind::Sound { icon, sound } => {
            assert_eq!(icon, "Speaker");
            assert!(sound.is_some());
        }
        other => panic!("expected Sound at index 1, got {other:?}"),
    }
    assert!(matches!(
        &read[2].kind,
        AnnotationKind::FileAttachment { .. }
    ));
}
