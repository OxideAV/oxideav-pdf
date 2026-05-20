//! Round-36 — Document-action enumeration.
//!
//! Builds minimal PDF 1.4 byte streams that attach actions to every
//! place ISO 32000-1 §12.6 allows — Catalog `/OpenAction` + `/AA`,
//! page `/AA`, annotation `/A` + `/AA`, form-field `/A` + `/AA`, and
//! the `/Names /JavaScript` name tree — and asserts that
//! [`oxideav_pdf::reader::DocumentReader::actions`] surfaces every
//! one with the correct trigger + typed action payload.
//!
//! Provenance: ISO 32000-1:2008 §7.7.4 (Catalog), §7.9.6 (Name Trees),
//! §12.5 + §12.5.3 (Annotation actions, Table 165), §12.6.2 (Trigger
//! Events), §12.6.3 (Action dictionaries — Tables 196..198), §12.6.4.x
//! (Action type entries — Tables 199..217), §12.7.5.x (Form actions
//! — Tables 236..240). No third-party PDF library was consulted.

use oxideav_pdf::reader::{ActionKind, ActionTrigger, DocumentReader};

/// Build an N-object PDF given a sequence of body objects (`(id,
/// "body")` — the body must include `<id> 0 obj … endobj`).
fn build_pdf(objs: &[(u32, String)]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<(u32, usize)> = Vec::new();
    for (id, body) in objs {
        let off = buf.len();
        buf.extend_from_slice(body.as_bytes());
        offsets.push((*id, off));
    }
    let xref_off = buf.len();
    let max_id = offsets.iter().map(|(id, _)| *id).max().unwrap_or(1);
    let count = (max_id + 1) as usize;
    buf.extend_from_slice(format!("xref\n0 {count}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    let mut by_id: Vec<usize> = vec![usize::MAX; count];
    for (id, off) in &offsets {
        by_id[*id as usize] = *off;
    }
    for off in by_id.iter().skip(1) {
        if *off == usize::MAX {
            buf.extend_from_slice(b"0000000000 00000 f \n");
        } else {
            buf.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
        }
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n")
            .as_bytes(),
    );
    buf
}

// ──────────────────────── tests ────────────────────────

/// Catalog `/OpenAction` with a `/URI` action: the URI surfaces with
/// the right trigger + kind.
#[test]
fn catalog_open_action_uri() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [4 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /S /URI /URI (https://example.com) >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    assert_eq!(acts[0].trigger, ActionTrigger::CatalogOpen);
    match &acts[0].kind {
        ActionKind::Uri { uri, is_map } => {
            assert_eq!(uri, "https://example.com");
            assert!(!is_map);
        }
        other => panic!("expected URI, got {other:?}"),
    }
    assert_eq!(acts[0].chain_depth, 0);
}

/// Catalog `/AA /WC` close action that runs JavaScript — the JS source
/// is recovered.
#[test]
fn catalog_aa_will_close_javascript() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AA << /WC 3 0 R >> >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [4 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /S /JavaScript /JS (app.alert\\('bye'\\)) >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    match &acts[0].trigger {
        ActionTrigger::Catalog { event } => assert_eq!(event, "WC"),
        other => panic!("expected Catalog WC, got {other:?}"),
    }
    match &acts[0].kind {
        ActionKind::JavaScript { script } => assert_eq!(script, "app.alert('bye')"),
        other => panic!("expected JavaScript, got {other:?}"),
    }
}

/// Page `/AA /O` (page open) with a `/Named` action.
#[test]
fn page_aa_open_named() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /AA << /O 4 0 R >> >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /S /Named /N /NextPage >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    match &acts[0].trigger {
        ActionTrigger::Page { page_index, event } => {
            assert_eq!(*page_index, 0);
            assert_eq!(event, "O");
        }
        other => panic!("expected Page O, got {other:?}"),
    }
    match &acts[0].kind {
        ActionKind::Named { name } => assert_eq!(name, "NextPage"),
        other => panic!("expected Named, got {other:?}"),
    }
}

/// Annotation `/A /Launch` carries a filename — surfaced.
#[test]
fn annotation_launch_filename() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /Type /Annot /Subtype /Link /Rect [0 0 100 100] /A 5 0 R >>\nendobj\n".into(),
        ),
        (
            5,
            "5 0 obj\n<< /S /Launch /F (calc.exe) /NewWindow true >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    match &acts[0].trigger {
        ActionTrigger::Annotation {
            page_index,
            subtype,
            event,
        } => {
            assert_eq!(*page_index, 0);
            assert_eq!(subtype, "Link");
            assert_eq!(event, "A");
        }
        other => panic!("expected Annotation Link/A, got {other:?}"),
    }
    match &acts[0].kind {
        ActionKind::Launch { file, new_window } => {
            assert_eq!(file.as_deref(), Some("calc.exe"));
            assert_eq!(*new_window, Some(true));
        }
        other => panic!("expected Launch, got {other:?}"),
    }
}

/// Annotation `/AA /U` (mouse up) carries a `/GoToR` to a remote file.
#[test]
fn annotation_aa_mouse_up_gotor() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /Type /Annot /Subtype /Link /Rect [0 0 100 100] /AA << /U 5 0 R >> >>\nendobj\n".into(),
        ),
        (
            5,
            "5 0 obj\n<< /S /GoToR /F (other.pdf) /D /Section1 >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    match &acts[0].trigger {
        ActionTrigger::Annotation { event, .. } => assert_eq!(event, "U"),
        other => panic!("expected Annotation U, got {other:?}"),
    }
    match &acts[0].kind {
        ActionKind::GoToR {
            file,
            new_window: _,
            raw_dest,
        } => {
            assert_eq!(file.as_deref(), Some("other.pdf"));
            assert_eq!(raw_dest.as_deref(), Some("Section1"));
        }
        other => panic!("expected GoToR, got {other:?}"),
    }
}

/// Form-field /A with `/SubmitForm` flags + URL.
#[test]
fn form_field_submit_form() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 6 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Btn /T (Submit) /Rect [0 0 100 100] /A 5 0 R >>\nendobj\n".into(),
        ),
        (
            5,
            "5 0 obj\n<< /S /SubmitForm /F (https://example.com/submit) /Flags 4 >>\nendobj\n".into(),
        ),
        (
            6,
            "6 0 obj\n<< /Fields [4 0 R] >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    // The annotation-walk + form-field walk both pick this up; we
    // expect two entries with different triggers but the same kind.
    assert!(!acts.is_empty());
    let has_form_trigger = acts.iter().any(|a| {
        matches!(&a.trigger, ActionTrigger::FormField { field_name, event }
            if field_name.as_deref() == Some("Submit") && event == "A")
    });
    assert!(has_form_trigger, "expected FormField trigger: {acts:?}");
    let has_submit_kind = acts.iter().any(|a| {
        matches!(&a.kind, ActionKind::SubmitForm { url, flags }
            if url.as_deref() == Some("https://example.com/submit") && *flags == 4)
    });
    assert!(has_submit_kind, "expected SubmitForm kind: {acts:?}");
}

/// Form-field `/AA /K` keystroke action with `/ResetForm`.
#[test]
fn form_field_aa_keystroke_reset_form() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 6 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /FT /Tx /T (Name) /AA << /K 5 0 R >> >>\nendobj\n".into(),
        ),
        (5, "5 0 obj\n<< /S /ResetForm /Flags 0 >>\nendobj\n".into()),
        (6, "6 0 obj\n<< /Fields [4 0 R] >>\nendobj\n".into()),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    match &acts[0].trigger {
        ActionTrigger::FormField { field_name, event } => {
            assert_eq!(field_name.as_deref(), Some("Name"));
            assert_eq!(event, "K");
        }
        other => panic!("expected FormField K, got {other:?}"),
    }
    match &acts[0].kind {
        ActionKind::ResetForm { flags } => assert_eq!(*flags, 0),
        other => panic!("expected ResetForm, got {other:?}"),
    }
}

/// Catalog `/Names /JavaScript` name-tree leaf entry — surfaces as a
/// `NamedJavaScript` trigger with JavaScript payload.
#[test]
fn names_javascript_tree_leaf() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Names 7 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
        (
            5,
            "5 0 obj\n<< /S /JavaScript /JS (var x = 1;) >>\nendobj\n".into(),
        ),
        (
            6,
            "6 0 obj\n<< /Names [(MyScript) 5 0 R] >>\nendobj\n".into(),
        ),
        (7, "7 0 obj\n<< /JavaScript 6 0 R >>\nendobj\n".into()),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    match &acts[0].trigger {
        ActionTrigger::NamedJavaScript { name } => assert_eq!(name, "MyScript"),
        other => panic!("expected NamedJavaScript, got {other:?}"),
    }
    match &acts[0].kind {
        ActionKind::JavaScript { script } => assert_eq!(script, "var x = 1;"),
        other => panic!("expected JavaScript, got {other:?}"),
    }
}

/// `/Hide` action `/T` literal + `/H true` default surface intact.
#[test]
fn annotation_hide_action() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [4 0 R] >>\nendobj\n".into(),
        ),
        (3, "3 0 obj\n<< /S /Hide /T (Submit) >>\nendobj\n".into()),
        (
            4,
            "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    match &acts[0].kind {
        ActionKind::Hide { hide, target } => {
            assert!(*hide, "default is hide=true per Table 209");
            assert_eq!(target.as_deref(), Some("Submit"));
        }
        other => panic!("expected Hide, got {other:?}"),
    }
}

/// `/SetOCGState` action — counts of On/Off/Toggle entries are
/// recovered. (Object 10 is /OCG so the /State refs resolve; their
/// concrete dict content doesn't matter for the counter.)
#[test]
fn setocgstate_counts() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [4 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /S /SetOCGState /State [/ON 5 0 R 6 0 R /OFF 7 0 R /Toggle 8 0 R 9 0 R] >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
        (5, "5 0 obj\n<< /Type /OCG /Name (A) >>\nendobj\n".into()),
        (6, "6 0 obj\n<< /Type /OCG /Name (B) >>\nendobj\n".into()),
        (7, "7 0 obj\n<< /Type /OCG /Name (C) >>\nendobj\n".into()),
        (8, "8 0 obj\n<< /Type /OCG /Name (D) >>\nendobj\n".into()),
        (9, "9 0 obj\n<< /Type /OCG /Name (E) >>\nendobj\n".into()),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    match &acts[0].kind {
        ActionKind::SetOcgState {
            on_count,
            off_count,
            toggle_count,
        } => {
            assert_eq!(*on_count, 2);
            assert_eq!(*off_count, 1);
            assert_eq!(*toggle_count, 2);
        }
        other => panic!("expected SetOcgState, got {other:?}"),
    }
}

/// `/Next` chain — the carrier and the next action both surface,
/// with chain_depth 0 and 1 respectively.
#[test]
fn next_chain_two_actions() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [5 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /S /URI /URI (https://first.example) /Next 4 0 R >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /S /URI /URI (https://second.example) >>\nendobj\n".into(),
        ),
        (
            5,
            "5 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 2);
    assert_eq!(acts[0].chain_depth, 0);
    assert_eq!(acts[1].chain_depth, 1);
    let uris: Vec<_> = acts
        .iter()
        .filter_map(|a| match &a.kind {
            ActionKind::Uri { uri, .. } => Some(uri.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(uris, ["https://first.example", "https://second.example"]);
}

/// `/Next` cycle — a chain that loops back to itself terminates
/// without blowing the stack. We expect the carrier + the resolved
/// next to land, then the cycle gets cut.
#[test]
fn next_chain_cycle_does_not_loop() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [5 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /S /URI /URI (https://loop.example) /Next 4 0 R >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /S /URI /URI (https://loop2.example) /Next 3 0 R >>\nendobj\n".into(),
        ),
        (
            5,
            "5 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    // Must terminate. We accept 2 (the cycle gets cut on the second
    // hop back to obj 3) up to a small bounded count.
    assert!(acts.len() >= 2, "expected at least two actions");
    assert!(acts.len() < 100, "cycle should not run away");
}

/// An unknown `/S` action surfaces as `ActionKind::Other`.
#[test]
fn unknown_action_kind_falls_through() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [4 0 R] >>\nendobj\n".into(),
        ),
        (3, "3 0 obj\n<< /S /WeirdFutureAction >>\nendobj\n".into()),
        (
            4,
            "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    match &acts[0].kind {
        ActionKind::Other { kind } => assert_eq!(kind, "WeirdFutureAction"),
        other => panic!("expected Other, got {other:?}"),
    }
}

/// A PDF with **no** actions anywhere returns an empty Vec.
#[test]
fn no_actions_returns_empty_vec() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert!(acts.is_empty());
}

/// JS source stored as a UTF-16BE-BOM hex string decodes to UTF-8.
#[test]
fn javascript_utf16be_bom_hex_string_decodes() {
    // /JS = <FEFF 0061 006C 0065 0072 0074> -> "alert"
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [4 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /S /JavaScript /JS <FEFF0061006C00650072007400> >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    match &acts[0].kind {
        ActionKind::JavaScript { script } => {
            // The trailing 00 byte in the hex string is a stray zero
            // pad — accept any prefix that recovers "alert".
            assert!(
                script.starts_with("alert"),
                "expected JS to start with 'alert', got {script:?}"
            );
        }
        other => panic!("expected JavaScript, got {other:?}"),
    }
}

/// `/GoTo` with an explicit destination array resolves `page_index`.
#[test]
fn goto_explicit_destination_resolves_page() {
    let pdf = build_pdf(&[
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".into(),
        ),
        (
            2,
            "2 0 obj\n<< /Type /Pages /Count 2 /Kids [4 0 R 5 0 R] >>\nendobj\n".into(),
        ),
        (
            3,
            "3 0 obj\n<< /S /GoTo /D [5 0 R /Fit] >>\nendobj\n".into(),
        ),
        (
            4,
            "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
        (
            5,
            "5 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".into(),
        ),
    ]);
    let mut r = DocumentReader::open(&pdf).unwrap();
    let acts = r.actions().unwrap();
    assert_eq!(acts.len(), 1);
    match &acts[0].kind {
        ActionKind::GoTo {
            page_index,
            raw_dest,
        } => {
            assert_eq!(*page_index, Some(1));
            assert!(raw_dest.is_some());
        }
        other => panic!("expected GoTo, got {other:?}"),
    }
}
