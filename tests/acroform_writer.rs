//! Round-31 — AcroForm interactive-widget writer end-to-end tests
//! (ISO 32000-1 §12.7).
//!
//! Validates that [`oxideav_pdf::write_pdf_with_form`] emits a PDF
//! whose Catalog carries `/AcroForm`, whose `/Fields` array lists each
//! top-level field, and whose page-level `/Annots` carries the
//! matching widget annotations for every field type.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::pubsec::der;
use oxideav_pdf::pubsec::verify::{
    rsa_pubkey_to_pkcs1_der, verify_signature, AttachedContent, OID_RSA_ENCRYPTION,
};
use oxideav_pdf::pubsec::x509::Certificate;
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    pdf_signed_bytes, write_pdf_with_form, AnnotationKind, FieldJustification, FormField,
    FormFieldCheckbox, FormFieldChoice, FormFieldRadioGroup, FormFieldSignature, FormFieldText,
    RadioOption, RsaPkcs1v15Sha256Signer, SignerIdentity,
};
use oxideav_scene::{Page, Scene};

fn one_page_scene() -> Scene {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(90.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(90.0, 90.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 200.0,
        height: 200.0,
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
    let mut page = Page::new(200.0, 200.0);
    page.content = frame;
    Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    }
}

/// Build a minimal X.509 v3 Certificate suitable for `Certificate::parse`.
/// Same approach as `sig_writer_round30.rs::build_x509_cert`.
fn build_rsa_test_cert(issuer_der: &[u8], serial: &[u8], pub_key: &rsa::RsaPublicKey) -> Vec<u8> {
    let spki_bits = rsa_pubkey_to_pkcs1_der(pub_key);
    let version = der::write_tlv(
        der::Class::ContextSpecific,
        true,
        0,
        &der::write_integer_u64(2),
    );
    let serial_field = der::write_integer_bytes(serial);
    let sig_alg = der::write_sequence(&{
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 1, 11]);
        b.extend_from_slice(&der::write_null());
        b
    });
    let nb = der::write_tlv(der::Class::Universal, false, 24, b"20000101000000Z");
    let na = der::write_tlv(der::Class::Universal, false, 24, b"99991231235959Z");
    let validity = der::write_sequence(&{
        let mut b = nb.clone();
        b.extend_from_slice(&na);
        b
    });
    let spki_alg = der::write_sequence(&{
        let mut b = der::write_oid(&OID_RSA_ENCRYPTION);
        b.extend_from_slice(&der::write_null());
        b
    });
    let spki_bs = der::write_tlv(der::Class::Universal, false, 3, &{
        let mut b = vec![0u8];
        b.extend_from_slice(&spki_bits);
        b
    });
    let spki = der::write_sequence(&{
        let mut b = spki_alg;
        b.extend_from_slice(&spki_bs);
        b
    });
    let tbs = der::write_sequence(&{
        let mut b = version;
        b.extend_from_slice(&serial_field);
        b.extend_from_slice(&sig_alg);
        b.extend_from_slice(issuer_der);
        b.extend_from_slice(&validity);
        b.extend_from_slice(issuer_der);
        b.extend_from_slice(&spki);
        b
    });
    let outer_sig_alg = der::write_sequence(&{
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 1, 11]);
        b.extend_from_slice(&der::write_null());
        b
    });
    let outer_sig_value = der::write_tlv(der::Class::Universal, false, 3, &[0u8, 0u8]);
    der::write_sequence(&{
        let mut b = tbs;
        b.extend_from_slice(&outer_sig_alg);
        b.extend_from_slice(&outer_sig_value);
        b
    })
}

#[test]
fn text_field_emits_valid_acroform() {
    let scene = one_page_scene();
    let field = FormField::Text(FormFieldText {
        name: "FullName".into(),
        rect: [20.0, 150.0, 180.0, 170.0],
        page_index: 0,
        value: Some("Hello World".into()),
        max_length: Some(64),
        multi_line: false,
        justification: FieldJustification::Left,
        default_appearance: None,
    });

    let pdf = write_pdf_with_form(&scene, &[field]).expect("write text field");
    assert!(pdf.starts_with(b"%PDF-"));
    assert!(pdf.ends_with(b"%%EOF\n"));

    // Bytes-level sanity: the field type and value must appear.
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/AcroForm"), "expected /AcroForm in {s}");
    assert!(s.contains("/FT /Tx"), "expected /FT /Tx");
    assert!(s.contains("/T (FullName)"), "expected /T (FullName)");
    assert!(s.contains("/MaxLen 64"), "expected /MaxLen 64");

    // Reader-side: the widget annotation must round-trip.
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let annots = reader.annotations().expect("annotations");
    assert_eq!(annots.len(), 1, "exactly one Widget annotation");
    let a = &annots[0];
    match &a.kind {
        AnnotationKind::Widget {
            field_type,
            field_name,
            value,
        } => {
            assert_eq!(field_type.as_deref(), Some("Tx"));
            assert_eq!(field_name.as_deref(), Some("FullName"));
            assert_eq!(value.as_deref(), Some("Hello World"));
        }
        other => panic!("expected Widget, got {other:?}"),
    }
}

#[test]
fn checkbox_in_checked_state_renders() {
    let scene = one_page_scene();
    let field = FormField::Checkbox(FormFieldCheckbox {
        name: "Subscribe".into(),
        rect: [20.0, 100.0, 40.0, 120.0],
        page_index: 0,
        checked: true,
        default_appearance: None,
    });

    let pdf = write_pdf_with_form(&scene, &[field]).expect("write checkbox");
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/FT /Btn"), "expected /FT /Btn");
    assert!(
        s.contains("/V /Yes"),
        "expected /V /Yes for checked checkbox"
    );
    assert!(s.contains("/AS /Yes"), "expected /AS /Yes");

    // Reader round-trip.
    let mut reader = DocumentReader::open(&pdf).expect("open");
    let annots = reader.annotations().expect("annotations");
    assert_eq!(annots.len(), 1);
    match &annots[0].kind {
        AnnotationKind::Widget {
            field_type, value, ..
        } => {
            assert_eq!(field_type.as_deref(), Some("Btn"));
            assert_eq!(
                value.as_deref(),
                Some("Yes"),
                "checked checkbox round-trips with /V == /Yes"
            );
        }
        other => panic!("expected Widget, got {other:?}"),
    }
}

#[test]
fn checkbox_in_unchecked_state_renders() {
    let scene = one_page_scene();
    let field = FormField::Checkbox(FormFieldCheckbox {
        name: "Optin".into(),
        rect: [20.0, 100.0, 40.0, 120.0],
        page_index: 0,
        checked: false,
        default_appearance: None,
    });
    let pdf = write_pdf_with_form(&scene, &[field]).expect("write");
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/V /Off"));
    assert!(s.contains("/AS /Off"));
}

#[test]
fn radio_group_emits_consistent_state() {
    let scene = one_page_scene();
    let field = FormField::RadioGroup(FormFieldRadioGroup {
        name: "Color".into(),
        options: vec![
            RadioOption {
                export_value: "Red".into(),
                rect: [20.0, 80.0, 40.0, 100.0],
                page_index: 0,
            },
            RadioOption {
                export_value: "Green".into(),
                rect: [50.0, 80.0, 70.0, 100.0],
                page_index: 0,
            },
            RadioOption {
                export_value: "Blue".into(),
                rect: [80.0, 80.0, 100.0, 100.0],
                page_index: 0,
            },
        ],
        value: Some("Green".into()),
    });

    let pdf = write_pdf_with_form(&scene, &[field]).expect("write radio group");
    let s = String::from_utf8_lossy(&pdf);
    // Aggregate field must carry /V /Green.
    assert!(s.contains("/V /Green"), "aggregate /V /Green");
    // Exactly one kid should have /AS /Green; the other two /AS /Off.
    let green_count = s.matches("/AS /Green").count();
    let off_count = s.matches("/AS /Off").count();
    assert_eq!(green_count, 1, "exactly one kid /AS /Green: {s}");
    assert_eq!(off_count, 2, "two kids /AS /Off");
}

#[test]
fn choice_field_round_trips() {
    let scene = one_page_scene();
    let field = FormField::Choice(FormFieldChoice {
        name: "Country".into(),
        rect: [20.0, 50.0, 180.0, 70.0],
        page_index: 0,
        options: vec!["Japan".into(), "France".into(), "USA".into()],
        value: Some("France".into()),
        combo_box: true,
        default_appearance: None,
    });
    let pdf = write_pdf_with_form(&scene, &[field]).expect("write choice");
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/FT /Ch"));
    assert!(s.contains("/Opt"));
    assert!(s.contains("(Japan)"));
    assert!(s.contains("(France)"));
    assert!(s.contains("(USA)"));
    assert!(s.contains("/V (France)"));
    // /Ff bit 17 = combo (0x20000 = 131072).
    assert!(s.contains("/Ff 131072"));
}

#[test]
fn signature_field_combines_with_sig_writer() {
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R31 AcroForm");
    let serial = vec![0x31, 0x01];
    let cert_der = build_rsa_test_cert(&issuer_der, &serial, &pub_key);
    let identity =
        SignerIdentity::from_signer_cert_der(cert_der.clone()).expect("identity from cert");

    let signer = RsaPkcs1v15Sha256Signer::new(priv_key);
    let scene = one_page_scene();
    let field = FormField::Signature(FormFieldSignature {
        name: "Signature1".into(),
        rect: [20.0, 20.0, 180.0, 40.0],
        page_index: 0,
        signer: Box::new(signer),
        identity,
    });

    let pdf = write_pdf_with_form(&scene, &[field]).expect("sign through form");
    assert!(pdf.starts_with(b"%PDF-"));
    assert!(pdf.ends_with(b"%%EOF\n"));

    // Open with the round-21/27 reader.
    let mut reader = DocumentReader::open(&pdf).expect("open signed AcroForm PDF");
    let sigs = reader.signatures().expect("walk signatures");
    assert_eq!(sigs.len(), 1, "exactly one /FT /Sig field");
    let sig = &sigs[0];
    assert_eq!(sig.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
    assert!(sig.is_cms_detached());

    let sd = sig.signed_data.as_ref().expect("CMS SignedData parsed");
    assert_eq!(sd.signer_infos.len(), 1);
    let signer_info = &sd.signer_infos[0];

    let signed = pdf_signed_bytes(&pdf, &sig.byte_range).expect("signed bytes");
    let cert = Certificate::parse(&cert_der).expect("parse signer cert");
    let pool = std::slice::from_ref(&cert);
    let ok = verify_signature(signer_info, pool, AttachedContent::External(&signed))
        .expect("verify dispatch");
    assert!(ok, "AcroForm-embedded signature must verify");
}

#[test]
fn rejects_field_on_out_of_range_page() {
    let scene = one_page_scene();
    let field = FormField::Text(FormFieldText {
        name: "Stray".into(),
        rect: [0.0, 0.0, 10.0, 10.0],
        page_index: 9,
        value: None,
        max_length: None,
        multi_line: false,
        justification: FieldJustification::Left,
        default_appearance: None,
    });
    let err = write_pdf_with_form(&scene, &[field]).expect_err("page out of range must error");
    assert!(
        format!("{err}").contains("out of range"),
        "expected range error, got: {err}"
    );
}

#[test]
fn rejects_multiple_signature_fields() {
    fn mk_sig() -> FormFieldSignature {
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let issuer_der = der::write_sequence(b"O=R31 dual");
        let serial = vec![0x31, 0x02];
        let cert_der = build_rsa_test_cert(&issuer_der, &serial, &pub_key);
        let identity = SignerIdentity::from_signer_cert_der(cert_der).unwrap();
        FormFieldSignature {
            name: "Sig".into(),
            rect: [0.0, 0.0, 10.0, 10.0],
            page_index: 0,
            signer: Box::new(RsaPkcs1v15Sha256Signer::new(priv_key)),
            identity,
        }
    }
    let scene = one_page_scene();
    let fields = vec![
        FormField::Signature(mk_sig()),
        FormField::Signature(mk_sig()),
    ];
    let err = write_pdf_with_form(&scene, &fields).expect_err("two sigs must error");
    assert!(format!("{err}").contains("only one"));
}

#[test]
fn qpdf_check_accepts_text_and_checkbox_form() {
    if !tool_exists("qpdf") {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    let scene = one_page_scene();
    let fields = vec![
        FormField::Text(FormFieldText {
            name: "Name".into(),
            rect: [20.0, 150.0, 180.0, 170.0],
            page_index: 0,
            value: Some("Jane".into()),
            max_length: None,
            multi_line: false,
            justification: FieldJustification::Left,
            default_appearance: None,
        }),
        FormField::Checkbox(FormFieldCheckbox {
            name: "Accept".into(),
            rect: [20.0, 100.0, 40.0, 120.0],
            page_index: 0,
            checked: true,
            default_appearance: None,
        }),
    ];
    let pdf = write_pdf_with_form(&scene, &fields).expect("write");
    let path = write_temp_pdf(&pdf, "round31-acroform");
    let path_str = path.to_string_lossy().to_string();
    let output = std::process::Command::new("qpdf")
        .args(["--check", &path_str])
        .output()
        .expect("spawn qpdf");
    let _ = std::fs::remove_file(&path);
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        code == 0 || code == 3,
        "qpdf --check exit code {code}: {stderr}\n{stdout}"
    );
}

fn tool_exists(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn write_temp_pdf(pdf: &[u8], stem: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("oxideav-pdf-{stem}-{pid}-{nanos}.pdf"));
    std::fs::write(&path, pdf).expect("temp pdf write");
    path
}
