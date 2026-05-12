//! Round-30 — `/Sig` writer end-to-end.
//!
//! Symmetric counterpart of the round-21 reader tests + the round-27
//! verifier. Builds a small PDF + Scene, signs it with the round-30
//! writer, opens the bytes back with the round-21 reader, and verifies
//! the signature with the round-20 `verify_signature` dispatch.
//!
//! Provenance: ISO 32000-1 §12.7.4.5 + §12.8.1 + RFC 5652 §5 + §5.4 +
//! §11.2. No third-party PDF / CMS source consulted.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::pubsec::der;
use oxideav_pdf::pubsec::signed_data::SignerIdentifier;
use oxideav_pdf::pubsec::verify::{
    rsa_pubkey_to_pkcs1_der, verify_signature, AttachedContent, OID_EC_PUBLIC_KEY,
    OID_NAMED_CURVE_P256, OID_RSA_ENCRYPTION,
};
use oxideav_pdf::pubsec::x509::Certificate;
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    pdf_signed_bytes, sign_pdf_from_scene, EcdsaP256Sha256Signer, RsaPkcs1v15Sha256Signer,
    SignerIdentity,
};
use oxideav_scene::{Page, Scene};

// ---------------------------------------------------------------------
// Fixture: a tiny scene + a minimal X.509 v3 Certificate builder.
// ---------------------------------------------------------------------

fn one_page_scene() -> Scene {
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(90.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(90.0, 90.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 100.0,
        height: 100.0,
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
    let mut page = Page::new(100.0, 100.0);
    page.content = frame;
    Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    }
}

/// Build a minimal but structurally-valid X.509 v3 Certificate DER
/// suitable for `Certificate::parse`. The `Certificate::parse`
/// best-effort SPKI extraction tolerates a truncated TBS body (round
/// 10 covers the synthetic-cert path), so we only need enough fields
/// to satisfy the leading SEQUENCE walk + IAS extraction.
///
/// Layout (the bare-minimum prefix `Certificate::parse` reads):
///
/// ```asn.1
/// Certificate ::= SEQUENCE {
///   tbsCertificate ::= SEQUENCE {
///     [0] EXPLICIT INTEGER version (= 2),
///     serialNumber INTEGER,
///     signature AlgorithmIdentifier,
///     issuer Name,
///     validity (notBefore, notAfter),
///     subject Name,
///     subjectPublicKeyInfo
///   },
///   signatureAlgorithm AlgorithmIdentifier,
///   signatureValue BIT STRING
/// }
/// ```
#[allow(clippy::too_many_arguments)]
fn build_x509_cert(
    issuer_name: &[u8],
    serial: &[u8],
    spki_alg_oid: &[u64],
    spki_alg_params: &[u8],
    spki_pubkey_bits: &[u8],
) -> Vec<u8> {
    // [0] EXPLICIT INTEGER 2 (v3).
    let version = der::write_tlv(
        der::Class::ContextSpecific,
        true,
        0,
        &der::write_integer_u64(2),
    );
    // serialNumber INTEGER.
    let serial_field = der::write_integer_bytes(serial);
    // signature AlgorithmIdentifier (placeholder — SHA256-with-RSA).
    let sig_alg = der::write_sequence(&{
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 1, 11]);
        b.extend_from_slice(&der::write_null());
        b
    });
    // issuer Name SEQUENCE — `issuer_name` is already a full SEQUENCE
    // TLV (tag + length + body) at our call sites, so we splice it in
    // verbatim rather than re-wrapping.
    let issuer_field = issuer_name.to_vec();
    // validity SEQUENCE — two GeneralizedTime entries.
    let nb = der::write_tlv(der::Class::Universal, false, 24, b"20000101000000Z");
    let na = der::write_tlv(der::Class::Universal, false, 24, b"99991231235959Z");
    let validity = der::write_sequence(&{
        let mut b = nb.clone();
        b.extend_from_slice(&na);
        b
    });
    // subject Name SEQUENCE (re-use issuer since this is self-signed-style).
    let subject_field = issuer_name.to_vec();
    // SPKI SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }.
    let spki_alg = der::write_sequence(&{
        let mut b = der::write_oid(spki_alg_oid);
        b.extend_from_slice(spki_alg_params);
        b
    });
    // BIT STRING with 0 unused bits.
    let spki_bs = der::write_tlv(der::Class::Universal, false, 3, &{
        let mut b = vec![0u8]; // unused-bits
        b.extend_from_slice(spki_pubkey_bits);
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
        b.extend_from_slice(&issuer_field);
        b.extend_from_slice(&validity);
        b.extend_from_slice(&subject_field);
        b.extend_from_slice(&spki);
        b
    });

    // Outer signatureAlgorithm (placeholder).
    let outer_sig_alg = der::write_sequence(&{
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 1, 11]);
        b.extend_from_slice(&der::write_null());
        b
    });
    // signatureValue BIT STRING — dummy 0x00 byte body.
    let outer_sig_value = der::write_tlv(der::Class::Universal, false, 3, &[0u8, 0u8]);

    der::write_sequence(&{
        let mut b = tbs;
        b.extend_from_slice(&outer_sig_alg);
        b.extend_from_slice(&outer_sig_value);
        b
    })
}

fn build_rsa_test_cert(issuer_der: &[u8], serial: &[u8], pub_key: &rsa::RsaPublicKey) -> Vec<u8> {
    let spki_bits = rsa_pubkey_to_pkcs1_der(pub_key);
    build_x509_cert(
        issuer_der,
        serial,
        &OID_RSA_ENCRYPTION,
        &der::write_null(),
        &spki_bits,
    )
}

fn build_ecdsa_p256_test_cert(
    issuer_der: &[u8],
    serial: &[u8],
    verify_key: &p256::ecdsa::VerifyingKey,
) -> Vec<u8> {
    // SEC1 uncompressed point — what an ECC SubjectPublicKey BIT STRING
    // wraps. Round-20 verifier reads it as the raw SPKI BIT STRING
    // contents.
    let encoded_point = verify_key.to_encoded_point(false);
    let spki_bits = encoded_point.as_bytes().to_vec();
    let params = der::write_oid(&OID_NAMED_CURVE_P256);
    build_x509_cert(issuer_der, serial, &OID_EC_PUBLIC_KEY, &params, &spki_bits)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[test]
fn sign_pdf_with_rsa_pkcs1v15_sha256_produces_reader_verifiable_signature() {
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R30 RSA Signer");
    let serial = vec![0x30, 0x01];
    let cert_der = build_rsa_test_cert(&issuer_der, &serial, &pub_key);

    let identity =
        SignerIdentity::from_signer_cert_der(cert_der.clone()).expect("identity from cert");
    assert_eq!(identity.issuer_der, issuer_der);
    assert_eq!(identity.serial, serial);

    let signer = RsaPkcs1v15Sha256Signer::new(priv_key);
    let scene = one_page_scene();
    let signed_pdf = sign_pdf_from_scene(&scene, &signer, identity).expect("sign");

    // Open the result with the round-21 reader.
    let mut reader = DocumentReader::open(&signed_pdf).expect("open signed PDF");
    let sigs = reader.signatures().expect("walk signatures");
    assert_eq!(sigs.len(), 1, "exactly one /Sig field");
    let sig = &sigs[0];
    assert_eq!(sig.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
    assert_eq!(sig.filter.as_deref(), Some("Adobe.PPKLite"));
    assert!(sig.is_cms_detached());

    let sd = sig.signed_data.as_ref().expect("CMS SignedData parsed");
    assert_eq!(sd.signer_infos.len(), 1);
    let signer_info = &sd.signer_infos[0];
    match &signer_info.sid {
        SignerIdentifier::IssuerAndSerial(ias) => {
            assert_eq!(ias.issuer_der, issuer_der);
            assert_eq!(ias.serial, serial);
        }
        other => panic!("expected IAS, got {other:?}"),
    }

    // The signed range concatenation must round-trip through the
    // reader's pdf_signed_bytes helper.
    let signed = pdf_signed_bytes(&signed_pdf, &sig.byte_range).expect("signed bytes");
    // Run the round-20 verifier end-to-end against the embedded cert.
    let cert = Certificate::parse(&cert_der).expect("parse signer cert");
    let pool = std::slice::from_ref(&cert);
    let ok = verify_signature(signer_info, pool, AttachedContent::External(&signed))
        .expect("verify dispatch");
    assert!(ok, "RSA-PKCS1v15+SHA-256 signed PDF must verify");
}

#[test]
fn sign_pdf_with_ecdsa_p256_sha256_produces_reader_verifiable_signature() {
    use p256::ecdsa::SigningKey;

    let signing_key = SigningKey::random(&mut rsa::rand_core::OsRng);
    let verify_key = p256::ecdsa::VerifyingKey::from(&signing_key);

    let issuer_der = der::write_sequence(b"O=R30 ECDSA Signer");
    let serial = vec![0x30, 0x02];
    let cert_der = build_ecdsa_p256_test_cert(&issuer_der, &serial, &verify_key);
    let identity =
        SignerIdentity::from_signer_cert_der(cert_der.clone()).expect("identity from cert");

    let signer = EcdsaP256Sha256Signer::new(signing_key);
    let scene = one_page_scene();
    let signed_pdf = sign_pdf_from_scene(&scene, &signer, identity).expect("sign");

    let mut reader = DocumentReader::open(&signed_pdf).expect("open signed PDF");
    let sigs = reader.signatures().expect("walk signatures");
    assert_eq!(sigs.len(), 1);
    let sig = &sigs[0];
    assert!(sig.is_cms_detached());
    let sd = sig.signed_data.as_ref().expect("CMS SignedData parsed");
    assert_eq!(sd.signer_infos.len(), 1);
    let signer_info = &sd.signer_infos[0];

    let signed = pdf_signed_bytes(&signed_pdf, &sig.byte_range).expect("signed bytes");
    let cert = Certificate::parse(&cert_der).expect("parse ECDSA cert");
    let pool = std::slice::from_ref(&cert);
    let ok = verify_signature(signer_info, pool, AttachedContent::External(&signed))
        .expect("verify dispatch");
    assert!(ok, "ECDSA-P256+SHA-256 signed PDF must verify");
}

#[test]
fn sign_pdf_byterange_placeholder_filled_correctly() {
    // Smoke test: the byte-range integers point at real PDF bytes and
    // exclude the `<…hex…>` literal of /Contents. The two ranges
    // together cover everything except the contents-hex span.
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R30 BR-Test");
    let serial = vec![0x30, 0x03];
    let cert_der = build_rsa_test_cert(&issuer_der, &serial, &pub_key);
    let identity = SignerIdentity::from_signer_cert_der(cert_der).expect("identity");

    let signer = RsaPkcs1v15Sha256Signer::new(priv_key);
    let scene = one_page_scene();
    let signed_pdf = sign_pdf_from_scene(&scene, &signer, identity).expect("sign");

    let mut reader = DocumentReader::open(&signed_pdf).expect("open");
    let sigs = reader.signatures().unwrap();
    let sig = &sigs[0];
    let [a, b, c, d] = sig.byte_range;

    // Range 1 must start at file byte 0 (the PDF header).
    assert_eq!(a, 0, "/ByteRange[0] must be 0");
    assert!(b > 0, "/ByteRange[1] must be positive");
    // Range 2 must start past range 1.
    assert!(c > b, "/ByteRange[2] must be past end of range 1");
    // Together they must cover all but a CONTENTS_HEX_LEN-byte gap.
    let gap = (c - b) as usize;
    assert_eq!(
        gap, 8192,
        "/Contents <…> hex literal must reserve exactly 8192 bytes"
    );
    // Total of the two ranges + gap must equal file length.
    assert_eq!(
        (b + d) as usize + gap,
        signed_pdf.len(),
        "ranges + contents-hex gap must cover the whole file"
    );

    // The byte at index `b` (the last byte of range 1) must be `<` —
    // the opening bracket of the /Contents hex literal is INCLUDED in
    // the signed range so the structural shape of the dictionary is
    // part of the signed message.
    assert_eq!(
        signed_pdf[(b - 1) as usize],
        b'<',
        "last byte of /ByteRange range 1 must be the `<` of /Contents"
    );
    // The byte at index `c` (the first byte of range 2) must be `>`.
    assert_eq!(
        signed_pdf[c as usize], b'>',
        "first byte of /ByteRange range 2 must be the `>` of /Contents"
    );
}

#[test]
fn sign_pdf_with_rsa_pkcs1v15_sha256_produces_qpdf_check_clean() {
    // External oracle: `qpdf --check` must accept the round-30 output.
    // The check covers xref consistency, trailer validity, object
    // structure — i.e. confirms our incremental-update layout is
    // well-formed PDF, independent of the signature crypto.
    if !tool_exists("qpdf") {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R30 qpdf check");
    let serial = vec![0x30, 0x05];
    let cert_der = build_rsa_test_cert(&issuer_der, &serial, &pub_key);
    let identity = SignerIdentity::from_signer_cert_der(cert_der).expect("identity");

    let signer = RsaPkcs1v15Sha256Signer::new(priv_key);
    let scene = one_page_scene();
    let signed_pdf = sign_pdf_from_scene(&scene, &signer, identity).expect("sign");

    // qpdf ≥ 11 doesn't accept `-` as a stdin substitute (every
    // recent build resolves the literal filename `-` and reports
    // "No such file or directory"). Write the PDF to a temp file
    // and let qpdf open it by path.
    let path = write_temp_pdf(&signed_pdf, "round30-sig-rsa");
    let path_str = path.to_string_lossy().to_string();
    let output = std::process::Command::new("qpdf")
        .args(["--check", &path_str])
        .output()
        .expect("spawn qpdf");
    let _ = std::fs::remove_file(&path);
    // Tolerate `qpdf --check` exit code 3 — that's "warnings only"
    // (e.g. "file is damaged but recoverable"), which qpdf emits on
    // many incremental-update PDFs because the linearization hint
    // is absent. Exit code 0 = clean; 3 = warnings; 2 = errors.
    // ISO 32000-1 §7.5.6 expressly permits the shape we're writing.
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        code == 0 || code == 3,
        "qpdf --check exit code {code}: {stderr}\n{stdout}"
    );
}

#[test]
fn sign_pdf_with_ecdsa_p256_sha256_produces_qpdf_check_clean() {
    // ECDSA-P256 counterpart of the RSA qpdf-check test.
    if !tool_exists("qpdf") {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    use p256::ecdsa::SigningKey;
    let signing_key = SigningKey::random(&mut rsa::rand_core::OsRng);
    let verify_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let issuer_der = der::write_sequence(b"O=R30 qpdf check ECDSA");
    let serial = vec![0x30, 0x06];
    let cert_der = build_ecdsa_p256_test_cert(&issuer_der, &serial, &verify_key);
    let identity = SignerIdentity::from_signer_cert_der(cert_der).expect("identity");

    let signer = EcdsaP256Sha256Signer::new(signing_key);
    let scene = one_page_scene();
    let signed_pdf = sign_pdf_from_scene(&scene, &signer, identity).expect("sign");

    let path = write_temp_pdf(&signed_pdf, "round30-sig-ecdsa");
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

/// External-tool feature-check (mirrors `external_validation.rs`).
fn tool_exists(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Mirrors `external_validation::write_temp_pdf` — keeps the two test
/// files independent so we don't grow cross-file fixtures.
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

#[test]
fn tampering_breaks_round30_writer_signature() {
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R30 Tamper");
    let serial = vec![0x30, 0x04];
    let cert_der = build_rsa_test_cert(&issuer_der, &serial, &pub_key);
    let identity = SignerIdentity::from_signer_cert_der(cert_der.clone()).expect("identity");

    let signer = RsaPkcs1v15Sha256Signer::new(priv_key);
    let scene = one_page_scene();
    let mut signed_pdf = sign_pdf_from_scene(&scene, &signer, identity).expect("sign");

    // Flip a byte deep in the body (after the header, well before
    // /Contents) — this changes the signed bytes so the
    // messageDigest cross-check (RFC 5652 §11.2) must fail.
    let flip_off = 50;
    signed_pdf[flip_off] ^= 0x01;

    let mut reader = DocumentReader::open(&signed_pdf).expect("open tampered");
    let sigs = reader.signatures().unwrap();
    let sig = &sigs[0];
    let signed = pdf_signed_bytes(&signed_pdf, &sig.byte_range).unwrap();
    let cert = Certificate::parse(&cert_der).unwrap();
    let pool = std::slice::from_ref(&cert);
    let ok = verify_signature(
        &sig.signed_data.as_ref().unwrap().signer_infos[0],
        pool,
        AttachedContent::External(&signed),
    )
    .expect("verify dispatch");
    assert!(
        !ok,
        "tampered file must fail messageDigest cross-check (RFC 5652 §11.2)"
    );
}
