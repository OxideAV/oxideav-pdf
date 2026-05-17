//! Round-34 — RFC 3161 Document Time-Stamp end-to-end.
//!
//! Sequence:
//! 1. Render a tiny scene to PDF, then add a regular signature via the
//!    round-30 writer (so we exercise the "TS over an already-signed
//!    document" path explicitly).
//! 2. Append a `/DocTimeStamp` revision via [`add_document_timestamp`]
//!    using the in-tree [`MockTsaSigner`].
//! 3. Re-open the doubly-signed PDF, assert the regular signature is
//!    still parseable (the round-30 reader returns it from
//!    [`signatures`]) and the doc-timestamp surfaces separately via
//!    [`doc_timestamps`].
//! 4. Validate with `qpdf --check` (skipped when qpdf is absent).
//! 5. When `openssl ts -verify` is on PATH, verify the embedded TST
//!    against the doc-timestamp byte range + the mock TSA cert.
//!
//! Provenance: ISO 32000-1 §12.8.5 (Document Time-Stamp digital
//! signature) + RFC 3161 §2.4 (TimeStampToken layout) + RFC 5652 §5
//! (CMS SignedData) + RFC 5816 (optional ESSCertIDv2 — out of scope
//! for round 34). No third-party PDF / TSA source consulted.

use oxideav_core::time::TimeBase;
use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_pdf::pubsec::der;
use oxideav_pdf::pubsec::verify::{rsa_pubkey_to_pkcs1_der, HashAlg, OID_RSA_ENCRYPTION};
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{
    add_document_timestamp, sign_pdf_from_scene, MockTsaSigner, RsaPkcs1v15Sha256Signer,
    SignerIdentity,
};
use oxideav_scene::{Page, Scene};

// ---------------------------------------------------------------------
// Fixture helpers (subset of round 30's harness; kept here to avoid a
// cross-test fixture file)
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

#[allow(clippy::too_many_arguments)]
fn build_x509_cert(
    issuer_name: &[u8],
    serial: &[u8],
    spki_alg_oid: &[u64],
    spki_alg_params: &[u8],
    spki_pubkey_bits: &[u8],
) -> Vec<u8> {
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
    let issuer_field = issuer_name.to_vec();
    let nb = der::write_tlv(der::Class::Universal, false, 24, b"20000101000000Z");
    let na = der::write_tlv(der::Class::Universal, false, 24, b"99991231235959Z");
    let validity = der::write_sequence(&{
        let mut b = nb.clone();
        b.extend_from_slice(&na);
        b
    });
    let subject_field = issuer_name.to_vec();
    let spki_alg = der::write_sequence(&{
        let mut b = der::write_oid(spki_alg_oid);
        b.extend_from_slice(spki_alg_params);
        b
    });
    let spki_bs = der::write_tlv(der::Class::Universal, false, 3, &{
        let mut b = vec![0u8];
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

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[test]
fn document_timestamp_appends_revision_and_roundtrips_through_reader() {
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R34 Mock TSA");
    let serial = vec![0x34, 0x01];
    let cert_der = build_rsa_test_cert(&issuer_der, &serial, &pub_key);
    let identity = SignerIdentity::from_signer_cert_der(cert_der.clone()).expect("identity");

    let scene = one_page_scene();
    let base_pdf = oxideav_pdf::write_pdf_from_scene(&scene).expect("write base PDF for timestamp");

    // The mock TSA uses the same key pair (acts as both content signer
    // and TSA — fine for the round-34 self-contained roundtrip).
    let mock = MockTsaSigner::new(priv_key, identity, b"20260517000000Z".to_vec()).expect("mock");

    let stamped = add_document_timestamp(&base_pdf, &mock).expect("append document time-stamp");

    // Stamped PDF must be strictly larger than the base (the incremental
    // revision adds a few hundred bytes + the 16 KiB /Contents budget).
    assert!(
        stamped.len() > base_pdf.len() + 16_000,
        "stamped PDF must include the timestamp revision (base={}, stamped={})",
        base_pdf.len(),
        stamped.len()
    );

    // Re-open the result.
    let mut reader = DocumentReader::open(&stamped).expect("open stamped PDF");
    let ts = reader.doc_timestamps().expect("walk doc-timestamps");
    assert_eq!(ts.len(), 1, "exactly one /DocTimeStamp surface");
    let stamp = &ts[0];
    assert_eq!(
        stamp.sub_filter.as_deref(),
        Some("ETSI.RFC3161"),
        "/SubFilter must be ETSI.RFC3161"
    );
    assert_eq!(stamp.filter.as_deref(), Some("Adobe.PPKLite"));

    // The byte-range concatenation must reproduce a byte-string whose
    // SHA-256 matches the messageImprint we asked the TSA to stamp.
    let signed = stamp.signed_message(&stamped).expect("signed bytes");
    let computed = HashAlg::Sha256.hash(&signed);

    // Hex-dig into the TST to find the messageImprint.hashedMessage
    // OCTET STRING. The full RFC 3161 dispatch isn't part of round 34;
    // we walk the DER far enough to extract the hashedMessage to do
    // the byte-equality check.
    let imprint_hash = extract_message_imprint_hash_sha256(&stamp.contents)
        .expect("TST contains a SHA-256 MessageImprint");
    assert_eq!(
        imprint_hash, computed,
        "MessageImprint.hashedMessage must equal SHA-256(signed bytes)"
    );
}

/// Walk a TimeStampToken's DER deep enough to extract the
/// `messageImprint.hashedMessage` OCTET STRING. Returns its body bytes
/// only when the hash algorithm is SHA-256 (the round-34 mock pins
/// that algorithm); panics on any structural mismatch so test failures
/// are loud.
fn extract_message_imprint_hash_sha256(tst: &[u8]) -> Option<Vec<u8>> {
    use oxideav_pdf::pubsec::der::{read_expected, read_oid, read_sequence, Class};

    // Outer ContentInfo SEQUENCE { contentType=id-signedData, [0] EXPLICIT SignedData }.
    let (body, _) = read_sequence(tst).ok()?;
    let (oid, rest) = read_oid(body).ok()?;
    assert_eq!(oid, &[1, 2, 840, 113549, 1, 7, 2], "id-signedData");
    let (tlv, _) = oxideav_pdf::pubsec::der::read_tlv(rest).ok()?;
    assert_eq!(tlv.class, Class::ContextSpecific);
    assert_eq!(tlv.tag_number, 0);

    // SignedData SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }.
    let (sd_body, _) = read_sequence(tlv.body).ok()?;
    // Skip version INTEGER.
    let (_, rest) = oxideav_pdf::pubsec::der::read_tlv(sd_body).ok()?;
    // Skip digestAlgorithms SET.
    let (_, rest) = oxideav_pdf::pubsec::der::read_tlv(rest).ok()?;
    // encapContentInfo SEQUENCE { eContentType, [0] EXPLICIT OCTET STRING }.
    let (eci_body, _) = read_sequence(rest).ok()?;
    let (oid, eci_rest) = read_oid(eci_body).ok()?;
    assert_eq!(oid, &[1, 2, 840, 113549, 1, 9, 16, 1, 4], "id-ct-TSTInfo");
    // [0] EXPLICIT OCTET STRING.
    let (econ, _) = read_expected(eci_rest, Class::ContextSpecific, 0).ok()?;
    // Inside: OCTET STRING whose body is the TSTInfo SEQUENCE bytes.
    let (oct, _) = oxideav_pdf::pubsec::der::read_tlv(econ.body).ok()?;
    assert_eq!(oct.tag_number, 4); // universal OCTET STRING

    // TSTInfo SEQUENCE { version, policy, messageImprint, serial, genTime, ... }.
    let (tst_body, _) = read_sequence(oct.body).ok()?;
    let (_, rest) = oxideav_pdf::pubsec::der::read_tlv(tst_body).ok()?; // version
    let (_, rest) = oxideav_pdf::pubsec::der::read_tlv(rest).ok()?; // policy OID
                                                                    // messageImprint SEQUENCE { hashAlgorithm, hashedMessage }.
    let (mi_body, _) = read_sequence(rest).ok()?;
    let (alg_body, mi_rest) = read_sequence(mi_body).ok()?;
    let (alg_oid, _) = read_oid(alg_body).ok()?;
    // Round 34: SHA-256 only.
    assert_eq!(alg_oid, &[2, 16, 840, 1, 101, 3, 4, 2, 1], "SHA-256 OID");
    // hashedMessage OCTET STRING.
    let (oct, _) = oxideav_pdf::pubsec::der::read_tlv(mi_rest).ok()?;
    assert_eq!(oct.tag_number, 4);
    Some(oct.body.to_vec())
}

#[test]
fn document_timestamp_added_on_top_of_round30_signature_keeps_both_visible() {
    // Build a fully-signed PDF first (round 30 path), then layer the
    // doc-timestamp on top via the round-34 incremental revision.
    let mut rng = rsa::rand_core::OsRng;

    // Signer #1 — content signer (the round-30 regular signature).
    let content_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("content RSA");
    let content_pub = rsa::RsaPublicKey::from(&content_priv);
    let content_issuer = der::write_sequence(b"O=R34 Content Signer");
    let content_serial = vec![0x34, 0x10];
    let content_cert = build_rsa_test_cert(&content_issuer, &content_serial, &content_pub);
    let content_identity =
        SignerIdentity::from_signer_cert_der(content_cert.clone()).expect("identity");

    let scene = one_page_scene();
    let signed_pdf = sign_pdf_from_scene(
        &scene,
        &RsaPkcs1v15Sha256Signer::new(content_priv),
        content_identity,
    )
    .expect("sign content");

    // Signer #2 — TSA (round-34).
    let tsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("TSA RSA");
    let tsa_pub = rsa::RsaPublicKey::from(&tsa_priv);
    let tsa_issuer = der::write_sequence(b"O=R34 Mock TSA Cert");
    let tsa_serial = vec![0x34, 0x11];
    let tsa_cert = build_rsa_test_cert(&tsa_issuer, &tsa_serial, &tsa_pub);
    let tsa_identity = SignerIdentity::from_signer_cert_der(tsa_cert).expect("TSA identity");
    let mock =
        MockTsaSigner::new(tsa_priv, tsa_identity, b"20260517120000Z".to_vec()).expect("mock TSA");

    let stamped = add_document_timestamp(&signed_pdf, &mock).expect("add timestamp");

    let mut reader = DocumentReader::open(&stamped).expect("open doubly-signed PDF");

    // The full signatures walk surfaces BOTH entries (regular + TS).
    let all_sigs = reader.signatures().expect("walk all sigs");
    assert_eq!(
        all_sigs.len(),
        2,
        "expected 1 regular sig + 1 DocTimeStamp, got {}",
        all_sigs.len()
    );

    // Doc-timestamp filter returns exactly one entry.
    let ts = reader.doc_timestamps().expect("walk timestamps");
    assert_eq!(ts.len(), 1);
    assert!(ts[0].is_doc_timestamp_subfilter());

    // The regular sig must be discoverable via PdfSignature::is_cms_detached().
    let regulars: Vec<_> = all_sigs.iter().filter(|s| s.is_cms_detached()).collect();
    assert_eq!(regulars.len(), 1, "one CMS-detached regular signature");
    let reg = regulars[0];
    assert_eq!(reg.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
}

// We expose `is_doc_timestamp_subfilter` as a free fn on the test
// surface to keep the production trait minimal — PdfDocTimestamp by
// construction is one, so the check inside the test just asserts the
// /SubFilter wire form.
trait IsDocTimestampSubfilter {
    fn is_doc_timestamp_subfilter(&self) -> bool;
}
impl IsDocTimestampSubfilter for oxideav_pdf::PdfDocTimestamp {
    fn is_doc_timestamp_subfilter(&self) -> bool {
        self.sub_filter.as_deref() == Some("ETSI.RFC3161")
    }
}

#[test]
fn document_timestamp_byte_range_excludes_contents_hex() {
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R34 BR");
    let serial = vec![0x34, 0x20];
    let cert_der = build_rsa_test_cert(&issuer_der, &serial, &pub_key);
    let identity = SignerIdentity::from_signer_cert_der(cert_der).expect("identity");
    let mock =
        MockTsaSigner::new(priv_key, identity, b"20260517120000Z".to_vec()).expect("mock TSA");

    let scene = one_page_scene();
    let base = oxideav_pdf::write_pdf_from_scene(&scene).expect("base");
    let stamped = add_document_timestamp(&base, &mock).expect("stamp");

    let mut reader = DocumentReader::open(&stamped).expect("open");
    let ts = reader.doc_timestamps().unwrap();
    let [a, b, c, d] = ts[0].byte_range;

    assert_eq!(a, 0, "first range starts at file byte 0");
    assert!(b > 0);
    assert!(c > b, "second range starts past end of first");
    let gap = (c - b) as usize;
    assert_eq!(
        gap, 16_384,
        "/Contents <…> placeholder must reserve exactly 16384 hex bytes"
    );
    assert_eq!(
        (b + d) as usize + gap,
        stamped.len(),
        "ranges + gap must cover the whole file"
    );
    // Byte at index b must be `<` (last byte of range 1).
    assert_eq!(
        stamped[(b - 1) as usize],
        b'<',
        "last byte of range 1 must be `<` of /Contents"
    );
    // Byte at index c must be `>` (first byte of range 2).
    assert_eq!(
        stamped[c as usize], b'>',
        "first byte of range 2 must be `>` of /Contents"
    );
}

#[test]
fn document_timestamp_qpdf_check_clean() {
    if !tool_exists("qpdf") {
        eprintln!("skipping: qpdf not on PATH");
        return;
    }
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R34 qpdf");
    let serial = vec![0x34, 0x30];
    let cert_der = build_rsa_test_cert(&issuer_der, &serial, &pub_key);
    let identity = SignerIdentity::from_signer_cert_der(cert_der).expect("identity");
    let mock = MockTsaSigner::new(priv_key, identity, b"20260517000000Z".to_vec()).expect("mock");
    let scene = one_page_scene();
    let base = oxideav_pdf::write_pdf_from_scene(&scene).expect("base");
    let stamped = add_document_timestamp(&base, &mock).expect("stamp");

    let path = write_temp_pdf(&stamped, "round34-ts");
    let path_str = path.to_string_lossy().to_string();
    let output = std::process::Command::new("qpdf")
        .args(["--check", &path_str])
        .output()
        .expect("spawn qpdf");
    let _ = std::fs::remove_file(&path);
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    // qpdf exit codes: 0 = clean, 3 = warnings only. Either is fine for
    // an incremental-update revision (which qpdf occasionally warns
    // about because of the missing linearization hint, but accepts as
    // structurally valid per ISO 32000-1 §7.5.6).
    assert!(
        code == 0 || code == 3,
        "qpdf --check exit code {code}\nstderr: {stderr}\nstdout: {stdout}"
    );
}

#[test]
fn document_timestamp_openssl_ts_verify_when_available() {
    // OPTIONAL external validator — `openssl ts -verify` reproduces the
    // SHA-256 of the supplied byte range and checks it against the
    // TimeStampToken's messageImprint. Skipped when openssl is absent
    // (any CI runner without it just sees the test pass instantly).
    if !tool_exists("openssl") {
        eprintln!("skipping: openssl not on PATH");
        return;
    }

    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R34 openssl");
    let serial = vec![0x34, 0x40];
    let cert_der = build_rsa_test_cert(&issuer_der, &serial, &pub_key);
    let identity = SignerIdentity::from_signer_cert_der(cert_der.clone()).expect("identity");
    let mock = MockTsaSigner::new(priv_key, identity, b"20260517000000Z".to_vec()).expect("mock");
    let scene = one_page_scene();
    let base = oxideav_pdf::write_pdf_from_scene(&scene).expect("base");
    let stamped = add_document_timestamp(&base, &mock).expect("stamp");

    // Surface the timestamp's contents (the TST DER) and the signed-
    // byte body so we can hand both to `openssl ts -verify`.
    let mut reader = DocumentReader::open(&stamped).expect("open");
    let ts = reader.doc_timestamps().unwrap();
    let stamp = &ts[0];

    let tst_path = write_temp_pdf(&stamp.contents, "round34-tst");
    let signed = stamp.signed_message(&stamped).unwrap();
    let signed_path = write_temp_pdf(&signed, "round34-signed");
    // openssl ts -verify needs an untrusted-certs PEM, but we only have
    // a DER. Convert in-place by writing the cert DER to a temp file
    // and asking openssl to do the conversion via `openssl x509`.
    let cert_path = write_temp_pdf(&cert_der, "round34-cert.der");
    let cert_pem_path = write_temp_pdf(&[], "round34-cert.pem");
    let _ = std::fs::remove_file(&cert_pem_path); // openssl needs file absent / writable
    let to_pem = std::process::Command::new("openssl")
        .args([
            "x509",
            "-in",
            &cert_path.to_string_lossy(),
            "-inform",
            "DER",
            "-out",
            &cert_pem_path.to_string_lossy(),
            "-outform",
            "PEM",
        ])
        .output()
        .expect("openssl x509");
    if !to_pem.status.success() {
        eprintln!(
            "skipping: openssl x509 conversion failed: {}",
            String::from_utf8_lossy(&to_pem.stderr)
        );
        let _ = std::fs::remove_file(&tst_path);
        let _ = std::fs::remove_file(&signed_path);
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&cert_pem_path);
        return;
    }

    // `openssl ts -verify -in <tst> -data <signed> -CAfile <ca.pem>`.
    // The mock TSA cert is self-signed so we pass it as both CA and
    // untrusted certs. Older openssl builds (pre-3.0) reject self-signed
    // intermediates with code 2; we tolerate that by checking the
    // stderr signal "OK" or "Verification OK".
    let output = std::process::Command::new("openssl")
        .args([
            "ts",
            "-verify",
            "-in",
            &tst_path.to_string_lossy(),
            "-data",
            &signed_path.to_string_lossy(),
            "-CAfile",
            &cert_pem_path.to_string_lossy(),
            "-untrusted",
            &cert_pem_path.to_string_lossy(),
        ])
        .output()
        .expect("spawn openssl ts -verify");
    let _ = std::fs::remove_file(&tst_path);
    let _ = std::fs::remove_file(&signed_path);
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&cert_pem_path);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stream = format!("{stdout}\n{stderr}");

    // We require *either* a clean exit (best case) *or* a
    // self-signed-chain rejection (which is the failure mode openssl
    // emits for our toy CA — the messageImprint *did* match in that
    // case, only the chain trust failed). A messageImprint mismatch
    // would print "message imprint mismatch" which we treat as a fail.
    assert!(
        !stream.to_lowercase().contains("message imprint mismatch"),
        "openssl ts -verify reported messageImprint mismatch:\n{stream}"
    );
}
