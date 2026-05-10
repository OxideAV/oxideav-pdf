//! Round-21 — `/Sig` form-field reader end-to-end.
//!
//! Builds a minimal PDF 1.4 byte stream with one `/AcroForm` containing
//! one `/FT /Sig` field whose `/V` points at a signature dict. The
//! signature is a real `adbe.pkcs7.detached` CMS `SignedData` blob over
//! the `/ByteRange`-named bytes; the round-21 reader walks the AcroForm,
//! surfaces the [`PdfSignature`], and the round-20
//! [`pubsec::verify::verify_signature`] verifies it end-to-end.
//!
//! Provenance: ISO 32000-1 §12.7.4.5 (Sig field) + §12.8.1 (signature
//! dictionary) + §12.8.3.3 (`adbe.pkcs7.detached` SubFilter); RFC 5652
//! §5 (CMS SignedData) + §11.2 (messageDigest attribute). No
//! third-party PDF / CMS source consulted.

use oxideav_pdf::pubsec::der;
use oxideav_pdf::pubsec::signed_data::SignerIdentifier;
use oxideav_pdf::pubsec::verify::{
    build_message_digest_attribute_der, implicit_signed_attrs_tlv, pack_signed_attrs_implicit,
    rsa_pubkey_to_pkcs1_der, signed_attrs_to_be_signed, verify_signature, AttachedContent, HashAlg,
    OID_RSA_ENCRYPTION, OID_SHA256,
};
use oxideav_pdf::pubsec::x509::Certificate;
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::{pdf_signed_bytes, PdfSignature};

// -------------------------------------------------------------------
// Minimal-PDF fixture builder
// -------------------------------------------------------------------

/// Number of bytes the `<…>` placeholder of `/Contents` reserves. The
/// signed data blob must fit (in hex form, so 2× expansion) inside this
/// budget. 8192 hex chars = 4096 raw bytes — comfortable for any
/// SHA-256 + RSA-2048 SignedData with a single signer.
const CONTENTS_HEX_LEN: usize = 8192;

/// Marker byte string used to align the `/ByteRange` slot for in-place
/// patching. Each slot is 10 chars wide right-aligned (matches Rust's
/// `{:>10}` format spec), with one ASCII space between slots — wide
/// enough for any 10-digit (≤ ~9.9 GB) PDF byte offset.
const BYTE_RANGE_PLACEHOLDER: &str = "/ByteRange [         0          0          0          0]";

/// Build a minimal valid PDF 1.4 document whose AcroForm contains one
/// `/Sig` field. Returns the bytes plus the byte-range pair the
/// signature should cover (= entire file minus the `/Contents` `<…>`
/// literal). The `/Contents` placeholder is filled with `0x00` bytes
/// of length [`CONTENTS_HEX_LEN`] (so `CONTENTS_HEX_LEN/2` raw bytes).
fn build_pdf_with_unfilled_sig() -> (Vec<u8>, [i64; 4], usize) {
    // Object ids used:
    //   1 = Catalog
    //   2 = Pages root
    //   3 = Page leaf
    //   4 = AcroForm
    //   5 = Sig field
    //   6 = Sig dict (the /V of the field)
    //
    // We hand-lay the body so we can precisely control the offsets that
    // `/ByteRange` will reference.

    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);

    // Header — PDF 1.4 + 4-byte binary marker (§7.5.2).
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    // 1 = Catalog.
    let off_1 = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>\nendobj\n");

    // 2 = Pages root.
    let off_2 = buf.len();
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");

    // 3 = Page leaf — empty content stream.
    let off_3 = buf.len();
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>\nendobj\n",
    );

    // 4 = AcroForm dictionary.
    let off_4 = buf.len();
    buf.extend_from_slice(b"4 0 obj\n<< /Fields [5 0 R] /SigFlags 3 >>\nendobj\n");

    // 5 = Sig form field — terminal (no /Kids), /FT /Sig, /V points at 6.
    let off_5 = buf.len();
    buf.extend_from_slice(b"5 0 obj\n<< /FT /Sig /T (Signature1) /V 6 0 R >>\nendobj\n");

    // 6 = Signature dict. We'll patch /ByteRange + /Contents below.
    let off_6 = buf.len();
    buf.extend_from_slice(b"6 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite ");
    buf.extend_from_slice(b"/SubFilter /adbe.pkcs7.detached ");
    // /ByteRange placeholder — fixed-width so we can patch in-place
    // without changing offsets.
    buf.extend_from_slice(BYTE_RANGE_PLACEHOLDER.as_bytes());
    buf.extend_from_slice(b" /Contents <");
    let contents_hex_offset = buf.len();
    buf.resize(buf.len() + CONTENTS_HEX_LEN, b'0');
    buf.extend_from_slice(b"> >>\nendobj\n");

    // xref + trailer.
    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n0 7\n");
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for off in [off_1, off_2, off_3, off_4, off_5, off_6] {
        let line = format!("{:010} 00000 n \n", off);
        buf.extend_from_slice(line.as_bytes());
    }
    buf.extend_from_slice(b"trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n");
    buf.extend_from_slice(format!("{xref_off}\n%%EOF\n").as_bytes());

    // Compute the /ByteRange entries per ISO 32000-1 §12.8.1.1.
    // /ByteRange must cover the entire document EXCEPT the bytes
    // between `<` and `>` of /Contents (i.e. the hex literal itself
    // is excluded; the `<` and `>` brackets ARE included so the
    // structural shape of the dictionary is part of the signed
    // message).
    //
    // `contents_hex_offset` is the byte index of the first hex char
    // (immediately after `<`). So:
    //   range 1 = bytes [0 .. contents_hex_offset)  (covers up to
    //             and including `<`),
    //   range 2 = bytes [contents_hex_offset + CONTENTS_HEX_LEN .. EOF)
    //             (covers `>` plus everything after).
    let total = buf.len() as i64;
    let b1_len = contents_hex_offset as i64;
    let r2_start = (contents_hex_offset + CONTENTS_HEX_LEN) as i64;
    let r2_len = total - r2_start;
    (buf, [0, b1_len, r2_start, r2_len], contents_hex_offset)
}

/// Patch the `/ByteRange` placeholder. Length-preserving so the offsets
/// the byte-range refers to don't shift.
fn patch_byte_range(pdf: &mut [u8], byte_range: [i64; 4]) {
    let formatted = format!(
        "/ByteRange [{:>10} {:>10} {:>10} {:>10}]",
        byte_range[0], byte_range[1], byte_range[2], byte_range[3]
    );
    assert_eq!(
        formatted.len(),
        BYTE_RANGE_PLACEHOLDER.len(),
        "ByteRange width drift"
    );
    let placeholder_bytes = BYTE_RANGE_PLACEHOLDER.as_bytes();
    let pos = pdf
        .windows(placeholder_bytes.len())
        .position(|w| w == placeholder_bytes)
        .expect("ByteRange placeholder must be present");
    pdf[pos..pos + placeholder_bytes.len()].copy_from_slice(formatted.as_bytes());
}

/// Patch the `/Contents <…>` hex literal in place. The bytes between
/// `<` and `>` (the bytes the round-21 reader hex-decodes) are the
/// EXCLUDED range under `/ByteRange`, so this write does not shift any
/// signed byte offset — safe to call after the signature has been
/// computed.
fn patch_contents(pdf: &mut [u8], contents_hex_offset: usize, contents_der: &[u8]) {
    let hex_bytes: Vec<u8> = contents_der
        .iter()
        .flat_map(|b| {
            let lo = b & 0x0F;
            let hi = (b >> 4) & 0x0F;
            [hex_digit(hi), hex_digit(lo)]
        })
        .collect();
    assert!(
        hex_bytes.len() <= CONTENTS_HEX_LEN,
        "CMS blob {} hex chars exceeds /Contents budget {}",
        hex_bytes.len(),
        CONTENTS_HEX_LEN
    );
    pdf[contents_hex_offset..contents_hex_offset + hex_bytes.len()].copy_from_slice(&hex_bytes);
    // Pad the rest with `0` so trailing budget bytes hex-decode to 0x00
    // — the round-21 reader's CMS trim drops them at the outer SEQUENCE
    // boundary.
    for byte in pdf
        .iter_mut()
        .skip(contents_hex_offset + hex_bytes.len())
        .take(CONTENTS_HEX_LEN - hex_bytes.len())
    {
        *byte = b'0';
    }
}

/// One-shot: patch /ByteRange and /Contents together. Used by the
/// pre-verification fixture tests where the contents value is just a
/// placeholder for the reader walk (no real signature flow).
fn patch_byte_range_and_contents(
    pdf: &mut [u8],
    byte_range: [i64; 4],
    contents_hex_offset: usize,
    contents_der: &[u8],
) {
    patch_byte_range(pdf, byte_range);
    patch_contents(pdf, contents_hex_offset, contents_der);
}

fn hex_digit(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'A' + (n - 10),
        _ => unreachable!(),
    }
}

// -------------------------------------------------------------------
// CMS SignedData builder (mirrors the round-20 fixture builder).
// -------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_signed_data_blob(
    issuer_der: &[u8],
    serial: &[u8],
    digest_oid: &[u64],
    digest_alg_params: &[u8],
    signature_oid: &[u64],
    sig_alg_params: &[u8],
    signed_attrs_body: Option<&[u8]>,
    signature_bytes: &[u8],
    encap_payload_octets: Option<&[u8]>,
) -> Vec<u8> {
    let mut si_body = der::write_integer_u64(1); // v=1 (IAS)

    let ias_body = {
        let mut b = issuer_der.to_vec();
        b.extend_from_slice(&der::write_integer_bytes(serial));
        b
    };
    si_body.extend_from_slice(&der::write_sequence(&ias_body));

    let da_alg = {
        let mut b = der::write_oid(digest_oid);
        b.extend_from_slice(digest_alg_params);
        der::write_sequence(&b)
    };
    si_body.extend_from_slice(&da_alg);

    if let Some(sa_body) = signed_attrs_body {
        si_body.extend_from_slice(&implicit_signed_attrs_tlv(sa_body));
    }

    let sig_alg = {
        let mut b = der::write_oid(signature_oid);
        b.extend_from_slice(sig_alg_params);
        der::write_sequence(&b)
    };
    si_body.extend_from_slice(&sig_alg);
    si_body.extend_from_slice(&der::write_octet_string(signature_bytes));
    let signer_info = der::write_sequence(&si_body);

    let da_set = der::write_set(&da_alg);
    let eci_body = {
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 1]); // id-data
        if let Some(payload) = encap_payload_octets {
            let octet = der::write_octet_string(payload);
            b.extend_from_slice(&der::write_context_constructed(0, &octet));
        }
        b
    };
    let eci = der::write_sequence(&eci_body);
    let si_set = der::write_set(&signer_info);

    let mut sd_body = der::write_integer_u64(1);
    sd_body.extend_from_slice(&da_set);
    sd_body.extend_from_slice(&eci);
    sd_body.extend_from_slice(&si_set);
    let sd = der::write_sequence(&sd_body);

    let outer_body = {
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 2]); // id-signedData
        b.extend_from_slice(&der::write_context_constructed(0, &sd));
        b
    };
    der::write_sequence(&outer_body)
}

fn fake_rsa_cert(issuer_der: Vec<u8>, serial: Vec<u8>, rsa_pkcs1_der: Vec<u8>) -> Certificate {
    Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(rsa_pkcs1_der),
        spki_algorithm_oid: Some(OID_RSA_ENCRYPTION.to_vec()),
        spki_algorithm_params: Some(der::write_null()),
        ..Default::default()
    }
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[test]
fn signatures_walks_acroform_and_surfaces_pdf_signature() {
    let (pdf, byte_range, contents_hex_offset) = build_pdf_with_unfilled_sig();
    // We don't need a real CMS for this test — just a non-zero
    // hex-encoded blob so the reader can decode `/Contents`.
    let mut pdf = pdf;
    let dummy_der = der::write_sequence(b"\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02\x80\x00");
    patch_byte_range_and_contents(&mut pdf, byte_range, contents_hex_offset, &dummy_der);

    let mut reader = DocumentReader::open(&pdf).expect("open PDF");
    let sigs = reader.signatures().expect("walk signatures");
    assert_eq!(sigs.len(), 1, "exactly one /Sig field");
    let s = &sigs[0];
    assert_eq!(s.byte_range, byte_range);
    assert_eq!(s.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
    assert_eq!(s.filter.as_deref(), Some("Adobe.PPKLite"));
    assert_eq!(s.sig_type.as_deref(), Some("Sig"));
    assert!(s.is_cms_detached());
    // The dummy DER doesn't parse as a real SignedData ContentInfo
    // (the OID inside is right but the eContent encoding is bogus).
    // Either way, contents are surfaced verbatim.
    assert!(!s.contents.is_empty());
}

#[test]
fn signed_message_helper_concatenates_byte_range() {
    let (pdf, byte_range, contents_hex_offset) = build_pdf_with_unfilled_sig();
    let mut pdf = pdf;
    let dummy = vec![0xDE, 0xAD, 0xBE, 0xEF];
    patch_byte_range_and_contents(&mut pdf, byte_range, contents_hex_offset, &dummy);

    let mut reader = DocumentReader::open(&pdf).expect("open PDF");
    let sigs = reader.signatures().unwrap();
    let s = &sigs[0];
    let signed = s.signed_message(&pdf).expect("signed message");

    // Sanity: signed message must NOT contain the four hex `D` `E` `A`
    // `D` characters from the patched blob (those live between the
    // `<` and `>`, which is the *excluded* range).
    let hex_blob = &pdf[contents_hex_offset..contents_hex_offset + 8];
    assert_eq!(hex_blob, b"DEADBEEF");
    assert!(
        !signed.windows(8).any(|w| w == hex_blob),
        "signed message must not include the excluded /Contents hex"
    );
    // The signed message must include both the `<` and `>` bracket
    // bytes — those are part of the signed range.
    assert_eq!(
        signed[byte_range[0] as usize..byte_range[1] as usize].last(),
        Some(&b'<')
    );
}

#[test]
fn end_to_end_rsa_pkcs1v15_sha256_detached_verifies() {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::traits::SignatureScheme;
    use sha2::Sha256;

    // 1. Lay out the PDF skeleton with the signature placeholder.
    let (mut pdf, byte_range, contents_hex_offset) = build_pdf_with_unfilled_sig();

    // 2. Generate a 2048-bit RSA key pair + a fake cert that points at
    //    its public key.
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R21 PDF Sig E2E");
    let serial = vec![0x21];
    let cert = fake_rsa_cert(
        issuer_der.clone(),
        serial.clone(),
        rsa_pubkey_to_pkcs1_der(&pub_key),
    );

    // 3. Patch /ByteRange first — the four integers are themselves part
    //    of the signed range, so they must reach their final value
    //    BEFORE we hash. /Contents stays as the all-zero placeholder
    //    (the bytes between `<` and `>` are EXCLUDED from the signed
    //    range per ISO 32000-1 §12.8.1.1).
    patch_byte_range(&mut pdf, byte_range);
    let signed = pdf_signed_bytes(&pdf, &byte_range).expect("signed bytes");

    // 4. Sign — this is a `signedAttrs`-present flow (CAdES-style):
    //    messageDigest attribute carries SHA-256(signed_message); the
    //    actual signature is over the canonical SET-tagged signedAttrs
    //    DER. RFC 5652 §5.4 + §11.2.
    let content_hash = HashAlg::Sha256.hash(&signed);
    let md_attr = build_message_digest_attribute_der(&content_hash);
    let attrs_body = pack_signed_attrs_implicit(&[md_attr]);
    let to_be_signed = signed_attrs_to_be_signed(&attrs_body);
    let tbs_hash = HashAlg::Sha256.hash(&to_be_signed);
    let signature = Pkcs1v15Sign::new::<Sha256>()
        .sign(None::<&mut rsa::rand_core::OsRng>, &priv_key, &tbs_hash)
        .expect("RSA-PKCS1v15 sign");

    // 5. Build the detached SignedData ContentInfo (no eContent).
    let cms_blob = build_signed_data_blob(
        &issuer_der,
        &serial,
        &OID_SHA256,
        &der::write_null(),
        &OID_RSA_ENCRYPTION,
        &der::write_null(),
        Some(&attrs_body),
        &signature,
        None, // detached
    );

    // 6. Patch /Contents in place — the signed bytes don't change
    //    because they exclude the `<…hex…>` literal.
    patch_contents(&mut pdf, contents_hex_offset, &cms_blob);

    // 7. Open + walk + verify.
    let mut reader = DocumentReader::open(&pdf).expect("open PDF");
    let sigs = reader.signatures().expect("walk signatures");
    assert_eq!(sigs.len(), 1);
    let s = &sigs[0];
    assert_eq!(s.byte_range, byte_range);
    assert!(s.is_cms_detached());
    let sd = s
        .signed_data
        .as_ref()
        .expect("CMS SignedData parsed by the round-21 reader");
    assert_eq!(sd.signer_infos.len(), 1);
    let signer = &sd.signer_infos[0];
    match &signer.sid {
        SignerIdentifier::IssuerAndSerial(ias) => {
            assert_eq!(ias.issuer_der, issuer_der);
            assert_eq!(ias.serial, serial);
        }
        other => panic!("expected IAS got {other:?}"),
    }

    // 8. Recover the signed bytes from the *patched* PDF — the bytes
    //    are byte-identical to those signed at step 3 because the
    //    /Contents hex is the excluded range.
    let to_verify = s.signed_message(&pdf).expect("signed bytes from sig");
    assert_eq!(
        to_verify, signed,
        "patching /Contents must not shift any signed byte"
    );

    // 9. Run the round-20 verifier — the round-21 reader simply hands
    //    the bytes off; the actual cryptography is round-20's.
    let cert_pool = std::slice::from_ref(&cert);
    let ok = verify_signature(signer, cert_pool, AttachedContent::External(&to_verify))
        .expect("verify dispatch");
    assert!(ok, "Round-21 PDF /Sig must verify with round-20 verifier");

    // 10. Tamper detection: flip a byte in the file's body (outside
    //     /Contents) and re-verify — the signed message changes, so
    //     the messageDigest cross-check must fail.
    let mut tampered = pdf.clone();
    // Pick a byte that lives in the first signed range — flip it.
    tampered[40] ^= 0x01;
    let mut tamper_reader = DocumentReader::open(&tampered).expect("open tampered");
    let tamper_sigs = tamper_reader.signatures().unwrap();
    let bad_signed = tamper_sigs[0].signed_message(&tampered).unwrap();
    let bad_ok = verify_signature(
        &tamper_sigs[0].signed_data.as_ref().unwrap().signer_infos[0],
        cert_pool,
        AttachedContent::External(&bad_signed),
    )
    .expect("verify tampered dispatch");
    assert!(
        !bad_ok,
        "tampered file must fail messageDigest cross-check (RFC 5652 §11.2)"
    );
}

#[test]
fn no_acroform_returns_empty_vec() {
    // A regular round-2 PDF has no AcroForm — `signatures()` must
    // succeed and return an empty Vec rather than erroring.
    use oxideav_core::time::TimeBase;
    use oxideav_core::vector::{
        FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
    };
    use oxideav_scene::{Page, Scene};

    let mut path = Path::new();
    path.commands
        .push(PathCommand::MoveTo(Point::new(0.0, 0.0)));
    path.commands
        .push(PathCommand::LineTo(Point::new(10.0, 0.0)));
    path.commands
        .push(PathCommand::LineTo(Point::new(10.0, 10.0)));
    path.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 100.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path,
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
    let scene = Scene {
        pages: Some(vec![page]),
        ..Scene::default()
    };
    let pdf = oxideav_pdf::write_pdf_from_scene(&scene).unwrap();
    let mut reader = DocumentReader::open(&pdf).unwrap();
    assert!(reader.signatures().unwrap().is_empty());
}

#[test]
fn nested_field_with_inherited_ft_is_walked() {
    // Build a PDF where /Fields contains a non-terminal parent whose
    // /FT /Sig propagates to a terminal kid (the ISO 32000-1 §12.7.3.1
    // "inherited /FT" pattern).
    //
    // Layout:
    //   1 = Catalog
    //   2 = Pages root
    //   3 = Page leaf
    //   4 = AcroForm  /Fields [5 0 R]
    //   5 = Parent field (FT=Sig, no V, Kids=[6 0 R])
    //   6 = Child field (no FT — inherited; V=7 0 R)
    //   7 = Sig dict (with /ByteRange + /Contents placeholders)

    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let off_1 = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>\nendobj\n");
    let off_2 = buf.len();
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    let off_3 = buf.len();
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>\nendobj\n",
    );
    let off_4 = buf.len();
    buf.extend_from_slice(b"4 0 obj\n<< /Fields [5 0 R] >>\nendobj\n");
    let off_5 = buf.len();
    buf.extend_from_slice(b"5 0 obj\n<< /FT /Sig /Kids [6 0 R] /T (Parent) >>\nendobj\n");
    let off_6 = buf.len();
    buf.extend_from_slice(b"6 0 obj\n<< /T (Child) /V 7 0 R >>\nendobj\n");
    let off_7 = buf.len();
    buf.extend_from_slice(
        b"7 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached ",
    );
    buf.extend_from_slice(b"/ByteRange [0 0 0 0] /Contents <00> >>\nendobj\n");

    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n0 8\n0000000000 65535 f \n");
    for off in [off_1, off_2, off_3, off_4, off_5, off_6, off_7] {
        buf.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    buf.extend_from_slice(b"trailer\n<< /Size 8 /Root 1 0 R >>\nstartxref\n");
    buf.extend_from_slice(format!("{xref_off}\n%%EOF\n").as_bytes());

    let mut reader = DocumentReader::open(&buf).expect("open nested PDF");
    let sigs = reader.signatures().expect("walk");
    assert_eq!(
        sigs.len(),
        1,
        "inherited /FT /Sig must surface terminal kid"
    );
    let s = &sigs[0];
    assert_eq!(s.byte_range, [0, 0, 0, 0]);
    assert_eq!(s.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
}

#[test]
fn signature_metadata_fields_round_trip() {
    // /Name, /Reason, /Location, /ContactInfo, /M — all literal text
    // strings. Our text_value helper decodes them.
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let off_1 = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>\nendobj\n");
    let off_2 = buf.len();
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    let off_3 = buf.len();
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>\nendobj\n",
    );
    let off_4 = buf.len();
    buf.extend_from_slice(b"4 0 obj\n<< /Fields [5 0 R] >>\nendobj\n");
    let off_5 = buf.len();
    buf.extend_from_slice(b"5 0 obj\n<< /FT /Sig /T (Sig1) /V 6 0 R >>\nendobj\n");
    let off_6 = buf.len();
    buf.extend_from_slice(b"6 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite ");
    buf.extend_from_slice(b"/SubFilter /adbe.pkcs7.detached ");
    buf.extend_from_slice(b"/ByteRange [0 0 0 0] /Contents <00> ");
    buf.extend_from_slice(b"/Name (Mark Karpeles) /Reason (Approval) ");
    buf.extend_from_slice(b"/Location (Tokyo) /ContactInfo (admin@example.com) ");
    buf.extend_from_slice(b"/M (D:20260510123456+09'00') >>\nendobj\n");

    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n0 7\n0000000000 65535 f \n");
    for off in [off_1, off_2, off_3, off_4, off_5, off_6] {
        buf.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    buf.extend_from_slice(b"trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n");
    buf.extend_from_slice(format!("{xref_off}\n%%EOF\n").as_bytes());

    let mut reader = DocumentReader::open(&buf).expect("open");
    let sigs = reader.signatures().unwrap();
    let s = &sigs[0];
    assert_eq!(s.name.as_deref(), Some("Mark Karpeles"));
    assert_eq!(s.reason.as_deref(), Some("Approval"));
    assert_eq!(s.location.as_deref(), Some("Tokyo"));
    assert_eq!(s.contact_info.as_deref(), Some("admin@example.com"));
    assert_eq!(s.signing_time.as_deref(), Some("D:20260510123456+09'00'"));
}

#[test]
fn unsigned_sig_field_without_value_is_skipped() {
    // A Sig field whose /V is absent is a "placeholder, not yet signed"
    // — the walker should skip it silently rather than error.
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    buf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let off_1 = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>\nendobj\n");
    let off_2 = buf.len();
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    let off_3 = buf.len();
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>\nendobj\n",
    );
    let off_4 = buf.len();
    buf.extend_from_slice(b"4 0 obj\n<< /Fields [5 0 R] >>\nendobj\n");
    let off_5 = buf.len();
    buf.extend_from_slice(b"5 0 obj\n<< /FT /Sig /T (UnsignedSlot) >>\nendobj\n");

    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
    for off in [off_1, off_2, off_3, off_4, off_5] {
        buf.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    buf.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n");
    buf.extend_from_slice(format!("{xref_off}\n%%EOF\n").as_bytes());

    let mut reader = DocumentReader::open(&buf).expect("open");
    assert!(reader.signatures().unwrap().is_empty());
}

#[test]
fn pdf_signature_struct_is_clone_and_debug() {
    let s = PdfSignature {
        byte_range: [1, 2, 3, 4],
        contents: vec![0xAA, 0xBB],
        sub_filter: Some("adbe.pkcs7.detached".into()),
        filter: Some("Adobe.PPKLite".into()),
        sig_type: Some("Sig".into()),
        name: None,
        reason: None,
        location: None,
        contact_info: None,
        signing_time: None,
        signed_data: None,
        contents_offset: None,
    };
    let copy = s.clone();
    assert_eq!(copy.byte_range, [1, 2, 3, 4]);
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("adbe.pkcs7.detached"));
}
