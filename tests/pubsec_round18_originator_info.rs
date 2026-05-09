//! Round-18 — `OriginatorInfo certs[] / crls[]` surface end-to-end.
//!
//! The CMS `EnvelopedData.originatorInfo` field (RFC 5652 §10.2.1) was
//! previously parsed and silently discarded. Round 18 surfaces it via
//! [`oxideav_pdf::pubsec::cms::OriginatorInfo`] + the
//! [`oxideav_pdf::pubsec::cms::EnvelopedData::originator_info`] accessor —
//! callers (e.g. validation pipelines) can now inspect the originator's
//! transmitted certificate / CRL bundle.
//!
//! Provenance: RFC 5652 §10.2.1 (`OriginatorInfo`) + §10.2.2
//! (`CertificateChoices`) + RFC 5280 §5 (`CertificateList` for CRLs).

use oxideav_pdf::pubsec::cms::{parse_envelope, OriginatorInfo};
use oxideav_pdf::pubsec::cms_build::{
    build_envelope_aes256, build_envelope_aes256_with_originator_info, RecipientPlain,
};
use oxideav_pdf::pubsec::der;
use oxideav_pdf::pubsec::x509::Certificate;

/// Build a minimal X.509 v3 cert SEQUENCE with `(issuer, serial)` —
/// enough for the round-18 OriginatorInfo round-trip test (we only
/// re-parse `issuer + serial` from the bundled certs).
fn synth_cert_der(issuer_cn: &[u8], serial: &[u8]) -> Vec<u8> {
    let issuer_seq = der::write_sequence(issuer_cn);
    // tbsCertificate: [0] EXPLICIT version, INTEGER serial,
    // signatureAlg SEQUENCE, issuer Name, ...
    let version = der::write_context_constructed(0, &der::write_integer_u64(2)); // v3
    let serial_int = der::write_integer_bytes(serial);
    let sig_alg = der::write_sequence(&{
        let mut b = der::write_oid(&[1, 2, 840, 113549, 1, 1, 11]); // sha256WithRSA
        b.extend_from_slice(&der::write_null());
        b
    });
    let mut tbs = Vec::new();
    tbs.extend_from_slice(&version);
    tbs.extend_from_slice(&serial_int);
    tbs.extend_from_slice(&sig_alg);
    tbs.extend_from_slice(&issuer_seq);
    let tbs_seq = der::write_sequence(&tbs);
    let mut outer = tbs_seq;
    // signatureAlgorithm + signatureValue (placeholder).
    outer.extend_from_slice(&der::write_sequence(&der::write_oid(&[
        1, 2, 840, 113549, 1, 1, 11,
    ])));
    outer.extend_from_slice(&der::write_tlv(
        der::Class::Universal,
        false,
        3, // BIT STRING
        &[0x00, 0xAB, 0xCD],
    ));
    der::write_sequence(&outer)
}

/// Build a tiny synthetic CRL (`CertificateList`) DER. We don't parse
/// it back beyond byte-comparing the surfaced raw entries.
fn synth_crl_der(payload: &[u8]) -> Vec<u8> {
    // Minimal SEQUENCE wrapping the payload — it's enough that the
    // outer TLV passes the parser's split_set_into_raw_entries.
    der::write_sequence(payload)
}

#[test]
fn originator_info_round_trip_preserves_certs_and_crls() {
    // Two synthetic originator certs — bundled inside the envelope.
    let cert_a = synth_cert_der(b"O=Originator A", &[0xA1, 0xA2]);
    let cert_b = synth_cert_der(b"O=Originator B", &[0xB1, 0xB2, 0xB3]);
    let crl_a = synth_crl_der(b"OXIDEAV-FAKE-CRL-A");
    let crl_b = synth_crl_der(b"OXIDEAV-FAKE-CRL-BBB");

    // One synthetic recipient — not consulted by this test (we re-parse
    // structurally only).
    let issuer_der = der::write_sequence(b"O=R");
    let serial = vec![0x01];
    let recipient = RecipientPlain::ias(issuer_der, serial, vec![0x42; 256]);

    let envelope = build_envelope_aes256_with_originator_info(
        &[recipient],
        &[0u8; 24],
        &[0xAAu8; 32],
        &[0xBBu8; 16],
        &[cert_a.clone(), cert_b.clone()],
        &[crl_a.clone(), crl_b.clone()],
    );

    let parsed = parse_envelope(&envelope).expect("parse envelope");
    let oi = parsed.originator_info().expect("OriginatorInfo present");
    assert_eq!(oi.certs.len(), 2, "certs[] entries");
    assert_eq!(oi.crls.len(), 2, "crls[] entries");

    // Byte-identical round-trip on certs[].
    assert_eq!(oi.certs[0], cert_a);
    assert_eq!(oi.certs[1], cert_b);
    assert_eq!(oi.crls[0], crl_a);
    assert_eq!(oi.crls[1], crl_b);

    // Re-parse the surfaced cert DER to confirm serials match.
    let parsed_a = Certificate::parse(&oi.certs[0]).expect("parse cert A");
    assert_eq!(parsed_a.serial, vec![0xA1, 0xA2]);
    let parsed_b = Certificate::parse(&oi.certs[1]).expect("parse cert B");
    assert_eq!(parsed_b.serial, vec![0xB1, 0xB2, 0xB3]);
}

#[test]
fn envelope_without_originator_info_surfaces_none() {
    // Plain envelope (no OriginatorInfo) — accessor returns None.
    let issuer_der = der::write_sequence(b"O=R");
    let serial = vec![0x01];
    let recipient = RecipientPlain::ias(issuer_der, serial, vec![0x42; 256]);
    let envelope = build_envelope_aes256(&[recipient], &[0u8; 24], &[0xAAu8; 32], &[0xBBu8; 16]);
    let parsed = parse_envelope(&envelope).expect("parse envelope");
    assert!(
        parsed.originator_info().is_none(),
        "expected no OriginatorInfo"
    );
    assert!(parsed.originator_info.is_empty());
}

#[test]
fn originator_info_with_only_certs_omits_crls() {
    // Bundle two certs but no CRLs — `crls[]` stays empty.
    let cert_a = synth_cert_der(b"O=Only certs", &[0x42]);
    let issuer_der = der::write_sequence(b"O=R");
    let serial = vec![0x01];
    let recipient = RecipientPlain::ias(issuer_der, serial, vec![0x42; 256]);
    let envelope = build_envelope_aes256_with_originator_info(
        &[recipient],
        &[0u8; 24],
        &[0xAAu8; 32],
        &[0xBBu8; 16],
        std::slice::from_ref(&cert_a),
        &[],
    );
    let parsed = parse_envelope(&envelope).expect("parse envelope");
    let oi = parsed.originator_info().expect("OriginatorInfo present");
    assert_eq!(oi.certs.len(), 1);
    assert!(oi.crls.is_empty());
    assert_eq!(oi.certs[0], cert_a);
}

#[test]
fn originator_info_default_is_empty_and_helper_default() {
    let oi = OriginatorInfo::default();
    assert!(oi.is_empty());
    assert!(oi.certs.is_empty());
    assert!(oi.crls.is_empty());
}
