//! Round-19 — PKCS#7 / CMS `SignedData` parser scaffolding (RFC 5652
//! §5).
//!
//! Builds on the existing CMS DER + X.509 + EnvelopedData infra to add
//! parser-side recognition of `id-signedData` (OID
//! `1.2.840.113549.1.7.2`) — the content type that wraps every PDF
//! digital signature (ISO 32000-1 §12.8). Round-19 ships the parser +
//! typed accessors only; the verify dispatch (hash-then-RSA / ECDSA per
//! `digestAlgorithm` + `signatureAlgorithm`) is deferred.
//!
//! Provenance: RFC 5652 §5 + RFC 5126 §5 (CAdES) + ISO 32000-1 §12.8.

use oxideav_pdf::pubsec::der;
use oxideav_pdf::pubsec::signed_data::{
    parse_signed_data, SignedData, SignerIdentifier, SignerInfo,
};

/// Build a self-contained ContentInfo wrapping a SignedData with a
/// single IAS signer and an attached `eContent` payload. We exercise
/// the end-to-end shape — the parser must reach every field.
fn synth_signed_data_v1_attached(
    issuer_der: Vec<u8>,
    serial: Vec<u8>,
    payload: &[u8],
    signature_bytes: &[u8],
) -> Vec<u8> {
    let digest_oid = vec![2u64, 16, 840, 1, 101, 3, 4, 2, 1]; // sha256
    let signature_oid = vec![1u64, 2, 840, 113549, 1, 1, 1]; // rsaEncryption

    // SignerInfo ----------------------------------------------------
    let mut si_body = der::write_integer_u64(1); // v=1 → IAS
    let ias_body = {
        let mut b = issuer_der.clone();
        b.extend_from_slice(&der::write_integer_bytes(&serial));
        b
    };
    si_body.extend_from_slice(&der::write_sequence(&ias_body));
    let da_alg = {
        let mut b = der::write_oid(&digest_oid);
        b.extend_from_slice(&der::write_null());
        der::write_sequence(&b)
    };
    si_body.extend_from_slice(&da_alg);
    let sig_alg = {
        let mut b = der::write_oid(&signature_oid);
        b.extend_from_slice(&der::write_null());
        der::write_sequence(&b)
    };
    si_body.extend_from_slice(&sig_alg);
    si_body.extend_from_slice(&der::write_octet_string(signature_bytes));
    let signer_info = der::write_sequence(&si_body);

    // SignedData fields -------------------------------------------------
    let da_set = der::write_set(&da_alg);
    let eci_body = {
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 1]); // id-data
        let octet = der::write_octet_string(payload);
        b.extend_from_slice(&der::write_context_constructed(0, &octet));
        b
    };
    let eci = der::write_sequence(&eci_body);
    let si_set = der::write_set(&signer_info);

    let mut sd_body = der::write_integer_u64(1);
    sd_body.extend_from_slice(&da_set);
    sd_body.extend_from_slice(&eci);
    sd_body.extend_from_slice(&si_set);
    let sd = der::write_sequence(&sd_body);

    // ContentInfo wrapper ------------------------------------------------
    let outer_body = {
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 2]); // id-signedData
        b.extend_from_slice(&der::write_context_constructed(0, &sd));
        b
    };
    der::write_sequence(&outer_body)
}

/// Build a SignedData with `certificates[0]` populated — exercises the
/// optional cert-set parse path. The cert is opaque DER bytes (we don't
/// re-parse it).
fn synth_signed_data_with_cert(cert_der: Vec<u8>) -> Vec<u8> {
    let issuer_der = der::write_sequence(b"O=Round-19 Test Signer");
    let serial = vec![0xAB, 0xCD];
    let signature = vec![0xCC; 256];
    let digest_oid = vec![2u64, 16, 840, 1, 101, 3, 4, 2, 1];
    let signature_oid = vec![1u64, 2, 840, 113549, 1, 1, 1];

    let mut si_body = der::write_integer_u64(1);
    let ias_body = {
        let mut b = issuer_der.clone();
        b.extend_from_slice(&der::write_integer_bytes(&serial));
        b
    };
    si_body.extend_from_slice(&der::write_sequence(&ias_body));
    let da_alg = {
        let mut b = der::write_oid(&digest_oid);
        b.extend_from_slice(&der::write_null());
        der::write_sequence(&b)
    };
    si_body.extend_from_slice(&da_alg);
    let sig_alg = {
        let mut b = der::write_oid(&signature_oid);
        b.extend_from_slice(&der::write_null());
        der::write_sequence(&b)
    };
    si_body.extend_from_slice(&sig_alg);
    si_body.extend_from_slice(&der::write_octet_string(&signature));
    let signer_info = der::write_sequence(&si_body);

    let da_set = der::write_set(&da_alg);
    // Detached signature (no eContent).
    let eci = der::write_sequence(&der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 1]));
    // certificates [0] IMPLICIT CertificateSet — emit the cert bytes
    // wrapped by the [0] context-specific constructed tag.
    let certs_tlv = der::write_tlv(der::Class::ContextSpecific, true, 0, &cert_der);
    let si_set = der::write_set(&signer_info);

    let mut sd_body = der::write_integer_u64(1);
    sd_body.extend_from_slice(&da_set);
    sd_body.extend_from_slice(&eci);
    sd_body.extend_from_slice(&certs_tlv);
    sd_body.extend_from_slice(&si_set);
    let sd = der::write_sequence(&sd_body);

    let outer_body = {
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 2]);
        b.extend_from_slice(&der::write_context_constructed(0, &sd));
        b
    };
    der::write_sequence(&outer_body)
}

#[test]
fn parse_attached_signed_data_round_trips_all_fields() {
    let issuer_der = der::write_sequence(b"O=Round-19 IAS Signer");
    let serial = vec![0x10, 0x20, 0x30];
    let payload = b"OXIDEAV-ROUND-19-PAYLOAD".to_vec();
    let signature = vec![0xEE; 256];
    let blob =
        synth_signed_data_v1_attached(issuer_der.clone(), serial.clone(), &payload, &signature);

    let parsed: SignedData = parse_signed_data(&blob).expect("parse SignedData");
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.digest_algorithms.len(), 1);
    assert_eq!(parsed.encap_content_octets.as_deref(), Some(&payload[..]));
    assert!(parsed.certs.is_empty());
    assert!(parsed.crls.is_empty());
    assert_eq!(parsed.signer_infos.len(), 1);

    let si: &SignerInfo = &parsed.signer_infos[0];
    assert_eq!(si.version, 1);
    match &si.sid {
        SignerIdentifier::IssuerAndSerial(ias) => {
            assert_eq!(ias.issuer_der, issuer_der);
            assert_eq!(ias.serial, serial);
        }
        other => panic!("expected IAS got {other:?}"),
    }
    assert_eq!(si.signature, signature);
    assert!(si.signed_attrs.is_empty(), "no signed attrs in v1 fixture");
    assert!(si.signed_attrs_der.is_none());
}

#[test]
fn parse_signed_data_with_certificate_surfaces_certs_array() {
    // Synthetic cert bytes — the parser surfaces the raw DER (we don't
    // re-parse the inner X.509 here).
    let synthetic_cert = der::write_sequence(b"OXIDEAV-FAKE-CERT-PAYLOAD");
    let blob = synth_signed_data_with_cert(synthetic_cert.clone());
    let parsed = parse_signed_data(&blob).expect("parse SignedData with certs");
    assert_eq!(parsed.certs.len(), 1, "one cert in certs[0]");
    assert_eq!(parsed.certs[0], synthetic_cert);
    assert!(parsed.encap_content_octets.is_none(), "detached signature");
}

#[test]
fn parse_signed_data_rejects_envelope_with_wrong_oid() {
    // ContentInfo whose contentType is id-envelopedData (1.2.840.113549.1.7.3)
    // — parse_signed_data must refuse it.
    let inner = der::write_sequence(&der::write_integer_u64(0));
    let outer_body = {
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 3]);
        b.extend_from_slice(&der::write_context_constructed(0, &inner));
        b
    };
    let envelope = der::write_sequence(&outer_body);
    let err = parse_signed_data(&envelope).expect_err("must reject");
    assert!(format!("{err}").contains("id-signedData"));
}

#[test]
fn parse_signed_data_rejects_truncated_blob() {
    // Just the outer SEQUENCE tag — must fail cleanly.
    let bad = vec![0x30, 0x02, 0x01, 0x00];
    assert!(parse_signed_data(&bad).is_err());
}

#[test]
fn parse_signed_data_with_empty_signer_infos_rejected() {
    // Build a SignedData whose signerInfos SET is empty — RFC 5652 §5.1
    // allows it on the wire but we refuse (no useful information for a
    // verifier; defensive parse).
    let digest_oid = vec![2u64, 16, 840, 1, 101, 3, 4, 2, 1];
    let da_alg = {
        let mut b = der::write_oid(&digest_oid);
        b.extend_from_slice(&der::write_null());
        der::write_sequence(&b)
    };
    let da_set = der::write_set(&da_alg);
    let eci = der::write_sequence(&der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 1]));
    let si_set = der::write_set(b""); // empty SET
    let mut sd_body = der::write_integer_u64(1);
    sd_body.extend_from_slice(&da_set);
    sd_body.extend_from_slice(&eci);
    sd_body.extend_from_slice(&si_set);
    let sd = der::write_sequence(&sd_body);
    let outer_body = {
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 2]);
        b.extend_from_slice(&der::write_context_constructed(0, &sd));
        b
    };
    let envelope = der::write_sequence(&outer_body);
    assert!(parse_signed_data(&envelope).is_err());
}
