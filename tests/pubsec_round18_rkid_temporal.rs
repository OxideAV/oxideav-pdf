//! Round-18 — `RecipientKeyIdentifier { date, other }` OPTIONAL field
//! parse + temporal trust-store lookup.
//!
//! Per RFC 5652 §6.2.2:
//!
//! ```asn.1
//! RecipientKeyIdentifier ::= SEQUENCE {
//!   subjectKeyIdentifier SubjectKeyIdentifier,
//!   date GeneralizedTime OPTIONAL,
//!   other OtherKeyAttribute OPTIONAL
//! }
//! ```
//!
//! Round 17 ignored both OPTIONAL fields; round 18 captures them on
//! the parser side AND adds [`TrustStore::find_with_temporal_validity`]
//! so a long-lived archive whose recipient SKI has been re-certified
//! multiple times can resolve the cert generation that was active when
//! the envelope was authored.
//!
//! Provenance: RFC 5652 §6.2.2 + RFC 5280 §4.1.2.5 (Validity) only.

use oxideav_pdf::pubsec::cms::{parse_envelope, KeyAgreeRecipientId, RecipientInfoVariant};
use oxideav_pdf::pubsec::cms_build::{
    build_envelope_kari_aes256, KariRecipientIdRef, KariRecipientPlain, OriginatorIdRef,
};
use oxideav_pdf::pubsec::der;
use oxideav_pdf::pubsec::x509::Certificate;
use oxideav_pdf::TrustStore;

/// Build a minimal KARI envelope whose single recipient slot carries
/// an RKID with the supplied SKI + optional `date` + optional `other`.
fn build_kari_with_rkid(
    ski: &[u8],
    date: Option<Vec<u8>>,
    other: Option<(Vec<u64>, Vec<u8>)>,
) -> Vec<u8> {
    let originator_pubkey = b"FAKE-OXIDEAV-EC-POINT-32-BYTES!!".to_vec();
    let originator = OriginatorIdRef::OriginatorKey {
        algorithm_oid: vec![1, 2, 840, 10045, 2, 1], // ecPublicKey
        algorithm_params: der::write_oid(&[1, 2, 840, 10045, 3, 1, 7]), // P-256
        public_key: originator_pubkey,
    };
    let kea_oid = vec![1u64, 3, 133, 16, 840, 63, 0, 11, 1]; // dhSinglePass-stdDH-sha256kdf
    let aes256_wrap_oid = [2u64, 16, 840, 1, 101, 3, 4, 1, 45];
    let kea_params = der::write_sequence(&der::write_oid(&aes256_wrap_oid));
    let recipient = KariRecipientPlain {
        rid: KariRecipientIdRef::RecipientKeyIdentifier {
            ski: ski.to_vec(),
            date,
            other,
        },
        encrypted_key: vec![0xDEu8; 40],
    };
    build_envelope_kari_aes256(
        &originator,
        Some(b"OXIDEAV-RT-18-RKID"),
        &kea_oid,
        &kea_params,
        &[recipient],
        b"OXIDEAV-RT-18-PT-32-BYTES-PADDIN",
        &[0xAAu8; 32],
        &[0xBBu8; 16],
    )
}

#[test]
fn rkid_round_trip_captures_date_and_other_when_present() {
    let ski = vec![0x42u8; 20];
    let date = b"20260510120000Z".to_vec();
    let other_oid = vec![1u64, 2, 840, 113549, 1, 9, 16, 2, 99]; // arbitrary OID
    let other_attr = vec![0x05, 0x00]; // empty NULL (DER)
    let envelope = build_kari_with_rkid(
        &ski,
        Some(date.clone()),
        Some((other_oid.clone(), other_attr.clone())),
    );
    let parsed = parse_envelope(&envelope).expect("parse envelope");
    let kari = match &parsed.all_recipients[0] {
        RecipientInfoVariant::KeyAgree(k) => k,
        _ => panic!("expected KARI"),
    };
    assert_eq!(kari.recipient_encrypted_keys.len(), 1);
    match &kari.recipient_encrypted_keys[0].rid {
        KeyAgreeRecipientId::RecipientKeyIdentifier {
            ski: out_ski,
            date: out_date,
            other: out_other,
        } => {
            assert_eq!(out_ski, &ski);
            assert_eq!(out_date.as_deref(), Some(&date[..]));
            let out_other = out_other.as_ref().expect("OtherKeyAttribute present");
            assert_eq!(out_other.key_attr_id, other_oid);
            assert_eq!(out_other.key_attr, other_attr);
        }
        other => panic!("expected RKID, got {other:?}"),
    }
}

#[test]
fn rkid_round_trip_with_only_date_omits_other() {
    let ski = vec![0x33u8; 20];
    let date = b"20260101000000Z".to_vec();
    let envelope = build_kari_with_rkid(&ski, Some(date.clone()), None);
    let parsed = parse_envelope(&envelope).expect("parse envelope");
    let kari = match &parsed.all_recipients[0] {
        RecipientInfoVariant::KeyAgree(k) => k,
        _ => panic!("expected KARI"),
    };
    match &kari.recipient_encrypted_keys[0].rid {
        KeyAgreeRecipientId::RecipientKeyIdentifier {
            ski: out_ski,
            date: out_date,
            other: out_other,
        } => {
            assert_eq!(out_ski, &ski);
            assert_eq!(out_date.as_deref(), Some(&date[..]));
            assert!(out_other.is_none(), "other should be absent");
        }
        other => panic!("expected RKID, got {other:?}"),
    }
}

#[test]
fn rkid_round_trip_with_only_other_omits_date() {
    let ski = vec![0xCDu8; 20];
    let other_oid = vec![1u64, 3, 6, 1, 4, 1, 11129, 2, 5, 7];
    let other_attr = vec![]; // absent ANY
    let envelope = build_kari_with_rkid(&ski, None, Some((other_oid.clone(), other_attr.clone())));
    let parsed = parse_envelope(&envelope).expect("parse envelope");
    let kari = match &parsed.all_recipients[0] {
        RecipientInfoVariant::KeyAgree(k) => k,
        _ => panic!("expected KARI"),
    };
    match &kari.recipient_encrypted_keys[0].rid {
        KeyAgreeRecipientId::RecipientKeyIdentifier {
            ski: out_ski,
            date: out_date,
            other: out_other,
        } => {
            assert_eq!(out_ski, &ski);
            assert!(out_date.is_none(), "date should be absent");
            let out_other = out_other.as_ref().expect("OtherKeyAttribute present");
            assert_eq!(out_other.key_attr_id, other_oid);
        }
        other => panic!("expected RKID, got {other:?}"),
    }
}

#[test]
fn rkid_with_no_optional_fields_keeps_round_17_behaviour() {
    let ski = vec![0xEFu8; 20];
    let envelope = build_kari_with_rkid(&ski, None, None);
    let parsed = parse_envelope(&envelope).expect("parse envelope");
    let kari = match &parsed.all_recipients[0] {
        RecipientInfoVariant::KeyAgree(k) => k,
        _ => panic!("expected KARI"),
    };
    match &kari.recipient_encrypted_keys[0].rid {
        KeyAgreeRecipientId::RecipientKeyIdentifier {
            ski: out_ski,
            date,
            other,
        } => {
            assert_eq!(out_ski, &ski);
            assert!(date.is_none());
            assert!(other.is_none());
        }
        other => panic!("expected RKID, got {other:?}"),
    }
}

/// End-to-end scenario: trust store carries 2 certs sharing the same
/// SKI but different validity periods. The envelope's RKID `date`
/// pins the second cert generation; `find_with_temporal_validity`
/// must surface the second cert.
#[test]
fn temporal_lookup_picks_cert_active_at_envelope_date() {
    let shared_pubkey = b"shared-spki-bits-32-bytes-PADDED".to_vec();
    let cert_2024 = Certificate {
        issuer_der: der::write_sequence(b"O=Recipient 2024"),
        serial: vec![0x01],
        spki_pubkey_bits: Some(shared_pubkey.clone()),
        validity: Some((b"20240101000000Z".to_vec(), b"20241231235959Z".to_vec())),
        ..Default::default()
    };
    let cert_2025 = Certificate {
        issuer_der: der::write_sequence(b"O=Recipient 2025"),
        serial: vec![0x02],
        spki_pubkey_bits: Some(shared_pubkey.clone()),
        validity: Some((b"20250101000000Z".to_vec(), b"20251231235959Z".to_vec())),
        ..Default::default()
    };
    // Sanity: both certs derive the same SKI from the shared SPKI bits.
    let ski = cert_2024.subject_key_identifier().expect("SKI");
    assert_eq!(ski, cert_2025.subject_key_identifier().expect("SKI"));

    let mut store = TrustStore::new();
    store.insert_certificate(cert_2024.clone());
    store.insert_certificate(cert_2025.clone());

    // Envelope's RKID date is in 2025 → must hit cert_2025.
    let envelope = build_kari_with_rkid(&ski, Some(b"20250601120000Z".to_vec()), None);
    let parsed = parse_envelope(&envelope).expect("parse");
    let kari = match &parsed.all_recipients[0] {
        RecipientInfoVariant::KeyAgree(k) => k,
        _ => panic!("expected KARI"),
    };
    let (rkid_ski, rkid_date) = match &kari.recipient_encrypted_keys[0].rid {
        KeyAgreeRecipientId::RecipientKeyIdentifier { ski, date, .. } => {
            (ski.clone(), date.clone())
        }
        other => panic!("expected RKID, got {other:?}"),
    };
    let hit = store
        .find_with_temporal_validity(&rkid_ski, rkid_date.as_deref())
        .expect("temporal lookup hit");
    assert_eq!(hit.serial, vec![0x02]);
    assert_eq!(hit.issuer_der, der::write_sequence(b"O=Recipient 2025"));

    // Envelope from 2024 → must hit cert_2024.
    let envelope_old = build_kari_with_rkid(&ski, Some(b"20240601120000Z".to_vec()), None);
    let parsed_old = parse_envelope(&envelope_old).expect("parse old");
    let rkid_date_old = match &parsed_old.all_recipients[0] {
        RecipientInfoVariant::KeyAgree(k) => match &k.recipient_encrypted_keys[0].rid {
            KeyAgreeRecipientId::RecipientKeyIdentifier { date, .. } => date.clone(),
            _ => panic!(),
        },
        _ => panic!(),
    };
    let hit_old = store
        .find_with_temporal_validity(&ski, rkid_date_old.as_deref())
        .expect("temporal lookup hit old");
    assert_eq!(hit_old.serial, vec![0x01]);
}

#[test]
fn temporal_lookup_returns_none_when_no_cert_window_contains_instant() {
    let shared_pubkey = b"shared-spki-bits-32-bytes-PADDED".to_vec();
    let cert = Certificate {
        issuer_der: der::write_sequence(b"O=Old cert"),
        serial: vec![0x42],
        spki_pubkey_bits: Some(shared_pubkey.clone()),
        validity: Some((b"20200101000000Z".to_vec(), b"20201231235959Z".to_vec())),
        ..Default::default()
    };
    let ski = cert.subject_key_identifier().expect("SKI");
    let mut store = TrustStore::new();
    store.insert_certificate(cert);
    // Date in 2026 — no cert window covers it.
    let hit = store.find_with_temporal_validity(&ski, Some(b"20260101000000Z"));
    assert!(hit.is_none(), "no cert should match a 2026 instant");
}

#[test]
fn temporal_lookup_falls_back_to_lookup_when_instant_is_none() {
    let shared_pubkey = b"shared-spki-bits-32-bytes-PADDED".to_vec();
    let cert = Certificate {
        issuer_der: der::write_sequence(b"O=Only cert"),
        serial: vec![0xAA],
        spki_pubkey_bits: Some(shared_pubkey.clone()),
        validity: Some((b"20240101000000Z".to_vec(), b"20241231235959Z".to_vec())),
        ..Default::default()
    };
    let ski = cert.subject_key_identifier().expect("SKI");
    let mut store = TrustStore::new();
    store.insert_certificate(cert);
    let hit = store
        .find_with_temporal_validity(&ski, None)
        .expect("fallback hit");
    assert_eq!(hit.serial, vec![0xAA]);
}
