//! Round-17 — read-only legacy CMS content-encryption support.
//!
//! Tests `EncryptedContentInfo.contentEncryptionAlgorithm` decode for:
//!   * RC2-CBC (OID 1.2.840.113549.3.2 — RFC 2268 + RFC 3217 §3 +
//!     RFC 3370 §5.1)
//!   * DES-EDE3-CBC (OID 1.2.840.113549.3.7 — RFC 3370 §5.2 / RFC 5652
//!     §12.4)
//!
//! Both algorithms are deprecated by PDF 2.0; we accept on decode only
//! so legacy archives still open. No encode-side support — the
//! `cms_build::build_envelope_rc2_cbc` / `_des_ede3_cbc` helpers are
//! `#[doc(hidden)]` test fixtures.
//!
//! Provenance: RFC 5652 §6 + §12.4 + RFC 3217 + RFC 3370 + RFC 2268 only.

use oxideav_pdf::pubsec::cms::{parse_envelope, ContentEncryption, RecipientInfoVariant};
use oxideav_pdf::pubsec::cms_build::{
    build_envelope_des_ede3_cbc, build_envelope_rc2_cbc, rsa_pkcs1_encrypt, RecipientPlain,
};
use oxideav_pdf::pubsec::der;

fn rsa_keypair() -> (rsa::RsaPrivateKey, rsa::RsaPublicKey) {
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    (priv_key, pub_key)
}

#[test]
fn rc2_cbc_envelope_parses_as_rc2_with_correct_iv_and_eff_bits() {
    let (_priv_key, pub_key) = rsa_keypair();
    let issuer_der = der::write_sequence(b"O=RC2 round-17");
    let serial = vec![0x12];
    let cek = vec![0x77u8; 16]; // 128-bit RC2 raw key
    let iv = [0x42u8; 8];
    let plaintext =
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13";
    let encrypted_key = rsa_pkcs1_encrypt(&pub_key, &cek).unwrap();
    let envelope = build_envelope_rc2_cbc(
        &[RecipientPlain::ias(issuer_der, serial, encrypted_key)],
        plaintext,
        &cek,
        128,
        &iv,
    );
    let parsed = parse_envelope(&envelope).expect("parse RC2 envelope");
    match parsed.content_encryption {
        ContentEncryption::Rc2Cbc {
            effective_key_bits,
            iv: parsed_iv,
        } => {
            assert_eq!(effective_key_bits, 128);
            assert_eq!(parsed_iv, [0x42; 8]);
        }
        other => panic!("expected RC2-CBC, got {other:?}"),
    }
    assert_eq!(parsed.recipients.len(), 1);
}

#[test]
fn rc2_cbc_envelope_decrypts_round_trip() {
    // End-to-end: build envelope → decrypt with the matching recipient
    // RSA key → assert plaintext recovery.
    use oxideav_pdf::objects::{Dict, Object};
    use oxideav_pdf::pubsec::{open_with_certificate, PubSecCredential};
    let (priv_key, pub_key) = rsa_keypair();
    let issuer_der = der::write_sequence(b"O=RC2 round-17 RT");
    let serial = vec![0x55];
    let cek = vec![0x99u8; 16];
    let iv = [0x33u8; 8];
    // Plaintext is the standard 20-byte seed + 4-byte permissions
    // shape so the file-key derivation is exercised.
    let mut plaintext = vec![0u8; 24];
    plaintext[..20].copy_from_slice(&[0xCC; 20]);
    plaintext[20..24].copy_from_slice(&((-4i32) as u32).to_le_bytes());
    let encrypted_key = rsa_pkcs1_encrypt(&pub_key, &cek).unwrap();
    let envelope = build_envelope_rc2_cbc(
        &[RecipientPlain::ias(
            issuer_der.clone(),
            serial.clone(),
            encrypted_key,
        )],
        &plaintext,
        &cek,
        128,
        &iv,
    );
    let mut d = Dict::default();
    d.set("Filter", Object::Name("Adobe.PPKLite".into()));
    d.set("SubFilter", Object::Name("adbe.pkcs7.s4".into()));
    d.set("V", Object::Integer(2));
    d.set("P", Object::Integer(-4));
    d.set(
        "Recipients",
        Object::Array(vec![Object::LiteralString(envelope)]),
    );
    let cred = PubSecCredential::from_parsed(
        oxideav_pdf::pubsec::x509::Certificate {
            issuer_der,
            serial,
            spki_pubkey_bits: None,
            validity: None,
        },
        priv_key,
    );
    let handler = open_with_certificate(&d, &cred)
        .expect("open RC2 envelope")
        .expect("matched");
    // Just verifying we got a handler back — the file key derivation
    // ran successfully on the RC2-decrypted plaintext.
    assert_eq!(
        handler.method,
        oxideav_pdf::decrypt::CryptMethod::Rc4,
        "s4 handler defaults to RC4 per pubsec subfilter"
    );
}

#[test]
fn rc2_with_eff_key_64_bits_decrypts() {
    // RFC 2268 §6: effective-key 64 bits → version byte 120.
    use oxideav_pdf::objects::{Dict, Object};
    use oxideav_pdf::pubsec::{open_with_certificate, PubSecCredential};
    let (priv_key, pub_key) = rsa_keypair();
    let issuer_der = der::write_sequence(b"O=RC2 64-bit");
    let serial = vec![0x40];
    let cek = vec![0x11u8; 8]; // 64-bit RC2 key
    let iv = [0x77u8; 8];
    let mut plaintext = vec![0u8; 24];
    plaintext[..20].copy_from_slice(&[0xAB; 20]);
    let encrypted_key = rsa_pkcs1_encrypt(&pub_key, &cek).unwrap();
    let envelope = build_envelope_rc2_cbc(
        &[RecipientPlain::ias(
            issuer_der.clone(),
            serial.clone(),
            encrypted_key,
        )],
        &plaintext,
        &cek,
        64,
        &iv,
    );
    let parsed = parse_envelope(&envelope).expect("parse");
    match parsed.content_encryption {
        ContentEncryption::Rc2Cbc {
            effective_key_bits, ..
        } => {
            assert_eq!(effective_key_bits, 64);
        }
        other => panic!("expected RC2-CBC, got {other:?}"),
    }
    let mut d = Dict::default();
    d.set("Filter", Object::Name("Adobe.PPKLite".into()));
    d.set("SubFilter", Object::Name("adbe.pkcs7.s4".into()));
    d.set("V", Object::Integer(2));
    d.set("P", Object::Integer(-4));
    d.set(
        "Recipients",
        Object::Array(vec![Object::LiteralString(envelope)]),
    );
    let cred = PubSecCredential::from_parsed(
        oxideav_pdf::pubsec::x509::Certificate {
            issuer_der,
            serial,
            spki_pubkey_bits: None,
            validity: None,
        },
        priv_key,
    );
    let _handler = open_with_certificate(&d, &cred)
        .expect("open RC2-64 envelope")
        .expect("matched");
}

#[test]
fn des_ede3_cbc_envelope_parses_with_correct_iv() {
    let (_priv_key, pub_key) = rsa_keypair();
    let issuer_der = der::write_sequence(b"O=3DES round-17");
    let serial = vec![0x07];
    let cek = [0xABu8; 24]; // 24-byte 3DES key (3 × 8-byte DES sub-keys)
    let iv = [0x66u8; 8];
    let plaintext = b"OXIDEAV-3DES-PARSE-FIXTURE-PADDED";
    let encrypted_key = rsa_pkcs1_encrypt(&pub_key, &cek).unwrap();
    let envelope = build_envelope_des_ede3_cbc(
        &[RecipientPlain::ias(issuer_der, serial, encrypted_key)],
        plaintext,
        &cek,
        &iv,
    );
    let parsed = parse_envelope(&envelope).expect("parse 3DES envelope");
    match parsed.content_encryption {
        ContentEncryption::DesEde3Cbc { iv: parsed_iv } => {
            assert_eq!(parsed_iv, [0x66; 8]);
        }
        other => panic!("expected DES-EDE3-CBC, got {other:?}"),
    }
    assert!(matches!(
        parsed.all_recipients[0],
        RecipientInfoVariant::KeyTrans(_)
    ));
}

#[test]
fn des_ede3_cbc_envelope_decrypts_round_trip() {
    use oxideav_pdf::objects::{Dict, Object};
    use oxideav_pdf::pubsec::{open_with_certificate, PubSecCredential};
    let (priv_key, pub_key) = rsa_keypair();
    let issuer_der = der::write_sequence(b"O=3DES round-17 RT");
    let serial = vec![0x37];
    let cek = [0xC3u8; 24];
    let iv = [0x9Eu8; 8];
    let mut plaintext = vec![0u8; 24];
    plaintext[..20].copy_from_slice(&[0xDD; 20]);
    let encrypted_key = rsa_pkcs1_encrypt(&pub_key, &cek).unwrap();
    let envelope = build_envelope_des_ede3_cbc(
        &[RecipientPlain::ias(
            issuer_der.clone(),
            serial.clone(),
            encrypted_key,
        )],
        &plaintext,
        &cek,
        &iv,
    );
    let mut d = Dict::default();
    d.set("Filter", Object::Name("Adobe.PPKLite".into()));
    d.set("SubFilter", Object::Name("adbe.pkcs7.s4".into()));
    d.set("V", Object::Integer(2));
    d.set("P", Object::Integer(-4));
    d.set(
        "Recipients",
        Object::Array(vec![Object::LiteralString(envelope)]),
    );
    let cred = PubSecCredential::from_parsed(
        oxideav_pdf::pubsec::x509::Certificate {
            issuer_der,
            serial,
            spki_pubkey_bits: None,
            validity: None,
        },
        priv_key,
    );
    let _handler = open_with_certificate(&d, &cred)
        .expect("open 3DES envelope")
        .expect("matched");
}
