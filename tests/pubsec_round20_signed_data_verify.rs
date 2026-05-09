//! Round-20 — end-to-end CMS SignedData signature verification.
//!
//! Builds a complete `ContentInfo` wrapping a `SignedData` (RFC 5652
//! §5) for each algorithm combination supported by the round-20
//! verifier, parses it via [`parse_signed_data`], and asserts that
//! [`verify_signature`] returns `Ok(true)` for the genuine signature
//! and either `Ok(false)` or `Err` for tamper variants.
//!
//! Algorithm combinations exercised end-to-end:
//!
//! | digestAlgorithm | signatureAlgorithm                |
//! |-----------------|-----------------------------------|
//! | SHA-256         | RSA-PKCS#1 v1.5 (rsaEncryption)   |
//! | SHA-256         | RSA-PSS (id-RSASSA-PSS)           |
//! | SHA-256         | ECDSA on P-256 (ecdsa-with-SHA256)|
//! | SHA-384         | ECDSA on P-384 (ecdsa-with-SHA384)|
//! | SHA-512         | ECDSA on P-521 (ecdsa-with-SHA512)|
//!
//! Provenance: RFC 5652 §5.4 + RFC 8017 + RFC 5754 + RFC 5758. No
//! third-party CMS / OpenSSL source consulted.

use oxideav_pdf::pubsec::der;
use oxideav_pdf::pubsec::signed_data::{parse_signed_data, SignerIdentifier};
use oxideav_pdf::pubsec::verify::{
    build_message_digest_attribute_der, implicit_signed_attrs_tlv, pack_signed_attrs_implicit,
    rsa_pubkey_to_pkcs1_der, signed_attrs_to_be_signed, verify_signature, AttachedContent, HashAlg,
    OID_ATTR_MESSAGE_DIGEST, OID_ECDSA_WITH_SHA256, OID_ECDSA_WITH_SHA384, OID_ECDSA_WITH_SHA512,
    OID_EC_PUBLIC_KEY, OID_NAMED_CURVE_P256, OID_NAMED_CURVE_P384, OID_NAMED_CURVE_P521,
    OID_RSA_ENCRYPTION, OID_RSA_PSS, OID_SHA256, OID_SHA384, OID_SHA512,
};
use oxideav_pdf::pubsec::x509::Certificate;

// -------------------------------------------------------------------
// Common SignedData builder
// -------------------------------------------------------------------

/// Build a complete CMS `ContentInfo` (id-signedData) DER blob with
/// one IAS signer, an attached `eContent` payload, and the supplied
/// per-signer fields. The returned bytes are exactly what
/// [`parse_signed_data`] consumes.
#[allow(clippy::too_many_arguments)]
fn build_signed_data(
    issuer_der: &[u8],
    serial: &[u8],
    digest_oid: &[u64],
    digest_alg_params: &[u8],
    signature_oid: &[u64],
    sig_alg_params: &[u8],
    signed_attrs_body: Option<&[u8]>,
    signature_bytes: &[u8],
    eci_payload: &[u8],
) -> Vec<u8> {
    // SignerInfo SEQUENCE.
    let mut si_body = der::write_integer_u64(1); // v=1 → IAS

    // sid = IssuerAndSerialNumber
    let ias_body = {
        let mut b = issuer_der.to_vec();
        b.extend_from_slice(&der::write_integer_bytes(serial));
        b
    };
    si_body.extend_from_slice(&der::write_sequence(&ias_body));

    // digestAlgorithm AlgorithmIdentifier
    let da_alg = {
        let mut b = der::write_oid(digest_oid);
        b.extend_from_slice(digest_alg_params);
        der::write_sequence(&b)
    };
    si_body.extend_from_slice(&da_alg);

    // [0] IMPLICIT signedAttrs SET OF Attribute OPTIONAL
    if let Some(sa_body) = signed_attrs_body {
        si_body.extend_from_slice(&implicit_signed_attrs_tlv(sa_body));
    }

    // signatureAlgorithm AlgorithmIdentifier
    let sig_alg = {
        let mut b = der::write_oid(signature_oid);
        b.extend_from_slice(sig_alg_params);
        der::write_sequence(&b)
    };
    si_body.extend_from_slice(&sig_alg);
    si_body.extend_from_slice(&der::write_octet_string(signature_bytes));
    let signer_info = der::write_sequence(&si_body);

    // SignedData fields.
    let da_set = der::write_set(&da_alg);
    let eci_body = {
        let mut b = der::write_oid(&[1u64, 2, 840, 113549, 1, 7, 1]); // id-data
        let octet = der::write_octet_string(eci_payload);
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

    // Outer ContentInfo wrapper.
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

fn fake_ec_cert(
    issuer_der: Vec<u8>,
    serial: Vec<u8>,
    sec1_pubkey: Vec<u8>,
    named_curve_oid: &[u64],
) -> Certificate {
    Certificate {
        issuer_der,
        serial,
        spki_pubkey_bits: Some(sec1_pubkey),
        spki_algorithm_oid: Some(OID_EC_PUBLIC_KEY.to_vec()),
        spki_algorithm_params: Some(der::write_oid(named_curve_oid)),
        ..Default::default()
    }
}

// -------------------------------------------------------------------
// SHA-256 + RSA-PKCS#1 v1.5 — full signed_attrs path with messageDigest
// -------------------------------------------------------------------

#[test]
fn end_to_end_sha256_rsa_pkcs1v15_with_signed_attrs() {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::traits::SignatureScheme;
    use sha2::Sha256;

    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R20 RSA E2E");
    let serial = vec![0x42];
    let cert = fake_rsa_cert(
        issuer_der.clone(),
        serial.clone(),
        rsa_pubkey_to_pkcs1_der(&pub_key),
    );

    // Encapsulated content + its SHA-256.
    let payload = b"OXIDEAV-R20-RSA-PKCS1V15-PAYLOAD";
    let content_hash = HashAlg::Sha256.hash(payload);

    // Build signedAttrs with a messageDigest matching the content hash.
    let md_attr = build_message_digest_attribute_der(&content_hash);
    let attrs_body = pack_signed_attrs_implicit(&[md_attr]);

    // Sign the canonical (universal-SET-tag) form of the attrs body.
    let to_be_signed = signed_attrs_to_be_signed(&attrs_body);
    let tbs_hash = HashAlg::Sha256.hash(&to_be_signed);
    let signature = Pkcs1v15Sign::new::<Sha256>()
        .sign(None::<&mut rsa::rand_core::OsRng>, &priv_key, &tbs_hash)
        .expect("RSA-PKCS1v15 sign");

    let blob = build_signed_data(
        &issuer_der,
        &serial,
        &OID_SHA256,
        &der::write_null(),
        &OID_RSA_ENCRYPTION,
        &der::write_null(),
        Some(&attrs_body),
        &signature,
        payload,
    );
    let parsed = parse_signed_data(&blob).expect("parse");

    // Sanity: the parser surfaced exactly the bytes we encoded.
    assert_eq!(parsed.signer_infos.len(), 1);
    let signer = &parsed.signer_infos[0];
    assert_eq!(signer.signed_attrs_der.as_deref(), Some(&attrs_body[..]));
    match &signer.sid {
        SignerIdentifier::IssuerAndSerial(ias) => {
            assert_eq!(ias.issuer_der, issuer_der);
            assert_eq!(ias.serial, serial);
        }
        other => panic!("expected IAS got {other:?}"),
    }
    assert_eq!(signer.digest_algorithm_oid, OID_SHA256);
    assert_eq!(signer.signature_algorithm_oid, OID_RSA_ENCRYPTION);

    let cert_pool = std::slice::from_ref(&cert);
    let ok = verify_signature(signer, cert_pool, AttachedContent::FromEContent(&parsed))
        .expect("verify dispatch");
    assert!(ok, "RSA-PKCS1v15 + SHA-256 SignedData must verify");

    // Tamper detection: flip a byte of the signature.
    let mut bad_signer = signer.clone();
    bad_signer.signature[0] ^= 0xFF;
    let bad = verify_signature(
        &bad_signer,
        cert_pool,
        AttachedContent::FromEContent(&parsed),
    )
    .expect("dispatch");
    assert!(!bad, "tampered signature must not verify");

    // Tamper detection (eContent path): re-build the SignedData with a
    // tweaked payload so the parsed SignedData carries the wrong
    // eContent for the original signed messageDigest.
    let mut tampered_payload = payload.to_vec();
    tampered_payload[0] ^= 0x01;
    let blob_tampered = build_signed_data(
        &issuer_der,
        &serial,
        &OID_SHA256,
        &der::write_null(),
        &OID_RSA_ENCRYPTION,
        &der::write_null(),
        Some(&attrs_body),
        &signature,
        &tampered_payload,
    );
    let parsed_t = parse_signed_data(&blob_tampered).expect("parse tampered");
    let bad_eci = verify_signature(
        &parsed_t.signer_infos[0],
        &[cert],
        AttachedContent::FromEContent(&parsed_t),
    )
    .expect("dispatch");
    assert!(!bad_eci, "tampered eContent must fail messageDigest check");
}

// -------------------------------------------------------------------
// SHA-256 + RSA-PSS (no signedAttrs)
// -------------------------------------------------------------------

#[test]
fn end_to_end_sha256_rsa_pss_no_signed_attrs() {
    use rsa::pss::Pss;
    use rsa::traits::SignatureScheme;
    use sha2::Sha256;

    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let issuer_der = der::write_sequence(b"O=R20 RSA-PSS E2E");
    let serial = vec![0x21, 0x37];
    let cert = fake_rsa_cert(
        issuer_der.clone(),
        serial.clone(),
        rsa_pubkey_to_pkcs1_der(&pub_key),
    );
    let payload = b"OXIDEAV-R20-RSA-PSS-PAYLOAD";
    let payload_hash = HashAlg::Sha256.hash(payload);
    let signature = Pss::new::<Sha256>()
        .sign(Some(&mut rng), &priv_key, &payload_hash)
        .expect("RSA-PSS sign");

    let blob = build_signed_data(
        &issuer_der,
        &serial,
        &OID_SHA256,
        &der::write_null(),
        &OID_RSA_PSS,
        // PSS parameters carry MGF1 hash + salt-length but the round-20
        // verifier accepts the OID with default parameters when the
        // digestAlgorithm names the same hash; emit a NULL parameter
        // body so the parser still walks the AlgorithmIdentifier shape.
        &der::write_null(),
        None,
        &signature,
        payload,
    );
    let parsed = parse_signed_data(&blob).expect("parse");
    let ok = verify_signature(
        &parsed.signer_infos[0],
        &[cert],
        AttachedContent::FromEContent(&parsed),
    )
    .expect("dispatch");
    assert!(ok);
}

// -------------------------------------------------------------------
// SHA-256 + ECDSA-P256
// -------------------------------------------------------------------

#[test]
fn end_to_end_sha256_ecdsa_p256() {
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};

    let scalar = [0x21u8; 32];
    let signing_key = SigningKey::from_slice(&scalar).expect("scalar");
    let pub_sec1 = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let issuer_der = der::write_sequence(b"O=R20 ECDSA P-256");
    let serial = vec![0xC0, 0xC0];
    let cert = fake_ec_cert(
        issuer_der.clone(),
        serial.clone(),
        pub_sec1,
        &OID_NAMED_CURVE_P256,
    );
    let payload = b"OXIDEAV-R20-ECDSA-P256-PAYLOAD";
    let sig: Signature = signing_key.sign(payload);
    let sig_der = sig.to_der().as_bytes().to_vec();

    let blob = build_signed_data(
        &issuer_der,
        &serial,
        &OID_SHA256,
        &der::write_null(),
        &OID_ECDSA_WITH_SHA256,
        &[], // ECDSA AlgorithmIdentifier in CMS has absent parameters (RFC 5754 §3.2)
        None,
        &sig_der,
        payload,
    );
    let parsed = parse_signed_data(&blob).expect("parse");
    let ok = verify_signature(
        &parsed.signer_infos[0],
        &[cert],
        AttachedContent::FromEContent(&parsed),
    )
    .expect("dispatch");
    assert!(ok);
}

// -------------------------------------------------------------------
// SHA-384 + ECDSA-P384
// -------------------------------------------------------------------

#[test]
fn end_to_end_sha384_ecdsa_p384() {
    use p384::ecdsa::signature::Signer as _;
    use p384::ecdsa::{Signature, SigningKey};

    let scalar = [0x35u8; 48];
    let signing_key = SigningKey::from_slice(&scalar).expect("scalar");
    let pub_sec1 = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let issuer_der = der::write_sequence(b"O=R20 ECDSA P-384");
    let serial = vec![0x38, 0x84];
    let cert = fake_ec_cert(
        issuer_der.clone(),
        serial.clone(),
        pub_sec1,
        &OID_NAMED_CURVE_P384,
    );
    let payload = b"OXIDEAV-R20-ECDSA-P384-PAYLOAD";
    let sig: Signature = signing_key.sign(payload);
    let sig_der = sig.to_der().as_bytes().to_vec();

    let blob = build_signed_data(
        &issuer_der,
        &serial,
        &OID_SHA384,
        &der::write_null(),
        &OID_ECDSA_WITH_SHA384,
        &[],
        None,
        &sig_der,
        payload,
    );
    let parsed = parse_signed_data(&blob).expect("parse");
    let ok = verify_signature(
        &parsed.signer_infos[0],
        &[cert],
        AttachedContent::FromEContent(&parsed),
    )
    .expect("dispatch");
    assert!(ok);
}

// -------------------------------------------------------------------
// SHA-512 + ECDSA-P521
// -------------------------------------------------------------------

#[test]
fn end_to_end_sha512_ecdsa_p521() {
    use p521::ecdsa::signature::Signer as _;
    use p521::ecdsa::{Signature, SigningKey, VerifyingKey};

    let mut scalar = [0u8; 66];
    scalar[1] = 0x01;
    scalar[65] = 0x42;
    let signing_key = SigningKey::from_slice(&scalar).expect("scalar");
    let verifying_key = VerifyingKey::from(&signing_key);
    let pub_sec1 = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let issuer_der = der::write_sequence(b"O=R20 ECDSA P-521");
    let serial = vec![0x52, 0x21];
    let cert = fake_ec_cert(
        issuer_der.clone(),
        serial.clone(),
        pub_sec1,
        &OID_NAMED_CURVE_P521,
    );
    let payload = b"OXIDEAV-R20-ECDSA-P521-PAYLOAD";
    let sig: Signature = signing_key.sign(payload);
    let sig_der = sig.to_der().as_bytes().to_vec();

    let blob = build_signed_data(
        &issuer_der,
        &serial,
        &OID_SHA512,
        &der::write_null(),
        &OID_ECDSA_WITH_SHA512,
        &[],
        None,
        &sig_der,
        payload,
    );
    let parsed = parse_signed_data(&blob).expect("parse");
    let ok = verify_signature(
        &parsed.signer_infos[0],
        &[cert],
        AttachedContent::FromEContent(&parsed),
    )
    .expect("dispatch");
    assert!(ok);
}

// -------------------------------------------------------------------
// Negative — cert not in pool returns Err
// -------------------------------------------------------------------

#[test]
fn end_to_end_cert_not_in_pool_errors() {
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    let scalar = [0x55u8; 32];
    let signing_key = SigningKey::from_slice(&scalar).expect("scalar");
    let pub_sec1 = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let issuer_der = der::write_sequence(b"O=Original");
    let serial = vec![0x01];
    let payload = b"some-payload";
    let sig: Signature = signing_key.sign(payload);
    let sig_der = sig.to_der().as_bytes().to_vec();

    let blob = build_signed_data(
        &issuer_der,
        &serial,
        &OID_SHA256,
        &der::write_null(),
        &OID_ECDSA_WITH_SHA256,
        &[],
        None,
        &sig_der,
        payload,
    );
    let parsed = parse_signed_data(&blob).expect("parse");

    // Pool contains a *different* cert.
    let other_cert = fake_ec_cert(
        der::write_sequence(b"O=Other"),
        vec![0x02],
        pub_sec1,
        &OID_NAMED_CURVE_P256,
    );
    let err = verify_signature(
        &parsed.signer_infos[0],
        &[other_cert],
        AttachedContent::FromEContent(&parsed),
    )
    .expect_err("must error when signer cert not in pool");
    assert!(format!("{err}").contains("no certificate"));
}

// -------------------------------------------------------------------
// messageDigest attribute round-trip — ensure the OID constant is
// re-exported from the verify module's public surface (callers will
// build their own signedAttrs using these helpers).
// -------------------------------------------------------------------

#[test]
fn message_digest_attr_oid_is_reachable() {
    assert_eq!(OID_ATTR_MESSAGE_DIGEST, [1, 2, 840, 113549, 1, 9, 4]);
}
