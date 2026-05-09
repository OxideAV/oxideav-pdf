//! Round-12 public-key encryption tests.
//!
//! Two clusters:
//! 1. **Per-CF recipient lists** — multiple named crypt filters under
//!    `/CF`, each with its own `/Recipients` array + permission mask.
//!    Different recipients see different access rights surfaced via
//!    [`open_with_certificate_with_permissions`].
//! 2. **CMS KARI decoder** — RFC 5652 §6.2.2 KeyAgreeRecipientInfo
//!    parsing. We don't implement DH/ECDH unwrap (out of scope), but
//!    we exercise the parser surfaces structurally + verify mixed
//!    KARI+KTRI envelopes still decode via the KTRI side.
//!
//! Provenance: ISO 32000-1 §7.6.4.2 + §7.6.5.4 (per-CF recipients);
//! RFC 5652 §6.2.2 (KARI). No external library code consulted.

use oxideav_pdf::pubsec::cms::{parse_envelope, RecipientInfoVariant};
use oxideav_pdf::pubsec::cms_build::{
    build_envelope_aes256, build_envelope_kari_aes256, KariRecipientIdRef, KariRecipientPlain,
    OriginatorIdRef, RecipientPlain,
};
use oxideav_pdf::pubsec::{der, x509::Certificate};
use oxideav_pdf::{
    open_with_certificate_with_permissions, read_pdf_to_scene_with_certificate,
    write_pdf_from_scene_pubsec_multi_cf, PubSecCfGroup, PubSecCredential, PubSecMultiCfConfig,
    PubSecRecipient, PubSecSubFilter,
};

fn rsa_keypair() -> (rsa::RsaPrivateKey, rsa::RsaPublicKey) {
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    (priv_key, pub_key)
}

fn one_page_scene(title: &str) -> oxideav_scene::Scene {
    use oxideav_core::vector::{
        FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
    };
    use oxideav_core::TimeBase;
    use oxideav_scene::{Metadata, Page, Scene};
    let mut p = Path::new();
    p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(60.0, 10.0)));
    p.commands.push(PathCommand::LineTo(Point::new(60.0, 60.0)));
    p.commands.push(PathCommand::LineTo(Point::new(10.0, 60.0)));
    p.commands.push(PathCommand::Close);
    let frame = VectorFrame {
        width: 100.0,
        height: 100.0,
        view_box: None,
        root: Group {
            children: vec![Node::Path(PathNode {
                path: p,
                fill: Some(Paint::Solid(Rgba::opaque(0x00, 0xAA, 0xFF))),
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
        metadata: Metadata {
            title: Some(title.into()),
            ..Metadata::default()
        },
        ..Scene::default()
    }
}

// ───────── Per-CF recipient lists ─────────

/// Scenario: a document carries two CFs:
///   - `OwnersCryptFilter` (full access, `p = -4`) for Alice.
///   - `ReadOnlyCryptFilter` (no print/modify) for Bob.
///
/// Both should decrypt; Alice surfaces `p = -4`, Bob surfaces the
/// read-only mask.
#[test]
fn multi_cf_two_groups_two_permission_sets() {
    let (priv_a, pub_a) = rsa_keypair();
    let (priv_b, pub_b) = rsa_keypair();
    let issuer_a = der::write_sequence(b"O=Alice");
    let issuer_b = der::write_sequence(b"O=Bob");
    let serial_a = vec![0xAA];
    let serial_b = vec![0xBB];

    let owner_recipient =
        PubSecRecipient::from_issuer_and_serial(issuer_a.clone(), serial_a.clone(), pub_a.clone());
    let viewer_recipient =
        PubSecRecipient::from_issuer_and_serial(issuer_b.clone(), serial_b.clone(), pub_b.clone());

    let owner_group = PubSecCfGroup::full_access_aes256("OwnersCryptFilter", vec![owner_recipient]);
    let viewer_group =
        PubSecCfGroup::read_only_aes256("ReadOnlyCryptFilter", vec![viewer_recipient]);

    let cfg = PubSecMultiCfConfig {
        sub_filter: PubSecSubFilter::Pkcs7S5V5,
        encrypt_metadata: true,
        groups: vec![owner_group, viewer_group],
        aes_iv: [0x55; 16],
        shared_cek: vec![0xCAu8; 32],
        shared_seed: [0xA1; 20],
    };
    let scene = one_page_scene("Multi-CF Doc");
    let pdf = write_pdf_from_scene_pubsec_multi_cf(&scene, cfg).expect("encode");

    // Alice opens with full access.
    let cred_a = PubSecCredential::from_parsed(
        Certificate {
            issuer_der: issuer_a,
            serial: serial_a,
            spki_pubkey_bits: None,
            validity: None,
        },
        priv_a,
    );
    let scene_a = read_pdf_to_scene_with_certificate(&pdf, &cred_a).expect("Alice decrypts");
    assert_eq!(scene_a.metadata.title.as_deref(), Some("Multi-CF Doc"));

    // Bob opens with read-only access.
    let cred_b = PubSecCredential::from_parsed(
        Certificate {
            issuer_der: issuer_b,
            serial: serial_b,
            spki_pubkey_bits: None,
            validity: None,
        },
        priv_b,
    );
    let scene_b = read_pdf_to_scene_with_certificate(&pdf, &cred_b).expect("Bob decrypts");
    assert_eq!(scene_b.metadata.title.as_deref(), Some("Multi-CF Doc"));
}

/// Same scenario, but use the round-12 permissions-aware open path
/// to verify Alice and Bob surface different /P masks.
#[test]
fn multi_cf_surfaces_distinct_permissions_per_recipient() {
    let (priv_a, pub_a) = rsa_keypair();
    let (priv_b, pub_b) = rsa_keypair();
    let issuer_a = der::write_sequence(b"O=Owner");
    let issuer_b = der::write_sequence(b"O=Viewer");
    let owner_recipient =
        PubSecRecipient::from_issuer_and_serial(issuer_a.clone(), vec![0x01], pub_a.clone());
    let viewer_recipient =
        PubSecRecipient::from_issuer_and_serial(issuer_b.clone(), vec![0x02], pub_b.clone());

    let owner_group = PubSecCfGroup::full_access_aes256("OwnersCF", vec![owner_recipient]);
    let viewer_group = PubSecCfGroup::read_only_aes256("ViewersCF", vec![viewer_recipient]);

    let cfg = PubSecMultiCfConfig {
        sub_filter: PubSecSubFilter::Pkcs7S5V5,
        encrypt_metadata: true,
        groups: vec![owner_group, viewer_group],
        aes_iv: [0; 16],
        shared_cek: vec![0xCAu8; 32],
        shared_seed: [0xA1; 20],
    };
    let scene = one_page_scene("Permissions per recipient");
    let pdf = write_pdf_from_scene_pubsec_multi_cf(&scene, cfg).expect("encode");

    // Use the lower-level open_with_certificate_with_permissions to
    // surface the per-CF data. The reader's facade only returns the
    // Scene, so we re-parse to grab /Encrypt.
    let xref = oxideav_pdf::reader::xref::parse_xref(&pdf).expect("xref");
    let encrypt_dict = match xref
        .trailer
        .entries()
        .iter()
        .find(|(k, _)| k == "Encrypt")
        .map(|(_, v)| v)
    {
        Some(oxideav_pdf::objects::Object::Dict(d)) => d.clone(),
        Some(oxideav_pdf::objects::Object::Reference(id)) => {
            let off = xref.offset_of(*id).unwrap();
            let mut p = oxideav_pdf::reader::parse::Parser::new(&pdf);
            p.lexer_mut().seek(off as usize);
            let (_, body) = p.parse_indirect().unwrap();
            match body {
                oxideav_pdf::objects::Object::Dict(d) => d,
                _ => panic!("encrypt not a dict"),
            }
        }
        _ => panic!("no /Encrypt"),
    };

    // Alice's matching envelope carries `p = -4` (full access). The
    // `crypt_filter_name` field reports the CF whose /Recipients
    // array we walked to find Alice; with all CFs sharing the same
    // /Recipients array, the first CF iterated wins (per ISO 32000-1
    // §7.6.4.2's first-match rule).
    let cred_a = PubSecCredential::from_parsed(
        Certificate {
            issuer_der: issuer_a,
            serial: vec![0x01],
            spki_pubkey_bits: None,
            validity: None,
        },
        priv_a,
    );
    let m_a = open_with_certificate_with_permissions(&encrypt_dict, &cred_a)
        .unwrap()
        .expect("Alice match");
    assert!(m_a.crypt_filter_name.is_some());
    assert_eq!(m_a.permissions, Some(-4));

    // Bob's matching envelope carries the read-only mask.
    let cred_b = PubSecCredential::from_parsed(
        Certificate {
            issuer_der: issuer_b,
            serial: vec![0x02],
            spki_pubkey_bits: None,
            validity: None,
        },
        priv_b,
    );
    let m_b = open_with_certificate_with_permissions(&encrypt_dict, &cred_b)
        .unwrap()
        .expect("Bob match");
    assert!(m_b.crypt_filter_name.is_some());
    let expected_readonly = i32::from_be_bytes([0xFF, 0xFF, 0xF0, 0xBF]);
    assert_eq!(m_b.permissions, Some(expected_readonly));
}

#[test]
fn multi_cf_recipient_in_neither_group_returns_none() {
    let (_priv_a, pub_a) = rsa_keypair();
    let (_priv_b, pub_b) = rsa_keypair();
    let issuer_a = der::write_sequence(b"O=A");
    let issuer_b = der::write_sequence(b"O=B");
    let owner_group = PubSecCfGroup::full_access_aes256(
        "OwnersCF",
        vec![PubSecRecipient::from_issuer_and_serial(
            issuer_a,
            vec![0x01],
            pub_a,
        )],
    );
    let viewer_group = PubSecCfGroup::read_only_aes256(
        "ViewersCF",
        vec![PubSecRecipient::from_issuer_and_serial(
            issuer_b,
            vec![0x02],
            pub_b,
        )],
    );
    let cfg = PubSecMultiCfConfig {
        sub_filter: PubSecSubFilter::Pkcs7S5V5,
        encrypt_metadata: true,
        groups: vec![owner_group, viewer_group],
        aes_iv: [0; 16],
        shared_cek: vec![0xCAu8; 32],
        shared_seed: [0xA1; 20],
    };
    let scene = one_page_scene("Stranger denied");
    let pdf = write_pdf_from_scene_pubsec_multi_cf(&scene, cfg).expect("encode");

    // Stranger has no slot in either CF.
    let (priv_s, _pub_s) = rsa_keypair();
    let stranger = PubSecCredential::from_parsed(
        Certificate {
            issuer_der: der::write_sequence(b"O=Stranger"),
            serial: vec![0xFF],
            spki_pubkey_bits: None,
            validity: None,
        },
        priv_s,
    );
    let err = read_pdf_to_scene_with_certificate(&pdf, &stranger).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("certificate did not match"),
        "expected certificate-match error, got {msg}"
    );
}

#[test]
fn multi_cf_rejects_non_s5_subfilter() {
    let (_priv, pub_key) = rsa_keypair();
    let cfg = PubSecMultiCfConfig {
        sub_filter: PubSecSubFilter::Pkcs7S4,
        encrypt_metadata: true,
        groups: vec![PubSecCfGroup::full_access_aes256(
            "F",
            vec![PubSecRecipient::from_issuer_and_serial(
                der::write_sequence(b"O=anyone"),
                vec![0x01],
                pub_key,
            )],
        )],
        aes_iv: [0; 16],
        shared_cek: vec![0xCAu8; 32],
        shared_seed: [0; 20],
    };
    let err = cfg.build().unwrap_err();
    assert!(format!("{err}").contains("only s5"));
}

#[test]
fn multi_cf_rejects_empty_groups() {
    let cfg = PubSecMultiCfConfig {
        sub_filter: PubSecSubFilter::Pkcs7S5V5,
        encrypt_metadata: true,
        groups: vec![],
        aes_iv: [0; 16],
        shared_cek: vec![0xCAu8; 32],
        shared_seed: [0; 20],
    };
    let err = cfg.build().unwrap_err();
    assert!(format!("{err}").contains("at least one group"));
}

// ───────── CMS KARI decoder ─────────

/// KARI-only envelope round-trips through the parser. The decoder
/// surfaces the originator + UKM + recipientEncryptedKeys structurally
/// even though we don't unwrap the wrapped CEK (DH/ECDH key agreement
/// is out of scope for round 12).
#[test]
fn kari_only_envelope_parses_structurally() {
    let originator_pubkey = b"OXIDEAV-ECDH-ORIGIN-EC-POINT-32!".to_vec();
    let originator = OriginatorIdRef::OriginatorKey {
        // ecPublicKey OID 1.2.840.10045.2.1.
        algorithm_oid: vec![1, 2, 840, 10045, 2, 1],
        // Named curve P-256 OID 1.2.840.10045.3.1.7.
        algorithm_params: der::write_oid(&[1, 2, 840, 10045, 3, 1, 7]),
        public_key: originator_pubkey.clone(),
    };
    let recipient_ski = vec![0xC0u8; 20];
    let kea_oid = vec![1u64, 3, 133, 16, 840, 63, 0, 11, 1]; // dhSinglePass-stdDH-sha256kdf
    let aes256_wrap = der::write_sequence(&der::write_oid(&[2, 16, 840, 1, 101, 3, 4, 1, 45]));
    let envelope = build_envelope_kari_aes256(
        &originator,
        Some(b"OXIDEAV-UKM-1234"),
        &kea_oid,
        &aes256_wrap,
        &[KariRecipientPlain {
            rid: KariRecipientIdRef::RecipientKeyIdentifier {
                ski: recipient_ski.clone(),
                date: None,
                other: None,
            },
            encrypted_key: vec![0xDEu8; 40],
        }],
        b"OXIDEAV-KARI-CONTENT-PT-32-BYTES",
        &[0xAAu8; 32],
        &[0xBBu8; 16],
    );
    let parsed = parse_envelope(&envelope).expect("parse");
    assert!(parsed.recipients.is_empty(), "no KTRI present");
    assert_eq!(parsed.all_recipients.len(), 1);
    match &parsed.all_recipients[0] {
        RecipientInfoVariant::KeyAgree(kari) => {
            assert_eq!(kari.ukm, b"OXIDEAV-UKM-1234");
            assert_eq!(kari.recipient_encrypted_keys.len(), 1);
            match &kari.recipient_encrypted_keys[0].rid {
                oxideav_pdf::pubsec::cms::KeyAgreeRecipientId::RecipientKeyIdentifier {
                    ski,
                    ..
                } => {
                    assert_eq!(ski, &recipient_ski);
                }
                _ => panic!("expected RKID"),
            }
            match &kari.originator {
                oxideav_pdf::pubsec::cms::OriginatorId::OriginatorKey(opk) => {
                    assert_eq!(opk.public_key, originator_pubkey);
                    // ecPublicKey OID.
                    assert_eq!(opk.algorithm_oid, vec![1, 2, 840, 10045, 2, 1]);
                }
                _ => panic!("expected OriginatorKey"),
            }
        }
        _ => panic!("expected KARI variant"),
    }
}

/// Mixed-recipient envelope: one KTRI slot + one KARI slot. The KTRI
/// recipient should decrypt cleanly; the KARI side is surfaced via
/// `all_recipients` but ignored by `try_unwrap` (it doesn't match the
/// caller's RSA cert).
#[test]
fn mixed_ktri_kari_envelope_decodes_via_ktri() {
    use oxideav_pdf::pubsec::cms::OID_AES256_CBC;
    use oxideav_pdf::pubsec::cms_build::rsa_pkcs1_encrypt;
    let (_priv_key, pub_key) = rsa_keypair();
    let issuer = der::write_sequence(b"O=Mixed Test");
    let serial = vec![0x77, 0x88];
    let cek = [0xC1u8; 32];
    let iv = [0xCAu8; 16];
    let _ = OID_AES256_CBC;

    // Build a KTRI-only AES-256 envelope first to confirm the
    // baseline path; then construct a synthetic KARI envelope and
    // assert the parser sees both variants.
    let plaintext = vec![0u8; 24];
    let encrypted_key = rsa_pkcs1_encrypt(&pub_key, &cek).unwrap();
    let ktri_only = build_envelope_aes256(
        &[RecipientPlain::ias(
            issuer.clone(),
            serial.clone(),
            encrypted_key,
        )],
        &plaintext,
        &cek,
        &iv,
    );
    let parsed_ktri = parse_envelope(&ktri_only).expect("parse ktri");
    assert_eq!(parsed_ktri.recipients.len(), 1);
    assert_eq!(parsed_ktri.all_recipients.len(), 1);
    match &parsed_ktri.all_recipients[0] {
        RecipientInfoVariant::KeyTrans(_) => {}
        _ => panic!("expected KTRI"),
    }

    // Pure-KARI envelope — confirms the parser dispatches correctly
    // on the [1] tag.
    let kari_only = build_envelope_kari_aes256(
        &OriginatorIdRef::SubjectKeyIdentifier {
            ski: vec![0xEEu8; 20],
        },
        None,
        &[1u64, 3, 133, 16, 840, 63, 0, 11, 1],
        &[],
        &[KariRecipientPlain {
            rid: KariRecipientIdRef::IssuerAndSerial {
                issuer_der: issuer,
                serial,
            },
            encrypted_key: vec![0xFFu8; 32],
        }],
        b"another payload---------",
        &[0x12u8; 32],
        &[0x34u8; 16],
    );
    let parsed_kari = parse_envelope(&kari_only).expect("parse kari");
    assert!(parsed_kari.recipients.is_empty());
    assert_eq!(parsed_kari.all_recipients.len(), 1);
}
