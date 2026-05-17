//! Round-34 — RFC 3161 Document Time-Stamp writer.
//!
//! Adds an incremental-update revision to an already-rendered PDF whose
//! AcroForm gains a `/FT /Sig` field carrying a *signature dictionary*
//! with `/Type /DocTimeStamp`, `/SubFilter /ETSI.RFC3161`, and a
//! `/Contents <…hex…>` literal holding an RFC 3161 `TimeStampToken`
//! (the entire token, not a CMS-wrapped digest of one).
//!
//! Provenance:
//! * **ISO 32000-1 §12.8.5** — *Document Time-Stamp digital signature*
//!   (the `/DocTimeStamp` sig variant whose `/SubFilter` is
//!   `ETSI.RFC3161` and whose `/Contents` is the TST).
//! * **RFC 3161 §2.4** — TimeStampReq / TimeStampResp / TimeStampToken
//!   shape and the embedded `TSTInfo`.
//! * **RFC 5816** — adds the optional `ESSCertIDv2` signed attribute
//!   (we don't emit it in round 34 — the mock TSA is bare RFC 3161).
//!
//! # Public surface
//!
//! * [`TsaSigner`] — async-friendly trait the caller implements. Takes
//!   a [`MessageImprint`] (hash-algorithm OID + raw message-digest
//!   octets) and returns the full TimeStampToken bytes (an outer DER
//!   `ContentInfo` of type `id-signedData` whose eContent is a
//!   `TSTInfo` SEQUENCE).
//! * [`MockTsaSigner`] — in-tree reference implementation. Generates a
//!   self-signed TST around a fresh RSA-2048 / SHA-256 SignerInfo. Used
//!   by the round-34 test fixture and by callers who want a fully
//!   self-contained roundtrip without an external TSA round-trip.
//! * [`add_document_timestamp`] — public entry point: take an existing
//!   signed-or-unsigned PDF, a [`TsaSigner`], and produce the new bytes
//!   with the timestamp revision appended.
//! * [`build_tst_info`] / [`wrap_tst_in_signed_data`] — DER builders
//!   exposed for callers stitching their own TST out-of-band.
//!
//! # The TST flow
//!
//! 1. Render or accept the base PDF (already signed if you want both a
//!    regular signature AND a doc-timestamp — both are independent
//!    incremental revisions and may be combined freely).
//! 2. Append an incremental revision whose new objects are a Catalog
//!    override + an AcroForm dict + a `/FT /Sig` field + a
//!    `/Type /DocTimeStamp` sig dict with placeholder `/ByteRange` +
//!    placeholder `/Contents <000…0>` (the budget is sized to fit any
//!    realistic TST: 16 KiB hex = 8 KiB raw bytes).
//! 3. Patch `/ByteRange` with the computed offsets.
//! 4. Hash the byte-ranged bytes with SHA-256 (the round-34 fixed
//!    digest algorithm — RFC 3161 §2.4.1 supports any registered hash;
//!    SHA-256 is the standard PDF / CAdES choice).
//! 5. Hand the digest to the [`TsaSigner`] as a [`MessageImprint`].
//! 6. The signer returns the full TimeStampToken bytes. We hex-encode
//!    them and overwrite the placeholder.
//!
//! Because the `<…hex…>` bytes are *excluded* from `/ByteRange`, the
//! overwrite in step 6 does not invalidate the digest computed in
//! step 4 — the byte-stable property mirrors the round-30 regular-
//! signature flow.

use crate::error::PdfError;
use crate::objects::Object;
use crate::pubsec::cms::OID_SIGNED_DATA;
use crate::pubsec::der::{
    write_context_constructed, write_integer_bytes, write_integer_u64, write_null,
    write_octet_string, write_oid, write_sequence, write_set, write_tlv, Class,
};
use crate::pubsec::verify::{
    build_message_digest_attribute_der, implicit_signed_attrs_tlv, pack_signed_attrs_implicit,
    signed_attrs_to_be_signed, HashAlg, OID_RSA_ENCRYPTION, OID_SHA256,
};
use crate::sig::writer::{build_content_type_attribute_der, SignerIdentity};

// ---------------------------------------------------------------------
// OIDs
// ---------------------------------------------------------------------

/// OID 1.2.840.113549.1.9.16.1.4 — `id-ct-TSTInfo`. RFC 3161 §2.4.2:
/// the `eContentType` inside a TimeStampToken's CMS SignedData.
pub const OID_CT_TST_INFO: [u64; 9] = [1, 2, 840, 113549, 1, 9, 16, 1, 4];

// ---------------------------------------------------------------------
// Placeholder budgets (mirror sig::writer)
// ---------------------------------------------------------------------

/// Number of bytes reserved for the hex-encoded TimeStampToken inside
/// `/Contents`. 16384 hex chars = 8192 raw bytes — enough room for any
/// realistic TST (typical RFC 3161 token + chain ≈ 3-6 KiB).
const TST_CONTENTS_HEX_LEN: usize = 16384;

/// Fixed-width `/ByteRange` placeholder (matches the round-30 writer).
const BYTE_RANGE_PLACEHOLDER: &str = "/ByteRange [         0          0          0          0]";

// ---------------------------------------------------------------------
// MessageImprint + TsaSigner trait
// ---------------------------------------------------------------------

/// `MessageImprint` per RFC 3161 §2.4.1 — the input to a TSA request.
///
/// ```asn.1
/// MessageImprint ::= SEQUENCE {
///   hashAlgorithm  AlgorithmIdentifier,
///   hashedMessage  OCTET STRING
/// }
/// ```
#[derive(Debug, Clone)]
pub struct MessageImprint {
    /// The hash algorithm the digest in [`Self::hashed_message`] uses.
    /// Round 34 always passes [`HashAlg::Sha256`].
    pub hash_alg: HashAlg,
    /// Raw digest bytes — `hashAlgorithm.digest(signedBytes)`.
    pub hashed_message: Vec<u8>,
}

impl MessageImprint {
    /// Map [`Self::hash_alg`] to its DER algorithm OID.
    pub fn hash_alg_oid(&self) -> &'static [u64] {
        match self.hash_alg {
            HashAlg::Sha256 => &OID_SHA256,
            // The doc-timestamp writer locks to SHA-256 for round 34; the
            // Mock TSA also hashes the imprint a second time with the
            // same algorithm so it knows what `oid_for_alg` returns —
            // mismatches at the trait surface still surface a clean error.
            other => {
                panic!("Round-34 doc-timestamp: hash algorithm {other:?} not wired (SHA-256 only)")
            }
        }
    }
}

/// Abstract Time-Stamp Authority signer.
///
/// Real-world implementations send the [`MessageImprint`] to a remote
/// TSA over HTTP (RFC 3161 §3) and parse a `TimeStampResp` reply,
/// returning the embedded `timeStampToken`. The in-tree
/// [`MockTsaSigner`] short-circuits the round-trip and produces the
/// token locally — handy for tests and for self-contained roundtrips.
///
/// The output bytes are the *whole* `TimeStampToken` — a DER
/// `ContentInfo` of type `id-signedData` whose `eContentType` is
/// [`OID_CT_TST_INFO`] and whose `eContent` is a `TSTInfo` SEQUENCE.
pub trait TsaSigner {
    /// Stamp `imprint` with the TSA and return the full TimeStampToken
    /// (a DER `ContentInfo`).
    fn timestamp(&self, imprint: &MessageImprint) -> Result<Vec<u8>, PdfError>;
}

// ---------------------------------------------------------------------
// In-tree reference signer
// ---------------------------------------------------------------------

/// Reference [`TsaSigner`] that builds a self-signed RFC 3161
/// TimeStampToken locally. Useful for tests and for any caller that
/// wants a TST stamped by an in-tree key — no network round-trip.
///
/// The TST embeds:
/// * a [`build_tst_info`]-built `TSTInfo` carrying the supplied policy,
///   the requested message imprint, a deterministic serial, and a
///   GeneralizedTime captured at construction time.
/// * a [`SignerIdentity`] + an RSA-PKCS#1 v1.5 + SHA-256 signature over
///   the canonical `signedAttrs` SET (RFC 5652 §5.4 — same shape as the
///   round-30 regular-signature flow).
pub struct MockTsaSigner {
    private_key: rsa::RsaPrivateKey,
    identity: SignerIdentity,
    /// `tsa-policy-id` per RFC 3161 §2.4.2 `TSTInfo.policy`. The mock
    /// uses a private OID under the `2.25.<uuid>` (joint-iso-itu-t
    /// uuid arc) so we don't squat on a real authority's policy.
    policy_oid: Vec<u64>,
    /// GeneralizedTime ASCII bytes (`b"YYYYMMDDHHMMSSZ"`). Captured at
    /// construction so repeated calls produce the same token (handy for
    /// byte-stable test fixtures).
    gen_time: Vec<u8>,
    /// Deterministic serial INTEGER body. Round 34 picks `0x01`.
    serial: Vec<u8>,
}

impl MockTsaSigner {
    /// Build a self-signed mock TSA. `private_key` signs the inner CMS;
    /// `identity` carries the issuer-and-serial + cert chain that the
    /// reader can use to verify the embedded SignerInfo.
    ///
    /// `gen_time` must be `b"YYYYMMDDHHMMSSZ"` (GeneralizedTime per RFC
    /// 5280 §4.1.2.5.2). The constructor enforces the length so a
    /// caller passing a `D:YYYYMMDDHHMMSSZ` PDF date string fails fast.
    pub fn new(
        private_key: rsa::RsaPrivateKey,
        identity: SignerIdentity,
        gen_time: impl Into<Vec<u8>>,
    ) -> Result<Self, PdfError> {
        let gen_time = gen_time.into();
        if gen_time.len() != 15 || !gen_time.ends_with(b"Z") {
            return Err(PdfError::other(
                "MockTsaSigner: gen_time must be 15 ASCII bytes YYYYMMDDHHMMSSZ",
            ));
        }
        Ok(Self {
            private_key,
            identity,
            // 2.25.42 — `joint-iso-itu-t uuid` arc, arbitrary suffix.
            // Any non-conflicting policy OID works; consumers that care
            // can override via [`Self::with_policy_oid`].
            policy_oid: vec![2, 25, 42],
            gen_time,
            serial: vec![0x01],
        })
    }

    /// Override the deterministic serial number.
    pub fn with_serial(mut self, serial: impl Into<Vec<u8>>) -> Self {
        self.serial = serial.into();
        self
    }

    /// Override the TSA policy OID.
    pub fn with_policy_oid(mut self, oid: impl Into<Vec<u64>>) -> Self {
        self.policy_oid = oid.into();
        self
    }
}

impl TsaSigner for MockTsaSigner {
    fn timestamp(&self, imprint: &MessageImprint) -> Result<Vec<u8>, PdfError> {
        // Build TSTInfo (the eContent we sign).
        let tst_info = build_tst_info(imprint, &self.policy_oid, &self.serial, &self.gen_time);

        // The SignerInfo signs the canonical SignedAttributes SET whose
        // attributes are `contentType=id-ct-TSTInfo` + `messageDigest`
        // (SHA-256 of the TSTInfo bytes) — RFC 5652 §5.4 + §11.2.
        let tst_hash = HashAlg::Sha256.hash(&tst_info);
        let md_attr = build_message_digest_attribute_der(&tst_hash);
        let ct_attr = build_content_type_attribute_der(&OID_CT_TST_INFO);
        let attrs_body = pack_signed_attrs_implicit(&[ct_attr, md_attr]);
        let tbs = signed_attrs_to_be_signed(&attrs_body);
        let tbs_hash = HashAlg::Sha256.hash(&tbs);

        use rsa::pkcs1v15::Pkcs1v15Sign;
        use rsa::traits::SignatureScheme;
        use sha2::Sha256;
        let sig_bytes = Pkcs1v15Sign::new::<Sha256>()
            .sign(
                None::<&mut rsa::rand_core::OsRng>,
                &self.private_key,
                &tbs_hash,
            )
            .map_err(|e| PdfError::other(format!("MockTsaSigner: RSA sign failed: {e}")))?;

        Ok(wrap_tst_in_signed_data(
            &tst_info,
            &self.identity.issuer_der,
            &self.identity.serial,
            &self.identity.cert_chain,
            Some(&attrs_body),
            &sig_bytes,
        ))
    }
}

// ---------------------------------------------------------------------
// TSTInfo + ContentInfo builders
// ---------------------------------------------------------------------

/// Build a DER-encoded `TSTInfo` SEQUENCE per RFC 3161 §2.4.2.
///
/// ```asn.1
/// TSTInfo ::= SEQUENCE {
///   version                  INTEGER  { v1(1) },
///   policy                   TSAPolicyId,
///   messageImprint           MessageImprint,
///   serialNumber             INTEGER,
///   genTime                  GeneralizedTime,
///   accuracy                 Accuracy                 OPTIONAL,
///   ordering                 BOOLEAN          DEFAULT FALSE,
///   nonce                    INTEGER          OPTIONAL,
///   tsa                  [0] GeneralName       OPTIONAL,
///   extensions           [1] IMPLICIT Extensions OPTIONAL
/// }
/// ```
///
/// Round-34 emits the mandatory five fields only (version + policy +
/// messageImprint + serial + genTime). Accuracy / ordering / nonce /
/// tsa / extensions are all left absent — `ordering DEFAULT FALSE` is
/// the only one with a defined default and the omission is spec-clean.
pub fn build_tst_info(
    imprint: &MessageImprint,
    policy_oid: &[u64],
    serial: &[u8],
    gen_time_ascii: &[u8],
) -> Vec<u8> {
    let version = write_integer_u64(1);
    let policy = write_oid(policy_oid);

    // MessageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier,
    //                           hashedMessage OCTET STRING }
    let hash_alg_oid = imprint.hash_alg_oid();
    let hash_alg = write_sequence(&{
        let mut b = write_oid(hash_alg_oid);
        b.extend_from_slice(&write_null()); // SHA-256 carries NULL params (RFC 5754 §2)
        b
    });
    let mi = write_sequence(&{
        let mut b = hash_alg;
        b.extend_from_slice(&write_octet_string(&imprint.hashed_message));
        b
    });

    let serial_field = write_integer_bytes(serial);
    let gen_time = write_tlv(Class::Universal, false, 24, gen_time_ascii);

    write_sequence(&{
        let mut b = version;
        b.extend_from_slice(&policy);
        b.extend_from_slice(&mi);
        b.extend_from_slice(&serial_field);
        b.extend_from_slice(&gen_time);
        b
    })
}

/// Wrap a `TSTInfo` blob into a full RFC 3161 TimeStampToken — a CMS
/// `SignedData` ContentInfo whose `encapContentInfo.eContentType` is
/// [`OID_CT_TST_INFO`] and whose `eContent` is the supplied TSTInfo.
///
/// The wire form is parallel to the round-30 regular-signature CMS
/// builder, with two key differences:
///
/// * `encapContentInfo.eContent` is **present** (RFC 3161 §2.4.2: the
///   TST is an *attached* signature over its own TSTInfo).
/// * `encapContentInfo.eContentType` is `id-ct-TSTInfo`, not `id-data`.
///
/// Arguments mirror [`crate::sig::writer::pkcs7_wrap_signed_data`].
pub fn wrap_tst_in_signed_data(
    tst_info_der: &[u8],
    signer_issuer_der: &[u8],
    signer_serial: &[u8],
    cert_chain: &[Vec<u8>],
    signed_attrs_body: Option<&[u8]>,
    signature_bytes: &[u8],
) -> Vec<u8> {
    let digest_oid = &OID_SHA256;
    let sig_oid = &OID_RSA_ENCRYPTION;

    // ---- SignerInfo body.
    let mut si_body = write_integer_u64(1); // CMSVersion = 1 (IAS)
    let ias_body = {
        let mut b = signer_issuer_der.to_vec();
        b.extend_from_slice(&write_integer_bytes(signer_serial));
        b
    };
    si_body.extend_from_slice(&write_sequence(&ias_body));
    let da_alg = {
        let mut b = write_oid(digest_oid);
        b.extend_from_slice(&write_null());
        write_sequence(&b)
    };
    si_body.extend_from_slice(&da_alg);
    if let Some(sa) = signed_attrs_body {
        si_body.extend_from_slice(&implicit_signed_attrs_tlv(sa));
    }
    let sig_alg = {
        let mut b = write_oid(sig_oid);
        b.extend_from_slice(&write_null());
        write_sequence(&b)
    };
    si_body.extend_from_slice(&sig_alg);
    si_body.extend_from_slice(&write_octet_string(signature_bytes));
    let signer_info = write_sequence(&si_body);

    // ---- digestAlgorithms SET.
    let da_set = write_set(&da_alg);

    // ---- encapContentInfo — TSTInfo carried as eContent [0] EXPLICIT OCTET STRING.
    // RFC 5652 §5.2: eContent ::= [0] EXPLICIT OCTET STRING — the
    // TSTInfo SEQUENCE bytes go inside the OCTET STRING.
    let eci = {
        let mut body = write_oid(&OID_CT_TST_INFO);
        let oct = write_octet_string(tst_info_der);
        body.extend_from_slice(&write_context_constructed(0, &oct));
        write_sequence(&body)
    };

    // ---- certificates [0] IMPLICIT CertificateSet OPTIONAL.
    let certs_body: Vec<u8> = cert_chain.iter().flat_map(|c| c.iter().copied()).collect();
    let certs_field = write_tlv(Class::ContextSpecific, true, 0, &certs_body);

    // ---- signerInfos SET.
    let si_set = write_set(&signer_info);

    // ---- SignedData SEQUENCE.
    let mut sd_body = write_integer_u64(3); // CMSVersion = 3 — eContentType ≠ id-data (RFC 5652 §5.1)
    sd_body.extend_from_slice(&da_set);
    sd_body.extend_from_slice(&eci);
    sd_body.extend_from_slice(&certs_field);
    sd_body.extend_from_slice(&si_set);
    let sd = write_sequence(&sd_body);

    // ---- Outer ContentInfo SEQUENCE.
    let outer_body = {
        let mut b = write_oid(&OID_SIGNED_DATA);
        b.extend_from_slice(&write_context_constructed(0, &sd));
        b
    };
    write_sequence(&outer_body)
}

// ---------------------------------------------------------------------
// Public entry point — add a /DocTimeStamp to existing PDF bytes
// ---------------------------------------------------------------------

/// Add an RFC 3161 Document Time-Stamp signature to an existing PDF.
///
/// The base `pdf` bytes may already carry one or more regular
/// signatures (round 30) — the timestamp is appended as a separate
/// incremental update (ISO 32000-1 §7.5.6), so any prior signature's
/// `/ByteRange` remains intact (the prior signature byte range stops
/// at the prior `%%EOF`; the bytes the new revision adds are part of
/// the timestamp's range, not the prior signature's).
///
/// Returns the new PDF bytes — ready to write to disk.
pub fn add_document_timestamp<T: TsaSigner>(pdf: &[u8], tsa: &T) -> Result<Vec<u8>, PdfError> {
    // 1. Append the timestamp revision (with placeholders).
    let (mut out, byte_range, contents_hex_offset) = append_doctimestamp_revision(pdf)?;

    // 2. Patch /ByteRange first — the four integers are inside the
    //    signed range, so they must reach final values BEFORE hashing.
    patch_byte_range(&mut out, byte_range);

    // 3. Hash the byte-ranged content with SHA-256 and ask the TSA.
    let signed = concat_byte_ranges(&out, byte_range)?;
    let imprint = MessageImprint {
        hash_alg: HashAlg::Sha256,
        hashed_message: HashAlg::Sha256.hash(&signed),
    };
    let tst = tsa.timestamp(&imprint)?;

    // 4. Patch /Contents.
    patch_contents(&mut out, contents_hex_offset, &tst)?;
    Ok(out)
}

// ---------------------------------------------------------------------
// Incremental-revision layout
// ---------------------------------------------------------------------

fn append_doctimestamp_revision(base: &[u8]) -> Result<(Vec<u8>, [i64; 4], usize), PdfError> {
    let prev_xref_off = crate::reader::xref::find_startxref_offset(base)?;
    let prev_table = crate::reader::xref::parse_xref(base)?;
    let prev_root = prev_table.root()?;
    let prev_max_id = prev_table.entries.keys().copied().max().unwrap_or(0);
    let prev_size_from_trailer = prev_table
        .trailer
        .entries()
        .iter()
        .find(|(k, _)| k == "Size")
        .and_then(|(_, v)| match v {
            Object::Integer(n) if *n >= 0 => Some(*n as u32),
            _ => None,
        });
    let prev_size = prev_size_from_trailer.unwrap_or(prev_max_id + 1);

    // Resolve the existing catalog so we can preserve its entries (and
    // any pre-existing /AcroForm — round 34 must coexist with round 30's
    // regular signature when both are wired into the same document).
    let mut reader = crate::reader::document::DocumentReader::open(base)?;
    let prev_catalog_obj = reader.resolve(prev_root)?;
    let mut catalog_dict = match prev_catalog_obj {
        Object::Dict(d) => d,
        _ => {
            return Err(PdfError::other(
                "add_document_timestamp: previous /Root is not a Dict",
            ));
        }
    };

    // Examine the existing AcroForm to see if we need to extend an
    // /Fields array or create a new AcroForm dict. The pre-existing
    // dict may already have a /Fields entry (a regular signature from
    // round 30); we splice in the timestamp's field id at the end.
    let existing_acroform = catalog_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "AcroForm")
        .map(|(_, v)| v.clone());

    // Allocate ids for the new objects.
    let acroform_id = prev_max_id + 1;
    let ts_field_id = prev_max_id + 2;
    let ts_sigdict_id = prev_max_id + 3;

    // Build the new AcroForm dictionary. If one already exists, we copy
    // every entry from it and patch /Fields to include our new field.
    let mut acroform_dict = crate::objects::Dict::new();
    let mut sig_flags: i64 = 3;
    if let Some(acro_obj) = existing_acroform.clone() {
        let resolved = reader.deref(acro_obj)?;
        if let Object::Dict(existing) = resolved {
            // Copy existing /Fields (if an array) and append the new id.
            let mut fields = Vec::new();
            for (k, v) in existing.entries() {
                if k == "Fields" {
                    if let Object::Array(items) = v {
                        for item in items {
                            fields.push(item.clone());
                        }
                    }
                } else if k == "SigFlags" {
                    if let Object::Integer(n) = v {
                        // OR our SigFlags bits in (round 30 already sets 3).
                        sig_flags |= *n;
                    }
                } else {
                    acroform_dict.set(k, v.clone());
                }
            }
            // Append our new sig field.
            fields.push(Object::Reference(crate::objects::ObjectId::new(
                ts_field_id,
            )));
            acroform_dict.set("Fields", Object::Array(fields));
        } else {
            // /AcroForm pointed at a non-dict — replace with a fresh one.
            acroform_dict.set(
                "Fields",
                Object::Array(vec![Object::Reference(crate::objects::ObjectId::new(
                    ts_field_id,
                ))]),
            );
        }
    } else {
        acroform_dict.set(
            "Fields",
            Object::Array(vec![Object::Reference(crate::objects::ObjectId::new(
                ts_field_id,
            ))]),
        );
    }
    acroform_dict.set("SigFlags", Object::Integer(sig_flags));

    // Patch /AcroForm in the catalog override to point at the new dict.
    catalog_dict.set(
        "AcroForm",
        Object::Reference(crate::objects::ObjectId::new(acroform_id)),
    );

    let mut out: Vec<u8> = base.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }

    // Helper to serialise one indirect dict.
    fn write_indirect_dict(
        out: &mut Vec<u8>,
        id: u32,
        dict: &crate::objects::Dict,
    ) -> Result<usize, PdfError> {
        let offset = out.len();
        out.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
        crate::objects::write_dict_to(out, dict)?;
        out.extend_from_slice(b"\nendobj\n");
        Ok(offset)
    }

    // 1. Catalog override (same id as previous catalog).
    let catalog_offset = write_indirect_dict(&mut out, prev_root.number, &catalog_dict)?;

    // 2. AcroForm dict.
    let acroform_offset = write_indirect_dict(&mut out, acroform_id, &acroform_dict)?;

    // 3. Timestamp sig field — terminal, /FT /Sig, /T (Timestamp1).
    let ts_field_dict = crate::objects::Dict::new()
        .with("FT", Object::Name("Sig".to_string()))
        .with("T", Object::LiteralString(b"DocTimeStamp1".to_vec()))
        .with(
            "V",
            Object::Reference(crate::objects::ObjectId::new(ts_sigdict_id)),
        );
    let ts_field_offset = write_indirect_dict(&mut out, ts_field_id, &ts_field_dict)?;

    // 4. Sig dictionary — hand-rolled for /ByteRange + /Contents control.
    let sigdict_offset = out.len();
    out.extend_from_slice(format!("{ts_sigdict_id} 0 obj\n").as_bytes());
    out.extend_from_slice(b"<< /Type /DocTimeStamp /Filter /Adobe.PPKLite ");
    out.extend_from_slice(b"/SubFilter /ETSI.RFC3161 ");
    out.extend_from_slice(b"/V 0 ");
    out.extend_from_slice(BYTE_RANGE_PLACEHOLDER.as_bytes());
    out.extend_from_slice(b" /Contents <");
    let contents_hex_offset = out.len();
    out.resize(out.len() + TST_CONTENTS_HEX_LEN, b'0');
    out.extend_from_slice(b"> >>\nendobj\n");

    // xref + trailer for this revision.
    let xref_off = out.len();
    out.extend_from_slice(b"xref\n");
    // Two subsections: one for the catalog override, one for the new
    // contiguous range of three objects.
    out.extend_from_slice(format!("{} 1\n", prev_root.number).as_bytes());
    out.extend_from_slice(format!("{catalog_offset:010} 00000 n \n").as_bytes());
    out.extend_from_slice(format!("{acroform_id} 3\n").as_bytes());
    out.extend_from_slice(format!("{acroform_offset:010} 00000 n \n").as_bytes());
    out.extend_from_slice(format!("{ts_field_offset:010} 00000 n \n").as_bytes());
    out.extend_from_slice(format!("{sigdict_offset:010} 00000 n \n").as_bytes());

    let new_size = (ts_sigdict_id + 1).max(prev_size);
    out.extend_from_slice(b"trailer\n<< ");
    out.extend_from_slice(format!("/Size {new_size} ").as_bytes());
    out.extend_from_slice(
        format!("/Root {} {} R ", prev_root.number, prev_root.generation).as_bytes(),
    );
    out.extend_from_slice(format!("/Prev {prev_xref_off} ").as_bytes());
    if let Some(info_id) = prev_table.info() {
        out.extend_from_slice(
            format!("/Info {} {} R ", info_id.number, info_id.generation).as_bytes(),
        );
    }
    out.extend_from_slice(b">>\n");
    out.extend_from_slice(b"startxref\n");
    out.extend_from_slice(format!("{xref_off}\n%%EOF\n").as_bytes());

    let a = 0i64;
    let b = contents_hex_offset as i64;
    let c = (contents_hex_offset + TST_CONTENTS_HEX_LEN) as i64;
    let total = out.len() as i64;
    let d = total - c;

    Ok((out, [a, b, c, d], contents_hex_offset))
}

fn patch_byte_range(pdf: &mut [u8], byte_range: [i64; 4]) {
    let formatted = format!(
        "/ByteRange [{:>10} {:>10} {:>10} {:>10}]",
        byte_range[0], byte_range[1], byte_range[2], byte_range[3]
    );
    debug_assert_eq!(formatted.len(), BYTE_RANGE_PLACEHOLDER.len());
    let placeholder = BYTE_RANGE_PLACEHOLDER.as_bytes();
    // Patch the LAST occurrence — the base PDF may already contain a
    // round-30 regular-signature /ByteRange placeholder that was filled
    // before being appended here; we want to hit the timestamp's slot
    // (which is the freshly-appended one at the end).
    if let Some(pos) = pdf
        .windows(placeholder.len())
        .rposition(|w| w == placeholder)
    {
        pdf[pos..pos + placeholder.len()].copy_from_slice(formatted.as_bytes());
    }
}

fn patch_contents(
    pdf: &mut [u8],
    contents_hex_offset: usize,
    tst_der: &[u8],
) -> Result<(), PdfError> {
    let hex_len_needed = tst_der.len() * 2;
    if hex_len_needed > TST_CONTENTS_HEX_LEN {
        return Err(PdfError::other(format!(
            "add_document_timestamp: TST {} hex chars exceeds /Contents budget {}",
            hex_len_needed, TST_CONTENTS_HEX_LEN
        )));
    }
    for (i, b) in tst_der.iter().enumerate() {
        let hi = (b >> 4) & 0x0F;
        let lo = b & 0x0F;
        pdf[contents_hex_offset + 2 * i] = hex_digit(hi);
        pdf[contents_hex_offset + 2 * i + 1] = hex_digit(lo);
    }
    for byte in pdf
        .iter_mut()
        .skip(contents_hex_offset + hex_len_needed)
        .take(TST_CONTENTS_HEX_LEN - hex_len_needed)
    {
        *byte = b'0';
    }
    Ok(())
}

fn hex_digit(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'A' + (n - 10),
        _ => unreachable!(),
    }
}

fn concat_byte_ranges(pdf: &[u8], byte_range: [i64; 4]) -> Result<Vec<u8>, PdfError> {
    let [a, b, c, d] = byte_range;
    if a < 0 || b < 0 || c < 0 || d < 0 {
        return Err(PdfError::other(
            "add_document_timestamp: negative /ByteRange entry",
        ));
    }
    let (a, b, c, d) = (a as usize, b as usize, c as usize, d as usize);
    if a + b > pdf.len() || c + d > pdf.len() {
        return Err(PdfError::other(
            "add_document_timestamp: /ByteRange extends past file length",
        ));
    }
    let mut out = Vec::with_capacity(b + d);
    out.extend_from_slice(&pdf[a..a + b]);
    out.extend_from_slice(&pdf[c..c + d]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tst_info_is_well_formed_der() {
        let imprint = MessageImprint {
            hash_alg: HashAlg::Sha256,
            hashed_message: vec![0u8; 32],
        };
        let tst = build_tst_info(&imprint, &[2, 25, 42], &[0x01], b"20260517000000Z");
        // Outer tag must be a universal constructed SEQUENCE (0x30).
        assert_eq!(tst[0], 0x30, "TSTInfo must start with SEQUENCE tag");
        // Round-trip through the DER reader.
        let (tlv, rest) = crate::pubsec::der::read_tlv(&tst).expect("read TSTInfo");
        assert!(rest.is_empty(), "no trailing bytes after TSTInfo");
        assert_eq!(tlv.tag_number, 16); // SEQUENCE
    }

    #[test]
    fn mock_tsa_rejects_short_gen_time() {
        // Build a placeholder identity (cert chain may be empty for this
        // unit-level test — we only exercise the constructor path).
        let issuer_der = crate::pubsec::der::write_sequence(b"O=R34 Unit");
        let identity = SignerIdentity {
            issuer_der,
            serial: vec![0x01],
            cert_chain: Vec::new(),
        };
        let mut rng = rsa::rand_core::OsRng;
        let pk = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
        // Wrong length — must fail.
        match MockTsaSigner::new(pk, identity, b"D:20260517".to_vec()) {
            Ok(_) => panic!("MockTsaSigner accepted invalid gen_time"),
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("YYYYMMDDHHMMSSZ"),
                    "expected gen_time validation error, got {msg}"
                );
            }
        }
    }

    #[test]
    fn message_imprint_oid_dispatches_sha256() {
        let mi = MessageImprint {
            hash_alg: HashAlg::Sha256,
            hashed_message: vec![],
        };
        assert_eq!(mi.hash_alg_oid(), &OID_SHA256);
    }
}
