//! Round-30 — `/Sig` writer.
//!
//! Builds a signed PDF from a [`oxideav_scene::Scene`] + a [`Signer`].
//!
//! Provenance: ISO 32000-1 §12.7.4.5 (Signature fields) + §12.8.1
//! (Signature dictionaries) + RFC 5652 §5 (CMS `SignedData`) + RFC 5652
//! §5.4 (`SignedAttributes` re-tagging) + RFC 5652 §11.2
//! (`messageDigest` signed-attribute). No third-party PDF / CMS source
//! consulted.
//!
//! # Public surface
//!
//! * [`Signer`] — abstract per-algorithm signing primitive. The caller
//!   supplies an implementation that signs a SHA-2 digest against
//!   their private key.
//! * [`RsaPkcs1v15Sha256Signer`] / [`EcdsaP256Sha256Signer`] — concrete
//!   `Signer` impls that wrap the in-crate `rsa` / `p256` deps.
//! * [`SigWriter`] — builder that wires `Scene` → signed PDF bytes.
//! * [`sign_pdf_from_scene`] — one-shot convenience wrapper.
//! * [`pkcs7_wrap_signed_data`] — DER builder for the CMS blob alone
//!   (exposed so callers stitching their own PDF body can reuse it).

use crate::error::PdfError;
use crate::pubsec::cms::{OID_DATA, OID_RSA_ENCRYPTION, OID_SIGNED_DATA};
use crate::pubsec::der::{
    write_context_constructed, write_integer_bytes, write_integer_u64, write_null,
    write_octet_string, write_oid, write_sequence, write_set, write_tlv, Class,
};
use crate::pubsec::verify::{
    build_message_digest_attribute_der, implicit_signed_attrs_tlv, pack_signed_attrs_implicit,
    signed_attrs_to_be_signed, HashAlg, OID_ECDSA_WITH_SHA256, OID_SHA256,
};
use crate::writer::write_pdf_from_scene;
use oxideav_scene::Scene;

// ---------------------------------------------------------------------
// Placeholder budgets
// ---------------------------------------------------------------------

/// Number of bytes the `<…>` placeholder of `/Contents` reserves. The
/// hex-encoded CMS blob must fit. 8192 hex chars = 4096 raw bytes —
/// comfortable for any RSA-2048 / ECDSA-P256 SHA-256 SignedData with a
/// single signer and a single cert.
const CONTENTS_HEX_LEN: usize = 8192;

/// Fixed-width `/ByteRange` placeholder. Each of the four integer
/// slots is right-aligned in a 10-char field — wide enough for any
/// 10-digit (≤ ~9.9 GB) PDF byte offset. Total width is exactly
/// `len("/ByteRange [") + 10 + 1 + 10 + 1 + 10 + 1 + 10 + len("]")`.
const BYTE_RANGE_PLACEHOLDER: &str = "/ByteRange [         0          0          0          0]";

// ---------------------------------------------------------------------
// Signing algorithm + Signer trait
// ---------------------------------------------------------------------

/// The signature algorithm a [`Signer`] produces.
///
/// Round-30 ships the two algorithms the reader (round 27) is most
/// likely to verify in production: RSA-PKCS#1 v1.5 with SHA-256 and
/// ECDSA-P256 with SHA-256. Additional algorithms (RSA-PSS,
/// ECDSA-P384 / P521, Ed25519) are out of scope for round 30 — they
/// can be plumbed through the same trait without touching the writer
/// surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// RSA-PKCS#1 v1.5 (RFC 8017 §8.2) over a SHA-256 message digest.
    /// `signatureAlgorithm` OID emitted: `rsaEncryption`
    /// (1.2.840.113549.1.1.1) per RFC 5652 §10.1.1.
    RsaPkcs1v15Sha256,
    /// ECDSA (RFC 5753 §2.1) over a SHA-256 message digest on the
    /// NIST P-256 curve. `signatureAlgorithm` OID emitted:
    /// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
    EcdsaP256Sha256,
}

impl SigningAlgorithm {
    /// The message-digest algorithm this scheme hashes with. Always
    /// SHA-256 in round 30.
    pub fn hash(self) -> HashAlg {
        match self {
            Self::RsaPkcs1v15Sha256 | Self::EcdsaP256Sha256 => HashAlg::Sha256,
        }
    }

    /// `digestAlgorithm` OID to emit in `SignerInfo`.
    pub fn digest_algorithm_oid(self) -> &'static [u64] {
        match self {
            Self::RsaPkcs1v15Sha256 | Self::EcdsaP256Sha256 => &OID_SHA256,
        }
    }

    /// `signatureAlgorithm` OID to emit in `SignerInfo`.
    pub fn signature_algorithm_oid(self) -> &'static [u64] {
        match self {
            Self::RsaPkcs1v15Sha256 => &OID_RSA_ENCRYPTION,
            Self::EcdsaP256Sha256 => &OID_ECDSA_WITH_SHA256,
        }
    }

    /// `signatureAlgorithm.parameters` bytes. RSA-PKCS#1 v1.5 carries
    /// a NULL; ECDSA carries no parameters at all.
    pub fn signature_algorithm_params(self) -> Vec<u8> {
        match self {
            Self::RsaPkcs1v15Sha256 => write_null(),
            Self::EcdsaP256Sha256 => Vec::new(),
        }
    }
}

/// Abstract signing primitive. A `Signer` consumes a SHA-2 digest of
/// the bytes to be signed (the canonical `SignedAttributes` SET, per
/// RFC 5652 §5.4) and produces the algorithm-specific signature octets
/// that go into `SignerInfo.signature`.
///
/// The trait is the integration seam between this crate (which knows
/// PDF + CMS) and the user's chosen crypto stack — `ring`, `rsa`,
/// `p256`, an HSM, a hardware token, … any private-key provider can
/// implement this.
///
/// # Contract
///
/// * [`Self::algorithm`] returns the algorithm the implementor produces.
///   The writer uses it to populate the `digestAlgorithm` and
///   `signatureAlgorithm` OIDs in the emitted `SignerInfo`. The
///   message-digest algorithm is therefore fixed by the implementor —
///   the writer does **not** ask for a separate digest spec.
/// * [`Self::sign`] receives `tbs_hash` — the SHA-2 digest of the
///   canonical `SignedAttributes` SET to be signed. The output must be
///   the wire-form signature octets the corresponding verifier
///   primitive ([`crate::pubsec::verify::verify_signature`]) accepts:
///   PKCS#1 v1.5 padded big-endian for RSA, DER-encoded `Ecdsa-Sig-Value`
///   (SEQUENCE { r INTEGER, s INTEGER }) for ECDSA.
///
/// Implementations are expected to be side-effect-free past the
/// signing call — the writer hashes once, signs once, and stitches the
/// result in.
pub trait Signer {
    /// The algorithm this signer produces.
    fn algorithm(&self) -> SigningAlgorithm;

    /// Sign `tbs_hash` (the digest of the canonical SignedAttributes
    /// SET) with the implementor's private key.
    fn sign(&self, tbs_hash: &[u8]) -> Result<Vec<u8>, PdfError>;
}

// ---------------------------------------------------------------------
// Built-in signer impls — thin wrappers over the in-crate `rsa` /
// `p256` deps so callers don't have to bring their own crypto.
// ---------------------------------------------------------------------

/// Reference `Signer` impl that uses the in-crate `rsa` crate to sign
/// with RSA-PKCS#1 v1.5 + SHA-256.
pub struct RsaPkcs1v15Sha256Signer {
    private_key: rsa::RsaPrivateKey,
}

impl RsaPkcs1v15Sha256Signer {
    /// Wrap an [`rsa::RsaPrivateKey`].
    pub fn new(private_key: rsa::RsaPrivateKey) -> Self {
        Self { private_key }
    }
}

impl Signer for RsaPkcs1v15Sha256Signer {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::RsaPkcs1v15Sha256
    }

    fn sign(&self, tbs_hash: &[u8]) -> Result<Vec<u8>, PdfError> {
        use rsa::pkcs1v15::Pkcs1v15Sign;
        use rsa::traits::SignatureScheme;
        use sha2::Sha256;
        Pkcs1v15Sign::new::<Sha256>()
            .sign(
                None::<&mut rsa::rand_core::OsRng>,
                &self.private_key,
                tbs_hash,
            )
            .map_err(|e| PdfError::other(format!("RSA-PKCS1v15 sign: {e}")))
    }
}

/// Reference `Signer` impl that uses the in-crate `p256` crate to sign
/// with ECDSA over P-256 + SHA-256.
pub struct EcdsaP256Sha256Signer {
    signing_key: p256::ecdsa::SigningKey,
}

impl EcdsaP256Sha256Signer {
    /// Wrap a [`p256::ecdsa::SigningKey`].
    pub fn new(signing_key: p256::ecdsa::SigningKey) -> Self {
        Self { signing_key }
    }
}

impl Signer for EcdsaP256Sha256Signer {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::EcdsaP256Sha256
    }

    fn sign(&self, tbs_hash: &[u8]) -> Result<Vec<u8>, PdfError> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = self
            .signing_key
            .sign_prehash(tbs_hash)
            .map_err(|e| PdfError::other(format!("ECDSA-P256 sign: {e}")))?;
        // The CMS wire form is the DER-encoded ASN.1 `Ecdsa-Sig-Value`
        // SEQUENCE { r INTEGER, s INTEGER } (RFC 5753 §2.1). The
        // `p256` crate gives us a fixed-width `(r ‖ s)` raw form by
        // default; `to_der()` produces the SEQUENCE wrap.
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

// ---------------------------------------------------------------------
// SigWriter — the encoder.
// ---------------------------------------------------------------------

/// Signer identity bundle — the X.509 details the CMS SignerInfo
/// needs (IAS) plus the raw cert chain bytes that populate the
/// outer SignedData `certificates` SET.
///
/// Decoupled from any specific cert-builder so callers can plug in
/// pre-parsed certs (from `pubsec::x509::Certificate`), raw DER from
/// a PKCS#12 export, or synthetic test certs without having to
/// round-trip through [`crate::pubsec::x509::Certificate::parse`].
#[derive(Debug, Clone)]
pub struct SignerIdentity {
    /// Signer cert `issuer` Name SEQUENCE — DER bytes *including* the
    /// outer tag/length so the byte-compare in the verifier's IAS
    /// matcher is exact. Same shape as
    /// [`crate::pubsec::x509::Certificate::issuer_der`].
    pub issuer_der: Vec<u8>,
    /// Signer cert serial number — raw INTEGER body bytes.
    pub serial: Vec<u8>,
    /// Full cert chain to embed in `SignedData.certificates`. The
    /// signer cert SHOULD be `cert_chain[0]`. Each entry is one full
    /// X.509 v3 `Certificate` SEQUENCE DER blob. Empty is permitted —
    /// callers that distribute certs out-of-band (CAdES-LT trust list,
    /// pre-installed PKCS#11 token) can omit them; the verifier then
    /// has to resolve the signer through its own pool.
    pub cert_chain: Vec<Vec<u8>>,
}

impl SignerIdentity {
    /// Build a [`SignerIdentity`] from a single self-signed signer cert
    /// DER. Parses the cert via
    /// [`crate::pubsec::x509::Certificate::parse`] to extract IAS.
    pub fn from_signer_cert_der(cert_der: Vec<u8>) -> Result<Self, PdfError> {
        let parsed = crate::pubsec::x509::Certificate::parse(&cert_der)?;
        Ok(Self {
            issuer_der: parsed.issuer_der,
            serial: parsed.serial,
            cert_chain: vec![cert_der],
        })
    }
}

/// Builder that wires a `Scene` + a `Signer` + a [`SignerIdentity`]
/// into a signed PDF.
pub struct SigWriter<'a, S: Signer> {
    scene: &'a Scene,
    signer: &'a S,
    identity: SignerIdentity,
}

impl<'a, S: Signer> SigWriter<'a, S> {
    /// New builder.
    pub fn new(scene: &'a Scene, signer: &'a S, identity: SignerIdentity) -> Self {
        Self {
            scene,
            signer,
            identity,
        }
    }

    /// Build the signed PDF bytes. Drives the round-21 placeholder
    /// pattern end-to-end:
    ///
    /// Step 1 — render the base PDF via [`write_pdf_from_scene`].
    ///
    /// Step 2 — append an incremental-update revision adding an
    /// `/AcroForm` + a `/FT /Sig` field + a signature dictionary with
    /// `/ByteRange` + `/Contents` placeholders.
    ///
    /// Step 3 — patch `/ByteRange` with the computed offsets.
    ///
    /// Step 4 — hash the bytes named by `/ByteRange`, hand the hash to
    /// the [`Signer`], wrap the signature in a CMS SignedData blob
    /// (with `signedAttrs` carrying `contentType` + `messageDigest` per
    /// RFC 5652 §5.4 + §11.2), hex-encode, and overwrite the
    /// `/Contents` placeholder.
    ///
    /// Returns the final signed PDF bytes — ready to write to disk or
    /// hand to a verifier.
    pub fn sign(self) -> Result<Vec<u8>, PdfError> {
        // 1. Base PDF.
        let base = write_pdf_from_scene(self.scene)?;

        // 2. Append the signed-revision bytes — laid out by hand so we
        //    can hit the placeholder offsets exactly.
        let signer_cert_for_dict = self
            .identity
            .cert_chain
            .first()
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let (mut pdf, byte_range, contents_hex_offset) =
            append_signed_revision(&base, signer_cert_for_dict)?;

        // 3. Patch /ByteRange (the four integers are themselves inside
        //    the signed range, so they reach their final values BEFORE
        //    the hash is computed).
        patch_byte_range(&mut pdf, byte_range);

        // 4. Compute the signed message + the `signedAttrs` to-be-signed
        //    canonical form, sign, wrap, patch.
        let signed_bytes = concat_byte_ranges(&pdf, byte_range)?;
        let content_hash = self.signer.algorithm().hash().hash(&signed_bytes);
        let md_attr = build_message_digest_attribute_der(&content_hash);
        let ct_attr = build_content_type_attribute_der(&OID_DATA);
        let attrs_body = pack_signed_attrs_implicit(&[ct_attr, md_attr]);
        let tbs = signed_attrs_to_be_signed(&attrs_body);
        let tbs_hash = self.signer.algorithm().hash().hash(&tbs);
        let signature_bytes = self.signer.sign(&tbs_hash)?;

        let cms_blob = pkcs7_wrap_signed_data(
            self.signer.algorithm(),
            &self.identity.issuer_der,
            &self.identity.serial,
            &self.identity.cert_chain,
            Some(&attrs_body),
            &signature_bytes,
        );

        patch_contents(&mut pdf, contents_hex_offset, &cms_blob)?;
        Ok(pdf)
    }
}

/// One-shot convenience wrapper: build, sign, return.
pub fn sign_pdf_from_scene<S: Signer>(
    scene: &Scene,
    signer: &S,
    identity: SignerIdentity,
) -> Result<Vec<u8>, PdfError> {
    SigWriter::new(scene, signer, identity).sign()
}

// ---------------------------------------------------------------------
// Signed-revision layout (hand-rolled incremental update).
// ---------------------------------------------------------------------

/// Append a signed-revision section to `base`, returning the full
/// new-file bytes, the byte-range `[a b c d]` integers that cover
/// everything *except* the `/Contents` hex literal, and the byte
/// offset of the first hex digit (immediately after the `<`).
///
/// The appended revision is a minimal classical-xref incremental
/// update per ISO 32000-1 §7.5.6:
///
/// * **Catalog rewrite** — same id as the previous Catalog, with an
///   `/AcroForm <ref>` entry added.
/// * **AcroForm dict** — `<< /Fields [<sig-field-ref>] /SigFlags 3 >>`
///   (SigFlags=3 = SignaturesExist | AppendOnly, ISO 32000-1 §12.7.2).
/// * **Sig field** — `<< /FT /Sig /T (Signature1) /V <sig-dict-ref> >>`.
/// * **Sig dictionary** — the round-21 layout, with reserved
///   placeholder runs for `/ByteRange` and `/Contents`.
///
/// The xref table covers exactly the four objects this revision
/// writes (Catalog override + AcroForm + Sig field + Sig dict).
fn append_signed_revision(
    base: &[u8],
    signer_cert_der: &[u8],
) -> Result<(Vec<u8>, [i64; 4], usize), PdfError> {
    // Find the previous revision's startxref + catalog id + max
    // object id so the new revision picks up cleanly.
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
            crate::objects::Object::Integer(n) if *n >= 0 => Some(*n as u32),
            _ => None,
        });
    let prev_size = prev_size_from_trailer.unwrap_or(prev_max_id + 1);

    // Open the base to inspect the previous Catalog dict — we need to
    // preserve its entries (/Pages, optional /Info, /Metadata, …) and
    // only inject `/AcroForm`.
    let mut reader = crate::reader::document::DocumentReader::open(base)?;
    let prev_catalog_obj = reader.resolve(prev_root)?;
    let mut catalog_dict = match prev_catalog_obj {
        crate::objects::Object::Dict(d) => d,
        _ => {
            return Err(PdfError::other("SigWriter: previous /Root is not a Dict"));
        }
    };

    // Allocate ids for the three new objects.
    let acroform_id = prev_max_id + 1;
    let sigfield_id = prev_max_id + 2;
    let sigdict_id = prev_max_id + 3;

    // Patch the catalog dict in-memory — add /AcroForm pointing at
    // the new AcroForm object.
    catalog_dict.set(
        "AcroForm",
        crate::objects::Object::Reference(crate::objects::ObjectId::new(acroform_id)),
    );

    // The new revision is appended verbatim — start from the base
    // bytes and grow.
    let mut out: Vec<u8> = base.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }

    // Helper to serialise one indirect object via the existing
    // Object writer. The Document writer would do this for us, but we
    // need the precise byte offset of the Sig dict's `/Contents <` so
    // hand-laying is simpler.
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

    // ---- 1. Catalog override (same id as previous catalog).
    let catalog_offset = write_indirect_dict(&mut out, prev_root.number, &catalog_dict)?;

    // ---- 2. AcroForm dictionary.
    let acroform_dict = crate::objects::Dict::new()
        .with(
            "Fields",
            crate::objects::Object::Array(vec![crate::objects::Object::Reference(
                crate::objects::ObjectId::new(sigfield_id),
            )]),
        )
        .with("SigFlags", crate::objects::Object::Integer(3));
    let acroform_offset = write_indirect_dict(&mut out, acroform_id, &acroform_dict)?;

    // ---- 3. Sig field (terminal — no /Kids).
    let sigfield_dict = crate::objects::Dict::new()
        .with("FT", crate::objects::Object::Name("Sig".to_string()))
        .with(
            "T",
            crate::objects::Object::LiteralString(b"Signature1".to_vec()),
        )
        .with(
            "V",
            crate::objects::Object::Reference(crate::objects::ObjectId::new(sigdict_id)),
        );
    let sigfield_offset = write_indirect_dict(&mut out, sigfield_id, &sigfield_dict)?;

    // ---- 4. Sig dictionary — hand-rolled because we need precise
    //         control over the /ByteRange + /Contents placeholders.
    let sigdict_offset = out.len();
    out.extend_from_slice(format!("{sigdict_id} 0 obj\n").as_bytes());
    out.extend_from_slice(b"<< /Type /Sig /Filter /Adobe.PPKLite ");
    out.extend_from_slice(b"/SubFilter /adbe.pkcs7.detached ");
    // ByteRange placeholder — fixed-width.
    out.extend_from_slice(BYTE_RANGE_PLACEHOLDER.as_bytes());
    out.extend_from_slice(b" /Contents <");
    let contents_hex_offset = out.len();
    out.resize(out.len() + CONTENTS_HEX_LEN, b'0');
    out.extend_from_slice(b"> ");
    // /Cert array — single-entry hex string of the signer cert so old
    // (pre-PAdES) tools that look there before /Contents have somewhere
    // to pick up the signer identity. ISO 32000-1 §12.8.1 lists /Cert
    // as optional but recommended for adbe.pkcs7.detached.
    out.extend_from_slice(b"/Cert <");
    for b in signer_cert_der {
        out.extend_from_slice(format!("{b:02X}").as_bytes());
    }
    out.extend_from_slice(b"> >>\nendobj\n");

    // ---- xref + trailer for this revision.
    let xref_off = out.len();
    out.extend_from_slice(b"xref\n");
    // The xref subsections cover only the changed object ids. We use
    // two subsections: one for the Catalog id (which overrides the
    // previous revision's), one for the new contiguous range.
    out.extend_from_slice(format!("{} 1\n", prev_root.number).as_bytes());
    out.extend_from_slice(format!("{catalog_offset:010} 00000 n \n").as_bytes());
    out.extend_from_slice(format!("{acroform_id} 3\n").as_bytes());
    out.extend_from_slice(format!("{acroform_offset:010} 00000 n \n").as_bytes());
    out.extend_from_slice(format!("{sigfield_offset:010} 00000 n \n").as_bytes());
    out.extend_from_slice(format!("{sigdict_offset:010} 00000 n \n").as_bytes());

    // Trailer — /Size at least the previous /Size; /Prev points at the
    // previous startxref offset (so readers that follow the chain see
    // both revisions).
    let new_size = (sigdict_id + 1).max(prev_size);
    out.extend_from_slice(b"trailer\n<< ");
    out.extend_from_slice(format!("/Size {new_size} ").as_bytes());
    out.extend_from_slice(
        format!("/Root {} {} R ", prev_root.number, prev_root.generation).as_bytes(),
    );
    out.extend_from_slice(format!("/Prev {prev_xref_off} ").as_bytes());
    // Forward /Info if the previous trailer had one — keeps the doc
    // metadata reachable through the new revision.
    if let Some(info_id) = prev_table.info() {
        out.extend_from_slice(
            format!("/Info {} {} R ", info_id.number, info_id.generation).as_bytes(),
        );
    }
    out.extend_from_slice(b">>\n");
    out.extend_from_slice(b"startxref\n");
    out.extend_from_slice(format!("{xref_off}\n%%EOF\n").as_bytes());

    // Compute /ByteRange [a b c d] — `a = 0`, `b = bytes up to and
    // including the `<` of /Contents`, `c = first byte after the `>`
    // of /Contents`, `d = total - c`.
    let a = 0i64;
    let b = contents_hex_offset as i64;
    let c = (contents_hex_offset + CONTENTS_HEX_LEN) as i64;
    let total = out.len() as i64;
    let d = total - c;

    Ok((out, [a, b, c, d], contents_hex_offset))
}

/// Patch the `/ByteRange` placeholder. Length-preserving.
fn patch_byte_range(pdf: &mut [u8], byte_range: [i64; 4]) {
    let formatted = format!(
        "/ByteRange [{:>10} {:>10} {:>10} {:>10}]",
        byte_range[0], byte_range[1], byte_range[2], byte_range[3]
    );
    debug_assert_eq!(
        formatted.len(),
        BYTE_RANGE_PLACEHOLDER.len(),
        "ByteRange width drift"
    );
    let placeholder_bytes = BYTE_RANGE_PLACEHOLDER.as_bytes();
    if let Some(pos) = pdf
        .windows(placeholder_bytes.len())
        .position(|w| w == placeholder_bytes)
    {
        pdf[pos..pos + placeholder_bytes.len()].copy_from_slice(formatted.as_bytes());
    }
}

/// Patch the `/Contents <…>` hex literal in place. The bytes between
/// `<` and `>` (the bytes the reader hex-decodes) are the EXCLUDED
/// range under `/ByteRange`, so this write does not shift any signed
/// byte offset — safe to call after the signature has been computed.
fn patch_contents(
    pdf: &mut [u8],
    contents_hex_offset: usize,
    contents_der: &[u8],
) -> Result<(), PdfError> {
    let hex_len_needed = contents_der.len() * 2;
    if hex_len_needed > CONTENTS_HEX_LEN {
        return Err(PdfError::other(format!(
            "SigWriter: CMS blob {} hex chars exceeds /Contents budget {}",
            hex_len_needed, CONTENTS_HEX_LEN
        )));
    }
    for (i, b) in contents_der.iter().enumerate() {
        let hi = (b >> 4) & 0x0F;
        let lo = b & 0x0F;
        pdf[contents_hex_offset + 2 * i] = hex_digit(hi);
        pdf[contents_hex_offset + 2 * i + 1] = hex_digit(lo);
    }
    // Pad remaining placeholder with `0`s — the reader's CMS parser
    // stops at the outer SEQUENCE boundary so trailing 0x00 bytes are
    // harmless.
    for byte in pdf
        .iter_mut()
        .skip(contents_hex_offset + hex_len_needed)
        .take(CONTENTS_HEX_LEN - hex_len_needed)
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

/// Concatenate `pdf[a..a+b] ‖ pdf[c..c+d]`.
fn concat_byte_ranges(pdf: &[u8], byte_range: [i64; 4]) -> Result<Vec<u8>, PdfError> {
    let [a, b, c, d] = byte_range;
    if a < 0 || b < 0 || c < 0 || d < 0 {
        return Err(PdfError::other("SigWriter: negative /ByteRange entry"));
    }
    let (a, b, c, d) = (a as usize, b as usize, c as usize, d as usize);
    if a + b > pdf.len() || c + d > pdf.len() {
        return Err(PdfError::other(
            "SigWriter: /ByteRange extends past file length",
        ));
    }
    let mut out = Vec::with_capacity(b + d);
    out.extend_from_slice(&pdf[a..a + b]);
    out.extend_from_slice(&pdf[c..c + d]);
    Ok(out)
}

// ---------------------------------------------------------------------
// CMS SignedData ContentInfo builder.
// ---------------------------------------------------------------------

/// Wrap a signature into a CMS `SignedData` ContentInfo per RFC 5652 §5.
///
/// Layout:
///
/// ```asn.1
/// ContentInfo ::= SEQUENCE {
///   contentType  OBJECT IDENTIFIER, -- id-signedData
///   content      [0] EXPLICIT SignedData
/// }
///
/// SignedData ::= SEQUENCE {
///   version              CMSVersion,                        -- 1
///   digestAlgorithms     SET OF DigestAlgorithmIdentifier,  -- { sha256 }
///   encapContentInfo     EncapsulatedContentInfo,           -- detached: eContent absent
///   certificates     [0] IMPLICIT CertificateSet OPTIONAL,
///   signerInfos          SET OF SignerInfo                  -- one
/// }
/// ```
///
/// Arguments:
///
/// * `algorithm` — picks the digest + signature OIDs.
/// * `signer_issuer_der` — DER bytes of the signer cert's `issuer` Name
///   SEQUENCE (tag + length included — same shape as
///   [`crate::pubsec::x509::Certificate::issuer_der`]).
/// * `signer_serial` — raw INTEGER body of the signer cert's serial.
/// * `cert_chain` — the full chain (signer first, then intermediates),
///   each entry a complete X.509 v3 `Certificate` SEQUENCE DER blob.
/// * `signed_attrs_body` — pre-packed `signedAttrs` body bytes (the
///   contents of the `[0] IMPLICIT SET` — i.e. the concatenated DER of
///   each Attribute SEQUENCE). `None` to emit a SignerInfo without
///   `signedAttrs`; `Some` is the round-30 default (RFC 5652 §5.4 +
///   §11.2 — `messageDigest` is required for CAdES-BES).
/// * `signature_bytes` — the raw signature octets (RSA-PKCS#1 v1.5
///   padded bytes / DER `Ecdsa-Sig-Value`) — what the `Signer` returned.
pub fn pkcs7_wrap_signed_data(
    algorithm: SigningAlgorithm,
    signer_issuer_der: &[u8],
    signer_serial: &[u8],
    cert_chain: &[Vec<u8>],
    signed_attrs_body: Option<&[u8]>,
    signature_bytes: &[u8],
) -> Vec<u8> {
    let digest_oid = algorithm.digest_algorithm_oid();
    let sig_oid = algorithm.signature_algorithm_oid();
    let sig_params = algorithm.signature_algorithm_params();

    // ---- SignerInfo body.
    let mut si_body = write_integer_u64(1); // CMSVersion = 1 (IAS)

    // IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }.
    let ias_body = {
        let mut b = signer_issuer_der.to_vec();
        b.extend_from_slice(&write_integer_bytes(signer_serial));
        b
    };
    si_body.extend_from_slice(&write_sequence(&ias_body));

    // digestAlgorithm AlgorithmIdentifier.
    let da_alg = {
        let mut b = write_oid(digest_oid);
        b.extend_from_slice(&write_null()); // SHA-256 carries NULL params per RFC 5754 §2
        write_sequence(&b)
    };
    si_body.extend_from_slice(&da_alg);

    // signedAttrs [0] IMPLICIT SET OF Attribute OPTIONAL.
    if let Some(sa) = signed_attrs_body {
        si_body.extend_from_slice(&implicit_signed_attrs_tlv(sa));
    }

    // signatureAlgorithm AlgorithmIdentifier.
    let sig_alg = {
        let mut b = write_oid(sig_oid);
        b.extend_from_slice(&sig_params);
        write_sequence(&b)
    };
    si_body.extend_from_slice(&sig_alg);

    // signature OCTET STRING.
    si_body.extend_from_slice(&write_octet_string(signature_bytes));
    let signer_info = write_sequence(&si_body);

    // ---- digestAlgorithms SET (single entry — same AlgorithmIdentifier
    //      as SignerInfo.digestAlgorithm per RFC 5652 §5.1).
    let da_set = write_set(&da_alg);

    // ---- encapContentInfo — detached (eContent omitted).
    let eci = {
        let body = write_oid(&OID_DATA);
        write_sequence(&body)
    };

    // ---- certificates [0] IMPLICIT CertificateSet OPTIONAL.
    let certs_body: Vec<u8> = cert_chain.iter().flat_map(|c| c.iter().copied()).collect();
    let certs_field = write_tlv(Class::ContextSpecific, true, 0, &certs_body);

    // ---- signerInfos SET (single SignerInfo).
    let si_set = write_set(&signer_info);

    // ---- SignedData SEQUENCE.
    let mut sd_body = write_integer_u64(1); // version = 1 (single-cert + IAS — RFC 5652 §5.1)
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

/// Build the `contentType` signed-attribute (RFC 5652 §11.1) for a given
/// eContent OID. The result is one DER `Attribute` SEQUENCE — caller
/// stitches it together with `messageDigest` (and any other attrs) via
/// [`pack_signed_attrs_implicit`].
pub fn build_content_type_attribute_der(content_type_oid: &[u64]) -> Vec<u8> {
    use crate::pubsec::verify::OID_ATTR_CONTENT_TYPE;
    let oid = write_oid(&OID_ATTR_CONTENT_TYPE);
    let value = write_oid(content_type_oid);
    let value_set = write_set(&value);
    let mut body = oid;
    body.extend_from_slice(&value_set);
    write_sequence(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byterange_placeholder_width_is_fixed() {
        let formatted = format!("/ByteRange [{:>10} {:>10} {:>10} {:>10}]", 0, 0, 0, 0);
        assert_eq!(formatted.len(), BYTE_RANGE_PLACEHOLDER.len());
        assert_eq!(formatted, BYTE_RANGE_PLACEHOLDER);
    }

    #[test]
    fn patch_byte_range_in_place_preserves_length() {
        let mut buf = format!("prefix {BYTE_RANGE_PLACEHOLDER} suffix").into_bytes();
        let original_len = buf.len();
        patch_byte_range(&mut buf, [0, 12345, 6789, 9876543210]);
        assert_eq!(buf.len(), original_len);
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.contains("/ByteRange [         0      12345       6789 9876543210]"));
    }
}
