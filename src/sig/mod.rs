//! PDF `/Sig` annotation writer — round 30.
//!
//! Symmetric encoder side of the round-27 / round-21 reader. Given a
//! [`oxideav_scene::Scene`] and a [`Signer`] implementation, emits a
//! signed PDF whose AcroForm `/Fields` contains a `/FT /Sig` field whose
//! `/V` points at a signature dictionary carrying the `/ByteRange`
//! placeholders and the PKCS#7 / CMS `SignedData` blob.
//!
//! # ISO references
//!
//! * **ISO 32000-1 §12.7.4.5** — Signature fields (`/FT /Sig`).
//! * **ISO 32000-1 §12.8.1** — Signature dictionaries (`/Type /Sig`,
//!   `/Filter /Adobe.PPKLite`, `/SubFilter /adbe.pkcs7.detached`,
//!   `/ByteRange [a b c d]`, `/Contents <…hex…>`).
//! * **RFC 5652 §5** — CMS `SignedData` ContentInfo (the bytes that go
//!   into `/Contents`).
//! * **RFC 5652 §5.4** — `SignedAttributes` re-tagging from `[0]
//!   IMPLICIT` to universal SET for hashing.
//! * **RFC 5652 §11.2** — `messageDigest` signed-attribute.
//!
//! # The byte-range placeholder pattern
//!
//! Per §12.8.1.1, `/ByteRange` covers the entire PDF *except* the bytes
//! between `<` and `>` of `/Contents`. So the encoder:
//!
//! 1. Writes the PDF body up to and including the `<` of `/Contents`.
//! 2. Reserves a fixed-width run of `0` bytes (the placeholder for the
//!    hex-encoded signature blob).
//! 3. Writes the closing `>`, the rest of the dictionary, the xref,
//!    the trailer, and `%%EOF`.
//! 4. Patches `/ByteRange` in place (the four 10-digit slots reserved
//!    earlier) with the actual offsets.
//! 5. Hashes the bytes named by `/ByteRange`, signs the hash, wraps
//!    the signature into a CMS `SignedData` ContentInfo, hex-encodes
//!    the blob, and overwrites the `0…0` run from step 2 with the hex
//!    digits (length-preserving — the budget is reserved generously
//!    enough that any RSA-2048 / ECDSA-P256 SHA-256 SignedData fits).
//!
//! Because the bytes between `<` and `>` are *excluded* from
//! `/ByteRange`, step 5's overwrite does not invalidate the hash
//! computed in step 4 — the byte-stable property is what makes this
//! pattern work.

pub mod timestamp;
pub mod writer;

pub use timestamp::{
    add_document_timestamp, build_tst_info, wrap_tst_in_signed_data, MessageImprint, MockTsaSigner,
    TsaSigner, OID_CT_TST_INFO,
};
pub use writer::{
    pkcs7_wrap_signed_data, sign_pdf_from_scene, EcdsaP256Sha256Signer, RsaPkcs1v15Sha256Signer,
    SigWriter, Signer, SignerIdentity, SigningAlgorithm,
};
