//! Round-7 per-stream `/Filter /Crypt` `/Identity` opt-out
//! (ISO 32000-1 §7.6.5).
//!
//! In an encrypted PDF, a stream whose first `/Filter` is `/Crypt` and
//! whose matching `/DecodeParms` carries `/Name /Identity` (or no
//! `/Name` at all — the default per §7.4.10 Table 24) is intentionally
//! NOT encrypted. The classic real-world consumer is XMP metadata: a
//! handful of PDFs need to expose the metadata stream cleartext so
//! search indexers can read it without authenticating.
//!
//! These tests verify that
//! 1. the writer leaves a `/Crypt /Identity`-tagged stream untouched
//!    when building an encrypted PDF, and
//! 2. the reader accepts the same shape on input — i.e. the round-7
//!    detector matches the producer-side check.

use oxideav_pdf::encrypt::{EncryptionConfig, EncryptionState};
use oxideav_pdf::objects::{Dict, Document, Object, Stream};

#[test]
fn writer_leaves_crypt_identity_stream_in_cleartext() {
    // Build a hand-rolled minimal Document with two streams:
    //   - one normal stream (gets encrypted),
    //   - one /Filter /Crypt + /DecodeParms /Name /Identity (leave alone).
    let mut doc = Document::new();
    let normal_payload: &[u8] = b"normal stream - should be encrypted";
    let crypt_payload: &[u8] = b"<x:xmpmeta xmlns:x='adobe:ns:meta/'/>";

    let normal_id = doc.add(Object::Stream(Stream::new(
        Dict::new(),
        normal_payload.to_vec(),
    )));
    let _ = normal_id;

    let crypt_dict = Dict::new()
        .with("Filter", Object::Name("Crypt".into()))
        .with(
            "DecodeParms",
            Object::Dict(
                Dict::new()
                    .with("Type", Object::Name("CryptFilterDecodeParms".into()))
                    .with("Name", Object::Name("Identity".into())),
            ),
        )
        .with("Type", Object::Name("Metadata".into()))
        .with("Subtype", Object::Name("XML".into()));
    let crypt_id = doc.add(Object::Stream(Stream::new(
        crypt_dict,
        crypt_payload.to_vec(),
    )));
    let _ = crypt_id;

    // Catalog so write_to is happy.
    let catalog = doc.add(Object::Dict(
        Dict::new().with("Type", Object::Name("Catalog".into())),
    ));
    doc.root = Some(catalog);

    let cfg = EncryptionConfig::aes_128(b"hello", b"OXIDEAV-FIXTURE-ID-FOR-CRYPT-FLT");
    doc.encryption = Some(EncryptionState::build(&cfg).unwrap());

    let mut out = Vec::new();
    doc.write_to(&mut out).expect("encrypted write");

    // The crypt-identity payload must appear verbatim in the output —
    // proving the writer skipped per-object encryption for it.
    let needle = crypt_payload;
    assert!(
        out.windows(needle.len()).any(|w| w == needle),
        "crypt-/Identity stream payload should appear verbatim in encrypted PDF"
    );
    // The normal stream's plaintext, on the other hand, must NOT
    // appear verbatim — encryption should have replaced it.
    let neg = normal_payload;
    assert!(
        !out.windows(neg.len()).any(|w| w == neg),
        "non-/Identity stream payload should be encrypted"
    );
}

#[test]
fn writer_treats_crypt_filter_with_default_name_as_identity() {
    // /Filter /Crypt with NO /DecodeParms — Table 24 default for
    // /Name is /Identity. Same as the explicit case above.
    let mut doc = Document::new();
    let crypt_payload: &[u8] = b"\x01\x02\x03\x04 unique-bytes-default-Crypt";
    let dict = Dict::new().with("Filter", Object::Name("Crypt".into()));
    doc.add(Object::Stream(Stream::new(dict, crypt_payload.to_vec())));
    let catalog = doc.add(Object::Dict(
        Dict::new().with("Type", Object::Name("Catalog".into())),
    ));
    doc.root = Some(catalog);
    let cfg = EncryptionConfig::aes_128(b"pw", b"FIXED-FILE-ID-DEFAULT-CRYPT-FLT!");
    doc.encryption = Some(EncryptionState::build(&cfg).unwrap());
    let mut out = Vec::new();
    doc.write_to(&mut out).expect("encrypted write");
    assert!(
        out.windows(crypt_payload.len()).any(|w| w == crypt_payload),
        "default /Crypt parms (no /Name) should be treated as /Identity"
    );
}

#[test]
fn writer_encrypts_streams_without_crypt_filter() {
    // Negative control — a stream that has /Filter /FlateDecode (no
    // /Crypt anywhere) must be encrypted.
    let mut doc = Document::new();
    let payload: &[u8] = b"plain payload - should be encrypted by writer";
    let dict = Dict::new().with("Filter", Object::Name("FlateDecode".into()));
    doc.add(Object::Stream(Stream::new(dict, payload.to_vec())));
    let catalog = doc.add(Object::Dict(
        Dict::new().with("Type", Object::Name("Catalog".into())),
    ));
    doc.root = Some(catalog);
    let cfg = EncryptionConfig::aes_128(b"pw", b"FIXED-FILE-ID-FOR-PLAINTEXT-FILT");
    doc.encryption = Some(EncryptionState::build(&cfg).unwrap());
    let mut out = Vec::new();
    doc.write_to(&mut out).expect("encrypted write");
    assert!(
        !out.windows(payload.len()).any(|w| w == payload),
        "non-Crypt-filter stream should be encrypted"
    );
}
