# oxideav-pdf

Pure-Rust **PDF writer + reader** for the oxideav framework. The
writer emits PDF 1.4 vector documents from
[`VectorFrame`](https://docs.rs/oxideav-core) /
[`Scene`](https://docs.rs/oxideav-scene) inputs (paths stay paths,
fills stay fills); the reader walks bytes back into a Scene, with
optional decryption for password-protected files. Zero C dependencies.

Part of the [oxideav](https://github.com/OxideAV/oxideav-workspace) framework — a pure-Rust media stack. Codec, container, and filter crates are implemented from the spec (no C codec libraries linked or wrapped, no `*-sys` crates).

## What round 1 supports

- **Paths**: `MoveTo` (`m`), `LineTo` (`l`), `CubicCurveTo` (`c`),
  `QuadCurveTo` (lifted to cubic via the `2/3 * (control - endpoint)`
  trick), `ArcTo` (flattened to cubic per SVG 1.1 Appendix F.6.5),
  `Close` (`h`).
- **Fills**: `Paint::Solid` (DeviceRGB `sc`), `Paint::LinearGradient`
  (axial pattern shading, `Pattern Type 2` + `Function Type 2`),
  `Paint::RadialGradient` (radial shading, `Function Type 3`).
- **Strokes**: width (`w`), cap (`J`), join (`j`), miter limit (`M`),
  dash pattern (`d`).
- **Transforms**: every `Group::transform` emits one `cm` operator.
- **Groups**: `q ... Q` save/restore brackets around children. Group
  opacity becomes an `ExtGState` resource referenced via `/GSx gs`.
- **Clip paths**: emitted before the children's content stream as `W n`
  (or `W* n` for even-odd fill rule).
- **Fill rules**: `NonZero` (`f` / `B`) vs. `EvenOdd` (`f*` / `B*`).
- **Embedded raster**: `ImageRef` whose underlying `VideoFrame` is
  RGBA8 lands as a FlateDecode `Image` XObject and is painted with `Do`.

## Encryption decode (full Standard handler)

The reader handles **password-protected PDFs** under the standard
security handler across the full revision range ISO 32000 defines:

- **R=2** — RC4-40 (V=1, `Length=40`).
- **R=3** — RC4-128 (V=2, `Length=128`).
- **R=4** — AES-128 CBC or RC4-128, picked from the crypt-filter
  `CFM` (`AESV2` vs `V2`).
- **R=5** — AES-256 CBC, V=5, `CFM=AESV3`. Adobe extension level 3
  (PDF 1.7); plain SHA-256 password derivation with validation +
  key salts.
- **R=6** — AES-256 CBC, V=5, `CFM=AESV3`. ISO 32000-2:2020
  (PDF 2.0); iterated SHA-256/384/512 hash chain (Algorithm 2.B)
  plus `/Perms` block validation (Algorithm 13).

Both user and owner passwords authenticate (Algorithms 6 + 7 for
R≤4; Algorithms 11 + 12 for R≥5); the default empty user password
is tried first so PDFs encrypted "just for permission flags" open
with no caller intervention. Strings and stream payloads are
decrypted via per-object keys (Algorithm 1) for R≤4 and via the
file key directly (no per-object derivation) for R≥5.

```rust
let pdf = std::fs::read("locked.pdf")?;
// Default API tries the empty user password.
match oxideav_pdf::read_pdf_to_scene(&pdf) {
    Ok(scene) => println!("opened: {} pages", scene.pages.unwrap().len()),
    Err(_)    => {
        // Password-protected — supply one.
        let scene = oxideav_pdf::read_pdf_to_scene_with_password(&pdf, b"hunter2")?;
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Per-stream crypt-filter overrides land in a follow-up round.

## Public-key encryption (decode + encode)

The reader and writer both handle **public-key-encrypted PDFs** under
the `adbe.pkcs7.s3` / `s4` / `s5` SubFilters of the public-key
security handler (ISO 32000-1 §7.6.4 + ISO 32000-2 §7.6.5):

- **`adbe.pkcs7.s3`** — RC4-40, V=1, SHA-1 file-key derivation.
- **`adbe.pkcs7.s4`** — RC4-128, V=2, SHA-1.
- **`adbe.pkcs7.s5`, V=4** — RC4-128 or AES-128 CBC via `CFM` (V2 / AESV2).
- **`adbe.pkcs7.s5`, V=5** — AES-256 CBC, `CFM=AESV3`, SHA-256.

The trailer's `/Recipients` array (or `/CF /<StmF> /Recipients` for
s5) carries one CMS `EnvelopedData` (RFC 5652 §6.1) per access-
permission set; each envelope's `KeyTransRecipientInfo` SET wraps the
content-encryption key with `RSAES-PKCS1-v1_5` to a recipient's RSA
public key. The reader matches by either `IssuerAndSerialNumber` (CMS
v0) or `SubjectKeyIdentifier` (CMS v2 — RFC 5280 §4.2.1.2 method 1
SHA-1 of the SPKI BIT STRING contents), RSA-decrypts the wrapped CEK,
decrypts the envelope contents (RC4 / AES-128 / AES-256 CBC), then
derives the file encryption key per §7.6.4.3 / §7.6.5.3.

```rust,ignore
use oxideav_pdf::{read_pdf_to_scene_with_certificate, PubSecCredential};

let cert_der    = std::fs::read("user.cert.der")?;
let pkcs8_der   = std::fs::read("user.key.pkcs8.der")?;
let credential  = PubSecCredential::from_der(&cert_der, &pkcs8_der)?;
let scene = read_pdf_to_scene_with_certificate(&pdf_bytes, &credential)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Round 11 lands the symmetric **encoder side**: the writer emits
public-key-encrypted PDFs that round-trip through the reader.

```rust,ignore
use oxideav_pdf::{
    write_pdf_from_scene_pubsec_encrypted, PubSecEncoderConfig, PubSecRecipient,
};

// One recipient — IssuerAndSerial form.
let recipient = PubSecRecipient::from_issuer_and_serial(
    issuer_der,           // recipient cert's `issuer` SEQUENCE bytes
    serial_bytes,         // recipient cert's serial INTEGER body
    rsa_public_key,
);
let cfg = PubSecEncoderConfig::pkcs7_s5_v5_aes256(vec![recipient]);
let pdf = write_pdf_from_scene_pubsec_encrypted(&scene, &cfg)?;
# Ok::<(), oxideav_pdf::PdfError>(())
```

`PubSecRecipient` also exposes `from_subject_key_identifier(ski, key)`
for the CMS v2 form. Round 12 adds **per-crypt-filter recipient
lists** — `write_pdf_from_scene_pubsec_multi_cf` + `PubSecMultiCfConfig`
+ `PubSecCfGroup` emit a doc with multiple permission sets (each its
own envelope), and `open_with_certificate_with_permissions` surfaces
the matched recipient's permission mask. Round 12 lands the **CMS KARI
decoder** (RFC 5652 §6.2.2) — KeyAgree (ECDH/DH) recipients parse
structurally. **Round 14 closes the unwrap**: P-256 ECDH + RFC 5753
§7.1.2 X9.63-SHA-256 KDF + RFC 3394 AES Key Wrap (128/192/256-bit) for
the `dhSinglePass-stdDH-sha256kdf-scheme` KEA OID. **Round 15 extends
the curve set**: P-384 (`dhSinglePass-stdDH-sha384kdf-scheme`,
X9.63-SHA-384) and X25519 (RFC 8418 §2.1, secg-scheme `…sha256kdf` +
`id-X25519`) join P-256 — pass `PubSecCredential::from_parsed_ec(cert,
KariCurve::P384, scalar)` (or `P256` / `X25519`) and the KARI envelope
opens through the same `read_pdf_to_scene_with_certificate` entry
point as KTRI. **Round 15 also lands the writer-side KARI encode**:
`write_pdf_from_scene_pubsec_kari(scene, &PubSecKariConfig)` mirrors
the round-11 KTRI writer — each `KariRecipient { curve, … }` becomes
one CMS KARI envelope with AES-256-WRAP. **Round 16** lands P-521 (`dhSinglePass-stdDH-sha512kdf-scheme`,
X9.63-SHA-512) + RFC 8418 §2.2 HKDF binding for X25519
(`dhSinglePass-stdDH-hkdf-sha256/384/512-scheme`, smime-alg 19/20/21).
**Round 24** closes the RFC 8418 curve set with X448 (RFC 7748 §5 / RFC
8410 §3 — `id-X448` 1.3.101.111, 56-byte raw u-coordinate, 224-bit
security level): pass `KariCurve::X448` and the same writer + reader
entry points handle it. Default KDF is X9.63-SHA-512 (security-strength
match); HKDF SHA-256/384/512 are also valid via the
`KariRecipient::x448_hkdf_*` constructors. Cross-checked against the
RFC 7748 §6.2 Alice/Bob shared-secret vector byte-for-byte.
**Round 17** closes the long-term-cert originator gap: when a KARI
envelope's `OriginatorIdentifierOrKey` is `IssuerAndSerial` or
`SubjectKeyIdentifier` rather than the in-band `OriginatorPublicKey`,
the recipient resolves the originator cert through a `TrustStore` —
pass it via `read_pdf_to_scene_with_certificate_and_trust_store(pdf,
&cred, &store)`. Round 17 also adds **read-only** decode for legacy
RC2-CBC (RFC 2268 + RFC 3217) and DES-EDE3-CBC (3DES, RFC 3370 §5.2)
envelope content algorithms so PDF 2.0-deprecated archives still open;
no encode-side support — the writer always uses AES.
**Round 18** surfaces previously-discarded CMS metadata: the envelope's
`OriginatorInfo` (RFC 5652 §10.2.1 — `certs[]` / `crls[]`) is now
exposed via `EnvelopedData::originator_info()`, and the `RecipientKeyIdentifier`'s
OPTIONAL `date` (`GeneralizedTime`) + `other` (`OtherKeyAttribute`)
fields are captured by the parser. New
`TrustStore::find_with_temporal_validity(ski, instant)` uses the RKID
`date` to pick the cert generation that was active when the envelope
was authored — useful for long-lived archives where multiple cert
generations exist for the same SKI. The `Certificate` parser now also
extracts the `validity` window (notBefore / notAfter), normalising
`UTCTime` to `GeneralizedTime` per RFC 5280 §4.1.2.5.1's 1950..2049
pivot for direct byte-comparison.
**Round 19** ships two orthogonal additions. **Document-level XMP
`/Metadata` stream** end-to-end (ISO 32000-1 §14.3.2 + Adobe XMP Spec
2012): writer entry `write_pdf_from_scene_with_xmp(scene, xmp_bytes)`
attaches the raw XMP RDF/XML packet to the catalog as a `/Type
/Metadata /Subtype /XML` stream (no `/Filter`); reader accessor
`DocumentReader::xmp_metadata()` returns `Some(bytes)` for documents
that carry one. **CMS `SignedData` parser scaffolding** (RFC 5652 §5
— PKCS#7): `pubsec::signed_data::parse_signed_data` decodes
`id-signedData` blobs into typed `SignedData { digest_algorithms,
encap_content, certs, crls, signer_infos }` + `SignerInfo` (sid,
digest / signature OIDs, signed / unsigned attribute lists with
raw-DER values, raw `signature` octets).

**Round 20** closes the round-19 verification deferral. New
`pubsec::verify::verify_signature(signer, certs, content)` resolves the
signer's certificate from a pool by `IssuerAndSerial` or
`SubjectKeyIdentifier`, hashes the canonical (universal-SET-tag)
re-encoding of `signedAttrs` per `digestAlgorithm`, and verifies the
hash against `signature` per `signatureAlgorithm` (RFC 5652 §5.4 +
§11.2). Hash side: SHA-1 / SHA-256 / SHA-384 / SHA-512. Signature
side: RSA-PKCS#1 v1.5 (the `rsaEncryption` + four `sha*WithRSA` OIDs
all map here), RSA-PSS (`id-RSASSA-PSS`), and ECDSA on P-256 / P-384
/ P-521 (curve dispatch by the cert SPKI's named-curve OID per RFC
5480 §2.1.1.1). When `signedAttrs` is present, the verifier also
cross-checks the `messageDigest` attribute against the eContent hash
(RFC 5652 §11.2) — so a tampered eContent fails even when the outer
signature still verifies. Detached signatures (PAdES — eContent absent)
feed the document bytes through `AttachedContent::External(&[u8])`.
Round-20 also extends `x509::Certificate` to capture
`spki_algorithm_oid` + `spki_algorithm_params` so the verifier can
route ECDSA on the named-curve OID without re-parsing the certificate.

**Round 21** closes the reader half of the round-20 follow-up list:
**PDF `/Sig` annotation reader** (ISO 32000-1 §12.7.4.5 + §12.8.1).
`DocumentReader::signatures()` walks the catalog → `/AcroForm /Fields`
tree (honouring `/FT` inheritance through non-terminal `/Kids`
parents per §12.7.3.1) and surfaces one [`PdfSignature`] per `/V`
signature dictionary it can parse. Each value carries the
[a, b, c, d] `/ByteRange`, the hex-decoded `/Contents` blob, the
`/SubFilter` (`adbe.pkcs7.detached` / `ETSI.CAdES.detached` etc.),
the optional metadata fields (`/Name`, `/Reason`, `/Location`,
`/ContactInfo`, `/M`), and — for the CMS-detached SubFilters — the
parsed [`pubsec::signed_data::SignedData`]. `PdfSignature::signed_message(pdf)`
concatenates the two `/ByteRange`-named slices into the byte string
the signing tool hashed; pass it as `AttachedContent::External(...)`
to the existing [`pubsec::verify::verify_signature`] for a full
end-to-end verify.

```rust,ignore
use oxideav_pdf::reader::DocumentReader;
use oxideav_pdf::pubsec::verify::{verify_signature, AttachedContent};
use oxideav_pdf::pubsec::x509::parse_certificate;

let mut r = DocumentReader::open(&pdf_bytes)?;
for sig in r.signatures()? {
    if !sig.is_cms_detached() { continue; }
    let signed = sig.signed_message(&pdf_bytes)?;
    let sd = sig.signed_data.as_ref().expect("CMS-detached parsed");
    let certs: Vec<_> = sd.certs.iter()
        .filter_map(|der| parse_certificate(der).ok())
        .collect();
    let ok = verify_signature(
        &sd.signer_infos[0],
        &certs,
        AttachedContent::External(&signed),
    )?;
    println!("signature verifies: {ok}");
}
# Ok::<(), oxideav_pdf::PdfError>(())
```

The reader is tolerant of unsigned slots (a Sig form field whose `/V`
is absent — common for "approval line still pending" templates), of
non-terminal parent fields without their own `/V`, and of malformed
`/Contents` blobs (the dict surfaces but `signed_data` is `None`).

**Round 30** closes the symmetric writer half: the new
`oxideav_pdf::sig` module emits signed PDFs with valid `/ByteRange`
+ PKCS#7 / CMS `SignedData` `/Contents` blobs (ISO 32000-1 §12.7.4.5 +
§12.8.1 + §7.5.6 + RFC 5652 §5 + §5.4 + §11.2). The classic
"ByteRange-placeholder fill-in" pattern is implemented end-to-end —
build PDF with a fixed-width `/ByteRange` `[?? ?? ?? ??]` + a
`/Contents <0…0>` placeholder (8192 hex chars = 4096 raw bytes,
enough for any RSA-2048 / ECDSA-P256 SHA-256 SignedData with a single
signer + cert), patch `/ByteRange` with the computed offsets, hash the
bytes spanned by `/ByteRange`, wrap into a CAdES-BES-style CMS
`SignedData` with `signedAttrs = { contentType, messageDigest }` per
RFC 5652 §11.1+§11.2, hex-encode, overwrite the placeholder. A
[`Signer`] trait decouples the crypto: bring your own `ring` / `rsa` /
`p256` / HSM impl, or use the reference [`RsaPkcs1v15Sha256Signer`] /
[`EcdsaP256Sha256Signer`] that wrap the in-crate deps.

```rust,ignore
use oxideav_pdf::{sign_pdf_from_scene, RsaPkcs1v15Sha256Signer, SignerIdentity};

let private_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)?;
let signer = RsaPkcs1v15Sha256Signer::new(private_key);
let identity = SignerIdentity::from_signer_cert_der(cert_der)?;
let signed_pdf = sign_pdf_from_scene(&scene, &signer, identity)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Round-30 ships RSA-PKCS#1 v1.5 + SHA-256 and ECDSA-P256 + SHA-256.
RSA-PSS, ECDSA on P-384 / P-521, and Ed25519 plug in through the same
[`Signer`] trait without touching the writer surface. The output is
accepted by `qpdf --check` and verifies end-to-end against the
round-27 PKCS#7 verify dispatch.

## Encryption encode (writer side)

The writer emits password-protected PDFs across the same revision range
the reader handles. [`oxideav_pdf::write_pdf_from_scene_encrypted`]
takes a [`Scene`] and an [`encrypt::EncryptionConfig`] and produces
bytes that round-trip through `read_pdf_to_scene_with_password`:

```rust
use oxideav_pdf::encrypt::EncryptionConfig;

let cfg = EncryptionConfig::aes_256_r6(b"hunter2", b"FILE-ID-16-BYTES");
let pdf = oxideav_pdf::write_pdf_from_scene_encrypted(&scene, &cfg)?;
# Ok::<(), oxideav_pdf::PdfError>(())
```

Writer-side coverage matches the reader: R=2 (RC4-40), R=3 (RC4-128),
R=4 (AES-128 / RC4 via `CFM`), R=5 (Adobe ext L3), R=6 (ISO 2.0).
`/O`, `/U`, `/OE`, `/UE`, and `/Perms` come from the canonical
algorithms (3, 4, 5 for V≤4; 8, 9, 10 for V=5); per-object key
derivation is Algorithm 1 (V≤4) or the file key directly (V=5).

## Cross-reference streams

Both reader and writer support the binary cross-reference *stream*
form introduced in PDF 1.5 (ISO 32000-1 §7.5.8): a `/Type /XRef`
stream object whose body packs each entry into `/W [w1 w2 w3]`
big-endian fields, Flate-compressed with `/Predictor 12` (PNG-Up).
The classical `xref`-keyword form (PDF 1.0..1.4) is also accepted
on input and remains the writer's default; opt into the stream form
via [`oxideav_pdf::write_pdf_from_scene_xref_stream`].

**Hybrid-reference files** (§7.5.8.4) are also accepted on the read
path. A hybrid PDF carries a classical `xref` subsection (so
pre-PDF-1.5 tools can still find the catalog and page tree) plus an
`/XRefStm offset` entry in the same update trailer that points at a
supplementary `/Type /XRef` stream. The supplementary stream surfaces
the compressed-object slots the classical subsection marks `free`.
The reader follows the §7.5.8.4 resolution order — current section's
classical entries first, then its `/XRefStm` entries, then walk
`/Prev` — and applies a newer-wins merge so hidden compressed slots
override the classical `free` markers they shadow. Chained `/XRefStm`
references are bounded at 32 hops and short-circuit on cycles, the
same guards the `/Prev`-section walker already enforces.

**§7.5.8.3 forward-compat.** Unknown entry types (≥ 3) are resolved
as references to the null object per spec — "any other value shall be
interpreted as a reference to the null object, thus permitting new
entry types to be defined in the future." The `/W` array's
zero-width defaults are honoured (`w[0] == 0` ⇒ type field defaults
to 1; `w[2] == 0` ⇒ generation defaults to 0 per Table 18 Type 1
field 3). Multi-subsection `/Index` arrays walk per-subsection
starting object numbers rather than implicitly numbering from zero.

## Object streams

Both reader and writer support PDF 1.5+ object streams
(`/Type /ObjStm`, ISO 32000-1 §7.5.7). The reader resolves
`Compressed` xref entries by fetching the containing object stream,
parsing its `(obj_num offset)` header, and returning the body bytes
from the matching slot. The writer packs every compressible
indirect object (every dict that isn't a stream and isn't the
Catalog) into one ObjStm container — opt in via
[`oxideav_pdf::write_pdf_from_scene_object_stream`]. Stream objects
(content streams, image XObjects, the xref stream itself) cannot be
compressed per §7.5.7 and remain at their own byte offsets.

## Stream filters (round 104 adds the `/Predictor` post-filter)

`decode_stream` recovers a stream's raw payload by applying its
`/Filter` (single `Name` or `Array` chain, §7.4.1). The generic
decompression filters are all handled in array order, so chains like
`[/ASCII85Decode /LZWDecode]` (§7.4.4 Example 2) round-trip:

- **`/FlateDecode`** (§7.4.4) — zlib DEFLATE; the writer's default.
- **`/LZWDecode`** (§7.4.4.2) — variable-width (9..=12-bit) MSB-first
  LZW, the TIFF flavour. Round 98 wires this through `decode_stream`
  plus the round-23 image-XObject and round-35 inline-image filter
  peels. The `/EarlyChange` parameter (§7.4.4.3 Table 8) is honoured
  from `/DecodeParms`, defaulting to `1` (TIFF/PDF default); the
  KwKwK self-reference and clear-table (256) / EOD (257) codes are
  handled, and a truncated stream returns its partial decode.
- **`/ASCII85Decode`** (§7.4.3), **`/ASCIIHexDecode`** (§7.4.2),
  **`/RunLengthDecode`** (§7.4.5) — also accepted in single + chain
  position, including the inline-image abbreviations (`/Fl`, `/LZW`,
  `/A85`, `/AHx`, `/RL`).

Round 104 wires the **`/DecodeParms /Predictor` post-filter**
(§7.4.4.4) into `decode_stream`, so a `/FlateDecode` or `/LZWDecode`
stream whose `/DecodeParms` carries `/Predictor` > 1 is un-differenced
after inflating — the same path the xref-stream walker already used,
now reaching every generic stream:

- **PNG predictors** (`/Predictor 10..=15`, Table 10) — each row's
  leading algorithm tag (Table 9: None / Sub / Up / Average / Paeth)
  is authoritative, with the "left"/"upper-left" neighbours taken
  `bpp = ceil(Colors * BitsPerComponent / 8)` bytes back.
- **TIFF Predictor 2** (`/Predictor 2`) — per-component left
  differencing, with sub-byte `/BitsPerComponent` (1 / 2 / 4) unpacked,
  summed modulo `2^bpc`, and repacked; 8- and 16-bit components run
  byte/word-wise.

`/Colors`, `/BitsPerComponent`, and `/Columns` are read from the same
parameter dict (Table 8 defaults 1 / 8 / 1). `/Predictor 1` (or no
`/DecodeParms`) is a no-op passthrough.

Terminal image-codec filters (`/DCTDecode`, `/JPXDecode`,
`/JBIG2Decode`, `/CCITTFaxDecode`) are *not* decoded here — they keep
routing to the dedicated image walkers that hand the opaque payload to
a codec crate.

Validated against ISO 32000-1:2008 §7.4.4.2 Example 2's packed vector
(`80 0B 60 50 22 0C 0C 85 01` → `45 45 45 45 45 65 45 45 45 66`), plus
PNG (Sub / Up / Average / Paeth) and TIFF-2 (8-bit, RGB-interleaved,
4-bit) predictor round-trips.

## Indirect stream `/Length` (round 91)

The reader resolves stream-object `/Length` entries that are
**indirect references** rather than direct integers, per ISO 32000-1
§7.3.10 Example 3:

```
7 0 obj
    << /Length 8 0 R >>
stream
    BT /F1 12 Tf 72 712 Td ( ... ) Tj ET
endstream
endobj

8 0 obj
    77
endobj
```

This shape is what every one-pass PDF writer produces — the encoder
doesn't know the compressed body length until after deflating it, so
the dict carries a forward reference to an integer object written
*after* the stream. Real-world spec PDFs (e.g.
`docs/video/mpeg1/ISO_IEC_11172-2-MPEG1-Video-1993.pdf`) use this on
**every** content stream. Before round 91 the reader rejected them
outright; now it consults the xref table, fetches the
length-carrying integer, and patches the resolved direct value into
the stream dictionary so downstream consumers (`decode_stream`,
encryption length tracking) never see the stale `Reference`.

The resolver is exposed at the parser level as
`Parser::parse_indirect_with_length_resolver(&mut dyn LengthResolver)`
— callers that already have an xref table provide a closure,
callers that don't (the xref-stream parser itself, before any xref
has been built) pass `NoLengthResolver` and indirect `/Length` is
rejected per §7.5.8's effective direct-integer requirement.
Compressed-target lookups (length integer stored inside an ObjStm)
surface a clear error rather than mis-resolving; not yet seen in the
wild.

## Incremental updates

[`oxideav_pdf::write_pdf_incremental_update`] appends new revisions
to a previously-written PDF per ISO 32000-1 §7.5.6 — the new
revision's body is appended verbatim, followed by a new xref
subsection that lists only the changed slots, plus a trailer
carrying `/Prev <prev_xref_off>` pointing back at the original
revision. The reader follows the `/Prev` chain and merges entries:
the newest revision wins on overlap.

```rust,ignore
let original = oxideav_pdf::write_pdf_from_scene(&scene_v1)?;
// ... time passes; user adds two pages ...
let updated = oxideav_pdf::write_pdf_incremental_update(&original, &new_pages)?;
// `updated` starts with `original` byte-for-byte, then appends.
```

## Per-stream `/Crypt /Identity` opt-out

ISO 32000-1 §7.6.5 lets a single stream opt out of per-object
encryption by listing `/Crypt` as its first `/Filter` with
`/DecodeParms /Name /Identity` (or no `/Name` — the default per
§7.4.10 Table 24). The writer leaves such streams untouched while
encrypting the rest of the file; the reader applies the same rule
on input. The classic consumer is XMP metadata streams that need to
remain searchable in encrypted PDFs.

## Linearization (Fast Web View)

Round 9 emits **Linearized PDF** per ISO 32000-1 §7.5.6 + Annex F.
[`write_pdf_from_scene_linearized`] produces a PDF whose first 1024
bytes carry a complete linearization parameter dictionary
(`/Linearized 1` + `/L` + `/H` + `/O` + `/E` + `/N` + `/T`); the
on-wire layout follows F.3.1 (header → lin-dict → first-page xref →
catalog → hint stream → first-page section → remaining pages →
main xref). `startxref` at EOF points at the first-page xref;
the first-page trailer's `/Prev` points at the main xref. The
output is also a valid plain PDF — readers ignoring `/Linearized`
walk the same Catalog + Pages tree + page content.

The hint stream emits the page offset table (F.4.1) with full
per-page entries (round 13: items 1, 2, 6, 7 — object count, page
length, content stream offset relative to page start, content stream
length) at fixed 32-bit width, plus minimal shared-object (F.4.2),
thumbnail (F.4.3), and outline (F.4.4) header sections. Entry counts
for the latter three are zero so no per-shared-object / per-thumbnail
/ per-outline bytes are generated. The hint dict carries `/S`, `/T`,
`/O` offsets into the decoded hint stream so a reader walking the
optional tables sees a fully-formed (if empty) layout. Extended
generic (F.4.5) and embedded-file-stream (F.4.6) tables are still
deferred — we generate no interactive forms / structure trees /
embedded files.

## Text extraction (round 22)

[`DocumentReader::text_extraction`] walks every page's content
stream and emits one [`TextRun`] per `Tj` / `TJ` / `'` / `"` operator,
with the text-matrix origin and `Tf` font + size resolved per ISO
32000-1 §9.4.4. Encoded glyphs are mapped back to Unicode through
the font's `/ToUnicode` CMap when present (parsing the `bfchar` /
`bfrange` blocks defined in §9.10.3 + Adobe Tech Note #5014); for
Identity-H Type 0 fonts without `/ToUnicode` the walker falls back
to interpreting each 2-byte CID as a BMP code point. Simple fonts
honour `/Encoding /WinAnsiEncoding` and `/Encoding /MacRomanEncoding`
(Annex D.2), with a Latin-1 fallback for everything else.

```rust,ignore
use oxideav_pdf::reader::DocumentReader;

let pdf = std::fs::read("invoice.pdf")?;
let mut reader = DocumentReader::open(&pdf)?;
let extraction = reader.text_extraction()?;
for run in &extraction.runs {
    println!("@({:.0},{:.0}) {}/{}: {}",
        run.position.0, run.position.1,
        run.font_name, run.font_size, run.text);
}
println!("flat: {}", extraction.flat_text());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Runs come out in stream order — the rendering order the page would
have laid down. Reading-order reconstruction (column / paragraph
segmentation) is a future-round followup; round 22 gives the raw
runs plus matrix positions so a downstream layout pass can do its
own segmentation.

## JPEG passthrough on Image XObjects (round 23)

[`DocumentReader::image_xobjects`] walks every page's
`/Resources /XObject` subdict and surfaces every Image XObject whose
final filter is `/DCTDecode` (ISO 32000-1 §7.4.8). The returned
[`PdfImageXObject`] carries the unmodified JPEG bytes — the exact
JPEG-1 / JFIF stream a JPEG decoder needs — plus the dictionary's
`/Width`, `/Height`, `/ColorSpace` (mapped to the [`ColorSpace`] tag:
`DeviceRGB` / `DeviceCMYK` / `DeviceGray` / `Indexed` / `Other`), and
`/BitsPerComponent`. Wrapping `/ASCII85Decode` / `/ASCIIHexDecode` /
`/FlateDecode` filters preceding `/DCTDecode` are unwrapped before
the JPEG payload is returned, so callers always get a self-contained
JPEG stream (the standard `pdfimages -all` shape).

```rust,ignore
use oxideav_pdf::reader::DocumentReader;

let pdf = std::fs::read("photos.pdf")?;
let mut reader = DocumentReader::open(&pdf)?;
for (id, image) in reader.image_xobjects()? {
    let path = format!("xobj-{}.jpg", id.number);
    std::fs::write(&path, &image.data)?;
    println!("{} ({}x{} {:?}, {} bpc)", path,
        image.width, image.height, image.color_space,
        image.bits_per_component);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

The same XObject referenced from multiple pages is returned once
(deduplicated by `ObjectId`). Image XObjects with non-DCTDecode
filters (`FlateDecode`-only raster XObjects, `JBIG2Decode`, `JPXDecode`,
`CCITTFaxDecode`) are silently skipped — the round-23 walker is
JPEG-only. Cross-checked against `pdfimages -all` (poppler-utils):
the bytes are byte-identical.

## Inline-image extraction (round 35)

[`DocumentReader::inline_images`] walks every page's content stream and
surfaces every `BI … ID … EI` triplet (ISO 32000-1 §8.9.7) as a
[`PdfInlineImage`] — the content-stream-level counterpart of the
round-23 Image XObject walker. Both abbreviated (Table 93 — `/W`,
`/H`, `/CS /RGB`, `/F /DCT`) and long-form (`/Width`, `/ColorSpace
/DeviceRGB`, `/Filter /DCTDecode`) keys are accepted on input.

Filter coverage mirrors the round-23 XObject walker: wrapping `/A85`,
`/AHx`, `/Fl`, `/RL` are peeled before the payload reaches the
caller; terminal codec filters (`/DCT`, `/JPX`, `/JBIG2`, `/CCF`) are
left in place and surface as an [`InlineImageFilter`] tag so a
downstream JPEG / JPEG2000 / JBIG2 / CCITT-Fax decoder can take
over.

The `/IM true` image-mask flag is preserved (1-bit stencil that takes
its colour from the current path-paint state); `source_page_index`
and `source_page_obj` are filled in so callers can locate where in
the document the inline image was painted.

```rust,ignore
use oxideav_pdf::reader::{DocumentReader, InlineImageFilter};

let pdf = std::fs::read("scan.pdf")?;
let mut reader = DocumentReader::open(&pdf)?;
for img in reader.inline_images()? {
    println!("page {} {}x{} bpc={} filter={:?} {} bytes",
        img.source_page_index, img.width, img.height,
        img.bits_per_component, img.filter, img.data.len());
    if matches!(img.filter, InlineImageFilter::DctDecode) {
        std::fs::write(format!("inline-p{}.jpg", img.source_page_index),
                       &img.data)?;
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

§8.9.7 framing detail: the `EI` terminator must be preceded by a
whitespace byte and followed by whitespace or EOF — embedded `EI`
sequences inside the payload (with no surrounding whitespace) are
preserved as data, matching `pdfimages -all`'s extraction behaviour.

## Optional Content / OCG layers (round 95)

[`DocumentReader::optional_content`] walks the catalog's
`/OCProperties` entry and surfaces every Optional Content Group +
configuration (ISO 32000-1 §8.11 + §7.7.2 Table 28). PDFs with
toggleable "layers" — CAD drawings, multi-language alternates,
watermark / content separations — store one [`OptionalContentGroup`]
per `/Type /OCG` indirect object, with `/Name` UI label, optional
`/Intent` (`View` / `Design`), and optional `/Usage` filters
(language / zoom / print / view / export / page-element).

The configuration dictionary's `/BaseState` (`ON` / `OFF` /
`Unchanged`) + `/ON` + `/OFF` arrays apply per §8.11.4.5 algorithm
steps (a)+(b)+(c), giving each group a resolved boolean state.
`OptionalContent::is_visible(group_id)` is the lookup;
`states_for_config(&alt)` re-resolves under any of the `/Configs`
alternate configurations.

```rust,ignore
use oxideav_pdf::reader::DocumentReader;
let mut r = DocumentReader::open(&pdf_bytes)?;
if let Some(oc) = r.optional_content()? {
    println!("{} layers, default cfg = {:?}",
        oc.groups.len(), oc.default_config.name);
    for g in &oc.groups {
        println!("  {:?} {} ({})", g.id, g.name,
            if oc.is_visible(g.id) { "ON" } else { "OFF" });
    }
}
# Ok::<(), oxideav_pdf::PdfError>(())
```

Optional Content Membership Dictionaries (OCMDs, Table 99) are also
covered — `parse_membership(reader, dict)` decodes the `/OCGs`
reference list, the `/P` policy (`AllOn` / `AnyOn` / `AnyOff` /
`AllOff`), and the `/VE` visibility expression (PDF 1.6 — `[/And …]`
/ `[/Or …]` / `[/Not e]`, recursively nested). `OptionalContent::evaluate_membership(&mem)`
plugs an OCMD into the current state map and returns the boolean
visibility per §8.11.2.2's NOTE 2 (when `/VE` is present, the
expression wins over `/P`). The configuration's `/Order` array
parses into a tree of [`OcOrderItem::Group`] leaves and
[`OcOrderItem::Subtree { label, items }`] nodes — both the labelled-
collection form (`[(Frog Anatomy) g1 g2]`) and the sublayer-nesting
form (`[g1 [g2 g3]]`).

## Action enumeration (round 36)

[`DocumentReader::actions`] walks every place an action can hide in
a PDF and surfaces each as a [`PdfAction`] — the audit-grade
counterpart to the round-25 link reader (links only) and the round-26
annotation reader (annotations only). Sources walked (ISO 32000-1
§12.6):

- **Catalog `/OpenAction`** (§7.7.2 Table 28) — fires on document
  open. Action-dict form lands; destination-array form is purely
  navigation and is skipped.
- **Catalog `/AA`** additional actions (§12.6.3 Table 197) — `WC`,
  `WS`, `DS`, `WP`, `DP`.
- **Page `/AA`** (§12.6.3 Table 196) — `O` (page open), `C` (page
  close).
- **Annotation `/A` + `/AA`** (§12.5.3 Table 165) — `E`/`X`/`D`/`U`/
  `Fo`/`Bl`/`PO`/`PC`/`PV`/`PI` plus the primary `/A`.
- **Form-field `/A` + `/AA`** (§12.7.4 Table 220 + Table 196 events
  `K`/`F`/`V`/`C`) walked through the `/AcroForm /Fields` tree, with
  `/Kids` recursion bounded at depth 32.
- **Catalog `/Names /JavaScript`** name tree (§7.7.4 Table 31 +
  §7.9.6) — every JavaScript function the document defines.

Each action's `/Next` chain (§12.6.3) is followed recursively up to
depth 32, with indirect-reference dedup to break malformed cycles.
The carrier action and every chained-`/Next` action surface as their
own [`PdfAction`] with progressively-higher `chain_depth`.

Per-type payload decodes the high-signal entries Table 198 calls
out:

- **`/URI`** (§12.6.4.7 Table 206) — URI text + `/IsMap`.
- **`/JavaScript`** (§12.6.4.16 Table 217) — `/JS` is decoded from
  literal-string / hex-string / stream form, recognising UTF-8 BOM
  (`EF BB BF`), UTF-16BE BOM (`FE FF`), UTF-16LE BOM (`FF FE`), or
  PDFDocEncoding fallback.
- **`/Launch`** (§12.6.4.5 Table 202) — `/F` filename + `/NewWindow`.
- **`/GoToR`** (§12.6.4.3 Table 200) / **`/GoToE`** (§12.6.4.4
  Table 201) — `/F` filespec + raw `/D` destination.
- **`/SubmitForm`** (§12.7.5.2 Tables 236+237) — `/F` URL + `/Flags`
  bitfield (Include/Exclude / IncludeNoValueFields / ExportFormat /
  GetMethod / SubmitCoordinates / XFDF …).
- **`/ResetForm`** (§12.7.5.3 Table 239), **`/ImportData`**
  (§12.7.5.4 Table 240), **`/Hide`** (§12.6.4.10 Table 209),
  **`/Named`** (§12.6.4.11 Table 211), **`/SetOCGState`** (§12.6.4.12
  Table 212 — On/Off/Toggle counts), **`/GoTo`** (§12.6.4.2 — page
  index resolved when `/D` is an explicit array).
- The remaining Table 198 types (`/Thread`, `/Sound`, `/Movie`,
  `/Rendition`, `/Trans`, `/GoTo3DView`) surface as their unit
  variants; unknown `/S` values fall through to
  `ActionKind::Other { kind }` with the raw name preserved.

```rust,ignore
use oxideav_pdf::reader::{ActionKind, ActionTrigger, DocumentReader};

let mut r = DocumentReader::open(&pdf_bytes)?;
for action in r.actions()? {
    match (&action.trigger, &action.kind) {
        (ActionTrigger::CatalogOpen, ActionKind::JavaScript { script }) => {
            println!("OPEN-JS (auto-fires!): {script}");
        }
        (_, ActionKind::Launch { file, .. }) => {
            println!("launches binary: {:?}", file);
        }
        (_, ActionKind::SubmitForm { url, flags }) => {
            println!("submits form to {:?} (flags {flags:#x})", url);
        }
        (trg, kind) => println!("[{trg:?}] {kind:?}"),
    }
}
# Ok::<(), oxideav_pdf::PdfError>(())
```

The walker is tolerant of malformed action dicts (skipped silently),
of `/Next` chains that loop back on themselves (the indirect-ref
visited-set cuts the loop), and of action types this round doesn't
decode (`ActionKind::Other` preserves the raw `/S` name so callers
walking a forensic / unknown PDF still get a complete enumeration).

## Annotations beyond Link + XMP packet fields (round 26)

[`DocumentReader::annotations`] walks every page's `/Annots` array and
surfaces every entry as a [`PdfAnnotation`] (ISO 32000-1 §12.5.6
Tables 169..209). Per-subtype payload covers `/Text` (sticky notes —
`/Open`, `/Name` icon, `/State`, `/StateModel`), `/FreeText` (`/DA`,
`/Q` quadding, `/RC`, `/IT` intent), `/Stamp` (icon name), the four
text-markup variants `/Highlight` / `/Underline` / `/Squiggly` /
`/StrikeOut` (`/QuadPoints`), `/Square` + `/Circle` (`/IC`, `/RD`),
`/Link` (re-uses the round-25 go-to / URI decoder), and `/Widget`
(`/FT`, `/T`, `/V`). Unknown subtypes (Movie, Sound, 3D, RichMedia,
…) surface as `AnnotationKind::Other { subtype }`. Common Table 164
fields (`/Rect`, `/Contents`, `/NM`, `/M`, `/F`, `/C`, `/Border`) are
decoded for every subtype.

```rust,ignore
use oxideav_pdf::{reader::DocumentReader, AnnotationKind};

let mut r = DocumentReader::open(&pdf_bytes)?;
for a in r.annotations()? {
    println!("page {} {:?}: {}", a.source_page_index, a.rect,
        a.contents.as_deref().unwrap_or(""));
    if let AnnotationKind::Stamp { icon } = &a.kind {
        println!("  stamp icon: {icon}");
    }
}
# Ok::<(), oxideav_pdf::PdfError>(())
```

[`DocumentReader::xmp_packet`] parses the document-level XMP packet
round-19 surfaces into a structured [`XmpPacket`] (ISO 32000-1
§14.3.2 + Adobe XMP Spec 2012 / ISO 16684-1 / ISO 19005-1..3 §6.x).
Covers the most-used Dublin Core (`dc:title` through `rdf:Alt`,
`dc:creator` through `rdf:Seq`, `dc:subject` `rdf:Bag`, `dc:rights`,
`dc:format`), XMP Basic (`xmp:CreateDate` / `xmp:ModifyDate` /
`xmp:MetadataDate` / `xmp:CreatorTool`), PDF schema (`pdf:Producer` /
`pdf:Keywords` / `pdf:PDFVersion` / `pdf:Trapped`), and PDF/A
identification (`pdfaid:part` / `pdfaid:conformance`) fields. Element
and attribute forms both recognised; XML entities (`&amp;` / `&lt;` /
`&gt;` / `&quot;` / `&apos;`) plus numeric character references
decode. `XmpPacket::is_pdf_a()` + `pdf_a_conformance()` collapse the
pair into a `1B`-style PDF/A conformance designator.

```rust,ignore
let mut r = oxideav_pdf::reader::DocumentReader::open(&pdf_bytes)?;
if let Some(p) = r.xmp_packet()? {
    println!("title:    {:?}", p.dc_title);
    println!("creator:  {:?}", p.dc_creator);
    println!("producer: {:?}", p.pdf_producer);
    if p.is_pdf_a() {
        println!("PDF/A conformance: {:?}", p.pdf_a_conformance());
    }
}
# Ok::<(), oxideav_pdf::PdfError>(())
```

## Simple-font `/Encoding /Differences` resolver (round 28)

Simple Type 1 / TrueType / Type 3 fonts may carry their `/Encoding` as
a dictionary that overlays a `/Differences` array on top of a named
`/BaseEncoding` (ISO 32000-1 §9.6.6.1). The reader resolves this
properly: the array's flat `[N name1 name2 … M nameK …]` form is
parsed (numeric tokens reset the running code; names land at
consecutive slots), and each glyph name maps to its Unicode scalar
through the Adobe Glyph List (subset staged under
`docs/document/pdf/agl/subset.txt`, ~320 glyph names). The resolver
plugs into the [`DocumentReader::text_extraction`] path so a
`/Differences`-using font decodes correctly to Unicode.

```rust,ignore
use oxideav_pdf::reader::{
    apply_encoding_differences, parse_encoding_differences, BaseEncoding,
    EncodingMap,
};
// Imagine an inline encoding dict resolved from a PDF font:
//   /Encoding << /BaseEncoding /WinAnsiEncoding
//                /Differences [24 /breve /caron /circumflex] >>
let diffs = parse_encoding_differences(&diffs_array)?;
let base  = EncodingMap::from_base(BaseEncoding::WinAnsi);
let map   = apply_encoding_differences(&base, &diffs);
assert_eq!(map.decode(&[0x18]), "\u{02D8}"); // breve
# Ok::<(), oxideav_pdf::PdfError>(())
```

Unknown glyph names emit U+FFFD as a marker (matching what
`pdftotext --raw` does for un-resolvable glyphs). Multi-character
glyph expansions (`/fi` → "fi", `/fl` → "fl") are accommodated. Six
base encodings are recognised: `WinAnsi` / `MacRoman` / `MacExpert` /
`Standard` / `Symbol` / `ZapfDingbats`. Full AGL coverage (CJK,
Cyrillic, Devanagari) is round-29+.

## Reading-order layout pass (round 29)

[`DocumentReader::read_in_logical_order`] walks the catalog's
`/StructTreeRoot /K` tree and emits text runs in *author-intended*
reading order rather than the painter's raster order (ISO 32000-1
§14.6 + §14.7 + §14.8 — Tagged PDF). For a 2-column document, naive
raster extraction interleaves column 1's first row, column 2's first
row, column 1's second row, …; the round-29 pass walks `[Sect_col1,
Sect_col2]` and emits all of column 1 before any of column 2. The
walker handles every leaf shape ISO 32000-1 §14.7.4.4 defines:
bare-integer MCID kids (resolve against the ancestor's inheritable
`/Pg`), `<</Type /MCR /Pg p /MCID m>>` marked-content references with
their own `/Pg` overrides (cross-page tables), `<</Type /OBJR …>>`
object references (skipped — they reference annotations, not text),
and nested `/StructElem` kids which recurse with a 64-deep cycle
guard.

```rust,ignore
use oxideav_pdf::reader::{DocumentReader, LayoutMode};

let mut r = DocumentReader::open(&pdf_bytes)?;
let result = r.read_in_logical_order()?;
match result.mode {
    LayoutMode::Tagged => println!("logical reading order:"),
    LayoutMode::Raster => println!("raster fallback (no /StructTreeRoot):"),
}
for run in &result.runs {
    println!("  {}", run.text);
}
# Ok::<(), oxideav_pdf::PdfError>(())
```

Documents *without* a `/StructTreeRoot` (or with a malformed / empty
tree) fall back to the existing raster-order extraction with
`LayoutMode::Raster` set on the return so callers can branch. The
pass also exposes `extract_text_marked(reader)` which emits every
text run alongside the marked-content `/MCID` it was painted under
(for callers that want to assemble a custom logical order outside the
StructTreeRoot — e.g. PDF/UA accessibility audits).

## AcroForm interactive-widget writer (round 31)

[`write_pdf_with_form`] is the writer-side counterpart of the
round-26 `AnnotationKind::Widget` reader. Given a `Scene` in pages
mode plus a slice of `FormField` specs it emits a PDF whose Catalog
carries `/AcroForm` and whose page `/Annots` arrays carry the matching
`/Subtype /Widget` annotations (ISO 32000-1 §12.7).

All four canonical field types per §12.7.4 land:

- **Text** (`/FT /Tx`) — `FormFieldText` with optional default value,
  `/MaxLen`, `/Q` justification (left/centre/right per Table 222),
  and `/Ff` bit 12 (multi-line) per Table 228.
- **Checkbox** (`/FT /Btn`) — `FormFieldCheckbox` keyed by `/Yes` and
  `/Off` appearance states per Table 228. `/V`, `/DV`, and `/AS` stay
  consistent.
- **Radio group** (`/FT /Btn` with Radio + NoToggleToOff flags) —
  `FormFieldRadioGroup` becomes one aggregate field with `/Kids`
  referring to one widget per option; the selected option's `/AS`
  carries its export-value Name, others carry `/Off`.
- **Choice** (`/FT /Ch`) — `FormFieldChoice` with `/Opt` array and
  optional `/V`. `/Ff` bit 18 selects combo-box vs. list-box.
- **Signature** (`/FT /Sig`) — `FormFieldSignature` wraps a
  `Box<dyn Signer>` + `SignerIdentity` and re-uses the round-30
  `/Contents` placeholder pattern. Only one signature field per call.

```rust,ignore
use oxideav_pdf::{
    write_pdf_with_form, FieldJustification, FormField, FormFieldText,
    FormFieldCheckbox,
};

let fields = vec![
    FormField::Text(FormFieldText {
        name: "FullName".into(),
        rect: [20.0, 150.0, 180.0, 170.0],
        page_index: 0,
        value: Some("Jane Doe".into()),
        max_length: Some(64),
        multi_line: false,
        justification: FieldJustification::Left,
        default_appearance: None,
    }),
    FormField::Checkbox(FormFieldCheckbox {
        name: "Accept".into(),
        rect: [20.0, 100.0, 40.0, 120.0],
        page_index: 0,
        checked: true,
        default_appearance: None,
    }),
];
let pdf = write_pdf_with_form(&scene, &fields)?;
# Ok::<(), oxideav_pdf::PdfError>(())
```

The AcroForm dict gets `/DA "(/Helv 12 Tf 0 g)"` per §12.7.3.3 (the
caller can override per field), `/NeedAppearances true` so viewers
regenerate `/AP` at open time, and `/SigFlags 3` when a signature
field is present. `qpdf --check` accepts the output; the round-26
reader round-trips `field_type` / `field_name` / `value` for every
widget.

## General annotations writer (round 32)

[`write_pdf_with_annotations`] is the symmetric writer side of the
round-26 generic annotation reader. Where round 25 emitted only
`/Subtype /Link` and round 31 emitted `/Subtype /Widget`, round 32
covers the rest of the §12.5.6 subtype taxonomy that authoring tools
produce in the wild: Text, Link, FreeText, Highlight, Underline,
Squiggly, StrikeOut, Stamp, Square, Circle, and Ink.

Five most-common interactive PDF subtypes (Text/Link/FreeText/
Highlight/Stamp) plus three markup ones (Square/Circle/Ink) are
all wired into a single `Annotation` struct + `WriterAnnotationKind`
enum, with cross-subtype Table 164 fields (`/T` author, `/M`
modified-date, `/F` flags, `/C` colour, `/Border`) hanging off the
struct itself:

```rust,ignore
use oxideav_pdf::{
    write_pdf_with_annotations, Annotation, FreeTextQuadding,
    WriterAnnotationKind,
};

let annots = vec![
    Annotation {
        source_page_index: 0,
        rect: [10.0, 10.0, 30.0, 30.0],
        author: Some("Jane Reviewer".into()),
        modified: None,
        flags: None,
        colour: Some(vec![1.0, 1.0, 0.0]),
        border: None,
        kind: WriterAnnotationKind::Text {
            contents: "Please clarify".into(),
            icon: Some("Comment".into()),
            open: true,
        },
    },
    Annotation {
        source_page_index: 0,
        rect: [40.0, 60.0, 200.0, 80.0],
        author: None,
        modified: None,
        flags: None,
        colour: None,
        border: None,
        kind: WriterAnnotationKind::Link {
            uri: "https://example.com".into(),
        },
    },
    Annotation {
        source_page_index: 0,
        rect: [40.0, 100.0, 200.0, 130.0],
        author: None,
        modified: None,
        flags: None,
        colour: None,
        border: None,
        kind: WriterAnnotationKind::FreeText {
            contents: "header".into(),
            default_appearance: None,
            quadding: FreeTextQuadding::Center,
        },
    },
];
let pdf = write_pdf_with_annotations(&scene, &annots)?;
# Ok::<(), oxideav_pdf::PdfError>(())
```

Highlight/Underline/Squiggly/StrikeOut take a
`Vec<[f32; 8]>` of quads (lowered to the spec's `8N`-real
`/QuadPoints` array); Ink takes a `Vec<Vec<f32>>` of strokes
(each `[x0, y0, x1, y1, …]`). `qpdf --check` accepts the output;
the round-26 reader round-trips every subtype.

## Embedded file attachments (round 33)

`write_pdf_with_attachments(scene, &[Attachment])` embeds arbitrary
files inside the PDF as `/Type /EmbeddedFile` streams, materialises
one `/Type /Filespec` dictionary per attachment (ISO 32000-1 §7.11.3
Table 44 + §7.11.4 Table 45 + §3.10), registers each filespec in the
catalog's `/Names → /EmbeddedFiles` name tree (§7.7.4 Table 31 +
§7.9.6 Name trees), and optionally drops a `/FileAttachment`
annotation marker (§12.5.6.15 Table 187) on a chosen page. The
embedded-file stream body is FlateDecode-compressed when that
shrinks; otherwise stored cleartext.

```rust,ignore
use oxideav_pdf::{write_pdf_with_attachments, Attachment};

let pdf = write_pdf_with_attachments(&scene, &[
    Attachment::new("notes.txt", b"Hello PDF.\n".to_vec())
        .with_mime_type("text/plain")
        .with_modified("D:20260515120000Z"),
    Attachment::new("logo.png", png_bytes)
        .with_mime_type("image/png")
        .with_annotation(0, [10.0, 10.0, 30.0, 30.0]),
])?;
# Ok::<(), oxideav_pdf::PdfError>(())
```

Each attachment's `/F` entry is the PDFDocEncoded name (literal
string for ASCII; UTF-16BE-with-BOM hex string otherwise), the `/UF`
entry is always UTF-16BE for full Unicode coverage (PDF 1.7+), and
`/EF /F` and `/EF /UF` both point at the same embedded-file stream.
Name-tree keys are emitted in byte-wise lexicographic order per
§7.9.6.2.

The reader-side counterpart [`read_pdf_attachments`] walks the same
name tree back into `Vec<PdfAttachment { name, mime_type, bytes,
modified }>`. `qpdf --check` and `qpdf --json` both accept the
output; `qpdf --json` lists each embedded file by name.

## Document time-stamp signatures (round 34)

`add_document_timestamp(pdf, tsa)` appends an RFC 3161
**Document Time-Stamp** revision (ISO 32000-1 §12.8.5) to an existing
(signed-or-unsigned) PDF. The new revision adds a `/FT /Sig` field
whose `/V` is a sig dictionary with `/Type /DocTimeStamp` +
`/SubFilter /ETSI.RFC3161`, and whose `/Contents <…hex…>` holds a
full RFC 3161 `TimeStampToken` (a CMS `SignedData` ContentInfo over
a `TSTInfo` SEQUENCE). The byte-range placeholder pattern of round
30 is reused, so a doc-timestamp can coexist with one or more
regular signatures in the same document — each is its own
incremental update per ISO 32000-1 §7.5.6.

```rust,ignore
use oxideav_pdf::{add_document_timestamp, MockTsaSigner, SignerIdentity};
let tsa = MockTsaSigner::new(rsa_priv, identity, b"20260517000000Z".to_vec())?;
let stamped = add_document_timestamp(&signed_pdf, &tsa)?;
```

The [`TsaSigner`] trait is the integration seam for production TSAs
(RFC 3161 §3 HTTP transport, RFC 5816 ESSCertIDv2 — both out of
scope for round 34). The in-tree [`MockTsaSigner`] short-circuits the
network round-trip with a self-signed RSA-2048 / SHA-256 token —
handy for tests and for self-contained roundtrips. The reader side
surfaces timestamps separately via `DocumentReader::doc_timestamps()`
(or the free fn [`read_pdf_doc_timestamps`]). `qpdf --check` accepts
the output; when `openssl ts -verify` is on PATH, it accepts the
embedded TST.

## Content-stream DeviceCMYK colour (round 115)

The content-stream parser now honours the `k` (fill) and `K` (stroke)
**DeviceCMYK** colour operators (ISO 32000-1 §8.6.4.4). Because the
vector IR carries only DeviceRGB, each CMYK colour is converted via
§10.3.5 ("Conversion from DeviceCMYK to DeviceRGB") — `red = 1 −
min(1, cyan + black)` and the magenta/yellow counterparts, no black
generation or undercolour removal. Pure cyan/magenta/yellow inks
reconstruct as `(0,255,255)` / `(255,0,255)` / `(255,255,0)` and
`0 0 0 1 k` as black, where the parser previously collapsed every
CMYK colour to opaque black. Out-of-range operands are clamped to
`0.0..=1.0` first (§10.3.4 NOTE 4).

## Content-stream colour-space selection (round 118)

The content-stream parser now honours the `cs` / `CS` colour-space
operators and interprets the following `sc` / `scn` / `SC` / `SCN`
colour values against the selected space (ISO 32000-1 §8.6.8 Table 74
+ §8.6.4). Where the round-3 parser collapsed every `sc`/`scn` to
opaque black, a document setting colour via `/DeviceRGB cs 1 0 0 sc`
(instead of the `1 0 0 rg` shorthand) now reconstructs red. The three
device families resolve by name — `/DeviceGray` (1 component),
`/DeviceRGB` (3), `/DeviceCMYK` (4, via the §10.3.5 conversion), plus
the abbreviated inline-image spellings `G` / `RGB` / `CMYK`. The
implicit-space operators (`g`/`rg`/`k`, `G`/`RG`/`K`) also record
their space so a subsequent bare `sc`/`scn` resolves correctly, and a
bare `cs`/`CS` initialises the colour to black per §8.6.4.2..4.

`/Pattern`, a trailing `/Name` pattern operand (§8.7.3.3), CIE-based /
Indexed / Separation / DeviceN spaces, and any unresolved `/Resources
/ColorSpace` key keep the conservative black fallback — resolving
non-device spaces needs the page's `/Resources` dict, which this layer
doesn't yet reach.

## Content-stream `Tj` / `TJ` text-show with `/Resources /Font` (round 128)

The content-stream parser now resolves text-show operators against the
page's `/Resources /Font` subdictionary (ISO 32000-1 §9.4 + Table 105 +
Table 108 + Table 109). A new
[`parse_content_stream_full(input, ext_gstate, fonts)`] entry point
returns a [`ParsedContent { root, text_shows }`] carrying one
[`ContentTextShow`] per `Tj` / `TJ` / `'` / `"` show, each with the
resolved font dictionary, the `Tf`-recorded font name + size, the
decoded operand bytes (literal-string escapes + hex-pair decoding both
handled per §7.3.4), the text-matrix origin at the moment of the show,
and a [`TextShowOp`] discriminator naming the originating operator.

Text-state operators (`BT` / `ET` / `Tf` / `Tm` / `Td` / `TD` / `T*` /
`TL`) are honoured per §9.4.2 Table 108 — the text matrix resets to
identity on every `BT`, advances by the explicit displacement on
`Td`/`TD`/`Tm`, and steps down by the current leading on `T*` /
implicit-`T*` from `'` and `"`. `TJ`'s per-element numeric kerning
displacements are dropped because they affect only glyph positioning,
not the decoded text payload — the strings are concatenated in array
order.

The page walker plumbs the page's `/Resources /Font` through a new
single-hop indirect-dereference helper (`resolve_font_resources`)
mirroring the round-125 `resolve_ext_gstate` shape. A `Tf` against a
font name that isn't present in the resources dict still emits the
show — the consumer learns the font wasn't resolved via
`font_dict = None` rather than the show silently disappearing. The
round-22 [`DocumentReader::text_extraction`] walker still owns the
byte→Unicode mapping (encoding / `/ToUnicode` CMap resolution); this
round-128 surface is the narrower path a consumer that already has
the page resources resolved can use.

The legacy [`parse_content_stream`] and
[`parse_content_stream_with_resources`] entry points keep their
round-3 / round-125 no-op behaviour — text-show operands are dropped
silently so existing callers don't see new events appear.

## Content-stream `gs` ExtGState resolution (round 125)

The content-stream parser now honours the `gs` graphics-state operator
(ISO 32000-1 §8.4.5 + Table 57). Each page's `/Resources /ExtGState`
subdictionary is plumbed through to the parser; a `/GSx gs` looks
`/GSx` up there and applies the Table-58 entries that map onto the
round-3 vector IR:

- **`LW`** — line width (overrides the `w` operator).
- **`LC`** — line cap (`Butt` / `Round` / `Square`).
- **`LJ`** — line join (`Miter` / `Round` / `Bevel`).
- **`ML`** — miter limit.
- **`D`** — `[dashArray dashPhase]` pair (the same shape `d` takes).
- **`CA`** — stroking alpha constant (§11.6.4.4); multiplies into the
  current stroke paint's alpha channel.
- **`ca`** — nonstroking alpha constant; multiplies into the current
  fill paint's alpha.

Multiple `gs` invocations cumulate — an earlier `/GW gs` carrying only
`LW` survives a later `/GA gs` carrying only `CA`, matching the
§8.4.5 "results of gs shall be cumulative" rule. Other Table-58 keys
(`BM`, `OP` / `op` / `OPM`, `SMask`, `Font`, `BG` / `UCR` / `TR` / `HT`,
`RI`, `SA`, `AIS`, `TK`, `FL`, `SM`) are tolerated as silent no-ops —
they need IR plumbing the vector model doesn't yet carry, so honouring
them now would be misleading rather than additive.

## Fuzz harness (round 145)

The crate ships a cargo-fuzz harness under `fuzz/` with three
panic-free decode-side targets. PDF has no external library worth
pulling in as a cross-decode oracle (and the clean-room wall bars
qpdf / pdfium / poppler / mupdf source anyway), so this is a
decode-only contract: feed arbitrary bytes to the public reader
entry points and assert they always return a `Result` rather than
panicking, aborting, or OOMing.

- **`parse`** — drives `read_pdf_to_scene` end-to-end (§7.5 file
  structure + §7.8 page tree + §8/§9 content streams + §7.4 stream
  filters) plus the three standalone reader entry points
  `parse_linearization_dict` (§7.5.2), `extract_inline_images_from_stream`
  (§8.9.7), and `parse_content_stream` (§8/§9).
- **`xref`** — drives the §7.5.4 classic xref-table parser, the
  §7.5.8 cross-reference-stream parser, and the §7.5.8.4
  hybrid-reference merge directly: both the one-shot `parse_xref`
  entry point and the two-step `find_startxref_offset` +
  `parse_xref_at` split, the latter with a fuzz-derived
  out-of-range offset pulled from the input.
- **`decrypt`** — drives `read_pdf_to_scene_with_password` with an
  arbitrary password split out of the fuzzer input. Exercises §7.6
  standard-handler dispatch (R=2 RC4-40, R=3 RC4-128, R=4 AES-128 /
  RC4-128 with crypt filters, R=5 / R=6 AES-256 with SHA-256/384/512
  key derivation per ISO 32000-2:2020 §7.6.4.4.3 Algorithm 2.B).

The corpus is seeded with the existing in-tree fixtures
(`tests/fixtures/{font_resources,gs_ext_gstate,hybrid_xrefstm}.pdf`)
plus minimal scaffolds. Round 1 of the harness ran ~5 M execs per
target locally and surfaced two reader-side panics (a §7.7.3.2
/Pages-tree cycle that recursed forever, and a §7.3.4.2 literal
string with a trailing `\` that overran the slice index), both
fixed in this round with regression coverage under
`tests/fuzz_regressions.rs`. CI runs the suite daily under
`.github/workflows/fuzz.yml` with a 30-minute total budget split
across the three targets.

## Deferred

- **Text emission** — writer-side `BT … Tj … ET` for `Node::Text`
  using Type 0 fonts with a CIDFont built via
  `oxideav-ttf`/`oxideav-otf`. The reader-side extraction surface
  landed in round 22 (see above).
- **Writer-side JPEG passthrough on `ImageRef` (DCTDecode XObject)** —
  needs core IR support for "raw codec bytes" alongside the decoded
  VideoFrame so the writer can emit `/Filter /DCTDecode` instead of
  re-encoding every JPEG to FlateDecoded raw RGBA. The *reader-side*
  surface landed in round 23 (see above).
- Extended generic hint tables (F.4.5) and embedded-file-stream
  hint tables (F.4.6) for linearized output — we generate no
  interactive forms / structure trees / embedded files, so the
  per-table content would be empty anyway.
- Ed25519 / Ed448 signature dispatch in `pubsec::verify` — round 20
  covers RSA-PKCS#1 v1.5 / RSA-PSS / ECDSA on P-256 / P-384 / P-521;
  EdDSA needs an `ed25519-dalek` (or `ed448-goldilocks`) dep.
- Transparency groups beyond a per-`Group` `/ca`+`/CA` opacity.

## Usage

```toml
[dependencies]
oxideav-core = "0.1"
oxideav-pdf  = "0.0"
```

```rust
use oxideav_core::{
    FillRule, Group, Node, Paint, Path, PathNode, Point, Rgba, VectorFrame,
};
use oxideav_core::TimeBase;

let mut p = Path::new();
p.move_to(Point::new(10.0, 10.0))
    .line_to(Point::new(110.0, 10.0))
    .line_to(Point::new(110.0, 60.0))
    .line_to(Point::new(10.0, 60.0))
    .close();

let frame = VectorFrame {
    width: 200.0,
    height: 100.0,
    view_box: None,
    root: Group {
        children: vec![Node::Path(PathNode {
            path: p,
            fill: Some(Paint::Solid(Rgba::opaque(0xFF, 0x80, 0x00))),
            stroke: None,
            fill_rule: FillRule::NonZero,
        })],
        ..Group::default()
    },
    pts: None,
    time_base: TimeBase::new(1, 1),
};

let pdf = oxideav_pdf::write_pdf(&frame).expect("vector → PDF");
std::fs::write("out.pdf", pdf).unwrap();
# Ok::<(), Box<dyn std::error::Error>>(())
```

## License

MIT — see [LICENSE](LICENSE).
