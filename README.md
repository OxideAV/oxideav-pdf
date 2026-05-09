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
raw-DER values, raw `signature` octets). Signature **verification**
(hash-then-verify dispatch) is a round-20 deferral; today's surface
covers every byte the verifier will need.

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

## Deferred

- Text (waiting on `Node::Text`; will use Type 0 fonts with a
  CIDFont built via `oxideav-ttf`/`oxideav-otf`).
- JPEG passthrough on `ImageRef` (DCTDecode XObject) — needs core
  IR support for "raw codec bytes" alongside the decoded VideoFrame.
- Extended generic hint tables (F.4.5) and embedded-file-stream
  hint tables (F.4.6) for linearized output — we generate no
  interactive forms / structure trees / embedded files, so the
  per-table content would be empty anyway.
- CMS KARI for P-521 (`dhSinglePass-stdDH-sha512kdf-scheme`) — round
  14 covers P-256, round 15 extends to P-384 + X25519; P-521 is
  unblocked by the same mechanism (add `sha2::Sha512` to the
  `KariCurve` enum + a `p521` dep).
- CMS KARI HKDF binding (RFC 8418 §2.2 — `smime-alg 19/20/21` OIDs
  for X25519/X448 with HKDF) — round 15 ships the X9.63 binding only.
- CMS KARI X448 (RFC 8418 §2 — needs an X448 ECDH crate; the dalek
  ecosystem doesn't ship one, so this likely waits on a third-party
  crate or hand-rolled curve arithmetic).
- CMS KARI long-term originator certificates — `OriginatorId::IssuerAndSerial`
  / `SubjectKeyIdentifier` resolution against a recipient-supplied
  trust store; current code requires the originator's public key
  in-band (the only form Adobe ever emits).
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
