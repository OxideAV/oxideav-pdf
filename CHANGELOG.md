# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Round-12: **per-crypt-filter recipient lists** — multiple named
  crypt filters under `/CF`, each with its own permission mask, all
  sharing one `/Recipients` array of multi-envelope PKCS#7 blobs (one
  envelope per permission set). New
  `write_pdf_from_scene_pubsec_multi_cf(scene, PubSecMultiCfConfig)`
  + `PubSecCfGroup` (group = one permission set: full-access /
  read-only constructors provided). The reader gains
  `open_with_certificate_with_permissions` returning a `PubSecMatch
  { handler, permissions, crypt_filter_name }`, so a caller can
  surface "you have read-only access" alongside the decrypted scene.
  Per ISO 32000-1 §7.6.4.2 + §7.6.5.4, every recipient walks every
  envelope; the first match wins. Provenance: ISO 32000-1 §7.6.4.2 +
  §7.6.5.4 only.
- Round-12: **CMS KARI decoder** (RFC 5652 §6.2.2) — KeyAgreeRecipientInfo
  parsing. Surfaces originator (IAS / SKI / OriginatorPublicKey) +
  ukm + keyEncryptionAlgorithm OID + recipientEncryptedKeys via the
  new `cms::RecipientInfoVariant::KeyAgree` arm + `KeyAgreeRecipientInfo`
  / `OriginatorId` / `KeyAgreeRecipientId` types. KARI envelopes
  (alone or mixed with KTRI) parse cleanly through `parse_envelope`;
  the KTRI side still drives the actual unwrap (DH/ECDH key
  agreement + RFC 5753 KDFs are out of scope). Encoder-side helper
  `cms_build::build_envelope_kari_aes256` builds fixture envelopes.
  Provenance: RFC 5652 §6.2.2 only.
- Round-12 tests: 9 new tests — 7 round-12 integration tests in
  `tests/pubsec_round12.rs` (multi-CF round-trip + permissions
  surfacing + neither-group-matches + non-s5-rejection +
  empty-groups-rejection + KARI structural parse + mixed-KARI/KTRI),
  2 unit tests in `cms_build` (KARI round-trip + alternate-CHOICE
  KARI variant).

- Round-11 writer: **public-key encryption encode** — the symmetric
  encoder side of round 10. New top-level
  `write_pdf_from_scene_pubsec_encrypted(scene, &PubSecEncoderConfig)`
  emits PDFs whose `/Encrypt /Filter` is `/Adobe.PPKLite` and whose
  `/Recipients` array carries one CMS `EnvelopedData` (RFC 5652 §6.1)
  per access-permission set. `PubSecEncoderConfig` constructors:
  `pkcs7_s4` (RC4-128 / SHA-1), `pkcs7_s5_v4_aes128` (AES-128 CBC /
  SHA-1), `pkcs7_s5_v5_aes256` (AES-256 CBC / SHA-256). Each
  recipient's content-encryption key is RSA-PKCS1-v1.5 wrapped to its
  public key; the file encryption key is `SHA-1/SHA-256(seed ‖
  envelope_blob [‖ 0xFFFFFFFF])` per ISO 32000-1 §7.6.4.3 / ISO
  32000-2 §7.6.5.3. The `cms_build` module is promoted from `pub(crate)
  test-only` to `pub` and gains a `build_envelope_rc4` helper +
  `RecipientPlain::ias` / `::ski` constructors. `PubSecEncryptionState`
  produces a `EncryptionState` shape so the writer reuses the
  password-handler's per-object encryption walker without duplication.
- Round-11: **`SubjectKeyIdentifier` recipient matching** (CMS v2 per
  RFC 5652 §6.2.1). Previously the parser errored on the v=2 KTRI
  variant; round 11 wires it through. `cms::RecipientId` becomes a
  CHOICE-shaped enum with `IssuerAndSerial` and
  `SubjectKeyIdentifier(Vec<u8>)` arms; `pubsec::open_with_certificate`
  accepts either form, computing the cert's SKI as
  `SHA-1(SubjectPublicKeyInfo BIT STRING contents)` (RFC 5280
  §4.2.1.2 method 1). `x509::Certificate` extends with
  `spki_pubkey_bits` + `subject_key_identifier()` accessor; the
  X.509 parser now walks past `issuer` to `subjectPublicKeyInfo`
  (best-effort — synthetic test certs that truncate after `issuer`
  silently leave `spki_pubkey_bits = None`).
- Round-11 writer: **linearization F.4.2 / F.4.3 / F.4.4 hint
  tables** — shared-object (24-byte zero header), thumbnail (28-byte
  zero header), outline (14-byte zero header). The hint stream's
  dict gains `/S` (shared-object table offset), `/T` (thumbnail
  table offset), `/O` (outline table offset). Entry sections stay
  empty (we generate no shared objects / thumbnails / outlines), so
  readers parsing these tables conclude there's nothing to consume —
  but the structural completeness lets `qpdf --linearize-check` and
  similar tools see a fully-formed hint stream.
- Round-11 tests: 11 new tests — 4 lib unit tests for the
  shared/thumbnail/outline hint table builders + the hint-stream
  dict /S/T/O presence; 4 lib unit tests for the writer-side
  encoder (s4 / s5-V4-AES128 / s5-V5-AES256 round-trip via
  `open_with_certificate` + a SKI-form variant + an empty-recipients
  rejection); 5 integration tests in `tests/pubsec.rs` exercising
  the full writer→reader pipeline including a two-recipients-either
  -opens scenario and an SKI-form round trip; 1 X.509 unit test for
  the SPKI extractor / SHA-1 SKI computation.

- Round-10 reader: **public-key encryption decode** for the
  `adbe.pkcs7.s3` / `s4` / `s5` SubFilters of the public-key
  security handler (ISO 32000-1 §7.6.4 + ISO 32000-2 §7.6.5).
  New `pubsec` module + top-level `PubSecCredential` (X.509 cert
  + RSA private key) + `read_pdf_to_scene_with_certificate`. The
  reader parses each `/Recipients` CMS `EnvelopedData` (RFC 5652
  §6.1) — minimal in-tree DER + CMS parsers, no external library
  code consulted — matches a recipient slot by
  `IssuerAndSerialNumber`, RSA-PKCS1-v1.5 unwraps the
  content-encryption key, then decrypts the envelope contents
  (RC4 / AES-128 CBC / AES-256 CBC). The file encryption key is
  the first n/8 bytes of `SHA-1(seed || all_recipient_blobs)`
  for the V≤4 paths and `SHA-256(...)` for the AES-256 path,
  per §7.6.4.3 / §7.6.5.3. Reader hands the resulting key off
  to the existing `decrypt::StandardHandler` so per-object
  string + stream decryption uses the same Algorithm 1 path the
  password-based reader already exercises. Encoder side is round 11+.
- Round-10 deps: pure-Rust `rsa` (RustCrypto, RSAES-PKCS1-v1_5)
  and `sha1` (RustCrypto). No `*-sys` wrappers; both crates are
  used purely on the decoder path. The CMS / X.509 / DER parsers
  are hand-rolled from RFC 5652 / RFC 5280 / X.690 — no
  pkcs / cms / x509-cert crate dependency.
- Round-10 tests: 17 new tests — 12 unit tests covering the DER
  TLV parser/writer round-trip, OID encoding, an AES-256 CMS
  envelope round-trip, X.509 issuer/serial extraction from a
  synthetic certificate, and `open_with_certificate` against
  s4 / s5-V4 / s5-V5 envelopes; 5 integration tests in
  `tests/pubsec.rs` building a complete public-key-encrypted PDF
  + verifying `read_pdf_to_scene_with_certificate` recovers
  the encrypted `/Title` + content stream end-to-end across
  RC4-128, AES-128 CBC, and AES-256 CBC profiles, plus a wrong-
  certificate negative test and an unencrypted-PDF passthrough.

- Round-9 writer: **Linearization (Fast Web View)**, ISO 32000-1
  §7.5.6 + Annex F. New `write_pdf_from_scene_linearized(scene)`
  emits a PDF whose first 1024 bytes carry a complete linearization
  parameter dictionary (`/Linearized 1` + `/L` + `/H` + `/O` +
  `/E` + `/N` + `/T`); the layout follows Annex F.3.1 (header,
  lin-dict, first-page xref, catalog, hint stream, first-page
  section, remaining pages, main xref). `startxref` at EOF points
  at the first-page xref (per F.3.11); the first-page trailer's
  `/Prev` points at the main xref (per F.3.4). The output remains
  a valid plain PDF — readers ignoring `/Linearized` still see
  the same Catalog + Pages tree + page content. Hint stream emits
  the mandatory page offset hint table only (Tables F.3 + F.4);
  shared-object / thumbnail / generic hints (F.4.2 / F.4.3 /
  F.4.4 / F.4.5 / F.4.6) are deferred. Two-pass emission:
  placeholder values are written 10-digit zero-padded so the
  patch step preserves byte alignment.
- Round-9 writer: **ObjStm + encryption combined path**
  (`write_pdf_from_scene_object_stream_encrypted`). Lifts the
  round-8 "ObjStm OR encryption, not both" guard per the §7.5.7
  carve-out: "In an encrypted file (i.e., entire object stream
  is encrypted), strings occurring anywhere in an object stream
  shall not be separately encrypted." The ObjStm container body
  is encrypted as a unit using the container's own object id as
  the per-object key seed; compressed bodies inside it are NOT
  separately encrypted. Round-trips through the round-7 reader
  with `read_pdf_to_scene_with_password`.
- Round-9 tests: 23 new tests — 13 in `tests/linearization.rs`
  covering the lin-dict-in-first-1024-bytes invariant, /L/N/O/E
  consistency with actual file shape, startxref → first-page xref,
  first-page trailer /Prev → main xref, single + multi-page
  round-trips through the reader; 10 unit tests in `src/linearize.rs`
  for the same; one new test in `tests/object_stream_encode.rs`
  for the ObjStm + encryption combo round-trip.

- Round-8 writer: **object-stream encoder** (`/Type /ObjStm`,
  ISO 32000-1 §7.5.7). New `Document::object_stream` flag
  (requires `xref_stream = true`) packs every compressible
  indirect object — every dict that isn't a stream, the Catalog,
  or the Encrypt object — into one ObjStm container per
  revision. The xref stream's type-2 entries point at the
  container; pairs with the round-7 reader-side resolver. New
  one-shot entry point `write_pdf_from_scene_object_stream`.
  Stream objects remain at byte offsets (§7.5.7 forbids
  embedding them).
- Round-8 writer: **incremental updates** (`/Prev`,
  ISO 32000-1 §7.5.6). New `write_pdf_incremental_update(prev_pdf,
  &new_pages)` appends a new revision to a previously-written
  PDF: re-renders the new pages with fresh ids past the prior
  maximum, rewrites the `/Pages` tree at its existing id
  (so the new kids list overrides), emits a new xref subsection
  listing only the changed slots, and writes a trailer with
  `/Prev` pointing at the previous xref offset. Original bytes
  are preserved verbatim — partial readers that ignore `/Prev`
  see the original revision unchanged.
- Round-8 reader: `parse_xref` now follows the trailer's `/Prev`
  chain (up to 32 hops, cycle-detected) and merges older xref
  sections beneath the newest. Newer revisions win on overlap.
- Round-8 tests: 17 new integration tests across
  `tests/object_stream_encode.rs` (6), `tests/incremental_update.rs`
  (5), and `tests/encrypt_metadata_false.rs` (6) covering
  encoder→reader round-trips, multi-page packing, two-level
  `/Prev` chaining, original-bytes preservation, and the
  `/EncryptMetadata false` end-to-end matrix (R=3 / R=4 / R=6).
- `Document::set_next_id` + `Document::next_id` accessors so
  the incremental-update writer can resume id allocation past
  a previously-written revision's maximum.

- Round-7 writer: cross-reference *stream* (`/Type /XRef`,
  ISO 32000-1 §7.5.8) emission. Mirror of the round-6 reader —
  `/W [1 4 2]` field widths, FlateDecode + PNG-Up `/Predictor 12`
  body, trailer dict folded into the stream's own dictionary. New
  `Document::xref_stream` flag + `write_pdf_from_scene_xref_stream`
  one-shot entry point. Header bumped to PDF 1.5 when active.
- Round-7 reader: PDF 1.5+ **object-stream resolver**
  (`/Type /ObjStm`, ISO 32000-1 §7.5.7). `DocumentReader::resolve`
  now walks `XrefEntry::Compressed` slots — fetches the containing
  ObjStm, parses its `(obj_num offset)` header, and slices out the
  matching body. Header object-number mismatches surface as parse
  errors. Pairs naturally with the round-7 xref-stream encoder.
- Round-7 reader+writer: per-stream `/Filter /Crypt` `/Identity`
  opt-out (ISO 32000-1 §7.6.5 + §7.4.10). Streams whose first filter
  is `/Crypt` and whose `/DecodeParms /Name` is `/Identity` (or
  absent — Table 24 default) bypass per-object encryption on both
  encode and decode paths. The classic consumer is XMP metadata
  that needs to remain searchable in encrypted PDFs.

- Round-6 writer: standard-security-handler **encryption** for the
  full revision range — R=2 / R=3 / R=4 (RC4 + AES-128) / R=5 / R=6
  (AES-256). New `encrypt::EncryptionConfig` builder + `encrypt::EncryptionState`
  installed on `Document::encryption`; `write_pdf_from_scene_encrypted`
  one-shot entry point. Implements Algorithms 3, 4, 5 (V≤4) plus
  reuses 8, 9, 10 from `decrypt::r5_r6` (V=5). Round-trip tested across
  all five revisions including full encode → decrypt → re-encode →
  decrypt bounce, owner-password authentication, wrong-password
  rejection, and content-stream encryption verification.
- Round-6 reader: PDF 1.5+ cross-reference *streams* (`/Type /XRef`,
  ISO 32000-1 §7.5.8). Binary `/W [w1 w2 w3]` field decoding, optional
  `/Index` subsections, optional `/Filter /FlateDecode` body, full
  PNG-Up `/Predictor 12` (and 10..15 fallback handling) reversal.
  `XrefEntry::Compressed` variant added for type-2 entries (the
  object-stream resolver itself is the next round).
- Bug fix: `tests/external_validation.rs` `qpdf --check` test was
  piping bytes through stdin, which qpdf ≥ 11 rejects (`-` is not
  treated as stdin). Switched to a temp-file path so qpdf opens it
  by name.
- Round-4 reader: standard-security-handler decryption (ISO 32000-1
  §7.6) for revisions R=2 (RC4-40), R=3 (RC4-128), and R=4 (AES-128
  CBC or RC4-128 via `CFM`).
- Round-5 reader: AES-256 standard-handler decryption for **R=5**
  (PDF 1.7 Adobe extension level 3) and **R=6** (ISO 32000-2:2020
  PDF 2.0). Implements Algorithms 2.A, 2.B, 8, 9, 10, 11, 12 and 13
  from ISO 32000-2 §7.6.4.4 — full coverage of the AESV3 era.
- `decrypt::r5_r6` module exposing `algorithm_8` / `algorithm_9` /
  `algorithm_10` for fixture builders, plus the SHA-256/384/512
  iterated hash chain of Algorithm 2.B.
- `CryptMethod::Aes256` variant (V=5 file-key direct AES-256 CBC,
  no per-object Algorithm 1 derivation).
- `EncryptParams` is extended with `oe`, `ue`, `perms` slots that
  the reader populates for V=5 PDFs (32 / 32 / 16 bytes).
- `read_pdf_to_scene_with_password()` and
  `DocumentReader::open_with_password()` public APIs.
- `decrypt` module exposing `StandardHandler`, `CryptMethod`, plus
  hand-rolled `rc4()` / `md5()` (RFC 1321) and AES-128 CBC via the
  `aes` + `cbc` RustCrypto crates.
- New `sha2` (RustCrypto) dep for SHA-256/384/512 — pure-Rust, no
  `*-sys`. Used only by the V=5 password derivation path.
- ~32 new tests: SHA-256/384/512 FIPS 180-4 known-answers,
  Algorithm 9 → 11 user-auth round-trip (R=5 + R=6), Algorithm 10
  → 13 Perms round-trip, Algorithm 2.B determinism, file-key
  wrap/unwrap, and end-to-end fixture decode for R=5 + R=6 covering
  user / owner / wrong / empty / Unicode / >127-byte passwords.

## [0.1.0](https://github.com/OxideAV/oxideav-pdf/compare/v0.0.2...v0.1.0) - 2026-05-04

### Other

- promote to 0.1
- clippy 1.95: drop useless .into_iter() in zip; switch test literal off PI
- round 3: top-level walker — bytes → Scene roundtrip
- round 3: content-stream operator parser (inverse of operators.rs)
- round 3: cross-reference table + trailer parser
- round 3: PDF object parser (tokens → Object tree)
- round 3: PDF reader scaffold + tokenizer (ISO 32000-1 §7.2)
- round 2: scene Metadata::custom map → /Info custom keys
- round 2: scene Metadata standard fields → PDF /Info dict
- round 2: multi-page output via write_pdf_from_scene

## [0.0.2](https://github.com/OxideAV/oxideav-pdf/compare/v0.0.1...v0.0.2) - 2026-05-03

### Other

- use from_utf8_lossy for output containing the binary marker
- silence remaining lints from `-D warnings`

## [0.0.1] - 2026-05-04

### Added

- Round 1 PDF writer that emits a single-page PDF 1.4 document from an
  `oxideav_core::VectorFrame`.
- PDF imaging-model mapping for paths (move/line/cubic/quadratic-as-cubic
  /arc-as-cubic/close), solid + linear/radial gradient fills, strokes
  (width/cap/join/miter/dash), `Transform2D` (`cm`), `Group` (`q`/`Q`),
  group opacity (ExtGState `/ca` + `/CA`), clip paths (`W n`), and
  fill rules (`f` / `f*` / `B` / `B*`).
- FlateDecode `Image` XObjects for embedded uncompressed RGBA frames.
- `register()` adding a PDF encoder to `oxideav_core::CodecRegistry`
  and a write-only `pdf` muxer to `oxideav_core::ContainerRegistry`.
