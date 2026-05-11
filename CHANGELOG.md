# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Round 29: **Reading-order layout pass over Tagged PDF
  StructTreeRoot** (ISO 32000-1 §14.6 + §14.7 + §14.8). New
  `oxideav_pdf::reader::layout::read_in_logical_order(reader)` — and
  the convenience `DocumentReader::read_in_logical_order()` — walks
  the catalog's `/StructTreeRoot /K` tree and emits text runs in
  *author-intended* reading order rather than the painter's raster
  order. For a 2-column document, raster extraction interleaves
  column 1's first row, column 2's first row, column 1's second row,
  …; the round-29 pass walks `[Sect_col1, Sect_col2]` and emits all
  of column 1 before any of column 2. The walker handles every leaf
  shape ISO 32000-1 §14.7.4.4 defines:
  * Bare-integer MCID kids resolve against the inheritable `/Pg`
    field on the nearest ancestor.
  * `<</Type /MCR /Pg p /MCID m>>` marked-content references override
    the inherited `/Pg`, supporting Tagged tables whose rows draw
    from multiple pages.
  * `<</Type /OBJR …>>` object references (annotations, not content)
    are skipped — they carry no text.
  * Nested `/StructElem` kids (Sect inside Div inside …) recurse;
    indirect refs are followed with a 64-deep cycle guard.
  Documents *without* a `/StructTreeRoot` (or a malformed / empty
  tree) fall back to the existing raster-order extraction with
  `LayoutMode::Raster` set on the return so callers can branch.

  The pass piggybacks on a round-29 addition to the round-22 text
  walker: the new `extract_text_marked(reader)` (and matching
  `DocumentReader::marked_text_extraction()`) emits every text run
  alongside the marked-content `/MCID` it was painted under (ISO
  32000-1 §14.6 — `BDC` / `BMC` / `EMC` operators). The walker
  recognises `BDC` / `BMC` / `EMC` / `MP` / `DP` keywords and parses
  the `/MCID` slot out of inline `<</MCID n>>` property dicts at the
  top level. New public surfaces under `oxideav_pdf::reader`:
  * `MarkedTextRun { run, mcid, page_obj_num, page_index }`
  * `PdfMarkedTextExtraction { runs }`
  * `LayoutMode { Tagged, Raster }`
  * `ReadingOrderText { mode, runs }` (with `flat_text()`)

  Seven fixtures under `tests/reading_order_round29.rs` cover:
  two-column tagged-PDF logical reordering vs. raster baseline,
  non-tagged fallback, cross-page MCRs (`/MCR /Pg ... /MCID ...`),
  marked-text MCID accounting, and nested `/Sect > /P > MCID`
  recursion. No external library was consulted.

- Round 28: **Simple-font `/Encoding /Differences` resolver wired into
  text extraction** (ISO 32000-1 §9.6.6.1 + §D.2 + Adobe Glyph List v2.0
  public document). When a simple Type1 / TrueType / Type3 font carries
  an encoding *dictionary* (not just a name) the reader now overlays the
  `/Differences` array onto the `/BaseEncoding` map before mapping bytes
  back to Unicode. Three new public surfaces under
  `oxideav_pdf::reader::encoding`:
  * `parse_encoding_differences(arr) -> EncodingDifferences` walks the
    flat `[N name1 name2 … M nameK …]` form per §9.6.6.1 — numeric
    tokens reset the running code, names land at consecutive slots,
    unknown tokens are tolerated. Honours `Object::Integer` AND
    `Object::Real` numeric forms.
  * `apply_encoding_differences(&base, &diffs) -> EncodingMap` overlays
    one parsed array on top of any of the six named `BaseEncoding`
    variants (`WinAnsi` / `MacRoman` / `MacExpert` / `Standard` /
    `Symbol` / `ZapfDingbats`). Unknown glyph names leave the slot
    empty so the decoder emits U+FFFD as a marker (matching what
    `pdftotext --raw` does for un-resolvable glyphs).
  * `EncodingMap::from_base(BaseEncoding)` ships a 256-entry table per
    Annex D.2 / D.4 / D.5 / D.6 plus the Adobe Type 1 Standard
    encoding. Multi-character glyph expansions (`/fi` → "fi", `/fl` →
    "fl") are accommodated; the table slot is a short `String` rather
    than a single `char`.

  The Adobe Glyph List subset shipped with the resolver covers the
  PostScript Latin character set, common Greek letters, smart-quote /
  dash / fraction set, math operators, arrows, and the `/fi` and `/fl`
  ligatures — about 320 glyph names. Extension to the full ~4280-line
  AGL is round-29+. Glyph list staged under
  `docs/document/pdf/agl/subset.txt` and the README there cites the AGL
  v2.0 public-document source. Seven new fixtures under
  `tests/encoding_differences_round28.rs` cover smart-quote overrides,
  Greek glyph remap, `/fi` / `/fl` ligature expansion, multi-segment
  arrays with running-code resets, unknown-glyph replacement-char
  fallback, empty `/Differences`, and `/MacRomanEncoding` base
  encoding. Three of them feed the fixture PDF to a system `pdftotext`
  binary when available and assert the extracted text contains the
  expected substring.

- Round 27: **Linearization Parameter Dictionary reader + Object
  Hierarchy validator + PDF/A conformance detection beyond XMP**
  (ISO 32000-1 §F.2 + §7.7.2 + §7.7.3 / ISO 19005-1..4 §6.x).
  Three new reader-side surfaces:
  * `parse_linearization_dict(bytes) -> Result<Option<LinearizationParams>>`
    and `DocumentReader::linearization()` parse the `/Linearized 1 /L /H
    [off len] /O /E /N /T` first-object dictionary every Fast-Web-View
    PDF emits in its head (§F.3.3 — entirely within first 1024 bytes).
    Round 9's writer-side emission now has its reader-side complement.
    `LinearizationParams::verify(&bytes)` cross-checks `/L` against the
    actual file length and bounds-checks `/T`, `/E`, `/H`. The parser
    returns `Ok(None)` for plain (non-linearized) files so callers can
    branch on the Option. Hint-table decoding (Annex F.4) is round 28+.
  * `verify_pdf_hierarchy(reader) -> Result<HierarchyReport>` (and
    `DocumentReader::verify_hierarchy()`) walks Catalog → Pages → Page
    and collects every spec divergence as a `HierarchyIssue` with
    `IssueSeverity::Error` or `Warning`: Catalog `/Type` + `/Pages`
    presence (§7.7.2 Table 28), `/Pages` node `/Type` / `/Kids` /
    `/Count` (§7.7.3.2 Table 29), `/Page` leaf `/Parent` back-reference
    + `/MediaBox` presence (§7.7.3.3 Table 30), cycle detection with
    a 32-hop depth guard. Never aborts the walk — surfaces every issue
    at once so a downstream tool can `report.is_valid()` or filter by
    severity.
  * `read_pdf_pdfa_signals(reader) -> Result<PdfACatalogSignals>` (and
    `DocumentReader::pdfa_signals()` + `::pdfa_conformance()`) surface
    the structural PDF/A signals from the catalog independently of the
    XMP `pdfaid:part` claim: `/MarkInfo /Marked|UserProperties|Suspects`,
    `/StructTreeRoot` presence, `/Lang`, `/OutputIntents` count, and
    `/Metadata` presence. `PdfAConformance::from_signals_and_xmp` cross-
    verifies the XMP-declared part + conformance against the structural
    prerequisites ISO 19005-1 §6.2.2 / §6.7 / §6.8 require — an `A`-level
    claim missing `/MarkInfo /Marked true` or `/StructTreeRoot` flags
    `claim_inconsistent = true` with a free-form diagnostic.
  Tested end-to-end with +33 tests (15 integration in `tests/round27.rs`
  + 10 unit in `src/reader/linearize.rs` + 4 unit in
  `src/reader/hierarchy.rs` + 7 unit in `src/reader/pdfa.rs`).

- Round 26: **Annotations beyond Link + XMP packet field extraction**
  (ISO 32000-1 §12.5.6 Tables 169..209 + §14.3.2 / Adobe XMP Spec
  2012 / ISO 16684-1 / ISO 19005-1..3 §6.x). New reader entry
  `DocumentReader::annotations()` (free function: `read_pdf_annotations`)
  walks every page's `/Annots` array and surfaces every entry as a
  `PdfAnnotation`. Per-subtype payload covers `/Text` (§12.5.6.4 Table
  172 — `/Open`, `/Name` icon, `/State`, `/StateModel`), `/FreeText`
  (§12.5.6.6 Table 174 — `/DA`, `/Q` quadding, `/RC`, `/IT` intent),
  `/Stamp` (§12.5.6.13 Table 184 — icon name), the four text-markup
  variants `/Highlight` / `/Underline` / `/Squiggly` / `/StrikeOut`
  (§12.5.6.10 Table 179 — `/QuadPoints`), `/Square` + `/Circle`
  (§12.5.6.8 Table 177 — `/IC`, `/RD`), `/Link` (re-uses round-25's
  go-to / URI dispatch), and `/Widget` (§12.5.6.19 Table 188 + §12.7.4
  Table 220 — `/FT`, `/T`, `/V`). Unknown subtypes surface as
  `AnnotationKind::Other { subtype }`. Common Table 164 fields
  (`/Rect`, `/Contents`, `/NM`, `/M`, `/F`, `/C`, `/Border`) are
  decoded for every subtype.
  New `DocumentReader::xmp_packet()` (and `XmpPacket::parse(bytes)` for
  callers with the raw bytes already in hand) parses the document-level
  XMP packet round-19 surfaces into a structured view of the most-used
  Dublin Core (`dc:title` through `rdf:Alt` / `dc:creator` through
  `rdf:Seq` / `dc:subject` `rdf:Bag` / `dc:rights` / `dc:format`),
  XMP Basic (`xmp:CreateDate` / `xmp:ModifyDate` / `xmp:MetadataDate`
  / `xmp:CreatorTool`), PDF schema (`pdf:Producer` / `pdf:Keywords` /
  `pdf:PDFVersion` / `pdf:Trapped`), and PDF/A identification schema
  (`pdfaid:part` / `pdfaid:conformance`) fields. Element-body and
  attribute forms both recognised; the standard five XML entities
  (`&amp;` / `&lt;` / `&gt;` / `&quot;` / `&apos;`) plus numeric
  character references decode. `XmpPacket::is_pdf_a()` and
  `pdf_a_conformance()` collapse the pair into a `1B`-style designator
  for PDF/A conformance detection. Tested end-to-end with +36 tests
  (19 integration in `tests/annotations_round26.rs` covering every
  subtype dispatch, common-field decode, page-without-annots baseline,
  unified-reader round-trip of the writer's Link annotations, XMP
  Dublin Core / XMP Basic / PDF / PDF/A identification, attribute-form
  XMP, XML-entity decode, and absent-XMP `None`; +6 unit tests in
  `src/reader/annotation.rs` and +11 unit tests in `src/reader/xmp.rs`).
- Round 25: **Document outline (bookmarks) + Link annotations**
  (ISO 32000-1 §12.3.3 Tables 152+153 + §12.5.6.5 Table 173 + §12.3.2
  Table 151 destinations). New writer entry points
  `write_pdf_from_scene_with_outlines` + `…_with_outlines_and_links`
  attach a `/Outlines` tree to the catalog and per-page `/Annots
  [/Subtype /Link]` arrays without disturbing the existing single-/
  multi-page entry points. New reader functions `read_pdf_outline`
  + `read_pdf_links` walk the bookmark tree (the doubly-linked
  `/First`/`/Last`/`/Next`/`/Prev` shape collapses back into a
  parent-owned `children` Vec) and per-page link list. Destinations
  cover all eight Table 151 forms — `Xyz` / `Fit` / `FitH` / `FitV`
  / `FitR` / `FitB` / `FitBH` / `FitBV` — with `null` retain-current
  semantics on the optional numerics. Link targets cover both
  internal `/Dest <explicit-array>` go-to and external
  `/A << /S /URI /URI (...) >>` action forms. Outline `/Count`
  honours the open / closed sign per Table 153 (open ⇒
  +visible_descendants; closed ⇒ -|hidden_descendants|), and the
  reader's `OutlineNode::is_open()` / `descendant_count()` helpers
  expose the same convention to callers. Tested end-to-end with
  `+19 tests` (16 integration in `tests/outline_round25.rs` covering
  three-bookmark catalog, nested open/closed chapters, every dest
  variant, Unicode title, URI + go-to link, multi-page link
  grouping, out-of-range writer rejection, combined outline+link
  round-trip, and empty-input baseline; +13 unit tests across
  `src/outline.rs` + `src/reader/outline.rs` + `src/reader/link.rs`).
- Round 24: **CMS KARI X448 ECDH** (RFC 7748 §5 + RFC 8410 §3 + RFC 8418
  §2.1 + §2.2). New `KariCurve::X448` joins the existing P-256/P-384/
  P-521/X25519 dispatch — `id-X448` (OID 1.3.101.111), 56-byte raw
  u-coordinate keys, 224-bit security level. Default KDF binding is
  X9.63-SHA-512 (security-strength match); HKDF SHA-256/384/512 are
  also valid via the new `KariRecipient::x448_hkdf_*` constructors.
  Reader (`unwrap_kari` / `read_pdf_to_scene_with_certificate`) and
  writer (`write_pdf_from_scene_pubsec_kari`) both handle X448 KARI
  envelopes through the existing entry points. RFC 7748 §6.2
  Alice/Bob test vector cross-checked byte-for-byte. Backed by the
  pure-Rust `x448` (RustCrypto / `ed448-goldilocks`) crate.
- Round 23: **JPEG passthrough on `/Filter /DCTDecode` Image XObjects**
  (ISO 32000-1 §7.4.8 + §8.9). New `DocumentReader::image_xobjects()`
  walks every page's `/Resources /XObject` subdict and surfaces every
  Image XObject whose final filter is `/DCTDecode`. The returned
  `PdfImageXObject` carries the unmodified JPEG bytes (ready for any
  JPEG decoder), the `/Width` / `/Height`, the `/ColorSpace`
  (`DeviceRGB` / `DeviceCMYK` / `DeviceGray` / `Indexed` / `Other`),
  and the `/BitsPerComponent`. Wrapping `/ASCII85Decode` /
  `/ASCIIHexDecode` / `/FlateDecode` filters preceding `/DCTDecode` are
  unwrapped before the JPEG payload is returned. Cross-checked against
  `pdfimages -all` (poppler-utils) as a black-box validator — extracted
  bytes are byte-identical to both the source JPEG and `pdfimages`'s
  dump.
- Round 22: text extraction. `DocumentReader::text_extraction()` walks
  every page's content stream and emits `TextRun`s (text + position +
  font name + font size) for `Tj` / `TJ` / `'` / `"` operators. Maps
  encoded glyphs back to Unicode through embedded `/ToUnicode` CMaps
  (`bfchar` / `bfrange` per ISO 32000-1 §9.10.3), Identity-H Type 0
  CIDs, WinAnsiEncoding, and MacRomanEncoding (Annex D.2). Cross-checked
  against `pdftotext` (poppler) as a black-box validator.

## [0.1.1](https://github.com/OxideAV/oxideav-pdf/compare/v0.1.0...v0.1.1) - 2026-05-09

### Other

- CMS SignedData signature verification (RFC 5652 §5.4)
- XMP /Metadata stream end-to-end + CMS SignedData parser scaffolding
- round-18 docs: refresh pubsec module-level deferrals list
- OriginatorInfo certs[]/crls[] surface + RKID date/other parse + temporal trust-store lookup
- TrustStore originator lookup + RC2/3DES decode + KARI EM=false test
- KARI P-521 + RFC 8418 §2.2 HKDF binding for X25519
- round-15 KARI multi-curve + writer entry-point
- KARI multi-curve (P-384 + X25519) + writer-side encode
- KARI unwrap (P-256 ECDH + RFC 5753 KDF + RFC 3394 AES-KW)
- round 13 emits per-page hint table entries
- page-offset hint table per-page entries (Annex F.4.1)
- per-CF recipient lists + CMS KARI decoder
- public-key encryption encode + SubjectKeyIdentifier matching
- public-key encryption decode (adbe.pkcs7.s3/s4/s5)
- linearization (Fast Web View) + ObjStm-with-encryption combo
- ObjStm encoder + incremental updates + EncryptMetadata false
- xref-stream encode + ObjStm resolve + /Crypt /Identity
- encryption encode + XRef stream decode
- round-5 AES-256 standard handler (R=5 Adobe ext + R=6 ISO 2.0)
- round-4 standard-handler decryption (RC4-40 / RC4-128 / AES-128)
- reframe FFI claim — HW-engine crates use OS FFI by necessity
- drop stale REGISTRARS / with_all_features intra-doc links
- drop dead `linkme` dep
- auto-register via oxideav_core::register! macro (linkme distributed slice)
- unify entry point on register(&mut RuntimeContext) ([#502](https://github.com/OxideAV/oxideav-pdf/pull/502))
- release v0.0.3 ([#2](https://github.com/OxideAV/oxideav-pdf/pull/2))

### Added

- Round-21: **PDF `/Sig` annotation reader** (ISO 32000-1 §12.7.4.5
  + §12.8.1) — closes the round-20 follow-up that surfaced
  `pubsec::verify::verify_signature` without a way to feed it real
  PDF signatures. New `reader::sig::PdfSignature` carries the parsed
  `[a, b, c, d]` `/ByteRange`, the hex-decoded `/Contents` blob, the
  `/SubFilter` name (`adbe.pkcs7.detached` /
  `ETSI.CAdES.detached` etc.), the optional metadata fields
  (`/Name`, `/Reason`, `/Location`, `/ContactInfo`, `/M`), and — for
  the CMS-detached SubFilters — the parsed
  [`pubsec::signed_data::SignedData`] (CMS trim handles trailing
  zero-padding bytes after the outer SEQUENCE, which Adobe and iText
  routinely emit when the `/Contents` hex budget exceeds the actual
  signature size). `DocumentReader::signatures()` walks the catalog
  → `/AcroForm /Fields` tree honouring `/FT` inheritance through
  non-terminal `/Kids` parents per ISO 32000-1 §12.7.3.1 (a parent
  carrying `/FT /Sig` propagates to its child fields), and is
  tolerant of unsigned slots (a Sig field whose `/V` is absent —
  common for "approval line still pending" templates), of malformed
  `/Contents` blobs, and of documents without an `/AcroForm`
  (returns an empty Vec). New `PdfSignature::signed_message(pdf)`
  helper concatenates the two `/ByteRange`-named slices into the
  byte string the signing tool hashed; pass it as
  `AttachedContent::External(...)` to the round-20
  `verify_signature` for end-to-end verification. Tested end-to-end
  with a hand-laid PDF 1.4 fixture carrying one
  `adbe.pkcs7.detached` signature signed with RSA-PKCS#1 v1.5 +
  SHA-256 over a `signedAttrs` set with the RFC 5652 §11.2
  `messageDigest` cross-check; tamper detection (flip a byte outside
  `/Contents`) is also exercised. `+14 tests` (8 integration in
  `tests/sig_round21.rs` + 6 unit in `src/reader/sig.rs`). The
  writer side (laying out an `/AcroForm /Fields` with reservable
  `/Contents` / `/ByteRange` slots so a downstream signing tool can
  fill them in place) is the round-22+ follow-up.

- Round-20: **CMS `SignedData` signature verification** (RFC 5652 §5.4 +
  §11.2 + RFC 8017 + RFC 5754 + RFC 5758). Closes the round-19 deferral
  that surfaced parsed `SignerInfo` bytes without a verifier. New
  `pubsec::verify::verify_signature(signer, certs, content) -> Result<bool>`
  resolves the signer's certificate from a pool by `IssuerAndSerial` or
  `SubjectKeyIdentifier`, hashes the canonical (universal-SET-tag)
  re-encoding of `signedAttrs` (or the raw eContent when `signedAttrs`
  is absent) per `digestAlgorithm`, and verifies the resulting hash
  against `signature` per `signatureAlgorithm`. Hash side: SHA-1 /
  SHA-256 / SHA-384 / SHA-512 via the existing `sha1` + `sha2` deps.
  Signature side: RSA-PKCS#1 v1.5 (the `rsaEncryption` + four
  `sha*WithRSA` OIDs all map here), RSA-PSS (`id-RSASSA-PSS`), and
  ECDSA on P-256 / P-384 / P-521 (curve dispatch by the cert SPKI's
  named-curve OID per RFC 5480 §2.1.1.1). When `signedAttrs` is
  present, the verifier also cross-checks the `messageDigest`
  attribute against the eContent hash per RFC 5652 §11.2 — so a
  tampered eContent still fails even when the outer signature
  verifies against intact attrs. Detached signatures (PAdES — eContent
  absent) feed the document bytes through a new
  `AttachedContent::External(&[u8])` parameter. New helpers
  `signed_attrs_to_be_signed`, `build_message_digest_attribute_der`,
  `pack_signed_attrs_implicit`, `implicit_signed_attrs_tlv`,
  `rsa_pubkey_to_pkcs1_der` for fixture builders. New OID constants
  `OID_SHA1` / `OID_SHA256` / `OID_SHA384` / `OID_SHA512` /
  `OID_RSA_ENCRYPTION` / `OID_SHA{1,256,384,512}_WITH_RSA` /
  `OID_RSA_PSS` / `OID_EC_PUBLIC_KEY` /
  `OID_ECDSA_WITH_SHA{1,256,384,512}` /
  `OID_NAMED_CURVE_P{256,384,521}` / `OID_ATTR_MESSAGE_DIGEST`.
- Round-20: **`x509::Certificate.spki_algorithm_oid` +
  `spki_algorithm_params`** — the SPKI's `AlgorithmIdentifier` is now
  captured (in addition to the BIT STRING contents already extracted
  in round 11) so the verifier can route ECDSA on the named-curve OID
  without re-parsing the certificate. `Certificate` now derives
  `Default`, so test fixtures can use `..Default::default()` for the
  optional fields.
- Round-20 tests: 20 new tests — 13 `pubsec::verify` unit tests
  (hash-OID dispatch, signed_attrs SET re-tag, RSA-PKCS1v15 with
  signedAttrs, RSA-PKCS1v15 without signedAttrs, content-tamper via
  messageDigest mismatch, single-bit signature flip rejection,
  cert-not-in-pool error, RSA-PSS, ECDSA-P256/384/521, ECDSA-P256
  signature-tamper rejection, SKI signer resolution) + 7
  `tests/pubsec_round20_signed_data_verify.rs` end-to-end integration
  tests (full SignedData ContentInfo → parse → verify, four algorithm
  combinations from the round dispatch sheet, both tamper paths,
  cert-not-in-pool, OID re-export visibility).

- Round-19: **Document-level XMP `/Metadata` stream end-to-end**
  (ISO 32000-1 §14.3.2 + Adobe XMP Spec 2012). Closes the round-17
  `EncryptMetadata=false` carve-out by giving the PDF a place to put
  the unencrypted document-level XMP packet. Writer entry point
  `write_pdf_from_scene_with_xmp(scene, xmp_bytes)` attaches the raw
  XMP RDF/XML payload to the catalog as a `/Type /Metadata /Subtype
  /XML` stream object — no `/Filter` per §14.3.2 (so archival-system
  grep tools can index the packet without decompressing). Reader
  accessor `DocumentReader::xmp_metadata() -> Result<Option<Vec<u8>>>`
  resolves the `/Metadata` indirect reference, decodes the stream, and
  returns the raw XMP bytes (caller does any XML / RDF parse). New
  `Document::object_mut` mutation helper enables the post-`build_pages`
  catalog patch.
- Round-19: **CMS `SignedData` parser scaffolding** (RFC 5652 §5,
  PKCS#7). Builds on the existing CMS DER + X.509 + EnvelopedData
  infrastructure to add parser-side recognition of `id-signedData`
  (OID `1.2.840.113549.1.7.2`) — the content type that wraps every PDF
  digital signature (ISO 32000-1 §12.8). New
  `pubsec::signed_data::SignedData { version, digest_algorithms,
  encap_content_type, encap_content_octets, certs, crls, signer_infos }`
  with one-shot accessor `parse_signed_data(der_bytes) ->
  Result<SignedData, PdfError>`. New
  `pubsec::signed_data::SignerInfo { version, sid, digest_algorithm_oid,
  digest_algorithm_params, signed_attrs, signed_attrs_der,
  signature_algorithm_oid, signature_algorithm_params, signature,
  unsigned_attrs }` exposes both the structural decode (signed +
  unsigned attribute lists with raw-DER values, IAS / SKI signer
  identifier) and the verification-helper bytes (raw `signed_attrs`
  DER body, ready for the SET-tag re-encode RFC 5652 §5.4 mandates
  before hashing). New `pubsec::signed_data::SignerIdentifier` mirrors
  the IAS / SKI CHOICE the CMS RecipientId already exposes for the
  envelope side. New OID constant `pubsec::cms::OID_SIGNED_DATA`.
  Signature verification (hash-then-verify dispatch per
  `digestAlgorithm` + `signatureAlgorithm`) is deferred to round 20.
- Round-19 tests: 13 new tests — 3 `pubsec::signed_data` unit tests
  (v=1 IAS attached signature, v=3 SKI with signed attrs, wrong-OID
  rejection) + 5 `tests/xmp_metadata_round19.rs` (byte-for-byte XMP
  round-trip, dict-shape inspection, no-metadata-returns-None,
  binary-payload survives, XMP coexists with `/Info`) + 5
  `tests/pubsec_round19_signed_data.rs` (attached SignedData parse
  with all fields surfaced, certs[] surfacing, wrong-OID rejection,
  truncated-blob rejection, empty-signerInfos rejection).
- Round-18: **CMS `OriginatorInfo` `certs[]` / `crls[]` surface**. The
  `EnvelopedData.originatorInfo` field (RFC 5652 §10.2.1 — `[0] IMPLICIT
  OriginatorInfo OPTIONAL`) was previously parsed-and-discarded. New
  `pubsec::cms::OriginatorInfo { certs: Vec<Vec<u8>>, crls: Vec<Vec<u8>> }`
  carries each `CertificateChoices` / `RevocationInfoChoices` entry as
  raw DER (preserving the outer tag + length, so callers can re-parse
  without reconstruction). New accessor
  `EnvelopedData::originator_info() -> Option<&OriginatorInfo>` returns
  `Some` only when the envelope carried a non-empty `OriginatorInfo`.
  Test fixture `pubsec::cms_build::build_envelope_aes256_with_originator_info`
  emits the bundled-cert form for the round-trip integration test.
- Round-18: **`RecipientKeyIdentifier { date, other }` parse + temporal
  trust-store lookup**. Per RFC 5652 §6.2.2 the RKID SEQUENCE may carry
  OPTIONAL `date GeneralizedTime` + `other OtherKeyAttribute` fields;
  round 17 ignored both. Round 18 captures them on the parser side
  (new `pubsec::cms::OtherKeyAttribute { key_attr_id: Vec<u64>, key_attr:
  Vec<u8> }`; the `KeyAgreeRecipientId::RecipientKeyIdentifier` arm
  gains `date: Option<Vec<u8>>` + `other: Option<OtherKeyAttribute>`
  fields), AND the encode-side fixture (`KariRecipientIdRef::RecipientKeyIdentifier`
  in `cms_build`) emits both OPTIONAL fields when populated.
  New `TrustStore::find_with_temporal_validity(ski, instant: Option<&[u8]>)`
  picks among multiple certs sharing an SKI the one whose validity
  window contains the supplied instant — useful for long-lived archives
  where the same recipient identity has been re-certified multiple
  times (yearly cert rotation preserving the SubjectKey). The
  `Certificate` parser now also extracts the `(not_before, not_after)`
  validity window, normalising `UTCTime` to `GeneralizedTime` per RFC
  5280 §4.1.2.5.1's 1950..2049 pivot so envelope `GeneralizedTime`
  bytes byte-compare directly against the cert's window. New helper
  `pubsec::x509::time_within(instant, not_before, not_after) -> bool`.
- Round-18 tests: 14 new tests — 3 `pubsec::trust` unit tests (temporal
  pick / temporal-skip-without-window / x509 validity round-trip) +
  4 `tests/pubsec_round18_originator_info.rs` (round-trip with both
  certs+crls, envelope-without-OI surfaces None, certs-only without
  CRLs, default-empty) + 7 `tests/pubsec_round18_rkid_temporal.rs`
  (RKID round-trip with date+other / date-only / other-only / neither,
  temporal lookup picks active generation, returns None outside any
  window, falls back to single-entry lookup when instant is None).
- Round-17: **Long-term originator cert via TrustStore**. Closes the
  RFC 5652 §6.2.2 `OriginatorIdentifierOrKey` `IssuerAndSerial` /
  `SubjectKeyIdentifier` decoder gap — when a KARI envelope identifies
  the originator by long-term cert reference rather than carrying its
  public point in-band, the recipient resolves the cert through a
  caller-supplied `TrustStore`. New types `pubsec::trust::TrustStore`
  + `pubsec::trust::CertRef` (re-exported as `oxideav_pdf::TrustStore`
  / `oxideav_pdf::CertRef`); new entry points
  `read_pdf_to_scene_with_certificate_and_trust_store(pdf, &cred, &store)`
  + `pubsec::open_with_certificate_and_trust_store(...)` +
  `..._with_permissions(...)`. New helper
  `pubsec::kari::unwrap_kari_with_trust_store(kari, slot, recipient,
  Option<&TrustStore>)` dispatches the lookup and pulls the
  originator's encoded public point straight out of the cert's SPKI BIT
  STRING contents (SEC1 uncompressed for NIST EC curves per RFC 5480
  §2.2; raw 32-byte u-coordinate for X25519 per RFC 8410 §4). Backwards
  compatible: the existing `read_pdf_to_scene_with_certificate` /
  `open_with_certificate` paths still refuse long-term-cert originators
  with a structured error.
- Round-17: **RC2 / 3DES envelope content decode (read-only)**. Adds
  decode support for `EncryptedContentInfo.contentEncryptionAlgorithm`
  values that legacy CMS envelopes may carry: RC2-CBC
  (OID `1.2.840.113549.3.2`, RFC 2268 + RFC 3217 §3 + RFC 3370 §5.1
  with the `rc2ParameterVersion` ↔ effective-key-bits mapping at
  160→40, 120→64, 58→128) and DES-EDE3-CBC / 3DES
  (OID `1.2.840.113549.3.7`, RFC 3370 §5.2 / RFC 5652 §12.4). New
  `pubsec::cms::ContentEncryption::Rc2Cbc { effective_key_bits, iv }` +
  `pubsec::cms::ContentEncryption::DesEde3Cbc { iv }` enum variants;
  RC2 dispatch goes through `Rc2::new_with_eff_key_len` to honour the
  RFC 3370 §5.1 effective-key parameter independently of the raw key
  length. Hidden test fixtures `pubsec::cms_build::build_envelope_rc2_cbc`
  + `..._des_ede3_cbc` (`#[doc(hidden)]`) so the read-only path is
  testable without exposing an encode-side public API. **PDF 2.0
  deprecates both algorithms** — no encode-side support is provided;
  the writer always uses AES. New deps: `rc2` 0.8 + `des` 0.8
  (RustCrypto, pure-Rust).
- Round-17: **`/EncryptMetadata false` × KARI end-to-end test**. Adds
  three integration tests confirming that
  `PubSecKariConfig::encrypt_metadata = false` round-trips through both
  the `/Encrypt` dict entry AND the SHA-256 file-key derivation's
  `0xFFFFFFFF` opt-in tail (ISO 32000-2 §7.6.5.3) for both P-256 ECDH
  and X25519 KARI envelopes — symmetric to the round-8 KTRI coverage
  in `tests/encrypt_metadata_false.rs`. The plumbing was already
  present from round 15; round 17 closes the test-coverage gap.
- Round-17 tests: 16 new tests — 4 `pubsec::trust` unit tests
  (IAS / SKI / dual-form-insert round-trips + SPKI-absent skip path) +
  3 `tests/pubsec_round17_kari_encrypt_metadata_false.rs` integration
  tests + 4 `tests/pubsec_round17_trust_store.rs` integration tests
  (long-term IAS originator + long-term SKI originator + missing-cert
  negative + wrong-cert AES-KW-failure negative) + 5
  `tests/pubsec_round17_rc2_3des.rs` integration tests (RC2-CBC parse +
  RC2-CBC round-trip + RC2-CBC 64-bit-effective-key round-trip +
  3DES-CBC parse + 3DES-CBC round-trip).

- Round-16: **P-521 KARI + RFC 8418 §2.2 HKDF binding for X25519**.
  Closes the NIST KARI curve coverage and adds the modern HKDF KDF
  family for X25519. New `pubsec::kari::KariCurve::P521` variant +
  `EcRecipient::p521` constructor + `KariRecipient::p521` writer
  constructor — bound to `dhSinglePass-stdDH-sha512kdf-scheme`
  (OID `1.3.132.1.11.3`) + X9.63-SHA-512 KDF per RFC 5753 §7.1.4.
  New `KariKdf` enum with `X963Sha256/384/512` + `HkdfSha256/384/512`
  arms (and `KariKdf::from_kea_oid` / `is_valid_for(curve)` helpers
  enforcing the RFC 5753 / RFC 8418 pairing matrix). New writer
  constructors `KariRecipient::x25519_hkdf_sha256/384/512` switch the
  X25519 binding from the legacy X9.63-SHA-256 (RFC 8418 §2.1) to the
  modern HKDF family — `dhSinglePass-stdDH-hkdf-sha256/384/512-scheme`
  OIDs `1.2.840.113549.1.9.16.3.{19,20,21}` per RFC 8418 §2.2. Per
  RFC 8418 §2.2: HKDF-Extract uses `salt = ukm` (or absent when UKM
  is missing) and `IKM = ECDH shared secret`; HKDF-Expand consumes
  the same DER `ECC-CMS-SharedInfo` structure as the X9.63 path.
  Reader auto-routes by parsing the KEA OID into `KariKdf` (no
  caller-side opt-in needed). New helpers `derive_kek` (KDF dispatch)
  + `hkdf_kdf_sha256/384/512` (RFC 5869 wrappers). The round-15
  `wrap_cek_for_recipient` keeps its signature; new
  `wrap_cek_for_recipient_with_kdf` accepts an explicit `KariKdf`
  override. Provenance: RFC 5753 §7.1.4 + RFC 5869 + RFC 8418 §2.2 +
  NIST FIPS 186-4 (P-521 curve) + NIST SP 800-56C only. New deps:
  `p521` 0.13 (`ecdh` + `std`) + `hkdf` 0.12.
- Round-16 tests: 11 new tests — 5 `pubsec::kari` unit tests (P-521 +
  AES-256 KW round-trip, X25519 + HKDF-SHA-256/384/512 + AES-128/256
  KW round-trips, KDF/curve pairing matrix coverage, HKDF dispatch
  byte-equivalence with `hkdf` crate primitive, X9.63-SHA-512 KDF
  one-block, build-time KDF/curve mismatch rejection) + 6 integration
  tests in `tests/pubsec_round16_kari.rs` (P-521 writer→reader
  round-trip, X25519 HKDF-SHA-256/384/512 writer→reader round-trips
  with UKM-present/absent variants, P-256-credential-against-P-521
  negative, wrong-X25519-scalar-against-HKDF negative).

- Round-15: **KARI multi-curve + writer-side encode**. Extends the
  round-14 KARI unwrap path to **P-384** (`dhSinglePass-stdDH-sha384kdf-scheme`,
  OID `1.3.132.1.11.2`, X9.63-SHA-384 KDF) and **X25519** (RFC 8418
  §2.1 — secg-scheme `1.3.132.1.11.1` X9.63-SHA-256 binding +
  `id-X25519` `1.3.101.110` curve OID). New `pubsec::kari::KariCurve`
  enum + `EcRecipient::p256/p384/x25519` constructors + generic
  `x963_kdf::<H: sha2::Digest>` (the SHA-256 wrapper
  `x963_kdf_sha256` is kept). Single dispatcher `unwrap_kari` routes
  on the recipient's curve; the round-14 `unwrap_kari_p256` entry
  point still works. New `PubSecCredential::from_parsed_ec(cert,
  curve, scalar)` + `with_ec_scalar(curve, scalar)` (round-14
  `_p256` variants forward here). Provenance: RFC 5753 §7.1.4 + RFC
  8418 §2.1 + RFC 8410 §3 + RFC 7748 §5 only. New deps: `p384` 0.13
  (`ecdh` + `std`) + `x25519-dalek` 2 (`static_secrets`).
- Round-15 writer: **`write_pdf_from_scene_pubsec_kari(scene, &PubSecKariConfig)`**.
  Symmetric to the round-11 `write_pdf_from_scene_pubsec_encrypted`
  KTRI path. Each `KariRecipient { curve, issuer/serial, recipient_pub_bytes,
  ephemeral_scalar }` becomes one CMS `EnvelopedData` carrying its
  own `KeyAgreeRecipientInfo` (one per recipient because the KEA
  pinpoints one curve per KARI); all envelopes wrap the same shared
  CEK with AES-256-WRAP and decrypt to the same AES-256 file content.
  New public types: `PubSecKariConfig::aes256(recipients)` +
  `KariRecipient::p256/p384/x25519` + `PubSecEncryptionState::build_kari`.
  The round-15 `wrap_cek_for_recipient(curve, ephemeral_scalar,
  recipient_pub_bytes, ukm, cek, wrap)` is the public dispatch
  helper used by `build_kari` (the round-14 P-256-only
  `wrap_cek_for_p256_recipient` forwards here).
- Round-15 tests: 8 new tests — 4 `pubsec::kari` unit tests
  (P-384 + AES-256 KW round trip, X25519 + AES-128 KW round trip,
  X9.63-SHA-384 KDF one-block, curve dispatch consistency) + 4
  integration tests in `tests/pubsec_round15_kari.rs` (P-256 / P-384 /
  X25519 writer→reader round-trips through the new
  `write_pdf_from_scene_pubsec_kari`, plus a wrong-key negative path).

- Round-14: **KARI unwrap** (RFC 5753 §7.1 + RFC 3394) — closes the
  round-12 deferral. P-256 ECDH key agreement + RFC 5753 §7.1.2 X9.63
  KDF with SHA-256 + RFC 3394 AES Key Wrap (128 / 192 / 256 bit) for
  the `dhSinglePass-stdDH-sha256kdf-scheme` KEA OID
  (`1.3.132.1.11.1`). New `pubsec::kari` module:
  `unwrap_kari_p256(kari, slot, &EcRecipient)` performs the full
  ECDH + KDF + AES-KW recovery; `x963_kdf_sha256` + `build_ecc_cms_shared_info`
  are the public KDF-input helpers. New
  `PubSecCredential::from_parsed_ec_p256(cert, ec_scalar)` +
  `with_ec_p256_scalar(scalar)` constructors plumb a P-256 SEC1 raw
  private scalar into the credential. The reader's `try_unwrap` now
  walks `all_recipients` (KTRI + KARI) — KARI slots whose
  `keyEncryptionAlgorithm` matches `dhSinglePass-stdDH-sha256kdf-scheme`
  and whose RID matches the credential's cert are unwrapped via P-256;
  unsupported KEA OIDs / mismatched RIDs are skipped silently so a
  mixed-recipient envelope (KTRI + KARI) opens via either side. New
  deps: `p256` 0.13 (with `ecdh` + `std` features) + `aes-kw` 0.2
  (with `alloc` feature). Provenance: RFC 5753 §3.1 / §7.1 / §7.2 +
  RFC 3394 §2.2.2 + RFC 5652 §6.2.2 + NIST SP 800-56A only. Decoder
  side; encoder-side `wrap_cek_for_p256_recipient` is a `#[doc(hidden)]`
  fixture helper used by the round-14 integration tests. P-384 / P-521
  / X25519 stay deferred (the structural parser already accepts every
  curve via `OriginatorPublicKey.algorithm`).
- Round-14 tests: 11 new tests — 8 `pubsec::kari` unit tests
  (X9.63-SHA-256 KDF one-block + truncated-multi-block, ECC-CMS-SharedInfo
  builder with + without UKM, wrap-OID round trip, P-256 + AES-128 KW
  round trip, P-256 + AES-256 KW round trip, unsupported-KEA-OID
  error path) + 3 integration tests in `tests/pubsec_round14_kari.rs`
  (`adbe.pkcs7.s5` V=5 KARI-encrypted PDF round-trip via
  `read_pdf_to_scene_with_certificate` — IAS form, SKI form, wrong
  EC key error path).

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
