# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
