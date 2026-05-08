# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Round-4 reader: standard-security-handler decryption (ISO 32000-1
  §7.6) for revisions R=2 (RC4-40), R=3 (RC4-128), and R=4 (AES-128
  CBC or RC4-128 via `CFM`).
- `read_pdf_to_scene_with_password()` and
  `DocumentReader::open_with_password()` public APIs.
- `decrypt` module exposing `StandardHandler`, `CryptMethod`, plus
  hand-rolled `rc4()` / `md5()` (RFC 1321) and AES-128 CBC via the
  `aes` + `cbc` RustCrypto crates.
- 23 new tests: MD5 RFC 1321 §A.5 known-answers, RC4 RFC 6229 §2
  known-answers, Algorithm 1/2 derivation vectors, AES-128 CBC
  round-trip, and end-to-end fixture decode for R=2/R=3/R=4 with
  user-password, owner-password (Algorithm 7), wrong-password, and
  empty-default-password paths.

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
