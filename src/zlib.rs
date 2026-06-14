//! One-shot zlib (RFC 1950) helpers shared by every FlateDecode call
//! site in the crate.
//!
//! `/FlateDecode` (ISO 32000-1 §7.4.4) is zlib-wrapped DEFLATE — RFC
//! 1950 framing around RFC 1951 compressed data. Both the writer
//! (stream-payload compression for image XObjects, object streams,
//! cross-reference streams, embedded-file streams) and the reader
//! (inflating `/FlateDecode` content + cross-reference streams) only
//! ever need whole-buffer compress / decompress, so these two thin
//! `Vec<u8>` wrappers are the crate's entire compression surface.
//!
//! RFC 1950 / RFC 1951 framing is delegated to `compcol`, the
//! workspace-wide compression collection (the same crate the other
//! oxideav format crates — png, tiff, mov, id3 — use), so the PDF
//! crate links no third-party DEFLATE backend of its own.

use crate::error::PdfError;
use compcol::zlib::Zlib;

/// Compress `data` into a zlib (RFC 1950) stream at `compcol`'s default
/// DEFLATE level (6 — the zlib default). The writer leaves the level
/// choice to the compressor; every `/FlateDecode` stream the crate
/// emits uses this single entry point.
///
/// Compression of an in-memory buffer cannot fail, so the helper
/// returns a bare `Vec<u8>` and panics only on an impossible internal
/// error (mirroring the previous `expect(...)` contract).
pub(crate) fn flate_compress(data: &[u8]) -> Vec<u8> {
    compcol::vec::compress_to_vec::<Zlib>(data).expect("zlib compression cannot fail on Vec")
}

/// Decompress a zlib (RFC 1950) stream into a `Vec<u8>`. Each call site
/// wraps the error with stream-specific context (`/FlateDecode`
/// content stream vs cross-reference stream vs object stream …).
pub(crate) fn flate_decompress(data: &[u8]) -> Result<Vec<u8>, PdfError> {
    compcol::vec::decompress_to_vec::<Zlib>(data)
        .map_err(|e| PdfError::other(format!("PDF filter: FlateDecode failed: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flate_round_trips_payload() {
        let raw = b"the quick brown fox jumps over the lazy dog, repeated; \
                    the quick brown fox jumps over the lazy dog, repeated.";
        let compressed = flate_compress(raw);
        // zlib framing: 0x78 CMF byte (CM=8 deflate, CINFO=7 for 32K
        // window) per RFC 1950 §2.2.
        assert_eq!(compressed[0], 0x78);
        let back = flate_decompress(&compressed).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn flate_decompress_rejects_garbage() {
        let err = flate_decompress(&[0x00, 0x01, 0x02, 0x03]);
        assert!(err.is_err());
    }

    #[test]
    fn flate_compress_empty_round_trips() {
        let compressed = flate_compress(b"");
        let back = flate_decompress(&compressed).unwrap();
        assert!(back.is_empty());
    }
}
