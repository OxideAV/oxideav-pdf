//! Crate-local error type.
//!
//! Internal modules return [`PdfError`]; the public surface (top-level
//! `write_pdf`, the [`oxideav_core::Encoder`] impl) converts to
//! [`oxideav_core::Error`] at the boundary.

use std::io;

/// Errors that can arise while building a PDF.
#[derive(Debug)]
pub enum PdfError {
    /// I/O error while serialising. Currently only produced by the
    /// `Vec<u8>`-backed writer when something pathological happens to
    /// the underlying allocator.
    Io(io::Error),
    /// Catch-all for assembly-time problems (missing /Root, malformed
    /// gradient, etc.). Carries a static or owned string message.
    Other(String),
}

impl PdfError {
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}

impl std::fmt::Display for PdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "PDF I/O error: {e}"),
            Self::Other(s) => write!(f, "PDF error: {s}"),
        }
    }
}

impl std::error::Error for PdfError {}

impl From<io::Error> for PdfError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<PdfError> for oxideav_core::Error {
    fn from(e: PdfError) -> Self {
        match e {
            PdfError::Io(io) => oxideav_core::Error::Io(io),
            PdfError::Other(msg) => oxideav_core::Error::invalid(msg),
        }
    }
}
