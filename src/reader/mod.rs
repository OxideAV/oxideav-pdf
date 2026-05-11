//! PDF *reader* — byte-stream → typed object tree → high-level Scene.
//!
//! Round 3, in commits:
//!
//! 1. [`lex`]: tokenizer (bytes → [`Token`]s) per ISO 32000-1 §7.2.
//! 2. [`parse`]: object parser (tokens → [`crate::objects::Object`]).
//! 3. xref + trailer parser, top-level catalog walk.
//! 4. Content-stream operator parser (inverse of
//!    [`crate::operators`]) — `m`/`l`/`c`/`re` → [`PathCommand`],
//!    `cm` → [`Transform2D`], `q`/`Q` → group save/restore, etc.
//! 5. /Info dict → [`oxideav_scene::Metadata`] +
//!    Scene assembly via [`oxideav_scene::Page`].
//!
//! Round 3 supports PDF 1.4 with simple xref + uncompressed object
//! streams. Object streams (PDF 1.5+), encryption, incremental
//! updates, and linearization land in round 4+.
//!
//! [`Token`]: lex::Token
//! [`PathCommand`]: oxideav_core::vector::PathCommand
//! [`Transform2D`]: oxideav_core::vector::Transform2D

pub mod annotation;
pub mod content;
pub mod document;
pub mod encoding;
pub mod hierarchy;
pub mod images;
pub mod layout;
pub mod lex;
pub mod linearize;
pub mod link;
pub mod outline;
pub mod parse;
pub mod pdfa;
pub mod sig;
pub mod text;
pub mod xmp;
pub mod xref;

pub use annotation::{annotations, AnnotationKind, PdfAnnotation, TextMarkupVariant};
pub use document::{
    read_pdf_to_scene, read_pdf_to_scene_with_certificate,
    read_pdf_to_scene_with_certificate_and_trust_store, read_pdf_to_scene_with_password,
    DocumentReader,
};
pub use encoding::{
    apply_encoding_differences, parse_encoding_differences, BaseEncoding, EncodingDifferences,
    EncodingMap, EncodingOverride,
};
pub use hierarchy::{verify_hierarchy, HierarchyIssue, HierarchyReport, IssueSeverity};
pub use images::{image_xobjects, ColorSpace, PdfImageXObject};
pub use layout::{read_in_logical_order, LayoutMode, ReadingOrderText};
pub use linearize::{parse_linearization_dict, LinearizationParams};
pub use link::{links, PdfLink, PdfLinkTarget};
pub use outline::{outline, OutlineNode, PdfOutline};
pub use pdfa::{pdfa_signals, PdfACatalogSignals, PdfAConformance};
pub use sig::{signatures, signed_bytes, PdfSignature};
pub use text::{
    extract_text, extract_text_marked, MarkedTextRun, PdfMarkedTextExtraction, PdfTextExtraction,
    TextRun,
};
pub use xmp::XmpPacket;
