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

pub mod actions;
pub mod annotation;
pub mod attachments;
pub(crate) mod cid_cmap;
pub mod content;
pub mod document;
pub mod encoding;
// Internal: stream-filter implementations behind `decode_stream` (exposed for tests).
#[doc(hidden)]
pub mod filters;
pub mod hierarchy;
pub(crate) mod image_decode;
pub mod images;
pub mod inline_images;
pub mod layout;
// Internal: tokenizer plumbing behind the object parser (exposed for tests).
#[doc(hidden)]
pub mod lex;
pub mod linearize;
pub mod link;
pub mod named_dest;
pub mod nametree;
pub mod ocg;
pub mod outline;
pub mod page_labels;
// Internal: object-parser plumbing behind `DocumentReader` (exposed for tests).
#[doc(hidden)]
pub mod parse;
pub mod pdfa;
pub mod sig;
pub mod text;
pub mod threads;
pub mod xmp;
// Internal: xref-walker plumbing behind `DocumentReader` (exposed for tests).
#[doc(hidden)]
pub mod xref;

pub use actions::{actions, ActionKind, ActionTrigger, PdfAction};
pub use annotation::{
    annotations, AnnotationAppearance, AnnotationKind, FixedPrint, MovieActivation, PdfAnnotation,
    TextMarkupVariant, ThreeDActivation, ThreeDViewSelector,
};
pub use attachments::{attachments, PdfAttachment};
pub use content::{
    parse_content_stream, parse_content_stream_full, parse_content_stream_full_with_color_space,
    parse_content_stream_full_with_properties, parse_content_stream_full_with_shading,
    parse_content_stream_full_with_soft_masks, parse_content_stream_with_resources,
    ContentInlineImage, ContentMarkedContent, ContentShading, ContentTextShow, MarkedContentOp,
    MeshPatch, MeshShading, MeshTriangle, MeshVertex, ParsedContent, ResolvedImageXObject,
    ResolvedSoftMask, ShadingGradient, TextShowOp,
};
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
pub use images::{image_xobjects, ColorSpace, PdfImageXObject, SoftMaskImage};
pub use inline_images::{inline_images, InlineImageFilter, PdfInlineImage};
pub use layout::{read_in_logical_order, LayoutMode, ReadingOrderText};
pub use linearize::{parse_linearization_dict, LinearizationParams};
pub use link::{links, PdfLink, PdfLinkTarget};
pub use named_dest::{named_destinations, resolve_named_destination, NamedDestination};
pub use nametree::{decode_key_text, name_tree_entries, name_tree_lookup, number_tree_entries};
pub use ocg::{
    optional_content, parse_membership, OcBaseState, OcConfig, OcListMode, OcMembership,
    OcOrderItem, OcUsage, OcVisibilityExpression, OcVisibilityPolicy, OptionalContent,
    OptionalContentGroup,
};
pub use outline::{outline, OutlineNode, PdfOutline};
pub use page_labels::{
    page_label_map, page_label_ranges, page_labels, PageLabelRange, PageLabelStyle,
};
pub use pdfa::{pdfa_signals, PdfACatalogSignals, PdfAConformance};
pub use sig::{doc_timestamps, signatures, signed_bytes, PdfDocTimestamp, PdfSignature};
pub use text::{
    extract_text, extract_text_marked, MarkedTextRun, PdfMarkedTextExtraction, PdfTextExtraction,
    TextRenderMode, TextRun,
};
pub use threads::{threads, PdfBead, PdfThread};
pub use xmp::XmpPacket;
