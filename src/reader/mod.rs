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
pub(crate) mod std14_metrics;
pub mod text;
pub mod threads;
pub mod xmp;
// Internal: xref-walker plumbing behind `DocumentReader` (exposed for tests).
#[doc(hidden)]
pub mod xref;

pub use actions::{ActionKind, ActionTrigger, PdfAction, actions};
pub use annotation::{
    AnnotationAppearance, AnnotationKind, FixedPrint, MovieActivation, PdfAnnotation,
    TextMarkupVariant, ThreeDActivation, ThreeDViewSelector, annotations,
};
pub use attachments::{PdfAttachment, attachments};
pub use content::{
    ContentInlineImage, ContentMarkedContent, ContentShading, ContentTextShow, MarkedContentOp,
    MeshPatch, MeshShading, MeshTriangle, MeshVertex, ParsedContent, ResolvedImageXObject,
    ResolvedSoftMask, ShadingGradient, TextShowOp, parse_content_stream, parse_content_stream_full,
    parse_content_stream_full_with_color_space, parse_content_stream_full_with_properties,
    parse_content_stream_full_with_shading, parse_content_stream_full_with_soft_masks,
    parse_content_stream_with_resources,
};
pub use document::{
    DocumentReader, read_pdf_to_scene, read_pdf_to_scene_with_certificate,
    read_pdf_to_scene_with_certificate_and_trust_store, read_pdf_to_scene_with_password,
};
pub use encoding::{
    BaseEncoding, EncodingDifferences, EncodingMap, EncodingOverride, apply_encoding_differences,
    parse_encoding_differences,
};
pub use hierarchy::{HierarchyIssue, HierarchyReport, IssueSeverity, verify_hierarchy};
pub use images::{ColorSpace, PdfImageXObject, SoftMaskImage, image_xobjects};
pub use inline_images::{InlineImageFilter, PdfInlineImage, inline_images};
pub use layout::{LayoutMode, ReadingOrderText, read_in_logical_order};
pub use linearize::{LinearizationParams, parse_linearization_dict};
pub use link::{PdfLink, PdfLinkTarget, links};
pub use named_dest::{NamedDestination, named_destinations, resolve_named_destination};
pub use nametree::{decode_key_text, name_tree_entries, name_tree_lookup, number_tree_entries};
pub use ocg::{
    OcBaseState, OcConfig, OcListMode, OcMembership, OcOrderItem, OcUsage, OcVisibilityExpression,
    OcVisibilityPolicy, OptionalContent, OptionalContentGroup, optional_content, parse_membership,
};
pub use outline::{OutlineNode, PdfOutline, outline};
pub use page_labels::{
    PageLabelRange, PageLabelStyle, page_label_map, page_label_ranges, page_labels,
};
pub use pdfa::{PdfACatalogSignals, PdfAConformance, pdfa_signals};
pub use sig::{PdfDocTimestamp, PdfSignature, doc_timestamps, signatures, signed_bytes};
pub use text::{
    MarkedTextRun, PdfMarkedTextExtraction, PdfTextExtraction, TextRenderMode, TextRun,
    WORD_GAP_EM, assemble_text, extract_text, extract_text_marked, reorder_bidi_line,
};
pub use threads::{PdfBead, PdfThread, threads};
pub use xmp::XmpPacket;
