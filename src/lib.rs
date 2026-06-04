//! Pure-Rust PDF writer for the oxideav framework — round 1.
//!
//! Round 1 supports a single-page PDF 1.4 document built from one
//! [`oxideav_core::vector::VectorFrame`]. The imaging-model surface
//! emitted is the SVG / PDF intersection that `oxideav-core` already
//! models:
//!
//! * **Paths** — move / line / cubic / quadratic (lifted to cubic) /
//!   elliptic-arc (flattened to cubic) / close.
//! * **Solid + linear/radial gradient fills** (Pattern Type 2 +
//!   Function Type 2 / Type 3 stitching).
//! * **Strokes** — width, cap, join, miter limit, dash array+offset.
//! * **2D affine transforms** (`cm`).
//! * **Groups** with optional opacity (ExtGState `/ca` + `/CA`) and
//!   clip path (`W n`).
//! * **Embedded raster images** as FlateDecode `Image` XObjects with
//!   per-pixel alpha via `SMask`. RGBA8 only — JPEG passthrough,
//!   palette images, and 16-bit depth are round 2.
//!
//! Text rendering, multi-page output, transparency groups beyond a
//! per-`Group` `/ca`+`/CA` opacity, and PDF *reading* are all out of
//! scope for round 1 — see `README.md` for the full deferred list.
//!
//! # Public surface
//!
//! ```rust
//! use oxideav_core::{Group, VectorFrame, time::TimeBase};
//!
//! let frame = VectorFrame {
//!     width: 100.0,
//!     height: 100.0,
//!     view_box: None,
//!     root: Group::default(),
//!     pts: None,
//!     time_base: TimeBase::new(1, 1),
//! };
//! let bytes = oxideav_pdf::write_pdf(&frame).unwrap();
//! assert!(bytes.starts_with(b"%PDF-1.4"));
//! ```
//!
//! The crate also registers itself with [`oxideav_core::CodecRegistry`]
//! so it can be selected via the standard codec-id lookup
//! (`"pdf"`).

pub mod acroform;
pub mod annotations;
pub mod arc;
pub mod attachments;
pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod info;
pub mod linearize;
pub mod objects;
pub mod operators;
pub mod outline;
pub mod page;
pub mod pubsec;
pub mod reader;
pub mod resources;
pub mod sig;
pub mod writer;

pub use acroform::{
    write_pdf_with_form, FieldJustification, FormField, FormFieldCheckbox, FormFieldChoice,
    FormFieldRadioGroup, FormFieldSignature, FormFieldText, RadioOption,
};
pub use annotations::{
    write_pdf_with_annotations, Annotation, AnnotationKind as WriterAnnotationKind, CaretSymbol,
    FreeTextQuadding,
};
pub use attachments::{
    write_pdf_with_annotations_and_attachments, write_pdf_with_attachments, AfRelationship,
    Attachment,
};
pub use error::PdfError;
pub use outline::{LinkAnnotationSpec, LinkTarget, OutlineDestination, OutlineSpec};
pub use pubsec::{
    open_with_certificate, open_with_certificate_and_trust_store,
    open_with_certificate_and_trust_store_with_permissions, open_with_certificate_with_permissions,
    CertRef, KariRecipient, PubSecCfGroup, PubSecCredential, PubSecEncoderConfig,
    PubSecEncryptionState, PubSecKariConfig, PubSecMatch, PubSecMultiCfConfig, PubSecRecipient,
    PubSecSubFilter, TrustStore,
};
pub use reader::doc_timestamps as read_pdf_doc_timestamps;
pub use reader::{
    actions as read_pdf_actions, annotations as read_pdf_annotations,
    attachments as read_pdf_attachments, extract_text as extract_pdf_text,
    extract_text_marked as extract_pdf_text_marked, image_xobjects as read_pdf_image_xobjects,
    inline_images as read_pdf_inline_images, links as read_pdf_links, outline as read_pdf_outline,
    parse_linearization_dict, pdfa_signals as read_pdf_pdfa_signals,
    read_in_logical_order as read_pdf_in_logical_order, read_pdf_to_scene,
    read_pdf_to_scene_with_certificate, read_pdf_to_scene_with_certificate_and_trust_store,
    read_pdf_to_scene_with_password, signatures as read_pdf_signatures,
    signed_bytes as pdf_signed_bytes, verify_hierarchy as verify_pdf_hierarchy, ActionKind,
    ActionTrigger, AnnotationKind, ColorSpace, FixedPrint, HierarchyIssue, HierarchyReport,
    InlineImageFilter, IssueSeverity, LayoutMode, LinearizationParams, MarkedTextRun,
    MovieActivation, OutlineNode, PdfACatalogSignals, PdfAConformance, PdfAction, PdfAnnotation,
    PdfAttachment, PdfDocTimestamp, PdfImageXObject, PdfInlineImage, PdfLink, PdfLinkTarget,
    PdfMarkedTextExtraction, PdfOutline, PdfSignature, PdfTextExtraction, ReadingOrderText,
    TextMarkupVariant, TextRun, ThreeDActivation, ThreeDViewSelector, XmpPacket,
};
pub use sig::{
    add_document_timestamp, build_tst_info, pkcs7_wrap_signed_data, sign_pdf_from_scene,
    wrap_tst_in_signed_data, EcdsaP256Sha256Signer, MessageImprint, MockTsaSigner,
    RsaPkcs1v15Sha256Signer, SigWriter, Signer, SignerIdentity, SigningAlgorithm, TsaSigner,
    OID_CT_TST_INFO,
};
pub use writer::{
    write_pdf, write_pdf_from_scene, write_pdf_from_scene_encrypted,
    write_pdf_from_scene_linearized, write_pdf_from_scene_object_stream,
    write_pdf_from_scene_object_stream_encrypted, write_pdf_from_scene_pubsec_encrypted,
    write_pdf_from_scene_pubsec_kari, write_pdf_from_scene_pubsec_multi_cf,
    write_pdf_from_scene_with_outlines, write_pdf_from_scene_with_outlines_and_links,
    write_pdf_from_scene_with_xmp, write_pdf_from_scene_xref_stream, write_pdf_incremental_update,
};

use oxideav_core::{
    CodecCapabilities, CodecId, CodecInfo, CodecParameters, CodecRegistry, ContainerRegistry,
    Encoder, Error, Frame, MediaType, Muxer, Packet, Result, RuntimeContext, StreamInfo, TimeBase,
    WriteSeek,
};

/// String form of the [`oxideav_core::CodecId`] this crate registers
/// under. Use it from container code that wants to claim PDF as an
/// output target.
pub const CODEC_ID_STR: &str = "pdf";

// ───────────────────────── Encoder ─────────────────────────

struct PdfEncoder {
    output_params: CodecParameters,
    pending: Option<Vec<u8>>,
    eof: bool,
}

fn make_encoder(params: &CodecParameters) -> Result<Box<dyn Encoder>> {
    let mut output_params = params.clone();
    output_params.media_type = MediaType::Video;
    output_params.codec_id = CodecId::new(CODEC_ID_STR);
    Ok(Box::new(PdfEncoder {
        output_params,
        pending: None,
        eof: false,
    }))
}

impl Encoder for PdfEncoder {
    fn codec_id(&self) -> &CodecId {
        &self.output_params.codec_id
    }

    fn output_params(&self) -> &CodecParameters {
        &self.output_params
    }

    fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        match frame {
            Frame::Vector(v) => {
                let bytes = write_pdf(v).map_err(Error::from)?;
                self.pending = Some(bytes);
                Ok(())
            }
            _ => Err(Error::invalid(
                "PDF encoder: only vector frames are accepted (Frame::Vector)",
            )),
        }
    }

    fn receive_packet(&mut self) -> Result<Packet> {
        if let Some(bytes) = self.pending.take() {
            let mut pkt = Packet::new(0, TimeBase::new(1, 1), bytes);
            pkt.flags.keyframe = true;
            return Ok(pkt);
        }
        if self.eof {
            return Err(Error::Eof);
        }
        Err(Error::NeedMore)
    }

    fn flush(&mut self) -> Result<()> {
        self.eof = true;
        Ok(())
    }
}

// ───────────────────────── Muxer ─────────────────────────

struct PdfMuxer {
    output: Box<dyn WriteSeek>,
    written_packet: bool,
}

fn open_muxer(output: Box<dyn WriteSeek>, _streams: &[StreamInfo]) -> Result<Box<dyn Muxer>> {
    Ok(Box::new(PdfMuxer {
        output,
        written_packet: false,
    }))
}

impl Muxer for PdfMuxer {
    fn format_name(&self) -> &str {
        "pdf"
    }

    fn write_header(&mut self) -> Result<()> {
        // The PDF encoder writes a complete file in one packet, so the
        // muxer header is a no-op — the entire byte sequence (header,
        // body, xref, trailer) lands in `write_packet`.
        Ok(())
    }

    fn write_packet(&mut self, packet: &Packet) -> Result<()> {
        if self.written_packet {
            return Err(Error::invalid(
                "PDF muxer: round-1 supports a single page; got more than one packet",
            ));
        }
        use std::io::Write;
        self.output.write_all(&packet.data)?;
        self.written_packet = true;
        Ok(())
    }

    fn write_trailer(&mut self) -> Result<()> {
        // Already self-contained — nothing more to flush.
        Ok(())
    }
}

// ───────────────────────── Registration ─────────────────────────

/// Register the PDF encoder with `codecs`.
pub fn register_codecs(reg: &mut CodecRegistry) {
    let caps = CodecCapabilities::video("pdf_sw")
        .with_intra_only(true)
        .with_lossless(true);
    reg.register(
        CodecInfo::new(CodecId::new(CODEC_ID_STR))
            .capabilities(caps)
            .encoder(make_encoder),
    );
}

/// Register the PDF muxer with `containers`.
pub fn register_containers(reg: &mut ContainerRegistry) {
    reg.register_muxer("pdf", open_muxer);
    reg.register_extension("pdf", "pdf");
}

/// Unified registration entry point — installs the PDF encoder into
/// the codec sub-registry and the PDF muxer into the container
/// sub-registry of the supplied [`RuntimeContext`].
///
/// Also wired into [`oxideav_meta::register_all`] via the
/// [`oxideav_core::register!`] macro below.
pub fn register(ctx: &mut RuntimeContext) {
    register_codecs(&mut ctx.codecs);
    register_containers(&mut ctx.containers);
}

oxideav_core::register!("pdf", register);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_adds_encoder_and_muxer() {
        let mut ctx = RuntimeContext::new();
        register(&mut ctx);
        assert!(ctx.codecs.has_encoder(&CodecId::new(CODEC_ID_STR)));
        assert!(ctx.containers.muxer_names().any(|n| n == "pdf"));
    }

    #[test]
    fn register_via_runtime_context_installs_both_sides() {
        let mut ctx = RuntimeContext::new();
        register(&mut ctx);
        let id = CodecId::new(CODEC_ID_STR);
        assert!(
            ctx.codecs.has_encoder(&id),
            "PDF encoder factory not installed via RuntimeContext"
        );
        assert_eq!(
            ctx.containers.container_for_extension("pdf"),
            Some("pdf"),
            "PDF container extension not installed via RuntimeContext"
        );
    }
}
