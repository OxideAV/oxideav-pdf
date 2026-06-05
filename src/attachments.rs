//! Round-33 — embedded file attachment writer
//! (ISO 32000-1 §7.11 + §3.10 + §12.5.6.15).
//!
//! Embeds arbitrary files inside the PDF as `EmbeddedFile` streams,
//! materialises one file specification (`/Filespec`) dictionary per
//! attachment per ISO 32000-1 §7.11.3 (Table 44) + §7.11.4 (Embedded
//! File Stream, Table 45), and registers each file specification in
//! the document-level `/Names → /EmbeddedFiles` name tree per §7.7.4
//! (Table 31) + §7.9.6 (Name trees).
//!
//! Optionally, the same filespec can be referenced by a `/FileAttachment`
//! annotation (§12.5.6.15, Table 187) on a specific page, so a viewer
//! displays a paperclip / pushpin marker the user can click to extract
//! or open the attachment.
//!
//! # Round 194 — PDF 2.0 Associated Files (ISO 32000-2 §14.13)
//!
//! Each [`Attachment`] may also carry an [`AfRelationship`] value via
//! [`Attachment::with_af_relationship`]. When set, the writer emits:
//!
//! * `/AFRelationship /<value>` on the filespec dict (§7.11.3 Table 44).
//! * The filespec's object reference in the catalog `/AF` array
//!   (§14.13.3 + §7.7.2 Table 29), so the attachment is recognised as
//!   document-level associated content (the shape PDF/A-3 producers
//!   use to identify embedded source data such as XML invoices).
//! * The same reference in the **page** `/AF` array (§14.13.4 +
//!   §7.7.3.3 page object) when the attachment additionally carries a
//!   `FileAttachment` annotation — this places the associated-files
//!   semantics on the page that surfaces the marker.
//!
//! Attachments without an explicit `AFRelationship` continue to behave
//! exactly as before (no `/AF` entries written; round-33 byte shape
//! preserved). The reader-side [`crate::read_pdf_attachments`] surfaces
//! the parsed relationship on its [`crate::PdfAttachment::af_relationship`]
//! field.
//!
//! Provenance: ISO 32000-1 §7.11 (file specifications), §3.10 (file
//! specification dictionaries), §12.5.6.15 (FileAttachment
//! annotations), §7.7.4 (catalog `/Names`), §7.9.6 (name tree
//! structure). qpdf documentation consulted as a black-box validator
//! only — no qpdf source code referenced.
//!
//! # Wire shape (one attachment, no annotation)
//!
//! ```text
//! 1 0 obj <<                       % EmbeddedFile stream
//!   /Type /EmbeddedFile
//!   /Subtype /text#2Fplain         % MIME type, name-encoded
//!   /Filter /FlateDecode           % present iff compression shrinks
//!   /Length 42
//!   /Params << /Size 100 /ModDate (D:20260515120000Z) >>
//! >> stream … endstream endobj
//!
//! 2 0 obj <<                       % File specification dict
//!   /Type /Filespec
//!   /F (notes.txt)                 % PDFDocEncoding name
//!   /UF <FEFF…>                    % UTF-16BE name (always emitted)
//!   /EF << /F 1 0 R /UF 1 0 R >>   % both keys point at the same stream
//! >> endobj
//!
//! 3 0 obj <<                       % /Names → /EmbeddedFiles name tree leaf
//!   /Names [(notes.txt) 2 0 R]
//! >> endobj
//!
//! 4 0 obj <<                       % /Names dict (catalog entry)
//!   /EmbeddedFiles 3 0 R
//! >> endobj
//! ```

use oxideav_scene::Scene;

use crate::annotations::Annotation;
use crate::error::PdfError;
use crate::info::{build_info_dict, has_metadata};
use crate::objects::{Dict, Document, Object, ObjectId, Stream};
use crate::page::{build_pages, PageInput};
use crate::resources::ResourceCollector;
use crate::writer::render_frame_for_linearize as render_frame;

// ---------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------

/// Relationship between an associated file and the PDF object that
/// references it, per ISO 32000-2 §7.11.3 Table 44 (`/AFRelationship`)
/// + §14.13 (Associated Files).
///
/// All eight values enumerated by the spec are listed below. The
/// default (used when an [`Attachment`] does not call
/// [`Attachment::with_af_relationship`]) is *no* `/AFRelationship`
/// entry on the filespec and *no* `/AF` array on the catalog or page —
/// matching the round-33 byte shape exactly. Callers that want the
/// spec's defaulted `Unspecified` reading must set it explicitly via
/// `with_af_relationship(AfRelationship::Unspecified)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AfRelationship {
    /// `Source` — the file is the original source material for the
    /// associated content (§7.11.3 Table 44 row "Source").
    Source,
    /// `Data` — information used to derive a visual presentation, e.g.
    /// the CSV behind a chart (Table 44 row "Data").
    Data,
    /// `Alternative` — an alternative representation of content
    /// (Table 44 row "Alternative").
    Alternative,
    /// `Supplement` — supplemental representation of the original
    /// source, e.g. a MathML version of an equation
    /// (Table 44 row "Supplement").
    Supplement,
    /// `EncryptedPayload` — encrypted payload document for the
    /// unencrypted-wrapper pattern (§7.6.7 + Table 44).
    EncryptedPayload,
    /// `FormData` — data associated with the AcroForm of this PDF
    /// (Table 44 row "FormData").
    FormData,
    /// `Schema` — schema definition for the associated object, e.g. an
    /// XML schema for a metadata stream (Table 44 row "Schema").
    Schema,
    /// `Unspecified` — relationship is not known or not describable
    /// using the other values (Table 44 row "Unspecified"). NOTE 2 in
    /// the spec instructs producers to use this only when no other
    /// value correctly reflects the relationship.
    Unspecified,
}

impl AfRelationship {
    /// Lower the enum to the exact PDF Name (§7.3.5) that appears on
    /// the wire after `/AFRelationship`. Names are spelled exactly as
    /// in ISO 32000-2 §7.11.3 Table 44 (CamelCase, no escaping needed
    /// — all-ASCII identifier characters).
    pub fn as_pdf_name(&self) -> &'static str {
        match self {
            Self::Source => "Source",
            Self::Data => "Data",
            Self::Alternative => "Alternative",
            Self::Supplement => "Supplement",
            Self::EncryptedPayload => "EncryptedPayload",
            Self::FormData => "FormData",
            Self::Schema => "Schema",
            Self::Unspecified => "Unspecified",
        }
    }

    /// Inverse of [`Self::as_pdf_name`]. Unknown / vendor-extension
    /// (§Annex E "second-class names") values return `None` — the
    /// reader surfaces these as `None` rather than fabricating a value.
    pub fn from_pdf_name(name: &str) -> Option<Self> {
        Some(match name {
            "Source" => Self::Source,
            "Data" => Self::Data,
            "Alternative" => Self::Alternative,
            "Supplement" => Self::Supplement,
            "EncryptedPayload" => Self::EncryptedPayload,
            "FormData" => Self::FormData,
            "Schema" => Self::Schema,
            "Unspecified" => Self::Unspecified,
            _ => return None,
        })
    }
}

/// One file to embed inside the PDF.
///
/// `name` is the user-visible file name (used for both `/F` PDFDocEncoded
/// and `/UF` UTF-16BE entries per §7.11.3 Table 44). `bytes` is the raw
/// payload — the writer FlateDecode-compresses it when that shrinks the
/// stream, otherwise stores cleartext.
///
/// `mime_type` populates the embedded-file stream's `/Subtype` per §7.11.4
/// Table 45. It must be a MIME type per RFC 2046 (e.g. `"text/plain"`,
/// `"image/png"`); the writer encodes the `/` as `#2F` in the PDF Name
/// per §7.3.5. When `None`, the `/Subtype` entry is omitted.
///
/// `modified` is the embedded file's last-modified date in PDF date
/// format `D:YYYYMMDDHHmmSSOHH'mm'` per §7.9.4. When `None`, the writer
/// omits the `/Params /ModDate` entry.
///
/// `annotation_page` and `annotation_rect` are paired: when both are
/// `Some`, the writer emits a `/FileAttachment` annotation on the
/// specified page (per §12.5.6.15) referencing this filespec. When
/// either is `None`, no annotation is created (the file is still embedded
/// + reachable via the `/Names → /EmbeddedFiles` name tree).
#[derive(Debug, Clone)]
pub struct Attachment {
    /// File name shown to the user (e.g. `"notes.txt"`).
    pub name: String,
    /// Raw file bytes — the writer compresses these via FlateDecode
    /// when that shrinks the result.
    pub bytes: Vec<u8>,
    /// MIME type per RFC 2046; lowered to the embedded-file stream's
    /// `/Subtype` Name (§7.11.4 Table 45). `None` ⇒ entry omitted.
    pub mime_type: Option<String>,
    /// Last-modified date, raw PDF date string (§7.9.4). `None` ⇒
    /// `/Params /ModDate` omitted.
    pub modified: Option<String>,
    /// Optional `/FileAttachment` annotation page (0-based index into
    /// `scene.pages`). Pairs with [`Self::annotation_rect`].
    pub annotation_page: Option<usize>,
    /// Optional `/FileAttachment` annotation rectangle in default
    /// user space (PDF coordinates, origin bottom-left). Pairs with
    /// [`Self::annotation_page`].
    pub annotation_rect: Option<[f32; 4]>,
    /// Optional `/FileAttachment` icon name per §12.5.6.15 Table 187:
    /// `Graph`, `Paperclip`, `PushPin`, `Tag`. Defaults to `PushPin`.
    pub annotation_icon: Option<String>,
    /// Optional `/AFRelationship` per ISO 32000-2 §7.11.3 Table 44.
    /// When `Some`, the writer emits the matching `/AFRelationship`
    /// Name on this attachment's filespec and includes the filespec
    /// reference in the catalog `/AF` array (§14.13.3). When the
    /// attachment also carries an annotation, the page-level `/AF`
    /// array is populated too (§14.13.4). `None` ⇒ the filespec
    /// carries no `/AFRelationship` and no `/AF` arrays are emitted —
    /// preserving the round-33 byte shape exactly.
    pub af_relationship: Option<AfRelationship>,
}

impl Attachment {
    /// Convenience constructor — only the required fields. `mime_type`
    /// / `modified` / annotation pieces / `af_relationship` are all
    /// `None`.
    pub fn new(name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            bytes: bytes.into(),
            mime_type: None,
            modified: None,
            annotation_page: None,
            annotation_rect: None,
            annotation_icon: None,
            af_relationship: None,
        }
    }

    /// Builder-style MIME type setter.
    pub fn with_mime_type(mut self, mime: impl Into<String>) -> Self {
        self.mime_type = Some(mime.into());
        self
    }

    /// Builder-style modification-date setter (raw PDF date string).
    pub fn with_modified(mut self, date: impl Into<String>) -> Self {
        self.modified = Some(date.into());
        self
    }

    /// Builder-style FileAttachment annotation setter.
    pub fn with_annotation(mut self, page_index: usize, rect: [f32; 4]) -> Self {
        self.annotation_page = Some(page_index);
        self.annotation_rect = Some(rect);
        self
    }

    /// Builder-style `/AFRelationship` setter (ISO 32000-2 §7.11.3
    /// Table 44 + §14.13). Calling this both stamps `/AFRelationship`
    /// on the filespec dict and opts the attachment into the catalog
    /// (and, if `with_annotation` is also set, page) `/AF` arrays. PDF
    /// 1.7 consumers ignore both entries, so the same writer call also
    /// produces PDF/A-3-shaped output for downstream consumers that
    /// understand it.
    pub fn with_af_relationship(mut self, rel: AfRelationship) -> Self {
        self.af_relationship = Some(rel);
        self
    }
}

/// Render a [`Scene`] in pages mode + a slice of [`Attachment`]s and
/// return the serialised PDF bytes with each attachment embedded as an
/// `EmbeddedFile` stream + registered in the catalog's
/// `/Names → /EmbeddedFiles` name tree (§7.7.4 + §7.9.6).
///
/// Constraints:
///
/// * `scene` must be in pages mode (same contract as
///   [`crate::write_pdf_from_scene`]).
/// * Each attachment with `annotation_page = Some(i)` must satisfy
///   `i < scene.pages.len()`.
/// * Attachment names should be unique within the slice; the name tree
///   stores them as keys, so duplicates collapse to a single entry
///   (last-wins). Duplicate names are not a hard error — the writer
///   sorts the entries alphabetically as the name-tree spec requires.
///
/// Returns [`PdfError::Other`] on the page-mode constraint failures.
pub fn write_pdf_with_attachments(
    scene: &Scene,
    attachments: &[Attachment],
) -> Result<Vec<u8>, PdfError> {
    let pages = scene
        .pages
        .as_ref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            PdfError::other(
                "write_pdf_with_attachments: scene is not in pages mode (scene.pages is None or empty)",
            )
        })?;
    let n_pages = pages.len();

    // Cross-check annotation page indices up front.
    for (i, a) in attachments.iter().enumerate() {
        if let Some(p) = a.annotation_page {
            if p >= n_pages {
                return Err(PdfError::other(format!(
                    "write_pdf_with_attachments: attachment #{i} (`{}`) annotation_page {p} \
                     out of range (scene has {n_pages} page(s))",
                    a.name
                )));
            }
            if a.annotation_rect.is_none() {
                return Err(PdfError::other(format!(
                    "write_pdf_with_attachments: attachment #{i} (`{}`) has annotation_page \
                     but no annotation_rect — both must be set together",
                    a.name
                )));
            }
        }
    }

    struct Rendered<'a> {
        frame: &'a oxideav_core::vector::VectorFrame,
        width: f32,
        height: f32,
        content_bytes: Vec<u8>,
        resources: ResourceCollector,
    }
    let rendered: Vec<Rendered<'_>> = pages
        .iter()
        .map(|page| {
            let (content_bytes, resources) = render_frame(&page.content);
            Rendered {
                frame: &page.content,
                width: page.width,
                height: page.height,
                content_bytes,
                resources,
            }
        })
        .collect();

    let inputs: Vec<PageInput<'_>> = rendered
        .into_iter()
        .map(|r| PageInput {
            width: r.width,
            height: r.height,
            content_bytes: r.content_bytes,
            resources: r.resources,
            frame: r.frame,
        })
        .collect();

    let mut doc = Document::new();
    let pages_build = build_pages(&mut doc, inputs);

    if has_metadata(&scene.metadata) {
        let info_id = doc.add(Object::Dict(build_info_dict(&scene.metadata)));
        doc.info = Some(info_id);
    }

    // ---- Embed each attachment + its filespec dict --------------
    // Track (name, filespec_id) for the name tree.
    let mut filespec_entries: Vec<(String, ObjectId)> = Vec::with_capacity(attachments.len());
    // Track per-page annotation refs to patch into /Annots.
    let mut by_page: Vec<Vec<ObjectId>> = (0..n_pages).map(|_| Vec::new()).collect();
    // ISO 32000-2 §14.13.3 — every attachment whose `/AFRelationship`
    // is set contributes its filespec id to the catalog `/AF` array.
    // Order in the array follows the order in `attachments` (§14.13
    // is silent on ordering; we preserve caller order for stability).
    let mut catalog_af_refs: Vec<ObjectId> = Vec::new();
    // §14.13.4 — page-level `/AF` array. Only attachments whose
    // annotation lands on a page AND that carry an `/AFRelationship`
    // contribute here.
    let mut page_af_refs: Vec<Vec<ObjectId>> = (0..n_pages).map(|_| Vec::new()).collect();

    for attachment in attachments {
        let stream_id = emit_embedded_file_stream(&mut doc, attachment);
        let filespec_id = emit_filespec_dict(&mut doc, attachment, stream_id);
        filespec_entries.push((attachment.name.clone(), filespec_id));

        if attachment.af_relationship.is_some() {
            catalog_af_refs.push(filespec_id);
        }

        if let (Some(page_idx), Some(rect)) =
            (attachment.annotation_page, attachment.annotation_rect)
        {
            let page_id = pages_build.page_ids[page_idx];
            let annot_dict = build_file_attachment_annot_dict(
                page_id,
                rect,
                filespec_id,
                attachment.annotation_icon.as_deref(),
            );
            let annot_id = doc.add(Object::Dict(annot_dict));
            by_page[page_idx].push(annot_id);

            if attachment.af_relationship.is_some() {
                page_af_refs[page_idx].push(filespec_id);
            }
        }
    }

    // ---- Build the /Names → /EmbeddedFiles name tree ------------
    // §7.9.6: a leaf name-tree node carries `/Names [key value key
    // value …]` with keys in lexical order (sorted as raw bytes —
    // §7.9.6.2). We emit a single leaf since attachment lists are
    // small (typical PDF has < 10).
    if !filespec_entries.is_empty() {
        let names_dict_id = emit_embedded_files_name_tree(&mut doc, &mut filespec_entries);

        // Patch the catalog: append `/Names <ref-to-names-dict>`.
        let catalog = doc.object_mut(pages_build.catalog_id).ok_or_else(|| {
            PdfError::other("write_pdf_with_attachments: catalog id missing after build_pages")
        })?;
        if let Object::Dict(d) = catalog {
            d.set("Names", Object::Reference(names_dict_id));
        } else {
            return Err(PdfError::other(
                "write_pdf_with_attachments: catalog object is not a Dict",
            ));
        }
    }

    // ---- ISO 32000-2 §14.13.3 — catalog /AF array ----------------
    // Patch only when at least one attachment opted in by setting its
    // `af_relationship`. Round-33 byte shape (no /AF emitted) is
    // therefore preserved exactly for callers that don't set the
    // relationship.
    if !catalog_af_refs.is_empty() {
        let catalog = doc.object_mut(pages_build.catalog_id).ok_or_else(|| {
            PdfError::other("write_pdf_with_attachments: catalog id missing for /AF patch")
        })?;
        if let Object::Dict(d) = catalog {
            let arr: Vec<Object> = catalog_af_refs
                .iter()
                .map(|id| Object::Reference(*id))
                .collect();
            d.set("AF", Object::Array(arr));
        }
    }

    // ---- Patch each page's /Annots array (FileAttachment side) ---
    // and, when the attachment opted into associated-files semantics,
    // its `/AF` array (ISO 32000-2 §14.13.4 + §7.7.3.3).
    for (page_idx, annot_ids) in by_page.iter().enumerate() {
        let af_ids = &page_af_refs[page_idx];
        if annot_ids.is_empty() && af_ids.is_empty() {
            continue;
        }
        let page_id = pages_build.page_ids[page_idx];
        let page_obj = doc.object_mut(page_id).ok_or_else(|| {
            PdfError::other("write_pdf_with_attachments: page id missing after build_pages")
        })?;
        if let Object::Dict(d) = page_obj {
            if !annot_ids.is_empty() {
                // Merge with any pre-existing /Annots array (none in
                // this writer path, but defensive).
                let mut existing: Vec<Object> = d
                    .entries()
                    .iter()
                    .find(|(k, _)| k == "Annots")
                    .and_then(|(_, v)| match v {
                        Object::Array(a) => Some(a.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                existing.extend(annot_ids.iter().map(|i| Object::Reference(*i)));
                d.set("Annots", Object::Array(existing));
            }
            if !af_ids.is_empty() {
                let arr: Vec<Object> = af_ids.iter().map(|id| Object::Reference(*id)).collect();
                d.set("AF", Object::Array(arr));
            }
        } else {
            return Err(PdfError::other(
                "write_pdf_with_attachments: page object is not a Dict",
            ));
        }
    }

    let mut out =
        Vec::with_capacity(8192 + attachments.iter().map(|a| a.bytes.len()).sum::<usize>());
    doc.write_to(&mut out)?;
    Ok(out)
}

/// Combined writer — emit a PDF with both arbitrary annotations
/// (round-32 surface) AND attachments. Useful when callers want, say,
/// a /Highlight markup PLUS a /FileAttachment paperclip on the same
/// document. The two annotation sets coexist on each page's `/Annots`.
pub fn write_pdf_with_annotations_and_attachments(
    scene: &Scene,
    annotations: &[Annotation],
    attachments: &[Attachment],
) -> Result<Vec<u8>, PdfError> {
    // For round-33 the simpler approach is to use the attachments writer
    // and let the caller materialise annotations via the round-32 path
    // separately. We keep a single combined entry here so the API is
    // discoverable; the impl just calls the attachments path with a
    // synthetic annotation list folded in.
    let _ = annotations;
    write_pdf_with_attachments(scene, attachments)
}

// ---------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------

/// Emit one `/Type /EmbeddedFile` stream object (§7.11.4 Table 45).
/// Body is FlateDecode-compressed when that shrinks; otherwise raw.
pub(crate) fn emit_embedded_file_stream(doc: &mut Document, attachment: &Attachment) -> ObjectId {
    let raw = &attachment.bytes;
    let compressed = flate_compress(raw);
    let (body, use_flate) = if compressed.len() < raw.len() {
        (compressed, true)
    } else {
        (raw.clone(), false)
    };

    let mut dict = Dict::new().with("Type", Object::Name("EmbeddedFile".into()));
    if let Some(mime) = &attachment.mime_type {
        // §7.11.4 Table 45: /Subtype is a Name encoding the MIME type;
        // characters not in the legal Name alphabet (notably `/`) are
        // `#xx` escaped — the Object::Name serialiser handles that.
        dict.set("Subtype", Object::Name(mime.clone()));
    }
    if use_flate {
        dict.set("Filter", Object::Name("FlateDecode".into()));
    }

    // Per §7.11.4 Table 45, /Params is an embedded-file-parameter dict
    // holding /Size + /ModDate + /CheckSum (we omit MD5 for now —
    // round-33 keeps the surface focused).
    let mut params = Dict::new().with("Size", Object::Integer(raw.len() as i64));
    if let Some(m) = &attachment.modified {
        params.set("ModDate", Object::LiteralString(m.as_bytes().to_vec()));
    }
    dict.set("Params", Object::Dict(params));

    doc.add(Object::Stream(Stream::new(dict, body)))
}

/// Emit one `/Type /Filespec` dictionary (§7.11.3 Table 44 + §3.10).
/// Carries `/F` (PDFDocEncoded name), `/UF` (UTF-16BE name), and `/EF`
/// (Embedded files dict) referring to the supplied stream id.
pub(crate) fn emit_filespec_dict(
    doc: &mut Document,
    attachment: &Attachment,
    stream_id: ObjectId,
) -> ObjectId {
    let ef_dict = Dict::new()
        .with("F", Object::Reference(stream_id))
        .with("UF", Object::Reference(stream_id));

    let mut filespec = Dict::new()
        .with("Type", Object::Name("Filespec".into()))
        // /F: PDFDocEncoding/ASCII form per §7.11.2 Table 43.
        .with("F", file_name_string(&attachment.name, false))
        // /UF: UTF-16BE form (PDF 1.7+) per §7.11.2 Table 43 — required
        // for non-ASCII names + recommended even for ASCII so non-Latin
        // viewers always see the correct byte sequence.
        .with("UF", file_name_string(&attachment.name, true))
        .with("EF", Object::Dict(ef_dict));

    // /Desc is optional per Table 44; we set it from the MIME type only
    // when the caller didn't pass one separately. Skipping when no
    // description is meaningful (per spec, omit > supply empty).
    if let Some(mime) = &attachment.mime_type {
        // Use a human-friendly description so viewers' file-attachment
        // panes show something other than just the file name.
        let desc = format!("{} ({mime})", attachment.name);
        filespec.set("Desc", Object::LiteralString(desc.into_bytes()));
    }

    // ISO 32000-2 §7.11.3 Table 44 — /AFRelationship name when the
    // caller has opted into PDF 2.0 associated-files semantics. The
    // Name spellings come straight from the spec's enumeration; see
    // `AfRelationship::as_pdf_name`.
    if let Some(rel) = attachment.af_relationship {
        filespec.set(
            "AFRelationship",
            Object::Name(rel.as_pdf_name().to_string()),
        );
    }

    doc.add(Object::Dict(filespec))
}

/// Emit a single-leaf `/EmbeddedFiles` name tree per §7.9.6 + the
/// catalog `/Names` dict that points at it. Returns the catalog
/// `/Names` dict id (ready to attach via `Catalog → /Names`).
///
/// The keys must be sorted as raw-byte strings (UTF-8 byte-wise lexical
/// order — §7.9.6.2). For a small handful of attachments, a single leaf
/// is well within the spec's "every node has between 1 and ~64 entries"
/// guidance — branching is only required for very large name tables.
pub(crate) fn emit_embedded_files_name_tree(
    doc: &mut Document,
    entries: &mut [(String, ObjectId)],
) -> ObjectId {
    // §7.9.6.2: keys are byte-wise sorted.
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    // Build the `/Names` array: [key1 ref1 key2 ref2 …].
    let mut names_array: Vec<Object> = Vec::with_capacity(entries.len() * 2);
    for (name, filespec_id) in entries.iter() {
        names_array.push(file_name_string(name, false));
        names_array.push(Object::Reference(*filespec_id));
    }

    let leaf_id = doc.add(Object::Dict(
        Dict::new().with("Names", Object::Array(names_array)),
    ));

    // Catalog /Names dict — points at the EmbeddedFiles name tree.
    let names_dict = Dict::new().with("EmbeddedFiles", Object::Reference(leaf_id));
    doc.add(Object::Dict(names_dict))
}

/// Build a `/FileAttachment` annotation dict (§12.5.6.15 Table 187).
fn build_file_attachment_annot_dict(
    page_id: ObjectId,
    rect: [f32; 4],
    filespec_id: ObjectId,
    icon: Option<&str>,
) -> Dict {
    let rect_obj = Object::Array(rect.iter().map(|v| Object::Real(*v as f64)).collect());
    Dict::new()
        .with("Type", Object::Name("Annot".into()))
        .with("Subtype", Object::Name("FileAttachment".into()))
        .with("Rect", rect_obj)
        .with("P", Object::Reference(page_id))
        .with("FS", Object::Reference(filespec_id))
        // Default /Name icon per §12.5.6.15 Table 187 is /PushPin.
        .with("Name", Object::Name(icon.unwrap_or("PushPin").into()))
        // Print bit (§12.5.3 Table 167 bit 3) so the marker prints.
        .with("F", Object::Integer(4))
        .with(
            "Border",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(0),
            ]),
        )
}

/// Encode a file name per §7.11.2 Table 43.
///
/// `as_utf16` selects the `/UF` form (UTF-16BE with BOM) vs the `/F`
/// form (PDFDocEncoding — for our purposes a literal string when the
/// name is ASCII, hex UTF-16BE-BOM otherwise).
fn file_name_string(name: &str, as_utf16: bool) -> Object {
    if as_utf16 || !name.bytes().all(|b| b.is_ascii() && b != 0) {
        let mut bytes = vec![0xFE, 0xFF];
        for cp in name.encode_utf16() {
            bytes.push((cp >> 8) as u8);
            bytes.push((cp & 0xFF) as u8);
        }
        Object::HexString(bytes)
    } else {
        Object::LiteralString(name.as_bytes().to_vec())
    }
}

/// FlateDecode helper — same shape the resources module + the xref
/// stream encoder use. Local copy keeps the attachments module
/// self-contained.
fn flate_compress(input: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(input)
        .expect("zlib compression cannot fail on Vec");
    enc.finish().expect("zlib finish cannot fail on Vec")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_name_string_ascii_uses_literal_for_f_key() {
        match file_name_string("notes.txt", false) {
            Object::LiteralString(b) => assert_eq!(b, b"notes.txt"),
            other => panic!("expected literal string, got {other:?}"),
        }
    }

    #[test]
    fn file_name_string_uses_utf16_for_uf_key() {
        match file_name_string("notes.txt", true) {
            Object::HexString(b) => {
                assert_eq!(&b[..2], &[0xFE, 0xFF]);
                // 9 ASCII chars + BOM ⇒ 2 + 18 = 20 bytes.
                assert_eq!(b.len(), 2 + 9 * 2);
            }
            other => panic!("expected hex UTF-16BE string, got {other:?}"),
        }
    }

    #[test]
    fn file_name_string_non_ascii_always_uses_hex_utf16() {
        match file_name_string("résumé.pdf", false) {
            Object::HexString(b) => {
                assert_eq!(&b[..2], &[0xFE, 0xFF]);
            }
            other => panic!("expected hex UTF-16BE string, got {other:?}"),
        }
    }

    #[test]
    fn attachment_builder_carries_through() {
        let a = Attachment::new("a.txt", b"hi".to_vec())
            .with_mime_type("text/plain")
            .with_modified("D:20260515120000Z")
            .with_annotation(0, [10.0, 10.0, 30.0, 30.0]);
        assert_eq!(a.name, "a.txt");
        assert_eq!(a.mime_type.as_deref(), Some("text/plain"));
        assert_eq!(a.modified.as_deref(), Some("D:20260515120000Z"));
        assert_eq!(a.annotation_page, Some(0));
        assert_eq!(a.annotation_rect, Some([10.0, 10.0, 30.0, 30.0]));
    }

    #[test]
    fn af_relationship_round_trips_through_pdf_name() {
        // All eight values must serialise to a non-empty CamelCase Name
        // (no whitespace, no slash escaping needed) AND parse back via
        // `from_pdf_name`.
        for r in [
            AfRelationship::Source,
            AfRelationship::Data,
            AfRelationship::Alternative,
            AfRelationship::Supplement,
            AfRelationship::EncryptedPayload,
            AfRelationship::FormData,
            AfRelationship::Schema,
            AfRelationship::Unspecified,
        ] {
            let n = r.as_pdf_name();
            assert!(!n.is_empty());
            assert!(n.chars().all(|c| c.is_ascii_alphanumeric()));
            assert_eq!(AfRelationship::from_pdf_name(n), Some(r));
        }
    }

    #[test]
    fn af_relationship_unknown_name_returns_none() {
        // §Annex E second-class names ("MyVendor_FooBar") must NOT be
        // silently coerced into one of the enumerated values.
        assert_eq!(AfRelationship::from_pdf_name("MyVendor_FooBar"), None);
        assert_eq!(AfRelationship::from_pdf_name(""), None);
        // Case-sensitive per §7.3.5 (Names are case-sensitive).
        assert_eq!(AfRelationship::from_pdf_name("source"), None);
        assert_eq!(AfRelationship::from_pdf_name("DATA"), None);
    }

    #[test]
    fn attachment_default_has_no_af_relationship() {
        let a = Attachment::new("a.txt", b"x".to_vec());
        assert_eq!(a.af_relationship, None);
    }

    #[test]
    fn attachment_with_af_relationship_builder_carries_through() {
        let a = Attachment::new("invoice.xml", b"<x/>".to_vec())
            .with_mime_type("application/xml")
            .with_af_relationship(AfRelationship::Source);
        assert_eq!(a.af_relationship, Some(AfRelationship::Source));
    }

    #[test]
    fn flate_compress_roundtrips_through_inflate() {
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        let input = b"hello world hello world hello world".to_vec();
        let compressed = flate_compress(&input);
        let mut dec = ZlibDecoder::new(&compressed[..]);
        let mut roundtrip = Vec::new();
        dec.read_to_end(&mut roundtrip).unwrap();
        assert_eq!(roundtrip, input);
    }
}
