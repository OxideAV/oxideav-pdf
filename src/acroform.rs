//! Round-31 — AcroForm interactive-widget writer (ISO 32000-1 §12.7).
//!
//! Symmetric writer side of the round-26 reader's [`crate::reader::AnnotationKind::Widget`]
//! decoder. Given a [`oxideav_scene::Scene`] in pages mode + a slice of
//! [`FormField`] specs, emits a PDF whose Catalog carries `/AcroForm`
//! and whose first page carries a `/Annots` array of `/Subtype /Widget`
//! annotations bound to the fields.
//!
//! Field types implemented (per §12.7.4):
//!
//! * **Text field** — `/FT /Tx`. Optional `/V` default value, `/MaxLen`,
//!   `/Q` justification, `/Ff` multi-line bit (bit 12 — bit index 13).
//! * **Button** — `/FT /Btn`. Three subtypes via `/Ff`:
//!   * Pushbutton (`/Ff` bit 16 — bit-index 17 in §12.7.4.2.1 Table 226)
//!   * Checkbox — neither pushbutton nor radio bit
//!   * Radio (`/Ff` bit 15 — bit-index 16 in Table 226). The whole
//!     [`FormFieldRadioGroup`] becomes one terminal field with `/Kids`,
//!     one widget annotation per option (the appearance state name
//!     selects the active option).
//! * **Choice** — `/FT /Ch`. Combo (`/Ff` bit 17 — bit-index 18) vs.
//!   list box. `/Opt` is an array of option labels.
//! * **Signature** — `/FT /Sig` wrapping a [`crate::sig::Signer`]. Re-uses
//!   the round-30 `/Contents` placeholder pattern: a placeholder is
//!   reserved at writer time, then patched after the surrounding bytes
//!   are stable. Only one signature field per call (the byte-range
//!   placeholder pattern assumes a single signed range).
//!
//! Provenance: ISO 32000-1 §12.7.2 (AcroForm dict), §12.7.3 (field
//! dictionaries), §12.7.4.2 (button), §12.7.4.3 (text), §12.7.4.4
//! (choice), §12.7.4.5 (signature), §12.5.6.19 Table 188 (Widget
//! annotation). No third-party PDF source consulted.

use oxideav_scene::Scene;

use crate::error::PdfError;
use crate::info::{build_info_dict, has_metadata};
use crate::objects::{Dict, Document, Object, ObjectId};
use crate::page::{build_pages, PageInput};
use crate::resources::ResourceCollector;
use crate::sig::Signer;
use crate::writer::render_frame_for_linearize as render_frame;

// ---------------------------------------------------------------------
// Public API — field type structs + the FormField enum.
// ---------------------------------------------------------------------

/// Text justification (`/Q` in §12.7.3.3 Table 222).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FieldJustification {
    /// Left-justified (default).
    #[default]
    Left,
    /// Centred.
    Center,
    /// Right-justified.
    Right,
}

impl FieldJustification {
    fn as_int(self) -> i64 {
        match self {
            Self::Left => 0,
            Self::Center => 1,
            Self::Right => 2,
        }
    }
}

/// `/FT /Tx` — single-line or multi-line text field (§12.7.4.3).
#[derive(Debug, Clone)]
pub struct FormFieldText {
    /// `/T` partial field name (must be unique within the form).
    pub name: String,
    /// `/Rect` bounding box on the page (PDF coordinates).
    pub rect: [f32; 4],
    /// 0-based page index the widget lives on. Defaults to 0 (the
    /// first page).
    pub page_index: usize,
    /// `/V` default value — the visible text.
    pub value: Option<String>,
    /// `/MaxLen` maximum number of characters. `None` = unbounded.
    pub max_length: Option<u32>,
    /// `/Ff` bit 12 — multi-line text input (§12.7.4.3 Table 228).
    pub multi_line: bool,
    /// `/Q` justification.
    pub justification: FieldJustification,
    /// `/DA` default appearance string. `None` ⇒
    /// inherit AcroForm /DA `"(/Helv 12 Tf 0 g)"`.
    pub default_appearance: Option<String>,
}

/// `/FT /Btn` checkbox (§12.7.4.2.3). The checked / unchecked appearance
/// is keyed by `/Yes` (checked) and `/Off` (unchecked) state names per
/// Table 228 — round-31 emits both as the rendered glyph 'X' / blank.
#[derive(Debug, Clone)]
pub struct FormFieldCheckbox {
    /// `/T` partial field name.
    pub name: String,
    /// `/Rect` widget bounds.
    pub rect: [f32; 4],
    /// 0-based page index.
    pub page_index: usize,
    /// Initial checked state.
    pub checked: bool,
    /// `/DA` default appearance.
    pub default_appearance: Option<String>,
}

/// One option in a [`FormFieldRadioGroup`] — a single physical widget
/// annotation that participates in the group's mutual-exclusion via
/// its `/AS` appearance state.
#[derive(Debug, Clone)]
pub struct RadioOption {
    /// Distinct `/AS` appearance state name (the "on" state). When the
    /// radio group's value equals this name, this option's `/AS` is set
    /// to the matching name; otherwise it's `/Off`.
    pub export_value: String,
    /// `/Rect` widget bounds.
    pub rect: [f32; 4],
    /// 0-based page index.
    pub page_index: usize,
}

/// `/FT /Btn` with `NoToggleToOff` + `Radio` flags (§12.7.4.2.2). One
/// terminal field with `/Kids` listing every option's widget.
#[derive(Debug, Clone)]
pub struct FormFieldRadioGroup {
    /// `/T` partial field name.
    pub name: String,
    /// The physical options.
    pub options: Vec<RadioOption>,
    /// `/V` currently-selected export value. `None` ⇒ no option active.
    pub value: Option<String>,
}

/// `/FT /Ch` choice field (§12.7.4.4). Combo-box (`/Ff` bit 17) when
/// `combo_box` is true; list box otherwise.
#[derive(Debug, Clone)]
pub struct FormFieldChoice {
    /// `/T` partial field name.
    pub name: String,
    /// `/Rect` widget bounds.
    pub rect: [f32; 4],
    /// 0-based page index.
    pub page_index: usize,
    /// `/Opt` array — each entry is one option label.
    pub options: Vec<String>,
    /// `/V` currently-selected value (must appear in `options` to
    /// round-trip cleanly).
    pub value: Option<String>,
    /// True ⇒ combo box; false ⇒ list box.
    pub combo_box: bool,
    /// `/DA` default appearance.
    pub default_appearance: Option<String>,
}

/// `/FT /Sig` signature field — round-30 [`crate::sig::Signer`] wired
/// into the AcroForm. Only one signature field per
/// [`write_pdf_with_form`] call.
pub struct FormFieldSignature {
    /// `/T` partial field name (e.g. `"Signature1"`).
    pub name: String,
    /// `/Rect` widget bounds.
    pub rect: [f32; 4],
    /// 0-based page index.
    pub page_index: usize,
    /// The cryptographic signer + identity used to populate the CMS
    /// SignedData blob.
    pub signer: Box<dyn Signer>,
    /// Signer identity (cert chain + IAS).
    pub identity: crate::sig::SignerIdentity,
}

impl std::fmt::Debug for FormFieldSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FormFieldSignature")
            .field("name", &self.name)
            .field("rect", &self.rect)
            .field("page_index", &self.page_index)
            .field("signer", &"<dyn Signer>")
            .finish()
    }
}

/// One of the four interactive form field types defined by
/// §12.7.4. The writer collapses these into the `/AcroForm /Fields`
/// array + the per-page `/Annots /Subtype /Widget` annotations.
#[allow(missing_docs)]
pub enum FormField {
    Text(FormFieldText),
    Checkbox(FormFieldCheckbox),
    RadioGroup(FormFieldRadioGroup),
    Choice(FormFieldChoice),
    Signature(FormFieldSignature),
}

impl std::fmt::Debug for FormField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(t) => f.debug_tuple("Text").field(t).finish(),
            Self::Checkbox(c) => f.debug_tuple("Checkbox").field(c).finish(),
            Self::RadioGroup(r) => f.debug_tuple("RadioGroup").field(r).finish(),
            Self::Choice(c) => f.debug_tuple("Choice").field(c).finish(),
            Self::Signature(s) => f.debug_tuple("Signature").field(s).finish(),
        }
    }
}

/// Default AcroForm `/DA` per §12.7.3.3 — Helvetica 12pt black.
const DEFAULT_DA: &str = "/Helv 12 Tf 0 g";

// Same /Contents budget as the round-30 sig writer.
const CONTENTS_HEX_LEN: usize = 8192;

/// Width-stable maximum value for each `/ByteRange` slot. 8 digits =
/// 99,999,999 — any PDF under ~100 MB fits. All four slots use this
/// same value at placeholder time so the serialised `/ByteRange
/// [N N N N]` array has a known byte width (4 * 8 + 3 spaces = 35
/// bytes between the `[` and `]`).
const BYTE_RANGE_SLOT_MAX: i64 = 99_999_999;
const BYTE_RANGE_SLOT_WIDTH: usize = 8;

/// Render a [`Scene`] with the supplied AcroForm fields attached
/// (ISO 32000-1 §12.7). When the slice contains a
/// [`FormField::Signature`], the round-30 byte-range placeholder
/// pattern is applied so the resulting bytes are a valid signed PDF.
///
/// Constraints:
///
/// * `scene` must be in pages mode (same contract as
///   [`crate::write_pdf_from_scene`]).
/// * At most one [`FormField::Signature`] per call. The byte-range
///   placeholder pattern of §12.8.1.1 has a single excluded range
///   `[b, c)`, so a multi-signature scheme would require multiple
///   incremental-update revisions — out of scope for round 31.
/// * Each field's `page_index` must be `< scene.pages.len()`.
pub fn write_pdf_with_form(scene: &Scene, form_fields: &[FormField]) -> Result<Vec<u8>, PdfError> {
    let pages = scene
        .pages
        .as_ref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            PdfError::other(
                "write_pdf_with_form: scene is not in pages mode (scene.pages is None or empty)",
            )
        })?;
    let n_pages = pages.len();

    let signature_count = form_fields
        .iter()
        .filter(|f| matches!(f, FormField::Signature(_)))
        .count();
    if signature_count > 1 {
        return Err(PdfError::other(
            "write_pdf_with_form: only one /FT /Sig field per call is supported (round 31)",
        ));
    }
    validate_pages(form_fields, n_pages)?;

    // Render every page's content stream + resources up front.
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

    // ---- Allocate ids ----------------------------------------------
    // Allocate one id per top-level field (terminal field for
    // single-widget types; aggregate field for radio groups). For
    // signature fields we also allocate the sig dict id.
    let mut top_field_ids: Vec<ObjectId> = Vec::with_capacity(form_fields.len());
    // Per top-field, the widget ids that should land in the matching
    // page's /Annots. For non-radio fields the field id IS the widget
    // (merged-field shape per §12.7.3.1).
    let mut widgets_per_page: Vec<Vec<ObjectId>> = (0..n_pages).map(|_| Vec::new()).collect();
    // Bookkeeping for the signature placeholder (only one allowed).
    let mut sig_field_idx: Option<usize> = None;
    let mut sig_dict_id: Option<ObjectId> = None;
    // Per-radio-group kid ids so we can wire /Kids after id allocation.
    let mut radio_kid_ids: Vec<Vec<ObjectId>> = Vec::with_capacity(form_fields.len());

    for (i, field) in form_fields.iter().enumerate() {
        let id = doc.allocate_id();
        top_field_ids.push(id);
        match field {
            FormField::Text(t) => {
                widgets_per_page[t.page_index].push(id);
                radio_kid_ids.push(Vec::new());
            }
            FormField::Checkbox(c) => {
                widgets_per_page[c.page_index].push(id);
                radio_kid_ids.push(Vec::new());
            }
            FormField::RadioGroup(r) => {
                let mut kids = Vec::with_capacity(r.options.len());
                for opt in &r.options {
                    let kid_id = doc.allocate_id();
                    kids.push(kid_id);
                    widgets_per_page[opt.page_index].push(kid_id);
                }
                radio_kid_ids.push(kids);
            }
            FormField::Choice(c) => {
                widgets_per_page[c.page_index].push(id);
                radio_kid_ids.push(Vec::new());
            }
            FormField::Signature(s) => {
                sig_field_idx = Some(i);
                let sdid = doc.allocate_id();
                sig_dict_id = Some(sdid);
                widgets_per_page[s.page_index].push(id);
                radio_kid_ids.push(Vec::new());
            }
        }
    }

    // ---- Emit each top-level field dict ----------------------------
    let mut contents_hex_offset_marker: Option<u32> = None;
    for (i, field) in form_fields.iter().enumerate() {
        let id = top_field_ids[i];
        match field {
            FormField::Text(t) => {
                let dict = build_text_field_dict(t);
                doc.add_object(id, Object::Dict(dict));
            }
            FormField::Checkbox(c) => {
                let dict = build_checkbox_dict(c);
                doc.add_object(id, Object::Dict(dict));
            }
            FormField::RadioGroup(r) => {
                let kid_ids = &radio_kid_ids[i];
                let aggregate = build_radio_aggregate_dict(r, id, kid_ids);
                doc.add_object(id, Object::Dict(aggregate));
                for (opt, kid_id) in r.options.iter().zip(kid_ids.iter()) {
                    let active = matches!(&r.value, Some(v) if v == &opt.export_value);
                    let kid = build_radio_kid_dict(opt, id, active);
                    doc.add_object(*kid_id, Object::Dict(kid));
                }
            }
            FormField::Choice(c) => {
                let dict = build_choice_field_dict(c);
                doc.add_object(id, Object::Dict(dict));
            }
            FormField::Signature(s) => {
                // The signature widget field. /V points at the sig dict.
                let dict = Dict::new()
                    .with("Type", Object::Name("Annot".into()))
                    .with("Subtype", Object::Name("Widget".into()))
                    .with("FT", Object::Name("Sig".into()))
                    .with("T", text_string(&s.name))
                    .with("Rect", rect_array(s.rect))
                    .with("F", Object::Integer(4))
                    .with(
                        "V",
                        Object::Reference(
                            sig_dict_id.expect("sig_dict_id allocated for signature field"),
                        ),
                    )
                    .with("P", Object::Reference(pages_build.page_ids[s.page_index]));
                doc.add_object(id, Object::Dict(dict));

                // Emit the sig dict with size-stable placeholders so the
                // serialiser yields the EXACT final byte layout: the
                // /Contents value is a HexString of CONTENTS_HEX_LEN/2
                // bytes (= CONTENTS_HEX_LEN hex chars + the `< >`
                // brackets), and /ByteRange is a literal-string
                // matching BYTE_RANGE_PLACEHOLDER. Both are
                // length-preserving overwrites after offsets are known.
                let contents_placeholder = vec![0u8; CONTENTS_HEX_LEN / 2];
                let signer_cert_hex = {
                    let cert_bytes = s
                        .identity
                        .cert_chain
                        .first()
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]);
                    cert_bytes.to_vec()
                };
                // We embed /ByteRange as a LiteralString carrying the
                // placeholder text. This lets the serialiser emit the
                // exact `(/ByteRange [...])` byte sequence with stable
                // length so we can locate + patch it in place.
                let sig_dict = Dict::new()
                    .with("Type", Object::Name("Sig".into()))
                    .with("Filter", Object::Name("Adobe.PPKLite".into()))
                    .with("SubFilter", Object::Name("adbe.pkcs7.detached".into()))
                    .with(
                        "ByteRange",
                        Object::Array(vec![
                            Object::Integer(BYTE_RANGE_SLOT_MAX),
                            Object::Integer(BYTE_RANGE_SLOT_MAX),
                            Object::Integer(BYTE_RANGE_SLOT_MAX),
                            Object::Integer(BYTE_RANGE_SLOT_MAX),
                        ]),
                    )
                    .with("Contents", Object::HexString(contents_placeholder))
                    .with("Cert", Object::HexString(signer_cert_hex));
                doc.add_object(sig_dict_id.unwrap(), Object::Dict(sig_dict));
                contents_hex_offset_marker = Some(sig_dict_id.unwrap().number);
            }
        }
    }

    // ---- AcroForm dict + Catalog patch -----------------------------
    let acroform_id = doc.allocate_id();
    let mut acroform_dict = Dict::new()
        .with(
            "Fields",
            Object::Array(
                top_field_ids
                    .iter()
                    .map(|id| Object::Reference(*id))
                    .collect(),
            ),
        )
        .with("DA", Object::LiteralString(DEFAULT_DA.as_bytes().to_vec()));
    // SigFlags 3 = SignaturesExist | AppendOnly when a signature is present.
    if sig_field_idx.is_some() {
        acroform_dict.set("SigFlags", Object::Integer(3));
    }
    // /NeedAppearances true makes most viewers regenerate /AP at open
    // time — keeps the writer from having to draw glyph-perfect
    // appearance streams for every text-field value.
    acroform_dict.set("NeedAppearances", Object::Bool(true));
    doc.add_object(acroform_id, Object::Dict(acroform_dict));

    // Patch catalog to point at /AcroForm.
    let catalog = doc
        .object_mut(pages_build.catalog_id)
        .ok_or_else(|| PdfError::other("write_pdf_with_form: catalog id missing"))?;
    if let Object::Dict(d) = catalog {
        d.set("AcroForm", Object::Reference(acroform_id));
    }

    // ---- Per-page /Annots arrays -----------------------------------
    for (page_idx, widgets) in widgets_per_page.iter().enumerate() {
        if widgets.is_empty() {
            continue;
        }
        let page_id = pages_build.page_ids[page_idx];
        let page_obj = doc
            .object_mut(page_id)
            .ok_or_else(|| PdfError::other("write_pdf_with_form: page id missing"))?;
        if let Object::Dict(d) = page_obj {
            d.set(
                "Annots",
                Object::Array(widgets.iter().map(|w| Object::Reference(*w)).collect()),
            );
        }
    }

    // ---- Serialise & (maybe) sign ----------------------------------
    if let Some(sig_idx) = sig_field_idx {
        // For the signature path, we serialise with a marker stream so
        // we can locate the sig dict's bytes, then overwrite that
        // region in-place with the hand-laid version carrying the
        // /ByteRange + /Contents placeholders. The /ByteRange is
        // computed once the surrounding bytes are stable.
        sign_path(
            &mut doc,
            form_fields,
            sig_idx,
            sig_dict_id.expect("sig dict id"),
            contents_hex_offset_marker,
        )
    } else {
        let mut out = Vec::with_capacity(4096);
        doc.write_to(&mut out)?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------
// Dict builders.
// ---------------------------------------------------------------------

fn rect_array(rect: [f32; 4]) -> Object {
    Object::Array(rect.iter().map(|v| Object::Real(*v as f64)).collect())
}

fn text_string(s: &str) -> Object {
    // PDF "text string" form per §7.9.2.2.1 — ASCII passes through as a
    // literal string; non-ASCII becomes UTF-16BE-with-BOM in a hex
    // string. Same logic as `crate::writer::outline_text_string`.
    if s.bytes().all(|b| b.is_ascii() && b != 0) {
        Object::LiteralString(s.as_bytes().to_vec())
    } else {
        let mut bytes = vec![0xFE, 0xFF];
        for cp in s.encode_utf16() {
            bytes.push((cp >> 8) as u8);
            bytes.push((cp & 0xFF) as u8);
        }
        Object::HexString(bytes)
    }
}

fn build_text_field_dict(t: &FormFieldText) -> Dict {
    let mut d = Dict::new()
        .with("Type", Object::Name("Annot".into()))
        .with("Subtype", Object::Name("Widget".into()))
        .with("FT", Object::Name("Tx".into()))
        .with("T", text_string(&t.name))
        .with("Rect", rect_array(t.rect))
        .with("F", Object::Integer(4)); // /F bit 3 = Print
    if let Some(v) = &t.value {
        d.set("V", text_string(v));
        d.set("DV", text_string(v));
    }
    if let Some(m) = t.max_length {
        d.set("MaxLen", Object::Integer(m as i64));
    }
    // Field flags: bit 13 (value 0x1000) = Multiline per Table 228.
    if t.multi_line {
        d.set("Ff", Object::Integer(0x1000));
    }
    d.set("Q", Object::Integer(t.justification.as_int()));
    let da = t.default_appearance.as_deref().unwrap_or(DEFAULT_DA);
    d.set("DA", Object::LiteralString(da.as_bytes().to_vec()));
    d
}

fn build_checkbox_dict(c: &FormFieldCheckbox) -> Dict {
    let mut d = Dict::new()
        .with("Type", Object::Name("Annot".into()))
        .with("Subtype", Object::Name("Widget".into()))
        .with("FT", Object::Name("Btn".into()))
        .with("T", text_string(&c.name))
        .with("Rect", rect_array(c.rect))
        .with("F", Object::Integer(4));
    if c.checked {
        d.set("V", Object::Name("Yes".into()));
        d.set("AS", Object::Name("Yes".into()));
        d.set("DV", Object::Name("Yes".into()));
    } else {
        d.set("V", Object::Name("Off".into()));
        d.set("AS", Object::Name("Off".into()));
        d.set("DV", Object::Name("Off".into()));
    }
    let da = c.default_appearance.as_deref().unwrap_or(DEFAULT_DA);
    d.set("DA", Object::LiteralString(da.as_bytes().to_vec()));
    // No /Ff bits set ⇒ checkbox (neither Pushbutton bit 17 nor Radio
    // bit 16 of Table 228).
    d
}

fn build_radio_aggregate_dict(
    r: &FormFieldRadioGroup,
    _self_id: ObjectId,
    kid_ids: &[ObjectId],
) -> Dict {
    // /Ff bits 16 (Radio = 0x8000) + 15 (NoToggleToOff = 0x4000) per
    // Table 228. We don't set bit 17 (Pushbutton) — that would conflict
    // with Radio.
    let ff: i64 = 0x8000 | 0x4000;
    let mut d = Dict::new()
        .with("FT", Object::Name("Btn".into()))
        .with("T", text_string(&r.name))
        .with("Ff", Object::Integer(ff))
        .with(
            "Kids",
            Object::Array(kid_ids.iter().map(|id| Object::Reference(*id)).collect()),
        );
    if let Some(v) = &r.value {
        d.set("V", Object::Name(v.clone()));
        d.set("DV", Object::Name(v.clone()));
    } else {
        d.set("V", Object::Name("Off".into()));
        d.set("DV", Object::Name("Off".into()));
    }
    d
}

fn build_radio_kid_dict(opt: &RadioOption, parent_id: ObjectId, active: bool) -> Dict {
    let mut d = Dict::new()
        .with("Type", Object::Name("Annot".into()))
        .with("Subtype", Object::Name("Widget".into()))
        .with("Parent", Object::Reference(parent_id))
        .with("Rect", rect_array(opt.rect))
        .with("F", Object::Integer(4));
    // Per §12.7.4.2.3 + Table 239, a radio kid's /AS is either /Off
    // or the export_value Name to indicate which option is "on".
    let as_name = if active {
        Object::Name(opt.export_value.clone())
    } else {
        Object::Name("Off".into())
    };
    d.set("AS", as_name);
    d
}

fn build_choice_field_dict(c: &FormFieldChoice) -> Dict {
    let mut d = Dict::new()
        .with("Type", Object::Name("Annot".into()))
        .with("Subtype", Object::Name("Widget".into()))
        .with("FT", Object::Name("Ch".into()))
        .with("T", text_string(&c.name))
        .with("Rect", rect_array(c.rect))
        .with("F", Object::Integer(4));
    // Option array — each entry is a single string per §12.7.4.4 Table 231.
    let opt_array: Vec<Object> = c.options.iter().map(|s| text_string(s)).collect();
    d.set("Opt", Object::Array(opt_array));
    if let Some(v) = &c.value {
        d.set("V", text_string(v));
        d.set("DV", text_string(v));
    }
    // /Ff bit 18 = Combo. List boxes are the default (no bit).
    if c.combo_box {
        d.set("Ff", Object::Integer(0x20000));
    }
    let da = c.default_appearance.as_deref().unwrap_or(DEFAULT_DA);
    d.set("DA", Object::LiteralString(da.as_bytes().to_vec()));
    d
}

fn validate_pages(form_fields: &[FormField], n_pages: usize) -> Result<(), PdfError> {
    for field in form_fields {
        match field {
            FormField::Text(t) => check_page(t.page_index, n_pages)?,
            FormField::Checkbox(c) => check_page(c.page_index, n_pages)?,
            FormField::Choice(c) => check_page(c.page_index, n_pages)?,
            FormField::Signature(s) => check_page(s.page_index, n_pages)?,
            FormField::RadioGroup(r) => {
                if r.options.is_empty() {
                    return Err(PdfError::other(
                        "write_pdf_with_form: radio group has no options",
                    ));
                }
                for opt in &r.options {
                    check_page(opt.page_index, n_pages)?;
                }
            }
        }
    }
    Ok(())
}

fn check_page(page_index: usize, n_pages: usize) -> Result<(), PdfError> {
    if page_index >= n_pages {
        Err(PdfError::other(format!(
            "write_pdf_with_form: form field page_index {page_index} \
             out of range (scene has {n_pages} page(s))",
        )))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Signature path — re-uses the round-30 byterange-placeholder pattern.
// ---------------------------------------------------------------------

fn sign_path(
    doc: &mut Document,
    form_fields: &[FormField],
    sig_idx: usize,
    sig_dict_id: ObjectId,
    _contents_hex_offset_marker: Option<u32>,
) -> Result<Vec<u8>, PdfError> {
    // Strategy: the sig dict has been emitted with size-stable
    // placeholders (HexString of CONTENTS_HEX_LEN/2 bytes → `<{HEX}>`
    // of CONTENTS_HEX_LEN+2 bytes; /ByteRange as
    // `[MAX MAX MAX MAX]` where MAX is BYTE_RANGE_SLOT_MAX padded to
    // BYTE_RANGE_SLOT_WIDTH digits). So we can serialise once, locate
    // both placeholders, and patch in place — no offset shifting.

    let mut out = Vec::with_capacity(4096);
    doc.write_to(&mut out)?;

    // Find the sig dict's serialised body.
    let id_prefix = format!("{} 0 obj\n", sig_dict_id.number);
    let obj_start = out
        .windows(id_prefix.len())
        .position(|w| w == id_prefix.as_bytes())
        .ok_or_else(|| PdfError::other("sign_path: sig dict missing in serialised PDF"))?;
    let body_start = obj_start + id_prefix.len();
    let endobj_off = find_subslice(&out[body_start..], b"\nendobj\n")
        .ok_or_else(|| PdfError::other("sign_path: endobj missing after sig dict"))?;
    let body_end = body_start + endobj_off;
    let body = &out[body_start..body_end];

    // Locate the `/Contents <…>` hex placeholder inside the sig dict.
    let contents_marker = b"/Contents <";
    let contents_in_body = find_subslice(body, contents_marker)
        .ok_or_else(|| PdfError::other("sign_path: /Contents <…> marker missing"))?;
    let contents_hex_start = body_start + contents_in_body + contents_marker.len();

    // Locate the `/ByteRange [...]` array inside the sig dict.
    let br_marker = b"/ByteRange [";
    let br_in_body = find_subslice(body, br_marker)
        .ok_or_else(|| PdfError::other("sign_path: /ByteRange marker missing"))?;
    let br_array_start = body_start + br_in_body + br_marker.len();
    // The array body is `<8>D <8>D <8>D <8>D` separated by single
    // spaces, terminated by `]`. The serialiser emits no leading
    // padding (Integer is `{}`); since all four start at
    // BYTE_RANGE_SLOT_MAX they are exactly BYTE_RANGE_SLOT_WIDTH
    // digits, so the array body byte length is
    // 4*W + 3 + 0 = 35 (no surrounding brackets — those are outside
    // br_array_start).
    let array_body_len = BYTE_RANGE_SLOT_WIDTH * 4 + 3;
    let br_array_end = br_array_start + array_body_len;
    // Sanity check — the byte right after must be `]`.
    if out.get(br_array_end) != Some(&b']') {
        return Err(PdfError::other(format!(
            "sign_path: /ByteRange array width drift (expected `]` at off {br_array_end})",
        )));
    }

    // Compute byte-range integers. The signed range is everything
    // EXCEPT the bytes between `<` and `>` of /Contents (per
    // §12.8.1.1).
    let a: i64 = 0;
    let b: i64 = contents_hex_start as i64;
    let c: i64 = (contents_hex_start + CONTENTS_HEX_LEN) as i64;
    let d: i64 = out.len() as i64 - c;

    // Each slot must fit BYTE_RANGE_SLOT_MAX digits.
    if a > BYTE_RANGE_SLOT_MAX
        || b > BYTE_RANGE_SLOT_MAX
        || c > BYTE_RANGE_SLOT_MAX
        || d > BYTE_RANGE_SLOT_MAX
    {
        return Err(PdfError::other(format!(
            "sign_path: PDF too large for /ByteRange slot width {BYTE_RANGE_SLOT_WIDTH} \
             (max value {BYTE_RANGE_SLOT_MAX})",
        )));
    }

    // Patch the four slots — each is exactly BYTE_RANGE_SLOT_WIDTH
    // digits, zero-padded.
    let formatted = format!(
        "{a:0w$} {b:0w$} {c:0w$} {d:0w$}",
        a = a,
        b = b,
        c = c,
        d = d,
        w = BYTE_RANGE_SLOT_WIDTH
    );
    if formatted.len() != array_body_len {
        return Err(PdfError::other(
            "sign_path: byte-range formatter width drift",
        ));
    }
    out[br_array_start..br_array_end].copy_from_slice(formatted.as_bytes());

    // Hash + sign.
    let (signer_ref, identity) = match &form_fields[sig_idx] {
        FormField::Signature(s) => (s.signer.as_ref(), &s.identity),
        _ => unreachable!(),
    };
    let signed_bytes = concat_byte_ranges(&out, [a, b, c, d])?;
    let content_hash = signer_ref.algorithm().hash().hash(&signed_bytes);
    let md_attr = crate::pubsec::verify::build_message_digest_attribute_der(&content_hash);
    let ct_attr =
        crate::sig::writer::build_content_type_attribute_der(&crate::pubsec::cms::OID_DATA);
    let attrs_body = crate::pubsec::verify::pack_signed_attrs_implicit(&[ct_attr, md_attr]);
    let tbs = crate::pubsec::verify::signed_attrs_to_be_signed(&attrs_body);
    let tbs_hash = signer_ref.algorithm().hash().hash(&tbs);
    let signature_bytes = signer_ref.sign(&tbs_hash)?;

    let cms_blob = crate::sig::pkcs7_wrap_signed_data(
        signer_ref.algorithm(),
        &identity.issuer_der,
        &identity.serial,
        &identity.cert_chain,
        Some(&attrs_body),
        &signature_bytes,
    );

    patch_contents(&mut out, contents_hex_start, &cms_blob)?;
    Ok(out)
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn patch_contents(
    pdf: &mut [u8],
    contents_hex_offset: usize,
    contents_der: &[u8],
) -> Result<(), PdfError> {
    let hex_len_needed = contents_der.len() * 2;
    if hex_len_needed > CONTENTS_HEX_LEN {
        return Err(PdfError::other(format!(
            "write_pdf_with_form: CMS blob {hex_len_needed} hex chars exceeds /Contents budget {CONTENTS_HEX_LEN}",
        )));
    }
    for (i, b) in contents_der.iter().enumerate() {
        let hi = (b >> 4) & 0x0F;
        let lo = b & 0x0F;
        pdf[contents_hex_offset + 2 * i] = hex_digit(hi);
        pdf[contents_hex_offset + 2 * i + 1] = hex_digit(lo);
    }
    for byte in pdf
        .iter_mut()
        .skip(contents_hex_offset + hex_len_needed)
        .take(CONTENTS_HEX_LEN - hex_len_needed)
    {
        *byte = b'0';
    }
    Ok(())
}

fn hex_digit(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'A' + (n - 10),
        _ => unreachable!(),
    }
}

fn concat_byte_ranges(pdf: &[u8], byte_range: [i64; 4]) -> Result<Vec<u8>, PdfError> {
    let [a, b, c, d] = byte_range;
    if a < 0 || b < 0 || c < 0 || d < 0 {
        return Err(PdfError::other("write_pdf_with_form: negative /ByteRange"));
    }
    let (a, b, c, d) = (a as usize, b as usize, c as usize, d as usize);
    if a + b > pdf.len() || c + d > pdf.len() {
        return Err(PdfError::other(
            "write_pdf_with_form: /ByteRange extends past file length",
        ));
    }
    let mut out = Vec::with_capacity(b + d);
    out.extend_from_slice(&pdf[a..a + b]);
    out.extend_from_slice(&pdf[c..c + d]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_da_is_helvetica_12pt_black() {
        // §12.7.3.3 default appearance.
        assert_eq!(DEFAULT_DA, "/Helv 12 Tf 0 g");
    }

    #[test]
    fn rect_array_emits_four_reals() {
        let o = rect_array([1.0, 2.0, 3.0, 4.0]);
        match o {
            Object::Array(a) => assert_eq!(a.len(), 4),
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn justification_int_values_match_table_222() {
        // Table 222 lists 0=left, 1=centre, 2=right.
        assert_eq!(FieldJustification::Left.as_int(), 0);
        assert_eq!(FieldJustification::Center.as_int(), 1);
        assert_eq!(FieldJustification::Right.as_int(), 2);
    }
}
