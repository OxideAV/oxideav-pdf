//! Round-95 — Optional Content (OCG / OCMD) reader (ISO 32000-1
//! §8.11 + §7.7.2 Table 28 catalog `/OCProperties`).
//!
//! PDFs declare visibility "layers" (called *Optional Content Groups*
//! in ISO 32000) the user can toggle on / off at view time — CAD
//! drawing layers, multi-language alternates, redaction overlays,
//! watermark-vs-content separations, ….  The catalog's
//! `/OCProperties` entry (§7.7.2 Table 28; required if any optional
//! content exists per §8.11.4.2) carries:
//!
//! * `/OCGs` — array of every OCG dictionary in the document
//!   (Table 100).
//! * `/D` — the document's *default* configuration dictionary
//!   (Table 101) — `BaseState` / `ON` / `OFF` / `Intent` / `Order` /
//!   `ListMode` / `RBGroups` / `Locked`.
//! * `/Configs` — optional array of alternate configurations.
//!
//! Each OCG (Table 98) carries `/Type /OCG`, `/Name`, optional
//! `/Intent` (`View` / `Design` / array of either), optional `/Usage`
//! dictionary (Tables 102–103 — language / zoom / print / view /
//! export / user / page-element filters).
//!
//! Membership dictionaries (OCMDs — Table 99) reference a *set* of
//! OCGs via `/OCGs` plus a `/P` visibility policy (`AllOn`, `AnyOn`,
//! `AnyOff`, `AllOff` — default `AnyOn`) or a `/VE` visibility
//! expression (`[ /And ocg1 ocg2 ]`, `[ /Or … ]`, `[ /Not ocg ]` —
//! recursively nested).
//!
//! [`DocumentReader::optional_content`] returns a [`OptionalContent`]
//! summary carrying every group, the resolved default configuration,
//! and the resolved on/off state per group after applying the
//! default config's `BaseState` + `ON` + `OFF` arrays per
//! §8.11.4.5. Callers that just want "is OCG N visible?" call
//! [`OptionalContent::is_visible`]; callers walking the Order tree
//! for a UI use [`OptionalContent::groups`] + the config's
//! [`OcConfig::order`] list.
//!
//! Alternate configurations (the `/Configs` array) are surfaced
//! alongside the default for completeness (e.g. CAD packages that
//! ship an "engineering" and a "presentation" configuration in the
//! same PDF). Callers can re-resolve states by passing one of these
//! to [`OptionalContent::states_for_config`].
//!
//! Walker is best-effort — malformed entries are skipped silently
//! to match the round-26 annotation reader's contract; an unparseable
//! `/OCProperties` itself surfaces as `Ok(None)` rather than an
//! error so callers can branch cleanly on "this PDF has no optional
//! content".

use std::collections::HashMap;

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::reader::document::DocumentReader;

/// Visibility policy for an Optional Content Membership Dictionary
/// (`/P` entry of an OCMD, ISO 32000-1 §8.11.2.2 Table 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcVisibilityPolicy {
    /// Visible only if all referenced OCGs are ON.
    AllOn,
    /// Visible if any referenced OCG is ON. The Table 99 default.
    AnyOn,
    /// Visible if any referenced OCG is OFF.
    AnyOff,
    /// Visible only if all referenced OCGs are OFF.
    AllOff,
}

impl OcVisibilityPolicy {
    /// Resolve the `/P` name into a policy. Unknown names fall back to
    /// the Table 99 default (`AnyOn`).
    pub fn from_name(name: &str) -> Self {
        match name {
            "AllOn" => OcVisibilityPolicy::AllOn,
            "AnyOff" => OcVisibilityPolicy::AnyOff,
            "AllOff" => OcVisibilityPolicy::AllOff,
            _ => OcVisibilityPolicy::AnyOn,
        }
    }
}

/// `/BaseState` value of a configuration dictionary (Table 101).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OcBaseState {
    /// All groups initially ON. Table 101 default.
    #[default]
    On,
    /// All groups initially OFF.
    Off,
    /// Groups keep their prior state (only valid in non-default
    /// configurations per Table 101's "If BaseState is present in the
    /// document's default configuration dictionary, its value shall
    /// be ON" footnote).
    Unchanged,
}

impl OcBaseState {
    fn from_name(name: &str) -> Self {
        match name {
            "OFF" => OcBaseState::Off,
            "Unchanged" => OcBaseState::Unchanged,
            // ISO 32000-1 §8.11.4.3 Table 101: default is ON.
            _ => OcBaseState::On,
        }
    }
}

/// One Optional Content Group (ISO 32000-1 §8.11.2 Table 98).
///
/// Surfaced verbatim from the document — the `state` slot on this
/// struct is *not* filled in by [`optional_content`]; resolved states
/// live in [`OptionalContent::states`] keyed by group id (the
/// `/OCProperties /OCGs` array is the source of truth for "which
/// objects are OCGs", which lets callers cross-walk against e.g.
/// content-stream `/OC /OCx BDC` resource names).
#[derive(Debug, Clone)]
pub struct OptionalContentGroup {
    /// Indirect object id — the OCG dict's `(n 0 obj)` number. Used
    /// by content streams + OCMDs to refer to the group.
    pub id: ObjectId,
    /// `/Name` — UI label. PDF text string (literal or hex with
    /// optional UTF-16BE BOM).
    pub name: String,
    /// `/Intent` — `View` / `Design` / both. Empty array on input
    /// surfaces as an empty vec (per §8.11.2.3 "If the configuration's
    /// Intent is an empty array, no groups shall be used in determining
    /// visibility").
    pub intents: Vec<String>,
    /// `/Usage` subkeys (Table 102). The most-used ones get typed
    /// slots; everything else stays in the raw dict.
    pub usage: Option<OcUsage>,
}

/// Selected `/Usage` subkeys decoded from Table 102 — the categories
/// usage-application dictionaries (Table 103) consult for `View` /
/// `Print` / `Export` state derivation.
#[derive(Debug, Clone, Default)]
pub struct OcUsage {
    /// `/Language /Lang` (§8.11.4.4 — IETF BCP 47 language tag, e.g.
    /// `en-US`, `fr`, `es-MX`).
    pub language: Option<String>,
    /// `/Language /Preferred` — `ON` / `OFF` for partial matches.
    pub language_preferred: Option<bool>,
    /// `/Zoom /min` — minimum zoom factor at which the group is ON
    /// (default 0.0 per Table 102).
    pub zoom_min: Option<f64>,
    /// `/Zoom /max` — maximum zoom factor at which the group is ON
    /// (default +inf per Table 102; we surface `None` rather than a
    /// floating-point sentinel).
    pub zoom_max: Option<f64>,
    /// `/Print /Subtype` — `Trapping`, `PrintersMarks`, `Watermark`,
    /// ….
    pub print_subtype: Option<String>,
    /// `/Print /PrintState` — `ON` / `OFF`.
    pub print_state: Option<bool>,
    /// `/View /ViewState` — `ON` / `OFF`.
    pub view_state: Option<bool>,
    /// `/Export /ExportState` — `ON` / `OFF`.
    pub export_state: Option<bool>,
    /// `/PageElement /Subtype` — `HF`, `FG`, `BG`, `L`.
    pub page_element_subtype: Option<String>,
}

/// One Optional Content Configuration Dictionary (Table 101).
///
/// The catalog's `/OCProperties /D` is one of these; alternate
/// configurations in `/OCProperties /Configs` are also surfaced
/// using this same shape.
#[derive(Debug, Clone, Default)]
pub struct OcConfig {
    /// `/Name` — display name for this configuration.
    pub name: Option<String>,
    /// `/Creator` — application that created this configuration.
    pub creator: Option<String>,
    /// `/BaseState` — initial state ON / OFF / Unchanged.
    pub base_state: OcBaseState,
    /// `/ON` — group ids whose state shall be ON after BaseState is
    /// applied (overrides BaseState=OFF for these).
    pub on: Vec<ObjectId>,
    /// `/OFF` — group ids whose state shall be OFF after BaseState is
    /// applied (overrides BaseState=ON for these).
    pub off: Vec<ObjectId>,
    /// `/Intent` — names this configuration's state filter recognises
    /// (default `[View]`; empty `[]` ⇒ no groups participate).
    pub intents: Vec<String>,
    /// `/Order` — UI tree for "Layers"-style listings (Table 101).
    /// `OcOrderItem::Group(id)` for individual groups,
    /// `OcOrderItem::Subtree { label, items }` for nested
    /// collections (with an optional first-element text label).
    pub order: Vec<OcOrderItem>,
    /// `/ListMode` — `AllPages` (default) or `VisiblePages`.
    pub list_mode: OcListMode,
    /// `/RBGroups` — radio-button group sets (each inner array is a
    /// mutually-exclusive set; turning one on turns the others off).
    pub rb_groups: Vec<Vec<ObjectId>>,
    /// `/Locked` — group ids the UI shall not let the user toggle.
    pub locked: Vec<ObjectId>,
}

/// `/ListMode` of a configuration (Table 101).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OcListMode {
    /// `AllPages` — display every group in `Order`. Table 101 default.
    #[default]
    AllPages,
    /// `VisiblePages` — only display groups referenced by visible pages.
    VisiblePages,
}

/// One node in a configuration's `/Order` array (Table 101).
#[derive(Debug, Clone)]
pub enum OcOrderItem {
    /// A leaf OCG reference — the group appears as a toggleable item
    /// at this position in the UI tree.
    Group(ObjectId),
    /// A nested subtree. PDFs use this two ways:
    ///
    /// * **Labelled collection** — first element is a text string
    ///   acting as a non-selectable group heading; remaining elements
    ///   are nested order items.
    /// * **Sublayer nesting** — no leading string; the items
    ///   represent a sub-layer of the immediately-preceding group.
    Subtree {
        /// Group label (text string at the start of the nested array)
        /// or `None` for the sublayer-nesting form.
        label: Option<String>,
        /// Nested items.
        items: Vec<OcOrderItem>,
    },
}

/// Full optional-content picture for a document.
///
/// Returned by [`DocumentReader::optional_content`].
#[derive(Debug, Clone)]
pub struct OptionalContent {
    /// Every OCG in the document, in `/OCProperties /OCGs` order.
    pub groups: Vec<OptionalContentGroup>,
    /// The catalog's `/OCProperties /D` configuration (always
    /// present per §8.11.4.2 when `/OCProperties` itself is).
    pub default_config: OcConfig,
    /// Alternate configurations from `/OCProperties /Configs`.
    pub alternate_configs: Vec<OcConfig>,
    /// Resolved state per group, after applying the default
    /// configuration's `BaseState` / `ON` / `OFF` (§8.11.4.5
    /// algorithm). `true` ⇒ ON, `false` ⇒ OFF.
    pub states: HashMap<ObjectId, bool>,
}

impl OptionalContent {
    /// Is this OCG visible under the default configuration? Returns
    /// `false` for unknown ids (a content stream referencing an OCG
    /// that isn't in `/OCProperties /OCGs` is malformed; treat as
    /// hidden).
    pub fn is_visible(&self, group: ObjectId) -> bool {
        self.states.get(&group).copied().unwrap_or(false)
    }

    /// Re-resolve states under an alternate configuration. Useful when
    /// a PDF carries multiple `/Configs` (e.g. an engineering vs.
    /// presentation layer setup) and the caller wants to switch.
    pub fn states_for_config(&self, config: &OcConfig) -> HashMap<ObjectId, bool> {
        resolve_states(&self.groups, config)
    }

    /// Evaluate an OCMD's visibility under the current default
    /// configuration states. Surfaces the `AllOn` / `AnyOn` / `AllOff` /
    /// `AnyOff` policy or the `/VE` visibility expression.
    ///
    /// Returns `true` when no groups are referenced (per §8.11.2.2
    /// "If this entry is not present, is an empty array, or contains
    /// references only to null or deleted objects, the membership
    /// dictionary shall have no effect on the visibility of any
    /// content").
    pub fn evaluate_membership(&self, mem: &OcMembership) -> bool {
        evaluate_membership_with_states(mem, &self.states)
    }
}

/// One OCMD parsed from an `/OC` / `/Properties` slot.
///
/// Membership dicts attach to content via `BDC /OC /Name` operators
/// (the `/OC` *tag* + a name from the page resources' `/Properties`
/// dict) or via form / image XObject and annotation `/OC` entries.
#[derive(Debug, Clone)]
pub struct OcMembership {
    /// `/OCGs` — group references this membership composes.
    pub groups: Vec<ObjectId>,
    /// `/P` — simple boolean policy. `None` ⇒ `AnyOn` per Table 99,
    /// or `/VE` was used and policy is irrelevant.
    pub policy: OcVisibilityPolicy,
    /// `/VE` — visibility expression. When `Some`, takes precedence
    /// over `policy` per §8.11.2.2 NOTE 2.
    pub visibility_expression: Option<OcVisibilityExpression>,
}

/// Visibility expression (`/VE`, ISO 32000-1 §8.11.2.2 — PDF 1.6).
///
/// Three operator forms per §8.11.2.2:
///
/// * `[ /And  e1 e2 … ]` — visible iff every sub-expression is true.
/// * `[ /Or   e1 e2 … ]` — visible iff any sub-expression is true.
/// * `[ /Not  e        ]` — visible iff `e` is false (exactly one
///   subexpression).
///
/// Leaves are OCG references; `ON` = `true`, `OFF` = `false`.
#[derive(Debug, Clone)]
pub enum OcVisibilityExpression {
    And(Vec<OcVisibilityExpression>),
    Or(Vec<OcVisibilityExpression>),
    Not(Box<OcVisibilityExpression>),
    /// Reference to an OCG (leaf).
    Group(ObjectId),
}

/// Parse the catalog `/OCProperties` entry into a structured
/// [`OptionalContent`]. Returns `Ok(None)` when the catalog has no
/// `/OCProperties` (the common case — most PDFs are not layered).
pub fn optional_content(
    reader: &mut DocumentReader<'_>,
) -> Result<Option<OptionalContent>, PdfError> {
    let root_id = reader.xref().root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog_dict) = catalog else {
        return Err(PdfError::other(format!(
            "PDF OCG reader: /Root must be a dict (got {catalog:?})"
        )));
    };
    let ocp_obj = catalog_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "OCProperties")
        .map(|(_, v)| v.clone());
    let Some(ocp_obj) = ocp_obj else {
        return Ok(None);
    };
    let ocp_dict = match reader.deref(ocp_obj)? {
        Object::Dict(d) => d,
        // Malformed /OCProperties — treat as "no optional content".
        _ => return Ok(None),
    };

    // /OCGs — the array of every group in the document.
    let ocgs_array = ocp_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "OCGs")
        .map(|(_, v)| v.clone());
    let Some(ocgs_array) = ocgs_array else {
        return Ok(None);
    };
    let ocgs_array = reader.deref(ocgs_array)?;
    let Object::Array(group_refs) = ocgs_array else {
        return Ok(None);
    };

    let mut groups: Vec<OptionalContentGroup> = Vec::with_capacity(group_refs.len());
    for item in group_refs {
        let Object::Reference(id) = item else {
            continue;
        };
        let group_obj = match reader.resolve(id) {
            Ok(o) => o,
            Err(_) => continue,
        };
        let Object::Dict(group_dict) = group_obj else {
            continue;
        };
        // Best-effort: skip dicts that aren't /Type /OCG.
        let kind = dict_name(&group_dict, "Type");
        if let Some(k) = kind.as_deref() {
            if k != "OCG" {
                continue;
            }
        }
        let name = dict_text(&group_dict, "Name").unwrap_or_default();
        let intents = decode_intent_array(reader, &group_dict)?;
        let usage = decode_usage(reader, &group_dict)?;
        groups.push(OptionalContentGroup {
            id,
            name,
            intents,
            usage,
        });
    }

    // /D — default configuration. Required per Table 100 but treat
    // missing as an empty default so we don't refuse partially-formed
    // PDFs.
    let default_config = match ocp_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "D")
        .map(|(_, v)| v.clone())
    {
        Some(o) => decode_config(reader, o)?.unwrap_or_default(),
        None => OcConfig::default(),
    };

    // /Configs — optional alternates.
    let mut alternate_configs: Vec<OcConfig> = Vec::new();
    if let Some(arr) = ocp_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Configs")
        .map(|(_, v)| v.clone())
    {
        let arr = reader.deref(arr)?;
        if let Object::Array(items) = arr {
            for it in items {
                if let Some(c) = decode_config(reader, it)? {
                    alternate_configs.push(c);
                }
            }
        }
    }

    let states = resolve_states(&groups, &default_config);

    Ok(Some(OptionalContent {
        groups,
        default_config,
        alternate_configs,
        states,
    }))
}

/// Parse one Optional Content Membership Dictionary (Table 99). Accepts
/// the dict directly — callers walking content streams or annotation
/// dictionaries pull the `/OC` slot and dispatch to this helper.
///
/// Returns `None` when the supplied dict isn't a valid OCMD (wrong
/// `/Type`, no `/OCGs` / `/VE`, etc.) — best-effort matching the
/// rest of the reader's contract.
pub fn parse_membership(
    reader: &mut DocumentReader<'_>,
    dict: &Dict,
) -> Result<Option<OcMembership>, PdfError> {
    let kind = dict_name(dict, "Type");
    if let Some(k) = kind.as_deref() {
        if k != "OCMD" {
            return Ok(None);
        }
    }
    let mut groups: Vec<ObjectId> = Vec::new();
    if let Some(o) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "OCGs")
        .map(|(_, v)| v.clone())
    {
        let o = reader.deref(o)?;
        collect_group_refs(reader, o, &mut groups)?;
    }
    let policy = dict_name(dict, "P")
        .map(|s| OcVisibilityPolicy::from_name(&s))
        .unwrap_or(OcVisibilityPolicy::AnyOn);

    // /VE — PDF 1.6+ visibility expression. Takes precedence.
    let mut visibility_expression: Option<OcVisibilityExpression> = None;
    if let Some(ve) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "VE")
        .map(|(_, v)| v.clone())
    {
        let ve = reader.deref(ve)?;
        if let Object::Array(items) = ve {
            visibility_expression = parse_visibility_expression(reader, &items, 0)?;
        }
    }
    Ok(Some(OcMembership {
        groups,
        policy,
        visibility_expression,
    }))
}

// ── internals ─────────────────────────────────────────────────────────

/// Apply the §8.11.4.5 state-resolution algorithm to a config:
///
/// (a) BaseState applies to every group.
/// (b) `/ON` array sets ON over the top of BaseState=OFF / Unchanged.
/// (c) `/OFF` array sets OFF over the top of BaseState=ON / Unchanged.
///
/// `Unchanged` is treated as ON for our purposes when applied to the
/// default configuration (Table 101 mandates BaseState=ON for the
/// default config; we apply that constraint here rather than at parse
/// time so an alternate-config caller still sees `Unchanged`).
fn resolve_states(groups: &[OptionalContentGroup], config: &OcConfig) -> HashMap<ObjectId, bool> {
    let mut states: HashMap<ObjectId, bool> = HashMap::with_capacity(groups.len());
    let base = match config.base_state {
        OcBaseState::On => true,
        OcBaseState::Off => false,
        // Unchanged in an alternate config = leave groups at the prior
        // state. Without a prior state we have to pick something; we
        // default to ON (the document's default for the spec's hidden
        // "this is what the doc was last in" assumption).
        OcBaseState::Unchanged => true,
    };
    for g in groups {
        states.insert(g.id, base);
    }
    for id in &config.on {
        if let Some(s) = states.get_mut(id) {
            *s = true;
        } else {
            states.insert(*id, true);
        }
    }
    for id in &config.off {
        if let Some(s) = states.get_mut(id) {
            *s = false;
        } else {
            states.insert(*id, false);
        }
    }
    states
}

/// Decode one configuration dictionary (Table 101). Accepts either an
/// inline Dict object or a Reference to one.
fn decode_config(
    reader: &mut DocumentReader<'_>,
    obj: Object,
) -> Result<Option<OcConfig>, PdfError> {
    let dict = match reader.deref(obj)? {
        Object::Dict(d) => d,
        _ => return Ok(None),
    };
    let mut cfg = OcConfig {
        name: dict_text(&dict, "Name"),
        creator: dict_text(&dict, "Creator"),
        base_state: dict_name(&dict, "BaseState")
            .map(|s| OcBaseState::from_name(&s))
            .unwrap_or(OcBaseState::On),
        ..OcConfig::default()
    };

    if let Some(o) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "ON")
        .map(|(_, v)| v.clone())
    {
        let o = reader.deref(o)?;
        collect_group_refs(reader, o, &mut cfg.on)?;
    }
    if let Some(o) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "OFF")
        .map(|(_, v)| v.clone())
    {
        let o = reader.deref(o)?;
        collect_group_refs(reader, o, &mut cfg.off)?;
    }
    cfg.intents = decode_intent_array(reader, &dict)?;
    if cfg.intents.is_empty() {
        // §8.11.2.3: default is [/View] for the default configuration.
        cfg.intents.push("View".to_owned());
    }

    if let Some(o) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Order")
        .map(|(_, v)| v.clone())
    {
        let o = reader.deref(o)?;
        if let Object::Array(items) = o {
            cfg.order = decode_order_items(reader, &items, 0)?;
        }
    }

    cfg.list_mode = match dict_name(&dict, "ListMode").as_deref() {
        Some("VisiblePages") => OcListMode::VisiblePages,
        _ => OcListMode::AllPages,
    };

    if let Some(o) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "RBGroups")
        .map(|(_, v)| v.clone())
    {
        let o = reader.deref(o)?;
        if let Object::Array(outer) = o {
            for inner in outer {
                let inner = reader.deref(inner)?;
                if let Object::Array(ids) = inner {
                    let mut group = Vec::with_capacity(ids.len());
                    for it in ids {
                        if let Object::Reference(id) = it {
                            group.push(id);
                        }
                    }
                    if !group.is_empty() {
                        cfg.rb_groups.push(group);
                    }
                }
            }
        }
    }

    if let Some(o) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Locked")
        .map(|(_, v)| v.clone())
    {
        let o = reader.deref(o)?;
        collect_group_refs(reader, o, &mut cfg.locked)?;
    }

    Ok(Some(cfg))
}

/// Decode an `/Intent` entry (Table 98 + Table 101). The spec allows
/// either a single Name or an array of Names; we normalise to a Vec.
fn decode_intent_array(
    reader: &mut DocumentReader<'_>,
    dict: &Dict,
) -> Result<Vec<String>, PdfError> {
    let Some(o) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Intent")
        .map(|(_, v)| v.clone())
    else {
        return Ok(Vec::new());
    };
    let o = reader.deref(o)?;
    Ok(match o {
        Object::Name(s) => vec![s],
        Object::Array(items) => items
            .into_iter()
            .filter_map(|it| match it {
                Object::Name(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    })
}

/// Decode an OCG's `/Usage` subdictionary (Table 102).
fn decode_usage(
    reader: &mut DocumentReader<'_>,
    group_dict: &Dict,
) -> Result<Option<OcUsage>, PdfError> {
    let Some(o) = group_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Usage")
        .map(|(_, v)| v.clone())
    else {
        return Ok(None);
    };
    let usage_dict = match reader.deref(o)? {
        Object::Dict(d) => d,
        _ => return Ok(None),
    };
    let mut out = OcUsage::default();
    // /Language { /Lang text, /Preferred /ON|/OFF }
    if let Some(o) = usage_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Language")
        .map(|(_, v)| v.clone())
    {
        if let Object::Dict(d) = reader.deref(o)? {
            out.language = dict_text(&d, "Lang");
            out.language_preferred = dict_name(&d, "Preferred").map(|n| n == "ON");
        }
    }
    // /Zoom { /min n, /max n }
    if let Some(o) = usage_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Zoom")
        .map(|(_, v)| v.clone())
    {
        if let Object::Dict(d) = reader.deref(o)? {
            out.zoom_min = d
                .entries()
                .iter()
                .find(|(k, _)| k == "min")
                .and_then(|(_, v)| number_to_f64(v));
            out.zoom_max = d
                .entries()
                .iter()
                .find(|(k, _)| k == "max")
                .and_then(|(_, v)| number_to_f64(v));
        }
    }
    // /Print { /Subtype, /PrintState }
    if let Some(o) = usage_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Print")
        .map(|(_, v)| v.clone())
    {
        if let Object::Dict(d) = reader.deref(o)? {
            out.print_subtype = dict_name(&d, "Subtype");
            out.print_state = dict_name(&d, "PrintState").map(|n| n == "ON");
        }
    }
    // /View { /ViewState }
    if let Some(o) = usage_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "View")
        .map(|(_, v)| v.clone())
    {
        if let Object::Dict(d) = reader.deref(o)? {
            out.view_state = dict_name(&d, "ViewState").map(|n| n == "ON");
        }
    }
    // /Export { /ExportState }
    if let Some(o) = usage_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Export")
        .map(|(_, v)| v.clone())
    {
        if let Object::Dict(d) = reader.deref(o)? {
            out.export_state = dict_name(&d, "ExportState").map(|n| n == "ON");
        }
    }
    // /PageElement { /Subtype HF|FG|BG|L }
    if let Some(o) = usage_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "PageElement")
        .map(|(_, v)| v.clone())
    {
        if let Object::Dict(d) = reader.deref(o)? {
            out.page_element_subtype = dict_name(&d, "Subtype");
        }
    }
    Ok(Some(out))
}

/// Decode the configuration `/Order` array (Table 101). Items may be
/// OCG references or nested arrays.
///
/// The `_reader` parameter is unused at the moment — the spec only
/// requires references / arrays / strings here, all of which are
/// direct values in the array. Kept on the signature so a future
/// extension that resolves intermediate references (a malformed
/// producer could theoretically point at an array via a reference)
/// has a place to hook in without churn.
#[allow(clippy::only_used_in_recursion)]
fn decode_order_items(
    reader: &mut DocumentReader<'_>,
    items: &[Object],
    depth: usize,
) -> Result<Vec<OcOrderItem>, PdfError> {
    // §8.11.4.3's Order array forms a tree — bound the recursion so a
    // malformed PDF can't OOM us.
    if depth > 32 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match it.clone() {
            Object::Reference(id) => out.push(OcOrderItem::Group(id)),
            Object::Array(nested) => {
                // First element may be a label string per Table 101.
                let mut iter = nested.into_iter();
                let mut label: Option<String> = None;
                let mut sub_items: Vec<Object> = Vec::new();
                let first = iter.next();
                match first {
                    Some(Object::LiteralString(b)) | Some(Object::HexString(b)) => {
                        label = Some(decode_text_string(&b));
                        sub_items.extend(iter);
                    }
                    Some(other) => {
                        sub_items.push(other);
                        sub_items.extend(iter);
                    }
                    None => {}
                }
                let sub = decode_order_items(reader, &sub_items, depth + 1)?;
                out.push(OcOrderItem::Subtree { label, items: sub });
            }
            _ => {} // Skip non-ref / non-array entries.
        }
    }
    Ok(out)
}

/// Decode a `/VE` visibility expression array per §8.11.2.2:
///
/// ```text
/// [ /And  e1 e2 …  ]
/// [ /Or   e1 e2 …  ]
/// [ /Not  e        ]
/// ```
///
/// Returns `Ok(None)` for malformed arrays (best-effort).
fn parse_visibility_expression(
    reader: &mut DocumentReader<'_>,
    items: &[Object],
    depth: usize,
) -> Result<Option<OcVisibilityExpression>, PdfError> {
    if depth > 32 || items.is_empty() {
        return Ok(None);
    }
    let op = match &items[0] {
        Object::Name(s) => s.as_str(),
        _ => return Ok(None),
    };
    let mut subs: Vec<OcVisibilityExpression> = Vec::new();
    for it in &items[1..] {
        let resolved = reader.deref(it.clone())?;
        match resolved {
            Object::Reference(id) => subs.push(OcVisibilityExpression::Group(id)),
            Object::Array(inner) => {
                if let Some(e) = parse_visibility_expression(reader, &inner, depth + 1)? {
                    subs.push(e);
                }
            }
            // A direct OCG dict in the VE position is unusual but the
            // spec doesn't forbid it; track the host id via the dict's
            // /Type check.
            _ => {} // Skip atypical leaves.
        }
    }
    match op {
        "And" => Ok(Some(OcVisibilityExpression::And(subs))),
        "Or" => Ok(Some(OcVisibilityExpression::Or(subs))),
        "Not" => {
            // §8.11.2.2: "If the first element is Not, it shall have
            // only one subsequent element."  We're lenient — take the
            // first one.
            if let Some(first) = subs.into_iter().next() {
                Ok(Some(OcVisibilityExpression::Not(Box::new(first))))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

/// Evaluate a membership dict against a state map. Visibility
/// expressions override the simple policy per §8.11.2.2 NOTE 2.
fn evaluate_membership_with_states(mem: &OcMembership, states: &HashMap<ObjectId, bool>) -> bool {
    if let Some(ve) = &mem.visibility_expression {
        return evaluate_visibility_expression(ve, states);
    }
    // §8.11.2.2: if OCGs is empty / null / all-deleted, the
    // membership dict has no effect (visible).
    if mem.groups.is_empty() {
        return true;
    }
    match mem.policy {
        OcVisibilityPolicy::AllOn => mem
            .groups
            .iter()
            .all(|id| states.get(id).copied().unwrap_or(false)),
        OcVisibilityPolicy::AnyOn => mem
            .groups
            .iter()
            .any(|id| states.get(id).copied().unwrap_or(false)),
        OcVisibilityPolicy::AllOff => mem
            .groups
            .iter()
            .all(|id| !states.get(id).copied().unwrap_or(false)),
        OcVisibilityPolicy::AnyOff => mem
            .groups
            .iter()
            .any(|id| !states.get(id).copied().unwrap_or(false)),
    }
}

fn evaluate_visibility_expression(
    expr: &OcVisibilityExpression,
    states: &HashMap<ObjectId, bool>,
) -> bool {
    match expr {
        OcVisibilityExpression::And(subs) => subs
            .iter()
            .all(|e| evaluate_visibility_expression(e, states)),
        OcVisibilityExpression::Or(subs) => subs
            .iter()
            .any(|e| evaluate_visibility_expression(e, states)),
        OcVisibilityExpression::Not(inner) => !evaluate_visibility_expression(inner, states),
        OcVisibilityExpression::Group(id) => states.get(id).copied().unwrap_or(false),
    }
}

/// Pull every `Object::Reference` out of `obj` (which may be a single
/// reference or an array of references) and append to `out`.
///
/// The caller is expected to have already `reader.deref`-ed the outer
/// object — but the *items* inside the array must be left as references
/// rather than dereferenced (otherwise we'd resolve each reference to
/// the OCG dict itself and lose the indirect-object id we need to
/// cross-reference the global `/OCGs` list).
fn collect_group_refs(
    _reader: &mut DocumentReader<'_>,
    obj: Object,
    out: &mut Vec<ObjectId>,
) -> Result<(), PdfError> {
    match obj {
        Object::Reference(id) => out.push(id),
        Object::Array(items) => {
            for it in items {
                if let Object::Reference(id) = it {
                    out.push(id);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Decode a PDF text-string entry — literal or hex; UTF-16BE-with-BOM
/// recognised. Mirrors the existing reader-side text decoder.
fn dict_text(d: &Dict, key: &str) -> Option<String> {
    d.entries()
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            Object::LiteralString(b) | Object::HexString(b) => Some(decode_text_string(b)),
            Object::Name(s) => Some(s.clone()),
            _ => None,
        })
}

fn decode_text_string(b: &[u8]) -> String {
    if b.len() >= 2 && b[0] == 0xFE && b[1] == 0xFF {
        let utf16: Vec<u16> = b[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&utf16)
    } else {
        String::from_utf8_lossy(b).into_owned()
    }
}

fn dict_name(d: &Dict, key: &str) -> Option<String> {
    d.entries()
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            Object::Name(s) => Some(s.clone()),
            _ => None,
        })
}

fn number_to_f64(o: &Object) -> Option<f64> {
    match o {
        Object::Integer(n) => Some(*n as f64),
        Object::Real(f) => Some(*f),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::ObjectId;
    use std::collections::HashMap;

    fn id(n: u32) -> ObjectId {
        ObjectId::new(n)
    }

    fn make_states(pairs: &[(u32, bool)]) -> HashMap<ObjectId, bool> {
        let mut m = HashMap::new();
        for (n, s) in pairs {
            m.insert(id(*n), *s);
        }
        m
    }

    #[test]
    fn visibility_policy_from_name_defaults_anyon() {
        assert_eq!(
            OcVisibilityPolicy::from_name("garbage"),
            OcVisibilityPolicy::AnyOn
        );
        assert_eq!(OcVisibilityPolicy::from_name(""), OcVisibilityPolicy::AnyOn);
    }

    #[test]
    fn visibility_policy_recognises_all_four_names() {
        assert_eq!(
            OcVisibilityPolicy::from_name("AllOn"),
            OcVisibilityPolicy::AllOn
        );
        assert_eq!(
            OcVisibilityPolicy::from_name("AnyOn"),
            OcVisibilityPolicy::AnyOn
        );
        assert_eq!(
            OcVisibilityPolicy::from_name("AnyOff"),
            OcVisibilityPolicy::AnyOff
        );
        assert_eq!(
            OcVisibilityPolicy::from_name("AllOff"),
            OcVisibilityPolicy::AllOff
        );
    }

    #[test]
    fn base_state_defaults_to_on() {
        assert!(matches!(OcBaseState::from_name("garbage"), OcBaseState::On));
        assert!(matches!(OcBaseState::from_name("ON"), OcBaseState::On));
        assert!(matches!(OcBaseState::from_name("OFF"), OcBaseState::Off));
        assert!(matches!(
            OcBaseState::from_name("Unchanged"),
            OcBaseState::Unchanged
        ));
    }

    #[test]
    fn resolve_states_basestate_on_sets_all_on() {
        let groups = vec![
            OptionalContentGroup {
                id: id(10),
                name: "L1".into(),
                intents: vec!["View".into()],
                usage: None,
            },
            OptionalContentGroup {
                id: id(11),
                name: "L2".into(),
                intents: vec!["View".into()],
                usage: None,
            },
        ];
        let cfg = OcConfig {
            base_state: OcBaseState::On,
            ..OcConfig::default()
        };
        let s = resolve_states(&groups, &cfg);
        assert_eq!(s.get(&id(10)), Some(&true));
        assert_eq!(s.get(&id(11)), Some(&true));
    }

    #[test]
    fn resolve_states_basestate_off_sets_all_off() {
        let groups = vec![OptionalContentGroup {
            id: id(10),
            name: "L1".into(),
            intents: vec!["View".into()],
            usage: None,
        }];
        let cfg = OcConfig {
            base_state: OcBaseState::Off,
            ..OcConfig::default()
        };
        let s = resolve_states(&groups, &cfg);
        assert_eq!(s.get(&id(10)), Some(&false));
    }

    #[test]
    fn resolve_states_on_overrides_off_basestate() {
        let groups = vec![
            OptionalContentGroup {
                id: id(10),
                name: "L1".into(),
                intents: vec![],
                usage: None,
            },
            OptionalContentGroup {
                id: id(11),
                name: "L2".into(),
                intents: vec![],
                usage: None,
            },
            OptionalContentGroup {
                id: id(12),
                name: "L3".into(),
                intents: vec![],
                usage: None,
            },
        ];
        let cfg = OcConfig {
            base_state: OcBaseState::Off,
            on: vec![id(11)],
            ..OcConfig::default()
        };
        let s = resolve_states(&groups, &cfg);
        assert_eq!(s.get(&id(10)), Some(&false));
        assert_eq!(s.get(&id(11)), Some(&true));
        assert_eq!(s.get(&id(12)), Some(&false));
    }

    #[test]
    fn resolve_states_off_overrides_on_basestate() {
        let groups = vec![
            OptionalContentGroup {
                id: id(10),
                name: "L1".into(),
                intents: vec![],
                usage: None,
            },
            OptionalContentGroup {
                id: id(11),
                name: "L2".into(),
                intents: vec![],
                usage: None,
            },
        ];
        let cfg = OcConfig {
            base_state: OcBaseState::On,
            off: vec![id(10)],
            ..OcConfig::default()
        };
        let s = resolve_states(&groups, &cfg);
        assert_eq!(s.get(&id(10)), Some(&false));
        assert_eq!(s.get(&id(11)), Some(&true));
    }

    #[test]
    fn evaluate_membership_all_on() {
        let states = make_states(&[(10, true), (11, true), (12, false)]);
        let mem = OcMembership {
            groups: vec![id(10), id(11)],
            policy: OcVisibilityPolicy::AllOn,
            visibility_expression: None,
        };
        assert!(evaluate_membership_with_states(&mem, &states));
        let mem_with_off = OcMembership {
            groups: vec![id(10), id(12)],
            policy: OcVisibilityPolicy::AllOn,
            visibility_expression: None,
        };
        assert!(!evaluate_membership_with_states(&mem_with_off, &states));
    }

    #[test]
    fn evaluate_membership_any_on() {
        let states = make_states(&[(10, false), (11, false), (12, true)]);
        let mem = OcMembership {
            groups: vec![id(10), id(11)],
            policy: OcVisibilityPolicy::AnyOn,
            visibility_expression: None,
        };
        assert!(!evaluate_membership_with_states(&mem, &states));
        let mem_with_on = OcMembership {
            groups: vec![id(10), id(12)],
            policy: OcVisibilityPolicy::AnyOn,
            visibility_expression: None,
        };
        assert!(evaluate_membership_with_states(&mem_with_on, &states));
    }

    #[test]
    fn evaluate_membership_all_off() {
        let states = make_states(&[(10, false), (11, false), (12, true)]);
        let mem = OcMembership {
            groups: vec![id(10), id(11)],
            policy: OcVisibilityPolicy::AllOff,
            visibility_expression: None,
        };
        assert!(evaluate_membership_with_states(&mem, &states));
        let mem_with_on = OcMembership {
            groups: vec![id(10), id(12)],
            policy: OcVisibilityPolicy::AllOff,
            visibility_expression: None,
        };
        assert!(!evaluate_membership_with_states(&mem_with_on, &states));
    }

    #[test]
    fn evaluate_membership_any_off() {
        let states = make_states(&[(10, true), (11, true), (12, false)]);
        let mem = OcMembership {
            groups: vec![id(10), id(11)],
            policy: OcVisibilityPolicy::AnyOff,
            visibility_expression: None,
        };
        assert!(!evaluate_membership_with_states(&mem, &states));
        let mem_with_off = OcMembership {
            groups: vec![id(10), id(12)],
            policy: OcVisibilityPolicy::AnyOff,
            visibility_expression: None,
        };
        assert!(evaluate_membership_with_states(&mem_with_off, &states));
    }

    #[test]
    fn evaluate_membership_empty_groups_visible() {
        let states = make_states(&[]);
        let mem = OcMembership {
            groups: vec![],
            policy: OcVisibilityPolicy::AllOn,
            visibility_expression: None,
        };
        assert!(evaluate_membership_with_states(&mem, &states));
    }

    #[test]
    fn evaluate_visibility_expression_simple_and() {
        let states = make_states(&[(10, true), (11, true), (12, false)]);
        let ve = OcVisibilityExpression::And(vec![
            OcVisibilityExpression::Group(id(10)),
            OcVisibilityExpression::Group(id(11)),
        ]);
        assert!(evaluate_visibility_expression(&ve, &states));

        let ve_fail = OcVisibilityExpression::And(vec![
            OcVisibilityExpression::Group(id(10)),
            OcVisibilityExpression::Group(id(12)),
        ]);
        assert!(!evaluate_visibility_expression(&ve_fail, &states));
    }

    #[test]
    fn evaluate_visibility_expression_simple_or() {
        let states = make_states(&[(10, false), (11, true), (12, false)]);
        let ve = OcVisibilityExpression::Or(vec![
            OcVisibilityExpression::Group(id(10)),
            OcVisibilityExpression::Group(id(11)),
        ]);
        assert!(evaluate_visibility_expression(&ve, &states));

        let ve_fail = OcVisibilityExpression::Or(vec![
            OcVisibilityExpression::Group(id(10)),
            OcVisibilityExpression::Group(id(12)),
        ]);
        assert!(!evaluate_visibility_expression(&ve_fail, &states));
    }

    #[test]
    fn evaluate_visibility_expression_not() {
        let states = make_states(&[(10, true)]);
        let ve = OcVisibilityExpression::Not(Box::new(OcVisibilityExpression::Group(id(10))));
        assert!(!evaluate_visibility_expression(&ve, &states));
        let ve_inv = OcVisibilityExpression::Not(Box::new(OcVisibilityExpression::Group(id(11))));
        assert!(evaluate_visibility_expression(&ve_inv, &states));
    }

    #[test]
    fn evaluate_visibility_expression_nested() {
        // §8.11.2.2 EXAMPLE 3: "(OCG 1) OR (NOT OCG 2) OR (OCG 3 AND OCG 4 AND OCG 5)"
        let states = make_states(&[
            (1, false),
            (2, true), // NOT OCG 2 = false
            (3, true),
            (4, true),
            (5, true), // AND chain = true
        ]);
        let ve = OcVisibilityExpression::Or(vec![
            OcVisibilityExpression::Group(id(1)),
            OcVisibilityExpression::Not(Box::new(OcVisibilityExpression::Group(id(2)))),
            OcVisibilityExpression::And(vec![
                OcVisibilityExpression::Group(id(3)),
                OcVisibilityExpression::Group(id(4)),
                OcVisibilityExpression::Group(id(5)),
            ]),
        ]);
        // The AND-chain branch is true so the whole Or evaluates true.
        assert!(evaluate_visibility_expression(&ve, &states));
    }

    #[test]
    fn unknown_group_id_treated_as_off() {
        let states = make_states(&[]);
        let mem = OcMembership {
            groups: vec![id(99)],
            policy: OcVisibilityPolicy::AllOn,
            visibility_expression: None,
        };
        assert!(!evaluate_membership_with_states(&mem, &states));
    }
}
