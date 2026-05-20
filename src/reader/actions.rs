//! Round-36 — PDF action reader (ISO 32000-1 §12.6).
//!
//! Walks every place an action can hide in a PDF — Catalog
//! `/OpenAction` + `/AA` (additional actions, §12.6.3 Table 198),
//! per-page `/AA`, per-annotation `/A` + `/AA`, per-form-field
//! `/A` + `/AA`, plus the document-level `/Names /JavaScript` name
//! tree (§7.7.4 Table 31 + §12.6.4.16) — and surfaces each as a
//! [`PdfAction`] with the trigger event, the action's location in the
//! document, and a typed [`ActionKind`] payload covering Table 198's
//! 18 action types (`GoTo`, `GoToR`, `GoToE`, `Launch`, `Thread`,
//! `URI`, `Sound`, `Movie`, `Hide`, `Named`, `SubmitForm`,
//! `ResetForm`, `ImportData`, `JavaScript`, `SetOCGState`,
//! `Rendition`, `Trans`, `GoTo3DView`).
//!
//! Why this surface matters: PDFs in the wild can trigger
//! JavaScript on open (`/OpenAction`), navigate to a remote file
//! (`/GoToR`), launch a binary (`/Launch`), or submit a form to a
//! URL (`/SubmitForm`) — all interesting from a forensic / sandbox
//! / archival audit perspective. The round-25 link reader and the
//! round-26 annotation reader each cover one slice; this round
//! unifies them into a single audit walk so a caller asking "what
//! can this PDF *do*?" gets one comprehensive answer rather than
//! seven scattered ones.
//!
//! Per Table 198 trigger semantics: `/Next` chained actions inside
//! an action dict are followed recursively (the spec lets an
//! action carry `/Next` pointing at another action or array of
//! actions), with a depth bound that stops at 32 to defeat malformed
//! cycles. The carrier action and each chained-`/Next` action both
//! surface as their own [`PdfAction`] entries so callers see the
//! full execution trace.
//!
//! Filter coverage in round 36: every action *type* Table 198
//! defines, every trigger event Tables 196 + 197 + 199 define for
//! the catalog / page / annotation / form-field origins.
//! Type-specific payloads decode the high-signal entries — for
//! `/JS` actions the script text is recovered (literal-string or
//! stream form per §12.6.4.16); for `/URI` actions the URI text;
//! for `/Launch` the target filename; for `/GoToR` / `/GoToE` the
//! file specification + destination; for `/SubmitForm` the URL +
//! `/Flags` bitfield; for `/Hide` the target annotation list;
//! for `/Named` the predefined name; for `/SetOCGState` the on /
//! off / toggle arrays; the rest surface as
//! [`ActionKind::Other`] with the raw `/S` name preserved.
//!
//! Provenance: ISO 32000-1:2008 §7.7.4 (Catalog), §7.7.6 (Pages
//! Tree), §7.9.6 (Name Trees), §12.5.6 (Annotations), §12.6.2
//! (Trigger events), §12.6.3 (Action dictionaries), §12.6.4.x
//! (Action types). No third-party PDF library or reference was
//! consulted.

use std::collections::HashSet;

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::reader::document::DocumentReader;
use crate::reader::outline::build_page_index_map;

/// One action surfaced by [`actions`].
///
/// `trigger` records *where* the action lives — Catalog open, a
/// specific page event, an annotation event, a form-field event, or
/// a name-tree entry — and `kind` records *what* the action does.
#[derive(Debug, Clone)]
pub struct PdfAction {
    /// Where in the document this action lives.
    pub trigger: ActionTrigger,
    /// What the action does (Table 198 action type + decoded payload).
    pub kind: ActionKind,
    /// Chain depth — 0 for the action that lives at `trigger`, 1 for
    /// the first `/Next`, 2 for the next, etc. Per §12.6.3, an action
    /// may carry `/Next` to chain further actions on the same trigger.
    pub chain_depth: u32,
}

/// Where in the document an action is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionTrigger {
    /// `Catalog /OpenAction` — fired when the document is opened
    /// (§7.7.2 Table 28 + §12.6.4 Table 198).
    CatalogOpen,
    /// `Catalog /AA` additional actions per §12.6.3 Table 197 —
    /// `WC` (will-close), `WS` (will-save), `DS` (did-save),
    /// `WP` (will-print), `DP` (did-print).
    Catalog {
        /// Trigger-event key from Table 197 (`WC` / `WS` / `DS` /
        /// `WP` / `DP`).
        event: String,
    },
    /// `Page /AA` additional actions per §12.6.3 Table 196 —
    /// `O` (page open) / `C` (page close).
    Page {
        /// 0-based page index in DFS order.
        page_index: usize,
        /// Trigger-event key from Table 196 (`O` / `C`).
        event: String,
    },
    /// Annotation action — either the primary `/A` action or an
    /// `/AA` entry per §12.5.3 Table 165 (`E` / `X` / `D` / `U` /
    /// `Fo` / `Bl` / `PO` / `PC` / `PV` / `PI`).
    Annotation {
        page_index: usize,
        /// `Subtype` of the carrier annotation (`Link`, `Widget`,
        /// …) — surfaced verbatim.
        subtype: String,
        /// `"A"` for the primary action, or the Table-165 trigger
        /// key (`E` / `X` / `D` / `U` / `Fo` / `Bl` / `PO` / `PC` /
        /// `PV` / `PI`).
        event: String,
    },
    /// Form-field action — `/A` action or `/AA` (Table 196)
    /// `K` (keystroke) / `F` (format) / `V` (validate) / `C`
    /// (calculate) entry on a form-field dict.
    FormField {
        /// `/T` (partial field name) of the carrying field, when
        /// present. Field names are PDFDocEncoded text strings.
        field_name: Option<String>,
        /// `"A"` for the primary action, or the Table-196 trigger
        /// key (`K` / `F` / `V` / `C`).
        event: String,
    },
    /// `Catalog /Names /JavaScript` name-tree entry per §7.7.4
    /// Table 31. The `name` is the name-tree key — typically the
    /// JavaScript function name a `/Named` action can invoke.
    NamedJavaScript {
        /// Name-tree key (script identifier).
        name: String,
    },
}

/// Typed action payload — Table 198's 18 action types.
#[derive(Debug, Clone)]
pub enum ActionKind {
    /// `/S /GoTo` — in-document jump (§12.6.4.2 Table 199). `/D` is
    /// either an explicit `[page-ref mode args …]` array (caller
    /// can re-decode via [`crate::reader::link`]) or a named
    /// destination (Name / string).
    GoTo {
        /// 0-based page index when the `/D` array was explicit and
        /// the page-ref resolved cleanly.
        page_index: Option<usize>,
        /// Raw `/D` value — Name, byte-string, or explicit-array
        /// debug form — preserved for callers that need the
        /// untouched destination.
        raw_dest: Option<String>,
    },
    /// `/S /GoToR` — remote go-to (§12.6.4.3 Table 200).
    /// `/F` is the [Filespec](crate::reader::attachments) — surfaced
    /// as its `/UF`/`/F` filename string.
    GoToR {
        /// Remote file path / URI from the file specification.
        file: Option<String>,
        /// `/NewWindow` flag.
        new_window: Option<bool>,
        /// Raw `/D` destination (same shape as [`Self::GoTo`]'s
        /// `raw_dest`).
        raw_dest: Option<String>,
    },
    /// `/S /GoToE` — embedded go-to (PDF 1.6 — §12.6.4.4 Table 201).
    /// Refers to an embedded file (`/T` target dict chain).
    GoToE {
        /// External file specification (`/F`), when present.
        file: Option<String>,
        /// Raw `/D` destination.
        raw_dest: Option<String>,
    },
    /// `/S /Launch` — launch external app or open external file
    /// (§12.6.4.5 Table 202).
    Launch {
        /// `/F` filename for the file to launch.
        file: Option<String>,
        /// `/NewWindow` flag.
        new_window: Option<bool>,
    },
    /// `/S /Thread` — go-to-article-thread (§12.6.4.6).
    Thread,
    /// `/S /URI` — open a URL (§12.6.4.7 Table 206). `/URI` is the
    /// ASCII-encoded URI; `/IsMap` marks form-coordinate posting.
    Uri {
        /// `/URI` string.
        uri: String,
        /// `/IsMap` flag.
        is_map: bool,
    },
    /// `/S /Sound` — play a sound (§12.6.4.8 Table 207).
    Sound,
    /// `/S /Movie` — play a movie (§12.6.4.9 Table 208). Legacy
    /// (replaced by Rendition in PDF 1.5).
    Movie,
    /// `/S /Hide` — show / hide annotations (§12.6.4.10 Table 209).
    Hide {
        /// `/H` flag — true means hide (the default), false means
        /// show.
        hide: bool,
        /// `/T` target annotations (annotation names or refs).
        /// Surfaced as the raw string form for arrays / names.
        target: Option<String>,
    },
    /// `/S /Named` — invoke a predefined action by name
    /// (§12.6.4.11 Table 211).
    Named {
        /// `/N` — name of the predefined action
        /// (`NextPage`, `PrevPage`, `FirstPage`, `LastPage`, plus
        /// authoring-tool / viewer extensions).
        name: String,
    },
    /// `/S /SubmitForm` — submit form data to a URL
    /// (§12.7.5.2 Table 236).
    SubmitForm {
        /// `/F` URL the submission posts to.
        url: Option<String>,
        /// `/Flags` — Table 237 bit flags. Bit 1 = Include/Exclude,
        /// 2 = IncludeNoValueFields, 3 = ExportFormat, 4 =
        /// GetMethod, 5 = SubmitCoordinates, 6 = XFDF, …
        flags: u32,
    },
    /// `/S /ResetForm` — reset form-field values (§12.7.5.3 Table 239).
    ResetForm {
        /// `/Flags` bit 1 = Exclude (otherwise Include).
        flags: u32,
    },
    /// `/S /ImportData` — import form data from a file
    /// (§12.7.5.4 Table 240).
    ImportData {
        /// `/F` source filename.
        file: Option<String>,
    },
    /// `/S /JavaScript` — execute JavaScript (§12.6.4.16 Table 217).
    /// `/JS` is either a literal-string or a stream of UTF-8 / UTF-16
    /// JavaScript source — round-36 recovers it to a String through
    /// the same PDFDocEncoding / UTF-16BE-BOM lossy decoder the rest
    /// of the reader uses.
    JavaScript {
        /// JavaScript source text.
        script: String,
    },
    /// `/S /SetOCGState` — toggle optional-content groups
    /// (§12.6.4.12 Table 212). The state array is preserved as
    /// the count of On/Off/Toggle entries.
    SetOcgState {
        /// Number of `/ON` entries in the state array.
        on_count: usize,
        /// Number of `/OFF` entries in the state array.
        off_count: usize,
        /// Number of `/Toggle` entries in the state array.
        toggle_count: usize,
    },
    /// `/S /Rendition` — multimedia rendition (§12.6.4.13 Table 213).
    /// PDF 1.5 — replaces the legacy Movie / Sound types.
    Rendition,
    /// `/S /Trans` — slide-show transition (§12.6.4.14).
    Trans,
    /// `/S /GoTo3DView` — change 3D camera view (§12.6.4.15 Table 215).
    GoTo3DView,
    /// `/S` value the round didn't decode — name surfaced verbatim.
    Other {
        /// Raw `/S` action-type name.
        kind: String,
    },
}

/// Walk every action source in the document and surface each as a
/// [`PdfAction`].
///
/// Sources walked (in this order):
/// 1. Catalog `/OpenAction` (single action or array of actions).
/// 2. Catalog `/AA` (Table 197 — `WC`/`WS`/`DS`/`WP`/`DP`).
/// 3. Per-page `/AA` (Table 196 — `O`/`C`).
/// 4. Per-annotation `/A` and `/AA` (Table 165 — `E`/`X`/`D`/`U`/
///    `Fo`/`Bl`/`PO`/`PC`/`PV`/`PI`).
/// 5. Form-field `/A` and `/AA` walked through the `/AcroForm /Fields`
///    tree (Table 220).
/// 6. Catalog `/Names /JavaScript` name tree (Table 31 + §7.9.6).
///
/// Each action's `/Next` chain is followed recursively up to a depth
/// of 32 hops; the carrier and every chained-`/Next` action surface
/// as their own [`PdfAction`] with progressively-higher `chain_depth`.
pub fn actions(reader: &mut DocumentReader<'_>) -> Result<Vec<PdfAction>, PdfError> {
    let page_index_map = build_page_index_map(reader)?;
    let mut pages_by_index: Vec<ObjectId> = Vec::with_capacity(page_index_map.len());
    pages_by_index.resize(page_index_map.len(), ObjectId::new(0));
    for (n, idx) in &page_index_map {
        pages_by_index[*idx] = ObjectId::new(*n);
    }

    let mut out = Vec::new();
    let mut visited: HashSet<ObjectId> = HashSet::new();

    // ---- 1+2: Catalog OpenAction + AA ----
    let root_id = reader.xref().root()?;
    let catalog = reader.resolve(root_id)?;
    if let Object::Dict(catalog) = &catalog {
        // /OpenAction may be an action dict OR a destination array.
        // Only the action-dict form lands here; the destination-array
        // form is purely a navigation target with no action object.
        if let Some(open) = catalog
            .entries()
            .iter()
            .find(|(k, _)| k == "OpenAction")
            .map(|(_, v)| v.clone())
        {
            let open = reader.deref(open)?;
            if let Object::Dict(a) = open {
                expand_action_chain(
                    reader,
                    &a,
                    ActionTrigger::CatalogOpen,
                    0,
                    &mut visited,
                    &mut out,
                )?;
            }
            // (Destination-array form: not an action — silently skip.)
        }

        if let Some(aa) = catalog
            .entries()
            .iter()
            .find(|(k, _)| k == "AA")
            .map(|(_, v)| v.clone())
        {
            let aa = reader.deref(aa)?;
            if let Object::Dict(aa) = aa {
                for (event, val) in aa.entries() {
                    let val = reader.deref(val.clone())?;
                    if let Object::Dict(a) = val {
                        expand_action_chain(
                            reader,
                            &a,
                            ActionTrigger::Catalog {
                                event: event.clone(),
                            },
                            0,
                            &mut visited,
                            &mut out,
                        )?;
                    }
                }
            }
        }
    }

    // ---- 3: Per-page /AA ----
    for (page_index, page_id) in pages_by_index.iter().enumerate() {
        if page_id.number == 0 {
            continue;
        }
        let page = match reader.resolve(*page_id)? {
            Object::Dict(d) => d,
            _ => continue,
        };
        let aa_obj = page
            .entries()
            .iter()
            .find(|(k, _)| k == "AA")
            .map(|(_, v)| v.clone());
        if let Some(aa) = aa_obj {
            let aa = reader.deref(aa)?;
            if let Object::Dict(aa) = aa {
                for (event, val) in aa.entries() {
                    let val = reader.deref(val.clone())?;
                    if let Object::Dict(a) = val {
                        expand_action_chain(
                            reader,
                            &a,
                            ActionTrigger::Page {
                                page_index,
                                event: event.clone(),
                            },
                            0,
                            &mut visited,
                            &mut out,
                        )?;
                    }
                }
            }
        }
    }

    // ---- 4: Per-annotation /A + /AA ----
    for (page_index, page_id) in pages_by_index.iter().enumerate() {
        if page_id.number == 0 {
            continue;
        }
        let page = match reader.resolve(*page_id)? {
            Object::Dict(d) => d,
            _ => continue,
        };
        let annots_obj = page
            .entries()
            .iter()
            .find(|(k, _)| k == "Annots")
            .map(|(_, v)| v.clone());
        let Some(annots_obj) = annots_obj else {
            continue;
        };
        let annots_obj = reader.deref(annots_obj)?;
        let Object::Array(items) = annots_obj else {
            continue;
        };
        for item in items {
            let annot = match reader.deref(item)? {
                Object::Dict(d) => d,
                _ => continue,
            };
            let subtype = annot
                .entries()
                .iter()
                .find(|(k, _)| k == "Subtype")
                .and_then(|(_, v)| match v {
                    Object::Name(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            collect_a_and_aa(
                reader,
                &annot,
                |event| ActionTrigger::Annotation {
                    page_index,
                    subtype: subtype.clone(),
                    event,
                },
                &mut visited,
                &mut out,
            )?;
        }
    }

    // ---- 5: Form fields /A + /AA via /AcroForm /Fields ----
    if let Object::Dict(catalog) = &catalog {
        let acro_obj = catalog
            .entries()
            .iter()
            .find(|(k, _)| k == "AcroForm")
            .map(|(_, v)| v.clone());
        if let Some(acro_obj) = acro_obj {
            let acro = reader.deref(acro_obj)?;
            if let Object::Dict(acro) = acro {
                let fields_obj = acro
                    .entries()
                    .iter()
                    .find(|(k, _)| k == "Fields")
                    .map(|(_, v)| v.clone());
                if let Some(fields_obj) = fields_obj {
                    let fields = reader.deref(fields_obj)?;
                    if let Object::Array(items) = fields {
                        let mut depth = 0u32;
                        for field in items {
                            walk_form_field(reader, field, &mut out, &mut visited, &mut depth)?;
                        }
                    }
                }
            }
        }
    }

    // ---- 6: Catalog /Names /JavaScript name tree ----
    if let Object::Dict(catalog) = &catalog {
        let names_obj = catalog
            .entries()
            .iter()
            .find(|(k, _)| k == "Names")
            .map(|(_, v)| v.clone());
        if let Some(names_obj) = names_obj {
            let names = reader.deref(names_obj)?;
            if let Object::Dict(names) = names {
                let js_obj = names
                    .entries()
                    .iter()
                    .find(|(k, _)| k == "JavaScript")
                    .map(|(_, v)| v.clone());
                if let Some(js_obj) = js_obj {
                    let js = reader.deref(js_obj)?;
                    if let Object::Dict(root) = js {
                        let mut pairs: Vec<(String, Object)> = Vec::new();
                        walk_name_tree(reader, &root, &mut pairs, 0)?;
                        for (key, val) in pairs {
                            let val = reader.deref(val)?;
                            if let Object::Dict(a) = val {
                                expand_action_chain(
                                    reader,
                                    &a,
                                    ActionTrigger::NamedJavaScript { name: key },
                                    0,
                                    &mut visited,
                                    &mut out,
                                )?;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(out)
}

/// Walk a single form-field subtree, surfacing this field's `/A` +
/// `/AA` actions and recursing through `/Kids`.
fn walk_form_field(
    reader: &mut DocumentReader<'_>,
    field_obj: Object,
    out: &mut Vec<PdfAction>,
    visited: &mut HashSet<ObjectId>,
    depth: &mut u32,
) -> Result<(), PdfError> {
    if *depth > 32 {
        return Ok(());
    }
    *depth += 1;
    let dict = match reader.deref(field_obj)? {
        Object::Dict(d) => d,
        _ => {
            *depth -= 1;
            return Ok(());
        }
    };
    let field_name = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "T")
        .and_then(|(_, v)| decode_text_obj(v));
    collect_a_and_aa(
        reader,
        &dict,
        |event| ActionTrigger::FormField {
            field_name: field_name.clone(),
            event,
        },
        visited,
        out,
    )?;
    if let Some(kids_obj) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Kids")
        .map(|(_, v)| v.clone())
    {
        let kids = reader.deref(kids_obj)?;
        if let Object::Array(items) = kids {
            for kid in items {
                walk_form_field(reader, kid, out, visited, depth)?;
            }
        }
    }
    *depth -= 1;
    Ok(())
}

/// Collect the `/A` primary action and every `/AA` trigger-event
/// entry from `dict`, expanding each action's `/Next` chain.
fn collect_a_and_aa<F>(
    reader: &mut DocumentReader<'_>,
    dict: &Dict,
    make_trigger: F,
    visited: &mut HashSet<ObjectId>,
    out: &mut Vec<PdfAction>,
) -> Result<(), PdfError>
where
    F: Fn(String) -> ActionTrigger,
{
    if let Some(a) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "A")
        .map(|(_, v)| v.clone())
    {
        let a = reader.deref(a)?;
        if let Object::Dict(a) = a {
            expand_action_chain(reader, &a, make_trigger("A".into()), 0, visited, out)?;
        }
    }
    if let Some(aa) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "AA")
        .map(|(_, v)| v.clone())
    {
        let aa = reader.deref(aa)?;
        if let Object::Dict(aa) = aa {
            for (event, val) in aa.entries() {
                let val = reader.deref(val.clone())?;
                if let Object::Dict(a) = val {
                    expand_action_chain(reader, &a, make_trigger(event.clone()), 0, visited, out)?;
                }
            }
        }
    }
    Ok(())
}

/// Decode one action dict + follow its `/Next` chain (§12.6.3).
///
/// `/Next` may be a single dict, a reference to one, or an array
/// of dicts / references. The chain depth is bounded at 32 hops and
/// `visited` deduplicates indirect-object visits so malformed cycles
/// can't blow the stack.
fn expand_action_chain(
    reader: &mut DocumentReader<'_>,
    action: &Dict,
    trigger: ActionTrigger,
    chain_depth: u32,
    visited: &mut HashSet<ObjectId>,
    out: &mut Vec<PdfAction>,
) -> Result<(), PdfError> {
    if chain_depth > 32 {
        return Ok(());
    }
    let kind = decode_action_kind(reader, action)?;
    out.push(PdfAction {
        trigger: trigger.clone(),
        kind,
        chain_depth,
    });
    // Follow /Next chain. Per Table 198, /Next may be a single
    // action dict or an array of action dicts. Indirect references
    // through `visited` get deduplicated to break cycles.
    if let Some(next) = action
        .entries()
        .iter()
        .find(|(k, _)| k == "Next")
        .map(|(_, v)| v.clone())
    {
        process_next(reader, next, &trigger, chain_depth + 1, visited, out)?;
    }
    Ok(())
}

fn process_next(
    reader: &mut DocumentReader<'_>,
    next_obj: Object,
    trigger: &ActionTrigger,
    chain_depth: u32,
    visited: &mut HashSet<ObjectId>,
    out: &mut Vec<PdfAction>,
) -> Result<(), PdfError> {
    match next_obj {
        Object::Reference(id) => {
            if !visited.insert(id) {
                return Ok(()); // cycle
            }
            let resolved = reader.resolve(id)?;
            process_next(reader, resolved, trigger, chain_depth, visited, out)?;
        }
        Object::Array(items) => {
            for it in items {
                process_next(reader, it, trigger, chain_depth, visited, out)?;
            }
        }
        Object::Dict(a) => {
            expand_action_chain(reader, &a, trigger.clone(), chain_depth, visited, out)?;
        }
        _ => {}
    }
    Ok(())
}

/// Decode one action's `/S` type and per-type payload.
fn decode_action_kind(
    reader: &mut DocumentReader<'_>,
    action: &Dict,
) -> Result<ActionKind, PdfError> {
    let s = action
        .entries()
        .iter()
        .find(|(k, _)| k == "S")
        .and_then(|(_, v)| match v {
            Object::Name(s) => Some(s.as_str()),
            _ => None,
        })
        .unwrap_or("");

    match s {
        "GoTo" => {
            let (page_index, raw_dest) = decode_dest_entry(reader, action, "D")?;
            Ok(ActionKind::GoTo {
                page_index,
                raw_dest,
            })
        }
        "GoToR" => {
            let file = decode_filespec_entry(reader, action, "F")?;
            let new_window = action
                .entries()
                .iter()
                .find(|(k, _)| k == "NewWindow")
                .and_then(|(_, v)| match v {
                    Object::Bool(b) => Some(*b),
                    _ => None,
                });
            let (_, raw_dest) = decode_dest_entry(reader, action, "D")?;
            Ok(ActionKind::GoToR {
                file,
                new_window,
                raw_dest,
            })
        }
        "GoToE" => {
            let file = decode_filespec_entry(reader, action, "F")?;
            let (_, raw_dest) = decode_dest_entry(reader, action, "D")?;
            Ok(ActionKind::GoToE { file, raw_dest })
        }
        "Launch" => {
            let file = decode_filespec_entry(reader, action, "F")?;
            let new_window = action
                .entries()
                .iter()
                .find(|(k, _)| k == "NewWindow")
                .and_then(|(_, v)| match v {
                    Object::Bool(b) => Some(*b),
                    _ => None,
                });
            Ok(ActionKind::Launch { file, new_window })
        }
        "Thread" => Ok(ActionKind::Thread),
        "URI" => {
            let uri = action
                .entries()
                .iter()
                .find(|(k, _)| k == "URI")
                .and_then(|(_, v)| match v {
                    Object::LiteralString(b) | Object::HexString(b) => {
                        Some(String::from_utf8_lossy(b).into_owned())
                    }
                    _ => None,
                })
                .unwrap_or_default();
            let is_map = action
                .entries()
                .iter()
                .find(|(k, _)| k == "IsMap")
                .and_then(|(_, v)| match v {
                    Object::Bool(b) => Some(*b),
                    _ => None,
                })
                .unwrap_or(false);
            Ok(ActionKind::Uri { uri, is_map })
        }
        "Sound" => Ok(ActionKind::Sound),
        "Movie" => Ok(ActionKind::Movie),
        "Hide" => {
            let hide = action
                .entries()
                .iter()
                .find(|(k, _)| k == "H")
                .and_then(|(_, v)| match v {
                    Object::Bool(b) => Some(*b),
                    _ => None,
                })
                .unwrap_or(true);
            let target = action
                .entries()
                .iter()
                .find(|(k, _)| k == "T")
                .and_then(|(_, v)| decode_t_target(v));
            Ok(ActionKind::Hide { hide, target })
        }
        "Named" => {
            let name = action
                .entries()
                .iter()
                .find(|(k, _)| k == "N")
                .and_then(|(_, v)| match v {
                    Object::Name(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            Ok(ActionKind::Named { name })
        }
        "SubmitForm" => {
            let url = decode_filespec_entry(reader, action, "F")?;
            let flags = action
                .entries()
                .iter()
                .find(|(k, _)| k == "Flags")
                .and_then(|(_, v)| match v {
                    Object::Integer(n) => Some(*n as u32),
                    _ => None,
                })
                .unwrap_or(0);
            Ok(ActionKind::SubmitForm { url, flags })
        }
        "ResetForm" => {
            let flags = action
                .entries()
                .iter()
                .find(|(k, _)| k == "Flags")
                .and_then(|(_, v)| match v {
                    Object::Integer(n) => Some(*n as u32),
                    _ => None,
                })
                .unwrap_or(0);
            Ok(ActionKind::ResetForm { flags })
        }
        "ImportData" => {
            let file = decode_filespec_entry(reader, action, "F")?;
            Ok(ActionKind::ImportData { file })
        }
        "JavaScript" => {
            let script = decode_js_entry(reader, action)?;
            Ok(ActionKind::JavaScript { script })
        }
        "SetOCGState" => {
            let (on_count, off_count, toggle_count) = decode_ocg_state(reader, action)?;
            Ok(ActionKind::SetOcgState {
                on_count,
                off_count,
                toggle_count,
            })
        }
        "Rendition" => Ok(ActionKind::Rendition),
        "Trans" => Ok(ActionKind::Trans),
        "GoTo3DView" => Ok(ActionKind::GoTo3DView),
        other => Ok(ActionKind::Other {
            kind: other.to_owned(),
        }),
    }
}

/// Decode the `/D` destination entry for `GoTo` / `GoToR` / `GoToE`.
/// Returns `(page_index, raw_dest)`. `page_index` is populated only
/// when the destination is an in-document explicit array whose first
/// element resolves through the page-index map.
fn decode_dest_entry(
    reader: &mut DocumentReader<'_>,
    action: &Dict,
    key: &str,
) -> Result<(Option<usize>, Option<String>), PdfError> {
    let Some(d) = action
        .entries()
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
    else {
        return Ok((None, None));
    };
    let d = reader.deref(d)?;
    Ok(match d {
        Object::Name(s) => (None, Some(s)),
        Object::LiteralString(b) | Object::HexString(b) => {
            (None, Some(String::from_utf8_lossy(&b).into_owned()))
        }
        Object::Array(items) => {
            // First element of an explicit destination is the page
            // reference; we surface the array's debug-form as raw
            // text for completeness.
            let page_index = match items.first() {
                Some(Object::Reference(id)) => {
                    let map = build_page_index_map(reader).ok();
                    map.and_then(|m| m.get(&id.number).copied())
                }
                _ => None,
            };
            let raw = format!("{items:?}");
            (page_index, Some(raw))
        }
        _ => (None, None),
    })
}

/// Decode a `/F` file-specification entry — either a string filename
/// or a Filespec dict whose `/UF` / `/F` carries the filename.
fn decode_filespec_entry(
    reader: &mut DocumentReader<'_>,
    action: &Dict,
    key: &str,
) -> Result<Option<String>, PdfError> {
    let Some(f) = action
        .entries()
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
    else {
        return Ok(None);
    };
    let f = reader.deref(f)?;
    Ok(match f {
        Object::LiteralString(b) | Object::HexString(b) => {
            Some(String::from_utf8_lossy(&b).into_owned())
        }
        Object::Name(s) => Some(s),
        Object::Dict(d) => {
            // /Filespec — prefer /UF (PDF 1.7+ UTF-16BE), fall back
            // to /F (PDFDocEncoded).
            let pick = d
                .entries()
                .iter()
                .find(|(k, _)| k == "UF")
                .or_else(|| d.entries().iter().find(|(k, _)| k == "F"));
            pick.and_then(|(_, v)| decode_text_obj(v))
        }
        _ => None,
    })
}

/// Decode `/JS` — either a literal/hex string or a content stream.
/// Per §12.6.4.16: when `/JS` is a stream, its filtered payload is
/// the JavaScript source.
fn decode_js_entry(reader: &mut DocumentReader<'_>, action: &Dict) -> Result<String, PdfError> {
    let Some(js) = action
        .entries()
        .iter()
        .find(|(k, _)| k == "JS")
        .map(|(_, v)| v.clone())
    else {
        return Ok(String::new());
    };
    let js = reader.deref(js)?;
    Ok(match js {
        Object::LiteralString(b) | Object::HexString(b) => decode_js_bytes(&b),
        Object::Stream(s) => {
            let bytes = crate::reader::document::decode_stream(&s)?;
            decode_js_bytes(&bytes)
        }
        _ => String::new(),
    })
}

/// JavaScript source decoder. PDF 2.0 §12.6.4.16 calls out UTF-8
/// (after a leading EF BB BF BOM) and UTF-16BE (after FE FF) as the
/// recognised encodings; the historical PDFDocEncoded form remains
/// supported. UTF-16LE (FF FE) is accepted here too — Adobe Acrobat
/// has historically emitted it.
fn decode_js_bytes(b: &[u8]) -> String {
    if b.len() >= 3 && &b[..3] == b"\xEF\xBB\xBF" {
        return String::from_utf8_lossy(&b[3..]).into_owned();
    }
    if b.len() >= 2 && b[0] == 0xFE && b[1] == 0xFF {
        let utf16: Vec<u16> = b[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&utf16);
    }
    if b.len() >= 2 && b[0] == 0xFF && b[1] == 0xFE {
        let utf16: Vec<u16> = b[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&utf16);
    }
    String::from_utf8_lossy(b).into_owned()
}

/// Decode a `/Hide` action's `/T` target — either a single annotation
/// name, an annotation reference, or an array of either.
fn decode_t_target(v: &Object) -> Option<String> {
    match v {
        Object::Name(s) => Some(s.clone()),
        Object::LiteralString(b) | Object::HexString(b) => {
            Some(String::from_utf8_lossy(b).into_owned())
        }
        Object::Array(items) => Some(format!("{items:?}")),
        _ => None,
    }
}

/// Decode a `/SetOCGState` action's `/State` array.
///
/// Per Table 212: state is a flat array `[mode ocg-ref ocg-ref … mode
/// ocg-ref …]` where `mode` is one of `/ON`, `/OFF`, `/Toggle`.
fn decode_ocg_state(
    reader: &mut DocumentReader<'_>,
    action: &Dict,
) -> Result<(usize, usize, usize), PdfError> {
    let Some(state) = action
        .entries()
        .iter()
        .find(|(k, _)| k == "State")
        .map(|(_, v)| v.clone())
    else {
        return Ok((0, 0, 0));
    };
    let state = reader.deref(state)?;
    let Object::Array(items) = state else {
        return Ok((0, 0, 0));
    };
    let mut on = 0usize;
    let mut off = 0usize;
    let mut tog = 0usize;
    enum Mode {
        On,
        Off,
        Toggle,
        None,
    }
    let mut mode = Mode::None;
    for it in items {
        match it {
            Object::Name(s) => {
                mode = match s.as_str() {
                    "ON" => Mode::On,
                    "OFF" => Mode::Off,
                    "Toggle" => Mode::Toggle,
                    _ => Mode::None,
                };
            }
            Object::Reference(_) => match mode {
                Mode::On => on += 1,
                Mode::Off => off += 1,
                Mode::Toggle => tog += 1,
                Mode::None => {}
            },
            _ => {}
        }
    }
    Ok((on, off, tog))
}

/// Walk a `/JavaScript` name-tree node into a flat
/// `(name, action-ref-or-dict)` list. Mirrors the same shape as
/// [`crate::reader::attachments`]' walker but bound to JavaScript
/// entries.
fn walk_name_tree(
    reader: &mut DocumentReader<'_>,
    node: &Dict,
    out: &mut Vec<(String, Object)>,
    depth: usize,
) -> Result<(), PdfError> {
    if depth > 32 || out.len() > 100_000 {
        return Ok(());
    }
    if let Some(Object::Array(items)) = node
        .entries()
        .iter()
        .find(|(k, _)| k == "Names")
        .map(|(_, v)| v)
    {
        let mut iter = items.iter();
        while let (Some(key_obj), Some(val_obj)) = (iter.next(), iter.next()) {
            let Some(key) = decode_text_obj(key_obj) else {
                continue;
            };
            out.push((key, val_obj.clone()));
        }
        return Ok(());
    }
    if let Some(kids_obj) = node
        .entries()
        .iter()
        .find(|(k, _)| k == "Kids")
        .map(|(_, v)| v.clone())
    {
        let kids = reader.deref(kids_obj)?;
        if let Object::Array(items) = kids {
            for kid in items {
                let kid = reader.deref(kid)?;
                if let Object::Dict(d) = kid {
                    walk_name_tree(reader, &d, out, depth + 1)?;
                }
            }
        }
    }
    Ok(())
}

/// Decode a PDF text object into a `String`. Mirrors the round-25 /
/// round-33 decoder: literal-string → UTF-8 lossy; hex-string →
/// UTF-16BE when prefixed with the BOM, else UTF-8 lossy.
fn decode_text_obj(obj: &Object) -> Option<String> {
    match obj {
        Object::LiteralString(b) => Some(String::from_utf8_lossy(b).into_owned()),
        Object::HexString(b) => {
            if b.len() >= 2 && b[0] == 0xFE && b[1] == 0xFF {
                let utf16: Vec<u16> = b[2..]
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Some(String::from_utf16_lossy(&utf16))
            } else {
                Some(String::from_utf8_lossy(b).into_owned())
            }
        }
        Object::Name(s) => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_js_bytes_utf8_bom() {
        let s = decode_js_bytes(b"\xEF\xBB\xBFapp.alert('hi')");
        assert_eq!(s, "app.alert('hi')");
    }

    #[test]
    fn decode_js_bytes_utf16be_bom() {
        // "alert"
        let mut b: Vec<u8> = vec![0xFE, 0xFF];
        for ch in b"alert" {
            b.push(0x00);
            b.push(*ch);
        }
        assert_eq!(decode_js_bytes(&b), "alert");
    }

    #[test]
    fn decode_js_bytes_utf16le_bom() {
        let mut b: Vec<u8> = vec![0xFF, 0xFE];
        for ch in b"alert" {
            b.push(*ch);
            b.push(0x00);
        }
        assert_eq!(decode_js_bytes(&b), "alert");
    }

    #[test]
    fn decode_js_bytes_plain_ascii_passes_through() {
        assert_eq!(decode_js_bytes(b"app.alert('hi')"), "app.alert('hi')");
    }

    #[test]
    fn decode_t_target_array_falls_back_to_debug() {
        // Debug-form of an Object::Array preserves the variant tag so
        // callers downstream can pattern-match the raw shape.
        let v = Object::Array(vec![Object::Name("BtnA".into())]);
        let s = decode_t_target(&v).unwrap();
        assert!(s.contains("BtnA"), "expected BtnA in {s:?}");
    }

    #[test]
    fn decode_t_target_name_returns_name() {
        let v = Object::Name("BtnA".into());
        assert_eq!(decode_t_target(&v).as_deref(), Some("BtnA"));
    }
}
