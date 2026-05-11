//! Round-27 — PDF/A conformance detection beyond the XMP tag
//! (ISO 19005-1..4 §6.x — identification + structural requirements).
//!
//! Round 26 surfaced `pdfaid:part` / `pdfaid:conformance` from the
//! XMP `/Metadata` packet only. ISO 19005 conformance, however, also
//! requires:
//!
//! * **`/MarkInfo /Marked true`** on the catalog (PDF/A-1a / -2a / -3a
//!   "accessibility" levels — ISO 19005-1 §6.8.3 / 19005-2 §6.7.7).
//! * **`/StructTreeRoot`** on the catalog (same — accessible logical
//!   structure tree).
//! * **`/Lang`** on the catalog (recommended for `A` conformance).
//!
//! Round 27 surfaces ALL of these so a caller checking
//! "is this REALLY PDF/A?" can cross-verify the XMP tag against the
//! structural signals. A doc that claims PDF/A-1a in XMP but doesn't
//! carry `/MarkInfo /Marked true` is technically non-conformant
//! (Adobe's preflight reports it as such); this module lets you spot
//! that mismatch.
//!
//! Scope: detection only. We do NOT validate the structure tree's
//! tagging contents (P / H1..H6 / Span / Figure etc.); that's a
//! standards-test problem orthogonal to format identification.

use crate::error::PdfError;
use crate::objects::{Dict, Object};
use crate::reader::document::DocumentReader;
use crate::reader::xmp::XmpPacket;

/// Structural PDF/A signals from the catalog, independent of the
/// XMP packet. Surfaced by [`pdfa_signals`].
///
/// Use [`PdfAConformance::from_signals_and_xmp`] to combine these
/// with the XMP packet's `pdfaid:part` / `pdfaid:conformance`
/// declaration into a single conformance picture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PdfACatalogSignals {
    /// `/MarkInfo /Marked` — true when the catalog declares the
    /// document is logically structured ("tagged PDF" per
    /// §14.7.2). Required by PDF/A `A`-level conformance.
    pub mark_info_marked: bool,
    /// `/MarkInfo /UserProperties` — true when user-properties are
    /// declared (PDF 1.6+). Not required by any PDF/A level, but
    /// surfaced for completeness.
    pub mark_info_user_properties: bool,
    /// `/MarkInfo /Suspects` — true when the document has suspect
    /// markings (PDF 1.6+). Recommended FALSE for PDF/A-2a / -3a.
    pub mark_info_suspects: bool,
    /// `/StructTreeRoot` reference present on the catalog. The
    /// dict's contents (the actual tag tree) is NOT walked here.
    pub has_struct_tree_root: bool,
    /// `/Lang` on the catalog — language identifier per BCP 47.
    /// Recommended for PDF/A `A` conformance.
    pub catalog_lang: Option<String>,
    /// `/OutputIntents` on the catalog — required by PDF/A for
    /// embedded ICC output intent (§6.2.2). Surfaced as the count
    /// of intent dicts found.
    pub output_intent_count: usize,
    /// `/Metadata` reference on the catalog. PDF/A requires an
    /// embedded XMP packet (§6.7); this is `true` when present.
    pub has_xmp_metadata: bool,
}

/// Resolved PDF/A conformance picture, combining XMP claims with
/// catalog signals. See [`PdfAConformance::from_signals_and_xmp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfAConformance {
    /// What the XMP packet declares — `Some((part, conformance))`
    /// when `pdfaid:part` is set; `None` when the document does not
    /// claim PDF/A in XMP.
    pub declared: Option<(u8, String)>,
    /// True when the structural signals are sufficient for the
    /// declared conformance. False when the document claims an
    /// `A`-level (accessibility) conformance but lacks the tagged-
    /// PDF prerequisites.
    pub structurally_sound: bool,
    /// True when the document claims PDF/A in XMP but is missing
    /// one or more structural prerequisites — caller's signal to
    /// surface "PDF/A claim untrustworthy" diagnostic.
    pub claim_inconsistent: bool,
    /// Free-form description of any inconsistency found. Empty
    /// vec when the claim and structure agree.
    pub inconsistencies: Vec<String>,
}

impl PdfAConformance {
    /// Combine catalog signals with the XMP packet's claim.
    ///
    /// The conformance rules per ISO 19005-x:
    /// * Any `pdfaid:part` requires `/Metadata` (XMP packet present),
    ///   `/OutputIntents` ≥ 1 (ISO 19005-1 §6.2.2), `/StructTreeRoot`
    ///   for `A` conformance levels and `/MarkInfo /Marked true`.
    /// * `B` (basic) conformance ⇒ no structural requirements.
    /// * `U` (Unicode) conformance ⇒ no structural requirements
    ///   (extra ToUnicode coverage; doesn't bubble to catalog).
    /// * `A` (accessibility) conformance ⇒ requires tagged PDF.
    pub fn from_signals_and_xmp(sig: &PdfACatalogSignals, xmp: Option<&XmpPacket>) -> Self {
        let declared = xmp.and_then(|x| {
            let part = x.pdfaid_part?;
            let conf = x.pdfaid_conformance.clone().unwrap_or_default();
            Some((part, conf))
        });
        let mut inconsistencies = Vec::new();
        let mut sound = true;

        if let Some((part, ref conf)) = declared {
            // /Metadata must be present per ISO 19005-1 §6.7.
            if !sig.has_xmp_metadata {
                inconsistencies.push(
                    "PDF/A claim in XMP but Catalog /Metadata reference is absent (§6.7)".into(),
                );
                sound = false;
            }
            // /OutputIntents required for every part.
            if sig.output_intent_count == 0 {
                inconsistencies.push(format!(
                    "PDF/A-{part}{conf}: Catalog /OutputIntents missing (§6.2.2)"
                ));
                sound = false;
            }
            // `A` (accessibility) conformance — tagged PDF prerequisites.
            if conf.eq_ignore_ascii_case("A") {
                if !sig.mark_info_marked {
                    inconsistencies.push(format!(
                        "PDF/A-{part}A claims accessibility but Catalog /MarkInfo /Marked is not true (§6.8.3)"
                    ));
                    sound = false;
                }
                if !sig.has_struct_tree_root {
                    inconsistencies.push(format!(
                        "PDF/A-{part}A claims accessibility but Catalog /StructTreeRoot is absent (§6.8.2)"
                    ));
                    sound = false;
                }
                if sig.catalog_lang.is_none() {
                    inconsistencies.push(format!(
                        "PDF/A-{part}A claims accessibility but Catalog /Lang is absent (recommended)"
                    ));
                    // /Lang is recommended, not required — don't fail
                    // the structural soundness flag for this alone.
                }
            }
        }

        let claim_inconsistent = declared.is_some() && !inconsistencies.is_empty();
        Self {
            declared,
            structurally_sound: sound,
            claim_inconsistent,
            inconsistencies,
        }
    }

    /// True when the document claims PDF/A in XMP. Synonym for
    /// `self.declared.is_some()`.
    pub fn is_declared(&self) -> bool {
        self.declared.is_some()
    }

    /// Convenience: `"1A"` / `"2B"` / `"3U"` style designator —
    /// returns `Some(s)` when both part and conformance are known.
    pub fn designator(&self) -> Option<String> {
        let (part, conf) = self.declared.as_ref()?;
        if conf.is_empty() {
            None
        } else {
            Some(format!("{part}{conf}"))
        }
    }
}

/// Surface the structural PDF/A signals from the catalog.
///
/// Does NOT consult the XMP packet — combine with
/// [`crate::reader::DocumentReader::xmp_packet`] for the full
/// conformance picture via [`PdfAConformance::from_signals_and_xmp`].
pub fn pdfa_signals(reader: &mut DocumentReader<'_>) -> Result<PdfACatalogSignals, PdfError> {
    let root_id = reader.xref().root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog) = catalog else {
        return Ok(PdfACatalogSignals::default());
    };

    let mut sig = PdfACatalogSignals::default();

    // /MarkInfo (§14.7 Table 321). May be a dict OR an indirect ref.
    if let Some(mark_info_obj) = lookup(&catalog, "MarkInfo").cloned() {
        let mark_info = reader.deref(mark_info_obj)?;
        if let Object::Dict(d) = mark_info {
            sig.mark_info_marked = matches!(lookup(&d, "Marked"), Some(Object::Bool(true)));
            sig.mark_info_user_properties =
                matches!(lookup(&d, "UserProperties"), Some(Object::Bool(true)));
            sig.mark_info_suspects = matches!(lookup(&d, "Suspects"), Some(Object::Bool(true)));
        }
    }

    // /StructTreeRoot (§14.7.2 Table 322). Presence-check only.
    sig.has_struct_tree_root = lookup(&catalog, "StructTreeRoot").is_some();

    // /Lang on the catalog (§14.9.2.2).
    sig.catalog_lang = match lookup(&catalog, "Lang") {
        Some(Object::LiteralString(b)) | Some(Object::HexString(b)) => {
            Some(String::from_utf8_lossy(b).into_owned())
        }
        _ => None,
    };

    // /OutputIntents (§14.11.5 Table 388). Required for PDF/A.
    if let Some(oi_obj) = lookup(&catalog, "OutputIntents").cloned() {
        let oi_obj = reader.deref(oi_obj)?;
        if let Object::Array(items) = oi_obj {
            sig.output_intent_count = items.len();
        }
    }

    // /Metadata (§14.3.2). The xmp_metadata accessor returns Some
    // when this is wired through — re-implementing the resolution
    // here would double-fetch the stream; we just check presence.
    sig.has_xmp_metadata = lookup(&catalog, "Metadata").is_some();

    Ok(sig)
}

fn lookup<'d>(d: &'d Dict, k: &str) -> Option<&'d Object> {
    d.entries().iter().find(|(kk, _)| kk == k).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::write_pdf_from_scene;
    use oxideav_core::time::TimeBase;
    use oxideav_core::vector::{
        FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
    };
    use oxideav_scene::{Page, Scene};

    fn empty_page() -> Page {
        let mut p = Path::new();
        p.commands.push(PathCommand::MoveTo(Point::new(0.0, 0.0)));
        p.commands.push(PathCommand::LineTo(Point::new(10.0, 10.0)));
        p.commands.push(PathCommand::Close);
        let frame = VectorFrame {
            width: 100.0,
            height: 100.0,
            view_box: None,
            root: Group {
                children: vec![Node::Path(PathNode {
                    path: p,
                    fill: Some(Paint::Solid(Rgba::opaque(0, 0, 0))),
                    stroke: None,
                    fill_rule: FillRule::NonZero,
                })],
                ..Group::default()
            },
            pts: None,
            time_base: TimeBase::new(1, 1),
        };
        let mut page = Page::new(100.0, 100.0);
        page.content = frame;
        page
    }

    #[test]
    fn writer_output_has_no_pdfa_signals() {
        let scene = Scene {
            pages: Some(vec![empty_page()]),
            ..Scene::default()
        };
        let pdf = write_pdf_from_scene(&scene).expect("write_pdf");
        let mut reader = DocumentReader::open(&pdf).expect("open");
        let sig = pdfa_signals(&mut reader).expect("signals");
        assert!(!sig.mark_info_marked);
        assert!(!sig.has_struct_tree_root);
        assert!(sig.catalog_lang.is_none());
        assert_eq!(sig.output_intent_count, 0);
        assert!(!sig.has_xmp_metadata);
    }

    #[test]
    fn unclaimed_doc_yields_undeclared_conformance() {
        let sig = PdfACatalogSignals::default();
        let conformance = PdfAConformance::from_signals_and_xmp(&sig, None);
        assert!(!conformance.is_declared());
        assert!(conformance.structurally_sound);
        assert!(!conformance.claim_inconsistent);
        assert!(conformance.inconsistencies.is_empty());
        assert!(conformance.designator().is_none());
    }

    #[test]
    fn claim_without_outputintents_flags_inconsistency() {
        let sig = PdfACatalogSignals {
            has_xmp_metadata: true,
            output_intent_count: 0,
            ..Default::default()
        };
        let xmp = XmpPacket {
            pdfaid_part: Some(2),
            pdfaid_conformance: Some("B".into()),
            ..XmpPacket::default()
        };
        let c = PdfAConformance::from_signals_and_xmp(&sig, Some(&xmp));
        assert!(c.is_declared());
        assert!(c.claim_inconsistent);
        assert!(!c.structurally_sound);
        assert!(c
            .inconsistencies
            .iter()
            .any(|m| m.contains("OutputIntents")));
    }

    #[test]
    fn a_level_without_marked_flags_accessibility_gap() {
        let sig = PdfACatalogSignals {
            has_xmp_metadata: true,
            output_intent_count: 1,
            mark_info_marked: false,
            has_struct_tree_root: false,
            ..Default::default()
        };
        let xmp = XmpPacket {
            pdfaid_part: Some(2),
            pdfaid_conformance: Some("A".into()),
            ..XmpPacket::default()
        };
        let c = PdfAConformance::from_signals_and_xmp(&sig, Some(&xmp));
        assert!(c.claim_inconsistent);
        assert!(c
            .inconsistencies
            .iter()
            .any(|m| m.contains("Marked is not true")));
        assert!(c
            .inconsistencies
            .iter()
            .any(|m| m.contains("StructTreeRoot is absent")));
    }

    #[test]
    fn a_level_with_full_structure_is_sound() {
        let sig = PdfACatalogSignals {
            has_xmp_metadata: true,
            output_intent_count: 1,
            mark_info_marked: true,
            has_struct_tree_root: true,
            catalog_lang: Some("en".into()),
            ..Default::default()
        };
        let xmp = XmpPacket {
            pdfaid_part: Some(3),
            pdfaid_conformance: Some("A".into()),
            ..XmpPacket::default()
        };
        let c = PdfAConformance::from_signals_and_xmp(&sig, Some(&xmp));
        assert!(c.is_declared());
        assert!(c.structurally_sound);
        assert!(!c.claim_inconsistent);
        assert!(c.inconsistencies.is_empty());
        assert_eq!(c.designator().as_deref(), Some("3A"));
    }

    #[test]
    fn b_level_no_structural_requirements_beyond_oi() {
        let sig = PdfACatalogSignals {
            has_xmp_metadata: true,
            output_intent_count: 1,
            mark_info_marked: false,
            has_struct_tree_root: false,
            ..Default::default()
        };
        let xmp = XmpPacket {
            pdfaid_part: Some(2),
            pdfaid_conformance: Some("B".into()),
            ..XmpPacket::default()
        };
        let c = PdfAConformance::from_signals_and_xmp(&sig, Some(&xmp));
        assert!(c.is_declared());
        // B-level needs no tagged-PDF — sound despite missing marked/struct.
        assert!(c.structurally_sound);
        assert!(!c.claim_inconsistent);
    }

    #[test]
    fn case_insensitive_conformance_match() {
        let sig = PdfACatalogSignals {
            has_xmp_metadata: true,
            output_intent_count: 1,
            mark_info_marked: false,
            has_struct_tree_root: false,
            ..Default::default()
        };
        let xmp = XmpPacket {
            pdfaid_part: Some(1),
            // Some authoring tools emit lowercase.
            pdfaid_conformance: Some("a".into()),
            ..XmpPacket::default()
        };
        let c = PdfAConformance::from_signals_and_xmp(&sig, Some(&xmp));
        assert!(c.claim_inconsistent);
    }
}
