//! Round-27 — Object-hierarchy validator (ISO 32000-1 §7.7.2 + §7.7.3).
//!
//! Walks the `Catalog → Pages → Page` chain and surfaces every
//! structural integrity problem a downstream tool would care about
//! WITHOUT failing the whole open. Returns a [`HierarchyReport`]
//! collecting per-node issues so callers can branch on severity
//! (errors → fail; warnings → log + proceed).
//!
//! The checks are the structural-soundness invariants the spec
//! mandates but the writer-symmetric reader currently doesn't
//! verify explicitly:
//!
//! | Check | Severity | Reference |
//! |-------|----------|-----------|
//! | Catalog `/Type` = `/Catalog` | Error | §7.7.2 Table 28 |
//! | Catalog has `/Pages` reference | Error | §7.7.2 Table 28 |
//! | Pages root resolves to a `/Type /Pages` dict | Error | §7.7.3 Table 29 |
//! | Pages-node `/Type` = `/Pages` (or absent) | Warning | §7.7.3 Table 29 |
//! | Pages-node `/Count` matches actual leaves | Warning | §7.7.3 Table 29 |
//! | Page leaf `/Parent` references its parent | Warning | §7.7.3 Table 30 |
//! | Page-tree depth ≤ 32 (cycle guard) | Error | implementation |
//! | All `/Kids` entries resolve to dictionaries | Error | §7.7.3 |
//! | No cycles in the `/Kids` graph | Error | implementation |
//!
//! The validator is independent of the [`crate::reader::document`]
//! page walker — that one is permissive (default MediaBox of A4,
//! tolerant of missing `/Type`); this one surfaces every divergence
//! from the spec letter.

use std::collections::HashSet;

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::reader::document::DocumentReader;

/// Severity tag for [`HierarchyIssue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueSeverity {
    /// Spec violation that breaks rendering — e.g. a `/Pages` tree
    /// with no leaves, or a missing required `/Root` reference.
    Error,
    /// Spec divergence the reader can tolerate — e.g. a `/Pages`
    /// node missing its `/Type` tag, or a `/Count` that doesn't
    /// match the actual leaves.
    Warning,
}

/// One issue surfaced by [`verify_hierarchy`].
#[derive(Debug, Clone)]
pub struct HierarchyIssue {
    /// The offending object — `None` for issues that fault the
    /// document as a whole (e.g. "Catalog missing /Pages").
    pub object_id: Option<ObjectId>,
    /// Severity flag — see [`IssueSeverity`].
    pub severity: IssueSeverity,
    /// Human-readable description naming the spec section.
    pub message: String,
}

/// Summary report from [`verify_hierarchy`].
#[derive(Debug, Clone, Default)]
pub struct HierarchyReport {
    /// Number of page leaves the walker found.
    pub page_count: usize,
    /// Maximum DFS depth reached during the walk.
    pub max_depth: usize,
    /// Every integrity finding, in walker order.
    pub issues: Vec<HierarchyIssue>,
}

impl HierarchyReport {
    /// True when no errors were found. Warnings are allowed.
    pub fn is_valid(&self) -> bool {
        !self
            .issues
            .iter()
            .any(|i| i.severity == IssueSeverity::Error)
    }

    /// Convenience: filter by severity.
    pub fn errors(&self) -> impl Iterator<Item = &HierarchyIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == IssueSeverity::Error)
    }

    /// Convenience: filter by severity.
    pub fn warnings(&self) -> impl Iterator<Item = &HierarchyIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == IssueSeverity::Warning)
    }
}

/// Walk `Catalog → Pages → Page` and collect every spec-deviation
/// observed along the way.
pub fn verify_hierarchy(reader: &mut DocumentReader<'_>) -> Result<HierarchyReport, PdfError> {
    let mut report = HierarchyReport::default();

    // ---- Catalog (§7.7.2) -----------------------------------------
    let root_id = reader.xref().root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog_dict) = catalog else {
        report.issues.push(HierarchyIssue {
            object_id: Some(root_id),
            severity: IssueSeverity::Error,
            message: "Catalog (/Root) must be a dictionary (§7.7.2 Table 28)".into(),
        });
        return Ok(report);
    };

    // Catalog /Type
    match lookup(&catalog_dict, "Type") {
        Some(Object::Name(s)) if s == "Catalog" => {}
        Some(other) => report.issues.push(HierarchyIssue {
            object_id: Some(root_id),
            severity: IssueSeverity::Error,
            message: format!("Catalog /Type must be /Catalog (§7.7.2 Table 28) — got {other:?}"),
        }),
        None => report.issues.push(HierarchyIssue {
            object_id: Some(root_id),
            severity: IssueSeverity::Warning,
            message: "Catalog missing /Type entry (§7.7.2 Table 28)".into(),
        }),
    }

    // Catalog /Pages
    let pages_root_id = match lookup(&catalog_dict, "Pages") {
        Some(Object::Reference(id)) => *id,
        Some(other) => {
            report.issues.push(HierarchyIssue {
                object_id: Some(root_id),
                severity: IssueSeverity::Error,
                message: format!(
                    "Catalog /Pages must be an indirect reference (§7.7.2 Table 28) — got {other:?}"
                ),
            });
            return Ok(report);
        }
        None => {
            report.issues.push(HierarchyIssue {
                object_id: Some(root_id),
                severity: IssueSeverity::Error,
                message: "Catalog missing required /Pages entry (§7.7.2 Table 28)".into(),
            });
            return Ok(report);
        }
    };

    // ---- Pages tree (§7.7.3) --------------------------------------
    let mut visited: HashSet<u32> = HashSet::new();
    let mut leaves = 0usize;
    let mut max_depth = 0usize;
    walk_pages_node(
        reader,
        pages_root_id,
        /*parent_expected=*/ None,
        0,
        &mut visited,
        &mut leaves,
        &mut max_depth,
        &mut report,
    )?;
    report.page_count = leaves;
    report.max_depth = max_depth;
    if leaves == 0 {
        report.issues.push(HierarchyIssue {
            object_id: Some(pages_root_id),
            severity: IssueSeverity::Error,
            message: "Pages tree contained no Page leaves (§7.7.3.3)".into(),
        });
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn walk_pages_node(
    reader: &mut DocumentReader<'_>,
    node_id: ObjectId,
    parent_expected: Option<ObjectId>,
    depth: usize,
    visited: &mut HashSet<u32>,
    leaves: &mut usize,
    max_depth: &mut usize,
    report: &mut HierarchyReport,
) -> Result<(), PdfError> {
    if depth > *max_depth {
        *max_depth = depth;
    }
    // Cycle / runaway guard.
    if depth > 32 {
        report.issues.push(HierarchyIssue {
            object_id: Some(node_id),
            severity: IssueSeverity::Error,
            message: format!(
                "Pages-tree depth exceeded 32 at node {node_id:?} — refusing to recurse"
            ),
        });
        return Ok(());
    }
    if !visited.insert(node_id.number) {
        report.issues.push(HierarchyIssue {
            object_id: Some(node_id),
            severity: IssueSeverity::Error,
            message: format!("Pages-tree cycle: node {node_id:?} visited twice (§7.7.3)"),
        });
        return Ok(());
    }
    let node = match reader.resolve(node_id) {
        Ok(o) => o,
        Err(e) => {
            report.issues.push(HierarchyIssue {
                object_id: Some(node_id),
                severity: IssueSeverity::Error,
                message: format!("Pages-tree node {node_id:?} unresolvable: {e}"),
            });
            return Ok(());
        }
    };
    let Object::Dict(d) = node else {
        report.issues.push(HierarchyIssue {
            object_id: Some(node_id),
            severity: IssueSeverity::Error,
            message: format!("Pages-tree node {node_id:?} is not a dictionary"),
        });
        return Ok(());
    };

    let type_name = match lookup(&d, "Type") {
        Some(Object::Name(s)) => Some(s.as_str()),
        _ => None,
    };

    match type_name {
        Some("Page") => {
            *leaves += 1;
            check_page_leaf(&d, node_id, parent_expected, report);
        }
        Some("Pages") | None => {
            if type_name.is_none() {
                report.issues.push(HierarchyIssue {
                    object_id: Some(node_id),
                    severity: IssueSeverity::Warning,
                    message: format!(
                        "Pages-tree node {node_id:?} missing /Type (§7.7.3.2 Table 29 — required)"
                    ),
                });
            }
            check_pages_node(
                reader,
                &d,
                node_id,
                parent_expected,
                depth,
                visited,
                leaves,
                max_depth,
                report,
            )?;
        }
        Some(other) => {
            report.issues.push(HierarchyIssue {
                object_id: Some(node_id),
                severity: IssueSeverity::Error,
                message: format!(
                    "Pages-tree node {node_id:?} has unrecognised /Type /{other} (expected /Pages or /Page)"
                ),
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_pages_node(
    reader: &mut DocumentReader<'_>,
    d: &Dict,
    node_id: ObjectId,
    parent_expected: Option<ObjectId>,
    depth: usize,
    visited: &mut HashSet<u32>,
    leaves: &mut usize,
    max_depth: &mut usize,
    report: &mut HierarchyReport,
) -> Result<(), PdfError> {
    // /Parent — required on non-root /Pages nodes (Table 29). The
    // root /Pages node has no parent — `parent_expected` is None
    // there. We only report when there *should* be a parent.
    if let Some(expected) = parent_expected {
        match lookup(d, "Parent") {
            Some(Object::Reference(actual)) if *actual == expected => {}
            Some(Object::Reference(actual)) => {
                report.issues.push(HierarchyIssue {
                    object_id: Some(node_id),
                    severity: IssueSeverity::Warning,
                    message: format!(
                        "/Pages {node_id:?} /Parent points to {actual:?} but DFS parent is {expected:?}"
                    ),
                });
            }
            Some(other) => {
                report.issues.push(HierarchyIssue {
                    object_id: Some(node_id),
                    severity: IssueSeverity::Warning,
                    message: format!(
                        "/Pages {node_id:?} /Parent must be an indirect reference (got {other:?})"
                    ),
                });
            }
            None => {
                report.issues.push(HierarchyIssue {
                    object_id: Some(node_id),
                    severity: IssueSeverity::Warning,
                    message: format!(
                        "/Pages {node_id:?} missing /Parent (§7.7.3.2 Table 29 — required on non-root nodes)"
                    ),
                });
            }
        }
    }

    // /Kids — required, array of references.
    let kids = match lookup(d, "Kids") {
        Some(Object::Array(items)) => items.clone(),
        Some(other) => {
            report.issues.push(HierarchyIssue {
                object_id: Some(node_id),
                severity: IssueSeverity::Error,
                message: format!("/Pages {node_id:?} /Kids must be an array (got {other:?})"),
            });
            return Ok(());
        }
        None => {
            report.issues.push(HierarchyIssue {
                object_id: Some(node_id),
                severity: IssueSeverity::Error,
                message: format!("/Pages {node_id:?} missing required /Kids"),
            });
            return Ok(());
        }
    };

    let leaves_before = *leaves;
    for kid in kids {
        let Object::Reference(kid_id) = kid else {
            report.issues.push(HierarchyIssue {
                object_id: Some(node_id),
                severity: IssueSeverity::Error,
                message: format!(
                    "/Pages {node_id:?} /Kids entry must be an indirect reference (got {kid:?})"
                ),
            });
            continue;
        };
        walk_pages_node(
            reader,
            kid_id,
            Some(node_id),
            depth + 1,
            visited,
            leaves,
            max_depth,
            report,
        )?;
    }
    let descendants = *leaves - leaves_before;

    // /Count — must equal the number of /Page leaves under this node
    // (§7.7.3.2 — "the number of leaf nodes [Page objects] that are
    // descendants of this node within the page tree").
    match lookup(d, "Count") {
        Some(Object::Integer(n)) => {
            if *n as usize != descendants {
                report.issues.push(HierarchyIssue {
                    object_id: Some(node_id),
                    severity: IssueSeverity::Warning,
                    message: format!(
                        "/Pages {node_id:?} /Count = {n} but DFS found {descendants} leaves"
                    ),
                });
            }
        }
        Some(other) => {
            report.issues.push(HierarchyIssue {
                object_id: Some(node_id),
                severity: IssueSeverity::Warning,
                message: format!("/Pages {node_id:?} /Count must be an integer (got {other:?})"),
            });
        }
        None => {
            report.issues.push(HierarchyIssue {
                object_id: Some(node_id),
                severity: IssueSeverity::Warning,
                message: format!("/Pages {node_id:?} missing required /Count (§7.7.3.2 Table 29)"),
            });
        }
    }
    Ok(())
}

fn check_page_leaf(
    d: &Dict,
    node_id: ObjectId,
    parent_expected: Option<ObjectId>,
    report: &mut HierarchyReport,
) {
    // /Parent — required on Page leaves (Table 30).
    match (lookup(d, "Parent"), parent_expected) {
        (Some(Object::Reference(actual)), Some(expected)) if *actual == expected => {}
        (Some(Object::Reference(actual)), Some(expected)) => {
            report.issues.push(HierarchyIssue {
                object_id: Some(node_id),
                severity: IssueSeverity::Warning,
                message: format!(
                    "/Page {node_id:?} /Parent {actual:?} doesn't match DFS parent {expected:?}"
                ),
            });
        }
        (Some(other), _) => {
            report.issues.push(HierarchyIssue {
                object_id: Some(node_id),
                severity: IssueSeverity::Warning,
                message: format!(
                    "/Page {node_id:?} /Parent must be an indirect reference (got {other:?})"
                ),
            });
        }
        (None, _) => {
            report.issues.push(HierarchyIssue {
                object_id: Some(node_id),
                severity: IssueSeverity::Warning,
                message: format!(
                    "/Page {node_id:?} missing /Parent (§7.7.3.3 Table 30 — required)"
                ),
            });
        }
    }
    // MediaBox — required on the leaf OR inheritable from an
    // ancestor /Pages node. We can't easily check inheritance here,
    // so a missing MediaBox is a Warning rather than Error.
    if lookup(d, "MediaBox").is_none() {
        report.issues.push(HierarchyIssue {
            object_id: Some(node_id),
            severity: IssueSeverity::Warning,
            message: format!(
                "/Page {node_id:?} has no directly-attached /MediaBox (inheritance may still satisfy §7.7.3.3)"
            ),
        });
    }
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

    fn page_with(w: f32, h: f32, color: Rgba) -> Page {
        let mut p = Path::new();
        p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
        p.commands
            .push(PathCommand::LineTo(Point::new(w - 10.0, 10.0)));
        p.commands
            .push(PathCommand::LineTo(Point::new(w - 10.0, h - 10.0)));
        p.commands.push(PathCommand::Close);
        let frame = VectorFrame {
            width: w,
            height: h,
            view_box: None,
            root: Group {
                children: vec![Node::Path(PathNode {
                    path: p,
                    fill: Some(Paint::Solid(color)),
                    stroke: None,
                    fill_rule: FillRule::NonZero,
                })],
                ..Group::default()
            },
            pts: None,
            time_base: TimeBase::new(1, 1),
        };
        let mut page = Page::new(w, h);
        page.content = frame;
        page
    }

    #[test]
    fn writer_output_passes_hierarchy_check() {
        let scene = Scene {
            pages: Some(vec![
                page_with(100.0, 100.0, Rgba::opaque(255, 0, 0)),
                page_with(200.0, 200.0, Rgba::opaque(0, 255, 0)),
            ]),
            ..Scene::default()
        };
        let pdf = write_pdf_from_scene(&scene).expect("write_pdf");
        let mut reader = DocumentReader::open(&pdf).expect("open");
        let report = verify_hierarchy(&mut reader).expect("verify");
        assert_eq!(report.page_count, 2);
        assert!(
            report.errors().count() == 0,
            "writer output must have no hierarchy errors; got {:?}",
            report.issues
        );
        assert!(report.is_valid());
    }

    #[test]
    fn writer_single_page_reports_one_leaf() {
        let scene = Scene {
            pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(0, 0, 0))]),
            ..Scene::default()
        };
        let pdf = write_pdf_from_scene(&scene).expect("write_pdf");
        let mut reader = DocumentReader::open(&pdf).expect("open");
        let report = verify_hierarchy(&mut reader).expect("verify");
        assert_eq!(report.page_count, 1);
        assert!(report.is_valid());
    }

    #[test]
    fn report_is_valid_no_errors_default() {
        let report = HierarchyReport::default();
        assert!(report.is_valid());
        assert_eq!(report.page_count, 0);
        assert_eq!(report.max_depth, 0);
    }

    #[test]
    fn report_distinguishes_errors_from_warnings() {
        let mut report = HierarchyReport::default();
        report.issues.push(HierarchyIssue {
            object_id: None,
            severity: IssueSeverity::Warning,
            message: "warn".into(),
        });
        assert!(report.is_valid(), "warnings don't invalidate report");
        report.issues.push(HierarchyIssue {
            object_id: None,
            severity: IssueSeverity::Error,
            message: "err".into(),
        });
        assert!(!report.is_valid(), "errors invalidate report");
        assert_eq!(report.errors().count(), 1);
        assert_eq!(report.warnings().count(), 1);
    }
}
