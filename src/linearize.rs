//! Linearized PDF writer (ISO 32000-1 §7.5.6 + Annex F).
//!
//! "Fast Web View" — a structural reorganisation that lets a PDF
//! viewer render page 1 without first downloading the entire file.
//! The on-wire form is a strict superset of standard PDF: linearized
//! files start with a linearization parameter dictionary, a first-page
//! cross-reference section, the document catalog, the first-page
//! section, a primary hint stream, the remaining pages, and finally a
//! main cross-reference table at the end. A reader that ignores
//! `/Linearized` still sees a valid PDF; one that recognises it can
//! stream the first page from the head of the file.
//!
//! # Layout (Annex F.3)
//!
//! ```text
//! Part 1:  %PDF-1.5\n + binary marker        (header)
//! Part 2:  <lin param dict>                  (first object body)
//! Part 3:  first-page xref + trailer         (with /Prev → main xref)
//! Part 4:  Catalog + document-level objects  (Info, Pages tree)
//! Part 5:  Primary hint stream               (page offset hint table)
//! Part 6:  First-page section                (page object + resources + contents)
//! Part 7:  Remaining pages                   (pages 2..N if N > 1)
//! Part 11: Main xref + trailer               (referenced by startxref)
//! ```
//!
//! Hint streams (Part 5) follow Tables F.3 / F.4 — we emit the
//! mandatory page offset hint table only. Shared object hints
//! (F.4.2), thumbnails (F.4.3), and the various generic hint tables
//! (F.4.4 / F.4.5 / F.4.6) are not emitted: per-page resources are
//! independent in our IR, and we generate no thumbnails / outlines
//! / threads.
//!
//! # Two-pass emission
//!
//! Several values in the linearization parameter dictionary depend on
//! the final byte layout (`/L` file length, `/E` end-of-first-page,
//! `/H` hint stream byte range, `/T` main xref offset). The first-page
//! trailer's `/Prev` similarly points at the main xref offset. We use
//! a two-pass scheme: emit each part with placeholder values padded to
//! a 10-digit fixed width, record their byte positions, then patch
//! the placeholders in-place once every offset is known. PDF integers
//! accept leading zeros, so 10-digit padding is on-spec.

use std::io::Write;

use oxideav_scene::Scene;

use crate::error::PdfError;
use crate::info::{build_info_dict, has_metadata};
use crate::objects::{Dict, Document, IndirectObject, Object, ObjectId, Stream};
use crate::resources::ResourceCollector;
use crate::writer::render_frame_for_linearize;

/// Render a [`Scene`] in pages mode as a Linearized PDF 1.5 document
/// per ISO 32000-1 §7.5.6 + Annex F (Fast Web View). The output is a
/// strict superset of plain PDF: a viewer that ignores `/Linearized`
/// still sees a valid Catalog + Pages tree + page content, just
/// without the streaming optimisation.
pub fn write_pdf_linearized(scene: &Scene) -> Result<Vec<u8>, PdfError> {
    let pages = scene
        .pages
        .as_ref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            PdfError::other(
                "write_pdf_linearized: scene is not in pages mode (scene.pages is None or empty)",
            )
        })?;

    // ---- Render every page's content + resources -------------------
    let rendered: Vec<RenderedOwned> = pages
        .iter()
        .map(|page| {
            let (content_bytes, resources) = render_frame_for_linearize(&page.content);
            RenderedOwned {
                width: page.width,
                height: page.height,
                content_bytes,
                resources,
            }
        })
        .collect();

    let n_pages = rendered.len();

    // ---- Pre-flatten resource sub-objects --------------------------
    // Each page's ResourceCollector may add gradient / image
    // sub-objects to a Document. We need to know how many up front
    // so the id allocator can lay out all ids before any byte is
    // written. Use a fresh Document per page so each page's extras
    // get ids starting at 1 (predictable seed for the remap step).
    let mut owned_pages: Vec<OwnedPage> = Vec::with_capacity(n_pages);
    for r in &rendered {
        let mut sub_doc = Document::new();
        sub_doc.set_next_id(1);
        let res_obj = r.resources.flatten_into_resources_dict(&mut sub_doc);
        let extras = crate::objects::take_objects(&mut sub_doc);
        owned_pages.push(OwnedPage {
            width: r.width,
            height: r.height,
            content_bytes: r.content_bytes.clone(),
            resources_dict: res_obj,
            extra_objects: extras,
        });
    }

    // ---- Allocate object ids per Annex F.3.1 -----------------------
    // Group 2 (pages 2..N): one (page, resources, contents) triple
    // each, plus their per-page resource extras. Group 1 starts at
    // the next id.
    let mut next_id_n = 1u32;
    let mut alloc = || {
        let id = ObjectId::new(next_id_n);
        next_id_n += 1;
        id
    };

    let mut g2_page_ids = Vec::with_capacity(n_pages.saturating_sub(1));
    let mut g2_resources_ids = Vec::with_capacity(n_pages.saturating_sub(1));
    let mut g2_contents_ids = Vec::with_capacity(n_pages.saturating_sub(1));
    // Per-page extras get fresh ids in the same group; track them per
    // page so we can stitch the references together below.
    let mut g2_extra_ids: Vec<Vec<ObjectId>> = Vec::with_capacity(n_pages.saturating_sub(1));
    for owned in owned_pages.iter().skip(1) {
        g2_page_ids.push(alloc());
        g2_resources_ids.push(alloc());
        g2_contents_ids.push(alloc());
        let mut extras = Vec::with_capacity(owned.extra_objects.len());
        for _ in 0..owned.extra_objects.len() {
            extras.push(alloc());
        }
        g2_extra_ids.push(extras);
    }

    // Group 1
    let catalog_id = alloc();
    let pages_tree_id = alloc();
    let info_id_opt = if has_metadata(&scene.metadata) {
        Some(alloc())
    } else {
        None
    };
    let lin_param_id = alloc();
    let first_page_id = alloc();
    let first_page_resources_id = alloc();
    let first_page_contents_id = alloc();
    let mut first_page_extra_ids = Vec::with_capacity(owned_pages[0].extra_objects.len());
    for _ in 0..owned_pages[0].extra_objects.len() {
        first_page_extra_ids.push(alloc());
    }
    let hint_stream_id = alloc();
    let total_ids = next_id_n; // ids in use are 1..total_ids; /Size = total_ids

    // ---- Re-target references inside resource dicts ---------------
    // Each page's resource dict refers to its extras by their
    // placeholder ids (assigned 1.. by the per-page throwaway
    // Document). Remap the placeholders to the final allocation.
    let first_page_owned = remap_owned_page(&owned_pages[0], &first_page_extra_ids);
    let mut g2_owned: Vec<OwnedPageRemapped> = Vec::with_capacity(n_pages.saturating_sub(1));
    for (i, p) in owned_pages.iter().enumerate().skip(1) {
        g2_owned.push(remap_owned_page(p, &g2_extra_ids[i - 1]));
    }

    // Build the Pages tree's /Kids array.
    let mut kids: Vec<Object> = Vec::with_capacity(n_pages);
    kids.push(Object::Reference(first_page_id));
    for id in &g2_page_ids {
        kids.push(Object::Reference(*id));
    }

    // ---- Pass 1: emit the layout with placeholder values -----------
    let mut out = Vec::with_capacity(8192);

    // Part 1: header
    out.extend_from_slice(b"%PDF-1.5\n");
    out.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");

    // Part 2: linearization parameter dict
    let lin_param_off = out.len() as u64;
    write!(
        &mut out,
        "{} 0 obj\n<< /Linearized 1 /L {:010} /H [ {:010} {:010} ] /O {} /E {:010} /N {} /T {:010} >>\nendobj\n",
        lin_param_id.number,
        0u64,
        0u64,
        0u64,
        first_page_id.number,
        0u64,
        n_pages,
        0u64,
    )
    .map_err(|e| PdfError::other(format!("linearize lin-dict format: {e}")))?;

    // Part 3: first-page xref + trailer
    let first_xref_off = out.len() as u64;
    let first_group_start = catalog_id.number;
    let first_group_count = total_ids - first_group_start;

    out.extend_from_slice(b"xref\n");
    writeln!(&mut out, "{} {}", first_group_start, first_group_count)
        .map_err(|e| PdfError::other(format!("linearize first-xref header: {e}")))?;
    let first_xref_entries_off = out.len() as u64;
    for _ in 0..first_group_count {
        out.extend_from_slice(b"0000000000 00000 n \n");
    }

    out.extend_from_slice(b"trailer\n");
    // Build trailer dict but emit /Prev with a 10-digit zero placeholder
    // by hand so we can patch it post-hoc without changing layout.
    write_first_page_trailer_dict(
        &mut out,
        total_ids,
        catalog_id,
        info_id_opt,
        /*prev_placeholder*/ 0,
    )?;
    let prev_patch_off = first_trailer_prev_offset(&out, first_xref_off as usize);
    out.extend_from_slice(b"\nstartxref\n");
    let first_startxref_value_off = out.len() as u64;
    out.extend_from_slice(b"0000000000\n%%EOF\n");

    // Part 4: Catalog
    let catalog_off = out.len() as u64;
    write_indirect(
        &mut out,
        &IndirectObject {
            id: catalog_id,
            object: Object::Dict(
                Dict::new()
                    .with("Type", Object::Name("Catalog".into()))
                    .with("Pages", Object::Reference(pages_tree_id)),
            ),
        },
    )?;

    // Pages tree
    let pages_tree_off = out.len() as u64;
    write_indirect(
        &mut out,
        &IndirectObject {
            id: pages_tree_id,
            object: Object::Dict(
                Dict::new()
                    .with("Type", Object::Name("Pages".into()))
                    .with("Kids", Object::Array(kids))
                    .with("Count", Object::Integer(n_pages as i64)),
            ),
        },
    )?;

    // /Info
    let info_off_opt = if let Some(info_id) = info_id_opt {
        let off = out.len() as u64;
        write_indirect(
            &mut out,
            &IndirectObject {
                id: info_id,
                object: Object::Dict(build_info_dict(&scene.metadata)),
            },
        )?;
        Some(off)
    } else {
        None
    };

    // Part 5: hint stream
    let hint_stream_off = out.len() as u64;
    let hint_data = build_page_offset_hint_table(n_pages);
    let hint_dict = Dict::new()
        // /S = byte offset of shared-object hint table inside the
        // (decoded) hint stream. We don't emit a shared-object table;
        // pointing past EOS is the conventional sentinel.
        .with("S", Object::Integer(hint_data.len() as i64));
    write_indirect(
        &mut out,
        &IndirectObject {
            id: hint_stream_id,
            object: Object::Stream(Stream::new(hint_dict, hint_data)),
        },
    )?;
    let hint_stream_end = out.len() as u64;
    let hint_stream_total_len = hint_stream_end - hint_stream_off;

    // Part 6: first-page section
    let first_page_off = out.len() as u64;
    write_indirect(
        &mut out,
        &IndirectObject {
            id: first_page_id,
            object: Object::Dict(
                Dict::new()
                    .with("Type", Object::Name("Page".into()))
                    .with("Parent", Object::Reference(pages_tree_id))
                    .with(
                        "MediaBox",
                        Object::Array(vec![
                            Object::Real(0.0),
                            Object::Real(0.0),
                            Object::Real(first_page_owned.width as f64),
                            Object::Real(first_page_owned.height as f64),
                        ]),
                    )
                    .with("Resources", Object::Reference(first_page_resources_id))
                    .with("Contents", Object::Reference(first_page_contents_id)),
            ),
        },
    )?;

    let first_resources_off = out.len() as u64;
    write_indirect(
        &mut out,
        &IndirectObject {
            id: first_page_resources_id,
            object: first_page_owned.resources_dict.clone(),
        },
    )?;

    // First-page resource extras
    let mut first_extra_offs: Vec<u64> = Vec::with_capacity(first_page_owned.extra_objects.len());
    for (i, body) in first_page_owned.extra_objects.iter().enumerate() {
        first_extra_offs.push(out.len() as u64);
        write_indirect(
            &mut out,
            &IndirectObject {
                id: first_page_extra_ids[i],
                object: body.clone(),
            },
        )?;
    }

    let first_contents_off = out.len() as u64;
    write_indirect(
        &mut out,
        &IndirectObject {
            id: first_page_contents_id,
            object: Object::Stream(Stream::new(
                Dict::new(),
                first_page_owned.content_bytes.clone(),
            )),
        },
    )?;

    // /E — end of first-page section.
    let end_of_first_page = out.len() as u64;

    // Part 7: remaining pages
    let mut g2_page_offs = Vec::with_capacity(g2_owned.len());
    let mut g2_resources_offs = Vec::with_capacity(g2_owned.len());
    let mut g2_contents_offs = Vec::with_capacity(g2_owned.len());
    let mut g2_extra_offs: Vec<Vec<u64>> = Vec::with_capacity(g2_owned.len());

    for (idx, owned) in g2_owned.iter().enumerate() {
        g2_page_offs.push(out.len() as u64);
        write_indirect(
            &mut out,
            &IndirectObject {
                id: g2_page_ids[idx],
                object: Object::Dict(
                    Dict::new()
                        .with("Type", Object::Name("Page".into()))
                        .with("Parent", Object::Reference(pages_tree_id))
                        .with(
                            "MediaBox",
                            Object::Array(vec![
                                Object::Real(0.0),
                                Object::Real(0.0),
                                Object::Real(owned.width as f64),
                                Object::Real(owned.height as f64),
                            ]),
                        )
                        .with("Resources", Object::Reference(g2_resources_ids[idx]))
                        .with("Contents", Object::Reference(g2_contents_ids[idx])),
                ),
            },
        )?;

        g2_resources_offs.push(out.len() as u64);
        write_indirect(
            &mut out,
            &IndirectObject {
                id: g2_resources_ids[idx],
                object: owned.resources_dict.clone(),
            },
        )?;

        let mut extras_offs = Vec::with_capacity(owned.extra_objects.len());
        for (i, body) in owned.extra_objects.iter().enumerate() {
            extras_offs.push(out.len() as u64);
            write_indirect(
                &mut out,
                &IndirectObject {
                    id: g2_extra_ids[idx][i],
                    object: body.clone(),
                },
            )?;
        }
        g2_extra_offs.push(extras_offs);

        g2_contents_offs.push(out.len() as u64);
        write_indirect(
            &mut out,
            &IndirectObject {
                id: g2_contents_ids[idx],
                object: Object::Stream(Stream::new(Dict::new(), owned.content_bytes.clone())),
            },
        )?;
    }

    // Part 11: main xref + trailer
    let main_xref_off = out.len() as u64;
    out.extend_from_slice(b"xref\n");
    writeln!(&mut out, "0 {}", total_ids)
        .map_err(|e| PdfError::other(format!("linearize main-xref header: {e}")))?;
    out.extend_from_slice(b"0000000000 65535 f \n");

    // Build a flat id → offset table.
    let mut all_offs: Vec<u64> = vec![0; total_ids as usize];
    for (i, page_id) in g2_page_ids.iter().enumerate() {
        all_offs[page_id.number as usize] = g2_page_offs[i];
        all_offs[g2_resources_ids[i].number as usize] = g2_resources_offs[i];
        all_offs[g2_contents_ids[i].number as usize] = g2_contents_offs[i];
        for (j, off) in g2_extra_offs[i].iter().enumerate() {
            all_offs[g2_extra_ids[i][j].number as usize] = *off;
        }
    }
    all_offs[catalog_id.number as usize] = catalog_off;
    all_offs[pages_tree_id.number as usize] = pages_tree_off;
    if let (Some(info_id), Some(off)) = (info_id_opt, info_off_opt) {
        all_offs[info_id.number as usize] = off;
    }
    all_offs[lin_param_id.number as usize] = lin_param_off;
    all_offs[first_page_id.number as usize] = first_page_off;
    all_offs[first_page_resources_id.number as usize] = first_resources_off;
    all_offs[first_page_contents_id.number as usize] = first_contents_off;
    for (i, off) in first_extra_offs.iter().enumerate() {
        all_offs[first_page_extra_ids[i].number as usize] = *off;
    }
    all_offs[hint_stream_id.number as usize] = hint_stream_off;

    for id in 1..total_ids {
        let off = all_offs[id as usize];
        writeln!(&mut out, "{:010} {:05} n ", off, 0)
            .map_err(|e| PdfError::other(format!("linearize main-xref entry: {e}")))?;
    }

    out.extend_from_slice(b"trailer\n");
    let mut main_trailer = Dict::new()
        .with("Size", Object::Integer(total_ids as i64))
        .with("Root", Object::Reference(catalog_id));
    if let Some(info_id) = info_id_opt {
        main_trailer.set("Info", Object::Reference(info_id));
    }
    let mut main_trailer_bytes = Vec::new();
    write_object_to_vec(&mut main_trailer_bytes, &Object::Dict(main_trailer))?;
    out.extend_from_slice(&main_trailer_bytes);
    out.extend_from_slice(b"\nstartxref\n");
    writeln!(&mut out, "{}", first_xref_off)
        .map_err(|e| PdfError::other(format!("linearize startxref: {e}")))?;
    out.extend_from_slice(b"%%EOF\n");

    let total_file_length = out.len() as u64;

    // ---- Pass 2: patch placeholder values --------------------------
    // /L, /H[0], /H[1], /E, /T in the linearization param dict
    patch_padded_int(&mut out, lin_param_off as usize, b"/L ", total_file_length)?;
    patch_padded_int(&mut out, lin_param_off as usize, b"/H [ ", hint_stream_off)?;
    {
        // /H's second integer immediately follows the first (10 digits + 1 space)
        let anchor = b"/H [ ";
        let pos = find_anchor(&out, lin_param_off as usize, anchor)?;
        let after_first = pos + anchor.len() + 11; // 10 digits + 1 space
        write_padded_at(&mut out, after_first, hint_stream_total_len)?;
    }
    patch_padded_int(&mut out, lin_param_off as usize, b"/E ", end_of_first_page)?;
    patch_padded_int(&mut out, lin_param_off as usize, b"/T ", main_xref_off)?;

    // /Prev in the first-page trailer (also 10-digit padded)
    write_padded_at(&mut out, prev_patch_off, main_xref_off)?;

    // First-page startxref (points at first-page xref offset itself)
    write_padded_at(&mut out, first_startxref_value_off as usize, first_xref_off)?;

    // First-page xref entries
    {
        let mut entry_off = first_xref_entries_off as usize;
        for id in first_group_start..(first_group_start + first_group_count) {
            let off = all_offs[id as usize];
            let line = format!("{:010} {:05} n \n", off, 0);
            debug_assert_eq!(line.len(), 20);
            out[entry_off..entry_off + 20].copy_from_slice(line.as_bytes());
            entry_off += 20;
        }
    }

    Ok(out)
}

// ---- Internal helpers ------------------------------------------------

struct RenderedOwned {
    width: f32,
    height: f32,
    content_bytes: Vec<u8>,
    resources: ResourceCollector,
}

struct OwnedPage {
    width: f32,
    height: f32,
    content_bytes: Vec<u8>,
    /// The flattened /Resources dict (an [`Object::Dict`]). It refers
    /// to extras by [`ObjectId`] — those ids are seeded by the
    /// throwaway Document used during pre-flattening; we remap them
    /// to the final ids in [`remap_owned_page`].
    resources_dict: Object,
    /// Sub-objects (IndirectObject = id + body) allocated by
    /// [`ResourceCollector`] — gradient streams, image XObjects,
    /// function dicts. Their `id.number` values are placeholders and
    /// get rewritten in [`remap_owned_page`] too.
    extra_objects: Vec<IndirectObject>,
}

struct OwnedPageRemapped {
    width: f32,
    height: f32,
    content_bytes: Vec<u8>,
    resources_dict: Object,
    /// Bodies only — the final ids are tracked separately via the
    /// per-page id arrays passed to [`remap_owned_page`].
    extra_objects: Vec<Object>,
}

/// Walk `page` and rewrite every reference whose target matches a
/// placeholder id (the id assigned by the throwaway Document during
/// pre-flatten) to the matching `final_ids[i]`. The mapping is
/// established by the position of each extra in `page.extra_objects`
/// — extras[i] had placeholder id `extras[i].id`, and the desired
/// final id is `final_ids[i]`.
fn remap_owned_page(page: &OwnedPage, final_ids: &[ObjectId]) -> OwnedPageRemapped {
    use std::collections::HashMap;
    let placeholder_to_final: HashMap<u32, ObjectId> = page
        .extra_objects
        .iter()
        .enumerate()
        .map(|(i, ind)| (ind.id.number, final_ids[i]))
        .collect();
    let mut resources_dict = page.resources_dict.clone();
    remap_object(&mut resources_dict, &placeholder_to_final);
    let extras: Vec<Object> = page
        .extra_objects
        .iter()
        .map(|ind| {
            let mut body = ind.object.clone();
            remap_object(&mut body, &placeholder_to_final);
            body
        })
        .collect();
    OwnedPageRemapped {
        width: page.width,
        height: page.height,
        content_bytes: page.content_bytes.clone(),
        resources_dict,
        extra_objects: extras,
    }
}

fn remap_object(obj: &mut Object, map: &std::collections::HashMap<u32, ObjectId>) {
    match obj {
        Object::Reference(id) => {
            if let Some(&new_id) = map.get(&id.number) {
                *id = new_id;
            }
        }
        Object::Array(items) => {
            for it in items {
                remap_object(it, map);
            }
        }
        Object::Dict(d) => {
            let entries = d.entries().to_vec();
            *d = Dict::new();
            for (k, mut v) in entries {
                remap_object(&mut v, map);
                d.set(&k, v);
            }
        }
        Object::Stream(s) => {
            let entries = s.dict.entries().to_vec();
            s.dict = Dict::new();
            for (k, mut v) in entries {
                remap_object(&mut v, map);
                s.dict.set(&k, v);
            }
        }
        _ => {}
    }
}

fn write_indirect(out: &mut Vec<u8>, ind: &IndirectObject) -> Result<(), PdfError> {
    writeln!(out, "{} {} obj", ind.id.number, ind.id.generation)
        .map_err(|e| PdfError::other(format!("write_indirect: {e}")))?;
    write_object_to_vec(out, &ind.object)?;
    out.extend_from_slice(b"\nendobj\n");
    Ok(())
}

fn write_object_to_vec(out: &mut Vec<u8>, obj: &Object) -> Result<(), PdfError> {
    crate::objects::write_object_to(out, obj).map_err(PdfError::Io)
}

/// Emit the first-page trailer dict with an explicit 10-digit /Prev
/// placeholder. We hand-roll this rather than use `write_object`
/// because the Object tree's Integer printer would emit `0`, not
/// `0000000000`, and `write_object` doesn't expose the formatter.
fn write_first_page_trailer_dict(
    out: &mut Vec<u8>,
    size: u32,
    root: ObjectId,
    info: Option<ObjectId>,
    prev_placeholder: u64,
) -> Result<(), PdfError> {
    write!(out, "<< /Size {} /Root {} 0 R", size, root.number)
        .map_err(|e| PdfError::other(format!("first-trailer dict: {e}")))?;
    if let Some(info_id) = info {
        write!(out, " /Info {} 0 R", info_id.number)
            .map_err(|e| PdfError::other(format!("first-trailer dict: {e}")))?;
    }
    write!(out, " /Prev {:010} >>", prev_placeholder)
        .map_err(|e| PdfError::other(format!("first-trailer dict: {e}")))?;
    Ok(())
}

/// Locate the byte offset of the first digit of `/Prev <int>` inside
/// the first-page trailer dict, scanning from `first_xref_section_off`
/// onwards.
fn first_trailer_prev_offset(out: &[u8], first_xref_section_off: usize) -> usize {
    let needle = b"/Prev ";
    let pos = out[first_xref_section_off..]
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("first-page trailer must carry /Prev");
    first_xref_section_off + pos + needle.len()
}

/// Scan `hay[start..]` for `anchor`. Returns the byte position of
/// `anchor` (relative to `hay[0]`).
fn find_anchor(hay: &[u8], start: usize, anchor: &[u8]) -> Result<usize, PdfError> {
    hay[start..]
        .windows(anchor.len())
        .position(|w| w == anchor)
        .map(|p| start + p)
        .ok_or_else(|| {
            PdfError::other(format!(
                "linearize patch: anchor `{}` not found",
                String::from_utf8_lossy(anchor)
            ))
        })
}

/// Patch a 10-digit zero-padded integer that follows `anchor` in
/// `out[start..]` to `value`.
fn patch_padded_int(
    out: &mut [u8],
    start: usize,
    anchor: &[u8],
    value: u64,
) -> Result<(), PdfError> {
    let anchor_pos = out[start..]
        .windows(anchor.len())
        .position(|w| w == anchor)
        .ok_or_else(|| {
            PdfError::other(format!(
                "linearize patch: anchor `{}` not found",
                String::from_utf8_lossy(anchor)
            ))
        })?;
    write_padded_at(out, start + anchor_pos + anchor.len(), value)
}

fn write_padded_at(out: &mut [u8], at: usize, value: u64) -> Result<(), PdfError> {
    if value > 9_999_999_999 {
        return Err(PdfError::other(format!(
            "linearize patch: value {} exceeds 10-digit width",
            value
        )));
    }
    let s = format!("{:010}", value);
    if at + s.len() > out.len() {
        return Err(PdfError::other("linearize patch: write past EOF"));
    }
    out[at..at + s.len()].copy_from_slice(s.as_bytes());
    Ok(())
}

/// Build the page offset hint table per Tables F.3 + F.4.
///
/// Round-9 emits the minimum-information form: every "bits-needed"
/// header field is 0 (every page is reported as having the least
/// number of objects, the least page length, etc.), so the per-page
/// entries collapse to nothing. The 36-byte header still lands at
/// offset 0 of the hint stream as required by F.3.6.
///
/// Header field widths (bits): 32 + 32 + 16 + 32 + 16 + 32 + 16 + 32
/// + 16 + 16 + 16 + 16 + 16 = 288 bits = 36 bytes.
fn build_page_offset_hint_table(_n_pages: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(36);
    // Item 1 (32): least objects per page = 3 (Page + Resources + Contents)
    buf.extend_from_slice(&3u32.to_be_bytes());
    // Item 2 (32): location of first page's page object = 0 (placeholder)
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Item 3 (16): bits-needed for max-min objects/page delta = 0
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Item 4 (32): least page length in bytes = 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Item 5 (16): bits-needed for page length delta = 0
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Item 6 (32): least content stream offset = 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Item 7 (16): bits-needed for content stream offset delta = 0
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Item 8 (32): least content stream length = 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Item 9 (16): bits-needed for content stream length delta = 0
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Item 10 (16): bits-needed for max shared-object count per page = 0
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Item 11 (16): bits-needed for shared-object id range = 0
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Item 12 (16): bits-needed for fractional position numerator = 0
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Item 13 (16): denominator for fractional position = 4
    buf.extend_from_slice(&4u16.to_be_bytes());
    debug_assert_eq!(buf.len(), 36);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxideav_core::time::TimeBase;
    use oxideav_core::vector::{
        FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
    };
    use oxideav_scene::Page;

    fn rect_frame(w: f32, h: f32, color: Rgba) -> VectorFrame {
        let mut p = Path::new();
        p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
        p.commands
            .push(PathCommand::LineTo(Point::new(w - 10.0, 10.0)));
        p.commands
            .push(PathCommand::LineTo(Point::new(w - 10.0, h - 10.0)));
        p.commands
            .push(PathCommand::LineTo(Point::new(10.0, h - 10.0)));
        p.commands.push(PathCommand::Close);
        VectorFrame {
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
        }
    }

    fn page_with(w: f32, h: f32, color: Rgba) -> Page {
        let mut page = Page::new(w, h);
        page.content = rect_frame(w, h, color);
        page
    }

    fn single_page_scene() -> Scene {
        Scene {
            pages: Some(vec![page_with(100.0, 100.0, Rgba::opaque(255, 0, 0))]),
            ..Scene::default()
        }
    }

    fn multi_page_scene() -> Scene {
        Scene {
            pages: Some(vec![
                page_with(100.0, 100.0, Rgba::opaque(255, 0, 0)),
                page_with(200.0, 150.0, Rgba::opaque(0, 255, 0)),
                page_with(300.0, 200.0, Rgba::opaque(0, 0, 255)),
            ]),
            ..Scene::default()
        }
    }

    #[test]
    fn linearized_emits_pdf_1_5_header_and_marker() {
        let pdf = write_pdf_linearized(&single_page_scene()).expect("linearize");
        assert!(pdf.starts_with(b"%PDF-1.5\n"));
        // Binary marker on second line.
        assert_eq!(&pdf[9..14], &[0x25, 0xE2, 0xE3, 0xCF, 0xD3]);
        assert!(pdf.ends_with(b"%%EOF\n"));
    }

    /// Decode a PDF byte buffer to a String for substring scanning.
    /// `String::from_utf8_lossy` replaces the binary-marker bytes
    /// (0xE2 0xE3 0xCF 0xD3 on line 2) with U+FFFD, but keeps every
    /// other ASCII byte intact — which is what we need.
    fn pdf_lossy(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn linearization_dict_is_within_first_1024_bytes() {
        // F.3.3: "The linearization parameter dictionary shall be
        // entirely contained within the first 1024 bytes of the PDF
        // file."
        let pdf = write_pdf_linearized(&multi_page_scene()).expect("linearize");
        let head = &pdf[..1024.min(pdf.len())];
        let s = pdf_lossy(head);
        assert!(s.contains("/Linearized 1"), "head must carry /Linearized 1");
        // Find the lin-dict closer.
        let lin_idx = s.find("/Linearized 1").unwrap();
        let close_idx = s[lin_idx..].find(">>").expect("lin-dict close");
        assert!(
            lin_idx + close_idx < 1024,
            "lin-dict must close within first 1024 bytes"
        );
    }

    #[test]
    fn linearization_dict_carries_required_keys() {
        let pdf = write_pdf_linearized(&multi_page_scene()).expect("linearize");
        let s = pdf_lossy(&pdf);
        for key in ["/Linearized", "/L ", "/H [", "/O ", "/E ", "/N ", "/T "] {
            assert!(s.contains(key), "lin-dict missing {key:?}");
        }
    }

    #[test]
    fn linearized_l_matches_actual_file_length() {
        let pdf = write_pdf_linearized(&multi_page_scene()).expect("linearize");
        let actual = pdf.len();
        let head = pdf_lossy(&pdf[..1024.min(pdf.len())]);
        let l_idx = head.find("/L ").unwrap();
        let after = &head[l_idx + 3..];
        let value: u64 = after
            .split_ascii_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(value as usize, actual, "/L must equal actual file length");
    }

    #[test]
    fn n_matches_page_count() {
        let pdf = write_pdf_linearized(&multi_page_scene()).expect("linearize");
        let head = pdf_lossy(&pdf[..1024.min(pdf.len())]);
        let n_idx = head.find("/N ").unwrap();
        let after = &head[n_idx + 3..];
        let value: u64 = after
            .split_ascii_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(value, 3);
    }

    #[test]
    fn startxref_points_at_first_page_xref() {
        let pdf = write_pdf_linearized(&single_page_scene()).expect("linearize");
        let s = pdf_lossy(&pdf);
        let start_off = s.rfind("startxref\n").unwrap() + "startxref\n".len();
        let line: &str = s[start_off..].split('\n').next().unwrap();
        let off: usize = line.trim().parse().unwrap();
        // First-page xref appears at the FIRST `xref\n` occurrence in
        // the byte stream.
        let first_xref_off = pdf
            .windows(b"xref\n".len())
            .position(|w| w == b"xref\n")
            .unwrap();
        assert_eq!(off, first_xref_off);
    }

    #[test]
    fn first_page_trailer_carries_prev() {
        let pdf = write_pdf_linearized(&single_page_scene()).expect("linearize");
        let s = pdf_lossy(&pdf);
        let first_trailer_off = s.find("trailer\n").unwrap();
        let after = &s[first_trailer_off..];
        let close_off = after.find(">>").unwrap();
        let prev_off = after
            .find("/Prev ")
            .expect("first trailer must carry /Prev");
        assert!(prev_off < close_off);
    }

    #[test]
    fn round_trips_through_reader() {
        let pdf = write_pdf_linearized(&multi_page_scene()).expect("linearize");
        let scene = crate::reader::read_pdf_to_scene(&pdf).expect("reader accepts linearized");
        assert_eq!(scene.pages.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn single_page_round_trips() {
        let pdf = write_pdf_linearized(&single_page_scene()).expect("linearize");
        let scene = crate::reader::read_pdf_to_scene(&pdf).expect("reader accepts");
        assert_eq!(scene.pages.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn page_offset_hint_table_is_36_bytes() {
        let table = build_page_offset_hint_table(1);
        assert_eq!(table.len(), 36);
        assert_eq!(&table[0..4], &3u32.to_be_bytes());
        assert_eq!(&table[34..36], &4u16.to_be_bytes());
    }
}
