//! PDF object model and serializer (ISO 32000-1 §7.3 / §7.5).
//!
//! Round 1 ships the minimum surface a single-page writer needs:
//! booleans, numerics, names, strings, arrays, dictionaries, streams,
//! null, indirect references. The crate emits **only** these and walks
//! a [`Document`] of [`IndirectObject`]s into the standard
//! header / body / xref / trailer layout (§7.5.2 — §7.5.5).
//!
//! No parser. The writer never reads back any byte it emits.

use std::io::{self, Write};

use crate::encrypt::EncryptionState;
use crate::error::PdfError;

/// A PDF "any" value — every primitive plus the composite ones.
///
/// Round 1 keeps the variant set tight; future rounds (text, encryption,
/// outlines) can extend without breaking writer-only call sites.
#[derive(Clone, Debug)]
pub enum Object {
    Null,
    Bool(bool),
    Integer(i64),
    Real(f64),
    /// PDF Name object (`/Foo`). The leading slash is added by the
    /// serializer; values must use the unescaped name characters
    /// (ISO 32000-1 §7.3.5 — printable ASCII excluding the delimiters).
    Name(String),
    /// Literal string `(...)` — bytes go through PDF escape rules.
    LiteralString(Vec<u8>),
    /// Hexadecimal string `<...>` — used when content might confuse
    /// the literal-string parser (e.g. images embedded inline).
    HexString(Vec<u8>),
    Array(Vec<Object>),
    Dict(Dict),
    /// Indirect reference (`<n> <gen> R`). Generation is always 0 in
    /// the writer's output (objects never get re-released).
    Reference(ObjectId),
    /// Stream object — dictionary describing the payload + the bytes.
    Stream(Stream),
}

/// Tagged identifier of an indirect object inside a [`Document`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectId {
    pub number: u32,
    pub generation: u16,
}

impl ObjectId {
    pub const fn new(number: u32) -> Self {
        Self {
            number,
            generation: 0,
        }
    }
}

/// A PDF dictionary `<< /Key Value >>`. Iteration order is insertion
/// order so generated PDFs are byte-stable across runs.
#[derive(Clone, Debug, Default)]
pub struct Dict {
    entries: Vec<(String, Object)>,
}

impl Dict {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or overwrite) `key`. Returns `&mut self` for chaining.
    pub fn set(&mut self, key: &str, value: Object) -> &mut Self {
        if let Some(slot) = self.entries.iter_mut().find(|(k, _)| k == key) {
            slot.1 = value;
        } else {
            self.entries.push((key.to_owned(), value));
        }
        self
    }

    /// Insert (or overwrite) and return self by value (builder style).
    pub fn with(mut self, key: &str, value: Object) -> Self {
        self.set(key, value);
        self
    }

    pub fn entries(&self) -> &[(String, Object)] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A PDF stream — its dictionary describes the payload and is required
/// to carry `/Length`. The serializer fills `/Length` from `data.len()`
/// at write time so callers don't have to.
#[derive(Clone, Debug)]
pub struct Stream {
    pub dict: Dict,
    pub data: Vec<u8>,
}

impl Stream {
    /// Wrap raw uncompressed bytes. The serializer adds `/Length`; any
    /// other dictionary entries (filters, decode parameters, type tags)
    /// are the caller's responsibility.
    pub fn new(dict: Dict, data: Vec<u8>) -> Self {
        Self { dict, data }
    }
}

/// One indirect object stored in a [`Document`]. Each gets its own
/// `<n> <gen> obj … endobj` block in the output.
#[derive(Clone, Debug)]
pub struct IndirectObject {
    pub id: ObjectId,
    pub object: Object,
}

/// The whole PDF document — an append-only list of indirect objects
/// plus a /Root reference (and optional /Info reference) for the
/// trailer dictionary.
#[derive(Default)]
pub struct Document {
    objects: Vec<IndirectObject>,
    next_id: u32,
    pub root: Option<ObjectId>,
    /// Optional document-level information dictionary. When set, the
    /// reference is written into the trailer as `/Info <n> <gen> R` —
    /// PDF readers surface the dictionary's `/Title`, `/Author`, etc.
    /// keys as the document's metadata. ISO 32000-1 §14.3.3 also
    /// allows arbitrary additional keys, used by the round-2 writer
    /// to round-trip custom scene metadata.
    pub info: Option<ObjectId>,
    /// Optional encryption state. When set, every string and stream
    /// payload in the body is encrypted via the standard handler
    /// (Algorithms 1 + 4/5 / 8/9 / etc.) and the trailer carries
    /// `/Encrypt <n> 0 R` + a matching `/ID` array. The dictionary
    /// itself (the Encrypt object) is **not** encrypted — see
    /// ISO 32000-1 §7.6.1.
    pub encryption: Option<EncryptionState>,
    /// When `true`, [`Self::write_to`] emits a PDF 1.5+ cross-reference
    /// *stream* (`/Type /XRef`, ISO 32000-1 §7.5.8) instead of the
    /// classical `xref`-keyword table. The trailer dict is folded into
    /// the stream's own dictionary (per §7.5.8.2), so the file no
    /// longer carries a separate `trailer << ... >>` block.
    ///
    /// The xref stream uses `/W [1 4 2]` — one byte for the entry
    /// type, four bytes for the offset (or compressed-stream id), two
    /// bytes for the generation (or in-stream index). The body is
    /// flate-compressed with the PNG-Up `/Predictor 12` so the
    /// reader's predictor reversal is exercised end-to-end.
    pub xref_stream: bool,
    /// When `true` (and [`Self::xref_stream`] is also `true`),
    /// [`Self::write_to`] packs every compressible indirect object
    /// (non-stream, non-Encrypt, non-Catalog-when-flagged) into one
    /// `/Type /ObjStm` container per ISO 32000-1 §7.5.7. The xref
    /// stream's type-2 entries point at the container; the round-7
    /// reader's [`crate::reader::DocumentReader::resolve`] follows
    /// them. Implies a PDF 1.5+ header (already implied by
    /// [`Self::xref_stream`]).
    ///
    /// Stream objects (content streams, image XObjects, the xref
    /// stream itself, the encryption-metadata stream, etc.) cannot
    /// live inside an ObjStm (§7.5.7) and remain at their own byte
    /// offsets. The Encrypt indirect object (when set) is excluded
    /// because §7.6.1 forbids it from being compressed.
    pub object_stream: bool,
    /// Optional pointer at a previous cross-reference section's byte
    /// offset. When `Some(off)`, the trailer dict (or, with
    /// [`Self::xref_stream`], the xref-stream dict) carries
    /// `/Prev <off>` per ISO 32000-1 §7.5.6 — the marker that lets a
    /// reader walk a chain of incremental updates. Set by
    /// [`crate::write_pdf_incremental_update`] on the new revision's
    /// document; unused for one-shot writes.
    pub prev_xref_offset: Option<u64>,
    /// When emitting an incremental update, the reader's view of
    /// `/Size` must be at least the original revision's `/Size` —
    /// this honours that minimum even when the new revision adds
    /// only one or two indirect objects past the old maximum.
    pub min_size: Option<u32>,
    /// When emitting an incremental update, the body section is
    /// appended to a previous file's bytes. The xref subsection
    /// header(s) the writer emits must list only the *changed* slots
    /// and skip the unchanged ones. When set, the xref emitter (both
    /// classical and stream forms) groups slots into contiguous
    /// subsections covering only these ids (and id 0 for the
    /// free-list head); when `None` the writer emits one subsection
    /// covering `[0, max_id]`.
    pub xref_only_ids: Option<Vec<u32>>,
}

impl Document {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            next_id: 1,
            root: None,
            info: None,
            encryption: None,
            xref_stream: false,
            object_stream: false,
            prev_xref_offset: None,
            min_size: None,
            xref_only_ids: None,
        }
    }

    /// Pre-seed the next-id allocator past `max_id`. Used by the
    /// incremental-update writer to make new objects pick up after
    /// the previous revision's maximum id.
    pub fn set_next_id(&mut self, next_id: u32) {
        self.next_id = next_id;
    }

    /// The next id [`Self::allocate_id`] will hand out. Useful for
    /// the incremental-update writer to know where the new revision's
    /// id range starts.
    pub fn next_id(&self) -> u32 {
        self.next_id
    }

    /// Reserve a fresh id without committing the object body. Useful
    /// when two objects need to reference each other (page → resources,
    /// resources → page); allocate both ids first, then fill them in.
    pub fn allocate_id(&mut self) -> ObjectId {
        let id = ObjectId::new(self.next_id);
        self.next_id += 1;
        id
    }

    /// Add an object that already has an id (one obtained via
    /// [`Self::allocate_id`]).
    pub fn add_object(&mut self, id: ObjectId, object: Object) {
        self.objects.push(IndirectObject { id, object });
    }

    /// Allocate-and-add in one step. Returns the assigned id.
    pub fn add(&mut self, object: Object) -> ObjectId {
        let id = self.allocate_id();
        self.add_object(id, object);
        id
    }

    /// Number of indirect objects committed so far.
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Borrow the object body of the indirect object at `id` for
    /// mutation. Used by writer code paths that need to extend the
    /// catalog dictionary after [`crate::page::build_pages`] has
    /// returned (e.g. to attach `/Metadata <ref>` per ISO 32000-1
    /// §14.3.2). Returns `None` when `id` was never committed.
    pub fn object_mut(&mut self, id: ObjectId) -> Option<&mut Object> {
        self.objects
            .iter_mut()
            .find(|o| o.id == id)
            .map(|o| &mut o.object)
    }

    /// Walk this document into the on-wire layout: header + body +
    /// xref + trailer + startxref. Bytes for sub-objects are emitted
    /// in insertion order.
    pub fn write_to(&self, out: &mut Vec<u8>) -> Result<(), PdfError> {
        let root = self
            .root
            .ok_or_else(|| PdfError::other("Document::write_to: missing /Root reference"))?;
        if self.object_stream && !self.xref_stream {
            return Err(PdfError::other(
                "Document::write_to: object_stream=true requires xref_stream=true (ObjStm \
                 containers can only be referenced from a /Type /XRef stream — \
                 ISO 32000-1 §7.5.7)",
            ));
        }
        // ---- Header ---------------------------------------------------
        // PDF 1.4 magic + the four >0x80 bytes that mark the file as
        // binary so PDF readers don't treat it as ASCII (ISO 32000-1
        // §7.5.2). Any byte ≥0x80 satisfies the rule; we use 0xE2 0xE3
        // 0xCF 0xD3 — the canonical pdftk / Acrobat marker.
        //
        // Skip the header when we're appending an incremental update —
        // the previous revision's bytes already carry one (§7.5.6).
        if self.prev_xref_offset.is_none() {
            let header_version: &[u8] = if self
                .encryption
                .as_ref()
                .map(|e| e.handler.revision >= 5)
                .unwrap_or(false)
            {
                // V=5 was introduced in PDF 1.7 + ISO 32000-2 (2.0). Bump
                // the magic so PDF 2.0 readers don't flag the file as
                // pre-1.7-using-1.7-features.
                b"%PDF-2.0\n"
            } else if self.xref_stream {
                // XRef streams require PDF 1.5+ readers (§7.5.8). Bump
                // the header so older parsers refuse the file rather than
                // silently misinterpreting the cross-reference section.
                b"%PDF-1.5\n"
            } else {
                b"%PDF-1.4\n"
            };
            out.extend_from_slice(header_version);
            out.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");
        }

        // ---- ObjStm packing happens BEFORE encryption ---------------
        // §7.5.7 + §7.6.1 interaction: when an ObjStm container lives
        // inside an encrypted file, the *container body* is encrypted
        // as one unit (per the ObjStm container's own object id), but
        // strings and stream bodies inside the compressed objects are
        // NOT separately encrypted ("In an encrypted file (i.e., entire
        // object stream is encrypted), strings occurring anywhere in
        // an object stream shall not be separately encrypted." —
        // §7.5.7). So the partition has to happen first, leaving the
        // compressible bodies cleartext while the kept (non-objstm)
        // objects still go through per-object encryption below.
        let mut objects_to_emit: Vec<IndirectObject> = self.objects.clone();
        let mut compressed_map: std::collections::HashMap<u32, (u32, u32)> =
            std::collections::HashMap::new();
        let objstm_id_opt: Option<ObjectId> = if self.object_stream {
            let mut compressible: Vec<IndirectObject> = Vec::new();
            let mut keep: Vec<IndirectObject> = Vec::new();
            for ind in objects_to_emit.drain(..) {
                let is_stream = matches!(ind.object, Object::Stream(_));
                let is_root = ind.id == root;
                if !is_stream && !is_root {
                    compressible.push(ind);
                } else {
                    keep.push(ind);
                }
            }
            objects_to_emit = keep;

            if compressible.is_empty() {
                None
            } else {
                // Allocate a fresh id for the ObjStm container past
                // every existing object id.
                let max_kept = objects_to_emit
                    .iter()
                    .map(|o| o.id.number)
                    .max()
                    .unwrap_or(0);
                let max_compressed = compressible.iter().map(|o| o.id.number).max().unwrap_or(0);
                // Reserve room for an Encrypt id past max_kept too,
                // because encryption assigns the Encrypt id from
                // `objects_to_emit.iter().map(id).max() + 1` after we
                // return — bump by 2 here so the ObjStm id and any
                // future Encrypt id can both be placed without clash.
                let mut next_id = max_kept
                    .max(max_compressed)
                    .max(self.next_id.saturating_sub(1))
                    + 1;
                if self.encryption.is_some() {
                    // Leave one id slot for the /Encrypt indirect
                    // object that gets allocated below.
                    next_id += 1;
                }
                let objstm_id = ObjectId::new(next_id);

                // §7.5.7: header is a whitespace-separated sequence of
                // `obj_num offset` decimal pairs (offsets relative to
                // /First, the start of the body region in the *decoded*
                // stream); body is the concatenation of each compressed
                // object's serialised form (no wrappers).
                let mut bodies: Vec<Vec<u8>> = Vec::with_capacity(compressible.len());
                for ind in &compressible {
                    let mut b = Vec::new();
                    write_object(&mut b, &ind.object).map_err(PdfError::Io)?;
                    bodies.push(b);
                }
                let mut header = String::new();
                let mut running = 0usize;
                for (ind, body) in compressible.iter().zip(bodies.iter()) {
                    if !header.is_empty() {
                        header.push(' ');
                    }
                    header.push_str(&format!("{} {}", ind.id.number, running));
                    running += body.len();
                }
                header.push(' ');

                let header_bytes = header.into_bytes();
                let first = header_bytes.len();
                let n_compressed = compressible.len();

                let mut payload =
                    Vec::with_capacity(first + bodies.iter().map(|b| b.len()).sum::<usize>());
                payload.extend_from_slice(&header_bytes);
                for body in &bodies {
                    payload.extend_from_slice(body);
                }

                let compressed = flate_compress(&payload);

                let dict = Dict::new()
                    .with("Type", Object::Name("ObjStm".into()))
                    .with("N", Object::Integer(n_compressed as i64))
                    .with("First", Object::Integer(first as i64))
                    .with("Filter", Object::Name("FlateDecode".into()));

                objects_to_emit.push(IndirectObject {
                    id: objstm_id,
                    object: Object::Stream(Stream::new(dict, compressed)),
                });

                for (idx, ind) in compressible.into_iter().enumerate() {
                    compressed_map.insert(ind.id.number, (objstm_id.number, idx as u32));
                }

                Some(objstm_id)
            }
        } else {
            None
        };

        // ---- Encryption -------------------------------------------------
        // Per-object encryption now runs on the kept set only (the
        // ObjStm container Stream is in `objects_to_emit` and gets its
        // body encrypted as a unit; the compressed bodies inside it are
        // NOT separately encrypted — §7.5.7). The Encrypt indirect
        // object itself is NOT encrypted (§7.6.1).
        let encrypt_id_opt: Option<ObjectId> = if let Some(state) = &self.encryption {
            let max_id_now = objects_to_emit
                .iter()
                .map(|o| o.id.number)
                .max()
                .unwrap_or(0);
            let id = ObjectId::new(max_id_now + 1);
            for ind in &mut objects_to_emit {
                encrypt_object_in_place(&mut ind.object, ind.id, state)?;
            }
            objects_to_emit.push(IndirectObject {
                id,
                object: Object::Dict(state.encrypt_dict.clone()),
            });
            Some(id)
        } else {
            None
        };

        // ---- XRef-stream branch: the cross-reference itself is an
        // indirect object so we have to allocate its id BEFORE we
        // emit the body (its offset depends on its position, but its
        // own xref entry has to know its id to record itself). We
        // pre-allocate the id and add a placeholder Stream that the
        // post-body fix-up populates with the real binary table.
        let xref_stream_id_opt: Option<ObjectId> = if self.xref_stream {
            let mut max_existing = objects_to_emit
                .iter()
                .map(|o| o.id.number)
                .max()
                .unwrap_or(0);
            // Account for any previously-allocated next_id (incremental
            // updates) — the xref stream's id must not clash with an
            // id that was reserved but not yet committed.
            if self.next_id.saturating_sub(1) > max_existing {
                max_existing = self.next_id - 1;
            }
            // Account for compressed-object ids (they're not in
            // `objects_to_emit` after the ObjStm-packing drain, but
            // they still occupy id slots in the cross-reference).
            if let Some(top) = compressed_map.keys().max() {
                if *top > max_existing {
                    max_existing = *top;
                }
            }
            Some(ObjectId::new(max_existing + 1))
        } else {
            None
        };

        // ---- Body -----------------------------------------------------
        // Sort by id so the xref subsection slot table lines up neatly.
        objects_to_emit.sort_by_key(|o| o.id.number);

        // Offsets[i] = byte offset of the indirect object whose id is
        // (i+1). Slot 0 of the xref is reserved for the head of the
        // free list (always entry `0000000000 65535 f`).
        let body_max_id = objects_to_emit
            .last()
            .map(|o| o.id.number as usize)
            .unwrap_or(0);
        let mut max_id = match xref_stream_id_opt {
            Some(id) => id.number as usize,
            None => body_max_id,
        };
        // Compressed-only ids might exceed body_max_id when the ObjStm
        // container has fewer ids than the original objects.
        if let Some(top) = compressed_map.keys().max() {
            max_id = max_id.max(*top as usize);
        }
        // Honour the requested minimum (incremental updates: trailer
        // /Size must be at least the previous revision's value).
        if let Some(min) = self.min_size {
            if (min as usize) > max_id + 1 {
                max_id = (min as usize).saturating_sub(1);
            }
        }
        let mut offsets: Vec<u64> = vec![0; max_id + 1];

        for ind in &objects_to_emit {
            let off = out.len() as u64;
            offsets[ind.id.number as usize] = off;
            write_indirect(out, ind).map_err(PdfError::Io)?;
        }

        // ---- Cross-reference + trailer -------------------------------
        let xref_off = out.len() as u64;
        // Build the subsection list — for a one-shot write, this is
        // [(0, max_id+1)]; for an incremental update, only the changed
        // ids land in subsections (plus id 0 if not already excluded).
        let subsections: Vec<(u32, u32)> = match &self.xref_only_ids {
            Some(ids) => Self::group_into_subsections(ids),
            None => vec![(0, (max_id + 1) as u32)],
        };

        if let Some(xref_stream_id) = xref_stream_id_opt {
            // Record the xref stream's own offset in the entry table.
            offsets[xref_stream_id.number as usize] = xref_off;
            self.write_xref_stream(
                out,
                xref_stream_id,
                root,
                encrypt_id_opt,
                objstm_id_opt,
                &offsets,
                &compressed_map,
                max_id,
                &subsections,
            )?;
        } else {
            out.extend_from_slice(b"xref\n");
            for (start, count) in &subsections {
                let header_line = format!("{} {}\n", start, count);
                out.extend_from_slice(header_line.as_bytes());
                for id in *start..(*start + *count) {
                    if id == 0 {
                        // Free-list head — slot 0 always 0..f.
                        out.extend_from_slice(b"0000000000 65535 f \n");
                    } else {
                        let off = offsets.get(id as usize).copied().unwrap_or(0);
                        // 10-digit zero-padded byte offset, 5-digit
                        // zero-padded generation, 'n' (in-use), exact
                        // two-character newline terminator per §7.5.4.
                        let line = format!("{:010} {:05} n \n", off, 0);
                        out.extend_from_slice(line.as_bytes());
                    }
                }
            }
            out.extend_from_slice(b"trailer\n");
            let trailer_dict = self.build_trailer_dict(root, encrypt_id_opt, max_id);
            let trailer = Object::Dict(trailer_dict);
            write_object(out, &trailer).map_err(PdfError::Io)?;
            out.extend_from_slice(b"\n");
        }
        out.extend_from_slice(b"startxref\n");
        out.extend_from_slice(format!("{}\n", xref_off).as_bytes());
        out.extend_from_slice(b"%%EOF\n");

        Ok(())
    }

    /// Group a sorted list of ids into contiguous `(start, count)`
    /// subsections. Used by the incremental-update path to emit only
    /// the changed slots in the new xref section. Id 0 is always
    /// included so the free-list head is rewritten on every revision.
    fn group_into_subsections(ids: &[u32]) -> Vec<(u32, u32)> {
        let mut all = Vec::with_capacity(ids.len() + 1);
        all.push(0);
        all.extend_from_slice(ids);
        all.sort_unstable();
        all.dedup();
        let mut out: Vec<(u32, u32)> = Vec::new();
        let mut iter = all.iter().copied();
        let Some(mut start) = iter.next() else {
            return out;
        };
        let mut prev = start;
        let mut count: u32 = 1;
        for v in iter {
            if v == prev + 1 {
                count += 1;
            } else {
                out.push((start, count));
                start = v;
                count = 1;
            }
            prev = v;
        }
        out.push((start, count));
        out
    }

    /// Build the trailer dict shared between the classical-xref and
    /// xref-stream emission paths. Carries `/Size`, `/Root`, optional
    /// `/Info`, and (when encrypted) `/Encrypt` + `/ID`. When
    /// `prev_xref_offset` is set (incremental update),
    /// `/Prev <prev_off>` is emitted so a reader can chain back to
    /// the previous revision's cross-reference section per
    /// ISO 32000-1 §7.5.6.
    fn build_trailer_dict(
        &self,
        root: ObjectId,
        encrypt_id_opt: Option<ObjectId>,
        max_id: usize,
    ) -> Dict {
        let mut trailer_dict = Dict::new()
            .with("Size", Object::Integer((max_id + 1) as i64))
            .with("Root", Object::Reference(root));
        if let Some(info_id) = self.info {
            trailer_dict.set("Info", Object::Reference(info_id));
        }
        if let Some(prev) = self.prev_xref_offset {
            trailer_dict.set("Prev", Object::Integer(prev as i64));
        }
        if let (Some(eid), Some(state)) = (encrypt_id_opt, &self.encryption) {
            trailer_dict.set("Encrypt", Object::Reference(eid));
            // /ID is required when /Encrypt is present (§7.5.5 +
            // §7.6.3.3). We emit ID[0] == ID[1] (no incremental
            // updates → both halves point to the same permanent
            // identifier).
            let id_array = Object::Array(vec![
                Object::LiteralString(state.file_id.clone()),
                Object::LiteralString(state.file_id.clone()),
            ]);
            trailer_dict.set("ID", id_array);
        }
        trailer_dict
    }

    /// Emit a PDF 1.5+ cross-reference stream (ISO 32000-1 §7.5.8).
    /// `offsets[i]` is the byte offset of the indirect object whose
    /// id is `i`; slot 0 is the free-list head and is encoded as
    /// `(0, 0, 65535)` per §7.5.8.3 (Type 0 entry). Compressed-object
    /// entries (type 2) come from `compressed_map[id] = (container,
    /// index)` and override the type-1 default.
    #[allow(clippy::too_many_arguments)]
    fn write_xref_stream(
        &self,
        out: &mut Vec<u8>,
        xref_id: ObjectId,
        root: ObjectId,
        encrypt_id_opt: Option<ObjectId>,
        objstm_id_opt: Option<ObjectId>,
        offsets: &[u64],
        compressed_map: &std::collections::HashMap<u32, (u32, u32)>,
        max_id: usize,
        subsections: &[(u32, u32)],
    ) -> Result<(), PdfError> {
        // Field widths: type=1 byte, offset=4 bytes (handles ≤4 GiB),
        // generation=2 bytes. PDFs above 4 GiB would need w[1]=8; we
        // guard against the overflow rather than silently truncating.
        const W: [usize; 3] = [1, 4, 2];
        let entry_width = W[0] + W[1] + W[2];

        // Collect every id we're emitting an entry for, in subsection
        // order. The /Index array on the stream dict mirrors
        // `subsections` exactly.
        let mut emit_ids: Vec<u32> = Vec::new();
        for (start, count) in subsections {
            for id in *start..(*start + *count) {
                emit_ids.push(id);
            }
        }
        let n_entries = emit_ids.len();
        let mut raw_table = Vec::with_capacity(n_entries * entry_width);

        for id in &emit_ids {
            if *id == 0 {
                // Slot 0 — free-list head. Type 0, next=0, gen=65535.
                raw_table.push(0);
                raw_table.extend_from_slice(&0u32.to_be_bytes());
                raw_table.extend_from_slice(&65535u16.to_be_bytes());
            } else if let Some((container, idx)) = compressed_map.get(id).copied() {
                // Type 2 — compressed inside an ObjStm container.
                raw_table.push(2);
                raw_table.extend_from_slice(&container.to_be_bytes());
                raw_table.extend_from_slice(&(idx as u16).to_be_bytes());
            } else {
                let off = offsets.get(*id as usize).copied().unwrap_or(0);
                if off > u32::MAX as u64 {
                    return Err(PdfError::other(format!(
                        "Document::write_xref_stream: object {id} offset {off} exceeds 32-bit\
                         limit — bump /W[1] to 8 bytes"
                    )));
                }
                raw_table.push(1);
                raw_table.extend_from_slice(&(off as u32).to_be_bytes());
                raw_table.extend_from_slice(&0u16.to_be_bytes());
            }
        }

        // PNG-Up forward predictor (tag 2): each row is `entry[i] -
        // prev[i]` (mod 256). Match the round-6 reader's reversal.
        let mut predicted = Vec::with_capacity(n_entries * (entry_width + 1));
        let mut prev = vec![0u8; entry_width];
        for chunk in raw_table.chunks_exact(entry_width) {
            predicted.push(0x02); // PNG-Up tag.
            for i in 0..entry_width {
                predicted.push(chunk[i].wrapping_sub(prev[i]));
            }
            prev.copy_from_slice(chunk);
        }

        // FlateDecode the predicted bytes.
        let compressed = flate_compress(&predicted);

        // Build the xref-stream dict — fold trailer entries in.
        let trailer_dict = self.build_trailer_dict(root, encrypt_id_opt, max_id);
        let mut index_array: Vec<Object> = Vec::with_capacity(subsections.len() * 2);
        for (start, count) in subsections {
            index_array.push(Object::Integer(*start as i64));
            index_array.push(Object::Integer(*count as i64));
        }
        let mut stream_dict = Dict::new()
            .with("Type", Object::Name("XRef".into()))
            .with("Filter", Object::Name("FlateDecode".into()))
            .with(
                "DecodeParms",
                Object::Dict(
                    Dict::new()
                        .with("Predictor", Object::Integer(12))
                        .with("Columns", Object::Integer(entry_width as i64)),
                ),
            )
            .with(
                "W",
                Object::Array(vec![
                    Object::Integer(W[0] as i64),
                    Object::Integer(W[1] as i64),
                    Object::Integer(W[2] as i64),
                ]),
            )
            .with("Index", Object::Array(index_array));
        // Copy trailer fields (Size, Root, Info, Prev, Encrypt, ID).
        for (k, v) in trailer_dict.entries() {
            stream_dict.set(k, v.clone());
        }

        let stream = Stream::new(stream_dict, compressed);
        let indirect = IndirectObject {
            id: xref_id,
            object: Object::Stream(stream),
        };
        write_indirect(out, &indirect).map_err(PdfError::Io)?;
        // Suppress unused-variable warning when `objstm_id_opt` is set
        // but the caller doesn't need it here — kept on the signature
        // so future revisions (per-stream encryption opt-out for the
        // ObjStm container itself) can read it without re-threading.
        let _ = objstm_id_opt;
        Ok(())
    }
}

/// FlateDecode helper shared between the xref-stream encoder and any
/// future stream-compression call sites in this module. Keeping it
/// inline avoids a circular import on `resources::flate_compress`.
fn flate_compress(input: &[u8]) -> Vec<u8> {
    crate::zlib::flate_compress(input)
}

/// Recursively encrypt every literal/hex string and stream payload in
/// `obj`, in place, using the per-object key derivation associated with
/// `id`. Numeric / boolean / name / reference values pass through
/// unchanged. Nested dicts and arrays are walked recursively so nested
/// strings (e.g. `/Title (...)` inside an /Info dict) are encrypted.
///
/// Streams whose first `/Filter` is `/Crypt` with a `/Name /Identity`
/// crypt-filter parm (or a missing parm — the default Name is
/// `/Identity` per §7.4.10 Table 24) are explicitly NOT encrypted —
/// this is the §7.6.5 opt-out for "this stream is intentionally
/// cleartext even though the rest of the file is encrypted".
fn encrypt_object_in_place(
    obj: &mut Object,
    id: ObjectId,
    state: &EncryptionState,
) -> Result<(), PdfError> {
    match obj {
        Object::LiteralString(s) | Object::HexString(s) => {
            *s = state.handler.encrypt_object(id, s, &state.aes_iv)?;
        }
        Object::Array(items) => {
            for item in items {
                encrypt_object_in_place(item, id, state)?;
            }
        }
        Object::Dict(d) => {
            encrypt_dict_in_place(d, id, state)?;
        }
        Object::Stream(s) => {
            // Recurse into the dict for any nested string values.
            encrypt_dict_in_place(&mut s.dict, id, state)?;
            // §7.6.5 opt-out: /Filter /Crypt + /DecodeParms /Name
            // /Identity → leave the body untouched.
            if has_identity_crypt_filter(&s.dict) {
                return Ok(());
            }
            // Encrypt the stream body. Note: per §7.6.1, the
            // body-already-Filter-encoded layer is what gets encrypted —
            // FlateDecode etc. are applied first, then the bytes are
            // ciphered.
            s.data = state.handler.encrypt_object(id, &s.data, &state.aes_iv)?;
        }
        _ => {}
    }
    Ok(())
}

/// Match a stream-dict shape that opts out of per-stream encryption
/// per ISO 32000-1 §7.6.5. Mirror of the reader-side detector in
/// [`crate::reader::document`]; kept private here so the encoder
/// doesn't need to round-trip through the reader.
fn has_identity_crypt_filter(dict: &Dict) -> bool {
    let filter = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Filter")
        .map(|(_, v)| v);
    let parms = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "DecodeParms")
        .map(|(_, v)| v);
    let crypt_pos: Option<usize> = match filter {
        Some(Object::Name(s)) if s == "Crypt" => Some(0),
        Some(Object::Array(items)) => items
            .iter()
            .position(|f| matches!(f, Object::Name(n) if n == "Crypt")),
        _ => None,
    };
    let Some(idx) = crypt_pos else {
        return false;
    };
    let parms_dict = match parms {
        Some(Object::Dict(d)) if idx == 0 => Some(d.clone()),
        Some(Object::Array(items)) => match items.get(idx) {
            Some(Object::Dict(d)) => Some(d.clone()),
            _ => None,
        },
        _ => None,
    };
    let Some(d) = parms_dict else {
        return true;
    };
    match d
        .entries()
        .iter()
        .find(|(k, _)| k == "Name")
        .map(|(_, v)| v)
    {
        Some(Object::Name(s)) => s == "Identity",
        None => true,
        _ => false,
    }
}

fn encrypt_dict_in_place(
    d: &mut Dict,
    id: ObjectId,
    state: &EncryptionState,
) -> Result<(), PdfError> {
    let mut new_entries: Vec<(String, Object)> = Vec::with_capacity(d.entries().len());
    for (k, v) in d.entries() {
        let mut v = v.clone();
        encrypt_object_in_place(&mut v, id, state)?;
        new_entries.push((k.clone(), v));
    }
    *d = Dict::default();
    for (k, v) in new_entries {
        d.set(&k, v);
    }
    Ok(())
}

/// Crate-private re-export of [`write_object`] for the linearize
/// module — it serialises one [`Object`] body into a byte buffer using
/// exactly the same shape as [`Document::write_to`] does internally
/// (so /Length on streams gets auto-patched, etc.). Kept private to
/// the crate so external callers don't depend on the writer's
/// internals.
pub(crate) fn write_object_to(out: &mut Vec<u8>, obj: &Object) -> io::Result<()> {
    write_object(out, obj)
}

/// Drain every [`IndirectObject`] from `doc` into a fresh `Vec`,
/// in insertion order. Used by the linearize module to capture the
/// gradient / image sub-objects allocated by
/// [`crate::resources::ResourceCollector::flatten_into_resources_dict`]
/// without having to re-implement that walker.
pub(crate) fn take_objects(doc: &mut Document) -> Vec<IndirectObject> {
    std::mem::take(&mut doc.objects)
}

fn write_indirect(out: &mut Vec<u8>, ind: &IndirectObject) -> io::Result<()> {
    let header = format!("{} {} obj\n", ind.id.number, ind.id.generation);
    out.write_all(header.as_bytes())?;
    write_object(out, &ind.object)?;
    out.write_all(b"\nendobj\n")?;
    Ok(())
}

fn write_object(out: &mut Vec<u8>, obj: &Object) -> io::Result<()> {
    match obj {
        Object::Null => out.write_all(b"null"),
        Object::Bool(b) => out.write_all(if *b { b"true" } else { b"false" }),
        Object::Integer(n) => out.write_all(format!("{}", n).as_bytes()),
        Object::Real(f) => out.write_all(format_real(*f).as_bytes()),
        Object::Name(s) => {
            out.write_all(b"/")?;
            // Per §7.3.5, characters 0x21..=0x7E that are not delimiters
            // are emitted verbatim; everything else uses #xx hex
            // escapes. Round-1 callers only generate names from a
            // closed alphabet (Page, Pages, Catalog, GS<n>, Pat<n>,
            // Im<n>, etc.) so the loop almost always falls through to
            // the verbatim path — but the escape is here for safety.
            for &b in s.as_bytes() {
                let needs_escape = matches!(
                    b,
                    0x00..=0x20 | 0x23 | 0x25 | 0x28 | 0x29 | 0x2F | 0x3C | 0x3E | 0x5B | 0x5D
                        | 0x7B | 0x7D | 0x7F..=0xFF
                );
                if needs_escape {
                    out.write_all(format!("#{:02X}", b).as_bytes())?;
                } else {
                    out.write_all(&[b])?;
                }
            }
            Ok(())
        }
        Object::LiteralString(bytes) => {
            out.write_all(b"(")?;
            for &b in bytes {
                match b {
                    b'\\' => out.write_all(br"\\")?,
                    b'(' => out.write_all(br"\(")?,
                    b')' => out.write_all(br"\)")?,
                    b'\n' => out.write_all(br"\n")?,
                    b'\r' => out.write_all(br"\r")?,
                    b'\t' => out.write_all(br"\t")?,
                    _ => out.write_all(&[b])?,
                }
            }
            out.write_all(b")")
        }
        Object::HexString(bytes) => {
            out.write_all(b"<")?;
            for b in bytes {
                out.write_all(format!("{:02X}", b).as_bytes())?;
            }
            out.write_all(b">")
        }
        Object::Array(items) => {
            out.write_all(b"[")?;
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.write_all(b" ")?;
                }
                write_object(out, it)?;
            }
            out.write_all(b"]")
        }
        Object::Dict(d) => write_dict(out, d),
        Object::Reference(id) => {
            out.write_all(format!("{} {} R", id.number, id.generation).as_bytes())
        }
        Object::Stream(s) => {
            // Always patch /Length to match the payload — this is the
            // only field the serializer owns; everything else (filters,
            // type, image params) was set by the caller.
            let mut d = s.dict.clone();
            d.set("Length", Object::Integer(s.data.len() as i64));
            write_dict(out, &d)?;
            // Per §7.3.8.1, `stream` keyword followed by an EOL marker
            // (CRLF or just LF) is required; the data starts at the
            // byte right after the marker. Use LF — single byte is
            // legal and keeps the output more compact than CRLF.
            out.write_all(b"\nstream\n")?;
            out.write_all(&s.data)?;
            // The data must be followed by an EOL before `endstream`
            // (whether the data already ends with one or not).
            out.write_all(b"\nendstream")
        }
    }
}

fn write_dict(out: &mut Vec<u8>, d: &Dict) -> io::Result<()> {
    out.write_all(b"<<")?;
    for (k, v) in &d.entries {
        out.write_all(b" /")?;
        out.write_all(k.as_bytes())?;
        out.write_all(b" ")?;
        write_object(out, v)?;
    }
    out.write_all(b" >>")
}

/// Round-30 sig-writer entry point — serialise one [`Dict`] into a
/// caller-provided buffer using the same byte sequence the document
/// writer emits. Used by the `/Sig` writer's incremental-update
/// section so the appended-revision objects (Catalog override,
/// AcroForm, Sig field) come out byte-stable with the rest of the
/// file.
// Internal: sig-writer serialization plumbing (exposed for tests).
#[doc(hidden)]
pub fn write_dict_to(out: &mut Vec<u8>, d: &Dict) -> Result<(), PdfError> {
    write_dict(out, d).map_err(PdfError::Io)
}

/// Format a PDF real number per §7.3.3: no scientific notation,
/// trailing zeros trimmed, integer values written without a decimal
/// point. Bounded fractional precision keeps the output compact.
fn format_real(f: f64) -> String {
    if !f.is_finite() {
        // PDF has no Inf/NaN representation; clamp to 0 — the alternative
        // would be to refuse to write, but that would force every
        // gradient/transform call site to validate float inputs first.
        return "0".to_string();
    }
    if f.fract() == 0.0 && f.abs() < 1e16 {
        // Integer-valued — emit without a fractional component.
        return format!("{}", f as i64);
    }
    // 6 digits of fractional precision is a common writer choice
    // (observed across black-box tool output). Trim trailing zeros to
    // keep streams small; never leave a bare trailing dot.
    let s = format!("{:.6}", f);
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "-" {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_one(obj: &Object) -> Vec<u8> {
        let mut buf = Vec::new();
        write_object(&mut buf, obj).unwrap();
        buf
    }

    #[test]
    fn primitives_serialize() {
        assert_eq!(write_one(&Object::Null), b"null");
        assert_eq!(write_one(&Object::Bool(true)), b"true");
        assert_eq!(write_one(&Object::Bool(false)), b"false");
        assert_eq!(write_one(&Object::Integer(42)), b"42");
        assert_eq!(write_one(&Object::Integer(-7)), b"-7");
    }

    #[test]
    fn real_numbers_have_no_trailing_zeros() {
        assert_eq!(write_one(&Object::Real(0.0)), b"0");
        assert_eq!(write_one(&Object::Real(1.0)), b"1");
        assert_eq!(write_one(&Object::Real(0.5)), b"0.5");
        assert_eq!(write_one(&Object::Real(-1.25)), b"-1.25");
        assert_eq!(write_one(&Object::Real(2.345678987654)), b"2.345679");
    }

    #[test]
    fn names_are_slash_prefixed() {
        assert_eq!(write_one(&Object::Name("Pages".into())), b"/Pages");
        // Whitespace gets escaped.
        let escaped = write_one(&Object::Name("a b".into()));
        assert_eq!(escaped, b"/a#20b");
    }

    #[test]
    fn arrays_have_space_separated_items() {
        let a = Object::Array(vec![
            Object::Integer(1),
            Object::Integer(2),
            Object::Real(0.5),
        ]);
        assert_eq!(write_one(&a), b"[1 2 0.5]");
    }

    #[test]
    fn dicts_iterate_in_insertion_order() {
        let d = Dict::new()
            .with("Type", Object::Name("Pages".into()))
            .with("Count", Object::Integer(1));
        assert_eq!(write_one(&Object::Dict(d)), b"<< /Type /Pages /Count 1 >>");
    }

    #[test]
    fn streams_serialize_with_length() {
        let body = b"hello".to_vec();
        let s = Stream::new(Dict::new(), body);
        let bytes = write_one(&Object::Stream(s));
        let needle = b"/Length 5";
        assert!(
            bytes.windows(needle.len()).any(|w| w == needle),
            "expected /Length 5 in {:?}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(bytes.windows(7).any(|w| w == b"stream\n"));
        assert!(bytes.windows(9).any(|w| w == b"endstream"));
    }

    #[test]
    fn document_writes_full_pdf_envelope() {
        let mut doc = Document::new();
        let pages_id = doc.allocate_id();
        let catalog = Object::Dict(
            Dict::new()
                .with("Type", Object::Name("Catalog".into()))
                .with("Pages", Object::Reference(pages_id)),
        );
        let catalog_id = doc.add(catalog);
        doc.add_object(
            pages_id,
            Object::Dict(
                Dict::new()
                    .with("Type", Object::Name("Pages".into()))
                    .with("Count", Object::Integer(0))
                    .with("Kids", Object::Array(Vec::new())),
            ),
        );
        doc.root = Some(catalog_id);

        let mut bytes = Vec::new();
        doc.write_to(&mut bytes).unwrap();
        assert!(bytes.starts_with(b"%PDF-1.4\n"));
        assert!(bytes.ends_with(b"%%EOF\n"));
        assert!(bytes.windows(5).any(|w| w == b"xref\n"));
        assert!(bytes.windows(8).any(|w| w == b"trailer\n"));
        assert!(bytes.windows(10).any(|w| w == b"startxref\n"));
    }
}
