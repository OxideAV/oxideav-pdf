//! Top-level reader — bytes → resolved [`Document`] / [`Scene`].
//!
//! Glues [`crate::reader::xref`] (locate + parse cross-reference
//! table) and [`crate::reader::parse`] (decode an indirect object at
//! a given byte offset) into a one-shot pipeline:
//!
//! 1. [`load_xref`] — locate `startxref`, parse the xref table,
//!    keep the trailer dict.
//! 2. [`fetch_object`] — given an [`ObjectId`], seek to the byte
//!    offset, decode the indirect object's body (recursively
//!    resolving references on demand).
//! 3. [`read_pdf_to_scene`] — top-level entry point: bytes →
//!    [`oxideav_scene::Scene`] in pages mode. Walks the catalog →
//!    pages tree → per-page Contents → content-stream parser, and
//!    extracts /Info → [`Metadata`].
//!
//! Round 3 supports PDF 1.4 with a simple xref + uncompressed object
//! streams. FlateDecode-compressed Contents streams **are** decoded
//! here — the writer FlateDecode-compresses image XObjects + may
//! later compress content streams; supporting it now keeps the
//! reader symmetric with the writer's output. Object streams (PDF
//! 1.5+) and encryption are deferred to round 4+.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use oxideav_core::vector::{
    FillRule, Group, MaskKind, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, Transform2D,
    VectorFrame,
};
use oxideav_core::TimeBase;
use oxideav_scene::{Metadata, Page, Scene};

use crate::decrypt::{open_with_password, StandardHandler};
use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId, Stream};
use crate::pubsec::{
    open_with_certificate, open_with_certificate_and_trust_store, PubSecCredential, TrustStore,
};
use crate::reader::content::{
    parse_content_stream_full_with_soft_masks, parse_content_stream_full_with_tiling,
    parse_content_stream_full_with_type3, ResolvedSoftMask, TilingPattern, Type3Font,
};
use crate::reader::parse::Parser;
use crate::reader::xref::{parse_xref, XrefEntry, XrefTable};

/// A read-time view of the PDF document — owns the byte slice plus a
/// resolved cross-reference table and a small object cache. Indirect
/// objects are decoded lazily via [`Self::resolve`].
///
/// When the file's trailer carries an `/Encrypt` entry, the reader
/// holds a [`StandardHandler`] derived from the supplied password.
/// Every [`Self::resolve`] call decrypts string and stream payloads
/// against that handler before caching them. PDFs without encryption
/// leave `crypt = None` and the decrypt path is a no-op.
pub struct DocumentReader<'a> {
    input: &'a [u8],
    xref: XrefTable,
    cache: HashMap<ObjectId, Object>,
    crypt: Option<StandardHandler>,
    /// §7.5.7 compressed-object resolver memo. Each entry holds the
    /// FlateDecode-decompressed body of one ObjStm container plus the
    /// parsed `(obj_num, byte_offset_inside_payload)` header pairs.
    /// Without this cache, resolving N compressed objects whose xref
    /// type-2 entries all point at one container costs O(N²) — every
    /// `resolve(compressed)` call re-decompresses the whole stream
    /// and re-parses the `n` header pairs from scratch. Keyed by the
    /// container object number (not [`ObjectId`] — the generation of
    /// an ObjStm is always 0 per §7.5.7).
    objstm_cache: HashMap<u32, ObjStmDecoded>,
}

/// Cached decoded ObjStm: the Flate-expanded payload + the parsed
/// header table mapping each slot index to `(obj_num, body_offset)`
/// inside the payload. `first` is `pairs[0].1 + the base` — but the
/// resolver only needs to add the per-slot body_offset to the
/// absolute payload base, which we precompute here so the hot path
/// is a single `HashMap` lookup + `Parser::new(&payload[abs..])`.
struct ObjStmDecoded {
    payload: Vec<u8>,
    /// Absolute byte offset from `payload[0]` for slot `i`'s body.
    /// `(obj_num, abs_offset_into_payload)`.
    slots: Vec<(u32, usize)>,
}

impl<'a> DocumentReader<'a> {
    /// Parse the cross-reference table + trailer for `input`. Equivalent
    /// to [`Self::open_with_password`] with the empty password — works
    /// for unencrypted PDFs and for PDFs whose user password is empty.
    pub fn open(input: &'a [u8]) -> Result<Self, PdfError> {
        Self::open_with_password(input, b"")
    }

    /// Parse the cross-reference table + trailer for `input`. If the
    /// trailer carries `/Encrypt`, derive a decryption handler from the
    /// supplied password (tested first as the user password, then as
    /// the owner password per ISO 32000-1 §7.6.3.1).
    ///
    /// Returns [`PdfError::Other`] when the file is encrypted but the
    /// password fails to authenticate — the typical "wrong password"
    /// error a PDF viewer surfaces.
    pub fn open_with_password(input: &'a [u8], password: &[u8]) -> Result<Self, PdfError> {
        let xref = parse_xref(input)?;
        let crypt = build_crypt(&xref, input, password)?;
        Ok(Self {
            input,
            xref,
            cache: HashMap::new(),
            objstm_cache: HashMap::new(),
            crypt,
        })
    }

    /// Parse the cross-reference table + trailer and unlock a
    /// public-key-protected PDF using `credential`. Round-10
    /// implementation; see [`crate::pubsec`] for the supported
    /// SubFilters and crypt methods. Returns `PdfError::Other` when
    /// the PDF is encrypted but the supplied certificate doesn't
    /// match any recipient slot in any envelope of `/Recipients`.
    pub fn open_with_certificate(
        input: &'a [u8],
        credential: &PubSecCredential,
    ) -> Result<Self, PdfError> {
        let xref = parse_xref(input)?;
        let crypt = build_crypt_pubsec(&xref, input, credential, None)?;
        Ok(Self {
            input,
            xref,
            cache: HashMap::new(),
            objstm_cache: HashMap::new(),
            crypt,
        })
    }

    /// Round-17: same as [`Self::open_with_certificate`] but consults a
    /// [`TrustStore`] when a KARI envelope identifies the originator by
    /// `IssuerAndSerial` or `SubjectKeyIdentifier` (RFC 5652 §6.2.2)
    /// instead of carrying its public point in-band.
    pub fn open_with_certificate_and_trust_store(
        input: &'a [u8],
        credential: &PubSecCredential,
        trust_store: &TrustStore,
    ) -> Result<Self, PdfError> {
        let xref = parse_xref(input)?;
        let crypt = build_crypt_pubsec(&xref, input, credential, Some(trust_store))?;
        Ok(Self {
            input,
            xref,
            cache: HashMap::new(),
            objstm_cache: HashMap::new(),
            crypt,
        })
    }

    /// The trailer dict (carries `/Root`, optional `/Info`, etc.).
    pub fn xref(&self) -> &XrefTable {
        &self.xref
    }

    /// `true` when the underlying PDF carried an `/Encrypt` entry that
    /// the supplied password successfully authenticated against.
    pub fn is_encrypted(&self) -> bool {
        self.crypt.is_some()
    }

    /// Round-21: enumerate every `/Sig` form-field signature dictionary
    /// embedded in this PDF. See [`crate::reader::sig::signatures`] for
    /// the full contract — this is a thin convenience wrapper.
    ///
    /// ```rust,ignore
    /// use oxideav_pdf::reader::DocumentReader;
    /// use oxideav_pdf::pubsec::verify::{verify_signature, AttachedContent};
    ///
    /// let mut r = DocumentReader::open(&pdf)?;
    /// for sig in r.signatures()? {
    ///     if !sig.is_cms_detached() { continue; }
    ///     let signed = sig.signed_message(&pdf)?;
    ///     let sd = sig.signed_data.as_ref().unwrap();
    ///     // ... resolve certs from sd.certs[] ...
    ///     let ok = verify_signature(&sd.signer_infos[0], &certs,
    ///         AttachedContent::External(&signed))?;
    /// }
    /// # Ok::<(), oxideav_pdf::PdfError>(())
    /// ```
    pub fn signatures(&mut self) -> Result<Vec<crate::reader::sig::PdfSignature>, PdfError> {
        crate::reader::sig::signatures(self)
    }

    /// Round-34: surface only the document time-stamp signatures (ISO
    /// 32000-1 §12.8.5 — `/Type /DocTimeStamp` or `/SubFilter
    /// /ETSI.RFC3161`).
    pub fn doc_timestamps(&mut self) -> Result<Vec<crate::reader::sig::PdfDocTimestamp>, PdfError> {
        crate::reader::sig::doc_timestamps(self)
    }

    /// Round-19: surface the document-level XMP `/Metadata` packet
    /// per ISO 32000-1 §14.3.2 + Adobe XMP Spec 2012. Returns
    /// `Ok(None)` when the catalog has no `/Metadata` entry; otherwise
    /// resolves the referenced stream and returns its decoded payload
    /// (the raw XMP RDF/XML bytes — caller is expected to do their
    /// own XML / RDF parse if they need structured access).
    ///
    /// Symmetric to [`crate::write_pdf_from_scene_with_xmp`].
    /// Round-26: walk every page's `/Annots` array and surface each
    /// annotation as a [`crate::reader::annotation::PdfAnnotation`]
    /// (ISO 32000-1 §12.5).
    ///
    /// Subsumes [`Self::signatures`] (those land as `Other { subtype:
    /// "Widget" }` plus `/FT /Sig` widget hosting) at a higher level —
    /// callers that just want the structured `/Sig` slot should keep
    /// using `signatures()`; callers that want every annotation across
    /// every page (Text, FreeText, Stamp, Highlight, Square, Link,
    /// Widget, …) want `annotations()`.
    pub fn annotations(
        &mut self,
    ) -> Result<Vec<crate::reader::annotation::PdfAnnotation>, PdfError> {
        crate::reader::annotation::annotations(self)
    }

    /// Round-36: enumerate every action attached to the document (ISO
    /// 32000-1 §12.6). Walks the catalog `/OpenAction` + `/AA`,
    /// per-page `/AA`, per-annotation `/A` + `/AA`, per-form-field
    /// `/A` + `/AA`, and the `/Names /JavaScript` name tree, surfacing
    /// each as a [`crate::reader::actions::PdfAction`] with the
    /// trigger location, the typed [`crate::reader::actions::ActionKind`]
    /// payload, and the `/Next` chain depth.
    pub fn actions(&mut self) -> Result<Vec<crate::reader::actions::PdfAction>, PdfError> {
        crate::reader::actions::actions(self)
    }

    /// Round-95: surface the catalog's `/OCProperties` Optional Content
    /// configuration (ISO 32000-1 §8.11 + §7.7.2 Table 28). Returns
    /// `Ok(None)` when the document has no optional content (the
    /// common case); returns `Ok(Some(_))` carrying every OCG, the
    /// default configuration dict, any alternate configurations, and
    /// the resolved on/off state per group after applying the default
    /// configuration's `BaseState` / `ON` / `OFF` per §8.11.4.5.
    pub fn optional_content(
        &mut self,
    ) -> Result<Option<crate::reader::ocg::OptionalContent>, PdfError> {
        crate::reader::ocg::optional_content(self)
    }

    /// Round-27: parse the Linearization Parameter Dictionary at the
    /// head of the file (ISO 32000-1 §F.2 + Annex F.3). Returns
    /// `Ok(None)` for non-linearized files (the common case);
    /// returns `Ok(Some(_))` with parsed `/L /H /O /E /N /T` for
    /// "Fast Web View" PDFs.
    ///
    /// Independent of the rest of the open path — the lin-dict
    /// is parsed from the raw bytes, NOT from the resolved xref.
    /// A reader can poll for linearization status without paying
    /// the xref-walk cost.
    pub fn linearization(
        &self,
    ) -> Result<Option<crate::reader::linearize::LinearizationParams>, PdfError> {
        crate::reader::linearize::LinearizationParams::parse(self.input)
    }

    /// Round-27: walk Catalog → Pages → Page and collect every
    /// integrity divergence per ISO 32000-1 §7.7.2 + §7.7.3. The
    /// returned [`crate::reader::hierarchy::HierarchyReport`] is
    /// permissive — it never aborts the walk, so callers can decide
    /// per-issue what to do with warnings vs. errors.
    pub fn verify_hierarchy(
        &mut self,
    ) -> Result<crate::reader::hierarchy::HierarchyReport, PdfError> {
        crate::reader::hierarchy::verify_hierarchy(self)
    }

    /// Round-27: surface the structural PDF/A catalog signals
    /// (`/MarkInfo`, `/StructTreeRoot`, `/Lang`, `/OutputIntents`,
    /// `/Metadata`) independent of the XMP packet's claim.
    ///
    /// Pair with [`Self::xmp_packet`] + [`crate::reader::pdfa::PdfAConformance::from_signals_and_xmp`]
    /// to cross-verify a `pdfaid:part` declaration against the
    /// structural prerequisites ISO 19005-x requires.
    pub fn pdfa_signals(&mut self) -> Result<crate::reader::pdfa::PdfACatalogSignals, PdfError> {
        crate::reader::pdfa::pdfa_signals(self)
    }

    /// Round-27: combined PDF/A conformance picture — the XMP
    /// packet's `pdfaid:part` / `pdfaid:conformance` claim cross-
    /// verified against the catalog's structural signals
    /// (`/MarkInfo /Marked`, `/StructTreeRoot`, `/OutputIntents`).
    ///
    /// Returns a [`crate::reader::pdfa::PdfAConformance`] whose
    /// `claim_inconsistent` is `true` when the document declares
    /// PDF/A in XMP but lacks one or more structural prerequisites.
    pub fn pdfa_conformance(&mut self) -> Result<crate::reader::pdfa::PdfAConformance, PdfError> {
        let signals = self.pdfa_signals()?;
        let xmp = self.xmp_packet()?;
        Ok(crate::reader::pdfa::PdfAConformance::from_signals_and_xmp(
            &signals,
            xmp.as_ref(),
        ))
    }

    /// Round-26: surface the document-level XMP `/Metadata` packet as
    /// a structured [`crate::reader::xmp::XmpPacket`] — the most-used
    /// Dublin Core / XMP Basic / PDF / PDF/A identification fields,
    /// pre-decoded from the raw bytes [`Self::xmp_metadata`] returns.
    ///
    /// Returns `Ok(None)` when the catalog has no `/Metadata` entry.
    pub fn xmp_packet(&mut self) -> Result<Option<crate::reader::xmp::XmpPacket>, PdfError> {
        Ok(self
            .xmp_metadata()?
            .as_deref()
            .map(crate::reader::xmp::XmpPacket::parse))
    }

    pub fn xmp_metadata(&mut self) -> Result<Option<Vec<u8>>, PdfError> {
        let root_id = self.xref.root()?;
        let catalog = self.resolve(root_id)?;
        let Object::Dict(catalog) = catalog else {
            return Err(PdfError::other(format!(
                "PDF reader: /Root must be a dictionary (got {catalog:?})"
            )));
        };
        let metadata_obj = catalog
            .entries()
            .iter()
            .find(|(k, _)| k == "Metadata")
            .map(|(_, v)| v.clone());
        let Some(metadata_obj) = metadata_obj else {
            return Ok(None);
        };
        // /Metadata is conventionally an indirect reference (§14.3.2
        // gives the catalog entry as `metadata stream`). Accept both
        // direct-stream and reference-to-stream shapes.
        let stream_obj = match metadata_obj {
            Object::Reference(id) => self.resolve(id)?,
            other => other,
        };
        let Object::Stream(s) = stream_obj else {
            return Err(PdfError::other(format!(
                "PDF reader: catalog /Metadata must resolve to a Stream (got {stream_obj:?})"
            )));
        };
        Ok(Some(decode_stream(&s)?))
    }

    /// Decode the indirect object at `id`. Cached on first hit so a
    /// second `resolve(id)` is O(1). When the file is encrypted, the
    /// per-object decryption is applied here so callers above this
    /// layer see plaintext only.
    ///
    /// Compressed objects (xref entry type 2 — PDF 1.5+ object
    /// streams, ISO 32000-1 §7.5.7) are resolved by fetching their
    /// containing object stream, slicing the matching body out of the
    /// concatenated payload, and re-parsing it with the standard
    /// object parser.
    pub fn resolve(&mut self, id: ObjectId) -> Result<Object, PdfError> {
        if let Some(o) = self.cache.get(&id) {
            return Ok(o.clone());
        }
        // Compressed entries take a different path — they live inside
        // an object stream (`/Type /ObjStm`) rather than at a byte
        // offset. The container itself is encrypted (when the file is
        // encrypted); the per-stored-object payload is **not**
        // re-encrypted (§7.6.1, "object streams are encrypted as a
        // unit").
        if let Some(XrefEntry::Compressed {
            obj_stream_id,
            index_within_stream,
        }) = self.xref.entries.get(&id.number).copied()
        {
            let body = self.resolve_compressed(id, obj_stream_id, index_within_stream)?;
            self.cache.insert(id, body.clone());
            return Ok(body);
        }
        let off = self
            .xref
            .offset_of(id)
            .ok_or_else(|| PdfError::other(format!("PDF reader: object {id:?} not in xref")))?;
        let mut p = Parser::new(self.input);
        p.lexer_mut().seek(off as usize);
        // ISO 32000-1 §7.3.10 Example 3: a stream's `/Length` may be
        // an indirect reference, deferring the size until after the
        // body for one-pass writers. Resolve the reference against
        // the xref table — the target must be an in-use integer
        // object at a known byte offset (Compressed targets are
        // currently rejected; see docs-gap note in the resolver).
        let input = self.input;
        let xref_snapshot = &self.xref;
        let id_being_parsed = id;
        let mut resolver = move |length_ref_id: ObjectId| -> Result<i64, PdfError> {
            resolve_indirect_length(input, xref_snapshot, length_ref_id, id_being_parsed)
        };
        let (parsed_id, mut body) = p.parse_indirect_with_length_resolver(&mut resolver)?;
        if parsed_id != id {
            return Err(PdfError::other(format!(
                "PDF reader: xref points to wrong object — wanted {id:?}, got {parsed_id:?}"
            )));
        }
        if let Some(crypt) = &self.crypt {
            decrypt_object_in_place(&mut body, id, crypt)?;
        }
        self.cache.insert(id, body.clone());
        Ok(body)
    }

    /// Resolve a compressed object — fetch + decode the containing
    /// object stream (PDF 1.5+ `/Type /ObjStm`), slice the body whose
    /// header matches `wanted.number`, and parse it with the standard
    /// object parser.
    ///
    /// The decoded payload + header slot table are memoised in
    /// [`Self::objstm_cache`] so the second-and-subsequent compressed
    /// object resolved against the same container skip Flate
    /// decompression + header re-parse. Without the cache the cost of
    /// resolving the M compressed objects packed into one ObjStm
    /// container is O(M²) (every call decompresses the full payload
    /// and re-parses every header pair); with it the cost is
    /// O(M) for the first call + O(1) per subsequent slot lookup.
    fn resolve_compressed(
        &mut self,
        wanted: ObjectId,
        obj_stream_num: u32,
        index_within_stream: u32,
    ) -> Result<Object, PdfError> {
        // Fast path: container already decoded.
        if let Some(decoded) = self.objstm_cache.get(&obj_stream_num) {
            return Self::slot_from_decoded(decoded, wanted, index_within_stream);
        }
        let decoded = self.decode_objstm_container(wanted, obj_stream_num)?;
        let body = Self::slot_from_decoded(&decoded, wanted, index_within_stream)?;
        self.objstm_cache.insert(obj_stream_num, decoded);
        Ok(body)
    }

    /// Fetch the container ObjStm object, validate its dict, Flate-
    /// decompress the body, and parse the §7.5.7 header table into a
    /// flat `[(obj_num, abs_payload_offset); N]` slice. Cached by
    /// [`Self::resolve_compressed`].
    fn decode_objstm_container(
        &mut self,
        wanted: ObjectId,
        obj_stream_num: u32,
    ) -> Result<ObjStmDecoded, PdfError> {
        let container_id = ObjectId::new(obj_stream_num);
        // §7.5.7: "An object stream shall not contain other object
        // streams. Furthermore, the cross-reference entries for
        // compressed objects shall not themselves use type 2 to point
        // back at the containing object stream." A hostile xref that
        // marks the container as itself compressed (or as compressed
        // inside another container that is in turn compressed inside
        // it) would otherwise loop `resolve` → `decode_objstm_container`
        // → `resolve` until the stack overflows. Reject any Type-2 entry
        // for the container before re-entering `resolve`. Caught from
        // a fuzz finding (parse target stack-overflow on a crafted
        // hybrid-reference file whose XRefStm declared object 1 as
        // compressed inside container 1).
        if let Some(XrefEntry::Compressed { .. }) = self.xref.entries.get(&container_id.number) {
            return Err(PdfError::other(format!(
                "PDF reader: ObjStm container {container_id:?} (for compressed object \
                 {wanted:?}) is itself declared as a Type-2 compressed entry in the xref \
                 — forbidden by ISO 32000-1 §7.5.7"
            )));
        }
        let container = self.resolve(container_id)?;
        let Object::Stream(s) = container else {
            return Err(PdfError::other(format!(
                "PDF reader: object {wanted:?} expected its container {container_id:?} to be a Stream"
            )));
        };
        // /Type must be /ObjStm.
        let dict = &s.dict;
        let lookup = |k: &str| {
            dict.entries()
                .iter()
                .find(|(kk, _)| kk == k)
                .map(|(_, v)| v.clone())
        };
        if !matches!(lookup("Type"), Some(Object::Name(ref n)) if n == "ObjStm") {
            return Err(PdfError::other(format!(
                "PDF reader: container {container_id:?} is not /Type /ObjStm"
            )));
        }
        let n = match lookup("N") {
            Some(Object::Integer(v)) if v >= 0 => v as u32,
            other => {
                return Err(PdfError::other(format!(
                    "PDF reader: ObjStm /N must be a non-negative integer (got {other:?})"
                )))
            }
        };
        let first = match lookup("First") {
            Some(Object::Integer(v)) if v >= 0 => v as usize,
            other => {
                return Err(PdfError::other(format!(
                    "PDF reader: ObjStm /First must be a non-negative integer (got {other:?})"
                )))
            }
        };
        let payload = decode_stream(&s)?;
        if first > payload.len() {
            return Err(PdfError::other(format!(
                "PDF reader: ObjStm /First {first} exceeds payload length {}",
                payload.len()
            )));
        }
        let header_bytes = &payload[..first];
        // Header is `obj_num_1 off_1 obj_num_2 off_2 ...` with
        // whitespace separators per §7.5.7. Re-use the standard
        // parser's integer machinery rather than re-implementing it.
        let mut hp = Parser::new(header_bytes);
        let mut slots: Vec<(u32, usize)> = Vec::with_capacity(n as usize);
        for i in 0..n {
            let on = hp.parse_object()?.ok_or_else(|| {
                PdfError::other(format!(
                    "PDF reader: ObjStm header truncated at pair {i} (obj_num)"
                ))
            })?;
            let off = hp.parse_object()?.ok_or_else(|| {
                PdfError::other(format!(
                    "PDF reader: ObjStm header truncated at pair {i} (offset)"
                ))
            })?;
            let (Object::Integer(num), Object::Integer(o)) = (on, off) else {
                return Err(PdfError::other(format!(
                    "PDF reader: ObjStm header pair {i} must be two integers"
                )));
            };
            if num < 1 || o < 0 {
                return Err(PdfError::other(format!(
                    "PDF reader: ObjStm header pair {i} out of range ({num}, {o})"
                )));
            }
            let abs_off = first
                .checked_add(o as usize)
                .ok_or_else(|| PdfError::other("PDF reader: ObjStm offset overflow"))?;
            if abs_off > payload.len() {
                return Err(PdfError::other(format!(
                    "PDF reader: ObjStm body offset {abs_off} past payload length {}",
                    payload.len()
                )));
            }
            slots.push((num as u32, abs_off));
        }
        Ok(ObjStmDecoded { payload, slots })
    }

    /// Per-slot extraction against a cached [`ObjStmDecoded`].
    /// Validates `index_within_stream` against the header table,
    /// confirms the declared object number matches what the xref
    /// promised, then parses one object out of the payload starting
    /// at the precomputed absolute offset.
    fn slot_from_decoded(
        decoded: &ObjStmDecoded,
        wanted: ObjectId,
        index_within_stream: u32,
    ) -> Result<Object, PdfError> {
        let n = decoded.slots.len() as u32;
        if index_within_stream >= n {
            return Err(PdfError::other(format!(
                "PDF reader: ObjStm index {index_within_stream} out of range (N={n})"
            )));
        }
        let (header_num, abs_off) = decoded.slots[index_within_stream as usize];
        if header_num != wanted.number {
            return Err(PdfError::other(format!(
                "PDF reader: ObjStm slot {index_within_stream} declares object {header_num},\
                 but xref expected {}",
                wanted.number
            )));
        }
        // Compressed objects in an ObjStm cannot themselves be
        // streams (§7.5.7), and have no `n gen obj` wrapper — we
        // parse a single object starting at `abs_off`.
        let mut bp = Parser::new(&decoded.payload[abs_off..]);
        let body = bp
            .parse_object()?
            .ok_or_else(|| PdfError::other("PDF reader: ObjStm body parse returned EOF"))?;
        Ok(body)
    }

    /// If `obj` is `Object::Reference`, follow it (recursively) until
    /// a non-reference value resolves. Returns the deref'd value.
    pub fn deref(&mut self, obj: Object) -> Result<Object, PdfError> {
        let mut cur = obj;
        let mut hops = 0;
        while let Object::Reference(id) = cur {
            cur = self.resolve(id)?;
            hops += 1;
            if hops > 16 {
                return Err(PdfError::other(
                    "PDF reader: indirect-reference chain too deep (>16 hops)",
                ));
            }
        }
        Ok(cur)
    }
}

/// Round-91: resolve a stream's indirect `/Length` (ISO 32000-1
/// §7.3.10 Example 3 — `<< /Length 8 0 R >> stream … endstream`).
///
/// The length-carrying object lives at a byte offset given by the
/// xref table. Spec-conforming PDFs put a small `n 0 obj N endobj`
/// integer there, so we re-enter the resolver-less parse path
/// (deliberately — the length object is never itself a stream).
///
/// `containing_stream` is the object currently being read; passed in
/// only to make the error message useful when an indirect reference
/// is malformed (otherwise the caller has no breadcrumb back to the
/// stream that triggered the lookup).
///
/// Cycle protection: an indirect reference whose target is itself an
/// indirect-length stream pointing back at us is not a meaningful PDF
/// shape — the length-carrying object is required to be a direct
/// integer per §7.3.8.2 Table 5, so any chain longer than one hop is
/// already malformed. We reject deeper chains with a clear message.
fn resolve_indirect_length(
    input: &[u8],
    xref: &XrefTable,
    length_ref: ObjectId,
    containing_stream: ObjectId,
) -> Result<i64, PdfError> {
    if length_ref == containing_stream {
        return Err(PdfError::other(format!(
            "PDF reader: stream {containing_stream:?} /Length refers to itself"
        )));
    }
    // Compressed entries (PDF 1.5+ object-stream-resident integers)
    // would require fetching the container ObjStm first, which itself
    // needs an xref walk. The mainstream encoders we've seen never put
    // a length-carrying integer inside an ObjStm — they're tiny and
    // the writer wants them resolvable without paying ObjStm decoding
    // cost. If we hit one in the wild, surface a clear error rather
    // than silently mis-resolving.
    if let Some(XrefEntry::Compressed { .. }) = xref.entries.get(&length_ref.number) {
        return Err(PdfError::other(format!(
            "PDF reader: indirect /Length {length_ref:?} lives in an object stream \
             — not supported (ISO 32000-1 §7.5.7); the length object should be a \
             direct uncompressed integer"
        )));
    }
    let off = xref.offset_of(length_ref).ok_or_else(|| {
        PdfError::other(format!(
            "PDF reader: indirect /Length {length_ref:?} (for stream \
             {containing_stream:?}) is not in the xref table"
        ))
    })?;
    let mut p = Parser::new(input);
    p.lexer_mut().seek(off as usize);
    // No resolver here — the length-carrying object must be a direct
    // integer per §7.3.8.2 (Length is an `integer`, not a value-may-
    // be-indirect entry). A stream-of-streams cycle is therefore
    // statically impossible.
    let (parsed_id, body) = p.parse_indirect()?;
    if parsed_id != length_ref {
        return Err(PdfError::other(format!(
            "PDF reader: xref points to wrong object for indirect /Length — \
             wanted {length_ref:?}, got {parsed_id:?}"
        )));
    }
    match body {
        Object::Integer(n) => Ok(n),
        other => Err(PdfError::other(format!(
            "PDF reader: indirect /Length {length_ref:?} target must be an \
             integer (got {other:?})"
        ))),
    }
}

/// Resolve the trailer's `/Encrypt` reference + `/ID[0]` and try the
/// supplied password against the standard security handler. Returns
/// `Ok(None)` when the trailer has no `/Encrypt`. Errors when present
/// but malformed or when the password fails to authenticate.
fn build_crypt(
    xref: &XrefTable,
    input: &[u8],
    password: &[u8],
) -> Result<Option<StandardHandler>, PdfError> {
    let encrypt_ref = xref.trailer.entries().iter().find(|(k, _)| k == "Encrypt");
    let Some((_, encrypt_obj)) = encrypt_ref else {
        return Ok(None);
    };

    // /Encrypt may be inline or an indirect reference. Resolve as needed.
    let encrypt_dict = match encrypt_obj {
        Object::Dict(d) => d.clone(),
        Object::Reference(id) => {
            let off = xref
                .offset_of(*id)
                .ok_or_else(|| PdfError::other("PDF reader: /Encrypt refers to missing object"))?;
            let mut p = Parser::new(input);
            p.lexer_mut().seek(off as usize);
            let (_, body) = p.parse_indirect()?;
            match body {
                Object::Dict(d) => d,
                other => {
                    return Err(PdfError::other(format!(
                        "PDF reader: /Encrypt must resolve to a dict (got {other:?})"
                    )))
                }
            }
        }
        other => {
            return Err(PdfError::other(format!(
                "PDF reader: /Encrypt must be a dict or reference (got {other:?})"
            )))
        }
    };

    // /ID is required for encrypted PDFs (Algorithm 2 step (e)). The
    // first element is the document-permanent identifier.
    let id_obj = xref
        .trailer
        .entries()
        .iter()
        .find(|(k, _)| k == "ID")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| PdfError::other("PDF reader: encrypted PDF missing /ID in trailer"))?;
    let Object::Array(id_items) = id_obj else {
        return Err(PdfError::other("PDF reader: /ID must be an array"));
    };
    if id_items.is_empty() {
        return Err(PdfError::other("PDF reader: trailer /ID array is empty"));
    }
    let file_id = match &id_items[0] {
        Object::LiteralString(s) | Object::HexString(s) => s.clone(),
        other => {
            return Err(PdfError::other(format!(
                "PDF reader: /ID[0] must be a string (got {other:?})"
            )))
        }
    };

    let handler = open_with_password(&encrypt_dict, &file_id, password)?;
    handler
        .ok_or_else(|| {
            PdfError::other("PDF reader: wrong password (or PDF requires owner password)")
        })
        .map(Some)
}

/// Public-key analogue of [`build_crypt`] — fetches the trailer's
/// `/Encrypt` dict (resolving any indirect reference) and asks
/// [`crate::pubsec::open_with_certificate`] to derive a
/// [`StandardHandler`] from the user's certificate. Returns
/// `Ok(None)` when no `/Encrypt` is present (so a non-encrypted PDF
/// still opens via the certificate-based entry point).
fn build_crypt_pubsec(
    xref: &XrefTable,
    input: &[u8],
    credential: &PubSecCredential,
    trust_store: Option<&TrustStore>,
) -> Result<Option<StandardHandler>, PdfError> {
    let encrypt_ref = xref.trailer.entries().iter().find(|(k, _)| k == "Encrypt");
    let Some((_, encrypt_obj)) = encrypt_ref else {
        return Ok(None);
    };
    let encrypt_dict = match encrypt_obj {
        Object::Dict(d) => d.clone(),
        Object::Reference(id) => {
            let off = xref
                .offset_of(*id)
                .ok_or_else(|| PdfError::other("PDF reader: /Encrypt refers to missing object"))?;
            let mut p = Parser::new(input);
            p.lexer_mut().seek(off as usize);
            let (_, body) = p.parse_indirect()?;
            match body {
                Object::Dict(d) => d,
                other => {
                    return Err(PdfError::other(format!(
                        "PDF reader: /Encrypt must resolve to a dict (got {other:?})"
                    )))
                }
            }
        }
        other => {
            return Err(PdfError::other(format!(
                "PDF reader: /Encrypt must be a dict or reference (got {other:?})"
            )))
        }
    };
    let handler = match trust_store {
        Some(store) => open_with_certificate_and_trust_store(&encrypt_dict, credential, store)?,
        None => open_with_certificate(&encrypt_dict, credential)?,
    };
    handler
        .ok_or_else(|| {
            PdfError::other(
                "PDF reader: certificate did not match any recipient in /Recipients (round-10)",
            )
        })
        .map(Some)
}

/// In-place decrypt: walk the parsed [`Object`] tree, decrypting every
/// string and stream payload it contains. Encrypted PDFs only encrypt
/// strings + streams — not numeric / boolean / name / array structure
/// — so the recursion only mutates the leaf content of those two
/// variants.
///
/// Per ISO 32000-1 §7.4.10 + §7.6.5, a stream's first `/Filter` may be
/// `/Crypt` with `/DecodeParms /Name /Identity` to opt out of the
/// per-object decryption — the bytes are then treated as cleartext.
/// This is the standard "this stream is intentionally NOT encrypted
/// even though the rest of the file is" override (used e.g. for
/// document-level XMP metadata streams when `/EncryptMetadata false`
/// can't be applied uniformly).
fn decrypt_object_in_place(
    obj: &mut Object,
    id: ObjectId,
    crypt: &StandardHandler,
) -> Result<(), PdfError> {
    match obj {
        Object::LiteralString(s) | Object::HexString(s) => {
            *s = crypt.decrypt_object(id, s)?;
        }
        Object::Array(items) => {
            for item in items {
                decrypt_object_in_place(item, id, crypt)?;
            }
        }
        Object::Dict(d) => {
            decrypt_dict_in_place(d, id, crypt)?;
        }
        Object::Stream(s) => {
            // Stream body is decrypted; the `/Length` already reflects
            // the encrypted length (which equals the cleartext length
            // for RC4; for AES the cleartext is shorter by IV+padding).
            // Recurse into the stream dict for any nested strings.
            decrypt_dict_in_place(&mut s.dict, id, crypt)?;
            // Per-stream /Crypt /Identity override: skip decryption.
            if has_identity_crypt_filter(&s.dict) {
                return Ok(());
            }
            // The stream's `/Filter` handling already decrypts before
            // applying the filter — we decrypt the raw, still-filtered
            // bytes here.
            s.data = crypt.decrypt_object(id, &s.data)?;
        }
        // Numbers, booleans, names, null, references — not encrypted.
        _ => {}
    }
    Ok(())
}

/// Detect a per-stream `/Filter [/Crypt …] /DecodeParms [<<…>>]` shape
/// where the crypt-filter parms specify `/Name /Identity` — the ISO
/// 32000-1 §7.6.5 opt-out for "this stream is NOT encrypted".
///
/// Accepts both the `/Filter /Crypt` (single name) and `/Filter
/// [/Crypt …]` (array) forms; the matching `/DecodeParms` may be a
/// single dict or an array of dicts (parallel to `/Filter`).
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

    // The matching DecodeParms slot.
    let parms_dict = match parms {
        Some(Object::Dict(d)) if idx == 0 => Some(d.clone()),
        Some(Object::Array(items)) => match items.get(idx) {
            Some(Object::Dict(d)) => Some(d.clone()),
            _ => None,
        },
        _ => None,
    };
    let Some(d) = parms_dict else {
        // No parms → default Crypt filter. Default crypt filter
        // /Name is /Identity per §7.4.10 (Table 24).
        return true;
    };
    match d
        .entries()
        .iter()
        .find(|(k, _)| k == "Name")
        .map(|(_, v)| v)
    {
        Some(Object::Name(s)) => s == "Identity",
        // Missing /Name defaults to /Identity (Table 24).
        None => true,
        _ => false,
    }
}

fn decrypt_dict_in_place(
    d: &mut Dict,
    id: ObjectId,
    crypt: &StandardHandler,
) -> Result<(), PdfError> {
    // We can't borrow_mut + iterate; reconstruct entries with the
    // mutated values.
    let mut new_entries: Vec<(String, Object)> = Vec::with_capacity(d.entries().len());
    for (k, v) in d.entries() {
        let mut v = v.clone();
        decrypt_object_in_place(&mut v, id, crypt)?;
        new_entries.push((k.clone(), v));
    }
    *d = Dict::default();
    for (k, v) in new_entries {
        d.set(&k, v);
    }
    Ok(())
}

/// Convenience — open + read straight into a [`Scene`] in pages mode.
/// Inverse of [`crate::write_pdf_from_scene`] for PDFs the writer
/// would produce.
///
/// Returns `Err` for:
/// - Malformed xref / trailer (round-3 only handles plain xref tables;
///   PDF 1.5+ /XRef streams surface as parse errors).
/// - Encrypted PDFs that aren't openable with the empty user password
///   (use [`read_pdf_to_scene_with_password`] instead).
/// - Documents that decode to zero pages (catalog → pages tree
///   walked but no Page leaves found).
pub fn read_pdf_to_scene(input: &[u8]) -> Result<Scene, PdfError> {
    read_pdf_to_scene_with_password(input, b"")
}

/// Like [`read_pdf_to_scene`] but accepts a user / owner password
/// for encrypted PDFs.
///
/// Round-4 supports the standard security handler (R=2, R=3, R=4
/// — RC4-40, RC4-128, AES-128 CBC). R=5 / R=6 (AES-256) (round 5).
/// Public-key handlers go via
/// [`read_pdf_to_scene_with_certificate`] (round 10).
pub fn read_pdf_to_scene_with_password(input: &[u8], password: &[u8]) -> Result<Scene, PdfError> {
    let reader = DocumentReader::open_with_password(input, password)?;
    decode_to_scene(reader)
}

/// Like [`read_pdf_to_scene`] but unlocks a public-key-encrypted PDF
/// (`adbe.pkcs7.s3` / `s4` / `s5`) using the supplied X.509
/// certificate + RSA private key. Round-10 implementation; see
/// [`crate::pubsec`] for SubFilter and crypt-method coverage.
///
/// Returns `PdfError::Other` when the PDF is encrypted but the
/// supplied certificate doesn't match any recipient slot in
/// `/Recipients` — analogous to the wrong-password error from
/// [`read_pdf_to_scene_with_password`].
pub fn read_pdf_to_scene_with_certificate(
    input: &[u8],
    credential: &PubSecCredential,
) -> Result<Scene, PdfError> {
    let reader = DocumentReader::open_with_certificate(input, credential)?;
    decode_to_scene(reader)
}

/// Round-17: variant of [`read_pdf_to_scene_with_certificate`] that
/// consults a [`TrustStore`] when a KARI envelope identifies the
/// originator by `IssuerAndSerial` or `SubjectKeyIdentifier` (RFC 5652
/// §6.2.2) instead of carrying its public point in-band.
///
/// In-band `OriginatorPublicKey` envelopes still work without
/// consulting the trust store — the lookup path is only triggered for
/// the long-term-cert forms.
pub fn read_pdf_to_scene_with_certificate_and_trust_store(
    input: &[u8],
    credential: &PubSecCredential,
    trust_store: &TrustStore,
) -> Result<Scene, PdfError> {
    let reader =
        DocumentReader::open_with_certificate_and_trust_store(input, credential, trust_store)?;
    decode_to_scene(reader)
}

fn decode_to_scene(mut reader: DocumentReader<'_>) -> Result<Scene, PdfError> {
    // Catalog → /Pages reference.
    let root_id = reader.xref.root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog) = catalog else {
        return Err(PdfError::other(format!(
            "PDF reader: /Root must be a dictionary (got {catalog:?})"
        )));
    };
    let pages_ref = catalog
        .entries()
        .iter()
        .find(|(k, _)| k == "Pages")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| PdfError::other("PDF reader: catalog missing /Pages"))?;
    let Object::Reference(pages_root_id) = pages_ref else {
        return Err(PdfError::other(format!(
            "PDF reader: catalog /Pages must be an indirect reference (got {pages_ref:?})"
        )));
    };

    // Walk the /Pages tree depth-first into a flat list of Page leaf
    // ids.
    let mut leaves = Vec::new();
    walk_pages_tree(&mut reader, pages_root_id, &mut leaves)?;
    if leaves.is_empty() {
        return Err(PdfError::other(
            "PDF reader: /Pages tree contained no Page leaves",
        ));
    }

    // Resolve the catalog's optional-content state once (§8.11) — the
    // annotation-appearance path consults it for per-annotation /OC
    // visibility (§12.5.2 Table 164). A malformed /OCProperties is
    // treated as "not layered" rather than failing the whole decode.
    let optional_content = crate::reader::ocg::optional_content(&mut reader).unwrap_or(None);

    // Decode each Page → oxideav_scene::Page.
    let mut scene_pages = Vec::with_capacity(leaves.len());
    for leaf_id in leaves {
        scene_pages.push(decode_page(
            &mut reader,
            leaf_id,
            optional_content.as_ref(),
        )?);
    }

    // /Info → Metadata.
    let metadata = if let Some(info_id) = reader.xref.info() {
        let info = reader.resolve(info_id)?;
        decode_metadata(info)?
    } else {
        Metadata::default()
    };

    Ok(Scene {
        pages: Some(scene_pages),
        metadata,
        ..Scene::default()
    })
}

/// Maximum nesting depth of a §7.7.3.2 /Pages tree the reader will
/// follow. ISO 32000-1 does not specify a hard bound — but a
/// well-formed pages tree is balanced at most logarithmically in page
/// count, so a 256-level deep tree would map to more pages than any
/// sane consumer would attempt. Anything past this bound is treated
/// as a malformed tree (likely an attacker-shaped chain) and the
/// walker returns Err rather than blowing the call stack.
const MAX_PAGES_TREE_DEPTH: u32 = 256;

fn walk_pages_tree(
    reader: &mut DocumentReader<'_>,
    node_id: ObjectId,
    out: &mut Vec<ObjectId>,
) -> Result<(), PdfError> {
    let mut visited = HashSet::new();
    walk_pages_tree_inner(reader, node_id, out, &mut visited, 0)
}

fn walk_pages_tree_inner(
    reader: &mut DocumentReader<'_>,
    node_id: ObjectId,
    out: &mut Vec<ObjectId>,
    visited: &mut HashSet<ObjectId>,
    depth: u32,
) -> Result<(), PdfError> {
    if depth > MAX_PAGES_TREE_DEPTH {
        return Err(PdfError::other(format!(
            "PDF reader: /Pages tree exceeds maximum depth ({MAX_PAGES_TREE_DEPTH})"
        )));
    }
    // §7.7.3.2 says a /Pages node's /Kids array MUST NOT reference
    // an ancestor — but in malformed (or hostile) input it can, which
    // would loop the walker forever. Track every visited node and
    // refuse to re-enter one.
    if !visited.insert(node_id) {
        return Err(PdfError::other(format!(
            "PDF reader: /Pages tree contains a cycle at {node_id:?}"
        )));
    }
    let node = reader.resolve(node_id)?;
    let Object::Dict(d) = node else {
        return Err(PdfError::other(format!(
            "PDF reader: pages-tree node {node_id:?} is not a dict"
        )));
    };
    let kind = d
        .entries()
        .iter()
        .find(|(k, _)| k == "Type")
        .and_then(|(_, v)| match v {
            Object::Name(s) => Some(s.as_str()),
            _ => None,
        });
    match kind {
        Some("Page") => {
            out.push(node_id);
            Ok(())
        }
        Some("Pages") => {
            let kids = d
                .entries()
                .iter()
                .find(|(k, _)| k == "Kids")
                .map(|(_, v)| v.clone())
                .ok_or_else(|| {
                    PdfError::other(format!("PDF reader: /Pages node {node_id:?} missing /Kids"))
                })?;
            let Object::Array(items) = kids else {
                return Err(PdfError::other(format!(
                    "PDF reader: /Kids must be an array on {node_id:?}"
                )));
            };
            for item in items {
                if let Object::Reference(id) = item {
                    walk_pages_tree_inner(reader, id, out, visited, depth + 1)?;
                }
            }
            Ok(())
        }
        _ => Err(PdfError::other(format!(
            "PDF reader: pages-tree node {node_id:?} has unknown /Type {kind:?}"
        ))),
    }
}

/// Maximum `/Parent` chain length walked when resolving an inheritable
/// page attribute (§7.7.3.4). A well-formed page tree is shallow; this
/// ceiling bounds a malformed or cyclic chain so resolution always
/// terminates even though the per-node visited set already breaks a
/// direct cycle.
const MAX_PAGE_TREE_DEPTH: usize = 64;

/// Resolve an inheritable page attribute (`MediaBox`, `Resources`,
/// `CropBox`, or `Rotate`, §7.7.3.4 Table 30) for a leaf page. The
/// page dictionary is checked first; when it omits the key the
/// `/Parent` chain is walked up the page tree and the first ancestor
/// that carries the key supplies the value. Returns `Ok(None)` when
/// neither the page nor any ancestor defines it (the caller then
/// applies the attribute's default).
///
/// The walk is bounded by [`MAX_PAGE_TREE_DEPTH`] and cycle-guarded by
/// a visited-id set so a self-referential `/Parent` (malformed input)
/// can't loop. The returned `Object` is the value verbatim (an
/// indirect reference is *not* dereferenced here — the caller's
/// existing one-hop resolution handles that, matching the prior
/// directly-attached path).
fn resolve_inheritable_attr(
    reader: &mut DocumentReader<'_>,
    page_dict: &Dict,
    key: &str,
) -> Result<Option<Object>, PdfError> {
    if let Some((_, v)) = page_dict.entries().iter().find(|(k, _)| k == key) {
        return Ok(Some(v.clone()));
    }
    // Climb `/Parent` until the key is found, the chain ends, or the
    // depth / cycle guard fires.
    let mut parent = page_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Parent")
        .map(|(_, v)| v.clone());
    let mut visited: HashSet<ObjectId> = HashSet::new();
    let mut depth = 0;
    while let Some(Object::Reference(parent_id)) = parent {
        if depth >= MAX_PAGE_TREE_DEPTH || !visited.insert(parent_id) {
            break;
        }
        depth += 1;
        let Object::Dict(node) = reader.resolve(parent_id)? else {
            break;
        };
        if let Some((_, v)) = node.entries().iter().find(|(k, _)| k == key) {
            return Ok(Some(v.clone()));
        }
        parent = node
            .entries()
            .iter()
            .find(|(k, _)| k == "Parent")
            .map(|(_, v)| v.clone());
    }
    Ok(None)
}

fn decode_page(
    reader: &mut DocumentReader<'_>,
    page_id: ObjectId,
    optional_content: Option<&crate::reader::ocg::OptionalContent>,
) -> Result<Page, PdfError> {
    let page_obj = reader.resolve(page_id)?;
    let Object::Dict(page_dict) = page_obj else {
        return Err(PdfError::other(format!(
            "PDF reader: page {page_id:?} is not a dict"
        )));
    };

    // /MediaBox is required for the leaf page or inherited from an
    // ancestor /Pages node (§7.7.3.4 — `MediaBox` is one of the four
    // inheritable page attributes alongside `Resources`, `CropBox`,
    // and `Rotate`). Walk the `/Parent` chain when the leaf omits it.
    let media_box = resolve_inheritable_attr(reader, &page_dict, "MediaBox")?;
    let (width, height) = match media_box {
        Some(Object::Array(items)) if items.len() == 4 => {
            let llx = number_to_f32(&items[0])?;
            let lly = number_to_f32(&items[1])?;
            let urx = number_to_f32(&items[2])?;
            let ury = number_to_f32(&items[3])?;
            ((urx - llx).abs(), (ury - lly).abs())
        }
        Some(other) => {
            return Err(PdfError::other(format!(
                "PDF reader: /MediaBox must be a 4-array (got {other:?})"
            )));
        }
        None => {
            // No /MediaBox on the page or any ancestor — default to A4
            // portrait so the page object is still constructible.
            (595.0, 842.0)
        }
    };

    // /Contents is one stream OR an array of streams. Concatenate.
    let contents_obj = page_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Contents")
        .map(|(_, v)| v.clone());
    let content_bytes = match contents_obj {
        Some(Object::Reference(id)) => extract_stream_data(reader, id)?,
        Some(Object::Array(items)) => {
            let mut all = Vec::new();
            for item in items {
                if let Object::Reference(id) = item {
                    all.extend_from_slice(&extract_stream_data(reader, id)?);
                    all.push(b'\n');
                }
            }
            all
        }
        Some(other) => {
            return Err(PdfError::other(format!(
                "PDF reader: /Contents must be a Stream or array (got {other:?})"
            )));
        }
        None => Vec::new(),
    };

    // /Resources is a dictionary or an indirect reference to one
    // (§7.8.3 Table 33). It is inheritable (§7.7.3.4): a page that
    // omits it takes the nearest ancestor /Pages node's /Resources, so
    // documents that hang one resource dictionary on the page-tree root
    // resolve their fonts / XObjects / shadings instead of rendering
    // empty.
    let resources_obj = resolve_inheritable_attr(reader, &page_dict, "Resources")?;
    let resources_dict = match resources_obj {
        Some(Object::Reference(id)) => match reader.resolve(id)? {
            Object::Dict(d) => Some(d),
            _ => None,
        },
        Some(Object::Dict(d)) => Some(d),
        _ => None,
    };
    let ext_gstate_dict = if let Some(rdict) = resources_dict.as_ref() {
        resolve_ext_gstate(reader, rdict)?
    } else {
        None
    };
    let fonts_dict = if let Some(rdict) = resources_dict.as_ref() {
        resolve_font_resources(reader, rdict)?
    } else {
        None
    };
    let shading_dict = if let Some(rdict) = resources_dict.as_ref() {
        resolve_shading_resources(reader, rdict)?
    } else {
        None
    };
    let color_space_dict = if let Some(rdict) = resources_dict.as_ref() {
        resolve_color_space_resources(reader, rdict)?
    } else {
        None
    };
    let properties_dict = if let Some(rdict) = resources_dict.as_ref() {
        resolve_properties_resources(reader, rdict)?
    } else {
        None
    };
    let xobject_forms = if let Some(rdict) = resources_dict.as_ref() {
        let mut seen = HashSet::new();
        resolve_xobject_forms(reader, rdict, 0, &mut seen)?
    } else {
        None
    };
    let pattern_dict = if let Some(rdict) = resources_dict.as_ref() {
        resolve_pattern_resources(reader, rdict)?
    } else {
        None
    };
    let tiling_patterns = if let Some(rdict) = resources_dict.as_ref() {
        resolve_tiling_patterns(reader, rdict, 0)?
    } else {
        None
    };
    let type3_fonts = if let Some(rdict) = resources_dict.as_ref() {
        resolve_type3_fonts(reader, rdict, 0)?
    } else {
        None
    };
    let soft_masks = if let Some(rdict) = resources_dict.as_ref() {
        let mut seen = HashSet::new();
        resolve_soft_masks(reader, rdict, 0, &mut seen)?
    } else {
        None
    };

    let parsed = parse_content_stream_full_with_soft_masks(
        &content_bytes,
        ext_gstate_dict.as_ref(),
        fonts_dict.as_ref(),
        shading_dict.as_ref(),
        color_space_dict.as_ref(),
        properties_dict.as_ref(),
        xobject_forms.as_ref(),
        pattern_dict.as_ref(),
        tiling_patterns.as_ref(),
        type3_fonts.as_ref(),
        soft_masks.as_ref(),
    )?;
    let mut root = parsed.root;

    // §12.5.5 — paint each /Annots annotation's applicable appearance
    // stream on top of the page content (the appearance composites
    // over "the page content along with any previously painted
    // annotations", so array order is paint order).
    let annot_groups = resolve_annotation_appearances(reader, &page_dict, optional_content)?;
    if !annot_groups.is_empty() {
        // The parsed page root is normally a bare container; if it
        // carries its own transform / clip / opacity, nest it so the
        // annotation groups (positioned in default user space) don't
        // inherit page-content state.
        if root.transform != Transform2D::identity() || root.clip.is_some() || root.opacity != 1.0 {
            root = Group {
                children: vec![Node::Group(root)],
                ..Group::default()
            };
        }
        root.children
            .extend(annot_groups.into_iter().map(Node::Group));
    }

    let mut page = Page::new(width, height);
    // /Rotate (§7.7.3.3 Table 30) — degrees clockwise, a multiple of
    // 90, inheritable. Normalise any multiple of 90 (incl. negative /
    // > 360 values some producers emit) into the canonical 0 / 90 /
    // 180 / 270 the scene `Page::orientation` carries; a non-multiple
    // of 90 is malformed and left at the default 0.
    if let Some(Object::Integer(deg)) = resolve_inheritable_attr(reader, &page_dict, "Rotate")? {
        if deg % 90 == 0 {
            page.orientation = (deg.rem_euclid(360)) as u16;
        }
    }
    page.content = VectorFrame {
        width,
        height,
        view_box: None,
        root,
        pts: None,
        time_base: TimeBase::new(1, 1),
    };
    Ok(page)
}

/// Resolve a page's `/Resources /ExtGState` subdictionary into a
/// fully-dereferenced [`Dict`] (each per-name `/GSx` value is itself
/// resolved into a direct `Dict` if it was an indirect reference).
/// Returns `Ok(None)` when the resources dict carries no `/ExtGState`
/// entry — the most common case for documents that don't use the
/// `gs` operator.
///
/// Only direct + single-hop indirect dicts are surfaced. A malformed
/// entry (non-dict resolved value, deeply nested indirection beyond a
/// single hop) is silently dropped so a `gs` against that name
/// behaves as a tolerated no-op, matching the round-3 fallback.
fn resolve_ext_gstate(
    reader: &mut DocumentReader<'_>,
    resources: &Dict,
) -> Result<Option<Dict>, PdfError> {
    let ext_obj = resources
        .entries()
        .iter()
        .find(|(k, _)| k == "ExtGState")
        .map(|(_, v)| v.clone());
    let ext_obj = match ext_obj {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Dict(ext_dict) = ext_obj else {
        return Ok(None);
    };
    // Walk each per-name entry; resolve a one-hop indirect reference
    // into its target dict so the content-stream parser can read entry
    // keys directly without touching the reader.
    let mut out = Dict::new();
    for (name, value) in ext_dict.entries() {
        let resolved = match value {
            Object::Reference(id) => reader.resolve(*id)?,
            other => other.clone(),
        };
        if let Object::Dict(d) = resolved {
            out.set(name, Object::Dict(d));
        }
    }
    Ok(Some(out))
}

/// Resolve a page's `/Resources /Font` subdictionary into a
/// fully-dereferenced [`Dict`] (each per-name `/Fx` value is itself
/// resolved into a direct `Dict` if it was an indirect reference).
/// Returns `Ok(None)` when the resources dict carries no `/Font`
/// entry — the most common case for documents that don't use any
/// text-showing operator (`Tj` / `TJ` / `'` / `"`).
///
/// Mirrors [`resolve_ext_gstate`]'s shape so the round-128 `Tj` /
/// `TJ` plumbing slots into the same single-hop indirect dereference
/// path the round-125 `gs` resolver uses (ISO 32000-1 §7.8.3 + Table 33
/// for the `/Resources` shape, §9.5 + §9.6 + §9.7 for fonts).
///
/// Only direct + single-hop indirect dicts are surfaced. A malformed
/// entry (non-dict resolved value, deeply nested indirection beyond a
/// single hop) is silently dropped so a `Tj` against that font name
/// behaves as a "font unresolved" event (the show still fires with
/// `font_dict = None` so the consumer knows what happened), matching
/// the round-3 tolerance stance.
fn resolve_font_resources(
    reader: &mut DocumentReader<'_>,
    resources: &Dict,
) -> Result<Option<Dict>, PdfError> {
    let font_obj = resources
        .entries()
        .iter()
        .find(|(k, _)| k == "Font")
        .map(|(_, v)| v.clone());
    let font_obj = match font_obj {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Dict(font_dict) = font_obj else {
        return Ok(None);
    };
    let mut out = Dict::new();
    for (name, value) in font_dict.entries() {
        let resolved = match value {
            Object::Reference(id) => reader.resolve(*id)?,
            other => other.clone(),
        };
        if let Object::Dict(mut d) = resolved {
            // Deep-resolve the entries the content walker's §9.4.4 text
            // advance needs (`/Widths`, `/FontDescriptor /MissingWidth`,
            // and for Type0 the descendant CIDFont's `/W` / `/DW`) so
            // they are direct numerics / arrays rather than indirect
            // references when `build_font_metrics` reads them.
            resolve_font_widths(reader, &mut d)?;
            out.set(name, Object::Dict(d));
        }
    }
    Ok(Some(out))
}

/// Dereference the width-related entries of a single resolved font
/// dictionary so the content walker's §9.4.4 advance sees direct
/// values. Mutates `font` in place:
///
/// * `/Widths` — an indirect array reference is replaced by the
///   resolved `Object::Array`.
/// * `/FontDescriptor` — resolved to a direct dict (its
///   `/MissingWidth` is read by the walker).
/// * `/DescendantFonts` — for Type0 fonts the (usually one-element)
///   array is resolved, its CIDFont dict dereferenced, and that
///   CIDFont's `/W` array dereferenced. The descendant is stored back
///   as a direct `Object::Dict` so `build_cid_metrics` finds it.
fn resolve_font_widths(reader: &mut DocumentReader<'_>, font: &mut Dict) -> Result<(), PdfError> {
    // /Widths (simple fonts) — resolve an indirect array.
    if let Some(Object::Reference(id)) =
        font.entries()
            .iter()
            .find_map(|(k, v)| if k == "Widths" { Some(v.clone()) } else { None })
    {
        let resolved = reader.resolve(id)?;
        font.set("Widths", resolved);
    }
    // /FontDescriptor — resolve to a direct dict for /MissingWidth.
    if let Some(Object::Reference(id)) = font.entries().iter().find_map(|(k, v)| {
        if k == "FontDescriptor" {
            Some(v.clone())
        } else {
            None
        }
    }) {
        if let Ok(Object::Dict(d)) = reader.resolve(id) {
            font.set("FontDescriptor", Object::Dict(d));
        }
    }
    // /DescendantFonts (Type0) — resolve the array + CIDFont + its /W.
    let descendant_ref = font.entries().iter().find_map(|(k, v)| {
        if k == "DescendantFonts" {
            Some(v.clone())
        } else {
            None
        }
    });
    if let Some(obj) = descendant_ref {
        let array_obj = match obj {
            Object::Reference(id) => reader.resolve(id)?,
            other => other,
        };
        // Pull the first dict (the sole CIDFont) out of the array.
        let cid_ref = match array_obj {
            Object::Array(items) => items.into_iter().next(),
            Object::Dict(d) => Some(Object::Dict(d)),
            _ => None,
        };
        if let Some(cid_obj) = cid_ref {
            let cid_obj = match cid_obj {
                Object::Reference(id) => reader.resolve(id)?,
                other => other,
            };
            if let Object::Dict(mut cid_font) = cid_obj {
                // Resolve the CIDFont's /W array (often indirect).
                if let Some(Object::Reference(id)) = cid_font.entries().iter().find_map(|(k, v)| {
                    if k == "W" {
                        Some(v.clone())
                    } else {
                        None
                    }
                }) {
                    let resolved = reader.resolve(id)?;
                    cid_font.set("W", resolved);
                }
                font.set("DescendantFonts", Object::Dict(cid_font));
            }
        }
    }
    Ok(())
}

/// Resolve a page's `/Resources /Shading` subdictionary into a
/// fully-dereferenced [`Dict`] (each per-name `/Shx` value is itself
/// resolved into a direct `Object::Dict` if it was an indirect
/// reference, *and* indirect `Object::Stream` values are surfaced
/// as their stream dictionary — Type 4..7 shadings are stream
/// objects per §8.7.4.5 Tables 82..86 whose dictionary holds the
/// Table 78 + per-type entries).
///
/// Returns `Ok(None)` when the resources dict carries no `/Shading`
/// entry — the most common case for documents that don't use the
/// `sh` operator (gradients via `Pattern Type 2` go through
/// `/Resources /Pattern` instead).
///
/// Mirrors [`resolve_ext_gstate`] / [`resolve_font_resources`] —
/// single-hop indirect dereference, malformed entries silently
/// dropped so a `sh` against the missing name still emits the event
/// with `shading_dict = None`.
fn resolve_shading_resources(
    reader: &mut DocumentReader<'_>,
    resources: &Dict,
) -> Result<Option<Dict>, PdfError> {
    let shading_obj = resources
        .entries()
        .iter()
        .find(|(k, _)| k == "Shading")
        .map(|(_, v)| v.clone());
    let shading_obj = match shading_obj {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Dict(shading_dict) = shading_obj else {
        return Ok(None);
    };
    let mut out = Dict::new();
    for (name, value) in shading_dict.entries() {
        let resolved = match value {
            Object::Reference(id) => reader.resolve(*id)?,
            other => other.clone(),
        };
        // Type 1..3 shadings are bare dictionaries (§8.7.4.5.2..4);
        // Type 4..7 shadings are streams whose dictionary holds the
        // same Table 78 + per-type entries plus the bit-packed mesh
        // geometry payload in the stream body. For a stream-shaped
        // shading the decoded body is folded into the surfaced
        // dictionary under the synthetic `__MeshData` key (a
        // `HexString`), mirroring the Type 0 function `__Samples`
        // handling, so the content parser can interpret the mesh
        // without re-fetching the stream. Either shape's optional
        // `/Function` entry (§8.7.4.5.5..8 — a parametric colour
        // transform shared by mesh types) is prepared in place so the
        // parser sees a self-contained, evaluable function.
        let d = match resolved {
            Object::Dict(d) => Some(d),
            Object::Stream(s) => {
                let mesh = decode_stream(&s)?;
                let mut d = s.dict;
                d.set("__MeshData", Object::HexString(mesh));
                Some(d)
            }
            _ => None,
        };
        if let Some(mut d) = d {
            if let Some((_, fobj)) = d
                .entries()
                .iter()
                .find(|(k, _)| k == "Function")
                .map(|(k, v)| (k.clone(), v.clone()))
            {
                // §8.7.4.5.5: `/Function` is either a single 1-in /
                // n-out function or an array of n 1-in / 1-out
                // functions. A reference may stand in for either; one
                // hop is dereferenced before deciding which shape it
                // is, then each element of an array is prepared
                // individually.
                let fobj = match fobj {
                    Object::Reference(id) => reader.resolve(id)?,
                    other => other,
                };
                let prepared = match fobj {
                    Object::Array(items) => {
                        let mut prepared = Vec::with_capacity(items.len());
                        for f in items {
                            prepared.push(prepare_function_object(reader, f)?);
                        }
                        Object::Array(prepared)
                    }
                    other => prepare_function_object(reader, other)?,
                };
                d.set("Function", prepared);
            }
            out.set(name, Object::Dict(d));
        }
    }
    Ok(Some(out))
}

/// Resolve a page's `/Resources /Pattern` subdictionary (§8.7.3) into a
/// fully-dereferenced [`Dict`] the content parser can interpret for
/// `scn`/`SCN` shading-pattern fills.
///
/// Returns `Ok(None)` when the resources dict carries no `/Pattern`
/// entry. Each per-name value is dereferenced to a pattern dictionary
/// (a tiling pattern, `/PatternType 1`, is a *stream*; a shading
/// pattern, `/PatternType 2`, is a bare dictionary). For a shading
/// pattern the nested `/Shading` is dereferenced and, when it is an
/// axial / radial shading carrying a `/Function`, that function is
/// prepared in place (sample bodies / nested references resolved) so the
/// content parser sees a self-contained, evaluable shading — mirroring
/// [`resolve_shading_resources`]. Tiling patterns are surfaced verbatim
/// (the parser renders no scene primitive for them this round). The pattern's `/Matrix` is left as-is.
fn resolve_pattern_resources(
    reader: &mut DocumentReader<'_>,
    resources: &Dict,
) -> Result<Option<Dict>, PdfError> {
    let pat_obj = resources
        .entries()
        .iter()
        .find(|(k, _)| k == "Pattern")
        .map(|(_, v)| v.clone());
    let pat_obj = match pat_obj {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Dict(pat_dict) = pat_obj else {
        return Ok(None);
    };
    let mut out = Dict::new();
    for (name, value) in pat_dict.entries() {
        let resolved = match value {
            Object::Reference(id) => reader.resolve(*id)?,
            other => other.clone(),
        };
        // A shading pattern is a bare dict; a tiling pattern is a stream
        // (its dict still carries /PatternType 1). Surface the dict for
        // either shape; only the shading-pattern path is interpreted.
        let mut d = match resolved {
            Object::Dict(d) => d,
            Object::Stream(s) => s.dict,
            _ => continue,
        };
        // For a shading pattern (PatternType 2), dereference + prepare
        // the nested /Shading so the content parser sees a self-contained
        // shading dictionary with an evaluable /Function.
        if let Some((_, sh)) = d
            .entries()
            .iter()
            .find(|(k, _)| k == "Shading")
            .map(|(k, v)| (k.clone(), v.clone()))
        {
            let sh = match sh {
                Object::Reference(id) => reader.resolve(id)?,
                other => other,
            };
            if let Object::Dict(mut shading) = sh {
                if let Some((_, fobj)) = shading
                    .entries()
                    .iter()
                    .find(|(k, _)| k == "Function")
                    .map(|(k, v)| (k.clone(), v.clone()))
                {
                    let fobj = match fobj {
                        Object::Reference(id) => reader.resolve(id)?,
                        other => other,
                    };
                    let prepared = match fobj {
                        Object::Array(items) => {
                            let mut prepared = Vec::with_capacity(items.len());
                            for f in items {
                                prepared.push(prepare_function_object(reader, f)?);
                            }
                            Object::Array(prepared)
                        }
                        other => prepare_function_object(reader, other)?,
                    };
                    shading.set("Function", prepared);
                }
                d.set("Shading", Object::Dict(shading));
            }
        }
        out.set(name, Object::Dict(d));
    }
    Ok(Some(out))
}

/// Resolve a page's `/Resources /Pattern` subdictionary into the
/// pre-parsed `/PatternType 1` tiling patterns (§8.7.3) the content
/// walker replicates across `scn`/`SCN` tiling-pattern fills. Each
/// tiling pattern is a *stream*; its content stream is decoded and
/// parsed into a [`Group`] against the pattern's own `/Resources`
/// (mirroring [`resolve_one_form_xobject`]), and the `/BBox`, `/XStep`,
/// `/YStep`, `/Matrix`, and `/PaintType` (Table 75) are captured.
///
/// Returns `Ok(None)` when the resources dict carries no `/Pattern`
/// entry or no entry is a renderable tiling pattern (a shading pattern,
/// `/PatternType 2`, is handled separately by
/// [`resolve_pattern_resources`]). A tiling pattern whose cell can't be
/// decoded, whose `/XStep` / `/YStep` is zero/absent, or whose `/BBox`
/// is malformed is skipped (its fill keeps the conservative black
/// fallback). `depth` bounds nested-Form recursion inside a cell.
fn resolve_tiling_patterns(
    reader: &mut DocumentReader<'_>,
    resources: &Dict,
    depth: usize,
) -> Result<Option<BTreeMap<String, TilingPattern>>, PdfError> {
    if depth >= MAX_XOBJECT_DEPTH {
        return Ok(None);
    }
    let pat_obj = resources
        .entries()
        .iter()
        .find(|(k, _)| k == "Pattern")
        .map(|(_, v)| v.clone());
    let pat_obj = match pat_obj {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Dict(pat_dict) = pat_obj else {
        return Ok(None);
    };
    let mut out: BTreeMap<String, TilingPattern> = BTreeMap::new();
    for (name, value) in pat_dict.entries() {
        let resolved = match value {
            Object::Reference(id) => reader.resolve(*id)?,
            other => other.clone(),
        };
        // Only a tiling pattern is a stream; a shading pattern is a bare
        // dict (handled elsewhere).
        let Object::Stream(stream) = resolved else {
            continue;
        };
        if dict_int(&stream.dict, "PatternType") != Some(1) {
            continue;
        }
        if let Some(tp) = resolve_one_tiling_pattern(reader, &stream, depth)? {
            out.insert(name.clone(), tp);
        }
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

/// Parse one `/PatternType 1` tiling pattern stream into a
/// [`TilingPattern`] (§8.7.3.1 Table 75). Returns `Ok(None)` when the
/// cell content can't be decoded / parses to nothing, the required
/// `/XStep` / `/YStep` is missing or zero, or the `/BBox` is malformed.
fn resolve_one_tiling_pattern(
    reader: &mut DocumentReader<'_>,
    stream: &Stream,
    depth: usize,
) -> Result<Option<TilingPattern>, PdfError> {
    let bbox = match read_rect(&stream.dict, "BBox") {
        Some(r) => r,
        None => return Ok(None),
    };
    let xstep = match dict_num(&stream.dict, "XStep") {
        Some(v) if v.is_finite() && v != 0.0 => v,
        _ => return Ok(None),
    };
    let ystep = match dict_num(&stream.dict, "YStep") {
        Some(v) if v.is_finite() && v != 0.0 => v,
        _ => return Ok(None),
    };
    let paint_type = dict_int(&stream.dict, "PaintType").unwrap_or(1);
    let matrix = form_matrix(&stream.dict);

    let content_bytes = match decode_stream(stream) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };

    // The cell's own /Resources (Table 75 — required, but tolerate
    // absence the same way a Form XObject does).
    let cell_resources = match stream.dict.entries().iter().find(|(k, _)| k == "Resources") {
        Some((_, Object::Reference(id))) => match reader.resolve(*id)? {
            Object::Dict(d) => Some(d),
            _ => None,
        },
        Some((_, Object::Dict(d))) => Some(d.clone()),
        _ => None,
    };

    let ext_gstate_dict = match cell_resources.as_ref() {
        Some(r) => resolve_ext_gstate(reader, r)?,
        None => None,
    };
    let fonts_dict = match cell_resources.as_ref() {
        Some(r) => resolve_font_resources(reader, r)?,
        None => None,
    };
    let shading_dict = match cell_resources.as_ref() {
        Some(r) => resolve_shading_resources(reader, r)?,
        None => None,
    };
    let color_space_dict = match cell_resources.as_ref() {
        Some(r) => resolve_color_space_resources(reader, r)?,
        None => None,
    };
    let properties_dict = match cell_resources.as_ref() {
        Some(r) => resolve_properties_resources(reader, r)?,
        None => None,
    };
    let mut seen = HashSet::new();
    let nested_forms = match cell_resources.as_ref() {
        Some(r) => resolve_xobject_forms(reader, r, depth + 1, &mut seen)?,
        None => None,
    };
    let pattern_dict = match cell_resources.as_ref() {
        Some(r) => resolve_pattern_resources(reader, r)?,
        None => None,
    };
    // A cell may itself paint with a tiling pattern (§8.7.2 NOTE 1 — an
    // inner pattern is local to the outer cell); recurse with a deeper
    // bound so a self-referential pattern terminates.
    let nested_tiling = match cell_resources.as_ref() {
        Some(r) => resolve_tiling_patterns(reader, r, depth + 1)?,
        None => None,
    };

    let parsed = parse_content_stream_full_with_tiling(
        &content_bytes,
        ext_gstate_dict.as_ref(),
        fonts_dict.as_ref(),
        shading_dict.as_ref(),
        color_space_dict.as_ref(),
        properties_dict.as_ref(),
        nested_forms.as_ref(),
        pattern_dict.as_ref(),
        nested_tiling.as_ref(),
    )?;
    if parsed.root.children.is_empty() {
        return Ok(None);
    }
    Ok(Some(TilingPattern {
        cell: parsed.root,
        bbox,
        xstep,
        ystep,
        matrix,
        paint_type,
    }))
}

/// Resolve every Type 3 font (§9.6.5) in a `/Resources /Font`
/// subdictionary into a [`Type3Font`], keyed by font resource name.
///
/// For each `/Subtype /Type3` font dictionary this:
///
/// * reads `/FontMatrix` (glyph→text space, default `[0.001 0 0 0.001
///   0 0]`);
/// * parses `/Encoding /Differences` into a code→glyph-name map
///   (§9.6.6.1 — a Type 3 font's encoding is given entirely by
///   `/Differences`, Table 112);
/// * decodes each `/CharProcs` glyph-description stream and parses it
///   against the font's own `/Resources` (falling back to the page's
///   when absent, §9.6.5 Table 112) into a [`Group`].
///
/// Non-Type3 fonts and any glyph that fails to decode are skipped. A
/// font with no usable glyphs is omitted from the map. `depth` bounds
/// the Form / pattern recursion a glyph description may trigger.
fn resolve_type3_fonts(
    reader: &mut DocumentReader<'_>,
    resources: &Dict,
    depth: usize,
) -> Result<Option<BTreeMap<String, Type3Font>>, PdfError> {
    if depth >= MAX_XOBJECT_DEPTH {
        return Ok(None);
    }
    let font_obj = resources
        .entries()
        .iter()
        .find(|(k, _)| k == "Font")
        .map(|(_, v)| v.clone());
    let font_obj = match font_obj {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Dict(font_dict) = font_obj else {
        return Ok(None);
    };
    let mut out: BTreeMap<String, Type3Font> = BTreeMap::new();
    for (name, value) in font_dict.entries() {
        let resolved = match value {
            Object::Reference(id) => reader.resolve(*id)?,
            other => other.clone(),
        };
        let Object::Dict(fd) = resolved else {
            continue;
        };
        if !matches!(
            fd.entries().iter().find(|(k, _)| k == "Subtype"),
            Some((_, Object::Name(s))) if s == "Type3"
        ) {
            continue;
        }
        if let Some(font) = resolve_one_type3_font(reader, &fd, resources, depth)? {
            out.insert(name.clone(), font);
        }
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

/// Parse a single Type 3 font dictionary into a [`Type3Font`] (§9.6.5).
/// Returns `Ok(None)` when the font has no paintable glyphs.
///
/// `enclosing_resources` is the resource dictionary the font was found
/// in (the page's, a Form XObject's, or a pattern cell's). Per §9.6.5
/// Table 112, when a glyph description names resources but the font
/// carries no `/Resources` of its own, the names resolve against this
/// enclosing dictionary.
fn resolve_one_type3_font(
    reader: &mut DocumentReader<'_>,
    fd: &Dict,
    enclosing_resources: &Dict,
    depth: usize,
) -> Result<Option<Type3Font>, PdfError> {
    // /FontMatrix (Table 112, required) — default to the conventional
    // 1000-unit glyph space when absent / malformed.
    let font_matrix = match fd.entries().iter().find(|(k, _)| k == "FontMatrix") {
        Some((_, obj @ Object::Array(items))) if items.len() == 6 => array_matrix(obj),
        _ => Transform2D {
            a: 0.001,
            b: 0.0,
            c: 0.0,
            d: 0.001,
            e: 0.0,
            f: 0.0,
        },
    };

    // /Encoding /Differences → code → glyph name (§9.6.6.1). A Type 3
    // font's complete encoding lives in /Differences (Table 112).
    let mut encoding: BTreeMap<u8, String> = BTreeMap::new();
    let enc_obj = match fd.entries().iter().find(|(k, _)| k == "Encoding") {
        Some((_, Object::Reference(id))) => Some(reader.resolve(*id)?),
        Some((_, other)) => Some(other.clone()),
        None => None,
    };
    if let Some(Object::Dict(enc)) = enc_obj {
        let diffs = match enc.entries().iter().find(|(k, _)| k == "Differences") {
            Some((_, Object::Reference(id))) => Some(reader.resolve(*id)?),
            Some((_, other)) => Some(other.clone()),
            None => None,
        };
        if let Some(arr) = diffs {
            if let Ok(parsed) = crate::reader::encoding::parse_encoding_differences(&arr) {
                for ov in parsed.overrides {
                    encoding.insert(ov.code, ov.glyph_name);
                }
            }
        }
    }
    if encoding.is_empty() {
        return Ok(None);
    }

    // The font's own /Resources (Table 112). A glyph description that
    // names a resource looks it up here; when the font omits /Resources
    // the names fall back to the enclosing (page / form / cell) resource
    // dictionary the font was found in (§9.6.5 Table 112).
    let glyph_resources = match fd.entries().iter().find(|(k, _)| k == "Resources") {
        Some((_, Object::Reference(id))) => match reader.resolve(*id)? {
            Object::Dict(d) => Some(d),
            _ => Some(enclosing_resources.clone()),
        },
        Some((_, Object::Dict(d))) => Some(d.clone()),
        _ => Some(enclosing_resources.clone()),
    };

    // /CharProcs — glyph name → glyph-description stream (Table 112).
    let charprocs_obj = match fd.entries().iter().find(|(k, _)| k == "CharProcs") {
        Some((_, Object::Reference(id))) => reader.resolve(*id)?,
        Some((_, other)) => other.clone(),
        None => return Ok(None),
    };
    let Object::Dict(charprocs) = charprocs_obj else {
        return Ok(None);
    };

    let mut glyphs: BTreeMap<String, Group> = BTreeMap::new();
    let mut shape_only: BTreeSet<String> = BTreeSet::new();
    // Only resolve glyphs the encoding actually references.
    let referenced: BTreeSet<&String> = encoding.values().collect();
    for (glyph_name, value) in charprocs.entries() {
        if !referenced.contains(glyph_name) {
            continue;
        }
        let resolved = match value {
            Object::Reference(id) => reader.resolve(*id)?,
            other => other.clone(),
        };
        let Object::Stream(stream) = resolved else {
            continue;
        };
        let content_bytes = match decode_stream(&stream) {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Detect a leading `d1` (shape-only glyph, §9.6.5 Table 113) so
        // the walker can later recolour it with the current fill colour.
        if charproc_is_shape_only(&content_bytes) {
            shape_only.insert(glyph_name.clone());
        }
        if let Some(group) =
            parse_glyph_description(reader, &content_bytes, glyph_resources.as_ref(), depth)?
        {
            if !group.children.is_empty() {
                glyphs.insert(glyph_name.clone(), group);
            }
        }
    }
    if glyphs.is_empty() {
        return Ok(None);
    }
    Ok(Some(Type3Font {
        font_matrix,
        encoding,
        glyphs,
        shape_only,
    }))
}

/// Whether a Type 3 glyph description's first operator is `d1` (§9.6.5
/// Table 113) — meaning the glyph specifies shape only and takes its
/// colour from the graphics state. Scans past the leading numeric
/// operands to the first keyword token. A `d0` first operator (or
/// neither) means the glyph carries its own colour.
fn charproc_is_shape_only(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // Skip whitespace + numeric-operand characters (digits, sign,
        // dot, exponent) — d0/d1 are preceded by 2 or 6 numbers.
        if c.is_ascii_whitespace()
            || c.is_ascii_digit()
            || c == b'+'
            || c == b'-'
            || c == b'.'
            || c == b'e'
            || c == b'E'
        {
            i += 1;
            continue;
        }
        // First non-numeric token: must be `d0` or `d1`.
        if bytes[i..].starts_with(b"d1") {
            return true;
        }
        return false;
    }
    false
}

/// Parse a Type 3 glyph description content stream into a [`Group`]
/// (§9.6.5). The stream is parsed against the font's own `/Resources`
/// (`glyph_resources`); the `d0` / `d1` leading operator is consumed as
/// a no-op by the content walker. Returns `Ok(None)` when the content
/// parses to nothing.
fn parse_glyph_description(
    reader: &mut DocumentReader<'_>,
    content_bytes: &[u8],
    glyph_resources: Option<&Dict>,
    depth: usize,
) -> Result<Option<Group>, PdfError> {
    let ext_gstate_dict = match glyph_resources {
        Some(r) => resolve_ext_gstate(reader, r)?,
        None => None,
    };
    let fonts_dict = match glyph_resources {
        Some(r) => resolve_font_resources(reader, r)?,
        None => None,
    };
    let shading_dict = match glyph_resources {
        Some(r) => resolve_shading_resources(reader, r)?,
        None => None,
    };
    let color_space_dict = match glyph_resources {
        Some(r) => resolve_color_space_resources(reader, r)?,
        None => None,
    };
    let properties_dict = match glyph_resources {
        Some(r) => resolve_properties_resources(reader, r)?,
        None => None,
    };
    let mut seen = HashSet::new();
    let nested_forms = match glyph_resources {
        Some(r) => resolve_xobject_forms(reader, r, depth + 1, &mut seen)?,
        None => None,
    };
    let pattern_dict = match glyph_resources {
        Some(r) => resolve_pattern_resources(reader, r)?,
        None => None,
    };
    let tiling_patterns = match glyph_resources {
        Some(r) => resolve_tiling_patterns(reader, r, depth + 1)?,
        None => None,
    };
    // A glyph description may itself show text in a (nested) Type 3
    // font; recurse with a deeper bound so a self-referential glyph
    // terminates.
    let nested_type3 = match glyph_resources {
        Some(r) => resolve_type3_fonts(reader, r, depth + 1)?,
        None => None,
    };

    let parsed = parse_content_stream_full_with_type3(
        content_bytes,
        ext_gstate_dict.as_ref(),
        fonts_dict.as_ref(),
        shading_dict.as_ref(),
        color_space_dict.as_ref(),
        properties_dict.as_ref(),
        nested_forms.as_ref(),
        pattern_dict.as_ref(),
        tiling_patterns.as_ref(),
        nested_type3.as_ref(),
    )?;
    if parsed.root.children.is_empty() {
        return Ok(None);
    }
    Ok(Some(parsed.root))
}

/// A six-number `/FontMatrix` / `/Matrix` array `Object` as a
/// [`Transform2D`]. Caller guarantees the array has six elements.
fn array_matrix(obj: &Object) -> Transform2D {
    let Object::Array(items) = obj else {
        return Transform2D::identity();
    };
    let mut m = [0.0f32; 6];
    for (i, slot) in m.iter_mut().enumerate() {
        match items.get(i) {
            Some(Object::Integer(v)) => *slot = *v as f32,
            Some(Object::Real(v)) => *slot = *v as f32,
            _ => return Transform2D::identity(),
        }
    }
    Transform2D {
        a: m[0],
        b: m[1],
        c: m[2],
        d: m[3],
        e: m[4],
        f: m[5],
    }
}

/// Read a dict entry as an `f32` (Integer or Real). `None` for any other
/// shape or an absent key.
fn dict_num(dict: &Dict, key: &str) -> Option<f32> {
    match dict
        .entries()
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
    {
        Some(Object::Integer(v)) => Some(*v as f32),
        Some(Object::Real(v)) => Some(*v as f32),
        _ => None,
    }
}

/// Read a dict entry as an `i64` (Integer). `None` for any other shape.
fn dict_int(dict: &Dict, key: &str) -> Option<i64> {
    match dict
        .entries()
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
    {
        Some(Object::Integer(v)) => Some(*v),
        _ => None,
    }
}

/// Read a four-number rectangle entry `[a b c d]` as `[a, b, c, d]`.
/// `None` when absent, not a 4-element array, or any element is not a
/// finite number.
fn read_rect(dict: &Dict, key: &str) -> Option<[f32; 4]> {
    let items = match dict
        .entries()
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
    {
        Some(Object::Array(items)) if items.len() == 4 => items,
        _ => return None,
    };
    let mut out = [0.0f32; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = match &items[i] {
            Object::Integer(v) => *v as f32,
            Object::Real(v) => *v as f32,
            _ => return None,
        };
        if !slot.is_finite() {
            return None;
        }
    }
    Some(out)
}

/// Resolve a page's `/Resources /ColorSpace` subdictionary into a
/// fully-dereferenced [`Dict`] whose per-name entries are resolved
/// colour-space `Object`s the round-275 content parser interprets
/// (ISO 32000-1 §8.6.8 Table 74 + §8.6.5 + §8.6.6).
///
/// Returns `Ok(None)` when the resources dict carries no `/ColorSpace`
/// entry — the common case for documents that paint only in the
/// implicit device families (`rg` / `g` / `k`) or name the device
/// families directly in `cs` / `CS`.
///
/// Each per-name value is resolved so the parser never has to touch
/// the reader:
///
/// * A bare device `/Name` passes through verbatim.
/// * An `[ /ICCBased <stream-ref> ]` array (§8.6.5.5) has the ICC
///   profile stream replaced by its **dictionary** — the parser reads
///   `/N` + `/Alternate` from it to pick the device fallback; the ICC
///   profile bytes are never interpreted, so they are dropped.
/// * An `[ /Indexed base hival lookup ]` array (§8.6.6.3) has a lookup
///   *stream* (PDF 1.2 allows a stream or a byte string) replaced by
///   its decoded bytes as a `HexString` so the parser sees a
///   self-contained colour table; a base that is itself an indirect
///   reference is dereferenced one hop.
///
/// Any other shape (CalRGB / CalGray / Lab / Separation / DeviceN /
/// Pattern, or a malformed entry) is surfaced verbatim — the parser's
/// [`crate::reader::content`] interpreter reduces what it can and
/// leaves the rest `Unknown` (the round-118 black fallback).
fn resolve_color_space_resources(
    reader: &mut DocumentReader<'_>,
    resources: &Dict,
) -> Result<Option<Dict>, PdfError> {
    let cs_obj = resources
        .entries()
        .iter()
        .find(|(k, _)| k == "ColorSpace")
        .map(|(_, v)| v.clone());
    let cs_obj = match cs_obj {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Dict(cs_dict) = cs_obj else {
        return Ok(None);
    };
    let mut out = Dict::new();
    for (name, value) in cs_dict.entries() {
        let resolved = match value {
            Object::Reference(id) => reader.resolve(*id)?,
            other => other.clone(),
        };
        let prepared = prepare_color_space_object(reader, resolved)?;
        out.set(name, prepared);
    }
    Ok(Some(out))
}

/// Resolve a page's `/Resources /Properties` subdictionary into a
/// fully-dereferenced [`Dict`] (each per-name property-list value is
/// itself resolved into a direct `Object::Dict` if it was an indirect
/// reference). Returns `Ok(None)` when the resources dict carries no
/// `/Properties` entry — the common case for documents that use no
/// `DP`/`BDC` marked-content operator, or that only ever write their
/// property lists inline (§14.6.2).
///
/// Mirrors [`resolve_ext_gstate`] / [`resolve_font_resources`] /
/// [`resolve_shading_resources`] — single-hop indirect dereference,
/// malformed entries silently dropped so a `DP`/`BDC` naming the
/// missing key still emits its event with `properties = None` (ISO
/// 32000-1 §14.6.2 + §7.8.3 Table 33 for the `/Resources /Properties`
/// shape).
fn resolve_properties_resources(
    reader: &mut DocumentReader<'_>,
    resources: &Dict,
) -> Result<Option<Dict>, PdfError> {
    let props_obj = resources
        .entries()
        .iter()
        .find(|(k, _)| k == "Properties")
        .map(|(_, v)| v.clone());
    let props_obj = match props_obj {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Dict(props_dict) = props_obj else {
        return Ok(None);
    };
    let mut out = Dict::new();
    for (name, value) in props_dict.entries() {
        let resolved = match value {
            Object::Reference(id) => reader.resolve(*id)?,
            other => other.clone(),
        };
        // A property list may also be carried as a stream object (e.g.
        // an /OCG membership dict referenced indirectly is a dict, but
        // some producers wrap larger lists in streams). Surface either
        // shape as the per-name entry's resolved `Dict`.
        let d = match resolved {
            Object::Dict(d) => Some(d),
            Object::Stream(s) => Some(s.dict),
            _ => None,
        };
        if let Some(d) = d {
            out.set(name, Object::Dict(d));
        }
    }
    Ok(Some(out))
}

/// Maximum nesting depth for Form XObject recursion (§8.10). A form
/// may paint another form via its own `Do`; without a ceiling a
/// pathologically deep (or cyclic, though the visited-set guards the
/// direct cycle) chain could exhaust the stack. 12 mirrors the
/// parser's own structural depth ceiling and is far beyond any
/// legitimate document's appearance-stream nesting.
const MAX_XOBJECT_DEPTH: usize = 12;

/// Resolve a page's (or form's) `/Resources /XObject` subdictionary
/// into a map of resource-name → pre-parsed Form XObject [`Group`]
/// (ISO 32000-1 §8.10). Image XObjects are skipped (they are surfaced
/// separately by [`crate::reader::images`]); only `/Subtype /Form`
/// entries are returned.
///
/// Each form's content stream is decoded, its own `/Resources` are
/// resolved, and its content is recursively parsed (so a form that
/// itself paints nested forms via `Do` is expanded). The resulting
/// `Group` carries:
///
/// * `transform` = the form's `/Matrix` (default identity), mapping
///   form space into the user space in effect where `Do` is invoked
///   (§8.10.1: the matrix is concatenated with the CTM);
/// * `clip` = the `/BBox` rectangle as a closed subpath (§8.10.1: the
///   form is clipped to its bounding box).
///
/// `depth` bounds the recursion at [`MAX_XOBJECT_DEPTH`]; `visited`
/// tracks the object ids of forms currently on the resolution stack so
/// a direct self-reference (a form whose content `Do`s itself) is
/// broken rather than looping. A malformed or unresolvable entry is
/// silently dropped so a `Do` against it behaves as a tolerated no-op.
///
/// Returns `Ok(None)` when the resources dict carries no `/XObject`
/// entry or when no entry resolved to a non-empty Form group.
/// Resolve every `/Resources /ExtGState` entry's `/SMask` soft-mask
/// dictionary (§11.6.5.2 Table 144) into a [`ResolvedSoftMask`], keyed
/// by the ExtGState resource name (the same key a `gs` operator names,
/// §8.4.5). The `/G` transparency-group XObject is parsed exactly like
/// a `Do`-spliced form — `/Matrix` on the group transform, `/BBox` as
/// the group clip, content against its own `/Resources` — and the `/S`
/// subtype maps `/Luminosity` → [`MaskKind::Luminance`] and `/Alpha` →
/// [`MaskKind::Alpha`]. Entries whose `/SMask` is absent, the name
/// `None`, missing a usable `/S` or `/G`, or whose group parses to
/// nothing are skipped (the walker then paints unmasked — the same
/// tolerant degradation every unresolvable resource takes).
fn resolve_soft_masks(
    reader: &mut DocumentReader<'_>,
    resources: &Dict,
    depth: usize,
    visited: &mut HashSet<ObjectId>,
) -> Result<Option<BTreeMap<String, ResolvedSoftMask>>, PdfError> {
    if depth >= MAX_XOBJECT_DEPTH {
        return Ok(None);
    }
    let ext_obj = resources
        .entries()
        .iter()
        .find(|(k, _)| k == "ExtGState")
        .map(|(_, v)| v.clone());
    let ext_obj = match ext_obj {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Dict(ext_dict) = ext_obj else {
        return Ok(None);
    };
    let mut out: BTreeMap<String, ResolvedSoftMask> = BTreeMap::new();
    for (name, value) in ext_dict.entries() {
        let gs = match value {
            Object::Reference(id) => reader.resolve(*id)?,
            other => other.clone(),
        };
        let Object::Dict(gs) = gs else { continue };
        let sm = gs
            .entries()
            .iter()
            .find(|(k, _)| k == "SMask")
            .map(|(_, v)| v.clone());
        let sm = match sm {
            Some(Object::Reference(id)) => reader.resolve(id)?,
            Some(other) => other,
            None => continue,
        };
        // `/SMask /None` (§11.6.4.3) carries nothing to resolve — the
        // walker handles the reset at `gs` time.
        let Object::Dict(sm) = sm else { continue };
        // `/S` — required subtype (Table 144).
        let kind = match sm.entries().iter().find(|(k, _)| k == "S").map(|(_, v)| v) {
            Some(Object::Name(s)) if s == "Luminosity" => MaskKind::Luminance,
            Some(Object::Name(s)) if s == "Alpha" => MaskKind::Alpha,
            _ => continue,
        };
        // `/G` — required transparency-group XObject (Table 144). An
        // XObject is an indirect stream object; capture the id so a
        // self-referential mask group is cycle-guarded.
        let g = sm
            .entries()
            .iter()
            .find(|(k, _)| k == "G")
            .map(|(_, v)| v.clone());
        let (g_id, g_obj) = match g {
            Some(Object::Reference(id)) => (Some(id), reader.resolve(id)?),
            Some(other) => (None, other),
            None => continue,
        };
        let Object::Stream(stream) = g_obj else {
            continue;
        };
        if let Some(id) = g_id {
            if visited.contains(&id) {
                continue;
            }
            visited.insert(id);
        }
        let group = resolve_one_form_xobject(reader, &stream, depth, visited)?;
        if let Some(id) = g_id {
            visited.remove(&id);
        }
        let Some(mask) = group else { continue };
        out.insert(name.clone(), ResolvedSoftMask { kind, mask });
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

fn resolve_xobject_forms(
    reader: &mut DocumentReader<'_>,
    resources: &Dict,
    depth: usize,
    visited: &mut HashSet<ObjectId>,
) -> Result<Option<BTreeMap<String, Group>>, PdfError> {
    if depth >= MAX_XOBJECT_DEPTH {
        return Ok(None);
    }
    let xobj_obj = resources
        .entries()
        .iter()
        .find(|(k, _)| k == "XObject")
        .map(|(_, v)| v.clone());
    let xobj_obj = match xobj_obj {
        Some(Object::Reference(id)) => reader.resolve(id)?,
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Dict(xobj_dict) = xobj_obj else {
        return Ok(None);
    };
    let mut out: BTreeMap<String, Group> = BTreeMap::new();
    for (name, value) in xobj_dict.entries() {
        // Per §8.9 / §8.10 an XObject is an indirect object; capture
        // its id so a form referencing itself is cycle-guarded.
        let (form_id, resolved) = match value {
            Object::Reference(id) => (Some(*id), reader.resolve(*id)?),
            other => (None, other.clone()),
        };
        let Object::Stream(stream) = resolved else {
            continue;
        };
        // Only Form XObjects splice into the scene tree here.
        let subtype = stream
            .dict
            .entries()
            .iter()
            .find(|(k, _)| k == "Subtype")
            .map(|(_, v)| v);
        if !matches!(subtype, Some(Object::Name(s)) if s == "Form") {
            continue;
        }
        if let Some(id) = form_id {
            if visited.contains(&id) {
                continue;
            }
            visited.insert(id);
        }
        let group = resolve_one_form_xobject(reader, &stream, depth, visited)?;
        if let Some(id) = form_id {
            visited.remove(&id);
        }
        if let Some(g) = group {
            if !g.children.is_empty() {
                out.insert(name.clone(), g);
            }
        }
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

/// Parse one Form XObject stream into a [`Group`] (§8.10.1). The
/// form's `/Matrix` becomes the group transform, its `/BBox` the group
/// clip, and its content stream — resolved against its own
/// `/Resources` (fonts, ext-gstate, shadings, colour spaces,
/// properties, and nested Form XObjects) — the group children.
/// Returns `Ok(None)` for a form that can't be decoded or whose
/// content parses to nothing.
fn resolve_one_form_xobject(
    reader: &mut DocumentReader<'_>,
    stream: &Stream,
    depth: usize,
    visited: &mut HashSet<ObjectId>,
) -> Result<Option<Group>, PdfError> {
    let content_bytes = match decode_stream(stream) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };

    // The form's own /Resources (Table 95). A form may omit it (PDF 1.1
    // promoted resources to the page), in which case the form sees no
    // resources here — its `Do` / text / shading operators degrade to
    // the same tolerated no-ops the page path uses for a missing entry.
    let form_resources = match stream.dict.entries().iter().find(|(k, _)| k == "Resources") {
        Some((_, Object::Reference(id))) => match reader.resolve(*id)? {
            Object::Dict(d) => Some(d),
            _ => None,
        },
        Some((_, Object::Dict(d))) => Some(d.clone()),
        _ => None,
    };

    let ext_gstate_dict = match form_resources.as_ref() {
        Some(r) => resolve_ext_gstate(reader, r)?,
        None => None,
    };
    let fonts_dict = match form_resources.as_ref() {
        Some(r) => resolve_font_resources(reader, r)?,
        None => None,
    };
    let shading_dict = match form_resources.as_ref() {
        Some(r) => resolve_shading_resources(reader, r)?,
        None => None,
    };
    let color_space_dict = match form_resources.as_ref() {
        Some(r) => resolve_color_space_resources(reader, r)?,
        None => None,
    };
    let properties_dict = match form_resources.as_ref() {
        Some(r) => resolve_properties_resources(reader, r)?,
        None => None,
    };
    let nested_forms = match form_resources.as_ref() {
        Some(r) => resolve_xobject_forms(reader, r, depth + 1, visited)?,
        None => None,
    };
    let pattern_dict = match form_resources.as_ref() {
        Some(r) => resolve_pattern_resources(reader, r)?,
        None => None,
    };
    let tiling_patterns = match form_resources.as_ref() {
        Some(r) => resolve_tiling_patterns(reader, r, depth + 1)?,
        None => None,
    };
    let type3_fonts = match form_resources.as_ref() {
        Some(r) => resolve_type3_fonts(reader, r, depth + 1)?,
        None => None,
    };
    // A form's own content may establish a soft mask from its own
    // /Resources /ExtGState (§11.6.5.2); `visited` doubles as the /G
    // cycle guard so a mask group referencing its enclosing form
    // terminates.
    let soft_masks = match form_resources.as_ref() {
        Some(r) => resolve_soft_masks(reader, r, depth + 1, visited)?,
        None => None,
    };

    let parsed = parse_content_stream_full_with_soft_masks(
        &content_bytes,
        ext_gstate_dict.as_ref(),
        fonts_dict.as_ref(),
        shading_dict.as_ref(),
        color_space_dict.as_ref(),
        properties_dict.as_ref(),
        nested_forms.as_ref(),
        pattern_dict.as_ref(),
        tiling_patterns.as_ref(),
        type3_fonts.as_ref(),
        soft_masks.as_ref(),
    )?;

    // The content parser returns a root `Group` carrying any top-level
    // `cm` transform + clip. We nest that under an outer group whose
    // transform is the form's /Matrix and whose clip is the /BBox, so
    // the §8.10.1 (b) concat-Matrix and (c) clip-BBox steps wrap the
    // form's own content as a single splice-able unit.
    let inner = parsed.root;
    let matrix = form_matrix(&stream.dict);
    let clip = form_bbox_clip(&stream.dict);
    let children = if inner.transform == Transform2D::identity()
        && inner.clip.is_none()
        && inner.opacity == 1.0
    {
        // The inner root is a bare container — flatten it so we don't
        // wrap an identity group inside the form group.
        inner.children
    } else {
        vec![Node::Group(inner)]
    };
    if children.is_empty() {
        return Ok(None);
    }
    Ok(Some(Group {
        transform: matrix,
        opacity: 1.0,
        clip,
        children,
        ..Group::default()
    }))
}

/// The form's `/Matrix` (§8.10.2 Table 95) as a [`Transform2D`], or
/// the identity matrix when absent / malformed.
fn form_matrix(dict: &Dict) -> Transform2D {
    let nums = match dict.entries().iter().find(|(k, _)| k == "Matrix") {
        Some((_, Object::Array(items))) if items.len() == 6 => items,
        _ => return Transform2D::identity(),
    };
    let mut m = [0.0f32; 6];
    for (i, slot) in m.iter_mut().enumerate() {
        match &nums[i] {
            Object::Integer(v) => *slot = *v as f32,
            Object::Real(v) => *slot = *v as f32,
            _ => return Transform2D::identity(),
        }
    }
    Transform2D {
        a: m[0],
        b: m[1],
        c: m[2],
        d: m[3],
        e: m[4],
        f: m[5],
    }
}

/// The form's `/BBox` (§8.10.2 Table 95) as a closed-rectangle clip
/// [`Path`], or `None` when absent / malformed. The four numbers are
/// the left, bottom, right, top edges in form space (the same
/// coordinate system the group transform — the form `/Matrix` — is
/// applied in, so the clip is expressed pre-transform exactly like the
/// content it bounds).
fn form_bbox_clip(dict: &Dict) -> Option<Path> {
    let items = match dict.entries().iter().find(|(k, _)| k == "BBox") {
        Some((_, Object::Array(items))) if items.len() == 4 => items,
        _ => return None,
    };
    let mut v = [0.0f32; 4];
    for (i, slot) in v.iter_mut().enumerate() {
        match &items[i] {
            Object::Integer(n) => *slot = *n as f32,
            Object::Real(n) => *slot = *n as f32,
            _ => return None,
        }
    }
    let (x0, y0, x1, y1) = (v[0], v[1], v[2], v[3]);
    // Normalise so the rectangle is well-formed regardless of edge
    // ordering (§8.10.2 names them left/bottom/right/top but a
    // producer may emit them swapped).
    let (lx, rx) = (x0.min(x1), x0.max(x1));
    let (by, ty) = (y0.min(y1), y0.max(y1));
    if rx <= lx || ty <= by {
        return None;
    }
    let mut path = Path::new();
    path.commands.push(PathCommand::MoveTo(Point::new(lx, by)));
    path.commands.push(PathCommand::LineTo(Point::new(rx, by)));
    path.commands.push(PathCommand::LineTo(Point::new(rx, ty)));
    path.commands.push(PathCommand::LineTo(Point::new(lx, ty)));
    path.commands.push(PathCommand::Close);
    Some(path)
}

/// A dictionary entry's 4-number rectangle, normalised so element 0/1
/// is the lower-left corner and 2/3 the upper-right (§7.9.5 — "the
/// form of a rectangle is not required to place the smaller values
/// first"; consumers shall normalise). Returns `None` when the entry
/// is absent, not a 4-array, or carries a non-numeric element.
fn dict_rect4(dict: &Dict, key: &str) -> Option<[f32; 4]> {
    let items = match dict.entries().iter().find(|(k, _)| k == key) {
        Some((_, Object::Array(items))) if items.len() == 4 => items,
        _ => return None,
    };
    let mut v = [0.0f32; 4];
    for (i, slot) in v.iter_mut().enumerate() {
        match &items[i] {
            Object::Integer(n) => *slot = *n as f32,
            Object::Real(n) => *slot = *n as f32,
            _ => return None,
        }
    }
    Some([
        v[0].min(v[2]),
        v[1].min(v[3]),
        v[0].max(v[2]),
        v[1].max(v[3]),
    ])
}

/// §12.5.5 — resolve every annotation in the page's `/Annots` array
/// (§12.5.2 Table 164) whose appearance dictionary carries an
/// applicable appearance stream, and return one positioned [`Group`]
/// per painted annotation, in `/Annots` array order.
///
/// Enumeration is best-effort like the `annotations()` surface: a
/// malformed annotation dictionary (or one whose appearance stream
/// can't be decoded) contributes nothing rather than aborting the
/// page.
fn resolve_annotation_appearances(
    reader: &mut DocumentReader<'_>,
    page_dict: &Dict,
    optional_content: Option<&crate::reader::ocg::OptionalContent>,
) -> Result<Vec<Group>, PdfError> {
    let annots = match page_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Annots")
        .map(|(_, v)| v.clone())
    {
        Some(Object::Reference(id)) => match reader.resolve(id) {
            Ok(o) => o,
            Err(_) => return Ok(Vec::new()),
        },
        Some(other) => other,
        None => return Ok(Vec::new()),
    };
    let Object::Array(items) = annots else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for item in items {
        let annot = match item {
            Object::Reference(id) => match reader.resolve(id) {
                Ok(o) => o,
                Err(_) => continue,
            },
            other => other,
        };
        let Object::Dict(annot) = annot else {
            continue;
        };
        // /OC (Table 164) — "Before the annotation is drawn, its
        // visibility shall be determined based on this entry"; an
        // invisible annotation "shall be skipped, as if it were not
        // in the document" (§12.5.2).
        if !annotation_oc_visible(reader, &annot, optional_content) {
            continue;
        }
        if let Some(group) = annotation_appearance_group(reader, &annot)? {
            out.push(group);
        }
    }
    Ok(out)
}

/// §12.5.2 Table 164 `/OC` — resolve the annotation's optional-content
/// visibility under the document's default configuration (§8.11). The
/// entry may reference an optional-content *group* (visible iff the
/// group's resolved state is ON) or an optional-content *membership*
/// dictionary (`/Type /OCMD`, evaluated through its `/P` policy or
/// `/VE` visibility expression per §8.11.2.2).
///
/// Tolerant defaults: no `/OC` entry, no `/OCProperties` in the
/// catalog (the document isn't layered), or an unresolvable entry all
/// mean *visible*. An OCG referenced by id but absent from
/// `/OCProperties /OCGs` is treated as hidden (matching
/// [`crate::reader::ocg::OptionalContent::is_visible`]).
fn annotation_oc_visible(
    reader: &mut DocumentReader<'_>,
    annot: &Dict,
    optional_content: Option<&crate::reader::ocg::OptionalContent>,
) -> bool {
    let Some(entry) = annot
        .entries()
        .iter()
        .find(|(k, _)| k == "OC")
        .map(|(_, v)| v.clone())
    else {
        return true;
    };
    let Some(oc) = optional_content else {
        return true;
    };
    let (group_id, dict) = match entry {
        Object::Reference(id) => match reader.resolve(id) {
            Ok(Object::Dict(d)) => (Some(id), d),
            _ => return true,
        },
        Object::Dict(d) => (None, d),
        _ => return true,
    };
    // OCMD when tagged /Type /OCMD or carrying the OCMD-only keys;
    // otherwise it's an OCG whose id looks up the resolved state.
    let type_name = dict.entries().iter().find_map(|(k, v)| match (k, v) {
        (k, Object::Name(n)) if k == "Type" => Some(n.clone()),
        _ => None,
    });
    let is_ocmd = type_name.as_deref() == Some("OCMD")
        || (type_name.is_none() && dict.entries().iter().any(|(k, _)| k == "OCGs" || k == "VE"));
    if is_ocmd {
        match crate::reader::ocg::parse_membership(reader, &dict) {
            Ok(Some(mem)) => oc.evaluate_membership(&mem),
            _ => true,
        }
    } else {
        match group_id {
            Some(id) => oc.is_visible(id),
            // An inline (non-indirect) OCG can't be matched against
            // /OCProperties /OCGs — tolerate as visible.
            None => true,
        }
    }
}

/// §12.5.5 — resolve one annotation's normal (`/AP /N`) appearance
/// stream into a [`Group`] positioned inside the annotation `/Rect`.
///
/// The appearance stream is a Form XObject (§8.10): its content is
/// parsed by [`resolve_one_form_xobject`] into a group carrying the
/// form `/Matrix` as transform and `/BBox` as clip. The group is then
/// wrapped in the §12.5.5 *Algorithm: Appearance streams* placement
/// matrix `A`:
///
///   a) the `/BBox` corners are transformed by `/Matrix` and the
///      smallest upright rectangle enclosing the quadrilateral taken
///      (the *transformed appearance box*);
///   b) `A` scales + translates that box onto the annotation `/Rect`
///      (lower-left corner to lower-left corner, upper-right to
///      upper-right);
///   c) the effective content mapping is `AA = Matrix × A` — realised
///      here as the outer wrapper carrying `A` and the inner form
///      group carrying `Matrix`.
///
/// Returns `Ok(None)` for an annotation without an applicable
/// appearance (no `/AP`, no usable `/N` stream, missing `/Rect` or
/// `/BBox`, or content that parses to nothing) — NOTE 3's "reasonable
/// behaviour (such as displaying nothing)".
fn annotation_appearance_group(
    reader: &mut DocumentReader<'_>,
    annot: &Dict,
) -> Result<Option<Group>, PdfError> {
    // /F (Table 164) — the §12.5.3 flag word. A Hidden (bit 2)
    // annotation "shall not be displayed or printed … regardless of
    // its annotation type"; a NoView (bit 6) annotation is hidden for
    // on-screen display (Table 165). Neither reaches the scene.
    let flags = match annot.entries().iter().find(|(k, _)| k == "F") {
        Some((_, Object::Integer(v))) => *v,
        _ => 0,
    };
    const FLAG_HIDDEN: i64 = 1 << 1; // bit 2
    const FLAG_NO_VIEW: i64 = 1 << 5; // bit 6
    if flags & (FLAG_HIDDEN | FLAG_NO_VIEW) != 0 {
        return Ok(None);
    }

    // §12.5.6.14 — a pop-up annotation "shall have no appearance
    // stream … of its own"; its text is displayed through the pop-up
    // window machinery, not painted on the page. Skip the subtype
    // outright.
    if matches!(
        annot.entries().iter().find(|(k, _)| k == "Subtype"),
        Some((_, Object::Name(s))) if s == "Popup"
    ) {
        return Ok(None);
    }

    // /Rect (Table 164, required) — the annotation rectangle in
    // default user space.
    let Some(rect) = dict_rect4(annot, "Rect") else {
        return Ok(None);
    };

    // /AP (Table 164) → the Table 168 appearance dictionary.
    let ap = match annot
        .entries()
        .iter()
        .find(|(k, _)| k == "AP")
        .map(|(_, v)| v.clone())
    {
        Some(Object::Reference(id)) => match reader.resolve(id) {
            Ok(o) => o,
            Err(_) => return Ok(None),
        },
        Some(other) => other,
        None => return Ok(None),
    };
    let Object::Dict(ap) = ap else {
        return Ok(None);
    };

    // /N (Table 168, required) — the normal appearance, used when the
    // annotation is not interacting with the user (and for printing).
    let n_entry = ap
        .entries()
        .iter()
        .find(|(k, _)| k == "N")
        .map(|(_, v)| v.clone());
    let (stream_id, n_obj) = match n_entry {
        Some(Object::Reference(id)) => match reader.resolve(id) {
            Ok(o) => (Some(id), o),
            Err(_) => return Ok(None),
        },
        Some(other) => (None, other),
        None => return Ok(None),
    };
    let (stream_id, stream) = match n_obj {
        Object::Stream(s) => (stream_id, s),
        // §12.5.5 — an appearance-dictionary entry may instead be a
        // subdictionary of appearance streams keyed by appearance
        // state; the annotation's /AS entry (Table 164, required in
        // that case) selects the applicable one. An absent /AS, or an
        // /AS designating a state the subdictionary doesn't define,
        // displays nothing (NOTE 3).
        Object::Dict(states) => {
            let Some(Object::Name(state)) = annot
                .entries()
                .iter()
                .find(|(k, _)| k == "AS")
                .map(|(_, v)| v.clone())
            else {
                return Ok(None);
            };
            let selected = states
                .entries()
                .iter()
                .find(|(k, _)| *k == state)
                .map(|(_, v)| v.clone());
            match selected {
                Some(Object::Reference(id)) => match reader.resolve(id) {
                    Ok(Object::Stream(s)) => (Some(id), s),
                    _ => return Ok(None),
                },
                Some(Object::Stream(s)) => (None, s),
                _ => return Ok(None),
            }
        }
        _ => return Ok(None),
    };

    build_appearance_group(reader, &stream, stream_id, rect)
}

/// Parse one appearance stream (a Form XObject per §12.5.5) and wrap
/// it in the placement matrix `A` mapping its transformed `/BBox` onto
/// the annotation rectangle `rect` (already normalised lower-left /
/// upper-right).
fn build_appearance_group(
    reader: &mut DocumentReader<'_>,
    stream: &Stream,
    stream_id: Option<ObjectId>,
    rect: [f32; 4],
) -> Result<Option<Group>, PdfError> {
    // /BBox (Table 95, required for a form XObject) — an appearance
    // without one can't be mapped onto /Rect; display nothing.
    let Some(bbox) = dict_rect4(&stream.dict, "BBox") else {
        return Ok(None);
    };
    let matrix = form_matrix(&stream.dict);

    let mut visited = HashSet::new();
    if let Some(id) = stream_id {
        visited.insert(id);
    }
    let Some(form_group) = resolve_one_form_xobject(reader, stream, 0, &mut visited)? else {
        return Ok(None);
    };

    // Step a) — transform the BBox corners by Matrix and take the
    // smallest upright rectangle that encompasses the quadrilateral.
    let corners = [
        Point::new(bbox[0], bbox[1]),
        Point::new(bbox[2], bbox[1]),
        Point::new(bbox[2], bbox[3]),
        Point::new(bbox[0], bbox[3]),
    ];
    let (mut tx0, mut ty0, mut tx1, mut ty1) = (f32::MAX, f32::MAX, f32::MIN, f32::MIN);
    for c in corners {
        let p = matrix.apply(c);
        tx0 = tx0.min(p.x);
        ty0 = ty0.min(p.y);
        tx1 = tx1.max(p.x);
        ty1 = ty1.max(p.y);
    }

    // Step b) — A scales + translates the transformed appearance box
    // onto /Rect. A degenerate axis (zero-width / zero-height box, or
    // a non-finite product of a malformed matrix) keeps unit scale on
    // that axis and aligns the lower-left corners only.
    let (tw, th) = (tx1 - tx0, ty1 - ty0);
    let sx = if tw.is_finite() && tw > f32::EPSILON {
        (rect[2] - rect[0]) / tw
    } else {
        1.0
    };
    let sy = if th.is_finite() && th > f32::EPSILON {
        (rect[3] - rect[1]) / th
    } else {
        1.0
    };
    let a = Transform2D {
        a: sx,
        b: 0.0,
        c: 0.0,
        d: sy,
        e: rect[0] - sx * tx0,
        f: rect[1] - sy * ty0,
    };

    // Step c) — AA = Matrix × A: the outer wrapper applies A after the
    // inner form group's own /Matrix.
    Ok(Some(Group {
        transform: a,
        children: vec![Node::Group(form_group)],
        ..Group::default()
    }))
}

/// Recursively dereference + simplify a colour-space `Object` so the
/// content parser sees a self-contained value: ICC profile streams
/// become their dictionaries, Indexed lookup streams become their
/// decoded bytes, and nested base spaces / indirect references are
/// resolved one element at a time. Plain values pass through.
fn prepare_color_space_object(
    reader: &mut DocumentReader<'_>,
    obj: Object,
) -> Result<Object, PdfError> {
    match obj {
        Object::Reference(id) => {
            let target = reader.resolve(id)?;
            prepare_color_space_object(reader, target)
        }
        Object::Array(items) => {
            let family = items.first().and_then(|o| match o {
                Object::Name(n) => Some(n.clone()),
                _ => None,
            });
            match family.as_deref() {
                Some("ICCBased") => {
                    // [ /ICCBased stream ] — replace the profile stream
                    // with its dictionary so the parser reads /N +
                    // /Alternate. §8.6.5.5.
                    let mut out = vec![Object::Name("ICCBased".into())];
                    let stream_obj = match items.into_iter().nth(1) {
                        Some(Object::Reference(id)) => reader.resolve(id)?,
                        Some(other) => other,
                        None => return Ok(Object::Array(out)),
                    };
                    match stream_obj {
                        Object::Stream(s) => {
                            // /Alternate may itself be an indirect ref
                            // or a nested array — prepare it too.
                            let mut dict = s.dict;
                            if let Some((_, alt)) = dict
                                .entries()
                                .iter()
                                .find(|(k, _)| k == "Alternate")
                                .map(|(k, v)| (k.clone(), v.clone()))
                            {
                                let prepared_alt = prepare_color_space_object(reader, alt)?;
                                dict.set("Alternate", prepared_alt);
                            }
                            out.push(Object::Dict(dict));
                        }
                        Object::Dict(d) => out.push(Object::Dict(d)),
                        _ => {}
                    }
                    Ok(Object::Array(out))
                }
                Some("Indexed") => {
                    // [ /Indexed base hival lookup ] — §8.6.6.3.
                    let mut it = items.into_iter();
                    let _family = it.next();
                    let base = match it.next() {
                        Some(b) => prepare_color_space_object(reader, b)?,
                        None => return Ok(Object::Array(vec![Object::Name("Indexed".into())])),
                    };
                    let hival = it.next().unwrap_or(Object::Null);
                    let hival = match hival {
                        Object::Reference(id) => reader.resolve(id)?,
                        other => other,
                    };
                    let lookup = match it.next() {
                        Some(Object::Reference(id)) => reader.resolve(id)?,
                        Some(other) => other,
                        None => Object::Null,
                    };
                    // A lookup stream (PDF 1.2) → decode to a byte
                    // string. A literal/hex string passes through.
                    let lookup = match lookup {
                        Object::Stream(s) => Object::HexString(decode_stream(&s)?),
                        other => other,
                    };
                    Ok(Object::Array(vec![
                        Object::Name("Indexed".into()),
                        base,
                        hival,
                        lookup,
                    ]))
                }
                Some("Separation") => {
                    // [ /Separation name alternateSpace tintTransform ]
                    // — §8.6.6.4. Resolve the colorant name, prepare the
                    // alternate space recursively (it may be a device
                    // name, an ICCBased/Indexed array, or an indirect
                    // ref), and prepare the tint-transform function so
                    // the content parser sees a self-contained 4-element
                    // array. The function object is normalised by
                    // `prepare_function_object` (Type 0/4 streams keep
                    // their dictionary; Type 3 sub-functions recurse).
                    let mut it = items.into_iter();
                    let _family = it.next();
                    let name = match it.next() {
                        Some(Object::Reference(id)) => reader.resolve(id)?,
                        Some(other) => other,
                        None => return Ok(Object::Array(vec![Object::Name("Separation".into())])),
                    };
                    let alt = match it.next() {
                        Some(a) => prepare_color_space_object(reader, a)?,
                        None => Object::Null,
                    };
                    let tint = match it.next() {
                        Some(f) => prepare_function_object(reader, f)?,
                        None => Object::Null,
                    };
                    Ok(Object::Array(vec![
                        Object::Name("Separation".into()),
                        name,
                        alt,
                        tint,
                    ]))
                }
                Some("DeviceN") => {
                    // [ /DeviceN names alternateSpace tintTransform
                    //   (attributes) ] — §8.6.6.5. Resolve the names
                    // array (each entry may be an indirect ref),
                    // prepare the alternate space recursively, and
                    // prepare the n-in/m-out tint-transform function so
                    // the content parser sees a self-contained array.
                    // The optional attributes dictionary is dropped (its
                    // NChannel custom-blending hints are not consulted —
                    // §8.6.6.5 lets a conforming reader render through
                    // the alternate + tint transform instead).
                    let mut it = items.into_iter();
                    let _family = it.next();
                    let names = match it.next() {
                        Some(Object::Reference(id)) => reader.resolve(id)?,
                        Some(other) => other,
                        None => return Ok(Object::Array(vec![Object::Name("DeviceN".into())])),
                    };
                    // The names entry must be an array; resolve any
                    // indirect colorant-name references one hop.
                    let names = match names {
                        Object::Array(elems) => {
                            let mut resolved = Vec::with_capacity(elems.len());
                            for e in elems {
                                let r = match e {
                                    Object::Reference(id) => reader.resolve(id)?,
                                    other => other,
                                };
                                resolved.push(r);
                            }
                            Object::Array(resolved)
                        }
                        other => other,
                    };
                    let alt = match it.next() {
                        Some(a) => prepare_color_space_object(reader, a)?,
                        None => Object::Null,
                    };
                    let tint = match it.next() {
                        Some(f) => prepare_function_object(reader, f)?,
                        None => Object::Null,
                    };
                    Ok(Object::Array(vec![
                        Object::Name("DeviceN".into()),
                        names,
                        alt,
                        tint,
                    ]))
                }
                _ => Ok(Object::Array(items)),
            }
        }
        other => Ok(other),
    }
}

/// Normalise a PDF function object (§7.10) into a self-contained value
/// the content parser can interpret without further document access.
///
/// A function may be a dictionary (Type 2 / Type 3) or a stream (Type 0
/// sampled / Type 4 PostScript-calculator). This content parser
/// evaluates the dictionary-shaped Type 2 (exponential, §7.10.3) and
/// Type 3 (stitching, §7.10.4) functions, plus the stream-shaped Type 0
/// (sampled, §7.10.2) and Type 4 (PostScript-calculator, §7.10.5)
/// functions, so:
///
/// * An indirect reference is dereferenced one hop.
/// * A stream's dictionary is surfaced so the common Table 38 entries
///   (`/FunctionType`, `/Domain`, `/Range`) and the Table 39 Type 0
///   entries (`/Size`, `/BitsPerSample`, `/Encode`, `/Decode`) stay
///   reachable. For a Type 0 function the decoded sample body is also
///   carried into the dictionary under the synthetic `__Samples` key (a
///   `HexString`), mirroring the Indexed-space lookup-stream handling,
///   so the content parser sees a self-contained sampled function. For a
///   Type 4 function the decoded PostScript program source is carried
///   under the synthetic `__Program` key (a `HexString`) the same way,
///   so the content parser sees a self-contained calculator function.
/// * A Type 3 stitching dictionary's `/Functions` array is prepared
///   element-by-element so each sub-function is itself self-contained.
fn prepare_function_object(
    reader: &mut DocumentReader<'_>,
    obj: Object,
) -> Result<Object, PdfError> {
    let obj = match obj {
        Object::Reference(id) => reader.resolve(id)?,
        other => other,
    };
    // Surface a stream as its dictionary so common Table 38 entries
    // (/FunctionType, /Domain, /Range) stay reachable. A Type 0 sampled
    // function's decoded body is folded in under `__Samples` (§7.10.2);
    // any other stream body is dropped (only its parameters are needed).
    let mut dict = match obj {
        Object::Stream(s) => {
            let function_type = s
                .dict
                .entries()
                .iter()
                .find(|(k, _)| k == "FunctionType")
                .and_then(|(_, v)| match v {
                    Object::Integer(n) => Some(*n),
                    _ => None,
                });
            match function_type {
                // Type 0 (sampled, §7.10.2): fold the decoded sample
                // body into `__Samples`.
                Some(0) => {
                    let samples = decode_stream(&s)?;
                    let mut d = s.dict;
                    d.set("__Samples", Object::HexString(samples));
                    d
                }
                // Type 4 (PostScript calculator, §7.10.5): the program
                // body lives in the stream, so fold the decoded source
                // text into `__Program` mirroring the Type 0 handling.
                Some(4) => {
                    let program = decode_stream(&s)?;
                    let mut d = s.dict;
                    d.set("__Program", Object::HexString(program));
                    d
                }
                // Any other stream's body is irrelevant — only its
                // parameters are needed.
                _ => s.dict,
            }
        }
        Object::Dict(d) => d,
        other => return Ok(other),
    };
    // A Type 3 stitching function references sub-functions in its
    // `/Functions` array; recurse so each is self-contained.
    if let Some((_, Object::Array(funcs))) = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Functions")
        .map(|(k, v)| (k.clone(), v.clone()))
    {
        let mut prepared = Vec::with_capacity(funcs.len());
        for f in funcs {
            prepared.push(prepare_function_object(reader, f)?);
        }
        dict.set("Functions", Object::Array(prepared));
    }
    Ok(Object::Dict(dict))
}

fn extract_stream_data(reader: &mut DocumentReader<'_>, id: ObjectId) -> Result<Vec<u8>, PdfError> {
    let obj = reader.resolve(id)?;
    let Object::Stream(s) = obj else {
        return Err(PdfError::other(format!(
            "PDF reader: object {id:?} expected to be a Stream (got {obj:?})"
        )));
    };
    decode_stream(&s)
}

/// Apply the stream's `/Filter` (if any) to recover the raw payload.
///
/// Generic decompression filters land here: `FlateDecode` (§7.4.4),
/// `LZWDecode` (§7.4.4.2 — round 98), `ASCII85Decode` (§7.4.3),
/// `ASCIIHexDecode` (§7.4.2), and `RunLengthDecode` (§7.4.5), in both
/// the single-`Name` and the `Array` (filter-chain) forms (§7.4.1).
/// Filters are applied in array order so a chain such as
/// `[/ASCII85Decode /LZWDecode]` (§7.4.4 Example 2) round-trips.
///
/// Terminal image codec filters (`DCTDecode`, `JPXDecode`,
/// `JBIG2Decode`, `CCITTFaxDecode`) are *not* decoded here — they
/// surface to the dedicated round-23 / round-35 image walkers that
/// hand their opaque payload to a codec crate. A `/Filter` naming one
/// of those is reported as unsupported rather than silently mangled.
pub fn decode_stream(stream: &Stream) -> Result<Vec<u8>, PdfError> {
    let filter = stream
        .dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Filter")
        .map(|(_, v)| v.clone());
    // The matching `/DecodeParms` slot (or `/DP` abbreviation): a dict
    // for a single filter, or a (possibly null-padded) array parallel
    // to the `/Filter` array. Used to read LZW's `/EarlyChange`.
    let parms = stream
        .dict
        .entries()
        .iter()
        .find(|(k, _)| k == "DecodeParms" || k == "DP")
        .map(|(_, v)| v.clone());
    match filter {
        None => Ok(stream.data.clone()),
        Some(Object::Name(name)) => apply_filter(&name, &stream.data, parms_for_index(&parms, 0)),
        Some(Object::Array(items)) => {
            let mut data = stream.data.clone();
            for (idx, item) in items.iter().enumerate() {
                let Object::Name(name) = item else {
                    return Err(PdfError::other(format!(
                        "PDF reader: /Filter chain item must be a Name (got {item:?})"
                    )));
                };
                data = apply_filter(name, &data, parms_for_index(&parms, idx))?;
            }
            Ok(data)
        }
        Some(other) => Err(PdfError::other(format!(
            "PDF reader: /Filter must be a Name or array of Names (got {other:?})"
        ))),
    }
}

/// Pull the `/DecodeParms` dictionary that lines up with filter slot
/// `idx`. A bare dict applies to the (single) filter at index 0; an
/// array is indexed positionally, treating `null` and out-of-range
/// slots as "no parameters" per §7.4.1.
fn parms_for_index(parms: &Option<Object>, idx: usize) -> Option<&Dict> {
    match parms {
        Some(Object::Dict(d)) if idx == 0 => Some(d),
        Some(Object::Array(items)) => match items.get(idx) {
            Some(Object::Dict(d)) => Some(d),
            _ => None,
        },
        _ => None,
    }
}

/// Apply one named generic filter to `data`.
///
/// For `FlateDecode` / `LZWDecode`, the `/DecodeParms /Predictor`
/// post-filter (§7.4.4.4) is applied to the decompressed bytes when
/// present — a stream whose `/DecodeParms` carries `/Predictor` > 1
/// (PNG predictors 10..=15 or TIFF Predictor 2) is un-differenced
/// before being returned. `/Colors`, `/BitsPerComponent`, and
/// `/Columns` come from the same dict (Table 8 defaults: 1 / 8 / 1).
fn apply_filter(name: &str, data: &[u8], parms: Option<&Dict>) -> Result<Vec<u8>, PdfError> {
    use crate::reader::filters;
    match name {
        "FlateDecode" | "Fl" => apply_predictor_post(filters::flate_decompress(data)?, parms),
        "LZWDecode" | "LZW" => {
            // `/EarlyChange` defaults to 1 (§7.4.4.3 Table 8); only 0
            // postpones the width bump.
            let early = parms
                .and_then(|d| d.entries().iter().find(|(k, _)| k == "EarlyChange"))
                .and_then(|(_, v)| match v {
                    Object::Integer(n) => Some(*n != 0),
                    _ => None,
                })
                .unwrap_or(true);
            apply_predictor_post(filters::lzw_decode_with_early_change(data, early)?, parms)
        }
        "ASCII85Decode" | "A85" => filters::ascii85_decode(data),
        "ASCIIHexDecode" | "AHx" => filters::ascii_hex_decode(data),
        "RunLengthDecode" | "RL" => filters::run_length_decode(data),
        other => Err(PdfError::other(format!(
            "PDF reader: filter `{other}` not yet supported by decode_stream \
             (image codec filters DCT/JPX/JBIG2/CCITTFax route through the image walkers)"
        ))),
    }
}

/// Apply the `/DecodeParms /Predictor` post-filter to `LZWDecode` /
/// `FlateDecode` output if the slot's parameter dict requests one
/// (§7.4.4.4 Table 8 / Table 10). When `/Predictor` is absent or `1`
/// the bytes pass through unchanged.
fn apply_predictor_post(data: Vec<u8>, parms: Option<&Dict>) -> Result<Vec<u8>, PdfError> {
    use crate::reader::filters::{apply_predictor, PredictorParams};
    let Some(parms) = parms else {
        return Ok(data);
    };
    let int = |key: &str| -> Option<i64> {
        parms
            .entries()
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| match v {
                Object::Integer(n) => Some(*n),
                _ => None,
            })
    };
    let predictor = int("Predictor").unwrap_or(1);
    if predictor <= 1 {
        return Ok(data);
    }
    let def = PredictorParams::default();
    let params = PredictorParams {
        predictor,
        colors: int("Colors")
            .map(|n| n.max(0) as usize)
            .unwrap_or(def.colors),
        bits_per_component: int("BitsPerComponent")
            .map(|n| n.max(0) as usize)
            .unwrap_or(def.bits_per_component),
        columns: int("Columns")
            .map(|n| n.max(0) as usize)
            .unwrap_or(def.columns),
    };
    apply_predictor(&data, &params)
}

fn decode_metadata(info: Object) -> Result<Metadata, PdfError> {
    let Object::Dict(d) = info else {
        return Err(PdfError::other(format!(
            "PDF reader: /Info must be a dict (got {info:?})"
        )));
    };
    let mut m = Metadata::default();
    for (k, v) in d.entries() {
        match k.as_str() {
            "Title" => m.title = decode_text(v),
            "Author" => m.author = decode_text(v),
            "Subject" => m.subject = decode_text(v),
            "Keywords" => {
                if let Some(s) = decode_text(v) {
                    // Reverse the writer's `keywords.join(", ")` —
                    // split + trim. Falls back to a single-element
                    // vec when the string has no separator.
                    m.keywords = s.split(',').map(|p| p.trim().to_owned()).collect();
                }
            }
            "Creator" => m.creator = decode_text(v),
            "Producer" => m.producer = decode_text(v),
            "CreationDate" => m.created_at = decode_text(v).map(pdf_date_to_iso8601),
            "ModDate" => m.modified_at = decode_text(v).map(pdf_date_to_iso8601),
            other => {
                if let Some(s) = decode_text(v) {
                    m.custom.insert(other.to_owned(), s);
                }
            }
        }
    }
    Ok(m)
}

/// Convert a PDF date `D:YYYYMMDDHHmmSSOHH'mm'` back to ISO-8601.
/// Inputs that don't start with `D:` are returned as-is so the
/// scene's metadata round-trip is lossless for non-date strings.
pub fn pdf_date_to_iso8601(s: String) -> String {
    let bytes = s.as_bytes();
    if !bytes.starts_with(b"D:") {
        return s;
    }
    let rest = &bytes[2..];
    if rest.len() < 4 {
        return s.clone();
    }
    let mut out = String::with_capacity(25);
    let year = &rest[0..4.min(rest.len())];
    out.push_str(&String::from_utf8_lossy(year));
    if rest.len() >= 6 {
        out.push('-');
        out.push_str(&String::from_utf8_lossy(&rest[4..6]));
    }
    if rest.len() >= 8 {
        out.push('-');
        out.push_str(&String::from_utf8_lossy(&rest[6..8]));
    }
    if rest.len() >= 10 {
        out.push('T');
        out.push_str(&String::from_utf8_lossy(&rest[8..10]));
    }
    if rest.len() >= 12 {
        out.push(':');
        out.push_str(&String::from_utf8_lossy(&rest[10..12]));
    }
    if rest.len() >= 14 {
        out.push(':');
        out.push_str(&String::from_utf8_lossy(&rest[12..14]));
    }
    // Zone designator.
    if rest.len() == 15 && rest[14] == b'Z' {
        out.push('Z');
    } else if rest.len() >= 17 && (rest[14] == b'+' || rest[14] == b'-') {
        // ±HH'mm'  → ±HH:mm
        out.push(rest[14] as char);
        out.push_str(&String::from_utf8_lossy(&rest[15..17]));
        // Skip the apostrophe; mm follows.
        if rest.len() >= 20 && rest[17] == b'\'' {
            out.push(':');
            out.push_str(&String::from_utf8_lossy(&rest[18..20]));
        }
    }
    out
}

fn decode_text(v: &Object) -> Option<String> {
    match v {
        Object::LiteralString(b) => Some(String::from_utf8_lossy(b).into_owned()),
        Object::HexString(b) => {
            // The writer uses UTF-16BE-with-BOM for non-ASCII; decode
            // back to a Rust String.
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
        _ => None,
    }
}

fn number_to_f32(o: &Object) -> Result<f32, PdfError> {
    match o {
        Object::Integer(n) => Ok(*n as f32),
        Object::Real(f) => Ok(*f as f32),
        other => Err(PdfError::other(format!(
            "PDF reader: expected number, got {other:?}"
        ))),
    }
}

// Suppress dead-code warning on a small helper that the round-3
// Scene assembly doesn't yet use — keeps the writer/reader symmetry
// obvious and lets round-4+ wire it up.
#[allow(dead_code)]
fn empty_root() -> Group {
    Group::default()
}

#[allow(dead_code)]
fn empty_path_node() -> PathNode {
    PathNode {
        path: Path {
            commands: vec![PathCommand::Close],
        },
        fill: Some(Paint::Solid(Rgba::opaque(0, 0, 0))),
        stroke: None,
        fill_rule: FillRule::NonZero,
    }
}

// `Node` is referenced by our parsed content stream output — make
// sure the import isn't pruned by dead-code analysis when this
// commit's tests don't directly observe a Node variant.
#[allow(dead_code)]
fn _node_imported(_: Node) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_pdf_from_scene;

    fn make_scene_with_one_red_rect() -> Scene {
        use oxideav_core::vector::{
            FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Point, Rgba, VectorFrame,
        };
        let mut p = Path::new();
        p.commands.push(PathCommand::MoveTo(Point::new(10.0, 10.0)));
        p.commands.push(PathCommand::LineTo(Point::new(90.0, 10.0)));
        p.commands.push(PathCommand::LineTo(Point::new(90.0, 90.0)));
        p.commands.push(PathCommand::LineTo(Point::new(10.0, 90.0)));
        p.commands.push(PathCommand::Close);
        let frame = VectorFrame {
            width: 100.0,
            height: 100.0,
            view_box: None,
            root: Group {
                children: vec![Node::Path(PathNode {
                    path: p,
                    fill: Some(Paint::Solid(Rgba::opaque(255, 0, 0))),
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
        Scene {
            pages: Some(vec![page]),
            ..Scene::default()
        }
    }

    #[test]
    fn read_pdf_to_scene_roundtrip_single_page() {
        let scene = make_scene_with_one_red_rect();
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        let pages = parsed.pages.expect("scene has pages");
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].width, 100.0);
        assert_eq!(pages[0].height, 100.0);
        // Walk the rebuilt vector frame for a path with the red fill.
        let root = &pages[0].content.root;
        // The reader produces a top-level frame containing one
        // `q ... Q`-derived child group; that child group contains
        // the path node.
        // The reader's q/Q nesting mirrors the writer's emission:
        //   root q (frame group walker)
        //     per-path q
        //       path
        //     Q
        //   Q
        // — so the path is two Group hops below the root.
        let path_node = find_first_path(root).expect("at least one PathNode in the tree");
        match &path_node.fill {
            Some(Paint::Solid(rgba)) => assert_eq!((rgba.r, rgba.g, rgba.b), (255, 0, 0)),
            other => panic!("expected solid red, got {other:?}"),
        }
    }

    fn find_first_path(group: &Group) -> Option<&PathNode> {
        for child in &group.children {
            match child {
                Node::Path(p) => return Some(p),
                Node::Group(g) => {
                    if let Some(p) = find_first_path(g) {
                        return Some(p);
                    }
                }
                _ => {}
            }
        }
        None
    }

    #[test]
    fn read_pdf_to_scene_roundtrip_multi_page() {
        use oxideav_core::vector::Rgba;
        let mut scene = make_scene_with_one_red_rect();
        let mut p2 = Page::new(200.0, 100.0);
        p2.content.width = 200.0;
        p2.content.height = 100.0;
        // Make a green rect on page 2.
        use oxideav_core::vector::{Group, Node, Paint, Path, PathCommand, PathNode, Point};
        let mut path = Path::new();
        path.commands
            .push(PathCommand::MoveTo(Point::new(0.0, 0.0)));
        path.commands
            .push(PathCommand::LineTo(Point::new(50.0, 0.0)));
        path.commands
            .push(PathCommand::LineTo(Point::new(50.0, 50.0)));
        path.commands.push(PathCommand::Close);
        p2.content.root = Group {
            children: vec![Node::Path(PathNode {
                path,
                fill: Some(Paint::Solid(Rgba::opaque(0, 255, 0))),
                stroke: None,
                fill_rule: FillRule::NonZero,
            })],
            ..Group::default()
        };
        scene.pages.as_mut().unwrap().push(p2);
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        let pages = parsed.pages.expect("scene has pages");
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].width, 100.0);
        assert_eq!(pages[1].width, 200.0);
    }

    #[test]
    fn read_pdf_metadata_roundtrip() {
        let mut scene = make_scene_with_one_red_rect();
        scene.metadata = Metadata {
            title: Some("Round 3 Doc".into()),
            author: Some("Mark".into()),
            subject: Some("Reader test".into()),
            keywords: vec!["pdf".into(), "round3".into()],
            creator: Some("MyApp".into()),
            producer: Some("oxideav-pdf".into()),
            created_at: Some("2026-05-04T12:30:45Z".into()),
            modified_at: Some("2026-05-04T13:00:00Z".into()),
            ..Metadata::default()
        };
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        assert_eq!(parsed.metadata.title.as_deref(), Some("Round 3 Doc"));
        assert_eq!(parsed.metadata.author.as_deref(), Some("Mark"));
        assert_eq!(parsed.metadata.subject.as_deref(), Some("Reader test"));
        assert_eq!(parsed.metadata.creator.as_deref(), Some("MyApp"));
        assert_eq!(parsed.metadata.producer.as_deref(), Some("oxideav-pdf"));
        assert_eq!(
            parsed.metadata.keywords,
            vec!["pdf".to_string(), "round3".to_string()]
        );
        // PDF dates round-trip through `pdf_date_to_iso8601`.
        assert_eq!(
            parsed.metadata.created_at.as_deref(),
            Some("2026-05-04T12:30:45Z")
        );
    }

    #[test]
    fn read_pdf_custom_metadata_roundtrip() {
        let mut scene = make_scene_with_one_red_rect();
        let mut custom = std::collections::BTreeMap::new();
        custom.insert("dc:rights".into(), "(c) 2026 Karpeles".into());
        custom.insert("Trapped".into(), "False".into());
        scene.metadata = Metadata {
            custom,
            ..Metadata::default()
        };
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        assert_eq!(
            parsed.metadata.custom.get("dc:rights").map(String::as_str),
            Some("(c) 2026 Karpeles")
        );
        assert_eq!(
            parsed.metadata.custom.get("Trapped").map(String::as_str),
            Some("False")
        );
    }

    #[test]
    fn read_pdf_unicode_metadata_roundtrip() {
        let mut scene = make_scene_with_one_red_rect();
        scene.metadata = Metadata {
            title: Some("日本語".into()),
            ..Metadata::default()
        };
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        assert_eq!(parsed.metadata.title.as_deref(), Some("日本語"));
    }

    #[test]
    fn pdf_date_to_iso8601_format() {
        assert_eq!(
            pdf_date_to_iso8601("D:20260504123045Z".to_string()),
            "2026-05-04T12:30:45Z"
        );
        assert_eq!(
            pdf_date_to_iso8601("D:20260504123045+09'00'".to_string()),
            "2026-05-04T12:30:45+09:00"
        );
    }

    #[test]
    fn no_metadata_yields_default() {
        let scene = make_scene_with_one_red_rect();
        let pdf = write_pdf_from_scene(&scene).unwrap();
        let parsed = read_pdf_to_scene(&pdf).unwrap();
        assert!(parsed.metadata.title.is_none());
        assert!(parsed.metadata.custom.is_empty());
    }

    /// `decode_stream` on a `/FlateDecode` stream that also carries a
    /// `/DecodeParms /Predictor 12` (PNG-Up) un-differences the body
    /// after inflating (§7.4.4.4). The expected output is the original
    /// pre-predictor sample bytes.
    #[test]
    fn decode_stream_applies_flate_png_predictor() {
        // Two rows of 3 single-byte samples (Colors=1, BPC=8,
        // Columns=3): [10,20,30] and [11,22,33]. PNG-encoded with a
        // None tag on row 0 and an Up tag (deltas) on row 1.
        let predicted: &[u8] = &[
            0, 10, 20, 30, // row 0: tag None
            2, 1, 2, 3, // row 1: tag Up
        ];
        let compressed = crate::zlib::flate_compress(predicted);

        let dict = Dict::new()
            .with("Filter", Object::Name("FlateDecode".into()))
            .with(
                "DecodeParms",
                Object::Dict(
                    Dict::new()
                        .with("Predictor", Object::Integer(12))
                        .with("Columns", Object::Integer(3)),
                ),
            );
        let stream = Stream::new(dict, compressed);
        let out = decode_stream(&stream).unwrap();
        assert_eq!(out, [10u8, 20, 30, 11, 22, 33]);
    }

    /// A `/FlateDecode` stream with no `/DecodeParms` (or `/Predictor 1`)
    /// returns the inflated bytes unchanged — the predictor path is a
    /// no-op there.
    #[test]
    fn decode_stream_flate_without_predictor_is_passthrough() {
        let raw = b"hello predictor-free world";
        let compressed = crate::zlib::flate_compress(raw);

        let dict = Dict::new().with("Filter", Object::Name("FlateDecode".into()));
        let stream = Stream::new(dict, compressed);
        assert_eq!(decode_stream(&stream).unwrap(), raw);
    }

    /// End-to-end document path for a Type 4 (free-form Gouraud) mesh
    /// shading carried as a `/FlateDecode` stream resource: opening the
    /// hand-rolled PDF, resolving its `/Resources /Shading`, and feeding
    /// the surfaced dict to `evaluate_mesh_shading` produces the
    /// triangle. Verifies `resolve_shading_resources` folds the
    /// decompressed `__MeshData` body (§8.7.4.5.5).
    #[test]
    fn resolve_shading_folds_mesh_stream_body() {
        use crate::reader::content::evaluate_mesh_shading_for_test;
        // One all-coloured triangle: f=0 (0,0)R, f=0 (255,0)G, f=0 (0,255)B,
        // 8-bit flag / coord / component, byte-aligned per vertex.
        let mut body: Vec<u8> = Vec::new();
        for (x, y, r, g, b) in [
            (0u8, 0u8, 255u8, 0u8, 0u8),
            (255, 0, 0, 255, 0),
            (0, 255, 0, 0, 255),
        ] {
            body.extend_from_slice(&[0, x, y, r, g, b]); // flag, x, y, r, g, b
        }
        let compressed = crate::zlib::flate_compress(&body);

        // Hand-roll a minimal PDF whose page `/Resources /Shading /Sh1`
        // points at the mesh stream (object 5).
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
        let mut offs: Vec<usize> = vec![0];
        offs.push(out.len());
        out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        offs.push(out.len());
        out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
        offs.push(out.len());
        out.extend_from_slice(
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] \
              /Resources << /Shading << /Sh1 5 0 R >> >> >>\nendobj\n",
        );
        offs.push(out.len());
        out.extend_from_slice(b"4 0 obj\n<< >>\nendobj\n");
        offs.push(out.len());
        let header = format!(
            "5 0 obj\n<< /ShadingType 4 /ColorSpace /DeviceRGB \
             /BitsPerCoordinate 8 /BitsPerComponent 8 /BitsPerFlag 8 \
             /Decode [0 1 0 1 0 1 0 1 0 1] /Filter /FlateDecode /Length {} >>\nstream\n",
            compressed.len()
        );
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(&compressed);
        out.extend_from_slice(b"\nendstream\nendobj\n");

        let xref_off = out.len();
        out.extend_from_slice(b"xref\n0 6\n");
        out.extend_from_slice(b"0000000000 65535 f \n");
        for &o in &offs[1..] {
            out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n")
                .as_bytes(),
        );

        let mut reader = DocumentReader::open(&out).expect("open");
        let resources = Dict::new().with(
            "Shading",
            Object::Dict(Dict::new().with("Sh1", Object::Reference(ObjectId::new(5)))),
        );
        let resolved = resolve_shading_resources(&mut reader, &resources)
            .expect("resolve")
            .expect("some shading dict");
        let sh1 = match resolved.entries().iter().find(|(k, _)| k == "Sh1") {
            Some((_, Object::Dict(d))) => d.clone(),
            _ => panic!("Sh1 not a dict"),
        };
        // The decompressed mesh body was folded into __MeshData.
        assert!(sh1.entries().iter().any(|(k, _)| k == "__MeshData"));
        let mesh = evaluate_mesh_shading_for_test(&sh1).expect("mesh");
        // One triangle with three coloured vertices.
        assert!(format!("{mesh:?}").contains("Triangles"));
    }
}
