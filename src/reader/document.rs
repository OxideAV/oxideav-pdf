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

use std::collections::{HashMap, HashSet};

use oxideav_core::vector::{
    FillRule, Group, Node, Paint, Path, PathCommand, PathNode, Rgba, VectorFrame,
};
use oxideav_core::TimeBase;
use oxideav_scene::{Metadata, Page, Scene};

use crate::decrypt::{open_with_password, StandardHandler};
use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId, Stream};
use crate::pubsec::{
    open_with_certificate, open_with_certificate_and_trust_store, PubSecCredential, TrustStore,
};
use crate::reader::content::parse_content_stream_full;
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
    fn resolve_compressed(
        &mut self,
        wanted: ObjectId,
        obj_stream_num: u32,
        index_within_stream: u32,
    ) -> Result<Object, PdfError> {
        let container_id = ObjectId::new(obj_stream_num);
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
        if index_within_stream >= n {
            return Err(PdfError::other(format!(
                "PDF reader: ObjStm index {index_within_stream} out of range (N={n})"
            )));
        }
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
        let mut pairs: Vec<(u32, usize)> = Vec::with_capacity(n as usize);
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
            pairs.push((num as u32, o as usize));
        }
        let (header_num, body_off) = pairs[index_within_stream as usize];
        if header_num != wanted.number {
            return Err(PdfError::other(format!(
                "PDF reader: ObjStm slot {index_within_stream} declares object {header_num},\
                 but xref expected {}",
                wanted.number
            )));
        }
        let abs_off = first
            .checked_add(body_off)
            .ok_or_else(|| PdfError::other("PDF reader: ObjStm offset overflow"))?;
        if abs_off > payload.len() {
            return Err(PdfError::other(format!(
                "PDF reader: ObjStm body offset {abs_off} past payload length {}",
                payload.len()
            )));
        }
        // Compressed objects in an ObjStm cannot themselves be
        // streams (§7.5.7), and have no `n gen obj` wrapper — we
        // parse a single object starting at `abs_off`.
        let mut bp = Parser::new(&payload[abs_off..]);
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

    // Decode each Page → oxideav_scene::Page.
    let mut scene_pages = Vec::with_capacity(leaves.len());
    for leaf_id in leaves {
        scene_pages.push(decode_page(&mut reader, leaf_id)?);
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

fn decode_page(reader: &mut DocumentReader<'_>, page_id: ObjectId) -> Result<Page, PdfError> {
    let page_obj = reader.resolve(page_id)?;
    let Object::Dict(page_dict) = page_obj else {
        return Err(PdfError::other(format!(
            "PDF reader: page {page_id:?} is not a dict"
        )));
    };

    // /MediaBox is required for the leaf page (or inherited from a
    // parent — round-3 only handles directly-attached media boxes;
    // inheritance lands in round 4 if the writer ever needs it).
    let media_box = page_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "MediaBox")
        .map(|(_, v)| v.clone());
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
            // Round-3: no inheritance walk. Default to A4 portrait
            // so the page object is still constructible.
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
    // (§7.8.3 Table 33). Inheritance through `/Parent` is round-4+
    // (matching the round-3 /MediaBox stance) — directly-attached
    // entries only.
    let resources_obj = page_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Resources")
        .map(|(_, v)| v.clone());
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

    let parsed = parse_content_stream_full(
        &content_bytes,
        ext_gstate_dict.as_ref(),
        fonts_dict.as_ref(),
    )?;
    let root = parsed.root;
    let mut page = Page::new(width, height);
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
        if let Object::Dict(d) = resolved {
            out.set(name, Object::Dict(d));
        }
    }
    Ok(Some(out))
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
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        // Two rows of 3 single-byte samples (Colors=1, BPC=8,
        // Columns=3): [10,20,30] and [11,22,33]. PNG-encoded with a
        // None tag on row 0 and an Up tag (deltas) on row 1.
        let predicted: &[u8] = &[
            0, 10, 20, 30, // row 0: tag None
            2, 1, 2, 3, // row 1: tag Up
        ];
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(predicted).unwrap();
        let compressed = enc.finish().unwrap();

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
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let raw = b"hello predictor-free world";
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(raw).unwrap();
        let compressed = enc.finish().unwrap();

        let dict = Dict::new().with("Filter", Object::Name("FlateDecode".into()));
        let stream = Stream::new(dict, compressed);
        assert_eq!(decode_stream(&stream).unwrap(), raw);
    }
}
