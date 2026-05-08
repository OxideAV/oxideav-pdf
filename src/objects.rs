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
}

impl Document {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            next_id: 1,
            root: None,
            info: None,
            encryption: None,
        }
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

    /// Walk this document into the on-wire layout: header + body +
    /// xref + trailer + startxref. Bytes for sub-objects are emitted
    /// in insertion order.
    pub fn write_to(&self, out: &mut Vec<u8>) -> Result<(), PdfError> {
        let root = self
            .root
            .ok_or_else(|| PdfError::other("Document::write_to: missing /Root reference"))?;

        // ---- Header ---------------------------------------------------
        // PDF 1.4 magic + the four >0x80 bytes that mark the file as
        // binary so PDF readers don't treat it as ASCII (ISO 32000-1
        // §7.5.2). Any byte ≥0x80 satisfies the rule; we use 0xE2 0xE3
        // 0xCF 0xD3 — the canonical pdftk / Acrobat marker.
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
        } else {
            b"%PDF-1.4\n"
        };
        out.extend_from_slice(header_version);
        out.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");

        // If encrypted, allocate an Encrypt indirect object so its body
        // is interleaved with the rest. We do this on a clone so the
        // public Document state stays unchanged. The Encrypt object
        // itself is **not** encrypted (§7.6.1).
        let mut objects_to_emit: Vec<IndirectObject> = self.objects.clone();
        let encrypt_id_opt: Option<ObjectId> = if let Some(state) = &self.encryption {
            let next_id = self.objects.iter().map(|o| o.id.number).max().unwrap_or(0) + 1;
            let id = ObjectId::new(next_id);
            // Apply per-object encryption to the cloned object list,
            // mutating leaf strings and stream bodies in place. We do
            // this BEFORE pushing the Encrypt indirect object so the
            // Encrypt-object payload itself is left untouched (§7.6.1).
            for ind in &mut objects_to_emit {
                encrypt_object_in_place(&mut ind.object, ind.id, state)?;
            }
            // Push the /Encrypt indirect object now so it gets an
            // xref slot.
            objects_to_emit.push(IndirectObject {
                id,
                object: Object::Dict(state.encrypt_dict.clone()),
            });
            Some(id)
        } else {
            None
        };

        // ---- Body -----------------------------------------------------
        // Sort by id so the xref subsection slot table lines up neatly.
        objects_to_emit.sort_by_key(|o| o.id.number);
        let sorted: Vec<&IndirectObject> = objects_to_emit.iter().collect();

        // Offsets[i] = byte offset of the indirect object whose id is
        // (i+1). Slot 0 of the xref is reserved for the head of the
        // free list (always entry `0000000000 65535 f`).
        let max_id = sorted.last().map(|o| o.id.number as usize).unwrap_or(0);
        let mut offsets: Vec<u64> = vec![0; max_id + 1];

        for ind in &sorted {
            let off = out.len() as u64;
            offsets[ind.id.number as usize] = off;
            write_indirect(out, ind).map_err(PdfError::Io)?;
        }

        // ---- Cross-reference table -----------------------------------
        let xref_off = out.len() as u64;
        out.extend_from_slice(b"xref\n");
        // Single subsection covering [0, max_id].
        let header_line = format!("0 {}\n", max_id + 1);
        out.extend_from_slice(header_line.as_bytes());
        // Free-list head — slot 0 always 0000000000 65535 f.
        out.extend_from_slice(b"0000000000 65535 f \n");
        for offset in offsets.iter().skip(1) {
            // 10-digit zero-padded byte offset, 5-digit zero-padded
            // generation, 'n' (in-use) marker, exact two-character
            // newline terminator (space + LF) per §7.5.4.
            let line = format!("{:010} {:05} n \n", offset, 0);
            out.extend_from_slice(line.as_bytes());
        }

        // ---- Trailer + startxref + EOF -------------------------------
        out.extend_from_slice(b"trailer\n");
        let mut trailer_dict = Dict::new()
            .with("Size", Object::Integer((max_id + 1) as i64))
            .with("Root", Object::Reference(root));
        if let Some(info_id) = self.info {
            trailer_dict.set("Info", Object::Reference(info_id));
        }
        if let (Some(eid), Some(state)) = (encrypt_id_opt, &self.encryption) {
            trailer_dict.set("Encrypt", Object::Reference(eid));
            // /ID is required when /Encrypt is present (§7.5.5 + §7.6.3.3).
            // We emit ID[0] == ID[1] (no incremental updates → both
            // halves point to the same permanent identifier).
            let id_array = Object::Array(vec![
                Object::LiteralString(state.file_id.clone()),
                Object::LiteralString(state.file_id.clone()),
            ]);
            trailer_dict.set("ID", id_array);
        }
        let trailer = Object::Dict(trailer_dict);
        write_object(out, &trailer).map_err(PdfError::Io)?;
        out.extend_from_slice(b"\nstartxref\n");
        out.extend_from_slice(format!("{}\n", xref_off).as_bytes());
        out.extend_from_slice(b"%%EOF\n");

        Ok(())
    }
}

/// Recursively encrypt every literal/hex string and stream payload in
/// `obj`, in place, using the per-object key derivation associated with
/// `id`. Numeric / boolean / name / reference values pass through
/// unchanged. Nested dicts and arrays are walked recursively so nested
/// strings (e.g. `/Title (...)` inside an /Info dict) are encrypted.
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
    // 6 digits of fractional precision is what most PDF writers use
    // (matches qpdf's default). Trim trailing zeros to keep streams
    // small; never leave a bare trailing dot.
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
