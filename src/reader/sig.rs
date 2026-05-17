//! Round-21 — PDF `/Sig` annotation reader.
//!
//! Surfaces the digital-signature dictionaries embedded in a PDF as
//! [`PdfSignature`] values, ready to be handed to the round-20
//! [`crate::pubsec::verify::verify_signature`] CMS verifier.
//!
//! # ISO 32000 references
//!
//! * **§12.7.4.5 (Signature fields)** — a signature is embedded as an
//!   interactive form field with `/FT /Sig`. The field's `/V` entry is
//!   an indirect reference to a *signature dictionary*.
//! * **§12.8.1 (Signature dictionaries)** — the signature dict carries:
//!   * `/Type /Sig` (or `/DocTimeStamp` — both share the same shape).
//!   * `/Filter /Adobe.PPKLite` (handler-specific, but always a Name).
//!   * `/SubFilter /adbe.pkcs7.detached` (or `/adbe.pkcs7.sha1`,
//!     `/ETSI.CAdES.detached`, `/ETSI.RFC3161` — the SubFilter names
//!     the encoding of `/Contents`).
//!   * `/Contents <hex-encoded CMS blob>` — for `*.detached` SubFilters
//!     this is a complete CMS `SignedData` ContentInfo (RFC 5652 §5)
//!     whose eContent is **omitted** (the signed bytes are the PDF
//!     byte ranges named in `/ByteRange`).
//!   * `/ByteRange [a b c d]` — two byte ranges of the PDF file that
//!     together cover everything *except* the `<…hex…>` literal of
//!     `/Contents`. The signed message is `pdf[a..a+b] ‖ pdf[c..c+d]`.
//!   * Optional metadata: `/Name`, `/Reason`, `/Location`, `/ContactInfo`,
//!     `/M` (signing time, PDF date string).
//! * **§12.7.3.1 (Field hierarchy — terminal vs non-terminal fields)**
//!   — a field tree may be flat (every leaf carries `/FT`) or nested
//!   (parents carry `/FT`, kids inherit). The walker below recurses
//!   through `/Kids` to find every terminal /Sig field.
//!
//! # Surface
//!
//! [`DocumentReader::signatures`] returns one [`PdfSignature`] per
//! Sig form field whose `/V` resolves to a parseable signature dict.
//! [`signed_bytes`] concatenates the two `/ByteRange`-named slices so
//! the caller can pass them as `AttachedContent::External(&signed)` to
//! [`crate::pubsec::verify::verify_signature`].
//!
//! Field walking is best-effort — a malformed Sig field (missing `/V`,
//! unparseable `/Contents`, …) is skipped rather than aborting the whole
//! document. The verifier itself stays strict: a parsed but invalid
//! signature returns `Ok(false)`, a structural problem returns `Err`.

use crate::error::PdfError;
use crate::objects::{Dict, Object, ObjectId};
use crate::pubsec::der;
use crate::pubsec::signed_data::{parse_signed_data, SignedData};
use crate::reader::document::DocumentReader;

/// One PDF `/Sig` form field's signature dictionary, fully parsed and
/// ready to verify.
#[derive(Debug, Clone)]
pub struct PdfSignature {
    /// `/ByteRange [a b c d]` — exactly four signed integers per
    /// ISO 32000-1 §12.8.1. The signed bytes are
    /// `pdf[a..a+b] ‖ pdf[c..c+d]`. Stored as `i64` (the spec says
    /// "integer", and Adobe-encoded files routinely overflow `u32` for
    /// large PDFs — keeping `i64` matches the on-wire shape).
    pub byte_range: [i64; 4],
    /// `/Contents` hex-decoded — the raw CMS `SignedData` ContentInfo
    /// blob (DER) for `adbe.pkcs7.detached` / `ETSI.CAdES.detached`, or
    /// the raw RFC 3161 TimeStampToken for `ETSI.RFC3161`.
    pub contents: Vec<u8>,
    /// `/SubFilter` name — `adbe.pkcs7.detached`, `adbe.pkcs7.sha1`,
    /// `ETSI.CAdES.detached`, `ETSI.RFC3161`, or any other handler-
    /// specific name. `None` only when the dict omits it (extremely
    /// non-conformant; we still surface the rest of the dict).
    pub sub_filter: Option<String>,
    /// `/Filter` name — typically `Adobe.PPKLite` or `Adobe.PPKMS`.
    /// `None` when the dict omits it.
    pub filter: Option<String>,
    /// `/Type` name — `Sig` (default), `DocTimeStamp`, or absent.
    pub sig_type: Option<String>,
    /// Optional `/Name` — the human-readable signer name embedded by
    /// the signing application (PDF text string).
    pub name: Option<String>,
    /// Optional `/Reason`.
    pub reason: Option<String>,
    /// Optional `/Location`.
    pub location: Option<String>,
    /// Optional `/ContactInfo`.
    pub contact_info: Option<String>,
    /// Optional `/M` — signing-time, PDF date format `D:YYYYMMDDHHmmSS`.
    pub signing_time: Option<String>,
    /// CMS `SignedData` parsed from [`Self::contents`]. Surfaced as
    /// `Some` only when [`Self::sub_filter`] is one of the SubFilters
    /// whose `/Contents` is a CMS `ContentInfo` blob — the round-21
    /// reader does not parse RFC 3161 `TimeStampToken`s (those carry a
    /// nested CMS as well, but the outer wrapper is different and the
    /// signed message is the digest in `MessageImprint`, not the
    /// `/ByteRange` body).
    pub signed_data: Option<SignedData>,
    /// The byte offset (in the original PDF) at which the signature
    /// dictionary's `/Contents` `<…>` hex literal starts. Useful for
    /// diagnostics and for round-trip rewriting (replace the placeholder
    /// hex with a real signature, leaving everything else byte-stable).
    /// Stored as `u64` so it can address arbitrarily large PDFs.
    pub contents_offset: Option<u64>,
}

impl PdfSignature {
    /// Compute the bytes the `/ByteRange` entry says were signed:
    /// `pdf[a..a+b] ‖ pdf[c..c+d]`. Returns an error when any range
    /// falls outside the input or when the byte-range integers are
    /// negative.
    pub fn signed_message(&self, pdf: &[u8]) -> Result<Vec<u8>, PdfError> {
        signed_bytes(pdf, &self.byte_range)
    }

    /// `true` when this signature's `/SubFilter` names one of the CMS-
    /// based detached forms whose `/Contents` is a complete CMS
    /// `ContentInfo` blob. The verifier dispatch in
    /// [`crate::pubsec::verify::verify_signature`] applies to these.
    pub fn is_cms_detached(&self) -> bool {
        matches!(
            self.sub_filter.as_deref(),
            Some("adbe.pkcs7.detached") | Some("ETSI.CAdES.detached")
        )
    }

    /// `true` when this entry is a *document time-stamp* signature per
    /// ISO 32000-1 §12.8.5 — i.e. the dict's `/Type` is `DocTimeStamp`
    /// or its `/SubFilter` is `ETSI.RFC3161`. Either marker
    /// independently identifies a DocTimeStamp (the spec allows both
    /// `/Type /DocTimeStamp` *and* `/SubFilter /ETSI.RFC3161` —
    /// real-world files frequently set both, but only one is required).
    pub fn is_doc_timestamp(&self) -> bool {
        self.sig_type.as_deref() == Some("DocTimeStamp")
            || self.sub_filter.as_deref() == Some("ETSI.RFC3161")
    }
}

/// One PDF `/DocTimeStamp` signature, surfaced separately from regular
/// signatures so callers don't have to filter the [`PdfSignature`] list.
///
/// A DocTimeStamp's `/Contents` is an RFC 3161 `TimeStampToken` — a DER
/// `ContentInfo` of type `id-signedData` whose `eContentType` is
/// `id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4). The TST embeds the
/// hash of the byte-ranged PDF content; callers who want to verify the
/// stamp re-hash `pdf[a..a+b] ‖ pdf[c..c+d]` with the imprint's
/// algorithm and compare with the `messageImprint.hashedMessage` field
/// of the inner TSTInfo.
///
/// Round 34 surfaces the timestamp structurally; full RFC 3161
/// verification dispatch (cert chain + GenTime ordering) lives in a
/// follow-up round.
#[derive(Debug, Clone)]
pub struct PdfDocTimestamp {
    /// `/ByteRange [a b c d]` — same shape as [`PdfSignature::byte_range`].
    pub byte_range: [i64; 4],
    /// `/Contents` hex-decoded — the raw RFC 3161 TimeStampToken bytes.
    pub contents: Vec<u8>,
    /// `/SubFilter` — `ETSI.RFC3161` for a conformant DocTimeStamp.
    pub sub_filter: Option<String>,
    /// `/Filter` — typically `Adobe.PPKLite`.
    pub filter: Option<String>,
}

impl PdfDocTimestamp {
    /// The bytes the time-stamp covers: `pdf[a..a+b] ‖ pdf[c..c+d]`.
    pub fn signed_message(&self, pdf: &[u8]) -> Result<Vec<u8>, PdfError> {
        signed_bytes(pdf, &self.byte_range)
    }
}

/// Promote a [`PdfSignature`] to a [`PdfDocTimestamp`] when the entry's
/// `/SubFilter` is `ETSI.RFC3161` (or the `/Type` is `DocTimeStamp`).
/// Returns `None` for entries that aren't a doc-timestamp.
fn promote_doc_timestamp(sig: &PdfSignature) -> Option<PdfDocTimestamp> {
    if !sig.is_doc_timestamp() {
        return None;
    }
    Some(PdfDocTimestamp {
        byte_range: sig.byte_range,
        contents: sig.contents.clone(),
        sub_filter: sig.sub_filter.clone(),
        filter: sig.filter.clone(),
    })
}

/// Walk a [`DocumentReader`] and return only the document time-stamp
/// signatures — the entries whose `/SubFilter` is `ETSI.RFC3161` or
/// whose `/Type` is `DocTimeStamp` (ISO 32000-1 §12.8.5).
///
/// This is sugar over [`signatures`] + [`PdfSignature::is_doc_timestamp`].
/// Callers that want both regular signatures and timestamps in one walk
/// should call [`signatures`] directly and filter via `is_doc_timestamp`
/// themselves.
pub fn doc_timestamps(reader: &mut DocumentReader<'_>) -> Result<Vec<PdfDocTimestamp>, PdfError> {
    let sigs = signatures(reader)?;
    Ok(sigs.iter().filter_map(promote_doc_timestamp).collect())
}

/// Concatenate the two byte ranges `[a b c d]` describes, returning
/// `pdf[a..a+b] ‖ pdf[c..c+d]`.
///
/// Per ISO 32000-1 §12.8.1.1, `/ByteRange` covers the entire PDF *except*
/// the `<…hex…>` literal of the signature's own `/Contents` entry — so
/// the concatenation here is exactly the byte string the signing tool
/// hashed.
pub fn signed_bytes(pdf: &[u8], byte_range: &[i64; 4]) -> Result<Vec<u8>, PdfError> {
    let [a, b, c, d] = *byte_range;
    if a < 0 || b < 0 || c < 0 || d < 0 {
        return Err(PdfError::other(format!(
            "PDF /Sig: /ByteRange contains a negative integer ({byte_range:?})"
        )));
    }
    let total = pdf.len() as u64;
    let (a, b, c, d) = (a as u64, b as u64, c as u64, d as u64);
    let end1 = a
        .checked_add(b)
        .ok_or_else(|| PdfError::other("PDF /Sig: /ByteRange overflow on first range"))?;
    let end2 = c
        .checked_add(d)
        .ok_or_else(|| PdfError::other("PDF /Sig: /ByteRange overflow on second range"))?;
    if end1 > total || end2 > total {
        return Err(PdfError::other(format!(
            "PDF /Sig: /ByteRange {byte_range:?} extends past file length {total}"
        )));
    }
    if c < end1 {
        return Err(PdfError::other(format!(
            "PDF /Sig: /ByteRange {byte_range:?} second range starts ({c}) before first range ends ({end1})"
        )));
    }
    let mut out = Vec::with_capacity((b + d) as usize);
    out.extend_from_slice(&pdf[a as usize..end1 as usize]);
    out.extend_from_slice(&pdf[c as usize..end2 as usize]);
    Ok(out)
}

/// Walk a [`DocumentReader`] for every terminal `/FT /Sig` form field,
/// returning one [`PdfSignature`] per field that has a parseable `/V`
/// signature dictionary.
///
/// Field nesting (`/Kids`) is honoured: a non-terminal parent carrying
/// `/FT /Sig` propagates the field type down to leaves that omit it
/// (ISO 32000-1 §12.7.3.1). Fields with no `/V` (placeholder /
/// not-yet-signed) are skipped silently — they don't carry signed bytes
/// to verify.
///
/// The walker is also tolerant of:
/// * Documents with no `/AcroForm` (returns an empty Vec).
/// * `/AcroForm /Fields` arrays containing non-reference items
///   (skipped).
/// * Signature dicts with malformed `/Contents` or `/ByteRange`
///   (skipped).
///
/// Returns `Err` only on infrastructural problems (catalog missing,
/// xref errors propagating up from [`DocumentReader::resolve`]).
pub fn signatures(reader: &mut DocumentReader<'_>) -> Result<Vec<PdfSignature>, PdfError> {
    let root_id = reader.xref().root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog) = catalog else {
        return Ok(Vec::new());
    };
    let acro_form = catalog
        .entries()
        .iter()
        .find(|(k, _)| k == "AcroForm")
        .map(|(_, v)| v.clone());
    let Some(acro_obj) = acro_form else {
        return Ok(Vec::new());
    };
    let acro_dict = match reader.deref(acro_obj)? {
        Object::Dict(d) => d,
        _ => return Ok(Vec::new()),
    };
    let fields = acro_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "Fields")
        .map(|(_, v)| v.clone());
    let Some(Object::Array(field_refs)) = fields else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for item in field_refs {
        if let Object::Reference(id) = item {
            walk_field(reader, id, /* inherited_ft = */ None, &mut out)?;
        }
    }
    Ok(out)
}

/// Recursive `/Fields` / `/Kids` walker — terminal nodes carrying
/// `/FT /Sig` are surfaced; `/Kids` arrays are recursed.
fn walk_field(
    reader: &mut DocumentReader<'_>,
    field_id: ObjectId,
    inherited_ft: Option<String>,
    out: &mut Vec<PdfSignature>,
) -> Result<(), PdfError> {
    let field = reader.resolve(field_id)?;
    let Object::Dict(d) = field else {
        return Ok(());
    };
    let ft = d
        .entries()
        .iter()
        .find(|(k, _)| k == "FT")
        .and_then(|(_, v)| match v {
            Object::Name(n) => Some(n.clone()),
            _ => None,
        })
        .or(inherited_ft);

    let kids = d
        .entries()
        .iter()
        .find(|(k, _)| k == "Kids")
        .map(|(_, v)| v.clone());
    if let Some(Object::Array(items)) = kids {
        // Non-terminal field — recurse.
        for item in items {
            if let Object::Reference(id) = item {
                walk_field(reader, id, ft.clone(), out)?;
            }
        }
        return Ok(());
    }

    // Terminal field. Only /FT /Sig is interesting to round 21.
    if ft.as_deref() != Some("Sig") {
        return Ok(());
    }
    let v = d
        .entries()
        .iter()
        .find(|(k, _)| k == "V")
        .map(|(_, v)| v.clone());
    let Some(v) = v else {
        return Ok(());
    };
    let sig_dict_obj = reader.deref(v)?;
    let Object::Dict(sig_dict) = sig_dict_obj else {
        return Ok(());
    };
    if let Some(parsed) = decode_sig_dict(&sig_dict)? {
        out.push(parsed);
    }
    Ok(())
}

/// Convert a fully-resolved signature `Dict` into a [`PdfSignature`].
/// Returns `Ok(None)` when the dict is missing required fields
/// (`/ByteRange` or `/Contents`) — those are treated as "skip this
/// signature, don't fail the doc".
fn decode_sig_dict(dict: &Dict) -> Result<Option<PdfSignature>, PdfError> {
    let lookup = |k: &str| {
        dict.entries()
            .iter()
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.clone())
    };

    let byte_range = match lookup("ByteRange") {
        Some(Object::Array(items)) if items.len() == 4 => {
            let mut br = [0i64; 4];
            for (i, item) in items.iter().enumerate() {
                br[i] = match item {
                    Object::Integer(n) => *n,
                    Object::Real(f) => *f as i64,
                    _ => return Ok(None),
                };
            }
            br
        }
        _ => return Ok(None),
    };

    let contents = match lookup("Contents") {
        // The lexer decoded the hex string already — the inner bytes
        // are the raw DER blob.
        Some(Object::HexString(bytes)) | Some(Object::LiteralString(bytes)) => bytes,
        _ => return Ok(None),
    };

    let sub_filter = match lookup("SubFilter") {
        Some(Object::Name(s)) => Some(s),
        _ => None,
    };
    let filter = match lookup("Filter") {
        Some(Object::Name(s)) => Some(s),
        _ => None,
    };
    let sig_type = match lookup("Type") {
        Some(Object::Name(s)) => Some(s),
        _ => None,
    };

    let signed_data = if matches!(
        sub_filter.as_deref(),
        Some("adbe.pkcs7.detached") | Some("ETSI.CAdES.detached")
    ) {
        // Best-effort — a malformed CMS surfaces as `None` rather than
        // failing the whole walk. Callers that care can re-parse via
        // [`parse_signed_data`] directly to get the structural error.
        //
        // The hex literal in `/Contents` is a fixed-size budget chosen
        // by the signing tool (Adobe / iText etc. routinely reserve
        // more bytes than the actual SignedData consumes); the trailing
        // bytes are zero-padding (or `0x00` after hex decode, since the
        // reserved bytes are spec'd as `0`). `parse_signed_data` rejects
        // trailing bytes, so trim to the outer SEQUENCE length first.
        cms_trim_to_outer_sequence(&contents)
            .ok()
            .and_then(|trimmed| parse_signed_data(&trimmed).ok())
    } else {
        None
    };

    Ok(Some(PdfSignature {
        byte_range,
        contents,
        sub_filter,
        filter,
        sig_type,
        name: text_value(&lookup("Name")),
        reason: text_value(&lookup("Reason")),
        location: text_value(&lookup("Location")),
        contact_info: text_value(&lookup("ContactInfo")),
        signing_time: text_value(&lookup("M")),
        signed_data,
        contents_offset: None,
    }))
}

/// Trim trailing bytes after the outer SEQUENCE in a CMS `ContentInfo`
/// blob. Adobe / iText routinely reserve more bytes for the `/Contents`
/// hex string than the actual SignedData consumes; the unused bytes
/// are zero-padding (decoded to `0x00`). [`parse_signed_data`] rejects
/// trailing bytes, so we ask the DER tag/length parser how long the
/// outer SEQUENCE is and slice off the rest before handing it on.
fn cms_trim_to_outer_sequence(data: &[u8]) -> Result<Vec<u8>, PdfError> {
    let (tlv, _) = der::read_tlv(data)?;
    // Outer SEQUENCE = tag(1) + length(1..5) + body. Re-derive the
    // header length by subtracting body.len() from the position of
    // body relative to data.
    let body_offset = (tlv.body.as_ptr() as usize)
        .checked_sub(data.as_ptr() as usize)
        .ok_or_else(|| PdfError::other("CMS trim: body pointer math failed"))?;
    let total = body_offset
        .checked_add(tlv.body.len())
        .ok_or_else(|| PdfError::other("CMS trim: total length overflow"))?;
    if total > data.len() {
        return Err(PdfError::other("CMS trim: SEQUENCE extends past input"));
    }
    Ok(data[..total].to_vec())
}

/// Decode a PDF text-string entry into a `String`. Mirrors the same
/// rule [`crate::reader::document`] uses for `/Info` entries: a
/// hex-string starting with the UTF-16BE BOM (`FE FF`) is decoded as
/// UTF-16BE; everything else is treated as PDFDocEncoding-equivalent
/// (close enough to UTF-8 for the ASCII subset Sig metadata uses in
/// practice — and `from_utf8_lossy` keeps the path total).
fn text_value(o: &Option<Object>) -> Option<String> {
    let Some(o) = o else {
        return None;
    };
    match o {
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
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_bytes_concatenates_two_ranges() {
        let pdf = b"AAAABBBBCCCCDDDD";
        // First range = bytes 0..4 ("AAAA"); skip "BBBB" (4 bytes);
        // second range = bytes 8..16 ("CCCCDDDD").
        let signed = signed_bytes(pdf, &[0, 4, 8, 8]).unwrap();
        assert_eq!(signed, b"AAAACCCCDDDD");
    }

    #[test]
    fn signed_bytes_rejects_negative_range() {
        let pdf = b"AAAA";
        assert!(signed_bytes(pdf, &[-1, 0, 0, 0]).is_err());
        assert!(signed_bytes(pdf, &[0, -1, 0, 0]).is_err());
    }

    #[test]
    fn signed_bytes_rejects_out_of_bounds() {
        let pdf = b"AAAA";
        // Range 0..5 doesn't fit a 4-byte file.
        assert!(signed_bytes(pdf, &[0, 5, 5, 0]).is_err());
        // Second range overruns.
        assert!(signed_bytes(pdf, &[0, 2, 2, 5]).is_err());
    }

    #[test]
    fn signed_bytes_rejects_overlapping_ranges() {
        let pdf = b"AAAABBBBCCCC";
        // Second range starts (3) before first range ends (4).
        assert!(signed_bytes(pdf, &[0, 4, 3, 9]).is_err());
    }

    #[test]
    fn signed_bytes_overflow_caught() {
        let pdf = b"AAAA";
        let huge = i64::MAX;
        assert!(signed_bytes(pdf, &[huge, huge, 0, 0]).is_err());
    }

    #[test]
    fn pdf_signature_is_cms_detached_recognises_two_subfilters() {
        let mut s = PdfSignature {
            byte_range: [0, 0, 0, 0],
            contents: Vec::new(),
            sub_filter: Some("adbe.pkcs7.detached".into()),
            filter: None,
            sig_type: None,
            name: None,
            reason: None,
            location: None,
            contact_info: None,
            signing_time: None,
            signed_data: None,
            contents_offset: None,
        };
        assert!(s.is_cms_detached());
        s.sub_filter = Some("ETSI.CAdES.detached".into());
        assert!(s.is_cms_detached());
        s.sub_filter = Some("ETSI.RFC3161".into());
        assert!(!s.is_cms_detached());
        s.sub_filter = None;
        assert!(!s.is_cms_detached());
    }
}
