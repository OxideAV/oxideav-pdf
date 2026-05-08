//! Minimal DER (X.690) parser and writer used by the public-key
//! security-handler module.
//!
//! Only the BER/DER subset that ISO 32000-1 §7.6.4 + RFC 5652 (CMS) +
//! RFC 5280 (X.509) need is implemented:
//!
//! * Class / tag / form decoding for the universal SEQUENCE / SET /
//!   INTEGER / OBJECT IDENTIFIER / OCTET STRING / NULL / BOOLEAN
//!   types and the `[n]` context-specific constructed forms.
//! * Length parsing in short + long forms; indefinite-length is *not*
//!   accepted (DER never produces it; only BER might).
//! * Tag matching with optional unwrap of `[n] EXPLICIT` wrappers.
//!
//! Provenance: RFC 5280 + RFC 5652 only — no openssl / other-library
//! source consulted.

use crate::error::PdfError;

/// The four ASN.1 tag classes of X.690 §8.1.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Universal = 0,
    Application = 1,
    ContextSpecific = 2,
    Private = 3,
}

/// A parsed TLV view onto the input slice. `body` is the bare value
/// bytes without the tag/length header; `tag_number` is the universal
/// or context-specific tag number; `constructed` is the form bit.
#[derive(Debug)]
pub struct Tlv<'a> {
    pub class: Class,
    pub constructed: bool,
    pub tag_number: u32,
    pub body: &'a [u8],
}

/// Universal tag numbers we touch.
pub mod tag {
    pub const BOOLEAN: u32 = 1;
    pub const INTEGER: u32 = 2;
    pub const BIT_STRING: u32 = 3;
    pub const OCTET_STRING: u32 = 4;
    pub const NULL: u32 = 5;
    pub const OID: u32 = 6;
    pub const SEQUENCE: u32 = 16;
    pub const SET: u32 = 17;
}

/// Decode a single TLV at `data[..]`, returning the parsed view + the
/// remaining tail. Surfaces a `PdfError::Other` on malformed input.
pub fn read_tlv(data: &[u8]) -> Result<(Tlv<'_>, &[u8]), PdfError> {
    if data.is_empty() {
        return Err(PdfError::other("DER: unexpected end of data parsing tag"));
    }
    let id_byte = data[0];
    let class = match (id_byte >> 6) & 0b11 {
        0 => Class::Universal,
        1 => Class::Application,
        2 => Class::ContextSpecific,
        _ => Class::Private,
    };
    let constructed = (id_byte & 0b0010_0000) != 0;
    let tag_low = id_byte & 0b0001_1111;
    let (tag_number, mut rest) = if tag_low == 0b0001_1111 {
        // Multi-byte tag (unused for the OIDs we touch, but parse it
        // for correctness rather than misparsing the length).
        let mut tn: u32 = 0;
        let mut idx = 1;
        loop {
            if idx >= data.len() {
                return Err(PdfError::other("DER: tag continuation byte missing"));
            }
            let b = data[idx];
            tn = (tn << 7) | u32::from(b & 0x7F);
            idx += 1;
            if (b & 0x80) == 0 {
                break;
            }
        }
        (tn, &data[idx..])
    } else {
        (u32::from(tag_low), &data[1..])
    };
    if rest.is_empty() {
        return Err(PdfError::other("DER: missing length byte"));
    }
    let len_byte = rest[0];
    rest = &rest[1..];
    let len: usize = if len_byte < 0x80 {
        len_byte as usize
    } else if len_byte == 0x80 {
        return Err(PdfError::other(
            "DER: indefinite-length form not supported (BER only)",
        ));
    } else {
        let n = (len_byte & 0x7F) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return Err(PdfError::other(format!(
                "DER: invalid long-form length {n}"
            )));
        }
        let mut v: usize = 0;
        for &b in &rest[..n] {
            v = (v << 8) | usize::from(b);
        }
        rest = &rest[n..];
        v
    };
    if rest.len() < len {
        return Err(PdfError::other(format!(
            "DER: length {} exceeds remaining {}",
            len,
            rest.len()
        )));
    }
    let body = &rest[..len];
    let tail = &rest[len..];
    Ok((
        Tlv {
            class,
            constructed,
            tag_number,
            body,
        },
        tail,
    ))
}

/// Read a TLV and require its class+tag match `(class, tag)`. Used to
/// pull a specific structural element (e.g. a SEQUENCE).
pub fn read_expected<'a>(
    data: &'a [u8],
    class: Class,
    tag: u32,
) -> Result<(Tlv<'a>, &'a [u8]), PdfError> {
    let (t, rest) = read_tlv(data)?;
    if t.class != class || t.tag_number != tag {
        return Err(PdfError::other(format!(
            "DER: expected class={class:?} tag={tag} but got class={:?} tag={}",
            t.class, t.tag_number
        )));
    }
    Ok((t, rest))
}

/// Convenience: read a SEQUENCE; return its body + the tail after the
/// SEQUENCE.
pub fn read_sequence(data: &[u8]) -> Result<(&[u8], &[u8]), PdfError> {
    let (t, rest) = read_expected(data, Class::Universal, tag::SEQUENCE)?;
    if !t.constructed {
        return Err(PdfError::other("DER: SEQUENCE must be constructed"));
    }
    Ok((t.body, rest))
}

/// Convenience: read a SET; return its body + tail.
pub fn read_set(data: &[u8]) -> Result<(&[u8], &[u8]), PdfError> {
    let (t, rest) = read_expected(data, Class::Universal, tag::SET)?;
    if !t.constructed {
        return Err(PdfError::other("DER: SET must be constructed"));
    }
    Ok((t.body, rest))
}

/// Read an OBJECT IDENTIFIER and return its decoded arc list.
pub fn read_oid(data: &[u8]) -> Result<(Vec<u64>, &[u8]), PdfError> {
    let (t, rest) = read_expected(data, Class::Universal, tag::OID)?;
    if t.constructed {
        return Err(PdfError::other("DER: OID must be primitive"));
    }
    Ok((decode_oid(t.body)?, rest))
}

/// Read an OCTET STRING and return its raw bytes.
pub fn read_octet_string(data: &[u8]) -> Result<(&[u8], &[u8]), PdfError> {
    let (t, rest) = read_expected(data, Class::Universal, tag::OCTET_STRING)?;
    if t.constructed {
        return Err(PdfError::other(
            "DER: OCTET STRING constructed form not supported",
        ));
    }
    Ok((t.body, rest))
}

/// Read an INTEGER as raw two's-complement bytes (big-endian). The
/// caller decides whether to treat it as signed / unsigned / big-int.
pub fn read_integer_bytes(data: &[u8]) -> Result<(&[u8], &[u8]), PdfError> {
    let (t, rest) = read_expected(data, Class::Universal, tag::INTEGER)?;
    if t.constructed {
        return Err(PdfError::other("DER: INTEGER must be primitive"));
    }
    Ok((t.body, rest))
}

/// Read an INTEGER as a small u64 (errors if it doesn't fit or if it's
/// negative).
pub fn read_integer_u64(data: &[u8]) -> Result<(u64, &[u8]), PdfError> {
    let (body, rest) = read_integer_bytes(data)?;
    if body.is_empty() {
        return Err(PdfError::other("DER: INTEGER body empty"));
    }
    if body[0] & 0x80 != 0 {
        return Err(PdfError::other("DER: negative INTEGER not expected here"));
    }
    let mut v: u64 = 0;
    for &b in body {
        if v > u64::MAX >> 8 {
            return Err(PdfError::other("DER: INTEGER value too large for u64"));
        }
        v = (v << 8) | u64::from(b);
    }
    Ok((v, rest))
}

/// Decode an OID from its primitive body bytes (X.690 §8.19).
fn decode_oid(body: &[u8]) -> Result<Vec<u64>, PdfError> {
    if body.is_empty() {
        return Err(PdfError::other("DER: empty OID body"));
    }
    let first = body[0];
    let arc1 = (first / 40) as u64;
    let arc2 = (first % 40) as u64;
    let mut out = vec![arc1, arc2];
    let mut acc: u64 = 0;
    let mut have = false;
    for &b in &body[1..] {
        acc = (acc << 7) | u64::from(b & 0x7F);
        have = true;
        if (b & 0x80) == 0 {
            out.push(acc);
            acc = 0;
            have = false;
        }
    }
    if have {
        return Err(PdfError::other(
            "DER: OID truncated (last byte has continuation bit)",
        ));
    }
    Ok(out)
}

/// Encode an OID arc list into its primitive bytes.
pub fn encode_oid(arcs: &[u64]) -> Vec<u8> {
    debug_assert!(arcs.len() >= 2);
    let mut out = Vec::with_capacity(arcs.len() * 2);
    out.push((arcs[0] * 40 + arcs[1]) as u8);
    for &a in &arcs[2..] {
        // Base-128 with continuation bit on all but the last byte.
        let mut buf = [0u8; 10];
        let mut idx = buf.len();
        let mut v = a;
        loop {
            idx -= 1;
            buf[idx] = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        let total = buf.len() - idx;
        for (i, b) in buf[idx..].iter_mut().enumerate() {
            if i + 1 < total {
                *b |= 0x80;
            }
        }
        out.extend_from_slice(&buf[idx..]);
    }
    out
}

/// Encode a TLV: leading identifier byte(s) + length + body.
pub fn write_tlv(class: Class, constructed: bool, tag: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 8);
    let class_bits = (class as u8) << 6;
    let pc = if constructed { 0b0010_0000 } else { 0 };
    if tag < 31 {
        out.push(class_bits | pc | (tag as u8));
    } else {
        out.push(class_bits | pc | 0b0001_1111);
        // High-tag-number form, big-endian base-128, continuation
        // bit on all but the last byte.
        let mut buf = [0u8; 5];
        let mut idx = buf.len();
        let mut v = tag;
        loop {
            idx -= 1;
            buf[idx] = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        let total = buf.len() - idx;
        for (i, b) in buf[idx..].iter_mut().enumerate() {
            if i + 1 < total {
                *b |= 0x80;
            }
        }
        out.extend_from_slice(&buf[idx..]);
    }
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let mut nbytes = [0u8; 8];
        let mut count = 0;
        let mut v = n;
        while v > 0 {
            count += 1;
            nbytes[8 - count] = (v & 0xFF) as u8;
            v >>= 8;
        }
        out.push(0x80 | count as u8);
        out.extend_from_slice(&nbytes[8 - count..]);
    }
    out.extend_from_slice(body);
    out
}

/// Convenience: write a SEQUENCE around `body`.
pub fn write_sequence(body: &[u8]) -> Vec<u8> {
    write_tlv(Class::Universal, true, tag::SEQUENCE, body)
}

/// Convenience: write a SET around `body`.
pub fn write_set(body: &[u8]) -> Vec<u8> {
    write_tlv(Class::Universal, true, tag::SET, body)
}

/// Convenience: write an OCTET STRING.
pub fn write_octet_string(body: &[u8]) -> Vec<u8> {
    write_tlv(Class::Universal, false, tag::OCTET_STRING, body)
}

/// Convenience: write a primitive INTEGER from raw two's-complement
/// big-endian bytes (caller is responsible for any required leading
/// 0x00 padding when the high bit is set).
pub fn write_integer_bytes(body: &[u8]) -> Vec<u8> {
    write_tlv(Class::Universal, false, tag::INTEGER, body)
}

/// Convenience: write a small u64 INTEGER (canonical DER — minimal
/// bytes, padding with 0x00 when MSB would otherwise make it negative).
pub fn write_integer_u64(v: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(9);
    if v == 0 {
        body.push(0);
    } else {
        // Minimal big-endian encoding.
        let mut started = false;
        for shift in (0..8).rev() {
            let b = ((v >> (shift * 8)) & 0xFF) as u8;
            if started || b != 0 {
                body.push(b);
                started = true;
            }
        }
        if body[0] & 0x80 != 0 {
            // Avoid the value being interpreted as negative.
            body.insert(0, 0);
        }
    }
    write_integer_bytes(&body)
}

/// Convenience: write an OBJECT IDENTIFIER from its arc list.
pub fn write_oid(arcs: &[u64]) -> Vec<u8> {
    let body = encode_oid(arcs);
    write_tlv(Class::Universal, false, tag::OID, &body)
}

/// Convenience: write a primitive NULL.
pub fn write_null() -> Vec<u8> {
    write_tlv(Class::Universal, false, tag::NULL, &[])
}

/// Convenience: write a context-specific `[n]` constructed wrapper
/// around `body` — used for the `EXPLICIT` outer tags of CMS
/// `EnvelopedData` etc.
pub fn write_context_constructed(tag_n: u32, body: &[u8]) -> Vec<u8> {
    write_tlv(Class::ContextSpecific, true, tag_n, body)
}

/// Convenience: write a context-specific primitive `[n]` wrapper.
pub fn write_context_primitive(tag_n: u32, body: &[u8]) -> Vec<u8> {
    write_tlv(Class::ContextSpecific, false, tag_n, body)
}

/// Read a context-specific `[n]` wrapper. Returns its body + tail.
pub fn read_context(data: &[u8], tag_n: u32) -> Result<(&[u8], &[u8]), PdfError> {
    let (t, rest) = read_expected(data, Class::ContextSpecific, tag_n)?;
    Ok((t.body, rest))
}

/// Optionally read a context-specific `[n]` wrapper if the next TLV
/// matches; otherwise leave `data` unchanged. Used for OPTIONAL
/// fields.
pub fn maybe_read_context(data: &[u8], tag_n: u32) -> Result<(Option<&[u8]>, &[u8]), PdfError> {
    if data.is_empty() {
        return Ok((None, data));
    }
    let (t, _) = read_tlv(data)?;
    if t.class == Class::ContextSpecific && t.tag_number == tag_n {
        let (body, rest) = read_context(data, tag_n)?;
        Ok((Some(body), rest))
    } else {
        Ok((None, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small_integer() {
        let der = write_integer_u64(0x1234_5678_9ABC_DEF0);
        let (v, rest) = read_integer_u64(&der).unwrap();
        assert!(rest.is_empty());
        assert_eq!(v, 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn roundtrip_msb_set_integer_pads_zero() {
        // 0x80 must be encoded as 00 80, not 80 (which would be -128).
        let der = write_integer_u64(0x80);
        // Identifier 02, length 02, body 00 80.
        assert_eq!(&der, &[0x02, 0x02, 0x00, 0x80]);
        let (v, _) = read_integer_u64(&der).unwrap();
        assert_eq!(v, 0x80);
    }

    #[test]
    fn roundtrip_oid_rsa_encryption() {
        // 1.2.840.113549.1.1.1 (rsaEncryption)
        let arcs = [1u64, 2, 840, 113549, 1, 1, 1];
        let der = write_oid(&arcs);
        // Sanity: 06 09 2A 86 48 86 F7 0D 01 01 01
        assert_eq!(
            &der,
            &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        );
        let (parsed, _) = read_oid(&der).unwrap();
        assert_eq!(parsed.as_slice(), &arcs[..]);
    }

    #[test]
    fn long_form_length_parses() {
        // SEQUENCE { 200 zero bytes }: 30 81 C8 ...
        let body = vec![0u8; 200];
        let der = write_sequence(&body);
        assert_eq!(der[0], 0x30);
        assert_eq!(der[1], 0x81);
        assert_eq!(der[2], 0xC8);
        let (parsed, rest) = read_sequence(&der).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.len(), 200);
    }

    #[test]
    fn context_tag_roundtrip() {
        let payload = b"hello";
        let der = write_context_constructed(0, payload);
        // Identifier: A0 (class context, constructed, tag 0).
        assert_eq!(der[0], 0xA0);
        let (body, rest) = read_context(&der, 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(body, payload);
    }

    #[test]
    fn rejects_indefinite_length() {
        // SEQUENCE indefinite — 30 80 ... 00 00. We refuse.
        let bad = [0x30u8, 0x80, 0x00, 0x00];
        let err = read_tlv(&bad).err().unwrap();
        let msg = format!("{err}");
        assert!(msg.contains("indefinite"), "{msg}");
    }
}
