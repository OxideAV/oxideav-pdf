//! Minimal X.509 v3 (RFC 5280) parser — extracts only the
//! `IssuerAndSerialNumber` pair the PDF public-key handler needs to
//! match a recipient slot.
//!
//! ```asn.1
//! Certificate ::= SEQUENCE {
//!   tbsCertificate     TBSCertificate,
//!   signatureAlgorithm AlgorithmIdentifier,
//!   signatureValue     BIT STRING
//! }
//! TBSCertificate ::= SEQUENCE {
//!   version          [0] EXPLICIT INTEGER OPTIONAL DEFAULT v1,
//!   serialNumber     CertificateSerialNumber,  -- INTEGER
//!   signature        AlgorithmIdentifier,
//!   issuer           Name,                    -- SEQUENCE
//!   ...
//! }
//! ```
//!
//! Only the leading three TBSCertificate fields are read; everything
//! after `issuer` is skipped. The point of this module is to give the
//! pubsec module the same `(issuer_der, serial)` pair it parses out
//! of CMS RecipientInfo, so a byte-for-byte equality test decides
//! recipient matching.
//!
//! Provenance: RFC 5280 §4.1 only.

use crate::error::PdfError;

use super::der::{maybe_read_context, read_integer_bytes, read_sequence, tag, Class};

/// The two fields a CMS recipient slot needs to match against a user's
/// certificate. Stored exactly as DER bytes so equality is a memcmp.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Raw DER of the issuer `Name` (a SEQUENCE).
    pub issuer_der: Vec<u8>,
    /// Raw INTEGER body bytes of the serial number.
    pub serial: Vec<u8>,
}

impl Certificate {
    /// Parse a DER-encoded X.509 v3 `Certificate`, returning only the
    /// fields this crate consumes.
    pub fn parse(der: &[u8]) -> Result<Self, PdfError> {
        // Outer Certificate SEQUENCE.
        let (cert_body, rest) = read_sequence(der)?;
        if !rest.is_empty() {
            return Err(PdfError::other(
                "X.509: trailing bytes after Certificate SEQUENCE",
            ));
        }
        // tbsCertificate SEQUENCE.
        let (tbs, _after_tbs) = read_sequence(cert_body)?;
        // [0] EXPLICIT version OPTIONAL — skip.
        let (_version_ctx, after_version) = maybe_read_context(tbs, 0)?;
        // serialNumber INTEGER.
        let (serial_body, after_serial) = read_integer_bytes(after_version)?;
        // signature AlgorithmIdentifier (SEQUENCE) — skip.
        let (_alg_body, after_alg) = read_sequence(after_serial)?;
        // issuer Name (SEQUENCE) — capture its raw bytes including the
        // tag/length header so it can be byte-compared.
        let (issuer_tlv, _after_issuer) = super::der::read_tlv(after_alg)?;
        if issuer_tlv.class != Class::Universal || issuer_tlv.tag_number != tag::SEQUENCE {
            return Err(PdfError::other(
                "X.509: tbsCertificate.issuer must be SEQUENCE",
            ));
        }
        let issuer_total = after_alg.len() - {
            let (_t, after) = super::der::read_tlv(after_alg)?;
            after.len()
        };
        let issuer_der = after_alg[..issuer_total].to_vec();
        Ok(Self {
            issuer_der,
            serial: serial_body.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubsec::der::{
        write_context_constructed, write_integer_bytes, write_integer_u64, write_oid,
        write_sequence,
    };

    /// Build a tiny synthetic X.509 v3 cert that's just barely valid
    /// enough to walk past the issuer field.
    fn synth_cert(issuer_der: &[u8], serial: &[u8]) -> Vec<u8> {
        let version = write_context_constructed(0, &write_integer_u64(2)); // v3
        let serial_int = write_integer_bytes(serial);
        let sig_alg = write_sequence(&{
            let mut b = write_oid(&[1, 2, 840, 113549, 1, 1, 11]); // sha256WithRSA
            b.extend_from_slice(&super::super::der::write_null());
            b
        });
        // We can also skip everything after issuer since we don't
        // parse it.
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&version);
        tbs.extend_from_slice(&serial_int);
        tbs.extend_from_slice(&sig_alg);
        tbs.extend_from_slice(issuer_der);
        let tbs_seq = write_sequence(&tbs);
        write_sequence(&{
            let mut b = tbs_seq;
            // Bogus signatureAlgorithm + signatureValue.
            b.extend_from_slice(&write_sequence(&write_oid(&[1, 2, 840, 113549, 1, 1, 11])));
            b.extend_from_slice(&super::super::der::write_tlv(
                Class::Universal,
                false,
                3, // BIT STRING
                &[0x00, 0xAB, 0xCD],
            ));
            b
        })
    }

    #[test]
    fn parse_synthetic_cert_extracts_issuer_and_serial() {
        let issuer_der = write_sequence(b"O=Synthetic Test CA");
        let serial = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let cert_der = synth_cert(&issuer_der, &serial);
        let cert = Certificate::parse(&cert_der).expect("parse");
        assert_eq!(cert.issuer_der, issuer_der);
        assert_eq!(cert.serial, serial);
    }
}
