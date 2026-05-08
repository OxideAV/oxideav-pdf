//! Minimal X.509 v3 (RFC 5280) parser — extracts the fields the PDF
//! public-key handler needs to match a recipient slot.
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
//!   validity         Validity,                -- SEQUENCE
//!   subject          Name,                    -- SEQUENCE
//!   subjectPublicKeyInfo SubjectPublicKeyInfo, -- SEQUENCE
//!   ...
//! }
//! SubjectPublicKeyInfo ::= SEQUENCE {
//!   algorithm        AlgorithmIdentifier,
//!   subjectPublicKey BIT STRING
//! }
//! ```
//!
//! Round 11 extends the parser to also extract the
//! `subjectPublicKeyInfo` BIT STRING contents — the bytes whose SHA-1
//! is the certificate's `SubjectKeyIdentifier` (RFC 5280 §4.2.1.2
//! method 1). This lets the pubsec matcher recognise the SKI form of
//! the CMS RecipientIdentifier.
//!
//! Provenance: RFC 5280 §4.1 + §4.2.1.2 only.

use crate::error::PdfError;

use super::der::{maybe_read_context, read_integer_bytes, read_sequence, read_tlv, tag, Class};

/// The fields a CMS recipient slot needs to match against a user's
/// certificate. Stored exactly as DER bytes so equality is a memcmp.
///
/// The `spki_pubkey_bits` slot holds the BIT STRING contents of the
/// certificate's `subjectPublicKeyInfo.subjectPublicKey` — the bytes
/// whose SHA-1 is the certificate's SubjectKeyIdentifier (RFC 5280
/// §4.2.1.2 method 1). It is `None` when the parser couldn't reach
/// the SPKI (e.g. because the synthetic test certificate truncates
/// TBSCertificate after `issuer`).
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Raw DER of the issuer `Name` (a SEQUENCE).
    pub issuer_der: Vec<u8>,
    /// Raw INTEGER body bytes of the serial number.
    pub serial: Vec<u8>,
    /// `subjectPublicKey` BIT STRING contents (no leading unused-bits
    /// byte). `None` when SPKI couldn't be located in the TBS body.
    pub spki_pubkey_bits: Option<Vec<u8>>,
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
        let (issuer_tlv, after_issuer) = read_tlv(after_alg)?;
        if issuer_tlv.class != Class::Universal || issuer_tlv.tag_number != tag::SEQUENCE {
            return Err(PdfError::other(
                "X.509: tbsCertificate.issuer must be SEQUENCE",
            ));
        }
        let issuer_total = after_alg.len() - after_issuer.len();
        let issuer_der = after_alg[..issuer_total].to_vec();

        // Best-effort SPKI extraction: the synthetic test certs in the
        // round-10 unit suite truncate TBS after `issuer`, so we have
        // to tolerate a parse failure here. validity SEQUENCE, subject
        // Name SEQUENCE, then subjectPublicKeyInfo SEQUENCE.
        let spki_pubkey_bits = (|| -> Option<Vec<u8>> {
            let after_validity = match read_sequence(after_issuer) {
                Ok((_, rest)) => rest,
                Err(_) => return None,
            };
            // subject SEQUENCE — skip.
            let after_subject = match read_sequence(after_validity) {
                Ok((_, rest)) => rest,
                Err(_) => return None,
            };
            // subjectPublicKeyInfo SEQUENCE.
            let (spki_body, _) = read_sequence(after_subject).ok()?;
            // skip algorithm SEQUENCE
            let (_, after_alg) = read_sequence(spki_body).ok()?;
            // BIT STRING — body has a leading unused-bits byte we drop.
            let (bs, _) = read_tlv(after_alg).ok()?;
            if bs.class != Class::Universal || bs.tag_number != tag::BIT_STRING {
                return None;
            }
            if bs.body.is_empty() {
                return None;
            }
            // RFC 5280 §4.2.1.2 method 1 hashes the BIT STRING value
            // (the bytes after the unused-bits byte).
            Some(bs.body[1..].to_vec())
        })();

        Ok(Self {
            issuer_der,
            serial: serial_body.to_vec(),
            spki_pubkey_bits,
        })
    }

    /// Return the certificate's SubjectKeyIdentifier per RFC 5280
    /// §4.2.1.2 method 1: SHA-1 over the SPKI BIT STRING contents.
    /// Returns `None` when the parser couldn't reach the SPKI (e.g.
    /// the round-10 synthetic test certs that truncate TBS after
    /// `issuer`).
    pub fn subject_key_identifier(&self) -> Option<Vec<u8>> {
        use sha1::Digest;
        self.spki_pubkey_bits
            .as_deref()
            .map(|b| sha1::Sha1::digest(b).to_vec())
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

    /// Synthetic X.509 v3 cert that includes a complete TBSCertificate
    /// up to and including SubjectPublicKeyInfo so the round-11 SKI
    /// extractor can run end-to-end.
    fn synth_cert_with_spki(
        issuer_der: &[u8],
        serial: &[u8],
        spki_pubkey_contents: &[u8],
    ) -> Vec<u8> {
        let version = write_context_constructed(0, &write_integer_u64(2)); // v3
        let serial_int = write_integer_bytes(serial);
        let sig_alg = write_sequence(&{
            let mut b = write_oid(&[1, 2, 840, 113549, 1, 1, 11]);
            b.extend_from_slice(&super::super::der::write_null());
            b
        });
        // validity SEQUENCE { notBefore, notAfter } — both UTCTime
        // (tag 23). Use empty bodies; the parser only checks the
        // outer SEQUENCE shape.
        let validity = write_sequence(&{
            let mut b = super::super::der::write_tlv(Class::Universal, false, 23, b"260101000000Z");
            b.extend_from_slice(&super::super::der::write_tlv(
                Class::Universal,
                false,
                23,
                b"360101000000Z",
            ));
            b
        });
        // subject SEQUENCE — empty.
        let subject = write_sequence(b"");
        // subjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey }
        let spki = write_sequence(&{
            let mut b = sig_alg.clone();
            // BIT STRING with leading 0x00 unused-bits byte then the
            // pubkey contents.
            let mut bs = vec![0x00];
            bs.extend_from_slice(spki_pubkey_contents);
            b.extend_from_slice(&super::super::der::write_tlv(
                Class::Universal,
                false,
                3,
                &bs,
            ));
            b
        });
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&version);
        tbs.extend_from_slice(&serial_int);
        tbs.extend_from_slice(&sig_alg);
        tbs.extend_from_slice(issuer_der);
        tbs.extend_from_slice(&validity);
        tbs.extend_from_slice(&subject);
        tbs.extend_from_slice(&spki);
        let tbs_seq = write_sequence(&tbs);
        write_sequence(&{
            let mut b = tbs_seq;
            b.extend_from_slice(&write_sequence(&write_oid(&[1, 2, 840, 113549, 1, 1, 11])));
            b.extend_from_slice(&super::super::der::write_tlv(
                Class::Universal,
                false,
                3,
                &[0x00, 0xAB, 0xCD],
            ));
            b
        })
    }

    #[test]
    fn parse_synthetic_cert_extracts_spki_and_ski() {
        let issuer_der = write_sequence(b"O=SKI Test CA");
        let serial = vec![0x42];
        let pubkey = b"FakePubKeyBitsForSKIHashing-32B!";
        let cert_der = synth_cert_with_spki(&issuer_der, &serial, pubkey);
        let cert = Certificate::parse(&cert_der).expect("parse");
        assert_eq!(cert.spki_pubkey_bits.as_deref(), Some(&pubkey[..]));
        let ski = cert.subject_key_identifier().expect("SKI");
        // Check SHA-1 of the pubkey bytes.
        use sha1::Digest;
        let expected = sha1::Sha1::digest(pubkey).to_vec();
        assert_eq!(ski, expected);
        assert_eq!(ski.len(), 20);
    }
}
