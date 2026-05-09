//! Round-17: long-term-cert originator trust store for KARI envelopes.
//!
//! Per RFC 5652 §6.2.2 the `OriginatorIdentifierOrKey` CHOICE has three
//! arms: `IssuerAndSerialNumber`, `SubjectKeyIdentifier`, and the in-band
//! `OriginatorPublicKey`. Round 14–16 only handled the in-band form
//! because the recipient could pull the originator's public point
//! straight out of the envelope. Round 17 closes the long-term-cert
//! gap: when the originator is identified by `IssuerAndSerial` or `SKI`
//! the recipient is expected to look up the originator's certificate in
//! its own [`TrustStore`] and recover the public point from there.
//!
//! The trust store maps either form of [`CertRef`] to a parsed
//! [`super::x509::Certificate`] whose `spki_pubkey_bits` slot carries
//! the originator's encoded EC public point — SEC1 uncompressed for
//! NIST curves (P-256 / P-384 / P-521) or the raw 32-byte u-coordinate
//! for X25519 per RFC 8410 §4. The reader-side
//! [`super::open_with_certificate_and_trust_store`] entry point accepts
//! a `&TrustStore` argument and threads it through the KARI unwrap
//! dispatch.
//!
//! Provenance: RFC 5652 §6.2.2 + RFC 5280 §4.1.2.2 / §4.2.1.2 +
//! RFC 5480 §2.1.1.1 + RFC 8410 §4 only.

use std::collections::HashMap;

use super::x509::Certificate;

/// CHOICE tag for one entry in a [`TrustStore`]. Mirrors the two
/// long-term-cert forms of `OriginatorIdentifierOrKey`'s CHOICE
/// (RFC 5652 §6.2.2): `IssuerAndSerial` (CMS v0) or `SubjectKeyIdentifier`
/// (CMS v2).
///
/// The same enum doubles as a generic certificate-reference type, so a
/// caller can also use it for application-level cert pinning beyond the
/// KARI originator path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CertRef {
    /// `IssuerAndSerialNumber` form — DER `issuer` Name SEQUENCE plus
    /// the raw INTEGER body of the serial number (matches the bytes
    /// stored in [`super::x509::Certificate::issuer_der`] +
    /// [`super::x509::Certificate::serial`]).
    IssuerAndSerial {
        /// DER-encoded `issuer` Name (a SEQUENCE OF RelativeDistinguishedName).
        issuer_der: Vec<u8>,
        /// Raw INTEGER body of the serial number (RFC 5280 §4.1.2.2 —
        /// up to 20 octets, big-endian two's complement).
        serial: Vec<u8>,
    },
    /// `SubjectKeyIdentifier` form — the 20-byte SHA-1 of the cert's
    /// `SubjectPublicKeyInfo` BIT STRING contents (RFC 5280 §4.2.1.2
    /// method 1).
    SubjectKeyIdentifier(Vec<u8>),
}

/// Recipient-side trust store mapping cert references (IAS or SKI) to
/// parsed [`Certificate`]s. Lookups are O(1) byte-comparison hash table
/// hits; both forms are indexed independently so the same store can
/// serve both originator-id encodings.
///
/// A single physical certificate may be inserted under both forms when
/// the consumer wants to permit either RID encoding to resolve to the
/// same key — see [`Self::insert_certificate`] which automatically
/// indexes by both IAS and SKI when the cert's SPKI is parsable.
#[derive(Debug, Default, Clone)]
pub struct TrustStore {
    by_ias: HashMap<(Vec<u8>, Vec<u8>), Certificate>,
    by_ski: HashMap<Vec<u8>, Certificate>,
}

impl TrustStore {
    /// Build an empty trust store. Use [`Self::insert`] /
    /// [`Self::insert_certificate`] to populate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a certificate under one explicit [`CertRef`] form. Use
    /// [`Self::insert_certificate`] to index a cert under both forms
    /// automatically.
    pub fn insert(&mut self, key: CertRef, cert: Certificate) {
        match key {
            CertRef::IssuerAndSerial { issuer_der, serial } => {
                self.by_ias.insert((issuer_der, serial), cert);
            }
            CertRef::SubjectKeyIdentifier(ski) => {
                self.by_ski.insert(ski, cert);
            }
        }
    }

    /// Insert a certificate under both its [`CertRef::IssuerAndSerial`]
    /// and [`CertRef::SubjectKeyIdentifier`] forms (when the latter is
    /// derivable from the cert's SPKI). The two index entries point at
    /// independent clones of the same struct — modifying one after
    /// insertion does not affect the other.
    pub fn insert_certificate(&mut self, cert: Certificate) {
        let ias_key = (cert.issuer_der.clone(), cert.serial.clone());
        if let Some(ski) = cert.subject_key_identifier() {
            self.by_ski.insert(ski, cert.clone());
        }
        self.by_ias.insert(ias_key, cert);
    }

    /// Look up a certificate by [`CertRef`]. Returns `None` when no
    /// matching entry exists.
    pub fn lookup(&self, key: &CertRef) -> Option<&Certificate> {
        match key {
            CertRef::IssuerAndSerial { issuer_der, serial } => {
                self.by_ias.get(&(issuer_der.clone(), serial.clone()))
            }
            CertRef::SubjectKeyIdentifier(ski) => self.by_ski.get(ski),
        }
    }

    /// Number of certificate entries in the store. Counts each indexed
    /// form — a certificate inserted via [`Self::insert_certificate`]
    /// contributes 2 (IAS + SKI) when its SPKI is parseable, else 1.
    pub fn len(&self) -> usize {
        self.by_ias.len() + self.by_ski.len()
    }

    /// `true` when no entries have been inserted.
    pub fn is_empty(&self) -> bool {
        self.by_ias.is_empty() && self.by_ski.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_cert(issuer: &[u8], serial: &[u8], spki: Option<Vec<u8>>) -> Certificate {
        Certificate {
            issuer_der: issuer.to_vec(),
            serial: serial.to_vec(),
            spki_pubkey_bits: spki,
        }
    }

    #[test]
    fn ias_round_trip() {
        let mut store = TrustStore::new();
        let cert = synth_cert(b"O=A", &[0x01, 0x02], None);
        store.insert(
            CertRef::IssuerAndSerial {
                issuer_der: cert.issuer_der.clone(),
                serial: cert.serial.clone(),
            },
            cert.clone(),
        );
        let key = CertRef::IssuerAndSerial {
            issuer_der: cert.issuer_der.clone(),
            serial: cert.serial.clone(),
        };
        assert!(store.lookup(&key).is_some());
        let key_miss = CertRef::IssuerAndSerial {
            issuer_der: b"O=Other".to_vec(),
            serial: vec![0x99],
        };
        assert!(store.lookup(&key_miss).is_none());
    }

    #[test]
    fn ski_round_trip() {
        let mut store = TrustStore::new();
        let ski = vec![0xCDu8; 20];
        let cert = synth_cert(b"O=B", &[0x05], Some(b"FakeSPKI".to_vec()));
        store.insert(CertRef::SubjectKeyIdentifier(ski.clone()), cert);
        assert!(store.lookup(&CertRef::SubjectKeyIdentifier(ski)).is_some());
        assert!(store
            .lookup(&CertRef::SubjectKeyIdentifier(vec![0; 20]))
            .is_none());
    }

    #[test]
    fn insert_certificate_indexes_both_forms_when_spki_present() {
        let mut store = TrustStore::new();
        let pubkey = b"PK-bytes-for-SKI-derivation--32!";
        let cert = synth_cert(b"O=C", &[0x07], Some(pubkey.to_vec()));
        let ski = cert.subject_key_identifier().expect("SKI");
        store.insert_certificate(cert.clone());
        assert!(store
            .lookup(&CertRef::IssuerAndSerial {
                issuer_der: cert.issuer_der.clone(),
                serial: cert.serial.clone(),
            })
            .is_some());
        assert!(store.lookup(&CertRef::SubjectKeyIdentifier(ski)).is_some());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn insert_certificate_skips_ski_when_spki_absent() {
        let mut store = TrustStore::new();
        let cert = synth_cert(b"O=D", &[0x09], None);
        store.insert_certificate(cert.clone());
        assert!(store
            .lookup(&CertRef::IssuerAndSerial {
                issuer_der: cert.issuer_der,
                serial: cert.serial,
            })
            .is_some());
        assert_eq!(store.len(), 1);
    }
}
