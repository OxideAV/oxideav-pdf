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

use super::x509::{time_within, Certificate};

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
    /// Round-18: multi-entry SKI index — every cert ever inserted via
    /// [`Self::insert_certificate`] is appended here (along with its
    /// SKI) so [`Self::find_with_temporal_validity`] can pick among
    /// multiple certs that share an SKI but have different validity
    /// windows. The single-entry [`Self::by_ski`] is kept as the fast
    /// path for callers that don't care about temporal selection — it
    /// holds the LAST cert inserted under each SKI (last-writer-wins).
    by_ski_multi: Vec<(Vec<u8>, Certificate)>,
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
    ///
    /// Round 18: SKI inserts also land in the multi-entry SKI index
    /// consulted by [`Self::find_with_temporal_validity`].
    pub fn insert(&mut self, key: CertRef, cert: Certificate) {
        match key {
            CertRef::IssuerAndSerial { issuer_der, serial } => {
                self.by_ias.insert((issuer_der, serial), cert);
            }
            CertRef::SubjectKeyIdentifier(ski) => {
                self.by_ski_multi.push((ski.clone(), cert.clone()));
                self.by_ski.insert(ski, cert);
            }
        }
    }

    /// Insert a certificate under both its [`CertRef::IssuerAndSerial`]
    /// and [`CertRef::SubjectKeyIdentifier`] forms (when the latter is
    /// derivable from the cert's SPKI). The two index entries point at
    /// independent clones of the same struct — modifying one after
    /// insertion does not affect the other.
    ///
    /// Round 18: also appended to the multi-entry SKI index so multiple
    /// certs with the same SKI but different validity windows survive
    /// (the single-entry [`Self::by_ski`] still keeps last-writer-wins
    /// semantics for the [`Self::lookup`] fast path).
    pub fn insert_certificate(&mut self, cert: Certificate) {
        let ias_key = (cert.issuer_der.clone(), cert.serial.clone());
        if let Some(ski) = cert.subject_key_identifier() {
            self.by_ski_multi.push((ski.clone(), cert.clone()));
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

    /// Round-18: pick among multiple certs sharing the same
    /// `SubjectKeyIdentifier` the one whose validity window contains
    /// the supplied `instant` (a `GeneralizedTime` ASCII byte string,
    /// `b"YYYYMMDDHHMMSSZ"` — see [`super::x509::time_within`]). When
    /// `instant` is `None` (i.e. the envelope's `RecipientKeyIdentifier`
    /// omitted the OPTIONAL `date` field), this falls back to the
    /// last-inserted cert under the SKI — equivalent to [`Self::lookup`].
    ///
    /// When `instant` is `Some(_)`, every cert sharing the SKI is
    /// scanned in insertion order; the FIRST one whose validity window
    /// contains `instant` wins. Certs without a parsed validity window
    /// are skipped during the temporal scan (so a tester would wind up
    /// using the [`Self::lookup`] fall-through instead).
    ///
    /// Use case: long-lived archives where the same recipient SKI has
    /// been re-certified multiple times (e.g. yearly cert rotation
    /// preserving the SubjectKey across roll-overs); the envelope's
    /// `RecipientKeyIdentifier.date` pins the cert generation that was
    /// active at envelope-creation time. RFC 5652 §6.2.2.
    pub fn find_with_temporal_validity(
        &self,
        ski: &[u8],
        instant: Option<&[u8]>,
    ) -> Option<&Certificate> {
        match instant {
            Some(inst) => {
                for (entry_ski, cert) in &self.by_ski_multi {
                    if entry_ski.as_slice() != ski {
                        continue;
                    }
                    if let Some((nb, na)) = cert.validity() {
                        if time_within(inst, nb, na) {
                            return Some(cert);
                        }
                    }
                }
                // No cert under this SKI had a window containing the
                // instant. Don't fall through — the caller specifically
                // asked for temporal validity.
                None
            }
            None => self.by_ski.get(ski),
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
            validity: None,
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

    /// Round-18: build two certs with the same SKI but disjoint
    /// validity windows; verify [`TrustStore::find_with_temporal_validity`]
    /// picks the cert whose window contains the instant.
    fn synth_cert_with_validity(
        issuer: &[u8],
        serial: &[u8],
        spki: Vec<u8>,
        not_before: &[u8],
        not_after: &[u8],
    ) -> Certificate {
        Certificate {
            issuer_der: issuer.to_vec(),
            serial: serial.to_vec(),
            spki_pubkey_bits: Some(spki),
            validity: Some((not_before.to_vec(), not_after.to_vec())),
        }
    }

    #[test]
    fn find_with_temporal_validity_picks_active_generation() {
        let mut store = TrustStore::new();
        // Two certs share the same SPKI bits => same SKI. cert_a is
        // valid 2024-01-01 .. 2024-12-31; cert_b is valid 2025-01-01 ..
        // 2025-12-31.
        let pubkey = b"shared-spki-bits-32-bytes-ZZZZ!!".to_vec();
        let cert_a = synth_cert_with_validity(
            b"O=A 2024",
            &[0x01],
            pubkey.clone(),
            b"20240101000000Z",
            b"20241231235959Z",
        );
        let cert_b = synth_cert_with_validity(
            b"O=B 2025",
            &[0x02],
            pubkey.clone(),
            b"20250101000000Z",
            b"20251231235959Z",
        );
        store.insert_certificate(cert_a.clone());
        store.insert_certificate(cert_b.clone());
        let ski = cert_a.subject_key_identifier().expect("SKI");

        // Instant in 2024 → cert_a.
        let hit_a = store
            .find_with_temporal_validity(&ski, Some(b"20240601000000Z"))
            .expect("temporal-A");
        assert_eq!(hit_a.serial, vec![0x01]);

        // Instant in 2025 → cert_b.
        let hit_b = store
            .find_with_temporal_validity(&ski, Some(b"20250601000000Z"))
            .expect("temporal-B");
        assert_eq!(hit_b.serial, vec![0x02]);

        // Instant in 2026 (outside both windows) → None.
        assert!(store
            .find_with_temporal_validity(&ski, Some(b"20260601000000Z"))
            .is_none());

        // No instant → fall-through to lookup (last-writer-wins =
        // cert_b for the single-entry by_ski path).
        let fallback = store
            .find_with_temporal_validity(&ski, None)
            .expect("fallback");
        assert_eq!(fallback.serial, vec![0x02]);
    }

    #[test]
    fn find_with_temporal_validity_skips_certs_without_window() {
        let mut store = TrustStore::new();
        let pubkey = b"some-spki-bits-32-bytes-padding!".to_vec();
        // cert_no_window has SPKI but no validity bytes — temporal
        // scan must skip it.
        let cert_no_window = Certificate {
            issuer_der: b"O=No window".to_vec(),
            serial: vec![0xAA],
            spki_pubkey_bits: Some(pubkey.clone()),
            validity: None,
        };
        let cert_with_window = synth_cert_with_validity(
            b"O=With window",
            &[0xBB],
            pubkey.clone(),
            b"20260101000000Z",
            b"20261231235959Z",
        );
        store.insert_certificate(cert_no_window);
        store.insert_certificate(cert_with_window.clone());
        let ski = cert_with_window.subject_key_identifier().expect("SKI");

        let hit = store
            .find_with_temporal_validity(&ski, Some(b"20260601000000Z"))
            .expect("temporal-with-window");
        assert_eq!(hit.serial, vec![0xBB]);
    }
}
