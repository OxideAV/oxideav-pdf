#![no_main]

//! Password-decrypt fuzz harness.
//!
//! Drives [`read_pdf_to_scene_with_password`] on arbitrary fuzz-supplied
//! bytes with an arbitrary password split out of the same input.
//! Exercises the §7.6 standard-handler dispatch (R=2 RC4-40, R=3 RC4-128,
//! R=4 AES-128 / RC4-128 with crypt filters, R=5 / R=6 AES-256 with
//! SHA-256/384/512 key derivation per Algorithm 2.B in ISO 32000-2:2020
//! §7.6.4.4.3) layered on top of the full reader, so any panic in the
//! AES-128 / AES-256 / RC4 / CBC / SHA-256 / SHA-384 / SHA-512 key
//! derivation or stream-decrypt paths surfaces here.
//!
//! Input split: the first byte is interpreted as a password length
//! `n` (0..=255). The next `min(n, remaining)` bytes are the password.
//! Everything after that is fed to the decoder as the PDF body. This
//! gives the fuzzer independent control over password length / content
//! and document content, so it can drive
//!   - empty-password files (n=0)
//!   - the §7.6.4.3.5 owner-password fallback (long passwords)
//!   - the §7.6.4.4.4 R=5/R=6 SASLprep + UTF-8 truncation at 127 bytes
//!     (passwords with high-bit / surrogate bytes)
//!
//! without the harness having to bias its corpus toward any of them.
//!
//! Contract: every call returns to its caller. A `panic!`, `unwrap()`
//! on `None`, slice-OOB, integer-overflow in debug, or OOM abort is a
//! finding and fails the fuzzer.

use libfuzzer_sys::fuzz_target;
use oxideav_pdf::read_pdf_to_scene_with_password;

fuzz_target!(|data: &[u8]| {
    let (password, pdf_body): (&[u8], &[u8]) = if data.is_empty() {
        (data, data)
    } else {
        let n = data[0] as usize;
        let rest = &data[1..];
        let split = n.min(rest.len());
        (&rest[..split], &rest[split..])
    };
    let _ = read_pdf_to_scene_with_password(pdf_body, password);
});
