//! Known-answer tests.
//!
//! These are the tests that answer the question a property suite cannot: *is
//! this implementation the one we think it is?*
//!
//! Round-trip and tamper tests pass on a subtly wrong implementation just as
//! happily as on a correct one. These compare byte-for-byte against expected
//! values produced by two implementations that share no code with
//! RustCrypto:
//!
//!   - XChaCha20-Poly1305 expected values from PyNaCl (libsodium)
//!   - Argon2id expected values from argon2-cffi (the PHC reference C code)
//!
//! The XChaCha20 inputs are libsodium's own test-suite vectors, so the inputs
//! are not self-generated either.
//!
//! Vectors are produced by `scripts/gen_kat.py` and live in `kat_vectors.rs`.

// Vectors live in a subdirectory on purpose: cargo treats every *.rs directly
// under tests/ as its own integration-test target, which would compile the
// data file as a binary with no tests in it.
#[path = "vectors/kat.rs"]
mod kat_vectors;

use kat_vectors::{ARGON2ID_KATS, XCHACHA_KATS};

use vaultnote_lib::crypto::{self, KdfParams};

#[test]
fn xchacha20poly1305_matches_libsodium() {
    assert!(!XCHACHA_KATS.is_empty(), "vector table is empty");
    for kat in XCHACHA_KATS {
        // libsodium (via PyNaCl) returns ciphertext||tag; so does the aead
        // crate, so the expected value is the concatenation of the two.
        let mut expected = kat.ct.to_vec();
        expected.extend_from_slice(kat.tag);

        let got = crypto::encrypt_with_nonce(&kat.key, &kat.nonce, kat.msg)
            .unwrap_or_else(|e| panic!("{}: encrypt failed: {e}", kat.name));

        assert_eq!(got.len(), expected.len(), "{}: length mismatch", kat.name);
        assert_eq!(
            &got[..],
            &expected[..],
            "{}: ciphertext or tag differs from libsodium",
            kat.name
        );
    }
}

#[test]
fn xchacha20poly1305_decrypts_libsodium_vectors() {
    for kat in XCHACHA_KATS {
        let mut blob = kat.ct.to_vec();
        blob.extend_from_slice(kat.tag);

        let pt = crypto::decrypt(&kat.key, &kat.nonce, &blob)
            .unwrap_or_else(|e| panic!("{}: decrypt failed: {e}", kat.name));
        assert_eq!(&pt[..], kat.msg, "{}: plaintext mismatch", kat.name);
    }
}

#[test]
fn a_flipped_bit_breaks_a_libsodium_vector() {
    // Guards the test above: if authentication were not actually running, the
    // decrypt assertion would pass on corrupted data too.
    let kat = &XCHACHA_KATS[0];
    let mut blob = kat.ct.to_vec();
    blob.extend_from_slice(kat.tag);
    blob[0] ^= 0x01;

    assert!(
        crypto::decrypt(&kat.key, &kat.nonce, &blob).is_err(),
        "a corrupted ciphertext must not authenticate"
    );
}

#[test]
fn argon2id_matches_the_reference_implementation() {
    assert!(!ARGON2ID_KATS.is_empty(), "vector table is empty");
    for kat in ARGON2ID_KATS {
        assert_eq!(
            kat.out_len,
            crypto::KEY_LEN,
            "{}: out_len unsupported",
            kat.label
        );

        let params = KdfParams {
            m_cost: kat.m_cost,
            t_cost: kat.t_cost,
            p_cost: kat.p_cost,
        };
        let salt: [u8; crypto::SALT_LEN] = kat.salt;

        let pw = String::from_utf8_lossy(kat.password);
        let got = crypto::derive_root_key(&pw, &salt, &params)
            .unwrap_or_else(|e| panic!("{}: derivation failed: {e}", kat.label));

        assert_eq!(
            &got[..],
            kat.expected,
            "{}: derived key differs from argon2-cffi",
            kat.label
        );
    }
}

#[test]
fn shipped_kdf_parameters_are_covered_by_a_vector() {
    // The app derives keys with KdfParams::default(). If no vector pins that
    // exact configuration, a change to it would never be caught.
    let default = KdfParams::default();
    assert!(
        ARGON2ID_KATS.iter().any(|k| {
            k.m_cost == default.m_cost && k.t_cost == default.t_cost && k.p_cost == default.p_cost
        }),
        "no known-answer vector covers KdfParams::default() ({default:?})"
    );
}
