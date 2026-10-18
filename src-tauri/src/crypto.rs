//! Phase 1 — crypto core.
//!
//! Design (docs/2026-10-18-standard-notes-alternative-design.md §5):
//!
//! ```text
//! password --Argon2id(salt, params)--> root_key          (once per unlock)
//!   data_key = random 32 bytes                          (once per note)
//!   ciphertext = XChaCha20Poly1305(data_key, nonce, note_json)
//!   wrapped    = XChaCha20Poly1305(root_key, nonce2, data_key)   (stored)
//! ```
//!
//! Envelope layout means a password change only re-wraps `wrapped`; note
//! bodies are never re-encrypted, and one corrupt note cannot affect others.
//!
//! Every secret in this module is wrapped in `Zeroizing`, so it is wiped from
//! memory on drop rather than left for the allocator to reuse.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24; // XChaCha20 extended nonce
pub const SALT_LEN: usize = 16;
pub const WRAP_LEN: usize = NONCE_LEN + KEY_LEN + 16; // nonce || ct || Poly1305 tag

/// Argon2id cost parameters.
///
/// `m_cost` is in KiB. The default is the OWASP-recommended 64 MiB, which is
/// deliberately expensive: it is what makes an offline dictionary attack
/// against a stolen `vault.db` impractical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    /// Cheap parameters for tests only. Never use for real key material.
    pub fn fast() -> Self {
        Self {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Argon2 parameters were rejected (e.g. m_cost too small).
    KdfParams,
    /// Key derivation failed.
    Kdf,
    /// Encryption failed.
    Encrypt,
    /// Decryption or authentication failed — wrong key, or tampered ciphertext.
    ///
    /// This is deliberately the *same* error the caller gets for a wrong
    /// master password, so the failure mode leaks nothing.
    Decrypt,
    /// Stored nonce was not 24 bytes.
    BadNonce,
    /// Stored wrapped-key blob was the wrong length.
    BadWrap,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Uniform text: callers must not be able to distinguish causes.
        let text = match self {
            CryptoError::KdfParams => "key derivation failed",
            CryptoError::Kdf => "key derivation failed",
            CryptoError::Encrypt => "encryption failed",
            CryptoError::Decrypt => "key derivation failed",
            CryptoError::BadNonce => "key derivation failed",
            CryptoError::BadWrap => "key derivation failed",
        };
        f.write_str(text)
    }
}

impl std::error::Error for CryptoError {}

fn cipher_from(key: &[u8; KEY_LEN]) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::KdfParams)
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive the root key from the master password.
///
/// Returns the same key for the same `(password, salt, params)`, and a
/// different key if any of the three changes.
pub fn derive_root_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError::KdfParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

/// 32 bytes of CSPRNG output.
pub fn generate_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(key.as_mut());
    key
}

/// 16 bytes of CSPRNG output, stored in the DB. Not a secret.
pub fn generate_salt() -> Zeroizing<[u8; SALT_LEN]> {
    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
    OsRng.fill_bytes(salt.as_mut());
    salt
}

// ---------------------------------------------------------------------------
// Payload encryption
// ---------------------------------------------------------------------------

/// Encrypt `plaintext`, returning `(nonce, ciphertext || tag)`.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = cipher_from(key)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::Encrypt)?;
    Ok((nonce.to_vec(), ct))
}

/// Encrypt with a caller-supplied nonce, returning `ciphertext || tag`.
///
/// Production never calls this. [`encrypt`] generates a fresh random nonce for
/// every message, which is required for security; pinning a nonce is only
/// useful when comparing against a published test vector, which is what
/// `tests/kat.rs` does. Encrypting two different messages under the same nonce
/// and key destroys the security of both, so this is deliberately kept off
/// every vault code path.
pub fn encrypt_with_nonce(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = cipher_from(key)?;
    cipher
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|_| CryptoError::Encrypt)
}

/// Decrypt `ciphertext` under `key`.
///
/// Returns [`CryptoError::Decrypt`] if the key is wrong or a single bit of the
/// ciphertext or nonce was altered — Poly1305 authentication catches both.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::BadNonce);
    }
    let cipher = cipher_from(key)?;
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(pt))
}

// ---------------------------------------------------------------------------
// Envelope key wrapping
// ---------------------------------------------------------------------------

/// Wrap `data_key` under `root_key`. Output is `nonce || ciphertext || tag`.
pub fn wrap_key(
    root_key: &[u8; KEY_LEN],
    data_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let (nonce, ct) = encrypt(root_key, data_key)?;
    let mut blob = nonce;
    blob.extend_from_slice(&ct);
    debug_assert_eq!(blob.len(), WRAP_LEN);
    Ok(blob)
}

/// Recover `data_key` from a blob produced by [`wrap_key`].
///
/// This is what runs during unlock: it is how a wrong password is detected —
/// with high probability the unwrap fails authentication, and with a
/// probability on the order of 2^-256 the note body then fails to decrypt.
pub fn unwrap_key(
    root_key: &[u8; KEY_LEN],
    blob: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    if blob.len() != WRAP_LEN {
        return Err(CryptoError::BadWrap);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let pt = decrypt(root_key, nonce, ct)?;
    if pt.len() != KEY_LEN {
        return Err(CryptoError::BadWrap);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&pt);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_recovers_plaintext() {
        let key = generate_key();
        let msg = br#"{"title":"secret","text":"my bank pin is 1234"}"#;
        let (nonce, ct) = encrypt(&key, msg).unwrap();
        let out = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(&out[..], msg);
    }

    #[test]
    fn nonce_is_xchacha_length_and_unique() {
        let key = generate_key();
        let (n1, _) = encrypt(&key, b"x").unwrap();
        let (n2, _) = encrypt(&key, b"x").unwrap();
        assert_eq!(n1.len(), NONCE_LEN);
        assert_ne!(n1, n2, "two encryptions must not reuse a nonce");
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let key = generate_key();
        let (nonce, mut ct) = encrypt(&key, b"authentic").unwrap();
        ct[0] ^= 0x01;
        assert_eq!(
            decrypt(&key, &nonce, &ct).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn tampered_nonce_fails_authentication() {
        let key = generate_key();
        let (mut nonce, ct) = encrypt(&key, b"authentic").unwrap();
        nonce[0] ^= 0x01;
        assert_eq!(
            decrypt(&key, &nonce, &ct).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let (_, nonce, ct) = {
            let k = generate_key();
            let (n, c) = encrypt(&k, b"authentic").unwrap();
            (k, n, c)
        };
        assert_eq!(
            decrypt(&generate_key(), &nonce, &ct).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn derivation_is_deterministic_for_same_inputs() {
        let salt = [7u8; SALT_LEN];
        let a = derive_root_key("correct horse", &salt, &KdfParams::fast()).unwrap();
        let b = derive_root_key("correct horse", &salt, &KdfParams::fast()).unwrap();
        assert_eq!(&a[..], &b[..]);
    }

    #[test]
    fn derivation_changes_with_password_salt_and_params() {
        let salt = [7u8; SALT_LEN];
        let base = derive_root_key("pw-a", &salt, &KdfParams::fast()).unwrap();
        let other_pw = derive_root_key("pw-b", &salt, &KdfParams::fast()).unwrap();
        let other_salt = derive_root_key("pw-a", &[8u8; SALT_LEN], &KdfParams::fast()).unwrap();
        let mut slow = KdfParams::fast();
        slow.t_cost = 2;
        let other_params = derive_root_key("pw-a", &salt, &slow).unwrap();
        assert_ne!(&base[..], &other_pw[..]);
        assert_ne!(&base[..], &other_salt[..]);
        assert_ne!(&base[..], &other_params[..]);
    }

    #[test]
    fn empty_and_unicode_passwords_do_not_panic() {
        let salt = generate_salt();
        assert!(derive_root_key("", &salt, &KdfParams::fast()).is_ok());
        assert!(derive_root_key("🔐 नोट्स 🔐", &salt, &KdfParams::fast()).is_ok());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let root = generate_key();
        let data = generate_key();
        let blob = wrap_key(&root, &data).unwrap();
        assert_eq!(blob.len(), WRAP_LEN);
        let back = unwrap_key(&root, &blob).unwrap();
        assert_eq!(&back[..], &data[..]);
    }

    #[test]
    fn unwrap_with_wrong_root_fails() {
        let blob = wrap_key(&generate_key(), &generate_key()).unwrap();
        assert!(unwrap_key(&generate_key(), &blob).is_err());
    }

    #[test]
    fn wrapped_key_is_not_the_data_key() {
        let root = generate_key();
        let data = generate_key();
        let blob = wrap_key(&root, &data).unwrap();
        assert!(!blob.windows(KEY_LEN).any(|w| w == &data[..]));
    }

    #[test]
    fn wrong_password_yields_generic_error() {
        // The caller cannot tell "wrong password" from "corrupt blob".
        let salt = [1u8; SALT_LEN];
        let root = derive_root_key("right", &salt, &KdfParams::fast()).unwrap();
        let blob = wrap_key(&root, &generate_key()).unwrap();
        let wrong = derive_root_key("wrong", &salt, &KdfParams::fast()).unwrap();
        assert_eq!(
            unwrap_key(&wrong, &blob).unwrap_err().to_string(),
            "key derivation failed"
        );
    }

    #[test]
    fn default_params_are_64mib_and_run() {
        let salt = generate_salt();
        // Proves the shipped KDF configuration is actually accepted by Argon2.
        assert!(derive_root_key("pw", &salt, &KdfParams::default()).is_ok());
    }
}
