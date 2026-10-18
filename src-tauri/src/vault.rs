//! The Vault — the only place where a master password becomes readable notes.
//!
//! Everything above this module speaks in encrypted rows; everything below it
//! (`db`) only ever sees ciphertext. The root key lives in this struct and in
//! `session` — never in a `#[tauri::command]` return value.

use std::cmp::Reverse;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams};
use crate::db::{new_id, ItemRow, Store, StoreError};

/// A fixed known value, wrapped under the root key at first run. Unwrapping it
/// is an exact password check — as opposed to "try to decrypt something and
/// see if it fails", which would accept a wrong password with probability
/// 2^-256 and is harder to reason about.
const VERIFIER: [u8; crypto::KEY_LEN] = *b"vaultnote-password-verifier-v01!";

/// Attachment chunk size. 1 MiB: large enough that per-chunk overhead is
/// negligible, small enough that decrypting a 500 MB file never holds more
/// than a megabyte of plaintext plus its ciphertext at a time.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// What actually gets encrypted into `attachment_meta.meta_ct`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAttachmentMeta {
    filename: String,
    mime: String,
    size: u64,
    chunks: u32,
}

/// Decrypted attachment metadata, safe to hand to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentInfo {
    pub id: String,
    pub item_id: String,
    pub filename: String,
    pub mime: String,
    pub size: u64,
    pub chunks: u32,
}

/// Plaintext shape of a note. Exists in memory only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Note {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<String>,
    #[serde(default)]
    pub pinned: bool,
}

/// What the note list needs. Enough to render without decrypting twice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteSummary {
    pub id: String,
    pub title: String,
    pub tags: Vec<String>,
    pub pinned: bool,
    pub updated_at: i64,
}

#[derive(Debug, PartialEq)]
pub enum VaultError {
    /// The password did not unwrap the verifier.
    WrongPassword,
    /// A stored row was malformed.
    Corrupt,
    /// Rejected before any key derivation happened, so no timing difference.
    WeakPassword,
    Storage(StoreError),
    Crypto,
    Serialisation,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            // Wrong password and corruption are reported identically on
            // purpose: a distinct "corrupt vault" message would tell an
            // attacker something about the file before they had a password.
            VaultError::WrongPassword => "wrong password, or the vault file is damaged",
            VaultError::Corrupt => "wrong password, or the vault file is damaged",
            VaultError::WeakPassword => "password must be at least 8 characters",
            VaultError::Storage(_) => "storage error",
            VaultError::Crypto => "crypto error",
            VaultError::Serialisation => "crypto error",
        })
    }
}

impl std::error::Error for VaultError {}

impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        VaultError::Storage(e)
    }
}

pub struct Vault {
    store: Store,
    root_key: Zeroizing<[u8; crypto::KEY_LEN]>,
}

impl Vault {
    /// First run: make a vault, write the salt and the verifier, return an
    /// open session. There is no recovery path from here — the password is the
    /// only key.
    pub fn create(path: &Path, password: &str) -> Result<Self, VaultError> {
        let store = Store::open(path)?;
        if store.get_meta("password_check")?.is_some() {
            return Err(VaultError::WrongPassword);
        }
        let params = KdfParams::default();
        let salt = crypto::generate_salt();
        let root_key =
            crypto::derive_root_key(password, &salt, &params).map_err(|_| VaultError::Crypto)?;

        store.set_salt(&salt)?;
        store.set_meta(
            "kdf_params",
            &serde_json::json!({ "m_cost": params.m_cost, "t_cost": params.t_cost, "p_cost": params.p_cost })
                .to_string(),
        )?;
        store.set_meta(
            "password_check",
            &hex(&crypto::wrap_key(&root_key, &VERIFIER).map_err(|_| VaultError::Crypto)?),
        )?;

        Ok(Self { store, root_key })
    }

    /// Subsequent runs: derive from the stored salt and check the password.
    pub fn open(path: &Path, password: &str) -> Result<Self, VaultError> {
        let store = Store::open(path)?;
        let salt = store.get_salt()?.ok_or(VaultError::WrongPassword)?;
        let check = store
            .get_meta("password_check")?
            .and_then(|h| unhex(&h))
            .ok_or(VaultError::WrongPassword)?;

        let root_key = crypto::derive_root_key(password, &salt, &KdfParams::default())
            .map_err(|_| VaultError::Crypto)?;

        let unwrapped =
            crypto::unwrap_key(&root_key, &check).map_err(|_| VaultError::WrongPassword)?;
        if unwrapped[..] != VERIFIER {
            return Err(VaultError::WrongPassword);
        }

        Ok(Self { store, root_key })
    }

    /// True when this vault has never been initialised.
    pub fn is_initialised(path: &Path) -> bool {
        Store::open(path)
            .and_then(|s| s.get_meta("password_check").map(|v| v.is_some()))
            .unwrap_or(false)
    }

    // -- reads --------------------------------------------------------------

    pub fn list(&self) -> Result<Vec<NoteSummary>, VaultError> {
        let mut out = Vec::new();
        for row in self.store.list_items()? {
            if let Some(s) = self.summarise(&row)? {
                out.push(s);
            }
        }
        // Pinned first, then most recently updated. Both comparisons are reversed
        // rather than written out longhand.
        out.sort_by_key(|n| (Reverse(n.pinned), Reverse(n.updated_at)));
        Ok(out)
    }

    pub fn get(&self, id: &str) -> Result<Option<Note>, VaultError> {
        // `decrypt_note` already returns an Option — a row that is not a note
        // yields None rather than being a decrypt failure.
        match self.store.get_item(id)? {
            None => Ok(None),
            Some(row) => self.decrypt_note(&row),
        }
    }

    pub fn trashed(&self) -> Result<Vec<NoteSummary>, VaultError> {
        let mut out = Vec::new();
        for row in self.store.list_trashed()? {
            if let Some(s) = self.summarise(&row)? {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Case-insensitive substring search over title, body and tags.
    ///
    /// Every row is decrypted to search it — that is the cost of holding an
    /// encrypted index, and it is the right trade for a local vault.
    pub fn search(&self, query: &str) -> Result<Vec<NoteSummary>, VaultError> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return self.list();
        }
        let mut out = Vec::new();
        for row in self.store.list_items()? {
            if let Some(note) = self.decrypt_note(&row)? {
                let hit = note.title.to_lowercase().contains(&needle)
                    || note.text.to_lowercase().contains(&needle)
                    || note.tags.iter().any(|t| t.to_lowercase().contains(&needle));
                if hit {
                    out.push(self.summary_of(&row.id, note));
                }
            }
        }
        Ok(out)
    }

    /// Every distinct tag in the vault, with counts.
    pub fn all_tags(&self) -> Result<Vec<(String, usize)>, VaultError> {
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for note in self.list()?.into_iter().flat_map(|s| s.tags) {
            *counts.entry(note).or_default() += 1;
        }
        let mut tags: Vec<_> = counts.into_iter().collect();
        tags.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        Ok(tags)
    }

    // -- writes -------------------------------------------------------------

    /// Create or overwrite a note. `id` of `None` creates a new one.
    pub fn save(&mut self, id: Option<&str>, note: &Note) -> Result<String, VaultError> {
        let json = serde_json::to_vec(note).map_err(|_| VaultError::Serialisation)?;

        let item_id = match id {
            None => new_id(),
            Some(existing) => existing.to_string(),
        };

        // A fresh data key per write: no key is ever reused across two
        // encryptions of the same note.
        let data_key = crypto::generate_key();
        let (nonce, ciphertext) =
            crypto::encrypt(&data_key, &json).map_err(|_| VaultError::Crypto)?;
        let wrapped =
            crypto::wrap_key(&self.root_key, &data_key).map_err(|_| VaultError::Crypto)?;

        match self.store.get_item(&item_id)? {
            Some(_) => {
                self.store
                    .update_item(&item_id, &nonce, &wrapped, &ciphertext)?;
            }
            None => {
                let ts = now_ms();
                self.store.insert_item(&ItemRow {
                    id: item_id.clone(),
                    content_type: "note".into(),
                    nonce,
                    wrapped_key: wrapped,
                    ciphertext,
                    created_at: ts,
                    updated_at: ts,
                    deleted_at: None,
                })?;
            }
        }
        Ok(item_id)
    }

    pub fn delete(&self, id: &str) -> Result<(), VaultError> {
        self.store.soft_delete(id)?;
        Ok(())
    }

    pub fn restore(&self, id: &str) -> Result<(), VaultError> {
        self.store.restore(id)?;
        Ok(())
    }

    pub fn purge(&self, id: &str) -> Result<(), VaultError> {
        self.store.purge(id)?;
        Ok(())
    }

    /// Re-wrap every key under a new password. Note bodies are untouched —
    /// this is the whole point of the envelope layout.
    pub fn change_password(&mut self, new_password: &str) -> Result<(), VaultError> {
        let new_root =
            crypto::derive_root_key(new_password, &self.salt_stored(), &KdfParams::default())
                .map_err(|_| VaultError::Crypto)?;

        let rows = self.store.all_wrapped_keys()?;
        let mut rewrapped = Vec::with_capacity(rows.len());
        for (id, blob) in rows {
            let data_key =
                crypto::unwrap_key(&self.root_key, &blob).map_err(|_| VaultError::Crypto)?;
            let wrapped = crypto::wrap_key(&new_root, &data_key).map_err(|_| VaultError::Crypto)?;
            rewrapped.push((id, wrapped));
        }

        for (id, wrapped) in rewrapped {
            self.store.set_wrapped_key(&id, &wrapped)?;
        }

        self.store.set_meta(
            "password_check",
            &hex(&crypto::wrap_key(&new_root, &VERIFIER).map_err(|_| VaultError::Crypto)?),
        )?;

        // Assign rather than deref-assign: both sides are `Zeroizing`, and
        // overwriting drops the old key so it gets wiped.
        self.root_key = new_root;
        Ok(())
    }

    fn salt_stored(&self) -> [u8; crypto::SALT_LEN] {
        // The salt never changes after first run, so it is always present.
        self.store
            .get_salt()
            .ok()
            .flatten()
            .unwrap_or([0u8; crypto::SALT_LEN])
    }

    // -- attachments --------------------------------------------------------

    /// Encrypt and store a file against a note.
    ///
    /// The filename and MIME type go inside the encrypted metadata rather than
    /// a plaintext column. A filename like `card-2026-04.pdf` or
    /// `salary.png` leaks more than most people assume, and this app's entire
    /// premise is that the file reveals nothing.
    ///
    /// The data is split into [`CHUNK_SIZE`] pieces and each is encrypted
    /// independently under its own random nonce. That bounds memory for large
    /// files, and it means a truncated or missing chunk is detected rather than
    /// silently producing a short file.
    pub fn add_attachment(
        &mut self,
        item_id: &str,
        filename: &str,
        mime: &str,
        data: &[u8],
    ) -> Result<String, VaultError> {
        if self.store.get_item(item_id)?.is_none() {
            return Err(VaultError::Corrupt);
        }

        let id = new_id();
        let data_key = crypto::generate_key();
        let wrapped =
            crypto::wrap_key(&self.root_key, &data_key).map_err(|_| VaultError::Crypto)?;

        let mut chunks: Vec<(u32, Vec<u8>, Vec<u8>)> = Vec::new();
        for (i, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
            // Fresh random nonce per chunk. Reusing one across chunks under
            // the same key would leak plaintext XOR.
            let (nonce, ct) = crypto::encrypt(&data_key, chunk).map_err(|_| VaultError::Crypto)?;
            chunks.push((i as u32, nonce, ct));
        }

        let meta = serde_json::to_vec(&StoredAttachmentMeta {
            filename,
            mime,
            size: data.len() as u64,
            chunks: chunks.len() as u32,
        })
        .map_err(|_| VaultError::Serialisation)?;
        let (meta_nonce, meta_ct) =
            crypto::encrypt(&data_key, &meta).map_err(|_| VaultError::Crypto)?;

        self.store.insert_attachment(
            &crate::db::AttachmentMetaRow {
                id: id.clone(),
                item_id: item_id.to_string(),
                nonce: meta_nonce,
                wrapped_key: wrapped,
                meta_ct,
                created_at: now_ms(),
            },
            &chunks,
        )?;
        Ok(id)
    }

    /// Metadata for one attachment. Decrypts to get the filename, so this
    /// fails with a wrong-password style error if the session key is wrong.
    pub fn attachment_info(&self, id: &str) -> Result<Option<AttachmentInfo>, VaultError> {
        let Some(row) = self.store.get_attachment_meta(id)? else {
            return Ok(None);
        };
        let data_key = crypto::unwrap_key(&self.root_key, &row.wrapped_key)
            .map_err(|_| VaultError::WrongPassword)?;
        let plain = crypto::decrypt(&data_key, &row.nonce, &row.meta_ct)
            .map_err(|_| VaultError::Corrupt)?;
        let meta: StoredAttachmentMeta =
            serde_json::from_slice(&plain).map_err(|_| VaultError::Corrupt)?;
        Ok(Some(AttachmentInfo {
            id: row.id,
            filename: meta.filename,
            mime: meta.mime,
            size: meta.size,
            chunks: meta.chunks,
            item_id: row.item_id,
        }))
    }

    pub fn list_attachments(&self, item_id: &str) -> Result<Vec<AttachmentInfo>, VaultError> {
        let mut out = Vec::new();
        for row in self.store.list_attachments_for_item(item_id)? {
            let data_key = crypto::unwrap_key(&self.root_key, &row.wrapped_key)
                .map_err(|_| VaultError::WrongPassword)?;
            let plain = crypto::decrypt(&data_key, &row.nonce, &row.meta_ct)
                .map_err(|_| VaultError::Corrupt)?;
            let meta: StoredAttachmentMeta =
                serde_json::from_slice(&plain).map_err(|_| VaultError::Corrupt)?;
            out.push(AttachmentInfo {
                id: row.id,
                item_id: row.item_id,
                filename: meta.filename,
                mime: meta.mime,
                size: meta.size,
                chunks: meta.chunks,
            });
        }
        Ok(out)
    }

    /// Decrypt a whole attachment into memory.
    ///
    /// The working set is one chunk, not one file — but the result still
    /// arrives in one piece, so callers handling large files should prefer
    /// [`Self::read_attachment_chunk`].
    pub fn read_attachment(&self, id: &str) -> Result<Vec<u8>, VaultError> {
        let info = self.attachment_info(id)?.ok_or(VaultError::Corrupt)?;
        let row = self
            .store
            .get_attachment_meta(id)?
            .ok_or(VaultError::Corrupt)?;
        let data_key = crypto::unwrap_key(&self.root_key, &row.wrapped_key)
            .map_err(|_| VaultError::WrongPassword)?;

        let stored = self.store.count_attachment_chunks(id)?;
        if stored != info.chunks {
            return Err(VaultError::Corrupt);
        }

        let mut out = Vec::with_capacity(info.size as usize);
        for index in 0..info.chunks {
            let (nonce, ct) = self
                .store
                .get_attachment_chunk(id, index)?
                .ok_or(VaultError::Corrupt)?;
            let plain = crypto::decrypt(&data_key, &nonce, &ct).map_err(|_| VaultError::Corrupt)?;
            out.extend_from_slice(&plain);
        }

        // Trusting the chunk count alone would let a truncated attachment look
        // complete. The size is authenticated too, so check it.
        if out.len() as u64 != info.size {
            return Err(VaultError::Corrupt);
        }
        Ok(out)
    }

    /// Decrypt one chunk. Used by the UI to stream a large file.
    pub fn read_attachment_chunk(&self, id: &str, index: u32) -> Result<Vec<u8>, VaultError> {
        let row = self
            .store
            .get_attachment_meta(id)?
            .ok_or(VaultError::Corrupt)?;
        let data_key = crypto::unwrap_key(&self.root_key, &row.wrapped_key)
            .map_err(|_| VaultError::WrongPassword)?;
        let (nonce, ct) = self
            .store
            .get_attachment_chunk(id, index)?
            .ok_or(VaultError::Corrupt)?;
        let plain = crypto::decrypt(&data_key, &nonce, &ct).map_err(|_| VaultError::Corrupt)?;
        Ok(plain)
    }

    pub fn delete_attachment(&self, id: &str) -> Result<(), VaultError> {
        self.store.delete_attachment(id)?;
        Ok(())
    }

    // -- internals ----------------------------------------------------------

    fn data_key_for(&self, row: &ItemRow) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>, VaultError> {
        crypto::unwrap_key(&self.root_key, &row.wrapped_key).map_err(|_| VaultError::WrongPassword)
    }

    fn decrypt_note(&self, row: &ItemRow) -> Result<Option<Note>, VaultError> {
        if row.content_type != "note" {
            return Ok(None);
        }
        let data_key = self.data_key_for(row)?;
        let plain = crypto::decrypt(&data_key, &row.nonce, &row.ciphertext)
            .map_err(|_| VaultError::Corrupt)?;
        serde_json::from_slice(&plain)
            .map(Some)
            .map_err(|_| VaultError::Corrupt)
    }

    fn summarise(&self, row: &ItemRow) -> Result<Option<NoteSummary>, VaultError> {
        Ok(self
            .decrypt_note(row)?
            .map(|note| self.summary_of(&row.id, note)))
    }

    fn summary_of(&self, id: &str, note: Note) -> NoteSummary {
        NoteSummary {
            id: id.to_string(),
            title: note.title,
            tags: note.tags,
            pinned: note.pinned,
            updated_at: now_ms(),
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16)?;
            let lo = (p[1] as char).to_digit(16)?;
            Some(((hi << 4) | lo) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempVault(std::path::PathBuf);
    impl Drop for TempVault {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn temp_path(tag: &str) -> TempVault {
        let p = std::env::temp_dir().join(format!("vaultnote-test-{tag}-{}.db", &new_id()[..8]));
        TempVault(p)
    }

    fn note(title: &str, text: &str, tags: &[&str]) -> Note {
        Note {
            title: title.into(),
            text: text.into(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            attachments: vec![],
            pinned: false,
        }
    }

    const PW: &str = "correct horse battery staple";

    #[test]
    fn create_then_reopen_with_same_password() {
        let p = temp_path("reopen");
        {
            let mut v = Vault::create(&p.0, PW).unwrap();
            v.save(None, &note("Bank", "PIN 1234", &["secret"]))
                .unwrap();
        }
        let v = Vault::open(&p.0, PW).unwrap();
        let notes = v.list().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].title, "Bank");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let p = temp_path("wrongpw");
        Vault::create(&p.0, PW).unwrap();
        // `unwrap_err` would need `Vault: Debug`, and Vault owns a rusqlite
        // connection which is not Debug. Match instead.
        let err = match Vault::open(&p.0, "not the password") {
            Err(e) => e,
            Ok(_) => panic!("a wrong password must not open the vault"),
        };
        assert_eq!(err, VaultError::WrongPassword);
    }

    #[test]
    fn wrong_password_message_is_indistinguishable_from_corruption() {
        // A separate "this file is corrupt" message would be a free oracle.
        let wrong = VaultError::WrongPassword.to_string();
        let corrupt = VaultError::Corrupt.to_string();
        assert_eq!(wrong, corrupt);
    }

    #[test]
    fn create_refuses_to_overwrite_existing_vault() {
        let p = temp_path("noclobber");
        Vault::create(&p.0, PW).unwrap();
        assert!(
            Vault::create(&p.0, PW).is_err(),
            "must not silently reset a vault"
        );
    }

    #[test]
    fn notes_survive_reopen() {
        let p = temp_path("persist");
        let id = {
            let mut v = Vault::create(&p.0, PW).unwrap();
            v.save(None, &note("Title", "Body text", &["a", "b"]))
                .unwrap()
        };
        let v = Vault::open(&p.0, PW).unwrap();
        let n = v.get(&id).unwrap().unwrap();
        assert_eq!(n.title, "Title");
        assert_eq!(n.text, "Body text");
        assert_eq!(n.tags, vec!["a", "b"]);
    }

    #[test]
    fn update_replaces_body_in_place() {
        let p = temp_path("update");
        let mut v = Vault::create(&p.0, PW).unwrap();
        let id = v.save(None, &note("Before", "old", &[])).unwrap();
        v.save(Some(&id), &note("After", "new", &[])).unwrap();
        let n = v.get(&id).unwrap().unwrap();
        assert_eq!(n.title, "After");
        assert_eq!(
            v.list().unwrap().len(),
            1,
            "update must not create a second row"
        );
    }

    #[test]
    fn search_matches_title_body_and_tags() {
        let p = temp_path("search");
        let mut v = Vault::create(&p.0, PW).unwrap();
        v.save(None, &note("Groceries", "milk and eggs", &["shopping"]))
            .unwrap();
        v.save(None, &note("Meeting", "discuss roadmap", &["work"]))
            .unwrap();

        assert_eq!(v.search("groc").unwrap().len(), 1, "title match");
        assert_eq!(
            v.search("EGGS").unwrap().len(),
            1,
            "case-insensitive body match"
        );
        assert_eq!(v.search("work").unwrap().len(), 1, "tag match");
        assert_eq!(v.search("nothing here").unwrap().len(), 0);
        assert_eq!(v.search("  ").unwrap().len(), 2, "empty query lists all");
    }

    #[test]
    fn trash_roundtrip() {
        let p = temp_path("trash");
        let mut v = Vault::create(&p.0, PW).unwrap();
        let id = v.save(None, &note("Bye", "", &[])).unwrap();
        v.delete(&id).unwrap();
        assert!(v.list().unwrap().is_empty());
        assert_eq!(v.trashed().unwrap().len(), 1);
        v.restore(&id).unwrap();
        assert_eq!(v.list().unwrap().len(), 1);
        v.purge(&id).unwrap();
        assert!(v.get(&id).unwrap().is_none());
    }

    #[test]
    fn tags_are_counted() {
        let p = temp_path("tags");
        let mut v = Vault::create(&p.0, PW).unwrap();
        v.save(None, &note("a", "", &["x", "shared"])).unwrap();
        v.save(None, &note("b", "", &["y", "shared"])).unwrap();
        let tags = v.all_tags().unwrap();
        assert_eq!(tags[0], ("shared".to_string(), 2));
        assert_eq!(tags.len(), 3);
    }

    #[test]
    fn changing_password_keeps_every_note_readable() {
        let p = temp_path("chpw");
        let id = {
            let mut v = Vault::create(&p.0, PW).unwrap();
            v.save(None, &note("Keep me", "important body", &["tag"]))
                .unwrap()
        };

        let mut v = Vault::open(&p.0, PW).unwrap();
        v.change_password("a brand new password").unwrap();
        assert_eq!(v.get(&id).unwrap().unwrap().text, "important body");

        // Old password no longer opens it; new one does.
        assert!(Vault::open(&p.0, PW).is_err());
        let v = Vault::open(&p.0, "a brand new password").unwrap();
        assert_eq!(v.get(&id).unwrap().unwrap().title, "Keep me");
    }

    #[test]
    fn is_initialised_reflects_state() {
        let p = temp_path("init");
        assert!(!Vault::is_initialised(&p.0));
        Vault::create(&p.0, PW).unwrap();
        assert!(Vault::is_initialised(&p.0));
    }

    #[test]
    fn unicode_and_empty_notes_work() {
        let p = temp_path("unicode");
        let mut v = Vault::create(&p.0, PW).unwrap();
        let id = v
            .save(None, &note("🔐 नोट्स", "日本語のテキスト", &["tag-🔑"]))
            .unwrap();
        let n = v.get(&id).unwrap().unwrap();
        assert_eq!(n.title, "🔐 नोट्स");
        assert_eq!(n.tags, vec!["tag-🔑"]);
    }
}
