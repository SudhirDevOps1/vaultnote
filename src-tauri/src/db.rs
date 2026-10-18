//! Phase 2 — encrypted storage.
//!
//! Invariant: nothing but ciphertext, nonces, wrapped keys and timestamps ever
//! reach SQLite. Note titles, bodies and tags are encrypted *before* this
//! layer, so there is no plaintext column for them to leak through.
//!
//! `rusqlite` is used directly rather than a JS-side SQL plugin so that the
//! database never has to be handed to the webview in order to be read.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::crypto;

pub const SCHEMA_VERSION: &str = "1";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS items (
    id           TEXT    PRIMARY KEY,
    content_type TEXT    NOT NULL,
    nonce        BLOB    NOT NULL,
    wrapped_key  BLOB    NOT NULL,   -- nonce || ct || tag, see crypto::wrap_key
    ciphertext   BLOB    NOT NULL,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    deleted_at   INTEGER
);

CREATE TABLE IF NOT EXISTS attachments (
    id      TEXT PRIMARY KEY,
    item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    meta_ct BLOB NOT NULL,   -- encrypted {filename, mime, size}
    data_ct BLOB NOT NULL    -- encrypted file bytes
);

CREATE INDEX IF NOT EXISTS idx_items_alive   ON items(deleted_at);
CREATE INDEX IF NOT EXISTS idx_items_updated ON items(updated_at);
CREATE INDEX IF NOT EXISTS idx_attach_item   ON attachments(item_id);
"#;

#[derive(Debug)]
pub enum StoreError {
    Sql(rusqlite::Error),
    BadSalt,
}

/// Compares variants only. `rusqlite::Error` is not `PartialEq`, and the
/// inner error is deliberately not surfaced to callers anyway — equality here
/// only needs to answer "same failure class?".
impl PartialEq for StoreError {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Sql(_) => f.write_str("storage error"),
            StoreError::BadSalt => f.write_str("storage error"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sql(e)
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 64 hex characters of CSPRNG output. No `uuid` dependency needed.
pub fn new_id() -> String {
    let raw = crypto::generate_key();
    let mut s = String::with_capacity(64);
    for b in raw.iter() {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// One stored row. Every field here is safe to write to disk as-is.
#[derive(Debug, Clone)]
pub struct ItemRow {
    pub id: String,
    pub content_type: String,
    pub nonce: Vec<u8>,
    pub wrapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        // WAL keeps a crash mid-write from corrupting the whole vault.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    /// Open a throwaway in-memory store. Tests only.
    #[cfg(test)]
    pub fn open_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    fn migrate(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(SCHEMA)?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        match existing {
            None => {
                conn.execute(
                    "INSERT INTO meta(key, value) VALUES('schema_version', ?1)",
                    params![SCHEMA_VERSION],
                )?;
                conn.execute(
                    "INSERT INTO meta(key, value) VALUES('created_at', ?1)",
                    params![now_ms().to_string()],
                )?;
            }
            Some(v) if v != SCHEMA_VERSION => {
                // Single-version schema for now. A real migration chain lands
                // with the first breaking change, not before it is needed.
                return Err(StoreError::BadSalt);
            }
            Some(_) => {}
        }
        Ok(())
    }

    // -- meta ---------------------------------------------------------------

    pub fn get_meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// The Argon2id salt. Stored in the clear on purpose: a salt is not a
    /// secret, and hiding it would buy nothing.
    pub fn get_salt(&self) -> Result<Option<[u8; crypto::SALT_LEN]>, StoreError> {
        match self.get_meta("argon2_salt")? {
            None => Ok(None),
            Some(hex) => {
                let bytes = hex_decode(&hex).ok_or(StoreError::BadSalt)?;
                if bytes.len() != crypto::SALT_LEN {
                    return Err(StoreError::BadSalt);
                }
                let mut salt = [0u8; crypto::SALT_LEN];
                salt.copy_from_slice(&bytes);
                Ok(Some(salt))
            }
        }
    }

    pub fn set_salt(&self, salt: &[u8; crypto::SALT_LEN]) -> Result<(), StoreError> {
        self.set_meta("argon2_salt", &hex_encode(salt))
    }

    // -- items --------------------------------------------------------------

    /// Insert a new encrypted item.
    pub fn insert_item(&mut self, row: &ItemRow) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO items
                (id, content_type, nonce, wrapped_key, ciphertext, created_at, updated_at, deleted_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                row.id,
                row.content_type,
                row.nonce,
                row.wrapped_key,
                row.ciphertext,
                row.created_at,
                row.updated_at,
                row.deleted_at,
            ],
        )?;
        Ok(())
    }

    /// Replace only the wrapped key of one item, leaving the note body alone.
    /// This is the sole storage operation a password change needs.
    pub fn set_wrapped_key(&self, id: &str, wrapped: &[u8]) -> Result<usize, StoreError> {
        self.conn
            .execute(
                "UPDATE items SET wrapped_key = ?2 WHERE id = ?1",
                params![id, wrapped],
            )
            .map_err(StoreError::from)
    }

    /// Overwrite the ciphertext of an existing item. The id and created_at are
    /// never rewritten, so ordering and identity survive an edit.
    pub fn update_item(
        &mut self,
        id: &str,
        nonce: &[u8],
        wrapped_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<usize, StoreError> {
        self.conn
            .execute(
                "UPDATE items
                 SET nonce = ?2, wrapped_key = ?3, ciphertext = ?4, updated_at = ?5
                 WHERE id = ?1",
                params![id, nonce, wrapped_key, ciphertext, now_ms()],
            )
            .map_err(StoreError::from)
    }

    pub fn get_item(&self, id: &str) -> Result<Option<ItemRow>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, content_type, nonce, wrapped_key, ciphertext, created_at, updated_at, deleted_at
                 FROM items WHERE id = ?1",
                params![id],
                row_to_item,
            )
            .optional()?)
    }

    /// Live items, newest first. Trashed items are excluded.
    pub fn list_items(&self) -> Result<Vec<ItemRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content_type, nonce, wrapped_key, ciphertext, created_at, updated_at, deleted_at
             FROM items WHERE deleted_at IS NULL ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_item)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_trashed(&self) -> Result<Vec<ItemRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content_type, nonce, wrapped_key, ciphertext, created_at, updated_at, deleted_at
             FROM items WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_item)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn soft_delete(&self, id: &str) -> Result<usize, StoreError> {
        let ts = now_ms();
        self.conn
            .execute(
                "UPDATE items SET deleted_at = ?2, updated_at = ?2 WHERE id = ?1",
                params![id, ts],
            )
            .map_err(StoreError::from)
    }

    pub fn restore(&self, id: &str) -> Result<usize, StoreError> {
        self.conn
            .execute(
                "UPDATE items SET deleted_at = NULL, updated_at = ?2 WHERE id = ?1",
                params![id, now_ms()],
            )
            .map_err(StoreError::from)
    }

    pub fn purge(&self, id: &str) -> Result<usize, StoreError> {
        self.conn
            .execute("DELETE FROM items WHERE id = ?1", params![id])
            .map_err(StoreError::from)
    }

    pub fn count_items(&self, include_trashed: bool) -> Result<i64, StoreError> {
        let sql = if include_trashed {
            "SELECT COUNT(*) FROM items"
        } else {
            "SELECT COUNT(*) FROM items WHERE deleted_at IS NULL"
        };
        Ok(self.conn.query_row(sql, [], |r| r.get(0))?)
    }

    /// Every `wrapped_key` in the vault. Used by the password-change flow,
    /// which must re-wrap every key without touching a single note body.
    pub fn all_wrapped_keys(&self) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, wrapped_key FROM items ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }
}

fn row_to_item(r: &rusqlite::Row<'_>) -> rusqlite::Result<ItemRow> {
    Ok(ItemRow {
        id: r.get(0)?,
        content_type: r.get(1)?,
        nonce: r.get(2)?,
        wrapped_key: r.get(3)?,
        ciphertext: r.get(4)?,
        created_at: r.get(5)?,
        updated_at: r.get(6)?,
        deleted_at: r.get(7)?,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_row(id: &str) -> ItemRow {
        ItemRow {
            id: id.to_string(),
            content_type: "note".into(),
            nonce: vec![1u8; crypto::NONCE_LEN],
            wrapped_key: vec![2u8; crypto::WRAP_LEN],
            ciphertext: vec![3u8; 64],
            created_at: 1000,
            updated_at: 1000,
            deleted_at: None,
        }
    }

    #[test]
    fn ids_are_unique_and_hex() {
        let a = new_id();
        let b = new_id();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hex_roundtrip() {
        let salt = [0xABu8; crypto::SALT_LEN];
        assert_eq!(hex_decode(&hex_encode(&salt)).unwrap(), salt.to_vec());
    }

    #[test]
    fn odd_length_hex_is_rejected() {
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn open_creates_schema_and_version() {
        let s = Store::open_memory().unwrap();
        assert_eq!(
            s.get_meta("schema_version").unwrap().as_deref(),
            Some(SCHEMA_VERSION)
        );
        assert!(s.get_meta("created_at").unwrap().is_some());
    }

    #[test]
    fn salt_roundtrip() {
        let s = Store::open_memory().unwrap();
        assert!(s.get_salt().unwrap().is_none());
        let salt = [9u8; crypto::SALT_LEN];
        s.set_salt(&salt).unwrap();
        assert_eq!(s.get_salt().unwrap(), Some(salt));
    }

    #[test]
    fn insert_and_read_back() {
        let mut s = Store::open_memory().unwrap();
        s.insert_item(&dummy_row("a")).unwrap();
        let got = s.get_item("a").unwrap().unwrap();
        assert_eq!(got.content_type, "note");
        assert_eq!(got.ciphertext, vec![3u8; 64]);
    }

    #[test]
    fn update_replaces_ciphertext_and_keeps_identity() {
        let mut s = Store::open_memory().unwrap();
        s.insert_item(&dummy_row("a")).unwrap();
        let n = s
            .update_item(
                "a",
                &[7u8; crypto::NONCE_LEN],
                &[8u8; crypto::WRAP_LEN],
                &[9u8; 10],
            )
            .unwrap();
        assert_eq!(n, 1);
        let got = s.get_item("a").unwrap().unwrap();
        assert_eq!(got.ciphertext, vec![9u8; 10]);
        assert_eq!(got.created_at, 1000, "created_at must not move on edit");
        assert!(got.updated_at >= 1000);
    }

    #[test]
    fn delete_is_soft_then_hard() {
        let mut s = Store::open_memory().unwrap();
        s.insert_item(&dummy_row("a")).unwrap();
        assert_eq!(s.count_items(false).unwrap(), 1);

        s.soft_delete("a").unwrap();
        assert_eq!(s.count_items(false).unwrap(), 0, "trashed item is not live");
        assert_eq!(s.count_items(true).unwrap(), 1, "but it still exists");
        assert!(s.get_item("a").unwrap().unwrap().deleted_at.is_some());

        s.restore("a").unwrap();
        assert_eq!(s.count_items(false).unwrap(), 1);

        s.purge("a").unwrap();
        assert_eq!(s.count_items(true).unwrap(), 0);
        assert!(s.get_item("a").unwrap().is_none());
    }

    #[test]
    fn list_excludes_trashed_and_sorts_by_recency() {
        let mut s = Store::open_memory().unwrap();
        let mut old = dummy_row("old");
        old.updated_at = 1;
        let mut new = dummy_row("new");
        new.updated_at = 9_999;
        s.insert_item(&old).unwrap();
        s.insert_item(&new).unwrap();
        s.soft_delete("new").unwrap();

        let live = s.list_items().unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, "old");
        assert_eq!(s.list_trashed().unwrap()[0].id, "new");
    }

    #[test]
    fn all_wrapped_keys_covers_every_item() {
        let mut s = Store::open_memory().unwrap();
        for id in ["a", "b", "c"] {
            s.insert_item(&dummy_row(id)).unwrap();
        }
        let keys = s.all_wrapped_keys().unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.iter().all(|(_, k)| k.len() == crypto::WRAP_LEN));
    }

    #[test]
    fn schema_has_no_plaintext_column_for_note_content() {
        // The table must not grow a column that could hold a readable title.
        let s = Store::open_memory().unwrap();
        let mut stmt = s
            .conn
            .prepare("SELECT name FROM pragma_table_info('items')")
            .unwrap();
        let cols: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for col in cols {
            assert!(
                !["title", "text", "body", "tags", "note", "content"].contains(&col.as_str()),
                "unexpected plaintext column: {col}"
            );
        }
    }
}
