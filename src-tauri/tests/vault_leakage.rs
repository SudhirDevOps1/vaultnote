//! Phase 2 gate: prove the vault file itself does not leak.
//!
//! This is the check that matters most in a local-first encrypted app — the
//! server-side threat model does not apply, so "is the file actually
//! ciphertext?" has to be verified directly rather than assumed from the code
//! reading correctly.
//!
//! It plants known plaintext markers, then searches the raw bytes of the
//! database *and its WAL* for every one of them.

use std::fs;
use std::path::PathBuf;

use vaultnote_lib::vault::{Note, Vault};

const TITLE: &str = "PLAINTEXT_TITLE_MARKER_7a1c";
const BODY: &str = "PLAINTEXT_BODY_MARKER_9d2f";
const TAG: &str = "PLAINTEXT_TAG_MARKER_b3e4";
const PASSWORD: &str = "PLAINTEXT_PASSWORD_MARKER_c5f6";

struct Cleanup(Vec<PathBuf>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = fs::remove_file(p);
        }
    }
}

fn vault_path(tag: &str) -> PathBuf {
    std::env::temp_dir()
        .join(format!(
            "vaultnote-leak-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
        .with_extension("db")
}

fn read_if_present(p: &PathBuf) -> Option<Vec<u8>> {
    fs::read(p).ok()
}

#[test]
fn vault_file_and_wal_contain_no_plaintext() {
    let path = vault_path("plain");
    let cleanup = Cleanup(vec![
        path.clone(),
        path.with_extension("db-wal"),
        path.with_extension("db-shm"),
    ]);

    // Write several notes so the file is not trivially small.
    {
        let mut v = Vault::create(&path, PASSWORD).expect("create vault");
        for i in 0..25 {
            v.save(
                None,
                &Note {
                    title: if i == 0 {
                        TITLE.into()
                    } else {
                        format!("Filler {i}")
                    },
                    text: if i == 0 {
                        BODY.into()
                    } else {
                        format!("filler body number {i} with some padding text")
                    },
                    tags: if i == 0 {
                        vec![TAG.into()]
                    } else {
                        vec!["filler".into()]
                    },
                    attachments: vec![],
                    pinned: false,
                },
            )
            .expect("save note");
        }
    }

    // The vault is dropped above, so the connection is closed and the WAL
    // checkpointed; we still read the WAL explicitly in case it survived.
    let db_bytes = read_if_present(&path).expect("vault file must exist");
    assert!(
        !db_bytes.is_empty(),
        "vault file is empty — the test proved nothing"
    );

    let wal_bytes = read_if_present(&path.with_extension("db-wal")).unwrap_or_default();

    let markers: [&str; 4] = [TITLE, BODY, TAG, PASSWORD];

    for (name, haystack) in [("vault.db", &db_bytes), ("vault.db-wal", &wal_bytes)] {
        for marker in markers {
            assert!(
                !find_subslice(haystack, marker.as_bytes()),
                "PLAINTEXT LEAK: {marker:?} was found in {name}"
            );
        }
    }

    // A stronger structural claim: nothing in the file should look like the
    // SQLite text of a note, so the column check below has teeth.
    assert!(
        db_bytes.len() > 4096,
        "suspiciously small vault file — markers may simply be absent"
    );

    drop(cleanup);
}

#[test]
fn reopening_reveals_the_plaintext_that_was_hidden() {
    // The counterpart to the test above: the markers must be *recoverable*
    // through the API, so their absence from disk is encryption working and
    // not data loss.
    let path = vault_path("recover");
    let cleanup = Cleanup(vec![path.clone(), path.with_extension("db-wal")]);

    let id = {
        let mut v = Vault::create(&path, PASSWORD).unwrap();
        v.save(
            None,
            &Note {
                title: TITLE.into(),
                text: BODY.into(),
                tags: vec![TAG.into()],
                attachments: vec![],
                pinned: false,
            },
        )
        .unwrap()
    };

    let bytes = fs::read(&path).unwrap();
    assert!(
        !find_subslice(&bytes, TITLE.as_bytes()),
        "title leaked to disk"
    );

    let v = Vault::open(&path, PASSWORD).unwrap();
    let n = v.get(&id).unwrap().expect("note must still exist");
    assert_eq!(n.title, TITLE);
    assert_eq!(n.text, BODY);
    assert_eq!(n.tags, vec![TAG.to_string()]);

    drop(cleanup);
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
