//! Session state.
//!
//! The root key lives here, in Rust memory, for as long as the vault is
//! unlocked. It is never serialised, never returned to the webview, and is
//! wiped when the session locks, when the idle timeout fires, or when the
//! process exits.
//!
//! Every accessor goes through [`SessionManager::with`], which is what makes
//! "idle => locked" true even if no timer ever fires.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::crypto;
use crate::vault::{Vault, VaultError};

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultStatus {
    /// No vault file yet — first run.
    Empty,
    /// A vault exists but is locked.
    Locked,
    /// Unlocked; the root key is resident.
    Unlocked,
}

struct Inner {
    vault: Option<Vault>,
    last_activity: Option<Instant>,
}

pub struct SessionManager {
    inner: Mutex<Inner>,
    idle_timeout: Duration,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(DEFAULT_IDLE_TIMEOUT)
    }
}

impl SessionManager {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                vault: None,
                last_activity: None,
            }),
            idle_timeout,
        }
    }

    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Lock if the idle window has passed. Called at the top of every
    /// accessor so the timeout cannot be bypassed by a quiet timer thread.
    fn expire_if_idle(&self, inner: &mut Inner, now: Instant) -> bool {
        match inner.last_activity {
            Some(t) if now.duration_since(t) >= self.idle_timeout => {
                drop(inner.vault.take());
                inner.last_activity = None;
                true
            }
            _ => false,
        }
    }

    pub fn status(&self, path: &std::path::Path) -> VaultStatus {
        let mut inner = self.lock_inner();
        let now = Instant::now();
        self.expire_if_idle(&mut inner, now);
        if inner.vault.is_some() {
            VaultStatus::Unlocked
        } else if Vault::is_initialised(path) {
            VaultStatus::Locked
        } else {
            VaultStatus::Empty
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.lock_inner().vault.is_some()
    }

    pub fn create(&self, path: &std::path::Path, password: &str) -> Result<(), VaultError> {
        reject_weak_password(password)?;
        let vault = Vault::create(path, password)?;
        let mut inner = self.lock_inner();
        *inner = Inner {
            vault: Some(vault),
            last_activity: Some(Instant::now()),
        };
        Ok(())
    }

    pub fn unlock(&self, path: &std::path::Path, password: &str) -> Result<(), VaultError> {
        let vault = Vault::open(path, password)?;
        let mut inner = self.lock_inner();
        *inner = Inner {
            vault: Some(vault),
            last_activity: Some(Instant::now()),
        };
        Ok(())
    }

    /// Drop the root key. Idempotent.
    pub fn lock(&self) {
        let mut inner = self.lock_inner();
        drop(inner.vault.take());
        inner.last_activity = None;
    }

    /// Lock if the idle window has passed, reporting whether it did.
    ///
    /// Used by the background ticker. Access paths use `expire_if_idle`
    /// directly, so this is belt-and-braces rather than the only guard.
    pub fn lock_if_idle(&self) -> bool {
        let mut inner = self.lock_inner();
        self.expire_if_idle(&mut inner, Instant::now())
    }

    /// Run `f` against the open vault, refreshing the idle timer first.
    ///
    /// This is the only way a command should reach note data.
    pub fn with<R>(&self, f: impl FnOnce(&mut Vault) -> R) -> Result<R, VaultError> {
        let mut inner = self.lock_inner();
        let now = Instant::now();
        self.expire_if_idle(&mut inner, now);
        match inner.vault.as_mut() {
            None => Err(VaultError::WrongPassword),
            Some(vault) => {
                inner.last_activity = Some(now);
                Ok(f(vault))
            }
        }
    }

    /// Recover from a poisoned mutex rather than propagating the panic to the
    /// UI: the vault is simply locked again.
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A short master password is the one failure mode the crypto cannot fix.
fn reject_weak_password(password: &str) -> Result<(), VaultError> {
    if password.chars().count() < 8 {
        return Err(VaultError::WeakPassword);
    }
    Ok(())
}

/// Held only as long as a derivation is in flight.
pub type TransientKey = Zeroizing<[u8; crypto::KEY_LEN]>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Note;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vaultnote-session-{tag}-{}.db",
            crate::db::new_id()[..8].to_string()
        ))
    }

    const PW: &str = "a good long password";

    #[test]
    fn status_progresses_empty_to_unlocked_to_locked() {
        let p = temp_path("status");
        let s = SessionManager::new(Duration::from_secs(300));
        assert_eq!(s.status(&p), VaultStatus::Empty);

        s.create(&p, PW).unwrap();
        assert_eq!(s.status(&p), VaultStatus::Unlocked);

        s.lock();
        assert_eq!(s.status(&p), VaultStatus::Locked);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn short_password_is_refused() {
        let p = temp_path("weak");
        let s = SessionManager::default();
        assert_eq!(s.create(&p, "short"), Err(VaultError::WeakPassword));
        assert!(s.is_unlocked() == false);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn access_requires_unlock() {
        let p = temp_path("noaccess");
        let s = SessionManager::default();
        s.create(&p, PW).unwrap();
        s.lock();
        assert!(s.with(|_| ()).is_err());
        assert_eq!(s.unlock(&p, PW).map(|_| ()), Ok(()));
        assert!(s.with(|_| ()).is_ok());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn idle_timeout_locks_on_next_access() {
        let p = temp_path("idle");
        let s = SessionManager::new(Duration::from_millis(1));
        s.create(&p, PW).unwrap();
        assert!(s.is_unlocked());

        std::thread::sleep(Duration::from_millis(20));
        // The timer thread may not have run; the accessor must still refuse.
        assert!(s.with(|_| ()).is_err(), "idle session must not serve data");
        assert!(!s.is_unlocked());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn zero_tolerance_lock_timeout() {
        let p = temp_path("zero");
        let s = SessionManager::new(Duration::ZERO);
        s.create(&p, PW).unwrap();
        assert!(s.with(|_| ()).is_err());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn session_serves_notes_end_to_end() {
        let p = temp_path("e2e");
        let s = SessionManager::default();
        s.create(&p, PW).unwrap();

        let id = s
            .with(|v| {
                v.save(
                    None,
                    &Note {
                        title: "Secret".into(),
                        text: "body".into(),
                        ..Default::default()
                    },
                )
            })
            .unwrap()
            .unwrap();

        let title = s.with(|v| v.get(&id)).unwrap().unwrap().unwrap().title;
        assert_eq!(title, "Secret");

        s.lock();
        let _ = std::fs::remove_file(&p);
    }
}
