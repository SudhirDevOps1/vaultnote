//! The IPC surface — the complete list of things the webview can ask for.
//!
//! Notice what is *not* here: no command takes or returns key material. The
//! webview can ask for plaintext notes; it can never ask for the root key, a
//! data key, or a wrapped key.

use std::path::PathBuf;

use tauri::{AppHandle, Manager, State};

use crate::session::{SessionManager, VaultStatus};
use crate::vault::{Note, NoteSummary, VaultError};

/// `<app data dir>/vault.db` — beside the app, never in a synced folder.
fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("cannot locate app data directory: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create app data directory: {e}"))?;
    Ok(dir.join("vault.db"))
}

fn err(e: VaultError) -> String {
    e.to_string()
}

#[tauri::command]
pub fn vault_status(app: AppHandle, session: State<'_, SessionManager>) -> VaultStatus {
    match vault_path(&app) {
        Ok(p) => session.status(&p),
        Err(_) => VaultStatus::Empty,
    }
}

#[tauri::command]
pub fn create_vault(
    app: AppHandle,
    session: State<'_, SessionManager>,
    password: String,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    session.create(&path, &password).map_err(err)
}

#[tauri::command]
pub fn unlock(
    app: AppHandle,
    session: State<'_, SessionManager>,
    password: String,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    session.unlock(&path, &password).map_err(err)
}

#[tauri::command]
pub fn lock(session: State<'_, SessionManager>) {
    session.lock();
}

#[tauri::command]
pub fn is_unlocked(session: State<'_, SessionManager>) -> bool {
    session.is_unlocked()
}

#[tauri::command]
pub fn idle_timeout_seconds(session: State<'_, SessionManager>) -> u64 {
    session.idle_timeout().as_secs()
}

#[tauri::command]
pub fn list_notes(session: State<'_, SessionManager>) -> Result<Vec<NoteSummary>, String> {
    session.with(|v| v.list()).map_err(err)
}

#[tauri::command]
pub fn list_trashed(session: State<'_, SessionManager>) -> Result<Vec<NoteSummary>, String> {
    session.with(|v| v.trashed()).map_err(err)
}

#[tauri::command]
pub fn get_note(session: State<'_, SessionManager>, id: String) -> Result<Option<Note>, String> {
    session.with(|v| v.get(&id)).map_err(err)
}

#[tauri::command]
pub fn save_note(
    session: State<'_, SessionManager>,
    id: Option<String>,
    note: Note,
) -> Result<String, String> {
    session.with(|v| v.save(id.as_deref(), &note)).map_err(err)
}

#[tauri::command]
pub fn delete_note(session: State<'_, SessionManager>, id: String) -> Result<(), String> {
    session.with(|v| v.delete(&id)).map_err(err)
}

#[tauri::command]
pub fn restore_note(session: State<'_, SessionManager>, id: String) -> Result<(), String> {
    session.with(|v| v.restore(&id)).map_err(err)
}

#[tauri::command]
pub fn purge_note(session: State<'_, SessionManager>, id: String) -> Result<(), String> {
    session.with(|v| v.purge(&id)).map_err(err)
}

#[tauri::command]
pub fn search_notes(
    session: State<'_, SessionManager>,
    query: String,
) -> Result<Vec<NoteSummary>, String> {
    session.with(|v| v.search(&query)).map_err(err)
}

#[tauri::command]
pub fn list_tags(session: State<'_, SessionManager>) -> Result<Vec<(String, usize)>, String> {
    session.with(|v| v.all_tags()).map_err(err)
}

#[tauri::command]
pub fn change_password(
    session: State<'_, SessionManager>,
    new_password: String,
) -> Result<(), String> {
    if new_password.chars().count() < 8 {
        return Err("password must be at least 8 characters".into());
    }
    session.with(|v| v.change_password(&new_password)).map_err(err)
}