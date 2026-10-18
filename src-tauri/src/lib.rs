//! Vaultnote — local-first end-to-end encrypted notes.
//!
//! Security invariant (docs/2026-10-18-standard-notes-alternative-design.md §4):
//! the master key never crosses into the webview. Decryption happens in
//! `vault`, under `crypto`, holding `session`'s root key; only note plaintext
//! is returned over IPC. `commands` is the whole of that surface, and it has no
//! command that takes or returns key material.

pub mod commands;
pub mod crypto;
pub mod db;
pub mod session;
pub mod vault;

use tauri::{Emitter, Manager};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let manager = session::SessionManager::default();
    let tick = manager.idle_timeout() / 4;

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(manager)
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::create_vault,
            commands::unlock,
            commands::lock,
            commands::is_unlocked,
            commands::idle_timeout_seconds,
            commands::list_notes,
            commands::list_trashed,
            commands::get_note,
            commands::save_note,
            commands::delete_note,
            commands::restore_note,
            commands::purge_note,
            commands::search_notes,
            commands::list_tags,
            commands::change_password,
        ])
        .setup(move |app| {
            // Access paths already refuse an expired session; this ticker
            // exists so the key is also released while the app sits idle with
            // no traffic at all.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(tick).await;
                    let session = handle.state::<session::SessionManager>();
                    if session.lock_if_idle() {
                        let _ = handle.emit("vault-locked", ());
                    }
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window drops the session with the process.
            if let tauri::WindowEvent::Destroyed = event {
                window.state::<session::SessionManager>().lock();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
