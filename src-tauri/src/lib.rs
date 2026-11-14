//! DirShield – Windows folder locker.
//!
//! Module map:
//! * `crypto`    – primitives composition (AES-GCM, Argon2id, HKDF, X25519 escrow)
//! * `auth`      – master password / recovery key / session / rate limiting
//! * `vault`     – Secure Lock format + journaled engine
//! * `quicklock` – Quick Lock (move + attributes + ACL), `winsec` ACL code
//! * `search`    – Windows Search privacy measures
//! * `shell`     – Explorer context menu, autostart, accent colour
//! * `ops`       – background operation manager
//! * `commands`  – Tauri command surface

pub mod app;
pub mod auth;
pub mod commands;
pub mod crypto;
pub mod db;
pub mod error;
pub mod fsutil;
pub mod ops;
pub mod quicklock;
pub mod search;
pub mod shell;
pub mod vault;
pub mod winsec;

use std::sync::atomic::Ordering;
use std::time::Duration;

use tauri::{Emitter, Manager};

fn focus_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

pub fn run() {
    let state = match app::AppState::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("DirShield failed to start: {e}");
            std::process::exit(1);
        }
    };
    *state.pending.lock().unwrap() = shell::parse_args(std::env::args().skip(1));
    let autostart = std::env::args().any(|a| a == "--autostart");

    tauri::Builder::default()
        // Explorer menu invocations while DirShield is running are forwarded
        // to the existing instance (one process owns the database).
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if let Some(action) = shell::parse_args(argv.into_iter().skip(1)) {
                let _ = app.emit("shell-action", &action);
            }
            focus_main(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .setup(move |app| {
            let st = app.state::<app::AppState>();
            let window = app.get_webview_window("main").expect("main window");

            // Windows 11 Mica backdrop (build 22000+). Windows 10 falls back to an opaque surface.
            #[cfg(windows)]
            if shell::windows_build() >= 22000 {
                use tauri::window::{Effect, EffectsBuilder};
                if window.set_effects(EffectsBuilder::new().effect(Effect::Mica).build()).is_ok() {
                    st.mica.store(true, Ordering::Relaxed);
                }
            }
            let theme = st.db.get_setting("theme").ok().flatten().unwrap_or_default();
            let _ = window.set_theme(match theme.as_str() {
                "light" => Some(tauri::Theme::Light),
                "dark" => Some(tauri::Theme::Dark),
                _ => None,
            });
            if autostart {
                let _ = window.minimize();
            }

            st.ops.start_ticker(app.handle().clone(), st.db.clone());

            // Auto-lock after inactivity. Running operations keep their own key
            // copies so they continue, but the UI requires sign-in again.
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(5));
                let st = handle.state::<app::AppState>();
                if st.session.expire_if_idle() {
                    st.db.log("auto_lock", None, "info", None);
                    let _ = handle.emit("session-locked", ());
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::setup_master,
            commands::login,
            commands::logout,
            commands::touch,
            commands::change_master_password,
            commands::reset_master_password,
            commands::scan_folder,
            commands::free_space,
            commands::list_vaults,
            commands::find_by_path,
            commands::vault_details,
            commands::quick_lock,
            commands::quick_unlock,
            commands::quick_set_hidden,
            commands::secure_lock,
            commands::restore_vault,
            commands::verify_vault,
            commands::remove_originals,
            commands::delete_vault,
            commands::change_folder_password,
            commands::import_vault,
            commands::find_orphans,
            commands::recover_orphan,
            commands::list_operations,
            commands::op_errors,
            commands::op_pause,
            commands::op_cancel,
            commands::op_resume,
            commands::op_discard,
            commands::clear_finished_operations,
            commands::list_activity,
            commands::clear_activity,
            commands::get_settings,
            commands::save_settings,
            commands::take_pending_action,
            commands::open_in_explorer,
        ])
        .run(tauri::generate_context!())
        .expect("error while running DirShield");
}
