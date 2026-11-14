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
pub mod foldericon;
pub mod fsutil;
pub mod ops;
pub mod quicklock;
pub mod search;
pub mod shell;
pub mod vault;
pub mod winsec;

use std::sync::atomic::Ordering;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent};

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Mica backdrop (Windows 11 build 22000+; Windows 10 gets an opaque
/// surface) and the saved theme, for any DirShield window.
fn style_window(window: &WebviewWindow, st: &app::AppState) {
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
}

/// Explorer actions answered by the small password window instead of the app.
fn is_prompt_action(st: &app::AppState, a: &shell::ShellAction) -> bool {
    matches!(a.action.as_str(), "lock" | "quick-lock" | "unlock" | "unhide") && a.path.is_some() && auth::load_metadata(&st.db).ok().flatten().is_some()
}

/// Opens (or re-targets) the small password window for an Explorer action.
fn open_prompt(app: &AppHandle, action: shell::ShellAction) {
    let st = app.state::<app::AppState>();
    *st.prompt.lock().unwrap() = Some(action);
    if let Some(w) = app.get_webview_window("prompt") {
        let _ = app.emit_to("prompt", "prompt-action", ());
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let built = WebviewWindowBuilder::new(app, "prompt", WebviewUrl::App("index.html".into()))
        .title("DirShield")
        .inner_size(440.0, 330.0)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .center()
        .always_on_top(true)
        .transparent(true)
        .focused(true)
        .build();
    match built {
        Ok(w) => style_window(&w, &st),
        Err(_) => {
            // Fall back to the full app.
            let a = st.prompt.lock().unwrap().take();
            *st.pending.lock().unwrap() = a;
            show_main(app);
        }
    }
}

/// Routes an Explorer action to the prompt window or the main window.
fn route_action(app: &AppHandle, action: shell::ShellAction) {
    let st = app.state::<app::AppState>();
    if is_prompt_action(&st, &action) {
        open_prompt(app, action);
    } else {
        let _ = app.emit_to("main", "shell-action", &action);
        show_main(app);
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
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| match shell::parse_args(argv.into_iter().skip(1)) {
            Some(action) => route_action(app, action),
            None => show_main(app),
        }))
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .setup(move |app| {
            let st = app.state::<app::AppState>();
            let window = app.get_webview_window("main").expect("main window");
            style_window(&window, &st);

            // The main window starts hidden: a right-click lock/unlock only
            // shows the small password window.
            let startup = st.pending.lock().unwrap().clone();
            match startup {
                Some(a) if is_prompt_action(&st, &a) => {
                    st.pending.lock().unwrap().take();
                    open_prompt(app.handle(), a);
                }
                _ => {
                    let _ = window.show();
                    if autostart {
                        let _ = window.minimize();
                    }
                }
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
        // Closing the prompt ends DirShield if it was only started for it.
        .on_window_event(|window, event| {
            if window.label() == "prompt" && matches!(event, WindowEvent::Destroyed) {
                let app = window.app_handle();
                app.state::<app::AppState>().prompt.lock().unwrap().take();
                let main_visible = app.get_webview_window("main").and_then(|w| w.is_visible().ok()).unwrap_or(false);
                if !main_visible {
                    app.exit(0);
                }
            }
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
            commands::prompt_info,
            commands::prompt_submit,
            commands::prompt_open_main,
            commands::prompt_close,
        ])
        .run(tauri::generate_context!())
        .expect("error while running DirShield");
}
