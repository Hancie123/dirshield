//! DirShield – Windows folder locker.
//!
//! Module map:
//! * `app`       – application shell: state, windows, tray, background operations
//! * `commands`  – Tauri command surface (the only API the frontend can call)
//! * `domain`    – error type and the typed values shared across layers
//! * `security`  – cryptography, master password, session, rate limiting, Windows Hello
//! * `storage`   – SQLite database and encrypted backups
//! * `vault`     – Secure Lock: on-disk format and the journaled engine
//! * `quicklock` – Quick Lock: move, attributes, NTFS access restriction
//! * `platform`  – Windows integration: file system, Explorer menu, Search, session events

// Command/worker entry points pass many owned values into background threads;
// grouping them into ad-hoc structs would not make the code clearer.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

pub mod app;
pub mod commands;
pub mod domain;
pub mod platform;
pub mod quicklock;
pub mod security;
pub mod storage;
pub mod vault;

use std::sync::atomic::Ordering;
use std::time::Duration;

use tauri::{Emitter, Manager, WindowEvent};

use app::uninstall::{CONFIRM_UNINSTALL_ARG, UNINSTALL_CONFIRMED, UNINSTALL_MODE};
use app::windows::{is_prompt_action, open_prompt, route_action, show_main, style_window};
use app::AppState;
use platform::{session_events, shell};
use security::auth;

pub fn run() {
    let uninstall = std::env::args().any(|a| a == CONFIRM_UNINSTALL_ARG);
    UNINSTALL_MODE.store(uninstall, Ordering::Relaxed);
    let state = match AppState::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("DirShield failed to start: {e}");
            // Without a readable database there is no password to ask for.
            std::process::exit(if uninstall { 0 } else { 1 });
        }
    };
    if uninstall && !matches!(auth::load_metadata(&state.db), Ok(Some(_))) {
        // No master password set up yet: nothing to confirm.
        std::process::exit(0);
    }
    if !uninstall {
        *state.pending.lock() = shell::parse_args(std::env::args().skip(1));
    }
    let autostart = std::env::args().any(|a| a == "--autostart");

    let mut builder = tauri::Builder::default();
    if !uninstall {
        // Explorer menu invocations while DirShield is running are forwarded
        // to the existing instance (one process owns the database). The
        // uninstall check must not be forwarded: it needs its own exit code.
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| match shell::parse_args(argv.into_iter().skip(1)) {
            Some(action) => route_action(app, action),
            None => show_main(app),
        }));
    }
    builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_notification::init())
        .manage(state)
        .setup(move |app| {
            let st = app.state::<AppState>();
            let window = app.get_webview_window("main").expect("main window");
            style_window(&window, &st);

            if uninstall {
                open_prompt(app.handle(), shell::ShellAction { action: "uninstall".into(), path: None });
                return Ok(());
            }

            // The main window starts hidden: a right-click lock/unlock only
            // shows the small password window.
            let startup = st.pending.lock().clone();
            match startup {
                Some(a) if is_prompt_action(&st, &a) => {
                    st.pending.lock().take();
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
            let _ = app::tray::build(app);

            // Sign out when Windows locks, signs out or goes to sleep.
            let handle = app.handle().clone();
            session_events::watch(move |event| commands::on_system_event(&handle, event));

            // Auto-lock after inactivity. Running operations keep their own key
            // copies so they continue, but the UI requires sign-in again.
            // Work sessions are not ended here: being idle in DirShield says
            // nothing about whether the restored folder is still in use.
            // Once a minute, the background task (log seal, deferred header
            // updates, scheduled integrity checks).
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let mut ticks: u32 = 0;
                loop {
                    std::thread::sleep(Duration::from_secs(5));
                    let st = handle.state::<AppState>();
                    if st.session.expire_if_idle() {
                        st.close_all_browsers();
                        st.db.log("auto_lock", None, "info", None);
                        let _ = handle.emit("session-locked", ());
                    }
                    ticks += 1;
                    if ticks % 12 == 1 {
                        commands::background_tick(&handle);
                    }
                }
            });
            Ok(())
        })
        // Closing the prompt ends DirShield if it was only started for it.
        .on_window_event(|window, event| {
            if window.label() == "prompt" && matches!(event, WindowEvent::Destroyed) {
                let app = window.app_handle();
                app.state::<AppState>().prompt.lock().take();
                if UNINSTALL_MODE.load(Ordering::Relaxed) {
                    std::process::exit(if UNINSTALL_CONFIRMED.load(Ordering::Relaxed) { 0 } else { 1 });
                }
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
            commands::login_hello,
            commands::hello_enable,
            commands::hello_disable,
            commands::logout,
            commands::touch,
            commands::password_strength,
            commands::change_master_password,
            commands::reset_master_password,
            commands::recovery_rotate_begin,
            commands::recovery_rotate_commit,
            commands::recovery_rotate_cancel,
            commands::set_portable_vaults,
            commands::backup_create,
            commands::backup_restore,
            commands::work_session_end,
            commands::work_session_keep,
            commands::lock_all_folders,
            commands::verify_activity_log,
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
            commands::relock_vault,
            commands::browse_open,
            commands::browse_list,
            commands::browse_extract,
            commands::browse_open_file,
            commands::browse_close,
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
            commands::set_window_mode,
        ])
        .build(tauri::generate_context!())
        .expect("error while running DirShield")
        .run(|app, event| {
            // Files opened from a vault don't outlive DirShield.
            if let tauri::RunEvent::Exit = event {
                app.state::<AppState>().close_all_browsers();
            }
        });
}
