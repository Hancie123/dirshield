//! Notification-area icon: open, Lock all, Sign out, Quit.

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

use super::windows::show_main;
use super::AppState;
use crate::commands;

pub fn build(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open DirShield", true, None::<&str>)?;
    let lock_all = MenuItem::with_id(app, "lock_all", "Lock all folders", true, None::<&str>)?;
    let sign_out = MenuItem::with_id(app, "sign_out", "Sign out", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit DirShield", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &lock_all, &sign_out, &sep, &quit])?;
    let mut tray = TrayIconBuilder::with_id("dirshield")
        .tooltip("DirShield")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, e| {
            let app = app.clone();
            match e.id().as_ref() {
                "open" => show_main(&app),
                // Off the UI thread: these touch the disk and the database.
                "lock_all" => {
                    std::thread::spawn(move || {
                        let msg = match commands::lock_all(&app) {
                            Ok(r) => {
                                let mut m = format!("{} folder(s) hidden, {} being locked again.", r.hidden, r.relocking);
                                if !r.skipped.is_empty() {
                                    m.push_str(&format!(" Not locked: {}.", r.skipped.join(", ")));
                                }
                                m
                            }
                            Err(e) => e.to_string(),
                        };
                        commands::notify(&app, "DirShield: Lock all", &msg);
                    });
                }
                "sign_out" => {
                    std::thread::spawn(move || commands::sign_out(&app, "tray"));
                }
                "quit" => {
                    if app.state::<AppState>().ops.any_active() {
                        commands::notify(&app, "DirShield is still working", "Wait for the running operations to finish, or cancel them, before quitting.");
                        show_main(&app);
                    } else {
                        app.exit(0);
                    }
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, e| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}
