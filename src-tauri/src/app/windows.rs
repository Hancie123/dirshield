//! Window management: the main window, the small Explorer password prompt,
//! and routing Explorer context-menu actions between them.

use std::sync::atomic::Ordering;

use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use super::uninstall::UNINSTALL_MODE;
use super::AppState;
use crate::commands;
use crate::platform::shell::ShellAction;
use crate::security::auth;

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// The main window is small while signed out (fitted to the sign-in card;
/// `compact` is the size the page asks for) and full size once signed in.
pub fn apply_window_mode(w: &WebviewWindow, full: bool, compact: Option<(f64, f64)>) {
    use tauri::LogicalSize;
    if full {
        let _ = w.set_resizable(true);
        // The maximize button stays disabled in every mode.
        let _ = w.set_maximizable(false);
        let _ = w.set_min_size(Some(LogicalSize::new(760.0, 540.0)));
        let _ = w.set_size(LogicalSize::new(1120.0, 740.0));
    } else {
        let _ = w.unmaximize();
        let _ = w.set_min_size(None::<LogicalSize<f64>>);
        let (cw, ch) = compact.unwrap_or((480.0, 420.0));
        let _ = w.set_size(LogicalSize::new(cw.clamp(360.0, 720.0), ch.clamp(300.0, 760.0)));
        let _ = w.set_resizable(false);
        let _ = w.set_maximizable(false);
    }
    let _ = w.center();
}

/// Mica backdrop (Windows 11 build 22000+; Windows 10 gets an opaque
/// surface) and the saved theme, for any DirShield window.
pub fn style_window(window: &WebviewWindow, st: &AppState) {
    #[cfg(windows)]
    if crate::platform::shell::windows_build() >= 22000 {
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
///
/// Every menu entry asks for its password in that same small window. Actions
/// the window can't finish itself (Secure Lock, Settings, unlocking a Secure
/// Lock folder) sign DirShield in there and then continue in the main window;
/// if DirShield is already signed in they go straight to the main window.
pub fn is_prompt_action(st: &AppState, a: &ShellAction) -> bool {
    if auth::load_metadata(&st.db).ok().flatten().is_none() {
        return false; // first run: the main window shows setup
    }
    let signed_in = st.session.is_unlocked();
    match (a.action.as_str(), a.path.as_deref()) {
        // Quick Lock always confirms with a password, even when signed in.
        ("lock" | "quick-lock", Some(_)) => true,
        ("unlock" | "unhide", Some(p)) => !signed_in || commands::has_quick_record(st, p),
        ("secure-lock", Some(_)) | ("settings", _) => !signed_in,
        _ => false,
    }
}

/// Opens (or re-targets) the small password window for an Explorer action.
pub fn open_prompt(app: &AppHandle, action: ShellAction) {
    let st = app.state::<AppState>();
    *st.prompt.lock() = Some(action);
    if let Some(w) = app.get_webview_window("prompt") {
        let _ = app.emit_to("prompt", "prompt-action", ());
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let built = WebviewWindowBuilder::new(app, "prompt", WebviewUrl::App("index.html".into()))
        .title("DirShield")
        .inner_size(440.0, 350.0)
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
        Err(_) if UNINSTALL_MODE.load(Ordering::Relaxed) => std::process::exit(1),
        Err(_) => {
            // Fall back to the full app.
            let a = st.prompt.lock().take();
            *st.pending.lock() = a;
            show_main(app);
        }
    }
}

/// Routes an Explorer action to the prompt window or the main window.
pub fn route_action(app: &AppHandle, action: ShellAction) {
    let st = app.state::<AppState>();
    if is_prompt_action(&st, &action) {
        open_prompt(app, action);
    } else {
        let _ = app.emit_to("main", "shell-action", &action);
        show_main(app);
    }
}
