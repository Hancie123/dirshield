//! The small password window opened from the Explorer context menu.

use super::*;

// ---------------- Explorer prompt window ----------------
//
// Right-click actions on a folder open a small password window instead of the
// full app. These commands verify the password themselves, so they work
// without signing in to the main window (and never sign it in).

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptVault {
    key_mode: String,
    hidden: bool,
    moved: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptInfo {
    action: String,
    path: String,
    name: String,
    /// The Quick Lock record for this folder, if it has one.
    vault: Option<PromptVault>,
    /// The prompt only signs in (master password) and the action continues
    /// in the main window.
    handoff: bool,
    /// Windows Hello can be used instead of the master password.
    hello: bool,
}

/// Actions the prompt only signs in for, finishing them in the main window:
/// Secure Lock and Settings; unlock/unhide of a folder that isn't
/// Quick-Locked (Secure Lock folders are restored there); and unlocking a
/// moved folder with its own password while DirShield is signed out. That
/// folder's original location is encrypted metadata, so the main window,
/// once signed in, asks where to put it back.
fn is_handoff(st: &AppState, action: &str, quick: Option<&(VaultRow, QuickState)>) -> bool {
    match action {
        "secure-lock" | "settings" => true,
        "unlock" => match quick {
            None => true,
            Some((r, q)) => r.key_mode == "password" && q.moved && !st.session.is_unlocked(),
        },
        "unhide" => quick.is_none(),
        _ => false,
    }
}

/// Quick-Locked folder at `path`. Its current location is stored in plain
/// form, so no key is needed to find it.
fn quick_row_at(st: &AppState, path: &str) -> Result<Option<(VaultRow, QuickState)>> {
    // A locked folder renamed in Explorer is found under its new name.
    sync_quick_locations(st, None);
    let key = fsutil::path_key(Path::new(path));
    for r in all_vaults(st)? {
        if r.mode != "quick" {
            continue;
        }
        if let Some(q) = r.quick.as_deref().and_then(|s| serde_json::from_str::<QuickState>(s).ok()) {
            if fsutil::path_key(Path::new(&q.current_path)) == key {
                return Ok(Some((r, q)));
            }
        }
    }
    Ok(None)
}

/// True if DirShield has a Quick Lock record for the folder at `path`.
pub(crate) fn has_quick_record(st: &AppState, path: &str) -> bool {
    matches!(quick_row_at(st, path), Ok(Some(_)))
}

/// The prompt's action and folder ("" for Settings, which has none).
fn prompt_action(st: &AppState) -> Result<(String, String)> {
    let a = st.prompt.lock().clone();
    match a {
        Some(ShellAction { action, path: Some(path) }) => Ok((action, path)),
        Some(ShellAction { action, path: None }) if action == "settings" => Ok((action, String::new())),
        _ => invalid("Nothing to do."),
    }
}

/// Signs DirShield in with an already verified master key, then hands the
/// prompt's action to the main window and closes the prompt.
fn handoff_to_main(app: &AppHandle, st: &AppState, mk: Key32) {
    st.session.unlock(mk);
    st.db.log("sign_in", None, "success", Some("explorer menu"));
    // The main window picks the action up after it sees the sign-in.
    *st.pending.lock() = st.prompt.lock().take();
    let _ = app.emit_to("main", "session-unlocked", ());
    crate::app::windows::show_main(app);
    if let Some(w) = app.get_webview_window("prompt") {
        let _ = w.close();
    }
    notify_relock_pending(app, st);
}

/// The prompt was opened by the uninstaller (`--confirm-uninstall`).
fn is_uninstall_prompt(st: &AppState) -> bool {
    crate::app::uninstall::UNINSTALL_MODE.load(std::sync::atomic::Ordering::Relaxed) && st.prompt.lock().as_ref().is_some_and(|a| a.action == "uninstall")
}

pub(super) fn folder_name(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string())
}

#[tauri::command]
pub async fn prompt_info(app: AppHandle) -> Result<PromptInfo> {
    run(&app, move |_, st| {
        if is_uninstall_prompt(st) {
            return Ok(PromptInfo { action: "uninstall".into(), path: String::new(), name: "DirShield".into(), vault: None, handoff: false, hello: false });
        }
        let hello = hello::available() && hello::is_enabled(&st.db);
        let (action, path) = prompt_action(st)?;
        if path.is_empty() {
            let handoff = is_handoff(st, &action, None);
            return Ok(PromptInfo { action, path, name: "DirShield".into(), vault: None, handoff, hello });
        }
        let quick = quick_row_at(st, &path)?;
        let handoff = is_handoff(st, &action, quick.as_ref());
        let vault = quick.map(|(r, q)| PromptVault { key_mode: r.key_mode, hidden: q.hidden, moved: q.moved });
        Ok(PromptInfo { action, name: folder_name(&path), path, vault, handoff, hello })
    })
    .await
}

/// Runs the prompt's action with the password the user typed: the master
/// password, or for unlock/unhide the folder's own password when it has one.
#[tauri::command]
pub async fn prompt_submit(app: AppHandle, password: String, use_hello: Option<bool>) -> Result<String> {
    let use_hello = use_hello.unwrap_or(false);
    run(&app, move |app, st| {
        let password = Zeroizing::new(password);
        let master = |st: &AppState| if use_hello { hello::unlock(&st.db) } else { verify_master(st, &password) };
        if is_uninstall_prompt(st) {
            verify_master(st, &password)?;
            crate::app::uninstall::UNINSTALL_CONFIRMED.store(true, std::sync::atomic::Ordering::Relaxed);
            st.db.log("uninstall_confirmed", None, "success", None);
            return Ok("Password confirmed. Uninstall will continue.".into());
        }
        let (action, path) = prompt_action(st)?;
        let name = folder_name(&path);
        // Actions finished in the main window: sign in here, continue there.
        let quick = if path.is_empty() { None } else { quick_row_at(st, &path)? };
        if is_handoff(st, &action, quick.as_ref()) {
            let mk = master(st)?;
            handoff_to_main(app, st, mk);
            return Ok("Opening DirShield…".into());
        }
        match action.as_str() {
            "lock" | "quick-lock" => {
                if quick_row_at(st, &path)?.is_some() {
                    return invalid("This folder is already locked.");
                }
                let mk = master(st)?;
                let hide = action == "quick-lock";
                quick_lock_impl(app, st, &mk, &path, None, hide)?;
                Ok(if hide { format!("\u{201c}{name}\u{201d} is locked and hidden.") } else { format!("\u{201c}{name}\u{201d} is locked.") })
            }
            "unlock" | "unhide" => {
                let (r, q) = quick_row_at(st, &path)?.ok_or_else(|| Error::NotFound("Quick Lock record for this folder".into()))?;
                let mk = if r.key_mode == "master" {
                    Some(master(st)?)
                } else if use_hello {
                    return invalid("This folder has its own password. Type it to unlock.");
                } else {
                    quick_verify(st, &r, &Credential { kind: "folder".into(), secret: password.to_string() })?;
                    st.session.master_active().ok()
                };
                if action == "unhide" {
                    quick_set_hidden_core(app, st, &r, false)?;
                    return Ok(format!("\u{201c}{name}\u{201d} is visible again. It stays locked."));
                }
                // The original location is encrypted metadata; for a folder
                // locked in place it is simply where the folder is now.
                let original = match &mk {
                    Some(mk) => PathBuf::from(info(st, mk, &r).original_path),
                    None if !q.moved => PathBuf::from(&q.current_path),
                    None => {
                        // Signed out since the prompt opened: the main window
                        // asks where to restore the folder once signed in.
                        open_main_with_action(app, st);
                        return Ok("Sign in to DirShield to choose where to restore this folder.".into());
                    }
                };
                quick_unlock_core(app, st, &r, &original, None)?;
                Ok(format!("\u{201c}{name}\u{201d} is unlocked."))
            }
            _ => invalid("This action needs the DirShield window."),
        }
    })
    .await
}

/// Hands the prompt's action to the main window, for cases the prompt can't
/// handle (Secure Lock folders, folders DirShield doesn't know).
#[tauri::command]
pub fn prompt_open_main(app: AppHandle, state: tauri::State<'_, AppState>) {
    open_main_with_action(&app, &state);
}

/// Moves the prompt's action to the main window (run there now if signed
/// in, otherwise after sign-in) and closes the prompt.
fn open_main_with_action(app: &AppHandle, st: &AppState) {
    if let Some(a) = st.prompt.lock().take() {
        if st.session.is_unlocked() {
            let _ = app.emit_to("main", "shell-action", &a);
        } else {
            *st.pending.lock() = Some(a);
        }
    }
    crate::app::windows::show_main(app);
    if let Some(w) = app.get_webview_window("prompt") {
        let _ = w.close();
    }
}

/// Main window size: compact while signed out, full once signed in.
#[tauri::command]
pub fn set_window_mode(app: AppHandle, full: bool, width: Option<f64>, height: Option<f64>) {
    if let Some(w) = app.get_webview_window("main") {
        crate::app::windows::apply_window_mode(&w, full, width.zip(height));
    }
}

#[tauri::command]
pub fn prompt_close(app: AppHandle) {
    if let Some(w) = app.get_webview_window("prompt") {
        let _ = w.close();
    }
}
