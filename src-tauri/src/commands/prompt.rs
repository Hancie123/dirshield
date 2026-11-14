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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptInfo {
    action: String,
    path: String,
    name: String,
    /// The Quick Lock record for this folder, if it has one.
    vault: Option<PromptVault>,
}

/// Quick-Locked folder at `path`. Its current location is stored in plain
/// form, so no key is needed to find it.
fn quick_row_at(st: &AppState, path: &str) -> Result<Option<(VaultRow, QuickState)>> {
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
            return Ok(PromptInfo { action: "uninstall".into(), path: String::new(), name: "DirShield".into(), vault: None });
        }
        let (action, path) = prompt_action(st)?;
        if path.is_empty() {
            return Ok(PromptInfo { action, path, name: "DirShield".into(), vault: None });
        }
        let vault = quick_row_at(st, &path)?.map(|(r, q)| PromptVault { key_mode: r.key_mode, hidden: q.hidden });
        Ok(PromptInfo { action, name: folder_name(&path), path, vault })
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
        let handoff = match action.as_str() {
            "secure-lock" | "settings" => true,
            "unlock" | "unhide" => quick.is_none(),
            _ => false,
        };
        if handoff {
            let mk = verify_master(st, &password)?;
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
                    None => return invalid("Sign in to DirShield to restore this folder."),
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
    if let Some(a) = state.prompt.lock().take() {
        if state.session.is_unlocked() {
            let _ = app.emit_to("main", "shell-action", &a);
        } else {
            *state.pending.lock() = Some(a);
        }
    }
    crate::app::windows::show_main(&app);
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
