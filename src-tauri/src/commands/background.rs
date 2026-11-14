//! Work done without a command from the window: signing out when Windows
//! locks or sleeps, ending work sessions, "Lock all" from the tray, and the
//! periodic task (log sealing, deferred header updates, scheduled integrity
//! checks).

use tauri_plugin_notification::NotificationExt;

use super::*;

/// Signs DirShield out: ends every work session (their folders are locked
/// again in the background), then drops the master key and every open vault
/// browser. `reason` is recorded in the activity log.
pub fn sign_out(app: &AppHandle, reason: &str) {
    let st = app.state::<AppState>();
    // The key goes first: before sleep there may be little time left.
    let was_unlocked = st.session.is_unlocked();
    st.lock_session();
    if was_unlocked {
        st.db.log("sign_out", None, "info", Some(reason));
    }
    let _ = app.emit("session-locked", ());
    // Work sessions hold their own vault keys; locking their folders again
    // scans them first, so that runs off this thread.
    if !st.work.lock().is_empty() {
        let app = app.clone();
        std::thread::spawn(move || {
            let st = app.state::<AppState>();
            end_all_work_sessions(&app, &st);
        });
    }
}

/// Windows locked, the user signed out of Windows, or the PC is going to sleep.
pub fn on_system_event(app: &AppHandle, event: &str) {
    let st = app.state::<AppState>();
    if st.db.get_setting("signOutOnLock").ok().flatten().as_deref() == Some("false") {
        return;
    }
    if st.session.is_unlocked() || !st.work.lock().is_empty() {
        sign_out(app, event);
    }
}

// ---------------------------------------------------------------------------
// Work sessions and "Lock all"
// ---------------------------------------------------------------------------

/// Locks a restored folder again and removes the unlocked copy (see
/// `spawn_relock` with cleanup). Returns the operation id.
fn relock_and_clean(app: &AppHandle, st: &AppState, r: &VaultRow, ws: WorkSession) -> Result<String> {
    if r.status != "restored" {
        return invalid("This folder isn't restored.");
    }
    if st.ops.is_vault_busy(&r.id) {
        return Err(Error::Conflict("An operation is already running for this folder.".into()));
    }
    if !ws.source.is_dir() {
        return Err(Error::NotFound(format!("restored folder {}", ws.source.display())));
    }
    if is_same_or_inside(Path::new(&r.vault_path), &ws.source) {
        return invalid("The vault is stored inside this folder.");
    }
    close_browsers_for(st, &r.id);
    let p = RelockParams { source: fsutil::display_path(&ws.source), thorough: false, prev_status: r.status.clone(), ..Default::default() };
    let op_id = engine::create_relock(&st.db, &r.id, Path::new(&r.vault_path), &ws.vk, p, &engine::Control::default())?;
    st.db.lock().execute("UPDATE vaults SET name=?2, original_path=?3, updated_at=?4 WHERE id=?1", params![r.id, ws.name_enc, ws.path_enc, now_ms()])?;
    let (tf, tb): (i64, i64) = st.db.lock().query_row("SELECT total_files, total_bytes FROM operations WHERE id=?1", [&op_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    spawn_relock(app, st, op_id.clone(), r.id.clone(), PathBuf::from(&r.vault_path), ws.source, ws.name, ws.vk, tf as u64, tb as u64, true)?;
    // The re-lock is now a resumable operation of its own.
    let _ = st.db.delete_setting(&work_pending_key(&r.id));
    Ok(op_id)
}

/// Ends one work session. A session whose folder is busy stays open and is
/// retried at the next sign-out.
fn end_work_session(app: &AppHandle, st: &AppState, id: &str) -> Result<Option<String>> {
    let Some(ws) = st.work.lock().remove(id) else { return Ok(None) };
    let r = match load_vault(st, id) {
        Ok(r) if r.status == "restored" => r,
        _ => {
            // Re-locked or removed some other way.
            let _ = st.db.delete_setting(&work_pending_key(id));
            return Ok(None);
        }
    };
    if st.ops.is_vault_busy(id) {
        st.work.lock().insert(id.to_string(), ws);
        return Err(Error::Conflict("An operation is running for this folder. It will be locked at the next sign-out.".into()));
    }
    match relock_and_clean(app, st, &r, ws) {
        Ok(op) => {
            st.db.log("work_session_end", Some(id), "info", None);
            Ok(Some(op))
        }
        Err(e) => {
            st.db.log("work_session_end", Some(id), "failed", Some(&e.to_string()));
            Err(e)
        }
    }
}

pub(super) fn end_all_work_sessions(app: &AppHandle, st: &AppState) -> u32 {
    let ids: Vec<String> = st.work.lock().keys().cloned().collect();
    let mut started = 0;
    for id in ids {
        if let Ok(Some(_)) = end_work_session(app, st, &id) {
            started += 1;
        }
    }
    if started > 0 {
        emit_vaults_changed(app);
    }
    started
}

/// Ends a work session now: the folder is encrypted again and the unlocked copy removed.
#[tauri::command]
pub async fn work_session_end(app: AppHandle, id: String) -> Result<Option<String>> {
    run(&app, move |app, st| {
        st.session.master_active()?;
        let r = end_work_session(app, st, &id);
        emit_vaults_changed(app);
        r
    })
    .await
}

/// Keeps a restored folder unlocked: it is no longer locked again at sign-out.
#[tauri::command]
pub async fn work_session_keep(app: AppHandle, id: String) -> Result<()> {
    run(&app, move |app, st| {
        st.session.master_active()?;
        let pending = st.db.get_setting(&work_pending_key(&id))?.is_some();
        let _ = st.db.delete_setting(&work_pending_key(&id));
        if st.work.lock().remove(&id).is_some() || pending {
            st.db.log("work_session_kept", Some(&id), "info", None);
        }
        emit_vaults_changed(app);
        Ok(())
    })
    .await
}

/// Locks a folder again whose work session was cut short by a crash, a
/// forced exit or a power failure (see `VaultInfo::relock_pending`). The
/// folder is re-encrypted and the unlocked copy removed, as when a work
/// session ends. Master-password folders need no credential while signed in.
#[tauri::command]
pub async fn work_session_recover(app: AppHandle, id: String, credential: Option<Credential>) -> Result<String> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let r = load_vault(st, &id)?;
        if !is_relock_pending(st, &r) {
            return invalid("This folder has no unfinished work session.");
        }
        let vk = match &credential {
            Some(c) => secure_vault_key(st, &r, c)?,
            None if r.key_mode == "master" => {
                let h = VaultHeader::read(Path::new(&r.vault_path))?;
                let vk = h.unwrap_with_master(&mk)?;
                h.verify_mac(&vk)?;
                vk
            }
            None => return Err(Error::AuthFailed),
        };
        let i = info(st, &mk, &r);
        let src = i.restored_path.clone().ok_or_else(|| Error::NotFound("where this folder was restored to".into()))?;
        let mdk = crypto::metadata_key(&mk);
        let name = folder_name(&src);
        let ws =
            WorkSession { vk, source: PathBuf::from(&src), name_enc: crypto::encrypt_text(&mdk, &name, &aad(&r.id, "name")), path_enc: crypto::encrypt_text(&mdk, &src, &aad(&r.id, "path")), name };
        let op = relock_and_clean(app, st, &r, ws)?;
        st.db.log("work_session_recovered", Some(&id), "info", None);
        emit_vaults_changed(app);
        Ok(op)
    })
    .await
}

/// After sign-in: points out folders still decrypted from a work session
/// that DirShield never got to end.
pub(super) fn notify_relock_pending(app: &AppHandle, st: &AppState) {
    let Ok(mk) = st.session.master() else { return };
    let Ok(rows) = all_vaults(st) else { return };
    let names: Vec<String> = rows.iter().filter(|r| is_relock_pending(st, r)).map(|r| info(st, &mk, r).name).collect();
    if names.is_empty() {
        return;
    }
    let list = names.iter().map(|n| format!("\u{201c}{n}\u{201d}")).collect::<Vec<_>>().join(", ");
    let _ = app.emit(
        "notice",
        serde_json::json!({
            "title": "Folders left unlocked",
            "body": format!("DirShield closed before it could lock {list} again, so they are still decrypted on disk. Choose \u{201c}Lock again now\u{201d} for each one in Protected folders."),
            "severity": "warning",
        }),
    );
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LockAllReport {
    /// Quick Lock folders hidden again.
    pub hidden: u32,
    /// Restored Secure Lock folders being locked again.
    pub relocking: u32,
    /// Folders that need a password or attention: listed by name.
    pub skipped: Vec<String>,
}

/// Hides every visible Quick Lock folder and locks every restored Secure
/// Lock folder again (work sessions, and master-password folders while
/// signed in). Folder-password folders outside a work session need their
/// password and are listed as skipped.
pub fn lock_all(app: &AppHandle) -> Result<LockAllReport> {
    let st = app.state::<AppState>();
    let mut rep = LockAllReport { relocking: end_all_work_sessions(app, &st), ..Default::default() };
    let mk = st.session.master().ok();
    for r in all_vaults(&st)? {
        if st.ops.is_vault_busy(&r.id) {
            continue;
        }
        match (r.mode.as_str(), r.status.as_str()) {
            ("quick", "quick_visible") => {
                if quick_set_hidden_core(app, &st, &r, true).is_ok() {
                    rep.hidden += 1;
                }
            }
            ("secure", "restored") => {
                let Some(mk) = mk.as_ref() else {
                    rep.skipped.push(String::new());
                    continue;
                };
                let i = info(&st, mk, &r);
                let vk = VaultHeader::read(Path::new(&r.vault_path)).and_then(|h| {
                    let vk = h.unwrap_with_master(mk)?;
                    h.verify_mac(&vk)?;
                    Ok(vk)
                });
                let (Ok(vk), Some(src)) = (vk, i.restored_path.clone()) else {
                    rep.skipped.push(i.name);
                    continue;
                };
                let mdk = crypto::metadata_key(mk);
                let name = folder_name(&src);
                let ws = WorkSession {
                    vk,
                    source: PathBuf::from(&src),
                    name_enc: crypto::encrypt_text(&mdk, &name, &aad(&r.id, "name")),
                    path_enc: crypto::encrypt_text(&mdk, &src, &aad(&r.id, "path")),
                    name,
                };
                match relock_and_clean(app, &st, &r, ws) {
                    Ok(_) => rep.relocking += 1,
                    Err(_) => rep.skipped.push(i.name),
                }
            }
            _ => {}
        }
    }
    // Restored folders seen while signed out have no readable name.
    let unnamed = rep.skipped.iter().filter(|n| n.is_empty()).count();
    rep.skipped.retain(|n| !n.is_empty());
    if unnamed > 0 {
        rep.skipped.push(format!("{unnamed} restored folder(s): sign in to lock them"));
    }
    st.db.log("lock_all", None, "info", Some(&format!("hidden {}, relocking {}, skipped {}", rep.hidden, rep.relocking, rep.skipped.len())));
    emit_vaults_changed(app);
    Ok(rep)
}

#[tauri::command]
pub async fn lock_all_folders(app: AppHandle) -> Result<LockAllReport> {
    run(&app, |app, st| {
        st.session.master_active()?;
        lock_all(app)
    })
    .await
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

/// Shows a Windows notification (best effort) and tells the window.
pub fn notify(app: &AppHandle, title: &str, body: &str) {
    let _ = app.notification().builder().title(title).body(body).show();
    let _ = app.emit("notice", serde_json::json!({ "title": title, "body": body }));
}

pub(super) fn notify_verify_failed(app: &AppHandle, name: &str, error: &str) {
    notify(app, "DirShield: integrity check failed", &format!("\u{201c}{name}\u{201d} didn't pass its scheduled check: {error}"));
}

// ---------------------------------------------------------------------------
// Periodic task (once a minute)
// ---------------------------------------------------------------------------

/// Days between scheduled integrity checks; 0 turns them off.
fn verify_interval_days(st: &AppState) -> u64 {
    st.db.get_setting("verifyIntervalDays").ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(30)
}

/// Runs while DirShield is signed in (it needs the master key): seals the
/// activity log, applies a deferred header update, and starts at most one
/// due integrity check when nothing else is running. Scheduled checks cover
/// master-password folders only; folders with their own password can't be
/// opened without it.
pub fn background_tick(app: &AppHandle) {
    let st = app.state::<AppState>();
    // Needs no key: runs while signed out too.
    if sync_quick_locations(&st, st.session.master().ok().as_deref()) {
        emit_vaults_changed(app);
    }
    check_quick_locks(app, &st);
    let Ok(mk) = st.session.master() else { return };
    let _ = st.db.checkpoint_log(&mk);
    if st.ops.any_active() {
        return;
    }
    if st.db.get_setting("headersDirty").ok().flatten().as_deref() == Some("1") {
        let _ = sync_headers(&st, &mk);
    }
    let days = verify_interval_days(&st);
    if days == 0 {
        return;
    }
    let due_before = now_ms() - (days as i64) * 86_400_000;
    let Ok(vaults) = all_vaults(&st) else { return };
    for r in vaults {
        if r.mode != "secure" || r.key_mode != "master" || !matches!(r.status.as_str(), "encrypted" | "locked" | "restored") {
            continue;
        }
        let last = st.db.get_setting(&last_verify_key(&r.id)).ok().flatten().and_then(|v| v.parse::<i64>().ok()).or(r.locked_at).unwrap_or(r.created_at);
        if last > due_before {
            continue;
        }
        let name = info(&st, &mk, &r).name;
        let vk = VaultHeader::read(Path::new(&r.vault_path)).and_then(|h| {
            let vk = h.unwrap_with_master(&mk)?;
            h.verify_mac(&vk)?;
            Ok(vk)
        });
        match vk {
            Ok(vk) => {
                if spawn_verify(app, &st, &r, vk, Some(name)).is_ok() {
                    emit_vaults_changed(app);
                }
            }
            Err(e) => {
                // Storage missing (drive unplugged) or the header is damaged.
                let _ = st.db.set_setting(&last_verify_key(&r.id), &now_ms().to_string());
                st.db.log("scheduled_verify", Some(&r.id), "failed", Some(&e.to_string()));
                notify_verify_failed(app, &name, &e.to_string());
            }
        }
        return; // one at a time
    }
}

// ---------------------------------------------------------------------------
// Quick Lock watchdog
// ---------------------------------------------------------------------------

/// Quick Lock is an access restriction the folder's owner can always remove
/// (any program running as this user can). Once a minute, every Quick-Locked
/// folder is checked; a removed restriction is put back and reported.
fn check_quick_locks(app: &AppHandle, st: &AppState) {
    /// Folders whose restriction couldn't be put back (reported once).
    static FAILED: parking_lot::Mutex<Vec<String>> = parking_lot::const_mutex(Vec::new());
    let Ok(rows) = all_vaults(st) else { return };
    for id in rows.into_iter().filter(|r| r.mode == "quick").map(|r| r.id) {
        // Held across re-reading the row and fixing the folder: an unlock in
        // progress removes the restriction on purpose.
        let _guard = st.quick_guard.lock();
        let Ok(r) = load_vault(st, &id) else { continue }; // unlocked meanwhile
        if !matches!(r.status.as_str(), "quick_locked" | "quick_visible") || st.ops.is_vault_busy(&r.id) {
            continue;
        }
        let Some(q) = r.quick.as_deref().and_then(|s| serde_json::from_str::<QuickState>(s).ok()) else { continue };
        let path = PathBuf::from(&q.current_path);
        // Missing (drive unplugged, folder moved): nothing to restrict here.
        if !path.is_dir() {
            continue;
        }
        match quicklock::acl::is_restricted(&path) {
            Ok(false) => {}
            Ok(true) => {
                FAILED.lock().retain(|f| f != &r.id);
                continue;
            }
            Err(_) => continue,
        }
        // The name is encrypted; without the master key, stay generic.
        let who = st.session.master().ok().map(|mk| format!("\u{201c}{}\u{201d}", info(st, &mk, &r).name)).unwrap_or_else(|| "A Quick Lock folder".into());
        match quicklock::acl::apply_deny(&path) {
            Ok(()) => {
                FAILED.lock().retain(|f| f != &r.id);
                fsutil::notify_shell_changed(&path);
                st.db.log("quick_lock_reapplied", Some(&r.id), "warning", Some("the access restriction had been removed outside DirShield"));
                notify(
                    app,
                    "DirShield: Quick Lock was removed",
                    &format!("{who} was unlocked outside DirShield and has been locked again. Its files may have been read in the meantime. Use Secure Lock for data that must stay private."),
                );
            }
            Err(e) => {
                {
                    let mut failed = FAILED.lock();
                    if failed.contains(&r.id) {
                        continue; // reported already
                    }
                    failed.push(r.id.clone());
                }
                st.db.log("quick_lock_reapplied", Some(&r.id), "failed", Some(&e.to_string()));
                notify(app, "DirShield: Quick Lock failed", &format!("{who} was unlocked outside DirShield and couldn't be locked again: {e}"));
            }
        }
    }
}
