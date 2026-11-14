//! Sign-in, setup, Windows Hello and master password commands.

use super::*;

// ---------------------------------------------------------------------------
// App / authentication
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    initialized: bool,
    unlocked: bool,
    lockout_ms: i64,
    mica: bool,
    windows_build: u32,
    accent: Option<String>,
    version: String,
    data_dir: String,
    default_vault_root: String,
    /// Windows Hello is set up on this PC.
    hello_available: bool,
    /// Windows Hello unlock is turned on for DirShield.
    hello: bool,
}

#[tauri::command]
pub async fn app_info(app: AppHandle) -> Result<AppInfo> {
    run(&app, |app, st| {
        Ok(AppInfo {
            initialized: auth::load_metadata(&st.db)?.is_some(),
            unlocked: st.session.is_unlocked(),
            lockout_ms: RateLimiter::remaining_ms(&st.db),
            mica: st.mica.load(Ordering::Relaxed),
            windows_build: shell::windows_build(),
            accent: shell::accent_color(),
            version: app.package_info().version.to_string(),
            data_dir: fsutil::display_path(&st.dirs.base),
            default_vault_root: fsutil::display_path(&default_vault_root(st)),
            hello_available: hello::available(),
            hello: hello::is_enabled(&st.db),
        })
    })
    .await
}

#[tauri::command]
pub async fn setup_master(app: AppHandle, password: String, confirm: String) -> Result<String> {
    run(&app, move |_, st| {
        let password = Zeroizing::new(password);
        if *password != confirm {
            return invalid("The passwords don't match.");
        }
        let (mk, recovery) = auth::setup(&st.db, &password, KdfParams::new_default())?;
        st.session.unlock(mk);
        // The Explorer menu is on by default (the installer adds it too); turn it off in Settings.
        let ok = shell::register_context_menu().is_ok();
        st.db.set_setting("contextMenu", if ok { "true" } else { "false" })?;
        Ok(recovery.to_string())
    })
    .await
}

#[tauri::command]
pub async fn login(app: AppHandle, password: String) -> Result<()> {
    run(&app, move |app, st| {
        let password = Zeroizing::new(password);
        let mk = verify_master(st, &password)?;
        st.session.unlock(mk);
        st.db.log("sign_in", None, "success", None);
        notify_relock_pending(app, st);
        Ok(())
    })
    .await
}

/// Signs in with Windows Hello instead of the master password.
#[tauri::command]
pub async fn login_hello(app: AppHandle) -> Result<()> {
    run(&app, move |app, st| {
        auth::load_metadata(&st.db)?.ok_or(Error::NotInitialized)?;
        let mk = hello::unlock(&st.db)?;
        st.session.unlock(mk);
        st.db.log("sign_in_windows_hello", None, "success", None);
        notify_relock_pending(app, st);
        Ok(())
    })
    .await
}

/// Turns on Windows Hello unlock. Needs the master password once.
#[tauri::command]
pub async fn hello_enable(app: AppHandle, password: String) -> Result<()> {
    run(&app, move |_, st| {
        let password = Zeroizing::new(password);
        st.session.master_active()?;
        let mk = verify_master(st, &password)?;
        hello::enable(&st.db, &mk)?;
        st.db.log("windows_hello_on", None, "success", None);
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn hello_disable(app: AppHandle) -> Result<()> {
    run(&app, move |_, st| {
        st.session.master_active()?;
        hello::disable(&st.db)?;
        st.db.log("windows_hello_off", None, "success", None);
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn logout(app: AppHandle) -> Result<()> {
    run(&app, |app, _| {
        sign_out(app, "manual");
        Ok(())
    })
    .await
}

#[tauri::command]
pub fn touch(state: tauri::State<'_, AppState>) {
    state.session.touch();
}

/// Strength estimate for a password being chosen (meter in the UI). The same
/// estimate gates new master passwords in `auth::validate_master_password`.
/// Runs on a worker thread: a synchronous command would run on the UI thread
/// and freeze every window while zxcvbn works.
#[tauri::command]
pub async fn password_strength(password: String) -> auth::PasswordStrength {
    let password = Zeroizing::new(password);
    tauri::async_runtime::spawn_blocking(move || auth::password_strength(&password)).await.unwrap_or(auth::PasswordStrength { score: 0, warning: None, suggestions: vec![] })
}

#[tauri::command]
pub async fn change_master_password(app: AppHandle, current: String, new_password: String) -> Result<()> {
    run(&app, move |_, st| {
        let current = Zeroizing::new(current);
        let new_password = Zeroizing::new(new_password);
        let mk = verify_master(st, &current)?;
        auth::rewrap_master(&st.db, &mk, &new_password, KdfParams::new_default())?;
        st.db.log("change_master_password", None, "success", None);
        // Vault headers' portable copies must stop accepting the old password.
        if portable_enabled(st) {
            sync_headers(st, &mk)?;
        }
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn reset_master_password(app: AppHandle, recovery_key: String, new_password: String) -> Result<()> {
    run(&app, move |_, st| {
        let rk = Zeroizing::new(recovery_key);
        let new_password = Zeroizing::new(new_password);
        auth::validate_master_password(&new_password)?;
        let meta = auth::load_metadata(&st.db)?.ok_or(Error::NotInitialized)?;
        let mk = RateLimiter::guarded(&st.db, || auth::unwrap_master_with_recovery(&meta, &rk))?;
        auth::rewrap_master(&st.db, &mk, &new_password, KdfParams::new_default())?;
        if portable_enabled(st) {
            sync_headers(st, &mk)?;
        }
        st.session.unlock(mk);
        st.db.log("reset_master_password_with_recovery_key", None, "success", None);
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------
// Recovery key replacement
// ---------------------------------------------------------------------------

/// Step 1 of replacing the recovery key: checks the master password and
/// returns a new key. Nothing changes until [`recovery_rotate_commit`]
/// receives the same key back (after the user has saved it), so a key that
/// was never shown can't end up in use.
#[tauri::command]
pub async fn recovery_rotate_begin(app: AppHandle, credential: Credential) -> Result<String> {
    run(&app, move |_, st| {
        st.session.master_active()?;
        master_from(st, &credential)?;
        let rk = crypto::random_key();
        let text = crypto::encode_recovery_key(&rk);
        *st.pending_recovery.lock() = Some(rk);
        Ok(text)
    })
    .await
}

/// Step 2: puts the new recovery key into use. The old key stops opening
/// DirShield at once; vault headers are re-escrowed to the new key (those
/// that can't be updated now are reported).
#[tauri::command]
pub async fn recovery_rotate_commit(app: AppHandle, recovery_key: String) -> Result<SyncReport> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let typed = crypto::decode_recovery_key(&Zeroizing::new(recovery_key))?;
        let pending = st.pending_recovery.lock().take().ok_or_else(|| Error::Invalid("Start again: no new recovery key is waiting.".into()))?;
        if *typed != *pending {
            *st.pending_recovery.lock() = Some(pending);
            return invalid("That isn't the new recovery key.");
        }
        auth::rotate_recovery(&st.db, &mk, &pending)?;
        st.db.log("recovery_key_replaced", None, "success", None);
        let rep = sync_headers(st, &mk)?;
        emit_vaults_changed(app);
        Ok(rep)
    })
    .await
}

#[tauri::command]
pub fn recovery_rotate_cancel(state: tauri::State<'_, AppState>) {
    state.pending_recovery.lock().take();
}

// ---------------------------------------------------------------------------
// Opening vaults on another PC with the master password
// ---------------------------------------------------------------------------

/// Turns the portable master-password copy in vault headers on or off.
/// Turning it on needs the master password: from then on, anyone holding a
/// vault folder can try to guess the master password against it (Argon2id,
/// like a folder password), without needing DirShield's database.
#[tauri::command]
pub async fn set_portable_vaults(app: AppHandle, enabled: bool, credential: Credential) -> Result<SyncReport> {
    run(&app, move |app, st| {
        st.session.master_active()?;
        let mk = master_from(st, &credential)?;
        st.db.set_setting("portableVaults", if enabled { "true" } else { "false" })?;
        st.db.log("portable_vaults", None, "success", Some(if enabled { "on" } else { "off" }));
        let rep = sync_headers(st, &mk)?;
        emit_vaults_changed(app);
        Ok(rep)
    })
    .await
}

// ---------------------------------------------------------------------------
// Encrypted backup of the database
// ---------------------------------------------------------------------------

/// Writes an encrypted backup of DirShield's database (the list of
/// protected folders, Quick Lock records and passwords, settings and the
/// activity log) to `dest`. Folder contents are not included: Secure Lock
/// vaults live in their own folders.
#[tauri::command]
pub async fn backup_create(app: AppHandle, dest: String) -> Result<String> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let mut dest = PathBuf::from(dest.trim());
        if !dest.is_absolute() {
            return invalid("Choose where to save the backup.");
        }
        if dest.extension().is_none() {
            dest.set_extension(crate::storage::backup::EXTENSION);
        }
        if is_same_or_inside(&dest, &st.dirs.base) {
            return invalid("Save the backup outside DirShield's own storage, ideally on another drive.");
        }
        crate::storage::backup::create(&st.db, &mk, &app.package_info().version.to_string(), &dest, &st.dirs.base.join("data"))?;
        st.db.set_setting("lastBackupAt", &now_ms().to_string())?;
        st.db.log("backup_created", None, "success", None);
        Ok(fsutil::display_path(&dest))
    })
    .await
}

/// Replaces DirShield's database with a backup, opened with the master
/// password it was made with (`kind` "master") or the recovery key
/// ("recovery"). Allowed on a fresh install, or while signed in.
#[tauri::command]
pub async fn backup_restore(app: AppHandle, path: String, credential: Credential) -> Result<()> {
    run(&app, move |app, st| {
        let initialized = auth::load_metadata(&st.db)?.is_some();
        if initialized {
            st.session.master_active()?;
        }
        if st.ops.any_active() {
            return Err(Error::Conflict("Wait for running operations to finish (or cancel them) first.".into()));
        }
        if !st.work.lock().is_empty() {
            return Err(Error::Conflict("End your work sessions first.".into()));
        }
        let secret = Zeroizing::new(credential.secret.clone());
        let file = PathBuf::from(path.trim());
        let opened = RateLimiter::guarded(&st.db, || match credential.kind.as_str() {
            "master" => crate::storage::backup::open(&file, crate::storage::backup::Secret::Password(&secret)),
            "recovery" => crate::storage::backup::open(&file, crate::storage::backup::Secret::Recovery(&secret)),
            _ => Err(Error::Invalid("unknown credential type".into())),
        })?;
        let previous = st.session.master().ok();
        st.lock_session();
        if let Err(e) = crate::storage::backup::restore(&st.db, &opened, &st.dirs.base.join("data")) {
            if let Some(mk) = previous {
                st.session.unlock(mk);
            }
            return Err(e);
        }
        crate::app::reconcile(&st.db)?;
        if let Some(m) = st.db.get_setting("autoLockMinutes")?.and_then(|v| v.parse::<u64>().ok()) {
            st.session.set_timeout(Duration::from_secs(m * 60));
        }
        // The restored rate-limit counters belong to the backup's moment.
        RateLimiter::success(&st.db)?;
        // On a fresh install the Explorer menu isn't registered yet.
        if st.db.get_setting("contextMenu")?.as_deref() != Some("false") {
            let _ = shell::register_context_menu();
        }
        st.session.unlock(Key32::new(*opened.mk));
        st.db.log("backup_restored", None, "success", Some(&format!("backup from {}", opened.created_utc)));
        emit_vaults_changed(app);
        let _ = app.emit("ops-changed", ());
        Ok(())
    })
    .await
}
