//! Folder commands: Quick Lock, Secure Lock, restore, re-lock, verify, import.

use super::*;

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn scan_folder(app: AppHandle, path: String) -> Result<ScanReport> {
    run(&app, move |_, st| {
        let mk = st.session.master_active()?;
        let p = validate_target(st, &mk, &path, None)?;
        scan::scan(&p, true)
    })
    .await
}

#[tauri::command]
pub async fn free_space(app: AppHandle, path: String) -> Result<u64> {
    run(&app, move |_, _| fsutil::free_space(Path::new(&path))).await
}

#[tauri::command]
pub async fn list_vaults(app: AppHandle) -> Result<Vec<VaultInfo>> {
    run(&app, |_, st| {
        let mk = st.session.master()?;
        Ok(all_vaults(st)?.iter().map(|r| info(st, &mk, r)).collect())
    })
    .await
}

#[tauri::command]
pub async fn find_by_path(app: AppHandle, path: String) -> Result<Option<VaultInfo>> {
    run(&app, move |_, st| {
        let mk = st.session.master()?;
        let key = fsutil::path_key(Path::new(&path));
        for r in all_vaults(st)? {
            let i = info(st, &mk, &r);
            let q: Option<QuickState> = r.quick.as_deref().and_then(|s| serde_json::from_str(s).ok());
            if fsutil::path_key(Path::new(&i.original_path)) == key || q.map(|q| fsutil::path_key(Path::new(&q.current_path)) == key).unwrap_or(false) {
                return Ok(Some(i));
            }
        }
        Ok(None)
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDetails {
    #[serde(flatten)]
    info: VaultInfo,
    wrappers: Vec<String>,
    algorithm: Option<String>,
    chunk_size: Option<u32>,
    sealed: Option<bool>,
    current_path: Option<String>,
    format_version: Option<u16>,
    /// The vault is escrowed to the current recovery key.
    recovery_current: Option<bool>,
    /// The header carries the portable master-password copy.
    portable: Option<bool>,
    /// When it last passed (or failed) an integrity check.
    last_verified_at: Option<i64>,
}

#[tauri::command]
pub async fn vault_details(app: AppHandle, id: String) -> Result<VaultDetails> {
    run(&app, move |_, st| {
        let mk = st.session.master()?;
        let r = load_vault(st, &id)?;
        let mut d = VaultDetails {
            info: info(st, &mk, &r),
            wrappers: vec![],
            algorithm: None,
            chunk_size: None,
            sealed: None,
            current_path: None,
            format_version: None,
            recovery_current: None,
            portable: None,
            last_verified_at: st.db.get_setting(&last_verify_key(&r.id))?.and_then(|v| v.parse().ok()),
        };
        if r.mode == "secure" {
            if let Ok(h) = VaultHeader::read(Path::new(&r.vault_path)) {
                let meta = auth::load_metadata(&st.db)?.ok_or(Error::NotInitialized)?;
                d.recovery_current = Some(h.recovery_id() == Some(meta.recovery_id.as_str()));
                d.portable = Some(h.wrappers.iter().any(|w| matches!(w, KeyWrapper::MasterPassword { .. })));
                d.wrappers = h.wrappers.iter().map(|w| w.kind().to_string()).collect();
                d.algorithm = Some(h.algorithm.clone());
                d.chunk_size = Some(h.chunk_size);
                d.sealed = Some(h.sealed);
                d.format_version = Some(h.format_version);
            }
        } else {
            let q: Option<QuickState> = r.quick.as_deref().and_then(|s| serde_json::from_str(s).ok());
            d.current_path = q.map(|q| q.current_path);
            d.wrappers = vec![if r.key_mode == "password" { "folder password".into() } else { "master password".into() }];
        }
        Ok(d)
    })
    .await
}

// ---------------- Quick Lock ----------------

#[tauri::command]
pub async fn quick_lock(app: AppHandle, path: String, credential: Credential, folder_password: Option<String>, hide: Option<bool>) -> Result<VaultInfo> {
    let hide = hide.unwrap_or(true);
    run(&app, move |app, st| {
        let folder_password = folder_password.map(Zeroizing::new);
        st.session.master_active()?;
        let mk = master_from(st, &credential)?;
        quick_lock_impl(app, st, &mk, &path, folder_password.as_deref().map(|s| s.as_str()), hide)
    })
    .await
}

/// Quick Lock with an already verified master key.
pub(super) fn quick_lock_impl(app: &AppHandle, st: &AppState, mk: &Key32, path: &str, folder_password: Option<&str>, hide: bool) -> Result<VaultInfo> {
    if !cfg!(windows) {
        return invalid("Quick Lock uses Windows file permissions and isn't available on this system. Use Secure Lock to encrypt the folder instead.");
    }
    {
        if let Some(fp) = folder_password {
            auth::validate_new_password(fp)?;
        }
        let src = validate_target(st, mk, path, None)?;
        let rep = scan::scan(&src, false)?;
        let id = crypto::random_id();
        let state = quicklock::lock(&src, Some(&st.dirs.quick_store), &id, hide, Some(&st.dirs.base))?;
        let mdk = crypto::metadata_key(mk);
        let now = now_ms();
        let key_mode = if folder_password.is_some() { "password" } else { "master" };
        let insert = st.db.lock().execute(
            "INSERT INTO vaults(id, name, original_path, vault_path, protection_mode, key_mode, status, size_bytes, file_count, quick_state, locked_at, created_at, updated_at)
             VALUES(?1,?2,?3,?4,'quick',?5,?10,?6,?7,?8,?9,?9,?9)",
            params![
                id,
                crypto::encrypt_text(&mdk, &rep.name, &aad(&id, "name")),
                crypto::encrypt_text(&mdk, &fsutil::display_path(&src), &aad(&id, "path")),
                state.current_path,
                key_mode,
                rep.total_bytes as i64,
                rep.total_files as i64,
                serde_json::to_string(&state)?,
                now,
                if hide { "quick_locked" } else { "quick_visible" }
            ],
        );
        if let Err(e) = insert {
            // Could not record it: undo the lock so the folder is never stranded.
            let _ = quicklock::unlock(&state, &src, None);
            return Err(e.into());
        }
        if let Some(fp) = folder_password {
            store_quick_verifier(st, &id, fp)?;
        }
        st.db.log("quick_lock", Some(&id), "success", None);
        emit_vaults_changed(app);
        Ok(info(st, mk, &load_vault(st, &id)?))
    }
}

#[tauri::command]
pub async fn quick_unlock(app: AppHandle, id: String, credential: Credential, dest: Option<String>) -> Result<String> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let r = load_vault(st, &id)?;
        if r.mode != "quick" {
            return invalid("not a Quick Lock folder");
        }
        quick_verify(st, &r, &credential)?;
        let i = info(st, &mk, &r);
        let dest = dest.map(PathBuf::from);
        quick_unlock_core(app, st, &r, Path::new(&i.original_path), dest.as_deref())
    })
    .await
}

pub(super) fn quick_unlock_core(app: &AppHandle, st: &AppState, r: &VaultRow, original: &Path, dest: Option<&Path>) -> Result<String> {
    let state: QuickState = serde_json::from_str(r.quick.as_deref().unwrap_or("{}"))?;
    let final_path = quicklock::unlock(&state, original, dest)?;
    st.db.lock().execute("DELETE FROM vaults WHERE id=?1", [&r.id])?;
    st.db.log("quick_unlock", Some(&r.id), "success", None);
    emit_vaults_changed(app);
    Ok(fsutil::display_path(&final_path))
}

#[tauri::command]
pub async fn quick_set_hidden(app: AppHandle, id: String, hidden: bool, credential: Credential) -> Result<()> {
    run(&app, move |app, st| {
        st.session.master_active()?;
        let r = load_vault(st, &id)?;
        if r.mode != "quick" {
            return invalid("not a Quick Lock folder");
        }
        quick_verify(st, &r, &credential)?;
        quick_set_hidden_core(app, st, &r, hidden)
    })
    .await
}

pub(super) fn quick_set_hidden_core(app: &AppHandle, st: &AppState, r: &VaultRow, hidden: bool) -> Result<()> {
    let mut state: QuickState = serde_json::from_str(r.quick.as_deref().unwrap_or("{}"))?;
    quicklock::set_hidden(&mut state, hidden)?;
    st.db.lock().execute(
        "UPDATE vaults SET quick_state=?2, status=?3, updated_at=?4 WHERE id=?1",
        params![r.id, serde_json::to_string(&state)?, if hidden { "quick_locked" } else { "quick_visible" }, now_ms()],
    )?;
    st.db.log(if hidden { "hide" } else { "unhide" }, Some(&r.id), "success", None);
    emit_vaults_changed(app);
    Ok(())
}

// ---------------- Secure Lock ----------------

pub(super) fn spawn_encrypt(
    app: &AppHandle,
    st: &AppState,
    op_id: String,
    vault_id: String,
    vault_dir: PathBuf,
    source: PathBuf,
    name: String,
    vk: Key32,
    total_files: u64,
    total_bytes: u64,
) -> Result<()> {
    let db = st.db.clone();
    let db2 = st.db.clone();
    let app2 = app.clone();
    let w = workers(st);
    let vid = vault_id.clone();
    let opid = op_id.clone();
    engine::set_vault_status(&st.db, &vault_id, "encrypting")?;
    engine::set_op_status(&st.db, &op_id, "running", None)?;
    st.ops.spawn(
        app.clone(),
        st.db.clone(),
        op_id,
        vault_id.clone(),
        "encrypt",
        total_files,
        total_bytes,
        move |ctrl| {
            let original = fsutil::display_path(&source);
            engine::run_encrypt(&EncryptJob { db: &db, op_id: &opid, vault_id: &vid, vault_dir: &vault_dir, source: &source, root_name: &name, original_path: &original, vk: &vk, workers: w, ctrl })
        },
        move |r| {
            match r {
                Ok(()) => db2.log("secure_lock", Some(&vault_id), "success", None),
                Err(Error::Cancelled) => {
                    let _ = engine::set_vault_status(&db2, &vault_id, "incomplete");
                    db2.log("secure_lock", Some(&vault_id), "cancelled", None);
                }
                Err(e) => {
                    let _ = engine::set_vault_status(&db2, &vault_id, "incomplete");
                    db2.log("secure_lock", Some(&vault_id), "failed", Some(&e.to_string()));
                }
            }
            emit_vaults_changed(&app2);
        },
    )
}

#[tauri::command]
pub async fn secure_lock(app: AppHandle, path: String, credential: Credential, folder_password: Option<String>, vault_root: Option<String>) -> Result<String> {
    run(&app, move |app, st| {
        let folder_password = folder_password.map(Zeroizing::new);
        st.session.master_active()?;
        let mk = master_from(st, &credential)?;
        if let Some(fp) = &folder_password {
            auth::validate_new_password(fp)?;
        }
        let src = validate_target(st, &mk, &path, None)?;
        let root = vault_root.filter(|s| !s.trim().is_empty()).map(PathBuf::from).unwrap_or_else(|| default_vault_root(st));
        std::fs::create_dir_all(&root)?;
        let root = fsutil::normalize(&root)?;
        if is_same_or_inside(&root, &src) {
            return invalid("The vault location can't be inside the folder you're locking.");
        }
        let _ = search::mark_not_indexed(&root);
        let meta = auth::load_metadata(&st.db)?.ok_or(Error::NotInitialized)?;
        let vault_id = crypto::random_id();
        let vk = crypto::random_key();
        let primary = match &folder_password {
            Some(fp) => header::password_wrapper(&vault_id, fp, &vk)?,
            None => header::master_wrapper(&vault_id, &mk, &vk),
        };
        let wrappers = header_wrappers(st, &meta, &vault_id, &vk, primary)?;
        let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mdk = crypto::metadata_key(&mk);
        let spec = NewVaultSpec {
            vault_id: &vault_id,
            source: &src,
            vault_root: &root,
            vk: &vk,
            wrappers,
            name_enc: crypto::encrypt_text(&mdk, &name, &aad(&vault_id, "name")),
            path_enc: crypto::encrypt_text(&mdk, &fsutil::display_path(&src), &aad(&vault_id, "path")),
            key_mode: if folder_password.is_some() { "password" } else { "master" },
            chunk: DEFAULT_CHUNK,
        };
        let ctrl = engine::Control::default();
        let nv = engine::create_secure_vault(&st.db, spec, &ctrl)?;
        let (tf, tb): (i64, i64) = st.db.lock().query_row("SELECT total_files, total_bytes FROM operations WHERE id=?1", [&nv.op_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        spawn_encrypt(app, st, nv.op_id.clone(), vault_id, nv.vault_dir, src, name, vk, tf as u64, tb as u64)?;
        emit_vaults_changed(app);
        Ok(nv.op_id)
    })
    .await
}

/// Runs a full restore, or a selective one ("extract") when `p.include` is
/// set. `restored_enc` (encrypted destination) is recorded as the vault's
/// restored location once a full restore finishes.
pub(super) fn spawn_decrypt(
    app: &AppHandle,
    st: &AppState,
    op_id: String,
    vault_id: String,
    vault_dir: PathBuf,
    vk: Key32,
    p: DecryptParams,
    restored_enc: Option<String>,
    work: Option<WorkSession>,
    total_files: u64,
    total_bytes: u64,
) -> Result<()> {
    let db = st.db.clone();
    let db2 = st.db.clone();
    let app2 = app.clone();
    let w = workers(st);
    let vid = vault_id.clone();
    let opid = op_id.clone();
    let prev = p.prev_status.clone();
    let partial = p.is_partial();
    let action = if partial { "extract" } else { "restore" };
    if !partial {
        engine::set_vault_status(&st.db, &vault_id, "restoring")?;
    }
    engine::set_op_status(&st.db, &op_id, "running", None)?;
    st.ops.spawn(
        app.clone(),
        st.db.clone(),
        op_id,
        vault_id.clone(),
        if partial { "extract" } else { "decrypt" },
        total_files,
        total_bytes,
        move |ctrl| engine::run_decrypt(&engine::DecryptJob { db: &db, op_id: &opid, vault_id: &vid, vault_dir: &vault_dir, vk: &vk, params: &p, workers: w, ctrl }),
        move |r| {
            match r {
                Ok(()) => {
                    if let Some(enc) = &restored_enc {
                        let _ = db2.lock().execute("UPDATE vaults SET restored_path=?2 WHERE id=?1", params![vault_id, enc]);
                    }
                    db2.log(action, Some(&vault_id), "success", None);
                    if let Some(w) = work {
                        app2.state::<AppState>().work.lock().insert(vault_id.clone(), w);
                        db2.log("work_session_start", Some(&vault_id), "info", None);
                    }
                }
                Err(e) => {
                    if !partial {
                        let _ = engine::set_vault_status(&db2, &vault_id, &prev);
                    }
                    db2.log(action, Some(&vault_id), if matches!(e, Error::Cancelled) { "cancelled" } else { "failed" }, Some(&e.to_string()));
                }
            }
            emit_vaults_changed(&app2);
        },
    )
}

pub(super) fn restored_enc(mk: &[u8; 32], vault_id: &str, dest: &str) -> String {
    crypto::encrypt_text(&crypto::metadata_key(mk), dest, &aad(vault_id, "restored"))
}

/// Destination checks shared by restore and extract.
pub(super) fn check_dest(st: &AppState, r: &VaultRow, dest: &Path) -> Result<()> {
    if !dest.is_absolute() {
        return invalid("Choose an absolute destination path.");
    }
    if is_same_or_inside(dest, Path::new(&r.vault_path)) || is_same_or_inside(dest, &st.dirs.base) {
        return invalid("Can't restore into DirShield's own storage.");
    }
    Ok(())
}

#[tauri::command]
pub async fn restore_vault(app: AppHandle, id: String, credential: Credential, dest: Option<String>, conflict: String, work_session: Option<bool>) -> Result<String> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let r = load_vault(st, &id)?;
        if !matches!(r.status.as_str(), "encrypted" | "locked" | "restored") {
            return invalid("This vault is not complete and can't be restored. Resume or discard its operation first.");
        }
        if st.ops.is_vault_busy(&id) {
            return Err(Error::Conflict("An operation is already running for this folder.".into()));
        }
        if !matches!(conflict.as_str(), "fail" | "skip" | "rename") {
            return invalid("invalid conflict option");
        }
        let vk = secure_vault_key(st, &r, &credential)?;
        let i = info(st, &mk, &r);
        let dest = dest.filter(|d| !d.trim().is_empty()).unwrap_or_else(|| i.original_path.clone());
        let dest_p = PathBuf::from(&dest);
        check_dest(st, &r, &dest_p)?;
        let p = DecryptParams { dest: fsutil::display_path(&dest_p), conflict, prev_status: r.status.clone(), ..Default::default() };
        let op_id = engine::create_operation(&st.db, &id, "decrypt", &serde_json::to_string(&p)?)?;
        let ctrl = engine::Control::default();
        if let Err(e) = engine::prepare_decrypt(&st.db, &op_id, Path::new(&r.vault_path), &vk, &p, &ctrl) {
            st.db.lock().execute("DELETE FROM operations WHERE id=?1", [&op_id])?;
            return Err(e);
        }
        let (tf, tb): (i64, i64) = st.db.lock().query_row("SELECT total_files, total_bytes FROM operations WHERE id=?1", [&op_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let enc = restored_enc(&mk, &id, &p.dest);
        // A work session restores into exactly this folder (a renamed copy
        // would not be the folder that gets locked again).
        let work = match work_session.unwrap_or(false) {
            true => {
                if p.conflict == "rename" && dest_p.exists() {
                    return invalid("For a work session, restore into a new folder or choose \"Skip\" for existing files.");
                }
                let name = folder_name(&p.dest);
                let mdk = crypto::metadata_key(&mk);
                Some(WorkSession {
                    vk: Key32::new(*vk),
                    source: dest_p.clone(),
                    name_enc: crypto::encrypt_text(&mdk, &name, &aad(&id, "name")),
                    path_enc: crypto::encrypt_text(&mdk, &p.dest, &aad(&id, "path")),
                    name,
                })
            }
            false => None,
        };
        close_browsers_for(st, &id);
        spawn_decrypt(app, st, op_id.clone(), id, PathBuf::from(&r.vault_path), vk, p, Some(enc), work, tf as u64, tb as u64)?;
        emit_vaults_changed(app);
        Ok(op_id)
    })
    .await
}

// ---------------- Re-lock (update a vault, re-encrypting only changes) ----------------

/// Runs a prepared re-lock. With `cleanup`, the unlocked folder is then
/// removed as well: only files identical to what the vault now holds are
/// deleted (see `engine::remove_originals`); anything else is kept.
pub(super) fn spawn_relock(
    app: &AppHandle,
    st: &AppState,
    op_id: String,
    vault_id: String,
    vault_dir: PathBuf,
    source: PathBuf,
    name: String,
    vk: Key32,
    total_files: u64,
    total_bytes: u64,
    cleanup: bool,
) -> Result<()> {
    let db = st.db.clone();
    let db2 = st.db.clone();
    let app2 = app.clone();
    let w = workers(st);
    let vid = vault_id.clone();
    let opid = op_id.clone();
    let opid2 = op_id.clone();
    engine::set_vault_status(&st.db, &vault_id, "relocking")?;
    engine::set_op_status(&st.db, &op_id, "running", None)?;
    st.ops.spawn(
        app.clone(),
        st.db.clone(),
        op_id,
        vault_id.clone(),
        "relock",
        total_files,
        total_bytes,
        move |ctrl| {
            let original = fsutil::display_path(&source);
            engine::run_relock(&EncryptJob { db: &db, op_id: &opid, vault_id: &vid, vault_dir: &vault_dir, source: &source, root_name: &name, original_path: &original, vk: &vk, workers: w, ctrl })?;
            if cleanup {
                // The vault is sealed and up to date from here on; a failed
                // cleanup only leaves the folder in place.
                engine::set_vault_status(&db, &vid, "removing")?;
                ctrl.processed_files.store(0, Ordering::Relaxed);
                ctrl.processed_bytes.store(0, Ordering::Relaxed);
                match engine::remove_originals(&vault_dir, &vk, &source, ctrl) {
                    Ok(rep) => {
                        engine::set_vault_status(&db, &vid, "locked")?;
                        db.log("remove_originals", Some(&vid), "success", Some(&serde_json::to_string(&rep).unwrap_or_default()));
                    }
                    Err(e) => {
                        engine::set_vault_status(&db, &vid, "encrypted")?;
                        db.log("remove_originals", Some(&vid), "failed", Some(&e.to_string()));
                    }
                }
            }
            Ok(())
        },
        move |r| {
            match r {
                Ok(()) => db2.log("relock", Some(&vault_id), "success", None),
                Err(e) => {
                    let prev = engine::load_relock_params(&db2, &opid2).map(|p| p.prev_status).unwrap_or_default();
                    let _ = engine::set_vault_status(&db2, &vault_id, if prev.is_empty() { "encrypted" } else { &prev });
                    db2.log("relock", Some(&vault_id), if matches!(e, Error::Cancelled) { "cancelled" } else { "failed" }, Some(&e.to_string()));
                }
            }
            emit_vaults_changed(&app2);
        },
    )
}

/// Locks a restored folder again (or refreshes a vault whose originals are
/// still in place), encrypting only files that are new or changed. `source`
/// defaults to where the vault was restored to.
#[tauri::command]
pub async fn relock_vault(app: AppHandle, id: String, credential: Credential, source: Option<String>, thorough: bool) -> Result<String> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let r = load_vault(st, &id)?;
        if r.mode != "secure" || !matches!(r.status.as_str(), "restored" | "encrypted") {
            return invalid("Only a restored folder, or one whose originals are still in place, can be locked again.");
        }
        if st.ops.is_vault_busy(&id) {
            return Err(Error::Conflict("An operation is already running for this folder.".into()));
        }
        let i = info(st, &mk, &r);
        let default_src = if r.status == "restored" { i.restored_path.clone().unwrap_or_else(|| i.original_path.clone()) } else { i.original_path.clone() };
        let raw = source.filter(|s| !s.trim().is_empty()).unwrap_or(default_src);
        let src = validate_target(st, &mk, &raw, Some(&id))?;
        if is_same_or_inside(Path::new(&r.vault_path), &src) {
            return invalid("The vault is stored inside this folder. Move the vault first.");
        }
        let vk = secure_vault_key(st, &r, &credential)?;
        close_browsers_for(st, &id);
        let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let p = RelockParams { source: fsutil::display_path(&src), thorough, prev_status: r.status.clone(), ..Default::default() };
        let op_id = engine::create_relock(&st.db, &id, Path::new(&r.vault_path), &vk, p, &engine::Control::default())?;
        // From here on the vault describes this folder (it is what "Remove
        // originals" will clean up once the update is sealed).
        let mdk = crypto::metadata_key(&mk);
        st.db.lock().execute(
            "UPDATE vaults SET name=?2, original_path=?3, updated_at=?4 WHERE id=?1",
            params![id, crypto::encrypt_text(&mdk, &name, &aad(&id, "name")), crypto::encrypt_text(&mdk, &fsutil::display_path(&src), &aad(&id, "path")), now_ms()],
        )?;
        let (tf, tb): (i64, i64) = st.db.lock().query_row("SELECT total_files, total_bytes FROM operations WHERE id=?1", [&op_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        st.work.lock().remove(&id);
        spawn_relock(app, st, op_id.clone(), id, PathBuf::from(&r.vault_path), src, name, vk, tf as u64, tb as u64, false)?;
        emit_vaults_changed(app);
        Ok(op_id)
    })
    .await
}

#[tauri::command]
pub async fn verify_vault(app: AppHandle, id: String, credential: Credential) -> Result<String> {
    run(&app, move |app, st| {
        st.session.master_active()?;
        let r = load_vault(st, &id)?;
        let vk = secure_vault_key(st, &r, &credential)?;
        spawn_verify(app, st, &r, vk, None)
    })
    .await
}

/// Settings key holding when a vault was last verified.
pub(super) fn last_verify_key(id: &str) -> String {
    format!("verify.last.{id}")
}

/// Starts an integrity check. `background_name` is set for a scheduled
/// check: its result is then also shown as a Windows notification if it fails.
pub(super) fn spawn_verify(app: &AppHandle, st: &AppState, r: &VaultRow, vk: Key32, background_name: Option<String>) -> Result<String> {
    if st.ops.is_vault_busy(&r.id) {
        return Err(Error::Conflict("An operation is already running for this folder.".into()));
    }
    let op_id = engine::create_operation(&st.db, &r.id, "verify", if background_name.is_some() { r#"{"scheduled":true}"# } else { "{}" })?;
    st.db.lock().execute("UPDATE operations SET total_files=?2, total_bytes=?3 WHERE id=?1", params![op_id, r.files, r.size])?;
    let db = st.db.clone();
    let app2 = app.clone();
    let dir = PathBuf::from(&r.vault_path);
    let vid = r.id.clone();
    let action = if background_name.is_some() { "scheduled_verify" } else { "verify_vault" };
    st.ops.spawn(
        app.clone(),
        st.db.clone(),
        op_id.clone(),
        r.id.clone(),
        "verify",
        r.files as u64,
        r.size as u64,
        move |ctrl| engine::verify_vault(&dir, &vk, ctrl).map(|_| ()),
        move |res| {
            match res {
                Ok(()) => db.log(action, Some(&vid), "success", None),
                Err(Error::Cancelled) => db.log(action, Some(&vid), "cancelled", None),
                Err(e) => {
                    db.log(action, Some(&vid), "failed", Some(&e.to_string()));
                    if let Some(name) = &background_name {
                        notify_verify_failed(&app2, name, &e.to_string());
                    }
                }
            }
            if !matches!(res, Err(Error::Cancelled)) {
                let _ = db.set_setting(&last_verify_key(&vid), &now_ms().to_string());
            }
            emit_vaults_changed(&app2);
        },
    )?;
    Ok(op_id)
}

#[tauri::command]
pub async fn remove_originals(app: AppHandle, id: String, credential: Credential, confirm_name: String) -> Result<String> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let r = load_vault(st, &id)?;
        if r.status != "encrypted" {
            return invalid("Originals can only be removed from a completed, verified vault.");
        }
        if st.ops.is_vault_busy(&id) {
            return Err(Error::Conflict("An operation is already running for this folder.".into()));
        }
        let i = info(st, &mk, &r);
        if confirm_name.trim() != i.name {
            return invalid("Type the folder name exactly to confirm.");
        }
        let vk = secure_vault_key(st, &r, &credential)?;
        // Claim the vault atomically: only one caller can move it from
        // "encrypted" to "removing", even if two requests passed the checks above.
        let claimed = st.db.lock().execute("UPDATE vaults SET status='removing', updated_at=?2 WHERE id=?1 AND status='encrypted'", params![id, now_ms()])?;
        if claimed == 0 {
            return Err(Error::Conflict("An operation is already running for this folder.".into()));
        }
        let op_id = match engine::create_operation(&st.db, &id, "cleanup", "{}") {
            Ok(op_id) => op_id,
            Err(e) => {
                let _ = engine::set_vault_status(&st.db, &id, "encrypted");
                return Err(e);
            }
        };
        let db = st.db.clone();
        let app2 = app.clone();
        let dir = PathBuf::from(&r.vault_path);
        let root = PathBuf::from(&i.original_path);
        let vid = id.clone();
        let opid = op_id.clone();
        let report: std::sync::Arc<parking_lot::Mutex<Option<CleanupReport>>> = Default::default();
        let rep2 = report.clone();
        let spawned = st.ops.spawn(
            app.clone(),
            st.db.clone(),
            op_id.clone(),
            id,
            "cleanup",
            r.files as u64,
            r.size as u64,
            move |ctrl| {
                let rep = engine::remove_originals(&dir, &vk, &root, ctrl)?;
                *rep2.lock() = Some(rep);
                Ok(())
            },
            move |res| {
                match res {
                    Ok(()) => {
                        let rep = report.lock().clone().unwrap_or_default();
                        let _ = engine::set_vault_status(&db, &vid, "locked");
                        let detail = serde_json::to_string(&rep).unwrap_or_default();
                        let _ = db.lock().execute("UPDATE operations SET params=?2 WHERE id=?1", params![opid, detail]);
                        db.log("remove_originals", Some(&vid), "success", Some(&detail));
                    }
                    Err(e) => {
                        let _ = engine::set_vault_status(&db, &vid, "encrypted");
                        db.log("remove_originals", Some(&vid), "failed", Some(&e.to_string()));
                    }
                }
                emit_vaults_changed(&app2);
            },
        );
        if let Err(e) = spawned {
            let _ = engine::set_op_status(&st.db, &op_id, "failed", Some(&e.to_string()));
            let _ = engine::set_vault_status(&st.db, &r.id, "encrypted");
            return Err(e);
        }
        Ok(op_id)
    })
    .await
}

#[tauri::command]
pub async fn delete_vault(app: AppHandle, id: String, credential: Credential, confirm_name: String) -> Result<()> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let r = load_vault(st, &id)?;
        if r.mode != "secure" {
            return invalid("Quick-Locked folders are removed from DirShield by unlocking them.");
        }
        if st.ops.is_vault_busy(&id) {
            return Err(Error::Conflict("An operation is running for this vault.".into()));
        }
        let i = info(st, &mk, &r);
        if confirm_name.trim() != i.name {
            return invalid("Type the folder name exactly to confirm.");
        }
        secure_vault_key(st, &r, &credential)?;
        close_browsers_for(st, &id);
        engine::discard_vault_storage(Path::new(&r.vault_path));
        let c = st.db.lock();
        c.execute("DELETE FROM operations WHERE vault_id=?1", [&id])?;
        c.execute("DELETE FROM vaults WHERE id=?1", [&id])?;
        drop(c);
        st.db.log("delete_vault", Some(&id), "success", Some(&format!("status was {}", r.status)));
        emit_vaults_changed(app);
        Ok(())
    })
    .await
}

/// new_mode: "master" (use the master password) or "password" (individual folder password).
#[tauri::command]
pub async fn change_folder_password(app: AppHandle, id: String, credential: Credential, new_mode: String, new_password: Option<String>) -> Result<()> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let new_password = new_password.map(Zeroizing::new);
        // Some(password) exactly when switching to a folder password.
        let new_pw: Option<&str> = match new_mode.as_str() {
            "password" => {
                let pw = new_password.as_deref().map(|s| s.as_str()).ok_or_else(|| Error::Invalid("A new folder password is required.".into()))?;
                auth::validate_new_password(pw)?;
                Some(pw)
            }
            "master" => None,
            _ => return invalid("invalid mode"),
        };
        let r = load_vault(st, &id)?;
        if st.ops.is_vault_busy(&id) {
            return Err(Error::Conflict("An operation is running for this folder.".into()));
        }
        if r.mode == "quick" {
            quick_verify(st, &r, &credential)?;
            if let Some(pw) = new_pw {
                store_quick_verifier(st, &id, pw)?;
            } else {
                st.db.lock().execute("DELETE FROM vault_key_wrappers WHERE vault_id=?1 AND wrapper_type='quick_password'", [&id])?;
            }
        } else {
            let vk = secure_vault_key(st, &r, &credential)?;
            let dir = PathBuf::from(&r.vault_path);
            let mut h = VaultHeader::read(&dir)?;
            let primary = match new_pw {
                Some(pw) => header::password_wrapper(&h.vault_id, pw, &vk)?,
                None => header::master_wrapper(&h.vault_id, &mk, &vk),
            };
            // Also escrows the vault key to the current recovery key, which
            // brings a folder-password vault up to date after the recovery
            // key was replaced.
            let meta = auth::load_metadata(&st.db)?.ok_or(Error::NotInitialized)?;
            h.wrappers = header_wrappers(st, &meta, &h.vault_id.clone(), &vk, primary)?;
            write_header(st, &id, &dir, &mut h, &vk)?;
        }
        st.db.lock().execute("UPDATE vaults SET key_mode=?2, updated_at=?3 WHERE id=?1", params![id, new_mode, now_ms()])?;
        st.db.log("change_folder_password", Some(&id), "success", Some(&new_mode));
        emit_vaults_changed(app);
        Ok(())
    })
    .await
}

/// Registers a vault directory found on disk (after reinstalling, losing the
/// database, or on another PC) and re-wraps it for this install.
///
/// `credential.kind`:
/// * "recovery" – the recovery key the vault was escrowed to;
/// * "master"   – the master password the vault was made with (works on
///   another PC when "Open vaults on another PC with the master password"
///   was on there), or this install's own master password;
/// * "folder"   – the vault's own folder password, which it keeps.
#[tauri::command]
pub async fn import_vault(app: AppHandle, path: String, credential: Credential) -> Result<VaultInfo> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let secret = Zeroizing::new(credential.secret.clone());
        let dir = fsutil::normalize(Path::new(&path))?;
        let mut h = VaultHeader::read(&dir)?;
        if load_vault(st, &h.vault_id).is_ok() {
            return Err(Error::Conflict("This vault is already in DirShield.".into()));
        }
        if !h.sealed {
            return invalid("This vault was never completed and can't be imported.");
        }
        let meta = auth::load_metadata(&st.db)?.ok_or(Error::NotInitialized)?;
        let vk = RateLimiter::guarded(&st.db, || match credential.kind.as_str() {
            "recovery" => h.unwrap_with_recovery(&*crypto::decode_recovery_key(&secret)?),
            "master" => h.unwrap_with_master_password(&secret).or_else(|_| {
                // A vault made by this install (its database was lost or restored).
                let own = auth::unwrap_master(&meta, &secret)?;
                h.unwrap_with_master(&own)
            }),
            "folder" => h.unwrap_with_password(&secret),
            _ => Err(Error::Invalid("unknown credential type".into())),
        })?;
        h.verify_mac(&vk)?;
        let (name, original, files, bytes) = engine::manifest_summary(&dir, &vk)?;
        let keep_folder_pw = credential.kind == "folder";
        let primary = match keep_folder_pw {
            true => h.wrappers.iter().find(|w| matches!(w, KeyWrapper::Password { .. })).cloned().ok_or(Error::AuthFailed)?,
            false => header::master_wrapper(&h.vault_id, &mk, &vk),
        };
        h.wrappers = header_wrappers(st, &meta, &h.vault_id.clone(), &vk, primary)?;
        let id = h.vault_id.clone();
        let key_mode = if keep_folder_pw { "password" } else { "master" };
        let mdk = crypto::metadata_key(&mk);
        let now = now_ms();
        st.db.lock().execute(
            "INSERT INTO vaults(id, name, original_path, vault_path, protection_mode, key_mode, status, size_bytes, file_count, locked_at, created_at, updated_at)
             VALUES(?1,?2,?3,?4,'secure',?8,'locked',?5,?6,?7,?7,?7)",
            params![
                id,
                crypto::encrypt_text(&mdk, &name, &aad(&id, "name")),
                crypto::encrypt_text(&mdk, &original, &aad(&id, "path")),
                fsutil::display_path(&dir),
                bytes as i64,
                files as i64,
                now,
                key_mode
            ],
        )?;
        if let Err(e) = write_header(st, &id, &dir, &mut h, &vk) {
            st.db.lock().execute("DELETE FROM vaults WHERE id=?1", [&id])?;
            return Err(e);
        }
        st.db.log("import_vault", Some(&id), "success", None);
        emit_vaults_changed(app);
        Ok(info(st, &mk, &load_vault(st, &id)?))
    })
    .await
}

#[tauri::command]
pub async fn find_orphans(app: AppHandle) -> Result<Vec<quicklock::Orphan>> {
    run(&app, |_, st| {
        st.session.master_active()?;
        let ids: Vec<String> = all_vaults(st)?.into_iter().map(|r| r.id).collect();
        quicklock::find_orphans(&st.dirs.quick_store, &ids)
    })
    .await
}

/// Returns a Quick-Locked folder whose database record was lost.
#[tauri::command]
pub async fn recover_orphan(app: AppHandle, id: String, password: String, dest: Option<String>) -> Result<String> {
    run(&app, move |_, st| {
        let password = Zeroizing::new(password);
        st.session.master_active()?;
        verify_master(st, &password)?;
        let ids: Vec<String> = all_vaults(st)?.into_iter().map(|r| r.id).collect();
        let o = quicklock::find_orphans(&st.dirs.quick_store, &ids)?.into_iter().find(|o| o.id == id).ok_or_else(|| Error::NotFound("orphaned folder".into()))?;
        let dest = dest.filter(|d| !d.trim().is_empty()).or_else(|| o.original_path.clone()).ok_or_else(|| Error::Invalid("Choose where to put this folder.".into()))?;
        let dest = PathBuf::from(dest);
        if !dest.is_absolute() || is_same_or_inside(&dest, &st.dirs.base) {
            return invalid("Choose a destination outside DirShield's storage.");
        }
        let p = quicklock::recover_orphan(&st.dirs.quick_store, &o, &dest)?;
        st.db.log("recover_orphan", None, "success", None);
        Ok(fsutil::display_path(&p))
    })
    .await
}
