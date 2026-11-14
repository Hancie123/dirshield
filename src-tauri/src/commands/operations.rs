//! Background operations: listing, pause, cancel, resume and discard.

use super::*;

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationInfo {
    id: String,
    vault_id: String,
    vault_name: String,
    op_type: String,
    status: String,
    total_bytes: i64,
    processed_bytes: i64,
    total_files: i64,
    processed_files: i64,
    failed_files: i64,
    error: Option<String>,
    params: Option<String>,
    created_at: i64,
    updated_at: i64,
    live: Option<crate::app::ops::Progress>,
}

#[tauri::command]
pub async fn list_operations(app: AppHandle) -> Result<Vec<OperationInfo>> {
    run(&app, |_, st| {
        let mk = st.session.master()?;
        let mdk = crypto::metadata_key(&mk);
        let c = st.db.lock();
        let mut s = c.prepare(
            "SELECT o.id, o.vault_id, COALESCE(v.name,''), o.operation_type, o.status, o.total_bytes, o.processed_bytes, o.total_files, o.processed_files, o.failed_files,
                    o.error, o.params, o.created_at, o.updated_at,
                    (SELECT COUNT(*) FROM operation_journal j WHERE j.operation_id=o.id AND j.status='error')
             FROM operations o LEFT JOIN vaults v ON v.id=o.vault_id ORDER BY o.updated_at DESC LIMIT 200",
        )?;
        let rows = s
            .query_map([], |r| {
                let vid: String = r.get(1)?;
                let name_enc: String = r.get(2)?;
                let journal_errors: i64 = r.get(14)?;
                Ok(OperationInfo {
                    vault_name: crypto::decrypt_text(&mdk, &name_enc, &aad(&vid, "name")).unwrap_or_else(|_| "(removed)".into()),
                    id: r.get(0)?,
                    vault_id: vid,
                    op_type: r.get(3)?,
                    status: r.get(4)?,
                    total_bytes: r.get(5)?,
                    processed_bytes: r.get(6)?,
                    total_files: r.get(7)?,
                    processed_files: r.get(8)?,
                    failed_files: journal_errors.max(r.get(9)?),
                    error: r.get(10)?,
                    params: r.get(11)?,
                    created_at: r.get(12)?,
                    updated_at: r.get(13)?,
                    live: None,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(s);
        drop(c);
        Ok(rows
            .into_iter()
            .map(|mut o| {
                if let Some(a) = st.ops.get(&o.id) {
                    let snap = a.snapshot();
                    o.status = snap.status.clone();
                    o.live = Some(snap);
                }
                o
            })
            .collect())
    })
    .await
}

#[tauri::command]
pub async fn op_errors(app: AppHandle, id: String) -> Result<Vec<engine::ItemError>> {
    run(&app, move |_, st| {
        st.session.master()?;
        engine::list_errors(&st.db, &id, 200)
    })
    .await
}

#[tauri::command]
pub async fn op_pause(app: AppHandle, id: String, paused: bool) -> Result<()> {
    run(&app, move |app, st| {
        let op = st.ops.get(&id).ok_or_else(|| Error::NotFound("running operation".into()))?;
        op.ctrl.pause.store(paused, Ordering::Relaxed);
        engine::set_op_status(&st.db, &id, if paused { "paused" } else { "running" }, None)?;
        let _ = app.emit("ops-changed", ());
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn op_cancel(app: AppHandle, id: String) -> Result<()> {
    run(&app, move |_, st| {
        let op = st.ops.get(&id).ok_or_else(|| Error::NotFound("running operation".into()))?;
        op.ctrl.cancel.store(true, Ordering::Relaxed);
        op.ctrl.pause.store(false, Ordering::Relaxed);
        Ok(())
    })
    .await
}

/// Resume an interrupted / failed / cancelled operation.
/// mode: "resume" (pending items), "retry" (also retry failed items),
/// "skip" (explicitly exclude failed items, which stay in the original folder).
#[tauri::command]
pub async fn op_resume(app: AppHandle, id: String, credential: Credential, mode: String) -> Result<()> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        if st.ops.get(&id).is_some() {
            return Err(Error::Conflict("This operation is already running.".into()));
        }
        let (vault_id, op_type, status, params_json): (String, String, String, Option<String>) =
            st.db.lock().query_row("SELECT vault_id, operation_type, status, params FROM operations WHERE id=?1", [&id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        if status == "completed" {
            return invalid("This operation already completed.");
        }
        let r = load_vault(st, &vault_id)?;
        let vk = secure_vault_key(st, &r, &credential)?;
        match mode.as_str() {
            "retry" => engine::retry_failed(&st.db, &id)?,
            "skip" => engine::skip_failed(&st.db, &id)?,
            _ => {}
        }
        let (tf, tb): (i64, i64) = st.db.lock().query_row("SELECT total_files, total_bytes FROM operations WHERE id=?1", [&id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        match op_type.as_str() {
            "encrypt" => {
                let i = info(st, &mk, &r);
                spawn_encrypt(app, st, id.clone(), vault_id.clone(), PathBuf::from(&r.vault_path), PathBuf::from(&i.original_path), i.name, vk, tf as u64, tb as u64)?;
            }
            "decrypt" | "extract" => {
                let p: DecryptParams = serde_json::from_str(params_json.as_deref().unwrap_or("{}"))?;
                let enc = (!p.is_partial()).then(|| restored_enc(&mk, &vault_id, &p.dest));
                spawn_decrypt(app, st, id.clone(), vault_id.clone(), PathBuf::from(&r.vault_path), vk, p, enc, None, tf as u64, tb as u64)?;
            }
            "relock" => {
                let p = engine::load_relock_params(&st.db, &id)?;
                let src = PathBuf::from(&p.source);
                let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                spawn_relock(app, st, id.clone(), vault_id.clone(), PathBuf::from(&r.vault_path), src, name, vk, tf as u64, tb as u64, false)?;
            }
            _ => return invalid("This operation can't be resumed; start it again instead."),
        }
        st.db.log("resume_operation", Some(&vault_id), "info", Some(&mode));
        emit_vaults_changed(app);
        Ok(())
    })
    .await
}

/// Discards an unfinished operation. For Secure Lock this deletes the
/// incomplete encrypted output only - originals were never modified.
/// For a restore, already-restored (verified) files are left in place.
#[tauri::command]
pub async fn op_discard(app: AppHandle, id: String) -> Result<()> {
    run(&app, move |app, st| {
        st.session.master_active()?;
        if st.ops.get(&id).is_some() {
            return Err(Error::Conflict("Cancel the operation first.".into()));
        }
        let (vault_id, op_type, status, params_json): (String, String, String, Option<String>) =
            st.db.lock().query_row("SELECT vault_id, operation_type, status, params FROM operations WHERE id=?1", [&id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        if op_type == "encrypt" && status != "completed" {
            if let Ok(r) = load_vault(st, &vault_id) {
                if r.status == "incomplete" || r.status == "encrypting" {
                    let sealed = VaultHeader::read(Path::new(&r.vault_path)).map(|h| h.sealed).unwrap_or(false);
                    if sealed {
                        return Err(Error::Conflict("This vault is already complete and can't be discarded here.".into()));
                    }
                    engine::discard_vault_storage(Path::new(&r.vault_path));
                    st.db.lock().execute("DELETE FROM vaults WHERE id=?1", [&vault_id])?;
                }
            }
        } else if op_type == "relock" && status != "completed" {
            if let Ok(r) = load_vault(st, &vault_id) {
                engine::discard_relock(&st.db, &id, &vault_id, Path::new(&r.vault_path))?;
            }
        } else if op_type == "decrypt" && status != "completed" {
            if let Some(p) = params_json.and_then(|p| serde_json::from_str::<DecryptParams>(&p).ok()) {
                if let Ok(r) = load_vault(st, &vault_id) {
                    if r.status == "restoring" {
                        engine::set_vault_status(&st.db, &vault_id, &p.prev_status)?;
                    }
                }
            }
        }
        st.db.lock().execute("DELETE FROM operations WHERE id=?1", [&id])?;
        st.db.log("discard_operation", Some(&vault_id), "info", Some(&op_type));
        emit_vaults_changed(app);
        let _ = app.emit("ops-changed", ());
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn clear_finished_operations(app: AppHandle) -> Result<()> {
    run(&app, |app, st| {
        st.session.master_active()?;
        st.db.lock().execute("DELETE FROM operations WHERE status='completed'", [])?;
        let _ = app.emit("ops-changed", ());
        Ok(())
    })
    .await
}
