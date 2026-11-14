//! Browsing a vault: listing, extracting and opening single files.

use super::*;

// ---------------- Browse a vault, extract or open single files ----------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowseInfo {
    token: String,
    name: String,
    files: u64,
    bytes: u64,
}

pub(super) fn close_browsers_for(st: &AppState, vault_id: &str) {
    let gone: Vec<_> = {
        let mut m = st.browse.lock();
        let keys: Vec<String> = m.iter().filter(|(_, s)| s.vault_id == vault_id).map(|(k, _)| k.clone()).collect();
        keys.into_iter().filter_map(|k| m.remove(&k)).collect()
    };
    for s in gone {
        for d in s.opened.lock().drain(..) {
            browse::wipe_tree(&d);
        }
    }
}

fn browser(st: &AppState, token: &str) -> Result<std::sync::Arc<BrowseSession>> {
    st.session.master_active()?;
    st.browse.lock().get(token).cloned().ok_or_else(|| Error::NotFound("open vault (it was closed; open it again)".into()))
}

/// Decrypts a vault's manifest so its contents can be browsed. The vault key
/// stays in memory until the browser is closed or DirShield locks.
#[tauri::command]
pub async fn browse_open(app: AppHandle, id: String, credential: Credential) -> Result<BrowseInfo> {
    run(&app, move |_, st| {
        st.session.master_active()?;
        let r = load_vault(st, &id)?;
        if r.mode != "secure" || !matches!(r.status.as_str(), "encrypted" | "locked" | "restored") {
            return invalid("Only a completed Secure Lock vault can be browsed.");
        }
        if st.ops.is_vault_busy(&id) {
            return Err(Error::Conflict("An operation is running for this vault.".into()));
        }
        let vk = secure_vault_key(st, &r, &credential)?;
        let dir = PathBuf::from(&r.vault_path);
        let index = VaultIndex::load(&dir, &vk)?;
        let token = crypto::random_id();
        let out = BrowseInfo { token: token.clone(), name: index.root_name.clone(), files: index.files, bytes: index.bytes };
        st.browse.lock().insert(token, std::sync::Arc::new(BrowseSession { vault_id: id.clone(), vault_dir: dir, vk, index, opened: Default::default() }));
        st.db.log("browse_vault", Some(&id), "success", None);
        Ok(out)
    })
    .await
}

#[tauri::command]
pub async fn browse_list(app: AppHandle, token: String, dir: String) -> Result<Vec<BrowseEntry>> {
    run(&app, move |_, st| browser(st, &token)?.index.list(&dir)).await
}

/// Restores the selected files and folders (all in folder `base`) into `dest`.
#[tauri::command]
pub async fn browse_extract(app: AppHandle, token: String, paths: Vec<String>, dest: String, conflict: String) -> Result<String> {
    run(&app, move |app, st| {
        let s = browser(st, &token)?;
        if paths.is_empty() {
            return invalid("Select at least one file or folder.");
        }
        if !matches!(conflict.as_str(), "fail" | "skip" | "rename") {
            return invalid("invalid conflict option");
        }
        let r = load_vault(st, &s.vault_id)?;
        if st.ops.is_vault_busy(&r.id) {
            return Err(Error::Conflict("An operation is already running for this vault.".into()));
        }
        s.index.measure(&paths)?;
        let dest_p = PathBuf::from(dest.trim());
        check_dest(st, &r, &dest_p)?;
        let base = paths[0].rfind('/').map(|i| paths[0][..i].to_string()).unwrap_or_default();
        let p = DecryptParams { dest: fsutil::display_path(&dest_p), conflict, prev_status: r.status.clone(), include: paths, base };
        let op_id = engine::create_operation(&st.db, &r.id, "extract", &serde_json::to_string(&p)?)?;
        if let Err(e) = engine::prepare_decrypt(&st.db, &op_id, &s.vault_dir, &s.vk, &p, &engine::Control::default()) {
            st.db.lock().execute("DELETE FROM operations WHERE id=?1", [&op_id])?;
            return Err(e);
        }
        let (tf, tb): (i64, i64) = st.db.lock().query_row("SELECT total_files, total_bytes FROM operations WHERE id=?1", [&op_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        spawn_decrypt(app, st, op_id.clone(), r.id.clone(), s.vault_dir.clone(), Key32::new(*s.vk), p, None, None, tf as u64, tb as u64)?;
        Ok(op_id)
    })
    .await
}

/// Decrypts one file into a private temp folder and opens it with its
/// default app. The copy is read-only and is wiped when the vault browser
/// closes, when DirShield locks or exits, or at the next start.
#[tauri::command]
pub async fn browse_open_file(app: AppHandle, token: String, path: String) -> Result<()> {
    run(&app, move |_, st| {
        let s = browser(st, &token)?;
        if st.ops.is_vault_busy(&s.vault_id) {
            return Err(Error::Conflict("An operation is running for this vault.".into()));
        }
        let f = s.index.file(&path)?;
        if browse::is_executable(&f.name) {
            return invalid("Programs and scripts aren't opened straight from a vault. Extract the file instead.");
        }
        let dir = browse::new_temp_dir(&st.dirs.temp)?;
        let out = dir.join(&f.name);
        if let Err(e) = s.index.decrypt_file(&s.vault_dir, &s.vk, &f, &out) {
            browse::wipe_tree(&dir);
            return Err(e);
        }
        s.opened.lock().push(dir);
        let a = fsutil::get_attrs(&out).unwrap_or(0) & fsutil::RESTORABLE_ATTRS;
        let _ = fsutil::set_attrs(&out, a | fsutil::FILE_ATTRIBUTE_READONLY);
        // The path is a single argument (no shell interpretation).
        std::process::Command::new("explorer.exe").arg(&out).spawn()?;
        st.db.log("open_from_vault", Some(&s.vault_id), "success", None);
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn browse_close(app: AppHandle, token: String) -> Result<()> {
    run(&app, move |_, st| {
        if let Some(s) = st.browse.lock().remove(&token) {
            for d in s.opened.lock().drain(..) {
                browse::wipe_tree(&d);
            }
        }
        Ok(())
    })
    .await
}
