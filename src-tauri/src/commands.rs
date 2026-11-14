//! Tauri command surface. Keys never cross into the frontend; passwords are
//! received, used and dropped (zeroized) inside a single command.
//! All work runs on blocking worker threads so the UI never freezes.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::app::{AppState, BrowseSession};
use crate::auth::{self, RateLimiter};
use crate::crypto::{self, KdfParams, Key32};
use crate::db::now_ms;
use crate::error::{invalid, Error, Result};
use crate::fsutil::{self, is_same_or_inside};
use crate::hello;
use crate::quicklock::{self, QuickState};
use crate::search;
use crate::shell::{self, ShellAction};
use crate::vault::browse::{self, Entry as BrowseEntry, VaultIndex};
use crate::vault::engine::{self, CleanupReport, DecryptParams, EncryptJob, NewVaultSpec, RelockParams};
use crate::vault::header::{self, KeyWrapper, VaultHeader};
use crate::vault::scan::{self, ScanReport};
use crate::vault::stream::DEFAULT_CHUNK;

async fn run<T, F>(app: &AppHandle, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&AppHandle, &AppState) -> Result<T> + Send + 'static,
{
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let st = app.state::<AppState>();
        f(&app, &st)
    })
    .await
    .map_err(|e| Error::Invalid(format!("background task failed: {e}")))?
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    /// "master" | "folder" | "recovery" | "hello" (Windows Hello; no secret)
    pub kind: String,
    #[serde(default)]
    pub secret: String,
}

fn verify_master(st: &AppState, password: &str) -> Result<Key32> {
    let meta = auth::load_metadata(&st.db)?.ok_or(Error::NotInitialized)?;
    RateLimiter::guarded(&st.db, || auth::unwrap_master(&meta, password))
}

/// Master key from a "master" (password) or "hello" (Windows Hello) credential.
fn master_from(st: &AppState, cred: &Credential) -> Result<Key32> {
    match cred.kind.as_str() {
        "master" => verify_master(st, &Zeroizing::new(cred.secret.clone())),
        "hello" => hello::unlock(&st.db),
        _ => Err(Error::AuthFailed),
    }
}

fn aad(id: &str, field: &str) -> Vec<u8> {
    format!("dirshield/v1/vault/{id}/{field}").into_bytes()
}

#[derive(Clone)]
struct VaultRow {
    id: String,
    name_enc: String,
    path_enc: String,
    vault_path: String,
    mode: String,
    key_mode: String,
    status: String,
    size: i64,
    files: i64,
    skipped: i64,
    quick: Option<String>,
    locked_at: Option<i64>,
    created_at: i64,
    restored_enc: Option<String>,
}

const VAULT_COLS: &str = "id, name, original_path, vault_path, protection_mode, key_mode, status, size_bytes, file_count, skipped_count, quick_state, locked_at, created_at, restored_path";

fn map_row(r: &rusqlite::Row) -> rusqlite::Result<VaultRow> {
    Ok(VaultRow {
        id: r.get(0)?,
        name_enc: r.get(1)?,
        path_enc: r.get(2)?,
        vault_path: r.get(3)?,
        mode: r.get(4)?,
        key_mode: r.get(5)?,
        status: r.get(6)?,
        size: r.get(7)?,
        files: r.get(8)?,
        skipped: r.get(9)?,
        quick: r.get(10)?,
        locked_at: r.get(11)?,
        created_at: r.get(12)?,
        restored_enc: r.get(13)?,
    })
}

fn load_vault(st: &AppState, id: &str) -> Result<VaultRow> {
    st.db.lock().query_row(&format!("SELECT {VAULT_COLS} FROM vaults WHERE id=?1"), [id], map_row).optional()?.ok_or_else(|| Error::NotFound("protected folder".into()))
}

fn all_vaults(st: &AppState) -> Result<Vec<VaultRow>> {
    let c = st.db.lock();
    let mut s = c.prepare(&format!("SELECT {VAULT_COLS} FROM vaults ORDER BY created_at DESC"))?;
    let rows = s.query_map([], map_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub original_path: String,
    pub vault_path: String,
    pub mode: String,
    pub key_mode: String,
    pub status: String,
    pub size_bytes: i64,
    pub file_count: i64,
    pub skipped_count: i64,
    pub locked_at: Option<i64>,
    pub created_at: i64,
    pub hidden: Option<bool>,
    pub moved: Option<bool>,
    pub busy: bool,
    /// Where a Secure Lock vault was last restored to.
    pub restored_path: Option<String>,
}

fn info(st: &AppState, mk: &[u8; 32], r: &VaultRow) -> VaultInfo {
    let mdk = crypto::metadata_key(mk);
    let name = crypto::decrypt_text(&mdk, &r.name_enc, &aad(&r.id, "name")).unwrap_or_else(|_| "(unreadable)".into());
    let path = crypto::decrypt_text(&mdk, &r.path_enc, &aad(&r.id, "path")).unwrap_or_default();
    let q: Option<QuickState> = r.quick.as_deref().and_then(|s| serde_json::from_str(s).ok());
    VaultInfo {
        id: r.id.clone(),
        name,
        original_path: path,
        vault_path: r.vault_path.clone(),
        mode: r.mode.clone(),
        key_mode: r.key_mode.clone(),
        status: r.status.clone(),
        size_bytes: r.size,
        file_count: r.files,
        skipped_count: r.skipped,
        locked_at: r.locked_at,
        created_at: r.created_at,
        hidden: q.as_ref().map(|q| q.hidden),
        moved: q.as_ref().map(|q| q.moved),
        busy: st.ops.is_vault_busy(&r.id),
        restored_path: r.restored_enc.as_deref().and_then(|e| crypto::decrypt_text(&mdk, e, &aad(&r.id, "restored")).ok()),
    }
}

/// Unwraps a Secure Lock vault key with the given credential (rate limited) and verifies the header MAC.
fn secure_vault_key(st: &AppState, row: &VaultRow, cred: &Credential) -> Result<Key32> {
    if row.mode != "secure" {
        return invalid("not a Secure Lock vault");
    }
    let secret = Zeroizing::new(cred.secret.clone());
    let header = VaultHeader::read(Path::new(&row.vault_path))?;
    if cred.kind == "hello" {
        // Not under the rate limiter: Windows Hello has its own lockout, and
        // its prompt must not hold the limiter's gate while the user responds.
        let mk = hello::unlock(&st.db)?;
        let vk = header.unwrap_with_master(&mk)?;
        header.verify_mac(&vk)?;
        return Ok(vk);
    }
    let meta = auth::load_metadata(&st.db)?.ok_or(Error::NotInitialized)?;
    let vk = RateLimiter::guarded(&st.db, || match cred.kind.as_str() {
        "master" => {
            let mk = auth::unwrap_master(&meta, &secret)?;
            header.unwrap_with_master(&mk)
        }
        "folder" => header.unwrap_with_password(&secret),
        "recovery" => header.unwrap_with_recovery(&*crypto::decode_recovery_key(&secret)?),
        _ => Err(Error::Invalid("unknown credential type".into())),
    })?;
    header.verify_mac(&vk)?;
    Ok(vk)
}

const QUICK_VERIFIER: &[u8] = b"dirshield-quick-lock-verifier";

/// Authenticates access to a Quick-Locked folder.
fn quick_verify(st: &AppState, row: &VaultRow, cred: &Credential) -> Result<()> {
    if cred.kind == "hello" {
        if row.key_mode != "master" {
            return Err(Error::AuthFailed);
        }
        return hello::unlock(&st.db).map(|_| ());
    }
    let secret = Zeroizing::new(cred.secret.clone());
    let meta = auth::load_metadata(&st.db)?.ok_or(Error::NotInitialized)?;
    RateLimiter::guarded(&st.db, || match cred.kind.as_str() {
        "master" if row.key_mode == "master" => auth::unwrap_master(&meta, &secret).map(|_| ()),
        "master" => Err(Error::AuthFailed),
        "folder" => {
            let w: String = st
                .db
                .lock()
                .query_row("SELECT wrapped_vault_key FROM vault_key_wrappers WHERE vault_id=?1 AND wrapper_type='quick_password'", [&row.id], |r| r.get(0))
                .optional()?
                .ok_or(Error::AuthFailed)?;
            let (kdf, sealed): (KdfParams, crypto::Sealed) = serde_json::from_str(&w)?;
            let k = crypto::derive_password_key(&secret, &kdf)?;
            crypto::open(&k, &sealed, &aad(&row.id, "quick")).map(|_| ())
        }
        "recovery" => auth::unwrap_master_with_recovery(&meta, &secret).map(|_| ()),
        _ => Err(Error::Invalid("unknown credential type".into())),
    })
}

fn store_quick_verifier(st: &AppState, id: &str, password: &str) -> Result<()> {
    let kdf = KdfParams::new_default();
    let k = crypto::derive_password_key(password, &kdf)?;
    let sealed = crypto::seal(&k, QUICK_VERIFIER, &aad(id, "quick"));
    let c = st.db.lock();
    c.execute("DELETE FROM vault_key_wrappers WHERE vault_id=?1 AND wrapper_type='quick_password'", [id])?;
    c.execute(
        "INSERT INTO vault_key_wrappers(vault_id, wrapper_type, kdf_salt, kdf_parameters, wrapped_vault_key, created_at) VALUES(?1,'quick_password',?2,?3,?4,?5)",
        params![id, hex::encode(&kdf.salt), serde_json::to_string(&kdf)?, serde_json::to_string(&(kdf.clone(), sealed))?, now_ms()],
    )?;
    Ok(())
}

/// Folders that must never be locked: system locations, profile roots and
/// well-known folders, DirShield's own storage, and anything overlapping an
/// already protected folder.
/// `except`: the vault whose own folder this is (when re-locking it).
fn validate_target(st: &AppState, mk: &[u8; 32], raw: &str, except: Option<&str>) -> Result<PathBuf> {
    let p = fsutil::normalize(Path::new(raw))?;
    let meta = std::fs::symlink_metadata(&p)?;
    if !meta.is_dir() || scan::is_link(&meta) {
        return invalid("Select a regular folder. Files, symbolic links and junctions can't be locked.");
    }
    if p.parent().is_none() || p.parent() == Some(Path::new("")) {
        return invalid("Whole drives can't be locked. Choose a folder instead.");
    }
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    for k in ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "ProgramW6432"] {
        if let Some(sys) = env(k) {
            if is_same_or_inside(&p, &sys) || is_same_or_inside(&sys, &p) {
                return invalid("System and program folders can't be locked.");
            }
        }
    }
    if let Some(profile) = env("USERPROFILE") {
        if is_same_or_inside(&profile, &p) {
            return invalid("Your user profile folder (or a folder containing it) can't be locked. Choose a folder inside it.");
        }
        for k in ["Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos", "OneDrive", "AppData"] {
            if fsutil::path_key(&p) == fsutil::path_key(&profile.join(k)) {
                return invalid(format!("The {k} folder itself can't be locked. Choose a folder inside it."));
            }
        }
        if is_same_or_inside(&p, &profile.join("AppData")) {
            return invalid("Application data folders can't be locked.");
        }
    }
    if is_same_or_inside(&p, &st.dirs.base) || is_same_or_inside(&st.dirs.base, &p) {
        return invalid("This folder contains DirShield's own storage.");
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if is_same_or_inside(dir, &p) {
                return invalid("This folder contains the DirShield application.");
            }
        }
    }
    let vault_root = default_vault_root(st);
    if is_same_or_inside(&vault_root, &p) {
        return invalid("This folder contains the DirShield vault storage location.");
    }
    for r in all_vaults(st)? {
        if r.status == "restored" || Some(r.id.as_str()) == except {
            continue;
        }
        let i = info(st, mk, &r);
        let orig = PathBuf::from(&i.original_path);
        if is_same_or_inside(&p, &orig) || is_same_or_inside(&orig, &p) {
            return Err(Error::Conflict(format!("This folder overlaps \"{}\", which is already protected.", i.name)));
        }
        if r.mode == "secure" && (is_same_or_inside(Path::new(&r.vault_path), &p) || is_same_or_inside(&p, Path::new(&r.vault_path))) {
            return invalid("This folder contains DirShield vault data.");
        }
    }
    Ok(p)
}

fn default_vault_root(st: &AppState) -> PathBuf {
    st.db.get_setting("defaultVaultRoot").ok().flatten().filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or_else(|| st.dirs.vaults.clone())
}

fn workers(st: &AppState) -> usize {
    st.db.get_setting("concurrency").ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(2usize).clamp(1, 8)
}

fn emit_vaults_changed(app: &AppHandle) {
    let _ = app.emit("vaults-changed", ());
}

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
    run(&app, move |_, st| {
        let password = Zeroizing::new(password);
        let mk = verify_master(st, &password)?;
        st.session.unlock(mk);
        st.db.log("sign_in", None, "success", None);
        Ok(())
    })
    .await
}

/// Signs in with Windows Hello instead of the master password.
#[tauri::command]
pub async fn login_hello(app: AppHandle) -> Result<()> {
    run(&app, move |_, st| {
        auth::load_metadata(&st.db)?.ok_or(Error::NotInitialized)?;
        let mk = hello::unlock(&st.db)?;
        st.session.unlock(mk);
        st.db.log("sign_in_windows_hello", None, "success", None);
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
    run(&app, |app, st| {
        st.lock_session();
        let _ = app.emit("session-locked", ());
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
        st.session.unlock(mk);
        st.db.log("reset_master_password_with_recovery_key", None, "success", None);
        Ok(())
    })
    .await
}

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
}

#[tauri::command]
pub async fn vault_details(app: AppHandle, id: String) -> Result<VaultDetails> {
    run(&app, move |_, st| {
        let mk = st.session.master()?;
        let r = load_vault(st, &id)?;
        let mut d = VaultDetails { info: info(st, &mk, &r), wrappers: vec![], algorithm: None, chunk_size: None, sealed: None, current_path: None, format_version: None };
        if r.mode == "secure" {
            if let Ok(h) = VaultHeader::read(Path::new(&r.vault_path)) {
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
fn quick_lock_impl(app: &AppHandle, st: &AppState, mk: &Key32, path: &str, folder_password: Option<&str>, hide: bool) -> Result<VaultInfo> {
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

fn quick_unlock_core(app: &AppHandle, st: &AppState, r: &VaultRow, original: &Path, dest: Option<&Path>) -> Result<String> {
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

fn quick_set_hidden_core(app: &AppHandle, st: &AppState, r: &VaultRow, hidden: bool) -> Result<()> {
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
    crate::show_main(app);
    if let Some(w) = app.get_webview_window("prompt") {
        let _ = w.close();
    }
}

/// The prompt was opened by the uninstaller (`--confirm-uninstall`).
fn is_uninstall_prompt(st: &AppState) -> bool {
    crate::UNINSTALL_MODE.load(std::sync::atomic::Ordering::Relaxed) && st.prompt.lock().as_ref().is_some_and(|a| a.action == "uninstall")
}

fn folder_name(path: &str) -> String {
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
            crate::UNINSTALL_CONFIRMED.store(true, std::sync::atomic::Ordering::Relaxed);
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
    crate::show_main(&app);
    if let Some(w) = app.get_webview_window("prompt") {
        let _ = w.close();
    }
}

/// Main window size: compact while signed out, full once signed in.
#[tauri::command]
pub fn set_window_mode(app: AppHandle, full: bool, width: Option<f64>, height: Option<f64>) {
    if let Some(w) = app.get_webview_window("main") {
        crate::apply_window_mode(&w, full, width.zip(height));
    }
}

#[tauri::command]
pub fn prompt_close(app: AppHandle) {
    if let Some(w) = app.get_webview_window("prompt") {
        let _ = w.close();
    }
}

// ---------------- Secure Lock ----------------

fn spawn_encrypt(app: &AppHandle, st: &AppState, op_id: String, vault_id: String, vault_dir: PathBuf, source: PathBuf, name: String, vk: Key32, total_files: u64, total_bytes: u64) -> Result<()> {
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
        let wrappers = vec![primary, header::recovery_wrapper(&vault_id, &meta.recovery_pub()?, &meta.recovery_id, &meta.recovery_salt, &vk)?];
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
fn spawn_decrypt(
    app: &AppHandle,
    st: &AppState,
    op_id: String,
    vault_id: String,
    vault_dir: PathBuf,
    vk: Key32,
    p: DecryptParams,
    restored_enc: Option<String>,
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
                    db2.log(action, Some(&vault_id), "success", None)
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

fn restored_enc(mk: &[u8; 32], vault_id: &str, dest: &str) -> String {
    crypto::encrypt_text(&crypto::metadata_key(mk), dest, &aad(vault_id, "restored"))
}

/// Destination checks shared by restore and extract.
fn check_dest(st: &AppState, r: &VaultRow, dest: &Path) -> Result<()> {
    if !dest.is_absolute() {
        return invalid("Choose an absolute destination path.");
    }
    if is_same_or_inside(dest, Path::new(&r.vault_path)) || is_same_or_inside(dest, &st.dirs.base) {
        return invalid("Can't restore into DirShield's own storage.");
    }
    Ok(())
}

#[tauri::command]
pub async fn restore_vault(app: AppHandle, id: String, credential: Credential, dest: Option<String>, conflict: String) -> Result<String> {
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
        close_browsers_for(st, &id);
        spawn_decrypt(app, st, op_id.clone(), id, PathBuf::from(&r.vault_path), vk, p, Some(enc), tf as u64, tb as u64)?;
        emit_vaults_changed(app);
        Ok(op_id)
    })
    .await
}

// ---------------- Browse a vault, extract or open single files ----------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowseInfo {
    token: String,
    name: String,
    files: u64,
    bytes: u64,
}

fn close_browsers_for(st: &AppState, vault_id: &str) {
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
        spawn_decrypt(app, st, op_id.clone(), r.id.clone(), s.vault_dir.clone(), Key32::new(*s.vk), p, None, tf as u64, tb as u64)?;
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

// ---------------- Re-lock (update a vault, re-encrypting only changes) ----------------

fn spawn_relock(app: &AppHandle, st: &AppState, op_id: String, vault_id: String, vault_dir: PathBuf, source: PathBuf, name: String, vk: Key32, total_files: u64, total_bytes: u64) -> Result<()> {
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
            engine::run_relock(&EncryptJob { db: &db, op_id: &opid, vault_id: &vid, vault_dir: &vault_dir, source: &source, root_name: &name, original_path: &original, vk: &vk, workers: w, ctrl })
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
        spawn_relock(app, st, op_id.clone(), id, PathBuf::from(&r.vault_path), src, name, vk, tf as u64, tb as u64)?;
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
        let op_id = engine::create_operation(&st.db, &id, "verify", "{}")?;
        st.db.lock().execute("UPDATE operations SET total_files=?2, total_bytes=?3 WHERE id=?1", params![op_id, r.files, r.size])?;
        let db = st.db.clone();
        let app2 = app.clone();
        let dir = PathBuf::from(&r.vault_path);
        let vid = id.clone();
        let opid = op_id.clone();
        st.ops.spawn(
            app.clone(),
            st.db.clone(),
            op_id.clone(),
            id,
            "verify",
            r.files as u64,
            r.size as u64,
            move |ctrl| engine::verify_vault(&dir, &vk, ctrl).map(|_| ()),
            move |res| {
                match res {
                    Ok(()) => db.log("verify_vault", Some(&vid), "success", None),
                    Err(e) => db.log("verify_vault", Some(&vid), "failed", Some(&e.to_string())),
                }
                let _ = opid;
                emit_vaults_changed(&app2);
            },
        )?;
        Ok(op_id)
    })
    .await
}

#[tauri::command]
pub async fn remove_originals(app: AppHandle, id: String, credential: Credential, confirm_name: String) -> Result<String> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let r = load_vault(st, &id)?;
        if r.status != "encrypted" {
            return invalid("Originals can only be removed from a completed, verified vault.");
        }
        let i = info(st, &mk, &r);
        if confirm_name.trim() != i.name {
            return invalid("Type the folder name exactly to confirm.");
        }
        let vk = secure_vault_key(st, &r, &credential)?;
        let op_id = engine::create_operation(&st.db, &id, "cleanup", "{}")?;
        engine::set_vault_status(&st.db, &id, "removing")?;
        let db = st.db.clone();
        let app2 = app.clone();
        let dir = PathBuf::from(&r.vault_path);
        let root = PathBuf::from(&i.original_path);
        let vid = id.clone();
        let opid = op_id.clone();
        let report: std::sync::Arc<parking_lot::Mutex<Option<CleanupReport>>> = Default::default();
        let rep2 = report.clone();
        st.ops.spawn(
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
        )?;
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
            let recovery: Vec<KeyWrapper> = h.wrappers.iter().filter(|w| matches!(w, KeyWrapper::RecoveryEscrow { .. })).cloned().collect();
            let primary = match new_pw {
                Some(pw) => header::password_wrapper(&h.vault_id, pw, &vk)?,
                None => header::master_wrapper(&h.vault_id, &mk, &vk),
            };
            h.wrappers = std::iter::once(primary).chain(recovery).collect();
            h.compute_mac(&vk)?;
            h.write_atomic(&dir)?; // only the small header is rewritten; no data is re-encrypted
            let c = st.db.lock();
            c.execute("DELETE FROM vault_key_wrappers WHERE vault_id=?1", [&id])?;
            for w in &h.wrappers {
                c.execute("INSERT INTO vault_key_wrappers(vault_id, wrapper_type, wrapped_vault_key, created_at) VALUES(?1,?2,?3,?4)", params![id, w.kind(), serde_json::to_string(w)?, now_ms()])?;
            }
        }
        st.db.lock().execute("UPDATE vaults SET key_mode=?2, updated_at=?3 WHERE id=?1", params![id, new_mode, now_ms()])?;
        st.db.log("change_folder_password", Some(&id), "success", Some(&new_mode));
        emit_vaults_changed(app);
        Ok(())
    })
    .await
}

/// Registers a vault directory found on disk (e.g. after reinstalling or losing
/// the database) using the recovery key. Re-wraps it for the current master key.
#[tauri::command]
pub async fn import_vault(app: AppHandle, path: String, recovery_key: String) -> Result<VaultInfo> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        let rk = Zeroizing::new(recovery_key);
        let dir = fsutil::normalize(Path::new(&path))?;
        let mut h = VaultHeader::read(&dir)?;
        if load_vault(st, &h.vault_id).is_ok() {
            return Err(Error::Conflict("This vault is already in DirShield.".into()));
        }
        if !h.sealed {
            return invalid("This vault was never completed and can't be imported.");
        }
        let rk_bytes = crypto::decode_recovery_key(&rk)?;
        let vk = RateLimiter::guarded(&st.db, || h.unwrap_with_recovery(&rk_bytes))?;
        h.verify_mac(&vk)?;
        let (name, original, files, bytes) = engine::manifest_summary(&dir, &vk)?;
        let recovery: Vec<KeyWrapper> = h.wrappers.iter().filter(|w| matches!(w, KeyWrapper::RecoveryEscrow { .. })).cloned().collect();
        h.wrappers = std::iter::once(header::master_wrapper(&h.vault_id, &mk, &vk)).chain(recovery).collect();
        h.compute_mac(&vk)?;
        h.write_atomic(&dir)?;
        let mdk = crypto::metadata_key(&mk);
        let id = h.vault_id.clone();
        let now = now_ms();
        st.db.lock().execute(
            "INSERT INTO vaults(id, name, original_path, vault_path, protection_mode, key_mode, status, size_bytes, file_count, locked_at, created_at, updated_at)
             VALUES(?1,?2,?3,?4,'secure','master','locked',?5,?6,?7,?7,?7)",
            params![id, crypto::encrypt_text(&mdk, &name, &aad(&id, "name")), crypto::encrypt_text(&mdk, &original, &aad(&id, "path")), fsutil::display_path(&dir), bytes as i64, files as i64, now],
        )?;
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
    live: Option<crate::ops::Progress>,
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
                spawn_decrypt(app, st, id.clone(), vault_id.clone(), PathBuf::from(&r.vault_path), vk, p, enc, tf as u64, tb as u64)?;
            }
            "relock" => {
                let p = engine::load_relock_params(&st.db, &id)?;
                let src = PathBuf::from(&p.source);
                let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                spawn_relock(app, st, id.clone(), vault_id.clone(), PathBuf::from(&r.vault_path), src, name, vk, tf as u64, tb as u64)?;
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

// ---------------------------------------------------------------------------
// Activity, settings, shell integration
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    id: i64,
    action: String,
    vault_id: Option<String>,
    vault_name: Option<String>,
    status: String,
    detail: Option<String>,
    created_at: i64,
}

#[tauri::command]
pub async fn list_activity(app: AppHandle, limit: i64) -> Result<Vec<Activity>> {
    run(&app, move |_, st| {
        let mk = st.session.master()?;
        let mdk = crypto::metadata_key(&mk);
        let c = st.db.lock();
        let mut s = c.prepare(
            "SELECT a.id, a.action, a.vault_id, v.name, a.status, a.detail, a.created_at FROM activity_logs a LEFT JOIN vaults v ON v.id=a.vault_id
             ORDER BY a.created_at DESC, a.id DESC LIMIT ?1",
        )?;
        let rows = s
            .query_map([limit.clamp(1, 2000)], |r| {
                let vid: Option<String> = r.get(2)?;
                let name: Option<String> = r.get(3)?;
                Ok(Activity {
                    vault_name: match (&vid, name) {
                        (Some(v), Some(n)) => crypto::decrypt_text(&mdk, &n, &aad(v, "name")).ok(),
                        _ => None,
                    },
                    id: r.get(0)?,
                    action: r.get(1)?,
                    vault_id: vid,
                    status: r.get(4)?,
                    detail: r.get(5)?,
                    created_at: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await
}

#[tauri::command]
pub async fn clear_activity(app: AppHandle) -> Result<()> {
    run(&app, |_, st| {
        st.session.master_active()?;
        st.db.lock().execute("DELETE FROM activity_logs", [])?;
        Ok(())
    })
    .await
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    theme: String,
    auto_lock_minutes: u32,
    concurrency: u32,
    default_vault_root: String,
    context_menu: bool,
    context_menu_current: bool,
    launch_at_startup: bool,
}

#[tauri::command]
pub async fn get_settings(app: AppHandle) -> Result<Settings> {
    run(&app, |_, st| {
        let g = |k: &str, d: &str| st.db.get_setting(k).ok().flatten().unwrap_or_else(|| d.to_string());
        let (menu, current) = shell::context_menu_status();
        Ok(Settings {
            theme: g("theme", "system"),
            auto_lock_minutes: g("autoLockMinutes", "10").parse().unwrap_or(10),
            concurrency: g("concurrency", "2").parse().unwrap_or(2),
            default_vault_root: fsutil::display_path(&default_vault_root(st)),
            context_menu: menu,
            context_menu_current: current,
            launch_at_startup: shell::autostart_enabled(),
        })
    })
    .await
}

#[tauri::command]
pub async fn save_settings(app: AppHandle, settings: Settings) -> Result<()> {
    run(&app, move |app, st| {
        st.session.master_active()?;
        if !matches!(settings.theme.as_str(), "system" | "light" | "dark") {
            return invalid("invalid theme");
        }
        st.db.set_setting("theme", &settings.theme)?;
        let mins = settings.auto_lock_minutes.min(240);
        st.db.set_setting("autoLockMinutes", &mins.to_string())?;
        st.session.set_timeout(Duration::from_secs(mins as u64 * 60));
        st.db.set_setting("concurrency", &settings.concurrency.clamp(1, 8).to_string())?;
        let root = settings.default_vault_root.trim();
        if !root.is_empty() {
            let p = PathBuf::from(root);
            if !p.is_absolute() {
                return invalid("The vault location must be an absolute path.");
            }
            std::fs::create_dir_all(&p)?;
            st.db.set_setting("defaultVaultRoot", &fsutil::display_path(&fsutil::normalize(&p)?))?;
        }
        if settings.context_menu {
            shell::register_context_menu()?;
        } else {
            shell::unregister_context_menu()?;
        }
        st.db.set_setting("contextMenu", if settings.context_menu { "true" } else { "false" })?;
        shell::set_autostart(settings.launch_at_startup)?;
        if let Some(w) = app.get_webview_window("main") {
            let theme = match settings.theme.as_str() {
                "light" => Some(tauri::Theme::Light),
                "dark" => Some(tauri::Theme::Dark),
                _ => None,
            };
            let _ = w.set_theme(theme);
        }
        st.db.log("settings_changed", None, "success", None);
        Ok(())
    })
    .await
}

#[tauri::command]
pub fn take_pending_action(state: tauri::State<'_, AppState>) -> Option<ShellAction> {
    state.pending.lock().take()
}

#[tauri::command]
pub async fn open_in_explorer(app: AppHandle, path: String) -> Result<()> {
    run(&app, move |_, st| {
        st.session.master_active()?;
        let p = PathBuf::from(&path);
        if !p.is_absolute() || !p.exists() {
            return invalid("That location doesn't exist.");
        }
        // Path is passed as a single argument (no shell interpretation).
        std::process::Command::new("explorer.exe").arg(&p).spawn()?;
        Ok(())
    })
    .await
}
