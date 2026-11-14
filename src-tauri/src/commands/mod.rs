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

use crate::app::{AppState, BrowseSession, WorkSession};
use crate::domain::error::{invalid, Error, Result};
use crate::platform::fsutil::{self, is_same_or_inside};
use crate::platform::search;
use crate::platform::shell::{self, ShellAction};
use crate::quicklock::{self, QuickState};
use crate::security::auth::{self, RateLimiter};
use crate::security::crypto::{self, KdfParams, Key32};
use crate::security::hello;
use crate::storage::db::now_ms;
use crate::vault::browse::{self, Entry as BrowseEntry, VaultIndex};
use crate::vault::engine::{self, CleanupReport, DecryptParams, EncryptJob, NewVaultSpec, RelockParams};
use crate::vault::header::{self, KeyWrapper, VaultHeader};
use crate::vault::scan::{self, ScanReport};
use crate::vault::stream::DEFAULT_CHUNK;

mod account;
mod background;
mod operations;
mod prompt;
mod settings;
mod vault_browse;
mod vaults;

pub use account::*;
pub use background::*;
pub use operations::*;
pub use prompt::*;
pub use settings::*;
pub use vault_browse::*;
pub use vaults::*;

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
    /// Restored for a work session: it is locked again when DirShield signs out.
    pub work_session: bool,
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
        work_session: st.work.lock().contains_key(&r.id),
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
// Vault header key wrappers
// ---------------------------------------------------------------------------

/// "Open vaults on another PC with the master password" is on.
fn portable_enabled(st: &AppState) -> bool {
    st.db.get_setting("portableVaults").ok().flatten().as_deref() == Some("true")
}

/// A vault's full set of key wrappers for this install: `primary` (the
/// master key or folder password wrapper), the portable master-password copy
/// for master-key vaults when that setting is on, and an escrow for the
/// current recovery key.
fn header_wrappers(st: &AppState, meta: &auth::MasterKeyMetadata, vault_id: &str, vk: &[u8; 32], primary: KeyWrapper) -> Result<Vec<KeyWrapper>> {
    let master = matches!(primary, KeyWrapper::Master { .. });
    let mut w = vec![primary];
    if master && portable_enabled(st) {
        w.push(KeyWrapper::MasterPassword { kdf: meta.kdf.clone(), sealed: meta.mk_by_password.clone() });
    }
    w.push(header::recovery_wrapper(vault_id, &meta.recovery_pub()?, &meta.recovery_id, &meta.recovery_salt, vk)?);
    Ok(w)
}

/// Re-MACs and atomically rewrites a vault header (only the small header;
/// no data is re-encrypted) and mirrors its wrappers into the database.
fn write_header(st: &AppState, id: &str, dir: &Path, h: &mut VaultHeader, vk: &[u8; 32]) -> Result<()> {
    h.compute_mac(vk)?;
    h.write_atomic(dir)?;
    let c = st.db.lock();
    c.execute("DELETE FROM vault_key_wrappers WHERE vault_id=?1 AND wrapper_type!='quick_password'", [id])?;
    for w in &h.wrappers {
        c.execute("INSERT INTO vault_key_wrappers(vault_id, wrapper_type, wrapped_vault_key, created_at) VALUES(?1,?2,?3,?4)", params![id, w.kind(), serde_json::to_string(w)?, now_ms()])?;
    }
    Ok(())
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    /// Vault headers brought up to date.
    pub updated: u32,
    /// Vaults that couldn't be updated now: their storage is unavailable,
    /// or they use a folder password (they're updated the next time that
    /// password is changed or entered again).
    pub pending: Vec<String>,
    /// Operations were running; the update runs automatically once they finish.
    pub deferred: bool,
}

/// Brings every Secure Lock vault header in line with the current master
/// key metadata: the current recovery escrow, and the portable master
/// password copy (added, refreshed or removed). Needs the master key, so
/// only master-key vaults can be updated; folder-password vaults are listed
/// as pending if their recovery escrow is out of date.
///
/// Headers are never rewritten while an operation runs (encryption keeps the
/// header in memory and writes it at the end); the update is then deferred
/// and retried by the background task.
fn sync_headers(st: &AppState, mk: &[u8; 32]) -> Result<SyncReport> {
    let mut rep = SyncReport::default();
    if st.ops.any_active() {
        st.db.set_setting("headersDirty", "1")?;
        rep.deferred = true;
        return Ok(rep);
    }
    let meta = auth::load_metadata(&st.db)?.ok_or(Error::NotInitialized)?;
    for r in all_vaults(st)? {
        if r.mode != "secure" {
            continue;
        }
        let name = || info(st, mk, &r).name;
        let dir = PathBuf::from(&r.vault_path);
        let Ok(mut h) = VaultHeader::read(&dir) else {
            rep.pending.push(name());
            continue;
        };
        match h.unwrap_with_master(mk).and_then(|vk| h.verify_mac(&vk).map(|_| vk)) {
            Ok(vk) => {
                h.wrappers = header_wrappers(st, &meta, &h.vault_id.clone(), &vk, header::master_wrapper(&h.vault_id, mk, &vk))?;
                match write_header(st, &r.id, &dir, &mut h, &vk) {
                    Ok(()) => rep.updated += 1,
                    Err(_) => rep.pending.push(name()),
                }
            }
            Err(_) => {
                if h.recovery_id() != Some(meta.recovery_id.as_str()) {
                    rep.pending.push(name());
                }
            }
        }
    }
    st.db.set_setting("headersDirty", "0")?;
    Ok(rep)
}
