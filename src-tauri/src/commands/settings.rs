//! Activity log, settings and shell integration.

use super::*;

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

/// Which log entries to list or export. Empty fields match everything.
#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase", default)]
pub struct ActivityFilter {
    /// An `action` code such as `quick_lock`.
    action: Option<String>,
    /// Entries about this protected folder.
    vault_id: Option<String>,
    /// Entries about folders DirShield no longer protects (their names are gone).
    removed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityPage {
    rows: Vec<Activity>,
    /// Entries matching the filter, across all pages.
    total: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityFolder {
    id: String,
    name: String,
}

/// The values the Activity filters can offer.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityFacets {
    actions: Vec<String>,
    folders: Vec<ActivityFolder>,
    /// Some entries are about folders that are no longer protected.
    has_removed: bool,
}

const ACTIVITY_FROM: &str = "FROM activity_logs a LEFT JOIN vaults v ON v.id=a.vault_id
     WHERE (?1 IS NULL OR a.action=?1) AND (?2 IS NULL OR a.vault_id=?2) AND (?3=0 OR (a.vault_id IS NOT NULL AND v.id IS NULL))";

/// Matching entries, newest first. `limit` < 0 means all of them.
fn query_activity(st: &AppState, mk: &[u8; 32], f: &ActivityFilter, offset: i64, limit: i64) -> Result<Vec<Activity>> {
    let mdk = crypto::metadata_key(mk);
    let c = st.db.lock();
    let mut s = c.prepare(&format!("SELECT a.id, a.action, a.vault_id, v.name, a.status, a.detail, a.created_at {ACTIVITY_FROM} ORDER BY a.created_at DESC, a.id DESC LIMIT ?4 OFFSET ?5"))?;
    let rows = s
        .query_map(params![f.action, f.vault_id, f.removed, limit, offset.max(0)], |r| {
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
}

/// One page of the activity log, newest first.
#[tauri::command]
pub async fn list_activity(app: AppHandle, filter: Option<ActivityFilter>, offset: i64, limit: i64) -> Result<ActivityPage> {
    run(&app, move |_, st| {
        let mk = st.session.master()?;
        let f = filter.unwrap_or_default();
        let total: i64 = st.db.lock().query_row(&format!("SELECT COUNT(*) {ACTIVITY_FROM}"), params![f.action, f.vault_id, f.removed], |r| r.get(0))?;
        let rows = query_activity(st, &mk, &f, offset, limit.clamp(1, 500))?;
        Ok(ActivityPage { rows, total })
    })
    .await
}

/// The actions and folders that appear in the log, for the filters.
#[tauri::command]
pub async fn activity_facets(app: AppHandle) -> Result<ActivityFacets> {
    run(&app, move |_, st| {
        let mk = st.session.master()?;
        let mdk = crypto::metadata_key(&mk);
        let c = st.db.lock();
        let actions = c.prepare("SELECT DISTINCT action FROM activity_logs ORDER BY action")?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        let mut folders = c
            .prepare("SELECT DISTINCT v.id, v.name FROM activity_logs a JOIN vaults v ON v.id=a.vault_id")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|(id, n)| crypto::decrypt_text(&mdk, &n, &aad(&id, "name")).ok().map(|name| ActivityFolder { id, name }))
            .collect::<Vec<_>>();
        folders.sort_by_key(|f| f.name.to_lowercase());
        let has_removed = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM activity_logs a LEFT JOIN vaults v ON v.id=a.vault_id WHERE a.vault_id IS NOT NULL AND v.id IS NULL)",
            [],
            |r| r.get(0),
        )?;
        Ok(ActivityFacets { actions, folders, has_removed })
    })
    .await
}

/// Writes the entries matching `filter` to a CSV file at `dest`. `labels`
/// maps action codes to the names the app shows. Returns the rows written.
#[tauri::command]
pub async fn export_activity_csv(app: AppHandle, dest: String, filter: Option<ActivityFilter>, labels: std::collections::HashMap<String, String>) -> Result<usize> {
    run(&app, move |_, st| {
        let mk = st.session.master_active()?;
        let mut dest = PathBuf::from(dest.trim());
        if !dest.is_absolute() {
            return invalid("Choose where to save the file.");
        }
        if !dest.extension().is_some_and(|e| e.eq_ignore_ascii_case("csv")) {
            dest.set_extension("csv");
        }
        if is_same_or_inside(&dest, &st.dirs.base) {
            return invalid("Save the file outside DirShield's own storage.");
        }
        let rows = query_activity(st, &mk, &filter.unwrap_or_default(), 0, -1)?;
        // The byte order mark makes Excel read the file as UTF-8.
        let mut out = String::from("\u{feff}Time (UTC),Action,Action code,Folder,Result,Details\r\n");
        for r in &rows {
            let folder = match (&r.vault_name, &r.vault_id) {
                (Some(n), _) => n.clone(),
                (None, Some(_)) => "(removed)".into(),
                (None, None) => String::new(),
            };
            let cells = [
                utc_time(r.created_at),
                labels.get(&r.action).cloned().unwrap_or_else(|| r.action.replace('_', " ")),
                r.action.clone(),
                folder,
                status_label(&r.status).to_string(),
                r.detail.clone().unwrap_or_default(),
            ];
            out.push_str(&cells.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
            out.push_str("\r\n");
        }
        std::fs::write(&dest, out)?;
        st.db.log("activity_exported", None, "success", Some(&format!("{} entries", rows.len())));
        Ok(rows.len())
    })
    .await
}

/// Result names as the app shows them (keep in sync with `activityStatusLabel` in src/lib/format.ts).
fn status_label(s: &str) -> &str {
    match s {
        "success" => "Succeeded",
        "failed" => "Failed",
        "cancelled" => "Cancelled",
        "warning" => "Warning",
        "info" => "Info",
        other => other,
    }
}

/// A CSV field, quoted when needed. Text a spreadsheet would run as a
/// formula gets a leading apostrophe: folder names and error details come
/// from outside DirShield.
fn csv_cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// Milliseconds since 1970 as `YYYY-MM-DD HH:MM:SS` (UTC).
fn utc_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Days to civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[tauri::command]
pub async fn clear_activity(app: AppHandle) -> Result<()> {
    run(&app, |_, st| {
        let mk = st.session.master_active()?;
        st.db.clear_log(&mk)
    })
    .await
}

/// Checks the activity log's hash chain and sealed checkpoint.
#[tauri::command]
pub async fn verify_activity_log(app: AppHandle) -> Result<crate::storage::db::LogCheck> {
    run(&app, |_, st| {
        let mk = st.session.master_active()?;
        // Seal what is there now first, so only earlier tampering shows up.
        let before = st.db.verify_log(&mk)?;
        if before.ok {
            st.db.checkpoint_log(&mk)?;
            return st.db.verify_log(&mk);
        }
        Ok(before)
    })
    .await
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    theme: String,
    /// 0 means never auto-lock (shown as "Never" in Settings).
    auto_lock_minutes: u32,
    concurrency: u32,
    default_vault_root: String,
    context_menu: bool,
    context_menu_current: bool,
    launch_at_startup: bool,
    /// Sign out when Windows locks, signs out or goes to sleep.
    #[serde(default = "yes")]
    sign_out_on_lock: bool,
    /// Days between scheduled integrity checks (0 = off).
    #[serde(default = "thirty")]
    verify_interval_days: u32,
    /// Read-only here: changed with `set_portable_vaults`.
    #[serde(default)]
    portable_vaults: bool,
    /// Read-only: when the last backup was made (ms), if ever.
    #[serde(default)]
    last_backup_at: Option<i64>,
}

fn yes() -> bool {
    true
}

fn thirty() -> u32 {
    30
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
            sign_out_on_lock: g("signOutOnLock", "true") != "false",
            verify_interval_days: g("verifyIntervalDays", "30").parse().unwrap_or(30),
            portable_vaults: g("portableVaults", "false") == "true",
            last_backup_at: st.db.get_setting("lastBackupAt").ok().flatten().and_then(|v| v.parse().ok()),
        })
    })
    .await
}

/// `raw` made absolute and canonical without requiring it to exist yet: the
/// deepest existing ancestor is canonicalised and the rest appended.
fn normalize_new_dir(raw: &Path) -> Result<PathBuf> {
    use std::path::Component;
    if !raw.is_absolute() {
        return invalid("The vault location must be an absolute path.");
    }
    if raw.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
        return invalid("The vault location can't contain \".\" or \"..\".");
    }
    let mut existing = raw;
    let mut rest = Vec::new();
    while !existing.exists() {
        rest.push(existing.file_name().ok_or_else(|| Error::NotFound(raw.display().to_string()))?.to_owned());
        existing = existing.parent().ok_or_else(|| Error::NotFound(raw.display().to_string()))?;
    }
    let mut p = fsutil::normalize(existing)?;
    if !p.is_dir() {
        return invalid("The vault location must be a folder.");
    }
    for c in rest.iter().rev() {
        p.push(c);
    }
    Ok(p)
}

#[tauri::command]
pub async fn save_settings(app: AppHandle, settings: Settings) -> Result<()> {
    run(&app, move |app, st| {
        let mk = st.session.master_active()?;
        // Everything is checked before anything is saved, so a rejected
        // value never leaves the other settings half applied.
        let theme = match settings.theme.as_str() {
            "light" => Some(tauri::Theme::Light),
            "dark" => Some(tauri::Theme::Dark),
            "system" => None,
            _ => return invalid("invalid theme"),
        };
        let root = settings.default_vault_root.trim();
        let new_root = if root.is_empty() || fsutil::path_key(Path::new(root)) == fsutil::path_key(&default_vault_root(st)) {
            None
        } else {
            let p = normalize_new_dir(Path::new(root))?;
            policy::check_vault_root(&p, &target_context(st, &mk, None, true)?)?;
            Some(p)
        };

        // Changes outside the database first: they are the ones that can fail.
        if let Some(p) = &new_root {
            std::fs::create_dir_all(p)?;
        }
        if settings.context_menu {
            shell::register_context_menu()?;
        } else {
            shell::unregister_context_menu()?;
        }
        shell::set_autostart(settings.launch_at_startup)?;

        let mins = settings.auto_lock_minutes.min(240);
        st.db.set_setting("theme", &settings.theme)?;
        st.db.set_setting("autoLockMinutes", &mins.to_string())?;
        st.db.set_setting("concurrency", &settings.concurrency.clamp(1, 8).to_string())?;
        st.db.set_setting("signOutOnLock", if settings.sign_out_on_lock { "true" } else { "false" })?;
        st.db.set_setting("verifyIntervalDays", &settings.verify_interval_days.min(365).to_string())?;
        st.db.set_setting("contextMenu", if settings.context_menu { "true" } else { "false" })?;
        if let Some(p) = &new_root {
            st.db.set_setting("defaultVaultRoot", &fsutil::display_path(&fsutil::normalize(p)?))?;
        }
        st.session.set_timeout(Duration::from_secs(mins as u64 * 60));
        if let Some(w) = app.get_webview_window("main") {
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
        if !p.is_absolute() {
            return invalid("That location doesn't exist.");
        }
        // Explorer *runs* a file it is given (an .exe, a script, a shortcut),
        // so only folders are opened directly. Anything else is selected in
        // its folder instead (`/select,` never launches it).
        let meta = std::fs::symlink_metadata(&p).map_err(|_| Error::Invalid("That location doesn't exist.".into()))?;
        let mut cmd = std::process::Command::new("explorer.exe");
        if meta.is_dir() && !scan::is_link(&meta) {
            // Path is passed as a single argument (no shell interpretation).
            cmd.arg(&p);
        } else {
            #[cfg(windows)]
            {
                // Explorer doesn't parse standard argument quoting for
                // `/select`; Windows paths can't contain `"`.
                use std::os::windows::process::CommandExt;
                cmd.raw_arg(format!("/select,\"{}\"", fsutil::display_path(&p)));
            }
            #[cfg(not(windows))]
            cmd.arg(p.parent().unwrap_or(&p));
        }
        cmd.spawn()?;
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_cells_are_escaped() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("-1"), "'-1");
        assert_eq!(csv_cell("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn utc_times() {
        assert_eq!(utc_time(0), "1970-01-01 00:00:00");
        assert_eq!(utc_time(951_782_400_000), "2000-02-29 00:00:00");
        assert_eq!(utc_time(1_789_400_000_123), "2026-09-14 15:33:20");
        assert_eq!(utc_time(-1_000), "1969-12-31 23:59:59");
    }
}
