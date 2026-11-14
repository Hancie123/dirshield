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
        st.db.set_setting("signOutOnLock", if settings.sign_out_on_lock { "true" } else { "false" })?;
        st.db.set_setting("verifyIntervalDays", &settings.verify_interval_days.min(365).to_string())?;
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
