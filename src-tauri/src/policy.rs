//! Pure decision logic, kept free of Tauri, the database and the environment so
//! it can be unit tested: which folders may be locked, and what an Explorer
//! prompt should do with the password it was given.

use std::path::{Path, PathBuf};

use crate::error::{invalid, Error, Result};
use crate::fsutil::{self, is_same_or_inside};
use crate::model::KeyMode;

// ---------------------------------------------------------------------------
// Lock targets
// ---------------------------------------------------------------------------

/// An already protected folder.
#[derive(Clone, Debug)]
pub struct Protected {
    pub name: String,
    pub original: PathBuf,
    /// Secure Lock vault directory (None for Quick Lock).
    pub vault_dir: Option<PathBuf>,
}

/// Everything [`check_target`] needs to know about the machine and the app.
#[derive(Clone, Debug, Default)]
pub struct TargetContext {
    /// %SystemRoot%, Program Files (both), ProgramData...
    pub system_dirs: Vec<PathBuf>,
    /// %USERPROFILE%
    pub profile: Option<PathBuf>,
    /// DirShield's data folder.
    pub data_dir: PathBuf,
    /// Folder holding the running executable.
    pub exe_dir: Option<PathBuf>,
    /// Where new vaults are created.
    pub vault_root: PathBuf,
    pub protected: Vec<Protected>,
}

/// Well-known profile folders that may hold locked folders but can't be locked themselves.
pub const PROFILE_FOLDERS: &[&str] = &["Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos", "OneDrive", "AppData"];

impl TargetContext {
    pub fn from_env(data_dir: PathBuf, vault_root: PathBuf, protected: Vec<Protected>) -> Self {
        let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        Self {
            system_dirs: ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "ProgramW6432"].iter().filter_map(|k| env(k)).collect(),
            profile: env("USERPROFILE"),
            data_dir,
            exe_dir: std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)),
            vault_root,
            protected,
        }
    }
}

/// Folders that must never be locked: whole drives, system locations, profile
/// roots and well-known folders, DirShield's own storage and program, and
/// anything overlapping an already protected folder.
///
/// `p` must already be normalised (absolute, no `..`). Filesystem checks
/// (exists, is a directory, not a link) are the caller's job.
pub fn check_target(p: &Path, ctx: &TargetContext) -> Result<()> {
    if p.parent().is_none() || p.parent() == Some(Path::new("")) {
        return invalid("Whole drives can't be locked. Choose a folder instead.");
    }
    for sys in &ctx.system_dirs {
        if is_same_or_inside(p, sys) || is_same_or_inside(sys, p) {
            return invalid("System and program folders can't be locked.");
        }
    }
    if let Some(profile) = &ctx.profile {
        if is_same_or_inside(profile, p) {
            return invalid("Your user profile folder (or a folder containing it) can't be locked. Choose a folder inside it.");
        }
        for k in PROFILE_FOLDERS {
            if fsutil::path_key(p) == fsutil::path_key(&profile.join(k)) {
                return invalid(format!("The {k} folder itself can't be locked. Choose a folder inside it."));
            }
        }
        if is_same_or_inside(p, &profile.join("AppData")) {
            return invalid("Application data folders can't be locked.");
        }
    }
    if is_same_or_inside(p, &ctx.data_dir) || is_same_or_inside(&ctx.data_dir, p) {
        return invalid("This folder contains DirShield's own storage.");
    }
    if let Some(dir) = &ctx.exe_dir {
        if is_same_or_inside(dir, p) {
            return invalid("This folder contains the DirShield application.");
        }
    }
    if is_same_or_inside(&ctx.vault_root, p) {
        return invalid("This folder contains the DirShield vault storage location.");
    }
    for v in &ctx.protected {
        if is_same_or_inside(p, &v.original) || is_same_or_inside(&v.original, p) {
            return Err(Error::Conflict(format!("This folder overlaps \"{}\", which is already protected.", v.name)));
        }
        if let Some(vd) = &v.vault_dir {
            if is_same_or_inside(vd, p) || is_same_or_inside(p, vd) {
                return invalid("This folder contains DirShield vault data.");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Explorer prompt
// ---------------------------------------------------------------------------

/// Which password the prompt must check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptCheck {
    Master,
    FolderPassword,
}

/// What `prompt_submit` should do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptPlan {
    /// Quick Lock the folder (master password).
    Lock { hide: bool },
    /// Remove the Quick Lock.
    Unlock(PromptCheck),
    /// Make it visible again; it stays locked.
    Unhide(PromptCheck),
}

/// `action` comes from the Explorer menu; `quick` is the folder's Quick Lock
/// key mode if DirShield has a record for it.
pub fn plan_prompt(action: &str, quick: Option<KeyMode>) -> Result<PromptPlan> {
    let check = |k: KeyMode| match k {
        KeyMode::Master => PromptCheck::Master,
        KeyMode::Password => PromptCheck::FolderPassword,
    };
    match (action, quick) {
        ("lock" | "quick-lock", Some(_)) => invalid("This folder is already locked."),
        ("lock", None) => Ok(PromptPlan::Lock { hide: false }),
        ("quick-lock", None) => Ok(PromptPlan::Lock { hide: true }),
        ("unlock" | "unhide", None) => Err(Error::NotFound("Quick Lock record for this folder".into())),
        ("unlock", Some(k)) => Ok(PromptPlan::Unlock(check(k))),
        ("unhide", Some(k)) => Ok(PromptPlan::Unhide(check(k))),
        _ => invalid("This action needs the DirShield window."),
    }
}

/// Where an unlocked Quick Lock folder goes back to. The original location is
/// encrypted metadata, so without the master key (folder-password unlock while
/// DirShield is signed out) it's only known for folders locked in place.
pub fn quick_restore_target(original_with_key: Option<PathBuf>, moved: bool, current: &Path) -> Result<PathBuf> {
    match original_with_key {
        Some(p) => Ok(p),
        None if !moved => Ok(current.to_path_buf()),
        None => invalid("Sign in to DirShield to restore this folder."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\")
        } else {
            PathBuf::from("/")
        }
    }

    fn ctx() -> TargetContext {
        let r = root();
        TargetContext {
            system_dirs: vec![r.join("Windows"), r.join("Program Files"), r.join("ProgramData")],
            profile: Some(r.join("Users").join("me")),
            data_dir: r.join("Users").join("me").join("AppData").join("Local").join("DirShield"),
            exe_dir: Some(r.join("Users").join("me").join("AppData").join("Local").join("Programs").join("DirShield")),
            vault_root: r.join("Vaults"),
            protected: vec![
                Protected { name: "Taxes".into(), original: r.join("Users").join("me").join("Documents").join("Taxes"), vault_dir: Some(r.join("Vaults").join("v1")) },
                Protected { name: "Photos".into(), original: r.join("Data").join("Photos"), vault_dir: None },
            ],
        }
    }

    fn rejects(p: PathBuf, why: &str) {
        let e = check_target(&p, &ctx()).expect_err(&format!("{} should be rejected", p.display()));
        assert!(e.to_string().contains(why), "{}: got {e:?}, expected {why:?}", p.display());
    }

    fn me() -> PathBuf {
        root().join("Users").join("me")
    }

    #[test]
    fn ordinary_folders_are_allowed() {
        let c = ctx();
        for p in [me().join("Documents").join("Private"), me().join("Desktop").join("stuff"), root().join("Data").join("Other"), root().join("Vaults2")] {
            check_target(&p, &c).unwrap_or_else(|e| panic!("{} rejected: {e}", p.display()));
        }
    }

    #[test]
    fn drives_are_rejected() {
        rejects(root(), "Whole drives");
    }

    #[test]
    fn system_folders_and_their_parents_are_rejected() {
        rejects(root().join("Windows"), "System and program");
        rejects(root().join("Windows").join("System32"), "System and program");
        rejects(root().join("Program Files").join("App"), "System and program");
        rejects(root().join("ProgramData"), "System and program");
    }

    #[test]
    fn profile_root_and_well_known_folders_are_rejected() {
        rejects(me(), "user profile");
        rejects(root().join("Users"), "user profile");
        for k in PROFILE_FOLDERS {
            rejects(me().join(k), "itself can't be locked");
        }
        rejects(me().join("AppData").join("Roaming").join("x"), "Application data");
    }

    #[test]
    fn well_known_folder_match_ignores_case_on_windows() {
        if cfg!(windows) {
            rejects(me().join("documents"), "itself can't be locked");
        }
    }

    #[test]
    fn dirshield_storage_program_and_vault_root_are_rejected() {
        // the data dir lives under AppData, which is caught first; test it on its own too
        let mut c = ctx();
        c.profile = None;
        let data = c.data_dir.clone();
        assert!(check_target(&data.join("Vaults"), &c).unwrap_err().to_string().contains("own storage"));
        assert!(check_target(data.parent().unwrap(), &c).unwrap_err().to_string().contains("own storage"));
        let exe = c.exe_dir.clone().unwrap();
        assert!(check_target(exe.parent().unwrap(), &c).unwrap_err().to_string().contains("DirShield application"));
        rejects(root().join("Vaults"), "vault storage location");
    }

    #[test]
    fn overlapping_protected_folders_conflict() {
        let c = ctx();
        for p in [me().join("Documents").join("Taxes"), me().join("Documents").join("Taxes").join("2025"), root().join("Data"), root().join("Data").join("Photos").join("x")] {
            assert!(matches!(check_target(&p, &c), Err(Error::Conflict(_))), "{} should conflict", p.display());
        }
    }

    #[test]
    fn secure_vault_dirs_are_rejected() {
        let mut c = ctx();
        c.vault_root = root().join("Elsewhere");
        assert!(check_target(&root().join("Vaults").join("v1").join("blobs"), &c).unwrap_err().to_string().contains("vault data"));
        assert!(check_target(&root().join("Vaults"), &c).unwrap_err().to_string().contains("vault data"));
    }

    #[test]
    fn prompt_plans() {
        use PromptCheck::*;
        assert_eq!(plan_prompt("lock", None).unwrap(), PromptPlan::Lock { hide: false });
        assert_eq!(plan_prompt("quick-lock", None).unwrap(), PromptPlan::Lock { hide: true });
        assert!(plan_prompt("lock", Some(KeyMode::Master)).is_err());
        assert!(plan_prompt("quick-lock", Some(KeyMode::Password)).is_err());
        assert!(matches!(plan_prompt("unlock", None), Err(Error::NotFound(_))));
        assert_eq!(plan_prompt("unlock", Some(KeyMode::Master)).unwrap(), PromptPlan::Unlock(Master));
        assert_eq!(plan_prompt("unlock", Some(KeyMode::Password)).unwrap(), PromptPlan::Unlock(FolderPassword));
        assert_eq!(plan_prompt("unhide", Some(KeyMode::Password)).unwrap(), PromptPlan::Unhide(FolderPassword));
        // Secure Lock actions and anything unknown go to the main window
        for a in ["secure-lock", "restore", "", "LOCK"] {
            assert!(matches!(plan_prompt(a, None), Err(Error::Invalid(_))), "{a}");
        }
    }

    #[test]
    fn quick_restore_needs_key_for_moved_folders() {
        let cur = root().join("Store").join("x");
        assert_eq!(quick_restore_target(Some(root().join("orig")), true, &cur).unwrap(), root().join("orig"));
        assert_eq!(quick_restore_target(None, false, &cur).unwrap(), cur);
        assert!(quick_restore_target(None, true, &cur).is_err());
    }
}
