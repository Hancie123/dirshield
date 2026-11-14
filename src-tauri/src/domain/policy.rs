//! Pure decision logic, kept free of Tauri, the database and the environment so
//! it can be unit tested: which folders may be locked, and where vaults may be
//! stored.

use std::path::{Path, PathBuf};

use crate::domain::error::{invalid, Error, Result};
use crate::platform::fsutil::{self, is_same_or_inside};

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

/// Where new vaults may be stored by default (the Settings vault location).
/// `p` must already be normalised. It may not be a system folder, and it may
/// not be inside a protected folder (or one restored from a vault): vault data
/// written there would be swept into that folder when it is next locked.
pub fn check_vault_root(p: &Path, ctx: &TargetContext) -> Result<()> {
    if p.parent().is_none() || p.parent() == Some(Path::new("")) {
        return invalid("Choose a folder for the vault location, not a whole drive.");
    }
    for sys in &ctx.system_dirs {
        if is_same_or_inside(p, sys) {
            return invalid("Vaults can't be stored in system or program folders.");
        }
    }
    if let Some(dir) = &ctx.exe_dir {
        if is_same_or_inside(p, dir) {
            return invalid("Vaults can't be stored in the DirShield application folder.");
        }
    }
    for v in &ctx.protected {
        if is_same_or_inside(p, &v.original) {
            return Err(Error::Conflict(format!("The vault location can't be inside \"{}\", which is protected by DirShield.", v.name)));
        }
        if let Some(vd) = &v.vault_dir {
            if is_same_or_inside(p, vd) {
                return invalid("The vault location can't be inside another vault.");
            }
        }
    }
    Ok(())
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
    fn vault_root_rules() {
        let c = ctx();
        for p in [root().join("Vaults"), root().join("Vaults2"), me().join("Documents").join("Vaults"), c.data_dir.join("Vaults")] {
            check_vault_root(&p, &c).unwrap_or_else(|e| panic!("{} rejected: {e}", p.display()));
        }
        assert!(check_vault_root(&root(), &c).is_err());
        assert!(check_vault_root(&root().join("Windows").join("x"), &c).is_err());
        // a folder that merely contains a protected one is fine
        check_vault_root(&root().join("Data"), &c).unwrap();
        for p in [me().join("Documents").join("Taxes"), me().join("Documents").join("Taxes").join("v"), root().join("Data").join("Photos").join("v")] {
            assert!(matches!(check_vault_root(&p, &c), Err(Error::Conflict(_))), "{} should conflict", p.display());
        }
        assert!(check_vault_root(&root().join("Vaults").join("v1").join("x"), &c).unwrap_err().to_string().contains("another vault"));
    }
}
