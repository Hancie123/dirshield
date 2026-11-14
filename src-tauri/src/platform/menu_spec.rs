//! What DirShield adds to the Explorer menu for folders. This file is shared:
//! the app compiles it as `platform::menu_spec` (classic menu in the registry)
//! and the Windows 11 menu handler (`shell-ext/`) includes it with `#[path]`,
//! so both menus always offer the same entries. Keep it dependency-free.
//! `windows/hooks.nsh` repeats the classic entries for the installer.

/// (registry subkey, label, verb). Each entry runs
/// `dirshield.exe --action <verb> "<folder>"`. `lock` locks in place and keeps
/// the folder visible; `quick-lock` (kept for older registrations) locks and
/// hides it.
pub const VERBS: &[(&str, &str, &str)] = &[
    ("01lock", "Lock Folder", "lock"),
    ("02lockhide", "Lock and Hide Folder", "quick-lock"),
    ("03secure", "Secure Lock (encrypt)", "secure-lock"),
    ("04unlock", "Unlock Folder", "unlock"),
    ("05unhide", "Unhide Folder", "unhide"),
    ("06settings", "DirShield Settings", "settings"),
];

/// Verbs shown after a separator.
pub const SEPARATOR_BEFORE: &[&str] = &["settings"];

/// COM class of the Windows 11 menu handler (`IExplorerCommand`), as declared
/// in `windows/sparse/AppxManifest.xml`.
pub const HANDLER_CLSID: &str = "85e4875a-1c49-42ed-b994-a52b37669a06";

/// Identity name of the sparse package that declares the handler.
pub const SPARSE_PACKAGE_NAME: &str = "DirShield.ContextMenu";

/// Installed next to `dirshield.exe` (only by builds signed with a
/// code-signing certificate; see `scripts/build-sparse-package.ps1`).
pub const SPARSE_MSIX_FILE: &str = "dirshield-shell.msix";
pub const HANDLER_DLL_FILE: &str = "dirshield_shell.dll";
