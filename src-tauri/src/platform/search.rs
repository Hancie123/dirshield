//! Windows Search privacy measures. These reduce the chance that protected
//! content appears in Explorer search; they are NOT a security boundary.
//!
//! 1. `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` on the folder and, for Quick Lock,
//!    on every file and subfolder inside it (works without admin). Changing the
//!    attribute also prompts the indexer to drop items it indexed earlier.
//! 2. A crawl-scope exclusion rule via the Windows Search COM API
//!    (`ISearchCrawlScopeManager`). Writing crawl scope rules normally requires
//!    administrator rights; without them this step reports `false` and the
//!    other measures still apply.
//! 3. For Quick Lock, the inherited deny ACE also prevents the indexer
//!    (running as SYSTEM) from reading the folder at all.
//!
//! Previously indexed results are removed by Windows on its own schedule.

use std::path::Path;

use crate::platform::fsutil;

fn scope_url(p: &Path) -> String {
    let mut s = fsutil::display_path(p);
    if !s.ends_with('\\') {
        s.push('\\');
    }
    format!("file:///{s}")
}

#[cfg(windows)]
fn with_crawl_scope<T>(f: impl FnOnce(&windows::Win32::System::Search::ISearchCrawlScopeManager) -> windows::core::Result<T>) -> windows::core::Result<T> {
    use windows::core::w;
    use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED};
    use windows::Win32::System::Search::{CSearchManager, ISearchManager};
    unsafe {
        let init = CoInitializeEx(None, COINIT_MULTITHREADED);
        let r = (|| {
            let mgr: ISearchManager = CoCreateInstance(&CSearchManager, None, CLSCTX_LOCAL_SERVER)?;
            let catalog = mgr.GetCatalog(w!("SystemIndex"))?;
            let scope = catalog.GetCrawlScopeManager()?;
            f(&scope)
        })();
        if init.is_ok() {
            CoUninitialize();
        }
        r
    }
}

/// Adds an exclusion rule. Returns true if Windows accepted it.
#[cfg(windows)]
pub fn exclude(p: &Path) -> bool {
    use windows::core::PCWSTR;
    let _ = mark_not_indexed(p);
    let url = fsutil::wide_str(&scope_url(p));
    with_crawl_scope(|s| unsafe {
        s.AddUserScopeRule(PCWSTR(url.as_ptr()), false, true, 0)?;
        s.SaveAll()
    })
    .is_ok()
}

#[cfg(windows)]
pub fn remove_exclusion(p: &Path) -> bool {
    use windows::core::PCWSTR;
    let url = fsutil::wide_str(&scope_url(p));
    with_crawl_scope(|s| unsafe {
        s.RemoveScopeRule(PCWSTR(url.as_ptr()))?;
        s.SaveAll()
    })
    .is_ok()
}

#[cfg(not(windows))]
pub fn exclude(_p: &Path) -> bool {
    false
}
#[cfg(not(windows))]
pub fn remove_exclusion(_p: &Path) -> bool {
    false
}

pub fn mark_not_indexed(p: &Path) -> crate::domain::error::Result<()> {
    let a = fsutil::get_attrs(p)?;
    if a & fsutil::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED == 0 {
        fsutil::set_attrs(p, (a & fsutil::RESTORABLE_ATTRS) | fsutil::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)?;
    }
    Ok(())
}

/// Attribute bits SetFileAttributes accepts; everything else is left alone.
const SETTABLE_ATTRS: u32 = 0x1 | 0x2 | 0x4 | 0x20 | 0x100 | 0x1000 | 0x2000 | 0x8_0000 | 0x10_0000;

/// Items below `root` (not `root` itself), never following links or junctions.
fn tree(root: &Path) -> impl Iterator<Item = walkdir::DirEntry> {
    walkdir::WalkDir::new(root).min_depth(1).follow_links(false).into_iter().filter_map(|e| e.ok()).filter(|e| !e.path_is_symlink())
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).map(fsutil::display_path).unwrap_or_default()
}

/// Marks every file and folder below `root` as not-indexed so Windows Search
/// drops and skips them. Best effort: items that can't be changed are skipped.
/// Returns the relative paths that already had the flag, so `unmark_tree`
/// can restore the attributes exactly.
pub fn mark_tree_not_indexed(root: &Path) -> Vec<String> {
    let nci = fsutil::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    let mut already = Vec::new();
    for e in tree(root) {
        let Ok(a) = fsutil::get_attrs(e.path()) else { continue };
        if a & nci != 0 {
            already.push(rel(root, e.path()));
        } else {
            let _ = fsutil::set_attrs(e.path(), (a & SETTABLE_ATTRS) | nci);
        }
    }
    already
}

/// Reverses `mark_tree_not_indexed`, leaving items listed in `keep` flagged.
pub fn unmark_tree_not_indexed(root: &Path, keep: &[String]) {
    let nci = fsutil::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    let keep: std::collections::HashSet<&str> = keep.iter().map(String::as_str).collect();
    for e in tree(root) {
        let Ok(a) = fsutil::get_attrs(e.path()) else { continue };
        if a & nci != 0 && !keep.contains(rel(root, e.path()).as_str()) {
            let _ = fsutil::set_attrs(e.path(), a & SETTABLE_ATTRS & !nci);
        }
    }
}
