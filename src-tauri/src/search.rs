//! Windows Search privacy measures. These reduce the chance that protected
//! content appears in Explorer search; they are NOT a security boundary.
//!
//! 1. `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` on the folder (works without admin).
//! 2. A crawl-scope exclusion rule via the Windows Search COM API
//!    (`ISearchCrawlScopeManager`). Writing crawl scope rules normally requires
//!    administrator rights; without them this step reports `false` and the
//!    other measures still apply.
//! 3. For Quick Lock, the inherited deny ACE also prevents the indexer
//!    (running as SYSTEM) from reading the folder at all.
//!
//! Previously indexed results are removed by Windows on its own schedule.

use std::path::Path;

use crate::fsutil;

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

pub fn mark_not_indexed(p: &Path) -> crate::error::Result<()> {
    let a = fsutil::get_attrs(p)?;
    if a & fsutil::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED == 0 {
        fsutil::set_attrs(p, (a & fsutil::RESTORABLE_ATTRS) | fsutil::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)?;
    }
    Ok(())
}
