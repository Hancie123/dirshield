//! DirShield's entry in the Windows 11 File Explorer menu.
//!
//! Windows 11 shows only `IExplorerCommand` handlers that belong to a package
//! in its top-level menu; registry verbs land under "Show more options". This
//! DLL is that handler. It is declared by a sparse package
//! (`windows/sparse/AppxManifest.xml`) whose external location is DirShield's
//! install folder, and Explorer loads it from there.
//!
//! The menu is a "DirShield" flyout with the same entries as the classic menu
//! (`menu_spec::VERBS`). Choosing one starts `dirshield.exe --action <verb>
//! "<folder>"` next to this DLL, exactly as the classic menu does, so all
//! decisions stay in the app. The handler never touches the folder itself.

#[allow(dead_code)]
#[path = "../../src/platform/menu_spec.rs"]
pub mod menu_spec;

/// The folder Explorer passes is user-controlled: it is quoted so that the
/// app receives it as exactly one argument (`CommandLineToArgvW` rules:
/// backslashes are literal except before a quote).
pub fn quote_arg(s: &str) -> String {
    if !s.is_empty() && !s.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut backslashes = 0;
    for c in s.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// Command line for one menu entry. The executable is quoted without escapes:
/// argv[0] is parsed differently and never ends in a backslash.
pub fn command_line(exe: &str, verb: &str, folder: Option<&str>) -> String {
    let mut cmd = format!("\"{exe}\" --action {verb}");
    if let Some(f) = folder {
        cmd.push(' ');
        cmd.push_str(&quote_arg(f));
    }
    cmd
}

/// At most this many folders are handed to DirShield per click (one prompt
/// each), as Explorer does for classic verbs.
pub const MAX_ITEMS: u32 = 16;

#[cfg(windows)]
mod handler {
    use std::ffi::c_void;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicIsize, AtomicPtr, AtomicUsize, Ordering};

    use windows::core::{implement, IUnknown, Interface, Ref, Result, BOOL, GUID, HRESULT, HSTRING, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_NOTIMPL, E_POINTER, HINSTANCE, HMODULE, S_FALSE, S_OK};
    use windows::Win32::System::Com::{CoTaskMemFree, IBindCtx, IClassFactory, IClassFactory_Impl};
    use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
    use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
    use windows::Win32::System::Threading::{CreateProcessW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW};
    use windows::Win32::UI::Shell::{
        IEnumExplorerCommand, IEnumExplorerCommand_Impl, IExplorerCommand, IExplorerCommand_Impl, IShellItemArray, SHStrDupW, ECF_DEFAULT, ECF_HASSUBCOMMANDS, ECF_SEPARATORBEFORE, ECS_ENABLED,
        SIGDN_FILESYSPATH,
    };
    use windows::Win32::UI::WindowsAndMessaging::{AllowSetForegroundWindow, ASFW_ANY};

    use super::menu_spec::{HANDLER_CLSID, SEPARATOR_BEFORE, VERBS};

    const APP_EXE: &str = "dirshield.exe";

    /// This DLL's module handle, for finding `dirshield.exe` next to it.
    static MODULE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    /// Live COM objects plus `LockServer` locks; the DLL may unload at 0.
    static REFS: AtomicIsize = AtomicIsize::new(0);

    struct Live;
    impl Live {
        fn new() -> Self {
            REFS.fetch_add(1, Ordering::SeqCst);
            Live
        }
    }
    impl Drop for Live {
        fn drop(&mut self) {
            REFS.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn clsid() -> GUID {
        GUID::try_from(HANDLER_CLSID).unwrap_or_default()
    }

    fn app_exe() -> Option<PathBuf> {
        let mut buf = vec![0u16; 1024];
        loop {
            let n = unsafe { GetModuleFileNameW(Some(HMODULE(MODULE.load(Ordering::Relaxed))), &mut buf) } as usize;
            if n == 0 {
                return None;
            }
            if n < buf.len() {
                let dll = PathBuf::from(String::from_utf16_lossy(&buf[..n]));
                return dll.parent().map(|d| d.join(APP_EXE));
            }
            if buf.len() >= 32 * 1024 {
                return None;
            }
            buf.resize(buf.len() * 2, 0);
        }
    }

    /// A string Explorer frees with `CoTaskMemFree`.
    fn dup(s: &str) -> Result<PWSTR> {
        unsafe { SHStrDupW(&HSTRING::from(s)) }
    }

    /// File-system paths of the selected items (virtual items are skipped).
    fn selected_folders(items: Option<&IShellItemArray>) -> Vec<String> {
        let Some(items) = items else { return Vec::new() };
        let count = unsafe { items.GetCount() }.unwrap_or(0).min(super::MAX_ITEMS);
        (0..count)
            .filter_map(|i| {
                let item = unsafe { items.GetItemAt(i) }.ok()?;
                let p = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }.ok()?;
                let s = unsafe { p.to_string() }.ok();
                unsafe { CoTaskMemFree(Some(p.0 as *const c_void)) };
                s
            })
            .collect()
    }

    fn launch(verb: &str, folder: Option<&str>) -> Result<()> {
        let exe = app_exe().ok_or_else(windows::core::Error::from_win32)?;
        let exe_s = exe.to_string_lossy();
        let mut cmd: Vec<u16> = super::command_line(&exe_s, verb, folder).encode_utf16().chain(std::iter::once(0)).collect();
        let app = HSTRING::from(exe.as_os_str());
        let dir = exe.parent().map(|d| HSTRING::from(d.as_os_str())).unwrap_or_default();
        let si = STARTUPINFOW { cb: std::mem::size_of::<STARTUPINFOW>() as u32, ..Default::default() };
        let mut pi = PROCESS_INFORMATION::default();
        unsafe {
            // DirShield shows a password window: let it come to the front.
            let _ = AllowSetForegroundWindow(ASFW_ANY);
            CreateProcessW(&app, Some(PWSTR(cmd.as_mut_ptr())), None, None, false, PROCESS_CREATION_FLAGS(0), None, &dir, &si, &mut pi)?;
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
        }
        Ok(())
    }

    /// The "DirShield" flyout (`None`) or one of its entries (index into `VERBS`).
    #[implement(IExplorerCommand)]
    struct Command {
        verb: Option<usize>,
        _live: Live,
    }

    impl Command {
        fn new(verb: Option<usize>) -> Self {
            Command { verb, _live: Live::new() }
        }
    }

    impl IExplorerCommand_Impl for Command_Impl {
        fn GetTitle(&self, _items: Ref<'_, IShellItemArray>) -> Result<PWSTR> {
            dup(match self.verb {
                None => "DirShield",
                Some(i) => VERBS[i].1,
            })
        }

        fn GetIcon(&self, _items: Ref<'_, IShellItemArray>) -> Result<PWSTR> {
            let exe = app_exe().ok_or_else(|| windows::core::Error::from(E_NOTIMPL))?;
            dup(&format!("{},0", exe.display()))
        }

        fn GetToolTip(&self, _items: Ref<'_, IShellItemArray>) -> Result<PWSTR> {
            Err(E_NOTIMPL.into())
        }

        fn GetCanonicalName(&self) -> Result<GUID> {
            match self.verb {
                None => Ok(clsid()),
                Some(_) => Err(E_NOTIMPL.into()),
            }
        }

        fn GetState(&self, _items: Ref<'_, IShellItemArray>, _ok_to_be_slow: BOOL) -> Result<u32> {
            Ok(ECS_ENABLED.0 as u32)
        }

        fn Invoke(&self, items: Ref<'_, IShellItemArray>, _bind: Ref<'_, IBindCtx>) -> Result<()> {
            let Some(i) = self.verb else { return Ok(()) };
            let verb = VERBS[i].2;
            if verb == "settings" {
                return launch(verb, None);
            }
            for folder in selected_folders(items.ok().ok()) {
                launch(verb, Some(&folder))?;
            }
            Ok(())
        }

        fn GetFlags(&self) -> Result<u32> {
            let flags = match self.verb {
                None => ECF_HASSUBCOMMANDS,
                Some(i) if SEPARATOR_BEFORE.contains(&VERBS[i].2) => ECF_SEPARATORBEFORE,
                Some(_) => ECF_DEFAULT,
            };
            Ok(flags.0 as u32)
        }

        fn EnumSubCommands(&self) -> Result<IEnumExplorerCommand> {
            match self.verb {
                None => Ok(SubCommands::new(0).into()),
                Some(_) => Err(E_NOTIMPL.into()),
            }
        }
    }

    #[implement(IEnumExplorerCommand)]
    struct SubCommands {
        pos: AtomicUsize,
        _live: Live,
    }

    impl SubCommands {
        fn new(pos: usize) -> Self {
            SubCommands { pos: AtomicUsize::new(pos), _live: Live::new() }
        }
    }

    impl IEnumExplorerCommand_Impl for SubCommands_Impl {
        fn Next(&self, celt: u32, out: *mut Option<IExplorerCommand>, fetched: *mut u32) -> HRESULT {
            if out.is_null() {
                return E_POINTER;
            }
            let mut n = 0u32;
            while n < celt {
                let i = self.pos.load(Ordering::Relaxed);
                if i >= VERBS.len() {
                    break;
                }
                self.pos.store(i + 1, Ordering::Relaxed);
                unsafe { out.add(n as usize).write(Some(Command::new(Some(i)).into())) };
                n += 1;
            }
            if !fetched.is_null() {
                unsafe { *fetched = n };
            }
            if n == celt {
                S_OK
            } else {
                S_FALSE
            }
        }

        fn Skip(&self, celt: u32) -> Result<()> {
            self.pos.fetch_add(celt as usize, Ordering::Relaxed);
            Ok(())
        }

        fn Reset(&self) -> Result<()> {
            self.pos.store(0, Ordering::Relaxed);
            Ok(())
        }

        fn Clone(&self) -> Result<IEnumExplorerCommand> {
            Ok(SubCommands::new(self.pos.load(Ordering::Relaxed)).into())
        }
    }

    #[implement(IClassFactory)]
    struct Factory {
        _live: Live,
    }

    impl IClassFactory_Impl for Factory_Impl {
        fn CreateInstance(&self, outer: Ref<'_, IUnknown>, riid: *const GUID, ppv: *mut *mut c_void) -> Result<()> {
            if ppv.is_null() {
                return Err(E_POINTER.into());
            }
            unsafe { *ppv = std::ptr::null_mut() };
            if outer.ok().is_ok() {
                return Err(CLASS_E_NOAGGREGATION.into());
            }
            let cmd: IUnknown = Command::new(None).into();
            unsafe { cmd.query(riid, ppv) }.ok()
        }

        fn LockServer(&self, lock: BOOL) -> Result<()> {
            REFS.fetch_add(if lock.as_bool() { 1 } else { -1 }, Ordering::SeqCst);
            Ok(())
        }
    }

    #[unsafe(no_mangle)]
    extern "system" fn DllMain(module: HINSTANCE, reason: u32, _reserved: *mut c_void) -> BOOL {
        if reason == DLL_PROCESS_ATTACH {
            MODULE.store(module.0, Ordering::Relaxed);
        }
        true.into()
    }

    /// # Safety
    /// Called by COM with valid pointers.
    #[unsafe(no_mangle)]
    unsafe extern "system" fn DllGetClassObject(rclsid: *const GUID, riid: *const GUID, ppv: *mut *mut c_void) -> HRESULT {
        if ppv.is_null() {
            return E_POINTER;
        }
        unsafe { *ppv = std::ptr::null_mut() };
        if rclsid.is_null() || unsafe { *rclsid } != clsid() {
            return CLASS_E_CLASSNOTAVAILABLE;
        }
        let factory: IClassFactory = Factory { _live: Live::new() }.into();
        unsafe { factory.query(riid, ppv) }
    }

    #[unsafe(no_mangle)]
    extern "system" fn DllCanUnloadNow() -> HRESULT {
        if REFS.load(Ordering::SeqCst) <= 0 {
            S_OK
        } else {
            S_FALSE
        }
    }

    /// Drives the handler through COM the way Explorer does.
    #[cfg(test)]
    mod com_tests {
        use super::*;

        fn take(p: PWSTR) -> String {
            let s = unsafe { p.to_string() }.unwrap();
            unsafe { CoTaskMemFree(Some(p.0 as *const c_void)) };
            s
        }

        #[test]
        fn flyout_through_class_factory() {
            let mut factory: Option<IClassFactory> = None;
            let hr = unsafe { DllGetClassObject(&clsid(), &IClassFactory::IID, &mut factory as *mut _ as *mut *mut c_void) };
            assert_eq!(hr, S_OK);
            let wrong = GUID::from_u128(1);
            let mut none: *mut c_void = std::ptr::null_mut();
            assert_eq!(unsafe { DllGetClassObject(&wrong, &IClassFactory::IID, &mut none) }, CLASS_E_CLASSNOTAVAILABLE);

            let root: IExplorerCommand = unsafe { factory.unwrap().CreateInstance(None) }.unwrap();
            assert_eq!(take(unsafe { root.GetTitle(None) }.unwrap()), "DirShield");
            assert_eq!(unsafe { root.GetFlags() }.unwrap(), ECF_HASSUBCOMMANDS.0 as u32);
            assert!(take(unsafe { root.GetIcon(None) }.unwrap()).ends_with("dirshield.exe,0"));

            let subs = unsafe { root.EnumSubCommands() }.unwrap();
            let mut titles = Vec::new();
            let mut flags = Vec::new();
            loop {
                let mut out = [None];
                let mut n = 0;
                let hr = unsafe { subs.Next(&mut out, Some(&mut n)) };
                if n == 0 {
                    assert_eq!(hr, S_FALSE);
                    break;
                }
                let c = out[0].take().unwrap();
                titles.push(take(unsafe { c.GetTitle(None) }.unwrap()));
                flags.push(unsafe { c.GetFlags() }.unwrap());
                assert!(unsafe { c.EnumSubCommands() }.is_err());
            }
            assert_eq!(titles, VERBS.iter().map(|v| v.1).collect::<Vec<_>>());
            assert_eq!(flags.last(), Some(&(ECF_SEPARATORBEFORE.0 as u32)));
            assert!(flags[..flags.len() - 1].iter().all(|f| *f == 0));
            unsafe { subs.Reset() }.unwrap();
            let mut out = [None, None];
            let mut n = 0;
            assert_eq!(unsafe { subs.Next(&mut out, Some(&mut n)) }, S_OK);
            assert_eq!(n, 2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_like_command_line_to_argv() {
        assert_eq!(quote_arg(r"C:\A"), r"C:\A");
        assert_eq!(quote_arg(r"C:\My Files (2024)"), r#""C:\My Files (2024)""#);
        // A trailing backslash must not escape the closing quote.
        assert_eq!(quote_arg(r"C:\My Files\"), r#""C:\My Files\\""#);
        assert_eq!(quote_arg(r"C:\"), r"C:\");
        assert_eq!(quote_arg(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote_arg(r#"a\"b"#), r#""a\\\"b""#);
        assert_eq!(quote_arg(""), r#""""#);
        assert_eq!(quote_arg("Ünïcode & ;rm -rf"), "\"Ünïcode & ;rm -rf\"");
    }

    #[test]
    fn command_lines() {
        let exe = r"C:\Users\me\AppData\Local\DirShield\dirshield.exe";
        assert_eq!(command_line(exe, "lock", Some(r"D:\Tax 2024")), format!(r#""{exe}" --action lock "D:\Tax 2024""#));
        assert_eq!(command_line(exe, "settings", None), format!(r#""{exe}" --action settings"#));
    }

    #[test]
    fn every_verb_is_known_to_the_app() {
        for (_, label, verb) in menu_spec::VERBS {
            assert!(!label.is_empty() && !verb.contains(' '));
        }
        for v in menu_spec::SEPARATOR_BEFORE {
            assert!(menu_spec::VERBS.iter().any(|(_, _, x)| x == v));
        }
    }
}
