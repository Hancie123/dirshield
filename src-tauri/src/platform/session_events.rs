//! Windows session events: the workstation locking, the user signing out of
//! Windows, and the PC going to sleep or hibernating.
//!
//! A hidden window on its own thread receives `WM_WTSSESSION_CHANGE` and
//! `WM_POWERBROADCAST` and reports them to the handler given to [`watch`].

use std::sync::OnceLock;

type Handler = Box<dyn Fn(&'static str) + Send + Sync>;
static HANDLER: OnceLock<Handler> = OnceLock::new();

/// Starts watching. `on_event` receives "windows_locked", "windows_sign_out"
/// or "sleep", on the watcher thread. Only the first call has any effect.
pub fn watch(on_event: impl Fn(&'static str) + Send + Sync + 'static) {
    if HANDLER.set(Box::new(on_event)).is_err() {
        return;
    }
    #[cfg(windows)]
    let _ = std::thread::Builder::new().name("session-events".into()).spawn(win::run);
}

#[cfg(windows)]
mod win {
    use windows::core::w;
    use windows::Win32::Foundation::{HANDLE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Power::RegisterSuspendResumeNotification;
    use windows::Win32::System::RemoteDesktop::{WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW, DEVICE_NOTIFY_WINDOW_HANDLE, MSG, PBT_APMSUSPEND, WINDOW_EX_STYLE, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE,
        WNDCLASSW, WS_OVERLAPPED, WTS_SESSION_LOCK, WTS_SESSION_LOGOFF,
    };

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        let event = match (msg, wp.0 as u32) {
            (WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK) => Some("windows_locked"),
            (WM_WTSSESSION_CHANGE, WTS_SESSION_LOGOFF) => Some("windows_sign_out"),
            (WM_POWERBROADCAST, PBT_APMSUSPEND) => Some("sleep"),
            _ => None,
        };
        if let (Some(e), Some(h)) = (event, super::HANDLER.get()) {
            h(e);
        }
        unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
    }

    pub fn run() {
        unsafe {
            let Ok(module) = GetModuleHandleW(None) else { return };
            let class = w!("DirShieldSessionEvents");
            let wc = WNDCLASSW { lpfnWndProc: Some(wndproc), hInstance: module.into(), lpszClassName: class, ..Default::default() };
            if RegisterClassW(&wc) == 0 {
                return;
            }
            // A top-level window that is never shown (message-only windows
            // don't receive power broadcasts).
            let Ok(hwnd) = CreateWindowExW(WINDOW_EX_STYLE(0), class, w!("DirShield"), WS_OVERLAPPED, 0, 0, 0, 0, None, None, Some(module.into()), None) else {
                return;
            };
            let _ = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
            let _ = RegisterSuspendResumeNotification(HANDLE(hwnd.0), DEVICE_NOTIFY_WINDOW_HANDLE);
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                DispatchMessageW(&msg);
            }
        }
    }
}
