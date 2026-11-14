import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { CheckmarkCircleFilled, DeleteRegular, EyeRegular, LockClosedRegular, LockOpenRegular, EyeOffRegular, SettingsRegular, ShieldLockRegular } from "@fluentui/react-icons";
import { api, errMsg, type PromptInfo } from "../lib/api";
import { FluentButton, FluentPasswordInput, FluentSpinner, InfoBar } from "../components/fluent";
import { applyTheme } from "../lib/store";

/**
 * The small window opened by Explorer's right-click menu: one password field,
 * then the action runs and the window closes. The full app never opens.
 */

const TEXT: Record<string, { title: string; button: string; busy: string; icon: React.ReactNode }> = {
  lock: { title: "Lock folder", button: "Lock", busy: "Locking…", icon: <LockClosedRegular /> },
  "quick-lock": { title: "Lock and hide folder", button: "Lock and hide", busy: "Locking…", icon: <EyeOffRegular /> },
  unlock: { title: "Unlock folder", button: "Unlock", busy: "Unlocking…", icon: <LockOpenRegular /> },
  unhide: { title: "Unhide folder", button: "Unhide", busy: "Working…", icon: <EyeRegular /> },
  uninstall: { title: "Uninstall DirShield", button: "Uninstall", busy: "Checking…", icon: <DeleteRegular /> },
  "secure-lock": { title: "Secure Lock folder", button: "Continue", busy: "Signing in…", icon: <ShieldLockRegular /> },
  settings: { title: "DirShield settings", button: "Continue", busy: "Signing in…", icon: <SettingsRegular /> },
};

/**
 * Actions this window signs in for and then continues in DirShield: Secure
 * Lock and Settings, and unlock/unhide of a folder that isn't Quick-Locked
 * (a Secure Lock folder is restored in the app).
 */
function isHandoff(p: PromptInfo): boolean {
  if (p.action === "secure-lock" || p.action === "settings") return true;
  return (p.action === "unlock" || p.action === "unhide") && !p.vault;
}

const HANDOFF_NOTE: Record<string, string> = {
  "secure-lock": "Enter your master password. DirShield opens to choose the encryption options.",
  settings: "Enter your master password to open DirShield's settings.",
  unlock: "This folder isn't Quick-Locked. Enter your master password to continue in DirShield (Secure Lock folders are restored there).",
  unhide: "This folder isn't Quick-Locked. Enter your master password to continue in DirShield.",
};

/** Cases the prompt can't handle at all. */
function blocker(p: PromptInfo): string | null {
  const locking = p.action === "lock" || p.action === "quick-lock";
  if (locking && p.vault) return "This folder is already locked.";
  if (p.action === "unhide" && p.vault && !p.vault.hidden) return "This folder isn't hidden.";
  return null;
}

export function PromptApp() {
  const [info, setInfo] = useState<PromptInfo | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    setError(null);
    setDone(null);
    setPassword("");
    try {
      setInfo(await api.promptInfo());
    } catch (e) {
      setError(errMsg(e));
    }
    setTimeout(() => input.current?.focus(), 50);
  }, []);

  useEffect(() => {
    applyTheme(localStorage.getItem("dirshield.theme") ?? "system");
    api
      .appInfo()
      .then((i) => {
        document.documentElement.classList.toggle("mica", i.mica);
        if (i.accent) document.documentElement.style.setProperty("--accent-base", i.accent);
      })
      .catch(() => {});
    load();
    // Another right-click while this window is open re-targets it.
    const un = listen("prompt-action", () => load());
    const esc = (e: KeyboardEvent) => e.key === "Escape" && api.promptClose();
    window.addEventListener("keydown", esc);
    return () => {
      un.then((f) => f());
      window.removeEventListener("keydown", esc);
    };
  }, [load]);

  const submit = async () => {
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      setDone(await api.promptSubmit(password));
      setTimeout(() => api.promptClose(), 1400);
    } catch (e) {
      setError(errMsg(e));
      setTimeout(() => input.current?.select(), 0);
    } finally {
      setPassword("");
      setBusy(false);
    }
  };

  const t = TEXT[info?.action ?? "lock"] ?? TEXT.lock;
  const block = info ? blocker(info) : null;
  const handoff = !!info && isHandoff(info);
  const button = handoff ? "Continue" : t.button;
  const busyText = handoff ? "Signing in…" : t.busy;
  const folderPw = info?.vault?.keyMode === "password" && (info.action === "unlock" || info.action === "unhide");

  return (
    <div className="h-full flex flex-col p-6 gap-4 anim-page">
      <div className="flex items-center gap-3">
        <span className="text-[24px] text-[var(--accent)] flex">{t.icon}</span>
        <h1 className="t-subtitle font-display">{t.title}</h1>
      </div>

      {info?.action === "uninstall" ? (
        <div className="t-body text-[var(--text-2)]">Enter your master password to confirm that you want to uninstall DirShield. Your vaults and locked folders are kept.</div>
      ) : info && (
        <div className="min-w-0 flex flex-col gap-2">
          {info.path && (
            <div className="min-w-0">
              <div className="t-body-strong truncate">{info.name}</div>
              <div className="t-caption text-[var(--text-2)] truncate selectable" title={info.path}>
                {info.path}
              </div>
            </div>
          )}
          {handoff && !block && <div className="t-caption text-[var(--text-2)]">{HANDOFF_NOTE[info.action]}</div>}
        </div>
      )}

      {done ? (
        <div className="flex items-center gap-3 py-2">
          <CheckmarkCircleFilled fontSize={28} className="text-[var(--success)] shrink-0" />
          <span>{done}</span>
        </div>
      ) : block ? (
        <InfoBar severity="info">{block}</InfoBar>
      ) : (
        info && (
          <FluentPasswordInput
            ref={input}
            label={folderPw ? "Folder password" : "Master password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            disabled={busy}
            autoFocus
          />
        )
      )}
      {error && !done && <InfoBar severity="error">{error}</InfoBar>}

      <div className="mt-auto flex justify-end gap-2">
        {done ? null : block ? (
          <FluentButton onClick={() => api.promptClose()}>Close</FluentButton>
        ) : (
          <>
            <FluentButton variant="accent" disabled={!password || busy || !info} onClick={submit}>
              {busy ? (
                <span className="flex items-center gap-2">
                  <FluentSpinner size={14} /> {busyText}
                </span>
              ) : (
                button
              )}
            </FluentButton>
            <FluentButton disabled={busy} onClick={() => api.promptClose()}>
              Cancel
            </FluentButton>
          </>
        )}
      </div>
    </div>
  );
}
