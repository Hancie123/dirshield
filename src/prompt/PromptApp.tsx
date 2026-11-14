import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { CheckmarkCircleFilled, EyeRegular, LockClosedRegular, LockOpenRegular, EyeOffRegular } from "@fluentui/react-icons";
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
};

type Blocker = { message: string; openMain: boolean } | null;

/** Cases the prompt can't handle by itself. */
function blocker(p: PromptInfo): Blocker {
  const locking = p.action === "lock" || p.action === "quick-lock";
  if (locking && p.vault) return { message: "This folder is already locked.", openMain: false };
  if (!locking && !p.vault) return { message: "This folder isn't Quick-Locked here. Open DirShield to see its protection (Secure Lock folders are restored from the app).", openMain: true };
  if (p.action === "unhide" && p.vault && !p.vault.hidden) return { message: "This folder isn't hidden.", openMain: false };
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
  const folderPw = info?.vault?.keyMode === "password" && (info.action === "unlock" || info.action === "unhide");

  return (
    <div className="h-full flex flex-col p-6 gap-4 anim-page">
      <div className="flex items-center gap-3">
        <span className="text-[24px] text-[var(--accent)] flex">{t.icon}</span>
        <h1 className="t-subtitle font-display">{t.title}</h1>
      </div>

      {info && (
        <div className="min-w-0">
          <div className="t-body-strong truncate">{info.name}</div>
          <div className="t-caption text-[var(--text-2)] truncate selectable" title={info.path}>
            {info.path}
          </div>
        </div>
      )}

      {done ? (
        <div className="flex items-center gap-3 py-2">
          <CheckmarkCircleFilled fontSize={28} className="text-[var(--success)] shrink-0" />
          <span>{done}</span>
        </div>
      ) : block ? (
        <InfoBar severity="info">{block.message}</InfoBar>
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
          <>
            {block.openMain && (
              <FluentButton variant="accent" onClick={() => api.promptOpenMain()}>
                Open DirShield
              </FluentButton>
            )}
            <FluentButton onClick={() => api.promptClose()}>Close</FluentButton>
          </>
        ) : (
          <>
            <FluentButton variant="accent" disabled={!password || busy || !info} onClick={submit}>
              {busy ? (
                <span className="flex items-center gap-2">
                  <FluentSpinner size={14} /> {t.busy}
                </span>
              ) : (
                t.button
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
