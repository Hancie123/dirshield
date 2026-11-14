import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { api, errMsg, type AppInfo, type OperationInfo, type Progress, type ShellAction, type VaultInfo } from "@/api";
import { useNotify } from "@/components/fluent";

export type Page = "home" | "folders" | "operations" | "recovery" | "activity" | "settings" | "about";

export type DialogState =
  | { kind: "lock"; mode: "quick" | "secure"; path?: string; hide?: boolean }
  | { kind: "unlock"; vault: VaultInfo; recovery?: boolean }
  | { kind: "details"; vault: VaultInfo }
  | { kind: "changePassword"; vault: VaultInfo }
  | { kind: "removeOriginals"; vault: VaultInfo }
  | { kind: "delete"; vault: VaultInfo }
  | { kind: "verify"; vault: VaultInfo }
  | { kind: "recoverWork"; vault: VaultInfo }
  | { kind: "visibility"; vault: VaultInfo; hidden: boolean }
  | { kind: "resume"; op: OperationInfo; mode: "resume" | "retry" | "skip" }
  | { kind: "errors"; op: OperationInfo }
  | { kind: "progress"; opId: string; title: string }
  | null;

interface Store {
  info: AppInfo | null;
  refreshInfo: () => Promise<void>;
  unlocked: boolean;
  setUnlocked: (v: boolean) => void;
  vaults: VaultInfo[];
  /** `vaults` and `ops` have been fetched at least once since signing in. */
  loaded: boolean;
  ops: OperationInfo[];
  live: Record<string, Progress>;
  refresh: () => Promise<void>;
  page: Page;
  setPage: (p: Page) => void;
  dialog: DialogState;
  openDialog: (d: DialogState) => void;
  closeDialog: () => void;
  /** A folder is being dragged over the window. */
  dragging: boolean;
}

const Ctx = createContext<Store | null>(null);

export function useStore(): Store {
  const s = useContext(Ctx);
  if (!s) throw new Error("store missing");
  return s;
}

export function applyTheme(theme: string) {
  const dark = theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

export function setThemePreference(theme: string) {
  localStorage.setItem("dirshield.theme", theme);
  applyTheme(theme);
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const notify = useNotify();
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [unlocked, setUnlocked] = useState(false);
  const [vaults, setVaults] = useState<VaultInfo[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [ops, setOps] = useState<OperationInfo[]>([]);
  const [live, setLive] = useState<Record<string, Progress>>({});
  const [page, setPage] = useState<Page>("home");
  const [dialog, setDialog] = useState<DialogState>(null);
  const [dragging, setDragging] = useState(false);
  const dialogRef = useRef<DialogState>(null);
  dialogRef.current = dialog;
  const pendingAction = useRef<ShellAction | null>(null);
  const unlockedRef = useRef(false);
  unlockedRef.current = unlocked;

  const refreshInfo = useCallback(async () => {
    const i = await api.appInfo();
    setInfo(i);
    setUnlocked(i.unlocked);
    document.documentElement.classList.toggle("mica", i.mica);
    if (i.accent) document.documentElement.style.setProperty("--accent-base", i.accent);
  }, []);

  const refresh = useCallback(async () => {
    if (!unlockedRef.current) return;
    try {
      const [v, o] = await Promise.all([api.listVaults(), api.listOperations()]);
      setVaults(v);
      setOps(o);
      setLoaded(true);
    } catch {
      /* session may have just locked */
    }
  }, []);

  // Theme: follow the saved preference; "system" tracks Windows live.
  useEffect(() => {
    const pref = localStorage.getItem("dirshield.theme") ?? "system";
    applyTheme(pref);
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const on = () => applyTheme(localStorage.getItem("dirshield.theme") ?? "system");
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);

  useEffect(() => {
    refreshInfo().catch(() => {});
  }, [refreshInfo]);

  // Small window for sign-in, full size once signed in (and back on lock).
  const wasUnlocked = useRef(false);
  useEffect(() => {
    if (unlocked === wasUnlocked.current) return;
    wasUnlocked.current = unlocked;
    if (unlocked) api.setWindowMode(true).catch(() => {});
  }, [unlocked]);

  useEffect(() => {
    if (!unlocked) setLoaded(false);
    if (unlocked) {
      refresh();
      api.getSettings().then((s) => setThemePreference(s.theme)).catch(() => {});
    }
  }, [unlocked, refresh]);

  // Shell (Explorer context menu) actions
  const handleAction = useCallback(
    async (a: ShellAction) => {
      if (!unlockedRef.current) {
        pendingAction.current = a;
        notify({ severity: "info", title: "Sign in to continue", message: "Sign in with your master password to complete the Explorer action." });
        return;
      }
      if (a.action === "settings") return setPage("settings");
      if (!a.path) return;
      if (a.action === "lock" || a.action === "quick-lock" || a.action === "secure-lock") {
        setPage("home");
        setDialog({ kind: "lock", mode: a.action === "secure-lock" ? "secure" : "quick", path: a.path, hide: a.action === "quick-lock" });
        return;
      }
      try {
        const v = await api.findByPath(a.path);
        if (!v) {
          notify({ severity: "info", title: "Not protected", message: `“${a.path}” isn't protected by DirShield.` });
          return;
        }
        setPage("folders");
        if (a.action === "unlock") setDialog({ kind: "unlock", vault: v });
        else if (v.mode === "quick") setDialog({ kind: "visibility", vault: v, hidden: false });
        else notify({ severity: "info", title: "Nothing to unhide", message: "Secure Lock folders are encrypted, not hidden. Use Unlock to restore them." });
      } catch (e) {
        notify({ severity: "error", title: "Couldn't complete the action", message: errMsg(e) });
      }
    },
    [notify],
  );

  useEffect(() => {
    const subs = [
      listen("vaults-changed", () => refresh()),
      listen("ops-changed", () => refresh()),
      listen<Progress[]>("op-progress", (e) => setLive(Object.fromEntries(e.payload.map((p) => [p.id, p])))),
      listen("session-locked", () => {
        setUnlocked(false);
        setDialog(null);
        setVaults([]);
        setLoaded(false);
      }),
      listen<ShellAction>("shell-action", (e) => handleAction(e.payload)),
      // Signed in from the Explorer menu window; its action is waiting as the pending action.
      listen("session-unlocked", () => refreshInfo().catch(() => {})),
      // Background results (scheduled integrity checks, Lock all from the tray).
      listen<{ title: string; body: string; severity?: "info" | "warning" | "error" }>("notice", (e) =>
        notify({ severity: e.payload.severity ?? (e.payload.title.includes("failed") ? "error" : e.payload.title.includes("removed") ? "warning" : "info"), title: e.payload.title, message: e.payload.body }),
      ),
    ];
    return () => {
      subs.forEach((p) => p.then((un) => un()));
    };
  }, [refresh, refreshInfo, handleAction]);

  // Drop a folder on the window to lock it (opens the lock dialog for it).
  useEffect(() => {
    const un = getCurrentWebview().onDragDropEvent((e) => {
      const p = e.payload;
      if (!unlockedRef.current || dialogRef.current) return setDragging(false);
      if (p.type === "enter" || p.type === "over") setDragging(true);
      else if (p.type === "leave") setDragging(false);
      else if (p.type === "drop") {
        setDragging(false);
        if (p.paths.length !== 1) {
          notify({ severity: "info", title: "Drop one folder at a time" });
          return;
        }
        setPage("home");
        setDialog({ kind: "lock", mode: "secure", path: p.paths[0] });
      }
    });
    return () => {
      un.then((f) => f());
    };
  }, [notify]);

  // Clear stale live progress when nothing is running anymore.
  useEffect(() => {
    const ids = new Set(ops.filter((o) => o.live).map((o) => o.id));
    setLive((l) => Object.fromEntries(Object.entries(l).filter(([k]) => ids.has(k))));
  }, [ops]);

  // After sign-in: process the action that launched the app, or one that arrived while locked.
  useEffect(() => {
    if (!unlocked) return;
    (async () => {
      const startup = await api.takePendingAction().catch(() => null);
      const a = pendingAction.current ?? startup;
      pendingAction.current = null;
      if (a) handleAction(a);
    })();
  }, [unlocked, handleAction]);

  // Report user activity (throttled) so auto-lock measures real inactivity.
  useEffect(() => {
    if (!unlocked) return;
    let last = 0;
    const ping = () => {
      const now = Date.now();
      if (now - last > 20_000) {
        last = now;
        api.touch().catch(() => {});
      }
    };
    window.addEventListener("mousemove", ping);
    window.addEventListener("keydown", ping);
    return () => {
      window.removeEventListener("mousemove", ping);
      window.removeEventListener("keydown", ping);
    };
  }, [unlocked]);

  // While anything is live, poll the op list occasionally (status transitions).
  useEffect(() => {
    if (!Object.keys(live).length) return;
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [live, refresh]);

  const value: Store = {
    info,
    refreshInfo,
    unlocked,
    setUnlocked,
    vaults,
    loaded,
    ops,
    live,
    refresh,
    page,
    setPage,
    dialog,
    openDialog: setDialog,
    closeDialog: () => setDialog(null),
    dragging,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
