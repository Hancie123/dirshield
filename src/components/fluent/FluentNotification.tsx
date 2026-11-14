import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { DismissRegular } from "@fluentui/react-icons";

type Severity = "info" | "success" | "warning" | "error";
interface Toast {
  id: number;
  severity: Severity;
  title: string;
  message?: string;
  action?: { label: string; onClick: () => void };
}

const Ctx = createContext<(t: Omit<Toast, "id">) => void>(() => {});

export function useNotify() {
  return useContext(Ctx);
}

/** In-app notifications in the style of Windows toasts (bottom-right stack). */
export function NotificationHost({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const notify = useCallback((t: Omit<Toast, "id">) => {
    const id = Date.now() + Math.random();
    setToasts((ts) => [...ts.slice(-3), { ...t, id }]);
    setTimeout(() => setToasts((ts) => ts.filter((x) => x.id !== id)), t.severity === "error" ? 9000 : 5500);
  }, []);
  const color = { info: "var(--accent)", success: "var(--success)", warning: "var(--caution)", error: "var(--critical)" };
  return (
    <Ctx.Provider value={notify}>
      {children}
      <div className="fixed right-4 bottom-4 z-[70] flex flex-col gap-2 w-[360px] max-w-[calc(100vw-32px)]" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className="anim-flyout rounded-[8px] bg-[var(--flyout)] backdrop-blur-xl border border-[var(--stroke-card)] shadow-[var(--shadow-flyout)] p-4 flex gap-3">
            <span className="w-1 rounded-full shrink-0" style={{ background: color[t.severity] }} />
            <div className="flex-1 min-w-0">
              <div className="t-body-strong">{t.title}</div>
              {t.message && <div className="text-[13px] text-[var(--text-2)] mt-0.5 break-words selectable">{t.message}</div>}
              {t.action && (
                <button
                  className="mt-2 text-[14px] text-[var(--accent-text)] hover:underline"
                  onClick={() => {
                    t.action!.onClick();
                    setToasts((ts) => ts.filter((x) => x.id !== t.id));
                  }}
                >
                  {t.action.label}
                </button>
              )}
            </div>
            <button aria-label="Dismiss" className="self-start w-6 h-6 rounded-[4px] flex items-center justify-center text-[var(--text-2)] hover:bg-[var(--fill-subtle-hover)]" onClick={() => setToasts((ts) => ts.filter((x) => x.id !== t.id))}>
              <DismissRegular fontSize={14} />
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}
