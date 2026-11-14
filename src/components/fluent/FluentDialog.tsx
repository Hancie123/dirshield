import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

/** WinUI ContentDialog: smoke layer, centered surface, footer band with actions. */
export function FluentDialog({
  open,
  title,
  children,
  footer,
  onClose,
  width = 540,
  dismissable = true,
}: {
  open: boolean;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  onClose?: () => void;
  width?: number;
  dismissable?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    const t = setTimeout(() => {
      const el = ref.current?.querySelector<HTMLElement>("[data-autofocus], input:not([disabled]), button:not([disabled])");
      el?.focus();
    }, 30);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && dismissable) onClose?.();
      if (e.key === "Tab" && ref.current) {
        const f = Array.from(ref.current.querySelectorAll<HTMLElement>("button:not([disabled]), input:not([disabled]), select, [tabindex='0']"));
        if (!f.length) return;
        const first = f[0];
        const last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      clearTimeout(t);
      window.removeEventListener("keydown", onKey);
      prev?.focus?.();
    };
  }, [open, dismissable, onClose]);

  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--smoke)] anim-fade p-6">
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        className="anim-dialog flex flex-col max-h-full rounded-[8px] overflow-hidden bg-[var(--dialog-bg)] border border-[var(--stroke-card)] shadow-[var(--shadow-dialog)]"
        style={{ width, maxWidth: "100%" }}
      >
        <div className="px-6 pt-6 pb-5 overflow-y-auto">
          <h2 className="t-subtitle font-display mb-3">{title}</h2>
          <div className="text-[14px] leading-5">{children}</div>
        </div>
        {footer && <div className="flex justify-end gap-2 px-6 py-6 bg-[var(--dialog-footer)] border-t border-[var(--stroke-card)] [&>*]:min-w-[120px]">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}

/** InfoBar (inline message) used inside dialogs and pages. */
export function InfoBar({ severity = "info", title, children, action }: { severity?: "info" | "success" | "warning" | "error"; title?: ReactNode; children?: ReactNode; action?: ReactNode }) {
  const bg = { info: "bg-[var(--info-bg)]", success: "bg-[var(--success-bg)]", warning: "bg-[var(--caution-bg)]", error: "bg-[var(--critical-bg)]" }[severity];
  const icon = { info: "var(--accent)", success: "var(--success)", warning: "var(--caution)", error: "var(--critical)" }[severity];
  const glyph = { info: "i", success: "✓", warning: "!", error: "✕" }[severity];
  return (
    <div className={`flex items-start gap-3 rounded-[4px] border border-[var(--stroke-card)] px-4 py-3 ${bg}`}>
      <span className="mt-[1px] w-4 h-4 shrink-0 rounded-full flex items-center justify-center text-[10px] font-bold text-[var(--dialog-bg)]" style={{ background: icon }}>
        {glyph}
      </span>
      <div className="flex-1 min-w-0 text-[14px] leading-5">
        {title && <span className="font-semibold mr-2">{title}</span>}
        {children}
      </div>
      {action}
    </div>
  );
}
