import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

export interface MenuItem {
  key: string;
  label?: string;
  icon?: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  danger?: boolean;
  separator?: boolean;
}

/** MenuFlyout surface positioned at a point, kept on screen. */
function MenuSurface({ x, y, items, onClose }: { x: number; y: number; items: MenuItem[]; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ left: x, top: y });
  useLayoutEffect(() => {
    const r = ref.current?.getBoundingClientRect();
    if (!r) return;
    setPos({ left: Math.min(x, window.innerWidth - r.width - 8), top: y + r.height > window.innerHeight - 8 ? Math.max(8, y - r.height) : y });
  }, [x, y]);
  useEffect(() => {
    const close = (e: Event) => {
      if (ref.current && e.target instanceof Node && ref.current.contains(e.target)) return;
      onClose();
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const btns = Array.from(ref.current?.querySelectorAll<HTMLButtonElement>("button:not([disabled])") ?? []);
        const i = btns.indexOf(document.activeElement as HTMLButtonElement);
        const n = e.key === "ArrowDown" ? (i + 1) % btns.length : (i - 1 + btns.length) % btns.length;
        btns[n]?.focus();
      }
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("blur", onClose);
    window.addEventListener("keydown", key);
    window.addEventListener("resize", onClose);
    ref.current?.querySelector<HTMLButtonElement>("button:not([disabled])")?.focus();
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("blur", onClose);
      window.removeEventListener("keydown", key);
      window.removeEventListener("resize", onClose);
    };
  }, [onClose]);
  return createPortal(
    <div
      ref={ref}
      role="menu"
      className="fixed z-[60] min-w-[200px] py-1 rounded-[8px] bg-[var(--flyout)] backdrop-blur-xl border border-[var(--stroke-card)] shadow-[var(--shadow-flyout)] anim-flyout"
      style={pos}
      onContextMenu={(e) => e.preventDefault()}
    >
      {items.map((it) =>
        it.separator ? (
          <div key={it.key} className="my-1 h-px bg-[var(--stroke-divider)]" />
        ) : (
          <button
            key={it.key}
            role="menuitem"
            disabled={it.disabled}
            onClick={() => {
              onClose();
              it.onClick?.();
            }}
            className={`flex w-[calc(100%-8px)] mx-1 items-center gap-3 h-8 px-3 rounded-[4px] text-left text-[14px] outline-none hover:bg-[var(--fill-subtle-hover)] focus:bg-[var(--fill-subtle-hover)] disabled:text-[var(--text-disabled)] disabled:hover:bg-transparent ${
              it.danger ? "text-[var(--critical)]" : ""
            }`}
          >
            <span className="w-4 flex text-[16px]">{it.icon}</span>
            {it.label}
          </button>
        ),
      )}
    </div>,
    document.body,
  );
}

/** Drop-down menu attached to a trigger element. */
export function FluentMenu({ trigger, items }: { trigger: (open: (e: React.MouseEvent) => void) => ReactNode; items: MenuItem[] }) {
  const [at, setAt] = useState<{ x: number; y: number } | null>(null);
  return (
    <>
      {trigger((e) => {
        e.stopPropagation();
        const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
        setAt({ x: r.left, y: r.bottom + 4 });
      })}
      {at && <MenuSurface x={at.x} y={at.y} items={items} onClose={() => setAt(null)} />}
    </>
  );
}

/** Right-click context menu. Use `open(e)` from an onContextMenu handler. */
export function useFluentContextMenu() {
  const [state, setState] = useState<{ x: number; y: number; items: MenuItem[] } | null>(null);
  const open = (e: React.MouseEvent, items: MenuItem[]) => {
    e.preventDefault();
    setState({ x: e.clientX, y: e.clientY, items });
  };
  const element = state ? <MenuSurface x={state.x} y={state.y} items={state.items} onClose={() => setState(null)} /> : null;
  return { open, element };
}

export function FluentContextMenu({ children, items }: { children: ReactNode; items: MenuItem[] }) {
  const cm = useFluentContextMenu();
  return (
    <div onContextMenu={(e) => cm.open(e, items)}>
      {children}
      {cm.element}
    </div>
  );
}
