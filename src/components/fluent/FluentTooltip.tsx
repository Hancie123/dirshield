import { useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

/** Tooltip shown after a short hover delay, positioned above the target. */
export function FluentTooltip({ content, children, className = "inline-flex" }: { content: ReactNode; children: ReactNode; className?: string }) {
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const timer = useRef<number | undefined>(undefined);
  const show = (el: HTMLElement) => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      const r = el.getBoundingClientRect();
      setPos({ x: r.left + r.width / 2, y: r.top });
    }, 600);
  };
  const hide = () => {
    window.clearTimeout(timer.current);
    setPos(null);
  };
  return (
    <span className={className} onMouseEnter={(e) => show(e.currentTarget)} onMouseLeave={hide} onMouseDown={hide} onFocus={(e) => show(e.currentTarget)} onBlur={hide}>
      {children}
      {pos &&
        createPortal(
          <div
            role="tooltip"
            className="fixed z-[80] max-w-[320px] -translate-x-1/2 -translate-y-full -mt-2 px-2 py-1.5 rounded-[4px] text-[12px] leading-4 bg-[var(--flyout)] border border-[var(--stroke-card)] shadow-[var(--shadow-flyout)] anim-fade pointer-events-none"
            style={{ left: Math.max(170, Math.min(pos.x, window.innerWidth - 170)), top: pos.y - 4 }}
          >
            {content}
          </div>,
          document.body,
        )}
    </span>
  );
}
