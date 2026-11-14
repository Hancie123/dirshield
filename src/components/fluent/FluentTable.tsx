import { useEffect, useRef, useState, type ReactNode } from "react";
import { FluentSkeleton, SKELETON_WIDTHS } from "./FluentSkeleton";

export interface Column<T> {
  key: string;
  header: string;
  width?: string;
  render: (row: T) => ReactNode;
  align?: "left" | "right";
  /** Leave this column out while the table is narrower than this (px). */
  hideBelow?: number;
}

/** Explorer "Details" view–style list with column headers and row hover/selection. */
export function FluentTable<T>({
  columns,
  rows,
  rowKey,
  selected,
  onSelect,
  onOpen,
  onContextMenu,
  empty,
  minWidth,
  loading,
  skeletonRows = 5,
}: {
  /** Show placeholder rows instead of `rows` / `empty`. */
  loading?: boolean;
  skeletonRows?: number;
  /** Below this width the table scrolls horizontally instead of squeezing columns. */
  minWidth?: number;
  columns: Column<T>[];
  rows: T[];
  rowKey: (r: T) => string;
  selected?: string | null;
  onSelect?: (r: T) => void;
  onOpen?: (r: T) => void;
  onContextMenu?: (e: React.MouseEvent, r: T) => void;
  empty?: ReactNode;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState<number | null>(null);
  const responsive = columns.some((c) => c.hideBelow);
  useEffect(() => {
    const el = box.current;
    if (!el || !responsive) return;
    const ro = new ResizeObserver(([e]) => setWidth(e.contentRect.width));
    ro.observe(el);
    return () => ro.disconnect();
  }, [responsive]);
  // Until measured, show every column.
  if (width != null) columns = columns.filter((c) => !c.hideBelow || width >= c.hideBelow);
  const template = columns.map((c) => c.width ?? "1fr").join(" ");
  return (
    <div ref={box} className="rounded-[8px] bg-[var(--card)] border border-[var(--stroke-card)] overflow-x-auto">
    <div role="grid" style={{ minWidth }}>
      <div role="row" className="grid items-center h-9 px-3 gap-3 mx-1 border-b border-[var(--stroke-divider)] t-caption text-[var(--text-2)]" style={{ gridTemplateColumns: template }}>
        {columns.map((c) => (
          <div role="columnheader" key={c.key} className={`truncate ${c.align === "right" ? "text-right" : ""}`}>
            {c.header}
          </div>
        ))}
      </div>
      {loading && (
        <div role="status" aria-label="Loading" aria-busy="true">
          {Array.from({ length: skeletonRows }, (_, i) => (
            <div key={i} className="grid items-center min-h-[48px] px-3 gap-3 mx-1 my-[2px]" style={{ gridTemplateColumns: template }}>
              {columns.map((c, j) => (
                <div key={c.key} className={`flex min-w-0 ${c.align === "right" ? "justify-end" : ""}`}>
                  {c.header && <FluentSkeleton width={SKELETON_WIDTHS[(i + j) % SKELETON_WIDTHS.length]} />}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
      {!loading && rows.length === 0 && <div className="px-4 py-10 text-center text-[var(--text-2)]">{empty}</div>}
      {!loading && rows.map((r) => {
        const k = rowKey(r);
        const sel = selected === k;
        return (
          <div
            role="row"
            aria-selected={sel}
            tabIndex={0}
            key={k}
            onClick={() => onSelect?.(r)}
            onDoubleClick={() => onOpen?.(r)}
            onKeyDown={(e) => e.key === "Enter" && onOpen?.(r)}
            onContextMenu={(e) => {
              onSelect?.(r);
              onContextMenu?.(e, r);
            }}
            className={`relative grid items-center min-h-[48px] px-3 gap-3 mx-1 my-[2px] rounded-[4px] outline-none ${sel ? "bg-[var(--fill-subtle-hover)]" : "hover:bg-[var(--fill-subtle-hover)]"} focus-visible:outline-2`}
            style={{ gridTemplateColumns: template }}
          >
            {sel && <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-4 rounded-full bg-[var(--accent)]" />}
            {columns.map((c) => (
              <div role="gridcell" key={c.key} className={`min-w-0 text-[14px] ${c.align === "right" ? "text-right" : ""}`}>
                {c.render(r)}
              </div>
            ))}
          </div>
        );
      })}
    </div>
    </div>
  );
}
