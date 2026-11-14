import type { ReactNode } from "react";

export interface Column<T> {
  key: string;
  header: string;
  width?: string;
  render: (row: T) => ReactNode;
  align?: "left" | "right";
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
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (r: T) => string;
  selected?: string | null;
  onSelect?: (r: T) => void;
  onOpen?: (r: T) => void;
  onContextMenu?: (e: React.MouseEvent, r: T) => void;
  empty?: ReactNode;
}) {
  const template = columns.map((c) => c.width ?? "1fr").join(" ");
  return (
    <div role="grid" className="rounded-[8px] bg-[var(--card)] border border-[var(--stroke-card)] overflow-hidden">
      <div role="row" className="grid items-center h-9 px-3 gap-3 border-b border-[var(--stroke-divider)] t-caption text-[var(--text-2)]" style={{ gridTemplateColumns: template }}>
        {columns.map((c) => (
          <div role="columnheader" key={c.key} className={`truncate ${c.align === "right" ? "text-right" : ""}`}>
            {c.header}
          </div>
        ))}
      </div>
      {rows.length === 0 && <div className="px-4 py-10 text-center text-[var(--text-2)]">{empty}</div>}
      {rows.map((r) => {
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
  );
}
