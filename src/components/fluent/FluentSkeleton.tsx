import type { CSSProperties } from "react";

/** Placeholder block shown while content loads (WinUI shimmer). */
export function FluentSkeleton({ width = "100%", height = 12, round = false, className = "", style }: { width?: number | string; height?: number | string; round?: boolean; className?: string; style?: CSSProperties }) {
  return <span aria-hidden className={`fl-skeleton block ${round ? "rounded-full" : "rounded-[4px]"} ${className}`} style={{ width, height, ...style }} />;
}

/** Widths cycled through so placeholder rows don't look identical. */
export const SKELETON_WIDTHS = ["72%", "54%", "86%", "63%", "45%", "78%"];

/** Placeholder rows for a list or table that is still loading: `columns` bars per row, laid out by the CSS grid `template` if given. */
export function SkeletonRows({ rows = 5, template, columns = 1, rowHeight = 48 }: { rows?: number; template?: string; columns?: number; rowHeight?: number }) {
  const cols = columns;
  return (
    <div role="status" aria-label="Loading" aria-busy="true">
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="grid items-center px-3 gap-3 mx-1 my-[2px]" style={{ gridTemplateColumns: template ?? `repeat(${cols}, 1fr)`, minHeight: rowHeight }}>
          {Array.from({ length: cols }, (_, c) => (
            <FluentSkeleton key={c} width={SKELETON_WIDTHS[(r + c) % SKELETON_WIDTHS.length]} />
          ))}
        </div>
      ))}
    </div>
  );
}
