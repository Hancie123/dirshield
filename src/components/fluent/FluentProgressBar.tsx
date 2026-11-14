export function FluentProgressBar({ value, paused, error, className = "" }: { value?: number | null; paused?: boolean; error?: boolean; className?: string }) {
  const indeterminate = value == null;
  const color = error ? "bg-[var(--critical)]" : paused ? "bg-[var(--caution)]" : "bg-[var(--accent)]";
  return (
    <div
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={indeterminate ? undefined : Math.round(value * 100)}
      className={`relative h-[3px] w-full overflow-hidden rounded-full ${className}`}
    >
      <div className="absolute inset-x-0 top-1/2 -translate-y-1/2 h-px bg-[var(--stroke-strong)]" />
      {indeterminate ? (
        <div className={`absolute top-0 h-full w-[40%] rounded-full ${color}`} style={{ animation: "fl-indeterminate 1.6s ease-in-out infinite" }} />
      ) : (
        <div className={`absolute top-0 left-0 h-full rounded-full transition-[width] duration-300 ${color}`} style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }} />
      )}
    </div>
  );
}

export function FluentSpinner({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" style={{ animation: "fl-spin 1s linear infinite" }} role="status" aria-label="Working">
      <circle cx="8" cy="8" r="6.5" fill="none" stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="round" strokeDasharray="28 14" />
    </svg>
  );
}
