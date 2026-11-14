import type { ReactNode } from "react";

export function FluentToggle({ checked, onChange, disabled, label, showState = true }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string; showState?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-3 ${disabled ? "opacity-60" : ""}`}>
      {showState && <span className="text-[14px] min-w-6 text-right">{checked ? "On" : "Off"}</span>}
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`group relative w-10 h-5 rounded-full transition-colors border ${
          checked ? "bg-[var(--accent)] border-[var(--accent)] hover:bg-[var(--accent-hover)]" : "bg-[var(--fill-control)] border-[var(--stroke-strong)] hover:bg-[var(--fill-subtle-hover)]"
        }`}
      >
        <span
          className={`absolute top-1/2 -translate-y-1/2 w-3 h-3 rounded-full transition-all duration-150 group-hover:w-[14px] group-hover:h-[14px] ${
            checked ? "left-[22px] group-hover:left-[21px] bg-[var(--on-accent)]" : "left-[3px] bg-[var(--text-2)]"
          }`}
        />
      </button>
    </span>
  );
}

export function FluentCheckbox({ checked, onChange, children, disabled }: { checked: boolean; onChange: (v: boolean) => void; children: ReactNode; disabled?: boolean }) {
  return (
    <label className={`flex items-start gap-2.5 ${disabled ? "opacity-60" : ""}`}>
      <button
        type="button"
        role="checkbox"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`mt-[1px] w-[18px] h-[18px] shrink-0 rounded-[4px] border flex items-center justify-center transition-colors ${
          checked ? "bg-[var(--accent)] border-[var(--accent)] text-[var(--on-accent)]" : "bg-[var(--fill-control)] border-[var(--stroke-strong)] hover:bg-[var(--fill-subtle-hover)]"
        }`}
      >
        {checked && (
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M2.5 6.5l2.5 2.5 4.5-5.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        )}
      </button>
      <span className="text-[14px] leading-5">{children}</span>
    </label>
  );
}

export function FluentRadio<T extends string>({
  value,
  options,
  onChange,
  name,
}: {
  value: T;
  options: { value: T; label: ReactNode; description?: ReactNode; disabled?: boolean }[];
  onChange: (v: T) => void;
  name: string;
}) {
  return (
    <div role="radiogroup" aria-label={name} className="flex flex-col gap-2.5">
      {options.map((o) => {
        const on = o.value === value;
        return (
          <label key={o.value} className={`flex items-start gap-2.5 ${o.disabled ? "opacity-50" : ""}`}>
            <button
              type="button"
              role="radio"
              aria-checked={on}
              disabled={o.disabled}
              onClick={() => onChange(o.value)}
              className={`group mt-[0px] w-5 h-5 shrink-0 rounded-full border flex items-center justify-center ${
                on ? "bg-[var(--accent)] border-[var(--accent)]" : "bg-[var(--fill-control)] border-[var(--stroke-strong)] hover:bg-[var(--fill-subtle-hover)]"
              }`}
            >
              <span className={`rounded-full bg-[var(--on-accent)] transition-all ${on ? "w-2.5 h-2.5 group-hover:w-3 group-hover:h-3" : "w-0 h-0"}`} />
            </button>
            <span>
              <span className="text-[14px] leading-5">{o.label}</span>
              {o.description && <span className="block t-caption text-[var(--text-2)] mt-0.5">{o.description}</span>}
            </span>
          </label>
        );
      })}
    </div>
  );
}

export function FluentSelect<T extends string | number>({ value, options, onChange, label }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; label?: string }) {
  return (
    <select
      aria-label={label}
      value={String(value)}
      onChange={(e) => {
        const o = options.find((x) => String(x.value) === e.target.value);
        if (o) onChange(o.value);
      }}
      className="h-8 min-w-[150px] rounded-[4px] px-2.5 bg-[var(--fill-control)] hover:bg-[var(--fill-control-hover)] border border-[var(--stroke-control)] border-b-[var(--stroke-control-bottom)] text-[14px] text-[var(--text-1)] outline-none"
    >
      {options.map((o) => (
        <option key={String(o.value)} value={String(o.value)} style={{ background: "var(--card-solid)", color: "var(--text-1)" }}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

/** Segmented control (two or three exclusive choices). */
export function FluentSegmented<T extends string>({ value, options, onChange }: { value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex p-[3px] gap-[2px] rounded-[6px] bg-[var(--fill-subtle-press)] border border-[var(--stroke-control)]">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          className={`h-7 px-3 rounded-[4px] text-[14px] inline-flex items-center gap-1.5 transition-colors ${
            o.value === value ? "bg-[var(--fill-input-focus)] shadow-[0_1px_2px_rgba(0,0,0,0.12)] text-[var(--text-1)]" : "text-[var(--text-2)] hover:bg-[var(--fill-subtle-hover)]"
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
