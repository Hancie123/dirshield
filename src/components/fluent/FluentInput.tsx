import { forwardRef, useId, type InputHTMLAttributes, type ReactNode } from "react";

export interface FluentInputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  trailing?: ReactNode;
}

export const inputShell =
  "flex items-center h-8 rounded-[4px] bg-[var(--fill-control)] border border-[var(--stroke-control)] border-b-[var(--stroke-strong)] hover:bg-[var(--fill-control-hover)] focus-within:bg-[var(--fill-input-focus)] focus-within:border-b-[var(--accent)] focus-within:shadow-[inset_0_-1px_0_var(--accent)] transition-colors";

export const FluentInput = forwardRef<HTMLInputElement, FluentInputProps>(function FluentInput({ label, hint, error, trailing, className = "", id, ...rest }, ref) {
  const auto = useId();
  const inputId = id ?? auto;
  return (
    <div className={`flex flex-col gap-1.5 ${className}`}>
      {label && (
        <label htmlFor={inputId} className="text-[14px] leading-5">
          {label}
        </label>
      )}
      <div className={inputShell}>
        <input
          ref={ref}
          id={inputId}
          className="flex-1 min-w-0 h-full bg-transparent outline-none px-[11px] text-[14px] text-[var(--text-1)] placeholder:text-[var(--text-3)] disabled:text-[var(--text-disabled)]"
          {...rest}
        />
        {trailing}
      </div>
      {error ? <div className="t-caption text-[var(--critical)]">{error}</div> : hint ? <div className="t-caption text-[var(--text-2)]">{hint}</div> : null}
    </div>
  );
});
