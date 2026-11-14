import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";

type Variant = "standard" | "accent" | "subtle" | "danger";

export interface FluentButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  icon?: ReactNode;
  size?: "normal" | "large";
}

const base =
  "inline-flex items-center justify-center gap-2 rounded-[4px] text-[14px] leading-5 whitespace-nowrap transition-colors duration-100 disabled:cursor-default select-none";

const variants: Record<Variant, string> = {
  standard:
    "bg-[var(--fill-control)] hover:bg-[var(--fill-control-hover)] active:bg-[var(--fill-control-press)] active:text-[var(--text-2)] text-[var(--text-1)] border border-[var(--stroke-control)] border-b-[var(--stroke-control-bottom)] disabled:bg-[var(--fill-disabled)] disabled:text-[var(--text-disabled)]",
  accent:
    "bg-[var(--accent)] hover:bg-[var(--accent-hover)] active:bg-[var(--accent-press)] text-[var(--on-accent)] border border-black/10 disabled:bg-[var(--fill-disabled)] disabled:text-[var(--text-disabled)] disabled:border-transparent",
  subtle:
    "bg-transparent hover:bg-[var(--fill-subtle-hover)] active:bg-[var(--fill-subtle-press)] text-[var(--text-1)] border border-transparent disabled:text-[var(--text-disabled)]",
  danger:
    "bg-[var(--critical)] hover:opacity-90 active:opacity-80 text-[var(--dialog-bg)] border border-black/10 disabled:bg-[var(--fill-disabled)] disabled:text-[var(--text-disabled)]",
};

export const FluentButton = forwardRef<HTMLButtonElement, FluentButtonProps>(function FluentButton(
  { variant = "standard", icon, size = "normal", className = "", children, type = "button", ...rest },
  ref,
) {
  const pad = children ? (size === "large" ? "px-5 h-10" : "px-3 h-8") : size === "large" ? "w-10 h-10" : "w-8 h-8";
  return (
    <button ref={ref} type={type} className={`${base} ${variants[variant]} ${pad} ${className}`} {...rest}>
      {icon && <span className="text-[16px] flex -my-1">{icon}</span>}
      {children}
    </button>
  );
});
