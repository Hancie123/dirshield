import type { HTMLAttributes, ReactNode } from "react";

export function FluentCard({ className = "", children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={`rounded-[8px] bg-[var(--card)] border border-[var(--stroke-card)] shadow-[var(--shadow-card)] ${className}`} {...rest}>
      {children}
    </div>
  );
}

/** Windows Settings–style row: icon, title, description, trailing control. */
export function SettingsRow({
  icon,
  title,
  description,
  children,
  onClick,
  className = "",
}: {
  icon?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  onClick?: () => void;
  className?: string;
}) {
  const interactive = !!onClick;
  return (
    <div
      onClick={onClick}
      role={interactive ? "button" : undefined}
      tabIndex={interactive ? 0 : undefined}
      onKeyDown={interactive ? (e) => (e.key === "Enter" || e.key === " ") && onClick?.() : undefined}
      className={`flex items-center gap-4 min-h-[68px] px-4 py-3 rounded-[6px] bg-[var(--card)] border border-[var(--stroke-card)] ${
        interactive ? "hover:bg-[var(--card-hover)]" : ""
      } ${className}`}
    >
      {icon && <span className="text-[20px] flex text-[var(--text-1)] shrink-0">{icon}</span>}
      <div className="flex-1 min-w-0">
        <div className="text-[14px] leading-5">{title}</div>
        {description && <div className="t-caption text-[var(--text-2)] mt-0.5">{description}</div>}
      </div>
      {children && <div className="flex items-center gap-2 shrink-0">{children}</div>}
    </div>
  );
}

export function SectionHeader({ children }: { children: ReactNode }) {
  return <h3 className="t-body-strong mt-7 mb-2 first:mt-0">{children}</h3>;
}

export function Badge({ tone = "neutral", children }: { tone?: "success" | "caution" | "critical" | "neutral" | "accent"; children: ReactNode }) {
  const dot: Record<string, string> = {
    success: "bg-[var(--success)]",
    caution: "bg-[var(--caution)]",
    critical: "bg-[var(--critical)]",
    neutral: "bg-[var(--text-3)]",
    accent: "bg-[var(--accent)]",
  };
  return (
    <span className="inline-flex items-center gap-1.5 text-[12px] leading-4 text-[var(--text-2)] whitespace-nowrap">
      <span className={`w-2 h-2 rounded-full ${dot[tone]}`} />
      {children}
    </span>
  );
}
