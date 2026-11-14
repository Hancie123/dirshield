import type { ReactNode } from "react";

export interface NavItem<K extends string> {
  key: K;
  label: string;
  icon: ReactNode;
  iconSelected?: ReactNode;
  badge?: number;
  footer?: boolean;
}

/** Windows Settings–style NavigationView (left pane). */
export function FluentNavigation<K extends string>({ items, value, onChange, header }: { items: NavItem<K>[]; value: K; onChange: (k: K) => void; header?: ReactNode }) {
  const render = (it: NavItem<K>) => {
    const on = it.key === value;
    return (
      <button
        key={it.key}
        onClick={() => onChange(it.key)}
        aria-current={on ? "page" : undefined}
        className={`relative flex items-center gap-4 h-9 px-3 mx-1 rounded-[4px] text-[14px] text-left transition-colors ${on ? "bg-[var(--fill-subtle-hover)]" : "hover:bg-[var(--fill-subtle-hover)] active:bg-[var(--fill-subtle-press)]"}`}
      >
        <span className={`absolute left-0 top-1/2 -translate-y-1/2 w-[3px] rounded-full bg-[var(--accent)] transition-all duration-200 ${on ? "h-4" : "h-0"}`} />
        <span className="text-[18px] flex">{on && it.iconSelected ? it.iconSelected : it.icon}</span>
        <span className="flex-1 truncate">{it.label}</span>
        {!!it.badge && <span className="min-w-[18px] h-[18px] px-1 rounded-full bg-[var(--accent)] text-[var(--on-accent)] text-[11px] leading-[18px] text-center font-semibold">{it.badge}</span>}
      </button>
    );
  };
  return (
    <nav className="flex flex-col h-full w-[280px] shrink-0 pt-2 pb-3 max-[900px]:w-[220px]">
      {header}
      <div className="flex flex-col gap-[2px] mt-2">{items.filter((i) => !i.footer).map(render)}</div>
      <div className="flex-1" />
      <div className="flex flex-col gap-[2px]">{items.filter((i) => i.footer).map(render)}</div>
    </nav>
  );
}
