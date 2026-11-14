import { useStore } from "@/app/store";
import { FluentButton, FluentCard, SectionHeader } from "@/components/fluent";
import { useUpdater } from "@/features/updates/updater";
import logo from "../../../src-tauri/icons/128x128.png";

export function AboutPage() {
  const { info } = useStore();
  return (
    <div className="flex flex-col gap-1">
      <FluentCard className="p-5">
        <div className="flex items-center gap-4">
          <img src={logo} alt="" className="w-12 h-12 shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="t-body-strong">DirShield</div>
            <div className="t-caption text-[var(--text-2)]">
              Version {info?.version ?? "—"}
              <UpdateStatus />
            </div>
          </div>
          <UpdateButton />
        </div>
        <div className="mt-4 pt-4 border-t border-[var(--stroke-divider)] flex flex-col gap-2 text-[14px]">
          <p>
            DirShield keeps your private folders private on Windows. Use Quick Lock to instantly hide a folder and block access to it, or Secure Lock to encrypt its files, names and structure so
            nothing can be read without your password or recovery key.
          </p>
          <p>Lock and unlock right from File Explorer, keep folders open during a work session, and back up your settings safely. Everything stays on your PC — no account, no cloud.</p>
        </div>
      </FluentCard>
      <SectionHeader>Developers</SectionHeader>
      <FluentCard className="p-5">
        <ul className="list-disc pl-5 flex flex-col gap-1 text-[14px] selectable">
          <li>Hancie Phago</li>
          <li>Nitesh Hamal</li>
          <li>Pravesh Rai</li>
        </ul>
      </FluentCard>
    </div>
  );
}

function UpdateStatus() {
  const { state } = useUpdater();
  const text =
    state.kind === "checking"
      ? "Checking for updates…"
      : state.kind === "none"
        ? "You're on the latest version"
        : state.kind === "available"
          ? `Version ${state.update.version} is available`
          : state.kind === "installing"
            ? `Installing${state.pct != null ? ` — ${state.pct}%` : "…"}`
            : state.kind === "error"
              ? `Couldn't check for updates: ${state.message}`
              : null;
  return text ? <span className={state.kind === "error" ? "text-[var(--critical)]" : ""}> · {text}</span> : null;
}

function UpdateButton() {
  const { state, check, install } = useUpdater();
  const { ops } = useStore();
  const busy = ops.some((o) => o.live);
  return state.kind === "available" ? (
    <FluentButton variant="accent" disabled={busy} onClick={install}>
      Install and restart
    </FluentButton>
  ) : (
    <FluentButton disabled={state.kind === "checking" || state.kind === "installing"} onClick={check}>
      Check for updates
    </FluentButton>
  );
}
