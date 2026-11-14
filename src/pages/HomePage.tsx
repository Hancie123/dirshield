import { useEffect, useState } from "react";
import { ArrowRightRegular, FlashRegular, LockOpenRegular, ShieldLockRegular } from "@fluentui/react-icons";
import { api, type Activity } from "../lib/api";
import { FluentButton, FluentCard, FluentProgressBar, SectionHeader, SettingsRow } from "../components/fluent";
import { actionLabel, formatBytes, formatCount, opTypeLabel, relativeTime } from "../lib/format";
import { useStore } from "../lib/store";
import logo from "../../src-tauri/icons/128x128.png";

export function HomePage() {
  const { vaults, ops, live, openDialog, setPage } = useStore();
  const [activity, setActivity] = useState<Activity[]>([]);
  useEffect(() => {
    api.listActivity(6).then(setActivity).catch(() => {});
  }, [vaults, ops]);

  const quick = vaults.filter((v) => v.mode === "quick").length;
  const secure = vaults.filter((v) => v.mode === "secure" && v.status !== "restored").length;
  const storage = vaults.filter((v) => v.status !== "restored").reduce((a, v) => a + v.sizeBytes, 0);
  const active = ops.filter((o) => o.live);
  const attention = ops.filter((o) => !o.live && ["interrupted", "failed", "cancelled"].includes(o.status));

  const stats: [string, string][] = [
    ["Protected folders", formatCount(quick + secure)],
    ["Quick Locked", formatCount(quick)],
    ["Secure Locked", formatCount(secure)],
    ["Protected storage", formatBytes(storage)],
    ["Active operations", formatCount(active.length)],
  ];

  return (
    <div className="flex flex-col gap-1">
      <FluentCard className="p-6 flex items-center gap-6 max-[760px]:flex-col max-[760px]:items-start">
        <img src={logo} alt="" className="w-16 h-16" />
        <div className="flex-1 min-w-0">
          <div className="t-subtitle font-display">Protect a folder</div>
          <div className="text-[var(--text-2)] mt-1">Choose how strongly you want to protect it. You can also right-click any folder in File Explorer.</div>
        </div>
        <div className="flex flex-wrap gap-2">
          <FluentButton variant="accent" icon={<ShieldLockRegular />} onClick={() => openDialog({ kind: "lock", mode: "secure" })}>
            Secure Lock
          </FluentButton>
          <FluentButton icon={<FlashRegular />} onClick={() => openDialog({ kind: "lock", mode: "quick" })}>
            Quick Lock
          </FluentButton>
          <FluentButton icon={<LockOpenRegular />} onClick={() => setPage("folders")}>
            Unlock
          </FluentButton>
        </div>
      </FluentCard>

      <FluentCard className="mt-3 grid grid-cols-5 max-[900px]:grid-cols-3 divide-x divide-[var(--stroke-divider)]">
        {stats.map(([k, v]) => (
          <div key={k} className="px-5 py-4 min-w-0">
            <div className="t-caption text-[var(--text-2)] truncate">{k}</div>
            <div className="text-[20px] leading-7 font-semibold font-display mt-0.5 tabular-nums">{v}</div>
          </div>
        ))}
      </FluentCard>

      {(active.length > 0 || attention.length > 0) && (
        <>
          <SectionHeader>Operations</SectionHeader>
          <div className="flex flex-col gap-1">
            {active.map((o) => {
              const p = live[o.id] ?? o.live!;
              const frac = p.totalBytes ? p.processedBytes / p.totalBytes : null;
              return (
                <SettingsRow key={o.id} icon={<ShieldLockRegular />} title={`${opTypeLabel[o.opType]} · ${o.vaultName}`} description={<FluentProgressBar className="mt-2 max-w-[420px]" value={frac} paused={p.status === "paused"} />} onClick={() => setPage("operations")}>
                  <span className="text-[var(--text-2)] tabular-nums">{frac == null ? "" : `${Math.floor(frac * 100)}%`}</span>
                  <ArrowRightRegular />
                </SettingsRow>
              );
            })}
            {attention.length > 0 && (
              <SettingsRow
                icon={<ShieldLockRegular className="text-[var(--critical)]" />}
                title={`${attention.length} operation(s) need your attention`}
                description="An encryption or restore was interrupted, failed or cancelled. Originals are untouched; resume or discard it."
                onClick={() => setPage("operations")}
              >
                <ArrowRightRegular />
              </SettingsRow>
            )}
          </div>
        </>
      )}

      <SectionHeader>Recent activity</SectionHeader>
      <FluentCard className="py-1">
        {activity.length === 0 && <div className="px-4 py-6 text-[var(--text-2)]">No activity yet.</div>}
        {activity.map((a) => (
          <div key={a.id} className="flex items-center gap-3 px-4 h-11 border-b last:border-0 border-[var(--stroke-divider)]">
            <span className={`w-2 h-2 rounded-full ${a.status === "success" ? "bg-[var(--success)]" : a.status === "failed" ? "bg-[var(--critical)]" : "bg-[var(--text-3)]"}`} />
            <span className="flex-1 truncate">
              {actionLabel(a.action)}
              {a.vaultName && <span className="text-[var(--text-2)]"> · {a.vaultName}</span>}
            </span>
            <span className="t-caption text-[var(--text-2)]">{relativeTime(a.createdAt)}</span>
          </div>
        ))}
      </FluentCard>
      <div className="mt-2">
        <FluentButton variant="subtle" onClick={() => setPage("activity")}>
          View all activity
        </FluentButton>
      </div>
    </div>
  );
}
