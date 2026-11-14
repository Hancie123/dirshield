import type { ReactNode } from "react";
import {
  AddRegular,
  ArrowRightRegular,
  ChevronRightRegular,
  FlashRegular,
  FolderAddRegular,
  FolderRegular,
  LockClosedRegular,
  ShieldLockRegular,
  StorageRegular,
  WarningRegular,
} from "@fluentui/react-icons";
import type { VaultStatus } from "@/api";
import { useStore } from "@/app/store";
import { FluentButton, FluentCard, FluentProgressBar, SectionHeader, SettingsRow } from "@/components/fluent";
import { formatBytes, formatCount, opTypeLabel } from "@/lib/format";
import { pickFolder } from "@/lib/pickers";

const LOCKED: VaultStatus[] = ["locked", "quick_locked"];
const OPEN: VaultStatus[] = ["quick_visible", "encrypted", "restored"];

export function HomePage() {
  const { vaults, ops, live, openDialog, setPage, dragging } = useStore();

  const total = vaults.length;
  const locked = vaults.filter((v) => LOCKED.includes(v.status)).length;
  const open = vaults.filter((v) => OPEN.includes(v.status)).length;
  const secure = vaults.filter((v) => v.mode === "secure").length;
  const quick = vaults.filter((v) => v.mode === "quick").length;
  const storage = vaults.filter((v) => v.status !== "restored").reduce((a, v) => a + v.sizeBytes, 0);
  const active = ops.filter((o) => o.live);
  const attention = ops.filter((o) => !o.live && ["interrupted", "failed", "cancelled"].includes(o.status));

  const headline =
    total === 0 ? "No folders protected yet" : open === 0 && locked === total ? "All folders are locked" : open > 0 ? `${open} ${open === 1 ? "folder is" : "folders are"} open` : "Protection in progress";
  const sub = total === 0 ? "Protect a folder to get started." : `${locked} of ${total} locked`;

  return (
    <div className="flex flex-col gap-1">
      <FluentCard className="p-6 flex items-center gap-6 max-[640px]:flex-col max-[640px]:items-start">
        <ProtectionRing ratio={total ? locked / total : 0} empty={total === 0} />
        <div className="flex-1 min-w-0">
          <div className="t-subtitle font-display">{headline}</div>
          <div className="text-[var(--text-2)] mt-0.5">{sub}</div>
        </div>
        <div className="flex flex-wrap gap-2">
          <FluentButton variant="accent" icon={<AddRegular />} onClick={() => openDialog({ kind: "lock", mode: "secure" })}>
            Protect a folder
          </FluentButton>
          <FluentButton icon={<FolderRegular />} onClick={() => setPage("folders")}>
            View folders
          </FluentButton>
        </div>
      </FluentCard>

      <SectionHeader>Protect a folder</SectionHeader>
      <DropZone
        active={dragging}
        onBrowse={async () => {
          const path = await pickFolder("Choose a folder to protect");
          if (path) openDialog({ kind: "lock", mode: "secure", path });
        }}
      />
      <div className="grid grid-cols-2 gap-1 max-[640px]:grid-cols-1">
        <ModeTile icon={<ShieldLockRegular />} title="Secure Lock" description="Encrypts files, names and structure" onClick={() => openDialog({ kind: "lock", mode: "secure" })} />
        <ModeTile icon={<FlashRegular />} title="Quick Lock" description="Hides and blocks a folder instantly" onClick={() => openDialog({ kind: "lock", mode: "quick" })} />
      </div>

      <SectionHeader>Overview</SectionHeader>
      <div className="grid grid-cols-4 gap-1 max-[900px]:grid-cols-2">
        <Stat icon={<LockClosedRegular />} label="Protected folders" value={formatCount(total)} />
        <Stat icon={<ShieldLockRegular />} label="Secure Lock" value={formatCount(secure)} />
        <Stat icon={<FlashRegular />} label="Quick Lock" value={formatCount(quick)} />
        <Stat icon={<StorageRegular />} label="Protected storage" value={formatBytes(storage)} />
      </div>

      {(active.length > 0 || attention.length > 0) && (
        <>
          <SectionHeader>Operations</SectionHeader>
          <div className="flex flex-col gap-1">
            {active.map((o) => {
              const p = live[o.id] ?? o.live!;
              const frac = p.totalBytes ? p.processedBytes / p.totalBytes : null;
              return (
                <SettingsRow
                  key={o.id}
                  icon={<ShieldLockRegular />}
                  title={`${opTypeLabel[o.opType]} · ${o.vaultName}`}
                  description={<FluentProgressBar className="mt-2 max-w-[420px]" value={frac} paused={p.status === "paused"} />}
                  onClick={() => setPage("operations")}
                >
                  <span className="text-[var(--text-2)] tabular-nums">{frac == null ? "" : `${Math.floor(frac * 100)}%`}</span>
                  <ArrowRightRegular />
                </SettingsRow>
              );
            })}
            {attention.length > 0 && (
              <SettingsRow icon={<WarningRegular className="text-[var(--critical)]" />} title={`${attention.length} operation(s) need your attention`} onClick={() => setPage("operations")}>
                <ChevronRightRegular />
              </SettingsRow>
            )}
          </div>
        </>
      )}
    </div>
  );
}

/** Progress ring in the style of Windows Settings storage/backup indicators. */
function ProtectionRing({ ratio, empty }: { ratio: number; empty: boolean }) {
  const r = 34;
  const c = 2 * Math.PI * r;
  return (
    <div className="relative w-[84px] h-[84px] shrink-0">
      <svg viewBox="0 0 84 84" className="w-full h-full -rotate-90">
        <circle cx="42" cy="42" r={r} fill="none" stroke="var(--stroke-divider)" strokeWidth="6" />
        {!empty && (
          <circle
            cx="42"
            cy="42"
            r={r}
            fill="none"
            stroke="var(--accent)"
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={c}
            strokeDashoffset={c * (1 - ratio)}
            style={{ transition: "stroke-dashoffset 0.5s cubic-bezier(0,0,0,1)" }}
          />
        )}
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <ShieldLockRegular fontSize={32} className="text-[var(--text-1)]" />
      </div>
    </div>
  );
}

/** Drop target for folders. The drop itself is handled window-wide in the store; this only shows where to drop. */
function DropZone({ active, onBrowse }: { active: boolean; onBrowse: () => void }) {
  return (
    <div
      className={`flex flex-col items-center justify-center gap-2 py-8 px-4 mb-1 rounded-[6px] border-2 border-dashed text-center transition-colors ${
        active ? "border-[var(--accent)] bg-[var(--fill-subtle-hover)]" : "border-[var(--stroke-strong)]/40 bg-[var(--card)]"
      }`}
    >
      <FolderAddRegular fontSize={36} className={active ? "text-[var(--accent-text)]" : "text-[var(--text-2)]"} />
      <div className="text-[14px] leading-5 font-semibold">{active ? "Release to protect this folder" : "Drag a folder here to protect it"}</div>
      {!active && (
        <div className="flex items-center gap-2 text-[var(--text-2)]">
          <span className="t-caption">or</span>
          <FluentButton onClick={onBrowse}>Browse…</FluentButton>
        </div>
      )}
    </div>
  );
}

function ModeTile({ icon, title, description, onClick }: { icon: ReactNode; title: string; description: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="text-left flex items-center gap-4 min-h-[68px] px-4 py-3 rounded-[6px] bg-[var(--card)] border border-[var(--stroke-card)] hover:bg-[var(--card-hover)] active:bg-[var(--fill-subtle-press)]"
    >
      <span className="text-[20px] flex text-[var(--text-1)] shrink-0">{icon}</span>
      <span className="flex-1 min-w-0">
        <span className="block text-[14px] leading-5">{title}</span>
        <span className="block t-caption text-[var(--text-2)] mt-0.5 truncate">{description}</span>
      </span>
      <ChevronRightRegular className="text-[var(--text-1)] shrink-0" />
    </button>
  );
}

function Stat({ icon, label, value, className = "" }: { icon: ReactNode; label: string; value: string; className?: string }) {
  return (
    <FluentCard className={`px-4 py-3 flex items-center gap-4 min-w-0 min-h-[68px] ${className}`}>
      <span className="text-[20px] flex text-[var(--text-1)] shrink-0">{icon}</span>
      <div className="min-w-0">
        <div className="t-caption text-[var(--text-2)] truncate">{label}</div>
        <div className="text-[14px] leading-5 font-semibold tabular-nums truncate">{value}</div>
      </div>
    </FluentCard>
  );
}
