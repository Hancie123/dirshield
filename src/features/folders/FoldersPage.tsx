import { useState } from "react";
import { AddRegular, FlashRegular, FolderRegular, LockClosedRegular, MoreHorizontalRegular, ShieldLockRegular } from "@fluentui/react-icons";
import { api, errMsg, type VaultInfo } from "@/api";
import { useStore } from "@/app/store";
import { Badge, FluentButton, FluentMenu, FluentTable, FluentTooltip, useFluentContextMenu, useNotify, type Column } from "@/components/fluent";
import { vaultMenuItems, type MenuAct } from "@/features/folders/vaultMenu";
import { formatBytes, formatCount, formatDate, vaultStatusLabel, vaultTone } from "@/lib/format";

export function FoldersPage() {
  const { vaults, loaded, openDialog, refresh } = useStore();
  const notify = useNotify();
  const [selected, setSelected] = useState<string | null>(null);
  const act: MenuAct = (f, success) =>
    f()
      .then(() => notify({ severity: "success", title: success }))
      .catch((e) => notify({ severity: "error", title: "Couldn't complete the action", message: errMsg(e) }))
      .finally(() => refresh());
  const lockable = vaults.some((v) => v.status === "quick_visible" || v.status === "restored");
  const cm = useFluentContextMenu();
  const sel = vaults.find((v) => v.id === selected);

  const columns: Column<VaultInfo>[] = [
    {
      key: "name",
      header: "Name",
      width: "minmax(140px,2fr)",
      render: (v) => (
        <div className="flex items-center gap-3 min-w-0">
          <span className="relative flex text-[22px] text-[#e8a22a]">
            <FolderRegular />
            <span className="absolute -right-1 -bottom-1 text-[12px] text-[var(--accent)] bg-[var(--dialog-bg)] rounded-full">{v.mode === "secure" ? <ShieldLockRegular /> : <FlashRegular />}</span>
          </span>
          <span className="truncate">{v.name}</span>
          {v.workSession && <Badge tone="caution">Work session</Badge>}
          {v.relockPending && (
            <FluentTooltip content="DirShield closed before this work session ended. The folder is still decrypted on disk: choose Lock again now.">
              <Badge tone="critical">Left unlocked</Badge>
            </FluentTooltip>
          )}
        </div>
      ),
    },
    { key: "mode", header: "Protection", width: "100px", hideBelow: 680, render: (v) => <span className="whitespace-nowrap">{v.mode === "secure" ? "Secure Lock" : "Quick Lock"}</span> },
    {
      key: "loc",
      header: "Original location",
      width: "minmax(100px,2fr)",
      hideBelow: 470,
      render: (v) => (
        <FluentTooltip content={v.originalPath} className="flex min-w-0">
          <span className="truncate text-[var(--text-2)]">{v.originalPath}</span>
        </FluentTooltip>
      ),
    },
    { key: "size", header: "Size", width: "80px", align: "right", hideBelow: 570, render: (v) => <span className="tabular-nums whitespace-nowrap">{formatBytes(v.sizeBytes)}</span> },
    { key: "files", header: "Files", width: "56px", align: "right", hideBelow: 910, render: (v) => <span className="tabular-nums">{formatCount(v.fileCount)}</span> },
    { key: "date", header: "Date locked", width: "160px", hideBelow: 850, render: (v) => <span className="block truncate text-[var(--text-2)]">{formatDate(v.lockedAt ?? v.createdAt)}</span> },
    { key: "status", header: "Status", width: "minmax(120px,1fr)", render: (v) => <Badge tone={vaultTone(v.status)}>{vaultStatusLabel[v.status]}</Badge> },
    {
      key: "more",
      header: "",
      width: "36px",
      render: (v) => (
        <FluentMenu items={vaultMenuItems(v, openDialog, act)} trigger={(open) => <FluentButton variant="subtle" aria-label="More actions" icon={<MoreHorizontalRegular />} onClick={open} />} />
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2 flex-wrap">
        <FluentButton variant="accent" icon={<AddRegular />} onClick={() => openDialog({ kind: "lock", mode: "secure" })}>
          Protect a folder
        </FluentButton>
        <FluentTooltip content="Hide visible Quick Lock folders and lock restored folders again">
          <FluentButton
            variant="subtle"
            icon={<LockClosedRegular />}
            disabled={!lockable}
            onClick={() =>
              api
                .lockAllFolders()
                .then((r) =>
                  notify({
                    severity: r.skipped.length ? "warning" : "success",
                    title: "Lock all",
                    message: `${r.hidden} hidden, ${r.relocking} being locked again.${r.skipped.length ? ` Not locked: ${r.skipped.join(", ")}.` : ""}`,
                  }),
                )
                .catch((e) => notify({ severity: "error", title: "Lock all failed", message: errMsg(e) }))
                .finally(() => refresh())
            }
          >
            Lock all
          </FluentButton>
        </FluentTooltip>
        <div className="w-px h-6 bg-[var(--stroke-divider)] mx-1" />
        {sel ? (
          vaultMenuItems(sel, openDialog, act)
            .filter((i) => !i.separator && ["unlock", "restore", "details", "originals"].includes(i.key))
            .map((i) => (
              <FluentButton key={i.key} variant="subtle" icon={i.icon} disabled={i.disabled} onClick={i.onClick}>
                {i.label}
              </FluentButton>
            ))
        ) : (
          <span className="t-caption text-[var(--text-2)]">Select a folder to see actions. Right-click for more.</span>
        )}
      </div>
      <FluentTable
        columns={columns}
        rows={vaults}
        loading={!loaded}
        rowKey={(v) => v.id}
        // Columns drop out as the window narrows (see hideBelow) so the table
        // fits the smallest window without scrolling sideways.
        minWidth={360}
        selected={selected}
        onSelect={(v) => setSelected(v.id)}
        onOpen={(v) => openDialog({ kind: "details", vault: v })}
        onContextMenu={(e, v) => cm.open(e, vaultMenuItems(v, openDialog, act))}
        empty={
          <div className="flex flex-col items-center gap-2">
            <FolderRegular fontSize={40} className="text-[var(--text-3)]" />
            <div>No protected folders yet.</div>
            <div className="t-caption">Use “Protect a folder”, or right-click a folder in File Explorer and choose DirShield.</div>
          </div>
        }
      />
      {cm.element}
    </div>
  );
}
