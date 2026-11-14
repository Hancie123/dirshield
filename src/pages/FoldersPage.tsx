import { useState } from "react";
import { AddRegular, FlashRegular, FolderRegular, MoreHorizontalRegular, ShieldLockRegular } from "@fluentui/react-icons";
import type { VaultInfo } from "../lib/api";
import { Badge, FluentButton, FluentMenu, FluentTable, FluentTooltip, useFluentContextMenu, type Column } from "../components/fluent";
import { formatBytes, formatCount, formatDate, vaultStatusLabel, vaultTone } from "../lib/format";
import { useStore } from "../lib/store";
import { vaultMenuItems } from "./vaultMenu";

export function FoldersPage() {
  const { vaults, openDialog } = useStore();
  const [selected, setSelected] = useState<string | null>(null);
  const cm = useFluentContextMenu();
  const sel = vaults.find((v) => v.id === selected);

  const columns: Column<VaultInfo>[] = [
    {
      key: "name",
      header: "Name",
      width: "minmax(180px,2fr)",
      render: (v) => (
        <div className="flex items-center gap-3 min-w-0">
          <span className="relative flex text-[22px] text-[#e8a22a]">
            <FolderRegular />
            <span className="absolute -right-1 -bottom-1 text-[12px] text-[var(--accent)] bg-[var(--dialog-bg)] rounded-full">{v.mode === "secure" ? <ShieldLockRegular /> : <FlashRegular />}</span>
          </span>
          <span className="truncate">{v.name}</span>
        </div>
      ),
    },
    { key: "mode", header: "Protection", width: "110px", render: (v) => (v.mode === "secure" ? "Secure Lock" : "Quick Lock") },
    {
      key: "loc",
      header: "Original location",
      width: "minmax(140px,2fr)",
      render: (v) => (
        <FluentTooltip content={v.originalPath}>
          <span className="block truncate text-[var(--text-2)]">{v.originalPath}</span>
        </FluentTooltip>
      ),
    },
    { key: "size", header: "Size", width: "90px", align: "right", render: (v) => <span className="tabular-nums">{formatBytes(v.sizeBytes)}</span> },
    { key: "files", header: "Files", width: "80px", align: "right", render: (v) => <span className="tabular-nums">{formatCount(v.fileCount)}</span> },
    { key: "date", header: "Date locked", width: "150px", render: (v) => <span className="text-[var(--text-2)]">{formatDate(v.lockedAt ?? v.createdAt)}</span> },
    { key: "status", header: "Status", width: "minmax(130px,1.2fr)", render: (v) => <Badge tone={vaultTone(v.status)}>{vaultStatusLabel[v.status]}</Badge> },
    {
      key: "more",
      header: "",
      width: "36px",
      render: (v) => (
        <FluentMenu items={vaultMenuItems(v, openDialog)} trigger={(open) => <FluentButton variant="subtle" aria-label="More actions" icon={<MoreHorizontalRegular />} onClick={open} />} />
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2 flex-wrap">
        <FluentButton variant="accent" icon={<AddRegular />} onClick={() => openDialog({ kind: "lock", mode: "secure" })}>
          Protect a folder
        </FluentButton>
        <div className="w-px h-6 bg-[var(--stroke-divider)] mx-1" />
        {sel ? (
          vaultMenuItems(sel, openDialog)
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
        rowKey={(v) => v.id}
        selected={selected}
        onSelect={(v) => setSelected(v.id)}
        onOpen={(v) => openDialog({ kind: "details", vault: v })}
        onContextMenu={(e, v) => cm.open(e, vaultMenuItems(v, openDialog))}
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
