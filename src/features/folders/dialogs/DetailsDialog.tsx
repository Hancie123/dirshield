import { useEffect, useState } from "react";
import { api, errMsg, type VaultDetails, type VaultInfo } from "@/api";
import { useStore } from "@/app/store";
import { KeyValue } from "@/components/KeyValue";
import { FluentButton, FluentDialog, InfoBar } from "@/components/fluent";
import { formatBytes, formatCount, formatDate, vaultStatusLabel } from "@/lib/format";

export function DetailsDialog({ vault }: { vault: VaultInfo }) {
  const { closeDialog } = useStore();
  const [d, setD] = useState<VaultDetails | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    api.vaultDetails(vault.id).then(setD).catch((e) => setErr(errMsg(e)));
  }, [vault.id]);
  const v = d ?? vault;
  return (
    <FluentDialog open title={vault.name} width={620} onClose={closeDialog} footer={<FluentButton onClick={closeDialog}>Close</FluentButton>}>
      {err && <InfoBar severity="error">{err}</InfoBar>}
      <KeyValue
        rows={[
          ["Protection", v.mode === "quick" ? "Quick Lock (access restriction, not encryption)" : "Secure Lock (encrypted)"],
          ["Status", vaultStatusLabel[v.status]],
          ["Original location", v.originalPath],
          ["Size", `${formatBytes(v.sizeBytes)} · ${formatCount(v.fileCount)} files`],
          ["Locked", formatDate(v.lockedAt)],
          ["Unlocks with", v.keyMode === "password" ? "Folder password or recovery key" : "Master password or recovery key"],
          ...((d?.currentPath ? [["Stored at", d.currentPath]] : []) as [string, string][]),
          ...((v.mode === "secure"
            ? [
                ["Vault folder", v.vaultPath],
                ["Algorithm", d?.algorithm ?? "—"],
                ["Chunk size", d?.chunkSize ? formatBytes(d.chunkSize) : "—"],
                ["Key wrappers", d?.wrappers.join(", ") || "—"],
                ["Format version", String(d?.formatVersion ?? "—")],
                ["Sealed", d?.sealed == null ? "—" : d.sealed ? "Yes — complete and verified" : "No — incomplete"],
                ["Last integrity check", d?.lastVerifiedAt ? formatDate(d.lastVerifiedAt) : "Never"],
                ["Recovery key", d?.recoveryCurrent == null ? "—" : d.recoveryCurrent ? "Current key" : "An older key — change this folder's password to update it"],
                ["On another PC", d?.portable ? "Opens with the master password" : v.keyMode === "password" ? "Opens with the folder password or recovery key" : "Opens with the recovery key"],
                ...((v.workSession ? [["Work session", "Locked again when you sign out or Windows locks"]] : []) as [string, string][]),
              ]
            : []) as [string, string][]),
          ...((v.skippedCount > 0 ? [["Not in vault", `${formatCount(v.skippedCount)} item(s) (links, unreadable or excluded) remain in the original folder`]] : []) as [string, string][]),
        ]}
      />
    </FluentDialog>
  );
}
