import { useState } from "react";
import { api, type VaultInfo } from "@/api";
import { FluentInput, InfoBar } from "@/components/fluent";
import { AuthDialog } from "@/features/folders/dialogs/AuthDialog";

export function RemoveOriginalsDialog({ vault }: { vault: VaultInfo }) {
  const [confirm, setConfirm] = useState("");
  return (
    <AuthDialog
      title="Remove unencrypted originals"
      vault={vault}
      danger
      intro={
        <div className="flex flex-col gap-3">
          <InfoBar severity="warning" title="This deletes the original files.">
            Only files that are exactly as they were when encrypted are removed. Files you changed or added afterwards, and anything excluded from the vault, stay in place.
          </InfoBar>
          <p className="t-caption text-[var(--text-2)]">
            This is a normal deletion. On SSDs and modern file systems, deleted data may remain physically recoverable with forensic tools; DirShield does not claim secure erasure.
          </p>
          <p className="t-caption text-[var(--text-2)] selectable">{vault.originalPath}</p>
        </div>
      }
      extra={<FluentInput label={`Type “${vault.name}” to confirm`} value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
      canSubmit={confirm.trim() === vault.name}
      confirmLabel="Remove originals"
      run={(c) => api.removeOriginals(vault.id, c, confirm)}
      success="Originals removed — the folder is now encrypted only."
    />
  );
}
