import { useState } from "react";
import { api, type VaultInfo } from "@/api";
import { FluentInput, InfoBar } from "@/components/fluent";
import { AuthDialog } from "@/features/folders/dialogs/AuthDialog";

export function DeleteVaultDialog({ vault }: { vault: VaultInfo }) {
  const [confirm, setConfirm] = useState("");
  const dataLoss = vault.status === "locked";
  return (
    <AuthDialog
      title="Delete encrypted vault"
      vault={vault}
      danger
      intro={
        dataLoss ? (
          <InfoBar severity="error" title="This permanently destroys the only copy.">
            The originals of “{vault.name}” were removed. Deleting the vault means this data is gone for good. Restore the folder first if you still need it.
          </InfoBar>
        ) : (
          <InfoBar severity="warning" title="The encrypted copy will be deleted.">
            {vault.status === "restored" ? "The folder has been restored, so its files exist unencrypted at the destination." : "The unencrypted originals are still in place."}
          </InfoBar>
        )
      }
      extra={<FluentInput label={`Type “${vault.name}” to confirm`} value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
      canSubmit={confirm.trim() === vault.name}
      confirmLabel="Delete vault"
      run={(c) => api.deleteVault(vault.id, c, confirm)}
      success="Vault deleted"
    />
  );
}
