import { api, type VaultInfo } from "@/api";
import { AuthDialog } from "@/features/folders/dialogs/AuthDialog";

export function VerifyDialog({ vault }: { vault: VaultInfo }) {
  return (
    <AuthDialog
      title="Check vault integrity"
      vault={vault}
      intro={<p>DirShield will decrypt and authenticate every chunk of every file and compare checksums. Nothing is written to disk.</p>}
      confirmLabel="Check now"
      run={(c) => api.verifyVault(vault.id, c)}
      success="Vault verified — every file is intact."
    />
  );
}
