import { api, type VaultInfo } from "@/api";
import { AuthDialog } from "@/features/folders/dialogs/AuthDialog";

/** Locks again a folder whose work session DirShield never got to end. */
export function RecoverWorkDialog({ vault }: { vault: VaultInfo }) {
  return (
    <AuthDialog
      title="Lock folder again"
      vault={vault}
      intro={
        <p>
          DirShield closed before it could lock “{vault.name}” again, so it is still decrypted at {vault.restoredPath ?? vault.originalPath}. Its changes will be encrypted into the vault and the
          unlocked copy removed.
        </p>
      }
      confirmLabel="Lock again"
      run={(c) => api.workSessionRecover(vault.id, c)}
      success="Folder locked again."
    />
  );
}
