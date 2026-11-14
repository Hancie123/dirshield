import { api, type VaultInfo } from "@/api";
import { AuthDialog } from "@/features/folders/dialogs/AuthDialog";

export function VisibilityDialog({ vault, hidden }: { vault: VaultInfo; hidden: boolean }) {
  return (
    <AuthDialog
      title={hidden ? "Hide folder" : "Unhide folder"}
      vault={vault}
      intro={
        <p>
          {hidden
            ? "The folder will be hidden from Explorer again."
            : "The folder becomes visible in Explorer but stays locked: it can't be opened until you unlock it."}
        </p>
      }
      confirmLabel={hidden ? "Hide" : "Unhide"}
      run={(c) => api.quickSetHidden(vault.id, hidden, c)}
      success={hidden ? "Folder hidden" : "Folder is visible (still locked)"}
    />
  );
}
