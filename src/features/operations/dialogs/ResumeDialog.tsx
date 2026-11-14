import { api, type OperationInfo } from "@/api";
import { useStore } from "@/app/store";
import { InfoBar } from "@/components/fluent";
import { AuthDialog } from "@/features/folders/dialogs/AuthDialog";

export function ResumeDialog({ op, mode }: { op: OperationInfo; mode: "resume" | "retry" | "skip" }) {
  const { vaults } = useStore();
  const vault = vaults.find((v) => v.id === op.vaultId);
  if (!vault) return null;
  const titles = { resume: "Resume operation", retry: "Retry failed items", skip: "Exclude failed items and continue" };
  return (
    <AuthDialog
      title={titles[mode]}
      vault={vault}
      intro={
        mode === "skip" ? (
          <InfoBar severity="warning" title="Failed items will be left out of the vault.">
            They stay unencrypted in the original folder and are never removed by DirShield.
          </InfoBar>
        ) : (
          <p>Work continues from where it stopped. Items already finished and verified aren't processed again.</p>
        )
      }
      confirmLabel={mode === "resume" ? "Resume" : mode === "retry" ? "Retry" : "Exclude and continue"}
      run={async (c) => {
        await api.opResume(op.id, c, mode);
        return op.id;
      }}
      success="Operation completed"
    />
  );
}
