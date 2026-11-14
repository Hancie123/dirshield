import { useState } from "react";
import { ArrowImportRegular, FolderOpenRegular, KeyRegular, LockClosedRegular, WarningRegular, ChevronRightRegular } from "@fluentui/react-icons";
import { api, errMsg } from "@/api";
import { useStore } from "@/app/store";
import { Badge, FluentButton, FluentDialog, FluentPasswordInput, FluentRadio, InfoBar, SectionHeader, SettingsRow, useNotify } from "@/components/fluent";
import { OrphanRecovery } from "@/features/recovery/OrphanRecovery";
import { pickFolder } from "@/lib/pickers";

export function RecoveryPage() {
  const { vaults, ops, openDialog, setPage, refresh } = useStore();
  const notify = useNotify();
  const [importOpen, setImportOpen] = useState(false);
  const [importPath, setImportPath] = useState("");
  const [rk, setRk] = useState("");
  const [importKind, setImportKind] = useState<"recovery" | "master" | "folder">("recovery");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [pick, setPick] = useState(false);
  const attention = ops.filter((o) => !o.live && o.status !== "completed");
  const recoverable = vaults.filter((v) => v.mode === "quick" || ["encrypted", "locked", "restored"].includes(v.status));

  return (
    <div className="flex flex-col gap-1">
      <InfoBar severity="info">
        Your recovery key can unlock any folder protected on this PC, reset your master password, and re-open vaults if the DirShield database is lost. If both the master password and the recovery key are lost, encrypted data cannot be recovered.
      </InfoBar>
      <SectionHeader>Recover</SectionHeader>
      <SettingsRow icon={<WarningRegular />} title="Interrupted operations" description={attention.length ? `${attention.length} operation(s) can be resumed or discarded safely.` : "Nothing needs recovery."} onClick={() => setPage("operations")}>
        {attention.length > 0 && <Badge tone="critical">{attention.length}</Badge>}
        <ChevronRightRegular />
      </SettingsRow>
      <SettingsRow icon={<KeyRegular />} title="Unlock a folder with the recovery key" description="Use this if you've forgotten a folder password.">
        <FluentButton disabled={!recoverable.length} onClick={() => setPick(true)}>
          Choose folder
        </FluentButton>
      </SettingsRow>
      <SettingsRow icon={<ArrowImportRegular />} title="Import an existing vault" description="Re-register a Secure Lock vault folder: after reinstalling Windows, losing DirShield's data, or to open it on this PC.">
        <FluentButton onClick={() => setImportOpen(true)}>Import…</FluentButton>
      </SettingsRow>
      <OrphanRecovery />
      <SettingsRow icon={<LockClosedRegular />} title="Forgot your master password?" description="Sign out, then choose “Forgot your password?” on the sign-in screen and enter your recovery key." />

      {pick && (
        <FluentDialog open title="Choose a folder" onClose={() => setPick(false)} footer={<FluentButton onClick={() => setPick(false)}>Cancel</FluentButton>}>
          <div className="flex flex-col gap-1 max-h-[360px] overflow-y-auto">
            {recoverable.map((v) => (
              <button
                key={v.id}
                className="flex items-center gap-3 px-3 h-12 rounded-[4px] hover:bg-[var(--fill-subtle-hover)] text-left"
                onClick={() => {
                  setPick(false);
                  openDialog({ kind: "unlock", vault: v, recovery: true });
                }}
              >
                <span className="flex-1 truncate">{v.name}</span>
                <span className="t-caption text-[var(--text-2)]">{v.mode === "quick" ? "Quick Lock" : "Secure Lock"}</span>
              </button>
            ))}
          </div>
        </FluentDialog>
      )}

      {importOpen && (
        <FluentDialog
          open
          title="Import a vault"
          onClose={busy ? undefined : () => setImportOpen(false)}
          footer={
            <>
              <FluentButton
                variant="accent"
                disabled={!importPath || !rk || busy}
                onClick={async () => {
                  setBusy(true);
                  setErr(null);
                  try {
                    const v = await api.importVault(importPath, { kind: importKind, secret: rk });
                    notify({
                      severity: "success",
                      title: "Vault imported",
                      message: importKind === "folder" ? `“${v.name}” keeps its folder password.` : `“${v.name}” now unlocks with your current master password.`,
                    });
                    setImportOpen(false);
                    setRk("");
                    refresh();
                  } catch (e) {
                    setErr(errMsg(e));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {busy ? "Importing…" : "Import"}
              </FluentButton>
              <FluentButton disabled={busy} onClick={() => setImportOpen(false)}>
                Cancel
              </FluentButton>
            </>
          }
        >
          <div className="flex flex-col gap-4">
            <p className="text-[var(--text-2)]">Select the vault folder — the one containing “vault.dsv” — and how to open it.</p>
            <div className="flex items-center gap-3">
              <div className="flex-1 min-w-0 truncate selectable">{importPath || <span className="text-[var(--text-3)]">No folder selected</span>}</div>
              <FluentButton
                icon={<FolderOpenRegular />}
                onClick={async () => {
                  const p = await pickFolder("Select the vault folder");
                  if (p) setImportPath(p);
                }}
              >
                Browse…
              </FluentButton>
            </div>
            <FluentRadio
              name="Open it with"
              value={importKind}
              onChange={(k) => (setImportKind(k), setRk(""))}
              options={[
                { value: "recovery", label: "The recovery key it was protected with" },
                { value: "master", label: "The master password it was made with", description: "Works for vaults from another PC when “Open vaults on another PC with the master password” was on there." },
                { value: "folder", label: "Its own folder password" },
              ]}
            />
            <FluentPasswordInput
              label={importKind === "recovery" ? "Recovery key" : importKind === "master" ? "Master password" : "Folder password"}
              value={rk}
              onChange={(e) => setRk(e.target.value)}
              placeholder={importKind === "recovery" ? "XXXX-XXXX-XXXX-…" : undefined}
            />
            {err && <InfoBar severity="error">{err}</InfoBar>}
          </div>
        </FluentDialog>
      )}
    </div>
  );
}
