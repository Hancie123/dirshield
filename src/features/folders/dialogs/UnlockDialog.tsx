import { useState } from "react";
import { api, errCode, errMsg, type ConflictPolicy, type Credential, type OperationInfo, type VaultInfo } from "@/api";
import { useStore } from "@/app/store";
import { CredentialFields, credReady, defaultKind } from "@/components/CredentialFields";
import { KeyValue } from "@/components/KeyValue";
import { OperationProgress } from "@/components/OperationProgress";
import { FluentButton, FluentCheckbox, FluentDialog, FluentRadio, InfoBar, useNotify } from "@/components/fluent";
import { formatBytes, formatCount } from "@/lib/format";
import { pickFolder } from "@/lib/pickers";

type Step = "auth" | "working" | "progress" | "done" | "failed";

export function UnlockDialog({ vault, recovery }: { vault: VaultInfo; recovery?: boolean }) {
  const { closeDialog, refresh, openDialog } = useStore();
  const notify = useNotify();
  const [cred, setCred] = useState<Credential>({ kind: recovery ? "recovery" : defaultKind(vault.keyMode), secret: "" });
  const [dest, setDest] = useState<string>("");
  const [conflict, setConflict] = useState<ConflictPolicy>("fail");
  const [showConflict, setShowConflict] = useState(false);
  const [work, setWork] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState<Step>("auth");
  const [opId, setOpId] = useState<string | null>(null);
  const [finalOp, setFinalOp] = useState<OperationInfo | undefined>();
  const quick = vault.mode === "quick";
  const target = dest || vault.originalPath;

  const submit = async () => {
    setError(null);
    setStep("working");
    try {
      if (quick) {
        const p = await api.quickUnlock(vault.id, cred, dest || null);
        notify({ severity: "success", title: "Folder unlocked", message: p, action: { label: "Open folder", onClick: () => api.openInExplorer(p) } });
        await refresh();
        closeDialog();
      } else {
        const id = await api.restoreVault(vault.id, cred, dest || null, conflict, work);
        setOpId(id);
        setStep("progress");
      }
    } catch (e) {
      if (errCode(e) === "conflict") setShowConflict(true);
      setError(errMsg(e));
      setStep("auth");
    }
  };

  const busy = step === "working";
  const footer =
    step === "progress" ? (
      <FluentButton onClick={closeDialog}>Run in background</FluentButton>
    ) : step === "done" ? (
      <>
        <FluentButton variant="accent" onClick={() => api.openInExplorer(target).catch(() => {})}>
          Open folder
        </FluentButton>
        {!work && <FluentButton onClick={() => openDialog({ kind: "delete", vault })}>Delete encrypted copy…</FluentButton>}
        <FluentButton onClick={closeDialog}>Close</FluentButton>
      </>
    ) : step === "failed" ? (
      <FluentButton onClick={closeDialog}>Close</FluentButton>
    ) : (
      <>
        <FluentButton variant="accent" disabled={!credReady(cred) || busy} onClick={submit}>
          {busy ? "Working…" : quick ? "Unlock" : "Restore folder"}
        </FluentButton>
        <FluentButton disabled={busy} onClick={closeDialog}>
          Cancel
        </FluentButton>
      </>
    );

  return (
    <FluentDialog open title={step === "progress" ? "Restoring folder" : step === "done" ? "Folder restored" : `Unlock “${vault.name}”`} onClose={busy ? undefined : closeDialog} dismissable={!busy} footer={footer}>
      {(step === "auth" || step === "working") && (
        <div className="flex flex-col gap-4">
          <KeyValue
            rows={[
              ["Protection", quick ? "Quick Lock" : "Secure Lock (AES-256-GCM)"],
              ["Size", `${formatBytes(vault.sizeBytes)} · ${formatCount(vault.fileCount)} files`],
              [quick ? "Restore to" : "Destination", target],
            ]}
          />
          {(!quick || vault.moved) && (
            <div>
              <FluentButton
                onClick={async () => {
                  const p = await pickFolder("Choose a location to restore to");
                  if (p) setDest(`${p.replace(/\\$/, "")}\\${vault.name}`);
                }}
              >
                Restore to a different location…
              </FluentButton>
            </div>
          )}
          {!quick && (
            <p className="t-caption text-[var(--text-2)]">
              DirShield checks the vault's integrity, decrypts every file, verifies it against its recorded checksum and only then puts it in place. Existing files are never overwritten.
            </p>
          )}
          {!quick && showConflict && (
            <FluentRadio
              name="If a file already exists"
              value={conflict}
              onChange={setConflict}
              options={[
                { value: "fail", label: "Stop (choose another location)" },
                // A work session locks everything in the folder when it ends,
                // so it can't restore into a folder that already has files.
                ...(work ? [] : [{ value: "skip" as const, label: "Keep the existing file and skip the vault copy" }]),
                { value: "rename", label: "Keep both — restored copy is renamed “(restored)”" },
              ]}
            />
          )}
          {!quick && (
            <FluentCheckbox
              checked={work}
              onChange={(w) => {
                setWork(w);
                if (w && conflict === "skip") setConflict("fail");
              }}
            >
              <span>
                Work session — lock it again automatically when I sign out of DirShield or Windows locks or sleeps
                <span className="block t-caption text-[var(--text-2)]">
                  Changes are encrypted into the vault, then the unlocked copy is removed. Files that couldn't be saved to the vault are kept. Needs a new or empty destination folder, since everything in it is locked when the session ends.
                </span>
              </span>
            </FluentCheckbox>
          )}
          <CredentialFields keyMode={vault.keyMode} value={cred} onChange={setCred} />
          {error && <InfoBar severity="error">{error}</InfoBar>}
        </div>
      )}
      {step === "progress" && opId && (
        <OperationProgress
          opId={opId}
          onFinished={(op) => {
            setFinalOp(op);
            setStep(op?.status === "completed" ? "done" : "failed");
          }}
        />
      )}
      {step === "done" && (
        <div className="flex flex-col gap-3">
          <InfoBar severity="success" title="Restored and verified.">
            Every file matched its checksum.
          </InfoBar>
          <p>
            The folder is back at <span className="selectable font-semibold">{target}</span>.{" "}
            {work ? "It will be locked again when you sign out of DirShield or Windows locks or sleeps, or when you choose End work session." : "The encrypted copy is kept until you delete it."}
          </p>
        </div>
      )}
      {step === "failed" && (
        <InfoBar severity="error" title="Restore didn't finish.">
          {finalOp?.error ?? "The operation stopped."} The vault is unchanged; you can resume from Active operations.
        </InfoBar>
      )}
    </FluentDialog>
  );
}
