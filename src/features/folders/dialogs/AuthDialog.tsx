import { useState } from "react";
import { errMsg, type Credential, type OperationInfo, type VaultInfo } from "@/api";
import { useStore } from "@/app/store";
import { CredentialFields, credReady, defaultKind } from "@/components/CredentialFields";
import { OperationProgress } from "@/components/OperationProgress";
import { FluentButton, FluentDialog, InfoBar, useNotify } from "@/components/fluent";
import { formatCount } from "@/lib/format";

/** Generic "authenticate then do X" dialog. */
export function AuthDialog({
  title,
  vault,
  intro,
  confirmLabel,
  danger,
  extra,
  canSubmit = true,
  run,
  success,
}: {
  title: string;
  vault: VaultInfo;
  intro?: React.ReactNode;
  confirmLabel: string;
  danger?: boolean;
  extra?: React.ReactNode;
  canSubmit?: boolean;
  run: (c: Credential) => Promise<string | void>;
  success?: string;
}) {
  const { closeDialog, refresh } = useStore();
  const notify = useNotify();
  const [cred, setCred] = useState<Credential>({ kind: defaultKind(vault.keyMode), secret: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opId, setOpId] = useState<string | null>(null);
  const [done, setDone] = useState<OperationInfo | undefined | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await run(cred);
      await refresh();
      if (typeof r === "string" && r.length === 32) setOpId(r);
      else {
        if (success) notify({ severity: "success", title: success });
        closeDialog();
      }
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  if (opId)
    return (
      <FluentDialog open title={title} onClose={closeDialog} footer={<FluentButton onClick={closeDialog}>{done ? "Close" : "Run in background"}</FluentButton>}>
        {done === null ? (
          <OperationProgress opId={opId} onFinished={(o) => setDone(o)} />
        ) : done?.status === "completed" ? (
          <InfoBar severity="success" title={success ?? "Done."}>
            {done.opType === "cleanup" && done.params ? cleanupSummary(done.params) : null}
          </InfoBar>
        ) : (
          <InfoBar severity="error" title="The operation didn't finish.">
            {done?.error}
          </InfoBar>
        )}
      </FluentDialog>
    );

  return (
    <FluentDialog
      open
      title={title}
      onClose={busy ? undefined : closeDialog}
      dismissable={!busy}
      footer={
        <>
          <FluentButton variant={danger ? "danger" : "accent"} disabled={!credReady(cred) || !canSubmit || busy} onClick={submit}>
            {busy ? "Working…" : confirmLabel}
          </FluentButton>
          <FluentButton disabled={busy} onClick={closeDialog}>
            Cancel
          </FluentButton>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {intro}
        {extra}
        <CredentialFields keyMode={vault.keyMode} value={cred} onChange={setCred} autoFocus={!extra} />
        {error && <InfoBar severity="error">{error}</InfoBar>}
      </div>
    </FluentDialog>
  );
}

function cleanupSummary(params: string) {
  try {
    const r = JSON.parse(params) as { removedFiles: number; keptFiles: number; rootRemoved: boolean };
    return `${formatCount(r.removedFiles)} original file(s) removed.${r.keptFiles ? ` ${formatCount(r.keptFiles)} file(s) were changed or added after encryption and were kept.` : ""}${
      r.rootRemoved ? "" : " Some items remain in the original folder."
    }`;
  } catch {
    return null;
  }
}
