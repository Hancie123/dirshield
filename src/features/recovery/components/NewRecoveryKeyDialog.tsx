import { useState } from "react";
import { api, errMsg } from "@/api";
import { FluentButton, FluentDialog, FluentPasswordInput, InfoBar, useNotify } from "@/components/fluent";
import { RecoveryKeyBox } from "@/features/recovery/components/RecoveryKeyBox";
import { RecoveryKeyCheck } from "@/features/recovery/components/RecoveryKeyCheck";
import { syncSummary } from "@/features/recovery/syncSummary";

export function NewRecoveryKeyDialog({ onClose }: { onClose: () => void }) {
  const notify = useNotify();
  const [step, setStep] = useState<"auth" | "show" | "check">("auth");
  const [pw, setPw] = useState("");
  const [key, setKey] = useState("");
  const [ok, setOk] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const cancel = () => {
    api.recoveryRotateCancel().catch(() => {});
    onClose();
  };
  const run = async (f: () => Promise<void>) => {
    setBusy(true);
    setErr(null);
    try {
      await f();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const begin = () =>
    run(async () => {
      setKey(await api.recoveryRotateBegin(pw));
      setPw("");
      setStep("show");
    });

  const footer =
    step === "auth" ? (
      <>
        <FluentButton variant="accent" disabled={!pw || busy} onClick={begin}>
          {busy ? "Checking…" : "Continue"}
        </FluentButton>
        <FluentButton disabled={busy} onClick={cancel}>
          Cancel
        </FluentButton>
      </>
    ) : step === "show" ? (
      <>
        <FluentButton variant="accent" onClick={() => setStep("check")}>
          I've saved it
        </FluentButton>
        <FluentButton onClick={cancel}>Cancel</FluentButton>
      </>
    ) : (
      <>
        <FluentButton
          variant="accent"
          disabled={!ok || busy}
          onClick={() =>
            run(async () => {
              const r = await api.recoveryRotateCommit(key);
              await navigator.clipboard.writeText("").catch(() => {});
              notify({ severity: "success", title: "New recovery key in use", message: syncSummary(r) });
              onClose();
            })
          }
        >
          {busy ? "Updating vaults…" : "Use the new key"}
        </FluentButton>
        <FluentButton disabled={busy} onClick={() => setStep("show")}>
          Back
        </FluentButton>
      </>
    );

  return (
    <FluentDialog open title="Create a new recovery key" width={580} onClose={busy ? undefined : cancel} footer={footer}>
      <div className="flex flex-col gap-4">
        {step === "auth" && (
          <>
            <p className="text-[var(--text-2)]">
              Do this if your recovery key is lost or someone else may have seen it. Once the new key is in use, the old one no longer opens DirShield, and every vault that uses your master password is updated to the new key.
            </p>
            <InfoBar severity="warning">
              Folders with their own password keep the old key until you change their password. Older backups and copies of vault folders made before today still open with the old key.
            </InfoBar>
            <FluentPasswordInput label="Master password" value={pw} autoFocus onChange={(e) => setPw(e.target.value)} onKeyDown={(e) => e.key === "Enter" && pw && !busy && begin()} />
          </>
        )}
        {step === "show" && (
          <>
            <p className="text-[var(--text-2)]">Save this key somewhere safe and separate from this PC. It isn't in use yet: nothing changes until you confirm it on the next step.</p>
            <RecoveryKeyBox value={key} />
          </>
        )}
        {step === "check" && <RecoveryKeyCheck value={key} onChange={setOk} />}
        {err && <InfoBar severity="error">{err}</InfoBar>}
      </div>
    </FluentDialog>
  );
}
