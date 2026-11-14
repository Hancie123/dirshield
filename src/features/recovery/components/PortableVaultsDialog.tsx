import { useState } from "react";
import { api, errMsg } from "@/api";
import { FluentButton, FluentDialog, FluentPasswordInput, InfoBar, useNotify } from "@/components/fluent";
import { syncSummary } from "@/features/recovery/syncSummary";

export function PortableVaultsDialog({ enable, onClose, onDone }: { enable: boolean; onClose: () => void; onDone: () => void }) {
  const notify = useNotify();
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await api.setPortableVaults(enable, pw);
      notify({ severity: "success", title: enable ? "Vaults open on another PC with your master password" : "Turned off", message: syncSummary(r) });
      onDone();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
      setPw("");
    }
  };
  return (
    <FluentDialog
      open
      title={enable ? "Open vaults on another PC with your master password?" : "Turn off opening vaults with the master password?"}
      width={580}
      onClose={busy ? undefined : onClose}
      footer={
        <>
          <FluentButton variant="accent" disabled={!pw || busy} onClick={submit}>
            {busy ? "Updating vaults…" : enable ? "Turn on" : "Turn off"}
          </FluentButton>
          <FluentButton disabled={busy} onClick={onClose}>
            Cancel
          </FluentButton>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {enable ? (
          <>
            <p>
              Each vault that uses your master password gets a copy of your master key, locked with that password. On another PC, import the vault folder from <b>Recovery → Import an existing vault</b> and enter this master password — no recovery key or database needed.
            </p>
            <InfoBar severity="warning">
              Anyone who gets a copy of a vault folder can then try to guess your master password against it, as they could with a folder password. Your master password must be strong. Vaults made with older DirShield versions can't be opened by those versions once this is on.
            </InfoBar>
          </>
        ) : (
          <p>The copies are removed from every vault DirShield can reach now. Vault folders copied elsewhere before this keep them.</p>
        )}
        <FluentPasswordInput label="Master password" value={pw} autoFocus onChange={(e) => setPw(e.target.value)} onKeyDown={(e) => e.key === "Enter" && pw && !busy && submit()} />
        {err && <InfoBar severity="error">{err}</InfoBar>}
      </div>
    </FluentDialog>
  );
}
