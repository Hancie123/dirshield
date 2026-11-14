import { useState } from "react";
import { api, errCode, errMsg } from "@/api";
import { FluentButton, FluentDialog, FluentPasswordInput, InfoBar } from "@/components/fluent";

/** Turns on Windows Hello unlock. Needs the master password once. */
export function HelloDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api.helloEnable(pw);
      onDone();
    } catch (e) {
      if (errCode(e) !== "cancelled") setErr(errMsg(e));
    } finally {
      setBusy(false);
      setPw("");
    }
  };
  return (
    <FluentDialog
      open
      title="Turn on Windows Hello?"
      width={520}
      onClose={busy ? undefined : onClose}
      footer={
        <>
          <FluentButton variant="accent" disabled={!pw || busy} onClick={submit}>
            {busy ? "Waiting for Windows Hello…" : "Turn on"}
          </FluentButton>
          <FluentButton disabled={busy} onClick={onClose}>
            Cancel
          </FluentButton>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <p>
          Sign in to DirShield and unlock folders that use your master password with your fingerprint, face or PIN. It works only on this PC and for this Windows account. Your master password and recovery key keep working, and folders with their own password still need that password.
        </p>
        <FluentPasswordInput label="Master password" value={pw} autoFocus onChange={(e) => setPw(e.target.value)} onKeyDown={(e) => e.key === "Enter" && pw && !busy && submit()} />
        {err && <InfoBar severity="error">{err}</InfoBar>}
      </div>
    </FluentDialog>
  );
}
