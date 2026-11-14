import { useState } from "react";
import { api, errMsg } from "@/api";
import { masterStrongEnough, StrengthMeter, usePasswordStrength } from "@/components/PasswordStrength";
import { FluentButton, FluentDialog, FluentPasswordInput, InfoBar, useNotify } from "@/components/fluent";

export function ChangeMasterDialog({ onClose }: { onClose: () => void }) {
  const notify = useNotify();
  const [cur, setCur] = useState("");
  const [np, setNp] = useState("");
  const [np2, setNp2] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const npStrength = usePasswordStrength(np);
  const ok = cur && np.length >= 8 && np === np2 && masterStrongEnough(npStrength);
  return (
    <FluentDialog
      open
      title="Change master password"
      onClose={busy ? undefined : onClose}
      footer={
        <>
          <FluentButton
            variant="accent"
            disabled={!ok || busy}
            onClick={async () => {
              setBusy(true);
              setErr(null);
              try {
                await api.changeMasterPassword(cur, np);
                notify({ severity: "success", title: "Master password changed" });
                onClose();
              } catch (e) {
                setErr(errMsg(e));
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? "Changing…" : "Change password"}
          </FluentButton>
          <FluentButton disabled={busy} onClick={onClose}>
            Cancel
          </FluentButton>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <FluentPasswordInput label="Current master password" value={cur} onChange={(e) => setCur(e.target.value)} />
        <FluentPasswordInput label="New master password" value={np} onChange={(e) => setNp(e.target.value)} />
        <StrengthMeter pw={np} strength={npStrength} master />
        <FluentPasswordInput label="Confirm new master password" value={np2} onChange={(e) => setNp2(e.target.value)} error={np2 && np !== np2 ? "Passwords don't match" : undefined} />
        <p className="t-caption text-[var(--text-2)]">Your recovery key stays the same. Folders with their own password aren't affected. If vaults open on another PC with the master password, they're updated to the new password.</p>
        {err && <InfoBar severity="error">{err}</InfoBar>}
      </div>
    </FluentDialog>
  );
}
