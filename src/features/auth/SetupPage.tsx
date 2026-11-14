import { useState } from "react";
import { KeyRegular, ShieldLockRegular } from "@fluentui/react-icons";
import logo from "../../../src-tauri/icons/128x128.png";
import { api, errMsg } from "@/api";
import { useStore } from "@/app/store";
import { masterStrongEnough, StrengthMeter, usePasswordStrength } from "@/components/PasswordStrength";
import { FluentButton, FluentPasswordInput, InfoBar } from "@/components/fluent";
import { Shell } from "@/features/auth/AuthShell";
import { RecoveryKeyBox } from "@/features/recovery/components/RecoveryKeyBox";
import { RecoveryKeyCheck } from "@/features/recovery/components/RecoveryKeyCheck";
import { RestoreBackupForm } from "@/features/recovery/components/RestoreBackupForm";

export function SetupPage() {
  const { refreshInfo } = useStore();
  const [step, setStep] = useState<"welcome" | "password" | "recovery" | "check" | "restore">("welcome");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recovery, setRecovery] = useState("");
  const [checked, setChecked] = useState(false);
  const strength = usePasswordStrength(pw);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      const rk = await api.setupMaster(pw, pw2);
      setRecovery(rk);
      setPw("");
      setPw2("");
      setStep("recovery");
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  if (step === "welcome")
    return (
      <Shell width={520}>
        <img src={logo} alt="" className="w-16 h-16 mb-4" />
        <h1 className="t-title font-display">Welcome to DirShield</h1>
        <p className="mt-3 text-[var(--text-2)]">Protect folders on this PC. Everything stays on this device — no account, no cloud.</p>
        <div className="mt-6 flex flex-col gap-4">
          <div className="flex gap-3">
            <KeyRegular fontSize={22} className="text-[var(--accent)] shrink-0" />
            <div>
              <div className="t-body-strong">Quick Lock</div>
              <div className="text-[var(--text-2)] text-[13px]">Instantly hides a folder and blocks access with Windows permissions. Convenient privacy — not encryption.</div>
            </div>
          </div>
          <div className="flex gap-3">
            <ShieldLockRegular fontSize={22} className="text-[var(--accent)] shrink-0" />
            <div>
              <div className="t-body-strong">Secure Lock</div>
              <div className="text-[var(--text-2)] text-[13px]">Encrypts contents, file names and structure with AES-256-GCM. Works for folders of hundreds of gigabytes.</div>
            </div>
          </div>
        </div>
        <div className="mt-8 flex items-center justify-between gap-3">
          <button type="button" className="text-[13px] text-[var(--accent-text)] hover:underline" onClick={() => setStep("restore")}>
            Restore from a backup
          </button>
          <FluentButton variant="accent" onClick={() => setStep("password")}>
            Get started
          </FluentButton>
        </div>
      </Shell>
    );

  if (step === "restore")
    return (
      <Shell width={560}>
        <h1 className="t-subtitle font-display mb-4">Restore from a backup</h1>
        <RestoreBackupForm signedIn={false} onCancel={() => setStep("welcome")} onDone={() => refreshInfo()} />
      </Shell>
    );

  if (step === "password") {
    const mismatch = pw2.length > 0 && pw !== pw2;
    const ok = pw.length >= 8 && pw === pw2 && masterStrongEnough(strength);
    return (
      <Shell>
        <h1 className="t-subtitle font-display">Create your master password</h1>
        <p className="mt-2 text-[var(--text-2)]">It unlocks DirShield and every folder that uses it. DirShield never stores it — choose something long you'll remember.</p>
        <div className="mt-5 flex flex-col gap-3">
          <FluentPasswordInput label="Master password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus />
          <StrengthMeter pw={pw} strength={strength} master />
          <FluentPasswordInput label="Confirm master password" value={pw2} onChange={(e) => setPw2(e.target.value)} error={mismatch ? "Passwords don't match" : undefined} onKeyDown={(e) => e.key === "Enter" && ok && create()} />
          {error && <InfoBar severity="error">{error}</InfoBar>}
        </div>
        <div className="mt-6 flex justify-end gap-2">
          <FluentButton onClick={() => setStep("welcome")} disabled={busy}>
            Back
          </FluentButton>
          <FluentButton variant="accent" disabled={!ok || busy} onClick={create}>
            {busy ? "Creating keys…" : "Next"}
          </FluentButton>
        </div>
      </Shell>
    );
  }

  return (
    <Shell width={560}>
      <h1 className="t-subtitle font-display">Save your recovery key</h1>
      <p className="mt-2 text-[var(--text-2)]">
        If you forget your master password, this key is the only way to get back in and unlock your folders. Store it somewhere safe and separate from this PC — print it, or keep it in a password manager.
      </p>
      {step === "recovery" ? (
        <>
          <div className="mt-5">
            <RecoveryKeyBox value={recovery} />
          </div>
          <div className="mt-4">
            <InfoBar severity="warning">If you lose both your master password and this recovery key, encrypted data can't be recovered — by you, or by anyone.</InfoBar>
          </div>
          <div className="mt-6 flex justify-end">
            <FluentButton variant="accent" onClick={() => setStep("check")}>
              I've saved it
            </FluentButton>
          </div>
        </>
      ) : (
        <>
          <div className="mt-5">
            <RecoveryKeyCheck value={recovery} onChange={setChecked} />
          </div>
          <div className="mt-6 flex justify-end gap-2">
            <FluentButton onClick={() => setStep("recovery")}>Show the key again</FluentButton>
            <FluentButton
              variant="accent"
              disabled={!checked}
              onClick={async () => {
                setRecovery("");
                await navigator.clipboard.writeText("").catch(() => {});
                await refreshInfo();
              }}
            >
              Finish
            </FluentButton>
          </div>
        </>
      )}
    </Shell>
  );
}
