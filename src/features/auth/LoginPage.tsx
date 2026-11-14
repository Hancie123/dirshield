import { useEffect, useState } from "react";
import { FingerprintRegular } from "@fluentui/react-icons";
import logo from "../../../src-tauri/icons/128x128.png";
import { api, errCode, errMsg } from "@/api";
import { useStore } from "@/app/store";
import { masterStrongEnough, StrengthMeter, usePasswordStrength } from "@/components/PasswordStrength";
import { FluentButton, FluentPasswordInput, InfoBar } from "@/components/fluent";
import { Shell } from "@/features/auth/AuthShell";

export function LoginPage() {
  const { info, refreshInfo, setUnlocked } = useStore();
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lockout, setLockout] = useState(info?.lockoutMs ?? 0);
  const [forgot, setForgot] = useState(false);
  const [rk, setRk] = useState("");
  const [np, setNp] = useState("");
  const [np2, setNp2] = useState("");
  const npStrength = usePasswordStrength(np);

  useEffect(() => {
    if (lockout <= 0) return;
    const t = setInterval(() => setLockout((l) => Math.max(0, l - 1000)), 1000);
    return () => clearInterval(t);
  }, [lockout > 0]); // eslint-disable-line react-hooks/exhaustive-deps

  const handle = async (f: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await f();
      setUnlocked(true);
      await refreshInfo();
    } catch (e) {
      // Closing the Windows Hello prompt isn't an error.
      if (errCode(e) !== "cancelled") setError(errMsg(e));
      if (errCode(e) === "rate_limited" || errCode(e) === "auth_failed") {
        const i = await api.appInfo();
        setLockout(i.lockoutMs);
      }
    } finally {
      setBusy(false);
      setPw("");
    }
  };

  const locked = lockout > 0;
  const hello = !!info?.hello && !!info?.helloAvailable;

  if (forgot)
    return (
      <Shell>
        <h1 className="t-subtitle font-display">Reset master password</h1>
        <p className="mt-2 text-[var(--text-2)]">Enter the recovery key you saved during setup, then choose a new master password. Your folders stay exactly as they are.</p>
        <div className="mt-5 flex flex-col gap-3">
          <FluentPasswordInput label="Recovery key" value={rk} onChange={(e) => setRk(e.target.value)} placeholder="XXXX-XXXX-XXXX-…" autoFocus />
          <FluentPasswordInput label="New master password" value={np} onChange={(e) => setNp(e.target.value)} />
          <StrengthMeter pw={np} strength={npStrength} master />
          <FluentPasswordInput label="Confirm new master password" value={np2} onChange={(e) => setNp2(e.target.value)} error={np2 && np !== np2 ? "Passwords don't match" : undefined} />
          {error && <InfoBar severity="error">{error}</InfoBar>}
        </div>
        <div className="mt-6 flex justify-end gap-2">
          <FluentButton onClick={() => setForgot(false)} disabled={busy}>
            Back
          </FluentButton>
          <FluentButton variant="accent" disabled={busy || locked || !rk || np.length < 8 || np !== np2 || !masterStrongEnough(npStrength)} onClick={() => handle(() => api.resetMasterPassword(rk, np))}>
            {busy ? "Working…" : "Reset password"}
          </FluentButton>
        </div>
      </Shell>
    );

  return (
    <Shell width={400}>
      <div className="flex flex-col items-center text-center">
        <img src={logo} alt="" className="w-16 h-16" />
        <h1 className="t-subtitle font-display mt-4">DirShield is locked</h1>
        <p className="mt-1 text-[var(--text-2)]">{hello ? "Use Windows Hello or enter your master password to continue." : "Enter your master password to continue."}</p>
      </div>
      <form
        className="mt-6 flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (pw && !locked) handle(() => api.login(pw));
        }}
      >
        <FluentPasswordInput aria-label="Master password" placeholder="Master password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus disabled={busy} />
        {locked ? <InfoBar severity="warning">Too many attempts. Try again in {Math.ceil(lockout / 1000)} s.</InfoBar> : error ? <InfoBar severity="error">{error}</InfoBar> : null}
        <FluentButton type="submit" variant="accent" disabled={!pw || busy || locked}>
          {busy ? "Signing in…" : "Sign in"}
        </FluentButton>
        {hello && (
          <FluentButton type="button" disabled={busy} onClick={() => handle(() => api.loginHello())}>
            <FingerprintRegular fontSize={18} /> Sign in with Windows Hello
          </FluentButton>
        )}
        <button type="button" className="text-[13px] text-[var(--accent-text)] hover:underline mt-1" onClick={() => setForgot(true)}>
          Forgot your password? Use your recovery key
        </button>
      </form>
    </Shell>
  );
}
