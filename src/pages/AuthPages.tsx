import { useEffect, useState } from "react";
import { CopyRegular, KeyRegular, ShieldLockRegular } from "@fluentui/react-icons";
import { api, errCode, errMsg } from "../lib/api";
import { FluentButton, FluentCard, FluentCheckbox, FluentPasswordInput, InfoBar } from "../components/fluent";
import { passwordStrength } from "../lib/format";
import { useStore } from "../lib/store";
import logo from "../../src-tauri/icons/128x128.png";

function Shell({ children, width = 460 }: { children: React.ReactNode; width?: number }) {
  return (
    <div className="h-full overflow-y-auto flex items-center justify-center p-6">
      <FluentCard className="anim-page p-8 bg-[var(--dialog-bg)]!" style={{ width, maxWidth: "100%" }}>
        {children}
      </FluentCard>
    </div>
  );
}

function StrengthMeter({ pw }: { pw: string }) {
  const s = passwordStrength(pw);
  const color = ["var(--critical)", "var(--critical)", "var(--caution)", "var(--success)", "var(--success)"][s.score];
  return (
    <div className="flex items-center gap-2">
      <div className="flex gap-1 flex-1">
        {[0, 1, 2, 3].map((i) => (
          <span key={i} className="h-1 flex-1 rounded-full" style={{ background: i < s.score ? color : "var(--stroke-divider)" }} />
        ))}
      </div>
      <span className="t-caption text-[var(--text-2)] w-16 text-right">{pw ? s.label : ""}</span>
    </div>
  );
}

export function SetupPage() {
  const { refreshInfo } = useStore();
  const [step, setStep] = useState<"welcome" | "password" | "recovery">("welcome");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recovery, setRecovery] = useState("");
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);

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
        <div className="mt-8 flex justify-end">
          <FluentButton variant="accent" onClick={() => setStep("password")}>
            Get started
          </FluentButton>
        </div>
      </Shell>
    );

  if (step === "password") {
    const mismatch = pw2.length > 0 && pw !== pw2;
    const ok = pw.length >= 8 && pw === pw2;
    return (
      <Shell>
        <h1 className="t-subtitle font-display">Create your master password</h1>
        <p className="mt-2 text-[var(--text-2)]">It unlocks DirShield and every folder that uses it. DirShield never stores it — choose something long you'll remember.</p>
        <div className="mt-5 flex flex-col gap-3">
          <FluentPasswordInput label="Master password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus />
          <StrengthMeter pw={pw} />
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
      <div className="mt-5 rounded-[6px] border border-[var(--stroke-card)] bg-[var(--fill-control)] p-4 font-mono text-[15px] tracking-wide text-center selectable break-all">{recovery}</div>
      <div className="mt-2 flex justify-end">
        <FluentButton
          icon={<CopyRegular />}
          onClick={async () => {
            await navigator.clipboard.writeText(recovery);
            setCopied(true);
          }}
        >
          {copied ? "Copied" : "Copy"}
        </FluentButton>
      </div>
      <div className="mt-4">
        <InfoBar severity="warning">If you lose both your master password and this recovery key, encrypted data can't be recovered — by you, or by anyone.</InfoBar>
      </div>
      <div className="mt-4">
        <FluentCheckbox checked={saved} onChange={setSaved}>
          I've saved my recovery key in a safe place
        </FluentCheckbox>
      </div>
      <div className="mt-6 flex justify-end">
        <FluentButton
          variant="accent"
          disabled={!saved}
          onClick={async () => {
            setRecovery("");
            await navigator.clipboard.writeText("").catch(() => {});
            await refreshInfo();
          }}
        >
          Finish
        </FluentButton>
      </div>
    </Shell>
  );
}

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
      setError(errMsg(e));
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

  if (forgot)
    return (
      <Shell>
        <h1 className="t-subtitle font-display">Reset master password</h1>
        <p className="mt-2 text-[var(--text-2)]">Enter the recovery key you saved during setup, then choose a new master password. Your folders stay exactly as they are.</p>
        <div className="mt-5 flex flex-col gap-3">
          <FluentPasswordInput label="Recovery key" value={rk} onChange={(e) => setRk(e.target.value)} placeholder="XXXX-XXXX-XXXX-…" autoFocus />
          <FluentPasswordInput label="New master password" value={np} onChange={(e) => setNp(e.target.value)} />
          <StrengthMeter pw={np} />
          <FluentPasswordInput label="Confirm new master password" value={np2} onChange={(e) => setNp2(e.target.value)} error={np2 && np !== np2 ? "Passwords don't match" : undefined} />
          {error && <InfoBar severity="error">{error}</InfoBar>}
        </div>
        <div className="mt-6 flex justify-end gap-2">
          <FluentButton onClick={() => setForgot(false)} disabled={busy}>
            Back
          </FluentButton>
          <FluentButton variant="accent" disabled={busy || locked || !rk || np.length < 8 || np !== np2} onClick={() => handle(() => api.resetMasterPassword(rk, np))}>
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
        <p className="mt-1 text-[var(--text-2)]">Enter your master password to continue.</p>
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
        <button type="button" className="text-[13px] text-[var(--accent-text)] hover:underline mt-1" onClick={() => setForgot(true)}>
          Forgot your password? Use your recovery key
        </button>
      </form>
    </Shell>
  );
}
