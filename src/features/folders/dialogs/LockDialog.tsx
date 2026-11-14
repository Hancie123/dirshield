import { useEffect, useState } from "react";
import { ChevronDownRegular, FolderOpenRegular, FolderRegular, FlashRegular, ShieldLockRegular } from "@fluentui/react-icons";
import { api, errMsg, type OperationInfo, type ScanReport } from "@/api";
import { useStore } from "@/app/store";
import { HelloNote, useHelloEnabled } from "@/components/CredentialFields";
import { OperationProgress } from "@/components/OperationProgress";
import { StrengthHint } from "@/components/PasswordStrength";
import { FluentButton, FluentCheckbox, FluentDialog, FluentPasswordInput, FluentRadio, FluentSegmented, FluentSpinner, InfoBar, useNotify } from "@/components/fluent";
import { formatBytes, formatCount } from "@/lib/format";
import { pickFolder } from "@/lib/pickers";

type Step = "pick" | "scanning" | "confirm" | "working" | "progress" | "done" | "failed";

export function LockDialog({ initialMode, initialPath, initialHide = true }: { initialMode: "quick" | "secure"; initialPath?: string; initialHide?: boolean }) {
  const { closeDialog, openDialog, vaults, refresh } = useStore();
  const notify = useNotify();
  const [mode, setMode] = useState(initialMode);
  const [path, setPath] = useState(initialPath ?? "");
  const [hide, setHide] = useState(initialHide);
  const [step, setStep] = useState<Step>(initialPath ? "scanning" : "pick");
  const [scan, setScan] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const helloOn = useHelloEnabled();
  const [useHello, setUseHello] = useState(false);
  const [useFolderPw, setUseFolderPw] = useState<"master" | "password">("master");
  const [folderPw, setFolderPw] = useState("");
  const [folderPw2, setFolderPw2] = useState("");
  const [vaultRoot, setVaultRoot] = useState("");
  const [vaultFree, setVaultFree] = useState<number | null>(null);
  const [understood, setUnderstood] = useState(false);
  const [more, setMore] = useState(false);
  const [opId, setOpId] = useState<string | null>(null);
  const [finalOp, setFinalOp] = useState<OperationInfo | undefined>();

  // Default: the vault is created next to the folder, on the same drive.
  const besideFolder = scan ? scan.path.replace(/[\\/]+$/, "").replace(/[\\/][^\\/]*$/, "") || scan.path : "";
  const root = vaultRoot || (/^[A-Za-z]:$/.test(besideFolder) ? `${besideFolder}\\` : besideFolder);

  const doScan = async (p: string) => {
    setStep("scanning");
    setError(null);
    try {
      const r = await api.scanFolder(p);
      setScan(r);
      setPath(r.path);
      setStep("confirm");
    } catch (e) {
      setError(errMsg(e));
      setStep("pick");
    }
  };

  useEffect(() => {
    if (initialPath) doScan(initialPath);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (mode === "secure" && root) api.freeSpace(root).then(setVaultFree).catch(() => setVaultFree(null));
  }, [mode, root]);

  const choose = async () => {
    const p = await pickFolder("Choose a folder to protect");
    if (p) doScan(p);
  };

  const pwMismatch = useFolderPw === "password" && folderPw2.length > 0 && folderPw !== folderPw2;
  const pwOk = (useHello || password.length > 0) && (useFolderPw === "master" || (folderPw.length >= 8 && folderPw === folderPw2));
  const spaceOk = mode === "quick" || vaultFree == null || !scan || vaultFree >= scan.estimatedVaultBytes;
  const canConfirm = step === "confirm" && pwOk && spaceOk && (mode === "quick" || understood);

  const submit = async () => {
    setError(null);
    setStep("working");
    try {
      const fp = useFolderPw === "password" ? folderPw : null;
      const cred = useHello ? ({ kind: "hello", secret: "" } as const) : ({ kind: "master", secret: password } as const);
      if (mode === "quick") {
        const v = await api.quickLock(path, cred, fp, hide);
        notify({ severity: "success", title: "Folder locked", message: hide ? `“${v.name}” is now hidden and access-restricted.` : `“${v.name}” is now access-restricted. It stays visible where it is.` });
        await refresh();
        closeDialog();
      } else {
        const id = await api.secureLock(path, cred, fp, vaultRoot || null);
        setOpId(id);
        setStep("progress");
      }
    } catch (e) {
      setError(errMsg(e));
      setStep("confirm");
    } finally {
      setPassword("");
    }
  };

  const vault = opId ? vaults.find((v) => finalOp && v.id === finalOp.vaultId) : undefined;
  const busy = step === "working" || step === "scanning";
  const title = step === "progress" ? "Encrypting folder" : step === "done" ? "Folder encrypted" : step === "failed" ? "Encryption stopped" : mode === "quick" ? "Quick Lock" : "Secure Lock";

  let footer: React.ReactNode;
  if (step === "progress") footer = <FluentButton onClick={closeDialog}>Run in background</FluentButton>;
  else if (step === "done")
    footer = (
      <>
        {vault && (
          <FluentButton variant="accent" onClick={() => openDialog({ kind: "removeOriginals", vault })}>
            Remove originals…
          </FluentButton>
        )}
        <FluentButton onClick={closeDialog}>Keep originals for now</FluentButton>
      </>
    );
  else if (step === "failed") footer = <FluentButton onClick={closeDialog}>Close</FluentButton>;
  else
    footer = (
      <>
        <FluentButton variant="accent" disabled={!canConfirm || busy} onClick={submit}>
          {step === "working" ? (mode === "quick" ? "Locking…" : "Preparing…") : mode === "quick" ? (hide ? "Lock and hide" : "Lock folder") : "Encrypt folder"}
        </FluentButton>
        <FluentButton disabled={busy} onClick={closeDialog}>
          Cancel
        </FluentButton>
      </>
    );

  return (
    <FluentDialog open title={title} onClose={step === "progress" || step === "done" || step === "failed" || !busy ? closeDialog : undefined} dismissable={!busy} width={500} footer={footer}>
      {(step === "pick" || step === "scanning" || step === "confirm" || step === "working") && (
        <div className="flex flex-col gap-4">
          <FluentSegmented
            value={mode}
            onChange={setMode}
            options={[
              { value: "quick", label: <><FlashRegular /> Quick Lock</> },
              { value: "secure", label: <><ShieldLockRegular /> Secure Lock</> },
            ]}
          />
          {step === "pick" && (
            <div className="flex flex-col gap-3">
              <p className="text-[var(--text-2)]">Choose the folder you want to protect.</p>
              <div>
                <FluentButton variant="accent" icon={<FolderOpenRegular />} onClick={choose}>
                  Choose folder…
                </FluentButton>
              </div>
            </div>
          )}
          {step === "scanning" && (
            <div className="flex items-center gap-3 py-4">
              <FluentSpinner size={20} />
              <span>Scanning folder… large folders can take a moment.</span>
            </div>
          )}
          {error && <InfoBar severity="error">{error}</InfoBar>}
          {scan && (step === "confirm" || step === "working") && (
            <>
              <div className="flex items-center gap-3 px-3 py-2.5 rounded-[6px] bg-[var(--card)] border border-[var(--stroke-card)]">
                <FolderRegular fontSize={28} className="text-[#e8a22a] shrink-0" />
                <div className="min-w-0">
                  <div className="font-semibold truncate">{scan.name}</div>
                  <div className="t-caption text-[var(--text-2)] truncate" title={scan.path}>
                    {formatBytes(scan.totalBytes)} · {formatCount(scan.totalFiles)} files · {scan.path}
                  </div>
                </div>
              </div>
              {mode === "quick" && (
                <InfoBar severity="warning" title="Quick Lock keeps people out. Secure Lock keeps data safe.">
                  Quick Lock only blocks access; it doesn't encrypt. Any program running under your Windows account, including malware, can remove it without your password, and an administrator or
                  another operating system can read the files. DirShield checks every minute and locks the folder again if it was removed. For anything sensitive, use Secure Lock.
                </InfoBar>
              )}
              {scan.links > 0 && (
                <InfoBar severity="warning" title={`${formatCount(scan.links)} link(s) or junction(s) will be skipped.`}>
                  They are not followed and stay where they are.
                </InfoBar>
              )}
              {scan.inaccessible > 0 && (
                <InfoBar severity="warning" title={`${formatCount(scan.inaccessible)} item(s) can't be read right now.`}>
                  {mode === "secure" ? "They may be open in another program. You'll be able to retry or exclude them." : "They'll be locked along with the folder."}
                  <div className="t-caption mt-1 text-[var(--text-2)] truncate">{scan.inaccessibleSamples.slice(0, 3).join(" · ")}</div>
                </InfoBar>
              )}
              {mode === "secure" && scan.badNames > 0 && (
                <InfoBar severity="warning" title={`${formatCount(scan.badNames)} item(s) have names Secure Lock can't store.`}>
                  Their names contain invalid characters. They'll be skipped and left in the folder, unencrypted. Rename them to include them.
                  <div className="t-caption mt-1 text-[var(--text-2)] truncate">{scan.badNameSamples.slice(0, 3).join(" · ")}</div>
                </InfoBar>
              )}
              {mode === "secure" && !spaceOk && (
                <InfoBar severity="error" title="Not enough free space.">
                  Needs about {formatBytes(scan.estimatedVaultBytes)}; {vaultFree != null ? formatBytes(vaultFree) : "less"} free. Choose another vault location under More options.
                </InfoBar>
              )}
              {useHello ? (
                <HelloNote onUsePassword={() => setUseHello(false)} />
              ) : (
                <div className="flex flex-col gap-2">
                  <FluentPasswordInput label="Master password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => e.key === "Enter" && canConfirm && submit()} />
                  {helloOn && (
                    <button type="button" className="self-start text-[13px] text-[var(--accent-text)] hover:underline" onClick={() => setUseHello(true)}>
                      Use Windows Hello instead
                    </button>
                  )}
                </div>
              )}
              {mode === "secure" && (
                <FluentCheckbox checked={understood} onChange={setUnderstood}>
                  I understand encrypted data can't be recovered without my password or recovery key.
                </FluentCheckbox>
              )}

              <button type="button" className="flex items-center gap-1.5 self-start text-[14px] text-[var(--text-1)] hover:text-[var(--text-2)]" onClick={() => setMore((m) => !m)} aria-expanded={more}>
                <ChevronDownRegular className={`transition-transform ${more ? "" : "-rotate-90"}`} />
                More options
              </button>
              {more && (
                <div className="flex flex-col gap-4 pl-5">
                  {mode === "quick" && (
                    <FluentCheckbox checked={hide} onChange={setHide}>
                      Also hide the folder
                    </FluentCheckbox>
                  )}
                  {mode === "secure" && (
                    <div className="flex items-center gap-3">
                      <div className="flex-1 min-w-0">
                        <div>Vault location{!vaultRoot && <span className="text-[var(--text-2)]"> · next to the folder</span>}</div>
                        <div className="t-caption text-[var(--text-2)] truncate" title={root}>
                          {root}
                          {vaultFree != null && ` · ${formatBytes(vaultFree)} free`}
                        </div>
                      </div>
                      <FluentButton
                        onClick={async () => {
                          const p = await pickFolder("Choose where to store the encrypted vault", root);
                          if (p) setVaultRoot(p);
                        }}
                      >
                        Change…
                      </FluentButton>
                    </div>
                  )}
                  <FluentRadio
                    name="Password"
                    value={useFolderPw}
                    onChange={setUseFolderPw}
                    options={[
                      { value: "master", label: "Use my master password" },
                      { value: "password", label: "Use a separate password for this folder" },
                    ]}
                  />
                  {useFolderPw === "password" && (
                    <div className="grid grid-cols-2 gap-3">
                      <FluentPasswordInput label="Folder password" value={folderPw} onChange={(e) => setFolderPw(e.target.value)} hint={<StrengthHint pw={folderPw} />} />
                      <FluentPasswordInput label="Confirm folder password" value={folderPw2} onChange={(e) => setFolderPw2(e.target.value)} error={pwMismatch ? "Passwords don't match" : undefined} />
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      )}
      {step === "progress" && opId && (
        <div className="flex flex-col gap-4">
          <p className="text-[var(--text-2)]">You can keep using DirShield or close this window — encryption continues in the background and survives restarts.</p>
          <OperationProgress
            opId={opId}
            onFinished={(op) => {
              setFinalOp(op);
              setStep(op?.status === "completed" ? "done" : "failed");
            }}
          />
        </div>
      )}
      {step === "done" && (
        <div className="flex flex-col gap-3">
          <InfoBar severity="success" title="Encrypted and verified.">
            Every file was encrypted, read back and checked.
          </InfoBar>
          <p>
            Your original folder is still in place. To finish protecting it, remove the unencrypted originals. Only files that are exactly as they were encrypted will be removed.
          </p>
        </div>
      )}
      {step === "failed" && (
        <div className="flex flex-col gap-3">
          <InfoBar severity={finalOp?.status === "cancelled" ? "warning" : "error"} title={finalOp?.status === "cancelled" ? "Encryption was cancelled." : "Encryption didn't finish."}>
            {finalOp?.error}
          </InfoBar>
          <p>Your original folder hasn't been changed. You can resume, retry or discard this operation from Active operations.</p>
        </div>
      )}
    </FluentDialog>
  );
}
