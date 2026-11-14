import { useEffect, useState } from "react";
import { FolderOpenRegular, FlashRegular, ShieldLockRegular } from "@fluentui/react-icons";
import { api, errMsg, type OperationInfo, type ScanReport } from "../lib/api";
import { FluentButton, FluentCheckbox, FluentDialog, FluentPasswordInput, FluentRadio, FluentSegmented, FluentSpinner, InfoBar, useNotify } from "../components/fluent";
import { formatBytes, formatCount, passwordStrength } from "../lib/format";
import { useStore } from "../lib/store";
import { KeyValue, OperationProgress, pickFolder } from "./shared";

type Step = "pick" | "scanning" | "confirm" | "working" | "progress" | "done" | "failed";

export function LockDialog({ initialMode, initialPath }: { initialMode: "quick" | "secure"; initialPath?: string }) {
  const { closeDialog, info, openDialog, vaults, refresh } = useStore();
  const notify = useNotify();
  const [mode, setMode] = useState(initialMode);
  const [path, setPath] = useState(initialPath ?? "");
  const [step, setStep] = useState<Step>(initialPath ? "scanning" : "pick");
  const [scan, setScan] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [useFolderPw, setUseFolderPw] = useState<"master" | "password">("master");
  const [folderPw, setFolderPw] = useState("");
  const [folderPw2, setFolderPw2] = useState("");
  const [vaultRoot, setVaultRoot] = useState("");
  const [vaultFree, setVaultFree] = useState<number | null>(null);
  const [understood, setUnderstood] = useState(false);
  const [opId, setOpId] = useState<string | null>(null);
  const [finalOp, setFinalOp] = useState<OperationInfo | undefined>();

  const root = vaultRoot || info?.defaultVaultRoot || "";

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
  const pwOk = password.length > 0 && (useFolderPw === "master" || (folderPw.length >= 8 && folderPw === folderPw2));
  const spaceOk = mode === "quick" || vaultFree == null || !scan || vaultFree >= scan.estimatedVaultBytes;
  const canConfirm = step === "confirm" && pwOk && spaceOk && (mode === "quick" || understood);

  const submit = async () => {
    setError(null);
    setStep("working");
    try {
      const fp = useFolderPw === "password" ? folderPw : null;
      if (mode === "quick") {
        const v = await api.quickLock(path, password, fp);
        notify({ severity: "success", title: "Folder locked", message: `“${v.name}” is now hidden and access-restricted.` });
        await refresh();
        closeDialog();
      } else {
        const id = await api.secureLock(path, password, fp, vaultRoot || null);
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
          {step === "working" ? (mode === "quick" ? "Locking…" : "Preparing…") : mode === "quick" ? "Lock folder" : "Encrypt folder"}
        </FluentButton>
        <FluentButton disabled={busy} onClick={closeDialog}>
          Cancel
        </FluentButton>
      </>
    );

  return (
    <FluentDialog open title={title} onClose={step === "progress" || step === "done" || step === "failed" || !busy ? closeDialog : undefined} dismissable={!busy} width={step === "confirm" || step === "working" ? 600 : 540} footer={footer}>
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
              <KeyValue
                rows={[
                  ["Folder", <span className="font-semibold">{scan.name}</span>],
                  ["Location", scan.path],
                  ["Size", `${formatBytes(scan.totalBytes)} · ${formatCount(scan.totalFiles)} files, ${formatCount(scan.totalDirs)} folders`],
                  ...(mode === "secure" ? ([["Space needed", `About ${formatBytes(scan.estimatedVaultBytes)} on ${root}${vaultFree != null ? ` (${formatBytes(vaultFree)} free)` : ""}`]] as [string, React.ReactNode][]) : []),
                  ["Drive", scan.driveType === "removable" ? "Removable drive" : scan.driveType === "network" ? "Network drive" : "Local drive"],
                ]}
              />
              {mode === "quick" ? (
                <InfoBar severity="warning" title="Quick Lock is not encryption.">
                  It hides the folder, moves it into DirShield's protected store when it's on the same drive, blocks access with Windows permissions, and asks Windows Search to skip it. Administrators, another operating system, offline disk access or privileged software can bypass it. Use Secure Lock for sensitive data.
                </InfoBar>
              ) : (
                <InfoBar severity="info" title="Secure Lock encrypts everything.">
                  File contents, names and folder structure are encrypted with AES-256-GCM. Your originals stay untouched until encryption is complete and verified — you decide afterwards whether to remove them.
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
              {mode === "secure" && !spaceOk && <InfoBar severity="error" title="Not enough free space.">Choose another vault location or free up space.</InfoBar>}
              {mode === "secure" && (
                <div className="flex items-center gap-3">
                  <div className="flex-1 min-w-0">
                    <div>Vault location</div>
                    <div className="t-caption text-[var(--text-2)] truncate">{root}</div>
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
              <div className="h-px bg-[var(--stroke-divider)]" />
              <FluentRadio
                name="Password"
                value={useFolderPw}
                onChange={setUseFolderPw}
                options={[
                  { value: "master", label: "Use my master password", description: "Recommended. You can change it later without re-encrypting." },
                  { value: "password", label: "Use a separate password for this folder", description: "Your recovery key can still unlock it." },
                ]}
              />
              {useFolderPw === "password" && (
                <div className="grid grid-cols-2 gap-3">
                  <FluentPasswordInput label="Folder password" value={folderPw} onChange={(e) => setFolderPw(e.target.value)} hint={folderPw ? passwordStrength(folderPw).label : "At least 8 characters"} />
                  <FluentPasswordInput label="Confirm folder password" value={folderPw2} onChange={(e) => setFolderPw2(e.target.value)} error={pwMismatch ? "Passwords don't match" : undefined} />
                </div>
              )}
              <FluentPasswordInput label="Confirm with your master password" value={password} onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => e.key === "Enter" && canConfirm && submit()} />
              {mode === "secure" && (
                <FluentCheckbox checked={understood} onChange={setUnderstood}>
                  I understand that without my password and recovery key, encrypted data can't be recovered by anyone.
                </FluentCheckbox>
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
