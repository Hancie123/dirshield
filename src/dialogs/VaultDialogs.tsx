import { useEffect, useState } from "react";
import { api, errMsg, type Credential, type ItemError, type KeyMode, type OperationInfo, type VaultDetails, type VaultInfo } from "../lib/api";
import { FluentButton, FluentDialog, FluentInput, FluentPasswordInput, FluentRadio, FluentSpinner, InfoBar, useNotify } from "../components/fluent";
import { formatBytes, formatCount, formatDate, passwordStrength, vaultStatusLabel } from "../lib/format";
import { useStore } from "../lib/store";
import { CredentialFields, defaultKind, KeyValue, OperationProgress } from "./shared";

/** Generic "authenticate then do X" dialog. */
function AuthDialog({
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
          <FluentButton variant={danger ? "danger" : "accent"} disabled={!cred.secret || !canSubmit || busy} onClick={submit}>
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

export function VerifyDialog({ vault }: { vault: VaultInfo }) {
  return (
    <AuthDialog
      title="Check vault integrity"
      vault={vault}
      intro={<p>DirShield will decrypt and authenticate every chunk of every file and compare checksums. Nothing is written to disk.</p>}
      confirmLabel="Check now"
      run={(c) => api.verifyVault(vault.id, c)}
      success="Vault verified — every file is intact."
    />
  );
}

export function VisibilityDialog({ vault, hidden }: { vault: VaultInfo; hidden: boolean }) {
  return (
    <AuthDialog
      title={hidden ? "Hide folder" : "Unhide folder"}
      vault={vault}
      intro={
        <p>
          {hidden
            ? "The folder will be hidden from Explorer again."
            : "The folder becomes visible in Explorer but stays locked: it can't be opened until you unlock it."}
        </p>
      }
      confirmLabel={hidden ? "Hide" : "Unhide"}
      run={(c) => api.quickSetHidden(vault.id, hidden, c)}
      success={hidden ? "Folder hidden" : "Folder is visible (still locked)"}
    />
  );
}

export function RemoveOriginalsDialog({ vault }: { vault: VaultInfo }) {
  const [confirm, setConfirm] = useState("");
  return (
    <AuthDialog
      title="Remove unencrypted originals"
      vault={vault}
      danger
      intro={
        <div className="flex flex-col gap-3">
          <InfoBar severity="warning" title="This deletes the original files.">
            Only files that are exactly as they were when encrypted are removed. Files you changed or added afterwards, and anything excluded from the vault, stay in place.
          </InfoBar>
          <p className="t-caption text-[var(--text-2)]">
            This is a normal deletion. On SSDs and modern file systems, deleted data may remain physically recoverable with forensic tools; DirShield does not claim secure erasure.
          </p>
          <p className="t-caption text-[var(--text-2)] selectable">{vault.originalPath}</p>
        </div>
      }
      extra={<FluentInput label={`Type “${vault.name}” to confirm`} value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
      canSubmit={confirm.trim() === vault.name}
      confirmLabel="Remove originals"
      run={(c) => api.removeOriginals(vault.id, c, confirm)}
      success="Originals removed — the folder is now encrypted only."
    />
  );
}

export function DeleteVaultDialog({ vault }: { vault: VaultInfo }) {
  const [confirm, setConfirm] = useState("");
  const dataLoss = vault.status === "locked";
  return (
    <AuthDialog
      title="Delete encrypted vault"
      vault={vault}
      danger
      intro={
        dataLoss ? (
          <InfoBar severity="error" title="This permanently destroys the only copy.">
            The originals of “{vault.name}” were removed. Deleting the vault means this data is gone for good. Restore the folder first if you still need it.
          </InfoBar>
        ) : (
          <InfoBar severity="warning" title="The encrypted copy will be deleted.">
            {vault.status === "restored" ? "The folder has been restored, so its files exist unencrypted at the destination." : "The unencrypted originals are still in place."}
          </InfoBar>
        )
      }
      extra={<FluentInput label={`Type “${vault.name}” to confirm`} value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
      canSubmit={confirm.trim() === vault.name}
      confirmLabel="Delete vault"
      run={(c) => api.deleteVault(vault.id, c, confirm)}
      success="Vault deleted"
    />
  );
}

export function ChangeFolderPasswordDialog({ vault }: { vault: VaultInfo }) {
  const [mode, setMode] = useState<KeyMode>(vault.keyMode);
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const valid = mode === "master" || (pw.length >= 8 && pw === pw2);
  return (
    <AuthDialog
      title="Change folder password"
      vault={vault}
      intro={<p className="text-[var(--text-2)]">Only the key wrapper is replaced — nothing is re-encrypted, even for very large folders.</p>}
      extra={
        <div className="flex flex-col gap-3">
          <FluentRadio
            name="New password"
            value={mode}
            onChange={setMode}
            options={[
              { value: "master", label: "Use my master password" },
              { value: "password", label: "Use a separate password for this folder" },
            ]}
          />
          {mode === "password" && (
            <div className="grid grid-cols-2 gap-3">
              <FluentPasswordInput label="New folder password" value={pw} onChange={(e) => setPw(e.target.value)} hint={pw ? passwordStrength(pw).label : "At least 8 characters"} />
              <FluentPasswordInput label="Confirm" value={pw2} onChange={(e) => setPw2(e.target.value)} error={pw2 && pw !== pw2 ? "Passwords don't match" : undefined} />
            </div>
          )}
          <div className="h-px bg-[var(--stroke-divider)]" />
          <div className="t-body-strong">Current password</div>
        </div>
      }
      canSubmit={valid}
      confirmLabel="Change password"
      run={(c) => api.changeFolderPassword(vault.id, c, mode, mode === "password" ? pw : null)}
      success="Folder password changed"
    />
  );
}

export function ResumeDialog({ op, mode }: { op: OperationInfo; mode: "resume" | "retry" | "skip" }) {
  const { vaults } = useStore();
  const vault = vaults.find((v) => v.id === op.vaultId);
  if (!vault) return null;
  const titles = { resume: "Resume operation", retry: "Retry failed items", skip: "Exclude failed items and continue" };
  return (
    <AuthDialog
      title={titles[mode]}
      vault={vault}
      intro={
        mode === "skip" ? (
          <InfoBar severity="warning" title="Failed items will be left out of the vault.">
            They stay unencrypted in the original folder and are never removed by DirShield.
          </InfoBar>
        ) : (
          <p>Work continues from where it stopped. Items already finished and verified aren't processed again.</p>
        )
      }
      confirmLabel={mode === "resume" ? "Resume" : mode === "retry" ? "Retry" : "Exclude and continue"}
      run={async (c) => {
        await api.opResume(op.id, c, mode);
        return op.id;
      }}
      success="Operation completed"
    />
  );
}

export function ErrorsDialog({ op }: { op: OperationInfo }) {
  const { closeDialog } = useStore();
  const [items, setItems] = useState<ItemError[] | null>(null);
  useEffect(() => {
    api.opErrors(op.id).then(setItems).catch(() => setItems([]));
  }, [op.id]);
  return (
    <FluentDialog open title="Error details" width={680} onClose={closeDialog} footer={<FluentButton onClick={closeDialog}>Close</FluentButton>}>
      {op.error && (
        <div className="mb-3">
          <InfoBar severity="error">{op.error}</InfoBar>
        </div>
      )}
      {items == null ? (
        <FluentSpinner />
      ) : items.length === 0 ? (
        <p className="text-[var(--text-2)]">No individual file errors were recorded.</p>
      ) : (
        <div className="max-h-[360px] overflow-y-auto rounded-[4px] border border-[var(--stroke-card)] selectable">
          {items.map((it, i) => (
            <div key={i} className="px-3 py-2 border-b border-[var(--stroke-divider)] last:border-0">
              <div className="text-[13px] break-all">{it.path}</div>
              <div className="t-caption text-[var(--critical)]">{it.error}</div>
            </div>
          ))}
        </div>
      )}
    </FluentDialog>
  );
}

export function DetailsDialog({ vault }: { vault: VaultInfo }) {
  const { closeDialog } = useStore();
  const [d, setD] = useState<VaultDetails | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    api.vaultDetails(vault.id).then(setD).catch((e) => setErr(errMsg(e)));
  }, [vault.id]);
  const v = d ?? vault;
  return (
    <FluentDialog open title={vault.name} width={620} onClose={closeDialog} footer={<FluentButton onClick={closeDialog}>Close</FluentButton>}>
      {err && <InfoBar severity="error">{err}</InfoBar>}
      <KeyValue
        rows={[
          ["Protection", v.mode === "quick" ? "Quick Lock (access restriction, not encryption)" : "Secure Lock (encrypted)"],
          ["Status", vaultStatusLabel[v.status]],
          ["Original location", v.originalPath],
          ["Size", `${formatBytes(v.sizeBytes)} · ${formatCount(v.fileCount)} files`],
          ["Locked", formatDate(v.lockedAt)],
          ["Unlocks with", v.keyMode === "password" ? "Folder password or recovery key" : "Master password or recovery key"],
          ...((d?.currentPath ? [["Stored at", d.currentPath]] : []) as [string, string][]),
          ...((v.mode === "secure"
            ? [
                ["Vault folder", v.vaultPath],
                ["Algorithm", d?.algorithm ?? "—"],
                ["Chunk size", d?.chunkSize ? formatBytes(d.chunkSize) : "—"],
                ["Key wrappers", d?.wrappers.join(", ") || "—"],
                ["Format version", String(d?.formatVersion ?? "—")],
                ["Sealed", d?.sealed == null ? "—" : d.sealed ? "Yes — complete and verified" : "No — incomplete"],
              ]
            : []) as [string, string][]),
          ...((v.skippedCount > 0 ? [["Not in vault", `${formatCount(v.skippedCount)} item(s) (links, unreadable or excluded) remain in the original folder`]] : []) as [string, string][]),
        ]}
      />
    </FluentDialog>
  );
}
