import { useState } from "react";
import { DocumentRegular } from "@fluentui/react-icons";
import { api, errMsg } from "@/api";
import { FluentButton, FluentPasswordInput, FluentRadio, InfoBar } from "@/components/fluent";
import { pickBackupFile } from "@/features/recovery/backupFiles";

/**
 * Restores DirShield's database from an encrypted backup. Used on the setup
 * screen (fresh install) and from Settings (signed in).
 */
export function RestoreBackupForm({ onCancel, onDone, signedIn }: { onCancel: () => void; onDone: () => void; signedIn: boolean }) {
  const [file, setFile] = useState("");
  const [kind, setKind] = useState<"master" | "recovery">("master");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api.backupRestore(file, { kind, secret });
      onDone();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
      setSecret("");
    }
  };
  return (
    <div className="flex flex-col gap-4">
      <p className="text-[var(--text-2)]">
        A backup holds DirShield's list of protected folders, Quick Lock records, settings and activity — not the folder contents. Secure Lock vaults stay in their own folders; Quick-Locked folders stay in DirShield's data folder on the PC that locked them.
      </p>
      {signedIn && <InfoBar severity="warning">Everything DirShield knows now is replaced by the backup. Folders protected after the backup was made won't be listed; import them again from Recovery.</InfoBar>}
      <div className="flex items-center gap-3">
        <DocumentRegular fontSize={20} className="text-[var(--text-2)] shrink-0" />
        <div className="flex-1 min-w-0 truncate selectable">{file || <span className="text-[var(--text-3)]">No backup selected</span>}</div>
        <FluentButton
          onClick={async () => {
            const p = await pickBackupFile();
            if (p) setFile(p);
          }}
        >
          Browse…
        </FluentButton>
      </div>
      <FluentRadio
        name="Open the backup with"
        value={kind}
        onChange={(k) => (setKind(k), setSecret(""))}
        options={[
          { value: "master", label: "The master password in use when the backup was made" },
          { value: "recovery", label: "The recovery key" },
        ]}
      />
      <FluentPasswordInput
        label={kind === "master" ? "Master password" : "Recovery key"}
        placeholder={kind === "recovery" ? "XXXX-XXXX-XXXX-…" : undefined}
        value={secret}
        onChange={(e) => setSecret(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && file && secret && !busy && submit()}
      />
      {err && <InfoBar severity="error">{err}</InfoBar>}
      <div className="flex justify-end gap-2">
        <FluentButton disabled={busy} onClick={onCancel}>
          {signedIn ? "Cancel" : "Back"}
        </FluentButton>
        <FluentButton variant="accent" disabled={!file || !secret || busy} onClick={submit}>
          {busy ? "Restoring…" : "Restore"}
        </FluentButton>
      </div>
    </div>
  );
}
