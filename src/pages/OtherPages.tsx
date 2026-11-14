import { useEffect, useState } from "react";
import {
  ArrowImportRegular,
  ArrowDownloadRegular,
  ColorRegular,
  DeleteRegular,
  FolderOpenRegular,
  KeyRegular,
  LockClosedRegular,
  ArrowSyncRegular,
  PlayCircleRegular,
  StorageRegular,
  TimerRegular,
  WarningRegular,
  WindowRegular,
  ChevronRightRegular,
} from "@fluentui/react-icons";
import { api, errMsg, type Activity, type Orphan, type Settings } from "../lib/api";
import { Badge, FluentButton, FluentCard, FluentDialog, FluentPasswordInput, FluentSelect, FluentTable, FluentToggle, InfoBar, SectionHeader, SettingsRow, useNotify } from "../components/fluent";
import { actionLabel, formatDate } from "../lib/format";
import { masterStrongEnough, StrengthMeter, usePasswordStrength } from "../lib/strength";
import { setThemePreference, useStore } from "../lib/store";
import { pickFolder } from "../dialogs/shared";
import { useUpdater } from "../lib/updater";

// ---------------------------------------------------------------- Recovery

export function RecoveryPage() {
  const { vaults, ops, openDialog, setPage, refresh } = useStore();
  const notify = useNotify();
  const [importOpen, setImportOpen] = useState(false);
  const [importPath, setImportPath] = useState("");
  const [rk, setRk] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [pick, setPick] = useState(false);
  const attention = ops.filter((o) => !o.live && o.status !== "completed");
  const recoverable = vaults.filter((v) => v.mode === "quick" || ["encrypted", "locked", "restored"].includes(v.status));

  return (
    <div className="flex flex-col gap-1">
      <InfoBar severity="info">
        Your recovery key can unlock any folder protected on this PC, reset your master password, and re-open vaults if the DirShield database is lost. If both the master password and the recovery key are lost, encrypted data cannot be recovered.
      </InfoBar>
      <SectionHeader>Recover</SectionHeader>
      <SettingsRow icon={<WarningRegular />} title="Interrupted operations" description={attention.length ? `${attention.length} operation(s) can be resumed or discarded safely.` : "Nothing needs recovery."} onClick={() => setPage("operations")}>
        {attention.length > 0 && <Badge tone="critical">{attention.length}</Badge>}
        <ChevronRightRegular />
      </SettingsRow>
      <SettingsRow icon={<KeyRegular />} title="Unlock a folder with the recovery key" description="Use this if you've forgotten a folder password.">
        <FluentButton disabled={!recoverable.length} onClick={() => setPick(true)}>
          Choose folder
        </FluentButton>
      </SettingsRow>
      <SettingsRow icon={<ArrowImportRegular />} title="Import an existing vault" description="Re-register a Secure Lock vault folder (for example after reinstalling Windows or restoring a backup).">
        <FluentButton onClick={() => setImportOpen(true)}>Import…</FluentButton>
      </SettingsRow>
      <OrphanRecovery />
      <SettingsRow icon={<LockClosedRegular />} title="Forgot your master password?" description="Sign out, then choose “Forgot your password?” on the sign-in screen and enter your recovery key." />

      {pick && (
        <FluentDialog open title="Choose a folder" onClose={() => setPick(false)} footer={<FluentButton onClick={() => setPick(false)}>Cancel</FluentButton>}>
          <div className="flex flex-col gap-1 max-h-[360px] overflow-y-auto">
            {recoverable.map((v) => (
              <button
                key={v.id}
                className="flex items-center gap-3 px-3 h-12 rounded-[4px] hover:bg-[var(--fill-subtle-hover)] text-left"
                onClick={() => {
                  setPick(false);
                  openDialog({ kind: "unlock", vault: v, recovery: true });
                }}
              >
                <span className="flex-1 truncate">{v.name}</span>
                <span className="t-caption text-[var(--text-2)]">{v.mode === "quick" ? "Quick Lock" : "Secure Lock"}</span>
              </button>
            ))}
          </div>
        </FluentDialog>
      )}

      {importOpen && (
        <FluentDialog
          open
          title="Import a vault"
          onClose={busy ? undefined : () => setImportOpen(false)}
          footer={
            <>
              <FluentButton
                variant="accent"
                disabled={!importPath || !rk || busy}
                onClick={async () => {
                  setBusy(true);
                  setErr(null);
                  try {
                    const v = await api.importVault(importPath, rk);
                    notify({ severity: "success", title: "Vault imported", message: `“${v.name}” now unlocks with your current master password.` });
                    setImportOpen(false);
                    setRk("");
                    refresh();
                  } catch (e) {
                    setErr(errMsg(e));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {busy ? "Importing…" : "Import"}
              </FluentButton>
              <FluentButton disabled={busy} onClick={() => setImportOpen(false)}>
                Cancel
              </FluentButton>
            </>
          }
        >
          <div className="flex flex-col gap-4">
            <p className="text-[var(--text-2)]">Select the vault folder — the one containing “vault.dsv” — and enter the recovery key that was active when it was created.</p>
            <div className="flex items-center gap-3">
              <div className="flex-1 min-w-0 truncate selectable">{importPath || <span className="text-[var(--text-3)]">No folder selected</span>}</div>
              <FluentButton
                icon={<FolderOpenRegular />}
                onClick={async () => {
                  const p = await pickFolder("Select the vault folder");
                  if (p) setImportPath(p);
                }}
              >
                Browse…
              </FluentButton>
            </div>
            <FluentPasswordInput label="Recovery key" value={rk} onChange={(e) => setRk(e.target.value)} placeholder="XXXX-XXXX-XXXX-…" />
            {err && <InfoBar severity="error">{err}</InfoBar>}
          </div>
        </FluentDialog>
      )}
    </div>
  );
}

/** Quick-Locked folders still in DirShield's store but missing from its database. */
function OrphanRecovery() {
  const notify = useNotify();
  const [orphans, setOrphans] = useState<Orphan[]>([]);
  const [target, setTarget] = useState<Orphan | null>(null);
  const [dest, setDest] = useState("");
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const load = () => api.findOrphans().then(setOrphans).catch(() => {});
  useEffect(() => {
    load();
  }, []);
  if (!orphans.length) return null;
  return (
    <>
      <SettingsRow
        icon={<WarningRegular className="text-[var(--caution)]" />}
        title={`${orphans.length} Quick-Locked folder(s) without a record`}
        description="These folders are still protected in DirShield's store, but their database entry is missing (for example after the database was deleted). Return them to their original location."
      >
        <FluentButton
          onClick={() => {
            setTarget(orphans[0]);
            setDest(orphans[0].originalPath ?? "");
          }}
        >
          Review…
        </FluentButton>
      </SettingsRow>
      {target && (
        <FluentDialog
          open
          title="Return folder"
          onClose={busy ? undefined : () => setTarget(null)}
          footer={
            <>
              <FluentButton
                variant="accent"
                disabled={!pw || !dest || busy}
                onClick={async () => {
                  setBusy(true);
                  setErr(null);
                  try {
                    const p = await api.recoverOrphan(target.id, pw, dest);
                    notify({ severity: "success", title: "Folder returned", message: p, action: { label: "Open folder", onClick: () => api.openInExplorer(p) } });
                    setTarget(null);
                    setPw("");
                    load();
                  } catch (e) {
                    setErr(errMsg(e));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {busy ? "Working…" : "Return folder"}
              </FluentButton>
              <FluentButton disabled={busy} onClick={() => setTarget(null)}>
                Cancel
              </FluentButton>
            </>
          }
        >
          <div className="flex flex-col gap-4">
            <KeyValueLite rows={[["Locked", target.lockedAt ? formatDate(target.lockedAt) : "Unknown"], ["Original location", target.originalPath ?? "Unknown — choose a destination"]]} />
            <div className="flex items-center gap-3">
              <div className="flex-1 min-w-0 truncate selectable">{dest || <span className="text-[var(--text-3)]">No destination</span>}</div>
              <FluentButton
                onClick={async () => {
                  const p = await pickFolder("Choose where to put the folder");
                  if (p) setDest(`${p.replace(/\\$/, "")}\\${(target.originalPath ?? "Recovered folder").split("\\").pop()}`);
                }}
              >
                Change…
              </FluentButton>
            </div>
            <FluentPasswordInput label="Master password" value={pw} onChange={(e) => setPw(e.target.value)} />
            {err && <InfoBar severity="error">{err}</InfoBar>}
          </div>
        </FluentDialog>
      )}
    </>
  );
}

function KeyValueLite({ rows }: { rows: [string, string][] }) {
  return (
    <dl className="grid grid-cols-[140px_1fr] gap-y-1 gap-x-4">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-[var(--text-2)]">{k}</dt>
          <dd className="selectable break-all">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

// ---------------------------------------------------------------- Activity

export function ActivityPage() {
  const [rows, setRows] = useState<Activity[]>([]);
  const [confirm, setConfirm] = useState(false);
  const load = () => api.listActivity(500).then(setRows).catch(() => {});
  useEffect(() => {
    load();
  }, []);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex justify-end gap-2">
        <FluentButton variant="subtle" icon={<ArrowSyncRegular />} onClick={load}>
          Refresh
        </FluentButton>
        <FluentButton variant="subtle" icon={<DeleteRegular />} disabled={!rows.length} onClick={() => setConfirm(true)}>
          Clear history
        </FluentButton>
      </div>
      <FluentTable
        rows={rows}
        rowKey={(r) => String(r.id)}
        empty="No activity recorded."
        columns={[
          { key: "time", header: "Time", width: "170px", render: (r) => <span className="text-[var(--text-2)]">{formatDate(r.createdAt)}</span> },
          { key: "action", header: "Action", width: "minmax(160px,1.5fr)", render: (r) => actionLabel(r.action) },
          { key: "folder", header: "Folder", width: "minmax(120px,1fr)", render: (r) => <span className="truncate block">{r.vaultName ?? (r.vaultId ? "(removed)" : "—")}</span> },
          {
            key: "status",
            header: "Result",
            width: "minmax(120px,1.5fr)",
            render: (r) => (
              <span title={r.detail ?? undefined} className="flex items-center gap-2 min-w-0">
                <Badge tone={r.status === "success" ? "success" : r.status === "failed" ? "critical" : r.status === "cancelled" ? "caution" : "neutral"}>{r.status}</Badge>
                {r.detail && r.status === "failed" && <span className="t-caption text-[var(--text-2)] truncate">{r.detail}</span>}
              </span>
            ),
          },
        ]}
      />
      {confirm && (
        <FluentDialog
          open
          title="Clear activity history?"
          onClose={() => setConfirm(false)}
          footer={
            <>
              <FluentButton variant="accent" onClick={() => api.clearActivity().then(() => (setConfirm(false), load()))}>
                Clear
              </FluentButton>
              <FluentButton onClick={() => setConfirm(false)}>Cancel</FluentButton>
            </>
          }
        >
          This removes the activity log only. Protected folders aren't affected.
        </FluentDialog>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Settings

export function SettingsPage() {
  const { info } = useStore();
  const notify = useNotify();
  const [s, setS] = useState<Settings | null>(null);
  const [pwOpen, setPwOpen] = useState(false);
  useEffect(() => {
    api.getSettings().then(setS).catch((e) => notify({ severity: "error", title: "Couldn't load settings", message: errMsg(e) }));
  }, [notify]);
  if (!s) return null;

  const save = async (next: Settings) => {
    setS(next);
    try {
      await api.saveSettings(next);
      setThemePreference(next.theme);
      setS(await api.getSettings());
    } catch (e) {
      notify({ severity: "error", title: "Couldn't save setting", message: errMsg(e) });
      setS(await api.getSettings());
    }
  };

  return (
    <div className="flex flex-col gap-1">
      <SectionHeader>Appearance</SectionHeader>
      <SettingsRow icon={<ColorRegular />} title="App theme" description="Follow Windows, or choose light or dark.">
        <FluentSelect
          label="App theme"
          value={s.theme}
          onChange={(theme) => save({ ...s, theme })}
          options={[
            { value: "system", label: "Use system setting" },
            { value: "light", label: "Light" },
            { value: "dark", label: "Dark" },
          ]}
        />
      </SettingsRow>

      <SectionHeader>Security</SectionHeader>
      <SettingsRow icon={<KeyRegular />} title="Master password" description="Changing it re-wraps your keys instantly — no folder is re-encrypted.">
        <FluentButton onClick={() => setPwOpen(true)}>Change</FluentButton>
      </SettingsRow>
      <SettingsRow icon={<TimerRegular />} title="Lock DirShield after inactivity" description="Running operations continue in the background while locked.">
        <FluentSelect
          label="Auto-lock"
          value={s.autoLockMinutes}
          onChange={(autoLockMinutes) => save({ ...s, autoLockMinutes })}
          options={[
            { value: 1, label: "1 minute" },
            { value: 5, label: "5 minutes" },
            { value: 10, label: "10 minutes" },
            { value: 30, label: "30 minutes" },
            { value: 60, label: "1 hour" },
            { value: 0, label: "Never" },
          ]}
        />
      </SettingsRow>

      <SectionHeader>Windows integration</SectionHeader>
      <SettingsRow
        icon={<WindowRegular />}
        title="File Explorer context menu"
        description={
          s.contextMenu && !s.contextMenuCurrent
            ? "Registered, but pointing to a different copy of DirShield. Turn off and on to repair."
            : "Adds Quick Lock, Secure Lock, Unlock and Unhide when you right-click a folder. On Windows 11 they're under “Show more options”."
        }
      >
        <FluentToggle label="Context menu" checked={s.contextMenu} onChange={(contextMenu) => save({ ...s, contextMenu })} />
      </SettingsRow>
      <SettingsRow icon={<PlayCircleRegular />} title="Start DirShield when I sign in to Windows" description="Starts minimized.">
        <FluentToggle label="Launch at startup" checked={s.launchAtStartup} onChange={(launchAtStartup) => save({ ...s, launchAtStartup })} />
      </SettingsRow>

      <SectionHeader>Storage and performance</SectionHeader>
      <SettingsRow icon={<StorageRegular />} title="Default vault location" description={s.defaultVaultRoot}>
        <FluentButton
          onClick={async () => {
            const p = await pickFolder("Choose the default location for encrypted vaults", s.defaultVaultRoot);
            if (p) save({ ...s, defaultVaultRoot: p });
          }}
        >
          Change…
        </FluentButton>
      </SettingsRow>
      <SettingsRow icon={<ArrowSyncRegular />} title="Files processed in parallel" description="Higher can be faster on SSDs. Keep 1–2 for hard drives and USB sticks.">
        <FluentSelect
          label="Parallel files"
          value={s.concurrency}
          onChange={(concurrency) => save({ ...s, concurrency })}
          options={[1, 2, 3, 4, 6, 8].map((n) => ({ value: n, label: `${n}${n === 2 ? " (default)" : ""}` }))}
        />
      </SettingsRow>
      <SettingsRow icon={<FolderOpenRegular />} title="DirShield data folder" description={info?.dataDir}>
        <FluentButton onClick={() => info && api.openInExplorer(info.dataDir).catch(() => {})}>Open</FluentButton>
      </SettingsRow>
      {pwOpen && <ChangeMasterDialog onClose={() => setPwOpen(false)} />}
    </div>
  );
}

function ChangeMasterDialog({ onClose }: { onClose: () => void }) {
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
        <p className="t-caption text-[var(--text-2)]">Your recovery key stays the same. Folders with their own password aren't affected.</p>
        {err && <InfoBar severity="error">{err}</InfoBar>}
      </div>
    </FluentDialog>
  );
}

// ---------------------------------------------------------------- About

function UpdateRow() {
  const { state, check, install } = useUpdater();
  const { ops } = useStore();
  const busy = ops.some((o) => o.live);
  const description =
    state.kind === "checking"
      ? "Checking…"
      : state.kind === "none"
        ? "You're on the latest version."
        : state.kind === "available"
          ? `Version ${state.update.version} is available.`
          : state.kind === "installing"
            ? `Installing${state.pct != null ? ` — ${state.pct}%` : "…"}`
            : state.kind === "error"
              ? `Couldn't check for updates: ${state.message}`
              : "Updates are signed and verified before they're installed.";
  return (
    <SettingsRow icon={<ArrowDownloadRegular />} title="Updates" description={description}>
      {state.kind === "available" ? (
        <FluentButton variant="accent" disabled={busy} onClick={install}>
          Install and restart
        </FluentButton>
      ) : (
        <FluentButton disabled={state.kind === "checking" || state.kind === "installing"} onClick={check}>
          Check for updates
        </FluentButton>
      )}
    </SettingsRow>
  );
}

export function AboutPage() {
  const { info } = useStore();
  const facts: [string, string][] = [
    ["Version", info?.version ?? "—"],
    ["Windows build", info?.windowsBuild ? String(info.windowsBuild) : "—"],
    ["Secure Lock", "AES-256-GCM, 4 MiB authenticated chunks (STREAM), per-file HKDF-SHA256 keys"],
    ["Passwords", "Argon2id (64 MiB, 3 passes, 4 lanes) with unique random salts"],
    ["Recovery", "256-bit recovery key; vault keys escrowed with X25519"],
    ["Storage", "Local only — no account, no cloud. The only network request is the update check to GitHub Releases."],
  ];
  return (
    <div className="flex flex-col gap-1">
      <UpdateRow />
      <FluentCard className="p-5">
        <dl className="grid grid-cols-[160px_1fr] gap-y-2 gap-x-4">
          {facts.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-[var(--text-2)]">{k}</dt>
              <dd className="selectable">{v}</dd>
            </div>
          ))}
        </dl>
      </FluentCard>
      <SectionHeader>What DirShield does and doesn't protect against</SectionHeader>
      <FluentCard className="p-5 flex flex-col gap-3 text-[14px]">
        <p>
          <b>Quick Lock</b> hides a folder and blocks access through Windows permissions. It is not encryption: an administrator, another operating system, offline disk access or privileged software can bypass it.
        </p>
        <p>
          <b>Secure Lock</b> encrypts contents, names and folder structure. Without the password or recovery key, the data can't be read. File sizes are approximately visible from the encrypted objects.
        </p>
        <p>
          <b>Removing originals</b> uses normal deletion. On SSDs and journaling file systems, old data may remain physically recoverable with forensic tools.
        </p>
        <p>
          <b>Windows Search</b> exclusions are a privacy aid, not a security boundary. Previously indexed results, backups, cloud sync and third-party indexers may still hold copies made before locking.
        </p>
        <p>
          <b>Virtual drive</b> (browsing a vault without restoring it) is not available in this version; it requires the WinFsp driver and is planned. Restore is used to unlock Secure Lock folders.
        </p>
      </FluentCard>
    </div>
  );
}
