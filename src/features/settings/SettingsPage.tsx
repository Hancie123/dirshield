import { useEffect, useState } from "react";
import { ColorRegular, FolderOpenRegular, KeyRegular, ArrowSyncRegular, PlayCircleRegular, TimerRegular, WindowRegular, LockShieldRegular, KeyResetRegular, GlobeRegular, SaveRegular, HistoryRegular, ShieldCheckmarkRegular } from "@fluentui/react-icons";
import { api, errMsg, type Settings } from "@/api";
import { setThemePreference, useStore } from "@/app/store";
import { FluentButton, FluentDialog, FluentSelect, FluentToggle, SectionHeader, SettingsRow, useNotify } from "@/components/fluent";
import { pickBackupDestination } from "@/features/recovery/backupFiles";
import { NewRecoveryKeyDialog } from "@/features/recovery/components/NewRecoveryKeyDialog";
import { PortableVaultsDialog } from "@/features/recovery/components/PortableVaultsDialog";
import { RestoreBackupForm } from "@/features/recovery/components/RestoreBackupForm";
import { ChangeMasterDialog } from "@/features/settings/ChangeMasterDialog";
import { formatDate } from "@/lib/format";

export function SettingsPage() {
  const { info } = useStore();
  const notify = useNotify();
  const [s, setS] = useState<Settings | null>(null);
  const [pwOpen, setPwOpen] = useState(false);
  const [rkOpen, setRkOpen] = useState(false);
  const [portable, setPortable] = useState<boolean | null>(null);
  const [restoreOpen, setRestoreOpen] = useState(false);
  const [backingUp, setBackingUp] = useState(false);
  const { refresh, refreshInfo } = useStore();
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
      <SettingsRow icon={<ColorRegular />} title="App theme">
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
      <SettingsRow icon={<KeyRegular />} title="Master password">
        <FluentButton onClick={() => setPwOpen(true)}>Change</FluentButton>
      </SettingsRow>
      <SettingsRow icon={<TimerRegular />} title="Lock DirShield after inactivity">
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
      <SettingsRow icon={<LockShieldRegular />} title="Sign out when Windows locks or sleeps">
        <FluentToggle label="Sign out on lock" checked={s.signOutOnLock} onChange={(signOutOnLock) => save({ ...s, signOutOnLock })} />
      </SettingsRow>
      <SettingsRow icon={<KeyResetRegular />} title="Recovery key">
        <FluentButton onClick={() => setRkOpen(true)}>Create new key…</FluentButton>
      </SettingsRow>
      <SettingsRow
        icon={<GlobeRegular />}
        title="Open vaults on another PC with the master password"
      >
        <FluentToggle label="Portable vaults" checked={s.portableVaults} onChange={(v) => setPortable(v)} />
      </SettingsRow>
      <SettingsRow icon={<ShieldCheckmarkRegular />} title="Check vault integrity automatically">
        <FluentSelect
          label="Integrity checks"
          value={s.verifyIntervalDays}
          onChange={(verifyIntervalDays) => save({ ...s, verifyIntervalDays })}
          options={[
            { value: 7, label: "Every week" },
            { value: 30, label: "Every month" },
            { value: 90, label: "Every 3 months" },
            { value: 0, label: "Off" },
          ]}
        />
      </SettingsRow>

      <SectionHeader>Backup</SectionHeader>
      <SettingsRow
        icon={<SaveRegular />}
        title="Back up DirShield's data"
        description={s.lastBackupAt ? `Last backup: ${formatDate(s.lastBackupAt)}` : "No backup yet"}
      >
        <FluentButton
          disabled={backingUp}
          onClick={async () => {
            const dest = await pickBackupDestination();
            if (!dest) return;
            setBackingUp(true);
            try {
              const p = await api.backupCreate(dest);
              notify({ severity: "success", title: "Backup saved", message: p });
              setS(await api.getSettings());
            } catch (e) {
              notify({ severity: "error", title: "Backup failed", message: errMsg(e) });
            } finally {
              setBackingUp(false);
            }
          }}
        >
          {backingUp ? "Backing up…" : "Back up…"}
        </FluentButton>
      </SettingsRow>
      <SettingsRow icon={<HistoryRegular />} title="Restore from a backup">
        <FluentButton onClick={() => setRestoreOpen(true)}>Restore…</FluentButton>
      </SettingsRow>

      <SectionHeader>Windows integration</SectionHeader>
      <SettingsRow
        icon={<WindowRegular />}
        title="File Explorer context menu"
        description={s.contextMenu && !s.contextMenuCurrent ? "Registered, but pointing to a different copy of DirShield. Turn off and on to repair." : undefined}
      >
        <FluentToggle label="Context menu" checked={s.contextMenu} onChange={(contextMenu) => save({ ...s, contextMenu })} />
      </SettingsRow>
      <SettingsRow icon={<PlayCircleRegular />} title="Start DirShield when I sign in to Windows">
        <FluentToggle label="Launch at startup" checked={s.launchAtStartup} onChange={(launchAtStartup) => save({ ...s, launchAtStartup })} />
      </SettingsRow>

      <SectionHeader>Storage and performance</SectionHeader>
      <SettingsRow icon={<ArrowSyncRegular />} title="Files processed in parallel">
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
      {rkOpen && <NewRecoveryKeyDialog onClose={() => setRkOpen(false)} />}
      {portable != null && (
        <PortableVaultsDialog
          enable={portable}
          onClose={() => setPortable(null)}
          onDone={async () => {
            setPortable(null);
            setS(await api.getSettings());
          }}
        />
      )}
      {restoreOpen && (
        <FluentDialog open title="Restore from a backup" width={580} onClose={() => setRestoreOpen(false)}>
          <RestoreBackupForm
            signedIn
            onCancel={() => setRestoreOpen(false)}
            onDone={async () => {
              setRestoreOpen(false);
              notify({ severity: "success", title: "Restored from backup" });
              await refreshInfo();
              await refresh();
              setS(await api.getSettings());
            }}
          />
        </FluentDialog>
      )}
    </div>
  );
}
