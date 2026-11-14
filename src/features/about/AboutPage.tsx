import { ArrowDownloadRegular } from "@fluentui/react-icons";
import { useStore } from "@/app/store";
import { FluentButton, FluentCard, SectionHeader, SettingsRow } from "@/components/fluent";
import { useUpdater } from "@/features/updates/updater";

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
