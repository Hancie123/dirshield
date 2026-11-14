import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { PauseRegular, PlayRegular, DismissRegular } from "@fluentui/react-icons";
import type { Credential, CredentialKind, KeyMode, OperationInfo, Progress } from "../lib/api";
import { api, errMsg } from "../lib/api";
import { FluentButton, FluentPasswordInput, FluentProgressBar, InfoBar } from "../components/fluent";
import { formatBytes, formatCount, formatDuration } from "../lib/format";
import { useStore } from "../lib/store";

export async function pickFolder(title: string, defaultPath?: string): Promise<string | null> {
  const r = await open({ directory: true, multiple: false, title, defaultPath });
  return typeof r === "string" ? r : null;
}

export function defaultKind(keyMode: KeyMode): CredentialKind {
  return keyMode === "password" ? "folder" : "master";
}

/** Password / recovery-key entry for unlocking a protected folder. */
export function CredentialFields({
  keyMode,
  value,
  onChange,
  allowRecovery = true,
  error,
  autoFocus = true,
}: {
  keyMode: KeyMode;
  value: Credential;
  onChange: (c: Credential) => void;
  allowRecovery?: boolean;
  error?: string;
  autoFocus?: boolean;
}) {
  const recovery = value.kind === "recovery";
  const label = recovery ? "Recovery key" : value.kind === "folder" ? "Folder password" : "Master password";
  return (
    <div className="flex flex-col gap-2">
      <FluentPasswordInput
        label={label}
        value={value.secret}
        autoFocus={autoFocus}
        data-autofocus
        placeholder={recovery ? "XXXX-XXXX-XXXX-…" : undefined}
        onChange={(e) => onChange({ ...value, secret: e.target.value })}
        error={error}
      />
      {allowRecovery && (
        <button type="button" className="self-start text-[13px] text-[var(--accent-text)] hover:underline" onClick={() => onChange({ kind: recovery ? defaultKind(keyMode) : "recovery", secret: "" })}>
          {recovery ? (keyMode === "password" ? "Use the folder password instead" : "Use the master password instead") : "Use recovery key instead"}
        </button>
      )}
    </div>
  );
}

export function KeyValue({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[150px_1fr] gap-x-4 gap-y-1.5 text-[14px]">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-[var(--text-2)]">{k}</dt>
          <dd className="min-w-0 break-words selectable">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Live progress for one background operation, with pause / resume / cancel. */
export function OperationProgress({ opId, onFinished }: { opId: string; onFinished?: (op: OperationInfo | undefined) => void }) {
  const { live, ops, refresh } = useStore();
  const p: Progress | undefined = live[opId];
  const op = ops.find((o) => o.id === opId);
  const [err, setErr] = useState<string | null>(null);
  const finished = !p && op && !op.live && op.status !== "running" && op.status !== "paused";

  useEffect(() => {
    if (finished) onFinished?.(op);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finished]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const processed = p?.processedBytes ?? op?.processedBytes ?? 0;
  const total = p?.totalBytes ?? op?.totalBytes ?? 0;
  const frac = total > 0 ? processed / total : p ? null : 0;
  const paused = p?.status === "paused";

  const act = async (f: () => Promise<void>) => {
    try {
      setErr(null);
      await f();
      await refresh();
    } catch (e) {
      setErr(errMsg(e));
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-baseline justify-between gap-4">
        <span className="t-body-strong">{paused ? "Paused" : p?.phase || "Starting…"}</span>
        <span className="text-[var(--text-2)] tabular-nums">{frac == null ? "" : `${Math.floor(frac * 100)}%`}</span>
      </div>
      <FluentProgressBar value={p && total === 0 ? null : frac} paused={paused} />
      <div className="t-caption text-[var(--text-2)] truncate selectable" title={p?.current}>
        {p?.current ? p.current : " "}
      </div>
      <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-[13px]">
        <span className="text-[var(--text-2)]">Processed</span>
        <span className="tabular-nums">
          {formatBytes(processed)} of {formatBytes(total)}
        </span>
        <span className="text-[var(--text-2)]">Files</span>
        <span className="tabular-nums">
          {formatCount(p?.processedFiles ?? op?.processedFiles ?? 0)} of {formatCount(p?.totalFiles ?? op?.totalFiles ?? 0)}
          {(p?.failedFiles ?? 0) > 0 && <span className="text-[var(--critical)]"> · {p!.failedFiles} failed</span>}
        </span>
        <span className="text-[var(--text-2)]">Speed</span>
        <span className="tabular-nums">{p && !paused ? `${formatBytes(p.speedBps)}/s` : "—"}</span>
        <span className="text-[var(--text-2)]">Time remaining</span>
        <span className="tabular-nums">{paused ? "Paused" : p ? formatDuration(p.etaSecs) : "—"}</span>
      </div>
      {err && <InfoBar severity="error">{err}</InfoBar>}
      {p && (
        <div className="flex gap-2">
          <FluentButton icon={paused ? <PlayRegular /> : <PauseRegular />} onClick={() => act(() => api.opPause(opId, !paused))}>
            {paused ? "Resume" : "Pause"}
          </FluentButton>
          <FluentButton icon={<DismissRegular />} onClick={() => act(() => api.opCancel(opId))}>
            Cancel
          </FluentButton>
        </div>
      )}
    </div>
  );
}
