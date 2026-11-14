import { useEffect, useState } from "react";
import { PauseRegular, PlayRegular, DismissRegular } from "@fluentui/react-icons";
import { type OperationInfo, type Progress, api, errMsg } from "@/api";
import { useStore } from "@/app/store";
import { FluentButton, FluentProgressBar, InfoBar } from "@/components/fluent";
import { formatBytes, formatCount, formatDuration } from "@/lib/format";

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
