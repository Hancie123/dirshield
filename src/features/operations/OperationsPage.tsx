import { useState } from "react";
import { ArrowClockwiseRegular, DeleteRegular, DismissRegular, ErrorCircleRegular, PauseRegular, PlayRegular, SkipForwardTabRegular } from "@fluentui/react-icons";
import { api, errMsg, type OperationInfo } from "@/api";
import { useStore } from "@/app/store";
import { Badge, FluentButton, FluentCard, FluentDialog, FluentProgressBar, FluentSkeleton, InfoBar, SectionHeader, useNotify } from "@/components/fluent";
import { formatBytes, formatCount, formatDuration, opStatusLabel, opTone, opTypeLabel, relativeTime } from "@/lib/format";

function OpCard({ o, onDiscard }: { o: OperationInfo; onDiscard: (o: OperationInfo) => void }) {
  const { live, openDialog, refresh } = useStore();
  const notify = useNotify();
  const p = live[o.id] ?? o.live;
  const processed = p?.processedBytes ?? o.processedBytes;
  const total = p?.totalBytes ?? o.totalBytes;
  const frac = total > 0 ? processed / total : null;
  const status = p ? p.status : o.status;
  const resumable = !p && (o.opType === "encrypt" || o.opType === "decrypt") && ["interrupted", "failed", "cancelled"].includes(o.status);
  const run = (f: () => Promise<void>) =>
    f()
      .then(refresh)
      .catch((e) => notify({ severity: "error", title: "Action failed", message: errMsg(e) }));

  return (
    <FluentCard className="px-5 py-4">
      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="t-body-strong truncate">
              {opTypeLabel[o.opType]} · {o.vaultName}
            </span>
            <Badge tone={opTone(status)}>{opStatusLabel[status]}</Badge>
          </div>
          <div className="t-caption text-[var(--text-2)] mt-0.5">
            Started {relativeTime(o.createdAt)}
            {p?.phase ? ` · ${p.phase}` : ""}
          </div>
        </div>
        <div className="flex gap-1 flex-wrap justify-end">
          {p && (
            <>
              <FluentButton icon={p.status === "paused" ? <PlayRegular /> : <PauseRegular />} onClick={() => run(() => api.opPause(o.id, p.status !== "paused"))}>
                {p.status === "paused" ? "Resume" : "Pause"}
              </FluentButton>
              <FluentButton icon={<DismissRegular />} onClick={() => run(() => api.opCancel(o.id))}>
                Cancel
              </FluentButton>
            </>
          )}
          {resumable && (
            <>
              <FluentButton variant="accent" icon={<PlayRegular />} onClick={() => openDialog({ kind: "resume", op: o, mode: o.failedFiles > 0 ? "retry" : "resume" })}>
                {o.failedFiles > 0 ? "Retry" : "Resume"}
              </FluentButton>
              {o.failedFiles > 0 && o.opType === "encrypt" && (
                <FluentButton icon={<SkipForwardTabRegular />} onClick={() => openDialog({ kind: "resume", op: o, mode: "skip" })}>
                  Exclude failed
                </FluentButton>
              )}
              <FluentButton icon={<DeleteRegular />} onClick={() => onDiscard(o)}>
                Discard
              </FluentButton>
            </>
          )}
          {!p && (o.error || o.failedFiles > 0) && (
            <FluentButton variant="subtle" icon={<ErrorCircleRegular />} onClick={() => openDialog({ kind: "errors", op: o })}>
              Details
            </FluentButton>
          )}
        </div>
      </div>
      {(p || o.status !== "completed") && <FluentProgressBar className="mt-4" value={p && total === 0 ? null : frac} paused={status === "paused"} error={o.status === "failed" || o.status === "interrupted"} />}
      <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-[13px] text-[var(--text-2)] tabular-nums">
        <span>
          {formatBytes(processed)} of {formatBytes(total)}
          {frac != null && ` (${Math.floor(frac * 100)}%)`}
        </span>
        <span>
          {formatCount(p?.processedFiles ?? o.processedFiles)} of {formatCount(p?.totalFiles ?? o.totalFiles)} files
        </span>
        {p && p.status === "running" && <span>{formatBytes(p.speedBps)}/s</span>}
        {p && p.status === "running" && <span>{formatDuration(p.etaSecs)} left</span>}
        {(p?.failedFiles ?? o.failedFiles) > 0 && <span className="text-[var(--critical)]">{formatCount(p?.failedFiles ?? o.failedFiles)} failed</span>}
      </div>
      {p?.current && <div className="t-caption text-[var(--text-3)] mt-1 truncate selectable">{p.current}</div>}
      {!p && o.error && (
        <div className="mt-3">
          <InfoBar severity={o.status === "cancelled" ? "warning" : "error"}>{o.error}</InfoBar>
        </div>
      )}
    </FluentCard>
  );
}

/** Placeholder for an operation card while the list loads. */
function OpCardSkeleton() {
  return (
    <FluentCard className="px-5 py-4 flex flex-col gap-3">
      <div className="flex items-center gap-3">
        <FluentSkeleton width="40%" height={14} />
        <FluentSkeleton width={72} height={18} className="ml-auto" />
      </div>
      <FluentSkeleton height={3} />
      <FluentSkeleton width="55%" />
    </FluentCard>
  );
}

export function OperationsPage() {
  const { ops, loaded, refresh } = useStore();
  const notify = useNotify();
  const [discard, setDiscard] = useState<OperationInfo | null>(null);
  const active = ops.filter((o) => o.live);
  const attention = ops.filter((o) => !o.live && o.status !== "completed");
  const done = ops.filter((o) => !o.live && o.status === "completed");

  return (
    <div className="flex flex-col gap-2">
      <div className="flex justify-end">
        <FluentButton variant="subtle" icon={<ArrowClockwiseRegular />} onClick={refresh}>
          Refresh
        </FluentButton>
      </div>
      <SectionHeader>Active</SectionHeader>
      {!loaded ? (
        <OpCardSkeleton />
      ) : active.length === 0 ? <div className="text-[var(--text-2)] px-1">Nothing is running right now.</div> : active.map((o) => <OpCard key={o.id} o={o} onDiscard={setDiscard} />)}
      {attention.length > 0 && (
        <>
          <SectionHeader>Needs attention</SectionHeader>
          <p className="t-caption text-[var(--text-2)] -mt-1 mb-1">Interrupted operations are recovered automatically after a restart or crash. Original folders are never modified by an unfinished encryption.</p>
          {attention.map((o) => (
            <OpCard key={o.id} o={o} onDiscard={setDiscard} />
          ))}
        </>
      )}
      <SectionHeader>Completed</SectionHeader>
      {!loaded ? (
        <>
          <OpCardSkeleton />
          <OpCardSkeleton />
        </>
      ) : done.length === 0 ? <div className="text-[var(--text-2)] px-1">No completed operations.</div> : done.slice(0, 30).map((o) => <OpCard key={o.id} o={o} onDiscard={setDiscard} />)}
      {done.length > 0 && (
        <div>
          <FluentButton variant="subtle" onClick={() => api.clearFinishedOperations().then(refresh)}>
            Clear completed
          </FluentButton>
        </div>
      )}
      {discard && (
        <FluentDialog
          open
          title="Discard this operation?"
          onClose={() => setDiscard(null)}
          footer={
            <>
              <FluentButton
                variant="accent"
                onClick={() =>
                  api
                    .opDiscard(discard.id)
                    .then(() => {
                      setDiscard(null);
                      refresh();
                    })
                    .catch((e) => notify({ severity: "error", title: "Couldn't discard", message: errMsg(e) }))
                }
              >
                Discard
              </FluentButton>
              <FluentButton onClick={() => setDiscard(null)}>Cancel</FluentButton>
            </>
          }
        >
          {discard.opType === "encrypt"
            ? "The incomplete encrypted output will be deleted. Your original folder hasn't been changed and stays exactly as it is."
            : "The restore will be stopped. Files already restored and verified stay at the destination; the vault is unchanged."}
        </FluentDialog>
      )}
    </div>
  );
}
