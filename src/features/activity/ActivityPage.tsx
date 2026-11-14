import { useEffect, useState } from "react";
import { DeleteRegular, ArrowSyncRegular, ShieldCheckmarkRegular } from "@fluentui/react-icons";
import { api, errMsg, type Activity, type LogCheck } from "@/api";
import { Badge, FluentButton, FluentDialog, FluentTable, InfoBar } from "@/components/fluent";
import { actionLabel, formatDate } from "@/lib/format";

export function ActivityPage() {
  const [rows, setRows] = useState<Activity[]>([]);
  const [confirm, setConfirm] = useState(false);
  const [check, setCheck] = useState<LogCheck | null>(null);
  const [checkErr, setCheckErr] = useState<string | null>(null);
  const load = () => api.listActivity(500).then(setRows).catch(() => {});
  useEffect(() => {
    load();
  }, []);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex justify-end gap-2">
        <FluentButton
          variant="subtle"
          icon={<ShieldCheckmarkRegular />}
          onClick={() => {
            setCheckErr(null);
            api.verifyActivityLog().then(setCheck).catch((e) => setCheckErr(errMsg(e)));
          }}
        >
          Check for tampering
        </FluentButton>
        <FluentButton variant="subtle" icon={<ArrowSyncRegular />} onClick={load}>
          Refresh
        </FluentButton>
        <FluentButton variant="subtle" icon={<DeleteRegular />} disabled={!rows.length} onClick={() => setConfirm(true)}>
          Clear history
        </FluentButton>
      </div>
      {checkErr && <InfoBar severity="error">{checkErr}</InfoBar>}
      {check &&
        (check.ok ? (
          <InfoBar severity="success" title="The log is intact.">
            {check.entries} entr{check.entries === 1 ? "y" : "ies"} checked; none were changed or removed.
            {check.unchained > 0 && ` ${check.unchained} older entr${check.unchained === 1 ? "y" : "ies"} from before this check existed can't be verified.`}
          </InfoBar>
        ) : (
          <InfoBar severity="error" title="The log has been tampered with.">
            <ul className="list-disc pl-5">
              {check.problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </InfoBar>
        ))}
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
          This removes the activity log only. Protected folders aren't affected. A note that the history was cleared stays in the log.
        </FluentDialog>
      )}
    </div>
  );
}
