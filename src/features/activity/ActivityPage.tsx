import { useCallback, useEffect, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { ArrowDownloadRegular, ArrowSyncRegular, ChevronLeftRegular, ChevronRightRegular, DeleteRegular, ShieldCheckmarkRegular } from "@fluentui/react-icons";
import { api, errMsg, type Activity, type ActivityFacets, type ActivityFilter, type LogCheck } from "@/api";
import { Badge, FluentButton, FluentDialog, FluentSelect, FluentTable, InfoBar, useNotify } from "@/components/fluent";
import { actionLabel, actionLabelMap, activityStatusLabel, activityTone, formatCount, formatDate } from "@/lib/format";

const PAGE_SIZE = 50;

/** Folder filter as a select value: "" all, "removed", or "id:<vault id>". */
function folderFilter(v: string): Pick<ActivityFilter, "vaultId" | "removed"> {
  if (v === "removed") return { vaultId: null, removed: true };
  if (v.startsWith("id:")) return { vaultId: v.slice(3), removed: false };
  return { vaultId: null, removed: false };
}

export function ActivityPage() {
  const notify = useNotify();
  const [rows, setRows] = useState<Activity[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [action, setAction] = useState("");
  const [folder, setFolder] = useState("");
  const [facets, setFacets] = useState<ActivityFacets | null>(null);
  const [exporting, setExporting] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [check, setCheck] = useState<LogCheck | null>(null);
  const [checkErr, setCheckErr] = useState<string | null>(null);

  const filter: ActivityFilter = { action: action || null, ...folderFilter(folder) };
  const filterKey = JSON.stringify(filter);
  const filtered = !!action || !!folder;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const load = useCallback(() => {
    setLoading(true);
    api
      .listActivity(JSON.parse(filterKey) as ActivityFilter, page * PAGE_SIZE, PAGE_SIZE)
      .then((r) => {
        setRows(r.rows);
        setTotal(r.total);
        // Entries were cleared or the filter shrank the list: go to the last page.
        if (page > 0 && r.rows.length === 0 && r.total > 0) setPage(Math.ceil(r.total / PAGE_SIZE) - 1);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [filterKey, page]);

  const loadFacets = () => api.activityFacets().then(setFacets).catch(() => {});

  useEffect(load, [load]);
  useEffect(() => {
    loadFacets();
  }, []);

  const refresh = () => {
    load();
    loadFacets();
  };

  const exportCsv = async () => {
    const day = new Date().toISOString().slice(0, 10);
    const dest = await save({ title: "Export activity", defaultPath: `DirShield activity ${day}.csv`, filters: [{ name: "CSV file", extensions: ["csv"] }] });
    if (!dest) return;
    setExporting(true);
    try {
      const n = await api.exportActivityCsv(dest, filter, actionLabelMap());
      notify({ severity: "success", title: "Activity exported", message: `${formatCount(n)} entr${n === 1 ? "y" : "ies"} saved to ${dest}` });
      refresh(); // the export itself is logged
    } catch (e) {
      notify({ severity: "error", title: "Couldn't export the activity", message: errMsg(e) });
    } finally {
      setExporting(false);
    }
  };

  // Labels sorted as shown; codes stay the values.
  const actionOptions = [{ value: "", label: "All actions" }, ...(facets?.actions ?? []).map((a) => ({ value: a, label: actionLabel(a) })).sort((a, b) => a.label.localeCompare(b.label))];
  if (action && !actionOptions.some((o) => o.value === action)) actionOptions.push({ value: action, label: actionLabel(action) });
  const folderOptions = [
    { value: "", label: "All folders" },
    ...(facets?.folders ?? []).map((f) => ({ value: `id:${f.id}`, label: f.name })),
    ...(facets?.hasRemoved ? [{ value: "removed", label: "Folders no longer protected" }] : []),
  ];
  const from = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const to = Math.min(total, (page + 1) * PAGE_SIZE);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <FluentSelect
          label="Filter by action"
          value={action}
          options={actionOptions}
          onChange={(v) => {
            setAction(v);
            setPage(0);
          }}
        />
        <FluentSelect
          label="Filter by folder"
          value={folder}
          options={folderOptions}
          onChange={(v) => {
            setFolder(v);
            setPage(0);
          }}
        />
        {filtered && (
          <FluentButton
            variant="subtle"
            onClick={() => {
              setAction("");
              setFolder("");
              setPage(0);
            }}
          >
            Clear filters
          </FluentButton>
        )}
        <div className="flex-1" />
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
        <FluentButton variant="subtle" icon={<ArrowDownloadRegular />} disabled={!total || exporting} onClick={exportCsv}>
          {exporting ? "Exporting…" : filtered ? "Export filtered (CSV)" : "Export CSV"}
        </FluentButton>
        <FluentButton variant="subtle" icon={<ArrowSyncRegular />} onClick={refresh}>
          Refresh
        </FluentButton>
        <FluentButton variant="subtle" icon={<DeleteRegular />} disabled={!total && !filtered} onClick={() => setConfirm(true)}>
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
        loading={loading && rows.length === 0}
        skeletonRows={8}
        rowKey={(r) => String(r.id)}
        empty={filtered ? "No activity matches these filters." : "No activity recorded."}
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
                <Badge tone={activityTone(r.status)}>{activityStatusLabel(r.status)}</Badge>
                {r.detail && r.status !== "success" && <span className="t-caption text-[var(--text-2)] truncate">{r.detail}</span>}
              </span>
            ),
          },
        ]}
      />
      {total > 0 && (
        <div className={`flex items-center justify-end gap-2 ${loading ? "opacity-60" : ""}`}>
          <span className="t-caption text-[var(--text-2)] tabular-nums mr-2">
            {formatCount(from)}–{formatCount(to)} of {formatCount(total)}
          </span>
          <FluentButton variant="subtle" aria-label="Previous page" icon={<ChevronLeftRegular />} disabled={page === 0 || loading} onClick={() => setPage((p) => p - 1)} />
          <span className="t-caption tabular-nums">
            Page {page + 1} of {pages}
          </span>
          <FluentButton variant="subtle" aria-label="Next page" icon={<ChevronRightRegular />} disabled={page >= pages - 1 || loading} onClick={() => setPage((p) => p + 1)} />
        </div>
      )}
      {confirm && (
        <FluentDialog
          open
          title="Clear activity history?"
          onClose={() => setConfirm(false)}
          footer={
            <>
              <FluentButton
                variant="accent"
                onClick={() =>
                  api.clearActivity().then(() => {
                    setConfirm(false);
                    setPage(0);
                    refresh();
                  })
                }
              >
                Clear
              </FluentButton>
              <FluentButton onClick={() => setConfirm(false)}>Cancel</FluentButton>
            </>
          }
        >
          This removes the whole activity log, not just the entries shown. Protected folders aren't affected. A note that the history was cleared stays in the log.
        </FluentDialog>
      )}
    </div>
  );
}
