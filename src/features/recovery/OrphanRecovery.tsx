import { useEffect, useState } from "react";
import { WarningRegular } from "@fluentui/react-icons";
import { api, errMsg, type Orphan } from "@/api";
import { FluentButton, FluentDialog, FluentPasswordInput, InfoBar, SettingsRow, useNotify } from "@/components/fluent";
import { formatDate } from "@/lib/format";
import { pickFolder } from "@/lib/pickers";

/** Quick-Locked folders still in DirShield's store but missing from its database. */
export function OrphanRecovery() {
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
