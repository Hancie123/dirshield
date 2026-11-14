import { useEffect, useState } from "react";
import { api, type ItemError, type OperationInfo } from "@/api";
import { useStore } from "@/app/store";
import { FluentButton, FluentDialog, FluentSpinner, InfoBar } from "@/components/fluent";

export function ErrorsDialog({ op }: { op: OperationInfo }) {
  const { closeDialog } = useStore();
  const [items, setItems] = useState<ItemError[] | null>(null);
  useEffect(() => {
    api.opErrors(op.id).then(setItems).catch(() => setItems([]));
  }, [op.id]);
  return (
    <FluentDialog open title="Error details" width={680} onClose={closeDialog} footer={<FluentButton onClick={closeDialog}>Close</FluentButton>}>
      {op.error && (
        <div className="mb-3">
          <InfoBar severity="error">{op.error}</InfoBar>
        </div>
      )}
      {items == null ? (
        <FluentSpinner />
      ) : items.length === 0 ? (
        <p className="text-[var(--text-2)]">No individual file errors were recorded.</p>
      ) : (
        <div className="max-h-[360px] overflow-y-auto rounded-[4px] border border-[var(--stroke-card)] selectable">
          {items.map((it, i) => (
            <div key={i} className="px-3 py-2 border-b border-[var(--stroke-divider)] last:border-0">
              <div className="text-[13px] break-all">{it.path}</div>
              <div className="t-caption text-[var(--critical)]">{it.error}</div>
            </div>
          ))}
        </div>
      )}
    </FluentDialog>
  );
}
