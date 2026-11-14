import { useState } from "react";
import { CopyRegular } from "@fluentui/react-icons";
import { FluentButton } from "@/components/fluent";

/** The recovery key in a selectable box, with a Copy button. */
export function RecoveryKeyBox({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex flex-col gap-2">
      <div className="rounded-[6px] border border-[var(--stroke-card)] bg-[var(--fill-control)] p-4 font-mono text-[15px] tracking-wide text-center selectable break-all">{value}</div>
      <div className="flex justify-end">
        <FluentButton
          icon={<CopyRegular />}
          onClick={async () => {
            await navigator.clipboard.writeText(value);
            setCopied(true);
          }}
        >
          {copied ? "Copied" : "Copy"}
        </FluentButton>
      </div>
    </div>
  );
}
