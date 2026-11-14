import { FingerprintRegular } from "@fluentui/react-icons";
import { type Credential, type CredentialKind, type KeyMode } from "@/api";
import { useStore } from "@/app/store";
import { FluentPasswordInput } from "@/components/fluent";

export function defaultKind(keyMode: KeyMode): CredentialKind {
  return keyMode === "password" ? "folder" : "master";
}

/** Windows Hello is turned on for DirShield and usable on this PC. */
export function useHelloEnabled(): boolean {
  const { info } = useStore();
  return !!info?.hello && !!info?.helloAvailable;
}

/** The credential can be submitted (Windows Hello needs no typed secret). */
export function credReady(c: Credential): boolean {
  return c.kind === "hello" || c.secret.length > 0;
}

/** Shown in place of a password field while Windows Hello is selected. */
export function HelloNote({ onUsePassword }: { onUsePassword: () => void }) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-3 rounded-md border border-[var(--stroke-card)] px-3 py-2.5">
        <FingerprintRegular fontSize={22} className="text-[var(--accent)] shrink-0" />
        <span className="t-body">Windows Hello will ask you to verify it's you when you continue.</span>
      </div>
      <button type="button" className="self-start text-[13px] text-[var(--accent-text)] hover:underline" onClick={onUsePassword}>
        Use the master password instead
      </button>
    </div>
  );
}

/** Password / recovery-key / Windows Hello entry for unlocking a protected folder. */
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
  const hello = useHelloEnabled() && keyMode === "master";
  if (value.kind === "hello") return <HelloNote onUsePassword={() => onChange({ kind: "master", secret: "" })} />;
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
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        {hello && value.kind === "master" && (
          <button type="button" className="text-[13px] text-[var(--accent-text)] hover:underline" onClick={() => onChange({ kind: "hello", secret: "" })}>
            Use Windows Hello instead
          </button>
        )}
        {allowRecovery && (
          <button type="button" className="text-[13px] text-[var(--accent-text)] hover:underline" onClick={() => onChange({ kind: recovery ? defaultKind(keyMode) : "recovery", secret: "" })}>
            {recovery ? (keyMode === "password" ? "Use the folder password instead" : "Use the master password instead") : "Use recovery key instead"}
          </button>
        )}
      </div>
    </div>
  );
}
