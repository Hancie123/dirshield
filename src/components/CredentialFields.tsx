import { type Credential, type CredentialKind, type KeyMode } from "@/api";
import { FluentPasswordInput } from "@/components/fluent";

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
