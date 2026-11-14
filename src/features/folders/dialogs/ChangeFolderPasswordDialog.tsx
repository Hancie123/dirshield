import { useState } from "react";
import { api, type KeyMode, type VaultInfo } from "@/api";
import { StrengthHint } from "@/components/PasswordStrength";
import { FluentPasswordInput, FluentRadio } from "@/components/fluent";
import { AuthDialog } from "@/features/folders/dialogs/AuthDialog";

export function ChangeFolderPasswordDialog({ vault }: { vault: VaultInfo }) {
  const [mode, setMode] = useState<KeyMode>(vault.keyMode);
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const valid = mode === "master" || (pw.length >= 8 && pw === pw2);
  return (
    <AuthDialog
      title="Change folder password"
      vault={vault}
      intro={<p className="text-[var(--text-2)]">Only the key wrapper is replaced — nothing is re-encrypted, even for very large folders.</p>}
      extra={
        <div className="flex flex-col gap-3">
          <FluentRadio
            name="New password"
            value={mode}
            onChange={setMode}
            options={[
              { value: "master", label: "Use my master password" },
              { value: "password", label: "Use a separate password for this folder" },
            ]}
          />
          {mode === "password" && (
            <div className="grid grid-cols-2 gap-3">
              <FluentPasswordInput label="New folder password" value={pw} onChange={(e) => setPw(e.target.value)} hint={<StrengthHint pw={pw} />} />
              <FluentPasswordInput label="Confirm" value={pw2} onChange={(e) => setPw2(e.target.value)} error={pw2 && pw !== pw2 ? "Passwords don't match" : undefined} />
            </div>
          )}
          <div className="h-px bg-[var(--stroke-divider)]" />
          <div className="t-body-strong">Current password</div>
        </div>
      }
      canSubmit={valid}
      confirmLabel="Change password"
      run={(c) => api.changeFolderPassword(vault.id, c, mode, mode === "password" ? pw : null)}
      success="Folder password changed"
    />
  );
}
