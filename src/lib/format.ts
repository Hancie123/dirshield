import { OpStatus, OpType, VaultStatus } from "@/api";

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  const units = ["bytes", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  if (i === 0) return `${n} ${n === 1 ? "byte" : "bytes"}`;
  return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${units[i]}`;
}

export function formatCount(n: number): string {
  return new Intl.NumberFormat().format(n);
}

export function formatDuration(secs: number | null | undefined): string {
  if (secs == null || !Number.isFinite(secs)) return "Calculating…";
  const s = Math.max(0, Math.round(secs));
  if (s < 60) return `${s} sec`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ${s % 60} sec`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} hr ${m % 60} min`;
  return `${Math.floor(h / 24)} days ${h % 24} hr`;
}

export function formatDate(ms: number | null | undefined): string {
  if (!ms) return "—";
  return new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function relativeTime(ms: number): string {
  const d = Date.now() - ms;
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (d < 60_000) return "Just now";
  if (d < 3_600_000) return rtf.format(-Math.round(d / 60_000), "minute");
  if (d < 86_400_000) return rtf.format(-Math.round(d / 3_600_000), "hour");
  if (d < 7 * 86_400_000) return rtf.format(-Math.round(d / 86_400_000), "day");
  return formatDate(ms);
}

export const vaultStatusLabel: Record<VaultStatus, string> = {
  quick_locked: "Locked and hidden",
  quick_visible: "Locked (visible)",
  encrypting: "Encrypting",
  incomplete: "Incomplete",
  encrypted: "Encrypted · originals kept",
  removing: "Removing originals",
  locked: "Encrypted",
  restoring: "Restoring",
  restored: "Restored",
};

export type Tone = "success" | "caution" | "critical" | "neutral" | "accent";

export function vaultTone(s: VaultStatus): Tone {
  switch (s) {
    case "locked":
    case "quick_locked":
      return "success";
    case "encrypted":
    case "quick_visible":
      return "caution";
    case "incomplete":
      return "critical";
    case "encrypting":
    case "restoring":
    case "removing":
      return "accent";
    default:
      return "neutral";
  }
}

export const opTypeLabel: Record<OpType, string> = {
  encrypt: "Encryption",
  decrypt: "Restore",
  verify: "Integrity check",
  cleanup: "Remove originals",
  relock: "Lock again",
  extract: "Extract files",
};

export const opStatusLabel: Record<OpStatus, string> = {
  running: "Running",
  paused: "Paused",
  interrupted: "Interrupted",
  failed: "Failed",
  cancelled: "Cancelled",
  completed: "Completed",
};

export function opTone(s: OpStatus): Tone {
  return s === "completed" ? "success" : s === "failed" || s === "interrupted" ? "critical" : s === "cancelled" || s === "paused" ? "caution" : "accent";
}

const actionLabels: Record<string, string> = {
  setup: "DirShield set up",
  sign_in: "Signed in",
  authentication: "Sign-in or password check",
  auto_lock: "Locked after inactivity",
  quick_lock: "Quick Lock",
  quick_unlock: "Quick Lock removed",
  hide: "Folder hidden",
  unhide: "Folder unhidden",
  secure_lock: "Secure Lock",
  restore: "Folder restored",
  verify_vault: "Integrity check",
  remove_originals: "Originals removed",
  delete_vault: "Vault deleted",
  change_master_password: "Master password changed",
  reset_master_password_with_recovery_key: "Master password reset with recovery key",
  change_folder_password: "Folder password changed",
  import_vault: "Vault imported",
  resume_operation: "Operation resumed",
  discard_operation: "Operation discarded",
  settings_changed: "Settings changed",
  recovered_after_restart: "Recovered after restart",
  recover_orphan: "Orphaned folder returned",
  sign_out: "Signed out",
  sign_in_windows_hello: "Signed in with Windows Hello",
  work_session_start: "Work session started",
  work_session_end: "Work session ended",
  work_session_kept: "Kept unlocked (work session ended)",
  lock_all: "Lock all",
  relock: "Locked again",
  extract: "Files extracted",
  scheduled_verify: "Scheduled integrity check",
  recovery_key_replaced: "New recovery key",
  portable_vaults: "Open on another PC with master password",
  backup_created: "Backup created",
  backup_restored: "Restored from backup",
  activity_cleared: "Activity history cleared",
  activity_exported: "Activity exported",
  quick_lock_reapplied: "Quick Lock put back",
  quick_lock_moved: "Locked folder renamed or moved",
  work_session_recovered: "Work session recovered",
};
/** Every known action label, keyed by action code. */
export function actionLabelMap(): Record<string, string> {
  return { ...actionLabels };
}

/** Activity results as shown to the user (keep in sync with `status_label` in commands/settings.rs). */
const activityStatusLabels: Record<string, string> = {
  success: "Succeeded",
  failed: "Failed",
  cancelled: "Cancelled",
  warning: "Warning",
  info: "Info",
};
export function activityStatusLabel(s: string): string {
  return activityStatusLabels[s] ?? s.charAt(0).toUpperCase() + s.slice(1);
}
export function activityTone(s: string): Tone {
  return s === "success" ? "success" : s === "failed" ? "critical" : s === "cancelled" || s === "warning" ? "caution" : "neutral";
}

export function actionLabel(a: string): string {
  return actionLabels[a] ?? a.replace(/_/g, " ");
}
