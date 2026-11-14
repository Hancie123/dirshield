import type { SyncReport } from "@/api";

/** Summary of a vault header update, for a notification. */
export function syncSummary(r: SyncReport): string {
  const parts: string[] = [];
  if (r.deferred) parts.push("Vaults will be updated once the running operations finish.");
  else if (r.updated) parts.push(`${r.updated} vault(s) updated.`);
  if (r.pending.length) parts.push(`Not updated yet: ${r.pending.join(", ")}. Folders with their own password update when you change their password; others when their storage is available.`);
  return parts.join(" ") || "Nothing to update.";
}
