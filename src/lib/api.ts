// Typed wrappers over the Rust commands. Keys never come back from the backend;
// passwords are sent once per command and not stored in the frontend.
import { invoke } from "@tauri-apps/api/core";

export interface AppError {
  code: string;
  message: string;
}

export function errMsg(e: unknown): string {
  if (e && typeof e === "object" && "message" in e) return String((e as AppError).message);
  return String(e);
}
export function errCode(e: unknown): string {
  if (e && typeof e === "object" && "code" in e) return String((e as AppError).code);
  return "unknown";
}

export interface AppInfo {
  initialized: boolean;
  unlocked: boolean;
  lockoutMs: number;
  mica: boolean;
  windowsBuild: number;
  accent: string | null;
  version: string;
  dataDir: string;
  defaultVaultRoot: string;
}

export type ProtectionMode = "quick" | "secure";
export type KeyMode = "master" | "password";
export type VaultStatus =
  | "quick_locked"
  | "quick_visible"
  | "encrypting"
  | "incomplete"
  | "encrypted"
  | "removing"
  | "locked"
  | "restoring"
  | "restored";

export interface VaultInfo {
  id: string;
  name: string;
  originalPath: string;
  vaultPath: string;
  mode: ProtectionMode;
  keyMode: KeyMode;
  status: VaultStatus;
  sizeBytes: number;
  fileCount: number;
  skippedCount: number;
  lockedAt: number | null;
  createdAt: number;
  hidden: boolean | null;
  moved: boolean | null;
  busy: boolean;
}

export interface VaultDetails extends VaultInfo {
  wrappers: string[];
  algorithm: string | null;
  chunkSize: number | null;
  sealed: boolean | null;
  currentPath: string | null;
  formatVersion: number | null;
}

export interface ScanReport {
  path: string;
  name: string;
  totalFiles: number;
  totalDirs: number;
  totalBytes: number;
  largestFile: number;
  links: number;
  linkSamples: string[];
  inaccessible: number;
  inaccessibleSamples: string[];
  estimatedVaultBytes: number;
  driveType: string;
  sourceFreeBytes: number;
}

export interface Progress {
  id: string;
  vaultId: string;
  opType: OpType;
  status: "running" | "paused";
  phase: string;
  current: string;
  processedBytes: number;
  totalBytes: number;
  processedFiles: number;
  totalFiles: number;
  failedFiles: number;
  speedBps: number;
  etaSecs: number | null;
  elapsedSecs: number;
}

export type OpType = "encrypt" | "decrypt" | "verify" | "cleanup";
export type OpStatus = "running" | "paused" | "interrupted" | "failed" | "cancelled" | "completed";

export interface OperationInfo {
  id: string;
  vaultId: string;
  vaultName: string;
  opType: OpType;
  status: OpStatus;
  totalBytes: number;
  processedBytes: number;
  totalFiles: number;
  processedFiles: number;
  failedFiles: number;
  error: string | null;
  params: string | null;
  createdAt: number;
  updatedAt: number;
  live: Progress | null;
}

export interface ItemError {
  path: string;
  error: string;
}

export interface Activity {
  id: number;
  action: string;
  vaultId: string | null;
  vaultName: string | null;
  status: string;
  detail: string | null;
  createdAt: number;
}

export interface Settings {
  theme: "system" | "light" | "dark";
  autoLockMinutes: number;
  concurrency: number;
  defaultVaultRoot: string;
  contextMenu: boolean;
  contextMenuCurrent: boolean;
  launchAtStartup: boolean;
}

export interface PromptInfo {
  action: "lock" | "quick-lock" | "secure-lock" | "unlock" | "unhide" | "settings" | "uninstall";
  path: string;
  name: string;
  vault: { keyMode: "master" | "password"; hidden: boolean } | null;
}

export interface ShellAction {
  action: "lock" | "quick-lock" | "secure-lock" | "unlock" | "unhide" | "settings";
  path: string | null;
}

export interface Orphan {
  id: string;
  storedPath: string;
  originalPath: string | null;
  lockedAt: number | null;
}

export type CredentialKind = "master" | "folder" | "recovery";
export interface Credential {
  kind: CredentialKind;
  secret: string;
}
export interface PasswordStrength {
  /** 0 (too guessable) ... 4 (very unguessable), zxcvbn */
  score: number;
  warning: string | null;
  suggestions: string[];
}
export type ConflictPolicy = "fail" | "skip" | "rename";

export const api = {
  appInfo: () => invoke<AppInfo>("app_info"),
  setupMaster: (password: string, confirm: string) => invoke<string>("setup_master", { password, confirm }),
  login: (password: string) => invoke<void>("login", { password }),
  logout: () => invoke<void>("logout"),
  touch: () => invoke<void>("touch"),
  passwordStrength: (password: string) => invoke<PasswordStrength>("password_strength", { password }),
  changeMasterPassword: (current: string, newPassword: string) => invoke<void>("change_master_password", { current, newPassword }),
  resetMasterPassword: (recoveryKey: string, newPassword: string) => invoke<void>("reset_master_password", { recoveryKey, newPassword }),

  scanFolder: (path: string) => invoke<ScanReport>("scan_folder", { path }),
  freeSpace: (path: string) => invoke<number>("free_space", { path }),
  listVaults: () => invoke<VaultInfo[]>("list_vaults"),
  findByPath: (path: string) => invoke<VaultInfo | null>("find_by_path", { path }),
  vaultDetails: (id: string) => invoke<VaultDetails>("vault_details", { id }),

  quickLock: (path: string, password: string, folderPassword: string | null, hide: boolean) => invoke<VaultInfo>("quick_lock", { path, password, folderPassword, hide }),
  quickUnlock: (id: string, credential: Credential, dest: string | null) => invoke<string>("quick_unlock", { id, credential, dest }),
  quickSetHidden: (id: string, hidden: boolean, credential: Credential) => invoke<void>("quick_set_hidden", { id, hidden, credential }),

  secureLock: (path: string, password: string, folderPassword: string | null, vaultRoot: string | null) =>
    invoke<string>("secure_lock", { path, password, folderPassword, vaultRoot }),
  restoreVault: (id: string, credential: Credential, dest: string | null, conflict: ConflictPolicy) => invoke<string>("restore_vault", { id, credential, dest, conflict }),
  verifyVault: (id: string, credential: Credential) => invoke<string>("verify_vault", { id, credential }),
  removeOriginals: (id: string, credential: Credential, confirmName: string) => invoke<string>("remove_originals", { id, credential, confirmName }),
  deleteVault: (id: string, credential: Credential, confirmName: string) => invoke<void>("delete_vault", { id, credential, confirmName }),
  changeFolderPassword: (id: string, credential: Credential, newMode: KeyMode, newPassword: string | null) =>
    invoke<void>("change_folder_password", { id, credential, newMode, newPassword }),
  importVault: (path: string, recoveryKey: string) => invoke<VaultInfo>("import_vault", { path, recoveryKey }),

  findOrphans: () => invoke<Orphan[]>("find_orphans"),
  recoverOrphan: (id: string, password: string, dest: string | null) => invoke<string>("recover_orphan", { id, password, dest }),

  listOperations: () => invoke<OperationInfo[]>("list_operations"),
  opErrors: (id: string) => invoke<ItemError[]>("op_errors", { id }),
  opPause: (id: string, paused: boolean) => invoke<void>("op_pause", { id, paused }),
  opCancel: (id: string) => invoke<void>("op_cancel", { id }),
  opResume: (id: string, credential: Credential, mode: "resume" | "retry" | "skip") => invoke<void>("op_resume", { id, credential, mode }),
  opDiscard: (id: string) => invoke<void>("op_discard", { id }),
  clearFinishedOperations: () => invoke<void>("clear_finished_operations"),

  listActivity: (limit: number) => invoke<Activity[]>("list_activity", { limit }),
  clearActivity: () => invoke<void>("clear_activity"),
  getSettings: () => invoke<Settings>("get_settings"),
  saveSettings: (settings: Settings) => invoke<void>("save_settings", { settings }),
  takePendingAction: () => invoke<ShellAction | null>("take_pending_action"),
  promptInfo: () => invoke<PromptInfo>("prompt_info"),
  promptSubmit: (password: string) => invoke<string>("prompt_submit", { password }),
  promptOpenMain: () => invoke<void>("prompt_open_main"),
  promptClose: () => invoke<void>("prompt_close"),
  setWindowMode: (full: boolean, width?: number, height?: number) => invoke<void>("set_window_mode", { full, width, height }),
  openInExplorer: (path: string) => invoke<void>("open_in_explorer", { path }),
};
