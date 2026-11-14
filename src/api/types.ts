// Types exchanged with the Rust backend. Field names match the serde
// (camelCase) output of src-tauri/src/commands.

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
  restoredPath: string | null;
  /** Restored for a work session: locked again when DirShield signs out or Windows locks. */
  workSession: boolean;
}

export interface VaultDetails extends VaultInfo {
  wrappers: string[];
  algorithm: string | null;
  chunkSize: number | null;
  sealed: boolean | null;
  currentPath: string | null;
  formatVersion: number | null;
  /** Escrowed to the current recovery key. */
  recoveryCurrent: boolean | null;
  /** Can be opened on another PC with the master password. */
  portable: boolean | null;
  lastVerifiedAt: number | null;
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

export type OpType = "encrypt" | "decrypt" | "verify" | "cleanup" | "relock" | "extract";

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
  signOutOnLock: boolean;
  /** Days between scheduled integrity checks; 0 = off. */
  verifyIntervalDays: number;
  /** Read-only: change with setPortableVaults. */
  portableVaults: boolean;
  /** Read-only. */
  lastBackupAt: number | null;
}

export interface SyncReport {
  updated: number;
  pending: string[];
  deferred: boolean;
}

export interface LockAllReport {
  hidden: number;
  relocking: number;
  skipped: string[];
}

export interface LogCheck {
  ok: boolean;
  entries: number;
  unchained: number;
  sealedThrough: number;
  problems: string[];
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
