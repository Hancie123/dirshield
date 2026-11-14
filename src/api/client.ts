// Typed wrappers over the Rust commands. Keys never come back from the backend;
// passwords are sent once per command and not stored in the frontend.

import { invoke } from "@tauri-apps/api/core";
import type {
  Activity,
  AppInfo,
  ConflictPolicy,
  Credential,
  ItemError,
  KeyMode,
  LockAllReport,
  LogCheck,
  OperationInfo,
  Orphan,
  PasswordStrength,
  PromptInfo,
  ScanReport,
  Settings,
  ShellAction,
  SyncReport,
  VaultDetails,
  VaultInfo,
} from "./types";

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

  quickLock: (path: string, password: string, folderPassword: string | null, hide: boolean) =>
    invoke<VaultInfo>("quick_lock", { path, credential: { kind: "master", secret: password }, folderPassword, hide }),
  quickUnlock: (id: string, credential: Credential, dest: string | null) => invoke<string>("quick_unlock", { id, credential, dest }),
  quickSetHidden: (id: string, hidden: boolean, credential: Credential) => invoke<void>("quick_set_hidden", { id, hidden, credential }),

  secureLock: (path: string, password: string, folderPassword: string | null, vaultRoot: string | null) =>
    invoke<string>("secure_lock", { path, credential: { kind: "master", secret: password }, folderPassword, vaultRoot }),
  restoreVault: (id: string, credential: Credential, dest: string | null, conflict: ConflictPolicy, workSession = false) =>
    invoke<string>("restore_vault", { id, credential, dest, conflict, workSession }),
  workSessionEnd: (id: string) => invoke<string | null>("work_session_end", { id }),
  workSessionKeep: (id: string) => invoke<void>("work_session_keep", { id }),
  lockAllFolders: () => invoke<LockAllReport>("lock_all_folders"),
  verifyVault: (id: string, credential: Credential) => invoke<string>("verify_vault", { id, credential }),
  removeOriginals: (id: string, credential: Credential, confirmName: string) => invoke<string>("remove_originals", { id, credential, confirmName }),
  deleteVault: (id: string, credential: Credential, confirmName: string) => invoke<void>("delete_vault", { id, credential, confirmName }),
  changeFolderPassword: (id: string, credential: Credential, newMode: KeyMode, newPassword: string | null) =>
    invoke<void>("change_folder_password", { id, credential, newMode, newPassword }),
  importVault: (path: string, credential: Credential) => invoke<VaultInfo>("import_vault", { path, credential }),

  recoveryRotateBegin: (password: string) => invoke<string>("recovery_rotate_begin", { credential: { kind: "master", secret: password } }),
  recoveryRotateCommit: (recoveryKey: string) => invoke<SyncReport>("recovery_rotate_commit", { recoveryKey }),
  recoveryRotateCancel: () => invoke<void>("recovery_rotate_cancel"),
  setPortableVaults: (enabled: boolean, password: string) => invoke<SyncReport>("set_portable_vaults", { enabled, credential: { kind: "master", secret: password } }),
  backupCreate: (dest: string) => invoke<string>("backup_create", { dest }),
  backupRestore: (path: string, credential: Credential) => invoke<void>("backup_restore", { path, credential }),

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
  verifyActivityLog: () => invoke<LogCheck>("verify_activity_log"),
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
