import { open, save } from "@tauri-apps/plugin-dialog";

const BACKUP_FILTER = [{ name: "DirShield backup", extensions: ["dsbackup"] }];

export async function pickBackupFile(): Promise<string | null> {
  const r = await open({ multiple: false, directory: false, title: "Choose a DirShield backup", filters: BACKUP_FILTER });
  return typeof r === "string" ? r : null;
}

export async function pickBackupDestination(): Promise<string | null> {
  const day = new Date().toISOString().slice(0, 10);
  return save({ title: "Save DirShield backup", defaultPath: `DirShield backup ${day}.dsbackup`, filters: BACKUP_FILTER });
}
