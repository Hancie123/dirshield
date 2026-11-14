// Errors from the backend arrive as `{ code, message }` (see
// src-tauri/src/domain/error.rs).

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
