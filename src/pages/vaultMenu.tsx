import {
  DeleteRegular,
  EyeOffRegular,
  EyeRegular,
  FolderOpenRegular,
  InfoRegular,
  KeyRegular,
  LockOpenRegular,
  ShieldCheckmarkRegular,
  DocumentDismissRegular,
} from "@fluentui/react-icons";
import type { VaultInfo } from "../lib/api";
import { api } from "../lib/api";
import type { MenuItem } from "../components/fluent";
import type { DialogState } from "../lib/store";

/** Actions available for a protected folder, in context-menu order. */
export function vaultMenuItems(v: VaultInfo, open: (d: DialogState) => void): MenuItem[] {
  const busy = v.busy;
  const secureReady = v.mode === "secure" && ["encrypted", "locked", "restored"].includes(v.status);
  const items: MenuItem[] = [];
  if (v.mode === "quick") {
    items.push({ key: "unlock", label: "Unlock", icon: <LockOpenRegular />, onClick: () => open({ kind: "unlock", vault: v }), disabled: busy });
    items.push(
      v.hidden
        ? { key: "unhide", label: "Unhide (stay locked)", icon: <EyeRegular />, onClick: () => open({ kind: "visibility", vault: v, hidden: false }) }
        : { key: "hide", label: "Hide", icon: <EyeOffRegular />, onClick: () => open({ kind: "visibility", vault: v, hidden: true }) },
    );
  } else {
    items.push({ key: "restore", label: v.status === "restored" ? "Restore again…" : "Unlock (restore folder)", icon: <LockOpenRegular />, onClick: () => open({ kind: "unlock", vault: v }), disabled: busy || !secureReady });
    if (v.status === "encrypted") items.push({ key: "originals", label: "Remove originals…", icon: <DocumentDismissRegular />, onClick: () => open({ kind: "removeOriginals", vault: v }), disabled: busy });
    items.push({ key: "verify", label: "Check integrity", icon: <ShieldCheckmarkRegular />, onClick: () => open({ kind: "verify", vault: v }), disabled: busy || !secureReady });
  }
  items.push({ key: "pw", label: "Change password…", icon: <KeyRegular />, onClick: () => open({ kind: "changePassword", vault: v }), disabled: busy || (v.mode === "secure" && v.status === "incomplete") });
  if (v.status === "restored") items.push({ key: "openr", label: "Open restored folder", icon: <FolderOpenRegular />, onClick: () => api.openInExplorer(v.originalPath).catch(() => {}) });
  items.push({ key: "details", label: "Details", icon: <InfoRegular />, onClick: () => open({ kind: "details", vault: v }) });
  if (v.mode === "secure") {
    items.push({ key: "sep", separator: true });
    items.push({ key: "delete", label: "Delete vault…", icon: <DeleteRegular />, danger: true, onClick: () => open({ kind: "delete", vault: v }), disabled: busy || v.status === "incomplete" });
  }
  return items;
}
