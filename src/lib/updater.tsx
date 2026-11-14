import { useCallback, useEffect, useState } from "react";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { FluentButton, InfoBar } from "../components/fluent";
import { useStore } from "./store";

// Updates are fetched from GitHub Releases (latest.json) and verified against
// the public key in tauri.conf.json before anything is installed: a tampered
// or unsigned installer is rejected by the updater plugin.

type State =
  | { kind: "idle" }
  | { kind: "checking" }
  | { kind: "none" }
  | { kind: "available"; update: Update }
  | { kind: "installing"; pct: number | null }
  | { kind: "error"; message: string };

let shared: State = { kind: "idle" };
const listeners = new Set<(s: State) => void>();
const set = (s: State) => {
  shared = s;
  listeners.forEach((l) => l(s));
};
let autoChecked = false;

async function runCheck() {
  if (shared.kind === "checking" || shared.kind === "installing") return;
  set({ kind: "checking" });
  try {
    const u = await check();
    set(u ? { kind: "available", update: u } : { kind: "none" });
  } catch (e) {
    set({ kind: "error", message: String(e) });
  }
}

export function useUpdater() {
  const [s, setS] = useState<State>(shared);
  useEffect(() => {
    listeners.add(setS);
    return () => void listeners.delete(setS);
  }, []);
  const install = useCallback(async () => {
    if (shared.kind !== "available") return;
    const u = shared.update;
    let total = 0;
    let got = 0;
    set({ kind: "installing", pct: null });
    try {
      await u.downloadAndInstall((ev) => {
        if (ev.event === "Started") total = ev.data.contentLength ?? 0;
        if (ev.event === "Progress") {
          got += ev.data.chunkLength;
          set({ kind: "installing", pct: total ? Math.round((got / total) * 100) : null });
        }
      });
      await relaunch();
    } catch (e) {
      set({ kind: "error", message: String(e) });
    }
  }, []);
  return { state: s, check: runCheck, install };
}

/** One quiet check per app start; failures (offline etc.) are silent. */
export function useAutoUpdateCheck() {
  useEffect(() => {
    if (autoChecked) return;
    autoChecked = true;
    const t = setTimeout(() => {
      runCheck().then(() => {
        if (shared.kind === "error") set({ kind: "idle" });
      });
    }, 5000);
    return () => clearTimeout(t);
  }, []);
}

export function UpdateBanner() {
  const { state, install } = useUpdater();
  const { ops } = useStore();
  const busy = ops.some((o) => o.live);
  if (state.kind === "available")
    return (
      <div className="mb-5">
        <InfoBar
          title={`DirShield ${state.update.version} is available`}
          action={
            <FluentButton variant="accent" disabled={busy} onClick={install}>
              Install and restart
            </FluentButton>
          }
        >
          {busy ? "Wait for running operations to finish before installing." : "It may include security fixes. Installing takes a few seconds."}
        </InfoBar>
      </div>
    );
  if (state.kind === "installing")
    return (
      <div className="mb-5">
        <InfoBar title="Installing update">{state.pct != null ? `Downloading… ${state.pct}%` : "Downloading…"}</InfoBar>
      </div>
    );
  return null;
}
