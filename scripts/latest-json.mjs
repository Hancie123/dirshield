#!/usr/bin/env node
// Builds latest.json, the manifest tauri-plugin-updater reads from
// https://github.com/<repo>/releases/latest/download/latest.json
//
// Usage: node scripts/latest-json.mjs <artifacts-dir> <version> <owner/repo> > latest.json
//
// Each updatable bundle (NSIS .exe, .AppImage) must have a matching .sig file
// produced by `tauri build` with TAURI_SIGNING_PRIVATE_KEY set.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";

const [dir, version, repo] = process.argv.slice(2);
if (!dir || !version || !repo) {
  console.error("usage: latest-json.mjs <artifacts-dir> <version> <owner/repo>");
  process.exit(2);
}

const walk = (d) => readdirSync(d).flatMap((n) => (statSync(join(d, n)).isDirectory() ? walk(join(d, n)) : [join(d, n)]));
const files = walk(dir);

const targets = [
  { platform: "windows-x86_64", match: (f) => f.endsWith("-setup.exe") },
  { platform: "linux-x86_64", match: (f) => f.endsWith(".AppImage") },
];

const platforms = {};
for (const t of targets) {
  const bundle = files.find(t.match);
  if (!bundle) continue;
  const sig = files.find((f) => f === `${bundle}.sig`);
  if (!sig) {
    console.error(`missing signature for ${basename(bundle)}; is TAURI_SIGNING_PRIVATE_KEY set?`);
    process.exit(1);
  }
  platforms[t.platform] = {
    signature: readFileSync(sig, "utf8").trim(),
    url: `https://github.com/${repo}/releases/download/v${version}/${encodeURIComponent(basename(bundle))}`,
  };
}
if (!platforms["windows-x86_64"]) {
  console.error("no signed Windows installer found");
  process.exit(1);
}

process.stdout.write(
  JSON.stringify({ version, notes: `See https://github.com/${repo}/releases/tag/v${version}`, pub_date: new Date().toISOString(), platforms }, null, 2) + "\n",
);
