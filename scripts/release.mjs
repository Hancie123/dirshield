#!/usr/bin/env node
// Release DirShield: set the version everywhere, commit, and push.
// GitHub Actions then builds the Windows and Linux installers and publishes
// the GitHub Release "DirShield v<version>" (see .github/workflows/build.yml).
//
// Usage:
//   yarn release patch          1.0.0 -> 1.0.1
//   yarn release minor          1.0.0 -> 1.1.0
//   yarn release major          1.0.0 -> 2.0.0
//   yarn release 1.4.2          exact version
//   add --dry-run to only show what would happen

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const bump = args.find((a) => !a.startsWith("--"));

const fail = (msg) => {
  console.error(`\n✖ ${msg}`);
  process.exit(1);
};
const git = (...a) => execFileSync("git", a, { cwd: root, encoding: "utf8" }).trim();
const tryGit = (...a) => {
  try {
    return git(...a);
  } catch {
    return null;
  }
};

if (!bump) fail("Give a version: yarn release patch | minor | major | 1.2.3");

// --- work out the new version -------------------------------------------
const files = {
  tauri: join(root, "src-tauri", "tauri.conf.json"),
  pkg: join(root, "package.json"),
  cargo: join(root, "src-tauri", "Cargo.toml"),
  lock: join(root, "src-tauri", "Cargo.lock"),
};
const read = (f) => readFileSync(f, "utf8");
const current = JSON.parse(read(files.tauri)).version;
const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;
const m = current.match(SEMVER);
if (!m) fail(`Current version "${current}" in tauri.conf.json isn't x.y.z.`);
const [maj, min, pat] = m.slice(1).map(Number);
const next =
  bump === "patch" ? `${maj}.${min}.${pat + 1}` :
  bump === "minor" ? `${maj}.${min + 1}.0` :
  bump === "major" ? `${maj + 1}.0.0` :
  normalize(bump);
if (!SEMVER.test(next)) fail(`"${bump}" isn't patch, minor, major or a version like 1.2.3.`);
const [nMaj, nMin, nPat] = next.split(".").map(Number);
if (nMaj * 1e8 + nMin * 1e4 + nPat < maj * 1e8 + min * 1e4 + pat) fail(`${next} is lower than the current version ${current}.`);
const tag = `v${next}`;

/** "v1" → "1.0.0", "1.2" → "1.2.0", "1.2.3" unchanged. */
function normalize(v) {
  const parts = v.replace(/^v/i, "").split(".");
  if (parts.length > 3 || parts.some((p) => !/^\d+$/.test(p))) return v;
  while (parts.length < 3) parts.push("0");
  return parts.map(Number).join(".");
}

// --- safety checks -------------------------------------------------------
const branch = git("rev-parse", "--abbrev-ref", "HEAD");
if (branch !== "master") fail(`You're on "${branch}". Releases build from master: git checkout master`);
if (tryGit("rev-parse", "-q", "--verify", `refs/tags/${tag}`)) fail(`${tag} already exists locally. Pick a higher version.`);
if (tryGit("ls-remote", "--tags", "origin", tag)) fail(`${tag} is already released on GitHub. Pick a higher version.`);
tryGit("fetch", "-q", "origin", "master");
const behind = tryGit("rev-list", "--count", "HEAD..origin/master");
if (behind && behind !== "0") fail(`Your master is ${behind} commit(s) behind GitHub. Run: git pull`);

const dirty = execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trimEnd();
console.log(next === current ? `\nDirShield ${next} (first release of this version)` : `\nDirShield ${current} → ${next}`);
if (dirty) {
  console.log("\nUncommitted changes that will be included in the release commit:");
  console.log(dirty.split("\n").map((l) => `  ${l}`).join("\n"));
}
if (dryRun) {
  console.log(`\n(dry run) Would set ${next} in tauri.conf.json, package.json, Cargo.toml, Cargo.lock, commit "Release ${tag}" and push.`);
  process.exit(0);
}
const rl = createInterface({ input: process.stdin, output: process.stdout });
const answer = (await rl.question(`\nRelease ${tag} and push to GitHub? (y/N) `)).trim().toLowerCase();
rl.close();
if (answer !== "y" && answer !== "yes") fail("Cancelled. Nothing was changed.");

// --- write the version (format-preserving edits) ---------------------------
const replaceOnce = (file, re, to, what) => {
  const s = read(file);
  if (!re.test(s)) fail(`Couldn't find the version in ${what}.`);
  writeFileSync(file, s.replace(re, to));
};
replaceOnce(files.tauri, /("version"\s*:\s*")[^"]+(")/, `$1${next}$2`, "tauri.conf.json");
replaceOnce(files.pkg, /("version"\s*:\s*")[^"]+(")/, `$1${next}$2`, "package.json");
replaceOnce(files.cargo, /^(version\s*=\s*")[^"]+(")/m, `$1${next}$2`, "Cargo.toml");
replaceOnce(files.lock, /(name = "dirshield"\r?\nversion = ")[^"]+(")/, `$1${next}$2`, "Cargo.lock");

// --- commit and push -------------------------------------------------------
git("add", "-A");
// --allow-empty: releasing the current version with nothing else changed
// still needs a push to start the build.
git("commit", "--allow-empty", "-m", `Release ${tag}`);
execFileSync("git", ["push", "origin", "master"], { cwd: root, stdio: "inherit" });

const remote = tryGit("remote", "get-url", "origin") ?? "";
const repo = remote.replace(/\.git$/, "").replace(/^git@github\.com:/, "https://github.com/");
console.log(`\n✔ Pushed ${tag}. GitHub is building the installers now.`);
if (repo.startsWith("https://github.com/")) {
  console.log(`  Build progress: ${repo}/actions`);
  console.log(`  Release (when done): ${repo}/releases/tag/${tag}`);
}
