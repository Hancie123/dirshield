# DirShield — project instructions

Windows 10/11 x64 folder locker. Tauri 2 + React 19 + TypeScript + Vite + Tailwind v4 (frontend), Rust (backend), SQLite (rusqlite, bundled). Package manager: **Yarn 1**. Fully offline; no MCP server, no AI integration, no network calls.

## Commands
- `yarn tauri:dev` — run the app (Vite on :1420 + debug Rust build)
- `yarn tauri:build` — release exe + NSIS installer → `src-tauri/target/release/bundle/nsis/`
- `yarn typecheck` / `yarn build` — frontend typecheck / production bundle
- `cargo test --manifest-path src-tauri/Cargo.toml` — all Rust unit + integration tests (must stay green)
- `DIRSHIELD_DATA_DIR=<dir>` — run against an isolated data dir (DB, vaults, Quick Lock store). **Always use this when testing**; never test destructive flows on real user folders.
- `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222` — expose the WebView over CDP for scripted UI checks.

## Layout
- `src-tauri/src/crypto.rs` — AES-256-GCM wrap, Argon2id, HKDF, HMAC, X25519 recovery escrow, recovery-key encoding
- `src-tauri/src/vault/` — `stream.rs` (chunked STREAM blob format), `header.rs` (vault.dsv), `manifest.rs` (encrypted JSON-lines manifest), `scan.rs`, `engine.rs` (journaled encrypt/decrypt/verify/remove-originals)
- `src-tauri/src/auth.rs` — master key hierarchy, rate limiting, session/auto-lock
- `src-tauri/src/quicklock.rs`, `winsec.rs` (deny ACE), `search.rs` (Windows Search), `shell.rs` (HKCU context menu, autostart, accent)
- `src-tauri/src/ops.rs` — background operation threads + progress events; `commands.rs` — the Tauri command surface; `app.rs` — state, data dirs, crash reconciliation
- `src/components/fluent/` — Fluent component library (use these; don't add another UI kit)
- `src/pages/`, `src/dialogs/`, `src/lib/{api,store,format}.ts(x)`
- `docs/` — ARCHITECTURE, VAULT_FORMAT, WINDOWS_INTEGRATION, INSTALL, USER_GUIDE

## Non-negotiable rules
1. Never delete or overwrite user files silently. Originals are removed only by the explicit "Remove originals" action, only for files whose size+mtime match the verified manifest. Restores never overwrite (policies: fail / skip / rename).
2. A vault is "complete" only when its header is rewritten with `sealed = true` (the atomic commit point) after every item was encrypted, flushed, re-read and verified and the manifest verified. Never report an unsealed vault as locked.
3. Never load whole files/folders into memory. Streaming only (1 MiB reads, 4 MiB chunks), bounded worker pool, bounded channels.
4. Never reuse an AES-GCM nonce: each blob has a fresh random file id → its own HKDF key; nonces are chunk counters. Re-encrypting a file always creates a new blob.
5. No plaintext passwords or keys in SQLite, logs, errors or the frontend. Names/paths in SQLite are encrypted with the MK-derived metadata key. Use `Zeroizing` for secrets.
6. Use RustCrypto/dalek crates only; never hand-roll primitives.
7. Quick Lock is not encryption — UI copy must always say so. Keep it recoverable: owner retains WRITE_DAC; never change owners or strip allow ACEs.
8. Don't claim secure deletion on SSDs, guaranteed search-index removal, or virtual-drive support (not implemented; WinFsp needed).
9. Every security-relevant change needs tests in `src-tauri/tests/` or module tests. Build and run tests after each change.
10. UI follows Windows 11 Fluent (Settings-style NavigationView, settings cards, ContentDialog, Mica). No generic SaaS dashboards, gradients or neon.
11. Changing the on-disk format requires bumping `FORMAT_VERSION`/`BLOB_VERSION` and keeping readers for old versions.

## Gotchas
- Tauri sync commands run on the main thread — every command here is `async` and uses `run()` (spawn_blocking).
- Paths: `fsutil::normalize` for user input, `fsutil::wide` (\\?\ verbatim) for direct Win32 calls; Rust std handles long paths itself.
- Locking anything under `%USERPROFILE%\AppData` (including %TEMP%) is refused by design — put test fixtures elsewhere or use the engine tests.
- Moved Quick-Lock folders have a `<id>.dirshield-quick.json` sidecar in the store so they can be returned if the DB is lost (Recovery page → orphaned folders).
