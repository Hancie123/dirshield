# DirShield architecture

## Overview

```
React UI (WebView2)  ──invoke──▶  Tauri commands (commands.rs, async + spawn_blocking)
      ▲                                 │
      │ events: op-progress,            ├── auth.rs      master key, recovery, session, rate limit
      │ ops-changed, vaults-changed,    ├── quicklock.rs + winsec.rs + search.rs
      │ session-locked, shell-action    ├── vault/engine.rs  (journaled operations)
      │                                 ├── ops.rs       background threads + progress ticker
      └─────────────────────────────────┤── shell.rs     context menu / autostart / accent
                                        └── db.rs        SQLite (WAL, synchronous=FULL, migrations)
```

The frontend never sees a key. Passwords travel once per command and are zeroized after use.

## Key hierarchy

```
master password ─Argon2id(64 MiB, t=3, p=4, salt)─▶ KEK_pw ─AES-GCM─▶ MK (256-bit random)
recovery key (256-bit) ─HKDF─▶ KEK_rec ─AES-GCM─▶ MK
recovery key ─HKDF(salt)─▶ X25519 secret;  public key stored  ──▶ escrow of every vault key
MK ─AES-GCM─▶ vault key (master mode)        folder password ─Argon2id─▶ vault key (password mode)
MK ─HKDF─▶ metadata key (encrypts folder names / paths in SQLite)
```

* Changing the master password re-wraps MK only — no vault is touched.
* Changing a folder password rewrites only that vault's small header.
* Every vault header carries a recovery escrow (X25519 + HKDF + AES-GCM) including its salt, so a vault directory plus the recovery key is self-sufficient even if the database is lost ("Import a vault").

## Secure Lock pipeline (engine.rs)

1. **Scan** (`scan.rs`): counts, size, links/junctions (never followed), unreadable items, estimated vault size, free space.
2. **Create** (`create_secure_vault`): vault dir + unsealed header; DB rows; the full item list is written to `operation_journal` in batches (resumability); free-space check — failure rolls everything back.
3. **Run** (`run_encrypt`): bounded worker pool (default 2, max 8). Per file: stream 1 MiB reads → `BlobWriter` (4 MiB chunks) → temp file → fsync → re-check the source's size/mtime (changed → retry once) → re-read and authenticate every chunk, compare SHA-256 → rename into `objects/`. Journal row marked `done`.
4. **Errors** (locked file, access denied) mark the item `error`; the op ends *failed*, originals untouched. The user may retry or explicitly exclude failed items. Disk-full aborts immediately.
5. **Finalize**: sweep temp/orphan objects, stream the manifest from the journal, verify it and every object size, then atomically rewrite the header with `sealed = true` (**commit point**), then update the DB and purge the journal's plaintext paths.
6. **Remove originals** (separate, explicit, typed confirmation): deletes only manifest files whose size + mtime still match; then empty directories bottom-up.

Restore (`prepare_decrypt` / `run_decrypt`) verifies header MAC, manifest, existence and exact size of every object before writing anything; then decrypts to `~dirshield-<op>-<item>.tmp`, verifies the checksum, re-reads from disk to verify again, sets mtime, and renames with a **no-replace** move. Conflicts follow the chosen policy (fail / skip / rename); nothing is ever overwritten.

## Crash recovery (`app::reconcile`)

On start-up, running/paused operations become *interrupted*. A vault still marked `encrypting` whose header is sealed is completed (only the DB write was lost); otherwise it becomes `incomplete` and can be resumed (pending items only) or discarded (deletes only the vault directory). Restores resume the same way; temp names are deterministic so partial files are cleaned.

## Quick Lock

1. If the folder is on the same volume as the store, write a sidecar (`<id>.dirshield-quick.json`), then atomic rename into `%LOCALAPPDATA%\DirShield\QuickStore\<id>` (never a cross-volume copy).
2. Hidden + System + Not-content-indexed attributes.
3. One explicit inheritable deny ACE for Everyone (read/list/traverse/write/delete). Owner keeps WRITE_DAC, so removal never needs admin.
4. Best-effort Windows Search crawl-scope exclusion for in-place locks.

Each step rolls back the previous ones on failure. Unlock reverses them and refuses if anything already exists at the destination.

## Data locations

| What | Where |
|---|---|
| Database | `%LOCALAPPDATA%\DirShield\data\dirshield.db` |
| Vaults (default) | `%LOCALAPPDATA%\DirShield\Vaults\<vault id>` (configurable per lock / in Settings) |
| Quick Lock store | `%LOCALAPPDATA%\DirShield\QuickStore\<id>` |

The uninstaller never touches `%LOCALAPPDATA%\DirShield`.

## Concurrency and memory

* Per worker: one 1 MiB read buffer, one 4 MiB chunk buffer (+ tag), two 4 MiB decrypt buffers when verifying. Default 2 workers ⇒ well under 50 MiB regardless of folder size.
* Journal paging: 1,000 items per query; insert batches of 2,000.
* SQLite in WAL mode with `synchronous=FULL`.

## Tests

`cargo test` runs unit tests (crypto, stream format, manifest path safety, auth, rate limiting, auto-lock, shell argument parsing) and integration tests:

* `tests/vault_engine.rs` — full roundtrip (nested, Unicode, spaces/parentheses, empty dirs/files, read-only, >300-char paths, multi-chunk), no plaintext names/content in the vault, journal purge, wrong password, password re-wrap without re-encryption, recovery escrow, corrupted chunk (nothing partial left), tampered header/manifest, cancelled + crashed encryption resume with orphan sweep, duplicate run refused, cancelled decryption resume, no-overwrite restore policies, selective original removal, empty folder, junctions skipped (target untouched), exclusively-locked file → retry / exclude.
* `tests/quick_lock.rs` — deny ACE blocks list/read-by-full-path/delete; hide/unhide; exact attribute restoration; moved lock refuses to overwrite; orphan recovery without a database.

Performance tests on 10–400 GB datasets are manual (see docs/INSTALL.md → "Large-folder testing"); they require real disks.
