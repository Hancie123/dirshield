# DirShield

Windows 10/11 folder locker with a native Windows 11 (Fluent) interface.

* **Quick Lock** — instantly hide a folder, move it into a protected store and block access with NTFS permissions. Convenient privacy, explicitly *not* encryption.
* **Secure Lock** — AES-256-GCM encryption of contents, names and structure, streaming in 4 MiB authenticated chunks; scales to hundreds of GB with flat memory use. Journaled, resumable after crashes, verified before anything is reported done; originals are removed only on explicit request.
* Master password (Argon2id), optional per-folder passwords, 256-bit recovery key, rate limiting, auto-lock.
* File Explorer right-click menu, Windows Search exclusion, Mica, light/dark, accent colour.
* Fully offline.

```powershell
yarn install
yarn tauri:dev                                        # run
yarn tauri:build                                      # installer
cargo test --manifest-path src-tauri/Cargo.toml       # tests
```

Docs: [Architecture](docs/ARCHITECTURE.md) · [Vault format](docs/VAULT_FORMAT.md) · [Windows integration](docs/WINDOWS_INTEGRATION.md) · [Install & build](docs/INSTALL.md) · [User guide](docs/USER_GUIDE.md)

Not in v1.0: Windows 11 top-level (IExplorerCommand) menu entries (classic menu is used), and mounting vaults as a virtual drive (WinFsp) — see docs/WINDOWS_INTEGRATION.md.
