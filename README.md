<div align="center">

<img src="src-tauri/icons/128x128@2x.png" alt="DirShield logo" width="128" height="128" />

# DirShield

**Lock, hide and encrypt folders on Windows, with a native Windows 11 interface.**

[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D4?logo=windows&logoColor=white)](#requirements)
[![Built with Tauri](https://img.shields.io/badge/built%20with-Tauri%202-24C8DB?logo=tauri&logoColor=white)](https://tauri.app)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B-000000?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen)](https://github.com/Hancie123/dirshield/releases)

[Features](#features) · [Security model](#security-model) · [Installation](#installation) · [Building from source](#building-from-source) · [Contributing](#contributing)

</div>

---

## Overview

DirShield is a free, open-source folder locker for Windows 10 and 11. It has two protection modes:

- **Quick Lock** hides a folder and blocks access to it instantly, whatever its size.
- **Secure Lock** encrypts a folder's contents, file names and directory structure with AES-256-GCM.

DirShield works fully offline. It has no accounts, no telemetry and no cloud dependency. Your keys never leave your machine.

## Features

### 🔒 Two protection modes

| | **Quick Lock** | **Secure Lock** |
|---|---|---|
| **Purpose** | Fast, convenient privacy | Real cryptographic protection |
| **Speed** | Instant, at any size | Limited by disk throughput |
| **Mechanism** | Atomic move into a protected store, Hidden + System attributes, deny-Everyone NTFS ACE | AES-256-GCM streaming encryption |
| **Protects names and structure** | Hidden only | ✅ Encrypted |
| **Resists admins and offline disk access** | ❌ No | ✅ Yes |

> [!IMPORTANT]
> Quick Lock is **not encryption**. An administrator, another operating system, or anyone with offline access to the disk can bypass it. Use **Secure Lock** for sensitive data.

### 🛡️ Secure Lock engine

- **Built for large data.** Files stream in 4 MiB authenticated chunks, so memory use stays flat for vaults of hundreds of gigabytes.
- **Crash-safe.** Every operation is journaled in SQLite. You can resume or roll back after a crash, a power loss or a cancellation.
- **Verified before done.** A vault is marked sealed only after every file has been encrypted, written, flushed, re-read and verified.
- **Non-destructive by default.** Your original files stay untouched. DirShield deletes them only when you ask, and only after you type the folder's name to confirm.
- **Pause, resume and cancel** long-running operations from the Operations page.

### 🔑 Accounts and keys

- **Master password** protected with Argon2id (64 MiB, 3 iterations, 4 lanes).
- **Optional per-folder passwords** that work independently of the master password.
- **256-bit recovery key** for resetting a forgotten master password and importing vaults on a new machine, even if the DirShield database is lost.
- **Rate limiting** on failed unlock attempts, and **auto-lock** after a configurable idle period.

### 🪟 Windows integration

- **File Explorer context menu**: Quick Lock, Secure Lock, Unlock and Unhide from a right-click. It is registered per user, so it needs no admin rights.
- **Windows Search exclusion** keeps protected content out of search results.
- **Fluent design** with Mica, light and dark themes, and your system accent colour.
- **Optional launch at startup**, with a single running instance.

## Security model

DirShield builds only on audited [RustCrypto](https://github.com/RustCrypto) and [dalek](https://github.com/dalek-cryptography) primitives. **No cryptographic primitive is implemented by hand.**

| Purpose | Primitive |
|---|---|
| Content encryption | AES-256-GCM, [STREAM](https://eprint.iacr.org/2015/189) construction, 4 MiB chunks |
| Password → key | Argon2id |
| Sub-key derivation | HKDF-SHA256 |
| Vault header integrity | HMAC-SHA256 |
| Recovery escrow | X25519 + HKDF sealed box |
| Randomness | OS CSPRNG (`BCryptGenRandom`) |

**Key hierarchy**

```text
master password ──Argon2id──▶ KEK ──AES-GCM──▶ master key (random, 256-bit)
recovery key    ──HKDF─────▶ KEK ──AES-GCM──▶ master key
master key      ──AES-GCM──▶ vault key        (one random key per vault)
vault key       ──HKDF─────▶ per-file key     (one per encrypted blob)
recovery key    ──X25519───▶ every vault key is also escrowed to the recovery key
```

**Properties**

- Each encrypted file gets its own key, derived from the vault key and a random 128-bit file ID.
- Each chunk is authenticated against its vault, its file, its position and whether it is the final chunk. Reordering, swapping, truncating or extending chunks fails verification.
- Plaintext is released only after the chunk's authentication tag verifies.
- The vault header holds no plaintext names or paths, and it is HMAC-protected against tampering.
- Changing the master password re-wraps a single key. No vault needs to be re-encrypted.
- Key material in memory is zeroized when it is no longer needed.

> [!NOTE]
> DirShield has not had an independent security audit. If you find a vulnerability, please report it privately (see [Reporting security issues](#reporting-security-issues)).

## Installation

### Requirements

- Windows 10 or Windows 11 (x64)
- Microsoft Edge WebView2 runtime. Windows 11 ships with it, and the installer fetches it on Windows 10 if it is missing.

### Download

Download the latest installer from the [**Releases**](https://github.com/Hancie123/dirshield/releases) page and run it. DirShield installs per user and needs no administrator rights.

### Where your data lives

DirShield keeps its database, Secure Lock vaults and Quick-Locked folders in:

```text
%LOCALAPPDATA%\DirShield
```

> [!WARNING]
> **The uninstaller never deletes this folder**, so your protected data survives an uninstall. Reinstall DirShield to unlock it. Unlock your folders before you uninstall if you no longer need them protected.
>
> **Keep your recovery key somewhere safe.** If you lose both your master password and your recovery key, your Secure Lock vaults cannot be recovered.

## Building from source

### Prerequisites

- [Node.js](https://nodejs.org) 20+ and [Yarn](https://yarnpkg.com)
- [Rust](https://rustup.rs) 1.80+ (MSVC toolchain)
- [Tauri 2 prerequisites for Windows](https://tauri.app/start/prerequisites/): Microsoft C++ Build Tools and WebView2

### Commands

```powershell
git clone https://github.com/Hancie123/dirshield.git
cd dirshield
yarn install

yarn tauri:dev      # Run the app in development mode
yarn tauri:build    # Build the NSIS installer (src-tauri/target/release/bundle/nsis)
yarn test:rust      # Run the Rust test suite
yarn typecheck      # Type-check the frontend
```

### Project structure

```text
dirshield/
├── src/                     # React + TypeScript frontend
│   ├── components/fluent/   # Fluent UI component library
│   ├── dialogs/             # Lock / unlock / vault dialogs
│   ├── pages/               # Home, Folders, Operations, Settings, Auth
│   └── lib/                 # Tauri API bindings, state store, formatting
└── src-tauri/               # Rust backend (Tauri 2)
    ├── src/
    │   ├── auth.rs          # Master password, recovery key, sessions, rate limiting
    │   ├── crypto.rs        # Cryptographic building blocks
    │   ├── quicklock.rs     # Quick Lock implementation
    │   ├── vault/           # Secure Lock: header, manifest, streaming, journaled engine
    │   ├── winsec.rs        # NTFS ACL handling
    │   ├── shell.rs         # Explorer context menu and startup registration
    │   ├── search.rs        # Windows Search exclusion
    │   └── commands.rs      # Tauri command surface
    ├── tests/               # Integration tests (vault engine, Quick Lock)
    └── windows/hooks.nsh    # Installer hooks
```

## Roadmap

Not yet included in v1.0:

- [ ] Entries in the top-level Windows 11 context menu (`IExplorerCommand`). For now, DirShield's entries appear under **Show more options**.
- [ ] Mounting vaults as a virtual drive (WinFsp) to browse them without restoring.

## Contributing

Contributions are welcome: bug reports, feature ideas, documentation fixes or pull requests.

1. Fork the repository and create a branch: `git checkout -b feature/my-change`
2. Make your changes, then run `yarn typecheck` and `yarn test:rust`.
3. Commit with a clear message and open a pull request that describes what you changed and why.

For large changes, please [open an issue](https://github.com/Hancie123/dirshield/issues) first so we can agree on the approach. Changes to the cryptography or the vault format get extra scrutiny and should include tests.

## Reporting security issues

Please **do not** open a public issue for security vulnerabilities. Report them privately through [GitHub Security Advisories](https://github.com/Hancie123/dirshield/security/advisories/new) instead. You'll get an acknowledgement, and the fix will be coordinated before the issue is made public.

## License

<!-- TODO: add a LICENSE file (e.g. MIT, Apache-2.0 or GPL-3.0) and name it here. -->
License to be announced. See [LICENSE](LICENSE) once it is added.

## Acknowledgements

- [Tauri](https://tauri.app): a lightweight, secure desktop app framework
- [RustCrypto](https://github.com/RustCrypto) and [dalek-cryptography](https://github.com/dalek-cryptography): audited cryptographic primitives
- [Fluent UI System Icons](https://github.com/microsoft/fluentui-system-icons): iconography

<div align="center">

Made with ❤️ by [Hancie123](https://github.com/Hancie123)

</div>
