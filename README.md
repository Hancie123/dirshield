<div align="center">

<img src="src-tauri/icons/128x128@2x.png" alt="DirShield logo" width="128" height="128" />

# DirShield

**Lock, hide and encrypt folders on Windows and Linux, with a native Windows 11 interface.**

[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?logo=windows&logoColor=white)](#requirements)
[![Linux](https://img.shields.io/badge/Linux-experimental-FCC624?logo=linux&logoColor=black)](#linux-experimental)
[![Built with Tauri](https://img.shields.io/badge/built%20with-Tauri%202-24C8DB?logo=tauri&logoColor=white)](https://tauri.app)
[![Rust](https://img.shields.io/badge/Rust-1.89%2B-000000?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![Version](https://img.shields.io/badge/version-1.1.0-brightgreen)](https://github.com/Hancie123/dirshield/releases)

[Features](#features) · [Security model](#security-model) · [Installation](#installation) · [Building from source](#building-from-source) · [Contributing](#contributing)

</div>

---

## Overview

DirShield is a free, open-source folder locker for Windows 10 and 11, with experimental support for Linux (x64). It has two protection modes:

- **Quick Lock** hides a folder and blocks access to it instantly, whatever its size.
- **Secure Lock** encrypts a folder's contents, file names and directory structure with AES-256-GCM.

DirShield works offline. It has no accounts, no telemetry and no cloud dependency, and your keys never leave your machine. The only network request is the signed update check against GitHub Releases (see [Updates](#updates)).

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

- **File Explorer context menu**: Quick Lock, Secure Lock, Unlock and Unhide from a right-click. It is registered per user, so it needs no admin rights. On Windows 11, releases signed with a code-signing certificate also add DirShield to the top-level menu, so you don't need **Show more options** (see [Windows 11 context menu](#windows-11-context-menu)).
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

**Windows**

- Windows 10 or Windows 11 (x64)
- Microsoft Edge WebView2 runtime. Windows 11 ships with it, and the installer fetches it on Windows 10 if it is missing.

**Linux** (experimental, see [Linux](#linux-experimental))

- A 64-bit (x64) distribution with WebKitGTK 4.1, e.g. Ubuntu 22.04+, Debian 12+, Fedora 39+
- The `.deb` works on Debian and Ubuntu; the `.AppImage` runs on most other distributions

### Download

Download the latest release from the [**Releases**](https://github.com/Hancie123/dirshield/releases) page.

**Windows:** run `DirShield_<version>_x64-setup.exe`. DirShield installs per user and needs no administrator rights.

**Linux:**

```bash
# Debian / Ubuntu
sudo apt install ./DirShield_<version>_amd64.deb

# Any distribution (AppImage, updates itself)
chmod +x DirShield_<version>_amd64.AppImage
./DirShield_<version>_amd64.AppImage
```

### Verifying a download

Every release lists a `SHA256SUMS.txt` file and a signed build-provenance attestation that proves the files were built by this repository's GitHub Actions workflow from the tagged commit.

```powershell
# Checksum (PowerShell): compare with the line in SHA256SUMS.txt
Get-FileHash .\DirShield_<version>_x64-setup.exe -Algorithm SHA256

# Provenance (GitHub CLI)
gh attestation verify .\DirShield_<version>_x64-setup.exe --repo Hancie123/dirshield
```

```bash
# Linux: checks every file you downloaded against SHA256SUMS.txt
sha256sum --check --ignore-missing SHA256SUMS.txt
gh attestation verify DirShield_<version>_amd64.AppImage --repo Hancie123/dirshield
```

### Updates

DirShield checks GitHub Releases for a new version a few seconds after it starts, and you can check by hand under **About → Updates**. Updates are signed with the project's update key. The app checks that signature against the public key built into it and refuses any update that fails the check. An update is never installed while an encryption or restore is still running. The update check is the only network request DirShield makes.

### Linux (experimental)

Releases also include `.deb` and `.AppImage` builds. They run the same code, but DirShield is designed for Windows, and several protections depend on Windows features:

| Feature | Linux |
| --- | --- |
| Secure Lock (AES-256-GCM vaults, recovery key, import, verify) | ✅ Works the same as on Windows. Vaults move between Windows and Linux. |
| Master password, auto-lock, rate limiting, activity log | ✅ Works |
| Auto-update | ✅ AppImage only (`.deb` installs must be updated by hand) |
| Quick Lock | ⚠️ **No real protection.** The folder is only moved into DirShield's data folder. The NTFS deny-ACLs and hidden/system attributes that Quick Lock relies on are not applied. Use Secure Lock instead. |
| File manager context menu, start at sign-in, Windows Search exclusion, Mica | ❌ Windows only |
| Free-space check before encrypting | ❌ Skipped. Make sure the target drive has room. |

### Where your data lives

DirShield keeps its database, Secure Lock vaults and Quick-Locked folders in:

| OS | Location |
| --- | --- |
| Windows | `%LOCALAPPDATA%\DirShield` |
| Linux | `$XDG_DATA_HOME/DirShield` (usually `~/.local/share/DirShield`) |

> [!WARNING]
> **The uninstaller never deletes this folder**, so your protected data survives an uninstall. Reinstall DirShield to unlock it. Unlock your folders before you uninstall if you no longer need them protected.
>
> **Keep your recovery key somewhere safe.** If you lose both your master password and your recovery key, your Secure Lock vaults cannot be recovered.

## Building from source

### Prerequisites

- [Node.js](https://nodejs.org) 20+ and [Yarn](https://yarnpkg.com)
- [Rust](https://rustup.rs) 1.89+
- **Windows:** the MSVC toolchain and the [Tauri 2 prerequisites](https://tauri.app/start/prerequisites/#windows) (Microsoft C++ Build Tools and WebView2)
- **Linux:** the [Tauri 2 prerequisites](https://tauri.app/start/prerequisites/#linux). On Debian / Ubuntu:

  ```bash
  sudo apt install libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf build-essential
  ```

### Commands

```bash
git clone https://github.com/Hancie123/dirshield.git
cd dirshield
yarn install

yarn tauri:dev      # Run the app in development mode
yarn tauri:build    # Build installers: NSIS on Windows, .deb + .AppImage on Linux
                    # (output in src-tauri/target/release/bundle/)
yarn test:rust      # Run the Rust test suite
yarn typecheck      # Type-check the frontend
```

### Project structure

```text
dirshield/
├── src/                         # React + TypeScript frontend (imports use the @/ alias)
│   ├── main.tsx                 # Entry: main window or Explorer password prompt
│   ├── app/                     # App shell (layout, navigation) and global store
│   ├── api/                     # Typed client for the Rust commands: types, errors, client
│   ├── components/
│   │   ├── fluent/              # Fluent UI component library (buttons, dialogs, tables…)
│   │   └── *.tsx                # Shared app components (credentials, progress, strength meter)
│   ├── features/                # One folder per feature: its pages, dialogs and helpers
│   │   ├── auth/                # First-run setup and sign-in
│   │   ├── home/                # Dashboard
│   │   ├── folders/             # Protected folders list, context menu, lock/unlock dialogs
│   │   ├── operations/          # Running and finished operations
│   │   ├── recovery/            # Recovery key, backups, orphaned Quick Lock folders
│   │   ├── activity/            # Activity log
│   │   ├── settings/            # Settings and master password change
│   │   ├── about/               # About and updates
│   │   ├── updates/             # Auto-updater
│   │   └── prompt/              # Small password window opened from Explorer
│   ├── lib/                     # Framework-free helpers (formatting, native pickers)
│   └── styles/                  # Global stylesheet (Tailwind + Fluent tokens)
└── src-tauri/                   # Rust backend (Tauri 2)
    ├── src/
    │   ├── lib.rs               # Entry point and module map
    │   ├── app/                 # State, windows, tray, background operations, uninstall
    │   ├── commands/            # Tauri command surface, one file per area
    │   ├── domain/              # Error type and typed values shared across layers
    │   ├── security/            # Crypto, master key, password rules, session, rate limit, Hello
    │   ├── storage/             # SQLite database and encrypted backups
    │   ├── vault/               # Secure Lock: header, manifest, streaming, scan, browse
    │   │   └── engine/          # Journaled engine: encrypt, relock, restore, verify, cleanup
    │   ├── quicklock/           # Quick Lock, NTFS ACL (acl.rs), locked-folder icon
    │   └── platform/            # Windows integration: fs, Explorer menu, Search, session events
    ├── shell-ext/               # Windows 11 Explorer menu handler (IExplorerCommand DLL)
    ├── tests/                   # Integration tests (vault engine, Quick Lock)
    └── windows/
        ├── hooks.nsh            # Installer hooks
        └── sparse/              # Sparse MSIX manifest for the Windows 11 menu
```

### Windows 11 context menu

Windows 11's top-level right-click menu only shows commands from packaged
`IExplorerCommand` handlers. Registry verbs, which DirShield always installs,
appear under **Show more options**. Windows only registers the package, and
Explorer only loads the handler, when the package is signed by a certificate
the PC trusts. In practice that means a code-signing certificate from a public
CA or Azure Trusted Signing. A self-signed certificate would have to be
installed on every user's PC with admin rights.

The pieces:

| Piece | Location | Role |
| --- | --- | --- |
| Menu handler | `src-tauri/shell-ext/` → `dirshield_shell.dll` | A "DirShield" flyout with the same entries as the classic menu. Each entry runs `dirshield.exe --action <verb> "<folder>"`. |
| Shared spec | `src-tauri/src/platform/menu_spec.rs` | Entries, CLSID and package name, compiled into both the app and the DLL. |
| Sparse package | `src-tauri/windows/sparse/AppxManifest.xml` | Declares the handler. The install folder is its external location. |
| Build script | `scripts/build-sparse-package.ps1` | Builds the DLL, packs and signs the package, and writes a Tauri config that bundles both. |
| Registration | `platform/shell.rs` | Registers the package for the current user (no admin) when the Explorer menu is on, and removes it when the menu is turned off or DirShield is uninstalled. |

To build a release with it, use a `.pfx` code-signing certificate:

```bash
pwsh scripts/build-sparse-package.ps1 -PfxPath codesign.pfx -PfxPassword <password>
yarn tauri build --config src-tauri/target/sparse/tauri.sparse.conf.json
```

In CI, set the `WINDOWS_CERTIFICATE` (the .pfx, base64-encoded) and
`WINDOWS_CERTIFICATE_PASSWORD` secrets. Without them, the installer is built
exactly as before, with the classic menu only.

## Roadmap

Not yet included in v1.0:

- [ ] Signed releases that ship the top-level Windows 11 context menu. The handler and packaging are in place ([details](#windows-11-context-menu)); releases need a code-signing certificate. Until then, DirShield's entries appear under **Show more options**.
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
