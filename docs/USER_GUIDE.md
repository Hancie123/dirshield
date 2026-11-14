# DirShield user guide

## First start

1. Create a **master password** (at least 8 characters; longer is better).
2. Save the **recovery key** shown next — print it or store it in a password manager. It's the only way back in if you forget the master password. If you lose both, encrypted data can't be recovered by anyone.

DirShield locks itself after inactivity (Settings → Security). Encryption and restore keep running while it's locked.

## Two kinds of protection

| | Quick Lock | Secure Lock |
|---|---|---|
| How | Hides the folder, moves it into DirShield's store (same drive), blocks access with Windows permissions | Encrypts contents, names and structure (AES-256-GCM) |
| Speed | Instant | Proportional to size |
| Protects against | People using your Windows account casually, Explorer browsing and search | Anyone without your password or recovery key, including disk theft |
| Doesn't protect against | Administrators, another OS, removing the disk | Malware running while you have the folder unlocked |

## Locking a folder

* **In DirShield:** Home → Secure Lock or Quick Lock → choose a folder.
* **In File Explorer:** right-click a folder → DirShield → Quick Lock / Secure Lock (Windows 11: *Show more options* first).

For Secure Lock you'll see the size, file count, the space the vault needs, and any links or unreadable files. You can use your master password or give the folder its own password. Encryption runs in the background; you can pause, resume or cancel it, and it continues after a restart.

When it finishes, your **original folder is still there**. Choose *Remove originals* to delete the unencrypted copy (type the folder name to confirm). Only files that are exactly as they were encrypted are deleted; anything changed or added since stays. Note: on SSDs, deleted data can remain physically recoverable with forensic tools.

## Unlocking

* **Quick Lock:** Protected folders → Unlock. The folder goes back to where it was (or a location you choose; existing folders are never overwritten).
* **Secure Lock:** Protected folders → Unlock (restore folder). DirShield verifies every file before putting it in place. If files already exist at the destination, choose: stop, skip existing, or keep both (restored copy gets “(restored)” in its name). Afterwards you can delete the encrypted copy.
* **Unhide** (Quick Lock only) makes a folder visible again but it stays locked.

## If something goes wrong

* **App closed or PC crashed during encryption:** Active operations shows it as *Interrupted*. Resume continues where it stopped; Discard deletes only the incomplete encrypted copy. Originals are never modified by an unfinished encryption.
* **A file is in use:** the operation stops with the list of failed files. Close the program and choose Retry, or Exclude failed (those files stay unencrypted in the original folder).
* **Forgot a folder password:** Recovery → Unlock a folder with the recovery key.
* **Forgot the master password:** on the sign-in screen choose *Forgot your password?* and enter the recovery key.
* **Reinstalled Windows / lost DirShield's database:** Recovery → Import an existing vault (select the vault folder, enter the recovery key). Quick-Locked folders without a record appear on the Recovery page so you can return them.
* **Too many wrong passwords:** DirShield waits 30 seconds, then longer, before allowing another try.

## Good to know

* Windows Search exclusion is a privacy aid; results indexed before locking may take time to disappear, and backups or cloud-sync copies made earlier are not affected.
* Vaults live in `%LOCALAPPDATA%\DirShield\Vaults` by default; you can pick another drive per folder or in Settings (useful for very large folders or external drives).
* Uninstalling DirShield never deletes your vaults or locked folders.
