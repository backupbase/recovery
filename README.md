# backupbase-restore

An open-source command-line tool that restores [Backup Base](https://backupbase.org) backups on any computer, without the Backup Base app.

Source code and releases: https://github.com/backupbase/recovery

## When to use it

The Backup Base app is the normal way to restore: open it, choose Restore, pick a version and the files you want. Restoring in the app needs no license, no subscription and no internet connection, only the backup folder and its passcode.

This tool is for everything else: a computer where the app is not installed or cannot be, Linux, a script, or a time when Backup Base, its website and the app stores no longer exist. It reads the same backup folders, now or in 20 years. It needs only two things:

1. **The backup folder.** The app saves backups into a folder you chose, usually a "Backup Base" folder inside OneDrive, SharePoint or Google Drive. Copy or sync that folder to the computer you are using. If your cloud service keeps files "online-only", make sure they are downloaded.
2. **The passcode** you chose for that backup.

It has no network code: it never connects to anything, and it never changes the backup folder.

It is written from the published format specification ([FORMAT.md](FORMAT.md)) alone and shares no code with the app, so it is a second, independent implementation of the format.

## Download and check it

Download the file for your computer, and `SHA256SUMS`, from the Releases page of this repository (https://github.com/backupbase/recovery/releases) into the same folder:

| Computer | File |
|---|---|
| Mac (macOS 11 or later, Apple silicon and Intel) | `backupbase-restore-<version>-macos` |
| Windows 10 and 11 (64-bit) | `backupbase-restore-<version>-windows.exe` |
| Linux (x86-64, static, any distribution) | `backupbase-restore-<version>-linux` |

Each file is the program itself: there is nothing to unzip or install. The steps below use version 0.1.1 in your Downloads folder; use the version you downloaded.

### 1. Check the download

`SHA256SUMS` lists the SHA-256 of every file in the release. Check yours against it:

```sh
# macOS (Terminal): must say OK for your file
cd ~/Downloads
shasum -a 256 -c SHA256SUMS --ignore-missing
```

```sh
# Linux: must say OK for your file
cd ~/Downloads
sha256sum -c SHA256SUMS --ignore-missing
```

```powershell
# Windows PowerShell: prints True when the file matches
cd $HOME\Downloads
$f = "backupbase-restore-0.1.1-windows.exe"
(Get-FileHash $f -Algorithm SHA256).Hash -eq (Select-String -SimpleMatch $f SHA256SUMS).Line.Split(" ")[0]
```

```bat
:: Windows Command Prompt: compare the result with the line for this file in SHA256SUMS
cd %USERPROFILE%\Downloads
certutil -hashfile backupbase-restore-0.1.1-windows.exe SHA256
findstr windows SHA256SUMS
```

Releases are built from this repository's source by GitHub Actions, and GitHub signs a build provenance attestation for every file. With the [GitHub CLI](https://cli.github.com) you can check that a file was built from this repository and not changed since:

```sh
gh attestation verify backupbase-restore-0.1.1-macos --repo backupbase/recovery
```

(Use the name of the file you downloaded.) Releases are published as immutable releases: once published, their files and tag cannot be changed or replaced, and `gh release verify-asset v0.1.1 backupbase-restore-0.1.1-macos --repo backupbase/recovery` confirms that a file belongs to that release.

### 2. Make it runnable

The files are not signed with an Apple or Microsoft certificate, so the system may block the first run. Check the download first (step 1), then rename it to `backupbase-restore` (`backupbase-restore.exe` on Windows) so the commands below work as written:

- **macOS** (Terminal): rename it, allow it to run, and remove the download flag:

  ```sh
  cd ~/Downloads
  mv backupbase-restore-0.1.1-macos backupbase-restore
  chmod +x backupbase-restore
  xattr -d com.apple.quarantine backupbase-restore
  ```

  (`xattr` says "No such xattr" when there was no flag; that is fine.) Instead of `xattr`, you can Control-click the file in Finder and choose Open (on recent macOS: run it once, then open System Settings, Privacy & Security, and choose Open Anyway).
- **Windows** (PowerShell): rename it and remove the download flag:

  ```powershell
  cd $HOME\Downloads
  Rename-Item backupbase-restore-0.1.1-windows.exe backupbase-restore.exe
  Unblock-File .\backupbase-restore.exe
  ```

  Or rename it in File Explorer; if Windows then shows "Windows protected your PC", choose More info, then Run anyway.
- **Linux**:

  ```sh
  cd ~/Downloads
  mv backupbase-restore-0.1.1-linux backupbase-restore
  chmod +x backupbase-restore
  ```

### Checking a Backup Base app download

This repository also holds [backupbase-release.pub](backupbase-release.pub), the public key that signs every Backup Base release (key ID `61E043145CD8F604`). The same file is published at https://backupbase.org/backupbase-release.pub, and every release of the app has `SHA256SUMS` and `SHA256SUMS.minisig` at `https://backupbase.org/updates/<version>/`. Check them with [minisign](https://jedisct1.github.io/minisign/), using the key from this repository:

```sh
minisign -Vm SHA256SUMS -p backupbase-release.pub
```

The copy here is the one to trust: someone who took over the website could replace the key there together with the files. A key ID alone proves nothing, since anyone can give a key of their own any ID; the key line (`RWQE9thcFEPgYdO98hVePpJ6PbfAtX92Cwlv1+Lqexsy+ogCqEgX6jdG`) must match exactly.

## Use it

Four commands:

| Command | What it does |
|---|---|
| `list <folder>` | The backups in a folder, with their format, when and by which app version they were made, and their versions (date, number of files, size). |
| `files <backup>` | The files, folders and links in one version. |
| `restore <backup> --to <folder>` | Restores one version, or parts of it, into a folder. |
| `verify <backup>` | Decrypts everything a version stores and checks every file, without writing anything. |

`<folder>` is the folder that holds your backups. `<backup>` is one backup inside it (the folder that holds `vault.bbv`), or a folder that holds only one backup. Versions are named by the time they were made, for example `20260925T150000Z-3fa9c2d1` (25 September 2026, 15:00 UTC). Without `--version`, commands use the latest version. Run `backupbase-restore help <command>` for every option.

You are asked for the passcode, and nothing is shown while you type.

### macOS and Linux (Terminal)

```sh
cd ~/Downloads
./backupbase-restore list ~/Library/CloudStorage/OneDrive-Personal/"Backup Base"
./backupbase-restore files ~/Library/CloudStorage/OneDrive-Personal/"Backup Base"/Documents --path Documents/Contracts
./backupbase-restore restore ~/Library/CloudStorage/OneDrive-Personal/"Backup Base"/Documents --to ~/Restored
./backupbase-restore restore ~/Library/CloudStorage/OneDrive-Personal/"Backup Base"/Documents --to ~/Restored-contracts --version 20260925T150000Z --path Documents/Contracts
./backupbase-restore verify ~/Library/CloudStorage/OneDrive-Personal/"Backup Base"/Documents --all
```

### Windows (Command Prompt, cmd.exe)

```bat
cd %USERPROFILE%\Downloads
backupbase-restore list "%USERPROFILE%\OneDrive\Backup Base"
backupbase-restore files "%USERPROFILE%\OneDrive\Backup Base\Documents" --path Documents/Contracts
backupbase-restore restore "%USERPROFILE%\OneDrive\Backup Base\Documents" --to "%USERPROFILE%\Restored"
backupbase-restore verify "%USERPROFILE%\OneDrive\Backup Base\Documents" --all
```

### Windows (PowerShell)

```powershell
cd $HOME\Downloads
.\backupbase-restore.exe list "$HOME\OneDrive\Backup Base"
.\backupbase-restore.exe restore "$HOME\OneDrive\Backup Base\Documents" --to "$HOME\Restored" --path Documents/Contracts --path Documents/Taxes
.\backupbase-restore.exe verify "$HOME\OneDrive\Backup Base\Documents"
```

### Scripts

For scripts, give the passcode in the `BB_PASSCODE` environment variable, or in a file with `--passcode-file <file>` (the first line of the file is the passcode; the file can be UTF-8, or UTF-16 as Windows PowerShell 5.1 writes it with `>` or `Out-File`). Typing it at the prompt is safer: shells can keep a history of commands (PowerShell keeps one on disk), so avoid typing the passcode into a command line.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Done. |
| 1 | An error, for example a disk or permission problem. |
| 2 | Wrong command line, or the target folder is not empty or is in or next to a backup (see below). |
| 3 | Wrong passcode. |
| 4 | No backup, version or path found, or the backup was made by a newer version of the format. |
| 5 | Damage found: some files could not be restored or verified (they are listed), or a version could not be read (`restore` and `files` then use the newest one that can be read, with a warning; `list` shows it under "Ignored"). |
| 6 | The restore finished, but some items were skipped (they are listed). |
| 130 | Stopped with Ctrl+C. |

Symbolic links that are not created (because they point outside the target folder, or on Windows) are listed but do not change the exit code: they are refused on purpose, and on Windows every backup with links would otherwise end in 6.

## What a restore does

- **It never overwrites anything.** The target folder must be new or empty, unless you add `--keep-both`: then existing files stay, a file that already has exactly the restored content is left alone, and other restored files are saved as `name (restored).ext`.
- Files go to `<target>/<backed-up folder name>/...`, for example `~/Restored/Documents/Contracts/nda.pdf`.
- Every file is checked against the SHA-256 recorded when it was backed up before it gets its name, so a restored file is exactly the file that was backed up, or it is not restored and is listed.
- Files get their modification time and read-only setting back, and on macOS and Linux their permissions (setuid, setgid and sticky bits are never restored). Folders get their time and permissions last.
- Symbolic links are created last, and only when they point inside the target folder: a link target may use `..` only at its start, and may not go through a link that was already there. On Windows they are skipped with a note (creating them needs administrator rights or developer mode).
- Paths that are not safe (absolute paths, `..`, empty names) are refused and listed. On Windows, characters Windows does not allow in names (`< > : " | ? *` and `\`) become `_`, a trailing dot or space becomes `_`, and reserved names (CON, PRN, AUX, NUL, COM0 to COM9, LPT0 to LPT9, with or without an extension) are refused; each change is listed.
- Files a version lists without content (the app could not read them when that backup ran, for example a locked or online-only file) cannot be restored from that version. They are listed; an older version may hold them. A copy marked as possibly incomplete (the file changed while it was being read) is restored and listed.
- A damaged backup is restored as far as possible: everything before the damage is restored and the rest is listed.
- It never restores into a backup folder or next to one: not into the backup it reads, not into the folder that holds it (your "Backup Base" folder, with `HOW-TO-RESTORE.txt` and the backups), not into any other folder that holds a `vault.bbv`, not into a folder that holds a backup folder, and not into anything inside those. Such a target is refused with exit code 2. With `--keep-both`, a folder already in the target that is one of these (for example a folder with the same name as the backed-up folder, found where a backup is kept) is skipped with everything that would go in it, and listed, with exit code 6.
- **Restore into a folder outside your cloud folder** (OneDrive, SharePoint, Google Drive): restored files are not encrypted, and the tool cannot know which folders your sync app uploads.
- Without `--version`, when the newest version cannot be read (damaged, or not fully synced yet), the newest version that can be read is used, with a warning, and the exit code is 5, so a script can tell it did not get the newest files.
- While a file is written it is a temporary file named `.bbrestore-<numbers>.tmp` in the same folder (on macOS and Linux readable only by you). Ctrl+C stops the restore: the temporary file is removed, files already restored are complete, and the exit code is 130. A second Ctrl+C stops at once (for example while an online-only file is still downloading) and leaves the temporary file behind. If the tool ends any other way halfway (a crash, a power cut), such a file can be left behind; it is unencrypted, so delete it.

Not kept by the format, so never restored: extended attributes (including Finder tags), the macOS hidden flag and other file flags, access control lists, and hard links (each name comes back as its own file).

## Build from source

Install Rust from [rustup.rs](https://rustup.rs), then:

```sh
cargo build --release --locked
# the tool is target/release/backupbase-restore (backupbase-restore.exe on Windows)
cargo test --release
```

All dependencies are pure Rust, so a static Linux build needs nothing else:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl
```

Dependencies (versions pinned in `Cargo.toml` and `Cargo.lock`): `aes-gcm`, `argon2`, `hkdf`, `hmac`, `sha2`, `zeroize` (RustCrypto), `ruzstd` (zstd decoder), `serde` and `serde_json`, `base64`, `unicode-normalization`, `rpassword` (passcode prompt), `filetime` (restoring times).

## Try it

`fixtures/macos/` holds two small sample backups made by the Backup Base app on macOS, one in each format version, with a manifest of every file in every version. Test data only; the passcode is `Recovery-Fixture-2026!-Granite-Walrus`.

```sh
cargo build --release --locked
target/release/backupbase-restore list fixtures/macos/backups
```

## More

- [FORMAT.md](FORMAT.md): the backup format specification.
- [SECURITY.md](SECURITY.md): how to report a security problem.
- [CHANGELOG.md](CHANGELOG.md): what changed in each version.
- License: MIT ([LICENSE](LICENSE)).
