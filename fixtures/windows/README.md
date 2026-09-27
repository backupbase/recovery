# Windows recovery fixtures

Two Backup Base backups made on Windows 11 by the Backup Base apps, for testing `backupbase-restore`. Test data only; the passcode is public on purpose.

They are stored unzipped in `format-v1/` and `format-v2/` (each: `manifest.json`, then `backup/` exactly as the app wrote it), so `tests/windows_fixtures.rs` can restore every version and compare it with the manifest. They were made and checked as the two zips below; the files here are the zips' contents, byte for byte.

| Original zip | Size | SHA-256 |
|---|---|---|
| `windows-format-v1.zip` | 11,657,672 bytes | `1019c43a5a9e41a1ad9e7544977a1668b29447f9c2bce825adaa022931f2b82d` |
| `windows-format-v2.zip` | 22,376,625 bytes | `ad521f48f20bd3ef8ed9ff4bfc2130ccdbdb1b692470a8dbd7497c6b5ad541de` |

- **Format v1** (per-file layout, `data/*.bbk` + `snapshots/*.bbs`): made by Backup Base 1.0.2, commit `eb59f27d32c14f8ffb0a1d2299edea256fd54b5d`.
- **Format v2** (archive layout, `archives/*.bba` + `*.bbs`): made by Backup Base 1.1.0, commit `e1965d1dfae099b4518c17c0a856e7fffb1f0bde`.

Passcode for both: `Recovery-Fixture-2026!-Granite-Walrus`

## Zip layout

```
manifest.json                      what each version must restore to
backup/                            the backup folder, exactly as the app left it
  HOW-TO-RESTORE.txt
  Recovery Fixture/                the vault (set name "Recovery Fixture")
    vault.bbv, writer.json, data/ + snapshots/ (v1) or archives/ (v2)
```

`backup/` is what `backupbase-restore list <backup-folder>` should look at. `backup/Recovery Fixture` is the vault for `files`, `restore` and `verify`.

## Versions

Both vaults hold the same two versions of one source folder, `C:\bbtest\rfx\src` (root name `src`).

| Version | v1 vault id | v2 vault id | Files | Folders | Bytes |
|---|---|---|---|---|---|
| 1 | `20260927T032037Z-2d43652a` | `20260927T032438Z-899ca610` | 319 | 44 | 13,092,928 |
| 2 | `20260927T032510Z-214d1fce` | `20260927T032537Z-11c3cc02` | 305 | 45 | 12,942,087 |

The source tree in version 1 has:
- 300 small text, CSV and JSON files in `Projects/<Alpha..Echo>/<notes|specs|data>/`;
- unicode names: Cyrillic, Japanese, Greek, Hebrew, emoji, accented NFC names, one NFD name (`Cafe` + U+0301), and brackets, `&`, `#`, `%20`;
- a relative path of 359 characters under `Deep/` (377 characters as an absolute path on the source computer), plus an empty folder at that depth;
- empty folders (`Empty Folder`, `Nested/empty/inside/empty`) and zero-byte files;
- `Attributes/readonly.txt` (read-only), `hidden.txt` (hidden), `hidden-and-readonly.txt` (both), and `.dotfile-config`;
- `Media/sample-10MiB.bin` (10,485,760 random bytes: several segments) and `Media/photo.jpg` (an already-compressed type).

Version 2 changes the tree:
- **Edited:** `README.txt`, `Projects/Bravo/specs/specs-001.csv`, `Projects/Echo/data/data-020.json`, `Unicode/日本語/テスト ファイル.txt`, `Media/photo.jpg` (bytes changed, same size).
- **Attribute only:** `Projects/Alpha/notes/notes-010.txt` became hidden.
- **Added:** 8 files in a new folder `Projects/Foxtrot/`, `Unicode/Документы/новый файл.txt`, `Unicode/emoji 🎉 party/🆕 added.txt`, `added-zero-byte.dat`, and the empty folder `Empty Folder Added In v2`.
- **Deleted:** `Projects/Alpha/notes/notes-001.txt`, `Projects/Bravo/data/data-005.json`, `Projects/Charlie/specs/specs-010.csv`, `Unicode/UPPER CASE.TXT`, `zero-byte.dat`, and the folder `Projects/Delta/data/` with its 20 files.
- **Renamed:** `Projects/Echo/notes/notes-005.txt` to `notes-005 renamed.txt` (same content and time).

## manifest.json

- `versions[n].entries`: every file and folder of that version (the root itself is not listed), sorted by path. Paths are relative to the root `src` with `/` separators.
- Files have `size` and `sha256`; files and folders have `mtime_ms` (Unix milliseconds, UTC, as the vault's `m`), `mtime` (the same instant, ISO 8601) and `attr` (vault format bits: 1 read-only, 2 hidden; `attributes` gives the same by name).
- `backup_id` is the version's id in that vault (the index file name without `.bbs`).

**A correct restore** of version N writes exactly `versions[N-1].entries` under `<target>/src/`:
- the same file bytes (sha256) and sizes;
- the same modification times, to the millisecond;
- on Windows, the read-only and hidden attributes;
- every folder, empty ones included.

## How these were made

1. `node tools/make-fixture-tree.mjs create C:\bbtest\rfx\src` (deterministic: the same bytes and times every time), then `tools/fixture-manifest.ps1` for the manifest.
2. Each app with its own scratch data folder (`BACKUPBASE_HOME`). First-run wizard: source `C:\bbtest\rfx\src`, set name `Recovery Fixture`, the passcode above, destination "Another folder…" on a local disk, "Back up now after creating".
3. `node tools/make-fixture-tree.mjs mutate C:\bbtest\rfx\src`, manifest again, then "Back up now" in each app.
   - The v1 app reported "Encrypted 15 changed files": the new zero-byte file and the renamed file reuse content already stored, and the attribute change needs no new data.
   - The v2 app wrote a second full archive.

**One change to both apps:** they were built locally (`tauri build --no-bundle`) with one patch, so the vaults carry a random computer name instead of the real one. The app writes the computer name into `writer.json` and into every index, which anyone with this public passcode can read. Nothing else differs from the commits above.

```diff
 pub fn device_name() -> String {
-    platform::device_name()
-        .map(|n| n.trim().to_string())
-        .filter(|n| !n.is_empty())
-        .unwrap_or_else(|| if cfg!(windows) { "Windows PC".to_string() } else { "Mac".to_string() })
+    // Recovery fixture build only (never committed): a random name instead of the real computer name.
+    "DESKTOP-HVWGRW5".to_string()
 }
```

## Checks done before publishing

- **Index vs manifest:** every index in both vaults was decrypted with the product's own vault code and compared with the manifest: 363 and 350 entries, 0 differences in path, kind, size, sha256, mtime or attributes.
- **Zip round trip:** the vault files extracted from each zip are byte-identical to what the app wrote, and the extracted vaults open with the passcode. A wrong passcode is refused.
- **Identifying data:** the zips' files, the decrypted indexes and the manifests were searched (UTF-8 and UTF-16, any case) for the real computer names, the Windows user name, the profile path and the work tenant name: none found. The only match for "OneDrive" is the app's generic help text in `HOW-TO-RESTORE.txt`. Paths inside the indexes start at `C:\bbtest\rfx\src`.

## tools/

- `make-fixture-tree.mjs`: builds the source tree (`create`) and version 2 (`mutate`). Node 18+, Windows (it runs `attrib` for the hidden and read-only files).
- `fixture-manifest.ps1`: the manifest of one version (Windows PowerShell 5.1, long paths through `\\?\`).
