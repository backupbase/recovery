<!-- The published Backup Base vault format specification: the same text the app is built from, without references to the app's private source code. -->

# Backup Base vault format (versions 1 and 2)

This is the on-disk format the app writes into the user's synced folder. It is a public contract: a vault written by any released version must stay restorable by every later version, on either OS. Change it only by adding a new `version` and keeping the reader for old ones.

Two versions exist, and the app reads and writes both:

- **Version 1, files layout** (app 1.0.x): one encrypted blob per distinct file content, deduplicated, plus one encrypted snapshot index per run. Everything from "Layout" to "Renaming a backup set" below describes it.
- **Version 2, archive layout** (app 1.1.0 and later): one encrypted archive plus one encrypted index per run that changed something. Every new backup set is version 2. See "Format v2: one archive per run" at the end; it reuses v1's cryptography, `vault.bbv` key wrap, `writer.json`, encrypted file format and snapshot JSON, and says exactly what differs.

A vault never changes version: sets made by 1.0.x stay version 1 and keep backing up and restoring. The engine picks the code path from `vault.bbv`'s `version`.

Goals, from the website's promises: files are encrypted on the device with the user's passcode (AES-256) before they reach the synced folder; the cloud sees only sealed files; any file or folder can be restored, on any computer, with only the passcode.

## Layout

The user picks a **destination root**, normally a folder inside a synced location, e.g. `~/Library/CloudStorage/OneDrive-Personal/Backup Base` or `C:\Users\Alex\OneDrive\Backup Base`. Each backup set gets its own **vault** folder inside it, named after the set (sanitised: strip `\/:*?"<>|` and control chars, trim dots/spaces, max 80 chars; if the name exists and belongs to another vault, append ` (2)`, ` (3)`...).

```
<destination root>/
  HOW-TO-RESTORE.txt                    plaintext help, no secrets, rewritten after each run
  <Set name>/                           a vault
    vault.bbv                           JSON header (plaintext, contains no secret)
    writer.json                         which device currently backs up into this vault
    snapshots/
      20260925T150000Z-3fa9c2d1.bbs     encrypted snapshot index (one per run that changed something)
    data/
      7f/7fk2m9qz4x8b1c3d5e6g7h8j9k.bbk  encrypted file content, name = scrambled id
```

- File names under `data/` reveal nothing about the file (keyed HMAC of the content hash).
- Snapshot names reveal only the time of the run, which the cloud already knows from file times.
- Nothing else is left in the vault. Temporary files exist only while something is written: in the app's local staging folder, or, when the vault is on another volume than the app's data folder, in `<vault>/.staging/` (see "Writing").

What is **not** secret: the vault folder's name and the `name` in vault.bbv (the backup set's name, also listed in HOW-TO-RESTORE.txt), the number of blobs (about one per distinct file) and their approximate sizes, and when they change. vault.bbv's `name`, `created_at` and `created_by` are plain metadata outside the key wrap: anyone who can write the folder can change them, so they are shown as a label only and never trusted for anything else.

## Cryptography

| Purpose | Algorithm |
|---|---|
| Passcode to key-encryption key (KEK) | Argon2id v19, m = 65536 KiB, t = 3, p = 1, 32-byte output, 16-byte random salt (readers accept any salt of 8 bytes or more) |
| Master key (MK) | 32 random bytes from the OS CSPRNG, generated once per vault |
| MK wrapping | AES-256-GCM(KEK), 12-byte random nonce, AAD = `"backupbase-vault-v1:" + vault_id` |
| Subkeys | HKDF-SHA256(ikm = MK, salt = the 16 raw bytes of `vault_id` (UUID), info = label) |
| `K_data` | info `"bb/v1/data"`: file-content encryption |
| `K_snap` | info `"bb/v1/snap"`: snapshot encryption |
| `K_name` | info `"bb/v1/name"`: blob ids |
| Blob id | `HMAC-SHA256(K_name, SHA-256(plaintext))`, first 16 bytes, encoded as 26 chars of lowercase Crockford base32 (`0123456789abcdefghjkmnpqrstvwxyz`, no padding), most significant bit first: each char is the next 5 bits, so the 26th char holds the last 3 bits followed by 2 zero bits |
| Content encryption | AES-256-GCM in the STREAM construction (below) with a per-file key |
| Per-file key | HKDF-SHA256(ikm = `K_data` or `K_snap`, salt = the file's 24-byte `file_salt`, info = `"bb/v1/file"`) |
| Compression | zstd level 3, applied before encryption, skipped for already-compressed content |

The passcode is normalised to Unicode NFC and encoded as UTF-8 before Argon2id, so a passcode typed on macOS (NFD input) and Windows gives the same key.

A wrong passcode is detected by the GCM tag failing when unwrapping MK. There is no other verifier.

Changing the passcode re-wraps the same MK with a new salt and KEK (keeping the vault's stored KDF parameters) and atomically replaces `vault.bbv`. Data files are untouched. The old passcode no longer opens the current `vault.bbv`, but it still opens any older copy of `vault.bbv`, and sync services keep those (OneDrive, SharePoint and Google Drive version history, recycle bins). Such a copy holds the same MK, so it decrypts versions written after the change too. To retire an old passcode completely, start a new backup set (a new vault has a new MK) and delete the old one. The app's Change passcode dialog says this.

## vault.bbv

```json
{
  "format": "backupbase-vault",
  "version": 1,
  "vault_id": "3b0f0e2c-7a8e-4d4b-9f6c-2f1f3c7d9a10",
  "name": "Documents",
  "created_at": "2026-09-25T15:00:00Z",
  "created_by": { "app_version": "1.0.0", "os": "macos" },
  "kdf": { "alg": "argon2id", "v": 19, "m_kib": 65536, "t": 3, "p": 1, "salt": "<base64 std, 16 bytes>" },
  "wrapped_key": { "alg": "aes-256-gcm", "nonce": "<base64 std, 12 bytes>", "ct": "<base64 std, 48 bytes = 32 key + 16 tag>" }
}
```

Readers must reject `format` other than `backupbase-vault` and `version` they do not know, with a clear message ("This backup was made by a newer version of Backup Base. Update the app to open it.").

KDF parameters: writers create every vault with the v1 values above (m 65536 KiB, t 3, p 1); a passcode change keeps the parameters already stored in the vault. Readers use the parameters stored in `kdf`, as long as they are within bounds (m 8 KiB to 1 GiB, i.e. 8..=1048576 KiB; t 1..=16; p 1..=8; and m >= 8 x p, Argon2's own minimum), and reject anything outside them as `corrupt` before running Argon2, so a tampered header cannot make the app allocate huge memory or spin for minutes.

Reader error codes (the names the app uses): `not_a_vault` (no vault.bbv, not JSON, or `format` is not `backupbase-vault`), `newer_format` (`version` above 2 or a version 2 `layout` this reader does not know, see "Format v2"; or an unknown `kdf.alg` / `kdf.v` / `wrapped_key.alg`), `corrupt` (a missing or malformed field, `vault_id` not a UUID, KDF parameters out of bounds, a salt under 8 bytes, a nonce that is not 12 bytes, `ct` that is not 48 bytes), `wrong_passcode` (the key wrap does not authenticate). Blobs and snapshots that fail authentication are `corrupt`; a missing blob is `not_found`.

## writer.json

```json
{ "device_id": "<app install uuid>", "device_name": "Alex's MacBook Pro", "os": "macos", "updated_at": "2026-09-25T15:00:00Z" }
```

A vault has one writer. Before a backup run the engine reads `writer.json`: if it names a different device, the run stops with "Another computer (Alex's MacBook Pro) is backing up into this folder" and the UI offers **Take over**, which rewrites it. Restore never needs to be the writer. This keeps GC safe without distributed locking.

`writer.json` separates computers. On one computer, two copies of the app for the same user share a device id, so the app also holds an exclusive lock file in its own data folder (`locks/<hash of the vault folder>.lock`, not in the vault) for the whole backup run including retention and GC, and for a passcode change; a second copy stops with `already_running`.

## Encrypted file format (`.bbk` data and `.bbs` snapshots)

Header, 32 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `42 42 4B 31` ("BBK1") |
| 4 | 1 | kind: `1` data, `2` snapshot |
| 5 | 1 | flags: bit 0 = zstd compressed; other bits 0 |
| 6 | 1 | segment size as log2; v1 writers use `20` (1 MiB); readers accept 16..24 |
| 7 | 1 | reserved, 0 |
| 8 | 24 | `file_salt`, random |

Body: the plaintext (after compression when flag set) is split into segments of exactly `2^seglog` bytes; the final segment holds the remainder and may be 0 bytes (an empty file is one empty final segment). Every segment is sealed with AES-256-GCM:

- key: the per-file key
- nonce (12 bytes): segment index as big-endian u64 (8 bytes) || `00 00 00` || last-flag (`01` for the final segment, `00` otherwise)
- AAD: the 32 header bytes
- output: ciphertext || 16-byte tag

So every non-final segment is `2^seglog + 16` bytes on disk and the final one is `len + 16`. A reader decrypts segment by segment; a segment is final when it is followed by EOF. If the plaintext length is an exact multiple of the segment size, the last full segment carries the final flag and no empty segment follows. Truncation, reordering, splicing between files and header tampering all fail authentication. The reader must never output plaintext from a segment whose tag failed, and must treat "EOF before a final-flagged segment" as corruption.

Compression is skipped (flag clear) for files whose extension is in a known-compressed list (jpg jpeg png gif webp heic heif avif mp4 m4v mov mkv avi webm mp3 m4a aac flac ogg opus zip 7z rar gz tgz bz2 xz zst lz4 dmg iso pkg msi docx xlsx pptx odt ods odp epub jar apk ipa pdf) and for files under 64 bytes. Readers must support both.

## Snapshot index (`.bbs`)

Decrypts (and decompresses) to UTF-8 JSON:

```json
{
  "v": 1,
  "vault_id": "3b0f0e2c-...",
  "snapshot_id": "20260925T150000Z-3fa9c2d1",
  "created_at": "2026-09-25T15:00:00Z",
  "device": { "id": "<uuid>", "name": "Alex's MacBook Pro", "os": "macos", "app_version": "1.0.0" },
  "roots": [ { "id": 0, "path": "/Users/alex/Documents", "name": "Documents" } ],
  "entries": [
    { "r": 0, "p": "",                    "k": "d", "m": 1727276400000, "mode": 493 },
    { "r": 0, "p": "Contracts",           "k": "d", "m": 1727276400000, "mode": 493 },
    { "r": 0, "p": "Contracts/nda.pdf",   "k": "f", "s": 1153433, "m": 1726650000000, "mode": 420, "h": "<sha256 hex of plaintext>", "b": "7fk2m9qz4x8b1c3d5e6g7h8j9k" },
    { "r": 0, "p": "current",             "k": "l", "t": "Contracts/nda.pdf", "m": 1726650000000 }
  ],
  "stats": { "files": 1, "dirs": 2, "links": 1, "bytes": 1153433, "new_files": 1, "new_bytes": 1153433, "skipped": 0 }
}
```

- `r` root id, `p` path relative to that root with `/` separators (never leading `/`, never `..`; the root itself is `""`), `k` kind (`f` file, `d` directory, `l` symlink), `s` size, `m` mtime in Unix milliseconds, `mode` Unix permission bits (macOS; omitted on Windows), `attr` Windows attribute bits we restore (1 readonly, 2 hidden; omitted on macOS), `h` SHA-256 of plaintext, `b` blob id, `t` symlink target (stored, never followed).
- `roots[].name` is the backed-up folder's own name (app 1.1.4 and later): `\/:*?"<>|` and control characters dropped, whitespace and trailing dots trimmed, at most 80 characters, leading dots kept (`.ssh`); an empty result (a root of `/`) is `Backup`. Names are made unique ignoring case with ` (2)`, ` (3)`. The app uses it in Activity lines and messages. Indexes written before app 1.1.4 may hold a name without its leading dot (`.ssh` as `ssh`, and `.claude` as `claude (2)` when `claude` was also backed up), which is why readers take the restored folder's name from `path` (see "Restore", Chosen folder).
- Entries are sorted by (`r`, `p`) so readers can build a tree in one pass.
- `stats.new_files` / `new_bytes`: files whose content was not in the vault before this run (new or edited files). A renamed or moved file whose content is already stored, or a file only touched, does not count.
- Snapshot file name: `YYYYMMDDTHHMMSSZ-<8 random hex>.bbs` in UTC, with a real date and time; lexical order is time order. A new name follows the run's **baseline**: the newest snapshot **that decrypts** and is dated at most 10 minutes past the run's clock (only when no such snapshot exists, the newest one that decrypts). When the run's time (whole seconds) is not later than the baseline's (two runs in one second, or the clock went back), the new snapshot's `created_at` and name use its time plus 1 second, but never more than 10 minutes past the run's clock. The writer checks the name is valid before writing.
- A version dated far in the future (this computer's clock was wrong once) is therefore not followed and not the baseline: later versions get their real time, sort before it, and change detection compares with them, so it cannot make every run write a new version. It stays in the list: Restore shows it first (as the latest), and retention keeps it as the newest version, until real time passes its date.
- Files in `snapshots/` that are not versions this vault can read (a name that is not a valid snapshot id, such as a sync conflict copy, or a file that does not decrypt) are ignored: never listed for restore, never the "newest", never deleted, and reported once in the app's Activity.
- Readers bound what an index may cost (v1 snapshots and v2 indexes alike): its zstd window at most 2^24 bytes, and its decompressed JSON at most 64 MB plus 256 times the `.bbs` file's size (real indexes expand about 16 times: 170,000 entries are 32 MB of JSON in a 2 MB file). An index past either limit is `corrupt`, like one that does not decrypt. Listing versions parses each index while reading it, skipping the entries, and the app reads at most 4 indexes at once.

## Backup run algorithm

1. Open the vault (unwrap MK using the passcode from the keychain). Check `writer.json`.
2. Load the baseline (the newest snapshot that decrypts and is not dated more than 10 minutes in the future, see "Snapshot index"; if any) into a map `(root path, p) -> entry`, where root path is `roots[r].path` (not the root id `r`, so adding, removing or reordering source folders does not force a full re-read). This is the change-detection cache; there is no separate local cache.
3. Walk each root without following symlinks. Skip: sockets, fifos, devices; the destination root and the app's own data folder if they are inside a root; entries matching the set's exclude patterns (default: none). Record per-file errors (permission denied, locked by another process, vanished) and continue.
   Size, `m`, `mode` and `attr` come from each entry itself (lstat on macOS; on Windows a metadata-only open of the entry, which sharing modes do not block). Never from the copy that a Windows directory listing (FindFirstFile / FindNextFile) returns: NTFS updates that copy lazily, so it can show an old size and time for a file another app still has open, for a file changed through another hard link, and for a folder whose contents changed. If asking the entry fails for any reason other than the entry being gone, the listing's copy is used and reading the file reports the problem.
4. For each regular file: if the previous snapshot has the same path with the same `s` and `m`, reuse its entry. Otherwise stream it once: read, SHA-256 the plaintext, compress (unless skipped), encrypt into a staging file. Compute the blob id. If `data/<id[0..2]>/<id>.bbk` already exists (dedup across files and runs), delete the staging file; else move it into place (see "Writing").
   Unreadable things never erase good backups: a file that cannot be read this time keeps its last good entry from the previous snapshot (when its blob still exists), and a source folder that cannot be read at all keeps all of its previous entries. Each counts in `stats.skipped` and is reported. If nothing at all could be read (every source failed), the run fails and writes no snapshot.
5. If nothing changed compared with the previous snapshot (same roots and the same entries: paths, kinds, sizes, mtimes, modes or attributes, hashes, blobs, link targets), write no snapshot; the run is still a success ("No changes since last run"). Directory mtimes do not count in this comparison: a folder's time moves whenever anything is created or deleted inside it, temporary and excluded files included, and that alone is no reason for a new version. New, removed or renamed folders, and folder mode or attribute changes, do count. A snapshot written for any other reason records the current directory mtimes.
6. Otherwise write the new snapshot (encrypted with `K_snap`), then, if verify is on, re-read every blob written in this run plus the snapshot, decrypt fully and compare SHA-256.
7. Apply retention and garbage-collect (below).
8. Rewrite `HOW-TO-RESTORE.txt` in the destination root.

A crash at any point leaves at worst orphan blobs (collected later) and never a snapshot that references a missing blob, because the snapshot is written only after all its new blobs are in place.

## Writing (sync-client safety)

Sync clients upload files as they grow and can fail when a partially written file is renamed underneath them (seen with Google Drive in the old app). So nothing is written in place:

- Stage in the app's local data folder (`<app data>/staging/<random id>/`, one subfolder per writer: a backup run, a rename, a take over) and atomically rename into the vault. If rename fails because the vault is on another volume (EXDEV / ERROR_NOT_SAME_DEVICE), that writer uses its own `<vault>/.staging/<random id>/` for the rest of its work instead (rename within one folder tree is atomic) and at the end deletes that subfolder, then `.staging` if it is empty, so a quick write never deletes a running backup's files. Leftovers of a crash are deleted when the app starts (the local folder) and when the set's next backup run starts, holding the vault lock (`<vault>/.staging`).
- `vault.bbv`, `writer.json` and snapshots use the same write-then-rename.
- fsync the staging file before rename.

## Retention and GC

Per set `retention_days` (choices 7, 30, 90, 365, 0 = keep forever; app 1.0.x made sets with 30 by default, and every set made by 1.1.0 is version 2).

Retention only considers snapshots that decrypt; any other file in `snapshots/` is left alone.

- Always keep the newest snapshot.
- Keep every snapshot younger than 48 hours.
- Between 48 hours and `retention_days`: keep the newest snapshot of each calendar day (local time of the writing device).
- Delete older snapshots.
- `retention_days` is 0..=36500 (the app refuses larger values); a value too large to subtract from the current time keeps everything older, like forever.
- GC: decrypt all remaining snapshots, collect every referenced blob id, delete every `.bbk` under `data/` that is not referenced. Only the writer runs GC. GC is skipped while a snapshot with a valid name and a valid encrypted-file header (magic `BBK1`, kind 2: a file this vault could have written) fails to decrypt: never delete data on uncertainty. A file without a valid header (empty, garbage, planted) is foreign and does not hold GC back.

## Restore

- Open: given a vault folder and a passcode (or a set whose passcode is in the keychain), unwrap MK, list snapshots newest first.
- Browse: build the tree of a snapshot; directory sizes are the sum of their files.
- Restore selected entries to:
  - **Original location**: `roots[r].path` joined with `p` (converted to native separators). Root paths are chosen by whoever made the backup, so the app only restores there inside the user's home folder or a folder one of this computer's backup sets reads from, never into `~/Library/LaunchAgents`, `~/Library/LaunchDaemons` or the Windows Startup folder, and never to a network share or device path (`\\server\share`, `\\?\`, `\\.\`); anything else is refused with a message suggesting a chosen folder. The app lists the absolute target folders and asks before an Original restore. A vault opened from another computer (its folder and `vault_id` do not both match one of this computer's sets) starts with Chosen folder selected.
  - **Chosen folder**: `<folder>/<root folder>/<p>`. The root folder is the last component of `roots[r].path`, leading dots kept. A path that starts with `/` (made on macOS) is split on `/` only, since a macOS folder name may contain `\`; any other path (made on Windows) is split on both `/` and `\`, so a backup made on either OS restores on the other. The name is not usable when it is empty, `.`, `..` or holds a NUL or `/`, or, on Windows, when it is a reserved name (CON, PRN, AUX, NUL, COM0-9, LPT0-9, CONIN$, CONOUT$, with or without an extension). On macOS a usable name is kept as it is. On Windows `<>:"|?*\` and control characters become `_`, and a last character that is a dot or space becomes `_` (only the last one: `Notes..` becomes `Notes._`, `...` becomes `.._`, `C:foo` becomes `C_foo`). When the path has no last component (`/`, `C:\`) or it is not usable, `roots[r].name` with surrounding whitespace trimmed, by the same rule; when neither is usable, `Folder <r+1>`. Names are made unique in root id order, ignoring case and Unicode normalization form (NFC), with ` (2)`, ` (3)`; the name before the suffix is shortened on a character boundary so the whole fits in 255 bytes. The app's Restore view shows each root under the same name.
- Conflicts, when a file already exists at the target: if its SHA-256 equals `h`, skip it; otherwise follow the chosen policy, **Keep both** (default: write `name (restored).ext`, then `name (restored 2).ext`...; the name is shortened on a character boundary so it fits in 255 bytes) or **Replace**.
- Each file is decrypted to a temp file next to the target (`.bbrestore-<hex>.tmp`, created readable by the owner only, mode 0600 on macOS), its SHA-256 checked against `h`, its mode (macOS) applied, then renamed into place; its mtime and attributes (Windows) are applied after the rename (a temp file never carries an old time, so another restore worker's cleanup below cannot take it for a leftover). A later restore deletes such temp files older than 15 minutes (left by a crash) from the folders it writes into.
- Directories are created as needed and get their recorded permission bits (`mode & 0o777`) exactly, and their mtime, as the last step, deepest first, after everything inside them is written (an existing read-only folder is made writable for the restore and set back). On Windows a directory recorded as hidden (`attr` bit 2) is made hidden then too. setuid, setgid and sticky bits are recorded but never restored.
- A folder that cannot be created (a file is in the way, no permission) is reported once; everything below it is skipped without an error per file. Problems are plain sentences, never raw OS error text.
- Symlinks are recreated on macOS; on Windows they are skipped with a note (creating them needs admin or developer mode).
- Restoring onto a different OS: paths are converted; characters invalid on Windows (`<>:"|?*`) are replaced with `_` and reported.
- Not kept by format v1: extended attributes (including Finder tags and other `com.apple.*` metadata), the macOS hidden flag and other file flags (`chflags`), ACLs, and hard links (each linked name is backed up and restored as its own file; the content is stored once). A later format version could add optional fields for them (readers ignore unknown fields).

## Verify

- After each run (setting, default on): the blobs written in that run and the new snapshot, as described above.
- "Verify backup" action: decrypt every blob referenced by the newest snapshot that decrypts and compare hashes; report missing or corrupt files by path. The next backup encrypts the reported files again and says "Repaired N files that failed verification".

## Renaming a backup set

The set's name lives in the app's config and in vault.bbv's `name`. When the set is renamed and this computer is the vault's writer, the app rewrites vault.bbv with the new name (through staging, nothing else changes) and HOW-TO-RESTORE.txt; when the folder is not reachable, the next backup run does it.

## Format v2: one archive per run

Version 2 stores each run as one encrypted archive holding the whole set, so a sync client sees one finished file per run instead of thousands of small ones. The cryptography, the key wrap, the subkeys, `writer.json` and the encrypted file format are exactly those of version 1.

### Layout

```
<destination root>/
  HOW-TO-RESTORE.txt                      plaintext help (describes both layouts)
  <Set name>/                             a vault
    vault.bbv                             version 2, layout archive
    writer.json                           as in v1
    archives/
      20260925T150000Z-3fa9c2d1.bba       the run's encrypted archive (all files of the set)
      20260925T150000Z-3fa9c2d1.bbs       its encrypted index (file list, sizes, hashes)
```

There is no `data/` and no `snapshots/` folder. An archive and its index share the snapshot id (naming and uniqueness as in v1: `YYYYMMDDTHHMMSSZ-<8 random hex>`, following the run's baseline, see "Snapshot index"). The index's presence marks a complete run: an archive without an index is an interrupted run, never a version.

What is **not** secret: the set's name (vault folder, `vault.bbv`), when each run happened and how large each archive is. Unlike v1, the number of files and their sizes are no longer visible.

### vault.bbv

The v1 header with `"version": 2` and `"layout": "archive"`:

```json
{ "format": "backupbase-vault", "version": 2, "layout": "archive", "vault_id": "...", "name": "Documents", "created_at": "...", "created_by": { ... }, "kdf": { ... }, "wrapped_key": { ... } }
```

The key wrap is unchanged (AAD `"backupbase-vault-v1:" + vault_id`), so the same passcode unwraps the master key of either version. A version 1 header has no `layout` field; a v1 `vault.bbv` rewritten by a newer app (passcode change, rename) keeps it absent, so 1.0.x still opens it. Readers: version 1 with `layout` absent or `"files"`, and version 2 with `"archive"`, are known; version 2 without a layout or version 1 with another layout is `corrupt`; version 2 with another layout, or a version above 2, is `newer_format`. App 1.0.x refuses version 2 with its "newer version" message.

### The archive (`.bba`)

An encrypted file in the v1 format (header, STREAM segments, per-file key `HKDF(K_data, file_salt, "bb/v1/file")`) with header **kind 3** (archive) and flag bit 0 (zstd) always set. Readers refuse kind 3 without the zstd flag, and the blob and index readers refuse kind 3, so an archive can never be read as another kind of file.

Its plaintext is a zstd stream (level 3; readers refuse frames whose window exceeds 2^24 bytes, writers use at most 2^21) of a POSIX tar stream:

- One tar entry per index entry, in exactly the index's order (`r`, then `p` by bytes), so a folder always comes before what is in it. Entry names are `r<root id>/<p>`, with a trailing `/` for folders; the root itself is `r<root id>/`.
- Entry types: `5` folder, `0` regular file, `2` symbolic link (target in `linkname`). ustar header (magic `ustar\0`, version `00`), checksum as POSIX, uid and gid 0, empty user and group names, mode `mode & 0o7777` from the index (0644 files and 0755 folders when the index has none, e.g. Windows; links are always 0777 on every OS, the index keeps no mode for them), mtime in whole seconds (`floor(m / 1000)`).
- A pax extended header (type `x`, name `././@PaxHeader`) precedes an entry whose name or link target is not plain ASCII of at most 100 bytes (`path`, `linkpath`), whose size needs more than 11 octal digits (`size`), or whose time is before 1970 or after 8^11 - 1 seconds, in the year 2242 (`mtime`; the ustar field has 11 octal digits). The ustar fields then hold an ASCII stand-in (the time clamped to that range).
- A file's data is exactly the index's `s` bytes, zero-padded to 512; folders and links have no data. The stream ends with two zero blocks and nothing after them: readers refuse any data after them. zstd skippable frames decompress to nothing, so readers pass over any that follow without a note, as any zstd reader does; they sit inside the encryption, so only someone holding the key could add them.

The tar metadata is informational: restores take paths, times, modes and attributes from the index only. A reader checks every entry against the index entry expected next: name, type, size (files) and link target (links) must match exactly, or the archive is damaged from that point on.

### The index (`.bbs`)

An encrypted file of kind 2 with `K_snap`, exactly like a v1 snapshot, holding the v1 snapshot JSON plus two fields:

```json
{
  "v": 1, "vault_id": "...", "snapshot_id": "20260925T150000Z-3fa9c2d1", "created_at": "2026-09-25T15:00:00Z",
  "layout": "archive",
  "archive": { "file": "20260925T150000Z-3fa9c2d1.bba", "size": 12402318848, "sha256": "<hex of the encrypted archive file>" },
  "device": { ... }, "roots": [ ... ],
  "entries": [ { "r": 0, "p": "Contracts/nda.pdf", "k": "f", "s": 1153433, "m": 1726650000000, "mode": 420, "h": "<sha256 hex of the stored bytes>" } ],
  "stats": { ... }
}
```

- `archive.file` must be `<snapshot_id>.bba` (readers refuse anything else), `size` and `sha256` describe the encrypted file.
- Entries are v1 entries without `b` (there are no blobs). A file entry may carry `"c": true`: the file changed while it was being read, so the stored copy (still exactly `s` bytes, `h` their hash) may be incomplete (see "A file that changes during a run").
- A file entry **without `h`** is listed but not stored: the file could not be opened (locked, no permission) or was online-only (see "Online-only cloud files") when the run was made. It has no tar entry (readers skip it when they match the archive against the index), it is not counted in `stats.files` or `stats.bytes`, Restore neither lists nor restores it (a restore of a folder holding it says so in a note), and an older version may hold its last copy. Indexes written before this rule always have `h` on files.
- `stats.new_files` / `new_bytes`: files whose path is new or whose hash differs from the previous index (a renamed file counts as new here).
- In a version 2 vault an index without `layout: "archive"` and a valid `archive` object is `corrupt`; in a version 1 vault a snapshot with them is `corrupt`.

### Backup run algorithm

1. Open the vault, check and claim `writer.json` (as v1), hold the per-vault lock.
2. Load the baseline: the newest index that decrypts and is dated at most 10 minutes past the run's clock, or, only when there is none, the newest that decrypts (a version dated in the future is not compared with, see "Snapshot index"). Walk the sources with the v1 walker and skip rules (on Windows the metadata comes from the file itself); the walk also marks online-only files.
3. If every source failed, the run fails and writes nothing (as v1).
4. **Change detection** (the v1 rule without hashes): the walk equals the baseline when the roots are the same and every entry matches in path, kind, size, mtime, mode and attributes (files), mode and attributes (folders; folder times alone never count), target and mtime (links). Roots that could not be read this time are left out of the comparison (their last copies stay in older archives). A new archive would not hold what cannot be read, so these never count as a change by themselves:
   - a file that is online-only now (whatever the baseline holds for it);
   - a file the baseline lists without content (no `h`) that still cannot be opened (the run tries to open it, non-blocking, and reports it as skipped again); once it opens, that is a change and the next archive stores it.
   A file entry marked `c` with the walk's size and time counts as a change once: it is unchanged only when the version before the baseline also marked it `c` with the same size and time (it was already saved again once and came out incomplete again, as with a lock another app holds while it has the file open), so a lasting lock never makes every run write a complete archive.
   Also a change: the baseline's archive is missing or has another size than its index says, or the last "Verify backup" found it damaged. If nothing changed, nothing is written ("No changes since last run").
5. Check free space in the local staging folder: the estimated archive size plus 64 MB. The estimate starts from today's data (the sizes of the files the run reads, online-only ones left out) plus an overhead of 1 KiB per entry and 64 KiB. After a previous archive (whose index lists any data) it is the data times that archive's ratio of archive size to data, limited to 0.02..1.05, times 1.1, plus the overhead, but never more than 5% above the data plus the overhead; on a first run it is the data plus the overhead (incompressible worst case). Not enough: the run fails with "There is not enough free space on this computer to prepare the backup..." and writes nothing. A disk that fills up anyway during the run gives the same message.
6. **Archive** in the local staging folder (the run's own `<app data>/staging/<random id>/`, always local, even when other writes fell back to `<vault>/.staging`): one pass in index order. A few reader threads open upcoming files and read their first 256 KB ahead of the writer (at most 32 files ahead, so memory stays bounded); the writer streams each file's declared size into the tar stream, hashing it, through zstd and the STREAM encryption, hashing the ciphertext. Online-only files are never opened. A file that cannot be opened is reported as skipped; on macOS a file is opened without waiting and checked, and one that is no longer a regular file (a FIFO put in its place since the walk) is refused and skipped the same way. Both kinds are listed in the index without content (no `h`) and left out of the archive. A cancel ends the run without waiting for a reader stuck in an open (a network disk that stopped answering). Then fsync.
7. **Verify** the staged archive completely, before any of it reaches the synced folder: decrypt, decompress, parse every tar entry against the index, compare every file's size and SHA-256, check the end of the stream, and the ciphertext's size and SHA-256. Any problem: the staged file is deleted and the run fails; nothing in the vault changed.
8. **Move in**: flush the staged archive to the drive itself (F_FULLFSYNC on macOS, where plain fsync can leave it in the drive's cache), rename it to `archives/<id>.bba` (atomic) and flush the `archives/` folder, so an index can never survive a power cut that its archive does not; then write the index `archives/<id>.bbs` through staging and read it back. Across volumes (the vault on another disk than the app's data folder) the archive is first copied into this run's own subfolder `<vault>/.staging/<random id>/`, flushed, read back and compared with the verified SHA-256, then renamed. Limitation of that fallback: while the copy is written, a sync client can see a growing file of the archive's full size in `.staging` and may start uploading it; it is gone when the run ends (after a crash, the next run of the set deletes `.staging`). Every writer (a run, a rename, a take over) stages in its own subfolder and removes only that one, so a quick write never deletes a running backup's copy. A cancel during steps 6 and 7 leaves nothing behind; once step 8 starts, its two renames always finish.
9. Retention (below), then rewrite `HOW-TO-RESTORE.txt`.

A crash can leave at worst a staging file (deleted at the next start) or, between the two renames of step 8, an archive without its index; a later run deletes such an archive once it is 48 hours older than the newest complete version (so a pair still arriving from another computer through sync is never cut short).

### A file that changes during a run

The tar header declares the size the walk saw before the data follows, so the archive can never hold more or fewer bytes than declared:

- a file that shrank is padded with zeros to the declared size,
- a file that grew is cut at the declared size,
- a file whose size or modification time differs after reading (checked on the open handle), or that could not be read to the end, is also marked.

Such an entry gets `"c": true`, `h` is the hash of what was stored, the run records a warning in Activity ("... changed while being saved. The next backup saves it again"), verification passes (the archive matches its index), a restore brings the stored bytes back with a note that the copy may be incomplete (and never replaces an existing file with it, even under Replace: it is restored next to it), and the next run writes a new archive to save the file again. When that copy is marked again with the same size and time (part of the file could not be read again), the warning says "It is saved again when it changes" and later runs wait for its size or time to change (step 4).

### Online-only cloud files

Cloud clients can keep a file's name and size on this computer while its content stays in the cloud until something opens it: iCloud Drive with "Optimize Mac Storage" and File Provider clients such as OneDrive on macOS (a dataless file, `st_flags` bit `SF_DATALESS` 0x40000000), OneDrive Files On-Demand and Known Folder Move on Windows (attributes `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` 0x400000, `FILE_ATTRIBUTE_RECALL_ON_OPEN` 0x40000 or `FILE_ATTRIBUTE_OFFLINE` 0x1000). Every archive reads every file, so opening them would download them all at each changed run (and fail while offline).

The walk reads these bits from the entry's own metadata, which does not download anything, and a version 2 run never opens such a file: it is listed in the index without content (no `h`) and not counted as skipped. Every run reports them: the run summary ends with ", N online-only files not backed up" and the set shows a warning ("N online-only files not backed up") while there are any; a notification follows only when their number grows. Activity adds a warning when an archive is saved or the number changes, "N files in Documents are online-only (kept in the cloud, not on this computer), so they were not downloaded and are not in this backup. To back them up, make them available on this computer (in OneDrive: Always keep on this device; in iCloud Drive: Keep Downloaded)", with the list. It never makes a run write an archive by itself (step 4). Retention keeps no older copy for it: its content is in the user's cloud account with that service's own version history, and protecting the last copy of each file would keep one more full archive for every day on which some file went online-only (OneDrive Storage Sense, macOS evicting File Provider files), without limit. A copy saved earlier stays only as long as retention keeps its archive. When the file is on this computer again (opened, or "Always keep on this device"), the next run stores it. Version 1 vaults are unchanged: they read only files whose size or time changed, and a file that cannot be read keeps its previous entry.

### Retention

Only versions whose index decrypts count; other files in `archives/` (sync conflict copies, planted files) are never listed, never the newest and never deleted.

- Always keep the 2 newest archives dated at most 10 minutes past the run's clock (the baseline and the version before it). A version dated later (a clock that was ahead once, see "Snapshot index") is kept until real time reaches it, and counts neither among the 2 newest nor as a day's newest.
- Within `retention_days`: keep the newest archive of each calendar day (local time of the writing device).
- Also keep, for anything this run could not read (a locked file, an unreadable folder, a source folder that is missing, e.g. an unplugged drive) and every file the newest version lists without content because it could not be opened, the newest other version that holds it, so its last copy never ages out while it cannot be read. A version holds a file when it stores it with content, and a folder when it stores a file or link below it (every version written while a folder cannot be read still lists the folder itself). Online-only files are not protected (see "Online-only cloud files"). This is looked up only when a version is due for deletion.
- Delete the rest, the index first and then its archive.
- `retention_days` 0 keeps everything. New sets default to 7 days, because every archive is a full copy (7 for new installs; an install upgraded from 1.0.x keeps the default saved in its settings, 30 unless the user changed it).
- So 7 days with a run every hour keeps about 9 archives: the newest of each of the 8 calendar days the 7-day window touches, plus the second newest. The app says "keeps one per day for the last 7 days, plus the two newest".

There is no garbage collection: an archive belongs to exactly one version.

### Restore

- List versions from the indexes (no archive is read); browse from an index, as v1.
- Restore selected entries in one pass over the version's archive: folders and links come from the index (as v1), files from the archive. Every archive entry is checked against the index entry expected next (a name, type, size or link target that differs is damage and ends the pass there). Selected files go through every v1 rule: path validation, Original-location guard (see "Restore" above), keep both or replace, identical files skipped, temp file readable by the owner only, SHA-256 checked against `h`, then times, modes and attributes. A copy marked `c` never replaces an existing file (it is kept next to it, with a note), and files listed without content are not restored (one note says how many). Small files (up to 256 KB) are written by a few worker threads (at most 64 queued, about 16 MB); larger ones stream straight from the archive into their temp file. The pass ends after the last selected file, and progress counts archive bytes read.
- A missing archive fails the restore with "The archive for this version is not in the backup folder. If the folder is still syncing, wait for it to finish, then try again." A damaged one restores everything before the damage and reports the rest.

### Verify

- After every run, before the archive is moved in (step 7 above, always on for version 2).
- "Verify backup" reads the newest version's archive (picked like the baseline, step 2 of the run) completely in the same way and reports damaged or unchecked files by path. A damaged or missing newest archive makes the next run write a complete new one even when nothing changed.

### Known-answer vectors

`tests/fixtures/vault-test-vectors.json` (the vectors published with this format) has a `v2` section: `vault.bbv` version 2, the kind 3 header, a tiny archive (its tar stream, the zstd bytes our writer produced, the encrypted file) and its index. The app checks them with its own engine and with a separate Node.js implementation; backupbase-restore checks them in `tests/vectors.rs`. The zstd bytes are stored, not recomputed: another zstd version may compress differently, which is allowed; what is frozen is the tar stream, the encryption of the stored bytes, and that they decompress to the tar stream.
