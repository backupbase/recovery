# Changelog

## 0.1.3 (2026-09-29)

- A backed-up folder whose name starts with a dot is restored under its own name: `~/.ssh` goes to `<target>/.ssh`, not `<target>/ssh`, and `~/.claude` backed up next to `~/claude` goes to `<target>/.claude`, not `<target>/claude (2)`. Backup Base 1.1.3 and earlier recorded these names without the dot, so the folder name now comes from the last part of the folder's original path (made on macOS or Windows alike), and from the recorded name only when the path gives no usable one. `files` shows the same names.
- `--path` takes these names. A `--path` that matches nothing is also tried with the recorded names, so `--path ssh/config` still works for a backup made before Backup Base 1.1.4 when no backed-up folder now has the name `ssh` (a folder now named `ssh`, such as `~/ssh`, wins).
- A macOS folder whose name contains `\` keeps it (only a path made on Windows is split on `\`). Folder names that differ only in Unicode form (`café` typed two ways) are made unique like names that differ only in case, and a ` (2)` suffix no longer makes a long name go past 255 bytes.
- A backed-up folder with no usable name is restored as `Folder <n>` counting from 1, as the app does (it counted from 0).
- On Windows, a folder that was hidden when it was backed up (such as a dot folder) is hidden again after the restore, as files already were and as the app does.

## 0.1.2 (2026-09-28)

Documentation only, no code changes: the README says precisely who wrote this implementation, and suggests keeping a copy of the tool, `SHA256SUMS` and `FORMAT.md` next to your backups.

## 0.1.1 (2026-09-27)

First release. (0.1.0 was published for about an hour and withdrawn; 0.1.1 has the same code.)

- Reads backup format version 1 (one encrypted file per file, Backup Base 1.0.x) and version 2 (one encrypted archive per run, Backup Base 1.1.0 and later).
- Commands: `list`, `files`, `restore`, `verify`.
- Restores never overwrite: a new or empty target folder, or `--keep-both`.
- Never restores into a backup folder, into the folder that holds the backup being read (the synced "Backup Base" folder), into a folder that holds a backup folder, or into anything inside those (exit code 2). With `--keep-both`, such a folder found inside the target is skipped and listed (exit code 6). Paths are compared by their real path, on Windows ignoring case, and a target that does not exist yet is judged by the nearest folder above it.
- Restores file contents (checked against their SHA-256), modification times, read-only settings and, on macOS and Linux, permissions and symbolic links that point inside the target folder.
- When the newest version cannot be read, `restore` and `files` use the newest version that can be read, print a warning and end with exit code 5 (as `verify` does).
- Ctrl+C stops a restore at the next piece of data, removes the temporary file being written, says how many files were restored, and ends with exit code 130. A second Ctrl+C stops at once.
- `list` ends with exit code 5 when a version's index is damaged.
- Passcode from a prompt that does not show what is typed, the `BB_PASSCODE` environment variable, or `--passcode-file` (UTF-8, or UTF-16 with a byte order mark as Windows PowerShell 5.1 writes it).
- Tested against the format's known-answer vectors and against backups made by the Backup Base app on macOS and Windows.
