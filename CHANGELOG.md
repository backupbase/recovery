# Changelog

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
