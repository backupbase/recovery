# Sample backups (macOS)

Two small backups made by the Backup Base app's backup engine (version 1.1.0) on macOS, for testing backupbase-restore on any computer. Test data only.

- Passcode: `Recovery-Fixture-2026!-Granite-Walrus`
- `backups/Fixture v1`: format version 1 (one encrypted file per file), two versions.
- `backups/Fixture v2`: format version 2 (one encrypted archive per run), two versions.
- `manifests/<backup>/<version>.json`: every file, folder and link of that version as it was on the Mac when the version was made (path relative to the restore folder, size, SHA-256, modification time in Unix milliseconds, permissions).

The tree includes a Unicode name, a path longer than 260 characters, an empty folder, an empty file, a file larger than one encryption segment, read-only and executable files, a name with characters Windows does not allow (`Q&A: notes?.txt`), a name Windows reserves (`aux.txt`), a link inside the backup and a link pointing outside it. Version 2 edits a file, adds one, deletes one and renames one.

`tests/fixtures.rs` restores every version and compares it with its manifest. On Windows the expected differences are that `Q&A: notes?.txt` comes back as `Q&A_ notes_.txt`, `aux.txt` is refused (exit code 6), and links are not created.

```sh
backupbase-restore list fixtures/macos/backups
```
