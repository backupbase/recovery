# Security

## Reporting a problem

Please email **team@backupbase.org** about any security problem in backupbase-restore or in the backup format ([FORMAT.md](FORMAT.md)), for example a way to make the tool write outside the folder it restores into, read something it should not, or accept a damaged or changed backup as valid.

Please do not open a public issue for a security problem. Include the version (`backupbase-restore --version`), your operating system, and the steps or a small sample that shows the problem. Never send your passcode or real backups; a sample made with a test passcode is enough.

We confirm that we received your report, keep you informed while we fix it, and credit you in the changelog if you wish.

## Supported versions

Fixes go into the latest release. Older releases keep working for restores, since the format does not change under them; upgrade to get fixes.

## What the tool does to stay safe

- It never connects to a network and never writes into the backup folder, into the folder that holds it (the synced "Backup Base" folder), into any folder that holds a `vault.bbv`, or into a folder that holds a backup folder. Target folders are compared by their real path (links resolved; on Windows ignoring case), and a target that does not exist yet is judged by the nearest folder above it that does. With `--keep-both`, a folder already in the target that is one of these (the backed-up folder's name can lead there) is skipped, not written into. It cannot know which other folders a sync app uploads, so the README asks you to restore outside your cloud folder.
- Ctrl+C stops a restore at the next piece of data and removes the unencrypted temporary file being written. A second Ctrl+C, a crash or a power cut can still leave one behind.
- It never overwrites a file, never writes outside the target folder, and never writes through a symbolic link; links are created last and only when they point inside the target folder: a link target may use `..` only at its start, and may not go through a link that was already in the folder.
- Every stored file is authenticated (AES-256-GCM) and checked against its SHA-256 before it gets its name.
- It limits what a damaged or hostile backup can make it do: key derivation settings, index sizes and compression windows are bounded as FORMAT.md states, and every error ends in a message, not a crash.
- Names and labels from a backup are printed with control characters replaced, so they cannot send commands to your terminal.
- The passcode is never printed or logged, and keys are wiped from memory when they are no longer needed.
