//! Findings from the Windows tester (2026-09-26, Windows 11, commit 75cf351), one test each:
//! the folder that holds the backup is never a target, a damaged newest version ends in exit
//! code 5, UTF-16 passcode files work, and Ctrl+C removes the file being written.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::*;

const ID1: &str = "20260925T150000Z-00000001";
const ID2: &str = "20260926T150000Z-00000002";
const REFUSED: &str = "Choose a folder outside the backup folder";

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// root/dest (the synced "Backup Base" folder) holds HOW-TO-RESTORE.txt and the backup
/// root/dest/Documents.
fn setup() -> (tempfile::TempDir, PathBuf, TestVault) {
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let dest = root.join("dest");
    let vault = TestVault::create(&dest.join("Documents"), 2);
    fs::write(dest.join("HOW-TO-RESTORE.txt"), b"how to restore").unwrap();
    vault.v2_version(ID1, &[dir("Contracts"), file("Contracts/nda.txt", b"secret contract text")]);
    (tmp, root, vault)
}

fn refused(vault: &TestVault, to: &Path, keep_both: bool) {
    let mut args = vec!["restore", s(&vault.dir), "--to", s(to)];
    if keep_both {
        args.push("--keep-both");
    }
    let o = run(&args);
    assert_eq!(o.status.code(), Some(2), "{}: {}{}", to.display(), stdout(&o), stderr(&o));
    assert!(stderr(&o).contains(REFUSED), "{}", stderr(&o));
}

/// Every file below `dir` (relative, `/`-separated).
fn files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    fn rec(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for d in rd.flatten() {
            let p = d.path();
            if d.file_type().unwrap().is_dir() {
                rec(root, &p, out);
            } else {
                out.push(p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
            }
        }
    }
    rec(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
fn the_folder_that_holds_the_backup_is_never_a_target() {
    let (_tmp, root, vault) = setup();
    let dest = root.join("dest");
    let before = files(&dest);
    // The folder itself (with --keep-both), a new folder in it, a new folder deeper in it, an
    // empty folder in it, and a path that climbs back into it.
    fs::create_dir_all(dest.join("Empty")).unwrap();
    refused(&vault, &dest, true);
    refused(&vault, &dest.join("Restored"), false);
    refused(&vault, &dest.join("Restored").join("deeper"), false);
    refused(&vault, &dest.join("Empty"), false);
    refused(&vault, &root.join("elsewhere").join("..").join("dest").join("Restored"), false);
    // Spelled with other capitals, on a disk that ignores case (macOS and Windows by default).
    if root.join("DEST").exists() {
        refused(&vault, &root.join("DEST").join("Restored"), false);
    }
    // Through a symbolic link to it.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&dest, root.join("alias")).unwrap();
        refused(&vault, &root.join("alias").join("Restored"), false);
    }
    assert!(!dest.join("Restored").exists() && !root.join("elsewhere").exists(), "nothing is created");
    assert_eq!(files(&dest), before, "nothing was written into the folder that holds the backup");

    // Folders next to it are fine, including one whose name starts the same way.
    for to in [root.join("out"), root.join("dest-restored")] {
        let o = run(&["restore", s(&vault.dir), "--to", s(&to)]);
        assert_eq!(o.status.code(), Some(0), "{}: {}{}", to.display(), stdout(&o), stderr(&o));
        assert_eq!(fs::read(to.join("Documents/Contracts/nda.txt")).unwrap(), b"secret contract text");
    }
}

#[test]
fn a_folder_that_holds_another_backup_is_never_a_target() {
    let (_tmp, root, vault) = setup();
    // Another synced folder with a backup in it (not the one being read).
    let other = root.join("OneDrive").join("Backup Base");
    let o2 = TestVault::create(&other.join("Pictures"), 1);
    o2.v1_version(ID1, &[file("p.jpg", b"picture")]);
    refused(&vault, &other, true);
    refused(&vault, &other.join("Restored"), false);
    assert!(!other.join("Restored").exists(), "nothing is created");
    // Today's refusals stay: inside the backup being read, and inside another backup.
    refused(&vault, &vault.dir.join("x"), false);
    refused(&vault, &other.join("Pictures").join("x"), false);
}

/// The newest version's index is damaged: the newest readable version is used, with a
/// warning and exit code 5, for restore and files alike.
#[test]
fn a_damaged_newest_version_ends_in_exit_code_5() {
    let (_tmp, root, vault) = setup();
    vault.v2_version(ID2, &[dir("Contracts"), file("Contracts/nda.txt", b"newer contract text")]);
    let bbs = vault.index_dir().join(format!("{ID2}.bbs"));
    let mut bytes = fs::read(&bbs).unwrap();
    let n = bytes.len();
    bytes[n - 5] ^= 1;
    fs::write(&bbs, bytes).unwrap();

    let to = root.join("out");
    let o = run(&["restore", s(&vault.dir), "--to", s(&to)]);
    assert_eq!(o.status.code(), Some(5), "{}{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains(&format!("Warning: version {ID2} could not be read")) && stderr(&o).contains(&format!("the newest version that can be read, {ID1}, is used")), "{}", stderr(&o));
    assert!(stdout(&o).contains("Warning: 1 version newer than this one could not be read"), "{}", stdout(&o));
    assert_eq!(fs::read(to.join("Documents/Contracts/nda.txt")).unwrap(), b"secret contract text");

    let o = run(&["files", s(&vault.dir)]);
    assert_eq!(o.status.code(), Some(5), "{}{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("Warning: version") && stdout(&o).contains("Contracts/nda.txt"), "{}{}", stdout(&o), stderr(&o));

    // Asking for the older version by name is not damage.
    let o = run(&["restore", s(&vault.dir), "--to", s(&root.join("out2")), "--version", ID1]);
    assert_eq!(o.status.code(), Some(0), "{}{}", stdout(&o), stderr(&o));
    assert!(!stderr(&o).contains("Warning"), "{}", stderr(&o));
}

/// Windows PowerShell 5.1 writes `"text" > file` and Out-File as UTF-16LE with a byte order mark.
#[test]
fn utf16_passcode_files_are_read() {
    let (_tmp, root, vault) = setup();
    let text = format!("{PASS}\r\n");
    let le: Vec<u8> = [0xFF, 0xFE].into_iter().chain(text.encode_utf16().flat_map(u16::to_le_bytes)).collect();
    let be: Vec<u8> = [0xFE, 0xFF].into_iter().chain(text.encode_utf16().flat_map(u16::to_be_bytes)).collect();
    for (name, bytes) in [("le.txt", le), ("be.txt", be)] {
        let pf = root.join(name);
        fs::write(&pf, bytes).unwrap();
        let o = std::process::Command::new(bin()).args(["verify", s(&vault.dir), "--passcode-file", s(&pf)]).env_remove("BB_PASSCODE").output().unwrap();
        assert_eq!(o.status.code(), Some(0), "{name}: {}{}", stdout(&o), stderr(&o));
    }
    let pf = root.join("bad.txt");
    fs::write(&pf, b"\xFF\xFEa").unwrap();
    let o = std::process::Command::new(bin()).args(["verify", s(&vault.dir), "--passcode-file", s(&pf)]).env_remove("BB_PASSCODE").output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("The passcode file is not UTF-8 or UTF-16 text."), "{}", stderr(&o));
}

/// A backup with a small file and then a 512 MiB file (stored as a tiny blob), for Ctrl+C.
#[cfg(unix)]
fn big_backup(root: &Path) -> TestVault {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    let vault = TestVault::create(&root.join("dest").join("Documents"), 1);
    // 512 MiB of zeros as a tiny zstd frame of RLE blocks (window 128 KiB).
    let size: u64 = 512 << 20;
    let block: u32 = 128 << 10;
    let n = size / block as u64;
    let mut frame = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x38];
    for i in 0..n {
        let header = (i == n - 1) as u32 | (1 << 1) | (block << 3);
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.push(0);
    }
    let mut h = Sha256::new();
    let zeros = vec![0u8; block as usize];
    for _ in 0..n {
        h.update(&zeros);
    }
    let sha: [u8; 32] = h.finalize().into();
    let id = bbrestore::crypto::blob_id(&vault.k_name, &sha);
    let blob_dir = vault.dir.join("data").join(&id[..2]);
    fs::create_dir_all(&blob_dir).unwrap();
    fs::write(blob_dir.join(format!("{id}.bbk")), encrypt(&vault.k_data, 1, true, 16, [5; 24], &frame)).unwrap();
    let big = json!({"r":0,"p":"big.bin","k":"f","s":size,"m":1758812401000i64,"mode":420,"h":bbrestore::crypto::hex(&sha),"b":id});
    vault.v1_version(ID1, &[file("a.txt", b"small file restored first"), Item::Raw(big)]);
    vault
}

/// Waits until the large file's temporary file in `docs` has some data, then sends SIGINT.
#[cfg(unix)]
fn ctrl_c_while_writing(docs: &Path, pid: u32) {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    loop {
        let writing = fs::read_dir(docs).map(|rd| rd.flatten().any(|d| d.file_name().to_string_lossy().starts_with(".bbrestore-") && d.metadata().is_ok_and(|m| m.len() > 1 << 20))).unwrap_or(false);
        if writing {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "the large file was never being written");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(std::process::Command::new("kill").args(["-INT", &pid.to_string()]).status().unwrap().success());
}

/// Ctrl+C (SIGINT) while a large file is written: the temporary file is removed, the files
/// already restored stay, and the exit code is 130.
#[cfg(unix)]
#[test]
fn ctrl_c_removes_the_file_being_written() {
    use std::process::{Command, Stdio};

    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let vault = big_backup(&root);
    let to = root.join("out");
    let child = Command::new(bin()).args(["restore", s(&vault.dir), "--to", s(&to)]).env("BB_PASSCODE", PASS).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let docs = to.join("Documents");
    ctrl_c_while_writing(&docs, child.id());
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(130), "{}{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("Stopped: 1 of 2 files restored. Files already restored are complete."), "{}", stderr(&o));
    assert_eq!(files(&to), vec!["Documents/a.txt"], "no temporary file is left");
    assert_eq!(fs::read(docs.join("a.txt")).unwrap(), b"small file restored first");
}

/// Ctrl+C that was ignored when the tool started (nohup, a background job) stays ignored.
#[cfg(unix)]
#[test]
fn an_ignored_ctrl_c_stays_ignored() {
    use std::process::{Command, Stdio};

    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let vault = big_backup(&root);
    let to = root.join("out");
    let child = Command::new("sh")
        .args(["-c", "trap '' INT; exec \"$0\" \"$@\"", bin(), "restore", s(&vault.dir), "--to", s(&to)])
        .env("BB_PASSCODE", PASS)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ctrl_c_while_writing(&to.join("Documents"), child.id());
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(fs::metadata(to.join("Documents/big.bin")).unwrap().len(), 512 << 20);
}
