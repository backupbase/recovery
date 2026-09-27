//! Review of the Windows tester fixes: a target above the folder that holds the backup is
//! accepted (by design), but the backed-up folder's name can lead the restore into that
//! folder, or into a folder that holds another backup. Nothing may be written there.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::*;

const ID1: &str = "20260925T150000Z-00000001";

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
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

/// The backed-up folder is named "Documents", like the folder that holds the backup
/// (root/cloud/Documents/Vault). Restoring into root/cloud with --keep-both puts the files
/// into root/cloud/Documents, next to the backup.
#[test]
fn the_backed_up_folder_name_never_leads_into_the_folder_that_holds_the_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = fs::canonicalize(tmp.path()).unwrap();
    let holder = root.join("cloud").join("Documents");
    let vault = TestVault::create(&holder.join("Vault"), 2);
    fs::write(holder.join("HOW-TO-RESTORE.txt"), b"how to restore").unwrap();
    vault.v2_version(ID1, &[dir("Contracts"), file("Contracts/nda.txt", b"secret contract text")]);
    let before = files(&holder);

    let o = run(&["restore", s(&vault.dir), "--to", s(&root.join("cloud")), "--keep-both"]);
    assert_ne!(o.status.code(), Some(0), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(files(&holder), before, "plaintext was written into the folder that holds the backup: {}{}", stdout(&o), stderr(&o));
    assert_eq!(o.status.code(), Some(6), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("Documents holds a Backup Base backup folder, and nothing is restored next to one"), "{}", stdout(&o));
}

/// The same through a folder that holds another backup (not the one being read).
#[test]
fn the_backed_up_folder_name_never_leads_into_a_folder_that_holds_another_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = fs::canonicalize(tmp.path()).unwrap();
    let vault = TestVault::create(&root.join("mine").join("Vault"), 2);
    vault.v2_version(ID1, &[dir("Contracts"), file("Contracts/nda.txt", b"secret contract text")]);
    let other = root.join("target").join("Documents");
    let o2 = TestVault::create(&other.join("Pictures"), 1);
    o2.v1_version(ID1, &[file("p.jpg", b"picture")]);
    let before = files(&other);

    let o = run(&["restore", s(&vault.dir), "--to", s(&root.join("target")), "--keep-both"]);
    assert_ne!(o.status.code(), Some(0), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(files(&other), before, "plaintext was written into a folder that holds a backup: {}{}", stdout(&o), stderr(&o));
    assert_eq!(o.status.code(), Some(6), "{}{}", stdout(&o), stderr(&o));
}

/// A `..` after a folder that does not exist yet climbs past the nearest existing folder:
/// the target is judged where it really lands, before anything is created.
#[test]
fn a_target_that_climbs_past_a_new_folder_is_judged_where_it_lands() {
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = fs::canonicalize(tmp.path()).unwrap();
    let holder = root.join("OneDrive").join("Backup Base");
    let vault = TestVault::create(&holder.join("Documents"), 2);
    vault.v2_version(ID1, &[file("a.txt", b"secret")]);
    fs::create_dir_all(root.join("OneDrive").join("Other")).unwrap();
    let to = root.join("OneDrive").join("Other").join("nonexist").join("..").join("..").join("Backup Base").join("new2");
    let o = run(&["restore", s(&vault.dir), "--to", s(&to)]);
    assert_eq!(o.status.code(), Some(2), "{}{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("Choose a folder outside the backup folder"), "{}", stderr(&o));
    assert!(!holder.join("new2").exists() && !root.join("OneDrive/Other/nonexist").exists(), "nothing is created");
}

/// A target that is a link to a folder that does not exist yet (in the folder that holds the
/// backup): whatever the folder creation made there is removed again.
#[cfg(unix)]
#[test]
fn a_dangling_link_target_leaves_nothing_in_the_backup_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = fs::canonicalize(tmp.path()).unwrap();
    let holder = root.join("Backup Base");
    let vault = TestVault::create(&holder.join("Documents"), 2);
    vault.v2_version(ID1, &[file("a.txt", b"secret")]);
    std::os::unix::fs::symlink(holder.join("Planted"), root.join("dang")).unwrap();
    let to = format!("{}/", s(&root.join("dang")));
    let o = run(&["restore", s(&vault.dir), "--to", &to]);
    assert_ne!(o.status.code(), Some(0), "{}{}", stdout(&o), stderr(&o));
    assert!(!holder.join("Planted").exists(), "a folder was left in the folder that holds the backup");
}

/// A passcode file in UTF-16 without a byte order mark gets the encoding message, not
/// "wrong passcode".
#[test]
fn a_passcode_file_in_another_encoding_says_so() {
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = fs::canonicalize(tmp.path()).unwrap();
    let vault = TestVault::create(&root.join("Documents"), 2);
    vault.v2_version(ID1, &[file("a.txt", b"a")]);
    let pf = root.join("pass.txt");
    fs::write(&pf, format!("{PASS}\r\n").encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>()).unwrap();
    let o = std::process::Command::new(bin()).args(["verify", s(&vault.dir), "--passcode-file", s(&pf)]).env_remove("BB_PASSCODE").output().unwrap();
    assert_eq!(o.status.code(), Some(2), "{}{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("The passcode file is not UTF-8 or UTF-16 text."), "{}", stderr(&o));
}
