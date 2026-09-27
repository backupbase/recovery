//! Adversarial review cases (2026-09-26). Each test states a promise from README.md or
//! SECURITY.md and tries to break it. A failing test here is a real problem to fix.

mod common;

#[cfg(unix)]
use std::fs;
use std::path::Path;

use common::*;

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

const ID1: &str = "20260925T150000Z-00000001";

/// README: "Symbolic links are created last, and only when they point inside the target
/// folder." SECURITY.md: "links are created last and only when they point inside the target
/// folder." The check resolves each target as text, so a link that goes through another
/// restored link can point outside the target.
#[cfg(unix)]
#[test]
fn a_chain_of_links_never_points_outside_the_target() {
    for version in [1u8, 2] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let vault = TestVault::create(&root.join("dest").join("Documents"), version);
        // up -> ".." is the restore folder itself (inside). esc -> "up/.." is the restore
        // folder's parent once "up" is a link, but "inside" when read as text.
        let items = [link("up", ".."), link("esc", "up/.."), link("esc2", "up/../../..")];
        if version == 1 {
            vault.v1_version(ID1, &items);
        } else {
            vault.v2_version(ID1, &items);
        }
        let to = root.join("restore");
        let o = run(&["restore", s(&vault.dir), "--to", s(&to)]);
        let target = fs::canonicalize(&to).unwrap();
        for name in ["esc", "esc2"] {
            let p = target.join("Documents").join(name);
            if let Ok(real) = fs::canonicalize(&p) {
                assert!(real.starts_with(&target), "v{version}: Documents/{name} was created and resolves to {} outside {}\n{}", real.display(), target.display(), stdout(&o));
            }
        }
    }
}

/// README: "It never restores into the backup folder itself." SECURITY.md: "It never ...
/// writes into the backup folder." The check only refuses a target inside the backup, not a
/// target that holds it: restoring into the folder that holds the backups (the synced
/// "Backup Base" folder) with --keep-both walks into the backup when the backup folder and
/// the backed-up folder share a name, which is the usual case (a set is named after its
/// folder), and writes unencrypted files into the synced backup folder.
#[test]
fn never_writes_into_the_backup_folder_when_the_target_holds_it() {
    for version in [1u8, 2] {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("Backup Base");
        let vault = TestVault::create(&dest.join("Documents"), version);
        let items = [dir("Contracts"), file("Contracts/nda.txt", b"secret contract text")];
        if version == 1 {
            vault.v1_version(ID1, &items);
        } else {
            vault.v2_version(ID1, &items);
        }
        let o = run(&["restore", s(&vault.dir), "--to", s(&dest), "--keep-both"]);
        let leaked = vault.dir.join("Contracts").join("nda.txt");
        assert!(!leaked.exists(), "v{version}: exit {:?}, an unencrypted file was written into the backup folder: {}\n{}{}", o.status.code(), leaked.display(), stdout(&o), stderr(&o));
    }
}

/// SECURITY.md: "every error ends in a message, not a crash". A pax record whose length
/// field overflows makes the tar reader index out of bounds (release builds wrap the
/// addition). The panic is caught, so this shows as an internal error (exit 1), not as
/// damage (exit 5). Needs the key, so only a vault made by someone who knows the passcode.
#[test]
fn a_hostile_pax_length_is_damage_not_an_internal_error() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = TestVault::create(&tmp.path().join("dest").join("Documents"), 2);
    let mut tar = TarW::default();
    tar.dir("r0/");
    // Two records. The first (12 bytes) ends in two newlines; the second claims a length of
    // usize::MAX, so pos + len wraps to 11, passes the bounds check, and data[10] is '\n'.
    let mut rec2 = "12 a=bcdef\n\n".to_string().into_bytes();
    assert_eq!(rec2.len(), 12);
    rec2.extend(format!("{} path=x\n", usize::MAX).into_bytes());
    tar.raw_header("././@PaxHeader", b'x', rec2.len() as u64, "", 0o644);
    tar.buf.extend(&rec2);
    while tar.buf.len() % 512 != 0 {
        tar.buf.push(0);
    }
    tar.raw_header("r0/x", b'0', 0, "", 0o644);
    let archive = encrypt(&vault.k_data, 3, true, 16, [3; 24], &zstd(&tar.finish()));
    let entries = vec![
        serde_json::json!({"r":0,"p":"","k":"d","m":1758812400000i64,"mode":493}),
        serde_json::json!({"r":0,"p":"x","k":"f","s":0,"m":1758812400000i64,"mode":420,"h":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
    ];
    vault.v2_raw(ID1, entries, archive);
    let o = run(&["verify", s(&vault.dir)]);
    assert_eq!(o.status.code(), Some(5), "{}{}", stdout(&o), stderr(&o));
}

/// A FIFO planted where a version's archive should be makes every command that opens it
/// wait forever (File::open on a FIFO blocks until a writer appears). Anyone who can write
/// the synced folder can plant one. Runs the tool with a timeout.
#[cfg(unix)]
#[test]
fn a_fifo_in_place_of_the_archive_does_not_hang() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let tmp = tempfile::tempdir().unwrap();
    let vault = TestVault::create(&tmp.path().join("dest").join("Documents"), 2);
    vault.v2_version(ID1, &[file("a.txt", b"hello")]);
    let bba = vault.index_dir().join(format!("{ID1}.bba"));
    fs::remove_file(&bba).unwrap();
    let st = Command::new("mkfifo").arg(&bba).status().unwrap();
    assert!(st.success());
    let mut child = Command::new(bin()).args(["verify", s(&vault.dir)]).env("BB_PASSCODE", PASS).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            panic!("verify still waiting after 10 s on a FIFO planted as the archive");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
