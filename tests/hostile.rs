//! Damaged and hostile vaults: every case ends in a clean message and the right exit code,
//! and nothing is ever written outside the target folder.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use bbrestore::error::Kind;
use bbrestore::vault::VaultHeader;
use common::*;
use serde_json::json;

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut v = Vec::with_capacity(len + 8);
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(len);
    v
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Every path under `root` (relative, `/`-separated).
fn tree(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    fn rec(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for d in rd.flatten() {
            let p = d.path();
            out.push(p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
            if d.file_type().unwrap().is_dir() {
                rec(root, &p, out);
            }
        }
    }
    rec(root, root, &mut out);
    out.sort();
    out
}

struct Case {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    vault: TestVault,
}

fn case(version: u8) -> Case {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let vault = TestVault::create(&root.join("dest").join("Documents"), version);
    Case { _tmp: tmp, root, vault }
}

const ID1: &str = "20260925T150000Z-00000001";
const ID2: &str = "20260926T150000Z-00000002";

#[test]
fn traversal_and_absolute_paths_are_refused() {
    for version in [1u8, 2] {
        let c = case(version);
        let items = [file("../evil.txt", b"evil"), file("a/../../evil2.txt", b"evil"), dir("ok"), file("ok/./x.txt", b"evil"), file("ok/good.txt", b"good")];
        if version == 1 {
            c.vault.v1_version(ID1, &items);
        } else {
            c.vault.v2_version(ID1, &items);
        }
        let to = c.root.join("restore").join("here");
        let o = run(&["restore", s(&c.vault.dir), "--to", s(&to)]);
        assert_eq!(o.status.code(), Some(6), "v{version}: {}{}", stdout(&o), stderr(&o));
        let out = stdout(&o);
        assert!(out.contains("../evil.txt: not restored, its path is not a safe relative path"), "{out}");
        assert!(out.contains("ok/./x.txt: not restored"), "{out}");
        assert_eq!(tree(&c.root.join("restore")), vec!["here", "here/Documents", "here/Documents/ok", "here/Documents/ok/good.txt"], "v{version}");
        assert!(!c.root.join("evil.txt").exists() && !c.root.join("restore/evil.txt").exists() && !c.root.join("restore/evil2.txt").exists());
    }
}

#[test]
fn absolute_entry_path_is_refused() {
    let c = case(1);
    let (h, b) = c.vault.write_blob(b"abs");
    c.vault.v1_version(ID1, &[Item::Raw(json!({"r":0,"p":"/tmp/abs.txt","k":"f","s":3,"m":0,"h":h,"b":b})), file("fine.txt", b"fine")]);
    let to = c.root.join("out");
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to)]);
    assert_eq!(o.status.code(), Some(6), "{}", stdout(&o));
    assert!(stdout(&o).contains("Documents//tmp/abs.txt: not restored"), "{}", stdout(&o));
    assert_eq!(tree(&to), vec!["Documents", "Documents/fine.txt"]);
}

#[cfg(unix)]
#[test]
fn links_are_created_last_and_only_inside_the_target() {
    for version in [1u8, 2] {
        let c = case(version);
        let items = [
            dir("sub"),
            link("sub/inside", "../top.txt"),
            link("sub/outside", "../../../etc/passwd"),
            link("sub/absolute", "/etc/passwd"),
            // A link and then a file "through" it: the file lands in a real folder.
            link("tricky", "sub"),
            file("tricky/f.txt", b"f"),
            file("top.txt", b"top"),
        ];
        if version == 1 {
            c.vault.v1_version(ID1, &items);
        } else {
            c.vault.v2_version(ID1, &items);
        }
        let to = c.root.join("out");
        let o = run(&["restore", s(&c.vault.dir), "--to", s(&to)]);
        assert_eq!(o.status.code(), Some(0), "v{version}: {}{}", stdout(&o), stderr(&o));
        let out = stdout(&o);
        assert!(out.contains("Documents/sub/outside: it points outside the restore folder (../../../etc/passwd)"), "{out}");
        assert!(out.contains("Documents/sub/absolute: it points outside the restore folder (/etc/passwd)"), "{out}");
        assert!(out.contains("Documents/tricky  saved as  tricky (restored)"), "{out}");
        let d = to.join("Documents");
        assert_eq!(fs::read(d.join("sub/inside")).unwrap(), b"top");
        assert!(fs::symlink_metadata(d.join("tricky")).unwrap().is_dir());
        assert_eq!(fs::read(d.join("tricky/f.txt")).unwrap(), b"f");
        assert_eq!(fs::read_link(d.join("tricky (restored)")).unwrap().to_str().unwrap(), "sub");
        assert!(fs::symlink_metadata(d.join("sub/outside")).is_err());
    }
}

#[test]
fn not_stored_and_incomplete_entries_are_reported() {
    let c = case(2);
    c.vault.v2_version(
        ID1,
        &[
            file("a.txt", b"aaa"),
            Item::Raw(json!({"r":0,"p":"locked.xlsx","k":"f","s":10,"m":1758812401000i64,"mode":420})),
            file("z.txt", b"zzz"),
        ],
    );
    // Mark z.txt as possibly incomplete: rewrite the index with "c": true.
    let v = {
        let mut tar = TarW::default();
        tar.dir("r0/");
        tar.file("r0/a.txt", b"aaa");
        tar.file("r0/z.txt", b"zzz");
        let archive = encrypt(&c.vault.k_data, 3, true, 16, [3; 24], &zstd(&tar.finish()));
        let entries = vec![
            json!({"r":0,"p":"","k":"d","m":1758812400000i64,"mode":493}),
            json!({"r":0,"p":"a.txt","k":"f","s":3,"m":1758812401000i64,"mode":420,"h":bbrestore::crypto::hex(&bbrestore::crypto::sha256(b"aaa"))}),
            json!({"r":0,"p":"locked.xlsx","k":"f","s":10,"m":1758812401000i64,"mode":420}),
            json!({"r":0,"p":"z.txt","k":"f","s":3,"m":1758812401000i64,"mode":420,"c":true,"h":bbrestore::crypto::hex(&bbrestore::crypto::sha256(b"zzz"))}),
        ];
        c.vault.v2_raw(ID1, entries, archive)
    };
    assert_eq!(v["entries"].as_array().unwrap().len(), 4);
    let files = run(&["files", s(&c.vault.dir)]);
    let out = stdout(&files);
    assert!(out.contains("Documents/locked.xlsx  [not stored in this version]") && out.contains("Documents/z.txt  [may be incomplete]"), "{out}");
    let to = c.root.join("out");
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to)]);
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
    let out = stdout(&o);
    assert!(out.contains("1 file was not restored because this version lists it without content") && out.contains("  Documents/locked.xlsx"), "{out}");
    assert!(out.contains("1 file was restored, but may be incomplete") && out.contains("  Documents/z.txt"), "{out}");
    assert_eq!(tree(&to), vec!["Documents", "Documents/a.txt", "Documents/z.txt"]);
    let ver = run(&["verify", s(&c.vault.dir)]);
    assert!(ver.status.success(), "{}", stdout(&ver));
    assert!(stdout(&ver).contains("Note: 1 file is listed without content"));
}

#[test]
fn damaged_archive_restores_what_comes_before_the_damage() {
    let c = case(2);
    c.vault.v2_version(ID1, &[file("a-first.txt", b"first"), file("b-big.bin", &noise(300_000, 1)), file("c-last.txt", b"last")]);
    let bba = c.vault.index_dir().join(format!("{ID1}.bba"));
    let mut bytes = fs::read(&bba).unwrap();
    let n = bytes.len();
    bytes[n - 40] ^= 0x55; // inside the final segment
    fs::write(&bba, &bytes).unwrap();
    let ver = run(&["verify", s(&c.vault.dir)]);
    assert_eq!(ver.status.code(), Some(5), "{}", stdout(&ver));
    assert!(stdout(&ver).contains("is damaged at"), "{}", stdout(&ver));
    let to = c.root.join("out");
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to)]);
    assert_eq!(o.status.code(), Some(5), "{}", stdout(&o));
    let out = stdout(&o);
    assert!(out.contains("Damage: The archive") && out.contains("Documents/c-last.txt: not restored"), "{out}");
    assert_eq!(fs::read(to.join("Documents/a-first.txt")).unwrap(), b"first");
    assert!(!to.join("Documents/c-last.txt").exists());
    // No temp files left behind.
    assert!(tree(&to).iter().all(|p| !p.contains(".bbrestore-")), "{:?}", tree(&to));
}

#[test]
fn archive_checks_end_size_and_hash() {
    let c = case(2);
    let mut tar = TarW::default();
    tar.dir("r0/");
    tar.file("r0/a.txt", b"aaa");
    let mut t = tar.finish();
    t.extend_from_slice(&[0u8; 512]); // data after the two end blocks
    let archive = encrypt(&c.vault.k_data, 3, true, 16, [3; 24], &zstd(&t));
    let entries = vec![json!({"r":0,"p":"","k":"d","m":0,"mode":493}), json!({"r":0,"p":"a.txt","k":"f","s":3,"m":0,"mode":420,"h":bbrestore::crypto::hex(&bbrestore::crypto::sha256(b"aaa"))})];
    c.vault.v2_raw(ID1, entries, archive);
    let ver = run(&["verify", s(&c.vault.dir)]);
    assert_eq!(ver.status.code(), Some(5));
    assert!(stdout(&ver).contains("data after its end"), "{}", stdout(&ver));
    // Restoring stops after the last file it needs, so it succeeds (every file is still checked).
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&c.root.join("out"))]);
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
}

#[test]
fn zstd_window_over_the_limit_is_refused() {
    let c = case(2);
    // A frame asking for a 2^25 byte window (the limit is 2^24), then an empty last block.
    let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 15 << 3, 0x01, 0x00, 0x00];
    let archive = encrypt(&c.vault.k_data, 3, true, 16, [3; 24], &frame);
    let entries = vec![json!({"r":0,"p":"","k":"d","m":0,"mode":493}), json!({"r":0,"p":"a.txt","k":"f","s":3,"m":0,"mode":420,"h":bbrestore::crypto::hex(&bbrestore::crypto::sha256(b"aaa"))})];
    c.vault.v2_raw(ID1, entries, archive);
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&c.root.join("out"))]);
    assert_eq!(o.status.code(), Some(5), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("compressed data is damaged"), "{}", stdout(&o));
}

#[test]
fn oversized_index_is_refused() {
    let c = case(1);
    c.vault.v1_version(ID1, &[file("a.txt", b"a")]);
    // Newer version: a tiny .bbs that decompresses past 64 MB + 256 x its size.
    let pad = " ".repeat(70 << 20);
    let v = json!({"v":1,"snapshot_id":ID2,"roots":[{"id":0,"path":"/x","name":"Documents"}],"entries":[],"pad":pad});
    c.vault.write_index(ID2, &v, true);
    let h = VaultHeader::read(&c.vault.dir).unwrap();
    let keys = h.unlock(PASS).unwrap();
    let e = h.read_index(&keys, ID2, false).unwrap_err();
    assert_eq!(e.kind, Kind::Corrupt, "{}", e.message);
    assert!(e.message.contains("larger than this reader allows"), "{}", e.message);
    // "latest" passes over it to the version before, warns, and ends with exit code 5.
    let o = run(&["files", s(&c.vault.dir)]);
    assert_eq!(o.status.code(), Some(5));
    assert!(stderr(&o).contains(&format!("Warning: version {ID2} could not be read")), "{}", stderr(&o));
    assert!(stdout(&o).contains(ID1));
    let l = run(&["list", s(&c.vault.dir)]);
    assert_eq!(l.status.code(), Some(5), "{}", stdout(&l));
    assert!(stdout(&l).contains("Ignored:   1 file") && stdout(&l).contains(&format!("{ID2}.bbs")), "{}", stdout(&l));
}

#[test]
fn headers_that_are_wrong_or_newer() {
    let c = case(1);
    c.vault.v1_version(ID1, &[file("a.txt", b"a")]);
    let path = c.vault.dir.join("vault.bbv");
    let orig: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let check = |edit: &dyn Fn(&mut serde_json::Value), code: i32, text: &str| {
        let mut v = orig.clone();
        edit(&mut v);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        let o = run(&["files", s(&c.vault.dir)]);
        assert_eq!(o.status.code(), Some(code), "{text}: {}", stderr(&o));
        assert!(stderr(&o).contains(text), "{text}: {}", stderr(&o));
    };
    check(&|v| v["version"] = json!(3), 4, "newer version of Backup Base");
    check(&|v| v["version"] = json!(2), 5, "a version 2 header without a layout");
    check(&|v| v["layout"] = json!("files2"), 5, "unknown layout");
    check(&|v| { v["version"] = json!(2); v["layout"] = json!("blocks") }, 4, "newer version");
    check(&|v| v["kdf"]["m_kib"] = json!(2_000_000), 5, "outside the allowed bounds");
    check(&|v| v["kdf"]["alg"] = json!("scrypt"), 4, "newer version");
    check(&|v| v["kdf"]["salt"] = json!("AAAA"), 5, "shorter than 8 bytes");
    check(&|v| v["wrapped_key"]["ct"] = json!("AAAA"), 5, "not 48 bytes");
    check(&|v| v["vault_id"] = json!("not-a-uuid"), 5, "not a UUID");
    check(&|v| v["format"] = json!("other"), 4, "is not a Backup Base backup folder");
    fs::write(&path, b"not json").unwrap();
    let o = run(&["files", s(&c.vault.dir)]);
    assert_eq!(o.status.code(), Some(4));
    fs::write(&path, serde_json::to_vec(&orig).unwrap()).unwrap();
    let o = run_with(&["files", s(&c.vault.dir)], "wrong");
    assert_eq!(o.status.code(), Some(3));
    assert!(stderr(&o).contains("The passcode does not open the backup \"Documents\"."));
    let o = run(&["files", s(&c.root)]);
    assert_eq!(o.status.code(), Some(0), "a folder holding one backup: {}", stderr(&o));
    let o = run(&["files", s(&c.root.join("nothing-here"))]);
    assert_eq!(o.status.code(), Some(4));
}

#[test]
fn v1_missing_and_tampered_blobs() {
    let c = case(1);
    c.vault.v1_version(ID1, &[file("a.txt", b"first file with some text in it, over 64 bytes long to be compressed"), file("b.txt", b"second"), file("c.txt", b"third")]);
    let blob = |data: &[u8]| {
        let id = bbrestore::crypto::blob_id(&c.vault.k_name, &bbrestore::crypto::sha256(data));
        c.vault.dir.join("data").join(&id[..2]).join(format!("{id}.bbk"))
    };
    fs::remove_file(blob(b"second")).unwrap();
    let p = blob(b"third");
    let mut bytes = fs::read(&p).unwrap();
    bytes[33] ^= 1;
    fs::write(&p, bytes).unwrap();
    let ver = run(&["verify", s(&c.vault.dir)]);
    assert_eq!(ver.status.code(), Some(5));
    let out = stdout(&ver);
    assert!(out.contains("Documents/b.txt: its stored file is missing") && out.contains("Documents/c.txt: the stored file") && out.contains("damaged"), "{out}");
    let to = c.root.join("out");
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to)]);
    assert_eq!(o.status.code(), Some(5));
    assert_eq!(tree(&to), vec!["Documents", "Documents/a.txt"]);
}

#[test]
fn target_rules() {
    let c = case(2);
    c.vault.v2_version(ID1, &[file("a.txt", b"new"), file("b.txt", b"same")]);
    let to = c.root.join("out");
    fs::create_dir_all(to.join("Documents")).unwrap();
    fs::write(to.join("Documents/a.txt"), b"old").unwrap();
    fs::write(to.join("Documents/b.txt"), b"same").unwrap();
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to)]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("is not empty"));
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to), "--keep-both"]);
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
    assert_eq!(fs::read(to.join("Documents/a.txt")).unwrap(), b"old");
    assert_eq!(fs::read(to.join("Documents/a (restored).txt")).unwrap(), b"new");
    assert!(!to.join("Documents/b (restored).txt").exists());
    assert!(stdout(&o).contains("Already there with the same content: 1 file"));
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to), "--keep-both"]);
    assert!(o.status.success());
    assert_eq!(fs::read(to.join("Documents/a (restored 2).txt")).unwrap(), b"new");
    // Never into the backup folder itself.
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&c.vault.dir.join("x"))]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("outside the backup folder"));
    // A file where the target folder should be.
    fs::write(c.root.join("file"), b"x").unwrap();
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&c.root.join("file"))]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn a_file_in_the_way_of_a_folder() {
    let c = case(2);
    c.vault.v2_version(ID1, &[dir("sub"), file("sub/a.txt", b"a"), file("top.txt", b"t")]);
    let to = c.root.join("out");
    fs::create_dir_all(to.join("Documents")).unwrap();
    fs::write(to.join("Documents/sub"), b"in the way").unwrap();
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to), "--keep-both"]);
    assert_eq!(o.status.code(), Some(6), "{}", stdout(&o));
    let out = stdout(&o);
    assert!(out.contains("Documents/sub: the folder could not be created") && out.contains("1 item inside folders that could not be restored was skipped"), "{out}");
    assert_eq!(fs::read(to.join("Documents/top.txt")).unwrap(), b"t");
}

#[test]
fn paths_versions_and_passcode_files() {
    let c = case(2);
    c.vault.v2_version(ID1, &[dir("Café"), file("Café/menu.txt", b"old"), file("other.txt", b"o")]);
    c.vault.v2_version(ID2, &[dir("Café"), file("Café/menu.txt", b"new"), file("other.txt", b"o")]);
    // NFD spelling of the path matches the NFC name in the index.
    let nfd = "Documents/Cafe\u{301}";
    let to = c.root.join("out");
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to), "--path", nfd, "--version", "20260925"]);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(tree(&to), vec!["Documents", "Documents/Café", "Documents/Café/menu.txt"]);
    assert_eq!(fs::read(to.join("Documents/Café/menu.txt")).unwrap(), b"old");
    // Passcode file with a byte order mark and a Windows line ending; BB_PASSCODE unset.
    let pf = c.root.join("pass.txt");
    fs::write(&pf, format!("\u{feff}{PASS}\r\n")).unwrap();
    let o = std::process::Command::new(bin()).args(["files", s(&c.vault.dir), "--passcode-file", s(&pf), "--path", "Documents/Café/menu.txt"]).env_remove("BB_PASSCODE").output().unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains(ID2));
    let o = run(&["files", s(&c.vault.dir), "--version", "2026"]);
    assert_eq!(o.status.code(), Some(2), "ambiguous");
    let o = run(&["files", s(&c.vault.dir), "--version", "20270101T000000Z-00000000"]);
    assert_eq!(o.status.code(), Some(4));
    let o = run(&["verify", s(&c.vault.dir), "--all"]);
    assert!(o.status.success(), "{}", stdout(&o));
    assert_eq!(stdout(&o).matches("OK: 2 files").count(), 2);
    let o = run(&["restore", s(&c.vault.dir)]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["frobnicate"]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["verify", s(&c.vault.dir), "--keep-both"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn missing_archive() {
    let c = case(2);
    c.vault.v2_version(ID1, &[file("a.txt", b"a")]);
    fs::remove_file(c.vault.index_dir().join(format!("{ID1}.bba"))).unwrap();
    let l = run(&["list", s(&c.vault.dir)]);
    assert!(stdout(&l).contains("(archive missing)"), "{}", stdout(&l));
    let to = c.root.join("out");
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to)]);
    assert_eq!(o.status.code(), Some(4));
    assert!(stderr(&o).contains("is not in the backup folder. If the folder is still syncing"), "{}", stderr(&o));
    assert!(!to.exists(), "nothing is created before the archive is found");
    let v = run(&["verify", s(&c.vault.dir)]);
    assert_eq!(v.status.code(), Some(5));
}

#[test]
fn several_backups_and_roots() {
    let tmp = tempfile::tempdir().unwrap();
    let a = TestVault::create(&tmp.path().join("A"), 1);
    let b = TestVault::create(&tmp.path().join("B"), 2);
    a.v1_version(ID1, &[file("x.txt", b"x")]);
    b.v2_version(ID1, &[file("y.txt", b"y")]);
    let l = run(&["list", s(tmp.path())]);
    assert!(l.status.success());
    let out = stdout(&l);
    assert!(out.starts_with("2 backups in") && out.contains("version 1 (one encrypted file per file)") && out.contains("version 2 (one encrypted archive per run)"), "{out}");
    let o = run(&["files", s(tmp.path())]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("holds several backups"));
    let l = run(&["list", s(tmp.path()), "--no-passcode"]);
    assert!(stdout(&l).contains("1 found (the passcode is needed to list them)"));
}

#[test]
fn two_roots_with_the_same_name() {
    let c = case(1);
    let (h1, b1) = c.vault.write_blob(b"one");
    let (h2, b2) = c.vault.write_blob(b"two");
    let v = json!({"v":1,"snapshot_id":ID1,"roots":[{"id":0,"path":"/a/Documents","name":"Documents"},{"id":1,"path":"/b/documents","name":"documents"}],
        "entries":[{"r":0,"p":"","k":"d"},{"r":0,"p":"f.txt","k":"f","s":3,"h":h1,"b":b1},{"r":1,"p":"","k":"d"},{"r":1,"p":"f.txt","k":"f","s":3,"h":h2,"b":b2}]});
    c.vault.write_index(ID1, &v, true);
    let to = c.root.join("out");
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to)]);
    assert!(o.status.success(), "{}", stdout(&o));
    assert_eq!(fs::read(to.join("Documents/f.txt")).unwrap(), b"one");
    assert_eq!(fs::read(to.join("documents (2)/f.txt")).unwrap(), b"two");
}

#[test]
fn root_folders_come_from_the_original_path() {
    // Names as Backup Base 1.1.3 recorded them: the leading dot dropped, ".claude" made
    // unique against "claude". The folders take the path's last component, from either OS.
    let c = case(1);
    let (h1, b1) = c.vault.write_blob(b"ssh");
    let (h2, b2) = c.vault.write_blob(b"plain");
    let (h3, b3) = c.vault.write_blob(b"dot");
    let v = json!({"v":1,"snapshot_id":ID1,"roots":[{"id":0,"path":"/Users/a/.ssh","name":"ssh"},{"id":1,"path":"C:\\Users\\a\\claude","name":"claude"},{"id":2,"path":"/Users/a/.claude","name":"claude (2)"}],
        "entries":[{"r":0,"p":"","k":"d"},{"r":0,"p":"config","k":"f","s":3,"h":h1,"b":b1},{"r":1,"p":"","k":"d"},{"r":1,"p":"f.txt","k":"f","s":5,"h":h2,"b":b2},{"r":2,"p":"","k":"d"},{"r":2,"p":"f.txt","k":"f","s":3,"h":h3,"b":b3}]});
    c.vault.write_index(ID1, &v, true);
    let to = c.root.join("out");
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to)]);
    assert!(o.status.success(), "{}", stdout(&o));
    assert_eq!(tree(&to), vec![".claude", ".claude/f.txt", ".ssh", ".ssh/config", "claude", "claude/f.txt"]);
    assert_eq!(fs::read(to.join(".claude/f.txt")).unwrap(), b"dot");
    let l = run(&["files", s(&c.vault.dir)]);
    assert!(stdout(&l).contains(" .ssh/config\n") && stdout(&l).contains(" .claude/f.txt\n"), "{}", stdout(&l));
    // --path takes the new names, and the recorded ones when nothing else matches.
    for (p, want) in [(".ssh/config", ".ssh/config"), ("ssh/config", ".ssh/config"), ("claude (2)", ".claude/f.txt"), ("claude", "claude/f.txt")] {
        let to = c.root.join("by-path").join(p.replace('/', "_"));
        let o = run(&["restore", s(&c.vault.dir), "--to", s(&to), "--path", p]);
        assert!(o.status.success(), "{p}: {}{}", stdout(&o), stderr(&o));
        let files: Vec<String> = tree(&to).into_iter().filter(|x| x.ends_with("f.txt") || x.ends_with("config")).collect();
        assert_eq!(files, vec![want.to_string()], "{p}");
    }
}

#[cfg(windows)]
#[test]
fn hidden_folders_stay_hidden_on_windows() {
    // A dot folder backed up on Windows is usually hidden too (attr bit 2): the restored root
    // folder and a hidden folder inside it are hidden again, a plain folder is not.
    use std::os::windows::fs::MetadataExt;
    let c = case(1);
    let (h1, b1) = c.vault.write_blob(b"key");
    let v = json!({"v":1,"snapshot_id":ID1,"roots":[{"id":0,"path":"C:\\Users\\a\\.ssh","name":".ssh"}],
        "entries":[{"r":0,"p":"","k":"d","attr":2},{"r":0,"p":"keys","k":"d","attr":2},{"r":0,"p":"plain","k":"d","attr":0},{"r":0,"p":"keys/id","k":"f","s":3,"h":h1,"b":b1}]});
    c.vault.write_index(ID1, &v, true);
    let to = c.root.join("out");
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to)]);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    let hidden = |p: &Path| fs::metadata(p).unwrap().file_attributes() & 2 != 0;
    assert!(hidden(&to.join(".ssh")), "the root folder is not hidden");
    assert!(hidden(&to.join(".ssh").join("keys")), "the hidden folder inside is not hidden");
    assert!(!hidden(&to.join(".ssh").join("plain")), "a plain folder became hidden");
    assert_eq!(fs::read(to.join(".ssh").join("keys").join("id")).unwrap(), b"key");
}

#[test]
fn a_target_inside_any_backup_folder_is_refused() {
    let c = case(2);
    c.vault.v2_version(ID1, &[file("a.txt", b"a")]);
    // Another backup next to it: a folder holding vault.bbv.
    let other = c.root.join("dest").join("Other");
    fs::create_dir_all(&other).unwrap();
    fs::copy(c.vault.dir.join("vault.bbv"), other.join("vault.bbv")).unwrap();
    for to in [other.join("new"), other.clone()] {
        let o = run(&["restore", s(&c.vault.dir), "--to", s(&to), "--keep-both"]);
        assert_eq!(o.status.code(), Some(2), "{}{}", stdout(&o), stderr(&o));
        assert!(stderr(&o).contains("Choose a folder outside the backup folder"), "{}", stderr(&o));
    }
    assert!(!other.join("new").exists(), "nothing is created inside a backup folder");
}

#[test]
fn keep_both_never_restores_into_another_backup_folder() {
    let c = case(2);
    c.vault.v2_version(ID1, &[dir("sub"), file("sub/a.txt", b"a")]);
    // The target already holds a backup folder named like the backed-up folder: refused.
    let to = c.root.join("restore");
    fs::create_dir_all(to.join("Documents")).unwrap();
    fs::copy(c.vault.dir.join("vault.bbv"), to.join("Documents").join("vault.bbv")).unwrap();
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to), "--keep-both"]);
    assert_eq!(o.status.code(), Some(2), "{}{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("Choose a folder outside the backup folder"), "{}", stderr(&o));
    assert_eq!(tree(&to), vec!["Documents", "Documents/vault.bbv"]);
    // Deeper down, the backup folder is found while restoring and skipped.
    let to = c.root.join("restore2");
    fs::create_dir_all(to.join("Documents/sub")).unwrap();
    fs::copy(c.vault.dir.join("vault.bbv"), to.join("Documents/sub/vault.bbv")).unwrap();
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to), "--keep-both"]);
    assert_eq!(o.status.code(), Some(6), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("Documents holds a Backup Base backup folder, and nothing is restored next to one"), "{}", stdout(&o));
    assert_eq!(tree(&to), vec!["Documents", "Documents/sub", "Documents/sub/vault.bbv"]);
}

#[cfg(unix)]
#[test]
fn keep_both_never_links_through_a_link_that_was_already_there() {
    let c = case(2);
    c.vault.v2_version(ID1, &[dir("d"), link("d/esc", "../planted/x"), link("d/fine", "../d")]);
    let to = c.root.join("restore");
    let outside = c.root.join("outside");
    fs::create_dir_all(to.join("Documents")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, to.join("Documents").join("planted")).unwrap();
    let o = run(&["restore", s(&c.vault.dir), "--to", s(&to), "--keep-both"]);
    let out = stdout(&o);
    assert_eq!(o.status.code(), Some(0), "{out}{}", stderr(&o));
    assert!(out.contains("Documents/d/esc: it points through a link that was already in the restore folder"), "{out}");
    assert!(fs::symlink_metadata(to.join("Documents/d/esc")).is_err());
    assert!(fs::symlink_metadata(to.join("Documents/d/fine")).unwrap().file_type().is_symlink());
}

#[test]
fn the_passcode_file_uses_its_first_line_only() {
    let c = case(2);
    c.vault.v2_version(ID1, &[file("a.txt", b"a")]);
    let pf = c.root.join("pass.txt");
    fs::write(&pf, format!("{PASS}\r\nsecond line\n")).unwrap();
    let o = std::process::Command::new(bin()).args(["verify", s(&c.vault.dir), "--passcode-file", s(&pf)]).env_remove("BB_PASSCODE").output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}{}", stdout(&o), stderr(&o));
}

#[test]
fn control_characters_from_the_backup_are_not_printed() {
    let c = case(2);
    c.vault.v2_version(ID1, &[file("a\u{1b}[2Jb.txt", b"a")]);
    let o = run(&["files", s(&c.vault.dir)]);
    let out = stdout(&o);
    assert_eq!(o.status.code(), Some(0), "{out}");
    assert!(!out.contains('\u{1b}') && out.contains("Documents/a?[2Jb.txt"), "{out}");
}

#[test]
fn verify_reports_a_newest_version_that_cannot_be_read() {
    let c = case(2);
    c.vault.v2_version(ID1, &[file("a.txt", b"a")]);
    c.vault.v2_version(ID2, &[file("a.txt", b"b")]);
    let bbs = c.vault.index_dir().join(format!("{ID2}.bbs"));
    let mut bytes = fs::read(&bbs).unwrap();
    let n = bytes.len();
    bytes[n - 5] ^= 1;
    fs::write(&bbs, bytes).unwrap();
    let o = run(&["verify", s(&c.vault.dir)]);
    let out = stdout(&o);
    assert_eq!(o.status.code(), Some(5), "{out}");
    assert!(out.contains(&format!("Version {ID2}")) && out.contains("its index cannot be read") && out.contains("OK: 1 file"), "{out}");
}
