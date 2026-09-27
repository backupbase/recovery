//! Restores the sample backups in fixtures/windows (made on Windows 11 by the Backup Base apps:
//! 1.0.2 for format v1, 1.1.0 for format v2; test data only) and compares every file and folder
//! of every version with fixtures/windows/<format>/manifest.json: size, SHA-256, modification
//! time, and on Windows the read-only and hidden attributes.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

const PASS: &str = "Recovery-Fixture-2026!-Granite-Walrus";

fn fixture(format: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join("windows").join(format)
}

fn tool(args: &[&str], pass: &str) -> (i32, String) {
    let o = Command::new(common::bin()).args(args).env("BB_PASSCODE", pass).output().unwrap();
    (o.status.code().unwrap_or(-1), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

fn sha256(p: &Path) -> String {
    let mut f = fs::File::open(p).unwrap();
    let (mut h, mut buf) = (Sha256::new(), vec![0u8; 1 << 16]);
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn mtime_ms(md: &fs::Metadata) -> i64 {
    let t = filetime::FileTime::from_last_modification_time(md);
    t.unix_seconds() * 1000 + (t.nanoseconds() / 1_000_000) as i64
}

/// Every path below `root`, relative with `/`.
fn tree(root: &Path, dir: &Path, out: &mut Vec<String>) {
    for d in fs::read_dir(dir).unwrap().flatten() {
        let p = d.path();
        out.push(p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
        if fs::symlink_metadata(&p).unwrap().is_dir() {
            tree(root, &p, out);
        }
    }
}

/// Read-only files (and, on Windows, folders) block removal: clear it first.
fn remove(dir: &Path) {
    if !dir.exists() {
        return;
    }
    let mut all = vec![];
    tree(dir, dir, &mut all);
    for rel in all {
        let p = dir.join(&rel);
        if let Ok(md) = fs::symlink_metadata(&p) {
            let mut perm = md.permissions();
            if perm.readonly() {
                #[allow(clippy::permissions_set_readonly_false)]
                perm.set_readonly(false);
                let _ = fs::set_permissions(&p, perm);
            }
        }
    }
    fs::remove_dir_all(dir).unwrap();
}

fn check(format: &str) {
    let d = fixture(format);
    let m: Value = serde_json::from_str(&fs::read_to_string(d.join("manifest.json")).unwrap()).unwrap();
    let backup = d.join("backup");
    let vault = backup.join(m["set_name"].as_str().unwrap());
    let (b, v) = (backup.to_str().unwrap(), vault.to_str().unwrap());
    let root = m["root_name"].as_str().unwrap();

    let (code, out) = tool(&["list", b], PASS);
    assert_eq!(code, 0, "list: {out}");
    assert!(out.contains(m["set_name"].as_str().unwrap()), "list names the backup: {out}");
    let (code, out) = tool(&["verify", v, "--all"], PASS);
    assert_eq!(code, 0, "verify --all: {out}");
    let (code, out) = tool(&["list", v], "not-the-passcode");
    assert_eq!(code, 3, "a wrong passcode is refused: {out}");

    for ver in m["versions"].as_array().unwrap() {
        let id = ver["backup_id"].as_str().unwrap();
        let to = std::env::temp_dir().join(format!("bbrestore-winfx-{format}-{id}-{}", std::process::id()));
        remove(&to);
        let (code, out) = tool(&["restore", v, "--to", to.to_str().unwrap(), "--version", id], PASS);
        assert_eq!(code, 0, "restore {id}: {out}");
        let base = to.join(root);

        let want: BTreeMap<String, &Value> = ver["entries"].as_array().unwrap().iter().map(|e| (e["path"].as_str().unwrap().to_string(), e)).collect();
        let mut got = vec![];
        tree(&base, &base, &mut got);
        got.sort();
        let want_paths: Vec<String> = want.keys().cloned().collect();
        assert_eq!(got, want_paths, "{format} {id}: restored paths equal the manifest");

        for (rel, e) in &want {
            let p = base.join(rel);
            let md = fs::symlink_metadata(&p).unwrap();
            let attr = e["attr"].as_u64().unwrap_or(0);
            match e["kind"].as_str().unwrap() {
                "dir" => assert!(md.is_dir(), "{rel}: a folder"),
                _ => {
                    assert!(md.is_file(), "{rel}: a file");
                    assert_eq!(md.len(), e["size"].as_u64().unwrap(), "{rel}: size");
                    assert_eq!(sha256(&p), e["sha256"].as_str().unwrap(), "{rel}: content");
                    assert_eq!(mtime_ms(&md), e["mtime_ms"].as_i64().unwrap(), "{rel}: modification time");
                    assert_eq!(md.permissions().readonly(), attr & 1 != 0, "{rel}: read-only");
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::MetadataExt;
                        assert_eq!(md.file_attributes() & 2 != 0, attr & 2 != 0, "{rel}: hidden");
                    }
                }
            }
        }
        remove(&to);
    }
}

#[test]
fn windows_format_v1_restores_exactly() {
    check("format-v1");
}

#[test]
fn windows_format_v2_restores_exactly() {
    check("format-v2");
}
