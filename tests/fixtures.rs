//! Restores the sample backups in fixtures/macos (made by the Backup Base app's engine on
//! macOS, test data only) and compares every entry with the manifest written when each
//! version was made. On Windows this is the cross-OS check: names Windows does not allow are
//! changed, reserved names are refused, links are skipped, read-only comes back.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use bbrestore::pathsafe;
use serde_json::Value;

const PASS: &str = "Recovery-Fixture-2026!-Granite-Walrus";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join("macos")
}

fn tool(args: &[&str]) -> (i32, String) {
    let o = Command::new(common::bin()).args(args).env("BB_PASSCODE", PASS).output().unwrap();
    (o.status.code().unwrap_or(-1), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
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

#[test]
fn macos_fixtures_restore_and_match_their_manifests() {
    let base = fixtures();
    let windows = pathsafe::WINDOWS;
    let (code, out) = tool(&["list", base.join("backups").to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("2 backups"), "{out}");
    let mut checked = 0;
    for backup in ["Fixture v1", "Fixture v2"] {
        let vault = base.join("backups").join(backup);
        let (code, out) = tool(&["verify", vault.to_str().unwrap(), "--all"]);
        assert_eq!(code, 0, "{backup}: {out}");
        let mut manifests: Vec<PathBuf> = fs::read_dir(base.join("manifests").join(backup)).unwrap().flatten().map(|d| d.path()).collect();
        manifests.sort();
        assert_eq!(manifests.len(), 2, "{backup}");
        for m in manifests {
            let man: Value = serde_json::from_slice(&fs::read(&m).unwrap()).unwrap();
            let id = man["version_id"].as_str().unwrap();
            let tmp = tempfile::tempdir().unwrap();
            let to = tmp.path().join("restored");
            let (code, out) = tool(&["restore", vault.to_str().unwrap(), "--version", id, "--to", to.to_str().unwrap()]);
            // On Windows the reserved name aux.txt is refused, which is exit 6 (items skipped).
            assert_eq!(code, if windows { 6 } else { 0 }, "{backup} {id}: {out}");
            // Every link is skipped on Windows; elsewhere this one because it points outside.
            let outside = if windows { "Documents/links/outside: symbolic links are not created on Windows" } else { "Documents/links/outside: it points outside the restore folder" };
            assert!(out.contains(outside), "{out}");
            let mut expected_paths = Vec::new();
            for e in man["entries"].as_array().unwrap() {
                let path = e["path"].as_str().unwrap();
                let kind = e["kind"].as_str().unwrap();
                if path.ends_with("links/outside") || (windows && kind == "link") {
                    continue;
                }
                // The path this computer uses: the root folder name, then the index path.
                let (root, rest) = path.split_once('/').unwrap_or((path, ""));
                let fixed = match pathsafe::fix_path(rest, windows) {
                    Ok((c, _)) => c,
                    Err(_) => {
                        assert!(windows && rest.ends_with("aux.txt"), "{path}");
                        assert!(out.contains("aux.txt: not restored, its name is reserved by Windows"), "{out}");
                        continue;
                    }
                };
                let rel: String = std::iter::once(root.to_string()).chain(fixed).collect::<Vec<_>>().join("/");
                expected_paths.push(rel.clone());
                let p = to.join(&rel);
                let md = fs::symlink_metadata(&p).unwrap_or_else(|e| panic!("{backup} {id}: {rel}: {e}"));
                match kind {
                    "file" => {
                        let data = fs::read(&p).unwrap();
                        assert_eq!(data.len() as u64, e["size"].as_u64().unwrap(), "{rel}");
                        assert_eq!(bbrestore::crypto::hex(&bbrestore::crypto::sha256(&data)), e["sha256"].as_str().unwrap(), "{rel}");
                        assert_eq!(mtime_ms(&md), e["mtime_ms"].as_i64().unwrap(), "{rel} mtime");
                        let mode = e["mode"].as_u64().unwrap() as u32;
                        assert_eq!(md.permissions().readonly(), mode & 0o200 == 0, "{rel} read-only");
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            assert_eq!(md.permissions().mode() & 0o777, mode, "{rel} mode");
                        }
                    }
                    "folder" => {
                        assert!(md.is_dir(), "{rel}");
                        assert_eq!(mtime_ms(&md), e["mtime_ms"].as_i64().unwrap(), "{rel} mtime");
                    }
                    _ => {
                        assert_eq!(fs::read_link(&p).unwrap().to_string_lossy(), e["target"].as_str().unwrap(), "{rel}");
                    }
                }
            }
            let mut got = Vec::new();
            tree(&to, &to, &mut got);
            got.sort();
            expected_paths.sort();
            assert_eq!(got, expected_paths, "{backup} {id}: restored entries");
            checked += 1;
            // Read-only files must be made writable before the temp folder can go.
            for p in &got {
                let p = to.join(p);
                if let Ok(md) = fs::symlink_metadata(&p) {
                    if !md.file_type().is_symlink() {
                        let mut perm = md.permissions();
                        #[allow(clippy::permissions_set_readonly_false)]
                        perm.set_readonly(false);
                        let _ = fs::set_permissions(&p, perm);
                    }
                }
            }
        }
    }
    assert_eq!(checked, 4);
}
