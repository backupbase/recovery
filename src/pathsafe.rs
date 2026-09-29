//! Turning index paths into safe names on this computer (FORMAT.md "Restore").
//!
//! Every restored path is `<target>/<root name>/<p>`. An index path is `/`-separated and
//! relative: an empty component, `.`, `..` or a NUL byte refuses the entry (so a leading `/`,
//! traversal and absolute paths never leave the target). On Windows, characters Windows does
//! not allow in names (`<>:"|?*`, `\` and control characters) become `_` and are reported, so a
//! drive letter (`C:`) or a backslash can never form a path; a trailing dot or space becomes
//! `_`; and reserved device names (CON, PRN, AUX, NUL, COM0-9, LPT0-9, CONIN$, CONOUT$, with
//! or without an extension) are refused. On macOS and Linux those names are ordinary.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use unicode_normalization::UnicodeNormalization;

use crate::vault::Root;

pub const WINDOWS: bool = cfg!(windows);

/// A name component as it will be written on this computer (`windows` selects the rules).
pub fn fix_component(c: &str, windows: bool) -> Result<Cow<'_, str>, &'static str> {
    if c.is_empty() || c == "." || c == ".." {
        return Err("its path is not a safe relative path");
    }
    if c.contains('\0') || c.contains('/') {
        return Err("its name contains a character that is never allowed");
    }
    if !windows {
        return Ok(Cow::Borrowed(c));
    }
    if is_reserved_windows(c) {
        return Err("its name is reserved by Windows");
    }
    let mut changed = false;
    let mut out: String = c
        .chars()
        .map(|ch| {
            if matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\\') || (ch as u32) < 32 {
                changed = true;
                '_'
            } else {
                ch
            }
        })
        .collect();
    // Windows drops a trailing dot or space: replace the last character ("a.." becomes "a._").
    if out.ends_with('.') || out.ends_with(' ') {
        out.pop();
        out.push('_');
        changed = true;
    }
    if changed {
        Ok(Cow::Owned(out))
    } else {
        Ok(Cow::Borrowed(c))
    }
}

pub fn is_reserved_windows(c: &str) -> bool {
    let stem = c.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ((stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4 && stem.as_bytes()[3].is_ascii_digit())
        || ((stem.starts_with("COM") || stem.starts_with("LPT")) && matches!(&stem[3..], "¹" | "²" | "³"))
}

/// The components below the root folder for an index path `p` (empty for the root itself).
/// Returns the safe components and whether any of them was changed.
pub fn fix_path(p: &str, windows: bool) -> Result<(Vec<String>, bool), &'static str> {
    if p.is_empty() {
        return Ok((vec![], false));
    }
    let mut out = Vec::new();
    let mut changed = false;
    for c in p.split('/') {
        match fix_component(c, windows)? {
            Cow::Borrowed(s) => out.push(s.to_string()),
            Cow::Owned(s) => {
                changed = true;
                out.push(s)
            }
        }
    }
    Ok((out, changed))
}

/// The last component of a root's original path. A path made on Windows (not starting with
/// `/`) is split on `/` and `\`, so a backup made on either OS can be restored on the other;
/// a macOS path only on `/`, since a macOS folder name may contain `\`. None for "/", a
/// drive (`C:\`) or "".
fn last_component(path: &str) -> Option<&str> {
    let seps: &[char] = if path.starts_with('/') { &['/'] } else { &['/', '\\'] };
    let last = path.rsplit(seps).find(|c| !c.is_empty())?;
    let b = last.as_bytes();
    (!(b.len() == 2 && b[1] == b':' && b[0].is_ascii_alphabetic())).then_some(last)
}

/// The folder name each root gets in the target (FORMAT.md "Restore", Chosen folder): the
/// last component of its original path (leading dots kept: `.ssh`) made safe, or its
/// recorded name (trimmed) when that is not usable, or `Folder <id+1>`; made unique ignoring
/// case and Unicode form, in root id order, shortened so a suffix still fits in 255 bytes.
/// Indexes written before Backup Base 1.1.4 may record a name without its leading dot
/// (`.ssh` as `ssh`), which is why the path comes first.
pub fn root_dirs(roots: &[Root], windows: bool) -> HashMap<u32, String> {
    let mut sorted: Vec<&Root> = roots.iter().collect();
    sorted.sort_by_key(|r| r.id);
    let mut used = HashSet::new();
    let mut out = HashMap::new();
    for r in sorted {
        let base = last_component(&r.path)
            .and_then(|c| fix_component(c, windows).ok())
            .or_else(|| fix_component(r.name.trim(), windows).ok())
            .map(Cow::into_owned)
            .unwrap_or_else(|| format!("Folder {}", r.id as u64 + 1));
        let mut name = base.clone();
        let mut n = 2;
        while !used.insert(name.nfc().collect::<String>().to_lowercase()) {
            let tag = format!(" ({n})");
            let mut cut = base.len().min(255 - tag.len());
            while !base.is_char_boundary(cut) {
                cut -= 1;
            }
            name = format!("{}{tag}", &base[..cut]);
            n += 1;
        }
        out.insert(r.id, name);
    }
    out
}

/// `name (restored).ext`, `name (restored 2).ext`..., shortened on a character boundary so
/// the name fits in 255 bytes.
pub fn restored_name(name: &str, n: u32) -> String {
    let tag = if n <= 1 { " (restored)".to_string() } else { format!(" (restored {n})") };
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    let (stem, ext) = if ext.len() + tag.len() > 128 { (name, "") } else { (stem, ext) };
    let room = 255usize.saturating_sub(tag.len() + ext.len());
    let mut cut = stem.len().min(room);
    while !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{}{}", &stem[..cut], tag, ext)
}

/// Whether a symbolic link at `link_dir` (components below the target) pointing to `target`
/// stays inside the target, resolved as text (links are never followed while restoring).
/// Only `(../)*name(/name)*` is accepted: a `..` after a name could climb out through a name
/// that is itself a link (`up -> ..`, then `esc -> up/..`). With that rule every name either
/// goes down into a real folder or into a link that obeys the same rule, so the depth count
/// holds. Existing links in the way are checked by the restore (`--keep-both`).
pub fn link_stays_inside(link_dir: &[String], target: &str) -> bool {
    if target.is_empty() || target.starts_with('/') || target.starts_with('\\') || target.contains('\0') {
        return false;
    }
    let b = target.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return false;
    }
    let mut depth = link_dir.len() as i64;
    let mut named = false;
    for c in target.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 || named {
                    return false;
                }
            }
            _ => {
                named = true;
                depth += 1
            }
        }
    }
    true
}

/// The names a link target goes down through after its leading `..` components (for a target
/// `link_stays_inside` accepted): how many levels it goes up, then the names.
pub fn link_names(target: &str) -> (usize, Vec<&str>) {
    let mut up = 0;
    let mut names = Vec::new();
    for c in target.split('/') {
        match c {
            "" | "." => {}
            ".." => up += 1,
            n => names.push(n),
        }
    }
    (up, names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components() {
        for bad in ["", ".", "..", "a\0b"] {
            assert!(fix_component(bad, false).is_err(), "{bad:?}");
            assert!(fix_component(bad, true).is_err(), "{bad:?}");
        }
        assert_eq!(fix_component("C:", false).unwrap(), "C:");
        assert_eq!(fix_component("C:", true).unwrap(), "C_");
        assert_eq!(fix_component(r"a\..\b", true).unwrap(), "a_.._b");
        assert_eq!(fix_component("what?<>|*\".txt", true).unwrap(), "what______.txt");
        assert_eq!(fix_component("tab\there", true).unwrap(), "tab_here");
        assert_eq!(fix_component("ends. ", true).unwrap(), "ends._");
        assert_eq!(fix_component("dots..", true).unwrap(), "dots._");
        for reserved in ["CON", "con.txt", "Nul", "aux.tar.gz", "COM1", "lpt9.log", "COM¹", "CONIN$", "PRN "] {
            assert!(fix_component(reserved, true).is_err(), "{reserved}");
            assert!(fix_component(reserved, false).is_ok(), "{reserved}");
        }
        for fine in ["CONSOLE", "COM10", "nul1", "context.txt", "Résumé ✓.txt"] {
            assert!(matches!(fix_component(fine, true), Ok(Cow::Borrowed(_))), "{fine}");
        }
    }

    #[test]
    fn paths() {
        assert_eq!(fix_path("", false).unwrap(), (vec![], false));
        assert_eq!(fix_path("a/b c/d.txt", false).unwrap().0, vec!["a", "b c", "d.txt"]);
        for bad in ["/abs", "a//b", "a/../b", "../x", "a/.", "a/"] {
            assert!(fix_path(bad, false).is_err(), "{bad}");
        }
        assert_eq!(fix_path("C:/Windows/x", true).unwrap(), (vec!["C_".to_string(), "Windows".into(), "x".into()], true));
    }

    #[test]
    fn restored_names() {
        assert_eq!(restored_name("report.pdf", 1), "report (restored).pdf");
        assert_eq!(restored_name("report.pdf", 2), "report (restored 2).pdf");
        assert_eq!(restored_name(".bashrc", 1), ".bashrc (restored)");
        assert_eq!(restored_name("archive.tar.gz", 1), "archive.tar (restored).gz");
        assert_eq!(restored_name("noext", 3), "noext (restored 3)");
        let long = "é".repeat(127) + ".txt"; // 258 bytes
        let n = restored_name(&long, 1);
        assert!(n.len() <= 255 && n.ends_with(" (restored).txt"), "{n} {}", n.len());
        assert!(n.starts_with('é'));
    }

    #[test]
    fn links() {
        let d = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(link_stays_inside(&d(&["Documents"]), "file.txt"));
        assert!(link_stays_inside(&d(&["Documents", "a"]), "../b/c"));
        assert!(link_stays_inside(&d(&["Documents"]), "../Other/x"));
        assert!(!link_stays_inside(&d(&["Documents"]), "../../x"));
        assert!(!link_stays_inside(&d(&["Documents", "a"]), "b/../../../../x"));
        // A ".." after a name is refused, even when it would stay inside as text.
        assert!(!link_stays_inside(&d(&["Documents", "a"]), "b/../c"));
        assert!(!link_stays_inside(&d(&["Documents"]), "up/.."));
        assert!(!link_stays_inside(&d(&["Documents"]), "./up/../x"));
        assert!(link_stays_inside(&d(&["Documents"]), ".."));
        assert!(link_stays_inside(&d(&["Documents", "a"]), "./../../Other/./x/"));
        assert_eq!(link_names("./../../Other/./x/"), (2, vec!["Other", "x"]));
        assert!(!link_stays_inside(&d(&["Documents"]), "/etc/passwd"));
        assert!(!link_stays_inside(&d(&["Documents"]), "C:/x"));
        assert!(!link_stays_inside(&d(&["Documents"]), ""));
    }

    #[test]
    fn root_names() {
        let r = |id, name: &str| Root { id, path: String::new(), name: name.into() };
        let m = root_dirs(&[r(0, "Documents"), r(1, "documents"), r(2, ".."), r(3, "Documents")], false);
        assert_eq!(m[&0], "Documents");
        assert_eq!(m[&1], "documents (2)");
        assert_eq!(m[&2], "Folder 3");
        assert_eq!(m[&3], "Documents (3)");
    }

    #[test]
    fn root_names_from_paths() {
        let r = |id, path: &str, name: &str| Root { id, path: path.into(), name: name.into() };
        let names = |roots: &[Root], w: bool| {
            let m = root_dirs(roots, w);
            (0..roots.len() as u32).map(|i| m[&i].clone()).collect::<Vec<_>>()
        };
        // The path's last component, leading dot kept, from either OS.
        assert_eq!(names(&[r(0, "/Users/a/.ssh", ".ssh"), r(1, "C:\\Users\\a\\.ssh", ".ssh")], false), vec![".ssh", ".ssh (2)"]);
        assert_eq!(names(&[r(0, "C:\\Users\\a\\.ssh\\", ".ssh")], true), vec![".ssh"]);
        // Old indexes recorded "ssh" and "claude (2)": the path wins.
        assert_eq!(names(&[r(0, "/Users/a/.ssh", "ssh"), r(1, "/Users/a/claude", "claude"), r(2, "/Users/a/.claude", "claude (2)")], false), vec![".ssh", "claude", ".claude"]);
        // Duplicates across roots, ignoring case, in root id order (listed out of order here).
        assert_eq!(names(&[r(1, "/b/documents", "documents (2)"), r(0, "/a/Documents", "Documents"), r(2, "D:\\DOCUMENTS", "DOCUMENTS (3)")], false), vec!["Documents", "documents (2)", "DOCUMENTS (3)"]);
        // No usable path: the recorded name; neither: "Folder N".
        assert_eq!(names(&[r(0, "", "Documents"), r(1, "/", "Backup"), r(2, "C:\\", "C")], false), vec!["Documents", "Backup", "C"]);
        assert_eq!(names(&[r(0, "/", "../../.."), r(1, "", ""), r(2, "/x/..", "a/b")], false), vec!["Folder 1", "Folder 2", "Folder 3"]);
        // Windows rules: replacements, reserved names refused (then the recorded name).
        assert_eq!(names(&[r(0, "/Users/a/notes: q?", "notes q"), r(1, "/Users/a/CON", "CON")], true), vec!["notes_ q_", "Folder 2"]);
        assert_eq!(names(&[r(0, "/Users/a/aux.d", "aux.d")], false), vec!["aux.d"]);
        // Only the last trailing dot or space is replaced; a name of dots or a leading "X:" is
        // kept (made safe) rather than refused. The recorded name is trimmed.
        assert_eq!(names(&[r(0, "/a/Notes..", "Notes"), r(1, "/b/...", "Folder"), r(2, "/c/C:foo", "Cfoo")], true), vec!["Notes._", ".._", "C_foo"]);
        assert_eq!(names(&[r(0, "/c/C:foo", "Cfoo"), r(1, "/", " Docs ")], false), vec!["C:foo", "Docs"]);
        // A macOS name may hold "\"; a Windows path is split on it.
        assert_eq!(names(&[r(0, "/Users/a/back\\slash", "backslash"), r(1, "D:\\x\\back", "back")], false), vec!["back\\slash", "back"]);
        assert_eq!(names(&[r(0, "/Users/a/back\\slash", "backslash")], true), vec!["back_slash"]);
        // Unique ignoring Unicode form (APFS treats both spellings of "café" as one name).
        assert_eq!(names(&[r(0, "/a/caf\u{e9}", "caf\u{e9}"), r(1, "/b/cafe\u{301}", "cafe\u{301}")], false), vec!["caf\u{e9}", "cafe\u{301} (2)"]);
        // A suffix still fits in 255 bytes, cut on a character boundary.
        let long = "\u{e9}".repeat(127); // 254 bytes
        let got = names(&[r(0, &format!("/a/{long}"), "a"), r(1, &format!("/b/{long}"), "b")], false);
        assert_eq!(got[0], long);
        assert!(got[1].len() <= 255 && got[1].ends_with(" (2)") && got[1].starts_with('\u{e9}'), "{}", got[1].len());
    }
}
