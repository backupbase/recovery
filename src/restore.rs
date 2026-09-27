//! Restoring a version (or parts of it) into a folder. Never overwrites anything: a name that
//! is taken gets `name (restored).ext`. Contents are checked against their SHA-256 before
//! they get their final name; links are created last and only when they point inside the
//! target; folder times and permissions are set at the end, deepest first.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use filetime::FileTime;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::crypto;
use crate::error::{display, reason, usage, Error, Kind, Result};
use crate::pathsafe::{self, WINDOWS};
use crate::store::{self, ArchiveCursor};
use crate::text;
use crate::vault::{Entry, Index, Keys, VaultHeader, HEADER_FILE};

/// Set (by the Ctrl+C handler) to stop a restore at the next chunk.
pub static STOP: AtomicBool = AtomicBool::new(false);

fn stopping() -> bool {
    STOP.load(Ordering::Relaxed)
}

pub struct Options {
    pub to: PathBuf,
    pub prefixes: Vec<String>,
    pub keep_both: bool,
    pub progress: bool,
}

#[derive(Default, Debug)]
pub struct Report {
    pub target: PathBuf,
    pub files: u64,
    pub bytes: u64,
    pub dirs: u64,
    pub links: u64,
    /// Existing files that already held exactly this content (only with --keep-both).
    pub identical: u64,
    /// Listed in the version without content (could not be read when the backup ran).
    pub not_stored: Vec<String>,
    /// Restored copies marked as possibly incomplete (changed while being read).
    pub incomplete: Vec<String>,
    /// Saved under another name because the name was taken: (path, new name).
    pub renamed: Vec<(String, String)>,
    /// Names changed for this computer (characters Windows does not allow): (path, new path).
    pub fixed_names: Vec<(String, String)>,
    /// Links not created: (path, reason).
    pub links_skipped: Vec<(String, String)>,
    /// Entries not restored for another reason (refused names, folders that could not be made,
    /// write errors), one sentence each.
    pub problems: Vec<String>,
    /// Entries below a folder that was refused or could not be created (not listed one by one).
    pub skipped_below: u64,
    /// Files not restored because their stored copy is damaged or missing.
    pub damaged: Vec<String>,
    /// Damage that ended the pass over an archive.
    pub damage: Option<String>,
    /// Warnings about the backup itself (for example an archive of another size than its index says).
    pub warnings: Vec<String>,
    /// Files this restore was to write.
    pub files_total: u64,
    /// Stopped by Ctrl+C: the file being written was removed, nothing after it was done.
    pub stopped: bool,
}

impl Report {
    pub fn exit_code(&self) -> i32 {
        if self.damage.is_some() || !self.damaged.is_empty() {
            crate::error::EXIT_DAMAGED
        } else if !self.problems.is_empty() || self.skipped_below > 0 {
            crate::error::EXIT_INCOMPLETE
        } else {
            crate::error::EXIT_OK
        }
    }
}

/// `<root name>/<p>`: how paths are shown and matched by `--path`.
pub fn display_path(names: &HashMap<u32, String>, e: &Entry) -> String {
    let root = names.get(&e.r).map(String::as_str).unwrap_or("?");
    if e.p.is_empty() {
        root.to_string()
    } else {
        format!("{root}/{}", e.p)
    }
}

pub fn normalize_prefix(p: &str) -> String {
    let mut s: String = p.nfc().collect();
    if WINDOWS {
        s = s.replace('\\', "/");
    }
    while s.starts_with("./") {
        s.drain(..2);
    }
    while s.ends_with('/') {
        s.pop();
    }
    s
}

pub fn path_matches(display: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let d: String = display.nfc().collect();
    d == prefix || (d.len() > prefix.len() && d.starts_with(prefix) && d.as_bytes()[prefix.len()] == b'/')
}

/// Indexes of the entries a restore or listing covers; every prefix must match something.
pub fn select(idx: &Index, names: &HashMap<u32, String>, prefixes: &[String]) -> Result<Vec<usize>> {
    let prefixes: Vec<String> = prefixes.iter().map(|p| normalize_prefix(p)).collect();
    if prefixes.is_empty() {
        return Ok((0..idx.entries.len()).collect());
    }
    let mut hit = vec![false; prefixes.len()];
    let mut out = Vec::new();
    for (i, e) in idx.entries.iter().enumerate() {
        let d = display_path(names, e);
        let mut any = false;
        for (j, p) in prefixes.iter().enumerate() {
            if path_matches(&d, p) {
                hit[j] = true;
                any = true;
            }
        }
        if any {
            out.push(i);
        }
    }
    if let Some(j) = hit.iter().position(|h| !h) {
        return Err(Error::new(Kind::NotFound, format!("Nothing in this version matches --path \"{}\". Run \"backupbase-restore files\" to see the paths.", prefixes[j])));
    }
    Ok(out)
}

/// Progress on stderr, only when it is a terminal.
pub struct Progress {
    on: bool,
    last: Cell<Option<Instant>>,
    pub files_total: u64,
    pub bytes_total: u64,
    files: Cell<u64>,
    bytes: Cell<u64>,
    verb: &'static str,
}

impl Progress {
    pub fn new(on: bool, verb: &'static str, files_total: u64, bytes_total: u64) -> Progress {
        Progress { on: on && io::stderr().is_terminal(), last: Cell::new(None), files_total, bytes_total, files: Cell::new(0), bytes: Cell::new(0), verb }
    }
    pub fn add_bytes(&self, n: u64) {
        self.bytes.set(self.bytes.get() + n);
        self.tick(false);
    }
    pub fn add_file(&self) {
        self.files.set(self.files.get() + 1);
        self.tick(false);
    }
    fn tick(&self, force: bool) {
        if !self.on {
            return;
        }
        let now = Instant::now();
        if !force && self.last.get().is_some_and(|t| now.duration_since(t) < Duration::from_millis(250)) {
            return;
        }
        self.last.set(Some(now));
        let line = format!("{}: {} of {} files, {} of {}", self.verb, text::thousands(self.files.get()), text::thousands(self.files_total), text::bytes(self.bytes.get()), text::bytes(self.bytes_total));
        eprint!("\r{line:<78}");
        let _ = io::stderr().flush();
    }
    pub fn done(&self) {
        if self.on && self.last.get().is_some() {
            eprint!("\r{:<78}\r", "");
            let _ = io::stderr().flush();
        }
    }
}

/// Records the first write error, so a disk problem is not mistaken for damage.
struct Recorder<'a> {
    f: &'a mut File,
    err: Option<io::Error>,
}

impl Write for Recorder<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if stopping() {
            return Err(io::Error::other("stopped"));
        }
        match self.f.write(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                let copy = io::Error::new(e.kind(), e.to_string());
                self.err.get_or_insert(e);
                Err(copy)
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.f.flush()
    }
}

/// Skips a file's data in the archive, until Ctrl+C.
struct StopSink;

impl Write for StopSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if stopping() {
            return Err(io::Error::other("stopped"));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Streams a file's stored content into a writer (reporting bytes); returns its SHA-256.
type Fill<'a> = dyn FnMut(&mut dyn Write, &dyn Fn(u64)) -> Result<[u8; 32]> + 'a;

enum Written {
    Ok,
    /// Not written for a reason already reported (write error, damaged content, name taken).
    Skipped,
    /// Reading the stored copy failed (damage, missing): the caller decides what that means.
    ReadFailed(Error),
    /// Stopped by Ctrl+C; the temporary file was removed.
    Stopped,
}

struct FileJob {
    i: usize,
    parent: PathBuf,
    name: String,
    disp: String,
}

struct Restorer<'a> {
    idx: &'a Index,
    keep_both: bool,
    base: PathBuf,
    names: HashMap<u32, String>,
    /// The backup folder (canonical), never restored into.
    vault_dir: Option<PathBuf>,
    /// The folder that holds it (canonical), never restored into either.
    holder: Option<PathBuf>,
    ok_dirs: HashSet<PathBuf>,
    created: HashSet<PathBuf>,
    /// Links this restore made (or found already pointing where the backup says).
    #[cfg_attr(not(unix), allow(dead_code))]
    made_links: HashSet<PathBuf>,
    blocked: HashSet<(u32, String)>,
    counter: u64,
    rep: Report,
}

pub fn file_time(ms: i64) -> FileTime {
    FileTime::from_unix_time(ms.div_euclid(1000), (ms.rem_euclid(1000) * 1_000_000) as u32)
}

/// Whether `dir` or a folder above it holds a backup (`vault.bbv`).
fn in_backup_folder(dir: &Path) -> bool {
    dir.ancestors().any(|a| fs::symlink_metadata(a.join(HEADER_FILE)).is_ok())
}

/// Whether one of the folders in `dir` holds a backup (`vault.bbv`).
fn holds_backup_folder(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|rd| rd.flatten().any(|d| fs::symlink_metadata(d.path().join(HEADER_FILE)).is_ok()))
}

/// Whether `p` is `dir` or inside it (on Windows ignoring case).
fn within(p: &Path, dir: &Path) -> bool {
    if WINDOWS {
        let key = |x: &Path| PathBuf::from(display(x).to_lowercase());
        key(p).starts_with(key(dir))
    } else {
        p.starts_with(dir)
    }
}

/// The nearest folder of `p` that exists (canonical), and `p` below it: a target that does not
/// exist yet is judged by where it would be created.
fn resolve_lenient(p: &Path) -> Option<(PathBuf, PathBuf)> {
    let abs = std::path::absolute(p).ok()?;
    // (Some drives cannot report a final path: an absolute path is used there.)
    let (found, real) = abs.ancestors().find_map(|a| fs::canonicalize(a).ok().or_else(|| a.exists().then(|| a.to_path_buf())).map(|c| (a, c)))?;
    let mut full = real.clone();
    let mut above = false;
    for c in abs.strip_prefix(found).ok()?.components() {
        match c {
            Component::ParentDir => {
                // A `..` at the existing folder climbs above it (as mkdir does): the rest is
                // judged again from there, since it may name existing folders or links.
                above |= full.as_path() == real.as_path();
                full.pop();
            }
            Component::Normal(n) => full.push(n),
            _ => {}
        }
    }
    if above && full != real {
        return resolve_lenient(&full);
    }
    Some((real, full))
}

/// Whether restoring into `to` would put files into or next to a backup: inside the backup
/// being read or the folder that holds it (the synced "Backup Base" folder), inside any
/// folder that holds `vault.bbv`, or into a folder that holds a backup folder.
fn target_in_backup(to: &Path, vault_dir: &Path) -> bool {
    if std::path::absolute(to).is_ok_and(|a| in_backup_folder(&a)) {
        return true;
    }
    let Some((existing, full)) = resolve_lenient(to) else { return false };
    let vault = fs::canonicalize(vault_dir).or_else(|_| std::path::absolute(vault_dir)).ok();
    let holder = vault.as_deref().map(|v| v.parent().unwrap_or(v));
    in_backup_folder(&existing) || holder.is_some_and(|h| within(&full, h)) || holds_backup_folder(&existing)
}

const INSIDE_BACKUP: &str = "Choose a folder outside the backup folder: restoring into it would put unencrypted files where the encrypted backup is.";

/// Checks and prepares the target folder; returns its absolute form.
pub fn prepare_target(to: &Path, keep_both: bool, vault_dir: &Path) -> Result<PathBuf> {
    let mut made = Vec::new();
    if target_in_backup(to, vault_dir) {
        return Err(usage(INSIDE_BACKUP));
    }
    match fs::metadata(to) {
        Ok(md) if !md.is_dir() => return Err(usage(format!("{} is not a folder.", display(to)))),
        Ok(_) => {
            let mut rd = fs::read_dir(to).map_err(|e| Error::new(Kind::Io, format!("Could not open {}: {}.", display(to), reason(&e))))?;
            if rd.next().is_some() && !keep_both {
                return Err(usage(format!(
                    "The folder {} is not empty. Restore into a new or empty folder, or add --keep-both to keep what is there and save restored files next to existing ones.",
                    display(to)
                )));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            create_dirs(to, &mut made).map_err(|e| Error::new(Kind::Io, format!("Could not create the folder {}: {}.", display(to), reason(&e))))?;
        }
        Err(e) => return Err(Error::new(Kind::Io, format!("Could not open {}: {}.", display(to), reason(&e)))),
    }
    // Absolute (on Windows the \\?\ form, so long paths work).
    // (Some drives cannot report a final path; an absolute path is enough there.)
    let base = fs::canonicalize(to).or_else(|_| std::path::absolute(to)).map_err(|e| Error::new(Kind::Io, format!("Could not open {}: {}.", display(to), reason(&e))))?;
    if target_in_backup(&base, vault_dir) {
        // (A link that did not lead anywhere yet can make the folders land in the backup.)
        for d in made.iter().rev() {
            let _ = fs::remove_dir(d);
        }
        return Err(usage(INSIDE_BACKUP));
    }
    Ok(base)
}

/// `fs::create_dir_all` that notes the folders it made (their real paths), parents first.
fn create_dirs(p: &Path, made: &mut Vec<PathBuf>) -> io::Result<()> {
    match fs::create_dir(p) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && p.is_dir() => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let Some(parent) = p.parent().filter(|q| !q.as_os_str().is_empty()) else { return Err(e) };
            create_dirs(parent, made)?;
            match fs::create_dir(p) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && p.is_dir() => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    }
    made.push(fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()));
    Ok(())
}

pub fn restore(h: &VaultHeader, keys: &Keys, idx: &Index, opts: &Options) -> Result<Report> {
    let names = pathsafe::root_dirs(&idx.roots, WINDOWS);
    let selected = select(idx, &names, &opts.prefixes)?;
    // A missing archive fails before anything is written.
    let mut cursor = if h.version == 2 && selected.iter().any(|&i| idx.entries[i].stored()) { Some(ArchiveCursor::open(h, keys, idx)?) } else { None };
    let base = prepare_target(&opts.to, opts.keep_both, &h.dir)?;
    let vault_dir = fs::canonicalize(&h.dir).ok();
    let holder = vault_dir.as_deref().and_then(Path::parent).map(Path::to_path_buf);
    let mut r = Restorer { idx, keep_both: opts.keep_both, base: base.clone(), names, vault_dir, holder, ok_dirs: HashSet::new(), created: HashSet::new(), made_links: HashSet::new(), blocked: HashSet::new(), counter: 0, rep: Report { target: base.clone(), ..Default::default() } };
    r.ok_dirs.insert(base);

    // Folders first (index order puts a folder before what is in it), then plan the files.
    let mut jobs: Vec<FileJob> = Vec::new();
    let mut links: Vec<(usize, Vec<String>)> = Vec::new();
    let mut dirs: Vec<(usize, PathBuf)> = Vec::new();
    for &i in &selected {
        let e = &idx.entries[i];
        let disp = display_path(&r.names, e);
        let Some(comps) = r.plan(e, &disp) else { continue };
        if e.is_dir() {
            match r.ensure_dir(&comps) {
                Ok(p) => {
                    r.rep.dirs += 1;
                    dirs.push((i, p));
                }
                Err(why) => {
                    r.rep.problems.push(format!("{disp}: the folder could not be created ({why}); everything in it was skipped."));
                    r.blocked.insert((e.r, e.p.clone()));
                }
            }
        } else if e.is_link() {
            links.push((i, comps));
        } else if !e.stored() {
            r.rep.not_stored.push(disp);
        } else {
            let (parent_comps, name) = comps.split_at(comps.len() - 1);
            match r.ensure_dir(parent_comps) {
                Ok(parent) => jobs.push(FileJob { i, parent, name: name[0].clone(), disp }),
                Err(why) => {
                    let pp = parent_p(&e.p);
                    let pdisp = if pp.is_empty() { r.names[&e.r].clone() } else { format!("{}/{}", r.names[&e.r], pp) };
                    r.rep.problems.push(format!("{pdisp}: the folder could not be created ({why}); everything in it was skipped."));
                    r.blocked.insert((e.r, pp.to_string()));
                    r.rep.skipped_below += 1;
                }
            }
        }
    }

    let files_total = jobs.len() as u64;
    r.rep.files_total = files_total;
    let bytes_total = jobs.iter().map(|j| idx.entries[j.i].size()).sum();
    let prog = Progress::new(opts.progress, "Restoring", files_total, bytes_total);
    if h.version == 1 {
        for j in &jobs {
            if stopping() {
                r.rep.stopped = true;
                break;
            }
            let e = &idx.entries[j.i];
            let b = e.b.clone().unwrap_or_default();
            match r.write_file(j, e, &prog, &mut |w: &mut dyn Write, on: &dyn Fn(u64)| store::read_blob(h, keys, &b, w, on).map(|(sha, _)| sha)) {
                Written::ReadFailed(err) => r.rep.damaged.push(format!("{}: {}", j.disp, short(&err))),
                Written::Stopped => {
                    r.rep.stopped = true;
                    break;
                }
                _ => {}
            }
        }
    } else if let Some(c) = cursor.as_mut() {
        if !c.size_matches() {
            r.rep.warnings.push(format!("The archive {} is {} but its index says otherwise; every restored file is still checked against its SHA-256.", display(&c.path), text::bytes(c.file_size)));
        }
        r.archive_pass(c, &jobs, &prog);
    }
    prog.done();
    if r.rep.stopped {
        return Ok(r.rep);
    }

    if WINDOWS {
        for (i, _) in &links {
            let e = &idx.entries[*i];
            r.rep.links_skipped.push((display_path(&r.names, e), "symbolic links are not created on Windows".into()));
        }
    } else {
        for (i, comps) in &links {
            r.make_link(*i, comps);
        }
    }

    // Folder times and permissions last, deepest first, only on folders this restore made.
    dirs.sort_by_key(|(_, p)| std::cmp::Reverse(p.components().count()));
    for (i, p) in &dirs {
        if !r.created.contains(p) {
            continue;
        }
        let e = &idx.entries[*i];
        if let Some(m) = e.m {
            let _ = filetime::set_file_mtime(p, file_time(m));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = e.mode.map(|m| m & 0o777).unwrap_or(0o755);
            if let Err(err) = fs::set_permissions(p, fs::Permissions::from_mode(mode)) {
                r.rep.problems.push(format!("{}: the folder's permissions could not be set ({}).", display_path(&r.names, e), reason(&err)));
            }
        }
    }
    Ok(r.rep)
}

fn parent_p(p: &str) -> &str {
    match p.rfind('/') {
        Some(i) => &p[..i],
        None => "",
    }
}

fn short(e: &Error) -> String {
    e.message.trim_end_matches('.').to_string()
}

fn file_sha(path: &Path) -> Option<[u8; 32]> {
    let mut f = File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize().into())
}

impl Restorer<'_> {
    fn is_blocked(&self, r: u32, p: &str) -> bool {
        if self.blocked.is_empty() {
            return false;
        }
        if self.blocked.contains(&(r, String::new())) || self.blocked.contains(&(r, p.to_string())) {
            return true;
        }
        p.match_indices('/').any(|(i, _)| self.blocked.contains(&(r, p[..i].to_string())))
    }

    /// Safe components (root folder first) for an entry, or None when it is not restored.
    fn plan(&mut self, e: &Entry, disp: &str) -> Option<Vec<String>> {
        if self.is_blocked(e.r, &e.p) {
            self.rep.skipped_below += 1;
            return None;
        }
        match pathsafe::fix_path(&e.p, WINDOWS) {
            Ok((comps, changed)) => {
                let mut all = Vec::with_capacity(comps.len() + 1);
                all.push(self.names[&e.r].clone());
                all.extend(comps);
                if changed {
                    self.rep.fixed_names.push((disp.to_string(), all.join("/")));
                }
                Some(all)
            }
            Err(why) => {
                self.rep.problems.push(format!("{disp}: not restored, {why}."));
                if e.is_dir() {
                    self.blocked.insert((e.r, e.p.clone()));
                }
                None
            }
        }
    }

    /// Why nothing may be restored into an existing folder: it is a backup folder (holds
    /// `vault.bbv`) or inside this one, it is (or is inside) the folder that holds this backup,
    /// or it holds another backup folder. The backed-up folder's name can lead there.
    fn refused_folder(&self, p: &Path) -> Option<String> {
        let real = fs::canonicalize(p).ok();
        let inside = |dir: &Option<PathBuf>| matches!((&real, dir), (Some(c), Some(d)) if within(c, d));
        if fs::symlink_metadata(p.join(HEADER_FILE)).is_ok() || inside(&self.vault_dir) {
            Some(format!("{} is a Backup Base backup folder, and nothing is restored into one", display(p)))
        } else if holds_backup_folder(p) || real.is_some() && real == self.holder {
            Some(format!("{} holds a Backup Base backup folder, and nothing is restored next to one", display(p)))
        } else if inside(&self.holder) {
            Some(format!("{} is inside the folder that holds the backup, and nothing is restored there", display(p)))
        } else {
            None
        }
    }

    /// Creates (or accepts existing) real folders for `comps` below the target, never
    /// through a symbolic link or junction, and never into or next to a backup folder.
    fn ensure_dir(&mut self, comps: &[String]) -> std::result::Result<PathBuf, String> {
        let mut cur = self.base.clone();
        for c in comps {
            cur.push(c);
            if self.ok_dirs.contains(&cur) {
                continue;
            }
            match fs::symlink_metadata(&cur) {
                Ok(md) if md.is_dir() => {
                    if let Some(why) = self.refused_folder(&cur) {
                        return Err(why);
                    }
                }
                Ok(_) => return Err(format!("{} is in the way", display(&cur))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::create_dir(&cur) {
                    Ok(()) => {
                        self.created.insert(cur.clone());
                    }
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists && fs::symlink_metadata(&cur).map(|m| m.is_dir()).unwrap_or(false) => {
                        if let Some(why) = self.refused_folder(&cur) {
                            return Err(why);
                        }
                    }
                    Err(e) => return Err(reason(&e)),
                },
                Err(e) => return Err(reason(&e)),
            }
            self.ok_dirs.insert(cur.clone());
        }
        Ok(cur)
    }

    fn temp_file(&mut self, dir: &Path, e: &Entry) -> io::Result<(PathBuf, File)> {
        loop {
            self.counter += 1;
            let p = dir.join(format!(".bbrestore-{:x}-{}.tmp", std::process::id(), self.counter));
            let mut o = OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                if e.attr.is_some_and(|a| a & 2 != 0) {
                    o.attributes(2); // FILE_ATTRIBUTE_HIDDEN
                }
            }
            #[cfg(not(windows))]
            let _ = e;
            match o.open(&p) {
                Ok(f) => return Ok((p, f)),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }
    }

    fn free_name(&self, dir: &Path, name: &str) -> Option<String> {
        (1..=10_000).map(|n| pathsafe::restored_name(name, n)).find(|c| matches!(fs::symlink_metadata(dir.join(c)), Err(e) if e.kind() == io::ErrorKind::NotFound))
    }

    /// Writes one file: temp file, SHA-256 check, a free final name, times, permissions.
    fn write_file(&mut self, j: &FileJob, e: &Entry, prog: &Progress, fill: &mut Fill) -> Written {
        let expected = e.h.as_deref().and_then(crypto::unhex::<32>).unwrap_or([0; 32]);
        let (tmp, mut f) = match self.temp_file(&j.parent, e) {
            Ok(x) => x,
            Err(err) => {
                self.rep.problems.push(format!("{}: could not be written ({}).", j.disp, reason(&err)));
                return Written::Skipped;
            }
        };
        let mut rec = Recorder { f: &mut f, err: None };
        let res = fill(&mut rec, &|n| prog.add_bytes(n));
        let werr = rec.err.take();
        let flushed = f.flush();
        drop(f);
        if stopping() {
            let _ = fs::remove_file(&tmp);
            return Written::Stopped;
        }
        let sha = match (res, werr.or(flushed.err())) {
            (_, Some(we)) => {
                let _ = fs::remove_file(&tmp);
                self.rep.problems.push(format!("{}: could not be written ({}).", j.disp, reason(&we)));
                return Written::Skipped;
            }
            (Err(err), None) => {
                let _ = fs::remove_file(&tmp);
                return Written::ReadFailed(err);
            }
            (Ok(sha), None) => sha,
        };
        if sha != expected {
            let _ = fs::remove_file(&tmp);
            self.rep.damaged.push(format!("{}: its content does not match its SHA-256", j.disp));
            return Written::Skipped;
        }
        let mut dest = j.parent.join(&j.name);
        match fs::symlink_metadata(&dest) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Ok(md) => {
                if self.keep_both && md.is_file() && md.len() == e.size() && file_sha(&dest) == Some(sha) {
                    let _ = fs::remove_file(&tmp);
                    self.rep.identical += 1;
                    prog.add_file();
                    return Written::Ok;
                }
                match self.free_name(&j.parent, &j.name) {
                    Some(n) => {
                        self.rep.renamed.push((j.disp.clone(), n.clone()));
                        dest = j.parent.join(n);
                    }
                    None => {
                        let _ = fs::remove_file(&tmp);
                        self.rep.problems.push(format!("{}: no free name to save it under.", j.disp));
                        return Written::Skipped;
                    }
                }
            }
            Err(err) => {
                let _ = fs::remove_file(&tmp);
                self.rep.problems.push(format!("{}: could not be written ({}).", j.disp, reason(&err)));
                return Written::Skipped;
            }
        }
        if let Err(err) = fs::rename(&tmp, &dest) {
            let _ = fs::remove_file(&tmp);
            self.rep.problems.push(format!("{}: could not be written ({}).", j.disp, reason(&err)));
            return Written::Skipped;
        }
        if let Err(err) = apply_file_meta(&dest, e) {
            self.rep.problems.push(format!("{}: restored, but its time or permissions could not be set ({}).", j.disp, reason(&err)));
        }
        self.rep.files += 1;
        self.rep.bytes += e.size();
        if e.incomplete() {
            self.rep.incomplete.push(j.disp.clone());
        }
        prog.add_file();
        Written::Ok
    }

    /// One pass over a v2 archive in index order; stops after the last selected file.
    fn archive_pass(&mut self, c: &mut ArchiveCursor, jobs: &[FileJob], prog: &Progress) {
        let Some(last) = jobs.iter().map(|j| j.i).max() else { return };
        let by_index: HashMap<usize, &FileJob> = jobs.iter().map(|j| (j.i, j)).collect();
        let idx = self.idx;
        for (i, e) in idx.entries.iter().enumerate() {
            if i > last {
                break;
            }
            if stopping() {
                self.rep.stopped = true;
                return;
            }
            if !store::in_archive(e) {
                continue;
            }
            let res: std::result::Result<(), (Option<String>, String)> = (|| {
                c.expect(e).map_err(|err| (None, err.to_string()))?;
                if !e.is_file() {
                    return Ok(());
                }
                match by_index.get(&i) {
                    Some(j) => match self.write_file(j, e, prog, &mut |w: &mut dyn Write, on: &dyn Fn(u64)| {
                        c.copy_file(w, on).map_err(|err| Error::new(Kind::Corrupt, err.to_string()))
                    }) {
                        Written::ReadFailed(err) => Err((Some(j.disp.clone()), err.message)),
                        Written::Stopped => Err((None, String::new())),
                        _ => Ok(()),
                    },
                    None => c.copy_file(&mut StopSink, |_| {}).map(|_| ()).map_err(|err| (None, err.to_string())),
                }
            })();
            if res.is_err() && stopping() {
                self.rep.stopped = true;
                return;
            }
            if let Err((_, why)) = res {
                let disp = display_path(&self.names, e);
                self.rep.damage = Some(format!("The archive {} is damaged at \"{disp}\": {why}. Files before that point were restored.", display(&c.path)));
                for j in jobs.iter().filter(|j| j.i >= i) {
                    self.rep.damaged.push(format!("{}: not restored (the archive is damaged at or before it)", j.disp));
                }
                return;
            }
        }
    }

    #[cfg(unix)]
    fn make_link(&mut self, i: usize, comps: &[String]) {
        let e = &self.idx.entries[i];
        let disp = display_path(&self.names, e);
        let target = e.t.clone().unwrap_or_default();
        let (parent_comps, name) = comps.split_at(comps.len() - 1);
        if !pathsafe::link_stays_inside(parent_comps, &target) {
            self.rep.links_skipped.push((disp, format!("it points outside the restore folder ({target})")));
            return;
        }
        let parent = match self.ensure_dir(parent_comps) {
            Ok(p) => p,
            Err(why) => {
                self.rep.problems.push(format!("{disp}: the link could not be created ({why})."));
                return;
            }
        };
        // A name the target goes through may be a link that was already in the folder
        // (--keep-both) and points anywhere: only links this restore made are trusted.
        let (up, through) = pathsafe::link_names(&target);
        let mut cur = parent.clone();
        for _ in 0..up {
            cur.pop();
        }
        for n in through {
            cur.push(n);
            if fs::symlink_metadata(&cur).is_ok_and(|m| m.file_type().is_symlink()) && !self.made_links.contains(&cur) {
                self.rep.links_skipped.push((disp, format!("it points through a link that was already in the restore folder ({target})")));
                return;
            }
        }
        let mut dest = parent.join(&name[0]);
        if fs::symlink_metadata(&dest).is_ok() {
            if self.keep_both && fs::read_link(&dest).map(|t| t.as_os_str() == std::ffi::OsStr::new(&target)).unwrap_or(false) {
                self.made_links.insert(dest);
                self.rep.links += 1;
                return;
            }
            match self.free_name(&parent, &name[0]) {
                Some(n) => {
                    self.rep.renamed.push((disp.clone(), n.clone()));
                    dest = parent.join(n);
                }
                None => {
                    self.rep.problems.push(format!("{disp}: no free name to create the link under."));
                    return;
                }
            }
        }
        match std::os::unix::fs::symlink(&target, &dest) {
            Ok(()) => {
                if let Some(m) = e.m {
                    let t = file_time(m);
                    let _ = filetime::set_symlink_file_times(&dest, t, t);
                }
                self.made_links.insert(dest);
                self.rep.links += 1;
            }
            Err(err) => self.rep.problems.push(format!("{disp}: the link could not be created ({}).", reason(&err))),
        }
    }

    #[cfg(not(unix))]
    fn make_link(&mut self, _i: usize, _comps: &[String]) {}
}

fn apply_file_meta(path: &Path, e: &Entry) -> io::Result<()> {
    if let Some(m) = e.m {
        filetime::set_file_mtime(path, file_time(m))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut mode = e.mode.map(|m| m & 0o777).unwrap_or(0o644);
        if e.mode.is_none() && e.attr.is_some_and(|a| a & 1 != 0) {
            mode &= !0o222;
        }
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let readonly = match (e.attr, e.mode) {
            (Some(a), _) => a & 1 != 0,
            (None, Some(m)) => m & 0o200 == 0,
            (None, None) => false,
        };
        if readonly {
            let mut p = fs::metadata(path)?.permissions();
            p.set_readonly(true);
            fs::set_permissions(path, p)?;
        }
    }
    Ok(())
}
