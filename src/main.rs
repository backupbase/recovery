//! backupbase-restore command line.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bbrestore::error::{self, display, usage, Error, Kind, Result, EXIT_DAMAGED, EXIT_OK, EXIT_PASSCODE};
use bbrestore::passcode::{self, Source};
use bbrestore::restore::{self, display_path};
use bbrestore::text::{self, bytes, plural, thousands};
use bbrestore::vault::{self, VaultHeader};
use bbrestore::{load_version, pathsafe, resolve_vault, verify};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// println! for anything that can hold names from the backup: control characters become `?`.
macro_rules! say {
    () => { println!() };
    ($($t:tt)*) => { println!("{}", text::clean(&format!($($t)*))) };
}

const HELP: &str = "backupbase-restore VERSION
Restore files from a Backup Base backup folder on any computer, without the app.

Usage:
  backupbase-restore list <folder>
  backupbase-restore files <backup> [--version <id|latest>] [--path <path>]
  backupbase-restore restore <backup> --to <folder> [--version <id|latest>]
                             [--path <path>]... [--keep-both]
  backupbase-restore verify <backup> [--version <id|latest> | --all]
  backupbase-restore help <command>

<folder> is the folder that holds your backups, for example the \"Backup Base\"
folder in your OneDrive, SharePoint or Google Drive folder.
<backup> is one backup in it (the folder that holds vault.bbv), or a folder
that holds only one backup.

Passcode: you are asked for it, and nothing is shown while you type. For
scripts, set the BB_PASSCODE environment variable, or use
--passcode-file <file> (the first line of the file is the passcode; UTF-8,
or UTF-16 as Windows PowerShell writes it).

Restore into a folder outside your cloud folder: this tool cannot know which
folders your sync app uploads.

Exit codes:
  0    done
  1    error (for example a disk or permission problem)
  2    wrong command line, or the target folder is not empty or is in or
       next to a backup
  3    wrong passcode
  4    no backup, version or path found, or the backup needs a newer version
  5    damage found: some files could not be restored or verified, or a
       version could not be read (restore and files then use an older one)
  6    the restore finished, but some items were skipped (they are listed)
  130  stopped with Ctrl+C

Run \"backupbase-restore help <command>\" for details on a command.
";

const HELP_LIST: &str = "backupbase-restore list <folder> [--passcode-file <file>] [--no-passcode]

Shows the backups in <folder> (or <folder> itself when it is a backup): name,
format, when and by which app version it was made, and its versions with
their date, number of files and size.

Listing versions needs the passcode of each backup. You are asked once per
backup (press Enter to skip one). BB_PASSCODE or --passcode-file is tried on
every backup. --no-passcode shows only what can be read without it.

A version whose index is damaged is listed under \"Ignored\", and the exit
code is 5.
";

const HELP_FILES: &str = "backupbase-restore files <backup> [--version <id|latest>] [--path <path>]
                         [--passcode-file <file>]

Lists the files, folders and links in one version (the latest by default).
Each line shows the kind (d folder, f file, l link), the size in bytes, the
modification time (UTC) and the path. Paths start with the backed-up folder's
name, for example Documents/Contracts/nda.pdf. --path shows only that file or
folder and what is in it.

--version takes a version id from \"list\" (or its first characters), or latest.
Without --version, when the newest version cannot be read, the newest one
that can be read is listed, with a warning, and the exit code is 5.
";

const HELP_RESTORE: &str = "backupbase-restore restore <backup> --to <folder> [--version <id|latest>]
                           [--path <path>]... [--keep-both] [--passcode-file <file>]

Restores one version (the latest by default) into <folder>, as
<folder>/<backed-up folder name>/... Use --path (more than once if you like)
to restore only some files or folders; paths are shown by \"files\".

Nothing is ever overwritten. <folder> must be new or empty, unless you add
--keep-both: then existing files stay, a file that already has exactly the
restored content is left alone, and other restored files are saved as
\"name (restored).ext\".

Every file is checked against its SHA-256 before it gets its name. Files get
their modification time and their read-only setting back (and permissions on
macOS and Linux). Symbolic links are created last, only when they point
inside <folder> (on Windows they are skipped). Links not created are listed
but do not change the exit code. Paths that are not safe, and names Windows
does not allow, are refused or changed, and listed.

It never restores into a backup folder, into the folder that holds the
backup (the \"Backup Base\" folder), into anything inside those, or into a
folder that holds a backup folder. Such a target is refused (exit code 2).
With --keep-both, a folder already in <folder> that is one of these (for
example one with the same name as the backed-up folder) is skipped with
everything that would go in it, and listed (exit code 6). Choose a folder
outside your cloud folder: this tool cannot know which folders your sync app
uploads.

Without --version, when the newest version cannot be read, the newest one
that can be read is restored, with a warning, and the exit code is 5.

Ctrl+C stops the restore: the file being written is removed, files already
restored are complete, and the exit code is 130. A second Ctrl+C stops at
once and leaves the file being written (.bbrestore-<numbers>.tmp) behind.
";

const HELP_VERIFY: &str = "backupbase-restore verify <backup> [--version <id|latest> | --all]
                          [--passcode-file <file>]

Decrypts everything a version stores and checks every file's SHA-256, without
writing anything. Checks the latest version by default, or every version
with --all. Exit code 5 when a problem is found, including a newer version
whose index cannot be read (the latest readable version is then checked).
";

#[derive(Default)]
struct Args {
    cmd: String,
    positional: Vec<OsString>,
    version: Option<String>,
    paths: Vec<String>,
    to: Option<OsString>,
    keep_both: bool,
    all: bool,
    no_passcode: bool,
    passcode_file: Option<OsString>,
    help: bool,
}

fn utf8(v: OsString, opt: &str) -> Result<String> {
    v.into_string().map_err(|_| usage(format!("The value of {opt} is not valid text.")))
}

fn parse(argv: Vec<OsString>) -> Result<Args> {
    let mut a = Args::default();
    let mut it = argv.into_iter();
    let mut only_positional = false;
    while let Some(arg) = it.next() {
        let s = arg.to_string_lossy().into_owned();
        if only_positional || !s.starts_with('-') || s == "-" {
            if a.cmd.is_empty() {
                a.cmd = s;
            } else {
                a.positional.push(arg);
            }
            continue;
        }
        if s == "--" {
            only_positional = true;
            continue;
        }
        let (name, inline) = match s.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_string(), Some(OsString::from(v))),
            _ => (s.clone(), None),
        };
        let value = |it: &mut std::vec::IntoIter<OsString>| -> Result<OsString> { inline.clone().or_else(|| it.next()).ok_or_else(|| usage(format!("{name} needs a value."))) };
        match name.as_str() {
            "-h" | "--help" => a.help = true,
            "-V" if a.cmd.is_empty() => a.cmd = "--version".into(),
            "--version" if a.cmd.is_empty() => a.cmd = "--version".into(),
            "--version" => a.version = Some(utf8(value(&mut it)?, "--version")?),
            "--path" => a.paths.push(utf8(value(&mut it)?, "--path")?),
            "--to" => a.to = Some(value(&mut it)?),
            "--passcode-file" => a.passcode_file = Some(value(&mut it)?),
            "--keep-both" => a.keep_both = true,
            "--all" => a.all = true,
            "--no-passcode" => a.no_passcode = true,
            _ => return Err(usage(format!("Unknown option {name}. Run \"backupbase-restore --help\"."))),
        }
    }
    Ok(a)
}

fn one_path(a: &Args, what: &str) -> Result<PathBuf> {
    match a.positional.len() {
        1 => Ok(PathBuf::from(&a.positional[0])),
        0 => Err(usage(format!("Name the {what}. Run \"backupbase-restore help {}\".", a.cmd))),
        _ => Err(usage(format!("Too many arguments. Run \"backupbase-restore help {}\".", a.cmd))),
    }
}

fn allow(a: &Args, version: bool, paths: bool, to: bool, keep_both: bool, all: bool, no_pass: bool) -> Result<()> {
    let bad = [(a.version.is_some() && !version, "--version"), (!a.paths.is_empty() && !paths, "--path"), (a.to.is_some() && !to, "--to"), (a.keep_both && !keep_both, "--keep-both"), (a.all && !all, "--all"), (a.no_passcode && !no_pass, "--no-passcode")];
    if let Some((_, opt)) = bad.iter().find(|(b, _)| *b) {
        return Err(usage(format!("{opt} does not apply to \"{}\". Run \"backupbase-restore help {}\".", a.cmd, a.cmd)));
    }
    Ok(())
}

fn open(dir: &Path, a: &Args) -> Result<(VaultHeader, vault::Keys)> {
    let h = VaultHeader::read(dir)?;
    let file = a.passcode_file.as_ref().map(PathBuf::from);
    let src = passcode::source(file.as_deref());
    let pw = passcode::get(&src, &h.label(), false)?.expect("a passcode (skipping is off)");
    let keys = h.unlock(&pw)?;
    Ok((h, keys))
}

fn format_line(h: &VaultHeader) -> &'static str {
    if h.version == 1 {
        "version 1 (one encrypted file per file)"
    } else {
        "version 2 (one encrypted archive per run)"
    }
}

fn created_line(h: &VaultHeader) -> String {
    let mut s = h.created_at.as_deref().map(text::rfc3339).unwrap_or_else(|| "unknown date".into());
    if let Some(v) = &h.app_version {
        s.push_str(&format!(" by Backup Base {v}"));
    }
    if let Some(os) = &h.os {
        s.push_str(&format!(" on {}", text::os_label(os)));
    }
    s
}

fn cmd_list(a: &Args) -> Result<i32> {
    allow(a, false, false, false, false, false, true)?;
    let folder = one_path(a, "folder that holds your backups")?;
    if !folder.exists() {
        return Err(error::not_found(format!("{} does not exist.", display(&folder))));
    }
    let found = vault::find_vaults(&folder);
    if found.is_empty() {
        return Err(Error::new(Kind::NotAVault, format!("No Backup Base backup was found in {}.", display(&folder))));
    }
    let file = a.passcode_file.as_ref().map(PathBuf::from);
    let src = passcode::source(file.as_deref());
    let mut code = EXIT_OK;
    say!("{} in {}", plural(found.len() as u64, "backup", "backups"), display(&folder));
    for dir in &found {
        say!();
        let h = match VaultHeader::read(dir) {
            Ok(h) => h,
            Err(e) => {
                say!("{}", display(dir));
                say!("  Cannot be opened: {e}");
                code = code.max(e.exit_code());
                continue;
            }
        };
        say!("\"{}\"", h.label());
        say!("  Folder:    {}", display(dir));
        say!("  Format:    {}", format_line(&h));
        say!("  Created:   {}", created_line(&h));
        let (ids, other) = h.version_files()?;
        if a.no_passcode {
            say!("  Versions:  {} found (the passcode is needed to list them)", thousands(ids.len() as u64));
            continue;
        }
        let pw = match passcode::get(&src, &h.label(), matches!(src, Source::Prompt))? {
            Some(pw) => pw,
            None => {
                say!("  Versions:  {} found (skipped, no passcode)", thousands(ids.len() as u64));
                continue;
            }
        };
        let keys = match h.unlock(&pw) {
            Ok(k) => k,
            Err(e) if e.kind == Kind::WrongPasscode => {
                say!("  Versions:  {} found, but the passcode does not open this backup", thousands(ids.len() as u64));
                code = code.max(EXIT_PASSCODE);
                continue;
            }
            Err(e) => return Err(e),
        };
        let mut lines = Vec::new();
        let mut unreadable = Vec::new();
        for id in ids.iter().rev() {
            match h.read_index(&keys, id, false) {
                Ok(idx) => {
                    let missing = h.version == 2 && idx.archive.as_ref().is_some_and(|ar| !h.index_dir().join(&ar.file).is_file());
                    lines.push(format!(
                        "    {id}  {}  {:>15}  {:>9}{}",
                        text::id_date(id),
                        plural(idx.stats.files, "file", "files"),
                        bytes(idx.stats.bytes),
                        if missing { "  (archive missing)" } else { "" }
                    ));
                }
                Err(e) if e.kind == Kind::Corrupt => unreadable.push(format!("{id}.bbs")),
                Err(e) => lines.push(format!("    {id}  could not be read: {e}")),
            }
        }
        say!("  Versions:  {} (newest first)", thousands(lines.len() as u64));
        for l in &lines {
            say!("{l}");
        }
        let unreadable_n = unreadable.len();
        let ignored = other.len() + unreadable_n;
        if ignored > 0 {
            let mut all = other.clone();
            all.extend(unreadable);
            say!("  Ignored:   {} in {} that {} not a version this backup can read: {}", plural(ignored as u64, "file", "files"), display(&h.index_dir()), if ignored == 1 { "is" } else { "are" }, all.join(", "));
        }
        if unreadable_n > 0 {
            code = code.max(EXIT_DAMAGED);
        }
    }
    Ok(code)
}

fn version_heading(h: &VaultHeader, idx: &vault::Index) -> String {
    format!("Backup \"{}\", version {} ({})", h.label(), idx.id, text::id_date(&idx.id))
}

/// Newer versions whose index could not be read: damage, so the command ends with exit code 5.
fn warn_passed(passed: &[(String, String)], used: &str) {
    for (id, why) in passed {
        eprintln!("{}", text::clean(&format!("Warning: version {id} could not be read ({}), so the newest version that can be read, {used}, is used.", why.trim_end_matches('.'))));
    }
}

/// Ctrl+C sets restore::STOP instead of ending the process, so a restore can remove the file
/// it is writing before it stops. A second Ctrl+C ends the process at once (exit code 130).
fn stop_on_ctrl_c() {
    use std::sync::atomic::Ordering;
    #[cfg(unix)]
    {
        extern "C" fn on_sigint(_: std::ffi::c_int) {
            if restore::STOP.swap(true, Ordering::Relaxed) {
                // SAFETY: _exit is async-signal-safe.
                unsafe { _exit(error::EXIT_STOPPED) }
            }
        }
        extern "C" {
            fn signal(signum: std::ffi::c_int, handler: usize) -> usize;
            fn _exit(status: std::ffi::c_int) -> !;
        }
        const SIGINT: std::ffi::c_int = 2;
        const SIG_IGN: usize = 1;
        // SAFETY: the handler only uses an atomic and _exit, which are async-signal-safe.
        unsafe {
            // Ctrl+C that was ignored when the tool started (nohup, a background job) stays ignored.
            if signal(SIGINT, on_sigint as extern "C" fn(std::ffi::c_int) as usize) == SIG_IGN {
                signal(SIGINT, SIG_IGN);
            }
        }
    }
    #[cfg(windows)]
    {
        extern "system" fn on_ctrl(kind: u32) -> i32 {
            // CTRL_C_EVENT (0) and CTRL_BREAK_EVENT (1); others (closing the window) keep their default.
            if kind > 1 {
                return 0;
            }
            if restore::STOP.swap(true, Ordering::Relaxed) {
                std::process::exit(error::EXIT_STOPPED);
            }
            1
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
        }
        // SAFETY: registers a handler that only uses an atomic and ends the process.
        unsafe {
            SetConsoleCtrlHandler(Some(on_ctrl), 1);
        }
    }
}

fn cmd_files(a: &Args) -> Result<i32> {
    allow(a, true, true, false, false, false, false)?;
    if a.paths.len() > 1 {
        return Err(usage("\"files\" takes one --path."));
    }
    let dir = resolve_vault(&one_path(a, "backup")?)?;
    let (h, keys) = open(&dir, a)?;
    let (idx, passed) = load_version(&h, &keys, a.version.as_deref())?;
    warn_passed(&passed, &idx.id);
    let damaged = if passed.is_empty() { EXIT_OK } else { EXIT_DAMAGED };
    let names = pathsafe::root_dirs(&idx.roots, pathsafe::WINDOWS);
    let sel = restore::select(&idx, &names, &a.paths)?;
    let (mut files, mut dirs, mut links, mut total, mut not_stored) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let out = std::io::stdout();
    let mut out = std::io::BufWriter::new(out.lock());
    let _ = writeln!(out, "{}", text::clean(&version_heading(&h, &idx)));
    if !idx.device.name.is_empty() {
        let _ = writeln!(out, "{}", text::clean(&format!("Made on {} ({}) by Backup Base {}", idx.device.name, text::os_label(&idx.device.os), idx.device.app_version)));
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Kind           Size  Modified (UTC)       Path");
    for &i in &sel {
        let e = &idx.entries[i];
        let path = display_path(&names, e);
        let when = e.m.map(text::utc_ms).unwrap_or_else(|| " ".repeat(19));
        let line = match e.k.as_str() {
            "d" => {
                dirs += 1;
                format!("d    {:>14}  {when}  {path}/", "-")
            }
            "l" => {
                links += 1;
                format!("l    {:>14}  {when}  {path} -> {}", "-", e.t.as_deref().unwrap_or(""))
            }
            _ => {
                let mut l = format!("f    {:>14}  {when}  {path}", e.size());
                if !e.stored() {
                    not_stored += 1;
                    l.push_str("  [not stored in this version]");
                } else {
                    files += 1;
                    total += e.size();
                    if e.incomplete() {
                        l.push_str("  [may be incomplete]");
                    }
                }
                l
            }
        };
        if writeln!(out, "{}", text::clean(&line)).is_err() {
            return Ok(damaged); // output closed (for example piped into head)
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "{} ({}), {}, {}", plural(files, "file", "files"), bytes(total), plural(dirs, "folder", "folders"), plural(links, "link", "links"));
    if not_stored > 0 {
        let _ = writeln!(out, "{} listed without content: {} could not be read when this backup ran, so {} cannot be restored from this version (an older version may hold {}).", plural(not_stored, "file is", "files are"), if not_stored == 1 { "it" } else { "they" }, if not_stored == 1 { "it" } else { "they" }, if not_stored == 1 { "it" } else { "them" });
    }
    Ok(damaged)
}

fn print_list(title: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    say!("{title}");
    for i in items {
        say!("  {i}");
    }
}

fn cmd_restore(a: &Args) -> Result<i32> {
    allow(a, true, true, true, true, false, false)?;
    let to = a.to.as_ref().map(PathBuf::from).ok_or_else(|| usage("Name the folder to restore into with --to <folder>."))?;
    let dir = resolve_vault(&one_path(a, "backup")?)?;
    let (h, keys) = open(&dir, a)?;
    let (idx, passed) = load_version(&h, &keys, a.version.as_deref())?;
    warn_passed(&passed, &idx.id);
    let opts = restore::Options { to, prefixes: a.paths.clone(), keep_both: a.keep_both, progress: true };
    stop_on_ctrl_c();
    let rep = restore::restore(&h, &keys, &idx, &opts)?;
    if rep.stopped {
        let _ = std::io::stdout().flush();
        eprintln!("Stopped: {} of {} restored. Files already restored are complete.", thousands(rep.files + rep.identical), plural(rep.files_total, "file", "files"));
        return Ok(error::EXIT_STOPPED);
    }

    say!("{}", version_heading(&h, &idx));
    say!("Restored into {}", display(&rep.target));
    say!("  Files:    {} ({})", thousands(rep.files), bytes(rep.bytes));
    say!("  Folders:  {}", thousands(rep.dirs));
    say!("  Links:    {}", thousands(rep.links));
    if rep.identical > 0 {
        say!("  Already there with the same content: {}", plural(rep.identical, "file", "files"));
    }
    for w in &rep.warnings {
        say!("Warning: {w}");
    }
    let n = rep.not_stored.len() as u64;
    if n > 0 {
        print_list(&format!("{} not restored because this version lists {} without content (not readable when the backup ran; an older version may hold {}):", plural(n, "file was", "files were"), if n == 1 { "it" } else { "them" }, if n == 1 { "it" } else { "them" }), &rep.not_stored);
    }
    let n = rep.incomplete.len() as u64;
    if n > 0 {
        print_list(&format!("{} restored, but may be incomplete (changed while the backup was reading {}):", plural(n, "file was", "files were"), if n == 1 { "it" } else { "them" }), &rep.incomplete);
    }
    let renamed: Vec<String> = rep.renamed.iter().map(|(p, n)| format!("{p}  saved as  {n}")).collect();
    print_list("Saved under another name because the name was taken:", &renamed);
    let fixed: Vec<String> = rep.fixed_names.iter().map(|(p, n)| format!("{p}  restored as  {n}")).collect();
    print_list("Names changed for this computer:", &fixed);
    let links: Vec<String> = rep.links_skipped.iter().map(|(p, why)| format!("{p}: {why}")).collect();
    print_list("Links not created:", &links);
    print_list("Not restored:", &rep.problems);
    if rep.skipped_below > 0 {
        say!("  ({} inside folders that could not be restored {} skipped.)", plural(rep.skipped_below, "item", "items"), if rep.skipped_below == 1 { "was" } else { "were" });
    }
    if let Some(d) = &rep.damage {
        say!("Damage: {d}");
    }
    print_list("Not restored because the backup is damaged:", &rep.damaged);
    if !passed.is_empty() {
        say!("Warning: {} newer than this one could not be read, so this is not the newest backup (see the warning above).", plural(passed.len() as u64, "version", "versions"));
        return Ok(EXIT_DAMAGED);
    }
    Ok(rep.exit_code())
}

fn cmd_verify(a: &Args) -> Result<i32> {
    allow(a, true, false, false, false, true, false)?;
    if a.all && a.version.is_some() {
        return Err(usage("Use either --version or --all."));
    }
    let dir = resolve_vault(&one_path(a, "backup")?)?;
    let (h, keys) = open(&dir, a)?;
    let mut targets = Vec::new();
    let mut code = EXIT_OK;
    if a.all {
        let (ids, _) = h.version_files()?;
        if ids.is_empty() {
            return Err(error::not_found("This backup has no versions."));
        }
        for id in ids.iter().rev() {
            match h.read_index(&keys, id, true) {
                Ok(idx) => targets.push(idx),
                Err(e) => {
                    say!("Version {id} ({}): its index cannot be read: {e}", text::id_date(id));
                    code = EXIT_DAMAGED;
                }
            }
        }
    } else {
        // Without --version, a newer version whose index cannot be read is damage too.
        let (idx, passed) = load_version(&h, &keys, a.version.as_deref())?;
        for (id, why) in &passed {
            say!("Version {id} ({}): its index cannot be read: {why}", text::id_date(id));
            code = EXIT_DAMAGED;
        }
        targets.push(idx);
    }
    for idx in &targets {
        say!("{}", version_heading(&h, idx));
        let rep = verify::verify(&h, &keys, idx, true);
        if rep.problems.is_empty() {
            say!("  OK: {} ({}) decrypted and matched their SHA-256.", plural(rep.files, "file", "files"), bytes(rep.bytes));
        } else {
            code = EXIT_DAMAGED;
            say!("  {} checked and matched; {}:", plural(rep.files, "file", "files"), plural(rep.problems.len() as u64, "problem", "problems"));
            for p in &rep.problems {
                say!("    {p}");
            }
        }
        if rep.not_stored > 0 {
            say!("  Note: {} listed without content (not readable when the backup ran).", plural(rep.not_stored, "file is", "files are"));
        }
        if rep.incomplete > 0 {
            say!("  Note: {} marked as possibly incomplete (changed while the backup was reading).", plural(rep.incomplete, "file is", "files are"));
        }
    }
    Ok(code)
}

fn run(argv: Vec<OsString>) -> Result<i32> {
    let a = parse(argv)?;
    let help_for = |cmd: &str| -> Option<&'static str> {
        Some(match cmd {
            "list" => HELP_LIST,
            "files" => HELP_FILES,
            "restore" => HELP_RESTORE,
            "verify" => HELP_VERIFY,
            _ => return None,
        })
    };
    if a.cmd == "--version" {
        say!("backupbase-restore {VERSION}");
        return Ok(EXIT_OK);
    }
    if a.cmd.is_empty() || a.cmd == "help" {
        let topic = a.positional.first().map(|t| t.to_string_lossy().into_owned());
        match topic.as_deref().and_then(help_for) {
            Some(t) => print!("{t}"),
            None if topic.is_some() => return Err(usage(format!("There is no command \"{}\".", topic.unwrap()))),
            None => print!("{}", HELP.replace("VERSION", VERSION)),
        }
        return Ok(if a.cmd.is_empty() && !a.help { error::EXIT_USAGE } else { EXIT_OK });
    }
    if a.help {
        match help_for(&a.cmd) {
            Some(t) => print!("{t}"),
            None => print!("{}", HELP.replace("VERSION", VERSION)),
        }
        return Ok(EXIT_OK);
    }
    match a.cmd.as_str() {
        "list" => cmd_list(&a),
        "files" => cmd_files(&a),
        "restore" => cmd_restore(&a),
        "verify" => cmd_verify(&a),
        other => Err(usage(format!("There is no command \"{other}\". Run \"backupbase-restore --help\"."))),
    }
}

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    // A last resort: a bug must never end in a raw panic message.
    std::panic::set_hook(Box::new(|_| {}));
    let code = match std::panic::catch_unwind(|| run(argv)) {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            let _ = std::io::stdout().flush();
            eprintln!("{}", e.message);
            e.exit_code()
        }
        Err(_) => {
            let _ = std::io::stdout().flush();
            eprintln!("backupbase-restore stopped because of an internal error. Please report it to team@backupbase.org.");
            error::EXIT_ERROR
        }
    };
    ExitCode::from(code as u8)
}
