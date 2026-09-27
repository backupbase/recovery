//! Errors with a kind that maps to a stable exit code, and plain-sentence messages.

use std::fmt;
use std::io;
use std::path::Path;

/// Exit codes (stable; documented in README.md and `--help`).
pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_PASSCODE: i32 = 3;
pub const EXIT_NOT_FOUND: i32 = 4;
pub const EXIT_DAMAGED: i32 = 5;
pub const EXIT_INCOMPLETE: i32 = 6;
/// Stopped with Ctrl+C (128 + SIGINT, as shells report it).
pub const EXIT_STOPPED: i32 = 130;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Bad command line.
    Usage,
    /// The passcode does not open the backup.
    WrongPasscode,
    /// No vault.bbv, or it is not a Backup Base header.
    NotAVault,
    /// Made by a newer version of the format.
    NewerFormat,
    /// A version, path or archive that is not there.
    NotFound,
    /// A backup file failed its integrity check or breaks the format rules.
    Corrupt,
    /// Reading or writing failed (disk, permissions).
    Io,
}

#[derive(Debug)]
pub struct Error {
    pub kind: Kind,
    pub message: String,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(kind: Kind, message: impl Into<String>) -> Error {
        Error { kind, message: message.into() }
    }

    pub fn exit_code(&self) -> i32 {
        match self.kind {
            Kind::Usage => EXIT_USAGE,
            Kind::WrongPasscode => EXIT_PASSCODE,
            Kind::NotAVault | Kind::NewerFormat | Kind::NotFound => EXIT_NOT_FOUND,
            Kind::Corrupt => EXIT_DAMAGED,
            Kind::Io => EXIT_ERROR,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

pub fn usage(message: impl Into<String>) -> Error {
    Error::new(Kind::Usage, message)
}

pub fn corrupt(message: impl Into<String>) -> Error {
    Error::new(Kind::Corrupt, message)
}

pub fn not_found(message: impl Into<String>) -> Error {
    Error::new(Kind::NotFound, message)
}

/// An `io::Error` that means "the data is damaged" (used inside readers).
pub fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// A short, plain reason for an I/O error (no raw OS text for the common cases).
pub fn reason(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => "it does not exist".into(),
        io::ErrorKind::PermissionDenied => "permission denied".into(),
        io::ErrorKind::AlreadyExists => "it already exists".into(),
        io::ErrorKind::StorageFull => "the disk is full".into(),
        io::ErrorKind::ReadOnlyFilesystem => "the disk is read-only".into(),
        io::ErrorKind::InvalidFilename => "the name is not valid on this computer".into(),
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => e.to_string(),
        _ => {
            let s = e.to_string();
            // Drop Rust's " (os error N)" suffix.
            match s.find(" (os error") {
                Some(i) => s[..i].to_string(),
                None => s,
            }
        }
    }
}

/// Maps an I/O error while reading a backup file: damage stays damage, the rest is I/O.
pub fn from_read(e: io::Error, what: &str, path: &Path) -> Error {
    match e.kind() {
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => corrupt(format!("{what} {} is damaged: {}", display(path), e)),
        io::ErrorKind::NotFound => not_found(format!("{what} {} is missing.", display(path))),
        _ => Error::new(Kind::Io, format!("Could not read {what} {}: {}.", display(path), reason(&e))),
    }
}

/// A path for messages, without the Windows `\\?\` prefix.
pub fn display(path: &Path) -> String {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s.into_owned()
    }
}
