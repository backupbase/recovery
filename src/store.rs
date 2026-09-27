//! Reading stored file contents: v1 `.bbk` blobs, and one pass over a v2 `.bba` archive
//! checked entry by entry against its index.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::crypto;
use crate::error::{corrupt, display, from_read, invalid, not_found, Result};
use crate::stream::{self, Decryptor, Hashing, Zstd};
use crate::tar::{TarHeader, TarReader};
use crate::vault::{Entry, Index, Keys, VaultHeader};

/// Opens a file of the backup only when it is a regular file: a FIFO or device planted in the
/// synced folder would otherwise make the open wait forever. Anything else counts as damage.
pub fn open_regular(path: &Path) -> io::Result<File> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "it is not a regular file"));
    }
    File::open(path)
}

/// `data/<id[0..2]>/<id>.bbk`, only for a valid id.
pub fn blob_path(h: &VaultHeader, id: &str) -> Option<PathBuf> {
    if !crypto::is_blob_id(id) {
        return None;
    }
    Some(h.dir.join("data").join(&id[..2]).join(format!("{id}.bbk")))
}

/// Decrypts (and decompresses) one v1 blob into `out`. Returns the SHA-256 and length of the
/// plaintext. Errors keep their kind: damage is `Corrupt`, a missing blob `NotFound`.
pub fn read_blob(h: &VaultHeader, keys: &Keys, id: &str, out: &mut dyn Write, mut on_bytes: impl FnMut(u64)) -> Result<([u8; 32], u64)> {
    let path = blob_path(h, id).ok_or_else(|| corrupt("The version index names a stored file with an invalid id."))?;
    let f = open_regular(&path).map_err(|e| from_read(e, "the stored file", &path))?;
    let (hd, dec) = Decryptor::new(BufReader::with_capacity(1 << 18, f), &keys.data, stream::KIND_DATA).map_err(|e| from_read(e, "the stored file", &path))?;
    let mut reader: Box<dyn Read> = if hd.zstd { Box::new(Zstd::new(dec, stream::MAX_WINDOW_BLOB)) } else { Box::new(dec) };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(from_read(e, "the stored file", &path)),
        };
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(|e| crate::error::Error::new(crate::error::Kind::Io, format!("Could not write: {}.", crate::error::reason(&e))))?;
        total += n as u64;
        on_bytes(n as u64);
    }
    Ok((hasher.finalize().into(), total))
}

type ArchiveStack = TarReader<Zstd<Decryptor<Hashing<BufReader<File>>>>>;

/// The tar entry name an index entry must have: `r<root>/<p>`, `/` after folders.
pub fn tar_name(e: &Entry) -> String {
    match (e.is_dir(), e.p.is_empty()) {
        (_, true) => format!("r{}/", e.r),
        (true, false) => format!("r{}/{}/", e.r, e.p),
        (false, false) => format!("r{}/{}", e.r, e.p),
    }
}

/// Whether an index entry has a tar entry (folders, links, files with content).
pub fn in_archive(e: &Entry) -> bool {
    e.is_dir() || e.is_link() || e.stored()
}

pub struct ArchiveCursor {
    tar: ArchiveStack,
    pub path: PathBuf,
    expected_size: u64,
    expected_sha: [u8; 32],
    /// Size of the archive file on disk when it was opened.
    pub file_size: u64,
}

impl ArchiveCursor {
    pub fn open(h: &VaultHeader, keys: &Keys, idx: &Index) -> Result<ArchiveCursor> {
        let a = idx.archive.as_ref().ok_or_else(|| corrupt("The version index names no archive."))?;
        let path = h.index_dir().join(&a.file);
        let f = open_regular(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => not_found(format!(
                "The archive for this version ({}) is not in the backup folder. If the folder is still syncing, wait for it to finish, then try again.",
                display(&path)
            )),
            _ => from_read(e, "the archive", &path),
        })?;
        let file_size = f.metadata().map(|m| m.len()).unwrap_or(0);
        let (_, dec) = Decryptor::new(Hashing::new(BufReader::with_capacity(1 << 20, f)), &keys.data, stream::KIND_ARCHIVE).map_err(|e| from_read(e, "the archive", &path))?;
        let tar = TarReader::new(Zstd::new(dec, stream::MAX_WINDOW_ARCHIVE));
        let expected_sha = crypto::unhex::<32>(&a.sha256).unwrap_or([0; 32]);
        Ok(ArchiveCursor { tar, path, expected_size: a.size, expected_sha, file_size })
    }

    pub fn size_matches(&self) -> bool {
        self.file_size == self.expected_size
    }

    /// Reads the next tar entry and checks it against the index entry expected next.
    pub fn expect(&mut self, e: &Entry) -> io::Result<()> {
        let got = self.tar.next_entry()?.ok_or_else(|| invalid("the archive ends before all files in the index"))?;
        let want = TarHeader {
            name: tar_name(e),
            kind: if e.is_dir() {
                b'5'
            } else if e.is_link() {
                b'2'
            } else {
                b'0'
            },
            size: if e.is_file() { e.size() } else { 0 },
            link: if e.is_link() { e.t.clone().unwrap_or_default() } else { String::new() },
        };
        if got.name != want.name || got.kind != want.kind || got.size != want.size || (e.is_link() && got.link != want.link) {
            return Err(invalid(format!("the archive does not match its index at \"{}\"", want.name)));
        }
        Ok(())
    }

    /// Streams the current file's data into `out`; returns its SHA-256.
    pub fn copy_file(&mut self, out: &mut dyn Write, on_bytes: impl FnMut(u64)) -> io::Result<[u8; 32]> {
        self.tar.copy_data(out, on_bytes)
    }

    /// After the last index entry: the end blocks, nothing after them, the end of the
    /// encrypted file, and its size and SHA-256 as the index states.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.tar.next_entry()?.is_some() {
            return Err(invalid("the archive holds more entries than its index lists"));
        }
        self.tar.check_nothing_after()?;
        let dec = self.tar.get_ref().get_ref();
        if !dec.finished() {
            return Err(invalid("the archive ends too early"));
        }
        let hashing = dec.get_ref();
        let sha: [u8; 32] = hashing.hasher.clone().finalize().into();
        if hashing.count != self.expected_size || sha != self.expected_sha {
            return Err(invalid("the archive file is not the one its index describes (size or SHA-256 differs)"));
        }
        Ok(())
    }
}
