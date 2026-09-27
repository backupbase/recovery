//! A reader for the restricted POSIX tar stream inside a v2 archive (FORMAT.md "The archive"):
//! ustar headers with checked checksums, pax `x` headers for long or non-ASCII names, large
//! sizes and out-of-range times, entry types 0, 2 and 5 only, and two zero blocks at the end.

use std::io::{self, Read, Write};

use sha2::{Digest, Sha256};

use crate::error::invalid;
use crate::stream::read_full;

const BLOCK: usize = 512;
const MAX_PAX: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarHeader {
    pub name: String,
    /// b'0' file, b'5' folder, b'2' symbolic link.
    pub kind: u8,
    pub size: u64,
    pub link: String,
}

pub struct TarReader<R: Read> {
    r: R,
    /// Data bytes of the current file entry not yet read.
    pending: u64,
    /// Padding after the current entry's data.
    pad: u64,
    ended: bool,
}

fn field(b: &[u8]) -> &[u8] {
    match b.iter().position(|&c| c == 0) {
        Some(i) => &b[..i],
        None => b,
    }
}

fn octal(b: &[u8]) -> Option<u64> {
    let s = field(b);
    let s = match s.iter().position(|&c| c != b' ') {
        Some(i) => &s[i..],
        None => return None,
    };
    let end = s.iter().position(|&c| c == b' ').unwrap_or(s.len());
    if end == 0 || s[end..].iter().any(|&c| c != b' ') {
        return None;
    }
    let mut n: u64 = 0;
    for &c in &s[..end] {
        if !(b'0'..=b'7').contains(&c) {
            return None;
        }
        n = n.checked_mul(8)?.checked_add((c - b'0') as u64)?;
    }
    Some(n)
}

fn text(b: &[u8]) -> io::Result<String> {
    String::from_utf8(field(b).to_vec()).map_err(|_| invalid("a name in the archive is not valid text"))
}

#[derive(Default)]
struct Pax {
    path: Option<String>,
    linkpath: Option<String>,
    size: Option<u64>,
}

fn parse_pax(data: &[u8]) -> io::Result<Pax> {
    let mut pax = Pax::default();
    let mut pos = 0;
    let bad = || invalid("an extended header in the archive is damaged");
    while pos < data.len() {
        let sp = data[pos..].iter().position(|&c| c == b' ').ok_or_else(bad)? + pos;
        let len: usize = std::str::from_utf8(&data[pos..sp]).ok().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
        // The record holds at least "<len> " and "\n"; the sum cannot wrap.
        let end = pos.checked_add(len).ok_or_else(bad)?;
        if len <= sp - pos + 1 || end > data.len() || data[end - 1] != b'\n' {
            return Err(bad());
        }
        let rec = &data[sp + 1..end - 1];
        let eq = rec.iter().position(|&c| c == b'=').ok_or_else(bad)?;
        let key = &rec[..eq];
        let val = std::str::from_utf8(&rec[eq + 1..]).map_err(|_| bad())?;
        match key {
            b"path" => pax.path = Some(val.to_string()),
            b"linkpath" => pax.linkpath = Some(val.to_string()),
            b"size" => pax.size = Some(val.parse().map_err(|_| bad())?),
            _ => {} // mtime and anything else: informational (restores use the index)
        }
        pos += len;
    }
    Ok(pax)
}

impl<R: Read> TarReader<R> {
    pub fn new(r: R) -> TarReader<R> {
        TarReader { r, pending: 0, pad: 0, ended: false }
    }

    pub fn get_ref(&self) -> &R {
        &self.r
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.r
    }

    fn block(&mut self, b: &mut [u8; BLOCK]) -> io::Result<()> {
        if read_full(&mut self.r, b)? < BLOCK {
            return Err(invalid("the archive ends too early"));
        }
        Ok(())
    }

    fn skip(&mut self, n: u64, zeros: bool) -> io::Result<()> {
        let mut left = n;
        let mut buf = [0u8; 8192];
        while left > 0 {
            let k = (left as usize).min(buf.len());
            if read_full(&mut self.r, &mut buf[..k])? < k {
                return Err(invalid("the archive ends too early"));
            }
            if zeros && buf[..k].iter().any(|&c| c != 0) {
                return Err(invalid("the archive has data where padding was expected"));
            }
            left -= k as u64;
        }
        Ok(())
    }

    /// The next entry, or None after the two zero blocks that end the stream.
    pub fn next_entry(&mut self) -> io::Result<Option<TarHeader>> {
        if self.ended {
            return Ok(None);
        }
        if self.pending > 0 {
            let n = self.pending;
            self.pending = 0;
            self.skip(n, false)?;
        }
        if self.pad > 0 {
            let n = self.pad;
            self.pad = 0;
            self.skip(n, true)?;
        }
        let mut pax: Option<Pax> = None;
        let mut b = [0u8; BLOCK];
        loop {
            self.block(&mut b)?;
            if b.iter().all(|&c| c == 0) {
                self.block(&mut b)?;
                if !b.iter().all(|&c| c == 0) || pax.is_some() {
                    return Err(invalid("the archive has an unexpected empty block"));
                }
                self.ended = true;
                return Ok(None);
            }
            let stored = octal(&b[148..156]).ok_or_else(|| invalid("an archive header is damaged (checksum field)"))?;
            let sum: u64 = b.iter().enumerate().map(|(i, &c)| if (148..156).contains(&i) { b' ' as u64 } else { c as u64 }).sum();
            if sum != stored {
                return Err(invalid("an archive header is damaged (checksum)"));
            }
            if &b[257..263] != b"ustar\0" || &b[263..265] != b"00" {
                return Err(invalid("an archive header is not a ustar header"));
            }
            let kind = b[156];
            let size_field = octal(&b[124..136]);
            match kind {
                b'x' => {
                    if pax.is_some() {
                        return Err(invalid("the archive has two extended headers in a row"));
                    }
                    let size = size_field.ok_or_else(|| invalid("an archive header is damaged (size)"))?;
                    if size > MAX_PAX {
                        return Err(invalid("an extended header in the archive is too large"));
                    }
                    let mut data = vec![0u8; size as usize];
                    if read_full(&mut self.r, &mut data)? < data.len() {
                        return Err(invalid("the archive ends too early"));
                    }
                    self.skip(pad(size), true)?;
                    pax = Some(parse_pax(&data)?);
                }
                b'0' | b'5' | b'2' => {
                    let pax = pax.take().unwrap_or_default();
                    let name = match pax.path {
                        Some(p) => p,
                        None => {
                            let n = text(&b[0..100])?;
                            let prefix = text(&b[345..500])?;
                            if prefix.is_empty() {
                                n
                            } else {
                                format!("{prefix}/{n}")
                            }
                        }
                    };
                    let link = match pax.linkpath {
                        Some(l) => l,
                        None => text(&b[157..257])?,
                    };
                    let size = match pax.size {
                        Some(s) => s,
                        None => size_field.ok_or_else(|| invalid("an archive header is damaged (size)"))?,
                    };
                    if kind != b'0' && size != 0 {
                        return Err(invalid("a folder or link in the archive has data"));
                    }
                    self.pending = size;
                    self.pad = pad(size);
                    return Ok(Some(TarHeader { name, kind, size, link }));
                }
                _ => return Err(invalid(format!("the archive has an entry of an unsupported type ({})", kind as char))),
            }
        }
    }

    /// Streams the current file's data into `out`, hashing it. Returns its SHA-256.
    pub fn copy_data(&mut self, out: &mut dyn Write, mut on_bytes: impl FnMut(u64)) -> io::Result<[u8; 32]> {
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        while self.pending > 0 {
            let k = (self.pending as usize).min(buf.len());
            let n = read_full(&mut self.r, &mut buf[..k])?;
            if n < k {
                return Err(invalid("the archive ends too early"));
            }
            h.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            self.pending -= n as u64;
            on_bytes(n as u64);
        }
        let p = self.pad;
        self.pad = 0;
        self.skip(p, true)?;
        Ok(h.finalize().into())
    }

    /// After the end blocks: the decompressed stream must end here.
    pub fn check_nothing_after(&mut self) -> io::Result<()> {
        let mut one = [0u8; 1];
        if read_full(&mut self.r, &mut one)? != 0 {
            return Err(invalid("the archive has data after its end"));
        }
        Ok(())
    }
}

fn pad(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}
