//! The encrypted file format shared by `.bbk`, `.bbs` and `.bba` files (FORMAT.md "Encrypted
//! file format"): a 32-byte header, then AES-256-GCM STREAM segments. Plus a bounded,
//! multi-frame zstd reader for the compressed ones.

use std::io::{self, Read};

use aes_gcm::{Aes256Gcm, KeyInit};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

use crate::crypto;
use crate::error::invalid;

pub const MAGIC: &[u8; 4] = b"BBK1";
pub const KIND_DATA: u8 = 1;
pub const KIND_INDEX: u8 = 2;
pub const KIND_ARCHIVE: u8 = 3;
pub const FLAG_ZSTD: u8 = 1;

/// zstd window limits: indexes and archives (FORMAT.md), and v1 file contents, where the
/// format states no limit and this reader uses zstd's own default decoder limit (2^27).
pub const MAX_WINDOW_INDEX: u64 = 1 << 24;
pub const MAX_WINDOW_ARCHIVE: u64 = 1 << 24;
pub const MAX_WINDOW_BLOB: u64 = 1 << 27;

#[derive(Debug, Clone)]
pub struct Header {
    pub raw: [u8; 32],
    pub kind: u8,
    pub zstd: bool,
    pub seglog: u8,
    pub salt: [u8; 24],
}

impl Header {
    pub fn parse(raw: [u8; 32]) -> Result<Header, String> {
        if &raw[0..4] != MAGIC {
            return Err("it is not a Backup Base encrypted file".into());
        }
        let kind = raw[4];
        let flags = raw[5];
        let seglog = raw[6];
        if !(1..=3).contains(&kind) {
            return Err(format!("unknown file kind {kind}"));
        }
        if flags & !FLAG_ZSTD != 0 {
            return Err("unknown header flags".into());
        }
        if !(16..=24).contains(&seglog) {
            return Err(format!("segment size 2^{seglog} is outside 2^16..2^24"));
        }
        if raw[7] != 0 {
            return Err("reserved header byte is not 0".into());
        }
        if kind == KIND_ARCHIVE && flags & FLAG_ZSTD == 0 {
            return Err("an archive without compression".into());
        }
        let mut salt = [0u8; 24];
        salt.copy_from_slice(&raw[8..32]);
        Ok(Header { raw, kind, zstd: flags & FLAG_ZSTD != 0, seglog, salt })
    }
}

fn kind_name(kind: u8) -> &'static str {
    match kind {
        KIND_DATA => "a stored file",
        KIND_INDEX => "a version index",
        KIND_ARCHIVE => "an archive",
        _ => "an unknown kind of file",
    }
}

/// Something a reader stack can ask whether the bottom reader failed, and how (so a damaged
/// segment is not reported as a compression error, and a disk error is not reported as damage).
pub trait Source: Read {
    fn failure(&self) -> Option<(io::ErrorKind, String)> {
        None
    }
}

impl Source for &[u8] {}
impl Source for io::Cursor<Vec<u8>> {}

/// Reads exactly as many bytes as possible into `buf`; returns the count (short only at EOF).
pub fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Decrypts a STREAM body segment by segment. Never returns plaintext of a segment whose tag
/// failed; EOF before a final-flagged segment is damage.
pub struct Decryptor<R: Read> {
    src: R,
    cipher: Aes256Gcm,
    aad: [u8; 32],
    seg: usize,
    next: u64,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    peek: Option<u8>,
    finished: bool,
    failed: Option<(io::ErrorKind, String)>,
}

impl<R: Read> Decryptor<R> {
    /// Reads and checks the header; `kind` is the only kind accepted here.
    pub fn new(mut src: R, base_key: &[u8; 32], kind: u8) -> io::Result<(Header, Decryptor<R>)> {
        let mut raw = [0u8; 32];
        if read_full(&mut src, &mut raw)? < 32 {
            return Err(invalid("the file is too short to be a Backup Base encrypted file"));
        }
        let h = Header::parse(raw).map_err(invalid)?;
        if h.kind != kind {
            return Err(invalid(format!("it is {} where {} was expected", kind_name(h.kind), kind_name(kind))));
        }
        let key = crypto::file_key(base_key, &h.salt);
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| invalid("bad key"))?;
        let seg = 1usize << h.seglog;
        let d = Decryptor { src, cipher, aad: raw, seg, next: 0, buf: Vec::new(), start: 0, end: 0, peek: None, finished: false, failed: None };
        Ok((h, d))
    }

    /// True once the final segment was read and authenticated.
    pub fn finished(&self) -> bool {
        self.finished
    }

    pub fn get_ref(&self) -> &R {
        &self.src
    }

    fn next_segment(&mut self) -> io::Result<()> {
        let want = self.seg + 16;
        self.buf.clear();
        if let Some(b) = self.peek.take() {
            self.buf.push(b);
        }
        let need = (want - self.buf.len()) as u64;
        (&mut self.src).take(need).read_to_end(&mut self.buf)?;
        let n = self.buf.len();
        let last = if n < want {
            true
        } else {
            let mut one = [0u8; 1];
            if read_full(&mut self.src, &mut one)? == 0 {
                true
            } else {
                self.peek = Some(one[0]);
                false
            }
        };
        if n < 16 {
            return Err(invalid("the file ends too early (it is cut short)"));
        }
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.next.to_be_bytes());
        nonce[11] = last as u8;
        match crypto::gcm_open_with(&self.cipher, &nonce, &self.aad, &mut self.buf[..n]) {
            Some(len) => {
                self.next += 1;
                self.start = 0;
                self.end = len;
                self.finished = last;
                Ok(())
            }
            None => Err(invalid("it failed its integrity check (damaged, cut short or changed)")),
        }
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Some((k, m)) = &self.failed {
            return Err(io::Error::new(*k, m.clone()));
        }
        if out.is_empty() {
            return Ok(0);
        }
        while self.start == self.end {
            if self.finished {
                return Ok(0);
            }
            if let Err(e) = self.next_segment() {
                self.failed = Some((e.kind(), e.to_string()));
                // Never leave plaintext of a failed segment readable.
                self.buf.iter_mut().for_each(|b| *b = 0);
                self.start = 0;
                self.end = 0;
                return Err(e);
            }
        }
        let n = out.len().min(self.end - self.start);
        out[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
        self.start += n;
        Ok(n)
    }
}

impl<R: Read> Source for Decryptor<R> {
    fn failure(&self) -> Option<(io::ErrorKind, String)> {
        self.failed.clone()
    }
}

/// A zstd stream of one or more frames, with skippable frames passed over, every frame's
/// window limited, and content checksums checked when present.
pub struct Zstd<S: Source> {
    src: S,
    dec: FrameDecoder,
    in_frame: bool,
}

impl<S: Source> Zstd<S> {
    pub fn new(src: S, max_window: u64) -> Zstd<S> {
        let mut dec = FrameDecoder::new();
        dec.set_max_window_size(max_window);
        Zstd { src, dec, in_frame: false }
    }

    pub fn get_ref(&self) -> &S {
        &self.src
    }

    fn map_err(&self, what: String) -> io::Error {
        match self.src.failure() {
            Some((k, m)) => io::Error::new(k, m),
            None => invalid(format!("the compressed data is damaged ({what})")),
        }
    }
}

impl<S: Source> Read for Zstd<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.in_frame {
                while self.dec.can_collect() < buf.len() && !self.dec.is_finished() {
                    let need = buf.len() - self.dec.can_collect();
                    if let Err(e) = self.dec.decode_blocks(&mut self.src, BlockDecodingStrategy::UptoBytes(need)) {
                        return Err(self.map_err(e.to_string()));
                    }
                }
                let n = match self.dec.read(buf) {
                    Ok(n) => n,
                    Err(e) => return Err(self.map_err(e.to_string())),
                };
                if n > 0 {
                    return Ok(n);
                }
                if !self.dec.is_finished() {
                    return Err(invalid("the compressed data is damaged (no progress)"));
                }
                if let (Some(a), Some(b)) = (self.dec.get_checksum_from_data(), self.dec.get_calculated_checksum()) {
                    if a != b {
                        return Err(invalid("the compressed data is damaged (checksum)"));
                    }
                }
                self.in_frame = false;
            }
            // At a frame boundary.
            let mut magic = [0u8; 4];
            let k = read_full(&mut self.src, &mut magic)?;
            if k == 0 {
                return Ok(0);
            }
            if k < 4 {
                return Err(invalid("the compressed data ends inside a frame header"));
            }
            let m = u32::from_le_bytes(magic);
            if (0x184D_2A50..=0x184D_2A5F).contains(&m) {
                let mut len = [0u8; 4];
                if read_full(&mut self.src, &mut len)? < 4 {
                    return Err(invalid("the compressed data ends inside a skippable frame"));
                }
                let len = u32::from_le_bytes(len) as u64;
                if io::copy(&mut (&mut self.src).take(len), &mut io::sink())? < len {
                    return Err(invalid("the compressed data ends inside a skippable frame"));
                }
                continue;
            }
            if m != 0xFD2F_B528 {
                return Err(invalid("the data is not zstd compressed"));
            }
            let res = self.dec.reset(&mut (&magic[..]).chain(&mut self.src));
            if let Err(e) = res {
                return Err(self.map_err(e.to_string()));
            }
            self.in_frame = true;
        }
    }
}

/// Fails with "damaged" once more than `limit` bytes were read (bounds decompression).
pub struct Limit<R: Read> {
    inner: R,
    left: u64,
    what: &'static str,
}

impl<R: Read> Limit<R> {
    pub fn new(inner: R, limit: u64, what: &'static str) -> Limit<R> {
        Limit { inner, left: limit, what }
    }
}

impl<R: Read> Read for Limit<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.left {
            return Err(invalid(format!("{} is larger than this reader allows", self.what)));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// Counts and SHA-256 hashes the bytes read through it (the encrypted archive file).
pub struct Hashing<R: Read> {
    inner: R,
    pub hasher: sha2::Sha256,
    pub count: u64,
}

impl<R: Read> Hashing<R> {
    pub fn new(inner: R) -> Hashing<R> {
        use sha2::Digest;
        Hashing { inner, hasher: sha2::Sha256::new(), count: 0 }
    }
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use sha2::Digest;
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }
}
