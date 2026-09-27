//! Vault folders: `vault.bbv`, unlocking with the passcode, the list of versions and the
//! version indexes (FORMAT.md "vault.bbv", "Snapshot index", "Format v2").

use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::Value;

use crate::crypto::{self, KdfParams, Key};
use crate::error::{corrupt, display, from_read, not_found, Error, Kind, Result};
use crate::stream::{self, Decryptor, Limit, Zstd};

pub const HEADER_FILE: &str = "vault.bbv";
const MAX_HEADER_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone)]
pub struct VaultHeader {
    pub dir: PathBuf,
    /// 1 (files layout) or 2 (archive layout).
    pub version: u8,
    pub vault_id: String,
    pub uuid: [u8; 16],
    /// Plain labels outside the key wrap: shown, never trusted.
    pub name: String,
    pub created_at: Option<String>,
    pub app_version: Option<String>,
    pub os: Option<String>,
    pub kdf: KdfParams,
    pub salt: Vec<u8>,
    pub nonce: [u8; 12],
    pub ct: [u8; 48],
}

pub fn is_vault(dir: &Path) -> bool {
    dir.join(HEADER_FILE).is_file()
}

/// The folder itself when it is a vault, otherwise the vaults up to two levels below it.
pub fn find_vaults(folder: &Path) -> Vec<PathBuf> {
    if is_vault(folder) {
        return vec![folder.to_path_buf()];
    }
    let mut out = Vec::new();
    let mut level = vec![folder.to_path_buf()];
    for _ in 0..2 {
        let mut next = Vec::new();
        for dir in &level {
            let Ok(rd) = fs::read_dir(dir) else { continue };
            for d in rd.flatten() {
                if !d.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let p = d.path();
                if is_vault(&p) {
                    out.push(p);
                } else {
                    next.push(p);
                }
            }
        }
        level = next;
    }
    out.sort_by_key(|p| p.to_string_lossy().to_lowercase());
    out
}

pub fn newer_format() -> Error {
    Error::new(Kind::NewerFormat, "This backup was made by a newer version of Backup Base. Use a newer version of backupbase-restore to open it.")
}

impl VaultHeader {
    pub fn read(dir: &Path) -> Result<VaultHeader> {
        let path = dir.join(HEADER_FILE);
        let f = crate::store::open_regular(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::new(Kind::NotAVault, format!("{} is not a Backup Base backup folder (it has no vault.bbv).", display(dir))),
            _ => from_read(e, "the backup header", &path),
        })?;
        let mut bytes = Vec::new();
        f.take(MAX_HEADER_BYTES + 1).read_to_end(&mut bytes).map_err(|e| from_read(e, "the backup header", &path))?;
        if bytes.len() as u64 > MAX_HEADER_BYTES {
            return Err(Error::new(Kind::NotAVault, format!("{} is not a Backup Base backup header (it is too large).", display(&path))));
        }
        Self::parse(&bytes, dir)
    }

    pub fn parse(bytes: &[u8], dir: &Path) -> Result<VaultHeader> {
        let not_vault = || Error::new(Kind::NotAVault, format!("{} is not a Backup Base backup folder (vault.bbv is not a Backup Base header).", display(dir)));
        let v: Value = serde_json::from_slice(bytes).map_err(|_| not_vault())?;
        let o = v.as_object().ok_or_else(not_vault)?;
        if o.get("format").and_then(Value::as_str) != Some("backupbase-vault") {
            return Err(not_vault());
        }
        let bad = |what: &str| corrupt(format!("The backup header {} is damaged: {what}.", display(&dir.join(HEADER_FILE))));
        let version = o.get("version").and_then(Value::as_u64).ok_or_else(|| bad("no valid version"))?;
        let layout = match o.get("layout") {
            None => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(_) => return Err(bad("layout is not text")),
        };
        let version = match (version, layout) {
            (1, None) | (1, Some("files")) => 1u8,
            (1, Some(_)) => return Err(bad("a version 1 header with an unknown layout")),
            (2, Some("archive")) => 2u8,
            (2, None) => return Err(bad("a version 2 header without a layout")),
            (2, Some(_)) => return Err(newer_format()),
            (0, _) => return Err(bad("version 0")),
            _ => return Err(newer_format()),
        };
        let vault_id = o.get("vault_id").and_then(Value::as_str).ok_or_else(|| bad("no vault id"))?.to_string();
        let uuid = crypto::parse_uuid(&vault_id).ok_or_else(|| bad("the vault id is not a UUID"))?;

        let kdf = o.get("kdf").and_then(Value::as_object).ok_or_else(|| bad("no key derivation settings"))?;
        let alg = kdf.get("alg").and_then(Value::as_str).ok_or_else(|| bad("no key derivation algorithm"))?;
        if alg != "argon2id" {
            return Err(newer_format());
        }
        let kv = kdf.get("v").and_then(Value::as_u64).ok_or_else(|| bad("no Argon2 version"))?;
        if kv != 19 {
            return Err(newer_format());
        }
        let num = |k: &str| kdf.get(k).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok());
        let params = KdfParams {
            m_kib: num("m_kib").ok_or_else(|| bad("no Argon2 memory size"))?,
            t: num("t").ok_or_else(|| bad("no Argon2 time cost"))?,
            p: num("p").ok_or_else(|| bad("no Argon2 parallelism"))?,
        };
        if !params.in_bounds() {
            return Err(bad("Argon2 settings outside the allowed bounds"));
        }
        let b64 = |s: Option<&Value>| s.and_then(Value::as_str).and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok());
        let salt = b64(kdf.get("salt")).ok_or_else(|| bad("no valid salt"))?;
        if salt.len() < 8 {
            return Err(bad("the salt is shorter than 8 bytes"));
        }

        let wk = o.get("wrapped_key").and_then(Value::as_object).ok_or_else(|| bad("no wrapped key"))?;
        let walg = wk.get("alg").and_then(Value::as_str).ok_or_else(|| bad("no key wrap algorithm"))?;
        if walg != "aes-256-gcm" {
            return Err(newer_format());
        }
        let nonce: [u8; 12] = b64(wk.get("nonce")).and_then(|n| n.try_into().ok()).ok_or_else(|| bad("the key wrap nonce is not 12 bytes"))?;
        let ct: [u8; 48] = b64(wk.get("ct")).and_then(|n| n.try_into().ok()).ok_or_else(|| bad("the wrapped key is not 48 bytes"))?;

        let text = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
        let by = o.get("created_by").and_then(Value::as_object);
        let by_text = |k: &str| by.and_then(|b| b.get(k)).and_then(Value::as_str).map(str::to_string);
        Ok(VaultHeader {
            dir: dir.to_path_buf(),
            version,
            vault_id,
            uuid,
            name: text("name").unwrap_or_default(),
            created_at: text("created_at"),
            app_version: by_text("app_version"),
            os: by_text("os"),
            kdf: params,
            salt,
            nonce,
            ct,
        })
    }

    /// Where the version indexes live: `snapshots/` (v1) or `archives/` (v2).
    pub fn index_dir(&self) -> PathBuf {
        self.dir.join(if self.version == 1 { "snapshots" } else { "archives" })
    }

    pub fn index_path(&self, id: &str) -> PathBuf {
        self.index_dir().join(format!("{id}.bbs"))
    }

    pub fn unlock(&self, passcode: &str) -> Result<Keys> {
        let kek = crypto::derive_kek(passcode, &self.salt, self.kdf).ok_or_else(|| corrupt("The backup header has key settings this reader cannot use."))?;
        let mk = crypto::unwrap_master_key(&kek, &self.nonce, &self.ct, &self.vault_id)
            .ok_or_else(|| Error::new(Kind::WrongPasscode, format!("The passcode does not open the backup \"{}\".", self.label())))?;
        Ok(Keys {
            data: crypto::hkdf32(&mk[..], &self.uuid, crypto::INFO_DATA),
            snap: crypto::hkdf32(&mk[..], &self.uuid, crypto::INFO_SNAP),
            name: crypto::hkdf32(&mk[..], &self.uuid, crypto::INFO_NAME),
        })
    }

    /// The name to show (vault.bbv's name is not authenticated, so it is cleaned for printing).
    pub fn label(&self) -> String {
        let l = if self.name.trim().is_empty() { self.dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "backup".into()) } else { self.name.clone() };
        crate::text::clean(&l).into_owned()
    }

    /// Valid version ids found in the index folder (oldest first), and how many other
    /// `.bbs` files were there (sync conflict copies and the like, never versions).
    pub fn version_files(&self) -> Result<(Vec<String>, Vec<String>)> {
        let dir = self.index_dir();
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((vec![], vec![])),
            Err(e) => return Err(from_read(e, "the folder", &dir)),
        };
        let mut ids = Vec::new();
        let mut other = Vec::new();
        for d in rd.flatten() {
            let name = d.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".bbs") else { continue };
            if valid_id(stem) && d.file_type().map(|t| t.is_file()).unwrap_or(false) {
                ids.push(stem.to_string());
            } else {
                other.push(name);
            }
        }
        ids.sort();
        other.sort();
        Ok((ids, other))
    }
}

pub struct Keys {
    pub data: Key,
    pub snap: Key,
    pub name: Key,
}

/// `YYYYMMDDTHHMMSSZ-<8 hex>` with a real date and time.
pub fn valid_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 25 || b[8] != b'T' || b[15] != b'Z' || b[16] != b'-' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let mut n = 0u32;
        for &c in &b[r] {
            if !c.is_ascii_digit() {
                return None;
            }
            n = n * 10 + (c - b'0') as u32;
        }
        Some(n)
    };
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se)) = (digits(0..4), digits(4..6), digits(6..8), digits(9..11), digits(11..13), digits(13..15)) else {
        return false;
    };
    if !b[17..].iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1970..=9999).contains(&y) && (1..=dim).contains(&d) && h < 24 && mi < 60 && se < 60
}

// ----- version indexes ----------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Root {
    pub id: u32,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    pub r: u32,
    pub p: String,
    pub k: String,
    #[serde(default)]
    pub s: Option<u64>,
    #[serde(default)]
    pub m: Option<i64>,
    #[serde(default)]
    pub mode: Option<u32>,
    #[serde(default)]
    pub attr: Option<u32>,
    #[serde(default)]
    pub h: Option<String>,
    #[serde(default)]
    pub b: Option<String>,
    #[serde(default)]
    pub t: Option<String>,
    #[serde(default)]
    pub c: Option<bool>,
}

impl Entry {
    pub fn is_file(&self) -> bool {
        self.k == "f"
    }
    pub fn is_dir(&self) -> bool {
        self.k == "d"
    }
    pub fn is_link(&self) -> bool {
        self.k == "l"
    }
    /// A file entry whose content is stored (v2: listed without `h` means not stored).
    pub fn stored(&self) -> bool {
        self.is_file() && self.h.is_some()
    }
    pub fn incomplete(&self) -> bool {
        self.c == Some(true)
    }
    pub fn size(&self) -> u64 {
        self.s.unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Stats {
    #[serde(default)]
    pub files: u64,
    #[serde(default)]
    pub dirs: u64,
    #[serde(default)]
    pub links: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub skipped: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ArchiveRef {
    pub file: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Device {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub app_version: String,
}

#[derive(Deserialize)]
struct RawIndex<E> {
    #[serde(default)]
    snapshot_id: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    layout: Option<String>,
    #[serde(default)]
    archive: Option<ArchiveRef>,
    #[serde(default)]
    device: Option<Device>,
    #[serde(default)]
    roots: Vec<Root>,
    #[serde(default)]
    entries: E,
    #[serde(default)]
    stats: Stats,
}

/// A version index. `entries` is empty when read with `entries: false`.
#[derive(Debug, Clone)]
pub struct Index {
    pub id: String,
    pub created_at: Option<String>,
    pub device: Device,
    pub roots: Vec<Root>,
    pub entries: Vec<Entry>,
    pub stats: Stats,
    pub archive: Option<ArchiveRef>,
}

/// The decompressed JSON limit for an index read from a `.bbs` file of `file_len` bytes.
pub fn index_limit(file_len: u64) -> u64 {
    (64u64 << 20).saturating_add(file_len.saturating_mul(256))
}

impl VaultHeader {
    /// Reads and checks one version index. `entries: false` skips the file list (listing).
    pub fn read_index(&self, keys: &Keys, id: &str, entries: bool) -> Result<Index> {
        let path = self.index_path(id);
        let f = crate::store::open_regular(&path).map_err(|e| from_read(e, "the version index", &path))?;
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let (h, dec) = Decryptor::new(BufReader::with_capacity(1 << 16, f), &keys.snap, stream::KIND_INDEX).map_err(|e| from_read(e, "the version index", &path))?;
        let limit = index_limit(len);
        let reader: Box<dyn Read> = if h.zstd {
            Box::new(Limit::new(Zstd::new(dec, stream::MAX_WINDOW_INDEX), limit, "the version index"))
        } else {
            Box::new(Limit::new(dec, limit, "the version index"))
        };
        let reader = BufReader::with_capacity(1 << 16, reader);
        let json_err = |e: serde_json::Error| -> Error {
            match e.io_error_kind() {
                Some(k) if k != std::io::ErrorKind::InvalidData && k != std::io::ErrorKind::UnexpectedEof => from_read(std::io::Error::new(k, e.to_string()), "the version index", &path),
                Some(_) => from_read(std::io::Error::new(std::io::ErrorKind::InvalidData, strip_json_pos(&e)), "the version index", &path),
                None => corrupt(format!("The version index {} is damaged: {}.", display(&path), e)),
            }
        };
        let (snapshot_id, created_at, layout, archive, device, roots, list, stats) = if entries {
            let raw: RawIndex<Vec<Entry>> = serde_json::from_reader(reader).map_err(json_err)?;
            (raw.snapshot_id, raw.created_at, raw.layout, raw.archive, raw.device, raw.roots, raw.entries, raw.stats)
        } else {
            let raw: RawIndex<IgnoredAny> = serde_json::from_reader(reader).map_err(json_err)?;
            (raw.snapshot_id, raw.created_at, raw.layout, raw.archive, raw.device, raw.roots, Vec::new(), raw.stats)
        };
        let bad = |what: &str| corrupt(format!("The version index {} is damaged: {what}.", display(&path)));
        if self.version == 2 {
            let a = archive.as_ref().ok_or_else(|| bad("it names no archive"))?;
            if layout.as_deref() != Some("archive") {
                return Err(bad("it is not an archive index"));
            }
            let sid = snapshot_id.as_deref().unwrap_or(id);
            if a.file != format!("{sid}.bba") || !valid_id(sid) {
                return Err(bad("it names an archive file this reader refuses"));
            }
            if !crypto::is_sha256_hex(&a.sha256) {
                return Err(bad("the archive checksum is not valid"));
            }
        } else if layout.is_some() || archive.is_some() {
            return Err(bad("an archive index inside a version 1 backup"));
        }
        let idx = Index { id: id.to_string(), created_at, device: device.unwrap_or_default(), roots, entries: list, stats, archive };
        if entries {
            check_entries(&idx, self.version).map_err(|m| bad(&m))?;
        }
        Ok(idx)
    }
}

fn strip_json_pos(e: &serde_json::Error) -> String {
    let s = e.to_string();
    match s.find(" at line ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

/// Every entry must make sense before anything is restored from it.
fn check_entries(idx: &Index, version: u8) -> std::result::Result<(), String> {
    let roots: HashMap<u32, ()> = idx.roots.iter().map(|r| (r.id, ())).collect();
    for e in &idx.entries {
        if !roots.contains_key(&e.r) {
            return Err(format!("an entry names folder {} that the index does not list", e.r));
        }
        match e.k.as_str() {
            "f" => {
                if let Some(h) = &e.h {
                    if !crypto::is_sha256_hex(h) {
                        return Err("an entry has an invalid hash".into());
                    }
                    if e.s.is_none() {
                        return Err("a file entry has no size".into());
                    }
                    if version == 1 {
                        match &e.b {
                            Some(b) if crypto::is_blob_id(b) => {}
                            _ => return Err("a file entry has no valid stored file id".into()),
                        }
                    }
                }
            }
            "d" => {}
            "l" => {
                if e.t.is_none() {
                    return Err("a link entry has no target".into());
                }
            }
            _ => return Err(format!("an entry has an unknown kind \"{}\"", e.k)),
        }
    }
    Ok(())
}

/// Picks a version: an exact id, `latest`, or an unambiguous start of an id.
pub fn pick_version<'a>(ids: &'a [String], want: Option<&str>) -> Result<&'a str> {
    let want = want.unwrap_or("latest");
    if ids.is_empty() {
        return Err(not_found("This backup has no versions that can be read."));
    }
    if want == "latest" {
        return Ok(ids.last().unwrap());
    }
    if let Some(id) = ids.iter().find(|i| i.as_str() == want) {
        return Ok(id);
    }
    let matches: Vec<&String> = ids.iter().filter(|i| i.starts_with(want)).collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(not_found(format!("This backup has no version \"{want}\". Run \"backupbase-restore list\" to see the versions."))),
        n => Err(crate::error::usage(format!("\"{want}\" matches {n} versions. Give more of the version id."))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ids() {
        assert!(valid_id("20260925T150000Z-3fa9c2d1"));
        assert!(valid_id("20240229T235959Z-00000000"));
        for bad in ["20250229T000000Z-00000000", "20261301T000000Z-00000000", "20260925T240000Z-00000000", "20260925T150000Z-3FA9C2D1", "20260925T150000Z-3fa9c2d", "20260925T150000Z-3fa9c2d1 (1)", "19691231T000000Z-00000000"] {
            assert!(!valid_id(bad), "{bad}");
        }
    }

    #[test]
    fn picking() {
        let ids: Vec<String> = ["20260925T150000Z-00000001", "20260926T150000Z-00000002"].iter().map(|s| s.to_string()).collect();
        assert_eq!(pick_version(&ids, None).unwrap(), ids[1]);
        assert_eq!(pick_version(&ids, Some("20260925")).unwrap(), ids[0]);
        assert_eq!(pick_version(&ids, Some("2026")).unwrap_err().kind, Kind::Usage);
        assert_eq!(pick_version(&ids, Some("x")).unwrap_err().kind, Kind::NotFound);
        assert_eq!(pick_version(&[], None).unwrap_err().kind, Kind::NotFound);
    }

    #[test]
    fn index_limit_grows_with_the_file() {
        assert_eq!(index_limit(0), 64 << 20);
        assert_eq!(index_limit(2 << 20), (64 << 20) + (512 << 20));
    }
}
