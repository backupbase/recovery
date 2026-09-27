//! A small test-only writer for synthetic vaults (normal, damaged and hostile ones), built on
//! the published format. Known-answer vectors (tests/vectors.rs) and vaults made by the real
//! app (tests/fixtures.rs, the private repo's crosscheck) keep it honest.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use aes_gcm::aead::{AeadInOut, Nonce};
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::Engine as _;
use bbrestore::crypto;
use serde_json::{json, Value};

pub const PASS: &str = "Test passcode 2026";

pub struct TestVault {
    pub dir: PathBuf,
    pub version: u8,
    pub id: String,
    pub k_data: [u8; 32],
    pub k_snap: [u8; 32],
    pub k_name: [u8; 32],
}

pub fn gcm_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let c = Aes256Gcm::new_from_slice(key).unwrap();
    let mut buf = plain.to_vec();
    let n = Nonce::<Aes256Gcm>::try_from(&nonce[..]).unwrap();
    let tag = c.encrypt_inout_detached(&n, aad, buf.as_mut_slice().into()).unwrap();
    buf.extend_from_slice(&tag);
    buf
}

/// An encrypted file (header + STREAM segments) of `plain`, already compressed if `zstd`.
pub fn encrypt(base: &[u8; 32], kind: u8, zstd: bool, seglog: u8, salt: [u8; 24], plain: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 32];
    header[..4].copy_from_slice(b"BBK1");
    header[4] = kind;
    header[5] = zstd as u8;
    header[6] = seglog;
    header[8..].copy_from_slice(&salt);
    let key = crypto::file_key(base, &salt);
    let seg = 1usize << seglog;
    let mut out = header.to_vec();
    let chunks: Vec<&[u8]> = if plain.is_empty() { vec![&[][..]] } else { plain.chunks(seg).collect() };
    for (i, c) in chunks.iter().enumerate() {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
        nonce[11] = (i == chunks.len() - 1) as u8;
        out.extend(gcm_seal(&key, &nonce, &header, c));
    }
    out
}

pub fn zstd(data: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
}

fn salt(n: u8) -> [u8; 24] {
    [n; 24]
}

impl TestVault {
    pub fn create(dir: &Path, version: u8) -> TestVault {
        fs::create_dir_all(dir).unwrap();
        let id = "11111111-2222-4333-8444-555555555555".to_string();
        let uuid = crypto::parse_uuid(&id).unwrap();
        let mk = [7u8; 32];
        let ksalt = [9u8; 16];
        let params = crypto::KdfParams { m_kib: 8, t: 1, p: 1 };
        let kek = crypto::derive_kek(PASS, &ksalt, params).unwrap();
        let nonce = [3u8; 12];
        let ct = gcm_seal(&kek, &nonce, format!("backupbase-vault-v1:{id}").as_bytes(), &mk);
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let mut v = json!({
            "format": "backupbase-vault", "version": version, "vault_id": id, "name": "Documents",
            "created_at": "2026-09-25T15:00:00Z", "created_by": {"app_version": "1.1.0", "os": "macos"},
            "kdf": {"alg": "argon2id", "v": 19, "m_kib": 8, "t": 1, "p": 1, "salt": b64(&ksalt)},
            "wrapped_key": {"alg": "aes-256-gcm", "nonce": b64(&nonce), "ct": b64(&ct)}
        });
        if version == 2 {
            v["layout"] = json!("archive");
        }
        fs::write(dir.join("vault.bbv"), serde_json::to_vec_pretty(&v).unwrap()).unwrap();
        fs::create_dir_all(dir.join(if version == 1 { "snapshots" } else { "archives" })).unwrap();
        let k = |info: &[u8]| *crypto::hkdf32(&mk, &uuid, info);
        TestVault { dir: dir.to_path_buf(), version, id, k_data: k(crypto::INFO_DATA), k_snap: k(crypto::INFO_SNAP), k_name: k(crypto::INFO_NAME) }
    }

    pub fn index_dir(&self) -> PathBuf {
        self.dir.join(if self.version == 1 { "snapshots" } else { "archives" })
    }

    pub fn write_index(&self, id: &str, v: &Value, compress: bool) {
        let json = serde_json::to_vec(v).unwrap();
        let body = if compress { zstd(&json) } else { json };
        fs::write(self.index_dir().join(format!("{id}.bbs")), encrypt(&self.k_snap, 2, compress, 16, salt(2), &body)).unwrap();
    }

    /// A v1 blob for `data`; returns (sha hex, blob id).
    pub fn write_blob(&self, data: &[u8]) -> (String, String) {
        let sha = crypto::sha256(data);
        let id = crypto::blob_id(&self.k_name, &sha);
        let dir = self.dir.join("data").join(&id[..2]);
        fs::create_dir_all(&dir).unwrap();
        let compress = data.len() >= 64;
        let body = if compress { zstd(data) } else { data.to_vec() };
        fs::write(dir.join(format!("{id}.bbk")), encrypt(&self.k_data, 1, compress, 16, salt(1), &body)).unwrap();
        (crypto::hex(&sha), id)
    }

    /// A v1 version from (path, kind, data or link target) items under one root.
    pub fn v1_version(&self, id: &str, items: &[Item]) {
        let mut entries = vec![json!({"r":0,"p":"","k":"d","m":1758812400000i64,"mode":493})];
        for it in items {
            entries.push(match it {
                Item::Dir(p) => json!({"r":0,"p":p,"k":"d","m":1758812400000i64,"mode":493}),
                Item::File(p, d) => {
                    let (h, b) = self.write_blob(d);
                    json!({"r":0,"p":p,"k":"f","s":d.len(),"m":1758812401000i64,"mode":420,"h":h,"b":b})
                }
                Item::Link(p, t) => json!({"r":0,"p":p,"k":"l","t":t,"m":1758812402000i64}),
                Item::Raw(v) => v.clone(),
            });
        }
        let v = json!({"v":1,"vault_id":self.id,"snapshot_id":id,"created_at":"2026-09-25T15:00:00Z",
            "device":{"id":"x","name":"Test Mac","os":"macos","app_version":"1.0.0"},
            "roots":[{"id":0,"path":"/Users/alex/Documents","name":"Documents"}],
            "entries":entries,"stats":{"files":0,"dirs":0,"links":0,"bytes":0}});
        self.write_index(id, &v, true);
    }

    /// A v2 version: entries in the given order; files carry data unless `NoContent`.
    pub fn v2_version(&self, id: &str, items: &[Item]) -> Value {
        let mut tar = TarW::default();
        let mut entries = vec![json!({"r":0,"p":"","k":"d","m":1758812400000i64,"mode":493})];
        tar.dir("r0/");
        for it in items {
            match it {
                Item::Dir(p) => {
                    entries.push(json!({"r":0,"p":p,"k":"d","m":1758812400000i64,"mode":493}));
                    tar.dir(&format!("r0/{p}/"));
                }
                Item::File(p, d) => {
                    entries.push(json!({"r":0,"p":p,"k":"f","s":d.len(),"m":1758812401000i64,"mode":420,"h":crypto::hex(&crypto::sha256(d))}));
                    tar.file(&format!("r0/{p}"), d);
                }
                Item::Link(p, t) => {
                    entries.push(json!({"r":0,"p":p,"k":"l","t":t,"m":1758812402000i64}));
                    tar.link(&format!("r0/{p}"), t);
                }
                Item::Raw(v) => {
                    // An index entry with no tar entry of its own (e.g. a file without h).
                    entries.push(v.clone());
                }
            }
        }
        let archive = encrypt(&self.k_data, 3, true, 16, salt(3), &zstd(&tar.finish()));
        self.v2_raw(id, entries, archive)
    }

    pub fn v2_raw(&self, id: &str, entries: Vec<Value>, archive: Vec<u8>) -> Value {
        fs::write(self.index_dir().join(format!("{id}.bba")), &archive).unwrap();
        let v = json!({"v":1,"vault_id":self.id,"snapshot_id":id,"created_at":"2026-09-25T15:00:00Z",
            "layout":"archive","archive":{"file":format!("{id}.bba"),"size":archive.len(),"sha256":crypto::hex(&crypto::sha256(&archive))},
            "device":{"id":"x","name":"Test Mac","os":"macos","app_version":"1.1.0"},
            "roots":[{"id":0,"path":"/Users/alex/Documents","name":"Documents"}],
            "entries":entries,"stats":{"files":0,"dirs":0,"links":0,"bytes":0}});
        self.write_index(id, &v, true);
        v
    }
}

pub enum Item {
    Dir(String),
    File(String, Vec<u8>),
    Link(String, String),
    Raw(Value),
}

pub fn dir(p: &str) -> Item {
    Item::Dir(p.into())
}
pub fn file(p: &str, d: &[u8]) -> Item {
    Item::File(p.into(), d.to_vec())
}
pub fn link(p: &str, t: &str) -> Item {
    Item::Link(p.into(), t.into())
}

/// A minimal ustar + pax writer (the archive rules of FORMAT.md).
#[derive(Default)]
pub struct TarW {
    pub buf: Vec<u8>,
}

impl TarW {
    fn header(&mut self, name: &str, kind: u8, size: u64, link: &str, mode: u32) {
        let long = |s: &str| !s.is_ascii() || s.len() > 100;
        if long(name) || long(link) {
            let mut rec = Vec::new();
            for (k, v) in [("path", name), ("linkpath", link)] {
                if !long(v) {
                    continue;
                }
                let body = format!(" {k}={v}\n");
                let mut n = body.len() + 1;
                loop {
                    let m = body.len() + n.to_string().len();
                    if m == n {
                        break;
                    }
                    n = m;
                }
                rec.extend(format!("{n}{body}").into_bytes());
            }
            self.raw_header("././@PaxHeader", b'x', rec.len() as u64, "", 0o644);
            self.buf.extend(&rec);
            self.pad();
        }
        let n = if long(name) { "pax-name" } else { name };
        let l = if long(link) { "pax-link" } else { link };
        self.raw_header(n, kind, size, l, mode);
    }

    pub fn raw_header(&mut self, name: &str, kind: u8, size: u64, link: &str, mode: u32) {
        let mut b = [0u8; 512];
        b[..name.len()].copy_from_slice(name.as_bytes());
        let oct = |b: &mut [u8], v: u64| {
            let s = format!("{:0w$o}\0", v, w = b.len() - 1);
            b.copy_from_slice(s.as_bytes());
        };
        oct(&mut b[100..108], mode as u64);
        oct(&mut b[108..116], 0);
        oct(&mut b[116..124], 0);
        oct(&mut b[124..136], size);
        oct(&mut b[136..148], 1758812400);
        b[156] = kind;
        b[157..157 + link.len()].copy_from_slice(link.as_bytes());
        b[257..263].copy_from_slice(b"ustar\0");
        b[263..265].copy_from_slice(b"00");
        b[148..156].copy_from_slice(b"        ");
        let sum: u64 = b.iter().map(|&c| c as u64).sum();
        let s = format!("{sum:06o}\0 ");
        b[148..156].copy_from_slice(s.as_bytes());
        self.buf.extend_from_slice(&b);
    }

    fn pad(&mut self) {
        while self.buf.len() % 512 != 0 {
            self.buf.push(0);
        }
    }

    pub fn dir(&mut self, name: &str) {
        self.header(name, b'5', 0, "", 0o755);
    }
    pub fn file(&mut self, name: &str, data: &[u8]) {
        self.header(name, b'0', data.len() as u64, "", 0o644);
        self.buf.extend_from_slice(data);
        self.pad();
    }
    pub fn link(&mut self, name: &str, target: &str) {
        self.header(name, b'2', 0, target, 0o777);
    }
    pub fn finish(mut self) -> Vec<u8> {
        self.buf.extend_from_slice(&[0u8; 1024]);
        self.buf
    }
}

pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_backupbase-restore")
}

/// Runs the tool with the test passcode in BB_PASSCODE.
pub fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).env("BB_PASSCODE", PASS).output().unwrap()
}

pub fn run_with(args: &[&str], pass: &str) -> Output {
    Command::new(bin()).args(args).env("BB_PASSCODE", pass).output().unwrap()
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

pub fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
