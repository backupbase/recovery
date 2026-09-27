//! Verifying a version: decrypt everything it stores and compare every file's SHA-256, with
//! no writes. v1: every blob the version uses. v2: the whole archive against its index,
//! including its end, its size and its SHA-256.

use std::collections::BTreeMap;
use std::io;

use crate::crypto;
use crate::error::{display, Kind};
use crate::pathsafe::{self, WINDOWS};
use crate::restore::{display_path, Progress};
use crate::store::{self, ArchiveCursor};
use crate::vault::{Index, Keys, VaultHeader};

#[derive(Default, Debug)]
pub struct VerifyReport {
    pub files: u64,
    pub bytes: u64,
    pub not_stored: u64,
    pub incomplete: u64,
    pub problems: Vec<String>,
}

pub fn verify(h: &VaultHeader, keys: &Keys, idx: &Index, progress: bool) -> VerifyReport {
    let names = pathsafe::root_dirs(&idx.roots, WINDOWS);
    let mut rep = VerifyReport::default();
    let stored: Vec<usize> = (0..idx.entries.len()).filter(|&i| idx.entries[i].stored()).collect();
    rep.not_stored = idx.entries.iter().filter(|e| e.is_file() && !e.stored()).count() as u64;
    rep.incomplete = stored.iter().filter(|&&i| idx.entries[i].incomplete()).count() as u64;
    let prog = Progress::new(progress, "Verifying", stored.len() as u64, stored.iter().map(|&i| idx.entries[i].size()).sum());

    if h.version == 1 {
        // Each blob once; every entry that uses it must name the same content.
        let mut by_blob: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for &i in &stored {
            by_blob.entry(idx.entries[i].b.as_deref().unwrap_or("")).or_default().push(i);
        }
        for (b, users) in by_blob {
            let res = store::read_blob(h, keys, b, &mut io::sink(), |n| prog.add_bytes(n));
            for &i in &users {
                let e = &idx.entries[i];
                let disp = display_path(&names, e);
                let hx = e.h.as_deref().unwrap_or("");
                match &res {
                    Ok((sha, _)) if crypto::hex(sha) == hx => {
                        if let Some(want) = crypto::unhex::<32>(hx) {
                            if crypto::blob_id(&keys.name, &want) != b {
                                rep.problems.push(format!("{disp}: stored under an id that does not match its content"));
                                continue;
                            }
                        }
                        rep.files += 1;
                        rep.bytes += e.size();
                    }
                    Ok(_) => rep.problems.push(format!("{disp}: its stored content does not match its SHA-256")),
                    Err(err) if err.kind == Kind::NotFound => rep.problems.push(format!("{disp}: its stored file is missing ({})", display(&store::blob_path(h, b).unwrap_or_default()))),
                    Err(err) => rep.problems.push(format!("{disp}: {}", err.message.trim_end_matches('.'))),
                }
                prog.add_file();
            }
        }
        prog.done();
        return rep;
    }

    let mut c = match ArchiveCursor::open(h, keys, idx) {
        Ok(c) => c,
        Err(err) => {
            prog.done();
            rep.problems.push(err.message);
            return rep;
        }
    };
    for (i, e) in idx.entries.iter().enumerate() {
        if !store::in_archive(e) {
            continue;
        }
        let disp = display_path(&names, e);
        let res = c.expect(e).and_then(|_| if e.is_file() { c.copy_file(&mut io::sink(), |n| prog.add_bytes(n)).map(Some) } else { Ok(None) });
        match res {
            Ok(Some(sha)) => {
                if Some(sha) == e.h.as_deref().and_then(crypto::unhex::<32>) {
                    rep.files += 1;
                    rep.bytes += e.size();
                } else {
                    rep.problems.push(format!("{disp}: its stored content does not match its SHA-256"));
                }
                prog.add_file();
            }
            Ok(None) => {}
            Err(err) => {
                let left = idx.entries[i..].iter().filter(|e| e.stored()).count();
                prog.done();
                rep.problems.push(format!("The archive {} is damaged at \"{disp}\": {err}. {} not checked.", display(&c.path), crate::text::plural(left as u64, "file was", "files were")));
                return rep;
            }
        }
    }
    prog.done();
    if let Err(err) = c.finish() {
        rep.problems.push(format!("The archive {} is damaged: {err}.", display(&c.path)));
    }
    rep
}
