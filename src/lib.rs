//! backupbase-restore: an independent reader for Backup Base vaults (format versions 1 and 2),
//! written from the published format specification (FORMAT.md). It shares no code with the
//! Backup Base app.

pub mod crypto;
pub mod error;
pub mod passcode;
pub mod pathsafe;
pub mod restore;
pub mod store;
pub mod stream;
pub mod tar;
pub mod text;
pub mod vault;
pub mod verify;

use std::path::{Path, PathBuf};

use error::{display, not_found, usage, Error, Kind, Result};
use vault::{Index, Keys, VaultHeader};

/// The vault a command works on: the folder itself, or the only vault inside it.
pub fn resolve_vault(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        return Err(not_found(format!("{} does not exist.", display(path))));
    }
    let found = vault::find_vaults(path);
    match found.len() {
        0 => Err(Error::new(Kind::NotAVault, format!("No Backup Base backup was found in {}.", display(path)))),
        1 => Ok(found.into_iter().next().unwrap()),
        _ => {
            let list: Vec<String> = found.iter().map(|p| format!("  {}", display(p))).collect();
            Err(usage(format!("{} holds several backups. Name one of them:\n{}", display(path), list.join("\n"))))
        }
    }
}

/// A version to work on, with its entries. `latest` (or none) is the newest version that
/// can be read; the ids passed over on the way are returned so they can be mentioned.
pub fn load_version(h: &VaultHeader, keys: &Keys, want: Option<&str>) -> Result<(Index, Vec<(String, String)>)> {
    let (ids, _) = h.version_files()?;
    let want = want.unwrap_or("latest");
    if want != "latest" {
        let id = vault::pick_version(&ids, Some(want))?;
        return Ok((h.read_index(keys, id, true)?, vec![]));
    }
    let mut passed = Vec::new();
    for id in ids.iter().rev() {
        match h.read_index(keys, id, true) {
            Ok(idx) => return Ok((idx, passed)),
            Err(e) if e.kind == Kind::Corrupt => passed.push((id.clone(), e.message)),
            Err(e) => return Err(e),
        }
    }
    Err(not_found("This backup has no versions that can be read."))
}
