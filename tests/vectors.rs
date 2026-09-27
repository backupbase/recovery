//! Known-answer vectors from FORMAT.md (tests/fixtures/vault-test-vectors.json, a copy of the
//! vectors published with the format). The v2 archive and index bytes were produced by the
//! Backup Base app, so decrypting and restoring them checks this reader against the real writer.

mod common;

use std::fs;
use std::io::Read;

use bbrestore::crypto;
use bbrestore::stream::{self, Decryptor, Header, Zstd};
use bbrestore::tar::TarReader;
use bbrestore::vault::VaultHeader;
use common::hex_decode;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/vault-test-vectors.json")).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    hex_decode(v.as_str().unwrap()).try_into().unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn decrypt_all(base: &[u8; 32], kind: u8, bytes: &[u8]) -> std::io::Result<(Header, Vec<u8>)> {
    let (h, mut d) = Decryptor::new(bytes, base, kind)?;
    let mut out = Vec::new();
    d.read_to_end(&mut out)?;
    Ok((h, out))
}

#[test]
fn kdf_and_nfc() {
    let v = vectors();
    let k = &v["kdf"];
    let params = crypto::KdfParams { m_kib: k["m_kib"].as_u64().unwrap() as u32, t: k["t"].as_u64().unwrap() as u32, p: k["p"].as_u64().unwrap() as u32 };
    let salt = hex_decode(s(&k["salt_hex"]));
    let kek = crypto::derive_kek(s(&k["passcode"]), &salt, params).unwrap();
    assert_eq!(crypto::hex(&kek[..]), s(&k["kek_hex"]));
    // NFC and NFD spellings of one passcode give one key.
    let nfc = crypto::derive_kek(s(&k["nfc_passcode"]), &salt, params).unwrap();
    let nfd = String::from_utf8(hex_decode(s(&k["nfd_passcode_hex"]))).unwrap();
    assert_ne!(nfd, s(&k["nfc_passcode"]));
    let nfd = crypto::derive_kek(&nfd, &salt, params).unwrap();
    assert_eq!(crypto::hex(&nfc[..]), s(&k["nfc_nfd_kek_hex"]));
    assert_eq!(crypto::hex(&nfd[..]), s(&k["nfc_nfd_kek_hex"]));
}

#[test]
fn key_wrap_subkeys_file_key_blob_id() {
    let v = vectors();
    let w = &v["wrap"];
    let ct: [u8; 48] = hex_decode(s(&w["ct_hex"])).try_into().unwrap();
    let nonce: [u8; 12] = hex_decode(s(&w["nonce_hex"])).try_into().unwrap();
    let mk = crypto::unwrap_master_key(&h32(&w["kek_hex"]), &nonce, &ct, s(&w["vault_id"])).unwrap();
    assert_eq!(crypto::hex(&mk[..]), s(&w["mk_hex"]));
    assert!(crypto::unwrap_master_key(&h32(&w["kek_hex"]), &nonce, &ct, "another-id").is_none());

    let sk = &v["subkeys"];
    let salt = hex_decode(s(&sk["hkdf_salt_hex"]));
    let mk = h32(&sk["mk_hex"]);
    assert_eq!(crypto::parse_uuid("3b0f0e2c-7a8e-4d4b-9f6c-2f1f3c7d9a10").unwrap().to_vec(), salt);
    assert_eq!(crypto::hex(&crypto::hkdf32(&mk, &salt, b"bb/v1/data")[..]), s(&sk["k_data_hex"]));
    assert_eq!(crypto::hex(&crypto::hkdf32(&mk, &salt, b"bb/v1/snap")[..]), s(&sk["k_snap_hex"]));
    assert_eq!(crypto::hex(&crypto::hkdf32(&mk, &salt, b"bb/v1/name")[..]), s(&sk["k_name_hex"]));

    let fk = &v["file_key"];
    let fsalt: [u8; 24] = hex_decode(s(&fk["file_salt_hex"])).try_into().unwrap();
    assert_eq!(crypto::hex(&crypto::file_key(&h32(&fk["base_hex"]), &fsalt)[..]), s(&fk["key_hex"]));

    let b = &v["blob_id"];
    let sha = crypto::sha256(s(&b["plaintext"]).as_bytes());
    assert_eq!(crypto::hex(&sha), s(&b["sha256_hex"]));
    assert_eq!(crypto::blob_id(&h32(&b["k_name_hex"]), &sha), s(&b["id"]));
    assert!(crypto::is_blob_id(s(&b["id"])));
}

#[test]
fn header_and_small_files() {
    let v = vectors();
    let hd = &v["header"];
    let raw: [u8; 32] = hex_decode(s(&hd["bytes_hex"])).try_into().unwrap();
    let h = Header::parse(raw).unwrap();
    assert_eq!((h.kind, h.zstd, h.seglog), (1, false, 20));
    assert_eq!(crypto::hex(&h.salt), s(&hd["file_salt_hex"]));

    let sf = &v["small_file"];
    let (_, out) = decrypt_all(&h32(&sf["base_hex"]), stream::KIND_DATA, &hex_decode(s(&sf["encrypted_hex"]))).unwrap();
    assert_eq!(out, s(&sf["plaintext"]).as_bytes());

    let ef = &v["empty_file"];
    let (_, out) = decrypt_all(&h32(&ef["base_hex"]), stream::KIND_DATA, &hex_decode(s(&ef["encrypted_hex"]))).unwrap();
    assert!(out.is_empty());

    let sn = &v["snapshot_file"];
    let bytes = hex_decode(s(&sn["encrypted_hex"]));
    let (_, out) = decrypt_all(&h32(&sn["base_hex"]), stream::KIND_INDEX, &bytes).unwrap();
    assert_eq!(out, s(&sn["plaintext"]).as_bytes());
    // The blob reader refuses a snapshot, and the other way round.
    assert!(Decryptor::new(&bytes[..], &h32(&sn["base_hex"]), stream::KIND_DATA).is_err());
}

#[test]
fn segment_boundaries() {
    let v = vectors();
    for name in ["exact_multiple", "multi_segment"] {
        let t = &v[name];
        let len = t["length"].as_u64().unwrap() as usize;
        let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let salt: [u8; 24] = hex_decode("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7").try_into().unwrap();
        let enc = common::encrypt(&h32(&t["base_hex"]), 1, false, t["seglog"].as_u64().unwrap() as u8, salt, &plain);
        assert_eq!(enc.len() as u64, t["encrypted_len"].as_u64().unwrap(), "{name}");
        assert_eq!(crypto::hex(&crypto::sha256(&enc)), s(&t["encrypted_sha256_hex"]), "{name}");
        let (_, out) = decrypt_all(&h32(&t["base_hex"]), 1, &enc).unwrap();
        assert_eq!(out, plain);
        // Cut at a segment boundary: the last remaining segment is not final, so it fails.
        let cut = 32 + (1 << 16) + 16;
        assert!(decrypt_all(&h32(&t["base_hex"]), 1, &enc[..cut]).is_err(), "{name} truncated at a boundary");
        assert!(decrypt_all(&h32(&t["base_hex"]), 1, &enc[..enc.len() - 1]).is_err(), "{name} truncated by one byte");
        let mut flipped = enc.clone();
        flipped[40] ^= 1;
        assert!(decrypt_all(&h32(&t["base_hex"]), 1, &flipped).is_err(), "{name} flipped");
    }
}

#[test]
fn v2_archive_and_index() {
    let v = vectors();
    let a = &v["v2"]["archive"];
    let enc = hex_decode(s(&a["encrypted_hex"]));
    assert_eq!(crypto::hex(&crypto::sha256(&enc)), s(&a["encrypted_sha256_hex"]));
    let (h, zst) = decrypt_all(&h32(&a["k_data_hex"]), stream::KIND_ARCHIVE, &enc).unwrap();
    assert!(h.zstd);
    assert_eq!(crypto::hex(&zst), s(&a["zstd_hex"]));
    let mut tar = Vec::new();
    Zstd::new(&zst[..], stream::MAX_WINDOW_ARCHIVE).read_to_end(&mut tar).unwrap();
    assert_eq!(crypto::hex(&tar), s(&a["tar_hex"]));

    let i = &v["v2"]["index"];
    let (_, json) = decrypt_all(&h32(&i["k_snap_hex"]), stream::KIND_INDEX, &hex_decode(s(&i["encrypted_hex"]))).unwrap();
    assert_eq!(json, s(&i["plaintext"]).as_bytes());

    // The tar stream matches the index entry by entry.
    let idx: Value = serde_json::from_slice(&json).unwrap();
    let mut t = TarReader::new(&tar[..]);
    for e in idx["entries"].as_array().unwrap() {
        let got = t.next_entry().unwrap().unwrap();
        let p = s(&e["p"]);
        let name = match (s(&e["k"]), p.is_empty()) {
            (_, true) => "r0/".to_string(),
            ("d", false) => format!("r0/{p}/"),
            _ => format!("r0/{p}"),
        };
        assert_eq!(got.name, name);
        if s(&e["k"]) == "f" {
            let mut data = Vec::new();
            let sha = t.copy_data(&mut data, |_| {}).unwrap();
            assert_eq!(crypto::hex(&sha), s(&e["h"]));
        }
        if s(&e["k"]) == "l" {
            assert_eq!(got.link, s(&e["t"]));
        }
    }
    assert!(t.next_entry().unwrap().is_none());
    t.check_nothing_after().unwrap();
}

/// Builds the v2 vector as a real vault folder and runs the tool on it end to end.
#[test]
fn v2_vector_vault_restores_with_the_tool() {
    let v = vectors();
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("Backup Base").join("Documents");
    fs::create_dir_all(vault.join("archives")).unwrap();
    fs::write(vault.join("vault.bbv"), serde_json::to_vec(&v["v2"]["vault_bbv"]["json"]).unwrap()).unwrap();
    let id = s(&v["v2"]["index"]["snapshot_id"]);
    fs::write(vault.join("archives").join(format!("{id}.bbs")), hex_decode(s(&v["v2"]["index"]["encrypted_hex"]))).unwrap();
    fs::write(vault.join("archives").join(format!("{id}.bba")), hex_decode(s(&v["v2"]["archive"]["encrypted_hex"]))).unwrap();
    let pass = s(&v["v2"]["vault_bbv"]["passcode"]);

    let h = VaultHeader::read(&vault).unwrap();
    assert_eq!(h.version, 2);
    let keys = h.unlock(pass).unwrap();
    assert_eq!(crypto::hex(&keys.data[..]), s(&v["subkeys"]["k_data_hex"]));

    let list = common::run_with(&["list", tmp.path().join("Backup Base").to_str().unwrap()], pass);
    assert!(list.status.success(), "{}{}", common::stdout(&list), common::stderr(&list));
    let out = common::stdout(&list);
    assert!(out.contains("version 2") && out.contains(id) && out.contains("3 files"), "{out}");

    let ver = common::run_with(&["verify", vault.to_str().unwrap()], pass);
    assert!(ver.status.success(), "{}", common::stdout(&ver));

    let to = tmp.path().join("out");
    let r = common::run_with(&["restore", vault.to_str().unwrap(), "--to", to.to_str().unwrap()], pass);
    assert!(r.status.success(), "{}{}", common::stdout(&r), common::stderr(&r));
    let root = to.join("Documents");
    assert_eq!(fs::read(root.join("Docs/hello.txt")).unwrap(), b"Hello, Backup Base!\n");
    assert_eq!(fs::read(root.join("Résumé ✓.txt")).unwrap().len(), 13);
    assert_eq!(fs::read(root.join("empty.txt")).unwrap().len(), 0);
    let md = fs::metadata(root.join("Docs/hello.txt")).unwrap();
    assert_eq!(filetime::FileTime::from_last_modification_time(&md).unix_seconds(), 1758812400);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(root.join("Résumé ✓.txt")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_link(root.join("link")).unwrap().to_str().unwrap(), "Docs/hello.txt");
        assert_eq!(fs::read(root.join("link")).unwrap(), b"Hello, Backup Base!\n");
    }

    let wrong = common::run_with(&["files", vault.to_str().unwrap()], "wrong passcode");
    assert_eq!(wrong.status.code(), Some(3));
}

#[test]
fn v1_vector_vault_header_opens() {
    let v = vectors();
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("vault.bbv"), serde_json::to_vec(&v["vault_bbv"]["json"]).unwrap()).unwrap();
    let h = VaultHeader::read(tmp.path()).unwrap();
    assert_eq!(h.version, 1);
    let keys = h.unlock(s(&v["vault_bbv"]["passcode"])).unwrap();
    assert_eq!(crypto::hex(&keys.snap[..]), s(&v["subkeys"]["k_snap_hex"]));
    assert_eq!(crypto::hex(&keys.name[..]), s(&v["subkeys"]["k_name_hex"]));
    assert!(matches!(h.unlock("Correct horse battery staple"), Err(e) if e.kind == bbrestore::error::Kind::WrongPasscode));
}
