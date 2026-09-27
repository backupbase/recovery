//! Cryptography of the vault format (FORMAT.md "Cryptography"): Argon2id passcode key,
//! AES-256-GCM key wrap, HKDF-SHA256 subkeys and per-file keys, HMAC-SHA256 blob ids.

use aes_gcm::aead::{AeadInOut, Nonce, Tag};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub type Key = Zeroizing<[u8; 32]>;

pub const INFO_DATA: &[u8] = b"bb/v1/data";
pub const INFO_SNAP: &[u8] = b"bb/v1/snap";
pub const INFO_NAME: &[u8] = b"bb/v1/name";
pub const INFO_FILE: &[u8] = b"bb/v1/file";
pub const WRAP_AAD_PREFIX: &str = "backupbase-vault-v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// The bounds readers enforce before running Argon2 (FORMAT.md "vault.bbv").
    pub fn in_bounds(&self) -> bool {
        (8..=1_048_576).contains(&self.m_kib) && (1..=16).contains(&self.t) && (1..=8).contains(&self.p) && self.m_kib >= 8 * self.p
    }
}

/// The passcode as Unicode NFC (macOS input can arrive as NFD).
pub fn nfc(passcode: &str) -> Zeroizing<String> {
    Zeroizing::new(passcode.nfc().collect())
}

/// Argon2id v19 of the NFC passcode: the key-encryption key.
pub fn derive_kek(passcode: &str, salt: &[u8], params: KdfParams) -> Option<Key> {
    if !params.in_bounds() || salt.len() < 8 {
        return None;
    }
    let pw = nfc(passcode);
    let p = argon2::Params::new(params.m_kib, params.t, params.p, Some(32)).ok()?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pw.as_bytes(), salt, &mut out[..]).ok()?;
    Some(out)
}

/// AES-256-GCM decryption of `buf` (ciphertext followed by the 16-byte tag) in place.
/// Returns the plaintext length, or None when the tag does not verify.
pub fn gcm_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Option<usize> {
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    gcm_open_with(&cipher, nonce, aad, buf)
}

pub fn gcm_open_with(cipher: &Aes256Gcm, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Option<usize> {
    let n = buf.len().checked_sub(16)?;
    let (msg, tag) = buf.split_at_mut(n);
    let tag = Tag::<Aes256Gcm>::try_from(&tag[..]).ok()?;
    let nonce = Nonce::<Aes256Gcm>::try_from(&nonce[..]).ok()?;
    cipher.decrypt_inout_detached(&nonce, aad, msg.into(), &tag).ok()?;
    Some(n)
}

/// Unwraps the vault's master key. None: the passcode (KEK) is wrong or the header was changed.
pub fn unwrap_master_key(kek: &[u8; 32], nonce: &[u8; 12], ct: &[u8; 48], vault_id: &str) -> Option<Key> {
    let mut buf = Zeroizing::new(*ct);
    let aad = format!("{WRAP_AAD_PREFIX}{vault_id}");
    let n = gcm_open(kek, nonce, aad.as_bytes(), &mut buf[..])?;
    if n != 32 {
        return None;
    }
    let mut mk = Zeroizing::new([0u8; 32]);
    mk.copy_from_slice(&buf[..32]);
    Some(mk)
}

/// HKDF-SHA256 with a 32-byte output.
pub fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut out[..]).expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// Per-file key: HKDF(base = K_data or K_snap, salt = file_salt, info "bb/v1/file").
pub fn file_key(base: &[u8; 32], file_salt: &[u8; 24]) -> Key {
    hkdf32(base, file_salt, INFO_FILE)
}

/// Blob id: HMAC-SHA256(K_name, sha256(plaintext)), first 16 bytes, Crockford base32.
pub fn blob_id(k_name: &[u8; 32], plaintext_sha256: &[u8; 32]) -> String {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(k_name).expect("HMAC takes any key length");
    mac.update(plaintext_sha256);
    let out = mac.finalize().into_bytes();
    let mut first = [0u8; 16];
    first.copy_from_slice(&out[..16]);
    crockford26(&first)
}

pub const CROCKFORD: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// 16 bytes as 26 lowercase Crockford base32 chars, most significant bit first, no padding.
pub fn crockford26(bytes: &[u8; 16]) -> String {
    let v = u128::from_be_bytes(*bytes);
    // 26 chars hold 130 bits: the value shifted left by 2 (two zero bits at the end).
    let mut out = String::with_capacity(26);
    for i in 0..26i32 {
        let shift = 125 - 5 * i; // bit position of this char's top bit within 130 bits
        let idx = if shift >= 2 { (v >> (shift - 2)) & 31 } else { (v << (2 - shift)) & 31 };
        out.push(CROCKFORD[idx as usize] as char);
    }
    out
}

pub fn is_blob_id(s: &str) -> bool {
    s.len() == 26 && s.bytes().all(|c| CROCKFORD.contains(&c))
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

/// Lowercase hex of exactly `N` bytes.
pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let b = s.as_bytes();
    for i in 0..N {
        let d = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        out[i] = (d(b[2 * i])? << 4) | d(b[2 * i + 1])?;
    }
    Some(out)
}

pub fn is_sha256_hex(s: &str) -> bool {
    unhex::<32>(s).is_some()
}

/// A vault id: a UUID, hyphenated (8-4-4-4-12) or 32 plain hex digits, any case.
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let plain: String = if s.len() == 36 {
        let b = s.as_bytes();
        if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
            return None;
        }
        s.chars().filter(|c| *c != '-').collect()
    } else if s.len() == 32 {
        s.to_string()
    } else {
        return None;
    };
    unhex::<16>(&plain.to_ascii_lowercase())
}
