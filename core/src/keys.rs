// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read the key file written by the Python core (`<db>.keys.json`). This slice never writes one.
//!
//! Format (pinned by `storage/keys.py`): standard base64 with padding, fixed AAD bytes,
//! NFC-normalised passphrases, Argon2id version 0x13 with parallelism 1. Nothing here prints,
//! logs or Debug-formats key material.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const FORMAT_VERSION: u64 = 1;
pub const PASSPHRASE_ENV: &str = "DISCONECT_PASSPHRASE";
pub const KEYS_ENV: &str = "DISCONECT_KEYS";
pub const KEY_FILE_SUFFIX: &str = ".keys.json";
pub const NEXT_SUFFIX: &str = ".next";
pub const RECOVERY_WORDS_ENV: &str = "DISCONECT_RECOVERY_WORDS";
pub const PURPOSE_PASSPHRASE: &str = "passphrase";

// Frozen wire constants (docs/kb/24-wire-constants.md): they stay `hearthbeat` through every rename.
const INFO_DB: &[u8] = b"hearthbeat/db";
const INFO_KEY_ID: &[u8] = b"hearthbeat/key-id";
const AAD_PREFIX: &[u8] = b"hearthbeat/keys/v1/";
const KEY_FILE_FORMAT: &str = "hearthbeat-keys";

const KDF_FLOOR_M_KIB: u64 = 64 * 1024;
const KDF_FLOOR_T: u64 = 2;
const KDF_CEILING_M_KIB: u64 = 4 * 1024 * 1024;
const KDF_CEILING_T: u64 = 20;

/// Test-only hook, mirrors Python's `set_kdf_params`: lifts the cost floor (never the ceiling).
static FLOOR_OFF: AtomicBool = AtomicBool::new(false);

/// Lift (or restore) the KDF cost floor. Intended for tests only.
pub fn set_kdf_floor_off(off: bool) {
    FLOOR_OFF.store(off, Ordering::SeqCst);
}

/// A 32-byte master key. Zeroised on drop.
pub type Secret32 = Zeroizing<[u8; 32]>;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("no key file at {0}; run 'hearthbeat key init' (or set HEARTHBEAT_KEYS)")]
    KeyFileMissing(String),
    #[error("key file is corrupt: {0}")]
    KeyFileCorrupt(String),
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("the database is encrypted and no unlock path applies (set HEARTHBEAT_PASSPHRASE or pass a passphrase file)")]
    Locked,
}

fn corrupt<T>(reason: &str) -> Result<T, KeyError> {
    Err(KeyError::KeyFileCorrupt(reason.to_string()))
}

/// The parsed key file. Holds no secrets.
#[derive(Debug, Clone)]
pub struct KeyFile {
    pub key_id: [u8; 16],
    pub created_at: String,
    pub wraps: Vec<Value>,
}

/// `Path.expanduser()` for a leading `~` or `~/`: `$HOME` stands in for the home directory.
/// (`~name` is left alone; Python would look `name` up in the password database.)
pub fn expand_user(path: &Path) -> PathBuf {
    match (path.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => path.to_path_buf(),
    }
}

/// `$DISCONECT_KEYS` (with `~` expanded) if set and non-empty, else `<db>.keys.json` beside the database.
pub fn key_path_for(db_path: &Path) -> PathBuf {
    match std::env::var_os(KEYS_ENV) {
        Some(p) if !p.is_empty() => expand_user(Path::new(&p)),
        _ => sibling_with_suffix(db_path, KEY_FILE_SUFFIX),
    }
}

/// `<path><suffix>` in the same directory.
pub fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(suffix);
    path.with_file_name(name)
}

/// The rotation-in-progress companion of a key file (`<keys>.next`).
pub fn next_path_for(key_path: &Path) -> PathBuf {
    sibling_with_suffix(key_path, NEXT_SUFFIX)
}

pub fn read_key_file(path: &Path) -> Result<KeyFile, KeyError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            return Err(KeyError::KeyFileMissing(name));
        }
        Err(_) => return corrupt("key file is unreadable"),
    };
    let raw: Value = serde_json::from_str(&text).or_else(|_| corrupt("key file is unreadable"))?;
    parse_document(&raw)
}

fn parse_document(raw: &Value) -> Result<KeyFile, KeyError> {
    let format_ok = raw.get("format").and_then(Value::as_str) == Some(KEY_FILE_FORMAT);
    let version = raw.get("format_version").and_then(Value::as_u64).unwrap_or(0);
    if !format_ok || version > FORMAT_VERSION {
        return corrupt("key file is not a disconect key file this build understands");
    }
    let key_id_hex = raw.get("key_id").and_then(Value::as_str).unwrap_or("");
    let key_id: [u8; 16] = hex::decode(key_id_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| KeyError::KeyFileCorrupt("key file has no usable key id or wraps".into()))?;
    let wraps = raw.get("wraps").and_then(Value::as_array).cloned().unwrap_or_default();
    if wraps.is_empty() {
        return corrupt("key file has no usable key id or wraps");
    }
    let created_at = raw.get("created_at").and_then(Value::as_str).unwrap_or("").to_string();
    Ok(KeyFile { key_id, created_at, wraps })
}

/// Argon2id parameters after validation: exact keys, p = 1, v = 0x13, cost inside [floor, ceiling].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
}

pub fn validate_params(params: &Value) -> Result<KdfParams, KeyError> {
    let obj = params
        .as_object()
        .ok_or_else(|| KeyError::KeyFileCorrupt("key file KDF params are malformed".into()))?;
    let exact = obj.len() == 4 && ["m_kib", "t", "p", "v"].iter().all(|k| obj.contains_key(*k));
    if !exact {
        return corrupt("key file KDF params are malformed");
    }
    let get = |k: &str| obj.get(k).and_then(Value::as_u64);
    let (Some(m), Some(t), Some(p), Some(v)) = (get("m_kib"), get("t"), get("p"), get("v")) else {
        return corrupt("key file KDF params are malformed");
    };
    if p != 1 || v != 0x13 {
        return corrupt("key file asks for Argon2 settings this build does not use");
    }
    if m > KDF_CEILING_M_KIB || t > KDF_CEILING_T {
        return corrupt("key file asks for a KDF cost above the ceiling; refusing");
    }
    if !FLOOR_OFF.load(Ordering::SeqCst) && (m < KDF_FLOOR_M_KIB || t < KDF_FLOOR_T) {
        return corrupt("key file asks for a KDF cost below the floor; refusing");
    }
    // Both fit u32 after the ceiling check; t = 0 or tiny m are rejected by Argon2 itself.
    Ok(KdfParams { m_kib: m as u32, t: t as u32 })
}

/// NFC-normalised UTF-8 bytes of a passphrase.
pub fn normalise_passphrase(text: &str) -> Zeroizing<Vec<u8>> {
    let normalised: String = text.nfc().collect();
    Zeroizing::new(normalised.into_bytes())
}

fn aad(purpose: &str, key_id: &[u8; 16]) -> Vec<u8> {
    let mut out = AAD_PREFIX.to_vec();
    out.extend_from_slice(purpose.as_bytes());
    out.push(b'/');
    out.extend_from_slice(hex::encode(key_id).as_bytes());
    out
}

fn passphrase_key(passphrase: &str, salt: &[u8], params: &Value) -> Result<Secret32, KeyError> {
    let p = validate_params(params)?;
    let argon_params = Params::new(p.m_kib, p.t, 1, Some(32))
        .or_else(|_| corrupt("key derivation failed"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out: Secret32 = Zeroizing::new([0u8; 32]);
    let pw = normalise_passphrase(passphrase);
    argon
        .hash_password_into(&pw, salt, &mut *out)
        .or_else(|_| corrupt("key derivation failed"))?;
    Ok(out)
}

fn hkdf32(master: &[u8], info: &[u8]) -> Secret32 {
    let mut out: Secret32 = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below the HKDF-SHA256 limit; expand cannot fail.
    if Hkdf::<Sha256>::new(None, master).expand(info, &mut *out).is_err() {
        out.fill(0);
    }
    out
}

/// HKDF-SHA256(master, no salt, "hearthbeat/key-id", 16 bytes).
pub fn key_id_for(master: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    // 16 bytes is far below the HKDF-SHA256 limit; expand cannot fail.
    if Hkdf::<Sha256>::new(None, master).expand(INFO_KEY_ID, &mut out).is_err() {
        out = [0u8; 16];
    }
    out
}

/// The 32-byte SQLCipher raw key for `master`.
pub fn db_key(master: &[u8; 32]) -> Secret32 {
    hkdf32(master, INFO_DB)
}

/// Lowercase hex of [`db_key`].
pub fn db_key_hex(master: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(hex::encode(*db_key(master)))
}

fn b64_field(wrap: &Value, name: &str) -> Result<Vec<u8>, KeyError> {
    let text = wrap.get(name).and_then(Value::as_str);
    text.and_then(|t| STANDARD.decode(t).ok())
        .ok_or_else(|| KeyError::KeyFileCorrupt("key file wrap is malformed: ValueError".into()))
}

fn unwrap_one(wrap: &Value, key_id: &[u8; 16], passphrase: &str) -> Result<Secret32, KeyError> {
    let params = wrap
        .get("params")
        .filter(|p| p.is_object())
        .ok_or_else(|| KeyError::KeyFileCorrupt("key file wrap is malformed".into()))?;
    let salt = b64_field(wrap, "salt")?;
    let nonce = b64_field(wrap, "nonce")?;
    let sealed = b64_field(wrap, "ct")?;
    if wrap.get("kdf").and_then(Value::as_str) != Some("argon2id")
        || wrap.get("aead").and_then(Value::as_str) != Some("chacha20poly1305")
    {
        return corrupt("key file uses algorithms this build does not know");
    }
    if salt.len() != 16 || nonce.len() != 12 {
        return corrupt("key file wrap has the wrong salt or nonce size");
    }
    let purpose = wrap.get("purpose").and_then(Value::as_str).unwrap_or("");
    let key = passphrase_key(passphrase, &salt, params)?;
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let nonce = Nonce::try_from(nonce.as_slice())
        .or_else(|_| corrupt("key file wrap has the wrong salt or nonce size"))?;
    let plain = cipher
        .decrypt(&nonce, Payload { msg: &sealed, aad: &aad(purpose, key_id) })
        .map_err(|_| KeyError::WrongPassphrase)?;
    let plain = Zeroizing::new(plain);
    let master: [u8; 32] = plain
        .as_slice()
        .try_into()
        .or_else(|_| corrupt("key file's master key has the wrong size"))?;
    let master: Secret32 = Zeroizing::new(master);
    if key_id_for(&master) != *key_id {
        return corrupt("key file's key id does not match its master key");
    }
    Ok(master)
}

/// Unlock `key_file` with `passphrase` (first passphrase wrap).
pub fn unlock_with_passphrase(key_file: &KeyFile, passphrase: &str) -> Result<Secret32, KeyError> {
    let wrap = key_file
        .wraps
        .iter()
        .find(|w| w.get("purpose").and_then(Value::as_str) == Some(PURPOSE_PASSPHRASE))
        .ok_or_else(|| KeyError::KeyFileCorrupt("key file has no passphrase wrap".into()))?;
    unwrap_one(wrap, &key_file.key_id, passphrase)
}

/// Read and REMOVE the test/CI passphrase from the process environment.
pub fn take_env_passphrase() -> Option<Zeroizing<String>> {
    let value = std::env::var(PASSPHRASE_ENV).ok();
    // SAFETY: called early on the calling thread; this crate does not read the env concurrently.
    unsafe { std::env::remove_var(PASSPHRASE_ENV) };
    value.filter(|v| !v.is_empty()).map(Zeroizing::new)
}

/// Remove both secret variables (`serve` never unlocks from the environment). Returns whether the
/// passphrase variable was set, even to an empty string (that is what the oracle warns about).
///
/// Call this first thing in `main`, before any thread exists: `remove_var` is unsafe in edition 2024
/// because another thread's `getenv` may race it.
pub fn scrub_env_secrets() -> bool {
    let was_set = std::env::var_os(PASSPHRASE_ENV).is_some();
    // SAFETY: documented above; the binary calls this before it spawns anything.
    unsafe {
        std::env::remove_var(PASSPHRASE_ENV);
        std::env::remove_var(RECOVERY_WORDS_ENV);
    }
    was_set
}

/// Where a passphrase may come from in this slice (no keychain, no prompt).
pub enum PassphraseSource<'a> {
    /// `DISCONECT_PASSPHRASE`, then nothing else.
    Env,
    /// An explicit passphrase from the caller; the environment variable is still consumed.
    Explicit(&'a str),
}

/// Unlock the key file at `key_path` with the given source; `Locked` if no source has a passphrase.
pub fn unlock(key_path: &Path, source: PassphraseSource<'_>) -> Result<Secret32, KeyError> {
    let key_file = read_key_file(key_path)?;
    let from_env = take_env_passphrase();
    let passphrase: Zeroizing<String> = match source {
        PassphraseSource::Explicit(p) => Zeroizing::new(p.to_string()),
        PassphraseSource::Env => from_env.ok_or(KeyError::Locked)?,
    };
    unlock_with_passphrase(&key_file, &passphrase)
}

#[cfg(test)]
mod wire_constants {
    //! Known-answer vectors for the frozen derivations; the Python twin is `tests/test_wire_constants.py`.
    use super::*;

    const KEY_ID_HEX: &str = "b4714bc6c191877abbd67d79274a4fd2";
    const DB_KEY_HEX: &str = "5a0db69ac2f8cc262e5bfb28d4deb8b9ba8637307cea5de707d890654573b162";

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test.keys.json")
    }

    #[test]
    fn labels_are_frozen_verbatim() {
        assert_eq!(INFO_DB, b"hearthbeat/db");
        assert_eq!(INFO_KEY_ID, b"hearthbeat/key-id");
        assert_eq!(AAD_PREFIX, b"hearthbeat/keys/v1/");
        assert_eq!(KEY_FILE_FORMAT, "hearthbeat-keys");
        let key_id: [u8; 16] = [0x11; 16];
        let expected = format!("hearthbeat/keys/v1/passphrase/{}", hex::encode(key_id));
        assert_eq!(aad(PURPOSE_PASSPHRASE, &key_id), expected.as_bytes());
    }

    #[test]
    fn known_answer_key_id_and_db_key() {
        let key_file = read_key_file(&fixture()).expect("fixture key file");
        let secret = unlock_with_passphrase(&key_file, "core-test-passphrase-2026").expect("unlock");
        assert_eq!(hex::encode(key_id_for(&secret)), KEY_ID_HEX);
        assert_eq!(&*db_key_hex(&secret), DB_KEY_HEX);
    }
}
