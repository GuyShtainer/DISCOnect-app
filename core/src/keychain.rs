// SPDX-License-Identifier: AGPL-3.0-or-later
//! The OS keychain item that holds a store's master key: the twin of `storage/keys.py`'s keychain
//! half (`keychain_get`, `keychain_set`, `keychain_delete`, `keychain_state`).
//!
//! Layout is Python `keyring`'s: generic password, service `hearthbeat`, account = the key id in
//! lowercase hex, password = the master key in lowercase hex. On macOS the item is read and written
//! through the Security framework in-process (the `security-framework` crate), never through
//! `security add-generic-password -w`, which would put the key in a child process's argv. macOS
//! binds an item's access to the binary that made it, so an item Python made reads as `stale` here
//! (and the other way round); the app handles `stale` and 11d carries the migration note.
//!
//! Elsewhere there is no keychain: `get` finds nothing and `set`/`delete` report `NoBackend`, which
//! `serve` surfaces the way the oracle surfaces `keyring`'s `NoKeyringError`.
//!
//! **Test-only switch:** `DISCONECT_KEYCHAIN=fail` makes the backend behave like Python's
//! `PYTHON_KEYRING_BACKEND=keyring.backends.fail.Keyring` (reads find nothing, writes fail), so a
//! differential run never touches the real keychain. The desktop sidecar's env allowlist never
//! passes it on.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

pub const SERVICE: &str = "hearthbeat";
/// Test-only: `fail` disables the backend (see the module docs).
pub const BACKEND_ENV: &str = "DISCONECT_KEYCHAIN";
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// `cached` when this process can read the item, `absent` when none exists, `stale` when an item
/// exists that this code identity cannot read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainState {
    Cached,
    Absent,
    Stale,
}

impl KeychainState {
    pub fn as_str(self) -> &'static str {
        match self {
            KeychainState::Cached => "cached",
            KeychainState::Absent => "absent",
            KeychainState::Stale => "stale",
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeychainError {
    /// No usable keychain (`keyring.errors.NoKeyringError` in the oracle).
    #[error("no keychain backend")]
    NoBackend,
    /// The keychain refused or failed; carries no key material.
    #[error("keychain error: {0}")]
    Backend(String),
    /// The stored text is not hex (`bytes.fromhex` raising `ValueError` in the oracle).
    #[error("the keychain item is not hexadecimal")]
    NotHex,
}

fn disabled() -> bool {
    std::env::var(BACKEND_ENV).is_ok_and(|v| v == "fail")
}

fn account(key_id: &[u8; 16]) -> String {
    hex::encode(key_id)
}

#[cfg(target_os = "macos")]
mod backend {
    use security_framework::base::Error;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    // errSecItemNotFound
    const NOT_FOUND: i32 = -25300;

    pub fn read(service: &str, account: &str) -> Option<Vec<u8>> {
        get_generic_password(service, account).ok()
    }

    pub fn write(service: &str, account: &str, password: &[u8]) -> Result<(), Error> {
        set_generic_password(service, account, password)
    }

    /// `Ok(true)` when an item was removed, `Ok(false)` when there was none.
    pub fn remove(service: &str, account: &str) -> Result<bool, Error> {
        match delete_generic_password(service, account) {
            Ok(()) => Ok(true),
            Err(e) if e.code() == NOT_FOUND => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn error_text(error: &Error) -> String {
        format!("OSStatus {}", error.code())
    }
}

/// The master key cached for `key_id`, or `None` when there is none or the keychain cannot be read
/// (any keychain failure means "not cached", never a crash). Text that is not hex is an error.
pub fn get(key_id: &[u8; 16]) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
    if disabled() {
        return Ok(None);
    }
    read_item(key_id)
}

/// Store `master` (as lowercase hex, like `keyring`) for `key_id`.
pub fn set(key_id: &[u8; 16], master: &[u8]) -> Result<(), KeychainError> {
    if disabled() {
        return Err(KeychainError::NoBackend);
    }
    write_item(key_id, master)
}

/// Remove the item; `Ok(false)` when there was none (Python's `PasswordDeleteError`, swallowed).
pub fn delete(key_id: &[u8; 16]) -> Result<bool, KeychainError> {
    if disabled() {
        return Err(KeychainError::NoBackend);
    }
    delete_item(key_id)
}

#[cfg(target_os = "macos")]
fn read_item(key_id: &[u8; 16]) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
    let Some(stored) = backend::read(SERVICE, &account(key_id)).map(Zeroizing::new) else {
        return Ok(None);
    };
    if stored.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&stored).map_err(|_| KeychainError::NotHex)?;
    hex::decode(text)
        .map(|bytes| Some(Zeroizing::new(bytes)))
        .map_err(|_| KeychainError::NotHex)
}

#[cfg(target_os = "macos")]
fn write_item(key_id: &[u8; 16], master: &[u8]) -> Result<(), KeychainError> {
    let password = Zeroizing::new(hex::encode(master));
    backend::write(SERVICE, &account(key_id), password.as_bytes())
        .map_err(|e| KeychainError::Backend(backend::error_text(&e)))
}

#[cfg(target_os = "macos")]
fn delete_item(key_id: &[u8; 16]) -> Result<bool, KeychainError> {
    backend::remove(SERVICE, &account(key_id))
        .map_err(|e| KeychainError::Backend(backend::error_text(&e)))
}

#[cfg(not(target_os = "macos"))]
fn read_item(_key_id: &[u8; 16]) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
    Ok(None)
}

#[cfg(not(target_os = "macos"))]
fn write_item(_key_id: &[u8; 16], _master: &[u8]) -> Result<(), KeychainError> {
    Err(KeychainError::NoBackend)
}

#[cfg(not(target_os = "macos"))]
fn delete_item(_key_id: &[u8; 16]) -> Result<bool, KeychainError> {
    Err(KeychainError::NoBackend)
}

/// macOS only: does an item for this key id exist at all, readable by us or not? Never reads it:
/// `security find-generic-password` without `-w` prints attributes only. Anything wrong with the
/// probe (not macOS, no `security`, a timeout) means "no".
pub fn item_exists(key_id: &[u8; 16]) -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    let spawned = std::process::Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            SERVICE,
            "-a",
            &account(key_id),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else { return false };
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if started.elapsed() < PROBE_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(5))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// `keys.keychain_state`.
pub fn state(key_id: &[u8; 16]) -> Result<KeychainState, KeychainError> {
    if get(key_id)?.is_some() {
        return Ok(KeychainState::Cached);
    }
    Ok(if item_exists(key_id) {
        KeychainState::Stale
    } else {
        KeychainState::Absent
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_names_are_the_protocols() {
        assert_eq!(KeychainState::Cached.as_str(), "cached");
        assert_eq!(KeychainState::Absent.as_str(), "absent");
        assert_eq!(KeychainState::Stale.as_str(), "stale");
    }

    #[test]
    fn account_is_the_key_id_in_lowercase_hex() {
        assert_eq!(account(&[0xab; 16]), "ab".repeat(16));
    }
}
