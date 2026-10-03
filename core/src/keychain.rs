// SPDX-License-Identifier: AGPL-3.0-or-later
//! The OS keychain item that holds a store's master key: the twin of `storage/keys.py`'s keychain
//! half (`keychain_get`, `keychain_set`, `keychain_delete`, `keychain_state`), with one deliberate
//! difference: it never lets macOS ask the user a question except on the explicit switch.
//!
//! Layout is Python `keyring`'s except for the service: generic password, service
//! [`SERVICE`] (`identity::KEYCHAIN_SERVICE`, `disconect`; Python uses `disconect-cli`), account = the
//! key id in lowercase hex, password = the master key in lowercase hex. On macOS the item is read
//! and written through the Security framework in-process (the `security-framework` crate), never
//! through `security add-generic-password -w`, which would put the key in a child process's argv.
//!
//! What the 11d keychain matrix measured (slice 4A, 2026-10-03; kb/23 class 5): macOS binds an item to the program that made it
//! (for ad-hoc builds: to its code hash, so every rebuild turns the previous build's item foreign).
//! A secret read of a foreign item needs a user dialog, an attributes-only search never does, and
//! `SecItemUpdate` over a foreign item *succeeds but leaves it unreadable to everyone* — so
//! "enable" is delete-then-add, never update.
//!
//! * [`get`] and [`state`] read the secret only with user interaction switched off
//!   (`SecKeychainSetUserInteractionAllowed(false)`): a foreign item then fails at once with an
//!   `OSStatus` instead of raising a dialog, and reads as `stale` (the item exists, attributes-only
//!   probe) — a navigation or an app start can never show a keychain prompt.
//! * [`set`] / [`delete`] are the explicit switch: they remove the item (by query, and by item
//!   reference when the query is refused for a foreign item), and `set` then adds a fresh one made
//!   by this program. They may touch only the item of [`SERVICE`] and the given key id.
//!
//! Elsewhere there is no keychain: `get` finds nothing and `set`/`delete` report `NoBackend`, which
//! `serve` surfaces the way the oracle surfaces `keyring`'s `NoKeyringError`.
//!
//! **Test-only switch:** `DISCONECT_KEYCHAIN=fail` makes the backend behave like Python's
//! `PYTHON_KEYRING_BACKEND=keyring.backends.fail.Keyring` (reads find nothing, writes fail), so a
//! differential run never touches the real keychain. The desktop sidecar's env allowlist never
//! passes it on.

use zeroize::Zeroizing;

use crate::identity::KEYCHAIN_SERVICE;

/// The keychain service of this core (see `identity::KEYCHAIN_SERVICE`).
pub const SERVICE: &str = KEYCHAIN_SERVICE;
/// Test-only: `fail` disables the backend (see the module docs).
pub const BACKEND_ENV: &str = "DISCONECT_KEYCHAIN";

/// `cached` when this process can read the item without a dialog, `absent` when none exists,
/// `stale` when an item exists that this code identity cannot read without one.
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

/// What a quiet (no dialog) attempt to read the secret came to.
#[derive(Debug, PartialEq, Eq)]
enum Quiet {
    Secret(Vec<u8>),
    NotFound,
    /// Anything else: the item needs a dialog, the keychain is locked, no UI is possible, ...
    Unreadable,
}

#[cfg(target_os = "macos")]
mod backend {
    use std::sync::Mutex;

    use security_framework::base::Error;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    use super::Quiet;

    // errSecItemNotFound
    const NOT_FOUND: i32 = -25300;

    /// `SecKeychainSetUserInteractionAllowed` is process-wide: one keychain call at a time, so a
    /// quiet read can never overlap an explicit (dialog-allowed) write on another thread.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Read the secret with user interaction off. If it cannot be switched off the read is not
    /// attempted (fail closed): a status screen must never be able to raise a dialog.
    pub fn read_quiet(service: &str, account: &str) -> Quiet {
        let _one = exclusive();
        let Ok(_no_ui) = SecKeychain::disable_user_interaction() else {
            return Quiet::Unreadable;
        };
        match get_generic_password(service, account) {
            Ok(bytes) => Quiet::Secret(bytes),
            Err(e) if e.code() == NOT_FOUND => Quiet::NotFound,
            Err(_) => Quiet::Unreadable,
        }
    }

    /// Does an item exist at all, readable by us or not? An attributes-only search: no data is
    /// requested, so no dialog (and no secret read) is possible. `None` = the search itself failed.
    pub fn probe(service: &str, account: &str) -> Option<bool> {
        let _one = exclusive();
        let _no_ui = SecKeychain::disable_user_interaction().ok();
        let found = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(service)
            .account(account)
            .load_attributes(true)
            .limit(Limit::Max(1))
            .search();
        match found {
            Ok(items) => Some(!items.is_empty()),
            Err(e) if e.code() == NOT_FOUND => Some(false),
            Err(_) => None,
        }
    }

    pub fn write(service: &str, account: &str, password: &[u8]) -> Result<(), Error> {
        let _one = exclusive();
        set_generic_password(service, account, password)
    }

    /// Remove the item by query; when the query is refused (`errSecInvalidOwnerEdit`, -25244, is
    /// what a foreign item answers) remove it through its item reference, which macOS allows, and
    /// check that it is gone. `Ok(true)` when an item was removed, `Ok(false)` when there was none.
    pub fn remove(service: &str, account: &str) -> Result<bool, Error> {
        let _one = exclusive();
        match delete_generic_password(service, account) {
            Ok(()) => Ok(true),
            Err(e) if e.code() == NOT_FOUND => Ok(false),
            Err(refused) => remove_by_reference(service, account).map_err(|_| refused),
        }
    }

    fn remove_by_reference(service: &str, account: &str) -> Result<bool, Error> {
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::generic_password())
            .service(service)
            .account(account)
            .load_refs(true)
            .limit(Limit::Max(1));
        let mut called = false;
        for found in query.search()? {
            if let SearchResult::Ref(Reference::KeychainItem(item)) = found {
                item.delete(); // the wrapper drops the status: the check below is the proof
                called = true;
            }
        }
        let mut check = ItemSearchOptions::new();
        check
            .class(ItemClass::generic_password())
            .service(service)
            .account(account)
            .load_attributes(true)
            .limit(Limit::Max(1));
        match check.search() {
            Ok(left) if !left.is_empty() => Err(Error::from_code(-25244)),
            Ok(_) => Ok(called),
            Err(e) if e.code() == NOT_FOUND => Ok(called),
            Err(e) => Err(e),
        }
    }

    pub fn error_text(error: &Error) -> String {
        format!("OSStatus {}", error.code())
    }
}

fn quiet_read(service: &str, key_id: &[u8; 16]) -> Quiet {
    #[cfg(target_os = "macos")]
    {
        backend::read_quiet(service, &account(key_id))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, key_id);
        Quiet::NotFound
    }
}

/// The master key cached for `key_id` **if it can be read without any dialog**, else `None` (no
/// item, a foreign item, a locked keychain: never a crash, never a prompt). Text that is not hex is
/// an error.
pub fn get(key_id: &[u8; 16]) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
    get_in(SERVICE, key_id)
}

/// [`get`] under another service name: the seam the real-keychain test uses with a scratch name.
pub fn get_in(
    service: &str,
    key_id: &[u8; 16],
) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
    if disabled() {
        return Ok(None);
    }
    read_item(service, key_id)
}

/// Replace the cached master key for `key_id` with `master` (as lowercase hex, like `keyring`):
/// remove any item first, then add one made by this program. This is the explicit switch and may
/// show one dialog; a status call never does.
pub fn set(key_id: &[u8; 16], master: &[u8]) -> Result<(), KeychainError> {
    set_in(SERVICE, key_id, master)
}

/// [`set`] under another service name (the test seam).
pub fn set_in(service: &str, key_id: &[u8; 16], master: &[u8]) -> Result<(), KeychainError> {
    if disabled() {
        return Err(KeychainError::NoBackend);
    }
    write_item(service, key_id, master)
}

/// Remove the item; `Ok(false)` when there was none (Python's `PasswordDeleteError`, swallowed).
pub fn delete(key_id: &[u8; 16]) -> Result<bool, KeychainError> {
    delete_in(SERVICE, key_id)
}

/// [`delete`] under another service name (the test seam).
pub fn delete_in(service: &str, key_id: &[u8; 16]) -> Result<bool, KeychainError> {
    if disabled() {
        return Err(KeychainError::NoBackend);
    }
    delete_item(service, key_id)
}

fn read_item(
    service: &str,
    key_id: &[u8; 16],
) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
    let Quiet::Secret(stored) = quiet_read(service, key_id) else {
        return Ok(None);
    };
    let stored = Zeroizing::new(stored);
    if stored.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&stored).map_err(|_| KeychainError::NotHex)?;
    hex::decode(text)
        .map(|bytes| Some(Zeroizing::new(bytes)))
        .map_err(|_| KeychainError::NotHex)
}

#[cfg(target_os = "macos")]
fn write_item(service: &str, key_id: &[u8; 16], master: &[u8]) -> Result<(), KeychainError> {
    let password = Zeroizing::new(hex::encode(master));
    let account = account(key_id);
    let backend_error =
        |e: &security_framework::base::Error| KeychainError::Backend(backend::error_text(e));
    backend::remove(service, &account).map_err(|e| backend_error(&e))?;
    backend::write(service, &account, password.as_bytes()).map_err(|e| backend_error(&e))
}

#[cfg(target_os = "macos")]
fn delete_item(service: &str, key_id: &[u8; 16]) -> Result<bool, KeychainError> {
    backend::remove(service, &account(key_id))
        .map_err(|e| KeychainError::Backend(backend::error_text(&e)))
}

#[cfg(not(target_os = "macos"))]
fn write_item(_service: &str, _key_id: &[u8; 16], _master: &[u8]) -> Result<(), KeychainError> {
    Err(KeychainError::NoBackend)
}

#[cfg(not(target_os = "macos"))]
fn delete_item(_service: &str, _key_id: &[u8; 16]) -> Result<bool, KeychainError> {
    Err(KeychainError::NoBackend)
}

/// macOS only: does an item for this key id exist at all, readable by us or not? In-process and
/// attributes-only: it never reads the secret and cannot raise a dialog. Anything wrong with the
/// probe (not macOS, the search failing) means "no".
pub fn item_exists(key_id: &[u8; 16]) -> bool {
    item_exists_in(SERVICE, key_id)
}

fn item_exists_in(service: &str, key_id: &[u8; 16]) -> bool {
    #[cfg(target_os = "macos")]
    {
        backend::probe(service, &account(key_id)).unwrap_or(false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, key_id);
        false
    }
}

/// `keys.keychain_state`, without ever showing a dialog.
pub fn state(key_id: &[u8; 16]) -> Result<KeychainState, KeychainError> {
    state_in(SERVICE, key_id)
}

/// [`state`] under another service name (the test seam).
pub fn state_in(service: &str, key_id: &[u8; 16]) -> Result<KeychainState, KeychainError> {
    if get_in(service, key_id)?.is_some() {
        return Ok(KeychainState::Cached);
    }
    Ok(if !disabled() && item_exists_in(service, key_id) {
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

    #[test]
    fn the_service_is_this_cores_own_and_not_pythons() {
        assert_eq!(SERVICE, "disconect");
        assert_ne!(SERVICE, "disconect-cli");
    }
}
