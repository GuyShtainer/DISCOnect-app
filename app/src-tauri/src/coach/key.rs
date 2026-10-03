// SPDX-License-Identifier: AGPL-3.0-or-later
//! The coach's provider key (the user's own API key). Two homes, neither of them a file:
//!
//! * the **OS keychain** (macOS), a generic password under the service `disconect-coach`
//!   (`identity::COACH_KEYCHAIN_SERVICE`) with a fixed account, written through `disconect_core::keychain` so
//!   it follows the rules the 11d matrix measured (kb/23 class 5): quiet read (never a dialog), and
//!   delete-then-add on write, never update. The item is made by *this* app, so after a rebuild an ad-hoc
//!   signed app finds the previous build's item foreign: it reads as [`KeyState::Stale`] and is treated as
//!   "no key" (fail closed: the person enters the key again);
//! * a **session-only** key in [`KeyHolder`] (managed Tauri state): kept in memory, never written anywhere,
//!   gone when the app quits.
//!
//! The key is a [`Zeroizing`] string from the moment it crosses the command boundary; its `Debug` output is
//! always `<redacted>`; it is in no error, no log (there are none) and no settings file. Off macOS there is
//! no keychain: `store`/`load`/`forget` answer [`KeyError::NoKeychain`] and only the session key works.

use std::fmt;
use std::sync::Mutex;

use disconect_core::identity::COACH_KEYCHAIN_SERVICE;
use disconect_core::keychain::{self, KeychainError, KeychainState};
use serde::Serialize;
use zeroize::Zeroizing;

/// The keychain account of the one provider key: the first 16 bytes of SHA-256 over the ASCII
/// `disconect/coach/v1` (a test recomputes it). One item, not one per provider: switching provider replaces it.
pub const ACCOUNT_ID: [u8; 16] = [0x6a, 0x98, 0xd3, 0x36, 0x4f, 0x17, 0x25, 0xff, 0x49, 0xc3, 0xee, 0x66, 0x56, 0x44, 0xfb, 0xe6];
/// What the account id is derived from.
pub const ACCOUNT_SEED: &str = "disconect/coach/v1";
/// A key longer than this is not an API key.
const MAX_KEY_LEN: usize = 4096;

/// Where the key is, as the UI needs to say it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// No key anywhere.
    Absent,
    /// In the keychain and readable without a dialog.
    Cached,
    /// An item exists that this build cannot read without a dialog: enter the key again.
    Stale,
    /// In memory only, for this run.
    SessionOnly,
}

/// Why a key operation failed. Closed; fixed messages; never the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// This platform (or this run) has no keychain; the session-only key still works.
    NoKeychain,
    /// The key is empty or holds anything but visible ASCII.
    Empty,
    /// The key is longer than any API key.
    TooLong,
    /// The keychain refused or failed.
    Refused,
    /// The keychain item is not text this app wrote.
    Corrupt,
    /// The session holder's lock was poisoned.
    Busy,
}

impl KeyError {
    pub fn message(&self) -> &'static str {
        match self {
            KeyError::NoKeychain => "there is no keychain on this device; the key can be kept for this session only",
            KeyError::Empty => "the key is empty or has characters a provider key does not (spaces, control or non-ASCII)",
            KeyError::TooLong => "the key is longer than any provider key",
            KeyError::Refused => "the keychain refused the request",
            KeyError::Corrupt => "the keychain item is not a key this app stored",
            KeyError::Busy => "the key holder is busy; try again",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            KeyError::NoKeychain => "no_keychain",
            KeyError::Empty => "key_empty",
            KeyError::TooLong => "key_too_long",
            KeyError::Refused => "keychain_refused",
            KeyError::Corrupt => "keychain_corrupt",
            KeyError::Busy => "key_busy",
        }
    }
}

fn from_keychain(error: KeychainError) -> KeyError {
    match error {
        KeychainError::NoBackend => KeyError::NoKeychain,
        KeychainError::Backend(_) => KeyError::Refused,
        KeychainError::NotHex => KeyError::Corrupt,
    }
}

/// A key is one visible ASCII token (a header value): non-empty, no spaces or control characters, bounded.
pub fn check(key: &str) -> Result<(), KeyError> {
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(KeyError::Empty);
    }
    if key.len() > MAX_KEY_LEN {
        return Err(KeyError::TooLong);
    }
    Ok(())
}

// ---- the keychain half (with a seam for the real-keychain test) ----------------------------------

fn store_in(service: &str, id: &[u8; 16], key: &Zeroizing<String>) -> Result<(), KeyError> {
    check(key)?;
    // delete-then-add is inside `set_in` (kb/23 class 5)
    keychain::set_in(service, id, key.as_bytes()).map_err(from_keychain)
}

fn load_in(service: &str, id: &[u8; 16]) -> Result<Option<Zeroizing<String>>, KeyError> {
    let Some(bytes) = keychain::get_in(service, id).map_err(from_keychain)? else {
        return Ok(None); // absent, stale or locked: all "no key" here; `state` tells them apart
    };
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| KeyError::Corrupt)?;
    Ok(Some(Zeroizing::new(text)))
}

fn forget_in(service: &str, id: &[u8; 16]) -> Result<bool, KeyError> {
    keychain::delete_in(service, id).map_err(from_keychain)
}

fn state_in(service: &str, id: &[u8; 16]) -> KeyState {
    match keychain::state_in(service, id) {
        Ok(KeychainState::Cached) => KeyState::Cached,
        Ok(KeychainState::Stale) => KeyState::Stale,
        Ok(KeychainState::Absent) | Err(_) => KeyState::Absent,
    }
}

/// Keep `key` in the keychain (replacing any item: delete-then-add). May show one keychain dialog.
pub fn store(key: Zeroizing<String>) -> Result<(), KeyError> {
    store_in(COACH_KEYCHAIN_SERVICE, &ACCOUNT_ID, &key)
}

/// The keychain key if it can be read without a dialog; a stale or foreign item is `Ok(None)`.
pub fn load() -> Result<Option<Zeroizing<String>>, KeyError> {
    load_in(COACH_KEYCHAIN_SERVICE, &ACCOUNT_ID)
}

/// Remove the keychain item; `Ok(false)` when there was none.
pub fn forget() -> Result<bool, KeyError> {
    forget_in(COACH_KEYCHAIN_SERVICE, &ACCOUNT_ID)
}

/// The keychain's side of [`KeyState`] (never `SessionOnly`: see [`KeyHolder::state`]). Never a dialog.
pub fn state() -> KeyState {
    state_in(COACH_KEYCHAIN_SERVICE, &ACCOUNT_ID)
}

// ---- the session half ----------------------------------------------------------------------------

/// A key that lives in memory only. `Debug` never shows the text.
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(key: Zeroizing<String>) -> Secret {
        Secret(key)
    }

    /// A copy for one request (zeroised when dropped).
    pub fn reveal(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.as_str().to_string())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Managed Tauri state: the session-only key.
#[derive(Default)]
pub struct KeyHolder {
    session: Mutex<Option<Secret>>,
}

impl fmt::Debug for KeyHolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyHolder(<redacted>)")
    }
}

impl KeyHolder {
    /// Keep `key` for this run only (replacing any earlier session key).
    pub fn set(&self, key: Zeroizing<String>) -> Result<(), KeyError> {
        check(&key)?;
        let mut slot = self.session.lock().map_err(|_| KeyError::Busy)?;
        *slot = Some(Secret::new(key));
        Ok(())
    }

    pub fn clear(&self) -> Result<(), KeyError> {
        let mut slot = self.session.lock().map_err(|_| KeyError::Busy)?;
        *slot = None;
        Ok(())
    }

    pub fn has_session_key(&self) -> bool {
        self.session.lock().map(|slot| slot.is_some()).unwrap_or(false)
    }

    /// Where the key is: the session key wins, then the keychain (quiet).
    pub fn state(&self) -> KeyState {
        if self.has_session_key() {
            KeyState::SessionOnly
        } else {
            state()
        }
    }

    /// The key a request should carry: the session key, else the keychain's. `None` is "no usable key".
    pub fn resolve(&self) -> Option<Zeroizing<String>> {
        if let Some(secret) = self.session.lock().ok().and_then(|slot| slot.as_ref().map(Secret::reveal)) {
            return Some(secret);
        }
        load().ok().flatten()
    }

    /// Forget the key everywhere: the session copy and the keychain item. Both are attempted; the first
    /// keychain failure (if any) is returned after the session copy is gone.
    pub fn forget(&self) -> Result<(), KeyError> {
        let session = self.clear();
        match forget() {
            Ok(_) | Err(KeyError::NoKeychain) => session,
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn the_account_id_is_the_hash_of_its_seed() {
        let digest = Sha256::digest(ACCOUNT_SEED.as_bytes());
        assert_eq!(&digest[..16], &ACCOUNT_ID[..]);
    }

    #[test]
    fn the_service_is_the_coachs_own() {
        use disconect_core::identity::{CLI_KEYCHAIN_SERVICE, KEYCHAIN_SERVICE};
        assert_eq!(COACH_KEYCHAIN_SERVICE, "disconect-coach");
        assert_ne!(COACH_KEYCHAIN_SERVICE, KEYCHAIN_SERVICE);
        assert_ne!(COACH_KEYCHAIN_SERVICE, CLI_KEYCHAIN_SERVICE);
    }

    #[test]
    fn debug_output_never_shows_the_key() {
        let holder = KeyHolder::default();
        holder.set(Zeroizing::new("sk-test-0123456789".into())).unwrap();
        let secret = Secret::new(Zeroizing::new("sk-test-0123456789".into()));
        for shown in [format!("{secret:?}"), format!("{holder:?}")] {
            assert!(!shown.contains("sk-test") && shown.contains("redacted"), "{shown}");
        }
    }

    #[test]
    fn error_messages_are_fixed_and_key_free() {
        for e in [KeyError::NoKeychain, KeyError::Empty, KeyError::TooLong, KeyError::Refused, KeyError::Corrupt, KeyError::Busy] {
            assert!(!e.message().is_empty() && !e.code().is_empty());
        }
        assert_eq!(check(""), Err(KeyError::Empty));
        assert_eq!(check("sk test"), Err(KeyError::Empty));
        assert_eq!(check("sk-test\n"), Err(KeyError::Empty));
        assert_eq!(check("sk-tést"), Err(KeyError::Empty));
        assert_eq!(check(&"k".repeat(MAX_KEY_LEN + 1)), Err(KeyError::TooLong));
        assert!(check("sk-test-0123456789").is_ok());
    }

    #[test]
    fn the_session_key_is_held_resolved_and_cleared_without_touching_the_keychain() {
        let holder = KeyHolder::default();
        assert!(!holder.has_session_key());
        holder.set(Zeroizing::new("sk-test-0123456789".into())).unwrap();
        assert!(holder.has_session_key());
        assert_eq!(holder.state(), KeyState::SessionOnly);
        assert_eq!(holder.resolve().as_deref().map(String::as_str), Some("sk-test-0123456789"));
        holder.clear().unwrap();
        assert!(!holder.has_session_key());
        assert_eq!(holder.set(Zeroizing::new(String::new())), Err(KeyError::Empty));
    }

    #[test]
    fn the_state_names_are_the_uis() {
        assert_eq!(serde_json::to_string(&KeyState::SessionOnly).unwrap(), "\"session_only\"");
        assert_eq!(serde_json::to_string(&KeyState::Stale).unwrap(), "\"stale\"");
    }

    /// The one test that touches the real OS keychain: service `disconect-coach`, a TEST account (never the
    /// production one), removed at the end. Run on purpose: `cargo test -- --ignored coach_key`.
    #[test]
    #[ignore = "touches the real macOS keychain (a scratch item under the coach's service)"]
    fn coach_key_keychain_round_trip_under_a_test_account() {
        const TEST_ACCOUNT: [u8; 16] = *b"coach-key-test-1";
        assert_ne!(TEST_ACCOUNT, ACCOUNT_ID);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let service = COACH_KEYCHAIN_SERVICE;
            let key = Zeroizing::new("sk-test-keychain-0123456789".to_string());
            let mut rows: Vec<String> = Vec::new();
            let _ = forget_in(service, &TEST_ACCOUNT); // a clean start
            rows.push(format!("state before: {:?}", state_in(service, &TEST_ACCOUNT)));
            let stored = store_in(service, &TEST_ACCOUNT, &key);
            rows.push(format!("store: {stored:?}"));
            let loaded = load_in(service, &TEST_ACCOUNT);
            rows.push(format!("load matches: {}", loaded.as_ref().ok().and_then(Option::as_ref).map(|k| k.as_str() == key.as_str()) == Some(true)));
            rows.push(format!("state after store: {:?}", state_in(service, &TEST_ACCOUNT)));
            let replaced = store_in(service, &TEST_ACCOUNT, &Zeroizing::new("sk-test-replaced".to_string()));
            let again = load_in(service, &TEST_ACCOUNT).ok().flatten();
            rows.push(format!("replace: {replaced:?}, reads back replaced: {}", again.as_ref().map(|k| k.as_str() == "sk-test-replaced") == Some(true)));
            let forgotten = forget_in(service, &TEST_ACCOUNT);
            rows.push(format!("forget: {forgotten:?}"));
            rows.push(format!("state after forget: {:?}", state_in(service, &TEST_ACCOUNT)));
            rows.push(format!("forget again: {:?}", forget_in(service, &TEST_ACCOUNT)));
            let _ = tx.send((rows, stored, loaded.map(|k| k.map(|k| k.as_str() == key.as_str())), forgotten));
        });
        let (rows, stored, loaded, forgotten) = rx.recv_timeout(std::time::Duration::from_secs(20)).expect("the keychain did not answer in 20 s (a dialog?)");
        for row in &rows {
            println!("{row}");
        }
        assert_eq!(stored, Ok(()));
        assert_eq!(loaded, Ok(Some(true)));
        assert_eq!(forgotten, Ok(true));
    }
}
