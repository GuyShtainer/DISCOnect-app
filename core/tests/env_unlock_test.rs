// SPDX-License-Identifier: AGPL-3.0-or-later
//! Alone in its own test binary: it edits the process environment.
mod common;

use common::{PASSPHRASE, encrypted_copy};
use disconect_core::keys::PASSPHRASE_ENV;
use disconect_core::keys::PassphraseSource;
use disconect_core::store;

#[test]
fn env_passphrase_opens_fixture_read_only_and_is_removed() {
    let (_dir, db) = encrypted_copy();
    // SAFETY: the only test in this binary; no other thread touches the environment.
    unsafe { std::env::set_var(PASSPHRASE_ENV, PASSPHRASE) };
    let ro = store::open_read_only(&db, PassphraseSource::Env).unwrap();
    assert_eq!(ro.user_version().unwrap(), 3);
    assert!(std::env::var(PASSPHRASE_ENV).is_err(), "env var removed after reading");
    let cipher = ro.cipher_version();
    println!("cipher_version = {}", cipher.as_deref().unwrap_or("none"));
    assert!(cipher.is_some());
}
