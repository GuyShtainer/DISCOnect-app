// SPDX-License-Identifier: AGPL-3.0-or-later
//! The real macOS keychain, once, on a scratch service and a random account: enable -> `cached`,
//! an item made by another program -> `stale` without blocking, enabling over it, disable -> `absent`.
//!
//! `cargo test --test keychain_real_test -- --ignored`. It creates and deletes only its own
//! items (service `disconect-test-<pid>-<nanos>`), never `disconect` or `hearthbeat`. Ignored by
//! default because it needs a login keychain; the whole point is that none of the calls may stop
//! at a dialog, so on an unlocked desktop a hang here is the finding.
#![cfg(target_os = "macos")]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use disconect_core::keychain::{self, KeychainState};

const MASTER: [u8; 32] = [7; 32];
/// A status call may take as long as a keychain search; a dialog would take as long as a person.
const QUIET: Duration = Duration::from_secs(5);

struct Scratch {
    service: String,
    key_id: [u8; 16],
}

impl Scratch {
    fn new() -> Scratch {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&nanos.to_le_bytes());
        Scratch {
            service: format!("disconect-test-{}-{nanos}", std::process::id()),
            key_id,
        }
    }

    fn account(&self) -> String {
        hex::encode(self.key_id)
    }

    /// The item as `/usr/bin/security` would leave it: another program's, unreadable to this one.
    fn make_foreign(&self) {
        let made = Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-s",
                &self.service,
                "-a",
                &self.account(),
                "-w",
            ])
            .arg(hex::encode(MASTER))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        assert!(
            made.is_ok_and(|s| s.success()),
            "security add-generic-password failed"
        );
    }

    fn timed_state(&self) -> (KeychainState, Duration) {
        let started = Instant::now();
        let state = keychain::state_in(&self.service, &self.key_id).expect("state");
        (state, started.elapsed())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = keychain::delete_in(&self.service, &self.key_id);
        let _ = Command::new("/usr/bin/security")
            .args([
                "delete-generic-password",
                "-s",
                &self.service,
                "-a",
                &self.account(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[test]
#[ignore = "touches the real login keychain (scratch service only)"]
fn enable_foreign_and_disable_on_the_real_keychain() {
    let item = Scratch::new();

    assert_eq!(item.timed_state().0, KeychainState::Absent);

    // enable -> cached, and the secret reads back
    keychain::set_in(&item.service, &item.key_id, &MASTER).expect("enable");
    let (state, took) = item.timed_state();
    assert_eq!(state, KeychainState::Cached);
    assert!(took < QUIET, "a status call took {took:?}");
    let back = keychain::get_in(&item.service, &item.key_id).expect("get");
    assert_eq!(back.as_deref().map(Vec::as_slice), Some(MASTER.as_slice()));

    // an item another program made: stale, quickly, and its secret is not handed over
    assert!(keychain::delete_in(&item.service, &item.key_id).expect("delete own"));
    assert_eq!(item.timed_state().0, KeychainState::Absent);
    item.make_foreign();
    let (state, took) = item.timed_state();
    assert_eq!(
        state,
        KeychainState::Stale,
        "a foreign item must read as stale"
    );
    assert!(
        took < QUIET,
        "a foreign item blocked a status call for {took:?}"
    );
    let started = Instant::now();
    assert!(
        keychain::get_in(&item.service, &item.key_id)
            .expect("get")
            .is_none()
    );
    assert!(started.elapsed() < QUIET);

    // the explicit switch replaces it with one of ours
    keychain::set_in(&item.service, &item.key_id, &MASTER).expect("enable over a foreign item");
    assert_eq!(item.timed_state().0, KeychainState::Cached);

    // disable -> absent; a second disable finds nothing
    assert!(keychain::delete_in(&item.service, &item.key_id).expect("disable"));
    assert_eq!(item.timed_state().0, KeychainState::Absent);
    assert!(!keychain::delete_in(&item.service, &item.key_id).expect("disable again"));
}
