// SPDX-License-Identifier: AGPL-3.0-or-later
//! How `disconect-core mcp` starts (Bet 11e, slice 2): the environment it scrubs, the key it needs, the
//! private protocol stream. Unlocking happens before stdin is read: a store with a key file needs its key
//! cached in the keychain (read without a dialog) or, for the test harness only, `--passphrase-file`;
//! otherwise exit 9 with one stderr line that says why and where to fix it.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::identity;
use crate::keychain::{self, KeychainState};
use crate::keys::{self, Secret32};
use crate::mcp::{Server, serve_lines};
use crate::serve::isolate_stdout;

/// Exit code of a store that cannot be unlocked here.
pub const EXIT_LOCKED: i32 = 9;

// ---- process start ----

/// The switches that make a build a test rig: a pinned clock and a disabled keychain. A release `mcp`
/// removes them from its environment (Claude Desktop's own environment reaches it), so only a debug build
/// the harness runs honours them. Returns the names removed.
pub fn scrub_test_switches() -> Vec<&'static str> {
    let mut removed = Vec::new();
    for name in [crate::time::NOW_ENV, keychain::BACKEND_ENV] {
        if std::env::var_os(name).is_some() {
            removed.push(name);
            // SAFETY: called first thing in `main`, before any thread exists.
            unsafe { std::env::remove_var(name) };
        }
    }
    removed
}

/// How the process was started: the store and, for the test harness only, a passphrase read from a file.
pub struct Options {
    pub db: PathBuf,
    pub passphrase: Option<Zeroizing<String>>,
}

/// The master key of a store with a key file, or the stderr line that says why not. Reads the keychain
/// without a dialog.
fn unlock(db: &Path, passphrase: Option<&str>) -> Result<Option<Secret32>, String> {
    let key_path = keys::key_path_for(db);
    if !key_path.exists() {
        return Ok(None);
    }
    let key_file = keys::read_key_file(&key_path)
        .map_err(|e| format!("disconect-core mcp: the key file cannot be read: {e}"))?;
    if let Some(phrase) = passphrase {
        return keys::unlock_with_passphrase(&key_file, phrase)
            .map(Some)
            .map_err(|e| {
                format!("disconect-core mcp: the passphrase does not open this store ({e})")
            });
    }
    let cached = keychain::get(&key_file.key_id)
        .ok()
        .flatten()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .filter(|master| keys::key_id_for(master) == key_file.key_id);
    if let Some(master) = cached {
        return Ok(Some(Zeroizing::new(master)));
    }
    let state = keychain::state(&key_file.key_id).unwrap_or(KeychainState::Absent);
    Err(locked_message(state))
}

/// The sentence that sends a person to the fix: the app's key screen and its keychain switch, worded as the
/// app words them ([`identity::KEY_SCREEN`], [`identity::KEYCHAIN_SWITCH`], pinned to `app.ts` by the drift
/// test), then a restart of the client that runs this server.
pub(crate) fn fix_instruction(switch: &str) -> String {
    format!(
        "Open {}, go to the \"{}\" screen, switch \"{}\" {switch}, then restart Claude Desktop.",
        identity::PRODUCT,
        identity::KEY_SCREEN,
        identity::KEYCHAIN_SWITCH,
    )
}

/// The one stderr line of a locked start: why the key is not available and where to fix it.
fn locked_message(state: KeychainState) -> String {
    let (cause, switch) = match state {
        KeychainState::Stale => (
            "it was remembered by another build of the app, which this program may not read without a dialog",
            "off and on again",
        ),
        _ => ("it is not remembered on this Mac", "on"),
    };
    format!(
        "disconect-core mcp: this store is encrypted and its key is locked ({cause}; keychain: {}). {}",
        state.as_str(),
        fix_instruction(switch),
    )
}

/// Unlock, then serve stdio until it closes. Returns the exit code: 0 at end of input, 9 locked, 1 on
/// anything else that stops the start.
pub fn run(options: Options) -> i32 {
    let master = match unlock(&options.db, options.passphrase.as_ref().map(|p| p.as_str())) {
        Ok(master) => master,
        Err(message) => {
            let _ = writeln!(io::stderr(), "{message}");
            return EXIT_LOCKED;
        }
    };
    let mut private = match isolate_stdout() {
        Ok(stream) => stream,
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "error: cannot isolate the protocol stream: {}",
                error.kind()
            );
            return 1;
        }
    };
    let mut server = Server::new(options.db, master);
    serve_lines(&mut server, io::stdin().lock(), &mut private);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_locked_line_names_the_screen_the_switch_and_the_keychain_state() {
        for (state, word, switch) in [
            (
                KeychainState::Absent,
                "keychain: absent",
                "\"Keep the key in this device's keychain\" on,",
            ),
            (
                KeychainState::Stale,
                "keychain: stale",
                "\"Keep the key in this device's keychain\" off and on again,",
            ),
        ] {
            let line = locked_message(state);
            assert!(
                line.contains(word)
                    && line.contains("\"Your key\" screen")
                    && line.contains(switch),
                "{line}"
            );
            assert!(!line.contains('\n') && line.starts_with("disconect-core mcp: "));
        }
    }
}
