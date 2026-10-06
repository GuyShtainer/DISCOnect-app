// SPDX-License-Identifier: AGPL-3.0-or-later
//! iOS only: the leftover-keychain-items rule. An uninstall deletes the app's files but keeps its
//! keychain items (kit gate E, kb/06), so a reinstall can find items whose store is gone. This
//! module decides, once at start, which of them to remove. It never writes a file (the marker is
//! the app's job) and never puts an account value in a report or a message.
//!
//! The rule, in this order:
//! 1. a store file exists: delete nothing, whatever the marker says;
//! 2. the marker exists: delete nothing;
//! 3. no key file: delete every item under both services;
//! 4. a key file is present: delete only the items whose account is not the key file's key id.

use std::path::Path;

use crate::keychain::{self, KeychainError};
use crate::keys;

/// The services this app stores items under: the master key and the coach's key.
pub const SERVICES: [&str; 2] = ["disconect", "disconect-coach"];

/// The three keychain operations the rule needs; the real backend and the test fake implement it.
pub trait Keychain {
    /// Every account stored under `service`.
    fn accounts(&mut self, service: &str) -> Result<Vec<String>, KeychainError>;
    /// Remove one item; an item that is already gone counts as success.
    fn delete(&mut self, service: &str, account: &str) -> Result<(), KeychainError>;
}

/// The real keychain of this app.
pub struct RealKeychain;

impl Keychain for RealKeychain {
    fn accounts(&mut self, service: &str) -> Result<Vec<String>, KeychainError> {
        keychain::list_accounts(service)
    }

    fn delete(&mut self, service: &str, account: &str) -> Result<(), KeychainError> {
        keychain::delete_account(service, account).map(|_| ())
    }
}

/// Why the rule did what it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// A store file exists.
    StoreExists,
    /// The marker exists.
    MarkerExists,
    /// No store, no marker, no key file: everything went.
    NoKeyFile,
    /// No store, no marker, a key file: everything but its own key id's item went.
    KeyFilePresent,
    /// A key file exists but cannot be read: nothing was touched (fail closed).
    KeyFileUnreadable,
}

/// What a run did: counts only, never an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub decision: Decision,
    /// `(service, items deleted)` per service, in [`SERVICES`] order; empty when nothing was eligible.
    pub deleted: Vec<(&'static str, usize)>,
}

impl Report {
    pub fn total(&self) -> usize {
        self.deleted.iter().map(|(_, n)| n).sum()
    }
}

/// Apply the rule to `keychain`. Pure apart from the keychain calls.
pub fn clean_leftovers(
    keychain: &mut dyn Keychain,
    store_exists: bool,
    marker_exists: bool,
    key_file_key_id: Option<[u8; 16]>,
) -> Result<Report, KeychainError> {
    let nothing = |decision| Report { decision, deleted: Vec::new() };
    if store_exists {
        return Ok(nothing(Decision::StoreExists));
    }
    if marker_exists {
        return Ok(nothing(Decision::MarkerExists));
    }
    let keep = key_file_key_id.map(hex::encode);
    let mut deleted = Vec::new();
    for service in SERVICES {
        let mut count = 0;
        for account in keychain.accounts(service)? {
            if keep.as_deref() == Some(account.as_str()) {
                continue;
            }
            keychain.delete(service, &account)?;
            count += 1;
        }
        deleted.push((service, count));
    }
    let decision = if keep.is_some() { Decision::KeyFilePresent } else { Decision::NoKeyFile };
    Ok(Report { decision, deleted })
}

/// The rule from paths: the store at `db_path`, its key file by [`keys::key_path_for`], and the
/// marker at `marker_path` (the app writes it). A key file that exists but cannot be read stops the
/// run with nothing deleted.
pub fn clean_leftovers_for(
    keychain: &mut dyn Keychain,
    db_path: &Path,
    marker_path: &Path,
) -> Result<Report, KeychainError> {
    let key_path = keys::key_path_for(db_path);
    let key_id = match keys::read_key_file(&key_path) {
        Ok(file) => Some(file.key_id),
        Err(keys::KeyError::KeyFileMissing(_)) => None,
        Err(_) => {
            return Ok(Report { decision: Decision::KeyFileUnreadable, deleted: Vec::new() });
        }
    };
    clean_leftovers(keychain, db_path.exists(), marker_path.exists(), key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory keychain: `(service, account)` pairs. Never touches the real one.
    #[derive(Default)]
    struct Fake {
        items: Vec<(String, String)>,
    }

    impl Fake {
        fn with(items: &[(&str, &str)]) -> Fake {
            Fake {
                items: items.iter().map(|(s, a)| (s.to_string(), a.to_string())).collect(),
            }
        }
        fn left(&self) -> Vec<(&str, &str)> {
            self.items.iter().map(|(s, a)| (s.as_str(), a.as_str())).collect()
        }
    }

    impl Keychain for Fake {
        fn accounts(&mut self, service: &str) -> Result<Vec<String>, KeychainError> {
            Ok(self.items.iter().filter(|(s, _)| s == service).map(|(_, a)| a.clone()).collect())
        }
        fn delete(&mut self, service: &str, account: &str) -> Result<(), KeychainError> {
            self.items.retain(|(s, a)| !(s == service && a == account));
            Ok(())
        }
    }

    const ID: [u8; 16] = [0xab; 16];

    fn three() -> Fake {
        Fake::with(&[
            ("disconect", "aa"),
            ("disconect", &hex::encode(ID)),
            ("disconect-coach", "bb"),
        ])
    }

    #[test]
    fn a_store_file_stops_everything_whatever_the_marker_says() {
        for marker in [false, true] {
            for key in [None, Some(ID)] {
                let mut kc = three();
                let report = clean_leftovers(&mut kc, true, marker, key).unwrap();
                assert_eq!(report.decision, Decision::StoreExists);
                assert_eq!(kc.items.len(), 3);
            }
        }
    }

    #[test]
    fn store_exists_and_no_marker_deletes_nothing() {
        let mut kc = three();
        let report = clean_leftovers(&mut kc, true, false, None).unwrap();
        assert_eq!(report.total(), 0);
        assert_eq!(kc.items.len(), 3);
    }

    #[test]
    fn a_marker_without_a_store_deletes_nothing() {
        let mut kc = three();
        let report = clean_leftovers(&mut kc, false, true, None).unwrap();
        assert_eq!(report.decision, Decision::MarkerExists);
        assert_eq!(kc.items.len(), 3);
    }

    #[test]
    fn no_store_no_marker_no_key_file_deletes_every_item_under_both_services() {
        let mut kc = three();
        let report = clean_leftovers(&mut kc, false, false, None).unwrap();
        assert_eq!(report.decision, Decision::NoKeyFile);
        assert_eq!(report.deleted, vec![("disconect", 2), ("disconect-coach", 1)]);
        assert!(kc.items.is_empty());
    }

    #[test]
    fn a_key_file_spares_its_own_key_ids_item_only() {
        let mut kc = three();
        kc.items.push(("disconect-coach".into(), hex::encode(ID)));
        let report = clean_leftovers(&mut kc, false, false, Some(ID)).unwrap();
        assert_eq!(report.decision, Decision::KeyFilePresent);
        assert_eq!(report.deleted, vec![("disconect", 1), ("disconect-coach", 1)]);
        let id = hex::encode(ID);
        assert_eq!(kc.left(), vec![("disconect", id.as_str()), ("disconect-coach", id.as_str())]);
    }

    #[test]
    fn items_under_other_services_are_never_touched() {
        let mut kc = Fake::with(&[("someone-else", "aa"), ("disconect", "bb")]);
        clean_leftovers(&mut kc, false, false, None).unwrap();
        assert_eq!(kc.left(), vec![("someone-else", "aa")]);
    }

    #[test]
    fn from_paths_a_missing_key_file_means_none_and_a_store_stops_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("s.hbdb");
        let marker = dir.path().join("marker");
        let mut kc = three();
        let report = clean_leftovers_for(&mut kc, &db, &marker).unwrap();
        assert_eq!(report.decision, Decision::NoKeyFile);
        let mut kc = three();
        std::fs::write(&db, b"x").unwrap();
        let report = clean_leftovers_for(&mut kc, &db, &marker).unwrap();
        assert_eq!(report.decision, Decision::StoreExists);
        assert_eq!(kc.items.len(), 3);
    }

    #[test]
    fn from_paths_an_unreadable_key_file_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("s.hbdb");
        std::fs::write(keys::key_path_for(&db), b"not json").unwrap();
        let mut kc = three();
        let report = clean_leftovers_for(&mut kc, &db, &dir.path().join("m")).unwrap();
        assert_eq!(report.decision, Decision::KeyFileUnreadable);
        assert_eq!(kc.items.len(), 3);
    }
}
