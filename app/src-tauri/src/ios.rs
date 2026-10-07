// SPDX-License-Identifier: AGPL-3.0-or-later
//! The iOS start-up hook (12-D, pitch items 2 and 3). It runs first in `setup`, before the core starts, so before
//! the store opens and before the page asks `key.unlock`. In this order:
//!
//! 0. a Forget that did not end (the `forget.pending` marker, `disconect_core::pair_forget`) is completed first, so
//!    nothing below sees a half-forgotten phone;
//! 1. the app data folder exists;
//! 2. leftover keychain items (a reinstall keeps them, kit gate E) are cleaned by the core's rule
//!    (`keychain_leftovers`), and the first-run marker is written;
//! 3. the data folder and each regular file in it are flagged `NSURLIsExcludedFromBackupKey` (every launch: Apple
//!    says some file operations reset the flag);
//! 4. the key file gets `NSFileProtectionComplete` (unreadable while the phone is locked). It is read at start-up,
//!    by `key.status`, by `key.unlock` (also the keychain path) and by `key.cache`, so those fail while the phone is
//!    locked (today as a `database` error, "key file is unreadable"; the phone half measures it, 12-F words it).
//!    The folder and the store keep the default class, so a sync running as the phone locks does not fail.
//!
//! A failure in any step is a note (plain words, counts and OS error text only, never an account or a key) and
//! never blocks start-up; the notes reach the core's diagnostics through `Sidecar::note`.

use std::path::Path;

use disconect_core::keychain_leftovers::{clean_leftovers_for, Decision, Keychain, RealKeychain};
use disconect_core::keys;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_foundation::{
    NSDictionary, NSFileManager, NSFileProtectionComplete, NSFileProtectionKey, NSNumber, NSString, NSURL,
    NSURLIsExcludedFromBackupKey,
};
use tauri::Manager;

/// The marker that says the leftover-items rule has run for this install.
const MARKER_FILE: &str = disconect_core::pair_forget::FIRST_RUN_MARKER;

/// Run the hook for this app's data folder; returns the notes. A release that `start_core` will refuse over a test
/// switch (`sidecar::inproc_env_refusal`) touches nothing here either: `DISCONECT_KEYS` would point the leftover rule
/// and the protection class at a file the phone does not use (12-D review S3).
pub fn prepare(app: &tauri::AppHandle) -> Vec<String> {
    if crate::sidecar::inproc_env_refusal(cfg!(debug_assertions), cfg!(desktop), |name| std::env::var_os(name)).is_some() {
        return vec!["start-up hook skipped: a test switch is set in a release".into()];
    }
    match app.path().app_data_dir() {
        Ok(dir) => prepare_in(&mut RealKeychain, &dir),
        Err(e) => vec![format!("start-up hook skipped: no app data folder ({e})")],
    }
}

/// The hook over an explicit folder and keychain (the tests pass a fake keychain).
fn prepare_in(keychain: &mut dyn Keychain, dir: &Path) -> Vec<String> {
    let mut notes = Vec::new();
    if let Err(e) = std::fs::create_dir_all(dir) {
        notes.push(format!("could not create the data folder: {e}"));
        return notes;
    }
    finish_forget(keychain, dir, &mut notes);
    leftovers(keychain, dir, &mut notes);
    exclude_all(dir, &mut notes);
    let key_path = keys::key_path_for(&dir.join(crate::PHONE_DB_FILE));
    if key_path.is_file() {
        if let Err(e) = protect_complete(&key_path) {
            notes.push(format!("could not lock the key file with the phone: {e}"));
        }
    }
    notes
}

/// The core's forget items over the leftovers rule's keychain (so one fake serves both in the tests): present or not
/// is read from the account list, so "removed" and "none" stay apart.
struct ForgetItems<'a>(&'a mut dyn Keychain);

impl disconect_core::pair_forget::Items for ForgetItems<'_> {
    fn remove(&mut self, key_id: &[u8; 16]) -> Result<bool, disconect_core::keychain::KeychainError> {
        let service = disconect_core::keychain::SERVICE;
        let account: String = key_id.iter().map(|b| format!("{b:02x}")).collect();
        if !self.0.accounts(service)?.contains(&account) {
            return Ok(false);
        }
        self.0.delete(service, &account)?;
        Ok(true)
    }
}

/// Step 0: complete a pending Forget. Notes say only what happened, never an account.
fn finish_forget(keychain: &mut dyn Keychain, dir: &Path, notes: &mut Vec<String>) {
    let db = dir.join(crate::PHONE_DB_FILE);
    let paths = disconect_core::pair_forget::Paths::beside(&db, &keys::key_path_for(&db));
    match disconect_core::pair_forget::complete_pending(&paths, &mut ForgetItems(keychain)) {
        None => {}
        Some(Ok(result)) => notes.push(format!("completed an interrupted Forget; keychain {}", result.text())),
        Some(Err(e)) => notes.push(format!("an interrupted Forget could not be completed yet: {e}")),
    }
}

fn leftovers(keychain: &mut dyn Keychain, dir: &Path, notes: &mut Vec<String>) {
    let db = dir.join(crate::PHONE_DB_FILE);
    let marker = dir.join(MARKER_FILE);
    match clean_leftovers_for(keychain, &db, &marker) {
        Ok(report) => {
            let counts: Vec<String> = report.deleted.iter().map(|(service, n)| format!("{service} {n}")).collect();
            notes.push(format!("leftover keychain items: {:?}, removed [{}]", report.decision, counts.join(", ")));
            // An unreadable key file touched nothing; leave the marker out so the rule runs again next launch.
            if report.decision != Decision::KeyFileUnreadable && !marker.exists() {
                if let Err(e) = std::fs::write(&marker, b"") {
                    notes.push(format!("could not write the first-run marker: {e}"));
                }
            }
        }
        Err(e) => notes.push(format!("could not check for leftover keychain items: {e}")),
    }
}

/// The folder, then each regular file directly in it.
fn exclude_all(dir: &Path, notes: &mut Vec<String>) {
    if let Err(e) = exclude_from_backup(dir) {
        notes.push(format!("could not exclude the data folder from backups: {e}"));
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            notes.push(format!("could not list the data folder to exclude its files from backups: {e}"));
            return;
        }
    };
    let mut failed = 0usize;
    let mut first = None;
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|t| t.is_file()) {
            if let Err(e) = exclude_from_backup(&entry.path()) {
                failed += 1;
                first.get_or_insert(e);
            }
        }
    }
    if let Some(e) = first {
        notes.push(format!("could not exclude {failed} file(s) in the data folder from backups: {e}"));
    }
}

// The three Foundation constants, read in one place (extern statics are `unsafe` to name).
fn backup_key() -> &'static NSString {
    // SAFETY: a constant string the OS defines and never changes.
    unsafe { NSURLIsExcludedFromBackupKey }
}

fn protection_key() -> &'static NSString {
    // SAFETY: as above.
    unsafe { NSFileProtectionKey }
}

fn protection_complete() -> &'static NSString {
    // SAFETY: as above.
    unsafe { NSFileProtectionComplete }
}

fn ns_path(path: &Path) -> Result<Retained<NSString>, String> {
    path.to_str().map(NSString::from_str).ok_or_else(|| "the path is not text".to_string())
}

fn file_url(path: &Path) -> Result<Retained<NSURL>, String> {
    Ok(NSURL::fileURLWithPath(&*ns_path(path)?))
}

/// `NSURLIsExcludedFromBackupKey = YES` on `path`.
fn exclude_from_backup(path: &Path) -> Result<(), String> {
    let url = file_url(path)?;
    let yes = NSNumber::new_bool(true);
    let value: &AnyObject = &yes;
    // SAFETY: the value for NSURLIsExcludedFromBackupKey is an NSNumber (BOOL), as passed.
    unsafe { url.setResourceValue_forKey_error(Some(value), backup_key()) }.map_err(|e| e.localizedDescription().to_string())
}

/// The flag as the OS reports it.
#[cfg(test)]
fn is_excluded_from_backup(path: &Path) -> Result<bool, String> {
    let url = file_url(path)?;
    let keys = objc2_foundation::NSArray::from_slice(&[backup_key()]);
    let values = url.resourceValuesForKeys_error(&keys).map_err(|e| e.localizedDescription().to_string())?;
    let value = values.objectForKey(backup_key()).ok_or("the flag is not reported")?;
    value.downcast::<NSNumber>().map(|n| n.boolValue()).map_err(|_| "the flag is not a number".to_string())
}

/// `NSFileProtectionComplete` on `path`.
fn protect_complete(path: &Path) -> Result<(), String> {
    let manager = NSFileManager::defaultManager();
    let class: &AnyObject = protection_complete();
    let attributes = NSDictionary::from_slices(&[protection_key()], &[class]);
    // SAFETY: the attribute dictionary holds the one key NSFileProtectionKey with an NSFileProtectionType string.
    unsafe { manager.setAttributes_ofItemAtPath_error(&attributes, &*ns_path(path)?) }.map_err(|e| e.localizedDescription().to_string())
}

/// The protection class the OS reports for `path`, if it reports one.
#[cfg(test)]
fn protection_of(path: &Path) -> Result<Option<String>, String> {
    let manager = NSFileManager::defaultManager();
    let attributes = manager.attributesOfItemAtPath_error(&*ns_path(path)?).map_err(|e| e.localizedDescription().to_string())?;
    Ok(attributes
        .objectForKey(protection_key())
        .and_then(|v| v.downcast::<NSString>().ok())
        .map(|s| s.to_string()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use disconect_core::keychain::KeychainError;

    /// A keychain that holds nothing and records nothing; the rule's own tests live in the core.
    struct Empty;

    impl Keychain for Empty {
        fn accounts(&mut self, _service: &str) -> Result<Vec<String>, KeychainError> {
            Ok(Vec::new())
        }
        fn delete(&mut self, _service: &str, _account: &str) -> Result<(), KeychainError> {
            Ok(())
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("disconect-ios-hook-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_backup_flag_is_set_on_a_folder_and_a_file_and_reads_back_yes() {
        let dir = scratch("flag");
        let file = dir.join("a.bin");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(is_excluded_from_backup(&file), Ok(false));
        exclude_from_backup(&dir).unwrap();
        exclude_from_backup(&file).unwrap();
        assert_eq!(is_excluded_from_backup(&dir), Ok(true));
        assert_eq!(is_excluded_from_backup(&file), Ok(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_is_an_error_text_for_the_backup_flag_not_a_panic() {
        let dir = scratch("missing");
        // (`protect_complete` on a missing path is not tested: the simulator answers success for it.)
        assert!(exclude_from_backup(&dir.join("nope")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_protection_call_succeeds_and_reads_back_when_the_simulator_reports_it() {
        let dir = scratch("protect");
        let file = dir.join("k.json");
        std::fs::write(&file, b"{}").unwrap();
        protect_complete(&file).unwrap();
        // Measured 2026-10-06 (iOS 18.1 simulator): the call succeeds and no class is reported back, so the
        // class itself is measured on the device. Where a class is reported, it must be the one set.
        if let Some(class) = protection_of(&file).unwrap() {
            assert_eq!(class, protection_complete().to_string());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_hook_makes_the_folder_writes_the_marker_flags_the_files_and_reports_in_words() {
        let dir = scratch("hook").join("support");
        let notes = prepare_in(&mut Empty, &dir);
        assert!(dir.join(MARKER_FILE).is_file(), "{notes:?}");
        assert_eq!(is_excluded_from_backup(&dir), Ok(true));
        assert_eq!(is_excluded_from_backup(&dir.join(MARKER_FILE)), Ok(true));
        assert!(notes.iter().any(|n| n.starts_with("leftover keychain items: NoKeyFile")), "{notes:?}");
        // a second launch: marker present, nothing eligible, flags re-asserted
        std::fs::write(dir.join("disconect.db"), b"x").unwrap();
        let again = prepare_in(&mut Empty, &dir);
        assert!(again.iter().any(|n| n.contains("StoreExists")), "{again:?}");
        assert_eq!(is_excluded_from_backup(&dir.join("disconect.db")), Ok(true));
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    /// A keychain with a list of `(service, account)` items.
    struct Items(Vec<(String, String)>);

    impl Keychain for Items {
        fn accounts(&mut self, service: &str) -> Result<Vec<String>, KeychainError> {
            Ok(self.0.iter().filter(|(s, _)| s == service).map(|(_, a)| a.clone()).collect())
        }
        fn delete(&mut self, service: &str, account: &str) -> Result<(), KeychainError> {
            self.0.retain(|(s, a)| !(s == service && a == account));
            Ok(())
        }
    }

    #[test]
    fn the_hook_completes_a_pending_forget_before_anything_else_and_a_marker_free_start_deletes_nothing() {
        let dir = scratch("forget");
        let db = dir.join(crate::PHONE_DB_FILE);
        let key = keys::key_path_for(&db);
        let id = "00112233445566778899aabbccddeeff";
        let seed = |with_marker: bool| {
            std::fs::write(&db, b"x").unwrap();
            std::fs::write(dir.join("disconect.db-wal"), b"x").unwrap();
            std::fs::write(&key, format!(r#"{{"format":"hearthbeat-keys","format_version":1,"key_id":"{id}","created_at":"","wraps":[{{"purpose":"passphrase"}}]}}"#)).unwrap();
            std::fs::write(dir.join("relay.json"), b"{}").unwrap();
            if with_marker {
                std::fs::write(dir.join(disconect_core::pair_forget::MARKER_NAME), b"").unwrap();
            }
        };
        let mut items = Items(vec![("disconect".into(), id.into())]);
        seed(false);
        let notes = prepare_in(&mut items, &dir);
        assert!(db.exists() && key.exists() && items.0.len() == 1, "no marker: nothing is forgotten: {notes:?}");
        seed(true);
        let notes = prepare_in(&mut items, &dir);
        assert!(!db.exists() && !key.exists() && !dir.join("relay.json").exists() && !dir.join("disconect.db-wal").exists(), "{notes:?}");
        assert!(items.0.is_empty(), "the keychain item went: {notes:?}");
        assert!(!dir.join(disconect_core::pair_forget::MARKER_NAME).exists());
        assert!(notes.iter().any(|n| n == "completed an interrupted Forget; keychain removed"), "{notes:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_key_file_leaves_no_marker_so_the_rule_runs_again() {
        let dir = scratch("badkey");
        std::fs::write(keys::key_path_for(&dir.join(crate::PHONE_DB_FILE)), b"not a key file").unwrap();
        let notes = prepare_in(&mut Empty, &dir);
        assert!(!dir.join(MARKER_FILE).exists(), "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("KeyFileUnreadable")), "{notes:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
