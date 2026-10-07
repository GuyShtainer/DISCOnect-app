// SPDX-License-Identifier: AGPL-3.0-or-later
//! "Forget this phone" (12-F, attack M5): delete everything this phone holds, in an order that survives a crash.
//! The logic is platform-neutral so its tests run with a fake keychain; only `serve.rs` (iOS) and the app's start-up
//! hook call it, and the desktop core answers `unsupported_transport` instead.
//!
//! The order, with the marker already written by the caller (step 1) and the import slot and write lock held (step 2):
//! 3. the store with its `-wal`, `-shm` and write-lock files;
//! 4. the keychain item, by the key id read from the key file *before* the key file goes;
//! 5. the key file;
//! 6. `relay.json`;
//! 7. (the caller drops the master from the session);
//! 8. the marker.
//!
//! A crash (or an error) at any step leaves the marker, and [`complete_pending`] at the next start-up runs the same
//! steps again; every step accepts "already gone". 12-D's rule holds at every step: the keychain item is touched only
//! after the store is confirmed gone, so an item is never removed while a store file still exists.

use std::io;
use std::path::{Path, PathBuf};

use crate::keychain::{self, KeychainError};
use crate::keys::{self, KeyError};
use crate::write_lock;

/// The marker that says a forget began and has not finished: a file beside the store.
pub const MARKER_NAME: &str = "forget.pending";
/// The app's "the leftover-items rule has run" marker (`ios.rs`). A forget that could not remove the keychain item
/// removes it, so the next start-up's rule (no store, no key file, no marker: sweep every item) retries the removal.
pub const FIRST_RUN_MARKER: &str = "first-run.done";

/// The files a forget touches, all beside the store.
#[derive(Debug, Clone)]
pub struct Paths {
    pub db: PathBuf,
    pub key: PathBuf,
    pub relay: PathBuf,
    pub marker: PathBuf,
    pub first_run: PathBuf,
}

impl Paths {
    pub fn beside(db: &Path, key: &Path) -> Paths {
        let folder = db.parent().map_or_else(PathBuf::new, Path::to_path_buf);
        Paths {
            db: db.to_path_buf(),
            key: key.to_path_buf(),
            relay: crate::home::relay_config_beside(db),
            marker: folder.join(MARKER_NAME),
            first_run: folder.join(FIRST_RUN_MARKER),
        }
    }

    fn store_files(&self) -> [PathBuf; 5] {
        [
            self.db.clone(),
            keys::sibling_with_suffix(&self.db, "-wal"),
            keys::sibling_with_suffix(&self.db, "-shm"),
            write_lock::lock_path_for(&self.db),
            keys::sibling_with_suffix(&self.db, ".write-lock.holder"),
        ]
    }
}

/// The one keychain operation a forget needs. The real one is [`RealItems`]; the tests pass a fake.
pub trait Items {
    /// Remove the master key's item for `key_id`: `Ok(true)` removed, `Ok(false)` there was none.
    fn remove(&mut self, key_id: &[u8; 16]) -> Result<bool, KeychainError>;
}

/// This app's keychain.
pub struct RealItems;

impl Items for RealItems {
    fn remove(&mut self, key_id: &[u8; 16]) -> Result<bool, KeychainError> {
        keychain::delete(key_id)
    }
}

/// What step 4 came to. The text is fixed: it never carries an OS status, an account or a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainResult {
    Removed,
    None,
    Failed(&'static str),
}

impl KeychainResult {
    pub fn text(self) -> String {
        match self {
            KeychainResult::Removed => "removed".into(),
            KeychainResult::None => "none".into(),
            KeychainResult::Failed(why) => format!("failed: {why}"),
        }
    }
}

/// The points after which a test may stop the run (a simulated crash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Store,
    Keychain,
    KeyFile,
    Relay,
}

/// Step 1: the marker. Written and flushed before anything is deleted.
pub fn write_marker(paths: &Paths) -> io::Result<()> {
    if let Some(folder) = paths.marker.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(folder)?;
    }
    let file = std::fs::File::create(&paths.marker)?;
    file.sync_all()
}

/// Take the marker away again (the forget was refused before it deleted anything).
pub fn clear_marker(paths: &Paths) {
    let _ = std::fs::remove_file(&paths.marker);
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn keychain_step(paths: &Paths, items: &mut dyn Items) -> KeychainResult {
    let key_id = match keys::read_key_file(&paths.key) {
        Ok(file) => file.key_id,
        // no key file: either none was ever made, or a crash took it after step 4 had already run
        Err(KeyError::KeyFileMissing(_)) => return KeychainResult::None,
        Err(_) => return KeychainResult::Failed("the key file could not be read"),
    };
    match items.remove(&key_id) {
        Ok(true) => KeychainResult::Removed,
        Ok(false) => KeychainResult::None,
        Err(KeychainError::NoBackend) => KeychainResult::Failed("no keychain is available"),
        Err(_) => KeychainResult::Failed("the keychain did not remove the item"),
    }
}

/// Steps 3 to 6 and 8, from a marker already on disk. `stop_after` returns true to end the run there with an error
/// (tests only; production passes `|_| false`). On any error the marker stays, so the next start-up finishes the job.
pub fn run(paths: &Paths, items: &mut dyn Items, stop_after: &mut dyn FnMut(Step) -> bool) -> io::Result<KeychainResult> {
    let interrupted = || io::Error::other("interrupted");
    // 3. the store
    for file in paths.store_files() {
        remove_if_present(&file)?;
    }
    if stop_after(Step::Store) {
        return Err(interrupted());
    }
    // 12-D: the keychain is touched only with the store confirmed gone
    if paths.db.exists() {
        return Err(io::Error::other("the store is still there"));
    }
    // 4. the keychain item, by the id the key file still gives
    let result = keychain_step(paths, items);
    if stop_after(Step::Keychain) {
        return Err(interrupted());
    }
    // 5. the key file
    remove_if_present(&paths.key)?;
    if stop_after(Step::KeyFile) {
        return Err(interrupted());
    }
    // 6. relay.json
    remove_if_present(&paths.relay)?;
    if stop_after(Step::Relay) {
        return Err(interrupted());
    }
    // an item that stayed: let the start-up rule sweep it (no store, no key file, no first-run marker)
    if matches!(result, KeychainResult::Failed(_)) {
        remove_if_present(&paths.first_run)?;
    }
    // 8. the marker
    remove_if_present(&paths.marker)?;
    Ok(result)
}

/// The start-up hook: finish a forget that did not end. `None` when no marker was found (nothing is touched).
pub fn complete_pending(paths: &Paths, items: &mut dyn Items) -> Option<io::Result<KeychainResult>> {
    paths.marker.exists().then(|| run(paths, items, &mut |_| false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        present: bool,
        fail: bool,
        calls: usize,
        store_seen: Vec<bool>,
        db: PathBuf,
    }

    impl Items for Fake {
        fn remove(&mut self, _key_id: &[u8; 16]) -> Result<bool, KeychainError> {
            self.calls += 1;
            self.store_seen.push(self.db.exists());
            if self.fail {
                return Err(KeychainError::Backend("secret detail".into()));
            }
            Ok(std::mem::take(&mut self.present))
        }
    }

    const KEY_FILE: &str = r#"{"format":"hearthbeat-keys","format_version":1,"key_id":"00112233445566778899aabbccddeeff","created_at":"2026-10-07T00:00:00Z","wraps":[{"purpose":"passphrase"}]}"#;

    fn seed(name: &str) -> (PathBuf, Paths) {
        let dir = std::env::temp_dir().join(format!("disconect-forget-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("disconect.db");
        let paths = Paths::beside(&db, &keys::sibling_with_suffix(&db, keys::KEY_FILE_SUFFIX));
        for file in paths.store_files() {
            std::fs::write(file, b"x").unwrap();
        }
        std::fs::write(&paths.key, KEY_FILE).unwrap();
        std::fs::write(&paths.relay, b"{}").unwrap();
        std::fs::write(&paths.first_run, b"").unwrap();
        (dir, paths)
    }

    fn fake(paths: &Paths, present: bool) -> Fake {
        Fake { present, db: paths.db.clone(), ..Fake::default() }
    }

    fn gone(paths: &Paths) -> bool {
        paths.store_files().iter().all(|f| !f.exists()) && !paths.key.exists() && !paths.relay.exists() && !paths.marker.exists()
    }

    #[test]
    fn the_key_file_in_the_tests_is_readable() {
        let (dir, paths) = seed("readable");
        assert!(keys::read_key_file(&paths.key).is_ok(), "the fixture key file must parse");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_whole_run_deletes_everything_in_order_and_clears_the_marker() {
        let (dir, paths) = seed("whole");
        write_marker(&paths).unwrap();
        let mut items = fake(&paths, true);
        let result = run(&paths, &mut items, &mut |_| false).unwrap();
        assert_eq!(result, KeychainResult::Removed);
        assert!(gone(&paths));
        assert!(paths.first_run.exists(), "a clean forget leaves the first-run marker");
        assert_eq!(items.store_seen, vec![false], "the item is touched only after the store is gone");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn no_item_reads_as_none_and_a_failure_is_fixed_text_and_re_arms_the_sweep() {
        let (dir, paths) = seed("none");
        write_marker(&paths).unwrap();
        assert_eq!(run(&paths, &mut fake(&paths, false), &mut |_| false).unwrap(), KeychainResult::None);
        let (dir2, paths2) = seed("failed");
        write_marker(&paths2).unwrap();
        let mut bad = fake(&paths2, true);
        bad.fail = true;
        let result = run(&paths2, &mut bad, &mut |_| false).unwrap();
        assert_eq!(result.text(), "failed: the keychain did not remove the item");
        assert!(!result.text().contains("secret"));
        assert!(gone(&paths2));
        assert!(!paths2.first_run.exists(), "the start-up sweep is re-armed so the item is retried");
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    }

    #[test]
    fn a_crash_after_each_step_is_finished_by_the_next_start_up() {
        for stop in [Step::Store, Step::Keychain, Step::KeyFile, Step::Relay] {
            let (dir, paths) = seed(&format!("crash-{stop:?}"));
            write_marker(&paths).unwrap();
            let mut items = fake(&paths, true);
            let first = run(&paths, &mut items, &mut |s| s == stop);
            assert!(first.is_err(), "{stop:?} stops the run");
            assert!(paths.marker.exists(), "{stop:?}: the marker stays");
            let finished = complete_pending(&paths, &mut items).expect("a marker was found").expect("the second run ends");
            assert!(gone(&paths), "{stop:?}: everything is gone after the next start-up");
            assert!(matches!(finished, KeychainResult::Removed | KeychainResult::None), "{stop:?}: {finished:?}");
            assert!(!items.present, "{stop:?}: the item is gone");
            assert!(items.store_seen.iter().all(|seen| !seen), "{stop:?}: never touched while a store file existed");
            assert!(complete_pending(&paths, &mut items).is_none(), "{stop:?}: no marker, nothing happens");
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_marker_left_with_a_half_deleted_store_is_finished() {
        let (dir, paths) = seed("half");
        write_marker(&paths).unwrap();
        std::fs::remove_file(&paths.db).unwrap(); // the store went, its -wal and the rest did not
        let mut items = fake(&paths, true);
        assert!(complete_pending(&paths, &mut items).unwrap().is_ok());
        assert!(gone(&paths) && !items.present);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn without_a_marker_nothing_is_deleted() {
        let (dir, paths) = seed("nomarker");
        let mut items = fake(&paths, true);
        assert!(complete_pending(&paths, &mut items).is_none());
        assert!(paths.db.exists() && paths.key.exists() && items.calls == 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_store_that_cannot_be_deleted_stops_before_the_keychain() {
        let (dir, paths) = seed("stuck");
        write_marker(&paths).unwrap();
        std::fs::remove_file(&paths.db).unwrap();
        std::fs::create_dir(&paths.db).unwrap(); // remove_file on a directory fails
        std::fs::write(paths.db.join("inner"), b"x").unwrap();
        let mut items = fake(&paths, true);
        assert!(run(&paths, &mut items, &mut |_| false).is_err());
        assert_eq!(items.calls, 0, "the item stays while the store does");
        assert!(paths.marker.exists() && paths.key.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_crash_after_the_key_file_still_removes_a_failed_keychain_marker_state() {
        // the key file is already gone at the second run: the id is unknown, the result reads `none`
        let (dir, paths) = seed("nokey");
        write_marker(&paths).unwrap();
        std::fs::remove_file(&paths.key).unwrap();
        let mut items = fake(&paths, true);
        assert_eq!(complete_pending(&paths, &mut items).unwrap().unwrap(), KeychainResult::None);
        assert!(gone(&paths));
        let _ = std::fs::remove_dir_all(dir);
    }
}
