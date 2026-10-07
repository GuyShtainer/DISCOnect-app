// SPDX-License-Identifier: AGPL-3.0-or-later
mod common;

use common::{PASSPHRASE, encrypted_copy, install_key};
use disconect_core::keys::{self, PassphraseSource};
use disconect_core::store::{self, StoreError};
use disconect_core::write_lock::{self, LockError};
use std::time::Duration;

fn pass() -> PassphraseSource<'static> {
    PassphraseSource::Explicit(PASSPHRASE)
}

fn versions(store: &store::Store) -> Vec<i64> {
    let mut stmt = store.conn().prepare("SELECT version FROM schema_migrations ORDER BY version").unwrap();
    stmt.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
}

#[test]
fn new_plaintext_store_migrates_and_reopen_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sub/dir/plain.db");
    let first = store::open_for_write(&db, "test", 5.0, PassphraseSource::Env).unwrap();
    assert_eq!(first.user_version().unwrap(), 3);
    assert_eq!(versions(&first), vec![1, 2, 3]);
    drop(first);
    let second = store::open_for_write(&db, "test", 5.0, PassphraseSource::Env).unwrap();
    assert_eq!(second.user_version().unwrap(), 3);
    assert_eq!(versions(&second), vec![1, 2, 3]);
    drop(second);
    assert!(!write_lock_holder_exists(&db), "holder file removed on release");
    let ro = store::open_read_only(&db, PassphraseSource::Env).unwrap();
    assert!(ro.conn().execute("CREATE TABLE x(a)", []).is_err(), "read-only refuses writes");
}

fn write_lock_holder_exists(db: &std::path::Path) -> bool {
    keys::sibling_with_suffix(db, ".write-lock.holder").exists()
}

#[test]
fn plaintext_db_beside_key_file_is_not_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("plain.db");
    drop(store::open_for_write(&db, "test", 5.0, PassphraseSource::Env).unwrap());
    install_key(&db);
    assert!(matches!(store::open_read_only(&db, pass()), Err(StoreError::NotEncrypted(_))));
    assert!(matches!(store::open_for_write(&db, "test", 5.0, pass()), Err(StoreError::NotEncrypted(_))));
}

#[test]
fn encrypted_db_without_key_file_is_encrypted() {
    let (_dir, db) = encrypted_copy();
    std::fs::remove_file(keys::sibling_with_suffix(&db, ".keys.json")).unwrap();
    assert!(matches!(store::open_read_only(&db, PassphraseSource::Env), Err(StoreError::Encrypted(_))));
}

#[test]
fn wrong_key_file_is_encrypted_and_wrong_passphrase_is_key_error() {
    let (_dir, db) = encrypted_copy();
    assert!(matches!(
        store::open_read_only(&db, PassphraseSource::Explicit("definitely wrong passphrase")),
        Err(StoreError::Key(keys::KeyError::WrongPassphrase))
    ));
    assert!(matches!(store::open_read_only(&db, PassphraseSource::Env), Err(StoreError::Key(keys::KeyError::Locked))));
}

#[test]
fn rotation_in_progress_is_refused_never_promoted() {
    let (_dir, db) = encrypted_copy();
    let key = keys::sibling_with_suffix(&db, ".keys.json");
    let next = keys::sibling_with_suffix(&key, ".next");
    std::fs::write(&next, "{}").unwrap();
    let err = store::open_read_only(&db, pass()).unwrap_err();
    assert!(matches!(err, StoreError::RotationInProgress(_)), "{err}");
    assert!(err.to_string().contains("rotation"));
    assert!(next.exists() && key.exists(), "nothing promoted or removed");
}

/// 7b-10 review N6: a second name for the store (a symlink) must meet the same lock, not a lock of its own.
#[cfg(unix)]
#[test]
fn a_symlinked_store_name_shares_the_write_lock() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("real.hbdb");
    std::fs::write(&db, b"").unwrap();
    let link = dir.path().join("link.hbdb");
    std::os::unix::fs::symlink(&db, &link).unwrap();
    assert_eq!(write_lock::lock_path_for(&link), write_lock::lock_path_for(&db));
    let held = write_lock::acquire(&db, "first", Duration::from_secs(1)).unwrap();
    match write_lock::acquire(&link, "second", Duration::from_millis(100)) {
        Err(LockError::Busy { holder }) => assert_eq!(holder.unwrap()["purpose"], "first"),
        other => panic!("the link must meet the real store's lock: {other:?}"),
    }
    drop(held);
    assert!(write_lock::acquire(&link, "after", Duration::from_millis(100)).is_ok());
    let missing = dir.path().join("not-yet.hbdb");
    let real_dir = std::fs::canonicalize(dir.path()).unwrap();
    assert_eq!(write_lock::lock_path_for(&missing), real_dir.join("not-yet.hbdb.write-lock"), "as spelled (folder resolved) until it exists");
    // a dangling link: SQLite would create the target, so the lock already sits beside the target
    let dangling = dir.path().join("dangling.hbdb");
    std::os::unix::fs::symlink(dir.path().join("target.hbdb"), &dangling).unwrap();
    assert_eq!(write_lock::lock_path_for(&dangling), real_dir.join("target.hbdb.write-lock"));
    let held = write_lock::acquire(&dangling, "via the link", Duration::from_secs(1)).unwrap();
    assert!(matches!(write_lock::acquire(&dir.path().join("target.hbdb"), "via the target", Duration::from_millis(100)), Err(LockError::Busy { .. })));
    drop(held);
}

#[test]
fn busy_write_lock_reports_holder() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("busy.db");
    let held = write_lock::acquire(&db, "holder-test", Duration::from_secs(1)).unwrap();
    let started = std::time::Instant::now();
    match store::open_for_write(&db, "second", 0.3, PassphraseSource::Env) {
        Err(StoreError::Lock(LockError::Busy { holder })) => {
            let holder = holder.expect("holder json");
            assert_eq!(holder["purpose"], "holder-test");
            assert_eq!(holder["pid"], std::process::id());
            assert!(holder["since"].as_str().unwrap().ends_with('Z'));
        }
        other => panic!("expected WriteLockBusy, got {other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(280));
    drop(held);
    assert!(store::open_for_write(&db, "third", 1.0, PassphraseSource::Env).is_ok());
}

#[test]
fn schema_too_new_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("new.db");
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("PRAGMA user_version = 4; CREATE TABLE t(a);").unwrap();
    }
    assert!(matches!(store::open_read_only(&db, PassphraseSource::Env), Err(StoreError::SchemaTooNew { found: 4 })));
    assert!(matches!(store::open_for_write(&db, "t", 1.0, PassphraseSource::Env), Err(StoreError::SchemaTooNew { found: 4 })));
}

#[test]
fn rust_creates_encrypted_store_under_fixture_key_and_rereads_it() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("fresh.hbdb");
    install_key(&db);
    let pass_file = dir.path().join("pass.txt");
    std::fs::write(&pass_file, format!("{PASSPHRASE}\n")).unwrap();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_disconect-core"))
        .arg("--db").arg(&db).arg("--passphrase-file").arg(&pass_file).arg("init")
        .status().unwrap();
    assert!(status.success());
    assert_eq!(store::is_encrypted_file(&db).unwrap(), Some(true));
    let ro = store::open_read_only(&db, pass()).unwrap();
    assert_eq!(ro.user_version().unwrap(), 3);
    assert!(ro.cipher_version().is_some());

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_disconect-core"))
        .arg("--db").arg(&db).arg("--passphrase-file").arg(&pass_file).args(["status", "--json"])
        .output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema_version"], 3);
    assert_eq!(v["encrypted"], true);
    assert_eq!(v["unlocked"], true);
    assert_eq!(v["tables"]["raw_records"], 0);
}

#[test]
fn cli_exits_9_when_locked_or_wrong() {
    let (dir, db) = encrypted_copy();
    let bad = dir.path().join("bad.txt");
    std::fs::write(&bad, "wrong passphrase here").unwrap();
    let run = |extra: &[&std::ffi::OsStr]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_disconect-core"))
            .env_remove("DISCONECT_PASSPHRASE").arg("--db").arg(&db).args(extra).args(["status", "--json"])
            .output().unwrap()
    };
    let locked = run(&[]);
    assert_eq!(locked.status.code(), Some(9));
    let wrong = run(&["--passphrase-file".as_ref(), bad.as_os_str()]);
    assert_eq!(wrong.status.code(), Some(9));
    let msg = String::from_utf8_lossy(&wrong.stderr);
    assert!(msg.starts_with("error: ") && msg.lines().count() == 1);
}

#[test]
fn a_writer_never_recreates_a_moved_legacy_folder() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join(".hearthbeat").join("hearthbeat.db");
    match store::open_for_write(&db, "import", 0.1, PassphraseSource::Env) {
        Err(StoreError::HomeMoved(moved)) => {
            assert_eq!(moved.to_string(), "data folder ~/.hearthbeat has moved; restart DISCOnect");
        }
        other => panic!("expected HomeMoved, got {other:?}"),
    }
    match write_lock::acquire(&db, "x", Duration::from_millis(100)) {
        Err(LockError::HomeMoved(_)) => {}
        other => panic!("expected the lock to refuse too, got {:?}", other.map(|_| ())),
    }
    assert!(!dir.path().join(".hearthbeat").exists());
    // any other missing folder is still created, the new data folder included
    for folder in [".disconect", "fresh"] {
        let ok = dir.path().join(folder).join("x.db");
        assert!(store::open_for_write(&ok, "t", 1.0, PassphraseSource::Env).is_ok());
        assert!(ok.is_file());
    }
}

#[test]
fn cli_import_into_a_moved_legacy_folder_exits_3_and_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join(".hearthbeat").join("hearthbeat.db");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_disconect-core"));
    cmd.env_clear();
    common::simulator_env(&mut cmd);
    let out = cmd
        .env("DISCONECT_KEYCHAIN", "fail")
        .arg("--db").arg(&db).args(["import", "/nonexistent"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("data folder ~/.hearthbeat has moved; restart DISCOnect"));
    assert!(!dir.path().join(".hearthbeat").exists());
}

#[test]
fn a_write_open_marks_a_dead_writers_running_run_interrupted() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("runs.db");
    let first = store::open_for_write(&db, "test", 5.0, PassphraseSource::Env).unwrap();
    first
        .conn()
        .execute("INSERT INTO import_runs(started_at, transport, status) VALUES('2026-01-01T00:00:00Z','export','running')", [])
        .unwrap();
    drop(first);
    let statuses = |s: &store::Store| -> Vec<(String, Option<String>, Option<String>)> {
        let mut stmt = s.conn().prepare("SELECT status, finished_at, error FROM import_runs ORDER BY id").unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect()
    };
    let ro = store::open_read_only(&db, PassphraseSource::Env).unwrap();
    assert_eq!(statuses(&ro), vec![("running".to_string(), None, None)], "a reader never changes a row");
    drop(ro);
    let second = store::open_for_write(&db, "test", 5.0, PassphraseSource::Env).unwrap();
    assert_eq!(statuses(&second), vec![("interrupted".to_string(), None, None)]);
    // committed before the store is handed out: a reader opened meanwhile sees it
    let peek = store::open_read_only(&db, PassphraseSource::Env).unwrap();
    assert_eq!(statuses(&peek), vec![("interrupted".to_string(), None, None)]);
    drop(peek);
    second
        .conn()
        .execute("INSERT INTO import_runs(started_at, transport, status) VALUES('2026-01-02T00:00:00Z','export','running')", [])
        .unwrap();
    assert_eq!(statuses(&second)[1].0, "running", "the UPDATE runs only at open time");
}
