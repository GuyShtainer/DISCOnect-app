// SPDX-License-Identifier: AGPL-3.0-or-later
//! `import` end to end on the synthetic FIT fixtures (no health data), into a plaintext store.

mod common;

use std::path::{Path, PathBuf};

use disconect_core::keys::PassphraseSource;
use disconect_core::sources::{import_path, iter_fit_files};
use disconect_core::store::{self, Store};
use rusqlite::Connection;

fn synthetic_folder(dir: &Path) -> PathBuf {
    let target = dir.join("drop");
    std::fs::create_dir_all(&target).expect("mkdir");
    let source = common::fixtures().join("synthetic");
    for entry in std::fs::read_dir(source).expect("read fixtures") {
        let path = entry.expect("entry").path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if let Some(stem) = name.strip_suffix(".fit.bin") {
            std::fs::copy(&path, target.join(format!("{stem}.fit"))).expect("copy fixture");
        }
    }
    target
}

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)).expect("count")
}

fn open(db: &Path) -> Store {
    store::open_for_write(db, "test", 5.0, PassphraseSource::Env).expect("open store")
}

#[test]
fn every_fixture_but_garbage_imports_and_garbage_fails_then_rerun_is_all_duplicates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let folder = synthetic_folder(dir.path());
    // One file (garbage) is expected to fail; every other fixture imports.
    let total = iter_fit_files(&folder).expect("walk").len() as i64;
    assert!(total >= 11, "expected at least 11 fixtures");
    let store = open(&dir.path().join("plain.db"));
    let conn = store.conn();

    let first = import_path(conn, &folder, None, None).expect("first import");
    assert_eq!((first.files_seen, first.files_imported, first.files_duplicate, first.files_failed), (total, total - 1, 0, 1));
    assert_eq!(first.status(), "partial");
    assert_eq!(first.transport, "drop");
    assert_eq!(first.failures.len(), 1);
    assert!(first.records_written > 0 && first.derived_days > 0);
    assert_eq!(count(conn, "raw_records"), total - 1);
    assert_eq!(count(conn, "import_failures"), 1);
    assert_eq!(count(conn, "import_runs"), 1);
    let (status, seen, failed): (String, i64, i64) = conn
        .query_row("SELECT status, files_seen, files_failed FROM import_runs", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("run row");
    assert_eq!((status.as_str(), seen, failed), ("partial", total, 1));
    let transport: String = conn.query_row("SELECT DISTINCT transport FROM raw_records", [], |r| r.get(0)).expect("transport");
    assert_eq!(transport, "drop");
    // the retained bytes are the file's bytes
    let (hash, size, payload): (String, i64, Vec<u8>) = conn
        .query_row("SELECT payload_hash, payload_bytes, payload FROM raw_records ORDER BY id LIMIT 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .expect("raw row");
    assert_eq!(hash.len(), 64);
    assert!(size > 0 && !payload.is_empty());

    let rows_before: Vec<(String, i64)> = store::table_counts(conn).expect("counts");
    let second = import_path(conn, &folder, Some("usb"), None).expect("second import");
    assert_eq!((second.files_seen, second.files_imported, second.files_duplicate), (total, 0, total - 1));
    // the undecodable file fails again (its failure row is unique by hash, so it is not duplicated)
    assert_eq!(second.files_failed, 1);
    assert_eq!(second.records_written, 0);
    assert_eq!(count(conn, "raw_records"), total - 1);
    assert_eq!(count(conn, "import_failures"), 1);
    assert_eq!(count(conn, "import_runs"), 2);
    let after: Vec<(String, i64)> = store::table_counts(conn).expect("counts");
    let changed: Vec<&str> = rows_before
        .iter()
        .zip(&after)
        .filter(|(a, b)| a.1 != b.1)
        .map(|(a, _)| a.0.as_str())
        .collect();
    assert_eq!(changed, ["import_runs"], "a re-import adds only its run row");
}

#[test]
fn single_file_and_zip_are_bags_of_fit_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let folder = synthetic_folder(dir.path());
    let one = folder.join("hrv_status.fit");
    let files = iter_fit_files(&one).expect("single file");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "hrv_status.fit");

    let zip_path = dir.path().join("bag.zip");
    {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&zip_path).expect("zip file"));
        let options = zip::write::SimpleFileOptions::default();
        for name in ["z/b.fit", "a.FIT", "notes.txt", "m/"] {
            if name.ends_with('/') {
                writer.add_directory(name, options).expect("dir");
            } else {
                writer.start_file(name, options).expect("start");
                writer.write_all(&std::fs::read(&one).expect("read")).expect("write");
            }
        }
        writer.finish().expect("finish");
    }
    let labels: Vec<String> = iter_fit_files(&zip_path).expect("zip").into_iter().map(|f| f.0).collect();
    assert_eq!(labels, ["a.FIT", "z/b.fit"]);

    let store = open(&dir.path().join("zip.db"));
    let stats = import_path(store.conn(), &zip_path, Some("ciq"), None).expect("zip import");
    assert_eq!((stats.files_imported, stats.files_duplicate), (1, 1), "the two entries are the same bytes");
    assert_eq!(stats.status(), "ok");
}

#[test]
fn a_missing_path_is_an_error_and_writes_no_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("none.db"));
    assert!(import_path(store.conn(), &dir.path().join("nope"), None, None).is_err());
    assert_eq!(count(store.conn(), "import_runs"), 0);
}

#[test]
fn cli_import_prints_counts_and_exits_1_on_partial() {
    let dir = tempfile::tempdir().expect("tempdir");
    let folder = synthetic_folder(dir.path());
    let db = dir.path().join("cli.db");
    let imported = iter_fit_files(&folder).expect("walk").len() - 1;
    let run = |extra: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_disconect-core"))
            .arg("--db")
            .arg(&db)
            .arg("import")
            .arg(&folder)
            .args(extra)
            .env_remove("DISCONECT_PASSPHRASE")
            .output()
            .expect("run cli")
    };
    let out = run(&["--transport", "gadgetbridge"]);
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with(&format!("partial: {imported} imported, 0 duplicate, 1 failed, ")), "{text}");
    assert!(text.contains("derived daily steps/distance for 1 day(s)"));
    assert!(text.contains("  FAILED garbage.fit: [unrecognized_payload]"));
    let bad = run(&["--transport", "carrier-pigeon"]);
    assert_eq!(bad.status.code(), Some(1));
    let clean = dir.path().join("clean");
    std::fs::create_dir_all(&clean).expect("mkdir");
    std::fs::copy(folder.join("hrv_status.fit"), clean.join("one.fit")).expect("copy");
    let ok = std::process::Command::new(env!("CARGO_BIN_EXE_disconect-core"))
        .args(["--db"])
        .arg(dir.path().join("ok.db"))
        .arg("import")
        .arg(&clean)
        .output()
        .expect("run cli");
    assert_eq!(ok.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&ok.stdout).starts_with("ok: 1 imported, 0 duplicate, 0 failed, "));
}
