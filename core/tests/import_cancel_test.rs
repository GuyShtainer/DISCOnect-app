// SPDX-License-Identifier: AGPL-3.0-or-later
//! BL-3 review N8: `import_path_with(cancel)` per phase — what is read, what is skipped, what is still
//! derived. Twin of `tests/test_import_cancel.py`. Synthetic data only.
mod common;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use disconect_core::keys::PassphraseSource;
use disconect_core::sources::import_path_with;
use disconect_core::store::{self, Store};
use disconect_core::writer::ImportStats;
use rusqlite::Connection;

const T0: f64 = 1750000000.0;

fn fixture_fit(name: &str) -> Vec<u8> {
    fs::read(common::fixtures().join("synthetic").join(format!("{name}.fit.bin"))).expect("fixture")
}

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, bytes).expect("write");
}

fn live_lines(step: i64) -> String {
    [
        r#"{"status": "scanning"}"#.to_string(),
        format!(r#"{{"t": {:?}, "metric": "steps", "value": {step}}}"#, T0 + 2.0),
        format!(r#"{{"t": {:?}, "metric": "heart_rate", "value": 71}}"#, T0 + 1.0),
        r#"{"status": "stopped", "stop": "LinkClosed"}"#.to_string(),
    ]
    .iter()
    .map(|l| format!("{l}\n"))
    .collect()
}

/// An export: two FIT members, then two UDS JSON files (one record each).
fn export_folder(dir: &Path) -> PathBuf {
    let root = dir.join("export");
    let mut nested = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut nested);
        let options = zip::write::SimpleFileOptions::default();
        for (name, bytes) in [("a_hrv.fit", fixture_fit("hrv_status")), ("b_skin.fit", fixture_fit("skin_temp"))] {
            zip.start_file(name, options).expect("start");
            zip.write_all(&bytes).expect("member");
        }
        zip.finish().expect("finish");
    }
    write(&root, "DI_CONNECT/DI-Connect-Uploaded-Files/UploadedFiles_1.zip", nested.get_ref());
    write(
        &root,
        "DI_CONNECT/DI-Connect-Aggregator/UDSFile_2025-06-01_2025-06-03.json",
        br#"[{"calendarDate":"2025-06-01","totalSteps":10}]"#,
    );
    write(
        &root,
        "DI_CONNECT/DI-Connect-Aggregator/UDSFile_2025-06-04_2025-06-05.json",
        br#"[{"calendarDate":"2025-06-04","totalSteps":12}]"#,
    );
    root
}

fn open(db: &Path) -> Store {
    store::open_for_write(db, "test", 1.0, PassphraseSource::Explicit("unused")).expect("open store")
}

/// A cancel check that says true from its n-th call on (0 = before anything is written).
fn after(n: u32) -> impl Fn() -> bool {
    let calls = Cell::new(0u32);
    move || {
        calls.set(calls.get() + 1);
        calls.get() > n
    }
}

fn import(path: &Path, db: &Path, cancel: Option<&dyn Fn() -> bool>) -> ImportStats {
    let store = open(db);
    import_path_with(store.conn(), path, None, None, cancel).expect("import")
}

fn counts(db: &Path) -> BTreeMap<&'static str, i64> {
    let conn = Connection::open(db).expect("open");
    let one = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0)).expect("count");
    let mut out = BTreeMap::new();
    for table in ["daily_metrics", "metric_samples", "monitoring_intervals", "daily_labels"] {
        out.insert(table, one(&format!("SELECT COUNT(*) FROM {table}")));
    }
    out.insert("fit_records", one("SELECT COUNT(*) FROM raw_records WHERE stream LIKE 'fit:%'"));
    out.insert("json_records", one("SELECT COUNT(*) FROM raw_records WHERE stream LIKE 'json:%'"));
    out
}

fn last_run_status(db: &Path) -> String {
    Connection::open(db)
        .expect("open")
        .query_row("SELECT status FROM import_runs ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
        .expect("status")
}

#[test]
fn fit_folder_cancel_after_one_file_derives_that_file_like_a_lone_import() {
    let dir = tempfile::tempdir().expect("tempdir");
    let folder = dir.path().join("drop");
    write(&folder, "a.fit", &fixture_fit("monitoring_timestamp16"));
    write(&folder, "b.fit", &fixture_fit("monitoring_cycles_resolution"));
    let lone = dir.path().join("lone");
    write(&lone, "a.fit", &fixture_fit("monitoring_timestamp16"));

    let cut_db = dir.path().join("cut.db");
    let stats = import(&folder, &cut_db, Some(&after(1)));
    assert!(stats.cancelled && stats.status() == "cancelled");
    assert_eq!((stats.files_seen, stats.files_imported, stats.files_failed), (1, 1, 0));
    assert_eq!(last_run_status(&cut_db), "cancelled");
    let cut = counts(&cut_db);
    assert_eq!(cut["fit_records"], 1);
    let lone_db = dir.path().join("lone.db");
    let whole = import(&lone, &lone_db, None);
    assert_eq!(whole.status(), "ok");
    assert_eq!(cut, counts(&lone_db), "the cut phase's tail derivations ran for the one file written");

    // a cancel before the first write reads nothing: booked cancelled with zero counters
    let zero_db = dir.path().join("zero.db");
    let stats = import(&folder, &zero_db, Some(&after(0)));
    assert!(stats.cancelled && stats.files_seen == 0);
    assert_eq!(last_run_status(&zero_db), "cancelled");
}

#[test]
fn live_phase_cancel_skips_the_fit_walk_and_still_derives_live_samples() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let folder = dir.path().join("drop");
    write(&folder, "live-1.jsonl", live_lines(40).as_bytes());
    write(&folder, "live-2.jsonl", live_lines(41).as_bytes());
    write(&folder, "m.fit", &fixture_fit("monitoring_timestamp16"));
    // unreadable: a FIT walk after the cancel would fail the run instead of booking it cancelled
    fs::set_permissions(folder.join("m.fit"), fs::Permissions::from_mode(0o000)).expect("chmod");

    let db = dir.path().join("live.db");
    let stats = import(&folder, &db, Some(&after(1)));
    assert!(stats.cancelled && stats.files_seen == 1 && stats.files_imported == 1, "{stats:?}");
    assert_eq!(last_run_status(&db), "cancelled");
    let c = counts(&db);
    assert_eq!((c["fit_records"], c["daily_metrics"]), (0, 0));
    assert!(c["metric_samples"] > 0, "derive_live_samples ran for the one live file written");
    fs::set_permissions(folder.join("m.fit"), fs::Permissions::from_mode(0o644)).expect("chmod back");
}

#[test]
fn export_json_phase_cancel_keeps_the_fit_rows_and_rederives_the_json_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = export_folder(dir.path());
    let whole_db = dir.path().join("whole.db");
    assert_eq!(import(&root, &whole_db, None).status(), "ok");
    let full = counts(&whole_db);

    // two FIT members (one check before each write), then the JSON files (one check before each): the fourth
    // check lands before the second JSON file
    let cut_db = dir.path().join("cut.db");
    let stats = import(&root, &cut_db, Some(&after(3)));
    assert!(stats.cancelled && stats.status() == "cancelled" && stats.files_imported >= 2, "{stats:?}");
    assert_eq!(last_run_status(&cut_db), "cancelled");
    let cut = counts(&cut_db);
    assert_eq!(cut["fit_records"], full["fit_records"], "the FIT phase finished before the cancel");
    assert!(0 < cut["json_records"] && cut["json_records"] < full["json_records"], "one JSON file read, the rest skipped: {cut:?} vs {full:?}");
    assert!(cut["daily_metrics"] > 0, "the JSON re-derivation ran for the file read");
}

#[test]
fn a_cancel_after_the_last_check_changes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let folder = dir.path().join("drop");
    write(&folder, "a.fit", &fixture_fit("monitoring_timestamp16"));
    for calls in [1, 3] {
        let db = dir.path().join(format!("one-{calls}.db"));
        let stats = import(&folder, &db, Some(&after(calls)));
        assert!(!stats.cancelled && stats.status() == "ok" && stats.files_imported == 1);
    }
}
