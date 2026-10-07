// SPDX-License-Identifier: AGPL-3.0-or-later
//! The coverage ledger against the Python oracle's committed answers (`ledger-synthetic*.json.gz`,
//! written by `tests/gen_serve_fixtures.py` from `coverage.ledger`), on the synthetic store and its
//! schema-v1 twin. `data.health` ports the ledger into the protocol in a later slice; until then no
//! serve request reaches `ledger`, so this is what holds it to the oracle. Values are compared as
//! `serde_json::Value`, whose numbers keep integers and floats apart.

use std::io::Read;
use std::path::{Path, PathBuf};

use disconect_core::contract::Contract;
use disconect_core::read::coverage;
use disconect_core::store;
use disconect_core::wirejson::PyStr;
use serde_json::Value;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../disconect/tests/fixtures/serve")
}

fn gunzip_json(path: &Path) -> Value {
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).expect("fixture"))
        .read_to_string(&mut text)
        .expect("gunzip");
    serde_json::from_str(&text).expect("json")
}

fn check(store_file: &str, ledger_file: &str, refinements: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("store.db");
    std::fs::copy(fixtures().join(store_file), &db).expect("copy store");
    let opened = store::open_read_only_with(&db, None).expect("open");
    let contract = Contract::get().expect("contract");
    let fixture = gunzip_json(&fixtures().join(ledger_file));
    let cases = fixture["cases"].as_array().expect("cases");
    assert!(cases.len() >= 9);
    for case in cases {
        let last_day = case["last_day"].as_str().expect("last_day");
        let window_days = case["window_days"].as_i64().expect("window_days");
        let got = coverage::ledger(opened.conn(), contract, last_day, window_days).expect("ledger");
        assert_eq!(
            got["refinements_available"],
            Value::Bool(refinements),
            "refinements on {store_file}"
        );
        if got != case["result"] {
            let key = got
                .as_object()
                .and_then(|g| {
                    g.keys()
                        .find(|k| got[k.as_str()] != case["result"][k.as_str()])
                })
                .cloned();
            unreachable!(
                "ledger differs for window_days={window_days}: first differing key {key:?}"
            );
        }
    }
}

#[test]
fn the_ledger_equals_the_oracles_on_the_synthetic_store() {
    check("synthetic.hbdb", "ledger-synthetic.json.gz", true);
}

#[test]
fn the_ledger_equals_the_oracles_on_a_schema_v1_store() {
    check("synthetic-v1.hbdb", "ledger-synthetic-v1.json.gz", false);
}

#[test]
fn the_ledger_shows_every_status_gap_truncation_and_drift_somewhere() {
    let fixture = gunzip_json(&fixtures().join("ledger-synthetic.json.gz"));
    let mut statuses = std::collections::BTreeSet::new();
    let (mut truncated, mut drift, mut sparse, mut failures) = (false, false, false, 0);
    for case in fixture["cases"].as_array().expect("cases") {
        let result = &case["result"];
        drift |= !result["map_drift"].as_array().expect("drift").is_empty();
        failures += result["unattributed_failures"].as_i64().expect("count");
        for row in result["ledger"].as_array().expect("rows") {
            truncated |= row["gaps_truncated"] == Value::Bool(true);
            sparse |= row["sparse"] == Value::Bool(true);
            for gap in row["gaps"].as_array().expect("gaps") {
                statuses.insert(gap["status"].as_str().expect("status").to_string());
            }
        }
    }
    assert!(truncated && drift && sparse && failures > 0);
    assert_eq!(
        statuses.into_iter().collect::<Vec<_>>(),
        ["failed", "not_covered", "source_empty"]
    );
}

// ---- completeness (7b-12): the twin cases of `tests/test_coverage.py` -------------------------

fn writable(dir: &Path) -> disconect_core::store::Store {
    store::open_for_write(&dir.join("store.db"), "test", 5.0, disconect_core::keys::PassphraseSource::Env)
        .expect("open store")
}

fn raw(conn: &rusqlite::Connection, stream: &str, start: &str, end: &str) -> i64 {
    conn.execute(
        "INSERT INTO raw_records(stream, source_key, source_scope, transport, payload_kind, payload, payload_hash, \
         payload_bytes, start_utc, end_utc, imported_at) VALUES(?1, ?2, 'device', 'usb', 'fit', x'00', 'h', 1, ?3, ?4, \
         '2025-07-01T00:00:00Z')",
        rusqlite::params![stream, format!("{stream}-{start}"), start, end],
    )
    .expect("raw record");
    conn.last_insert_rowid()
}

/// One reading of `metric` every `step_s` from `start` up to (excluding) `end`, epoch seconds.
fn minutes(conn: &rusqlite::Connection, raw_id: i64, metric: &str, scope: &str, start: i64, end: i64, step_s: i64) {
    let mut moment = start;
    while moment < end {
        let stamp = chrono::DateTime::from_timestamp(moment, 0).expect("stamp").format("%Y-%m-%dT%H:%M:%SZ").to_string();
        conn.execute(
            "INSERT INTO metric_samples(metric, ts_utc, value, source_scope, raw_record_id) VALUES(?1, ?2, 60, ?3, ?4)",
            rusqlite::params![metric, stamp, scope, raw_id],
        )
        .expect("sample");
        moment += step_s;
    }
}

/// Epoch seconds of 2025-06-<day>T<hour>:<minute>Z.
fn utc(day: u32, hour: u32, minute: u32) -> i64 {
    chrono::NaiveDate::from_ymd_opt(2025, 6, day).expect("date").and_hms_opt(hour, minute, 0).expect("time").and_utc().timestamp()
}

fn shares(conn: &rusqlite::Connection, metric: &str, scope: &str, first: &str, last: &str) -> Vec<(String, Option<i64>)> {
    coverage::day_completeness(conn, Contract::get().expect("contract"), metric, scope, first, last).expect("completeness")
}

#[test]
fn completeness_full_day_gap_sparse_and_partial() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = writable(dir.path());
    let conn = store.conn();
    let full = raw(conn, "fit:monitoring_b", "2025-06-01T00:00:00Z", "2025-06-02T00:00:00Z");
    minutes(conn, full, "heart_rate", "device", utc(1, 0, 0), utc(2, 0, 0), 60); // every minute -> 100
    let twenty = raw(conn, "fit:monitoring_b", "2025-06-02T00:00:00Z", "2025-06-02T20:00:00Z");
    minutes(conn, twenty, "heart_rate", "device", utc(2, 0, 0), utc(2, 8, 0), 60); // 8 h, 4 h off, 8 h of 20 h -> 80
    minutes(conn, twenty, "heart_rate", "device", utc(2, 12, 0), utc(2, 20, 0), 60);
    let hour = raw(conn, "fit:monitoring_b", "2025-06-03T00:00:00Z", "2025-06-03T01:00:00Z");
    minutes(conn, hour, "heart_rate", "device", utc(3, 0, 0), utc(3, 1, 0), 360); // ten readings 6 min apart -> 16
    let today = raw(conn, "fit:monitoring_b", "2025-06-04T00:00:00Z", "2025-06-04T10:00:00Z");
    minutes(conn, today, "heart_rate", "device", utc(4, 0, 0), utc(4, 10, 0), 60); // a partial file, worn throughout -> 100
    let got = shares(conn, "heart_rate", "device", "2025-05-31", "2025-06-05");
    let want: Vec<(String, Option<i64>)> = [
        ("2025-05-31", None), ("2025-06-01", Some(100)), ("2025-06-02", Some(80)), ("2025-06-03", Some(16)),
        ("2025-06-04", Some(100)), ("2025-06-05", None),
    ]
    .into_iter()
    .map(|(day, share)| (day.to_string(), share))
    .collect();
    assert_eq!(got, want);
    let calendar = disconect_core::read::queries::metric_calendar(
        conn, Contract::get().expect("contract"), &PyStr::from_text("heart_rate"), &PyStr::from_text("device"), "2025-05-31", "2025-06-02",
    )
    .expect("calendar");
    let pairs: Vec<(String, String, Value)> = calendar
        .iter()
        .map(|row| (row["day"].as_str().unwrap().into(), row["status"].as_str().unwrap().into(), row["completeness"].clone()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("2025-05-31".to_string(), "not_covered".to_string(), Value::Null),
            ("2025-06-01".to_string(), "present".to_string(), Value::from(100)),
            ("2025-06-02".to_string(), "present".to_string(), Value::from(80)),
        ]
    );
}

#[test]
fn completeness_counts_overlapping_files_once_and_is_null_off_the_per_minute_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = writable(dir.path());
    let conn = store.conn();
    let first = raw(conn, "fit:monitoring_b", "2025-06-01T00:00:00Z", "2025-06-01T13:00:00Z");
    raw(conn, "fit:monitoring_b", "2025-06-01T11:00:00Z", "2025-06-02T00:00:00Z");
    minutes(conn, first, "heart_rate", "device", utc(1, 0, 0), utc(1, 12, 0), 60); // 12 h of 24 (not of 26) -> 50
    minutes(conn, first, "hrv_rmssd", "device", utc(1, 0, 0), utc(1, 12, 0), 300);
    conn.execute(
        "INSERT INTO daily_metrics(date, metric, value, source_scope, raw_record_id) VALUES('2025-06-01','steps',100,'device',?1)",
        [first],
    )
    .expect("daily");
    assert_eq!(shares(conn, "heart_rate", "device", "2025-06-01", "2025-06-01"), [("2025-06-01".to_string(), Some(50))]);
    assert_eq!(shares(conn, "hrv_rmssd", "device", "2025-06-01", "2025-06-01"), [("2025-06-01".to_string(), None)]);
    assert_eq!(shares(conn, "steps", "device", "2025-06-01", "2025-06-01"), [("2025-06-01".to_string(), None)]);
    assert_eq!(shares(conn, "heart_rate", "live", "2025-06-01", "2025-06-01"), [("2025-06-01".to_string(), None)]);
    let inverted = coverage::day_completeness(conn, Contract::get().expect("contract"), "heart_rate", "device", "2025-06-02", "2025-06-01");
    assert_eq!(inverted.unwrap_err().to_string(), "last_day must not be before first_day");
}

#[test]
fn completeness_claimed_export_window_covers_the_whole_day() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = writable(dir.path());
    let conn = store.conn();
    conn.execute_batch(
        "INSERT INTO import_runs(id, started_at, transport, status) VALUES(1,'2025-07-01T00:00:00Z','connect_export','ok'); \
         INSERT INTO raw_records(stream, source_key, source_scope, transport, payload_kind, payload, payload_hash, \
         payload_bytes, imported_at) VALUES('json:hr','k','vendor_cloud','connect_export','json',x'00','h',1,'2025-07-01T00:00:00Z'); \
         INSERT INTO export_ranges(run_id, stream, from_day, to_day) VALUES(1,'json:hr','2025-06-01','2025-06-01');",
    )
    .expect("seed");
    let raw_id: i64 = conn.query_row("SELECT id FROM raw_records WHERE stream='json:hr'", [], |r| r.get(0)).expect("raw id");
    minutes(conn, raw_id, "heart_rate", "vendor_cloud", utc(1, 0, 0), utc(1, 6, 0), 60); // 6 h of a claimed day -> 25
    assert_eq!(
        shares(conn, "heart_rate", "vendor_cloud", "2025-06-01", "2025-06-02"),
        [("2025-06-01".to_string(), Some(25)), ("2025-06-02".to_string(), None)]
    );
}

#[test]
fn completeness_follows_the_watch_clock() {
    // on a +5:30 watch the local day 06-01 is 05-31T18:30Z..06-01T18:30Z; a file and readings over exactly that are 100
    let dir = tempfile::tempdir().expect("tempdir");
    let store = writable(dir.path());
    let conn = store.conn();
    let raw_id = raw(conn, "fit:monitoring_b", "2025-05-31T18:30:00Z", "2025-06-01T18:30:00Z");
    conn.execute(
        "INSERT INTO clock_offsets(ts_utc, offset_s, raw_record_id) VALUES('2025-06-01T06:00:00Z', 19800, ?1)",
        [raw_id],
    )
    .expect("offset");
    minutes(conn, raw_id, "stress", "device", utc(1, 0, 0) - 5 * 3600 - 1800, utc(1, 18, 30), 60);
    assert_eq!(
        shares(conn, "stress", "device", "2025-05-31", "2025-06-02"),
        [("2025-05-31".to_string(), None), ("2025-06-01".to_string(), Some(100)), ("2025-06-02".to_string(), None)]
    );
}

#[test]
fn completeness_pins_the_worn_gap_boundary() {
    // readings exactly WORN_GAP_S apart bridge; one second more does not: 300 + 60 + 60 = 420 of 3600 -> 11
    let dir = tempfile::tempdir().expect("tempdir");
    let store = writable(dir.path());
    let conn = store.conn();
    let raw_id = raw(conn, "fit:monitoring_b", "2025-06-01T00:00:00Z", "2025-06-01T01:00:00Z");
    for stamp in ["2025-06-01T00:00:00Z", "2025-06-01T00:05:00Z", "2025-06-01T00:10:01Z"] {
        conn.execute(
            "INSERT INTO metric_samples(metric, ts_utc, value, source_scope, raw_record_id) VALUES('heart_rate', ?1, 60, 'device', ?2)",
            rusqlite::params![stamp, raw_id],
        )
        .expect("sample");
    }
    assert_eq!(shares(conn, "heart_rate", "device", "2025-06-01", "2025-06-01"), [("2025-06-01".to_string(), Some(11))]);
}

#[test]
fn completeness_day_bounds_never_step_back() {
    // a stated offset that jumps by more than a day (a watch clock never set) empties the day it swallows
    // instead of crediting a fully worn day's seconds elsewhere or going negative (unordered bounds made
    // bisect_right and partition_point disagree); an absurd offset is OverflowError, as on the Python side
    let dir = tempfile::tempdir().expect("tempdir");
    let store = writable(dir.path());
    let conn = store.conn();
    let raw_id = raw(conn, "fit:monitoring_b", "2025-06-01T00:00:00Z", "2025-06-05T00:00:00Z");
    for (day, offset) in [(1, 0), (2, 0), (3, 200_000), (4, 0), (5, 0)] {
        conn.execute(
            "INSERT INTO clock_offsets(ts_utc, offset_s, raw_record_id) VALUES(?1, ?2, ?3)",
            rusqlite::params![format!("2025-06-{day:02}T00:00:00Z"), offset, raw_id],
        )
        .expect("offset");
    }
    minutes(conn, raw_id, "heart_rate", "device", utc(1, 0, 0), utc(5, 0, 0), 60);
    assert_eq!(
        shares(conn, "heart_rate", "device", "2025-06-01", "2025-06-04"),
        [
            ("2025-06-01".to_string(), Some(100)),
            ("2025-06-02".to_string(), None),
            ("2025-06-03".to_string(), Some(100)),
            ("2025-06-04".to_string(), Some(100)),
        ]
    );
    conn.execute("UPDATE clock_offsets SET offset_s=?1 WHERE ts_utc='2025-06-03T00:00:00Z'", [i64::MIN])
        .expect("absurd offset");
    let absurd = coverage::day_completeness(conn, Contract::get().expect("contract"), "heart_rate", "device", "2025-06-01", "2025-06-04");
    assert!(matches!(absurd, Err(disconect_core::read::ReadError::Overflow)), "{absurd:?}");
}
