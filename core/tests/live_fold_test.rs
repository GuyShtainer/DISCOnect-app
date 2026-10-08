// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 9b-2: the live fold (`json:live` records -> `live`-scope samples), the twin of
//! `tests/test_live_fold.py`. Synthetic data only.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{NaiveDate, TimeZone, Utc};
use disconect_core::contract::Contract;
use disconect_core::keys::PassphraseSource;
use disconect_core::live::T_LIMIT;
use disconect_core::read::coverage::{NOT_COVERED, calendar};
use disconect_core::read::health::data_health;
use disconect_core::read::queries::{fetch_window, live_day, load_offsets, sample_day_aggregates};
use disconect_core::read::insight::{FactsQuery, period_facts};
use disconect_core::wirejson::PyStr;
use disconect_core::sources::{import_path, reparse_all};
use disconect_core::store::{self, Store};
use disconect_core::writer::fold_live_readings;
use serde_json::{Value, json};

const BASE: i64 = 1_749_981_600; // 2025-06-15T10:00:00Z

fn r(t: f64, metric: &str, value: i64) -> (f64, String, i64) {
    (t, metric.to_string(), value)
}

fn open(db: &Path) -> Store {
    store::open_for_write(db, "test", 5.0, PassphraseSource::Env).expect("open store")
}

fn write_session(path: &Path, readings: &[Value]) {
    let mut text = String::from("{\"status\": \"scanning\"}\n");
    for line in readings {
        text.push_str(&format!("{line}\n"));
    }
    text.push_str("{\"status\": \"stopped\", \"stop\": \"LinkClosed\"}\n");
    fs::write(path, text).expect("write");
}

#[test]
fn the_pure_fold_follows_the_rules() {
    let b = BASE as f64;
    let readings = vec![
        r(b + 1.5, "heart_rate", 70),
        r(b + 30.0, "heart_rate", 90),
        r(b + 59.999, "heart_rate", 80),
        r(b + 60.0, "heart_rate", 100),
        r(b + 61.0, "heart_rate", 99),
    ];
    let (rows, dropped) = fold_live_readings(&[(7, readings)]);
    assert_eq!(
        rows,
        [("heart_rate".to_string(), BASE, 80, 7), ("heart_rate".to_string(), BASE + 60, 99, 7)]
    );
    assert!(dropped.is_empty());

    // int and float t are the same number; the first contributing record owns the minute
    let a = vec![r(b + 1.0, "heart_rate", 70), r(b + 2.0, "heart_rate", 72), r(b + 10.0, "stress", 30)];
    let bb = vec![
        r(b + 1.0, "heart_rate", 70),
        r(b + 2.0, "heart_rate", 72),
        r(b + 2.0, "heart_rate", 74),
        r(b + 3.0, "heart_rate", 76),
    ];
    let (rows, _) = fold_live_readings(&[(1, a.clone()), (2, bb.clone())]);
    assert_eq!(
        rows,
        [("heart_rate".to_string(), BASE, 72, 1), ("stress".to_string(), BASE, 30, 1)]
    );
    let (reversed, _) = fold_live_readings(&[(2, bb), (1, a)]);
    assert_eq!(reversed[0], ("heart_rate".to_string(), BASE, 72, 2));
    assert_eq!(reversed[1].2, 30);

    // sentinels, ignored metrics
    let sentinels = vec![
        r(b, "heart_rate", 0),
        r(b, "stress", -1),
        r(b, "respiration_rate", -2),
        r(b, "spo2", 0),
        r(b, "energy_reserve", 101),
        r(b, "energy_reserve", -1),
        r(b, "steps", 500),
        r(b, "unknown", 1),
        r(b, "energy_reserve", 0),
        r(b, "stress", 0),
        // the upper bounds: a FIT uint8 never carries 0xFF, a percentage never 101 (review S3)
        r(b, "heart_rate", 255),
        r(b, "stress", 101),
        r(b, "respiration_rate", 255),
        r(b, "spo2", 101),
        r(b, "heart_rate", 254),
        r(b, "respiration_rate", 254),
        r(b, "spo2", 100),
        r(b, "stress", 100),
    ];
    let (rows, dropped) = fold_live_readings(&[(1, sentinels)]);
    assert_eq!(
        rows,
        [
            ("energy_reserve".to_string(), BASE, 0, 1),
            ("heart_rate".to_string(), BASE, 254, 1),
            ("respiration_rate".to_string(), BASE, 254, 1),
            ("spo2".to_string(), BASE, 100, 1),
            ("stress".to_string(), BASE, 0, 1)
        ]
    );
    let counts: Vec<(&str, i64)> = dropped.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    assert_eq!(
        counts,
        [
            ("live_energy_reserve_out_of_range", 2),
            ("live_heart_rate_zero", 2),
            ("live_respiration_sentinel", 2),
            ("live_spo2_off_wrist_or_zero", 2),
            ("live_stress_sentinel", 2),
        ]
    );
}

type Row = (String, String, f64, String, Option<String>, Option<String>);

fn live_rows(conn: &rusqlite::Connection) -> Vec<Row> {
    let mut stmt = conn
        .prepare(
            "SELECT metric, ts_utc, value, source_scope, device_id, \
             (SELECT source_key FROM raw_records r WHERE r.id=raw_record_id) \
             FROM metric_samples WHERE source_scope='live' ORDER BY metric, ts_utc",
        )
        .expect("prepare");
    stmt.query_map([], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?, x.get(4)?, x.get(5)?)))
        .expect("query")
        .map(|x| x.expect("row"))
        .collect()
}

fn sessions(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let (a_dir, b_dir, both) = (root.join("a"), root.join("b"), root.join("both"));
    for d in [&a_dir, &b_dir, &both] {
        fs::create_dir_all(d).expect("mkdir");
    }
    let mut a: Vec<Value> = (0..5)
        .map(|i| json!({"t": BASE as f64 + 60.0 * i as f64 + 0.5, "metric": "heart_rate", "value": 70 + i}))
        .collect();
    a.push(json!({"t": BASE + 1, "metric": "steps", "value": 100}));
    a.push(json!({"t": BASE + 2, "metric": "stress", "value": -1}));
    let mut b = a.clone();
    b.extend((5..9).map(|i| json!({"t": BASE + 60 * i, "metric": "heart_rate", "value": 70 + i})));
    b.push(json!({"t": BASE + 60 * 2 + 30, "metric": "heart_rate", "value": 99}));
    b.push(json!({"t": BASE + 3, "metric": "spo2", "value": 96}));
    write_session(&a_dir.join("live-a.jsonl"), &a);
    write_session(&b_dir.join("live-b.jsonl"), &b);
    fs::copy(a_dir.join("live-a.jsonl"), both.join("live-a.jsonl")).expect("copy");
    fs::copy(b_dir.join("live-b.jsonl"), both.join("live-b.jsonl")).expect("copy");
    (a_dir, b_dir, both)
}

#[test]
fn the_fold_is_the_same_in_every_order_and_after_a_reparse() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (a, b, both) = sessions(dir.path());
    let run = |name: &str, steps: &[&Path]| {
        let store = open(&dir.path().join(format!("{name}.db")));
        for step in steps {
            import_path(store.conn(), step, None, None).expect("import");
        }
        let rows = live_rows(store.conn());
        (store, rows)
    };
    let (_s1, ab) = run("ab", &[&a, &b]);
    let (_s2, ba) = run("ba", &[&b, &a]);
    let (_s3, sweep) = run("sweep", &[&both]);
    let (s4, _) = run("reparsed", &[&both]);
    s4.conn().execute("DELETE FROM metric_samples", []).expect("delete");
    let stats = reparse_all(s4.conn(), None, false).expect("reparse");
    assert_eq!(stats.files_failed, 0);
    let reparsed = live_rows(s4.conn());
    assert_eq!(ab, ba);
    assert_eq!(ab, sweep);
    assert_eq!(ab, reparsed);
    assert_eq!(ab.len(), 10);
    assert!(ab.iter().all(|row| row.3 == "live" && row.4.is_none() && row.5.is_some()));
    let hr: Vec<f64> = ab.iter().filter(|row| row.0 == "heart_rate").map(|row| row.2).collect();
    assert_eq!(hr, [70.0, 71.0, 72.0, 73.0, 74.0, 75.0, 76.0, 77.0, 78.0]);
}

#[test]
fn sentinel_drops_count_for_the_records_this_run_stored_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (a, b, _) = sessions(dir.path());
    let store = open(&dir.path().join("s.db"));
    let first = import_path(store.conn(), &a, None, None).expect("import");
    let second = import_path(store.conn(), &b, None, None).expect("import");
    let third = import_path(store.conn(), &a, None, None).expect("import");
    assert_eq!(first.dropped.into_iter().collect::<Vec<_>>(), [("live_stress_sentinel".to_string(), 1)]);
    assert_eq!(second.dropped.into_iter().collect::<Vec<_>>(), [("live_stress_sentinel".to_string(), 1)]);
    assert!(third.dropped.is_empty());
}

#[test]
fn health_keeps_live_apart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (a, _, _) = sessions(dir.path());
    let contract = Contract::get().expect("contract");
    let now = Utc.with_ymd_and_hms(2025, 6, 16, 12, 0, 0).unwrap();
    let store = open(&dir.path().join("s.db"));
    let empty = data_health(store.conn(), contract, 30, now).expect("health");
    assert_eq!(empty["live"], json!({"records": 0, "samples": 0, "first_day": null, "last_day": null}));
    import_path(store.conn(), &a, None, None).expect("import");
    let report = data_health(store.conn(), contract, 30, now).expect("health");
    assert_eq!(
        report["live"],
        json!({"records": 1, "samples": 5, "first_day": "2025-06-15", "last_day": "2025-06-15"})
    );
    let heart = report["metrics"].as_array().unwrap().iter().find(|m| m["metric"] == "heart_rate").unwrap();
    assert_eq!(heart["total"], Value::Null);
    assert_eq!(heart["days_in_window"], json!(0));
    // asked for the session scope alone and no end_date, the facts anchor on its newest day (review S1)
    let facts = period_facts(store.conn(), &FactsQuery::default()).expect("facts");
    assert_eq!(facts["reason"], json!("nothing stored yet"));
    let live_only = FactsQuery { source_scope: Some(PyStr::from_text("live")), ..FactsQuery::default() };
    let facts = period_facts(store.conn(), &live_only).expect("facts");
    assert_eq!(facts["as_of"], json!("2025-06-15"));
    assert_eq!(facts["facts"].as_array().unwrap().len(), 1);
    assert_eq!(facts["facts"][0]["metric"], json!("heart_rate"));
    // the default facts never see a session; naming the scope is the one way to its facts
    let query = FactsQuery { end_date: Some(PyStr::from_text("2025-06-16")), ..FactsQuery::default() };
    let facts = period_facts(store.conn(), &query).expect("facts");
    assert_eq!(facts["facts"], json!([]));
    let asked = FactsQuery { source_scope: Some(PyStr::from_text("live")), ..query };
    let facts = period_facts(store.conn(), &asked).expect("facts");
    let rows: Vec<(String, String, i64)> = facts["facts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["metric"].as_str().unwrap().to_string(),
                f["source_scope"].as_str().unwrap().to_string(),
                f["window_days_with_data"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(rows, vec![("heart_rate".to_string(), "live".to_string(), 1)]);
}

#[test]
fn a_reading_at_the_last_accepted_stamp_reads_back_at_a_plus_14_hour_offset() {
    // 9999-01-01T00:00:00Z, the number the Python twin derives; the last reading is 9998-12-31T23:59:59Z
    assert_eq!(T_LIMIT, 253_370_764_800);
    let dir = tempfile::tempdir().expect("tempdir");
    let folder = dir.path().join("late");
    fs::create_dir_all(&folder).expect("mkdir");
    write_session(&folder.join("live-late.jsonl"), &[json!({"t": T_LIMIT - 1, "metric": "heart_rate", "value": 61})]);
    let store = open(&dir.path().join("s.db"));
    import_path(store.conn(), &folder, None, None).expect("import");
    store
        .conn()
        .execute("INSERT INTO clock_offsets(ts_utc, offset_s) VALUES('2025-06-01T12:00:00Z', 50400)", [])
        .expect("offset");
    let contract = Contract::get().expect("contract");
    let day = live_day(store.conn(), contract, &PyStr::from_text("9999-01-01")).expect("data.live");
    assert_eq!(day["sessions"][0]["start_utc"], json!("9998-12-31T23:59:59Z"));
    assert_eq!(day["sessions"][0]["end_local"], json!("9999-01-01T13:59"));
    let heart = day["metrics"].as_array().unwrap().iter().find(|m| m["metric"] == "heart_rate").unwrap();
    assert_eq!(heart["minutes"], json!(1));
    assert_eq!(day["sessions"].as_array().map(Vec::len), Some(1));
    assert_eq!(day["sessions"][0]["minutes"], json!(1)); // 23:59:59 owns the folded minute 23:59
    let now = Utc.with_ymd_and_hms(2025, 6, 16, 12, 0, 0).unwrap();
    let report = data_health(store.conn(), contract, 30, now).expect("health");
    assert_eq!(report["live"]["last_day"], json!("9999-01-01"));
    // a store written before the bound was lowered may hold a span past it: data.live skips it instead of failing
    store
        .conn()
        .execute(
            "UPDATE raw_records SET start_utc='9999-12-31T23:59:59Z', end_utc='9999-12-31T23:59:59Z' \
             WHERE stream='json:live'",
            [],
        )
        .expect("legacy span");
    for asked in ["9999-01-01", "2025-06-15"] {
        let day = live_day(store.conn(), contract, &PyStr::from_text(asked)).expect("data.live skips the span");
        assert_eq!(day["sessions"], json!([]), "{asked}");
    }
}

#[test]
fn a_session_owns_the_minute_of_a_first_reading_off_the_minute() {
    // the fold floors readings to the minute, so a session starting at :10 owns that minute: readings at
    // 1750000030 and 1750000330 are 2 session minutes, as heart_rate says (Python twin: test_live_fold.py)
    let dir = tempfile::tempdir().expect("tempdir");
    let folder = dir.path().join("off");
    fs::create_dir_all(&folder).expect("mkdir");
    write_session(
        &folder.join("live-off.jsonl"),
        &[
            json!({"t": 1_750_000_030, "metric": "heart_rate", "value": 61}),
            json!({"t": 1_750_000_330, "metric": "heart_rate", "value": 62}),
        ],
    );
    let store = open(&dir.path().join("s.db"));
    import_path(store.conn(), &folder, None, None).expect("import");
    let contract = Contract::get().expect("contract");
    let day = live_day(store.conn(), contract, &PyStr::from_text("2025-06-15")).expect("data.live");
    assert_eq!(
        day["sessions"],
        json!([{"start_utc": "2025-06-15T15:07:10Z", "end_utc": "2025-06-15T15:12:10Z",
                "start_local": "2025-06-15T15:07", "end_local": "2025-06-15T15:12", "minutes": 2}])
    );
    let heart = day["metrics"].as_array().unwrap().iter().find(|m| m["metric"] == "heart_rate").unwrap();
    assert_eq!(heart["minutes"], json!(2));
}

#[test]
fn reads_at_the_calendar_ends_answer_empty_instead_of_overflowing() {
    // the over-fetch windows (-1 / +2 days) are clamped to 0001-01-01 .. 9999-12-31 (Python twin: test_live_fold.py)
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("s.db"));
    let contract = Contract::get().expect("contract");
    let offsets = load_offsets(store.conn()).expect("offsets");
    for edge in ["0001-01-01", "9999-12-31"] {
        let day = live_day(store.conn(), contract, &PyStr::from_text(edge)).expect("data.live");
        assert_eq!(day["sessions"], json!([]), "{edge}");
        assert!(day["metrics"].as_array().unwrap().iter().all(|m| m["minutes"] == json!(0)), "{edge}");
        let found =
            sample_day_aggregates(store.conn(), "heart_rate", edge, edge, &offsets, &["device".to_string()])
                .expect("aggregates");
        assert!(found.is_empty(), "{edge}");
    }
    let ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    let pair = |a: NaiveDate, b: NaiveDate| fetch_window(a, b);
    assert_eq!(pair(ymd(1, 1, 1), ymd(1, 1, 1)), ("0001-01-01".to_string(), "0001-01-03".to_string()));
    assert_eq!(pair(ymd(1, 1, 2), ymd(1, 1, 2)), ("0001-01-01".to_string(), "0001-01-04".to_string()));
    assert_eq!(pair(ymd(9999, 12, 31), ymd(9999, 12, 31)), ("9999-12-30".to_string(), "9999-12-31".to_string()));
    assert_eq!(pair(ymd(9999, 12, 30), ymd(9999, 12, 30)), ("9999-12-29".to_string(), "9999-12-31".to_string()));
    assert_eq!(pair(ymd(9999, 12, 29), ymd(9999, 12, 29)), ("9999-12-28".to_string(), "9999-12-31".to_string()));
    // the completeness day bounds: the midnight after 9999-12-31, and a local midnight before year 1 under a
    // positive offset, are plain integers (the opus review of 1e2d688 found `data.metric` at 9999-12-31 still internal)
    store
        .conn()
        .execute("INSERT INTO clock_offsets(ts_utc, offset_s) VALUES('2025-06-01T12:00:00Z', 45900)", [])
        .expect("offset");
    for edge in ["0001-01-01", "9999-12-31"] {
        let rows = calendar(store.conn(), contract, "heart_rate", "device", edge, edge).expect("calendar");
        assert_eq!(rows, vec![(edge.to_string(), NOT_COVERED, None)], "{edge}");
    }
}
