// SPDX-License-Identifier: AGPL-3.0-or-later
//! The writer surface the relay and the export ingest need (JSON records, `origin` passthrough,
//! `rewrite_canonical`, export ranges, parse-failure bounds), against the Python `Writer`'s SQL
//! semantics, in a scratch encrypted store with synthetic data only.

mod common;

use std::io::Read;

use common::{PASSPHRASE, encrypted_copy};
use disconect_core::canon::{self, Value};
use disconect_core::clock::ClockOffsets;
use disconect_core::keys::PassphraseSource;
use disconect_core::model::{
    ClockOffset, DailyFact, Decoded, Instant, Sample, SleepSession, SleepStage,
};
use disconect_core::store::{self, Store};
use disconect_core::time::parse_iso_utc;
use disconect_core::writer::{KeptRow, WriteOutcome, Writer, WriterError, json_summary};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

const FIT_FIXTURE: &str = "synthetic/skin_temp.fit.bin";

fn open() -> (tempfile::TempDir, Store) {
    let (dir, db) = encrypted_copy();
    let store = store::open_for_write(&db, "test", 5.0, PassphraseSource::Explicit(PASSPHRASE))
        .expect("open store");
    (dir, store)
}

fn writer<'c>(conn: &'c Connection, transport: &str) -> Writer<'c> {
    let mut writer = Writer::new(conn, ClockOffsets::load(conn).expect("offsets"), transport);
    writer.begin_run().expect("begin run");
    writer
}

fn at(text: &str) -> Instant {
    parse_iso_utc(text).expect("instant")
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).expect("count")
}

fn record(text: &str) -> Value {
    canon::parse(text.as_bytes()).expect("record")
}

/// One day's facts: a daily value, a sample, a sleep session with two stages and a clock offset.
fn decoded_for(day: &str, value: f64) -> Decoded {
    let mut decoded = Decoded::new("json:uds", "vendor_cloud");
    let noon = at(&format!("{day}T12:00:00Z"));
    decoded.start_utc = Some(noon);
    decoded.end_utc = Some(noon);
    decoded.daily.push(DailyFact {
        metric: "steps".into(),
        value,
        ts_utc: None,
        date: Some(day.into()),
    });
    decoded.samples.push(Sample {
        metric: "heart_rate".into(),
        ts_utc: noon,
        value,
    });
    decoded.sleep = Some(SleepSession {
        date: Some(day.into()),
        end_utc: Some(noon),
        stages: vec![
            SleepStage {
                stage: "light".into(),
                start_utc: at(&format!("{day}T01:00:00Z")),
                end_utc: at(&format!("{day}T02:00:00Z")),
            },
            SleepStage {
                stage: "deep".into(),
                start_utc: at(&format!("{day}T02:00:00Z")),
                end_utc: at(&format!("{day}T03:00:00Z")),
            },
        ],
        ..SleepSession::default()
    });
    decoded.offsets.push(ClockOffset {
        ts_utc: noon,
        offset_s: 7200,
    });
    decoded.dropped.insert("sentinel".into(), 2);
    decoded.warnings = (0..12).map(|i| format!("w{i}")).collect();
    decoded
}

fn rows_of(conn: &Connection, raw_id: i64) -> [i64; 6] {
    [
        "metric_samples",
        "daily_metrics",
        "sleep_sessions",
        "clock_offsets",
        "daily_labels",
        "monitoring_intervals",
    ]
    .map(|table| {
        count(
            conn,
            &format!("SELECT count(*) FROM {table} WHERE raw_record_id={raw_id}"),
        )
    })
}

fn raw_id_of(conn: &Connection, key: &str) -> i64 {
    conn.query_row(
        "SELECT id FROM raw_records WHERE source_key=?",
        [key],
        |r| r.get(0),
    )
    .expect("raw id")
}

#[test]
fn json_record_is_stored_as_canonical_bytes_and_a_known_key_adds_nothing() {
    let (_dir, store) = open();
    let conn = store.conn();
    let mut w = writer(conn, "connect_export");
    let first = record(r#"{"zeta": 1.0, "alpha": {"b": "é", "a": [2, 1]}}"#);
    let decoded = decoded_for("2025-06-15", 10.0);
    let outcome = w
        .write_json_record("json:uds", "2025-06-15", &first, &decoded, "label", None)
        .expect("write");
    assert_eq!(outcome, WriteOutcome::Imported);
    let expected_bytes = b"{\"alpha\":{\"a\":[2,1],\"b\":\"\\u00e9\"},\"zeta\":1.0}";
    let (kind, scope, transport, packed, hash, size, summary): (String, String, String, Vec<u8>, String, i64, String) = conn
        .query_row(
            "SELECT payload_kind, source_scope, transport, payload, payload_hash, payload_bytes, decode_summary FROM raw_records",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
        )
        .expect("raw row");
    assert_eq!(
        (kind.as_str(), scope.as_str(), transport.as_str()),
        ("json", "vendor_cloud", "connect_export")
    );
    let mut bytes = Vec::new();
    flate2::read::ZlibDecoder::new(packed.as_slice())
        .read_to_end(&mut bytes)
        .expect("inflate");
    assert_eq!(bytes, expected_bytes);
    assert_eq!(hash, hex::encode(Sha256::digest(expected_bytes)));
    assert_eq!(size, expected_bytes.len() as i64);
    // Python: json.dumps({"dropped": {"sentinel": 2}, "warnings": warnings[:10]}, sort_keys=True)
    assert_eq!(
        summary,
        r#"{"dropped": {"sentinel": 2}, "warnings": ["w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9"]}"#
    );
    assert_eq!(
        (
            w.stats.files_seen,
            w.stats.files_imported,
            w.stats.files_duplicate
        ),
        (1, 1, 0)
    );
    assert!(w.stats.records_written > 0);

    // The same (stream, key) with different bytes is a duplicate: nothing new, nothing replaced.
    let other = record(r#"{"different": true}"#);
    let again = w
        .write_json_record(
            "json:uds",
            "2025-06-15",
            &other,
            &decoded_for("2025-06-16", 3.0),
            "label",
            None,
        )
        .expect("write");
    assert_eq!(again, WriteOutcome::Duplicate);
    assert_eq!(count(conn, "SELECT count(*) FROM raw_records"), 1);
    assert_eq!(
        count(
            conn,
            "SELECT count(*) FROM daily_metrics WHERE date='2025-06-16'"
        ),
        0
    );
    assert_eq!(
        (
            w.stats.files_seen,
            w.stats.files_imported,
            w.stats.files_duplicate
        ),
        (2, 1, 1)
    );

    // The key is per stream: the same text under another stream is a new record.
    let third = w
        .write_json_record(
            "json:sleep",
            "2025-06-15",
            &first,
            &Decoded::new("json:sleep", "vendor_cloud"),
            "label",
            None,
        )
        .expect("write");
    assert_eq!(third, WriteOutcome::Imported);
    assert_eq!(count(conn, "SELECT count(*) FROM raw_records"), 2);
    let parse_ok: i64 = count(
        conn,
        "SELECT files_ok FROM stream_provenance WHERE stream='json:uds'",
    );
    assert_eq!(parse_ok, 1);
}

#[test]
fn origin_is_kept_for_json_and_fit_records() {
    let (_dir, store) = open();
    let conn = store.conn();
    let mut w = writer(conn, "drop");
    let origin = Some(("usb", "2024-01-02T03:04:05Z"));
    w.write_json_record(
        "json:uds",
        "k",
        &record("{}"),
        &decoded_for("2025-06-15", 1.0),
        "l",
        origin,
    )
    .expect("json");
    let fit = std::fs::read(common::fixtures().join(FIT_FIXTURE)).expect("fit fixture");
    assert_eq!(
        w.write_fit(&fit, "fit", origin).expect("fit"),
        WriteOutcome::Imported
    );
    let rows: Vec<(String, String)> = conn
        .prepare("SELECT transport, imported_at FROM raw_records")
        .and_then(|mut s| s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect())
        .expect("rows");
    assert_eq!(
        rows,
        vec![("usb".to_string(), "2024-01-02T03:04:05Z".to_string()); 2]
    );
    // No origin: the run's transport and now.
    let mut w = writer(conn, "ciq");
    w.write_json_record(
        "json:uds",
        "k2",
        &record("{}"),
        &decoded_for("2025-06-16", 1.0),
        "l",
        None,
    )
    .expect("json");
    let transport: String = conn
        .query_row(
            "SELECT transport FROM raw_records WHERE source_key='k2'",
            [],
            |r| r.get(0),
        )
        .expect("t");
    assert_eq!(transport, "ciq");
}

#[test]
fn last_raw_id_follows_the_highest_id() {
    let (_dir, store) = open();
    let conn = store.conn();
    let mut w = writer(conn, "drop");
    assert_eq!(w.last_raw_id().expect("empty"), 0);
    w.write_json_record(
        "json:uds",
        "a",
        &record("{}"),
        &decoded_for("2025-06-15", 1.0),
        "l",
        None,
    )
    .expect("a");
    w.write_json_record(
        "json:uds",
        "b",
        &record("{}"),
        &decoded_for("2025-06-16", 1.0),
        "l",
        None,
    )
    .expect("b");
    assert_eq!(w.last_raw_id().expect("two"), raw_id_of(conn, "b"));
    assert_eq!(w.last_raw_id().expect("two"), 2);
}

#[test]
fn export_range_is_idempotent_and_keeps_the_first_run() {
    let (_dir, store) = open();
    let conn = store.conn();
    let first = writer(conn, "connect_export");
    first
        .record_export_range("json:uds", "2025-01-01", "2025-03-31")
        .expect("range");
    first
        .record_export_range("json:uds", "2025-01-01", "2025-03-31")
        .expect("again");
    let first_run: i64 = conn
        .query_row("SELECT run_id FROM export_ranges", [], |r| r.get(0))
        .expect("run");
    let second = writer(conn, "connect_export");
    second
        .record_export_range("json:uds", "2025-01-01", "2025-03-31")
        .expect("other run, same window");
    second
        .record_export_range("json:uds", "2025-04-01", "2025-06-30")
        .expect("new window");
    second
        .record_export_range("json:sleep", "2025-01-01", "2025-03-31")
        .expect("other stream");
    assert_eq!(count(conn, "SELECT count(*) FROM export_ranges"), 3);
    let kept: i64 = conn
        .query_row(
            "SELECT run_id FROM export_ranges WHERE stream='json:uds' AND from_day='2025-01-01'",
            [],
            |r| r.get(0),
        )
        .expect("kept");
    assert_eq!(
        kept, first_run,
        "the run that first recorded a window owns it"
    );
}

#[test]
fn rewrite_canonical_replaces_every_row_of_that_raw_id_and_nothing_else() {
    let (_dir, store) = open();
    let conn = store.conn();
    let mut w = writer(conn, "connect_export");
    w.write_json_record(
        "json:uds",
        "A",
        &record(r#"{"id": "A"}"#),
        &decoded_for("2025-06-15", 10.0),
        "l",
        None,
    )
    .expect("A");
    w.write_json_record(
        "json:uds",
        "B",
        &record(r#"{"id": "B"}"#),
        &decoded_for("2025-06-16", 20.0),
        "l",
        None,
    )
    .expect("B");
    let (a, b) = (raw_id_of(conn, "A"), raw_id_of(conn, "B"));
    assert_eq!(rows_of(conn, a), [1, 1, 1, 1, 0, 0]);
    assert_eq!(count(conn, "SELECT count(*) FROM sleep_stages"), 4);
    let b_before = rows_of(conn, b);

    // New facts for A: another day, a label, no sleep, no offset.
    let mut fresh = Decoded::new("json:uds", "vendor_cloud");
    fresh.daily.push(DailyFact {
        metric: "steps".into(),
        value: 99.0,
        ts_utc: None,
        date: Some("2025-06-14".into()),
    });
    fresh.labels.push(disconect_core::model::DailyLabel {
        metric: "level".into(),
        label: "high".into(),
        ts_utc: None,
        date: Some("2025-06-14".into()),
    });
    let summary = json_summary(&fresh);
    let before_imported = w.stats.files_imported;
    let outcome = w
        .rewrite_canonical(a, "json:uds", &fresh, &summary)
        .expect("rewrite");
    assert_eq!(outcome, WriteOutcome::Reparsed);
    assert_eq!(rows_of(conn, a), [0, 1, 0, 0, 1, 0]);
    assert_eq!(
        count(
            conn,
            "SELECT count(*) FROM daily_metrics WHERE date='2025-06-15'"
        ),
        0,
        "A's old day is gone"
    );
    assert_eq!(
        count(
            conn,
            "SELECT count(*) FROM daily_metrics WHERE date='2025-06-14' AND value=99.0"
        ),
        1
    );
    assert_eq!(
        count(conn, "SELECT count(*) FROM sleep_stages"),
        2,
        "only B's stages remain"
    );
    assert_eq!(rows_of(conn, b), b_before, "B is untouched");
    let summary_text: String = conn
        .query_row(
            "SELECT decode_summary FROM raw_records WHERE id=?",
            [a],
            |r| r.get(0),
        )
        .expect("summary");
    assert_eq!(summary_text, r#"{"dropped": {}, "warnings": []}"#);
    // The raw record itself is kept as it was.
    assert_eq!(count(conn, "SELECT count(*) FROM raw_records"), 2);
    assert_eq!(w.stats.files_imported, before_imported + 1);
    assert_eq!(
        count(
            conn,
            "SELECT count(*) FROM stream_provenance WHERE stream='json:uds' AND files_ok >= 3"
        ),
        1
    );
}

#[test]
fn a_failed_rewrite_rolls_back_and_is_booked_as_a_storage_failure() {
    let (_dir, store) = open();
    let conn = store.conn();
    let mut w = writer(conn, "connect_export");
    w.write_json_record(
        "json:uds",
        "A",
        &record("{}"),
        &decoded_for("2025-06-15", 10.0),
        "l",
        None,
    )
    .expect("A");
    let a = raw_id_of(conn, "A");
    let before = rows_of(conn, a);
    // Break the last table the delete touches; the earlier deletes must be undone.
    conn.execute_batch("DROP TABLE clock_offsets")
        .expect("drop");
    let mut fresh = Decoded::new("json:uds", "vendor_cloud");
    fresh.daily.push(DailyFact {
        metric: "steps".into(),
        value: 1.0,
        ts_utc: None,
        date: Some("2025-07-01".into()),
    });
    let outcome = w
        .rewrite_canonical(a, "json:uds", &fresh, &json_summary(&fresh))
        .expect("rewrite");
    assert_eq!(outcome, WriteOutcome::Failed);
    let after = rows_of_without_offsets(conn, a);
    assert_eq!(
        after,
        [before[0], before[1], before[2]],
        "previous canonical rows intact"
    );
    assert_eq!(count(conn, "SELECT count(*) FROM sleep_stages"), 2);
    assert_eq!(w.stats.files_failed, 1);
    assert_eq!(
        (
            w.stats.failures[0].kind.as_str(),
            w.stats.failures[0].file.as_str()
        ),
        ("storage", format!("raw_record:{a}").as_str())
    );
    assert_eq!(
        count(
            conn,
            "SELECT files_failed FROM stream_provenance WHERE stream='json:uds'"
        ),
        1
    );
}

fn rows_of_without_offsets(conn: &Connection, raw_id: i64) -> [i64; 3] {
    ["metric_samples", "daily_metrics", "sleep_sessions"].map(|table| {
        count(
            conn,
            &format!("SELECT count(*) FROM {table} WHERE raw_record_id={raw_id}"),
        )
    })
}

#[test]
fn delete_canonical_for_raw_clears_stages_and_keeps_the_raw_record() {
    let (_dir, store) = open();
    let conn = store.conn();
    let mut w = writer(conn, "connect_export");
    w.write_json_record(
        "json:uds",
        "A",
        &record("{}"),
        &decoded_for("2025-06-15", 10.0),
        "l",
        None,
    )
    .expect("A");
    w.write_json_record(
        "json:uds",
        "B",
        &record("{}"),
        &decoded_for("2025-06-16", 10.0),
        "l",
        None,
    )
    .expect("B");
    w.delete_canonical_for_raw(raw_id_of(conn, "A"))
        .expect("delete");
    assert_eq!(rows_of(conn, raw_id_of(conn, "A")), [0; 6]);
    assert_eq!(count(conn, "SELECT count(*) FROM sleep_stages"), 2);
    assert_eq!(count(conn, "SELECT count(*) FROM sleep_sessions"), 1);
    assert_eq!(count(conn, "SELECT count(*) FROM raw_records"), 2);
}

#[test]
fn parse_failures_carry_the_given_hash_bounds_and_raw_record() {
    let (_dir, store) = open();
    let conn = store.conn();
    let mut w = writer(conn, "connect_export");
    w.write_json_record(
        "json:uds",
        "A",
        &record("{}"),
        &decoded_for("2025-06-15", 10.0),
        "l",
        None,
    )
    .expect("A");
    let a = raw_id_of(conn, "A");
    let hash = hex::encode(Sha256::digest(b"not json"));
    let (start, end) = (at("2025-02-01T12:00:00Z"), at("2025-02-28T12:00:00Z"));
    w.record_parse_failure(
        "json:uds",
        "export/file",
        "bad_json",
        "not valid",
        Some(start),
        Some(end),
        None,
        Some(&hash),
        true,
    )
    .expect("failure");
    w.record_parse_failure(
        "json:uds",
        "export/other",
        "decode",
        "no facts",
        None,
        None,
        Some(a),
        None,
        true,
    )
    .expect("failure");
    w.record_parse_failure(
        "json:sleep",
        "export/third",
        "bad_json",
        "unplaced",
        None,
        None,
        None,
        Some("hash-3"),
        false,
    )
    .expect("failure");
    // The same bytes fail once in the ledger, though the run counts both attempts.
    w.record_parse_failure(
        "json:uds",
        "export/file",
        "bad_json",
        "not valid",
        Some(start),
        Some(end),
        None,
        Some(&hash),
        true,
    )
    .expect("failure");
    assert_eq!(w.stats.files_failed, 4);
    assert_eq!(w.stats.failures.len(), 4);
    assert_eq!(count(conn, "SELECT count(*) FROM import_failures"), 3);
    type Row = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        String,
    );
    let rows: Vec<Row> = conn
        .prepare("SELECT stream, start_utc, end_utc, raw_record_id, payload_hash, kind FROM import_failures ORDER BY id")
        .and_then(|mut s| s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?.collect())
        .expect("rows");
    assert_eq!(
        rows[0],
        (
            Some("json:uds".into()),
            Some("2025-02-01T12:00:00Z".into()),
            Some("2025-02-28T12:00:00Z".into()),
            None,
            Some(hash),
            "bad_json".into()
        )
    );
    assert_eq!(
        rows[1],
        (
            Some("json:uds".into()),
            None,
            None,
            Some(a),
            None,
            "decode".into()
        )
    );
    assert_eq!(
        rows[2],
        (
            None,
            None,
            None,
            None,
            Some("hash-3".into()),
            "bad_json".into()
        )
    );
    assert_eq!(
        count(
            conn,
            "SELECT files_failed FROM stream_provenance WHERE stream='json:uds'"
        ),
        3
    );
}

#[test]
fn a_kept_records_span_stamp_strptime_refuses_is_bad_stamp_with_its_text() {
    // the oracle's keep_undecodable_record raises strptime's ValueError, uncaught, with this text
    let (_dir, store) = open();
    let conn = store.conn();
    let mut writer = writer(conn, "relay");
    let row = KeptRow { source_scope: "", device_id: None, start_utc: Some("2025-06-15 00:00:00"), end_utc: None };
    let outcome = writer.keep_undecodable_record("json:unknown", "k1", &row, b"{}", "label", None, None);
    match outcome {
        Err(WriterError::BadStamp(text)) => {
            assert_eq!(text, "time data '2025-06-15 00:00:00' does not match format '%Y-%m-%dT%H:%M:%SZ'")
        }
        other => panic!("expected BadStamp, got {other:?}"),
    }
}
