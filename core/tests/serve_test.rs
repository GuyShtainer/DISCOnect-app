// SPDX-License-Identifier: AGPL-3.0-or-later
//! `serve` in-process: the protocol envelope and the start-up methods against the oracle's behaviour
//! (`disconect/tests/test_serve.py`), plus source-level rules that keep the transport honest.
//! Nothing here reaches the OS keychain: encrypted-store cases that would are process-level tests
//! with the keychain disabled (`serve_process_test.rs`).

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::{PASSPHRASE, encrypted_copy};
use disconect_core::keys::PassphraseSource;
use disconect_core::read::DEFERRED_METHODS;
use disconect_core::serve::{self, Channel, METHODS, Session};
use disconect_core::store;
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer").extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Rig {
    session: Session,
    out: Buffer,
}

impl Rig {
    fn new(db: &std::path::Path) -> Rig {
        let out = Buffer::default();
        Rig {
            session: Session::new(db.to_path_buf(), Channel::new(Box::new(out.clone()))),
            out,
        }
    }

    /// Feed raw input; return every line written, parsed.
    fn feed(&mut self, input: &[u8]) -> Vec<Value> {
        assert_eq!(serve::serve_lines(&mut self.session, input), 0);
        let bytes = std::mem::take(&mut *self.out.0.lock().expect("buffer"));
        String::from_utf8(bytes)
            .expect("ascii output")
            .lines()
            .map(|l| serde_json::from_str(l).expect("protocol line"))
            .collect()
    }

    fn send(&mut self, method: &str, params: Value) -> Value {
        let mut lines = self
            .feed(format!("{}\n", json!({"id": 1, "method": method, "params": params})).as_bytes());
        assert_eq!(lines.len(), 1);
        lines.remove(0)
    }

    fn code(&mut self, method: &str, params: Value) -> String {
        let reply = self.send(method, params);
        assert!(reply.get("result").is_none(), "{reply}");
        reply["error"]["code"].as_str().expect("code").to_string()
    }
}

fn plain_store() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("plain.db");
    store::open_for_write(&db, "test", 1.0, PassphraseSource::Explicit("unused"))
        .expect("create store");
    (dir, db)
}

#[test]
fn app_info_names_the_product_the_notice_and_this_core() {
    let (_dir, db) = plain_store();
    let info = Rig::new(&db).send("app.info", json!({}))["result"].clone();
    assert_eq!(info["product"], "DISCOnect");
    assert_eq!(
        info["notice"],
        "Not affiliated with or endorsed by any watch manufacturer."
    );
    assert_eq!(info["encrypted"], false);
    assert_eq!(info["db"], db.to_string_lossy().as_ref());
    assert_eq!(info["contract"], 2);
    assert_eq!(info["schema"], store::SCHEMA_VERSION);
    assert!(
        info["core"]
            .as_str()
            .expect("core")
            .starts_with("disconect-core/")
    );
    let keys: Vec<&str> = info
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.len(), 7);
}

#[test]
fn malformed_and_unknown_requests_get_error_lines() {
    let (_dir, db) = plain_store();
    let lines = Rig::new(&db).feed(
        concat!(
            "not json\n[1]\n{\"id\":true,\"method\":\"app.info\"}\n{\"id\":7,\"method\":5}\n",
            "{\"id\":8,\"method\":\"no.such\"}\n\n{\"id\":\"x\",\"method\":\"app.info\",\"params\":[]}\n"
        )
        .as_bytes(),
    );
    let codes: Vec<(Value, &str)> = lines
        .iter()
        .map(|l| (l["id"].clone(), l["error"]["code"].as_str().expect("code")))
        .collect();
    assert_eq!(
        codes,
        [
            (Value::Null, "bad_params"),
            (Value::Null, "bad_params"),
            (Value::Null, "bad_params"),
            (json!(7), "bad_params"),
            (json!(8), "unknown_method"),
            (json!("x"), "bad_params"),
        ]
    );
}

#[test]
fn string_ids_round_trip_and_blank_lines_are_skipped() {
    let (_dir, db) = plain_store();
    let lines = Rig::new(&db).feed(b"\n   \n{\"id\":\"abc\",\"method\":\"app.info\"}\n");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["id"], "abc");
    assert!(lines[0].get("result").is_some());
}

#[test]
fn the_last_line_needs_no_newline_and_a_cr_is_just_whitespace() {
    let (_dir, db) = plain_store();
    let lines = Rig::new(&db)
        .feed(b"{\"id\":1,\"method\":\"key.status\"}\r\n{\"id\":2,\"method\":\"key.status\"}");
    assert_eq!(
        lines.iter().map(|l| l["id"].clone()).collect::<Vec<_>>(),
        [json!(1), json!(2)]
    );
    let lines = Rig::new(&db)
        .feed(b"{\"id\":1,\"method\":\"key.status\"}\r{\"id\":2,\"method\":\"key.status\"}\n");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["error"]["message"], "request is not valid JSON");
}

#[test]
fn invalid_utf8_becomes_a_replacement_character_in_the_echoed_id() {
    let (_dir, db) = plain_store();
    let lines = Rig::new(&db).feed(b"{\"id\":\"\xff\",\"method\":\"key.status\"}\n");
    assert_eq!(lines[0]["id"], "\u{fffd}");
}

#[test]
fn big_and_odd_ids_are_echoed_digit_for_digit() {
    let (_dir, db) = plain_store();
    let mut rig = Rig::new(&db);
    // serde_json would turn the first id into a float, so read the raw bytes the core wrote
    assert_eq!(
        serve::serve_lines(
            &mut rig.session,
            &b"{\"id\":123456789012345678901234567890,\"method\":\"no.such\"}\n{\"id\":-0,\"method\":\"no.such\"}\n"[..]
        ),
        0
    );
    let raw = String::from_utf8(rig.out.0.lock().expect("buffer").clone()).expect("utf8");
    let ids: Vec<&str> = raw
        .lines()
        .map(|l| l.split(',').next().unwrap_or(""))
        .collect();
    assert_eq!(ids, ["{\"id\":123456789012345678901234567890", "{\"id\":0"]);
}

#[test]
fn a_plaintext_store_has_nothing_to_unlock_nothing_to_cache_and_is_open() {
    let (_dir, db) = plain_store();
    let mut rig = Rig::new(&db);
    assert_eq!(
        rig.code("key.unlock", json!({"passphrase": PASSPHRASE})),
        "not_encrypted"
    );
    assert_eq!(rig.code("key.unlock", json!({})), "not_encrypted");
    assert_eq!(
        rig.code("key.cache", json!({"enable": true})),
        "not_encrypted"
    );
    assert_eq!(rig.code("key.cache", json!({})), "bad_params");
    assert_eq!(
        rig.code("key.cache", json!({"enable": "yes"})),
        "bad_params"
    );
    assert_eq!(
        rig.code("key.unlock", json!({"passphrase": 12345})),
        "bad_params"
    );
    let status = rig.send("key.status", json!({}))["result"].clone();
    assert_eq!(
        status,
        json!({"key_file": false, "encrypted": false, "unlocked": true, "keychain": "absent", "kdf": null})
    );
}

#[test]
fn locked_until_unlocked_then_unlocked() {
    let (_dir, db) = encrypted_copy();
    let mut rig = Rig::new(&db);
    assert_eq!(rig.code("key.cache", json!({"enable": true})), "locked");
    assert_eq!(
        rig.code(
            "key.unlock",
            json!({"passphrase": "not the passphrase at all!"})
        ),
        "wrong_passphrase"
    );
    assert_eq!(
        rig.code("key.unlock", json!({"passphrase": "abc\u{e9}"})),
        "wrong_passphrase"
    );
    assert_eq!(
        rig.send("key.unlock", json!({"passphrase": PASSPHRASE}))["result"],
        json!({"unlocked": true})
    );
    assert_eq!(rig.code("key.cache", json!({"enable": "no"})), "bad_params");
}

#[test]
fn key_lock_drops_the_master_and_is_idempotent() {
    let (_dir, db) = encrypted_copy();
    let mut rig = Rig::new(&db);
    let locked = json!({"state": "locked"});
    assert_eq!(rig.send("key.lock", json!({}))["result"], locked, "already locked");
    rig.send("key.unlock", json!({"passphrase": PASSPHRASE}));
    assert_eq!(rig.send("key.status", json!({}))["result"]["unlocked"], true);
    assert_eq!(rig.send("key.lock", json!({"x": 1}))["result"], locked, "params are ignored");
    assert_eq!(rig.send("key.status", json!({}))["result"]["unlocked"], false);
    assert_eq!(rig.code("sync.status", json!({})), "locked");
    assert_eq!(rig.code("import.cancel", json!({})), "locked");
    assert_eq!(rig.code("key.cache", json!({"enable": true})), "locked");
    assert_eq!(rig.send("key.lock", json!({}))["result"], locked, "twice");
    assert_eq!(rig.send("key.unlock", json!({"passphrase": PASSPHRASE}))["result"], json!({"unlocked": true}));
    assert_eq!(rig.send("key.status", json!({}))["result"]["unlocked"], true, "unlock works again");
}

#[test]
fn the_lone_surrogate_passphrase_is_bad_params_like_the_encoder_error() {
    let (_dir, db) = encrypted_copy();
    let mut rig = Rig::new(&db);
    let out = rig
        .feed(b"{\"id\":1,\"method\":\"key.unlock\",\"params\":{\"passphrase\":\"abc\\ud800\"}}\n");
    assert_eq!(out[0]["error"]["code"], "bad_params");
    assert_eq!(
        out[0]["error"]["message"],
        "'utf-8' codec can't encode character '\\ud800' in position 3: surrogates not allowed"
    );
}

#[test]
fn the_methods_table_and_the_deferred_list_partition_the_protocol() {
    let ported: Vec<&str> = METHODS.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        ported,
        [
            "app.info",
            "key.status",
            "key.unlock",
            "key.cache",
            "key.lock",
            "data.health",
            "data.metric",
            "data.today",
            "data.live",
            "data.sleep",
            "data.contract",
            "data.facts",
            "import.run",
            "import.last",
            "import.cancel",
            "sync.status",
            "sync.run",
            "relay.addresses",
            "relay.serve",
            "pair.offer",
            "pair.confirm",
            "pair.cancel",
            "tools.call",
            // 12-F: the phone's own method; every core that is not a phone refuses it (`serve_forget_test`)
            "pair.forget",
            // 12-F row 3: the phone as the pairing joiner; every core that is not a phone refuses after the prefix
            "pair.join",
            "pair.land"
        ]
    );
    assert!(DEFERRED_METHODS.is_empty(), "slice 3D ported the last deferred methods");
    for name in DEFERRED_METHODS {
        assert!(
            !ported.contains(name),
            "{name} is deferred, so it must not be in METHODS"
        );
    }
    let (_dir, db) = plain_store();
    let mut rig = Rig::new(&db);
    for name in DEFERRED_METHODS {
        let reply = rig.send(name, json!({}));
        assert_eq!(reply["error"]["code"], "unknown_method", "{name}");
        assert_eq!(reply["error"]["message"], "no such method");
    }
}

// ---- data.live ----

fn live_copy() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("live.db");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../disconect/tests/fixtures/serve/synthetic-live.hbdb");
    std::fs::copy(source, &db).expect("copy the committed live store");
    (dir, db)
}

fn live_minutes(result: &Value, metric: &str) -> (i64, Value) {
    let item = result["metrics"]
        .as_array()
        .expect("metrics")
        .iter()
        .find(|m| m["metric"] == metric)
        .expect("metric listed");
    (item["minutes"].as_i64().expect("minutes"), item["median"].clone())
}

#[test]
fn live_day_merges_overlapping_files_and_keeps_a_midnight_session_on_one_local_day() {
    let (_dir, db) = live_copy();
    let mut rig = Rig::new(&db);
    // 2025-06-15: a partial file (10:00-10:09) stored before the full one (10:00-10:13) is one session
    // (the store's watch clock runs +3 h, so the local times differ from the UTC ones)
    let day = rig.send("data.live", json!({"day": "2025-06-15"}))["result"].clone();
    assert_eq!(
        day["sessions"],
        json!([{"start_utc": "2025-06-15T10:00:00Z", "end_utc": "2025-06-15T10:13:00Z",
                "start_local": "2025-06-15T13:00", "end_local": "2025-06-15T13:13", "minutes": 14}])
    );
    assert_eq!(live_minutes(&day, "heart_rate"), (14, json!(96.0)));
    assert_eq!(live_minutes(&day, "spo2"), (1, json!(97.0)));
    // 2025-06-20 23:55Z -> 06-21 00:05Z crosses UTC midnight but not the watch's (+3:30 there): one local day
    assert_eq!(rig.send("data.live", json!({"day": "2025-06-20"}))["result"]["sessions"], json!([]));
    let after = rig.send("data.live", json!({"day": "2025-06-21"}))["result"].clone();
    assert_eq!(
        after["sessions"],
        json!([{"start_utc": "2025-06-20T23:55:00Z", "end_utc": "2025-06-21T00:05:00Z",
                "start_local": "2025-06-21T03:25", "end_local": "2025-06-21T03:35", "minutes": 11}])
    );
    assert_eq!(live_minutes(&after, "heart_rate"), (11, json!(65.0)));
    assert_eq!(live_minutes(&after, "spo2").0, 0);
}

#[test]
fn live_day_of_a_watch_behind_utc_is_the_local_day_not_the_utc_day() {
    // `day` is the date on the watch's own clock (the stated offset nearest the session's start/end), never
    // the UTC date. The store's watch ran -05:00 from 1 March to 10 April: a session at 2025-03-06T01:00:30Z..01:05:30Z
    // is the evening of 5 March there, so it is reported on the 5th and the UTC day (the 6th) lists nothing.
    let (_dir, db) = live_copy();
    let mut rig = Rig::new(&db);
    let utc_day = rig.send("data.live", json!({"day": "2025-03-06"}))["result"].clone();
    assert_eq!(utc_day["sessions"], json!([]));
    assert_eq!(live_minutes(&utc_day, "heart_rate").0, 0);
    let evening = rig.send("data.live", json!({"day": "2025-03-05"}))["result"].clone();
    assert_eq!(
        evening["sessions"],
        json!([{"start_utc": "2025-03-06T01:00:30Z", "end_utc": "2025-03-06T01:05:30Z",
                "start_local": "2025-03-05T20:00", "end_local": "2025-03-05T20:05", "minutes": 6}])
    );
    assert_eq!(live_minutes(&evening, "heart_rate"), (6, json!(72.0)));
}

// ---- data.sleep ----

fn stages_local(session: &Value) -> Vec<(String, String)> {
    session["stages"]
        .as_array()
        .expect("stages")
        .iter()
        .map(|g| {
            (
                g["start_local"].as_str().expect("start_local").to_string(),
                g["end_local"].as_str().expect("end_local").to_string(),
            )
        })
        .collect()
}

fn pair(a: &str, b: &str) -> (String, String) {
    (a.to_string(), b.to_string())
}

#[test]
fn sleep_night_latest_and_named_in_the_watchs_own_clock() {
    let (_dir, db) = live_copy();
    let mut rig = Rig::new(&db);
    let latest = rig.send("data.sleep", json!({}))["result"].clone();
    assert_eq!(latest["date"], "2025-06-30");
    // the offset nearest the session's end (04:00Z on 06-30) is the +03:30 one stored on 06-20
    let device = &latest["sessions"][0];
    assert_eq!(latest["sessions"].as_array().expect("sessions").len(), 1);
    assert_eq!(device["utc_offset_s"], 12600);
    assert_eq!(stages_local(device), [pair("00:30", "01:30")]);
    let named = rig.send("data.sleep", json!({"date": "2025-06-15"}))["result"].clone();
    let scopes: Vec<&str> = named["sessions"]
        .as_array()
        .expect("sessions")
        .iter()
        .map(|s| s["source_scope"].as_str().expect("scope"))
        .collect();
    assert_eq!(scopes, ["device", "vendor_cloud"]);
    assert_eq!(named["sessions"][0]["utc_offset_s"], 10800);
    assert_eq!(
        stages_local(&named["sessions"][0]),
        [pair("23:00", "00:00"), pair("00:00", "02:00"), pair("02:00", "06:00")]
    );
    // scores only: the offset, no stage keys
    assert!(named["sessions"][1].get("stages").is_none());
    assert_eq!(named["sessions"][1]["utc_offset_s"], 10800);
}

#[test]
fn sleep_night_with_no_record_or_no_sleep_says_why() {
    let (_dir, db) = live_copy();
    let mut rig = Rig::new(&db);
    let none = rig.send("data.sleep", json!({"date": "2025-06-20"}))["result"].clone();
    assert_eq!(none["sessions"], json!([]));
    assert_eq!(none["reason"], "no record of that night from any source");
    assert_eq!(none["date"], "2025-06-20");
    assert!(none.get("units").is_some());
    rusqlite::Connection::open(&db)
        .expect("open")
        .execute("DELETE FROM sleep_sessions", [])
        .expect("delete");
    let empty = Rig::new(&db).send("data.sleep", json!({}))["result"].clone();
    assert_eq!(empty["date"], Value::Null);
    assert_eq!(empty["reason"], "no sleep stored yet");
}

#[test]
fn sleep_night_bad_date_is_bad_params() {
    let (_dir, db) = live_copy();
    let mut rig = Rig::new(&db);
    for bad in [json!("20250615"), json!("2025-02-30"), json!(""), json!(5)] {
        assert_eq!(rig.code("data.sleep", json!({"date": bad})), "bad_params", "{bad}");
    }
}

/// 7b-4 review N6 (BACKLOG), twin of the Python test: each stage instant is read under the offset nearest to
/// it; a +1 h change at 22:30Z inside the 06-15 night.
#[test]
fn sleep_night_stages_across_a_clock_change_show_the_watchs_wall_clock() {
    let (_dir, db) = live_copy();
    let conn = rusqlite::Connection::open(&db).expect("open");
    conn.execute(
        "INSERT INTO clock_offsets(ts_utc, offset_s, raw_record_id) VALUES('2025-06-14T22:30:00Z', 14400, \
         (SELECT raw_record_id FROM clock_offsets LIMIT 1))",
        [],
    )
    .expect("offset");
    let mut rig = Rig::new(&db);
    let night = rig.send("data.sleep", json!({"date": "2025-06-15"}))["result"].clone();
    assert_eq!(night["sessions"][0]["utc_offset_s"], 14400);
    assert_eq!(
        stages_local(&night["sessions"][0]),
        [pair("23:00", "00:00"), pair("00:00", "03:00"), pair("03:00", "07:00")]
    );
}

#[test]
fn sleep_night_without_an_offset_has_no_local_keys_and_a_stage_can_cross_midnight() {
    let (_dir, db) = live_copy();
    let conn = rusqlite::Connection::open(&db).expect("open");
    conn.execute(
        "UPDATE sleep_stages SET start_utc='2025-06-14T20:30:00Z', end_utc='2025-06-14T21:30:00Z' \
         WHERE stage='light' AND sleep_id LIKE '2025-06-15|device%'",
        [],
    )
    .expect("update");
    let mut rig = Rig::new(&db);
    let night = rig.send("data.sleep", json!({"date": "2025-06-15"}))["result"].clone();
    // +03:00: the stage runs over local midnight
    assert_eq!(stages_local(&night["sessions"][0])[0], pair("23:30", "00:30"));
    conn.execute("DELETE FROM clock_offsets", []).expect("delete");
    let bare = rig.send("data.sleep", json!({"date": "2025-06-15"}))["result"].clone();
    for session in bare["sessions"].as_array().expect("sessions") {
        assert!(session.get("utc_offset_s").is_none());
        for stage in session["stages"].as_array().unwrap_or(&Vec::new()) {
            assert!(stage.get("start_local").is_none() && stage.get("end_local").is_none());
        }
    }
    assert_eq!(bare["sessions"][0]["stages"][0]["start_utc"], "2025-06-14T20:30:00Z");
}

#[test]
fn a_malformed_clock_offset_cell_reads_as_strptimes_text() {
    // the twin of test_serve.py's test of the same name: the three texts strptime gives a stored cell
    let (_dir, db) = plain_store();
    let conn = rusqlite::Connection::open(&db).expect("open");
    for (cell, text) in [
        ("2025-06-15 00:00:00", "time data '2025-06-15 00:00:00' does not match format '%Y-%m-%dT%H:%M:%SZ'"),
        ("2025-02-30T00:00:00Z", "day 30 must be in range 1..28 for month 2 in year 2025"),
        ("2025-06-15T00:00:00Z ", "unconverted data remains:  "),
    ] {
        only_offsets(&conn, &[(cell, 0)]);
        let reply = Rig::new(&db).send("data.health", json!({}));
        assert_eq!(reply["error"]["code"], "bad_params", "{cell:?}: {reply}");
        assert_eq!(reply["error"]["message"], text, "{cell:?}");
    }
}

#[test]
fn a_mean_the_float_cannot_hold_is_internal_unexpected_overflowerror() {
    // the twin of test_serve.py's test of the same name: the one OverflowError the oracles no longer carry
    let (_dir, db) = plain_store();
    let conn = rusqlite::Connection::open(&db).expect("open");
    two_huge_step_days(&conn);
    let reply = Rig::new(&db).send("data.facts", json!({"days": 7, "baseline_days": 28}));
    assert_eq!(reply["error"]["code"], "internal", "{reply}");
    assert_eq!(reply["error"]["message"], "unexpected OverflowError");
}

/// Two daily `steps` values of 1e308: their mean overflows Python's `fsum` (and the Rust twin answers `None`).
fn two_huge_step_days(conn: &rusqlite::Connection) {
    conn.execute(
        "INSERT INTO raw_records(stream, source_key, source_scope, transport, payload_kind, payload, payload_hash, \
         payload_bytes, imported_at) VALUES('fit:monitoring_b','k','device','usb','fit',x'00','h',1,'2025-07-01T00:00:00Z')",
        [],
    )
    .expect("raw record");
    for day in ["2025-06-29", "2025-06-30"] {
        conn.execute(
            "INSERT INTO daily_metrics(date, metric, value, source_scope, device_id, raw_record_id) \
             VALUES(?1,'steps',1e308,'device','7',1)",
            [day],
        )
        .expect("daily row");
    }
}

fn only_offsets(conn: &rusqlite::Connection, pairs: &[(&str, i64)]) {
    conn.execute("DELETE FROM clock_offsets", []).expect("delete");
    for (moment, seconds) in pairs {
        conn.execute("INSERT INTO clock_offsets(ts_utc, offset_s) VALUES(?, ?)", rusqlite::params![moment, seconds])
            .expect("insert");
    }
}

#[test]
fn sleep_night_without_an_end_takes_the_offset_nearest_its_start() {
    // the 06-30 device session runs 21:00Z..04:00Z; the 05:00Z offset is nearest its end, the 21:00Z one its start
    let (_dir, db) = live_copy();
    let conn = rusqlite::Connection::open(&db).expect("open");
    only_offsets(&conn, &[("2025-06-29T21:00:00Z", 3600), ("2025-06-30T05:00:00Z", 7200)]);
    let mut rig = Rig::new(&db);
    let with_end = rig.send("data.sleep", json!({}))["result"].clone();
    assert_eq!(with_end["sessions"][0]["utc_offset_s"], 7200);
    conn.execute("UPDATE sleep_sessions SET end_utc=NULL WHERE date='2025-06-30'", [])
        .expect("update");
    let night = rig.send("data.sleep", json!({}))["result"].clone();
    assert_eq!(night["sessions"][0]["utc_offset_s"], 3600);
    assert_eq!(stages_local(&night["sessions"][0]), [pair("22:00", "23:00")]);
}

#[test]
fn sleep_night_with_two_equally_near_offsets_takes_the_earlier() {
    let (_dir, db) = live_copy();
    let conn = rusqlite::Connection::open(&db).expect("open");
    // the session's end, 04:00Z, is exactly between the two
    only_offsets(&conn, &[("2025-06-30T03:00:00Z", 3600), ("2025-06-30T05:00:00Z", 7200)]);
    let night = Rig::new(&db).send("data.sleep", json!({}))["result"].clone();
    assert_eq!(night["sessions"][0]["utc_offset_s"], 3600);
}

#[test]
fn contract_lists_the_numeric_metrics_with_their_declared_scopes_and_answers_locked() {
    let (_d1, locked_db) = encrypted_copy();
    let (_d2, plain_db) = plain_store();
    for db in [&locked_db, &plain_db] {
        let reply = Rig::new(db).send("data.contract", json!({}))["result"].clone();
        assert_eq!(reply["scopes"], json!(["device", "vendor_cloud", "local", "live"]));
        let rows = reply["metrics"].as_array().expect("metrics");
        let by = |name: &str| rows.iter().find(|r| r["metric"] == name).cloned().expect(name);
        assert_eq!(by("heart_rate")["cadence"], "sample");
        assert_eq!(by("stress")["cadence"], "sample");
        assert_eq!(by("steps")["cadence"], "daily");
        assert_eq!(by("steps")["scopes"], json!(["vendor_cloud", "local"]));
        assert_eq!(rows[0]["metric"], "heart_rate");
        for row in rows {
            assert_eq!(row.as_object().expect("object").len(), 4);
            assert!(!row["scopes"].as_array().expect("scopes").is_empty());
        }
    }
}

#[test]
fn contract_lists_live_last_for_the_five_folded_metrics_and_for_no_other() {
    let (_dir, db) = plain_store();
    let reply = Rig::new(&db).send("data.contract", json!({}))["result"].clone();
    let folded = ["heart_rate", "stress", "respiration_rate", "spo2", "energy_reserve"];
    let rows = reply["metrics"].as_array().expect("metrics");
    for want in folded {
        assert!(rows.iter().any(|r| r["metric"] == want), "{want} is missing from the contract");
    }
    for row in rows {
        let scopes = row["scopes"].as_array().expect("scopes");
        let name = row["metric"].as_str().expect("metric");
        assert_eq!(scopes.iter().any(|s| s == "live"), folded.contains(&name), "{name}");
        if folded.contains(&name) {
            assert_eq!(scopes.last().expect("scope"), "live", "{name}");
        }
    }
}

#[test]
fn sleep_needs_the_store_unlocked() {
    let (_dir, db) = encrypted_copy();
    assert_eq!(Rig::new(&db).code("data.sleep", json!({})), "locked");
}

// ---- data.facts ----

fn synthetic_copy() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("synthetic.db");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../disconect/tests/fixtures/serve/synthetic.hbdb");
    std::fs::copy(source, &db).expect("copy the committed synthetic store");
    (dir, db)
}

#[test]
fn facts_on_an_empty_store_say_so_and_carry_the_rules() {
    let (_dir, db) = plain_store();
    let reply = Rig::new(&db).send("data.facts", json!({}));
    let result = &reply["result"];
    assert_eq!(result["as_of"], Value::Null);
    assert_eq!(result["facts"], json!([]));
    assert_eq!(result["reason"], "nothing stored yet");
    assert_eq!(result["ignored_metrics"], json!([]));
    assert_eq!(result["rules"].as_array().map(Vec::len), Some(3));
    assert_eq!(result.as_object().map(|o| o.len()), Some(5));
}

#[test]
fn facts_need_an_unlocked_store_and_then_answer() {
    let (_dir, db) = encrypted_copy();
    let mut rig = Rig::new(&db);
    assert_eq!(rig.code("data.facts", json!({})), "locked");
    assert_eq!(rig.code("data.facts", json!({"days": "x"})), "locked", "locked is checked before the params");
    rig.send("key.unlock", json!({"passphrase": PASSPHRASE}));
    let reply = rig.send("data.facts", json!({}));
    assert!(reply["result"].get("as_of").is_some(), "{reply}");
}

#[test]
fn facts_parameters_are_integers_and_are_clamped_like_the_oracle() {
    let (_dir, db) = synthetic_copy();
    let mut rig = Rig::new(&db);
    for bad in [json!(true), json!("7"), json!(7.5), json!(7.0), json!(null), json!([7])] {
        assert_eq!(rig.code("data.facts", json!({"days": bad})), "bad_params");
        assert_eq!(rig.code("data.facts", json!({"baseline_days": bad})), "bad_params");
    }
    let wide = rig.send("data.facts", json!({"days": 99999, "baseline_days": 1_000_000}))["result"].clone();
    assert_eq!((wide["window"]["days"].clone(), wide["baseline"]["days"].clone()), (json!(31), json!(365)));
    let narrow = rig.send("data.facts", json!({"days": -3, "baseline_days": 0}))["result"].clone();
    assert_eq!((narrow["window"]["days"].clone(), narrow["baseline"]["days"].clone()), (json!(1), json!(1)));
    let huge = rig.feed(
        format!("{{\"id\":2,\"method\":\"data.facts\",\"params\":{{\"days\":1{}}}}}\n", "0".repeat(4299)).as_bytes(),
    );
    assert_eq!(huge[0]["result"]["window"]["days"], 31, "a bigint clamps like Python's");
}

#[test]
fn facts_leave_out_the_convention_text_and_the_manufacturer_name() {
    let (_dir, db) = synthetic_copy();
    let result = Rig::new(&db).send("data.facts", json!({}))["result"].clone();
    assert!(result.get("sources").is_none());
    assert!(result.get("missing_values").is_some());
    assert!(!result.to_string().to_lowercase().contains("garmin"));
    let facts = result["facts"].as_array().expect("facts");
    assert!(facts.len() > 20);
    let keys: Vec<&str> = facts[0].as_object().expect("fact").keys().map(String::as_str).collect();
    assert_eq!(keys.len(), 14);
}

// ---- source rules ----

fn source(relative: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
        .expect("source file")
}

/// Everything before the first `#[cfg(test)]`: the production half of a module.
fn production(text: &str) -> &str {
    text.split("#[cfg(test)]").next().unwrap_or(text)
}

#[test]
fn serve_never_reaches_the_environment_passphrase() {
    let text = source("src/serve.rs");
    for forbidden in [
        "PASSPHRASE_ENV",
        "take_env_passphrase",
        "PassphraseSource",
        "scrub_env_secrets",
        "DISCONECT_RECOVERY",
    ] {
        assert!(
            !text.contains(forbidden),
            "serve.rs must not touch {forbidden}"
        );
    }
    assert!(!text.contains("env::var(\"DISCONECT_PASSPHRASE\""));
}

#[test]
fn the_read_and_transport_modules_never_ask_the_host_for_its_time_zone_or_print() {
    for file in [
        "src/serve.rs",
        "src/read/mod.rs",
        "src/contract.rs",
        "src/identity.rs",
        "src/keychain.rs",
        "src/wirejson.rs",
    ] {
        let text = source(file);
        let code = production(&text);
        assert!(
            !code.contains("Local"),
            "{file}: local days come from the watch's stored offsets, not the host zone"
        );
        assert!(
            !code.contains("println!") && !code.contains("print!(") && !code.contains("dbg!"),
            "{file} prints"
        );
    }
    assert!(source("src/lib.rs").contains("#![deny(clippy::print_stdout)]"));
    assert!(source("src/serve.rs").contains("clippy::unwrap_used"));
}

#[test]
fn the_dependency_tree_has_no_network_crate_but_the_lan_relays_client() {
    let lock = source("Cargo.lock");
    for crate_name in [
        "reqwest",
        "hyper",
        "curl",
        "tokio",
        "native-tls",
        "rustls",
    ] {
        assert!(
            !lock.contains(&format!("name = \"{crate_name}\"")),
            "{crate_name} would be a network dependency"
        );
    }
    // Bet 12 slice 12-B: the LAN relay is the one network feature (ADR 0005, "self-hosted"): `ureq` (client, no
    // TLS) and a std `TcpListener` server of its own (the review replaced `tiny_http`, which has no
    // time-outs), and nothing else in the crate may name them
    // Bet 12-E: the pairing joiner (`pair_client.rs`) is a second `ureq` client of the same LAN server
    let allowed = ["src/relay/lan.rs", "src/relay/lan_server.rs", "src/pair_client.rs"];
    let mut stack = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder).expect("read src") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .expect("under the crate")
                .to_string_lossy()
                .into_owned();
            let text = std::fs::read_to_string(&path).expect("source");
            let names_network = text.contains("ureq::") || text.contains("TcpListener");
            assert!(
                !names_network || allowed.contains(&relative.as_str()),
                "{relative} reaches the network outside the LAN relay modules"
            );
        }
    }
    assert!(!source("src/serve.rs").contains("relay::lan"), "serve talks to the relay only through `relay::config`");
}

/// The `dependencies` list of one `[[package]]` block of a lock file (crate names only).
fn lock_deps(lock: &str, package: &str) -> Vec<String> {
    let block = lock
        .split("[[package]]")
        .find(|b| b.lines().any(|l| l == format!("name = \"{package}\"")))
        .unwrap_or_else(|| panic!("{package} is in the lock file"));
    let mut deps = Vec::new();
    let mut inside = false;
    for line in block.lines() {
        if line.starts_with("dependencies = [") {
            inside = true;
        } else if inside && line == "]" {
            break;
        } else if inside {
            let entry = line.trim().trim_end_matches(',').trim_matches('"');
            deps.push(entry.split(' ').next().unwrap_or_default().to_string());
        }
    }
    deps
}

/// Bet 15 BACKLOG (closed 2026-10-03): the core's own lock links `ureq` without TLS, but inside the desktop app
/// Cargo unifies the app's `ureq` features (`rustls`, `platform-verifier`, for the coach) into the one `ureq` the
/// core's LAN relay client also uses, so that binary *could* speak https. It never does: the relay's URL rule
/// refuses anything but `http://host[:port]` before a client exists. This test reads both lock files and pins the
/// rule, so the unification stays harmless rather than unnoticed.
#[test]
fn the_apps_lock_turns_ureqs_tls_on_and_the_relay_url_rule_keeps_it_unused() {
    use disconect_core::relay::lan::parse_base_url;
    let own = lock_deps(&source("Cargo.lock"), "ureq");
    assert!(
        !own.iter().any(|d| d.starts_with("rustls") || d == "webpki-roots"),
        "the core's own ureq must stay without TLS: {own:?}"
    );
    let app_lock = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../app/src-tauri/Cargo.lock");
    match std::fs::read_to_string(&app_lock) {
        Ok(text) => {
            let unified = lock_deps(&text, "ureq");
            assert!(
                unified.iter().any(|d| d == "rustls"),
                "the app's lock no longer unifies rustls into ureq ({unified:?}): this guard and the BACKLOG note are stale"
            );
        }
        Err(_) => eprintln!("no app lock file next to this crate: only the core's own lock was checked"),
    }
    for url in [
        "https://127.0.0.1:8080",
        "https://relay.example",
        "HTTPS://relay.example",
        "http://user:pw@127.0.0.1:8080",
        "ftp://127.0.0.1",
        "127.0.0.1:8080",
        "http://127.0.0.1:8080/path",
    ] {
        assert!(parse_base_url(url).is_err(), "{url} must be refused");
    }
    assert_eq!(parse_base_url("http://127.0.0.1:8080").as_deref(), Ok("http://127.0.0.1:8080"));
}
