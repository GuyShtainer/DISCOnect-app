// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 9b slice 2: a live-link session file is kept as one `json:live` raw record and derives nothing
//! (the twin of `tests/test_live_import.py`). Synthetic data only.

mod common;

use std::fs;
use std::io::Read;
use std::path::Path;

use common::{PASSPHRASE, encrypted_copy};
use disconect_core::keys::{self, PassphraseSource};
use disconect_core::live::{parse_live_file, read_live_file};
use disconect_core::relay::folder::FolderRelay;
use disconect_core::relay::sync;
use disconect_core::sources::{DROPPED_LIVE_CUT_OFF, DROPPED_LIVE_EMPTY, import_path, iter_live_files, reparse_all};
use disconect_core::store::{self, Store};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

const T0: f64 = 1750000000.0;
const PINNED: &[u8] = b"{\"readings\":[[1750000001.0,\"heart_rate\",70],[1750000001.0,\"heart_rate\",71],[1750000002.0,\"steps\",40]]}";

fn live_lines() -> Vec<String> {
    vec![
        r#"{"status": "scanning"}"#.to_string(),
        format!(r#"{{"t": {:?}, "metric": "steps", "value": 40}}"#, T0 + 2.0),
        format!(r#"{{"t": {:?}, "metric": "heart_rate", "value": 71}}"#, T0 + 1.0),
        format!(r#"{{"t": {:?}, "metric": "heart_rate", "value": 70}}"#, T0 + 1.0),
        r#"{"status": "stopped", "stop": "LinkClosed"}"#.to_string(),
    ]
}

fn write_lines(path: &Path, lines: &[String]) {
    fs::write(path, lines.iter().map(|l| format!("{l}\n")).collect::<String>()).expect("write");
}

fn open(db: &Path) -> Store {
    store::open_for_write(db, "test", 5.0, PassphraseSource::Env).expect("open store")
}

type LiveRow = (String, String, String, Option<String>, Option<String>, Option<String>, String, Vec<u8>, String);

fn live_rows(conn: &Connection) -> Vec<LiveRow> {
    let mut statement = conn
        .prepare(
            "SELECT source_key, source_scope, transport, device_id, start_utc, end_utc, payload_kind, payload, \
             payload_hash FROM raw_records WHERE stream='json:live'",
        )
        .expect("prepare");
    statement
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?))
        })
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

fn inflate(blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(blob).read_to_end(&mut out).expect("inflate");
    out
}

fn canonical_counts(conn: &Connection) -> Vec<i64> {
    ["metric_samples", "daily_metrics", "daily_labels", "monitoring_intervals", "activities"]
        .iter()
        .map(|t| {
            // the 9b-2 fold writes `live`-scope samples; everything else stays empty
            let filter = if *t == "metric_samples" { " WHERE source_scope != 'live'" } else { "" };
            conn.query_row(&format!("SELECT COUNT(*) FROM {t}{filter}"), [], |r| r.get(0)).expect("count")
        })
        .collect()
}

#[test]
fn live_file_becomes_one_pinned_raw_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("live-20250615T150640Z.jsonl");
    write_lines(&path, &live_lines());
    let store = open(&dir.path().join("a.db"));
    let stats = import_path(store.conn(), &path, None, None).expect("import");
    assert_eq!((stats.files_imported, stats.files_failed), (1, 0));
    let rows = live_rows(store.conn());
    assert_eq!(rows.len(), 1);
    let (key, scope, transport, device, start, end, kind, blob, digest) = rows[0].clone();
    assert_eq!((scope.as_str(), transport.as_str(), kind.as_str()), ("device", "ble", "json"));
    assert_eq!(device, None);
    assert_eq!((start.as_deref(), end.as_deref()), (Some("2025-06-15T15:06:41Z"), Some("2025-06-15T15:06:42Z")));
    assert_eq!(inflate(&blob), PINNED);
    assert_eq!(key, digest);
    assert_eq!(key, hex::encode(Sha256::digest(PINNED)));
    assert!(canonical_counts(store.conn()).iter().all(|n| *n == 0));
}

#[test]
fn int_t_stays_an_int_and_the_run_keeps_its_transport() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("live-int.jsonl");
    write_lines(&path, &[r#"{"t": 1750000001, "metric": "steps", "value": 5}"#.to_string()]);
    let store = open(&dir.path().join("a.db"));
    let stats = import_path(store.conn(), &path, Some("usb"), None).expect("import");
    assert_eq!(stats.transport, "usb");
    let rows = live_rows(store.conn());
    assert_eq!(inflate(&rows[0].7), br#"{"readings":[[1750000001,"steps",5]]}"#);
    assert_eq!(rows[0].2, "ble");
}

#[test]
fn same_file_twice_is_duplicate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("a.db"));
    let first = dir.path().join("live-a.jsonl");
    write_lines(&first, &live_lines());
    import_path(store.conn(), &first, None, None).expect("import");
    let again = dir.path().join("live-b.jsonl");
    let mut reversed = live_lines();
    reversed.reverse();
    write_lines(&again, &reversed);
    let stats = import_path(store.conn(), &again, None, None).expect("import");
    assert_eq!((stats.files_imported, stats.files_duplicate), (0, 1));
    assert_eq!(live_rows(store.conn()).len(), 1);
}

#[test]
fn status_only_file_is_skipped_with_a_counted_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("live-empty.jsonl");
    write_lines(&path, &[r#"{"status": "scanning"}"#.to_string(), r#"{"status": "stopped", "stop": "x"}"#.to_string()]);
    let store = open(&dir.path().join("a.db"));
    let stats = import_path(store.conn(), &path, None, None).expect("import");
    assert_eq!(stats.dropped.iter().collect::<Vec<_>>(), [(&DROPPED_LIVE_EMPTY.to_string(), &1)]);
    assert_eq!((stats.files_seen, stats.files_imported, stats.files_failed), (0, 0, 0));
    assert!(live_rows(store.conn()).is_empty());
}

#[test]
fn a_file_cut_off_mid_line_keeps_its_whole_lines_and_is_counted() {
    // the lab killed mid-write leaves a partial last line: the session before it is imported, once, as the
    // same pinned record the whole file gives, and the loss is counted (9b-2 review O1)
    let dir = tempfile::tempdir().expect("tempdir");
    let whole = dir.path().join("whole/live-x.jsonl");
    fs::create_dir_all(whole.parent().expect("parent")).expect("mkdir");
    write_lines(&whole, &live_lines());
    let cut = dir.path().join("cut/live-x.jsonl");
    fs::create_dir_all(cut.parent().expect("parent")).expect("mkdir");
    let mut bytes = fs::read(&whole).expect("read");
    bytes.extend_from_slice(br#"{"t": 1750000003.0, "metric": "heart_"#);
    fs::write(&cut, &bytes).expect("write");
    assert_eq!(read_live_file(&bytes), parse_live_file(&fs::read(&whole).expect("read")).map(|r| (r, true)));
    assert!(parse_live_file(&bytes).is_none());
    let store = open(&dir.path().join("a.db"));
    let stats = import_path(store.conn(), &cut, None, None).expect("import");
    assert_eq!((stats.files_seen, stats.files_imported, stats.files_failed), (1, 1, 0));
    assert_eq!(stats.dropped.iter().collect::<Vec<_>>(), [(&DROPPED_LIVE_CUT_OFF.to_string(), &1)]);
    let rows = live_rows(store.conn());
    assert_eq!(rows.len(), 1);
    assert_eq!(inflate(&rows[0].7), PINNED);
    let stats = import_path(store.conn(), &whole, None, None).expect("import");
    assert_eq!(stats.files_duplicate, 1); // the whole file is the same record
    // the whole lines must pass the live rule, and at least one must precede the partial line
    assert!(read_live_file(b"{\"t\": 1, \"metric\": \"x\", \"value\": 1}\n{\"frame\": \"0a0b\"}\n{\"t\": 2, \"metr").is_none());
    assert!(read_live_file(b"{\"t\": 2, \"metr").is_none());
    assert!(read_live_file(b"{\"frame\": \"0a0b\"}\n").is_none()); // well-formed and not live stays not live
    assert_eq!(read_live_file(b"{\"status\": \"scanning\"}\n{\"t\": 2, \"metr"), Some((vec![], true)));
    let got = read_live_file(b"{\"status\": \"scanning\"}\n{\"t\": 1, \"metric\": \"x\", \"value\": 1}\r\n   \n{\"t\":");
    assert_eq!(got.map(|(r, cut)| (r.len(), cut)), Some((1, true)));
    // this port refuses NaN as unsupported, not as a cut: the file stays not live (the parse_live_file note)
    assert!(read_live_file(b"{\"status\": \"scanning\"}\n{\"t\": NaN, \"metric\": \"x\", \"value\": 1}").is_none());
}

#[test]
fn detection_rule() {
    assert!(parse_live_file(b"{\"status\": \"scanning\"}\n{\"frame\": \"0a0b\", \"dir\": \"rx\"}").is_none());
    assert!(parse_live_file(br#"{"t": 1, "metric": "steps", "value": 1.5}"#).is_none());
    assert!(parse_live_file(br#"{"t": 1, "metric": "steps", "value": true}"#).is_none());
    assert!(parse_live_file(br#"{"t": true, "metric": "steps", "value": 1}"#).is_none());
    assert!(parse_live_file(br#"{"t": 1, "metric": 7, "value": 1}"#).is_none());
    assert!(parse_live_file(b"[1]").is_none());
    assert!(parse_live_file(b"").is_none());
    assert!(parse_live_file(b"\n  \n\x1f\n").is_none());
    assert!(parse_live_file(b"\x00\x01\xff").is_none());
    assert!(parse_live_file(b"not json").is_none());
    assert_eq!(parse_live_file(br#"{"stop": 1}"#).map(|r| r.len()), Some(0));
    // blank lines and CR/LF endings are fine
    let got = parse_live_file(b"\r\n{\"t\": 1.5, \"metric\": \"a\", \"value\": 2}\r\n\r\n{\"status\": 1}\r\n");
    assert_eq!(got.map(|r| r.len()), Some(1));
}

#[test]
fn t_is_bounded_so_a_millisecond_stamp_is_not_a_live_file() {
    let line = |t: &str| format!(r#"{{"t": {t}, "metric": "steps", "value": 1}}"#);
    for ok in ["0", "0.0", "253370764799", "253370764799.5", "1750000000.5"] {
        assert_eq!(parse_live_file(line(ok).as_bytes()).map(|r| r.len()), Some(1), "{ok}");
    }
    for bad in ["253370764800", "253370764800.0", "253402300800", "253402300800.0", "1750000000123", "-1", "-0.5", "1e300"] {
        assert!(parse_live_file(line(bad).as_bytes()).is_none(), "{bad}");
    }
}

#[test]
fn folder_picks_live_files_and_zips_are_not_scanned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let folder = dir.path().join("drop");
    fs::create_dir_all(folder.join("sub")).expect("mkdir");
    write_lines(&folder.join("live-x.jsonl"), &live_lines());
    write_lines(&folder.join("sub/notes.jsonl"), &[r#"{"frame": "0a0b"}"#.to_string()]);
    fs::write(folder.join("readme.txt"), "x").expect("write");
    let found = iter_live_files(&folder).expect("scan");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, "live-x.jsonl");
    let store = open(&dir.path().join("a.db"));
    let stats = import_path(store.conn(), &folder, None, None).expect("import");
    assert_eq!((stats.files_imported, stats.files_failed), (1, 0));
    // a lone non-live .jsonl falls through to the FIT pass and fails there
    let frames = dir.path().join("frames.jsonl");
    write_lines(&frames, &[r#"{"frame": "0a0b"}"#.to_string()]);
    assert!(iter_live_files(&frames).expect("scan").is_empty());
    let stats = import_path(store.conn(), &frames, None, None).expect("import");
    assert_eq!(stats.files_failed, 1);
    // zips are never scanned
    let zip_path = dir.path().join("bag.zip");
    fs::write(&zip_path, b"PK").expect("write");
    assert!(iter_live_files(&zip_path).expect("scan").is_empty());
}

#[test]
fn reparse_all_keeps_the_live_record_and_derives_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("live-r.jsonl");
    write_lines(&path, &live_lines());
    let store = open(&dir.path().join("a.db"));
    import_path(store.conn(), &path, None, None).expect("import");
    let (before_rows, before_counts) = (live_rows(store.conn()), canonical_counts(store.conn()));
    let all = reparse_all(store.conn(), None, false).expect("reparse");
    let only = reparse_all(store.conn(), Some(&["json:live".to_string()]), false).expect("reparse live");
    assert_eq!((all.files_failed, only.files_failed, only.files_seen), (0, 0, 1));
    assert_eq!(live_rows(store.conn()), before_rows);
    assert_eq!(canonical_counts(store.conn()), before_counts);
}

#[test]
fn relay_carries_the_live_record_and_the_peer_stores_the_bytes() {
    let master = keys::unlock(&common::fixtures().join("test.keys.json"), PassphraseSource::Explicit(PASSPHRASE))
        .expect("unlock")
        .to_vec();
    let open_device = || {
        let (dir, db) = encrypted_copy();
        let secret = keys::unlock(&keys::key_path_for(&db), PassphraseSource::Explicit(PASSPHRASE)).expect("unlock");
        let store = store::open_for_write_with(&db, "test", 5.0, Some(&secret)).expect("open");
        (dir, store)
    };
    let (dir_a, a) = open_device();
    let (_dir_b, b) = open_device();
    let path = dir_a.path().join("live-p.jsonl");
    write_lines(&path, &live_lines());
    import_path(a.conn(), &path, None, None).expect("import");
    let relay = FolderRelay::creating_root(dir_a.path().join("relay"));
    sync::push(a.conn(), &master, &relay).expect("push");
    let result = sync::pull(b.conn(), &master, &relay).expect("pull");
    assert_eq!((result.records_new, result.records_invalid), (1, 0));
    let rows = live_rows(b.conn());
    assert_eq!(rows.len(), 1);
    assert_eq!(inflate(&rows[0].7), PINNED);
    assert_eq!(rows[0].2, "ble");
    assert!(canonical_counts(b.conn()).iter().all(|n| *n == 0));
    // the pull itself folds the live minutes: a pull-only device gets the same rows (9b-2 review S2)
    let folded = |conn: &Connection| -> Vec<(String, String, f64)> {
        let mut stmt = conn
            .prepare("SELECT metric, ts_utc, value FROM metric_samples WHERE source_scope='live' ORDER BY metric, ts_utc")
            .expect("prepare");
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows")
    };
    assert!(!folded(a.conn()).is_empty());
    assert_eq!(folded(a.conn()), folded(b.conn()));
}

#[test]
fn a_value_past_i64_makes_the_file_not_live() {
    // the oracle's `_is_reading` bounds the value the same way (9b-2 review M1)
    let huge = format!("1{}", "0".repeat(400));
    for text in ["9223372036854775808", "-9223372036854775809", huge.as_str()] {
        let line = format!("{{\"t\": 1749981601, \"metric\": \"heart_rate\", \"value\": {text}}}\n");
        assert_eq!(disconect_core::live::parse_live_file(line.as_bytes()), None, "{text}");
    }
    let edge = b"{\"t\": 1749981601, \"metric\": \"heart_rate\", \"value\": 9223372036854775807}\n";
    assert_eq!(disconect_core::live::parse_live_file(edge).map(|r| r.len()), Some(1));
}
