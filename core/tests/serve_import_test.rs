// SPDX-License-Identifier: AGPL-3.0-or-later
//! `import.run` and `import.last` over the `serve` protocol, in process: the two progress phases, the
//! response after the events, the import slot (`busy`), the cross-process write lock (`busy`), EOF
//! waiting for the worker, and the request-level errors that need no store write. The byte-level
//! comparison with the Python oracle is `tools/serve_diff.py` (its import leg).

mod common;

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use disconect_core::keys::PassphraseSource;
use disconect_core::serve::{self, Channel, Session};
use disconect_core::store;
use disconect_core::write_lock;
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

/// Input that arrives in pieces; `at_end` runs just before the reader reports EOF.
struct Pieces {
    chunks: VecDeque<Vec<u8>>,
    at_end: Option<Box<dyn FnOnce() + Send>>,
}

impl Read for Pieces {
    fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
        match self.chunks.pop_front() {
            Some(chunk) => {
                into[..chunk.len()].copy_from_slice(&chunk);
                Ok(chunk.len())
            }
            None => {
                if let Some(release) = self.at_end.take() {
                    release();
                }
                Ok(0)
            }
        }
    }
}

struct Rig {
    session: Session,
    out: Buffer,
}

impl Rig {
    fn new(db: &Path) -> Rig {
        let out = Buffer::default();
        Rig {
            session: Session::new(db.to_path_buf(), Channel::new(Box::new(out.clone()))),
            out,
        }
    }

    fn lines(&self) -> Vec<Value> {
        let bytes = std::mem::take(&mut *self.out.0.lock().expect("buffer"));
        String::from_utf8(bytes)
            .expect("ascii output")
            .lines()
            .map(|l| serde_json::from_str(l).expect("protocol line"))
            .collect()
    }

    fn feed(&mut self, input: &[u8]) -> Vec<Value> {
        assert_eq!(serve::serve_lines(&mut self.session, input), 0);
        self.lines()
    }

    fn send(&mut self, id: i64, method: &str, params: Value) -> Vec<Value> {
        self.feed(
            format!(
                "{}\n",
                json!({"id": id, "method": method, "params": params})
            )
            .as_bytes(),
        )
    }
}

fn request(id: i64, method: &str, params: Value) -> Vec<u8> {
    format!(
        "{}\n",
        json!({"id": id, "method": method, "params": params})
    )
    .into_bytes()
}

fn fixture_fit(name: &str) -> Vec<u8> {
    std::fs::read(
        common::fixtures()
            .join("synthetic")
            .join(format!("{name}.fit.bin")),
    )
    .expect("fixture")
}

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, bytes).expect("write");
}

/// An account export: three FIT files in the nested uploaded-files zip (two good, one not), two JSON files
/// of a recognised family (one good, one not JSON) and three entries that are ignored.
fn export_folder(dir: &Path) -> PathBuf {
    let root = dir.join("export");
    let mut nested = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut nested);
        let options = zip::write::SimpleFileOptions::default();
        for (name, bytes) in [
            ("a_hrv.fit", fixture_fit("hrv_status")),
            ("b_skin.fit", fixture_fit("skin_temp")),
            ("c_garbage.fit", fixture_fit("garbage")),
        ] {
            zip.start_file(name, options).expect("start");
            zip.write_all(&bytes).expect("member");
        }
        zip.finish().expect("finish");
    }
    write(
        &root,
        "DI_CONNECT/DI-Connect-Uploaded-Files/UploadedFiles_1.zip",
        nested.get_ref(),
    );
    write(
        &root,
        "DI_CONNECT/DI-Connect-Aggregator/UDSFile_2025-06-01_2025-06-03.json",
        br#"[{"calendarDate":"2025-06-01","totalSteps":10}]"#,
    );
    write(
        &root,
        "DI_CONNECT/DI-Connect-Aggregator/UDSFile_2025-06-04_2025-06-05.json",
        b"not json",
    );
    write(
        &root,
        "DI_CONNECT/DI-Connect-Aggregator/UDSFile_readme.txt",
        b"ignored",
    );
    write(&root, "DI_CONNECT/DI-Connect-Metrics/notes.txt", b"ignored");
    write(&root, "elsewhere/notes.json", b"[]");
    root
}

fn new_store() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("plain.db");
    store::open_for_write(&db, "test", 1.0, PassphraseSource::Explicit("unused"))
        .expect("create store");
    (dir, db)
}

fn events(lines: &[Value]) -> Vec<(u64, Option<u64>, String)> {
    lines
        .iter()
        .filter(|line| line.get("event").is_some())
        .map(|line| {
            assert_eq!(
                (line["event"].as_str(), line["op"].as_str()),
                (Some("progress"), Some("import"))
            );
            (
                line["done"].as_u64().expect("done"),
                line["total"].as_u64(),
                line["note"].as_str().expect("note").to_string(),
            )
        })
        .collect()
}

#[test]
fn import_run_streams_the_fit_phase_then_restarts_done_for_the_json_phase_and_answers_last() {
    let (dir, db) = new_store();
    let export = export_folder(dir.path());
    let lines = Rig::new(&db).send(
        7,
        "import.run",
        json!({"path": export, "transport": "export"}),
    );
    // FIT: (done, total, outcome) per file; JSON: done restarts at 0, total null, ignored entries uncounted
    assert_eq!(
        events(&lines),
        [
            (1, Some(3), "imported".to_string()),
            (2, Some(3), "imported".to_string()),
            (3, Some(3), "failed".to_string()),
            (1, None, "json:uds".to_string()),
            (2, None, "json:uds".to_string()),
        ]
    );
    let (response, before) = lines.split_last().expect("response");
    assert!(
        before.iter().all(|line| line.get("event").is_some()),
        "every event precedes the response"
    );
    assert_eq!(response["id"], 7);
    let result = response["result"].as_object().expect("result");
    let mut keys: Vec<&str> = result.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["duplicate", "failed", "files", "ok", "partial", "run_id"]
    );
    assert_eq!(
        (result["run_id"].as_i64(), result["partial"].as_bool()),
        (Some(1), Some(true))
    );
    assert_eq!(
        (
            result["ok"].as_i64(),
            result["failed"].as_i64(),
            result["duplicate"].as_i64()
        ),
        (Some(3), Some(2), Some(0))
    );

    let last = Rig::new(&db).send(8, "import.last", json!({}));
    let run = &last[0]["result"]["runs"][0];
    assert_eq!(
        (
            run["id"].as_i64(),
            run["transport"].as_str(),
            run["status"].as_str()
        ),
        (Some(1), Some("connect_export"), Some("partial"))
    );
    assert_eq!(run["failures"], 2);
    assert_eq!(run["error"], Value::Null);
}

/// A live link ends with a `ble` sweep of the readings folder; listed like any run, the sweeps would
/// push the USB and export runs out of the five-row list within a day (9b review N8): the list is the
/// newest five runs of the other transports plus the newest sweep, newest first.
#[test]
fn import_last_lists_the_newest_sweep_beside_five_runs_of_the_other_transports() {
    let (_dir, db) = new_store();
    let transports = [
        "usb", "connect_export", "ble", "usb", "ble", "drop", "usb", "ble", "usb", "ble", "ble",
    ];
    {
        let store = store::open_for_write(&db, "test", 1.0, PassphraseSource::Explicit("unused"))
            .expect("open store");
        for (index, transport) in transports.iter().enumerate() {
            store
                .conn()
                .execute(
                    "INSERT INTO import_runs(id, started_at, transport, status) \
                     VALUES(?, '2025-07-01T00:00:00Z', ?, 'ok')",
                    rusqlite::params![index as i64 + 1, transport],
                )
                .expect("insert run");
        }
    }
    let last = Rig::new(&db).send(1, "import.last", json!({}));
    let runs = last[0]["result"]["runs"].as_array().expect("runs");
    let ids: Vec<i64> = runs.iter().map(|run| run["id"].as_i64().unwrap()).collect();
    assert_eq!(ids, vec![11, 9, 7, 6, 4, 2]);
    let kinds: Vec<&str> = runs
        .iter()
        .map(|run| run["transport"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, vec!["ble", "usb", "usb", "drop", "usb", "connect_export"]);
    let health = Rig::new(&db).send(2, "data.health", json!({}));
    let recent: Vec<i64> = health[0]["result"]["recent_imports"]
        .as_array()
        .expect("recent_imports")
        .iter()
        .map(|run| run["id"].as_i64().unwrap())
        .collect();
    assert_eq!(recent, ids);
}

#[test]
fn import_last_with_only_sweeps_is_the_newest_one() {
    let (_dir, db) = new_store();
    {
        let store = store::open_for_write(&db, "test", 1.0, PassphraseSource::Explicit("unused"))
            .expect("open store");
        store
            .conn()
            .execute_batch(
                "INSERT INTO import_runs(id, started_at, transport, status) VALUES \
                 (1, '2025-07-01T00:00:00Z', 'ble', 'ok'), (2, '2025-07-01T00:00:00Z', 'ble', 'ok'), \
                 (3, '2025-07-01T00:00:00Z', 'ble', 'partial')",
            )
            .expect("insert runs");
    }
    let last = Rig::new(&db).send(1, "import.last", json!({}));
    let runs = last[0]["result"]["runs"].as_array().expect("runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["id"], 3);
    assert_eq!(runs[0]["status"], "partial");
}

#[test]
fn import_last_on_a_store_that_never_imported_is_an_empty_list() {
    let (_dir, db) = new_store();
    let last = Rig::new(&db).send(1, "import.last", json!({}));
    assert_eq!(last[0]["result"], json!({"runs": []}));
}

#[test]
fn a_second_import_while_one_runs_is_busy_and_reads_keep_working() {
    let (dir, db) = new_store();
    let export = export_folder(dir.path());
    let mut rig = Rig::new(&db);
    let (release, gate) = mpsc::channel::<()>();
    rig.session.hold_next_import(gate);
    let mut chunks = VecDeque::new();
    chunks.push_back(request(1, "import.run", json!({"path": export})));
    chunks.push_back(
        [
            request(2, "import.run", json!({"path": export})),
            request(3, "import.last", json!({})),
        ]
        .concat(),
    );
    let mut input = Pieces {
        chunks,
        at_end: Some(Box::new(move || drop(release))),
    };
    assert_eq!(serve::serve_lines(&mut rig.session, &mut input), 0);
    let lines = rig.lines();
    let by_id = |id: i64| lines.iter().find(|l| l["id"] == id).expect("answer");
    assert_eq!(by_id(2)["error"]["code"], "busy");
    assert_eq!(by_id(2)["error"]["message"], "an import is already running");
    assert_eq!(
        by_id(3)["result"],
        json!({"runs": []}),
        "a read is answered while the worker is held"
    );
    assert_eq!(by_id(1)["result"]["ok"], 3);
    assert_eq!(
        lines.last().expect("last")["id"],
        1,
        "the held import answers last, at EOF"
    );
    // the slot is free again
    let again = rig.send(4, "import.run", json!({"path": export}));
    assert!(
        again.last().expect("answer")["result"]["duplicate"]
            .as_i64()
            .expect("duplicate")
            > 0
    );
}


#[test]
fn a_held_import_cancelled_before_release_reads_nothing_and_is_booked_cancelled() {
    // the flag is set while the worker is held before it starts, so nothing is read: the check sits before each
    // file, the first included (twin of the Python test of the same name; the per-phase cuts are import_cancel_test)
    let (dir, db) = new_store();
    let export = export_folder(dir.path());
    let mut rig = Rig::new(&db);
    let (release, gate) = mpsc::channel::<()>();
    rig.session.hold_next_import(gate);
    let mut chunks = VecDeque::new();
    chunks.push_back(request(1, "import.run", json!({"path": export, "transport": "export"})));
    chunks.push_back(
        [
            request(2, "import.cancel", json!({})),
            request(3, "import.cancel", json!({})), // a repeat while it runs says the same
        ]
        .concat(),
    );
    let mut input = Pieces {
        chunks,
        at_end: Some(Box::new(move || drop(release))),
    };
    assert_eq!(serve::serve_lines(&mut rig.session, &mut input), 0);
    let lines = rig.lines();
    let by_id = |id: i64| lines.iter().find(|l| l["id"] == id).expect("answer");
    assert_eq!(by_id(2)["result"], json!({"state": "cancelling"}));
    assert_eq!(by_id(3)["result"], json!({"state": "cancelling"}));
    assert_eq!(
        by_id(1)["error"],
        json!({"code": "cancelled", "message": "the import was cancelled; the files read so far are kept"})
    );
    assert!(events(&lines).is_empty(), "nothing was read: the cancel landed before the first file");
    let last = rig.send(4, "import.last", json!({}));
    let run = &last.last().expect("answer")["result"]["runs"][0];
    assert_eq!(
        (run["status"].as_str(), run["files_seen"].as_i64(), run["files_imported"].as_i64(), run["error"].is_null()),
        (Some("cancelled"), Some(0), Some(0), true)
    );
    let none = rig.send(5, "import.cancel", json!({}));
    assert_eq!(
        none.last().expect("answer")["error"],
        json!({"code": "not_found", "message": "no import is running"}),
        "nothing runs now"
    );
    let again = rig.send(6, "import.run", json!({"path": export, "transport": "export"}));
    let result = &again.last().expect("answer")["result"];
    assert_eq!(
        (result["ok"].as_i64(), result["duplicate"].as_i64()),
        (Some(3), Some(0)),
        "the slot is free; nothing was kept, so nothing is a duplicate (three members: two good, one not)"
    );
}

#[test]
fn import_cancel_with_no_import_is_not_found() {
    let (_dir, db) = new_store();
    let mut rig = Rig::new(&db);
    let lines = rig.send(1, "import.cancel", json!({}));
    assert_eq!(
        lines.last().expect("answer")["error"],
        json!({"code": "not_found", "message": "no import is running"})
    );
}

#[test]
fn an_import_is_busy_while_another_process_holds_the_write_lock() {
    let (dir, db) = new_store();
    let export = export_folder(dir.path());
    let held = write_lock::acquire(&db, "cli import", Duration::from_secs(1)).expect("lock");
    let mut rig = Rig::new(&db);
    let lines = rig.send(1, "import.run", json!({"path": export}));
    assert_eq!(lines.len(), 1, "no events: nothing was written");
    assert_eq!(lines[0]["error"]["code"], "busy");
    let message = lines[0]["error"]["message"].as_str().expect("message");
    assert!(
        message.starts_with("another DISCOnect process is writing the database (cli import, pid "),
        "{message}"
    );
    drop(held);
    let lines = rig.send(2, "import.run", json!({"path": export}));
    assert_eq!(lines.last().expect("answer")["result"]["ok"], 3);
}

#[test]
fn eof_straight_after_the_request_still_delivers_events_and_response() {
    let (dir, db) = new_store();
    let export = export_folder(dir.path());
    let lines = Rig::new(&db).feed(&request(
        5,
        "import.run",
        json!({"path": export, "transport": "usb"}),
    ));
    assert!(lines.len() > 5 && lines.last().expect("response")["id"] == 5);
    let last = Rig::new(&db).send(6, "import.last", json!({}));
    assert_eq!(last[0]["result"]["runs"][0]["transport"], "usb");
}

#[test]
fn import_run_refuses_bad_parameters_before_it_touches_the_store() {
    let (_dir, db) = new_store();
    let mut rig = Rig::new(&db);
    let code = |rig: &mut Rig, params: Value| {
        let lines = rig.send(1, "import.run", params);
        assert_eq!(lines.len(), 1);
        (
            lines[0]["error"]["code"]
                .as_str()
                .expect("code")
                .to_string(),
            lines[0]["error"]["message"]
                .as_str()
                .expect("message")
                .to_string(),
        )
    };
    for path in [
        json!(null),
        json!(""),
        json!(5),
        json!(true),
        json!(["x"]),
        json!({"a": 1}),
        json!(1.5),
    ] {
        assert_eq!(
            code(&mut rig, json!({"path": path, "transport": "usb"})),
            (
                "bad_params".into(),
                "path must be a non-empty string".into()
            )
        );
    }
    assert_eq!(code(&mut rig, json!({})).0, "bad_params");
    for transport in [
        json!(5),
        json!(true),
        json!("Export"),
        json!("usb "),
        json!("gadgetbridge"),
        json!(["export"]),
        json!(0),
    ] {
        let (c, m) = code(
            &mut rig,
            json!({"path": "x", "transport": transport.clone()}),
        );
        assert_eq!(c, "bad_params", "{transport}");
        assert!(
            m == "transport must be one of ['ble', 'export', 'usb']"
                || m == "transport must be a non-empty string",
            "{m}"
        );
    }
    assert_eq!(
        code(&mut rig, json!({"path": "x", "transport": ""})).1,
        "transport must be a non-empty string"
    );
    assert_eq!(
        code(&mut rig, json!({"path": 5, "transport": 5})).1,
        "path must be a non-empty string"
    );
}

#[test]
fn a_missing_path_is_not_found_with_the_path_redacted_and_normalised_like_pathlib() {
    let (_dir, db) = new_store();
    let mut rig = Rig::new(&db);
    let message = |rig: &mut Rig, path: &str| {
        let lines = rig.send(1, "import.run", json!({"path": path}));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["error"]["code"], "not_found", "{path}");
        lines[0]["error"]["message"]
            .as_str()
            .expect("message")
            .to_string()
    };
    assert_eq!(
        message(&mut rig, "/Users/someone/me@example.com/missing"),
        "no such file or folder: {path}"
    );
    assert_eq!(
        message(&mut rig, "no-such//./inner/"),
        "no such file or folder: no-such/inner"
    );
    assert_eq!(
        message(&mut rig, "nothing"),
        "no such file or folder: nothing"
    );
}

// ---- write-path stamp rows (BACKLOG 477, 478): a hand-edited stored stamp on an import ----

const STAMP_TEXT: &str = "time data '2025-06-15T12:00:00' does not match format '%Y-%m-%dT%H:%M:%SZ'";

/// A fresh store holding one raw record and one hand-edited row (`seed_sql`), and a folder with the one
/// synthetic monitoring FIT (device 42, 2025-06-15T06:00Z; steps intervals and stress samples).
fn corrupt_import_rig(seed_sql: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let (dir, db) = new_store();
    let folder = dir.path().join("drop");
    write(&folder, "a.fit", &fixture_fit("monitoring_sentinels_counters"));
    let conn = rusqlite::Connection::open(&db).expect("open");
    conn.execute(
        "INSERT INTO raw_records(stream, source_key, source_scope, transport, payload_kind, payload, payload_hash, \
         payload_bytes, imported_at) VALUES('fit:monitoring_b','k','device','usb','fit',x'00','h',1,'2025-07-01T00:00:00Z')",
        [],
    )
    .expect("raw");
    conn.execute(seed_sql, []).expect("hand-edited row");
    (dir, db, folder)
}

type RunRow = (i64, String, i64, i64, i64, i64, Option<String>);

/// What an import leaves in the store: the run rows (no timestamps) and the table counts.
fn import_store_state(db: &Path) -> (Vec<RunRow>, [i64; 4]) {
    let conn = rusqlite::Connection::open(db).expect("open");
    let mut stmt = conn
        .prepare(
            "SELECT id, status, files_seen, files_imported, files_failed, records_written, error \
             FROM import_runs ORDER BY id",
        )
        .expect("prepare");
    let runs = stmt
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
        })
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows");
    let mut counts = [0_i64; 4];
    for (at, table) in ["raw_records", "daily_metrics", "metric_samples", "monitoring_intervals"].iter().enumerate() {
        counts[at] = conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)).expect("count");
    }
    (runs, counts)
}

fn error_of(lines: &[Value]) -> (String, String) {
    let reply = lines.last().expect("response");
    (
        reply["error"]["code"].as_str().unwrap_or_default().to_string(),
        reply["error"]["message"].as_str().unwrap_or_default().to_string(),
    )
}

#[test]
fn import_over_a_malformed_clock_offset_cell_is_bad_params_and_leaves_the_store_alone() {
    // the twin of test_serve.py's test of the same name: the offsets load fails before `begin_run`
    let (_dir, db, folder) =
        corrupt_import_rig("INSERT INTO clock_offsets(ts_utc, offset_s) VALUES('2025-06-15 00:00:00', 0)");
    let before = import_store_state(&db);
    let lines = Rig::new(&db).send(1, "import.run", json!({"path": folder}));
    assert_eq!(
        error_of(&lines),
        (
            "bad_params".to_string(),
            "time data '2025-06-15 00:00:00' does not match format '%Y-%m-%dT%H:%M:%SZ'".to_string()
        )
    );
    assert!(before.0.is_empty());
    assert_eq!(import_store_state(&db), before);
}

#[test]
fn import_over_an_unparseable_derivation_cell_is_bad_params_and_the_run_is_booked_failed() {
    // the twin of test_serve.py's test of the same name; the steps derivation fails first, the samples one after it
    let failed = |counts: [i64; 4]| {
        (vec![(1, "failed".to_string(), 1, 1, 0, 12, Some(format!("ValueError: {STAMP_TEXT}")))], counts)
    };
    for (seed_sql, state) in [
        (
            "INSERT INTO monitoring_intervals(ts_utc, activity_type, steps, source_scope, device_id, raw_record_id) \
             VALUES('2025-06-15T12:00:00','walking',5,'device','42',1)",
            failed([2, 3, 7, 2]),
        ),
        (
            "INSERT INTO metric_samples(ts_utc, metric, value, source_scope, device_id, raw_record_id) \
             VALUES('2025-06-15T12:00:00','stress',5,'device','42',1)",
            failed([2, 11, 8, 1]),
        ),
    ] {
        let (_dir, db, folder) = corrupt_import_rig(seed_sql);
        let lines = Rig::new(&db).send(1, "import.run", json!({"path": folder}));
        assert_eq!(error_of(&lines), ("bad_params".to_string(), STAMP_TEXT.to_string()), "{seed_sql}");
        assert_eq!(import_store_state(&db), state, "{seed_sql}");
    }
}
