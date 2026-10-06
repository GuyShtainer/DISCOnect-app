// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sync.status` and `sync.run` over the `serve` protocol, in process (Bet 12, slice B): the
//! checks in order, the progress events, counts-only results, the slot shared with `import.run`,
//! and the LAN transport on 127.0.0.1. The byte-level comparison with the Python oracle is
//! `tools/serve_diff.py` (its sync leg).

mod common;

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use common::{PASSPHRASE, encrypted_copy, fixtures};
use disconect_core::keys::{self, PassphraseSource};
use disconect_core::relay::lan_server::LanServer;
use disconect_core::serve::{self, Channel, Session};
use disconect_core::sources::import_path;
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

    fn send(&mut self, id: i64, method: &str, params: Value) -> Vec<Value> {
        let line = format!(
            "{}\n",
            json!({"id": id, "method": method, "params": params})
        );
        assert_eq!(serve::serve_lines(&mut self.session, line.as_bytes()), 0);
        self.lines()
    }

    fn unlock(&mut self) {
        let lines = self.send(1, "key.unlock", json!({"passphrase": PASSPHRASE}));
        assert_eq!(lines[0]["result"], json!({"unlocked": true}));
    }
}

fn request(id: i64, method: &str, params: Value) -> Vec<u8> {
    format!(
        "{}\n",
        json!({"id": id, "method": method, "params": params})
    )
    .into_bytes()
}

fn master() -> Vec<u8> {
    keys::unlock(
        &fixtures().join("test.keys.json"),
        PassphraseSource::Explicit(PASSPHRASE),
    )
    .expect("unlock the fixture key")
    .to_vec()
}

/// An encrypted scratch store, optionally holding the two synthetic monitoring FIT files.
fn encrypted_store(with_data: bool) -> (tempfile::TempDir, PathBuf) {
    let (dir, db) = encrypted_copy();
    if with_data {
        let drop = dir.path().join("drop");
        std::fs::create_dir_all(&drop).expect("mkdir");
        for stem in ["monitoring_timestamp16", "monitoring_cycles_resolution"] {
            std::fs::copy(
                fixtures().join("synthetic").join(format!("{stem}.fit.bin")),
                drop.join(format!("{stem}.fit")),
            )
            .expect("copy");
        }
        let secret = keys::unlock(
            &keys::key_path_for(&db),
            PassphraseSource::Explicit(PASSPHRASE),
        )
        .expect("unlock");
        let opened = store::open_for_write_with(&db, "test", 5.0, Some(&secret)).expect("open");
        import_path(opened.conn(), &drop, None, None).expect("import");
    }
    (dir, db)
}

fn relay_json(db: &Path, body: Value) {
    let path = db.parent().expect("folder").join("relay.json");
    std::fs::write(path, body.to_string()).expect("relay.json");
}

fn only_response(lines: &[Value]) -> &Value {
    let (last, before) = lines.split_last().expect("a response");
    assert!(
        before.iter().all(|l| l.get("event").is_some()),
        "every event precedes the response"
    );
    last
}

fn sync_events(lines: &[Value]) -> Vec<(String, String)> {
    lines
        .iter()
        .filter(|l| l.get("event").is_some())
        .map(|l| {
            assert_eq!(
                (l["event"].as_str(), l["op"].as_str()),
                (Some("progress"), Some("sync"))
            );
            (
                l["phase"].as_str().expect("phase").to_string(),
                l["state"].as_str().expect("state").to_string(),
            )
        })
        .collect()
}

#[test]
fn the_checks_run_in_order_locked_then_no_relay_then_no_key() {
    // a plaintext store: nothing to unlock, but nothing to derive a relay from either
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("plain.db");
    store::open_for_write(&db, "test", 1.0, PassphraseSource::Explicit("unused")).expect("create");
    let mut rig = Rig::new(&db);
    let status = rig.send(1, "sync.status", json!({}));
    assert_eq!(
        status[0]["result"],
        json!({"bundles": {}, "records_unsent": 0, "records_seen": 0, "conflicts": 0,
               "superseded": 0, "gaps": [], "last_pushed_at": null, "last_pulled_at": null,
               "serving": null})
    );
    let none = rig.send(2, "sync.run", json!({}));
    assert_eq!(none[0]["error"]["code"], "not_found");
    assert_eq!(
        none[0]["error"]["message"],
        "no relay is configured (relay.json in the data folder)"
    );
    relay_json(&db, json!({"folder": dir.path().join("relay")}));
    let plain = rig.send(3, "sync.run", json!({}));
    assert_eq!(plain[0]["error"]["code"], "not_encrypted");
    assert!(
        plain[0]["error"]["message"]
            .as_str()
            .expect("message")
            .starts_with("the relay needs an encrypted store")
    );

    // an encrypted store before unlock: locked first, whatever relay.json says
    let (edir, edb) = encrypted_store(false);
    let mut locked = Rig::new(&edb);
    for (id, method) in [(1, "sync.status"), (2, "sync.run")] {
        let lines = locked.send(id, method, json!({}));
        assert_eq!(lines[0]["error"]["code"], "locked", "{method}");
    }
    relay_json(&edb, json!({"folder": edir.path().join("relay")}));
    let lines = locked.send(3, "sync.run", json!({}));
    assert_eq!(lines[0]["error"]["code"], "locked");
}

#[test]
fn a_folder_relay_pushes_then_pulls_with_events_and_counts_only() {
    let tmp = tempfile::tempdir().expect("tmp");
    let relay = tmp.path().join("relay");
    let (_da, a) = encrypted_store(true);
    let (_db, b) = encrypted_store(false);
    for db in [&a, &b] {
        relay_json(db, json!({"folder": relay}));
    }
    let mut rig_a = Rig::new(&a);
    rig_a.unlock();
    let lines = rig_a.send(10, "sync.run", json!({}));
    assert_eq!(
        sync_events(&lines),
        [
            ("push", "start"),
            ("push", "done"),
            ("pull", "start"),
            ("pull", "done")
        ]
        .map(|(p, s)| (p.to_string(), s.to_string()))
    );
    let done = &lines[1];
    assert_eq!(
        (
            done["bundles"].as_i64(),
            done["records"].as_i64(),
            done["ranges"].as_i64()
        ),
        (Some(1), Some(2), Some(0))
    );
    let response = only_response(&lines);
    assert_eq!(response["id"], 10);
    assert_eq!(
        response["result"],
        json!({
            "push": {"bundles": 1, "records": 2, "ranges": 0},
            "pull": {"applied": 0, "rejected": 0, "records_new": 0, "records_duplicate": 0,
                     "records_invalid": 0, "conflicts": 0, "ranges_new": 0, "records_repaired": 0, "records_kept": 0, "gaps": 0, "status": "ok"}
        })
    );
    let status = rig_a.send(11, "sync.status", json!({}));
    assert_eq!(status[0]["result"]["bundles"], json!({"pushed_applied": 1}));
    assert_eq!(status[0]["result"]["records_unsent"], 0);

    let mut rig_b = Rig::new(&b);
    rig_b.unlock();
    let lines = rig_b.send(20, "sync.run", json!({}));
    let result = &only_response(&lines)["result"];
    assert_eq!(
        result["push"],
        json!({"bundles": 0, "records": 0, "ranges": 0})
    );
    assert_eq!(result["pull"]["applied"], 1);
    assert_eq!(result["pull"]["records_new"], 2);
    // nothing travels again
    let again = rig_b.send(21, "sync.run", json!({}));
    assert_eq!(only_response(&again)["result"]["pull"]["applied"], 0);
    let status = rig_b.send(22, "sync.status", json!({}));
    assert_eq!(status[0]["result"]["bundles"], json!({"pulled_applied": 1}));
    assert_eq!(status[0]["result"]["records_seen"], 2);
}

#[test]
fn the_lan_transport_serves_sync_run_and_names_its_failures() {
    let tmp = tempfile::tempdir().expect("tmp");
    let server = LanServer::start(
        "127.0.0.1:0",
        tmp.path().join("served"),
        &master(),
        Arc::new(|_, _| {}),
    )
    .expect("serve");
    let url = format!("http://{}", server.local_addr());
    let (_da, a) = encrypted_store(true);
    let (_db, b) = encrypted_store(false);
    relay_json(&a, json!({"lan": url}));
    relay_json(&b, json!({"lan": url}));
    let mut rig_a = Rig::new(&a);
    rig_a.unlock();
    let lines = rig_a.send(1, "sync.run", json!({}));
    assert_eq!(only_response(&lines)["result"]["push"]["bundles"], 1);
    let mut rig_b = Rig::new(&b);
    rig_b.unlock();
    let lines = rig_b.send(2, "sync.run", json!({}));
    assert_eq!(only_response(&lines)["result"]["pull"]["records_new"], 2);

    // a server for another master: its answers carry a tag this device cannot verify
    let stranger = LanServer::start(
        "127.0.0.1:0",
        tmp.path().join("other"),
        &(1u8..33).collect::<Vec<_>>(),
        Arc::new(|_, _| {}),
    )
    .expect("serve");
    relay_json(
        &a,
        json!({"lan": format!("http://{}", stranger.local_addr())}),
    );
    let lines = rig_a.send(3, "sync.run", json!({}));
    let error = &only_response(&lines)["error"];
    assert_eq!(error["code"], "relay_unverified");
    stranger.stop();

    // a server that went away: unreachable, reported as not_found with its own text
    let down = format!("http://{}", server.local_addr());
    server.stop();
    relay_json(&a, json!({"lan": down}));
    let lines = rig_a.send(4, "sync.run", json!({}));
    let error = &only_response(&lines)["error"];
    assert_eq!(error["code"], "not_found");
    assert_eq!(error["message"], "the relay is unreachable (retry later)");
    // a malformed address is a bad_params, before anything is opened
    relay_json(&a, json!({"lan": "https://127.0.0.1:9"}));
    let lines = rig_a.send(5, "sync.run", json!({}));
    assert_eq!(lines[0]["error"]["code"], "bad_params");
    let status = rig_a.send(6, "sync.status", json!({}));
    assert_eq!(status[0]["result"]["bundles"], json!({"pushed_applied": 1}));
}

#[test]
fn sync_run_shares_the_slot_with_import_run() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (dir, db) = encrypted_store(true);
    relay_json(&db, json!({"folder": tmp.path().join("relay")}));
    let drop = dir.path().join("drop");
    let mut rig = Rig::new(&db);
    rig.unlock();
    let (release, gate) = mpsc::channel::<()>();
    rig.session.hold_next_import(gate);
    let mut chunks = VecDeque::new();
    chunks.push_back(request(1, "import.run", json!({"path": drop})));
    chunks.push_back(request(2, "sync.run", json!({})));
    let mut input = Pieces {
        chunks,
        at_end: Some(Box::new(move || drop_sender(release))),
    };
    assert_eq!(serve::serve_lines(&mut rig.session, &mut input), 0);
    let lines = rig.lines();
    let busy = lines.iter().find(|l| l["id"] == 2).expect("answer");
    assert_eq!(busy["error"]["code"], "busy");
    assert_eq!(
        busy["error"]["message"],
        "an import or a sync is already running"
    );
    // the slot is free again, and the sync after the import works
    let lines = rig.send(3, "sync.run", json!({}));
    assert_eq!(only_response(&lines)["result"]["push"]["bundles"], 1);
}

fn drop_sender(sender: mpsc::Sender<()>) {
    drop(sender);
}

#[test]
fn a_verified_refusal_ten_minutes_off_is_relay_auth_failed() {
    use disconect_core::relay::lan::{AUTH_HEADER, RESP_HEADER, resp_header_value, token_key, wall_clock};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let key = token_key(&master());
    let thread = std::thread::spawn(move || {
        // answers every request with a 401 tagged under the right key and a server clock 10 minutes ahead
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&chunk[..n]),
                }
            }
            let head = String::from_utf8_lossy(&raw).to_string();
            let mut lines = head.split("\r\n");
            let mut first = lines.next().unwrap_or("").split(' ');
            let (method, target) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
            let auth = lines
                .filter_map(|l| l.split_once(':'))
                .find(|(n, _)| n.eq_ignore_ascii_case(AUTH_HEADER))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            let tag = resp_header_value(&*key, method, target, &auth, wall_clock() + 600, 401, b"").expect("tag");
            let _ = stream.write_all(
                format!("HTTP/1.1 401 X\r\nConnection: close\r\n{RESP_HEADER}: {tag}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
            );
        }
    });
    let (_da, a) = encrypted_store(true);
    relay_json(&a, json!({"lan": format!("http://{addr}")}));
    let mut rig = Rig::new(&a);
    rig.unlock();
    let lines = rig.send(1, "sync.run", json!({}));
    let error = &only_response(&lines)["error"];
    assert_eq!(error["code"], "relay_auth_failed");
    assert!(
        error["message"].as_str().expect("message").contains("10 minutes off the relay's"),
        "{error}"
    );
    drop(thread);
}
