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
               "chains": [], "serving": null, "relay_url": null, "relay_kind": null, "relays": null, "relay_list": null})
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

/// BL-7 negative, the twin of the Python oracle's: a folder text full of forbidden strings rides ONLY at
/// `sync.status` `.result.relay_list[N].path`; `sync.run` (the folder is unavailable) and every event say nothing of it.
#[test]
fn a_relay_path_is_legal_only_at_sync_status_relay_list() {
    let needles = ["/users/someone", "@example.com", "garmin", "1234567890"];
    let folder = "/Users/someone/Garmin-1234567890/me@example.com/relay";
    let (_dir, db) = encrypted_store(false);
    let mut rig = Rig::new(&db);
    rig.unlock();
    relay_json(&db, json!({"relays": [{"id": "a1", "kind": "folder", "path": folder, "label": "", "serve": true}]}));
    let status = rig.send(2, "sync.status", json!({}));
    assert_eq!(status.len(), 1, "no event on a status");
    assert_eq!(
        status[0]["result"]["relay_list"],
        json!([{"id": "a1", "kind": "folder", "label": "", "serve": true, "path": folder}])
    );
    let run = rig.send(3, "sync.run", json!({}));
    for line in &run {
        let text = line.to_string().to_lowercase();
        for needle in needles {
            assert!(!text.contains(needle), "{needle} leaked into a sync.run line: {line}");
        }
    }
    let reply = only_response(&run);
    if let Some(sites) = reply["result"]["sites"].as_array() {
        // the serve entry's root is created only by a put, and an empty store puts nothing: the site is clean or unavailable
        assert!(sites.iter().all(|row| row["error"].is_null() || row["error"] == "unavailable"), "{reply}");
    } else {
        assert!(reply.get("error").is_some(), "a run with no usable site answers an error or an unavailable site: {reply}");
    }
    // the only place any needle appears across both calls is that one key
    let status_text = status[0].to_string().to_lowercase();
    let mut without = status[0].clone();
    without["result"]["relay_list"][0]["path"] = Value::Null;
    let stripped = without.to_string().to_lowercase();
    for needle in needles {
        assert!(status_text.contains(needle), "{needle} rides on relay_list[0].path");
        assert!(!stripped.contains(needle), "{needle} appears elsewhere in the status: {}", status[0]);
    }
}

#[test]
fn sync_status_names_the_lan_relay_address_and_nothing_else() {
    let (_dir, db) = encrypted_store(false);
    let mut rig = Rig::new(&db);
    assert_eq!(rig.send(0, "key.unlock", json!({"passphrase": PASSPHRASE}))[0]["result"], json!({"unlocked": true}));
    let url = |rig: &mut Rig| rig.send(1, "sync.status", json!({}))[0]["result"]["relay_url"].clone();
    assert_eq!(url(&mut rig), Value::Null, "no relay.json");
    relay_json(&db, json!({"folder": "/some/folder"}));
    assert_eq!(url(&mut rig), Value::Null, "a folder relay has no address");
    relay_json(&db, json!({"folder": 5}));
    assert_eq!(url(&mut rig), Value::Null, "a file that names nothing");
    relay_json(&db, json!({"lan": "http://192.168.1.20:8321"}));
    assert_eq!(url(&mut rig), json!("http://192.168.1.20:8321"));
    relay_json(&db, json!({"lan": " http://192.168.1.20:8321/ ", "folder": "/f"}));
    assert_eq!(url(&mut rig), json!("http://192.168.1.20:8321"), "trimmed, no trailing slash, lan wins");
    for bad in ["https://192.168.1.20:8321", "http://user@host:1", "http://host:1/path", "192.168.1.20:8321"] {
        relay_json(&db, json!({"lan": bad}));
        assert_eq!(url(&mut rig), Value::Null, "{bad}: not a usable LAN address, so none is shown");
    }
}

#[test]
fn sync_status_relay_list_is_the_file_as_configured() {
    let (_dir, db) = encrypted_store(false);
    let mut rig = Rig::new(&db);
    assert_eq!(rig.send(0, "key.unlock", json!({"passphrase": PASSPHRASE}))[0]["result"], json!({"unlocked": true}));
    let listed = |rig: &mut Rig| rig.send(1, "sync.status", json!({}))[0]["result"]["relay_list"].clone();
    assert_eq!(listed(&mut rig), Value::Null, "no relay.json");
    relay_json(&db, json!({"relays": []}));
    assert_eq!(listed(&mut rig), json!([]));
    relay_json(
        &db,
        json!({"relays": [
            {"id": "a1", "kind": "folder", "path": "/vol/one", "label": "Disk"},
            {"id": "b2", "kind": "folder", "path": "/vol/two", "serve": true},
            {"id": "c3", "kind": "lan", "url": " http://192.168.1.20:8321/ ", "label": "Home"}]}),
    );
    assert_eq!(
        listed(&mut rig),
        json!([
            {"id": "a1", "kind": "folder", "label": "Disk", "serve": false, "path": "/vol/one"},
            {"id": "b2", "kind": "folder", "label": "", "serve": true, "path": "/vol/two"},
            {"id": "c3", "kind": "lan", "label": "Home", "serve": false, "url": "http://192.168.1.20:8321"}])
    );
    relay_json(&db, json!({"relays": [{"id": "d4", "kind": "lan", "url": "http://u:p@10.0.0.1:1"}]}));
    assert_eq!(listed(&mut rig), json!([{"id": "d4", "kind": "lan", "label": "", "serve": false, "url": null}]));
    // the configured text, exactly: never expanded, resolved or stat-ed
    relay_json(
        &db,
        json!({"relays": [{"id": "e5", "kind": "folder", "path": "~/relay x"},
                          {"id": "f6", "kind": "folder", "path": "relay"}]}),
    );
    assert_eq!(
        listed(&mut rig),
        json!([
            {"id": "e5", "kind": "folder", "label": "", "serve": false, "path": "~/relay x"},
            {"id": "f6", "kind": "folder", "label": "", "serve": false, "path": "relay"}])
    );
    relay_json(&db, json!({"folder": "/some/folder"}));
    assert_eq!(
        listed(&mut rig),
        json!([{"id": "default", "kind": "folder", "label": "", "serve": true, "path": "/some/folder"}])
    );
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
                     "records_invalid": 0, "conflicts": 0, "ranges_new": 0, "records_repaired": 0, "records_kept": 0, "gaps": 0, "status": "ok"},
            "sites": [{"id": "default", "kind": "folder", "label": "", "pushed": 1, "healed": 0, "behind": 0, "pulled": 0,
                       "rejected": 0, "error": null}],
            "status": "ok"
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

fn chains_of(rig: &mut Rig, id: i64) -> Vec<Value> {
    let lines = rig.send(id, "sync.status", json!({}));
    lines[0]["result"]["chains"].as_array().expect("chains").clone()
}

#[test]
fn sync_status_chains_name_each_writer_with_counts_and_a_self_flag() {
    let tmp = tempfile::tempdir().expect("tmp");
    let relay = tmp.path().join("relay");
    let (_da, a) = encrypted_store(true);
    let (_db, b) = encrypted_store(false);
    for db in [&a, &b] {
        relay_json(db, json!({"folder": relay}));
    }
    let (mut rig_a, mut rig_b) = (Rig::new(&a), Rig::new(&b));
    rig_a.unlock();
    rig_b.unlock();
    // a fresh store: no chains
    assert_eq!(chains_of(&mut rig_b, 2), Vec::<Value>::new());
    rig_a.send(10, "sync.run", json!({}));
    rig_b.send(11, "sync.run", json!({}));
    let (ca, cb) = (chains_of(&mut rig_a, 12), chains_of(&mut rig_b, 13));
    assert_eq!(ca.len(), 1);
    let row = &ca[0];
    assert_eq!((row["bundles"].as_i64(), row["records"].as_i64(), row["last_seq"].as_i64()), (Some(1), Some(2), Some(1)));
    assert_eq!(row["self"], true);
    assert_eq!(row["chain"].as_str().expect("id").len(), 16);
    assert_eq!(cb.len(), 1);
    assert_eq!(cb[0]["self"], false);
    assert_eq!(
        (&cb[0]["chain"], &cb[0]["bundles"], &cb[0]["records"], &cb[0]["last_seq"]),
        (&row["chain"], &row["bundles"], &row["records"], &row["last_seq"])
    );
    // B now holds something of its own (a different file), pushes; A pulls
    let drop = tmp.path().join("b-drop");
    std::fs::create_dir_all(&drop).expect("mkdir");
    std::fs::copy(
        fixtures().join("synthetic").join("hrv_status.fit.bin"),
        drop.join("hrv_status.fit"),
    )
    .expect("copy");
    let lines = rig_b.send(14, "import.run", json!({"path": drop}));
    assert!(lines.last().expect("response").get("result").is_some());
    rig_b.send(15, "sync.run", json!({}));
    rig_a.send(16, "sync.run", json!({}));
    let (ca, cb) = (chains_of(&mut rig_a, 17), chains_of(&mut rig_b, 18));
    for chains in [&ca, &cb] {
        assert_eq!(chains.len(), 2);
        assert!(chains[0]["chain"].as_str() < chains[1]["chain"].as_str());
        assert_eq!(chains.iter().filter(|c| c["self"] == true).count(), 1);
    }
    let strip = |chains: &Vec<Value>| -> Vec<Value> {
        chains.iter().map(|c| {
            let mut c = c.clone();
            c.as_object_mut().expect("obj").remove("self");
            c
        }).collect()
    };
    assert_eq!(strip(&ca), strip(&cb));
    // each store's own row is the other's non-self row
    let own = |chains: &Vec<Value>| chains.iter().find(|c| c["self"] == true).expect("own")["chain"].clone();
    assert_ne!(own(&ca), own(&cb));
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

fn site_row(id: &str, pushed: i64, healed: i64, pulled: i64, error: Value) -> Value {
    json!({"id": id, "kind": "folder", "label": "", "pushed": pushed, "healed": healed, "behind": 0, "pulled": pulled,
           "rejected": 0, "error": error})
}

fn labelled(mut row: Value, label: &str) -> Value {
    row["label"] = json!(label);
    row
}

#[test]
fn a_relays_param_replaces_the_list_for_the_call_and_status_echoes_the_sites() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (one, two, three) = (tmp.path().join("one"), tmp.path().join("two"), tmp.path().join("three"));
    for folder in [&one, &two, &three] {
        std::fs::create_dir_all(folder).expect("mkdir");
    }
    let (_da, a) = encrypted_store(true);
    let mut rig = Rig::new(&a);
    rig.unlock();
    // no relay.json at all: the param is the list; before the first run `relays` is null
    assert_eq!(rig.send(2, "sync.status", json!({}))[0]["result"]["relays"], Value::Null);
    let missing = tmp.path().join("not mounted");
    let relays = json!([
        {"id": "0000000a", "kind": "folder", "path": one, "label": "one"},
        {"id": "0000000b", "kind": "folder", "path": two},
        {"id": "0000000c", "kind": "folder", "path": missing},
        {"id": "0000000d", "kind": "folder", "unavailable": true},
        {"id": "0000000e", "kind": "folder", "path": one},
    ]);
    let lines = rig.send(3, "sync.run", json!({"relays": relays}));
    let result = &only_response(&lines)["result"];
    let sites = json!([
        labelled(site_row("0000000a", 1, 0, 0, Value::Null), "one"),
        site_row("0000000b", 1, 0, 0, Value::Null),
        site_row("0000000c", 0, 0, 0, json!("unavailable")),
        site_row("0000000d", 0, 0, 0, json!("unavailable")),
        site_row("0000000e", 0, 0, 0, json!("same_relay")),
    ]);
    assert_eq!(result["sites"], sites);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["push"]["bundles"], 1);
    assert!(!missing.exists(), "a missing root is never created");
    let status = rig.send(4, "sync.status", json!({}));
    assert_eq!(status[0]["result"]["relays"], sites, "the last run's sites");

    // a clean run over a legacy-free three-site list: heal after an emptied site, status ok
    let account = disconect_core::relay::bundle::account_for(&master());
    std::fs::remove_dir_all(two.join(&account)).expect("empty a site");
    let relays = json!([
        {"id": "0000000a", "kind": "folder", "path": one},
        {"id": "0000000b", "kind": "folder", "path": two},
        {"id": "0000000c", "kind": "folder", "path": three},
    ]);
    let lines = rig.send(5, "sync.run", json!({"relays": relays}));
    let result = &only_response(&lines)["result"];
    assert_eq!(
        result["sites"],
        json!([
            site_row("0000000a", 0, 0, 0, Value::Null),
            site_row("0000000b", 0, 1, 0, Value::Null),
            site_row("0000000c", 0, 1, 0, Value::Null),
        ])
    );
    assert_eq!(result["status"], "ok");

    // the shape and the empty list
    let empty = rig.send(6, "sync.run", json!({"relays": []}));
    assert_eq!(empty[0]["error"]["code"], "not_found");
    assert_eq!(empty[0]["error"]["message"], "no relay is configured (relay.json in the data folder)");
    for bad in [
        json!("x"),
        json!([5]),
        json!([{"id": "0000000a", "kind": "folder"}]),
        json!([{"id": "NOPE", "kind": "folder", "path": "/x"}]),
        json!([{"id": "0000000a", "kind": "ftp", "path": "/x"}]),
        json!([{"id": "0000000a", "kind": "folder", "path": "/x"}, {"id": "0000000a", "kind": "folder", "path": "/y"}]),
    ] {
        let reply = rig.send(7, "sync.run", json!({"relays": bad}));
        assert_eq!(reply[0]["error"]["code"], "bad_params", "{bad}");
        assert_eq!(reply[0]["error"]["message"], "relays: each entry needs an id, a kind and a path or url");
    }
}

#[test]
fn the_configured_list_runs_when_no_relays_param_is_given_and_a_failing_site_is_partial() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (one, two) = (tmp.path().join("one"), tmp.path().join("two"));
    std::fs::create_dir_all(&one).expect("mkdir");
    let (_da, a) = encrypted_store(true);
    // one entry serves (created on first use), the other is an unmounted folder
    relay_json(
        &a,
        json!({"relays": [
            {"id": "0000000a", "kind": "folder", "path": one},
            {"id": "0000000b", "kind": "folder", "path": two},
        ]}),
    );
    let mut rig = Rig::new(&a);
    rig.unlock();
    let lines = rig.send(2, "sync.run", json!({}));
    let result = &only_response(&lines)["result"];
    assert_eq!(result["status"], "partial");
    assert_eq!(result["sites"][0], site_row("0000000a", 1, 0, 0, Value::Null));
    assert_eq!(result["sites"][1], site_row("0000000b", 0, 0, 0, json!("unavailable")));
    assert!(!two.exists());
    // a lan entry anywhere makes relay_url the first one's base
    relay_json(
        &a,
        json!({"relays": [
            {"id": "0000000a", "kind": "folder", "path": one},
            {"id": "0000000b", "kind": "lan", "url": "http://127.0.0.1:9/"},
        ]}),
    );
    let status = rig.send(3, "sync.status", json!({}));
    assert_eq!(status[0]["result"]["relay_url"], "http://127.0.0.1:9");
}

#[test]
fn an_empty_relay_list_answers_not_found_and_a_public_lan_address_is_refused() {
    let (_da, a) = encrypted_store(true);
    relay_json(&a, json!({"relays": []}));
    let mut rig = Rig::new(&a);
    rig.unlock();
    for (id, method) in [(2, "sync.run"), (3, "relay.addresses")] {
        let reply = rig.send(id, method, json!({}));
        // the phone build cannot serve: its `relay.addresses` refuses before the shared prefix (12-F S5)
        if cfg!(target_os = "ios") && method == "relay.addresses" {
            assert_eq!(reply[0]["error"]["code"], "unsupported_transport", "{method}");
            continue;
        }
        assert_eq!(reply[0]["error"]["code"], "not_found", "{method}");
        assert_eq!(reply[0]["error"]["message"], "no relay is configured (relay.json in the data folder)");
    }
    // a per-call list of one `lan` entry must be an IP literal on a private or local network
    for url in ["http://8.8.8.8:24816", "http://mac.local:24816"] {
        let reply = rig.send(4, "sync.run", json!({"relays": [{"id": "0000000a", "kind": "lan", "url": url}]}));
        assert_eq!(reply[0]["error"]["code"], "bad_params", "{url}");
        assert_eq!(
            reply[0]["error"]["message"],
            "relays: a LAN relay address must be an IP address on a private or local network, not a name"
        );
    }
}

#[test]
fn a_lan_site_in_the_list_is_partial_while_the_mac_is_away_and_carries_its_label() {
    let tmp = tempfile::tempdir().expect("tmp");
    let one = tmp.path().join("one");
    std::fs::create_dir_all(&one).expect("mkdir");
    let (_da, a) = encrypted_store(true);
    // a port nothing listens on
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", closed.local_addr().expect("addr"));
    drop(closed);
    relay_json(
        &a,
        json!({"relays": [
            {"id": "0000000a", "kind": "folder", "path": one, "label": "disk"},
            {"id": "0000000b", "kind": "lan", "url": url, "label": "mac"},
        ]}),
    );
    let mut rig = Rig::new(&a);
    rig.unlock();
    let lines = rig.send(2, "sync.run", json!({}));
    let result = &only_response(&lines)["result"];
    assert_eq!(result["status"], "partial");
    assert_eq!(result["sites"][0]["label"], "disk");
    assert_eq!(result["sites"][0]["error"], Value::Null);
    assert_eq!((result["sites"][1]["label"].as_str(), result["sites"][1]["kind"].as_str()), (Some("mac"), Some("lan")));
    assert_eq!(result["sites"][1]["error"], "unreachable");
}

#[test]
fn auto_runs_the_folder_sites_and_reports_lan_not_auto() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (one, two) = (tmp.path().join("one"), tmp.path().join("two"));
    for folder in [&one, &two] {
        std::fs::create_dir_all(folder).expect("mkdir");
    }
    let (_da, a) = encrypted_store(true);
    // a listener that counts: a connection attempt of the run would be an accept
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    relay_json(
        &a,
        json!({"relays": [
            {"id": "0000000a", "kind": "folder", "path": one},
            {"id": "0000000b", "kind": "folder", "path": two},
            {"id": "0000000c", "kind": "lan", "url": url, "label": "mac"},
        ]}),
    );
    let mut rig = Rig::new(&a);
    rig.unlock();
    let lines = rig.send(2, "sync.run", json!({"auto": true}));
    let result = &only_response(&lines)["result"];
    assert_eq!(result["status"], "ok");
    assert_eq!(result["sites"][0], site_row("0000000a", 1, 0, 0, Value::Null));
    assert_eq!(result["sites"][1], site_row("0000000b", 1, 0, 0, Value::Null));
    let lan = json!({"id": "0000000c", "kind": "lan", "label": "mac", "pushed": 0, "healed": 0, "behind": 0, "pulled": 0,
                     "rejected": 0, "error": "not_auto"});
    assert_eq!(result["sites"][2], lan);
    let accepted = listener.accept();
    assert!(matches!(&accepted, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock), "no connection was opened: {accepted:?}");
    let status = rig.send(3, "sync.status", json!({}));
    assert_eq!(status[0]["result"]["relays"][2], lan);
    assert_eq!(status[0]["result"]["relay_kind"], "mixed");
}

#[test]
fn an_auto_run_never_creates_a_vanished_serve_root_and_a_click_does() {
    let tmp = tempfile::tempdir().expect("tmp");
    let root = tmp.path().join("cloud");
    std::fs::create_dir_all(&root).expect("mkdir");
    let (_da, a) = encrypted_store(true);
    relay_json(&a, json!({"relays": [{"id": "0000000a", "kind": "folder", "path": root, "serve": true}]}));
    let mut rig = Rig::new(&a);
    rig.unlock();
    std::fs::remove_dir_all(&root).expect("rm");
    let lines = rig.send(2, "sync.run", json!({"auto": true}));
    let reply = only_response(&lines);
    // what the same list answers today: a list of one is strict, and a vanished root is `unavailable`
    assert!(!root.exists(), "an auto run does not re-create the root: {reply}");
    let status = rig.send(3, "sync.status", json!({}));
    assert_eq!(status[0]["result"]["relays"][0]["error"], "unavailable", "{reply}");
    assert_eq!(reply["result"]["status"], "partial", "{reply}");
    assert_eq!(reply["result"]["sites"][0]["error"], "unavailable", "{reply}");
    let lines = rig.send(4, "sync.run", json!({}));
    assert_eq!(only_response(&lines)["result"]["status"], "ok");
    assert!(root.is_dir(), "a click re-creates the serve root");
}

#[test]
fn an_auto_run_keeps_each_not_auto_sites_click_row_in_the_remembered_relays() {
    let tmp = tempfile::tempdir().expect("tmp");
    let folder = tmp.path().join("one");
    std::fs::create_dir_all(&folder).expect("mkdir");
    let (_da, a) = encrypted_store(true);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", closed.local_addr().expect("addr"));
    drop(closed);
    relay_json(
        &a,
        json!({"relays": [
            {"id": "0000000a", "kind": "folder", "path": folder},
            {"id": "0000000b", "kind": "lan", "url": url, "label": "mac"},
        ]}),
    );
    let mut rig = Rig::new(&a);
    rig.unlock();
    let lines = rig.send(2, "sync.run", json!({}));
    assert_eq!(only_response(&lines)["result"]["sites"][1]["error"], "unreachable");
    let click_lan = rig.send(3, "sync.status", json!({}))[0]["result"]["relays"][1].clone();
    let lines = rig.send(4, "sync.run", json!({"auto": true}));
    // the run's own answer still says `not_auto`
    assert_eq!(only_response(&lines)["result"]["sites"][1]["error"], "not_auto");
    let relays = rig.send(5, "sync.status", json!({}))[0]["result"]["relays"].clone();
    assert_eq!(relays[1], click_lan, "the click's row is kept");
    assert_eq!(relays[1]["error"], "unreachable");
    assert_eq!(relays[0]["pushed"], 0, "the folder row is the auto run's own (nothing new to push)");
}

#[test]
fn auto_with_no_folder_site_is_not_folder() {
    let (_da, a) = encrypted_store(true);
    relay_json(&a, json!({"lan": "http://127.0.0.1:9"}));
    let mut rig = Rig::new(&a);
    rig.unlock();
    let text = "auto sync runs over folder relays only; the list has none";
    let reply = rig.send(2, "sync.run", json!({"auto": true}));
    assert_eq!((reply[0]["error"]["code"].as_str(), reply[0]["error"]["message"].as_str()), (Some("not_folder"), Some(text)));
    let per_call = json!([{"id": "0000000a", "kind": "lan", "url": "http://8.8.8.8:1"}]);
    let reply = rig.send(3, "sync.run", json!({"auto": true, "relays": per_call}));
    assert_eq!(reply[0]["error"]["code"], "not_folder");
    let reply = rig.send(4, "sync.run", json!({"auto": true, "relays": []}));
    assert_eq!(reply[0]["error"]["code"], "not_found");
}

#[test]
fn auto_must_be_true_or_absent() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (_da, a) = encrypted_store(true);
    relay_json(&a, json!({"folder": tmp.path().join("relay")}));
    let mut rig = Rig::new(&a);
    rig.unlock();
    for bad in [json!(false), json!(null), json!(1), json!("true")] {
        let reply = rig.send(2, "sync.run", json!({"auto": bad}));
        assert_eq!(reply[0]["error"]["code"], "bad_params", "{bad}");
        assert_eq!(reply[0]["error"]["message"], "auto: true or absent");
    }
}

#[test]
fn relay_kind_in_sync_status() {
    let (_da, a) = encrypted_store(false);
    let mut rig = Rig::new(&a);
    rig.unlock();
    let kind = |rig: &mut Rig, id: i64| rig.send(id, "sync.status", json!({}))[0]["result"]["relay_kind"].clone();
    assert_eq!(kind(&mut rig, 1), Value::Null);
    relay_json(&a, json!({"relays": []}));
    assert_eq!(kind(&mut rig, 2), Value::Null);
    relay_json(&a, json!({"folder": "/f"}));
    assert_eq!(kind(&mut rig, 3), json!("folder"));
    relay_json(&a, json!({"lan": "http://127.0.0.1:9"}));
    assert_eq!(kind(&mut rig, 4), json!("lan"));
    relay_json(&a, json!({"relays": [
        {"id": "0000000a", "kind": "folder", "path": "/f"},
        {"id": "0000000b", "kind": "lan", "url": "http://127.0.0.1:9"},
    ]}));
    assert_eq!(kind(&mut rig, 5), json!("mixed"));
}
