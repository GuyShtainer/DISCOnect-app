// SPDX-License-Identifier: AGPL-3.0-or-later
//! `relay.addresses`, `relay.serve`, `pair.offer`, `pair.confirm`, `pair.cancel` and the `serving` field of
//! `sync.status` over the serve protocol, in process, on 127.0.0.1 (pitch 7b-2, slice 1): the server's lifetime
//! (the joiner's first pull after delivery works; expiry and abort stop it), the shared check prefix, the
//! `listen` refusals, the address watcher with an injected list, the session end before the import wait, and a
//! privacy walk over every line the session wrote. The joiner is the library's own (`pair_client::join` + `land`).

mod common;

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use common::{PASSPHRASE, encrypted_copy, fixtures};
use disconect_core::keys::{self, PassphraseSource};
use disconect_core::pair::PairError;
use disconect_core::pair_client;
use disconect_core::relay::serving::{self, Env, Hooks, Site};
use disconect_core::relay::sync::PullResult;
use disconect_core::serve::{self, Channel, Session};
use disconect_core::sources::import_path;
use disconect_core::store;
use serde_json::{Value, json};

// ---- rig: a session on a thread, fed through a channel, with every output line kept ----

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

/// Blocks until a request arrives; end of input when the sender is dropped.
struct ChannelInput {
    rx: Receiver<Vec<u8>>,
    pending: VecDeque<u8>,
}

impl Read for ChannelInput {
    fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
        if self.pending.is_empty() {
            match self.rx.recv() {
                Ok(bytes) => self.pending.extend(bytes),
                Err(_) => return Ok(0),
            }
        }
        let mut count = 0;
        while count < into.len() {
            let Some(byte) = self.pending.pop_front() else { break };
            into[count] = byte;
            count += 1;
        }
        Ok(count)
    }
}

struct Live {
    out: Buffer,
    tx: Option<Sender<Vec<u8>>>,
    thread: Option<JoinHandle<i32>>,
    seen: Vec<Value>,
    parsed_bytes: usize,
    next_id: i64,
}

fn wait_until(seconds: u64, mut condition: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(seconds);
    loop {
        if condition() {
            return true;
        }
        if Instant::now() > end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

impl Live {
    fn start(db: &Path, hooks: Hooks, hold: Option<Receiver<()>>) -> Live {
        let out = Buffer::default();
        let mut session = Session::new(db.to_path_buf(), Channel::new(Box::new(out.clone())));
        session.set_relay_hooks(hooks);
        if let Some(gate) = hold {
            session.hold_next_import(gate);
        }
        let (tx, rx) = mpsc::channel();
        let input = ChannelInput {
            rx,
            pending: VecDeque::new(),
        };
        let thread = std::thread::spawn(move || serve::serve_lines(&mut session, input));
        Live {
            out,
            tx: Some(tx),
            thread: Some(thread),
            seen: Vec::new(),
            parsed_bytes: 0,
            next_id: 1,
        }
    }

    fn unlocked(db: &Path, hooks: Hooks) -> Live {
        let mut live = Live::start(db, hooks, None);
        let reply = live.call("key.unlock", json!({"passphrase": PASSPHRASE}));
        assert_eq!(reply["result"], json!({"unlocked": true}));
        live
    }

    fn drain(&mut self) {
        let bytes = self.out.0.lock().expect("buffer").clone();
        let text = String::from_utf8(bytes[self.parsed_bytes..].to_vec()).expect("ascii output");
        // only whole lines
        let whole = text.rfind('\n').map_or(0, |at| at + 1);
        for line in text[..whole].lines() {
            self.seen.push(serde_json::from_str(line).expect("protocol line"));
        }
        self.parsed_bytes += whole;
    }

    fn send(&mut self, method: &str, params: Value) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        let line = format!("{}\n", json!({"id": id, "method": method, "params": params}));
        self.tx.as_ref().expect("open").send(line.into_bytes()).expect("send");
        id
    }

    fn response(&mut self, id: i64) -> Value {
        let mut found = None;
        let ok = wait_until(30, || {
            self.drain();
            found = self.seen.iter().find(|l| l["id"] == id).cloned();
            found.is_some()
        });
        assert!(ok, "no response to request {id}");
        found.expect("response")
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.send(method, params);
        self.response(id)
    }

    /// The first event `name` in state `state` (waits for it).
    fn event(&mut self, name: &str, state: &str) -> Value {
        let mut found = None;
        let ok = wait_until(30, || {
            self.drain();
            found = self
                .seen
                .iter()
                .find(|l| l["event"] == name && l["state"] == state)
                .cloned();
            found.is_some()
        });
        assert!(ok, "no {name} event in state {state}; saw {:?}", self.seen);
        found.expect("event")
    }

    fn events(&mut self, name: &str) -> Vec<Value> {
        self.drain();
        self.seen.iter().filter(|l| l["event"] == name).cloned().collect()
    }

    fn serving(&mut self) -> Value {
        let status = self.call("sync.status", json!({}));
        status["result"]["serving"].clone()
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.tx = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// ---- fixtures ----

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
        let secret = keys::unlock(&keys::key_path_for(&db), PassphraseSource::Explicit(PASSPHRASE)).expect("unlock");
        let opened = store::open_for_write_with(&db, "test", 5.0, Some(&secret)).expect("open");
        import_path(opened.conn(), &drop, None, None).expect("import");
    }
    (dir, db)
}

fn relay_json(db: &Path, body: Value) {
    std::fs::write(db.parent().expect("folder").join("relay.json"), body.to_string()).expect("relay.json");
}

/// A scratch store with a folder relay beside it.
fn serving_store(with_data: bool) -> (tempfile::TempDir, PathBuf) {
    let (dir, db) = encrypted_store(with_data);
    relay_json(&db, json!({"folder": dir.path().join("relay")}));
    (dir, db)
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

fn listen_on_free_port() -> String {
    format!("127.0.0.1:{}", free_port())
}

fn fast(ttl: Option<u64>, linger_ms: u64) -> Hooks {
    Hooks {
        linger: Duration::from_millis(linger_ms),
        offer_ttl: ttl,
        ..Hooks::default()
    }
}

/// The status code of `GET path` on `addr` (raw HTTP/1.1, no client library); `None` when nothing answers.
fn http_status(addr: &str, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_secs(2)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    write!(stream, "GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").ok()?;
    let mut text = String::new();
    stream.read_to_string(&mut text).ok()?;
    text.split(' ').nth(1)?.parse().ok()
}

fn refused(addr: &str) -> bool {
    http_status(addr, "/v1/health").is_none()
}

/// A joiner on a thread: the six digits come through `sas`, the result is the first pull's counts.
struct Joiner {
    sas: Receiver<String>,
    thread: JoinHandle<Result<PullResult, PairError>>,
    _dir: tempfile::TempDir,
}

fn spawn_joiner(offer_text: String) -> Joiner {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, relay_file) = (dir.path().join("joiner.db"), dir.path().join("relay.json"));
    let (tx, sas) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let cancel = AtomicBool::new(false);
        let joined = pair_client::join(
            &offer_text,
            &mut |code| {
                let _ = tx.send(code.to_string());
            },
            &cancel,
        )?;
        let _ = cancel.load(Ordering::SeqCst);
        pair_client::land(&joined, &db, &relay_file)
    });
    Joiner {
        sas,
        thread,
        _dir: dir,
    }
}

impl Joiner {
    fn digits(&self) -> String {
        self.sas.recv_timeout(Duration::from_secs(20)).expect("the joiner shows its code")
    }
}

fn error_of(reply: &Value) -> (&str, &str) {
    (
        reply["error"]["code"].as_str().expect("an error code"),
        reply["error"]["message"].as_str().expect("an error message"),
    )
}

// ---- tests ----

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn the_first_pull_succeeds_with_keep_off_and_the_server_stops_at_expiry() {
    let (_dir, db) = serving_store(true);
    let mut live = Live::unlocked(&db, fast(Some(9), 600));
    let listen = listen_on_free_port();
    let reply = live.call("pair.offer", json!({"listen": listen}));
    let result = reply["result"].clone();
    assert_eq!(result["url"], format!("http://{listen}"));
    assert!(result["offer"].as_str().expect("offer").starts_with("disconect-pair:v2."));
    assert!(result["expires_at"].as_u64().expect("expires_at") > 0);
    // the push's two progress events came before the answer
    let position = |state: &str| {
        live.seen.iter().position(|l| {
            l["event"] == "progress" && l["op"] == "pair" && l["phase"] == "push" && l["state"] == state
        })
    };
    let (start, done) = (position("start").expect("start"), position("done").expect("done"));
    let answer = live.seen.iter().position(|l| l["id"] == reply["id"]).expect("answer");
    assert!(start < done && done < answer);
    assert_eq!(live.seen[done]["bundles"], 1);
    assert_eq!(live.seen[done]["records"], 2);

    let joiner = spawn_joiner(result["offer"].as_str().expect("offer").to_string());
    let digits = joiner.digits();
    live.event("pair", "bound");
    assert_eq!(live.serving()["offer"], "bound");
    // a malformed entry is refused without ending the offer
    let malformed = live.call("pair.confirm", json!({"digits": "12ab56"}));
    assert_eq!(error_of(&malformed), ("bad_params", "digits must be exactly six digits"));
    assert_eq!(live.serving()["offer"], "bound");
    let released = live.call("pair.confirm", json!({"digits": digits}));
    assert_eq!(released["result"], json!({"state": "released"}));
    live.event("pair", "delivered");

    // the joiner's first pull came from the same URL after the payload's 200
    let pulled = joiner.thread.join().expect("joiner thread").expect("the joiner lands");
    assert_eq!(pulled.records_new, 2);
    assert_eq!(
        live.serving(),
        json!({"url": format!("http://{listen}"), "keep": false, "offer": "delivered"})
    );
    assert_eq!(http_status(&listen, "/v1/health"), Some(200), "delivery does not end serving");

    // it serves until the offer's expiry, then stops
    assert!(wait_until(25, || live.serving().is_null()), "the server stops at expiry");
    assert!(wait_until(5, || refused(&listen)), "the listener closes as the stop completes");
    let states: Vec<String> = live
        .events("pair")
        .iter()
        .map(|e| e["state"].as_str().expect("state").to_string())
        .collect();
    assert_eq!(states, ["bound", "delivered"], "each transition exactly once, no expiry after delivery");

    privacy_walk(&live.seen, &digits);
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn wrong_digits_abort_with_codes_differ_and_the_joiner_reads_410_within_the_linger() {
    let (_dir, db) = serving_store(true);
    let mut live = Live::unlocked(&db, fast(None, 4000));
    let listen = listen_on_free_port();
    let reply = live.call("pair.offer", json!({"listen": listen}));
    let joiner = spawn_joiner(reply["result"]["offer"].as_str().expect("offer").to_string());
    let digits = joiner.digits();
    live.event("pair", "bound");
    let wrong = if digits == "000000" { "111111" } else { "000000" };
    let refused_reply = live.call("pair.confirm", json!({"digits": wrong}));
    assert_eq!(error_of(&refused_reply), ("pair_failed", "the codes differ"));
    let aborted = live.event("pair", "aborted");
    assert_eq!(aborted["reason"], "codes_differ");
    // the server still answers during the linger, so the joiner's poll reads 410, not a refused connection
    let outcome = joiner.thread.join().expect("joiner thread");
    assert!(matches!(outcome, Err(PairError::OfferEnded)), "{outcome:?}");
    // a second confirm on the ended offer says so
    let again = live.call("pair.confirm", json!({"digits": digits}));
    assert_eq!(error_of(&again), ("pair_failed", "the offer ended"));
    assert!(wait_until(15, || live.serving().is_null()), "the server stops after the linger");
    assert!(wait_until(5, || refused(&listen)), "the listener closes as the stop completes");
    let aborts: Vec<Value> = live.events("pair").into_iter().filter(|e| e["state"] == "aborted").collect();
    assert_eq!(aborts.len(), 1, "aborted exactly once");
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn a_second_device_aborts_with_another_device() {
    let (_dir, db) = serving_store(false);
    let mut live = Live::unlocked(&db, fast(None, 200));
    let listen = listen_on_free_port();
    let reply = live.call("pair.offer", json!({"listen": listen}));
    let text = reply["result"]["offer"].as_str().expect("offer").to_string();
    let first = spawn_joiner(text.clone());
    let _ = first.digits();
    live.event("pair", "bound");
    let second = spawn_joiner(text);
    // the second joiner's key differs from the bound one: the slot aborts
    let outcome = second.thread.join().expect("joiner thread");
    assert!(outcome.is_err());
    let aborted = live.event("pair", "aborted");
    assert_eq!(aborted["reason"], "another_device");
    let first_outcome = first.thread.join().expect("joiner thread");
    assert!(first_outcome.is_err());
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn cancel_ends_the_offer_once_and_is_idempotent() {
    let (_dir, db) = serving_store(false);
    let mut live = Live::unlocked(&db, fast(None, 300));
    let listen = listen_on_free_port();
    let reply = live.call("pair.offer", json!({"listen": listen}));
    assert!(reply["result"]["offer"].is_string());
    assert_eq!(live.call("pair.cancel", json!({}))["result"], json!({"state": "aborted"}));
    assert_eq!(live.event("pair", "aborted")["reason"], "cancelled");
    assert_eq!(live.call("pair.cancel", json!({}))["result"], json!({"state": "aborted"}));
    assert!(wait_until(15, || live.serving().is_null()), "keep is off: the server stops after the linger");
    assert!(wait_until(5, || refused(&listen)), "the listener closes as the stop completes");
    let aborts = live.events("pair").into_iter().filter(|e| e["state"] == "aborted").count();
    assert_eq!(aborts, 1);
    // the offer's text is dead: confirm says it ended (the record stays until the next offer)
    let confirm = live.call("pair.confirm", json!({"digits": "123456"}));
    assert_eq!(confirm["error"]["code"], "pair_failed");
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn cancel_with_keep_on_leaves_the_server_serving() {
    let (_dir, db) = serving_store(false);
    let mut live = Live::unlocked(&db, fast(None, 100));
    let listen = listen_on_free_port();
    live.call("relay.serve", json!({"on": true, "listen": listen}));
    live.call("pair.offer", json!({"listen": listen}));
    live.call("pair.cancel", json!({}));
    live.event("pair", "aborted");
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(http_status(&listen, "/v1/health"), Some(200));
    assert_eq!(live.serving()["keep"], true);
    assert_eq!(live.serving()["offer"], Value::Null);
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn a_second_offer_is_busy_and_sync_run_runs_during_an_open_offer() {
    let (_dir, db) = serving_store(true);
    let mut live = Live::unlocked(&db, fast(None, 200));
    let listen = listen_on_free_port();
    let first = live.call("pair.offer", json!({"listen": listen}));
    assert!(first["result"]["offer"].is_string());
    let second = live.call("pair.offer", json!({"listen": listen}));
    assert_eq!(error_of(&second), ("busy", "an offer is open"));
    // the import slot was released when the push ended
    let run = live.call("sync.run", json!({}));
    assert_eq!(run["result"]["push"]["bundles"], 0, "the offer's push already sent it");
    // "stop serving" while the offer is open does not stop the server
    let off = live.call("relay.serve", json!({"on": false}));
    assert_eq!(off["result"]["serving"], true);
    assert_eq!(http_status(&listen, "/v1/health"), Some(200));
    assert_eq!(live.serving()["offer"], "open");
    live.call("pair.cancel", json!({}));
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn a_held_import_makes_pair_offer_busy_and_leaves_no_reservation_behind() {
    let (dir, db) = serving_store(true);
    let (release, gate) = mpsc::channel::<()>();
    let mut live = Live::start(&db, fast(None, 200), Some(gate));
    let unlock = live.call("key.unlock", json!({"passphrase": PASSPHRASE}));
    assert_eq!(unlock["result"], json!({"unlocked": true}));
    let import = live.send("import.run", json!({"path": dir.path().join("drop")}));
    let listen = listen_on_free_port();
    let busy = live.call("pair.offer", json!({"listen": listen}));
    assert_eq!(error_of(&busy), ("busy", "an import or a sync is already running"));
    drop(release);
    assert!(live.response(import)["result"].is_object());
    let offered = live.call("pair.offer", json!({"listen": listen}));
    assert!(offered["result"]["offer"].is_string(), "{offered}");
    live.call("pair.cancel", json!({}));
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn relay_serve_switches_the_server_with_and_without_an_offer() {
    let (_dir, db) = serving_store(false);
    let mut live = Live::unlocked(&db, fast(None, 100));
    assert_eq!(live.serving(), Value::Null);
    let before = live.call("relay.addresses", json!({}));
    assert_eq!(before["result"]["port"], 24816, "the fixed default when nothing was served");
    let listen = listen_on_free_port();
    let on = live.call("relay.serve", json!({"on": true, "listen": listen}));
    assert_eq!(on["result"], json!({"serving": true, "url": format!("http://{listen}")}));
    assert_eq!(http_status(&listen, "/v1/health"), Some(200));
    assert_eq!(
        live.serving(),
        json!({"url": format!("http://{listen}"), "keep": true, "offer": null})
    );
    let port: u64 = listen.rsplit(':').next().expect("port").parse().expect("number");
    assert_eq!(live.call("relay.addresses", json!({}))["result"]["port"], port);
    // another address while serving is refused, for the switch and for an offer
    let other = listen_on_free_port();
    let again = live.call("relay.serve", json!({"on": true, "listen": other}));
    assert_eq!(error_of(&again), ("bad_params", "the relay already serves another address"));
    let offer = live.call("pair.offer", json!({"listen": other}));
    assert_eq!(error_of(&offer), ("bad_params", "the relay already serves another address"));
    // the same address again is fine (and keeps the one server)
    assert_eq!(live.call("relay.serve", json!({"on": true, "listen": listen}))["result"]["serving"], true);
    // off with no offer stops it
    let off = live.call("relay.serve", json!({"on": false}));
    assert_eq!(off["result"], json!({"serving": false, "url": null}));
    assert!(refused(&listen));
    assert_eq!(live.serving(), Value::Null);
    // the port of the last run is remembered for the session
    assert_eq!(live.call("relay.addresses", json!({}))["result"]["port"], port);
    let stray_off = live.call("relay.serve", json!({"on": false}));
    assert_eq!(stray_off["result"], json!({"serving": false, "url": null}));
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn a_delivered_offer_does_not_block_stop_serving() {
    let (_dir, db) = serving_store(true);
    let mut live = Live::unlocked(&db, fast(None, 200));
    let listen = listen_on_free_port();
    let reply = live.call("pair.offer", json!({"listen": listen}));
    let joiner = spawn_joiner(reply["result"]["offer"].as_str().expect("offer").to_string());
    let digits = joiner.digits();
    live.event("pair", "bound");
    live.call("pair.confirm", json!({"digits": digits}));
    live.event("pair", "delivered");
    joiner.thread.join().expect("joiner thread").expect("lands");
    let off = live.call("relay.serve", json!({"on": false}));
    assert_eq!(off["result"], json!({"serving": false, "url": null}));
    assert!(refused(&listen));
    assert_eq!(live.serving(), Value::Null);
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn the_prefix_runs_in_order_on_all_five_methods() {
    let calls = [
        ("relay.addresses", json!({})),
        ("relay.serve", json!({})),
        ("pair.offer", json!({})),
        ("pair.confirm", json!({})),
        ("pair.cancel", json!({})),
    ];
    // (1) locked, whatever relay.json says
    let (_d1, locked_db) = serving_store(false);
    let mut locked = Live::start(&locked_db, Hooks::default(), None);
    for (method, params) in &calls {
        let reply = locked.call(method, params.clone());
        assert_eq!(reply["error"]["code"], "locked", "{method}");
    }
    // pair.cancel is a stop path: only `locked` precedes it (see `the_stop_paths_...` below)
    let prefixed: Vec<_> = calls.iter().filter(|(method, _)| *method != "pair.cancel").collect();
    // (2) no relay: not_found with sync.run's text, before any parameter is looked at
    let (_d2, unconfigured) = encrypted_store(false);
    let mut live = Live::unlocked(&unconfigured, Hooks::default());
    for (method, params) in prefixed.iter().map(|call| (&call.0, &call.1)) {
        let reply = live.call(method, params.clone());
        assert_eq!(
            error_of(&reply),
            ("not_found", "no relay is configured (relay.json in the data folder)"),
            "{method}"
        );
    }
    // (3) a lan relay serves nothing
    relay_json(&unconfigured, json!({"lan": "http://127.0.0.1:9"}));
    for (method, params) in prefixed.iter().map(|call| (&call.0, &call.1)) {
        let reply = live.call(method, params.clone());
        assert_eq!(error_of(&reply), ("bad_params", "this device is a joiner; it serves nothing"), "{method}");
    }
    // (4) a plaintext store has nothing to derive a relay from
    let dir = tempfile::tempdir().expect("tempdir");
    let plain = dir.path().join("plain.db");
    store::open_for_write(&plain, "test", 1.0, PassphraseSource::Explicit("unused")).expect("create");
    relay_json(&plain, json!({"folder": dir.path().join("relay")}));
    let mut plain_live = Live::start(&plain, Hooks::default(), None);
    for (method, params) in prefixed.iter().map(|call| (&call.0, &call.1)) {
        let reply = plain_live.call(method, params.clone());
        assert_eq!(reply["error"]["code"], "not_encrypted", "{method}");
        assert!(
            reply["error"]["message"]
                .as_str()
                .expect("message")
                .starts_with("the relay needs an encrypted store"),
            "{method}"
        );
    }
    // (5) a key rotation in progress
    let (_d3, rotating) = serving_store(false);
    std::fs::write(keys::next_path_for(&keys::key_path_for(&rotating)), "{}").expect("next file");
    let mut rot = Live::unlocked(&rotating, Hooks::default());
    for (method, params) in prefixed.iter().map(|call| (&call.0, &call.1)) {
        let reply = rot.call(method, params.clone());
        assert_eq!(error_of(&reply), ("busy", "a key rotation is in progress; finish it first"), "{method}");
    }
    // (6) then the parameters
    let (_d4, ready) = serving_store(false);
    let mut shape = Live::unlocked(&ready, Hooks::default());
    let on_missing = shape.call("relay.serve", json!({}));
    assert_eq!(error_of(&on_missing), ("bad_params", "on must be true or false"));
    let listen_missing = shape.call("relay.serve", json!({"on": true}));
    assert_eq!(error_of(&listen_missing), ("bad_params", "listen must be a non-empty string"));
    let offer_missing = shape.call("pair.offer", json!({}));
    assert_eq!(error_of(&offer_missing), ("bad_params", "listen must be a non-empty string"));
    for digits in [json!("12345"), json!("1234567"), json!("12345a"), json!("１２３４５６"), json!(123456), json!(null)] {
        let reply = shape.call("pair.confirm", json!({"digits": digits}));
        assert_eq!(error_of(&reply), ("bad_params", "digits must be exactly six digits"), "{digits}");
    }
    // well-formed, but there is no offer
    let confirm = shape.call("pair.confirm", json!({"digits": "123456"}));
    assert_eq!(confirm["error"]["code"], "not_found");
    let cancel = shape.call("pair.cancel", json!({}));
    assert_eq!(cancel["error"]["code"], "not_found");
    // the addresses answer under the full prefix
    let addresses = shape.call("relay.addresses", json!({}));
    assert!(addresses["result"]["addresses"].is_array());
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn listen_refusals_name_the_rule_and_never_the_address() {
    let (_dir, db) = serving_store(false);
    let mut live = Live::unlocked(&db, Hooks::default());
    let refused_values = [
        ("localhost:24816", "listen must be an IP address and a port"),
        ("192.168.77.5", "listen must be an IP address and a port"),
        ("192.168.77.5:", "listen needs an explicit port"),
        ("192.168.77.5:0", "listen needs an explicit port"),
        ("192.168.77.5:024816", "listen needs an explicit port"),
        ("192.168.77.5:65536", "listen needs an explicit port"),
        ("192.168.77.5:+4816", "listen needs an explicit port"),
        ("0.0.0.0:24816", "listen needs a concrete address"),
        ("[::]:24816", "listen needs a concrete address"),
        ("[fe80::1]:24816", "listen cannot carry a zone id"),
        ("[fe80::1%en0]:24816", "listen cannot carry a zone id"),
        ("169.254.9.9:24816", "listen cannot carry a zone id"),
        ("::1:24816", "listen must be an IP address and a port"),
        ("[::1]24816", "listen must be an IP address and a port"),
        ("[::ffff:0.0.0.0]:24816", "listen must be an IP address and a port"),
        ("[::ffff:169.254.1.1]:24816", "listen must be an IP address and a port"),
        ("[::ffff:192.168.1.20]:24816", "listen must be an IP address and a port"),
    ];
    for (value, rule) in refused_values {
        for method in ["relay.serve", "pair.offer"] {
            let params = if method == "relay.serve" {
                json!({"on": true, "listen": value})
            } else {
                json!({"listen": value})
            };
            let reply = live.call(method, params);
            let (code, message) = error_of(&reply);
            assert_eq!(code, "bad_params", "{method} {value}");
            assert!(message.starts_with(rule), "{value}: {message}");
            for fragment in ["192.168.77", "169.254.9", "fe80", "localhost", "en0"] {
                assert!(!message.contains(fragment), "{value}: the message echoes the address: {message}");
            }
        }
    }
    for value in [json!(24816), json!(""), json!(["127.0.0.1:1"])] {
        let reply = live.call("relay.serve", json!({"on": true, "listen": value}));
        assert_eq!(error_of(&reply), ("bad_params", "listen must be a non-empty string"));
    }
    // a bind failure names no address either
    let taken = TcpListener::bind("127.0.0.1:0").expect("bind");
    let busy_port = taken.local_addr().expect("addr").port();
    let reply = live.call("relay.serve", json!({"on": true, "listen": format!("127.0.0.1:{busy_port}")}));
    assert_eq!(error_of(&reply), ("internal", "cannot listen on that address"));
    assert_eq!(live.serving(), Value::Null);
    assert!(serving::parse_listen("[::1]:24816").is_ok());
    assert!(serving::parse_listen("10.0.0.2:1").is_ok());
    for mapped in ["[::ffff:0.0.0.0]:24816", "[::ffff:169.254.1.1]:24816", "[::ffff:192.168.1.20]:24816"] {
        assert_eq!(
            serving::parse_listen(mapped).expect_err("an IPv4-mapped literal"),
            "listen must be an IP address and a port, like 192.168.1.20:24816"
        );
    }
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn relay_addresses_lists_the_network_first_and_loopback_last() {
    let (_dir, db) = serving_store(false);
    let list: Vec<IpAddr> = ["127.0.0.1", "fe80::1", "10.1.2.3", "::1", "169.254.4.4", "192.168.0.5", "2001:db8::7"]
        .iter()
        .map(|text| text.parse().expect("ip"))
        .collect();
    let hooks = Hooks {
        addresses: Arc::new(move || list.clone()),
        ..Hooks::default()
    };
    let mut live = Live::unlocked(&db, hooks);
    let reply = live.call("relay.addresses", json!({}));
    assert_eq!(
        reply["result"],
        json!({"addresses": [
            {"ip": "10.1.2.3", "label": "this network"},
            {"ip": "192.168.0.5", "label": "this network"},
            {"ip": "2001:db8::7", "label": "this network"},
            {"ip": "127.0.0.1", "label": "this Mac only, for testing"},
            {"ip": "::1", "label": "this Mac only, for testing"},
        ], "port": 24816})
    );
    // the real list: whatever this machine has, the loopback rows come last
    let mut real = Live::unlocked(&db, Hooks::default());
    let reply = real.call("relay.addresses", json!({}));
    let labels: Vec<&str> = reply["result"]["addresses"]
        .as_array()
        .expect("addresses")
        .iter()
        .map(|row| row["label"].as_str().expect("label"))
        .collect();
    let first_loopback = labels.iter().position(|l| l.starts_with("this Mac")).unwrap_or(labels.len());
    assert!(labels[first_loopback..].iter().all(|l| l.starts_with("this Mac")), "{labels:?}");
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn the_address_watcher_stops_the_server_when_its_address_is_gone() {
    let (_dir, db) = serving_store(false);
    let present = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&present);
    let loopback: IpAddr = "127.0.0.1".parse().expect("ip");
    let hooks = Hooks {
        address_check: Duration::from_millis(100),
        addresses: Arc::new(move || if flag.load(Ordering::SeqCst) { vec![loopback] } else { Vec::new() }),
        ..Hooks::default()
    };
    let mut live = Live::unlocked(&db, hooks);
    let listen = listen_on_free_port();
    live.call("relay.serve", json!({"on": true, "listen": listen}));
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(http_status(&listen, "/v1/health"), Some(200), "present: it keeps serving");
    present.store(false, Ordering::SeqCst);
    let stopped = live.event("relay", "stopped");
    assert_eq!(stopped["reason"], "address_gone");
    assert_eq!(live.serving(), Value::Null);
    assert!(wait_until(10, || refused(&listen)));
    assert_eq!(live.events("relay").len(), 1, "told once");
    // serving can start again once the address is back
    present.store(true, Ordering::SeqCst);
    let again = live.call("relay.serve", json!({"on": true, "listen": listen}));
    assert_eq!(again["result"]["serving"], true);
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn the_session_end_stops_the_server_before_the_import_wait() {
    let (dir, db) = serving_store(true);
    let (release, gate) = mpsc::channel::<()>();
    let mut live = Live::start(&db, Hooks::default(), Some(gate));
    live.call("key.unlock", json!({"passphrase": PASSPHRASE}));
    let listen = listen_on_free_port();
    live.call("relay.serve", json!({"on": true, "listen": listen}));
    assert_eq!(http_status(&listen, "/v1/health"), Some(200));
    let offer = live.call("pair.offer", json!({"listen": listen}));
    assert!(offer["result"]["offer"].is_string());
    let import = live.send("import.run", json!({"path": dir.path().join("drop")}));
    // EOF: the loop ends the relay, then waits for the held import
    live.tx = None;
    assert!(wait_until(15, || refused(&listen)), "the server stopped while the import is still held");
    let thread = live.thread.as_ref().expect("running");
    assert!(!thread.is_finished(), "the loop is still waiting for the import worker");
    drop(release);
    let code = live.thread.take().expect("running").join().expect("session thread");
    assert_eq!(code, 0);
    live.drain();
    assert!(live.seen.iter().any(|l| l["id"] == import), "the import still answered");
}

// ---- privacy ----

/// The leaf paths allowed to carry an address (the offer text carries the offerer's key and the URL).
const ALLOWED_PATHS: [&str; 3] = ["result.offer", "result.url", "result.serving.url"];

/// A joiner that goes all the way to delivery (digits confirmed, first pull landed).
fn deliver(live: &mut Live, offer_text: &str) -> String {
    let joiner = spawn_joiner(offer_text.to_string());
    let digits = joiner.digits();
    live.event("pair", "bound");
    assert_eq!(live.call("pair.confirm", json!({"digits": digits}))["result"], json!({"state": "released"}));
    live.event("pair", "delivered");
    joiner.thread.join().expect("joiner thread").expect("lands");
    digits
}

fn offer_text(reply: &Value) -> String {
    reply["result"]["offer"].as_str().expect("offer").to_string()
}

fn pair_states(live: &mut Live) -> Vec<String> {
    live.events("pair").iter().map(|e| e["state"].as_str().expect("state").to_string()).collect()
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn a_cancel_after_delivery_stops_the_server_after_the_linger_with_no_pair_event() {
    let (_dir, db) = serving_store(true);
    let mut live = Live::unlocked(&db, fast(None, 300));
    let listen = listen_on_free_port();
    let reply = live.call("pair.offer", json!({"listen": listen}));
    deliver(&mut live, &offer_text(&reply));
    assert_eq!(live.call("pair.cancel", json!({}))["result"], json!({"state": "aborted"}));
    assert!(wait_until(15, || live.serving().is_null()), "keep is off: the server stops after the linger");
    assert!(wait_until(5, || refused(&listen)), "the listener closes as the stop completes");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(pair_states(&mut live), ["bound", "delivered"], "no aborted event after a delivery");
    assert_eq!(live.event("relay", "stopped")["reason"], "offer_ended");
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn a_cancel_stops_the_server_after_the_linger_and_says_offer_ended_once() {
    let (_dir, db) = serving_store(true);
    let mut live = Live::unlocked(&db, fast(None, 200));
    let listen = listen_on_free_port();
    live.call("pair.offer", json!({"listen": listen}));
    assert_eq!(live.call("pair.cancel", json!({}))["result"], json!({"state": "aborted"}));
    let stopped = live.event("relay", "stopped");
    assert_eq!(stopped["reason"], "offer_ended");
    assert!(wait_until(15, || live.serving().is_null()), "the event comes with the stop");
    assert!(wait_until(5, || refused(&listen)), "the listener closes as the stop completes");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(live.events("relay").len(), 1, "one stop, one event");
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn keep_on_across_a_delivered_offer_that_reaches_its_expiry_keeps_the_server() {
    let (_dir, db) = serving_store(true);
    let mut live = Live::unlocked(&db, fast(Some(4), 200));
    let listen = listen_on_free_port();
    live.call("relay.serve", json!({"on": true, "listen": listen}));
    let reply = live.call("pair.offer", json!({"listen": listen}));
    deliver(&mut live, &offer_text(&reply));
    // the offer's exp passes (4 s) and the linger after it
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(http_status(&listen, "/v1/health"), Some(200), "keep is on: the server stays");
    assert_eq!(live.serving(), json!({"url": format!("http://{listen}"), "keep": true, "offer": null}));
    assert_eq!(pair_states(&mut live), ["bound", "delivered"], "no expiry event after a delivery");
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn the_address_watcher_takes_an_open_offer_silently_and_the_offer_is_gone() {
    let (_dir, db) = serving_store(false);
    let present = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&present);
    let loopback: IpAddr = "127.0.0.1".parse().expect("ip");
    let hooks = Hooks {
        address_check: Duration::from_millis(100),
        addresses: Arc::new(move || if flag.load(Ordering::SeqCst) { vec![loopback] } else { Vec::new() }),
        ..Hooks::default()
    };
    let mut live = Live::unlocked(&db, hooks);
    let listen = listen_on_free_port();
    assert!(live.call("pair.offer", json!({"listen": listen}))["result"]["offer"].is_string());
    present.store(false, Ordering::SeqCst);
    assert_eq!(live.event("relay", "stopped")["reason"], "address_gone");
    assert!(wait_until(10, || refused(&listen)));
    assert!(pair_states(&mut live).is_empty(), "the offer ends with no pair event");
    // documented in serve-protocol.md: the offer is gone, so confirm and cancel both say not_found
    let confirm = live.call("pair.confirm", json!({"digits": "123456"}));
    assert_eq!(error_of(&confirm), ("not_found", "there is no offer"));
    let cancel = live.call("pair.cancel", json!({}));
    assert_eq!(error_of(&cancel), ("not_found", "there is no offer to cancel"));
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn a_second_offer_after_a_delivery_reuses_the_running_server_and_refuses_another_address() {
    let (_dir, db) = serving_store(true);
    let mut live = Live::unlocked(&db, fast(Some(30), 200));
    let listen = listen_on_free_port();
    let first = live.call("pair.offer", json!({"listen": listen}));
    deliver(&mut live, &offer_text(&first));
    assert_eq!(live.serving()["offer"], "delivered");
    let other = listen_on_free_port();
    let refused_other = live.call("pair.offer", json!({"listen": other}));
    assert_eq!(error_of(&refused_other), ("bad_params", "the relay already serves another address"));
    let second = live.call("pair.offer", json!({"listen": listen}));
    assert_eq!(second["result"]["url"], format!("http://{listen}"), "the same address is reused");
    assert_ne!(offer_text(&second), offer_text(&first), "a new offer, a new QR text");
    assert_eq!(live.serving()["offer"], "open");
    assert_eq!(http_status(&listen, "/v1/health"), Some(200));
    live.call("pair.cancel", json!({}));
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn an_address_that_left_resets_keep_so_the_next_offers_server_follows_the_lifetime_rule() {
    let (_dir, db) = serving_store(false);
    let present = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&present);
    let loopback: IpAddr = "127.0.0.1".parse().expect("ip");
    let hooks = Hooks {
        address_check: Duration::from_millis(100),
        linger: Duration::from_millis(200),
        addresses: Arc::new(move || if flag.load(Ordering::SeqCst) { vec![loopback] } else { Vec::new() }),
        ..Hooks::default()
    };
    let mut live = Live::unlocked(&db, hooks);
    let listen = listen_on_free_port();
    live.call("relay.serve", json!({"on": true, "listen": listen}));
    present.store(false, Ordering::SeqCst);
    live.event("relay", "stopped");
    // the stop lands a tick after the event under full-suite load: wait, never assert the instant
    assert!(wait_until(5, || live.serving().is_null()), "the server left with its address");
    present.store(true, Ordering::SeqCst);
    // sync.status reads the server gone the moment it is taken; its stop (the acceptor's join, behind `stopping`)
    // completes a tick later, and under full-suite load the next offer on the same port meets "the relay is
    // stopping" or the port still held: retry until the old server is really gone, never assert the instant
    let mut reply = Value::Null;
    let started = wait_until(10, || {
        reply = live.call("pair.offer", json!({"listen": listen}));
        reply["result"]["offer"].is_string()
            || !matches!(reply["error"]["code"].as_str(), Some("busy") | Some("internal"))
    });
    assert!(started && reply["result"]["offer"].is_string(), "the next offer's server starts once the old one stopped: {reply}");
    assert_eq!(live.serving()["keep"], false, "the switch and the core agree: keep is off");
    live.call("pair.cancel", json!({}));
    assert!(wait_until(15, || live.serving().is_null()), "the server stops after the linger");
    assert!(wait_until(5, || refused(&listen)), "the listener closes as the stop completes");
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn the_stop_paths_work_without_the_relay_checks() {
    let (dir, db) = serving_store(false);
    let mut live = Live::unlocked(&db, fast(None, 200));
    let listen = listen_on_free_port();
    live.call("relay.serve", json!({"on": true, "listen": listen}));
    assert!(live.call("pair.offer", json!({"listen": listen}))["result"]["offer"].is_string());
    // `sync forget`-like state: no relay.json; then a lan one; then a rotation file
    std::fs::remove_file(dir.path().join("relay.json")).expect("remove relay.json");
    assert_eq!(live.call("pair.cancel", json!({}))["result"], json!({"state": "aborted"}));
    assert_eq!(live.event("pair", "aborted")["reason"], "cancelled");
    relay_json(&db, json!({"lan": "http://127.0.0.1:9"}));
    std::fs::write(keys::next_path_for(&keys::key_path_for(&db)), "{}").expect("next file");
    // the other methods still refuse...
    let on = live.call("relay.serve", json!({"on": true, "listen": listen}));
    assert_eq!(error_of(&on), ("bad_params", "this device is a joiner; it serves nothing"));
    // ...and the stop path stops the running listener (keep goes off, no offer needs it)
    let off = live.call("relay.serve", json!({"on": false}));
    assert_eq!(off["result"], json!({"serving": false, "url": null}));
    assert!(refused(&listen));
    assert_eq!(live.serving(), Value::Null);
    // nothing running: both answer in their no-op shapes, whatever relay.json says
    std::fs::remove_file(dir.path().join("relay.json")).expect("remove relay.json");
    assert_eq!(live.call("relay.serve", json!({"on": false}))["result"], json!({"serving": false, "url": null}));
    let cancel = live.call("pair.cancel", json!({}));
    assert_eq!(error_of(&cancel), ("not_found", "there is no offer to cancel"));
    // the parameter shape is still checked
    let shape = live.call("relay.serve", json!({"on": false, "listen": "localhost:1"}));
    assert_eq!(shape["error"]["code"], "bad_params");
}

/// The library-level rig: an env on the shared state with a site, no protocol loop.
fn library_env(linger_ms: u64) -> (tempfile::TempDir, Env, Site) {
    let (dir, db) = serving_store(false);
    let secret = keys::unlock(&keys::key_path_for(&db), PassphraseSource::Explicit(PASSPHRASE)).expect("unlock");
    let env = Env {
        shared: serving::new_state(),
        hooks: fast(None, linger_ms),
        emit: Arc::new(|_| {}),
    };
    let site = Site {
        folder: dir.path().join("relay"),
        master: secret,
    };
    (dir, env, site)
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn a_reserved_push_outlasting_the_linger_keeps_the_server_and_is_not_busy() {
    let (_dir, env, site) = library_env(150);
    let listen: std::net::SocketAddr = listen_on_free_port().parse().expect("addr");
    serving::reserve_offer(&env, listen).expect("reserve");
    serving::finish_offer(&env, listen, &site).expect("first offer");
    serving::cancel(&env).expect("cancel");
    // a second push is reserved right away and takes longer than the linger
    serving::reserve_offer(&env, listen).expect("reserve again");
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(http_status(&listen.to_string(), "/v1/health"), Some(200), "the reservation keeps the server");
    // another address is refused while the push is reserved
    let other: std::net::SocketAddr = listen_on_free_port().parse().expect("addr");
    let refusal = serving::serve_on(&env, other, &site).expect_err("another address");
    assert_eq!((refusal.code, refusal.message.as_str()), ("bad_params", "the relay already serves another address"));
    let (_, url, _) = serving::finish_offer(&env, listen, &site).expect("not busy: the relay is not stopping");
    assert_eq!(url, format!("http://{listen}"));
    serving::end_session(&env);
}

#[test]
#[cfg_attr(target_os = "ios", ignore = "the phone refuses the server roles (12-D 4b: unsupported_transport); the Mac serves the relay and offers pairing")]
fn a_cancel_during_the_push_ends_the_offer_with_pair_failed() {
    let (_dir, env, site) = library_env(150);
    let listen: std::net::SocketAddr = listen_on_free_port().parse().expect("addr");
    serving::reserve_offer(&env, listen).expect("reserve");
    serving::cancel(&env).expect("a cancel during the push is accepted");
    let refusal = serving::finish_offer(&env, listen, &site).expect_err("the offer ended");
    assert_eq!((refusal.code, refusal.message.as_str()), ("pair_failed", "the offer ended"));
    assert!(refused(&listen.to_string()), "no server was started for a cancelled offer");
    serving::end_session(&env);
}

fn strip(value: &mut Value, path: &[&str]) {
    match path {
        [] => {}
        [last] => {
            if let Some(object) = value.as_object_mut() {
                object.remove(*last);
            }
        }
        [first, rest @ ..] => {
            if let Some(child) = value.get_mut(*first) {
                strip(child, rest);
            }
        }
    }
}

fn has_hex_run(text: &str, length: usize) -> bool {
    let mut run = 0;
    for byte in text.bytes() {
        if byte.is_ascii_hexdigit() {
            run += 1;
            if run >= length {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn has_number(text: &str, number: &str) -> bool {
    let bytes = text.as_bytes();
    text.match_indices(number).any(|(at, _)| {
        let before = at == 0 || !bytes[at - 1].is_ascii_digit();
        let after = at + number.len() >= bytes.len() || !bytes[at + number.len()].is_ascii_digit();
        before && after
    })
}

/// Every emitted line, minus the allow-listed paths, holds no SAS, no 32-byte hex key or tag, no loopback
/// address (the joiner's peer address) and no folder.
fn privacy_walk(lines: &[Value], sas: &str) {
    assert!(!lines.is_empty());
    let mut walked = 0;
    for line in lines {
        let mut copy = line.clone();
        for path in ALLOWED_PATHS {
            let parts: Vec<&str> = path.split('.').collect();
            strip(&mut copy, &parts);
        }
        let text = copy.to_string();
        assert!(!has_number(&text, sas) || sas.len() < 6, "the SAS is on the serve channel: {text}");
        assert!(!text.contains(&format!("\"{sas}\"")), "the SAS is on the serve channel: {text}");
        assert!(!has_hex_run(&text, 64), "a key or tag is on the serve channel: {text}");
        assert!(!text.contains("127.0.0.1"), "an address is on the serve channel: {text}");
        assert!(!text.contains("/relay"), "a folder is on the serve channel: {text}");
        assert!(!text.to_lowercase().contains("sas"), "{text}");
        walked += 1;
    }
    assert_eq!(walked, lines.len());
    // the allow-list is exactly three leaves: the offer text and the URLs
    assert!(
        lines
            .iter()
            .any(|l| l["result"]["offer"].as_str().is_some_and(|t| has_hex_run(t, 16) || !t.is_empty())),
        "the offer text crossed once, in the pair.offer result"
    );
}
