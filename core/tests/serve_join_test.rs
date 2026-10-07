// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 12-F row 3: `pair.join` and `pair.land` (the phone as the pairing joiner).
//!
//! The prefix refusals run on every platform (they come before the phone gate). Everything that runs the
//! worker is iOS-only, as the worker is: those tests run in the 18.1 simulator, the joiner (a serve session
//! on a phone store path) against the library offerer (`relay::serving`, the same code the Mac's
//! `pair.offer` drives) in one process. Synthetic stores and a scratch passphrase only.

#![cfg_attr(not(target_os = "ios"), allow(dead_code, unused_imports))]

mod common;

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::{PASSPHRASE, encrypted_copy, fixtures};
use disconect_core::keys::{self, PassphraseSource};
use disconect_core::pair::{self, Offer};
use disconect_core::relay::folder::FolderRelay;
use disconect_core::relay::serving::{self, Env, Hooks, Site};
use disconect_core::relay::sync as relay_sync;
use disconect_core::serve::{self, Channel, JoinHooks, Session};
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
    joiners: Box<dyn Fn() -> usize + Send>,
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
        std::thread::sleep(Duration::from_millis(10));
    }
}

impl Live {
    fn start(db: &Path, hooks: JoinHooks) -> Live {
        let out = Buffer::default();
        let mut session = Session::new(db.to_path_buf(), Channel::new(Box::new(out.clone())));
        session.set_join_hooks(hooks);
        let joiners: Box<dyn Fn() -> usize + Send> = Box::new(session.joiner_counter());
        let (tx, rx) = mpsc::channel();
        let input = ChannelInput { rx, pending: VecDeque::new() };
        let thread = std::thread::spawn(move || serve::serve_lines(&mut session, input));
        Live { out, tx: Some(tx), thread: Some(thread), seen: Vec::new(), parsed_bytes: 0, next_id: 1, joiners }
    }

    fn drain(&mut self) {
        let bytes = self.out.0.lock().expect("buffer").clone();
        let text = String::from_utf8(bytes[self.parsed_bytes..].to_vec()).expect("ascii output");
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

    fn response_within(&mut self, id: i64, seconds: u64) -> Option<Value> {
        let mut found = None;
        wait_until(seconds, || {
            self.drain();
            found = self.seen.iter().find(|l| l["id"] == id).cloned();
            found.is_some()
        });
        found
    }

    fn response(&mut self, id: i64) -> Value {
        self.response_within(id, 40).unwrap_or_else(|| panic!("no response to request {id}"))
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.send(method, params);
        self.response(id)
    }

    /// Wait for the first event named `event` whose `phase` is `phase`.
    fn phase(&mut self, phase: &str) -> Value {
        let mut found = None;
        let ok = wait_until(40, || {
            self.drain();
            found = self.seen.iter().find(|l| l["event"] == "pair" && l["phase"] == phase).cloned();
            found.is_some()
        });
        assert!(ok, "no pair event in phase {phase}; saw {:?}", self.seen);
        found.expect("event")
    }

    fn lines(&mut self) -> Vec<Value> {
        self.drain();
        self.seen.clone()
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

fn error_of(reply: &Value) -> (&str, &str) {
    (
        reply["error"]["code"].as_str().unwrap_or_else(|| panic!("an error code in {reply}")),
        reply["error"]["message"].as_str().unwrap_or_else(|| panic!("an error message in {reply}")),
    )
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs()
}

// ---- fixtures ----

const CLOCK_EXPIRED: &str = "This offer expired by this phone's clock. Check the date and time.";
const CLOCK_AHEAD: &str = "This offer is too far ahead of this phone's clock. Check the date and time.";
const ALREADY_PAIRED: &str = "This phone is already paired";
const BAD_ADDRESS: &str = "the offer's address cannot be a pairing address";
const FORGET_PENDING: &str = "This phone has not finished forgetting its last pairing. Close and reopen the app, then try again.";
#[cfg(target_os = "ios")]
const NOT_ON_LINK: &str = "This offer's address is not on this phone's network. Join the same Wi-Fi as your Mac and start a new offer on it.";
#[cfg(target_os = "ios")]
const BUSY_PAIRING: &str = "a pairing is still running or stopping; try again in a moment";

/// A syntactically valid offer for `url` (a real X25519 public key; the secrets are random, so it is not
/// joinable) with the given expiry.
fn forged_offer(url: &str, exp: u64) -> String {
    let (_secret, public) = pair::ephemeral().expect("key");
    Offer { pub_key: public, c: [7u8; 32], s: [9u8; 16], id: [5u8; 16], exp, url: url.to_string() }.encode()
}

/// A phone: an empty scratch folder and the store path inside it (nothing exists there yet).
fn phone() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("phone").join("phone.hbdb");
    (dir, db)
}

fn phone_files(db: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(db.parent().expect("folder"))
        .map(|rd| rd.map(|e| e.expect("entry").file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    names.sort();
    names
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr").port()
}

/// A listener that must never see a connection (every refusal before the network).
struct Tripwire {
    listener: TcpListener,
}

impl Tripwire {
    fn new() -> Tripwire {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        Tripwire { listener }
    }
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.listener.local_addr().expect("addr").port())
    }
    fn tripped(&self) -> bool {
        self.listener.accept().is_ok()
    }
}

// ---- the prefix: refusals before any network call, on every platform ----

#[test]
fn the_prefix_refuses_before_any_network_call_in_order() {
    let (_dir, db) = phone();
    let wire = Tripwire::new();
    let mut live = Live::start(&db, JoinHooks::default());
    let url = wire.url();
    let fresh = now() + 600;
    let mut refuse = |label: &str, params: Value, want: (&str, &str)| {
        let reply = live.call("pair.join", params);
        assert_eq!(error_of(&reply), want, "{label}");
    };
    // the shape
    refuse("missing", json!({}), ("bad_params", "offer must be a non-empty string"));
    refuse("a number", json!({"offer": 12}), ("bad_params", "offer must be a non-empty string"));
    refuse("empty", json!({"offer": ""}), ("bad_params", "offer must be a non-empty string"));
    refuse("garbage", json!({"offer": "hello"}), ("bad_params", "that is not a pairing offer"));
    refuse("v1 prefix", json!({"offer": "disconect-pair:v1.abc"}), ("bad_params", "that is not a pairing offer"));
    let long = format!("disconect-pair:v2.{}", "A".repeat(2000));
    refuse("over the bound", json!({"offer": long}), ("bad_params", "that is not a pairing offer"));
    // an IP literal
    let host = "the offer's address must be an IP address, not a name";
    refuse("a hostname", json!({"offer": forged_offer("http://mac.local:24816", fresh)}), ("bad_params", host));
    refuse("a dotted name", json!({"offer": forged_offer("http://relay.example.com:80", fresh)}), ("bad_params", host));
    // the hostname is checked before the expiry
    refuse("hostname and expired", json!({"offer": forged_offer("http://mac.local:1", 1000)}), ("bad_params", host));
    // an address that is never a pairing address comes right after the IP literal, before the clock
    refuse("0.0.0.0 and expired", json!({"offer": forged_offer("http://0.0.0.0:24816", 1000)}), ("bad_params", BAD_ADDRESS));
    // exp: at most 900 + 300 s ahead
    refuse("exp too far", json!({"offer": forged_offer(&url, now() + 1500)}), ("pair_failed", CLOCK_AHEAD));
    // expired by this phone's clock: no tolerance past exp (the joiner itself refuses now > exp)
    refuse("expired", json!({"offer": forged_offer(&url, now() - 400)}), ("pair_failed", CLOCK_EXPIRED));
    refuse("expired by 100 s", json!({"offer": forged_offer(&url, now() - 100)}), ("pair_failed", CLOCK_EXPIRED));
    refuse("expired by 5 s", json!({"offer": forged_offer(&url, now() - 5)}), ("pair_failed", CLOCK_EXPIRED));
    refuse("long expired", json!({"offer": forged_offer(&url, 1000)}), ("pair_failed", CLOCK_EXPIRED));
    assert!(!wire.tripped(), "a refusal made a network call");
    assert!(phone_files(&db).is_empty(), "a refusal wrote something");
    assert_eq!((live.joiners)(), 0);
    // pair.land: the shape first
    let shape = live.call("pair.land", json!({}));
    assert_eq!(error_of(&shape), ("bad_params", "confirm must be true or false"));
    let shape = live.call("pair.land", json!({"confirm": "yes"}));
    assert_eq!(error_of(&shape), ("bad_params", "confirm must be true or false"));
    // nothing in a refusal carries the offer text or the address
    for line in live.lines() {
        let text = line.to_string();
        assert!(!text.contains("127.0.0.1") && !text.contains("disconect-pair"), "{text}");
    }
}

#[test]
fn an_already_paired_phone_is_refused_before_any_network_call() {
    let (dir, db) = phone();
    let wire = Tripwire::new();
    let url = wire.url();
    let fresh = now() + 600;
    for (label, make) in [
        ("a store", Box::new(|db: &Path| std::fs::write(db, b"x").expect("store")) as Box<dyn Fn(&Path)>),
        ("a key file", Box::new(|db: &Path| std::fs::write(keys::key_path_for(db), b"{}").expect("key"))),
        ("a rotation file", Box::new(|db: &Path| {
            std::fs::write(keys::next_path_for(&keys::key_path_for(db)), b"{}").expect("next")
        })),
        ("a relay file that is not a LAN relay", Box::new(|db: &Path| {
            std::fs::write(db.parent().expect("folder").join("relay.json"), r#"{"folder": "/elsewhere"}"#).expect("relay")
        })),
    ] {
        std::fs::create_dir_all(db.parent().expect("folder")).expect("mkdir");
        make(&db);
        let mut live = Live::start(&db, JoinHooks::default());
        let reply = live.call("pair.join", json!({"offer": forged_offer(&url, fresh)}));
        assert_eq!(error_of(&reply), ("pair_failed", ALREADY_PAIRED), "{label}");
        // an expired offer is refused as expired first (the order of the prefix)
        let reply = live.call("pair.join", json!({"offer": forged_offer(&url, 1000)}));
        assert_eq!(error_of(&reply), ("pair_failed", CLOCK_EXPIRED), "{label}");
        drop(live);
        std::fs::remove_dir_all(db.parent().expect("folder")).expect("clean");
    }
    assert!(!wire.tripped());
    drop(dir);
}

/// A LAN relay file beside no store and no key file is what a landing that failed before its commit point
/// leaves (12-H (d)): not a pairing, so the prefix passes it (off a phone the next refusal is the transport
/// one; on a phone the join would start) and nothing is written by the check.
#[test]
#[cfg(not(target_os = "ios"))]
fn a_relay_file_left_by_a_failed_landing_is_not_a_pairing() {
    let (_dir, db) = phone();
    let wire = Tripwire::new();
    std::fs::create_dir_all(db.parent().expect("folder")).expect("mkdir");
    let relay_file = db.parent().expect("folder").join("relay.json");
    std::fs::write(&relay_file, r#"{"lan": "http://10.9.9.9:1"}"#).expect("leftover");
    let mut live = Live::start(&db, JoinHooks::default());
    let reply = live.call("pair.join", json!({"offer": forged_offer(&wire.url(), now() + 600)}));
    assert_eq!(error_of(&reply).0, "unsupported_transport", "past the prefix: {reply}");
    assert!(!wire.tripped());
    assert_eq!(phone_files(&db), vec!["relay.json".to_string()], "the check writes nothing and removes nothing");
}

/// Off a phone, an offer that passes the whole prefix is refused as `unsupported_transport`; so is a
/// `pair.land` with a good shape. (On a phone the same calls start a worker; see the iOS tests.)
#[test]
#[cfg(not(target_os = "ios"))]
fn a_core_that_is_not_a_phone_refuses_after_the_prefix() {
    let (_dir, db) = phone();
    let wire = Tripwire::new();
    let mut live = Live::start(&db, JoinHooks::default());
    let reply = live.call("pair.join", json!({"offer": forged_offer(&wire.url(), now() + 600)}));
    assert_eq!(
        error_of(&reply),
        ("unsupported_transport", "this core is not a phone; it does not join a pairing")
    );
    let reply = live.call("pair.land", json!({"confirm": true}));
    assert_eq!(error_of(&reply).0, "unsupported_transport");
    assert!(!wire.tripped());
    assert!(phone_files(&db).is_empty());
}

// ---- the library offerer ----

/// The Mac's side, as the library runs it for `pair.offer`: a store with two records pushed to a folder
/// relay, the server and one open offer.
struct Mac {
    _dir: tempfile::TempDir,
    db: PathBuf,
    env: Env,
    master: keys::Secret32,
    offer: String,
}

fn mac(ttl: Option<u64>) -> Mac {
    let (dir, db) = encrypted_copy();
    let drop_dir = dir.path().join("drop");
    std::fs::create_dir_all(&drop_dir).expect("mkdir");
    for stem in ["monitoring_timestamp16", "monitoring_cycles_resolution"] {
        std::fs::copy(
            fixtures().join("synthetic").join(format!("{stem}.fit.bin")),
            drop_dir.join(format!("{stem}.fit")),
        )
        .expect("copy");
    }
    let master = keys::unlock(&keys::key_path_for(&db), PassphraseSource::Explicit(PASSPHRASE)).expect("unlock");
    let folder = dir.path().join("relay");
    {
        let opened = store::open_for_write_with(&db, "test", 5.0, Some(&master)).expect("open");
        import_path(opened.conn(), &drop_dir, None, None).expect("import");
        relay_sync::push(opened.conn(), master.as_slice(), &FolderRelay::new(folder.clone())).expect("push");
    }
    let env = Env {
        shared: serving::new_state(),
        hooks: Hooks { linger: Duration::from_millis(300), offer_ttl: ttl, ..Hooks::default() },
        emit: Arc::new(|_| {}),
    };
    let listen: std::net::SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    serving::reserve_offer(&env, listen).expect("reserve");
    let site = Site { folder, master: master.clone() };
    let (offer, _url, _) = serving::finish_offer(&env, listen, &site).expect("offer");
    Mac { _dir: dir, db, env, master, offer }
}

impl Mac {
    /// The Mac's owner types the six digits.
    fn confirm(&self, digits: &str) -> Result<(), String> {
        let key_file = std::fs::read(keys::key_path_for(&self.db)).expect("key file");
        serving::confirm(&self.env, digits, &self.master, &key_file).map_err(|r| r.message)
    }
}

impl Drop for Mac {
    fn drop(&mut self) {
        serving::end_session(&self.env);
    }
}

fn code_of(live: &mut Live) -> String {
    let event = live.phase("code");
    event["code"].as_str().expect("six digits").to_string()
}

fn fast_join() -> JoinHooks {
    JoinHooks { reach_backoff: Duration::from_millis(20), ..JoinHooks::default() }
}

/// The events and the answer of a complete, successful join, with the phone's folder checked.
#[cfg(target_os = "ios")]
fn join_and_land(live: &mut Live, mac: &Mac) -> (String, Value) {
    let id = live.send("pair.join", json!({"offer": mac.offer}));
    let digits = code_of(live);
    mac.confirm(&digits).expect("the Mac releases");
    live.phase("released");
    let decided = live.call("pair.land", json!({"confirm": true}));
    assert_eq!(decided["result"], json!({"state": "landing"}));
    let done = live.response(id);
    (digits, done)
}

// ---- the worker, on the phone ----

#[test]
#[cfg(target_os = "ios")]
fn a_join_against_the_library_offerer_lands_and_hands_the_master_back() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let mut live = Live::start(&pdb, fast_join());
    let (digits, done) = join_and_land(&mut live, &mac);
    assert_eq!(digits.len(), 6);
    assert_eq!(done["result"]["state"], "landed", "{done}");
    assert_eq!(done["result"]["pull"]["records_new"], 2);
    // N8: the key file's protection class: unknown (null) in the simulator, a bool on a device
    assert!(done["result"].as_object().expect("object").contains_key("key_file_protected"), "{done}");
    assert!(done["result"]["key_file_protected"].is_null(), "the simulator reports no classes: {done}");
    // the four landing steps came as progress, in order, before the final answer
    let lines = live.lines();
    let phases: Vec<&str> = lines
        .iter()
        .filter(|l| l["event"] == "progress" && l["op"] == "pair")
        .map(|l| l["phase"].as_str().expect("phase"))
        .collect();
    assert_eq!(phases, ["relay_file", "key_file", "store", "pull"]);
    // the event order: code, released, progress, the answer
    let at = |pred: &dyn Fn(&Value) -> bool| lines.iter().position(pred).expect("line");
    let code = at(&|l| l["phase"] == "code");
    let released = at(&|l| l["phase"] == "released");
    let first_step = at(&|l| l["phase"] == "relay_file");
    let answer = at(&|l| l["id"] == 1);
    assert!(code < released && released < first_step && first_step < answer);
    // the files
    let files = phone_files(&pdb);
    for name in ["phone.hbdb", "phone.hbdb.keys.json", "relay.json"] {
        assert!(files.contains(&name.to_string()), "{name} missing in {files:?}");
    }
    assert!(files.iter().all(|n| !n.contains(".tmp")), "no temp file is left: {files:?}");
    assert!(pdb.exists() && keys::key_path_for(&pdb).exists());
    // the hand-back: the very next request finds the session unlocked, with no passphrase typed
    let status = live.call("key.status", json!({}));
    assert_eq!(status["result"]["unlocked"], true);
    let sync = live.call("sync.status", json!({}));
    assert!(sync.get("error").is_none(), "{sync}");
    assert_eq!(live.call("pair.cancel", json!({}))["error"]["code"], "not_found");
    assert_eq!((live.joiners)(), 0, "the joiner is dropped on success");
    phone_privacy_walk(&live.lines(), &digits);
}

#[test]
#[cfg(target_os = "ios")]
fn the_six_digits_cross_the_serve_channel_exactly_once() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let mut live = Live::start(&pdb, fast_join());
    let (digits, done) = join_and_land(&mut live, &mac);
    assert_eq!(done["result"]["state"], "landed");
    let lines = live.lines();
    let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
    let count = text.match_indices(&digits).filter(|(at, _)| {
        let bytes = text.as_bytes();
        let before = *at == 0 || !bytes[at - 1].is_ascii_digit();
        let after = at + 6 >= bytes.len() || !bytes[at + 6].is_ascii_digit();
        before && after
    }).count();
    assert_eq!(count, 1, "the code is on the serve channel {count} times");
    let carriers: Vec<&Value> = lines.iter().filter(|l| l["event"] == "pair" && l["phase"] == "code").collect();
    assert_eq!(carriers.len(), 1);
    assert_eq!(carriers[0].as_object().expect("object").len(), 3, "event, phase, code and nothing else");
}

/// Every phone line, minus the one allowed leaf (`event=pair`, `phase=code`, `code=<6 digits>`), holds no
/// code, no 32-byte hex, no loopback address, no folder, no word of the protocol's secrets.
#[cfg(target_os = "ios")]
fn phone_privacy_walk(lines: &[Value], digits: &str) {
    assert!(!lines.is_empty());
    let mut leaves = 0;
    for line in lines {
        let mut copy = line.clone();
        // `sync.status.result.relay_url` is serve-protocol's own allow-listed leaf, not the join's
        if let Some(result) = copy.get_mut("result").and_then(Value::as_object_mut) {
            result.remove("relay_url");
        }
        if copy["event"] == "pair" && copy["phase"] == "code" {
            let code = copy["code"].as_str().expect("code");
            assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()));
            copy.as_object_mut().expect("object").remove("code");
            leaves += 1;
        }
        let text = copy.to_string();
        assert!(!text.contains(digits), "the code is on the serve channel outside its one leaf: {text}");
        assert!(!has_hex_run(&text, 32), "a key, tag or secret is on the serve channel: {text}");
        for needle in ["127.0.0.1", "/relay", "disconect-pair", "phone.hbdb", "/var/", "/tmp"] {
            assert!(!text.contains(needle), "{needle} is on the serve channel: {text}");
        }
    }
    assert_eq!(leaves, 1, "exactly one line carries a code");
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

#[test]
#[cfg(target_os = "ios")]
fn a_second_join_is_busy_and_a_cancel_before_release_writes_nothing() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let mut live = Live::start(&pdb, fast_join());
    let id = live.send("pair.join", json!({"offer": mac.offer}));
    let digits = code_of(&mut live);
    // a second join (the same or another offer text) while one runs
    let other = Tripwire::new();
    let second = live.call("pair.join", json!({"offer": mac.offer}));
    assert_eq!(error_of(&second), ("busy", BUSY_PAIRING));
    let third = live.call("pair.join", json!({"offer": forged_offer(&other.url(), now() + 600)}));
    assert_eq!(error_of(&third), ("busy", BUSY_PAIRING));
    // N7: an import or a sync that finds the slot held by a join is told so
    let import = live.call("import.run", json!({"path": "/nonexistent"}));
    assert_eq!(error_of(&import), ("busy", BUSY_PAIRING));
    assert!(!other.tripped());
    // pair.land before the release is refused
    let early = live.call("pair.land", json!({"confirm": true}));
    assert_eq!(error_of(&early), ("busy", "the Mac has not released this pairing yet"));
    // cancel: the joiner's flag only
    let cancelled = live.call("pair.cancel", json!({}));
    assert_eq!(cancelled["result"], json!({"state": "aborted"}));
    let done = live.response(id);
    assert_eq!(error_of(&done), ("pair_failed", "Cancelled. Cancel on your Mac too."));
    assert!(phone_files(&pdb).is_empty(), "nothing is written by a cancelled join");
    assert_eq!((live.joiners)(), 0, "cancel drops the joiner");
    // the Mac's offer is untouched by the phone's cancel (it does not tell the Mac): the digits still verify there
    assert!(mac.confirm(&digits).is_ok(), "the phone's cancel does not end the Mac's offer");
    // and the slot is free again
    let again = live.call("pair.cancel", json!({}));
    assert_eq!(error_of(&again), ("not_found", "there is no offer to cancel"));
}

#[test]
#[cfg(target_os = "ios")]
fn a_cancel_after_release_is_refused_and_landing_continues() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let mut live = Live::start(&pdb, fast_join());
    let id = live.send("pair.join", json!({"offer": mac.offer}));
    let digits = code_of(&mut live);
    mac.confirm(&digits).expect("release");
    live.phase("released");
    let refused = live.call("pair.cancel", json!({}));
    assert_eq!(error_of(&refused).0, "busy");
    assert!(phone_files(&pdb).is_empty(), "the check has not been answered: nothing landed");
    let land = live.call("pair.land", json!({"confirm": true}));
    assert_eq!(land["result"], json!({"state": "landing"}));
    let again = live.call("pair.land", json!({"confirm": true}));
    assert!(again.get("error").is_some(), "a second answer is refused or finds nothing");
    assert_eq!(live.response(id)["result"]["state"], "landed");
}

#[test]
#[cfg(target_os = "ios")]
fn pair_land_false_lands_nothing() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let mut live = Live::start(&pdb, fast_join());
    let id = live.send("pair.join", json!({"offer": mac.offer}));
    let digits = code_of(&mut live);
    mac.confirm(&digits).expect("release");
    live.phase("released");
    let no = live.call("pair.land", json!({"confirm": false}));
    assert_eq!(no["result"], json!({"state": "declined"}));
    let done = live.response(id);
    assert_eq!(error_of(&done), ("pair_failed", "Not paired. Nothing was saved on this device. Your Mac may say Paired; it keeps no record of this device. Start a new offer on your Mac to pair."));
    assert!(phone_files(&pdb).is_empty(), "a no lands nothing");
    assert_eq!((live.joiners)(), 0);
    assert_eq!(live.call("pair.land", json!({"confirm": true}))["error"]["code"], "not_found");
    phone_privacy_walk(&live.lines(), &digits);
}

#[test]
#[cfg(target_os = "ios")]
fn the_land_wait_ends_as_a_no() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let hooks = JoinHooks { land_wait: Duration::from_millis(400), ..fast_join() };
    let mut live = Live::start(&pdb, hooks);
    let id = live.send("pair.join", json!({"offer": mac.offer}));
    let digits = code_of(&mut live);
    mac.confirm(&digits).expect("release");
    let done = live.response(id);
    assert_eq!(error_of(&done), ("pair_failed", "Not paired. Nothing was saved on this device. Your Mac may say Paired; it keeps no record of this device. Start a new offer on your Mac to pair."));
    assert!(phone_files(&pdb).is_empty());
    // N3: a `pair.land` after the wait ran out is refused, never answered "landing"
    let late = live.call("pair.land", json!({"confirm": true}));
    assert_eq!(late["error"]["code"], "not_found", "{late}");
    assert!(phone_files(&pdb).is_empty());
}

#[test]
#[cfg(target_os = "ios")]
fn the_end_of_the_session_ends_a_join_waiting_for_the_check() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let mut live = Live::start(&pdb, fast_join());
    let _id = live.send("pair.join", json!({"offer": mac.offer}));
    let digits = code_of(&mut live);
    mac.confirm(&digits).expect("release");
    live.phase("released");
    let started = Instant::now();
    drop(live); // EOF: the worker must not wait out its 600 s
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(phone_files(&pdb).is_empty());
}

/// A server that accepts, records the body of every POST and closes without answering.
struct Mute {
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    connects: Arc<Mutex<u32>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Mute {
    fn on(listener: TcpListener) -> Mute {
        listener.set_nonblocking(true).expect("nonblocking");
        let (bodies, connects, stop) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(0)), Arc::new(AtomicBool::new(false)));
        let (b, c, s) = (Arc::clone(&bodies), Arc::clone(&connects), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                let Ok((mut conn, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                *c.lock().expect("count") += 1;
                conn.set_nonblocking(false).expect("blocking");
                conn.set_read_timeout(Some(Duration::from_millis(500))).expect("timeout");
                let mut data = Vec::new();
                let mut chunk = [0u8; 1024];
                while let Ok(n) = conn.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    data.extend_from_slice(&chunk[..n]);
                    if data.windows(4).position(|w| w == b"\r\n\r\n").is_some_and(|end| data.len() >= end + 4 + 64) {
                        break;
                    }
                }
                if data.starts_with(b"POST ")
                    && let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n")
                {
                    b.lock().expect("bodies").push(data[end + 4..].to_vec());
                }
                // closed with no reply
            }
        });
        Mute { bodies, connects, stop, thread: Some(thread) }
    }
}

impl Drop for Mute {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
#[cfg(target_os = "ios")]
fn a_retry_with_the_same_text_re_posts_the_identical_body_and_another_text_does_not() {
    let (_pdir, pdb) = phone();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://127.0.0.1:{}", listener.local_addr().expect("addr").port());
    let mute = Mute::on(listener);
    let mut live = Live::start(&pdb, fast_join());
    let text = forged_offer(&url, now() + 600);
    let first = live.call("pair.join", json!({"offer": text}));
    let network = "This phone cannot reach your Mac. Check that you are on the same Wi-Fi and that DISCOnect is allowed under Settings, Privacy and Security, Local Network. Then try again.";
    assert_eq!(error_of(&first), ("pair_failed", network));
    assert_eq!((live.joiners)(), 1, "a network failure keeps the joiner for the retry");
    let second = live.call("pair.join", json!({"offer": text}));
    assert_eq!(error_of(&second), ("pair_failed", network));
    assert_eq!((live.joiners)(), 1, "the same text reuses its joiner");
    let other = live.call("pair.join", json!({"offer": forged_offer(&url, now() + 601)}));
    assert_eq!(error_of(&other).0, "pair_failed");
    assert_eq!((live.joiners)(), 2, "another text is another joiner");
    let bodies = mute.bodies.lock().expect("bodies").clone();
    assert!(bodies.len() >= 6, "three attempts per join, got {}", bodies.len());
    assert!(bodies.iter().all(|b| b.len() == 64));
    assert!(bodies[..6].iter().take(3).all(|b| *b == bodies[0]), "attempts inside one join are identical");
    assert_eq!(bodies[3], bodies[0], "the retry re-posted the identical body");
    assert_eq!(bodies[4], bodies[0]);
    assert_ne!(bodies[6], bodies[0], "another offer text draws another key");
    assert!(phone_files(&pdb).is_empty());
    // the messages never carry the address or the text
    for line in live.lines() {
        let t = line.to_string();
        assert!(!t.contains("127.0.0.1") && !t.contains("disconect-pair"), "{t}");
    }
}

#[test]
#[cfg(target_os = "ios")]
fn the_reachability_wait_retries_until_the_address_answers_and_is_bounded_by_exp() {
    let (_pdir, pdb) = phone();
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}");
    let mut live = Live::start(&pdb, fast_join());
    let id = live.send("pair.join", json!({"offer": forged_offer(&url, now() + 600)}));
    // nothing listens: no answer, no event, no failure after 800 ms (a failure count would have ended it)
    std::thread::sleep(Duration::from_millis(800));
    assert!(live.response_within(id, 0).is_none(), "the wait ended while the address was unreachable");
    assert!(live.lines().iter().all(|l| l["event"] != "pair"));
    // the address starts answering: the worker connects, then POSTs
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind late");
    let mute = Mute::on(listener);
    let done = live.response(id);
    assert_eq!(error_of(&done).0, "pair_failed");
    assert!(*mute.connects.lock().expect("count") >= 2, "a reachability probe, then the POST");
    assert!(!mute.bodies.lock().expect("bodies").is_empty());
    drop(mute);
    // exp bounds the wait: an offer that ends in 2 s, an address that never answers
    let dead = format!("http://127.0.0.1:{}", free_port());
    let started = Instant::now();
    let reply = live.call("pair.join", json!({"offer": forged_offer(&dead, now() + 2)}));
    assert_eq!(error_of(&reply), ("pair_failed", "This offer expired. Cancel on your Mac and start a new offer."));
    assert!(started.elapsed() < Duration::from_secs(15));
    assert_eq!((live.joiners)(), 1, "expiry drops its joiner (the earlier text's joiner is the one kept)");
}

#[test]
#[cfg(target_os = "ios")]
fn a_cancel_during_the_reachability_wait_ends_it() {
    let (_pdir, pdb) = phone();
    let dead = format!("http://127.0.0.1:{}", free_port());
    let mut live = Live::start(&pdb, fast_join());
    let id = live.send("pair.join", json!({"offer": forged_offer(&dead, now() + 600)}));
    std::thread::sleep(Duration::from_millis(300));
    let cancelled = live.call("pair.cancel", json!({}));
    assert_eq!(cancelled["result"], json!({"state": "aborted"}));
    let done = live.response(id);
    assert_eq!(error_of(&done), ("pair_failed", "Cancelled. Cancel on your Mac too."));
    assert_eq!((live.joiners)(), 0);
    assert!(phone_files(&pdb).is_empty());
}

/// S4: there is no tolerance past `exp` (the joiner refuses `now > exp` itself, so a 300 s allowance in the prefix
/// never changed an outcome): a phone clock fast by any amount past `exp` is refused before the network.
#[test]
fn a_phone_clock_past_exp_is_refused_before_any_network_call() {
    let (_pdir, pdb) = phone();
    let wire = Tripwire::new();
    let mut live = Live::start(&pdb, fast_join());
    for past in [1u64, 100, 299, 300, 301, 900] {
        let reply = live.call("pair.join", json!({"offer": forged_offer(&wire.url(), now() - past)}));
        assert_eq!(error_of(&reply), ("pair_failed", CLOCK_EXPIRED), "past {past}");
    }
    assert!(!wire.tripped());
    assert_eq!((live.joiners)(), 0);
    assert!(phone_files(&pdb).is_empty());
}

/// S2 stage 1 (every core): addresses that are never a pairing address are refused after the IP-literal check.
#[test]
fn an_offer_address_that_is_never_a_pairing_address_is_refused_on_every_core() {
    let (_dir, db) = phone();
    let mut live = Live::start(&db, JoinHooks::default());
    let fresh = now() + 600;
    for host in [
        "0.0.0.0", "0.1.2.3", "255.255.255.255", "224.0.0.1", "239.255.255.250", "240.0.0.1", "169.254.1.1",
        "[::]", "[ff02::1]", "[fe80::1]", "[febf::1]", "[::ffff:0:0]",
    ] {
        let reply = live.call("pair.join", json!({"offer": forged_offer(&format!("http://{host}:24816"), fresh)}));
        assert_eq!(error_of(&reply), ("bad_params", BAD_ADDRESS), "{host}");
    }
    assert!(phone_files(&db).is_empty());
    assert_eq!((live.joiners)(), 0);
    // not refused by the class: loopback, private and global addresses pass stage 1 and meet the next refusal
    // (the expiry here, so no core goes on to the network or the phone's stage 2)
    for host in ["127.0.0.1", "[::1]", "10.0.0.5", "192.168.1.20", "100.64.0.1", "[fd00::5]", "8.8.8.8", "[2001:4860:4860::8888]"] {
        let reply = live.call("pair.join", json!({"offer": forged_offer(&format!("http://{host}:24816"), 1000)}));
        assert_eq!(error_of(&reply), ("pair_failed", CLOCK_EXPIRED), "{host}");
    }
}

/// The twin's trim equals Rust's: `str::trim` strips Unicode White_Space only (not U+001C..U+001F).
#[test]
fn the_offer_text_is_trimmed_by_unicode_white_space_only() {
    let (_dir, db) = phone();
    let mut live = Live::start(&db, JoinHooks::default());
    let good = forged_offer("http://127.0.0.1:24816", 1000); // refused as expired once it parses
    for (label, lead, trail) in [("space", " ", "\n"), ("ideographic space", "\u{3000}", ""), ("nel and nbsp", "\u{85}", "\u{a0}")] {
        let reply = live.call("pair.join", json!({"offer": format!("{lead}{good}{trail}")}));
        assert_eq!(error_of(&reply), ("pair_failed", CLOCK_EXPIRED), "{label}");
    }
    for (label, text) in [("a leading FS", format!("\u{1c}{good}")), ("a trailing US", format!("{good}\u{1f}")), ("a leading ZWSP", format!("\u{200b}{good}"))] {
        let reply = live.call("pair.join", json!({"offer": text}));
        assert_eq!(error_of(&reply), ("bad_params", "that is not a pairing offer"), "{label}");
    }
}

/// N5: an unfinished forget (its marker beside the store) refuses a join before any network call.
#[test]
fn a_pending_forget_refuses_a_join_after_the_landing_site_check() {
    let (_dir, db) = phone();
    let wire = Tripwire::new();
    let folder = db.parent().expect("folder").to_path_buf();
    std::fs::create_dir_all(&folder).expect("mkdir");
    std::fs::write(folder.join("forget.pending"), b"").expect("marker");
    let mut live = Live::start(&db, JoinHooks::default());
    let reply = live.call("pair.join", json!({"offer": forged_offer(&wire.url(), now() + 600)}));
    assert_eq!(error_of(&reply), ("pair_failed", FORGET_PENDING));
    // the expiry is checked first, and "already paired" wins over a pending forget
    let reply = live.call("pair.join", json!({"offer": forged_offer(&wire.url(), 1000)}));
    assert_eq!(error_of(&reply), ("pair_failed", CLOCK_EXPIRED));
    std::fs::write(&db, b"x").expect("store");
    let reply = live.call("pair.join", json!({"offer": forged_offer(&wire.url(), now() + 600)}));
    assert_eq!(error_of(&reply), ("pair_failed", ALREADY_PAIRED));
    assert!(!wire.tripped());
}

#[test]
#[cfg(target_os = "ios")]
fn the_offerer_ending_the_offer_reads_as_closed_and_keeps_no_secret() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let mut live = Live::start(&pdb, fast_join());
    let id = live.send("pair.join", json!({"offer": mac.offer}));
    let _digits = code_of(&mut live);
    serving::cancel(&mac.env).expect("the Mac cancels");
    let done = live.response(id);
    let (code, message) = error_of(&done);
    assert_eq!(code, "pair_failed");
    assert_eq!(message, "Your Mac closed this offer. Cancel on your Mac and start a new offer.");
    assert!(phone_files(&pdb).is_empty());
}

#[test]
#[cfg(target_os = "ios")]
fn a_failure_injected_after_each_landing_step_reports_what_is_left() {
    use disconect_core::pair_client::LandStep;
    for (step, name, has_key, has_store) in [
        (LandStep::RelayFile, "relay file", false, false),
        (LandStep::KeyFile, "key file", true, false),
        (LandStep::Store, "store", true, true),
        (LandStep::Pull, "pull", true, true),
    ] {
        let (_pdir, pdb) = phone();
        let mac = mac(None);
        let hooks = JoinHooks { fail_after: Some(step), ..fast_join() };
        let mut live = Live::start(&pdb, hooks);
        let id = live.send("pair.join", json!({"offer": mac.offer}));
        let digits = code_of(&mut live);
        mac.confirm(&digits).expect("release");
        live.phase("released");
        live.call("pair.land", json!({"confirm": true}));
        let done = live.response(id);
        let (code, message) = error_of(&done);
        assert_eq!(code, "pair_failed", "{name}");
        let expected = if has_key {
            "The key was saved, but the first pull did not finish. Open Sync and choose Pull now; if the app asks for the passphrase, enter it."
        } else {
            "Pairing stopped before the key was saved. Cancel on your Mac and start a new offer."
        };
        assert_eq!(message, expected, "{name}");
        // 12-H (d): a landing that fails before the key file takes its relay.json back out
        assert_eq!(pdb.parent().expect("folder").join("relay.json").exists(), has_key, "{name}: relay.json stays only with the key file");
        assert_eq!(keys::key_path_for(&pdb).exists(), has_key, "{name}: key file");
        assert_eq!(pdb.exists(), has_store, "{name}: store");
        // no master reached the session: a key file with no master reads as locked, never as unlocked
        let status = live.call("key.status", json!({}));
        assert_eq!(status["result"]["unlocked"], !has_key, "{name}: unlocked");
        let sync = live.call("sync.status", json!({}));
        if has_key {
            assert_eq!(error_of(&sync).0, "locked", "{name}");
        }
        // the joiner is dropped, the slot is free
        assert_eq!((live.joiners)(), 0, "{name}");
        // nothing in any line carries what the failure left
        for line in live.lines() {
            let t = line.to_string();
            assert!(!t.contains("keys.json") && !t.contains("127.0.0.1"), "{name}: {t}");
        }
    }
}

#[test]
#[cfg(target_os = "ios")]
fn no_request_during_landing_answers_locked() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    // 300 ms after each landing step widens the window between the key file and the hand-back
    let hooks = JoinHooks { step_pause: Duration::from_millis(300), ..fast_join() };
    let mut live = Live::start(&pdb, hooks);
    let id = live.send("pair.join", json!({"offer": mac.offer}));
    let digits = code_of(&mut live);
    mac.confirm(&digits).expect("release");
    live.phase("released");
    live.call("pair.land", json!({"confirm": true}));
    // poll until the key file exists, then until the answer: never `locked`, key.status never unlocked:false
    let mut polled_with_key = 0;
    let end = Instant::now() + Duration::from_secs(40);
    let mut landed = None;
    while landed.is_none() && Instant::now() < end {
        let key_there = keys::key_path_for(&pdb).exists();
        let status = live.call("key.status", json!({}));
        assert_eq!(status["result"]["unlocked"], true, "key.status said locked mid-landing: {status}");
        let sync = live.call("sync.status", json!({}));
        if let Some(error) = sync.get("error") {
            assert_ne!(error["code"], "locked", "a request answered locked mid-landing");
            assert_eq!(error["code"], "busy");
        }
        let data = live.call("data.today", json!({}));
        if let Some(error) = data.get("error") {
            assert_ne!(error["code"], "locked", "data.today answered locked mid-landing");
        }
        if key_there {
            polled_with_key += 1;
        }
        landed = live.response_within(id, 0);
    }
    assert!(polled_with_key >= 1, "the window between the key file and the hand-back was never probed");
    assert_eq!(landed.expect("landed")["result"]["state"], "landed");
    let sync = live.call("sync.status", json!({}));
    assert!(sync.get("error").is_none(), "after the hand-back the session reads the store: {sync}");
}

/// A server that reads a request and answers every one with `202` and `body` (a forged offerer).
fn liar(body: Vec<u8>) -> (String, Arc<AtomicBool>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let url = format!("http://127.0.0.1:{}", listener.local_addr().expect("addr").port());
    let stop = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        while !s.load(Ordering::SeqCst) {
            let Ok((mut conn, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            conn.set_nonblocking(false).expect("blocking");
            conn.set_read_timeout(Some(Duration::from_millis(300))).expect("timeout");
            let mut data = Vec::new();
            let mut chunk = [0u8; 1024];
            while let Ok(n) = conn.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&chunk[..n]);
                if data.windows(4).position(|w| w == b"\r\n\r\n").is_some_and(|end| data.len() >= end + 4 + 64) {
                    break;
                }
            }
            if data.starts_with(b"POST ") {
                let head = format!(
                    "HTTP/1.1 202 Accepted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = conn.write_all(head.as_bytes());
                let _ = conn.write_all(&body);
            }
        }
    });
    (url, stop, thread)
}

/// A forged offerer's `202` (wrong length, a reveal that is not the committed nonce, a random tag) shows no
/// code and reads the same on every variant: "did not check out", with the cancel-on-your-Mac line.
#[test]
#[cfg(target_os = "ios")]
fn a_forged_reply_shows_no_code_and_every_variant_reads_the_same() {
    let expected = "Your Mac's answer did not check out. Cancel on your Mac and start a new offer.";
    for (label, body) in [
        ("empty", Vec::new()),
        ("32 bytes", vec![3u8; 32]),
        ("64 bytes, reveal not committed", vec![4u8; 64]),
        ("a long body", vec![5u8; 400]),
    ] {
        let (_pdir, pdb) = phone();
        let (url, stop, thread) = liar(body);
        let mut live = Live::start(&pdb, fast_join());
        let reply = live.call("pair.join", json!({"offer": forged_offer(&url, now() + 600)}));
        assert_eq!(error_of(&reply), ("pair_failed", expected), "{label}");
        assert!(live.lines().iter().all(|l| l["event"] != "pair"), "{label}: a forged reply showed a code or an event");
        assert!(phone_files(&pdb).is_empty(), "{label}");
        stop.store(true, Ordering::SeqCst);
        thread.join().expect("liar");
    }
}

// ---- 12-F row 3 review fixes (simulator) ----

/// A TCP proxy in front of the Mac's listener that holds one response until released: the first reply to a
/// `POST` (the offerer's `202`) or the first `200` of a `GET .../payload`. Every request goes upstream with
/// `Connection: close` and every reply comes back with it, so a held reply never meets a reused connection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HoldWhat {
    Post,
    Payload200,
}

struct Hold {
    url: String,
    reached: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

fn read_request(conn: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    conn.set_read_timeout(Some(Duration::from_millis(500))).ok()?;
    let mut data = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match conn.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&chunk[..n]),
        }
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok()))
                .unwrap_or(0);
            if data.len() >= end + 4 + length {
                break;
            }
        }
    }
    (!data.is_empty()).then_some(data)
}

impl Hold {
    fn new(upstream: &str, what: HoldWhat) -> Hold {
        let upstream = upstream.strip_prefix("http://").expect("http url").to_string();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let url = format!("http://127.0.0.1:{}", listener.local_addr().expect("addr").port());
        let (reached, release, stop) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let (r, g, s) = (Arc::clone(&reached), Arc::clone(&release), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                let Ok((mut conn, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                conn.set_nonblocking(false).expect("blocking");
                let Some(request) = read_request(&mut conn) else { continue };
                // head as text, body as the bytes it is (a join body is binary)
                let split = request.windows(4).position(|w| w == b"\r\n\r\n").map_or(request.len(), |at| at + 4);
                let text = String::from_utf8_lossy(&request[..split]).into_owned();
                let first = text.lines().next().unwrap_or("").to_string();
                // forward with Connection: close (the offerer checks the Host header against its own address)
                let head: String = text
                    .split("\r\n")
                    .map(|l| if l.to_ascii_lowercase().starts_with("host:") { format!("Host: {upstream}") } else { l.to_string() })
                    .collect::<Vec<_>>()
                    .join("\r\n")
                    .replacen("\r\n", "\r\nConnection: close\r\n", 1);
                let mut forwarded = head.into_bytes();
                forwarded.extend_from_slice(&request[split..]);
                let Ok(mut up) = std::net::TcpStream::connect(&upstream) else { continue };
                let _ = up.write_all(&forwarded);
                let mut reply = Vec::new();
                let _ = up.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = up.read_to_end(&mut reply);
                let reply_text = String::from_utf8_lossy(&reply).into_owned();
                let held = match what {
                    HoldWhat::Post => first.starts_with("POST "),
                    HoldWhat::Payload200 => first.contains("/payload") && reply_text.starts_with("HTTP/1.1 200"),
                } && !r.load(Ordering::SeqCst);
                if held {
                    r.store(true, Ordering::SeqCst);
                    while !g.load(Ordering::SeqCst) && !s.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                // the reply as it came, its head's Connection header replaced
                let split = reply.windows(4).position(|w| w == b"\r\n\r\n").map_or(reply.len(), |at| at + 4);
                let head: String = String::from_utf8_lossy(&reply[..split])
                    .lines()
                    .filter(|l| !l.to_ascii_lowercase().starts_with("connection:"))
                    .map(|l| format!("{l}\r\n"))
                    .collect();
                let head = head.replacen("\r\n\r\n", "\r\n", 1);
                let _ = conn.write_all(head.as_bytes());
                let _ = conn.write_all(b"Connection: close\r\n\r\n");
                let _ = conn.write_all(&reply[split..]);
            }
        });
        Hold { url, reached, release, stop, thread: Some(thread) }
    }

    fn wait_reached(&self) {
        assert!(wait_until(40, || self.reached.load(Ordering::SeqCst)), "the proxy never saw the held request");
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.release.store(true, Ordering::SeqCst);
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// `mac.offer` pointed at `url` instead (the transcript does not hold the URL).
fn offer_at(offer: &str, url: &str) -> String {
    let parsed = Offer::parse(offer).expect("offer");
    Offer { url: url.to_string(), ..parsed }.encode()
}

fn mac_url(mac: &Mac) -> String {
    Offer::parse(&mac.offer).expect("offer").url
}

/// M1, the landing: `key.lock` while the landing runs must not be undone by the hand-back. The pairing still
/// lands (paired, locked) and the answer says landed.
#[test]
#[cfg(target_os = "ios")]
fn a_key_lock_during_landing_is_not_undone_by_the_hand_back() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let hooks = JoinHooks { step_pause: Duration::from_millis(400), ..fast_join() };
    let mut live = Live::start(&pdb, hooks);
    let id = live.send("pair.join", json!({"offer": mac.offer}));
    let digits = code_of(&mut live);
    mac.confirm(&digits).expect("release");
    live.phase("released");
    live.call("pair.land", json!({"confirm": true}));
    // the key file exists and the landing is paused after a step: lock the app now (lock_after_absence)
    assert!(wait_until(40, || keys::key_path_for(&pdb).exists()), "the key file never landed");
    let locked = live.call("key.lock", json!({}));
    assert_eq!(locked["result"], json!({"state": "locked"}));
    let done = live.response(id);
    assert_eq!(done["result"]["state"], "landed", "the pairing still lands: {done}");
    assert!(pdb.exists() && keys::key_path_for(&pdb).exists());
    // locked, and every reader answers locked: no master came back
    let status = live.call("key.status", json!({}));
    assert_eq!(status["result"]["unlocked"], false, "the hand-back undid key.lock: {status}");
    let sync = live.call("sync.status", json!({}));
    assert_eq!(error_of(&sync).0, "locked", "{sync}");
    let data = live.call("data.today", json!({}));
    assert_eq!(error_of(&data).0, "locked", "{data}");
    assert_eq!((live.joiners)(), 0);
    // a later join starts clean (the flag is per join): the phone is paired now, so it is refused as such
    let again = live.call("pair.join", json!({"offer": mac.offer}));
    assert_eq!(error_of(&again), ("pair_failed", ALREADY_PAIRED));
}

/// M1, the wait: `key.lock` while the join waits for `pair.land` ends it as a no and lands nothing.
#[test]
#[cfg(target_os = "ios")]
fn a_key_lock_during_the_land_wait_ends_the_join_not_paired() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let mut live = Live::start(&pdb, fast_join());
    let id = live.send("pair.join", json!({"offer": mac.offer}));
    let digits = code_of(&mut live);
    mac.confirm(&digits).expect("release");
    live.phase("released");
    let started = Instant::now();
    assert_eq!(live.call("key.lock", json!({}))["result"], json!({"state": "locked"}));
    let done = live.response(id);
    assert_eq!(error_of(&done), ("pair_failed", "Not paired. Nothing was saved on this device. Your Mac may say Paired; it keeps no record of this device. Start a new offer on your Mac to pair."));
    assert!(started.elapsed() < Duration::from_secs(20), "the 600 s wait was not ended");
    assert!(phone_files(&pdb).is_empty(), "nothing is written while the key is supposed to be dropped");
    assert_eq!((live.joiners)(), 0);
    assert_eq!(live.call("pair.land", json!({"confirm": true}))["error"]["code"], "not_found");
}

/// S1: a cancel that races the offerer's `202` is answered "aborted" and then no code event appears.
#[test]
#[cfg(target_os = "ios")]
fn a_cancel_that_races_the_202_shows_no_code() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let hold = Hold::new(&mac_url(&mac), HoldWhat::Post);
    let mut live = Live::start(&pdb, fast_join());
    let id = live.send("pair.join", json!({"offer": offer_at(&mac.offer, &hold.url)}));
    hold.wait_reached(); // the Mac answered; the phone has not seen it
    let cancelled = live.call("pair.cancel", json!({}));
    assert_eq!(cancelled["result"], json!({"state": "aborted"}));
    hold.release.store(true, Ordering::SeqCst);
    let done = live.response(id);
    assert_eq!(error_of(&done), ("pair_failed", "Cancelled. Cancel on your Mac too."));
    assert!(live.lines().iter().all(|l| l["event"] != "pair"), "an event followed the aborted reply: {:?}", live.lines());
    assert!(phone_files(&pdb).is_empty());
    assert_eq!((live.joiners)(), 0);
}

/// S3: the release gate. A cancel answered "aborted" while the payload's 200 is in flight wins: no "released",
/// "Cancelled", nothing written. (Without the gate the worker would release and wait for `pair.land`.)
#[test]
#[cfg(target_os = "ios")]
fn a_cancel_while_the_payload_is_in_flight_wins_over_the_release() {
    let (_pdir, pdb) = phone();
    let mac = mac(None);
    let hold = Hold::new(&mac_url(&mac), HoldWhat::Payload200);
    let hooks = JoinHooks { land_wait: Duration::from_millis(500), ..fast_join() };
    let mut live = Live::start(&pdb, hooks);
    let id = live.send("pair.join", json!({"offer": offer_at(&mac.offer, &hold.url)}));
    let digits = code_of(&mut live);
    mac.confirm(&digits).expect("release");
    hold.wait_reached(); // the payload's 200 is held
    let cancelled = live.call("pair.cancel", json!({}));
    assert_eq!(cancelled["result"], json!({"state": "aborted"}));
    hold.release.store(true, Ordering::SeqCst);
    let done = live.response(id);
    assert_eq!(error_of(&done), ("pair_failed", "Cancelled. Cancel on your Mac too."));
    assert!(live.lines().iter().all(|l| l["phase"] != "released"), "released after an answered cancel");
    assert!(phone_files(&pdb).is_empty());
    assert_eq!((live.joiners)(), 0);
}

/// N9: a valid reveal (the real `N_o` matching `c`) with a bad tag reads the same as every other forged reply.
#[test]
#[cfg(target_os = "ios")]
fn a_valid_reveal_with_a_bad_tag_reads_as_did_not_check_out() {
    let n_o = [0x42u8; 32];
    let (_secret, public) = pair::ephemeral().expect("key");
    let offer = Offer { pub_key: public, c: pair::commit(&n_o), s: [9u8; 16], id: [5u8; 16], exp: now() + 600, url: String::new() };
    let mut body = n_o.to_vec();
    body.extend_from_slice(&[0x99u8; 32]); // a tag nobody computed
    let (url, stop, thread) = liar(body);
    let (_pdir, pdb) = phone();
    let mut live = Live::start(&pdb, fast_join());
    let reply = live.call("pair.join", json!({"offer": Offer { url, ..offer }.encode()}));
    assert_eq!(
        error_of(&reply),
        ("pair_failed", "Your Mac's answer did not check out. Cancel on your Mac and start a new offer.")
    );
    assert!(live.lines().iter().all(|l| l["event"] != "pair"), "a bad tag showed a code or an event");
    assert!(phone_files(&pdb).is_empty());
    stop.store(true, Ordering::SeqCst);
    thread.join().expect("liar");
}

/// N2: two texts of one parsed offer are one joiner (the key is the canonical re-encoding, not the text).
#[test]
#[cfg(target_os = "ios")]
fn two_texts_of_one_parsed_offer_share_a_joiner() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (_pdir, pdb) = phone();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://127.0.0.1:{}", listener.local_addr().expect("addr").port());
    let mute = Mute::on(listener);
    let mut live = Live::start(&pdb, fast_join());
    let text = forged_offer(&url, now() + 600);
    // the same offer with spaces in its JSON: another text, the same parsed offer
    let json = URL_SAFE_NO_PAD.decode(text.strip_prefix("disconect-pair:v2.").expect("prefix")).expect("base64");
    let value: Value = serde_json::from_slice(&json).expect("json");
    let spaced = serde_json::to_string_pretty(&value).expect("pretty");
    let other = format!("disconect-pair:v2.{}", URL_SAFE_NO_PAD.encode(spaced.as_bytes()));
    assert_ne!(text, other);
    assert_eq!(Offer::parse(&text).expect("a").encode(), Offer::parse(&other).expect("b").encode());
    let _ = live.call("pair.join", json!({"offer": text}));
    assert_eq!((live.joiners)(), 1);
    let _ = live.call("pair.join", json!({"offer": other}));
    assert_eq!((live.joiners)(), 1, "the same parsed offer is the same joiner");
    let bodies = mute.bodies.lock().expect("bodies").clone();
    assert!(bodies.len() >= 6 && bodies.iter().all(|b| *b == bodies[0]), "the retry re-posted another key");
}

/// S2 stage 2 (simulator): a globally routable address that is not on one of this phone's networks is refused
/// before the network; RFC1918 reaches the network attempt; loopback is allowed in a simulator build.
#[test]
#[cfg(target_os = "ios")]
fn stage_two_refuses_an_off_link_global_address_and_lets_private_and_sim_loopback_through() {
    let (_pdir, pdb) = phone();
    let mut live = Live::start(&pdb, fast_join());
    let fresh = now() + 600;
    for host in ["8.8.8.8", "1.1.1.1", "[2001:4860:4860::8888]"] {
        let reply = live.call("pair.join", json!({"offer": forged_offer(&format!("http://{host}:24816"), fresh)}));
        assert_eq!(error_of(&reply), ("pair_failed", NOT_ON_LINK), "{host}");
    }
    assert!(phone_files(&pdb).is_empty());
    assert_eq!((live.joiners)(), 0);
    // RFC1918 (and CGNAT, ULA) are not refused: the worker starts and waits for the address (no answer yet)
    for host in ["10.255.254.253", "192.168.254.253", "172.31.254.253", "100.64.254.253", "[fd00:dead::5]"] {
        let id = live.send("pair.join", json!({"offer": forged_offer(&format!("http://{host}:24816"), fresh)}));
        std::thread::sleep(Duration::from_millis(400));
        assert!(live.response_within(id, 0).is_none(), "{host}: refused by the class instead of reaching the network attempt");
        assert_eq!(live.call("pair.cancel", json!({}))["result"], json!({"state": "aborted"}), "{host}");
        let done = live.response(id);
        assert_eq!(error_of(&done), ("pair_failed", "Cancelled. Cancel on your Mac too."), "{host}");
    }
    // loopback is allowed in the simulator (every other test here joins through it)
    let wire = Tripwire::new();
    let id = live.send("pair.join", json!({"offer": forged_offer(&wire.url(), fresh)}));
    std::thread::sleep(Duration::from_millis(400));
    assert!(live.response_within(id, 0).is_none(), "loopback was refused in a simulator build");
    assert_eq!(live.call("pair.cancel", json!({}))["result"], json!({"state": "aborted"}));
    let _ = live.response(id);
}
