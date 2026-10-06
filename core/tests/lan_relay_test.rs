// SPDX-License-Identifier: AGPL-3.0-or-later
//! The LAN relay (Bet 12, slice B) end to end on 127.0.0.1: a `LanRelay` client against the real
//! HTTP server (in process and as the `relay-serve` binary), through real stores. Synthetic data
//! and the committed test key only; every listener binds 127.0.0.1.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use common::{PASSPHRASE, encrypted_copy, fixtures};
use disconect_core::keys::{self, PassphraseSource};
use disconect_core::relay::bundle::account_for;
use disconect_core::relay::folder::{FolderRelay, Relay, RelayError};
use disconect_core::relay::lan::{
    AUTH_HEADER, LanRelay, RESP_HEADER, auth_value, auth_value_declaring, resp_header_value, token_key,
    wall_clock,
};
use disconect_core::relay::lan_server::{LanServer, Limits, Logger};
use disconect_core::relay::sync::{self, SyncError};
use disconect_core::sources::{self, import_path};
use disconect_core::store::{self, Store};
use rusqlite::Connection;
use serde_json::Value;

fn master() -> &'static [u8] {
    static MASTER: OnceLock<Vec<u8>> = OnceLock::new();
    MASTER.get_or_init(|| {
        keys::unlock(
            &fixtures().join("test.keys.json"),
            PassphraseSource::Explicit(PASSPHRASE),
        )
        .expect("unlock the fixture key")
        .to_vec()
    })
}

fn other_master() -> Vec<u8> {
    (1u8..33).collect()
}

struct Device {
    _dir: tempfile::TempDir,
    store: Store,
}

impl Device {
    fn conn(&self) -> &Connection {
        self.store.conn()
    }
}

fn device() -> Device {
    let (dir, db) = encrypted_copy();
    let secret = keys::unlock(
        &keys::key_path_for(&db),
        PassphraseSource::Explicit(PASSPHRASE),
    )
    .expect("unlock");
    let store = store::open_for_write_with(&db, "test", 5.0, Some(&secret)).expect("open store");
    Device { _dir: dir, store }
}

use common::convergence::{Fingerprint, MONITORING, count, export_with_uds, fit_drop};

fn fingerprint(device: &Device) -> Fingerprint {
    common::convergence::fingerprint(device.conn())
}

fn daily_rows(device: &Device) -> BTreeSet<String> {
    common::convergence::daily_rows(device.conn())
}

fn silent() -> Logger {
    Arc::new(|_, _| {})
}

/// A server in this process over a scratch folder, plus a client for it.
struct Lan {
    folder: PathBuf,
    server: LanServer,
}

impl Lan {
    fn start(dir: &Path, for_master: &[u8]) -> Lan {
        let folder = dir.join("relay");
        let server = LanServer::start("127.0.0.1:0", &folder, for_master, silent()).expect("serve");
        Lan { folder, server }
    }

    fn url(&self) -> String {
        format!("http://{}", self.server.local_addr())
    }

    fn client(&self, with: &[u8]) -> LanRelay {
        LanRelay::new(&self.url(), with).expect("client")
    }

    fn folder_relay(&self) -> FolderRelay {
        FolderRelay::new(&self.folder)
    }
}

fn http() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .proxy(None)
        .build()
        .into()
}

#[test]
fn a_pushes_over_lan_and_an_empty_b_pulls_to_the_same_store() {
    let tmp = tempfile::tempdir().expect("tmp");
    let lan = Lan::start(tmp.path(), master());
    let a = device();
    import_path(
        a.conn(),
        &export_with_uds(tmp.path(), "export", "2025-06-15", 4000),
        None,
        None,
    )
    .expect("import export");
    import_path(
        a.conn(),
        &fit_drop(tmp.path(), "fits", &MONITORING),
        None,
        None,
    )
    .expect("import fit");
    let b = device();
    let pushed = sync::push(a.conn(), master(), &lan.client(master())).expect("push");
    assert_eq!(pushed.bundles.len(), 1);
    assert!(pushed.records >= 3 && pushed.ranges == 1);
    // the server's folder is the folder relay: the object is there, and only ciphertext
    let account = account_for(master());
    let listed = lan.folder_relay().list(&account).expect("list");
    assert_eq!(listed, pushed.bundles);
    let blob = lan.folder_relay().get(&listed[0]).expect("object");
    assert!(blob.len() >= 64 * 1024 && !blob.windows(10).any(|w| w == b"totalSteps"));

    let pulled = sync::pull(b.conn(), master(), &lan.client(master())).expect("pull");
    assert_eq!(pulled.status, "ok");
    assert_eq!(pulled.applied, pushed.bundles);
    assert_eq!(pulled.records_new as usize, pushed.records);
    assert_eq!(fingerprint(&a), fingerprint(&b), "raw + ranges + counts");
    assert_eq!(daily_rows(&a), daily_rows(&b), "daily rows");
    assert!(!daily_rows(&b).is_empty());

    // reparse changes nothing on the pulled store
    let reference = (fingerprint(&b), daily_rows(&b));
    sources::reparse_all(b.conn(), None, false).expect("reparse");
    assert_eq!((fingerprint(&b), daily_rows(&b)), reference, "reparse 0");
    // idempotent and echo-free over the wire too
    assert!(
        sync::pull(b.conn(), master(), &lan.client(master()))
            .expect("pull")
            .applied
            .is_empty()
    );
    assert!(
        sync::push(b.conn(), master(), &lan.client(master()))
            .expect("push")
            .bundles
            .is_empty()
    );
    lan.server.stop();
}

#[test]
fn a_wrong_master_is_refused_and_nothing_is_marked() {
    let tmp = tempfile::tempdir().expect("tmp");
    let lan = Lan::start(tmp.path(), master());
    let stranger = lan.client(&other_master());
    // the server tags its answers under ITS key: a client with another key cannot verify them, so a
    // wrong master is `Unverified` (a Mac set up again with a new key looks exactly like this)
    let error = stranger
        .list(&account_for(&other_master()))
        .expect_err("unverified");
    assert!(matches!(error, RelayError::Unverified), "{error}");
    assert_eq!(error.reason(), "relay_unverified");
    assert!(error.to_string().starts_with("relay_unverified"));

    let a = device();
    import_path(
        a.conn(),
        &fit_drop(tmp.path(), "fits", &MONITORING),
        None,
        None,
    )
    .expect("import");
    let unsent = count(
        a.conn(),
        "SELECT count(*) FROM raw_records r LEFT JOIN relay_seen s ON s.raw_record_id=r.id WHERE s.raw_record_id IS NULL",
    );
    // the stranger's master packs under its own account; its first call is already unverifiable
    let refused = sync::push(a.conn(), &other_master(), &stranger).expect_err("refused");
    assert!(
        matches!(refused, SyncError::Relay(RelayError::Unverified)),
        "{refused}"
    );
    assert_eq!(count(a.conn(), "SELECT count(*) FROM relay_bundles"), 0);
    assert_eq!(count(a.conn(), "SELECT count(*) FROM relay_seen"), 0);
    assert!(unsent > 0);
    let account = account_for(master());
    assert!(
        lan.folder_relay().list(&account).expect("list").is_empty(),
        "nothing reached the folder"
    );
    // the right master still works
    assert_eq!(
        sync::push(a.conn(), master(), &lan.client(master()))
            .expect("push")
            .bundles
            .len(),
        1
    );
}

#[test]
fn stale_timestamps_bad_names_and_strangers_are_refused_over_http() {
    let tmp = tempfile::tempdir().expect("tmp");
    let lan = Lan::start(tmp.path(), master());
    let agent = http();
    let key = token_key(master());
    let account = account_for(master());
    let url = |path: &str| format!("{}{path}", lan.url());
    let sign = |method: &str, path: &str, stamp: u64, body: &[u8]| {
        auth_value(&*key, method, path, stamp, body).expect("header")
    };
    // health: no token, a tiny fixed answer
    let mut health = agent.get(&url("/v1/health")).call().expect("health");
    assert_eq!(health.status().as_u16(), 200);
    assert_eq!(
        health.body_mut().read_to_string().expect("body"),
        r#"{"product":"DISCOnect","relay":"lan","v":1}"#
    );
    // no token, and a valid token a minute and a day old
    let list = "/v1/objects";
    assert_eq!(agent.get(&url(list)).call().expect("call").status(), 401);
    let now = wall_clock();
    let fresh = agent
        .get(&url(list))
        .header(AUTH_HEADER, &sign("GET", list, now, b""))
        .call()
        .expect("call");
    assert_eq!(fresh.status(), 200);
    let minute = agent
        .get(&url(list))
        .header(AUTH_HEADER, &sign("GET", list, now - 60, b""))
        .call()
        .expect("call");
    assert_eq!(minute.status(), 200, "inside the 300 s window");
    let mut stale = agent
        .get(&url(list))
        .header(AUTH_HEADER, &sign("GET", list, now - 86_400, b""))
        .call()
        .expect("call");
    assert_eq!(stale.status(), 401);
    assert!(stale.body_mut().read_to_vec().expect("body").is_empty());
    let future = agent
        .get(&url(list))
        .header(AUTH_HEADER, &sign("GET", list, now + 3_600, b""))
        .call()
        .expect("call");
    assert_eq!(future.status(), 401);
    // a good token for another path does not open this one
    let replay = agent
        .get(&url("/v1/health2"))
        .header(AUTH_HEADER, &sign("GET", list, now, b""))
        .call()
        .expect("call");
    assert_eq!(replay.status(), 404);
    // bad names (valid token): 400; a foreign account: 403; unknown route: 404
    let bad = format!("/v1/objects/{account}/not-hex");
    let refused = agent
        .put(&url(&bad))
        .header(AUTH_HEADER, &sign("PUT", &bad, now, b"x"))
        .send(&b"x"[..])
        .expect("call");
    assert_eq!(refused.status(), 400);
    let foreign = format!("/v1/objects/{}/{}", "e".repeat(64), "a".repeat(32));
    let denied = agent
        .put(&url(&foreign))
        .header(AUTH_HEADER, &sign("PUT", &foreign, now, b"x"))
        .send(&b"x"[..])
        .expect("call");
    assert_eq!(denied.status(), 403);
    let unknown = agent
        .get(&url("/v2/objects"))
        .header(AUTH_HEADER, &sign("GET", "/v2/objects", now, b""))
        .call()
        .expect("call");
    assert_eq!(unknown.status(), 404);
    assert!(
        !tmp.path().join("relay").join("e".repeat(64)).exists(),
        "nothing was written for a refused name"
    );
    // a body that does not match its signed hash is a 401 and is never stored
    let name = format!("/v1/objects/{account}/{}", "d".repeat(32));
    let tampered = agent
        .put(&url(&name))
        .header(AUTH_HEADER, &sign("PUT", &name, now, b"signed bytes"))
        .send(&b"other bytes"[..])
        .expect("call");
    assert_eq!(tampered.status(), 401);
    assert!(lan.folder_relay().list(&account).expect("list").is_empty());
    lan.server.stop();
}

#[test]
fn put_get_list_delete_through_the_client_match_the_folder_relay() {
    let tmp = tempfile::tempdir().expect("tmp");
    let lan = Lan::start(tmp.path(), master());
    let client = lan.client(master());
    let account = account_for(master());
    let name = |c: char| format!("{account}/{}", c.to_string().repeat(32));
    client.put(&name('a'), b"one").expect("put");
    client.put(&name('b'), b"two").expect("put");
    assert_eq!(client.get(&name('a')).expect("get"), b"one");
    assert_eq!(
        client.list(&account).expect("list"),
        vec![name('a'), name('b')]
    );
    assert_eq!(
        client.list(&"f".repeat(64)).expect("other account"),
        Vec::<String>::new()
    );
    client.delete(&name('a')).expect("delete");
    assert_eq!(client.list(&account).expect("list"), vec![name('b')]);
    assert!(
        !lan.folder.join(name('a')).exists(),
        "the object is gone from the server's folder"
    );
    let missing = client.get(&name('a')).expect_err("gone");
    assert_eq!(missing.reason(), "FileNotFoundError");
    assert_eq!(
        client.delete(&name('a')).expect_err("gone").reason(),
        "FileNotFoundError"
    );
    assert!(matches!(client.put("../x", b"x"), Err(RelayError::BadName)));
    assert!(matches!(client.get("nope"), Err(RelayError::BadName)));
    // the folder relay reads what the client wrote, and the other way round
    assert_eq!(lan.folder_relay().get(&name('b')).expect("get"), b"two");
    lan.folder_relay().put(&name('c'), b"three").expect("put");
    assert_eq!(client.get(&name('c')).expect("get"), b"three");
    lan.server.stop();
}

#[test]
fn a_server_that_is_down_is_a_retryable_error_and_nothing_is_marked() {
    let tmp = tempfile::tempdir().expect("tmp");
    // find a port nothing listens on: bind, note, drop
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port();
    let down = LanRelay::new(&format!("http://127.0.0.1:{port}"), master()).expect("client");
    let account = account_for(master());
    assert!(matches!(down.list(&account), Err(RelayError::Unreachable)));
    assert!(RelayError::Unreachable.is_transient());

    let a = device();
    import_path(
        a.conn(),
        &fit_drop(tmp.path(), "fits", &MONITORING),
        None,
        None,
    )
    .expect("import");
    let push_error = sync::push(a.conn(), master(), &down).expect_err("down");
    assert!(matches!(
        push_error,
        SyncError::Relay(RelayError::Unreachable)
    ));
    assert_eq!(count(a.conn(), "SELECT count(*) FROM relay_bundles"), 0);
    assert_eq!(count(a.conn(), "SELECT count(*) FROM relay_seen"), 0);
    let b = device();
    let pull_error = sync::pull(b.conn(), master(), &down).expect_err("down");
    assert!(matches!(
        pull_error,
        SyncError::Relay(RelayError::Unreachable)
    ));
    assert_eq!(count(b.conn(), "SELECT count(*) FROM relay_bundles"), 0);
    assert_eq!(count(b.conn(), "SELECT count(*) FROM raw_records"), 0);

    // once the server is up the same stores sync (nothing was lost by failing)
    let lan = Lan::start(tmp.path(), master());
    assert_eq!(
        sync::push(a.conn(), master(), &lan.client(master()))
            .expect("push")
            .bundles
            .len(),
        1
    );
    assert_eq!(
        sync::pull(b.conn(), master(), &lan.client(master()))
            .expect("pull")
            .status,
        "ok"
    );
    assert_eq!(fingerprint(&a), fingerprint(&b));
    lan.server.stop();
}

/// Reads fail as if the connection dropped after the listing: the bundle must not be booked
/// `rejected` (a permanent-looking verdict), the next pull must apply it.
struct DropsOnGet(LanRelay);

impl Relay for DropsOnGet {
    fn put(&self, name: &str, data: &[u8]) -> Result<(), RelayError> {
        self.0.put(name, data)
    }
    fn get(&self, _name: &str) -> Result<Vec<u8>, RelayError> {
        Err(RelayError::Unreachable)
    }
    fn list(&self, account: &str) -> Result<Vec<String>, RelayError> {
        self.0.list(account)
    }
    fn delete(&self, name: &str) -> Result<(), RelayError> {
        self.0.delete(name)
    }
}

#[test]
fn a_connection_lost_while_reading_a_bundle_is_not_a_rejection() {
    let tmp = tempfile::tempdir().expect("tmp");
    let lan = Lan::start(tmp.path(), master());
    let a = device();
    import_path(
        a.conn(),
        &fit_drop(tmp.path(), "fits", &MONITORING),
        None,
        None,
    )
    .expect("import");
    sync::push(a.conn(), master(), &lan.client(master())).expect("push");
    let b = device();
    let broken = DropsOnGet(lan.client(master()));
    let error = sync::pull(b.conn(), master(), &broken).expect_err("lost");
    assert!(matches!(error, SyncError::Relay(RelayError::Unreachable)));
    assert_eq!(
        count(
            b.conn(),
            "SELECT count(*) FROM relay_bundles WHERE status='rejected'"
        ),
        0,
        "never booked as rejected"
    );
    let pulled = sync::pull(b.conn(), master(), &lan.client(master())).expect("retry");
    assert_eq!((pulled.applied.len(), pulled.status), (1, "ok"));
    assert_eq!(fingerprint(&a), fingerprint(&b));
    lan.server.stop();
}

#[test]
fn a_ring_mixing_lan_and_folder_converges() {
    let tmp = tempfile::tempdir().expect("tmp");
    let lan = Lan::start(tmp.path(), master());
    let folder = lan.folder_relay();
    let (a, b, c) = (device(), device(), device());
    import_path(
        a.conn(),
        &export_with_uds(tmp.path(), "export", "2025-06-15", 4000),
        None,
        None,
    )
    .expect("a imports an export");
    import_path(
        b.conn(),
        &fit_drop(tmp.path(), "fits", &MONITORING),
        None,
        None,
    )
    .expect("b imports FIT files");
    import_path(
        c.conn(),
        &export_with_uds(tmp.path(), "export-c", "2025-06-16", 7000),
        None,
        None,
    )
    .expect("c imports another day");
    // A pushes to LAN; B pulls LAN and pushes to the folder; C pulls the folder and pushes to it
    sync::push(a.conn(), master(), &lan.client(master())).expect("a push lan");
    sync::pull(b.conn(), master(), &lan.client(master())).expect("b pull lan");
    sync::push(b.conn(), master(), &folder).expect("b push folder");
    sync::pull(c.conn(), master(), &folder).expect("c pull folder");
    sync::push(c.conn(), master(), &folder).expect("c push folder");
    // everyone pulls what is left, each over the other transport than it pushed with
    sync::pull(a.conn(), master(), &folder).expect("a pull folder");
    sync::pull(b.conn(), master(), &lan.client(master())).expect("b pull lan");
    sync::pull(c.conn(), master(), &lan.client(master())).expect("c pull lan");
    let reference = (fingerprint(&a), daily_rows(&a));
    assert!(!reference.0.0.is_empty() && !reference.1.is_empty());
    for other in [&b, &c] {
        assert_eq!(fingerprint(other), reference.0, "raw + ranges + counts");
        assert_eq!(daily_rows(other), reference.1, "daily rows");
    }
    for seat in [&a, &b, &c] {
        let before = (fingerprint(seat), daily_rows(seat));
        sources::reparse_all(seat.conn(), None, false).expect("reparse");
        assert_eq!((fingerprint(seat), daily_rows(seat)), before, "reparse 0");
        let sent = sync::push(seat.conn(), master(), &lan.client(master())).expect("push");
        assert!(sent.bundles.is_empty(), "nothing echoes");
    }
    lan.server.stop();
}

// ---- the binary ----

struct Cli {
    home: PathBuf,
    pass: PathBuf,
}

impl Cli {
    fn new(dir: &Path) -> Cli {
        let pass = dir.join("pass.txt");
        fs::write(&pass, format!("{PASSPHRASE}\n")).expect("passphrase file");
        let home = dir.join("home");
        fs::create_dir_all(&home).expect("home");
        Cli { home, pass }
    }

    fn command(&self, db: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_disconect-core"));
        command
            .env("HOME", &self.home)
            .env_remove("DISCONECT_PASSPHRASE")
            .arg("--db")
            .arg(db)
            .arg("--passphrase-file")
            .arg(&self.pass);
        command
    }

    fn run(&self, db: &Path, args: &[&str]) -> Output {
        self.command(db).args(args).output().expect("run")
    }
}

/// `relay-serve` as a child process; killed on drop.
struct Served {
    child: Child,
    url: String,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn relay_serve(cli: &Cli, db: &Path, folder: &Path, extra: &[&str]) -> Served {
    let mut child = cli
        .command(db)
        .arg("relay-serve")
        .arg("--relay")
        .arg(folder)
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn relay-serve");
    let mut line = String::new();
    BufReader::new(child.stdout.take().expect("stdout"))
        .read_line(&mut line)
        .expect("first line");
    let url = line
        .trim()
        .strip_prefix("listening ")
        .unwrap_or_else(|| panic!("unexpected first line: {line:?}"))
        .to_string();
    Served { child, url }
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn the_binary_serves_and_syncs_over_lan_with_a_remembered_address() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cli = Cli::new(tmp.path());
    let (_da, a) = encrypted_copy();
    let (_db, b) = encrypted_copy();
    let (_ds, server_db) = encrypted_copy();
    let drop = fit_drop(tmp.path(), "drop", &MONITORING);
    assert_eq!(
        code(&cli.run(&a, &["import", drop.to_str().expect("utf8")])),
        0
    );
    let folder = tmp.path().join("served");
    let served = relay_serve(&cli, &server_db, &folder, &[]);
    assert!(
        served.url.starts_with("http://127.0.0.1:"),
        "{}",
        served.url
    );

    let mut health = http()
        .get(&format!("{}/v1/health", served.url))
        .call()
        .expect("health");
    assert_eq!(health.status().as_u16(), 200);
    assert!(
        health
            .body_mut()
            .read_to_string()
            .expect("body")
            .contains("\"lan\"")
    );

    let pushed = cli.run(&a, &["sync", "push", "--relay", &served.url, "--remember"]);
    assert_eq!(
        code(&pushed),
        0,
        "{}",
        String::from_utf8_lossy(&pushed.stderr)
    );
    assert!(
        text(&pushed).starts_with("pushed 1 bundle(s): 2 record(s), 0 range(s)"),
        "{}",
        text(&pushed)
    );
    assert_eq!(
        fs::read_to_string(cli.home.join(".disconect/relay.json")).expect("config"),
        format!("{{\"lan\": \"{}\"}}\n", served.url)
    );
    let pulled = cli.run(&b, &["sync", "pull"]);
    assert_eq!(
        code(&pulled),
        0,
        "{}",
        String::from_utf8_lossy(&pulled.stderr)
    );
    assert_eq!(
        text(&pulled).trim(),
        "pulled 1 bundle(s): 2 new, 0 duplicate, 0 invalid, 0 conflict(s), 0 new range(s); rejected 0; gaps 0; repaired 0; kept for a later decoder 0"
    );
    // the object sits in the served folder, which is a plain folder relay for anyone else
    let account = account_for(master());
    assert_eq!(
        FolderRelay::new(&folder)
            .list(&account)
            .expect("list")
            .len(),
        1
    );
    let folder_pull = {
        let (_dc, c) = encrypted_copy();
        let out = cli.run(
            &c,
            &["sync", "pull", "--relay", folder.to_str().expect("utf8")],
        );
        text(&out)
    };
    assert!(
        folder_pull.starts_with("pulled 1 bundle(s): 2 new"),
        "{folder_pull}"
    );

    // nothing listening: exit 5, retryable, and nothing marked
    let down = cli.run(&a, &["sync", "pull", "--relay", "http://127.0.0.1:1"]);
    assert_eq!(code(&down), 5, "{}", String::from_utf8_lossy(&down.stderr));
    // https is refused as a usage error; a path in the URL too
    for bad in ["https://127.0.0.1:1", "http://127.0.0.1:1/x"] {
        assert_eq!(
            code(&cli.run(&a, &["sync", "pull", "--relay", bad])),
            2,
            "{bad}"
        );
    }
    let status: Value =
        serde_json::from_str(&text(&cli.run(&b, &["--json", "sync", "status"]))).expect("json");
    assert_eq!(status["bundles"]["pulled_applied"], 1);
    assert_eq!(status["records_unsent"], 0);
}

#[test]
fn relay_serve_needs_an_encrypted_store_and_a_folder() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cli = Cli::new(tmp.path());
    let plain = tmp.path().join("plain.db");
    assert_eq!(code(&cli.run(&plain, &["init"])), 0);
    let folder = tmp.path().join("f");
    let refused = cli.run(
        &plain,
        &["relay-serve", "--relay", folder.to_str().expect("utf8")],
    );
    assert_eq!(code(&refused), 9);
    let (_d, db) = encrypted_copy();
    let no_folder = cli.run(&db, &["relay-serve"]);
    assert_eq!(code(&no_folder), 2);
    let a_url = cli.run(&db, &["relay-serve", "--relay", "http://127.0.0.1:1"]);
    assert_eq!(code(&a_url), 2);
    // not a listenable address
    let bad_listen = cli.run(
        &db,
        &[
            "relay-serve",
            "--relay",
            folder.to_str().expect("utf8"),
            "--listen",
            "not an address",
        ],
    );
    assert_eq!(code(&bad_listen), 1);
}

// ---- slow and forged peers (Bet 12 review F1): 127.0.0.1 only, nothing real ----

/// One HTTP request head (no body sent) on a fresh connection; the connection stays open.
fn open_with_head(addr: std::net::SocketAddr, head: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.write_all(head.as_bytes()).expect("write head");
    stream
}

/// The status of the first answer on `stream`, and how long it took (None: nothing before `wait`).
fn first_status(stream: &mut TcpStream, wait: Duration) -> Option<(u16, Duration)> {
    stream.set_read_timeout(Some(wait)).expect("timeout");
    let started = Instant::now();
    let mut buf = [0u8; 256];
    let count = stream.read(&mut buf).ok().filter(|n| *n > 0)?;
    let text = String::from_utf8_lossy(&buf[..count]).to_string();
    let status = text.split(' ').nth(1)?.parse().ok()?;
    Some((status, started.elapsed()))
}

fn put_head(path: &str, header: &str, length: usize) -> String {
    format!(
        "PUT {path} HTTP/1.1\r\nHost: x\r\n{AUTH_HEADER}: {header}\r\nContent-Length: {length}\r\n\r\n"
    )
}

fn health_millis(addr: std::net::SocketAddr) -> u128 {
    let started = Instant::now();
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .expect("write");
    let answer = first_status(&mut stream, Duration::from_secs(20));
    assert_eq!(answer.map(|a| a.0), Some(200), "health answers");
    started.elapsed().as_millis()
}

#[test]
fn forged_headers_declaring_a_big_body_never_stall_the_server() {
    let tmp = tempfile::tempdir().expect("tmp");
    // the default limits: the 10 s time-out must not be what saves the workers
    let lan = Lan::start(tmp.path(), master());
    let addr = lan.server.local_addr();
    let account = account_for(master());
    let path = format!("/v1/objects/{account}/{}", "b".repeat(32));
    let forged = format!("v1.{}.{}.{}", wall_clock(), "00".repeat(32), "00".repeat(32));
    // more connections than workers (4), each declaring 1 MB and sending none of it, kept open
    let mut held: Vec<TcpStream> = (0..8)
        .map(|_| open_with_head(addr, &put_head(&path, &forged, 1_000_000)))
        .collect();
    for stream in &mut held {
        let (status, took) = first_status(stream, Duration::from_secs(2)).expect("an answer");
        assert_eq!(status, 401, "refused on the head alone");
        assert!(took < Duration::from_secs(1), "answered at once, not after a read: {took:?}");
    }
    let millis = health_millis(addr);
    println!("F1 forged stalls: 8 held connections, health answered in {millis} ms");
    assert!(millis < 2_000, "health took {millis} ms");
    drop(held);
}

#[test]
fn a_replayed_header_with_another_length_is_refused_before_the_body() {
    let tmp = tempfile::tempdir().expect("tmp");
    let lan = Lan::start(tmp.path(), master());
    let addr = lan.server.local_addr();
    let key = token_key(master());
    let account = account_for(master());
    let path = format!("/v1/objects/{account}/{}", "c".repeat(32));
    let header = auth_value(&*key, "PUT", &path, wall_clock(), b"abcd").expect("header");
    // the honest request works
    let mut honest = open_with_head(addr, &put_head(&path, &header, 4));
    honest.write_all(b"abcd").expect("body");
    assert_eq!(first_status(&mut honest, Duration::from_secs(5)).map(|a| a.0), Some(204));
    // the same header on a longer or shorter body is 401 at once, with no body sent at all
    for length in [5usize, 3, 1_000_000, 0] {
        let mut replay = open_with_head(addr, &put_head(&path, &header, length));
        let (status, took) = first_status(&mut replay, Duration::from_secs(2)).expect("an answer");
        assert_eq!(status, 401, "length {length}");
        assert!(took < Duration::from_secs(1), "length {length}: {took:?}");
    }
    assert_eq!(lan.folder_relay().get(path.trim_start_matches("/v1/objects/")).expect("object"), b"abcd");
}

#[test]
fn a_valid_header_whose_body_never_comes_times_out_and_never_blocks_others() {
    let tmp = tempfile::tempdir().expect("tmp");
    let folder = tmp.path().join("relay");
    let limits = Limits { idle: Duration::from_secs(1) };
    let server = LanServer::start_with("127.0.0.1:0", &folder, master(), silent(), limits).expect("serve");
    let addr = server.local_addr();
    let key = token_key(master());
    let account = account_for(master());
    let path = format!("/v1/objects/{account}/{}", "d".repeat(32));
    // a captured, still valid header (the pre-tag passes), then silence
    let header = auth_value_declaring(&*key, "PUT", &path, wall_clock(), 1_000_000, b"x");
    let header = header.expect("header");
    let started = Instant::now();
    let mut held: Vec<TcpStream> = (0..4)
        .map(|_| open_with_head(addr, &put_head(&path, &header, 1_000_000)))
        .collect();
    for stream in &mut held {
        let (status, _) = first_status(stream, Duration::from_secs(5)).expect("an answer");
        assert_eq!(status, 408);
    }
    let millis = health_millis(addr);
    println!(
        "F1 valid-pre stalls: 4 stalled connections, all answered 408 after {} ms, then health in {millis} ms",
        started.elapsed().as_millis()
    );
    assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
    assert!(millis < 2_000);
    assert!(!folder.join(&account).join("d".repeat(32)).exists(), "nothing was written");
    server.stop();
}

#[test]
fn a_trickled_body_runs_out_of_its_total_budget() {
    let tmp = tempfile::tempdir().expect("tmp");
    let folder = tmp.path().join("relay");
    let limits = Limits { idle: Duration::from_secs(1) };
    let server = LanServer::start_with("127.0.0.1:0", &folder, master(), silent(), limits).expect("serve");
    let key = token_key(master());
    let account = account_for(master());
    let path = format!("/v1/objects/{account}/{}", "e".repeat(32));
    let body = vec![7u8; 1000];
    let header = auth_value(&*key, "PUT", &path, wall_clock(), &body).expect("header");
    let mut stream = open_with_head(server.local_addr(), &put_head(&path, &header, 1000));
    let started = Instant::now();
    // one byte every 400 ms never trips the 1 s no-progress limit, only the total budget (1 s + 0)
    let mut answer = None;
    for byte in &body {
        std::thread::sleep(Duration::from_millis(400));
        if stream.write_all(&[*byte]).is_err() {
            break;
        }
        stream.set_read_timeout(Some(Duration::from_millis(1))).expect("timeout");
        let mut buf = [0u8; 64];
        if let Ok(count) = stream.read(&mut buf) {
            answer = String::from_utf8_lossy(&buf[..count]).split(' ').nth(1).map(str::to_string);
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(6), "never cut off");
    }
    println!("F1 trickle: answer {answer:?} after {:?}", started.elapsed());
    assert_eq!(answer.as_deref(), Some("408"));
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(!folder.join(&account).join("e".repeat(32)).exists());
    server.stop();
}

/// Raw exchange on a fresh connection: the status and the body (empty when there is no answer).
fn exchange(addr: std::net::SocketAddr, request: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let _ = stream.write_all(request);
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).to_string();
    let status = text.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = text.find("\r\n\r\n").map(|i| out[i + 4..].to_vec()).unwrap_or_default();
    (status, body)
}

#[test]
fn hostile_heads_and_paths_get_bare_refusals_and_a_slow_head_is_cut() {
    let tmp = tempfile::tempdir().expect("tmp");
    let folder = tmp.path().join("relay");
    fs::create_dir_all(&folder).expect("folder");
    fs::write(tmp.path().join("secret.txt"), b"outside").expect("secret");
    let limits = Limits { idle: Duration::from_secs(1) };
    let server = LanServer::start_with("127.0.0.1:0", &folder, master(), silent(), limits).expect("serve");
    let addr = server.local_addr();
    let key = token_key(master());
    let account = account_for(master());
    let now = wall_clock();
    // signed GETs on traversal-shaped paths: 400 or 404, never a body
    for path in [
        "/v1/objects/../secret.txt".to_string(),
        "/v1/objects/..%2fsecret.txt".to_string(),
        "/v1/objects/%2e%2e/secret.txt".to_string(),
        format!("/v1/objects/{account}/../../secret.txt"),
        format!("/v1/objects/{account}/%2e%2e%2f%2e%2e%2fsecret.txt"),
        format!("/v1/objects//{account}/{}", "a".repeat(32)),
        format!("/v1/objects/{account}/{}/x", "a".repeat(32)),
        format!("/v1/objects/{}/{}", account.to_uppercase(), "a".repeat(32)),
        "//etc/passwd".to_string(),
        "/v1/objects?x=1".to_string(),
    ] {
        let header = auth_value(&*key, "GET", &path, now, b"").expect("header");
        let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\n{AUTH_HEADER}: {header}\r\nConnection: close\r\n\r\n");
        let (status, body) = exchange(addr, request.as_bytes());
        assert!(matches!(status, 400 | 404), "{path}: {status}");
        assert!(body.is_empty(), "{path}");
    }
    // heads this server does not accept: a bare 400 (the method is not logged, nothing is read)
    let header = auth_value(&*key, "GET", "/v1/objects", now, b"").expect("header");
    for (label, request) in [
        ("absolute-form target", format!("GET http://evil/v1/objects HTTP/1.1\r\n{AUTH_HEADER}: {header}\r\n\r\n")),
        ("chunked upload", format!("PUT /v1/objects/{account}/{} HTTP/1.1\r\nTransfer-Encoding: chunked\r\n{AUTH_HEADER}: {header}\r\n\r\n", "a".repeat(32))),
        ("two lengths", format!("PUT /v1/objects/{account}/{} HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n{AUTH_HEADER}: {header}\r\n\r\n", "a".repeat(32))),
        ("a signed length", "PUT /v1/objects HTTP/1.1\r\nContent-Length: +5\r\n\r\n".to_string()),
        ("a folded header", "GET /v1/health HTTP/1.1\r\nX-A: b\r\n  folded\r\n\r\n".to_string()),
        ("two auth headers", format!("GET /v1/objects HTTP/1.1\r\n{AUTH_HEADER}: {header}\r\n{AUTH_HEADER}: {header}\r\n\r\n")),
        ("an unknown version", "GET /v1/health HTTP/2.0\r\n\r\n".to_string()),
        ("a lower-case method", "get /v1/health HTTP/1.1\r\n\r\n".to_string()),
        ("an oversized head", format!("GET /v1/health HTTP/1.1\r\nX-Pad: {}\r\n\r\n", "a".repeat(40_000))),
    ] {
        let (status, body) = exchange(addr, request.as_bytes());
        assert_eq!((status, body.is_empty()), (400, true), "{label}");
    }
    // lower-case header names and a plain HTTP/1.0 request are fine
    let lower = format!("GET /v1/objects HTTP/1.0\r\n{}: {header}\r\n\r\n", AUTH_HEADER.to_lowercase());
    assert_eq!(exchange(addr, lower.as_bytes()).0, 200);
    // health says nothing about the host
    let (status, body) = exchange(addr, b"GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert_eq!((status, body.as_slice()), (200, &br#"{"product":"DISCOnect","relay":"lan","v":1}"#[..]));
    // half a head, then silence: the connection is cut after the idle limit, others are served meanwhile
    let mut slow = TcpStream::connect(addr).expect("connect");
    slow.write_all(b"GET /v1/health HTTP/1.1\r\nHost: ").expect("partial");
    let started = Instant::now();
    assert!(health_millis(addr) < 500, "health is served while a head is half sent");
    let answer = first_status(&mut slow, Duration::from_secs(4));
    println!("F1 half head: {answer:?} after {:?}", started.elapsed());
    assert_eq!(answer.map(|a| a.0), Some(408));
    assert!(started.elapsed() < Duration::from_secs(3));
    // a client that connects and says nothing is closed without an answer
    let mut mute = TcpStream::connect(addr).expect("connect");
    assert_eq!(first_status(&mut mute, Duration::from_secs(4)), None);
    server.stop();
}

#[test]
fn a_head_the_server_cannot_read_gets_a_bare_400_with_no_response_tag() {
    let tmp = tempfile::tempdir().expect("tmp");
    let server = LanServer::start("127.0.0.1:0", tmp.path().join("relay"), master(), silent()).expect("serve");
    let mut stream = TcpStream::connect(server.local_addr()).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    stream.write_all(b"get /v1/objects HTTP/1.1\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).to_ascii_lowercase();
    assert!(text.starts_with("http/1.1 400"), "{text}");
    assert!(!text.contains(&RESP_HEADER.to_ascii_lowercase()), "{text}");
    server.stop();
}

// ------------------------------------------------------------------ 12-RA: response authentication

/// What a fake server or a proxy sees of a request.
#[derive(Clone)]
struct Req {
    method: String,
    target: String,
    auth: String,
    raw: Vec<u8>,
}

/// Read one request (head and a declared body) off a connection.
fn read_request(stream: &mut TcpStream) -> Option<Req> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let end = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&raw[..end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_string(), first.next()?.to_string());
    let (mut auth, mut length) = (String::new(), 0usize);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        if name.eq_ignore_ascii_case(AUTH_HEADER) {
            auth = value.trim().to_string();
        } else if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    while raw.len() < end + length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    Some(Req { method, target, auth, raw })
}

/// A server thread: one request per connection, the answer is whatever `answer` returns (raw bytes).
struct Fake {
    addr: std::net::SocketAddr,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Fake {
    fn start(answer: impl Fn(&Req) -> Vec<u8> + Send + 'static) -> Fake {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).expect("blocking");
                if let Some(request) = read_request(&mut stream) {
                    let _ = stream.write_all(&answer(&request));
                }
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        });
        Fake { addr, stop, thread: Some(thread) }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A raw answer: status, body and any number of `X-Disconect-Resp` lines.
fn raw_answer(status: u16, body: &[u8], resp: &[String]) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n");
    for value in resp {
        head.push_str(&format!("{RESP_HEADER}: {value}\r\n"));
    }
    if status != 204 {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

fn tag_for(key: &[u8], req: &Req, status: u16, body: &[u8]) -> String {
    resp_header_value(key, &req.method, &req.target, &req.auth, wall_clock(), status, body).expect("tag")
}

fn list_of(url: &str) -> Result<Vec<String>, RelayError> {
    LanRelay::new(url, master()).expect("client").list(&account_for(master()))
}

#[test]
fn an_answer_without_a_valid_tag_is_unverified_and_a_tagged_401_is_the_clock() {
    let key = token_key(master());
    let other = token_key(&other_master());
    let k: Vec<u8> = key.to_vec();
    let o: Vec<u8> = other.to_vec();
    type Make = Box<dyn Fn(&Req) -> Vec<u8> + Send>;
    let cases: Vec<(&str, Make, bool)> = vec![
        ("tagged, correct", Box::new({ let k = k.clone(); move |r| raw_answer(200, b"[]", &[tag_for(&k, r, 200, b"[]")]) }), true),
        ("no header", Box::new(|_| raw_answer(200, b"[]", &[])), false),
        ("two headers", Box::new({ let k = k.clone(); move |r| { let t = tag_for(&k, r, 200, b"[]"); raw_answer(200, b"[]", &[t.clone(), t]) } }), false),
        ("malformed header", Box::new(|_| raw_answer(200, b"[]", &["v1.1.zz".to_string()])), false),
        ("tag of another status", Box::new({ let k = k.clone(); move |r| raw_answer(200, b"[]", &[tag_for(&k, r, 204, b"[]")]) }), false),
        ("tag of another body", Box::new({ let k = k.clone(); move |r| raw_answer(200, b"[]", &[tag_for(&k, r, 200, b"[ ]")]) }), false),
        ("tag under another key", Box::new({ let o = o.clone(); move |r| raw_answer(200, b"[]", &[tag_for(&o, r, 200, b"[]")]) }), false),
        ("answer A's tag on request B", Box::new({ let k = k.clone(); move |r| {
            let a = Req { auth: auth_value(&k, "GET", "/v1/objects", 1_000, b"").expect("auth"), ..r.clone() };
            raw_answer(200, b"[]", &[tag_for(&k, &a, 200, b"[]")]) } }), false),
        ("tag of another target", Box::new({ let k = k.clone(); move |r| {
            let a = Req { target: format!("{}?x", r.target), ..r.clone() };
            raw_answer(200, b"[]", &[tag_for(&k, &a, 200, b"[]")]) } }), false),
    ];
    for (label, make, ok) in cases {
        let fake = Fake::start(make);
        let outcome = list_of(&fake.url());
        if ok {
            assert_eq!(outcome.expect(label), Vec::<String>::new(), "{label}");
        } else {
            assert!(matches!(outcome, Err(RelayError::Unverified)), "{label}: {outcome:?}");
        }
    }
    // a 401 with a valid tag: the relay holds this key and refused the request (clocks)
    // 10 minutes off (either way) is the clock; within the skew window a verified 401 is the lure
    for (offset, skew) in [(600i64, -600i64), (-600, 600)] {
        let tagged = Fake::start({
            let k = k.clone();
            move |r| {
                let secs = (wall_clock() as i64 + offset) as u64;
                let t = resp_header_value(&k, &r.method, &r.target, &r.auth, secs, 401, b"").expect("tag");
                raw_answer(401, b"", &[t])
            }
        });
        let outcome = list_of(&tagged.url());
        match outcome {
            Err(RelayError::Unauthorized { skew_s }) => {
                assert!((skew_s - skew).abs() <= 3, "{skew_s} vs {skew}");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }
    let within = Fake::start({ let k = k.clone(); move |r| raw_answer(401, b"", &[tag_for(&k, r, 401, b"")]) });
    let outcome = list_of(&within.url());
    assert!(matches!(outcome, Err(RelayError::Unverified)), "within the skew: {outcome:?}");
    // the same 401 without a tag, or with a wrong one: only Unverified, never "re-pair" or "clock"
    let bare = Fake::start(|_| raw_answer(401, b"", &[]));
    assert!(matches!(list_of(&bare.url()), Err(RelayError::Unverified)));
    let wrong = Fake::start({ let o = o.clone(); move |r| raw_answer(401, b"", &[tag_for(&o, r, 401, b"")]) });
    assert!(matches!(list_of(&wrong.url()), Err(RelayError::Unverified)));
}

fn unsent(device: &Device) -> i64 {
    count(
        device.conn(),
        "SELECT count(*) FROM raw_records r LEFT JOIN relay_seen s ON s.raw_record_id=r.id WHERE s.raw_record_id IS NULL",
    )
}

fn next_seq(device: &Device) -> i64 {
    count(device.conn(), "SELECT coalesce((SELECT next_seq FROM relay_device WHERE id=1), 1)")
}

fn nothing_booked(device: &Device, seq_before: i64) {
    assert_eq!(count(device.conn(), "SELECT count(*) FROM relay_bundles"), 0);
    assert_eq!(count(device.conn(), "SELECT count(*) FROM relay_seen"), 0);
    assert_eq!(count(device.conn(), "SELECT count(*) FROM relay_seen_ranges"), 0);
    assert_eq!(next_seq(device), seq_before, "no sequence number consumed");
}

#[test]
fn a_fake_server_answering_204_to_everything_books_nothing() {
    let tmp = tempfile::tempdir().expect("tmp");
    let fake = Fake::start(|_| raw_answer(204, b"", &[]));
    let a = device();
    import_path(a.conn(), &fit_drop(tmp.path(), "fits", &MONITORING), None, None).expect("import");
    let before = unsent(&a);
    let seq = next_seq(&a);
    assert!(before > 0);
    let client = LanRelay::new(&fake.url(), master()).expect("client");
    let error = sync::push(a.conn(), master(), &client).expect_err("unverified");
    assert!(matches!(error, SyncError::Relay(RelayError::Unverified)), "{error}");
    nothing_booked(&a, seq);
    assert_eq!(unsent(&a), before, "every record is still unsent");
    let b = device();
    let pull = sync::pull(b.conn(), master(), &client).expect_err("unverified");
    assert!(matches!(pull, SyncError::Relay(RelayError::Unverified)), "{pull}");
    assert_eq!(count(b.conn(), "SELECT count(*) FROM relay_bundles"), 0);
}

/// A proxy between a client and a real server (one request per connection): `rewrite` gets the
/// server's whole answer (head and body) and returns what the client is shown.
fn proxy(upstream: std::net::SocketAddr, rewrite: impl Fn(&Req, Vec<u8>) -> Vec<u8> + Send + 'static) -> Fake {
    proxy_hops(upstream, |request| Hop::Forward(request.raw.clone()), rewrite)
}

/// What a proxy does with a request: send these bytes upstream, or answer without asking.
enum Hop {
    Forward(Vec<u8>),
    Answer(Vec<u8>),
}

/// A proxy that may also rewrite the request (`edit`) or answer it itself.
fn proxy_hops(
    upstream: std::net::SocketAddr,
    edit: impl Fn(&Req) -> Hop + Send + 'static,
    rewrite: impl Fn(&Req, Vec<u8>) -> Vec<u8> + Send + 'static,
) -> Fake {
    Fake::start(move |request| {
        let forwarded = match edit(request) {
            Hop::Answer(bytes) => return bytes,
            Hop::Forward(bytes) => bytes,
        };
        let mut up = TcpStream::connect(upstream).expect("upstream");
        up.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
        up.write_all(&forwarded).expect("forward");
        let mut answer = Vec::new();
        let _ = up.read_to_end(&mut answer);
        rewrite(request, answer)
    })
}

fn split_answer(answer: &[u8]) -> (String, Vec<u8>) {
    let end = answer.windows(4).position(|w| w == b"\r\n\r\n").expect("head end");
    (String::from_utf8_lossy(&answer[..end]).to_string(), answer[end + 4..].to_vec())
}

fn without_resp_header(head: &str) -> String {
    head.split("\r\n")
        .filter(|line| !line.to_ascii_lowercase().starts_with(&RESP_HEADER.to_ascii_lowercase()))
        .collect::<Vec<_>>()
        .join("\r\n")
}

#[test]
fn a_proxy_that_rewrites_the_list_makes_a_pull_unverified_and_books_nothing() {
    let tmp = tempfile::tempdir().expect("tmp");
    let lan = Lan::start(tmp.path(), master());
    let a = device();
    import_path(a.conn(), &fit_drop(tmp.path(), "fits", &MONITORING), None, None).expect("import");
    sync::push(a.conn(), master(), &lan.client(master())).expect("push");
    // the list answer becomes `[]` with a corrected Content-Length: the status stays 200, so only
    // the tag can notice (a wrong length would end in `Unreachable` for the wrong reason)
    let evil = proxy(lan.server.local_addr(), |request, answer| {
        if request.target != "/v1/objects" {
            return answer;
        }
        let (head, _) = split_answer(&answer);
        let head = head
            .split("\r\n")
            .map(|line| {
                if line.to_ascii_lowercase().starts_with("content-length") {
                    "Content-Length: 2".to_string()
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\r\n");
        let mut out = format!("{head}\r\n\r\n").into_bytes();
        out.extend_from_slice(b"[]");
        out
    });
    let b = device();
    let client = LanRelay::new(&evil.url(), master()).expect("client");
    let error = sync::pull(b.conn(), master(), &client).expect_err("unverified");
    assert!(matches!(error, SyncError::Relay(RelayError::Unverified)), "{error}");
    assert_eq!(count(b.conn(), "SELECT count(*) FROM relay_bundles"), 0, "no row, not even rejected");
    assert_eq!(count(b.conn(), "SELECT count(*) FROM raw_records"), 0);
    // the straight way still works
    assert_eq!(sync::pull(b.conn(), master(), &lan.client(master())).expect("pull").status, "ok");
    assert_eq!(fingerprint(&a), fingerprint(&b));
    lan.server.stop();
}

#[test]
fn a_proxy_that_strips_the_tag_books_nothing_and_the_retry_converges_without_a_gap() {
    let tmp = tempfile::tempdir().expect("tmp");
    let lan = Lan::start(tmp.path(), master());
    let a = device();
    import_path(a.conn(), &fit_drop(tmp.path(), "fits", &MONITORING), None, None).expect("import");
    let strip = proxy(lan.server.local_addr(), |_, answer| {
        let (head, body) = split_answer(&answer);
        let mut out = format!("{}\r\n\r\n", without_resp_header(&head)).into_bytes();
        out.extend_from_slice(&body);
        out
    });
    let before = unsent(&a);
    let seq = next_seq(&a);
    let blind = LanRelay::new(&strip.url(), master()).expect("client");
    let error = sync::push(a.conn(), master(), &blind).expect_err("unverified");
    assert!(matches!(error, SyncError::Relay(RelayError::Unverified)), "{error}");
    nothing_booked(&a, seq);
    assert_eq!(unsent(&a), before);
    // the PUT did land on the real server (an unverified PUT may have): the retry pushes the same
    // records again as a second bundle
    let account = account_for(master());
    assert_eq!(lan.folder_relay().list(&account).expect("list").len(), 1, "the unverified PUT landed");
    let retried = sync::push(a.conn(), master(), &lan.client(master())).expect("retry");
    assert_eq!(retried.bundles.len(), 1);
    assert_eq!(lan.folder_relay().list(&account).expect("list").len(), 2, "a duplicate bundle");
    // a second store pulls both and de-duplicates: the same content as A, no gap
    let b = device();
    let pulled = sync::pull(b.conn(), master(), &lan.client(master())).expect("pull");
    assert_eq!(pulled.status, "ok");
    assert_eq!(fingerprint(&a), fingerprint(&b), "fingerprints converge");
    assert!(sync::gaps(b.conn()).expect("gaps").is_empty(), "no gap");
    lan.server.stop();
}

/// The three transplants of the attack record (row 7): each ends in `Unverified`, no row, and the
/// straight pull afterwards applies the bundle.
fn pull_through_forger(forger: impl Fn(std::net::SocketAddr) -> Fake) {
    let tmp = tempfile::tempdir().expect("tmp");
    let lan = Lan::start(tmp.path(), master());
    let a = device();
    import_path(a.conn(), &fit_drop(tmp.path(), "fits", &MONITORING), None, None).expect("import");
    sync::push(a.conn(), master(), &lan.client(master())).expect("push");
    let evil = forger(lan.server.local_addr());
    let b = device();
    let client = LanRelay::new(&evil.url(), master()).expect("client");
    let error = sync::pull(b.conn(), master(), &client).expect_err("unverified");
    assert!(matches!(error, SyncError::Relay(RelayError::Unverified)), "{error}");
    assert_eq!(count(b.conn(), "SELECT count(*) FROM relay_bundles"), 0, "no row, not even rejected");
    assert_eq!(count(b.conn(), "SELECT count(*) FROM raw_records"), 0);
    assert_eq!(sync::pull(b.conn(), master(), &lan.client(master())).expect("pull").status, "ok");
    assert_eq!(fingerprint(&a), fingerprint(&b));
    lan.server.stop();
}

#[test]
fn a_proxy_that_rewrites_the_object_target_cannot_make_a_pull_reject_the_bundle() {
    pull_through_forger(|upstream| {
        proxy_hops(
            upstream,
            |request| {
                if !request.target.starts_with("/v1/objects/") {
                    return Hop::Forward(request.raw.clone());
                }
                let text = String::from_utf8_lossy(&request.raw).to_string();
                let line_end = text.find("\r\n").expect("line");
                let line = text[..line_end].replacen(&request.target, &format!("{}?x", request.target), 1);
                Hop::Forward(format!("{line}{}", &text[line_end..]).into_bytes())
            },
            |_, answer| answer,
        )
    });
}

#[test]
fn a_proxy_that_answers_object_reads_with_a_bare_404_cannot_make_a_pull_reject_the_bundle() {
    pull_through_forger(|upstream| {
        proxy_hops(
            upstream,
            |request| {
                if request.target.starts_with("/v1/objects/") {
                    Hop::Answer(raw_answer(404, b"", &[]))
                } else {
                    Hop::Forward(request.raw.clone())
                }
            },
            |_, answer| answer,
        )
    });
}

#[test]
fn a_proxy_that_adds_a_body_to_the_list_request_gets_a_real_401_that_stays_unverified() {
    // the real server refuses (tagged 401, within the skew window): a re-pair lure, never "the clock"
    pull_through_forger(|upstream| {
        proxy_hops(
            upstream,
            |request| {
                if request.target != "/v1/objects" {
                    return Hop::Forward(request.raw.clone());
                }
                let text = String::from_utf8_lossy(&request.raw).to_string();
                let line_end = text.find("\r\n").expect("line");
                let mut out = format!("{}\r\nContent-Length: 5{}", &text[..line_end], &text[line_end..]).into_bytes();
                out.extend_from_slice(b"hello");
                Hop::Forward(out)
            },
            |_, answer| answer,
        )
    });
}
