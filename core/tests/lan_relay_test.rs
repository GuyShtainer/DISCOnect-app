// SPDX-License-Identifier: AGPL-3.0-or-later
//! The LAN relay (Bet 12, slice B) end to end on 127.0.0.1: a `LanRelay` client against the real
//! HTTP server (in process and as the `relay-serve` binary), through real stores. Synthetic data
//! and the committed test key only; every listener binds 127.0.0.1.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, OnceLock};

use common::{PASSPHRASE, encrypted_copy, fixtures};
use disconect_core::keys::{self, PassphraseSource};
use disconect_core::relay::bundle::account_for;
use disconect_core::relay::folder::{FolderRelay, Relay, RelayError};
use disconect_core::relay::lan::{AUTH_HEADER, LanRelay, auth_value, token_key, wall_clock};
use disconect_core::relay::lan_server::{LanServer, Logger};
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

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).expect("count")
}

fn fit_drop(dir: &Path, name: &str, stems: &[&str]) -> PathBuf {
    let target = dir.join(name);
    fs::create_dir_all(&target).expect("mkdir");
    for stem in stems {
        fs::copy(
            fixtures().join("synthetic").join(format!("{stem}.fit.bin")),
            target.join(format!("{stem}.fit")),
        )
        .expect("copy fixture");
    }
    target
}

fn export_with_uds(dir: &Path, name: &str, day: &str, steps: i64) -> PathBuf {
    let root = dir.join(name);
    let path = root.join(format!(
        "DI_CONNECT/DI-Connect-Aggregator/UDSFile_{day}_{day}.json"
    ));
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(
        path,
        format!(
            r#"[{{"calendarDate":"{day}","totalSteps":{steps},"wellnessEndTimeGmt":"{day}T12:00:00.0","wellnessStartTimeGmt":"{day}T00:00:00.0"}}]"#
        ),
    )
    .expect("write");
    fs::create_dir_all(root.join("DI_CONNECT/DI-Connect-Uploaded-Files")).expect("mkdir");
    root
}

const MONITORING: [&str; 2] = ["monitoring_timestamp16", "monitoring_cycles_resolution"];

type Fingerprint = (BTreeSet<String>, BTreeSet<String>, Vec<i64>);

/// Raw keys and bytes, ranges and table counts: what a second device must reproduce.
fn fingerprint(device: &Device) -> Fingerprint {
    let conn = device.conn();
    let collect = |sql: &str| -> BTreeSet<String> {
        let mut stmt = conn.prepare(sql).expect("prepare");
        stmt.query_map([], |r| r.get(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    };
    let raw = collect(
        "SELECT stream || '|' || source_key || '|' || payload_hash || '|' || transport || '|' || imported_at FROM raw_records",
    );
    let ranges = collect("SELECT stream || '|' || from_day || '|' || to_day FROM export_ranges");
    let counts = [
        "SELECT count(*) FROM daily_metrics",
        "SELECT count(*) FROM daily_labels",
        "SELECT count(*) FROM metric_samples",
        "SELECT count(*) FROM monitoring_intervals",
        "SELECT count(*) FROM clock_offsets",
    ]
    .map(|sql| count(conn, sql))
    .to_vec();
    (raw, ranges, counts)
}

fn daily_rows(device: &Device) -> BTreeSet<String> {
    let mut stmt = device
        .conn()
        .prepare(
            "SELECT 'm|' || date || '|' || metric || '|' || source_scope || '|' || value || '|' || COALESCE(observed_utc, '') \
             FROM daily_metrics UNION ALL \
             SELECT 'l|' || date || '|' || metric || '|' || source_scope || '|' || label || '|' || COALESCE(observed_utc, '') \
             FROM daily_labels",
        )
        .expect("prepare");
    stmt.query_map([], |r| r.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
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
    let error = stranger
        .list(&account_for(&other_master()))
        .expect_err("401");
    assert!(matches!(error, RelayError::Unauthorized), "{error}");
    assert_eq!(error.reason(), "authentication_failed");
    assert!(error.to_string().starts_with("authentication_failed"));

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
    // the stranger's master packs under its own account; the server refuses the token first
    let refused = sync::push(a.conn(), &other_master(), &stranger).expect_err("refused");
    assert!(
        matches!(refused, SyncError::Relay(RelayError::Unauthorized)),
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
        "pulled 1 bundle(s): 2 new, 0 duplicate, 0 invalid, 0 conflict(s), 0 new range(s); rejected 0; gaps 0"
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
