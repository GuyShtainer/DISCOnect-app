// SPDX-License-Identifier: AGPL-3.0-or-later
//! `disconect-core sync push|pull|status|forget` end to end through the binary: the shared relay
//! config, exit codes and output lines, on scratch encrypted stores with synthetic FIT data.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{PASSPHRASE, encrypted_copy, fixtures};
use serde_json::Value;

struct Cli {
    home: PathBuf,
    pass: PathBuf,
}

impl Cli {
    fn new(dir: &Path) -> Cli {
        let pass = dir.join("pass.txt");
        std::fs::write(&pass, format!("{PASSPHRASE}\n")).expect("passphrase file");
        let home = dir.join("home");
        std::fs::create_dir_all(&home).expect("home");
        Cli { home, pass }
    }

    fn run(&self, db: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_disconect-core"))
            .env("HOME", &self.home)
            .env_remove("DISCONECT_PASSPHRASE")
            .arg("--db")
            .arg(db)
            .arg("--passphrase-file")
            .arg(&self.pass)
            .args(args)
            .output()
            .expect("run the binary")
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn drop_folder(dir: &Path) -> PathBuf {
    let target = dir.join("drop");
    std::fs::create_dir_all(&target).expect("mkdir");
    for stem in ["monitoring_timestamp16", "monitoring_cycles_resolution"] {
        std::fs::copy(
            fixtures().join("synthetic").join(format!("{stem}.fit.bin")),
            target.join(format!("{stem}.fit")),
        )
        .expect("copy");
    }
    target
}

#[test]
fn push_pull_status_forget_through_the_binary_and_the_shared_config() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cli = Cli::new(tmp.path());
    let (_da, a) = encrypted_copy();
    let (_db, b) = encrypted_copy();
    let drop = drop_folder(tmp.path());
    let imported = cli.run(&a, &["import", drop.to_str().expect("utf8")]);
    assert_eq!(code(&imported), 0);
    let relay = tmp.path().join("relay folder");
    let relay_arg = relay.to_str().expect("utf8");

    // no folder anywhere: usage
    let missing = cli.run(&a, &["sync", "push"]);
    assert_eq!(code(&missing), 2);

    let pushed = cli.run(&a, &["sync", "push", "--relay", relay_arg, "--remember"]);
    assert_eq!(
        code(&pushed),
        0,
        "{}",
        String::from_utf8_lossy(&pushed.stderr)
    );
    assert!(
        stdout(&pushed).starts_with("pushed 1 bundle(s): 2 record(s), 0 range(s)"),
        "{}",
        stdout(&pushed)
    );
    // `--remember` writes the list form: one serving folder entry with a new 8-hex id
    let remembered = disconect_core::relay::config::read_list(&cli.home.join(".disconect/relay.json")).expect("list");
    assert_eq!(remembered.len(), 1);
    assert_eq!(remembered[0].config, disconect_core::relay::config::RelayConfig::Folder(relay_arg.to_string()));
    assert!(remembered[0].serve);
    assert_eq!(remembered[0].id.len(), 8);

    // B pulls through the remembered folder
    let pulled = cli.run(&b, &["sync", "pull"]);
    assert_eq!(
        code(&pulled),
        0,
        "{}",
        String::from_utf8_lossy(&pulled.stderr)
    );
    assert_eq!(
        stdout(&pulled).trim(),
        "pulled 1 bundle(s): 2 new, 0 duplicate, 0 invalid, 0 conflict(s), 0 new range(s); rejected 0; gaps 0; repaired 0; kept for a later decoder 0"
    );
    let again = cli.run(&b, &["sync", "pull"]);
    assert_eq!(code(&again), 0);
    assert!(stdout(&again).starts_with("pulled 0 bundle(s): 0 new"));
    // nothing echoes
    let echo = cli.run(&b, &["sync", "push"]);
    assert!(stdout(&echo).starts_with("pushed 0 bundle(s): 0 record(s), 0 range(s)"));

    let status = cli.run(&b, &["sync", "status"]);
    assert_eq!(code(&status), 0);
    let line = stdout(&status).trim().to_string();
    assert!(line.starts_with(
        "relay: pushed 0, pulled 1, rejected 0; records unsent 0, seen 2; conflicts 0; gaps 0; chains 1; last push never, last pull 20"
    ));
    assert!(line.ends_with('Z'));
    let report: Value =
        serde_json::from_str(&stdout(&cli.run(&b, &["--json", "sync", "status"]))).expect("json");
    assert_eq!(report["bundles"]["pulled_applied"], 1);
    assert_eq!(report["records_unsent"], 0);
    assert_eq!(report["gaps"], Value::Array(Vec::new()));
    // 19b: A's chain, counts only, not this store's own
    let chains = report["chains"].as_array().expect("chains");
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0]["bundles"], 1);
    assert_eq!(chains[0]["records"], 2);
    assert_eq!(chains[0]["last_seq"], 1);
    assert_eq!(chains[0]["self"], false);

    // a rejected object makes the pull partial: exit 1, and the line says so
    let account = std::fs::read_dir(&relay)
        .expect("account folder")
        .next()
        .expect("one")
        .expect("entry")
        .path();
    let mut noise = vec![0x55u8; 70_000];
    noise[0] = 1;
    std::fs::write(account.join("f".repeat(32)), noise).expect("stray object");
    let partial = cli.run(&b, &["sync", "pull"]);
    assert_eq!(code(&partial), 1);
    assert!(
        stdout(&partial).trim().ends_with("rejected 1; gaps 0; repaired 0; kept for a later decoder 0"),
        "{}",
        stdout(&partial)
    );

    let forgotten = cli.run(&b, &["sync", "forget"]);
    assert_eq!(code(&forgotten), 0);
    assert_eq!(
        stdout(&forgotten).trim(),
        "relay bookkeeping cleared: the next 'sync push' publishes everything again"
    );
    let republished = cli.run(&b, &["sync", "push"]);
    assert!(stdout(&republished).starts_with("pushed 1 bundle(s): 2 record(s)"));
}

#[test]
fn a_store_with_no_key_file_cannot_sync_and_a_missing_passphrase_is_locked() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cli = Cli::new(tmp.path());
    // a plaintext store: init creates it, no key file beside it
    let plain = tmp.path().join("plain.db");
    assert_eq!(code(&cli.run(&plain, &["init"])), 0);
    let relay = tmp.path().join("relay");
    let relay_arg = relay.to_str().expect("utf8");
    for action in ["push", "pull"] {
        let out = cli.run(&plain, &["sync", action, "--relay", relay_arg]);
        assert_eq!(code(&out), 9, "{action}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("the relay needs an encrypted store")
        );
    }
    // status and forget need no key and work on any store
    assert_eq!(code(&cli.run(&plain, &["sync", "status"])), 0);
    assert_eq!(code(&cli.run(&plain, &["sync", "forget"])), 0);
    // an encrypted store with no passphrase source: locked, exit 9
    let (_dir, db) = encrypted_copy();
    let locked = Command::new(env!("CARGO_BIN_EXE_disconect-core"))
        .env("HOME", &cli.home)
        .env_remove("DISCONECT_PASSPHRASE")
        .args(["--db"])
        .arg(&db)
        .args(["sync", "push", "--relay", relay_arg])
        .output()
        .expect("run");
    assert_eq!(code(&locked), 9);
    // an unknown action is refused by the parser (exit 1, like every parse error)
    let bad = cli.run(&db, &["sync", "sideways"]);
    assert_eq!(code(&bad), 1);
}

fn table_count(status: &Output, table: &str) -> i64 {
    let value: Value = serde_json::from_slice(&status.stdout).expect("status json");
    value["tables"][table].as_i64().expect("table count")
}

#[test]
fn reparse_through_the_binary_changes_no_row_and_books_a_reparse_run() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cli = Cli::new(tmp.path());
    let (_dir, db) = encrypted_copy();
    let drop = drop_folder(tmp.path());
    assert_eq!(
        code(&cli.run(&db, &["import", drop.to_str().expect("utf8")])),
        0
    );
    let before = cli.run(&db, &["--json", "status"]);
    let (daily, samples, intervals) = (
        table_count(&before, "daily_metrics"),
        table_count(&before, "metric_samples"),
        table_count(&before, "monitoring_intervals"),
    );
    assert!(daily + samples + intervals > 0, "something to replay");
    let runs = table_count(&before, "import_runs");

    let out = cli.run(&db, &["--json", "reparse"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    let stats: Value = serde_json::from_slice(&out.stdout).expect("reparse json");
    assert_eq!(stats["status"], "ok");
    assert_eq!(stats["transport"], "reparse");
    assert_eq!(stats["files_seen"], 2);
    assert_eq!(stats["files_failed"], 0);
    let keys: Vec<&str> = stats
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "dates_assumed_utc",
            "derived_days",
            "dropped",
            "failures",
            "files_duplicate",
            "files_failed",
            "files_imported",
            "files_seen",
            "ignored",
            "records_written",
            "status",
            "streams",
            "transport",
            "warnings"
        ],
        "the Python `reparse --json` keys"
    );
    let after = cli.run(&db, &["--json", "status"]);
    assert_eq!(table_count(&after, "daily_metrics"), daily);
    assert_eq!(table_count(&after, "metric_samples"), samples);
    assert_eq!(table_count(&after, "monitoring_intervals"), intervals);
    assert_eq!(
        table_count(&after, "import_runs"),
        runs + 1,
        "one reparse run row"
    );

    // --stream limits the replay; an unknown stream replays nothing and is still ok
    let none = cli.run(&db, &["--json", "reparse", "--stream", "fit:nothing"]);
    assert_eq!(code(&none), 0);
    let none: Value = serde_json::from_slice(&none.stdout).expect("json");
    assert_eq!(none["files_seen"], 0);
    // the text form is the import summary
    let text = cli.run(&db, &["reparse", "--force"]);
    assert_eq!(code(&text), 0);
    assert!(stdout(&text).starts_with("ok: "), "{}", stdout(&text));
}

#[test]
fn reparse_on_a_busy_store_exits_four() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cli = Cli::new(tmp.path());
    let (_dir, db) = encrypted_copy();
    let secret = disconect_core::keys::unlock(
        &disconect_core::keys::key_path_for(&db),
        disconect_core::keys::PassphraseSource::Explicit(PASSPHRASE),
    )
    .expect("unlock");
    let held = disconect_core::store::open_for_write_with(&db, "hold", 1.0, Some(&secret))
        .expect("hold the write lock");
    let busy = cli.run(&db, &["reparse"]);
    assert_eq!(code(&busy), 4, "{}", String::from_utf8_lossy(&busy.stderr));
    drop(held);
    assert_eq!(code(&cli.run(&db, &["reparse"])), 0);
}

#[test]
fn reparse_json_failures_carry_the_records_stream() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cli = Cli::new(tmp.path());
    let (_dir, db) = encrypted_copy();
    let drop = drop_folder(tmp.path());
    assert_eq!(code(&cli.run(&db, &["import", drop.to_str().expect("utf8")])), 0);
    // one retained FIT record turns into bytes the decoder rejects; the dry run refuses the reparse
    let key = disconect_core::keys::unlock(
        &disconect_core::keys::key_path_for(&db),
        disconect_core::keys::PassphraseSource::Explicit(PASSPHRASE),
    )
    .expect("unlock");
    let store = disconect_core::store::open_for_write_with(&db, "test", 5.0, Some(&key)).expect("open");
    let mut junk = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut junk, b"this is not a FIT file").expect("deflate");
    store
        .conn()
        .execute(
            "UPDATE raw_records SET payload=? WHERE id=(SELECT min(id) FROM raw_records WHERE payload_kind='fit')",
            [junk.finish().expect("finish")],
        )
        .expect("corrupt");
    let stream: String = store
        .conn()
        .query_row("SELECT stream FROM raw_records WHERE payload_kind='fit' ORDER BY id LIMIT 1", [], |r| r.get(0))
        .expect("stream");
    std::mem::drop(store);
    let out = cli.run(&db, &["--json", "reparse"]);
    assert_eq!(code(&out), 1, "{}", String::from_utf8_lossy(&out.stderr));
    let stats: Value = serde_json::from_slice(&out.stdout).expect("json");
    let failures = stats["failures"].as_array().expect("failures");
    assert_eq!(failures.len(), 1);
    let keys: Vec<&str> = failures[0].as_object().expect("object").keys().map(String::as_str).collect();
    assert_eq!(keys, ["error", "file", "kind", "stream"], "Python's `_dry_run` failure keys");
    assert_eq!(failures[0]["stream"], stream.as_str());
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn sync_relay_add_remove_list_and_a_run_over_the_whole_list() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cli = Cli::new(tmp.path());
    let (_da, a) = encrypted_copy();
    let (_db, b) = encrypted_copy();
    let (s1, s2, s3) = (tmp.path().join("s1"), tmp.path().join("s2"), tmp.path().join("s3"));
    std::fs::create_dir_all(&s2).expect("mkdir");
    std::fs::create_dir_all(&s3).expect("mkdir");
    let (p1, p2, p3) = (s1.to_str().expect("utf8"), s2.to_str().expect("utf8"), s3.to_str().expect("utf8"));

    let none = cli.run(&a, &["sync", "relay", "list"]);
    assert_eq!((code(&none), stdout(&none).trim()), (0, ""));
    assert_eq!(code(&cli.run(&a, &["sync", "relay", "add", p1, "--serve"])), 0);
    assert_eq!(code(&cli.run(&a, &["sync", "relay", "add", p2, "--label", "cloud"])), 0);
    // refusals: the same relay twice (by folder), a second server, a serving address, an unknown id
    let again = cli.run(&a, &["sync", "relay", "add", p2]);
    assert_eq!(code(&again), 2);
    assert!(stderr(&again).contains("that relay is already in the list"), "{}", stderr(&again));
    let second = cli.run(&a, &["sync", "relay", "add", p3, "--serve"]);
    assert_eq!(code(&second), 2);
    assert!(stderr(&second).contains("only one relay can serve"), "{}", stderr(&second));
    assert_eq!(code(&cli.run(&a, &["sync", "relay", "add", "http://127.0.0.1:9", "--serve"])), 2);
    let unknown = cli.run(&a, &["sync", "relay", "remove", "ffffffff"]);
    assert_eq!(code(&unknown), 2);
    assert!(stderr(&unknown).contains("no relay with that id"), "{}", stderr(&unknown));

    let listed: Value = serde_json::from_str(&stdout(&cli.run(&a, &["--json", "sync", "relay", "list"]))).expect("json");
    let relays = listed["relays"].as_array().expect("relays");
    assert_eq!(relays.len(), 2);
    assert_eq!((relays[0]["path"].as_str(), relays[0]["serve"].as_bool()), (Some(p1), Some(true)));
    assert_eq!((relays[1]["path"].as_str(), relays[1]["label"].as_str(), relays[1]["serve"].as_bool()), (Some(p2), Some("cloud"), Some(false)));
    let (id1, id2) = (relays[0]["id"].as_str().expect("id").to_string(), relays[1]["id"].as_str().expect("id").to_string());
    let text = stdout(&cli.run(&a, &["sync", "relay", "list"]));
    assert_eq!(text.lines().count(), 2);
    assert!(text.lines().next().expect("line").starts_with(&id1) && text.contains("cloud") && text.contains("serves"), "{text}");

    // a run over the list: the serving folder is created on first use, every site gets a line
    let imported = cli.run(&a, &["import", drop_folder(tmp.path()).to_str().expect("utf8")]);
    assert_eq!(code(&imported), 0);
    let pushed = cli.run(&a, &["sync", "push"]);
    assert_eq!(code(&pushed), 0, "{}", stderr(&pushed));
    let out = stdout(&pushed);
    let mut lines = out.lines();
    assert!(lines.next().expect("first").starts_with("pushed 1 bundle(s): 2 record(s), 0 range(s)"));
    assert_eq!(lines.next(), Some(format!("  site {id1} folder: pushed 1, healed 0, behind 0, pulled 0, rejected 0").as_str()));
    assert_eq!(lines.next(), Some(format!("  site {id2} cloud folder: pushed 1, healed 0, behind 0, pulled 0, rejected 0").as_str()));
    // B shares the list file (same HOME) and pulls once from the union
    let pulled: Value = serde_json::from_str(&stdout(&cli.run(&b, &["--json", "sync", "pull"]))).expect("json");
    assert_eq!(pulled["applied"].as_array().map(Vec::len), Some(1));
    assert_eq!(pulled["sites"][0]["pulled"], 1);
    assert_eq!(pulled["sites"][1]["pulled"], 0, "the second site's copy is not fetched when the first applied it");
    assert_eq!(pulled["sites"][1]["error"], Value::Null);
    assert_eq!((pulled["sites"][0]["label"].as_str(), pulled["sites"][1]["label"].as_str()), (Some(""), Some("cloud")));

    // removing the serving entry leaves a list with no server; the last removal leaves nothing to sync with
    assert_eq!(code(&cli.run(&a, &["sync", "relay", "remove", &id1])), 0);
    let left = stdout(&cli.run(&a, &["sync", "relay", "list"]));
    assert_eq!(left.lines().count(), 1);
    assert_eq!(code(&cli.run(&a, &["sync", "relay", "remove", &id2])), 0);
    assert_eq!(code(&cli.run(&a, &["sync", "push"])), 2);
}

fn relay_file(cli: &Cli) -> PathBuf {
    cli.home.join(".disconect/relay.json")
}

#[test]
fn an_empty_list_is_no_relay() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cli = Cli::new(tmp.path());
    let (_da, a) = encrypted_copy();
    let folder = tmp.path().join("s1");
    std::fs::create_dir_all(&folder).expect("mkdir");
    let place = folder.to_str().expect("utf8");
    std::fs::create_dir_all(relay_file(&cli).parent().expect("parent")).expect("mkdir");
    std::fs::write(relay_file(&cli), "{\"relays\": []}").expect("write");

    let listed = cli.run(&a, &["sync", "relay", "list"]);
    assert_eq!((code(&listed), stdout(&listed)), (0, String::new()), "prints nothing");
    let json: Value = serde_json::from_str(&stdout(&cli.run(&a, &["--json", "sync", "relay", "list"]))).expect("json");
    assert_eq!(json, serde_json::json!({"relays": []}));
    assert_eq!(code(&cli.run(&a, &["sync", "push"])), 2, "no relay to sync with");
    // add appends to it
    assert_eq!(code(&cli.run(&a, &["sync", "relay", "add", place])), 0);
    let one: Value = serde_json::from_str(&stdout(&cli.run(&a, &["--json", "sync", "relay", "list"]))).expect("json");
    assert_eq!(one["relays"].as_array().map(Vec::len), Some(1));
    // removing the last entry deletes the file, and the next add works
    let id = one["relays"][0]["id"].as_str().expect("id").to_string();
    assert_eq!(code(&cli.run(&a, &["sync", "relay", "remove", &id])), 0);
    assert!(!relay_file(&cli).exists(), "the emptied list is no file");
    assert_eq!(code(&cli.run(&a, &["sync", "relay", "add", place])), 0);
    assert!(relay_file(&cli).exists());
}

#[test]
fn remember_replaces_a_list_of_one_and_refuses_a_longer_one() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cli = Cli::new(tmp.path());
    let (_da, a) = encrypted_copy();
    let (s1, s2, s3) = (tmp.path().join("s1"), tmp.path().join("s2"), tmp.path().join("s3"));
    for folder in [&s1, &s2, &s3] {
        std::fs::create_dir_all(folder).expect("mkdir");
    }
    let (p1, p2, p3) = (s1.to_str().expect("utf8"), s2.to_str().expect("utf8"), s3.to_str().expect("utf8"));
    // zero entries and one entry: --remember keeps replacing with the one-entry list
    assert_eq!(code(&cli.run(&a, &["sync", "push", "--relay", p1, "--remember"])), 0);
    assert_eq!(code(&cli.run(&a, &["sync", "push", "--relay", p2, "--remember"])), 0);
    let list = disconect_core::relay::config::read_list(&relay_file(&cli)).expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].config, disconect_core::relay::config::RelayConfig::Folder(p2.to_string()));
    // two entries: refused, the file untouched
    assert_eq!(code(&cli.run(&a, &["sync", "relay", "add", p1])), 0);
    let before = std::fs::read(relay_file(&cli)).expect("read");
    let refused = cli.run(&a, &["sync", "push", "--relay", p3, "--remember"]);
    assert_eq!(code(&refused), 2);
    assert!(stderr(&refused).contains("the relay list has more than one entry; use sync relay add"), "{}", stderr(&refused));
    assert_eq!(std::fs::read(relay_file(&cli)).expect("read"), before);
    // without --remember a one-off relay still runs over a longer list
    assert_eq!(code(&cli.run(&a, &["sync", "push", "--relay", p3])), 0);
}
