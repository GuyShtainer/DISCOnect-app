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
    // the config is Python's shape: {"folder": path}
    let config =
        std::fs::read_to_string(cli.home.join(".disconect/relay.json")).expect("config written");
    assert_eq!(config, format!("{{\"folder\": \"{relay_arg}\"}}\n"));

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
        "pulled 1 bundle(s): 2 new, 0 duplicate, 0 invalid, 0 conflict(s), 0 new range(s); rejected 0; gaps 0"
    );
    let again = cli.run(&b, &["sync", "pull"]);
    assert_eq!(code(&again), 0);
    assert!(stdout(&again).starts_with("pulled 0 bundle(s): 0 new"));
    // nothing echoes
    let echo = cli.run(&b, &["sync", "push"]);
    assert!(stdout(&echo).starts_with("pushed 0 bundle(s): 0 record(s), 0 range(s)"));

    let status = cli.run(&b, &["sync", "status"]);
    assert_eq!(code(&status), 0);
    assert_eq!(
        stdout(&status).trim(),
        "relay: pushed 0, pulled 1, rejected 0; records unsent 0, seen 2; conflicts 0; gaps 0"
    );
    let report: Value =
        serde_json::from_str(&stdout(&cli.run(&b, &["--json", "sync", "status"]))).expect("json");
    assert_eq!(report["bundles"]["pulled_applied"], 1);
    assert_eq!(report["records_unsent"], 0);
    assert_eq!(report["gaps"], Value::Array(Vec::new()));

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
        stdout(&partial).trim().ends_with("rejected 1; gaps 0"),
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
