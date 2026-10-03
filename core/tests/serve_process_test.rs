// SPDX-License-Identifier: AGPL-3.0-or-later
//! `serve` as a real child process: the guarantees `tests/test_serve.py` checks in a child, run
//! against the Rust binary (the Python twin of these is `tests/test_serve_rust.py` on the Python side).
//! The keychain is disabled (`DISCONECT_KEYCHAIN=fail`) so no test ever touches the real one.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use common::{PASSPHRASE, encrypted_copy};
use disconect_core::keys;
use serde_json::Value;

const WRONG: &str = "not the passphrase at all!";

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_disconect-core"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DISCONECT_KEYCHAIN", "fail")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn requests(calls: &[(&str, Value)]) -> String {
    calls
        .iter()
        .enumerate()
        .map(|(i, (method, params))| {
            format!(
                "{}\n",
                serde_json::json!({"id": i + 1, "method": method, "params": params})
            )
        })
        .collect()
}

fn run_to_eof(mut command: Command, input: &str) -> (std::process::ExitStatus, String, String) {
    let mut child = command.spawn().expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    (
        out.status,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn parsed(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("every stdout line is protocol JSON"))
        .collect()
}

#[test]
fn eof_ends_the_process_with_exit_zero_within_two_seconds() {
    let (dir, db) = encrypted_copy();
    let mut command = binary();
    command.arg("--db").arg(&db).env("HOME", dir.path());
    let mut child = command.spawn().expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    stdin
        .write_all(requests(&[("app.info", serde_json::json!({}))]).as_bytes())
        .expect("write");
    let mut line = String::new();
    reader.read_line(&mut line).expect("a response");
    let reply: Value = serde_json::from_str(&line).expect("json");
    assert_eq!(reply["result"]["product"], "DISCOnect");
    drop(stdin);
    let started = Instant::now();
    let status = child.wait().expect("wait");
    assert!(status.success() && started.elapsed() < Duration::from_secs(2));
}

#[test]
fn stray_prints_and_raw_fd_writes_never_reach_the_protocol_stream() {
    let probe = Path::new(env!("CARGO_BIN_EXE_disconect-core"))
        .parent()
        .expect("target dir")
        .join("examples")
        .join("fd_probe");
    if !probe.exists() {
        // `cargo test --test serve_process_test` does not build examples; a full `cargo test` does.
        let built = Command::new(env!("CARGO"))
            .args(["build", "--example", "fd_probe"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("run cargo");
        assert!(
            built.success() && probe.exists(),
            "the fd_probe example builds"
        );
    }
    let out = Command::new(probe).env_clear().output().expect("run probe");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let lines = parsed(&stdout);
    assert_eq!(
        lines.len(),
        2,
        "stdout holds exactly the two protocol lines"
    );
    assert_eq!(lines[0]["result"]["ok"], true);
    assert!(!stdout.contains("STRAY"));
    for kind in ["PRINT", "STDOUT", "RAW WRITE"] {
        assert!(
            stderr.contains(&format!("STRAY {kind}")),
            "{kind} went to stderr"
        );
    }
}

#[test]
fn passphrase_and_master_key_are_never_printed() {
    let (dir, db) = encrypted_copy();
    let key_file =
        keys::read_key_file(&common::fixtures().join("test.keys.json")).expect("key file");
    let master = keys::unlock_with_passphrase(&key_file, PASSPHRASE).expect("master");
    let mut command = binary();
    command.arg("--db").arg(&db).env("HOME", dir.path());
    let input = requests(&[
        ("key.unlock", serde_json::json!({"passphrase": WRONG})),
        ("key.unlock", serde_json::json!({"passphrase": PASSPHRASE})),
        ("key.cache", serde_json::json!({"enable": true})),
        ("key.status", serde_json::json!({})),
        ("key.cache", serde_json::json!({"enable": false})),
    ]);
    let (status, stdout, stderr) = run_to_eof(command, &input);
    assert!(status.success());
    let replies = parsed(&stdout);
    let errors: Vec<bool> = replies.iter().map(|r| r.get("error").is_some()).collect();
    assert_eq!(
        errors,
        [true, false, true, false, true],
        "wrong, ok, cache (no keychain), status, cache"
    );
    assert_eq!(replies[2]["error"]["code"], "internal");
    assert_eq!(replies[2]["error"]["message"], "unexpected NoKeyringError");
    assert_eq!(replies[3]["result"]["unlocked"], true);
    let db_key = keys::db_key(&master);
    let secrets: [(&str, Vec<u8>); 4] = [
        ("passphrase", PASSPHRASE.as_bytes().to_vec()),
        ("wrong passphrase", WRONG.as_bytes().to_vec()),
        ("master", master.to_vec()),
        ("db key", db_key.to_vec()),
    ];
    for (name, raw) in secrets {
        let forms = [
            String::from_utf8_lossy(&raw).into_owned(),
            hex::encode(&raw),
            base64::engine::general_purpose::STANDARD.encode(&raw),
            base64::engine::general_purpose::URL_SAFE.encode(&raw),
        ];
        for (stream, text) in [("stdout", &stdout), ("stderr", &stderr)] {
            for form in &forms {
                assert!(!text.contains(form.as_str()), "{name} leaked on {stream}");
            }
        }
    }
}

#[test]
fn env_passphrase_is_ignored_and_reported() {
    let (dir, db) = encrypted_copy();
    let mut command = binary();
    command
        .arg("--db")
        .arg(&db)
        .env("HOME", dir.path())
        .env("DISCONECT_PASSPHRASE", PASSPHRASE);
    let input = requests(&[
        ("key.status", serde_json::json!({})),
        ("key.cache", serde_json::json!({"enable": true})),
    ]);
    let (status, stdout, stderr) = run_to_eof(command, &input);
    assert!(status.success());
    let lines = parsed(&stdout);
    assert_eq!(lines[0]["event"], "log");
    assert_eq!(lines[0]["level"], "warn");
    assert_eq!(
        lines[0]["message"],
        "DISCONECT_PASSPHRASE is ignored by serve and was removed from the environment"
    );
    assert_eq!(lines[1]["result"]["unlocked"], false);
    assert_eq!(
        lines[2]["error"]["code"], "locked",
        "the env passphrase did not unlock anything"
    );
    assert!(!stdout.contains(PASSPHRASE) && !stderr.contains(PASSPHRASE));
}

#[test]
fn no_subcommand_serves_and_default_db_comes_from_the_environment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("elsewhere.db");
    let mut command = binary();
    command.env("DISCONECT_DB", &db).env("HOME", dir.path());
    let (status, stdout, _stderr) =
        run_to_eof(command, &requests(&[("app.info", serde_json::json!({}))]));
    assert!(status.success());
    let info = &parsed(&stdout)[0]["result"];
    assert_eq!(info["db"], db.to_string_lossy().as_ref());
    assert_eq!(
        info["encrypted"], false,
        "no file and no key file: not encrypted"
    );

    // with neither --db nor DISCONECT_DB it is ~/.hearthbeat/hearthbeat.db under HOME
    let mut command = binary();
    command.env("HOME", dir.path());
    let (_, stdout, _) = run_to_eof(command, &requests(&[("app.info", serde_json::json!({}))]));
    let expected = dir.path().join(".hearthbeat").join("hearthbeat.db");
    assert_eq!(
        parsed(&stdout)[0]["result"]["db"],
        expected.to_string_lossy().as_ref()
    );
}

#[test]
fn key_path_override_expands_the_home_directory() {
    let (dir, db) = encrypted_copy();
    let moved = dir.path().join("moved.keys.json");
    std::fs::rename(keys::sibling_with_suffix(&db, ".keys.json"), &moved).expect("move key file");
    let mut command = binary();
    command
        .arg("--db")
        .arg(&db)
        .env("HOME", dir.path())
        .env("DISCONECT_KEYS", "~/moved.keys.json");
    let (_, stdout, _) = run_to_eof(command, &requests(&[("key.status", serde_json::json!({}))]));
    let status = &parsed(&stdout)[0]["result"];
    assert_eq!(status["key_file"], true);
    assert_eq!(status["kdf"]["m_kib"], 262_144);
}

#[test]
fn serve_rejects_the_cli_only_flags() {
    let mut command = binary();
    command.arg("--json");
    let (status, _, stderr) = run_to_eof(command, "");
    assert_eq!(status.code(), Some(2));
    assert!(stderr.contains("serve takes only --db"));
}
