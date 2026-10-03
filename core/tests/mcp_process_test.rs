// SPDX-License-Identifier: AGPL-3.0-or-later
//! `disconect-core mcp` as a real child process: the cases the differential harness (`tools/mcp_diff.py`)
//! also plays, plus the ones only a process can show: an end of input that ends it, a locked store that
//! exits before stdin is read, the unlock paths and what lands on stderr. The keychain is disabled
//! (`DISCONECT_KEYCHAIN=fail`) so no test ever touches the real one.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{PASSPHRASE, encrypted_copy};
use serde_json::{Value, json};

const INIT: &str = r#"{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;

fn command(db: &Path, home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_disconect-core"));
    command
        .arg("mcp")
        .arg("--db")
        .arg(db)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("DISCONECT_KEYCHAIN", "fail")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Write `input`, close stdin, collect everything. Fails the test when the process does not end in time.
fn run(mut command: Command, input: &str) -> (Option<i32>, Vec<String>, String) {
    let mut child = command.spawn().expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let _ = stdin.write_all(input.as_bytes());
    drop(stdin);
    let started = Instant::now();
    let out = wait(child, Duration::from_secs(20));
    assert!(started.elapsed() < Duration::from_secs(20));
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn wait(mut child: Child, limit: Duration) -> std::process::Output {
    let started = Instant::now();
    while started.elapsed() < limit {
        if child.try_wait().expect("try_wait").is_some() {
            return child.wait_with_output().expect("output");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    panic!("the process did not end within {limit:?}");
}

fn plain_store() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("store.hbdb");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../disconect/tests/fixtures/serve/synthetic.hbdb"),
        &db,
    )
    .expect("copy the synthetic store");
    (dir, db)
}

fn parsed(lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .map(|l| serde_json::from_str(l).expect("every stdout line is JSON"))
        .collect()
}

#[test]
fn before_initialize_only_ping_is_answered_and_a_second_initialize_is_accepted() {
    let (dir, db) = plain_store();
    let input = [
        r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_contract","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"no/such/method"}"#,
        INIT,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/list"}"#,
        INIT,
    ]
    .join("\n");
    let (code, lines, _) = run(command(&db, dir.path()), &format!("{input}\n"));
    assert_eq!(code, Some(0));
    let out = parsed(&lines);
    assert_eq!(out.len(), 8);
    assert_eq!(out[0]["result"], json!({}));
    for refused in [&out[1], &out[2], &out[3]] {
        assert_eq!(
            refused["error"],
            json!({"code": -32602, "message": "Invalid request parameters", "data": ""})
        );
    }
    assert_eq!(out[4]["error"]["code"], -32601);
    assert_eq!(out[4]["error"]["data"], "no/such/method");
    assert_eq!(out[5]["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(out[6]["result"]["tools"].as_array().map(Vec::len), Some(6));
    assert_eq!(out[7]["id"], "init");
}

#[test]
fn malformed_lines_get_no_answer_and_ids_are_echoed_exactly() {
    let (dir, db) = plain_store();
    let lone = r#"{"jsonrpc":"2.0","id":9,"method":"ping","params":{"x":"\ud800"}}"#;
    let deep = format!(
        r#"{{"jsonrpc":"2.0","id":10,"method":"ping","params":{{"x":{}{}}}}}"#,
        "[".repeat(200),
        "]".repeat(200)
    );
    let shallow = format!(
        r#"{{"jsonrpc":"2.0","id":11,"method":"ping","params":{{"x":{}{}}}}}"#,
        "[".repeat(199),
        "]".repeat(199)
    );
    let silent = [
        "not json",
        r#"{"jsonrpc":"2.0","id":1,"method":"ping""#,
        r#"[{"jsonrpc":"2.0","id":2,"method":"ping"}]"#,
        r#"{"id":3,"method":"ping"}"#,
        r#"{"jsonrpc":"1.0","id":4,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":5.5,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":[1],"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}"#,
        "\u{feff}{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"ping\"}",
        r#"{"jsonrpc":"2.0","id":7,"method":"ping"} x"#,
        r#"{"jsonrpc":"2.0","id":8,"method":"ping"}{"jsonrpc":"2.0","id":8,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":8,"result":{}}"#,
        r#"{"jsonrpc":"2.0","id":8,"method":"ping","params":"x"}"#,
        lone,
        deep.as_str(),
        "",
        "   ",
    ];
    let answered = [
        r#"{"jsonrpc":"2.0","id":99999999999999999999,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":"é😀","method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":-0,"method":"ping","extra":NaN}"#,
        // the Python reader takes containers 201 deep (the message object is the first) and refuses 202
        shallow.as_str(),
    ];
    let input: Vec<&str> = silent.iter().chain(answered.iter()).copied().collect();
    let (code, lines, stderr) = run(command(&db, dir.path()), &format!("{}\n", input.join("\n")));
    assert_eq!(code, Some(0));
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert!(lines[0].contains("\"id\":99999999999999999999,"));
    assert_eq!(parsed(&lines)[1]["id"], "\u{e9}\u{1f600}");
    assert!(lines[2].contains("\"id\":0,"));
    assert!(lines[3].contains("\"id\":11,"));
    assert!(
        stderr
            .lines()
            .all(|l| l.starts_with("disconect-core mcp: "))
    );
}

#[test]
fn a_bare_cr_ends_a_line_like_pythons_text_stdin() {
    let (dir, db) = plain_store();
    let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\r\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}";
    let (_, lines, _) = run(command(&db, dir.path()), input);
    assert_eq!(
        parsed(&lines)
            .iter()
            .map(|l| l["id"].clone())
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
}

#[test]
fn end_of_input_ends_the_process_with_exit_zero_within_two_seconds() {
    let (dir, db) = plain_store();
    let mut child = command(&db, dir.path()).spawn().expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).expect("write");
    let mut line = String::new();
    stdout.read_line(&mut line).expect("an answer");
    assert!(line.contains("\"result\":{}"));
    drop(stdin);
    let started = Instant::now();
    let out = wait(child, Duration::from_secs(2));
    assert!(started.elapsed() < Duration::from_secs(2) && out.status.code() == Some(0));
}

#[test]
fn a_locked_store_exits_9_before_reading_stdin_and_says_where_to_fix_it() {
    let (dir, db) = encrypted_copy();
    // stdin stays open and silent: a process that read it first would hang until the timeout
    let mut child = command(&db, dir.path()).spawn().expect("spawn");
    let _keep_open = child.stdin.take().expect("stdin");
    let out = wait(child, Duration::from_secs(10));
    assert_eq!(out.status.code(), Some(9));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    for word in ["\"Your key\"", "Remember on this Mac", "keychain: absent"] {
        assert!(stderr.contains(word), "{stderr}");
    }
    assert!(!stderr.contains(PASSPHRASE));
}

#[test]
fn the_passphrase_file_unlocks_for_the_harness_and_a_wrong_one_is_exit_9() {
    let (dir, db) = encrypted_copy();
    let good = dir.path().join("good.txt");
    std::fs::write(&good, format!("{PASSPHRASE}\n")).expect("write");
    let call = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_activities","arguments":{}}}"#;
    let mut unlock = command(&db, dir.path());
    unlock.arg("--passphrase-file").arg(&good);
    let (code, lines, stderr) = run(unlock, &format!("{INIT}\n{call}\n"));
    assert_eq!(code, Some(0));
    let out = parsed(&lines);
    assert_eq!(out[1]["result"]["isError"], false);
    assert_eq!(
        out[1]["result"]["structuredContent"]["activities"],
        json!([])
    );
    assert!(!stderr.contains(PASSPHRASE));

    let bad = dir.path().join("bad.txt");
    std::fs::write(&bad, "not the passphrase at all!\n").expect("write");
    let mut wrong = command(&db, dir.path());
    wrong.arg("--passphrase-file").arg(&bad);
    let (code, lines, stderr) = run(wrong, &format!("{INIT}\n"));
    assert_eq!((code, lines.len()), (Some(9), 0));
    assert!(!stderr.contains("not the passphrase at all!"));
}

#[test]
fn the_passphrase_variable_is_ignored_and_never_printed() {
    let (dir, db) = encrypted_copy();
    let mut env_only = command(&db, dir.path());
    env_only.env("DISCONECT_PASSPHRASE", PASSPHRASE);
    let (code, lines, stderr) = run(env_only, &format!("{INIT}\n"));
    assert_eq!((code, lines.len()), (Some(9), 0));
    assert!(
        stderr.contains("DISCONECT_PASSPHRASE is ignored by mcp"),
        "{stderr}"
    );
    assert!(!stderr.contains(PASSPHRASE));
}

#[test]
fn a_missing_store_still_serves_and_names_what_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("never.hbdb");
    let call = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_data_health","arguments":{}}}"#;
    let (code, lines, _) = run(command(&db, dir.path()), &format!("{INIT}\n{call}\n"));
    assert_eq!(code, Some(0));
    let text = parsed(&lines)[1]["result"]["content"][0]["text"]
        .as_str()
        .expect("text")
        .to_string();
    assert!(
        text.starts_with("Error executing tool get_data_health: no DISCOnect database yet"),
        "{text}"
    );
    assert!(
        !dir.path().join("never.hbdb").exists(),
        "a read never creates a store"
    );
}

#[test]
fn stderr_gets_one_line_per_method_and_never_a_parameter() {
    let (dir, db) = plain_store();
    let call = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_activities","arguments":{"limit":"DISTINCTIVE-ARGUMENT"}}}"#;
    let input = format!(
        "{INIT}\n{}\n{call}\n{}\n{}\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"zz/\u0007odd"}"#,
    );
    let (_, lines, stderr) = run(command(&db, dir.path()), &input);
    assert_eq!(lines.len(), 4);
    let got: Vec<&str> = stderr.lines().collect();
    assert_eq!(
        got,
        [
            "disconect-core mcp: initialize",
            "disconect-core mcp: notifications/initialized",
            "disconect-core mcp: tools/call",
            "disconect-core mcp: ping",
            "disconect-core mcp: zz/?odd",
        ]
    );
    assert!(!stderr.contains("DISTINCTIVE"));
}

#[test]
fn stray_arguments_are_a_usage_error() {
    let (dir, db) = plain_store();
    let mut with_json = command(&db, dir.path());
    with_json.arg("--json");
    let (code, lines, stderr) = run(with_json, "");
    assert_eq!((code, lines.len()), (Some(2), 0));
    assert!(stderr.contains("mcp takes only"));
}
