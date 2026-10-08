// SPDX-License-Identifier: AGPL-3.0-or-later
//! `tools.call` over the `serve` protocol, in process (Bet 15, slice 2): the failures and their codes, the
//! locked gate, and a tool read through the session's own master key. The byte-level comparison with the
//! Python oracle is `tools/serve_diff.py` and `serve_oracle_test.rs` (the `gen: tools.call` script entries).

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::{PASSPHRASE, encrypted_copy};
use disconect_core::serve::{self, Channel, Session};
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

struct Rig {
    session: Session,
    out: Buffer,
}

impl Rig {
    fn new(db: &std::path::Path) -> Rig {
        let out = Buffer::default();
        Rig {
            session: Session::new(db.to_path_buf(), Channel::new(Box::new(out.clone()))),
            out,
        }
    }

    /// The raw text of the one response line to a request.
    fn raw(&mut self, method: &str, params: Value) -> String {
        let line = format!("{}\n", json!({"id": 1, "method": method, "params": params}));
        assert_eq!(serve::serve_lines(&mut self.session, line.as_bytes()), 0);
        let bytes = std::mem::take(&mut *self.out.0.lock().expect("buffer"));
        let text = String::from_utf8(bytes).expect("ascii output");
        assert_eq!(text.lines().count(), 1, "one response line");
        text
    }

    fn send(&mut self, method: &str, params: Value) -> Value {
        serde_json::from_str(self.raw(method, params).trim()).expect("protocol line")
    }

    fn call(&mut self, params: Value) -> Value {
        self.send("tools.call", params)
    }
}

fn plain_store() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("store.hbdb");
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../disconect/tests/fixtures/serve/synthetic.hbdb"),
        &db,
    )
    .expect("copy the synthetic store");
    (dir, db)
}

fn failure(response: &Value) -> (&str, &str) {
    (
        response["error"]["code"].as_str().expect("code"),
        response["error"]["message"].as_str().expect("message"),
    )
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed fixtures (projects/disconect/tests/fixtures), which are developed in the monorepo and are not in this repository")]
fn a_call_that_is_not_well_formed_is_invalid_params() {
    let (_dir, db) = plain_store();
    let mut rig = Rig::new(&db);
    for params in [
        json!({}),
        json!({"name": 5}),
        json!({"name": ""}),
        json!({"name": null}),
    ] {
        let answer = rig.call(params);
        assert_eq!(
            failure(&answer),
            ("invalid_params", "name must be a non-empty string")
        );
    }
    for arguments in [json!([]), json!("{}"), json!(5), json!(true)] {
        let answer = rig.call(json!({"name": "get_contract", "arguments": arguments}));
        assert_eq!(
            failure(&answer),
            ("invalid_params", "arguments must be an object")
        );
    }
    let answer = rig.call(json!({"name": 5, "arguments": []}));
    assert_eq!(failure(&answer).1, "name must be a non-empty string");
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed fixtures (projects/disconect/tests/fixtures), which are developed in the monorepo and are not in this repository")]
fn an_unknown_tool_and_rejected_arguments_have_their_own_codes() {
    let (_dir, db) = plain_store();
    let mut rig = Rig::new(&db);
    let answer = rig.call(json!({"name": "data.health"}));
    assert_eq!(
        failure(&answer),
        ("unknown_tool", "Unknown tool: data.health")
    );
    let answer = rig.call(json!({"name": "list_activities", "arguments": {"limit": "secret"}}));
    assert_eq!(
        failure(&answer),
        ("invalid_params", "arguments rejected: limit")
    );
    let answer = rig.call(json!({"name": "get_period_facts",
        "arguments": {"window_days": "x", "baseline_days": [], "end_date": 5}}));
    assert_eq!(
        failure(&answer),
        (
            "invalid_params",
            "arguments rejected: baseline_days, end_date, window_days"
        )
    );
    let answer = rig.call(json!({"name": "get_metric_series", "arguments": {}}));
    assert_eq!(
        failure(&answer),
        ("invalid_params", "arguments rejected: metrics")
    );
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed fixtures (projects/disconect/tests/fixtures), which are developed in the monorepo and are not in this repository")]
fn a_tool_that_fails_answers_its_error_text_under_tool_error() {
    let (_dir, db) = plain_store();
    let mut rig = Rig::new(&db);
    let answer = rig.call(json!({"name": "get_metric_series", "arguments": {"metrics": []}}));
    assert_eq!(
        failure(&answer),
        (
            "tool_error",
            "metrics must name at least one metric; call get_contract for the list"
        )
    );
    let answer = rig.call(json!({"name": "get_sleep_detail", "arguments": {"date": "nonsense"}}));
    assert_eq!(failure(&answer), ("tool_error", "date must be YYYY-MM-DD"));
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed fixtures (projects/disconect/tests/fixtures), which are developed in the monorepo and are not in this repository")]
fn a_result_names_the_tool_and_coerces_like_the_mcp() {
    let (_dir, db) = plain_store();
    let mut rig = Rig::new(&db);
    let raw = rig.raw(
        "tools.call",
        json!({"name": "list_activities", "arguments": {"limit": "3"}}),
    );
    assert!(raw.starts_with("{\"id\":1,\"result\":{\"name\":\"list_activities\",\"result\":{"));
    let answer: Value = serde_json::from_str(raw.trim()).expect("line");
    assert!(answer["result"]["result"]["activities"].is_array());
    let contract = rig.call(json!({"name": "get_contract"}));
    assert_eq!(contract["result"]["name"], "get_contract");
    assert!(contract["result"]["result"]["metrics"].is_array());
}

#[test]
fn a_locked_store_answers_locked_first_and_reads_with_the_unlocked_master_after() {
    let (_dir, db) = encrypted_copy();
    let mut rig = Rig::new(&db);
    for params in [
        json!({"name": "get_contract"}),
        json!({"name": "no_such_tool"}),
        json!({}),
    ] {
        let answer = rig.call(params);
        assert_eq!(failure(&answer).0, "locked");
    }
    let unlocked = rig.send("key.unlock", json!({"passphrase": PASSPHRASE}));
    assert_eq!(unlocked["result"], json!({"unlocked": true}));
    let health = rig.call(json!({"name": "get_data_health", "arguments": {"window_days": 7}}));
    assert_eq!(health["result"]["name"], "get_data_health");
    assert!(health["result"]["result"]["coverage"].is_object());
}
