// SPDX-License-Identifier: AGPL-3.0-or-later
//! The serve oracle's `tools.call` answers as test fixtures (Bet 15 slices 3 and 5).
//!
//! The answers are the `tools.call` entries of the serve oracle transcripts (synthetic stores only, committed
//! under `projects/disconect/tests/fixtures/serve/`): about 317 calls on each of three stores. The transcripts
//! are gzip lines of about 10 MB each, too large to copy into a second fixture, so they are read in place
//! (`gunzip -c`) and each line is paired with its request in `script.json` (same order, same length).
//! Nothing here opens a store or a home folder.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};

pub const SENDABLE: [&str; 5] =
    ["get_data_health", "get_metric_series", "get_sleep_detail", "list_activities", "get_period_facts"];
pub const STORES: [&str; 3] = ["synthetic", "synthetic-v1", "empty"];

#[derive(Clone)]
pub struct Answer {
    pub store: &'static str,
    pub tool: String,
    pub arguments: Value,
    pub result: Value,
}

pub fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../disconect/tests/fixtures/serve")
}

pub fn answers(store: &'static str) -> Vec<Answer> {
    let script: Value =
        serde_json::from_slice(&std::fs::read(fixtures().join("script.json")).expect("script.json")).expect("json");
    let entries = script["entries"].as_array().expect("entries");
    let out = Command::new("gunzip")
        .arg("-c")
        .arg(fixtures().join(format!("oracle-{store}.jsonl.gz")))
        .output()
        .expect("gunzip runs");
    assert!(out.status.success(), "gunzip failed");
    let text = String::from_utf8(out.stdout).expect("utf-8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), entries.len(), "oracle and script are the same length");
    let mut found = Vec::new();
    for (line, entry) in lines.iter().zip(entries) {
        let send = &entry["send"];
        if send["method"] != "tools.call" {
            continue;
        }
        let record: Value = serde_json::from_str(line).expect("oracle line");
        for reply in record["lines"].as_array().expect("lines") {
            let (Some(name), Some(result)) = (reply["result"]["name"].as_str(), reply["result"].get("result")) else {
                continue;
            };
            found.push(Answer {
                store,
                tool: name.to_string(),
                arguments: send["params"]["arguments"].clone(),
                result: result.clone(),
            });
        }
    }
    found
}

pub fn all_answers() -> Vec<Answer> {
    STORES.iter().flat_map(|store| answers(store)).collect()
}

pub fn sendable(all: &[Answer]) -> Vec<&Answer> {
    all.iter().filter(|a| SENDABLE.contains(&a.tool.as_str())).collect()
}

/// A run of `dd:dd:dd` anywhere in the text.
pub fn has_clock_time(text: &str) -> bool {
    let b = text.as_bytes();
    b.windows(8).any(|w| {
        w.iter().enumerate().all(|(i, c)| if i == 2 || i == 5 { *c == b':' } else { c.is_ascii_digit() })
    })
}

/// The arguments' effective value of one of the coach-limited keys (the core's own default when absent).
pub fn effective(arguments: &Value, key: &str, default: i64) -> Option<i64> {
    match arguments.get(key) {
        None | Some(Value::Null) => Some(default),
        Some(Value::Number(n)) => n.as_i64(),
        _ => None,
    }
}

/// True when the request is one the coach itself would make: inside every limit of `clamp`.
pub fn within_coach_limits(a: &Answer) -> bool {
    match a.tool.as_str() {
        "get_data_health" => effective(&a.arguments, "window_days", 30).is_some_and(|d| (1..=30).contains(&d)),
        "get_metric_series" => effective(&a.arguments, "days", 90).is_some_and(|d| (1..=90).contains(&d)),
        "list_activities" => effective(&a.arguments, "limit", 20).is_some_and(|d| (1..=20).contains(&d)),
        "get_period_facts" => !matches!(a.arguments.get("include_points"), Some(v) if v != &json!(false) && v != &Value::Null),
        _ => true,
    }
}

