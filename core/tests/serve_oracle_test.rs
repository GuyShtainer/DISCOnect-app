// SPDX-License-Identifier: AGPL-3.0-or-later
//! Replay of the committed request script against the committed synthetic stores (the current schema and
//! schema v1), compared with the Python oracle's committed responses (`oracle-synthetic*.jsonl.gz`,
//! written by `tools/serve_diff.py --python-only`). No Python runs here: this is the slice's regression
//! net when only cargo is at hand; the live two-core comparison is `tools/serve_diff.py`.
//!
//! Comparison is on tagged trees: `wirejson::Json` keeps bool, int, float, string, null, list and
//! object apart, big integers exactly. `app.info.core` and `app.info.db` are the only allowances.
//! Entries for methods that are not ported yet must answer `unknown_method`. An entry the script marks
//! `booked` (Python accepts a `last_day` form the port refuses, `docs/kb/23`) must be answered
//! `bad_params` unless it matches the oracle anyway.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use disconect_core::read::DEFERRED_METHODS;
use disconect_core::wirejson::{self, Json, PyStr};
use serde_json::Value;

const MASK: &str = "@allowed@";
const APP_INFO_KEYS: [&str; 7] = [
    "product",
    "core",
    "schema",
    "contract",
    "db",
    "encrypted",
    "notice",
];

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../hearthbeat/tests/fixtures/serve")
}

/// The script's anchor days (`$FIRST`, `$MID`, `$LAST`, `$BEFORE`), which the generator took from the store.
fn anchors(script: &Value) -> Vec<(String, String)> {
    script["anchors"]
        .as_object()
        .expect("anchors")
        .iter()
        .map(|(name, day)| (name.clone(), day.as_str().expect("day").to_string()))
        .collect()
}

fn entry_bytes(entry: &Value, anchors: &[(String, String)]) -> Vec<u8> {
    let templates = [
        ("$DIGITS4300", format!("1{}", "0".repeat(4299))),
        ("$DIGITS4301", format!("1{}", "0".repeat(4300))),
        (
            "$NEST100",
            format!("{}{}", "[".repeat(100), "]".repeat(100)),
        ),
    ];
    if let Some(request) = entry.get("send") {
        let mut text = serde_json::to_string(request)
            .expect("request")
            .replace("$PASSPHRASE", "an unused but perfectly long passphrase");
        for (name, day) in anchors {
            text = text.replace(name, day);
        }
        return text.into_bytes();
    }
    if let Some(raw) = entry.get("raw").and_then(Value::as_str) {
        let mut text = raw.to_string();
        for (name, value) in &templates {
            text = text.replace(name, value);
        }
        for (name, day) in anchors {
            text = text.replace(name, day);
        }
        return text.into_bytes();
    }
    hex::decode(entry["raw_hex"].as_str().expect("raw_hex")).expect("hex")
}

/// Object key order is not part of the protocol: sort every object's pairs.
fn sorted(node: Json) -> Json {
    match node {
        Json::Array(items) => Json::Array(items.into_iter().map(sorted).collect()),
        Json::Object(pairs) => {
            let mut pairs: Vec<(PyStr, Json)> =
                pairs.into_iter().map(|(k, v)| (k, sorted(v))).collect();
            pairs.sort_by_key(|(key, _)| key.units().collect::<Vec<u16>>());
            Json::Object(pairs)
        }
        other => other,
    }
}

fn mask(node: Json) -> Json {
    let Json::Object(mut pairs) = node else {
        return node;
    };
    let is_app_info = pairs.iter().any(|(k, v)| {
        k.equals("result")
            && matches!(v, Json::Object(inner)
                if inner.len() == APP_INFO_KEYS.len() && APP_INFO_KEYS.iter().all(|key| v.get(key).is_some()))
    });
    if is_app_info {
        for (key, value) in &mut pairs {
            if key.equals("result")
                && let Json::Object(inner) = value
            {
                for (name, field) in inner {
                    if (name.equals("core") || name.equals("db")) && matches!(field, Json::Str(_)) {
                        *field = Json::Str(PyStr::from_text(MASK));
                    }
                }
            }
        }
    }
    Json::Object(pairs)
}

fn gunzip(path: &Path) -> String {
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).expect("oracle file"))
        .read_to_string(&mut text)
        .expect("gunzip");
    text
}

#[test]
fn the_rust_core_answers_the_committed_script_like_the_python_oracle() {
    replay("synthetic.hbdb", "oracle-synthetic.jsonl.gz");
}

#[test]
fn the_rust_core_answers_the_committed_script_like_the_python_oracle_on_a_schema_v1_store() {
    replay("synthetic-v1.hbdb", "oracle-synthetic-v1.jsonl.gz");
}

fn replay(store_file: &str, oracle_file: &str) {
    let script: Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures().join("script.json")).expect("script"),
    )
    .expect("json");
    // read with wirejson: serde_json cannot hold the 4300-digit id some oracle lines echo
    let oracle: Vec<(String, Vec<Json>)> =
        gunzip(&fixtures().join(oracle_file))
            .lines()
            .map(|l| {
                let entry = wirejson::parse(l).expect("oracle line");
                let name = match entry.get("name") {
                    Some(Json::Str(text)) => text.to_text().expect("name"),
                    _ => unreachable!("oracle entries have a name"),
                };
                match entry.get("lines") {
                    Some(Json::Array(lines)) => (name, lines.clone()),
                    _ => unreachable!("oracle entries have lines"),
                }
            })
            .collect();
    let entries = script["entries"].as_array().expect("entries");
    assert_eq!(
        entries.len(),
        oracle.len(),
        "regenerate the oracle: python tests/gen_serve_fixtures.py --oracle"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("store.db");
    std::fs::copy(fixtures().join(store_file), &db).expect("copy store");
    let mut child = Command::new(env!("CARGO_BIN_EXE_disconect-core"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir.path())
        .env("TZ", "Pacific/Chatham")
        .env("DISCONECT_NOW", script["now"].as_str().expect("now"))
        .env("DISCONECT_KEYCHAIN", "fail")
        .arg("--db")
        .arg(&db)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let writer = std::thread::spawn({
        let anchors = anchors(&script);
        let payloads: Vec<Vec<u8>> = entries.iter().map(|e| entry_bytes(e, &anchors)).collect();
        move || {
            for (index, payload) in payloads.iter().enumerate() {
                stdin.write_all(payload).expect("write entry");
                stdin
                    .write_all(
                        format!("\n{{\"id\":\"@@sync-{index}\",\"method\":\"app.info\"}}\n")
                            .as_bytes(),
                    )
                    .expect("write sentinel");
            }
        }
    });
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut differences = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let sentinel = format!("\"id\":\"@@sync-{index}\"");
        let mut got: Vec<Json> = Vec::new();
        loop {
            let mut line = String::new();
            assert!(
                reader.read_line(&mut line).expect("read") > 0,
                "the core closed its output early"
            );
            if line.contains(&sentinel) {
                break;
            }
            got.push(wirejson::parse(&line).expect("protocol line"));
        }
        let method = entry["send"]["method"].as_str().unwrap_or("");
        if DEFERRED_METHODS.contains(&method) {
            let ok = got.len() == 1
                && got[0].get("error").and_then(|e| e.get("code"))
                    == Some(&Json::Str(PyStr::from_text("unknown_method")));
            if !ok {
                differences.push(format!(
                    "#{index} {method}: a deferred method must answer unknown_method"
                ));
            }
            continue;
        }
        let got: Vec<Json> = got.into_iter().map(|n| sorted(mask(n))).collect();
        let want: Vec<Json> = oracle[index]
            .1
            .iter()
            .cloned()
            .map(|n| sorted(mask(n)))
            .collect();
        if got != want {
            let refused = got.len() == 1
                && got[0]
                    .get("error")
                    .and_then(|e| e.get("code"))
                    == Some(&Json::Str(PyStr::from_text("bad_params")));
            if !(entry.get("booked").is_some() && refused) {
                differences.push(format!("#{index} {}", oracle[index].0));
            }
        }
    }
    writer.join().expect("writer");
    drop(reader);
    assert!(child.wait().expect("wait").success());
    assert!(
        differences.is_empty(),
        "{} entries differ from the oracle: {differences:?}",
        differences.len()
    );
}
