//! Bridge against the REAL Python core on a scratch encrypted database (acceptance item 3 of
//! pitch 07). Ignored by default because it needs local files:
//!
//!     DISCONECT_CORE=<.app>/Contents/Resources/hearthbeat-core/hearthbeat-core \
//!     DISCONECT_TEST_DB=/path/scratch.db DISCONECT_TEST_PASSPHRASE_FILE=/path/pass.txt \
//!     DISCONECT_TEST_IMPORT=/path/to/an/export/folder \
//!     cargo test --test real_core -- --ignored --nocapture
//!
//! DISCONECT_CORE is the BUNDLED sidecar (it serves without arguments and runs the CLI with
//! `cli`). The scratch DB must be a copy, never the live store (~/.disconect/disconect.db, or the legacy ~/.hearthbeat/hearthbeat.db); the passphrase file is
//! read once into a zeroized buffer and never printed. With DISCONECT_TEST_IMPORT set, the second
//! test imports that folder through the bridge on copy A and through the CLI on an identical copy
//! B, and the counts must agree (acceptance item 3).

// The child-process bridge (`Sidecar::start`) exists on desktop only; a phone runs the core in-process
// (see `inproc.rs`), so on iOS this file compiles to nothing (12-C, structural).
#![cfg(desktop)]

use std::path::PathBuf;
/// After `Command::env_clear()`: put back the three variables a child needs to start inside the iOS
/// simulator (bisected 2026-10-06, 12-C: `DYLD_ROOT_PATH`, `SIMULATOR_ROOT`, `SIMULATOR_SHARED_RESOURCES_DIRECTORY`;
/// see `disconect-core/tests/common/mod.rs`). A no-op off iOS.
fn simulator_env(cmd: &mut std::process::Command) -> &mut std::process::Command {
    if cfg!(target_os = "ios") {
        for name in ["DYLD_ROOT_PATH", "SIMULATOR_ROOT", "SIMULATOR_SHARED_RESOURCES_DIRECTORY"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
    }
    cmd
}

use std::sync::{Arc, Mutex};

use disconect_app_lib::sidecar::{EventSink, Launch, Sidecar};
use serde_json::{json, Value};
use zeroize::Zeroizing;

struct Collect(Mutex<Vec<(String, Value)>>);

impl EventSink for Collect {
    fn emit(&self, name: &str, payload: Value) {
        self.0.lock().unwrap().push((name.to_string(), payload));
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} (see the file header)"))
}

#[tokio::test]
#[ignore]
async fn locked_then_unlock_then_data_on_the_real_core() {
    let program = PathBuf::from(env("DISCONECT_CORE"));
    let db = env("DISCONECT_TEST_DB");
    let pass = Zeroizing::new(std::fs::read_to_string(env("DISCONECT_TEST_PASSPHRASE_FILE")).unwrap().trim_end().to_string());
    let sink = Arc::new(Collect(Mutex::new(vec![])));
    let core = Sidecar::start(Launch::new(program, Some(db)), sink.clone()).expect("core starts");

    let info = core.call("app.info", json!({})).await.expect("app.info");
    assert_eq!(info["product"], "DISCOnect");
    assert!(!info["notice"].as_str().unwrap_or("").is_empty());

    let status = core.call("key.status", json!({})).await.expect("key.status");
    assert_eq!(status["encrypted"], true, "the scratch DB must be encrypted");
    assert_eq!(status["unlocked"], false, "serve must never prime at start");

    let err = core.call("data.health", json!({})).await.unwrap_err();
    assert_eq!(err.code, "locked");

    let wrong = core.unlock(Zeroizing::new("definitely-not-the-passphrase".to_string())).await.unwrap_err();
    assert_eq!(wrong.code, "wrong_passphrase");

    let ok = core.unlock(pass).await.expect("unlock");
    assert_eq!(ok["unlocked"], true);

    let health = core.call("data.health", json!({"window_days": 90})).await.expect("data.health");
    let ledger = health["coverage"]["ledger"].as_array().expect("ledger rows");
    assert!(!ledger.is_empty());
    let text = health.to_string();
    assert!(!text.to_lowercase().contains("garmin"), "manufacturer name leaked into data.health");

    let steps = core.call("data.metric", json!({"metric": "steps", "scope": "local", "days": 90})).await.expect("data.metric");
    let days = steps["days"].as_array().expect("days");
    assert_eq!(days.len(), 90, "calendar-filled: one entry per local day");
    assert!(days.iter().all(|d| d["status"].is_string()));

    let today = core.call("data.today", json!({})).await.expect("data.today");
    assert!(today["metrics"].as_array().map(|m| !m.is_empty()).unwrap_or(false));

    let facts = core.call("data.facts", json!({"days": 7, "baseline_days": 28})).await.expect("data.facts");
    assert!(facts["facts"].is_array());

    println!(
        "REAL CORE: {} ledger rows, {} calendar days, {} today metrics",
        ledger.len(),
        days.len(),
        today["metrics"].as_array().map(Vec::len).unwrap_or(0)
    );
    core.shutdown();
}

/// Copy a database and its key file to a sibling path with the given suffix.
fn copy_store(db: &str, suffix: &str) -> String {
    let copy = format!("{db}.{suffix}");
    std::fs::copy(db, &copy).unwrap();
    let _ = std::fs::copy(format!("{db}.keys.json"), format!("{copy}.keys.json"));
    copy
}

fn count_after(summary: &str, word: &str) -> u64 {
    // "ok: 3 imported, 211 duplicate, 0 failed ..." -> the number before `word`
    summary
        .split([',', ':'])
        .find_map(|part| {
            let part = part.trim();
            part.strip_suffix(word).and_then(|n| n.trim().parse::<u64>().ok())
        })
        .unwrap_or_else(|| panic!("no '<n> {word}' in {summary:?}"))
}

#[tokio::test]
#[ignore]
async fn import_through_the_bridge_matches_the_cli() {
    let program = PathBuf::from(env("DISCONECT_CORE"));
    let db = env("DISCONECT_TEST_DB");
    let source = env("DISCONECT_TEST_IMPORT");
    let pass_file = env("DISCONECT_TEST_PASSPHRASE_FILE");
    let pass = Zeroizing::new(std::fs::read_to_string(&pass_file).unwrap().trim_end().to_string());
    let a = copy_store(&db, "bridge");
    let b = copy_store(&db, "cli");

    let sink = Arc::new(Collect(Mutex::new(vec![])));
    let core = Sidecar::start(Launch::new(program.clone(), Some(a.clone())), sink.clone()).expect("core starts");
    core.unlock(pass).await.expect("unlock");
    let via_bridge = core.call("import.run", json!({"path": source})).await.expect("import.run");
    assert!(sink.0.lock().unwrap().iter().any(|(n, _)| n == "core://progress"), "no progress event");
    core.shutdown();

    // The CLI on an identical copy, unlocked through the tests-only env path (never in the app).
    let pass_text = Zeroizing::new(std::fs::read_to_string(&pass_file).unwrap().trim_end().to_string());
    let mut cli = std::process::Command::new(&program);
    cli.args(["cli", "--db", &b, "import", &source]).env_clear();
    simulator_env(&mut cli);
    let out = cli
        .env("HOME", std::env::var("HOME").unwrap())
        .env("PATH", "/usr/bin:/bin")
        .env("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
        .env("DISCONECT_PASSPHRASE", pass_text.as_str())
        .output()
        .expect("cli runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let summary = stdout.lines().find(|l| l.contains("imported")).unwrap_or_else(|| panic!("no summary in {stdout:?}"));
    for (field, word) in [("ok", "imported"), ("duplicate", "duplicate"), ("failed", "failed")] {
        assert_eq!(via_bridge[field].as_u64().unwrap(), count_after(summary, word), "{field} differs: bridge {via_bridge} vs cli {summary:?}");
    }
    println!("IMPORT: bridge {via_bridge} == cli {summary:?}");
    for p in [a.clone(), format!("{a}.keys.json"), b.clone(), format!("{b}.keys.json")] {
        let _ = std::fs::remove_file(p);
    }
}
