//! Bridge against the REAL Python core on a scratch encrypted database (acceptance item 3 of
//! pitch 07). Ignored by default because it needs local files:
//!
//!     DISCONECT_CORE=../../hearthbeat/.venv/bin/hearthbeat-serve \
//!     DISCONECT_TEST_DB=/path/scratch.db DISCONECT_TEST_PASSPHRASE_FILE=/path/pass.txt \
//!     cargo test --test real_core -- --ignored --nocapture
//!
//! The scratch DB must be a copy, never ~/.hearthbeat/hearthbeat.db; the passphrase file is read
//! once into a zeroized buffer and never printed.

use std::path::PathBuf;
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
