//! Bridge mechanics against a fake sidecar (a few lines of Python speaking the protocol): ids
//! are matched, events are forwarded, a crash is restarted once, a timeout clears the slot,
//! the passphrase env never reaches the child, and `key.unlock` is refused on the plain path.
//! The real core is covered by `real_core.rs` (ignored by default; needs a scratch DB).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use disconect_app_lib::sidecar::{EventSink, Launch, Sidecar};
use serde_json::{json, Value};

const FAKE: &str = r#"
import json, os, sys, time
for line in sys.stdin:
    req = json.loads(line)
    m, p, i = req["method"], req.get("params", {}), req["id"]
    if m == "echo":
        print(json.dumps({"id": i, "result": {"params": p, "env_pass": os.environ.get("DISCONECT_PASSPHRASE"), "home": os.environ.get("HOME") is not None}}), flush=True)
    elif m == "slow":
        time.sleep(float(p.get("seconds", 2))); print(json.dumps({"id": i, "result": "late"}), flush=True)
    elif m == "crash":
        os._exit(3)
    elif m == "progress":
        print(json.dumps({"event": "progress", "op": "import", "done": 1, "total": 2}), flush=True)
        print(json.dumps({"id": i, "result": "ok"}), flush=True)
    elif m == "key.unlock":
        print(json.dumps({"id": i, "result": {"unlocked": p.get("passphrase") == "correct horse"}}), flush=True)
    else:
        print(json.dumps({"id": i, "error": {"code": "unknown_method", "message": m}}), flush=True)
"#;

struct Collect(Mutex<Vec<(String, Value)>>);

impl EventSink for Collect {
    fn emit(&self, name: &str, payload: Value) {
        self.0.lock().unwrap().push((name.to_string(), payload));
    }
}

fn fake_launch() -> Launch {
    let dir = std::env::temp_dir().join(format!("disconect-fake-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("fake.py");
    std::fs::write(&script, FAKE).unwrap();
    let wrapper = dir.join("fake.sh");
    std::fs::write(&wrapper, format!("#!/bin/sh\nexec /usr/bin/env python3 {}\n", script.display())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    Launch { program: wrapper, args: vec![] }
}

fn start() -> (Sidecar, Arc<Collect>) {
    let sink = Arc::new(Collect(Mutex::new(vec![])));
    let core = Sidecar::start(fake_launch(), sink.clone()).expect("fake sidecar starts");
    (core, sink)
}

#[tokio::test]
async fn ids_are_matched_and_params_round_trip() {
    let (core, _) = start();
    let a = core.call("echo", json!({"n": 1}));
    let b = core.call("echo", json!({"n": 2}));
    let (ra, rb) = tokio::join!(a, b);
    assert_eq!(ra.unwrap()["params"]["n"], 1);
    assert_eq!(rb.unwrap()["params"]["n"], 2);
    core.shutdown();
}

#[tokio::test]
async fn passphrase_env_is_stripped_but_home_survives() {
    std::env::set_var("DISCONECT_PASSPHRASE", "must-not-leak");
    let (core, _) = start();
    let r = core.call("echo", json!({})).await.unwrap();
    assert!(r["env_pass"].is_null(), "DISCONECT_PASSPHRASE reached the child");
    assert_eq!(r["home"], true);
    std::env::remove_var("DISCONECT_PASSPHRASE");
    core.shutdown();
}

#[tokio::test]
async fn events_are_forwarded_with_the_core_prefix() {
    let (core, sink) = start();
    core.call("progress", json!({})).await.unwrap();
    let events = sink.0.lock().unwrap();
    assert!(events.iter().any(|(n, p)| n == "core://progress" && p["done"] == 1));
    drop(events);
    core.shutdown();
}

#[tokio::test]
async fn a_crash_fails_the_caller_and_restarts_once() {
    let (core, sink) = start();
    let err = core.call("crash", json!({})).await.unwrap_err();
    assert_eq!(err.code, "core_exited");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(sink.0.lock().unwrap().iter().any(|(n, _)| n == "core://restarted"));
    assert_eq!(core.call("echo", json!({"after": true})).await.unwrap()["params"]["after"], true);
    let err2 = core.call("crash", json!({})).await.unwrap_err();
    assert_eq!(err2.code, "core_exited");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(sink.0.lock().unwrap().iter().any(|(n, _)| n == "core://exited"));
    assert_eq!(core.call("echo", json!({})).await.unwrap_err().code, "core_unavailable");
}

#[tokio::test]
async fn unlock_goes_through_the_zeroized_path_only() {
    let (core, _) = start();
    assert_eq!(core.call("key.unlock", json!({"passphrase": "x"})).await.unwrap_err().code, "bad_params");
    assert_eq!(core.call("key.unlock", json!({})).await.unwrap()["unlocked"], false); // keychain path is allowed
    let ok = core.unlock(zeroize::Zeroizing::new("correct horse".to_string())).await.unwrap();
    assert_eq!(ok["unlocked"], true);
    core.shutdown();
}

#[tokio::test]
async fn unknown_methods_surface_the_core_error_code() {
    let (core, _) = start();
    assert_eq!(core.call("nope", json!({})).await.unwrap_err().code, "unknown_method");
    core.shutdown();
}

#[tokio::test]
async fn a_timeout_clears_the_slot_and_later_calls_still_work() {
    let (core, _) = start();
    let err = core.call_with_timeout("slow", json!({"seconds": 1}), Some(Duration::from_millis(150))).await.unwrap_err();
    assert_eq!(err.code, "timeout");
    assert_eq!(core.call("echo", json!({"k": 1})).await.unwrap()["params"]["k"], 1);
    core.shutdown();
}
