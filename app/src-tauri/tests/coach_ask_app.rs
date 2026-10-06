// SPDX-License-Identifier: AGPL-3.0-or-later
//! `coach_ask` through a real `AppHandle` (Tauri's mock runtime) with the real managed state: the in-process
//! core over a copy of the synthetic store answers `tools.call`, a loopback listener plays the model, the
//! settings live in the mock app's own config dir under a scratch `HOME`. What the unit test in
//! `coach/commands.rs` cannot reach (it has no provider and an error core): a question that goes out, calls a
//! tool through the core, comes back with its trace, and the gate re-read from disk that stops the next one.
//! Nothing here touches the user's home: `HOME` is pinned to a scratch folder before any thread starts.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Once};

use disconect_app_lib::coach::commands::{coach_ask, CoachState};
use disconect_app_lib::coach::key::KeyHolder;
use disconect_app_lib::coach::settings::{self, Mode, Settings};
use disconect_app_lib::sidecar::{EventSink, Sidecar};
use disconect_app_lib::Core;
use serde_json::Value;
use tauri::Manager;

mod common;
use common::fake_provider::Step;
use common::socket::Server;

const NOW: &str = "2025-07-02T09:30:00Z";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> Scratch {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!("disconect-coach-ask-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).expect("mkdir");
    Scratch(dir)
}

/// Pin the process's own environment before any core thread exists (the pattern of `tests/inproc.rs`).
fn env_init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let home = std::env::temp_dir().join(format!("disconect-coach-ask-home-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&home);
        std::env::set_var("HOME", &home);
        std::env::set_var("DISCONECT_NOW", NOW);
        std::env::set_var("DISCONECT_KEYCHAIN", "fail");
    });
}

struct Quiet;

impl EventSink for Quiet {
    fn emit(&self, _name: &str, _payload: Value) {}
}

/// Every mock app of this binary shares one config dir (one `HOME`, one identifier), so the tests run one
/// at a time: the guard lives as long as the rig.
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The mock app: the in-process core over a copy of the synthetic store, an empty key holder, a fresh
/// conversation; the settings dir is the mock app's own config dir (under the scratch `HOME`).
fn rig(dir: &Scratch) -> (tauri::App<tauri::test::MockRuntime>, PathBuf, MutexGuard<'static, ()>) {
    let guard = serial();
    env_init();
    let db = dir.0.join("store.hbdb");
    std::fs::copy(repo().join("projects/disconect/tests/fixtures/serve/synthetic.hbdb"), &db).expect("copy the synthetic store");
    let core = Sidecar::start_inproc(db, Arc::new(Quiet)).expect("in-process core");
    let app = tauri::test::mock_builder()
        .manage(Core(Ok(core)))
        .manage(KeyHolder::default())
        .manage(CoachState::default())
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .expect("mock app");
    let config = app.path().app_config_dir().expect("the mock app has a config dir");
    assert!(config.starts_with(std::env::var("HOME").expect("HOME")), "the config dir is under the scratch home: {}", config.display());
    std::fs::create_dir_all(&config).expect("config dir");
    (app, config, guard)
}

fn local(port: u16) -> Settings {
    Settings { mode: Mode::Local, base_url: format!("http://127.0.0.1:{port}/v1"), model: "test-model".into(), ..Settings::default() }
}

#[test]
fn a_question_through_the_app_handle_calls_a_tool_on_the_core_and_returns_its_trace() {
    let dir = scratch();
    let (app, config, _serial) = rig(&dir);
    let handle = app.handle().clone();
    let server = Server::start(vec![Step::call("get_data_health", "{}"), Step::text("Your data covers the window.")]);
    settings::save(&config, &local(server.port)).expect("save settings");

    let reply = tauri::async_runtime::block_on(coach_ask(handle.clone(), "how complete is my data?".into())).expect("an answer");
    assert_eq!(reply.text, "Your data covers the window.");
    assert_eq!(reply.trace.len(), 1, "one tool call in the drawer: {:?}", reply.trace);
    assert_eq!(reply.trace[0].tool, "get_data_health");
    assert!(reply.trace[0].bytes_sent > 0, "the core's answer was projected and sent");
    let (accepts, seen) = server.finish();
    assert_eq!((accepts, seen.len()), (2, 2), "one connection per request");
    let first: Value = serde_json::from_slice(&seen[0].body).expect("json request");
    let second: Value = serde_json::from_slice(&seen[1].body).expect("json request");
    assert_eq!(seen[0].request_line, "POST /v1/chat/completions HTTP/1.1");
    let roles = |body: &Value| -> Vec<String> {
        body["messages"].as_array().expect("messages").iter().map(|m| m["role"].as_str().unwrap_or("").to_string()).collect()
    };
    assert_eq!(roles(&first), ["system", "user"]);
    assert_eq!(roles(&second), ["system", "user", "assistant", "tool"], "the tool's answer went back as a tool message");
    let tool_message = second["messages"][3]["content"].as_str().expect("tool content");
    let projected: Value = serde_json::from_str(tool_message).expect("the tool message is the projected JSON");
    assert!(projected.get("never_imported").is_some() && projected.get("recent_imports").is_none(), "projected, not the raw health: {projected}");
    assert!(seen[1].header_values("authorization").is_empty(), "an empty key holder under a failing keychain sends no bearer");
    assert!(first["messages"][1]["content"].as_str().is_some_and(|c| c.contains("how complete is my data?")));
}

#[test]
fn the_gate_reads_the_saved_settings_again_before_every_request_and_off_stops_the_next_question() {
    let dir = scratch();
    let (app, config, _serial) = rig(&dir);
    let handle = app.handle().clone();
    let server = Server::start(vec![Step::text("first answer")]);
    settings::save(&config, &local(server.port)).expect("save settings");
    let reply = tauri::async_runtime::block_on(coach_ask(handle.clone(), "one".into())).expect("an answer");
    assert_eq!(reply.text, "first answer");

    settings::save(&config, &Settings::default()).expect("switch off");
    let error = tauri::async_runtime::block_on(coach_ask(handle.clone(), "two".into())).expect_err("off");
    assert_eq!((error.code, error.sends, error.trace.len()), ("off", 0, 0));
    let (accepts, _) = server.finish();
    assert_eq!(accepts, 1, "the second question never reached the provider");
}
