// SPDX-License-Identifier: AGPL-3.0-or-later
//! The in-process core (Bet 12a) against the sidecar and against hostile input. All data is the
//! committed synthetic stores; every store is a scratch copy, HOME is a scratch folder, the clock is
//! pinned and the keychain is switched off for the whole test process.
//!
//! * wire bytes: the lines the in-process thread writes equal, byte for byte, the lines
//!   `disconect-core serve` writes for the same requests (`target/debug/disconect-core`, built from
//!   `../../core`; the test says so and fails if it is missing);
//! * the router path (`Sidecar::start_inproc`) answers the same results;
//! * a `.fit` that really panics fitparser (`hdr255`: `header_size = 255` + a nonzero header CRC) imported
//!   in-process fails the file, not the app, and the next `app.info` answers (plus the `panic = "unwind"`
//!   profile read from `Cargo.toml`, and a core thread that panics and is restarted);
//! * the passphrase environment variable is never an unlock path in-process.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, Once};
use std::time::Duration;

use disconect_app_lib::inproc::{self, ChannelReader, LineSink};
use disconect_app_lib::sidecar::{EventSink, Sidecar};
use disconect_core::serve::Session;
use serde_json::{json, Value};

const NOW: &str = "2025-07-02T09:30:00Z";
const PASSPHRASE: &str = "core-test-passphrase-2026"; // the committed fixture key's passphrase (synthetic)

/// The core crate, spelled so that the one `../../core` => `../../core` rewrite of the standalone
/// repository's history split reaches it.
fn core_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core")
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> Scratch {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "disconect-inproc-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("mkdir");
    Scratch(dir)
}

/// Pin the process's own environment before any core thread exists.
fn env_init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let home =
            std::env::temp_dir().join(format!("disconect-inproc-home-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&home);
        std::env::set_var("HOME", &home);
        std::env::set_var("DISCONECT_NOW", NOW);
        std::env::set_var("DISCONECT_KEYCHAIN", "fail");
        // set for the whole process, from the start: the in-process core must ignore it everywhere
        std::env::set_var("DISCONECT_PASSPHRASE", PASSPHRASE);
    });
}

fn synthetic_copy(dir: &Scratch, name: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../disconect/tests/fixtures/serve/synthetic.hbdb");
    let dst = dir.0.join(name);
    std::fs::copy(src, &dst).expect("copy the synthetic store");
    dst
}

#[derive(Default)]
struct Lines(Mutex<Vec<String>>);

impl LineSink for Lines {
    fn line(&self, line: &str) {
        self.0.lock().expect("lines").push(line.to_string());
    }
}

/// Feed `input` to the in-process thread as raw bytes, wait for it to finish, return the lines it wrote.
fn inproc_lines(db: &Path, input: &str) -> Vec<String> {
    env_init();
    let sink = Arc::new(Lines::default());
    let (done_tx, done_rx) = mpsc::channel();
    let core = inproc::start(
        db.to_path_buf(),
        inproc::serve_runner,
        sink.clone(),
        move |p| {
            let _ = done_tx.send(p);
        },
    )
    .expect("core thread");
    core.send_raw(input.as_bytes()).expect("send");
    core.close_and_wait();
    assert!(
        !done_rx.recv().expect("end"),
        "the in-process core panicked"
    );
    let out = sink.0.lock().expect("lines").clone();
    out
}

fn core_binary() -> PathBuf {
    // On iOS the comparison binary is the simulator build of the core (a macOS one cannot run there).
    let triple = if cfg!(target_os = "ios") { "aarch64-apple-ios-sim/" } else { "" };
    let bin = core_dir().join(format!("target/{triple}debug/disconect-core"));
    assert!(
        bin.is_file(),
        "build the sidecar to compare with: cargo build in projects/disconect-core"
    );
    bin
}

/// After `Command::env_clear()`: put back the three variables a child needs to start inside the iOS
/// simulator (bisected 2026-10-06, 12-C: `DYLD_ROOT_PATH`, `SIMULATOR_ROOT`, `SIMULATOR_SHARED_RESOURCES_DIRECTORY`;
/// see `disconect-core/tests/common/mod.rs`). A no-op off iOS.
fn simulator_env(cmd: &mut Command) -> &mut Command {
    if cfg!(target_os = "ios") {
        for name in ["DYLD_ROOT_PATH", "SIMULATOR_ROOT", "SIMULATOR_SHARED_RESOURCES_DIRECTORY"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
    }
    cmd
}

/// `disconect-core --db DB` (serve), the way `serve_diff.py` runs it: controlled environment.
fn sidecar_lines(db: &Path, input: &str) -> Vec<String> {
    let home = std::env::temp_dir().join(format!("disconect-inproc-home-{}", std::process::id()));
    let mut command = Command::new(core_binary());
    command.arg("--db").arg(db).env_clear();
    simulator_env(&mut command);
    let mut child = command
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("DISCONECT_NOW", NOW)
        .env("DISCONECT_KEYCHAIN", "fail")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the sidecar");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(input.as_bytes()).expect("write");
    drop(stdin);
    let lines: Vec<String> = BufReader::new(child.stdout.take().expect("stdout"))
        .lines()
        .map(|l| l.expect("line"))
        .collect();
    assert!(child.wait().expect("wait").success());
    lines
}

fn requests(items: &[(&str, Value)]) -> String {
    items
        .iter()
        .enumerate()
        .map(|(i, (m, p))| format!("{}\n", json!({"id": i + 1, "method": m, "params": p})))
        .collect()
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn in_process_lines_equal_the_sidecars_byte_for_byte() {
    env_init();
    let dir = scratch();
    let db = synthetic_copy(&dir, "synthetic.hbdb");
    let input = requests(&[
        ("app.info", json!({})),
        ("key.status", json!({})),
        ("data.health", json!({"window_days": 30})),
        ("data.today", json!({})),
        ("data.facts", json!({"days": 7, "baseline_days": 28})),
        (
            "data.metric",
            json!({"metric": "steps", "scope": "day", "days": 14}),
        ),
        ("import.last", json!({})),
        ("nope.nothing", json!({})),
        ("data.metric", json!({"metric": 1})),
    ]);
    let inside = inproc_lines(&db, &input);
    let outside = sidecar_lines(&db, &input);
    assert_eq!(inside.len(), 9);
    assert_eq!(inside, outside, "the two cores wrote different bytes");
    let info: Value = serde_json::from_str(&inside[0]).expect("json");
    assert_eq!(info["result"]["product"], "DISCOnect");
    let health: Value = serde_json::from_str(&inside[2]).expect("json");
    assert!(
        health["result"].is_object(),
        "data.health answered: {health}"
    );
}

struct Collect(Mutex<Vec<(String, Value)>>);

impl EventSink for Collect {
    fn emit(&self, name: &str, payload: Value) {
        self.0
            .lock()
            .expect("events")
            .push((name.to_string(), payload));
    }
}

fn collect() -> Arc<Collect> {
    Arc::new(Collect(Mutex::new(Vec::new())))
}

#[tokio::test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
async fn the_router_path_answers_what_the_sidecar_answers() {
    env_init();
    let dir = scratch();
    let db = synthetic_copy(&dir, "synthetic.hbdb");
    let core = Sidecar::start_inproc(db.clone(), collect()).expect("in-process core");
    assert!(core.is_inproc());
    let input = requests(&[
        ("app.info", json!({})),
        ("data.health", json!({"window_days": 30})),
        ("data.today", json!({})),
    ]);
    let outside: Vec<Value> = sidecar_lines(&db, &input)
        .iter()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();

    let info = core.call("app.info", json!({})).await.expect("app.info");
    assert!(
        info["core"]
            .as_str()
            .expect("core")
            .ends_with(" (in-process)"),
        "the About card says where the core runs"
    );
    for (i, method, params) in [
        (1usize, "data.health", json!({"window_days": 30})),
        (2, "data.today", json!({})),
    ] {
        let got = core.call(method, params).await.expect(method);
        assert_eq!(
            got, outside[i]["result"],
            "{method} differs from the sidecar's"
        );
    }
    // the passphrase path is refused on the plain call, exactly as for a child
    let refused = core
        .call("key.unlock", json!({"passphrase": "x"}))
        .await
        .unwrap_err();
    assert_eq!(refused.code, "bad_params");
    core.shutdown();
}

#[tokio::test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
async fn a_fit_that_panics_the_parser_fails_the_file_not_the_app() {
    env_init();
    let dir = scratch();
    let db = synthetic_copy(&dir, "synthetic.hbdb");
    let inbox = dir.0.join("inbox");
    std::fs::create_dir_all(&inbox).expect("mkdir");
    std::fs::copy(
        core_dir().join("tests/fixtures/synthetic/hdr255.fit.bin"),
        inbox.join("hdr255.fit"),
    )
    .expect("copy hdr255");
    let events = collect();
    let core = Sidecar::start_inproc(db, events.clone()).expect("in-process core");

    let run = tokio::time::timeout(
        Duration::from_secs(120),
        core.call("import.run", json!({"path": inbox.to_string_lossy()})),
    )
    .await
    .expect("the import finished");
    let result = run.expect("the import answered with a result, not a bridge failure");
    assert_eq!(result["files"], 1);
    assert_eq!(result["failed"], 1, "the failure is reported: {result}");
    assert_eq!(result["ok"], 0);
    // the input is the review's: a 14-byte header declaring `header_size = 255` with a nonzero CRC makes
    // fitparser itself panic (it slices `input[0..253]`); the core's `catch_unwind` turns that into a failed
    // file. Guard that the bytes still panic the parser in this build (a fitparser upgrade that fixed it
    // would otherwise leave this test proving nothing):
    let bytes = std::fs::read(core_dir().join("tests/fixtures/synthetic/hdr255.fit.bin")).expect("read hdr255");
    let direct = disconect_core::fit::decode_fit(&bytes).expect_err("hdr255 does not decode");
    assert_eq!(direct.kind, "unrecognized_payload");
    assert!(direct.message.contains("parser panicked on this input"), "{}", direct.message);
    // the same thread is still serving, and recorded the failed run (newest first)
    let info = core
        .call("app.info", json!({}))
        .await
        .expect("app.info after the bad file");
    assert_eq!(info["product"], "DISCOnect");
    let last = core
        .call("import.last", json!({}))
        .await
        .expect("import.last");
    assert_eq!(
        last["runs"][0]["status"], "failed",
        "the newest run is the bad file's: {last}"
    );
    assert_eq!(last["runs"][0]["files_failed"], 1);
    let names: Vec<String> = events
        .0
        .lock()
        .expect("events")
        .iter()
        .map(|(n, _)| n.clone())
        .collect();
    assert!(
        !names.contains(&"core://exited".to_string())
            && !names.contains(&"core://restarted".to_string()),
        "{names:?}"
    );
    core.shutdown();
}

#[test]
fn the_release_profile_unwinds_and_the_dev_profile_keeps_argon_fast() {
    let toml = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("Cargo.toml");
    let code: Vec<&str> = toml
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();
    assert!(
        code.contains(&"panic = \"unwind\""),
        "panic = \"unwind\" is what makes the core's two catch_unwind sites work"
    );
    assert!(
        !code.iter().any(|l| l.contains("abort")),
        "no profile may abort on panic"
    );
    for pkg in ["argon2", "blake2"] {
        let at = code
            .iter()
            .position(|l| *l == format!("[profile.dev.package.{pkg}]"))
            .expect("stanza");
        assert_eq!(code[at + 1], "opt-level = 3");
    }
    // and the build itself unwinds: a panic is catchable here (a test profile always unwinds, so this
    // guards only the harness; the file check above guards the shipped profile)
    assert!(std::panic::catch_unwind(|| panic!("probe")).is_err());
}

static FIRST: AtomicBool = AtomicBool::new(false);

/// A core thread that dies of a panic on its first request, then serves normally after the restart.
fn flaky_runner(session: Session, mut reader: ChannelReader) -> i32 {
    if !FIRST.swap(true, Ordering::SeqCst) {
        let mut byte = [0u8; 1];
        let _ = std::io::Read::read(&mut reader, &mut byte);
        panic!("injected core panic (test)");
    }
    inproc::serve_runner(session, reader)
}

#[tokio::test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
async fn a_core_thread_panic_fails_the_caller_and_restarts_once() {
    env_init();
    let dir = scratch();
    let db = synthetic_copy(&dir, "synthetic.hbdb");
    let events = collect();
    let core = Sidecar::start_inproc_with(db, flaky_runner, events.clone()).expect("core");
    let lost = core.call("app.info", json!({})).await.unwrap_err();
    assert_eq!(lost.code, "core_exited");
    for _ in 0..100 {
        if events
            .0
            .lock()
            .expect("events")
            .iter()
            .any(|(n, _)| n == "core://restarted")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let again = core
        .call("app.info", json!({}))
        .await
        .expect("served after the restart");
    assert_eq!(again["product"], "DISCOnect");
    assert!(
        core.stderr_tail()
            .iter()
            .any(|l| l.contains("internal error")),
        "{:?}",
        core.stderr_tail()
    );
    core.shutdown();
}

#[tokio::test]
async fn the_environment_passphrase_is_never_an_unlock_path_in_process() {
    env_init();
    let dir = scratch();
    let db = dir.0.join("store.hbdb");
    let fixtures = core_dir().join("tests/fixtures");
    std::fs::copy(fixtures.join("empty-v3.hbdb"), &db).expect("copy db");
    std::fs::copy(
        fixtures.join("test.keys.json"),
        dir.0.join("store.hbdb.keys.json"),
    )
    .expect("copy keys");
    assert_eq!(
        std::env::var("DISCONECT_PASSPHRASE").as_deref(),
        Ok(PASSPHRASE),
        "the harness set the variable"
    );
    let core = Sidecar::start_inproc(db, collect()).expect("core");
    let status = core
        .call("key.status", json!({}))
        .await
        .expect("key.status");
    assert_eq!(status["unlocked"], false, "the variable unlocked the store");
    let locked = core.call("data.today", json!({})).await.unwrap_err();
    assert_eq!(locked.code, "locked");
    let no_pass = core.call("key.unlock", json!({})).await.unwrap_err();
    assert_ne!(
        no_pass.code, "",
        "key.unlock without a passphrase uses the (disabled) keychain, never the variable"
    );
    let status = core
        .call("key.status", json!({}))
        .await
        .expect("key.status");
    assert_eq!(status["unlocked"], false);
    // the passphrase itself still works through the unlock path
    let ok = core
        .unlock(zeroize::Zeroizing::new(PASSPHRASE.to_string()))
        .await
        .expect("unlock");
    assert_eq!(ok["unlocked"], true);
    core.shutdown();
}

#[tokio::test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
async fn an_empty_folder_dropped_through_the_import_entry_point_answers_started_then_done_with_zero_files() {
    env_init();
    let dir = scratch();
    let db = synthetic_copy(&dir, "synthetic.hbdb");
    let folder = dir.0.join("copied-watch-folder");
    std::fs::create_dir_all(&folder).expect("mkdir");
    let core = Sidecar::start_inproc(db, collect()).expect("core");
    let (kind, path) = disconect_app_lib::import_drop::classify(std::slice::from_ref(&folder)).expect("a folder");
    let seen = Mutex::new(Vec::new());
    let emit = |name: &str, payload: Value| {
        assert_eq!(name, "core://import");
        seen.lock().expect("seen").push(payload);
    };
    disconect_app_lib::import_drop::run_import(&core, &emit, path, kind).await;
    let seen = seen.into_inner().expect("seen");
    assert_eq!(seen[0], json!({"state": "started", "kind": "usb"}));
    assert_eq!(seen[1]["state"], "done", "{:?}", seen[1]);
    assert_eq!(seen[1]["files"], 0);
    assert_eq!(seen[1]["ok"], 0);
    core.shutdown();
}

#[tokio::test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
async fn data_contract_lists_the_trend_metrics_and_marks_heart_rate_a_sample() {
    // stands in for the un-capturable open Trends select (pitch 7b-6 section 4)
    env_init();
    let dir = scratch();
    let db = synthetic_copy(&dir, "synthetic.hbdb");
    let core = Sidecar::start_inproc(db, collect()).expect("in-process core");
    let c = core.call("data.contract", json!({})).await.expect("data.contract");
    let metrics = c["metrics"].as_array().expect("metrics");
    // the contract's numeric metrics with a declared scope (Python data_contract: 62, heart_rate first, sweat_loss_ml last)
    assert_eq!(metrics.len(), 62, "{} metrics", metrics.len());
    assert_eq!(metrics[0]["metric"], "heart_rate");
    assert_eq!(metrics[61]["metric"], "sweat_loss_ml");
    let hr = metrics.iter().find(|m| m["metric"] == "heart_rate").expect("heart_rate");
    assert_eq!(hr["cadence"], "sample");
    core.shutdown();
}
