// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Watch screen's commands (Bet 9 follow-up, 2026-10-05): start and stop the live link, a read-only
//! Bluetooth session to the watch run by the lab's Python as a child process ([`crate::sidecar::LiveLink`]).
//!
//! Development builds only. The lab (`projects/ble-lab/`) is AGPL and is not bundled with the app, so a
//! release build answers `live_unavailable`; shipping a live link is its own decision (BACKLOG, 02b).
//! The child's readings reach the window as `live://line` events; nothing here reads them.

use std::ffi::OsStr;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tauri::{Emitter, Manager, Runtime, State};

use crate::sidecar::CoreError;
#[cfg(desktop)]
use crate::sidecar::LiveLink;
use crate::sidecar::{EventSink, Sidecar};
use crate::Core;

/// The one live link at a time, or none.
#[derive(Default)]
pub struct LiveState {
    #[cfg(desktop)]
    link: Mutex<Option<LiveLink>>,
    #[cfg(not(desktop))]
    link: Mutex<Option<()>>,
    /// A session ended while the store was locked or busy: its readings wait in the folder for the next unlock or
    /// link end. In memory only: after a restart the next link's end sweeps the whole folder and catches up.
    owed: AtomicBool,
    /// Counts link starts; every `live://stored` event carries the number of the link it belongs to.
    seq: AtomicU64,
}

impl LiveState {
    /// End the link if one runs (also called when the app exits).
    pub fn stop(&self) {
        #[cfg(desktop)]
        if let Some(link) = self.link.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() {
            link.stop();
        }
        #[cfg(not(desktop))]
        self.link.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
    }

    fn running(&self) -> bool {
        #[cfg(desktop)]
        {
            self.link.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref().is_some_and(LiveLink::running)
        }
        #[cfg(not(desktop))]
        {
            false
        }
    }
}

/// The lab's interpreter and script, resolved from this crate's own location: development builds only.
/// `None` when the lab's virtual environment is not there (a release build, or a checkout without it).
///
/// Debug builds only: `DISCONECT_LIVE_LAB=<executable>` replaces the lab's interpreter and script (evidence
/// runs without a watch; the child gets the same `--raw-dir` and the same four environment variables).
pub fn lab_program() -> Option<(PathBuf, Vec<String>)> {
    #[cfg(debug_assertions)]
    {
        let dir = raw_dir()?.to_string_lossy().into_owned();
        if let Some(stub) = std::env::var_os("DISCONECT_LIVE_LAB") {
            return Some((PathBuf::from(stub), vec!["--raw-dir".into(), dir]));
        }
        let lab = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("ble-lab");
        let python = lab.join(".venv").join("bin").join("python");
        let script = lab.join("live.py");
        (python.is_file() && script.is_file()).then(|| (python, vec![script.to_string_lossy().into_owned(), "--raw-dir".into(), dir]))
    }
    #[cfg(not(debug_assertions))]
    {
        None // the checkout path is not even compiled into a release binary
    }
}

/// The readings folder, named by the app: `~/garmin-data/ble` under `home`. The start (`--raw-dir`) and the
/// import sweep both use it.
fn raw_dir_in(home: &OsStr) -> PathBuf {
    PathBuf::from(home).join("garmin-data").join("ble")
}

/// [`raw_dir_in`] for the allow-listed `HOME`; `None` when it is not set.
pub fn raw_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| raw_dir_in(&home))
}

/// What the stopped line adds once the sweep answered: "stored" (>= 1 file imported), "nothing new stored"
/// (none imported, >= 1 duplicate), "not stored (<code>)" otherwise.
pub fn outcome_text(answer: &Result<Value, CoreError>) -> String {
    match answer {
        Err(e) => format!("not stored ({})", e.code),
        Ok(v) => {
            let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
            if n("ok") > 0 {
                "stored".into()
            } else if n("duplicate") > 0 {
                "nothing new stored".into()
            } else if n("failed") > 0 {
                "not stored (failed)".into()
            } else {
                "not stored (no_files)".into()
            }
        }
    }
}

/// What a link's end asks for.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Sweep,
    Owe,
}

/// A link ended: sweep if the store is open (a sweep covers the whole folder, so any debt is cleared), else owe
/// the sweep.
fn on_ended(owed: &AtomicBool, store_open: bool) -> Step {
    if store_open {
        owed.store(false, Ordering::SeqCst);
        Step::Sweep
    } else {
        owed.store(true, Ordering::SeqCst);
        Step::Owe
    }
}

/// An unlock succeeded: true exactly once per debt.
fn on_unlocked(owed: &AtomicBool) -> bool {
    owed.swap(false, Ordering::SeqCst)
}

/// The two core methods the live link uses (`key.status`, `import.run`); the seam the owe/pay tests fake.
pub trait CoreDoor: Send + Sync + 'static {
    fn call<'a>(&'a self, method: &'a str, params: Value) -> Pin<Box<dyn Future<Output = Result<Value, CoreError>> + Send + 'a>>;
}

impl CoreDoor for Sidecar {
    fn call<'a>(&'a self, method: &'a str, params: Value) -> Pin<Box<dyn Future<Output = Result<Value, CoreError>> + Send + 'a>> {
        Box::pin(Sidecar::call(self, method, params))
    }
}

/// Test-only: a fake door in the app's state replaces the real core.
#[cfg(test)]
struct FakeDoor(Arc<dyn CoreDoor>);

fn door_of<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<Arc<dyn CoreDoor>, CoreError> {
    #[cfg(test)]
    if let Some(fake) = app.try_state::<FakeDoor>() {
        return Ok(fake.0.clone());
    }
    app.state::<Core>().0.clone().map(|core| Arc::new(core) as Arc<dyn CoreDoor>)
}

/// Whether the store answers reads and imports now: plaintext, or unlocked.
async fn store_open(door: &dyn CoreDoor) -> Result<bool, CoreError> {
    let s = door.call("key.status", json!({})).await?;
    let flag = |k: &str| s.get(k).and_then(Value::as_bool).unwrap_or(false);
    Ok(!flag("encrypted") || flag("unlocked"))
}

/// Import the readings folder through the core door (the core answers DUPLICATE for files it holds). A `busy`
/// answer (another import or sync running) owes the sweep again.
async fn sweep(door: &dyn CoreDoor, owed: &AtomicBool) -> String {
    let Some(dir) = raw_dir() else { return "not stored (no_home)".into() };
    let answer = door.call("import.run", json!({ "path": dir.to_string_lossy(), "transport": "ble" })).await;
    if answer.as_ref().is_err_and(|e| e.code == "busy") {
        owed.store(true, Ordering::SeqCst);
    }
    outcome_text(&answer)
}

/// A link ended and no other link runs: sweep if the store is open, else owe the sweep (and, if the store was
/// unlocked in between, pay at once). Returns what the stopped line adds.
async fn after_end(door: &dyn CoreDoor, live: &LiveState) -> String {
    match store_open(door).await {
        Err(e) => outcome_text(&Err(e)),
        Ok(open) => match on_ended(&live.owed, open) {
            Step::Sweep => sweep(door, &live.owed).await,
            Step::Owe => match store_open(door).await {
                Ok(true) if on_unlocked(&live.owed) => sweep(door, &live.owed).await,
                _ => "not stored (locked)".into(),
            },
        },
    }
}

fn tell<R: Runtime>(app: &tauri::AppHandle<R>, seq: u64, text: String) {
    let _ = app.emit("live://stored", json!({ "text": text, "seq": seq }));
}

/// The sink the link's events go to: the window's, and one sweep after each `live://ended`. The number is the
/// link's own (`LiveState::seq` at its start); the sweep's `live://stored` event carries it.
pub struct LinkSink<R: Runtime>(pub tauri::AppHandle<R>, pub u64);

impl<R: Runtime> EventSink for LinkSink<R> {
    fn emit(&self, name: &str, payload: Value) {
        let _ = self.0.emit(name, payload);
        if name == "live://ended" {
            let (app, seq) = (self.0.clone(), self.1);
            tauri::async_runtime::spawn(async move {
                let door = match door_of(&app) {
                    Ok(d) => d,
                    Err(e) => return tell(&app, seq, outcome_text(&Err(e))),
                };
                let live = app.state::<LiveState>();
                // A newer link is running: its own end sweeps the whole folder; a sweep now would store its half-written file.
                if live.running() {
                    return;
                }
                tell(&app, seq, after_end(door.as_ref(), &live).await);
            });
        }
    }
}

/// Called after every successful unlock: pays a sweep owed by a link that ended while locked (or busy). While a
/// link runs the debt is kept: that link's end sweeps.
pub fn paid_on_unlock<R: Runtime>(app: &tauri::AppHandle<R>) {
    let live = app.state::<LiveState>();
    if live.running() || !on_unlocked(&live.owed) {
        return;
    }
    let (app, seq) = (app.clone(), live.seq.load(Ordering::SeqCst));
    tauri::async_runtime::spawn(async move {
        if let Ok(door) = door_of(&app) {
            tell(&app, seq, sweep(door.as_ref(), &app.state::<LiveState>().owed).await);
        }
    });
}

fn unavailable() -> CoreError {
    CoreError::new("live_unavailable", "the live link is part of development builds only; this build has no lab to run")
}

/// Start the live link. Refused while one already runs.
#[tauri::command]
pub fn live_start(app: tauri::AppHandle, state: State<'_, LiveState>) -> Result<Value, CoreError> {
    #[cfg(desktop)]
    {
        let (program, args) = lab_program().ok_or_else(unavailable)?;
        let mut slot = state.link.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.as_ref().is_some_and(LiveLink::running) {
            return Err(CoreError::new("live_busy", "the live link is already running"));
        }
        let seq = state.seq.load(Ordering::SeqCst) + 1;
        let link = LiveLink::start(&program, &args, Arc::new(LinkSink(app, seq)))?;
        state.seq.store(seq, Ordering::SeqCst);
        *slot = Some(link);
        Ok(json!({ "running": true, "seq": seq }))
    }
    #[cfg(not(desktop))]
    {
        let _ = (app, state);
        Err(unavailable())
    }
}

/// End the live link (a no-op when none runs).
#[tauri::command]
pub fn live_stop(state: State<'_, LiveState>) -> Result<Value, CoreError> {
    state.stop();
    Ok(json!({ "running": false }))
}

/// Whether the lab is replaced by a stub (`DISCONECT_LIVE_LAB`, debug builds only): the screen then says so,
/// so an evidence run's invented readings are never taken for the watch's.
pub fn stub_lab() -> bool {
    cfg!(debug_assertions) && std::env::var_os("DISCONECT_LIVE_LAB").is_some()
}

/// Whether a link runs, whether this build can start one, and whether a stub stands in for the lab.
#[tauri::command]
pub fn live_state(state: State<'_, LiveState>) -> Result<Value, CoreError> {
    Ok(json!({ "running": state.running(), "available": lab_program().is_some(), "stub": stub_lab(), "seq": state.seq.load(Ordering::SeqCst) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lab_is_found_next_to_the_app_in_a_debug_build_and_never_in_release() {
        let found = lab_program();
        if cfg!(debug_assertions) {
            let (python, args) = found.expect("the checkout carries projects/ble-lab/.venv");
            assert!(python.ends_with(".venv/bin/python"));
            assert_eq!(args.len(), 3);
            assert!(args[0].ends_with("live.py"));
            assert_eq!(args[1], "--raw-dir");
            assert!(args[2].ends_with("garmin-data/ble"));
        } else {
            assert!(found.is_none());
        }
    }

    #[test]
    fn an_empty_state_is_not_running_and_stop_is_a_no_op() {
        let state = LiveState::default();
        assert!(!state.running());
        state.stop();
        assert!(!state.running());
    }

    fn err(code: &str) -> Result<Value, CoreError> {
        Err(CoreError::new(code, "x"))
    }

    #[test]
    fn the_folder_is_under_home_and_the_outcome_words_are_fixed() {
        assert_eq!(raw_dir_in(OsStr::new("/scratch")), PathBuf::from("/scratch/garmin-data/ble"));
        assert_eq!(outcome_text(&Ok(json!({"ok": 1, "duplicate": 2, "failed": 0}))), "stored");
        assert_eq!(outcome_text(&Ok(json!({"ok": 0, "duplicate": 1, "failed": 0}))), "nothing new stored");
        assert_eq!(outcome_text(&Ok(json!({"ok": 0, "duplicate": 0, "failed": 1}))), "not stored (failed)");
        assert_eq!(outcome_text(&Ok(json!({"ok": 0, "duplicate": 0, "failed": 0}))), "not stored (no_files)");
        assert_eq!(outcome_text(&err("busy")), "not stored (busy)");
    }

    #[test]
    fn a_locked_end_owes_one_sweep_that_the_next_unlock_pays_once() {
        let owed = AtomicBool::new(false);
        assert_eq!(on_ended(&owed, true), Step::Sweep);
        assert!(!on_unlocked(&owed), "an open store owes nothing");
        assert_eq!(on_ended(&owed, false), Step::Owe);
        assert_eq!(on_ended(&owed, false), Step::Owe, "two locked ends are still one debt");
        assert!(on_unlocked(&owed));
        assert!(!on_unlocked(&owed), "paid once");
        assert_eq!(on_ended(&owed, false), Step::Owe);
        assert_eq!(on_ended(&owed, true), Step::Sweep);
        assert!(!on_unlocked(&owed), "a sweep covers the whole folder: the debt is gone");
    }

    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::time::Duration;

    use tauri::Listener;

    /// A core that answers `key.status` from a flag and counts `import.run` calls (and answers each with one file stored).
    struct FakeCore {
        locked: AtomicBool,
        imports: AtomicUsize,
        busy: AtomicBool,
    }

    impl CoreDoor for FakeCore {
        fn call<'a>(&'a self, method: &'a str, _params: Value) -> Pin<Box<dyn Future<Output = Result<Value, CoreError>> + Send + 'a>> {
            Box::pin(async move {
                match method {
                    "key.status" => Ok(json!({ "encrypted": true, "unlocked": !self.locked.load(Ordering::SeqCst) })),
                    "import.run" if self.busy.load(Ordering::SeqCst) => Err(CoreError::new("busy", "an import runs")),
                    "import.run" => {
                        self.imports.fetch_add(1, Ordering::SeqCst);
                        Ok(json!({ "ok": 1, "duplicate": 0, "failed": 0 }))
                    }
                    other => Err(CoreError::new("bad_method", other)),
                }
            })
        }
    }

    struct NoSink;

    impl EventSink for NoSink {
        fn emit(&self, _name: &str, _payload: Value) {}
    }

    /// A mock app holding the live state and a fake core, and a channel that receives every `live://stored` payload.
    fn rig() -> (tauri::App<tauri::test::MockRuntime>, Arc<FakeCore>, mpsc::Receiver<Value>) {
        let fake = Arc::new(FakeCore { locked: AtomicBool::new(true), imports: AtomicUsize::new(0), busy: AtomicBool::new(false) });
        let app = tauri::test::mock_builder()
            .manage(LiveState::default())
            .manage(FakeDoor(fake.clone()))
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("mock app");
        let (tx, rx) = mpsc::channel();
        app.handle().listen("live://stored", move |event| {
            let _ = tx.send(serde_json::from_str::<Value>(event.payload()).expect("json payload"));
        });
        (app, fake, rx)
    }

    fn ended(app: &tauri::AppHandle<tauri::test::MockRuntime>, seq: u64) {
        LinkSink(app.clone(), seq).emit("live://ended", json!({ "exit": 0 }));
    }

    const WAIT: Duration = Duration::from_secs(10);

    #[test]
    fn a_link_that_ends_locked_owes_one_debt_and_the_unlock_pays_exactly_one_sweep() {
        let (app, fake, events) = rig();
        let handle = app.handle().clone();
        ended(&handle, 1);
        let told = events.recv_timeout(WAIT).expect("the stopped line is told");
        assert_eq!((told["text"].as_str(), told["seq"].as_u64()), (Some("not stored (locked)"), Some(1)));
        assert_eq!(fake.imports.load(Ordering::SeqCst), 0);
        assert!(handle.state::<LiveState>().owed.load(Ordering::SeqCst), "one debt");
        fake.locked.store(false, Ordering::SeqCst);
        paid_on_unlock(&handle);
        let paid = events.recv_timeout(WAIT).expect("the debt is paid");
        assert_eq!((paid["text"].as_str(), paid["seq"].as_u64()), (Some("stored"), Some(0)));
        paid_on_unlock(&handle); // a second unlock owes nothing
        assert!(events.recv_timeout(Duration::from_millis(300)).is_err());
        assert_eq!(fake.imports.load(Ordering::SeqCst), 1, "exactly one import.run");
    }

    #[test]
    fn an_unlock_between_status_and_ended_pays_at_once_and_a_busy_answer_owes_again() {
        let (app, fake, events) = rig();
        let handle = app.handle().clone();
        fake.locked.store(false, Ordering::SeqCst);
        fake.busy.store(true, Ordering::SeqCst);
        ended(&handle, 4);
        let told = events.recv_timeout(WAIT).expect("told");
        assert_eq!(told["text"].as_str(), Some("not stored (busy)"));
        assert!(handle.state::<LiveState>().owed.load(Ordering::SeqCst), "busy owes the sweep");
        fake.busy.store(false, Ordering::SeqCst);
        paid_on_unlock(&handle);
        assert_eq!(events.recv_timeout(WAIT).expect("paid")["text"].as_str(), Some("stored"));
        assert_eq!(fake.imports.load(Ordering::SeqCst), 1);
    }

    #[cfg(desktop)]
    #[test]
    fn a_running_link_keeps_the_debt_and_nothing_sweeps_until_its_own_end() {
        let (app, fake, events) = rig();
        let handle = app.handle().clone();
        let live = handle.state::<LiveState>();
        live.owed.store(true, Ordering::SeqCst);
        fake.locked.store(false, Ordering::SeqCst);
        // `cat` runs until its stdin closes: a stand-in for a link in progress
        let link = LiveLink::start(std::path::Path::new("/bin/cat"), &[], Arc::new(NoSink)).expect("a running child");
        *live.link.lock().unwrap() = Some(link);
        assert!(live.running());
        paid_on_unlock(&handle);
        ended(&handle, 1); // an earlier link's end arriving while the newer one runs
        assert!(events.recv_timeout(Duration::from_millis(300)).is_err(), "no event while a link runs");
        assert_eq!(fake.imports.load(Ordering::SeqCst), 0, "no sweep while a link runs");
        assert!(live.owed.load(Ordering::SeqCst), "the debt is kept");
        live.stop();
        ended(&handle, 2); // the running link's own end sweeps and clears the debt
        assert_eq!(events.recv_timeout(WAIT).expect("told")["seq"].as_u64(), Some(2));
        assert_eq!(fake.imports.load(Ordering::SeqCst), 1);
        assert!(!live.owed.load(Ordering::SeqCst));
    }
}
