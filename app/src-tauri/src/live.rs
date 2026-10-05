// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Watch screen's commands (Bet 9 follow-up, 2026-10-05): start and stop the live link, a read-only
//! Bluetooth session to the watch run by the lab's Python as a child process ([`crate::sidecar::LiveLink`]).
//!
//! Development builds only. The lab (`projects/ble-lab/`) is AGPL and is not bundled with the app, so a
//! release build answers `live_unavailable`; shipping a live link is its own decision (BACKLOG, 02b).
//! The child's readings reach the window as `live://line` events; nothing here reads them.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tauri::{Manager, State};

use crate::sidecar::CoreError;
#[cfg(desktop)]
use crate::sidecar::LiveLink;
use crate::sidecar::EventSink;
use crate::{Core, WindowSink};

/// The one live link at a time, or none.
#[derive(Default)]
pub struct LiveState {
    #[cfg(desktop)]
    link: Mutex<Option<LiveLink>>,
    #[cfg(not(desktop))]
    link: Mutex<Option<()>>,
    /// A session ended while the store was locked: its readings wait in the folder for the next unlock.
    owed: AtomicBool,
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

/// What the stopped line adds once the sweep answered: "stored" (>= 1 file imported), "already stored"
/// (none imported, >= 1 duplicate), "not stored (<code>)" otherwise.
pub fn outcome_text(answer: &Result<Value, CoreError>) -> String {
    match answer {
        Err(e) => format!("not stored ({})", e.code),
        Ok(v) => {
            let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
            if n("ok") > 0 {
                "stored".into()
            } else if n("duplicate") > 0 {
                "already stored".into()
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

/// A link ended: sweep if the store is open, else owe the sweep.
fn on_ended(owed: &AtomicBool, store_open: bool) -> Step {
    if store_open {
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

/// Whether the store answers reads and imports now: plaintext, or unlocked.
async fn store_open(core: &crate::sidecar::Sidecar) -> Result<bool, CoreError> {
    let s = core.call("key.status", json!({})).await?;
    let flag = |k: &str| s.get(k).and_then(Value::as_bool).unwrap_or(false);
    Ok(!flag("encrypted") || flag("unlocked"))
}

/// Import the readings folder through the core door (the core answers DUPLICATE for files it holds).
async fn sweep(core: &crate::sidecar::Sidecar) -> String {
    let Some(dir) = raw_dir() else { return "not stored (no_home)".into() };
    let answer = core.call("import.run", json!({ "path": dir.to_string_lossy(), "transport": "ble" })).await;
    outcome_text(&answer)
}

fn tell(app: &tauri::AppHandle, text: String) {
    WindowSink(app.clone()).emit("live://stored", json!({ "text": text }));
}

/// The sink the link's events go to: the window's, and one sweep after each `live://ended`.
pub struct LinkSink(pub tauri::AppHandle);

impl EventSink for LinkSink {
    fn emit(&self, name: &str, payload: Value) {
        WindowSink(self.0.clone()).emit(name, payload);
        if name == "live://ended" {
            let app = self.0.clone();
            tauri::async_runtime::spawn(async move {
                let core = match app.state::<Core>().0.clone() {
                    Ok(c) => c,
                    Err(e) => return tell(&app, outcome_text(&Err(e))),
                };
                let open = match store_open(&core).await {
                    Ok(o) => o,
                    Err(e) => return tell(&app, outcome_text(&Err(e))),
                };
                match on_ended(&app.state::<LiveState>().owed, open) {
                    Step::Sweep => tell(&app, sweep(&core).await),
                    Step::Owe => tell(&app, "not stored (locked)".into()),
                }
            });
        }
    }
}

/// Called after every successful unlock: pays a sweep owed by a link that ended while locked.
pub fn paid_on_unlock(app: &tauri::AppHandle) {
    if !on_unlocked(&app.state::<LiveState>().owed) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Ok(core) = app.state::<Core>().0.clone() {
            tell(&app, sweep(&core).await);
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
        let link = LiveLink::start(&program, &args, Arc::new(LinkSink(app)))?;
        *slot = Some(link);
        Ok(json!({ "running": true }))
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

/// Whether a link runs and whether this build can start one.
#[tauri::command]
pub fn live_state(state: State<'_, LiveState>) -> Result<Value, CoreError> {
    Ok(json!({ "running": state.running(), "available": lab_program().is_some() }))
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
        assert_eq!(outcome_text(&Ok(json!({"ok": 0, "duplicate": 1, "failed": 0}))), "already stored");
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
    }
}
