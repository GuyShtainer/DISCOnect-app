// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Watch screen's commands (Bet 9 follow-up, 2026-10-05): start and stop the live link, a read-only
//! Bluetooth session to the watch run by the lab's Python as a child process ([`crate::sidecar::LiveLink`]).
//!
//! Development builds only. The lab (`projects/ble-lab/`) is AGPL and is not bundled with the app, so a
//! release build answers `live_unavailable`; shipping a live link is its own decision (BACKLOG, 02b).
//! The child's readings reach the window as `live://line` events; nothing here reads them.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tauri::State;

use crate::sidecar::CoreError;
#[cfg(desktop)]
use crate::sidecar::LiveLink;
use crate::WindowSink;

/// The one live link at a time, or none.
#[derive(Default)]
pub struct LiveState {
    #[cfg(desktop)]
    link: Mutex<Option<LiveLink>>,
    #[cfg(not(desktop))]
    link: Mutex<Option<()>>,
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
pub fn lab_program() -> Option<(PathBuf, Vec<String>)> {
    #[cfg(debug_assertions)]
    {
        let lab = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("ble-lab");
        let python = lab.join(".venv").join("bin").join("python");
        let script = lab.join("live.py");
        (python.is_file() && script.is_file()).then(|| (python, vec![script.to_string_lossy().into_owned()]))
    }
    #[cfg(not(debug_assertions))]
    {
        None // the checkout path is not even compiled into a release binary
    }
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
        let link = LiveLink::start(&program, &args, Arc::new(WindowSink(app)))?;
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
            assert_eq!(args.len(), 1);
            assert!(args[0].ends_with("live.py"));
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
}
