//! The Import screen's way in (pitch 7b-3). The egress guards allow no dialog plugin and no path chosen by the
//! webview, so the path comes from the OS: the main window's drag-and-drop event reaches [`handle_drop`] here, in
//! Rust, and the core's `import.run` is called from here. The webview never sends a path and never reads one; it
//! hears `core://import` events (`started`, `done`, `failed`) and the core's own `progress` events.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tauri::{Emitter, Manager, Runtime};

use crate::live::CoreDoor;
use crate::sidecar::CoreError;

/// The one fixed refusal text.
pub const REFUSAL: &str = "Drop one export zip or one copied watch folder";

/// What the dropped thing is: an account export (a `.zip` file) or a copied watch folder (a directory).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Export,
    Usb,
}

impl Kind {
    /// The word the events carry and the Import screen reads.
    pub fn word(self) -> &'static str {
        match self {
            Kind::Export => "export",
            Kind::Usb => "usb",
        }
    }
}

/// Exactly one path; a `.zip` file is an export, a directory is a copied watch folder, anything else (two paths,
/// none, a missing path, another kind of file) is refused.
pub fn classify(paths: &[PathBuf]) -> Result<(Kind, &Path), &'static str> {
    let [path] = paths else { return Err(REFUSAL) };
    if path.is_dir() {
        return Ok((Kind::Usb, path));
    }
    let zip = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip"));
    if zip && path.is_file() {
        return Ok((Kind::Export, path));
    }
    Err(REFUSAL)
}

fn failed(error: &CoreError) -> Value {
    json!({ "state": "failed", "code": error.code, "message": error.message })
}

/// Call `import.run` through the door and tell `emit` ("core://import", payload) what happens. The counts of the
/// core's answer ride on `done`; a core error (including `busy`) is a `failed` carrying the core's code.
pub async fn run_import(door: &dyn CoreDoor, emit: &(dyn Fn(&str, Value) + Sync), path: &Path, kind: Kind) {
    emit("core://import", json!({ "state": "started", "kind": kind.word() }));
    let transport = match kind {
        Kind::Export => "export",
        Kind::Usb => "usb",
    };
    let answer = door.call("import.run", json!({ "path": path.to_string_lossy(), "transport": transport })).await;
    let payload = match answer {
        Ok(counts) => {
            let n = |k: &str| counts.get(k).cloned().unwrap_or(Value::Null);
            json!({ "state": "done", "kind": kind.word(), "run_id": n("run_id"), "files": n("files"), "ok": n("ok"),
                    "partial": n("partial"), "duplicate": n("duplicate"), "failed": n("failed") })
        }
        Err(e) => failed(&e),
    };
    emit("core://import", payload);
}

/// The drop entry point (a real drop and the debug door both end here). Classifies, refuses with `bad_drop`, or
/// runs the import on the async runtime so the window never waits for it.
pub fn handle_drop<R: Runtime>(app: &tauri::AppHandle<R>, paths: Vec<PathBuf>) {
    let (kind, path) = match classify(&paths) {
        Ok((kind, path)) => (kind, path.to_path_buf()),
        Err(text) => {
            let _ = app.emit("core://import", json!({ "state": "failed", "code": "bad_drop", "message": text }));
            return;
        }
    };
    let Some(core) = app.try_state::<crate::Core>().and_then(|c| c.0.clone().ok()) else {
        let e = CoreError::new("core_unavailable", "the core is not running");
        let _ = app.emit("core://import", failed(&e));
        return;
    };
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let emit = |name: &str, payload: Value| {
            let _ = app.emit(name, payload);
        };
        run_import(&core, &emit, &path, kind).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("disconect-drop-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn a_zip_file_is_an_export_and_a_directory_is_a_watch_folder() {
        let dir = scratch("kinds");
        let zip = dir.join("export.ZIP");
        std::fs::write(&zip, b"x").expect("write");
        assert_eq!(classify(std::slice::from_ref(&zip)).map(|(k, _)| k), Ok(Kind::Export));
        assert_eq!(classify(&[dir.clone()]).map(|(k, _)| k), Ok(Kind::Usb));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_paths_none_a_missing_path_and_another_file_are_refused_with_the_fixed_text() {
        let dir = scratch("refused");
        let other = dir.join("notes.txt");
        let zip = dir.join("a.zip");
        std::fs::write(&other, b"x").expect("write");
        std::fs::write(&zip, b"x").expect("write");
        assert_eq!(classify(&[zip.clone(), dir.clone()]).err(), Some(REFUSAL));
        assert_eq!(classify(&[]).err(), Some(REFUSAL));
        assert_eq!(classify(&[dir.join("gone.zip")]).err(), Some(REFUSAL), "a zip name that is not there");
        assert_eq!(classify(&[other]).err(), Some(REFUSAL));
        assert_eq!(REFUSAL, "Drop one export zip or one copied watch folder");
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct Fake(Result<Value, CoreError>, Mutex<Vec<(String, Value)>>);

    impl CoreDoor for Fake {
        fn call<'a>(&'a self, method: &'a str, params: Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, CoreError>> + Send + 'a>> {
            self.1.lock().expect("calls").push((method.to_string(), params));
            let answer = self.0.clone();
            Box::pin(async move { answer })
        }
    }

    fn drive(door: &Fake, kind: Kind) -> Vec<Value> {
        let seen = Mutex::new(Vec::new());
        let emit = |name: &str, payload: Value| {
            assert_eq!(name, "core://import");
            seen.lock().expect("seen").push(payload);
        };
        tauri::async_runtime::block_on(run_import(door, &emit, Path::new("/scratch/in"), kind));
        seen.into_inner().expect("seen")
    }

    #[test]
    fn the_events_are_started_then_done_with_the_counts_and_the_call_names_the_transport() {
        let counts = json!({ "run_id": 7, "files": 3, "ok": 2, "partial": 0, "duplicate": 1, "failed": 0 });
        let door = Fake(Ok(counts), Mutex::new(Vec::new()));
        let events = drive(&door, Kind::Export);
        assert_eq!(events[0], json!({ "state": "started", "kind": "export" }));
        assert_eq!(events[1], json!({ "state": "done", "kind": "export", "run_id": 7, "files": 3, "ok": 2, "partial": 0, "duplicate": 1, "failed": 0 }));
        let calls = door.1.lock().expect("calls");
        assert_eq!(calls[0].0, "import.run");
        assert_eq!(calls[0].1, json!({ "path": "/scratch/in", "transport": "export" }));
    }

    #[test]
    fn a_busy_core_is_a_failed_event_with_the_core_code() {
        let door = Fake(Err(CoreError::new("busy", "an import or a sync is already running")), Mutex::new(Vec::new()));
        let events = drive(&door, Kind::Usb);
        assert_eq!(events[0], json!({ "state": "started", "kind": "usb" }));
        assert_eq!(events[1], json!({ "state": "failed", "code": "busy", "message": "an import or a sync is already running" }));
        assert_eq!(door.1.lock().expect("calls")[0].1["transport"], "usb");
    }
}
