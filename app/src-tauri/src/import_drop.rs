//! The Import screen's way in (pitch 7b-3). The egress guards allow no dialog plugin and no path chosen by the
//! webview, so the path comes from the OS: the main window's drag-and-drop event reaches [`handle_drop`] here, in
//! Rust, and the core's `import.run` is called from here. The webview never sends a path and never reads one; it
//! hears `core://import` events (`started`, `done`, `failed`) and the core's own `progress` events.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// The fixed text for a path that is gone by the time the core looks (the core's own message names the path).
pub const GONE: &str = "The item is gone; drop it again.";

/// Exactly one path, judged by what it is: a directory that looks like an unzipped account export is an export, any
/// other directory is a copied watch folder, a `.zip` file is an export only when it holds an export's folder, and
/// anything else (two paths, none, a missing path, another kind of file, a zip that is not an export) is refused.
pub fn classify(paths: &[PathBuf]) -> Result<(Kind, &Path), &'static str> {
    let [path] = paths else { return Err(REFUSAL) };
    if path.is_dir() {
        let kind = if disconect_core::sources::looks_like_export(path) { Kind::Export } else { Kind::Usb };
        return Ok((kind, path));
    }
    let zip = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip"));
    if zip && path.is_file() && disconect_core::sources::looks_like_export(path) {
        return Ok((Kind::Export, path));
    }
    Err(REFUSAL)
}

/// What a drop becomes: a refusal with its fixed text, or an import of this kind and path.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Refuse(&'static str),
    Run(Kind, PathBuf),
}

pub fn decide(paths: &[PathBuf]) -> Decision {
    match classify(paths) {
        Ok((kind, path)) => Decision::Run(kind, path.to_path_buf()),
        Err(text) => Decision::Refuse(text),
    }
}

fn failed(error: &CoreError) -> Value {
    // the core's `not_found` message carries the path; the page gets a fixed text instead
    let message = if error.code == "not_found" { GONE } else { error.message.as_str() };
    json!({ "state": "failed", "code": error.code, "message": message })
}

/// A drop that lands while a sync tick or a click holds the core's one task slot hears `busy` for well under a
/// second (BL-6, 19a review): the drop waits for the slot this long, in these steps, before it fails.
pub const BUSY_WAIT: std::time::Duration = std::time::Duration::from_millis(250);
pub const BUSY_TRIES: usize = 8;

/// Drops whose [`run_import_waiting`] is running now. Only the first drop waits for the slot: a drop that starts
/// while another is in flight gets no retries, so it fails `busy` at once and the page's count of extra drops stays
/// true (BL-6 review S1: otherwise a second drop could win the slot as the first import ended and run untracked).
static DROPS_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

struct InFlight(bool);

impl InFlight {
    fn enter() -> Self {
        InFlight(DROPS_IN_FLIGHT.fetch_add(1, Ordering::SeqCst) == 0)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        DROPS_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Call `import.run` through the door and tell `emit` ("core://import", payload) what happens. The counts of the
/// core's answer ride on `done`; a core error (including `busy`) is a `failed` carrying the core's code.
pub async fn run_import(door: &dyn CoreDoor, emit: &(dyn Fn(&str, Value) + Sync), path: &Path, kind: Kind) {
    run_import_waiting(door, emit, path, kind, BUSY_WAIT, BUSY_TRIES).await;
}

/// [`run_import`] with the wait for a busy slot as parameters (the tests run it in milliseconds).
pub async fn run_import_waiting(
    door: &dyn CoreDoor,
    emit: &(dyn Fn(&str, Value) + Sync),
    path: &Path,
    kind: Kind,
    wait: std::time::Duration,
    tries: usize,
) {
    let flight = InFlight::enter();
    let tries = if flight.0 { tries } else { 0 };
    emit("core://import", json!({ "state": "started", "kind": kind.word() }));
    let transport = match kind {
        Kind::Export => "export",
        Kind::Usb => "usb",
    };
    let params = json!({ "path": path.to_string_lossy(), "transport": transport });
    let mut answer = door.call("import.run", params.clone()).await;
    let mut left = tries;
    while left > 0 && answer.as_ref().is_err_and(|e| e.code == "busy") {
        tokio::time::sleep(wait).await;
        answer = door.call("import.run", params.clone()).await;
        left -= 1;
    }
    let payload = match answer {
        Ok(counts) => {
            let n = |k: &str| counts.get(k).cloned().unwrap_or(Value::Null);
            json!({ "state": "done", "kind": kind.word(), "run_id": n("run_id"), "files": n("files"), "ok": n("ok"),
                    "partial": n("partial"), "duplicate": n("duplicate"), "failed": n("failed") })
        }
        Err(e) => failed(&e),
    };
    emit("core://import", payload);
    drop(flight);
}

/// The drop entry point (a real drop and the debug door both end here). Classifies, refuses with `bad_drop`, or
/// runs the import on the async runtime so the window never waits for it.
pub fn handle_drop<R: Runtime>(app: &tauri::AppHandle<R>, paths: Vec<PathBuf>) {
    let (kind, path) = match decide(&paths) {
        Decision::Run(kind, path) => (kind, path),
        Decision::Refuse(text) => {
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

    /// A one-entry stored zip named like an export's folder (`looks_like_export` reads only the entry names).
    fn tiny_zip(path: &Path, entry: &str) {
        let name = entry.as_bytes();
        let n = name.len() as u16;
        let mut z = Vec::new();
        z.extend(0x0403_4b50u32.to_le_bytes());
        z.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // version, flags, method, time, date
        z.extend([0u8; 12]); // crc, sizes
        z.extend(n.to_le_bytes());
        z.extend([0, 0]);
        z.extend(name);
        let cd_at = z.len() as u32;
        z.extend(0x0201_4b50u32.to_le_bytes());
        z.extend([20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend([0u8; 12]);
        z.extend(n.to_le_bytes());
        z.extend([0u8; 12]); // extra, comment, disk, internal attrs, external attrs (4 bytes: 2+2+2+2+4 = 12)
        z.extend([0u8; 4]); // local header offset
        z.extend(name);
        let cd_len = z.len() as u32 - cd_at;
        z.extend(0x0605_4b50u32.to_le_bytes());
        z.extend([0, 0, 0, 0, 1, 0, 1, 0]);
        z.extend(cd_len.to_le_bytes());
        z.extend(cd_at.to_le_bytes());
        z.extend([0, 0]);
        std::fs::write(path, z).expect("write zip");
    }

    #[test]
    fn an_export_zip_and_an_unzipped_export_are_exports_and_another_directory_is_a_watch_folder() {
        let dir = scratch("kinds");
        let zip = dir.join("export.ZIP");
        tiny_zip(&zip, &format!("{}/a.json", disconect_core::sources::EXPORT_ROOT));
        assert_eq!(classify(std::slice::from_ref(&zip)).map(|(k, _)| k), Ok(Kind::Export));
        assert_eq!(classify(std::slice::from_ref(&dir)).map(|(k, _)| k), Ok(Kind::Usb));
        let unzipped = dir.join("unzipped");
        std::fs::create_dir_all(unzipped.join(disconect_core::sources::EXPORT_ROOT)).expect("mkdir");
        assert_eq!(classify(&[unzipped]).map(|(k, _)| k), Ok(Kind::Export));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_paths_none_a_missing_path_another_file_and_a_zip_that_is_not_an_export_are_refused_with_the_fixed_text() {
        let dir = scratch("refused");
        let other = dir.join("notes.txt");
        let zip = dir.join("a.zip");
        std::fs::write(&other, b"x").expect("write");
        std::fs::write(&zip, b"not a zip at all").expect("write");
        assert_eq!(classify(&[zip.clone(), dir.clone()]).err(), Some(REFUSAL));
        assert_eq!(classify(&[]).err(), Some(REFUSAL));
        assert_eq!(classify(&[dir.join("gone.zip")]).err(), Some(REFUSAL), "a zip name that is not there");
        assert_eq!(classify(&[other]).err(), Some(REFUSAL));
        assert_eq!(classify(&[zip]).err(), Some(REFUSAL), "a .zip of random bytes");
        let other_zip = dir.join("other.zip");
        tiny_zip(&other_zip, "somewhere/else.json");
        assert_eq!(classify(&[other_zip]).err(), Some(REFUSAL), "a real zip that is not an export");
        assert_eq!(REFUSAL, "Drop one export zip or one copied watch folder");
        assert_eq!(decide(&[]), Decision::Refuse(REFUSAL));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_dropped_paths_emit_exactly_one_bad_drop_failure_and_no_started() {
        use tauri::Listener;
        let app = tauri::test::mock_builder().build(tauri::test::mock_context(tauri::test::noop_assets())).expect("mock app");
        let (tx, rx) = std::sync::mpsc::channel();
        app.handle().listen("core://import", move |event| {
            let _ = tx.send(serde_json::from_str::<Value>(event.payload()).expect("json payload"));
        });
        handle_drop(app.handle(), vec![PathBuf::from("/a"), PathBuf::from("/b")]);
        let first = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("one event");
        assert_eq!(first, json!({ "state": "failed", "code": "bad_drop", "message": REFUSAL }));
        assert!(rx.recv_timeout(std::time::Duration::from_millis(300)).is_err(), "no second event, no started");
    }

    #[test]
    fn a_not_found_core_error_reaches_the_page_without_its_path() {
        let door = Fake(Err(CoreError::new("not_found", "no such file or folder: /Users/someone/secret")), Mutex::new(Vec::new()));
        let events = drive(&door, Kind::Usb);
        assert_eq!(events[1], json!({ "state": "failed", "code": "not_found", "message": GONE }));
    }

    struct Fake(Result<Value, CoreError>, Mutex<Vec<(String, Value)>>);

    impl CoreDoor for Fake {
        fn call<'a>(&'a self, method: &'a str, params: Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, CoreError>> + Send + 'a>> {
            self.1.lock().expect("calls").push((method.to_string(), params));
            let answer = self.0.clone();
            Box::pin(async move { answer })
        }
    }

    /// Busy for the first `n` calls, then the answer (a tick that holds the slot and lets go).
    struct BusyThen(usize, Result<Value, CoreError>, Mutex<Vec<(String, Value)>>);

    impl CoreDoor for BusyThen {
        fn call<'a>(&'a self, method: &'a str, params: Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, CoreError>> + Send + 'a>> {
            let mut calls = self.2.lock().expect("calls");
            calls.push((method.to_string(), params));
            let answer = if calls.len() <= self.0 { Err(CoreError::new("busy", "an import or a sync is already running")) } else { self.1.clone() };
            Box::pin(async move { answer })
        }
    }

    /// The drops-in-flight count is one static: tests that drive an import run one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn drive_waiting(door: &dyn CoreDoor, kind: Kind, tries: usize) -> Vec<Value> {
        let _one = serial();
        let seen = Mutex::new(Vec::new());
        let emit = |name: &str, payload: Value| {
            assert_eq!(name, "core://import");
            seen.lock().expect("seen").push(payload);
        };
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().expect("runtime");
        rt.block_on(run_import_waiting(door, &emit, Path::new("/scratch/in"), kind, std::time::Duration::from_millis(1), tries));
        seen.into_inner().expect("seen")
    }

    #[test]
    fn a_drop_that_hears_busy_waits_for_the_slot_and_then_imports() {
        let counts = json!({ "run_id": 3, "files": 1, "ok": 1, "partial": 0, "duplicate": 0, "failed": 0 });
        let door = BusyThen(3, Ok(counts), Mutex::new(Vec::new()));
        let events = drive_waiting(&door, Kind::Export, BUSY_TRIES);
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(events[0], json!({ "state": "started", "kind": "export" }));
        assert_eq!(events[1]["state"], "done");
        assert_eq!(events[1]["run_id"], 3);
        assert_eq!(door.2.lock().expect("calls").len(), 4, "three busy answers, then the import");
    }

    #[test]
    fn a_drop_that_hears_busy_past_the_wait_fails_with_the_core_code() {
        let door = BusyThen(usize::MAX, Ok(json!({})), Mutex::new(Vec::new()));
        let events = drive_waiting(&door, Kind::Usb, BUSY_TRIES);
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(events[1]["code"], "busy");
        assert_eq!(door.2.lock().expect("calls").len(), BUSY_TRIES + 1, "the first try and every retry");
    }

    #[test]
    fn a_second_drop_while_the_first_waits_for_the_slot_fails_busy_at_once() {
        let _one = serial();
        let counts = json!({ "run_id": 5, "files": 1, "ok": 1, "partial": 0, "duplicate": 0, "failed": 0 });
        let first = BusyThen(3, Ok(counts), Mutex::new(Vec::new()));
        let second = BusyThen(usize::MAX, Ok(json!({})), Mutex::new(Vec::new()));
        let seen_first = Mutex::new(Vec::new());
        let seen_second = Mutex::new(Vec::new());
        let emit_first = |_: &str, payload: Value| seen_first.lock().expect("seen").push(payload);
        let emit_second = |_: &str, payload: Value| seen_second.lock().expect("seen").push(payload);
        let wait = std::time::Duration::from_millis(1);
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().expect("runtime");
        rt.block_on(async {
            tokio::join!(
                run_import_waiting(&first, &emit_first, Path::new("/scratch/one"), Kind::Export, wait, BUSY_TRIES),
                run_import_waiting(&second, &emit_second, Path::new("/scratch/two"), Kind::Export, wait, BUSY_TRIES),
            );
        });
        let first_events = seen_first.into_inner().expect("seen");
        let second_events = seen_second.into_inner().expect("seen");
        assert_eq!(first_events[1]["state"], "done", "the first drop waited and imported: {first_events:?}");
        assert_eq!(first.2.lock().expect("calls").len(), 4);
        assert_eq!(second_events.len(), 2, "{second_events:?}");
        assert_eq!(second_events[1]["code"], "busy", "the second drop never waited: {second_events:?}");
        assert_eq!(second.2.lock().expect("calls").len(), 1, "one try, no retry");
        assert_eq!(DROPS_IN_FLIGHT.load(Ordering::SeqCst), 0, "both flights ended");
    }

    fn drive(door: &Fake, kind: Kind) -> Vec<Value> {
        let _one = serial();
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

    /// Runs under the production timer (`BUSY_WAIT` × `BUSY_TRIES`, about two seconds): the proof that `run_import`
    /// really retries that many times on a core that stays busy.
    #[test]
    fn a_busy_core_is_a_failed_event_with_the_core_code() {
        let door = Fake(Err(CoreError::new("busy", "an import or a sync is already running")), Mutex::new(Vec::new()));
        let events = drive(&door, Kind::Usb);
        assert_eq!(events[0], json!({ "state": "started", "kind": "usb" }));
        assert_eq!(events[1], json!({ "state": "failed", "code": "busy", "message": "an import or a sync is already running" }));
        let calls = door.1.lock().expect("calls");
        assert_eq!(calls[0].1["transport"], "usb");
        assert_eq!(calls.len(), BUSY_TRIES + 1, "the first try and every retry under the production timer");
    }
}
