// SPDX-License-Identifier: AGPL-3.0-or-later
//! The phone as a producer (Bet 19b, I5 row 3): a finished live-session file in the app's own container becomes one
//! `json:live` record under transport `ble`, through the same core call the Mac's live sweep makes
//! (`live.rs::sweep`: `import.run {"path", "transport": "ble"}`), so everything the core already does with a local
//! record applies: `sync.run` pushes it on the next sync and nothing new reaches the wire.
//!
//! The page names no path. The folder is built here (`<app data>/live-in/`); each file in it is checked (a regular
//! file, never a link, canonically inside the app's data or Documents folder, a live-session file in the core's own
//! line format with at least one reading), copied to a staging folder and imported from there, one file per call so the
//! counts are exact. Nothing here reads a watch and nothing transmits.
//!
//! What the phone keeps for its Sync screen is `live-produced.json`: counts and a time span, never a reading.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::live::CoreDoor;
use crate::sidecar::CoreError;
#[cfg(target_os = "ios")]
use tauri::Manager as _;

/// Where session files wait, under the app's data folder.
pub const LIVE_DIR: &str = "live-in";
/// The copy the core reads; removed after each import.
pub const STAGE_DIR: &str = "live-stage";
/// What the Sync screen shows.
pub const LEDGER: &str = "live-produced.json";
/// A session file larger than this is refused (ten minutes of two metrics is a few kilobytes; a day is well under it).
const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FILES: usize = 200;

/// A refusal word; the page maps it to a sentence, the core is never asked.
pub type Why = &'static str;

/// `path` canonically inside one of `roots`, with no link on the way down from the root (the file itself included).
/// Returns the canonical path. A `..` component is refused outright.
pub fn contained(path: &Path, roots: &[PathBuf]) -> Result<PathBuf, Why> {
    let canon = path.canonicalize().map_err(|_| "not_found")?;
    for root in roots {
        let Ok(croot) = root.canonicalize() else { continue };
        if !canon.starts_with(&croot) {
            continue;
        }
        let (base, rel) = match path.strip_prefix(root) {
            Ok(rel) => (root.clone(), rel),
            Err(_) => match path.strip_prefix(&croot) {
                Ok(rel) => (croot.clone(), rel),
                Err(_) => return Err("outside"),
            },
        };
        let mut walk = base;
        for part in rel.components() {
            let Component::Normal(name) = part else { return Err("outside") };
            walk.push(name);
            if std::fs::symlink_metadata(&walk).map_err(|_| "not_found")?.file_type().is_symlink() {
                return Err("link");
            }
        }
        return Ok(canon);
    }
    Err("outside")
}

/// A validated session: how many readings and the span (unix seconds).
#[derive(Debug, PartialEq)]
pub struct Session {
    pub readings: u64,
    pub from: u64,
    pub to: u64,
}

/// Is `bytes` a live-session file in the core's own format (`disconect_core::live::parse_live_file`: one JSON object
/// per line, a reading `{"t","metric","value"}` or a `status`/`stop` line) with at least one reading?
pub fn validate(bytes: &[u8]) -> Result<Session, Why> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err("too_large");
    }
    match disconect_core::live::parse_live_file(bytes) {
        Some(readings) if !readings.is_empty() => {}
        Some(_) => return Err("no_readings"),
        None => return Err("not_a_session"),
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "not_a_session")?;
    let (mut readings, mut from, mut to) = (0u64, f64::MAX, 0f64);
    for line in text.lines() {
        let Ok(Value::Object(o)) = serde_json::from_str::<Value>(line) else { continue };
        if let (Some(t), Some(_), Some(_)) = (o.get("t").and_then(Value::as_f64), o.get("metric"), o.get("value")) {
            readings += 1;
            from = from.min(t);
            to = to.max(t);
        }
    }
    if readings == 0 {
        return Err("no_readings");
    }
    Ok(Session { readings, from: from.floor() as u64, to: to.floor() as u64 })
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ledger {
    pub sessions: u64,
    pub readings: u64,
    pub last_from: Option<u64>,
    pub last_to: Option<u64>,
    pub last_at: Option<u64>,
}

pub fn load_ledger(data: &Path) -> Ledger {
    std::fs::read_to_string(data.join(LEDGER)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save_ledger(data: &Path, ledger: &Ledger) -> std::io::Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = data.join(format!(".{LEDGER}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(&tmp)?;
    f.write_all(serde_json::to_string(ledger).unwrap_or_default().as_bytes())?;
    f.sync_all()?;
    let target = data.join(LEDGER);
    std::fs::rename(&tmp, &target)?;
    #[cfg(target_os = "ios")]
    let _ = crate::ios::exclude_from_backup(&target);
    Ok(())
}

/// Forget this phone takes the files with it (they hold readings).
pub fn forget_in(data: &Path) {
    let _ = std::fs::remove_file(data.join(LEDGER));
    let _ = std::fs::remove_file(data.join(format!(".{LEDGER}.tmp")));
    let _ = std::fs::remove_dir_all(data.join(LIVE_DIR));
    let _ = std::fs::remove_dir_all(data.join(STAGE_DIR));
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn counted(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

/// Import every acceptable file in `<data>/live-in/` as the sweep does and answer counts and the span. A refused file
/// is counted under `refused` and never reaches the core. A core error (locked, busy) ends the run with that error.
pub async fn import_all(door: &dyn CoreDoor, data: &Path, roots: &[PathBuf]) -> Result<Value, CoreError> {
    let dir = data.join(LIVE_DIR);
    let none = || CoreError::new("no_session", "there is no session file to import");
    if !dir.is_dir() {
        return Err(none());
    }
    let dir = contained(&dir, roots).map_err(|_| CoreError::new("refused", "that folder is not inside this app"))?;
    let mut names: Vec<_> = std::fs::read_dir(&dir).map_err(|_| none())?.flatten().map(|e| e.path()).collect();
    names.sort();
    names.truncate(MAX_FILES);
    let stage = data.join(STAGE_DIR);
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).map_err(|_| CoreError::new("write_failed", "could not prepare the import"))?;
    let result = run_files(door, &names, roots, &stage).await;
    let _ = std::fs::remove_dir_all(&stage);
    let run = result?;
    let mut ledger = load_ledger(data);
    if run.ok > 0 {
        ledger.sessions += run.ok;
        ledger.readings += run.readings;
        ledger.last_from = run.last.as_ref().map(|s| s.from);
        ledger.last_to = run.last.as_ref().map(|s| s.to);
        ledger.last_at = Some(now_secs());
        let _ = save_ledger(data, &ledger);
    }
    if run.files == 0 {
        return Err(none());
    }
    Ok(json!({ "files": run.files, "ok": run.ok, "duplicate": run.duplicate, "failed": run.failed, "refused": run.refused,
               "readings": run.readings, "from": run.last.as_ref().map(|s| s.from), "to": run.last.as_ref().map(|s| s.to),
               "sessions": ledger.sessions, "readings_held": ledger.readings }))
}

#[derive(Default)]
struct Run {
    files: u64,
    ok: u64,
    duplicate: u64,
    failed: u64,
    refused: u64,
    readings: u64,
    last: Option<Session>,
}

async fn run_files(door: &dyn CoreDoor, files: &[PathBuf], roots: &[PathBuf], stage: &Path) -> Result<Run, CoreError> {
    let mut run = Run::default();
    for (i, path) in files.iter().enumerate() {
        let acceptable = (|| {
            let canon = contained(path, roots)?;
            let meta = std::fs::symlink_metadata(&canon).map_err(|_| "not_found")?;
            if !meta.is_file() || path.extension().is_none_or(|e| e != "jsonl") {
                return Err("not_a_session");
            }
            if meta.len() > MAX_BYTES {
                return Err("too_large");
            }
            let bytes = std::fs::read(&canon).map_err(|_| "not_found")?;
            validate(&bytes).map(|s| (bytes, s))
        })();
        let Ok((bytes, session)) = acceptable else {
            run.refused += 1;
            continue;
        };
        let staged = stage.join(format!("s{i}.jsonl"));
        std::fs::write(&staged, &bytes).map_err(|_| CoreError::new("write_failed", "could not prepare the import"))?;
        run.files += 1;
        let answer = door.call("import.run", json!({ "path": staged.to_string_lossy(), "transport": "ble" })).await?;
        let (ok, dup, failed) = (counted(&answer, "ok"), counted(&answer, "duplicate"), counted(&answer, "failed"));
        run.ok += ok;
        run.duplicate += dup;
        run.failed += failed;
        if ok > 0 {
            run.readings += session.readings;
            if run.last.as_ref().is_none_or(|l| session.to >= l.to) {
                run.last = Some(session);
            }
        }
    }
    Ok(run)
}

/// The synthetic session `n` (DEV only): ten minutes of heart rate and steps, one reading each every ten seconds,
/// invented values, a start time and offset that differ per `n` so two seeds are two records (identical sessions
/// dedupe to one under the hash-only conflict rule).
pub fn seed_text(n: u64) -> String {
    let start = 1_790_000_000 + n * 3600;
    let mut out = String::from("{\"status\": \"started\"}\n");
    for i in 0..60u64 {
        let t = start + i * 10;
        out.push_str(&format!("{{\"t\": {t}, \"metric\": \"heart_rate\", \"value\": {}}}\n", 100 + n + (i % 7)));
        out.push_str(&format!("{{\"t\": {t}, \"metric\": \"steps\", \"value\": {}}}\n", 1000 * (n + 1) + i * 3));
    }
    out.push_str("{\"status\": \"stopped\", \"seconds\": 600}\n");
    out
}

/// Write the next synthetic session into `<data>/live-in/` and return its number.
pub fn seed_next(data: &Path) -> std::io::Result<u64> {
    let dir = data.join(LIVE_DIR);
    std::fs::create_dir_all(&dir)?;
    #[cfg(target_os = "ios")]
    let _ = crate::ios::exclude_from_backup(&dir);
    let n = std::fs::read_dir(&dir)?.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("live-seed-")).count() as u64;
    let file = dir.join(format!("live-seed-{n}.jsonl"));
    std::fs::write(&file, seed_text(n))?;
    #[cfg(target_os = "ios")]
    let _ = crate::ios::exclude_from_backup(&file);
    Ok(n)
}


#[cfg(target_os = "ios")]
fn roots(app: &tauri::AppHandle) -> Result<(PathBuf, Vec<PathBuf>), CoreError> {
    let data = app.path().app_data_dir().map_err(|_| CoreError::new("write_failed", "no app data folder"))?;
    let mut roots = vec![data.clone()];
    roots.extend(app.path().document_dir());
    Ok((data, roots))
}

/// Import the session files waiting in the phone's own folder. The page passes nothing.
#[cfg(target_os = "ios")]
#[tauri::command]
pub async fn live_import(app: tauri::AppHandle, state: tauri::State<'_, crate::Core>) -> Result<Value, CoreError> {
    let core = state.0.clone()?;
    let (data, roots) = roots(&app)?;
    import_all(&core, &data, &roots).await
}

/// What this phone has produced so far: counts and a span.
#[cfg(target_os = "ios")]
#[tauri::command]
pub fn live_produced(app: tauri::AppHandle) -> Result<Value, CoreError> {
    let (data, _) = roots(&app)?;
    Ok(serde_json::to_value(load_ledger(&data)).unwrap_or_default())
}

/// DEV only (`--debug-live-seed`): write the next synthetic session and import it; once per process.
#[cfg(all(debug_assertions, target_os = "ios"))]
#[tauri::command]
pub async fn live_debug_seed(app: tauri::AppHandle, state: tauri::State<'_, crate::Core>) -> Result<Value, CoreError> {
    static ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let core = state.0.clone()?;
    let (data, roots) = roots(&app)?;
    if !ONCE.swap(true, std::sync::atomic::Ordering::SeqCst) {
        seed_next(&data).map_err(|_| CoreError::new("write_failed", "could not write the seed"))?;
    }
    import_all(&core, &data, &roots).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("disconect-livephone-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    /// Answers `import.run` with one file stored and records the params it was given.
    struct Fake(Mutex<Vec<Value>>, bool);

    impl CoreDoor for Fake {
        fn call<'a>(&'a self, method: &'a str, params: Value) -> Pin<Box<dyn Future<Output = Result<Value, CoreError>> + Send + 'a>> {
            Box::pin(async move {
                assert_eq!(method, "import.run");
                self.0.lock().unwrap().push(params);
                Ok(if self.1 { json!({"ok": 1, "duplicate": 0, "failed": 0}) } else { json!({"ok": 0, "duplicate": 1, "failed": 0}) })
            })
        }
    }

    #[test]
    fn a_path_outside_the_container_or_through_a_link_is_refused() {
        let root = scratch("contain");
        let outside = scratch("contain-out");
        std::fs::write(outside.join("x.jsonl"), seed_text(0)).unwrap();
        std::fs::create_dir_all(root.join("live-in")).unwrap();
        std::fs::write(root.join("live-in/a.jsonl"), seed_text(0)).unwrap();
        let roots = [root.clone()];
        assert!(contained(&root.join("live-in/a.jsonl"), &roots).is_ok());
        assert_eq!(contained(&outside.join("x.jsonl"), &roots), Err("outside"));
        assert!(contained(&root.join("live-in/../../x"), &roots).is_err(), "a parent step");
        std::os::unix::fs::symlink(outside.join("x.jsonl"), root.join("live-in/l.jsonl")).unwrap();
        assert!(contained(&root.join("live-in/l.jsonl"), &roots).is_err(), "a link to a file outside");
        std::os::unix::fs::symlink(root.join("live-in/a.jsonl"), root.join("live-in/inside.jsonl")).unwrap();
        assert_eq!(contained(&root.join("live-in/inside.jsonl"), &roots), Err("link"), "even a link that stays inside");
        std::os::unix::fs::symlink(&outside, root.join("dirlink")).unwrap();
        assert!(contained(&root.join("dirlink/x.jsonl"), &roots).is_err(), "a linked folder");
        let _ = (std::fs::remove_dir_all(&root), std::fs::remove_dir_all(&outside));
    }

    #[test]
    fn only_the_core_line_format_with_a_reading_validates() {
        let ok = validate(seed_text(0).as_bytes()).unwrap();
        assert_eq!((ok.readings, ok.from, ok.to), (120, 1_790_000_000, 1_790_000_590));
        assert_eq!(validate(b"hello\n"), Err("not_a_session"));
        assert_eq!(validate(b""), Err("not_a_session"));
        assert_eq!(validate(b"{\"status\": \"started\"}\n"), Err("no_readings"));
        assert_eq!(validate(b"{\"t\": 1, \"metric\": \"steps\", \"value\": 1.5}\n"), Err("not_a_session"), "a float value");
        assert_eq!(validate(b"{\"t\": 1000000000000, \"metric\": \"steps\", \"value\": 1}\n"), Err("not_a_session"), "a millisecond stamp");
        assert_eq!(validate(&vec![b' '; (MAX_BYTES + 1) as usize]), Err("too_large"));
    }

    #[test]
    fn seeds_are_distinct_and_the_import_goes_through_the_sweeps_call_from_a_staged_copy() {
        assert_ne!(seed_text(0), seed_text(1));
        let data = scratch("import");
        let outside = scratch("import-out");
        std::fs::write(outside.join("o.jsonl"), seed_text(9)).unwrap();
        assert_eq!(seed_next(&data).unwrap(), 0);
        assert_eq!(seed_next(&data).unwrap(), 1);
        std::fs::write(data.join(LIVE_DIR).join("junk.jsonl"), b"nope\n").unwrap();
        std::os::unix::fs::symlink(outside.join("o.jsonl"), data.join(LIVE_DIR).join("link.jsonl")).unwrap();
        let door = Fake(Mutex::new(Vec::new()), true);
        let roots = [data.clone()];
        let r = tauri::async_runtime::block_on(import_all(&door, &data, &roots)).unwrap();
        assert_eq!((r["files"].as_u64(), r["ok"].as_u64(), r["refused"].as_u64(), r["readings"].as_u64()), (Some(2), Some(2), Some(2), Some(240)));
        assert_eq!((r["from"].as_u64(), r["to"].as_u64()), (Some(1_790_003_600), Some(1_790_004_190)));
        let calls = door.0.lock().unwrap();
        assert_eq!(calls.len(), 2, "the refused files never reach the core");
        for c in calls.iter() {
            assert_eq!(c["transport"], "ble");
            assert!(c["path"].as_str().unwrap().contains(STAGE_DIR), "{c}");
        }
        assert!(!data.join(STAGE_DIR).exists(), "the staged copies are removed");
        assert_eq!(load_ledger(&data).sessions, 2);
        forget_in(&data);
        assert!(!data.join(LIVE_DIR).exists() && !data.join(LEDGER).exists());
        let _ = (std::fs::remove_dir_all(&data), std::fs::remove_dir_all(&outside));
    }

    #[test]
    fn a_duplicate_answer_adds_nothing_to_the_ledger_and_no_folder_is_no_session() {
        let data = scratch("dup");
        let roots = [data.clone()];
        let door = Fake(Mutex::new(Vec::new()), false);
        assert_eq!(tauri::async_runtime::block_on(import_all(&door, &data, &roots)).unwrap_err().code, "no_session");
        seed_next(&data).unwrap();
        let r = tauri::async_runtime::block_on(import_all(&door, &data, &roots)).unwrap();
        assert_eq!((r["ok"].as_u64(), r["duplicate"].as_u64(), r["sessions"].as_u64()), (Some(0), Some(1), Some(0)));
        assert!(!data.join(LEDGER).exists());
        let _ = std::fs::remove_dir_all(&data);
    }
}
