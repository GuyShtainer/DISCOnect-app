//! DISCOnect desktop shell (Bet 7). Rust holds no business logic: every command is a thin
//! relay to the Python core through [`sidecar`], and the webview draws what the core answers.
//! The Bet-3 CSV command stays until the Trend screen reads `data.metric` (slice 3c).

pub mod sidecar;

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use tauri::{Emitter, Manager, RunEvent, State};
use zeroize::Zeroizing;

use sidecar::{CoreError, EventSink, Launch, Sidecar};

#[derive(serde::Serialize)]
pub struct DailySteps {
    pub date: String,
    pub steps: u32,
    pub source: String,
}

fn csv_path() -> PathBuf {
    std::env::var_os("DISCONECT_DAILY_CSV")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data/daily.csv"))
}

/// Pick the steps column: device scope first, then local, then any `steps[...]`.
fn steps_column(header: &[&str]) -> Option<(usize, String)> {
    let preferred = ["steps[device]", "steps[local]"];
    for want in preferred {
        if let Some(i) = header.iter().position(|h| *h == want) {
            return Some((i, want.to_string()));
        }
    }
    header
        .iter()
        .position(|h| h.starts_with("steps["))
        .map(|i| (i, header[i].to_string()))
}

pub fn parse_daily_steps(text: &str) -> Result<Vec<DailySteps>, String> {
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().ok_or("empty CSV")?.split(',').collect();
    let date_col = header.iter().position(|h| *h == "date").ok_or("no date column")?;
    let (steps_col, source) = steps_column(&header).ok_or("no steps column")?;
    let mut rows = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split(',').collect();
        let Some(raw) = fields.get(steps_col) else { continue };
        if raw.is_empty() {
            continue;
        }
        let steps = raw
            .parse::<f64>()
            .map_err(|e| format!("bad steps value {raw:?}: {e}"))? as u32;
        rows.push(DailySteps { date: fields[date_col].to_string(), steps, source: source.clone() });
    }
    Ok(rows)
}

#[tauri::command]
fn daily_steps() -> Result<Vec<DailySteps>, String> {
    let path = csv_path();
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    parse_daily_steps(&text)
}

/// The core, or why it is not there. Stored in Tauri state so commands can reach it.
pub struct Core(pub Result<Sidecar, CoreError>);

struct WindowSink(tauri::AppHandle);

impl EventSink for WindowSink {
    fn emit(&self, name: &str, payload: Value) {
        let _ = self.0.emit(name, payload);
    }
}

fn core_of(state: &State<'_, Core>) -> Result<Sidecar, CoreError> {
    state.0.clone()
}

/// Generic relay. `key.unlock` is refused here; see [`core_unlock`].
#[tauri::command]
async fn core_call(state: State<'_, Core>, method: String, params: Option<Value>) -> Result<Value, CoreError> {
    let core = core_of(&state)?;
    core.call(&method, params.unwrap_or(Value::Object(Default::default()))).await
}

/// The passphrase arrives as `Zeroizing<String>` and is never cloned, formatted or logged.
#[tauri::command]
async fn core_unlock(state: State<'_, Core>, passphrase: Zeroizing<String>) -> Result<Value, CoreError> {
    let core = core_of(&state)?;
    core.unlock(passphrase).await
}

/// Last stderr lines of the core for a diagnostics panel (never key material: the core keeps
/// that off stderr; this is for "why did it stop" questions).
#[tauri::command]
fn core_stderr(state: State<'_, Core>) -> Result<Vec<String>, CoreError> {
    Ok(core_of(&state)?.stderr_tail())
}

/// Evidence hook, debug builds only: unlock with the passphrase read from the file named by
/// `DISCONECT_DEBUG_PASSPHRASE_FILE`, so Claude can capture unlocked screens without typing
/// into the webview. Compiled out of release builds.
#[cfg(debug_assertions)]
#[tauri::command]
async fn debug_unlock_from_file(state: State<'_, Core>) -> Result<Value, CoreError> {
    let Some(path) = std::env::var_os("DISCONECT_DEBUG_PASSPHRASE_FILE") else {
        return Err(CoreError { code: "bad_params".into(), message: "no debug passphrase file set".into() });
    };
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| CoreError { code: "bad_params".into(), message: format!("cannot read the debug file: {e}") })?,
    );
    let pass = Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_string());
    core_of(&state)?.unlock(pass).await
}

fn start_core(app: &tauri::AppHandle) -> Result<Sidecar, CoreError> {
    let resource_dir = app.path().resource_dir().ok();
    let program = sidecar::locate_core(resource_dir.as_deref()).ok_or_else(|| CoreError {
        code: "core_unavailable".into(),
        message: "the core is not bundled with this build and DISCONECT_CORE is unset".into(),
    })?;
    let db = Launch::db_from_args(std::env::args());
    Sidecar::start(Launch::new(program, db), Arc::new(WindowSink(app.clone())))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .setup(|app| {
            let core = start_core(app.handle());
            app.manage(Core(core));
            Ok(())
        });
    #[cfg(debug_assertions)]
    let builder = builder.invoke_handler(tauri::generate_handler![
        daily_steps,
        core_call,
        core_unlock,
        core_stderr,
        debug_unlock_from_file
    ]);
    #[cfg(not(debug_assertions))]
    let builder = builder.invoke_handler(tauri::generate_handler![daily_steps, core_call, core_unlock, core_stderr]);
    let app = builder
        .build(tauri::generate_context!())
        .expect("error while building tauri application");
    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Ok(core) = &handle.state::<Core>().0 {
                core.shutdown();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::parse_daily_steps;

    #[test]
    fn prefers_device_scope_and_skips_blanks() {
        let csv = "date,steps[vendor_cloud],steps[device]\n2025-06-11,100,120\n2025-06-12,,\n2025-06-13,90,";
        let rows = parse_daily_steps(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].date.as_str(), rows[0].steps), ("2025-06-11", 120));
        assert_eq!(rows[0].source, "steps[device]");
    }

    #[test]
    fn falls_back_to_any_steps_column() {
        let csv = "date,steps[vendor_cloud]\n2025-06-11,7\n";
        let rows = parse_daily_steps(csv).unwrap();
        assert_eq!(rows[0].source, "steps[vendor_cloud]");
    }

    #[test]
    fn missing_steps_column_is_an_error() {
        assert!(parse_daily_steps("date,foo\n2025-06-11,1\n").is_err());
    }
}
