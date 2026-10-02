//! DISCOnect desktop shell (Bet 7). Rust holds no business logic: every command is a thin
//! relay to the Python core through [`sidecar`], and the webview draws what the core answers.

pub mod sidecar;

use std::sync::Arc;

use serde_json::Value;
use tauri::{Emitter, Manager, RunEvent, State};
use zeroize::Zeroizing;

use sidecar::{CoreError, EventSink, Launch, Sidecar};

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

/// The command Claude Desktop should run to use this app's core as its MCP server.
#[tauri::command]
fn mcp_command(app: tauri::AppHandle) -> String {
    let bundled = app
        .path()
        .resource_dir()
        .ok()
        .map(|d| d.join("hearthbeat-core").join("hearthbeat-core"))
        .filter(|p| p.is_file());
    match bundled {
        Some(p) => format!("\"{}\" mcp", p.display()),
        None => "hearthbeat-mcp  (dev build: the core is not bundled; use the venv's script)".to_string(),
    }
}

/// The app's own argv (after the executable), so the UI can honour `--screen <id>`.
#[tauri::command]
fn launch_args() -> Vec<String> {
    std::env::args().skip(1).collect()
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
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command, debug_unlock_from_file]);
    #[cfg(not(debug_assertions))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command]);
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
