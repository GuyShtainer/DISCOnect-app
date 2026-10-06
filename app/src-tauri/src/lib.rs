//! DISCOnect app shell (Bet 7, Bet 12). The shell is thin: every command is a relay to the core
//! through [`sidecar`], and the webview draws what the core answers. The one exception is the
//! [`coach`] module (Bet 15, ADR 0010), which owns the product's single internet egress point
//! (`coach/egress.rs`) and is guarded by tests (`tests/egress_guards.rs`). The core is
//! the Rust port as a sidecar child (macOS release), in this process ([`inproc`]; debug builds and
//! phones), or the Python one via `--core hearthbeat`.

#[allow(dead_code)] // slices 5-8 fill it
pub mod coach;
pub mod inproc;
pub mod live;
pub mod sidecar;

use std::sync::Arc;

use serde_json::Value;
use tauri::webview::NewWindowResponse;
use tauri::{Emitter, Manager, RunEvent, State};
use zeroize::Zeroizing;

use sidecar::{CoreError, EventSink, Plan, Sidecar};
#[cfg(desktop)]
use sidecar::{CoreChoice, Launch};

/// The core, or why it is not there. Stored in Tauri state so commands can reach it.
pub struct Core(pub Result<Sidecar, CoreError>);

pub(crate) struct WindowSink(pub(crate) tauri::AppHandle);

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
async fn core_call(app: tauri::AppHandle, state: State<'_, Core>, method: String, params: Option<Value>) -> Result<Value, CoreError> {
    let core = core_of(&state)?;
    let answer = core.call(&method, params.unwrap_or(Value::Object(Default::default()))).await;
    if method == "key.unlock" && answer.as_ref().is_ok_and(|v| v.get("unlocked").and_then(Value::as_bool) == Some(true)) {
        live::paid_on_unlock(&app);
    }
    answer
}

/// The passphrase arrives as `Zeroizing<String>` and is never cloned, formatted or logged.
#[tauri::command]
async fn core_unlock(app: tauri::AppHandle, state: State<'_, Core>, passphrase: Zeroizing<String>) -> Result<Value, CoreError> {
    let core = core_of(&state)?;
    let answer = core.unlock(passphrase).await;
    if answer.is_ok() {
        live::paid_on_unlock(&app);
    }
    answer
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
        None => "disconect-mcp  (dev build: the core is not bundled; use the venv's script)".to_string(),
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

/// The passphrase named by `DISCONECT_DEBUG_PASSPHRASE_FILE` (evidence runs on scratch stores).
#[cfg(debug_assertions)]
fn debug_passphrase() -> Result<Zeroizing<String>, CoreError> {
    let Some(path) = std::env::var_os("DISCONECT_DEBUG_PASSPHRASE_FILE") else {
        return Err(CoreError { code: "bad_params".into(), message: "no debug passphrase file set".into() });
    };
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| CoreError { code: "bad_params".into(), message: format!("cannot read the debug file: {e}") })?,
    );
    Ok(Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_string()))
}

/// Evidence hook, debug builds only: unlock with the passphrase read from the file named by
/// `DISCONECT_DEBUG_PASSPHRASE_FILE`, so Claude can capture unlocked screens without typing
/// into the webview. Compiled out of release builds.
#[cfg(debug_assertions)]
#[tauri::command]
async fn debug_unlock_from_file(state: State<'_, Core>) -> Result<Value, CoreError> {
    core_of(&state)?.unlock(debug_passphrase()?).await
}

/// Evidence hook, debug builds only: the six digits the other device shows, read from the file named by
/// `DISCONECT_DEBUG_DIGITS_FILE` (the file usually appears a moment after the `bound` event, so it is polled
/// every 500 ms for up to 60 s), then `pair.confirm` through the core. Compiled out of release builds.
#[cfg(debug_assertions)]
#[tauri::command]
async fn debug_pair_digits_from_file(state: State<'_, Core>) -> Result<Value, CoreError> {
    let no_file = || CoreError { code: "bad_params".into(), message: "no debug digits file".into() };
    let path = std::env::var_os("DISCONECT_DEBUG_DIGITS_FILE").ok_or_else(no_file)?;
    let digits = tauri::async_runtime::spawn_blocking(move || {
        for _ in 0..120 {
            if let Ok(text) = std::fs::read_to_string(&path) {
                let t = text.trim();
                if t.len() == 6 && t.bytes().all(|b| b.is_ascii_digit()) {
                    return Some(t.to_string());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        None
    })
    .await
    .map_err(|_| no_file())?
    .ok_or_else(no_file)?;
    core_of(&state)?.call("pair.confirm", serde_json::json!({ "digits": digits })).await
}

/// The store the in-process core serves, resolved here and handed over explicitly (the core is
/// never left to look at `$HOME` itself). Desktop: `--db` from argv, else the binary's own rule
/// (`$DISCONECT_DB`, else `~/.disconect/disconect.db`, or the legacy folder while only it exists).
/// A phone: a file in the app's private data folder.
#[cfg(desktop)]
fn inproc_db(_app: &tauri::AppHandle, core_note: &mut Vec<String>) -> Result<std::path::PathBuf, CoreError> {
    if let Some(db) = Launch::db_from_args(std::env::args()) {
        return Ok(db.into()); // taken literally, like the binary's `--db`
    }
    let default = disconect_core::home::resolve_default_db()
        .ok_or_else(|| CoreError { code: "core_unavailable".into(), message: "no store: pass --db <path> or set DISCONECT_DB (HOME is not set)".into() })?;
    if let Some(legacy) = default.legacy_home {
        core_note.push(disconect_core::home::legacy_home_hint(legacy));
    }
    Ok(default.path)
}

#[cfg(not(desktop))]
fn inproc_db(app: &tauri::AppHandle, _core_note: &mut Vec<String>) -> Result<std::path::PathBuf, CoreError> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| CoreError { code: "core_unavailable".into(), message: format!("no app data folder: {e}") })?;
    Ok(dir.join("disconect.db"))
}

fn start_inproc(app: &tauri::AppHandle) -> Result<Sidecar, CoreError> {
    let mut notes = Vec::new();
    let db = inproc_db(app, &mut notes)?;
    let core = Sidecar::start_inproc(db, Arc::new(WindowSink(app.clone())))?;
    for line in notes {
        core.note(line);
    }
    Ok(core)
}

#[cfg(desktop)]
fn start_sidecar(app: &tauri::AppHandle, choice: Option<CoreChoice>) -> Result<Sidecar, CoreError> {
    let resource_dir = app.path().resource_dir().ok();
    let program = sidecar::locate_core(resource_dir.as_deref(), choice).ok_or_else(|| CoreError {
        code: "core_unavailable".into(),
        message: match choice {
            Some(c) => format!("the {} core named by --core is not bundled with this build", c.name()),
            None => "no core is bundled with this build".into(),
        },
    })?;
    let db = Launch::db_from_args(std::env::args());
    Sidecar::start(Launch::new(program, db), Arc::new(WindowSink(app.clone())))
}

fn start_core(app: &tauri::AppHandle) -> Result<Sidecar, CoreError> {
    #[cfg(desktop)]
    let choice = CoreChoice::from_args(std::env::args()).map_err(|message| CoreError { code: "core_unavailable".into(), message })?;
    #[cfg(not(desktop))]
    let choice = None; // a phone's argv is not ours
    let env_core = std::env::var_os("DISCONECT_CORE");
    match sidecar::plan(choice, cfg!(debug_assertions), cfg!(desktop), env_core.as_deref()) {
        Plan::InProcess => {
            if let Some(reason) = sidecar::inproc_env_refusal(cfg!(debug_assertions), cfg!(desktop), |name| std::env::var_os(name)) {
                return Err(CoreError { code: "core_unavailable".into(), message: reason.into() });
            }
            start_inproc(app)
        }
        #[cfg(desktop)]
        Plan::Sidecar(choice) => start_sidecar(app, choice),
        #[cfg(not(desktop))]
        Plan::Sidecar(_) => Err(CoreError { code: "core_unavailable".into(), message: "this platform has no sidecar".into() }),
    }
}

/// The main window is declared in `tauri.conf.json` with `"create": false` and built here, after the core
/// is in state, so it can carry the egress hooks (ADR 0010): top-level navigation is limited to the app's
/// own origin ([`coach::egress_guard::navigation_allowed`]) and `window.open` / `target=_blank` is denied.
fn build_main_window(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let config = app
        .config()
        .app
        .windows
        .first()
        .cloned()
        .ok_or("tauri.conf.json declares no window")?;
    tauri::WebviewWindowBuilder::from_config(app.handle(), &config)?
        .on_navigation(coach::egress_guard::navigation_allowed)
        .on_new_window(|_url, _features| NewWindowResponse::Deny)
        .build()?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .setup(|app| {
            let core = start_core(app.handle());
            // Evidence runs (debug builds, scratch stores): unlock before the window asks, so a
            // screenshot shows the unlocked screens; nothing is typed into the webview.
            #[cfg(debug_assertions)]
            if let (Ok(core), Ok(pass)) = (&core, debug_passphrase()) {
                let _ = tauri::async_runtime::block_on(core.unlock(pass));
            }
            app.manage(Core(core));
            app.manage(coach::key::KeyHolder::default());
            app.manage(coach::commands::CoachState::default());
            app.manage(live::LiveState::default());
            build_main_window(app)?;
            Ok(())
        });
    // Bet 17: `support_sites`/`support_open` exist only on macOS (`coach/commands.rs`'s own `#[cfg]`), so the
    // debug/release split below is crossed with `target_os = "macos"` rather than naming them unconditionally
    // (a non-macOS build, e.g. the iOS shell `tests/mobile_config.rs` checks, must still compile).
    #[cfg(all(debug_assertions, target_os = "macos"))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command, debug_unlock_from_file, debug_pair_digits_from_file,
        coach::commands::coach_settings_get, coach::commands::coach_settings_set, coach::commands::coach_key_set, coach::commands::coach_key_forget, coach::commands::coach_key_state, coach::commands::coach_ask, coach::commands::coach_reset, coach::commands::coach_probe, coach::commands::handoff_build, coach::commands::handoff_open,
        coach::commands::support_sites, coach::commands::support_open,
        live::live_start, live::live_stop, live::live_state]);
    #[cfg(all(debug_assertions, not(target_os = "macos")))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command, debug_unlock_from_file, debug_pair_digits_from_file,
        coach::commands::coach_settings_get, coach::commands::coach_settings_set, coach::commands::coach_key_set, coach::commands::coach_key_forget, coach::commands::coach_key_state, coach::commands::coach_ask, coach::commands::coach_reset, coach::commands::coach_probe, coach::commands::handoff_build, coach::commands::handoff_open,
        live::live_start, live::live_stop, live::live_state]);
    #[cfg(all(not(debug_assertions), target_os = "macos"))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command,
        coach::commands::coach_settings_get, coach::commands::coach_settings_set, coach::commands::coach_key_set, coach::commands::coach_key_forget, coach::commands::coach_key_state, coach::commands::coach_ask, coach::commands::coach_reset, coach::commands::coach_probe, coach::commands::handoff_build, coach::commands::handoff_open,
        coach::commands::support_sites, coach::commands::support_open,
        live::live_start, live::live_stop, live::live_state]);
    #[cfg(all(not(debug_assertions), not(target_os = "macos")))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command,
        coach::commands::coach_settings_get, coach::commands::coach_settings_set, coach::commands::coach_key_set, coach::commands::coach_key_forget, coach::commands::coach_key_state, coach::commands::coach_ask, coach::commands::coach_reset, coach::commands::coach_probe, coach::commands::handoff_build, coach::commands::handoff_open,
        live::live_start, live::live_stop, live::live_state]);
    let app = builder
        .build(tauri::generate_context!())
        .expect("error while building tauri application");
    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            handle.state::<live::LiveState>().stop();
            if let Ok(core) = &handle.state::<Core>().0 {
                core.shutdown();
            }
        }
    });
}
