//! DISCOnect app shell (Bet 7, Bet 12). The shell is thin: every command is a relay to the core
//! through [`sidecar`], and the webview draws what the core answers. The one exception is the
//! [`coach`] module (Bet 15, ADR 0010), which owns the product's single internet egress point
//! (`coach/egress.rs`) and is guarded by tests (`tests/egress_guards.rs`). The core is
//! the Rust port as a sidecar child (macOS release), in this process ([`inproc`]; debug builds and
//! phones), or the Python one via `--core hearthbeat`.

// 12-D item 5: `dev` (tauri-build's alias) is false only with `tauri/custom-protocol`, which the tauri CLI sets for a
// release. Without it, tauri's dev-server proxy (an HTTP client, the phone's second web client) would ship.
#[cfg(all(dev, target_os = "ios", not(debug_assertions)))]
compile_error!("an iOS release must be built with tauri/custom-protocol (the tauri CLI does this); without it tauri's dev-server proxy, the phone's second web client, would ship");

#[allow(dead_code)] // slices 5-8 fill it
pub mod coach;
pub mod import_drop;
pub mod inproc;
#[cfg(target_os = "ios")]
mod ios;
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

/// Every core method the page may call through [`core_call`] (the ones `src/*.ts` names; a guard in
/// `tests/egress_guards.rs` keeps the two in step). `import.run` is deliberately absent: an import starts only from
/// the OS drop handled in Rust (`import_drop.rs`), so a script in the webview cannot name a path. `key.unlock` is the
/// keychain path only (the sidecar refuses it with a passphrase; see [`core_unlock`]).
pub const ALLOWED_METHODS: &[&str] = &[
    "app.info", "data.today", "data.live", "data.sleep", "data.contract", "data.health", "data.metric", "data.facts", "key.status", "key.cache", "key.unlock", "import.last",
    "sync.status", "sync.run", "relay.addresses", "relay.serve", "pair.offer", "pair.confirm", "pair.cancel",
];

/// `Ok` when the page may call `method`; otherwise a fixed refusal that never echoes the method.
pub fn method_refusal(method: &str) -> Result<(), CoreError> {
    if ALLOWED_METHODS.contains(&method) {
        Ok(())
    } else {
        Err(CoreError::new("refused", "that method is not available to the page"))
    }
}

/// Generic relay, for the methods in [`ALLOWED_METHODS`] only.
#[tauri::command]
async fn core_call(app: tauri::AppHandle, state: State<'_, Core>, method: String, params: Option<Value>) -> Result<Value, CoreError> {
    method_refusal(&method)?;
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

/// Release filter: drop every `--debug-*` flag and, unless it is one of the flags that take no operand,
/// the operand after it (so `--debug-window 390x844` leaves nothing behind).
fn release_args(args: Vec<String>) -> Vec<String> {
    const NO_OPERAND: [&str; 5] = ["--debug-drop-over", "--debug-pair-digits", "--debug-drawer-open", "--debug-sync-run", "--debug-unlock"];
    let mut out = Vec::new();
    let mut it = args.into_iter().peekable();
    while let Some(a) = it.next() {
        if !a.starts_with("--debug-") {
            out.push(a);
        } else if !NO_OPERAND.contains(&a.as_str()) && it.peek().is_some_and(|n| !n.starts_with("--")) {
            it.next();
        }
    }
    out
}

#[cfg(test)]
mod release_args_tests {
    use super::release_args;

    #[test]
    fn a_release_build_drops_debug_flags_with_their_operands() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let window = concat!("--debug-", "window");
        assert_eq!(release_args(v(&[window, "390x844", "--screen", "today"])), v(&["--screen", "today"]));
        assert_eq!(release_args(v(&["--screen", "today", "--debug-drawer-open", "--theme", "dark"])), v(&["--screen", "today", "--theme", "dark"]));
        assert_eq!(release_args(v(&["--debug-listen", "127.0.0.1:9", "--debug-drop-over"])), v(&[]));
        assert_eq!(release_args(v(&["--screen", "sync", "--debug-sync-run", "--theme", "dark"])), v(&["--screen", "sync", "--theme", "dark"]));
        assert_eq!(release_args(v(&["--screen", "trend", "--debug-tip", "2025-06-20", "--trend", "steps"])), v(&["--screen", "trend", "--trend", "steps"]));
    }
}

/// The app's own argv (after the executable), so the UI can honour `--screen <id>`.
#[tauri::command]
fn launch_args() -> Vec<String> {
    #[allow(unused_mut)]
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // a release build ignores the debug flags even when they are typed on the command line
    if !cfg!(debug_assertions) {
        args = release_args(args);
    }
    // Evidence runs, debug builds only: `DISCONECT_DEBUG_DROP_OVER=1` reaches the page as `--debug-drop-over`
    // (the Import screen draws its drop cards in the hovered state).
    #[cfg(debug_assertions)]
    if std::env::var_os("DISCONECT_DEBUG_DROP_OVER").is_some_and(|v| v == "1") {
        args.push("--debug-drop-over".into());
    }
    args
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

/// The phone's store file inside `app_data_dir()` (shared with the iOS start-up hook, which names the same file).
#[cfg(not(desktop))]
pub(crate) const PHONE_DB_FILE: &str = "disconect.db";

#[cfg(not(desktop))]
fn inproc_db(app: &tauri::AppHandle, _core_note: &mut Vec<String>) -> Result<std::path::PathBuf, CoreError> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| CoreError { code: "core_unavailable".into(), message: format!("no app data folder: {e}") })?;
    Ok(dir.join(PHONE_DB_FILE))
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

/// Evidence hook, debug builds only: the folder or zip named by `DISCONECT_DEBUG_IMPORT_PATH` goes through the
/// same entry point as a real drop, a moment after the window exists (nothing is scriptable in an OS drag). It
/// is read here, in Rust; no command takes a path from the webview. The body is compiled out of release builds.
fn debug_import_door(app: &tauri::AppHandle) {
    let _ = app;
    #[cfg(debug_assertions)]
    {
        let Some(path) = std::env::var_os("DISCONECT_DEBUG_IMPORT_PATH") else { return };
        let app = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            import_drop::handle_drop(&app, vec![std::path::PathBuf::from(path)]);
        });
    }
}

/// Whether the debug switch `name` is set to `1`.
#[cfg(debug_assertions)]
fn debug_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| v == "1")
}

/// Evidence door, debug builds only: with `DISCONECT_DEBUG_CACHE_KEY=1`, turn the keychain cache on right after the
/// debug unlock (`key.cache` with `enable`; no key is passed or logged). The note holds the answer's state word only.
#[cfg(debug_assertions)]
fn debug_cache_key_door(core: &Sidecar) {
    if !debug_flag("DISCONECT_DEBUG_CACHE_KEY") {
        return;
    }
    let note = match tauri::async_runtime::block_on(core.call("key.cache", serde_json::json!({ "enable": true }))) {
        Ok(v) => format!("debug door: key.cache enabled, keychain {}", v.get("keychain").and_then(Value::as_str).unwrap_or("?")),
        Err(e) => format!("debug door: key.cache failed ({})", e.code),
    };
    core.note(note);
}

/// Evidence door, debug builds only: with `DISCONECT_DEBUG_SYNC_ON_START=1`, run `sync.run` once a moment after start
/// (the page's own call, no parameters). The note holds counts and the status word, never a data value.
#[cfg(debug_assertions)]
fn debug_sync_on_start_door(core: &Sidecar) {
    if !debug_flag("DISCONECT_DEBUG_SYNC_ON_START") {
        return;
    }
    let core = core.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(2000));
        let note = match tauri::async_runtime::block_on(core.call("sync.run", serde_json::json!({}))) {
            Ok(v) => {
                let n = |part: &str, field: &str| v.get(part).and_then(|p| p.get(field)).and_then(Value::as_u64).unwrap_or(0);
                format!(
                    "debug door: sync.run push {} bundles {} records, pull {} applied {} new records, status {}",
                    n("push", "bundles"),
                    n("push", "records"),
                    n("pull", "applied"),
                    n("pull", "records_new"),
                    v.get("pull").and_then(|p| p.get("status")).and_then(Value::as_str).unwrap_or("?")
                )
            }
            Err(e) => format!("debug door: sync.run failed ({})", e.code),
        };
        let _ = std::fs::write(std::env::temp_dir().join("sync-proof.json"), serde_json::json!({ "note": note }).to_string());
        core.note(note);
    });
}

/// Evidence door, debug builds on iOS only: with `DISCONECT_DEBUG_KEYCHAIN_PROOF=1`, write `keychain-proof.json` to the
/// container's `tmp/`: the number of items under each service and, for the key file's key id, the item's class
/// (`pdmn`) and synchronizable flag, and the start-up hook's notes (counts and plain words). Never the account, never the value.
#[cfg(debug_assertions)]
#[cfg(target_os = "ios")]
fn debug_keychain_proof_door(app: &tauri::AppHandle, startup_notes: &[String]) {
    use disconect_core::keychain_leftovers::{Keychain, RealKeychain, SERVICES};
    if !debug_flag("DISCONECT_DEBUG_KEYCHAIN_PROOF") {
        return;
    }
    let mut items = serde_json::Map::new();
    for service in SERVICES {
        let count = RealKeychain.accounts(service).map_or(Value::Null, |a| Value::from(a.len()));
        items.insert(service.to_string(), count);
    }
    let key_item = app
        .path()
        .app_data_dir()
        .ok()
        .and_then(|dir| disconect_core::keys::read_key_file(&disconect_core::keys::key_path_for(&dir.join(PHONE_DB_FILE))).ok())
        .and_then(|file| disconect_core::keychain::item_class(&file.key_id).ok().flatten())
        .map_or(Value::Null, |(pdmn, synchronizable)| serde_json::json!({ "pdmn": pdmn, "synchronizable": synchronizable }));
    let proof = serde_json::json!({ "items": items, "key_item": key_item, "startup_notes": startup_notes });
    let _ = std::fs::write(std::env::temp_dir().join("keychain-proof.json"), proof.to_string());
}

/// Tell the page whether something is hovering. The payload is only the flag, never a path.
fn drag_over(app: &tauri::AppHandle, over: bool) {
    let _ = app.emit("core://drag", serde_json::json!({ "over": over }));
}

/// `--debug-window <W>x<H>` from argv: both sides whole numbers of 1 to 4 digits, width 390 to 4000 px and height 600 to 4000 px (the window's minimums); anything else is ignored.
#[cfg(debug_assertions)]
fn debug_window_size(args: &[String]) -> Option<(f64, f64)> {
    let at = args.iter().position(|a| a == "--debug-window")?;
    let (w, h) = args.get(at + 1)?.split_once('x')?;
    let ok = |t: &str| t.len() <= 4 && t.bytes().all(|b| b.is_ascii_digit());
    if !ok(w) || !ok(h) {
        return None;
    }
    let (w, h): (u32, u32) = (w.parse().ok()?, h.parse().ok()?);
    ((390..=4000).contains(&w) && (600..=4000).contains(&h)).then_some((f64::from(w), f64::from(h)))
}

/// The main window is declared in `tauri.conf.json` with `"create": false` and built here, after the core
/// is in state, so it can carry the egress hooks (ADR 0010): top-level navigation is limited to the app's
/// own origin ([`coach::egress_guard::navigation_allowed`]) and `window.open` / `target=_blank` is denied.
fn build_main_window(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    #[allow(unused_mut)]
    let mut config = app
        .config()
        .app
        .windows
        .first()
        .cloned()
        .ok_or("tauri.conf.json declares no window")?;
    // Evidence runs, debug builds only: `--debug-window <W>x<H>` sets the window's inner size at build
    // (the page ignores the flag; a release build never reads argv here).
    #[cfg(debug_assertions)]
    if let Some((w, h)) = debug_window_size(&std::env::args().collect::<Vec<_>>()) {
        config.width = w;
        config.height = h;
    }
    // Pitch 7b-3: the OS drop is handled here, in Rust. The webview never listens to the `tauri://drag-*` events
    // (they carry the dragged paths into the page); it hears only `core://drag` with a bare `over` flag.
    let handle = app.handle().clone();
    let window = tauri::WebviewWindowBuilder::from_config(app.handle(), &config)?
        .on_navigation(coach::egress_guard::navigation_allowed)
        .on_new_window(|_url, _features| NewWindowResponse::Deny)
        .build()?;
    window.on_window_event(move |event| {
        if let tauri::WindowEvent::DragDrop(drag) = event {
            match drag {
                tauri::DragDropEvent::Enter { .. } => drag_over(&handle, true),
                tauri::DragDropEvent::Leave => drag_over(&handle, false),
                tauri::DragDropEvent::Drop { paths, .. } => {
                    drag_over(&handle, false);
                    import_drop::handle_drop(&handle, paths.clone());
                }
                _ => {} // Over: nothing to tell the page
            }
        }
    });
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .setup(|app| {
            // iOS only: leftover keychain items, backup flags and the key file's protection class, before the
            // store opens and before the page asks `key.unlock`. Its notes reach the core's diagnostics below.
            #[cfg(target_os = "ios")]
            let ios_notes = ios::prepare(app.handle());
            #[cfg(all(debug_assertions, target_os = "ios"))]
            let proof_notes = ios_notes.clone();
            let core = start_core(app.handle());
            #[cfg(target_os = "ios")]
            if let Ok(core) = &core {
                for line in ios_notes {
                    core.note(line);
                }
            }
            // Evidence runs (debug builds, scratch stores): unlock before the window asks, so a
            // screenshot shows the unlocked screens; nothing is typed into the webview.
            #[cfg(debug_assertions)]
            if let (Ok(core), Ok(pass)) = (&core, debug_passphrase()) {
                let _ = tauri::async_runtime::block_on(core.unlock(pass));
            }
            #[cfg(debug_assertions)]
            if let Ok(core) = &core {
                debug_cache_key_door(core);
                debug_sync_on_start_door(core);
            }
            app.manage(Core(core));
            app.manage(coach::key::KeyHolder::default());
            app.manage(coach::commands::CoachState::default());
            app.manage(live::LiveState::default());
            build_main_window(app)?;
            debug_import_door(app.handle());
            #[cfg(all(debug_assertions, target_os = "ios"))]
            debug_keychain_proof_door(app.handle(), &proof_notes);
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
