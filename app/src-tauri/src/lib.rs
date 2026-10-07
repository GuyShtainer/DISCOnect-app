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
mod cover;
#[cfg(target_os = "ios")]
mod ios;
#[cfg(target_os = "ios")]
mod relays;
pub mod live;
pub mod live_phone;
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

/// The iOS start-up hook's notes when the core did not start (empty everywhere else): what [`core_stderr`] answers then.
pub struct StartupNotes(pub Vec<String>);

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
#[cfg(not(target_os = "ios"))]
pub const ALLOWED_METHODS: &[&str] = &[
    "app.info", "data.today", "data.live", "data.sleep", "data.contract", "data.health", "data.metric", "data.facts", "key.status", "key.cache", "key.unlock", "import.last",
    "import.cancel", "sync.status", "sync.run", "relay.addresses", "relay.serve", "pair.offer", "pair.confirm", "pair.cancel",
];

/// The phone's list (12-F, S5): the four server-side methods are gone, because a phone serves nothing and the core
/// refuses them anyway (`unsupported_transport`). `pair.cancel` stays: on the phone it reaches only the joiner's cancel
/// flag, never the relay's offer. `pair.forget` (12-F row 5b) is on this list only: it deletes the phone's own copy.
/// `key.lock` (row 5c) is too: the phone drops its master after five minutes away (see [`AwayClock`]); the app calls it
/// in-process, the list says the page may too. `pair.join` and `pair.land` (12-F row 3) are the phone as the pairing
/// joiner; every other core refuses them after the shared prefix. `import.cancel` (BL-3) is on both lists: the Import
/// screen is desktop-only, and a phone's core answers it `not_found`.
/// `tests/egress_guards.rs` reads the first list above for the page's calls and this one for the four.
#[cfg(target_os = "ios")]
pub const ALLOWED_METHODS: &[&str] = &[
    "app.info", "data.today", "data.live", "data.sleep", "data.contract", "data.health", "data.metric", "data.facts", "key.status", "key.cache", "key.unlock", "key.lock", "import.last",
    "import.cancel", "sync.status", "sync.run", "pair.cancel", "pair.forget", "pair.join", "pair.land",
];

/// `Ok` when the page may call `method`; otherwise a fixed refusal that never echoes the method.
pub fn method_refusal(method: &str) -> Result<(), CoreError> {
    if ALLOWED_METHODS.contains(&method) {
        Ok(())
    } else {
        Err(CoreError::new("refused", "that method is not available to the page"))
    }
}

/// 19d (iOS): the phone's shell passes its relay list to the core as a `relays` param on `sync.run` (not on
/// `sync.status`, which only echoes the last run). On since the core took the param (19d DONE, slice 2).
#[cfg(target_os = "ios")]
pub(crate) const RELAYS_INJECT: bool = true;

/// `Ok` when the page may pass `params` to `method`. 19d (attack finding A6): the relay list reaches the core from
/// `relay.json` on the desktop and from the phone shell's bookmarks on iOS (built natively in `relays`), never from
/// the page — a `relays` key is refused on every platform and for every method, with a fixed text that never echoes
/// the parameter.
pub fn params_refusal(_method: &str, params: &Value) -> Result<(), CoreError> {
    if params.get("relays").is_some() {
        return Err(CoreError::new("refused", "that parameter is not available to the page"));
    }
    Ok(())
}

/// Generic relay, for the methods in [`ALLOWED_METHODS`] only.
#[tauri::command]
async fn core_call(app: tauri::AppHandle, state: State<'_, Core>, method: String, params: Option<Value>) -> Result<Value, CoreError> {
    method_refusal(&method)?;
    let params = params.unwrap_or(Value::Object(Default::default()));
    params_refusal(&method, &params)?;
    let core = core_of(&state)?;
    // iOS: the whole relay list rides on `sync.run` (once `RELAYS_INJECT` is on); the folders' scopes are held until
    // the answer is back and stop when `_scopes` drops at the end of this function.
    #[cfg(target_os = "ios")]
    let (params, _scopes) = relays::params_for_call(&app, &method, params, RELAYS_INJECT);
    let answer = core.call(&method, params).await;
    #[cfg(target_os = "ios")]
    if let Ok(value) = &answer {
        relays::note_answer(&app, &method, value);
        if method == "pair.forget" {
            relays::forget(&app);
            if let Ok(dir) = app.path().app_data_dir() {
                live_phone::forget_in(&dir);
            }
        }
    }
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
    // the last eighteen are the phone's pairing evidence flags (12-F row 4): states drawn with synthetic values, and the
    // debug door that feeds the offer text from a file and answers the screens' choices
    const NO_OPERAND: [&str; 34] = [
        "--debug-drop-over", "--debug-pair-digits", "--debug-drawer-open", "--debug-sync-run", "--debug-pair-start", "--debug-import-cancel", "--debug-unlock", "--debug-forget-open",
        "--debug-pair-scan", "--debug-pair-code", "--debug-pair-confirm", "--debug-pair-done", "--debug-pair-expired", "--debug-pair-paired",
        "--debug-pair-closed", "--debug-pair-ended", "--debug-pair-stopping", "--debug-pair-landing", "--debug-pair-joining", "--debug-pair-clock", "--debug-pair-notpaired", "--debug-pair-failed", "--debug-pair-offer-file", "--debug-pair-yes", "--debug-pair-no", "--debug-pair-cancel", "--debug-pair-open-today", "--debug-pair-reload-on-code", "--debug-pair-reload-on-confirm", "--debug-pair-start-scan", "--debug-pair-reload-on-landing", "--debug-relays-seed", "--debug-relays-remove-b", "--debug-live-seed",
    ];
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
        // 19a: a debug flag with an operand goes with it (the timer's seconds never reach a release build)
        assert_eq!(release_args(v(&["--screen", "sync", "--debug-auto-sync-seconds", "5", "--theme", "dark"])), v(&["--screen", "sync", "--theme", "dark"]));
        assert_eq!(release_args(v(&["--screen", "trend", "--debug-tip", "2025-06-20", "--trend", "steps"])), v(&["--screen", "trend", "--trend", "steps"]));
    }

    /// 19d row 4: the relay seed flag takes no operand, so a release build drops it and keeps what follows.
    #[test]
    fn a_release_build_drops_the_relay_seed_flag_and_keeps_what_follows() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(release_args(v(&["--debug-relays-seed", "--screen", "settings"])), v(&["--screen", "settings"]));
    }

    /// 19b row 3: the live-session seed flag takes no operand, so a release build drops it and keeps what follows.
    #[test]
    fn a_release_build_drops_the_live_seed_flag_and_keeps_what_follows() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(release_args(v(&["--debug-live-seed", "--screen", "sync"])), v(&["--screen", "sync"]));
    }

    /// 19d (the attack's A6): the page may not name `relays` on any method; the shell builds the list natively.
    #[test]
    fn a_relays_param_from_the_page_is_refused_on_every_method() {
        let refused = |m: &str, v: serde_json::Value| super::params_refusal(m, &v).is_err();
        assert!(refused("sync.run", serde_json::json!({"relays": []})));
        assert!(refused("sync.status", serde_json::json!({"a": 1, "relays": null})));
        assert!(!refused("sync.run", serde_json::json!({"a": 1})));
        assert!(!refused("sync.run", serde_json::json!({})));
    }

    /// 12-F row 4: every pairing evidence flag takes no operand, so a release build drops the flag and keeps the
    /// argument after it (`--theme dark`), and drops an operand-taking flag together with its operand.
    #[test]
    fn a_release_build_drops_every_phone_pairing_flag_and_keeps_what_follows() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for flag in [
            "--debug-pair-scan", "--debug-pair-code", "--debug-pair-confirm", "--debug-pair-done", "--debug-pair-expired", "--debug-pair-paired",
            "--debug-pair-closed", "--debug-pair-ended", "--debug-pair-stopping", "--debug-pair-landing", "--debug-pair-joining", "--debug-pair-clock", "--debug-pair-notpaired", "--debug-pair-failed", "--debug-pair-offer-file", "--debug-pair-yes", "--debug-pair-no", "--debug-pair-cancel", "--debug-pair-open-today",
        ] {
            assert_eq!(release_args(v(&[flag, "--theme", "dark"])), v(&["--theme", "dark"]), "{flag}");
        }
        assert_eq!(release_args(v(&["--debug-pair-unknown", "x", "--theme", "dark"])), v(&["--theme", "dark"]));
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

/// iOS only (12-F row 4): keep the screen awake while the pairing code is up, so the phone does not lock mid-wait. The
/// page turns it on when the Code screen shows and off on every way out of it (and once at start-up, in case a reload
/// left it on). It sets `UIApplication.idleTimerDisabled`, which UIKit wants on the main thread. Nothing else calls it.
#[cfg(target_os = "ios")]
#[tauri::command]
fn keep_awake(app: tauri::AppHandle, on: bool) -> Result<(), CoreError> {
    app.run_on_main_thread(move || {
        if let Some(mtm) = objc2::MainThreadMarker::new() {
            objc2_ui_kit::UIApplication::sharedApplication(mtm).setIdleTimerDisabled(on);
        }
    })
    .map_err(|_| CoreError::new("internal", "could not reach the main thread"))
}

/// Evidence hook, debug iOS builds only: the offer text the Mac side wrote to the file named by
/// `DISCONECT_DEBUG_OFFER_FILE` (polled every 500 ms for up to 90 s, because the offerer writes it a moment after the
/// app starts). It is the simulator's stand-in for the camera. The text is returned to the page and never logged.
/// Compiled out of release builds.
#[cfg(all(debug_assertions, target_os = "ios"))]
#[tauri::command]
async fn debug_offer_from_file() -> Result<String, CoreError> {
    let none = || CoreError { code: "bad_params".into(), message: "no debug offer file".into() };
    let path = std::env::var_os("DISCONECT_DEBUG_OFFER_FILE").ok_or_else(none)?;
    tauri::async_runtime::spawn_blocking(move || {
        for _ in 0..180 {
            if let Ok(text) = std::fs::read_to_string(&path) {
                let t = text.trim();
                if t.starts_with("disconect-pair:v2.") {
                    return Some(t.to_string());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        None
    })
    .await
    .map_err(|_| none())?
    .ok_or_else(none)
}

/// Last stderr lines of the core for a diagnostics panel (never key material: the core keeps
/// that off stderr; this is for "why did it stop" questions).
#[tauri::command]
fn core_stderr(state: State<'_, Core>, notes: State<'_, StartupNotes>) -> Result<Vec<String>, CoreError> {
    match core_of(&state) {
        Ok(core) => Ok(core.stderr_tail()),
        Err(e) if notes.0.is_empty() => Err(e),
        Err(_) => Ok(notes.0.clone()),
    }
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

/// How long the phone may be away (not the active app) before its master key leaves memory: 12-F pitch, "The master in
/// memory". Debug builds read `DISCONECT_DEBUG_AWAY_SECS` instead (evidence runs); that code is compiled out of release.
#[cfg_attr(not(target_os = "ios"), allow(dead_code))]
const AWAY_LIMIT: std::time::Duration = std::time::Duration::from_secs(300);

#[cfg(debug_assertions)]
#[cfg_attr(not(target_os = "ios"), allow(dead_code))]
fn away_limit() -> std::time::Duration {
    std::env::var("DISCONECT_DEBUG_AWAY_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(AWAY_LIMIT, std::time::Duration::from_secs)
}

#[cfg(not(debug_assertions))]
#[cfg_attr(not(target_os = "ios"), allow(dead_code))]
fn away_limit() -> std::time::Duration {
    AWAY_LIMIT
}

/// Whether coming back at `back` after leaving at `left` must drop the master: `limit` or more has passed, or the wall
/// clock went backwards (then the time away is unknown, so the safe answer is to lock). Wall-clock times on purpose:
/// `Instant` does not count the time a sleeping phone spends asleep.
#[cfg_attr(not(target_os = "ios"), allow(dead_code))]
fn away_requires_lock(left: std::time::SystemTime, back: std::time::SystemTime, limit: std::time::Duration) -> bool {
    back.duration_since(left).map_or(true, |away| away >= limit)
}

/// When the app last stopped being the active one (Tauri's `Suspended`, applicationWillResignActive). Every `Suspended`
/// overwrites it, so a Control Center pull-down that ended in the app again is not counted as time away.
#[cfg(target_os = "ios")]
#[derive(Default)]
struct AwayClock(std::sync::Mutex<Option<std::time::SystemTime>>);

#[cfg(target_os = "ios")]
impl AwayClock {
    fn left(&self, at: std::time::SystemTime) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(at);
        }
    }

    /// Back in the foreground at `now`: true when the master must go. No recorded departure also answers true.
    fn back(&self, now: std::time::SystemTime, limit: std::time::Duration) -> bool {
        let left = self.0.lock().ok().and_then(|mut slot| slot.take());
        left.is_none_or(|left| away_requires_lock(left, now, limit))
    }
}

/// How long the cover may stay on after the app is active again when it was held for a lock (12-F row 5 fix S4): the page
/// releases it once it has painted Unlock; if it never does, this long after the hold the cover comes off anyway.
#[cfg_attr(not(target_os = "ios"), allow(dead_code))]
const COVER_FAILSAFE: std::time::Duration = std::time::Duration::from_millis(1500);

/// Whether a cover held at `since` still stays at `now`: held, and the failsafe has not run out. Pure, so it is tested.
#[cfg_attr(not(target_os = "ios"), allow(dead_code))]
fn cover_hold_stays(since: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    since.is_some_and(|at| now.saturating_duration_since(at) < COVER_FAILSAFE)
}

/// iOS only (row 5 fix S4): the page calls this after it has painted Unlock (post a `requestAnimationFrame`); the cover
/// that was held across the lock comes off. Harmless when nothing is held.
#[cfg(target_os = "ios")]
#[tauri::command]
fn cover_release(app: tauri::AppHandle) -> Result<(), CoreError> {
    app.run_on_main_thread(cover::release)
        .map_err(|_| CoreError::new("internal", "could not reach the main thread"))
}

/// Drop the master through the same router the page uses, then tell the page (`core://locked`, no payload) so it draws
/// Unlock. Synchronous: the in-process call is a lock and a reply, and it must finish before the cover comes off.
#[cfg(target_os = "ios")]
fn lock_after_absence(app: &tauri::AppHandle) {
    let state = app.state::<Core>();
    let Ok(core) = core_of(&state) else { return };
    if tauri::async_runtime::block_on(core.call("key.lock", serde_json::json!({}))).is_ok() {
        // the cover was already held by cover.rs (it decides at DidBecomeActive); the page releases it after painting Unlock
        let _ = app.emit("core://locked", serde_json::json!({}));
    }
}

#[cfg(test)]
mod away_tests {
    use super::{away_requires_lock, AWAY_LIMIT};
    use std::time::{Duration, SystemTime};

    #[test]
    fn a_held_cover_stays_until_the_failsafe_and_an_unheld_one_never_does() {
        use super::{cover_hold_stays, COVER_FAILSAFE};
        let at = std::time::Instant::now();
        assert!(!cover_hold_stays(None, at), "nothing held: the cover comes off at once");
        assert!(cover_hold_stays(Some(at), at), "just held: it stays");
        assert!(cover_hold_stays(Some(at), at + COVER_FAILSAFE - Duration::from_millis(1)), "inside the failsafe: it stays");
        assert!(!cover_hold_stays(Some(at), at + COVER_FAILSAFE), "at the failsafe: it comes off");
        assert_eq!(COVER_FAILSAFE, Duration::from_millis(1500));
    }

    #[test]
    fn under_the_limit_keeps_the_master_the_limit_and_over_lock_and_a_clock_gone_back_locks() {
        let left = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let back = |secs: u64| left + Duration::from_secs(secs);
        assert!(!away_requires_lock(left, left, AWAY_LIMIT), "no time away");
        assert!(!away_requires_lock(left, back(299), AWAY_LIMIT), "299 s keeps");
        assert!(away_requires_lock(left, back(300), AWAY_LIMIT), "300 s locks");
        assert!(away_requires_lock(left, back(86_400), AWAY_LIMIT), "a day locks");
        assert!(away_requires_lock(left, left - Duration::from_secs(1), AWAY_LIMIT), "a clock one second back locks");
        assert!(away_requires_lock(left, SystemTime::UNIX_EPOCH, AWAY_LIMIT), "a clock far back locks");
        assert!(!away_requires_lock(left, back(5), Duration::from_secs(6)) && away_requires_lock(left, back(6), Duration::from_secs(6)), "the limit is a parameter");
    }

    #[test]
    fn the_limit_is_five_minutes() {
        assert_eq!(AWAY_LIMIT, Duration::from_secs(300));
    }
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
    #[cfg(target_os = "ios")]
    let away = AwayClock::default();
    let window = tauri::WebviewWindowBuilder::from_config(app.handle(), &config)?
        .on_navigation(coach::egress_guard::navigation_allowed)
        .on_new_window(|_url, _features| NewWindowResponse::Deny)
        .build()?;
    window.on_window_event(move |event| match event {
        tauri::WindowEvent::DragDrop(drag) => match drag {
            tauri::DragDropEvent::Enter { .. } => drag_over(&handle, true),
            tauri::DragDropEvent::Leave => drag_over(&handle, false),
            tauri::DragDropEvent::Drop { paths, .. } => {
                drag_over(&handle, false);
                import_drop::handle_drop(&handle, paths.clone());
            }
            _ => {} // Over: nothing to tell the page
        },
        // 12-F row 5c: five minutes away drops the master (the page then shows Unlock)
        #[cfg(target_os = "ios")]
        tauri::WindowEvent::Suspended => away.left(std::time::SystemTime::now()),
        #[cfg(target_os = "ios")]
        tauri::WindowEvent::Resumed if away.back(std::time::SystemTime::now(), away_limit()) => lock_after_absence(&handle),
        _ => {}
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
            relays::debug_seed(app.handle());
            // iOS only: the app-switcher cover (`cover.rs`): a plain view over the windows while the app is not active
            #[cfg(target_os = "ios")]
            if let Some(mtm) = objc2::MainThreadMarker::new() {
                cover::install(mtm);
            }
            #[cfg(all(debug_assertions, target_os = "ios"))]
            let proof_notes = ios_notes.clone();
            let core = start_core(app.handle());
            // N1: with no core there is no tail to hold the hook's notes; they wait in `StartupNotes` for `core_stderr`.
            #[cfg(target_os = "ios")]
            let orphan_notes = match &core {
                Ok(core) => {
                    for line in ios_notes {
                        core.note(line);
                    }
                    Vec::new()
                }
                Err(_) => ios_notes,
            };
            #[cfg(not(target_os = "ios"))]
            let orphan_notes: Vec<String> = Vec::new();
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
            app.manage(StartupNotes(orphan_notes));
            app.manage(coach::key::KeyHolder::default());
            app.manage(coach::commands::CoachState::default());
            app.manage(live::LiveState::default());
            build_main_window(app)?;
            debug_import_door(app.handle());
            #[cfg(all(debug_assertions, target_os = "ios"))]
            debug_keychain_proof_door(app.handle(), &proof_notes);
            Ok(())
        });
    // 12-F row 4: the phone's camera scan (the Mac app never links the plugin; its capability is iOS-scoped).
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    // Bet 17: `support_sites`/`support_open` exist only on macOS (`coach/commands.rs`'s own `#[cfg]`), so the
    // debug/release split below is crossed with `target_os = "macos"` rather than naming them unconditionally
    // (a non-macOS build, e.g. the iOS shell `tests/mobile_config.rs` checks, must still compile).
    #[cfg(all(debug_assertions, target_os = "macos"))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command, debug_unlock_from_file, debug_pair_digits_from_file,
        coach::commands::coach_settings_get, coach::commands::coach_settings_set, coach::commands::coach_key_set, coach::commands::coach_key_forget, coach::commands::coach_key_state, coach::commands::coach_ask, coach::commands::coach_reset, coach::commands::coach_probe, coach::commands::handoff_build, coach::commands::handoff_open,
        coach::commands::support_sites, coach::commands::support_open,
        live::live_start, live::live_stop, live::live_state]);
    #[cfg(all(debug_assertions, desktop, not(target_os = "macos")))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command, debug_unlock_from_file, debug_pair_digits_from_file,
        coach::commands::coach_settings_get, coach::commands::coach_settings_set, coach::commands::coach_key_set, coach::commands::coach_key_forget, coach::commands::coach_key_state, coach::commands::coach_ask, coach::commands::coach_reset, coach::commands::coach_probe, coach::commands::handoff_build, coach::commands::handoff_open,
        live::live_start, live::live_stop, live::live_state]);
    #[cfg(all(not(debug_assertions), target_os = "macos"))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command,
        coach::commands::coach_settings_get, coach::commands::coach_settings_set, coach::commands::coach_key_set, coach::commands::coach_key_forget, coach::commands::coach_key_state, coach::commands::coach_ask, coach::commands::coach_reset, coach::commands::coach_probe, coach::commands::handoff_build, coach::commands::handoff_open,
        coach::commands::support_sites, coach::commands::support_open,
        live::live_start, live::live_stop, live::live_state]);
    #[cfg(all(not(debug_assertions), desktop, not(target_os = "macos")))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command,
        coach::commands::coach_settings_get, coach::commands::coach_settings_set, coach::commands::coach_key_set, coach::commands::coach_key_forget, coach::commands::coach_key_state, coach::commands::coach_ask, coach::commands::coach_reset, coach::commands::coach_probe, coach::commands::handoff_build, coach::commands::handoff_open,
        live::live_start, live::live_stop, live::live_state]);
    // 12-F S5: the phone's lists carry no coach command (the coach is the product's one internet egress and is not on
    // the phone), so the phone binary registers none of them. `live_*` stay until Bet 14 decides the phone's link.
    #[cfg(all(debug_assertions, mobile, target_os = "ios"))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command, debug_unlock_from_file, debug_pair_digits_from_file, debug_offer_from_file, keep_awake, cover_release,
        relays::relays_list, relays::relays_add_folder, relays::relays_add_lan, relays::relays_remove, relays::relays_rename,
        live_phone::live_import, live_phone::live_produced, live_phone::live_debug_seed,
        live::live_start, live::live_stop, live::live_state]);
    #[cfg(all(not(debug_assertions), mobile, target_os = "ios"))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command, keep_awake, cover_release,
        relays::relays_list, relays::relays_add_folder, relays::relays_add_lan, relays::relays_remove, relays::relays_rename,
        live_phone::live_import, live_phone::live_produced, 
        live::live_start, live::live_stop, live::live_state]);
    #[cfg(all(debug_assertions, mobile, not(target_os = "ios")))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command, debug_unlock_from_file, debug_pair_digits_from_file,
        live::live_start, live::live_stop, live::live_state]);
    #[cfg(all(not(debug_assertions), mobile, not(target_os = "ios")))]
    let builder = builder.invoke_handler(tauri::generate_handler![core_call, core_unlock, core_stderr, launch_args, mcp_command,
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
