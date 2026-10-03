// SPDX-License-Identifier: AGPL-3.0-or-later
//! The coach's Tauri commands: settings and the provider key (slice 4), and the one command that asks the
//! model, [`coach_ask`] (slice 5). Errors cross the boundary as [`CoachError`]: two fixed strings from closed
//! enums and, for an error status only, its number.

use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;
use serde_json::{json, Value};
use tauri::{Manager, State};
use zeroize::Zeroizing;

use super::chat_loop::{self, Conversation, ToolCallError, TraceEntry};
use super::egress::EgressError;
use super::key::{self, KeyError, KeyHolder, KeyState};
use super::probe::{self, ProbeReport};
use super::settings::{self, Mode, Settings, SettingsError};

/// What a failed coach command tells the webview. Both strings come from closed enums. A failed question also
/// carries what already left the machine before the failure: the tool calls whose results were in a request
/// that was sent (`trace`, the same entries a good answer's drawer shows) and how many requests went out
/// (`sends`). Both are empty for every other failure.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CoachError {
    pub code: &'static str,
    pub message: &'static str,
    pub status: Option<u16>,
    pub trace: Vec<TraceEntry>,
    pub sends: usize,
}

impl CoachError {
    fn plain(code: &'static str, message: &'static str, status: Option<u16>) -> CoachError {
        CoachError { code, message, status, trace: Vec::new(), sends: 0 }
    }

    /// A failed question: the error and what had left before it.
    fn with_sent(error: chat_loop::CoachError, conversation: &Conversation) -> CoachError {
        CoachError {
            trace: conversation.sent_trace().to_vec(),
            sends: conversation.question_sends,
            ..CoachError::from(error)
        }
    }
}

/// The name the loop's commands use for [`CoachError`] on the wire.
pub type CoachErrorDto = CoachError;

impl From<chat_loop::CoachError> for CoachError {
    fn from(e: chat_loop::CoachError) -> Self {
        CoachError::plain(e.code(), e.message(), e.status())
    }
}

impl From<EgressError> for CoachError {
    fn from(e: EgressError) -> Self {
        CoachError::plain(e.code(), e.message(), e.status())
    }
}

impl From<KeyError> for CoachError {
    fn from(e: KeyError) -> Self {
        CoachError::plain(e.code(), e.message(), None)
    }
}

impl From<SettingsError> for CoachError {
    fn from(e: SettingsError) -> Self {
        let status = match e {
            SettingsError::Url(inner) => inner.status(),
            _ => None,
        };
        CoachError::plain(e.code(), e.message(), status)
    }
}

fn config_dir(app: &tauri::AppHandle) -> Result<PathBuf, CoachError> {
    app.path()
        .app_config_dir()
        .map_err(|_| CoachError::from(SettingsError::NotWritable))
}

#[tauri::command]
pub fn coach_settings_get(app: tauri::AppHandle) -> Settings {
    config_dir(&app).map(|dir| settings::load(&dir)).unwrap_or_default()
}

/// Validate and save. `key_in_keychain` is not the webview's to set: the stored value is kept.
#[tauri::command]
pub fn coach_settings_set(app: tauri::AppHandle, settings: Settings) -> Result<Settings, CoachError> {
    let dir = config_dir(&app)?;
    let merged = settings::load(&dir).accept_from_client(settings);
    settings::save(&dir, &merged)?;
    Ok(merged)
}

fn remember_flag(app: &tauri::AppHandle, in_keychain: bool) -> Result<(), CoachError> {
    let dir = config_dir(app)?;
    let mut current = settings::load(&dir);
    if current.key_in_keychain != in_keychain {
        current.key_in_keychain = in_keychain;
        // a half-typed address may be on file while the coach is off: write the flag without re-validating
        settings::save(&dir, &current).or_else(|e| match e {
            SettingsError::NotWritable => Err(e),
            _ => Ok(()),
        })?;
    }
    Ok(())
}

/// Keep the provider key: in the keychain (`remember`) or for this session only. The key is a
/// `Zeroizing<String>` from the first moment (as `core_unlock` does with the passphrase) and is moved,
/// never copied, into the keychain call or the holder. Blocking keychain work runs off the UI thread.
#[tauri::command]
pub async fn coach_key_set(
    app: tauri::AppHandle,
    holder: State<'_, KeyHolder>,
    key: Zeroizing<String>,
    remember: bool,
) -> Result<KeyState, CoachError> {
    key::check(&key)?;
    if remember {
        tauri::async_runtime::spawn_blocking(move || key::store(key))
            .await
            .map_err(|_| CoachError::from(KeyError::Busy))??;
        holder.clear()?;
        remember_flag(&app, true)?;
    } else {
        holder.set(key)?;
        // "do not remember" also removes an older remembered key, so the choice is what it says
        match tauri::async_runtime::spawn_blocking(key::forget).await {
            Ok(Ok(_) | Err(KeyError::NoKeychain)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(KeyError::Busy.into()),
        }
        remember_flag(&app, false)?;
    }
    Ok(holder.state())
}

#[tauri::command]
pub async fn coach_key_forget(app: tauri::AppHandle, holder: State<'_, KeyHolder>) -> Result<KeyState, CoachError> {
    holder.clear()?;
    match tauri::async_runtime::spawn_blocking(key::forget).await {
        Ok(Ok(_) | Err(KeyError::NoKeychain)) => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(KeyError::Busy.into()),
    }
    remember_flag(&app, false)?;
    Ok(holder.state())
}

/// Where the key is. A quiet read: it cannot raise a keychain dialog.
#[tauri::command]
pub fn coach_key_state(holder: State<'_, KeyHolder>) -> KeyState {
    holder.state()
}

// ---- the coach loop -----------------------------------------------------------------------------

/// The one conversation of the app, in managed state. In memory only: nothing here is written anywhere, and
/// [`coach_reset`] (or quitting) ends it.
#[derive(Default)]
pub struct CoachState {
    conversation: Mutex<Conversation>,
}

/// What a question returns to the webview: the model's scrubbed text and the tool calls of this question (for
/// the "what the model can see" drawer). Neither is kept anywhere else.
#[derive(Debug, Clone, Serialize)]
pub struct CoachReply {
    pub text: String,
    pub trace: Vec<TraceEntry>,
}

/// Ask the model. Order matters: the settings are read and the gate runs first, so **off sends nothing and
/// never reads the key**; the key is read only after the gate, and the settings are read again before every
/// later request of the question (the gate closure of [`ask_blocking`]). The loop is synchronous, so it runs on a blocking
/// thread, and its tool runner calls the core's `tools.call` from there.
#[tauri::command]
pub async fn coach_ask(app: tauri::AppHandle, text: String) -> Result<CoachReply, CoachErrorDto> {
    let settings = config_dir(&app).map(|dir| settings::load(&dir)).unwrap_or_default();
    chat_loop::gate(&settings)?;
    tauri::async_runtime::spawn_blocking(move || ask_blocking(&app, &settings, &text))
        .await
        .map_err(|_| CoachError::from(KeyError::Busy))?
}

fn ask_blocking(app: &tauri::AppHandle, settings: &Settings, text: &str) -> Result<CoachReply, CoachErrorDto> {
    let core = app.state::<crate::Core>().0.clone();
    let call_tool = move |name: &str, arguments: Value| -> Result<Value, ToolCallError> {
        let core = core.as_ref().map_err(|e| ToolCallError { code: e.code.clone() })?;
        let params = json!({"name": name, "arguments": arguments});
        tauri::async_runtime::block_on(core.call("tools.call", params)).map_err(|e| ToolCallError { code: e.code })
    };
    // before every request of the question the saved settings are read again: switching the coach off (or
    // changing the address) while a tool runs stops the next request. An unreadable file reads as off.
    let send_gate = || {
        let now = config_dir(app).map(|dir| settings::load(&dir)).unwrap_or_default();
        chat_loop::settings_gate(settings, &now)
    };
    let state = app.state::<CoachState>();
    let mut conversation = state.conversation.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let answer = chat_loop::ask_configured(
        settings,
        super::provider,
        || app.state::<KeyHolder>().resolve(),
        &call_tool,
        &send_gate,
        &mut conversation,
        text,
    );
    let trace = conversation.trace.clone();
    answer.map(|text| CoachReply { text, trace }).map_err(|error| CoachError::with_sent(error, &conversation))
}

/// Test the endpoint (slice 6): two synthetic requests, no tool, no core call, so a locked store is fine. The
/// settings gate runs first (off is [`CoachError`] `off`); a cloud endpoint without a key is `no_key`, the same
/// answer a question gets.
#[tauri::command]
pub async fn coach_probe(app: tauri::AppHandle) -> Result<ProbeReport, CoachErrorDto> {
    let settings = config_dir(&app).map(|dir| settings::load(&dir)).unwrap_or_default();
    chat_loop::gate(&settings)?;
    let bearer = app.state::<KeyHolder>().resolve();
    if settings.mode == Mode::Cloud && bearer.is_none() {
        return Err(chat_loop::CoachError::NoKey.into());
    }
    tauri::async_runtime::spawn_blocking(move || match super::provider(&settings) {
        Some(egress) => Ok(probe::probe(egress.as_ref(), &settings, bearer.as_ref())),
        None => Err(CoachError::from(EgressError::BadUrl)),
    })
    .await
    .map_err(|_| CoachError::from(KeyError::Busy))?
}

/// Forget the conversation and its trace.
#[tauri::command]
pub fn coach_reset(state: State<'_, CoachState>) {
    state.conversation.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coach_errors_carry_fixed_strings_and_only_a_status_number() {
        let e = CoachError::from(EgressError::Status(401));
        assert_eq!((e.code, e.status), ("status", Some(401)));
        assert!(!e.message.contains("401"));
        let k = CoachError::from(KeyError::Refused);
        assert_eq!((k.code, k.status), ("keychain_refused", None));
        let s = CoachError::from(SettingsError::Url(EgressError::PlainHttpNeedsLocalIp));
        assert_eq!(s.code, "plain_http_needs_local_ip");
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"status\":null"));
        assert!(json.contains("\"trace\":[]") && json.contains("\"sends\":0"), "{json}");
    }

    #[test]
    fn a_failed_question_carries_its_sent_trace_and_send_count() {
        let mut conversation = Conversation::new();
        let e = CoachError::with_sent(chat_loop::CoachError::Egress(EgressError::Status(500)), &conversation);
        assert_eq!((e.code, e.status, e.trace.len(), e.sends), ("status", Some(500), 0, 0));
        conversation.question_sends = 3;
        let e = CoachError::with_sent(chat_loop::CoachError::Off, &conversation);
        assert_eq!((e.code, e.sends), ("off", 3));
    }
}
