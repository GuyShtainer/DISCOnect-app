// SPDX-License-Identifier: AGPL-3.0-or-later
//! The coach's Tauri commands for slice 4: settings and the provider key. There is deliberately **no**
//! command here that makes a model call (slice 5). Errors cross the boundary as [`CoachError`]: two fixed
//! strings from closed enums and, for an error status only, its number.

use std::path::PathBuf;

use serde::Serialize;
use tauri::{Manager, State};
use zeroize::Zeroizing;

use super::egress::EgressError;
use super::key::{self, KeyError, KeyHolder, KeyState};
use super::settings::{self, Settings, SettingsError};

/// What a failed coach command tells the webview. Both strings come from closed enums.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoachError {
    pub code: &'static str,
    pub message: &'static str,
    pub status: Option<u16>,
}

impl From<EgressError> for CoachError {
    fn from(e: EgressError) -> Self {
        CoachError { code: e.code(), message: e.message(), status: e.status() }
    }
}

impl From<KeyError> for CoachError {
    fn from(e: KeyError) -> Self {
        CoachError { code: e.code(), message: e.message(), status: None }
    }
}

impl From<SettingsError> for CoachError {
    fn from(e: SettingsError) -> Self {
        let status = match e {
            SettingsError::Url(inner) => inner.status(),
            _ => None,
        };
        CoachError { code: e.code(), message: e.message(), status }
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
    }
}
