// SPDX-License-Identifier: AGPL-3.0-or-later
//! The coach's provider settings: everything about the provider that is **not** secret, kept as one small
//! JSON file in the app's config folder (Tauri's `app_config_dir()`, `coach.json`), never in the data folder
//! and never next to the store. The provider key is not here (see [`super::key`]); the only trace of it is
//! the `key_in_keychain` flag, which says whether to look in the keychain.
//!
//! Reading is tolerant (a missing, oversized or damaged file is [`Settings::default`], which is `Off`:
//! failing closed is the same as being off). Writing is atomic (a temp file, then a rename). The base URL is
//! checked with the egress rules on every save, so the Settings card can show a refusal at once.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::egress::{Endpoint, EgressError};

/// The file name inside the config folder.
pub const FILE_NAME: &str = "coach.json";
/// A settings file is a few hundred bytes; anything bigger is not ours.
const MAX_FILE: u64 = 64 * 1024;
const MAX_MODEL_LEN: usize = 200;

/// Where the coach sends its requests. `Off` (the default) means nothing is ever sent and no client exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Off,
    Local,
    Cloud,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub mode: Mode,
    /// The provider's base address, e.g. `https://api.example/v1` or `http://127.0.0.1:11434/v1`.
    pub base_url: String,
    /// The model name the provider knows.
    pub model: String,
    /// True when the provider key was stored in the OS keychain (advisory: the keychain is the truth).
    pub key_in_keychain: bool,
    /// Whether the data series the coach reads may include per-day points (otherwise facts only).
    pub include_points: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { mode: Mode::Off, base_url: String::new(), model: String::new(), key_in_keychain: false, include_points: false }
    }
}

/// Why settings could not be saved. Closed; fixed messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsError {
    /// The base address failed the egress rules.
    Url(EgressError),
    /// The model name is empty (when the coach is on), too long, or holds control characters.
    BadModel,
    /// The file could not be written.
    NotWritable,
}

impl SettingsError {
    pub fn message(&self) -> &'static str {
        match self {
            SettingsError::Url(e) => e.message(),
            SettingsError::BadModel => "the model name is empty, too long or has control characters",
            SettingsError::NotWritable => "the coach settings could not be saved",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            SettingsError::Url(e) => e.code(),
            SettingsError::BadModel => "bad_model",
            SettingsError::NotWritable => "settings_not_writable",
        }
    }
}

impl Settings {
    /// The rules a save enforces. `Off` may keep a half-typed address, but a non-empty one must still pass.
    pub fn validate(&self) -> Result<(), SettingsError> {
        let on = self.mode != Mode::Off;
        if on {
            Endpoint::from_settings(self).map_err(SettingsError::Url)?;
        } else if !self.base_url.trim().is_empty() {
            Endpoint::parse(&self.base_url).map_err(SettingsError::Url)?;
        }
        let model_ok = self.model.len() <= MAX_MODEL_LEN && !self.model.chars().any(char::is_control);
        if !model_ok || (on && self.model.trim().is_empty()) {
            return Err(SettingsError::BadModel);
        }
        Ok(())
    }

    /// What a client-sent value may change: everything except `key_in_keychain`, which only the key
    /// commands set (a webview cannot claim a key is stored).
    pub fn accept_from_client(&self, incoming: Settings) -> Settings {
        Settings { key_in_keychain: self.key_in_keychain, ..incoming }
    }
}

/// Read `coach.json` from `dir`; a missing or unusable file is the default (off).
pub fn load(dir: &Path) -> Settings {
    let path = dir.join(FILE_NAME);
    let usable = fs::metadata(&path).map(|m| m.is_file() && m.len() <= MAX_FILE).unwrap_or(false);
    if !usable {
        return Settings::default();
    }
    fs::read(&path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
}

/// Validate, then write `coach.json` atomically.
pub fn save(dir: &Path, settings: &Settings) -> Result<(), SettingsError> {
    settings.validate()?;
    write_atomic(dir, settings).map_err(|()| SettingsError::NotWritable)
}

fn write_atomic(dir: &Path, settings: &Settings) -> Result<(), ()> {
    fs::create_dir_all(dir).map_err(|_| ())?;
    let bytes = serde_json::to_vec_pretty(settings).map_err(|_| ())?;
    let temp = dir.join(format!("{FILE_NAME}.tmp"));
    let written = (|| {
        let mut file = fs::File::create(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
        return Err(());
    }
    fs::rename(&temp, dir.join(FILE_NAME)).map_err(|_| {
        let _ = fs::remove_file(&temp);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("disconect-coach-settings-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn cloud() -> Settings {
        Settings {
            mode: Mode::Cloud,
            base_url: "https://api.example/v1".into(),
            model: "some-model".into(),
            key_in_keychain: true,
            include_points: true,
        }
    }

    #[test]
    fn the_default_is_off_and_empty() {
        let s = Settings::default();
        assert_eq!(s.mode, Mode::Off);
        assert!(s.base_url.is_empty() && s.model.is_empty() && !s.key_in_keychain && !s.include_points);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn a_missing_oversized_or_damaged_file_reads_as_the_default() {
        let dir = scratch("tolerant");
        assert_eq!(load(&dir), Settings::default());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(FILE_NAME), b"{not json").unwrap();
        assert_eq!(load(&dir), Settings::default());
        fs::write(dir.join(FILE_NAME), vec![b' '; (MAX_FILE + 1) as usize]).unwrap();
        assert_eq!(load(&dir), Settings::default());
        fs::write(dir.join(FILE_NAME), br#"{"mode":"nonsense"}"#).unwrap();
        assert_eq!(load(&dir), Settings::default());
        // an older file without the newer fields keeps what it has
        fs::write(dir.join(FILE_NAME), br#"{"mode":"local","base_url":"http://127.0.0.1:1/v1","model":"m"}"#).unwrap();
        assert_eq!(load(&dir).mode, Mode::Local);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_then_load_round_trips_and_leaves_no_temp_file() {
        let dir = scratch("roundtrip");
        save(&dir, &cloud()).unwrap();
        assert_eq!(load(&dir), cloud());
        let names: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(names, vec![FILE_NAME.to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn nothing_secret_is_in_the_file() {
        let dir = scratch("nosecret");
        save(&dir, &cloud()).unwrap();
        let text = fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
        for name in &keys {
            assert!(!name.contains("key") || name.as_str() == "key_in_keychain", "{name}");
            assert!(!name.contains("secret") && !name.contains("token") && !name.contains("bearer"), "{name}");
        }
        assert_eq!(value["key_in_keychain"], serde_json::json!(true));
        assert!(value["key_in_keychain"].is_boolean(), "a flag, not a key");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_refuses_what_egress_refuses_and_writes_nothing() {
        let dir = scratch("refuse");
        let mut s = cloud();
        for (url, want) in [
            ("http://example.com", EgressError::PlainHttpNeedsLocalIp),
            ("https://user:pw@api.example", EgressError::UserinfoRefused),
            ("ftp://x", EgressError::BadUrl),
            ("", EgressError::BadUrl),
        ] {
            s.base_url = url.into();
            assert_eq!(save(&dir, &s), Err(SettingsError::Url(want)), "{url}");
        }
        let local = Settings { mode: Mode::Local, base_url: "https://api.example/v1".into(), ..cloud() };
        assert_eq!(save(&dir, &local), Err(SettingsError::Url(EgressError::LocalNeedsLocalAddress)));
        assert!(!dir.join(FILE_NAME).exists());
        // off keeps a blank address, but a typed one is still checked
        let mut off = Settings::default();
        assert!(save(&dir, &off).is_ok());
        off.base_url = "http://example.com".into();
        assert!(save(&dir, &off).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_model_name_is_checked() {
        let mut s = cloud();
        s.model = String::new();
        assert_eq!(s.validate(), Err(SettingsError::BadModel));
        s.model = "a\nb".into();
        assert_eq!(s.validate(), Err(SettingsError::BadModel));
        s.model = "x".repeat(MAX_MODEL_LEN + 1);
        assert_eq!(s.validate(), Err(SettingsError::BadModel));
    }

    #[test]
    fn the_client_cannot_set_the_keychain_flag() {
        let current = Settings { key_in_keychain: false, ..cloud() };
        let incoming = Settings { key_in_keychain: true, ..cloud() };
        assert!(!current.accept_from_client(incoming).key_in_keychain);
        let current = Settings { key_in_keychain: true, ..cloud() };
        let incoming = Settings { key_in_keychain: false, ..cloud() };
        assert!(current.accept_from_client(incoming).key_in_keychain);
    }

    #[test]
    fn messages_are_fixed_text() {
        for e in [SettingsError::BadModel, SettingsError::NotWritable, SettingsError::Url(EgressError::BadUrl)] {
            assert!(!e.message().contains("http") && !e.code().is_empty());
        }
    }
}
