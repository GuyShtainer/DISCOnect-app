// SPDX-License-Identifier: AGPL-3.0-or-later
//! Which relay a device uses: `relay.json` beside the store (`{"folder": path}` or
//! `{"lan": "http://host:port"}`), shared with the Python CLI, which reads the same file. No
//! secret lives there: the LAN token derives from the master key at the moment of use.

use std::path::Path;

use serde_json::Value;

use super::folder::{FolderRelay, Relay};
use super::lan::{LanRelay, parse_base_url};
use crate::keys;

/// The relay a configuration names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayConfig {
    /// A folder the user's own tools carry (`~` is expanded when it is opened).
    Folder(String),
    /// A LAN relay: `http://host:port`.
    Lan(String),
}

impl RelayConfig {
    /// The relay a command-line argument names: `http://...` is a LAN relay, anything else a folder.
    pub fn from_arg(text: &str) -> RelayConfig {
        if text.starts_with("http://") || text.starts_with("https://") {
            RelayConfig::Lan(text.to_string())
        } else {
            RelayConfig::Folder(text.to_string())
        }
    }

    /// The `relay.json` key and value.
    pub fn entry(&self) -> (&'static str, &str) {
        match self {
            RelayConfig::Folder(folder) => ("folder", folder),
            RelayConfig::Lan(url) => ("lan", url),
        }
    }
}

/// The configuration in `relay.json`, or `None` when the file is missing, unreadable, not an
/// object, or names nothing. A non-empty `lan` string wins over `folder` (the Python core reads the
/// same two keys in the same order and refuses `lan`).
pub fn read(path: &Path) -> Option<RelayConfig> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let text_of = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    text_of("lan")
        .map(RelayConfig::Lan)
        .or_else(|| text_of("folder").map(RelayConfig::Folder))
}

/// Open the relay a configuration names. `master` derives the LAN token. The error text states a
/// rule, never the configured address.
pub fn open(config: &RelayConfig, master: &[u8]) -> Result<Box<dyn Relay + Send>, String> {
    match config {
        RelayConfig::Folder(folder) => Ok(Box::new(FolderRelay::new(keys::expand_user(
            Path::new(folder),
        )))),
        RelayConfig::Lan(url) => Ok(Box::new(LanRelay::new(url, master)?)),
    }
}

/// `Ok` when `url` is acceptable as a LAN relay address (the check `open` applies).
pub fn check_lan_url(url: &str) -> Result<(), String> {
    parse_base_url(url).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_wins_and_junk_names_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("relay.json");
        assert_eq!(read(&path), None);
        for (text, want) in [
            (
                r#"{"folder": "/r"}"#,
                Some(RelayConfig::Folder("/r".into())),
            ),
            (
                r#"{"lan": "http://x:1"}"#,
                Some(RelayConfig::Lan("http://x:1".into())),
            ),
            (
                r#"{"folder": "/r", "lan": "http://x:1"}"#,
                Some(RelayConfig::Lan("http://x:1".into())),
            ),
            (
                r#"{"folder": "/r", "lan": ""}"#,
                Some(RelayConfig::Folder("/r".into())),
            ),
            (r#"{"folder": 5}"#, None),
            (r#"{"folder": ""}"#, None),
            (r#"[1]"#, None),
            ("not json", None),
        ] {
            std::fs::write(&path, text).expect("write");
            assert_eq!(read(&path), want, "{text}");
        }
    }

    #[test]
    fn an_argument_names_its_transport() {
        assert_eq!(
            RelayConfig::from_arg("http://127.0.0.1:9"),
            RelayConfig::Lan("http://127.0.0.1:9".into())
        );
        assert_eq!(
            RelayConfig::from_arg("/some/folder"),
            RelayConfig::Folder("/some/folder".into())
        );
        assert!(open(&RelayConfig::Lan("https://x:1".into()), &[1; 32]).is_err());
    }
}
