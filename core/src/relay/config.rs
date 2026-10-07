// SPDX-License-Identifier: AGPL-3.0-or-later
//! Which relays a device uses: `relay.json` beside the store, shared with the Python CLI, which reads the same
//! file. The list form is `{"relays": [{id, kind, path | url, label?, serve?}, ...]}`; the legacy forms
//! `{"folder": path}` (one entry that serves) and `{"lan": "http://host:port"}` still read. No secret lives
//! there: the LAN token derives from the master key at the moment of use.

use std::path::Path;

use serde_json::Value;

use super::folder::{FolderRelay, Relay};
use super::lan::{LanRelay, parse_base_url};
use crate::canon;
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
}

/// One relay of a device's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEntry {
    /// `default` (a legacy file) or 1-32 lowercase hex characters (written: 8, see [`new_id`]).
    pub id: String,
    pub config: RelayConfig,
    pub label: String,
    /// The entry this device serves to others (`relay.serve`, `pair.offer`): a folder, at most one per list.
    pub serve: bool,
}

/// `default`, or 1-32 characters of `[0-9a-f]`.
pub fn valid_id(id: &str) -> bool {
    id == "default"
        || (!id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// A fresh entry id: 8 lowercase hex characters from the operating system's randomness.
pub fn new_id() -> String {
    let mut random = [0u8; 4];
    if getrandom::fill(&mut random).is_err() {
        // no randomness: a time-derived id still keeps ids distinct within one list
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        random = now.to_be_bytes();
    }
    hex::encode(random)
}

/// One `relays` element, or `None` when it is malformed (the whole file is then unreadable).
fn parse_entry(value: &Value) -> Option<RelayEntry> {
    let object = value.as_object()?;
    let id = object.get("id")?.as_str()?;
    if !valid_id(id) {
        return None;
    }
    let text_of = |key: &str| object.get(key).and_then(Value::as_str).filter(|s| !s.is_empty());
    let config = match object.get("kind")?.as_str()? {
        "folder" => RelayConfig::Folder(text_of("path")?.to_string()),
        "lan" => RelayConfig::Lan(text_of("url")?.to_string()),
        _ => return None,
    };
    let label = match object.get("label") {
        None => "",
        Some(Value::String(text)) => text,
        Some(_) => return None,
    };
    let serve = match object.get("serve") {
        None => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return None,
    };
    if serve && matches!(config, RelayConfig::Lan(_)) {
        return None;
    }
    Some(RelayEntry {
        id: id.to_string(),
        config,
        label: label.to_string(),
        serve,
    })
}

/// The list in `relay.json`, or `None` when the file is missing, unreadable, not an object, or names nothing.
/// `{"relays": []}` is `Some` of an empty list: every caller reads it as "no relay", never as malformed.
///
/// `{"relays": [{id, kind: "folder" | "lan", path | url, label?, serve?}, ...]}` wins when `relays` is an array
/// (the legacy keys are then ignored). Any malformed entry, a repeated id or more than one `serve: true`
/// makes the whole file unreadable; an empty array is an empty list. A legacy `{"folder": ...}` is the one entry `default` with `serve: true`;
/// a legacy `{"lan": ...}` is the one entry `default` (a non-empty `lan` string wins over `folder`, as ever).
pub fn read_list(path: &Path) -> Option<Vec<RelayEntry>> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    if let Some(items) = value.get("relays").and_then(Value::as_array) {
        let entries: Vec<RelayEntry> = items.iter().map(parse_entry).collect::<Option<_>>()?;
        let mut seen = std::collections::HashSet::new();
        let distinct = entries.iter().all(|e| seen.insert(e.id.as_str()));
        let serving = entries.iter().filter(|e| e.serve).count();
        return (distinct && serving <= 1).then_some(entries);
    }
    let text_of = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let (config, serve) = match (text_of("lan"), text_of("folder")) {
        (Some(url), _) => (RelayConfig::Lan(url), false),
        (None, Some(folder)) => (RelayConfig::Folder(folder), true),
        (None, None) => return None,
    };
    Some(vec![RelayEntry {
        id: "default".to_string(),
        config,
        label: String::new(),
        serve,
    }])
}

/// What a legacy single-relay reader sees: the first entry's configuration.
pub fn read(path: &Path) -> Option<RelayConfig> {
    read_list(path)?.into_iter().next().map(|entry| entry.config)
}

/// Write `entries` as the list form (sorted keys, `label` only when set, `serve` only when true), atomically
/// (temp file beside it, mode 0600, rename), creating the parent folder. More than one `serve` entry is refused.
pub fn write_list(path: &Path, entries: &[RelayEntry]) -> std::io::Result<()> {
    if entries.iter().filter(|e| e.serve).count() > 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only one relay can serve",
        ));
    }
    let items = entries
        .iter()
        .map(|entry| {
            let (kind, place) = match &entry.config {
                RelayConfig::Folder(folder) => ("path", folder),
                RelayConfig::Lan(url) => ("url", url),
            };
            let mut members = vec![
                ("id".to_string(), canon::Value::Str(entry.id.clone())),
                (
                    "kind".to_string(),
                    canon::Value::Str(if kind == "path" { "folder" } else { "lan" }.to_string()),
                ),
                (kind.to_string(), canon::Value::Str(place.clone())),
            ];
            if !entry.label.is_empty() {
                members.push(("label".to_string(), canon::Value::Str(entry.label.clone())));
            }
            if entry.serve {
                members.push(("serve".to_string(), canon::Value::Bool(true)));
            }
            canon::Value::Object(members)
        })
        .collect();
    let text = canon::dumps_spaced(&canon::Value::Object(vec![(
        "relays".to_string(),
        canon::Value::Array(items),
    )]));
    crate::pair_client::write_atomic(path, format!("{text}\n").as_bytes())
}

/// The entry this device serves: the one with `serve: true`, when it is a folder.
pub fn serve_entry(entries: &[RelayEntry]) -> Option<&RelayEntry> {
    entries
        .iter()
        .find(|e| e.serve && matches!(e.config, RelayConfig::Folder(_)))
}

/// The address of the first `lan` entry as configured (`sync.status.relay_url` shows its base).
pub fn first_lan_url(entries: &[RelayEntry]) -> Option<String> {
    entries.iter().find_map(|e| match &e.config {
        RelayConfig::Lan(url) => Some(url.clone()),
        RelayConfig::Folder(_) => None,
    })
}

/// [`open`] on an entry.
pub fn open_entry(entry: &RelayEntry, master: &[u8]) -> Result<Box<dyn Relay + Send>, String> {
    open(&entry.config, master)
}

/// Open the relay a configuration names. `master` derives the LAN token. The error text states a
/// rule, never the configured address.
pub fn open(config: &RelayConfig, master: &[u8]) -> Result<Box<dyn Relay + Send>, String> {
    match config {
        RelayConfig::Folder(folder) => Ok(Box::new(FolderRelay::creating_root(keys::expand_user(
            Path::new(folder),
        )))),
        RelayConfig::Lan(url) => Ok(Box::new(LanRelay::new(url, master)?)),
    }
}

/// The normalised base address (`http://host[:port]`, no trailing slash) of a LAN relay `url`, or `None` when
/// [`check_lan_url`] would refuse it. What `sync.status.relay_url` shows.
pub fn lan_base_url(url: &str) -> Option<String> {
    parse_base_url(url).ok()
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

    fn entry(id: &str, config: RelayConfig, label: &str, serve: bool) -> RelayEntry {
        RelayEntry { id: id.into(), config, label: label.into(), serve }
    }

    #[test]
    fn the_legacy_forms_read_as_one_entry_named_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("relay.json");
        for (text, want) in [
            (r#"{"folder": "/r"}"#, Some(entry("default", RelayConfig::Folder("/r".into()), "", true))),
            (r#"{"lan": "http://x:1"}"#, Some(entry("default", RelayConfig::Lan("http://x:1".into()), "", false))),
            (r#"{"folder": "/r", "lan": "http://x:1"}"#, Some(entry("default", RelayConfig::Lan("http://x:1".into()), "", false))),
            (r#"{"folder": 5}"#, None),
            (r#"{}"#, None),
        ] {
            std::fs::write(&path, text).expect("write");
            assert_eq!(read_list(&path), want.map(|e| vec![e]), "{text}");
        }
    }

    #[test]
    fn the_list_form_wins_and_every_malformed_case_reads_as_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("relay.json");
        let good = r#"{"relays": [{"id": "0a1b2c3d", "kind": "folder", "path": "/a", "label": "cloud", "serve": true},
                                  {"id": "default", "kind": "lan", "url": "http://h:2"}], "folder": "/ignored"}"#;
        std::fs::write(&path, good).expect("write");
        assert_eq!(
            read_list(&path),
            Some(vec![
                entry("0a1b2c3d", RelayConfig::Folder("/a".into()), "cloud", true),
                entry("default", RelayConfig::Lan("http://h:2".into()), "", false),
            ])
        );
        std::fs::write(&path, r#"{"relays": []}"#).expect("write");
        assert_eq!(read_list(&path), Some(Vec::new()), "an empty array is an empty list");
        assert_eq!(read(&path), None);
        for bad in [
            r#"{"relays": [5]}"#,
            r#"{"relays": [{"kind": "folder", "path": "/a"}]}"#,
            r#"{"relays": [{"id": "ABCD", "kind": "folder", "path": "/a"}]}"#,
            r#"{"relays": [{"id": "", "kind": "folder", "path": "/a"}]}"#,
            r#"{"relays": [{"id": "0123456789abcdef0123456789abcdef0", "kind": "folder", "path": "/a"}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "ftp", "path": "/a"}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "folder"}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "folder", "path": ""}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "lan", "path": "/a"}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "folder", "path": "/a", "label": 5}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "folder", "path": "/a", "serve": "yes"}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "lan", "url": "http://h:2", "serve": true}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "folder", "path": "/a"}, {"id": "ab", "kind": "folder", "path": "/b"}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "folder", "path": "/a", "serve": true}, {"id": "cd", "kind": "folder", "path": "/b", "serve": true}]}"#,
            // what serde_json refuses, pinned so the Python oracle keeps refusing the same (BL-8)
            r#"{"relays": [{"id": "ab", "kind": "folder", "path": "\ud800"}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "folder", "path": "/a", "x": NaN}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "folder", "path": "/a", "x": -Infinity}]}"#,
            r#"{"relays": [{"id": "ab", "kind": "folder", "path": "/a", "x": 1e400}]}"#,
            &format!(r#"{{"relays": [{{"id": "ab", "kind": "folder", "path": "/a", "x": 1{}}}]}}"#, "0".repeat(400)),
            r#"{"relays": [{"id": "ab", "kind": "folder", "path": "\ud800"}], "relays": [{"id": "cd", "kind": "folder", "path": "/b"}]}"#,
            &format!(r#"{{"relays": [{{"id": "ab", "kind": "folder", "path": "/a", "x": {}{}}}]}}"#, "[".repeat(126), "]".repeat(126)),
        ] {
            std::fs::write(&path, bad).expect("write");
            assert_eq!(read_list(&path), None, "{bad}");
        }
        // an extra key serde can hold is no reason to refuse (u64::MAX, 1e300); nesting 127 deep in all (3 + 124) still reads
        for ok in [
            r#"{"relays": [{"id": "ab", "kind": "folder", "path": "/a", "x": 18446744073709551615, "y": 1e300}]}"#.to_string(),
            format!(r#"{{"relays": [{{"id": "ab", "kind": "folder", "path": "/a", "x": {}{}}}]}}"#, "[".repeat(124), "]".repeat(124)),
        ] {
            std::fs::write(&path, &ok).expect("write");
            assert_eq!(read_list(&path), Some(vec![entry("ab", RelayConfig::Folder("/a".into()), "", false)]), "{ok}");
        }
    }

    #[test]
    fn write_list_round_trips_in_sorted_keys_and_refuses_two_servers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("deeper").join("relay.json");
        let entries = vec![
            entry("0a1b2c3d", RelayConfig::Folder("~/Cloud".into()), "cloud", true),
            entry("deadbeef", RelayConfig::Lan("http://h:2".into()), "", false),
        ];
        write_list(&path, &entries).expect("write");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "{\"relays\": [{\"id\": \"0a1b2c3d\", \"kind\": \"folder\", \"label\": \"cloud\", \"path\": \"~/Cloud\", \"serve\": true}, \
             {\"id\": \"deadbeef\", \"kind\": \"lan\", \"url\": \"http://h:2\"}]}\n"
        );
        assert_eq!(read_list(&path), Some(entries.clone()));
        let two = vec![
            entry("aa", RelayConfig::Folder("/a".into()), "", true),
            entry("bb", RelayConfig::Folder("/b".into()), "", true),
        ];
        assert!(write_list(&path, &two).is_err());
        assert_eq!(read_list(&path), Some(entries), "a refused write leaves the file");
    }

    #[test]
    fn new_ids_are_eight_hex_and_the_serve_and_lan_helpers_pick_the_right_entry() {
        let id = new_id();
        assert!(id.len() == 8 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{id}");
        assert!(valid_id(&id) && valid_id("default") && !valid_id("Default") && !valid_id("xyz"));
        let list = vec![
            entry("aa", RelayConfig::Lan("http://h:2".into()), "", false),
            entry("bb", RelayConfig::Folder("/b".into()), "", true),
            entry("cc", RelayConfig::Lan("http://k:3".into()), "", false),
        ];
        assert_eq!(serve_entry(&list).map(|e| e.id.as_str()), Some("bb"));
        assert_eq!(first_lan_url(&list).as_deref(), Some("http://h:2"));
        assert_eq!(serve_entry(&list[..1]), None);
        assert_eq!(first_lan_url(&list[1..2]), None);
    }
}
