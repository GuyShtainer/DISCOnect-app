// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where the data folder is: pure resolution, no side effects (Bet 02a). The twin of
//! `disconect/storage/home.py`; the hint and warning texts are byte-identical on both sides.
//!
//! Nothing here creates, renames or moves anything (it runs from `serve` start-up and every app
//! launch). Moving the old folder is `disconect migrate-home` (Python only).
//!
//! A *writer* must never re-create an old folder that `migrate-home` moved away underneath a running
//! process: [`moved_legacy_home`] is the check every writer makes before its `create_dir_all`.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::identity::{
    COMMAND, DATA_DIR, DB_FILENAME, ENV_PREFIX, LEGACY_DB_FILENAME, LEGACY_ENV_PREFIX, LEGACY_HOMES, PRODUCT,
};

/// The variable that pins the database path.
pub const DB_ENV: &str = "DISCONECT_DB";
/// Env names of the old builds: never read, only warned about.
pub const LEGACY_ENV_SUFFIXES: [&str; 4] = ["DB", "KEYS", "PASSPHRASE", "RECOVERY_WORDS"];
pub const RELAY_CONFIG_NAME: &str = "relay.json";

/// The resolved default store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultDb {
    pub path: PathBuf,
    /// The old folder's name (`.hearthbeat`) when the store is being read through it.
    pub legacy_home: Option<&'static str>,
}

fn expand(path: &Path, home: Option<&Path>) -> PathBuf {
    match (path.strip_prefix("~"), home) {
        (Ok(rest), Some(home)) => home.join(rest),
        _ => path.to_path_buf(),
    }
}

/// The decision, with its inputs explicit: `$DISCONECT_DB` (with `~` expanded) if set and non-empty;
/// else `<home>/.disconect/disconect.db` if that **file** exists; else the old folder's file if it
/// exists; else the new path. `None` only when no override is set and there is no home.
pub fn resolve_in(home: Option<&Path>, db_env: Option<&OsStr>) -> Option<DefaultDb> {
    if let Some(over) = db_env.filter(|v| !v.is_empty()) {
        return Some(DefaultDb {
            path: expand(Path::new(over), home),
            legacy_home: None,
        });
    }
    let home = home?;
    let current = home.join(DATA_DIR).join(DB_FILENAME);
    if !current.is_file() {
        for legacy in LEGACY_HOMES {
            // the database under its old name, or under its new one in a half-done `migrate-home`
            // (siblings renamed, folder not yet)
            for name in [LEGACY_DB_FILENAME, DB_FILENAME] {
                let candidate = home.join(legacy).join(name);
                if candidate.is_file() {
                    return Some(DefaultDb {
                        path: candidate,
                        legacy_home: Some(legacy),
                    });
                }
            }
        }
    }
    Some(DefaultDb {
        path: current,
        legacy_home: None,
    })
}

/// [`resolve_in`] on the process environment.
pub fn resolve_default_db() -> Option<DefaultDb> {
    let home = std::env::var_os("HOME");
    resolve_in(
        home.as_deref().map(Path::new),
        std::env::var_os(DB_ENV).as_deref(),
    )
}

/// The resolved default store's path.
pub fn default_db_path() -> Option<PathBuf> {
    resolve_default_db().map(|d| d.path)
}

/// A writer was pointed into an old data folder that is gone: `migrate-home` moved it, and creating it
/// again would start a second, empty store next to the moved one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("data folder ~/{folder} has moved; restart {PRODUCT}")]
pub struct HomeMoved {
    pub folder: &'static str,
}

/// `Some` when the folder of `path` is missing and is one of [`LEGACY_HOMES`]; callers refuse to
/// `create_dir_all` it. Pure: looks, never creates.
pub fn moved_legacy_home(path: &Path) -> Option<HomeMoved> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty())?;
    if parent.is_dir() {
        return None;
    }
    let name = parent.file_name()?.to_str()?;
    LEGACY_HOMES
        .iter()
        .copied()
        .find(|legacy| *legacy == name)
        .map(|folder| HomeMoved { folder })
}

/// The `relay.json` beside the store `db`: the file the app (`serve`) and the CLI read for it.
pub fn relay_config_beside(db: &Path) -> PathBuf {
    db.parent().map_or_else(PathBuf::new, Path::to_path_buf).join(RELAY_CONFIG_NAME)
}

/// `relay.json` lives in the folder of the resolved database file.
pub fn relay_config_path() -> Option<PathBuf> {
    default_db_path().map(|db| {
        db.parent()
            .map_or_else(PathBuf::new, Path::to_path_buf)
            .join(RELAY_CONFIG_NAME)
    })
}

/// The one stderr line printed when the old folder is being read through.
pub fn legacy_home_hint(legacy: &str) -> String {
    format!("using legacy data folder ~/{legacy}; run '{COMMAND} migrate-home' to move it")
}

/// A one-line warning naming the new variables when any old `HEARTHBEAT_*` one is set.
pub fn legacy_env_warning(is_set: impl Fn(&str) -> bool) -> Option<String> {
    let stale: Vec<&str> = LEGACY_ENV_SUFFIXES
        .iter()
        .copied()
        .filter(|suffix| is_set(&format!("{LEGACY_ENV_PREFIX}{suffix}")))
        .collect();
    if stale.is_empty() {
        return None;
    }
    let join = |prefix: &str| {
        stale
            .iter()
            .map(|s| format!("{prefix}{s}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let verb = if stale.len() == 1 { "is" } else { "are" };
    Some(format!(
        "warning: {} {verb} no longer read; set {} instead",
        join(LEGACY_ENV_PREFIX),
        join(ENV_PREFIX)
    ))
}

/// [`legacy_env_warning`] on the process environment (a set-but-empty variable does not count).
pub fn legacy_env_warning_now() -> Option<String> {
    legacy_env_warning(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(folder: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(folder).expect("mkdir");
        let path = folder.join(name);
        std::fs::write(&path, b"").expect("touch");
        path
    }

    fn listing(root: &Path) -> Vec<String> {
        let mut names = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read_dir") {
                let path = entry.expect("entry").path();
                names.push(path.strip_prefix(root).expect("prefix").display().to_string());
                if path.is_dir() {
                    stack.push(path);
                }
            }
        }
        names.sort();
        names
    }

    #[test]
    fn the_new_file_wins_over_the_legacy_one() {
        let dir = tempfile::tempdir().expect("tmp");
        let new = touch(&dir.path().join(".disconect"), "disconect.db");
        touch(&dir.path().join(".hearthbeat"), "hearthbeat.db");
        let got = resolve_in(Some(dir.path()), None).expect("resolved");
        assert_eq!(got, DefaultDb { path: new, legacy_home: None });
    }

    #[test]
    fn the_legacy_file_is_read_through_when_only_it_exists() {
        let dir = tempfile::tempdir().expect("tmp");
        let legacy = touch(&dir.path().join(".hearthbeat"), "hearthbeat.db");
        let got = resolve_in(Some(dir.path()), None).expect("resolved");
        assert_eq!(
            got,
            DefaultDb { path: legacy, legacy_home: Some(".hearthbeat") }
        );
    }

    #[test]
    fn a_db_less_new_folder_does_not_hide_the_legacy_store() {
        let dir = tempfile::tempdir().expect("tmp");
        touch(&dir.path().join(".disconect"), "relay.json");
        let legacy = touch(&dir.path().join(".hearthbeat"), "hearthbeat.db");
        let got = resolve_in(Some(dir.path()), None).expect("resolved");
        assert_eq!(got.path, legacy);
        assert_eq!(got.legacy_home, Some(".hearthbeat"));
    }

    #[test]
    fn neither_exists_gives_the_new_path_and_creates_nothing() {
        let dir = tempfile::tempdir().expect("tmp");
        std::fs::create_dir(dir.path().join(".hearthbeat")).expect("mkdir");
        std::fs::write(dir.path().join(".hearthbeat/relay.json"), "{}").expect("write");
        let before = listing(dir.path());
        let got = resolve_in(Some(dir.path()), None).expect("resolved");
        assert_eq!(
            got,
            DefaultDb { path: dir.path().join(".disconect/disconect.db"), legacy_home: None }
        );
        assert_eq!(listing(dir.path()), before, "resolution must never mkdir");
    }

    #[test]
    fn the_env_override_wins_expands_the_tilde_and_is_never_a_legacy_read() {
        let dir = tempfile::tempdir().expect("tmp");
        touch(&dir.path().join(".hearthbeat"), "hearthbeat.db");
        let got = resolve_in(Some(dir.path()), Some(OsStr::new("~/elsewhere/x.db"))).expect("resolved");
        assert_eq!(
            got,
            DefaultDb { path: dir.path().join("elsewhere/x.db"), legacy_home: None }
        );
        // an empty override is no override
        let got = resolve_in(Some(dir.path()), Some(OsStr::new(""))).expect("resolved");
        assert_eq!(got.legacy_home, Some(".hearthbeat"));
        // an override needs no home at all; without one and without an override there is no answer
        assert_eq!(
            resolve_in(None, Some(OsStr::new("/x.db"))).map(|d| d.path),
            Some(PathBuf::from("/x.db"))
        );
        assert_eq!(resolve_in(None, None), None);
    }

    #[test]
    fn the_hint_and_the_warning_are_the_pythons_texts() {
        assert_eq!(
            legacy_home_hint(".hearthbeat"),
            "using legacy data folder ~/.hearthbeat; run 'disconect migrate-home' to move it"
        );
        assert_eq!(legacy_env_warning(|_| false), None);
        assert_eq!(
            legacy_env_warning(|n| n == "HEARTHBEAT_DB").as_deref(),
            Some("warning: HEARTHBEAT_DB is no longer read; set DISCONECT_DB instead")
        );
        assert_eq!(
            legacy_env_warning(|n| n == "HEARTHBEAT_DB" || n == "HEARTHBEAT_KEYS").as_deref(),
            Some("warning: HEARTHBEAT_DB, HEARTHBEAT_KEYS are no longer read; set DISCONECT_DB, DISCONECT_KEYS instead")
        );
    }

    #[test]
    fn a_half_done_migrate_home_resolves_to_the_renamed_db_in_the_old_folder() {
        let dir = tempfile::tempdir().expect("tmp");
        let half = touch(&dir.path().join(".hearthbeat"), "disconect.db");
        let got = resolve_in(Some(dir.path()), None).expect("resolved");
        assert_eq!(got, DefaultDb { path: half, legacy_home: Some(".hearthbeat") });
        // the old name still wins when both are there
        let old = touch(&dir.path().join(".hearthbeat"), "hearthbeat.db");
        let got = resolve_in(Some(dir.path()), None).expect("resolved");
        assert_eq!(got.path, old);
    }

    #[test]
    fn only_a_missing_legacy_folder_counts_as_moved() {
        let dir = tempfile::tempdir().expect("tmp");
        let legacy = dir.path().join(".hearthbeat").join("hearthbeat.db");
        let moved = moved_legacy_home(&legacy).expect("moved");
        assert_eq!(moved.to_string(), "data folder ~/.hearthbeat has moved; restart DISCOnect");
        assert_eq!(moved_legacy_home(&dir.path().join(".disconect/disconect.db")), None);
        assert_eq!(moved_legacy_home(&dir.path().join("elsewhere/x.db")), None);
        assert_eq!(moved_legacy_home(Path::new("x.db")), None);
        std::fs::create_dir(dir.path().join(".hearthbeat")).expect("mkdir");
        assert_eq!(moved_legacy_home(&legacy), None, "a folder that exists is not moved");
    }
}
