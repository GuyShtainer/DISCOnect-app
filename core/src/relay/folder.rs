// SPDX-License-Identifier: AGPL-3.0-or-later
//! The self-hosted relay: a folder. WebDAV, rsync or Syncthing carries it between machines.
//! The twin of `disconect/relay/folder.py`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::bundle::reasons;

/// Largest object a reader will load: the plaintext cap plus the envelope. Anything bigger is
/// the operator's problem, not ours (`too_large`).
pub const MAX_OBJECT: u64 = 64 * 1024 * 1024 + 4096;

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// The oracle's `TooLarge` (reason `too_large`).
    #[error("object larger than any bundle can be")]
    TooLarge,
    /// The oracle's `ValueError("bad object name")`.
    #[error("bad object name")]
    BadName,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A network relay could not be reached (connect, name lookup, time-out, broken response).
    /// Retryable: nothing was changed on either side.
    #[error("the relay is unreachable (retry later)")]
    Unreachable,
    /// A network relay that proved it holds this device's key (the answer's response tag verified)
    /// refused the request with HTTP 401 while this device's clock was more than the allowed skew
    /// off the relay's (`skew_s` = this device's seconds minus the relay's).
    #[error("relay_auth_failed: the relay holds this device's key but refused the request: this device's clock is {} minutes off the relay's; check the date and time on both devices", .skew_s.unsigned_abs() / 60)]
    Unauthorized { skew_s: i64 },
    /// A network relay's answer carried no valid response tag.
    #[error("relay_unverified: the relay's answer could not be verified: not the relay this device paired with, the relay was set up again with a new key (pair again from it), the network altered the answer, or the connection broke")]
    Unverified,
    /// A network relay answered an unexpected HTTP status (only the number is kept).
    #[error("the relay answered HTTP {0}")]
    Status(u16),
}

impl RelayError {
    /// The reason the oracle records for a failed read: the exception's `reason` attribute, else
    /// its class name.
    pub fn reason(&self) -> &'static str {
        use std::io::ErrorKind as K;
        match self {
            RelayError::TooLarge => reasons::TOO_LARGE,
            RelayError::BadName => reasons::PY_VALUE_ERROR,
            // network relays only; these never reach a `rejected` row (see `is_transient`)
            RelayError::Unreachable | RelayError::Status(_) => reasons::PY_OS_ERROR,
            RelayError::Unauthorized { .. } => "relay_auth_failed",
            RelayError::Unverified => "relay_unverified",
            RelayError::Io(error) => match error.kind() {
                K::NotFound => reasons::PY_FILE_NOT_FOUND,
                K::PermissionDenied => reasons::PY_PERMISSION,
                K::IsADirectory => reasons::PY_IS_A_DIRECTORY,
                K::NotADirectory => reasons::PY_NOT_A_DIRECTORY,
                K::AlreadyExists => reasons::PY_FILE_EXISTS,
                K::Interrupted => reasons::PY_INTERRUPTED,
                K::TimedOut => reasons::PY_TIMEOUT,
                K::WouldBlock => reasons::PY_BLOCKING_IO,
                K::BrokenPipe => reasons::PY_BROKEN_PIPE,
                _ => reasons::PY_OS_ERROR,
            },
        }
    }
}

impl RelayError {
    /// The stable word a site report carries for this failure (`SiteReport::error`). The Python twin and the
    /// app copy this table; it never holds a path, an address or an OS text.
    ///
    /// | failure                                   | word            |
    /// |-------------------------------------------|-----------------|
    /// | `TooLarge`                                | `too_large`     |
    /// | `BadName`                                 | `bad_name`      |
    /// | `Unreachable`, `Status(_)`                | `unreachable`   |
    /// | `Unauthorized`                            | `refused`       |
    /// | `Unverified`                              | `unverified`    |
    /// | `Io` NotFound, NotADirectory              | `missing`       |
    /// | `Io` PermissionDenied                     | `no_permission` |
    /// | any other `Io`                            | `io_error`      |
    ///
    /// `open_sites` adds `unavailable`, `same_relay`, `bad_url` and `unsupported_transport`.
    pub fn site_word(&self) -> &'static str {
        use std::io::ErrorKind as K;
        match self {
            RelayError::TooLarge => "too_large",
            RelayError::BadName => "bad_name",
            RelayError::Unreachable | RelayError::Status(_) => "unreachable",
            RelayError::Unauthorized { .. } => "refused",
            RelayError::Unverified => "unverified",
            RelayError::Io(error) => match error.kind() {
                K::NotFound | K::NotADirectory => "missing",
                K::PermissionDenied => "no_permission",
                _ => "io_error",
            },
        }
    }

    /// True when the failure says nothing about the object being read: the relay could not be
    /// reached, refused the token or broke. A pull stops on these (nothing is marked, the next pull
    /// retries) instead of recording the bundle as `rejected`.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            RelayError::Unreachable
                | RelayError::Unauthorized { .. }
                | RelayError::Unverified
                | RelayError::Status(_)
        )
    }
}

/// A dumb object store the user controls.
pub trait Relay {
    fn put(&self, name: &str, data: &[u8]) -> Result<(), RelayError>;
    fn get(&self, name: &str) -> Result<Vec<u8>, RelayError>;
    fn list(&self, account: &str) -> Result<Vec<String>, RelayError>;
    /// Remove one object (`FileNotFoundError` when it is not there). Nothing in a push or pull
    /// deletes; pairing and tests do.
    fn delete(&self, name: &str) -> Result<(), RelayError>;
    /// The names a heal may count as present: [`Relay::list`] by default. A folder also counts an evicted
    /// iCloud placeholder (`.<32 hex>.icloud`), which a `get` could not read but which is the same object.
    fn list_present(&self, account: &str) -> Result<Vec<String>, RelayError> {
        self.list(account)
    }
}

fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `^[0-9a-f]{64}/[0-9a-f]{32}$`
pub fn is_object_name(name: &str) -> bool {
    matches!(name.split_once('/'), Some((account, object)) if is_hex(account, 64) && is_hex(object, 32))
}

/// Objects are files `<root>/<account>/<32 hex>`. Writes go to a temp name in the same directory
/// and are renamed into place, so a reader never sees a partial object; anything that does not
/// match the name pattern (temp files, strangers) is ignored.
pub struct FolderRelay {
    root: PathBuf,
    create_root: bool,
}

impl FolderRelay {
    /// A folder whose root must already exist: a `put` into a root that is gone (an unmounted volume) fails
    /// `NotFound` and creates nothing; only the `<account>` level is created.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        FolderRelay { root: root.into(), create_root: false }
    }

    /// A folder the first `put` may create from nothing (the relay this device serves, the legacy single relay).
    pub fn creating_root(root: impl Into<PathBuf>) -> Self {
        FolderRelay { root: root.into(), create_root: true }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl Relay for FolderRelay {
    fn put(&self, name: &str, data: &[u8]) -> Result<(), RelayError> {
        if !is_object_name(name) {
            return Err(RelayError::BadName);
        }
        let target = self.root.join(name);
        let parent = target.parent().ok_or(RelayError::BadName)?;
        if self.create_root {
            fs::create_dir_all(parent)?;
        } else {
            if !self.root.is_dir() {
                return Err(RelayError::Io(std::io::ErrorKind::NotFound.into()));
            }
            match fs::create_dir(parent) {
                Err(error) if error.kind() != std::io::ErrorKind::AlreadyExists => return Err(error.into()),
                _ => {}
            }
        }
        let mut token = [0u8; 8];
        getrandom::fill(&mut token).map_err(|e| std::io::Error::other(e.to_string()))?;
        let temp = parent.join(format!(".tmp-{}", hex::encode(token)));
        let mut handle = fs::File::create(&temp)?;
        handle.write_all(data)?;
        handle.flush()?;
        handle.sync_all()?;
        drop(handle);
        fs::rename(&temp, &target)?;
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Vec<u8>, RelayError> {
        if !is_object_name(name) {
            return Err(RelayError::BadName);
        }
        let path = self.root.join(name);
        if fs::metadata(&path)?.len() > MAX_OBJECT {
            return Err(RelayError::TooLarge);
        }
        Ok(fs::read(&path)?)
    }

    fn delete(&self, name: &str) -> Result<(), RelayError> {
        if !is_object_name(name) {
            return Err(RelayError::BadName);
        }
        fs::remove_file(self.root.join(name))?;
        Ok(())
    }

    fn list(&self, account: &str) -> Result<Vec<String>, RelayError> {
        let folder = self.root.join(account);
        if !folder.is_dir() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(&folder)? {
            let entry = entry?;
            if !fs::metadata(entry.path())
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                continue;
            }
            let Some(file) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let name = format!("{account}/{file}");
            if is_object_name(&name) {
                names.push(name);
            }
        }
        names.sort();
        Ok(names)
    }

    fn list_present(&self, account: &str) -> Result<Vec<String>, RelayError> {
        let mut names = self.list(account)?;
        let folder = self.root.join(account);
        if let Ok(entries) = fs::read_dir(&folder) {
            for entry in entries.flatten() {
                let Some(file) = entry.file_name().to_str().map(str::to_string) else { continue };
                let evicted = file
                    .strip_prefix('.')
                    .and_then(|rest| rest.strip_suffix(".icloud"))
                    .filter(|object| is_hex(object, 32));
                if let Some(object) = evicted {
                    let name = format!("{account}/{object}");
                    if is_object_name(&name) && !names.contains(&name) {
                        names.push(name);
                    }
                }
            }
        }
        names.sort();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn name(tail: char) -> String {
        format!("{ACCOUNT}/{}", tail.to_string().repeat(32))
    }

    #[test]
    fn folder_relay_ignores_strangers_and_temp_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let relay = FolderRelay::creating_root(dir.path().join("relay"));
        relay.put(&name('a'), b"abc").expect("put");
        fs::write(
            dir.path().join("relay").join(ACCOUNT).join(".tmp-deadbeef"),
            b"partial",
        )
        .expect("temp");
        fs::write(
            dir.path().join("relay").join(ACCOUNT).join("README.txt"),
            b"hi",
        )
        .expect("stranger");
        fs::create_dir(dir.path().join("relay").join(ACCOUNT).join("b".repeat(32)))
            .expect("a directory");
        assert_eq!(relay.list(ACCOUNT).expect("list"), vec![name('a')]);
        assert_eq!(relay.get(&name('a')).expect("get"), b"abc");
        assert!(relay.list(&"f".repeat(64)).expect("list").is_empty());
        assert!(matches!(
            relay.put("../escape", b"x"),
            Err(RelayError::BadName)
        ));
        assert!(matches!(relay.get("../escape"), Err(RelayError::BadName)));
        relay.put(&name('0'), b"z").expect("put");
        assert_eq!(
            relay.list(ACCOUNT).expect("list"),
            vec![name('0'), name('a')],
            "sorted"
        );
    }

    #[test]
    fn a_missing_object_reads_as_file_not_found_and_an_oversized_one_as_too_large() {
        let dir = tempfile::tempdir().expect("tempdir");
        let relay = FolderRelay::creating_root(dir.path().join("relay"));
        let missing = relay.get(&name('c')).expect_err("missing");
        assert_eq!(missing.reason(), "FileNotFoundError");
        relay.put(&name('d'), b"x").expect("put");
        let path = dir.path().join("relay").join(name('d'));
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        file.set_len(MAX_OBJECT + 1).expect("sparse file");
        let big = relay.get(&name('d')).expect_err("oversized");
        assert!(matches!(big, RelayError::TooLarge));
        assert_eq!(big.reason(), "too_large");
    }

    #[test]
    fn delete_removes_one_object_and_validates_the_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let relay = FolderRelay::creating_root(dir.path().join("relay"));
        relay.put(&name('a'), b"abc").expect("put");
        relay.put(&name('b'), b"def").expect("put");
        relay.delete(&name('a')).expect("delete");
        assert_eq!(relay.list(ACCOUNT).expect("list"), vec![name('b')]);
        let missing = relay.delete(&name('a')).expect_err("already gone");
        assert_eq!(missing.reason(), "FileNotFoundError");
        assert!(matches!(
            relay.delete("../escape"),
            Err(RelayError::BadName)
        ));
        assert_eq!(relay.get(&name('b')).expect("untouched"), b"def");
    }

    #[test]
    fn network_errors_are_transient_and_folder_errors_are_not() {
        assert!(RelayError::Unreachable.is_transient());
        assert!(RelayError::Unauthorized { skew_s: 600 }.is_transient());
        assert!(RelayError::Unverified.is_transient());
        assert!(RelayError::Status(500).is_transient());
        assert!(!RelayError::BadName.is_transient());
        assert!(!RelayError::TooLarge.is_transient());
        assert!(!RelayError::Io(std::io::ErrorKind::NotFound.into()).is_transient());
        assert_eq!(RelayError::Unauthorized { skew_s: 600 }.reason(), "relay_auth_failed");
        assert_eq!(RelayError::Unverified.reason(), "relay_unverified");
        assert!(RelayError::Unverified.to_string().starts_with("relay_unverified: "));
        let text = RelayError::Unauthorized { skew_s: -600 }.to_string();
        assert!(text.starts_with("relay_auth_failed: "));
        assert!(text.contains("this device's clock is 10 minutes off the relay's"), "{text}");
    }

    #[test]
    fn object_names_follow_the_pattern() {
        assert!(is_object_name(&name('a')));
        assert!(!is_object_name(&format!("{ACCOUNT}/{}", "A".repeat(32))));
        assert!(!is_object_name(&format!("{ACCOUNT}/{}", "a".repeat(31))));
        assert!(!is_object_name(&"a".repeat(32)));
        assert!(!is_object_name(&format!(
            "{}/{}",
            "a".repeat(63),
            "a".repeat(32)
        )));
    }
}
