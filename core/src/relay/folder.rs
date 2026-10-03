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
}

impl RelayError {
    /// The reason the oracle records for a failed read: the exception's `reason` attribute, else
    /// its class name.
    pub fn reason(&self) -> &'static str {
        use std::io::ErrorKind as K;
        match self {
            RelayError::TooLarge => reasons::TOO_LARGE,
            RelayError::BadName => reasons::PY_VALUE_ERROR,
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

/// A dumb object store the user controls.
pub trait Relay {
    fn put(&self, name: &str, data: &[u8]) -> Result<(), RelayError>;
    fn get(&self, name: &str) -> Result<Vec<u8>, RelayError>;
    fn list(&self, account: &str) -> Result<Vec<String>, RelayError>;
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
}

impl FolderRelay {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        FolderRelay { root: root.into() }
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
        fs::create_dir_all(parent)?;
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
        let relay = FolderRelay::new(dir.path().join("relay"));
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
        let relay = FolderRelay::new(dir.path().join("relay"));
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
