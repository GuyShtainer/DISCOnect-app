// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cross-process single-writer lock, same protocol as `storage/write_lock.py`.
//!
//! BSD `flock(2)` on `<db>.write-lock` (macOS fcntl record locks do not see flock), polled every
//! 120 ms; `<db>.write-lock.holder` carries `{"purpose","pid","since"}` while held.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fs2::FileExt;
use serde_json::{Value, json};

use crate::identity::PRODUCT;
use crate::keys::sibling_with_suffix;
use crate::time::utc_now_iso;

pub const POLL_INTERVAL: Duration = Duration::from_millis(120);

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("{}", busy_message(.holder))]
    Busy { holder: Option<Value> },
    #[error("write lock I/O error: {0}")]
    Io(#[from] std::io::Error),
}

fn busy_message(holder: &Option<Value>) -> String {
    match holder {
        Some(h) => format!(
            "another {PRODUCT} process is writing the database ({}, pid {})",
            h.get("purpose").and_then(Value::as_str).unwrap_or("?"),
            h.get("pid").map(Value::to_string).unwrap_or_else(|| "?".into())
        ),
        None => format!("another {PRODUCT} process is writing the database"),
    }
}

pub fn lock_path_for(db_path: &Path) -> PathBuf {
    sibling_with_suffix(db_path, ".write-lock")
}

fn holder_path_for(db_path: &Path) -> PathBuf {
    sibling_with_suffix(db_path, ".write-lock.holder")
}

fn read_holder(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// A held write lock; dropping it releases the lock and removes the holder file.
#[derive(Debug)]
pub struct WriteLock {
    file: File,
    holder_path: PathBuf,
}

/// Take the exclusive write lock for `db_path`, waiting up to `timeout`.
pub fn acquire(db_path: &Path, purpose: &str, timeout: Duration) -> Result<WriteLock, LockError> {
    let lock_path = lock_path_for(db_path);
    let holder_path = holder_path_for(db_path);
    if let Some(parent) = lock_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new().append(true).create(true).read(true).open(&lock_path)?;
    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.raw_os_error() == Some(35) => {
                if Instant::now() >= deadline {
                    return Err(LockError::Busy { holder: read_holder(&holder_path) });
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => return Err(LockError::Io(e)),
        }
    }
    let holder = json!({"purpose": purpose, "pid": std::process::id(), "since": utc_now_iso()});
    std::fs::write(&holder_path, holder.to_string())?;
    Ok(WriteLock { file, holder_path })
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.holder_path);
        let _ = FileExt::unlock(&self.file);
    }
}
