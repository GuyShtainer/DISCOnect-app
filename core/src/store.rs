// SPDX-License-Identifier: AGPL-3.0-or-later
//! Open the SQLCipher store the way `storage/__init__.py` does: key state decided by the key file,
//! one writer under the write lock, any number of read-only readers.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use zeroize::Zeroizing;

use crate::identity::{COMMAND, PRODUCT};
use crate::keys::{self, KeyError, PassphraseSource, Secret32};
use crate::time::utc_now_iso;
use crate::write_lock::{self, LockError, WriteLock};

/// Same as Python's `BUSY_TIMEOUT_MS`.
pub const BUSY_TIMEOUT_MS: u64 = 5000;
/// Highest schema this build understands.
pub const SCHEMA_VERSION: i64 = 3;
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// `(version, DDL)`, append only; byte-identical to the Python `migrations._V1/_V2/_V3`.
pub const MIGRATIONS: [(i64, &str); 3] = [
    (1, include_str!("../sql/v1.sql")),
    (2, include_str!("../sql/v2.sql")),
    (3, include_str!("../sql/v3.sql")),
];

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("no {product} database yet at {0}", product = PRODUCT)]
    NotConfigured(String),
    #[error("{0}")]
    Encrypted(String),
    #[error("{0} is plaintext but a key file exists; run '{cmd} encrypt' to convert it (or remove the key file if it is not yours)", cmd = COMMAND)]
    NotEncrypted(String),
    #[error("database schema is version {found}; this build understands up to {SCHEMA_VERSION}. Upgrade.")]
    SchemaTooNew { found: i64 },
    #[error("a key rotation is in progress ({0} exists); finish it with the Python tool, this build never promotes it")]
    RotationInProgress(String),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// True if the file on disk is not plaintext SQLite, False if it is, None if empty or absent.
pub fn is_encrypted_file(path: &Path) -> Result<Option<bool>, StoreError> {
    match std::fs::metadata(path) {
        Ok(m) if m.len() > 0 => {}
        Ok(_) => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let mut head = [0u8; 16];
    let n = std::fs::File::open(path)?.read(&mut head)?;
    Ok(Some(n < 16 || &head != SQLITE_MAGIC))
}

/// The unlocked master key for `db_path`, or None when no key file exists (plaintext store).
/// Refuses while a `<keys>.next` rotation file exists.
pub fn resolve_master(db_path: &Path, source: PassphraseSource<'_>) -> Result<Option<Secret32>, StoreError> {
    let key_path = keys::key_path_for(db_path);
    let next = keys::next_path_for(&key_path);
    if next.exists() {
        let name = next.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        return Err(StoreError::RotationInProgress(name));
    }
    if !key_path.exists() {
        return Ok(None);
    }
    Ok(Some(keys::unlock(&key_path, source)?))
}

fn display_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

fn check_key_state(path: &Path, master: Option<&Secret32>) -> Result<(), StoreError> {
    let on_disk = is_encrypted_file(path)?;
    if master.is_none() && on_disk == Some(true) {
        return Err(StoreError::Encrypted(format!(
            "{} is encrypted but no key file was found at {}",
            display_name(path),
            display_name(&keys::key_path_for(path))
        )));
    }
    if master.is_some() && on_disk == Some(false) {
        return Err(StoreError::NotEncrypted(display_name(path)));
    }
    Ok(())
}

fn apply_key(conn: &Connection, master: &Secret32) -> Result<(), StoreError> {
    let sql = Zeroizing::new(format!("PRAGMA key = \"x'{}'\"", &**keys::db_key_hex(master)));
    conn.execute_batch(&sql)?;
    conn.execute_batch("PRAGMA cipher_compatibility = 4")?;
    Ok(())
}

fn is_wrong_key(err: &rusqlite::Error) -> bool {
    err.to_string().contains("not a database")
}

/// First statement on a keyed connection is where a wrong key surfaces; name it.
fn first_touch(conn: &Connection, path: &Path, keyed: bool) -> Result<(), StoreError> {
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)) {
        Ok(_) => Ok(()),
        Err(e) if keyed && is_wrong_key(&e) => Err(StoreError::Encrypted(format!(
            "{} could not be opened with this key (wrong key file or a damaged file)",
            display_name(path)
        ))),
        Err(e) => Err(e.into()),
    }
}

fn user_version_of(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}

fn check_not_too_new(conn: &Connection) -> Result<(), StoreError> {
    let found = user_version_of(conn)?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew { found });
    }
    Ok(())
}

/// Bring the schema up to [`SCHEMA_VERSION`]; one transaction per step. Caller holds the write lock.
fn migrate(conn: &mut Connection) -> Result<i64, StoreError> {
    let mut version = user_version_of(conn)?;
    for (target, ddl) in MIGRATIONS {
        if version >= target {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(ddl)?;
        tx.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(?1, ?2)",
            rusqlite::params![target, utc_now_iso()],
        )?;
        tx.execute_batch(&format!("PRAGMA user_version = {target}"))?;
        tx.commit()?;
        version = target;
    }
    Ok(version)
}

/// An open store. Field order matters: the connection closes before the write lock is released.
pub struct Store {
    conn: Connection,
    _lock: Option<WriteLock>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("writer", &self._lock.is_some()).finish()
    }
}

impl Store {
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// `PRAGMA cipher_version`; None on a plain SQLite build or an unkeyed connection.
    pub fn cipher_version(&self) -> Option<String> {
        self.conn
            .query_row("PRAGMA cipher_version", [], |r| r.get::<_, Option<String>>(0))
            .ok()
            .flatten()
            .filter(|v| !v.is_empty())
    }

    pub fn user_version(&self) -> Result<i64, StoreError> {
        user_version_of(&self.conn)
    }
}

/// Writer open: create parent dirs, take the write lock, pragmas, refuse too-new, migrate.
pub fn open_for_write(
    path: &Path,
    purpose: &str,
    timeout_s: f64,
    source: PassphraseSource<'_>,
) -> Result<Store, StoreError> {
    let master = resolve_master(path, source)?;
    open_for_write_with(path, purpose, timeout_s, master.as_ref())
}

/// Like [`open_for_write`] with an already-unlocked master key (None for a plaintext store).
pub fn open_for_write_with(
    path: &Path,
    purpose: &str,
    timeout_s: f64,
    master: Option<&Secret32>,
) -> Result<Store, StoreError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let lock = write_lock::acquire(path, purpose, Duration::from_secs_f64(timeout_s.max(0.0)))?;
    check_key_state(path, master)?;
    let mut conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    if let Some(m) = master {
        apply_key(&conn, m)?;
    }
    first_touch(&conn, path, master.is_some())?;
    conn.execute_batch("PRAGMA journal_mode = WAL")?;
    conn.execute_batch(&format!("PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}"))?;
    conn.execute_batch("PRAGMA foreign_keys = ON")?;
    check_not_too_new(&conn)?;
    migrate(&mut conn)?;
    Ok(Store { conn, _lock: Some(lock) })
}

/// Read-only open: no lock, no migration, `query_only`; too-new schemas are still refused.
pub fn open_read_only(path: &Path, source: PassphraseSource<'_>) -> Result<Store, StoreError> {
    let master = resolve_master(path, source)?;
    open_read_only_with(path, master.as_ref())
}

/// Like [`open_read_only`] with an already-unlocked master key (None for a plaintext store).
pub fn open_read_only_with(path: &Path, master: Option<&Secret32>) -> Result<Store, StoreError> {
    if !path.exists() {
        return Err(StoreError::NotConfigured(display_name(path)));
    }
    check_key_state(path, master)?;
    // SQLITE_OPEN_READ_ONLY is what `?mode=ro` selects; a plain path avoids URI escaping.
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    if let Some(m) = master {
        apply_key(&conn, m)?;
    }
    first_touch(&conn, path, master.is_some())?;
    conn.execute_batch("PRAGMA query_only = 1")?;
    conn.execute_batch(&format!("PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}"))?;
    check_not_too_new(&conn)?;
    Ok(Store { conn, _lock: None })
}

/// Row count of every table except `sqlite_*`, sorted by name. Counts only, never values.
pub fn table_counts(conn: &Connection) -> Result<Vec<(String, i64)>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name",
    )?;
    let names: Vec<String> = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let sql = format!("SELECT count(*) FROM \"{}\"", name.replace('"', "\"\""));
        out.push((name, conn.query_row(&sql, [], |r| r.get::<_, i64>(0))?));
    }
    Ok(out)
}
