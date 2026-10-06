// SPDX-License-Identifier: AGPL-3.0-or-later
//! `disconect-core` with no subcommand: the JSON-lines sidecar protocol the desktop app speaks over
//! stdio, ported from `disconect/serve.py` (the oracle is that file and `tests/test_serve.py`;
//! `docs/serve-protocol.md` follows them).
//!
//! Slice 3A ported the transport and the start-up methods: `app.info`, `key.status`, `key.unlock`,
//! `key.cache`; slice 3B added `data.facts`; slice 3C `data.metric` and `data.today`; slice 3D
//! `data.health`, `import.last` and `import.run`, which completes the oracle's table. A method not in
//! [`METHODS`] answers `unknown_method` (never a new error code, never a fake result); the list of what
//! was once absent is [`crate::read::DEFERRED_METHODS`], now empty.
//!
//! `tools.call` (Bet 15, slice 2) answers what the MCP tool of that name would, through an
//! [`crate::mcp::Server`] built from the session's store and master key, so the app's coach loop has no third
//! implementation of the six tools; see [`tools_call`].
//!
//! `import.run` is the one asynchronous method: the request loop validates it, takes the import slot
//! and starts a worker thread that holds the write lock, streams `progress` events and writes the
//! response when it is done (so a read such as `import.last` is answered while it runs); at EOF the loop
//! waits for the worker, like the oracle.
//!
//! Serve mode (pitch 7b-2, Rust only): `relay.addresses`, `relay.serve`, `pair.offer`, `pair.confirm` and
//! `pair.cancel` run the LAN relay and a pairing offer for the app, through [`crate::relay::serving`] (the
//! state machine, the watchers, the lifetime rule); the session end stops them before the import wait.
//!
//! Boundaries, drawn as hard as the oracle draws them:
//!
//! * **One private descriptor.** At start the real stdout is duplicated and fd 1 is pointed at
//!   stderr, so a stray write cannot corrupt the stream (unix only; row 13 owns Windows). Nothing in
//!   this crate prints: `print_stdout` is denied crate-wide, and the writer in [`Channel`] is the
//!   only path to the protocol stream.
//! * **No secrets from the environment.** `main` removes the passphrase variables before any thread
//!   exists; this module never reads them. A test scans this file to keep it so.
//! * **Never primes.** Nothing is unlocked at start; `key.unlock` is the only way in.
//! * **Nothing sensitive in a message.** Error text goes through [`redact_text`]; an unexpected
//!   failure reports only its kind.
//!
//! Requests are decoded like the oracle's stdin: UTF-8 with replacement characters, and a line ends
//! at `\n` only (CPython opens stdin with `newline="\n"` on POSIX, so a `\r` is an ordinary
//! character: JSON whitespace between tokens, a parse error anywhere else). A blank line (Python's
//! idea of blank) is skipped. Requests are read with [`crate::wirejson`], which accepts what Python's
//! `json.loads` accepts, and every line written is ASCII-only.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::contract::{Contract, ContractError};
use crate::identity::{self, NOTICE, PRODUCT};
use crate::keychain::{self, KeychainError, KeychainState};
use crate::keys::{self, KeyError, Secret32};
use crate::mcp::Server as ToolServer;
use crate::mcp_args::coerce;
use crate::mcp_tools::{Outcome, TOOLS, rejection_names, spec_text};
use crate::read::ReadError;
use crate::read::coverage::{self, NOT_COVERED, PRESENT};
use crate::read::health;
use crate::read::insight::{self, FactsQuery};
use crate::read::mcp_paths;
use crate::read::queries::{self, MAX_DAILY_DAYS, MAX_SAMPLE_DAYS};
use crate::redact::redact_text;
use crate::relay::config as relay_config;
use crate::relay::folder::{FolderRelay, Relay, RelayError};
use crate::relay::serving::{self, Env, Hooks, Refusal, Shared, Site};
use crate::relay::sync::{self as relay_sync, SyncError};
use crate::sources::{self, SourceError};
use crate::store::{self, StoreError};
use crate::home;
use crate::time::now_instant;
use crate::write_lock::LockError;
use crate::wirejson::{self, Id, Json, PyStr};

/// What `app.info.core` says: this implementation, not Python's version string.
pub const CORE: &str = concat!("disconect-core/", env!("CARGO_PKG_VERSION"));

// ---- failures ----

/// Why a request failed, before it has a protocol code. [`Failure::parts`] is `_error_for`.
#[derive(Debug)]
pub enum Failure {
    /// A failure that already knows its protocol code (`ServeError`).
    Serve {
        code: &'static str,
        message: String,
    },
    Key(KeyError),
    Store(StoreError),
    Keychain(KeychainError),
    Contract(ContractError),
    Read(ReadError),
    Source(SourceError),
    Sync(SyncError),
    Io(io::Error),
}

impl Failure {
    pub fn serve(code: &'static str, message: impl Into<String>) -> Failure {
        Failure::Serve {
            code,
            message: message.into(),
        }
    }

    /// `(code, message)`: the oracle's class-to-code map. Codes are exact; a message is fixed text
    /// where the oracle's is, and quotes the same exception text elsewhere. Unexpected failures
    /// report only their kind.
    pub fn parts(&self) -> (&'static str, String) {
        match self {
            Failure::Serve { code, message } => (code, message.clone()),
            Failure::Key(error) => key_parts(error),
            Failure::Store(error) => store_parts(error),
            Failure::Keychain(KeychainError::NoBackend) => {
                ("internal", "unexpected NoKeyringError".into())
            }
            Failure::Keychain(KeychainError::Backend(_)) => {
                ("internal", "unexpected KeyringError".into())
            }
            Failure::Keychain(KeychainError::NotHex) => (
                "bad_params",
                "non-hexadecimal number found in fromhex() arg at position 0".into(),
            ),
            Failure::Contract(_) => ("internal", "unexpected ContractError".into()),
            Failure::Read(error) => read_parts(error),
            Failure::Source(error) => source_parts(error),
            Failure::Sync(error) => sync_parts(error),
            Failure::Io(error) => io_parts(error),
        }
    }
}

/// An import failure under the oracle's class-to-code map. A missing path is `FileNotFoundError`
/// (`not_found`, fixed text); a run the oracle aborts with an uncaught Python exception carries
/// `Class: message`, mapped by class (`ValueError` and its subclasses `bad_params`, `FileNotFoundError`
/// `not_found`, anything else `internal` reporting only the class).
fn source_parts(error: &SourceError) -> (&'static str, String) {
    match error {
        SourceError::NotFound(_) => ("not_found", error.to_string()),
        SourceError::Io(inner) => io_parts(inner),
        SourceError::Zip(_) => ("internal", "unexpected BadZipFile".into()),
        SourceError::Writer(crate::writer::WriterError::Db(inner)) | SourceError::Db(inner) => {
            ("database", format!("database error: {inner}"))
        }
        SourceError::Writer(crate::writer::WriterError::Compress(_)) => {
            ("internal", "unexpected error".into())
        }
        SourceError::Writer(crate::writer::WriterError::BadStamp(message)) => ("bad_params", message.clone()),
        SourceError::Abort(text) => {
            let (class, message) = text.split_once(": ").unwrap_or((text.as_str(), ""));
            match class {
                "ValueError" | "UnicodeDecodeError" | "UnicodeEncodeError" | "JSONDecodeError" => {
                    ("bad_params", message.to_string())
                }
                "FileNotFoundError" => ("not_found", message.to_string()),
                other => ("internal", format!("unexpected {other}")),
            }
        }
    }
}

/// A sync failure under the oracle's class-to-code map. A folder relay's I/O errors map as every
/// other I/O error does; a network relay (Rust only) says `not_found` when it cannot be reached
/// (the text says "unreachable"), `relay_auth_failed` when it proves the key and refuses the request (clocks), `relay_unverified` when its answer
/// cannot be verified, `internal` with
/// the HTTP status for anything else.
fn sync_parts(error: &SyncError) -> (&'static str, String) {
    match error {
        SyncError::Db(inner) | SyncError::Writer(crate::writer::WriterError::Db(inner)) => {
            ("database", format!("database error: {inner}"))
        }
        SyncError::Writer(crate::writer::WriterError::Compress(_)) => {
            ("internal", "unexpected error".into())
        }
        SyncError::Writer(crate::writer::WriterError::BadStamp(message)) => ("bad_params", message.clone()),
        SyncError::Source(inner) => source_parts(inner),
        SyncError::Bundle(_) => ("internal", "unexpected ValueError".into()),
        SyncError::Relay(inner) => relay_parts(inner),
        SyncError::Abort(text) => {
            let (class, message) = text.split_once(": ").unwrap_or((text.as_str(), ""));
            match class {
                "ValueError" | "UnicodeDecodeError" | "UnicodeEncodeError" | "JSONDecodeError" => {
                    ("bad_params", message.to_string())
                }
                "FileNotFoundError" => ("not_found", message.to_string()),
                other => ("internal", format!("unexpected {other}")),
            }
        }
        SyncError::WriteFailed(_) => ("internal", "unexpected RecordWriteFailed".into()),
    }
}

fn relay_parts(error: &RelayError) -> (&'static str, String) {
    match error {
        RelayError::Io(inner) => io_parts(inner),
        RelayError::TooLarge | RelayError::BadName => ("bad_params", error.to_string()),
        RelayError::Unreachable => ("not_found", error.to_string()),
        RelayError::Unauthorized { .. } => ("relay_auth_failed", error.to_string()),
        RelayError::Unverified => ("relay_unverified", error.to_string()),
        RelayError::Status(_) => ("internal", error.to_string()),
    }
}

fn key_parts(error: &KeyError) -> (&'static str, String) {
    let code = match error {
        KeyError::WrongPassphrase => "wrong_passphrase",
        KeyError::KeyFileMissing(_) => "not_encrypted",
        KeyError::Locked => "locked",
        KeyError::KeyFileCorrupt(_) => "database",
    };
    (code, error.to_string())
}

fn store_parts(error: &StoreError) -> (&'static str, String) {
    match error {
        StoreError::NotConfigured(_) => (
            "not_found",
            format!("no {PRODUCT} database yet; run '{} import' first", identity::COMMAND),
        ),
        // the old folder was moved by `migrate-home`: the closest existing code is `not_found` (the
        // store is not where this process thinks), the text tells the user to restart
        StoreError::HomeMoved(_) | StoreError::Lock(LockError::HomeMoved(_)) => {
            ("not_found", error.to_string())
        }
        StoreError::Encrypted(message) => ("locked", message.clone()),
        StoreError::NotEncrypted(_) => ("not_encrypted", error.to_string()),
        StoreError::SchemaTooNew { found } => (
            "database",
            format!(
                "database schema is version {found}; this build understands up to {}. Upgrade {PRODUCT}.",
                store::SCHEMA_VERSION
            ),
        ),
        StoreError::Lock(_) => ("busy", error.to_string()),
        StoreError::Key(inner) => key_parts(inner),
        StoreError::Io(inner) => io_parts(inner),
        StoreError::RotationInProgress(_) | StoreError::Db(_) => ("database", error.to_string()),
    }
}

/// A read failure under the oracle's class-to-code map: a `ValueError` is `bad_params` and quotes its
/// text, a database error is `database`, anything else reports only its Python class name.
fn read_parts(error: &ReadError) -> (&'static str, String) {
    match error {
        ReadError::Value(message) => ("bad_params", message.clone()),
        ReadError::Db(inner) => ("database", format!("database error: {inner}")),
        ReadError::Unexpected(name) => ("internal", format!("unexpected {name}")),
        ReadError::Overflow => ("internal", "unexpected OverflowError".into()),
        ReadError::Contract(_) => ("internal", "unexpected ContractError".into()),
    }
}

fn io_parts(error: &io::Error) -> (&'static str, String) {
    match error.kind() {
        io::ErrorKind::NotFound => ("not_found", error.to_string()),
        io::ErrorKind::PermissionDenied => ("internal", "unexpected PermissionError".into()),
        _ => ("internal", "unexpected OSError".into()),
    }
}

impl From<KeyError> for Failure {
    fn from(error: KeyError) -> Failure {
        Failure::Key(error)
    }
}
impl From<StoreError> for Failure {
    fn from(error: StoreError) -> Failure {
        Failure::Store(error)
    }
}
impl From<KeychainError> for Failure {
    fn from(error: KeychainError) -> Failure {
        Failure::Keychain(error)
    }
}
impl From<ReadError> for Failure {
    fn from(error: ReadError) -> Failure {
        Failure::Read(error)
    }
}
impl From<SourceError> for Failure {
    fn from(error: SourceError) -> Failure {
        Failure::Source(error)
    }
}
impl From<SyncError> for Failure {
    fn from(error: SyncError) -> Failure {
        Failure::Sync(error)
    }
}
impl From<Refusal> for Failure {
    fn from(refusal: Refusal) -> Failure {
        Failure::Serve {
            code: refusal.code,
            message: refusal.message,
        }
    }
}
impl From<ContractError> for Failure {
    fn from(error: ContractError) -> Failure {
        Failure::Contract(error)
    }
}

// ---- the protocol's output ----

/// The protocol's output: one JSON object per line on a private stream, safe across threads.
pub struct Channel {
    stream: Mutex<Box<dyn Write + Send>>,
}

impl Channel {
    pub fn new(stream: Box<dyn Write + Send>) -> Channel {
        Channel {
            stream: Mutex::new(stream),
        }
    }

    /// Write one already-encoded protocol line and flush it.
    pub fn write_line(&self, line: &str) -> io::Result<()> {
        let mut text = String::with_capacity(line.len() + 1);
        text.push_str(line);
        text.push('\n');
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("protocol stream poisoned"))?;
        stream.write_all(text.as_bytes())?;
        stream.flush()
    }

    /// An unsolicited `log` event.
    pub fn log(&self, level: &str, message: &str) -> io::Result<()> {
        let mut line = String::from("{\"event\":\"log\",\"level\":");
        wirejson::write_text(&mut line, level);
        line.push_str(",\"message\":");
        wirejson::write_text(&mut line, message);
        line.push('}');
        self.write_line(&line)
    }
}

fn result_line(id: &Id, result: &Value) -> String {
    let mut line = String::from("{\"id\":");
    wirejson::write_json_id(&mut line, id);
    line.push_str(",\"result\":");
    wirejson::write_value(&mut line, result);
    line.push('}');
    line
}

fn ordered_result_line(id: &Id, result: &Json) -> String {
    let mut line = String::from("{\"id\":");
    wirejson::write_json_id(&mut line, id);
    line.push_str(",\"result\":");
    wirejson::write_json(&mut line, result, None);
    line.push('}');
    line
}

fn error_line(id: &Id, code: &str, message: &str) -> String {
    let mut line = String::from("{\"id\":");
    wirejson::write_json_id(&mut line, id);
    line.push_str(",\"error\":{\"code\":");
    wirejson::write_text(&mut line, code);
    line.push_str(",\"message\":");
    wirejson::write_text(&mut line, &redact_text(message));
    line.push_str("}}");
    line
}

fn failure_line(id: &Id, failure: &Failure) -> String {
    let (code, message) = failure.parts();
    error_line(id, code, &message)
}

// ---- session and requests ----

/// Everything one serve process holds: which store it serves, where output goes, the master key
/// `key.unlock` registered, and the import slot with its worker threads.
pub struct Session {
    pub db_path: PathBuf,
    pub channel: Arc<Channel>,
    unlocked: Option<Secret32>,
    /// True while an import worker owns the slot (`Session.import_slot` in the oracle).
    import_slot: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    /// Test hook: the next import worker waits for this channel to deliver or close first.
    hold: Option<Receiver<()>>,
    /// The relay this session serves: at most one LAN server, its offer, the watchers (process memory only).
    relay: Shared,
    relay_hooks: Hooks,
}

impl Session {
    pub fn new(db_path: PathBuf, channel: Channel) -> Session {
        Session {
            db_path,
            channel: Arc::new(channel),
            unlocked: None,
            import_slot: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
            hold: None,
            relay: serving::new_state(),
            relay_hooks: Hooks::default(),
        }
    }

    /// Test hook: shorten the relay's linger, the offer's life and the address check, or inject the
    /// address list (never an environment variable or a flag).
    #[doc(hidden)]
    pub fn set_relay_hooks(&mut self, hooks: Hooks) {
        self.relay_hooks = hooks;
    }

    /// What the relay's workers and watchers need: the state, the hooks, and a writer of event lines.
    fn relay_env(&self) -> Env {
        let channel = Arc::clone(&self.channel);
        Env {
            shared: Arc::clone(&self.relay),
            hooks: self.relay_hooks.clone(),
            emit: Arc::new(move |line| {
                // the bridge being gone is not the relay's problem: EOF on stdin ends the process
                let _ = channel.write_line(&line);
            }),
        }
    }

    /// Test hook (the oracle's tests monkeypatch `import_path` to hold the worker): the next import
    /// worker does not start until `gate` delivers a message or its sender is dropped.
    #[doc(hidden)]
    pub fn hold_next_import(&mut self, gate: Receiver<()>) {
        self.hold = Some(gate);
    }

    /// Wait for every import worker (the loop's last act, so an answer is never lost at EOF).
    fn wait_for_imports(&mut self) {
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }

    pub fn key_path(&self) -> PathBuf {
        keys::key_path_for(&self.db_path)
    }

    pub fn key_file_exists(&self) -> bool {
        self.key_path().exists()
    }

    /// True when nothing needs unlocking (no key file) or `key.unlock` succeeded in this process.
    pub fn is_unlocked(&self) -> bool {
        !self.key_file_exists() || self.unlocked.is_some()
    }

    /// Raise `locked` while an encrypted store has not been unlocked in this process.
    pub fn require_unlocked(&self) -> Result<(), Failure> {
        if self.is_unlocked() {
            Ok(())
        } else {
            Err(Failure::serve(
                "locked",
                "the store is locked; unlock it first",
            ))
        }
    }

    /// A read-only connection for one call (`Session.reader`). Never prompts: the store must already be
    /// unlocked, and a store this process cannot open answers with the usual codes.
    pub fn reader(&self) -> Result<store::Store, Failure> {
        self.require_unlocked()?;
        Ok(store::open_read_only_with(
            &self.db_path,
            self.unlocked.as_ref(),
        )?)
    }

    /// The master key unlocked in this process, if any. Never tries an unlock path.
    pub fn unlocked_master(&self) -> Option<&Secret32> {
        self.unlocked.as_ref()
    }
}

/// One parsed request. `params` is always a JSON object.
pub struct Call {
    pub id: Id,
    pub method: PyStr,
    pub params: Json,
}

/// How a method answers: now with a result, or by starting a worker that answers later.
#[derive(Clone, Copy)]
pub enum Handler {
    Reply(fn(&mut Session, &Call) -> Result<Value, Failure>),
    /// Like `Reply`, with a result that keeps the order of its keys (`tools.call`: the MCP's own tool output).
    Ordered(fn(&mut Session, &Call) -> Result<Json, Failure>),
    /// Validates, then starts a thread that writes the response itself (`import.run`).
    Spawn(fn(&mut Session, &Call) -> Result<(), Failure>),
}

/// The protocol's methods, in the oracle's order. A method exists exactly when it is a name here.
pub const METHODS: &[(&str, Handler)] = &[
    ("app.info", Handler::Reply(app_info)),
    ("key.status", Handler::Reply(key_status)),
    ("key.unlock", Handler::Reply(key_unlock)),
    ("key.cache", Handler::Reply(key_cache)),
    ("data.health", Handler::Reply(data_health)),
    ("data.metric", Handler::Reply(data_metric)),
    ("data.today", Handler::Reply(data_today)),
    ("data.live", Handler::Reply(data_live)),
    ("data.sleep", Handler::Reply(data_sleep)),
    ("data.contract", Handler::Reply(data_contract)),
    ("data.facts", Handler::Reply(data_facts)),
    ("import.run", Handler::Spawn(import_run)),
    ("import.last", Handler::Reply(import_last)),
    ("sync.status", Handler::Reply(sync_status)),
    ("sync.run", Handler::Spawn(sync_run)),
    ("relay.addresses", Handler::Reply(relay_addresses)),
    ("relay.serve", Handler::Reply(relay_serve)),
    ("pair.offer", Handler::Spawn(pair_offer)),
    ("pair.confirm", Handler::Reply(pair_confirm)),
    ("pair.cancel", Handler::Reply(pair_cancel)),
    ("tools.call", Handler::Ordered(tools_call)),
    ("pair.forget", Handler::Reply(phone_forget)),
];

/// `_int_param`: an integer (never a bool, never a float), `default` when the key is absent. An
/// integer beyond 64 bits is clamped, which every caller's own clamp makes the same as Python's bigint.
fn int_param(call: &Call, name: &str, default: i64) -> Result<i64, Failure> {
    match call.params.get(name) {
        None => Ok(default),
        Some(Json::Int(value)) => Ok(value.clamped_i64()),
        Some(_) => Err(Failure::serve(
            "bad_params",
            format!("{name} must be an integer"),
        )),
    }
}

/// `_text_param(required=True)`: a non-empty string.
fn text_param(call: &Call, name: &str) -> Result<PyStr, Failure> {
    match call.params.get(name) {
        Some(Json::Str(text)) if !text.is_empty() => Ok(text.clone()),
        _ => Err(Failure::serve(
            "bad_params",
            format!("{name} must be a non-empty string"),
        )),
    }
}

/// `_text_param(required=False)`: absent or null is None, anything else must be a non-empty string.
fn optional_text_param(call: &Call, name: &str) -> Result<Option<PyStr>, Failure> {
    match call.params.get(name) {
        None | Some(Json::Null) => Ok(None),
        _ => text_param(call, name).map(Some),
    }
}

fn bool_param(call: &Call, name: &str) -> Result<bool, Failure> {
    match call.params.get(name) {
        Some(Json::Bool(value)) => Ok(*value),
        _ => Err(Failure::serve(
            "bad_params",
            format!("{name} must be true or false"),
        )),
    }
}

// ---- app / key ----

/// Product, versions and which store this process serves.
fn app_info(session: &mut Session, _call: &Call) -> Result<Value, Failure> {
    let on_disk = store::is_encrypted_file(&session.db_path)?;
    let contract = Contract::get()?;
    Ok(json!({
        "product": PRODUCT,
        "core": CORE,
        "schema": store::SCHEMA_VERSION,
        "contract": contract.version()?,
        "db": session.db_path.to_string_lossy(),
        "encrypted": on_disk.unwrap_or_else(|| session.key_file_exists()),
        "notice": NOTICE,
    }))
}

/// `status_for`'s `kdf`: the first passphrase wrap's `params`, verbatim, or null. A wrap that is
/// not an object ends the oracle in an `AttributeError`, which is reported as `internal`.
fn kdf_of(key_file: &keys::KeyFile) -> Result<Value, Failure> {
    for wrap in &key_file.wraps {
        let Some(object) = wrap.as_object() else {
            return Err(Failure::serve("internal", "unexpected AttributeError"));
        };
        if object.get("purpose").and_then(Value::as_str) == Some(keys::PURPOSE_PASSPHRASE) {
            return Ok(object.get("params").cloned().unwrap_or(Value::Null));
        }
    }
    Ok(Value::Null)
}

/// Which unlock paths exist and whether this process has unlocked the store.
fn key_status(session: &mut Session, _call: &Call) -> Result<Value, Failure> {
    let key_path = session.key_path();
    let key_file_present = key_path.exists();
    let encrypted = store::is_encrypted_file(&session.db_path)?.unwrap_or(false);
    let (keychain, kdf) = if key_file_present {
        let key_file = keys::read_key_file(&key_path)?;
        let kdf = kdf_of(&key_file)?;
        (keychain::state(&key_file.key_id)?, kdf)
    } else {
        (KeychainState::Absent, Value::Null)
    };
    Ok(json!({
        "key_file": key_file_present,
        "encrypted": encrypted,
        "unlocked": session.is_unlocked(),
        "keychain": keychain.as_str(),
        "kdf": kdf,
    }))
}

/// The master key from the keychain, or `locked` when it holds none that fits this key file.
fn keychain_master(key_file: &keys::KeyFile) -> Result<Secret32, Failure> {
    let cached = keychain::get(&key_file.key_id)?;
    let fits = cached
        .as_deref()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .filter(|master| keys::key_id_for(master) == key_file.key_id);
    match fits {
        Some(master) => Ok(Zeroizing::new(master)),
        None => Err(Failure::serve(
            "locked",
            "no passphrase was given and the keychain holds no key for this store",
        )),
    }
}

/// The message Python's `str.encode("utf-8")` gives for a string with lone surrogates, positions
/// counted in code points of the NFC form (the passphrase is normalised first).
fn surrogate_message(passphrase: &PyStr) -> String {
    let mut positions: Vec<Option<u16>> = Vec::new();
    let mut run = String::new();
    let flush = |run: &mut String, positions: &mut Vec<Option<u16>>| {
        positions.extend(run.nfc().map(|_| None));
        run.clear();
    };
    for decoded in char::decode_utf16(passphrase.units()) {
        match decoded {
            Ok(c) => run.push(c),
            Err(lone) => {
                flush(&mut run, &mut positions);
                positions.push(Some(lone.unpaired_surrogate()));
            }
        }
    }
    flush(&mut run, &mut positions);
    let first = positions.iter().position(Option::is_some).unwrap_or(0);
    let end = positions[first..]
        .iter()
        .take_while(|p| p.is_some())
        .count()
        + first;
    if end - first == 1 {
        let unit = positions[first].unwrap_or(0);
        format!(
            "'utf-8' codec can't encode character '\\u{unit:04x}' in position {first}: surrogates not allowed"
        )
    } else {
        format!(
            "'utf-8' codec can't encode characters in position {first}-{}: surrogates not allowed",
            end - 1
        )
    }
}

/// Unlock with `passphrase` (or the keychain when none is given). The passphrase is not kept, and
/// no environment variable or process-wide cache is touched.
fn key_unlock(session: &mut Session, call: &Call) -> Result<Value, Failure> {
    let passphrase = match call.params.get("passphrase") {
        None | Some(Json::Null) => None,
        Some(Json::Str(text)) => Some(text),
        Some(_) => return Err(Failure::serve("bad_params", "passphrase must be a string")),
    };
    let key_file = keys::read_key_file(&session.key_path())?;
    let master = match passphrase {
        None => keychain_master(&key_file)?,
        Some(text) => match text.to_text() {
            Some(plain) => keys::unlock_with_passphrase(&key_file, &Zeroizing::new(plain))?,
            None => return Err(Failure::serve("bad_params", surrogate_message(text))),
        },
    };
    session.unlocked = Some(master);
    Ok(json!({"unlocked": true}))
}

/// Store or remove the master key in the OS keychain. Needs the store unlocked.
fn key_cache(session: &mut Session, call: &Call) -> Result<Value, Failure> {
    let enable = bool_param(call, "enable")?;
    session.require_unlocked()?;
    let Some(master) = session.unlocked_master() else {
        return Err(Failure::serve(
            "not_encrypted",
            "this store has no key to cache",
        ));
    };
    let key_id = keys::read_key_file(&session.key_path())?.key_id;
    if enable {
        keychain::set(&key_id, master.as_slice())?;
    } else {
        keychain::delete(&key_id)?;
    }
    Ok(json!({"keychain": keychain::state(&key_id)?.as_str()}))
}

// ---- data ----

/// Coverage, provenance and recent imports; the core's convention texts are left out and the
/// manufacturer's name scrubbed.
fn data_health(session: &mut Session, call: &Call) -> Result<Value, Failure> {
    session.require_unlocked()?;
    let window_days = int_param(call, "window_days", health::DEFAULT_HEALTH_DAYS)?;
    let store = session.reader()?;
    let mut report = health::data_health(store.conn(), Contract::get()?, window_days, now_instant())?;
    if let Some(object) = report.as_object_mut() {
        object.remove("conventions");
    }
    identity::neutral(&mut report);
    Ok(report)
}

/// The newest import runs, each with its recorded failure count.
fn import_last(session: &mut Session, _call: &Call) -> Result<Value, Failure> {
    session.require_unlocked()?;
    let store = session.reader()?;
    Ok(health::import_last(store.conn())?)
}

/// The recent window against this person's own baseline, as facts with confidence. The convention
/// text `sources` is left out and the manufacturer's name scrubbed, as in the oracle.
fn data_facts(session: &mut Session, call: &Call) -> Result<Value, Failure> {
    session.require_unlocked()?;
    let window_days = int_param(call, "days", insight::DEFAULT_WINDOW_DAYS)?;
    let baseline_days = int_param(call, "baseline_days", insight::DEFAULT_BASELINE_DAYS)?;
    let store = session.reader()?;
    let mut facts = insight::period_facts(
        store.conn(),
        &FactsQuery {
            window_days,
            baseline_days,
            ..FactsQuery::default()
        },
    )?;
    if let Some(object) = facts.as_object_mut() {
        object.remove("sources");
    }
    identity::neutral(&mut facts);
    Ok(facts)
}

/// `DEFAULT_METRIC_DAYS`: how many days `data.metric` serves when it is not told.
const DEFAULT_METRIC_DAYS: i64 = 90;

/// One metric and scope as a calendar-filled series: a missing day is null with its status.
fn data_metric(session: &mut Session, call: &Call) -> Result<Value, Failure> {
    session.require_unlocked()?;
    let metric = text_param(call, "metric")?;
    let scope = text_param(call, "scope")?;
    let days = int_param(call, "days", DEFAULT_METRIC_DAYS)?;
    let last_day = optional_text_param(call, "last_day")?;
    let contract = Contract::get()?;
    let sample = metric
        .to_text()
        .is_some_and(|name| contract.cadence_for(&name) == Some("sample"));
    let cap = if sample { MAX_SAMPLE_DAYS } else { MAX_DAILY_DAYS };
    let store = session.reader()?;
    let conn = store.conn();
    let last = match last_day {
        // strict `YYYY-MM-DD` with the MCP paths' message; Python's `queries.parse_day` says the same
        Some(text) => queries::parse_day(&text, "last_day")?,
        None => queries::parse_date(&queries::local_today(conn)?)?,
    };
    let first = queries::shift(last, -(days.clamp(1, cap) - 1))?;
    let series = queries::metric_calendar(
        conn,
        contract,
        &metric,
        &scope,
        &queries::iso(first),
        &queries::iso(last),
    )?;
    let name = metric.to_text().unwrap_or_default();
    Ok(json!({
        "metric": name,
        "scope": scope.to_text().unwrap_or_default(),
        "unit": contract.unit_for(&name),
        "days": series,
    }))
}

/// `data.live`: the live link on one local day (default today) — the Today live card's read.
fn data_live(session: &mut Session, call: &Call) -> Result<Value, Failure> {
    session.require_unlocked()?;
    let day = optional_text_param(call, "day")?;
    let contract = Contract::get()?;
    let store = session.reader()?;
    let conn = store.conn();
    let day = match day {
        Some(text) => text,
        None => PyStr::from_text(&queries::local_today(conn)?),
    };
    Ok(queries::live_day(conn, contract, &day)?)
}

/// `data.sleep`: one night (default the latest stored), every source's record, stages also on the watch's clock.
fn data_sleep(session: &mut Session, call: &Call) -> Result<Value, Failure> {
    session.require_unlocked()?;
    let date = optional_text_param(call, "date")?;
    let store = session.reader()?;
    let night = mcp_paths::sleep_detail_local(store.conn(), date.as_ref())?;
    night
        .to_serde()
        .ok_or_else(|| Failure::serve("internal", "sleep result is not JSON"))
}

/// `data.contract`: the numeric metrics with unit, cadence and declared scopes, in contract order. Reads
/// nothing from the store, so it answers on a locked one.
fn data_contract(_session: &mut Session, _call: &Call) -> Result<Value, Failure> {
    let contract = Contract::get()?;
    let metrics: Vec<Value> = contract
        .metrics
        .iter()
        .filter_map(|item| {
            let scopes: Vec<&String> = contract
                .source_scopes
                .iter()
                .filter(|scope| {
                    contract
                        .streams_for
                        .iter()
                        .chain(contract.session_streams_for.iter())
                        .any(|entry| entry.metric == item.metric && &entry.source_scope == *scope)
                })
                .collect();
            (!scopes.is_empty()).then(|| {
                json!({"metric": item.metric, "unit": item.unit, "cadence": item.cadence, "scopes": scopes})
            })
        })
        .collect();
    Ok(json!({"scopes": contract.source_scopes, "metrics": metrics}))
}

/// `_contract_pairs`: every (numeric metric, scope) the contract declares a stream for, in contract order.
fn contract_pairs(contract: &Contract) -> Vec<(String, String)> {
    let declared = |metric: &str, scope: &str| {
        contract
            .streams_for
            .iter()
            .any(|entry| entry.metric == metric && entry.source_scope == scope)
    };
    contract
        .metrics
        .iter()
        .flat_map(|item| {
            contract
                .source_scopes
                .iter()
                .map(move |scope| (item.metric.clone(), scope.clone()))
        })
        .filter(|(metric, scope)| declared(metric, scope))
        .collect()
}

/// The latest value, with its day, for every metric and scope in the contract; `day` is null when none.
fn data_today(session: &mut Session, _call: &Call) -> Result<Value, Failure> {
    session.require_unlocked()?;
    let contract = Contract::get()?;
    let store = session.reader()?;
    let conn = store.conn();
    let today = queries::local_today(conn)?;
    let mut latest = Vec::new();
    for (metric, scope) in contract_pairs(contract) {
        let found = queries::latest_value(conn, contract, &metric, &scope)?;
        latest.push((metric, scope, found));
    }
    let statuses = if latest.iter().any(|(_, _, found)| found.is_none()) {
        coverage::statuses_on(conn, contract, &today)?
    } else {
        Default::default()
    };
    let rows: Vec<Value> = latest
        .into_iter()
        .map(|(metric, scope, found)| {
            let status = if found.is_some() {
                PRESENT
            } else {
                statuses
                    .get(&(metric.clone(), scope.clone()))
                    .copied()
                    .unwrap_or(NOT_COVERED)
            };
            let (day, value) = match found {
                Some((day, value)) => (Value::from(day), value),
                None => (Value::Null, Value::Null),
            };
            json!({"metric": metric, "scope": scope, "value": value, "unit": contract.unit_for(&metric),
                   "day": day, "status": status})
        })
        .collect();
    Ok(json!({"day": today, "metrics": rows}))
}

// ---- import ----

/// Protocol transport names -> the names the store records (`TRANSPORTS` in the oracle).
const TRANSPORTS: [(&str, &str); 3] = [
    ("export", sources::TRANSPORT_CONNECT_EXPORT),
    ("usb", "usb"),
    ("ble", sources::TRANSPORT_BLE),
];

/// `str(pathlib.Path(text))`: empty and `.` components dropped, a leading `//` kept, `.` for nothing.
fn py_path_text(text: &str) -> String {
    let prefix = if text.starts_with("//") && !text.starts_with("///") {
        "//"
    } else if text.starts_with('/') {
        "/"
    } else {
        ""
    };
    let body: Vec<&str> = text
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let joined = format!("{prefix}{}", body.join("/"));
    if joined.is_empty() { ".".into() } else { joined }
}

/// One import request, everything the worker needs.
struct ImportJob {
    id: Id,
    /// None when the request's path holds a lone surrogate: no file can have that name here.
    path: Option<PathBuf>,
    /// The path as text for the one message that names it.
    named: String,
    transport: Option<&'static str>,
    db_path: PathBuf,
    master: Option<Secret32>,
    channel: Arc<Channel>,
    slot: Arc<AtomicBool>,
    hold: Option<Receiver<()>>,
}

/// A `progress` event line, shaped like the oracle's (`note` is redacted).
fn progress_line(done: u64, total: Option<u64>, note: &str) -> String {
    let mut line = format!("{{\"event\":\"progress\",\"op\":\"import\",\"done\":{done},\"total\":");
    match total {
        Some(total) => line.push_str(&total.to_string()),
        None => line.push_str("null"),
    }
    line.push_str(",\"note\":");
    wirejson::write_text(&mut line, &redact_text(note));
    line.push('}');
    line
}

/// `_run_import`: import under the write lock (never waiting for it), streaming progress events.
fn run_import(job: &ImportJob) -> Result<Value, Failure> {
    let store = store::open_for_write_with(&job.db_path, "import", 0.0, job.master.as_ref())?;
    let Some(path) = &job.path else {
        return Err(SourceError::NotFound(job.named.clone()).into());
    };
    let channel = &job.channel;
    // the bridge being gone is not the import's problem: EOF on stdin ends the process
    let mut progress = |done: u64, total: Option<u64>, note: &str| {
        let _ = channel.write_line(&progress_line(done, total, note));
    };
    let stats = sources::import_path(store.conn(), path, job.transport, Some(&mut progress))?;
    let run_id: Option<i64> = store
        .conn()
        .query_row("SELECT MAX(id) FROM import_runs", [], |row| row.get(0))
        .map_err(StoreError::from)?;
    Ok(json!({
        "run_id": run_id, "files": stats.files_seen, "ok": stats.files_imported,
        "partial": stats.status() == "partial", "duplicate": stats.files_duplicate,
        "failed": stats.files_failed,
    }))
}

/// `_import_worker`: run the import, free the slot, then answer the request.
fn import_worker(job: ImportJob) {
    if let Some(gate) = &job.hold {
        let _ = gate.recv();
    }
    // a panic inside the import must still free the slot and answer the request (Python answers
    // `internal` for any unexpected exception; a silently dead worker would leave `busy` forever)
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_import(&job)));
    let line = match outcome {
        Ok(Ok(result)) => result_line(&job.id, &result),
        Ok(Err(failure)) => failure_line(&job.id, &failure),
        Err(_) => failure_line(&job.id, &Failure::serve("internal", "unexpected panic in the import worker")),
    };
    job.slot.store(false, Ordering::SeqCst);
    let _ = job.channel.write_line(&line);
}

/// Start an import on a worker thread; the answer is sent when it finishes.
fn import_run(session: &mut Session, call: &Call) -> Result<(), Failure> {
    session.require_unlocked()?;
    let path = text_param(call, "path")?;
    let transport = match optional_text_param(call, "transport")? {
        None => None,
        Some(name) => match TRANSPORTS.iter().find(|(known, _)| name.equals(known)) {
            Some((_, stored)) => Some(*stored),
            None => {
                return Err(Failure::serve(
                    "bad_params",
                    "transport must be one of ['ble', 'export', 'usb']",
                ));
            }
        },
    };
    if session
        .import_slot
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(Failure::serve("busy", "an import is already running"));
    }
    // a path with a lone surrogate cannot name a file here: it is reported as missing (booked, kb/23)
    let text = path.to_text();
    let lossy = text.clone().unwrap_or_else(|| path.units_lossy());
    let named = py_path_text(&keys::expand_user(Path::new(&lossy)).to_string_lossy());
    let job = ImportJob {
        id: call.id.clone(),
        path: text.map(|_| PathBuf::from(&named)),
        named,
        transport,
        db_path: session.db_path.clone(),
        master: session.unlocked_master().cloned(),
        channel: Arc::clone(&session.channel),
        slot: Arc::clone(&session.import_slot),
        hold: session.hold.take(),
    };
    let slot = Arc::clone(&session.import_slot);
    match std::thread::Builder::new()
        .name("import".into())
        .spawn(move || import_worker(job))
    {
        Ok(handle) => {
            session.workers.push(handle);
            Ok(())
        }
        Err(error) => {
            slot.store(false, Ordering::SeqCst);
            Err(Failure::Io(error))
        }
    }
}

// ---- sync ----

/// `relay.json` beside the store this session serves (the CLI reads the one beside the *default*
/// store; a session serves the store it was started on).
fn relay_json_path(db_path: &Path) -> PathBuf {
    home::relay_config_beside(db_path)
}

/// The relay counts of the store (`sync status`): read-only, so a store older than the relay
/// tables answers what a fresh one would.
fn sync_status(session: &mut Session, _call: &Call) -> Result<Value, Failure> {
    session.require_unlocked()?;
    let store = session.reader()?;
    let report = relay_sync::status_or_fresh(store.conn())?;
    let mut status = relay_sync::status_value(&report);
    if let Some(object) = status.as_object_mut() {
        // Rust only: what the relay of this session is doing right now (null when it serves nothing)
        object.insert("serving".into(), serving::serving_value(&session.relay));
    }
    Ok(status)
}

/// One sync request: everything the worker needs.
struct SyncJob {
    id: Id,
    db_path: PathBuf,
    master: Secret32,
    relay: Box<dyn Relay + Send>,
    channel: Arc<Channel>,
    slot: Arc<AtomicBool>,
}

/// A `progress` event of `op` `sync` (or `pair`, whose only phase is `push`): `phase` is `push` or `pull`, `state` `start` or `done`; a
/// `done` event carries the phase's counts.
fn sync_event(op: &str, phase: &str, state: &str, counts: Option<&Value>) -> String {
    let mut event = json!({"event": "progress", "op": op, "phase": phase, "state": state});
    if let (Some(Value::Object(extra)), Some(object)) = (counts, event.as_object_mut()) {
        for (key, value) in extra {
            object.insert(key.clone(), value.clone());
        }
    }
    let mut line = String::new();
    wirejson::write_value(&mut line, &event);
    line
}

/// `sync.run`: push, then pull, over one connection and one hold of the write lock (never waiting
/// for it). Counts only: bundle names are random per push and nothing in a UI needs them.
fn run_sync(job: &SyncJob) -> Result<Value, Failure> {
    let store = store::open_for_write_with(&job.db_path, "sync", 0.0, Some(&job.master))?;
    let conn = store.conn();
    let emit = |line: String| {
        // the bridge being gone is not the sync's problem: EOF on stdin ends the process
        let _ = job.channel.write_line(&line);
    };
    emit(sync_event("sync", "push", "start", None));
    let pushed = relay_sync::push(conn, job.master.as_slice(), &*job.relay)?;
    let push = json!({"bundles": pushed.bundles.len(), "records": pushed.records, "ranges": pushed.ranges});
    emit(sync_event("sync", "push", "done", Some(&push)));
    emit(sync_event("sync", "pull", "start", None));
    let pulled = relay_sync::pull(conn, job.master.as_slice(), &*job.relay)?;
    let pull = json!({
        "applied": pulled.applied.len(),
        "rejected": pulled.rejected.len(),
        "records_new": pulled.records_new,
        "records_duplicate": pulled.records_duplicate,
        "records_invalid": pulled.records_invalid,
        "conflicts": pulled.conflicts,
        "ranges_new": pulled.ranges_new,
        "records_repaired": pulled.records_repaired,
        "records_kept": pulled.records_kept,
        "gaps": pulled.gaps.len(),
        "status": pulled.status,
    });
    emit(sync_event("sync", "pull", "done", Some(&pull)));
    Ok(json!({"push": push, "pull": pull}))
}

fn sync_worker(job: SyncJob) {
    // a panic must still free the slot and answer (see `import_worker`)
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_sync(&job)));
    let line = match outcome {
        Ok(Ok(result)) => result_line(&job.id, &result),
        Ok(Err(failure)) => failure_line(&job.id, &failure),
        Err(_) => failure_line(
            &job.id,
            &Failure::serve("internal", "unexpected panic in the sync worker"),
        ),
    };
    job.slot.store(false, Ordering::SeqCst);
    let _ = job.channel.write_line(&line);
}

/// Start a push-then-pull over the relay `relay.json` names; the answer is sent when it finishes.
/// Checked in this order: unlocked (`locked`), a relay configured (`not_found`), an encrypted store
/// (`not_encrypted`), the slot shared with `import.run` (`busy`).
fn sync_run(session: &mut Session, call: &Call) -> Result<(), Failure> {
    session.require_unlocked()?;
    let config = relay_config::read(&relay_json_path(&session.db_path)).ok_or_else(|| {
        Failure::serve(
            "not_found",
            "no relay is configured (relay.json in the data folder)",
        )
    })?;
    let Some(master) = session.unlocked_master().cloned() else {
        return Err(Failure::serve(
            "not_encrypted",
            format!(
                "the relay needs an encrypted store: run '{} key init' first",
                identity::COMMAND
            ),
        ));
    };
    let relay = relay_config::open(&config, master.as_slice())
        .map_err(|rule| Failure::serve("bad_params", format!("relay.json: {rule}")))?;
    if session
        .import_slot
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(Failure::serve(
            "busy",
            "an import or a sync is already running",
        ));
    }
    let job = SyncJob {
        id: call.id.clone(),
        db_path: session.db_path.clone(),
        master,
        relay,
        channel: Arc::clone(&session.channel),
        slot: Arc::clone(&session.import_slot),
    };
    let slot = Arc::clone(&session.import_slot);
    match std::thread::Builder::new()
        .name("sync".into())
        .spawn(move || sync_worker(job))
    {
        Ok(handle) => {
            session.workers.push(handle);
            Ok(())
        }
        Err(error) => {
            slot.store(false, Ordering::SeqCst);
            Err(Failure::Io(error))
        }
    }
}

// ---- relay and pairing (serve mode) ----

/// The checks `relay.addresses`, `relay.serve`, `pair.offer`, `pair.confirm` and `pair.cancel` share, in this
/// order on both cores: unlocked (`locked`); a relay configured (`not_found`, the `sync.run` text); a `lan`
/// relay serves nothing (`bad_params`); an encrypted store (`not_encrypted`); no `<keys>.next` rotation file
/// (`busy`, the CLI's `resolve_master` refusal, which `key.unlock` does not apply). Parameter shapes come after.
fn relay_prefix(session: &Session) -> Result<Site, Failure> {
    session.require_unlocked()?;
    let config = relay_config::read(&relay_json_path(&session.db_path)).ok_or_else(|| {
        Failure::serve(
            "not_found",
            "no relay is configured (relay.json in the data folder)",
        )
    })?;
    let folder = match config {
        relay_config::RelayConfig::Folder(folder) => keys::expand_user(Path::new(&folder)),
        relay_config::RelayConfig::Lan(_) => {
            return Err(Failure::serve(
                "bad_params",
                "this device is a joiner; it serves nothing",
            ));
        }
    };
    let Some(master) = session.unlocked_master().cloned() else {
        return Err(Failure::serve(
            "not_encrypted",
            format!(
                "the relay needs an encrypted store: run '{} key init' first",
                identity::COMMAND
            ),
        ));
    };
    if keys::next_path_for(&session.key_path()).exists() {
        return Err(Failure::serve(
            "busy",
            "a key rotation is in progress; finish it first",
        ));
    }
    Ok(Site { folder, master })
}

/// `listen`: absent or null is None; anything else must be a string that [`serving::parse_listen`] accepts.
fn listen_param(call: &Call) -> Result<Option<std::net::SocketAddr>, Failure> {
    let text = match call.params.get("listen") {
        None | Some(Json::Null) => return Ok(None),
        Some(Json::Str(text)) if !text.is_empty() => text,
        Some(_) => {
            return Err(Failure::serve(
                "bad_params",
                "listen must be a non-empty string",
            ));
        }
    };
    let Some(plain) = text.to_text() else {
        return Err(Failure::serve(
            "bad_params",
            "listen must be an IP address and a port, like 192.168.1.20:24816",
        ));
    };
    serving::parse_listen(&plain)
        .map(Some)
        .map_err(|message| Failure::serve("bad_params", message))
}

fn required_listen(call: &Call) -> Result<std::net::SocketAddr, Failure> {
    listen_param(call)?.ok_or_else(|| Failure::serve("bad_params", "listen must be a non-empty string"))
}

/// The Mac's assigned addresses and the port to suggest (Rust only: the Python core serves nothing).
fn relay_addresses(session: &mut Session, _call: &Call) -> Result<Value, Failure> {
    relay_prefix(session)?;
    Ok(serving::addresses_value(&session.relay_env()))
}

/// The user's switch: serve the relay on `listen` while the app runs (`on` true), or stop (`on` false: the
/// server stays while an offer still needs it, then follows the offer's lifetime rule).
fn relay_serve(session: &mut Session, call: &Call) -> Result<Value, Failure> {
    // the stop path checks only `locked` and the parameter shapes: a running listener must always be
    // stoppable, even after `sync forget`, a rewritten relay.json or a CLI key rotation
    session.require_unlocked()?;
    if matches!(bool_param(call, "on"), Ok(false)) {
        listen_param(call)?;
        let url = serving::serve_off(&session.relay_env());
        return Ok(json!({"serving": url.is_some(), "url": url}));
    }
    let site = relay_prefix(session)?;
    let on = bool_param(call, "on")?;
    let listen = listen_param(call)?;
    let env = session.relay_env();
    if on {
        let listen = listen
            .ok_or_else(|| Failure::serve("bad_params", "listen must be a non-empty string"))?;
        let url = serving::serve_on(&env, listen, &site)?;
        Ok(json!({"serving": true, "url": url}))
    } else {
        let url = serving::serve_off(&env);
        Ok(json!({"serving": url.is_some(), "url": url}))
    }
}

/// One `pair.offer` request: everything the worker needs.
struct PairJob {
    id: Id,
    db_path: PathBuf,
    site: Site,
    listen: std::net::SocketAddr,
    env: Env,
    channel: Arc<Channel>,
    slot: Arc<AtomicBool>,
}

/// Push the store to the relay folder (the joiner bootstraps from what was last pushed), releasing the
/// write lock when it is done. Two `progress` events, `op` `pair`.
fn pair_push(job: &PairJob) -> Result<(), Failure> {
    let store = store::open_for_write_with(&job.db_path, "pair", 0.0, Some(&job.site.master))?;
    let emit = |line: String| {
        let _ = job.channel.write_line(&line);
    };
    emit(sync_event("pair", "push", "start", None));
    let relay = FolderRelay::new(job.site.folder.clone());
    let pushed = relay_sync::push(store.conn(), job.site.master.as_slice(), &relay)?;
    let counts = json!({"bundles": pushed.bundles.len(), "records": pushed.records, "ranges": pushed.ranges});
    emit(sync_event("pair", "push", "done", Some(&counts)));
    Ok(())
}

fn pair_panic() -> Failure {
    Failure::serve("internal", "unexpected panic in the pair worker")
}

/// `pair.offer`'s worker: push (holding the import slot for the push only), then start the server if none
/// runs, attach the offer and answer `{"offer", "url", "expires_at"}`; the offer's watcher takes over.
fn pair_worker(job: PairJob) {
    let pushed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pair_push(&job)))
        .unwrap_or_else(|_| Err(pair_panic()));
    job.slot.store(false, Ordering::SeqCst);
    let outcome = match pushed {
        Err(failure) => {
            serving::drop_reservation(&job.env);
            Err(failure)
        }
        Ok(()) => {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                serving::finish_offer(&job.env, job.listen, &job.site).map_err(Failure::from)
            }))
            .unwrap_or_else(|_| {
                serving::drop_reservation(&job.env);
                Err(pair_panic())
            })
        }
    };
    let line = match outcome {
        Ok((offer, url, expires_at)) => {
            result_line(&job.id, &json!({"offer": offer, "url": url, "expires_at": expires_at}))
        }
        Err(failure) => failure_line(&job.id, &failure),
    };
    let _ = job.channel.write_line(&line);
}

/// Open an offer on `listen`. On the request loop: the shared prefix, `listen`, `busy` when an offer is open
/// (the offer is reserved here, so a second `pair.offer` or a `relay.serve` off cannot slip in during the
/// push) and `busy` when an import or a sync holds the slot.
fn pair_offer(session: &mut Session, call: &Call) -> Result<(), Failure> {
    let site = relay_prefix(session)?;
    let listen = required_listen(call)?;
    let env = session.relay_env();
    serving::reserve_offer(&env, listen)?;
    if session
        .import_slot
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        serving::drop_reservation(&env);
        return Err(Failure::serve(
            "busy",
            "an import or a sync is already running",
        ));
    }
    let job = PairJob {
        id: call.id.clone(),
        db_path: session.db_path.clone(),
        site,
        listen,
        env,
        channel: Arc::clone(&session.channel),
        slot: Arc::clone(&session.import_slot),
    };
    let (slot, env) = (Arc::clone(&session.import_slot), session.relay_env());
    match std::thread::Builder::new()
        .name("pair".into())
        .spawn(move || pair_worker(job))
    {
        Ok(handle) => {
            session.workers.push(handle);
            Ok(())
        }
        Err(error) => {
            slot.store(false, Ordering::SeqCst);
            serving::drop_reservation(&env);
            Err(Failure::Io(error))
        }
    }
}

/// The digits the user typed from the other device: exactly six ASCII digits, or `bad_params` (a malformed
/// entry does not abort the offer; the webview gets its one real try).
fn pair_confirm(session: &mut Session, call: &Call) -> Result<Value, Failure> {
    let site = relay_prefix(session)?;
    let digits = match call.params.get("digits") {
        Some(Json::Str(text)) => text.to_text().filter(|plain| {
            plain.len() == 6 && plain.bytes().all(|b| b.is_ascii_digit())
        }),
        _ => None,
    }
    .ok_or_else(|| Failure::serve("bad_params", "digits must be exactly six digits"))?;
    let key_file_bytes = std::fs::read(session.key_path())
        .map_err(|_| Failure::serve("internal", "cannot read the key file"))?;
    serving::confirm(&session.relay_env(), &digits, &site.master, &key_file_bytes)?;
    Ok(json!({"state": "released"}))
}

/// End the open offer (idempotent); `not_found` when there is none.
fn pair_cancel(session: &mut Session, _call: &Call) -> Result<Value, Failure> {
    session.require_unlocked()?;
    serving::cancel(&session.relay_env())?;
    Ok(json!({"state": "aborted"}))
}

// ---- tools ----

/// What the MCP tool `name` answers to `arguments` (`structuredContent`), read from this session's store: the
/// coach loop of the desktop app reaches the six read-only tools through here, so each tool has one
/// implementation per core. The tool runs on an [`ToolServer`] built from the session's store and master key;
/// arguments are coerced by [`coerce`] as the MCP does. Failures: `invalid_params` (`name` is not a non-empty
/// string, `arguments` is not an object, or the arguments do not fit the tool: the message names the
/// parameters at fault, never a value), `unknown_tool`, and `tool_error` (the tool's own error text, or the
/// crash text of `mcp.json`).
fn tools_call(session: &mut Session, call: &Call) -> Result<Json, Failure> {
    session.require_unlocked()?;
    let invalid = |message: &str| Failure::serve("invalid_params", message);
    let name = match call.params.get("name") {
        Some(Json::Str(text)) if !text.is_empty() => text,
        _ => return Err(invalid("name must be a non-empty string")),
    };
    let empty = Json::dict();
    let arguments = match call.params.get("arguments") {
        None | Some(Json::Null) => &empty,
        Some(object @ Json::Object(_)) => object,
        Some(_) => return Err(invalid("arguments must be an object")),
    };
    let Some(tool) = TOOLS.iter().find(|tool| name.equals(tool.name)) else {
        return Err(Failure::serve(
            "unknown_tool",
            spec_text(&["errors", "unknown_tool"]).replace("{name}", &name.units_lossy()),
        ));
    };
    let args = coerce(tool.params, arguments)
        .map_err(|rejected| invalid(&rejection_names(&rejected)))?;
    let server = ToolServer::new(session.db_path.clone(), session.unlocked.clone());
    match (tool.run)(&server, &args) {
        Outcome::Done(json) => {
            let mut answer = Json::dict();
            answer.set("name", Json::text(tool.name));
            answer.set("result", json);
            Ok(answer)
        }
        Outcome::Failed(message) => Err(Failure::serve("tool_error", message)),
        Outcome::Crashed => Err(Failure::serve(
            "tool_error",
            spec_text(&["errors", "crash"]).replace("{name}", tool.name),
        )),
    }
}

// ---- the loop ----

/// A line that is not a usable request; the id is [`Id::None`] when not even an id could be read.
struct Rejected {
    id: Id,
    message: &'static str,
}

fn parse(line: &str) -> Result<Call, Rejected> {
    let none = |message| Rejected {
        id: Id::None,
        message,
    };
    let request = wirejson::parse(line).map_err(|_| none("request is not valid JSON"))?;
    if !matches!(request, Json::Object(_)) {
        return Err(none("request must be a JSON object"));
    }
    let id = match request.get("id") {
        Some(Json::Int(int)) => Id::Int(int.clone()),
        Some(Json::Str(text)) => Id::Str(text.clone()),
        _ => return Err(none("request id must be an integer or a string")),
    };
    let params = match request.get("params") {
        None => Json::Object(Vec::new()),
        Some(object @ Json::Object(_)) => object.clone(),
        Some(_) => {
            return Err(Rejected {
                id,
                message: "method must be a string and params an object",
            });
        }
    };
    let Some(Json::Str(method)) = request.get("method") else {
        return Err(Rejected {
            id,
            message: "method must be a string and params an object",
        });
    };
    Ok(Call {
        id,
        method: method.clone(),
        params,
    })
}

// ---- the phone's own method ----

/// `pair.forget` (12-F, M5): the phone deletes its copy, key file, keychain item and `relay.json`, then forgets the
/// master. A phone-only method: any other core answers `unsupported_transport` (the Python core, the desktop build).
/// Params are ignored; the unsent count the sheet shows is `sync.status`'s `records_unsent`. The order and its crash
/// safety are in [`crate::phone_forget`]. Answers `{"forgotten": true, "keychain": "removed"|"none"|"failed: <text>"}`,
/// or `busy` when an import or a sync runs, with nothing deleted.
#[cfg(not(target_os = "ios"))]
fn phone_forget(_session: &mut Session, _call: &Call) -> Result<Value, Failure> {
    Err(Failure::serve(
        "unsupported_transport",
        "this core is not a phone; there is nothing to forget",
    ))
}

#[cfg(target_os = "ios")]
fn phone_forget(session: &mut Session, _call: &Call) -> Result<Value, Failure> {
    use crate::phone_forget as forget;
    let paths = forget::Paths::beside(&session.db_path, &session.key_path());
    // 1. the marker, before anything else
    forget::write_marker(&paths).map_err(Failure::Io)?;
    // 2. the import slot (shared with sync) and the write lock; a refusal deletes nothing and takes the marker back
    if session
        .import_slot
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        forget::clear_marker(&paths);
        return Err(Failure::serve("busy", "an import or a sync is already running"));
    }
    let outcome = forget_holding_slot(session, &paths);
    session.import_slot.store(false, Ordering::SeqCst);
    outcome
}

#[cfg(target_os = "ios")]
fn forget_holding_slot(session: &mut Session, paths: &crate::phone_forget::Paths) -> Result<Value, Failure> {
    use crate::phone_forget as forget;
    let lock = match crate::write_lock::acquire(&session.db_path, "forget", std::time::Duration::ZERO) {
        Ok(lock) => lock,
        Err(error) => {
            forget::clear_marker(paths);
            return Err(match error {
                LockError::Busy { .. } => Failure::serve("busy", error.to_string()),
                LockError::HomeMoved(_) => Failure::serve("not_found", error.to_string()),
                LockError::Io(io) => Failure::Io(io),
            });
        }
    };
    let result = forget::run(paths, &mut forget::RealItems, &mut |_| false);
    drop(lock);
    let keychain = result.map_err(Failure::Io)?;
    // 7. the master leaves the session
    session.unlocked = None;
    Ok(json!({"forgotten": true, "keychain": keychain.text()}))
}

/// The server roles a phone never plays (the Mac serves the relay and offers pairing), refused before
/// their handlers run. The names are the protocol's own; `ALLOWED_METHODS` in the app is unchanged.
#[cfg(target_os = "ios")]
const SERVER_ROLES: [&str; 5] =
    ["relay.addresses", "relay.serve", "pair.offer", "pair.confirm", "pair.cancel"];

#[cfg(target_os = "ios")]
fn refuse_server_roles(call: &Call) -> Option<String> {
    SERVER_ROLES.iter().any(|name| call.method.equals(name)).then(|| {
        error_line(
            &call.id,
            "unsupported_transport",
            "this phone does not serve the relay or offer pairing; the Mac does",
        )
    })
}

/// The response line for `call`, or None when the handler answers later (the import worker).
fn dispatch(session: &mut Session, call: &Call) -> Option<String> {
    #[cfg(target_os = "ios")]
    if let Some(refusal) = refuse_server_roles(call) {
        return Some(refusal);
    }
    let Some((_, handler)) = METHODS.iter().find(|(name, _)| call.method.equals(name)) else {
        return Some(error_line(&call.id, "unknown_method", "no such method"));
    };
    match handler {
        Handler::Reply(handler) => Some(match handler(session, call) {
            Ok(result) => result_line(&call.id, &result),
            Err(failure) => failure_line(&call.id, &failure),
        }),
        Handler::Ordered(handler) => Some(match handler(session, call) {
            Ok(result) => ordered_result_line(&call.id, &result),
            Err(failure) => failure_line(&call.id, &failure),
        }),
        Handler::Spawn(handler) => match handler(session, call) {
            Ok(()) => None,
            Err(failure) => Some(failure_line(&call.id, &failure)),
        },
    }
}

/// Answer one request line on the session's channel.
pub fn handle_line(session: &mut Session, line: &str) -> io::Result<()> {
    let reply = match parse(line) {
        Ok(call) => dispatch(session, &call),
        Err(rejected) => Some(error_line(&rejected.id, "bad_params", rejected.message)),
    };
    match reply {
        Some(line) => session.channel.write_line(&line),
        None => Ok(()),
    }
}

/// Python's `str.strip()` emptiness test: Unicode white space plus the four ASCII separators.
fn is_blank(line: &str) -> bool {
    line.chars()
        .all(|c| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// The request loop: one request per non-blank line until the input ends, then wait for any import.
/// Lines end at `\n` only; bytes that are not UTF-8 become U+FFFD. Returns the process exit code.
pub fn serve_lines(session: &mut Session, input: impl Read) -> i32 {
    read_requests(session, input);
    // the relay ends first: an open offer is aborted and the server stopped, so no listener outlives the
    // session while a worker is awaited (a worker that has not bound yet sees `ended` and does not)
    serving::end_session(&session.relay_env());
    session.wait_for_imports();
    0
}

fn read_requests(session: &mut Session, mut input: impl Read) {
    let mut line: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let count = match input.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        for byte in &chunk[..count] {
            if *byte != b'\n' {
                line.push(*byte);
            } else if answer(session, &mut line).is_err() {
                return; // the bridge's pipe is gone
            }
        }
    }
    let _ = answer(session, &mut line);
}

fn answer(session: &mut Session, line: &mut Vec<u8>) -> io::Result<()> {
    let text = String::from_utf8_lossy(line).into_owned();
    line.clear();
    if is_blank(&text) {
        Ok(())
    } else {
        handle_line(session, &text)
    }
}

// ---- process start ----

/// Move the protocol to a private descriptor and point fd 1 at stderr; return the private stream.
#[cfg(unix)]
pub fn isolate_stdout() -> io::Result<std::fs::File> {
    use std::os::fd::FromRawFd;
    // SAFETY: plain descriptor calls; `private` is a fresh descriptor this function now owns.
    unsafe {
        let private = libc::dup(1);
        if private < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::dup2(2, 1) < 0 {
            let error = io::Error::last_os_error();
            libc::close(private);
            return Err(error);
        }
        Ok(std::fs::File::from_raw_fd(private))
    }
}

/// Descriptor isolation needs `dup2`; Windows is row 13's problem.
#[cfg(not(unix))]
pub fn isolate_stdout() -> io::Result<std::fs::File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "serve needs unix file descriptors",
    ))
}

/// Serve the protocol on stdio until stdin closes. `warnings` are `log` events written first (the
/// binary reports there that it removed a passphrase variable). Returns the exit code.
pub fn run(db_path: PathBuf, warnings: &[String]) -> i32 {
    let private = match isolate_stdout() {
        Ok(stream) => stream,
        Err(error) => {
            // stderr is the only place left; the kind is enough
            let _ = writeln!(
                io::stderr(),
                "error: cannot isolate the protocol stream: {}",
                error.kind()
            );
            return 1;
        }
    };
    let mut session = Session::new(db_path, Channel::new(Box::new(private)));
    for warning in warnings {
        if session.channel.log("warn", warning).is_err() {
            return 0;
        }
    }
    serve_lines(&mut session, io::stdin().lock())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_means_pythons_strip() {
        assert!(is_blank("") && is_blank("  \t") && is_blank("\u{a0}\u{1c}\u{85}\u{2003}"));
        assert!(!is_blank("\u{feff}") && !is_blank(" x "));
    }

    #[test]
    fn surrogate_messages_follow_the_encoder() {
        let lone = PyStr::from_units(vec![0xd800]);
        assert_eq!(
            surrogate_message(&lone),
            "'utf-8' codec can't encode character '\\ud800' in position 0: surrogates not allowed"
        );
        // "a" + combining acute composes to one code point, so a run of two lone surrogates starts at 1
        let run = PyStr::from_units(vec![0x61, 0x301, 0xd800, 0xd801, 0x62]);
        assert_eq!(
            surrogate_message(&run),
            "'utf-8' codec can't encode characters in position 1-2: surrogates not allowed"
        );
    }
}
