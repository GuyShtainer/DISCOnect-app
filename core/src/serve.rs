// SPDX-License-Identifier: AGPL-3.0-or-later
//! `disconect-core` with no subcommand: the JSON-lines sidecar protocol the desktop app speaks over
//! stdio, ported from `hearthbeat/serve.py` (the oracle is that file and `tests/test_serve.py`;
//! `docs/serve-protocol.md` follows them).
//!
//! Slice 3A ports the transport and the start-up methods: `app.info`, `key.status`, `key.unlock`,
//! `key.cache`; slice 3B adds `data.facts`; slice 3C adds `data.metric` and `data.today`. Every other method of the protocol is simply absent from [`METHODS`], so it answers
//! `unknown_method` until its slice lands (never a new error code, never a fake result); the list of
//! what is still absent is [`crate::read::DEFERRED_METHODS`].
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
use std::sync::Mutex;

use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::contract::{Contract, ContractError};
use crate::identity::{self, NOTICE, PRODUCT};
use crate::keychain::{self, KeychainError, KeychainState};
use crate::keys::{self, KeyError, Secret32};
use crate::read::ReadError;
use crate::read::coverage::{self, NOT_COVERED, PRESENT};
use crate::read::insight::{self, FactsQuery};
use crate::read::queries::{self, MAX_DAILY_DAYS, MAX_SAMPLE_DAYS};
use crate::redact::redact_text;
use crate::store::{self, StoreError};
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
            Failure::Io(error) => io_parts(error),
        }
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
            "no Hearthbeat database yet; run 'hearthbeat import' first".into(),
        ),
        StoreError::Encrypted(message) => ("locked", message.clone()),
        StoreError::NotEncrypted(_) => ("not_encrypted", error.to_string()),
        StoreError::SchemaTooNew { found } => (
            "database",
            format!(
                "database schema is version {found}; this build understands up to {}. Upgrade Hearthbeat.",
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
/// `key.unlock` registered. (The import slot joins it with `import.run`.)
pub struct Session {
    pub db_path: PathBuf,
    pub channel: Channel,
    unlocked: Option<Secret32>,
}

impl Session {
    pub fn new(db_path: PathBuf, channel: Channel) -> Session {
        Session {
            db_path,
            channel,
            unlocked: None,
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

pub type Handler = fn(&mut Session, &Call) -> Result<Value, Failure>;

/// The protocol's methods. A method exists exactly when it is a name here.
pub const METHODS: &[(&str, Handler)] = &[
    ("app.info", app_info),
    ("key.status", key_status),
    ("key.unlock", key_unlock),
    ("key.cache", key_cache),
    ("data.facts", data_facts),
    ("data.metric", data_metric),
    ("data.today", data_today),
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
        Some(text) => queries::parse_date_py(&text)?,
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

/// The response line for `call`.
fn dispatch(session: &mut Session, call: &Call) -> String {
    let Some((_, handler)) = METHODS.iter().find(|(name, _)| call.method.equals(name)) else {
        return error_line(&call.id, "unknown_method", "no such method");
    };
    match handler(session, call) {
        Ok(result) => result_line(&call.id, &result),
        Err(failure) => failure_line(&call.id, &failure),
    }
}

/// Answer one request line on the session's channel.
pub fn handle_line(session: &mut Session, line: &str) -> io::Result<()> {
    let reply = match parse(line) {
        Ok(call) => dispatch(session, &call),
        Err(rejected) => error_line(&rejected.id, "bad_params", rejected.message),
    };
    session.channel.write_line(&reply)
}

/// Python's `str.strip()` emptiness test: Unicode white space plus the four ASCII separators.
fn is_blank(line: &str) -> bool {
    line.chars()
        .all(|c| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// The request loop: one request per non-blank line until the input ends. Lines end at `\n` only;
/// bytes that are not UTF-8 become U+FFFD. Returns the process exit code.
pub fn serve_lines(session: &mut Session, mut input: impl Read) -> i32 {
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
                return 0; // the bridge's pipe is gone
            }
        }
    }
    let _ = answer(session, &mut line);
    0
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

/// `$HEARTHBEAT_DB` (with `~` expanded) if set and non-empty, else `~/.hearthbeat/hearthbeat.db`.
pub fn default_db_path() -> Option<PathBuf> {
    match std::env::var_os("HEARTHBEAT_DB") {
        Some(path) if !path.is_empty() => Some(keys::expand_user(Path::new(&path))),
        _ => std::env::var_os("HOME").map(|home| {
            PathBuf::from(home)
                .join(".hearthbeat")
                .join("hearthbeat.db")
        }),
    }
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
