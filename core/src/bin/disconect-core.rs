// SPDX-License-Identifier: AGPL-3.0-or-later
//! `disconect-core [--db <path>]` (no subcommand, or `serve`) runs the JSON-lines sidecar protocol on
//! stdio; the default store is `$DISCONECT_DB`, else `~/.disconect/disconect.db` (or the old
//! `~/.hearthbeat/hearthbeat.db` while only that exists; see `disconect_core::home`).
//!
//! `disconect-core --db <path> [--passphrase-file <file>] [--json] status | init | import <path> [--transport T]
//!  | sync push|pull|status|forget [--relay <folder> [--remember]]`
//!
//! `sync` talks to the blind relay (`docs/relay-protocol.md`); the folder comes from `--relay` or
//! `relay.json` in the data folder (`{"folder": path}`, shared with the Python CLI; `--remember` writes
//! it). `push` and `pull` need the store's master key (a key file beside the db, unlocked with
//! `--passphrase-file` or `DISCONECT_PASSPHRASE`); `status` and `forget` need no relay and no key
//! beyond opening the store.
//!
//! Exit codes (the Python CLI's table): 0 ok; 1 failed, partial (`import` with failures, `pull`
//! that rejected a bundle) or an error the oracle lets escape; 2 usage (no such path, no relay
//! folder); 4 write lock busy; 6 database error; 7 schema newer than this build; 9 locked (wrong
//! or missing passphrase, or `sync push|pull` on a store with no key file).

use std::path::PathBuf;
use std::process::ExitCode;

use disconect_core::keys::{self, KeyError, PassphraseSource};
use disconect_core::home;
use disconect_core::identity;
use disconect_core::serve;
use disconect_core::relay::folder::{FolderRelay, RelayError};
use disconect_core::relay::sync::{self, PullResult, StatusReport, SyncError};
use disconect_core::sources::{self, SourceError, TRANSPORTS};
use disconect_core::writer::WriterError;
use disconect_core::store::{self, StoreError};
use disconect_core::write_lock::LockError;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

const EXIT_LOCKED: u8 = 9;
const EXIT_USAGE: u8 = 2;
const EXIT_BUSY: u8 = 4;
const EXIT_DATABASE: u8 = 6;
const EXIT_SCHEMA: u8 = 7;

struct Args {
    db: Option<PathBuf>,
    passphrase_file: Option<PathBuf>,
    /// None: serve.
    command: Option<String>,
    json: bool,
    import_path: Option<PathBuf>,
    transport: Option<String>,
    sync_action: Option<String>,
    relay: Option<String>,
    remember: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let (mut db, mut pass, mut command, mut json) = (None, None, None, false);
    let (mut import_path, mut transport) = (None, None);
    let (mut sync_action, mut relay, mut remember) = (None, None, false);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--db" => db = Some(PathBuf::from(it.next().ok_or("--db needs a path")?)),
            "--passphrase-file" => pass = Some(PathBuf::from(it.next().ok_or("--passphrase-file needs a path")?)),
            "--json" => json = true,
            "--transport" => {
                let value = it.next().ok_or("--transport needs a value")?;
                if !TRANSPORTS.contains(&value.as_str()) {
                    return Err(format!("--transport must be one of {}", TRANSPORTS.join(", ")));
                }
                transport = Some(value);
            }
            "--relay" => relay = Some(it.next().ok_or("--relay needs a folder")?),
            "--remember" => remember = true,
            "status" | "init" | "import" | "sync" | "serve" if command.is_none() => command = Some(arg),
            "push" | "pull" | "status" | "forget"
                if command.as_deref() == Some("sync") && sync_action.is_none() =>
            {
                sync_action = Some(arg);
            }
            _ if command.as_deref() == Some("import") && import_path.is_none() && !arg.starts_with("--") => {
                import_path = Some(PathBuf::from(arg));
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    Ok(Args {
        db,
        passphrase_file: pass,
        command: command.filter(|c| c != "serve"),
        json,
        import_path,
        transport,
        sync_action,
        relay,
        remember,
    })
}

fn read_passphrase(path: &PathBuf) -> Result<Zeroizing<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read passphrase file: {}", e.kind()))?;
    Ok(Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_string()))
}

fn exit_code_for(err: &StoreError) -> u8 {
    match err {
        StoreError::Key(KeyError::Locked | KeyError::WrongPassphrase) | StoreError::Encrypted(_) => EXIT_LOCKED,
        _ => 1,
    }
}

fn status(db: &std::path::Path, source: PassphraseSource<'_>) -> Result<Value, StoreError> {
    let encrypted = store::is_encrypted_file(db)?.unwrap_or(false);
    let opened = store::open_read_only(db, source)?;
    let mut tables = Map::new();
    for (name, count) in store::table_counts(opened.conn())? {
        tables.insert(name, json!(count));
    }
    Ok(json!({
        "schema_version": opened.user_version()?,
        "encrypted": encrypted,
        "unlocked": true,
        "cipher_version": opened.cipher_version(),
        "tables": tables,
    }))
}

fn import_exit_code(err: &SourceError) -> u8 {
    match err {
        SourceError::NotFound(_) => EXIT_USAGE,
        // the oracle's uncaught Python exception: traceback, exit 1
        SourceError::Abort(_) => 1,
        _ => EXIT_DATABASE,
    }
}

/// Import a path; the summary is counts only. Exit 0 on ok, 1 on partial/failed.
fn run_import(args: &Args, source: PassphraseSource<'_>) -> Result<(), (u8, String)> {
    let path = args.import_path.as_ref().ok_or((EXIT_USAGE, "import needs a path".to_string()))?;
    let opened = store::open_for_write(db_of(args)?, "import", 10.0, source).map_err(|e| {
        let code = match &e {
            StoreError::Lock(LockError::Busy { .. }) => EXIT_BUSY,
            StoreError::SchemaTooNew { .. } => EXIT_SCHEMA,
            StoreError::Db(_) => EXIT_DATABASE,
            other => exit_code_for(other),
        };
        (code, e.to_string())
    })?;
    let stats = sources::import_path(opened.conn(), path, args.transport.as_deref(), None)
        .map_err(|e| (import_exit_code(&e), e.to_string()))?;
    for line in stats.summary_lines() {
        println!("{line}");
    }
    if stats.status() == "ok" { Ok(()) } else { Err((1, String::new())) }
}

/// `Path.expanduser()` for a leading `~`.
fn expand_user(folder: &str) -> PathBuf {
    match (folder.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        (None, Some(home)) if folder == "~" => PathBuf::from(home),
        _ => PathBuf::from(folder),
    }
}

/// `relay.json` in the folder of the resolved database, shared with the Python CLI.
fn relay_config() -> Option<PathBuf> {
    home::relay_config_path()
}

/// `_relay_for`: the folder from `--relay` or the config file; no secrets live there.
fn relay_for(args: &Args) -> Result<FolderRelay, (u8, String)> {
    let config = relay_config();
    let mut folder = args.relay.clone();
    if folder.as_deref().is_none_or(str::is_empty)
        && let Some(path) = config.as_ref().filter(|p| p.exists())
    {
        folder = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|value| value.get("folder").and_then(Value::as_str).map(str::to_string));
    }
    let Some(folder) = folder.filter(|f| !f.is_empty()) else {
        let shown = config.as_ref().map_or_else(
            || format!("~/{}/{}", identity::DATA_DIR, home::RELAY_CONFIG_NAME),
            |p| p.display().to_string(),
        );
        return Err((
            EXIT_USAGE,
            format!("usage: no relay folder: pass --relay <folder> or write {{\"folder\": ...}} to {shown}"),
        ));
    };
    if args.relay.is_some() && args.remember {
        let path = config.ok_or((1, "cannot remember the relay: HOME is not set".to_string()))?;
        let text = disconect_core::canon::dumps_spaced(&disconect_core::canon::Value::Object(vec![(
            "folder".to_string(),
            disconect_core::canon::Value::Str(folder.clone()),
        )]));
        let write = || -> std::io::Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, format!("{text}\n"))
        };
        write().map_err(|e| (1, format!("cannot write the relay config: {}", e.kind())))?;
    }
    Ok(FolderRelay::new(expand_user(&folder)))
}

fn sync_exit(error: &SyncError) -> u8 {
    match error {
        SyncError::Db(_) | SyncError::Writer(WriterError::Db(_)) => EXIT_DATABASE,
        SyncError::Source(SourceError::Db(_)) => EXIT_DATABASE,
        SyncError::Relay(RelayError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => EXIT_USAGE,
        _ => 1,
    }
}

fn open_error_code(error: &StoreError) -> u8 {
    match error {
        StoreError::Lock(LockError::Busy { .. }) => EXIT_BUSY,
        StoreError::SchemaTooNew { .. } => EXIT_SCHEMA,
        StoreError::Db(_) => EXIT_DATABASE,
        other => exit_code_for(other),
    }
}

fn emit(json_output: bool, payload: Value, text: String) {
    if json_output {
        println!("{}", serde_json::to_string_pretty(&payload).unwrap_or_default());
    } else {
        println!("{text}");
    }
}

fn gaps_json(gaps: &[sync::Gap]) -> Value {
    Value::Array(
        gaps.iter()
            .map(|g| json!({"chain": g.chain, "device_seq": g.device_seq, "missing": g.missing}))
            .collect(),
    )
}

fn pull_json(result: &PullResult) -> Value {
    let rejected: Map<String, Value> = result.rejected.iter().map(|(n, r)| (n.clone(), json!(r))).collect();
    json!({
        "applied": result.applied,
        "rejected": rejected,
        "records_new": result.records_new,
        "records_duplicate": result.records_duplicate,
        "records_invalid": result.records_invalid,
        "conflicts": result.conflicts,
        "ranges_new": result.ranges_new,
        "gaps": gaps_json(&result.gaps),
        "status": result.status,
    })
}

fn status_text(report: &StatusReport) -> String {
    let count = |key: &str| report.bundles.get(key).copied().unwrap_or(0);
    format!(
        "relay: pushed {}, pulled {}, rejected {}; records unsent {}, seen {}; conflicts {}; gaps {}",
        count("pushed_applied"),
        count("pulled_applied"),
        count("pulled_rejected"),
        report.records_unsent,
        report.records_seen,
        report.conflicts,
        report.gaps.len()
    )
}

/// `sync push|pull|status|forget`: the blind relay (`docs/relay-protocol.md`). Needs an encrypted
/// store for push and pull: the relay account and keys derive from the master key.
fn run_sync(args: &Args, source: PassphraseSource<'_>) -> Result<(), (u8, String)> {
    let action = args
        .sync_action
        .as_deref()
        .ok_or((EXIT_USAGE, "sync needs an action: push | pull | status | forget".to_string()))?;
    let failed = |e: SyncError| (sync_exit(&e), e.to_string());
    let open_err = |e: StoreError| (open_error_code(&e), e.to_string());
    match action {
        "forget" => {
            let opened = store::open_for_write(db_of(args)?, "sync", 10.0, source).map_err(open_err)?;
            sync::forget_relay_state(opened.conn()).map_err(failed)?;
            emit(
                args.json,
                json!({"forgotten": true}),
                "relay bookkeeping cleared: the next 'sync push' publishes everything again".to_string(),
            );
            Ok(())
        }
        "status" => {
            let opened = store::open_for_write(db_of(args)?, "sync", 10.0, source).map_err(open_err)?;
            let report = sync::status(opened.conn()).map_err(failed)?;
            let bundles: Map<String, Value> = report.bundles.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            let payload = json!({
                "bundles": bundles,
                "records_unsent": report.records_unsent,
                "records_seen": report.records_seen,
                "conflicts": report.conflicts,
                "superseded": report.superseded,
                "gaps": gaps_json(&report.gaps),
            });
            emit(args.json, payload, status_text(&report));
            Ok(())
        }
        _ => {
            let master = store::resolve_master(db_of(args)?, source).map_err(open_err)?;
            let Some(master) = master else {
                return Err((
                    EXIT_LOCKED,
                    "the relay needs an encrypted store: run 'hearthbeat key init' first".to_string(),
                ));
            };
            let relay = relay_for(args)?;
            let opened =
                store::open_for_write_with(db_of(args)?, "sync", 10.0, Some(&master)).map_err(open_err)?;
            if action == "push" {
                let result = sync::push(opened.conn(), &*master, &relay).map_err(failed)?;
                emit(
                    args.json,
                    json!({"bundles": result.bundles, "records": result.records, "ranges": result.ranges}),
                    format!(
                        "pushed {} bundle(s): {} record(s), {} range(s)",
                        result.bundles.len(),
                        result.records,
                        result.ranges
                    ),
                );
                return Ok(());
            }
            let result = sync::pull(opened.conn(), &*master, &relay).map_err(failed)?;
            emit(
                args.json,
                pull_json(&result),
                format!(
                    "pulled {} bundle(s): {} new, {} duplicate, {} invalid, {} conflict(s), {} new range(s); rejected {}; gaps {}",
                    result.applied.len(),
                    result.records_new,
                    result.records_duplicate,
                    result.records_invalid,
                    result.conflicts,
                    result.ranges_new,
                    result.rejected.len(),
                    result.gaps.len()
                ),
            );
            if result.status == "ok" { Ok(()) } else { Err((1, String::new())) }
        }
    }
}

/// The store a command works on: `--db` is required for everything except `serve`.
fn db_of(args: &Args) -> Result<&PathBuf, (u8, String)> {
    args.db.as_ref().ok_or((1, "--db <path> is required".to_string()))
}

fn run(args: &Args) -> Result<(), (u8, String)> {
    let phrase = match &args.passphrase_file {
        Some(p) => Some(read_passphrase(p).map_err(|m| (1, m))?),
        None => None,
    };
    let source = match &phrase {
        Some(p) => PassphraseSource::Explicit(p.as_str()),
        None => PassphraseSource::Env,
    };
    let fail = |e: StoreError| (exit_code_for(&e), e.to_string());
    match args.command.as_deref().unwrap_or_default() {
        "import" => run_import(args, source),
        "sync" => run_sync(args, source),
        "status" if args.json => {
            let value = status(db_of(args)?, source).map_err(fail)?;
            println!("{value}");
            Ok(())
        }
        "status" => Err((1, "status requires --json".to_string())),
        _ => store::open_for_write(db_of(args)?, "init", 10.0, source).map(|_| ()).map_err(fail),
    }
}

/// `serve`: scrub the secret variables first (before any thread exists), then speak the protocol.
fn run_serve(args: &Args) -> ExitCode {
    let unexpected = args.json
        || args.passphrase_file.is_some()
        || args.import_path.is_some()
        || args.transport.is_some()
        || args.sync_action.is_some()
        || args.relay.is_some()
        || args.remember;
    if unexpected {
        eprintln!("error: serve takes only --db <path>");
        return ExitCode::from(EXIT_USAGE);
    }
    // `--db` is taken literally (the oracle's argparse default is the only place `~` is expanded)
    let db = match args.db.clone() {
        Some(db) => db,
        None => {
            let Some(default) = home::resolve_default_db() else {
                eprintln!("error: no store: pass --db <path> or set DISCONECT_DB (HOME is not set)");
                return ExitCode::from(1);
            };
            if let Some(legacy) = default.legacy_home {
                eprintln!("{}", home::legacy_home_hint(legacy));
            }
            default.path
        }
    };
    let removed = keys::scrub_env_secrets();
    let warnings: Vec<String> = removed
        .then(|| format!("{} is ignored by serve and was removed from the environment", keys::PASSPHRASE_ENV))
        .into_iter()
        .collect();
    ExitCode::from(u8::try_from(serve::run(db, &warnings)).unwrap_or(1))
}

fn main() -> ExitCode {
    disconect_core::fit::silence_parser_panics();
    let args = match parse_args() {
        Ok(a) => a,
        Err(m) => {
            eprintln!("error: {m}");
            return ExitCode::from(1);
        }
    };
    if let Some(warning) = home::legacy_env_warning_now() {
        eprintln!("{warning}");
    }
    if args.command.is_none() {
        return run_serve(&args);
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, message)) => {
            if !message.is_empty() {
                eprintln!("error: {}", message.lines().next().unwrap_or("failed"));
            }
            ExitCode::from(code)
        }
    }
}
