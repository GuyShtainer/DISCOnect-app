// SPDX-License-Identifier: AGPL-3.0-or-later
//! `disconect-core [--db <path>]` (no subcommand, or `serve`) runs the JSON-lines sidecar protocol on
//! stdio; the default store is `$DISCONECT_DB`, else `~/.disconect/disconect.db` (or the old
//! `~/.hearthbeat/hearthbeat.db` while only that exists; see `disconect_core::home`).
//!
//! `disconect-core mcp [--db <path>] [--passphrase-file <file>]` is the MCP server over stdio (`disconect_core::mcp`, `mcp_start`, `mcp_tools`):
//! the same store resolution as `serve`; exit 9 before reading stdin when the store is encrypted and its key is
//! not in the keychain. `--passphrase-file` is for the test harness; `DISCONECT_PASSPHRASE` is never read.
//!
//! `disconect-core --db <path> [--passphrase-file <file>] [--json] status | init | import <path> [--transport T]
//!  | reparse [--stream S]... [--force] | sync push|pull|status|forget [--relay <folder|url> [--remember]]
//!  | relay-serve --relay <folder> [--listen <addr:port>]`
//!
//! `relay-serve` serves a relay folder over HTTP on the LAN (`disconect_core::relay::lan_server`): it needs the
//! unlocked key only to derive the token key and the account, never decrypts a bundle, binds `127.0.0.1:0` unless
//! `--listen` says otherwise, prints `listening http://<addr>` on stdout and logs only method and status to stderr.
//!
//! `disconect-core --db <path> --passphrase-file <file> --relay <folder> --listen <addr:port> pair offer`
//! pairs a second device (Bet 12-E, ADR 0011): it is `relay-serve` plus one offer. It pushes the store to the
//! folder first, prints the offer text (one line, stdout; treat it like a QR photo), waits for a device, prints
//! the code on stderr, reads the six digits the other device shows from stdin and releases the key only if they
//! match; then it keeps serving until Ctrl-C (also when the offer ended: expired, aborted or wrong code). `--listen` must be an address the joiner can reach; port 0 is
//! refused (the URL becomes the joiner's relay).
//! `disconect-core --db <new db> [--relay-file <path>] [--i-saw-paired] pair join` reads the offer text from stdin (never argv),
//! refuses before any request when the store, its key file, `<keys>.next`, `DISCONECT_KEYS` or a relay file of another
//! store are in the way, shows its code on stderr, and once the offerer released asks on the terminal (`/dev/tty`
//! when the offer came on a pipe; stdin when stdin is the terminal, its stray input flushed first) whether the other
//! device says Paired, naming the relay host: `y`/`yes` lands, a blank line asks again, anything
//! else, EOF, no terminal at all or the offer's expiry drops the pairing with "Not paired; nothing was written"
//! (exit 1); `--i-saw-paired` answers yes for scripts; `DISCONECT_ASK_ON_STDIN=1` reads the answer from stdin
//! for test harnesses — the phone's `pair.land` step, 12-G N12. Then it writes the relay file (`relay.json` beside the db by default, where the app and the CLI read it), the
//! key file (atomically), the encrypted store, and pulls; stdout is `{"paired": true, "pulled": {...}}`.
//!
//! `reparse` replays decoding over the retained raw records (`sources::reparse_all`, the Python `reparse`);
//! `--json` prints the run's `ImportStats` plus `status`, the same keys as the Python CLI.
//!
//! `sync` talks to the blind relay (`docs/relay-protocol.md`); the relay comes from `--relay` (a folder, or
//! `http://host:port` for a LAN relay) or `relay.json` in the data folder (`{"folder": path}` or
//! `{"lan": url}`, shared with the Python CLI, which refuses `lan`; `--remember` writes it). `push` and `pull` need the store's master key (a key file beside the db, unlocked with
//! `--passphrase-file` or `DISCONECT_PASSPHRASE`); `status` and `forget` need no relay and no key
//! beyond opening the store.
//!
//! Exit codes (the Python CLI's table): 0 ok; 1 failed, partial (`import`/`reparse` with failures, `pull`
//! that rejected a bundle) or an error the oracle lets escape; 2 usage (no such path, no relay
//! folder); 4 write lock busy; 5 the LAN relay is unreachable (retryable; nothing was marked); 6 database error; 7 schema newer than this build; 9 locked (wrong
//! or missing passphrase, or `sync push|pull` on a store with no key file).

use std::path::PathBuf;
use std::process::ExitCode;

use disconect_core::keys::{self, KeyError, PassphraseSource};
use disconect_core::mcp_start as mcp;
use disconect_core::home;
use disconect_core::identity;
use disconect_core::serve;
use disconect_core::relay::config::{self as relay_cfg, RelayConfig, RelayEntry};
use disconect_core::relay::folder::{Relay, RelayError};
use disconect_core::pair::{EXPIRY_S, PairError};
use disconect_core::pair_client;
use disconect_core::relay::folder::FolderRelay;
use disconect_core::relay::lan_server::{LanServer, Limits};
use disconect_core::relay::pair_routes::{PairHandle, PairState};
use disconect_core::relay::sync::{self, PullResult, StatusReport, SyncError};
use disconect_core::sources::{self, SourceError, TRANSPORTS};
use disconect_core::writer::{ImportStats, WriterError};
use disconect_core::store::{self, StoreError};
use disconect_core::write_lock::LockError;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

const EXIT_LOCKED: u8 = 9;
const EXIT_USAGE: u8 = 2;
const EXIT_NOT_CONFIGURED: u8 = 3;
const EXIT_BUSY: u8 = 4;
const EXIT_UNREACHABLE: u8 = 5;
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
    listen: Option<String>,
    remember: bool,
    streams: Vec<String>,
    force: bool,
    pair_action: Option<String>,
    relay_file: Option<PathBuf>,
    i_saw_paired: bool,
    /// `sync relay add|remove|list`.
    relay_action: Option<String>,
    /// The folder or address of `add`, the id of `remove`.
    relay_arg: Option<String>,
    label: Option<String>,
    serve_flag: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let (mut db, mut pass, mut command, mut json) = (None, None, None, false);
    let (mut import_path, mut transport) = (None, None);
    let (mut sync_action, mut relay, mut remember) = (None, None, false);
    let mut listen = None;
    let (mut streams, mut force) = (Vec::new(), false);
    let (mut pair_action, mut relay_file, mut i_saw_paired) = (None, None, false);
    let (mut relay_action, mut relay_arg, mut label, mut serve_flag) = (None, None, None, false);
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
            "--relay" => relay = Some(it.next().ok_or("--relay needs a folder or an http:// address")?),
            "--listen" => listen = Some(it.next().ok_or("--listen needs host:port")?),
            "--remember" => remember = true,
            "--stream" => streams.push(it.next().ok_or("--stream needs a value")?),
            "--force" => force = true,
            "--relay-file" => relay_file = Some(PathBuf::from(it.next().ok_or("--relay-file needs a path")?)),
            "--i-saw-paired" => i_saw_paired = true,
            "--label" => label = Some(it.next().ok_or("--label needs a text")?),
            "--serve" => serve_flag = true,
            "status" | "init" | "import" | "reparse" | "sync" | "serve" | "mcp" | "relay-serve" | "pair" if command.is_none() => command = Some(arg),
            "offer" | "join" if command.as_deref() == Some("pair") && pair_action.is_none() => pair_action = Some(arg),
            "push" | "pull" | "status" | "forget" | "relay"
                if command.as_deref() == Some("sync") && sync_action.is_none() =>
            {
                sync_action = Some(arg);
            }
            "add" | "remove" | "list"
                if sync_action.as_deref() == Some("relay") && relay_action.is_none() =>
            {
                relay_action = Some(arg);
            }
            _ if sync_action.as_deref() == Some("relay")
                && matches!(relay_action.as_deref(), Some("add" | "remove"))
                && relay_arg.is_none()
                && !arg.starts_with("--") =>
            {
                relay_arg = Some(arg);
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
        listen,
        remember,
        streams,
        force,
        pair_action,
        relay_file,
        i_saw_paired,
        relay_action,
        relay_arg,
        label,
        serve_flag,
    })
}

fn read_passphrase(path: &PathBuf) -> Result<Zeroizing<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read passphrase file: {}", e.kind()))?;
    Ok(Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_string()))
}

fn exit_code_for(err: &StoreError) -> u8 {
    match err {
        StoreError::Key(KeyError::Locked | KeyError::WrongPassphrase) | StoreError::Encrypted(_) => EXIT_LOCKED,
        // the Python CLI's "not configured" code
        StoreError::HomeMoved(_) | StoreError::Lock(LockError::HomeMoved(_)) => EXIT_NOT_CONFIGURED,
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

/// The Python `reparse --json` payload: the run's `ImportStats` fields plus `status`.
fn stats_json(stats: &ImportStats) -> Value {
    let streams: Map<String, Value> = stats
        .streams
        .iter()
        .map(|(stream, counts)| (stream.clone(), json!(counts)))
        .collect();
    let failures: Vec<Value> = stats
        .failures
        .iter()
        .map(|f| match &f.stream {
            Some(stream) => json!({"file": f.file, "stream": stream, "kind": f.kind, "error": f.error}),
            None => json!({"file": f.file, "kind": f.kind, "error": f.error}),
        })
        .collect();
    json!({
        "transport": stats.transport,
        "files_seen": stats.files_seen,
        "files_imported": stats.files_imported,
        "files_duplicate": stats.files_duplicate,
        "files_failed": stats.files_failed,
        "records_written": stats.records_written,
        "ignored": stats.ignored,
        "streams": streams,
        "dropped": stats.dropped,
        "failures": failures,
        "warnings": stats.warnings,
        "dates_assumed_utc": stats.dates_assumed_utc,
        "derived_days": stats.derived_days,
        "status": stats.status(),
    })
}

/// `reparse [--stream S]... [--force]`: replay decoding over the retained raw records. Exit 0 on ok,
/// 1 on partial/failed (some record failed to decode; unless `--force`, nothing was changed).
fn run_reparse(args: &Args, source: PassphraseSource<'_>) -> Result<(), (u8, String)> {
    let opened = store::open_for_write(db_of(args)?, "reparse", 10.0, source)
        .map_err(|e| (open_error_code(&e), e.to_string()))?;
    let streams = (!args.streams.is_empty()).then_some(args.streams.as_slice());
    let stats = sources::reparse_all(opened.conn(), streams, args.force)
        .map_err(|e| (import_exit_code(&e), e.to_string()))?;
    emit(args.json, stats_json(&stats), stats.summary_lines().join("\n"));
    if stats.status() == "ok" { Ok(()) } else { Err((1, String::new())) }
}

/// A leading `~` stands for `$HOME` (`~name` is left alone): the library's one reading, shared with the Python core.
fn expand_user(folder: &str) -> PathBuf {
    keys::expand_user(std::path::Path::new(folder))
}

/// `relay.json` in the folder of the resolved database, shared with the Python CLI.
fn relay_config() -> Option<PathBuf> {
    home::relay_config_path()
}

/// The usage error of a command that finds no relay anywhere.
fn no_relay_error(config: Option<&PathBuf>) -> (u8, String) {
    let shown = config.map_or_else(
        || format!("~/{}/{}", identity::DATA_DIR, home::RELAY_CONFIG_NAME),
        |p| p.display().to_string(),
    );
    (
        EXIT_USAGE,
        format!("usage: no relay folder: pass --relay <folder> or write {{\"folder\": ...}} to {shown}"),
    )
}

/// The one relay `--relay` names, for this run only; with `--remember` it becomes the whole list (one entry:
/// a new id, `serve` for a folder).
fn adhoc_relay(args: &Args) -> Result<Option<RelayConfig>, (u8, String)> {
    let Some(text) = args.relay.as_deref().filter(|r| !r.is_empty()) else {
        return Ok(None);
    };
    let chosen = RelayConfig::from_arg(text);
    if let RelayConfig::Lan(url) = &chosen {
        relay_cfg::check_lan_url(url).map_err(|rule| (EXIT_USAGE, format!("usage: {rule}")))?;
    }
    if args.remember {
        let path = relay_config().ok_or((1, "cannot remember the relay: HOME is not set".to_string()))?;
        if path.exists() && relay_cfg::read_list(&path).is_some_and(|entries| entries.len() > 1) {
            return Err((EXIT_USAGE, "usage: the relay list has more than one entry; use sync relay add".to_string()));
        }
        if let Some(moved) = disconect_core::home::moved_legacy_home(&path) {
            return Err((EXIT_NOT_CONFIGURED, moved.to_string()));
        }
        let serve = matches!(chosen, RelayConfig::Folder(_));
        let entry = RelayEntry { id: relay_cfg::new_id(), config: chosen.clone(), label: String::new(), serve };
        write_relay_list(&path, &[entry])?;
    }
    Ok(Some(chosen))
}

fn write_relay_list(path: &std::path::Path, entries: &[RelayEntry]) -> Result<(), (u8, String)> {
    relay_cfg::write_list(path, entries).map_err(|e| (1, format!("cannot write the relay config: {}", e.kind())))
}

/// The list in `relay.json` (a usage error when there is none).
fn relay_list() -> Result<Vec<RelayEntry>, (u8, String)> {
    let config = relay_config();
    config
        .as_ref()
        .filter(|p| p.exists())
        .and_then(|p| relay_cfg::read_list(p))
        .filter(|entries| !entries.is_empty())
        .ok_or_else(|| no_relay_error(config.as_ref()))
}

/// The folder a command that serves one uses: `--relay <folder>`, else the entry of `relay.json` that serves.
fn serve_folder(args: &Args, command: &str) -> Result<PathBuf, (u8, String)> {
    let not_a_folder = || (EXIT_USAGE, format!("usage: {command} serves a folder, not an http:// address"));
    let config = match adhoc_relay(args)? {
        Some(config) => config,
        None => {
            let entries = relay_list()?;
            match relay_cfg::serve_entry(&entries) {
                Some(entry) => entry.config.clone(),
                None => return Err(not_a_folder()),
            }
        }
    };
    match config {
        RelayConfig::Folder(folder) => Ok(expand_user(&folder)),
        RelayConfig::Lan(_) => Err(not_a_folder()),
    }
}

fn relay_for(config: &RelayConfig, master: &[u8]) -> Result<Box<dyn Relay>, (u8, String)> {
    match relay_cfg::open(config, master) {
        Ok(relay) => Ok(relay),
        Err(rule) => Err((EXIT_USAGE, format!("usage: {rule}"))),
    }
}

fn sync_exit(error: &SyncError) -> u8 {
    match error {
        SyncError::Db(_) | SyncError::Writer(WriterError::Db(_)) | SyncError::WriteFailed(_) => EXIT_DATABASE,
        SyncError::Source(SourceError::Db(_)) => EXIT_DATABASE,
        SyncError::Relay(RelayError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => EXIT_USAGE,
        SyncError::Relay(RelayError::Unreachable | RelayError::Unverified | RelayError::Unauthorized { .. }) => EXIT_UNREACHABLE,
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
        "records_repaired": result.records_repaired,
        "records_kept": result.records_kept,
        "gaps": gaps_json(&result.gaps),
        "status": result.status,
    })
}

fn status_text(report: &StatusReport) -> String {
    let count = |key: &str| report.bundles.get(key).copied().unwrap_or(0);
    format!(
        "relay: pushed {}, pulled {}, rejected {}; records unsent {}, seen {}; conflicts {}; gaps {}; chains {}; last push {}, last pull {}",
        count("pushed_applied"),
        count("pulled_applied"),
        count("pulled_rejected"),
        report.records_unsent,
        report.records_seen,
        report.conflicts,
        report.gaps.len(),
        report.chains.len(),
        report.last_pushed_at.as_deref().unwrap_or("never"),
        report.last_pulled_at.as_deref().unwrap_or("never")
    )
}

/// `sync push|pull|status|forget`: the blind relay (`docs/relay-protocol.md`). Needs an encrypted
/// store for push and pull: the relay account and keys derive from the master key.
fn run_sync(args: &Args, source: PassphraseSource<'_>) -> Result<(), (u8, String)> {
    let action = args
        .sync_action
        .as_deref()
        .ok_or((EXIT_USAGE, "sync needs an action: push | pull | status | forget | relay".to_string()))?;
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
            let payload = sync::status_value(&report);
            emit(args.json, payload, status_text(&report));
            Ok(())
        }
        "relay" => run_relay_list(args),
        _ => {
            let master = store::resolve_master(db_of(args)?, source).map_err(open_err)?;
            let Some(master) = master else {
                return Err((
                    EXIT_LOCKED,
                    format!("the relay needs an encrypted store: run '{} key init' first", identity::COMMAND),
                ));
            };
            let adhoc = adhoc_relay(args)?;
            if let Some(config) = adhoc {
                // `--relay`: this one relay for this run, as ever
                let relay = relay_for(&config, master.as_slice())?;
                let opened = store::open_for_write_with(db_of(args)?, "sync", 10.0, Some(&master)).map_err(open_err)?;
                return if action == "push" {
                    let result = sync::push(opened.conn(), &*master, &*relay).map_err(failed)?;
                    print_push(args, &result, None);
                    Ok(())
                } else {
                    let result = sync::pull(opened.conn(), &*master, &*relay).map_err(failed)?;
                    print_pull(args, &result, None);
                    if result.status == "ok" { Ok(()) } else { Err((1, String::new())) }
                };
            }
            // no `--relay`: every relay of the list. A list of one raises its relay's failure as the error
            // (the single-relay behaviour); a longer list names each site's failure and ends partial.
            let entries = relay_list()?;
            let specs: Vec<sync::SiteSpec> = entries.iter().map(sync::SiteSpec::from_entry).collect();
            let strict = specs.len() == 1;
            if let [only] = specs.as_slice()
                && let RelayConfig::Lan(url) = &only.config
            {
                relay_cfg::check_lan_url(url).map_err(|rule| (EXIT_USAGE, format!("usage: {rule}")))?;
            }
            let (sites, mut reports) = sync::open_sites(&specs, master.as_slice());
            let opened = store::open_for_write_with(db_of(args)?, "sync", 10.0, Some(&master)).map_err(open_err)?;
            let shown = |reports: &[sync::SiteReport]| (!strict || reports.iter().any(|r| r.error.is_some())).then(|| reports.to_vec());
            if action == "push" {
                let result = if strict {
                    sync::push_strict(opened.conn(), master.as_slice(), &sites, &mut reports)
                } else {
                    sync::push_all(opened.conn(), master.as_slice(), &sites, &mut reports)
                }
                .map_err(failed)?;
                let sites_shown = shown(&reports);
                print_push(args, &result, sites_shown.as_deref());
                return if result.partial || reports.iter().any(|r| r.error.is_some()) { Err((1, String::new())) } else { Ok(()) };
            }
            let result = if strict {
                sync::pull_strict(opened.conn(), master.as_slice(), &sites, &mut reports, false)
            } else {
                sync::pull_all(opened.conn(), master.as_slice(), &sites, &mut reports, false)
            }
            .map_err(failed)?;
            let sites_shown = shown(&reports);
            print_pull(args, &result, sites_shown.as_deref());
            if result.status == "ok" { Ok(()) } else { Err((1, String::new())) }
        }
    }
}

/// One line per site: what the run did there and, when it failed, the reason word.
fn site_line(report: &sync::SiteReport) -> String {
    let label = if report.label.is_empty() { String::new() } else { format!(" {}", report.label) };
    let mut line = format!(
        "  site {}{label} {}: pushed {}, healed {}, behind {}, pulled {}, rejected {}",
        report.id, report.kind, report.pushed, report.healed, report.behind, report.pulled, report.rejected
    );
    if let Some(error) = report.error {
        line.push_str(&format!(", error {error}"));
    }
    line
}

/// Print a payload and its text, plus the sites (a line each; `"sites"` in the JSON) when there are some to show.
fn emit_with_sites(args: &Args, mut payload: Value, text: String, sites: Option<&[sync::SiteReport]>) {
    let mut text = text;
    if let Some(sites) = sites {
        for report in sites {
            text.push('\n');
            text.push_str(&site_line(report));
        }
        if let Some(object) = payload.as_object_mut() {
            object.insert("sites".into(), Value::Array(sites.iter().map(sync::SiteReport::value).collect()));
        }
    }
    emit(args.json, payload, text);
}

fn print_push(args: &Args, result: &sync::PushResult, sites: Option<&[sync::SiteReport]>) {
    emit_with_sites(
        args,
        json!({"bundles": result.bundles, "records": result.records, "ranges": result.ranges}),
        format!(
            "pushed {} bundle(s): {} record(s), {} range(s)",
            result.bundles.len(),
            result.records,
            result.ranges
        ),
        sites,
    );
}

fn print_pull(args: &Args, result: &PullResult, sites: Option<&[sync::SiteReport]>) {
    emit_with_sites(
        args,
        pull_json(result),
        format!(
            "pulled {} bundle(s): {} new, {} duplicate, {} invalid, {} conflict(s), {} new range(s); rejected {}; gaps {}; repaired {}; kept for a later decoder {}",
            result.applied.len(),
            result.records_new,
            result.records_duplicate,
            result.records_invalid,
            result.conflicts,
            result.ranges_new,
            result.rejected.len(),
            result.gaps.len(),
            result.records_repaired,
            result.records_kept
        ),
        sites,
    );
}

/// Who a folder is for the duplicate check: its (device, inode) when it exists, else the expanded path.
fn folder_key(folder: &str) -> String {
    let path = expand_user(folder);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(&path)
            && meta.is_dir()
        {
            return format!("{}:{}", meta.dev(), meta.ino());
        }
    }
    // the Python CLI's fallback is `str(Path)`: `~/x/` and `/h/x` are one key there too
    path.components().collect::<PathBuf>().to_string_lossy().into_owned()
}

/// Whether two configurations name the same relay: folders by [`folder_key`], addresses by their parsed base.
fn same_relay(a: &RelayConfig, b: &RelayConfig) -> bool {
    match (a, b) {
        (RelayConfig::Folder(x), RelayConfig::Folder(y)) => folder_key(x) == folder_key(y),
        (RelayConfig::Lan(x), RelayConfig::Lan(y)) => relay_cfg::lan_base_url(x) == relay_cfg::lan_base_url(y),
        _ => false,
    }
}

fn entry_json(entry: &RelayEntry) -> Value {
    let (key, place) = match &entry.config {
        RelayConfig::Folder(folder) => ("path", folder),
        RelayConfig::Lan(url) => ("url", url),
    };
    let kind = if key == "path" { "folder" } else { "lan" };
    let mut object = json!({"id": entry.id, "kind": kind, "label": entry.label, "serve": entry.serve});
    if let Some(map) = object.as_object_mut() {
        map.insert(key.into(), json!(place));
    }
    object
}

/// `sync relay add <folder|url> [--label <text>] [--serve]`, `sync relay remove <id>`, `sync relay list`: the
/// only commands (with `--remember`) that rewrite `relay.json`. They need no key and no store.
fn run_relay_list(args: &Args) -> Result<(), (u8, String)> {
    let action = args
        .relay_action
        .as_deref()
        .ok_or((EXIT_USAGE, "usage: sync relay needs an action: add <folder|url> | remove <id> | list".to_string()))?;
    let path = relay_config().ok_or((1, "HOME is not set".to_string()))?;
    let mut entries: Vec<RelayEntry> = if path.exists() {
        relay_cfg::read_list(&path).ok_or((EXIT_USAGE, "usage: relay.json is not a relay list this build reads; fix or remove it".to_string()))?
    } else {
        Vec::new()
    };
    match action {
        "list" => {
            let lines: Vec<String> = entries
                .iter()
                .map(|e| {
                    let (kind, place) = match &e.config {
                        RelayConfig::Folder(folder) => ("folder", folder),
                        RelayConfig::Lan(url) => ("lan", url),
                    };
                    let label = if e.label.is_empty() { "-" } else { e.label.as_str() };
                    format!("{}  {kind}  {place}  {label}{}", e.id, if e.serve { "  serves" } else { "" })
                })
                .collect();
            if lines.is_empty() && !args.json {
                return Ok(()); // no relay: nothing to print
            }
            emit(args.json, json!({"relays": entries.iter().map(entry_json).collect::<Vec<_>>()}), lines.join("\n"));
            Ok(())
        }
        "add" => {
            let text = args.relay_arg.as_deref().ok_or((EXIT_USAGE, "usage: sync relay add needs a folder or an http:// address".to_string()))?;
            let config = RelayConfig::from_arg(text);
            if let RelayConfig::Lan(url) = &config {
                relay_cfg::check_lan_url(url).map_err(|rule| (EXIT_USAGE, format!("usage: {rule}")))?;
                if args.serve_flag {
                    return Err((EXIT_USAGE, "usage: only a folder can serve".to_string()));
                }
            }
            if args.serve_flag && entries.iter().any(|e| e.serve) {
                return Err((EXIT_USAGE, "usage: only one relay can serve".to_string()));
            }
            if entries.iter().any(|e| same_relay(&e.config, &config)) {
                return Err((EXIT_USAGE, "usage: that relay is already in the list".to_string()));
            }
            let mut id = relay_cfg::new_id();
            while entries.iter().any(|e| e.id == id) {
                id = relay_cfg::new_id();
            }
            entries.push(RelayEntry { id: id.clone(), config, label: args.label.clone().unwrap_or_default(), serve: args.serve_flag });
            if let Some(moved) = disconect_core::home::moved_legacy_home(&path) {
                return Err((EXIT_NOT_CONFIGURED, moved.to_string()));
            }
            write_relay_list(&path, &entries)?;
            emit(args.json, json!({"added": id}), format!("added relay {id}"));
            Ok(())
        }
        "remove" => {
            let id = args.relay_arg.as_deref().ok_or((EXIT_USAGE, "usage: sync relay remove needs an id".to_string()))?;
            let Some(at) = entries.iter().position(|e| e.id == id) else {
                return Err((EXIT_USAGE, "usage: no relay with that id".to_string()));
            };
            entries.remove(at);
            if let Some(moved) = disconect_core::home::moved_legacy_home(&path) {
                return Err((EXIT_NOT_CONFIGURED, moved.to_string()));
            }
            if entries.is_empty() {
                // the last entry: no file at all (an empty list reads as no relay either way)
                std::fs::remove_file(&path).map_err(|e| (1, format!("cannot write the relay config: {}", e.kind())))?;
            } else {
                write_relay_list(&path, &entries)?;
            }
            emit(args.json, json!({"removed": id}), format!("removed relay {id}"));
            Ok(())
        }
        _ => Err((EXIT_USAGE, "usage: sync relay needs an action: add <folder|url> | remove <id> | list".to_string())),
    }
}

/// `relay-serve`: serve a relay folder over HTTP on the LAN until the process is killed. The master
/// key only derives the token key and the account name; no bundle is ever opened.
fn run_relay_serve(args: &Args, source: PassphraseSource<'_>) -> Result<(), (u8, String)> {
    if args.remember || args.sync_action.is_some() || args.import_path.is_some() {
        return Err((EXIT_USAGE, "usage: relay-serve takes --db, --passphrase-file, --relay <folder> and --listen".into()));
    }
    let master = store::resolve_master(db_of(args)?, source).map_err(|e| (open_error_code(&e), e.to_string()))?;
    let Some(master) = master else {
        return Err((
            EXIT_LOCKED,
            format!("the relay needs an encrypted store: run '{} key init' first", identity::COMMAND),
        ));
    };
    let folder = serve_folder(args, "relay-serve")?;
    let listen = args.listen.as_deref().unwrap_or("127.0.0.1:0");
    // method and status only: no path, no object name, no address of a peer
    let log: disconect_core::relay::lan_server::Logger = std::sync::Arc::new(|method, status| eprintln!("{method} {status}"));
    let server = LanServer::start(listen, folder, master.as_slice(), log).map_err(|m| (1, m))?;
    println!("listening http://{}", server.local_addr());
    server.wait();
    Ok(())
}

/// The refusal text of a pairing step. Never the offer text, a code or a key.
fn pair_failure(error: &PairError) -> (u8, String) {
    let code = match error {
        PairError::Precondition(_) | PairError::BadOffer(_) => EXIT_USAGE,
        PairError::Network => EXIT_UNREACHABLE,
        _ => 1,
    };
    (code, error.to_string())
}

/// `pair offer`: `relay-serve` plus one offer slot (Bet 12-E).
fn run_pair_offer(args: &Args, source: PassphraseSource<'_>) -> Result<(), (u8, String)> {
    if args.remember || args.sync_action.is_some() || args.import_path.is_some() || args.relay_file.is_some() || args.i_saw_paired {
        return Err((EXIT_USAGE, "usage: pair offer takes --db, --passphrase-file, --relay <folder> and --listen".into()));
    }
    let listen = args.listen.as_deref().ok_or((EXIT_USAGE, "usage: pair offer needs --listen <addr:port>".to_string()))?;
    let port = listen.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok());
    if port.is_none_or(|p| p == 0) {
        return Err((EXIT_USAGE, "usage: --listen needs an explicit port (not 0): the URL becomes the joiner's relay".into()));
    }
    let host = listen.rsplit_once(':').map_or("", |(h, _)| h).trim_matches(['[', ']']);
    if host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_unspecified()) {
        return Err((EXIT_USAGE, "pair offer needs a concrete address (the one other devices reach), not 0.0.0.0".into()));
    }
    let db = db_of(args)?;
    let master = store::resolve_master(db, source).map_err(|e| (open_error_code(&e), e.to_string()))?;
    let Some(master) = master else {
        return Err((
            EXIT_LOCKED,
            format!("the relay needs an encrypted store: run '{} key init' first", identity::COMMAND),
        ));
    };
    let folder = serve_folder(args, "pair offer")?;
    let key_file_bytes = std::fs::read(keys::key_path_for(db)).map_err(|_| (1, "cannot read the key file".to_string()))?;
    // the joiner bootstraps from what was last pushed: push first, then release the write lock
    {
        let opened = store::open_for_write_with(db, "pair", 10.0, Some(&master)).map_err(|e| (open_error_code(&e), e.to_string()))?;
        let relay = FolderRelay::creating_root(folder.clone());
        sync::push(opened.conn(), &*master, &relay).map_err(|e| (sync_exit(&e), e.to_string()))?;
    }
    let log: disconect_core::relay::lan_server::Logger = std::sync::Arc::new(|method, status| eprintln!("{method} {status}"));
    let (server, offer, handle) =
        LanServer::start_with_offer(listen, folder, master.as_slice(), log, Limits::default()).map_err(|m| (1, m))?;
    println!("{offer}");
    eprintln!("Waiting for a device\u{2026}");
    // the offer ends one way or another; the relay keeps serving either way (Ctrl-C to stop)
    let outcome = offer_session(&handle, &master, &key_file_bytes);
    if let Err(message) = outcome {
        eprintln!("{message}");
        eprintln!("offer ended; serving the relay (Ctrl-C to stop)");
    }
    server.wait();
    Ok(())
}

/// The offer's life: wait for a joiner, show the code, read the digits, release, wait for the fetch.
/// `Err` is what to tell the user when the offer ended without a delivery.
fn offer_session(handle: &PairHandle, master: &[u8; 32], key_file_bytes: &[u8]) -> Result<(), String> {
    if !handle.wait_joined(std::time::Duration::from_secs(EXPIRY_S + 5)) {
        return Err(match handle.state() {
            PairState::Aborted => "another device answered — start over".to_string(),
            _ => "the offer expired".to_string(),
        });
    }
    // the offerer never shows its own code (ADR 0011 v2; the handle does not even return it): a user who
    // typed a visible offerer code into a planted offer's victim would release the key with no guess at all
    eprintln!("A device answered.");
    eprintln!("Type the code shown on the other device:");
    let mut line = Zeroizing::new(String::new());
    let _ = std::io::stdin().read_line(&mut line);
    match handle.release(line.trim(), master, key_file_bytes) {
        Ok(()) => {}
        Err(PairError::CodesDiffer) => return Err("the codes differ — aborted".to_string()),
        Err(e) => return Err(e.to_string()),
    }
    eprintln!("released — waiting for the device to fetch");
    let left = handle.expires_at().saturating_sub(disconect_core::relay::lan::wall_clock());
    if handle.wait_delivered(std::time::Duration::from_secs(left)) {
        eprintln!("Paired; serving the relay (Ctrl-C to stop)");
    } else {
        eprintln!("the device never fetched the payload; serving the relay (Ctrl-C to stop)");
    }
    Ok(())
}

/// `pair join`: the offer text comes from stdin, never argv.
fn run_pair_join(args: &Args) -> Result<(), (u8, String)> {
    if args.remember || args.sync_action.is_some() || args.import_path.is_some() || args.relay.is_some() || args.listen.is_some() {
        return Err((EXIT_USAGE, "usage: pair join takes --db <new store> [--relay-file <path>] [--i-saw-paired]; the offer text comes on stdin".into()));
    }
    let db = db_of(args)?;
    let mut text = Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut text).map_err(|_| (1, "cannot read the offer text from stdin".to_string()))?;
    let text = Zeroizing::new(text.trim().to_string());
    let offer = disconect_core::pair::Offer::parse(&text).map_err(|e| pair_failure(&e))?;
    let relay_file = args
        .relay_file
        .clone()
        .unwrap_or_else(|| home::relay_config_beside(db));
    pair_client::check_landing_site(db, &relay_file, &offer.url).map_err(|e| pair_failure(&e))?;
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let joined = pair_client::join(
        &text,
        &mut |code| eprintln!("Code on this device: {code} — type it into the offerer"),
        &cancel,
    )
    .map_err(|e| pair_failure(&e))?;
    if !args.i_saw_paired && !confirmed(&offer) {
        return Err((1, "Not paired; nothing was written. If the other device says Paired, start a new offer there; if it never showed a device answering, cancel its offer.".into()));
    }
    let pulled = pair_client::land(&joined, db, &relay_file).map_err(|e| pair_failure(&e))?;
    println!("{}", json!({"paired": true, "pulled": pull_json(&pulled)}));
    if pulled.status == "ok" { Ok(()) } else { Err((1, String::new())) }
}

/// The human check the phone has as `pair.land` (12-F): the offerer released, and the landing waits for the user
/// to say the other device shows the pairing as done. Pasted text is exactly a planted offer's channel, and a
/// planted offerer releases a master of its own, so without this step the CLI adopted it (12-G N12). The question
/// names the relay host (what the store would trust) and goes to the terminal: stdin when stdin is a terminal
/// (stray input typed during the wait is flushed first), else `/dev/tty` (the offer came on a pipe); with no
/// terminal the answer is no. `y`/`yes` lands; a blank line asks again; anything else, EOF, a read error or the
/// offer's expiry (the master would otherwise sit in memory for ever) is a no. `DISCONECT_ASK_ON_STDIN=1` reads
/// from stdin whatever it is (test harnesses).
fn confirmed(offer: &disconect_core::pair::Offer) -> bool {
    use std::io::{BufRead, IsTerminal, Write};
    let on_stdin = std::env::var_os("DISCONECT_ASK_ON_STDIN").is_some_and(|v| v == "1");
    let (mut out, input): (Box<dyn Write>, Box<dyn BufRead + Send>) = if on_stdin || std::io::stdin().is_terminal() {
        if !on_stdin {
            flush_terminal_input(0);
        }
        (Box::new(std::io::stderr()), Box::new(std::io::BufReader::new(std::io::stdin())))
    } else {
        match (std::fs::OpenOptions::new().write(true).open("/dev/tty"), std::fs::File::open("/dev/tty")) {
            (Ok(writer), Ok(reader)) => {
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    flush_terminal_input(reader.as_raw_fd());
                }
                (Box::new(writer), Box::new(std::io::BufReader::new(reader)))
            }
            _ => {
                eprintln!("No terminal to ask on: the offer came on a pipe and /dev/tty is not open. Pass --i-saw-paired once the other device shows the pairing as done.");
                return false;
            }
        }
    };
    let host = offer.url.trim_start_matches("http://").to_string();
    let (sender, lines) = std::sync::mpsc::channel::<Option<String>>();
    std::thread::spawn(move || {
        let mut input = input;
        loop {
            let mut line = String::new();
            match input.read_line(&mut line) {
                Ok(0) | Err(_) => {
                    let _ = sender.send(None);
                    return;
                }
                Ok(_) => {
                    if sender.send(Some(line)).is_err() {
                        return;
                    }
                }
            }
        }
    });
    loop {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let left = std::time::Duration::from_secs(offer.exp.saturating_sub(now));
        if left.is_zero() {
            return false;
        }
        let _ = writeln!(out, "This store would use the relay at {host}.");
        let _ = writeln!(out, "Did the other device say Paired? Type y to keep this pairing, anything else to drop it [y/N]");
        let _ = out.flush();
        match lines.recv_timeout(left) {
            Ok(Some(line)) => match line.trim().to_ascii_lowercase().as_str() {
                "" => continue,
                "y" | "yes" => return true,
                _ => return false,
            },
            Ok(None) | Err(_) => return false,
        }
    }
}

/// Drop whatever was typed on the terminal before the question (an extra Enter after the paste, digits typed
/// into the wrong window during the wait), so it cannot be read as the answer.
#[cfg(unix)]
fn flush_terminal_input(fd: i32) {
    // SAFETY: tcflush on a file descriptor this process holds; a failure (not a terminal) is ignored
    unsafe {
        libc::tcflush(fd, libc::TCIFLUSH);
    }
}

#[cfg(not(unix))]
fn flush_terminal_input(_fd: i32) {}

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
        "reparse" => run_reparse(args, source),
        "sync" => run_sync(args, source),
        "relay-serve" => run_relay_serve(args, source),
        "pair" => match args.pair_action.as_deref() {
            Some("offer") => run_pair_offer(args, source),
            Some("join") => run_pair_join(args),
            _ => Err((EXIT_USAGE, "pair needs an action: offer | join".to_string())),
        },
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
        || args.listen.is_some()
        || args.remember
        || !args.streams.is_empty()
        || args.force;
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

/// `mcp`: scrub the secret variables (and, in a release build, the test switches) before any thread exists,
/// then unlock and speak MCP on stdio.
fn run_mcp(args: &Args) -> ExitCode {
    let unexpected = args.json
        || args.import_path.is_some()
        || args.transport.is_some()
        || args.sync_action.is_some()
        || args.relay.is_some()
        || args.listen.is_some()
        || args.remember
        || !args.streams.is_empty()
        || args.force;
    if unexpected {
        eprintln!("error: mcp takes only --db <path> and --passphrase-file <file>");
        return ExitCode::from(EXIT_USAGE);
    }
    let passphrase = match args.passphrase_file.as_ref().map(read_passphrase) {
        Some(Ok(phrase)) => Some(phrase),
        Some(Err(message)) => {
            eprintln!("error: {message}");
            return ExitCode::from(EXIT_USAGE);
        }
        None => None,
    };
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
    if keys::scrub_env_secrets() {
        eprintln!("{} is ignored by mcp and was removed from the environment", keys::PASSPHRASE_ENV);
    }
    if !cfg!(debug_assertions) {
        mcp::scrub_test_switches();
    }
    ExitCode::from(u8::try_from(mcp::run(mcp::Options { db, passphrase })).unwrap_or(1))
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
    if args.command.as_deref() == Some("mcp") {
        return run_mcp(&args);
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
