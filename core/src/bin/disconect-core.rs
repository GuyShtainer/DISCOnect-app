// SPDX-License-Identifier: AGPL-3.0-or-later
//! `disconect-core --db <path> [--passphrase-file <file>] status --json | init | import <path> [--transport T]`

use std::path::PathBuf;
use std::process::ExitCode;

use disconect_core::keys::{KeyError, PassphraseSource};
use disconect_core::sources::{self, SourceError, TRANSPORTS};
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
    db: PathBuf,
    passphrase_file: Option<PathBuf>,
    command: String,
    json: bool,
    import_path: Option<PathBuf>,
    transport: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let (mut db, mut pass, mut command, mut json) = (None, None, None, false);
    let (mut import_path, mut transport) = (None, None);
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
            "status" | "init" | "import" if command.is_none() => command = Some(arg),
            _ if command.as_deref() == Some("import") && import_path.is_none() && !arg.starts_with("--") => {
                import_path = Some(PathBuf::from(arg));
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    Ok(Args {
        db: db.ok_or("--db <path> is required")?,
        passphrase_file: pass,
        command: command.ok_or("a command is required: status --json | init | import <path>")?,
        json,
        import_path,
        transport,
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
        _ => EXIT_DATABASE,
    }
}

/// Import a path; the summary is counts only. Exit 0 on ok, 1 on partial/failed.
fn run_import(args: &Args, source: PassphraseSource<'_>) -> Result<(), (u8, String)> {
    let path = args.import_path.as_ref().ok_or((EXIT_USAGE, "import needs a path".to_string()))?;
    let opened = store::open_for_write(&args.db, "import", 10.0, source).map_err(|e| {
        let code = match &e {
            StoreError::Lock(LockError::Busy { .. }) => EXIT_BUSY,
            StoreError::SchemaTooNew { .. } => EXIT_SCHEMA,
            StoreError::Db(_) => EXIT_DATABASE,
            other => exit_code_for(other),
        };
        (code, e.to_string())
    })?;
    let stats = sources::import_path(opened.conn(), path, args.transport.as_deref())
        .map_err(|e| (import_exit_code(&e), e.to_string()))?;
    for line in stats.summary_lines() {
        println!("{line}");
    }
    if stats.status() == "ok" { Ok(()) } else { Err((1, String::new())) }
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
    match args.command.as_str() {
        "import" => run_import(args, source),
        "status" if args.json => {
            let value = status(&args.db, source).map_err(fail)?;
            println!("{value}");
            Ok(())
        }
        "status" => Err((1, "status requires --json".to_string())),
        _ => store::open_for_write(&args.db, "init", 10.0, source).map(|_| ()).map_err(fail),
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(m) => {
            eprintln!("error: {m}");
            return ExitCode::from(1);
        }
    };
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
