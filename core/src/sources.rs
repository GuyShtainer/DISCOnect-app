// SPDX-License-Identifier: AGPL-3.0-or-later
//! Turn a path into an import: a `.fit` file, a folder of them, a zip of them, or a Connect account
//! export (the twin of `ingest/sources.py`; the export's JSON half lives in `export.rs`).
//!
//! Two passes over the FIT bytes: first collect every UTC offset the files state, so local dates
//! resolve consistently regardless of file order; then decode and write.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, params, params_from_iter};

use crate::canon::{self, Value};
use crate::clock::ClockOffsets;
use crate::export::{self, DecodeError, Step};
use crate::fit::{self, FitDecodeError};
use crate::model::Decoded;
use crate::redact::{mask_label, redact_text};
use crate::writer::{Failure, ImportStats, WriteOutcome, Writer, WriterError, fit_summary, json_summary};

pub const TRANSPORT_DROP: &str = "drop";
pub const TRANSPORT_CONNECT_EXPORT: &str = "connect_export";
/// The transports `--transport` accepts.
pub const TRANSPORTS: [&str; 5] = ["connect_export", "usb", "gadgetbridge", "ciq", "drop"];

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("no such file or folder: {0}")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("{0}")]
    Writer(#[from] WriterError),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    /// An error the oracle raises as an uncaught Python exception (`BadZipFile`, `OverflowError`,
    /// ...): the run is booked as failed and the import aborts. The text is `Type: message`.
    #[error("{0}")]
    Abort(String),
}

/// The folder an extracted Connect account export keeps its data in.
pub const EXPORT_ROOT: &str = "DI_CONNECT";

/// `connect_export.looks_like_export`: true for an extracted export root, its `DI_CONNECT`
/// folder, or the outer zip (any entry whose first component is `DI_CONNECT` or that sits inside
/// a `DI_CONNECT/` folder).
pub fn looks_like_export(path: &Path) -> bool {
    if path.is_dir() {
        let named = path.file_name().is_some_and(|n| n == EXPORT_ROOT);
        return named || path.join(EXPORT_ROOT).is_dir();
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if path.is_file() && suffix_lower(&name) == ".zip" {
        let Ok(file) = fs::File::open(path) else {
            return false;
        };
        let Ok(mut archive) = zip::ZipArchive::new(file) else {
            return false;
        };
        let inside = format!("/{EXPORT_ROOT}/");
        return (0..archive.len()).any(|i| {
            archive.by_index_raw(i).is_ok_and(|entry| {
                let entry_name = entry.name();
                entry_name.split('/').next() == Some(EXPORT_ROOT) || entry_name.contains(&inside)
            })
        });
    }
    false
}

/// Python's `PurePath.suffix`: the text from the last dot, unless the dot is the first or last character.
pub(crate) fn suffix_lower(name: &str) -> String {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => name[i..].to_lowercase(),
        _ => String::new(),
    }
}

/// Sort key reproducing Python's `sorted(Path)` order: component by component, not by the joined string.
pub(crate) fn components_key(relative: &Path) -> Vec<Vec<u8>> {
    relative.components().map(|c| c.as_os_str().as_encoded_bytes().to_vec()).collect()
}

/// Every regular file under `root` (symlinked files included, symlinked directories not entered,
/// as `Path.rglob("*")` does), as paths relative to `root`.
pub(crate) fn walk_files(root: &Path, relative: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        let rel = relative.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            walk_files(root, &rel, out)?;
        } else if fs::metadata(root.join(&rel)).map(|m| m.is_file()).unwrap_or(false) {
            out.push(rel);
        }
    }
    Ok(())
}

fn le16(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize)
}

fn le32(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize)
}

/// The start of the end-of-central-directory record (the last one in the file).
fn end_record(raw: &[u8]) -> Option<usize> {
    let floor = raw.len().saturating_sub(22 + 65_535);
    (floor..=raw.len().checked_sub(22)?)
        .rev()
        .find(|&i| raw[i..i + 4] == [0x50, 0x4b, 0x05, 0x06])
}

/// Entry count the central directory states (`None` for zip64 sentinels or no directory).
fn directory_entry_count(raw: &[u8]) -> Option<usize> {
    let count = le16(raw, end_record(raw)? + 10)?;
    (count != 0xFFFF).then_some(count)
}

/// `(name, bytes)` for every central-directory entry, same-named ones included, stable-sorted by
/// name. Stored and deflated entries only (what the zip crate is built with here); no zip64.
fn duplicate_aware_entries(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>, SourceError> {
    let bad = || SourceError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "unreadable zip directory"));
    let end = end_record(raw).ok_or_else(bad)?;
    let count = le16(raw, end + 10).ok_or_else(bad)?;
    let mut at = le32(raw, end + 16).ok_or_else(bad)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if raw.get(at..at + 4) != Some(&[0x50, 0x4b, 0x01, 0x02]) {
            return Err(bad());
        }
        let flags = le16(raw, at + 8).ok_or_else(bad)?;
        let method = le16(raw, at + 10).ok_or_else(bad)?;
        let packed = le32(raw, at + 20).ok_or_else(bad)?;
        let name_len = le16(raw, at + 28).ok_or_else(bad)?;
        let extra_len = le16(raw, at + 30).ok_or_else(bad)?;
        let comment_len = le16(raw, at + 32).ok_or_else(bad)?;
        let local = le32(raw, at + 42).ok_or_else(bad)?;
        let name = String::from_utf8_lossy(raw.get(at + 46..at + 46 + name_len).ok_or_else(bad)?).into_owned();
        at += 46 + name_len + extra_len + comment_len;
        if flags & 1 != 0 || raw.get(local..local + 4) != Some(&[0x50, 0x4b, 0x03, 0x04]) {
            return Err(bad());
        }
        let data_at = local + 30 + le16(raw, local + 26).ok_or_else(bad)? + le16(raw, local + 28).ok_or_else(bad)?;
        let packed_bytes = raw.get(data_at..data_at + packed).ok_or_else(bad)?;
        let mut bytes = Vec::new();
        match method {
            0 => bytes.extend_from_slice(packed_bytes),
            8 => {
                flate2::read::DeflateDecoder::new(packed_bytes).read_to_end(&mut bytes)?;
            }
            _ => return Err(bad()),
        }
        entries.push((name, bytes));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

/// `(label, bytes)` for every `.fit` member of a zip held in memory, in the Python order
/// (`sorted(infolist(), key=filename)`, stable). Labels are masked names.
pub fn zip_fit_members(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>, SourceError> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(raw))?;
    // The zip crate keys entries by name, so of two same-named entries it keeps one; the
    // oracle imports both. When the directory states more entries than the crate kept, read
    // the directory directly.
    if directory_entry_count(raw).is_some_and(|stated| stated > archive.len()) {
        let mut out = Vec::new();
        for (entry_name, bytes) in duplicate_aware_entries(raw)? {
            if entry_name.ends_with('/') || !entry_name.to_lowercase().ends_with(".fit") {
                continue;
            }
            out.push((mask_label(&entry_name), bytes));
        }
        return Ok(out);
    }
    // `sorted(infolist(), key=filename)` is stable, so equal names would keep archive order.
    let mut entries: Vec<(String, usize)> = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        entries.push((archive.by_index_raw(index)?.name().to_string(), index));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    for (entry_name, index) in entries {
        if entry_name.ends_with('/') || !entry_name.to_lowercase().ends_with(".fit") {
            continue;
        }
        let mut entry = archive.by_index(index)?;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        out.push((mask_label(&entry_name), bytes));
    }
    Ok(out)
}

/// `(label, bytes)` for every `.fit` under `path` (file, folder or zip), in the Python order.
/// Labels are masked relative names: never a table value, only the run's failure report.
pub fn iter_fit_files(path: &Path) -> Result<Vec<(String, Vec<u8>)>, SourceError> {
    let is_file = path.is_file();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if is_file && suffix_lower(&name) == ".zip" {
        return zip_fit_members(&fs::read(path)?);
    }
    if is_file {
        return Ok(vec![(mask_label(&name), fs::read(path)?)]);
    }
    let mut files = Vec::new();
    walk_files(path, Path::new(""), &mut files)?;
    files.retain(|rel| rel.file_name().is_some_and(|n| suffix_lower(&n.to_string_lossy()) == ".fit"));
    files.sort_by_key(|rel| components_key(rel));
    let mut out = Vec::with_capacity(files.len());
    for rel in files {
        out.push((mask_label(&rel.to_string_lossy()), fs::read(path.join(&rel))?));
    }
    Ok(out)
}

/// `ProgressCallback`: `progress(done, total_or_None, note)`. The FIT phase reports `(done, total,
/// outcome)` after each file, where `outcome` is what `write_fit` returned (`imported`, `duplicate` or
/// `failed`: the oracle's `_import_fit_batch` names it `stream`, but it is the status constant); an
/// export's JSON phase restarts `done` at 0 and reports `(done, None, stream)` after each imported file.
/// Never a file name or path.
pub type Progress<'a> = &'a mut dyn FnMut(u64, Option<u64>, &str);

/// Lend a progress callback to one phase without giving it away.
pub fn reborrow<'b>(progress: &'b mut Option<Progress<'_>>) -> Option<Progress<'b>> {
    match progress {
        Some(inner) => Some(&mut **inner),
        None => None,
    }
}

/// The text `write_fit` returns in the oracle (`IMPORTED`, `DUPLICATE`, `FAILED`, `REPARSED`).
fn outcome_text(outcome: WriteOutcome) -> &'static str {
    match outcome {
        WriteOutcome::Imported => "imported",
        WriteOutcome::Duplicate => "duplicate",
        WriteOutcome::Failed => "failed",
        WriteOutcome::Reparsed => "reparsed",
    }
}

pub(crate) fn import_batch(
    files: &[(String, Vec<u8>)],
    writer: &mut Writer<'_>,
    mut progress: Option<Progress<'_>>,
) -> Result<(), WriterError> {
    for (_label, data) in files {
        writer.offsets.extend(fit::scan_clock_offsets(data));
    }
    let total = files.len() as u64;
    for (done, (label, data)) in (1u64..).zip(files) {
        let outcome = writer.write_fit(data, label, None)?;
        if let Some(report) = progress.as_deref_mut() {
            report(done, Some(total), outcome_text(outcome));
        }
    }
    writer.derive_daily_steps()?;
    writer.derive_daily_from_samples()?;
    Ok(())
}

/// Import whatever `path` is into `conn` (a writable connection holding the write lock) and report.
/// `transport` defaults to `connect_export` for an account export and `drop` otherwise. An
/// export's FIT members go first (one clock-offset pre-pass), then its JSON files, in one run.
/// `progress` is called after each file (see [`Progress`]).
pub fn import_path(
    conn: &Connection,
    path: &Path,
    transport: Option<&str>,
    mut progress: Option<Progress<'_>>,
) -> Result<ImportStats, SourceError> {
    if !path.exists() {
        return Err(SourceError::NotFound(path.display().to_string()));
    }
    let is_export = looks_like_export(path);
    let transport = transport.unwrap_or(if is_export { TRANSPORT_CONNECT_EXPORT } else { TRANSPORT_DROP });
    let mut writer = Writer::new(conn, ClockOffsets::load(conn)?, transport);
    writer.begin_run()?;
    let outcome = if is_export {
        export::collect_fit_members(path)
            .and_then(|files| {
                import_batch(&files, &mut writer, reborrow(&mut progress)).map_err(SourceError::from)
            })
            .and_then(|()| export::import_connect_export(path, &mut writer, reborrow(&mut progress)))
            .and_then(|()| {
                let stored = stored_json_streams(conn)?;
                rederive_json(conn, &mut writer, &stored)
            })
    } else {
        iter_fit_files(path).and_then(|files| {
            import_batch(&files, &mut writer, reborrow(&mut progress)).map_err(SourceError::from)
        })
    };
    if let Err(error) = outcome {
        writer.finish_run(Some(&error.to_string()))?;
        return Err(error);
    }
    writer.stats.dates_assumed_utc = writer.offsets.assumed_utc();
    writer.finish_run(None)?;
    Ok(writer.stats)
}

// ---- reparse: replay retained raw records through today's decoders ----

/// Largest zlib payload this port inflates from a stored record (the oracle has no limit; a record
/// past this is treated as undecodable instead of exhausting memory).
const MAX_INFLATED: u64 = 1 << 30;

/// `zlib.decompress` of a stored payload, capped at [`MAX_INFLATED`]. `None` is the oracle's
/// `zlib.error` (the class `error`).
pub fn inflate(blob: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut decoder = flate2::read::ZlibDecoder::new(blob).take(MAX_INFLATED + 1);
    decoder.read_to_end(&mut out).ok()?;
    (out.len() as u64 <= MAX_INFLATED).then_some(out)
}

/// A stored JSON payload parsed back: `Err((class, message))` carries the oracle's exception class.
pub fn parse_stored_json(blob: &[u8]) -> Result<Value, (&'static str, String)> {
    let data = inflate(blob).ok_or(("error", "Error -3 while decompressing data".to_string()))?;
    if std::str::from_utf8(&data).is_err() {
        return Err(("UnicodeDecodeError", "invalid utf-8".to_string()));
    }
    canon::parse(&data).map_err(|error| match error {
        canon::CanonError::Syntax(why) => ("JSONDecodeError", why.to_string()),
        canon::CanonError::Unsupported(why) => ("unsupported_json", format!("JSON this port refuses ({why})")),
    })
}

/// A `json:readiness` record the batch chose facts for: `(raw_id, decoded, summary)`.
type ReadinessChoice = (i64, Box<Decoded>, Value);
/// A stored record whose bytes fail to parse: `(raw_id, class, message)`.
type Unreadable = (i64, &'static str, String);

/// `_decode_readiness_batch`: decode every `json:readiness` raw record of the store together.
/// Returns the records the batch chose facts for and `(raw_id, class, message)` per record whose
/// stored bytes fail to parse (left out of the batch; it does not block the rest). Records are fed
/// in `payload_hash` order so the decoder's dedup on `timestamp` does not depend on arrival
/// order. A record that is not a JSON object is the oracle's uncaught `AttributeError`.
fn decode_readiness_stored(
    conn: &Connection,
) -> Result<(Vec<ReadinessChoice>, Vec<Unreadable>), SourceError> {
    let rows: Vec<(i64, String, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT id, source_key, payload FROM raw_records WHERE stream='json:readiness' ORDER BY payload_hash, id",
        )?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    let mut records = Vec::with_capacity(rows.len());
    let mut raw_id_by_key: HashMap<String, i64> = HashMap::new();
    let mut unreadable = Vec::new();
    for (raw_id, source_key, blob) in rows {
        match parse_stored_json(&blob) {
            Ok(record) => {
                records.push(record);
                raw_id_by_key.insert(source_key, raw_id);
            }
            Err((class, message)) => unreadable.push((raw_id, class, message)),
        }
    }
    if let Some(bad) = records.iter().find(|r| !matches!(r, Value::Object(_))) {
        return Err(SourceError::Abort(format!(
            "AttributeError: '{}' object has no attribute 'get'",
            export::type_name(bad)
        )));
    }
    let (steps, abort) = export::decode_readiness_batch(&records);
    if let Some(message) = abort {
        return Err(SourceError::Abort(message));
    }
    let mut chosen = Vec::new();
    for step in steps {
        let Step::Record { key, decoded, .. } = step else { continue };
        let Some(&raw_id) = raw_id_by_key.get(&key) else {
            continue; // decoder derived a key with no matching stored record
        };
        let summary = json_summary(&decoded);
        chosen.push((raw_id, decoded, summary));
    }
    Ok((chosen, unreadable))
}

/// `_reparse_readiness`: redecode every `json:readiness` raw record of the store together, in
/// one batch, and rewrite the canonical rows of every one of them. A record whose stored bytes
/// fail to parse is recorded as a failure and left out of the batch.
pub fn reparse_readiness(conn: &Connection, writer: &mut Writer<'_>) -> Result<(), SourceError> {
    let (chosen, unreadable) = decode_readiness_stored(conn)?;
    for (raw_id, class, message) in unreadable {
        writer.record_parse_failure(
            "json:readiness",
            &format!("raw_record:{raw_id}"),
            class,
            &message,
            None,
            None,
            Some(raw_id),
            None,
            true,
        )?;
    }
    for (raw_id, decoded, summary) in chosen {
        writer.rewrite_canonical(raw_id, "json:readiness", &decoded, &summary)?;
    }
    Ok(())
}

/// Every `json:*` stream that has a raw record in the store, sorted.
fn stored_json_streams(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut statement =
        conn.prepare("SELECT DISTINCT stream FROM raw_records WHERE stream LIKE 'json:%' ORDER BY stream")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect()
}

/// `rederive_json`: make the daily rows of the JSON `streams` a pure function of the raw records
/// stored now (bet 10b). Run at the end of every import and every pull, so devices that converged
/// on the same raw set converge on the same days whatever order the records arrived in. An export
/// import passes every JSON stream in the store, not just the ones it wrote this run: each record
/// commits on its own, so a retry of an interrupted import sees the finished streams as
/// all-duplicate and would never re-derive them. In one
/// transaction inside the caller's run (no `import_runs` row of its own, no import statistics or
/// provenance bumped: the records were just counted when they were written) the canonical rows
/// those streams' raw records produced are deleted and rebuilt record by record in the content
/// order of [`raw_ids_by_stream`], so a record a relay supersession removed stops contributing
/// and a runner-up it hid contributes again.
///
/// `json:readiness` is the one batch stream: when it is among `streams` it is redecoded together
/// after its rows were cleared, never per record. Names that are not `json:` are ignored; FIT
/// streams and the FIT-derived `local` rows are untouched.
///
/// Everything is decoded before anything is deleted. A stored record that no longer decodes keeps
/// the rows it has and is not reported here (`reparse_all` records and repairs such failures): an
/// unrelated import must not lose data or turn `partial`.
pub fn rederive_json(conn: &Connection, writer: &mut Writer<'_>, streams: &[String]) -> Result<(), SourceError> {
    let mut scope: Vec<String> = streams.iter().filter(|s| s.starts_with("json:")).cloned().collect();
    scope.sort();
    scope.dedup();
    if scope.is_empty() {
        return Ok(());
    }
    let assumed = writer.offsets.assumed_utc();
    writer.offsets = ClockOffsets::load(conn)?; // what a reparse would see
    writer.offsets.set_assumed_utc(assumed);
    let mut decodable: Vec<(i64, Decoded)> = Vec::new();
    let mut undecodable: Vec<i64> = Vec::new();
    for (raw_id, stream) in raw_ids_by_stream(conn, Some(&scope))? {
        if export::is_batch_stream(&stream) {
            continue;
        }
        match decode_raw(conn, raw_id) {
            Ok((_, decoded, _)) => decodable.push((raw_id, decoded)),
            Err(RawDecodeError::Other { caught: false, class, message }) => {
                return Err(SourceError::Abort(format!("{class}: {message}")));
            }
            Err(_) => undecodable.push(raw_id),
        }
    }
    let mut readiness: Vec<ReadinessChoice> = Vec::new();
    if scope.iter().any(|s| s == "json:readiness") {
        let (chosen, unreadable) = decode_readiness_stored(conn)?;
        readiness = chosen;
        undecodable.extend(unreadable.into_iter().map(|(raw_id, _, _)| raw_id));
    }
    let dropped_before = writer.stats.dropped.clone();
    conn.execute_batch("BEGIN")?;
    let run = |writer: &mut Writer<'_>| -> rusqlite::Result<()> {
        delete_canonical(conn, Some(&scope), &undecodable)?;
        for (raw_id, decoded) in &decodable {
            writer.write_canonical(decoded, *raw_id)?;
        }
        for (raw_id, decoded, summary) in &readiness {
            writer.write_canonical(decoded, *raw_id)?;
            conn.execute(
                "UPDATE raw_records SET decode_summary=? WHERE id=?",
                params![canon::dumps_spaced(summary), raw_id],
            )?;
        }
        Ok(())
    };
    let outcome = run(writer);
    writer.stats.dropped = dropped_before; // a re-derive re-counts nothing the import already counted
    match outcome {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(error.into());
        }
    }
    Ok(())
}

/// Why `decode_raw` could not decode a retained record.
#[derive(Debug)]
pub enum RawDecodeError {
    /// `FitDecodeError`: the FIT payload no longer parses.
    Fit(FitDecodeError),
    /// Any other exception: its Python class name and message. `caught` is true for the classes
    /// `reparse_record` turns into an `unrecognized_payload` failure, false for the ones it lets
    /// escape (an `AttributeError` on a record that is not an object, an `OverflowError`).
    Other { class: String, message: String, caught: bool },
}

impl RawDecodeError {
    /// `getattr(exc, "kind", type(exc).__name__)`, what `_dry_run` reports.
    pub fn kind(&self) -> String {
        match self {
            RawDecodeError::Fit(error) => error.kind.clone(),
            RawDecodeError::Other { class, .. } => class.clone(),
        }
    }

    pub fn message(&self) -> String {
        match self {
            RawDecodeError::Fit(error) => error.message.clone(),
            RawDecodeError::Other { class, message, .. } => format!("{class}: {message}"),
        }
    }
}

fn caught_class(class: &str) -> bool {
    matches!(class, "ValueError" | "JSONDecodeError" | "UnicodeDecodeError" | "error" | "TypeError" | "KeyError")
}

fn other(class: &str, message: impl Into<String>) -> RawDecodeError {
    RawDecodeError::Other { class: class.to_string(), message: message.into(), caught: caught_class(class) }
}

/// `Writer.decode_raw`: decode one retained raw record again, writing nothing. Returns
/// `(stream, decoded, summary)`.
pub fn decode_raw(conn: &Connection, raw_id: i64) -> Result<(String, Decoded, Value), RawDecodeError> {
    let row: Option<(String, String, Vec<u8>)> = conn
        .query_row("SELECT stream, payload_kind, payload FROM raw_records WHERE id=?", params![raw_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .ok();
    let Some((stream, kind, blob)) = row else {
        return Err(other("ValueError", format!("no raw_records row with id={raw_id}")));
    };
    if export::is_batch_stream(&stream) {
        return Err(other("ValueError", format!("{stream} reparses as a batch -- use sources.reparse_all")));
    }
    let data = inflate(&blob).ok_or_else(|| other("error", "Error -3 while decompressing data"))?;
    match kind.as_str() {
        "fit" => {
            let decoded = fit::decode_fit(&data).map_err(RawDecodeError::Fit)?;
            let summary = fit_summary(&decoded);
            Ok((stream, decoded, summary))
        }
        "json" => {
            if !export::has_record_decoder(&stream) {
                return Err(other("ValueError", format!("no reparse decoder registered for stream '{stream}'")));
            }
            let record = parse_stored_json(&blob).map_err(|(class, message)| other(class, message))?;
            match export::decode_stored_record(&stream, &record) {
                Ok(Some((_key, decoded))) => {
                    let summary = json_summary(&decoded);
                    Ok((stream, decoded, summary))
                }
                Ok(None) => Err(other("ValueError", "decoder produced no facts for this record")),
                Err(DecodeError::Refused(message)) => Err(other("ValueError", message)),
                Err(DecodeError::Abort(message)) => {
                    let (class, rest) = message.split_once(": ").unwrap_or(("Exception", message.as_str()));
                    Err(other(class, rest))
                }
            }
        }
        _ => Err(other("ValueError", format!("unknown payload_kind '{kind}'"))),
    }
}

/// `Writer.reparse_record`: redecode one retained raw record and replace the canonical rows it
/// produced. A decode failure is recorded and returns `Failed`; a caller bug or an exception the
/// oracle lets escape is `Err(SourceError::Abort)`.
pub fn reparse_record(conn: &Connection, writer: &mut Writer<'_>, raw_id: i64) -> Result<WriteOutcome, SourceError> {
    let label = format!("raw_record:{raw_id}");
    let stream_of = |conn: &Connection| -> String {
        conn.query_row("SELECT stream FROM raw_records WHERE id=?", params![raw_id], |r| r.get(0)).unwrap_or_default()
    };
    match decode_raw(conn, raw_id) {
        Ok((stream, decoded, summary)) => Ok(writer.rewrite_canonical(raw_id, &stream, &decoded, &summary)?),
        Err(RawDecodeError::Fit(error)) => {
            let stream = stream_of(conn);
            writer.record_parse_failure(&stream, &label, &error.kind, &error.message, None, None, Some(raw_id), None, true)?;
            Ok(WriteOutcome::Failed)
        }
        Err(RawDecodeError::Other { class, message, caught }) => {
            let programming_error = message.starts_with("no raw_records row") || message.contains("reparses as a batch");
            if !caught || programming_error {
                return Err(SourceError::Abort(format!("{class}: {message}")));
            }
            let stream = stream_of(conn);
            let text = if class == "ValueError" || class == "JSONDecodeError" || class == "UnicodeDecodeError" {
                message
            } else {
                format!("{class}: {message}")
            };
            writer.record_parse_failure(&stream, &label, "unrecognized_payload", &text, None, None, Some(raw_id), None, true)?;
            Ok(WriteOutcome::Failed)
        }
    }
}

/// `(id, stream)` for every raw record in an order that depends on content alone: oldest
/// `start_utc` first (NULL first), ties by `payload_hash`, `stream`, `source_key`, never the local
/// `id`, so two stores holding the same raw set fold it identically.
fn raw_ids_by_stream(conn: &Connection, streams: Option<&[String]>) -> rusqlite::Result<Vec<(i64, String)>> {
    let (sql, bound): (String, Vec<&String>) = match streams {
        Some(list) if !list.is_empty() => {
            let marks = vec!["?"; list.len()].join(",");
            (
                format!("SELECT id, stream FROM raw_records WHERE stream IN ({marks}) ORDER BY start_utc, payload_hash, stream, source_key"),
                list.iter().collect(),
            )
        }
        _ => (
            "SELECT id, stream FROM raw_records ORDER BY start_utc, payload_hash, stream, source_key".to_string(),
            Vec::new(),
        ),
    };
    let mut stmt = conn.prepare(&sql)?;
    let mapped = stmt.query_map(params_from_iter(bound), |r| Ok((r.get(0)?, r.get(1)?)))?;
    mapped.collect()
}

/// `_dry_run`: decode every record in scope without writing; the failures.
fn dry_run(conn: &Connection, rows: &[(i64, String)]) -> Result<Vec<Failure>, SourceError> {
    let mut failures = Vec::new();
    for (raw_id, stream) in rows {
        let failed = if export::is_batch_stream(stream) {
            let blob: Vec<u8> = conn.query_row("SELECT payload FROM raw_records WHERE id=?", params![raw_id], |r| r.get(0))?;
            match parse_stored_json(&blob) {
                Ok(_) => None,
                Err((class, message)) => Some((class.to_string(), format!("{class}: {message}"))),
            }
        } else {
            decode_raw(conn, *raw_id).err().map(|e| (e.kind(), e.message()))
        };
        if let Some((kind, error)) = failed {
            failures.push(Failure {
                file: format!("raw_record:{raw_id}"),
                stream: Some(stream.clone()),
                kind,
                error: redact_text(&error),
            });
        }
    }
    Ok(failures)
}

/// `_delete_canonical`: delete every canonical row the raw records in scope produced, except the
/// rows of the raw ids in `keep`. The caller owns the transaction.
fn delete_canonical(conn: &Connection, streams: Option<&[String]>, keep: &[i64]) -> rusqlite::Result<()> {
    let (mut scope_sql, mut bound): (String, Vec<SqlValue>) = match streams {
        Some(list) if !list.is_empty() => {
            let marks = vec!["?"; list.len()].join(",");
            (
                format!("raw_record_id IN (SELECT id FROM raw_records WHERE stream IN ({marks}))"),
                list.iter().cloned().map(SqlValue::Text).collect(),
            )
        }
        _ => ("raw_record_id IS NOT NULL".to_string(), Vec::new()),
    };
    if !keep.is_empty() {
        scope_sql.push_str(&format!(" AND raw_record_id NOT IN ({})", vec!["?"; keep.len()].join(",")));
        bound.extend(keep.iter().copied().map(SqlValue::Integer));
    }
    conn.execute(
        &format!("DELETE FROM sleep_stages WHERE sleep_id IN (SELECT sleep_id FROM sleep_sessions WHERE {scope_sql})"),
        params_from_iter(bound.iter()),
    )?;
    for table in [
        "metric_samples",
        "daily_metrics",
        "daily_labels",
        "monitoring_intervals",
        "activities",
        "clock_offsets",
        "sleep_sessions",
    ] {
        conn.execute(&format!("DELETE FROM {table} WHERE {scope_sql}"), params_from_iter(bound.iter()))?;
    }
    Ok(())
}

/// `_clear_canonical`: [`delete_canonical`] in one transaction.
fn clear_canonical(conn: &Connection, streams: Option<&[String]>) -> rusqlite::Result<()> {
    conn.execute_batch("BEGIN")?;
    match delete_canonical(conn, streams, &[]) {
        Ok(()) => conn.execute_batch("COMMIT"),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

/// `_clear_failures`: forget earlier reparse failures of records about to be redecoded.
fn clear_failures(conn: &Connection, raw_ids: &[i64]) -> rusqlite::Result<()> {
    for chunk in raw_ids.chunks(500) {
        let marks = vec!["?"; chunk.len()].join(",");
        conn.execute(
            &format!("DELETE FROM import_failures WHERE raw_record_id IN ({marks})"),
            params_from_iter(chunk.iter()),
        )?;
    }
    Ok(())
}

/// `sources.reparse_all`: redecode every retained raw record in scope and replace the canonical
/// rows it produced (`streams = None` is every stream). Records go in `start_utc, id` order, FIT
/// first; `json:readiness` is redecoded as one batch. Everything is decoded once before anything
/// is cleared: if any fails, nothing is touched and the run finishes `failed` unless `force`.
pub fn reparse_all(conn: &Connection, streams: Option<&[String]>, force: bool) -> Result<ImportStats, SourceError> {
    let mut writer = Writer::new(conn, ClockOffsets::load(conn)?, "reparse");
    writer.begin_run()?;
    let outcome = reparse_body(conn, &mut writer, streams, force);
    match outcome {
        Err(error) => {
            writer.finish_run(Some(&error.to_string()))?;
            Err(error)
        }
        Ok(Some(message)) => {
            writer.finish_run(Some(&message))?;
            Ok(writer.stats)
        }
        Ok(None) => {
            writer.finish_run(None)?;
            Ok(writer.stats)
        }
    }
}

/// The body of `reparse_all`; `Ok(Some(message))` is the dry run refusing to touch anything.
fn reparse_body(
    conn: &Connection,
    writer: &mut Writer<'_>,
    streams: Option<&[String]>,
    force: bool,
) -> Result<Option<String>, SourceError> {
    let rows = raw_ids_by_stream(conn, streams)?;
    writer.stats.files_seen = rows.len() as i64;
    let failures = dry_run(conn, &rows)?;
    if !failures.is_empty() && !force {
        writer.stats.files_failed = failures.len() as i64;
        let message = format!(
            "{} record(s) fail to decode; nothing was changed (fix the decoder or pass force)",
            failures.len()
        );
        writer.stats.failures = failures;
        return Ok(Some(message));
    }
    clear_canonical(conn, streams)?;
    let ids: Vec<i64> = rows.iter().map(|(id, _)| *id).collect();
    clear_failures(conn, &ids)?;
    let fit_ids: Vec<i64> = rows.iter().filter(|(_, s)| s.starts_with("fit:")).map(|(id, _)| *id).collect();
    let json_ids: Vec<i64> = rows
        .iter()
        .filter(|(_, s)| !export::is_batch_stream(s) && !s.starts_with("fit:"))
        .map(|(id, _)| *id)
        .collect();
    for raw_id in fit_ids {
        reparse_record(conn, writer, raw_id)?;
    }
    writer.offsets = ClockOffsets::load(conn)?; // pick up any offset a FIT reparse just corrected
    for raw_id in json_ids {
        reparse_record(conn, writer, raw_id)?;
    }
    if streams.is_none_or(|list| list.iter().any(|s| export::is_batch_stream(s))) {
        reparse_readiness(conn, writer)?;
    }
    writer.derive_daily_steps()?;
    writer.derive_daily_from_samples()?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zip_with(path: &Path, entries: &[(&str, &[u8])]) {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(fs::File::create(path).expect("create zip"));
        let options = zip::write::SimpleFileOptions::default();
        for (name, bytes) in entries {
            writer.start_file(*name, options).expect("start entry");
            writer.write_all(bytes).expect("write entry");
        }
        writer.finish().expect("finish zip");
    }

    #[test]
    fn export_layouts_are_recognised_like_the_oracle() {
        let dir = tempfile::tempdir().expect("tempdir");
        // The extracted root holds a DI_CONNECT folder.
        let root = dir.path().join("export");
        fs::create_dir_all(root.join("DI_CONNECT/DI-Connect-Wellness")).expect("mkdir");
        assert!(looks_like_export(&root));
        // The DI_CONNECT folder itself.
        assert!(looks_like_export(&root.join("DI_CONNECT")));
        // A plain folder of FIT files is not one.
        let plain = dir.path().join("plain");
        fs::create_dir_all(&plain).expect("mkdir");
        assert!(!looks_like_export(&plain));
        // Outer zips: first component or an inner DI_CONNECT folder.
        let first = dir.path().join("first.zip");
        zip_with(&first, &[("DI_CONNECT/a.json", b"[]")]);
        assert!(looks_like_export(&first));
        let nested = dir.path().join("nested.ZIP");
        zip_with(&nested, &[("wrapper/DI_CONNECT/a.json", b"[]")]);
        assert!(looks_like_export(&nested));
        let other = dir.path().join("other.zip");
        zip_with(&other, &[("DI_CONNECTED/a.json", b"[]"), ("x.fit", b"")]);
        assert!(!looks_like_export(&other));
        // Not a zip at all, or not there.
        let bad = dir.path().join("bad.zip");
        fs::write(&bad, b"nope").expect("write");
        assert!(!looks_like_export(&bad));
        assert!(!looks_like_export(&dir.path().join("missing")));
    }

    #[test]
    fn zip_entries_with_the_same_name_are_all_returned_in_archive_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dup.zip");
        // The zip writer refuses duplicate names, so write distinct ones of equal length and
        // rename the second in both its local header and the central directory.
        zip_with(
            &path,
            &[("b.fit", b"second-name"), ("a.fit", b"first"), ("c.fit", b"again"), ("skip.txt", b"x")],
        );
        let mut raw = fs::read(&path).expect("read zip");
        let needle = b"c.fit";
        let mut at = 0;
        while let Some(found) = raw[at..].windows(needle.len()).position(|w| w == needle) {
            raw[at + found] = b'a';
            at += found + needle.len();
        }
        fs::write(&path, raw).expect("write zip");
        let files = iter_fit_files(&path).expect("read zip");
        let bytes: Vec<&[u8]> = files.iter().map(|f| f.1.as_slice()).collect();
        assert_eq!(bytes, [b"first".as_slice(), b"again", b"second-name"]);
    }

    #[test]
    fn suffix_follows_python() {
        assert_eq!(suffix_lower("a.FIT"), ".fit");
        assert_eq!(suffix_lower(".fit"), "");
        assert_eq!(suffix_lower("a."), "");
        assert_eq!(suffix_lower("a.b.zip"), ".zip");
    }

    #[test]
    fn folder_order_is_component_wise_like_python_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        for rel in ["a-b/x.fit", "a/x.fit", "a.fit", "a/b.fit", "skip.txt", "a/Y.FIT"] {
            let path = dir.path().join(rel);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(&path, rel.as_bytes()).expect("write");
        }
        let labels: Vec<String> = iter_fit_files(dir.path()).expect("walk").into_iter().map(|f| f.0).collect();
        // Python: sorted(Path) compares part by part: "a" < "a-b" < "a.fit", and "Y" < "b" inside a/
        assert_eq!(labels, ["a/Y.FIT", "a/b.fit", "a/x.fit", "a-b/x.fit", "a.fit"]);
    }
}
