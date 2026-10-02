// SPDX-License-Identifier: AGPL-3.0-or-later
//! Connect account-export ingest: the Rust twin of `hearthbeat/ingest/connect_export.py` and the
//! export branch of `ingest/sources.py::import_path`.
//!
//! The export is an extracted folder (or its `DI_CONNECT` folder) or the outer zip. Its FIT corpus
//! sits in nested `UploadedFiles*.zip` members (read into memory first, [`collect_fit_members`]);
//! its JSON daily figures are nine file families, each decoded record by record into the same
//! `Decoded` shape the FIT path uses and written through the same `Writer`.
//!
//! Faithfulness rules, all from the oracle: files are visited in Python's sort order; a file is
//! read and parsed whole before its first record is written; a record's key is built through
//! `canon::py_str`; last-write-wins daily upserts make file and record order part of the
//! contract. A Python exception the oracle never catches (`BadZipFile`, an out-of-range
//! epoch-ms, a number where an object is expected) aborts the run here too: [`SourceError::Abort`]
//! books the run as failed and the import stops, earlier files stay written.
//!
//! Forms Python accepts that the real export never uses are refused, not imitated (see
//! `canon.rs`): such a file is booked as an `unsupported_json` failure, a container in a
//! key position as an `unsupported_json` failure of that record. Not imitated either: `%Y`/`%d`
//! style Unicode digits in `_parse_gmt` and in file-name windows, and same-named entries in the
//! *outer* zip (nested FIT zips handle them).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use chrono::{NaiveDate, TimeZone, Utc};
use sha2::{Digest, Sha256};

use crate::canon::{self, Value};
use crate::model::{DailyFact, DailyLabel, Decoded, Instant, SleepSession};
use crate::redact::mask_label;
use crate::sources::{EXPORT_ROOT, SourceError, components_key, walk_files, zip_fit_members};
use crate::time::civil_from_days;
use crate::writer::Writer;

const UPLOADED_FILES_SECTION: &str = "DI-Connect-Uploaded-Files";
const MORNING_CONTEXT: &str = "AFTER_WAKEUP_RESET";

type Obj = [(String, Value)];

// ---- file families ----

#[derive(Clone, Copy)]
enum Match {
    Prefix,
    Suffix,
}

/// Which export file family feeds which stream: (section, name test, needle, stream). A file
/// outside this table is counted as ignored.
const FILE_FAMILIES: [(&str, Match, &str, &str); 9] = [
    (
        "DI-Connect-Aggregator",
        Match::Prefix,
        "UDSFile_",
        "json:uds",
    ),
    (
        "DI-Connect-Wellness",
        Match::Suffix,
        "_sleepData.json",
        "json:sleep",
    ),
    (
        "DI-Connect-Metrics",
        Match::Prefix,
        "TrainingReadinessDTO_",
        "json:readiness",
    ),
    (
        "DI-Connect-Metrics",
        Match::Prefix,
        "MetricsMaxMetData_",
        "json:vo2max",
    ),
    (
        "DI-Connect-Metrics",
        Match::Prefix,
        "MetricsAcuteTrainingLoad_",
        "json:training_load",
    ),
    (
        "DI-Connect-Metrics",
        Match::Prefix,
        "EnduranceScore_",
        "json:endurance",
    ),
    (
        "DI-Connect-Metrics",
        Match::Prefix,
        "HillScore_",
        "json:hill",
    ),
    (
        "DI-Connect-Wellness",
        Match::Suffix,
        "_fitnessAgeData.json",
        "json:fitness_age",
    ),
    (
        "DI-Connect-Wellness",
        Match::Suffix,
        "_userBioMetrics.json",
        "json:biometrics",
    ),
];

/// `connect_export.stream_for_entry`: the stream a JSON export file belongs to.
pub fn stream_for_entry(section: Option<&str>, name: &str) -> Option<&'static str> {
    let section = section?;
    if !name.to_lowercase().ends_with(".json") {
        return None;
    }
    for (family_section, how, needle, stream) in FILE_FAMILIES {
        if section != family_section {
            continue;
        }
        let hit = match how {
            Match::Prefix => name.starts_with(needle),
            Match::Suffix => name.ends_with(needle),
        };
        if hit {
            return Some(stream);
        }
    }
    None
}

/// `connect_export._NO_DATE_REASON`: why a dateless record of a stream is counted as dropped.
fn no_date_reason(stream: &str) -> Option<&'static str> {
    match stream {
        "json:uds" => Some("uds_without_date"),
        "json:sleep" => Some("sleep_stub_without_date"),
        _ => None,
    }
}

/// `connect_export._connect_section`: the `DI_CONNECT` sub-folder an entry belongs to.
pub fn connect_section(relpath: &str) -> Option<&str> {
    let parts: Vec<&str> = relpath.split('/').collect();
    let index = parts.iter().position(|p| *p == EXPORT_ROOT)?;
    if parts.len() > index + 2 {
        Some(parts[index + 1])
    } else {
        None
    }
}

// ---- file-name windows ----

fn is_digit(byte: u8) -> bool {
    byte.is_ascii_digit()
}

/// `YYYY-MM-DD_YYYY-MM-DD` anywhere in the name (leftmost match, no look-arounds).
fn iso_range(name: &str) -> Option<(String, String)> {
    let bytes = name.as_bytes();
    const SHAPE: &[u8; 21] = b"dddd-dd-dd_dddd-dd-dd";
    if bytes.len() < SHAPE.len() {
        return None;
    }
    (0..=bytes.len() - SHAPE.len()).find_map(|at| {
        let window = &bytes[at..at + SHAPE.len()];
        let fits = window
            .iter()
            .zip(SHAPE)
            .all(|(b, s)| if *s == b'd' { is_digit(*b) } else { b == s });
        // The window is ASCII (digits and punctuation), so slicing the str on it is safe.
        fits.then(|| {
            (
                name[at..at + 10].to_string(),
                name[at + 11..at + 21].to_string(),
            )
        })
    })
}

/// `(?<!\d)(\d{4})(\d{2})(\d{2})_(\d{4})(\d{2})(\d{2})(?!\d)`, leftmost match.
fn compact_range(name: &str) -> Option<(String, String)> {
    let bytes = name.as_bytes();
    if bytes.len() < 17 {
        return None;
    }
    (0..=bytes.len() - 17).find_map(|at| {
        let first = &bytes[at..at + 8];
        let second = &bytes[at + 9..at + 17];
        let ok = (at == 0 || !is_digit(bytes[at - 1]))
            && first.iter().all(|b| is_digit(*b))
            && bytes[at + 8] == b'_'
            && second.iter().all(|b| is_digit(*b))
            && bytes.get(at + 17).is_none_or(|b| !is_digit(*b));
        ok.then(|| {
            let day = |s: &str| format!("{}-{}-{}", &s[0..4], &s[4..6], &s[6..8]);
            (day(&name[at..at + 8]), day(&name[at + 9..at + 17]))
        })
    })
}

/// `datetime.date.fromisoformat` of a fixed-width `YYYY-MM-DD` made of ASCII digits (year >= 1).
fn real_date(day: &str) -> Option<NaiveDate> {
    let number = |range: std::ops::Range<usize>| day.get(range)?.parse::<u32>().ok();
    if day.len() != 10 || day.as_bytes()[4] != b'-' || day.as_bytes()[7] != b'-' {
        return None;
    }
    let year = number(0..4).filter(|y| *y >= 1)?;
    NaiveDate::from_ymd_opt(year as i32, number(5..7)?, number(8..10)?)
}

/// `connect_export.date_range_in_name`: the `(from_day, to_day)` window a file name states, if any.
/// The ISO form wins over the compact one; the first match decides (an invalid or reversed pair
/// returns None, it does not fall through to the other form).
pub fn date_range_in_name(name: &str) -> Option<(String, String)> {
    let candidate = iso_range(name).or_else(|| compact_range(name))?;
    let first = real_date(&candidate.0)?;
    let last = real_date(&candidate.1)?;
    (first <= last).then_some(candidate)
}

fn noon_utc(day: &str) -> Option<Instant> {
    let noon = real_date(day)?.and_hms_opt(12, 0, 0)?;
    Some(Utc.from_utc_datetime(&noon))
}

// ---- walking the export ----

struct Entry {
    relpath: String,
    /// The file's own modification day, or the deferred `ValueError`/`OSError` the oracle would
    /// raise when its generator reached this entry.
    written: Result<Option<String>, String>,
    loc: Loc,
}

enum Loc {
    File(PathBuf),
    Zip(usize),
}

impl Entry {
    fn name(&self) -> &str {
        self.relpath.rsplit('/').next().unwrap_or("")
    }
}

/// An export laid out in the oracle's iteration order, bytes read on demand.
struct Tree {
    entries: Vec<Entry>,
    archive: Option<zip::ZipArchive<fs::File>>,
}

fn os_error(error: &std::io::Error) -> String {
    format!("OSError: {}", error.kind())
}

fn zip_error(error: &dyn std::fmt::Display) -> String {
    format!("BadZipFile: {error}")
}

/// `datetime.date(year, month, day).isoformat()` clamped as the oracle does: a year before 1980
/// is "unknown" (None), an impossible date is a `ValueError`.
pub fn written_day_from_ymd(year: i32, month: u32, day: u32) -> Result<Option<String>, String> {
    let date = NaiveDate::from_ymd_opt(year, month, day).ok_or_else(|| {
        if (1..=12).contains(&month) {
            "ValueError: day is out of range for month"
        } else {
            "ValueError: month must be in 1..12"
        }
        .to_string()
    })?;
    Ok((year >= 1980).then(|| date.format("%Y-%m-%d").to_string()))
}

/// The written day of a zip entry from its DOS date word (`ZipInfo.date_time[:3]`).
pub fn written_day_from_dos(date: u16) -> Result<Option<String>, String> {
    written_day_from_ymd(
        1980 + i32::from(date >> 9),
        u32::from((date >> 5) & 0xF),
        u32::from(date & 0x1F),
    )
}

fn day_of_unix_secs(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

fn modified_day(path: &Path) -> Result<Option<String>, String> {
    let modified = fs::metadata(path)
        .and_then(|m| m.modified())
        .map_err(|e| os_error(&e))?;
    let secs = match modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(after) => after.as_secs() as i64,
        Err(before) => {
            let back = before.duration();
            -(back.as_secs() as i64) - i64::from(back.subsec_nanos() > 0)
        }
    };
    Ok(Some(day_of_unix_secs(secs)))
}

impl Tree {
    /// `_entries`: every file of a folder (sorted component-wise like `sorted(Path)`), or every
    /// non-directory member of the outer zip sorted by name (stable).
    fn open(path: &Path) -> Result<Tree, SourceError> {
        if path.is_dir() {
            let at_root = path.file_name().is_some_and(|n| n == EXPORT_ROOT);
            let root = if at_root {
                match path.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => parent,
                    _ => Path::new("."),
                }
            } else {
                path
            };
            let mut files = Vec::new();
            walk_files(root, Path::new(""), &mut files)
                .map_err(|e| SourceError::Abort(os_error(&e)))?;
            files.sort_by_key(|rel| components_key(rel));
            let entries = files
                .into_iter()
                .map(|rel| Entry {
                    relpath: rel.to_string_lossy().replace('\\', "/"),
                    written: modified_day(&root.join(&rel)),
                    loc: Loc::File(root.join(&rel)),
                })
                .collect();
            return Ok(Tree {
                entries,
                archive: None,
            });
        }
        let abort = |m: String| SourceError::Abort(m);
        let mut archive =
            zip::ZipArchive::new(fs::File::open(path).map_err(|e| abort(os_error(&e)))?)
                .map_err(|e| abort(zip_error(&e)))?;
        let mut dates = fs::File::open(path).map_err(|e| abort(os_error(&e)))?;
        let mut listed: Vec<(String, usize, Result<Option<String>, String>)> =
            Vec::with_capacity(archive.len());
        for index in 0..archive.len() {
            let entry = archive
                .by_index_raw(index)
                .map_err(|e| abort(zip_error(&e)))?;
            let name = entry.name().to_string();
            // The DOS date word sits 14 bytes into the central-directory header; the oracle reads
            // `date_time[:3]` from it whatever the time word says.
            let written = if name.ends_with('/') {
                Ok(None)
            } else {
                let mut word = [0_u8; 2];
                dates
                    .seek(SeekFrom::Start(entry.central_header_start() + 14))
                    .and_then(|_| dates.read_exact(&mut word))
                    .map_err(|e| os_error(&e))
                    .and_then(|()| written_day_from_dos(u16::from_le_bytes(word)))
            };
            listed.push((name, index, written));
        }
        listed.sort_by(|a, b| a.0.cmp(&b.0));
        let entries = listed
            .into_iter()
            .filter(|(name, _, _)| !name.ends_with('/'))
            .map(|(name, index, written)| Entry {
                relpath: name.replace('\\', "/"),
                written,
                loc: Loc::Zip(index),
            })
            .collect();
        Ok(Tree {
            entries,
            archive: Some(archive),
        })
    }

    fn read(&mut self, index: usize) -> Result<Vec<u8>, SourceError> {
        let abort = SourceError::Abort;
        match &self.entries[index].loc {
            Loc::File(path) => fs::read(path).map_err(|e| abort(os_error(&e))),
            Loc::Zip(member) => {
                let archive = self
                    .archive
                    .as_mut()
                    .ok_or_else(|| abort("BadZipFile: no archive".to_string()))?;
                let mut entry = archive
                    .by_index(*member)
                    .map_err(|e| abort(zip_error(&e)))?;
                let mut bytes = Vec::new();
                entry
                    .read_to_end(&mut bytes)
                    .map_err(|e| abort(zip_error(&e)))?;
                Ok(bytes)
            }
        }
    }

    fn written(&self, index: usize) -> Result<Option<String>, SourceError> {
        self.entries[index]
            .written
            .clone()
            .map_err(SourceError::Abort)
    }
}

/// `collect_fit_members`: every `.fit` inside the export's nested `UploadedFiles` zips, as
/// (masked label, bytes), all read before the caller imports anything. A nested zip that does
/// not open, or a member that does not read, aborts the run.
pub fn collect_fit_members(path: &Path) -> Result<Vec<(String, Vec<u8>)>, SourceError> {
    let mut tree = Tree::open(path)?;
    let mut out = Vec::new();
    for index in 0..tree.entries.len() {
        tree.written(index)?;
        let entry = &tree.entries[index];
        if connect_section(&entry.relpath) != Some(UPLOADED_FILES_SECTION)
            || !entry.name().to_lowercase().ends_with(".zip")
        {
            continue;
        }
        let raw = tree.read(index)?;
        out.extend(zip_fit_members(&raw).map_err(|e| SourceError::Abort(zip_error(&e)))?);
    }
    Ok(out)
}

// ---- JSON loading ----

/// What `_load_json` makes of a file's bytes.
#[derive(Debug)]
pub enum Loaded {
    /// The records: a top-level object is one record, a top-level array keeps its objects.
    Records(Vec<Value>),
    /// `bad_json` (Python's `None`) or `unsupported_json` (Python accepts it, this port refuses).
    Failed { kind: &'static str, message: String },
}

pub const BAD_JSON_MESSAGE: &str = "file is not valid JSON or not a JSON array/object";

/// `connect_export._load_json`.
pub fn load_json(raw: &[u8]) -> Loaded {
    let bad = || Loaded::Failed {
        kind: "bad_json",
        message: BAD_JSON_MESSAGE.to_string(),
    };
    if std::str::from_utf8(raw).is_err() {
        return bad(); // `raw.decode("utf-8")` raises UnicodeDecodeError, a ValueError
    }
    match canon::parse(raw) {
        Ok(Value::Object(members)) => Loaded::Records(vec![Value::Object(members)]),
        Ok(Value::Array(items)) => Loaded::Records(
            items
                .into_iter()
                .filter(|v| matches!(v, Value::Object(_)))
                .collect(),
        ),
        Ok(_) => bad(),
        Err(canon::CanonError::Syntax(_)) => bad(),
        Err(canon::CanonError::Unsupported(why)) => Loaded::Failed {
            kind: "unsupported_json",
            message: format!("file holds JSON this port refuses ({why})"),
        },
    }
}

// ---- Python-shaped value helpers ----

fn get<'a>(object: &'a Obj, key: &str) -> Option<&'a Value> {
    object.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// A decode problem: `Abort` is an uncaught Python exception (the run stops), `Refused` a
/// record this port will not imitate (booked as a failure, the file goes on).
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    Abort(String),
    Refused(String),
}

impl From<String> for DecodeError {
    fn from(message: String) -> Self {
        DecodeError::Abort(message)
    }
}

type Decode<T> = Result<T, DecodeError>;

pub(crate) fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// Python truthiness of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Int(n) => *n != 0,
        Value::Float(x) => *x != 0.0,
        Value::Str(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `value or {}` followed by `.get(...)`: a falsy value is an empty dict, a dict is itself, any
/// other truthy value raises `AttributeError` on the `.get`.
fn dict_or_empty(value: Option<&Value>) -> Decode<&Obj> {
    match value {
        None => Ok(&[]),
        Some(v) if !truthy(v) => Ok(&[]),
        Some(Value::Object(members)) => Ok(members),
        Some(other) => Err(DecodeError::Abort(format!(
            "AttributeError: '{}' object has no attribute 'get'",
            type_name(other)
        ))),
    }
}

/// `for item in value or []` where the body skips anything that is not a dict: arrays yield their
/// items; a string or dict would yield only non-dicts (nothing to do); a truthy number raises.
fn list_or_empty(value: Option<&Value>) -> Decode<&[Value]> {
    match value {
        None => Ok(&[]),
        Some(v) if !truthy(v) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(Value::Str(_) | Value::Object(_)) => Ok(&[]),
        Some(other) => Err(DecodeError::Abort(format!(
            "TypeError: '{}' object is not iterable",
            type_name(other)
        ))),
    }
}

/// `_num`: int/float (not bool) as a float.
fn num(value: Option<&Value>) -> Option<f64> {
    match value {
        Some(Value::Int(n)) => Some(*n as f64),
        Some(Value::Float(x)) => Some(*x),
        _ => None,
    }
}

/// `_int`: `int(round(number))`, half-even. A result SQLite cannot hold is the oracle's
/// `OverflowError` when it writes it.
fn int(value: Option<&Value>) -> Decode<Option<i64>> {
    let Some(number) = num(value) else {
        return Ok(None);
    };
    let rounded = number.round_ties_even();
    if (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&rounded) {
        Ok(Some(rounded as i64))
    } else {
        Err(DecodeError::Abort(
            "OverflowError: Python int too large to convert to SQLite INTEGER".to_string(),
        ))
    }
}

fn is_str(value: Option<&Value>, text: &str) -> bool {
    matches!(value, Some(Value::Str(s)) if s == text)
}

/// `f"{record.get(key, '')}"`: missing is `''`, anything else its `str()`; a container is refused.
fn key_part(object: &Obj, key: &str) -> Decode<String> {
    match get(object, key) {
        None => Ok(String::new()),
        Some(value) => canon::py_str(value).map_err(|_| {
            DecodeError::Refused(format!(
                "a container where a source key part is expected ({key})"
            ))
        }),
    }
}

// ---- time ----

/// `_parse_gmt`: Connect's `YYYY-MM-DDTHH:MM:SS` GMT strings, fractional part ignored.
fn parse_gmt(value: Option<&Value>) -> Option<Instant> {
    let Some(Value::Str(text)) = value else {
        return None;
    };
    let chars: Vec<char> = text.chars().take(19).collect();
    if chars.len() < 19 {
        return None;
    }
    let digits = |from: usize, to: usize| -> Option<u32> {
        chars[from..to].iter().try_fold(0_u32, |acc, c| {
            Some(acc * 10 + c.to_digit(10).filter(|_| c.is_ascii_digit())?)
        })
    };
    let separators = [(4, '-'), (7, '-'), (10, 'T'), (13, ':'), (16, ':')];
    if separators.iter().any(|(at, c)| chars[*at] != *c) {
        return None;
    }
    let year = digits(0, 4)? as i32;
    let month = digits(5, 7)?;
    // strptime's `%d` also takes a blank-padded single digit; every other field is two digits wide here.
    let day = if chars[8] == ' ' && chars[9].is_ascii_digit() && chars[9] != '0' {
        digits(9, 10)?
    } else {
        digits(8, 10)?
    };
    let (hour, minute, second) = (digits(11, 13)?, digits(14, 16)?, digits(17, 19)?);
    if !(1..=12).contains(&month) || day == 0 || hour > 23 || minute > 59 || second > 59 {
        return None; // regex miss, or datetime refuses (second 60/61)
    }
    if year < 1 {
        return None;
    }
    let moment = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, second)?;
    Some(Utc.from_utc_datetime(&moment))
}

/// `datetime.fromtimestamp(number / 1000, UTC)` truncated to whole seconds, with CPython's
/// float handling: `modf`, the fraction scaled to microseconds and rounded half to even (a
/// fraction that rounds up to a full second carries). Out-of-range values raise as Python does.
pub fn epoch_ms_to_utc(number: f64) -> Result<Instant, String> {
    let seconds = number / 1000.0;
    let mut whole = seconds.trunc();
    let micros = ((seconds - whole) * 1e6).round_ties_even();
    if micros >= 1e6 {
        whole += 1.0;
    } else if micros < 0.0 {
        whole -= 1.0;
    }
    if !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&whole) {
        return Err("OverflowError: timestamp out of range for platform time_t".to_string());
    }
    let secs = whole as i64;
    let (year, _, _) = civil_from_days(secs.div_euclid(86_400));
    if (year - 1900).abs() > i64::from(i32::MAX) {
        return Err("OSError: [Errno 84] Value too large to be stored in data type".to_string());
    }
    if !(1..=9999).contains(&year) {
        return Err(format!("ValueError: year must be in 1..9999, not {year}"));
    }
    Utc.timestamp_opt(secs, 0)
        .single()
        .ok_or_else(|| format!("ValueError: year must be in 1..9999, not {year}"))
}

/// `_epoch_ms_to_utc`: None for a non-number.
fn epoch_ms(value: Option<&Value>) -> Decode<Option<Instant>> {
    match num(value) {
        None => Ok(None),
        Some(number) => Ok(Some(epoch_ms_to_utc(number)?)),
    }
}

/// `_calendar_date`: an ISO string's first ten characters, or the UTC day of an epoch-ms.
fn calendar_date(value: Option<&Value>) -> Decode<Option<String>> {
    if let Some(Value::Str(text)) = value
        && text.chars().count() >= 10
    {
        return Ok(Some(text.chars().take(10).collect()));
    }
    Ok(epoch_ms(value)?.map(|moment| moment.format("%Y-%m-%d").to_string()))
}

// ---- facts ----

/// `_fact`: a numeric value as a daily fact on `date`; below `minimum` it is counted as dropped.
fn fact(
    decoded: &mut Decoded,
    date: &str,
    metric: &str,
    value: Option<&Value>,
    minimum: Option<f64>,
) {
    if let Some(number) = num(value) {
        fact_number(decoded, date, metric, number, minimum);
    }
}

fn fact_number(decoded: &mut Decoded, date: &str, metric: &str, number: f64, minimum: Option<f64>) {
    if minimum.is_some_and(|m| number < m) {
        decoded.drop(&format!("{metric}_below_minimum"));
        return;
    }
    decoded.daily.push(DailyFact {
        metric: metric.to_string(),
        value: number,
        ts_utc: None,
        date: Some(date.to_string()),
    });
}

fn label(decoded: &mut Decoded, date: &str, metric: &str, text: &str) {
    decoded.labels.push(DailyLabel {
        metric: metric.to_string(),
        label: text.to_lowercase(),
        ts_utc: None,
        date: Some(date.to_string()),
    });
}

fn new_decoded(stream: &str) -> Decoded {
    Decoded::new(stream, "vendor_cloud")
}

type Keyed = Option<(String, Decoded)>;

// ---- UDSFile ----

fn decode_uds(record: &Obj) -> Decode<Keyed> {
    let Some(date) = calendar_date(get(record, "calendarDate"))? else {
        return Ok(None);
    };
    let mut decoded = new_decoded("json:uds");
    decoded.start_utc = parse_gmt(get(record, "wellnessStartTimeGmt"));
    decoded.end_utc = parse_gmt(get(record, "wellnessEndTimeGmt"));
    if matches!(
        get(record, "includesWellnessData"),
        Some(Value::Bool(false))
    ) {
        decoded.drop("uds_day_without_wellness_data");
        return Ok(Some((date, decoded)));
    }
    let d = &mut decoded;
    let simple: [(&str, &str, Option<f64>); 13] = [
        ("steps", "totalSteps", None),
        ("distance", "totalDistanceMeters", None),
        ("resting_heart_rate", "restingHeartRate", Some(1.0)),
        (
            "resting_heart_rate_current_day",
            "currentDayRestingHeartRate",
            Some(1.0),
        ),
        ("heart_rate_min", "minHeartRate", Some(1.0)),
        ("heart_rate_max", "maxHeartRate", Some(1.0)),
        (
            "intensity_minutes_moderate",
            "moderateIntensityMinutes",
            None,
        ),
        (
            "intensity_minutes_vigorous",
            "vigorousIntensityMinutes",
            None,
        ),
        ("calories_total", "totalKilocalories", None),
        ("calories_active", "activeKilocalories", None),
        ("calories_bmr", "bmrKilocalories", None),
        ("spo2_avg", "averageSpo2Value", Some(1.0)),
        ("spo2_lowest", "lowestSpo2Value", Some(1.0)),
    ];
    for (metric, field, minimum) in simple {
        fact(d, &date, metric, get(record, field), minimum);
    }
    let stress = dict_or_empty(get(record, "allDayStress"))?;
    for aggregate in list_or_empty(get(stress, "aggregatorList"))? {
        if let Value::Object(members) = aggregate
            && is_str(get(members, "type"), "TOTAL")
        {
            fact(
                d,
                &date,
                "stress_avg",
                get(members, "averageStressLevel"),
                Some(0.0),
            );
        }
    }
    let respiration = dict_or_empty(get(record, "respiration"))?;
    fact(
        d,
        &date,
        "respiration_avg_waking",
        get(respiration, "avgWakingRespirationValue"),
        Some(0.0),
    );
    fact(
        d,
        &date,
        "respiration_lowest",
        get(respiration, "lowestRespirationValue"),
        Some(0.0),
    );
    fact(
        d,
        &date,
        "respiration_highest",
        get(respiration, "highestRespirationValue"),
        Some(0.0),
    );
    let battery = dict_or_empty(get(record, "bodyBattery"))?;
    fact(
        d,
        &date,
        "body_battery_charged",
        get(battery, "chargedValue"),
        None,
    );
    fact(
        d,
        &date,
        "body_battery_drained",
        get(battery, "drainedValue"),
        None,
    );
    for stat in list_or_empty(get(battery, "bodyBatteryStatList"))? {
        let Value::Object(members) = stat else {
            continue;
        };
        let kind = get(members, "bodyBatteryStatType");
        if is_str(kind, "HIGHEST") {
            fact(
                d,
                &date,
                "body_battery_high",
                get(members, "statsValue"),
                None,
            );
        } else if is_str(kind, "LOWEST") {
            fact(
                d,
                &date,
                "body_battery_low",
                get(members, "statsValue"),
                None,
            );
        }
    }
    if let Some(seconds) = num(get(record, "activeSeconds")) {
        fact_number(d, &date, "active_minutes", seconds / 60.0, None);
    }
    if let Some(seconds) = num(get(record, "highlyActiveSeconds")) {
        fact_number(d, &date, "highly_active_minutes", seconds / 60.0, None);
    }
    let hydration = dict_or_empty(get(record, "hydration"))?;
    fact(d, &date, "hydration_ml", get(hydration, "valueInML"), None);
    fact(
        d,
        &date,
        "sweat_loss_ml",
        get(hydration, "sweatLossInML"),
        None,
    );
    Ok(Some((date, decoded)))
}

// ---- sleepData ----

const SLEEP_SCORE_FIELDS: [&str; 12] = [
    "overallScore",
    "qualityScore",
    "durationScore",
    "recoveryScore",
    "deepScore",
    "remScore",
    "lightScore",
    "awakeningsCountScore",
    "awakeTimeScore",
    "combinedAwakeScore",
    "restfulnessScore",
    "interruptionsScore",
];

fn decode_sleep(record: &Obj) -> Decode<Keyed> {
    let Some(date) = calendar_date(get(record, "calendarDate"))? else {
        return Ok(None);
    };
    let mut decoded = new_decoded("json:sleep");
    let mut session = SleepSession {
        start_utc: parse_gmt(get(record, "sleepStartTimestampGMT")),
        end_utc: parse_gmt(get(record, "sleepEndTimestampGMT")),
        date: Some(date.clone()),
        deep_s: int(get(record, "deepSleepSeconds"))?,
        light_s: int(get(record, "lightSleepSeconds"))?,
        rem_s: int(get(record, "remSleepSeconds"))?,
        awake_s: int(get(record, "awakeSleepSeconds"))?,
        unmeasurable_s: int(get(record, "unmeasurableSeconds"))?,
        awakenings_count: int(get(record, "awakeCount"))?,
        avg_stress: num(get(record, "avgSleepStress")),
        avg_respiration: num(get(record, "averageRespiration")),
        lowest_respiration: num(get(record, "lowestRespiration")),
        highest_respiration: num(get(record, "highestRespiration")),
        retro: get(record, "retro").is_some_and(truthy),
        ..SleepSession::default()
    };
    let scores = dict_or_empty(get(record, "sleepScores"))?;
    let score = |field: &str| int(get(scores, field));
    session.overall_score = score(SLEEP_SCORE_FIELDS[0])?;
    session.quality_score = score(SLEEP_SCORE_FIELDS[1])?;
    session.duration_score = score(SLEEP_SCORE_FIELDS[2])?;
    session.recovery_score = score(SLEEP_SCORE_FIELDS[3])?;
    session.deep_score = score(SLEEP_SCORE_FIELDS[4])?;
    session.rem_score = score(SLEEP_SCORE_FIELDS[5])?;
    session.light_score = score(SLEEP_SCORE_FIELDS[6])?;
    session.awakenings_count_score = score(SLEEP_SCORE_FIELDS[7])?;
    session.awake_time_score = score(SLEEP_SCORE_FIELDS[8])?;
    session.combined_awake_score = score(SLEEP_SCORE_FIELDS[9])?;
    session.restlessness_score = score(SLEEP_SCORE_FIELDS[10])?;
    session.interruptions_score = score(SLEEP_SCORE_FIELDS[11])?;
    let spo2 = dict_or_empty(get(record, "spo2SleepSummary"))?;
    session.avg_spo2 = num(get(spo2, "averageSPO2"));
    session.lowest_spo2 = int(get(spo2, "lowestSPO2"))?;
    session.avg_hr = num(get(spo2, "averageHR"));
    if let Some(naps) = get(record, "napList").filter(|v| truthy(v)) {
        let count = match naps {
            Value::Array(items) => items.len(),
            Value::Object(members) => members.len(),
            Value::Str(text) => text.chars().count(),
            other => {
                return Err(DecodeError::Abort(format!(
                    "TypeError: object of type '{}' has no len()",
                    type_name(other)
                )));
            }
        };
        *decoded
            .dropped
            .entry("naps_not_imported".to_string())
            .or_insert(0) += count as u64;
    }
    decoded.start_utc = session.start_utc;
    decoded.end_utc = session.end_utc;
    decoded.sleep = Some(session);
    Ok(Some((date, decoded)))
}

// ---- TrainingReadinessDTO ----

const READINESS_FACTORS: [(&str, &str); 6] = [
    ("sleepScoreFactorPercent", "readiness_factor_sleep"),
    (
        "recoveryTimeFactorPercent",
        "readiness_factor_recovery_time",
    ),
    ("acwrFactorPercent", "readiness_factor_load_ratio"),
    (
        "stressHistoryFactorPercent",
        "readiness_factor_stress_history",
    ),
    ("hrvFactorPercent", "readiness_factor_hrv"),
    (
        "sleepHistoryFactorPercent",
        "readiness_factor_sleep_history",
    ),
];

/// One stored record of a file, in the order the oracle writes it.
#[derive(Debug)]
pub enum Step {
    Record {
        key: String,
        index: usize,
        decoded: Box<Decoded>,
    },
    /// A record without a usable date: counted when its stream has a reason, else silent.
    NoDate,
    /// A record this port will not imitate; booked as an `unsupported_json` failure.
    Refused(String),
}

fn timestamp_str(object: &Obj) -> &str {
    match get(object, "timestamp") {
        Some(Value::Str(text)) => text,
        _ => "",
    }
}

/// `decode_readiness_records` over one file: every record with a date and a fresh string
/// timestamp is stored, only the day's chosen one (the morning reset, else the latest) carries
/// facts. The whole batch is decided before the first write, like the oracle's generator.
fn decode_readiness(records: &[Value]) -> (Vec<Step>, Option<String>) {
    let mut by_date: Vec<(String, Vec<usize>)> = Vec::new();
    let mut slot: HashMap<String, usize> = HashMap::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for (index, record) in records.iter().enumerate() {
        let Value::Object(object) = record else {
            continue;
        };
        let date = match calendar_date(get(object, "calendarDate")) {
            Ok(date) => date,
            Err(DecodeError::Abort(message) | DecodeError::Refused(message)) => {
                return (Vec::new(), Some(message));
            }
        };
        let Some(Value::Str(stamp)) = get(object, "timestamp") else {
            continue;
        };
        let Some(date) = date else { continue };
        if !seen.insert(stamp.as_str()) {
            continue;
        }
        let at = *slot.entry(date.clone()).or_insert_with(|| {
            by_date.push((date.clone(), Vec::new()));
            by_date.len() - 1
        });
        by_date[at].1.push(index);
    }
    let obj = |index: usize| -> &Obj {
        match &records[index] {
            Value::Object(members) => members,
            _ => &[],
        }
    };
    let mut steps = Vec::new();
    for (date, day_records) in &by_date {
        let morning: Vec<usize> = day_records
            .iter()
            .copied()
            .filter(|i| is_str(get(obj(*i), "inputContext"), MORNING_CONTEXT))
            .collect();
        let pool = if morning.is_empty() {
            day_records
        } else {
            &morning
        };
        let mut chosen = pool[0];
        for &candidate in &pool[1..] {
            if timestamp_str(obj(candidate)) > timestamp_str(obj(chosen)) {
                chosen = candidate;
            }
        }
        for &index in day_records {
            let record = obj(index);
            let mut decoded = new_decoded("json:readiness");
            let moment = parse_gmt(get(record, "timestamp"));
            decoded.start_utc = moment;
            decoded.end_utc = moment;
            if index == chosen {
                let d = &mut decoded;
                fact(d, date, "training_readiness", get(record, "score"), None);
                for (field, metric) in READINESS_FACTORS {
                    fact(d, date, metric, get(record, field), None);
                }
                fact(
                    d,
                    date,
                    "hrv_weekly_average",
                    get(record, "hrvWeeklyAverage"),
                    Some(0.1),
                );
                fact(d, date, "recovery_time", get(record, "recoveryTime"), None);
                if let Some(Value::Str(level)) = get(record, "level") {
                    label(d, date, "training_readiness_level", level);
                }
                if let Some(Value::Str(context)) = get(record, "inputContext") {
                    label(d, date, "training_readiness_context", context);
                }
            }
            steps.push(Step::Record {
                key: format!("{date}|{}", timestamp_str(record)),
                index,
                decoded: Box::new(decoded),
            });
        }
    }
    (steps, None)
}

// ---- MetricsMaxMetData, MetricsAcuteTrainingLoad, EnduranceScore, HillScore ----

fn decode_maxmet(record: &Obj) -> Decode<Keyed> {
    let Some(date) = calendar_date(get(record, "calendarDate"))? else {
        return Ok(None);
    };
    let mut decoded = new_decoded("json:vo2max");
    let moment = parse_gmt(get(record, "updateTimestamp"));
    decoded.start_utc = moment;
    decoded.end_utc = moment;
    fact(
        &mut decoded,
        &date,
        "vo2max",
        get(record, "vo2MaxValue"),
        Some(0.1),
    );
    if let Some(Value::Str(sport)) = get(record, "sport") {
        label(&mut decoded, &date, "vo2max_sport", sport);
    }
    let key = format!("{date}|{}", key_part(record, "updateTimestamp")?);
    Ok(Some((key, decoded)))
}

fn decode_training_load(record: &Obj) -> Decode<Keyed> {
    let Some(date) = calendar_date(get(record, "calendarDate"))? else {
        return Ok(None);
    };
    let mut decoded = new_decoded("json:training_load");
    let moment = epoch_ms(get(record, "timestamp"))?;
    decoded.start_utc = moment;
    decoded.end_utc = moment;
    let d = &mut decoded;
    fact(
        d,
        &date,
        "training_load_acute",
        get(record, "dailyTrainingLoadAcute"),
        None,
    );
    fact(
        d,
        &date,
        "training_load_chronic",
        get(record, "dailyTrainingLoadChronic"),
        None,
    );
    fact(
        d,
        &date,
        "training_load_ratio",
        get(record, "dailyAcuteChronicWorkloadRatio"),
        None,
    );
    if let Some(Value::Str(status)) = get(record, "acwrStatus") {
        label(d, &date, "training_load_status", status);
    }
    let key = format!("{date}|{}", key_part(record, "timestamp")?);
    Ok(Some((key, decoded)))
}

fn decode_endurance(record: &Obj) -> Decode<Keyed> {
    let Some(date) = calendar_date(get(record, "calendarDate"))? else {
        return Ok(None);
    };
    let mut decoded = new_decoded("json:endurance");
    let moment = epoch_ms(get(record, "timestamp"))?;
    decoded.start_utc = moment;
    decoded.end_utc = moment;
    fact(
        &mut decoded,
        &date,
        "endurance_score",
        get(record, "overallScore"),
        None,
    );
    let key = format!("{date}|{}", key_part(record, "timestamp")?);
    Ok(Some((key, decoded)))
}

fn decode_hill(record: &Obj) -> Decode<Keyed> {
    let Some(date) = calendar_date(get(record, "calendarDate"))? else {
        return Ok(None);
    };
    let mut decoded = new_decoded("json:hill");
    let moment = epoch_ms(get(record, "timestamp"))?;
    decoded.start_utc = moment;
    decoded.end_utc = moment;
    decoded.drop("hill_score_fields_ambiguous");
    let key = format!("{date}|{}", key_part(record, "timestamp")?);
    Ok(Some((key, decoded)))
}

// ---- fitnessAgeData, userBioMetrics ----

fn decode_fitness_age(record: &Obj) -> Decode<Keyed> {
    let Some(date) = calendar_date(get(record, "asOfDateGmt"))? else {
        return Ok(None);
    };
    let mut decoded = new_decoded("json:fitness_age");
    let moment = parse_gmt(get(record, "asOfDateGmt"));
    decoded.start_utc = moment;
    decoded.end_utc = moment;
    fact(
        &mut decoded,
        &date,
        "fitness_age",
        get(record, "currentBioAge"),
        None,
    );
    let key = format!("{date}|{}", key_part(record, "createTimestamp")?);
    Ok(Some((key, decoded)))
}

fn decode_biometrics(record: &Obj) -> Decode<Keyed> {
    let meta = dict_or_empty(get(record, "metaData"))?;
    let Some(date) = calendar_date(get(meta, "calendarDate"))? else {
        return Ok(None);
    };
    let mut decoded = new_decoded("json:biometrics");
    let weight = dict_or_empty(get(record, "weight"))?;
    let moment = parse_gmt(get(weight, "timestampGMT"));
    decoded.start_utc = moment;
    decoded.end_utc = moment;
    if let Some(number) = num(get(weight, "weight")) {
        // Garmin stores weight in grams when the number is large: above 1000 it is converted.
        fact_number(
            &mut decoded,
            &date,
            "weight_kg",
            if number > 1000.0 {
                number / 1000.0
            } else {
                number
            },
            None,
        );
    }
    let key = format!("{date}|{}", key_part(record, "version")?);
    Ok(Some((key, decoded)))
}

type RecordDecoder = fn(&Obj) -> Decode<Keyed>;

/// `RECORD_DECODERS`: the per-record decoder of each stream (`json:readiness` is a batch stream).
fn record_decoder(stream: &str) -> Option<RecordDecoder> {
    Some(match stream {
        "json:uds" => decode_uds,
        "json:sleep" => decode_sleep,
        "json:vo2max" => decode_maxmet,
        "json:training_load" => decode_training_load,
        "json:endurance" => decode_endurance,
        "json:hill" => decode_hill,
        "json:fitness_age" => decode_fitness_age,
        "json:biometrics" => decode_biometrics,
        _ => return None,
    })
}

/// `BATCH_STREAMS`: streams whose canonical value is decided across all their records at once.
pub fn is_batch_stream(stream: &str) -> bool {
    stream == "json:readiness"
}

/// Whether `RECORD_DECODERS` has an entry for `stream`.
pub fn has_record_decoder(stream: &str) -> bool {
    record_decoder(stream).is_some()
}

/// `RECORD_DECODERS[stream](record)` for a record read back from the store (the relay and the
/// reparse path). `Ok(None)` is a decoder that yields nothing (no usable date). A record that is
/// not a JSON object is the oracle's `AttributeError` on `record.get` (an `Abort`). The caller
/// has checked [`has_record_decoder`].
pub fn decode_stored_record(stream: &str, record: &Value) -> Decode<Keyed> {
    let Some(decoder) = record_decoder(stream) else {
        return Err(DecodeError::Abort(format!("KeyError: '{stream}'")));
    };
    match record {
        Value::Object(members) => decoder(members),
        other => Err(DecodeError::Abort(format!(
            "AttributeError: '{}' object has no attribute 'get'",
            type_name(other)
        ))),
    }
}

/// `decode_readiness_records` over every readiness record of the store at once (the relay's
/// store-wide re-batch). The caller has checked that every record is an object.
pub fn decode_readiness_batch(records: &[Value]) -> (Vec<Step>, Option<String>) {
    decode_readiness(records)
}

/// What decoding one file's records yields: the steps in write order, then maybe the abort the
/// oracle's exception would raise right after them.
#[derive(Debug)]
pub struct FileDecode {
    pub records: Vec<Value>,
    pub steps: Vec<Step>,
    pub abort: Option<String>,
}

/// Decode every record of one file of `stream` (the body of `_import_entry` after `_load_json`).
pub fn decode_file(stream: &str, records: Vec<Value>) -> FileDecode {
    if stream == "json:readiness" {
        let (steps, abort) = decode_readiness(&records);
        return FileDecode {
            records,
            steps,
            abort,
        };
    }
    let Some(decoder) = record_decoder(stream) else {
        return FileDecode {
            records,
            steps: Vec::new(),
            abort: Some(format!("KeyError: '{stream}'")),
        };
    };
    let mut steps = Vec::new();
    let mut abort = None;
    for (index, record) in records.iter().enumerate() {
        let Value::Object(object) = record else {
            continue;
        };
        match decoder(object) {
            Ok(Some((key, decoded))) => steps.push(Step::Record {
                key,
                index,
                decoded: Box::new(decoded),
            }),
            Ok(None) => steps.push(Step::NoDate),
            Err(DecodeError::Refused(message)) => steps.push(Step::Refused(message)),
            Err(DecodeError::Abort(message)) => {
                abort = Some(message);
                break;
            }
        }
    }
    FileDecode {
        records,
        steps,
        abort,
    }
}

// ---- importing ----

/// A recognised JSON file of the export and what the oracle derives from its name and mtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub stream: &'static str,
    /// The masked file name (never a table value).
    pub label: String,
    /// The claimed window, clamped so it does not run past the file's own written day.
    pub window: Option<(String, String)>,
    pub written_day: Option<String>,
}

fn plan(entry: &Entry, written_day: Option<String>) -> Option<FileInfo> {
    let stream = stream_for_entry(connect_section(&entry.relpath), entry.name())?;
    let mut window = date_range_in_name(entry.name());
    if let (Some(claimed), Some(written)) = (&window, &written_day)
        && written.as_str() < claimed.1.as_str()
    {
        // a file cannot vouch for days after it was written
        window = Some((claimed.0.clone(), claimed.0.clone().max(written.clone())));
    }
    Some(FileInfo {
        stream,
        label: mask_label(entry.name()),
        window,
        written_day,
    })
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// `import_connect_export`: feed every recognised JSON file of the export to `writer`; everything
/// else counts as ignored. (The FIT corpus is the caller's: [`collect_fit_members`].)
pub fn import_connect_export(path: &Path, writer: &mut Writer<'_>) -> Result<(), SourceError> {
    let mut tree = Tree::open(path)?;
    for index in 0..tree.entries.len() {
        let written = tree.written(index)?;
        let Some(info) = plan(&tree.entries[index], written) else {
            writer.stats.ignored += 1;
            continue;
        };
        import_entry(&mut tree, index, &info, writer)?;
    }
    Ok(())
}

fn import_entry(
    tree: &mut Tree,
    index: usize,
    info: &FileInfo,
    writer: &mut Writer<'_>,
) -> Result<(), SourceError> {
    let stream = info.stream;
    if let Some((from, to)) = &info.window {
        writer.record_export_range(stream, from, to)?;
    }
    let data = tree.read(index)?;
    let bounds = || {
        info.window
            .as_ref()
            .map_or((None, None), |(from, to)| (noon_utc(from), noon_utc(to)))
    };
    let records = match load_json(&data) {
        Loaded::Records(records) => records,
        Loaded::Failed { kind, message } => {
            let (start, end) = bounds();
            writer.record_parse_failure(
                stream,
                &info.label,
                kind,
                &message,
                start,
                end,
                None,
                Some(&sha256_hex(&data)),
                true,
            )?;
            return Ok(());
        }
    };
    let decode = decode_file(stream, records);
    for step in decode.steps {
        match step {
            Step::Record {
                key,
                index,
                decoded,
            } => {
                writer.write_json_record(
                    stream,
                    &key,
                    &decode.records[index],
                    &decoded,
                    &info.label,
                    None,
                )?;
            }
            Step::NoDate => {
                if let Some(reason) = no_date_reason(stream) {
                    *writer.stats.dropped.entry(reason.to_string()).or_insert(0) += 1;
                }
            }
            Step::Refused(message) => {
                let (start, end) = bounds();
                writer.record_parse_failure(
                    stream,
                    &info.label,
                    "unsupported_json",
                    &message,
                    start,
                    end,
                    None,
                    None,
                    true,
                )?;
            }
        }
    }
    match decode.abort {
        Some(message) => Err(SourceError::Abort(message)),
        None => Ok(()),
    }
}

/// One recognised file with its decoded records (or why it failed to load), for tests that
/// compare the decoder with the oracle without a store.
pub struct DecodedFile {
    pub info: FileInfo,
    pub loaded: Result<FileDecode, (&'static str, String)>,
}

/// Walk the export and decode every recognised JSON file, no writing.
pub fn decode_export(path: &Path) -> Result<Vec<DecodedFile>, SourceError> {
    let mut tree = Tree::open(path)?;
    let mut out = Vec::new();
    for index in 0..tree.entries.len() {
        let written = tree.written(index)?;
        let Some(info) = plan(&tree.entries[index], written) else {
            continue;
        };
        let data = tree.read(index)?;
        let loaded = match load_json(&data) {
            Loaded::Records(records) => Ok(decode_file(info.stream, records)),
            Loaded::Failed { kind, message } => Err((kind, message)),
        };
        out.push(DecodedFile { info, loaded });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use rusqlite::Connection;

    use super::*;
    use crate::keys::PassphraseSource;
    use crate::sources::import_path;
    use crate::store;

    fn obj(text: &str) -> Value {
        canon::parse(text.as_bytes()).expect("test JSON")
    }

    fn members(value: &Value) -> &Obj {
        match value {
            Value::Object(members) => members,
            other => panic!("not an object: {other:?}"),
        }
    }

    fn entry_stream(section: &str, name: &str) -> Option<&'static str> {
        stream_for_entry(Some(section), name)
    }

    #[test]
    fn every_family_maps_to_its_stream() {
        let cases = [
            (
                "DI-Connect-Aggregator",
                "UDSFile_2025-06-01_2025-06-30.json",
                "json:uds",
            ),
            (
                "DI-Connect-Wellness",
                "2025-06-01_2025-06-30_{id}_sleepData.json",
                "json:sleep",
            ),
            (
                "DI-Connect-Metrics",
                "TrainingReadinessDTO_{id}_20250101_20250301_1.json",
                "json:readiness",
            ),
            (
                "DI-Connect-Metrics",
                "MetricsMaxMetData_20250101_20250301_{id}.json",
                "json:vo2max",
            ),
            (
                "DI-Connect-Metrics",
                "MetricsAcuteTrainingLoad_20250101_20250301_{id}.json",
                "json:training_load",
            ),
            (
                "DI-Connect-Metrics",
                "EnduranceScore_20250101_20250301_{id}.json",
                "json:endurance",
            ),
            (
                "DI-Connect-Metrics",
                "HillScore_20250101_20250301_{id}.json",
                "json:hill",
            ),
            (
                "DI-Connect-Wellness",
                "{id}_fitnessAgeData.json",
                "json:fitness_age",
            ),
            (
                "DI-Connect-Wellness",
                "{id}_userBioMetrics.json",
                "json:biometrics",
            ),
        ];
        for (section, name, stream) in cases {
            assert_eq!(entry_stream(section, name), Some(stream), "{name}");
        }
        // the extension test is case-insensitive, the family name is not
        assert_eq!(
            entry_stream("DI-Connect-Aggregator", "UDSFile_x.JSON"),
            Some("json:uds")
        );
        assert_eq!(
            entry_stream("DI-Connect-Aggregator", "udsfile_x.json"),
            None
        );
        // wrong section, not JSON, outside DI_CONNECT
        assert_eq!(entry_stream("DI-Connect-Wellness", "UDSFile_x.json"), None);
        assert_eq!(entry_stream("DI-Connect-Aggregator", "UDSFile_x.csv"), None);
        assert_eq!(stream_for_entry(None, "UDSFile_x.json"), None);
        assert_eq!(
            connect_section("a/DI_CONNECT/DI-Connect-Metrics/f.json"),
            Some("DI-Connect-Metrics")
        );
        assert_eq!(connect_section("DI_CONNECT/f.json"), None);
        assert_eq!(connect_section("other/f.json"), None);
    }

    #[test]
    fn date_windows_in_both_name_forms() {
        let range = |name: &str| date_range_in_name(name);
        let pair = |a: &str, b: &str| Some((a.to_string(), b.to_string()));
        assert_eq!(
            range("UDSFile_2025-06-01_2025-06-30.json"),
            pair("2025-06-01", "2025-06-30")
        );
        assert_eq!(
            range("MetricsMaxMetData_20250601_20250630_{id}.json"),
            pair("2025-06-01", "2025-06-30")
        );
        assert_eq!(
            range("x_2025-06-01_2025-06-01_y.json"),
            pair("2025-06-01", "2025-06-01")
        );
        // ISO beats compact; an invalid ISO pair does not fall through to the compact one
        assert_eq!(
            range("20240101_20240102_2025-06-01_2025-06-30"),
            pair("2025-06-01", "2025-06-30")
        );
        assert_eq!(range("2025-13-01_2025-14-01_20240101_20240102"), None);
        // reversed, impossible day, no window, snapshot files
        assert_eq!(range("UDSFile_2025-06-30_2025-06-01.json"), None);
        assert_eq!(range("T_20250231_20250301.json"), None);
        assert_eq!(range("{id}_fitnessAgeData.json"), None);
        // compact form: digit runs around it break the match (look-arounds), like the regex
        assert_eq!(
            range("1_20250601_20250630.json"),
            pair("2025-06-01", "2025-06-30")
        );
        assert_eq!(range("120250601_20250630.json"), None);
        assert_eq!(range("20250601_202506301.json"), None);
        assert_eq!(
            range("a20250601_20250630"),
            pair("2025-06-01", "2025-06-30")
        );
        // year 0000 is not a date
        assert_eq!(range("0000-01-01_0000-01-02"), None);
    }

    #[test]
    fn written_day_follows_the_clamp_and_the_dos_word() {
        assert_eq!(
            written_day_from_ymd(2025, 6, 15),
            Ok(Some("2025-06-15".to_string()))
        );
        assert_eq!(
            written_day_from_ymd(1980, 1, 1),
            Ok(Some("1980-01-01".to_string()))
        );
        assert_eq!(
            written_day_from_ymd(1979, 12, 31),
            Ok(None),
            "before 1980 is unknown"
        );
        assert!(written_day_from_ymd(2025, 2, 30).is_err());
        assert!(written_day_from_ymd(2025, 0, 1).is_err());
        // DOS date: (year-1980) << 9 | month << 5 | day
        assert_eq!(
            written_day_from_dos((45 << 9) | (6 << 5) | 15),
            Ok(Some("2025-06-15".to_string()))
        );
        assert_eq!(
            written_day_from_dos(0x21),
            Ok(Some("1980-01-01".to_string()))
        );
        assert!(
            written_day_from_dos(0).is_err(),
            "month 0, day 0: the oracle's ValueError"
        );
        assert_eq!(day_of_unix_secs(0), "1970-01-01");
        assert_eq!(day_of_unix_secs(-1), "1969-12-31");
        assert_eq!(day_of_unix_secs(1_750_000_000), "2025-06-15");
    }

    #[test]
    fn epoch_ms_rounds_half_even_and_carries_like_fromtimestamp() {
        let at = |ms: f64| epoch_ms_to_utc(ms).map(|m| m.format("%Y-%m-%dT%H:%M:%SZ").to_string());
        assert_eq!(
            at(1_750_000_000_000.0).as_deref(),
            Ok("2025-06-15T15:06:40Z")
        );
        assert_eq!(
            at(1_750_000_000_000.5).as_deref(),
            Ok("2025-06-15T15:06:40Z")
        );
        // the fraction rounds up to a whole second: the second carries
        assert_eq!(
            at(1700000000999.9995).as_deref(),
            Ok("2023-11-14T22:13:21Z")
        );
        assert_eq!(at(1700000000999.999).as_deref(), Ok("2023-11-14T22:13:20Z"));
        // negatives
        assert_eq!(at(-1.0).as_deref(), Ok("1969-12-31T23:59:59Z"));
        assert_eq!(at(-999.9995).as_deref(), Ok("1969-12-31T23:59:59Z"));
        assert_eq!(at(-1000.0005).as_deref(), Ok("1969-12-31T23:59:58Z"));
        assert_eq!(at(0.0005).as_deref(), Ok("1970-01-01T00:00:00Z"));
        // the range of datetime, and what lies beyond it
        assert_eq!(
            at(253_402_300_799_999.0).as_deref(),
            Ok("9999-12-31T23:59:59Z")
        );
        assert!(at(253_402_300_800_000.0).is_err_and(|m| m.starts_with("ValueError")));
        assert_eq!(
            at(-62_135_596_800_000.0).as_deref(),
            Ok("0001-01-01T00:00:00Z")
        );
        assert!(at(-62_135_596_800_001.0).is_err_and(|m| m.starts_with("ValueError")));
        assert!(at(1e300).is_err_and(|m| m.starts_with("OverflowError")));
        assert!(at(1e20).is_err_and(|m| m.starts_with("OSError")));
    }

    #[test]
    fn gmt_strings_parse_like_strptime() {
        let at = |text: &str| {
            parse_gmt(Some(&Value::Str(text.to_string())))
                .map(|m| m.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        };
        assert_eq!(
            at("2025-06-15T04:00:00.0").as_deref(),
            Some("2025-06-15T04:00:00Z")
        );
        assert_eq!(
            at("2025-06-15T04:00:00").as_deref(),
            Some("2025-06-15T04:00:00Z")
        );
        assert_eq!(at("2025-06-15 04:00:00"), None);
        assert_eq!(at("2025-06-15T04:00"), None);
        assert_eq!(at("2025-02-30T04:00:00"), None);
        assert_eq!(at("2025-06-15T24:00:00"), None);
        assert_eq!(at("2025-06-15T04:00:60"), None);
        assert_eq!(at("0000-06-15T04:00:00"), None);
        assert_eq!(
            at("2025-06- 5T04:00:00").as_deref(),
            Some("2025-06-05T04:00:00Z")
        );
        assert_eq!(parse_gmt(Some(&Value::Int(5))), None);
        assert_eq!(parse_gmt(None), None);
        assert_eq!(
            calendar_date(Some(&Value::Str("2025-06-15T04:00:00.0".to_string()))),
            Ok(Some("2025-06-15".to_string()))
        );
        assert_eq!(
            calendar_date(Some(&Value::Str("short".to_string()))),
            Ok(None)
        );
        assert_eq!(
            calendar_date(Some(&Value::Int(1_750_000_000_000))),
            Ok(Some("2025-06-15".to_string()))
        );
        assert_eq!(calendar_date(Some(&Value::Bool(true))), Ok(None));
    }

    #[test]
    fn source_keys_are_built_with_pythons_str() {
        let key = |text: &str| -> Result<Option<String>, DecodeError> {
            let record = obj(text);
            Ok(decode_training_load(members(&record))?.map(|(key, _)| key))
        };
        let some = |s: &str| Ok(Some(s.to_string()));
        assert_eq!(
            key(r#"{"calendarDate":"2025-06-15","timestamp":1750000000000}"#),
            some("2025-06-15|1750000000000")
        );
        assert_eq!(
            key(r#"{"calendarDate":"2025-06-15","timestamp":1750000000000.5}"#),
            some("2025-06-15|1750000000000.5")
        );
        assert_eq!(
            key(r#"{"calendarDate":"2025-06-15","timestamp":1750000000000.0}"#),
            some("2025-06-15|1750000000000.0")
        );
        assert_eq!(
            key(r#"{"calendarDate":"2025-06-15","timestamp":null}"#),
            some("2025-06-15|None")
        );
        assert_eq!(
            key(r#"{"calendarDate":"2025-06-15","timestamp":true}"#),
            some("2025-06-15|True")
        );
        assert_eq!(
            key(r#"{"calendarDate":"2025-06-15","timestamp":false}"#),
            some("2025-06-15|False")
        );
        assert_eq!(key(r#"{"calendarDate":"2025-06-15"}"#), some("2025-06-15|"));
        assert_eq!(
            key(r#"{"calendarDate":"2025-06-15","timestamp":"text"}"#),
            some("2025-06-15|text")
        );
        assert!(matches!(
            key(r#"{"calendarDate":"2025-06-15","timestamp":[1]}"#),
            Err(DecodeError::Refused(_))
        ));
        assert!(matches!(
            key(r#"{"calendarDate":"2025-06-15","timestamp":{}}"#),
            Err(DecodeError::Refused(_))
        ));
        assert_eq!(key(r#"{"timestamp":1}"#), Ok(None), "no date, no record");
        // the other key shapes
        let record = obj(
            r#"{"calendarDate":"2025-06-15","updateTimestamp":"2025-06-15T01:02:03.0","sport":"RUNNING","vo2MaxValue":0.05}"#,
        );
        let (key, decoded) = decode_maxmet(members(&record))
            .expect("decodes")
            .expect("has a date");
        assert_eq!(key, "2025-06-15|2025-06-15T01:02:03.0");
        assert_eq!(
            decoded.dropped.get("vo2max_below_minimum"),
            Some(&1),
            "minimum= threshold"
        );
        assert_eq!(decoded.labels[0].label, "running", "labels are lower-cased");
        let record = obj(
            r#"{"asOfDateGmt":"2025-06-15T00:00:00.0","createTimestamp":1,"currentBioAge":31.5}"#,
        );
        assert_eq!(
            decode_fitness_age(members(&record))
                .expect("decodes")
                .expect("date")
                .0,
            "2025-06-15|1"
        );
        let record = obj(
            r#"{"metaData":{"calendarDate":"2025-06-15"},"version":7,"weight":{"weight":81500,"timestampGMT":"2025-06-15T05:00:00.0"}}"#,
        );
        let (key, decoded) = decode_biometrics(members(&record))
            .expect("decodes")
            .expect("date");
        assert_eq!(key, "2025-06-15|7");
        assert_eq!(
            decoded.daily[0].value, 81.5,
            "grams become kilograms above 1000"
        );
        let record = obj(r#"{"metaData":{"calendarDate":"2025-06-15"},"weight":{"weight":81.5}}"#);
        let (key, decoded) = decode_biometrics(members(&record))
            .expect("decodes")
            .expect("date");
        assert_eq!(
            (key.as_str(), decoded.daily[0].value),
            ("2025-06-15|", 81.5)
        );
        // a non-dict where the oracle calls .get: an uncaught AttributeError
        let record = obj(r#"{"metaData":[1],"weight":{}}"#);
        assert!(
            matches!(decode_biometrics(members(&record)), Err(DecodeError::Abort(m)) if m.starts_with("AttributeError"))
        );
    }

    fn ready(date: &str, stamp: &str, context: &str, score: i64) -> String {
        format!(
            r#"{{"calendarDate":"{date}","timestamp":"{stamp}","inputContext":"{context}","score":{score},"level":"HIGH"}}"#
        )
    }

    #[test]
    fn readiness_batch_picks_the_morning_reset_else_the_latest_and_stores_every_record() {
        let text = format!(
            "[{}]",
            [
                ready(
                    "2025-06-15",
                    "2025-06-15T15:00:00.0",
                    "UPDATE_REALTIME_VARIABLES",
                    60
                ),
                ready(
                    "2025-06-15",
                    "2025-06-15T04:00:00.0",
                    "AFTER_WAKEUP_RESET",
                    77
                ),
                ready(
                    "2025-06-15",
                    "2025-06-15T15:00:00.0",
                    "UPDATE_REALTIME_VARIABLES",
                    99
                ), // duplicate stamp
                ready(
                    "2025-06-15",
                    "2025-06-15T05:00:00.0",
                    "AFTER_WAKEUP_RESET",
                    78
                ), // later morning wins
                ready(
                    "2025-06-16",
                    "2025-06-16T09:00:00.0",
                    "POST_EXERCISE_RESET",
                    50
                ),
                ready(
                    "2025-06-16",
                    "2025-06-16T18:00:00.0",
                    "UPDATE_REALTIME_VARIABLES",
                    55
                ), // latest wins
                r#"{"calendarDate":"2025-06-17","timestamp":5}"#.to_string(), // not a string stamp
                r#"{"timestamp":"2025-06-18T01:00:00.0"}"#.to_string(),       // no date
            ]
            .join(",")
        );
        let Loaded::Records(records) = load_json(text.as_bytes()) else {
            panic!("loads")
        };
        let decode = decode_file("json:readiness", records);
        assert!(decode.abort.is_none());
        let stored: Vec<(&str, bool)> = decode
            .steps
            .iter()
            .map(|s| match s {
                Step::Record { key, decoded, .. } => (key.as_str(), !decoded.daily.is_empty()),
                other => panic!("unexpected step {other:?}"),
            })
            .collect();
        assert_eq!(
            stored,
            [
                // days in first-seen order, records in file order inside a day; only the chosen one has facts
                ("2025-06-15|2025-06-15T15:00:00.0", false),
                ("2025-06-15|2025-06-15T04:00:00.0", false),
                ("2025-06-15|2025-06-15T05:00:00.0", true),
                ("2025-06-16|2025-06-16T09:00:00.0", false),
                ("2025-06-16|2025-06-16T18:00:00.0", true),
            ]
        );
        let Step::Record { decoded, .. } = &decode.steps[2] else {
            panic!()
        };
        assert_eq!(decoded.daily[0].value, 78.0);
        assert_eq!(
            decoded
                .labels
                .iter()
                .map(|l| l.label.as_str())
                .collect::<Vec<_>>(),
            ["high", "after_wakeup_reset"]
        );
        // an epoch-ms calendarDate that overflows aborts before any record is produced
        let Loaded::Records(records) = load_json(br#"[{"calendarDate":1e300,"timestamp":"x"}]"#)
        else {
            panic!()
        };
        let decode = decode_file("json:readiness", records);
        assert!(
            decode.steps.is_empty() && decode.abort.is_some_and(|m| m.starts_with("OverflowError"))
        );
    }

    #[test]
    fn json_loading_follows_load_json() {
        assert!(
            matches!(load_json(b"[{\"a\":1},3,\"x\",{\"b\":2}]"), Loaded::Records(r) if r.len() == 2)
        );
        assert!(matches!(load_json(b"{\"a\":1}"), Loaded::Records(r) if r.len() == 1));
        assert!(matches!(load_json(b"[]"), Loaded::Records(r) if r.is_empty()));
        for bad in [
            &b"3"[..],
            b"\"x\"",
            b"null",
            b"[1,",
            b"",
            b"\xef\xbb\xbf[]",
            b"\xff",
        ] {
            assert!(
                matches!(
                    load_json(bad),
                    Loaded::Failed {
                        kind: "bad_json",
                        ..
                    }
                ),
                "{bad:?}"
            );
        }
        // Python accepts these; this port refuses them
        for refused in [
            &b"[NaN]"[..],
            b"[{\"a\":1e999}]",
            b"[{\"a\":\"\\ud800\"}]",
            b"[{\"a\":9223372036854775808}]",
        ] {
            assert!(
                matches!(
                    load_json(refused),
                    Loaded::Failed {
                        kind: "unsupported_json",
                        ..
                    }
                ),
                "{refused:?}"
            );
        }
    }

    fn store_in(dir: &Path) -> store::Store {
        store::open_for_write(&dir.join("t.db"), "test", 5.0, PassphraseSource::Env)
            .expect("open store")
    }

    fn write(dir: &Path, relative: &str, text: &str) {
        let path = dir.join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, text).expect("write");
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).expect("count")
    }

    #[test]
    fn dateless_records_are_counted_by_stream_and_failures_carry_the_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("export");
        write(
            &root,
            "DI_CONNECT/DI-Connect-Aggregator/UDSFile_2025-06-01_2025-06-03.json",
            r#"[{"calendarDate":"2025-06-01","totalSteps":10},{"totalSteps":5},{"calendarDate":"2025-06-02","includesWellnessData":false}]"#,
        );
        write(
            &root,
            "DI_CONNECT/DI-Connect-Wellness/2025-06-01_2025-06-03_1_sleepData.json",
            r#"[{"retro":false},{"retro":true}]"#,
        );
        write(
            &root,
            "DI_CONNECT/DI-Connect-Metrics/HillScore_20250601_20250603_1.json",
            r#"[{"timestamp":1750000000000}]"#,
        );
        let garbage = "not json at all";
        write(
            &root,
            "DI_CONNECT/DI-Connect-Metrics/EnduranceScore_20250601_20250603_1.json",
            garbage,
        );
        write(&root, "DI_CONNECT/DI-Connect-Metrics/ignored.txt", "x");
        write(&root, "elsewhere/notes.json", "[]");
        let store = store_in(dir.path());
        let conn = store.conn();
        let stats = import_path(conn, &root, None).expect("import");
        assert_eq!(stats.transport, "connect_export");
        assert_eq!(stats.dropped.get("uds_without_date"), Some(&1));
        assert_eq!(
            stats.dropped.get("sleep_stub_without_date"),
            Some(&2),
            "a retro stub has no date either"
        );
        assert_eq!(stats.dropped.get("uds_day_without_wellness_data"), Some(&1));
        assert_eq!(
            stats.dropped.get("hill_score_fields_ambiguous"),
            None,
            "a dateless hill record is silent"
        );
        assert_eq!(stats.ignored, 2);
        assert_eq!((stats.files_imported, stats.files_failed), (2, 1));
        assert_eq!(stats.status(), "partial");
        // the failure: kind, whole-file hash, noon bounds of the clamp-free window
        let (kind, hash, start, end, stream): (String, String, String, String, String) = conn
            .query_row(
                "SELECT kind, payload_hash, start_utc, end_utc, stream FROM import_failures",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .expect("one failure row");
        assert_eq!(
            (kind.as_str(), stream.as_str()),
            ("bad_json", "json:endurance")
        );
        assert_eq!(hash, sha256_hex(garbage.as_bytes()));
        assert_eq!(
            (start.as_str(), end.as_str()),
            ("2025-06-01T12:00:00Z", "2025-06-03T12:00:00Z")
        );
        assert_eq!(count(conn, "SELECT count(*) FROM export_ranges"), 4);
        // JSON facts carry no observation time
        assert_eq!(
            count(
                conn,
                "SELECT count(*) FROM daily_metrics WHERE source_scope='vendor_cloud' AND observed_utc IS NOT NULL"
            ),
            0
        );
        // a second import is all duplicates and books the same failure once
        let again = import_path(conn, &root, None).expect("second import");
        assert_eq!((again.files_imported, again.files_duplicate), (0, 2));
        assert_eq!(count(conn, "SELECT count(*) FROM import_failures"), 1);
    }

    #[test]
    fn the_window_is_clamped_to_the_day_the_file_was_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let zip_path = dir.path().join("export.zip");
        let mut writer = zip::ZipWriter::new(fs::File::create(&zip_path).expect("create zip"));
        // the zip crate's default DOS date is 1980-01-01
        let options = zip::write::SimpleFileOptions::default();
        for name in [
            "DI_CONNECT/DI-Connect-Aggregator/UDSFile_2025-06-10_2025-06-12.json",
            "DI_CONNECT/DI-Connect-Metrics/EnduranceScore_20250610_20250612_1.json",
        ] {
            writer.start_file(name, options).expect("start");
            writer.write_all(b"[]").expect("write");
        }
        writer.finish().expect("finish");
        let store = store_in(dir.path());
        let conn = store.conn();
        import_path(conn, &zip_path, None).expect("import");
        let ranges: Vec<(String, String, String)> = conn
            .prepare("SELECT stream, from_day, to_day FROM export_ranges ORDER BY stream")
            .expect("prepare")
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        // written 1980-01-01 is before the claimed start: the window collapses to its first day
        assert_eq!(
            ranges,
            [
                (
                    "json:endurance".to_string(),
                    "2025-06-10".to_string(),
                    "2025-06-10".to_string()
                ),
                (
                    "json:uds".to_string(),
                    "2025-06-10".to_string(),
                    "2025-06-10".to_string()
                )
            ]
        );
    }

    #[test]
    fn an_inner_bad_zip_aborts_the_run_with_a_run_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("export");
        write(
            &root,
            "DI_CONNECT/DI-Connect-Aggregator/UDSFile_2025-06-01_2025-06-03.json",
            r#"[{"calendarDate":"2025-06-01","totalSteps":10}]"#,
        );
        write(
            &root,
            "DI_CONNECT/DI-Connect-Uploaded-Files/UploadedFiles_0-_Part1.zip",
            "this is not a zip",
        );
        let store = store_in(dir.path());
        let conn = store.conn();
        let error = import_path(conn, &root, None).expect_err("aborts");
        assert!(
            matches!(&error, SourceError::Abort(m) if m.starts_with("BadZipFile")),
            "{error}"
        );
        let (status, error_text): (String, Option<String>) = conn
            .query_row("SELECT status, error FROM import_runs", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .expect("run row");
        assert_eq!(status, "failed");
        assert!(error_text.is_some_and(|t| t.starts_with("BadZipFile")));
        assert_eq!(
            count(conn, "SELECT count(*) FROM raw_records"),
            0,
            "FIT members are collected before anything is written"
        );
    }

    #[test]
    fn an_epoch_ms_overflow_mid_file_aborts_after_the_earlier_records_are_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("export");
        write(
            &root,
            "DI_CONNECT/DI-Connect-Metrics/MetricsAcuteTrainingLoad_20250601_20250603_1.json",
            r#"[{"calendarDate":"2025-06-01","timestamp":1748736000000,"dailyTrainingLoadAcute":10},{"calendarDate":"2025-06-02","timestamp":1e300}]"#,
        );
        write(
            &root,
            "DI_CONNECT/DI-Connect-Metrics/ZZ_not_reached.json",
            "[]",
        );
        let store = store_in(dir.path());
        let conn = store.conn();
        let error = import_path(conn, &root, None).expect_err("aborts");
        assert!(
            matches!(&error, SourceError::Abort(m) if m.starts_with("OverflowError")),
            "{error}"
        );
        assert_eq!(
            count(
                conn,
                "SELECT count(*) FROM raw_records WHERE stream='json:training_load'"
            ),
            1
        );
        let (status, files_imported): (String, i64) = conn
            .query_row("SELECT status, files_imported FROM import_runs", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .expect("run row");
        assert_eq!((status.as_str(), files_imported), ("failed", 1));
    }

    #[test]
    fn a_container_in_a_key_position_is_booked_and_the_file_goes_on() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("export");
        write(
            &root,
            "DI_CONNECT/DI-Connect-Metrics/EnduranceScore_20250601_20250603_1.json",
            r#"[{"calendarDate":"2025-06-01","timestamp":[1],"overallScore":5},{"calendarDate":"2025-06-02","timestamp":1748822400000,"overallScore":6}]"#,
        );
        let store = store_in(dir.path());
        let conn = store.conn();
        let stats = import_path(conn, &root, None).expect("import");
        assert_eq!((stats.files_imported, stats.files_failed), (1, 1));
        let kind: String = conn
            .query_row("SELECT kind FROM import_failures", [], |r| r.get(0))
            .expect("failure row");
        assert_eq!(kind, "unsupported_json");
    }

    #[test]
    fn a_folder_named_di_connect_is_walked_from_its_parent_and_files_come_sorted_by_component() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("export");
        for name in [
            "DI_CONNECT/b.json",
            "DI_CONNECT/a-b/c.json",
            "DI_CONNECT/a/c.json",
            "sibling.txt",
        ] {
            write(&root, name, "[]");
        }
        let tree = Tree::open(&root.join("DI_CONNECT")).expect("open");
        let names: Vec<&str> = tree.entries.iter().map(|e| e.relpath.as_str()).collect();
        assert_eq!(
            names,
            [
                "DI_CONNECT/a/c.json",
                "DI_CONNECT/a-b/c.json",
                "DI_CONNECT/b.json",
                "sibling.txt"
            ]
        );
        assert!(
            tree.entries
                .iter()
                .all(|e| e.written.as_ref().is_ok_and(Option::is_some))
        );
    }
}
