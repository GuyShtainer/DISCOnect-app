// SPDX-License-Identifier: AGPL-3.0-or-later
//! Persist decoded facts: raw bytes first, canonical rows second, provenance always. The twin of
//! `disconect/ingest/writer.py`; see `docs/writer-spec.md` (the Python wins on any disagreement).
//!
//! One transaction per source file, so a failure mid-file rolls back that file only. A file whose
//! bytes are already in `raw_records` is a duplicate and is skipped without decoding.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

use chrono::Duration;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use rusqlite::{Connection, OptionalExtension, ToSql, params};
use serde::Serialize;
use serde_json::ser::Formatter;
use sha2::{Digest, Sha256};

use crate::canon;
use crate::clock::ClockOffsets;
use crate::fit::{self, FitDecodeError};
use crate::model::{Decoded, Instant, SleepSession};
use crate::redact::redact_text;
use crate::time::{iso_utc, parse_iso_utc, utc_now_iso};

/// Readings further apart than this are not consecutive: the watch recorded nothing in between.
const STEP_GAP_MAX_S: i64 = 15 * 60;

#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Compress(String),
    /// A span stamp that is not the store's shape: `parse_iso_utc` raises `ValueError` in the
    /// oracle's `keep_undecodable_record`, outside any handler, so the pull aborts.
    #[error("{0}")]
    BadStamp(String),
}

/// Writes that must share the transaction of one record's write (the relay retires a conflict's
/// loser with it); an error from the hook rolls the whole transaction back.
pub type BeforeWrite<'a> = &'a dyn Fn(&Writer<'_>) -> rusqlite::Result<()>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    Imported,
    Duplicate,
    Failed,
    /// `rewrite_canonical` replaced a raw record's canonical rows.
    Reparsed,
    /// Bytes retained for a decoder this build lacks; no canonical rows.
    Kept,
}

// ---- Python-faithful numerics ----

/// Python's `round(x, ndigits)` for a float: the exact decimal expansion of the double rounded
/// half to even (CPython's `double_round`, via correctly-rounded dtoa), read back as the nearest double.
pub fn py_round(x: f64, ndigits: usize) -> f64 {
    if !x.is_finite() {
        return x;
    }
    format!("{x:.ndigits$}").parse::<f64>().unwrap_or(x)
}

/// Python's `round(x, 3)`.
pub fn round3(x: f64) -> f64 {
    py_round(x, 3)
}

/// Python 3.12+ `sum()` of floats: Neumaier-compensated, the compensation added at the end. The
/// start value is the int 0, so the first item enters as `0 + x`.
pub fn py_sum(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut it = values.into_iter();
    let Some(first) = it.next() else { return 0.0 };
    let mut sum = 0.0 + first;
    let mut c = 0.0_f64;
    for x in it {
        let t = sum + x;
        if sum.abs() >= x.abs() {
            c += (sum - t) + x;
        } else {
            c += (x - t) + sum;
        }
        sum = t;
    }
    if c != 0.0 && c.is_finite() {
        sum += c;
    }
    sum
}

/// Signed changes between consecutive readings of one local day, time-ordered, gaps skipped.
/// The day's first reading has no predecessor.
fn steps(readings: &[(i64, f64)]) -> Vec<f64> {
    let mut ordered = readings.to_vec();
    ordered.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)));
    ordered.windows(2).filter(|w| w[1].0 - w[0].0 <= STEP_GAP_MAX_S).map(|w| w[1].1 - w[0].1).collect()
}

/// Sum of the positive changes (energy gained).
pub fn charged(readings: &[(i64, f64)]) -> f64 {
    py_sum(steps(readings).into_iter().filter(|s| *s > 0.0))
}

/// Sum of the negative changes, sign flipped (energy spent).
pub fn drained(readings: &[(i64, f64)]) -> f64 {
    py_sum(steps(readings).into_iter().filter(|s| *s < 0.0).map(|s| -s))
}

#[derive(Clone, Copy)]
enum Reducer {
    Mean,
    Min,
    Max,
    Charged,
    Drained,
}

impl Reducer {
    fn apply(self, readings: &[(i64, f64)]) -> f64 {
        match self {
            Reducer::Mean => py_sum(readings.iter().map(|r| r.1)) / readings.len() as f64,
            Reducer::Min => readings.iter().map(|r| r.1).fold(f64::INFINITY, |a, b| if b < a { b } else { a }),
            Reducer::Max => readings.iter().map(|r| r.1).fold(f64::NEG_INFINITY, |a, b| if b > a { b } else { a }),
            Reducer::Charged => charged(readings),
            Reducer::Drained => drained(readings),
        }
    }
}

/// (sample metric, daily metric, reducer) derived per local day from the samples written this run.
const DERIVED_FROM_SAMPLES: [(&str, &str, Reducer); 7] = [
    ("stress", "stress_avg", Reducer::Mean),
    ("heart_rate", "heart_rate_min", Reducer::Min),
    ("heart_rate", "heart_rate_max", Reducer::Max),
    ("energy_reserve", "energy_reserve_high", Reducer::Max),
    ("energy_reserve", "energy_reserve_low", Reducer::Min),
    ("energy_reserve", "energy_reserve_charged", Reducer::Charged),
    ("energy_reserve", "energy_reserve_drained", Reducer::Drained),
];

// ---- stats ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub file: String,
    /// The record's stream. Only a reparse dry run sets it (Python's `_dry_run` failures carry it,
    /// the writer's own failures do not), and the `--json` output emits the key only then.
    pub stream: Option<String>,
    pub kind: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct ImportStats {
    pub transport: String,
    pub files_seen: i64,
    pub files_imported: i64,
    pub files_duplicate: i64,
    pub files_failed: i64,
    pub records_written: i64,
    pub ignored: i64,
    pub streams: BTreeMap<String, BTreeMap<String, i64>>,
    pub dropped: BTreeMap<String, i64>,
    pub failures: Vec<Failure>,
    pub warnings: Vec<String>,
    pub dates_assumed_utc: u64,
    pub derived_days: i64,
    /// The run was cancelled after a file (`import.cancel`): the counters are what it read before that.
    pub cancelled: bool,
}

impl ImportStats {
    pub fn new(transport: &str) -> Self {
        ImportStats {
            transport: transport.to_string(),
            files_seen: 0,
            files_imported: 0,
            files_duplicate: 0,
            files_failed: 0,
            records_written: 0,
            ignored: 0,
            streams: BTreeMap::new(),
            dropped: BTreeMap::new(),
            failures: Vec::new(),
            warnings: Vec::new(),
            dates_assumed_utc: 0,
            derived_days: 0,
            cancelled: false,
        }
    }

    /// `cancelled` (the caller's cancel check answered True), `ok`, `partial` (some failed) or `failed` (some
    /// failed and none imported).
    pub fn status(&self) -> &'static str {
        if self.cancelled {
            "cancelled"
        } else if self.files_failed > 0 && self.files_imported == 0 {
            "failed"
        } else if self.files_failed > 0 {
            "partial"
        } else {
            "ok"
        }
    }

    fn bump_stream(&mut self, stream: &str, key: &str, count: i64) {
        *self.streams.entry(stream.to_string()).or_default().entry(key.to_string()).or_insert(0) += count;
    }

    /// The CLI summary, line for line the Python `_import_summary` (counts and masked names only).
    pub fn summary_lines(&self) -> Vec<String> {
        let ignored = if self.ignored > 0 { format!(", {} files ignored", self.ignored) } else { String::new() };
        let mut lines = vec![format!(
            "{}: {} imported, {} duplicate, {} failed, {} rows written{}",
            self.status(),
            self.files_imported,
            self.files_duplicate,
            self.files_failed,
            self.records_written,
            ignored
        )];
        for (stream, counts) in &self.streams {
            lines.push(format!(
                "  {:<18} {:>5} files  {:>8} rows",
                stream,
                counts.get("files").copied().unwrap_or(0),
                counts.get("records").copied().unwrap_or(0)
            ));
        }
        if self.derived_days > 0 {
            lines.push(format!("  derived daily steps/distance for {} day(s)", self.derived_days));
        }
        if !self.dropped.is_empty() {
            let dropped: Vec<String> = self.dropped.iter().map(|(k, v)| format!("{k}={v}")).collect();
            lines.push(format!("  dropped (never stored as numbers): {}", dropped.join(", ")));
        }
        if self.dates_assumed_utc > 0 {
            lines.push(format!(
                "  WARNING: {} daily values dated in UTC -- no watch clock offset known",
                self.dates_assumed_utc
            ));
        }
        for failure in self.failures.iter().take(10) {
            lines.push(format!("  FAILED {}: [{}] {}", failure.file, failure.kind, failure.error));
        }
        if self.failures.len() > 10 {
            lines.push(format!("  ... and {} more failures", self.failures.len() - 10));
        }
        lines
    }
}

// ---- helpers ----

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// zlib at level 6, with the round trip proved before the bytes are trusted to disk.
fn compress_verified(data: &[u8]) -> Result<Vec<u8>, WriterError> {
    let fail = |e: std::io::Error| WriterError::Compress(format!("zlib: {e}"));
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(data).map_err(fail)?;
    let packed = encoder.finish().map_err(fail)?;
    let mut back = Vec::with_capacity(data.len());
    ZlibDecoder::new(packed.as_slice()).read_to_end(&mut back).map_err(fail)?;
    if back != data {
        return Err(WriterError::Compress("compressed payload does not round-trip".to_string()));
    }
    Ok(packed)
}

/// `json.dumps` separators (`", "` and `": "`) so `decode_summary` reads like the Python store's.
struct PythonSeparators;

impl Formatter for PythonSeparators {
    fn begin_array_value<W: ?Sized + Write>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()> {
        if first { Ok(()) } else { writer.write_all(b", ") }
    }
    fn begin_object_key<W: ?Sized + Write>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()> {
        if first { Ok(()) } else { writer.write_all(b", ") }
    }
    fn begin_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(b": ")
    }
}

fn decode_summary_json(decoded: &Decoded) -> String {
    #[derive(Serialize)]
    struct Summary<'a> {
        dropped: &'a BTreeMap<String, u64>,
        messages: &'a BTreeMap<String, u64>,
        warnings: &'a [String],
    }
    let summary = Summary {
        dropped: &decoded.dropped,
        messages: &decoded.message_counts,
        warnings: &decoded.warnings[..decoded.warnings.len().min(10)],
    };
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, PythonSeparators);
    if summary.serialize(&mut serializer).is_err() {
        return "{}".to_string();
    }
    String::from_utf8(out).unwrap_or_else(|_| "{}".to_string())
}

/// The `decode_summary` of a JSON record: `{"dropped": ..., "warnings": warnings[:10]}`.
pub fn json_summary(decoded: &Decoded) -> canon::Value {
    canon::Value::Object(vec![
        ("dropped".to_string(), counts_value(&decoded.dropped)),
        ("warnings".to_string(), warnings_value(&decoded.warnings)),
    ])
}

/// The `decode_summary` of a FIT file: `{"messages": ..., "dropped": ..., "warnings": warnings[:10]}`.
pub fn fit_summary(decoded: &Decoded) -> canon::Value {
    canon::Value::Object(vec![
        ("messages".to_string(), counts_value(&decoded.message_counts)),
        ("dropped".to_string(), counts_value(&decoded.dropped)),
        ("warnings".to_string(), warnings_value(&decoded.warnings)),
    ])
}

fn counts_value(counts: &BTreeMap<String, u64>) -> canon::Value {
    canon::Value::Object(
        counts
            .iter()
            .map(|(k, v)| (k.clone(), canon::Value::Int(i64::try_from(*v).unwrap_or(i64::MAX))))
            .collect(),
    )
}

fn warnings_value(warnings: &[String]) -> canon::Value {
    canon::Value::Array(warnings.iter().take(10).map(|w| canon::Value::Str(w.clone())).collect())
}

fn iso_opt(moment: &Option<Instant>) -> Option<String> {
    moment.as_ref().map(iso_utc)
}

/// (min, max) over instants, widened by an earlier span.
fn widen(span: &mut Option<(Instant, Instant)>, low: Instant, high: Instant) {
    *span = Some(match *span {
        None => (low, high),
        Some((a, b)) => (low.min(a), high.max(b)),
    });
}

fn device_key(device: &Option<String>) -> String {
    device.clone().unwrap_or_default()
}

/// (ts_utc, activity_type, steps, distance_m, raw_record_id) of one monitoring interval.
type IntervalRow = (String, String, Option<i64>, Option<f64>, i64);
/// One activity type's running maxima for a day: (type, steps, distance).
type TypeMax = (String, Option<i64>, Option<f64>);

/// What `store_raw` needs besides the decoded facts.
/// The sender's own fields of a relayed record (`row` of `keep_undecodable_record`).
pub struct KeptRow<'a> {
    pub source_scope: &'a str,
    pub device_id: Option<&'a str>,
    pub start_utc: Option<&'a str>,
    pub end_utc: Option<&'a str>,
}

struct RawInput<'a> {
    stream: &'a str,
    source_key: &'a str,
    kind: &'a str,
    packed: &'a [u8],
    payload_hash: &'a str,
    data_len: usize,
    summary: &'a str,
    origin: Option<(&'a str, &'a str)>,
}

// ---- the writer ----

/// Writes one import run.
pub struct Writer<'c> {
    conn: &'c Connection,
    pub offsets: ClockOffsets,
    pub stats: ImportStats,
    run_id: Option<i64>,
    interval_span: Option<(Instant, Instant)>,
    interval_devices: BTreeSet<Option<String>>,
    sample_span: Option<(Instant, Instant)>,
    sample_devices: BTreeSet<Option<String>>,
    /// Raw ids of the `json:live` records this run stored (a duplicate is not stored).
    live_run_ids: BTreeSet<i64>,
}

impl<'c> Writer<'c> {
    pub fn new(conn: &'c Connection, offsets: ClockOffsets, transport: &str) -> Self {
        Writer {
            conn,
            offsets,
            stats: ImportStats::new(transport),
            run_id: None,
            interval_span: None,
            interval_devices: BTreeSet::new(),
            sample_span: None,
            sample_devices: BTreeSet::new(),
            live_run_ids: BTreeSet::new(),
        }
    }

    // ---- run bookkeeping ----

    pub fn begin_run(&mut self) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO import_runs(started_at, transport, status) VALUES(?, ?, 'running')",
            params![utc_now_iso(), self.stats.transport],
        )?;
        let id = self.conn.last_insert_rowid();
        self.run_id = Some(id);
        Ok(id)
    }

    pub fn finish_run(&self, error: Option<&str>) -> rusqlite::Result<()> {
        let stats = &self.stats;
        let status = if error.is_some() { "failed" } else { stats.status() };
        self.conn.execute(
            "UPDATE import_runs SET finished_at=?, status=?, files_seen=?, files_imported=?, \
             files_duplicate=?, files_failed=?, records_written=?, error=? WHERE id=?",
            params![
                utc_now_iso(),
                status,
                stats.files_seen,
                stats.files_imported,
                stats.files_duplicate,
                stats.files_failed,
                stats.records_written,
                error.map(redact_text),
                self.run_id
            ],
        )?;
        Ok(())
    }

    // ---- provenance ----

    fn provenance(
        &self,
        stream: &str,
        stage: &str,
        ok: bool,
        kind: Option<&str>,
        message: Option<&str>,
        records: i64,
    ) -> rusqlite::Result<()> {
        let now = utc_now_iso();
        self.conn.execute(
            "INSERT OR IGNORE INTO stream_provenance(stream, updated_at) VALUES(?, ?)",
            params![stream, now],
        )?;
        if ok {
            self.conn.execute(
                &format!(
                    "UPDATE stream_provenance SET last_{stage}_ok_at=?, updated_at=?, \
                     files_ok = files_ok + ?, records_written = records_written + ? WHERE stream=?"
                ),
                params![now, now, i64::from(stage == "write"), records, stream],
            )?;
        } else {
            let redacted: String = redact_text(message.unwrap_or("")).chars().take(500).collect();
            self.conn.execute(
                &format!(
                    "UPDATE stream_provenance SET last_{stage}_error_at=?, last_{stage}_error_kind=?, \
                     last_{stage}_error_message=?, updated_at=?, files_failed = files_failed + 1 \
                     WHERE stream=?"
                ),
                params![now, kind, redacted, now, stream],
            )?;
        }
        Ok(())
    }

    /// Record that one record's bytes could not be decoded, without raising. The span is whatever
    /// was knowable (`start_utc`/`end_utc`, or the retained record's own via `raw_record_id`);
    /// `payload_hash` makes re-importing the same broken bytes record it once; `placeable = false`
    /// files the failure under no stream.
    #[allow(clippy::too_many_arguments)]
    pub fn record_parse_failure(
        &mut self,
        stream: &str,
        label: &str,
        kind: &str,
        message: &str,
        start_utc: Option<Instant>,
        end_utc: Option<Instant>,
        raw_record_id: Option<i64>,
        payload_hash: Option<&str>,
        placeable: bool,
    ) -> rusqlite::Result<()> {
        self.stats.files_failed += 1;
        self.stats.failures.push(Failure {
            file: label.to_string(),
            stream: None,
            kind: kind.to_string(),
            error: redact_text(message),
        });
        self.provenance(stream, "parse", false, Some(kind), Some(message), 0)?;
        self.conn.execute(
            "INSERT OR IGNORE INTO import_failures(run_id, stream, start_utc, end_utc, raw_record_id, \
             payload_hash, kind, recorded_at) VALUES(?,?,?,?,?,?,?,?)",
            params![
                self.run_id,
                if placeable { Some(stream) } else { None },
                iso_opt(&start_utc),
                iso_opt(&end_utc),
                raw_record_id,
                payload_hash,
                kind,
                utc_now_iso()
            ],
        )?;
        Ok(())
    }

    /// Highest `raw_records` id right now (the relay marks what a run wrote).
    pub fn last_raw_id(&self) -> rusqlite::Result<i64> {
        self.conn.query_row("SELECT COALESCE(MAX(id), 0) FROM raw_records", [], |r| r.get(0))
    }

    /// Note the local-date window (inclusive `YYYY-MM-DD`) a source file claims to cover for
    /// `stream`; the first run to claim a window owns it.
    pub fn record_export_range(&self, stream: &str, from_day: &str, to_day: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO export_ranges(run_id, stream, from_day, to_day) VALUES(?,?,?,?)",
            params![self.run_id, stream, from_day, to_day],
        )?;
        Ok(())
    }

    // ---- raw retention ----

    /// `INSERT OR IGNORE` of the raw record; its id, or None when the key was already there.
    /// `origin` = (transport, imported_at) of the record's first import, kept when the bytes
    /// arrive through the relay.
    fn store_raw(&self, decoded: &Decoded, raw: &RawInput) -> rusqlite::Result<Option<i64>> {
        let now = utc_now_iso();
        let (transport, imported_at) = raw.origin.unwrap_or((self.stats.transport.as_str(), now.as_str()));
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO raw_records(stream, source_key, source_scope, transport, \
             device_id, start_utc, end_utc, payload_kind, payload, payload_hash, payload_bytes, \
             decode_summary, imported_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                raw.stream,
                raw.source_key,
                decoded.source_scope,
                transport,
                decoded.device_id,
                iso_opt(&decoded.start_utc),
                iso_opt(&decoded.end_utc),
                raw.kind,
                raw.packed,
                raw.payload_hash,
                raw.data_len as i64,
                raw.summary,
                imported_at
            ],
        )?;
        Ok(if changed == 1 { Some(self.conn.last_insert_rowid()) } else { None })
    }

    /// Remove every canonical row `raw_id` previously produced. Sleep stages carry no
    /// `raw_record_id` of their own, so the sessions are looked up first and their stages deleted
    /// before the session rows.
    pub fn delete_canonical_for_raw(&self, raw_id: i64) -> rusqlite::Result<()> {
        let sleep_ids: Vec<String> = {
            let mut stmt = self.conn.prepare_cached("SELECT sleep_id FROM sleep_sessions WHERE raw_record_id=?")?;
            let mapped = stmt.query_map(params![raw_id], |r| r.get(0))?;
            mapped.collect::<Result<_, _>>()?
        };
        for sleep_id in &sleep_ids {
            self.conn.execute("DELETE FROM sleep_stages WHERE sleep_id=?", params![sleep_id])?;
        }
        for table in [
            "metric_samples",
            "daily_metrics",
            "daily_labels",
            "monitoring_intervals",
            "activities",
            "clock_offsets",
            "sleep_sessions",
        ] {
            self.conn.execute(&format!("DELETE FROM {table} WHERE raw_record_id=?"), params![raw_id])?;
        }
        Ok(())
    }

    // ---- canonical rows ----

    pub(crate) fn write_canonical(&mut self, decoded: &Decoded, raw_id: i64) -> rusqlite::Result<i64> {
        let conn = self.conn;
        let scope = decoded.source_scope.as_str();
        let device = &decoded.device_id;
        let mut written = 0_i64;
        if !decoded.samples.is_empty() {
            let mut stmt = conn.prepare_cached(
                "INSERT OR REPLACE INTO metric_samples(metric, ts_utc, value, source_scope, \
                 device_id, raw_record_id) VALUES(?,?,?,?,?,?)",
            )?;
            for s in &decoded.samples {
                stmt.execute(params![s.metric, iso_utc(&s.ts_utc), s.value, scope, device, raw_id])?;
            }
            written += decoded.samples.len() as i64;
            let (low, high) = bounds(decoded.samples.iter().map(|s| s.ts_utc));
            widen(&mut self.sample_span, low, high);
            self.sample_devices.insert(device.clone());
        }
        for fact in &decoded.daily {
            let Some(date) = self.date_of(fact.date.as_deref(), fact.ts_utc) else {
                *self.stats.dropped.entry("fact_without_date".to_string()).or_insert(0) += 1;
                continue;
            };
            let observed = iso_opt(&fact.ts_utc);
            written += self.upsert_daily(
                "daily_metrics", "value", &date, &fact.metric, &fact.value, observed.as_deref(), scope, device, raw_id,
            )?;
        }
        for label in &decoded.labels {
            let Some(date) = self.date_of(label.date.as_deref(), label.ts_utc) else {
                *self.stats.dropped.entry("fact_without_date".to_string()).or_insert(0) += 1;
                continue;
            };
            let observed = iso_opt(&label.ts_utc);
            written += self.upsert_daily(
                "daily_labels", "label", &date, &label.metric, &label.label, observed.as_deref(), scope, device, raw_id,
            )?;
        }
        if !decoded.intervals.is_empty() {
            let mut stmt = conn.prepare_cached(
                "INSERT OR REPLACE INTO monitoring_intervals(ts_utc, activity_type, steps, cycles, \
                 active_time_s, active_calories_kcal, distance_m, intensity, source_scope, device_id, \
                 raw_record_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            )?;
            for i in &decoded.intervals {
                stmt.execute(params![
                    iso_utc(&i.ts_utc),
                    i.activity_type,
                    i.steps,
                    i.cycles,
                    i.active_time_s,
                    i.active_calories_kcal,
                    i.distance_m,
                    i.intensity,
                    scope,
                    device,
                    raw_id
                ])?;
            }
            written += decoded.intervals.len() as i64;
            let (low, high) = bounds(decoded.intervals.iter().map(|i| i.ts_utc));
            widen(&mut self.interval_span, low, high);
            self.interval_devices.insert(device.clone());
        }
        if let Some(sleep) = &decoded.sleep {
            written += self.write_sleep(sleep, scope, device, raw_id)?;
        }
        for a in &decoded.activities {
            let start = iso_utc(&a.start_utc);
            conn.execute(
                "INSERT OR REPLACE INTO activities(activity_id, start_utc, end_utc, sport, sub_sport, \
                 total_timer_s, total_elapsed_s, distance_m, calories_kcal, avg_hr, max_hr, \
                 avg_speed_mps, total_ascent_m, total_descent_m, source_scope, device_id, \
                 raw_record_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                params![
                    format!("{start}|{scope}|{}", device_key(device)),
                    start,
                    iso_opt(&a.end_utc),
                    a.sport,
                    a.sub_sport,
                    a.total_timer_s,
                    a.total_elapsed_s,
                    a.distance_m,
                    a.calories_kcal,
                    a.avg_hr,
                    a.max_hr,
                    a.avg_speed_mps,
                    a.total_ascent_m,
                    a.total_descent_m,
                    scope,
                    device,
                    raw_id
                ],
            )?;
            written += 1;
        }
        if !decoded.offsets.is_empty() {
            ClockOffsets::persist(conn, &decoded.offsets, device.as_deref(), Some(raw_id))?;
            written += decoded.offsets.len() as i64;
        }
        Ok(written)
    }

    /// `fact.date or offsets.local_date(fact.ts_utc)`: an empty date text counts as absent, as in Python.
    fn date_of(&self, date: Option<&str>, ts: Option<Instant>) -> Option<String> {
        match date {
            Some(d) if !d.is_empty() => Some(d.to_string()),
            _ => ts.map(|t| self.offsets.local_date(t)),
        }
    }

    /// Keep the value observed latest for a (date, metric, scope, device) key; an equal
    /// observation lets the later write win. Returns rows written (0 or 1).
    #[allow(clippy::too_many_arguments)]
    fn upsert_daily(
        &self,
        table: &str,
        column: &str,
        date: &str,
        metric: &str,
        value: &dyn ToSql,
        observed: Option<&str>,
        scope: &str,
        device: &Option<String>,
        raw_id: i64,
    ) -> rusqlite::Result<i64> {
        let existing: Option<(i64, Option<String>)> = self
            .conn
            .prepare_cached(&format!(
                "SELECT id, observed_utc FROM {table} WHERE date=? AND metric=? AND source_scope=? \
                 AND COALESCE(device_id, '') = ?"
            ))?
            .query_row(params![date, metric, scope, device_key(device)], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let Some((existing_id, existing_observed)) = existing else {
            self.conn.prepare_cached(&format!(
                "INSERT INTO {table}(date, metric, {column}, observed_utc, source_scope, device_id, \
                 raw_record_id) VALUES(?,?,?,?,?,?,?)"
            ))?
            .execute(params![date, metric, value, observed, scope, device, raw_id])?;
            return Ok(1);
        };
        if let (Some(new), Some(old)) = (observed, existing_observed.as_deref())
            && new < old
        {
            return Ok(0);
        }
        self.conn
            .prepare_cached(&format!("UPDATE {table} SET {column}=?, observed_utc=?, raw_record_id=? WHERE id=?"))?
            .execute(params![value, observed, raw_id, existing_id])?;
        Ok(1)
    }

    fn write_sleep(&mut self, sleep: &SleepSession, scope: &str, device: &Option<String>, raw_id: i64) -> rusqlite::Result<i64> {
        let date = match &sleep.date {
            Some(d) => d.clone(),
            None => match sleep.end_utc {
                Some(end) => self.offsets.local_date(end),
                None => {
                    *self.stats.dropped.entry("sleep_without_date".to_string()).or_insert(0) += 1;
                    return Ok(0);
                }
            },
        };
        let sleep_id = format!("{date}|{scope}|{}", device_key(device));
        self.conn.execute("DELETE FROM sleep_stages WHERE sleep_id=?", params![sleep_id])?;
        self.conn.execute(
            "INSERT OR REPLACE INTO sleep_sessions(sleep_id, date, start_utc, end_utc, deep_s, \
             light_s, rem_s, awake_s, unmeasurable_s, overall_score, quality_score, duration_score, \
             recovery_score, deep_score, rem_score, light_score, awake_time_score, \
             awakenings_count_score, combined_awake_score, restlessness_score, interruptions_score, \
             awakenings_count, avg_stress, avg_spo2, lowest_spo2, avg_hr, avg_respiration, \
             lowest_respiration, highest_respiration, retro, source_scope, device_id, raw_record_id) \
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                sleep_id,
                date,
                iso_opt(&sleep.start_utc),
                iso_opt(&sleep.end_utc),
                sleep.deep_s,
                sleep.light_s,
                sleep.rem_s,
                sleep.awake_s,
                sleep.unmeasurable_s,
                sleep.overall_score,
                sleep.quality_score,
                sleep.duration_score,
                sleep.recovery_score,
                sleep.deep_score,
                sleep.rem_score,
                sleep.light_score,
                sleep.awake_time_score,
                sleep.awakenings_count_score,
                sleep.combined_awake_score,
                sleep.restlessness_score,
                sleep.interruptions_score,
                sleep.awakenings_count,
                sleep.avg_stress,
                sleep.avg_spo2,
                sleep.lowest_spo2,
                sleep.avg_hr,
                sleep.avg_respiration,
                sleep.lowest_respiration,
                sleep.highest_respiration,
                i64::from(sleep.retro),
                scope,
                device,
                raw_id
            ],
        )?;
        if !sleep.stages.is_empty() {
            let mut stmt = self.conn.prepare_cached(
                "INSERT INTO sleep_stages(sleep_id, stage, start_utc, end_utc) VALUES(?,?,?,?)",
            )?;
            for s in &sleep.stages {
                stmt.execute(params![sleep_id, s.stage, iso_utc(&s.start_utc), iso_utc(&s.end_utc)])?;
            }
        }
        let mut written = 1 + sleep.stages.len() as i64;
        let observed = iso_opt(&sleep.end_utc);
        if let Some(score) = sleep.overall_score {
            written += self.upsert_daily(
                "daily_metrics", "value", &date, "sleep_score", &(score as f64), observed.as_deref(), scope, device, raw_id,
            )?;
        }
        let asleep: Vec<i64> = [sleep.deep_s, sleep.light_s, sleep.rem_s].into_iter().flatten().collect();
        if !asleep.is_empty() {
            let minutes = py_round(asleep.iter().sum::<i64>() as f64 / 60.0, 1);
            written += self.upsert_daily(
                "daily_metrics", "value", &date, "sleep_duration", &minutes, observed.as_deref(), scope, device, raw_id,
            )?;
        }
        Ok(written)
    }

    // ---- entry points ----

    /// Retain and decode one FIT file. `label` is a PII-free name used only in failure reports.
    /// `origin` = (transport, imported_at) is set when the bytes came through the relay.
    pub fn write_fit(
        &mut self,
        data: &[u8],
        label: &str,
        origin: Option<(&str, &str)>,
    ) -> Result<WriteOutcome, WriterError> {
        self.stats.files_seen += 1;
        let source_key = sha256_hex(data);
        let duplicate = self
            .conn
            .prepare_cached("SELECT 1 FROM raw_records WHERE payload_kind='fit' AND source_key=?")?
            .exists(params![source_key])?;
        if duplicate {
            self.stats.files_duplicate += 1;
            return Ok(WriteOutcome::Duplicate);
        }
        let decoded = match fit::decode_fit(data) {
            Ok(decoded) => decoded,
            Err(FitDecodeError { kind, message, stream, start_utc, end_utc }) => {
                let placeable = stream.is_some();
                let stream = stream.unwrap_or_else(|| "fit:undecodable".to_string());
                self.record_parse_failure(
                    &stream, label, &kind, &message, start_utc, end_utc, None, Some(&source_key), placeable,
                )?;
                return Ok(WriteOutcome::Failed);
            }
        };
        let summary = decode_summary_json(&decoded);
        self.provenance(&decoded.stream, "parse", true, None, None, 0)?;
        let packed = compress_verified(data)?;
        let raw = RawInput {
            stream: &decoded.stream,
            source_key: &source_key,
            kind: "fit",
            packed: &packed,
            payload_hash: &source_key,
            data_len: data.len(),
            summary: &summary,
            origin,
        };
        match self.store_and_write(&decoded, &raw, None) {
            Ok(Some(written)) => {
                self.provenance(&decoded.stream, "write", true, None, None, written)?;
                self.account(&decoded, written);
                Ok(WriteOutcome::Imported)
            }
            Ok(None) => {
                self.stats.files_duplicate += 1;
                Ok(WriteOutcome::Duplicate)
            }
            Err(error) => {
                self.storage_failure(&decoded.stream, label, &error)?;
                Ok(WriteOutcome::Failed)
            }
        }
    }

    /// Retain one JSON record (a Connect export day or night) and its decoded facts. The stored
    /// bytes are the record's canonical JSON; the duplicate test is by (stream, source_key).
    pub fn write_json_record(
        &mut self,
        stream: &str,
        source_key: &str,
        record: &canon::Value,
        decoded: &Decoded,
        label: &str,
        origin: Option<(&str, &str)>,
    ) -> Result<WriteOutcome, WriterError> {
        self.write_json_record_with(stream, source_key, record, decoded, label, origin, None)
    }

    /// [`Writer::write_json_record`] with the relay's conflict hook. `before_write` runs inside this
    /// record's own transaction, ahead of the raw row and the canonical rows: it retires the stored
    /// record the new one replaces, so a storage error anywhere rolls the whole swap back (`Failed`,
    /// the old record untouched). With a hook the stored row is expected to exist, so the duplicate
    /// pre-check is skipped.
    #[allow(clippy::too_many_arguments)]
    pub fn write_json_record_with(
        &mut self,
        stream: &str,
        source_key: &str,
        record: &canon::Value,
        decoded: &Decoded,
        label: &str,
        origin: Option<(&str, &str)>,
        before_write: Option<BeforeWrite<'_>>,
    ) -> Result<WriteOutcome, WriterError> {
        self.stats.files_seen += 1;
        let duplicate = before_write.is_none()
            && self
                .conn
                .prepare_cached("SELECT 1 FROM raw_records WHERE stream=? AND source_key=?")?
                .exists(params![stream, source_key])?;
        if duplicate {
            self.stats.files_duplicate += 1;
            return Ok(WriteOutcome::Duplicate);
        }
        let data = canon::dumps(record);
        let summary = canon::dumps_spaced(&json_summary(decoded));
        let payload_hash = sha256_hex(&data);
        let packed = compress_verified(&data)?;
        let raw = RawInput {
            stream,
            source_key,
            kind: "json",
            packed: &packed,
            payload_hash: &payload_hash,
            data_len: data.len(),
            summary: &summary,
            origin,
        };
        match self.store_and_write(decoded, &raw, before_write) {
            Ok(Some(written)) => {
                self.provenance(stream, "parse", true, None, None, 0)?;
                self.provenance(stream, "write", true, None, None, written)?;
                self.account(decoded, written);
                Ok(WriteOutcome::Imported)
            }
            Ok(None) => {
                self.stats.files_duplicate += 1;
                Ok(WriteOutcome::Duplicate)
            }
            Err(error) => {
                self.storage_failure(stream, label, &error)?;
                Ok(WriteOutcome::Failed)
            }
        }
    }

    /// `keep_undecodable_record`: retain the bytes of a relayed JSON record whose stream this
    /// build has no decoder for. A peer on a newer build may publish a stream this one does not
    /// know yet; dropping the record would lose it for good (a pulled record is never pushed
    /// back), so the bytes are stored as a `raw_records` row with the sender's own scope, device
    /// and span (`row`), no canonical rows, and an `import_failures` row carrying the kind and
    /// message `decode_raw` gives such a record -- the trail `reparse` leaves until a decoder
    /// arrives and replays the bytes. Same transaction shape as [`Writer::write_json_record_with`]
    /// (`before_write` is the relay's conflict hook). Returns `Kept`, `Duplicate` or `Failed`
    /// (a storage error). A span stamp that is not the store's shape is `BadStamp` (the oracle's
    /// uncaught `ValueError`).
    #[allow(clippy::too_many_arguments)]
    pub fn keep_undecodable_record(
        &mut self,
        stream: &str,
        source_key: &str,
        row: &KeptRow<'_>,
        data: &[u8],
        label: &str,
        origin: Option<(&str, &str)>,
        before_write: Option<BeforeWrite<'_>>,
    ) -> Result<WriteOutcome, WriterError> {
        self.stats.files_seen += 1;
        let duplicate = before_write.is_none()
            && self
                .conn
                .prepare_cached("SELECT 1 FROM raw_records WHERE stream=? AND source_key=?")?
                .exists(params![stream, source_key])?;
        if duplicate {
            self.stats.files_duplicate += 1;
            return Ok(WriteOutcome::Duplicate);
        }
        let stamp = |text: Option<&str>| -> Result<Option<Instant>, WriterError> {
            match text.filter(|t| !t.is_empty()) {
                None => Ok(None),
                Some(t) => parse_iso_utc(t).map(Some).ok_or_else(|| {
                    WriterError::BadStamp(format!("time data {t:?} does not match format '%Y-%m-%dT%H:%M:%SZ'"))
                }),
            }
        };
        let mut shell = Decoded::new(stream, if row.source_scope.is_empty() { "vendor_cloud" } else { row.source_scope });
        shell.device_id = row.device_id.map(str::to_string);
        shell.start_utc = stamp(row.start_utc)?;
        shell.end_utc = stamp(row.end_utc)?;
        let payload_hash = sha256_hex(data);
        let packed = compress_verified(data)?;
        let summary = canon::dumps_spaced(&canon::Value::Object(vec![(
            "kept".to_string(),
            canon::Value::Str("no_decoder".to_string()),
        )]));
        let raw = RawInput {
            stream,
            source_key,
            kind: "json",
            packed: &packed,
            payload_hash: &payload_hash,
            data_len: data.len(),
            summary: &summary,
            origin,
        };
        let stored = (|| -> rusqlite::Result<Option<i64>> {
            self.conn.execute_batch("BEGIN")?;
            if let Some(hook) = before_write {
                hook(self)?;
            }
            let Some(raw_id) = self.store_raw(&shell, &raw)? else {
                self.conn.execute_batch("ROLLBACK")?;
                return Ok(None);
            };
            self.record_parse_failure(
                stream,
                label,
                "unrecognized_payload",
                &format!("no reparse decoder registered for stream '{stream}'"),
                None,
                None,
                Some(raw_id),
                Some(&payload_hash),
                true,
            )?;
            self.conn.execute_batch("COMMIT")?;
            Ok(Some(raw_id))
        })();
        match stored {
            Ok(Some(_)) => Ok(WriteOutcome::Kept),
            Ok(None) => {
                self.stats.files_duplicate += 1;
                Ok(WriteOutcome::Duplicate)
            }
            Err(error) => {
                self.storage_failure(stream, label, &error)?;
                Ok(WriteOutcome::Failed)
            }
        }
    }

    /// The latest recorded failure is a storage error (the write was refused), as opposed to a
    /// decode failure, which every device reaches identically. Call right after a write returned
    /// `Failed`.
    #[must_use]
    pub fn last_failure_is_storage(&self) -> bool {
        self.stats.failures.last().is_some_and(|f| f.kind == "storage")
    }

    /// Roll back the open transaction and book a `storage` failure for `stream`.
    fn storage_failure(&mut self, stream: &str, label: &str, error: &rusqlite::Error) -> rusqlite::Result<()> {
        let _ = self.conn.execute_batch("ROLLBACK");
        let message = error.to_string();
        self.stats.files_failed += 1;
        self.stats.failures.push(Failure {
            file: label.to_string(),
            stream: None,
            kind: "storage".to_string(),
            error: redact_text(&message),
        });
        self.provenance(stream, "write", false, Some("storage"), Some(&message), 0)
    }

    /// Replace every canonical row `raw_id` produced with freshly decoded facts. The caller has
    /// already decoded successfully: that is booked as a `parse` provenance event, then the
    /// `write` side runs in one transaction (delete what `raw_id` wrote, write `decoded`, refresh
    /// `decode_summary`), so a storage error leaves the previous rows intact and is recorded in
    /// `stats.failures`. Returns `Reparsed` or `Failed`.
    pub fn rewrite_canonical(
        &mut self,
        raw_id: i64,
        stream: &str,
        decoded: &Decoded,
        summary: &canon::Value,
    ) -> Result<WriteOutcome, WriterError> {
        self.provenance(stream, "parse", true, None, None, 0)?;
        let label = format!("raw_record:{raw_id}");
        match self.rewrite_in_transaction(raw_id, decoded, summary) {
            Ok(written) => {
                self.provenance(stream, "write", true, None, None, written)?;
                self.account(decoded, written);
                Ok(WriteOutcome::Reparsed)
            }
            Err(error) => {
                self.storage_failure(stream, &label, &error)?;
                Ok(WriteOutcome::Failed)
            }
        }
    }

    fn rewrite_in_transaction(&mut self, raw_id: i64, decoded: &Decoded, summary: &canon::Value) -> rusqlite::Result<i64> {
        self.conn.execute_batch("BEGIN")?;
        self.delete_canonical_for_raw(raw_id)?;
        let written = self.write_canonical(decoded, raw_id)?;
        self.conn.execute(
            "UPDATE raw_records SET decode_summary=? WHERE id=?",
            params![canon::dumps_spaced(summary), raw_id],
        )?;
        self.conn.execute_batch("COMMIT")?;
        Ok(written)
    }

    /// One transaction: raw record, then canonical rows. None = the raw key was already stored (rolled back).
    fn store_and_write(
        &mut self,
        decoded: &Decoded,
        raw: &RawInput,
        before_write: Option<BeforeWrite<'_>>,
    ) -> rusqlite::Result<Option<i64>> {
        self.conn.execute_batch("BEGIN")?;
        if let Some(hook) = before_write {
            hook(self)?;
        }
        let Some(raw_id) = self.store_raw(decoded, raw)? else {
            self.conn.execute_batch("ROLLBACK")?;
            return Ok(None);
        };
        let written = self.write_canonical(decoded, raw_id)?;
        self.conn.execute_batch("COMMIT")?;
        if decoded.stream == crate::live::STREAM {
            self.live_run_ids.insert(raw_id);
        }
        Ok(Some(written))
    }

    fn account(&mut self, decoded: &Decoded, written: i64) {
        self.stats.files_imported += 1;
        self.stats.records_written += written;
        self.stats.bump_stream(&decoded.stream, "files", 1);
        self.stats.bump_stream(&decoded.stream, "records", written);
        for (reason, count) in &decoded.dropped {
            *self.stats.dropped.entry(reason.clone()).or_insert(0) += *count as i64;
        }
        for warning in decoded.warnings.iter().take(3) {
            if self.stats.warnings.len() < 20 {
                self.stats.warnings.push(warning.clone());
            }
        }
    }

    // ---- derived dailies ----

    /// Daily steps and distance from the cumulative monitoring counters written this run.
    ///
    /// Per local day and activity type the counter's maximum is that type's total; the day's total
    /// is the sum over types. The record stamped exactly at local midnight closes the day just
    /// ended, so a record is dated by the moment one second before its timestamp. Written as
    /// source_scope `local`. Returns the step-day rows upserted.
    pub fn derive_daily_steps(&mut self) -> rusqlite::Result<i64> {
        let Some((span_lo, span_hi)) = self.interval_span else { return Ok(0) };
        let low = iso_utc(&(span_lo - Duration::days(1)));
        let high = iso_utc(&(span_hi + Duration::days(1)));
        let second = Duration::seconds(1);
        let first_day = self.offsets.local_date(span_lo - second);
        let last_day = self.offsets.local_date(span_hi - second);
        let mut days = 0_i64;
        let devices: Vec<Option<String>> = self.interval_devices.iter().cloned().collect();
        for device in devices {
            let rows: Vec<IntervalRow> = {
                let mut stmt = self.conn.prepare_cached(
                    "SELECT ts_utc, activity_type, steps, distance_m, raw_record_id FROM monitoring_intervals \
                     WHERE source_scope='device' AND COALESCE(device_id,'') = ? AND ts_utc BETWEEN ? AND ?",
                )?;
                let mapped = stmt.query_map(params![device_key(&device), low, high], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?;
                mapped.collect::<Result<_, _>>()?
            };
            // date -> activity types in first-seen order, each (type, steps max, distance max)
            let mut per_day: BTreeMap<String, Vec<TypeMax>> = BTreeMap::new();
            let mut latest: BTreeMap<String, (String, i64)> = BTreeMap::new();
            for (ts_text, activity_type, steps, distance, raw_id) in rows {
                let Some(moment) = parse_iso_utc(&ts_text) else { continue };
                let date = self.offsets.local_date(moment - second);
                if !(first_day <= date && date <= last_day) {
                    continue;
                }
                let types = per_day.entry(date.clone()).or_default();
                let at = match types.iter().position(|t| t.0 == activity_type) {
                    Some(at) => at,
                    None => {
                        types.push((activity_type, None, None));
                        types.len() - 1
                    }
                };
                if let Some(steps) = steps {
                    let prev = types[at].1.unwrap_or(0);
                    types[at].1 = Some(if steps > prev { steps } else { prev });
                }
                if let Some(distance) = distance {
                    let prev = types[at].2.unwrap_or(0.0);
                    types[at].2 = Some(if distance > prev { distance } else { prev });
                }
                if latest.get(&date).is_none_or(|l| ts_text > l.0) {
                    latest.insert(date, (ts_text, raw_id));
                }
            }
            for (date, types) in &per_day {
                let Some((observed, raw_id)) = latest.get(date) else { continue };
                let step_types: Vec<i64> = types.iter().filter_map(|t| t.1).collect();
                if !step_types.is_empty() {
                    let total = step_types.iter().sum::<i64>() as f64;
                    self.upsert_daily("daily_metrics", "value", date, "steps", &total, Some(observed), "local", &device, *raw_id)?;
                    days += 1;
                }
                let distance_types: Vec<f64> = types.iter().filter_map(|t| t.2).collect();
                if !distance_types.is_empty() {
                    let total = py_sum(distance_types);
                    self.upsert_daily("daily_metrics", "value", date, "distance", &total, Some(observed), "local", &device, *raw_id)?;
                }
            }
        }
        self.stats.derived_days = days;
        Ok(days)
    }

    /// Daily stress average, heart-rate min/max and energy-gauge figures from the device samples
    /// written this run, as source_scope `local`. Returns day rows upserted.
    pub fn derive_daily_from_samples(&mut self) -> rusqlite::Result<i64> {
        let Some((span_lo, span_hi)) = self.sample_span else { return Ok(0) };
        let low = iso_utc(&(span_lo - Duration::days(1)));
        let high = iso_utc(&(span_hi + Duration::days(1)));
        // The +-1-day window holds every sample of the days this run touched, but only part of the
        // day before the first sample: that day keeps its earlier, complete figure.
        let first_day = self.offsets.local_date(span_lo);
        let last_day = self.offsets.local_date(span_hi);
        let mut days = 0_i64;
        let devices: Vec<Option<String>> = self.sample_devices.iter().cloned().collect();
        let metrics: BTreeSet<&str> = DERIVED_FROM_SAMPLES.iter().map(|d| d.0).collect();
        for device in devices {
            for sample_metric in &metrics {
                let rows: Vec<(String, f64, i64)> = {
                    let mut stmt = self.conn.prepare_cached(
                        "SELECT ts_utc, value, raw_record_id FROM metric_samples WHERE metric=? AND \
                         source_scope='device' AND COALESCE(device_id,'') = ? AND ts_utc BETWEEN ? AND ? \
                         ORDER BY ts_utc",
                    )?;
                    let mapped = stmt.query_map(params![sample_metric, device_key(&device), low, high], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })?;
                    mapped.collect::<Result<_, _>>()?
                };
                let mut per_day: BTreeMap<String, Vec<(i64, f64)>> = BTreeMap::new();
                let mut latest: BTreeMap<String, (String, i64)> = BTreeMap::new();
                for (ts_text, value, raw_id) in rows {
                    let Some(moment) = parse_iso_utc(&ts_text) else { continue };
                    let date = self.offsets.local_date(moment);
                    if !(first_day <= date && date <= last_day) {
                        continue;
                    }
                    per_day.entry(date.clone()).or_default().push((moment.timestamp(), value));
                    if latest.get(&date).is_none_or(|l| ts_text > l.0) {
                        latest.insert(date, (ts_text, raw_id));
                    }
                }
                for (source, daily_metric, reducer) in DERIVED_FROM_SAMPLES {
                    if source != *sample_metric {
                        continue;
                    }
                    for (date, readings) in &per_day {
                        let Some((observed, raw_id)) = latest.get(date) else { continue };
                        let value = round3(reducer.apply(readings));
                        self.upsert_daily(
                            "daily_metrics", "value", date, daily_metric, &value, Some(observed), "local", &device, *raw_id,
                        )?;
                        days += 1;
                    }
                }
            }
        }
        Ok(days)
    }
}

// ---- the live fold (bet 9b-2) ----

/// The sample-cadence metrics the fold keeps; `steps` and anything else is ignored.
const LIVE_METRICS: [&str; 5] = ["heart_rate", "stress", "respiration_rate", "spo2", "energy_reserve"];

/// One decoded live record: its raw id and readings `(t, metric, value)` in payload order.
pub type LiveRecord = (i64, Vec<(f64, String, i64)>);

/// The reason a reading is a sentinel (dropped before thinning), None when it is kept: the FIT
/// decoder's rule plus the field's upper bound (a uint8 never carries 0xFF, a percentage never 101).
fn live_sentinel(metric: &str, value: i64) -> Option<&'static str> {
    match metric {
        "heart_rate" if !(1..255).contains(&value) => Some("live_heart_rate_zero"),
        "stress" if !(0..=100).contains(&value) => Some("live_stress_sentinel"),
        "respiration_rate" if !(0..255).contains(&value) => Some("live_respiration_sentinel"),
        "spo2" if !(1..=100).contains(&value) => Some("live_spo2_off_wrist_or_zero"),
        "energy_reserve" if !(0..=100).contains(&value) => Some("live_energy_reserve_out_of_range"),
        _ => None,
    }
}

/// One folded minute: `(metric, minute unix seconds, lower median, raw id)`.
pub type LiveMinute = (String, i64, i64, i64);

/// A minute bucket of the fold: `(metric, minute unix seconds)` -> (values, first raw id).
type LiveBuckets = BTreeMap<(String, i64), (Vec<i64>, i64)>;

/// The pure fold over decoded records in content order: the minute rows `(metric, minute, lower
/// median, raw id of the first contributing record)` sorted by (metric, ts), and the sentinel
/// drop counts. Readings are de-duplicated across all records by `(t as f64, metric, value)`.
pub fn fold_live_readings(records: &[LiveRecord]) -> (Vec<LiveMinute>, BTreeMap<String, i64>) {
    let mut seen: BTreeSet<(u64, String, i64)> = BTreeSet::new();
    let mut buckets: LiveBuckets = BTreeMap::new();
    let mut dropped: BTreeMap<String, i64> = BTreeMap::new();
    for (raw_id, readings) in records {
        for (t, metric, value) in readings {
            if !LIVE_METRICS.contains(&metric.as_str()) {
                continue;
            }
            // `+ 0.0` folds -0.0 into 0.0 so equal numbers share one key
            if !seen.insert(((*t + 0.0).to_bits(), metric.clone(), *value)) {
                continue;
            }
            if let Some(reason) = live_sentinel(metric, *value) {
                *dropped.entry(reason.to_string()).or_insert(0) += 1;
                continue;
            }
            let whole = t.floor() as i64;
            let minute = whole - whole.rem_euclid(60);
            buckets.entry((metric.clone(), minute)).or_insert_with(|| (Vec::new(), *raw_id)).0.push(*value);
        }
    }
    let rows = buckets
        .into_iter()
        .map(|((metric, minute), (mut values, raw_id))| {
            values.sort_unstable();
            let median = values[(values.len() - 1) / 2];
            (metric, minute, median, raw_id)
        })
        .collect();
    (rows, dropped)
}

/// A stored `json:live` payload as readings, None when it fails decompression, JSON or the 9b validation.
fn decode_stored_live(blob: &[u8]) -> Option<Vec<(f64, String, i64)>> {
    let data = crate::sources::inflate(blob)?;
    let canon::Value::Object(members) = canon::parse(&data).ok()? else { return None };
    crate::live::decode_live_record(&members).ok()?;
    let Some((_, canon::Value::Array(items))) = members.iter().find(|(k, _)| k == "readings") else { return None };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let canon::Value::Array(triple) = item else { return None };
        let (canon::Value::Str(metric), canon::Value::Int(value)) = (triple.get(1)?, triple.get(2)?) else { return None };
        let t = match triple.first()? {
            canon::Value::Int(i) => *i as f64,
            canon::Value::Float(x) => *x,
            _ => return None,
        };
        out.push((t, metric.clone(), *value));
    }
    Some(out)
}

impl Writer<'_> {
    /// The live fold: rebuild every `live`-scope sample (one per UTC minute and metric, the lower
    /// median) as a pure function of the stored `json:live` records. Written directly, not through
    /// the canonical path, so it never widens the sample span. Sentinel drops found in the records
    /// this run stored are added to `stats.dropped`. Returns the rows written.
    pub fn derive_live_samples(&mut self) -> rusqlite::Result<i64> {
        let stored: Vec<(i64, Vec<u8>)> = {
            let mut stmt = self.conn.prepare(
                "SELECT id, payload FROM raw_records WHERE stream='json:live' \
                 ORDER BY start_utc, payload_hash, stream, source_key",
            )?;
            let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            mapped.collect::<Result<_, _>>()?
        };
        let records: Vec<LiveRecord> = stored
            .iter()
            .filter_map(|(id, blob)| decode_stored_live(blob).map(|readings| (*id, readings)))
            .collect();
        let (rows, _) = fold_live_readings(&records);
        self.conn.execute_batch("BEGIN")?;
        let written = (|| -> rusqlite::Result<i64> {
            self.conn.execute("DELETE FROM metric_samples WHERE source_scope='live'", [])?;
            let mut insert = self.conn.prepare_cached(
                "INSERT INTO metric_samples(metric, ts_utc, value, source_scope, device_id, raw_record_id) \
                 VALUES(?,?,?,'live',NULL,?)",
            )?;
            let mut count = 0_i64;
            for (metric, minute, value, raw_id) in &rows {
                let Some(moment) = chrono::DateTime::<chrono::Utc>::from_timestamp(*minute, 0) else { continue };
                insert.execute(params![metric, iso_utc(&moment), *value as f64, raw_id])?;
                count += 1;
            }
            Ok(count)
        })();
        // a failed COMMIT rolls back too, so no later statement runs inside a stale transaction
        let written = written.and_then(|count| self.conn.execute_batch("COMMIT").map(|_| count));
        match written {
            Ok(count) => {
                let own: Vec<LiveRecord> =
                    records.into_iter().filter(|(id, _)| self.live_run_ids.contains(id)).collect();
                for (reason, count) in fold_live_readings(&own).1 {
                    *self.stats.dropped.entry(reason).or_insert(0) += count;
                }
                Ok(count)
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }
}

fn bounds(moments: impl Iterator<Item = Instant>) -> (Instant, Instant) {
    let mut low: Option<Instant> = None;
    let mut high: Option<Instant> = None;
    for m in moments {
        low = Some(low.map_or(m, |l| l.min(m)));
        high = Some(high.map_or(m, |h| h.max(m)));
    }
    // Callers only pass non-empty collections; the epoch is never reached.
    let fallback = chrono::DateTime::<chrono::Utc>::UNIX_EPOCH;
    (low.unwrap_or(fallback), high.unwrap_or(fallback))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_matches_python_on_tricky_doubles() {
        // Python: round(2.675, 2) == 2.67 (the double is below the tie), round(0.125, 2) == 0.12,
        // round(0.375, 2) == 0.38, round(0.25, 1) == 0.2, round(0.35, 1) == 0.3 (0.35 is below the tie),
        // round(0.1 + 0.2, 3) == 0.3, round(1.0005, 3) == 1.0 (below the tie), round(2.5, 0) == 2.0
        assert_eq!(py_round(2.675, 2), 2.67);
        assert_eq!(py_round(0.125, 2), 0.12);
        assert_eq!(py_round(0.375, 2), 0.38);
        assert_eq!(py_round(0.25, 1), 0.2);
        assert_eq!(py_round(0.35, 1), 0.3);
        assert_eq!(round3(0.1 + 0.2), 0.3);
        assert_eq!(round3(1.0005), 1.0);
        assert_eq!(py_round(2.5, 0), 2.0);
        assert_eq!(round3(72.123456789), 72.123);
        assert_eq!(round3(72.1235001), 72.124);
        assert_eq!(round3(-0.0001).to_bits(), (-0.0_f64).to_bits());
        assert_eq!(round3(0.0), 0.0);
        assert_eq!(py_round(f64::INFINITY, 3), f64::INFINITY);
        assert!(py_round(f64::NAN, 3).is_nan());
    }

    #[test]
    fn neumaier_sum_beats_the_naive_loop_like_python() {
        let tenths = vec![0.1; 10];
        let naive: f64 = tenths.iter().sum();
        assert_ne!(naive, 1.0);
        assert_eq!(py_sum(tenths), 1.0); // Python: sum([0.1] * 10) == 1.0
        assert_eq!(py_sum([1e100, 1.0, -1e100]), 1.0); // naive gives 0.0
        assert_eq!(py_sum(Vec::<f64>::new()), 0.0);
        assert_eq!(py_sum([-0.0]).to_bits(), 0.0_f64.to_bits(), "0 + -0.0 is +0.0");
    }

    #[test]
    fn charged_and_drained_skip_gaps_and_the_first_reading() {
        let m = |minutes: i64, v: f64| (minutes * 60, v);
        // 10 -> 14 (+4), 14 -> 11 (-3), gap of 20 min (skipped), 30 -> 33 (+3)
        let readings = vec![m(0, 10.0), m(5, 14.0), m(10, 11.0), m(30, 30.0), m(35, 33.0)];
        assert_eq!(charged(&readings), 7.0);
        assert_eq!(drained(&readings), 3.0);
        // order does not matter: the readings are sorted by time first
        let shuffled = vec![m(35, 33.0), m(0, 10.0), m(30, 30.0), m(10, 11.0), m(5, 14.0)];
        assert_eq!(charged(&shuffled), 7.0);
        // exactly 15 minutes apart still counts
        assert_eq!(charged(&[m(0, 1.0), m(15, 3.0)]), 2.0);
        assert_eq!(charged(&[m(0, 1.0)]), 0.0);
    }

    #[test]
    fn reducers_over_a_day() {
        let day = vec![(0, 4.0), (60, 8.0), (120, 3.0)];
        assert_eq!(Reducer::Min.apply(&day), 3.0);
        assert_eq!(Reducer::Max.apply(&day), 8.0);
        assert_eq!(Reducer::Mean.apply(&day), 5.0);
    }

    #[test]
    fn status_follows_the_counters() {
        let mut stats = ImportStats::new("drop");
        assert_eq!(stats.status(), "ok");
        stats.files_failed = 1;
        assert_eq!(stats.status(), "failed");
        stats.files_imported = 1;
        assert_eq!(stats.status(), "partial");
    }

    #[test]
    fn decode_summary_reads_like_python_json_dumps() {
        let mut decoded = Decoded::new("fit:test", "device");
        decoded.message_counts.insert("b".to_string(), 2);
        decoded.message_counts.insert("a".to_string(), 1);
        decoded.warnings = (0..12).map(|i| format!("w{i}")).collect();
        let text = decode_summary_json(&decoded);
        assert_eq!(
            text,
            r#"{"dropped": {}, "messages": {"a": 1, "b": 2}, "warnings": ["w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9"]}"#
        );
    }
}
