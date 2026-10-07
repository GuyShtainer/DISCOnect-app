// SPDX-License-Identifier: AGPL-3.0-or-later
//! The coverage ledger: why a (metric, scope, day) has no value. The twin of `disconect/coverage.py`.
//!
//! Four statuses, decided per local day in a fixed order: `present` > `failed` > `source_empty` >
//! `not_covered`. Everything is derived on request from what the store retains: `raw_records` spans
//! (the end is exclusive, so a file ending at local midnight does not cover the day that starts
//! then), the export windows files claimed, and the failures recorded with their spans. On a schema
//! without `export_ranges` / `import_failures` the ledger still answers, with those refinements
//! marked unavailable. No value, label, path or device identifier is read or returned.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{Datelike, Duration, NaiveDate};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;

use super::ReadError;
use super::queries::{iso, load_offsets, local_day, parse_date, parse_moment, shift, text};
use crate::model::Instant;
use crate::clock::ClockOffsets;
use crate::contract::Contract;
use crate::wirejson::Json;

pub const PRESENT: &str = "present";
pub const FAILED: &str = "failed";
pub const SOURCE_EMPTY: &str = "source_empty";
pub const NOT_COVERED: &str = "not_covered";

/// Two consecutive readings of a per-minute metric at most this many seconds apart span worn time
/// between them (`WORN_GAP_S`: five minutes bridges a short unmeasurable spell; a charger hour shows as a gap).
pub const WORN_GAP_S: i64 = 300;
/// The seconds a reading accounts for on its own (`READING_S`, the per-minute cadence): the last of a
/// run, or one whose next reading is farther than `WORN_GAP_S`.
pub const READING_S: i64 = 60;

/// The status window; gap lists, not the window, are what is capped.
pub const MAX_WINDOW_DAYS: i64 = 3650;
pub const MAX_GAPS: usize = 20;

/// Device streams written once per night: the watch produces such a file only when there was
/// something to record, so the all-day monitoring files are what prove the day was imported.
pub const NIGHTLY_DEVICE_STREAMS: [(&str, &str); 3] = [
    ("fit:sleep", "fit:monitoring_b"),
    ("fit:hrv", "fit:monitoring_b"),
    ("fit:skin_temp", "fit:monitoring_b"),
];

type Key = (String, String);
type Flags = Vec<bool>;
type Declared = BTreeMap<Key, BTreeSet<String>>;

/// Inclusive local-date window with day-index arithmetic (`_Window`).
struct Window {
    first: NaiveDate,
    last: NaiveDate,
    days: usize,
}

impl Window {
    fn new(first: &str, last: &str) -> Result<Window, ReadError> {
        let (first, last) = (parse_date(first)?, parse_date(last)?);
        let days = (last - first).num_days() + 1;
        // `if window.days < 1: raise ValueError(...)` in `_analyse`
        let days = usize::try_from(days)
            .ok()
            .filter(|days| *days >= 1)
            .ok_or_else(|| ReadError::Value("last_day must not be before first_day".into()))?;
        Ok(Window { first, last, days })
    }

    /// Position of `day` inside the window, or None when outside it.
    fn index(&self, day: &str) -> Result<Option<usize>, ReadError> {
        let offset = (parse_date(day)? - self.first).num_days();
        Ok(usize::try_from(offset).ok().filter(|at| *at < self.days))
    }

    /// Set every day of `from_day..to_day` (clipped to the window).
    fn mark(&self, flags: &mut [bool], from_day: &str, to_day: &str) -> Result<(), ReadError> {
        let start = (parse_date(from_day)? - self.first).num_days().max(0);
        let stop = (parse_date(to_day)? - self.first)
            .num_days()
            .min(self.days as i64 - 1);
        for position in start..=stop {
            if let Some(flag) = usize::try_from(position)
                .ok()
                .and_then(|at| flags.get_mut(at))
            {
                *flag = true;
            }
        }
        Ok(())
    }

    fn day(&self, position: usize) -> Result<String, ReadError> {
        let offset = i64::try_from(position).map_err(|_| ReadError::Overflow)?;
        shift(self.first, offset).map(iso)
    }
}

pub(crate) fn has_table(conn: &Connection, name: &str) -> Result<bool, ReadError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Python truthiness of a nullable text cell: NULL and `''` are falsy, as are zero and an empty blob;
/// any other non-text cell would make `strptime` raise a `TypeError`.
fn optional_text(cell: ValueRef<'_>) -> Result<Option<&str>, ReadError> {
    match cell {
        ValueRef::Null | ValueRef::Integer(0) => Ok(None),
        ValueRef::Real(0.0) => Ok(None),
        ValueRef::Blob([]) => Ok(None),
        ValueRef::Text(_) => text(cell).map(|found| Some(found).filter(|t| !t.is_empty())),
        _ => Err(ReadError::Unexpected("TypeError")),
    }
}

/// Every (metric, scope, stream) triple the store has actually produced.
fn observed_map(conn: &Connection) -> Result<BTreeSet<(String, String, String)>, ReadError> {
    let mut triples = BTreeSet::new();
    for table in ["daily_metrics", "daily_labels", "metric_samples"] {
        let mut statement = conn.prepare(&format!(
            "SELECT DISTINCT t.metric, t.source_scope, r.stream FROM {table} t \
             JOIN raw_records r ON r.id = t.raw_record_id"
        ))?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            triples.insert((
                text(row.get_ref(0)?)?.to_string(),
                text(row.get_ref(1)?)?.to_string(),
                text(row.get_ref(2)?)?.to_string(),
            ));
        }
    }
    Ok(triples)
}

/// Local dates a UTC span touches. The end is exclusive: one microsecond is taken off it unless the
/// span is empty or inverted, so a file ending at local midnight does not cover the day after.
fn span_days(
    offsets: &ClockOffsets,
    start_utc: Option<&str>,
    end_utc: Option<&str>,
) -> Result<Option<(String, String)>, ReadError> {
    let (Some(start_text), Some(end_text)) = (start_utc, end_utc) else {
        return Ok(None);
    };
    let (start, end) = (parse_moment(start_text)?, parse_moment(end_text)?);
    let first = local_day(offsets, start, false)?;
    let last = local_day(offsets, end, end > start)?;
    Ok(Some(if first <= last {
        (first, last)
    } else {
        (last, first)
    }))
}

/// Per stream, the days some retained file or claimed window spans; plus the undatable-file count.
fn covered_by_stream(
    conn: &Connection,
    window: &Window,
    offsets: &ClockOffsets,
    refinements: bool,
    session: &[String],
) -> Result<(BTreeMap<String, Flags>, i64), ReadError> {
    let mut covered: BTreeMap<String, Flags> = BTreeMap::new();
    let mut undatable = 0;
    let mut statement = conn.prepare("SELECT stream, start_utc, end_utc FROM raw_records")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let stream = text(row.get_ref(0)?)?;
        if session.iter().any(|s| s == stream) {
            continue; // a session claims no day
        }
        let span = span_days(
            offsets,
            optional_text(row.get_ref(1)?)?,
            optional_text(row.get_ref(2)?)?,
        )?;
        let Some((from_day, to_day)) = span else {
            undatable += 1;
            continue;
        };
        let flags = covered
            .entry(stream.to_string())
            .or_insert_with(|| vec![false; window.days]);
        window.mark(flags, &from_day, &to_day)?;
    }
    if refinements {
        let mut statement = conn.prepare("SELECT stream, from_day, to_day FROM export_ranges")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let stream = text(row.get_ref(0)?)?;
            let flags = covered
                .entry(stream.to_string())
                .or_insert_with(|| vec![false; window.days]);
            window.mark(flags, text(row.get_ref(1)?)?, text(row.get_ref(2)?)?)?;
        }
    }
    for (nightly, all_day) in NIGHTLY_DEVICE_STREAMS {
        if let Some(source) = covered.get(all_day).cloned() {
            let flags = covered
                .entry(nightly.to_string())
                .or_insert_with(|| vec![false; window.days]);
            for (flag, inherited) in flags.iter_mut().zip(source) {
                *flag |= inherited;
            }
        }
    }
    Ok((covered, undatable))
}

/// Per stream, the days a recorded failure spans; plus failures that cannot be placed on any day.
fn failed_by_stream(
    conn: &Connection,
    window: &Window,
    offsets: &ClockOffsets,
    refinements: bool,
    session: &[String],
) -> Result<(BTreeMap<String, Flags>, i64), ReadError> {
    let mut failed: BTreeMap<String, Flags> = BTreeMap::new();
    let mut unattributed = 0;
    if !refinements {
        return Ok((failed, unattributed));
    }
    let mut statement = conn.prepare(
        "SELECT f.stream, f.start_utc, f.end_utc, r.start_utc, r.end_utc FROM import_failures f \
         LEFT JOIN raw_records r ON r.id = f.raw_record_id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let own_stream = match row.get_ref(0)? {
            ValueRef::Null => None,
            cell => Some(text(cell)?),
        };
        if own_stream.is_some_and(|name| session.iter().any(|s| s == name)) {
            continue; // a refused session record is a failed raw record, not a failed day
        }
        // `start_utc or raw_start`: the failure's own span wins unless it is falsy
        let start = optional_text(row.get_ref(1)?)?.or(optional_text(row.get_ref(3)?)?);
        let end = optional_text(row.get_ref(2)?)?.or(optional_text(row.get_ref(4)?)?);
        let span = span_days(offsets, start, end)?;
        let stream = match row.get_ref(0)? {
            ValueRef::Null => None,
            cell => Some(text(cell)?),
        };
        let (Some(stream), Some((from_day, to_day))) = (stream, span) else {
            unattributed += 1;
            continue;
        };
        let flags = failed
            .entry(stream.to_string())
            .or_insert_with(|| vec![false; window.days]);
        window.mark(flags, &from_day, &to_day)?;
    }
    Ok((failed, unattributed))
}

/// `_HOUR_SAMPLES`: the samples of one (metric, scope) in one UTC hour bucket (`YYYY-MM-DDTHH`). The
/// `ts_utc` range lets SQLite search the sample index for the hour; with `substr` alone it walked every
/// row of the metric once per hour that holds a local midnight (7b-13 review: ~11 s on both cores for a
/// year of minutes on a half-hour-zone watch). The `substr` keeps the row set exactly the bucket's.
const HOUR_SAMPLES: &str = "SELECT ts_utc FROM metric_samples WHERE metric=? AND source_scope=? \
     AND ts_utc >= ? AND ts_utc < ? AND substr(ts_utc, 1, 13)=?";

/// `_hour_end`: the first text after every text that starts with `hour`: its last character, one higher.
fn hour_end(hour: &str) -> String {
    let mut chars: Vec<char> = hour.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = char::from_u32(u32::from(*last) + 1).unwrap_or(char::MAX);
    }
    chars.into_iter().collect()
}

/// Per (metric, scope), the local days that hold at least one row.
fn present_days(
    conn: &Connection,
    window: &Window,
    offsets: &ClockOffsets,
) -> Result<BTreeMap<Key, Flags>, ReadError> {
    let mut present: BTreeMap<Key, Flags> = BTreeMap::new();
    let (first, last) = (iso(window.first), iso(window.last));
    for table in ["daily_metrics", "daily_labels"] {
        let mut statement = conn.prepare(&format!(
            "SELECT DISTINCT metric, source_scope, date FROM {table} WHERE date BETWEEN ? AND ?"
        ))?;
        let mut rows = statement.query([&first, &last])?;
        while let Some(row) = rows.next()? {
            let (metric, scope) = (text(row.get_ref(0)?)?, text(row.get_ref(1)?)?);
            if let Some(position) = window.index(text(row.get_ref(2)?)?)? {
                mark_present(&mut present, window, metric, scope, position);
            }
        }
    }
    // Samples: resolve local dates once per UTC hour bucket, not per sample. Local days can begin up
    // to 14 h before/after their UTC namesake, so over-fetch one day each side.
    let low = iso(shift(window.first, -1)?);
    let high = iso(shift(window.last, 2)?);
    let mut statement = conn.prepare(
        "SELECT metric, source_scope, substr(ts_utc, 1, 13) FROM metric_samples \
         WHERE ts_utc >= ? AND ts_utc < ? GROUP BY 1, 2, 3",
    )?;
    let mut rows = statement.query([&low, &high])?;
    while let Some(row) = rows.next()? {
        let (metric, scope, hour) = (
            text(row.get_ref(0)?)?,
            text(row.get_ref(1)?)?,
            text(row.get_ref(2)?)?,
        );
        let first_day = local_day(offsets, parse_moment(&format!("{hour}:00:00Z"))?, false)?;
        let last_day = local_day(offsets, parse_moment(&format!("{hour}:59:59Z"))?, false)?;
        let days: BTreeSet<String> = if first_day == last_day {
            BTreeSet::from([first_day])
        } else {
            // a local midnight falls inside this hour (half-hour zones): resolve each sample
            let mut inner = conn.prepare(HOUR_SAMPLES)?;
            let end = hour_end(hour);
            let mut stamps = inner.query([metric, scope, hour, end.as_str(), hour])?;
            let mut found = BTreeSet::new();
            while let Some(stamp) = stamps.next()? {
                let moment = parse_moment(text(stamp.get_ref(0)?)?)?;
                found.insert(local_day(offsets, moment, false)?);
            }
            found
        };
        for day in days {
            if let Some(position) = window.index(&day)? {
                mark_present(&mut present, window, metric, scope, position);
            }
        }
    }
    Ok(present)
}

fn mark_present(
    present: &mut BTreeMap<Key, Flags>,
    window: &Window,
    metric: &str,
    scope: &str,
    position: usize,
) {
    let flags = present
        .entry((metric.to_string(), scope.to_string()))
        .or_insert_with(|| vec![false; window.days]);
    if let Some(flag) = flags.get_mut(position) {
        *flag = true;
    }
}

fn statuses_for(
    window: &Window,
    present: Option<&Flags>,
    streams: &BTreeSet<String>,
    covered: &BTreeMap<String, Flags>,
    failed: &BTreeMap<String, Flags>,
) -> Vec<&'static str> {
    let failed_flags: Vec<&Flags> = streams.iter().filter_map(|s| failed.get(s)).collect();
    let covered_flags: Vec<&Flags> = streams.iter().filter_map(|s| covered.get(s)).collect();
    let set = |flags: &Flags, position: usize| flags.get(position).copied().unwrap_or(false);
    (0..window.days)
        .map(|position| {
            if present.is_some_and(|flags| set(flags, position)) {
                PRESENT
            } else if failed_flags.iter().any(|flags| set(flags, position)) {
                FAILED
            } else if covered_flags.iter().any(|flags| set(flags, position)) {
                SOURCE_EMPTY
            } else {
                NOT_COVERED
            }
        })
        .collect()
}

/// Runs of consecutive non-present days with one status, oldest first; the newest `MAX_GAPS` kept.
fn gaps(window: &Window, statuses: &[&'static str]) -> Result<(Vec<Json>, bool), ReadError> {
    let mut found: Vec<Json> = Vec::new();
    let mut run_start: Option<usize> = None;
    for (position, status) in statuses.iter().copied().chain([PRESENT]).enumerate() {
        if let Some(start) = run_start
            && (status == PRESENT || Some(status) != statuses.get(start).copied())
        {
            found.push(Json::object([
                ("from", Json::text(&window.day(start)?)),
                ("to", Json::text(&window.day(position - 1)?)),
                (
                    "status",
                    Json::text(statuses.get(start).copied().unwrap_or(PRESENT)),
                ),
            ]));
            run_start = None;
        }
        if status != PRESENT && run_start.is_none() {
            run_start = Some(position);
        }
    }
    if found.len() > MAX_GAPS {
        let cut = found.len() - MAX_GAPS;
        return Ok((found.split_off(cut), true));
    }
    Ok((found, false))
}

/// Everything the ledger derives for one window, before it is shaped for a caller.
struct Analysis {
    window: Window,
    streams_for: Declared,
    drift: Vec<Json>,
    statuses: BTreeMap<Key, Vec<&'static str>>,
    undatable: i64,
    unattributed: i64,
    refinements: bool,
    offsets: ClockOffsets,
}

/// Declared streams per (metric, scope), plus any observed stream the declaration lacks.
fn declared_and_drift(
    conn: &Connection,
    contract: &Contract,
) -> Result<(Declared, Vec<Json>), ReadError> {
    let mut streams_for: Declared = contract
        .streams_for
        .iter()
        .map(|entry| {
            (
                (entry.metric.clone(), entry.source_scope.clone()),
                entry.streams.iter().cloned().collect(),
            )
        })
        .collect();
    let mut drift = Vec::new();
    for (metric, scope, stream) in observed_map(conn)? {
        if let Some(entry) = contract
            .session_streams_for
            .iter()
            .find(|e| e.metric == metric && e.source_scope == scope && e.streams.contains(&stream))
        {
            streams_for
                .entry((metric.clone(), scope.clone()))
                .or_default()
                .extend(entry.streams.iter().cloned());
            continue;
        }
        let declared = streams_for
            .entry((metric.clone(), scope.clone()))
            .or_default();
        if !declared.contains(&stream) {
            declared.insert(stream.clone());
            drift.push(Json::object([
                ("metric", Json::text(&metric)),
                ("source_scope", Json::text(&scope)),
                ("stream", Json::text(&stream)),
            ]));
        }
    }
    Ok((streams_for, drift))
}

/// The status of every local day in the window, for every (metric, scope) the store knows.
fn analyse(
    conn: &Connection,
    contract: &Contract,
    first_day: &str,
    last_day: &str,
) -> Result<Analysis, ReadError> {
    let window = Window::new(first_day, last_day)?;
    let offsets = load_offsets(conn)?;
    let refinements = has_table(conn, "export_ranges")? && has_table(conn, "import_failures")?;
    let (streams_for, drift) = declared_and_drift(conn, contract)?;
    let (covered, undatable) = covered_by_stream(conn, &window, &offsets, refinements, &contract.session_streams)?;
    let (failed, unattributed) = failed_by_stream(conn, &window, &offsets, refinements, &contract.session_streams)?;
    let present = present_days(conn, &window, &offsets)?;
    let statuses = streams_for
        .iter()
        .map(|(key, streams)| {
            (
                key.clone(),
                statuses_for(&window, present.get(key), streams, &covered, &failed),
            )
        })
        .collect();
    Ok(Analysis {
        window,
        streams_for,
        drift,
        statuses,
        undatable,
        unattributed,
        refinements,
        offsets,
    })
}

/// The coverage status of every local day from `first_day` to `last_day` for one metric and scope,
/// oldest first. A pair no stream can supply is `not_covered` throughout.
pub fn day_statuses(
    conn: &Connection,
    contract: &Contract,
    metric: &str,
    scope: &str,
    first_day: &str,
    last_day: &str,
) -> Result<Vec<(String, &'static str)>, ReadError> {
    let analysis = analyse(conn, contract, first_day, last_day)?;
    let statuses = analysis
        .statuses
        .get(&(metric.to_string(), scope.to_string()))
        .filter(|found| !found.is_empty())
        .cloned()
        .unwrap_or_else(|| vec![NOT_COVERED; analysis.window.days]);
    statuses
        .into_iter()
        .enumerate()
        .map(|(position, status)| Ok((analysis.window.day(position)?, status)))
        .collect()
}

/// The status of one local `day` for every (metric, scope) the store knows, in one pass.
pub fn statuses_on(
    conn: &Connection,
    contract: &Contract,
    day: &str,
) -> Result<BTreeMap<Key, &'static str>, ReadError> {
    let analysis = analyse(conn, contract, day, day)?;
    Ok(analysis
        .statuses
        .into_iter()
        .filter_map(|(key, statuses)| statuses.first().map(|status| (key, *status)))
        .collect())
}

/// The coverage block of `data_health`: per (metric, scope) counts and gaps over the window ending at
/// `last_day` (inclusive); `window_days` is clipped to [`MAX_WINDOW_DAYS`]. Plain data: no values,
/// no identifiers. Object keys are sorted (the `serve` wire form); [`ledger_ordered`] keeps Python's order.
pub fn ledger(
    conn: &Connection,
    contract: &Contract,
    last_day: &str,
    window_days: i64,
) -> Result<Value, ReadError> {
    ledger_ordered(conn, contract, last_day, window_days)?
        .to_serde()
        .ok_or(ReadError::Unexpected("TypeError"))
}

/// [`ledger`] with every object's keys in the order `coverage.ledger` inserts them.
pub fn ledger_ordered(
    conn: &Connection,
    contract: &Contract,
    last_day: &str,
    window_days: i64,
) -> Result<Json, ReadError> {
    let window_days = window_days.clamp(1, MAX_WINDOW_DAYS);
    let last = parse_date(last_day)?;
    let analysis = analyse(
        conn,
        contract,
        &iso(shift(last, -(window_days - 1))?),
        &iso(last),
    )?;
    let window = &analysis.window;
    let mut rows = Vec::new();
    for ((metric, scope), streams) in &analysis.streams_for {
        let statuses = analysis
            .statuses
            .get(&(metric.clone(), scope.clone()))
            .cloned()
            .unwrap_or_default();
        let (found, truncated) = gaps(window, &statuses)?;
        let count = |wanted: &str| Json::count(statuses.iter().filter(|s| **s == wanted).count());
        rows.push(Json::object([
            ("metric", Json::text(metric)),
            ("source_scope", Json::text(scope)),
            ("streams", Json::texts(streams)),
            ("sparse", Json::flag(contract.is_sparse(metric))),
            (PRESENT, count(PRESENT)),
            (FAILED, count(FAILED)),
            (SOURCE_EMPTY, count(SOURCE_EMPTY)),
            (NOT_COVERED, count(NOT_COVERED)),
            ("gaps", Json::Array(found)),
            ("gaps_truncated", Json::flag(truncated)),
        ]));
    }
    let refinements = if analysis.refinements {
        &contract.coverage_refinements.available
    } else {
        &contract.coverage_refinements.unavailable
    };
    Ok(Json::object([
        (
            "window",
            Json::object([
                ("from", Json::text(&iso(window.first))),
                ("to", Json::text(&iso(window.last))),
                ("days", Json::count(window.days)),
            ]),
        ),
        (
            "statuses",
            Json::Array(
                [PRESENT, FAILED, SOURCE_EMPTY, NOT_COVERED]
                    .into_iter()
                    .map(Json::text)
                    .collect(),
            ),
        ),
        ("ledger", Json::Array(rows)),
        ("map_drift", Json::Array(analysis.drift)),
        ("unattributed_failures", Json::int(analysis.unattributed)),
        ("undatable_files", Json::int(analysis.undatable)),
        ("refinements", Json::text(refinements)),
        ("refinements_available", Json::flag(analysis.refinements)),
    ]))
}

// ---- completeness (7b-12): how much of a day a per-minute metric's mean rests on -------------

/// `_day_bounds`: epoch seconds each window day starts at, plus the end of the last one
/// (`window.days + 1` entries). Local midnight is read under the offset nearest to it; UTC is
/// assumed where no offset is known. The bounds never step back (an offset jump of more than a day
/// leaves the day between empty, so `partition_point` searches a sorted slice and no piece is
/// negative); an offset that puts a midnight outside years 1-9999 is Python's `OverflowError`.
fn day_bounds(window: &Window, offsets: &ClockOffsets) -> Result<Vec<i64>, ReadError> {
    let mut bounds: Vec<i64> = Vec::with_capacity(window.days + 1);
    for position in 0..=window.days {
        let date = shift(window.first, i64::try_from(position).map_err(|_| ReadError::Overflow)?)?;
        let midnight: Instant = date.and_hms_opt(0, 0, 0).ok_or(ReadError::Overflow)?.and_utc();
        // `midnight - timedelta(seconds=offset)`
        let bound = Duration::try_seconds(offsets.offset_at(midnight).unwrap_or(0))
            .and_then(|by| midnight.checked_sub_signed(by))
            .filter(|moment| (1..=9999).contains(&moment.year()))
            .ok_or(ReadError::Overflow)?
            .timestamp();
        bounds.push(bounds.last().map_or(bound, |previous| bound.max(*previous)));
    }
    Ok(bounds)
}

/// `_add_clipped`: add the seconds of `[start, end)` that fall inside each window day to `seconds`.
fn add_clipped(start: i64, end: i64, bounds: &[i64], seconds: &mut [i64]) {
    let mut position = bounds.partition_point(|bound| *bound <= start).saturating_sub(1); // bisect_right - 1, floored at 0
    let mut start = start.max(bounds[0]);
    while position < seconds.len() && start < end {
        let piece_end = end.min(bounds[position + 1]);
        seconds[position] += piece_end - start;
        start = piece_end;
        position += 1;
    }
}

/// `_merged`: overlapping or touching spans folded into one each, in time order.
fn merged(mut spans: Vec<(i64, i64)>) -> Vec<(i64, i64)> {
    spans.sort_unstable();
    let mut out: Vec<(i64, i64)> = Vec::new();
    for (start, end) in spans {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

/// `_covered_seconds`: per window day, the seconds some retained file of `streams` spans (a claimed
/// window covers whole days).
fn covered_seconds(
    conn: &Connection,
    window: &Window,
    streams: &BTreeSet<String>,
    session: &[String],
    bounds: &[i64],
    refinements: bool,
) -> Result<Vec<i64>, ReadError> {
    let mut spans = Vec::new();
    let mut statement = conn.prepare("SELECT start_utc, end_utc FROM raw_records WHERE stream=?")?;
    for stream in streams {
        if session.iter().any(|s| s == stream) {
            continue; // a session claims no day
        }
        let mut rows = statement.query([stream])?;
        while let Some(row) = rows.next()? {
            if let (Some(start), Some(end)) = (optional_text(row.get_ref(0)?)?, optional_text(row.get_ref(1)?)?)
                && !start.is_empty()
                && !end.is_empty()
            {
                spans.push((parse_moment(start)?.timestamp(), parse_moment(end)?.timestamp()));
            }
        }
    }
    let mut seconds = vec![0; window.days];
    for (start, end) in merged(spans) {
        add_clipped(start, end, bounds, &mut seconds);
    }
    if refinements {
        let mut claimed = vec![false; window.days];
        let mut statement = conn.prepare("SELECT from_day, to_day FROM export_ranges WHERE stream=?")?;
        for stream in streams {
            let mut rows = statement.query([stream])?;
            while let Some(row) = rows.next()? {
                window.mark(&mut claimed, text(row.get_ref(0)?)?, text(row.get_ref(1)?)?)?;
            }
        }
        for (position, flag) in claimed.into_iter().enumerate() {
            if flag {
                seconds[position] = bounds[position + 1] - bounds[position];
            }
        }
    }
    Ok(seconds)
}

/// `_worn_seconds`: per window day, the seconds a reading accounts for: the gap to the next reading when
/// that is at most `WORN_GAP_S`, else its own minute (`READING_S`).
fn worn_seconds(
    conn: &Connection,
    metric: &str,
    scope: &str,
    window: &Window,
    bounds: &[i64],
) -> Result<Vec<i64>, ReadError> {
    let low = iso(shift(window.first, -1)?);
    let high = iso(shift(window.last, 2)?);
    let mut seconds = vec![0; window.days];
    let mut previous: Option<i64> = None;
    let mut statement = conn.prepare(
        "SELECT ts_utc FROM metric_samples WHERE metric=? AND source_scope=? AND ts_utc >= ? AND ts_utc < ? \
         ORDER BY ts_utc",
    )?;
    let mut rows = statement.query(rusqlite::params![metric, scope, low, high])?;
    while let Some(row) = rows.next()? {
        let moment = parse_moment(text(row.get_ref(0)?)?)?.timestamp();
        if let Some(earlier) = previous {
            let end = if moment - earlier <= WORN_GAP_S { moment } else { earlier + READING_S };
            add_clipped(earlier, end, bounds, &mut seconds);
        }
        previous = Some(moment);
    }
    if let Some(earlier) = previous {
        add_clipped(earlier, earlier + READING_S, bounds, &mut seconds);
    }
    Ok(seconds)
}

/// Per window position, the completeness share of one (metric, scope) from an analysis's offsets and stream
/// map (`COMPLETENESS_CONVENTION`): None for a pair that is not per-minute, for a session scope, and for a day
/// no file of the pair's streams spans.
fn completeness_from(
    conn: &Connection,
    contract: &Contract,
    metric: &str,
    scope: &str,
    window: &Window,
    offsets: &ClockOffsets,
    streams_for: &Declared,
) -> Result<Vec<Option<i64>>, ReadError> {
    let session_scope = contract.session_streams_for.iter().any(|entry| entry.source_scope == scope);
    if !contract.per_minute_metrics.iter().any(|m| m == metric) || session_scope {
        return Ok(vec![None; window.days]);
    }
    let streams = streams_for
        .get(&(metric.to_string(), scope.to_string()))
        .cloned()
        .unwrap_or_default();
    let bounds = day_bounds(window, offsets)?;
    let refinements = has_table(conn, "export_ranges")?;
    let covered = covered_seconds(conn, window, &streams, &contract.session_streams, &bounds, refinements)?;
    let worn = worn_seconds(conn, metric, scope, window, &bounds)?;
    Ok((0..window.days)
        .map(|position| (covered[position] > 0).then(|| (100 * worn[position] / covered[position]).min(100)))
        .collect())
}

/// One `calendar` row: the local day, its coverage status, its completeness share.
pub type CalendarDay = (String, &'static str, Option<i64>);

/// `(day, status, completeness)` for every local day from `first_day` to `last_day`, oldest first, in one
/// coverage pass: the status as `day_statuses` gives it, the completeness as `day_completeness` gives it
/// (7b-13: `metric_calendar` used to pay for the store-wide stream map twice).
pub fn calendar(
    conn: &Connection,
    contract: &Contract,
    metric: &str,
    scope: &str,
    first_day: &str,
    last_day: &str,
) -> Result<Vec<CalendarDay>, ReadError> {
    let analysis = analyse(conn, contract, first_day, last_day)?;
    let statuses = analysis
        .statuses
        .get(&(metric.to_string(), scope.to_string()))
        .filter(|found| !found.is_empty())
        .cloned()
        .unwrap_or_else(|| vec![NOT_COVERED; analysis.window.days]);
    let shares = completeness_from(
        conn,
        contract,
        metric,
        scope,
        &analysis.window,
        &analysis.offsets,
        &analysis.streams_for,
    )?;
    (0..analysis.window.days)
        .map(|position| Ok((analysis.window.day(position)?, statuses[position], shares[position])))
        .collect()
}

/// Per local day, the share (0-100) of the covered seconds a reading accounts for (the gap to the next reading
/// when at most `WORN_GAP_S`, else its minute; `COMPLETENESS_CONVENTION`); None for a pair that is not
/// per-minute, for a session scope, and for a day no file of the pair's streams spans. A projection of `calendar`.
pub fn day_completeness(
    conn: &Connection,
    contract: &Contract,
    metric: &str,
    scope: &str,
    first_day: &str,
    last_day: &str,
) -> Result<Vec<(String, Option<i64>)>, ReadError> {
    Ok(calendar(conn, contract, metric, scope, first_day, last_day)?
        .into_iter()
        .map(|(day, _status, share)| (day, share))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ClockOffset;
    use chrono::{TimeZone, Utc};

    /// A string member of a ledger object.
    fn field(object: &Json, key: &str) -> String {
        match object.get(key) {
            Some(Json::Str(text)) => text.units_lossy(),
            other => unreachable!("{key}: {other:?}"),
        }
    }

    fn window(first: &str, last: &str) -> Window {
        match Window::new(first, last) {
            Ok(window) => window,
            Err(error) => unreachable!("window: {error}"),
        }
    }

    #[test]
    fn a_window_clips_marks_and_refuses_an_inverted_range() {
        let w = window("2025-06-01", "2025-06-10");
        assert_eq!(w.days, 10);
        let mut flags = vec![false; w.days];
        assert!(w.mark(&mut flags, "2025-05-29", "2025-06-02").is_ok());
        assert!(w.mark(&mut flags, "2025-06-09", "2025-06-20").is_ok());
        assert!(w.mark(&mut flags, "2025-07-01", "2025-07-02").is_ok());
        assert_eq!(
            flags.iter().map(|f| u8::from(*f)).collect::<Vec<_>>(),
            [1, 1, 0, 0, 0, 0, 0, 0, 1, 1]
        );
        assert!(matches!(w.index("2025-06-10"), Ok(Some(9))));
        assert!(matches!(w.index("2025-06-11"), Ok(None)));
        assert!(matches!(w.index("2025-05-31"), Ok(None)));
        assert!(
            matches!(Window::new("2025-06-02", "2025-06-01"), Err(ReadError::Value(m)) if m == "last_day must not be before first_day")
        );
    }

    #[test]
    fn statuses_follow_the_precedence_present_failed_source_empty_not_covered() {
        let w = window("2025-06-01", "2025-06-04");
        let streams: BTreeSet<String> = ["fit:sleep".to_string()].into();
        let covered = BTreeMap::from([("fit:sleep".to_string(), vec![true, true, true, false])]);
        let failed = BTreeMap::from([("fit:sleep".to_string(), vec![false, true, true, false])]);
        let present = vec![false, false, true, false];
        assert_eq!(
            statuses_for(&w, Some(&present), &streams, &covered, &failed),
            [SOURCE_EMPTY, FAILED, PRESENT, NOT_COVERED]
        );
        assert_eq!(
            statuses_for(&w, None, &BTreeSet::new(), &covered, &failed),
            [NOT_COVERED; 4]
        );
    }

    #[test]
    fn gaps_are_runs_of_one_status_and_only_the_newest_twenty_are_kept() {
        let w = window("2025-01-01", "2025-03-31");
        let statuses: Vec<&'static str> = (0..w.days)
            .map(|day| if day % 2 == 0 { PRESENT } else { NOT_COVERED })
            .collect();
        let (found, truncated) = gaps(&w, &statuses).expect("gaps");
        assert!(truncated && found.len() == MAX_GAPS);
        assert_eq!(field(&found[MAX_GAPS - 1], "to"), "2025-03-31");
        let small = [
            "present",
            "source_empty",
            "source_empty",
            "failed",
            "present",
            "not_covered",
        ];
        let w = window("2025-06-01", "2025-06-06");
        let (found, truncated) = gaps(&w, &small).expect("gaps");
        assert!(!truncated);
        assert_eq!(field(&found[0], "from"), "2025-06-02");
        assert_eq!(field(&found[0], "to"), "2025-06-03");
        assert_eq!(field(&found[1], "status"), "failed");
        assert_eq!(field(&found[2], "from"), "2025-06-06");
    }

    #[test]
    fn a_span_ends_one_microsecond_before_its_exclusive_end() {
        let mut offsets = ClockOffsets::new();
        let at = |secs: i64| Utc.timestamp_opt(secs, 0).single().expect("instant");
        offsets.add(ClockOffset {
            ts_utc: at(0),
            offset_s: -18_000,
        });
        // 1970-01-02T05:00:00Z is local midnight at -05:00
        let span =
            |start: &str, end: &str| span_days(&offsets, Some(start), Some(end)).expect("span");
        assert_eq!(
            span("1970-01-01T05:00:00Z", "1970-01-02T05:00:00Z"),
            Some(("1970-01-01".into(), "1970-01-01".into()))
        );
        // an empty span and an inverted one do not lose the microsecond they never had
        assert_eq!(
            span("1970-01-02T05:00:00Z", "1970-01-02T05:00:00Z"),
            Some(("1970-01-02".into(), "1970-01-02".into()))
        );
        assert_eq!(
            span("1970-01-03T05:00:00Z", "1970-01-02T05:00:00Z"),
            Some(("1970-01-02".into(), "1970-01-03".into()))
        );
        assert_eq!(
            span_days(&offsets, None, Some("1970-01-02T05:00:00Z")).expect("span"),
            None
        );
        assert!(span_days(&offsets, Some("garbage"), Some("1970-01-02T05:00:00Z")).is_err());
    }

    #[test]
    fn the_midnight_hour_read_searches_the_sample_index() {
        // 7b-13 review: with `substr` alone SQLite walked every row of the metric once per midnight hour
        assert_eq!(hour_end("2025-06-01T18"), "2025-06-01T19");
        assert_eq!(hour_end("2025-06-01T09"), "2025-06-01T0:");
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::store::open_for_write_with(&dir.path().join("store.db"), "test", 5.0, None)
            .expect("store");
        let mut statement = store
            .conn()
            .prepare(&format!("EXPLAIN QUERY PLAN {HOUR_SAMPLES}"))
            .expect("plan");
        let plan = statement
            .query_map(
                ["heart_rate", "device", "2025-06-01T18", "2025-06-01T19", "2025-06-01T18"],
                |row| row.get::<_, String>(3),
            )
            .expect("rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("details")
            .join(" ");
        assert!(plan.contains("ts_utc>? AND ts_utc<?"), "{plan}");
    }

    #[test]
    fn nightly_streams_are_the_three_the_oracle_names() {
        assert_eq!(
            NIGHTLY_DEVICE_STREAMS.map(|(nightly, _)| nightly),
            ["fit:sleep", "fit:hrv", "fit:skin_temp"]
        );
        assert!(
            NIGHTLY_DEVICE_STREAMS
                .iter()
                .all(|(_, all_day)| *all_day == "fit:monitoring_b")
        );
    }
}
