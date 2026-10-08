// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-side queries: the twin of the parts of `disconect/queries.py` that `data.facts` reaches
//! (`_clean`, `sample_day_aggregates`) plus the store helpers `insight.py` brings (`_latest_stored_date`).
//! Every value is decoded by SQLite storage class (`ValueRef`), never through a declared Rust type.
//! `_window` is not here: `period_facts` never calls it (only `metric_series` does).

use std::collections::BTreeMap;

use chrono::{Datelike, Duration, NaiveDate};
use rusqlite::Connection;
use rusqlite::types::ValueRef;
use serde_json::{Value, json};

use super::ReadError;
use super::coverage;
use super::pyrepr;
use crate::clock::ClockOffsets;
use crate::contract::Contract;
use crate::model::Instant;
use crate::time::{iso_utc, now_instant, parse_iso_utc};
use crate::wirejson::PyStr;
use crate::writer::{py_round, py_sum};

/// `MAX_DAILY_DAYS` and `MAX_SAMPLE_DAYS`: the longest series a daily and a sample metric serve.
pub const MAX_DAILY_DAYS: i64 = 1825;
pub const MAX_SAMPLE_DAYS: i64 = 366;

/// `_clean`: floats rounded for presentation (FIT's fixed-point scales carry at most 3 decimals).
pub fn clean(value: f64) -> f64 {
    py_round(value, 3)
}

/// `_round(value)` of `insight.py`: `round(value, 2)`.
pub fn round2(value: f64) -> f64 {
    py_round(value, 2)
}

/// One local day of one sample metric: `{date, min, mean, max, samples}`.
#[derive(Debug, Clone, PartialEq)]
pub struct DayAggregate {
    pub date: String,
    pub min: f64,
    pub mean: f64,
    pub max: f64,
    pub samples: usize,
}

/// A numeric cell as Python's sqlite3 hands it over: REAL as a float. An INTEGER cell (a REAL column
/// forces them to floats on the way in, so none occurs in a store this software wrote) is widened;
/// anything else is a `TypeError` in the oracle.
pub(crate) fn number(cell: ValueRef<'_>) -> Result<f64, ReadError> {
    match cell {
        ValueRef::Real(value) => Ok(value),
        ValueRef::Integer(value) => Ok(value as f64),
        _ => Err(ReadError::Unexpected("TypeError")),
    }
}

/// A text cell (`UnicodeDecodeError` in the oracle when it is not UTF-8, `TypeError` for other classes).
pub(crate) fn text(cell: ValueRef<'_>) -> Result<&str, ReadError> {
    match cell {
        ValueRef::Text(bytes) => {
            std::str::from_utf8(bytes).map_err(|_| ReadError::Unexpected("UnicodeDecodeError"))
        }
        _ => Err(ReadError::Unexpected("TypeError")),
    }
}

/// `datetime.date.fromisoformat` for the one shape the store writes, `YYYY-MM-DD`, with CPython's
/// error texts. (Python 3.11+ also reads compact `YYYYMMDD` and ISO-week forms; neither a stored date
/// nor, here, a request may carry one: booked in `docs/kb/23` as "Python request-level permissiveness".)
pub fn parse_date(text: &str) -> Result<NaiveDate, ReadError> {
    let bytes = text.as_bytes();
    let well_formed = bytes.len() == 10
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit());
    if !well_formed {
        return Err(ReadError::Value(format!(
            "Invalid isoformat string: {}",
            pyrepr::repr_str(text)
        )));
    }
    let field =
        |range: std::ops::Range<usize>| text.get(range).and_then(|part| part.parse::<u32>().ok());
    let (Some(year), Some(month), Some(day)) = (field(0..4), field(5..7), field(8..10)) else {
        return Err(ReadError::Value("Invalid isoformat string".into()));
    };
    if year < 1 {
        return Err(ReadError::Value(format!(
            "year must be in 1..9999, not {year}"
        )));
    }
    if !(1..=12).contains(&month) {
        return Err(ReadError::Value(format!(
            "month must be in 1..12, not {month}"
        )));
    }
    let year = i32::try_from(year).unwrap_or(i32::MAX);
    let longest = (28..=31)
        .rev()
        .find(|last| NaiveDate::from_ymd_opt(year, month, *last).is_some())
        .unwrap_or(28);
    NaiveDate::from_ymd_opt(year, month, day).ok_or_else(|| {
        ReadError::Value(format!(
            "day {day} must be in range 1..{longest} for month {month} in year {year}"
        ))
    })
}

/// `parse_day`: `YYYY-MM-DD` and nothing else, as a request's own text (which may hold a lone
/// surrogate). Any other text, and a shape-correct day that is not on the calendar, is
/// `ValueError("<name> must be YYYY-MM-DD")`. It never overflows: `9999-12-31` and `0001-01-01` parse;
/// the `OverflowError` comes later, from the date arithmetic ([`window`], [`sample_day_aggregates`]).
pub fn parse_day(text: &PyStr, name: &str) -> Result<NaiveDate, ReadError> {
    text.to_text()
        .and_then(|plain| parse_date(&plain).ok())
        .ok_or_else(|| ReadError::Value(format!("{name} must be YYYY-MM-DD")))
}

/// `_today()`: the UTC date of the clock (not [`local_today`]: the series windows ignore the watch's offset).
pub fn today_utc() -> NaiveDate {
    now_instant().date_naive()
}

/// `_window`: `(from, to)` of the `days` (clamped to `1..=cap`) ending on `end_date`, or on today's UTC date
/// when it is absent or empty. `OverflowError` where the start leaves Python's date range.
pub fn window(
    days: i64,
    end_date: Option<&PyStr>,
    cap: i64,
) -> Result<(String, String), ReadError> {
    let days = days.clamp(1, cap);
    let end = match end_date.filter(|text| !text.is_empty()) {
        Some(text) => parse_day(text, "end_date")?,
        None => today_utc(),
    };
    let start = shift(end, 1 - days)?;
    Ok((iso(start), iso(end)))
}

/// `source_scope not in contract.SOURCE_SCOPES` -> `ValueError`, else the scopes to read: the one named,
/// or all of them (an empty text is not a scope: it fails the check).
/// The scopes `period_facts` answers when none is asked for: every contract scope but the ones a session
/// stream writes (`live`), so a link's minutes never shape the default facts (9b-2). A named scope, `live`
/// included, goes through `scopes_for` unchanged.
pub fn fact_scopes_for(
    contract: &Contract,
    source_scope: Option<&PyStr>,
) -> Result<Vec<String>, ReadError> {
    if source_scope.is_some() {
        return scopes_for(contract, source_scope);
    }
    Ok(contract
        .source_scopes
        .iter()
        .filter(|scope| !contract.session_streams_for.iter().any(|entry| &entry.source_scope == *scope))
        .cloned()
        .collect())
}

pub fn scopes_for(
    contract: &Contract,
    source_scope: Option<&PyStr>,
) -> Result<Vec<String>, ReadError> {
    let Some(requested) = source_scope else {
        return Ok(contract.source_scopes.clone());
    };
    match requested
        .to_text()
        .filter(|name| contract.source_scopes.contains(name))
    {
        Some(name) => Ok(vec![name]),
        None => {
            let names: Vec<String> = contract
                .source_scopes
                .iter()
                .map(|name| pyrepr::repr_str(name))
                .collect();
            Err(ReadError::Value(format!(
                "source_scope must be one of ({})",
                names.join(", ")
            )))
        }
    }
}

/// `date + timedelta(days=days)`, with Python's range: years 1 to 9999, else `OverflowError`.
pub fn shift(date: NaiveDate, days: i64) -> Result<NaiveDate, ReadError> {
    Duration::try_days(days)
        .and_then(|delta| date.checked_add_signed(delta))
        .filter(|moved| (1..=9999).contains(&moved.year()))
        .ok_or(ReadError::Overflow)
}

/// ISO `[low, high)` bounds that over-fetch one day before `first` and two after `last`, clamped to the
/// calendar (0001-01-01 .. 9999-12-31) instead of failing. Twin of Python's `coverage.fetch_window`.
pub fn fetch_window(first: NaiveDate, last: NaiveDate) -> (String, String) {
    let low = shift(first, -1).unwrap_or(first);
    const CALENDAR_END: NaiveDate = match NaiveDate::from_ymd_opt(9999, 12, 31) {
        Some(date) => date,
        None => unreachable!(),
    };
    let high = shift(last, 2).unwrap_or(CALENDAR_END);
    (iso(low), iso(high))
}

/// `date.isoformat()`.
pub fn iso(date: NaiveDate) -> String {
    format!("{:04}-{:02}-{:02}", date.year(), date.month(), date.day())
}

/// The clock offsets of the store; an unparseable stored moment is Python's `ValueError`.
pub fn load_offsets(conn: &Connection) -> Result<ClockOffsets, ReadError> {
    ClockOffsets::load(conn).map_err(|error| match error {
        rusqlite::Error::FromSqlConversionFailure(..) => {
            ReadError::Value("time data does not match format '%Y-%m-%dT%H:%M:%SZ'".into())
        }
        other => ReadError::Db(other),
    })
}

/// `parse_iso_utc` of a stored moment; a malformed one is Python's `ValueError`.
pub(crate) fn parse_moment(stamp: &str) -> Result<Instant, ReadError> {
    parse_iso_utc(stamp).ok_or_else(|| {
        ReadError::Value(format!(
            "time data {} does not match format '%Y-%m-%dT%H:%M:%SZ'",
            pyrepr::repr_str(stamp)
        ))
    })
}

/// The watch-local date at `moment`, or one microsecond before it (`before`); date arithmetic that
/// leaves Python's range is `OverflowError`.
pub(crate) fn local_day(
    offsets: &ClockOffsets,
    moment: Instant,
    before: bool,
) -> Result<String, ReadError> {
    offsets
        .local_date_checked(moment, before)
        .ok_or(ReadError::Overflow)
}

/// A float that goes into a response: Python's encoder refuses a non-finite one (`ValueError`).
pub(crate) fn json_number(value: f64) -> Result<Value, ReadError> {
    if value.is_finite() {
        Ok(json!(value))
    } else {
        Err(ReadError::Value(
            "Out of range float values are not JSON compliant".into(),
        ))
    }
}

/// `_today()`'s `now_utc()` and `local_today`: today as `YYYY-MM-DD`, the later of the UTC date and
/// the watch's local date (a watch ahead of UTC is already tomorrow; a store with no offset is UTC).
pub fn local_today(conn: &Connection) -> Result<String, ReadError> {
    local_today_at(conn, now_instant())
}

/// [`local_today`] for a given `now` (the tests pin it without touching the process environment).
pub fn local_today_at(conn: &Connection, now: Instant) -> Result<String, ReadError> {
    let local = local_day(&load_offsets(conn)?, now, false)?;
    let utc = iso(now.date_naive());
    Ok(if local > utc { local } else { utc })
}

/// `_latest_stored_date(conn, scopes)`: asked for session scopes only, the newest sample day of
/// those scopes (a session newer than the last cable sync stays reachable); else the plain rule.
pub fn latest_stored_date_for(
    conn: &Connection,
    contract: &Contract,
    scopes: &[String],
) -> Result<Option<String>, ReadError> {
    let is_session = |scope: &String| contract.session_streams_for.iter().any(|entry| &entry.source_scope == scope);
    if scopes.is_empty() || !scopes.iter().all(is_session) {
        return latest_stored_date(conn);
    }
    let marks = scopes.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!("SELECT MAX(substr(ts_utc, 1, 10)) FROM metric_samples WHERE source_scope IN ({marks})");
    let mut statement = conn.prepare(&sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(scopes.iter()))?;
    let Some(row) = rows.next()? else { return Ok(None) };
    Ok(match row.get_ref(0)? {
        rusqlite::types::ValueRef::Text(text) => Some(String::from_utf8_lossy(text).into_owned()),
        _ => None,
    })
}

/// `_latest_stored_date`: the later of the newest daily date and the newest sample's UTC date.
pub fn latest_stored_date(conn: &Connection) -> Result<Option<String>, ReadError> {
    let mut latest: Option<String> = None;
    for sql in [
        "SELECT MAX(date) FROM daily_metrics",
        "SELECT MAX(substr(ts_utc, 1, 10)) FROM metric_samples WHERE source_scope != 'live'",
    ] {
        let mut statement = conn.prepare(sql)?;
        let mut rows = statement.query([])?;
        if let Some(row) = rows.next()? {
            match row.get_ref(0)? {
                ValueRef::Null => {}
                cell => {
                    let candidate = text(cell)?;
                    // `candidates = [d for d in (daily, sample) if d]`: an empty string is skipped
                    if !candidate.is_empty()
                        && latest.as_deref().is_none_or(|best| candidate > best)
                    {
                        latest = Some(candidate.to_string());
                    }
                }
            }
        }
    }
    Ok(latest)
}

/// `sample_day_aggregates`: per-local-day min/mean/max/count for one sample-cadence metric, keyed by
/// source scope. The mean is the builtin `sum` (Neumaier) over the day's readings, rounded to 2 places.
pub fn sample_day_aggregates(
    conn: &Connection,
    metric: &str,
    start: &str,
    end: &str,
    offsets: &ClockOffsets,
    scopes: &[String],
) -> Result<BTreeMap<String, Vec<DayAggregate>>, ReadError> {
    // Local days can begin up to 14 h before/after their UTC namesake; over-fetch and filter.
    let (low, high) = fetch_window(parse_date(start)?, parse_date(end)?);
    let mut buckets: BTreeMap<String, BTreeMap<String, Vec<f64>>> = BTreeMap::new();
    let mut statement = conn.prepare(
        "SELECT ts_utc, value, source_scope FROM metric_samples WHERE metric=? \
         AND ts_utc >= ? AND ts_utc < ? ORDER BY ts_utc",
    )?;
    let mut rows = statement.query(rusqlite::params![metric, low, high])?;
    while let Some(row) = rows.next()? {
        let scope = text(row.get_ref(2)?)?;
        if !scopes.iter().any(|wanted| wanted == scope) {
            continue;
        }
        let stamp = text(row.get_ref(0)?)?;
        let moment = parse_moment(stamp)?;
        let day = local_day(offsets, moment, false)?;
        if start <= day.as_str() && day.as_str() <= end {
            let value = number(row.get_ref(1)?)?;
            buckets
                .entry(scope.to_string())
                .or_default()
                .entry(day)
                .or_default()
                .push(value);
        }
    }
    let mut out = BTreeMap::new();
    for (scope, days) in buckets {
        let points = days
            .into_iter()
            .map(|(date, values)| {
                let samples = values.len();
                DayAggregate {
                    date,
                    min: clean(
                        values
                            .iter()
                            .copied()
                            .fold(f64::INFINITY, |a, b| if b < a { b } else { a }),
                    ),
                    mean: round2(py_sum(values.iter().copied()) / samples as f64),
                    max: clean(
                        values
                            .iter()
                            .copied()
                            .fold(f64::NEG_INFINITY, |a, b| if b > a { b } else { a }),
                    ),
                    samples,
                }
            })
            .collect();
        out.insert(scope, points);
    }
    Ok(out)
}

/// A stored value as the oracle's `_clean` hands it on: a float rounded, anything else as it is. The
/// failure a Python response would hit later (a blob or a non-finite float cannot be written as JSON,
/// text that is not UTF-8 never decodes) is kept with the value, because only a value that reaches a
/// response can raise it.
type Stored = Result<Value, ReadError>;

fn stored(cell: ValueRef<'_>) -> Stored {
    match cell {
        ValueRef::Null => Ok(Value::Null),
        ValueRef::Integer(value) => Ok(json!(value)),
        ValueRef::Real(value) => json_number(clean(value)),
        ValueRef::Text(_) => text(cell).map(Value::from),
        ValueRef::Blob(_) => Err(ReadError::Unexpected("TypeError")),
    }
}

/// `_numeric_scope`: validate a (numeric metric, scope) pair and return the metric's cadence.
pub fn numeric_scope(
    contract: &Contract,
    metric: &PyStr,
    scope: &PyStr,
) -> Result<String, ReadError> {
    let cadence = metric
        .to_text()
        .and_then(|name| contract.cadence_for(&name).map(str::to_string));
    let Some(cadence) = cadence else {
        return Err(ReadError::Value(format!(
            "unknown numeric metric {}; see the contract for the list",
            pyrepr::repr(metric)
        )));
    };
    let known = scope
        .to_text()
        .is_some_and(|name| contract.source_scopes.contains(&name));
    if !known {
        let names: Vec<String> = contract.source_scopes.iter().map(|name| pyrepr::repr_str(name)).collect();
        return Err(ReadError::Value(
            format!("scope must be one of ({})", names.join(", ")),
        ));
    }
    Ok(cadence)
}

/// `_daily_values`: the stored value per local day for one daily metric and scope. A later row for
/// the same day replaces an earlier one, as in the oracle's dict.
fn daily_values(
    conn: &Connection,
    metric: &str,
    scope: &str,
    first_day: &str,
    last_day: &str,
) -> Result<BTreeMap<String, Stored>, ReadError> {
    let mut statement = conn.prepare(
        "SELECT date, value FROM daily_metrics WHERE metric=? AND source_scope=? AND date BETWEEN ? AND ?",
    )?;
    let mut rows = statement.query(rusqlite::params![metric, scope, first_day, last_day])?;
    let mut out = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let date = text(row.get_ref(0)?)?.to_string();
        out.insert(date, stored(row.get_ref(1)?));
    }
    Ok(out)
}

/// `_calendar_values`: the stored daily value, or the mean of that day's samples.
fn calendar_values(
    conn: &Connection,
    metric: &str,
    scope: &str,
    cadence: &str,
    first_day: &str,
    last_day: &str,
) -> Result<BTreeMap<String, Stored>, ReadError> {
    if cadence == "daily" {
        return daily_values(conn, metric, scope, first_day, last_day);
    }
    let offsets = load_offsets(conn)?;
    let scopes = vec![scope.to_string()];
    let aggregates =
        sample_day_aggregates(conn, metric, first_day, last_day, &offsets, &scopes)?;
    let mut out = BTreeMap::new();
    for point in aggregates.get(scope).map(Vec::as_slice).unwrap_or_default() {
        out.insert(point.date.clone(), json_number(point.mean));
    }
    Ok(out)
}

/// `metric_calendar`: every local day from `first_day` to `last_day` (inclusive, oldest first) as
/// `{day, value, status, completeness}`; `value` is null where the store has none and `status` says
/// why; `completeness` (0-100) says how much of the day a per-minute metric's mean rests on, null otherwise.
pub fn metric_calendar(
    conn: &Connection,
    contract: &Contract,
    metric: &PyStr,
    scope: &PyStr,
    first_day: &str,
    last_day: &str,
) -> Result<Vec<Value>, ReadError> {
    let cadence = numeric_scope(contract, metric, scope)?;
    let first = parse_date(first_day)?;
    let last = parse_date(last_day)?;
    let cap = if cadence == "daily" {
        MAX_DAILY_DAYS
    } else {
        MAX_SAMPLE_DAYS
    };
    let span = (last - first).num_days() + 1;
    if !(1..=cap).contains(&span) {
        return Err(ReadError::Value(format!(
            "the day range must cover 1 to {cap} days for {}",
            metric.to_text().unwrap_or_default()
        )));
    }
    // both texts are valid UTF-8: `numeric_scope` found them in the contract
    let (metric_text, scope_text) = (
        metric.to_text().unwrap_or_default(),
        scope.to_text().unwrap_or_default(),
    );
    let mut values = calendar_values(
        conn,
        &metric_text,
        &scope_text,
        &cadence,
        first_day,
        last_day,
    )?;
    let mut days = Vec::new();
    for (day, status, share) in coverage::calendar(conn, contract, &metric_text, &scope_text, first_day, last_day)? {
        let value = values.remove(&day).unwrap_or(Ok(Value::Null))?;
        days.push(json!({"day": day, "value": value, "status": status, "completeness": share}));
    }
    Ok(days)
}

/// `_latest_sample_day`: the local date of the newest stored sample of `metric` in `scope`.
fn latest_sample_day(
    conn: &Connection,
    metric: &str,
    offsets: &ClockOffsets,
    scope: &str,
) -> Result<Option<String>, ReadError> {
    let mut statement = conn
        .prepare("SELECT ts_utc, source_scope FROM metric_samples WHERE metric=? ORDER BY ts_utc DESC")?;
    let mut rows = statement.query([metric])?;
    while let Some(row) = rows.next()? {
        if text(row.get_ref(1)?)? == scope {
            let moment = parse_moment(text(row.get_ref(0)?)?)?;
            return local_day(offsets, moment, false).map(Some);
        }
    }
    Ok(None)
}

/// `LIVE_SCOPE`: the live link's source scope.
pub const LIVE_SCOPE: &str = "live";

/// `_local_minute`: `YYYY-MM-DDTHH:MM` on the watch's clock at `moment` (UTC assumed where no offset is known).
fn local_minute(moment: Instant, offsets: &ClockOffsets) -> Result<String, ReadError> {
    let offset = offsets.offset_at(moment).unwrap_or(0);
    moment
        .checked_add_signed(Duration::seconds(offset))
        .map(|local| local.format("%Y-%m-%dT%H:%M").to_string())
        .ok_or(ReadError::Overflow)
}

/// `live_day`: the live link on one local day — its sessions (runs of `json:live` records whose spans
/// overlap or touch, kept when their start or end falls on `day` on the watch's clock, each with its
/// count of distinct folded minutes from the first reading's minute) and, per metric the fold keeps in contract order, the minutes
/// whose local day is `day` with their lower median (null when none).
pub fn live_day(conn: &Connection, contract: &Contract, day: &PyStr) -> Result<Value, ReadError> {
    let date = parse_day(day, "day")?;
    let day = iso(date);
    let offsets = load_offsets(conn)?;
    let mut streams: Vec<&str> = Vec::new();
    for item in &contract.session_streams_for {
        if item.source_scope == LIVE_SCOPE {
            for stream in &item.streams {
                if !streams.contains(&stream.as_str()) {
                    streams.push(stream);
                }
            }
        }
    }
    let placeholders = vec!["?"; streams.len()].join(",");
    let mut sessions: Vec<(Instant, Instant)> = Vec::new();
    {
        let mut statement = conn.prepare(&format!(
            "SELECT start_utc, end_utc FROM raw_records WHERE stream IN ({placeholders}) \
             AND start_utc IS NOT NULL AND end_utc IS NOT NULL ORDER BY start_utc, end_utc"
        ))?;
        let mut rows = statement.query(rusqlite::params_from_iter(streams.iter()))?;
        while let Some(row) = rows.next()? {
            let first = parse_moment(text(row.get_ref(0)?)?)?;
            let last = parse_moment(text(row.get_ref(1)?)?)?;
            // a row written before the live import bound was lowered (9999-01-01Z) may have no local day the
            // calendar can hold: it is never listed instead of failing the whole read (the Python twin's _span_days)
            let (Some(first_day), Some(last_day)) =
                (offsets.local_date_checked(first, false), offsets.local_date_checked(last, false))
            else {
                continue;
            };
            if first_day != day && last_day != day {
                continue;
            }
            match sessions.last_mut() {
                Some(previous) if first <= previous.1 => {
                    if last > previous.1 {
                        previous.1 = last;
                    }
                }
                _ => sessions.push((first, last)),
            }
        }
    }
    let mut out_sessions = Vec::new();
    for (first, last) in &sessions {
        let (low, high) = (iso_utc(first), iso_utc(last));
        // the fold floors a reading to its minute, so the count starts at the first reading's minute
        let minute = first.format("%Y-%m-%dT%H:%M:00Z").to_string();
        let minutes: i64 = conn.query_row(
            "SELECT count(DISTINCT ts_utc) FROM metric_samples WHERE source_scope=? AND ts_utc BETWEEN ? AND ?",
            rusqlite::params![LIVE_SCOPE, minute, high],
            |row| row.get(0),
        )?;
        out_sessions.push(json!({
            "start_utc": low,
            "end_utc": high,
            "start_local": local_minute(*first, &offsets)?,
            "end_local": local_minute(*last, &offsets)?,
            "minutes": minutes,
        }));
    }
    // local days can begin up to 14 h before/after their UTC namesake; over-fetch and filter
    let (fetch_low, fetch_high) = fetch_window(date, date);
    let mut metrics = Vec::new();
    for item in &contract.metrics {
        let folded = contract
            .session_streams_for
            .iter()
            .any(|s| s.metric == item.metric && s.source_scope == LIVE_SCOPE);
        if !folded {
            continue;
        }
        let mut statement = conn.prepare(
            "SELECT ts_utc, value FROM metric_samples WHERE metric=? AND source_scope=? \
             AND ts_utc >= ? AND ts_utc < ? ORDER BY ts_utc",
        )?;
        let mut rows = statement.query(rusqlite::params![item.metric, LIVE_SCOPE, fetch_low, fetch_high])?;
        let mut values: Vec<(f64, Stored)> = Vec::new();
        while let Some(row) = rows.next()? {
            let moment = parse_moment(text(row.get_ref(0)?)?)?;
            if local_day(&offsets, moment, false)? != day {
                continue;
            }
            let cell = row.get_ref(1)?;
            values.push((number(cell)?, stored(cell)));
        }
        // the lower median: element (n - 1) / 2 of the ascending order (a stable sort, as Python's)
        values.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let count = values.len();
        let median = match count {
            0 => Value::Null,
            n => values.into_iter().nth((n - 1) / 2).map(|(_, v)| v).unwrap_or(Ok(Value::Null))?,
        };
        metrics.push(json!({"metric": item.metric, "unit": item.unit, "minutes": count, "median": median}));
    }
    Ok(json!({"day": day, "sessions": out_sessions, "metrics": metrics}))
}

/// `latest_value`: the newest `(local day, value)` stored for one numeric metric and scope, or None.
/// A sample metric reports the mean of its newest local day.
pub fn latest_value(
    conn: &Connection,
    contract: &Contract,
    metric: &str,
    scope: &str,
) -> Result<Option<(String, Value)>, ReadError> {
    let (metric_name, scope_name) = (PyStr::from_text(metric), PyStr::from_text(scope));
    let cadence = numeric_scope(contract, &metric_name, &scope_name)?;
    if cadence == "daily" {
        let mut statement = conn.prepare(
            "SELECT date, value FROM daily_metrics WHERE metric=? AND source_scope=? ORDER BY date DESC LIMIT 1",
        )?;
        let mut rows = statement.query([metric, scope])?;
        return match rows.next()? {
            Some(row) => {
                let day = text(row.get_ref(0)?)?.to_string();
                Ok(Some((day, stored(row.get_ref(1)?)?)))
            }
            None => Ok(None),
        };
    }
    let offsets = load_offsets(conn)?;
    let Some(day) = latest_sample_day(conn, metric, &offsets, scope)? else {
        return Ok(None);
    };
    let mut means = calendar_values(conn, metric, scope, &cadence, &day, &day)?;
    Ok(match means.remove(&day) {
        Some(mean) => Some((day, mean?)),
        None => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_parse_strictly_and_shift_within_pythons_range() {
        let date = parse_date("2025-06-30").map(iso);
        assert!(matches!(date.as_deref(), Ok("2025-06-30")));
        for bad in [
            "2025-6-30",
            "20250630",
            "2025-13-01",
            "2025-02-30",
            "2025-06-30 ",
            "",
            "２０２５-06-30",
        ] {
            assert!(
                matches!(parse_date(bad), Err(ReadError::Value(_))),
                "{bad:?}"
            );
        }
        let first = parse_date("0001-01-01");
        assert!(first.is_ok_and(|d| shift(d, -1).is_err()));
        let last = parse_date("9999-12-30");
        assert!(last.is_ok_and(|d| shift(d, 2).is_err() && shift(d, 1).is_ok()));
    }

    #[test]
    fn cells_are_decoded_by_storage_class() {
        assert!(matches!(number(ValueRef::Real(1.5)), Ok(v) if v == 1.5));
        assert!(matches!(number(ValueRef::Integer(3)), Ok(v) if v == 3.0));
        assert!(number(ValueRef::Null).is_err() && number(ValueRef::Text(b"1")).is_err());
        assert!(text(ValueRef::Integer(1)).is_err() && text(ValueRef::Text(&[0xff])).is_err());
    }

    #[test]
    fn a_tie_in_the_mean_rounds_half_even_like_python() {
        let conn = Connection::open_in_memory();
        let Ok(conn) = conn else {
            unreachable!("memory database")
        };
        let setup = conn.execute_batch(
            "CREATE TABLE metric_samples(metric TEXT, ts_utc TEXT, value REAL, source_scope TEXT);
             INSERT INTO metric_samples VALUES('stress','2025-06-01T10:00:00Z',60.0,'device');
             INSERT INTO metric_samples VALUES('stress','2025-06-01T11:00:00Z',60.25,'device');
             INSERT INTO metric_samples VALUES('stress','2025-06-01T12:00:00Z',1.0005,'other');",
        );
        assert!(setup.is_ok());
        let offsets = ClockOffsets::new();
        let scopes = vec!["device".to_string()];
        let found = sample_day_aggregates(
            &conn,
            "stress",
            "2025-06-01",
            "2025-06-02",
            &offsets,
            &scopes,
        );
        let Ok(found) = found else {
            unreachable!("query")
        };
        let day = &found["device"][0];
        assert_eq!(
            (day.mean, day.min, day.max, day.samples),
            (60.12, 60.0, 60.25, 2)
        );
        assert!(!found.contains_key("other"));
    }

    fn store_with_offsets(offsets: &[(&str, i64)]) -> Connection {
        let Ok(conn) = Connection::open_in_memory() else {
            unreachable!("memory database")
        };
        let setup = conn.execute_batch(
            "CREATE TABLE clock_offsets(ts_utc TEXT NOT NULL, offset_s INTEGER NOT NULL, device_id TEXT, raw_record_id INTEGER);",
        );
        assert!(setup.is_ok());
        for (stamp, offset) in offsets {
            let added = conn.execute(
                "INSERT INTO clock_offsets(ts_utc, offset_s) VALUES(?, ?)",
                rusqlite::params![stamp, offset],
            );
            assert!(added.is_ok());
        }
        conn
    }

    fn today(conn: &Connection, now: &str) -> String {
        let moment = parse_iso_utc(now);
        let Some(moment) = moment else {
            unreachable!("test instant")
        };
        match local_today_at(conn, moment) {
            Ok(day) => day,
            Err(error) => unreachable!("local_today: {error}"),
        }
    }

    #[test]
    fn today_is_the_later_of_the_utc_date_and_the_watch_date() {
        // the watch ahead of UTC (+03:30): 21:00Z is already the next day there
        let ahead = store_with_offsets(&[("2025-06-20T00:00:00Z", 12_600)]);
        assert_eq!(today(&ahead, "2025-07-02T09:30:00Z"), "2025-07-02");
        assert_eq!(today(&ahead, "2025-07-02T21:00:00Z"), "2025-07-03");
        assert_eq!(today(&ahead, "2025-07-02T20:29:59Z"), "2025-07-02");
        assert_eq!(today(&ahead, "2025-07-02T20:30:00Z"), "2025-07-03");
        // the watch behind UTC (-05:00): UTC's date is the later one
        let behind = store_with_offsets(&[("2025-03-01T00:00:00Z", -18_000)]);
        assert_eq!(today(&behind, "2025-03-06T02:00:00Z"), "2025-03-06");
        // no offset known: UTC
        let none = store_with_offsets(&[]);
        assert_eq!(today(&none, "2031-01-01T00:00:00Z"), "2031-01-01");
    }

    #[test]
    fn a_stored_value_keeps_its_class_and_fails_only_when_it_reaches_a_response() {
        assert!(matches!(stored(ValueRef::Real(1.23456)), Ok(v) if v == json!(1.235)));
        assert!(matches!(stored(ValueRef::Integer(3)), Ok(v) if v == json!(3)));
        assert!(matches!(stored(ValueRef::Null), Ok(Value::Null)));
        assert!(matches!(stored(ValueRef::Text(b"x")), Ok(v) if v == json!("x")));
        assert!(matches!(stored(ValueRef::Blob(b"x")), Err(ReadError::Unexpected("TypeError"))));
        assert!(matches!(stored(ValueRef::Real(f64::INFINITY)), Err(ReadError::Value(_))));
    }

    #[test]
    fn the_numeric_scope_check_quotes_python_reprs() {
        let Ok(contract) = Contract::get() else {
            unreachable!("contract")
        };
        let steps = PyStr::from_text("steps");
        let local = PyStr::from_text("local");
        assert!(matches!(numeric_scope(contract, &steps, &local).as_deref(), Ok("daily")));
        let heart = PyStr::from_text("heart_rate");
        assert!(matches!(numeric_scope(contract, &heart, &local).as_deref(), Ok("sample")));
        let unknown = numeric_scope(contract, &PyStr::from_text("it's"), &local);
        assert!(matches!(&unknown, Err(ReadError::Value(m))
            if m == "unknown numeric metric \"it's\"; see the contract for the list"));
        let scope = numeric_scope(contract, &steps, &PyStr::from_text("cloud"));
        assert!(matches!(&scope, Err(ReadError::Value(m))
            if m == "scope must be one of ('device', 'vendor_cloud', 'local', 'live')"));
        // a label is not a numeric metric
        assert!(numeric_scope(contract, &PyStr::from_text("hrv_status"), &local).is_err());
    }

    #[test]
    fn date_errors_carry_cpythons_texts() {
        let text = |input: &str| match parse_date(input) {
            Err(ReadError::Value(message)) => message,
            other => unreachable!("{input:?}: {other:?}"),
        };
        assert_eq!(text("nonsense"), "Invalid isoformat string: 'nonsense'");
        assert_eq!(text("2025-13-01"), "month must be in 1..12, not 13");
        assert_eq!(text("2025-02-30"), "day 30 must be in range 1..28 for month 2 in year 2025");
        assert_eq!(text("2024-02-30"), "day 30 must be in range 1..29 for month 2 in year 2024");
        assert_eq!(text("2025-06-00"), "day 0 must be in range 1..30 for month 6 in year 2025");
        assert_eq!(text("0000-01-01"), "year must be in 1..9999, not 0");
        assert_eq!(text("20261003"), "Invalid isoformat string: '20261003'");
        assert_eq!(text("2026-W40-6"), "Invalid isoformat string: '2026-W40-6'");
    }
}
