// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-side queries: the twin of the parts of `hearthbeat/queries.py` that `data.facts` reaches
//! (`_clean`, `sample_day_aggregates`) plus the store helpers `insight.py` brings (`_latest_stored_date`).
//! Every value is decoded by SQLite storage class (`ValueRef`), never through a declared Rust type.
//! `_window` is not here: `period_facts` never calls it (only `metric_series` does).

use std::collections::BTreeMap;

use chrono::{Datelike, Duration, NaiveDate};
use rusqlite::Connection;
use rusqlite::types::ValueRef;

use super::ReadError;
use crate::clock::ClockOffsets;
use crate::time::parse_iso_utc;
use crate::writer::{py_round, py_sum};

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

/// `datetime.date.fromisoformat` for the one shape the store writes, `YYYY-MM-DD`. (Python 3.14 also
/// reads compact and week forms; a request cannot reach this function with one, and no stored date
/// has one: booked in `docs/kb/23`.)
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
            "Invalid isoformat string: {text:?}"
        )));
    }
    let field =
        |range: std::ops::Range<usize>| text.get(range).and_then(|part| part.parse::<u32>().ok());
    let date = field(0..4)
        .zip(field(5..7))
        .zip(field(8..10))
        .and_then(|((year, month), day)| {
            NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, month, day)
        });
    date.ok_or_else(|| ReadError::Value("day is out of range for month".into()))
}

/// `date + timedelta(days=days)`, with Python's range: years 1 to 9999, else `OverflowError`.
pub fn shift(date: NaiveDate, days: i64) -> Result<NaiveDate, ReadError> {
    Duration::try_days(days)
        .and_then(|delta| date.checked_add_signed(delta))
        .filter(|moved| (1..=9999).contains(&moved.year()))
        .ok_or(ReadError::Unexpected("OverflowError"))
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

/// `_latest_stored_date`: the later of the newest daily date and the newest sample's UTC date.
pub fn latest_stored_date(conn: &Connection) -> Result<Option<String>, ReadError> {
    let mut latest: Option<String> = None;
    for sql in [
        "SELECT MAX(date) FROM daily_metrics",
        "SELECT MAX(substr(ts_utc, 1, 10)) FROM metric_samples",
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
    let low = iso(shift(parse_date(start)?, -1)?);
    let high = iso(shift(parse_date(end)?, 2)?);
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
        let moment = parse_iso_utc(stamp).ok_or_else(|| {
            ReadError::Value(format!(
                "time data {stamp:?} does not match format '%Y-%m-%dT%H:%M:%SZ'"
            ))
        })?;
        let day = offsets.local_date(moment);
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
}
