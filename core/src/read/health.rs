// SPDX-License-Identifier: AGPL-3.0-or-later
//! Data health and the import history: the twin of `disconect/health.py` (`data_health`,
//! `source_agreement`) and of `serve.import_last`. Everything is decoded by SQLite storage class
//! (`stream_provenance` is `SELECT *` in the oracle, so its columns follow the schema), and the shapes
//! are the oracle's exactly: `contract_version` is the *string* here (the oracle's `CONTRACT_VERSION`;
//! `app.info.contract` is its `int`), `total` is an object or null, `days_in_window` is an integer for
//! a sample metric and an object for a daily one. `summarize_for_humans` is the CLI's and is not ported.
//!
//! A value Python cannot write as JSON (a BLOB, a non-finite float) fails its response only at the
//! end, after every other step has run; here the first such value is kept and raised last, so a
//! request that would fail earlier for another reason still fails with that reason.

use std::collections::BTreeMap;

use chrono::Duration;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, Row};
use serde_json::{Map, Value, json};

use super::ReadError;
use super::coverage::{self, has_table};
use super::queries::{self, iso, json_number, number, text};
use crate::contract::Contract;
use crate::model::Instant;
use crate::redact::redact_text;
use crate::writer::{py_round, py_sum};

/// `serve.DEFAULT_HEALTH_DAYS`.
pub const DEFAULT_HEALTH_DAYS: i64 = 90;
/// `serve.LAST_IMPORTS`: how many runs `import.last` (and `data.health`) report.
pub const LAST_IMPORTS: i64 = 5;
/// `data_health` clamps its window to this many days.
pub const MAX_HEALTH_DAYS: i64 = 3650;

const RUN_COLUMNS: [&str; 11] = [
    "id",
    "started_at",
    "finished_at",
    "transport",
    "status",
    "files_seen",
    "files_imported",
    "files_duplicate",
    "files_failed",
    "records_written",
    "error",
];

/// Collects the one failure Python raises last: encoding the response.
#[derive(Default)]
struct Late(Option<ReadError>);

impl Late {
    /// One cell as the JSON value Python's sqlite3 would hand to `json.dumps`.
    fn cell(&mut self, cell: ValueRef<'_>) -> Value {
        let found = match cell {
            ValueRef::Null => Ok(Value::Null),
            ValueRef::Integer(value) => Ok(Value::from(value)),
            ValueRef::Real(value) => json_number(value),
            ValueRef::Text(_) => text(cell).map(Value::from),
            ValueRef::Blob(_) => Err(ReadError::Unexpected("TypeError")),
        };
        found.unwrap_or_else(|error| {
            self.0.get_or_insert(error);
            Value::Null
        })
    }

    fn column(&mut self, row: &Row<'_>, index: usize) -> Result<Value, ReadError> {
        Ok(self.cell(row.get_ref(index)?))
    }

    fn finish(self) -> Result<(), ReadError> {
        self.0.map_or(Ok(()), Err)
    }
}

/// `redact_text(cell)`: None stays None; any other class is a `TypeError` in the oracle.
fn redacted(cell: ValueRef<'_>) -> Result<Value, ReadError> {
    match cell {
        ValueRef::Null => Ok(Value::Null),
        ValueRef::Text(_) => Ok(Value::from(redact_text(text(cell)?))),
        _ => Err(ReadError::Unexpected("TypeError")),
    }
}

/// `_rows`: every row of `sql` as an object keyed by the statement's own column names.
fn rows_of(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
    late: &mut Late,
    redact: &[&str],
) -> Result<Vec<Map<String, Value>>, ReadError> {
    let mut statement = conn.prepare(sql)?;
    let names: Vec<String> = statement
        .column_names()
        .iter()
        .map(|n| n.to_string())
        .collect();
    let mut rows = statement.query(params)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut object = Map::new();
        for (index, name) in names.iter().enumerate() {
            let value = if redact.contains(&name.as_str()) {
                redacted(row.get_ref(index)?)?
            } else {
                late.column(row, index)?
            };
            object.insert(name.clone(), value);
        }
        out.push(object);
    }
    Ok(out)
}

/// `round(value, 3)` as a JSON number (a non-finite one cannot be written: `ValueError`).
fn round3(value: f64) -> Result<Value, ReadError> {
    json_number(py_round(value, 3))
}

type PairKey = (String, Option<String>, String, String);

/// `source_agreement`: where two sources state the same daily figure on the same date, how closely
/// they agree. Same metric in two scopes, plus the contract's comparison targets (our id against the
/// vendor's id for the same quantity). The first join is ordered (`ORDER BY a.date, ...`), because the
/// mean is a floating-point sum whose result depends on order.
pub fn source_agreement(conn: &Connection, contract: &Contract) -> Result<Vec<Value>, ReadError> {
    let mut pairs: BTreeMap<PairKey, Vec<(f64, f64)>> = BTreeMap::new();
    {
        let mut statement = conn.prepare(
            "SELECT a.metric, a.source_scope, b.source_scope, a.value, b.value FROM daily_metrics a \
             JOIN daily_metrics b ON b.date = a.date AND b.metric = a.metric \
             AND a.source_scope < b.source_scope ORDER BY a.date, a.metric, a.source_scope, b.source_scope",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let key = (
                text(row.get_ref(0)?)?.to_string(),
                None,
                text(row.get_ref(1)?)?.to_string(),
                text(row.get_ref(2)?)?.to_string(),
            );
            let values = (number(row.get_ref(3)?)?, number(row.get_ref(4)?)?);
            pairs.entry(key).or_default().push(values);
        }
    }
    for target in &contract.comparison_targets {
        let mut statement = conn.prepare(
            "SELECT a.value, b.value FROM daily_metrics a JOIN daily_metrics b ON b.date = a.date \
             WHERE a.metric=? AND a.source_scope=? AND b.metric=? AND b.source_scope=?",
        )?;
        let mut rows = statement.query(rusqlite::params![
            target.metric,
            target.source_scope,
            target.compared_with,
            target.compared_scope
        ])?;
        let mut values = Vec::new();
        while let Some(row) = rows.next()? {
            values.push((number(row.get_ref(0)?)?, number(row.get_ref(1)?)?));
        }
        if !values.is_empty() {
            let key = (
                target.metric.clone(),
                Some(target.compared_with.clone()),
                target.source_scope.clone(),
                target.compared_scope.clone(),
            );
            pairs.insert(key, values);
        }
    }
    let mut ordered: Vec<(PairKey, Vec<(f64, f64)>)> = pairs.into_iter().collect();
    // sorted(key=(metric, compared_with or "", (scope_a, scope_b)))
    ordered.sort_by(|(a, _), (b, _)| {
        (&a.0, a.1.as_deref().unwrap_or(""), &a.2, &a.3).cmp(&(
            &b.0,
            b.1.as_deref().unwrap_or(""),
            &b.2,
            &b.3,
        ))
    });
    let mut report = Vec::new();
    for ((metric, compared_with, scope_a, scope_b), values) in ordered {
        let diffs: Vec<f64> = values.iter().map(|(a, b)| a - b).collect();
        let matching = values
            .iter()
            .zip(&diffs)
            .filter(|((_, b), d)| d.abs() <= f64::max(0.5, 0.005 * b.abs()))
            .count();
        let mut absolute: Vec<f64> = diffs.iter().map(|d| d.abs()).collect();
        absolute.sort_by(f64::total_cmp);
        let (Some(median), Some(largest)) = (absolute.get(absolute.len() / 2), absolute.last())
        else {
            continue; // unreachable: a pair exists only with at least one row
        };
        report.push(json!({
            "metric": metric,
            "compared_with": compared_with,
            "unit": contract.unit_for(&metric),
            "scope_a": scope_a,
            "scope_b": scope_b,
            "days_compared": values.len(),
            "days_matching": matching,
            "median_abs_diff": round3(*median)?,
            "max_abs_diff": round3(*largest)?,
            "mean_diff_a_minus_b": round3(py_sum(diffs.iter().copied()) / diffs.len() as f64)?,
        }));
    }
    Ok(report)
}

/// `{days_with_data, first_day, last_day}` for one group of a stored-day aggregate.
fn span(late: &mut Late, row: &Row<'_>, first: usize) -> Result<Value, ReadError> {
    Ok(json!({
        "days_with_data": late.column(row, first)?,
        "first_day": late.column(row, first + 1)?,
        "last_day": late.column(row, first + 2)?,
    }))
}

/// `data_health(conn, window_days)`: coverage, provenance and recent imports as plain data (the
/// oracle's `conventions` block is part of the result; `serve` drops it). `now` is the one clock.
pub fn data_health(
    conn: &Connection,
    contract: &Contract,
    window_days: i64,
    now: Instant,
) -> Result<Value, ReadError> {
    let window_days = window_days.clamp(1, MAX_HEALTH_DAYS);
    let today = iso(now.date_naive());
    let since = Duration::try_days(window_days)
        .and_then(|delta| now.checked_sub_signed(delta))
        .map(|then| iso(then.date_naive()))
        .ok_or(ReadError::Unexpected("OverflowError"))?;
    let mut late = Late::default();

    let mut streams = Map::new();
    {
        let mut statement = conn.prepare(
            "SELECT stream, COUNT(*), MIN(start_utc), MAX(end_utc) FROM raw_records GROUP BY stream",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let stream = text(row.get_ref(0)?)?.to_string();
            streams.insert(
                stream,
                json!({
                    "records": late.column(row, 1)?,
                    "first": late.column(row, 2)?,
                    "last": late.column(row, 3)?,
                }),
            );
        }
    }

    let provenance: Vec<Value> = rows_of(
        conn,
        "SELECT * FROM stream_provenance ORDER BY stream",
        [],
        &mut late,
        &["last_parse_error_message", "last_write_error_message"],
    )?
    .into_iter()
    .map(Value::Object)
    .collect();

    let mut samples_total: BTreeMap<String, Value> = BTreeMap::new();
    {
        let mut statement = conn.prepare(
            "SELECT metric, COUNT(DISTINCT substr(ts_utc,1,10)), MIN(substr(ts_utc,1,10)), \
             MAX(substr(ts_utc,1,10)) FROM metric_samples GROUP BY metric",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let metric = text(row.get_ref(0)?)?.to_string();
            samples_total.insert(metric, span(&mut late, row, 1)?);
        }
    }
    let mut samples_window: BTreeMap<String, Value> = BTreeMap::new();
    {
        let mut statement = conn.prepare(
            "SELECT metric, COUNT(DISTINCT substr(ts_utc,1,10)) FROM metric_samples \
             WHERE substr(ts_utc,1,10) >= ? GROUP BY metric",
        )?;
        let mut rows = statement.query([&since])?;
        while let Some(row) = rows.next()? {
            let metric = text(row.get_ref(0)?)?.to_string();
            samples_window.insert(metric, late.column(row, 1)?);
        }
    }

    let mut daily_total: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    {
        let mut statement = conn.prepare(
            "SELECT metric, source_scope, COUNT(*), MIN(date), MAX(date) FROM daily_metrics \
             GROUP BY metric, source_scope",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let metric = text(row.get_ref(0)?)?.to_string();
            let scope = text(row.get_ref(1)?)?.to_string();
            daily_total
                .entry(metric)
                .or_default()
                .insert(scope, span(&mut late, row, 2)?);
        }
    }
    let mut daily_window: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    {
        let mut statement = conn.prepare(
            "SELECT metric, source_scope, COUNT(*) FROM daily_metrics WHERE date >= ? \
             GROUP BY metric, source_scope",
        )?;
        let mut rows = statement.query([&since])?;
        while let Some(row) = rows.next()? {
            let metric = text(row.get_ref(0)?)?.to_string();
            let scope = text(row.get_ref(1)?)?.to_string();
            daily_window
                .entry(metric)
                .or_default()
                .insert(scope, late.column(row, 2)?);
        }
    }

    let mut sleep = Map::new();
    {
        let mut statement = conn.prepare(
            "SELECT source_scope, COUNT(*), MIN(date), MAX(date) FROM sleep_sessions GROUP BY source_scope",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let scope = text(row.get_ref(0)?)?.to_string();
            sleep.insert(
                scope,
                json!({
                    "nights": late.column(row, 1)?,
                    "first_day": late.column(row, 2)?,
                    "last_day": late.column(row, 3)?,
                }),
            );
        }
    }
    let activities: i64 =
        conn.query_row("SELECT COUNT(*) FROM activities", [], |row| row.get(0))?;
    let offsets: i64 =
        conn.query_row("SELECT COUNT(*) FROM clock_offsets", [], |row| row.get(0))?;

    let runs: Vec<Value> = recent_runs(conn, &mut late)?
        .into_iter()
        .map(Value::Object)
        .collect();

    let metrics: Vec<Value> = contract
        .metrics
        .iter()
        .map(|item| {
            let (total, days_in_window) = if item.cadence == "sample" {
                (
                    samples_total
                        .get(&item.metric)
                        .cloned()
                        .unwrap_or(Value::Null),
                    samples_window
                        .get(&item.metric)
                        .cloned()
                        .unwrap_or(json!(0)),
                )
            } else {
                (
                    daily_total
                        .get(&item.metric)
                        .cloned()
                        .map_or(Value::Null, Value::Object),
                    Value::Object(daily_window.get(&item.metric).cloned().unwrap_or_default()),
                )
            };
            json!({"metric": item.metric, "unit": item.unit, "cadence": item.cadence,
                   "total": total, "days_in_window": days_in_window})
        })
        .collect();

    let local_today = queries::local_today_at(conn, now)?;
    let ledger = coverage::ledger(conn, contract, &local_today, window_days)?;
    let schema_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let agreement = source_agreement(conn, contract)?;
    late.finish()?;
    let conventions = &contract.conventions;
    Ok(json!({
        "contract_version": contract.contract_version,
        "coverage": ledger,
        "schema_version": schema_version,
        "window": {"days": window_days, "from": since, "to": today},
        "never_imported": streams.is_empty(),
        "streams": streams,
        "provenance": provenance,
        "metrics": metrics,
        "sleep": sleep,
        "activities": activities,
        "clock_offsets_known": offsets,
        "source_agreement": agreement,
        "recent_imports": runs,
        "conventions": {
            "time": conventions.time,
            "missing_values": conventions.missing_values,
            "sources": conventions.sources,
            "coverage": conventions.coverage,
        },
    }))
}

/// The newest [`LAST_IMPORTS`] runs with their 11 columns, `error` redacted (`data_health`'s
/// `recent_imports` and, with a `failures` count added, `import.last`).
fn recent_runs(conn: &Connection, late: &mut Late) -> Result<Vec<Map<String, Value>>, ReadError> {
    let sql = format!(
        "SELECT {} FROM import_runs ORDER BY id DESC LIMIT ?",
        RUN_COLUMNS.join(", ")
    );
    rows_of(conn, &sql, [LAST_IMPORTS], late, &["error"])
}

/// `serve.import_last`: `{"runs": [...]}`, newest first, each with its recorded failure count (0 on a
/// schema without the `import_failures` table).
pub fn import_last(conn: &Connection) -> Result<Value, ReadError> {
    let has_failures = has_table(conn, "import_failures")?;
    let mut late = Late::default();
    let mut runs = recent_runs(conn, &mut late)?;
    for run in &mut runs {
        let failures: i64 = if has_failures {
            // an id that is not an integer matches no failure row
            match run.get("id").and_then(Value::as_i64) {
                Some(id) => conn.query_row(
                    "SELECT COUNT(*) FROM import_failures WHERE run_id=?",
                    [id],
                    |row| row.get(0),
                )?,
                None => 0,
            }
        } else {
            0
        };
        run.insert("failures".into(), Value::from(failures));
    }
    late.finish()?;
    Ok(json!({"runs": runs.into_iter().map(Value::Object).collect::<Vec<_>>()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with_daily(rows: &[(&str, &str, &str, f64)]) -> Connection {
        let conn = Connection::open_in_memory().expect("memory db");
        conn.execute_batch("PRAGMA foreign_keys = OFF")
            .expect("pragma");
        for (_, ddl) in crate::store::MIGRATIONS {
            conn.execute_batch(ddl).expect("migrate");
        }
        for (date, metric, scope, value) in rows {
            conn.execute(
                "INSERT INTO daily_metrics(date, metric, value, source_scope, device_id, raw_record_id) \
                 VALUES(?,?,?,?,NULL,1)",
                rusqlite::params![date, metric, value, scope],
            )
            .expect("insert");
        }
        conn
    }

    fn contract() -> &'static Contract {
        match Contract::get() {
            Ok(contract) => contract,
            Err(error) => unreachable!("contract.json must load: {error}"),
        }
    }

    #[test]
    fn agreement_takes_the_upper_median_the_signed_mean_and_the_half_percent_band() {
        // device minus vendor_cloud: 0, 1, 2, 4 -> absolute [0, 1, 2, 4], upper median 2
        let mut rows = Vec::new();
        for (day, (ours, theirs)) in [
            (100.0, 100.0),
            (101.0, 100.0),
            (102.0, 100.0),
            (1004.0, 1000.0),
        ]
        .into_iter()
        .enumerate()
        {
            let date = format!("2025-06-0{}", day + 1);
            rows.push((date.clone(), "steps", "device", ours));
            rows.push((date, "steps", "vendor_cloud", theirs));
        }
        let borrowed: Vec<(&str, &str, &str, f64)> = rows
            .iter()
            .map(|(d, m, s, v)| (d.as_str(), *m, *s, *v))
            .collect();
        let conn = store_with_daily(&borrowed);
        let report = source_agreement(&conn, contract()).expect("report");
        assert_eq!(report.len(), 1);
        let row = &report[0];
        assert_eq!(row["compared_with"], Value::Null);
        assert_eq!(
            (row["scope_a"].as_str(), row["scope_b"].as_str()),
            (Some("device"), Some("vendor_cloud"))
        );
        assert_eq!(row["days_compared"], 4);
        // within 0.5 or 0.5 %: 0 (exact), 1 (1 > max(0.5, 0.5)), 2 (no), 4 of 1000 (4 <= 5 yes)
        assert_eq!(row["days_matching"], 2);
        assert_eq!(row["median_abs_diff"], 2.0);
        assert_eq!(row["max_abs_diff"], 4.0);
        assert_eq!(row["mean_diff_a_minus_b"], 1.75);
    }

    #[test]
    fn a_window_clamps_and_the_shapes_differ_between_sample_and_daily_metrics() {
        let conn = store_with_daily(&[("2025-06-01", "steps", "device", 1.0)]);
        let now = crate::time::parse_iso_utc("2025-07-02T09:30:00Z").expect("pin");
        let report = data_health(&conn, contract(), 99_999, now).expect("health");
        assert_eq!(
            report["window"],
            json!({"days": 3650, "from": "2015-07-05", "to": "2025-07-02"})
        );
        assert_eq!(report["contract_version"], "1");
        assert_eq!(report["never_imported"], true);
        let metrics = report["metrics"].as_array().expect("metrics");
        let steps = metrics
            .iter()
            .find(|m| m["metric"] == "steps")
            .expect("steps");
        assert_eq!(
            steps["total"],
            json!({"device": {"days_with_data": 1, "first_day": "2025-06-01", "last_day": "2025-06-01"}})
        );
        assert_eq!(steps["days_in_window"], json!({"device": 1}));
        let heart_rate = metrics
            .iter()
            .find(|m| m["metric"] == "heart_rate")
            .expect("heart_rate");
        assert_eq!(
            (&heart_rate["total"], &heart_rate["days_in_window"]),
            (&Value::Null, &json!(0))
        );
        let thin = data_health(&conn, contract(), -4, now).expect("health");
        assert_eq!(
            thin["window"],
            json!({"days": 1, "from": "2025-07-01", "to": "2025-07-02"})
        );
    }
}
