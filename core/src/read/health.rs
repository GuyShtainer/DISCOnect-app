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
use crate::clock::ClockOffsets;
use crate::contract::Contract;
use crate::model::Instant;
use crate::redact::redact_text;
use crate::wirejson::{self, Json, PyStr};
use crate::writer::{py_round, py_sum};

/// `serve.DEFAULT_HEALTH_DAYS`.
pub const DEFAULT_HEALTH_DAYS: i64 = 90;
/// `health.LAST_IMPORTS`: how many runs of the transports other than `ble` `import.last` (and
/// `data.health`) report; the newest `ble` run (a live link's end sweep) is listed beside them.
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

    /// [`Late::column`] as the ordered wire value.
    fn json(&mut self, row: &Row<'_>, index: usize) -> Result<Json, ReadError> {
        Ok(wirejson::from_serde(&self.column(row, index)?))
    }

    fn finish(self) -> Result<(), ReadError> {
        self.0.map_or(Ok(()), Err)
    }
}

/// A live sample's stored moment as the watch-local day (`ClockOffsets.local_date`); NULL stays null; a day the
/// calendar cannot hold (year 9999 plus a positive offset) keeps the UTC prefix, like the Python core's `_live_day`.
fn live_day(row: &Row<'_>, index: usize, offsets: &ClockOffsets) -> Result<Json, ReadError> {
    match row.get_ref(index)? {
        ValueRef::Null => Ok(Json::Null),
        cell => {
            let stamp = text(cell)?;
            let moment = queries::parse_moment(stamp)?;
            let day = offsets
                .local_date_checked(moment, false)
                .unwrap_or_else(|| stamp.get(..10).unwrap_or(stamp).to_string());
            Ok(wirejson::from_serde(&Value::from(day)))
        }
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

/// One row as Python's `dict(zip(names, row))`: the statement's column order.
type Row_ = Vec<(String, Value)>;

/// `_rows`: every row of `sql` keyed by the statement's own column names, in the statement's order.
fn rows_of(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
    late: &mut Late,
    redact: &[&str],
) -> Result<Vec<Row_>, ReadError> {
    let mut statement = conn.prepare(sql)?;
    let names: Vec<String> = statement
        .column_names()
        .iter()
        .map(|n| n.to_string())
        .collect();
    let mut rows = statement.query(params)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut object = Row_::new();
        for (index, name) in names.iter().enumerate() {
            let value = if redact.contains(&name.as_str()) {
                redacted(row.get_ref(index)?)?
            } else {
                late.column(row, index)?
            };
            object.push((name.clone(), value));
        }
        out.push(object);
    }
    Ok(out)
}

/// `round(value, 3)` as a JSON number (a non-finite one cannot be written: `ValueError`).
fn round3(value: f64) -> Result<Json, ReadError> {
    Ok(wirejson::from_serde(&json_number(py_round(value, 3))?))
}

/// A row as the ordered wire object.
fn row_json(row: Row_) -> Json {
    Json::Object(
        row.into_iter()
            .map(|(name, value)| (PyStr::from_text(&name), wirejson::from_serde(&value)))
            .collect(),
    )
}

type PairKey = (String, Option<String>, String, String);

/// `source_agreement`: where two sources state the same daily figure on the same date, how closely
/// they agree. Same metric in two scopes, plus the contract's comparison targets (our id against the
/// vendor's id for the same quantity). The first join is ordered (`ORDER BY a.date, ...`), because the
/// mean is a floating-point sum whose result depends on order.
pub fn source_agreement(conn: &Connection, contract: &Contract) -> Result<Vec<Value>, ReadError> {
    source_agreement_ordered(conn, contract)?
        .iter()
        .map(|row| row.to_serde().ok_or(ReadError::Unexpected("TypeError")))
        .collect()
}

/// [`source_agreement`] with each row's keys in the order `health.source_agreement` inserts them.
pub fn source_agreement_ordered(
    conn: &Connection,
    contract: &Contract,
) -> Result<Vec<Json>, ReadError> {
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
        report.push(Json::object([
            ("metric", Json::text(&metric)),
            (
                "compared_with",
                compared_with.as_deref().map_or(Json::Null, Json::text),
            ),
            (
                "unit",
                contract.unit_for(&metric).map_or(Json::Null, Json::text),
            ),
            ("scope_a", Json::text(&scope_a)),
            ("scope_b", Json::text(&scope_b)),
            ("days_compared", Json::count(values.len())),
            ("days_matching", Json::count(matching)),
            ("median_abs_diff", round3(*median)?),
            ("max_abs_diff", round3(*largest)?),
            (
                "mean_diff_a_minus_b",
                round3(py_sum(diffs.iter().copied()) / diffs.len() as f64)?,
            ),
        ]));
    }
    Ok(report)
}

/// `{days_with_data, first_day, last_day}` for one group of a stored-day aggregate.
fn span(late: &mut Late, row: &Row<'_>, first: usize) -> Result<Json, ReadError> {
    Ok(Json::object([
        ("days_with_data", late.json(row, first)?),
        ("first_day", late.json(row, first + 1)?),
        ("last_day", late.json(row, first + 2)?),
    ]))
}

/// `data_health(conn, window_days)`: coverage, provenance and recent imports as plain data (the
/// oracle's `conventions` block is part of the result; `serve` drops it). `now` is the one clock. Object keys
/// are sorted (the `serve` wire form); [`data_health_ordered`] keeps Python's insertion order.
pub fn data_health(
    conn: &Connection,
    contract: &Contract,
    window_days: i64,
    now: Instant,
) -> Result<Value, ReadError> {
    data_health_ordered(conn, contract, window_days, now)?
        .to_serde()
        .ok_or(ReadError::Unexpected("TypeError"))
}

/// [`data_health`] with every object's keys in the order `health.data_health` inserts them, so the MCP's
/// `text` is the oracle's byte for byte. Groups that Python builds from a query keep the query's row order.
pub fn data_health_ordered(
    conn: &Connection,
    contract: &Contract,
    window_days: i64,
    now: Instant,
) -> Result<Json, ReadError> {
    let window_days = window_days.clamp(1, MAX_HEALTH_DAYS);
    let today = iso(now.date_naive());
    let since = Duration::try_days(window_days)
        .and_then(|delta| now.checked_sub_signed(delta))
        .map(|then| iso(then.date_naive()))
        .ok_or(ReadError::Overflow)?;
    let mut late = Late::default();

    let mut streams = Json::dict();
    {
        let mut statement = conn.prepare(
            "SELECT stream, COUNT(*), MIN(start_utc), MAX(end_utc) FROM raw_records GROUP BY stream",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let stream = text(row.get_ref(0)?)?.to_string();
            streams.set(
                &stream,
                Json::object([
                    ("records", late.json(row, 1)?),
                    ("first", late.json(row, 2)?),
                    ("last", late.json(row, 3)?),
                ]),
            );
        }
    }
    let never_imported = matches!(&streams, Json::Object(pairs) if pairs.is_empty());

    let provenance: Vec<Json> = rows_of(
        conn,
        "SELECT * FROM stream_provenance ORDER BY stream",
        [],
        &mut late,
        &["last_parse_error_message", "last_write_error_message"],
    )?
    .into_iter()
    .map(row_json)
    .collect();

    let mut samples_total = Json::dict();
    {
        let mut statement = conn.prepare(
            "SELECT metric, COUNT(DISTINCT substr(ts_utc,1,10)), MIN(substr(ts_utc,1,10)), \
             MAX(substr(ts_utc,1,10)) FROM metric_samples WHERE source_scope != 'live' GROUP BY metric",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let metric = text(row.get_ref(0)?)?.to_string();
            samples_total.set(&metric, span(&mut late, row, 1)?);
        }
    }
    let mut samples_window = Json::dict();
    {
        let mut statement = conn.prepare(
            "SELECT metric, COUNT(DISTINCT substr(ts_utc,1,10)) FROM metric_samples \
             WHERE source_scope != 'live' AND substr(ts_utc,1,10) >= ? GROUP BY metric",
        )?;
        let mut rows = statement.query([&since])?;
        while let Some(row) = rows.next()? {
            let metric = text(row.get_ref(0)?)?.to_string();
            samples_window.set(&metric, late.json(row, 1)?);
        }
    }

    let mut daily_total = Json::dict();
    {
        let mut statement = conn.prepare(
            "SELECT metric, source_scope, COUNT(*), MIN(date), MAX(date) FROM daily_metrics \
             GROUP BY metric, source_scope",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let metric = text(row.get_ref(0)?)?.to_string();
            let scope = text(row.get_ref(1)?)?.to_string();
            let found = span(&mut late, row, 2)?;
            set_nested(&mut daily_total, &metric, &scope, found);
        }
    }
    let mut daily_window = Json::dict();
    {
        let mut statement = conn.prepare(
            "SELECT metric, source_scope, COUNT(*) FROM daily_metrics WHERE date >= ? \
             GROUP BY metric, source_scope",
        )?;
        let mut rows = statement.query([&since])?;
        while let Some(row) = rows.next()? {
            let metric = text(row.get_ref(0)?)?.to_string();
            let scope = text(row.get_ref(1)?)?.to_string();
            let found = late.json(row, 2)?;
            set_nested(&mut daily_window, &metric, &scope, found);
        }
    }

    let mut sleep = Json::dict();
    {
        let mut statement = conn.prepare(
            "SELECT source_scope, COUNT(*), MIN(date), MAX(date) FROM sleep_sessions GROUP BY source_scope",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let scope = text(row.get_ref(0)?)?.to_string();
            sleep.set(
                &scope,
                Json::object([
                    ("nights", late.json(row, 1)?),
                    ("first_day", late.json(row, 2)?),
                    ("last_day", late.json(row, 3)?),
                ]),
            );
        }
    }
    let live_records: i64 =
        conn.query_row("SELECT COUNT(*) FROM raw_records WHERE stream='json:live'", [], |row| row.get(0))?;
    // one load of clock_offsets: the live block (BL-9: its days are the watch's local days, like every other day
    // in the product), local_today and the coverage ledger share it
    let known_offsets = queries::load_offsets(conn)?;
    let live = {
        let mut statement = conn.prepare(
            "SELECT COUNT(*), MIN(ts_utc), MAX(ts_utc) FROM metric_samples WHERE source_scope='live'",
        )?;
        let mut rows = statement.query([])?;
        let Some(row) = rows.next()? else { return Err(ReadError::Unexpected("TypeError")) };
        Json::object([
            ("records", Json::int(live_records)),
            ("samples", late.json(row, 0)?),
            ("first_day", live_day(row, 1, &known_offsets)?),
            ("last_day", live_day(row, 2, &known_offsets)?),
        ])
    };
    let activities: i64 =
        conn.query_row("SELECT COUNT(*) FROM activities", [], |row| row.get(0))?;
    let offsets: i64 =
        conn.query_row("SELECT COUNT(*) FROM clock_offsets", [], |row| row.get(0))?;

    let runs: Vec<Json> = recent_runs(conn, &mut late)?
        .into_iter()
        .map(row_json)
        .collect();

    let metrics: Vec<Json> = contract
        .metrics
        .iter()
        .map(|item| {
            let (total, days_in_window) = if item.cadence == "sample" {
                (
                    samples_total
                        .get(&item.metric)
                        .cloned()
                        .unwrap_or(Json::Null),
                    samples_window
                        .get(&item.metric)
                        .cloned()
                        .unwrap_or(Json::int(0)),
                )
            } else {
                (
                    daily_total.get(&item.metric).cloned().unwrap_or(Json::Null),
                    daily_window
                        .get(&item.metric)
                        .cloned()
                        .unwrap_or_else(Json::dict),
                )
            };
            Json::object([
                ("metric", Json::text(&item.metric)),
                ("unit", Json::text(&item.unit)),
                ("cadence", Json::text(&item.cadence)),
                ("total", total),
                ("days_in_window", days_in_window),
            ])
        })
        .collect();

    let local_today = queries::local_today_with(&known_offsets, now)?;
    let ledger = coverage::ledger_ordered_with(conn, contract, &local_today, window_days, Some(known_offsets))?;
    let schema_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let agreement = source_agreement_ordered(conn, contract)?;
    late.finish()?;
    let conventions = &contract.conventions;
    Ok(Json::object([
        ("contract_version", Json::text(&contract.contract_version)),
        ("coverage", ledger),
        ("schema_version", Json::int(schema_version)),
        (
            "window",
            Json::object([
                ("days", Json::int(window_days)),
                ("from", Json::text(&since)),
                ("to", Json::text(&today)),
            ]),
        ),
        ("never_imported", Json::flag(never_imported)),
        ("streams", streams),
        ("provenance", Json::Array(provenance)),
        ("metrics", Json::Array(metrics)),
        ("sleep", sleep),
        ("live", live),
        ("activities", Json::int(activities)),
        ("clock_offsets_known", Json::int(offsets)),
        ("source_agreement", Json::Array(agreement)),
        ("recent_imports", Json::Array(runs)),
        (
            "conventions",
            Json::object([
                ("time", Json::text(&conventions.time)),
                ("missing_values", Json::text(&conventions.missing_values)),
                ("sources", Json::text(&conventions.sources)),
                ("coverage", Json::text(&conventions.coverage)),
                ("completeness", Json::text(&conventions.completeness)),
            ]),
        ),
    ]))
}

/// `groups.setdefault(metric, {})[scope] = value`, in insertion order.
fn set_nested(groups: &mut Json, metric: &str, scope: &str, value: Json) {
    if groups.get(metric).is_none() {
        groups.set(metric, Json::dict());
    }
    if let Json::Object(pairs) = groups
        && let Some((_, inner)) = pairs.iter_mut().find(|(name, _)| name.equals(metric))
    {
        inner.set(scope, value);
    }
}

/// `health.RECENT_RUNS_SQL`: the newest [`LAST_IMPORTS`] runs of every transport but `ble` plus the
/// newest `ble` run, newest first, with their 11 columns, `error` redacted (`data_health`'s
/// `recent_imports` and, with a `failures` count added, `import.last`). A live link ends with a sweep
/// of the readings folder (transport `ble`, usually "0 imported, N duplicate"); listed like any run,
/// the sweeps pushed the USB and export runs out of the list within a day (9b review N8).
fn recent_runs(conn: &Connection, late: &mut Late) -> Result<Vec<Row_>, ReadError> {
    let sql = format!(
        "SELECT {} FROM import_runs WHERE id IN (\
         SELECT id FROM (SELECT id FROM import_runs WHERE transport IS NOT 'ble' ORDER BY id DESC LIMIT ?) \
         UNION SELECT id FROM (SELECT id FROM import_runs WHERE transport = 'ble' ORDER BY id DESC LIMIT 1)\
         ) ORDER BY id DESC",
        RUN_COLUMNS.join(", ")
    );
    rows_of(conn, &sql, [LAST_IMPORTS], late, &["error"])
}

/// `serve.import_last`: `{"runs": [...]}`, newest first, each with its recorded failure count (0 on a
/// schema without the `import_failures` table).
pub fn import_last(conn: &Connection) -> Result<Value, ReadError> {
    let has_failures = has_table(conn, "import_failures")?;
    let mut late = Late::default();
    let mut runs: Vec<Map<String, Value>> = recent_runs(conn, &mut late)?
        .into_iter()
        .map(|row| row.into_iter().collect())
        .collect();
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
        assert_eq!(report["contract_version"], "2");
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

    #[test]
    fn the_live_days_are_the_watchs_local_days() {
        let conn = store_with_daily(&[]);
        let now = crate::time::parse_iso_utc("2025-07-02T09:30:00Z").expect("pin");
        let live = |conn: &Connection| data_health(conn, contract(), 90, now).expect("health")["live"].clone();
        assert_eq!(live(&conn), json!({"records": 0, "samples": 0, "first_day": null, "last_day": null}));
        for ts in ["2025-06-15T02:30:00Z", "2025-06-21T12:00:00Z"] {
            conn.execute(
                "INSERT INTO metric_samples(metric, ts_utc, value, source_scope, raw_record_id) \
                 VALUES('heart_rate', ?, 60, 'live', 1)",
                [ts],
            )
            .expect("insert");
        }
        // no stored offset: assumed UTC
        assert_eq!(live(&conn)["first_day"], "2025-06-15");
        conn.execute("INSERT INTO clock_offsets(ts_utc, offset_s) VALUES('2025-06-01T12:00:00Z', -18000)", [])
            .expect("offset");
        // -5 h: 02:30Z is the previous evening on the watch
        let found = live(&conn);
        assert_eq!((&found["first_day"], &found["last_day"]), (&json!("2025-06-14"), &json!("2025-06-21")));
        assert_eq!(found["samples"], 2);
        // +3 h: 23:30Z is already the next day on the watch, so last_day moves too
        conn.execute("UPDATE clock_offsets SET offset_s = 10800", []).expect("offset");
        conn.execute(
            "UPDATE metric_samples SET ts_utc = '2025-06-21T23:30:00Z' WHERE ts_utc = '2025-06-21T12:00:00Z'",
            [],
        )
        .expect("move");
        let found = live(&conn);
        assert_eq!((&found["first_day"], &found["last_day"]), (&json!("2025-06-15"), &json!("2025-06-22")));
        // the calendar ends at 9999: the UTC prefix is kept instead of an error (the Python core does the same)
        conn.execute(
            "INSERT INTO metric_samples(metric, ts_utc, value, source_scope, raw_record_id) \
             VALUES('heart_rate', '9999-12-31T23:46:00Z', 60, 'live', 1)",
            [],
        )
        .expect("insert");
        assert_eq!(live(&conn)["last_day"], "9999-12-31");
    }
}
