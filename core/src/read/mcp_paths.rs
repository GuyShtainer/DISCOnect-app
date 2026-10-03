// SPDX-License-Identifier: AGPL-3.0-or-later
//! The three read paths only the MCP server answers (Bet 11e, slice 1): `metric_series`,
//! `sleep_detail` and `list_activities`, the twins of the functions of `disconect/queries.py`
//! of those names. (`period_facts` and its options live in [`super::insight`]; `parse_day` and
//! `_window` in [`super::queries`].)
//!
//! They return [`Json`], the ordered, type-exact value of the wire layer: the MCP writes
//! `json.dumps(result, indent=2)`, so the order a Python dict was filled in is part of the answer,
//! and `1` is not `1.0`. Every cell is decoded by SQLite storage class and nothing is widened: a
//! sleep score of 77 stays the integer 77 (the facts path's `number()` would make it 77.0), a REAL
//! is `_clean`ed (`round(x, 3)`), `retro` is a `bool`. The caller scrubs the manufacturer's name
//! (`identity::neutral_json`), as `mcp_server._neutral_result` does for Python.

use std::collections::BTreeMap;

use rusqlite::Connection;
use rusqlite::types::ValueRef;

use super::ReadError;
use super::queries::{
    self, MAX_DAILY_DAYS, MAX_SAMPLE_DAYS, clean, parse_day, parse_moment, scopes_for, text, window,
};
use crate::contract::Contract;
use crate::wirejson::{Json, PyStr};
use crate::writer::py_round;

/// `_clean` over any cell, as a value: a float rounded to 3 places, an integer or text as it is, NULL as
/// null. A BLOB is Python's `TypeError` (bytes cannot be written as JSON).
fn cleaned(cell: ValueRef<'_>) -> Result<Json, ReadError> {
    match cell {
        ValueRef::Real(value) => Ok(Json::Float(clean(value))),
        other => raw(other),
    }
}

/// A cell as Python's sqlite3 returns it, with nothing rounded.
fn raw(cell: ValueRef<'_>) -> Result<Json, ReadError> {
    match cell {
        ValueRef::Null => Ok(Json::Null),
        ValueRef::Integer(value) => Ok(Json::int(value)),
        ValueRef::Real(value) => Ok(Json::Float(value)),
        ValueRef::Text(_) => text(cell).map(Json::text),
        ValueRef::Blob(_) => Err(ReadError::Unexpected("TypeError")),
    }
}

/// `bool(cell)`: nonzero, non-empty.
fn truthy(cell: ValueRef<'_>) -> bool {
    match cell {
        ValueRef::Null => false,
        ValueRef::Integer(value) => value != 0,
        ValueRef::Real(value) => value != 0.0,
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => !bytes.is_empty(),
    }
}

/// `dict.fromkeys(items)`: each distinct item once, in first-seen order.
fn distinct(items: &[PyStr]) -> Vec<&PyStr> {
    let mut seen: Vec<&PyStr> = Vec::new();
    for item in items {
        if !seen.contains(&item) {
            seen.push(item);
        }
    }
    seen
}

/// `{key: value, ...}` from a fixed list, in order.
fn object<const N: usize>(pairs: [(&str, Json); N]) -> Json {
    let mut out = Json::dict();
    for (key, value) in pairs {
        out.set(key, value);
    }
    out
}

/// `metric_series`: series for one or more contract metrics ending on `end_date` (default: today's UTC
/// date), per source scope, with the per-cadence caps (1825 days for a daily metric, 366 for a sample
/// metric, so two series of one answer can start on different days). Names are served once each, in
/// request order, but a label asked twice is answered twice; an unknown name lands in
/// `ignored_metrics`; a known metric with no data in the window is one series with a null scope and a
/// note. Errors, in Python's order: `source_scope`, then per metric `end_date` (`ValueError`) and the
/// window arithmetic (`OverflowError`).
pub fn metric_series(
    conn: &Connection,
    metrics: &[PyStr],
    days: i64,
    source_scope: Option<&PyStr>,
    end_date: Option<&PyStr>,
) -> Result<Json, ReadError> {
    let contract = Contract::get()?;
    let scopes = scopes_for(contract, source_scope)?;
    let offsets = queries::load_offsets(conn)?;
    let is_label = |name: &PyStr| {
        name.to_text()
            .is_some_and(|text| contract.labels.iter().any(|label| label.metric == text))
    };
    let mut series: Vec<Json> = Vec::new();
    let mut ignored: Vec<Json> = Vec::new();
    for name in distinct(metrics) {
        let metric = name.to_text();
        let known = metric
            .as_deref()
            .and_then(|text| contract.metric(text).map(|item| (text, item)));
        let Some((metric, item)) = known else {
            if !is_label(name) {
                ignored.push(Json::Str(name.clone()));
            }
            continue;
        };
        let daily = item.cadence == "daily";
        let (start, end) = window(
            days,
            end_date,
            if daily {
                MAX_DAILY_DAYS
            } else {
                MAX_SAMPLE_DAYS
            },
        )?;
        let mut by_scope: BTreeMap<String, Vec<Json>> = BTreeMap::new();
        if daily {
            let mut statement = conn.prepare(
                "SELECT date, value, source_scope FROM daily_metrics WHERE metric=? \
                 AND date BETWEEN ? AND ? ORDER BY date",
            )?;
            let mut rows = statement.query(rusqlite::params![metric, start, end])?;
            while let Some(row) = rows.next()? {
                let scope = text(row.get_ref(2)?)?;
                if scopes.iter().any(|wanted| wanted == scope) {
                    let point = object([
                        ("date", raw(row.get_ref(0)?)?),
                        ("value", cleaned(row.get_ref(1)?)?),
                    ]);
                    by_scope.entry(scope.to_string()).or_default().push(point);
                }
            }
        } else {
            let aggregates =
                queries::sample_day_aggregates(conn, metric, &start, &end, &offsets, &scopes)?;
            for (scope, per_day) in aggregates {
                let points = per_day
                    .into_iter()
                    .map(|day| {
                        object([
                            ("date", Json::text(&day.date)),
                            ("min", Json::Float(day.min)),
                            ("mean", Json::Float(day.mean)),
                            ("max", Json::Float(day.max)),
                            ("samples", Json::count(day.samples)),
                        ])
                    })
                    .collect();
                by_scope.insert(scope, points);
            }
        }
        let unit = contract.unit_for(metric).map_or(Json::Null, Json::text);
        let found = !by_scope.is_empty();
        for scope in &contract.source_scopes {
            if let Some(points) = by_scope.remove(scope) {
                series.push(object([
                    ("metric", Json::text(metric)),
                    ("unit", unit.clone()),
                    ("cadence", Json::text(&item.cadence)),
                    ("source_scope", Json::text(scope)),
                    ("from", Json::text(&start)),
                    ("to", Json::text(&end)),
                    ("points", Json::Array(points)),
                ]));
            }
        }
        if !found {
            series.push(object([
                ("metric", Json::text(metric)),
                ("unit", unit),
                ("cadence", Json::text(&item.cadence)),
                ("source_scope", Json::Null),
                ("from", Json::text(&start)),
                ("to", Json::text(&end)),
                ("points", Json::Array(Vec::new())),
                (
                    "note",
                    Json::text("no data in this window for any source scope"),
                ),
            ]));
        }
    }
    let labels = labels_in_window(conn, contract, metrics, days, end_date, &scopes)?;
    Ok(object([
        ("series", Json::Array(series)),
        ("labels", Json::Array(labels)),
        ("ignored_metrics", Json::Array(ignored)),
        (
            "missing_values",
            Json::text(&contract.conventions.missing_values),
        ),
        ("time", Json::text(&contract.conventions.time)),
        ("sources", Json::text(&contract.conventions.sources)),
    ]))
}

/// `_labels_in_window`: the requested label metrics (the raw list, so a repeat repeats) over the daily window.
fn labels_in_window(
    conn: &Connection,
    contract: &Contract,
    metrics: &[PyStr],
    days: i64,
    end_date: Option<&PyStr>,
    scopes: &[String],
) -> Result<Vec<Json>, ReadError> {
    let wanted: Vec<String> = metrics
        .iter()
        .filter_map(PyStr::to_text)
        .filter(|name| contract.labels.iter().any(|label| &label.metric == name))
        .collect();
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    let (start, end) = window(days, end_date, MAX_DAILY_DAYS)?;
    let mut out = Vec::new();
    for name in wanted {
        let mut statement = conn.prepare(
            "SELECT date, label, source_scope FROM daily_labels WHERE metric=? AND date BETWEEN ? AND ? \
             ORDER BY date",
        )?;
        let mut rows = statement.query(rusqlite::params![name, start, end])?;
        let mut points = Vec::new();
        while let Some(row) = rows.next()? {
            let scope = text(row.get_ref(2)?)?;
            if scopes.iter().any(|wanted| wanted == scope) {
                points.push(object([
                    ("date", raw(row.get_ref(0)?)?),
                    ("label", raw(row.get_ref(1)?)?),
                    ("source_scope", Json::text(scope)),
                ]));
            }
        }
        out.push(object([
            ("metric", Json::text(&name)),
            ("from", Json::text(&start)),
            ("to", Json::text(&end)),
            ("points", Json::Array(points)),
        ]));
    }
    Ok(out)
}

/// `_SLEEP_COLUMNS`, in the oracle's order; the last is `sleep_id`, which is popped from the record.
const SLEEP_COLUMNS: [&str; 31] = [
    "date",
    "source_scope",
    "start_utc",
    "end_utc",
    "deep_s",
    "light_s",
    "rem_s",
    "awake_s",
    "unmeasurable_s",
    "overall_score",
    "quality_score",
    "duration_score",
    "recovery_score",
    "deep_score",
    "rem_score",
    "light_score",
    "awake_time_score",
    "awakenings_count_score",
    "combined_awake_score",
    "restlessness_score",
    "interruptions_score",
    "awakenings_count",
    "avg_stress",
    "avg_spo2",
    "lowest_spo2",
    "avg_hr",
    "avg_respiration",
    "lowest_respiration",
    "highest_respiration",
    "retro",
    "sleep_id",
];
/// Where `sleep_id` and `retro` sit in [`SLEEP_COLUMNS`].
const SLEEP_ID: usize = 30;
const RETRO: usize = 29;
// The five columns that end in `_s` (`deep_s` .. `unmeasurable_s`) are the stage durations: they become
// `stage_minutes` (keys lose the suffix) and never appear under their own name.

/// `round(seconds / 60, 1)` of a stored duration: an INTEGER or REAL divides, anything else is a
/// `TypeError`.
fn minutes(cell: ValueRef<'_>) -> Result<f64, ReadError> {
    match cell {
        ValueRef::Integer(value) => Ok(py_round(value as f64 / 60.0, 1)),
        ValueRef::Real(value) => Ok(py_round(value / 60.0, 1)),
        _ => Err(ReadError::Unexpected("TypeError")),
    }
}

/// `sleep_detail`: every source's record of one night (default: the latest night stored), with stage
/// minutes and the stage timeline. A stage or score the source did not state is absent, never 0. The
/// integers the store holds stay integers. `date`, when given, must be exactly `YYYY-MM-DD`.
pub fn sleep_detail(conn: &Connection, date: Option<&PyStr>) -> Result<Json, ReadError> {
    let contract = Contract::get()?;
    let missing = Json::text(&contract.conventions.missing_values);
    if let Some(given) = date {
        parse_day(given, "date")?;
    }
    let night: String = match date {
        // `parse_day` accepted it: plain ASCII
        Some(given) => given.to_text().unwrap_or_default(),
        None => {
            let mut statement = conn.prepare("SELECT MAX(date) FROM sleep_sessions")?;
            let mut rows = statement.query([])?;
            let latest = match rows.next()? {
                Some(row) => match row.get_ref(0)? {
                    ValueRef::Null => None,
                    cell => Some(text(cell)?.to_string()),
                },
                None => None,
            };
            let Some(latest) = latest else {
                return Ok(object([
                    ("date", Json::Null),
                    ("sessions", Json::Array(Vec::new())),
                    ("reason", Json::text("no sleep stored yet")),
                    ("missing_values", missing),
                ]));
            };
            latest
        }
    };
    let mut sessions = Vec::new();
    let mut statement = conn.prepare(&format!(
        "SELECT {} FROM sleep_sessions WHERE date=? ORDER BY source_scope",
        SLEEP_COLUMNS.join(", ")
    ))?;
    let mut rows = statement.query([&night])?;
    while let Some(row) = rows.next()? {
        let mut entry = Json::dict();
        let mut stage_minutes = Json::dict();
        for (index, name) in SLEEP_COLUMNS.iter().enumerate().take(SLEEP_ID) {
            let cell = row.get_ref(index)?;
            if matches!(cell, ValueRef::Null) {
                continue;
            }
            if let Some(key) = name.strip_suffix("_s") {
                stage_minutes.set(key, Json::Float(minutes(cell)?));
            } else {
                entry.set(name, cleaned(cell)?);
            }
        }
        entry.set("stage_minutes", stage_minutes);
        // assigned after `stage_minutes`, but an existing key keeps its place in a dict
        entry.set("retro", Json::Bool(truthy(row.get_ref(RETRO)?)));
        let sleep_id = text(row.get_ref(SLEEP_ID)?)?;
        let stages = stage_timeline(conn, sleep_id)?;
        if !stages.is_empty() {
            entry.set("stages", Json::Array(stages));
        }
        sessions.push(entry);
    }
    let none = sessions.is_empty();
    let mut result = object([
        ("date", Json::text(&night)),
        ("sessions", Json::Array(sessions)),
        (
            "units",
            object([
                ("stage_minutes", Json::text("min")),
                ("avg_hr", Json::text("bpm")),
                ("avg_spo2", Json::text("%")),
                ("scores", Json::text("0-100")),
            ]),
        ),
        ("missing_values", missing),
        ("time", Json::text(&contract.conventions.time)),
    ]);
    if none {
        result.set(
            "reason",
            Json::text("no record of that night from any source"),
        );
    }
    Ok(result)
}

/// The stage rows of one night, oldest first, each with its length in minutes.
fn stage_timeline(conn: &Connection, sleep_id: &str) -> Result<Vec<Json>, ReadError> {
    let mut statement = conn.prepare(
        "SELECT stage, start_utc, end_utc FROM sleep_stages WHERE sleep_id=? ORDER BY start_utc",
    )?;
    let mut rows = statement.query([sleep_id])?;
    let mut stages = Vec::new();
    while let Some(row) = rows.next()? {
        let (stage, start, end) = (
            raw(row.get_ref(0)?)?,
            raw(row.get_ref(1)?)?,
            raw(row.get_ref(2)?)?,
        );
        // the oracle parses `end` first, so a malformed pair names the end
        let ended = parse_moment(text(row.get_ref(2)?)?)?;
        let started = parse_moment(text(row.get_ref(1)?)?)?;
        let seconds = (ended - started).num_seconds();
        stages.push(object([
            ("stage", stage),
            ("start_utc", start),
            ("end_utc", end),
            ("minutes", Json::Float(py_round(seconds as f64 / 60.0, 1))),
        ]));
    }
    Ok(stages)
}

/// `list_activities`' columns, in the oracle's order.
const ACTIVITY_COLUMNS: [&str; 14] = [
    "start_utc",
    "end_utc",
    "sport",
    "sub_sport",
    "total_timer_s",
    "total_elapsed_s",
    "distance_m",
    "calories_kcal",
    "avg_hr",
    "max_hr",
    "avg_speed_mps",
    "total_ascent_m",
    "total_descent_m",
    "source_scope",
];

/// `list_activities`: the most recent activities, newest first, `limit` clamped to `1..=200`. A column
/// the source did not state is absent. No route or coordinates are stored.
pub fn list_activities(conn: &Connection, limit: i64) -> Result<Json, ReadError> {
    let contract = Contract::get()?;
    let limit = limit.clamp(1, 200);
    let mut statement = conn.prepare(&format!(
        "SELECT {} FROM activities ORDER BY start_utc DESC LIMIT ?",
        ACTIVITY_COLUMNS.join(", ")
    ))?;
    let mut rows = statement.query([limit])?;
    let mut activities = Vec::new();
    while let Some(row) = rows.next()? {
        let mut entry = Json::dict();
        for (index, name) in ACTIVITY_COLUMNS.iter().enumerate() {
            let cell = row.get_ref(index)?;
            if !matches!(cell, ValueRef::Null) {
                entry.set(name, cleaned(cell)?);
            }
        }
        activities.push(entry);
    }
    let units = [
        ("distance_m", "m"),
        ("total_timer_s", "s"),
        ("total_elapsed_s", "s"),
        ("calories_kcal", "kcal"),
        ("avg_hr", "bpm"),
        ("max_hr", "bpm"),
        ("avg_speed_mps", "m/s"),
        ("total_ascent_m", "m"),
        ("total_descent_m", "m"),
    ];
    let mut unit_map = Json::dict();
    for (key, unit) in units {
        unit_map.set(key, Json::text(unit));
    }
    Ok(object([
        ("activities", Json::Array(activities)),
        ("units", unit_map),
        (
            "missing_values",
            Json::text(&contract.conventions.missing_values),
        ),
        ("time", Json::text(&contract.conventions.time)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory() -> Connection {
        match Connection::open_in_memory() {
            Ok(conn) => conn,
            Err(error) => unreachable!("memory database: {error}"),
        }
    }

    fn field<'a>(node: &'a Json, key: &str) -> &'a Json {
        match node.get(key) {
            Some(found) => found,
            None => unreachable!("no key {key}"),
        }
    }

    #[test]
    fn distinct_keeps_the_first_of_each_and_texts_builds_a_list() {
        let one = PyStr::from_text("a");
        let two = PyStr::from_text("b");
        let all = [one.clone(), two.clone(), one.clone()];
        assert_eq!(distinct(&all), [&one, &two]);
    }

    #[test]
    fn a_dict_assignment_to_an_existing_key_keeps_its_place() {
        let mut dict = Json::dict();
        dict.set("a", Json::int(1));
        dict.set("b", Json::int(2));
        dict.set("a", Json::Bool(true));
        let Json::Object(pairs) = &dict else {
            unreachable!("object")
        };
        let keys: Vec<String> = pairs.iter().map(|(key, _)| key.units_lossy()).collect();
        assert_eq!(keys, ["a", "b"]);
        assert_eq!(field(&dict, "a"), &Json::Bool(true));
    }

    #[test]
    fn a_stored_integer_stays_an_integer_and_a_real_is_rounded() {
        assert_eq!(cleaned(ValueRef::Integer(77)).ok(), Some(Json::int(77)));
        assert_eq!(
            cleaned(ValueRef::Real(76.123_456)).ok(),
            Some(Json::Float(76.123))
        );
        assert_eq!(
            raw(ValueRef::Real(76.123_456)).ok(),
            Some(Json::Float(76.123_456))
        );
        assert_eq!(cleaned(ValueRef::Null).ok(), Some(Json::Null));
        assert!(matches!(
            cleaned(ValueRef::Blob(b"x")),
            Err(ReadError::Unexpected("TypeError"))
        ));
        assert!(truthy(ValueRef::Integer(2)) && !truthy(ValueRef::Integer(0)));
        assert!(truthy(ValueRef::Text(b"0")) && !truthy(ValueRef::Text(b"")));
    }

    #[test]
    fn minutes_round_half_even_to_one_place() {
        // 3599 s = 59.98333 min -> 60.0; 90 s -> 1.5; 0 -> 0.0
        assert!(matches!(minutes(ValueRef::Integer(3599)), Ok(v) if v == 60.0));
        assert!(matches!(minutes(ValueRef::Integer(90)), Ok(v) if v == 1.5));
        assert!(matches!(minutes(ValueRef::Integer(0)), Ok(v) if v == 0.0));
        assert!(matches!(minutes(ValueRef::Real(45.0)), Ok(v) if v == 0.8));
        assert!(minutes(ValueRef::Text(b"60")).is_err());
    }

    #[test]
    fn activities_clamp_their_limit_and_list_newest_first() {
        let conn = memory();
        let mut script = String::from(
            "CREATE TABLE activities(start_utc TEXT, end_utc TEXT, sport TEXT, sub_sport TEXT, \
             total_timer_s REAL, total_elapsed_s REAL, distance_m REAL, calories_kcal INTEGER, avg_hr INTEGER, \
             max_hr INTEGER, avg_speed_mps REAL, total_ascent_m REAL, total_descent_m REAL, source_scope TEXT);",
        );
        for day in 1..=30 {
            script.push_str(&format!(
                "INSERT INTO activities(start_utc, sport, calories_kcal, distance_m, source_scope) \
                 VALUES('2025-06-{day:02}T06:00:00Z','run',{day},{day}.12345,'device');"
            ));
        }
        assert!(conn.execute_batch(&script).is_ok());
        let count = |limit: i64| match list_activities(&conn, limit) {
            Ok(result) => match field(&result, "activities") {
                Json::Array(items) => items.len(),
                _ => unreachable!("array"),
            },
            Err(error) => unreachable!("{error}"),
        };
        assert_eq!(
            [
                count(0),
                count(1),
                count(20),
                count(30),
                count(200),
                count(201),
                count(i64::MIN),
                count(i64::MAX)
            ],
            [1, 1, 20, 30, 30, 30, 1, 30]
        );
        let Ok(result) = list_activities(&conn, 2) else {
            unreachable!("activities")
        };
        let Json::Array(items) = field(&result, "activities") else {
            unreachable!("array")
        };
        assert_eq!(
            field(&items[0], "start_utc"),
            &Json::text("2025-06-30T06:00:00Z")
        );
        assert_eq!(field(&items[0], "calories_kcal"), &Json::int(30));
        assert_eq!(field(&items[0], "distance_m"), &Json::Float(30.123));
        assert!(items[0].get("end_utc").is_none() && items[0].get("avg_hr").is_none());
    }

    #[test]
    fn retro_is_a_bool_in_its_own_place_and_stage_keys_lose_their_suffix() {
        let conn = memory();
        let columns: Vec<String> = SLEEP_COLUMNS
            .iter()
            .map(|name| {
                let kind = match *name {
                    "date" | "source_scope" | "start_utc" | "end_utc" | "sleep_id" => "TEXT",
                    "avg_stress"
                    | "avg_spo2"
                    | "avg_hr"
                    | "avg_respiration"
                    | "lowest_respiration"
                    | "highest_respiration" => "REAL",
                    _ => "INTEGER",
                };
                format!("{name} {kind}")
            })
            .collect();
        let script = format!(
            "CREATE TABLE sleep_sessions({});
             CREATE TABLE sleep_stages(sleep_id TEXT, stage TEXT, start_utc TEXT, end_utc TEXT);
             INSERT INTO sleep_sessions(date, source_scope, deep_s, light_s, overall_score, avg_hr, retro, sleep_id)
               VALUES('2025-06-20','device',0,5400,77,54.3216,1,'s1');
             INSERT INTO sleep_stages VALUES('s1','deep','2025-06-20T01:00:00Z','2025-06-20T01:20:30Z');",
            columns.join(", ")
        );
        assert!(conn.execute_batch(&script).is_ok());
        let Ok(result) = sleep_detail(&conn, None) else {
            unreachable!("sleep")
        };
        assert_eq!(field(&result, "date"), &Json::text("2025-06-20"));
        let Json::Array(sessions) = field(&result, "sessions") else {
            unreachable!("array")
        };
        let Json::Object(pairs) = &sessions[0] else {
            unreachable!("object")
        };
        let keys: Vec<String> = pairs.iter().map(|(key, _)| key.units_lossy()).collect();
        assert_eq!(
            keys,
            [
                "date",
                "source_scope",
                "overall_score",
                "avg_hr",
                "retro",
                "stage_minutes",
                "stages"
            ]
        );
        assert_eq!(field(&sessions[0], "overall_score"), &Json::int(77));
        assert_eq!(field(&sessions[0], "avg_hr"), &Json::Float(54.322));
        assert_eq!(field(&sessions[0], "retro"), &Json::Bool(true));
        let minutes = field(&sessions[0], "stage_minutes");
        assert_eq!(field(minutes, "deep"), &Json::Float(0.0));
        assert_eq!(field(minutes, "light"), &Json::Float(90.0));
        let Json::Array(stages) = field(&sessions[0], "stages") else {
            unreachable!("array")
        };
        assert_eq!(field(&stages[0], "minutes"), &Json::Float(20.5));
        // a night nobody recorded, and the no-sleep store
        let none = sleep_detail(&conn, Some(&PyStr::from_text("2025-01-01")));
        assert!(matches!(
            none.as_ref().map(|r| r.get("reason")),
            Ok(Some(_))
        ));
        assert!(matches!(
            sleep_detail(&conn, Some(&PyStr::from_text(""))),
            Err(ReadError::Value(message)) if message == "date must be YYYY-MM-DD"
        ));
    }
}
