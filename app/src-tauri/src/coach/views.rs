// SPDX-License-Identifier: AGPL-3.0-or-later
//! The coach views (Bet 15 slice 3, attack findings B1 and B3): what the model may see of a tool answer.
//!
//! [`project`] is a pure function over the JSON a `tools.call` returned. It is an **allowlist**: a key it does
//! not name is dropped silently, a string it cannot prove harmless is dropped or reduced to a day, and the
//! sixth tool, `get_contract`, is never sent ([`ViewError::NotSent`]). The projection is not the gate:
//! [`super::schema::validate`] re-checks the projected value against a positive schema and fails closed, and
//! [`super::caps::fit`] bounds its size. Nothing here opens a store, reads a clock or formats a value for a log.
//!
//! # What the model can see
//!
//! The "what the model can see" drawer cites this table. "Day" means `YYYY-MM-DD`; no time of day, no
//! free text and no identifier of a file, a device or an account is in any column on the kept side.
//!
//! | Tool | Kept | Dropped | Why |
//! |---|---|---|---|
//! | `get_metric_series` | `series[]` (`metric`, `unit`, `cadence`, `source_scope`, `from`, `to`, `points` of `{date, value}` or `{date, min, mean, max, samples}`, `note` only when it is the fixed no-data sentence); `labels[]` (`metric`, `from`, `to`, `points` of `{date, label, source_scope}`, label values from a closed table, `dropped` counts the rest); `ignored_count` | `time`, `missing_values`, `sources` (contract text, the static tool description says it), the text of `ignored_metrics` (the names the model sent, only their count stays), any label value outside the table | Daily and per-day-aggregate values are the coaching material; the dropped keys are prose or echo input. |
//! | `get_period_facts` | `as_of`, `window{from,to,days}`, `baseline{from,to,days,min_days_with_data}`, `facts[]` (ids, `unit`, `cadence`, `source_scope`, `value`, `window_min/max`, day counts, `comparison{baseline_mean, baseline_sd, delta, delta_percent, z_score, direction}`, `confidence`, `reason_code`, `evidence{window_dates, baseline_from, baseline_to, baseline_days_with_data, aggregation}`), `reason` when fixed, `ignored_count`; `evidence.window_points` only when the caller's options ask for points | `rules`, `baseline.confidence_bands`, `missing_values`, `sources` (fixed contract text), `ignored_metrics` text | Facts without points are the default: the comparison already carries the window against the baseline. |
//! | `get_sleep_detail` | `date`, `sessions[]` (`date`, `source_scope`, `minutes` of the whole session, `stage_minutes`, the score and vital columns, `retro`, `stages` as ordered `{stage, minutes}`), `units`, `reason` when fixed | `start_utc`, `end_utc` of the session and of every stage, `time`, `missing_values` | A bedtime or a wake time is a time of day; the order and lengths of the stages carry the structure of the night without it. |
//! | `list_activities` | per activity `date`, `sport`, `sub_sport`, `total_timer_s`, `total_elapsed_s`, `distance_m`, `calories_kcal`, `avg_hr`, `max_hr`, `avg_speed_mps`, `total_ascent_m`, `total_descent_m`, `source_scope`; `units` | `start_utc`, `end_utc`, `time`, `missing_values` | The start second of a workout says when the person is out of the house. Sport names outside a closed table become `other`. |
//! | `get_data_health` | `contract_version`, `schema_version`, `window`, `never_imported`, `clock_offsets_known`, `activities`, `sleep` (nights and first and last day per scope), `streams[]` (name, record count, first and last **day**), `metrics[]` (per-metric days and first and last day, per scope), `source_agreement[]` (numeric comparisons between scopes), `coverage{window, ledger[] (status counts, gaps as day ranges), refinements_available, undatable_files, unattributed_failures}` | `recent_imports`, `provenance`, every `*_at`, every `*_message`, every `error`, `conventions`, `coverage.statuses`, `coverage.refinements` (text), `coverage.map_drift`, the ledger's `streams` lists, the time of day inside the stream bounds | The import log and the provenance rows carry timestamps to the second and free text (file names can sit in an error). Counts and days say what the data covers, which is what the coach needs. |
//! | `get_contract` | nothing | everything | 47 KB of contract text; the loop gives the model a short static description of the tools instead. |
//!
//! # Days
//!
//! The tool answers carry no per-record UTC offset (the offsets stay in the store; `clock_offsets_known` is only
//! a count). So where a day has to be derived from an instant (an activity's start) it is the **UTC date**; a sleep
//! session keeps the `date` the core already gave it (the local date the night ended, resolved with the watch's own
//! offsets). An evening run near midnight can therefore land on the neighbouring day. That is a known imprecision
//! of the day label, not a leak: no value finer than a day leaves.

use serde_json::{Map, Number, Value};

use super::schema::{
    self, label_allowed, Vocab, AGGREGATIONS, NOTE_NO_DATA, REASONS, SPORTS, STAGES, SUB_SPORTS,
};

type Obj = Map<String, Value>;

/// Why a tool answer cannot be projected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewError {
    /// The tool is never sent (`get_contract`).
    NotSent,
    /// Not one of the six tools.
    UnknownTool,
    /// The answer is not a JSON object.
    Malformed,
}

impl std::fmt::Display for ViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ViewError::NotSent => "this tool's answer is never sent to the model",
            ViewError::UnknownTool => "not a coach tool",
            ViewError::Malformed => "the tool answer is not a JSON object",
        })
    }
}

impl std::error::Error for ViewError {}

/// What the caller chooses about a projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ViewOptions {
    /// Keep `evidence.window_points` of a fact (the user's toggle, slice 5); off by default.
    pub include_points: bool,
}

/// [`project_with`] with the coach defaults.
pub fn project(tool: &str, result: &Value) -> Result<Value, ViewError> {
    project_with(tool, result, &ViewOptions::default())
}

/// The model-visible projection of one tool answer.
pub fn project_with(tool: &str, result: &Value, options: &ViewOptions) -> Result<Value, ViewError> {
    if tool == "get_contract" {
        return Err(ViewError::NotSent);
    }
    if !schema::SENDABLE_TOOLS.contains(&tool) {
        return Err(ViewError::UnknownTool);
    }
    let Value::Object(source) = result else {
        return Err(ViewError::Malformed);
    };
    let projected = match tool {
        "get_metric_series" => metric_series(source),
        "get_period_facts" => period_facts(source, options),
        "get_sleep_detail" => sleep_detail(source),
        "list_activities" => list_activities(source),
        _ => data_health(source),
    };
    Ok(Value::Object(projected))
}

// ---- helpers ---------------------------------------------------------------------------------------

/// Copy the listed keys that are present.
fn keep(source: &Obj, keys: &[&str], out: &mut Obj) {
    for key in keys {
        if let Some(value) = source.get(*key) {
            out.insert((*key).to_string(), value.clone());
        }
    }
}

/// A new object with the listed keys of `source`.
fn picked(source: &Obj, keys: &[&str]) -> Obj {
    let mut out = Obj::new();
    keep(source, keys, &mut out);
    out
}

/// The objects of an array under `key`, each through `each`; non-objects are dropped.
fn each_object(source: &Obj, key: &str, each: impl Fn(&Obj) -> Obj) -> Option<Value> {
    let items = source.get(key)?.as_array()?;
    Some(Value::Array(
        items.iter().filter_map(Value::as_object).map(|item| Value::Object(each(item))).collect(),
    ))
}

fn set(out: &mut Obj, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        out.insert(key.to_string(), value);
    }
}

/// The day of a string that starts with a plain date and continues, if at all, with a time part.
fn day_of(text: &str) -> Option<String> {
    let head = text.get(..10)?;
    let rest = text.get(10..)?;
    (schema::is_date(head) && (rest.is_empty() || rest.starts_with('T') || rest.starts_with(' ')))
        .then(|| head.to_string())
}

/// A string value as a day (a null stays null; anything else is dropped).
fn as_day(value: &Value) -> Option<Value> {
    match value {
        Value::Null => Some(Value::Null),
        Value::String(text) => day_of(text).map(Value::String),
        _ => None,
    }
}

/// The value when it is a string of the allowed set.
fn one_of(value: Option<&Value>, allowed: &[&str]) -> Option<Value> {
    let text = value?.as_str()?;
    allowed.contains(&text).then(|| Value::String(text.to_string()))
}

/// The name when it is in the table, else `other`.
fn named_or_other(value: Option<&Value>, table: &[&str]) -> Option<Value> {
    let text = value?.as_str()?;
    Some(Value::String(if table.contains(&text) { text } else { "other" }.to_string()))
}

fn count_of(source: &Obj, key: &str) -> Option<Value> {
    source.get(key)?.as_array().map(|items| Value::from(items.len()))
}

/// Days since 1970-01-01 of a civil date (the standard days-from-civil count).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Seconds since the epoch of `YYYY-MM-DDTHH:MM:SS` followed by an optional fraction and `Z`.
fn epoch_seconds(text: &str) -> Option<i64> {
    let field = |from: usize, to: usize| -> Option<i64> {
        let part = text.get(from..to)?;
        part.bytes().all(|b| b.is_ascii_digit()).then(|| part.parse().ok()).flatten()
    };
    let rest = text.get(19..)?;
    let fraction_ok = rest.is_empty()
        || rest == "Z"
        || (rest.starts_with('.') && rest.trim_end_matches('Z').bytes().skip(1).all(|b| b.is_ascii_digit()));
    if !fraction_ok || text.get(10..11) != Some("T") {
        return None;
    }
    let days = days_from_civil(field(0, 4)?, field(5, 7)?, field(8, 10)?);
    Some(days * 86_400 + field(11, 13)? * 3_600 + field(14, 16)? * 60 + field(17, 19)?)
}

/// The length of a span in minutes, one decimal; `None` when either end is not a plain instant or it is negative.
fn span_minutes(start: &Value, end: &Value) -> Option<Value> {
    let seconds = epoch_seconds(end.as_str()?)? - epoch_seconds(start.as_str()?)?;
    if seconds < 0 {
        return None;
    }
    #[allow(clippy::cast_precision_loss)]
    let minutes = (seconds as f64 / 60.0 * 10.0).round() / 10.0;
    Number::from_f64(minutes).map(Value::Number)
}

// ---- get_metric_series -----------------------------------------------------------------------------

fn metric_series(source: &Obj) -> Obj {
    let mut out = Obj::new();
    set(
        &mut out,
        "series",
        each_object(source, "series", |series| {
            let mut item = picked(series, &["metric", "unit", "cadence", "source_scope", "from", "to"]);
            set(
                &mut item,
                "points",
                each_object(series, "points", |point| {
                    picked(point, &["date", "value", "min", "mean", "max", "samples"])
                }),
            );
            if series.get("note").and_then(Value::as_str) == Some(NOTE_NO_DATA) {
                item.insert("note".into(), Value::String(NOTE_NO_DATA.into()));
            }
            item
        }),
    );
    set(
        &mut out,
        "labels",
        each_object(source, "labels", |entry| {
            let mut item = picked(entry, &["metric", "from", "to"]);
            let metric = entry.get("metric").and_then(Value::as_str).unwrap_or_default();
            let mut dropped = 0_u64;
            let mut points = Vec::new();
            for point in entry.get("points").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_object) {
                let allowed = point.get("label").and_then(Value::as_str).is_some_and(|l| label_allowed(metric, l));
                if allowed {
                    points.push(Value::Object(picked(point, &["date", "label", "source_scope"])));
                } else {
                    dropped += 1;
                }
            }
            item.insert("points".into(), Value::Array(points));
            if dropped > 0 {
                item.insert("dropped".into(), Value::from(dropped));
            }
            item
        }),
    );
    set(&mut out, "ignored_count", count_of(source, "ignored_metrics"));
    out
}

// ---- get_period_facts ------------------------------------------------------------------------------

fn period_facts(source: &Obj, options: &ViewOptions) -> Obj {
    let mut out = Obj::new();
    set(&mut out, "as_of", source.get("as_of").and_then(as_day));
    for (key, keys) in [
        ("window", &["from", "to", "days"][..]),
        ("baseline", &["from", "to", "days", "min_days_with_data"][..]),
    ] {
        if let Some(inner) = source.get(key).and_then(Value::as_object) {
            out.insert(key.into(), Value::Object(picked(inner, keys)));
        }
    }
    set(
        &mut out,
        "facts",
        each_object(source, "facts", |fact| {
            let mut item = picked(
                fact,
                &[
                    "fact_id", "metric", "unit", "cadence", "source_scope", "value", "window_min", "window_max",
                    "window_days_with_data", "baseline_days_with_data", "confidence", "reason_code",
                ],
            );
            match fact.get("comparison") {
                Some(Value::Object(comparison)) => {
                    let keys = ["baseline_mean", "baseline_sd", "delta", "delta_percent", "z_score", "direction"];
                    item.insert("comparison".into(), Value::Object(picked(comparison, &keys)));
                }
                Some(Value::Null) => {
                    item.insert("comparison".into(), Value::Null);
                }
                _ => {}
            }
            if let Some(evidence) = fact.get("evidence").and_then(Value::as_object) {
                item.insert("evidence".into(), Value::Object(evidence_view(evidence, options)));
            }
            item
        }),
    );
    set(&mut out, "ignored_count", count_of(source, "ignored_metrics"));
    set(&mut out, "reason", one_of(source.get("reason"), &REASONS));
    out
}

fn evidence_view(evidence: &Obj, options: &ViewOptions) -> Obj {
    let mut out = picked(evidence, &["baseline_from", "baseline_to", "baseline_days_with_data"]);
    if let Some(dates) = evidence.get("window_dates").and_then(Value::as_array) {
        let days = dates.iter().filter_map(Value::as_str).filter_map(day_of).map(Value::String).collect();
        out.insert("window_dates".into(), Value::Array(days));
    }
    set(&mut out, "aggregation", one_of(evidence.get("aggregation"), &AGGREGATIONS));
    if options.include_points {
        set(
            &mut out,
            "window_points",
            each_object(evidence, "window_points", |point| picked(point, &["date", "value"])),
        );
    }
    out
}

// ---- get_sleep_detail ------------------------------------------------------------------------------

const SLEEP_NUMBERS: [&str; 20] = [
    "overall_score", "quality_score", "duration_score", "recovery_score", "deep_score", "rem_score",
    "light_score", "awake_time_score", "awakenings_count_score", "combined_awake_score", "restlessness_score",
    "interruptions_score", "awakenings_count", "avg_stress", "avg_spo2", "lowest_spo2", "avg_hr",
    "avg_respiration", "lowest_respiration", "highest_respiration",
];

fn sleep_detail(source: &Obj) -> Obj {
    let mut out = Obj::new();
    set(&mut out, "date", source.get("date").and_then(as_day));
    set(
        &mut out,
        "sessions",
        each_object(source, "sessions", |session| {
            let mut item = Obj::new();
            // The core keys a night by the local date it ended; fall back to the UTC day of the end, then the start.
            let date = session
                .get("date")
                .and_then(as_day)
                .or_else(|| session.get("end_utc").and_then(as_day))
                .or_else(|| session.get("start_utc").and_then(as_day));
            set(&mut item, "date", date);
            keep(session, &["source_scope", "retro"], &mut item);
            if let (Some(start), Some(end)) = (session.get("start_utc"), session.get("end_utc")) {
                set(&mut item, "minutes", span_minutes(start, end));
            }
            if let Some(stage_minutes) = session.get("stage_minutes").and_then(Value::as_object) {
                let keys = ["deep", "light", "rem", "awake", "unmeasurable"];
                item.insert("stage_minutes".into(), Value::Object(picked(stage_minutes, &keys)));
            }
            keep(session, &SLEEP_NUMBERS, &mut item);
            set(
                &mut item,
                "stages",
                each_object(session, "stages", |stage| {
                    let mut kept = Obj::new();
                    set(&mut kept, "stage", named_or_other(stage.get("stage"), STAGES));
                    keep(stage, &["minutes"], &mut kept);
                    kept
                }),
            );
            item
        }),
    );
    if let Some(units) = source.get("units").and_then(Value::as_object) {
        out.insert("units".into(), Value::Object(picked(units, &["stage_minutes", "avg_hr", "avg_spo2", "scores"])));
    }
    set(&mut out, "reason", one_of(source.get("reason"), &REASONS));
    out
}

// ---- list_activities -------------------------------------------------------------------------------

const ACTIVITY_NUMBERS: [&str; 9] = [
    "total_timer_s", "total_elapsed_s", "distance_m", "calories_kcal", "avg_hr", "max_hr", "avg_speed_mps",
    "total_ascent_m", "total_descent_m",
];

fn list_activities(source: &Obj) -> Obj {
    let mut out = Obj::new();
    set(
        &mut out,
        "activities",
        each_object(source, "activities", |activity| {
            let mut item = Obj::new();
            // The UTC day of the start (no offset in the answer); see the module doc.
            set(&mut item, "date", activity.get("start_utc").and_then(as_day));
            set(&mut item, "sport", named_or_other(activity.get("sport"), SPORTS));
            set(&mut item, "sub_sport", named_or_other(activity.get("sub_sport"), SUB_SPORTS));
            keep(activity, &ACTIVITY_NUMBERS, &mut item);
            keep(activity, &["source_scope"], &mut item);
            item
        }),
    );
    if let Some(units) = source.get("units").and_then(Value::as_object) {
        out.insert("units".into(), Value::Object(picked(units, &ACTIVITY_NUMBERS)));
    }
    out
}

// ---- get_data_health -------------------------------------------------------------------------------

fn data_health(source: &Obj) -> Obj {
    let mut out = picked(
        source,
        &["contract_version", "schema_version", "never_imported", "clock_offsets_known", "activities"],
    );
    if let Some(window) = source.get("window").and_then(Value::as_object) {
        out.insert("window".into(), Value::Object(picked(window, &["from", "to", "days"])));
    }
    if let Some(sleep) = source.get("sleep").and_then(Value::as_object) {
        out.insert("sleep".into(), Value::Object(per_scope(sleep, &["nights", "first_day", "last_day"])));
    }
    if let Some(streams) = source.get("streams").and_then(Value::as_object) {
        let mut list = Vec::new();
        for (name, stream) in streams {
            let (true, Some(stream)) = (Vocab::Stream.contains(name), stream.as_object()) else {
                continue;
            };
            let mut item = Obj::new();
            item.insert("stream".into(), Value::String(name.clone()));
            keep(stream, &["records"], &mut item);
            set(&mut item, "first", stream.get("first").and_then(Value::as_str).and_then(day_of).map(Value::String));
            set(&mut item, "last", stream.get("last").and_then(Value::as_str).and_then(day_of).map(Value::String));
            list.push(Value::Object(item));
        }
        out.insert("streams".into(), Value::Array(list));
    }
    set(
        &mut out,
        "metrics",
        each_object(source, "metrics", |metric| {
            let mut item = picked(metric, &["metric", "unit", "cadence"]);
            match metric.get("days_in_window") {
                Some(Value::Object(days)) => {
                    item.insert("days_in_window".into(), Value::Object(per_scope(days, &[])));
                }
                Some(number @ Value::Number(_)) => {
                    item.insert("days_in_window".into(), number.clone());
                }
                _ => {}
            }
            match metric.get("total") {
                Some(Value::Object(total)) => {
                    let span = ["days_with_data", "first_day", "last_day"];
                    let mut kept = picked(total, &span);
                    kept.extend(per_scope(total, &span));
                    item.insert("total".into(), Value::Object(kept));
                }
                Some(Value::Null) => {
                    item.insert("total".into(), Value::Null);
                }
                _ => {}
            }
            item
        }),
    );
    set(
        &mut out,
        "source_agreement",
        each_object(source, "source_agreement", |row| {
            picked(
                row,
                &[
                    "metric", "scope_a", "scope_b", "compared_with", "unit", "days_compared", "days_matching",
                    "max_abs_diff", "mean_diff_a_minus_b", "median_abs_diff",
                ],
            )
        }),
    );
    if let Some(coverage) = source.get("coverage").and_then(Value::as_object) {
        let mut kept = picked(coverage, &["refinements_available", "undatable_files", "unattributed_failures"]);
        if let Some(window) = coverage.get("window").and_then(Value::as_object) {
            kept.insert("window".into(), Value::Object(picked(window, &["from", "to", "days"])));
        }
        set(
            &mut kept,
            "ledger",
            each_object(coverage, "ledger", |row| {
                let mut item = picked(
                    row,
                    &["metric", "source_scope", "present", "failed", "source_empty", "not_covered", "sparse", "gaps_truncated"],
                );
                set(&mut item, "gaps", each_object(row, "gaps", |gap| picked(gap, &["from", "to", "status"])));
                item
            }),
        );
        out.insert("coverage".into(), Value::Object(kept));
    }
    out
}

/// For each contract source scope present in `source`: the listed keys of its object value, or (when `keys` is
/// empty) its number value.
fn per_scope(source: &Obj, keys: &[&str]) -> Obj {
    let mut out = Obj::new();
    let Ok(contract) = disconect_core::contract::Contract::get() else {
        return out;
    };
    for scope in &contract.source_scopes {
        match source.get(scope) {
            Some(Value::Object(inner)) if !keys.is_empty() => {
                out.insert(scope.clone(), Value::Object(picked(inner, keys)));
            }
            Some(number @ Value::Number(_)) if keys.is_empty() => {
                out.insert(scope.clone(), number.clone());
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_contract_tool_is_never_sent_and_unknown_tools_are_refused() {
        assert_eq!(project("get_contract", &json!({})), Err(ViewError::NotSent));
        assert_eq!(project("nope", &json!({})), Err(ViewError::UnknownTool));
        assert_eq!(project("list_activities", &json!([])), Err(ViewError::Malformed));
    }

    #[test]
    fn activity_instants_become_days_and_unknown_keys_vanish() {
        let raw = json!({"activities": [{
            "start_utc": "2025-06-29T16:12:44Z", "end_utc": "2025-06-29T17:00:00Z", "sport": "running",
            "sub_sport": "666", "distance_m": 5000.5, "gps_note": "my street", "source_scope": "device"}],
            "time": "x", "missing_values": "y", "units": {"distance_m": "m", "extra": "z"}});
        let view = project("list_activities", &raw).expect("projects");
        assert_eq!(
            view,
            json!({"activities": [{"date": "2025-06-29", "sport": "running", "sub_sport": "other",
                "distance_m": 5000.5, "source_scope": "device"}], "units": {"distance_m": "m"}})
        );
        assert!(schema::validate("list_activities", &view).is_ok());
        assert!(schema::validate("list_activities", &raw).is_err());
    }

    #[test]
    fn a_sleep_session_keeps_stage_order_and_length_but_no_clock() {
        let raw = json!({"date": "2025-06-16", "sessions": [{
            "date": "2025-06-16", "source_scope": "device", "start_utc": "2025-06-15T20:00:00Z",
            "end_utc": "2025-06-16T03:30:00Z", "overall_score": 77, "retro": false,
            "stage_minutes": {"deep": 60.0, "light": 200.0}, "stages": [
                {"stage": "deep", "start_utc": "2025-06-15T20:00:00Z", "end_utc": "2025-06-15T21:00:00Z", "minutes": 60.0},
                {"stage": "mystery", "start_utc": "2025-06-15T21:00:00Z", "end_utc": "2025-06-15T21:30:00Z", "minutes": 30.0}]}],
            "units": {"avg_hr": "bpm"}, "time": "t"});
        let view = project("get_sleep_detail", &raw).expect("projects");
        let session = &view["sessions"][0];
        assert_eq!(session["minutes"], json!(450.0));
        assert_eq!(session["stages"], json!([{"stage": "deep", "minutes": 60.0}, {"stage": "other", "minutes": 30.0}]));
        assert!(!view.to_string().contains("_utc"));
        assert!(schema::validate("get_sleep_detail", &view).is_ok());
    }

    #[test]
    fn an_ignored_metric_name_is_only_counted_and_a_free_text_label_is_dropped() {
        let raw = json!({"series": [], "ignored_metrics": ["secret plan"], "labels": [{"metric": "hrv_status",
            "from": "2025-06-01", "to": "2025-06-30", "points": [
                {"date": "2025-06-02", "label": "balanced", "source_scope": "vendor_cloud"},
                {"date": "2025-06-03", "label": "call me at 555", "source_scope": "vendor_cloud"}]}]});
        let view = project("get_metric_series", &raw).expect("projects");
        assert_eq!(view["ignored_count"], json!(1));
        assert_eq!(view["labels"][0]["dropped"], json!(1));
        assert_eq!(view["labels"][0]["points"].as_array().map(Vec::len), Some(1));
        assert!(!view.to_string().contains("555") && !view.to_string().contains("secret"));
        assert!(schema::validate("get_metric_series", &view).is_ok());
    }

    #[test]
    fn facts_lose_points_unless_asked() {
        let raw = json!({"as_of": "2025-06-30", "facts": [{"fact_id": "period.steps", "evidence": {
            "window_dates": ["2025-06-30"], "window_points": [{"date": "2025-06-30", "value": 1.5}],
            "aggregation": "something else"}}], "rules": ["r"]});
        let without = project("get_period_facts", &raw).expect("projects");
        assert_eq!(without["facts"][0]["evidence"], json!({"window_dates": ["2025-06-30"]}));
        let with = project_with("get_period_facts", &raw, &ViewOptions { include_points: true }).expect("projects");
        assert!(with["facts"][0]["evidence"].get("window_points").is_some());
        assert!(without.get("rules").is_none());
    }

    #[test]
    fn instants_parse_to_seconds() {
        assert_eq!(epoch_seconds("1970-01-02T00:00:01Z"), Some(86_401));
        assert_eq!(epoch_seconds("2025-06-16T03:00:00.250Z"), Some(1_750_042_800));
        assert_eq!(epoch_seconds("2025-06-16"), None);
        assert_eq!(epoch_seconds("2025-06-16T03:00:00+02:00"), None);
        assert_eq!(day_of("2025-06-16T03:00:00Z").as_deref(), Some("2025-06-16"));
        assert_eq!(day_of("2025-06-16 and more"), Some("2025-06-16".to_string()));
        assert_eq!(day_of("2025-06-16abc"), None);
    }
}
