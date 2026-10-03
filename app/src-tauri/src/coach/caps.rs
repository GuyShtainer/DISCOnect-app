// SPDX-License-Identifier: AGPL-3.0-or-later
//! Byte caps and coach defaults (Bet 15 slice 3, attack finding B3). A projected tool answer is bounded by
//! [`ToolBudget`] before it may be sent: [`fit`] returns it as it is when it fits, else applies the tool's
//! shrink steps in a fixed order and gives up with [`CapError::StillTooLarge`]. The loop then tells the user;
//! it never sends an over-size answer. A shrunken answer still passes [`super::schema::validate`]:
//! `thinned`, `truncated` and `dropped_facts` are keys of the schema, so the model is told what was cut.
//!
//! Sizes are the compact JSON text of the projected value (`serde_json::to_string`); the tool-result message
//! wraps that text in a string, which adds a few percent of escaping, inside the margin the budgets leave.
//!
//! [`CoachArgs`] and [`clamp`] are the other half of B3: the arguments of a `tools.call` the model asked for
//! are forced inside the coach defaults before they reach the core, so the big answers are never produced.

use serde_json::{Map, Value};

/// The most bytes of compact JSON one projected answer may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolBudget {
    /// The cap.
    pub max_bytes: usize,
}

/// `get_data_health`: the attack measured 85-333 KB raw on the synthetic stores (median about 97 KB); the
/// projection drops the import log and provenance and the 30-day default window keeps the ledger short.
pub const DATA_HEALTH: ToolBudget = ToolBudget { max_bytes: 24 * 1024 };
/// `get_period_facts`: up to 144 KB raw with points; without points and evidence it is a table of numbers.
pub const PERIOD_FACTS: ToolBudget = ToolBudget { max_bytes: 24 * 1024 };
/// `get_metric_series`: up to 92 KB raw (several 90-day sample-metric series); thinning keeps the shape.
pub const METRIC_SERIES: ToolBudget = ToolBudget { max_bytes: 16 * 1024 };
/// `get_sleep_detail`: one night; the stage timeline is the only part that grows.
pub const SLEEP_DETAIL: ToolBudget = ToolBudget { max_bytes: 8 * 1024 };
/// `list_activities`: 20 activities of a dozen numbers.
pub const LIST_ACTIVITIES: ToolBudget = ToolBudget { max_bytes: 8 * 1024 };

/// The budget of a sendable tool.
pub fn budget(tool: &str) -> Option<ToolBudget> {
    match tool {
        "get_data_health" => Some(DATA_HEALTH),
        "get_period_facts" => Some(PERIOD_FACTS),
        "get_metric_series" => Some(METRIC_SERIES),
        "get_sleep_detail" => Some(SLEEP_DETAIL),
        "list_activities" => Some(LIST_ACTIVITIES),
        _ => None,
    }
}

/// Why an answer cannot be made to fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    /// The tool has no budget (it is never sent).
    UnknownTool,
    /// Every shrink step was applied and the answer is still over its cap.
    StillTooLarge,
}

impl std::fmt::Display for CapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CapError::UnknownTool => "this tool has no byte budget",
            CapError::StillTooLarge => "the answer is too large to send even after shrinking",
        })
    }
}

impl std::error::Error for CapError {}

/// The size of a value as it would be sent.
pub fn json_len(value: &Value) -> usize {
    serde_json::to_string(value).map_or(usize::MAX, |text| text.len())
}

/// The longest thinning stride tried for a metric series (a 90-day series keeps its first and last day).
const MAX_STRIDE: u64 = 45;

/// The projected answer within the tool's budget: as it is, or shrunk by the documented steps, in order.
///
/// * `get_metric_series`: drop `labels`, then keep every 2nd, 3rd, ... point (first and last always kept) and
///   set `thinned` to the stride.
/// * `get_period_facts`: drop `evidence.window_points`, then `evidence.window_dates`, then `evidence`, then the
///   facts that have no value (`no_data`, `no_data_in_window`), setting `dropped_facts` to their count.
/// * `get_data_health`: drop `source_agreement`, then the gap lists of the ledger, then the per-scope detail of
///   each metric (the per-scope day counts stay), then the ledger rows with nothing missing, then each metric's
///   `total`, then the whole ledger. The last two leave the per-metric day counts, which always fit.
///
/// Every cut of a named part is listed in the answer's `omitted` (a fixed vocabulary), so the model is told.
/// * `get_sleep_detail`: drop sessions from the oldest, then the stage lists; `truncated` counts what went.
/// * `list_activities`: drop activities from the oldest; `truncated` counts them.
pub fn fit(tool: &str, projected: &Value) -> Result<Value, CapError> {
    let limit = budget(tool).ok_or(CapError::UnknownTool)?.max_bytes;
    let mut value = projected.clone();
    let fits = |v: &Value| json_len(v) <= limit;
    if fits(&value) {
        return Ok(value);
    }
    match tool {
        "get_metric_series" => {
            remove_key(&mut value, "labels");
            if fits(&value) {
                return Ok(value);
            }
            for stride in 2..=MAX_STRIDE {
                let candidate = thinned(&value, stride);
                if fits(&candidate) {
                    return Ok(candidate);
                }
            }
        }
        "get_period_facts" => {
            let steps: [Step; 3] = [
                ("window_points", drop_window_points),
                ("window_dates", drop_window_dates),
                ("evidence", drop_evidence),
            ];
            if run_steps(&mut value, &steps, &fits) {
                return Ok(value);
            }
            drop_valueless_facts(&mut value);
            if fits(&value) {
                return Ok(value);
            }
        }
        "get_data_health" => {
            let steps: [Step; 6] = [
                ("source_agreement", drop_source_agreement),
                ("ledger_gaps", drop_gaps),
                ("metric_detail", drop_metric_detail),
                ("ledger_rows", drop_complete_ledger_rows),
                ("metric_totals", drop_metric_totals),
                ("ledger", drop_ledger),
            ];
            if run_steps(&mut value, &steps, &fits) {
                return Ok(value);
            }
        }
        "get_sleep_detail" => {
            truncate_from_start(&mut value, "sessions", &fits);
            if !fits(&value) {
                drop_stage_lists(&mut value);
            }
            if fits(&value) {
                return Ok(value);
            }
        }
        _ => {
            truncate_from_end(&mut value, "activities", &fits);
            if fits(&value) {
                return Ok(value);
            }
        }
    }
    Err(CapError::StillTooLarge)
}

// ---- steps -----------------------------------------------------------------------------------------

type Step = (&'static str, fn(&mut Value) -> bool);

/// Apply the steps in order until the value fits; each step that removed something is named in `omitted`.
fn run_steps(value: &mut Value, steps: &[Step], fits: &dyn Fn(&Value) -> bool) -> bool {
    for (name, step) in steps {
        if step(value) {
            if let Value::Object(map) = value {
                let list = map.entry("omitted").or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(items) = list {
                    items.push(Value::String((*name).to_string()));
                }
            }
        }
        if fits(value) {
            return true;
        }
    }
    false
}

fn remove_key(value: &mut Value, key: &str) {
    if let Value::Object(map) = value {
        map.remove(key);
    }
}

/// Each object element of the array under `key`.
fn elements<'a>(value: &'a mut Value, key: &str) -> impl Iterator<Item = &'a mut Map<String, Value>> {
    value
        .get_mut(key)
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object_mut)
}

fn thinned(value: &Value, stride: u64) -> Value {
    let mut out = value.clone();
    for series in elements(&mut out, "series") {
        if let Some(points) = series.get_mut("points").and_then(Value::as_array_mut) {
            let last = points.len().saturating_sub(1);
            let kept: Vec<Value> = points
                .iter()
                .enumerate()
                .filter(|(i, _)| (*i as u64).is_multiple_of(stride) || *i == last)
                .map(|(_, point)| point.clone())
                .collect();
            *points = kept;
        }
    }
    if let Value::Object(map) = &mut out {
        map.insert("thinned".into(), Value::from(stride));
    }
    out
}

fn drop_evidence_key(value: &mut Value, key: &str) -> bool {
    let mut removed = false;
    for fact in elements(value, "facts") {
        if let Some(evidence) = fact.get_mut("evidence").and_then(Value::as_object_mut) {
            removed |= evidence.remove(key).is_some();
        }
    }
    removed
}

fn drop_window_points(value: &mut Value) -> bool {
    drop_evidence_key(value, "window_points")
}

fn drop_window_dates(value: &mut Value) -> bool {
    drop_evidence_key(value, "window_dates")
}

fn drop_evidence(value: &mut Value) -> bool {
    let mut removed = false;
    for fact in elements(value, "facts") {
        removed |= fact.remove("evidence").is_some();
    }
    removed
}

fn drop_valueless_facts(value: &mut Value) {
    let Some(facts) = value.get_mut("facts").and_then(Value::as_array_mut) else {
        return;
    };
    let before = facts.len();
    facts.retain(|fact| {
        !matches!(fact.get("reason_code").and_then(Value::as_str), Some("no_data" | "no_data_in_window"))
    });
    let removed = before - facts.len();
    if removed > 0 {
        if let Value::Object(map) = value {
            map.insert("dropped_facts".into(), Value::from(removed));
        }
    }
}

fn drop_source_agreement(value: &mut Value) -> bool {
    match value {
        Value::Object(map) => map.remove("source_agreement").is_some(),
        _ => false,
    }
}

fn ledger(value: &mut Value) -> Option<&mut Vec<Value>> {
    value
        .get_mut("coverage")
        .and_then(Value::as_object_mut)
        .and_then(|coverage| coverage.get_mut("ledger"))
        .and_then(Value::as_array_mut)
}

fn drop_gaps(value: &mut Value) -> bool {
    let mut removed = false;
    for row in ledger(value).into_iter().flatten().filter_map(Value::as_object_mut) {
        removed |= row.remove("gaps").is_some();
        removed |= row.remove("gaps_truncated").is_some();
    }
    removed
}

fn drop_metric_detail(value: &mut Value) -> bool {
    let mut removed = false;
    for metric in elements(value, "metrics") {
        if let Some(total) = metric.get_mut("total").and_then(Value::as_object_mut) {
            let before = total.len();
            total.retain(|_, v| !v.is_object());
            removed |= total.len() != before;
        }
    }
    removed
}

fn drop_complete_ledger_rows(value: &mut Value) -> bool {
    let Some(rows) = ledger(value) else {
        return false;
    };
    let before = rows.len();
    rows.retain(|row| {
        let missing = |key: &str| row.get(key).and_then(Value::as_u64).unwrap_or(0);
        missing("failed") + missing("source_empty") + missing("not_covered") > 0
    });
    rows.len() != before
}

fn drop_metric_totals(value: &mut Value) -> bool {
    let mut removed = false;
    for metric in elements(value, "metrics") {
        removed |= metric.remove("total").is_some();
    }
    removed
}

fn drop_ledger(value: &mut Value) -> bool {
    value
        .get_mut("coverage")
        .and_then(Value::as_object_mut)
        .is_some_and(|coverage| coverage.remove("ledger").is_some())
}

/// Remove elements of the array under `key` from the front until the value fits (or the array is empty);
/// record the count in `truncated`.
fn truncate_from_start(value: &mut Value, key: &str, fits: &dyn Fn(&Value) -> bool) {
    let mut removed = 0_u64;
    while !fits(value) {
        let Some(items) = value.get_mut(key).and_then(Value::as_array_mut) else {
            break;
        };
        if items.is_empty() {
            break;
        }
        items.remove(0);
        removed += 1;
        mark_truncated(value, removed);
    }
}

fn truncate_from_end(value: &mut Value, key: &str, fits: &dyn Fn(&Value) -> bool) {
    let mut removed = 0_u64;
    while !fits(value) {
        let Some(items) = value.get_mut(key).and_then(Value::as_array_mut) else {
            break;
        };
        if items.pop().is_none() {
            break;
        }
        removed += 1;
        mark_truncated(value, removed);
    }
}

fn mark_truncated(value: &mut Value, removed: u64) {
    if let Value::Object(map) = value {
        map.insert("truncated".into(), Value::from(removed));
    }
}

fn drop_stage_lists(value: &mut Value) {
    let mut removed = value.get("truncated").and_then(Value::as_u64).unwrap_or(0);
    for session in elements(value, "sessions") {
        if let Some(Value::Array(stages)) = session.remove("stages") {
            removed += stages.len() as u64;
        }
    }
    if removed > 0 {
        mark_truncated(value, removed);
    }
}

// ---- coach defaults for the tools.call arguments ----------------------------------------------------

/// The coach's limits on what it may ask a tool for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoachArgs {
    /// Ask `get_period_facts` for the points behind a fact (the user's toggle, slice 5). Default off.
    pub include_points: bool,
    /// Most days of `get_metric_series`.
    pub series_days: i64,
    /// Most days of `get_data_health`'s window.
    pub health_window_days: i64,
    /// Most activities of `list_activities`.
    pub activities_limit: i64,
}

impl Default for CoachArgs {
    fn default() -> Self {
        Self { include_points: false, series_days: 90, health_window_days: 30, activities_limit: 20 }
    }
}

/// A whole number from a JSON number or numeric text, as the core would read it.
fn whole(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.fract() == 0.0 && f.abs() < 9.0e15).map(|f| f as i64)),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// `value` forced into `1..=max`; a missing or unreadable one becomes `max`, the coach's own default.
fn bounded(value: Option<&Value>, max: i64) -> Value {
    Value::from(value.and_then(whole).map_or(max, |n| n.clamp(1, max)))
}

/// [`clamp_with`] with the coach defaults.
pub fn clamp(tool: &str, arguments: &Value) -> Value {
    clamp_with(tool, arguments, &CoachArgs::default())
}

/// The `arguments` of a `tools.call` forced inside the limits: `get_period_facts` gets an explicit
/// `include_points` (true only when the user's toggle allows it), `get_metric_series` `days <= series_days`,
/// `get_data_health` `window_days <= health_window_days`, `list_activities` `limit <= activities_limit`.
/// Other arguments pass through; a non-object becomes an empty one.
pub fn clamp_with(tool: &str, arguments: &Value, limits: &CoachArgs) -> Value {
    let mut map = arguments.as_object().cloned().unwrap_or_default();
    match tool {
        "get_period_facts" => {
            let asked = map.get("include_points").is_some_and(|v| matches!(v, Value::Bool(true)));
            map.insert("include_points".into(), Value::Bool(asked && limits.include_points));
        }
        "get_metric_series" => {
            let days = bounded(map.get("days"), limits.series_days);
            map.insert("days".into(), days);
        }
        "get_data_health" => {
            let days = bounded(map.get("window_days"), limits.health_window_days);
            map.insert("window_days".into(), days);
        }
        "list_activities" => {
            let limit = bounded(map.get("limit"), limits.activities_limit);
            map.insert("limit".into(), limit);
        }
        "get_contract" => map.clear(),
        _ => {}
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn arguments_are_forced_inside_the_coach_limits() {
        assert_eq!(clamp("get_metric_series", &json!({"metrics": ["steps"], "days": 1825}))["days"], json!(90));
        assert_eq!(clamp("get_metric_series", &json!({"days": "400"}))["days"], json!(90));
        assert_eq!(clamp("get_metric_series", &json!({"days": 30.0}))["days"], json!(30));
        assert_eq!(clamp("get_metric_series", &json!({"days": -5}))["days"], json!(1));
        assert_eq!(clamp("get_metric_series", &json!({"days": "x"}))["days"], json!(90));
        assert_eq!(clamp("get_data_health", &json!(null)), json!({"window_days": 30}));
        assert_eq!(clamp("get_data_health", &json!({"window_days": 3650}))["window_days"], json!(30));
        assert_eq!(clamp("list_activities", &json!({"limit": 200}))["limit"], json!(20));
        assert_eq!(clamp("list_activities", &json!({"limit": 5}))["limit"], json!(5));
        assert_eq!(clamp("get_period_facts", &json!({"include_points": true}))["include_points"], json!(false));
        assert_eq!(clamp("get_period_facts", &json!({"include_points": "yes"}))["include_points"], json!(false));
        let toggled = CoachArgs { include_points: true, ..CoachArgs::default() };
        assert_eq!(clamp_with("get_period_facts", &json!({"include_points": true}), &toggled)["include_points"], json!(true));
        assert_eq!(clamp("get_contract", &json!({"x": 1})), json!({}));
    }

    #[test]
    fn a_small_answer_is_returned_unchanged_and_a_contract_has_no_budget() {
        let small = json!({"activities": []});
        assert_eq!(fit("list_activities", &small), Ok(small.clone()));
        assert_eq!(fit("get_contract", &small), Err(CapError::UnknownTool));
    }

    #[test]
    fn a_long_series_is_thinned_keeping_its_last_day_and_says_so() {
        let points: Vec<Value> = (0..2000)
            .map(|i| json!({"date": format!("2025-01-{:02}", 1 + i % 28), "min": 1.5, "mean": 2.5, "max": 3.5, "samples": 100}))
            .collect();
        let big = json!({"series": [{"metric": "heart_rate", "points": points}], "labels": [{"metric": "hrv_status"}]});
        let fitted = fit("get_metric_series", &big).expect("fits");
        assert!(json_len(&fitted) <= METRIC_SERIES.max_bytes);
        assert!(fitted.get("labels").is_none());
        assert!(fitted["thinned"].as_u64().is_some_and(|n| n >= 2));
        assert_eq!(fitted["series"][0]["points"].as_array().and_then(|p| p.last()), big["series"][0]["points"].as_array().and_then(|p| p.last()));
    }

    #[test]
    fn activities_are_cut_from_the_oldest_and_counted() {
        let rows: Vec<Value> = (0..200).map(|i| json!({"date": "2025-06-01", "sport": "running", "distance_m": f64::from(i) * 100.5, "calories_kcal": 500})).collect();
        let fitted = fit("list_activities", &json!({"activities": rows})).expect("fits");
        let kept = fitted["activities"].as_array().map_or(0, Vec::len);
        assert_eq!(fitted["truncated"], json!(200 - kept));
        assert_eq!(fitted["activities"][0]["distance_m"], json!(0.0));
    }

    #[test]
    fn a_big_health_answer_loses_parts_in_order_and_says_which() {
        let rows: Vec<Value> = (0..300)
            .map(|i| json!({"metric": format!("m{i}"), "source_scope": "device", "present": 3, "failed": 0, "source_empty": i % 2, "not_covered": 0,
                "sparse": false, "gaps": [{"from": "2025-06-01", "to": "2025-06-02", "status": "source_empty"}], "gaps_truncated": false}))
            .collect();
        let agreement: Vec<Value> = (0..40).map(|i| json!({"metric": format!("m{i}"), "days_compared": 7})).collect();
        let big = json!({"schema_version": 3, "source_agreement": agreement, "coverage": {"ledger": rows}});
        let fitted = fit("get_data_health", &big).expect("fits");
        assert!(json_len(&fitted) <= DATA_HEALTH.max_bytes);
        let omitted = fitted["omitted"].as_array().expect("omitted");
        assert_eq!(omitted[0], json!("source_agreement"));
        assert_eq!(omitted[1], json!("ledger_gaps"));
        assert!(fitted.get("source_agreement").is_none());
        assert!(fitted["schema_version"] == json!(3), "what is not cut stays");
    }

    #[test]
    fn facts_lose_evidence_in_steps_then_valueless_facts_and_the_cuts_are_counted() {
        let fact = |i: usize, code: &str| json!({"fact_id": format!("period.m{i}"), "reason_code": code, "value": 1.5,
            "evidence": {"window_dates": vec!["2025-06-01"; 30], "window_points": vec![json!({"date": "2025-06-01", "value": 1.5}); 30], "baseline_from": "2025-05-01"}});
        let facts: Vec<Value> = (0..500).map(|i| fact(i, if i % 2 == 0 { "ok" } else { "no_data" })).collect();
        let fitted = fit("get_period_facts", &json!({"facts": facts})).expect("fits");
        assert!(json_len(&fitted) <= PERIOD_FACTS.max_bytes);
        let omitted = fitted["omitted"].as_array().expect("omitted");
        assert_eq!(omitted[0], json!("window_points"));
        assert!(omitted.contains(&json!("evidence")));
        assert_eq!(fitted["dropped_facts"], json!(250));
    }

    #[test]
    fn an_answer_that_cannot_shrink_is_refused() {
        let text = "x".repeat(40_000);
        let impossible = json!({"series": [{"metric": text}]});
        assert_eq!(fit("get_metric_series", &impossible), Err(CapError::StillTooLarge));
    }
}
