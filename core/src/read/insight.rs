// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deterministic facts: a recent window of one person's data against their own history. The twin of
//! `disconect/insight.py`'s `period_facts` for what `data.facts` needs: `window_days` and
//! `baseline_days`. The MCP-only parameters (`end_date`, `metrics`, `source_scope`, `include_points`)
//! and `metric_series` / `sleep_detail` / `list_activities` belong to the Rust-MCP bet; [`FactsQuery`]
//! is where they will go.
//!
//! The layer emits facts, evidence and confidence and never a sentence. Three rules, as in the oracle:
//! compare only against the person's own history; thin evidence says so (`insufficient`, no
//! comparison); no diagnosis. The rules and confidence bands are read from `contract.json`
//! (`contract::InsightContract`), so the Python tables stay the one source.
//!
//! Numerics follow `statistics`: `fmean` is `math.fsum` / n and `stdev` is the exact-rational
//! variance with one correctly rounded square root ([`super::numerics`]); the builtin `sum` of
//! `sample_day_aggregates` is Neumaier ([`crate::writer::py_sum`]); `round(x, 2)` is [`super::queries::round2`].

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::ReadError;
use super::numerics::{fmean, stdev};
use super::queries::{self, iso, parse_date, round2, shift};
use crate::contract::{Contract, MetricContract};

pub const DEFAULT_WINDOW_DAYS: i64 = 7;
pub const DEFAULT_BASELINE_DAYS: i64 = 28;
pub const MAX_WINDOW_DAYS: i64 = 31;
pub const MAX_BASELINE_DAYS: i64 = 365;
/// Fewer baseline days than this: no comparison, confidence "insufficient".
pub const MIN_BASELINE_DAYS: usize = 3;
pub const INSUFFICIENT: &str = "insufficient";
/// `CADENCE_DAILY` and `CADENCE_SAMPLE` of the contract.
const CADENCE_DAILY: &str = "daily";

/// What `period_facts` is asked. New fields (the MCP parameters) are added here with defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactsQuery {
    pub window_days: i64,
    pub baseline_days: i64,
}

impl Default for FactsQuery {
    fn default() -> FactsQuery {
        FactsQuery {
            window_days: DEFAULT_WINDOW_DAYS,
            baseline_days: DEFAULT_BASELINE_DAYS,
        }
    }
}

/// `confidence_for`: the band of the number of baseline days that had data.
pub fn confidence_for(contract: &Contract, baseline_days_with_data: usize) -> &str {
    contract
        .insight
        .confidence_bands
        .iter()
        .find(|band| baseline_days_with_data as u64 >= u64::from(band.min_days))
        .map_or(INSUFFICIENT, |band| band.label.as_str())
}

/// `Comparison`; field order is the oracle's `dataclasses.asdict` order.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Comparison {
    pub baseline_mean: f64,
    pub baseline_sd: Option<f64>,
    pub delta: f64,
    pub delta_percent: Option<f64>,
    pub z_score: Option<f64>,
    pub direction: &'static str,
}

/// The `evidence` dict of a fact built from data (the oracle's `include_points` adds a key later).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Evidence {
    pub window_dates: Vec<String>,
    pub baseline_from: String,
    pub baseline_to: String,
    pub baseline_days_with_data: usize,
    pub aggregation: &'static str,
}

/// `Fact`: one metric in one window for one source scope, with its evidence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Fact {
    pub fact_id: String,
    pub metric: String,
    pub unit: String,
    pub cadence: String,
    pub source_scope: String,
    pub value: Option<f64>,
    pub window_min: Option<f64>,
    pub window_max: Option<f64>,
    pub window_days_with_data: usize,
    pub baseline_days_with_data: usize,
    pub comparison: Option<Comparison>,
    pub confidence: String,
    pub reason_code: &'static str,
    pub evidence: Evidence,
}

/// One day's value for one metric and scope.
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    pub date: String,
    pub value: f64,
}

struct Bounds {
    window_from: String,
    window_to: String,
    baseline_from: String,
    baseline_to: String,
}

/// Python would have raised `ValueError` writing a non-finite float into the protocol line.
const NOT_JSON: &str = "Out of range float values are not JSON compliant";

fn finite(value: f64) -> Result<f64, ReadError> {
    if value.is_finite() {
        Ok(value)
    } else {
        Err(ReadError::Value(NOT_JSON.into()))
    }
}

fn finite_all(values: &[f64]) -> Result<(), ReadError> {
    values.iter().try_for_each(|v| finite(*v).map(|_| ()))
}

fn mean_of(values: &[f64]) -> Result<f64, ReadError> {
    finite_all(values)?;
    fmean(values).ok_or(ReadError::Unexpected("OverflowError"))
}

fn min_of(values: &[f64]) -> f64 {
    values
        .iter()
        .copied()
        .fold(f64::INFINITY, |a, b| if b < a { b } else { a })
}

fn max_of(values: &[f64]) -> f64 {
    values
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, |a, b| if b > a { b } else { a })
}

/// `_daily_points`: stored daily values of one metric by scope, ordered by date. Rows of a scope the
/// contract does not name are dropped.
fn daily_points(
    conn: &Connection,
    metric: &str,
    start: &str,
    end: &str,
    scopes: &[String],
) -> Result<BTreeMap<String, Vec<Point>>, ReadError> {
    let mut by_scope: BTreeMap<String, Vec<Point>> = BTreeMap::new();
    let mut statement = conn.prepare(
        "SELECT date, value, source_scope FROM daily_metrics WHERE metric=? AND date BETWEEN ? AND ? \
         ORDER BY date",
    )?;
    let mut rows = statement.query(rusqlite::params![metric, start, end])?;
    while let Some(row) = rows.next()? {
        let scope = queries::text(row.get_ref(2)?)?;
        if !scopes.iter().any(|wanted| wanted == scope) {
            continue;
        }
        let date = queries::text(row.get_ref(0)?)?.to_string();
        let value = queries::number(row.get_ref(1)?)?;
        by_scope
            .entry(scope.to_string())
            .or_default()
            .push(Point { date, value });
    }
    Ok(by_scope)
}

fn build_fact(
    contract: &Contract,
    metric: &MetricContract,
    scope: &str,
    window: &[Point],
    baseline: &[Point],
    bounds: &Bounds,
) -> Result<Fact, ReadError> {
    let window_values: Vec<f64> = window.iter().map(|p| p.value).collect();
    let baseline_values: Vec<f64> = baseline.iter().map(|p| p.value).collect();
    let evidence = Evidence {
        window_dates: window.iter().map(|p| p.date.clone()).collect(),
        baseline_from: bounds.baseline_from.clone(),
        baseline_to: bounds.baseline_to.clone(),
        baseline_days_with_data: baseline_values.len(),
        aggregation: if metric.cadence == CADENCE_DAILY {
            "mean of the window's daily values"
        } else {
            "mean of per-day means of samples"
        },
    };
    let mut fact = Fact {
        fact_id: format!("period.{}", metric.metric),
        metric: metric.metric.clone(),
        unit: metric.unit.clone(),
        cadence: metric.cadence.clone(),
        source_scope: scope.to_string(),
        value: None,
        window_min: None,
        window_max: None,
        window_days_with_data: window_values.len(),
        baseline_days_with_data: baseline_values.len(),
        comparison: None,
        confidence: INSUFFICIENT.to_string(),
        reason_code: "no_data_in_window",
        evidence,
    };
    if window_values.is_empty() {
        return Ok(fact);
    }
    let value = mean_of(&window_values)?;
    fact.value = Some(finite(round2(value))?);
    fact.window_min = Some(finite(round2(min_of(&window_values)))?);
    fact.window_max = Some(finite(round2(max_of(&window_values)))?);
    if baseline_values.len() < MIN_BASELINE_DAYS {
        fact.reason_code = if baseline_values.is_empty() {
            "no_baseline"
        } else {
            "baseline_too_thin"
        };
        return Ok(fact);
    }
    let baseline_mean = mean_of(&baseline_values)?;
    let baseline_sd = if baseline_values.len() > 1 {
        Some(stdev(&baseline_values).ok_or(ReadError::Unexpected("OverflowError"))?)
    } else {
        None
    };
    let delta = value - baseline_mean;
    let direction = if delta.abs() < 1e-9 {
        "unchanged"
    } else if delta > 0.0 {
        "higher"
    } else {
        "lower"
    };
    let optional = |x: Option<f64>| x.map(round2).map(finite).transpose();
    fact.comparison = Some(Comparison {
        baseline_mean: finite(round2(baseline_mean))?,
        baseline_sd: optional(baseline_sd)?,
        delta: finite(round2(delta))?,
        delta_percent: optional((baseline_mean != 0.0).then(|| delta / baseline_mean * 100.0))?,
        z_score: optional(baseline_sd.filter(|sd| *sd != 0.0).map(|sd| delta / sd))?,
        direction,
    });
    fact.confidence = confidence_for(contract, baseline_values.len()).to_string();
    fact.reason_code = "ok";
    Ok(fact)
}

/// `period_facts(conn, window_days, baseline_days)`: facts for every metric with data, the last
/// `window_days` against the `baseline_days` before them. `as_of` is the latest date the store holds
/// (never the clock), so an old archive still answers. Metrics without data in either range are
/// omitted. The result carries the full oracle shape, `sources` included (`serve` drops it).
pub fn period_facts(conn: &Connection, query: &FactsQuery) -> Result<Value, ReadError> {
    let contract = Contract::get()?;
    let window_days = query.window_days.clamp(1, MAX_WINDOW_DAYS);
    let baseline_days = query.baseline_days.clamp(1, MAX_BASELINE_DAYS);
    let scopes = &contract.source_scopes;
    let rules: Vec<&String> = contract.insight.rules.iter().collect();
    let Some(as_of) = queries::latest_stored_date(conn)? else {
        return Ok(json!({
            "as_of": null, "facts": [], "ignored_metrics": [],
            "reason": "nothing stored yet", "rules": rules,
        }));
    };
    let end = parse_date(&as_of)?;
    let window_start = shift(end, 1 - window_days)?;
    let baseline_end = shift(window_start, -1)?;
    let baseline_start = shift(baseline_end, 1 - baseline_days)?;
    let bounds = Bounds {
        window_from: iso(window_start),
        window_to: as_of.clone(),
        baseline_from: iso(baseline_start),
        baseline_to: iso(baseline_end),
    };

    let offsets = queries::load_offsets(conn)?;
    let mut facts: Vec<Fact> = Vec::new();
    for item in &contract.metrics {
        let by_scope: BTreeMap<String, Vec<Point>> = if item.cadence == CADENCE_DAILY {
            daily_points(conn, &item.metric, &bounds.baseline_from, &as_of, scopes)?
        } else {
            queries::sample_day_aggregates(
                conn,
                &item.metric,
                &bounds.baseline_from,
                &as_of,
                &offsets,
                scopes,
            )?
            .into_iter()
            .map(|(scope, days)| {
                let points = days
                    .into_iter()
                    .map(|d| Point {
                        date: d.date,
                        value: d.mean,
                    })
                    .collect();
                (scope, points)
            })
            .collect()
        };
        for scope in scopes {
            let Some(points) = by_scope.get(scope).filter(|p| !p.is_empty()) else {
                continue;
            };
            let window: Vec<Point> = points
                .iter()
                .filter(|p| p.date >= bounds.window_from)
                .cloned()
                .collect();
            let baseline: Vec<Point> = points
                .iter()
                .filter(|p| p.date <= bounds.baseline_to)
                .cloned()
                .collect();
            facts.push(build_fact(
                contract, item, scope, &window, &baseline, &bounds,
            )?);
        }
    }

    let confidence_bands: Map<String, Value> = contract
        .insight
        .confidence_bands
        .iter()
        .map(|band| {
            (
                band.label.clone(),
                Value::String(format!(">= {} baseline days", band.min_days)),
            )
        })
        .collect();
    let mut out = Map::new();
    out.insert("as_of".into(), json!(as_of));
    out.insert(
        "window".into(),
        json!({"from": bounds.window_from, "to": bounds.window_to, "days": window_days}),
    );
    out.insert(
        "baseline".into(),
        json!({
            "from": bounds.baseline_from, "to": bounds.baseline_to, "days": baseline_days,
            "min_days_with_data": MIN_BASELINE_DAYS, "confidence_bands": confidence_bands,
        }),
    );
    out.insert(
        "facts".into(),
        serde_json::to_value(&facts).map_err(|_| ReadError::Unexpected("TypeError"))?,
    );
    out.insert("ignored_metrics".into(), json!([]));
    out.insert("rules".into(), json!(rules));
    out.insert(
        "missing_values".into(),
        json!(contract.conventions.missing_values),
    );
    out.insert("sources".into(), json!(contract.conventions.sources));
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> &'static Contract {
        match Contract::get() {
            Ok(c) => c,
            Err(e) => unreachable!("contract.json must load: {e}"),
        }
    }

    #[test]
    fn confidence_bands_are_pinned() {
        let labels: Vec<_> = [0, 2, 3, 4, 5, 7, 8, 30]
            .map(|n| confidence_for(contract(), n))
            .into();
        assert_eq!(
            labels,
            [
                "insufficient",
                "insufficient",
                "low",
                "low",
                "medium",
                "medium",
                "high",
                "high"
            ]
        );
        assert_eq!(
            (
                MIN_BASELINE_DAYS,
                DEFAULT_WINDOW_DAYS,
                DEFAULT_BASELINE_DAYS
            ),
            (3, 7, 28)
        );
        assert_eq!((MAX_WINDOW_DAYS, MAX_BASELINE_DAYS), (31, 365));
    }

    fn points(values: &[f64]) -> Vec<Point> {
        values
            .iter()
            .enumerate()
            .map(|(i, v)| Point {
                date: format!("2025-06-{:02}", i + 1),
                value: *v,
            })
            .collect()
    }

    fn fact_of(window: &[f64], baseline: &[f64]) -> Fact {
        let bounds = Bounds {
            window_from: "2025-06-25".into(),
            window_to: "2025-07-01".into(),
            baseline_from: "2025-05-28".into(),
            baseline_to: "2025-06-24".into(),
        };
        let metric = contract().metric("steps").cloned();
        let Some(metric) = metric else {
            unreachable!("steps is a metric")
        };
        match build_fact(
            contract(),
            &metric,
            "local",
            &points(window),
            &points(baseline),
            &bounds,
        ) {
            Ok(fact) => fact,
            Err(e) => unreachable!("fact: {e}"),
        }
    }

    #[test]
    fn the_reason_codes_follow_the_oracle() {
        assert_eq!(
            fact_of(&[], &[1.0, 2.0, 3.0]).reason_code,
            "no_data_in_window"
        );
        assert_eq!(fact_of(&[5.0], &[]).reason_code, "no_baseline");
        assert_eq!(
            fact_of(&[5.0], &[1.0, 2.0]).reason_code,
            "baseline_too_thin"
        );
        let ok = fact_of(&[5.0], &[1.0, 2.0, 3.0]);
        assert_eq!((ok.reason_code, ok.confidence.as_str()), ("ok", "low"));
    }

    #[test]
    fn a_zero_variance_baseline_has_no_z_score_and_equal_means_are_unchanged() {
        let flat = fact_of(&[160.0], &[150.0; 5]);
        let c = flat.comparison.clone();
        let Some(c) = c else {
            unreachable!("comparison")
        };
        assert_eq!(c.baseline_sd, Some(0.0));
        assert_eq!(
            (c.z_score, c.delta, c.delta_percent, c.direction),
            (None, 10.0, Some(6.67), "higher")
        );
        let tie = fact_of(&[10.0, 10.0], &[9.0, 11.0, 9.0, 11.0]);
        let c = tie.comparison.clone();
        let Some(c) = c else {
            unreachable!("comparison")
        };
        assert_eq!(
            (c.direction, c.delta, c.z_score),
            ("unchanged", 0.0, Some(0.0))
        );
    }

    #[test]
    fn a_difference_below_the_epsilon_is_unchanged_and_keeps_its_negative_zero() {
        // fmean of three 0.1 is one ulp above 0.1, of seven exactly 0.1: delta is about -2.8e-17
        let fact = fact_of(&[0.1; 7], &[0.1; 3]);
        let c = fact.comparison.clone();
        let Some(c) = c else {
            unreachable!("comparison")
        };
        assert_eq!(c.direction, "unchanged");
        assert!(
            c.delta == 0.0 && c.delta.is_sign_negative(),
            "round(-2.8e-17, 2) is -0.0"
        );
    }

    #[test]
    fn a_non_finite_stored_value_is_reported_like_the_json_encoder() {
        let bounds = Bounds {
            window_from: String::new(),
            window_to: String::new(),
            baseline_from: String::new(),
            baseline_to: String::new(),
        };
        let metric = contract().metric("steps").cloned();
        let Some(metric) = metric else {
            unreachable!("steps is a metric")
        };
        let failed = build_fact(
            contract(),
            &metric,
            "local",
            &points(&[f64::INFINITY]),
            &[],
            &bounds,
        );
        assert!(matches!(failed, Err(ReadError::Value(m)) if m == NOT_JSON));
    }
}
