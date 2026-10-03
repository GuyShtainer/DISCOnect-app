// SPDX-License-Identifier: AGPL-3.0-or-later
//! The MCP-only read paths (`read::mcp_paths`, `read::insight`, `read::queries`) against the Python
//! functions' own answers (`tests/fixtures/read_paths.json`, written by
//! `disconect/tests/gen_read_fixtures.py`): every recorded case is replayed over the committed stores
//! and compared as a tagged tree (`wirejson::Json` keeps bool, int, float, string, null, list and
//! object apart; floats compare by Python `repr`; **object key order counts**, because the MCP writes
//! the answer in insertion order). A Python `ValueError` must be a `ReadError::Value` with the same
//! text; an `OverflowError` a `ReadError::Overflow`.
//!
//! The counts per function are asserted, so a case that is silently skipped fails the run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Once;

use disconect_core::canon::py_float_repr;
use disconect_core::identity::neutral_json;
use disconect_core::read::ReadError;
use disconect_core::read::insight::{FactsQuery, period_facts_ordered};
use disconect_core::read::mcp_paths::{list_activities, metric_series, sleep_detail};
use disconect_core::read::queries::{MAX_DAILY_DAYS, MAX_SAMPLE_DAYS, iso, parse_day, window};
use disconect_core::store;
use disconect_core::wirejson::{self, Json, PyStr};

const NOW: &str = "2025-07-02T09:30:00Z";
/// What the generator wrote: cases per function, and how many of them are errors.
const EXPECTED: [(&str, usize, usize); 6] = [
    ("metric_series", 319, 110),
    ("sleep_detail", 130, 75),
    ("list_activities", 43, 0),
    ("period_facts", 388, 160),
    ("parse_day", 54, 46),
    ("window", 180, 68),
];

fn crate_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn store_file(name: &str) -> PathBuf {
    let tests = crate_dir().join("../disconect/tests/fixtures");
    match name {
        "synthetic" => tests.join("serve/synthetic.hbdb"),
        "synthetic-v1" => tests.join("serve/synthetic-v1.hbdb"),
        "empty" => tests.join("serve/empty.hbdb"),
        "privacy-seed" => tests.join("mcp/privacy-seed.hbdb"),
        "wide" => tests.join("read/wide.hbdb"),
        other => unreachable!("unknown store {other}"),
    }
}

/// The clock every case ran under, set once before any read of it (this file is its own process).
fn pin_clock() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: runs once, before any test thread reads the environment.
        unsafe { std::env::set_var("DISCONECT_NOW", NOW) };
    });
}

fn field<'a>(node: &'a Json, key: &str) -> &'a Json {
    node.get(key)
        .unwrap_or_else(|| unreachable!("no key {key}"))
}

fn text_arg(args: &Json, key: &str) -> Option<PyStr> {
    match args.get(key) {
        Some(Json::Str(text)) => Some(text.clone()),
        _ => None,
    }
}

fn int_arg(args: &Json, key: &str, default: i64) -> i64 {
    match args.get(key) {
        Some(Json::Int(value)) => value.clamped_i64(),
        _ => default,
    }
}

fn list_arg(args: &Json, key: &str) -> Option<Vec<PyStr>> {
    match args.get(key) {
        Some(Json::Array(items)) => Some(
            items
                .iter()
                .map(|item| match item {
                    Json::Str(text) => text.clone(),
                    other => unreachable!("not a string: {other:?}"),
                })
                .collect(),
        ),
        _ => None,
    }
}

fn kind(node: &Json) -> &'static str {
    match node {
        Json::Null => "null",
        Json::Bool(_) => "bool",
        Json::Int(_) => "int",
        Json::Float(_) => "float",
        Json::Str(_) => "str",
        Json::Array(_) => "list",
        Json::Object(_) => "dict",
    }
}

/// The path of the first difference between two trees (never a value), or `None` when they are equal:
/// types apart, floats by repr, list and key order significant.
fn first_difference(want: &Json, got: &Json, path: &str) -> Option<String> {
    match (want, got) {
        (Json::Null, Json::Null) => None,
        (Json::Bool(a), Json::Bool(b)) if a == b => None,
        (Json::Int(a), Json::Int(b)) if a == b => None,
        (Json::Float(a), Json::Float(b)) if float_repr(*a) == float_repr(*b) => None,
        (Json::Str(a), Json::Str(b)) if a == b => None,
        (Json::Array(a), Json::Array(b)) => {
            if a.len() != b.len() {
                return Some(format!("{path} (length {} vs {})", a.len(), b.len()));
            }
            a.iter()
                .zip(b)
                .enumerate()
                .find_map(|(index, (x, y))| first_difference(x, y, &format!("{path}[{index}]")))
        }
        (Json::Object(a), Json::Object(b)) => {
            let keys = |pairs: &[(PyStr, Json)]| -> Vec<String> {
                pairs.iter().map(|(key, _)| key.units_lossy()).collect()
            };
            if keys(a) != keys(b) {
                return Some(format!(
                    "{path} (keys or key order: {:?} vs {:?})",
                    keys(a),
                    keys(b)
                ));
            }
            a.iter().zip(b).find_map(|((key, x), (_, y))| {
                first_difference(x, y, &format!("{path}.{}", key.units_lossy()))
            })
        }
        (a, b) if kind(a) != kind(b) => Some(format!("{path} (type {} vs {})", kind(a), kind(b))),
        _ => Some(format!("{path} (value)")),
    }
}

fn float_repr(value: f64) -> String {
    if value.is_finite() {
        py_float_repr(value)
    } else {
        format!("{value}")
    }
}

/// What a case answered, in the fixture's own vocabulary.
enum Answer {
    Value(Json),
    Failed(ReadError),
}

fn run(conn: Option<&rusqlite::Connection>, name: &str, args: &Json) -> Answer {
    let conn = || conn.unwrap_or_else(|| unreachable!("{name} needs a store"));
    let outcome: Result<Json, ReadError> = match name {
        "metric_series" => metric_series(
            conn(),
            &list_arg(args, "metrics").unwrap_or_default(),
            int_arg(args, "days", 90),
            text_arg(args, "source_scope").as_ref(),
            text_arg(args, "end_date").as_ref(),
        ),
        "sleep_detail" => sleep_detail(conn(), text_arg(args, "date").as_ref()),
        "list_activities" => list_activities(conn(), int_arg(args, "limit", 20)),
        "period_facts" => period_facts_ordered(
            conn(),
            &FactsQuery {
                window_days: int_arg(args, "window_days", 7),
                baseline_days: int_arg(args, "baseline_days", 28),
                end_date: text_arg(args, "end_date"),
                metrics: list_arg(args, "metrics"),
                source_scope: text_arg(args, "source_scope"),
                include_points: matches!(args.get("include_points"), Some(Json::Bool(true))),
            },
        ),
        "parse_day" => {
            let text = text_arg(args, "text").unwrap_or_else(|| PyStr::from_text(""));
            let label = text_arg(args, "name")
                .map(|n| n.units_lossy())
                .unwrap_or_default();
            parse_day(&text, &label).map(|day| {
                let mut out = Json::dict();
                out.set("date", Json::text(&iso(day)));
                out
            })
        }
        "window" => {
            let cap = int_arg(args, "cap", 0);
            assert!(cap == MAX_DAILY_DAYS || cap == MAX_SAMPLE_DAYS);
            window(
                int_arg(args, "days", 1),
                text_arg(args, "end_date").as_ref(),
                cap,
            )
            .map(|(from, to)| {
                let mut out = Json::dict();
                out.set("from", Json::text(&from));
                out.set("to", Json::text(&to));
                out
            })
        }
        other => unreachable!("unknown function {other}"),
    };
    match outcome {
        Ok(mut value) => {
            neutral_json(&mut value);
            Answer::Value(value)
        }
        Err(error) => Answer::Failed(error),
    }
}

/// `None` when the answer is what Python gave; else what differed (a path or a class, never a value).
fn judge(want: &Json, answer: &Answer) -> Option<String> {
    let Json::Str(class) = want.get("class").unwrap_or(&Json::Null) else {
        return match answer {
            Answer::Value(got) => first_difference(want, got, ""),
            Answer::Failed(_) => Some("Rust failed where Python answered".into()),
        };
    };
    let text = field(want, "error");
    match (class.to_text().as_deref(), answer) {
        (Some("ValueError"), Answer::Failed(ReadError::Value(message))) => {
            if matches!(text, Json::Str(want_text) if want_text.equals(message)) {
                None
            } else {
                Some("ValueError text".into())
            }
        }
        (Some("OverflowError"), Answer::Failed(ReadError::Overflow)) => None,
        (Some(name), Answer::Failed(_)) => {
            Some(format!("Rust failed with another error than {name}"))
        }
        (Some(name), Answer::Value(_)) => Some(format!("Rust answered where Python raised {name}")),
        (None, _) => Some("class is not text".into()),
    }
}

#[test]
fn every_recorded_case_is_answered_like_python() {
    pin_clock();
    let source = std::fs::read_to_string(crate_dir().join("tests/fixtures/read_paths.json"))
        .expect("fixture");
    let fixture = wirejson::parse(&source).expect("fixture is JSON");
    assert!(matches!(field(&fixture, "now"), Json::Str(now) if now.equals(NOW)));
    let Json::Array(cases) = field(&fixture, "cases") else {
        unreachable!("cases")
    };
    let folder = tempfile::tempdir().expect("tempdir");
    let mut stores = BTreeMap::new();
    for name in ["synthetic", "synthetic-v1", "empty", "privacy-seed", "wide"] {
        let copy = folder.path().join(format!("{name}.hbdb"));
        std::fs::copy(store_file(name), &copy).expect("copy store");
        stores.insert(
            name,
            store::open_read_only_with(&copy, None).expect("open store"),
        );
    }
    let mut seen: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let Json::Str(function) = field(case, "fn") else {
            unreachable!("fn")
        };
        let function = function.units_lossy();
        let conn = match field(case, "store") {
            Json::Str(name) => {
                let name = name.units_lossy();
                Some(stores[name.as_str()].conn())
            }
            _ => None,
        };
        let want = field(case, "result");
        let answer = run(conn, &function, field(case, "args"));
        let counter = seen.entry(function.clone()).or_default();
        counter.0 += 1;
        counter.1 += usize::from(want.get("error").is_some());
        if let Some(difference) = judge(want, &answer) {
            failures.push(format!("case {index} ({function}): {difference}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ; first: {:?}",
        failures.len(),
        cases.len(),
        failures.iter().take(5).collect::<Vec<_>>()
    );
    for (function, total, errors) in EXPECTED {
        assert_eq!(
            seen.get(function).copied(),
            Some((total, errors)),
            "cases (and error cases) replayed for {function}"
        );
    }
    assert_eq!(
        cases.len(),
        EXPECTED.iter().map(|(_, total, _)| total).sum::<usize>()
    );
}

#[test]
fn the_comparison_tells_one_from_one_point_zero_and_names_a_path_not_a_value() {
    let one = wirejson::parse(r#"{"a":[1,{"b":"x"}],"c":1.0}"#).expect("json");
    let other = wirejson::parse(r#"{"a":[1,{"b":"y"}],"c":1.0}"#).expect("json");
    assert_eq!(
        first_difference(&one, &other, "").as_deref(),
        Some(".a[1].b (value)")
    );
    let typed = wirejson::parse(r#"{"a":[1,{"b":"x"}],"c":1}"#).expect("json");
    assert_eq!(
        first_difference(&one, &typed, "").as_deref(),
        Some(".c (type float vs int)")
    );
    let reordered = wirejson::parse(r#"{"c":1.0,"a":[1,{"b":"x"}]}"#).expect("json");
    assert!(first_difference(&one, &reordered, "").is_some_and(|d| d.contains("key order")));
    let zero = wirejson::parse("[0.0]").expect("json");
    let negative = wirejson::parse("[-0.0]").expect("json");
    assert!(first_difference(&zero, &negative, "").is_some());
    assert!(first_difference(&one, &one, "").is_none());
}
