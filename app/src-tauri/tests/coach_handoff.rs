// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 15c slice 1: the hand-off's text builder end to end, over the real tool answers (the serve oracle's
//! synthetic fixtures, the same ones `tests/coach_views.rs` and `tests/coach_loop.rs` use) and over synthetic
//! answers padded to the largest shape the byte caps allow. Nothing here opens a store or a home folder.

use disconect_app_lib::coach::chat_loop::ToolCallError;
use disconect_app_lib::coach::handoff::{build_text, HandoffError};
use disconect_core::identity::{DISCLAIMER, PRODUCT};
use serde_json::{json, Value};

mod common;
use common::fixtures::{answers, has_clock_time};

/// A `call_tool` that answers from a store's recorded fixtures, by tool name only (the arguments the coach
/// would have sent do not have to match a specific recorded call: the gate runs the same regardless).
fn canned(store: &'static str) -> impl Fn(&str, Value) -> Result<Value, ToolCallError> {
    let all = answers(store);
    move |name: &str, _arguments: Value| {
        all.iter()
            .find(|a| a.tool == name)
            .map(|a| json!({"name": name, "result": a.result.clone()}))
            .ok_or_else(|| ToolCallError { code: "tool_error".to_string() })
    }
}

#[test]
fn a_window_outside_seven_twenty_eight_ninety_is_refused_before_any_tool_runs() {
    let called = std::cell::Cell::new(false);
    let call = |_: &str, _: Value| -> Result<Value, ToolCallError> {
        called.set(true);
        Err(ToolCallError { code: "tool_error".to_string() })
    };
    assert_eq!(build_text(10, false, &call), Err(HandoffError::BadWindow));
    assert!(!called.get(), "no tool is called before the window is checked");
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn build_text_over_real_fixture_answers_names_itself_carries_the_disclaimer_and_stays_in_bounds() {
    let call = canned("synthetic");
    let result = build_text(28, false, &call).expect("builds over real answers");
    assert!(result.text.starts_with(PRODUCT), "{}", result.text);
    assert!(result.text.contains(DISCLAIMER), "{}", result.text);
    let headings = result.text.matches("## ").count();
    assert!(
        headings == 5 || (headings == 4 && result.text.to_lowercase().contains("no night")),
        "{headings} headings:\n{}",
        result.text
    );
    assert!(result.bytes <= 96 * 1024, "{} bytes", result.bytes);
    assert_eq!(result.bytes, result.text.len());
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn build_text_never_carries_a_clock_time() {
    let call = canned("synthetic-v1");
    let result = build_text(7, false, &call).expect("builds");
    assert!(!has_clock_time(&result.text), "{}", result.text);
}

#[test]
fn a_withheld_gate_result_cancels_the_whole_handoff() {
    // `activities` is a count in the schema (an integer); an array there survives the view's verbatim copy but
    // is refused by the schema, so the very first tool call already withholds and nothing further is built.
    let call = |name: &str, _arguments: Value| -> Result<Value, ToolCallError> {
        Ok(json!({"name": name, "result": {"activities": []}}))
    };
    assert_eq!(build_text(7, false, &call), Err(HandoffError::Withheld));
}

/// The raw (pre-projection) answer shape for `tool`, padded to the largest size each byte cap still allows
/// (see `caps.rs`'s own shrink-step tests for the same shapes): enough rows that every documented shrink step
/// actually runs, never so many that `caps::fit` gives up with `StillTooLarge`.
fn padded_answer(tool: &str) -> Value {
    match tool {
        "get_metric_series" => {
            let points: Vec<Value> =
                (0..2000).map(|i| json!({"date": format!("2025-01-{:02}", 1 + i % 28), "value": 1.5})).collect();
            json!({"series": [{"metric": "steps", "points": points}]})
        }
        "get_period_facts" => {
            let fact = |i: usize| {
                let code = if i.is_multiple_of(2) { "ok" } else { "no_data" };
                json!({
                    "fact_id": "period.steps",
                    "reason_code": code,
                    "evidence": {"window_dates": vec!["2025-06-01"; 30], "baseline_from": "2025-05-01"},
                })
            };
            json!({"facts": (0..450).map(fact).collect::<Vec<_>>()})
        }
        "get_sleep_detail" => {
            let sessions: Vec<Value> = (0..500).map(|_| json!({"date": "2025-06-01", "source_scope": "device"})).collect();
            json!({"sessions": sessions})
        }
        "list_activities" => {
            let activities: Vec<Value> = (0..300)
                .map(|_| json!({"start_utc": "2025-06-01T08:00:00Z", "source_scope": "device"}))
                .collect();
            json!({"activities": activities})
        }
        _ => {
            let rows: Vec<Value> = (0..300_u32)
                .map(|i| {
                    json!({
                        "metric": if i.is_multiple_of(2) { "steps" } else { "resting_heart_rate" },
                        "source_scope": "device",
                        "present": 3,
                        "failed": 0,
                        "source_empty": i % 2,
                        "not_covered": 0,
                        "sparse": false,
                        "gaps_truncated": false,
                        "gaps": [{"from": "2025-06-01", "to": "2025-06-02", "status": "source_empty"}],
                    })
                })
                .collect();
            let agreement: Vec<Value> =
                (0..40).map(|i| json!({"metric": format!("m{i}"), "days_compared": 7})).collect();
            json!({
                "sleep": {"device": {"nights": 500, "first_day": "2024-01-01", "last_day": "2025-06-30"}},
                "source_agreement": agreement,
                "coverage": {"ledger": rows},
            })
        }
    }
}

#[test]
fn the_largest_answers_the_caps_allow_still_fit_the_overall_bound() {
    let call = |name: &str, _arguments: Value| -> Result<Value, ToolCallError> {
        Ok(json!({"name": name, "result": padded_answer(name)}))
    };
    let result = build_text(90, false, &call).expect("builds even at the largest shapes the caps allow");
    assert!(result.bytes <= 96 * 1024, "{} bytes", result.bytes);
    assert_eq!(result.bytes, result.text.len());
    let headings = result.text.matches("## ").count();
    assert!(
        headings == 5 || (headings == 4 && result.text.to_lowercase().contains("no night")),
        "{headings} headings:\n{}",
        result.text
    );
}
