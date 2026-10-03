// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 15 review: hostile `tools.call` answers through the whole gate (`project`, then `validate`). Each case
//! puts a value where a day, a word or a number belongs; the projection must drop or reduce it, or the schema
//! must refuse the answer. Nothing hostile may reach a validated value.

use disconect_app_lib::coach::schema::validate;
use disconect_app_lib::coach::views::project;
use serde_json::{json, Value};

/// The projected, validated text of `answer`, or `None` when the gate refuses it.
fn gated(tool: &str, answer: Value) -> Option<String> {
    let projected = project(tool, &answer).ok()?;
    validate(tool, &projected).ok()?;
    Some(projected.to_string())
}

const SECRETS: [&str; 6] = ["23:10", "/Users/", "http", "@", "Wi-Fi", "AA:BB"];

fn clean(text: &str) -> bool {
    SECRETS.iter().all(|needle| !text.contains(needle))
}

#[test]
fn hostile_strings_are_dropped_reduced_or_refused_in_every_tool() {
    let cases: Vec<(&str, Value)> = vec![
        ("get_metric_series", json!({"labels": [{"metric": "hrv_status", "from": "2025-06-01", "to": "2025-06-02",
            "points": [{"date": "2025-06-01", "label": "2025-06-01T23:10:00Z", "source_scope": "device"},
                       {"date": "2025-06-02", "label": "home Wi-Fi AA:BB", "source_scope": "device"}]}],
            "ignored_metrics": ["/Users/x/secret.fit", "me@example.com"]})),
        ("get_metric_series", json!({"series": [{"metric": "/Users/x/a.fit", "cadence": "daily", "points": []}]})),
        ("get_metric_series", json!({"series": [{"metric": "steps", "cadence": "daily", "note": "imported from http://x",
            "points": [{"date": "2025-06-01T23:10:00", "value": 1}]}]})),
        ("get_sleep_detail", json!({"date": "2025-06-01T23:10:00Z", "sessions": [{"date": "2025-06-01T23:10:00Z",
            "source_scope": "device", "start_utc": "2025-06-01T23:10:00Z", "end_utc": "2025-06-02T06:00:00Z",
            "device_serial": "AA:BB", "stages": [{"stage": "http://evil.example/", "minutes": 5,
            "start_utc": "2025-06-01T23:10:00Z"}]}], "reason": "see /Users/x/log"})),
        ("get_period_facts", json!({"as_of": "2025-06-01T23:10:00Z", "facts": [{"fact_id": "period.steps",
            "metric": "steps", "evidence": {"aggregation": "custom http", "window_dates": ["2025-06-01T23:10:00Z"]}}],
            "reason": "me@example.com"})),
        ("get_period_facts", json!({"facts": [{"metric": "steps", "comparison": {"direction": "see http://x"}}]})),
        ("get_data_health", json!({"streams": {"/Users/x/a.fit": {"records": 1, "first": "2025-06-01T23:10:00Z"},
            "monitoring": {"records": 2, "first": "2025-06-01T23:10:00Z", "last": "2025-06-02T23:10:00Z", "path": "/Users/x"}},
            "recent_imports": [{"path": "/Users/x/a.fit"}], "provenance": [{"error": "AA:BB"}]})),
        ("get_data_health", json!({"coverage": {"ledger": [{"metric": "steps", "source_scope": "device",
            "gaps": [{"from": "2025-06-01", "to": "2025-06-02", "status": "file /Users/x/a.fit failed"}]}]}})),
        ("get_data_health", json!({"source_agreement": [{"metric": "steps", "compared_with": "me@example.com"}]})),
        ("list_activities", json!({"activities": [{"start_utc": "2025-06-01T23:10:00Z", "sport": "http://x",
            "sub_sport": "Wi-Fi", "name": "Run near /Users/", "source_scope": "device"}]})),
    ];
    let mut refused = 0;
    for (tool, answer) in cases {
        match gated(tool, answer) {
            Some(text) => assert!(clean(&text), "{tool} let a hostile value through: {text}"),
            None => refused += 1,
        }
    }
    assert!(refused >= 4, "the metric path, the gap status, the direction and the compared_with are refused: {refused}");
}

#[test]
fn a_hostile_label_is_counted_not_sent_and_an_echoed_metric_name_is_a_count() {
    let answer = json!({"labels": [{"metric": "hrv_status", "from": "2025-06-01", "to": "2025-06-02",
        "points": [{"date": "2025-06-01", "label": "2025-06-01T23:10:00Z", "source_scope": "device"},
                   {"date": "2025-06-02", "label": "balanced", "source_scope": "device"}]}],
        "ignored_metrics": ["/Users/x/secret.fit", "me@example.com"]});
    let text = gated("get_metric_series", answer).expect("the clean part passes");
    assert!(text.contains("\"dropped\":1") && text.contains("\"ignored_count\":2") && clean(&text), "{text}");
}
