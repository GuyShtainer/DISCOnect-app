// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 15 slice 3: the coach projection, the positive schema and the byte caps, over the real tool answers.
//!
//! The answers are the `tools.call` entries of the serve oracle transcripts (synthetic stores only, committed
//! under `projects/disconect/tests/fixtures/serve/`): about 317 calls on each of three stores. The transcripts
//! are gzip lines of about 10 MB each, too large to copy into a second fixture, so the test reads them in
//! place (`gunzip -c`) and pairs each line with its request in `script.json` (same order, same length).
//! Nothing here opens a store or a home folder.

use std::collections::BTreeMap;

use disconect_app_lib::coach::caps::{self, clamp, fit, json_len, CapError};
use disconect_app_lib::coach::schema::{validate, Reason};
use disconect_app_lib::coach::views::{project, project_with, ViewError, ViewOptions};
use serde_json::{json, Value};

mod common;
use common::fixtures::{all_answers, has_clock_time, sendable, within_coach_limits, Answer, SENDABLE, STORES};

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn the_fixtures_hold_the_expected_calls() {
    let all = all_answers();
    for store in STORES {
        let count = all.iter().filter(|a| a.store == store).count();
        assert!(count >= 100, "{store}: {count} successful tools.call results");
    }
    for tool in SENDABLE {
        assert!(all.iter().any(|a| a.tool == tool), "{tool} is in the fixtures");
    }
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn every_sendable_answer_projects_validates_and_carries_no_clock_text_or_log() {
    let all = all_answers();
    let mut checked = 0;
    for a in sendable(&all) {
        let projected = project(&a.tool, &a.result).unwrap_or_else(|e| panic!("{} {}: {e}", a.store, a.tool));
        if let Err(e) = validate(&a.tool, &projected) {
            panic!("{} {} {:?}: {e}", a.store, a.tool, a.arguments.to_string());
        }
        let text = projected.to_string();
        for banned in ["_utc", "_at\"", "_message", "error", "provenance", "recent_imports", "conventions"] {
            assert!(!text.contains(banned), "{} {} carries `{banned}`", a.store, a.tool);
        }
        assert!(!has_clock_time(&text), "{} {} carries a time of day", a.store, a.tool);
        // The `device` block of an answer is dropped; `device` as a source scope value or a per-scope key stays.
        assert!(projected.get("device").is_none(), "{} {}", a.store, a.tool);
        assert!(projected.get("time").is_none() && projected.get("missing_values").is_none());
        checked += 1;
    }
    assert!(checked >= 250, "{checked} projected answers");
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn the_contract_answer_is_never_sent() {
    let all = all_answers();
    let contracts: Vec<_> = all.iter().filter(|a| a.tool == "get_contract").collect();
    assert!(!contracts.is_empty());
    for a in contracts {
        assert_eq!(project("get_contract", &a.result), Err(ViewError::NotSent));
    }
    assert_eq!(project("no_such_tool", &json!({})), Err(ViewError::UnknownTool));
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn every_projection_fits_its_budget_and_the_numbers_are_recorded() {
    let all = all_answers();
    // tool -> (max raw, max projected, max fitted) over every call / over the calls the coach would make
    let mut every: BTreeMap<&str, [usize; 3]> = BTreeMap::new();
    let mut coach: BTreeMap<&str, [usize; 3]> = BTreeMap::new();
    let mut shrunk = 0;
    let mut cuts: BTreeMap<(String, bool, String), usize> = BTreeMap::new();
    let mut too_large = Vec::new();
    for a in sendable(&all) {
        let projected = project(&a.tool, &a.result).expect("projects");
        let raw = json_len(&a.result);
        let size = json_len(&projected);
        let cap = caps::budget(&a.tool).expect("a budget").max_bytes;
        let fitted = match fit(&a.tool, &projected) {
            Ok(v) => {
                assert!(json_len(&v) <= cap, "{} {}: {} > {cap}", a.store, a.tool, json_len(&v));
                assert!(validate(&a.tool, &v).is_ok(), "{} {}: a shrunken answer still validates", a.store, a.tool);
                if v != projected {
                    shrunk += 1;
                    let cut = (a.tool.clone(), within_coach_limits(a), v.get("omitted").map(Value::to_string).unwrap_or_default());
                    *cuts.entry(cut).or_insert(0) += 1;
                }
                json_len(&v)
            }
            Err(CapError::StillTooLarge) => {
                too_large.push((a.store, a.tool.clone(), a.arguments.to_string(), size));
                0
            }
            Err(e) => panic!("{e}"),
        };
        let tool = SENDABLE.iter().find(|t| **t == a.tool).copied().expect("sendable");
        for (map, take) in [(&mut every, true), (&mut coach, within_coach_limits(a))] {
            if take {
                let row = map.entry(tool).or_insert([0; 3]);
                row[0] = row[0].max(raw);
                row[1] = row[1].max(size);
                row[2] = row[2].max(fitted);
            }
        }
    }
    println!("max bytes: raw -> projected -> after fit (every call | calls inside the coach limits)");
    for tool in SENDABLE {
        let (e, c) = (every.get(tool).copied().unwrap_or_default(), coach.get(tool).copied().unwrap_or_default());
        println!("{tool:20} {:>7} -> {:>6} -> {:>6} | {:>7} -> {:>6} -> {:>6}", e[0], e[1], e[2], c[0], c[1], c[2]);
    }
    println!("answers shrunk by fit: {shrunk}; still too large: {}", too_large.len());
    for ((tool, in_limits, omitted), n) in &cuts {
        println!("  shrunk x{n}: {tool} (coach limits: {in_limits}) omitted={omitted}");
    }
    for (store, tool, args, size) in &too_large {
        println!("  too large: {store} {tool} {args} ({size} bytes projected)");
    }
    for (store, tool, args, size) in &too_large {
        assert!(
            !within_coach_limits(&Answer { store, tool: tool.clone(), arguments: serde_json::from_str(args).expect("json"), result: Value::Null }),
            "{store} {tool} {args} is a call the coach would make and it does not fit ({size} bytes)"
        );
    }
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn a_raw_answer_is_refused_by_the_schema() {
    let all = all_answers();
    let mut refused = 0;
    for a in sendable(&all) {
        // Un-projected answers carry keys the schema does not list (time, missing_values, sources, ...).
        if validate(&a.tool, &a.result).is_err() {
            refused += 1;
        }
    }
    assert_eq!(refused, sendable(&all).len(), "no raw answer passes the positive schema");
    let activities = all.iter().find(|a| a.tool == "list_activities" && !a.result["activities"].as_array().is_none_or(Vec::is_empty)).expect("an activity");
    assert!(activities.result["activities"][0].get("start_utc").is_some());
    assert_eq!(validate("list_activities", &activities.result).expect_err("raw").reason, Reason::UnknownKey);
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn an_injected_timestamp_free_text_key_or_datetime_date_fails_validation() {
    let all = all_answers();
    let activities = all
        .iter()
        .find(|a| a.tool == "list_activities" && !a.result["activities"].as_array().is_none_or(Vec::is_empty))
        .expect("an activity");
    let good = project("list_activities", &activities.result).expect("projects");
    assert!(validate("list_activities", &good).is_ok());

    let mut with_start = good.clone();
    with_start["activities"][0]["start_utc"] = json!("2025-06-14T20:00:00Z");
    assert_eq!(validate("list_activities", &with_start).expect_err("start_utc").reason, Reason::UnknownKey);

    let mut with_text = good.clone();
    with_text["activities"][0]["coach_note"] = json!("slept badly, call mum");
    assert_eq!(validate("list_activities", &with_text).expect_err("text key").reason, Reason::UnknownKey);

    let mut with_datetime = good.clone();
    with_datetime["activities"][0]["date"] = json!("2025-06-14T20:00:00Z");
    assert_eq!(validate("list_activities", &with_datetime).expect_err("datetime").reason, Reason::NotADate);

    let mut with_sentence = good;
    with_sentence["activities"][0]["sport"] = json!("went out after dinner");
    let err = validate("list_activities", &with_sentence).expect_err("sentence");
    assert_eq!(err.reason, Reason::NotInVocabulary);
    assert!(!err.to_string().contains("dinner"));
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn sleep_sessions_keep_order_and_minutes_and_lose_every_clock() {
    let all = all_answers();
    let with_stages = all
        .iter()
        .find(|a| a.tool == "get_sleep_detail" && a.result["sessions"].as_array().is_some_and(|s| s.iter().any(|x| x.get("stages").is_some())))
        .expect("a night with stages");
    let view = project("get_sleep_detail", &with_stages.result).expect("projects");
    for (raw, kept) in with_stages.result["sessions"].as_array().expect("s").iter().zip(view["sessions"].as_array().expect("s")) {
        let raw_stages = raw["stages"].as_array().cloned().unwrap_or_default();
        let kept_stages = kept["stages"].as_array().cloned().unwrap_or_default();
        assert_eq!(raw_stages.len(), kept_stages.len());
        for (r, k) in raw_stages.iter().zip(&kept_stages) {
            assert_eq!(r["stage"], k["stage"]);
            assert_eq!(r["minutes"], k["minutes"]);
            assert_eq!(k.as_object().map(|o| o.len()), Some(2));
        }
        assert!(kept["minutes"].is_number(), "the session length is kept");
        assert_eq!(kept["date"], raw["date"]);
    }
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn health_keeps_days_and_counts_and_drops_the_import_log() {
    let all = all_answers();
    let health = all.iter().find(|a| a.tool == "get_data_health" && a.store == "synthetic").expect("health");
    let view = project("get_data_health", &health.result).expect("projects");
    for dropped in ["recent_imports", "provenance", "conventions", "time"] {
        assert!(view.get(dropped).is_none(), "{dropped}");
    }
    assert!(view["streams"].as_array().is_some_and(|s| !s.is_empty()));
    for stream in view["streams"].as_array().expect("streams") {
        assert_eq!(stream["first"].as_str().map(str::len), Some(10));
        assert_eq!(stream["last"].as_str().map(str::len), Some(10));
    }
    assert!(view["coverage"]["ledger"].as_array().is_some_and(|l| !l.is_empty()));
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn facts_default_to_no_points_and_the_toggle_brings_them_back() {
    let all = all_answers();
    let points = all
        .iter()
        .find(|a| a.tool == "get_period_facts" && a.arguments.get("include_points") == Some(&json!(true)) && a.result["facts"].as_array().is_some_and(|f| f.iter().any(|x| x["evidence"].get("window_points").is_some())))
        .expect("facts with points");
    let default = project("get_period_facts", &points.result).expect("projects");
    assert!(!default.to_string().contains("window_points"));
    let toggled = project_with("get_period_facts", &points.result, &ViewOptions { include_points: true }).expect("projects");
    assert!(toggled.to_string().contains("window_points"));
    assert!(validate("get_period_facts", &toggled).is_ok());
    assert!(json_len(&toggled) > json_len(&default));
}

#[test]
#[cfg_attr(not(monorepo), ignore = "needs the Python oracle's committed synthetic stores and transcripts (projects/disconect/tests/fixtures/serve), which are developed in the monorepo and are not in this repository")]
fn clamped_arguments_never_exceed_the_coach_limits_for_any_fixture_request() {
    let all = all_answers();
    for a in &all {
        let clamped = clamp(&a.tool, &a.arguments);
        assert!(clamped.is_object());
        match a.tool.as_str() {
            "get_data_health" => assert!(clamped["window_days"].as_i64().is_some_and(|d| (1..=30).contains(&d))),
            "get_metric_series" => assert!(clamped["days"].as_i64().is_some_and(|d| (1..=90).contains(&d))),
            "list_activities" => assert!(clamped["limit"].as_i64().is_some_and(|d| (1..=20).contains(&d))),
            "get_period_facts" => assert_eq!(clamped["include_points"], json!(false)),
            _ => {}
        }
    }
}
