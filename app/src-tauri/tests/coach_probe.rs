// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 15 slice 6: the endpoint probe against the scripted provider. Verdicts for tools (yes / no / unknown)
//! and context (ok / too small / unknown), a 401, an unreachable endpoint, and the capture checks on the
//! bodies the probe sends: no store data can be in them (the probe has no core), round 1 is the system prompt
//! and the fixed question, and in round 2 the synthetic filler is the only user content.

use disconect_app_lib::coach::egress::{EgressError, Fake, Inbound, MAX_REQUEST_BODY};
use disconect_app_lib::coach::probe::{
    filler, min_reported_tokens, probe, ContextVerdict, ProbeReport, ToolsSupport, FILLER_BYTES, PROBE_QUESTION,
};
use disconect_app_lib::coach::prompt::system_prompt;
use disconect_app_lib::coach::settings::{Mode, Settings};
use disconect_app_lib::coach::wire::tool_specs;
use serde_json::{json, Value};
use zeroize::Zeroizing;

mod common;
use common::fake_provider::{scripted, Scripted, Step};

const MODEL: &str = "test-model";

fn local() -> Settings {
    Settings { mode: Mode::Local, base_url: "http://127.0.0.1:11434/v1".into(), model: MODEL.into(), ..Settings::default() }
}

/// A 200 chat completion with a text answer and (optionally) a `usage.prompt_tokens` of the test's choosing.
fn completion(prompt_tokens: Option<u64>) -> Result<Inbound, EgressError> {
    let mut body = json!({"choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "length"}]});
    if let Some(tokens) = prompt_tokens {
        body["usage"] = json!({"prompt_tokens": tokens, "completion_tokens": 1, "total_tokens": tokens + 1});
    }
    Ok(Inbound { status: 200, body: body.to_string().into_bytes() })
}

fn tool_reply(name: &str) -> Result<Inbound, EgressError> {
    let call = json!({"id": "call_1", "type": "function", "function": {"name": name, "arguments": "{\"metrics\":[\"steps\"],\"days\":7}"}});
    let body = json!({"choices": [{"index": 0, "message": {"role": "assistant", "content": null, "tool_calls": [call]}, "finish_reason": "tool_calls"}]});
    Ok(Inbound { status: 200, body: body.to_string().into_bytes() })
}

fn fake_with(answers: Vec<Result<Inbound, EgressError>>) -> Fake {
    let fake = Fake::new();
    answers.into_iter().for_each(|a| fake.push(a));
    fake
}

fn bodies(fake: &Fake) -> Vec<Value> {
    fake.sent.lock().expect("lock").iter().map(|s| serde_json::from_slice(&s.body).expect("JSON body")).collect()
}

/// The capture checks over what the probe sent. `rounds` is how many requests are expected.
fn assert_capture(requests: &[Value], rounds: usize) {
    assert_eq!(requests.len(), rounds);
    let system = json!({"role": "system", "content": system_prompt()});
    for (index, body) in requests.iter().enumerate() {
        let text = body.to_string();
        // nothing from a store: the seeded fragments of the privacy lists, and no sub-day or id keys
        for needle in ["3489012345", "/Users/", "/tmp/", "@example.com", "_utc", "device_id", "serial", "payload"] {
            assert!(!text.contains(needle), "{needle:?} in a probe body");
        }
        assert_eq!(body["model"], MODEL);
        assert_eq!(body["stream"], false);
        let messages = body["messages"].as_array().expect("messages");
        assert_eq!(messages.len(), 2, "the system prompt and one user message");
        assert_eq!(messages[0], system, "the first message is exactly the system prompt");
        let users: Vec<&Value> = messages.iter().filter(|m| m["role"] == "user").collect();
        assert_eq!(users.len(), 1);
        let mut keys: Vec<&str> = body.as_object().expect("object").keys().map(String::as_str).collect();
        keys.sort_unstable();
        if index == 0 {
            assert_eq!(keys, ["messages", "model", "stream", "tool_choice", "tools"]);
            assert_eq!(users[0]["content"], PROBE_QUESTION);
            assert_eq!(body["tools"], serde_json::to_value(tool_specs()).expect("specs"));
        } else {
            assert_eq!(keys, ["max_tokens", "messages", "model", "stream"], "no tools in the context round");
            assert_eq!(body["max_tokens"], 1);
            assert_eq!(users[0]["content"], filler().as_str(), "the filler is the only user content");
            assert_eq!(users[0]["content"].as_str().map(str::len), Some(FILLER_BYTES));
        }
    }
}

fn run_scripted(steps: Vec<Step>) -> (ProbeReport, Scripted) {
    let provider = scripted(steps);
    let report = probe(&provider, &local(), None);
    (report, provider)
}

#[test]
fn tools_yes_and_context_ok() {
    let (report, provider) = run_scripted(vec![Step::call("get_metric_series", "{\"metrics\":[\"steps\"],\"days\":7}"), Step::text("ok")]);
    assert_eq!((report.reachable, report.tools, report.context), (true, ToolsSupport::Yes, ContextVerdict::Ok));
    assert_eq!((report.status, report.error), (None, None));
    assert!(report.measured_prompt_tokens.expect("usage") >= min_reported_tokens());
    assert_capture(&provider.requests(), 2);
}

#[test]
fn tools_no_when_the_model_answers_in_text_only() {
    let (report, provider) = run_scripted(vec![Step::text("You walked a lot."), Step::text("ok")]);
    assert_eq!((report.reachable, report.tools, report.context, report.error), (true, ToolsSupport::No, ContextVerdict::Ok, None));
    assert_capture(&provider.requests(), 2);
}

#[test]
fn a_call_to_a_tool_that_was_not_offered_is_no() {
    let fake = fake_with(vec![tool_reply("get_contract"), completion(Some(13_000))]);
    let report = probe(&fake, &local(), None);
    assert_eq!(report.tools, ToolsSupport::No);
}

#[test]
fn tools_unknown_when_the_answer_cannot_be_read() {
    let (report, provider) = run_scripted(vec![Step::Garbage, Step::text("ok")]);
    assert_eq!((report.reachable, report.tools, report.error), (true, ToolsSupport::Unknown, Some("not_json")));
    assert_eq!(report.context, ContextVerdict::Ok, "round 2 still runs");
    assert_capture(&provider.requests(), 2);
}

#[test]
fn context_too_small_when_the_server_reports_a_cut_prompt() {
    // a 4k default: the server read 4096 tokens of a 12 000-token filler
    let fake = fake_with(vec![tool_reply("get_metric_series"), completion(Some(4096))]);
    let report = probe(&fake, &local(), None);
    assert_eq!((report.tools, report.context, report.measured_prompt_tokens), (ToolsSupport::Yes, ContextVerdict::TooSmall, Some(4096)));
    assert_eq!(report.error, None);
    assert_capture(&bodies(&fake), 2);
    // the threshold is a floor, not a guess: one token under is too small, exactly at it is ok
    let under = probe(&fake_with(vec![completion(None), completion(Some(min_reported_tokens() - 1))]), &local(), None);
    let at = probe(&fake_with(vec![completion(None), completion(Some(min_reported_tokens()))]), &local(), None);
    assert_eq!((under.context, at.context), (ContextVerdict::TooSmall, ContextVerdict::Ok));
}

#[test]
fn context_unknown_when_usage_is_absent() {
    let fake = fake_with(vec![tool_reply("get_metric_series"), completion(None)]);
    let report = probe(&fake, &local(), None);
    assert_eq!((report.tools, report.context, report.measured_prompt_tokens), (ToolsSupport::Yes, ContextVerdict::Unknown, None));
    assert!(report.reachable);
}

#[test]
fn a_401_is_reachable_and_unauthorised_and_nothing_else_is_tried() {
    let (report, provider) = run_scripted(vec![Step::Status(401)]);
    assert_eq!(
        report,
        ProbeReport {
            reachable: true,
            tools: ToolsSupport::Unknown,
            context: ContextVerdict::Unknown,
            measured_prompt_tokens: None,
            status: Some(401),
            error: Some("unauthorised")
        }
    );
    assert_capture(&provider.requests(), 1);
    let (forbidden, _) = run_scripted(vec![Step::Status(403)]);
    assert_eq!((forbidden.reachable, forbidden.error), (true, Some("unauthorised")));
}

#[test]
fn another_error_status_is_reachable_with_the_number_only() {
    let (report, provider) = run_scripted(vec![Step::Status(500), Step::Status(500)]);
    assert_eq!((report.reachable, report.error, report.status), (true, Some("status"), Some(500)));
    assert_eq!((report.tools, report.context), (ToolsSupport::Unknown, ContextVerdict::Unknown));
    assert_eq!(provider.count(), 2);
}

#[test]
fn an_unreachable_endpoint_is_not_reachable_and_stops_after_one_request() {
    let (report, provider) = run_scripted(vec![]);
    assert_eq!(
        report,
        ProbeReport {
            reachable: false,
            tools: ToolsSupport::Unknown,
            context: ContextVerdict::Unknown,
            measured_prompt_tokens: None,
            status: None,
            error: Some("unreachable")
        }
    );
    assert_eq!(provider.count(), 1);
}

#[test]
fn off_sends_nothing_and_the_key_never_enters_a_body() {
    let fake = Fake::new();
    let off = probe(&fake, &Settings::default(), None);
    assert_eq!((off.reachable, off.error, fake.count()), (false, Some("off"), 0));

    let fake = fake_with(vec![tool_reply("get_period_facts"), completion(Some(13_000))]);
    let key = Zeroizing::new("sk-test-probe-key-0001".to_string());
    let cloud = Settings { mode: Mode::Cloud, base_url: "https://api.example/v1".into(), model: MODEL.into(), ..Settings::default() };
    let report = probe(&fake, &cloud, Some(&key));
    assert_eq!((report.tools, report.context), (ToolsSupport::Yes, ContextVerdict::Ok));
    let sent = fake.sent.lock().expect("lock");
    assert_eq!(sent.len(), 2);
    for request in sent.iter() {
        assert!(request.header_names.contains(&"authorization"));
        assert!(request.body.len() < MAX_REQUEST_BODY);
        assert!(!String::from_utf8_lossy(&request.body).contains("sk-test-probe-key-0001"));
    }
}

#[test]
fn the_probe_report_serialises_to_closed_words() {
    let (report, _) = run_scripted(vec![Step::text("x"), Step::text("y")]);
    let value = serde_json::to_value(&report).expect("serialises");
    assert_eq!(value["tools"], "no");
    assert_eq!(value["context"], "ok");
    let mut keys: Vec<&str> = value.as_object().expect("object").keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["context", "error", "measured_prompt_tokens", "reachable", "status", "tools"]);
}
