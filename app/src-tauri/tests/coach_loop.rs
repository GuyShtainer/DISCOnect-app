// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bet 15 slice 5: the coach loop end to end, with a scripted provider and the serve oracle's `tools.call`
//! answers as the tool runner. Five evals (coverage gap, insufficient baseline, label-only metric, locked
//! store, provider error), the unknown-tool and bad-argument paths, the window manager over ten questions,
//! the off-mode and key order, and the capture: for every request body the provider received, the bytes are
//! the system prompt, the user's words, the model's own earlier turns, the five tool specs and tool messages
//! that are the projected, fitted, validated answers (recomputed here from the oracle) or fixed strings. One
//! scenario is then replayed through the real egress against a `127.0.0.1` listener and the bytes read off the
//! socket pass the same checks. Nothing here opens a store or a home folder.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use disconect_app_lib::coach::caps::{clamp, fit};
use disconect_app_lib::coach::chat_loop::{ask_configured, Coach, CoachError, Conversation, Outcome, ToolCallError, MAX_ROUNDS};
use disconect_app_lib::coach::egress::{Egress, EgressError, Endpoint, Inbound, Outbound, Real};
use disconect_app_lib::coach::prompt::system_prompt;
use disconect_app_lib::coach::schema::validate;
use disconect_app_lib::coach::settings::{Mode, Settings};
use disconect_app_lib::coach::views::project;
use disconect_app_lib::coach::wire::{tool_specs, WireError, OMITTED_CONTENT};
use disconect_core::identity::{neutral_text, MANUFACTURER_PATTERN};
use serde_json::{json, Value};
use zeroize::Zeroizing;

mod common;
use common::fake_provider::{scripted, Scripted, Step};
use common::fixtures::{answers, has_clock_time, within_coach_limits, Answer, SENDABLE};
use common::socket::Server;

// ---- the oracle as a tool runner ----------------------------------------------------------------

struct Oracle {
    answers: Vec<Answer>,
}

/// The oracle script never asks for a label metric, so no recorded answer carries a label series. This one is
/// built from a recorded answer: the envelope of `{"metrics": ["steps"], "days": 5}` with the series replaced
/// by the shape `queries.py::_labels_in_window` returns (`metric`, `from`, `to`, `points` of `date`, `label`,
/// `source_scope`), plus one free-text label the projection must drop.
fn label_answer(recorded: &[Answer]) -> Answer {
    let base = recorded
        .iter()
        .find(|a| a.tool == "get_metric_series" && a.arguments == json!({"metrics": ["steps"], "days": 5}))
        .expect("a recorded five-day series");
    let mut result = base.result.clone();
    result["series"] = json!([]);
    result["labels"] = json!([{
        "metric": "hrv_status", "from": "2025-06-03", "to": "2025-07-02",
        "points": [
            {"date": "2025-06-29", "label": "balanced", "source_scope": "vendor_cloud"},
            {"date": "2025-06-30", "label": "unbalanced", "source_scope": "vendor_cloud"},
            {"date": "2025-07-01", "label": "call me at 555-0100", "source_scope": "vendor_cloud"},
        ]
    }]);
    Answer { store: "synthetic", tool: "get_metric_series".into(), arguments: json!({"metrics": ["hrv_status"], "days": 30}), result }
}

fn oracle() -> &'static Oracle {
    static ORACLE: OnceLock<Oracle> = OnceLock::new();
    ORACLE.get_or_init(|| {
        let mut list: Vec<Answer> = answers("synthetic")
            .into_iter()
            .filter(|a| SENDABLE.contains(&a.tool.as_str()) && !a.arguments.to_string().contains('$') && within_coach_limits(a))
            .collect();
        let labels = label_answer(&list);
        list.push(labels);
        Oracle { answers: list }
    })
}

impl Oracle {
    /// The recorded answer whose request is `(name, args)` once both sides are clamped.
    fn lookup(&self, name: &str, args: &Value) -> Option<&Answer> {
        self.answers.iter().find(|a| a.tool == name && clamp(name, &a.arguments) == *args)
    }

    /// What the model must receive for this call, computed from the recorded answer alone: the compact JSON of
    /// the fitted projection.
    fn expected(&self, name: &str, arguments_json: &str) -> String {
        let args = clamp(name, &serde_json::from_str::<Value>(arguments_json).expect("test arguments are JSON"));
        let answer = self.lookup(name, &args).unwrap_or_else(|| panic!("no recorded answer for {name} {args}"));
        let projected = project(name, &answer.result).expect("projects");
        fit(name, &projected).expect("fits").to_string()
    }
}

enum Source {
    Oracle,
    /// Every call fails the way a locked store does.
    Locked,
}

struct Runner {
    mode: Source,
    log: Mutex<Vec<(String, Value)>>,
}

impl Runner {
    fn oracle() -> Runner {
        Runner { mode: Source::Oracle, log: Mutex::new(Vec::new()) }
    }

    fn locked() -> Runner {
        Runner { mode: Source::Locked, log: Mutex::new(Vec::new()) }
    }

    fn calls(&self) -> Vec<(String, Value)> {
        self.log.lock().expect("lock").clone()
    }

    fn call(&self, name: &str, arguments: Value) -> Result<Value, ToolCallError> {
        self.log.lock().expect("lock").push((name.to_string(), arguments.clone()));
        match self.mode {
            Source::Locked => Err(ToolCallError { code: "locked".into() }),
            Source::Oracle => match oracle().lookup(name, &arguments) {
                Some(a) => Ok(json!({"name": name, "result": a.result})),
                None => Err(ToolCallError { code: "tool_error".into() }),
            },
        }
    }
}

// ---- settings and one question ------------------------------------------------------------------

const MODEL: &str = "test-model";
const BASE: &str = "http://127.0.0.1:11434/v1";

fn local() -> Settings {
    Settings { mode: Mode::Local, base_url: BASE.into(), model: MODEL.into(), ..Settings::default() }
}

fn ask(provider: &dyn Egress, runner: &Runner, conv: &mut Conversation, settings: &Settings, text: &str) -> Result<String, CoachError> {
    let call = |name: &str, args: Value| runner.call(name, args);
    Coach::new(provider, &call, settings, None).ask(conv, text)
}

/// The vendor's name, spelled from the scrub's own pattern so this file never writes it.
fn vendor() -> &'static str {
    &MANUFACTURER_PATTERN[..6]
}

/// A scripted answer that names the vendor (the loop must scrub it) and its expected scrubbed form.
fn with_vendor(text: &str) -> (String, String) {
    let raw = format!("{text} (as shown by {} Connect)", vendor());
    let scrubbed = neutral_text(&raw);
    assert!(scrubbed.contains("{vendor}") && !scrubbed.to_lowercase().contains(vendor()));
    (raw, scrubbed)
}

// ---- dates --------------------------------------------------------------------------------------

/// Days since 1970-01-01 of a `YYYY-MM-DD` day (the civil-calendar algorithm), and back.
fn day_number(date: &str) -> i64 {
    let part = |range: std::ops::Range<usize>| date[range].parse::<i64>().expect("digits");
    let (y, m, d) = (part(0..4), part(5..7), part(8..10));
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn day_text(number: i64) -> String {
    let z = number + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

// ---- the capture --------------------------------------------------------------------------------

const FORBIDDEN_KEYS: [&str; 17] = [
    "device_id", "serial", "serial_number", "path", "email", "raw_record_id", "sleep_id", "payload", "payload_hash",
    "source_key", "user_profile", "userProfilePK", "uuid", "position_lat", "position_long", "latitude", "longitude",
];
/// `FORBIDDEN_TEXT` of `projects/disconect/tests/test_privacy.py`: the seeded serial and path-like fragments.
const FORBIDDEN_TEXT: [&str; 4] = ["3489012345", "/Users/", "/tmp/", "@example.com"];
const BANNED_IN_BODY: [&str; 5] = ["_utc", "_at", "_message", "provenance", "recent_imports"];
const FIXED_TOOL_CONTENTS: [&str; 9] = [
    r#"{"error":"unknown tool"}"#,
    r#"{"error":"bad arguments"}"#,
    r#"{"error":"withheld"}"#,
    r#"{"error":"locked"}"#,
    r#"{"error":"tool_error"}"#,
    r#"{"error":"invalid_params"}"#,
    r#"{"error":"unknown_tool"}"#,
    r#"{"error":"not_configured"}"#,
    OMITTED_CONTENT,
];
const FIVE: [&str; 5] = ["get_data_health", "get_metric_series", "get_sleep_detail", "list_activities", "get_period_facts"];

/// What a request may carry besides the system prompt and the tool specs.
struct Allowed {
    users: Vec<String>,
    /// The model's own scrubbed texts, as the loop hands them back.
    assistants: Vec<String>,
    /// The argument texts the scripted model sent.
    call_arguments: Vec<String>,
    /// The projected, fitted answers, recomputed from the oracle.
    tool_contents: Vec<String>,
}

impl Allowed {
    fn new(steps: &[Step], users: &[&str], tool_contents: Vec<String>) -> Allowed {
        let mut assistants = Vec::new();
        let mut call_arguments = Vec::new();
        for step in steps {
            match step {
                Step::Text(text) => assistants.push(neutral_text(text)),
                Step::ToolCall { arguments_json, .. } => call_arguments.push(arguments_json.clone()),
                Step::ToolCalls(calls) => call_arguments.extend(calls.iter().map(|(_, a)| a.clone())),
                Step::Status(_) | Step::Garbage => {}
            }
        }
        Allowed { users: users.iter().map(|u| u.to_string()).collect(), assistants, call_arguments, tool_contents }
    }
}

/// Every key (and its path) and every string of a JSON tree, checked against the privacy lists.
fn privacy_walk(node: &Value, path: &str) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                assert!(!FORBIDDEN_KEYS.contains(&key.as_str()), "forbidden key {key:?} at {path}");
                privacy_walk(value, &format!("{path}.{key}"));
            }
        }
        Value::Array(items) => items.iter().enumerate().for_each(|(i, item)| privacy_walk(item, &format!("{path}[{i}]"))),
        Value::String(text) => {
            for needle in FORBIDDEN_TEXT {
                assert!(!text.contains(needle), "{needle:?} at {path}");
            }
        }
        _ => {}
    }
}

/// Every assistant tool call is followed by exactly its tool messages, and every tool message follows a call.
fn assert_pairing(messages: &[Value]) {
    let mut at = 0;
    while at < messages.len() {
        let message = &messages[at];
        match message["role"].as_str().expect("a role") {
            "assistant" if message.get("tool_calls").is_some() => {
                let calls = message["tool_calls"].as_array().expect("calls");
                for (offset, call) in calls.iter().enumerate() {
                    let next = &messages[at + 1 + offset];
                    assert_eq!(next["role"], "tool", "a tool call without its answer");
                    assert_eq!(next["tool_call_id"], call["id"]);
                }
                at += 1 + calls.len();
            }
            "tool" => panic!("a tool message without the call it answers"),
            _ => at += 1,
        }
    }
}

/// The capture assertions of the pitch over request bodies as bytes. Returns how many bodies were checked.
fn assert_capture(bodies: &[Vec<u8>], allowed: &Allowed) -> usize {
    let system = system_prompt();
    let specs = serde_json::to_value(tool_specs()).expect("specs serialise");
    for raw in bodies {
        let body: Value = serde_json::from_slice(raw).expect("a request body is JSON");
        let mut keys: Vec<&str> = body.as_object().expect("an object").keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["messages", "model", "stream", "tool_choice", "tools"], "no other field leaves");
        assert_eq!((body["model"].as_str(), body["tool_choice"].as_str(), body["stream"].as_bool()), (Some(MODEL), Some("auto"), Some(false)));
        assert_eq!(body["tools"], specs, "the tools are the five specs");
        let names: Vec<&str> = body["tools"].as_array().expect("tools").iter().filter_map(|t| t["function"]["name"].as_str()).collect();
        assert_eq!(names, FIVE);

        let messages = body["messages"].as_array().expect("messages");
        assert_eq!(messages[0], json!({"role": "system", "content": system}), "the first message is exactly the system prompt");
        assert_pairing(messages);
        let mut tool_names: BTreeMap<String, String> = BTreeMap::new();
        for message in &messages[1..] {
            match message["role"].as_str().expect("role") {
                "user" => {
                    let text = message["content"].as_str().expect("text");
                    assert!(allowed.users.iter().any(|u| u == text), "a user message that is not the user's words: {text}");
                }
                "assistant" => {
                    if let Some(text) = message.get("content") {
                        let text = text.as_str().expect("text");
                        assert!(allowed.assistants.iter().any(|a| a == text), "assistant text the model did not say (scrubbed): {text}");
                    }
                    for call in message.get("tool_calls").and_then(Value::as_array).into_iter().flatten() {
                        assert_eq!(call["type"], "function");
                        let arguments = call["function"]["arguments"].as_str().expect("arguments text");
                        assert!(allowed.call_arguments.iter().any(|a| a == arguments), "{arguments}");
                        tool_names.insert(call["id"].as_str().expect("id").to_string(), call["function"]["name"].as_str().expect("name").to_string());
                    }
                }
                "tool" => {
                    let content = message["content"].as_str().expect("content");
                    let fixed = FIXED_TOOL_CONTENTS.contains(&content);
                    assert!(fixed || allowed.tool_contents.iter().any(|c| c == content), "a tool message that is neither a projected answer nor a fixed string");
                    if !fixed {
                        let parsed: Value = serde_json::from_str(content).expect("tool content is JSON");
                        let name = &tool_names[message["tool_call_id"].as_str().expect("id")];
                        validate(name, &parsed).expect("every tool message passes the positive schema");
                        privacy_walk(&parsed, "tool");
                    }
                }
                other => panic!("role {other}"),
            }
        }
        // the whole body, but for the tool specs (their prose is `mcp.json`'s and is asserted equal above)
        let mut without_tools = body.clone();
        without_tools.as_object_mut().expect("object").remove("tools");
        let text = without_tools.to_string();
        for banned in BANNED_IN_BODY {
            assert!(!text.contains(banned), "the body carries `{banned}`");
        }
        assert!(!has_clock_time(&text), "a time of day in a request");
        assert!(!text.to_lowercase().contains(vendor()), "the vendor's name in a request");
        privacy_walk(&body, "body");
    }
    bodies.len()
}

fn tally(scenario: &str, checked: usize) {
    println!("capture {scenario}: {checked} bodies checked, violations 0");
}

fn assert_pairing_in_turns(conv: &Conversation) {
    let value = serde_json::to_value(conv.turns()).expect("turns serialise");
    assert_pairing(value.as_array().expect("array"));
}

// ---- the five evals -----------------------------------------------------------------------------

#[test]
fn eval_1_a_coverage_gap_reaches_the_model_projected_and_the_answer_cites_its_dates() {
    let args = r#"{"metrics":["steps"]}"#;
    let expected = oracle().expected("get_metric_series", args);
    let view: Value = serde_json::from_str(&expected).expect("json");
    let local_series = view["series"].as_array().expect("series").iter().find(|s| s["source_scope"] == "local").expect("local scope");
    let dates: Vec<&str> = local_series["points"].as_array().expect("points").iter().map(|p| p["date"].as_str().expect("date")).collect();
    let (before, after) = dates.windows(2).map(|w| (w[0], w[1])).find(|(a, b)| day_number(b) - day_number(a) > 1).expect("a gap in the series");
    let (gap_from, gap_to) = (day_text(day_number(before) + 1), day_text(day_number(after) - 1));
    assert!(!dates.contains(&gap_from.as_str()));

    let (raw, scrubbed) = with_vendor(&format!("Steps (local scope) have no values from {gap_from} to {gap_to}, so that stretch is insufficient data."));
    let steps = vec![Step::call("get_metric_series", args), Step::text(&raw)];
    let provider = scripted(steps.clone());
    let runner = Runner::oracle();
    let mut conv = Conversation::new();
    let question = "How did my steps look this quarter?";
    let text = ask(&provider, &runner, &mut conv, &local(), question).expect("answers");

    assert_eq!(text, scrubbed, "the answer is the model's text, scrubbed");
    assert!(text.contains(&gap_from) && text.contains(&gap_to));
    assert_eq!((provider.count(), conv.sends), (2, 2));
    assert_eq!(runner.calls(), vec![("get_metric_series".to_string(), json!({"metrics": ["steps"], "days": 90}))], "the arguments were clamped");
    assert_eq!(conv.trace.len(), 1);
    let entry = &conv.trace[0];
    assert_eq!((entry.tool.as_str(), entry.outcome.clone(), entry.bytes_sent), ("get_metric_series", Outcome::Ok, expected.len()));
    assert_eq!(entry.projected, view, "the drawer shows exactly what left");
    let requests = provider.requests();
    assert_eq!(requests[1]["messages"].as_array().expect("m").last().expect("last")["content"], expected.as_str());
    tally("1 coverage gap", assert_capture(&provider.bodies(), &Allowed::new(&steps, &[question], vec![expected])));
    println!("trace 1: get_metric_series bytes_sent={} outcome=ok", entry.bytes_sent);
}

#[test]
fn eval_2_an_insufficient_baseline_passes_projected_and_the_model_says_insufficient_data() {
    let expected = oracle().expected("get_period_facts", "{}");
    let view: Value = serde_json::from_str(&expected).expect("json");
    let facts = view["facts"].as_array().expect("facts");
    assert!(
        facts.iter().any(|f| f["confidence"] == "insufficient" && f["reason_code"] == "baseline_too_thin"),
        "the answer carries a low-confidence reason"
    );
    assert!(!expected.contains("window_points"), "no points unless the toggle is on");

    let (raw, scrubbed) = with_vendor("For several metrics the baseline is too thin: insufficient data to compare them with your earlier days.");
    let steps = vec![Step::call("get_period_facts", "{}"), Step::text(&raw)];
    let provider = scripted(steps.clone());
    let runner = Runner::oracle();
    let mut conv = Conversation::new();
    let question = "Is this week different from my usual?";
    let text = ask(&provider, &runner, &mut conv, &local(), question).expect("answers");
    assert_eq!(text, scrubbed);
    assert!(text.contains("insufficient data"));
    assert_eq!(runner.calls()[0].1, json!({"include_points": false}));
    let entry = &conv.trace[0];
    assert_eq!((entry.tool.as_str(), entry.outcome.clone(), entry.bytes_sent), ("get_period_facts", Outcome::Ok, expected.len()));
    assert!(entry.bytes_sent <= 24 * 1024, "inside the tool's cap");
    tally("2 insufficient baseline", assert_capture(&provider.bodies(), &Allowed::new(&steps, &[question], vec![expected])));
    println!("trace 2: get_period_facts bytes_sent={} outcome=ok", entry.bytes_sent);
}

#[test]
fn eval_3_a_label_metric_sends_its_labels_and_no_values() {
    let args = r#"{"metrics":["hrv_status"],"days":30}"#;
    let expected = oracle().expected("get_metric_series", args);
    let view: Value = serde_json::from_str(&expected).expect("json");
    assert_eq!(view["series"], json!([]), "a label metric has no numeric series");
    let labels = &view["labels"][0];
    assert_eq!(labels["metric"], "hrv_status");
    let points: Vec<(&str, &str)> = labels["points"].as_array().expect("points").iter().map(|p| (p["date"].as_str().expect("d"), p["label"].as_str().expect("l"))).collect();
    assert_eq!(points, [("2025-06-29", "balanced"), ("2025-06-30", "unbalanced")]);
    assert_eq!(labels["dropped"], 1, "the free-text label is counted, not sent");
    assert!(!expected.contains("\"value\"") && !expected.contains("call me") && !expected.contains("555"));

    let (raw, scrubbed) = with_vendor("The status band was balanced on 2025-06-29 and unbalanced on 2025-06-30.");
    let steps = vec![Step::call("get_metric_series", args), Step::text(&raw)];
    let provider = scripted(steps.clone());
    let runner = Runner::oracle();
    let mut conv = Conversation::new();
    let question = "What was my HRV status?";
    let text = ask(&provider, &runner, &mut conv, &local(), question).expect("answers");
    assert_eq!(text, scrubbed);
    let sent = provider.requests()[1]["messages"].as_array().expect("m").last().expect("last")["content"].as_str().expect("c").to_string();
    assert_eq!(sent, expected);
    assert!(!provider.bodies().iter().any(|b| String::from_utf8_lossy(b).contains("call me")));
    assert_eq!(conv.trace[0].outcome, Outcome::Ok);
    tally("3 label-only metric", assert_capture(&provider.bodies(), &Allowed::new(&steps, &[question], vec![expected])));
    println!("trace 3: get_metric_series bytes_sent={} outcome=ok", conv.trace[0].bytes_sent);
}

#[test]
fn eval_4_a_locked_store_tells_the_model_one_word_and_the_turn_goes_on() {
    let (raw, scrubbed) = with_vendor("I cannot read your data right now because the store is locked.");
    let steps = vec![Step::call("get_sleep_detail", "{}"), Step::text(&raw)];
    let provider = scripted(steps.clone());
    let runner = Runner::locked();
    let mut conv = Conversation::new();
    let question = "How did I sleep?";
    let text = ask(&provider, &runner, &mut conv, &local(), question).expect("ask still returns the model's text");
    assert_eq!(text, scrubbed);
    let requests = provider.requests();
    let last = requests[1]["messages"].as_array().expect("m").last().expect("last").clone();
    assert_eq!(last["content"], r#"{"error":"locked"}"#);
    assert_eq!(conv.trace.len(), 1);
    assert_eq!(conv.trace[0].outcome, Outcome::ToolError("locked"));
    assert_eq!(conv.trace[0].projected, json!({"error": "locked"}));
    assert_eq!(conv.trace[0].bytes_sent, r#"{"error":"locked"}"#.len());
    tally("4 locked store", assert_capture(&provider.bodies(), &Allowed::new(&steps, &[question], Vec::new())));
    println!("trace 4: get_sleep_detail bytes_sent={} outcome=tool_error(locked)", conv.trace[0].bytes_sent);
}

#[test]
fn eval_5_provider_errors_are_closed_and_leave_the_conversation_consistent() {
    let runner = Runner::oracle();
    let mut conv = Conversation::new();
    let settings = local();

    // a tool round completes, then the endpoint fails: the half-finished exchange must not stay
    let provider = scripted(vec![Step::call("get_sleep_detail", "{}"), Step::Status(500)]);
    let error = ask(&provider, &runner, &mut conv, &settings, "How did I sleep?").expect_err("500");
    assert_eq!(error, CoachError::Egress(EgressError::Status(500)));
    assert_eq!((error.code(), error.status()), ("status", Some(500)));
    assert!(conv.turns().is_empty(), "no dangling tool call, no orphaned question");
    assert_eq!(conv.trace.len(), 1, "what was sent stays visible");
    assert_eq!(provider.count(), 2);

    let provider = scripted(vec![Step::Garbage]);
    let error = ask(&provider, &runner, &mut conv, &settings, "Again?").expect_err("not json");
    assert_eq!(error, CoachError::Wire(WireError::NotJson));
    assert!(conv.turns().is_empty());
    for shown in [error.message(), error.code()] {
        assert!(!shown.contains("this is not json") && !shown.contains("500") && !shown.contains("127.0.0.1"));
    }
    assert_eq!(CoachError::Egress(EgressError::Status(500)).message(), "the endpoint answered with an error status");

    // a good question afterwards works on a clean conversation
    let steps = vec![Step::call("list_activities", "{}"), Step::text("You ran on two days.")];
    let provider = scripted(steps.clone());
    ask(&provider, &runner, &mut conv, &settings, "What did I do?").expect("answers");
    assert_pairing_in_turns(&conv);
    assert_eq!(conv.turns().len(), 4, "question, tool call, tool answer, answer");
    let expected = oracle().expected("list_activities", "{}");
    tally("5 provider error (recovery question)", assert_capture(&provider.bodies(), &Allowed::new(&steps, &["What did I do?"], vec![expected])));
    println!("trace 5: Status(500) -> egress status 500; Garbage -> wire not_json");
}

// ---- the other paths ----------------------------------------------------------------------------

#[test]
fn an_unknown_tool_name_and_arguments_that_are_not_json_get_fixed_strings_and_never_reach_the_core() {
    let steps = vec![
        Step::ToolCalls(vec![
            ("get_contract".into(), "{}".into()),
            ("delete_everything".into(), "{}".into()),
            ("get_sleep_detail".into(), "{not json".into()),
            ("list_activities".into(), "[1, 2]".into()),
        ]),
        Step::text("I could not read that."),
    ];
    let provider = scripted(steps.clone());
    let runner = Runner::oracle();
    let mut conv = Conversation::new();
    ask(&provider, &runner, &mut conv, &local(), "anything").expect("answers");
    assert!(runner.calls().is_empty(), "none of the four reached the core");
    let request = &provider.requests()[1];
    let contents: Vec<&str> = request["messages"].as_array().expect("m").iter().filter(|m| m["role"] == "tool").map(|m| m["content"].as_str().expect("c")).collect();
    assert_eq!(
        contents,
        [r#"{"error":"unknown tool"}"#, r#"{"error":"unknown tool"}"#, r#"{"error":"bad arguments"}"#, r#"{"error":"bad arguments"}"#]
    );
    let outcomes: Vec<Outcome> = conv.trace.iter().map(|t| t.outcome.clone()).collect();
    assert_eq!(
        outcomes,
        [Outcome::ToolError("unknown tool"), Outcome::ToolError("unknown tool"), Outcome::ToolError("bad arguments"), Outcome::ToolError("bad arguments")]
    );
    tally("unknown tool / bad arguments", assert_capture(&provider.bodies(), &Allowed::new(&steps, &["anything"], Vec::new())));
}

#[test]
fn limits_five_calls_in_a_round_or_a_seventh_round_end_the_turn_and_roll_it_back() {
    let runner = Runner::oracle();
    let settings = local();

    let five: Vec<(String, String)> = (0..5).map(|_| ("get_sleep_detail".to_string(), "{}".to_string())).collect();
    let provider = scripted(vec![Step::ToolCalls(five)]);
    let mut conv = Conversation::new();
    assert_eq!(ask(&provider, &runner, &mut conv, &settings, "q"), Err(CoachError::TooManyToolCalls));
    assert!(conv.turns().is_empty() && runner.calls().is_empty(), "a refused round runs nothing");

    let rounds: Vec<Step> = (0..=MAX_ROUNDS).map(|_| Step::call("get_sleep_detail", "{}")).collect();
    let provider = scripted(rounds);
    let before = runner.calls().len();
    assert_eq!(ask(&provider, &runner, &mut conv, &settings, "q"), Err(CoachError::TooManyToolCalls));
    assert_eq!(provider.count(), MAX_ROUNDS + 1);
    assert_eq!(runner.calls().len() - before, MAX_ROUNDS, "six rounds ran, the seventh was refused");
    assert!(conv.turns().is_empty());
}

#[test]
fn an_answer_from_the_core_the_projection_refuses_is_withheld_not_forwarded() {
    // the core answers something that is not an object: nothing of it may leave
    let runner = |_: &str, _: Value| Ok(json!({"name": "get_sleep_detail", "result": "free text from somewhere"}));
    let provider = scripted(vec![Step::call("get_sleep_detail", "{}"), Step::text("done")]);
    let mut conv = Conversation::new();
    Coach::new(&provider, &runner, &local(), None).ask(&mut conv, "q").expect("answers");
    let request = &provider.requests()[1];
    assert_eq!(request["messages"].as_array().expect("m").last().expect("l")["content"], r#"{"error":"withheld"}"#);
    assert_eq!(conv.trace[0].outcome, Outcome::Rejected("view"));
    assert!(!String::from_utf8_lossy(&provider.bodies()[1]).contains("free text"));

    // a failure code the core invents is reported as tool_error, and its message text is never part of it
    let runner = |_: &str, _: Value| Err(ToolCallError { code: "open_failed: /Users/someone/secret.db".into() });
    let provider = scripted(vec![Step::call("get_sleep_detail", "{}"), Step::text("done")]);
    let mut conv = Conversation::new();
    Coach::new(&provider, &runner, &local(), None).ask(&mut conv, "q").expect("answers");
    assert_eq!(provider.requests()[1]["messages"].as_array().expect("m").last().expect("l")["content"], r#"{"error":"tool_error"}"#);
    assert!(!String::from_utf8_lossy(&provider.bodies()[1]).contains("secret.db"));
}

// ---- the window ---------------------------------------------------------------------------------

#[test]
fn ten_questions_with_three_tool_calls_each_stay_under_the_budget_and_keep_the_pairing() {
    let calls = [("get_sleep_detail", "{}"), ("list_activities", "{}"), ("get_metric_series", r#"{"metrics":["steps"],"days":5}"#)];
    let contents: Vec<String> = calls.iter().map(|(name, args)| oracle().expected(name, args)).collect();
    let users: Vec<String> = (0..10).map(|n| format!("question {n}")).collect();
    let mut steps = Vec::new();
    for n in 0..10 {
        steps.extend(calls.iter().map(|(name, args)| Step::call(name, args)));
        steps.push(Step::text(&format!("answer {n}")));
    }
    let provider = scripted(steps.clone());
    let runner = Runner::oracle();
    let mut conv = Conversation::new();
    let settings = local();
    let budget = 8_500;
    for user in &users {
        let call = |name: &str, args: Value| runner.call(name, args);
        let mut coach = Coach::new(&provider, &call, &settings, None);
        coach.context_bytes = budget;
        coach.ask(&mut conv, user).expect("answers");
        assert_pairing_in_turns(&conv);
    }
    assert_eq!((provider.count(), conv.sends, runner.calls().len()), (40, 40, 30));
    let requests = provider.requests();
    for (i, request) in requests.iter().enumerate() {
        let messages = request["messages"].as_array().expect("m");
        let size = serde_json::to_vec(messages).expect("bytes").len();
        assert!(size <= budget, "request {i}: {size} > {budget}");
        assert_pairing(messages);
    }
    let last = requests[39]["messages"].as_array().expect("m");
    let user_count = last.iter().filter(|m| m["role"] == "user").count();
    let omitted = last.iter().filter(|m| m["content"] == OMITTED_CONTENT).count();
    let full = last.iter().filter(|m| m["role"] == "tool" && m["content"] != OMITTED_CONTENT).count();
    assert!(user_count < 10, "the oldest questions were dropped ({user_count} kept)");
    assert!(omitted > 0 && full == 3, "older tool results are the marker, the current question's three stay (omitted {omitted}, full {full})");
    assert_eq!(last[1]["role"], "user", "the window starts at a question");
    assert_eq!(last.last().expect("l")["content"].as_str(), Some(contents[2].as_str()));
    // without a tight budget nothing is dropped, only the old tool results shrink
    let (provider, runner, mut conv) = (scripted(steps.clone()), Runner::oracle(), Conversation::new());
    for user in &users {
        ask(&provider, &runner, &mut conv, &settings, user).expect("answers");
    }
    let last = provider.requests()[39]["messages"].as_array().expect("m").clone();
    assert_eq!(last.iter().filter(|m| m["role"] == "user").count(), 10);
    tally("window (tight budget)", assert_capture(&provider_bodies_of(&requests), &Allowed::new(&steps, &users.iter().map(String::as_str).collect::<Vec<_>>(), contents.clone())));
    tally("window (default budget)", assert_capture(&provider.bodies(), &Allowed::new(&steps, &users.iter().map(String::as_str).collect::<Vec<_>>(), contents)));
    println!("window: 10 asks x 3 calls, budget {budget}: 40 sends, last request kept {user_count} questions");
}

fn provider_bodies_of(requests: &[Value]) -> Vec<Vec<u8>> {
    requests.iter().map(|r| serde_json::to_vec(r).expect("bytes")).collect()
}

// ---- off mode and the key -----------------------------------------------------------------------

struct Shared(Arc<Scripted>);
impl Egress for Shared {
    fn send(&self, out: Outbound) -> Result<Inbound, EgressError> {
        self.0.send(out)
    }
}

#[test]
fn off_sends_nothing_builds_no_egress_and_never_reads_the_key() {
    let provider = Arc::new(scripted(vec![Step::text("hi")]));
    let runner = Runner::oracle();
    let (built, key_reads) = (Cell::new(0), Cell::new(0));
    let call = |name: &str, args: Value| runner.call(name, args);
    let make = |_: &Settings| -> Option<Box<dyn Egress>> {
        built.set(built.get() + 1);
        Some(Box::new(Shared(provider.clone())))
    };
    let key = || {
        key_reads.set(key_reads.get() + 1);
        Some(Zeroizing::new("sk-test-0123456789".to_string()))
    };
    let mut conv = Conversation::new();

    let off = Settings { mode: Mode::Off, ..local() };
    assert_eq!(ask_configured(&off, make, key, &call, &mut conv, "hello"), Err(CoachError::Off));
    assert_eq!((built.get(), key_reads.get(), provider.count(), provider.fake.count()), (0, 0, 0, 0));
    assert!(conv.turns().is_empty() && conv.sends == 0 && runner.calls().is_empty());

    // a cloud endpoint with no key stops before any send
    let cloud = Settings { mode: Mode::Cloud, base_url: "https://api.example/v1".into(), ..local() };
    let make_none_key = |_: &Settings| -> Option<Box<dyn Egress>> { Some(Box::new(Shared(provider.clone()))) };
    assert_eq!(ask_configured(&cloud, make_none_key, || None, &call, &mut conv, "hello"), Err(CoachError::NoKey));
    assert_eq!(provider.count(), 0);

    // an address the egress rules refuse is an egress error with a fixed message, not a send
    let bad = Settings { mode: Mode::Cloud, base_url: "http://example.com".into(), ..local() };
    let error = ask_configured(&bad, make_none_key, key, &call, &mut conv, "hello").expect_err("refused");
    assert_eq!(error, CoachError::Egress(EgressError::PlainHttpNeedsLocalIp));
    assert_eq!((provider.count(), key_reads.get()), (0, 0));

    // on: the egress is built once, the key read once, one request sent, and the key is a bearer (header only)
    let text = ask_configured(&local(), make, key, &call, &mut conv, "hello").expect("answers");
    assert_eq!(text, "hi");
    assert_eq!((built.get(), key_reads.get(), provider.count()), (1, 1, 1));
    let sent = provider.fake.sent.lock().expect("lock");
    assert!(sent[0].header_names.contains(&"authorization"));
    assert!(!String::from_utf8_lossy(&sent[0].body).contains("sk-test"), "the key is never in the body");
    assert!(sent[0].url.ends_with("/v1/chat/completions"), "{}", sent[0].url);
}

// ---- the real socket ----------------------------------------------------------------------------

#[test]
fn the_real_egress_puts_only_the_capture_on_a_loopback_socket() {
    const KEY: &str = "sk-test-socket-0123456789";
    let args = r#"{"metrics":["steps"]}"#;
    let expected = oracle().expected("get_metric_series", args);
    let steps = vec![Step::call("get_metric_series", args), Step::text("Steps have a gap in the local series: insufficient data there.")];
    let question = "How did my steps look this quarter?";

    // the same conversation through the in-process fake gives the reference bytes
    let reference = scripted(steps.clone());
    let runner = Runner::oracle();
    ask(&reference, &runner, &mut Conversation::new(), &local(), question).expect("fake run");

    let server = Server::start(steps.clone());
    let port = server.port;
    let base = format!("http://127.0.0.1:{port}/v1");
    let settings = Settings { base_url: base.clone(), ..local() };
    let real = Real::new(Endpoint::parse(&base).expect("endpoint"));
    let runner = Runner::oracle();
    let mut conv = Conversation::new();
    let call = |name: &str, args: Value| runner.call(name, args);
    let text = Coach::new(&real, &call, &settings, Some(Zeroizing::new(KEY.to_string()))).ask(&mut conv, question).expect("answers over the socket");
    assert!(text.contains("insufficient data"));
    let (accepts, seen) = server.finish();
    assert_eq!((accepts, seen.len()), (2, 2), "one connection per request, nothing else");

    for wire in &seen {
        assert_eq!(wire.request_line, "POST /v1/chat/completions HTTP/1.1");
        assert_eq!(
            wire.names(),
            ["accept", "authorization", "content-length", "content-type", "host", "user-agent"],
            "exactly the headers slice 4 recorded: {:?}",
            wire.headers
        );
        assert_eq!(wire.header_values("authorization"), vec![format!("Bearer {KEY}").as_str()]);
        assert_eq!(wire.header_values("content-type"), vec!["application/json"]);
        assert_eq!(wire.header_values("content-length"), vec![wire.body.len().to_string().as_str()]);
        assert_eq!(wire.header_values("host"), vec![format!("127.0.0.1:{port}").as_str()]);
        assert!(!String::from_utf8_lossy(&wire.body).contains(KEY), "the key is a header, never in the body");
    }
    let bodies: Vec<Vec<u8>> = seen.iter().map(|w| w.body.clone()).collect();
    assert_eq!(bodies, reference.bodies(), "the bytes on the socket are the bytes the fake recorded");
    let allowed = Allowed::new(&steps, &[question], vec![expected]);
    tally("real socket (scenario 1)", assert_capture(&bodies, &allowed));
    println!("real socket headers: {:?}", seen[0].names());
}
