// SPDX-License-Identifier: AGPL-3.0-or-later
//! The coach loop (Bet 15, slice 5): one user question in, one scrubbed answer out, with the tool calls the
//! model asked for in between. (The module is `chat_loop` in Rust because `loop` is a keyword.)
//!
//! **A turn.** [`Coach::ask`] checks the settings (off sends nothing and touches no key; a cloud endpoint
//! needs a key), pushes the user's words, and then repeats: build the request (the system prompt, the
//! windowed turns, the five tools), send it through the one egress, read the answer. A text answer ends the
//! turn. A tool answer is run: the name must be one of the five, the arguments must be a JSON object, they are
//! forced inside the coach defaults ([`caps::clamp_with`]), the core runs the tool (`call_tool`), and the
//! answer goes through the three gates in order, [`views::project_with`], [`caps::fit`] and
//! [`schema::validated`]. Only the [`schema::Validated`] value, as compact JSON, becomes a tool message
//! ([`wire::ToolMessage::result`]); everything else the model hears about a call is one of a few fixed strings
//! ([`wire::ToolFailure`]). Never the core's message, never a raw answer.
//!
//! **Limits.** At most [`MAX_CALLS_PER_ROUND`] tool calls per answer and [`MAX_ROUNDS`] tool rounds per
//! question, else [`CoachError::TooManyToolCalls`]. A projected answer that cannot be made to fit its byte cap
//! is [`CoachError::ToolTooLarge`] (the loop tells the user; it never sends an over-size answer).
//!
//! **Failure leaves no trace in the conversation.** A turn that ends in an error is rolled back (the user's
//! words, the half-finished tool exchange), so the turns never hold an assistant tool call without its tool
//! message. What was sent stays in [`Conversation::trace`] for the "what the model can see" drawer.
//!
//! **The window** ([`window`]) keeps the request inside a byte budget: tool results from earlier questions
//! become a fixed marker, then the oldest whole exchanges are dropped, never the last two messages.
//!
//! **Nothing is persisted.** The conversation lives in memory for the session; the trace holds only what the
//! user could see in the drawer, and the next question replaces it.

use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroizing;

use disconect_core::identity::neutral_text;

use super::caps::{self, CapError, CoachArgs};
use super::egress::{Egress, EgressError, Endpoint, Outbound};
use super::prompt::system_prompt;
use super::schema::{self, SENDABLE_TOOLS};
use super::settings::{Mode, Settings};
use super::views::{self, ViewOptions};
use super::wire::{self, ChatRequest, Message, ServeCode, ToolCall, ToolFailure, ToolMessage, WireError, CHAT_PATH};

/// Most tool calls the model may make in one answer.
pub const MAX_CALLS_PER_ROUND: usize = 4;
/// Most rounds of tool calls in one question.
pub const MAX_ROUNDS: usize = 6;
/// The default request budget: the serialised system prompt and turns.
pub const DEFAULT_CONTEXT_BYTES: usize = 96 * 1024;
/// A tool name the model made up is shown in the trace, cut to this many characters.
const MAX_TRACE_NAME: usize = 64;

// ---- errors -------------------------------------------------------------------------------------

/// Why a question got no answer. Closed; every message is fixed text (never a key, URL or provider body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoachError {
    /// The coach is switched off: nothing was sent and no key was read.
    Off,
    /// A cloud endpoint is set and there is no key.
    NoKey,
    Egress(EgressError),
    Wire(WireError),
    TooManyToolCalls,
    ToolTooLarge,
    /// The store is locked (for a caller that checks before asking; a locked tool call during a turn is told to
    /// the model as `{"error":"locked"}` and the turn goes on).
    Locked,
}

impl CoachError {
    pub fn code(&self) -> &'static str {
        match self {
            CoachError::Off => "off",
            CoachError::NoKey => "no_key",
            CoachError::Egress(e) => e.code(),
            CoachError::Wire(e) => e.code(),
            CoachError::TooManyToolCalls => "too_many_tool_calls",
            CoachError::ToolTooLarge => "tool_too_large",
            CoachError::Locked => "locked",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            CoachError::Off => "the coach is switched off",
            CoachError::NoKey => "no provider key is stored for this cloud endpoint",
            CoachError::Egress(e) => e.message(),
            CoachError::Wire(e) => e.message(),
            CoachError::TooManyToolCalls => "the model asked for more tool calls than the coach allows",
            CoachError::ToolTooLarge => "a tool answer is too large to send, even after shrinking it",
            CoachError::Locked => "the store is locked",
        }
    }

    /// The HTTP status of an endpoint error status, the only number an error carries.
    pub fn status(&self) -> Option<u16> {
        match self {
            CoachError::Egress(e) => e.status(),
            _ => None,
        }
    }
}

impl From<EgressError> for CoachError {
    fn from(e: EgressError) -> Self {
        CoachError::Egress(e)
    }
}

impl From<WireError> for CoachError {
    fn from(e: WireError) -> Self {
        CoachError::Wire(e)
    }
}

/// A failed `tools.call`: the serve error's code (its message is dropped at the source).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallError {
    pub code: String,
}

// ---- the trace ----------------------------------------------------------------------------------

/// How one tool call ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum Outcome {
    /// The projected answer went to the model.
    Ok,
    /// The projection or the schema refused the answer (the reason is a fixed phrase); the model got
    /// `{"error":"withheld"}`.
    Rejected(&'static str),
    /// The answer would not fit its byte cap: the turn ended.
    TooLarge,
    /// The call failed before or inside the core: a serve code, or `unknown tool` / `bad arguments`.
    ToolError(&'static str),
}

/// One tool call, for the "what the model can see" drawer.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TraceEntry {
    pub tool: String,
    /// The arguments after they were forced inside the coach defaults (`Null` when they were not a JSON object).
    pub arguments_sent: Value,
    /// The size of the tool message's content, in bytes.
    pub bytes_sent: usize,
    /// What left for this call: the validated projection, or the fixed error object.
    pub projected: Value,
    pub outcome: Outcome,
}

/// The turns of one session (without the system message) and the trace of the latest question.
#[derive(Debug, Clone, Default)]
pub struct Conversation {
    turns: Vec<Message>,
    /// The tool calls of the latest question (replaced by the next one).
    pub trace: Vec<TraceEntry>,
    /// How many requests this conversation has sent (a refused or failed send counts).
    pub sends: usize,
}

impl Conversation {
    pub fn new() -> Conversation {
        Conversation::default()
    }

    pub fn turns(&self) -> &[Message] {
        &self.turns
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        *self = Conversation::default();
    }
}

// ---- the window manager -------------------------------------------------------------------------

fn is_user(message: &Message) -> bool {
    matches!(message, Message::User { .. })
}

/// The turns a request may carry within `budget_bytes` (their serialised size). The caller adds the system
/// message and subtracts its size from the budget.
///
/// 1. Every user and assistant message is kept. A tool message from before the latest user message gets the
///    fixed content [`wire::OMITTED_CONTENT`] with its pairing id; so an assistant tool call always keeps its
///    answers, which providers insist on.
/// 2. While the result is over budget, the oldest whole exchange (a user message and everything up to the next
///    one) is dropped. A whole exchange goes or none of it, so the pairing stays valid, and the last two
///    messages are never dropped.
pub fn window(turns: &[Message], budget_bytes: usize) -> Vec<Message> {
    let latest_user = turns.iter().rposition(is_user);
    let mut kept: Vec<Message> = turns
        .iter()
        .enumerate()
        .map(|(index, message)| match message {
            Message::Tool(tool) if latest_user.is_some_and(|u| index < u) => Message::Tool(tool.omitted()),
            other => other.clone(),
        })
        .collect();
    while wire::encoded_len(&kept) > budget_bytes {
        let Some(next) = kept.iter().enumerate().skip(1).find(|(_, m)| is_user(m)).map(|(i, _)| i) else {
            break;
        };
        if kept.len() - next < 2 {
            break;
        }
        kept.drain(..next);
    }
    kept
}

// ---- the loop -----------------------------------------------------------------------------------

/// Settings gate shared by the loop and the Tauri command: `Off` is [`CoachError::Off`], an address the egress
/// rules refuse is [`CoachError::Egress`], else the validated endpoint. Reads no key and sends nothing.
pub fn gate(settings: &Settings) -> Result<Endpoint, CoachError> {
    match Endpoint::from_settings(settings) {
        Ok(endpoint) => Ok(endpoint),
        Err(EgressError::Off) => Err(CoachError::Off),
        Err(other) => Err(CoachError::Egress(other)),
    }
}

/// The order a question is set up in, with every effect injected so a test can count it: the settings gate
/// first (off returns before anything else), then the egress is built, then the key is read, then the loop
/// runs. Off therefore builds no egress, reads no key and sends nothing.
pub fn ask_configured(
    settings: &Settings,
    make_egress: impl FnOnce(&Settings) -> Option<Box<dyn Egress>>,
    resolve_key: impl FnOnce() -> Option<Zeroizing<String>>,
    call_tool: &dyn Fn(&str, Value) -> Result<Value, ToolCallError>,
    conv: &mut Conversation,
    user_text: &str,
) -> Result<String, CoachError> {
    gate(settings)?;
    let Some(egress) = make_egress(settings) else {
        return Err(CoachError::Egress(EgressError::BadUrl));
    };
    let bearer = resolve_key();
    Coach::new(egress.as_ref(), call_tool, settings, bearer).ask(conv, user_text)
}

/// Runs a question. Borrows everything: the egress (real or scripted), the tool runner (the core behind
/// `tools.call`, or a fixture in tests), the settings and the key.
pub struct Coach<'a> {
    pub egress: &'a dyn Egress,
    /// `tools.call {name, arguments}`: the answer is `{"name", "result"}`; a failure is its serve code.
    pub call_tool: &'a dyn Fn(&str, Value) -> Result<Value, ToolCallError>,
    pub settings: &'a Settings,
    pub bearer: Option<Zeroizing<String>>,
    /// The request budget (see [`DEFAULT_CONTEXT_BYTES`]).
    pub context_bytes: usize,
}

fn shorten(name: &str) -> String {
    name.chars().take(MAX_TRACE_NAME).collect()
}

impl<'a> Coach<'a> {
    pub fn new(
        egress: &'a dyn Egress,
        call_tool: &'a dyn Fn(&str, Value) -> Result<Value, ToolCallError>,
        settings: &'a Settings,
        bearer: Option<Zeroizing<String>>,
    ) -> Coach<'a> {
        Coach { egress, call_tool, settings, bearer, context_bytes: DEFAULT_CONTEXT_BYTES }
    }

    /// Ask one question. On success the user's words and the model's scrubbed answer (and the tool exchange in
    /// between) are in `conv`; on failure `conv`'s turns are as they were.
    pub fn ask(&self, conv: &mut Conversation, user_text: &str) -> Result<String, CoachError> {
        let endpoint = gate(self.settings)?;
        if self.settings.mode == Mode::Cloud && self.bearer.is_none() {
            return Err(CoachError::NoKey);
        }
        let url = endpoint.join(CHAT_PATH)?;
        let rollback_to = conv.turns.len();
        conv.trace.clear();
        conv.turns.push(Message::User { content: user_text.to_string() });
        let outcome = self.rounds(conv, &url);
        if outcome.is_err() {
            conv.turns.truncate(rollback_to);
        }
        outcome
    }

    fn rounds(&self, conv: &mut Conversation, url: &url::Url) -> Result<String, CoachError> {
        let system = system_prompt();
        // the system message as it is serialised (JSON escapes and the role wrapper count), so the whole
        // `messages` array stays inside `context_bytes`
        let turn_budget = self.context_bytes.saturating_sub(wire::encoded_len(&[Message::System { content: system.clone() }]));
        for round in 0..=MAX_ROUNDS {
            let mut messages = vec![Message::System { content: system.clone() }];
            messages.extend(window(&conv.turns, turn_budget));
            let body = ChatRequest::new(&self.settings.model, messages).to_body()?;
            conv.sends += 1;
            let inbound = self.egress.send(Outbound { url: url.clone(), bearer: self.bearer.clone(), body })?;
            let reply = wire::parse_response(&inbound.body)?;
            let calls = reply.tool_calls();
            if calls.is_empty() {
                let text = neutral_text(reply.text().unwrap_or_default());
                conv.turns.push(Message::Assistant { content: Some(text.clone()), tool_calls: None });
                return Ok(text);
            }
            if round == MAX_ROUNDS || calls.len() > MAX_CALLS_PER_ROUND {
                return Err(CoachError::TooManyToolCalls);
            }
            let mut answers = Vec::with_capacity(calls.len());
            for call in calls {
                answers.push(self.run_call(call, &mut conv.trace)?);
            }
            conv.turns.push(reply.message.clone());
            conv.turns.extend(answers.into_iter().map(Message::Tool));
        }
        Err(CoachError::TooManyToolCalls)
    }

    /// One tool call to its tool message, and a trace entry. `Err` only when the answer cannot be made to fit.
    fn run_call(&self, call: &ToolCall, trace: &mut Vec<TraceEntry>) -> Result<ToolMessage, CoachError> {
        let id = call.id.as_str();
        let name = call.function.name.as_str();
        let failed = |trace: &mut Vec<TraceEntry>, arguments: Value, failure: ToolFailure, outcome: Outcome| {
            let message = ToolMessage::error(id, failure);
            trace.push(TraceEntry {
                tool: shorten(name),
                arguments_sent: arguments,
                bytes_sent: message.content().len(),
                projected: serde_json::from_str(message.content()).unwrap_or(Value::Null),
                outcome,
            });
            message
        };
        if !SENDABLE_TOOLS.contains(&name) {
            return Ok(failed(trace, Value::Null, ToolFailure::UnknownTool, Outcome::ToolError(ToolFailure::UnknownTool.label())));
        }
        let text = call.function.arguments.trim();
        let parsed: Option<Value> = if text.is_empty() { Some(Value::Object(Default::default())) } else { serde_json::from_str(text).ok() };
        let Some(arguments) = parsed.filter(Value::is_object) else {
            return Ok(failed(trace, Value::Null, ToolFailure::BadArguments, Outcome::ToolError(ToolFailure::BadArguments.label())));
        };
        let limits = CoachArgs { include_points: self.settings.include_points, ..CoachArgs::default() };
        let arguments = caps::clamp_with(name, &arguments, &limits);

        let answer = match (self.call_tool)(name, arguments.clone()) {
            Ok(answer) => answer,
            Err(error) => {
                let failure = ToolFailure::Serve(ServeCode::from_code(&error.code));
                return Ok(failed(trace, arguments, failure, Outcome::ToolError(failure.label())));
            }
        };
        let Some(result) = answer.get("result") else {
            let failure = ToolFailure::Serve(ServeCode::ToolError);
            return Ok(failed(trace, arguments, failure, Outcome::ToolError(failure.label())));
        };
        let options = ViewOptions { include_points: self.settings.include_points };
        let Ok(projected) = views::project_with(name, result, &options) else {
            return Ok(failed(trace, arguments, ToolFailure::Withheld, Outcome::Rejected("view")));
        };
        let fitted = match caps::fit(name, &projected) {
            Ok(fitted) => fitted,
            Err(CapError::StillTooLarge) => {
                trace.push(TraceEntry {
                    tool: name.to_string(),
                    arguments_sent: arguments,
                    bytes_sent: 0,
                    projected: Value::Null,
                    outcome: Outcome::TooLarge,
                });
                return Err(CoachError::ToolTooLarge);
            }
            Err(CapError::UnknownTool) => {
                return Ok(failed(trace, arguments, ToolFailure::UnknownTool, Outcome::ToolError(ToolFailure::UnknownTool.label())));
            }
        };
        match schema::validated(name, fitted) {
            Ok(validated) => {
                let message = ToolMessage::result(id, &validated);
                trace.push(TraceEntry {
                    tool: name.to_string(),
                    arguments_sent: arguments,
                    bytes_sent: message.content().len(),
                    projected: validated.as_value().clone(),
                    outcome: Outcome::Ok,
                });
                Ok(message)
            }
            Err(refused) => {
                Ok(failed(trace, arguments, ToolFailure::Withheld, Outcome::Rejected(refused.reason.text())))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user(text: &str) -> Message {
        Message::User { content: text.into() }
    }

    fn assistant(text: &str) -> Message {
        Message::Assistant { content: Some(text.into()), tool_calls: None }
    }

    fn call_message(ids: &[&str]) -> Message {
        let calls = ids
            .iter()
            .map(|id| ToolCall {
                id: (*id).into(),
                function: wire::FunctionCall { name: "get_sleep_detail".into(), arguments: "{}".into() },
            })
            .collect();
        Message::Assistant { content: None, tool_calls: Some(calls) }
    }

    fn tool_message(id: &str, bulk: usize) -> Message {
        // the only way to get a tool message with content is a validated value: pad a note-free activity list
        let activities: Vec<Value> = (0..bulk).map(|_| json!({"date": "2025-06-30", "sport": "running"})).collect();
        let validated = schema::validated("list_activities", json!({"activities": activities})).unwrap();
        Message::Tool(ToolMessage::result(id, &validated))
    }

    /// Every assistant tool call is answered by exactly its tool messages right after it, and every tool
    /// message follows a call it answers.
    fn pairing_holds(messages: &[Message]) -> bool {
        let mut at = 0;
        while at < messages.len() {
            match &messages[at] {
                Message::Assistant { tool_calls: Some(calls), .. } => {
                    for (offset, call) in calls.iter().enumerate() {
                        match messages.get(at + 1 + offset) {
                            Some(Message::Tool(t)) if t.tool_call_id() == call.id => {}
                            _ => return false,
                        }
                    }
                    at += 1 + calls.len();
                }
                Message::Tool(_) => return false,
                _ => at += 1,
            }
        }
        true
    }

    fn history(asks: usize, bulk: usize) -> Vec<Message> {
        let mut turns = Vec::new();
        for n in 0..asks {
            let (a, b) = (format!("c{n}a"), format!("c{n}b"));
            turns.push(user(&format!("question {n}")));
            turns.push(call_message(&[&a, &b]));
            turns.push(tool_message(&a, bulk));
            turns.push(tool_message(&b, bulk));
            turns.push(assistant(&format!("answer {n}")));
        }
        turns
    }

    #[test]
    fn old_tool_results_become_the_marker_and_the_pairing_survives() {
        let turns = history(3, 5);
        let windowed = window(&turns, usize::MAX);
        assert_eq!(windowed.len(), turns.len());
        assert!(pairing_holds(&windowed));
        let contents: Vec<&str> = windowed.iter().filter_map(|m| if let Message::Tool(t) = m { Some(t.content()) } else { None }).collect();
        assert_eq!(contents.len(), 6);
        assert!(contents[..4].iter().all(|c| *c == wire::OMITTED_CONTENT), "{contents:?}");
        assert!(contents[4..].iter().all(|c| c.starts_with("{\"activities\"")), "the latest question keeps its results");
        // users and assistant text are untouched
        assert_eq!(windowed[0], user("question 0"));
        assert_eq!(windowed[4], assistant("answer 0"));
    }

    #[test]
    fn within_one_question_earlier_rounds_keep_their_results() {
        let mut turns = vec![user("q"), call_message(&["a"]), tool_message("a", 3), call_message(&["b"]), tool_message("b", 3)];
        let windowed = window(&turns, usize::MAX);
        assert_eq!(windowed, turns);
        turns.push(assistant("done"));
        turns.push(user("next"));
        let windowed = window(&turns, usize::MAX);
        assert!(pairing_holds(&windowed));
        assert!(matches!(&windowed[2], Message::Tool(t) if t.content() == wire::OMITTED_CONTENT));
        assert!(matches!(&windowed[4], Message::Tool(t) if t.content() == wire::OMITTED_CONTENT));
    }

    #[test]
    fn over_budget_the_oldest_whole_exchanges_go_and_the_last_two_messages_never() {
        let turns = history(10, 40);
        let full = wire::encoded_len(&window(&turns, usize::MAX));
        // the newest exchange keeps its (large) tool results; room for it and about three older ones
        let budget = wire::encoded_len(&turns[turns.len() - 5..]) + 1100;
        assert!(budget < full);
        let windowed = window(&turns, budget);
        assert!(wire::encoded_len(&windowed) <= budget, "{} > {budget}", wire::encoded_len(&windowed));
        assert!(pairing_holds(&windowed));
        assert!(is_user(&windowed[0]), "an exchange starts with its user message");
        assert_eq!(windowed.last(), turns.last(), "the newest turn is kept");
        assert!(windowed.len() < turns.len());
        // what is kept is a suffix of the history
        let tail = &turns[turns.len() - windowed.len()..];
        for (kept, original) in windowed.iter().zip(tail) {
            match (kept, original) {
                (Message::Tool(_), Message::Tool(_)) => {}
                _ => assert_eq!(kept, original),
            }
        }
        // an impossible budget keeps the last exchange's user message and answer, nothing less
        let tiny = window(&turns, 10);
        assert!(tiny.len() >= 2 && pairing_holds(&tiny), "{}", tiny.len());
        assert_eq!(tiny.last(), turns.last());
        // a history of one pending question is never emptied
        let pending = vec![user("only")];
        assert_eq!(window(&pending, 1), pending);
        let pair = vec![user("q"), assistant("a"), user("q2")];
        assert_eq!(window(&pair, 1), pair, "dropping the first exchange would leave one message");
    }

    #[test]
    fn errors_have_fixed_messages_that_hold_no_key_url_or_body() {
        let all = [
            CoachError::Off,
            CoachError::NoKey,
            CoachError::Egress(EgressError::Status(500)),
            CoachError::Egress(EgressError::Unreachable),
            CoachError::Wire(WireError::NotJson),
            CoachError::Wire(WireError::NoChoices),
            CoachError::Wire(WireError::BadShape),
            CoachError::TooManyToolCalls,
            CoachError::ToolTooLarge,
            CoachError::Locked,
        ];
        for error in all {
            for shown in [error.message(), error.code()] {
                for sample in ["sk-test-0123456789", "https://api.example/v1", "127.0.0.1", "{\"choices\"", "500"] {
                    assert!(!shown.contains(sample), "{shown} contains {sample}");
                }
            }
        }
        assert_eq!(CoachError::Egress(EgressError::Status(500)).status(), Some(500));
        assert_eq!(CoachError::Wire(WireError::NotJson).status(), None);
        assert_eq!(CoachError::Egress(EgressError::Status(429)).code(), "status");
    }
}
