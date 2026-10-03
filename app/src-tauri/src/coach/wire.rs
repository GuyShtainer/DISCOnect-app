// SPDX-License-Identifier: AGPL-3.0-or-later
//! The OpenAI-compatible chat-completions wire (Bet 15, slice 5): pure functions and types, no I/O.
//!
//! **The request** is [`ChatRequest`] serialised with serde: `{model, messages, tools, tool_choice: "auto",
//! stream: false}` (plus `temperature` when set). It is POSTed to [`CHAT_PATH`] joined onto the endpoint base
//! by [`super::egress::Endpoint::join`]; the base is expected to end in `/v1` (`https://api.example/v1`,
//! `http://127.0.0.1:11434/v1`), so the request goes to `<base>/chat/completions`.
//!
//! **What may be in a message.** `System` and `User` carry text the app or the user wrote. `Assistant` is what
//! the model said. A `Tool` message can only be made from a [`Validated`] projection
//! ([`ToolMessage::result`]) or from one of a closed set of fixed strings ([`ToolFailure`], the omitted
//! marker): there is no constructor from a string, so no raw tool answer can reach a request. This is the
//! type-level half of the guarantee the capture tests check on the bytes.
//!
//! **The tools** are the five of `disconect-core/mcp.json` with their descriptions and input schemas as the
//! file has them (JSON-schema `title` keys, which are generator noise, are stripped); `get_contract` is not
//! sent. `mcp.json`'s `instructions` text is the MCP server's and is never used here.
//!
//! **The reply** is read by [`parse_response`], tolerant of extra fields (usage details, `system_fingerprint`,
//! `refusal`, ...) and strict about what the loop needs. [`WireError`] is a closed enum with fixed messages and
//! never carries the body.

use std::sync::LazyLock;

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use serde_json::Value;

use super::schema::{Validated, SENDABLE_TOOLS};

/// The path joined onto the endpoint base.
pub const CHAT_PATH: &str = "chat/completions";

/// What an older tool result is replaced with (see [`ToolMessage::omitted`]).
pub const OMITTED_CONTENT: &str = r#"{"omitted":"earlier tool result"}"#;

// ---- messages -----------------------------------------------------------------------------------

/// One chat message. Serialises as `{"role": ..., ...}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "role", rename_all = "lowercase")]
pub enum Message {
    System { content: String },
    User { content: String },
    Assistant {
        #[serde(skip_serializing_if = "Option::is_none")]
        content: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tool_calls: Option<Vec<ToolCall>>,
    },
    Tool(ToolMessage),
}

/// A function call the model asked for. `arguments` is JSON *text*, as the wire has it (the model's own).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub id: String,
    pub function: FunctionCall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

impl Serialize for ToolCall {
    /// `{"id", "type": "function", "function": {"name", "arguments"}}`, the shape providers expect back.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ToolCall", 3)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("type", "function")?;
        state.serialize_field("function", &self.function)?;
        state.end()
    }
}

/// The answer to one tool call. The fields are private: the only ways to make one are [`ToolMessage::result`]
/// (a [`Validated`] projection), [`ToolMessage::error`] (a fixed string) and [`ToolMessage::omitted`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolMessage {
    tool_call_id: String,
    content: String,
}

impl ToolMessage {
    /// The compact JSON of a validated projection.
    pub fn result(tool_call_id: &str, projection: &Validated) -> ToolMessage {
        ToolMessage { tool_call_id: tool_call_id.to_string(), content: projection.compact() }
    }

    /// One of the fixed error strings.
    pub fn error(tool_call_id: &str, failure: ToolFailure) -> ToolMessage {
        ToolMessage { tool_call_id: tool_call_id.to_string(), content: failure.content().to_string() }
    }

    /// The same message with its content replaced by [`OMITTED_CONTENT`] (the pairing id is kept).
    pub fn omitted(&self) -> ToolMessage {
        ToolMessage { tool_call_id: self.tool_call_id.clone(), content: OMITTED_CONTENT.to_string() }
    }

    pub fn tool_call_id(&self) -> &str {
        &self.tool_call_id
    }

    pub fn content(&self) -> &str {
        &self.content
    }
}

/// The codes a failed `tools.call` is reported to the model as. Anything the core says outside this list is
/// [`ServeCode::ToolError`]; the core's message text is never forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeCode {
    Locked,
    ToolError,
    InvalidParams,
    UnknownTool,
    NotConfigured,
}

impl ServeCode {
    /// The serve code named `code`, or [`ServeCode::ToolError`] for any other text.
    pub fn from_code(code: &str) -> ServeCode {
        match code {
            "locked" => ServeCode::Locked,
            "invalid_params" => ServeCode::InvalidParams,
            "unknown_tool" => ServeCode::UnknownTool,
            "not_configured" => ServeCode::NotConfigured,
            _ => ServeCode::ToolError,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            ServeCode::Locked => "locked",
            ServeCode::ToolError => "tool_error",
            ServeCode::InvalidParams => "invalid_params",
            ServeCode::UnknownTool => "unknown_tool",
            ServeCode::NotConfigured => "not_configured",
        }
    }
}

/// Why a tool call is answered with an error string. Closed; every content string is fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolFailure {
    /// The model named a tool that is not one of the five.
    UnknownTool,
    /// The model's arguments are not a JSON object.
    BadArguments,
    /// The tool answered but the projection or the schema refused it: nothing is sent.
    Withheld,
    /// The core refused the call.
    Serve(ServeCode),
}

impl ToolFailure {
    /// The exact tool-message content.
    pub fn content(self) -> &'static str {
        match self {
            ToolFailure::UnknownTool => r#"{"error":"unknown tool"}"#,
            ToolFailure::BadArguments => r#"{"error":"bad arguments"}"#,
            ToolFailure::Withheld => r#"{"error":"withheld"}"#,
            ToolFailure::Serve(ServeCode::Locked) => r#"{"error":"locked"}"#,
            ToolFailure::Serve(ServeCode::ToolError) => r#"{"error":"tool_error"}"#,
            ToolFailure::Serve(ServeCode::InvalidParams) => r#"{"error":"invalid_params"}"#,
            ToolFailure::Serve(ServeCode::UnknownTool) => r#"{"error":"unknown_tool"}"#,
            ToolFailure::Serve(ServeCode::NotConfigured) => r#"{"error":"not_configured"}"#,
        }
    }

    /// A short label for the trace.
    pub fn label(self) -> &'static str {
        match self {
            ToolFailure::UnknownTool => "unknown tool",
            ToolFailure::BadArguments => "bad arguments",
            ToolFailure::Withheld => "withheld",
            ToolFailure::Serve(code) => code.code(),
        }
    }
}

// ---- the request --------------------------------------------------------------------------------

/// `{"type": "function", "function": {name, description, parameters}}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ToolSpec {
    #[serde(rename = "type")]
    kind: &'static str,
    pub function: FunctionSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FunctionSpec {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

/// `mcp.json`, embedded (the core embeds the same file for the MCP server; its table is private there).
const MCP_JSON: &str = include_str!("../../../../core/mcp.json");

/// Remove JSON-schema `title` keys (a string next to the schema keywords; a *property* called `title` has an
/// object as its value and stays).
fn strip_titles(node: &mut Value) {
    match node {
        Value::Object(map) => {
            if matches!(map.get("title"), Some(Value::String(_))) {
                map.remove("title");
            }
            map.values_mut().for_each(strip_titles);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_titles),
        _ => {}
    }
}

static SPECS: LazyLock<Vec<ToolSpec>> = LazyLock::new(|| {
    let Ok(file) = serde_json::from_str::<Value>(MCP_JSON) else {
        return Vec::new();
    };
    let tools = file.get("tools").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut specs = Vec::new();
    for tool in tools {
        let (Some(name), Some(description)) =
            (tool.get("name").and_then(Value::as_str), tool.get("description").and_then(Value::as_str))
        else {
            continue;
        };
        if !SENDABLE_TOOLS.contains(&name) {
            continue; // get_contract: never sent
        }
        let mut parameters = tool.get("inputSchema").cloned().unwrap_or(Value::Null);
        strip_titles(&mut parameters);
        specs.push(ToolSpec {
            kind: "function",
            function: FunctionSpec { name: name.to_string(), description: description.to_string(), parameters },
        });
    }
    specs
});

/// The five tool specs, in `mcp.json`'s order, built once.
pub fn tool_specs() -> &'static [ToolSpec] {
    &SPECS
}

/// The body of one chat-completions POST.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    /// Omitted from the body when empty (the probe's context round offers no tools).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<&'static str>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Only the probe sets it (`1`: the context round wants the prompt token count, not an answer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
}

impl ChatRequest {
    /// A request for `model` over `messages`, offering the five tools with `tool_choice: "auto"`, not streamed.
    pub fn new(model: &str, messages: Vec<Message>) -> ChatRequest {
        ChatRequest {
            model: model.to_string(),
            messages,
            tools: tool_specs().to_vec(),
            tool_choice: Some("auto"),
            stream: false,
            temperature: None,
            max_tokens: None,
        }
    }

    /// A request that offers no tools and caps the answer at `max_tokens`: the probe's context round.
    pub fn without_tools(model: &str, messages: Vec<Message>, max_tokens: u32) -> ChatRequest {
        ChatRequest { tools: Vec::new(), tool_choice: None, max_tokens: Some(max_tokens), ..ChatRequest::new(model, messages) }
    }

    /// The JSON bytes that go on the wire.
    pub fn to_body(&self) -> Result<Vec<u8>, WireError> {
        serde_json::to_vec(self).map_err(|_| WireError::BadShape)
    }
}

/// The serialised size of some messages (what the window manager budgets).
pub fn encoded_len(messages: &[Message]) -> usize {
    serde_json::to_vec(messages).map_or(usize::MAX, |bytes| bytes.len())
}

// ---- the reply ----------------------------------------------------------------------------------

/// Why a provider answer could not be read. Closed; fixed messages; never the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The body is not JSON.
    NotJson,
    /// JSON, but no `choices` (or an empty list).
    NoChoices,
    /// `choices[0].message` is not what a chat completion carries.
    BadShape,
}

impl WireError {
    pub fn message(&self) -> &'static str {
        match self {
            WireError::NotJson => "the endpoint's answer is not JSON",
            WireError::NoChoices => "the endpoint's answer has no choices",
            WireError::BadShape => "the endpoint's answer is not a chat completion the coach can read",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            WireError::NotJson => "not_json",
            WireError::NoChoices => "no_choices",
            WireError::BadShape => "bad_shape",
        }
    }
}

/// Token counts, when the provider reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

/// The first choice of a chat completion.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    /// Always a [`Message::Assistant`].
    pub message: Message,
    pub finish_reason: Option<String>,
    pub usage: Option<Usage>,
}

impl Reply {
    /// The tool calls the model asked for (empty when it answered in text).
    pub fn tool_calls(&self) -> &[ToolCall] {
        match &self.message {
            Message::Assistant { tool_calls: Some(calls), .. } => calls,
            _ => &[],
        }
    }

    /// The text of the answer, if any.
    pub fn text(&self) -> Option<&str> {
        match &self.message {
            Message::Assistant { content, .. } => content.as_deref(),
            _ => None,
        }
    }
}

fn parse_call(index: usize, raw: &Value) -> Result<ToolCall, WireError> {
    let function = raw.get("function").and_then(Value::as_object).ok_or(WireError::BadShape)?;
    let name = function.get("name").and_then(Value::as_str).ok_or(WireError::BadShape)?;
    // some servers send the arguments as an object, some omit them for a tool without parameters
    let arguments = match function.get("arguments") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other @ Value::Object(_)) => other.to_string(),
        Some(_) => return Err(WireError::BadShape),
    };
    // a server that sends no call id still gets a stable one, so the answer can be paired
    let id = match raw.get("id") {
        Some(Value::String(id)) if !id.is_empty() => id.clone(),
        Some(Value::Null) | None => format!("call_{index}"),
        Some(_) => return Err(WireError::BadShape),
    };
    Ok(ToolCall { id, function: FunctionCall { name: name.to_string(), arguments } })
}

/// Read a chat-completions body.
pub fn parse_response(body: &[u8]) -> Result<Reply, WireError> {
    let root: Value = serde_json::from_slice(body).map_err(|_| WireError::NotJson)?;
    let choice = root.get("choices").and_then(Value::as_array).and_then(|choices| choices.first()).ok_or(WireError::NoChoices)?;
    let message = choice.get("message").and_then(Value::as_object).ok_or(WireError::BadShape)?;
    let content = match message.get("content") {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Null) | None => None,
        Some(_) => return Err(WireError::BadShape),
    };
    let calls = match message.get("tool_calls") {
        Some(Value::Array(raw)) => raw.iter().enumerate().map(|(i, call)| parse_call(i, call)).collect::<Result<Vec<_>, _>>()?,
        Some(Value::Null) | None => Vec::new(),
        Some(_) => return Err(WireError::BadShape),
    };
    if content.is_none() && calls.is_empty() {
        return Err(WireError::BadShape);
    }
    let finish_reason = choice.get("finish_reason").and_then(Value::as_str).map(str::to_string);
    let usage = root.get("usage").and_then(Value::as_object).map(|u| Usage {
        prompt_tokens: u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0),
        completion_tokens: u.get("completion_tokens").and_then(Value::as_u64).unwrap_or(0),
    });
    let tool_calls = if calls.is_empty() { None } else { Some(calls) };
    Ok(Reply { message: Message::Assistant { content, tool_calls }, finish_reason, usage })
}

#[cfg(test)]
mod tests {
    use super::*;
    use disconect_core::identity::MANUFACTURER_PATTERN;
    use serde_json::json;

    #[test]
    fn the_specs_are_the_five_tools_without_the_contract_and_without_titles() {
        let names: Vec<&str> = tool_specs().iter().map(|s| s.function.name.as_str()).collect();
        assert_eq!(names, ["get_data_health", "get_metric_series", "get_sleep_detail", "list_activities", "get_period_facts"]);
        assert!(!names.contains(&"get_contract"));
        for spec in tool_specs() {
            let text = serde_json::to_string(spec).unwrap();
            assert!(!text.contains("\"title\""), "{text}");
            assert!(!text.to_lowercase().contains(&MANUFACTURER_PATTERN[..6]), "no vendor name in what is sent");
            assert_eq!(spec.function.parameters["type"], "object");
        }
        let series = tool_specs().iter().find(|s| s.function.name == "get_metric_series").unwrap();
        assert_eq!(series.function.parameters["required"], json!(["metrics"]));
        assert_eq!(series.function.parameters["properties"]["days"]["default"], 90);
    }

    #[test]
    fn a_property_called_title_survives_the_strip() {
        let mut schema = json!({"title": "X", "properties": {"title": {"type": "string", "title": "Title"}}});
        strip_titles(&mut schema);
        assert_eq!(schema, json!({"properties": {"title": {"type": "string"}}}));
    }

    #[test]
    fn the_request_serialises_to_chat_completions_json() {
        let messages = vec![
            Message::System { content: "s".into() },
            Message::User { content: "u".into() },
            Message::Assistant {
                content: None,
                tool_calls: Some(vec![ToolCall {
                    id: "c1".into(),
                    function: FunctionCall { name: "get_sleep_detail".into(), arguments: "{}".into() },
                }]),
            },
            Message::Tool(ToolMessage::error("c1", ToolFailure::Serve(ServeCode::Locked))),
            Message::Assistant { content: Some("a".into()), tool_calls: None },
        ];
        let body: Value = serde_json::from_slice(&ChatRequest::new("m", messages).to_body().unwrap()).unwrap();
        assert_eq!(body["model"], "m");
        assert_eq!(body["tool_choice"], "auto");
        assert_eq!(body["stream"], false);
        assert!(body.get("temperature").is_none());
        assert_eq!(body["tools"].as_array().unwrap().len(), 5);
        assert_eq!(body["tools"][0]["type"], "function");
        assert_eq!(body["messages"][0], json!({"role": "system", "content": "s"}));
        assert_eq!(
            body["messages"][2],
            json!({"role": "assistant", "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "get_sleep_detail", "arguments": "{}"}}]})
        );
        assert_eq!(body["messages"][3], json!({"role": "tool", "tool_call_id": "c1", "content": "{\"error\":\"locked\"}"}));
        assert_eq!(body["messages"][4], json!({"role": "assistant", "content": "a"}));
    }

    #[test]
    fn a_text_reply_a_tool_reply_and_extra_fields_parse() {
        let text = br#"{"id":"x","object":"chat.completion","system_fingerprint":"f","choices":[{"index":0,"message":{"role":"assistant","content":"hello","refusal":null},"finish_reason":"stop","logprobs":null}],"usage":{"prompt_tokens":12,"completion_tokens":3,"total_tokens":15,"prompt_tokens_details":{"cached_tokens":0}}}"#;
        let reply = parse_response(text).unwrap();
        assert_eq!(reply.text(), Some("hello"));
        assert!(reply.tool_calls().is_empty());
        assert_eq!(reply.finish_reason.as_deref(), Some("stop"));
        assert_eq!(reply.usage, Some(Usage { prompt_tokens: 12, completion_tokens: 3 }));

        let tools = br#"{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_9","type":"function","function":{"name":"list_activities","arguments":"{\"limit\":3}"}},{"function":{"name":"get_sleep_detail","arguments":{"date":"2025-06-30"}}}]},"finish_reason":"tool_calls"}]}"#;
        let reply = parse_response(tools).unwrap();
        assert_eq!(reply.text(), None);
        let calls = reply.tool_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!((calls[0].id.as_str(), calls[0].function.arguments.as_str()), ("call_9", r#"{"limit":3}"#));
        assert_eq!(calls[1].id, "call_1", "a missing id is made up so the answer can be paired");
        assert_eq!(calls[1].function.arguments, r#"{"date":"2025-06-30"}"#);
        assert_eq!(reply.usage, None);
    }

    #[test]
    fn bad_answers_are_closed_errors_that_never_carry_the_body() {
        let secret = "sk-test-0123456789 https://api.example/v1";
        let cases: [(String, WireError); 6] = [
            (format!("not json {secret}"), WireError::NotJson),
            (format!("{{\"note\":\"{secret}\"}}"), WireError::NoChoices),
            (format!("{{\"choices\":[],\"note\":\"{secret}\"}}"), WireError::NoChoices),
            (format!("{{\"choices\":[{{\"message\":\"{secret}\"}}]}}"), WireError::BadShape),
            (format!("{{\"choices\":[{{\"message\":{{\"content\":7,\"x\":\"{secret}\"}}}}]}}"), WireError::BadShape),
            ("{\"choices\":[{\"message\":{\"role\":\"assistant\"}}]}".to_string(), WireError::BadShape),
        ];
        for (body, want) in cases {
            let got = parse_response(body.as_bytes()).unwrap_err();
            assert_eq!(got, want, "{body}");
            for shown in [got.message(), got.code()] {
                assert!(!shown.contains("sk-test") && !shown.contains("api.example"));
            }
        }
    }

    #[test]
    fn tool_messages_come_only_from_a_validated_value_or_a_fixed_string() {
        let value = json!({"activities": [], "units": {}});
        let projection = super::super::schema::validated("list_activities", value).unwrap();
        let message = ToolMessage::result("c1", &projection);
        assert_eq!(message.content(), projection.compact());
        assert!(super::super::schema::validated("list_activities", json!({"start_utc": "x"})).is_err());
        assert_eq!(message.omitted().content(), OMITTED_CONTENT);
        assert_eq!(message.omitted().tool_call_id(), "c1");
        let fixed = [
            (ToolFailure::UnknownTool, r#"{"error":"unknown tool"}"#),
            (ToolFailure::BadArguments, r#"{"error":"bad arguments"}"#),
            (ToolFailure::Serve(ServeCode::from_code("locked")), r#"{"error":"locked"}"#),
            (ToolFailure::Serve(ServeCode::from_code("something else")), r#"{"error":"tool_error"}"#),
        ];
        for (failure, content) in fixed {
            assert_eq!(failure.content(), content);
            assert_eq!(ToolMessage::error("c", failure).content(), content);
        }
    }
}
