// SPDX-License-Identifier: AGPL-3.0-or-later
//! `disconect-core mcp`: the MCP server over stdio, hand-rolled (Bet 11e, slice 2; pitch
//! `11e-rust-mcp.md`). The oracle is `disconect/mcp_server.py` as the Python SDK serves it; `mcp.json`
//! (tools, handshake texts, error templates, measured answers) is embedded and drift-tested against it,
//! and `tools/mcp_diff.py` plays raw JSON-RPC lines into both servers.
//!
//! One JSON-RPC message per line (`\n`, `\r\n` or a bare `\r` ends a line, as Python's text stdin does). A
//! line that is not a valid message gets **no answer**: bad JSON, a batch, no or wrong `jsonrpc`, a lone
//! surrogate, nesting past 201 levels, params that are not an object, a response. A request needs an int
//! or string id; with any other id it is a notification. Request order: spec methods have their params
//! checked (-32602, `data:""`), `initialize` opens the gate, a method nobody serves is -32601 with its name
//! in `data`, then (but for `ping`) the gate, then the handler. Notifications are never answered.
//!
//! Boundaries, as `serve`'s: the protocol goes out on a private descriptor (fd 1 points at stderr);
//! `DISCONECT_PASSPHRASE` is removed from the environment and never read; nothing prints a secret.
//! Unlocking (before stdin is read) is [`crate::mcp_start`]; the tools are [`crate::mcp_tools`]; the
//! arguments are coerced by [`crate::mcp_args`].

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde_json::Value;

use crate::keys::Secret32;
use crate::mcp_args::coerce;
use crate::mcp_tools::{Outcome, SPEC, TOOLS, rejection, spec_json, spec_text};
use crate::wirejson::{self, Id, Json};

/// Deepest nesting of containers the Python server's JSON reader accepts (the message object is level 1).
const MAX_DEPTH: usize = 201;
const SPEC_METHODS: [&str; 13] = [
    "completion/complete",
    "initialize",
    "logging/setLevel",
    "ping",
    "prompts/get",
    "prompts/list",
    "resources/list",
    "resources/read",
    "resources/subscribe",
    "resources/templates/list",
    "resources/unsubscribe",
    "tools/call",
    "tools/list",
];
const HANDLED: [&str; 8] = [
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
];
const LOG_LEVELS: [&str; 8] = [
    "debug",
    "info",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
];

// ---- messages ----

/// What a line is, once read.
enum Incoming {
    Ignore,
    Notification {
        method: String,
        params: Json,
    },
    Request {
        id: Id,
        method: String,
        params: Json,
    },
}

/// Every string readable (no lone surrogate) and containers no deeper than the Python reader allows.
fn readable(json: &Json, depth: usize) -> bool {
    match json {
        Json::Str(text) => text.to_text().is_some(),
        Json::Array(items) => {
            depth <= MAX_DEPTH && items.iter().all(|item| readable(item, depth + 1))
        }
        Json::Object(pairs) => {
            depth <= MAX_DEPTH
                && pairs
                    .iter()
                    .all(|(key, item)| key.to_text().is_some() && readable(item, depth + 1))
        }
        _ => true,
    }
}

fn classify(line: &str) -> Incoming {
    let Ok(message) = wirejson::parse(line) else {
        return Incoming::Ignore;
    };
    if !matches!(message, Json::Object(_)) || !readable(&message, 1) {
        return Incoming::Ignore;
    }
    if !matches!(message.get("jsonrpc"), Some(Json::Str(version)) if version.equals("2.0")) {
        return Incoming::Ignore;
    }
    let name = match message.get("method") {
        Some(Json::Str(text)) => text.to_text().unwrap_or_default(),
        _ => return Incoming::Ignore,
    };
    let params = match message.get("params") {
        None | Some(Json::Null) => Json::dict(),
        Some(object @ Json::Object(_)) => object.clone(),
        Some(_) => return Incoming::Ignore,
    };
    match message.get("id") {
        Some(Json::Int(int)) => Incoming::Request {
            id: Id::Int(int.clone()),
            method: name,
            params,
        },
        Some(Json::Str(text)) => Incoming::Request {
            id: Id::Str(text.clone()),
            method: name,
            params,
        },
        _ => Incoming::Notification {
            method: name,
            params,
        },
    }
}

fn is_str(value: Option<&Json>) -> bool {
    matches!(value, Some(Json::Str(_)))
}

/// Absent or null, or what `check` accepts.
fn optional(value: Option<&Json>, check: impl Fn(&Json) -> bool) -> bool {
    value.is_none_or(|item| matches!(item, Json::Null) || check(item))
}

fn is_object(value: &Json) -> bool {
    matches!(value, Json::Object(_))
}

/// The surface validation of a spec method's params (`_meta` and unknown keys allowed).
fn valid_params(method: &str, params: &Json) -> bool {
    if !optional(params.get("_meta"), is_object) {
        return false;
    }
    match method {
        "initialize" => {
            let info = params.get("clientInfo");
            is_str(params.get("protocolVersion"))
                && params.get("capabilities").is_some_and(is_object)
                && info.is_some_and(is_object)
                && is_str(info.and_then(|i| i.get("name")))
                && is_str(info.and_then(|i| i.get("version")))
        }
        "tools/list" | "resources/list" | "resources/templates/list" | "prompts/list" => {
            optional(params.get("cursor"), |c| matches!(c, Json::Str(_)))
        }
        "tools/call" => {
            is_str(params.get("name"))
                && optional(params.get("arguments"), is_object)
                && optional(params.get("task"), is_object)
        }
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => {
            is_str(params.get("uri"))
        }
        "prompts/get" => {
            is_str(params.get("name"))
                && optional(
                    params.get("arguments"),
                    |a| matches!(a, Json::Object(pairs) if pairs.iter().all(|(_, v)| matches!(v, Json::Str(_)))),
                )
        }
        "logging/setLevel" => {
            matches!(params.get("level"), Some(Json::Str(level)) if LOG_LEVELS.iter().any(|name| level.equals(name)))
        }
        "completion/complete" => {
            let argument = params.get("argument");
            params
                .get("ref")
                .is_some_and(|r| is_object(r) && is_str(r.get("type")))
                && argument.is_some_and(is_object)
                && is_str(argument.and_then(|a| a.get("name")))
                && is_str(argument.and_then(|a| a.get("value")))
        }
        _ => true,
    }
}

fn response(id: &Id, result: &str) -> String {
    let mut line = String::from("{\"jsonrpc\":\"2.0\",\"id\":");
    wirejson::write_json_id(&mut line, id);
    line.push_str(",\"result\":");
    line.push_str(result);
    line.push('}');
    line
}

/// A JSON-RPC error; `data` is already JSON text, or None for no `data` member.
fn failure(id: &Id, code: i64, message: &str, data: Option<&str>) -> String {
    let mut line = String::from("{\"jsonrpc\":\"2.0\",\"id\":");
    wirejson::write_json_id(&mut line, id);
    line.push_str(&format!(",\"error\":{{\"code\":{code},\"message\":"));
    wirejson::write_text(&mut line, message);
    if let Some(data) = data {
        line.push_str(",\"data\":");
        line.push_str(data);
    }
    line.push_str("}}");
    line
}

fn json_text(text: &str) -> String {
    let mut out = String::new();
    wirejson::write_text(&mut out, text);
    out
}

/// A `tools/call` answer that is a text and an `isError` flag (no `structuredContent`).
fn tool_text(id: &Id, text: &str, is_error: bool) -> String {
    response(
        id,
        &format!(
            "{{\"content\":[{{\"text\":{},\"type\":\"text\"}}],\"isError\":{is_error}}}",
            json_text(text)
        ),
    )
}

// ---- the server ----

/// What one `mcp` process holds: the store, its master key if it has one, and whether the gate is open.
pub struct Server {
    pub(crate) db: PathBuf,
    pub(crate) master: Option<Secret32>,
    initialized: bool,
}

impl Server {
    pub fn new(db: PathBuf, master: Option<Secret32>) -> Server {
        Server {
            db,
            master,
            initialized: false,
        }
    }

    /// The answer to one input line, or None when there is none to give.
    pub fn handle_line(&mut self, line: &str) -> Option<String> {
        match classify(line) {
            Incoming::Ignore => None,
            Incoming::Notification { method, params } => {
                log_method(&method);
                if method == "notifications/initialized" && valid_notification(&params) {
                    self.initialized = true;
                }
                None
            }
            Incoming::Request { id, method, params } => {
                log_method(&method);
                Some(self.request(&id, &method, &params))
            }
        }
    }

    fn request(&mut self, id: &Id, method: &str, params: &Json) -> String {
        let invalid = || failure(id, -32602, "Invalid request parameters", Some("\"\""));
        if SPEC_METHODS.contains(&method) && !valid_params(method, params) {
            return invalid();
        }
        if method == "initialize" {
            self.initialized = true;
            return response(id, &self.initialize_result(params));
        }
        if !HANDLED.contains(&method) {
            return failure(id, -32601, "Method not found", Some(&json_text(method)));
        }
        if !self.initialized && method != "ping" {
            return invalid();
        }
        let text_of = |key: &str| match params.get(key) {
            Some(Json::Str(text)) => text.to_text().unwrap_or_default(),
            _ => String::new(),
        };
        match method {
            "tools/list" => response(id, &format!("{{\"tools\":{}}}", spec_json(&["tools"]))),
            "tools/call" => self.call_tool(id, params),
            "resources/list" => response(id, "{\"resources\":[]}"),
            "resources/templates/list" => response(id, "{\"resourceTemplates\":[]}"),
            "prompts/list" => response(id, "{\"prompts\":[]}"),
            "resources/read" => {
                let uri = text_of("uri");
                let data = format!("{{\"uri\":{}}}", json_text(&uri));
                failure(id, -32602, &format!("Unknown resource: {uri}"), Some(&data))
            }
            "prompts/get" => failure(id, 0, &format!("Unknown prompt: {}", text_of("name")), None),
            _ => response(id, "{}"),
        }
    }

    fn initialize_result(&self, params: &Json) -> String {
        let accepted = SPEC["protocol"]["accepted"].as_array();
        let asked = match params.get("protocolVersion") {
            Some(Json::Str(text)) => accepted.and_then(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .find(|v| text.equals(v))
            }),
            _ => None,
        };
        let version = asked.unwrap_or_else(|| spec_text(&["protocol", "default"]));
        format!(
            "{{\"capabilities\":{},\"instructions\":{},\"protocolVersion\":{},\"serverInfo\":{}}}",
            spec_json(&["capabilities"]),
            json_text(spec_text(&["instructions"])),
            json_text(version),
            spec_json(&["serverInfo"])
        )
    }

    fn call_tool(&self, id: &Id, params: &Json) -> String {
        let name = match params.get("name") {
            Some(Json::Str(text)) => text.to_text().unwrap_or_default(),
            _ => String::new(),
        };
        let Some(tool) = TOOLS.iter().find(|tool| tool.name == name) else {
            return tool_text(
                id,
                &spec_text(&["errors", "unknown_tool"]).replace("{name}", &name),
                true,
            );
        };
        let empty = Json::dict();
        let arguments = match params.get("arguments") {
            Some(object @ Json::Object(_)) => object,
            _ => &empty,
        };
        let args = match coerce(tool.params, arguments) {
            Ok(args) => args,
            Err(rejected) => return tool_text(id, &rejection(tool, &rejected), true),
        };
        match (tool.run)(self, &args) {
            Outcome::Done(json) => {
                let mut text = String::new();
                wirejson::write_json(&mut text, &json, Some(2));
                let mut structured = String::new();
                wirejson::write_json(&mut structured, &json, None);
                response(
                    id,
                    &format!(
                        "{{\"content\":[{{\"text\":{},\"type\":\"text\"}}],\"isError\":false,\"structuredContent\":{structured}}}",
                        json_text(&text)
                    ),
                )
            }
            Outcome::Failed(message) => {
                let text = spec_text(&["errors", "tool_error"])
                    .replace("{name}", tool.name)
                    .replace("{message}", &message);
                tool_text(id, &text, true)
            }
            Outcome::Crashed => tool_text(
                id,
                &spec_text(&["errors", "crash"]).replace("{name}", tool.name),
                true,
            ),
        }
    }
}

/// `notifications/initialized` needs object params (or none) with an object `_meta`.
fn valid_notification(params: &Json) -> bool {
    optional(params.get("_meta"), is_object)
}

/// One stderr line per method name (never the params), for the session log of the client that runs us.
fn log_method(method: &str) {
    let shown: String = method
        .chars()
        .take(80)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    let _ = writeln!(io::stderr(), "disconect-core mcp: {shown}");
}

/// Feed `input` to the server line by line and write each answer to `out`; returns at end of input or when
/// `out` is gone. A line ends at `\n`, `\r\n` or `\r`; bytes that are not UTF-8 become U+FFFD.
pub fn serve_lines(server: &mut Server, mut input: impl Read, out: &mut impl Write) {
    let mut line: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut after_cr = false;
    let mut answer = |server: &mut Server, line: &mut Vec<u8>| -> io::Result<()> {
        let text = String::from_utf8_lossy(line).into_owned();
        line.clear();
        match server.handle_line(&text) {
            Some(reply) => out
                .write_all(format!("{reply}\n").as_bytes())
                .and_then(|()| out.flush()),
            None => Ok(()),
        }
    };
    loop {
        let count = match input.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        for byte in &chunk[..count] {
            if std::mem::take(&mut after_cr) && *byte == b'\n' {
                continue;
            }
            match byte {
                b'\n' | b'\r' => {
                    after_cr = *byte == b'\r';
                    if answer(server, &mut line).is_err() {
                        return;
                    }
                }
                other => line.push(*other),
            }
        }
    }
    let _ = answer(server, &mut line);
}
