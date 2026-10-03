// SPDX-License-Identifier: AGPL-3.0-or-later
//! A deterministic chat-completions provider for the coach tests (Bet 15 slice 5).
//!
//! **Where it lives:** here, in `tests/common/`, not in the library. Integration tests are separate crates and
//! cannot see `#[cfg(test)]` items of the lib, and a test-only module that is compiled into the shipped library
//! (or a Tauri command that reaches it) would put a scripted "model" in the product. Unit tests inside `coach/`
//! build their own tiny scripts from [`Fake`] directly.
//!
//! A [`Scripted`] answers the Nth `send` with the Nth [`Step`], as a chat-completions JSON body whose `usage`
//! has `prompt_tokens` = request bytes / 4. It wraps the library's own [`Fake`] egress, so every request body is
//! recorded by the same code that records them in the unit tests, and a send after the script ran out is
//! `Unreachable` like an empty [`Fake`].

use std::collections::VecDeque;
use std::sync::Mutex;

use disconect_app_lib::coach::egress::{Egress, EgressError, Fake, Inbound, Outbound};
use serde_json::{json, Value};

/// What the provider answers to one request.
#[derive(Debug, Clone)]
pub enum Step {
    /// One tool call. `arguments_json` is the argument *text* (it may be invalid JSON on purpose).
    ToolCall { name: String, arguments_json: String },
    /// Several tool calls in one answer.
    ToolCalls(Vec<(String, String)>),
    /// A text answer.
    Text(String),
    /// An endpoint error status (the egress answers `Status(n)`; no body arrives).
    Status(u16),
    /// A 200 whose body is not JSON.
    Garbage,
}

impl Step {
    pub fn call(name: &str, arguments_json: &str) -> Step {
        Step::ToolCall { name: name.to_string(), arguments_json: arguments_json.to_string() }
    }

    pub fn text(text: &str) -> Step {
        Step::Text(text.to_string())
    }
}

/// The 200 body for a step, or `None` for a step that is an error status. `request_len` is the request body's
/// size, `send_index` its position (so call ids are unique across a conversation).
pub fn response_body(step: &Step, request_len: usize, send_index: usize) -> Option<Vec<u8>> {
    let prompt_tokens = request_len / 4;
    let message = match step {
        Step::Status(_) => return None,
        Step::Garbage => return Some(b"this is not json".to_vec()),
        Step::Text(text) => json!({"role": "assistant", "content": text}),
        Step::ToolCall { name, arguments_json } => tool_message(&[(name.clone(), arguments_json.clone())], send_index),
        Step::ToolCalls(calls) => tool_message(calls, send_index),
    };
    let finish = if message.get("tool_calls").is_some() { "tool_calls" } else { "stop" };
    let body = json!({
        "id": format!("chatcmpl-{send_index}"),
        "object": "chat.completion",
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 8, "total_tokens": prompt_tokens + 8},
    });
    Some(body.to_string().into_bytes())
}

fn tool_message(calls: &[(String, String)], send_index: usize) -> Value {
    let calls: Vec<Value> = calls
        .iter()
        .enumerate()
        .map(|(i, (name, arguments))| {
            json!({"id": format!("call_{send_index}_{i}"), "type": "function", "function": {"name": name, "arguments": arguments}})
        })
        .collect();
    json!({"role": "assistant", "content": null, "tool_calls": calls})
}

/// The scripted provider: an [`Egress`] over a [`Fake`].
pub struct Scripted {
    pub fake: Fake,
    steps: Mutex<VecDeque<Step>>,
}

/// A provider that will answer `steps` in order.
pub fn scripted(steps: Vec<Step>) -> Scripted {
    Scripted { fake: Fake::new(), steps: Mutex::new(steps.into()) }
}

impl Scripted {
    /// How many requests arrived.
    pub fn count(&self) -> usize {
        self.fake.count()
    }

    /// Every request body, in order.
    pub fn bodies(&self) -> Vec<Vec<u8>> {
        self.fake.sent.lock().map(|sent| sent.iter().map(|s| s.body.clone()).collect()).unwrap_or_default()
    }

    /// Every request body parsed as JSON.
    pub fn requests(&self) -> Vec<Value> {
        self.bodies().iter().map(|b| serde_json::from_slice(b).expect("a request body is JSON")).collect()
    }

    /// Steps not yet used.
    pub fn remaining(&self) -> usize {
        self.steps.lock().map(|s| s.len()).unwrap_or(0)
    }
}

impl Egress for Scripted {
    fn send(&self, out: Outbound) -> Result<Inbound, EgressError> {
        let index = self.fake.count();
        let step = self.steps.lock().ok().and_then(|mut steps| steps.pop_front());
        if let Some(step) = step {
            match (&step, response_body(&step, out.body.len(), index)) {
                (Step::Status(code), _) => self.fake.push(Err(EgressError::Status(*code))),
                (_, Some(body)) => self.fake.push(Ok(Inbound { status: 200, body })),
                (_, None) => {}
            }
        }
        self.fake.send(out)
    }
}
