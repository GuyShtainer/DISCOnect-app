// SPDX-License-Identifier: AGPL-3.0-or-later
//! The endpoint probe (Bet 15, slice 6): two requests that tell the Settings card whether a model endpoint
//! can drive the coach. Nothing in them comes from the store, the probe runs no tool and never calls the
//! core, so it works on a locked store.
//!
//! **Round 1, tools.** The real system prompt, the five tool specs and a fixed user line that asks for the
//! last seven days of steps. The reply is only read, never answered: [`ToolsSupport::Yes`] when it carries a
//! tool call that names one of the five, [`ToolsSupport::No`] when it is text only (or names a tool that is
//! not offered), [`ToolsSupport::Unknown`] when the answer cannot be read.
//!
//! **Round 2, context.** The system prompt and a synthetic filler of known size, no tools, `max_tokens: 1`.
//! The filler is [`FILLER_TOKENS`] tokens at [`BYTES_PER_TOKEN`] bytes each, built from one short ASCII
//! sentence (no data). `usage.prompt_tokens` is the tokens the server really read: at least
//! [`MIN_REPORTED_PERCENT`] % of the filler means [`ContextVerdict::Ok`]; fewer means the server cut the
//! prompt to its window ([`ContextVerdict::TooSmall`]); no `usage` is [`ContextVerdict::Unknown`]. The system
//! prompt adds a little on top of the filler, so the threshold is a conservative floor. Why it matters
//! (pitch 15, B3): Ollama's default context is 4k tokens unless `num_ctx` is raised, the OpenAI-compatible
//! endpoint cannot set it, and a server that silently truncates would drop the system prompt first.
//!
//! **Errors.** A transport error is `reachable: false` with its code. A 401 or 403 is `reachable: true`,
//! `error: "unauthorised"` and nothing else is tried. Any other error status is `reachable: true`,
//! `error: "status"` with the number. Messages and codes are fixed strings, never the provider's text.

use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroizing;

use super::egress::{Egress, EgressError, Endpoint, Outbound};
use super::prompt::system_prompt;
use super::schema::SENDABLE_TOOLS;
use super::settings::Settings;
use super::wire::{self, ChatRequest, Message, CHAT_PATH};

/// The byte-per-token rule the filler is sized with (a common rule of thumb for English prose).
pub const BYTES_PER_TOKEN: usize = 4;
/// The filler's size in tokens: 12 000, above a 4k default and near what a long coach answer needs.
pub const FILLER_TOKENS: u64 = 12_000;
/// The filler's size in bytes (48 000, far below the egress body cap of 1 MiB; the assertion below is the proof).
pub const FILLER_BYTES: usize = FILLER_TOKENS as usize * BYTES_PER_TOKEN;
const _: () = assert!(FILLER_BYTES < super::egress::MAX_REQUEST_BODY);
/// Reported prompt tokens at or above this share of [`FILLER_TOKENS`] mean the prompt was not truncated.
pub const MIN_REPORTED_PERCENT: u64 = 85;
/// The fixed user line of round 1: a question one tool answers, with no data in it.
pub const PROBE_QUESTION: &str = "How many steps did I take on each of the last 7 days?";
/// One short sentence of 40 bytes, repeated to make the filler.
const FILLER_SENTENCE: &str = "The grass is green and the sky is blue. ";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolsSupport {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextVerdict {
    Ok,
    TooSmall,
    Unknown,
}

/// What the Settings card shows. Every field is a number, a bool, a closed word or a fixed code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeReport {
    pub reachable: bool,
    pub tools: ToolsSupport,
    pub context: ContextVerdict,
    pub measured_prompt_tokens: Option<u64>,
    pub status: Option<u16>,
    pub error: Option<&'static str>,
}

impl ProbeReport {
    fn new() -> ProbeReport {
        ProbeReport {
            reachable: false,
            tools: ToolsSupport::Unknown,
            context: ContextVerdict::Unknown,
            measured_prompt_tokens: None,
            status: None,
            error: None,
        }
    }

    /// Fold a failed round into the report: only the first problem is kept.
    fn note(&mut self, error: EgressError) {
        self.error.get_or_insert(error.code());
        if let EgressError::Status(status) = error {
            // an answer, even an error one, proves the endpoint is there
            self.reachable = true;
            self.status.get_or_insert(status);
            if matches!(status, 401 | 403) {
                self.error = Some("unauthorised");
            }
        }
    }

    fn unauthorised(&self) -> bool {
        self.error == Some("unauthorised")
    }
}

/// The synthetic filler: [`FILLER_BYTES`] bytes of one repeated ASCII sentence.
pub fn filler() -> String {
    let mut text = FILLER_SENTENCE.repeat(FILLER_BYTES / FILLER_SENTENCE.len() + 1);
    text.truncate(FILLER_BYTES);
    text
}

/// The smallest reported prompt size that counts as "not truncated".
pub fn min_reported_tokens() -> u64 {
    FILLER_TOKENS * MIN_REPORTED_PERCENT / 100
}

fn send(egress: &dyn Egress, endpoint: &Endpoint, bearer: Option<&Zeroizing<String>>, request: &ChatRequest) -> Result<Vec<u8>, EgressError> {
    let url = endpoint.join(CHAT_PATH)?;
    let body = request.to_body().map_err(|_| EgressError::BodyTooLarge)?;
    egress.send(Outbound { url, bearer: bearer.cloned(), body }).map(|inbound| inbound.body)
}

fn tools_verdict(body: &[u8]) -> Result<ToolsSupport, &'static str> {
    let reply = wire::parse_response(body).map_err(|e| e.code())?;
    let names_one = reply.tool_calls().iter().any(|call| SENDABLE_TOOLS.contains(&call.function.name.as_str()));
    Ok(if names_one { ToolsSupport::Yes } else { ToolsSupport::No })
}

/// `usage.prompt_tokens` read straight from the body (a reply with no text still reports it).
fn reported_prompt_tokens(body: &[u8]) -> Option<u64> {
    let root: Value = serde_json::from_slice(body).ok()?;
    root.get("usage")?.get("prompt_tokens")?.as_u64()
}

/// Run both rounds against `egress`. The settings name the model and the address; `bearer` is the key, if any.
pub fn probe(egress: &dyn Egress, settings: &Settings, bearer: Option<&Zeroizing<String>>) -> ProbeReport {
    let mut report = ProbeReport::new();
    let endpoint = match Endpoint::from_settings(settings) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            report.note(e);
            return report;
        }
    };
    let system = Message::System { content: system_prompt() };

    // round 1: does the model call a tool?
    let tools_request = ChatRequest::new(&settings.model, vec![system.clone(), Message::User { content: PROBE_QUESTION.to_string() }]);
    match send(egress, &endpoint, bearer, &tools_request) {
        Ok(body) => {
            report.reachable = true;
            match tools_verdict(&body) {
                Ok(verdict) => report.tools = verdict,
                Err(code) => report.error = Some(code),
            }
        }
        Err(e) => {
            report.note(e);
            if report.unauthorised() || !report.reachable {
                return report;
            }
        }
    }

    // round 2: how much of a long prompt does the server read?
    let context_request = ChatRequest::without_tools(&settings.model, vec![system, Message::User { content: filler() }], 1);
    match send(egress, &endpoint, bearer, &context_request) {
        Ok(body) => {
            report.reachable = true;
            report.measured_prompt_tokens = reported_prompt_tokens(&body);
            report.context = match report.measured_prompt_tokens {
                None => ContextVerdict::Unknown,
                Some(tokens) if tokens >= min_reported_tokens() => ContextVerdict::Ok,
                Some(_) => ContextVerdict::TooSmall,
            };
        }
        Err(e) => report.note(e),
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filler_is_exactly_the_size_the_constants_say_and_plain_ascii() {
        let text = filler();
        assert_eq!(text.len(), FILLER_BYTES);
        assert_eq!(FILLER_BYTES, 48_000);
        assert!(text.is_ascii());
        assert_eq!(min_reported_tokens(), 10_200);
    }
}
