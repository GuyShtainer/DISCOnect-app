// SPDX-License-Identifier: AGPL-3.0-or-later
//! The hand-off to the user's own chat (Bet 15c, pitch sections 1, 3 and 8; legal review GO WITH CONDITIONS,
//! 2026-10-05). No network leaves this module: it builds a text block through the same gate the coach loop
//! uses ([`super::gate::gate_tool`]) and, separately, opens one of five fixed `https` sites in the system
//! browser (`/usr/bin/open`) so the person can paste the text into the chat they already use, signed in under
//! their own account. The app holds no login, no key and no session for any of the five, and never reads
//! back an answer.
//!
//! **What leaves is exactly what the coach would send.** [`build_text`] runs the five sendable tools through
//! [`super::caps::clamp_with`] and [`super::gate::gate_tool`], the identical chain `chat_loop.rs` uses before
//! a request, and renders the validated answers as one text block with the product name and the disclaimer.
//! A gate failure of any kind cancels the whole hand-off: nothing is returned ([`HandoffError`]).
//!
//! **The URL is unrepresentable, not validated.** [`ProviderId`] is a closed enum; [`site`] `match`es it to a
//! `&'static str` literal. No string URL is ever built from input, here or anywhere else: [`open_fixed_site`]
//! is the only function in this crate besides `sidecar.rs` that spawns a child process, and the one argument
//! it ever passes to `/usr/bin/open` is one of those five literals.
//!
//! This file touches neither [`super::settings`] nor [`super::key`] nor `super::provider`: the hand-off
//! works while the coach is off, and opens no network connection of its own.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use disconect_core::identity::{neutral_text, DISCLAIMER, PRODUCT};

use super::caps::{self, CoachArgs};
use super::chat_loop::ToolCallError;
use super::gate::{self, GateFailure};
use super::schema::Validated;
use super::views::ViewOptions;

// ---- the five providers ------------------------------------------------------------------------------

/// One of the five chats the hand-off can open. Closed; the IPC boundary carries this, never a URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderId {
    ChatGpt,
    Claude,
    Gemini,
    LeChat,
    DeepSeek,
}

/// The five providers, for an exhaustive pass over all of them (tests, and a future picker).
pub const PROVIDERS: [ProviderId; 5] =
    [ProviderId::ChatGpt, ProviderId::Claude, ProviderId::Gemini, ProviderId::LeChat, ProviderId::DeepSeek];

/// The one fixed `https` address [`open_fixed_site`] opens for `provider`. No scheme, host or path is ever
/// built from anything but this `match`.
pub fn site(provider: ProviderId) -> &'static str {
    match provider {
        ProviderId::ChatGpt => "https://chatgpt.com/",
        ProviderId::Claude => "https://claude.ai/new",
        ProviderId::Gemini => "https://gemini.google.com/app",
        ProviderId::LeChat => "https://chat.mistral.ai/chat",
        ProviderId::DeepSeek => "https://chat.deepseek.com/",
    }
}

/// The host of [`site`], for the card to show before the click.
pub fn host(provider: ProviderId) -> &'static str {
    match provider {
        ProviderId::ChatGpt => "chatgpt.com",
        ProviderId::Claude => "claude.ai",
        ProviderId::Gemini => "gemini.google.com",
        ProviderId::LeChat => "chat.mistral.ai",
        ProviderId::DeepSeek => "chat.deepseek.com",
    }
}

/// The plain product name shown next to the picker (no logo, no provider colour: pitch section 6).
pub fn name(provider: ProviderId) -> &'static str {
    match provider {
        ProviderId::ChatGpt => "ChatGPT",
        ProviderId::Claude => "Claude",
        ProviderId::Gemini => "Gemini",
        ProviderId::LeChat => "Le Chat",
        ProviderId::DeepSeek => "DeepSeek",
    }
}

// ---- opening the browser -----------------------------------------------------------------------------

/// Why the hand-off could not be built or opened. Closed; every message is fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffError {
    /// `window_days` was not 7, 28 or 90.
    BadWindow,
    /// The view or the schema refused a tool answer: nothing was built.
    Withheld,
    /// A tool answer would not fit even after shrinking.
    TooLarge,
    /// The core refused a tool call (or named a tool this chain does not know): the fixed serve code.
    Tool(&'static str),
    /// `/usr/bin/open` ran and exited with a non-zero status.
    OpenFailed,
    /// Not macOS: there is no fixed-site opener for this target.
    Unsupported,
}

impl HandoffError {
    /// A stable short code, for the frontend to switch on.
    pub fn code(&self) -> &'static str {
        match self {
            HandoffError::BadWindow => "bad_window",
            HandoffError::Withheld => "withheld",
            HandoffError::TooLarge => "tool_too_large",
            HandoffError::Tool(code) => code,
            HandoffError::OpenFailed => "open_failed",
            HandoffError::Unsupported => "unsupported",
        }
    }

    /// A fixed, user-facing message. Holds no key, url or body.
    pub fn message(&self) -> &'static str {
        match self {
            HandoffError::BadWindow => "the window must be 7, 28 or 90 days",
            HandoffError::Withheld => "a tool answer was withheld; nothing was built",
            HandoffError::TooLarge => "a tool answer was too large to send, even after shrinking",
            HandoffError::Tool(_) => "a tool call failed while building the hand-off text",
            HandoffError::OpenFailed => "the browser could not be opened",
            HandoffError::Unsupported => "this computer has no fixed-site opener for a hand-off",
        }
    }
}

fn from_gate(failure: GateFailure) -> HandoffError {
    match failure {
        GateFailure::Withheld(_) => HandoffError::Withheld,
        GateFailure::TooLarge => HandoffError::TooLarge,
        GateFailure::ToolError(code) => HandoffError::Tool(code.code()),
        GateFailure::UnknownTool => HandoffError::Tool("unknown_tool"),
    }
}

/// Open `site(provider)` in the system browser: the one spawn in this file, and its only argument.
#[cfg(target_os = "macos")]
pub fn open_fixed_site(provider: ProviderId) -> Result<(), HandoffError> {
    use std::process::{Command, Stdio};
    let status = Command::new("/usr/bin/open")
        .arg(site(provider))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| HandoffError::OpenFailed)?;
    if status.success() {
        Ok(())
    } else {
        Err(HandoffError::OpenFailed)
    }
}

/// Not macOS: there is no fixed-site opener for this target.
#[cfg(not(target_os = "macos"))]
pub fn open_fixed_site(_provider: ProviderId) -> Result<(), HandoffError> {
    Err(HandoffError::Unsupported)
}

// ---- the text -----------------------------------------------------------------------------------------

/// `window_days` values [`build_text`] accepts.
const WINDOWS: [u8; 3] = [7, 28, 90];

/// Five daily metrics (one clean value per day), from the read contract: steps, the day's resting heart
/// rate, sleep length, the day's average stress and the day's highest energy reserve. Chosen for being a
/// single number per day; the loop's other metrics are sampled many times a day and would each need a mean,
/// min and max, which the hand-off's short window has no room for.
const METRIC_IDS: [&str; 5] = ["steps", "resting_heart_rate", "sleep_duration", "stress_avg", "energy_reserve_high"];

/// How much of the text was cut by the byte caps ([`caps::fit`]'s own counters, summed over the five answers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Shortened {
    /// How many answers were thinned (a series can be; the `thinned` key).
    pub thinned: usize,
    /// How many answers had a list cut (sleep's sessions or the activity list; the `truncated` key).
    pub truncated: usize,
    /// How many facts were dropped for carrying no value (`get_period_facts`'s `dropped_facts` key).
    pub dropped_facts: usize,
}

/// What [`build_text`] returns: the text ready to copy, its byte length, and how much of it was shortened.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HandoffText {
    pub text: String,
    pub bytes: usize,
    pub shortened: Shortened,
}

fn count_shortening(value: &Value, into: &mut Shortened) {
    if value.get("thinned").is_some() {
        into.thinned += 1;
    }
    if value.get("truncated").and_then(Value::as_u64).is_some_and(|n| n > 0) {
        into.truncated += 1;
    }
    if let Some(n) = value.get("dropped_facts").and_then(Value::as_u64) {
        into.dropped_facts += n as usize;
    }
}

/// The latest day across every source scope of a gated `get_data_health` answer's `sleep` block (its
/// `YYYY-MM-DD` day strings sort the same as the calendar, so the lexicographic maximum is the latest).
/// `None` when the answer carries no scope with a night at all.
fn latest_sleep_day(health: &Value) -> Option<String> {
    let sleep = health.get("sleep")?.as_object()?;
    sleep
        .values()
        .filter_map(Value::as_object)
        .filter_map(|scope| scope.get("last_day").and_then(Value::as_str))
        .max()
        .map(str::to_string)
}

/// The hand-off text: the five sendable tools, through the identical chain the coach loop sends through
/// ([`caps::clamp_with`] then [`gate::gate_tool`]), rendered as one block with the product name and the
/// disclaimer. `window_days` must be 7, 28 or 90; sleep detail is always the one latest night, never a
/// window. A gate failure of any kind cancels the whole hand-off: nothing is returned.
pub fn build_text(
    window_days: u8,
    include_points: bool,
    call_tool: &dyn Fn(&str, Value) -> Result<Value, ToolCallError>,
) -> Result<HandoffText, HandoffError> {
    if !WINDOWS.contains(&window_days) {
        return Err(HandoffError::BadWindow);
    }
    let days = i64::from(window_days);
    let limits = CoachArgs { include_points, series_days: days, health_window_days: days, ..CoachArgs::default() };
    let options = ViewOptions { include_points };
    let run = |tool: &'static str, arguments: Value| -> Result<Validated, HandoffError> {
        let clamped = caps::clamp_with(tool, &arguments, &limits);
        gate::gate_tool(tool, &clamped, &options, call_tool).map_err(from_gate)
    };

    let health = run("get_data_health", json!({"window_days": window_days}))?;
    let facts = run("get_period_facts", json!({}))?;
    let series = run("get_metric_series", json!({"metrics": METRIC_IDS, "days": window_days}))?;
    let night = latest_sleep_day(health.as_value());
    let sleep = match &night {
        Some(date) => Some(run("get_sleep_detail", json!({"date": date}))?),
        None => None,
    };
    let activities = run("list_activities", json!({"limit": 20}))?;

    let mut shortened = Shortened::default();
    let mut body = String::new();
    body.push_str(PRODUCT);
    body.push_str(" — a day-level summary of my own watch data, pasted by me\n");
    body.push_str(DISCLAIMER);
    body.push('\n');
    body.push_str(&format!("Window: the last {window_days} days; sleep detail: the latest night.\n"));

    let sections: [(&str, Option<&Validated>); 5] = [
        ("get_data_health", Some(&health)),
        ("get_period_facts", Some(&facts)),
        ("get_metric_series", Some(&series)),
        ("get_sleep_detail", sleep.as_ref()),
        ("list_activities", Some(&activities)),
    ];
    for (heading, validated) in sections {
        match validated {
            Some(v) => {
                count_shortening(v.as_value(), &mut shortened);
                body.push_str("\n## ");
                body.push_str(heading);
                body.push('\n');
                body.push_str(&v.compact());
                body.push('\n');
            }
            None => body.push_str("\nNo night was recorded in this window, so there is no sleep detail to add.\n"),
        }
    }

    if shortened.thinned + shortened.truncated + shortened.dropped_facts > 0 {
        body.push_str(&format!(
            "\n(shortened: {} series thinned, {} lists truncated, {} facts dropped)\n",
            shortened.thinned, shortened.truncated, shortened.dropped_facts
        ));
    }

    let text = neutral_text(&body);
    let bytes = text.len();
    Ok(HandoffText { text, bytes, shortened })
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn every_provider_has_a_name_a_host_and_one_fixed_plain_https_site() {
        for provider in PROVIDERS {
            let url = Url::parse(site(provider)).unwrap_or_else(|e| panic!("{provider:?}: {e}"));
            assert_eq!(url.scheme(), "https", "{provider:?}");
            assert_eq!(url.host_str(), Some(host(provider)), "{provider:?}");
            assert_eq!(url.port(), None, "{provider:?}");
            assert_eq!(url.query(), None, "{provider:?}");
            assert_eq!(url.fragment(), None, "{provider:?}");
            assert!(url.username().is_empty() && url.password().is_none(), "{provider:?}");
            assert!(!name(provider).is_empty(), "{provider:?}");
        }
    }

    #[test]
    fn the_five_providers_have_five_distinct_hosts_and_five_distinct_names() {
        let hosts: std::collections::BTreeSet<_> = PROVIDERS.iter().map(|p| host(*p)).collect();
        let names: std::collections::BTreeSet<_> = PROVIDERS.iter().map(|p| name(*p)).collect();
        assert_eq!(hosts.len(), PROVIDERS.len());
        assert_eq!(names.len(), PROVIDERS.len());
    }
}
