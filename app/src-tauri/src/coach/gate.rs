// SPDX-License-Identifier: AGPL-3.0-or-later
//! The tool-call gate (Bet 15c slice 1, pitch section 1): the pure chain from already-clamped `tools.call`
//! arguments to a [`schema::Validated`] answer. [`super::chat_loop`] and [`super::handoff`] both call
//! [`gate_tool`] so a tool answer is scrubbed the same way whether it goes to the model or into a hand-off:
//! `call_tool` -> [`views::project_with`] -> [`caps::fit`] -> [`schema::validated`], in that order, with
//! nothing else in between.
//!
//! The caller is responsible for [`caps::clamp_with`] first: `gate_tool` sends `arguments` to `call_tool`
//! exactly as given, and never re-checks them against the coach's own limits.
//!
//! [`GateFailure`] is closed and carries no data from the answer: only where the chain stopped (the core, the
//! view, the byte cap or the schema) and, for a core failure, the fixed serve code.

use serde_json::Value;

use super::caps::{self, CapError};
use super::chat_loop::ToolCallError;
use super::schema::{self, Validated};
use super::views::{self, ViewOptions};
use super::wire::ServeCode;

/// Where [`gate_tool`] stopped, and why. Closed; no key, value or message from the answer ever rides on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateFailure {
    /// The core refused the call, or its answer was not shaped `{"result": ...}`: the serve code.
    ToolError(ServeCode),
    /// The view or the schema refused the answer. The fixed reason text, never the offending key or value.
    Withheld(&'static str),
    /// Every shrink step ran and the answer is still over its byte cap.
    TooLarge,
    /// Not one of the schema's sendable tools (the caller is expected to have checked this already).
    UnknownTool,
}

/// `call_tool(name, arguments)` -> [`views::project_with`] -> [`caps::fit`] -> [`schema::validated`], in that
/// order. `arguments` must already be inside the coach's limits ([`caps::clamp_with`]); this function does not
/// clamp them again.
pub fn gate_tool(
    name: &str,
    arguments: &Value,
    options: &ViewOptions,
    call_tool: &dyn Fn(&str, Value) -> Result<Value, ToolCallError>,
) -> Result<Validated, GateFailure> {
    let answer =
        call_tool(name, arguments.clone()).map_err(|error| GateFailure::ToolError(ServeCode::from_code(&error.code)))?;
    let Some(result) = answer.get("result") else {
        return Err(GateFailure::ToolError(ServeCode::ToolError));
    };
    let projected = views::project_with(name, result, options).map_err(|_| GateFailure::Withheld("view"))?;
    let fitted = caps::fit(name, &projected).map_err(|error| match error {
        CapError::StillTooLarge => GateFailure::TooLarge,
        CapError::UnknownTool => GateFailure::UnknownTool,
    })?;
    schema::validated(name, fitted).map_err(|refused| GateFailure::Withheld(refused.reason.text()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_good_answer_gates_through_to_a_validated_value() {
        let call = |_: &str, _: Value| -> Result<Value, ToolCallError> {
            Ok(json!({"name": "list_activities", "result": {"activities": []}}))
        };
        let validated = gate_tool("list_activities", &json!({}), &ViewOptions::default(), &call).expect("gates");
        assert_eq!(validated.as_value(), &json!({"activities": []}));
    }

    #[test]
    fn a_core_failure_is_a_tool_error_with_the_serve_code() {
        let call = |_: &str, _: Value| -> Result<Value, ToolCallError> { Err(ToolCallError { code: "locked".into() }) };
        assert_eq!(
            gate_tool("list_activities", &json!({}), &ViewOptions::default(), &call),
            Err(GateFailure::ToolError(ServeCode::Locked))
        );
    }

    #[test]
    fn a_missing_result_key_is_a_tool_error() {
        let call = |_: &str, _: Value| -> Result<Value, ToolCallError> { Ok(json!({"name": "list_activities"})) };
        assert_eq!(
            gate_tool("list_activities", &json!({}), &ViewOptions::default(), &call),
            Err(GateFailure::ToolError(ServeCode::ToolError))
        );
    }

    #[test]
    fn a_malformed_result_is_withheld() {
        let call = |_: &str, _: Value| -> Result<Value, ToolCallError> { Ok(json!({"name": "list_activities", "result": []})) };
        assert_eq!(
            gate_tool("list_activities", &json!({}), &ViewOptions::default(), &call),
            Err(GateFailure::Withheld("view"))
        );
    }

    #[test]
    fn a_schema_rejection_is_withheld_with_the_schemas_reason() {
        let call = |_: &str, _: Value| -> Result<Value, ToolCallError> {
            Ok(json!({"name": "list_activities", "result": {
                "activities": [{"start_utc": "2025-06-01T08:00:00Z", "source_scope": "not_a_scope"}]
            }}))
        };
        let err = gate_tool("list_activities", &json!({}), &ViewOptions::default(), &call).unwrap_err();
        assert_eq!(err, GateFailure::Withheld("a string outside the allowed vocabulary"));
    }

    #[test]
    fn a_name_outside_the_five_is_withheld_by_the_view_before_any_cap_or_schema_runs() {
        // `views::project_with` already refuses any name outside the five sendable tools, so
        // `GateFailure::UnknownTool` (from `caps::fit`'s own `CapError::UnknownTool`) can never actually surface
        // through this chain: by the time a name would reach `caps::fit`, the view has already let only one of
        // the five through, and every one of those five has a budget. The variant stays for the same reason the
        // original `run_call` kept its own `Err(CapError::UnknownTool)` arm: `caps::fit`'s `Result` has two
        // variants and both must be handled, even though only one is reachable here. Neither caller of
        // `gate_tool` ever names an unknown tool (`chat_loop` checks `SENDABLE_TOOLS` first; `handoff` only
        // ever names one of the five literals), so this is the gate alone, not the integrated chain.
        let call = |_: &str, _: Value| -> Result<Value, ToolCallError> { Ok(json!({"name": "not_a_tool", "result": {}})) };
        assert_eq!(
            gate_tool("not_a_tool", &json!({}), &ViewOptions::default(), &call),
            Err(GateFailure::Withheld("view"))
        );
    }
}
