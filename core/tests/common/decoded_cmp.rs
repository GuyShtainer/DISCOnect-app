// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compare a Rust `Decoded` (as JSON) with the Python oracle's canonical JSON.
//!
//! Rules: numbers compare as f64 exactly; a string pair where the oracle has all ASCII digits
//! and the Rust side has a non-numeric name is accepted and counted (fitparser's profile names
//! enum values fitdecode's older profile leaves numeric); `message_counts` is compared only on
//! the 16 handled messages plus `file_id`, and on the sum of all counts (the two parsers spell
//! unknown or newer message names differently). The first differing JSON path is reported.
#![allow(dead_code)]

use serde_json::Value;

/// The messages the decoder handles (`file_id` is one of the 16).
pub const HANDLED_MESSAGES: [&str; 16] = [
    "file_id",
    "monitoring_info",
    "monitoring",
    "monitoring_hr_data",
    "stress_level",
    "respiration_rate",
    "spo2_data",
    "sleep_level",
    "sleep_assessment",
    "event",
    "hrv_status_summary",
    "hrv_value",
    "skin_temp_overnight",
    "max_met_data",
    "timestamp_correlation",
    "session",
];

/// Compare `actual` with `expected`; `Err(path)` names the first difference (never values).
/// `digit_vs_name` is incremented for every accepted digit-versus-name string pair.
pub fn compare(expected: &Value, actual: &Value, digit_vs_name: &mut usize) -> Result<(), String> {
    walk("$", expected, actual, digit_vs_name)
}

fn walk(path: &str, expected: &Value, actual: &Value, count: &mut usize) -> Result<(), String> {
    match (expected, actual) {
        (Value::Null, Value::Null) => Ok(()),
        (Value::Bool(a), Value::Bool(b)) if a == b => Ok(()),
        (Value::Number(a), Value::Number(b)) => {
            if a.as_f64() == b.as_f64() {
                Ok(())
            } else {
                Err(path.to_string())
            }
        }
        (Value::String(a), Value::String(b)) => {
            if a == b {
                Ok(())
            } else if is_digits(a) && !is_digits(b) && !b.is_empty() {
                *count += 1;
                Ok(())
            } else {
                Err(path.to_string())
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                return Err(format!("{path}.len"));
            }
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                walk(&format!("{path}[{i}]"), x, y, count)?;
            }
            Ok(())
        }
        (Value::Object(a), Value::Object(b)) => {
            if path == "$.message_counts" {
                return compare_counts(path, a, b);
            }
            for key in a.keys().chain(b.keys()) {
                if !a.contains_key(key) || !b.contains_key(key) {
                    return Err(format!("{path}.{key}"));
                }
            }
            for (key, x) in a {
                walk(&format!("{path}.{key}"), x, &b[key], count)?;
            }
            Ok(())
        }
        _ => Err(path.to_string()),
    }
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn compare_counts(
    path: &str,
    expected: &serde_json::Map<String, Value>,
    actual: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    let get =
        |m: &serde_json::Map<String, Value>, k: &str| m.get(k).and_then(Value::as_u64).unwrap_or(0);
    for key in HANDLED_MESSAGES {
        if get(expected, key) != get(actual, key) {
            return Err(format!("{path}.{key}"));
        }
    }
    let sum =
        |m: &serde_json::Map<String, Value>| m.values().filter_map(Value::as_u64).sum::<u64>();
    if sum(expected) != sum(actual) {
        return Err(format!("{path}.<sum>"));
    }
    Ok(())
}

/// Compare a decode outcome with an `expected.json` document (`ok` or `error`).
pub fn compare_outcome(
    expected: &Value,
    outcome: &Result<disconect_core::model::Decoded, disconect_core::fit::FitDecodeError>,
    digit_vs_name: &mut usize,
) -> Result<(), String> {
    let iso = |m: &Option<disconect_core::model::Instant>| match m {
        Some(m) => Value::String(m.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        None => Value::Null,
    };
    match (expected.get("ok"), expected.get("error"), outcome) {
        (Some(ok), _, Ok(decoded)) => {
            let actual = serde_json::to_value(decoded).map_err(|_| "$.serialize".to_string())?;
            compare(ok, &actual, digit_vs_name)
        }
        (_, Some(error), Err(e)) => {
            let actual = serde_json::json!({
                "kind": e.kind,
                "stream": e.stream,
                "start_utc": iso(&e.start_utc),
                "end_utc": iso(&e.end_utc),
            });
            compare(error, &actual, digit_vs_name)
        }
        (Some(_), _, Err(_)) => Err("$.expected-ok-but-error".to_string()),
        (_, Some(_), Ok(_)) => Err("$.expected-error-but-ok".to_string()),
        _ => Err("$.expected-shape".to_string()),
    }
}
