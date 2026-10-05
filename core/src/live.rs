// SPDX-License-Identifier: AGPL-3.0-or-later
//! Live-link session files (`live-*.jsonl`) as one retained raw record each; nothing is derived
//! (the twin of `ingest/live.py`, bet 9b).
//!
//! A live file holds one JSON object per line: a reading `{"t": number, "metric": str, "value": int}`
//! or a status line (a `status` or `stop` key). The record keeps the readings only.

use std::cmp::Ordering;

use sha2::{Digest, Sha256};

use crate::canon::{self, Value};
use crate::export::{Decode, DecodeError, Keyed, Obj, epoch_s_to_utc};
use crate::model::Decoded;

pub const STREAM: &str = "json:live";

/// Python's `str.splitlines()` boundaries.
fn is_line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// Python's `str.isspace` (Rust's `is_whitespace` plus the C0 separators `\x1c`-`\x1f`).
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// `[line for line in text.splitlines() if line.strip()]`.
fn non_empty_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        if !is_line_break(c) {
            continue;
        }
        lines.push(&text[start..at]);
        let mut end = at + c.len_utf8();
        if c == '\r' && matches!(chars.peek(), Some((_, '\n'))) {
            chars.next();
            end += 1;
        }
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines.retain(|line| !line.chars().all(is_py_space));
    lines
}

fn is_number(value: &Value) -> bool {
    matches!(value, Value::Int(_) | Value::Float(_))
}

/// A reading's three fields have the shapes the rule asks for: number, string, int (never bool).
fn is_reading(t: &Value, metric: &Value, value: &Value) -> bool {
    is_number(t) && matches!(metric, Value::Str(_)) && matches!(value, Value::Int(_))
}

/// The readings `[t, metric, value]` of a live file, or `None` when `data` is not one (the oracle's
/// `parse_live_file`). A status-only file returns an empty list. JSON this port refuses
/// (`canon::parse` `Unsupported`: NaN, integers past i64, lone surrogates) makes the file not live.
pub fn parse_live_file(data: &[u8]) -> Option<Vec<Vec<Value>>> {
    let lines = non_empty_lines(std::str::from_utf8(data).ok()?);
    if lines.is_empty() {
        return None;
    }
    let mut readings = Vec::new();
    for line in lines {
        let Value::Object(members) = canon::parse(line.as_bytes()).ok()? else {
            return None;
        };
        let get = |key: &str| members.iter().find(|(k, _)| k == key).map(|(_, v)| v);
        if let (Some(t), Some(metric), Some(value)) = (get("t"), get("metric"), get("value")) {
            if !is_reading(t, metric, value) {
                return None;
            }
            readings.push(vec![t.clone(), metric.clone(), value.clone()]);
        } else if get("status").is_none() && get("stop").is_none() {
            return None;
        }
    }
    Some(readings)
}

fn number(value: &Value) -> f64 {
    match value {
        Value::Int(i) => *i as f64,
        Value::Float(x) => *x,
        _ => f64::NAN,
    }
}

/// Python's numeric comparison (two ints compare exactly, anything else as floats).
fn compare_numbers(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x.cmp(y),
        _ => number(a).partial_cmp(&number(b)).unwrap_or(Ordering::Equal),
    }
}

fn compare_text(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Str(x), Value::Str(y)) => x.cmp(y),
        _ => Ordering::Equal,
    }
}

/// `canonical_payload`: the record `{"readings": [...]}`, readings sorted (stably) by `(t, metric, value)`.
pub fn canonical_record(mut readings: Vec<Vec<Value>>) -> Value {
    readings.sort_by(|a, b| {
        compare_numbers(&a[0], &b[0])
            .then_with(|| compare_text(&a[1], &b[1]))
            .then_with(|| compare_numbers(&a[2], &b[2]))
    });
    Value::Object(vec![("readings".to_string(), Value::Array(readings.into_iter().map(Value::Array).collect()))])
}

/// `decode_live_record`: `{"readings": [...]}` -> (sha256 hex of the canonical bytes, a `Decoded`
/// with the span and no canonical rows). No non-empty readings array is the oracle's `ValueError`;
/// a reading that is not `[number, str, int]` is refused (the oracle would raise `TypeError`).
pub fn decode_live_record(record: &Obj) -> Decode<Keyed> {
    let readings = match record.iter().find(|(k, _)| k == "readings") {
        Some((_, Value::Array(items))) if !items.is_empty() => items,
        _ => return Err(DecodeError::Abort("ValueError: live record without readings".to_string())),
    };
    let mut parsed = Vec::with_capacity(readings.len());
    for item in readings {
        match item {
            Value::Array(triple) if triple.len() == 3 && is_reading(&triple[0], &triple[1], &triple[2]) => {
                parsed.push(triple.clone());
            }
            _ => return Err(DecodeError::Refused("live record with a malformed reading".to_string())),
        }
    }
    let ordered = canonical_record(parsed);
    let (first, last) = match &ordered {
        Value::Object(members) => match &members[0].1 {
            Value::Array(sorted) => (sorted.first().cloned(), sorted.last().cloned()),
            _ => (None, None),
        },
        _ => (None, None),
    };
    let (Some(Value::Array(first)), Some(Value::Array(last))) = (first, last) else {
        return Ok(None);
    };
    let mut decoded = Decoded::new(STREAM, "device");
    decoded.start_utc = Some(epoch_s_to_utc(number(&first[0]))?);
    decoded.end_utc = Some(epoch_s_to_utc(number(&last[0]))?);
    Ok(Some((hex::encode(Sha256::digest(canon::dumps(&ordered))), decoded)))
}
