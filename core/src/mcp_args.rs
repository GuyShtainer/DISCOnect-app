// SPDX-License-Identifier: AGPL-3.0-or-later
//! The arguments of an MCP `tools/call` as the Python server coerces them: FastMCP's JSON pre-parse of a
//! string argument, then pydantic's lax validation of each declared parameter (Bet 11e, slice 2).
//! `mcp.json` holds the table measured on the wire (`coercions`); a test replays all of it.
//!
//! * a string argument whose declared type is not plain `str` is first `json.loads`-ed; a result that is
//!   `null`, a list or an object replaces it (a string, number or bool leaves the string alone);
//! * `int`: an int, a bool, a float with no fraction inside the `i64` range, or a string of `[+-]digits`
//!   (single `_` between digits, optionally `.0...`) after trimming white space;
//! * `bool`: a bool, `0`/`1`, `0.0`/`1.0`, or a word of `0 off f false n no` / `1 on t true y yes` in any case;
//! * `str | None` and `list[str] | None`: `null` is `None`; `list[str]`: a list of strings.
//!
//! Unknown keys are ignored and a repeated key keeps its last value (the wire reader does both). A
//! rejection names the parameter and a reason, never the value.

use crate::wirejson::{self, Json, PyInt, PyStr};

/// What a tool parameter is declared as, with its default where it has one.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Int(i64),
    OptStr,
    Bool(bool),
    /// `list[str]`, required.
    Strs,
    OptStrs,
}

#[derive(Debug, Clone, Copy)]
pub struct Param {
    pub name: &'static str,
    pub kind: Kind,
}

/// A coerced argument, in the order of the tool's parameters.
#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    Int(PyInt),
    Str(Option<PyStr>),
    Bool(bool),
    List(Option<Vec<PyStr>>),
}

/// `json.loads` of a string argument, kept only when FastMCP would use it: `null`, a list or an object.
fn preparsed(text: &PyStr) -> Option<Json> {
    let parsed = wirejson::parse(&text.to_text()?).ok()?;
    matches!(parsed, Json::Null | Json::Array(_) | Json::Object(_)).then_some(parsed)
}

/// `[+-]?digits` with a single `_` allowed between digits, then optionally `.` and only zeros.
fn int_from_text(raw: &str) -> Option<PyInt> {
    let trimmed = raw.trim();
    if trimmed.len() > 4300 {
        return None;
    }
    let whole = match trimmed.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() && fraction.bytes().all(|b| b == b'0') => {
            whole
        }
        Some(_) => return None,
        None => trimmed,
    };
    let (negative, body) = match whole.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, whole.strip_prefix('+').unwrap_or(whole)),
    };
    if body.split('_').any(str::is_empty) {
        return None;
    }
    PyInt::from_decimal(negative, &body.replace('_', ""))
}

/// A float that is a whole number inside `i64` (the bounds are exact in `f64`).
fn int_from_float(x: f64) -> Option<PyInt> {
    const LIMIT: f64 = 9_223_372_036_854_775_808.0;
    (x.is_finite() && x.fract() == 0.0 && (-LIMIT..LIMIT).contains(&x))
        .then(|| PyInt::from_i64(x as i64))
}

fn int_arg(value: &Json) -> Option<PyInt> {
    match value {
        Json::Int(int) => Some(int.clone()),
        Json::Bool(flag) => Some(PyInt::from_i64(i64::from(*flag))),
        Json::Float(x) => int_from_float(*x),
        Json::Str(text) => int_from_text(&text.to_text()?),
        _ => None,
    }
}

fn bool_arg(value: &Json) -> Option<bool> {
    const FALSE: [&str; 6] = ["0", "off", "f", "false", "n", "no"];
    const TRUE: [&str; 6] = ["1", "on", "t", "true", "y", "yes"];
    match value {
        Json::Bool(flag) => Some(*flag),
        Json::Int(int) => match int.text() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        },
        Json::Float(x) if *x == 0.0 => Some(false),
        Json::Float(x) if *x == 1.0 => Some(true),
        Json::Str(text) => {
            let word = text.to_text()?;
            let is = |list: &[&str]| list.iter().any(|w| word.eq_ignore_ascii_case(w));
            if is(&FALSE) {
                Some(false)
            } else if is(&TRUE) {
                Some(true)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn strings(items: &[Json]) -> Option<Vec<PyStr>> {
    items
        .iter()
        .map(|item| match item {
            Json::Str(text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn coerce_one(kind: Kind, value: Option<&Json>) -> Result<Arg, &'static str> {
    let Some(value) = value else {
        return match kind {
            Kind::Int(default) => Ok(Arg::Int(PyInt::from_i64(default))),
            Kind::Bool(default) => Ok(Arg::Bool(default)),
            Kind::OptStr => Ok(Arg::Str(None)),
            Kind::OptStrs => Ok(Arg::List(None)),
            Kind::Strs => Err("Field required"),
        };
    };
    match kind {
        Kind::Int(_) => int_arg(value)
            .map(Arg::Int)
            .ok_or("Input should be a valid integer"),
        Kind::Bool(_) => bool_arg(value)
            .map(Arg::Bool)
            .ok_or("Input should be a valid boolean"),
        Kind::OptStr => match value {
            Json::Null => Ok(Arg::Str(None)),
            Json::Str(text) => match preparsed(text) {
                None => Ok(Arg::Str(Some(text.clone()))),
                Some(Json::Null) => Ok(Arg::Str(None)),
                Some(_) => Err("Input should be a valid string"),
            },
            _ => Err("Input should be a valid string"),
        },
        Kind::Strs | Kind::OptStrs => {
            let optional = matches!(kind, Kind::OptStrs);
            let parsed = match value {
                Json::Str(text) => preparsed(text),
                other => Some(other.clone()),
            };
            match parsed {
                Some(Json::Null) if optional => Ok(Arg::List(None)),
                Some(Json::Array(items)) => strings(&items)
                    .map(|list| Arg::List(Some(list)))
                    .ok_or("Input should be a valid string"),
                _ => Err("Input should be a valid list"),
            }
        }
    }
}

/// Coerce every parameter of a tool from the `arguments` object; `Err` lists each rejected parameter
/// with its reason, in parameter order.
pub fn coerce(
    params: &[Param],
    arguments: &Json,
) -> Result<Vec<Arg>, Vec<(&'static str, &'static str)>> {
    let mut coerced = Vec::with_capacity(params.len());
    let mut rejected = Vec::new();
    for param in params {
        match coerce_one(param.kind, arguments.get(param.name)) {
            Ok(arg) => coerced.push(arg),
            Err(reason) => rejected.push((param.name, reason)),
        }
    }
    if rejected.is_empty() {
        Ok(coerced)
    } else {
        Err(rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_int(text: &str) -> Option<String> {
        int_from_text(text).map(|i| i.text().to_string())
    }

    #[test]
    fn integers_from_text_follow_pydantic() {
        for (input, want) in [
            ("3", Some("3")),
            (" 3 ", Some("3")),
            ("+3", Some("3")),
            ("-007", Some("-7")),
            ("1_000", Some("1000")),
            ("1_0.0", Some("10")),
            ("3.00", Some("3")),
            ("3\u{a0}", Some("3")),
            ("99999999999999999999999", Some("99999999999999999999999")),
            ("3.", None),
            (".5", None),
            ("3.5", None),
            ("1e2", None),
            ("1__0", None),
            ("_1", None),
            ("1_", None),
            ("--3", None),
            ("- 3", None),
            ("\u{663}", None),
            ("", None),
            ("0x10", None),
        ] {
            assert_eq!(text_int(input).as_deref(), want, "{input:?}");
        }
    }

    #[test]
    fn floats_and_bools_follow_pydantic() {
        assert_eq!(
            int_from_float(2.0).map(|i| i.text().to_string()).as_deref(),
            Some("2")
        );
        assert_eq!(
            int_from_float(-0.0)
                .map(|i| i.text().to_string())
                .as_deref(),
            Some("0")
        );
        assert!(
            int_from_float(2.5).is_none()
                && int_from_float(1e23).is_none()
                && int_from_float(f64::NAN).is_none()
        );
        assert!(int_from_float(9_223_372_036_854_775_808.0).is_none());
        assert!(int_from_float(-9_223_372_036_854_775_808.0).is_some());
        let word = |text: &str| bool_arg(&Json::text(text));
        assert_eq!(
            (word("tRuE"), word("OFF"), word("y"), word("0")),
            (Some(true), Some(false), Some(true), Some(false))
        );
        assert_eq!(
            (word(" true"), word("2"), word("1.0"), word("")),
            (None, None, None, None)
        );
        assert_eq!(bool_arg(&Json::Float(1.0)), Some(true));
        assert_eq!(bool_arg(&Json::int(2)), None);
    }
}
