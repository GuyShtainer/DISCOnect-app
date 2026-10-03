// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `serve` wire format as the Python oracle speaks it: `json.loads` on the way in, ASCII-only
//! `json.dumps(separators=(",", ":"))` on the way out.
//!
//! `serde_json` is stricter than Python's reader in ways a sidecar client could observe, so the
//! request side is parsed by hand: `NaN`, `Infinity` and `-Infinity` are values; integers are
//! arbitrary-precision (a request id beyond `u64` is echoed back digit for digit); `1e400` is an
//! infinite float; a lone `\ud800` escape is kept (strings are UTF-16 code units); duplicate keys
//! keep the last value; Python's 4300-digit integer limit is a parse failure. Where Python itself
//! gives up in a way that is not a clean error (nesting past the interpreter's recursion limit
//! crashes the oracle), this reader refuses at a fixed depth instead.

use serde_json::Value;

/// Python 3.11+ refuses `int()` on strings of more than this many digits (`ValueError`).
const MAX_INT_DIGITS: usize = 4300;
/// Deeper than any real request; the oracle would die with a `RecursionError` long before.
const MAX_DEPTH: usize = 512;

/// A JSON string as Python holds it: code points, but lone surrogates are legal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyStr(Vec<u16>);

impl PyStr {
    pub fn from_units(units: Vec<u16>) -> PyStr {
        PyStr(units)
    }

    /// The UTF-16 code units, lone surrogates included.
    pub fn units(&self) -> impl Iterator<Item = u16> + '_ {
        self.0.iter().copied()
    }

    pub fn from_text(text: &str) -> PyStr {
        PyStr(text.encode_utf16().collect())
    }

    /// The text, or `None` when it holds a lone surrogate (Python would fail to encode it).
    pub fn to_text(&self) -> Option<String> {
        String::from_utf16(&self.0).ok()
    }

    /// The text with each lone surrogate replaced by U+FFFD (for a message that cannot carry it).
    pub fn units_lossy(&self) -> String {
        String::from_utf16_lossy(&self.0)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn equals(&self, text: &str) -> bool {
        self.0.iter().copied().eq(text.encode_utf16())
    }
}

/// A JSON integer of any size: its canonical decimal text (`-0` is `0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyInt(String);

impl PyInt {
    pub fn text(&self) -> &str {
        &self.0
    }

    /// An `i64` as the integer Python would hold.
    pub fn from_i64(value: i64) -> PyInt {
        PyInt(value.to_string())
    }

    /// An integer of any size from its sign and its ASCII digits (leading zeros dropped, `-0` is `0`);
    /// `None` for no digits or a character that is not an ASCII digit.
    pub fn from_decimal(negative: bool, digits: &str) -> Option<PyInt> {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let trimmed = digits.trim_start_matches('0');
        Some(PyInt(match (trimmed.is_empty(), negative) {
            (true, _) => "0".to_string(),
            (false, true) => format!("-{trimmed}"),
            (false, false) => trimmed.to_string(),
        }))
    }

    /// The value when it fits an `i64`.
    pub fn to_i64(&self) -> Option<i64> {
        self.0.parse().ok()
    }

    /// The value clamped to the `i64` range (a window of 10^30 days is "as many as allowed").
    pub fn clamped_i64(&self) -> i64 {
        self.to_i64().unwrap_or(if self.0.starts_with('-') {
            i64::MIN
        } else {
            i64::MAX
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(PyInt),
    Float(f64),
    Str(PyStr),
    Array(Vec<Json>),
    Object(Vec<(PyStr, Json)>),
}

impl Json {
    /// A `str` value.
    pub fn text(text: &str) -> Json {
        Json::Str(PyStr::from_text(text))
    }

    /// An `int` value.
    pub fn int(value: i64) -> Json {
        Json::Int(PyInt::from_i64(value))
    }

    /// An `int` value from a count.
    pub fn count(value: usize) -> Json {
        Json::int(i64::try_from(value).unwrap_or(i64::MAX))
    }

    /// An empty `dict`; fill it with [`Json::set`] to keep Python's insertion order.
    pub fn dict() -> Json {
        Json::Object(Vec::new())
    }

    /// `dict[key] = value`: a new key goes last, an existing key keeps its place. Does nothing to a
    /// value that is not an object.
    pub fn set(&mut self, key: &str, value: Json) {
        if let Json::Object(pairs) = self {
            match pairs.iter_mut().find(|(name, _)| name.equals(key)) {
                Some(slot) => slot.1 = value,
                None => pairs.push((PyStr::from_text(key), value)),
            }
        }
    }

    /// The same tree as a `serde_json` value (objects sorted by key, a lone surrogate replaced), or
    /// `None` where it holds a float JSON cannot carry or an integer beyond 64 bits.
    pub fn to_serde(&self) -> Option<Value> {
        Some(match self {
            Json::Null => Value::Null,
            Json::Bool(flag) => Value::Bool(*flag),
            Json::Int(int) => Value::from(int.to_i64()?),
            Json::Float(number) => Value::Number(serde_json::Number::from_f64(*number)?),
            Json::Str(text) => Value::String(text.units_lossy()),
            Json::Array(items) => Value::Array(
                items.iter().map(Json::to_serde).collect::<Option<Vec<_>>>()?,
            ),
            Json::Object(pairs) => Value::Object(
                pairs
                    .iter()
                    .map(|(key, item)| Some((key.units_lossy(), item.to_serde()?)))
                    .collect::<Option<serde_json::Map<_, _>>>()?,
            ),
        })
    }

    /// `dict.get`: the last value stored under `key`.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(pairs) => pairs
                .iter()
                .rev()
                .find(|(k, _)| k.equals(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}

/// The line is not JSON as Python's `json.loads` reads it (its `ValueError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotJson;

/// Parse one request line the way `json.loads` does.
pub fn parse(text: &str) -> Result<Json, NotJson> {
    let mut reader = Reader {
        bytes: text.as_bytes(),
        at: 0,
    };
    reader.skip_space();
    let value = reader.value(0)?;
    reader.skip_space();
    if reader.at == reader.bytes.len() {
        Ok(value)
    } else {
        Err(NotJson)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn eat(&mut self, literal: &str) -> bool {
        if self.bytes[self.at..].starts_with(literal.as_bytes()) {
            self.at += literal.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, NotJson> {
        if depth > MAX_DEPTH {
            return Err(NotJson);
        }
        match self.peek().ok_or(NotJson)? {
            b'"' => Ok(Json::Str(self.string()?)),
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'n' if self.eat("null") => Ok(Json::Null),
            b't' if self.eat("true") => Ok(Json::Bool(true)),
            b'f' if self.eat("false") => Ok(Json::Bool(false)),
            b'N' if self.eat("NaN") => Ok(Json::Float(f64::NAN)),
            b'I' if self.eat("Infinity") => Ok(Json::Float(f64::INFINITY)),
            b'-' if self.eat("-Infinity") => Ok(Json::Float(f64::NEG_INFINITY)),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(NotJson),
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at - start
    }

    fn number(&mut self) -> Result<Json, NotJson> {
        let start = self.at;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(NotJson),
        }
        let int_end = self.at;
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            self.at += 1;
            if self.digits() == 0 {
                return Err(NotJson);
            }
            is_float = true;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if self.digits() == 0 {
                return Err(NotJson);
            }
            is_float = true;
        }
        let literal = std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| NotJson)?;
        if is_float {
            return literal.parse::<f64>().map(Json::Float).map_err(|_| NotJson);
        }
        let digits = &self.bytes[start + usize::from(negative)..int_end];
        if digits.len() > MAX_INT_DIGITS {
            return Err(NotJson);
        }
        let magnitude = std::str::from_utf8(digits).map_err(|_| NotJson)?;
        let canonical = if negative && magnitude != "0" {
            format!("-{magnitude}")
        } else {
            magnitude.to_string()
        };
        Ok(Json::Int(PyInt(canonical)))
    }

    fn hex4(&mut self) -> Result<u16, NotJson> {
        let chunk = self.bytes.get(self.at..self.at + 4).ok_or(NotJson)?;
        let mut unit = 0u16;
        for byte in chunk {
            let digit = (*byte as char).to_digit(16).ok_or(NotJson)?;
            unit = unit * 16 + digit as u16;
        }
        self.at += 4;
        Ok(unit)
    }

    fn string(&mut self) -> Result<PyStr, NotJson> {
        self.at += 1; // opening quote
        let mut units: Vec<u16> = Vec::new();
        loop {
            let byte = self.peek().ok_or(NotJson)?;
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(PyStr(units));
                }
                0..=0x1f => return Err(NotJson),
                b'\\' => {
                    self.at += 1;
                    let escape = self.peek().ok_or(NotJson)?;
                    self.at += 1;
                    match escape {
                        b'"' => units.push(u16::from(b'"')),
                        b'\\' => units.push(u16::from(b'\\')),
                        b'/' => units.push(u16::from(b'/')),
                        b'b' => units.push(8),
                        b'f' => units.push(12),
                        b'n' => units.push(10),
                        b'r' => units.push(13),
                        b't' => units.push(9),
                        b'u' => {
                            let unit = self.hex4()?;
                            units.push(unit);
                            // a high surrogate directly followed by a low one is one code point;
                            // any other unit stays as it is (the unit just pushed may be lone).
                            if (0xd800..=0xdbff).contains(&unit)
                                && self.bytes[self.at..].starts_with(b"\\u")
                                && let Some(next) = self.peek_low_surrogate()
                            {
                                units.push(next);
                                self.at += 6;
                            }
                        }
                        _ => return Err(NotJson),
                    }
                }
                _ => {
                    // valid UTF-8 by construction (the input is a `&str`): copy one scalar, looking at
                    // its own bytes only (validating the whole rest of the text per character is
                    // quadratic: a 3 MB fixture took a minute)
                    let width = match byte {
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xff => 4,
                        _ => 1,
                    };
                    let scalar = self.bytes.get(self.at..self.at + width).ok_or(NotJson)?;
                    let rest = std::str::from_utf8(scalar).map_err(|_| NotJson)?;
                    let c = rest.chars().next().ok_or(NotJson)?;
                    let mut buffer = [0u16; 2];
                    units.extend_from_slice(c.encode_utf16(&mut buffer));
                    self.at += c.len_utf8();
                }
            }
        }
    }

    /// The low surrogate in the `\uXXXX` escape at the cursor, if that is what it is.
    fn peek_low_surrogate(&self) -> Option<u16> {
        let digits = self.bytes.get(self.at + 2..self.at + 6)?;
        let mut unit = 0u16;
        for byte in digits {
            unit = unit * 16 + (*byte as char).to_digit(16)? as u16;
        }
        (0xdc00..=0xdfff).contains(&unit).then_some(unit)
    }

    fn array(&mut self, depth: usize) -> Result<Json, NotJson> {
        self.at += 1;
        let mut items = Vec::new();
        self.skip_space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_space();
            items.push(self.value(depth + 1)?);
            self.skip_space();
            match self.peek().ok_or(NotJson)? {
                b',' => self.at += 1,
                b']' => {
                    self.at += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(NotJson),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, NotJson> {
        self.at += 1;
        let mut pairs = Vec::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Json::Object(pairs));
        }
        loop {
            self.skip_space();
            if self.peek() != Some(b'"') {
                return Err(NotJson);
            }
            let key = self.string()?;
            self.skip_space();
            if self.peek() != Some(b':') {
                return Err(NotJson);
            }
            self.at += 1;
            self.skip_space();
            pairs.push((key, self.value(depth + 1)?));
            self.skip_space();
            match self.peek().ok_or(NotJson)? {
                b',' => self.at += 1,
                b'}' => {
                    self.at += 1;
                    return Ok(Json::Object(pairs));
                }
                _ => return Err(NotJson),
            }
        }
    }
}

// ---- output: json.dumps(ensure_ascii=True, separators=(",", ":")) ----

/// Append `units` as a JSON string literal, ASCII only (everything outside space..`~` is `\uXXXX`).
pub fn write_string(out: &mut String, units: impl IntoIterator<Item = u16>) {
    out.push('"');
    for unit in units {
        match unit {
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            0x0a => out.push_str("\\n"),
            0x0d => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            0x20..=0x7e => out.push(char::from(unit as u8)),
            other => out.push_str(&format!("\\u{other:04x}")),
        }
    }
    out.push('"');
}

/// Append a string value.
pub fn write_text(out: &mut String, text: &str) {
    write_string(out, text.encode_utf16());
}

/// Append a `serde_json` value in the oracle's compact, ASCII-only form.
pub fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(text) => write_text(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_text(out, key);
                out.push(':');
                write_value(out, item);
            }
            out.push('}');
        }
    }
}

/// Append `json` as `json.dumps` writes it with `ensure_ascii=True`: compact (`,` and `:`) when `indent` is
/// `None`, else one item per line indented by `indent` spaces per level (`indent=2`). Objects keep the order
/// they hold; a float is its `repr` and a non-finite one a bare word; an empty list or object is `[]` or `{}`.
pub fn write_json(out: &mut String, json: &Json, indent: Option<usize>) {
    write_level(out, json, indent, 0);
}

fn write_level(out: &mut String, json: &Json, indent: Option<usize>, level: usize) {
    let newline = |out: &mut String, depth: usize| {
        if let Some(step) = indent {
            out.push('\n');
            out.push_str(&" ".repeat(step * depth));
        }
    };
    match json {
        Json::Null => out.push_str("null"),
        Json::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Json::Int(int) => out.push_str(int.text()),
        Json::Float(x) if x.is_nan() => out.push_str("NaN"),
        Json::Float(x) if x.is_infinite() => out.push_str(if *x > 0.0 { "Infinity" } else { "-Infinity" }),
        Json::Float(x) => out.push_str(&crate::canon::py_float_repr(*x)),
        Json::Str(text) => write_string(out, text.units()),
        Json::Array(items) if items.is_empty() => out.push_str("[]"),
        Json::Object(pairs) if pairs.is_empty() => out.push_str("{}"),
        Json::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                out.push_str(if index == 0 { "" } else { "," });
                newline(out, level + 1);
                write_level(out, item, indent, level + 1);
            }
            newline(out, level);
            out.push(']');
        }
        Json::Object(pairs) => {
            out.push('{');
            for (index, (key, item)) in pairs.iter().enumerate() {
                out.push_str(if index == 0 { "" } else { "," });
                newline(out, level + 1);
                write_string(out, key.units());
                out.push_str(if indent.is_some() { ": " } else { ":" });
                write_level(out, item, indent, level + 1);
            }
            newline(out, level);
            out.push('}');
        }
    }
}

/// A `serde_json` value as the ordered wire value (object keys in the order `serde_json` holds them, sorted).
pub fn from_serde(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Number(number) => match (number.as_i64(), number.as_u64()) {
            (Some(int), _) => Json::int(int),
            (None, Some(big)) => PyInt::from_decimal(false, &big.to_string()).map_or(Json::Null, Json::Int),
            _ => Json::Float(number.as_f64().unwrap_or(f64::NAN)),
        },
        Value::String(text) => Json::text(text),
        Value::Array(items) => Json::Array(items.iter().map(from_serde).collect()),
        Value::Object(map) => Json::Object(map.iter().map(|(k, v)| (PyStr::from_text(k), from_serde(v))).collect()),
    }
}

/// Append a request id exactly as received.
pub fn write_json_id(out: &mut String, id: &Id) {
    match id {
        Id::None => out.push_str("null"),
        Id::Int(int) => out.push_str(int.text()),
        Id::Str(text) => write_string(out, text.0.iter().copied()),
    }
}

/// A request id: an integer of any size, a string, or (on an error with no readable id) null.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Id {
    None,
    Int(PyInt),
    Str(PyStr),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn int(text: &str) -> Json {
        Json::Int(PyInt(text.to_string()))
    }

    #[test]
    fn python_only_constants_and_big_numbers_parse() {
        assert!(matches!(parse("NaN"), Ok(Json::Float(f)) if f.is_nan()));
        assert_eq!(parse("-Infinity"), Ok(Json::Float(f64::NEG_INFINITY)));
        assert_eq!(parse("1e400"), Ok(Json::Float(f64::INFINITY)));
        assert_eq!(parse("-0"), Ok(int("0")));
        assert_eq!(
            parse("123456789012345678901234567890"),
            Ok(int("123456789012345678901234567890"))
        );
        assert_eq!(parse(&format!("1{}", "0".repeat(4299))).map(|_| ()), Ok(()));
        assert_eq!(
            parse(&format!("1{}", "0".repeat(4300))),
            Err(NotJson),
            "4301 digits: Python's int limit"
        );
        assert_eq!(parse("1.5e3"), Ok(Json::Float(1500.0)));
    }

    #[test]
    fn malformed_text_is_an_error_like_python() {
        for bad in [
            "",
            " ",
            "01",
            "1.",
            ".5",
            "1e",
            "-",
            "+1",
            "[1,]",
            "{\"a\":1,}",
            "{1:2}",
            "'a'",
            "nul",
            "[1] x",
            "\"a\nb\"",
            "\"\\x\"",
            "\"\\u12\"",
            "tru",
            "NaN1",
            "\u{feff}{}",
            "[",
            "{\"a\"}",
        ] {
            assert_eq!(parse(bad), Err(NotJson), "{bad:?}");
        }
        assert_eq!(parse(&"[".repeat(600)), Err(NotJson));
    }

    #[test]
    fn strings_keep_lone_surrogates_and_join_pairs() {
        let Ok(Json::Str(lone)) = parse(r#""\ud800x""#) else {
            unreachable!()
        };
        assert_eq!(lone.to_text(), None);
        let Ok(Json::Str(pair)) = parse(r#""\ud83d\ude00""#) else {
            unreachable!()
        };
        assert_eq!(pair.to_text().as_deref(), Some("\u{1f600}"));
        let mut line = String::new();
        write_string(&mut line, lone.0.iter().copied());
        assert_eq!(line, r#""\ud800x""#);
        assert!(parse("\"tab\\tquote\\\" slash\\/ \u{e9}\"").is_ok());
    }

    #[test]
    fn objects_keep_the_last_duplicate_and_whitespace_is_json_whitespace() {
        let Ok(object) = parse(" \t{\"id\": 1, \"id\": \"two\"}\r\n") else {
            unreachable!()
        };
        assert_eq!(object.get("id"), Some(&Json::Str(PyStr::from_text("two"))));
        assert_eq!(
            parse("\u{a0}{}"),
            Err(NotJson),
            "a no-break space is not JSON whitespace"
        );
    }

    #[test]
    fn output_is_compact_and_ascii_only() {
        let mut out = String::new();
        write_value(
            &mut out,
            &json!({"a": [1, true, null, "caf\u{e9} \u{1f600} \u{7f} \"q\"\n"]}),
        );
        assert_eq!(
            out,
            r#"{"a":[1,true,null,"caf\u00e9 \ud83d\ude00 \u007f \"q\"\n"]}"#
        );
        assert!(out.is_ascii());
    }

    #[test]
    fn json_dumps_indent_two_and_compact_match_python() {
        let Ok(tree) = parse(
            r#"{"a":[1,2.5,{"b":null}],"c":{},"d":[],"\u00e9":"x\n\u2028\ud83d\ude00","f":1e16,"g":1e-5,"h":100.0,"i":true,"j":-0.0}"#,
        ) else {
            unreachable!()
        };
        let mut pretty = String::new();
        write_json(&mut pretty, &tree, Some(2));
        assert_eq!(
            pretty,
            "{\n  \"a\": [\n    1,\n    2.5,\n    {\n      \"b\": null\n    }\n  ],\n  \"c\": {},\n  \"d\": [],\n  \"\\u00e9\": \"x\\n\\u2028\\ud83d\\ude00\",\n  \"f\": 1e+16,\n  \"g\": 1e-05,\n  \"h\": 100.0,\n  \"i\": true,\n  \"j\": -0.0\n}"
        );
        let mut compact = String::new();
        write_json(&mut compact, &tree, None);
        assert_eq!(
            compact,
            r#"{"a":[1,2.5,{"b":null}],"c":{},"d":[],"\u00e9":"x\n\u2028\ud83d\ude00","f":1e+16,"g":1e-05,"h":100.0,"i":true,"j":-0.0}"#
        );
        let mut words = String::new();
        write_json(&mut words, &Json::Array(vec![Json::Float(f64::NAN), Json::Float(f64::NEG_INFINITY)]), None);
        assert_eq!(words, "[NaN,-Infinity]");
    }

    #[test]
    fn decimal_integers_are_normalised_and_serde_values_convert() {
        assert_eq!(PyInt::from_decimal(true, "000").map(|i| i.text().to_string()).as_deref(), Some("0"));
        assert_eq!(PyInt::from_decimal(true, "007").map(|i| i.text().to_string()).as_deref(), Some("-7"));
        assert_eq!(PyInt::from_decimal(false, ""), None);
        assert_eq!(PyInt::from_decimal(false, "1_0"), None);
        let tree = from_serde(&json!({"n": 1, "f": 1.0, "big": 18446744073709551615u64, "s": "é", "l": [null, true]}));
        let mut out = String::new();
        write_json(&mut out, &tree, None);
        assert_eq!(out, r#"{"big":18446744073709551615,"f":1.0,"l":[null,true],"n":1,"s":"\u00e9"}"#);
    }
}
