// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical JSON: the bytes the Python oracle stores for a JSON record,
//! `json.dumps(record, sort_keys=True, separators=(",", ":"))` (ASCII-escaped, Python float
//! `repr`), reproduced byte for byte, plus `py_str` (Python's `str()` of a scalar, used for source
//! keys).
//!
//! The parser is strict and owns its value type, so an int stays an int and a float stays a float
//! by the literal's text (`70.0` is a float, `70` an int), never by magnitude. Forms Python
//! accepts that the real export never uses are refused, not imitated: `NaN`/`Infinity`, integers
//! outside `i64`, floats that overflow, lone surrogate escapes and invalid UTF-8.

use std::collections::HashMap;

/// Deepest nesting the parser accepts (Python's own recursion limit is ~1000).
const MAX_DEPTH: usize = 512;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    /// Insertion order as parsed, duplicate keys already collapsed (last value wins); sorting
    /// happens when emitting.
    Object(Vec<(String, Value)>),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonError {
    /// Valid for Python, refused here on purpose; the reason is a stable constant.
    #[error("unsupported JSON: {0}")]
    Unsupported(&'static str),
    /// Not JSON.
    #[error("invalid JSON: {0}")]
    Syntax(&'static str),
}

// ---- parser ----

/// Parse strict JSON. A number is an `Int` iff its text has no `.`, `e` or `E`.
pub fn parse(bytes: &[u8]) -> Result<Value, CanonError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CanonError::Unsupported("invalid UTF-8"))?;
    let mut parser = Parser {
        src: text.as_bytes(),
        text,
        at: 0,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.at != parser.src.len() {
        return Err(CanonError::Syntax("trailing data"));
    }
    Ok(value)
}

struct Parser<'a> {
    src: &'a [u8],
    text: &'a str,
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.at).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn eat_literal(&mut self, word: &'static str) -> bool {
        if self.src[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, CanonError> {
        if depth > MAX_DEPTH {
            return Err(CanonError::Unsupported("nesting too deep"));
        }
        match self.peek() {
            None => Err(CanonError::Syntax("unexpected end")),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') if self.eat_literal("true") => Ok(Value::Bool(true)),
            Some(b'f') if self.eat_literal("false") => Ok(Value::Bool(false)),
            Some(b'n') if self.eat_literal("null") => Ok(Value::Null),
            Some(b'N') if self.src[self.at..].starts_with(b"NaN") => {
                Err(CanonError::Unsupported("NaN"))
            }
            Some(b'I') if self.src[self.at..].starts_with(b"Infinity") => {
                Err(CanonError::Unsupported("Infinity"))
            }
            Some(b'-') if self.src[self.at..].starts_with(b"-Infinity") => {
                Err(CanonError::Unsupported("-Infinity"))
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(CanonError::Syntax("unexpected character")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, CanonError> {
        self.at += 1; // {
        let mut members: Vec<(String, Value)> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(CanonError::Syntax("object key must be a string"));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(CanonError::Syntax("expected ':'"));
            }
            self.at += 1;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            match index.get(&key) {
                Some(&slot) => members[slot].1 = value,
                None => {
                    index.insert(key.clone(), members.len());
                    members.push((key, value));
                }
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(members));
                }
                _ => return Err(CanonError::Syntax("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, CanonError> {
        self.at += 1; // [
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(CanonError::Syntax("expected ',' or ']'")),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at - start
    }

    fn number(&mut self) -> Result<Value, CanonError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(CanonError::Syntax("bad number")),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            self.at += 1;
            is_float = true;
            if self.digits() == 0 {
                return Err(CanonError::Syntax("bad number"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            is_float = true;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if self.digits() == 0 {
                return Err(CanonError::Syntax("bad number"));
            }
        }
        let literal = &self.text[start..self.at];
        if is_float {
            let parsed: f64 = literal
                .parse()
                .map_err(|_| CanonError::Syntax("bad number"))?;
            if !parsed.is_finite() {
                return Err(CanonError::Unsupported("float out of range"));
            }
            Ok(Value::Float(parsed))
        } else {
            literal
                .parse::<i64>()
                .map(Value::Int)
                .map_err(|_| CanonError::Unsupported("integer outside i64"))
        }
    }

    fn hex4(&mut self) -> Result<u32, CanonError> {
        let digits = self
            .src
            .get(self.at..self.at + 4)
            .ok_or(CanonError::Syntax("bad \\u escape"))?;
        let mut code = 0_u32;
        for &d in digits {
            let nibble = (d as char)
                .to_digit(16)
                .ok_or(CanonError::Syntax("bad \\u escape"))?;
            code = code * 16 + nibble;
        }
        self.at += 4;
        Ok(code)
    }

    fn string(&mut self) -> Result<String, CanonError> {
        self.at += 1; // opening quote
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(CanonError::Syntax("unterminated string"));
            };
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.at += 1;
                    let Some(escape) = self.peek() else {
                        return Err(CanonError::Syntax("unterminated string"));
                    };
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(CanonError::Syntax("bad escape")),
                    }
                }
                0..=0x1f => return Err(CanonError::Syntax("control character in string")),
                _ => {
                    // Copy one whole UTF-8 character (the input is valid UTF-8 and `at` is on a
                    // character boundary).
                    let rest = &self.text[self.at..];
                    let Some(ch) = rest.chars().next() else {
                        return Err(CanonError::Syntax("unterminated string"));
                    };
                    out.push(ch);
                    self.at += ch.len_utf8();
                }
            }
        }
    }

    /// After `\u`: one BMP scalar, or a high surrogate that must be followed by `\u` + a low one.
    fn unicode_escape(&mut self) -> Result<char, CanonError> {
        let first = self.hex4()?;
        let code = match first {
            0xD800..=0xDBFF => {
                if !self.src[self.at..].starts_with(b"\\u") {
                    return Err(CanonError::Unsupported("lone surrogate"));
                }
                self.at += 2;
                let second = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(CanonError::Unsupported("lone surrogate"));
                }
                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(CanonError::Unsupported("lone surrogate")),
            other => other,
        };
        char::from_u32(code).ok_or(CanonError::Unsupported("lone surrogate"))
    }
}

// ---- emitter ----

/// `json.dumps(value, sort_keys=True, separators=(",", ":"))` as UTF-8 bytes.
pub fn dumps(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    emit(value, &mut out, Separators::COMPACT);
    out
}

/// `json.dumps(value, sort_keys=True)` (Python's default `", "` / `": "` separators), the form of
/// the `decode_summary` column.
pub fn dumps_spaced(value: &Value) -> String {
    let mut out = Vec::new();
    emit(value, &mut out, Separators::SPACED);
    // The emitter writes ASCII only.
    String::from_utf8(out).unwrap_or_default()
}

#[derive(Clone, Copy)]
struct Separators {
    item: &'static [u8],
    key: &'static [u8],
}

impl Separators {
    const COMPACT: Separators = Separators {
        item: b",",
        key: b":",
    };
    const SPACED: Separators = Separators {
        item: b", ",
        key: b": ",
    };
}

fn emit(value: &Value, out: &mut Vec<u8>, sep: Separators) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::Float(x) => out.extend_from_slice(json_float(*x).as_bytes()),
        Value::Str(s) => emit_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(sep.item);
                }
                emit(item, out, sep);
            }
            out.push(b']');
        }
        Value::Object(members) => {
            let mut sorted: Vec<&(String, Value)> = members.iter().collect();
            // Rust compares `str` by UTF-8 bytes, which orders exactly like Python's code points.
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            out.push(b'{');
            for (i, (key, member)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(sep.item);
                }
                emit_string(key, out);
                out.extend_from_slice(sep.key);
                emit(member, out, sep);
            }
            out.push(b'}');
        }
    }
}

/// Python's `ensure_ascii` string encoder.
fn emit_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            ' '..='~' => out.push(ch as u8),
            _ => {
                let mut units = [0_u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    out.extend_from_slice(format!("\\u{unit:04x}").as_bytes());
                }
            }
        }
    }
    out.push(b'"');
}

/// `json.dumps` of a float: `repr`, except that the non-finite values are bare words.
fn json_float(x: f64) -> String {
    if x.is_nan() {
        "NaN".to_string()
    } else if x.is_infinite() {
        if x > 0.0 { "Infinity" } else { "-Infinity" }.to_string()
    } else {
        py_float_repr(x)
    }
}

/// Python's `repr(float)` for a finite value: shortest round-trip digits, exponent form iff the
/// scientific exponent is below -4 or at least 16.
pub fn py_float_repr(x: f64) -> String {
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0" } else { "0.0" }.to_string();
    }
    // ryu's digits are the shortest that round-trip and, among those, the closest to the value:
    // exactly Python's `repr`. (Rust's own `{:e}` is shortest but can pick a different last digit.)
    let mut buffer = ryu::Buffer::new();
    let text = buffer.format_finite(x.abs());
    let (mantissa, exponent) = text.split_once('e').unwrap_or((text, "0"));
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all = format!("{whole}{fraction}");
    let leading_zeros = all.len() - all.trim_start_matches('0').len();
    let digits = all.trim_matches('0').to_string();
    // Position of the decimal point relative to the first significant digit.
    let point = whole.len() as i32 + exponent.parse::<i32>().unwrap_or(0) - leading_zeros as i32;
    let exp10 = point - 1;
    let sign = if x < 0.0 { "-" } else { "" };
    if !(-4..16).contains(&exp10) {
        let (head, tail) = digits.split_at(1);
        let fraction = if tail.is_empty() {
            String::new()
        } else {
            format!(".{tail}")
        };
        let exp_sign = if exp10 < 0 { '-' } else { '+' };
        return format!(
            "{sign}{head}{fraction}e{exp_sign}{:02}",
            exp10.unsigned_abs()
        );
    }
    let count = digits.len() as i32;
    let body = if point <= 0 {
        format!("0.{}{digits}", "0".repeat(point.unsigned_abs() as usize))
    } else if point >= count {
        format!("{digits}{}.0", "0".repeat((point - count) as usize))
    } else {
        let (whole, fraction) = digits.split_at(point as usize);
        format!("{whole}.{fraction}")
    };
    format!("{sign}{body}")
}

// ---- entry points ----

/// `dumps(parse(bytes))`: the canonical bytes of a JSON text.
pub fn canonical(bytes: &[u8]) -> Result<Vec<u8>, CanonError> {
    Ok(dumps(&parse(bytes)?))
}

/// Python's `str()` of a scalar, the form a source key takes: strings as they are, ints in
/// decimal, floats by `repr`, `None`, `True`, `False`. Containers are refused.
pub fn py_str(value: &Value) -> Result<String, CanonError> {
    match value {
        Value::Str(s) => Ok(s.clone()),
        Value::Int(n) => Ok(n.to_string()),
        Value::Float(x) if x.is_nan() => Ok("nan".to_string()),
        Value::Float(x) if x.is_infinite() => Ok(if *x > 0.0 { "inf" } else { "-inf" }.to_string()),
        Value::Float(x) => Ok(py_float_repr(*x)),
        Value::Null => Ok("None".to_string()),
        Value::Bool(true) => Ok("True".to_string()),
        Value::Bool(false) => Ok("False".to_string()),
        Value::Array(_) | Value::Object(_) => {
            Err(CanonError::Unsupported("container in a key position"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_layout_follows_python_repr() {
        let cases: [(f64, &str); 14] = [
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (1.5e300, "1.5e+300"),
            (5e-324, "5e-324"),
            (-0.0, "-0.0"),
            (70.0, "70.0"),
            (0.1, "0.1"),
            (1234.5678, "1234.5678"),
            (-2.5e-7, "-2.5e-07"),
            (123456789012345.6, "123456789012345.6"),
            (0.000123, "0.000123"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
        ];
        for (x, text) in cases {
            assert_eq!(py_float_repr(x), text);
        }
    }

    #[test]
    fn shortest_digits_break_ties_to_even_like_python() {
        // Exact ties at the last digit: Python's repr keeps the even digit; Rust's `{}` does not.
        assert_eq!(py_float_repr(623721.3168945313), "623721.3168945312");
        assert_eq!(py_float_repr(1228471191644118.3), "1228471191644118.2");
        assert_eq!(py_float_repr(0.30000000000000004), "0.30000000000000004");
    }

    #[test]
    fn duplicate_keys_keep_the_last_value_and_sorting_is_by_code_point() {
        let value = parse(br#"{"b":1,"a":2,"b":3,"\ud83d\ude00":0,"\uffff":0}"#).unwrap();
        assert_eq!(
            dumps(&value),
            br#"{"a":2,"b":3,"\uffff":0,"\ud83d\ude00":0}"#.to_vec()
        );
    }

    #[test]
    fn spaced_form_is_pythons_default_separators() {
        let value = parse(br#"{"z":[1,2],"a":{}}"#).unwrap();
        assert_eq!(dumps_spaced(&value), r#"{"a": {}, "z": [1, 2]}"#);
    }

    #[test]
    fn refusals_are_unsupported_and_garbage_is_syntax() {
        assert!(matches!(parse(b"NaN"), Err(CanonError::Unsupported(_))));
        assert!(matches!(
            parse(b"[-Infinity]"),
            Err(CanonError::Unsupported(_))
        ));
        assert!(matches!(parse(b"1e999"), Err(CanonError::Unsupported(_))));
        assert!(matches!(
            parse(b"9223372036854775808"),
            Err(CanonError::Unsupported(_))
        ));
        assert!(matches!(
            parse(b"\"\\udc00\""),
            Err(CanonError::Unsupported(_))
        ));
        assert!(matches!(
            parse(&[b'"', 0xff, b'"']),
            Err(CanonError::Unsupported(_))
        ));
        assert!(matches!(parse(b"{"), Err(CanonError::Syntax(_))));
        assert!(matches!(parse(b"01"), Err(CanonError::Syntax(_))));
        assert!(matches!(parse(b"[1,]"), Err(CanonError::Syntax(_))));
        assert!(matches!(parse(b"\"a\nb\""), Err(CanonError::Syntax(_))));
        assert!(matches!(parse(b"[] x"), Err(CanonError::Syntax(_))));
        let deep = "[".repeat(2000);
        assert!(matches!(
            parse(deep.as_bytes()),
            Err(CanonError::Unsupported(_))
        ));
        assert_eq!(
            parse(b"-9223372036854775808").unwrap(),
            Value::Int(i64::MIN)
        );
        assert_eq!(parse(b"-0").unwrap(), Value::Int(0));
    }
}
