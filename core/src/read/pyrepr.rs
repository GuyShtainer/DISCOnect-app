// SPDX-License-Identifier: AGPL-3.0-or-later
//! `repr(str)` as Python writes it, for the error texts that quote a request's own text
//! (`unknown numeric metric 'x'`, `Invalid isoformat string: 'x'`).
//!
//! Exact for ASCII and for lone surrogates. For other characters Python escapes what
//! `str.isprintable` rejects (Unicode categories Cc, Cf, Co, Cs, Cn, Zl, Zp, Zs but the plain space);
//! std has no category table, so this recognises controls, spaces, the common format characters,
//! private use and non-characters, and treats every other code point as printable. A message may
//! therefore differ on an exotic unassigned character; the error *code* never does (booked, kb/23).

use crate::wirejson::PyStr;

/// Characters of category Cf that real text can carry.
fn is_format(c: char) -> bool {
    matches!(c as u32,
        0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x890..=0x891 | 0x8e2 | 0x180e
        | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f | 0xfeff
        | 0xfff9..=0xfffb | 0xe0001 | 0xe0020..=0xe007f)
}

fn is_printable(c: char) -> bool {
    let code = c as u32;
    !(c.is_control()
        || (c.is_whitespace() && c != ' ')
        || is_format(c)
        || matches!(code, 0xe000..=0xf8ff | 0xf0000..=0xffffd | 0x100000..=0x10fffd | 0xfdd0..=0xfdef)
        || code & 0xfffe == 0xfffe)
}

fn escape(out: &mut String, code: u32) {
    let text = match code {
        0..=0xff => format!("\\x{code:02x}"),
        0x100..=0xffff => format!("\\u{code:04x}"),
        _ => format!("\\U{code:08x}"),
    };
    out.push_str(&text);
}

/// `repr()` of a Python string given as UTF-16 code units (lone surrogates allowed).
pub fn repr(text: &PyStr) -> String {
    let points: Vec<Result<char, u16>> = char::decode_utf16(text.units())
        .map(|unit| unit.map_err(|lone| lone.unpaired_surrogate()))
        .collect();
    let has = |wanted: char| points.contains(&Ok(wanted));
    let quote = if has('\'') && !has('"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for point in points {
        match point {
            Err(surrogate) => escape(&mut out, u32::from(surrogate)),
            Ok(c) if c == quote || c == '\\' => {
                out.push('\\');
                out.push(c);
            }
            Ok('\t') => out.push_str("\\t"),
            Ok('\n') => out.push_str("\\n"),
            Ok('\r') => out.push_str("\\r"),
            Ok(c) if c.is_ascii() && (c as u32) >= 0x20 && c != '\u{7f}' => out.push(c),
            Ok(c) if c.is_ascii() => escape(&mut out, c as u32),
            Ok(c) if is_printable(c) => out.push(c),
            Ok(c) => escape(&mut out, c as u32),
        }
    }
    out.push(quote);
    out
}

/// `repr()` of text that is already valid UTF-8.
pub fn repr_str(text: &str) -> String {
    repr(&PyStr::from_text(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_and_escapes_follow_python() {
        assert_eq!(repr_str("nonsense"), "'nonsense'");
        assert_eq!(repr_str("it's"), "\"it's\"");
        assert_eq!(repr_str("it's \"x\""), "'it\\'s \"x\"'");
        assert_eq!(
            repr_str("a\\b\n\t\r\u{1}\u{7f}"),
            "'a\\\\b\\n\\t\\r\\x01\\x7f'"
        );
        assert_eq!(repr_str("caf\u{e9} \u{1f600}"), "'caf\u{e9} \u{1f600}'");
        assert_eq!(
            repr_str("\u{a0}\u{2003}\u{200b}\u{feff}"),
            "'\\xa0\\u2003\\u200b\\ufeff'"
        );
        assert_eq!(repr(&PyStr::from_units(vec![0x61, 0xd800])), "'a\\ud800'");
        assert_eq!(repr_str(""), "''");
    }
}
