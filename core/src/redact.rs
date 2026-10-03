// SPDX-License-Identifier: AGPL-3.0-or-later
//! Scrub identifiers from free text before it is stored or shown: the twin of `disconect/redact.py`
//! (plus `connect_export.mask_label`, which uses its own, simpler digit-run pattern).

use std::sync::LazyLock;

use fancy_regex::Regex;

type Pattern = Result<Regex, Box<fancy_regex::Error>>;

fn compile(source: &str) -> Pattern {
    Regex::new(source).map_err(Box::new)
}

static EMAIL: LazyLock<Pattern> = LazyLock::new(|| compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"));
/// ids, not decimals like 12.3456789
static LONG_NUMBER_REDACT: LazyLock<Pattern> = LazyLock::new(|| compile(r"(?<![\d.])\d{7,}(?!\d|\.\d)"));
static LONG_NUMBER_LABEL: LazyLock<Pattern> = LazyLock::new(|| compile(r"\d{7,}"));
// Python's `\s` on `str` also matches U+001C..U+001F (they are `str.isspace`); the regex crate's
// `\s` does not, so the classes name them explicitly (opus review of slice 3).
static POSIX_PATH: LazyLock<Pattern> =
    LazyLock::new(|| compile(r#"(?:(?<=[\s\x1c-\x1f])|^|(?<=['"(:]))/(?:[^\s\x1c-\x1f'"()]+/)+[^\s\x1c-\x1f'"()]*"#));
static WINDOWS_PATH: LazyLock<Pattern> =
    LazyLock::new(|| compile(r#"[A-Za-z]:\\(?:[^\s\x1c-\x1f'"()\\]+\\)*[^\s\x1c-\x1f'"()\\]*"#));

/// Replace every match of `pattern` in `text` with `with`; a pattern that failed to compile or a
/// runtime backtrack error leaves the rest of the text untouched.
fn replace_all(pattern: &Pattern, text: &str, with: &str) -> String {
    let Ok(re) = pattern else { return text.to_string() };
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for found in re.find_iter(text) {
        let Ok(found) = found else { break };
        out.push_str(&text[last..found.start()]);
        out.push_str(with);
        last = found.end();
    }
    out.push_str(&text[last..]);
    out
}

/// E-mail addresses, absolute paths and long identifiers replaced by visible placeholders.
pub fn redact_text(text: &str) -> String {
    let text = replace_all(&EMAIL, text, "{email}");
    let text = replace_all(&POSIX_PATH, &text, "{path}");
    let text = replace_all(&WINDOWS_PATH, &text, "{path}");
    replace_all(&LONG_NUMBER_REDACT, &text, "{id}")
}

/// A filename safe to put in a report: e-mail and long digit runs replaced.
pub fn mask_label(name: &str) -> String {
    let text = replace_all(&EMAIL, name, "{email}");
    replace_all(&LONG_NUMBER_LABEL, &text, "{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_mask_email_then_long_digits() {
        assert_eq!(mask_label("a.b@example.org_123456789.fit"), "{email}_{id}.fit");
        assert_eq!(mask_label("1234567.fit"), "{id}.fit");
        assert_eq!(mask_label("123456.fit"), "123456.fit");
    }

    #[test]
    fn redaction_keeps_decimals_and_hides_paths() {
        assert_eq!(redact_text("12.3456789 and 12345678"), "12.3456789 and {id}");
        assert_eq!(redact_text("open '/Users/x/y.fit' failed"), "open '{path}' failed");
        assert_eq!(redact_text(r"C:\Users\x\y.fit gone"), "{path} gone");
        assert_eq!(redact_text("mail me@x.io now"), "mail {email} now");
    }

    #[test]
    fn python_isspace_control_characters_count_as_path_boundaries() {
        // U+001C..U+001F are `str.isspace` in Python, so its `\s` treats them as a boundary
        assert_eq!(redact_text("nothing\u{1c}/Users/someone/secret"), "nothing\u{1c}{path}");
        assert_eq!(redact_text("x\u{1f}C:\\Users\\x\\y.fit"), "x\u{1f}{path}");
    }
}
