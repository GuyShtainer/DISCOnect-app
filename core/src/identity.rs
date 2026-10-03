// SPDX-License-Identifier: AGPL-3.0-or-later
//! Product identity strings and the manufacturer scrub: the twin of `disconect/identity.py` and
//! `disconect-app/src/identity.ts` (ADR 0001: one cheap place to rename, no manufacturer marks).
//!
//! A drift test (`tests/test_identity_drift.py`) fails when the three files stop agreeing, and it
//! also pins [`MANUFACTURER_PATTERN`] to `serve._MANUFACTURER` (the Python source of the scrub).

pub const PRODUCT: &str = "DISCOnect";
pub const NOTICE: &str = "Not affiliated with or endorsed by any watch manufacturer.";

/// The keychain service this core stores its master-key item under. **Different from the Python
/// core's [`CLI_KEYCHAIN_SERVICE`] on purpose:** a generic password is unique per (service, account)
/// and macOS binds it to the program that made it, so two programs sharing one service would fight
/// over the same item (the drift test pins that the two names differ).
pub const KEYCHAIN_SERVICE: &str = "disconect";

// Names mirrored from `identity.py` (the drift test pins them across the three files).
pub const DATA_DIR: &str = ".disconect";
pub const DB_FILENAME: &str = "disconect.db";
pub const ENV_PREFIX: &str = "DISCONECT_";
/// The Python core's keychain service (never used by this crate; kept here for the drift pin).
pub const CLI_KEYCHAIN_SERVICE: &str = "disconect-cli";
pub const MCP_SERVER_NAME: &str = "disconect";
pub const COMMAND: &str = "disconect";
/// Earlier builds' folders and backup prefixes, read through and never written.
pub const LEGACY_HOMES: &[&str] = &[".hearthbeat"];
pub const LEGACY_DB_FILENAME: &str = "hearthbeat.db";
pub const LEGACY_ENV_PREFIX: &str = "HEARTHBEAT_";
pub const BACKUP_PREFIX: &str = "disconect";
pub const LEGACY_BACKUP_PREFIXES: &[&str] = &["hearthbeat"];

/// The scrub as Python spells it (`re.compile(..., re.IGNORECASE)`): the manufacturer's name, with
/// an optional following " connect". [`neutral_text`] implements exactly this.
pub const MANUFACTURER_PATTERN: &str = "garmin(?: connect)?";

/// What the manufacturer's name becomes in anything the UI shows.
pub const VENDOR_PLACEHOLDER: &str = "{vendor}";

const NAME: &str = "garmin";
const SUFFIX: &str = " connect";

/// Python's `re.IGNORECASE` on a `str` pattern: ASCII case folding, plus U+0130 and U+0131 for `i`.
fn same_letter(text: char, want: char) -> bool {
    if text.eq_ignore_ascii_case(&want) {
        return true;
    }
    want == 'i' && matches!(text, '\u{130}' | '\u{131}')
}

fn literal_at(text: &[char], at: usize, literal: &str) -> bool {
    let want: Vec<char> = literal.chars().collect();
    text.get(at..at + want.len())
        .is_some_and(|got| got.iter().zip(&want).all(|(t, w)| same_letter(*t, *w)))
}

/// Replace every match of [`MANUFACTURER_PATTERN`] in `text` with [`VENDOR_PLACEHOLDER`].
pub fn neutral_text(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < chars.len() {
        if literal_at(&chars, at, NAME) {
            let mut end = at + NAME.len();
            if literal_at(&chars, end, SUFFIX) {
                end += SUFFIX.len();
            }
            out.push_str(VENDOR_PLACEHOLDER);
            at = end;
        } else {
            out.push(chars[at]);
            at += 1;
        }
    }
    out
}

/// `serve._neutral`: the scrub applied to every string *value* of a JSON tree (object keys are
/// left alone, exactly as the oracle does).
pub fn neutral(node: &mut serde_json::Value) {
    match node {
        serde_json::Value::Object(map) => map.values_mut().for_each(neutral),
        serde_json::Value::Array(items) => items.iter_mut().for_each(neutral),
        serde_json::Value::String(text) => *text = neutral_text(text),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scrub_matches_the_pythons_ignorecase_pattern() {
        assert_eq!(neutral_text("Garmin Connect"), "{vendor}");
        assert_eq!(
            neutral_text("GARMIN CONNECT and garmin"),
            "{vendor} and {vendor}"
        );
        assert_eq!(neutral_text("garmin  connect"), "{vendor}  connect");
        assert_eq!(neutral_text("garmin connectx"), "{vendor}x");
        assert_eq!(
            neutral_text("garm\u{131}n \u{130}x GARM\u{130}N"),
            "{vendor} \u{130}x {vendor}"
        );
        assert_eq!(neutral_text("no match here"), "no match here");
        assert_eq!(neutral_text("garmi"), "garmi");
    }

    #[test]
    fn neutral_rewrites_values_not_keys() {
        let mut tree = json!({"garmin": ["Garmin", {"k": "a garmin b"}, 7, null, true]});
        neutral(&mut tree);
        assert_eq!(
            tree,
            json!({"garmin": ["{vendor}", {"k": "a {vendor} b"}, 7, null, true]})
        );
    }
}
