// SPDX-License-Identifier: AGPL-3.0-or-later
//! The store's one time shape, `YYYY-MM-DDTHH:MM:SSZ` (UTC), without a date-time dependency.

use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{NaiveDate, TimeZone, Utc};

use crate::model::Instant;
use crate::read::pyrepr;

const ISO: &str = "%Y-%m-%dT%H:%M:%SZ";

/// An instant in the store's one shape (`iso_utc` in `storage/_time.py`).
pub fn iso_utc(moment: &Instant) -> String {
    moment.format(ISO).to_string()
}

/// Parse the store's `YYYY-MM-DDTHH:MM:SSZ` text back into an instant; None if `strptime` would refuse it.
pub fn parse_iso_utc(text: &str) -> Option<Instant> {
    parse_store_stamp(text).ok()
}

/// Parse a stored stamp exactly as `datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")` does — the path every
/// text takes in `storage/_time.py`'s `parse_iso_utc` unless it is the store's exact shape, which parses to
/// the same moment. The error is Python 3.14's `ValueError` text, which the serve layer carries to the wire
/// as `bad_params`, so a malformed cell reads the same from both cores.
///
/// CPython 3.14's `_strptime` compiles the format to one regex, matched at the start of the text and
/// ignoring case: `(\d\d\d\d)-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9])T(2[0-3]|[0-1]\d|\d| \d):`
/// `([0-5]\d|\d):(6[0-1]|[0-5]\d|\d)Z` (3.14 gave `%H` the spaced one-digit arm `%d` always had). No match
/// is `time data <repr> does not match format …`; a match that leaves text over is `unconverted data
/// remains: <rest>`; then the `datetime` constructor checks the year, the day of the month and the second,
/// in that order, with its own texts. Python's `\d` also takes non-ASCII decimal digits; this mirror reads
/// ASCII only (the one documented divergence). `tests/fixtures/strptime-stamps.json` pins both cores.
pub fn parse_store_stamp(text: &str) -> Result<Instant, String> {
    let shape = || format!("time data {} does not match format '{ISO}'", pyrepr::repr_str(text));
    let mut scan = Scan { bytes: text.as_bytes(), at: 0 };
    let (year, month, day, hour, minute, second) = scan.fields().ok_or_else(shape)?;
    if scan.at != scan.bytes.len() {
        return Err(format!("unconverted data remains: {}", &text[scan.at..])); // the prefix is ASCII: a char boundary
    }
    if !(1..=9999).contains(&year) {
        return Err(format!("year must be in 1..9999, not {year}"));
    }
    let days = days_in_month(year, month);
    if day > days {
        return Err(format!("day {day} must be in range 1..{days} for month {month} in year {year}"));
    }
    if second > 59 {
        return Err(format!("second must be in 0..59, not {second}"));
    }
    NaiveDate::from_ymd_opt(year as i32, month, day)
        .and_then(|date| date.and_hms_opt(hour, minute, second))
        .map(|naive| Utc.from_utc_datetime(&naive))
        .ok_or_else(shape) // cannot fire after the checks above; a shape failure rather than a panic
}

/// Days in `month` of `year` (proleptic Gregorian, as Python's `calendar`).
fn days_in_month(year: u32, month: u32) -> u32 {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The `_strptime` regex above, one group at a time. Each group is followed by a literal that is not a digit,
/// so the first alternative that matches is the one the backtracking regex settles on: a two-digit alternative
/// the following literal then refuses cannot be rescued by the one-digit one (that would need the second
/// digit to be the literal), and the day's leading-space alternative starts with a byte no other can.
struct Scan<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Scan<'_> {
    /// The six groups with their literals, in the format's order: None where the regex has no match.
    fn fields(&mut self) -> Option<(u32, u32, u32, u32, u32, u32)> {
        let year = self.year()?;
        let month = self.literal(b'-').then(|| self.month())??;
        let day = self.literal(b'-').then(|| self.day())??;
        let hour = self.literal(b'T').then(|| self.hour())??;
        let minute = self.literal(b':').then(|| self.minute())??;
        let second = self.literal(b':').then(|| self.second())??;
        self.literal(b'Z').then_some((year, month, day, hour, minute, second))
    }

    fn digit(&self, ahead: usize) -> Option<u32> {
        self.bytes.get(self.at + ahead).filter(|b| b.is_ascii_digit()).map(|b| u32::from(b - b'0'))
    }

    /// Two digits, each bounded; consumed only when both fit.
    fn two(&mut self, first: impl Fn(u32) -> bool, second: impl Fn(u32) -> bool) -> Option<u32> {
        let (a, b) = (self.digit(0)?, self.digit(1)?);
        (first(a) && second(b)).then(|| {
            self.at += 2;
            a * 10 + b
        })
    }

    /// One bounded digit.
    fn one(&mut self, ok: impl Fn(u32) -> bool) -> Option<u32> {
        let a = self.digit(0)?;
        ok(a).then(|| {
            self.at += 1;
            a
        })
    }

    /// A space then one bounded digit (`%d`'s and `%H`'s ` [1-9]` / ` \d` arms).
    fn spaced(&mut self, ok: impl Fn(u32) -> bool) -> Option<u32> {
        if self.bytes.get(self.at) != Some(&b' ') {
            return None;
        }
        let a = self.digit(1).filter(|&d| ok(d))?;
        self.at += 2;
        Some(a)
    }

    /// A literal, ASCII case-insensitively (`re.IGNORECASE`).
    fn literal(&mut self, wanted: u8) -> bool {
        let found = self.bytes.get(self.at).is_some_and(|b| b.eq_ignore_ascii_case(&wanted));
        self.at += usize::from(found);
        found
    }

    /// `(\d\d\d\d)`
    fn year(&mut self) -> Option<u32> {
        let digits = [self.digit(0)?, self.digit(1)?, self.digit(2)?, self.digit(3)?];
        self.at += 4;
        Some(digits.iter().fold(0, |value, d| value * 10 + d))
    }

    /// `1[0-2]|0[1-9]|[1-9]`
    fn month(&mut self) -> Option<u32> {
        self.two(|a| a == 1, |b| b <= 2)
            .or_else(|| self.two(|a| a == 0, |b| b >= 1))
            .or_else(|| self.one(|a| a >= 1))
    }

    /// `3[01]|[12]\d|0[1-9]|[1-9]| [1-9]`
    fn day(&mut self) -> Option<u32> {
        self.two(|a| a == 3, |b| b <= 1)
            .or_else(|| self.two(|a| a == 1 || a == 2, |_| true))
            .or_else(|| self.two(|a| a == 0, |b| b >= 1))
            .or_else(|| self.one(|a| a >= 1))
            .or_else(|| self.spaced(|a| a >= 1))
    }

    /// `2[0-3]|[0-1]\d|\d| \d`
    fn hour(&mut self) -> Option<u32> {
        self.two(|a| a == 2, |b| b <= 3)
            .or_else(|| self.two(|a| a <= 1, |_| true))
            .or_else(|| self.one(|_| true))
            .or_else(|| self.spaced(|_| true))
    }

    /// `[0-5]\d|\d`
    fn minute(&mut self) -> Option<u32> {
        self.two(|a| a <= 5, |_| true).or_else(|| self.one(|_| true))
    }

    /// `6[0-1]|[0-5]\d|\d`
    fn second(&mut self) -> Option<u32> {
        self.two(|a| a == 6, |b| b <= 1).or_else(|| self.two(|a| a <= 5, |_| true)).or_else(|| self.one(|_| true))
    }
}

/// TEST-ONLY clock pin, `YYYY-MM-DDTHH:MM:SSZ` (the twin of `storage/_time.py`'s `NOW_ENV`): both
/// cores honour it at their one `now()` site so a differential run is deterministic. The desktop
/// sidecar's env allowlist never passes it on; an unparseable value is ignored.
pub const NOW_ENV: &str = "DISCONECT_NOW";

/// The one clock this crate reads: Unix seconds now, or the `DISCONECT_NOW` pin.
pub fn now_unix() -> u64 {
    if let Some(pinned) = std::env::var(NOW_ENV).ok().filter(|v| !v.is_empty())
        && let Some(moment) = parse_iso_utc(&pinned)
        && let Ok(secs) = u64::try_from(moment.timestamp())
    {
        return secs;
    }
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The one clock as an instant (whole seconds): the twin of `now_utc()` in `storage/_time.py`.
pub fn now_instant() -> Instant {
    i64::try_from(now_unix())
        .ok()
        .and_then(|secs| chrono::DateTime::<Utc>::from_timestamp(secs, 0))
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
}

/// Now, as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_now_iso() -> String {
    iso_from_unix(now_unix())
}

/// Format Unix seconds (>= 0) as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's days-to-civil algorithm (days since 1970-01-01).
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::{iso_from_unix, iso_utc, parse_store_stamp};

    /// The outcomes `tests/fixtures/strptime-stamps.json` holds were read off the Python the fixture
    /// names (`test_time.py` checks them against its interpreter); a stored cell must read the same here.
    #[test]
    fn a_stored_stamp_reads_as_strptime_reads_it() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../disconect/tests/fixtures/strptime-stamps.json");
        let table: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("fixture")).expect("json");
        let rows = table["rows"].as_array().expect("rows");
        assert!(rows.len() >= 50);
        for row in rows {
            let text = row[0].as_str().expect("text");
            let outcome = row[2].as_str().expect("outcome");
            let expected = if row[1] == "ok" { Ok(outcome) } else { Err(outcome) };
            let got = parse_store_stamp(text).map(|moment| iso_utc(&moment));
            assert_eq!(got.as_deref().map_err(String::as_str), expected, "{text:?}");
        }
    }

    #[test]
    fn non_ascii_digits_are_the_one_documented_divergence() {
        // Python's `\d` takes U+FF12 etc. and `int()` reads them; the mirror reads ASCII digits only
        assert_eq!(
            parse_store_stamp("２０２５-06-15T00:00:00Z").unwrap_err(),
            "time data '２０２５-06-15T00:00:00Z' does not match format '%Y-%m-%dT%H:%M:%SZ'"
        );
    }

    #[test]
    fn known_instants() {
        assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_from_unix(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(iso_from_unix(1_782_864_000), "2026-07-01T00:00:00Z");
        assert_eq!(iso_from_unix(951_782_400), "2000-02-29T00:00:00Z");
    }
}
