// SPDX-License-Identifier: AGPL-3.0-or-later
//! The store's one time shape, `YYYY-MM-DDTHH:MM:SSZ` (UTC), without a date-time dependency.

use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{NaiveDateTime, TimeZone, Utc};

use crate::model::Instant;

const ISO: &str = "%Y-%m-%dT%H:%M:%SZ";

/// An instant in the store's one shape (`iso_utc` in `storage/_time.py`).
pub fn iso_utc(moment: &Instant) -> String {
    moment.format(ISO).to_string()
}

/// Parse the store's `YYYY-MM-DDTHH:MM:SSZ` text back into an instant; None if it is not that shape.
pub fn parse_iso_utc(text: &str) -> Option<Instant> {
    NaiveDateTime::parse_from_str(text, ISO).ok().map(|naive| Utc.from_utc_datetime(&naive))
}

/// Now, as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso_from_unix(secs)
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
fn civil_from_days(days: i64) -> (i64, u32, u32) {
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
    use super::iso_from_unix;

    #[test]
    fn known_instants() {
        assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_from_unix(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(iso_from_unix(1_782_864_000), "2026-07-01T00:00:00Z");
        assert_eq!(iso_from_unix(951_782_400), "2000-02-29T00:00:00Z");
    }
}
