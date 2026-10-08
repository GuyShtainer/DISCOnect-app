// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local calendar dates from the watch's own UTC offsets: the twin of `ingest/clock.py`.
//!
//! The resolver picks the stated offset nearest in time to the moment being dated (ties go to the
//! earlier entry). With no offset known at all it falls back to UTC and counts it in
//! [`ClockOffsets::assumed_utc`] rather than guessing a zone.

use std::cell::Cell;

use chrono::Duration;
use rusqlite::{Connection, params};

use crate::model::{ClockOffset, Instant};
use crate::time::{iso_utc, parse_store_stamp};

const MICROS: i64 = 1_000_000;

/// A `clock_offsets.ts_utc` cell `strptime` refuses, with its text: the twin's `ValueError`. Boxed into
/// rusqlite's conversion failure by [`ClockOffsets::load`] so a reader can tell it from a cell that is not
/// even UTF-8 (which the twin raises as a database error).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BadStamp(pub String);

/// A `clock_offsets.offset_s` cell Python's `int()` refuses, with the twin's `ValueError` text (`invalid literal for
/// int() with base 10: '<repr>'`). Boxed into rusqlite's conversion failure like [`BadStamp`].
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BadOffset(pub String);

/// `int(cell)` of a stored offset: INTEGER as is, REAL truncated toward zero, TEXT/BLOB by `int(str)`'s grammar.
/// `Ok(None)` is a cell the twin accepts but an `i64` cannot hold (a huge or infinite REAL, an overlong digit
/// string): the twin fails later with `OverflowError` (BACKLOG row); the caller keeps its database error.
fn python_int(cell: &rusqlite::types::Value) -> Result<Option<i64>, BadOffset> {
    use rusqlite::types::Value;
    match cell {
        Value::Integer(n) => Ok(Some(*n)),
        // inside i64 exactly: -2**63 is the lowest value, 2**63 the first one past the top
        Value::Real(x) if *x >= -9_223_372_036_854_775_808.0 && *x < 9_223_372_036_854_775_808.0 => {
            Ok(Some(x.trunc() as i64))
        }
        Value::Real(_) | Value::Null => Ok(None),
        // `int(str)` strips Unicode whitespace (`str.isspace` less U+001C..U+001F); `int(bytes)` only ASCII's
        Value::Text(text) => parse_int_literal(text.trim_matches(char::is_whitespace).as_bytes())
            .ok_or_else(|| invalid_literal(text.as_bytes(), false)),
        Value::Blob(bytes) => parse_int_literal(trim_py_bytes(bytes)).ok_or_else(|| invalid_literal(bytes, true)),
    }
}

/// `bytes.strip()`'s set (`Py_ISSPACE`): space, `\t \n \x0b \x0c \r` (Rust's `trim_ascii` leaves out `\x0b`).
fn trim_py_bytes(bytes: &[u8]) -> &[u8] {
    let space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    let start = bytes.iter().position(|b| !space(b)).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !space(b)).map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// The twin's `ValueError` text: CPython formats it with `%.200R`, so the repr is cut at 200 characters.
fn invalid_literal(bytes: &[u8], is_bytes: bool) -> BadOffset {
    let repr: String = py_repr(bytes, is_bytes).chars().take(200).collect();
    BadOffset(format!("invalid literal for int() with base 10: {repr}"))
}

/// Python's `int()` grammar over ASCII digits, on a literal its caller already trimmed: one sign, digits with single
/// `_` between. `None` is a literal Python refuses; `Some(None)` one it accepts but an `i64` cannot hold.
fn parse_int_literal(body: &[u8]) -> Option<Option<i64>> {
    let (negative, digits) = match body.first()? {
        b'-' => (true, &body[1..]),
        b'+' => (false, &body[1..]),
        _ => (false, body),
    };
    if digits.is_empty() || digits[0] == b'_' || digits[digits.len() - 1] == b'_' || digits.windows(2).any(|w| w == b"__") {
        return None;
    }
    let mut value: i128 = 0;
    for byte in digits.iter().filter(|b| **b != b'_') {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.saturating_mul(10).saturating_add(i128::from(byte - b'0'));
    }
    Some(i64::try_from(if negative { -value } else { value }).ok())
}

/// Python's `repr` of the cell text (`str`, or `bytes` with a `b` prefix): single quotes unless the text holds a
/// single quote and no double quote; backslash, `\n`, `\r`, `\t` and other control bytes escaped.
fn py_repr(bytes: &[u8], is_bytes: bool) -> String {
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') { '"' } else { '\'' };
    let mut out = String::new();
    if is_bytes {
        out.push('b');
    }
    out.push(quote);
    let push = |out: &mut String, c: char| match c {
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if c == quote => {
            out.push('\\');
            out.push(c);
        }
        c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
        c => out.push(c),
    };
    if is_bytes {
        for byte in bytes {
            if *byte >= 0x80 {
                out.push_str(&format!("\\x{byte:02x}"));
            } else {
                push(&mut out, char::from(*byte));
            }
        }
    } else {
        String::from_utf8_lossy(bytes).chars().for_each(|c| push(&mut out, c));
    }
    out.push(quote);
    out
}

/// Sorted (moment, offset) pairs with nearest-neighbour lookup.
#[derive(Debug, Default)]
pub struct ClockOffsets {
    moments: Vec<i64>,
    offsets: Vec<i64>,
    /// How many dates were resolved without any known offset.
    assumed_utc: Cell<u64>,
}

impl ClockOffsets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Offsets already persisted by earlier imports.
    pub fn load(conn: &Connection) -> rusqlite::Result<Self> {
        let mut offsets = Self::new();
        let mut stmt = conn.prepare("SELECT ts_utc, offset_s FROM clock_offsets")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, rusqlite::types::Value>(1)?)))?;
        for row in rows {
            let (ts_utc, offset_s) = row?;
            // a malformed cell carries strptime's text (the twin raises it from `parse_iso_utc`)
            let ts_utc = parse_store_stamp(&ts_utc).map_err(|text| {
                rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(BadStamp(text)))
            })?;
            // then `int()` of the offset cell, in the twin's own order (the moment first)
            let offset_s = match python_int(&offset_s) {
                Ok(Some(seconds)) => seconds,
                // a value the twin holds as a big int and fails on later (BACKLOG row): a database error here
                Ok(None) => {
                    return Err(rusqlite::Error::InvalidColumnType(
                        1,
                        "offset_s".to_string(),
                        offset_s.data_type(),
                    ));
                }
                Err(bad) => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        1,
                        offset_s.data_type(),
                        Box::new(bad),
                    ));
                }
            };
            offsets.add(ClockOffset { ts_utc, offset_s });
        }
        Ok(offsets)
    }

    /// [`load`](Self::load) for a write path: a malformed cell is the twin's `ValueError` raised before the run
    /// begins (`BadStamp`, served `bad_params`); any other failure, a non-UTF-8 cell included, is a database error.
    pub fn load_for_write(conn: &Connection) -> Result<Self, crate::writer::WriterError> {
        Self::load(conn).map_err(|error| match error {
            rusqlite::Error::FromSqlConversionFailure(_, _, inner) if inner.is::<BadStamp>() || inner.is::<BadOffset>() => {
                crate::writer::WriterError::BadStamp(inner.to_string())
            }
            other => crate::writer::WriterError::Db(other),
        })
    }

    pub fn len(&self) -> usize {
        self.moments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.moments.is_empty()
    }

    /// How many dates were resolved without any known offset.
    pub fn assumed_utc(&self) -> u64 {
        self.assumed_utc.get()
    }

    /// Carry the count of assumed-UTC dates over to a reloaded table.
    pub fn set_assumed_utc(&self, count: u64) {
        self.assumed_utc.set(count);
    }

    /// Insert, or replace the offset stated for the very same moment.
    pub fn add(&mut self, offset: ClockOffset) {
        let key = offset.ts_utc.timestamp();
        let index = self.moments.partition_point(|m| *m < key); // bisect_left
        if self.moments.get(index) == Some(&key) {
            self.offsets[index] = offset.offset_s;
            return;
        }
        self.moments.insert(index, key);
        self.offsets.insert(index, offset.offset_s);
    }

    pub fn extend(&mut self, offsets: impl IntoIterator<Item = ClockOffset>) {
        for offset in offsets {
            self.add(offset);
        }
    }

    /// The stated offset nearest to `moment` (ties to the earlier entry), or None if none is known.
    pub fn offset_at(&self, moment: Instant) -> Option<i64> {
        self.offset_near(moment.timestamp().saturating_mul(MICROS))
    }

    /// `offset_at` for an instant given in microseconds since the epoch: the coverage ledger asks
    /// about "one microsecond before" a span's exclusive end, and the nearest-offset tie rule must see it.
    fn offset_near(&self, key: i64) -> Option<i64> {
        if self.moments.is_empty() {
            return None;
        }
        let at = |index: usize| self.moments[index].saturating_mul(MICROS);
        let index = self.moments.partition_point(|m| m.saturating_mul(MICROS) < key); // bisect_left
        let mut best: Option<usize> = None;
        // Candidates index-1 then index; the first minimum wins.
        for candidate in [index.checked_sub(1), Some(index)].into_iter().flatten() {
            if candidate >= self.moments.len() {
                continue;
            }
            let distance = (at(candidate) - key).abs();
            let better = match best {
                None => true,
                Some(b) => distance < (at(b) - key).abs(),
            };
            if better {
                best = Some(candidate);
            }
        }
        best.map(|i| self.offsets[i])
    }

    /// `YYYY-MM-DD` on the watch's clock at `moment`.
    pub fn local_date(&self, moment: Instant) -> String {
        let offset = self.offset_at(moment).unwrap_or_else(|| {
            self.assumed_utc.set(self.assumed_utc.get() + 1);
            0
        });
        (moment + Duration::seconds(offset)).date_naive().format("%Y-%m-%d").to_string()
    }

    /// `local_date` for a read path that must not panic: the local date at `moment`, or at the
    /// instant one microsecond before it (`before`), or None where Python's date arithmetic would
    /// raise `OverflowError` (an absurd stored offset).
    pub fn local_date_checked(&self, moment: Instant, before: bool) -> Option<String> {
        let shift = i64::from(before);
        let key = moment.timestamp().saturating_mul(MICROS).saturating_sub(shift);
        let offset = self.offset_near(key).unwrap_or_else(|| {
            self.assumed_utc.set(self.assumed_utc.get() + 1);
            0
        });
        let local = moment.checked_add_signed(Duration::try_seconds(offset)?)?;
        let local = if before { local.checked_sub_signed(Duration::microseconds(1))? } else { local };
        let date = local.date_naive();
        (1..=9999).contains(&chrono::Datelike::year(&date)).then(|| date.format("%Y-%m-%d").to_string())
    }

    /// Persist offsets a file stated (`INSERT OR REPLACE`).
    pub fn persist(
        conn: &Connection,
        offsets: &[ClockOffset],
        device_id: Option<&str>,
        raw_record_id: Option<i64>,
    ) -> rusqlite::Result<()> {
        let mut stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO clock_offsets(ts_utc, offset_s, device_id, raw_record_id) VALUES(?, ?, ?, ?)",
        )?;
        for o in offsets {
            stmt.execute(params![iso_utc(&o.ts_utc), o.offset_s, device_id, raw_record_id])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn at(secs: i64) -> Instant {
        Utc.timestamp_opt(secs, 0).single().expect("valid instant")
    }

    fn offset(secs: i64, offset_s: i64) -> ClockOffset {
        ClockOffset { ts_utc: at(secs), offset_s }
    }

    #[test]
    fn no_offsets_means_utc_and_is_counted() {
        let clock = ClockOffsets::new();
        assert_eq!(clock.offset_at(at(0)), None);
        assert_eq!(clock.local_date(at(86_400 * 3 + 5)), "1970-01-04");
        assert_eq!(clock.local_date(at(86_399)), "1970-01-01");
        assert_eq!(clock.assumed_utc(), 2);
    }

    #[test]
    fn nearest_wins_and_ties_go_to_the_earlier_entry() {
        let mut clock = ClockOffsets::new();
        clock.extend([offset(1000, 3600), offset(2000, 7200), offset(500, -1800)]);
        assert_eq!(clock.len(), 3);
        assert_eq!(clock.offset_at(at(0)), Some(-1800));
        assert_eq!(clock.offset_at(at(700)), Some(-1800));
        assert_eq!(clock.offset_at(at(800)), Some(3600));
        assert_eq!(clock.offset_at(at(1500)), Some(3600), "exact tie: the earlier entry");
        assert_eq!(clock.offset_at(at(1501)), Some(7200));
        assert_eq!(clock.offset_at(at(9999)), Some(7200));
        assert_eq!(clock.assumed_utc(), 0);
    }

    #[test]
    fn an_equal_moment_replaces_instead_of_duplicating() {
        let mut clock = ClockOffsets::new();
        clock.add(offset(1000, 3600));
        clock.add(offset(1000, 7200));
        assert_eq!(clock.len(), 1);
        assert_eq!(clock.offset_at(at(5)), Some(7200));
    }

    #[test]
    fn local_date_crosses_midnight_with_the_offset() {
        let mut clock = ClockOffsets::new();
        clock.add(offset(0, -12_600)); // -03:30
        assert_eq!(clock.local_date(at(86_400 + 3600)), "1970-01-01");
        assert_eq!(clock.local_date(at(86_400 + 12_600)), "1970-01-02");
    }

    #[test]
    fn persist_then_load_round_trips() {
        let conn = Connection::open_in_memory().expect("memory db");
        conn.execute_batch(
            "CREATE TABLE clock_offsets(ts_utc TEXT NOT NULL, offset_s INTEGER NOT NULL, device_id TEXT, raw_record_id INTEGER,
             UNIQUE(ts_utc, device_id))",
        )
        .expect("table");
        ClockOffsets::persist(&conn, &[offset(1_700_000_000, 3600), offset(1_700_003_600, 7200)], Some("d"), None)
            .expect("persist");
        let loaded = ClockOffsets::load(&conn).expect("load");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.offset_at(at(1_700_000_001)), Some(3600));
    }

    #[test]
    fn load_for_write_maps_a_bad_stamp_to_the_value_arm_and_anything_else_to_the_database_arm() {
        use crate::writer::WriterError;
        let conn = Connection::open_in_memory().expect("memory db");
        conn.execute_batch("CREATE TABLE clock_offsets(ts_utc TEXT NOT NULL, offset_s INTEGER NOT NULL)").expect("table");
        conn.execute("INSERT INTO clock_offsets VALUES('2025-06-15 00:00:00', 0)", []).expect("row");
        match ClockOffsets::load_for_write(&conn) {
            Err(WriterError::BadStamp(text)) => {
                assert_eq!(text, "time data '2025-06-15 00:00:00' does not match format '%Y-%m-%dT%H:%M:%SZ'");
            }
            other => panic!("expected BadStamp, got {other:?}"),
        }
        // a cell that is not UTF-8 is a database error on both cores
        conn.execute("UPDATE clock_offsets SET ts_utc = CAST(x'ff' AS TEXT)", []).expect("non-utf8");
        assert!(matches!(ClockOffsets::load_for_write(&conn), Err(WriterError::Db(_))));
        // a table the store lacks is a database error too
        conn.execute_batch("DROP TABLE clock_offsets").expect("drop");
        assert!(matches!(ClockOffsets::load_for_write(&conn), Err(WriterError::Db(_))));
    }
}
