// SPDX-License-Identifier: AGPL-3.0-or-later
//! Push and pull: what crosses the relay and how it is applied. The twin of
//! `disconect/relay/sync.py` (read its module docstring and `docs/relay-protocol.md`).
//!
//! Push = every raw record and export range not yet marked in `relay_seen` /
//! `relay_seen_ranges` (pushed or received) -> bundles split on the *compressed* payload length
//! -> `relay.put`. Pull = `relay.list(account)` minus the applied bundles -> `unpack` -> verify
//! every record's bytes -> the normal `Writer` as one import run with transport `relay`: FIT
//! first, then JSON records through the export decoders, then the readiness batch, then the
//! derived dailies. A bundle that fails authentication or validation is recorded `rejected` and
//! retried on the next pull.
//!
//! Conflict rule (JSON streams): same `(stream, source_key)`, different `payload_hash` -> the
//! record whose decoded facts carry the later observed time wins, ties by the larger
//! `payload_hash`; the batch streams (readiness) have no time of their own, so the hash alone
//! decides. The loser's bytes go to `raw_superseded`, the decision to `sync_conflicts`.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::bundle::{
    self, BundleError, Header, RangeRow, RawRow, account_for, new_name, pack, unpack,
};
use super::folder::{Relay, RelayError};
use crate::canon::{self, Value};
use crate::clock::ClockOffsets;
use crate::export::{self, DecodeError};
use crate::fit;
use crate::model::{Decoded, Instant};
use crate::sources::{self, SourceError};
use crate::time::{parse_iso_utc, utc_now_iso};
use crate::writer::{WriteOutcome, Writer, WriterError};

pub const TRANSPORT_RELAY: &str = "relay";
/// A bundle is cut once its compressed payloads would pass this many bytes.
pub const PUSH_BYTES_LIMIT: usize = 8 * 1024 * 1024;
/// The `core` header field of the bundles this build writes.
const CORE: &str = concat!("disconect-core/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Writer(#[from] WriterError),
    #[error("{0}")]
    Source(#[from] SourceError),
    #[error("{0}")]
    Bundle(#[from] BundleError),
    #[error("{0}")]
    Relay(#[from] RelayError),
    /// An exception the oracle lets escape (`AttributeError` on a record that is not an object,
    /// `OverflowError` on a huge epoch): the pull stops, its run is booked failed.
    #[error("{0}")]
    Abort(String),
    /// A pulled record could not be stored (a storage error, not a decode failure). Whatever the
    /// write covered was rolled back -- for a conflict winner that includes the retirement of the
    /// losing record, which is still in place. The bundle stays `applying`; the next pull reapplies it.
    #[error("{0}")]
    WriteFailed(String),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PushResult {
    pub bundles: Vec<String>,
    pub records: usize,
    pub ranges: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub chain: String,
    pub device_seq: i64,
    pub missing: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullResult {
    pub applied: Vec<String>,
    /// (bundle name, reason), in the order they were met.
    pub rejected: Vec<(String, String)>,
    pub records_new: i64,
    pub records_duplicate: i64,
    pub records_invalid: i64,
    pub conflicts: i64,
    pub ranges_new: i64,
    pub gaps: Vec<Gap>,
    pub status: &'static str,
}

impl Default for PullResult {
    fn default() -> Self {
        PullResult {
            applied: Vec::new(),
            rejected: Vec::new(),
            records_new: 0,
            records_duplicate: 0,
            records_invalid: 0,
            conflicts: 0,
            ranges_new: 0,
            gaps: Vec::new(),
            status: "ok",
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn device(conn: &Connection) -> Result<(String, i64, Option<String>), SyncError> {
    let row: Option<(String, i64, Option<String>)> = conn
        .query_row(
            "SELECT device_id, next_seq, last_bundle FROM relay_device WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some(row) = row {
        return Ok(row);
    }
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|e| BundleError::Random(e.to_string()))?;
    let device_id = hex::encode(random);
    conn.execute(
        "INSERT INTO relay_device(id, device_id, next_seq, last_bundle) VALUES(1, ?, 1, NULL)",
        params![device_id],
    )?;
    Ok((device_id, 1, None))
}

// ---------------------------------------------------------------- push

/// Bundle every unseen local-origin record and range and put them on the relay.
pub fn push(conn: &Connection, master: &[u8], relay: &dyn Relay) -> Result<PushResult, SyncError> {
    let account = account_for(master);
    let mut result = PushResult::default();
    let rows: Vec<(i64, RawRow)> = {
        let mut stmt = conn.prepare(
            "SELECT r.id, r.stream, r.source_key, r.source_scope, r.transport, r.device_id, r.start_utc, r.end_utc, \
             r.payload_kind, r.payload, r.payload_hash, r.payload_bytes, r.imported_at FROM raw_records r \
             LEFT JOIN relay_seen s ON s.raw_record_id = r.id WHERE s.raw_record_id IS NULL ORDER BY r.id",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                RawRow {
                    stream: r.get(1)?,
                    source_key: r.get(2)?,
                    source_scope: r.get(3)?,
                    transport: r.get(4)?,
                    device_id: r.get(5)?,
                    start_utc: r.get(6)?,
                    end_utc: r.get(7)?,
                    payload_kind: r.get(8)?,
                    payload: r.get(9)?,
                    payload_hash: r.get(10)?,
                    payload_bytes: r.get(11)?,
                    imported_at: r.get(12)?,
                },
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    let ranges: Vec<(i64, RangeRow)> = {
        let mut stmt = conn.prepare(
            "SELECT x.id, x.stream, x.from_day, x.to_day FROM export_ranges x \
             LEFT JOIN relay_seen_ranges s ON s.export_range_id = x.id WHERE s.export_range_id IS NULL ORDER BY x.id",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                RangeRow {
                    stream: r.get(1)?,
                    from_day: r.get(2)?,
                    to_day: r.get(3)?,
                },
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    if rows.is_empty() && ranges.is_empty() {
        return Ok(result);
    }
    // split on the *compressed* payload length (what travels); ranges ride in the last bundle only
    let mut batches: Vec<Vec<(i64, RawRow)>> = vec![Vec::new()];
    let mut size = 0usize;
    for row in rows {
        let payload_len = row.1.payload.len();
        if batches.last().is_some_and(|b| !b.is_empty()) && size + payload_len > PUSH_BYTES_LIMIT {
            batches.push(Vec::new());
            size = 0;
        }
        if let Some(last) = batches.last_mut() {
            last.push(row);
        }
        size += payload_len;
    }
    let last_index = batches.len() - 1;
    for (index, batch) in batches.iter().enumerate() {
        let records: Vec<RawRow> = batch.iter().map(|(_, row)| row.clone()).collect();
        let (bundle_ranges, range_ids): (Vec<RangeRow>, Vec<i64>) = if index == last_index {
            ranges
                .iter()
                .map(|(id, range)| (range.clone(), *id))
                .unzip()
        } else {
            (Vec::new(), Vec::new())
        };
        // created lazily and outside the bundle's transaction, as the oracle does
        let (device_id, seq, prev) = device(conn)?;
        let name = new_name(&account)?;
        let header = Header {
            device_id: device_id.clone(),
            device_seq: seq,
            prev: prev.clone(),
            created_utc: utc_now_iso(),
        };
        let data = pack(master, &name, CORE, &header, &records, &bundle_ranges)?;
        relay.put(&name, &data)?; // the ONLY put in the crate: its argument is AEAD output
        conn.execute_batch("BEGIN")?;
        let booked = (|| -> rusqlite::Result<()> {
            conn.execute(
                "INSERT INTO relay_bundles(name, direction, status, device_id, device_seq, prev, created_utc, noted_at, \
                 bytes, records) VALUES(?,?,?,?,?,?,?,?,?,?)",
                params![
                    name,
                    "pushed",
                    "applied",
                    device_id,
                    seq,
                    prev,
                    header.created_utc,
                    utc_now_iso(),
                    data.len() as i64,
                    records.len() as i64
                ],
            )?;
            for (raw_id, _) in batch {
                conn.execute(
                    "INSERT OR IGNORE INTO relay_seen(raw_record_id, bundle, direction) VALUES(?,?,'pushed')",
                    params![raw_id, name],
                )?;
            }
            for range_id in &range_ids {
                conn.execute(
                    "INSERT OR IGNORE INTO relay_seen_ranges(export_range_id, bundle, direction) VALUES(?,?,'pushed')",
                    params![range_id, name],
                )?;
            }
            conn.execute(
                "UPDATE relay_device SET next_seq = ?, last_bundle = ? WHERE id=1",
                params![seq + 1, name],
            )?;
            Ok(())
        })();
        match booked {
            Ok(()) => conn.execute_batch("COMMIT")?,
            Err(error) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(error.into());
            }
        }
        result.records += records.len();
        result.ranges += bundle_ranges.len();
        result.bundles.push(name);
    }
    Ok(result)
}

// ---------------------------------------------------------------- pull

/// The decompressed bytes if they match the record's hashes, else `None` (`_verify`).
fn verify(record: &RawRow) -> Option<Vec<u8>> {
    let data = sources::inflate(&record.payload)?;
    let digest = sha256_hex(&data);
    if digest != record.payload_hash || data.len() as i64 != record.payload_bytes {
        return None;
    }
    if record.payload_kind == "fit" && digest != record.source_key {
        return None;
    }
    if record.payload_kind != "fit" && record.payload_kind != "json" {
        return None;
    }
    Some(data)
}

/// The latest moment the decoded facts speak for (`_observed`); `None` where the oracle has `''`.
fn observed(decoded: &Decoded) -> Option<Instant> {
    decoded
        .end_utc
        .into_iter()
        .chain(decoded.daily.iter().filter_map(|f| f.ts_utc))
        .max()
}

/// `_decode_json`: the record and its decoded facts, `None` where the oracle's `ValueError` /
/// `TypeError` / no-decoder / no-facts paths lead to an invalid record. An exception the oracle
/// lets escape (a record that is not an object) is `Err(Abort)`.
fn decode_json(
    stream: &str,
    data: &[u8],
    row: Option<&RawRow>,
) -> Result<Option<(Value, Decoded)>, SyncError> {
    let Ok(record) = canon::parse(data) else {
        return Ok(None); // json.loads -> ValueError, caught by the caller
    };
    if export::is_batch_stream(stream) {
        // decoded as a batch later; the raw row keeps the sender's span and device
        let scope = row
            .map(|r| r.source_scope.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("vendor_cloud");
        let mut decoded = Decoded::new(stream, scope);
        decoded.device_id = row.and_then(|r| r.device_id.clone());
        for (field, slot) in [
            (
                row.and_then(|r| r.start_utc.as_deref()),
                &mut decoded.start_utc,
            ),
            (row.and_then(|r| r.end_utc.as_deref()), &mut decoded.end_utc),
        ] {
            if let Some(text) = field.filter(|t| !t.is_empty()) {
                match parse_iso_utc(text) {
                    Some(moment) => *slot = Some(moment),
                    None => return Ok(None), // strptime -> ValueError
                }
            }
        }
        return Ok(Some((record, decoded)));
    }
    if !export::has_record_decoder(stream) {
        return Ok(None);
    }
    match export::decode_stored_record(stream, &record) {
        Ok(Some((_key, decoded))) => Ok(Some((record, decoded))),
        Ok(None) | Err(DecodeError::Refused(_)) => Ok(None),
        Err(DecodeError::Abort(message)) => {
            if message.starts_with("ValueError") || message.starts_with("TypeError") {
                Ok(None)
            } else {
                Err(SyncError::Abort(message))
            }
        }
    }
}

struct Existing {
    id: i64,
    payload: Vec<u8>,
    payload_hash: String,
    payload_kind: String,
    transport: String,
    imported_at: String,
}

fn insert_conflict(
    conn: &Connection,
    record: &RawRow,
    winner: &str,
    loser: &str,
    rule: &str,
    bundle_name: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO sync_conflicts(stream, source_key, winner_hash, loser_hash, rule, bundle, decided_at) \
         VALUES(?,?,?,?,?,?,?)",
        params![record.stream, record.source_key, winner, loser, rule, bundle_name, utc_now_iso()],
    )?;
    Ok(())
}

/// The bytes of the record that lost, as `raw_superseded` keeps them.
struct Loser<'a> {
    kind: &'a str,
    payload: &'a [u8],
    hash: &'a str,
    transport: &'a str,
    imported_at: &'a str,
}

fn insert_superseded(
    conn: &Connection,
    record: &RawRow,
    loser: &Loser<'_>,
    bundle_name: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO raw_superseded(stream, source_key, payload_kind, payload, payload_hash, transport, imported_at, \
         superseded_at, bundle) VALUES(?,?,?,?,?,?,?,?,?)",
        params![
            record.stream,
            record.source_key,
            loser.kind,
            loser.payload,
            loser.hash,
            loser.transport,
            loser.imported_at,
            utc_now_iso(),
            bundle_name
        ],
    )?;
    Ok(())
}

/// The decision on a same-key, different-bytes pair (`_decide_conflict`): pure, writes nothing.
pub struct Conflict {
    pub incoming_wins: bool,
    rule: &'static str,
    winner: String,
    loser: String,
    existing: Existing,
}

/// Same key, different bytes: who wins. `None` when no stored row differs from the incoming bytes
/// (no row at all, or the very same bytes): nothing to decide.
pub fn decide_conflict(
    conn: &Connection,
    record: &RawRow,
    incoming: &Decoded,
) -> Result<Option<Conflict>, SyncError> {
    let existing: Option<Existing> = conn
        .query_row(
            "SELECT id, payload, payload_hash, payload_kind, transport, imported_at FROM raw_records \
             WHERE stream=? AND source_key=?",
            params![record.stream, record.source_key],
            |r| {
                Ok(Existing {
                    id: r.get(0)?,
                    payload: r.get(1)?,
                    payload_hash: r.get(2)?,
                    payload_kind: r.get(3)?,
                    transport: r.get(4)?,
                    imported_at: r.get(5)?,
                })
            },
        )
        .optional()?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    if existing.payload_hash == record.payload_hash {
        return Ok(None);
    }
    let (existing_observed, incoming_observed) = if export::is_batch_stream(&record.stream) {
        // a batch stream's record carries no time of its own: the protocol's rule is the hash alone
        (None, None)
    } else {
        // an undecodable existing record loses by definition
        let decoded = sources::inflate(&existing.payload)
            .and_then(|data| decode_json(&record.stream, &data, None).ok().flatten())
            .map(|(_record, decoded)| decoded);
        (decoded.as_ref().and_then(observed), observed(incoming))
    };
    let (incoming_wins, rule) = if incoming_observed != existing_observed {
        (incoming_observed > existing_observed, "observed_utc")
    } else {
        (record.payload_hash > existing.payload_hash, "payload_hash")
    };
    let (winner, loser) = if incoming_wins {
        (record.payload_hash.clone(), existing.payload_hash.clone())
    } else {
        (existing.payload_hash.clone(), record.payload_hash.clone())
    };
    Ok(Some(Conflict {
        incoming_wins,
        rule,
        winner,
        loser,
        existing,
    }))
}

/// The incoming record lost: keep its bytes in `raw_superseded` with the decision, one transaction.
fn record_incoming_loser(
    conn: &Connection,
    record: &RawRow,
    conflict: &Conflict,
    bundle_name: &str,
) -> Result<(), SyncError> {
    conn.execute_batch("BEGIN")?;
    let decided = (|| -> rusqlite::Result<()> {
        insert_conflict(
            conn,
            record,
            &conflict.winner,
            &conflict.loser,
            conflict.rule,
            bundle_name,
        )?;
        let loser = Loser {
            kind: &record.payload_kind,
            payload: &record.payload,
            hash: &record.payload_hash,
            transport: &record.transport,
            imported_at: &record.imported_at,
        };
        insert_superseded(conn, record, &loser, bundle_name)
    })();
    match decided {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(error.into());
        }
    }
    Ok(())
}

/// The pre-write hook of an incoming winner: every write that retires the stored loser. It runs
/// inside `write_json_record_with`'s own transaction, before the winner's raw row and canonical
/// rows, so a storage error anywhere rolls the decision back together with the winner's write.
fn retire_loser(
    conn: &Connection,
    writer: &Writer<'_>,
    record: &RawRow,
    conflict: &Conflict,
    bundle_name: &str,
) -> rusqlite::Result<()> {
    let existing = &conflict.existing;
    insert_conflict(
        conn,
        record,
        &conflict.winner,
        &conflict.loser,
        conflict.rule,
        bundle_name,
    )?;
    let loser = Loser {
        kind: &existing.payload_kind,
        payload: &existing.payload,
        hash: &existing.payload_hash,
        transport: &existing.transport,
        imported_at: &existing.imported_at,
    };
    insert_superseded(conn, record, &loser, bundle_name)?;
    writer.delete_canonical_for_raw(existing.id)?;
    // rows that point at the losing record (a past decode failure, relay bookkeeping) go first
    conn.execute(
        "DELETE FROM import_failures WHERE raw_record_id=?",
        params![existing.id],
    )?;
    conn.execute(
        "DELETE FROM relay_seen WHERE raw_record_id=?",
        params![existing.id],
    )?;
    conn.execute("DELETE FROM raw_records WHERE id=?", params![existing.id])?;
    Ok(())
}

fn conflict_recorded(
    conn: &Connection,
    bundle_name: &str,
    record: &RawRow,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT 1 FROM sync_conflicts WHERE bundle=? AND source_key=? AND stream=?",
        params![bundle_name, record.source_key, record.stream],
        |_| Ok(()),
    )
    .optional()
    .map(|found| found.is_some())
}

/// Fetch and apply every bundle on the relay this store has not applied yet.
pub fn pull(conn: &Connection, master: &[u8], relay: &dyn Relay) -> Result<PullResult, SyncError> {
    let account = account_for(master);
    let mut result = PullResult::default();
    let names = |status: &str| -> rusqlite::Result<HashSet<String>> {
        let mut stmt = conn.prepare("SELECT name FROM relay_bundles WHERE status=?")?;
        let mapped = stmt.query_map(params![status], |r| r.get::<_, String>(0))?;
        mapped.collect()
    };
    let known = names("applied")?;
    let half_applied = names("applying")?;
    let pending: Vec<String> = relay
        .list(&account)?
        .into_iter()
        .filter(|name| !known.contains(name))
        .collect();
    if pending.is_empty() {
        report_gaps(conn, &mut result)?;
        return Ok(result);
    }
    let mut writer = Writer::new(conn, ClockOffsets::load(conn)?, TRANSPORT_RELAY);
    writer.begin_run()?;
    if let Err(error) = apply_pending(
        conn,
        master,
        relay,
        &mut writer,
        &pending,
        &half_applied,
        &mut result,
    ) {
        writer.finish_run(Some(&error.to_string()))?;
        return Err(error);
    }
    writer.stats.dates_assumed_utc = writer.offsets.assumed_utc();
    writer.finish_run(None)?;
    if !result.rejected.is_empty() {
        result.status = "partial";
    }
    report_gaps(conn, &mut result)?;
    Ok(result)
}

struct Applied {
    name: String,
    header: Header,
    size: usize,
    count: usize,
}

fn apply_pending(
    conn: &Connection,
    master: &[u8],
    relay: &dyn Relay,
    writer: &mut Writer<'_>,
    pending: &[String],
    half_applied: &HashSet<String>,
    result: &mut PullResult,
) -> Result<(), SyncError> {
    let mut applied: Vec<Applied> = Vec::new();
    let mut reparse_streams: BTreeSet<String> = BTreeSet::new();
    for name in pending {
        let fetched = match relay.get(name) {
            // the relay, not the object, is the problem: stop here, mark nothing, retry next pull
            Err(error) if error.is_transient() => return Err(error.into()),
            other => other,
        }
        .map_err(|e| e.reason().to_string())
        .and_then(|blob| {
            unpack(master, name, &blob)
                .map(|bundle| (blob, bundle))
                .map_err(|rejected| rejected.reason)
        });
        let (blob, bundle) = match fetched {
            Ok(pair) => pair,
            Err(reason) => {
                writer.stats.files_failed += 1;
                conn.execute(
                    "INSERT OR REPLACE INTO relay_bundles(name, direction, status, noted_at, reason) \
                     VALUES(?, 'pulled', 'rejected', ?, ?)",
                    params![name, utc_now_iso(), reason],
                )?;
                result.rejected.push((name.clone(), reason));
                continue;
            }
        };
        let bundle::Bundle {
            header,
            records,
            ranges,
        } = bundle;
        if half_applied.contains(name) {
            // a crash cut the previous pull before its derive step: its records are in, the derived
            // rows may not be -- re-derive those streams in full
            reparse_streams.extend(records.iter().map(|r| r.stream.clone()));
        }
        conn.execute(
            "INSERT OR REPLACE INTO relay_bundles(name, direction, status, noted_at, bytes, records) \
             VALUES(?, 'pulled', 'applying', ?, ?, ?)",
            params![name, utc_now_iso(), blob.len() as i64, records.len() as i64],
        )?;
        let mut fits: Vec<(&RawRow, Vec<u8>)> = Vec::new();
        let mut jsons: Vec<(&RawRow, Vec<u8>)> = Vec::new();
        for record in &records {
            let Some(data) = verify(record) else { continue };
            match record.payload_kind.as_str() {
                "fit" => fits.push((record, data)),
                "json" => jsons.push((record, data)),
                _ => {}
            }
        }
        result.records_invalid += (records.len() - fits.len() - jsons.len()) as i64;
        let label = format!("relay:{}", &name[name.len().saturating_sub(8)..]);
        for (_record, data) in &fits {
            writer.offsets.extend(fit::scan_clock_offsets(data));
        }
        for (record, data) in &fits {
            let before = writer.last_raw_id()?;
            let outcome =
                writer.write_fit(data, &label, Some((&record.transport, &record.imported_at)))?;
            if outcome == WriteOutcome::Failed && writer.last_failure_is_storage() {
                return Err(SyncError::WriteFailed(format!(
                    "{} file not stored ({outcome:?}); nothing it wrote is kept",
                    record.stream
                )));
            }
            mark(conn, before, name, outcome, result)?;
            if outcome == WriteOutcome::Duplicate {
                mark_existing(conn, record, name)?;
            }
        }
        for (record, data) in &jsons {
            let Some((record_value, facts)) = decode_json(&record.stream, data, Some(record))?
            else {
                result.records_invalid += 1;
                continue;
            };
            let conflict = decide_conflict(conn, record, &facts)?;
            if let Some(conflict) = conflict.as_ref().filter(|c| !c.incoming_wins) {
                // a reapplied bundle decided this record already
                if !conflict_recorded(conn, name, record)? {
                    record_incoming_loser(conn, record, conflict, name)?;
                }
                result.conflicts += 1;
                continue;
            }
            if conflict.is_none() {
                let stored = conn
                    .prepare_cached("SELECT 1 FROM raw_records WHERE stream=? AND source_key=?")?
                    .exists(params![record.stream, record.source_key])?;
                if stored {
                    // the same bytes are already here (a local import or an earlier bundle)
                    if conflict_recorded(conn, name, record)? {
                        // a reapplied bundle: the winner is stored, its relay_seen row may not be
                        result.conflicts += 1;
                        mark_existing(conn, record, name)?;
                    } else {
                        result.records_duplicate += 1;
                        mark_existing(conn, record, name)?;
                    }
                    continue;
                }
            }
            let before = writer.last_raw_id()?;
            let outcome = match conflict.as_ref() {
                Some(conflict) => {
                    let hook = |w: &Writer<'_>| retire_loser(conn, w, record, conflict, name);
                    writer.write_json_record_with(
                        &record.stream,
                        &record.source_key,
                        &record_value,
                        &facts,
                        &label,
                        Some((&record.transport, &record.imported_at)),
                        Some(&hook),
                    )?
                }
                None => writer.write_json_record(
                    &record.stream,
                    &record.source_key,
                    &record_value,
                    &facts,
                    &label,
                    Some((&record.transport, &record.imported_at)),
                )?,
            };
            let storage_failure =
                outcome == WriteOutcome::Failed && writer.last_failure_is_storage();
            if storage_failure || (conflict.is_some() && outcome != WriteOutcome::Imported) {
                return Err(SyncError::WriteFailed(format!(
                    "{} record not stored ({outcome:?}); nothing it wrote is kept",
                    record.stream
                )));
            }
            if conflict.is_some() {
                result.conflicts += 1;
            }
            mark(conn, before, name, outcome, result)?;
            if conflict.is_some() {
                // the winner may have reused the retired loser's rowid (`id > before` misses it)
                mark_existing(conn, record, name)?;
            }
        }
        for item in &ranges {
            let changes_before = conn.total_changes();
            writer.record_export_range(&item.stream, &item.from_day, &item.to_day)?;
            let id: Option<i64> = conn
                .query_row(
                    "SELECT id FROM export_ranges WHERE stream=? AND from_day=? AND to_day=?",
                    params![item.stream, item.from_day, item.to_day],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(id) = id {
                if conn.total_changes() > changes_before {
                    result.ranges_new += 1;
                }
                conn.execute(
                    "INSERT OR IGNORE INTO relay_seen_ranges(export_range_id, bundle, direction) VALUES(?,?,'pulled')",
                    params![id, name],
                )?;
            }
        }
        applied.push(Applied {
            name: name.clone(),
            header,
            size: blob.len(),
            count: records.len(),
        });
    }
    // daily rows are a pure function of the raw set: every JSON stream a record was written to
    // (new, or a conflict winner that replaced the loser) is rebuilt in content order
    let touched: Vec<String> = writer.stats.streams.keys().cloned().collect();
    sources::rederive_json(conn, writer, &touched)?;
    writer.derive_daily_steps()?;
    writer.derive_daily_from_samples()?;
    if !reparse_streams.is_empty() {
        let streams: Vec<String> = reparse_streams.into_iter().collect();
        sources::reparse_all(conn, Some(&streams), false)?;
    }
    for item in applied {
        conn.execute(
            "INSERT OR REPLACE INTO relay_bundles(name, direction, status, device_id, device_seq, prev, created_utc, \
             noted_at, bytes, records) VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![
                item.name,
                "pulled",
                "applied",
                item.header.device_id,
                item.header.device_seq,
                item.header.prev,
                item.header.created_utc,
                utc_now_iso(),
                item.size as i64,
                item.count as i64
            ],
        )?;
        result.applied.push(item.name);
    }
    Ok(())
}

/// `_mark`: an imported record's rows are marked received -- every raw id above `before`.
fn mark(
    conn: &Connection,
    before: i64,
    name: &str,
    outcome: WriteOutcome,
    result: &mut PullResult,
) -> Result<(), SyncError> {
    match outcome {
        WriteOutcome::Imported => {
            result.records_new += 1;
            let ids: Vec<i64> = {
                let mut stmt = conn.prepare("SELECT id FROM raw_records WHERE id > ?")?;
                let mapped = stmt.query_map(params![before], |r| r.get(0))?;
                mapped.collect::<Result<_, _>>()?
            };
            for raw_id in ids {
                conn.execute(
                    "INSERT OR IGNORE INTO relay_seen(raw_record_id, bundle, direction) VALUES(?,?,'pulled')",
                    params![raw_id, name],
                )?;
            }
        }
        WriteOutcome::Duplicate => result.records_duplicate += 1,
        WriteOutcome::Failed | WriteOutcome::Reparsed => result.records_invalid += 1,
    }
    Ok(())
}

/// `_mark_existing`: the same bytes were already here (a local import or an earlier bundle):
/// never push them back. A FIT record falls back to its key (the bytes' hash) alone.
fn mark_existing(conn: &Connection, record: &RawRow, name: &str) -> Result<(), SyncError> {
    let mut id: Option<i64> = conn
        .query_row(
            "SELECT id FROM raw_records WHERE stream=? AND source_key=? AND payload_hash=?",
            params![record.stream, record.source_key, record.payload_hash],
            |r| r.get(0),
        )
        .optional()?;
    if id.is_none() && record.payload_kind == "fit" {
        id = conn
            .query_row(
                "SELECT id FROM raw_records WHERE payload_kind='fit' AND source_key=?",
                params![record.source_key],
                |r| r.get(0),
            )
            .optional()?;
    }
    if let Some(id) = id {
        conn.execute(
            "INSERT OR IGNORE INTO relay_seen(raw_record_id, bundle, direction) VALUES(?,?,'pulled')",
            params![id, name],
        )?;
    }
    Ok(())
}

/// A device's chain (`device_seq`, `prev`) with a missing link means the relay dropped a middle bundle.
fn report_gaps(conn: &Connection, result: &mut PullResult) -> Result<(), SyncError> {
    result.gaps = gaps(conn)?;
    Ok(())
}

pub fn gaps(conn: &Connection) -> Result<Vec<Gap>, SyncError> {
    type Link = (i64, Option<String>, String);
    let rows: Vec<(String, Link)> = {
        let mut stmt = conn.prepare(
            "SELECT device_id, device_seq, prev, name FROM relay_bundles WHERE status='applied' \
             AND device_id IS NOT NULL ORDER BY device_id, device_seq",
        )?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?, r.get(3)?))))?;
        mapped.collect::<Result<_, _>>()?
    };
    let mut by_device: Vec<(String, Vec<Link>)> = Vec::new();
    for (device_id, link) in rows {
        match by_device.last_mut() {
            Some((id, chain)) if *id == device_id => chain.push(link),
            _ => by_device.push((device_id, vec![link])),
        }
    }
    let mut found = Vec::new();
    for (device_id, chain) in by_device {
        let names: HashSet<&str> = chain.iter().map(|(_, _, name)| name.as_str()).collect();
        for (seq, prev, _name) in &chain {
            if let Some(prev) = prev
                && !names.contains(prev.as_str())
            {
                found.push(Gap {
                    chain: device_id.clone(),
                    device_seq: *seq,
                    missing: prev.clone(),
                });
            }
        }
    }
    Ok(found)
}

/// Counts only: bundles pushed/pulled/rejected, records seen, conflicts, chain gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    /// `"<direction>_<status>"` -> bundle count.
    pub bundles: BTreeMap<String, i64>,
    pub records_unsent: i64,
    pub records_seen: i64,
    pub conflicts: i64,
    pub superseded: i64,
    pub gaps: Vec<Gap>,
}

pub fn status(conn: &Connection) -> Result<StatusReport, SyncError> {
    let mut bundles = BTreeMap::new();
    {
        let mut stmt =
            conn.prepare("SELECT direction, status, count(*) FROM relay_bundles GROUP BY 1, 2")?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in mapped {
            let (direction, state, count) = row?;
            bundles.insert(format!("{direction}_{state}"), count);
        }
    }
    let count = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0));
    Ok(StatusReport {
        bundles,
        records_unsent: count(
            "SELECT count(*) FROM raw_records r LEFT JOIN relay_seen s ON s.raw_record_id=r.id WHERE s.raw_record_id IS NULL",
        )?,
        records_seen: count("SELECT count(*) FROM relay_seen")?,
        conflicts: count("SELECT count(*) FROM sync_conflicts")?,
        superseded: count("SELECT count(*) FROM raw_superseded")?,
        gaps: gaps(conn)?,
    })
}

/// `status` for a store that may predate the relay tables (schema 1 or 2, never synced): the same
/// counts a fresh schema-3 store would show, so a read-only `sync.status` never needs a migration.
pub fn status_or_fresh(conn: &Connection) -> Result<StatusReport, SyncError> {
    let has_relay: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='relay_bundles')",
        [],
        |r| r.get(0),
    )?;
    if has_relay {
        return status(conn);
    }
    Ok(StatusReport {
        bundles: BTreeMap::new(),
        records_unsent: conn.query_row("SELECT count(*) FROM raw_records", [], |r| r.get(0))?,
        records_seen: 0,
        conflicts: 0,
        superseded: 0,
        gaps: Vec::new(),
    })
}

/// The JSON `sync status --json` prints and the `sync.status` method answers.
pub fn status_value(report: &StatusReport) -> serde_json::Value {
    let bundles: serde_json::Map<String, serde_json::Value> = report
        .bundles
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::json!(v)))
        .collect();
    let gaps: Vec<serde_json::Value> = report
        .gaps
        .iter()
        .map(|g| serde_json::json!({"chain": g.chain, "device_seq": g.device_seq, "missing": g.missing}))
        .collect();
    serde_json::json!({
        "bundles": bundles,
        "records_unsent": report.records_unsent,
        "records_seen": report.records_seen,
        "conflicts": report.conflicts,
        "superseded": report.superseded,
        "gaps": gaps,
    })
}

/// After a master rotation or a re-pair: a new account and key, so every record is pushed again
/// under them. Conflict and superseded history is kept (it is local history, not relay state).
pub fn forget_relay_state(conn: &Connection) -> Result<(), SyncError> {
    for table in [
        "relay_bundles",
        "relay_seen",
        "relay_seen_ranges",
        "relay_device",
    ] {
        conn.execute(&format!("DELETE FROM {table}"), [])?;
    }
    Ok(())
}
